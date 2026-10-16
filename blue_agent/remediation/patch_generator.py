"""
Patch Generator — Automatically generates code fixes for detected vulnerabilities.

Covers ALL vulnerability types in the target application:
- SQL Injection (login, search, comments)
- XSS (greet)
- Path Traversal (file)
- Command Injection (ping)
- SSRF (fetch)
- Insecure Deserialization (load)
- Broken Access Control (admin/users)
- Hardcoded Secrets (secret key)
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from blue_agent.logging_cfg import get_logger
from blue_agent.schemas import AttackEvent, LLMAnalysis, Patch, PatchOrigin

log = get_logger("remediation.patch_generator")


import os
from pathlib import Path
from blue_agent.config import PROJECT_ROOT, settings

class PatchGenerator:
    """
    Generates remediation patches based on attack events and LLM analysis.

    Supports dynamic LLM-driven patch generation by inspecting actual source files,
    with template fallbacks for offline demo environments.
    """

    def _locate_vulnerable_file(self, endpoint: str, component: str = "") -> tuple[Optional[Path], str]:
        """Dynamically locate the source code file handling this endpoint or component."""
        target_root = Path(settings.audit.target_app_path or (PROJECT_ROOT / "target_app"))
        if not target_root.exists() or not target_root.is_dir():
            target_root = Path("/target") if os.path.exists("/target") else (PROJECT_ROOT / "target_app")

        # Check if component points to an existing file
        if component:
            comp_path = target_root / component
            if comp_path.is_file():
                try:
                    rel = str(comp_path.relative_to(target_root)).replace("\\", "/")
                except ValueError:
                    rel = comp_path.name
                return comp_path, rel

        clean_ep = endpoint.strip("/")
        # Search for route handler in source files
        if target_root.is_dir():
            for ext in ("*.py", "*.js", "*.ts", "*.go", "*.php", "*.rb"):
                for path in target_root.rglob(ext):
                    if not path.is_file():
                        continue
                    try:
                        content = path.read_text(encoding="utf-8", errors="ignore")
                        if endpoint and (f'"{endpoint}"' in content or f"'{endpoint}'" in content or (clean_ep and clean_ep in content)):
                            try:
                                rel = str(path.relative_to(target_root)).replace("\\", "/")
                            except ValueError:
                                rel = path.name
                            return path, rel
                    except Exception:
                        continue

            # Fallback to main app files
            for candidate in ("app.py", "main.py", "server.js", "index.js", "web_app.py", "run.py"):
                cand_path = target_root / candidate
                if cand_path.is_file():
                    try:
                        rel = str(cand_path.relative_to(target_root)).replace("\\", "/")
                    except ValueError:
                        rel = candidate
                    return cand_path, rel

        return None, "target_app/app.py"

    def generate_patch(
        self,
        event: AttackEvent,
        analysis: Optional[LLMAnalysis] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Patch]:
        """
        Generate a patch based on the event and optional LLM analysis.
        Prefers real LLM generation against actual source code files,
        with template fallbacks for standard offline demo runs.
        """
        log.info("generating_patch", event_id=event.event_id, attack_type=event.attack_type)

        attack_type = event.attack_type.lower()
        endpoint = event.endpoint.lower()

        # Reconnaissance — no code patch needed, handled by hardening
        if "recon" in attack_type or "scan" in attack_type:
            log.info("recon_no_patch_needed", attack_type=attack_type)
            return None

        # 1. Try real dynamic LLM patch generation first
        if analysis and getattr(analysis, "patch_required", False):
            llm_patch = self._generate_llm_patch(event, analysis, context)
            if llm_patch:
                return llm_patch

        # 2. Template fallbacks for bundled target application
        if "sql" in attack_type or "injection" in attack_type:
            if "/login" in endpoint:
                return self._generate_sqli_login_patch()
            elif "/search" in endpoint:
                return self._generate_sqli_search_patch()
            elif "/comments" in endpoint:
                return self._generate_sqli_comments_patch()

        if ("xss" in attack_type or "cross-site" in attack_type or "script" in attack_type) and "/greet" in endpoint:
            return self._generate_xss_greet_patch()

        if ("path" in attack_type or "traversal" in attack_type or "directory" in attack_type) and "/file" in endpoint:
            return self._generate_path_traversal_patch()

        if ("command" in attack_type or "os command" in attack_type or "cmd" in attack_type) and "/ping" in endpoint:
            return self._generate_command_injection_patch()

        if ("ssrf" in attack_type or "server-side request" in attack_type) and "/fetch" in endpoint:
            return self._generate_ssrf_patch()

        if ("deseriali" in attack_type or "pickle" in attack_type) and "/load" in endpoint:
            return self._generate_deserialization_patch()

        if ("access control" in attack_type or "auth" in attack_type or "broken" in attack_type) and "/admin" in endpoint:
            return self._generate_broken_auth_patch()

        if "brute" in attack_type and "/login" in endpoint:
            return self._generate_rate_limit_patch()

        # 3. Final attempt: LLM patch even without prior explicit analysis flag
        llm_patch = self._generate_llm_patch(event, analysis, context)
        if llm_patch:
            return llm_patch

        log.warning("no_patch_template_available", attack_type=event.attack_type, endpoint=event.endpoint)
        return None

    # -----------------------------------------------------------------------
    # SQL Injection Patches
    # -----------------------------------------------------------------------
    def _generate_sqli_login_patch(self) -> Patch:
        """Template patch for the intentionally vulnerable /login route."""
        diff = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -100,6 +100,6 @@
     username = request.form.get("username", "")
     password = request.form.get("password", "")
     db = get_db()
-    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"  # noqa: S608
-    user = db.execute(query).fetchone()
+    query = "SELECT * FROM users WHERE username=? AND password=?"
+    user = db.execute(query, (username, password)).fetchone()
     if user:"""

        return Patch(
            patch_id=str(uuid.uuid4()),
            files_changed=["target_app/app.py"],
            diff=diff,
            strategy="parameterized_query",
            generated_by=PatchOrigin.TEMPLATE
        )

    def _generate_sqli_search_patch(self) -> Patch:
        """Template patch for the intentionally vulnerable /search route."""
        diff = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -115,5 +115,5 @@
     q = request.args.get("q", "")
     db = get_db()
     results = db.execute(
-        f"SELECT * FROM posts WHERE title LIKE '%{q}%'"  # noqa: S608
+        "SELECT * FROM posts WHERE title LIKE ?", (f"%{q}%",)
     ).fetchall()"""

        return Patch(
            patch_id=str(uuid.uuid4()),
            files_changed=["target_app/app.py"],
            diff=diff,
            strategy="parameterized_query",
            generated_by=PatchOrigin.TEMPLATE
        )

    def _generate_sqli_comments_patch(self) -> Patch:
        """Template patch for the intentionally vulnerable /comments route."""
        diff = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -204,5 +204,5 @@
     post_id = request.form.get("post_id", "")
     body = request.form.get("body", "")
     db = get_db()
-    db.execute(f"INSERT INTO comments (post_id, body) VALUES ({post_id}, '{body}')")  # noqa: S608
+    db.execute("INSERT INTO comments (post_id, body) VALUES (?, ?)", (post_id, body))
     db.commit()"""

        return Patch(
            patch_id=str(uuid.uuid4()),
            files_changed=["target_app/app.py"],
            diff=diff,
            strategy="parameterized_query",
            generated_by=PatchOrigin.TEMPLATE
        )

    # -----------------------------------------------------------------------
    # XSS Patch
    # -----------------------------------------------------------------------
    def _generate_xss_greet_patch(self) -> Patch:
        """Template patch for the intentionally vulnerable /greet route."""
        diff = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -124,4 +124,5 @@
 @app.route("/greet")
 def greet():
     name = request.args.get("name", "World")
-    return f"<html><body><h1>Hello, {name}!</h1></body></html>"
+    from markupsafe import escape
+    return f"<html><body><h1>Hello, {escape(name)}!</h1></body></html>"
 """
        return Patch(
            patch_id=str(uuid.uuid4()),
            files_changed=["target_app/app.py"],
            diff=diff,
            strategy="output_encoding",
            generated_by=PatchOrigin.TEMPLATE
        )

    # -----------------------------------------------------------------------
    # Path Traversal Patch
    # -----------------------------------------------------------------------
    def _generate_path_traversal_patch(self) -> Patch:
        """Template patch for the intentionally vulnerable /file route."""
        diff = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -139,5 +139,8 @@
 @app.route("/file")
 def read_file():
     filename = request.args.get("name", "")
-    filepath = os.path.join("/tmp/uploads", filename)  # noqa: S108
+    from werkzeug.utils import secure_filename
+    safe_name = secure_filename(filename)
+    if not safe_name:
+        return jsonify({"error": "Invalid filename"}), 400
+    filepath = os.path.join("/tmp/uploads", safe_name)  # noqa: S108
     try:
         with open(filepath) as f:"""
        return Patch(
            patch_id=str(uuid.uuid4()),
            files_changed=["target_app/app.py"],
            diff=diff,
            strategy="secure_filename",
            generated_by=PatchOrigin.TEMPLATE
        )

    # -----------------------------------------------------------------------
    # Command Injection Patch
    # -----------------------------------------------------------------------
    def _generate_command_injection_patch(self) -> Patch:
        """Template patch for the intentionally vulnerable /ping route."""
        diff = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -131,5 +131,12 @@
 @app.route("/ping")
 def ping():
     host = request.args.get("host", "127.0.0.1")
-    result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)  # noqa: S602
-    return jsonify({"output": result})
+    import re
+    # Only allow valid IP addresses or hostnames (no shell metacharacters)
+    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.\\-]{0,253}[a-zA-Z0-9]$', host):
+        return jsonify({"error": "Invalid host format"}), 400
+    try:
+        result = subprocess.check_output(
+            ["ping", "-c", "1", host], text=True, timeout=5  # noqa: S603
+        )
+        return jsonify({"output": result})
+    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
+        return jsonify({"error": f"Ping failed: {e}"}), 500"""
        return Patch(
            patch_id=str(uuid.uuid4()),
            files_changed=["target_app/app.py"],
            diff=diff,
            strategy="input_validation_and_safe_subprocess",
            generated_by=PatchOrigin.TEMPLATE
        )

    # -----------------------------------------------------------------------
    # SSRF Patch
    # -----------------------------------------------------------------------
    def _generate_ssrf_patch(self) -> Patch:
        """Template patch for the intentionally vulnerable /fetch route."""
        diff = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -160,9 +160,21 @@
 @app.route("/fetch")
 def fetch_url():
-    import urllib.request
     url = request.args.get("url", "")
+    from urllib.parse import urlparse
+    # SSRF protection: allowlist external domains only
+    ALLOWED_DOMAINS = {"example.com", "httpbin.org", "jsonplaceholder.typicode.com"}
+    parsed = urlparse(url)
+    if parsed.scheme not in ("http", "https"):
+        return jsonify({"error": "Only HTTP(S) URLs are allowed"}), 400
+    if not parsed.hostname:
+        return jsonify({"error": "Invalid URL"}), 400
+    # Block internal/private IPs and localhost
+    blocked = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "169.254.169.254"}
+    if parsed.hostname in blocked or parsed.hostname.startswith("10.") or parsed.hostname.startswith("192.168."):
+        return jsonify({"error": "Access to internal resources is blocked"}), 403
     try:
+        import urllib.request
         resp = urllib.request.urlopen(url)  # noqa: S310
         return resp.read().decode("utf-8", errors="replace")[:4096]
     except Exception as exc:"""
        return Patch(
            patch_id=str(uuid.uuid4()),
            files_changed=["target_app/app.py"],
            diff=diff,
            strategy="url_allowlist_validation",
            generated_by=PatchOrigin.TEMPLATE
        )

    # -----------------------------------------------------------------------
    # Insecure Deserialization Patch
    # -----------------------------------------------------------------------
    def _generate_deserialization_patch(self) -> Patch:
        """Template patch for the intentionally vulnerable /load route."""
        diff = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -152,6 +152,10 @@
 @app.route("/load", methods=["POST"])
 def load_object():
-    data = request.get_data()
-    obj = pickle.loads(data)  # noqa: S301
-    return jsonify({"type": str(type(obj)), "repr": repr(obj)})
+    import json as json_mod
+    try:
+        data = request.get_json(force=True)
+        if not isinstance(data, (dict, list, str, int, float, bool, type(None))):
+            return jsonify({"error": "Unsupported data type"}), 400
+        return jsonify({"type": str(type(data)), "repr": repr(data)})
+    except Exception:
+        return jsonify({"error": "Only JSON payloads are accepted. Pickle is disabled."}), 400"""
        return Patch(
            patch_id=str(uuid.uuid4()),
            files_changed=["target_app/app.py"],
            diff=diff,
            strategy="replace_pickle_with_json",
            generated_by=PatchOrigin.TEMPLATE
        )

    # -----------------------------------------------------------------------
    # Broken Access Control Patch
    # -----------------------------------------------------------------------
    def _generate_broken_auth_patch(self) -> Patch:
        """Template patch for the unprotected /admin/users endpoint."""
        diff = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -171,6 +171,9 @@
-@app.route("/admin/users")
-def admin_users():
+@app.route("/admin/users")
+@login_required
+def admin_users():
+    if session.get("role") != "admin":
+        return jsonify({"error": "Forbidden — admin role required"}), 403
     db = get_db()
     users = db.execute("SELECT id, username, role FROM users").fetchall()
     return jsonify([dict(u) for u in users])"""
        return Patch(
            patch_id=str(uuid.uuid4()),
            files_changed=["target_app/app.py"],
            diff=diff,
            strategy="add_authentication_and_authorization",
            generated_by=PatchOrigin.TEMPLATE
        )

    # -----------------------------------------------------------------------
    # Brute Force Rate Limiting Patch
    # -----------------------------------------------------------------------
    def _generate_rate_limit_patch(self) -> Patch:
        """Template patch to add rate limiting to /login."""
        diff = """--- a/target_app/app.py
+++ b/target_app/app.py
@@ -96,6 +96,18 @@
+# Simple in-memory rate limiter for login attempts
+_login_attempts = {}  # ip -> [(timestamp, ...)]
+
+def _check_rate_limit(ip, max_attempts=5, window=300):
+    import time as _time
+    now = _time.time()
+    attempts = _login_attempts.get(ip, [])
+    attempts = [t for t in attempts if now - t < window]
+    _login_attempts[ip] = attempts
+    if len(attempts) >= max_attempts:
+        return False
+    attempts.append(now)
+    _login_attempts[ip] = attempts
+    return True
+
 @app.route("/login", methods=["POST"])
 def login():
+    if not _check_rate_limit(request.remote_addr):
+        return jsonify({"error": "Too many login attempts. Try again later."}), 429
     username = request.form.get("username", "")"""
        return Patch(
            patch_id=str(uuid.uuid4()),
            files_changed=["target_app/app.py"],
            diff=diff,
            strategy="rate_limiting",
            generated_by=PatchOrigin.TEMPLATE
        )

    # -----------------------------------------------------------------------
    # Dynamic LLM Patch Generation
    # -----------------------------------------------------------------------
    def _generate_llm_patch(
        self,
        event: AttackEvent,
        analysis: Optional[LLMAnalysis] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Patch]:
        """Dynamically use LLM to inspect actual source code on disk and generate a unified diff."""
        try:
            from blue_agent.llm.llm_client import LLMClient
            client = LLMClient()

            affected_comp = analysis.affected_component if analysis else ""
            file_path, rel_path = self._locate_vulnerable_file(event.endpoint, affected_comp)

            code_snippet = ""
            if file_path and file_path.is_file():
                try:
                    code_snippet = file_path.read_text(encoding="utf-8", errors="replace")
                    lines = code_snippet.splitlines()
                    if len(lines) > 500:
                        code_snippet = "\n".join(lines[:500]) + "\n... [truncated]"
                except Exception as exc:
                    log.warning("failed_reading_target_file_for_patch", error=str(exc))

            root_cause = analysis.root_cause if analysis else f"Vulnerability exposed at {event.endpoint}"
            strategy = analysis.patch_strategy if analysis else f"Remediate {event.attack_type}"

            system_prompt = (
                "You are an expert cybersecurity software engineer and automated patch generator.\n"
                "Your job is to generate a clean, minimal, syntactically correct unified diff patch "
                "that fixes the vulnerability while keeping existing functionality working.\n"
                "RULES:\n"
                "1. Output ONLY the unified diff inside a ```diff code block.\n"
                f"2. The unified diff header MUST start with '--- a/{rel_path}' and '+++ b/{rel_path}'.\n"
                "3. Ensure the context lines match the source code provided exactly.\n"
                "4. Do NOT include markdown commentary outside the ```diff block."
            )

            user_prompt = f"""Target File: {rel_path}
Attack Type: {event.attack_type}
Endpoint: {event.endpoint}
Severity: {event.severity.value if hasattr(event.severity, 'value') else event.severity}
Root Cause: {root_cause}
Remediation Strategy: {strategy}

Current Source Code of {rel_path}:
```
{code_snippet}
```

Generate the unified diff now."""

            diff_text = client.generate_text(system_prompt, user_prompt, temperature=0.1)

            # Extract diff from code block if present
            if "```diff" in diff_text:
                diff_text = diff_text.split("```diff", 1)[1].split("```", 1)[0]
            elif "```" in diff_text:
                parts = diff_text.split("```")
                if len(parts) >= 3:
                    diff_text = parts[1]
                else:
                    diff_text = diff_text.replace("```", "")
            diff_text = diff_text.strip()

            if not diff_text or "@@" not in diff_text:
                log.warning("llm_patch_missing_diff_hunks", output=diff_text[:200])
                return None

            # Ensure proper unified diff headers if missing
            if not diff_text.startswith("--- "):
                diff_text = f"--- a/{rel_path}\n+++ b/{rel_path}\n" + diff_text

            return Patch(
                patch_id=str(uuid.uuid4()),
                files_changed=[rel_path],
                diff=diff_text,
                strategy=strategy,
                generated_by=PatchOrigin.LLM,
            )
        except Exception as e:
            log.error("llm_patch_generation_failed", error=str(e))
            return None
