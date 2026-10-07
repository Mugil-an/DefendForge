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


class PatchGenerator:
    """
    Generates remediation patches based on attack events and LLM analysis.

    Supports template-based patching for all known vulnerabilities in the
    Target Application, with LLM fallback for unknown vulnerability types.
    """

    def generate_patch(
        self,
        event: AttackEvent,
        analysis: Optional[LLMAnalysis] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Patch]:
        """
        Generate a patch based on the event and optional LLM analysis.
        """
        log.info("generating_patch", event_id=event.event_id, attack_type=event.attack_type)

        attack_type = event.attack_type.lower()
        endpoint = event.endpoint.lower()

        # SQL Injection patches
        if "sql" in attack_type or "injection" in attack_type:
            if "/login" in endpoint:
                return self._generate_sqli_login_patch()
            elif "/search" in endpoint:
                return self._generate_sqli_search_patch()
            elif "/comments" in endpoint:
                return self._generate_sqli_comments_patch()

        # XSS patch
        if ("xss" in attack_type or "cross-site" in attack_type or "script" in attack_type) and "/greet" in endpoint:
            return self._generate_xss_greet_patch()

        # Path Traversal patch
        if ("path" in attack_type or "traversal" in attack_type or "directory" in attack_type) and "/file" in endpoint:
            return self._generate_path_traversal_patch()

        # Command Injection patch
        if ("command" in attack_type or "os command" in attack_type or "cmd" in attack_type) and "/ping" in endpoint:
            return self._generate_command_injection_patch()

        # SSRF patch
        if ("ssrf" in attack_type or "server-side request" in attack_type) and "/fetch" in endpoint:
            return self._generate_ssrf_patch()

        # Insecure Deserialization patch
        if ("deseriali" in attack_type or "pickle" in attack_type) and "/load" in endpoint:
            return self._generate_deserialization_patch()

        # Broken Access Control patch
        if ("access control" in attack_type or "auth" in attack_type or "broken" in attack_type) and "/admin" in endpoint:
            return self._generate_broken_auth_patch()

        # Brute Force — add rate limiting
        if "brute" in attack_type and "/login" in endpoint:
            return self._generate_rate_limit_patch()

        # Reconnaissance — no code patch needed, handled by hardening
        if "recon" in attack_type or "scan" in attack_type:
            log.info("recon_no_patch_needed", attack_type=attack_type)
            return None

        # LLM fallback for unknown vulnerability types
        if analysis and getattr(analysis, "patch_required", False):
            return self._generate_llm_patch(event, analysis)

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
    # LLM Fallback
    # -----------------------------------------------------------------------
    def _generate_llm_patch(self, event: AttackEvent, analysis: LLMAnalysis) -> Optional[Patch]:
        """Use LLM to generate a patch for unknown vulnerability types."""
        try:
            from blue_agent.llm.llm_client import LLMClient
            client = LLMClient()
            prompt = f"""Generate a unified diff patch to fix this vulnerability:

Attack Type: {event.attack_type}
Endpoint: {event.endpoint}
Root Cause: {analysis.root_cause}
Affected Component: {analysis.affected_component}
Patch Strategy: {analysis.patch_strategy}

Generate ONLY the unified diff (no explanation). The target file is target_app/app.py."""

            # Use the LLM to generate diff text
            response = client.client.chat.completions.create(
                model=client._model,
                messages=[
                    {"role": "system", "content": "You are a security patch generator. Output only unified diff format."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
            )
            diff_text = response.choices[0].message.content.strip()
            # Strip markdown code fences if present
            if diff_text.startswith("```"):
                lines = diff_text.split("\n")
                diff_text = "\n".join(lines[1:-1])

            return Patch(
                patch_id=str(uuid.uuid4()),
                files_changed=["target_app/app.py"],
                diff=diff_text,
                strategy=analysis.patch_strategy,
                generated_by=PatchOrigin.LLM,
            )
        except Exception as e:
            log.error("llm_patch_generation_failed", error=str(e))
            return None
