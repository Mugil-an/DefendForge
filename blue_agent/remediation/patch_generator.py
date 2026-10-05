"""
Patch Generator — Automatically generates code fixes for detected vulnerabilities.
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
    
    For the MVP, we support template-based patching for known vulnerabilities
    in the Target Application (e.g., swapping a vulnerable SQL query for a 
    parameterized one). We also support falling back to an LLM for unknown vulnerabilities.
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
        
        if "sql" in attack_type:
            if "/login" in endpoint:
                return self._generate_sqli_login_patch()
            elif "/search" in endpoint:
                return self._generate_sqli_search_patch()
            elif "/comments" in endpoint:
                return self._generate_sqli_comments_patch()
            
        if ("xss" in attack_type or "cross-site scripting" in attack_type) and "/greet" in endpoint:
            return self._generate_xss_greet_patch()
            
        if "path" in attack_type and "/file" in endpoint:
            return self._generate_path_traversal_patch()

        # LLM fallback
        if analysis and getattr(analysis, "patch_required", False):
            return self._generate_llm_patch(event, analysis)

        log.warning("no_patch_template_available", attack_type=event.attack_type, endpoint=event.endpoint)
        return None

    def _generate_sqli_login_patch(self) -> Patch:
        """Template patch for the intentionally vulnerable /login route."""
        diff = """--- target_app/app.py
+++ target_app/app.py
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
        diff = """--- target_app/app.py
+++ target_app/app.py
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
        diff = """--- target_app/app.py
+++ target_app/app.py
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

    def _generate_xss_greet_patch(self) -> Patch:
        """Template patch for the intentionally vulnerable /greet route."""
        diff = """--- target_app/app.py
+++ target_app/app.py
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
        
    def _generate_path_traversal_patch(self) -> Patch:
        """Template patch for the intentionally vulnerable /file route."""
        diff = """--- target_app/app.py
+++ target_app/app.py
@@ -139,5 +139,6 @@
 @app.route("/file")
 def read_file():
     filename = request.args.get("name", "")
-    filepath = os.path.join("/tmp/uploads", filename)  # noqa: S108
+    from werkzeug.utils import secure_filename
+    filepath = os.path.join("/tmp/uploads", secure_filename(filename))  # noqa: S108
     try:
         with open(filepath) as f:"""
        return Patch(
            patch_id=str(uuid.uuid4()),
            files_changed=["target_app/app.py"],
            diff=diff,
            strategy="secure_filename",
            generated_by=PatchOrigin.TEMPLATE
        )

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
            response = client._client.chat.completions.create(
                model=client._settings.model,
                messages=[
                    {"role": "system", "content": "You are a security patch generator. Output only unified diff format."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
            )
            diff_text = response.choices[0].message.content.strip()
            # Strip markdown code fences if present
            if diff_text.startswith("```"):
                lines = diff_text.split("\\n")
                diff_text = "\\n".join(lines[1:-1])
            
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
