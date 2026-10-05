"""
Knowledge Ingestion — Utilities for bootstrapping the RAG vector store
with standard cybersecurity knowledge.
"""

from __future__ import annotations

from blue_agent.logging_cfg import get_logger
from blue_agent.rag.retriever import Retriever

log = get_logger("rag.ingestion")

# A minimal knowledge base for the MVP.
# In a real scenario, this would be loaded from JSON/Markdown files.
INITIAL_KNOWLEDGE = [
    {
        "text": "SQL Injection (SQLi) occurs when user input is incorrectly filtered, allowing an attacker to manipulate backend database queries. Remediation: Use parameterized queries (prepared statements) or ORM frameworks instead of string concatenation.",
        "metadata": {"source": "OWASP", "category": "Vulnerability", "cwe": "CWE-89"}
    },
    {
        "text": "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users. Remediation: Context-aware output encoding (escaping) and strict Content Security Policy (CSP).",
        "metadata": {"source": "OWASP", "category": "Vulnerability", "cwe": "CWE-79"}
    },
    {
        "text": "Path Traversal (Directory Traversal) aims to access files outside the intended web root (e.g. ../../etc/passwd). Remediation: Validate input against an allowlist, use absolute paths, and restrict filesystem permissions.",
        "metadata": {"source": "OWASP", "category": "Vulnerability", "cwe": "CWE-22"}
    },
    {
        "text": "Command Injection (OS Command Injection) involves executing arbitrary system commands via vulnerable applications. Remediation: Avoid calling OS commands directly; if necessary, strictly validate input and do not pass shell=True.",
        "metadata": {"source": "OWASP", "category": "Vulnerability", "cwe": "CWE-78"}
    },
    {
        "text": "Rate Limiting and Blocking: For brute force attacks, reconnaissance scanning, or repeated exploitation attempts, blocking the offending Source IP or temporarily rate-limiting their requests is a highly effective initial containment strategy.",
        "metadata": {"source": "Defensive Tactics", "category": "Containment"}
    },
    {
        "text": "Server-Side Request Forgery (SSRF) occurs when a web application fetches a remote resource without validating the user-supplied URL. Remediation: Validate URLs against a strict allowlist of domains or IPs, avoid resolving internal hostnames, and implement network segmentation to restrict outbound access.",
        "metadata": {"source": "OWASP", "category": "Vulnerability", "cwe": "CWE-918"}
    },
    {
        "text": "Insecure Deserialization leads to remote code execution or privilege escalation when user-controllable data is deserialized without validation. Remediation: Avoid using unsafe serialization formats like Python's pickle; prefer safe formats like JSON. Implement strict type and input validation before processing.",
        "metadata": {"source": "OWASP", "category": "Vulnerability", "cwe": "CWE-502"}
    },
    {
        "text": "Broken Access Control allows users to act outside their intended permissions, leading to unauthorized data access or modification. Remediation: Apply the principle of least privilege, implement Role-Based Access Control (RBAC), and enforce authentication and authorization checks on all endpoints.",
        "metadata": {"source": "OWASP", "category": "Vulnerability", "cwe": "A01:2021"}
    },
    {
        "text": "Security Logging and Monitoring failures allow breaches to remain undetected for long periods. Remediation: Implement structured, comprehensive logging for all security-critical events (login, access control failures). Establish proactive alerting and secure, tamper-evident audit trails.",
        "metadata": {"source": "OWASP", "category": "Vulnerability", "cwe": "A09:2021"}
    },
    {
        "text": "Input Validation and Output Encoding are critical defense-in-depth measures against injection attacks. Remediation: Validate all untrusted input against strict allowlists rather than blocklists. Apply context-aware output encoding to prevent interpretation of malicious data by the client or backend.",
        "metadata": {"source": "Defensive Tactics", "category": "Mitigation"}
    },
    {
        "text": "Secure Session Management prevents attackers from hijacking active user sessions. Remediation: Generate strong, random session IDs to prevent session fixation, rotate tokens after authentication, set Secure and HttpOnly flags on cookies, and enforce strict session timeout policies.",
        "metadata": {"source": "OWASP", "category": "Mitigation"}
    },
    {
        "text": "Cryptographic Storage failures expose sensitive data like passwords or PII. Remediation: Hash passwords using strong, adaptive algorithms like bcrypt or Argon2 with unique salts. Employ secure key management practices and strictly avoid hardcoding secrets in source code.",
        "metadata": {"source": "OWASP", "category": "Mitigation"}
    },
    {
        "text": "Security Headers provide an additional layer of protection against client-side vulnerabilities. Remediation: Configure headers such as Content-Security-Policy (CSP) to mitigate XSS, X-Frame-Options to prevent clickjacking, Strict-Transport-Security (HSTS) for HTTPS enforcement, and X-Content-Type-Options.",
        "metadata": {"source": "Defensive Tactics", "category": "Hardening"}
    },
    {
        "text": "Vulnerable and Outdated Components pose a significant risk due to unpatched known flaws. Remediation: Implement Software Composition Analysis (SCA) and automated vulnerability scanning. Maintain a Software Bill of Materials (SBOM) and automate dependency updates.",
        "metadata": {"source": "OWASP", "category": "Vulnerability"}
    },
    {
        "text": "Container Security involves securing the runtime environment and images of containerized applications. Remediation: Use minimal base images (like Alpine or Distroless), run containers as non-root users, implement robust secrets management, and perform regular image vulnerability scanning.",
        "metadata": {"source": "Defensive Tactics", "category": "Hardening"}
    },
]


def ingest_initial_knowledge(retriever: Retriever) -> int:
    """
    Ingest the baseline security knowledge into the vector store.
    Returns the number of documents added.
    """
    # Check if we already have documents to avoid duplication in tests/demos
    if retriever.store._index is not None and retriever.store._index.ntotal > 0:
        log.info("rag_ingestion_skipped", reason="already_populated")
        return 0

    texts = [item["text"] for item in INITIAL_KNOWLEDGE]
    metadatas = [item["metadata"] for item in INITIAL_KNOWLEDGE]
    
    doc_ids = retriever.add_texts(texts, metadatas)
    log.info("rag_initial_knowledge_ingested", count=len(doc_ids))
    return len(doc_ids)
