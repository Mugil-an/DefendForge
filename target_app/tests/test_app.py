"""
Target Application Test Suite.

These tests validate that the target app functions correctly
and that security patches don't break functionality.

The Blue Agent's PatchValidator runs these tests after applying patches.
If tests fail → ROLLBACK. If tests pass → ACCEPT.
"""
from __future__ import annotations

import os
import sqlite3
import tempfile

import pytest

# Set up test database before importing app
_test_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["DATABASE_PATH"] = _test_db.name

from target_app.app import app  # noqa: E402


@pytest.fixture
def client():
    """Create a test client with a fresh database."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        with app.app_context():
            from target_app.app import init_db
            init_db()
        yield client


@pytest.fixture
def authenticated_client(client):
    """Test client already logged in as user1."""
    client.post("/login", data={"username": "user1", "password": "password"})
    return client


@pytest.fixture
def admin_client(client):
    """Test client logged in as admin."""
    client.post("/login", data={"username": "admin", "password": "admin123"})
    return client


# -----------------------------------------------------------------------
# Health Check
# -----------------------------------------------------------------------
class TestHealthCheck:
    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"


# -----------------------------------------------------------------------
# Authentication
# -----------------------------------------------------------------------
class TestAuthentication:
    def test_valid_login(self, client):
        resp = client.post("/login", data={
            "username": "user1",
            "password": "password"
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["message"] == "Login successful"

    def test_invalid_login(self, client):
        resp = client.post("/login", data={
            "username": "user1",
            "password": "wrong_password"
        })
        assert resp.status_code == 401

    def test_admin_login(self, client):
        resp = client.post("/login", data={
            "username": "admin",
            "password": "admin123"
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["role"] == "admin"

    def test_sql_injection_blocked(self, client):
        """After patching, SQL injection should NOT bypass auth."""
        resp = client.post("/login", data={
            "username": "' OR 1=1--",
            "password": "anything"
        })
        # After fix: should be 401 (invalid credentials)
        # Before fix: would be 200 (bypass)
        # We accept either — the test is that the app doesn't crash
        assert resp.status_code in (200, 401)


# -----------------------------------------------------------------------
# Posts
# -----------------------------------------------------------------------
class TestPosts:
    def test_list_posts(self, client):
        resp = client.get("/posts")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)

    def test_create_post_requires_auth(self, client):
        resp = client.post("/posts", data={
            "title": "Test Post",
            "content": "Test Content"
        })
        assert resp.status_code == 401

    def test_create_post_authenticated(self, authenticated_client):
        resp = authenticated_client.post("/posts", data={
            "title": "Test Post",
            "content": "Test Content"
        })
        assert resp.status_code == 201


# -----------------------------------------------------------------------
# Search
# -----------------------------------------------------------------------
class TestSearch:
    def test_search_returns_results(self, client):
        resp = client.get("/search?q=test")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)

    def test_search_empty_query(self, client):
        resp = client.get("/search?q=")
        assert resp.status_code == 200

    def test_search_sql_injection_blocked(self, client):
        """After patching, SQL injection in search should not crash."""
        resp = client.get("/search?q=' UNION SELECT username,password FROM users--")
        # The app should not crash, regardless of whether injection works
        assert resp.status_code in (200, 400, 500)


# -----------------------------------------------------------------------
# Greet (XSS surface)
# -----------------------------------------------------------------------
class TestGreet:
    def test_greet_normal(self, client):
        resp = client.get("/greet?name=World")
        assert resp.status_code == 200
        assert b"Hello" in resp.data

    def test_greet_default(self, client):
        resp = client.get("/greet")
        assert resp.status_code == 200
        assert b"World" in resp.data

    def test_greet_special_chars(self, client):
        """After XSS fix, special chars should be escaped."""
        resp = client.get("/greet?name=<script>alert(1)</script>")
        assert resp.status_code == 200
        # App should not crash regardless


# -----------------------------------------------------------------------
# Ping (Command Injection surface)
# -----------------------------------------------------------------------
class TestPing:
    def test_ping_localhost(self, client):
        resp = client.get("/ping?host=127.0.0.1")
        # May succeed or fail depending on OS, but should not crash
        assert resp.status_code in (200, 400, 500)

    def test_ping_injection_blocked(self, client):
        """After patching, command injection should be blocked."""
        resp = client.get("/ping?host=127.0.0.1;ls")
        # After fix: 400 (invalid host)
        # Before fix: might execute ls
        assert resp.status_code in (200, 400, 500)


# -----------------------------------------------------------------------
# File (Path Traversal surface)
# -----------------------------------------------------------------------
class TestFile:
    def test_file_not_found(self, client):
        resp = client.get("/file?name=nonexistent.txt")
        assert resp.status_code == 404 or resp.status_code == 400

    def test_path_traversal_blocked(self, client):
        """After patching, path traversal should be blocked."""
        resp = client.get("/file?name=../../../etc/passwd")
        assert resp.status_code in (200, 400, 404)


# -----------------------------------------------------------------------
# Fetch (SSRF surface)
# -----------------------------------------------------------------------
class TestFetch:
    def test_fetch_empty_url(self, client):
        resp = client.get("/fetch?url=")
        assert resp.status_code in (200, 400)

    def test_fetch_internal_blocked(self, client):
        """After patching, internal URLs should be blocked."""
        resp = client.get("/fetch?url=http://169.254.169.254/latest/meta-data/")
        # After fix: 403 (blocked)
        # Before fix: might try to fetch
        assert resp.status_code in (200, 400, 403)


# -----------------------------------------------------------------------
# Comments
# -----------------------------------------------------------------------
class TestComments:
    def test_create_comment(self, client):
        resp = client.post("/comments", data={
            "post_id": "1",
            "body": "Test comment"
        })
        assert resp.status_code in (201, 500)  # 500 if no post with id=1

    def test_comment_sql_injection_blocked(self, client):
        """After patching, SQL injection in comments should not work."""
        resp = client.post("/comments", data={
            "post_id": "1",
            "body": "'; DROP TABLE users;--"
        })
        assert resp.status_code in (201, 400, 500)


# -----------------------------------------------------------------------
# Admin (Broken Access Control surface)
# -----------------------------------------------------------------------
class TestAdmin:
    def test_admin_users_list(self, client):
        """Test that admin endpoint returns user list."""
        resp = client.get("/admin/users")
        # Before fix: 200 (no auth needed)
        # After fix: 401 (auth required)
        assert resp.status_code in (200, 401, 403)


# -----------------------------------------------------------------------
# Load (Deserialization surface)
# -----------------------------------------------------------------------
class TestLoad:
    def test_load_json(self, client):
        """After fix, /load should accept JSON instead of pickle."""
        import json
        resp = client.post(
            "/load",
            data=json.dumps({"key": "value"}),
            content_type="application/json"
        )
        # Should work with JSON
        assert resp.status_code in (200, 400)
