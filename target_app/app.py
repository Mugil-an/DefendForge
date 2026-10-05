"""
Intentionally Vulnerable Flask Application — Target App

FOR RESEARCH ONLY.  This application contains deliberate security
vulnerabilities (SQL Injection, XSS, SSRF, path traversal, command
injection, insecure deserialization, weak auth) so the Blue Agent
can detect and remediate them.

DO NOT deploy this in any non-isolated environment.
"""

from __future__ import annotations

import os
import pickle
import sqlite3
import subprocess
from functools import wraps

from flask import Flask, g, jsonify, redirect, request, session

app = Flask(__name__)
app.secret_key = "super_secret_key_123"  # B105: hardcoded password

DATABASE = os.environ.get("DATABASE_PATH", "app.db")


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author_id INTEGER,
            FOREIGN KEY (author_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            body TEXT NOT NULL,
            FOREIGN KEY (post_id) REFERENCES posts(id)
        );
        INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin');
        INSERT OR IGNORE INTO users (username, password, role) VALUES ('user1', 'password', 'user');
    """)
    db.commit()


with app.app_context():
    init_db()


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# VULN: SQL Injection — string formatting in query
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"  # noqa: S608
    user = db.execute(query).fetchone()
    if user:
        session["user_id"] = user["id"]
        session["role"] = user["role"]
        return jsonify({"message": "Login successful", "role": user["role"]})
    return jsonify({"error": "Invalid credentials"}), 401


# VULN: SQL Injection on search
@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    results = db.execute(
        f"SELECT * FROM posts WHERE title LIKE '%{q}%'"  # noqa: S608
    ).fetchall()
    return jsonify([dict(r) for r in results])


# VULN: Reflected XSS
@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    return f"<html><body><h1>Hello, {name}!</h1></body></html>"


# VULN: Command Injection
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)  # noqa: S602
    return jsonify({"output": result})


# VULN: Path Traversal
@app.route("/file")
def read_file():
    filename = request.args.get("name", "")
    filepath = os.path.join("/tmp/uploads", filename)  # noqa: S108
    try:
        with open(filepath) as f:
            content = f.read()
        return jsonify({"content": content})
    except FileNotFoundError:
        return jsonify({"error": "Not found"}), 404


# VULN: Insecure Deserialization
@app.route("/load", methods=["POST"])
def load_object():
    data = request.get_data()
    obj = pickle.loads(data)  # noqa: S301
    return jsonify({"type": str(type(obj)), "repr": repr(obj)})


# VULN: SSRF
@app.route("/fetch")
def fetch_url():
    import urllib.request
    url = request.args.get("url", "")
    try:
        resp = urllib.request.urlopen(url)  # noqa: S310
        return resp.read().decode("utf-8", errors="replace")[:4096]
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


# VULN: Missing auth on admin endpoint
@app.route("/admin/users")
def admin_users():
    db = get_db()
    users = db.execute("SELECT id, username, role FROM users").fetchall()
    return jsonify([dict(u) for u in users])


# Authenticated CRUD
@app.route("/posts", methods=["GET"])
def list_posts():
    db = get_db()
    posts = db.execute("SELECT * FROM posts ORDER BY id DESC").fetchall()
    return jsonify([dict(p) for p in posts])


@app.route("/posts", methods=["POST"])
@login_required
def create_post():
    title = request.form.get("title", "")
    content = request.form.get("content", "")
    db = get_db()
    db.execute(
        "INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)",
        (title, content, session["user_id"]),
    )
    db.commit()
    return jsonify({"message": "Post created"}), 201


# VULN: SQL Injection in comment
@app.route("/comments", methods=["POST"])
def create_comment():
    post_id = request.form.get("post_id", "")
    body = request.form.get("body", "")
    db = get_db()
    db.execute(f"INSERT INTO comments (post_id, body) VALUES ({post_id}, '{body}')")  # noqa: S608
    db.commit()
    return jsonify({"message": "Comment added"}), 201


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)  # noqa: S104, S201
