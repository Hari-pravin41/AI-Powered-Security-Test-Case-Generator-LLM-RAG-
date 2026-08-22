"""
vulnerable_target/app.py — a small, deliberately vulnerable REST API.

⚠️ FOR LOCAL SECURITY TESTING ONLY. Do not deploy this anywhere reachable
from the internet — every endpoint here is intentionally broken so SentinelAI
has something real (but safe) to find.

Vulnerabilities implemented, matching the OWASP categories in the knowledge base:
  - GET  /api/v1/users/search?q=      -> SQL Injection (A03)
  - POST /api/v1/orders/<id>/refund   -> Broken Object Level Authorization (A01)
  - POST /api/v1/auth/login           -> No rate limiting (A07)
  - GET  /api/v1/health               -> Version disclosure in headers (A05)
"""

import sqlite3
import time

from flask import Flask, g, jsonify, request

app = Flask(__name__)
DB_PATH = "/tmp/sentinelai_vulnerable_target.db"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute("DROP TABLE IF EXISTS orders")
    conn.execute("""CREATE TABLE users (
        id INTEGER PRIMARY KEY, email TEXT, name TEXT, password TEXT)""")
    conn.execute("""CREATE TABLE orders (
        id INTEGER PRIMARY KEY, owner_id INTEGER, amount INTEGER, refunded INTEGER DEFAULT 0)""")
    conn.executemany("INSERT INTO users VALUES (?,?,?,?)", [
        (1, "alice@acme.com", "Alice", "hunter2"),
        (2, "bob@acme.com", "Bob", "letmein"),
        (3, "victim@acme.com", "Victim User", "correct-horse-battery"),
    ])
    conn.executemany("INSERT INTO orders VALUES (?,?,?,?)", [
        (101, 1, 4999, 0),
        (102, 2, 1299, 0),
        (103, 3, 8800, 0),
    ])
    conn.commit()
    conn.close()


# ---- A03: Injection — string-concatenated SQL, deliberately unsafe ----
@app.route("/api/v1/users/search")
def search_users():
    q = request.args.get("q", "")
    db = get_db()
    # VULNERABLE ON PURPOSE: naive string concatenation, no parameterization
    query = f"SELECT id, email, name FROM users WHERE name LIKE '%{q}%'"
    try:
        rows = db.execute(query).fetchall()
        return jsonify({"results": [dict(r) for r in rows]})
    except sqlite3.Error as e:
        return jsonify({"error": str(e), "query": query}), 500


# ---- A01: Broken Object Level Authorization ----
LOGGED_IN_USER_ID = 1  # simulates "whoever holds this demo token" — always user 1


@app.route("/api/v1/orders/<int:order_id>/refund", methods=["POST"])
def refund_order(order_id):
    db = get_db()
    row = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if row is None:
        return jsonify({"error": "not_found"}), 404
    # VULNERABLE ON PURPOSE: no check that row["owner_id"] == LOGGED_IN_USER_ID
    db.execute("UPDATE orders SET refunded = 1 WHERE id = ?", (order_id,))
    db.commit()
    return jsonify({
        "refund_id": f"rf_{order_id}_001",
        "status": "processed",
        "order_owner": row["owner_id"],
        "requested_by": LOGGED_IN_USER_ID,
    })


# ---- A07: No rate limiting on login ----
@app.route("/api/v1/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    password = data.get("password", "")
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    # VULNERABLE ON PURPOSE: no attempt counter, no lockout, no delay
    if row and row["password"] == password:
        return jsonify({"token": "demo-token", "user_id": row["id"]})
    return jsonify({"error": "invalid_credentials"}), 401


# ---- A05: Security misconfiguration — version disclosure ----
@app.route("/api/v1/health")
def health():
    resp = jsonify({"status": "ok"})
    # VULNERABLE ON PURPOSE: explicit version disclosure headers
    resp.headers["X-Powered-By"] = "Flask/3.0.0"
    resp.headers["Server"] = "Werkzeug/3.0.1 Python/3.11.6"
    return resp


@app.route("/api/v1/spec")
def spec():
    """A tiny hand-rolled endpoint list, standing in for a real OpenAPI spec."""
    return jsonify({
        "endpoints": [
            {"method": "GET", "path": "/api/v1/users/search"},
            {"method": "POST", "path": "/api/v1/orders/{id}/refund"},
            {"method": "POST", "path": "/api/v1/auth/login"},
            {"method": "GET", "path": "/api/v1/health"},
        ]
    })


if __name__ == "__main__":
    init_db()
    print("Vulnerable target running at http://127.0.0.1:5001")
    print("FOR LOCAL TESTING ONLY — do not expose this port publicly.")
    app.run(port=5001, debug=False)
else:
    init_db()