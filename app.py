from flask import Flask, request, jsonify
import time

from db import get_db, init_db
from security import generate_salt, hash_password, verify_password
from logger import log_attempt
from config import CONFIG

app = Flask(__name__)

@app.route("/register", methods=["POST"])
def register():
    # Create a new user with provided username and password
    data = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    # Generate per-user salt only in sha256 mode
    match CONFIG["hash_mode"]:
        case "sha256":
            salt = generate_salt()
        case _:
            salt = ""

    password_hash = hash_password(password, salt)

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, salt, strength) VALUES (?, ?, ?, ?)",
            (username, password_hash, salt, "manual"),
        )
        conn.commit()
    except Exception:
        conn.close()
        return jsonify({"error": "username already exists"}), 400

    conn.close()
    return jsonify({"message": "user created"}), 201


@app.route("/login", methods=["POST"])
def login():
    # Validate login and record timing/log attempts
    start = time.time()

    data = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()

    # User not found
    if not user:
        latency_ms = (time.time() - start) * 1000
        log_attempt(username, "fail_user_not_found", latency_ms)
        conn.close()
        return jsonify({"error": "user not found"}), 404

    salt = user["salt"]
    stored_hash = user["password_hash"]

    # Successful login
    if verify_password(password, salt, stored_hash):
        latency_ms = (time.time() - start) * 1000
        log_attempt(username, "success", latency_ms)
        conn.close()
        return jsonify({"message": "login success"}), 200

    # Wrong password
    latency_ms = (time.time() - start) * 1000
    log_attempt(username, "fail_wrong_password", latency_ms)
    conn.close()
    return jsonify({"error": "wrong password"}), 401


if __name__ == "__main__":
    init_db()
    app.run(port=5000, debug=True)
