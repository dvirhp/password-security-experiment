from flask import Flask, request, jsonify
import time

from db import get_db, init_db
from logger import log_attempt

# load config + hashing engine
from configuration.config import config
from hash import get_hashing_function, get_hashing_verification_function

app = Flask(__name__)

# hashing utilities
hash_func = get_hashing_function(config.hash_mode)
verify_func = get_hashing_verification_function(config.hash_mode)


@app.route("/register", methods=["POST"])
def register():
    # extract input
    data = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    # hash password using system hasher
    password_hash = hash_func(password)

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, salt, strength) VALUES (?, ?, ?, ?)",
            (username, password_hash, "", "manual"),
        )
        conn.commit()
    except Exception:
        conn.close()
        return jsonify({"error": "username already exists"}), 400

    conn.close()
    return jsonify({"message": "user created"}), 201


@app.route("/login", methods=["POST"])
def login():
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

    if not user:
        latency_ms = (time.time() - start) * 1000
        log_attempt(username, "fail_user_not_found", latency_ms)
        conn.close()
        return jsonify({"error": "user not found"}), 404

    stored_hash = user["password_hash"]

    if verify_func(stored_hash, password):
        latency_ms = (time.time() - start) * 1000
        log_attempt(username, "success", latency_ms)
        conn.close()
        return jsonify({"message": "login success"}), 200

    latency_ms = (time.time() - start) * 1000
    log_attempt(username, "fail_wrong_password", latency_ms)
    conn.close()
    return jsonify({"error": "wrong password"}), 401


if __name__ == "__main__":
    init_db()
    app.run(port=5000, debug=True)
