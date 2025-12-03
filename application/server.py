from flask import Flask, request, jsonify

from configuration import hash_mode, protections, add_user

from .hash import get_hashing_function, get_hashing_verification_function


class AuthServer:
    def __init__(self, database, selected_hash_mode=None, enabled_protections=None):
        self._database = database
        self._hash_mode = selected_hash_mode or hash_mode
        self._protections = enabled_protections or protections

        self._hash_function = get_hashing_function(self._hash_mode, self._protections)
        self._verify_function = get_hashing_verification_function(self._hash_mode, self._protections)

        self._app = Flask(__name__)
        self._register_routes()

    def _register_routes(self):
        self._app.add_url_rule("/register", "register", self._register, methods=["POST"])
        self._app.add_url_rule("/login", "login", self._login, methods=["POST"])
        self._app.add_url_rule("/login_totp", "login_totp", self._login_totp, methods=["POST"])

    def _register(self):
        data = request.get_json(force=True)
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "username and password are required"}), 400

        # hashed_password = self._hash_function(password)
        add_user(username, password, self._protections)  # Adds username and un-hashed password to users.json
        self._database.insert_user(username, self._hash_function(password))

        return jsonify({"message": "user created"}), 201

    def _login(self):
        data = request.get_json(force=True)
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "username and password are required"}), 400

        stored_hashed_password = self._database.retrieve_user_hash(username)

        if not stored_hashed_password:
            return jsonify({"error": "user not found"}), 404

        if self._verify_function(stored_hashed_password, password):
            return jsonify({"message": "login success"}), 200

        return jsonify({"error": "wrong password"}), 401

    def _login_totp(self):
        print(self._hash_mode)
        return jsonify({"TODO": "to be implemented"})

    def run(self, **kwargs):
        self._app.run(**kwargs)
