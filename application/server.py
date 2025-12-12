from flask import Flask, request, jsonify

from configuration import hash_mode, protections, add_user

from .hash import get_hashing_function, get_hashing_verification_function

import time

from configuration import GROUP_SEED

from .logger import AttemptLogger

class AuthServer:
    def __init__(self, database, selected_hash_mode=None, enabled_protections=None):
        self._database = database
        self._hash_mode = selected_hash_mode or hash_mode
        self._protections = enabled_protections or protections

        self._hash_function = get_hashing_function(self._hash_mode, self._protections)
        self._verify_function = get_hashing_verification_function(self._hash_mode, self._protections)

        self._app = Flask(__name__)
        self._register_routes()

        self._logger = AttemptLogger(
            log_path="attempts.log",
            group_seed=GROUP_SEED
        )

    def _register_routes(self):
        self._app.add_url_rule("/register", "register", self._register, methods=["POST"])
        self._app.add_url_rule("/login", "login", self._login, methods=["POST"])
        self._app.add_url_rule("/login_totp", "login_totp", self._login_totp, methods=["POST"])

    def _register(self):
        start_time = time.time()

        data = request.get_json(force=True)
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            self._logger.log(
                username=username,
                result="fail_missing_fields",
                hash_mode=self._hash_mode,
                protection_flags=self._protections,
                start_time=start_time,
                action="register"
            )
            return jsonify({"error": "username and password are required"}), 400

        add_user(username, password, self._protections)
        self._database.insert_user(username, self._hash_function(password))

        self._logger.log(
            username=username,
            result="success",
            hash_mode=self._hash_mode,
            protection_flags=self._protections,
            start_time=start_time,
            action="register"
        )

        return jsonify({"message": "user created"}), 201


    def _login(self):
        start_time = time.time()

        data = request.get_json(force=True)
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "username and password are required"}), 400

        stored_hashed_password = self._database.retrieve_user_hash(username)

        if not stored_hashed_password:
            self._logger.log(
                username=username,
                result="fail_user_not_found",
                hash_mode=self._hash_mode,
                protection_flags=self._protections,
                start_time=start_time,
                action="login"
            )
            return jsonify({"error": "user not found"}), 404

        if self._verify_function(stored_hashed_password, password):
            self._logger.log(
                username=username,
                result="success",
                hash_mode=self._hash_mode,
                protection_flags=self._protections,
                start_time=start_time,
                action="login"
            )
            return jsonify({"message": "login success"}), 200

        self._logger.log(
            username=username,
            result="fail_wrong_password",
            hash_mode=self._hash_mode,
            protection_flags=self._protections,
            start_time=start_time,
            action="login"
        )
        return jsonify({"error": "wrong password"}), 401

    def _login_totp(self):
        print(self._hash_mode)
        return jsonify({"TODO": "to be implemented"})

    def run(self, **kwargs):
        self._app.run(**kwargs)
