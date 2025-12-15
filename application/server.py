from flask import Flask, request, jsonify
from pathlib import Path
import time

from configuration import hash_mode, get_hash_params, protections, DummyMembersManager, GROUP_SEED

from .hash import get_hashing_function, get_hashing_verification_function
from .logger import Logger
from .database import Database

HTTP_OK = 200
HTTP_CREATED = 201
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_NOT_FOUND = 404


class AuthServer:
    def __init__(self, directory_path, selected_hash_mode=None, hash_params=None, enabled_protections=None):
        self._directory_path = Path(directory_path)

        self._database = Database(self._directory_path / "database.db")
        self._dummy_members_manager = DummyMembersManager(self._directory_path)

        self._hash_mode = selected_hash_mode or hash_mode
        self._hash_params = hash_params or get_hash_params(self._hash_mode)
        self._protections = enabled_protections or protections

        self._hash_function = get_hashing_function(self._hash_mode, self._hash_params, self._protections)
        self._verify_function = get_hashing_verification_function(self._hash_mode, self._hash_params, self._protections)

        self._app = Flask(__name__)
        self._register_routes()

        self._logger = Logger(self._directory_path, GROUP_SEED, self._hash_mode, self._hash_params, self._protections)

        self._register_dummy_members()  # Register Dummy members

    @property
    def dummy_members_manager(self) -> DummyMembersManager:
        return self._dummy_members_manager

    def _register_dummy_members(self):
        for member in self._dummy_members_manager.members:
            start_time = time.perf_counter()
            
            username = member["username"]
            self._database.insert_user(username, self._hash_function(member["password"]))
            
            end_time = time.perf_counter()
            
            self._logger.log_register(username, "success", HTTP_CREATED, "user created", start_time, end_time)

    def _register_routes(self):
        self._app.add_url_rule("/register", "register", self._register, methods=["POST"])
        self._app.add_url_rule("/login", "login", self._login, methods=["POST"])
        self._app.add_url_rule("/login_totp", "login_totp", self._login_totp, methods=["POST"])

    def _register_response(self, username, result, status, status_type, message, start_time, end_time):
        self._logger.log_register(username, result, status, message, start_time, end_time)
        return jsonify({status_type: message}), status

    def _login_response(self, username, result, status, status_type, message, start_time, end_time):
        self._logger.log_login(username, result, status, message, start_time, end_time)
        return jsonify({status_type: message}), status

    def _register_invalid_input(self, username, start_time):
        return self._register_response(
            username,
            "fail",
            HTTP_BAD_REQUEST,
            "error",
            "username and password are required",
            start_time,
            time.perf_counter()
        )

    def _register_success(self, username, start_time):
        return self._register_response(
            username,
            "success",
            HTTP_CREATED,
            "message",
            "user created",
            start_time,
            time.perf_counter()
        )

    def _login_invalid_input(self, username, start_time):
        return self._login_response(
            username,
            "fail",
            HTTP_BAD_REQUEST,
            "error",
            "username and password are required",
            start_time,
            time.perf_counter()
        )

    def _login_user_not_found(self, username, start_time):
        return self._login_response(
            username,
            "fail",
            HTTP_NOT_FOUND,
            "error",
            "user not found",
            start_time,
            time.perf_counter()
        )

    def _login_success(self, username, start_time):
        return self._login_response(
            username,
            "success",
            HTTP_OK,
            "message",
            "login success",
            start_time,
            time.perf_counter()
        )

    def _login_fail(self, username, start_time):
        return self._login_response(
            username,
            "fail",
            HTTP_UNAUTHORIZED,
            "error",
            "unauthorized attempt",
            start_time,
            time.perf_counter()
        )

    def _register(self):
        start_time = time.perf_counter()

        data = request.get_json(force=True)
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return self._register_invalid_input(username, start_time)

        self._dummy_members_manager.add_user(username, password, self._protections)
        self._database.insert_user(username, self._hash_function(password))

        return self._register_success(username, start_time)

    def _login(self):
        start_time = time.perf_counter()

        data = request.get_json(force=True)
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return self._login_invalid_input(username, start_time)

        stored_hashed_password = self._database.retrieve_user_hash(username)

        if not stored_hashed_password:
            return self._login_user_not_found(username, start_time)

        if self._verify_function(stored_hashed_password, password):
            return self._login_success(username, start_time)

        return self._login_fail(username, start_time)

    def _login_totp(self):
        print(self._hash_mode)
        return jsonify({"TODO": "to be implemented"})

    def close_database(self):
        self._database.close()

    def run(self, **kwargs):
        self._app.run(**kwargs)
