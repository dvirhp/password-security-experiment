from functools import partial

from flask import Flask, request, jsonify
from pathlib import Path
import time

from configuration import hash_mode, get_hash_params, protections, DummyMembersManager,\
    GROUP_SEED, get_environmental_pepper
from protection import ProtectionHandler

from .hash import get_hashing_function, get_hashing_verification_function
from .logger import Logger
from .database import Database
from .responses import ResponseHandler


class AuthServer:
    def __init__(self, directory_path, selected_hash_mode=None, hash_parameters=None, enabled_protections=None):
        self._directory_path = Path(directory_path)

        self._database = Database(self._directory_path / "database.db")
        self._dummy_members_manager = DummyMembersManager(self._directory_path)
        self._protection_handler = self._hash_function = self._verify_function = self._response_handler = None

        self._setup(selected_hash_mode, hash_parameters, enabled_protections)

        self._register_dummy_members()  # Register Dummy members

        self._app = Flask(__name__)
        self._register_routes()

    def _setup(self, selected_hash_mode=None, hash_parameters=None, enabled_protections=None):
        selected_hash_mode = selected_hash_mode or hash_mode
        hash_parameters = hash_parameters or get_hash_params(selected_hash_mode)
        enabled_protections = enabled_protections or protections
        pepper = enabled_protections.get("pepper", []) or get_environmental_pepper()
        logger = Logger(self._directory_path, GROUP_SEED, hash_mode, hash_parameters, enabled_protections)

        self._protection_handler = ProtectionHandler(enabled_protections)
        self._hash_function = get_hashing_function(selected_hash_mode, hash_parameters, pepper)
        self._verify_function = get_hashing_verification_function(selected_hash_mode, hash_parameters, pepper)
        self._response_handler = ResponseHandler(logger)

    @property
    def dummy_members_manager(self) -> DummyMembersManager:
        return self._dummy_members_manager

    def _register_dummy_members(self):
        for member in self._dummy_members_manager.members:
            start_time = time.perf_counter()

            username = member["username"]
            self._database.insert_user(username, self._hash_function(member["password"]))
            self._response_handler.register_dummy_member("system", username, start_time)

    def _register_routes(self):
        self._app.add_url_rule("/register", "register", self._register, methods=["POST"])
        self._app.add_url_rule("/login", "login", self._login, methods=["POST"])
        self._app.add_url_rule("/login_totp", "login_totp", self._login_totp, methods=["POST"])
        self._app.add_url_rule(
            "/admin/get_captcha_token", "get_captcha_token", self._get_captcha_token, methods=["GET"]
        )
        self._app.add_url_rule("/captcha_verify", "captcha_verify", self._captcha_verify, methods=["POST"])

    def _register(self):
        start_time = time.perf_counter()

        data = request.get_json(force=True)
        username = data.get("username")
        password = data.get("password")
        ip_address = request.remote_addr

        if not username or not password or not ip_address:
            return self._response_handler.register_invalid_input(ip_address, username, start_time)

        self._dummy_members_manager.add_user(username, password, self._protection_handler.totp_enabled)
        self._database.insert_user(username, self._hash_function(password))

        return self._response_handler.register_success(ip_address, username, start_time)

    def _login(self):
        start_time = time.perf_counter()

        data = request.get_json(force=True)
        username = data.get("username")
        password = data.get("password")
        ip_address = request.remote_addr or None

        # Rate limit
        if self._protection_handler.rate_limiter_allow_request(ip_address):
            return self._response_handler.login_too_many_requests(ip_address, username, start_time)

        # Captcha gate (hard stop)
        if self._protection_handler.captcha_blocked(ip_address):
            return self._response_handler.login_captcha_blocked(ip_address, username, start_time)

        if self._protection_handler.captcha_required(ip_address):
            return self._response_handler.login_captcha_required(ip_address, username, start_time)

        if not username or not password:
            return self._response_handler.login_invalid_input(ip_address, username, start_time)

        stored_hashed_password = self._database.retrieve_user_hash(username)

        if not stored_hashed_password:
            return self._response_handler.login_user_not_found(ip_address, username, start_time)

        verify_callable = partial(self._verify_function, stored_hashed_password, password)

        if self._protection_handler.lockout:
            return self._protection_handler.handle_lockout(
                self._response_handler, verify_callable, ip_address, username, start_time
            )

        if verify_callable():
            self._protection_handler.reset_captcha_failures(ip_address)
            return self._response_handler.login_success(ip_address, username, start_time)

        self._protection_handler.captcha.register_failure(ip_address)
        return self._response_handler.login_fail(ip_address, username, start_time)

    def _captcha_verify(self):
        data = request.get_json(force=True)
        token = data.get("token", "")
        ip_address = request.remote_addr or None

        if self._protection_handler.captcha.validate_token(token, ip_address):
            self._protection_handler.reset_captcha_failures(ip_address)
            return self._response_handler.valid_captcha()

        return self._response_handler.invalid_captcha()

    def _get_captcha_token(self):
        seed = request.args.get("group_seed")
        ip_address = request.remote_addr

        if seed != GROUP_SEED:
            return self._response_handler.invalid_captcha()

        token = self._protection_handler.captcha.generate_captcha_token(GROUP_SEED, ip_address)
        return self._response_handler.get_token_captcha(token)

    def _login_totp(self):
        print(self._protection_handler.totp_enabled)
        return jsonify({"TODO": "to be implemented"})

    def close_database(self):
        self._database.close()

    def run(self, **kwargs):
        self._app.run(**kwargs)
