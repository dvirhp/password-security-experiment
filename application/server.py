from flask import Flask, request, jsonify
from pathlib import Path
import time

from configuration import hash_mode, get_hash_params, protections, DummyMembersManager, GROUP_SEED
from protection import RateLimiter, Lockout
from protection.captcha import Captcha
from protection.totp import TOTP

from .hash import get_hashing_function, get_hashing_verification_function
from .logger import Logger
from .database import Database
from .responses import ResponseHandler


class AuthServer:
    def __init__(self, directory_path, selected_hash_mode=None, hash_params=None, enabled_protections=None):
        self._directory_path = Path(directory_path)

        self._database = Database(self._directory_path / "database.db")
        self._dummy_members_manager = DummyMembersManager(self._directory_path)

        self._hash_mode = selected_hash_mode or hash_mode
        self._hash_params = hash_params or get_hash_params(self._hash_mode)
        self._protections = enabled_protections or protections

        self._rate_limiter = RateLimiter() if self._protections.get("rate_limit_enabled", False) else None
        self._lockout = Lockout() if self._protections.get("lockout_enabled", False) else None
        self._captcha = Captcha() if self._protections.get("captcha_enabled", False) else None
        self._totp = TOTP() if self._protections.get("totp_enabled", False) else None

        self._hash_function = get_hashing_function(self._hash_mode, self._hash_params, self._protections)
        self._verify_function = get_hashing_verification_function(self._hash_mode, self._hash_params, self._protections)

        self._app = Flask(__name__)
        self._register_routes()

        self._logger = Logger(self._directory_path, GROUP_SEED, self._hash_mode, self._hash_params, self._protections)
        self._response_handler = ResponseHandler(self._logger)

        self._register_dummy_members()  # Register Dummy members

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

    def _register(self):
        start_time = time.perf_counter()

        data = request.get_json(force=True)
        username = data.get("username")
        password = data.get("password")
        ip_address = request.remote_addr

        if not username or not password or not ip_address:
            return self._response_handler.register_invalid_input(ip_address, username, start_time)

        self._dummy_members_manager.add_user(username, password, self._protections)
        self._database.insert_user(username, self._hash_function(password))

        return self._response_handler.register_success(ip_address, username, start_time)

    def _login(self):
        start_time = time.perf_counter()

        data = request.get_json(force=True)
        username = data.get("username")
        password = data.get("password")
        ip_address = request.remote_addr or None

        if self._rate_limiter and not self._rate_limiter.allow_request(ip_address):
            return self._response_handler.login_too_many_requests(ip_address, username, start_time)

        if not username or not password:
            return self._response_handler.login_invalid_input(ip_address, username, start_time)
        
        captcha_token = data.get("captcha_token")

        if self._captcha:
            self._captcha.apply_delay()

            if not captcha_token or not self._captcha.verify_token(captcha_token):
                return self._response_handler.login_captcha_required(
                    ip_address, username, start_time
                )
        
        stored_hashed_password = self._database.retrieve_user_hash(username)

        if not stored_hashed_password:
            return self._response_handler.login_user_not_found(ip_address, username, start_time)

        if self._lockout:
            return self._check_lockout(ip_address, username, start_time, stored_hashed_password, password)

        password_ok = self._verify_function(stored_hashed_password, password)

        if password_ok:
            if self._protections.get("totp_enabled", False):
                return self._response_handler.login_totp_required(
                    ip_address, username, start_time
                )

            return self._response_handler.login_success(
                ip_address, username, start_time
            )

        return self._response_handler.login_fail(
            ip_address, username, start_time
        )

    def _check_lockout(self, ip_address, username, start_time, stored_hashed_password, password):
        allowed, message = self._lockout.allow_attempt(username)
        if not allowed:
            return self._response_handler.login_lockout(ip_address, username, message, start_time)
        elif self._verify_function(stored_hashed_password, password):
            self._lockout.reset_after_successful_login(username)
            return self._response_handler.login_success(ip_address, username, start_time)
        return self._response_handler.login_fail(ip_address, username, start_time)

    def _login_totp(self):
        start_time = time.perf_counter()

        data = request.get_json(force=True)
        username = data.get("username")
        totp_code = data.get("totp")
        ip_address = request.remote_addr

        if not username or not totp_code:
            return self._response_handler.login_invalid_input(
                ip_address, username, start_time
            )

        if not self._protections.get("totp_enabled", False):
            return self._response_handler.login_fail(
                ip_address, username, start_time
            )

        if totp_code != "123456":
            return self._response_handler.login_totp_invalid(
                ip_address, username, start_time
            )

        return self._response_handler.login_success(
            ip_address, username, start_time
        )

    def close_database(self):
        self._database.close()

    def run(self, **kwargs):
        self._app.run(**kwargs)
