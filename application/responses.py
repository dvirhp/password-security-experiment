import time
from flask import jsonify

from .http_status import HTTPStatus, CAPTCHA_REQUIRED, TOTP_REQUIRED, ACCOUNT_BLOCKED


class ResponseHandler:
    """
    Centralizes HTTP response creation and logging for authentication flows.

    Ensures consistent JSON responses, status codes, and logging
    for registration, login, and security challenge outcomes.
    """

    def __init__(self, logger):
        """
        Args:
            logger: Logger instance used to record authentication events.
        """
        self._logger = logger

    def _register_response(self, ip_address, username, result, status, status_type, message, start_time, end_time):
        """Log a registration attempt and return a standardized Flask response."""
        self._logger.log_register(ip_address, username, result, status, message, start_time, end_time)
        return jsonify({status_type: message}), status

    def _login_response(self, ip_address, username, result, status, status_type, message, start_time, end_time):
        """Log a login attempt and return a standardized Flask response."""
        self._logger.log_login(ip_address, username, result, status, message, start_time, end_time)
        return jsonify({status_type: message}), status

    def register_dummy_member(self, ip_address, username, start_time):
        """Log creation of a dummy user without returning a client response."""
        self._logger.log_register(
            ip_address,
            username,
            "success",
            HTTPStatus.CREATED,
            "user created",
            start_time,
            time.perf_counter()
        )

    def register_username_conflict(self, ip_address, username, start_time):
        """Handle registration when the username already exists."""
        return self._register_response(
            ip_address,
            username,
            "fail",
            HTTPStatus.CONFLICT,
            "error",
            "username already exists",
            start_time,
            time.perf_counter()
        )

    def register_invalid_input(self, ip_address, username, start_time):
        """Handle registration with missing or invalid input."""
        return self._register_response(
            ip_address,
            username,
            "fail",
            HTTPStatus.BAD_REQUEST,
            "error",
            "username or password are missing",
            start_time,
            time.perf_counter()
        )

    def register_success(self, ip_address, username, start_time):
        """Handle successful user registration."""
        return self._register_response(
            ip_address,
            username,
            "success",
            HTTPStatus.CREATED,
            "message",
            "user created",
            start_time,
            time.perf_counter()
        )

    def login_invalid_input(self, ip_address, username, start_time):
        """Handle login with missing credentials."""
        return self._login_response(
            ip_address,
            username,
            "fail",
            HTTPStatus.BAD_REQUEST,
            "error",
            "username or password are missing",
            start_time,
            time.perf_counter()
        )

    def login_user_not_found(self, ip_address, username, start_time):
        """Handle login for a non-existent user."""
        return self._login_response(
            ip_address,
            username,
            "fail",
            HTTPStatus.NOT_FOUND,
            "error",
            "user not found",
            start_time,
            time.perf_counter()
        )

    def login_success(self, ip_address, username, start_time):
        """Handle successful login."""
        return self._login_response(
            ip_address,
            username,
            "success",
            HTTPStatus.OK,
            "message",
            "login success",
            start_time,
            time.perf_counter()
        )

    def login_fail(self, ip_address, username, start_time):
        """Handle failed login due to invalid credentials."""
        return self._login_response(
            ip_address,
            username,
            "fail",
            HTTPStatus.UNAUTHORIZED,
            "error",
            "unauthorized attempt",
            start_time,
            time.perf_counter()
        )

    def login_too_many_requests(self, ip_address, username, start_time):
        """Handle rate-limited login attempts."""
        return self._login_response(
            ip_address,
            username,
            "fail",
            HTTPStatus.TOO_MANY_REQUESTS,
            "error",
            "too many requests",
            start_time,
            time.perf_counter()
        )

    def login_lockout(self, ip_address, username, message, start_time):
        """Handle login attempts during an active lockout."""
        return self._login_response(
            ip_address,
            username,
            "fail",
            HTTPStatus.LOCKOUT,
            "error",
            message,
            start_time,
            time.perf_counter()
        )

    def login_captcha_required(self, ip_address, username, start_time):
        """Require CAPTCHA verification before allowing further login attempts."""
        return self._login_response(
            ip_address,
            username,
            "fail",
            HTTPStatus.FORBIDDEN,
            "error",
            CAPTCHA_REQUIRED,
            start_time,
            time.perf_counter()
        )

    def login_captcha_blocked(self, ip_address, username, start_time):
        """Handle account block after repeated CAPTCHA failures."""
        return self._login_response(
            ip_address,
            username,
            "fail",
            HTTPStatus.LOCKOUT,
            "error",
            ACCOUNT_BLOCKED,
            start_time,
            time.perf_counter()
        )

    def login_totp_required(self, ip_address, username, start_time):
        """Require TOTP verification as part of MFA."""
        return self._login_response(
            ip_address,
            username,
            "fail",
            HTTPStatus.FORBIDDEN,
            "error",
            TOTP_REQUIRED,
            start_time,
            time.perf_counter()
        )

    def login_totp_blocked(self, ip_address, username, start_time):
        """Handle account block after repeated TOTP failures."""
        return self.login_captcha_blocked(ip_address, username, start_time)

    def login_totp_fail(self, ip_address, username, start_time):
        """Handle incorrect TOTP submission."""
        return self._login_response(
            ip_address,
            username,
            "fail",
            HTTPStatus.UNAUTHORIZED,
            "error",
            "incorrect totp",
            start_time,
            time.perf_counter()
        )

    @staticmethod
    def get_token_captcha(token):
        """Return a CAPTCHA token to the client."""
        return jsonify({"captcha_token": token}), HTTPStatus.OK

    @staticmethod
    def valid_captcha():
        """Confirm successful CAPTCHA verification."""
        return jsonify({"message": "ip unlocked"}), HTTPStatus.ACCEPTED

    @staticmethod
    def invalid_captcha():
        """Handle invalid CAPTCHA submissions."""
        return jsonify({"error": "invalid captcha"}), HTTPStatus.BAD_REQUEST
