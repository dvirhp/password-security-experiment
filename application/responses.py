import time

from flask import jsonify

HTTP_OK = 200
HTTP_CREATED = 201
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_NOT_FOUND = 404
HTTP_LOCKOUT = 423
HTTP_TOO_MANY_REQUESTS = 429


class ResponseHandler:
    def __init__(self, logger):
        self._logger = logger

    def _register_response(self, ip_address, username, result, status, status_type, message, start_time, end_time):
        self._logger.log_register(ip_address, username, result, status, message, start_time, end_time)
        return jsonify({status_type: message}), status

    def _login_response(self, ip_address, username, result, status, status_type, message, start_time, end_time):
        self._logger.log_login(ip_address, username, result, status, message, start_time, end_time)
        return jsonify({status_type: message}), status

    def register_dummy_member(self, ip_address, username, start_time):
        self._logger.log_register(
            ip_address,
            username,
            "success",
            HTTP_CREATED,
            "user created",
            start_time,
            time.perf_counter()
        )

    def register_invalid_input(self, ip_address, username, start_time):
        return self._register_response(
            ip_address,
            username,
            "fail",
            HTTP_BAD_REQUEST,
            "error",
            "username and password are required",
            start_time,
            time.perf_counter()
        )

    def register_success(self, ip_address, username, start_time):
        return self._register_response(
            ip_address,
            username,
            "success",
            HTTP_CREATED,
            "message",
            "user created",
            start_time,
            time.perf_counter()
        )

    def login_invalid_input(self, ip_address, username, start_time):
        return self._login_response(
            ip_address,
            username,
            "fail",
            HTTP_BAD_REQUEST,
            "error",
            "username and password are required",
            start_time,
            time.perf_counter()
        )

    def login_user_not_found(self, ip_address, username, start_time):
        return self._login_response(
            ip_address,
            username,
            "fail",
            HTTP_NOT_FOUND,
            "error",
            "user not found",
            start_time,
            time.perf_counter()
        )

    def login_success(self, ip_address, username, start_time):
        return self._login_response(
            ip_address,
            username,
            "success",
            HTTP_OK,
            "message",
            "login success",
            start_time,
            time.perf_counter()
        )

    def login_fail(self, ip_address, username, start_time):
        return self._login_response(
            ip_address,
            username,
            "fail",
            HTTP_UNAUTHORIZED,
            "error",
            "unauthorized attempt",
            start_time,
            time.perf_counter()
        )

    def login_too_many_requests(self, ip_address, username, start_time):
        return self._login_response(
            ip_address,
            username,
            "fail",
            HTTP_TOO_MANY_REQUESTS,
            "error",
            "too many requests",
            start_time,
            time.perf_counter()
        )

    def login_lockout(self, ip_address, username, message, start_time):
        return self._login_response(
            ip_address,
            username,
            "fail",
            HTTP_LOCKOUT,
            "error",
            message,
            start_time,
            time.perf_counter()
        )

    def login_captcha_required(self, ip_address, username, start_time):
        return self._login_response(
            ip_address,
            username,
            "fail",
            HTTP_BAD_REQUEST,
            "error",
            "captcha required",
            start_time,
            time.perf_counter()
        )
    
    def login_totp_required(self, ip_address, username, start_time):
        return self._login_response(
            ip_address,
            username,
            "blocked",
            HTTP_UNAUTHORIZED,
            "error",
            "totp required",
            start_time,
            time.perf_counter()
        )

    def login_totp_invalid(self, ip_address, username, start_time):
        return self._login_response(
            ip_address,
            username,
            "fail",
            HTTP_UNAUTHORIZED,
            "error",
            "invalid totp",
            start_time,
            time.perf_counter()
        )

