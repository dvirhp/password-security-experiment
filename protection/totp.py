import time
from collections import defaultdict

import pyotp
from configuration import totp_parameters


class Totp:
    def __init__(self, parameters=None):
        self._params = parameters or totp_parameters

        self._time_step = self._params["time_step_ss"]
        self._tolerance = self._params["tolerance_ss"]
        self._max_failures = self._params["tokens"]

        self._secrets = {}
        self._failures = defaultdict(int)
        self._blocked = set()

    def register_user(self, username, secret):
        self._secrets[username] = secret

    def totp_enabled(self, username) -> bool:
        return username in self._secrets

    def totp_blocked(self, username) -> bool:
        return username in self._blocked

    def reset_failures(self, username):
        self._failures.pop(username, None)
        self._blocked.discard(username)

    def _register_failure(self, username):
        self._failures[username] += 1
        if self._failures[username] >= self._max_failures:
            self._blocked.add(username)

    def generate_code(self, username, drift_seconds=0) -> str:
        if username not in self._secrets:
            raise ValueError("Unknown user")

        secret = self._secrets[username]
        totp = pyotp.TOTP(secret, interval=self._time_step)
        return totp.at(int(time.time() + drift_seconds))

    def verify(self, username, code) -> bool:
        if self.totp_blocked(username):
            return False

        secret = self._secrets.get(username)
        if not secret:
            self._register_failure(username)
            return False

        totp = pyotp.TOTP(secret, interval=self._time_step)

        valid = totp.verify(code, valid_window=self._tolerance // self._time_step)

        if not valid:
            self._register_failure(username)
            return False

        self.reset_failures(username)
        return True
