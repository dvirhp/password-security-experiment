import hashlib
import secrets
import time
from collections import defaultdict

from configuration import captcha_parameters


class Captcha:
    def __init__(self, parameters=None):
        self._captcha_parameters = parameters or captcha_parameters

        self._tokens = self._captcha_parameters["tokens"]
        self._time_to_live = self._captcha_parameters["time_to_live"]

        self._failures = defaultdict(
            lambda: {
                "tokens": 0,
                "blocked": False
            }
        )

        self._used_tokens = {}

    def register_failure(self, ip_address):
        failure = self._failures[ip_address]
        failure["tokens"] += 1

    def captcha_required(self, ip_address) -> bool:
        failure = self._failures[ip_address]
        return failure["tokens"] >= self._tokens

    def captcha_blocked(self, ip_address) -> bool:
        failure = self._failures[ip_address]
        return failure["blocked"]

    def _captcha_block_ip(self, ip_address):
        failure = self._failures[ip_address]
        failure["blocked"] = True

    def generate_captcha_token(self, group_seed, ip_address) -> str:
        token = self._generate_token(group_seed)
        self._used_tokens[token] = {
            "expiry": time.perf_counter() + self._time_to_live,
            "ip": ip_address,
        }
        return token

    def validate_token(self, token, ip_address) -> bool:
        if self.captcha_blocked(ip_address):
            return False

        entry = self._used_tokens.get(token)
        if not entry:
            self._captcha_block_ip(ip_address)
            return False

        if time.perf_counter() > entry["expiry"]:
            self._used_tokens.pop(token, None)
            self._captcha_block_ip(ip_address)
            return False

        if entry["ip"] != ip_address:
            self._captcha_block_ip(ip_address)
            return False

        self._used_tokens.pop(token, None)

        if ip_address in self._failures:
            self._failures[ip_address]["tokens"] = 0

        return True

    @staticmethod
    def _generate_token(group_seed) -> str:
        raw = f"{group_seed}:{secrets.token_hex(16)}:{time.perf_counter()}"
        token = hashlib.sha256(raw.encode()).hexdigest()

        return token
