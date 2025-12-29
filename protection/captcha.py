"""
Captcha Module

This module provides a simple CAPTCHA system for limiting automated requests.
It tracks failed attempts per IP, generates time-limited tokens, and can block IPs on invalid usage.
"""

import time
import hashlib
import secrets
from collections import defaultdict

from configuration import captcha_parameters


class Captcha:
    """
    CAPTCHA system that tracks failed attempts, issues time-limited tokens,
    and can block IP addresses for invalid or expired token usage.

    Attributes:
        _captcha_parameters (dict): Configuration for tokens and TTL.
        _tokens (int): Number of failures before CAPTCHA is required.
        _time_to_live (float): TTL of CAPTCHA tokens in seconds.
        _failures (default-dict): Tracks failed attempts and blocked status per IP.
        _used_tokens (dict): Maps active CAPTCHA tokens to their expiry and IP.
    """

    def __init__(self, parameters=None):
        """
        Initialize the CAPTCHA system with optional parameters.

        Args:
            parameters (dict, optional): CAPTCHA configuration overrides. Defaults to None.
        """
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
        """
        Increment the failure counter for an IP address.

        Args:
            ip_address (str): The IP address of the failing client.
        """
        failure = self._failures[ip_address]
        failure["tokens"] += 1

    def captcha_required(self, ip_address) -> bool:
        """
        Determine whether an IP address should be presented with a CAPTCHA.

        Args:
            ip_address (str): IP address to check.

        Returns:
            bool: True if CAPTCHA is required, False otherwise.
        """
        failure = self._failures[ip_address]
        return failure["tokens"] >= self._tokens

    def captcha_blocked(self, ip_address) -> bool:
        """
        Check if an IP address is blocked due to invalid CAPTCHA behavior.

        Args:
            ip_address (str): IP address to check.

        Returns:
            bool: True if blocked, False otherwise.
        """
        failure = self._failures[ip_address]
        return failure["blocked"]

    def _captcha_block_ip(self, ip_address):
        """
        Block an IP address from further attempts.

        Args:
            ip_address (str): IP address to block.
        """
        failure = self._failures[ip_address]
        failure["blocked"] = True

    def generate_captcha_token(self, group_seed, ip_address) -> str:
        """
        Generate a new CAPTCHA token for a specific IP address.

        Args:
            group_seed (str): Seed value to generate deterministic tokens.
            ip_address (str): IP address for which the token is issued.

        Returns:
            str: The generated CAPTCHA token (SHA256 hex string).
        """
        token = self._generate_token(group_seed)
        self._used_tokens[token] = {
            "expiry": time.perf_counter() + self._time_to_live,
            "ip": ip_address,
        }
        return token

    def validate_token(self, token, ip_address) -> bool:
        """
        Validate a CAPTCHA token for an IP address.

        Args:
            token (str): The CAPTCHA token submitted by the client.
            ip_address (str): IP address of the client.

        Returns:
            bool: True if the token is valid, False otherwise.
        """
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

        # Valid token: remove it and reset failure counter
        self._used_tokens.pop(token, None)

        if ip_address in self._failures:
            self._failures[ip_address]["tokens"] = 0

        return True

    @staticmethod
    def _generate_token(group_seed) -> str:
        """
        Generate a SHA256 token based on a seed, random value, and timestamp.

        Args:
            group_seed (str): Seed to create deterministic tokens if needed.

        Returns:
            str: SHA256 hex string token.
        """
        raw = f"{group_seed}:{secrets.token_hex(16)}:{time.perf_counter()}"
        token = hashlib.sha256(raw.encode()).hexdigest()

        return token
