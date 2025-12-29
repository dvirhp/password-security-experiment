"""
TOTP (Time-based One-Time Password) module.

Implements user-based TOTP generation and verification with failure tracking and blocking.
"""

import time
import pyotp
from collections import defaultdict

from configuration import totp_parameters


class Totp:
    """
    TOTP handler with failure tracking and blocking.

    Each user has a secret and optional blocking if too many invalid attempts occur.
    """

    def __init__(self, parameters=None):
        """
        Initialize TOTP handler.

        Args:
            parameters (dict, optional): Configuration for TOTP. Expected keys:
                - "time_step_ss": Time step in seconds (TOTP interval)
                - "tolerance_ss": Allowed tolerance window in seconds
                - "tokens": Maximum allowed consecutive failures before blocking
        """
        self._params = parameters or totp_parameters

        self._time_step = self._params["time_step_ss"]
        self._tolerance = self._params["tolerance_ss"]
        self._max_failures = self._params["tokens"]

        self._secrets = {}
        self._failures = defaultdict(int)
        self._blocked = set()

    def register_user(self, username, secret):
        """
        Register a user with their TOTP secret.

        Args:
            username (str): Username of the member
            secret (str): Base32 encoded TOTP secret
        """
        self._secrets[username] = secret

    def totp_enabled(self, username) -> bool:
        """
        Check if TOTP is enabled for a user.

        Args:
            username (str)
        Returns:
            bool: True if TOTP is registered for this user
        """
        return username in self._secrets

    def totp_blocked(self, username) -> bool:
        """
        Check if the user is blocked due to failed attempts.

        Args:
            username (str)
        Returns:
            bool: True if user is blocked
        """
        return username in self._blocked

    def reset_failures(self, username):
        """
        Reset failure count and unblock the user.

        Args:
            username (str)
        """
        self._failures.pop(username, None)
        self._blocked.discard(username)

    def _register_failure(self, username):
        """
        Increment failure count and block user if maximum failures exceeded.

        Args:
            username (str)
        """
        self._failures[username] += 1
        if self._failures[username] >= self._max_failures:
            self._blocked.add(username)

    def generate_code(self, username, drift_seconds=0) -> str:
        """
        Generate a TOTP code for a user, optionally with a time drift.

        Args:
            username (str): Username
            drift_seconds (int, optional): Shift in seconds for testing or simulation

        Returns:
            str: TOTP code
        """
        if username not in self._secrets:
            raise ValueError("Unknown user")

        secret = self._secrets[username]
        totp = pyotp.TOTP(secret, interval=self._time_step)
        return totp.at(int(time.time() + drift_seconds))

    def verify(self, username, code) -> bool:
        """
        Verify a TOTP code for a user. Tracks failures and blocks users after too many attempts.

        Args:
            username (str)
            code (str)

        Returns:
            bool: True if the code is valid
        """
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
