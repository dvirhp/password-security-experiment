"""
Lockout Module

Implements a token-based user lockout system with exponential backoff.
Tracks failed login attempts, temporary lockouts, and permanent blocks.
"""

import time
from collections import defaultdict

from configuration import lockout_parameters
from application import ACCOUNT_BLOCKED, ACCOUNT_TEMPORARILY_BLOCKED

# Standardized results for login attempts
RESULTS = {
    "PERMANENTLY_BLOCKED": (False, ACCOUNT_BLOCKED),
    "TEMPORARILY_LOCKED": (False, ACCOUNT_TEMPORARILY_BLOCKED),
    "ALLOWED": (True, None)
}


class Lockout:
    """
    User lockout handler using a token bucket and exponential lockout duration.

    Attributes:
        _lockout_parameters (dict): Configuration for tokens, token_rate, duration, etc.
        _initial_tokens (int): Number of tokens initially assigned per user.
        _token_rate (int): Rate at which tokens are replenished after lockout.
        _base_duration_sec (float): Initial lockout duration in seconds.
        _duration_rate (float): Multiplier for exponential backoff of lockout duration.
        _users (default-dict): Tracks per-user state (tokens, lockout, etc.).
    """

    def __init__(self, parameters=None):
        """
        Initialize the lockout system with optional custom parameters.

        Args:
            parameters (dict, optional): Custom lockout configuration. Defaults to None.
        """
        self._lockout_parameters = parameters or lockout_parameters

        self._initial_tokens = self._lockout_parameters["tokens"]
        self._token_rate = self._lockout_parameters["token_rate"]
        self._base_duration_sec = self._lockout_parameters["duration_mm"] * 60
        self._duration_rate = self._lockout_parameters["duration_rate"]

        self._users = defaultdict(self._new_user_state)

    def _new_user_state(self) -> dict:
        """
        Initialize a new user's lockout state.

        Returns:
            dict: User state including tokens, next allocation, lockout time, last duration.
        """
        return {
            "tokens": self._initial_tokens,
            "next_allocation": max(0, self._initial_tokens // self._token_rate),
            "locked_until": None,
            "last_lockout_duration": self._base_duration_sec
        }

    def lock_user(self, username):
        """
        Immediately lock a user for the current lockout duration.

        Args:
            username (str): The username to lock.
        """
        user = self._users[username]
        user["locked_until"] = time.perf_counter() + user["last_lockout_duration"]

    def allow_attempt(self, username):
        """
        Determine whether a login attempt is allowed.

        Args:
            username (str): The username attempting to login.

        Returns:
            tuple: (allowed: bool, message: str or None)
                   - False + message if user is locked or permanently blocked
                   - True + None if attempt is allowed
        """
        user = self._users[username]
        now = time.perf_counter()

        # Tokens available: allow login and decrease token count
        if user["tokens"] > 0:
            user["tokens"] -= 1
            return RESULTS["ALLOWED"]

        # No more tokens and no allocation left -> permanent block
        if user["next_allocation"] <= 0:
            return RESULTS["PERMANENTLY_BLOCKED"]

        # If not currently locked, start a temporary lockout
        if user["locked_until"] is None:
            user["locked_until"] = now + user["last_lockout_duration"]
            return RESULTS["TEMPORARILY_LOCKED"]

        # If still locked -> temporarily blocked
        if now < user["locked_until"]:
            return RESULTS["TEMPORARILY_LOCKED"]

        # Lockout expired -> replenish tokens and adjust next allocation
        if now >= user["locked_until"]:
            user["tokens"] = user["next_allocation"] - 1
            user["next_allocation"] = max(0, user["next_allocation"] // self._token_rate)
            user["locked_until"] = None
            user["last_lockout_duration"] *= self._duration_rate

            return RESULTS["ALLOWED"]

        # Fallback → permanent block
        return RESULTS["PERMANENTLY_BLOCKED"]

    def reset_after_successful_login(self, username):
        """
        Reset a user's lockout state after a successful login.

        Args:
            username (str): Username to reset.
        """
        if username in self._users:
            user = self._users[username]
            user["tokens"] = self._initial_tokens
            user["next_allocation"] = max(0, self._initial_tokens // self._token_rate)
            user["locked_until"] = None
            user["last_lockout_duration"] = self._base_duration_sec
