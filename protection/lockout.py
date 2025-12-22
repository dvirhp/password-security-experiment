import time
from collections import defaultdict
from configuration import lockout_parameters


RESULTS = {
    "PERMANENTLY_BLOCKED": (False, "account blocked, contact admin"),
    "TEMPORARILY_LOCKED": (False, "account temporarily locked"),
    "ALLOWED": (True, None)
}


class Lockout:
    """
    User lockout handler based on token bucket + exponential lockout duration.

    Tokens decrease on failed login.
    Lockout duration doubles after each lockout.
    Tokens reset to tokens // rate after lockout.
    When tokens reach 0 → permanent block.
    """

    def __init__(self, parameters=None):
        self._lockout_parameters = parameters or lockout_parameters

        self._initial_tokens = self._lockout_parameters["tokens"]
        self._token_rate = self._lockout_parameters["token_rate"]
        self._base_duration_sec = self._lockout_parameters["duration_mm"] * 60
        self._duration_rate = self._lockout_parameters["duration_rate"]

        self._users = defaultdict(self._new_user_state)

    def _new_user_state(self) -> dict:
        return {
            "tokens": self._initial_tokens,
            "next_allocation": max(0, self._initial_tokens // self._token_rate),
            "locked_until": None,
            "last_lockout_duration": self._base_duration_sec
        }

    def lock_user(self, username):
        user = self._users[username]
        user["locked_until"] = time.perf_counter() + user["last_lockout_duration"]

    def allow_attempt(self, username):
        """
        Returns (allowed, message)

        - False + message if user is locked/permanently blocked
        - True + None if attempt allowed
        """

        user = self._users[username]
        now = time.perf_counter()

        if user["tokens"] > 0:
            user["tokens"] -= 1
            return RESULTS["ALLOWED"]

        if user["next_allocation"] <= 0:
            return RESULTS["PERMANENTLY_BLOCKED"]

        if user["locked_until"] is None:
            user["locked_until"] = now + user["last_lockout_duration"]
            return RESULTS["TEMPORARILY_LOCKED"]

        if now < user["locked_until"]:
            return RESULTS["TEMPORARILY_LOCKED"]

        if now >= user["locked_until"]:
            user["tokens"] = user["next_allocation"] - 1
            user["next_allocation"] = max(0, user["next_allocation"] // self._token_rate)
            user["locked_until"] = None
            user["last_lockout_duration"] *= self._duration_rate

            return RESULTS["ALLOWED"]

        return RESULTS["PERMANENTLY_BLOCKED"]

    def reset_after_successful_login(self, username):
        """
        Call this after a successful login (e.g., password + MFA)
        Resets tokens and lockout duration for this user.
        """
        if username in self._users:
            user = self._users[username]
            user["tokens"] = self._initial_tokens
            user["next_allocation"] = max(0, self._initial_tokens // self._token_rate)
            user["locked_until"] = None
            user["last_lockout_duration"] = self._base_duration_sec
