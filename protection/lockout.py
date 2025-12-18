import time
from collections import defaultdict
from configuration import lockout_parameters


class Lockout:
    """
    User lockout handler based on token bucket + exponential lockout duration.

    Tokens decrease on failed login.
    Lockout duration doubles after each lockout.
    Tokens reset to tokens // rate after lockout.
    When tokens reach 0 → permanent block.
    """

    def __init__(self, params=None):
        self._params = params or lockout_parameters

        self._initial_tokens = self._params["tokens"]
        self._token_rate = self._params["token_rate"]
        self._base_duration_sec = self._params["duration_mm"] * 60
        self._duration_rate = self._params["duration_rate"]

        self._users = defaultdict(self._new_user_state)

    def _new_user_state(self) -> dict:
        return {
            "tokens": self._initial_tokens,
            "locked_until": None,
            "last_lockout_duration": self._base_duration_sec
        }

    def _reset_tokens_after_lockout(self, user):
        user["tokens"] = max(0, user["tokens"] // self._token_rate)

    def allow_attempt(self, username):  # TODO: FIX LOGIC, SO IT WONT LOCKOUT FOREVER AT FIRST LOCKOUT
        """
        Returns (allowed, message)

        - False + message if user is locked/permanently blocked
        - True + None if attempt allowed
        """

        user = self._users[username]
        now = time.time()

        if user["tokens"] <= 0:
            return False, "account blocked, contact admin"

        if user["locked_until"] and now < user["locked_until"]:
            return False, "account temporarily locked"

        if user["locked_until"] and now >= user["locked_until"]:
            user["locked_until"] = None
            self._reset_tokens_after_lockout(user)

            if user["tokens"] <= 0:
                return False, "account blocked, contact admin"

            user["last_lockout_duration"] *= self._duration_rate

        user["tokens"] -= 1

        if user["tokens"] < 0:
            user["locked_until"] = now + user["last_lockout_duration"]
            return False, "account temporarily locked"

        return True, None

    def reset_after_successful_login(self, username):
        """
        Call this after a successful login (e.g., password + MFA)
        Resets tokens and lockout duration for this user.
        """
        if username in self._users:
            user = self._users[username]
            user["tokens"] = self._initial_tokens
            user["locked_until"] = None
            user["last_lockout_duration"] = self._base_duration_sec
