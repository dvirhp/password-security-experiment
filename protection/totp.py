import datetime
import time
from collections import defaultdict

import pyotp

from configuration import totp_parameters


class Totp:
    def __init__(self, parameters=None):
        self._totp_parameters = parameters or totp_parameters

        self._time_step = self._totp_parameters["time_step_ss"]
        self._tolerance = self._totp_parameters["tolerance_ss"]
        self._max_failures = self._totp_parameters["tokens"]

        self._failures = defaultdict(int)
        self._blocked = set()
        self._time_offsets = {}

    def is_blocked(self, username) -> bool:
        return username in self._blocked

    def register_failure(self, username):
        self._failures[username] += 1
        if self._failures[username] >= self._max_failures:
            self._blocked.add(username)

    def reset_failures(self, username):
        self._failures.pop(username, None)
        self._blocked.discard(username)

    def generate_code(self, secret, username=None, drift_seconds=0) -> str:
        """
        Generate a valid TOTP code.

        Args:
            secret (str): user's TOTP secret
            username (str): optional, to store simulated drift
            drift_seconds (int): seconds to simulate clock drift

        Returns:
            str: 6-digit TOTP code
        """
        if username:
            self._time_offsets[username] = drift_seconds

        totp = pyotp.TOTP(secret, interval=self._time_step)
        return totp.at(int(time.time() + drift_seconds))

    def validate_code(self, username, secret, code) -> dict:
        """
        Validate a TOTP code with tolerance and optional drift correction.

        Returns a dictionary with:
            - valid (bool)
            - applied_drift (int)
            - correction (int)
            - final_error (bool)
        """
        if self.is_blocked(username):
            return {"valid": False, "applied_drift": 0, "correction": 0, "final_error": True}

        base_time = time.time()
        drift = self._time_offsets.get(username, 0)
        totp = pyotp.TOTP(secret, interval=self._time_step)

        for delta in range(-self._tolerance, self._tolerance + 1):
            test_time = base_time + drift + delta * self._time_step
            test_dt = datetime.datetime.fromtimestamp(test_time)
            if totp.verify(code, for_time=test_dt):
                self.reset_failures(username)
                return {"valid": True, "applied_drift": drift, "correction": 0, "final_error": False}

        for correction in range(-10, 11):
            test_time = base_time + correction
            test_dt = datetime.datetime.fromtimestamp(test_time)
            if totp.verify(code, for_time=test_dt):
                self._time_offsets[username] = correction
                self.reset_failures(username)
                return {"valid": True, "applied_drift": drift, "correction": correction, "final_error": False}

        self.register_failure(username)
        return {"valid": False, "applied_drift": drift, "correction": 0, "final_error": True}

    @property
    def max_failures(self):
        return self._max_failures


# TODO: REMOVE AFTER TESTING


USER_SECRETS = {
    "alice": "JBSWY3DPEHPK3PXP",
    "bob": "KRSXG5DPOHPK3LXQ",
}


def run_totp_tests():
    totp_handler = Totp()

    username = "alice"
    secret = USER_SECRETS[username]

    print("=== TOTP Tester ===")

    code = totp_handler.generate_code(secret, username=username)
    print(f"Generated TOTP for {username}: {code}")

    result = totp_handler.validate_code(username, secret, code)
    print("Immediate validation result:", result)

    drift_seconds = 5
    code_with_drift = totp_handler.generate_code(secret, username=username, drift_seconds=drift_seconds)
    print(f"Generated TOTP with drift {drift_seconds}s: {code_with_drift}")
    result_drift = totp_handler.validate_code(username, secret, code_with_drift)
    print("Validation with drift result:", result_drift)

    print("\nSimulating failures to trigger blocking...")
    for i in range(totp_handler.max_failures + 1):
        fake_code = "000000"
        result_fail = totp_handler.validate_code(username, secret, fake_code)
        print(f"Attempt {i+1}, validation result:", result_fail)

    blocked_code = totp_handler.generate_code(secret, username=username)
    print("\nTrying correct code after user is blocked:")
    result_blocked = totp_handler.validate_code(username, secret, blocked_code)
    print("Validation after blocking:", result_blocked)


if __name__ == "__main__":
    run_totp_tests()
