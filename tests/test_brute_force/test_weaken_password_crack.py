import os
import secrets
import string
import time
import unittest
from pathlib import Path
import tempfile
import random

from application import AuthServer
# from configuration import hash_mode, protections, generate_password

import winsound

DIRECTORY_PATH = Path(__file__).parent

STRENGTHS = ["weak", "medium", "strong"]


# Set environment variable in Python code
os.environ["pepper"] = "25977022"

_hash_mode = "sha256"

_protections = {
    "pepper_enabled": False,
    "rate_limit_enabled": False,
    "lockout_enabled": False,
    "captcha_enabled": False,
    "totp_enabled": False
}


# def generate_weak_password(length):
#     chars = string.ascii_lowercase
#     chars += string.digits
#
#     return ''.join(secrets.choice(chars) for _ in range(length))


def generate_password(min_length, max_length, chars) -> str:
    length = random.randint(min_length, max_length)

    return ''.join(secrets.choice(chars) for _ in range(length))


class BruteForceTestCase(unittest.TestCase):
    def setUp(self):
        self._username = "alice"

    def tearDown(self):
        print("Closing database...")

    def test_bruteforce(self):
        # print(self._bruteforce(100, 50000, 4, 6, "01234"))
        # print(self._bruteforce(100, 50000, 4, 6, "012345"))
        # print(self._bruteforce(100, 50000, 4, 6, "0123456"))
        # print(self._bruteforce(100, 50000, 4, 6, "01234567"))
        # print(self._bruteforce(100, 50000, 4, 6, "012345678"))
        # print(self._bruteforce(100, 50000, 4, 6, "0123456789"))
        # print(self._bruteforce(100, 50000, 4, 6, "0123456789a"))
        # print(self._bruteforce(100, 50000, 4, 6, "0123456789ab"))
        # print(self._bruteforce(100, 50000, 4, 6, "0123456789abc"))
        # print(self._bruteforce(100, 50000, 4, 6, "0123456789abcd"))
        # print(self._bruteforce(100, 50000, 4, 6, "0123456789abcde"))
        # print(self._bruteforce(100, 50000, 4, 6, "0123456789abcdef"))
        # print(self._bruteforce(100, 50000, 6, 8, "0123456789abcdefg"))

        # chars = "0123456789!@#$%"
        # print(chars)

        # print(self._bruteforce(10, 50000, 5, 6, chars))

        self.assertTrue(True)

    @staticmethod
    def _bruteforce(total, max_attempts, min_length, max_length, chars):
        passed = 0
        cnt = 0
        start_time = time.time()
        tot_time = 0

        for exp in range(1, total + 1):
            _password = generate_password(min_length, max_length, chars)

            for attempt in range(1, max_attempts + 1):
                password = generate_password(min_length, max_length, chars)

                if password == _password:
                    passed += 1
                    cnt += attempt
                    break

        end_time = time.time()
        runtime = end_time - start_time

        tot_time += runtime

        result = {
            "min_length": min_length,
            "max_length": max_length,
            "chars": chars,
            "rate": f"{passed}%",
            "average_success_attempt": round(cnt / passed, 2) if passed else None
            # "average_runtime_s": round(tot_time // total, 3)
        }

        return result


if __name__ == "__main__":
    unittest.main()
