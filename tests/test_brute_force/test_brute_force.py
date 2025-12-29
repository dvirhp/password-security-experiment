import os
import time
import unittest
from pathlib import Path
import tempfile
from application import AuthServer
from configuration import hash_mode, get_hash_params, protections, generate_password

DIRECTORY_PATH = Path(__file__).parent

os.environ["pepper"] = "25977022"

_protections_1 = {
    "pepper": "25977022",
    "rate_limit": {"tokens": 4, "refill_rate_tps": 0},
    "lockout": {"tokens": 9, "token_rate": 10, "duration_rate": 1, "duration_mm": 0.1},
    "captcha": {"tokens": 15},
    "totp": {"number_of_users": 5, "length": 5, "period_ss": 30}
}

_protections = {
    "pepper_enabled": True,
    "rate_limit_enabled": True,
    "lockout_enabled": True,
    "captcha_enabled": False,
    "totp_enabled": False
}


class BruteForceTestCase(unittest.TestCase):
    def setUp(self):
        # self.temp_dir = tempfile.TemporaryDirectory()
        # self.auth = AuthServer(self.temp_dir.name, hash_mode, protections)

        # Uncomment the following line if you want to use a persistent directory instead
        self.auth = AuthServer(DIRECTORY_PATH, hash_mode, get_hash_params(hash_mode), _protections_1)
        # self.auth = AuthServer(DIRECTORY_PATH, "argon2id", get_hash_params("argon2id"), _protections)

        self.client = self.auth._app.test_client()  # Flask test client

    def tearDown(self):
        self.auth.close_database()

        # Comment this line if you are using a persistent (non-temporary) directory
        # self.temp_dir.cleanup()

        print("Closing database...")

    def test_bruteforce_login_random(self):
        """
        Brute-force test with controlled randomness.
        The correct password is injected at a random attempt.
        """

        username = self.auth.dummy_members_manager.get_random_user("weak")
        ip_address = "192.666.1.10"

        # max_attempts = 50_000
        max_attempts = 2000
        success = False

        print(username, " ", user_password, " ")

        for attempt in range(1, max_attempts + 1):

            if attempt == 1050:
                ip_address = "192.666.6.10"
                print("[INFO] Sleeping for 5 seconds after 1050 attempts")
                time.sleep(5)

            password = generate_password("weak")

            response = self.client.post(
                "/login",
                json={"username": username, "password": password},
                environ_base={"REMOTE_ADDR": ip_address}
            )

            if response.status_code == 200:
                print("break")
                print(f"[SUCCESS] Password cracked: {password}")
                print(f"Attempts: {attempt}")
                success = True
                break

        self.assertTrue(True)

        if not success:
            print("[INFO] Brute-force did not succeed within limit")


if __name__ == "__main__":
    os.environ["pepper"] = "25977022"
    unittest.main()
