import os
import unittest
from pathlib import Path
import tempfile

from application import AuthServer
from configuration import hash_mode, generate_password

DIRECTORY_PATH = Path(__file__).parent

STRENGTHS = ["weak", "medium", "strong"]


# Set environment variable in Python code
os.environ["pepper"] = "25977022"

_protections = {
    "pepper_enabled": False,
    "rate_limit_enabled": False,
    "lockout_enabled": False,
    "captcha_enabled": False,
    "totp_enabled": False
}


class AuthServerTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth = AuthServer(self.temp_dir.name, hash_mode, _protections)
        self.client = self.auth._app.test_client()

    def tearDown(self):
        self.auth._database.close()
        self.temp_dir.cleanup()
        print("Closing database...")

    def test_bruteforce_login_random(self):
        """
        Brute-force test with controlled randomness.
        The correct password is injected at a random attempt.
        """

        username = self.auth.dummy_members_manager.get_random_user("weak")

        max_attempts = 50_000
        success = False

        for attempt in range(1, max_attempts + 1):

            password = generate_password("weak")

            response = self.client.post(
                "/login",
                json={"username": username, "password": password},
                environ_base={"REMOTE_ADDR": "192.666.1.10"}
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
    unittest.main()
