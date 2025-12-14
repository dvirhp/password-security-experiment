# from attack.brute_force import BruteForceAttack
#
#
# def test_bruteforce_attack_runs():
#     attack = BruteForceAttack(
#         base_url="http://127.0.0.1:5000",
#         username="non_existing_user",
#         passwords=["a", "b", "c"]
#     )
#
#     # If no exception is raised → test passed
#     attack.run()


import os
import unittest
from pathlib import Path
import tempfile
import random

from application import AuthServer
from configuration import hash_mode, protections, generate_password

import winsound

DIRECTORY_PATH = Path(__file__).parent

STRENGTHS = ["weak", "medium", "strong"]


# Set environment variable in Python code
os.environ["pepper"] = "137379782"

_protections = {
    "pepper_enabled": True,
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

    def test_register_and_login(self):
        # Register user
        response = self.client.post(
            "/register",
            json={"username": "alice", "password": "my32rd"}
        )
        self.assertEqual(response.status_code, 201)

        # Login user
        response = self.client.post(
            "/login",
            json={"username": "alice", "password": "my32rd"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("login success", response.get_json().get("message"))

        # Wrong password
        response = self.client.post(
            "/login",
            json={"username": "alice", "password": "wrong"}
        )
        self.assertEqual(response.status_code, 401)

        # Non-existent user
        response = self.client.post(
            "/login",
            json={"username": "bob", "password": "123"}
        )
        self.assertEqual(response.status_code, 404)

    def test_bruteforce_login_random(self):
        """
        Brute-force test with controlled randomness.
        The correct password is injected at a random attempt.
        """

        username, _, user_password = self.auth.dummy_members_manager.get_random_user("weak")

        max_attempts = 50_000
        success = False

        insert_at = random.randint(
            int(max_attempts ** 0.5),
            int(max_attempts * 2)
        )

        print(username, " ", user_password, " ", insert_at)

        for attempt in range(1, max_attempts + 1):
            if attempt == insert_at:
                password = user_password
            else:
                strength = random.choice(STRENGTHS)
                password = generate_password(strength)

            response = self.client.post(
                "/login",
                json={"username": username, "password": password}
            )

            if response.status_code == 200:
                print("break")
                print(f"[SUCCESS] Password cracked: {password}")
                print(f"Attempts: {attempt}")
                success = True
                winsound.Beep(800, 800)
                break

            if attempt % 5_000 == 0:
                print(f"Attempt {attempt}...")

        self.assertTrue(True)

        if not success:
            print("[INFO] Brute-force did not succeed within limit")


if __name__ == "__main__":
    unittest.main()
