import os
import unittest
from pathlib import Path
import tempfile
from application import AuthServer
from configuration import hash_mode, get_hash_params, protections

DIRECTORY_PATH = Path(__file__).parent

_protections_1 = {
    "pepper": "25977022",
    "rate_limit": {"tokens": 4, "refill_rate_tps": 0},
    "lockout": {"tokens": 9, "token_rate": 10, "duration_rate": 1, "duration_mm": 0.1},
    "captcha": {"tokens": 15},
    "totp": {"number_of_users": 5, "length": 5, "period_ss": 30}
}

os.environ["pepper"] = "25977022"


class AuthServerTestCase(unittest.TestCase):
    def setUp(self):
        # self.temp_dir = tempfile.TemporaryDirectory()
        # self.auth = AuthServer(self.temp_dir.name, hash_mode, get_hash_params(hash_mode), protections)

        # Uncomment the following line if you want to use a persistent directory instead
        self.auth = AuthServer(DIRECTORY_PATH, "argon2id", get_hash_params("argon2id"), protections)

        self.client = self.auth._app.test_client()  # Flask test client

    def tearDown(self):
        self.auth.close_database()

        # Comment this line if you are using a persistent (non-temporary) directory
        # self.temp_dir.cleanup()

        print("Closing database...")

    def test_register_and_login(self):
        # Register user
        response = self.client.post(
            "/register",
            json={"username": "alice", "password": "my32rd"},
            environ_base={"REMOTE_ADDR": "192.168.1.10"}
        )
        self.assertEqual(response.status_code, 201)

        # Login user
        response = self.client.post(
            "/login",
            json={"username": "alice", "password": "my32rd"},
            environ_base={"REMOTE_ADDR": "192.168.1.10"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("login success", response.get_json().get("message"))

        # Wrong password
        response = self.client.post(
            "/login",
            json={"username": "alice", "password": "wrong"},
            environ_base={"REMOTE_ADDR": "192.168.1.10"}
        )
        self.assertEqual(response.status_code, 401)

        # Non-existent user
        response = self.client.post(
            "/login",
            json={"username": "bob", "password": "123"},
            environ_base={"REMOTE_ADDR": "192.168.1.10"}
        )
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
