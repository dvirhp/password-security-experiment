import unittest
from pathlib import Path
import tempfile
from application import AuthServer
from configuration import hash_mode, get_hash_params, protections

DIRECTORY_PATH = Path(__file__).parent


class AuthServerTestCase(unittest.TestCase):
    def setUp(self):
        # self.temp_dir = tempfile.TemporaryDirectory()
        # self.auth = AuthServer(self.temp_dir.name, hash_mode, protections)

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
        response = self.client.post("/register", json={"username": "alice", "password": "my32rd"})
        self.assertEqual(response.status_code, 201)

        # Login user
        response = self.client.post("/login", json={"username": "alice", "password": "my32rd"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("login success", response.get_json().get("message"))

        # Wrong password
        response = self.client.post("/login", json={"username": "alice", "password": "wrong"})
        self.assertEqual(response.status_code, 401)

        # Non-existent user
        response = self.client.post("/login", json={"username": "bob", "password": "123"})
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
