import unittest
from application import AuthServer, Database
from configuration import hash_mode, protections


class AuthServerTestCase(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")  # in-memory DB for testing
        self.auth = AuthServer(database=self.db, selected_hash_mode=hash_mode, enabled_protections=protections)
        self.client = self.auth._app.test_client()  # Flask test client

    def tearDown(self):
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
