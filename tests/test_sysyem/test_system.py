import os
import time
import unittest
from pathlib import Path
import tempfile
from application import AuthServer
from configuration import hash_mode, get_hash_params

DIRECTORY_PATH = Path(__file__).parent

BASE_PROTECTIONS = {
    "pepper": "137379782"
}

RATE_LIMIT_ONLY = {
    **BASE_PROTECTIONS,
    "rate_limit": {"tokens": 3, "refill_rate_tps": 1}
}

LOCKOUT_ONLY = {
    **BASE_PROTECTIONS,
    "lockout": {"tokens": 3, "token_rate": 2, "duration_rate": 1, "duration_mm": 0}
}

CAPTCHA_ONLY = {
    **BASE_PROTECTIONS,
    "captcha": {"tokens": 3, "time_to_live": 60}
}

TOTP_ONLY = {
    **BASE_PROTECTIONS,
    "totp": {"number_of_users": 5, "tokens": 3, "time_step_ss": 30, "tolerance_ss": 30}
}

NO_PROTECTIONS = BASE_PROTECTIONS

os.environ["pepper"] = "137379782"

_protections = {
    "pepper": "137379782",
    "rate_limit": {"tokens": 3, "refill_rate_tps": 1},
    "lockout": {"tokens": 3, "token_rate": 2, "duration_rate": 1, "duration_mm": 0},
    "captcha": {"tokens": 3, "time_to_live": 60},
    "totp": {"number_of_users": 5, "tokens": 3, "time_step_ss": 30, "tolerance_ss": 30}
}

REQUESTS = {
    "register_alice": {
        "path": "/register",
        "json": {"username": "alice", "password": "a2b25"},
        "ip": "192.168.1.10",
    },
    "register_bob": {
        "path": "/register",
        "json": {"username": "bob", "password": "a2c85"},
        "ip": "192.168.1.10",
    },
    "login_alice": {
        "path": "/login",
        "json": {"username": "alice", "password": "a2b25"},
        "ip": "192.168.1.10",
    },
    "login_alice_different_ip": {
        "path": "/login",
        "json": {"username": "alice", "password": "a2b25"},
        "ip": "192.666.1.10",
    },
    "login_wrong_password": {
        "path": "/login",
        "json": {"username": "alice", "password": "a3b25"},
        "ip": "192.168.1.10",
    },
    "login_bob": {
        "path": "/login",
        "json": {"username": "bob", "password": "a2c85"},
        "ip": "192.168.1.10",
    },
    "register_invalid_input": {
        "path": "/register",
        "json": {"username": "alice"},
        "ip": "192.168.1.10",
    },
    "login_invalid_input": {
        "path": "/login",
        "json": {"username": "alice"},
        "ip": "192.168.1.10",
    },
}


class BruteForceTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = None
        self.auth = None
        self.client = None
        # self.temp_dir = tempfile.TemporaryDirectory()
        # self.auth = AuthServer(self.temp_dir.name, hash_mode, get_hash_params(hash_mode), _protections)
        # self.client = self.auth._app.test_client()
        # self.totp = self.auth.totp

    def tearDown(self):
        if self.auth:
            self.auth.close_database()
        if self.temp_dir:
            self.temp_dir.cleanup()

        # self.auth.close_database()

        # Comment this line if you are using a persistent (non-temporary) directory
        # self.temp_dir.cleanup()

        print("Closing database...")

    def create_server(self, protections):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth = AuthServer(
            self.temp_dir.name,
            hash_mode,
            get_hash_params(hash_mode),
            protections
        )
        self.client = self.auth._app.test_client()
        self.protection_handler = getattr(self.auth, "_protection_handler", None)
        self.totp = getattr(self.protection_handler, "totp", None)

    def post(self, req):
        return self.client.post(req["path"], json=req["json"], environ_base={"REMOTE_ADDR": req["ip"]})

    def post_captcha(self, captcha_token, ip_address):
        return self.client.post(
            "/captcha_verify",
            json={"token": captcha_token},
            environ_base={"REMOTE_ADDR": ip_address}
        )

    def get_captcha(self, seed, ip_address):
        return self.client.get(
            "/admin/get_captcha_token",
            query_string={"group_seed": seed},
            environ_base={"REMOTE_ADDR": ip_address}
        )

    def test_register(self):
        self.create_server(BASE_PROTECTIONS)

        response = self.post(REQUESTS["register_alice"])
        self.assertEqual(response.status_code, 201)

    def test_valid_login(self):
        self.create_server(BASE_PROTECTIONS)

        response = self.post(REQUESTS["register_alice"])
        self.assertEqual(response.status_code, 201)

        response = self.post(REQUESTS["login_alice"])
        self.assertEqual(response.status_code, 200)

    def test_invalid_login(self):
        self.create_server(BASE_PROTECTIONS)

        response = self.post(REQUESTS["register_alice"])
        self.assertEqual(response.status_code, 201)

        response = self.post(REQUESTS["login_wrong_password"])
        self.assertEqual(response.status_code, 401)

    def test_register_invalid_input(self):
        self.create_server(BASE_PROTECTIONS)

        response = self.post(REQUESTS["register_invalid_input"])
        self.assertEqual(response.status_code, 400)

    def test_register_conflict(self):
        self.create_server(BASE_PROTECTIONS)

        response = self.post(REQUESTS["register_alice"])
        self.assertEqual(response.status_code, 201)

        response = self.post(REQUESTS["register_alice"])
        self.assertEqual(response.status_code, 409)

    def test_login_invalid_input(self):
        self.create_server(BASE_PROTECTIONS)

        response = self.post(REQUESTS["login_invalid_input"])
        self.assertEqual(response.status_code, 400)

    def test_login_user_not_found(self):
        self.create_server(BASE_PROTECTIONS)

        response = self.post(REQUESTS["login_bob"])
        self.assertEqual(response.status_code, 404)

    def test_brute_force_poc_no_protections(self):
        self.create_server(BASE_PROTECTIONS)
        
        response = self.post(REQUESTS["register_alice"])
        self.assertEqual(response.status_code, 201)

        for _ in range(3):
            response = self.post(REQUESTS["login_wrong_password"])
            self.assertEqual(response.status_code, 401)

        response = self.post(REQUESTS["login_alice"])
        self.assertEqual(response.status_code, 200)

    def test_brute_force_poc_rate_limit(self):
        self.create_server(RATE_LIMIT_ONLY)
        
        response = self.post(REQUESTS["register_alice"])
        self.assertEqual(response.status_code, 201)

        for _ in range(3):
            response = self.post(REQUESTS["login_wrong_password"])
            self.assertEqual(response.status_code, 401)

        response = self.post(REQUESTS["login_alice"])
        self.assertEqual(response.status_code, 429)

        time.sleep(2)

        response = self.post(REQUESTS["login_alice"])
        self.assertEqual(response.status_code, 200)

    def test_brute_force_poc_rate_limit_switch_ip(self):
        self.create_server(RATE_LIMIT_ONLY)

        response = self.post(REQUESTS["register_alice"])
        self.assertEqual(response.status_code, 201)

        for _ in range(3):
            response = self.post(REQUESTS["login_wrong_password"])
            self.assertEqual(response.status_code, 401)

        response = self.post(REQUESTS["login_alice"])
        self.assertEqual(response.status_code, 429)

        response = self.post(REQUESTS["login_alice_different_ip"])
        self.assertEqual(response.status_code, 200)

    def test_brute_force_poc_lockout(self):
        self.create_server(LOCKOUT_ONLY)

        response = self.post(REQUESTS["register_alice"])
        self.assertEqual(response.status_code, 201)

        response = self.post(REQUESTS["register_bob"])
        self.assertEqual(response.status_code, 201)

        for _ in range(3):
            response = self.post(REQUESTS["login_wrong_password"])
            self.assertEqual(response.status_code, 401)

        time.sleep(1)

        response = self.post(REQUESTS["login_alice"])
        self.assertEqual(response.status_code, 200)

        for _ in range(3):
            response = self.post(REQUESTS["login_wrong_password"])
            self.assertEqual(response.status_code, 401)

        time.sleep(1)

        response = self.post(REQUESTS["login_wrong_password"])
        self.assertEqual(response.status_code, 401)

        time.sleep(1)

        response = self.post(REQUESTS["login_alice"])
        self.assertEqual(response.status_code, 423)

        response = self.post(REQUESTS["login_bob"])
        self.assertEqual(response.status_code, 200)

    def test_brute_force_poc_captcha(self):
        self.create_server(CAPTCHA_ONLY)

        response = self.post(REQUESTS["register_alice"])
        self.assertEqual(response.status_code, 201)

        for _ in range(3):
            response = self.post(REQUESTS["login_wrong_password"])
            self.assertEqual(response.status_code, 401)

        response = self.post(REQUESTS["login_alice"])
        self.assertEqual(response.status_code, 403)
        self.assertIn("captcha required", response.get_json()["error"])

        resp = self.get_captcha("66666666", "192.168.1.10")
        self.assertEqual(resp.status_code, 400)

        resp = self.get_captcha("137379782", "192.168.1.10")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        captcha_token = data.get("captcha_token")

        resp = self.post_captcha(captcha_token, "192.168.1.10")
        self.assertEqual(resp.status_code, 202)

        response = self.post(REQUESTS["login_alice"])
        self.assertEqual(response.status_code, 200)

        for _ in range(3):
            response = self.post(REQUESTS["login_wrong_password"])
            self.assertEqual(response.status_code, 401)

        response = self.post(REQUESTS["login_alice"])
        self.assertEqual(response.status_code, 403)
        self.assertIn("captcha required", response.get_json()["error"])

        resp = self.get_captcha("137379782", "192.168.1.10")
        self.assertEqual(resp.status_code, 200)

        resp = self.post_captcha("666", "192.168.1.10")
        self.assertEqual(resp.status_code, 400)

        response = self.post(REQUESTS["login_alice"])
        self.assertEqual(response.status_code, 423)

    def test_brute_force_poc_totp(self):
        self.create_server(TOTP_ONLY)

        response = self.post(REQUESTS["register_alice"])
        self.assertEqual(response.status_code, 201)

        response = self.post(REQUESTS["login_alice"])
        self.assertEqual(response.status_code, 403)
        self.assertIn("totp required", response.get_json()["error"])

        response = self.post({"path": "/login_totp", "json": {"username": "alice"}, "ip": "192.168.1.10"})
        self.assertEqual(response.status_code, 400)

        code = self.totp.generate_code("alice")
        response = self.post({"path": "/login_totp", "json": {"username": "alice", "code": code}, "ip": "192.168.1.10"})
        self.assertEqual(response.status_code, 200)

        response = self.post(REQUESTS["login_alice"])
        self.assertEqual(response.status_code, 403)
        self.assertIn("totp required", response.get_json()["error"])

        response = self.post({"path": "/login_totp", "json": {"username": "alice", "code": "21"}, "ip": "192.168.1.10"})
        self.assertEqual(response.status_code, 401)

        response = self.post({"path": "/login_totp", "json": {"username": "alice", "code": "21"}, "ip": "192.168.1.10"})
        self.assertEqual(response.status_code, 401)

        response = self.post({"path": "/login_totp", "json": {"username": "alice", "code": "21"}, "ip": "192.168.1.10"})
        self.assertEqual(response.status_code, 401)

        code = self.totp.generate_code("alice")
        response = self.post({"path": "/login_totp", "json": {"username": "alice", "code": code}, "ip": "192.168.1.10"})
        self.assertEqual(response.status_code, 423)

        response = self.post(REQUESTS["register_bob"])
        self.assertEqual(response.status_code, 201)

        response = self.post(REQUESTS["login_bob"])
        self.assertEqual(response.status_code, 403)
        self.assertIn("totp required", response.get_json()["error"])

        code = self.totp.generate_code("bob", drift_seconds=20)
        response = self.post({"path": "/login_totp", "json": {"username": "bob", "code": code}, "ip": "192.168.1.10"})
        self.assertEqual(response.status_code, 200)

        response = self.post(REQUESTS["login_bob"])
        self.assertEqual(response.status_code, 403)
        self.assertIn("totp required", response.get_json()["error"])

        code = self.totp.generate_code("bob", drift_seconds=90)
        response = self.post({"path": "/login_totp", "json": {"username": "bob", "code": code}, "ip": "192.168.1.10"})
        self.assertEqual(response.status_code, 401)

        response = self.post({"path": "/login_totp", "json": {"username": "bob", "code": code}, "ip": "192.168.1.10"})
        self.assertEqual(response.status_code, 401)

        response = self.post({"path": "/login_totp", "json": {"username": "bob", "code": code}, "ip": "192.168.1.10"})
        self.assertEqual(response.status_code, 401)

        code = self.totp.generate_code("bob")
        response = self.post({"path": "/login_totp", "json": {"username": "bob", "code": code}, "ip": "192.168.1.10"})
        self.assertEqual(response.status_code, 423)


if __name__ == "__main__":
    unittest.main()
