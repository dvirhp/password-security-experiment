import unittest
import tempfile

from application import AuthServer
from attack import BruteForceAttack
from configuration import hash_mode, get_hash_params

BASE_PROTECTIONS = {
    "pepper": "25977022"
}

RATE_LIMIT_ONLY = {
    **BASE_PROTECTIONS,
    "rate_limit": {"tokens": 3, "refill_rate_tps": 1}
}

CAPTCHA_ONLY = {
    **BASE_PROTECTIONS,
    "captcha": {"tokens": 3, "time_to_live": 60}
}

LOCKOUT_ONLY = {
    **BASE_PROTECTIONS,
    "lockout": {"tokens": 3, "token_rate": 2, "duration_rate": 1, "duration_mm": 0}
}

TOTP_ONLY = {
    **BASE_PROTECTIONS,
    "totp": {"number_of_users": 5, "tokens": 3, "time_step_ss": 30, "tolerance_ss": 30}
}


class BruteForceAttackTestCase(unittest.TestCase):

    def setUp(self):
        self.temp_dir = None
        self.auth = None
        self.client = None

    def tearDown(self):
        if self.auth:
            self.auth.close_database()
        if self.temp_dir:
            self.temp_dir.cleanup()
        print("Closing database...")

    def _create_server(self, protections):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth = AuthServer(
            self.temp_dir.name,
            hash_mode,
            get_hash_params(hash_mode),
            protections
        )
        self.client = self.auth._app.test_client()

    def _register_user(self):
        self.client.post(
            "/register",
            json={"username": "alice", "password": "a2b25"},
            environ_base={"REMOTE_ADDR": "1.1.1.1"}
        )

    @staticmethod
    def _default_rules():
        return {
            "username": "alice",
            "max_attempts": 10,
            "ip_switch_enabled": False,
            "lockout_stop_enabled": True,
            "password_strength": "weak",
            "captcha_token_enabled": True,
            "seed": "25977022",
            "delay_ss": 0
        }

    # -------------------------
    # TESTS
    # -------------------------

    def test_attack_no_protections_succeeds(self):
        self._create_server(BASE_PROTECTIONS)
        self._register_user()

        rules = self._default_rules()
        attack = BruteForceAttack(self.client, rules)

        success, attempts, _ = attack.attack()

        self.assertFalse(success)
        self.assertLessEqual(attempts, rules["max_attempts"])

    def test_attack_rate_limit_with_delay(self):
        self._create_server(RATE_LIMIT_ONLY)
        self._register_user()

        rules = self._default_rules()
        rules["delay_ss"] = 1

        attack = BruteForceAttack(self.client, rules)

        success, attempts, _ = attack.attack()

        self.assertFalse(success)

    def test_attack_rate_limit_switch_ip(self):
        self._create_server(RATE_LIMIT_ONLY)
        self._register_user()

        rules = self._default_rules()
        rules["ip_switch_enabled"] = True

        attack = BruteForceAttack(self.client, rules)

        success, attempts, _ = attack.attack()

        self.assertFalse(success)

    def test_attack_captcha_required(self):
        self._create_server(CAPTCHA_ONLY)
        self._register_user()

        rules = self._default_rules()
        rules["captcha_token_enabled"] = True

        attack = BruteForceAttack(self.client, rules)

        success, attempts, result = attack.attack()

        self.assertFalse(success)

    def test_attack_totp_fails(self):
        self._create_server(TOTP_ONLY)
        self._register_user()

        rules = self._default_rules()
        attack = BruteForceAttack(self.client, rules)

        success, attempts, error = attack.attack()

        self.assertFalse(success)

    def test_attack_lockout_stops(self):
        self._create_server(LOCKOUT_ONLY)
        self._register_user()

        rules = self._default_rules()
        rules["lockout_stop_enabled"] = True

        attack = BruteForceAttack(self.client, rules)

        success, attempts, error = attack.attack()

        self.assertFalse(success)
        self.assertIn("blocked", str(error).lower())


if __name__ == "__main__":
    unittest.main()
