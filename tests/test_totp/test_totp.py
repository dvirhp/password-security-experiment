import time
import unittest
import pyotp

from protection.totp import Totp


def _generate_code(secret):
    totp = pyotp.TOTP(secret)
    return totp.at(int(time.time()))


class TestTotp(unittest.TestCase):

    def setUp(self):
        self.params = {
            "time_step_ss": 30,
            "tolerance_ss": 30,   # ±30 seconds
            "tokens": 3,          # max failures before block
        }
        self.totp = Totp(parameters=self.params)

        self.username = "alice"
        self.secret = pyotp.random_base32()
        self.totp.register_user(self.username, self.secret)

    # ---------- basic behavior ----------

    def test_success(self):
        code = self.totp.generate_code(self.username)
        self.assertTrue(self.totp.verify(self.username, code))
        self.assertFalse(self.totp.totp_blocked(self.username))

    def test_wrong_code(self):
        self.assertFalse(self.totp.verify(self.username, "000000"))
        self.assertFalse(self.totp.totp_blocked(self.username))

    # ---------- blocking ----------

    def test_block_after_max_failures(self):
        for _ in range(self.params["tokens"]):
            self.assertFalse(self.totp.verify(self.username, "000000"))

        self.assertTrue(self.totp.totp_blocked(self.username))

    def test_blocked_user_always_fails(self):
        for _ in range(self.params["tokens"]):
            self.totp.verify(self.username, "000000")

        code = self.totp.generate_code(self.username)
        self.assertFalse(self.totp.verify(self.username, code))

    def test_reset_unblocks_user(self):
        for _ in range(self.params["tokens"]):
            self.totp.verify(self.username, "000000")

        self.assertTrue(self.totp.totp_blocked(self.username))

        self.totp.reset_failures(self.username)
        self.assertFalse(self.totp.totp_blocked(self.username))

        code = self.totp.generate_code(self.username)
        self.assertTrue(self.totp.verify(self.username, code))

    # ---------- clock drift ----------

    def test_within_drift(self):
        code = self.totp.generate_code(self.username, drift_seconds=20)
        self.assertTrue(self.totp.verify(self.username, code))

    def test_outside_drift(self):
        code = self.totp.generate_code(self.username, drift_seconds=90)
        self.assertFalse(self.totp.verify(self.username, code))

    # ---------- attack simulations ----------

    def test_bruteforce_blocks_account(self):
        attempts = 0
        while not self.totp.totp_blocked(self.username):
            self.totp.verify(self.username, "123456")
            attempts += 1

        self.assertEqual(attempts, self.params["tokens"])

    def test_password_spraying(self):
        users = []
        for i in range(10):
            username = f"user{i}"
            secret = pyotp.random_base32()
            self.totp.register_user(username, secret)
            users.append(username)

        for username in users:
            self.assertFalse(self.totp.verify(username, "000000"))
            self.assertFalse(self.totp.totp_blocked(username))


if __name__ == "__main__":
    unittest.main()
