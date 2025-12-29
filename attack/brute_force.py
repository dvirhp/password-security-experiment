import time
import random

from configuration import generate_password
from application import HTTPStatus, CAPTCHA_REQUIRED, TOTP_REQUIRED, ACCOUNT_BLOCKED

STRENGTHS = ["weak", "medium", "strong"]
DEFAULT_CODE = "515151"  # attacker default guess
MAX_ATTEMPTS_REACHED = "max attempts reached"


class BruteForceAttack:
    """
    Simulates a configurable brute-force attack against the authentication server.

    The attack adapts its behavior based on server responses and enabled
    protections (rate limiting, CAPTCHA, TOTP, lockout).
    """

    def __init__(self, client, rules):
        """
        Args:
            client: Flask test client used to send HTTP requests.
            rules (dict): Attack configuration and behavior rules.
        """
        self._client = client
        self._rules = rules
        self._ip_address = self._get_random_ip()

    def attack(self):
        """
        Execute the brute-force attack until success, failure, or exhaustion.

        Returns:
            tuple: (success: bool, attempts: int, message: str)
        """
        for attempt in range(self.max_attempts):
            password = self._generate_random_password()
            response = self._post(password)

            result = self._handle_response(response, attempt)
            if result is not None:
                return result

        return False, self.max_attempts, MAX_ATTEMPTS_REACHED

    def _handle_response(self, response, attempt):
        """
        Interpret server responses and decide whether to continue,
        stop, or adapt the attack strategy.
        """
        status = response.status_code
        data = response.get_json() or {}

        if status == HTTPStatus.UNAUTHORIZED:
            return None
        elif status == HTTPStatus.OK:
            return True, attempt, data.get("message")
        elif status in (HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND):
            return False, attempt, data.get("error")
        elif status == HTTPStatus.TOO_MANY_REQUESTS:
            self._handle_rate_limit()
            return None
        elif status == HTTPStatus.FORBIDDEN:
            return self._handle_forbidden(data, attempt)
        elif status == HTTPStatus.LOCKOUT:
            return self._handle_lockout(data, attempt)

        return False, attempt, "unexpected response"

    def _handle_rate_limit(self):
        """
        React to rate limiting by either switching IP addresses
        or delaying further attempts.
        """
        if self.ip_switch_enabled:
            self._ip_address = self._get_random_ip()
        elif self.delay_ss:
            time.sleep(self.delay_ss)

    def _handle_forbidden(self, data, attempt):
        """Handle forbidden responses such as CAPTCHA or TOTP requirements."""
        error = data.get("error")

        if error == CAPTCHA_REQUIRED:
            return self._handle_captcha_required(attempt)
        elif error == TOTP_REQUIRED:
            self._post_totp(DEFAULT_CODE)  # attacker does not know the code
            return None

        return False, attempt, error

    def _handle_captcha_required(self, attempt):
        """Attempt to solve or bypass CAPTCHA depending on attack rules."""
        captcha_response = self._handle_captcha()

        if captcha_response.status_code == HTTPStatus.ACCEPTED:
            return None

        data = captcha_response.get_json() or {}
        return False, attempt, data.get("error")

    def _handle_lockout(self, data, attempt):
        """Handle account or IP lockout responses."""
        error = data.get("error")

        if error == ACCOUNT_BLOCKED and self.lockout_stop_enabled:
            return False, attempt, error
        elif self.delay_ss:
            time.sleep(self.delay_ss)

        return None

    def _post(self, password):
        """Send a login attempt."""
        return self._client.post(
            "/login",
            json={"username": self.username, "password": password},
            environ_base={"REMOTE_ADDR": self._ip_address}
        )

    def _post_captcha(self, captcha_token):
        """Submit a CAPTCHA token."""
        return self._client.post(
            "/captcha_verify",
            json={"token": captcha_token},
            environ_base={"REMOTE_ADDR": self._ip_address}
        )

    def _post_totp(self, totp_token):
        """Submit a TOTP code."""
        return self._client.post(
            "/login_totp",
            json={"username": self.username, "code": totp_token},
            environ_base={"REMOTE_ADDR": self._ip_address}
        )

    def _get_captcha(self):
        """Request a CAPTCHA token using the shared group seed."""
        return self._client.get(
            "/admin/get_captcha_token",
            query_string={"group_seed": self.seed},
            environ_base={"REMOTE_ADDR": self._ip_address}
        )

    @property
    def username(self):
        """Target username for the attack."""
        return self._rules["username"]

    @property
    def max_attempts(self):
        """Maximum number of brute-force attempts."""
        return self._rules["max_attempts"]

    @property
    def lockout_stop_enabled(self):
        """Stop attack immediately when lockout occurs."""
        return self._rules["lockout_stop_enabled"]

    @property
    def ip_switch_enabled(self):
        """Enable IP rotation to bypass rate limiting."""
        return self._rules["ip_switch_enabled"]

    @property
    def password_strength(self):
        """Primary password strength used for guesses."""
        return self._rules["password_strength"]

    @property
    def alternate_strength_enabled(self):
        """Enable random password strength per attempt."""
        return self._rules["alternate_strength_enabled"]

    @property
    def captcha_token_enabled(self):
        """Enable CAPTCHA token retrieval instead of blind guessing."""
        return self._rules["captcha_token_enabled"]

    @property
    def seed(self):
        """Group seed used for CAPTCHA token requests."""
        return self._rules["seed"]

    @property
    def delay_ss(self):
        """Delay (in seconds) between attempts when throttled."""
        return self._rules["delay_ss"]

    def _generate_random_password(self):
        """Generate a password guess based on configured strength rules."""
        if self.alternate_strength_enabled:
            return generate_password(self._get_random_strength())
        return generate_password(self.password_strength)

    def _handle_captcha(self):
        """
        Solve CAPTCHA either by requesting a valid token
        or submitting a default guess.
        """
        if not self.captcha_token_enabled:
            return self._post_captcha(DEFAULT_CODE)

        response = self._get_captcha()
        if response.status_code != HTTPStatus.OK:
            return response

        token = response.get_json().get("captcha_token")
        return self._post_captcha(token)

    @staticmethod
    def _get_random_strength():
        """Select a random password strength."""
        return random.choice(STRENGTHS)

    @staticmethod
    def _get_random_ip():
        """Generate a random IPv4 address."""
        return ".".join(str(random.randint(0, 255)) for _ in range(4))
