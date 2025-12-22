from .rate_limit import RateLimiter
from .lockout import Lockout
from .captcha import Captcha
from .totp import Totp

PROTECTIONS_CLASSES = {
    "rate_limit": RateLimiter,
    "lockout": Lockout,
    "captcha": Captcha,
    "totp": Totp
}


class ProtectionHandler:
    def __init__(self, protections):
        self._protections = protections
        self._instances = {}

        self._initialize_instances()

    def _initialize_protection(self, protection):
        protection_class = PROTECTIONS_CLASSES.get(protection)

        if protection_class is None:
            raise ValueError(f"Invalid protection class in protection.py: {protection}")

        params = self._protections.get(protection, [])
        return protection_class(params) if params else None

    def _initialize_instances(self):
        for name in PROTECTIONS_CLASSES:
            self._instances[name] = self._initialize_protection(name)

    @property
    def rate_limiter(self):
        return self._instances["rate_limit"]

    @property
    def lockout(self):
        return self._instances["lockout"]

    @property
    def captcha(self):
        return self._instances["captcha"]

    @property
    def totp(self):
        return self._instances["totp"]

    @property
    def totp_enabled(self):
        return self.totp is not None

    def rate_limiter_allow_request(self, ip_address):
        return self.rate_limiter and not self.rate_limiter.allow_request(ip_address)

    def handle_lockout(self, response_handler, verify_callable, ip_address, username, start_time):
        allowed, message = self.lockout.allow_attempt(username)
        if not allowed:
            return response_handler.login_lockout(ip_address, username, message, start_time)
        elif verify_callable():
            # self.reset_captcha_failures(ip_address)

            if self.totp_required(username):
                return response_handler.login_totp_required(ip_address, username, start_time)

            self.lockout.reset_after_successful_login(username)
            return response_handler.login_success(ip_address, username, start_time)

        self.lockout.lock_user(username)
        return response_handler.login_fail(ip_address, username, start_time)

    def captcha_required(self, ip_address):
        return self.captcha and self.captcha.captcha_required(ip_address)

    def captcha_register_failure(self, ip_address):
        if self.captcha:
            self.captcha.register_failure(ip_address)

    def captcha_blocked(self, ip_address):
        if self.captcha:
            return self.captcha.captcha_blocked(ip_address)

    def register_totp_if_needed(self, member):
        if self.totp is None:
            return

        totp_secret = member["totp_secret"]

        if totp_secret is not None:
            self.totp.register_user(member["username"], totp_secret)

    def totp_required(self, username):
        return self.totp and self.totp.totp_enabled(username)
