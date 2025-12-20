import time

class Captcha:
    def __init__(self, delay_seconds=0.25):
        self.delay_seconds = delay_seconds

    def is_required(self, attempts_count: int) -> bool:
        return attempts_count >= 1

    def verify_token(self, token: str) -> bool:
        return token == "valid-captcha-token"

    def apply_delay(self):
        time.sleep(self.delay_seconds)
