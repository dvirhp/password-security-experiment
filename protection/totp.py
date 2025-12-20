class TOTP:
    def __init__(self, valid_code="123456"):
        self._valid_code = valid_code

    def verify(self, code: str | None) -> bool:
        return code == self._valid_code
