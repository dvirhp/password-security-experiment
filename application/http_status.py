from enum import IntEnum

CAPTCHA_REQUIRED = "captcha required"
TOTP_REQUIRED = "totp required"
ACCOUNT_BLOCKED = "account blocked, contact admin"
ACCOUNT_TEMPORARILY_BLOCKED = "account temporarily locked"


class HTTPStatus(IntEnum):
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    CONFLICT = 409
    LOCKOUT = 423
    TOO_MANY_REQUESTS = 429
