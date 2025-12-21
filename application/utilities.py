import hashlib
import random
import secrets
import time


def get_random_ip():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))


def generate_token(group_seed) -> str:
    raw = f"{group_seed}:{secrets.token_hex(16)}:{time.perf_counter()}"
    token = hashlib.sha256(raw.encode()).hexdigest()

    return token
