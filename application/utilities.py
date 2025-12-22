import hashlib
import random
import secrets
import time


def get_random_ip():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))


