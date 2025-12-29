import os
import bcrypt
import hashlib
from argon2 import PasswordHasher, exceptions as argon2_exceptions

from configuration import hash_mode, get_hash_params


def sha256_hash(value, params) -> str:
    """
    Hash a value using SHA-256 with a random salt.

    Note: SHA-256 is not recommended for password storage.
    """
    salt_length = params.get("salt_length", 16)
    salt = os.urandom(salt_length)
    h = hashlib.sha256(salt + value.encode()).hexdigest()
    return f"{salt.hex()}:{h}"


def verify_sha256_hash(hashed, candidate) -> bool:
    """
    Verify SHA-256 salted hash against a candidate value.

    Raises:
        ValueError: If the stored hash format is invalid.
    """
    try:
        salt_hex, h = hashed.split(":")
    except ValueError:
        raise ValueError("Invalid stored hashed format. Expected 'salt:hashed'.")

    salt = bytes.fromhex(salt_hex)
    candidate_h = hashlib.sha256(salt + candidate.encode()).hexdigest()
    return candidate_h == h


def bcrypt_hash(value, params) -> str:
    """Hash a value using bcrypt."""
    cost = params.get("cost", 12)
    salt = bcrypt.gensalt(rounds=cost)
    return bcrypt.hashpw(value.encode(), salt).decode()


def verify_bcrypt_hash(hashed, candidate) -> bool:
    """Verify a bcrypt hash."""
    return bcrypt.checkpw(candidate.encode(), hashed.encode())


def argon2id_hash(value, params) -> str:
    """
    Hash a value using Argon2id with configurable parameters.

    Argon2id is recommended for modern password hashing.
    """
    argon2_hasher = PasswordHasher(
        time_cost=params["time_cost"],
        memory_cost=params["memory_cost"],
        parallelism=params["parallelism"]
    )

    return argon2_hasher.hash(value)


def verify_argon2id_hash(hashed, candidate, params):
    """Verify an Argon2id hash."""
    argon2_hasher = PasswordHasher(
        time_cost=params["time_cost"],
        memory_cost=params["memory_cost"],
        parallelism=params["parallelism"]
    )

    try:
        return argon2_hasher.verify(hashed, candidate)
    except argon2_exceptions.VerifyMismatchError:
        return False


HASH_FUNCTIONS = {
    "sha256": sha256_hash,
    "bcrypt": bcrypt_hash,
    "argon2id": argon2id_hash
}

HASH_VERIFICATION_FUNCTIONS = {
    "sha256": verify_sha256_hash,
    "bcrypt": verify_bcrypt_hash,
    "argon2id": verify_argon2id_hash
}


def get_hashing_function(mode=hash_mode, hash_params=None, pepper=None):
    """
    Return a configured hashing function for the selected hash mode.

    The returned function automatically applies parameters and optional pepper.
    """
    hash_params = get_hash_params(mode) if hash_params is None else hash_params

    func = HASH_FUNCTIONS.get(mode)
    if func is None:
        raise ValueError(f"Invalid hashed mode in config: {mode}")

    pepper = pepper or ""

    def wrapper(value):
        return func(value + pepper, hash_params)

    return wrapper


def get_hashing_verification_function(mode=hash_mode, hash_params=None, pepper=None):
    """
    Return a configured hash verification function for the selected hash mode.
    """
    func = HASH_VERIFICATION_FUNCTIONS.get(mode)
    if func is None:
        raise ValueError(f"Invalid hashed mode in config: {mode}")

    hash_params = get_hash_params(mode) if hash_params is None else hash_params
    pepper = pepper or ""

    if mode != "argon2id":
        def wrapper(hashed, candidate):
            return func(hashed, candidate + pepper)
        return wrapper

    def wrapper(hashed, candidate):
        return func(hashed, candidate + pepper, hash_params)

    return wrapper
