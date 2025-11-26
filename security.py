import hashlib
import os
import hmac
import bcrypt
from argon2 import PasswordHasher
from config import CONFIG

# Argon2 configuration (loaded from config.json)
argon = PasswordHasher(
    time_cost=CONFIG["hash_params"]["argon2id"]["time"],
    memory_cost=CONFIG["hash_params"]["argon2id"]["memory"],
    parallelism=CONFIG["hash_params"]["argon2id"]["parallelism"],
)

def generate_salt():
    # Generate random salt for SHA-256 mode
    length = CONFIG["hash_params"]["sha256"]["salt_length"]
    return os.urandom(length).hex()

def hash_password(password: str, salt: str | None) -> str:
    # Hash password according to selected hash_mode
    mode = CONFIG["hash_mode"]
    pepper = CONFIG["pepper"]

    match mode:
        case "sha256":
            # SHA-256 uses per-user salt + pepper
            data = (password + salt + pepper).encode()
            return hashlib.sha256(data).hexdigest()
        
        case "bcrypt":
            # bcrypt ignores manual salt (built-in salt); adds pepper
            data = (password + pepper).encode()
            cost = CONFIG["hash_params"]["bcrypt"]["cost"]
            hashed = bcrypt.hashpw(data, bcrypt.gensalt(cost))
            return hashed.decode()

        case "argon2id":
            # Argon2id with pepper appended
            data = password + pepper
            return argon.hash(data)

        case _:
            raise ValueError(f"Unknown hash mode: {mode}")

def verify_password(password: str, salt: str | None, stored_hash: str) -> bool:
    # Verify password for current hash_mode
    mode = CONFIG["hash_mode"]
    pepper = CONFIG["pepper"]

    match mode:
        case "sha256":
            # recompute SHA-256 with same salt + pepper
            data = (password + salt + pepper).encode()
            calc = hashlib.sha256(data).hexdigest()
            return hmac.compare_digest(calc, stored_hash)

        case "bcrypt":
            # bcrypt verify uses built-in salt inside stored_hash
            data = (password + pepper).encode()
            return bcrypt.checkpw(data, stored_hash.encode())

        case "argon2id":
            # argon2 verify raises exception if mismatch
            try:
                argon.verify(stored_hash, password + pepper)
                return True
            except Exception:
                return False

        case _:
            raise ValueError(f"Unknown hash mode: {mode}")
