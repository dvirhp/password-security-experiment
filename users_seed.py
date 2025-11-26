import random
from db import get_db, init_db
from security import generate_salt, hash_password
from config import CONFIG
import string

# Personal IDs used to derive deterministic SEED
# Dvir (ID): 314685751
# Bar  (ID): 323869065
# SEED = XOR of both IDs
DVIR_ID = 314685751
BAR_ID = 323869065

SEED = DVIR_ID ^ BAR_ID  # 137,379,782

# Initialize deterministic randomness
random.seed(SEED)

# Password generators (purely based on SEED no fixed lists)
def generate_weak_password():
    # Weak password: 4–6 numeric digits (very easy to brute-force)
    digits = "0123456789"
    length = random.randint(4, 6)
    return "".join(random.choice(digits) for _ in range(length))

def generate_medium_password():
    # Medium password: 3–6 lowercase letters followed by 2–3 digits
    letters = "abcdefghijklmnopqrstuvwxyz"
    word_length = random.randint(3, 6)
    num_length = random.randint(2, 3)

    word = "".join(random.choice(letters) for _ in range(word_length)).capitalize()
    number = "".join(str(random.randint(0, 9)) for _ in range(num_length))

    return word + number

def generate_strong_password():
    # Strong password: 10–14 characters (upper/lower/digits/symbols)
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    length = random.randint(10, 14)
    return "".join(random.choice(chars) for _ in range(length))

# Build 30 deterministic users
weak_users = [(f"weak{i:02d}", generate_weak_password()) for i in range(1, 11)]
medium_users = [(f"medium{i:02d}", generate_medium_password()) for i in range(1, 11)]
strong_users = [(f"strong{i:02d}", generate_strong_password()) for i in range(1, 11)]

# Insert into DB
def seed_group(users, strength: str):
    # Insert each group (weak/medium/strong) into the database
    conn = get_db()
    cur = conn.cursor()

    for username, password in users:
        # For SHA-256 we generate per-user salt; other modes ignore salt
        if CONFIG["hash_mode"] == "sha256":
            salt = generate_salt()
        else:
            salt = ""

        password_hash = hash_password(password, salt)

        cur.execute(
            "INSERT INTO users (username, password_hash, salt, strength) VALUES (?, ?, ?, ?)",
            (username, password_hash, salt, strength),
        )

    conn.commit()
    conn.close()

def main():
    init_db()
    seed_group(weak_users, "weak")
    seed_group(medium_users, "medium")
    seed_group(strong_users, "strong")
    print("30 deterministic users inserted based on SEED =", SEED)

if __name__ == "__main__":
    main()
