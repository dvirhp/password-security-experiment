import time
import json
from db import get_db
from config import CONFIG

ATTEMPTS_LOG_PATH = "attempts.log"

def log_attempt(username: str, result: str, latency_ms: float) -> None:
    # Log a single login attempt into DB and JSON-lines file
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")  # Human-readable timestamp
    group_seed = CONFIG.get("group_seed", "default")  # Label for experiment grouping
    hash_mode = CONFIG["hash_mode"]  # Current hashing algorithm used
    protection_flags = json.dumps(CONFIG["protections"])  # Store protections as JSON string

    # Insert log entry into SQLite database
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO logs (timestamp, group_seed, username, hash_mode, protection_flags, result, latency_ms) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (timestamp, group_seed, username, hash_mode, protection_flags, result, latency_ms),
    )
    conn.commit()
    conn.close()

    # Write JSON-lines log file for external analysis
    entry = {
        "timestamp": timestamp,
        "group_seed": group_seed,
        "username": username,
        "hash_mode": hash_mode,
        "protection_flags": CONFIG["protections"],
        "result": result,
        "latency_ms": latency_ms,
    }

    with open(ATTEMPTS_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
