import json
from datetime import datetime
from pathlib import Path


class Logger:
    """
    Responsible for logging authentication attempts
    in JSON-lines format, as required by the project.
    """

    def __init__(self, directory_path, group_seed, selected_hash_mode=None, enabled_protections=None):
        self._log_directory = Path(directory_path)

        self._attempt_log = self._log_directory / "attempts.log"
        self._register_log = self._log_directory / "register.log"

        self._group_seed = group_seed
        self._hash_mode = selected_hash_mode
        self._protections = enabled_protections,

    def _log(self, path, username, result, action, status, message, latency_ms):
        """Write a single JSONL entry to a log file."""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "group_seed": self._group_seed,
            "username": username,
            "hash_mode": self._hash_mode,
            "protection_flags": self._protections,
            "result": result,
            "status": status,
            "action": action,
            "message": message,
            "latency_ms": round(latency_ms, 3)
        }

        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def log_register(self, username, result, status, message, start_time, end_time):
        self._log(self._register_log, username, result, "register", status, message, (end_time - start_time) * 1000)

    def log_login(self, username, result, status, message, start_time, end_time):
        self._log(self._attempt_log, username, result, "login", status, message, (end_time - start_time) * 1000)
