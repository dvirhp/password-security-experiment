import json
import time
from datetime import datetime
from pathlib import Path


class AttemptLogger:
    """
    Responsible for logging authentication attempts
    in JSON-lines format, as required by the project.
    """

    def __init__(self, log_path: str, group_seed: str):
        self._log_path = Path(log_path)
        self._group_seed = group_seed

    def log(
        self,
        username: str,
        result: str,
        hash_mode: str,
        protection_flags: dict,
        start_time: float,
        action=None
    ):
        latency_ms = (time.time() - start_time) * 1000

        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "group_seed": self._group_seed,
            "username": username,
            "hash_mode": hash_mode,
            "protection_flags": protection_flags,
            "result": result,
            "latency_ms": round(latency_ms, 3),
        }

        if action is not None:
            entry["action"] = action

        with self._log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
