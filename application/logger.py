import json
from pathlib import Path
from datetime import datetime


class Logger:
    """
    Handles structured logging for authentication-related events.

    Logs are written in JSON Lines (JSONL) format to allow
    easy parsing, aggregation, and analysis.
    """

    def __init__(self, directory_path, group_seed, selected_hash_mode, hash_param, protections):
        """
        Initialize log file paths and metadata shared across all log entries.

        Args:
            directory_path (str | Path): Directory where log files are stored.
            group_seed: Identifier used to correlate logs across deployments.
            selected_hash_mode (str): Active password hashing algorithm.
            hash_param (dict): Parameters used by the hashing algorithm.
            protections (dict): Enabled security protections (e.g., pepper, CAPTCHA).
        """
        self._log_directory = Path(directory_path)

        self._attempt_log = self._log_directory / "attempts.log"
        self._register_log = self._log_directory / "register.log"

        self._group_seed = group_seed
        self._hash_mode = selected_hash_mode
        self._hash_params = hash_param
        self._protections = protections

    def _log(self, path, ip_address, username, result, action, status, message, latency_ms):
        """
        Write a single authentication event to a log file.

        Args:
            path (Path): Target log file.
            action (str): Action performed (e.g., "login", "register").
            latency_ms (float): Request duration in milliseconds.
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "group_seed": self._group_seed,
            "IP address": ip_address,
            "username": username,
            "hash_mode": self._hash_mode,
            "hash_parameters": self._hash_params,
            "protection_flags": self._protections,
            "result": result,
            "status": status,
            "action": action,
            "message": message,
            "latency_ms": round(latency_ms, 3)
        }

        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def log_register(self, ip_address, username, result, status, message, start_time, end_time):
        """Log a user registration attempt."""
        latency_ms = (end_time - start_time) * 1000
        self._log(self._register_log, ip_address, username, result, "register", status, message, latency_ms)

    def log_login(self, ip_address, username, result, status, message, start_time, end_time):
        """Log a user login attempt."""
        latency_ms = (end_time - start_time) * 1000
        self._log(self._attempt_log, ip_address, username, result, "login", status, message, latency_ms)

    @staticmethod
    def log_experiment(path, experiment_id, parameters, success, attempts, message, latency_ms):
        """
        Log the result of an offline security experiment or attack simulation.

        Sensitive values (e.g., pepper contents) are redacted before logging.
        """
        pepper = parameters["protections"].get("pepper", None)
        if pepper:
            parameters["protections"]["pepper"] = True
        else:
            parameters["protections"].pop("pepper", None)
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "experiment_id": experiment_id,
            "attack_parameters": parameters["attack_parameters"],
            "hash_mode": parameters["hash_mode"],
            "hash_parameters": parameters["hash_parameters"],
            "protections": parameters["protections"],
            "success": success,
            "attempts": attempts,
            "message": message,
            "latency_ms": round(latency_ms, 3)
        }

        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
