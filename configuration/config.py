"""
Configuration handler.

This module loads and validates configuration data, including:
    - the active hashed mode and its associated parameters
    - enabled or disabled protection mechanisms (e.g., rate limiting, lockouts, CAPTCHA, TOTP)

It centralizes all configuration logic to ensure consistent and secure behavior across the system.
"""

import json
import os
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "config.json"


class Config:
    def __init__(self):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            self._data = json.load(f)
        self._pepper_cache = None

    @property
    def raw(self) -> dict:
        """Full raw config dict."""
        return self._data

    @property
    def group_seed(self) -> str:
        return self._data["group_seed"]

    @property
    def hash_mode(self) -> str:
        return self._data["hash_mode"]

    @property
    def hash_parameters(self) -> dict:
        return self._data["hash_parameters"]

    def get_hash_params(self, mode=None) -> dict:
        """Return params for the currently configured hashed mode."""
        if mode is None:
            mode = self.hash_mode
        return self.hash_parameters.get(mode, {})

    @property
    def protections(self) -> dict:
        """Enabled/disabled booleans."""
        return self._data["protections"]

    @property
    def protections_parameters(self) -> dict:
        """Parameters for each protection."""
        return self._data["protections_parameters"]

    def get_protection_with_params(self) -> dict:
        """
        Return { protection_name: parameters } ONLY for enabled protections.
        """
        result = {}
        for name, enabled in self.protections.items():
            if not enabled:
                continue

            key = name.replace("_enabled", "")

            if key == "pepper":
                result[key] = self._get_environmental_pepper()
            else:
                result[key] = self.protections_parameters.get(key + "_parameters", {})

        return result

    def get_totp_user_count(self) -> int:
        """
        Return the number of users to assign TOTP to, as defined in the config.

        Returns:
            int: Number of users for TOTP.
        """
        return self._data.get("protections_parameters", {}) \
                         .get("totp_parameters", {}) \
                         .get("number_of_users", 0)

    def _get_environmental_pepper(self) -> str:
        """
         Load the cryptographic PEPPER from environment variables.

         Returns:
             str: The pepper value.

         Raises:
             RuntimeError: If PEPPER is missing or empty.
         """
        if self._pepper_cache is not None:
            return self._pepper_cache

        env_pepper = os.getenv("PEPPER", "").strip()

        if not env_pepper:
            raise RuntimeError("PEPPER environment variable not found.")

        self._pepper_cache = env_pepper
        return env_pepper

    def get_password_params(self, strength) -> dict:
        """
        Return the password generation parameters for the given strength.

        Args:
            strength (str): "weak", "medium", or "strong"

        Returns:
            dict: Parameters, e.g.

        Raises:
            ValueError: If strength is invalid or not found in config.
        """
        password_params = self._data.get("password_parameters", {}).get(strength)
        if not password_params:
            raise ValueError(f"Password parameters for strength '{strength}' not found in config.")

        return password_params


config = Config()
