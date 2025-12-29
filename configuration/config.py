"""
Configuration handler.

This module loads and validates configuration data, including:
    - the active hash mode and its associated parameters
    - enabled or disabled protection mechanisms (e.g., rate limiting, lockouts, CAPTCHA, TOTP)

It centralizes all configuration logic to ensure consistent and secure behavior across the system.
"""

import os
import json
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "config.json"


class Config:
    """
    Loads, stores, and exposes validated configuration values.

    Acts as a single source of truth for hashing, protections,
    and password generation parameters.
    """

    def __init__(self):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            self._data = json.load(f)
        self._pepper_cache = None

    @property
    def raw(self) -> dict:
        """Return the full raw configuration dictionary."""
        return self._data

    @property
    def group_seed(self) -> str:
        """Global seed used for experiments and administrative actions."""
        return self._data["group_seed"]

    @property
    def hash_mode(self) -> str:
        """Active password hashing algorithm."""
        return self._data["hash_mode"]

    @property
    def hash_parameters(self) -> dict:
        """All hash parameters grouped by hash mode."""
        return self._data["hash_parameters"]

    def get_hash_params(self, mode=None) -> dict:
        """
        Return hash parameters for the selected hash mode.

        Args:
            mode (str, optional): Hash mode override.

        Returns:
            dict: Hash parameters for the given mode.
        """
        if mode is None:
            mode = self.hash_mode
        return self.hash_parameters.get(mode, {})

    @property
    def protections(self) -> dict:
        """Enabled/disabled protection flags."""
        return self._data["protections"]

    @property
    def protections_parameters(self) -> dict:
        """Configuration parameters for each protection."""
        return self._data["protections_parameters"]

    @property
    def rate_limit_parameters(self) -> dict:
        """Rate limiting configuration."""
        return self.protections_parameters["rate_limit_parameters"]

    @property
    def lockout_parameters(self) -> dict:
        """Account lockout configuration."""
        return self.protections_parameters["lockout_parameters"]

    @property
    def captcha_parameters(self) -> dict:
        """CAPTCHA configuration."""
        return self.protections_parameters["captcha_parameters"]

    @property
    def totp_parameters(self) -> dict:
        """TOTP configuration."""
        return self.protections_parameters["totp_parameters"]

    def get_protection_with_params(self) -> dict:
        """
        Return enabled protections mapped to their parameters.

        Only protections explicitly enabled in the configuration
        are included in the result.
        """
        result = {}
        for name, enabled in self.protections.items():
            if not enabled:
                continue

            key = name.replace("_enabled", "")

            if key == "pepper" and self.get_environmental_pepper():
                result[key] = self._pepper_cache
            else:
                result[key] = self.protections_parameters.get(key + "_parameters", {})

        return result

    def get_totp_user_count(self) -> int:
        """
        Return the number of users to assign TOTP to.

        Returns:
            int: Number of users requiring TOTP.
        """
        return self._data.get("protections_parameters", {}) \
                         .get("totp_parameters", {}) \
                         .get("number_of_users", 0)

    def get_environmental_pepper(self) -> str:
        """
        Load and cache the cryptographic pepper from environment variables.

        Returns:
            str: Pepper value (empty string if unset).
        """
        if self._pepper_cache is not None:
            return self._pepper_cache

        env_pepper = os.getenv("pepper", "").strip()

        self._pepper_cache = env_pepper
        return env_pepper

    def get_password_params(self, strength) -> dict:
        """
        Return password generation parameters for a given strength.

        Args:
            strength (str): One of "weak", "medium", or "strong".

        Returns:
            dict: Password generation parameters.

        Raises:
            ValueError: If the strength is invalid or missing from config.
        """
        password_params = self._data.get("password_parameters", {}).get(strength)
        if not password_params:
            raise ValueError(f"Password parameters for strength '{strength}' not found in config.")

        return password_params


# Singleton configuration instance used throughout the application
config = Config()
