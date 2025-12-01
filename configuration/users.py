"""
Dummy (members) generator.

This module creates a set of test users for development or testing purposes.
Specifically, it generates 30 members with associated passwords, divided into
three strength levels:

    - 10 members with weak passwords
    - 10 members with medium-strength passwords
    - 10 members with strong passwords

One of the medium-strength users will always have a password equal to the
group_seed (from the config file).

It also provides helpers to:
    - fetch a random user (with or without TOTP)
    - fetch a user including a valid TOTP code
    - fetch a random username filtered by password strength and TOTP usage
"""

import random
import secrets
import string
import pyotp

import json  # TODO: REMOVE AFTER TESTING
from pathlib import Path  # TODO: REMOVE AFTER TESTING

from configuration import GROUP_SEED, get_password_params, get_totp_user_count


class DummyMembers:
    """
    Container object for all generated dummy users.
    """

    def __init__(self, group_seed):
        self._group_seed = group_seed
        self._members = []
        self._weak_members = []
        self._medium_members = []
        self._strong_members = []
        self._totp_users = []

        self._generate_members()

    def _generate_member(self, strength, index):
        return {
            "username": f"{strength}_user_{index}",
            "password": self.generate_password(strength),
            "strength": f"{strength}",
            "totp_secret": None
        }

    def _generate_members_by_quantity(self, strength, quantity) -> list:
        return [self._generate_member(strength, i) for i in range(quantity)]

    def _set_random_member_to_group_seed(self, members):
        if not members:
            raise ValueError("Member list is empty.")

        member = random.choice(members)
        member["password"] = self._group_seed

    def _generate_members(self):
        """Populate the internal members list with 30 users."""

        self._weak_members = self._generate_members_by_quantity("weak", 10)
        self._medium_members = self._generate_members_by_quantity("medium", 10)
        self._strong_members = self._generate_members_by_quantity("strong", 10)

        self._set_random_member_to_group_seed(self._medium_members)

        self._members.extend(self._weak_members + self._medium_members + self._strong_members)

        self._assign_totp_to_some_users(get_totp_user_count())

    def _assign_totp_to_user(self, members):
        temp = random.sample(members, 1)[0]
        temp["totp_secret"] = pyotp.random_base32()
        self._totp_users.append(temp)

    def _assign_totp_to_some_users(self, count):
        """Randomly select users and assign them a TOTP secret."""
        if count < 3:
            raise ValueError("Each strength level must have at least one member assigned a TOTP secret.")

        self._assign_totp_to_user(self._weak_members)
        self._assign_totp_to_user(self._medium_members)
        self._assign_totp_to_user(self._strong_members)

        count -= 3

        already_assigned_ids = {id(m) for m in self._totp_users}
        remaining_candidates = [m for m in self._members if id(m) not in already_assigned_ids]
        chosen = random.sample(remaining_candidates, count)
        for m in chosen:
            m["totp_secret"] = pyotp.random_base32()
            self._totp_users.append(m)

    def get_random_username(self, strength, is_totp=False) -> str:
        """
        Returns a username filtered by:
            - strength  ("weak", "medium", "strong")
            - is_totp  (True/False)
        """
        filtered = [
            m for m in self._members
            if m["strength"] == strength and (m["totp_secret"] is not None) == is_totp
        ]

        if not filtered:
            raise ValueError("No users match the provided filters.")

        return random.choice(filtered)["username"]

    @staticmethod
    def generate_password(strength) -> str:
        """
        Generate a password of a given strength using parameters from config.

        WARNING: This function is NOT cryptographically secure and should only
           be used for experimental, development, or testing purposes. Do NOT use
           in production systems.

        Args:
            strength (str): One of "weak", "medium", "strong"

        Returns:
            str: Generated password.
        """

        params = get_password_params(strength)

        length = random.randint(params["min_length"], params["max_length"])
        chars = string.ascii_lowercase

        if params.get("include_upper", True):
            chars += string.ascii_uppercase
        if params.get("include_digits", True):
            chars += string.digits
        if params.get("include_punctuation", False):
            chars += string.punctuation

        return ''.join(secrets.choice(chars) for _ in range(length))

    def save_members_to_json(self, file_path="users.json"):  # TODO: REMOVE (ONLY FOR TESTING)
        data_to_save = [
            {
                "username": m["username"],
                "password": m["password"],
                "strength": m["strength"],
                "totp_secret": m["totp_secret"]
            }
            for m in self._members
        ]

        file = Path(file_path)
        with file.open("w", encoding="utf-8") as f:
            json.dump(data_to_save, f, indent=4)

        print(f"Saved {len(self._members)} users to {file.resolve()}")


dummy_members = DummyMembers(group_seed=GROUP_SEED)


#   TODO: REMOVE (ONLY FOR TESTING)


def main():
    dummy_members.save_members_to_json("users.json")


if __name__ == "__main__":
    main()
