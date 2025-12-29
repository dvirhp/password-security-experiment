"""
Experiments Generator

This module generates authentication attack experiments for testing purposes.
It supports multiple hash algorithms, password strengths, and various protection mechanisms.
Each experiment is assigned to group based on hash, strength, and protection type.
"""

import json
from pathlib import Path
from collections import defaultdict

from configuration import GROUP_SEED, get_environmental_pepper

CONFIG_PATH = Path(__file__).parent / "experiments.json"
BASE_PROTECTIONS = {"pepper": get_environmental_pepper()}


class ExperimentsGenerator:
    """
    Generates authentication attack experiments and organizes them into groups.

    Attributes:
        _tests (list): List of generated experiment dictionaries.
        _groups (dict): Dictionary of grouped experiments keyed by group name.
        _data (dict): Raw configuration loaded from experiments.json.
    """

    def __init__(self):
        """Initialize the generator, load configuration, generate tests, and build groups."""
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            self._data = json.load(f)

        self._tests = []
        self._groups = None

        self._generate_tests()
        self._build_groups()

    @property
    def tests(self):
        """Return the list of all generated experiments."""
        return self._tests

    @property
    def groups(self):
        """Return a dictionary of experiments grouped by hash, strength, and protection."""
        return self._groups

    @property
    def _strength(self):
        return self._data["attack_options"]["password_strength"]

    @property
    def _sha256(self):
        return self._data["hash_options"]["sha256"]

    @property
    def _bcrypt(self):
        return self._data["hash_options"]["bcrypt"]

    @property
    def _argon2id(self):
        return self._data["hash_options"]["argon2id"]

    @property
    def groupers(self):
        """Return a dictionary of functions used to assign experiments to group."""
        return {
            "hash": self._group_by_hash,
            "strength": self._group_by_strength,
            "protection": self._group_by_protection,
        }

    def _assign_groups(self, experiment):
        """Assign experiment to group based on hash, strength, and protection."""
        groups = set()
        for grouper in self.groupers.values():
            groups.add(grouper(experiment))
        return groups

    @staticmethod
    def _pick_first(params_dict):
        """Pick the first value from each parameter list (deterministic selection)."""
        return {k: v[0] for k, v in params_dict.items()}

    def _build_protections(self, protection_names):
        """Return a protection dictionary including base protections and selected protections."""
        protections = dict(BASE_PROTECTIONS)

        for name in protection_names:
            protections[name] = self._pick_first(self._data["protections"][name])

        return protections

    def _base_attack_params(self, strength, alternate=False, ip_switch=False, lockout_stop=False, captcha_token=False):
        """Build default attack parameters for a given strength and optional flags."""
        return {
            "password_strength": strength,
            "max_attempts": self._data["attack_options"]["max_attempts"][0],
            "delay_ss": 0,
            "alternate_strength_enabled": alternate,
            "ip_switch_enabled": ip_switch,
            "lockout_stop_enabled": lockout_stop,
            "captcha_token_enabled": captcha_token,
            "seed": GROUP_SEED,
        }

    def _build_groups(self):
        """Assign groups for all tests and store in the _groups dictionary."""
        self._groups = defaultdict(list)

        for experiment in self._tests:
            experiment["groups"] = self._assign_groups(experiment)
            for group in experiment["groups"]:
                self._groups[group].append(experiment)

    def _generate_tests(self):
        """Generate all experiments with various combinations of hashes, protections, and attack parameters."""
        self._generate_no_protections_tests()
        self._generate_rate_limit_tests()
        self._generate_lockout_tests()
        self._generate_captcha_tests()
        self._generate_totp_tests()
        self._generate_totp_captcha_tests()
        self._generate_totp_lockout_tests()
        self._generate_rate_limit_captcha_tests()
        self._generate_all_protections_tests()

    def _get_hash_parameters(self, hash_mode):
        """Return hash parameters for the given hash mode."""
        if hash_mode == "sha256":
            return self._sha256
        elif hash_mode == "bcrypt":
            return self._bcrypt
        else:
            return self._argon2id

    def _generate_test(self, hash_mode, protections, attack_parameters):
        """Create a single experiment dictionary."""
        return {
            "hash_mode": hash_mode,
            "hash_parameters": self._get_hash_parameters(hash_mode),
            "protections": protections,
            "attack_parameters": attack_parameters,
        }

    def _generate_no_protections_tests(self):
        """Generate experiments with no protections enabled."""
        for strength in self._strength:
            protections = dict(BASE_PROTECTIONS)
            self._tests.append(self._generate_test("sha256", protections, self._base_attack_params(strength)))

        ap = self._base_attack_params("weak", alternate=True)
        self._tests.append(self._generate_test("sha256", dict(BASE_PROTECTIONS), ap))

        self._tests.append(self._generate_test("bcrypt", dict(BASE_PROTECTIONS), self._base_attack_params("weak")))
        self._tests.append(self._generate_test("argon2id", dict(BASE_PROTECTIONS), self._base_attack_params("weak")))

    def _generate_rate_limit_tests(self):
        """Generate experiments with rate limit protection."""
        for ip_switch in [True, False]:
            ap = self._base_attack_params("weak", ip_switch=ip_switch)
            self._tests.append(self._generate_test("sha256", self._build_protections({"rate_limit"}), ap))

    def _generate_lockout_tests(self):
        """Generate experiments with lockout protection."""
        for lockout_stop in [True, False]:
            ap = self._base_attack_params("strong", lockout_stop=lockout_stop)
            self._tests.append(self._generate_test("bcrypt", self._build_protections({"lockout"}), ap))

    def _generate_captcha_tests(self):
        """Generate experiments with captcha protection."""
        for lockout_stop in [True, False]:
            ap = self._base_attack_params("weak", lockout_stop=lockout_stop)
            self._tests.append(self._generate_test("argon2id", self._build_protections({"captcha"}), ap))

        ap = self._base_attack_params("weak", lockout_stop=True, captcha_token=True)
        self._tests.append(self._generate_test("sha256", self._build_protections({"captcha"}), ap))

        ap = self._base_attack_params("weak", ip_switch=True, lockout_stop=True)
        self._tests.append(self._generate_test("sha256", self._build_protections({"captcha"}), ap))

    def _generate_totp_tests(self):
        """Generate experiments with TOTP protection."""
        ap = self._base_attack_params("weak", lockout_stop=True)
        self._tests.append(self._generate_test("sha256", self._build_protections({"totp"}), ap))

        ap = self._base_attack_params("medium", lockout_stop=True)
        self._tests.append(self._generate_test("sha256", self._build_protections({"totp"}), ap))

    def _generate_totp_captcha_tests(self):
        """Generate experiments with both TOTP and captcha protections."""
        ap = self._base_attack_params("weak", lockout_stop=True, captcha_token=True)
        self._tests.append(self._generate_test("sha256", self._build_protections({"captcha", "totp"}), ap))

        ap = self._base_attack_params("weak", alternate=True, lockout_stop=True, captcha_token=True)
        self._tests.append(self._generate_test("sha256", self._build_protections({"captcha", "totp"}), ap))

    def _generate_totp_lockout_tests(self):
        """Generate experiments with both TOTP and lockout protections."""
        ap = self._base_attack_params("weak", ip_switch=True, lockout_stop=True)
        self._tests.append(self._generate_test("sha256", self._build_protections({"lockout", "totp"}), ap))

        ap = self._base_attack_params("strong", ip_switch=True, lockout_stop=True)
        self._tests.append(self._generate_test("sha256", self._build_protections({"lockout", "totp"}), ap))

        ap = self._base_attack_params("strong", ip_switch=True)
        self._tests.append(self._generate_test("sha256", self._build_protections({"lockout", "totp"}), ap))

    def _generate_rate_limit_captcha_tests(self):
        """Generate experiments with both rate limit and captcha protections."""
        for ip_switch in [True, False]:
            ap = self._base_attack_params("weak", ip_switch=ip_switch, lockout_stop=True, captcha_token=True)
            self._tests.append(self._generate_test("sha256", self._build_protections({"rate_limit", "captcha"}), ap))

        ap = self._base_attack_params("medium")
        self._tests.append(self._generate_test("bcrypt", self._build_protections({"rate_limit", "captcha"}), ap))

    def _generate_all_protections_tests(self):
        """Generate experiments with all protections enabled."""
        for lockout_stop in [True, False]:
            protections = self._build_protections({"rate_limit", "lockout", "captcha", "totp"})
            ap = self._base_attack_params("weak", ip_switch=True, lockout_stop=lockout_stop, captcha_token=True)
            self._tests.append(self._generate_test("sha256", protections, ap))

        protections = self._build_protections({"rate_limit", "lockout", "captcha", "totp"})
        ap = self._base_attack_params("medium", alternate=True, ip_switch=True, lockout_stop=True)
        self._tests.append(self._generate_test("argon2id", protections, ap))

    @staticmethod
    def _group_by_hash(experiment):
        return f"hash:{experiment['hash_mode']}"

    @staticmethod
    def _group_by_strength(experiment):
        strength = experiment["attack_parameters"]["password_strength"]
        if strength is None:
            return "strength:random"
        return f"strength:{strength}"

    @staticmethod
    def _group_by_protection(experiment):
        for k in experiment["protections"]:
            if k != "pepper":
                return f"protection:{k}"
        return "protection:none"


def main():
    """Example usage: print all experiments and group counts."""
    generator = ExperimentsGenerator()

    tests = generator.tests
    groups = generator.groups

    print("=== ALL EXPERIMENTS ===")
    for index, test in enumerate(tests, start=1):
        protections = [name for name, enabled in test["protections"].items() if enabled]
        strength = test["attack_parameters"]["password_strength"]
        attack_flags = {k: v for k, v in test["attack_parameters"].items() if isinstance(v, bool) and v is True}

        print(
            f"{index:03d} | "
            f"hash={test['hash_mode']:9s} | "
            f"strength={strength:6s} | "
            f"protections={protections if protections else ['none']} | "
            f"attack_flags={attack_flags if attack_flags else '{}'}"
        )

    print(f"\nTOTAL EXPERIMENTS: {len(tests)}")

    print("\n=== GROUP COUNTS ===")
    for group, experiment in sorted(groups.items()):
        print(f"{group:25s} : {len(experiment)}")


if __name__ == "__main__":
    main()
