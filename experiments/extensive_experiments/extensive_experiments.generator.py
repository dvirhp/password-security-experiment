"""
Experimental experiments' generator (future work).

This module is NOT part of the core project logic.
It is intended for future experimentation, benchmarking, and analysis of
authentication defenses under different attack configurations.

The code is kept here for extensibility and research purposes, but it is
not used by the main application runtime.
"""

import json
from pathlib import Path
from collections import defaultdict

from configuration import GROUP_SEED, get_environmental_pepper

CONFIG_PATH = Path(__file__).parent / "experiments.json"
BASE_PROTECTIONS = {"pepper": get_environmental_pepper()}


class ExperimentsGenerator:
    def __init__(self):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            self._data = json.load(f)

        self._strength = self._data["attack_options"]["password_strength"]

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

    @property
    def groupers(self):
        return {
            "hash": self._group_by_hash,
            "strength": self._group_by_strength,
            "protection": self._group_by_protection,
        }

    def _assign_groups(self, experiment):
        groups = set()
        for grouper in self.groupers.values():
            groups.add(grouper(experiment))
        return groups

    @staticmethod
    def _pick_first(params_dict):
        """Pick a deterministic representative value from a parameter list."""
        return {k: v[0] for k, v in params_dict.items()}

    def _build_protections(self, protection_names):
        protections = dict(BASE_PROTECTIONS)

        for name in protection_names:
            protections[name] = self._pick_first(self._data["protections"][name])

        return protections

    def _base_attack_params(self, strength):
        return {
            "password_strength": strength,
            "max_attempts": self._data["attack_options"]["max_attempts"][0],
            "delay_ss": 0,
            "alternate_strength_enabled": False,
            "ip_switch_enabled": False,
            "lockout_stop_enabled": False,
            "captcha_token_enabled": True,  # False,
            "seed": GROUP_SEED,
        }

    def generate_tests(self):
        tests = []
        tests += self._generate_no_protection_tests()
        # tests += self._generate_sha256_protection_tests()
        # tests += self._generate_bcrypt_tests()
        # tests += self._generate_argon2id_tests()

        # assign groups
        for experiment in tests:
            experiment["groups"] = self._assign_groups(experiment)

        return tests

    def build_groups(self):
        buckets = defaultdict(list)

        for experiment in self.generate_tests():
            for group in experiment["groups"]:
                buckets[group].append(experiment)

        return buckets

    def _generate_no_protection_tests(self):
        tests = []

        hash_mode = "sha256"
        for strength in self._strength:
            tests.append({
                "hash_mode": hash_mode,
                "hash_parameters": self._data["hash_options"][hash_mode],
                "protections": dict(BASE_PROTECTIONS),
                "attack_parameters": self._base_attack_params(strength),
            })

        return tests

    def _generate_sha256_protection_tests(self):
        tests = []

        protection_sets = [
            {"rate_limit"},
            {"lockout"},
            {"captcha"},
            {"totp"},
            {"rate_limit", "lockout"},
            {"captcha", "totp"},
            {"lockout", "totp"},  # special
        ]

        for strength in ["weak", "medium", "strong"]:
            for prot_set in protection_sets:
                if prot_set == {"lockout", "totp"}:
                    for lockout_stop in [True, False]:
                        ap = self._base_attack_params(strength)
                        ap["lockout_stop_enabled"] = lockout_stop

                        ap["lockout_stop_enabled"] = True  # TODO: REMOVE

                        tests.append({
                            "hash_mode": "sha256",
                            "hash_parameters": self._data["hash_options"]["sha256"],
                            "protections": self._build_protections(prot_set),
                            "attack_parameters": ap,
                        })
                else:
                    tests.append({
                        "hash_mode": "sha256",
                        "hash_parameters": self._data["hash_options"]["sha256"],
                        "protections": self._build_protections(prot_set),
                        "attack_parameters": self._base_attack_params(strength)
                    })

        return tests

    def _generate_bcrypt_tests(self):
        tests = []

        # totp + lockout, lockout_stop_enabled = True
        ap = self._base_attack_params("weak")
        ap["lockout_stop_enabled"] = True

        tests.append({
            "hash_mode": "bcrypt",
            "hash_parameters": self._data["hash_options"]["bcrypt"],
            "protections": self._build_protections({"totp", "lockout"}),
            "attack_parameters": ap,
        })

        # rate_limit + ip_switch
        ap = self._base_attack_params("weak")
        ap["ip_switch_enabled"] = True

        tests.append({
            "hash_mode": "bcrypt",
            "hash_parameters": self._data["hash_options"]["bcrypt"],
            "protections": self._build_protections({"rate_limit"}),
            "attack_parameters": ap,
        })

        return tests

    def _generate_argon2id_tests(self):
        tests = []

        for captcha_token_enabled in [True, False]:
            ap = self._base_attack_params("weak")
            ap["captcha_token_enabled"] = captcha_token_enabled

            tests.append({
                "hash_mode": "argon2id",
                "hash_parameters": self._data["hash_options"]["argon2id"],
                "protections": self._build_protections({"captcha", "totp"}),
                "attack_parameters": ap,
            })

        return tests

    @staticmethod
    def _enabled_protections(protections):
        """
        Return list of enabled protection names (excluding pepper).
        """
        return sorted(k for k in protections if k != "pepper")

    @staticmethod
    def _enabled_attack_flags(attack_parameters):
        """
        Return only attack parameters that are 'enabled'
        (True flags or non-zero delays).
        """
        enabled = {}

        for k, v in attack_parameters.items():
            if k == "seed":
                continue
            if isinstance(v, bool) and v:
                enabled[k] = v
            elif k == "delay_ss" and v != 0:
                enabled[k] = v

        return enabled


def main():
    groups = ExperimentsGenerator().build_groups()

    print("\n=== GROUP COUNTS ===")
    for group, experiments in sorted(groups.items()):
        print(f"{group:25s} : {len(experiments)}")

        for index, test in enumerate(experiments, start=1):
            protections = [name for name, enabled in test["protections"].items() if enabled],
            strength = test["attack_parameters"]["password_strength"]

            print(
                f"{index:03d} | "
                f"hash={test['hash_mode']:9s} | "
                f"strength={strength:6s} | "
                f"protections={protections if protections else ['none']} | "
            )


if __name__ == "__main__":
    main()
