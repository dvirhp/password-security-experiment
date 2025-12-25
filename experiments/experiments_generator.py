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

        self._tests = []
        self._groups = None

        self._generate_tests()
        self._build_groups()

    @property
    def tests(self):
        return self._tests

    @property
    def groups(self):
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

    def _base_attack_params(self, strength, alternate=False, ip_switch=False, lockout_stop=False, captcha_token=False):
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
        self._groups = defaultdict(list)

        for experiment in self._tests:
            experiment["groups"] = self._assign_groups(experiment)
            for group in experiment["groups"]:
                self._groups[group].append(experiment)

    def _generate_tests(self):
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
        if hash_mode == "sha256":
            return self._sha256
        elif hash_mode == "bcrypt":
            return self._bcrypt
        else:
            return self._argon2id

    def _generate_test(self, hash_mode, protections, attack_parameters):
        return {
            "hash_mode": hash_mode,
            "hash_parameters": self._get_hash_parameters(hash_mode),
            "protections": protections,
            "attack_parameters": attack_parameters,
        }

    def _generate_no_protections_tests(self):
        protections = dict(BASE_PROTECTIONS)

        for strength in self._strength:
            self._tests.append(self._generate_test("sha256", protections, self._base_attack_params(strength)))

        ap = self._base_attack_params("weak", alternate=True)
        self._tests.append(self._generate_test("sha256", dict(BASE_PROTECTIONS), ap))

        self._tests.append(self._generate_test("bcrypt", protections, self._base_attack_params("weak")))
        self._tests.append(self._generate_test("argon2id", protections, self._base_attack_params("weak")))

    def _generate_rate_limit_tests(self):
        for ip_switch in [True, False]:
            ap = self._base_attack_params("weak", ip_switch=ip_switch)
            self._tests.append(self._generate_test("sha256", self._build_protections({"rate_limit"}), ap))

    def _generate_lockout_tests(self):
        for lockout_stop in [True, False]:
            ap = self._base_attack_params("strong", lockout_stop=lockout_stop)
            self._tests.append(self._generate_test("bcrypt", self._build_protections({"lockout"}), ap))

    def _generate_captcha_tests(self):
        for lockout_stop in [True, False]:
            ap = self._base_attack_params("weak", lockout_stop=lockout_stop)
            self._tests.append(self._generate_test("argon2id", self._build_protections({"captcha"}), ap))

        ap = self._base_attack_params("weak", lockout_stop=True, captcha_token=True)
        self._tests.append(self._generate_test("sha256", self._build_protections({"captcha"}), ap))

        ap = self._base_attack_params("weak", ip_switch=True, lockout_stop=True)
        self._tests.append(self._generate_test("sha256", self._build_protections({"captcha"}), ap))

    def _generate_totp_tests(self):
        ap = self._base_attack_params("weak", lockout_stop=True)
        self._tests.append(self._generate_test("sha256", self._build_protections({"totp"}), ap))

        ap = self._base_attack_params("medium", lockout_stop=True)
        self._tests.append(self._generate_test("sha256", self._build_protections({"totp"}), ap))

    def _generate_totp_captcha_tests(self):
        ap = self._base_attack_params("weak", lockout_stop=True, captcha_token=True)
        self._tests.append(self._generate_test("sha256", self._build_protections({"captcha", "totp"}), ap))

        ap = self._base_attack_params("weak", alternate=True, lockout_stop=True, captcha_token=True)
        self._tests.append(self._generate_test("sha256", self._build_protections({"captcha", "totp"}), ap))

    def _generate_totp_lockout_tests(self):
        ap = self._base_attack_params("weak", ip_switch=True, lockout_stop=True)
        self._tests.append(self._generate_test("sha256", self._build_protections({"lockout", "totp"}), ap))

        ap = self._base_attack_params("strong", ip_switch=True, lockout_stop=True)
        self._tests.append(self._generate_test("sha256", self._build_protections({"lockout", "totp"}), ap))

        ap = self._base_attack_params("strong", ip_switch=True)
        self._tests.append(self._generate_test("sha256", self._build_protections({"lockout", "totp"}), ap))

    def _generate_rate_limit_captcha_tests(self):
        for ip_switch in [True, False]:
            ap = self._base_attack_params("weak", ip_switch=ip_switch, lockout_stop=True, captcha_token=True)
            self._tests.append(self._generate_test("sha256", self._build_protections({"rate_limit", "captcha"}), ap))

        ap = self._base_attack_params("medium")
        self._tests.append(self._generate_test("bcrypt", self._build_protections({"rate_limit", "captcha"}), ap))

    def _generate_all_protections_tests(self):
        protections = self._build_protections({"rate_limit", "lockout", "captcha", "totp"})

        for lockout_stop in [True, False]:
            ap = self._base_attack_params("weak", ip_switch=True, lockout_stop=lockout_stop, captcha_token=True)
            self._tests.append(self._generate_test("sha256", protections, ap))

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
