import json
from collections import defaultdict

with open(r"C:\Users\barto\Documents\School\20940 - Introduction to Cyber Security\Assignments\Maman 16\Maman "
          r"16\experiments\experiments.json", "r") as f:
    config = json.load(f)

BASE_PROTECTIONS = {
    "pepper": "137379782"
}

DEFAULT_TEST_SEED = 51515151

STRENGTH = config["attack_options"]["password_strength"]


def group_by_hash(exp):
    return f"hash:{exp['hash_mode']}"


def group_by_strength(exp):
    strength = exp["attack_parameters"]["password_strength"]
    if strength is None:
        return "strength:random"
    return f"strength:{strength}"


def group_by_protection(exp):
    for k in exp["protections"]:
        if k != "pepper":
            return f"protection:{k}"
    return "protection:none"


GROUPERS = {
    "hash": group_by_hash,
    "strength": group_by_strength,
    "protection": group_by_protection,
}


def assign_groups(exp):
    groups = set()
    for grouper in GROUPERS.values():
        groups.add(grouper(exp))
    return groups


def pick_first(params_dict):
    """
    Pick a deterministic representative value from a parameter list.
    """
    return {k: v[0] for k, v in params_dict.items()}


def build_protections(protection_names):
    """
    Build protections dict from JSON config using representative parameters.
    """
    protections = dict(BASE_PROTECTIONS)

    for name in protection_names:
        protections[name] = pick_first(config["protections"][name])

    return protections


def base_attack_params(strength):
    """
    Minimal attack parameters with defaults.
    """
    return {
        "password_strength": strength,
        "max_attempts": config["attack_options"]["max_attempts"][0],
        "delay_ss": 0,
        "alternate_strength_enabled": False,
        "ip_switch_enabled": False,
        "lockout_stop_enabled": False,
        "captcha_token_enabled": True,  # False,
        "seed": DEFAULT_TEST_SEED,
    }


def generate_tests():
    tests = []
    tests += generate_no_protection_tests()
    tests += generate_sha256_protection_tests()
    # tests += generate_bcrypt_tests()
    # tests += generate_argon2id_tests()

    # assign groups
    for exp in tests:
        exp["groups"] = assign_groups(exp)

    return tests


def build_groups():
    buckets = defaultdict(list)

    for exp in generate_tests():
        for group in exp["groups"]:
            buckets[group].append(exp)

    return buckets


# def generate_no_protection_tests():
#     tests = []
#
#     for hash_mode in config["hash_options"]:
#         for strength in STRENGTH:
#             tests.append({
#                 "hash_mode": hash_mode,
#                 "hash_parameters": config["hash_options"][hash_mode],
#                 "protections": dict(BASE_PROTECTIONS),
#                 "attack_parameters": base_attack_params(strength),
#             })
#
#     return tests

def generate_no_protection_tests():
    tests = []

    hash_mode = "sha256"
    for strength in STRENGTH:
        tests.append({
            "hash_mode": hash_mode,
            "hash_parameters": config["hash_options"][hash_mode],
            "protections": dict(BASE_PROTECTIONS),
            "attack_parameters": base_attack_params(strength),
        })

    return tests


def generate_sha256_protection_tests():
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
                    ap = base_attack_params(strength)
                    ap["lockout_stop_enabled"] = lockout_stop

                    ap["lockout_stop_enabled"] = True  # TODO: REMOVE

                    tests.append({
                        "hash_mode": "sha256",
                        "hash_parameters": config["hash_options"]["sha256"],
                        "protections": build_protections(prot_set),
                        "attack_parameters": ap,
                    })
            else:

                # TODO REVIEW
                ap = base_attack_params(strength)
                ap["lockout_stop_enabled"] = True
                # TODO REVIEW

                tests.append({
                    "hash_mode": "sha256",
                    "hash_parameters": config["hash_options"]["sha256"],
                    "protections": build_protections(prot_set),
                    "attack_parameters": ap,  # base_attack_params(strength), TODO REVIEW
                })

    return tests


def generate_bcrypt_tests():
    tests = []

    # totp + lockout, lockout_stop_enabled = True
    ap = base_attack_params("weak")
    ap["lockout_stop_enabled"] = True

    tests.append({
        "hash_mode": "bcrypt",
        "hash_parameters": config["hash_options"]["bcrypt"],
        "protections": build_protections({"totp", "lockout"}),
        "attack_parameters": ap,
    })

    # rate_limit + ip_switch
    ap = base_attack_params("weak")
    ap["ip_switch_enabled"] = True

    tests.append({
        "hash_mode": "bcrypt",
        "hash_parameters": config["hash_options"]["bcrypt"],
        "protections": build_protections({"rate_limit"}),
        "attack_parameters": ap,
    })

    return tests


def generate_argon2id_tests():
    tests = []

    for captcha_token_enabled in [True, False]:
        ap = base_attack_params("weak")
        ap["captcha_token_enabled"] = captcha_token_enabled
        ap["lockout_stop_enabled"] = True  # TODO: REMOVE

        tests.append({
            "hash_mode": "argon2id",
            "hash_parameters": config["hash_options"]["argon2id"],
            "protections": build_protections({"captcha", "totp"}),
            "attack_parameters": ap,
        })

    return tests


def enabled_protections(protections):
    """
    Return list of enabled protection names (excluding pepper).
    """
    return sorted(k for k in protections if k != "pepper")


def enabled_attack_flags(attack_parameters):
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
