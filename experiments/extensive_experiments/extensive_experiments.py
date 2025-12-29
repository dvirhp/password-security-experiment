"""
Experimental experiments' generator (future work).

This module is NOT part of the core project logic.
It is intended for future experimentation, benchmarking, and analysis of
authentication defenses under different attack configurations.

The code is kept here for extensibility and research purposes, but it is
not used by the main application runtime.
"""

import json
import itertools
from collections import defaultdict

with open(r"C:\Users\barto\Documents\School\20940 - Introduction to Cyber Security\Assignments\Maman 16\Maman "
          r"16\experiments\experiments.json", "r") as f:
    config = json.load(f)

BASE_PROTECTIONS = {
    "pepper": "25977022"
}

DEFAULT_TEST_SEED = 51515151


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


def get_random_user(strength, is_totp=False):
    """
    PoC mock user selector.
    Username encodes strength and TOTP status.
    """
    suffix = "_totp" if is_totp else ""
    return f"{strength}_user{suffix}"


def is_valid_experiment(protections, attack):
    has_rate_limit = "rate_limit" in protections
    has_captcha = "captcha" in protections
    has_lockout = "lockout" in protections
    has_totp = "totp" in protections

    if attack["ip_switch_enabled"] and not has_rate_limit:
        return False

    if attack["captcha_token_enabled"] and not has_captcha:
        return False

    if attack["lockout_stop_enabled"] and not has_lockout and not has_captcha and not has_totp:
        return False

    if not (has_rate_limit or has_lockout):
        if attack["delay_ss"] != 0:
            return False

    return True


def generate_experiment_configs():
    hash_options = config["hash_options"]
    protections_cfg = config["protections"]
    attack_cfg = config["attack_options"]

    protection_variants = []

    for protection_name, parameters in protections_cfg.items():
        keys = list(parameters.keys())
        values = list(parameters.values())

        for combo in itertools.product(*values):
            protection = dict(zip(keys, combo))
            protection_variants.append({
                **BASE_PROTECTIONS,
                protection_name: protection
            })

    attack_keys = list(attack_cfg.keys())
    attack_variants = [
        dict(zip(attack_keys, combo))
        for combo in itertools.product(*attack_cfg.values())
    ]

    # ---- Full experiment matrix ----
    for hash_mode, hash_parameters in hash_options.items():
        for protections in protection_variants:
            for attack_parameters in attack_variants:
                if not is_valid_experiment(protections, attack_parameters):
                    continue

                attack_parameters = dict(attack_parameters)  # defensive copy
                attack_parameters["seed"] = DEFAULT_TEST_SEED

                exp = {
                    "hash_mode": hash_mode,
                    "hash_parameters": hash_parameters,
                    "protections": protections,
                    "attack_parameters": attack_parameters
                }

                exp["groups"] = assign_groups(exp)
                yield exp


def build_groups():
    buckets = defaultdict(list)

    for exp in generate_experiment_configs():
        for group in exp["groups"]:
            buckets[group].append(exp)

    return buckets
