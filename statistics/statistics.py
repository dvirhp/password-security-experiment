import os
from pathlib import Path
import tempfile
from application import AuthServer

from .latency_statistics import LatencyStatistics

os.environ["pepper"] = "137379782"

DIRECTORY_PATH = Path(__file__).parent / "plots"
DIRECTORY_PATH.mkdir(exist_ok=True)

protections_a = {
    "pepper_enabled": False,
    "rate_limit_enabled": False,
    "lockout_enabled": False,
    "captcha_enabled": False,
    "totp_enabled": False
}

protections_b = {
    "pepper_enabled": True,
    "rate_limit_enabled": False,
    "lockout_enabled": False,
    "captcha_enabled": False,
    "totp_enabled": False
}

params_list = [
    {"hash_mode": "sha256", "hash_parameters": {"salt_length": 16}, "protections": protections_a},
    {"hash_mode": "sha256", "hash_parameters": {"salt_length": 8}, "protections": protections_a},
    {"hash_mode": "sha256", "hash_parameters": {"salt_length": 8}, "protections": protections_b},
    {"hash_mode": "sha256", "hash_parameters": {"salt_length": 16}, "protections": protections_b},

    {"hash_mode": "bcrypt", "hash_parameters": {"cost": 12}, "protections": protections_a},
    {"hash_mode": "bcrypt", "hash_parameters": {"cost": 8}, "protections": protections_a},
    {"hash_mode": "bcrypt", "hash_parameters": {"cost": 12}, "protections": protections_b},
    {"hash_mode": "bcrypt", "hash_parameters": {"cost": 8}, "protections": protections_b},

    {"hash_mode": "argon2id", "hash_parameters": {"time_cost": 1, "memory_cost": 65536, "parallelism": 1},
     "protections": protections_a},
    {"hash_mode": "argon2id", "hash_parameters": {"time_cost": 1, "memory_cost": 65536, "parallelism": 2},
     "protections": protections_a},
    {"hash_mode": "argon2id", "hash_parameters": {"time_cost": 1, "memory_cost": 65536, "parallelism": 1},
     "protections": protections_b},
    {"hash_mode": "argon2id", "hash_parameters": {"time_cost": 1, "memory_cost": 65536, "parallelism": 2},
     "protections": protections_b}
]


def plot_register_log_latency(output_path=DIRECTORY_PATH):
    logs = []

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir_path = Path(temp_dir)

        for i, params in enumerate(params_list):
            temp_path = temp_dir_path / f"exp{i}"
            temp_path.mkdir()

            auth = AuthServer(temp_path, params["hash_mode"], params["hash_parameters"], params["protections"])

            auth.close_database()

            log_file = temp_path / "register.log"
            if log_file.exists():
                logs.append(log_file)

        LatencyStatistics.generate_latency_graph_multi(logs, output_png=output_path / "latency_comparison.png")
