import tempfile
import time
import shutil
from pathlib import Path

from application import AuthServer, Logger
from attack import BruteForceAttack
from statistics import StatisticsPlotter  # your existing plot class


class ExperimentHandler:
    def __init__(self, experiment_generator, output_dir):
        self._experiment_generator = experiment_generator
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

        self._global_log_directory = tempfile.TemporaryDirectory()
        self._global_log_path = Path(self._global_log_directory.name)

        self._log = Logger.log_experiment

    def _ensure_group_dir(self, group):
        path = self._global_log_path / group.replace(":", "_")
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def _get_experiment_setup(experiment_temp_path, experiment):
        auth = AuthServer(
            experiment_temp_path.name,
            experiment["hash_mode"],
            experiment["hash_parameters"],
            experiment["protections"]
        )

        strength = experiment["attack_parameters"]["password_strength"]
        is_totp = "totp" in experiment["protections"]
        experiment["attack_parameters"]["username"] = auth.dummy_members_manager.get_random_user(strength, is_totp)

        client = auth.app.test_client()
        attack = BruteForceAttack(client, experiment["attack_parameters"])

        return auth, attack

    @staticmethod
    def _experiment_teardown(auth, experiment_temp_path, index, group_dir):
        auth.close_database()
        src_log = Path(experiment_temp_path.name) / "attempt.log"
        if src_log.exists():
            dst_log = group_dir / f"{index:04d}.log"
            shutil.copy2(src_log, dst_log)

        experiment_temp_path.cleanup()

    def run_group(self, group_name, experiments):
        """
        Run all experiments in a single group, then return the group log file path.
        """
        group_dir = self._ensure_group_dir(group_name)
        group_log_file = group_dir / "group_attempt.log"

        from tests.test_experiment_parameters.test_sample_experiments import enabled_protections, enabled_attack_flags

        for index, experiment in enumerate(experiments, start=1):

            # TODO: REMOVE

            prots = enabled_protections(experiment["protections"])
            attacks = enabled_attack_flags(experiment["attack_parameters"])
            strength = experiment["attack_parameters"]["password_strength"]
            max_attempts = experiment["attack_parameters"]["max_attempts"]

            print(
                f"{index:03d} | "
                f"hash={experiment['hash_mode']:9s} | "
                f"strength={strength:6s} | "
                f"max_attempts={max_attempts} | "
                f"protections={prots if prots else ['none']} | "
                f"attack_flags={attacks if attacks else '{}'}"
            )

            if experiment["attack_parameters"]["password_strength"] != "weak":
                continue
            if not experiment["attack_parameters"]["lockout_stop_enabled"] and prots:
                continue

            # TODO: REMOVE

            experiment_temp_path = tempfile.TemporaryDirectory()
            auth, attack = self._get_experiment_setup(experiment_temp_path, experiment)

            start_time = time.perf_counter()
            success, attempts, message = attack.attack()
            latency_ms = (time.perf_counter() - start_time) * 1000

            print(f"Index: {index}, success?: {success}, attempts: {attempts}, message: {message}")

            self._experiment_teardown(auth, experiment_temp_path, index, group_dir)

            # log into a group-specific log
            self._log(group_log_file, f"{index:04d}.log", experiment, success, attempts, message, latency_ms)

        return group_log_file

    def cleanup(self):
        self._global_log_directory.cleanup()


def test_sha():
    from tests.test_experiment_parameters.test_sample_experiments import generate_tests as generate_experiment_configs
    from statistics import StatisticsPlotter

    # Directory for plots
    plot_dir = r'C:\Users\barto\Documents\School\20940 - Introduction to Cyber Security\Assignments\Maman 16\Maman ' \
               r'16\statistics\plots '
    plotter = StatisticsPlotter(plot_dir)

    # Create handler
    experiment_handler = ExperimentHandler(generate_experiment_configs, plot_dir)

    # Filter only sha256 experiments
    sha_experiments = [e for e in generate_experiment_configs() if e["hash_mode"] == "sha256"]
    group_name = "hash:sha256"

    print(f"Running group {group_name} with {len(sha_experiments)} experiments...")

    # Run group
    group_log_file = experiment_handler.run_group(group_name, sha_experiments)

    # Plot results for this group
    plotter.plot_group_from_file(group_log_file, group_name)

    experiment_handler.cleanup()


def test_all():
    from tests.test_experiment_parameters.test_sample_experiments import generate_tests as generate_experiment_configs

    # Directory for plots
    plot_dir = r'C:\Users\barto\Documents\School\20940 - Introduction to Cyber Security\Assignments\Maman 16\Maman ' \
               r'16\statistics\plots '
    plotter = StatisticsPlotter(plot_dir)

    # Create handler
    experiment_handler = ExperimentHandler(generate_experiment_configs, plot_dir)

    # Example: group experiments by hash mode
    groups = {
        "hash:sha256": [e for e in generate_experiment_configs() if e["hash_mode"] == "sha256"],
        "hash:bcrypt": [e for e in generate_experiment_configs() if e["hash_mode"] == "bcrypt"],
        "hash:argon2id": [e for e in generate_experiment_configs() if e["hash_mode"] == "argon2id"],
    }

    for group_name, experiments in groups.items():
        print(f"Running group {group_name} with {len(experiments)} experiments...")

        # Run group
        group_log_file = experiment_handler.run_group(group_name, experiments)

        # Plot results for this group
        plotter.plot_group_from_file(group_log_file, group_name)

    experiment_handler.cleanup()


def main():
    test_sha()


if __name__ == "__main__":
    main()
