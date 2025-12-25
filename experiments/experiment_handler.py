import tempfile
import time
import shutil
from pathlib import Path

from application import AuthServer, Logger
from attack import BruteForceAttack


class ExperimentHandler:
    def __init__(self, path, group_name, experiments):
        self._experiments = experiments
        self._global_log_path = Path(path)
        self._global_log_path.mkdir(parents=True, exist_ok=True)
        self._global_log_file = self._global_log_path / f"{group_name.replace(':', '_')}.log"
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

    def _experiment_teardown(self, auth, experiment_temp_path, experiment, index):
        auth.close_database()
        src_log = Path(experiment_temp_path.name) / "attempt.log"
        if src_log.exists():
            for group in experiment["groups"]:
                dst_dir = self._ensure_group_dir(group)
                dst_log = dst_dir / f"{index:04d}.log"
                shutil.copy2(src_log, dst_log)

            all_dir = self._ensure_group_dir("all")
            shutil.copy2(src_log, all_dir / f"{index:04d}.log")

        experiment_temp_path.cleanup()

    def _run_single_experiment(self, experiment, index):
        experiment_temp_path = tempfile.TemporaryDirectory()
        auth, attack = self._get_experiment_setup(experiment_temp_path, experiment)

        start_time = time.perf_counter()
        success, attempts, message = attack.attack()
        latency_ms = (time.perf_counter() - start_time) * 1000

        self._experiment_teardown(auth, experiment_temp_path, experiment, index)
        self._log(self._global_log_file, f"{index:04d}.log", experiment, success, attempts, message, latency_ms)

    def _run_all_experiments(self):
        for index, experiment in enumerate(self._experiments, start=1):

            #  TODO: REMOVE AFTER TESTING

            if index in {5, 6, 9, 10, 11, 12, 24, 27}:
                continue

            #  TODO: REMOVE AFTER TESTING

            print(f"Running {index:04d}")
            self._run_single_experiment(experiment, index)

    def _print_global_log(self, expect_lines=None):  # TODO: REMOVE AFTER TESTING
        """
        Print the global attempt.log file.
        Optionally validate expected number of lines.
        """
        if not self._global_log_file.exists():
            print("Global log file does not exist.")
            return

        with open(self._global_log_file, "r") as f:
            lines = f.readlines()

        print("=== GLOBAL attempt.log ===")
        for line in lines:
            print(line.rstrip())

        print(f"\nTOTAL LINES: {len(lines)}")

        if expect_lines is not None:
            assert len(lines) == expect_lines, (
                f"Expected {expect_lines} lines, got {len(lines)}"
            )

    @property
    def global_log_file(self):
        return self._global_log_file

    def run(self):
        self._run_all_experiments()
        self._print_global_log()

        return self._global_log_file
