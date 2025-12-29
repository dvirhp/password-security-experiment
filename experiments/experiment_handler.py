"""
ExperimentHandler

This module manages the execution of authentication attack experiments
and logs the results for analysis. It is part of the main project logic
and provides structured ways to:

- Run a series of brute-force attack experiments.
- Handle temporary experiment environments.
- Capture detailed logs of attack attempts and outcomes.
- Organize experiment results by groups for easy analysis.
"""

import time
import shutil
import tempfile
from pathlib import Path

from application import AuthServer, Logger
from attack import BruteForceAttack


class ExperimentHandler:
    """
    Handles running multiple authentication attack experiments.

    Attributes:
        _experiments (list): List of experiment configurations.
        _global_log_path (Path): Directory path for global logs.
        _global_log_file (Path): Path for the consolidated log file.
        _log (function): Logger function to record experiment results.
    """

    def __init__(self, path, group_name, experiments):
        """
        Initialize the ExperimentHandler.

        Args:
            path (str or Path): Directory to store logs.
            group_name (str): Name of the experiment group.
            experiments (list): List of experiment dictionaries.
        """
        self._experiments = experiments
        self._global_log_path = Path(path)
        self._global_log_path.mkdir(parents=True, exist_ok=True)
        self._global_log_file = self._global_log_path / f"{group_name.replace(':', '_')}.log"
        self._log = Logger.log_experiment

    def _ensure_group_dir(self, group):
        """
        Ensure a directory exists for a specific experiment group.

        Args:
            group (str): Group name.

        Returns:
            Path: Path to the created directory.
        """
        path = self._global_log_path / group.replace(":", "_")
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def _get_experiment_setup(experiment_temp_path, experiment):
        """
        Set up the environment for a single experiment.

        Args:
            experiment_temp_path (TemporaryDirectory): Temporary directory for experiment data.
            experiment (dict): Experiment configuration.

        Returns:
            tuple: (AuthServer instance, BruteForceAttack instance)
        """
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

    def _experiment_teardown(self, auth, experiment_temp_path, experiment, index, save_log=False):
        """
        Tear down an experiment environment and optionally save logs.

        Args:
            auth (AuthServer): AuthServer instance used in the experiment.
            experiment_temp_path (TemporaryDirectory): Temporary directory used.
            experiment (dict): Experiment configuration.
            index (int): Index of the experiment.
            save_log (bool): Whether to save the attempt logs.
        """
        auth.close_database()
        src_log = Path(experiment_temp_path.name) / "attempts.log"
        if src_log.exists() and save_log:
            for group in experiment["groups"]:
                dst_dir = self._ensure_group_dir(group)
                dst_log = dst_dir / f"{index:04d}.log"
                shutil.copy2(src_log, dst_log)

            all_dir = self._ensure_group_dir("all")
            shutil.copy2(src_log, all_dir / f"{index:04d}.log")

        experiment_temp_path.cleanup()

    def _run_single_experiment(self, experiment, index):
        """
        Run a single brute-force attack experiment.

        Args:
            experiment (dict): Experiment configuration.
            index (int): Index of the experiment.
        """
        experiment_temp_path = tempfile.TemporaryDirectory()
        auth, attack = self._get_experiment_setup(experiment_temp_path, experiment)

        start_time = time.perf_counter()
        success, attempts, message = attack.attack()
        latency_ms = (time.perf_counter() - start_time) * 1000

        self._experiment_teardown(auth, experiment_temp_path, experiment, index)
        self._log(self._global_log_file, f"{index:04d}.log", experiment, success, attempts, message, latency_ms)

    def _run_all_experiments(self):
        """Run all experiments in sequence."""
        for index, experiment in enumerate(self._experiments, start=1):
            print(f"Running {index:04d}")
            self._run_single_experiment(experiment, index)

    def _print_global_log(self, expect_lines=None):
        """
        Print the global attempt.log file and optionally validate the number of lines.

        Args:
            expect_lines (int, optional): Expected number of lines in the log.
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
        """
        Return the path of the global log file.

        Returns:
            Path: Global log file path.
        """
        return self._global_log_file

    def run(self):
        """
        Run all experiments and print the global log.

        Returns:
            Path: Path to the global log file.
        """
        self._run_all_experiments()
        self._print_global_log()

        return self._global_log_file
