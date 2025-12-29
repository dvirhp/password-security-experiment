"""
ExperimentRunner

This module orchestrates the execution of authentication attack experiments
and manages logging and visualization of results.

Features:
- Run all experiments individually or grouped by test categories.
- Store experiment logs and generate combined logs.
- Produce statistical plots (latency, success rates) for analysis.
"""

import json
from pathlib import Path

from statistics import StatisticsPlotter
from experiment_handler import ExperimentHandler
from experiments_generator import ExperimentsGenerator

DIRECTORY_PATH = Path(__file__).parent


class ExperimentRunner:
    """
    Handles running experiment tests, managing logs, and generating plots.

    Attributes:
        _base_path (Path): Base directory for logs and plots.
        _logs_path (Path): Directory for storing individual and combined logs.
        _plots_path (Path): Directory for storing generated plots.
        _combined_log_path (Path): Path for the merged log of all experiments.
        _experiment_generator (ExperimentsGenerator): Generator for experiments and groups.
        _tests (list): List of all experiment dictionaries.
        _groups (dict): Dictionary of experiments grouped by category.
        _group_log_files (list): Paths to log files of individual groups.
        _plotter (StatisticsPlotter): Plotter instance to create statistical graphs.
    """

    def __init__(self, base_path):
        """
        Initialize the ExperimentRunner.

        Args:
            base_path (str or Path): Base directory where logs and plots will be stored.
        """
        self._base_path = Path(base_path)
        self._logs_path = self._base_path / "logs"
        self._plots_path = self._base_path / "plots"
        self._combined_log_path = self._logs_path / "experiments.log"

        self._logs_path.mkdir(parents=True, exist_ok=True)
        self._plots_path.mkdir(parents=True, exist_ok=True)

        self._experiment_generator = ExperimentsGenerator()
        self._tests = self._experiment_generator.tests
        self._groups = self._experiment_generator.groups
        self._group_log_files = []

        self._plotter = StatisticsPlotter(self._plots_path)

    def run_all_tests(self):
        """
        Run all experiments as a single batch and generate plots.

        The results are logged and plotted using the StatisticsPlotter.
        """
        handler = ExperimentHandler(path=self._logs_path, group_name="experiments", experiments=self._tests)
        log_file = handler.run()
        self._plotter.plot_all_graphs(log_file_path=log_file, group_name="experiments")

    def run_all_groups(self):
        """
        Run experiments grouped by categories and generate plots per group.

        After running all groups, merges all logs into a single file and
        generates a combined plot for the total experiment set.
        """
        for group_name, experiments in self._groups.items():
            handler = ExperimentHandler(path=self._logs_path, group_name=group_name, experiments=experiments)

            print(f"Running group: {group_name} ({len(experiments)} experiments)")
            log_file = handler.run()

            self._group_log_files.append(log_file)
            self._plotter.plot_latency_per_attempt_scatter(log_file_path=log_file, group_name=group_name)

        self._merge_logs()
        self._plotter.plot_latency_per_attempt_scatter(log_file_path=self._combined_log_path, group_name="total")

    def _merge_logs(self):
        """
        Merge all group log files into a single combined log file.

        The merged logs are sorted by experiment ID.
        """
        records = []

        for log_file in self._group_log_files:
            with log_file.open("r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        records.append(json.loads(line))

        records.sort(key=lambda r: int(r["experiment_id"].replace(".log", "")))

        with self._combined_log_path.open("w", encoding="utf-8") as out:
            for record in records:
                out.write(json.dumps(record) + "\n")


def main():
    """
    Main entry point to run experiments.

    Update the path to the desired base directory for logs and plots.
    """
    experiment_runner = ExperimentRunner(DIRECTORY_PATH)
    experiment_runner.run_all_tests()


if __name__ == "__main__":
    main()
