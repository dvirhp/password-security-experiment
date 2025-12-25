import json
from pathlib import Path

from statistics import StatisticsPlotter

from experiment_handler import ExperimentHandler
from experiments_generator import ExperimentsGenerator

DIRECTORY_PATH = Path(__file__).parent


class ExperimentRunner:
    def __init__(self, base_path):
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

        handler = ExperimentHandler(path=self._logs_path, group_name="all", experiments=self._tests)
        log_file = handler.run()
        self._plotter.plot_latency_per_attempt_scatter(log_file_path=log_file, group_name="total")

        # for index, test in enumerate(self._tests, start=1):

            #  TODO: REMOVE AFTER TESTING

            # if index in {5, 6, 9, 10, 11, 12, 24, 27}:
            #     continue

            #  TODO: REMOVE AFTER TESTING

            # handler = ExperimentHandler(path=self._logs_path, group_name="all", experiments=test)

            # print(f"Running test: {index}")
        #     log_file = handler.run()
        #
        #     self._group_log_files.append(log_file)
        #
        # self._merge_logs()
        # self._plotter.plot_latency_per_attempt_scatter(log_file_path=self._combined_log_path, group_name="total")

    def run_all_groups(self):
        for group_name, experiments in self._groups.items():

            handler = ExperimentHandler(path=self._logs_path, group_name=group_name, experiments=experiments)

            print(f"Running group: {group_name} ({len(experiments)} experiments)")
            log_file = handler.run()

            self._group_log_files.append(log_file)
            self._plotter.plot_latency_per_attempt_scatter(log_file_path=log_file, group_name=group_name)

        self._merge_logs()
        self._plotter.plot_latency_per_attempt_scatter(log_file_path=self._combined_log_path, group_name="total")

    def _merge_logs(self):
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
    experiment_runner = ExperimentRunner(DIRECTORY_PATH)
    experiment_runner.run_all_tests()


if __name__ == "__main__":
    main()
