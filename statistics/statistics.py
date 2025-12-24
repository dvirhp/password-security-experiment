import json
from pathlib import Path
import matplotlib.pyplot as plt


class StatisticsPlotter:
    def __init__(self, output_directory):
        self._output_directory = Path(output_directory)
        self._output_directory.mkdir(parents=True, exist_ok=True)

    def plot_group_from_file(self, log_file_path, group_name):
        success_rate, latency_per_attempt = self._extract_log_data(log_file_path)

        fig, axes = plt.subplots(1, 2, figsize=(10, 4))
        fig.suptitle(group_name)

        axes[0].bar(["Success rate"], [success_rate])
        axes[0].set_ylim(0, 1)
        axes[0].set_ylabel("Rate")
        axes[0].set_title("Success Rate")

        axes[1].boxplot(latency_per_attempt, vert=True)
        axes[1].set_ylabel("Latency per attempt (ms)")
        axes[1].set_title("Latency / Attempt")

        plt.tight_layout(rect=(0.0, 0.0, 1.0, 0.95))

        output_path = self._output_directory / f"{group_name.replace(':', '_')}.png"
        plt.savefig(output_path)
        plt.close()

    @staticmethod
    def _extract_log_data(log_file_path):
        successes = []
        latency_per_attempt = []

        with log_file_path.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue

                record = json.loads(line)

                successes.append(1 if record["success"] else 0)

                attempts = record.get("attempts", 1)
                latency = record.get("latency_ms", 0.0)

                if attempts > 0:
                    latency_per_attempt.append(latency / attempts)

        if successes:
            success_rate = sum(successes) / len(successes)
        else:
            success_rate = 0

        return success_rate, latency_per_attempt
