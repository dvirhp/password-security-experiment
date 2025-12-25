import json
from pathlib import Path
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D


class StatisticsPlotter:
    COLOR_BY_STRENGTH = {"weak": "green", "medium": "gold", "strong": "red"}
    MARKER_BY_HASH = {"sha256": "o", "bcrypt": "s", "argon2id": "^"}

    def __init__(self, output_directory):
        self._output_directory = Path(output_directory)
        self._output_directory.mkdir(parents=True, exist_ok=True)

    def plot_latency_per_attempt_scatter(self, log_file_path, group_name):
        ax, experiments = self._setup_plot(log_file_path, group_name)

        self._plot_data(ax, experiments)

        self._plot_axis(ax, experiments)
        self._plot_header(ax)
        self._plot_legend(ax)
        self._save_plot(group_name)

    def _setup_plot(self, log_file_path, group_name):
        experiments = self._extract_experiments(log_file_path)

        fig, ax = plt.subplots(figsize=(12, 5))
        fig.suptitle(group_name)

        for idx, exp in enumerate(experiments):
            exp["x"] = idx

        return ax, experiments

    def _plot_data(self, ax, experiments):
        for hash_mode, marker in self.MARKER_BY_HASH.items():
            group = [e for e in experiments if e["hash_mode"] == hash_mode]
            if not group:
                continue

            self._scatter_dot(ax, group, marker, hash_mode)

    def _scatter_dot(self, ax, group, marker, label):
        x = [e["x"] for e in group]
        y = [e["latency_per_attempt"] for e in group]
        color = [self.COLOR_BY_STRENGTH.get(e["password_strength"], "gray") for e in group]

        ax.scatter(x, y, c=color, marker=marker, s=100, label=label)

    def _plot_legend(self, ax):
        self._plot_hash_legend(ax)
        self._plot_strength_legend(ax)

    def _plot_hash_legend(self, ax):
        hash_handles = [
            Line2D([0], [0], marker=marker, color="black", linestyle="None", markersize=8, label=hash_mode)
            for hash_mode, marker in self.MARKER_BY_HASH.items()
        ]

        hash_legend = ax.legend(handles=hash_handles, title="Hash mode", loc="upper right")
        ax.add_artist(hash_legend)

    def _plot_strength_legend(self, ax):
        strength_handles = [
            Line2D([0], [0], marker="o", color=color, linestyle="None", markersize=8, label=strength)
            for strength, color in self.COLOR_BY_STRENGTH.items()
        ]

        ax.legend(handles=strength_handles, title="Password strength", loc="upper left")

    def _save_plot(self, group_name):
        plt.tight_layout()

        output_path = self._output_directory / f"{group_name.replace(':', '_')}_latency_scatter.png"
        plt.savefig(output_path, dpi=150)
        plt.close()

    @staticmethod
    def _plot_axis(ax, experiments):
        ax.set_xticks(range(len(experiments)))
        ax.set_xticklabels([e["experiment_id"] for e in experiments], rotation=45, ha="right")

        for label, exp in zip(ax.get_xticklabels(), experiments):
            if exp["success"]:
                label.set_bbox(dict(facecolor="lightgreen", edgecolor="none", alpha=0.6))

    @staticmethod
    def _plot_header(ax):
        ax.set_ylabel("Latency per attempt (ms)")
        ax.set_title("Latency per Attempt")
        ax.grid(axis="y", linestyle="--", alpha=0.4)

    @staticmethod
    def _extract_experiments(log_file_path):
        experiments = []

        with log_file_path.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue

                record = json.loads(line)

                experiments.append({
                    "experiment_id": record["experiment_id"].replace(".log", ""),
                    "latency_per_attempt": round(record["latency_ms"] / record["attempts"], 3),
                    "password_strength": record["attack_parameters"]["password_strength"],
                    "hash_mode": record["hash_mode"],
                    "attempts": record["attempts"],
                    "success": record["success"],
                })

        return experiments


def main():
    # path = r'C:\Users\barto\Documents\School\20940 - Introduction to Cyber Security\Assignments\Maman 16\Maman ' \
    #        r'16\statistics\plots'

    path = Path(r"C:\Users\barto\Documents\School\20940 - Introduction to Cyber Security\Assignments\Maman 16\Maman "
                r"16\experiments\plots")

    log = Path(r"C:\Users\barto\Documents\School\20940 - Introduction to Cyber Security\Assignments\Maman 16\Maman "
               r"16\experiments\logs\all.log")
    plotter = StatisticsPlotter(path)
    plotter.plot_latency_per_attempt_scatter(log, "total_latency_ms")


if __name__ == "__main__":
    main()
