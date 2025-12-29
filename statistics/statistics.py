"""
StatisticsPlotter: Visualizing Experiment Logs

This module provides the `StatisticsPlotter` class for generating visual summaries
from experiment logs. It is designed for experiments involving authentication
attacks, capturing metrics such as latency per login attempt, success rates, and
messages returned during login attempts.
"""

import json
from pathlib import Path
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D


class StatisticsPlotter:
    _COLOR_BY_STRENGTH = {"weak": "green", "medium": "gold", "strong": "red"}
    _MARKER_BY_HASH = {"sha256": "o", "bcrypt": "s", "argon2id": "^"}

    def __init__(self, output_directory):
        self._output_directory = Path(output_directory)
        self._output_directory.mkdir(parents=True, exist_ok=True)

    def plot_all_graphs(self, log_file_path, group_name):
        self.plot_latency_per_attempt_scatter(log_file_path=log_file_path, group_name=group_name)
        self.plot_average_attempts_successful(log_file_path, group_name)
        self.plot_message_frequency(log_file_path, group_name)

    def plot_latency_per_attempt_scatter(self, log_file_path, group_name):
        ax, experiments = self._latency_setup_plot(log_file_path, group_name)

        self._latency_plot_data(ax, experiments)

        self._latency_plot_axis(ax, experiments)
        self._latency_plot_header(ax)
        self._latency_plot_legend(ax)
        self._latency_save_plot(group_name)

    def plot_average_attempts_successful(self, log_file_path, group_name):
        experiments = self._extract_experiments(log_file_path)

        successful = [e for e in experiments if e["success"]]
        if not successful:
            return

        fig, ax = plt.subplots(figsize=(12, 5))
        fig.suptitle(group_name)

        x = range(len(successful))
        y = [e["attempts"] for e in successful]
        labels = [e["experiment_id"] for e in successful]

        ax.bar(x, y, color="steelblue")

        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=45, ha="right")
        ax.set_ylabel("Attempts")
        ax.set_title("Attempts (Successful Experiments Only)")
        ax.grid(axis="y", linestyle="--", alpha=0.4)

        plt.tight_layout()
        output_path = self._output_directory / f"{group_name}_attempts_success.png"
        plt.savefig(output_path, dpi=150)
        plt.close()

    def plot_message_frequency(self, log_file_path, group_name):
        message_counts = {}

        with log_file_path.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue

                record = json.loads(line)
                message = record.get("message", "unknown")

                message_counts[message] = message_counts.get(message, 0) + 1

        if not message_counts:
            return

        fig, ax = plt.subplots(figsize=(12, 5))
        fig.suptitle(group_name)

        x = range(len(message_counts))
        y = list(message_counts.values())
        labels = list(message_counts.keys())

        ax.bar(x, y, color="darkorange")

        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=45, ha="right")
        ax.set_ylabel("Frequency")
        ax.set_title("Message Frequency")
        ax.grid(axis="y", linestyle="--", alpha=0.4)

        plt.tight_layout()
        output_path = self._output_directory / f"{group_name}_message_frequency.png"
        plt.savefig(output_path, dpi=150)
        plt.close()

    def _latency_setup_plot(self, log_file_path, group_name):
        experiments = self._extract_experiments(log_file_path)

        fig, ax = plt.subplots(figsize=(12, 5))
        fig.suptitle(group_name)

        for idx, exp in enumerate(experiments):
            exp["x"] = idx

        return ax, experiments

    def _latency_plot_data(self, ax, experiments):
        for hash_mode, marker in self._MARKER_BY_HASH.items():
            group = [e for e in experiments if e["hash_mode"] == hash_mode]
            if not group:
                continue

            self._latency_scatter_dot(ax, group, marker, hash_mode)

    def _latency_scatter_dot(self, ax, group, marker, label):
        x = [e["x"] for e in group]
        y = [e["latency_per_attempt"] for e in group]
        color = [self._COLOR_BY_STRENGTH.get(e["password_strength"], "gray") for e in group]

        ax.scatter(x, y, c=color, marker=marker, s=100, label=label)

    def _latency_plot_legend(self, ax):
        self._latency_plot_hash_legend(ax)
        self._latency_plot_strength_legend(ax)

    def _latency_plot_hash_legend(self, ax):
        hash_handles = [
            Line2D([0], [0], marker=marker, color="black", linestyle="None", markersize=8, label=hash_mode)
            for hash_mode, marker in self._MARKER_BY_HASH.items()
        ]

        hash_legend = ax.legend(handles=hash_handles, title="Hash mode", loc="upper right")
        ax.add_artist(hash_legend)

    def _latency_plot_strength_legend(self, ax):
        strength_handles = [
            Line2D([0], [0], marker="o", color=color, linestyle="None", markersize=8, label=strength)
            for strength, color in self._COLOR_BY_STRENGTH.items()
        ]

        ax.legend(handles=strength_handles, title="Password strength", loc="upper left")

    def _latency_save_plot(self, group_name):
        plt.tight_layout()

        output_path = self._output_directory / f"{group_name.replace(':', '_')}_latency_scatter.png"
        plt.savefig(output_path, dpi=150)
        plt.close()

    @staticmethod
    def _latency_plot_axis(ax, experiments):
        ax.set_xticks(range(len(experiments)))
        ax.set_xticklabels([e["experiment_id"] for e in experiments], rotation=45, ha="right")

        for label, exp in zip(ax.get_xticklabels(), experiments):
            if exp["success"]:
                label.set_bbox(dict(facecolor="lightgreen", edgecolor="none", alpha=0.6))

    @staticmethod
    def _latency_plot_header(ax):
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
