import json
import matplotlib.pyplot as plt
from pathlib import Path


class LatencyStatistics:
    """Static utility class for latency analysis."""

    # ========= PUBLIC API =========

    @staticmethod
    def generate_latency_graph(log_path, output_png=None):
        log_entries = LatencyStatistics._read_log_file(log_path)
        latencies = LatencyStatistics._extract_latencies_by_strength(log_entries)
        averages = LatencyStatistics._compute_averages(latencies)

        title = LatencyStatistics._extract_configuration(log_entries)

        LatencyStatistics._plot_latency_bar_chart(averages, title, output_png)

    @staticmethod
    def generate_latency_graph_multi(log_paths, output_png=None):
        """
        Reads multiple JSONL log files, each potentially with different hash_mode/config,
        computes average latencies per strength and overall, and plots a combined graph.
        """
        all_data = []

        for path in log_paths:
            entries = LatencyStatistics._read_log_file(path)
            latencies = LatencyStatistics._extract_latencies_by_strength(entries)
            averages = LatencyStatistics._compute_averages(latencies)
            config_title = LatencyStatistics._extract_configuration(entries)
            all_data.append((config_title, averages))

        LatencyStatistics._plot_latency_bar_chart_multi(all_data, output_png)

    # ========= HELPERS =========

    @staticmethod
    def _read_log_file(log_path):
        """Reads a JSON-lines .log file into a list of dicts."""
        entries = []

        with open(log_path, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                entries.append(json.loads(line))

        return entries

    @staticmethod
    def _extract_latencies_by_strength(log_entries):
        """Groups latencies by inferred strength from username."""
        latencies = {
            "weak": [],
            "medium": [],
            "strong": [],
        }

        for entry in log_entries:
            username = entry["username"]
            latency = entry["latency_ms"]

            if "weak" in username:
                latencies["weak"].append(latency)
            elif "medium" in username:
                latencies["medium"].append(latency)
            elif "strong" in username:
                latencies["strong"].append(latency)

        return latencies

    @staticmethod
    def _compute_averages(latencies):
        averages = {}
        all_values = []

        for strength, values in latencies.items():
            avg = sum(values) / len(values) if values else 0.0
            averages[strength] = avg
            all_values.extend(values)

        averages["overall"] = (
            sum(all_values) / len(all_values) if all_values else 0.0
        )

        return averages

    @staticmethod
    def _extract_configuration(log_entries) -> str:
        """Builds a graph title from hash and protection configuration."""
        if not log_entries:
            return "Latency Statistics"

        entry = log_entries[0]

        hash_mode = entry["hash_mode"]

        hash_params = entry["hash_parameters"]
        params_str = ", ".join(f"{k}={v}" for k, v in hash_params.items())

        protections = entry.get("protection_flags", [])
        enabled = []

        if isinstance(protections, dict):
            items = protections.items()
        elif isinstance(protections, list) and protections:
            items = protections[0].items()
        else:
            items = []

        for key, value in items:
            if value:
                enabled.append(key.replace("_enabled", ""))

        protections_str = (
            ", ".join(enabled) if enabled else "none"
        )

        return (
            f"hash_mode={hash_mode} | "
            f"hash_params={params_str} | "
            f"protections={protections_str}"
        )

    @staticmethod
    def _plot_latency_bar_chart(averages, title, output_png=None) -> None:
        labels = ["Weak", "Medium", "Strong", "Overall"]
        values = [
            averages["weak"],
            averages["medium"],
            averages["strong"],
            averages["overall"],
        ]

        plt.figure(figsize=(9, 6))
        plt.bar(labels, values, color=["red", "orange", "green", "blue"])

        plt.title(title)
        plt.xlabel("Password Strength Category")
        plt.ylabel("Average Latency (ms)")

        plt.tight_layout()

        if output_png:
            output_png = Path(output_png)
            if output_png.is_dir():
                output_png = output_png / "latency_statistics.png"
            plt.savefig(output_png, dpi=150)
        else:
            plt.show()

    @staticmethod
    def _plot_latency_bar_chart_multi(data, output_png=None):
        """
        data: list of tuples (config_title, averages_dict)
        averages_dict must contain keys: weak, medium, strong, overall
        """
        categories = ["Weak", "Medium", "Strong", "Overall"]
        n_categories = len(categories)
        n_configs = len(data)
        bar_width = 0.15

        indices = list(range(n_categories))

        plt.figure(figsize=(12, 6))

        for i, (title, averages) in enumerate(data):
            values = [
                averages["weak"],
                averages["medium"],
                averages["strong"],
                averages["overall"]
            ]
            x_positions = [x + i * bar_width for x in indices]
            plt.bar(x_positions, values, bar_width, label=title)

        tick_positions = [x + bar_width * (n_configs - 1) / 2 for x in indices]
        plt.xticks(tick_positions, categories)
        plt.ylabel("Average Latency (ms)")
        plt.xlabel("Password Strength")
        plt.title("Latency comparison across hash modes & parameters")
        plt.legend(fontsize=8, bbox_to_anchor=(1.05, 1), loc='upper left')

        plt.tight_layout()

        if output_png:
            plt.savefig(output_png, dpi=150)
            plt.close()
        else:
            plt.show()
