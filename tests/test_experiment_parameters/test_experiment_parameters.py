from experiments import build_groups, generate_experiment_configs


def main():
    groups = build_groups()
    total = 0

    print("=== ALL EXPERIMENTS ===")
    for idx, exp in enumerate(generate_experiment_configs(), start=1):
        total += 1
        print(
            f"{idx:04d} | "
            # f"user={exp['attack_parameters']['username']} | "
            f"hash={exp['hash_mode']} | "
            f"protection={[k for k in exp['protections'] if k != 'pepper'][0]} | "
            f"attack={exp['attack_parameters']}"
        )

    print(f"\nTOTAL EXPERIMENTS: {total}")

    print("\n=== GROUP COUNTS ===")
    for group, exp in sorted(groups.items()):
        print(f"{group:25s} : {len(exp)}")


if __name__ == "__main__":
    main()
