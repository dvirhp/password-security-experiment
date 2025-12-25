# from experiments import generate_tests, build_groups, enabled_protections, enabled_attack_flags
#
#
# def main():
#     tests = generate_tests()
#     groups = build_groups()
#
#     print("=== ALL EXPERIMENTS ===")
#     for index, test in enumerate(tests, start=1):
#         protections = enabled_protections(test["protections"])
#         attacks = enabled_attack_flags(test["attack_parameters"])
#         strength = test["attack_parameters"]["password_strength"]
#         max_attempts = test["attack_parameters"]["max_attempts"]
#
#         print(
#             f"{index:03d} | "
#             f"hash={test['hash_mode']:9s} | "
#             f"strength={strength:6s} | "
#             f"max_attempts={max_attempts} | "
#             f"protections={protections if protections else ['none']} | "
#             f"attack_flags={attacks if attacks else '{}'}"
#         )
#
#     print(f"\nTOTAL EXPERIMENTS: {len(tests)}")
#
#     print("\n=== GROUP COUNTS ===")
#     for group, experiment in sorted(groups.items()):
#         print(f"{group:25s} : {len(experiment)}")
#
#
# if __name__ == "__main__":
#     main()
