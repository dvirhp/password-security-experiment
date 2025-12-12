from attack.brute_force import BruteForceAttack


def test_bruteforce_attack_runs():
    attack = BruteForceAttack(
        base_url="http://127.0.0.1:5000",
        username="non_existing_user",
        passwords=["a", "b", "c"]
    )

    # If no exception is raised → test passed
    attack.run()
