import json
import requests

SERVER_URL = "http://127.0.0.1:5000/register"
USERS_FILE = "users.json"


def load_users():
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def register_user(user):
    payload = {
        "username": user["username"],
        "password": user["password"]
    }

    try:
        response = requests.post(SERVER_URL, json=payload)
        return response.status_code, response.json()
    except Exception as e:
        return None, {"error": str(e)}


def main():
    users = load_users()
    print(f"Loaded {len(users)} users.\n")

    success_count = 0

    for user in users:
        status, result = register_user(user)
        if status == 201:
            success_count += 1
        else:
            print("FAILED:", result)

    print("\nDone.")
    print(f"Successfully registered {success_count}/{len(users)} users.")


if __name__ == "__main__":
    main()
