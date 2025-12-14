# from application import AuthServer, Database
import json

USERS_FILE = "users.json"  # TODO: GET FROM CONFIGURATION MODULE


# def setup():
#     with open(USERS_FILE, "r", encoding="utf-8") as f:
#         dummy_users = json.load(f)
#
#     for user in dummy_users:
#         database.add_user_entry(user["username"], get_hashing_function()(user["password"]))

def main():
    # database = Database()
    # database.populate()
    # server = AuthServer()
    # server.run(port=5000, debug=True)
    pass


if __name__ == "__main__":
    main()
