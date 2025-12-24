from pathlib import Path

from application import AuthServer
from configuration import hash_mode, get_hash_params, protections

DIRECTORY_PATH = Path(__file__).parent


def main():
    server = AuthServer(DIRECTORY_PATH, hash_mode, get_hash_params(hash_mode), protections)
    server.run(debug=False)


if __name__ == "__main__":
    main()
