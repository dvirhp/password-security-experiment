from application.server import AuthServer

if __name__ == "__main__":
    server = AuthServer(directory_path=".")
    server.run()
