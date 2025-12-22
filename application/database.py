import sqlite3
from sqlite3 import Connection

DB_PATH = "database.sqlite3"


class Database:
    def __init__(self, database_path=DB_PATH):
        self._connect = sqlite3.connect(database_path, check_same_thread=False)
        self._connect.row_factory = sqlite3.Row

        self._cursor = self._connect.cursor()

        self._initialize()

    @property
    def connect(self) -> Connection:
        return self._connect

    def _initialize(self):
        self._cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                hashed_password TEXT
            );
        """)

        self._connect.commit()

    def insert_user(self, username, hashed_password) -> bool:
        """
        Insert a new user into the users table.

        Args:
            username (str): The username to add.
            hashed_password (str): The hashed password.

        Raises:
            sqlite3.IntegrityError: If the username already exists.
        """
        try:
            self._cursor.execute(
                """
                INSERT INTO users (username, hashed_password)
                VALUES (?, ?)
                """,
                (username, hashed_password)
            )

            self._connect.commit()
            return True

        except sqlite3.IntegrityError:
            return False

    def retrieve_user_hash(self, username) -> str | None:
        """
        Retrieve the hashed password for a given username.

        Args:
            username (str): The username to look up.

        Returns:
            str | None: The hashed password if the user exists, otherwise None.
        """
        self._cursor.execute(
            "SELECT hashed_password FROM users WHERE username = ?",
            (username,)
        )
        row = self._cursor.fetchone()
        if row:
            return row["hashed_password"]
        return None

    def close(self):
        """Close the database cursor and connection."""
        if self._cursor:
            self._cursor.close()
            self._cursor = None

        if self._connect:
            self._connect.close()
            self._connect = None
