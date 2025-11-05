#!/usr/bin/env python
import sqlite3


class DatabaseManager:
    def __init__(self, db_name="payload.db"):
        self.conn = sqlite3.connect(db_name)
        self.create_table()

    def create_table(self):
        try:
            with self.conn:
                self.conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        payload TEXT NOT NULL
                    )
                """
                )
        except sqlite3.Error as e:
            print(f"An error occurred while creating the table: {e}")

    def save_packet(self, payload):
        with self.conn:
            self.conn.execute("INSERT INTO packets (payload) VALUES (?)", (payload,))

    def close(self):
        self.conn.close()
