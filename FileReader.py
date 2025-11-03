#!/usr/bin/env python

import ast
import os


class FileReader:
    def __init__(self, filename):
        self.file_path = filename

    def read_dictionary(self):
        """Read dictionaries from the text file."""
        with open(self.file_path, "r") as file:
            lines = file.readlines()
        return [
            ast.literal_eval(line.strip())
            for line in lines
            if line.strip() and not line.startswith("#")
        ]

    def read_payload(self):
        """Reading a txt file with hex values."""
        if not os.path.isfile(self.file_path):
            raise FileNotFoundError(f"File {self.file_path} not found")

        with open(self.file_path, "r") as file:
            hex_data = file.read().strip()

        # convert hex to bytes
        payload = bytes.fromhex(hex_data)
        return payload
