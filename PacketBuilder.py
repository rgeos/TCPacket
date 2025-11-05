#!/usr/bin/env python

from scapy.all import *
from FileReader import FileReader


class PacketBuilder:
    """
    Build a Packet object
    Executing some default message exchanges
    """

    def __init__(self, dest_ip, dest_port, file_path):
        self.src_ip = self.get_local_ip()
        self.dest_ip = dest_ip
        self.src_port = random.randint(1024, 65535)
        self.dest_port = dest_port

        self.flags = {"SYN": False, "ACK": False, "FIN": False}
        self.payload = b""
        self.file_path = file_path
        self.file_reader = FileReader(self.file_path)

    @staticmethod
    def get_local_ip():
        """
        Get the IPv4 address of the local machine
        :return:
        """
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return local_ip

    def create_payload(self, fields):
        """
        Create the payload of the file
        :param fields:
        :return:
        """
        for field, size in fields.items():
            self.payload += self.generate_dummy_data(size)

    def create_packet(self):
        """
        Create a packet with a payload
        :return:
        """
        self.create_payload(self.file_reader.read_lines())
        return self.payload

    @staticmethod
    def generate_dummy_data(size):
        """
        Generate a dummy data
        :param size:
        :return:
        """
        return os.urandom(size)  # Generate random bytes
