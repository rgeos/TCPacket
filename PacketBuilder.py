#!/usr/bin/env python

from scapy.all import *
from scapy.layers.inet import IP, TCP
from FileReader import FileReader


class PacketBuilder:
    """
    Build a Packet object
    Executing some default message exchanges
    """

    def __init__(self, dest_ip, dest_port, file_path):
        self.src_ip = self._get_local_ip()
        self.dest_ip = dest_ip
        self.src_port = random.randint(1024, 65535)
        self.dest_port = dest_port
        # self.seq_number = random.randint(0, 4294967295)
        self.seq_number = 0
        self.ack_number = 0

        self.flags = {"SYN": False, "ACK": False, "FIN": False}  # Added FIN flag
        self.payload = b""
        self.file_path = file_path
        self.file_reader = FileReader(self.file_path)

    def _get_local_ip(self):
        """
        Get the IPv4 address of the local machine
        :return:
        """
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return local_ip

    def tcp_handshake(self):
        # Step 1: Send SYN
        syn = IP(src=self.src_ip, dst=self.dest_ip) / TCP(
            sport=self.src_port, dport=self.dest_port, flags="S", seq=self.seq_number
        )
        send(syn)

        # Step 2: Wait for SYN-ACK
        syn_ack = sniff(
            filter=f"tcp and src host {self.dest_ip} and tcp port {self.src_port}",
            prn=lambda x: x,
            count=1,
            store=0,
        )

        if not syn_ack:
            print("No SYN-ACK received")
            return False

        # Step 3: Send ACK
        self.seq_number += 1  # Increment sequence number for ACK
        ack = IP(src=self.src_ip, dst=self.dest_ip) / TCP(
            sport=self.src_port,
            dport=self.dest_port,
            flags="A",
            seq=self.seq_number,
            ack=syn_ack[0][TCP].seq + 1,
        )
        send(ack)

        print("Three-way handshake completed successfully.")
        return True

    def tcp_connection_close(self):
        # Step 1: Send FIN
        fin = IP(src=self.src_ip, dst=self.dest_ip) / TCP(
            sport=self.src_port, dport=self.dest_port, flags="F", seq=self.seq_number
        )
        send(fin)

        # Step 2: Wait for FIN-ACK
        fin_ack = sniff(
            filter=f"tcp and src host {self.dest_ip} and tcp port {self.src_port}",
            prn=lambda x: x,
            count=1,
            store=0,
        )

        if not fin_ack:
            print("No FIN-ACK received")
            return False

        # Step 3: Send final ACK
        self.seq_number += 1  # Increment sequence number for final ACK
        final_ack = IP(src=self.src_ip, dst=self.dest_ip) / TCP(
            sport=self.src_port,
            dport=self.dest_port,
            flags="A",
            seq=self.seq_number,
            ack=fin_ack[0][TCP].seq + 1,
        )
        send(final_ack)

        print("Connection closed gracefully.")
        return True

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
        self.create_payload(self.file_reader.read_payload())
        return self.payload

    def generate_dummy_data(self, size):
        """
        Generate a dummy data
        :param size:
        :return:
        """
        return os.urandom(size)  # Generate random bytes
