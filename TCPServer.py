#!/usr/bin/env python

from scapy.all import *
from scapy.layers.inet import TCP, IP

from DataManager import DatabaseManager


class TCPServer:
    """
    A simple TCP server that listens for incoming TCP packets.
    """

    def __init__(self, ip="0.0.0.0", port=12345):
        self.ip = ip
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.db_manager = DatabaseManager()

    def start(self):
        self.server_socket.bind((self.ip, self.port))
        self.server_socket.listen(5)  # nothing in particular about 5
        print(f"Server started on  {self.ip}:{self.port}. Press Ctrl+C to stop.")

        # capture the packets and store it in DB
        self.capture_incoming_traffic()

        try:
            while True:
                client_socket, addr = self.server_socket.accept()
                print(f"Connection established with {addr}")
                client_thread = threading.Thread(
                    target=self.handle_client, args=(client_socket,)
                )
                client_thread.start()
        except KeyboardInterrupt:
            print("\nShutting down the server.")
            self.server_socket.close()
            self.db_manager.close()
            sys.exit()

    def capture_incoming_traffic(self):
        """Capturing incoming traffic on port 99"""
        print(f"Capture Incoming Traffic...")
        sniff(
            filter=f"tcp and port {self.port}",
            prn=self.store_payload,
        )

    def store_payload(self, pkt):
        """Filtering PSH & PSH-ACK"""
        if (
            pkt[TCP].dport == self.port
            and pkt.haslayer("TCP")
            and pkt[TCP].flags == (0x08 | 0x18)
        ):
            payload = bytes(pkt[TCP].payload)
            print(f"We got {payload} from {pkt[IP].src}:{pkt[IP].sport}")
            self.db_manager.save_packet(payload)

    @staticmethod
    def handle_client(client_socket):
        with client_socket:
            data = client_socket.recv(4096)
            if data:
                print(f"Received {data} from {client_socket.getpeername()}")
