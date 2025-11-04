#!/usr/bin/env python

from scapy.all import *
from scapy.layers.inet import TCP, IP
import threading
import socket
import sys


# todo - move the packet creation to PacketBuilder
class TCPServer:
    """
    A simple TCP server that listens for incoming TCP packets.
    """

    def __init__(self, ip="0.0.0.0", port=12345):
        self.ip = ip
        self.port = port
        self.server_socket = None

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.ip, self.port))
        self.server_socket.listen(5)
        print(f"Server started on port {self.port}. Press Ctrl+C to stop.")

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
            sys.exit()

    def handle_client(self, client_socket):
        while True:
            packet = self.receive_packet(client_socket)
            if not packet:
                break  # Exit if no packet received

            self.process_packet(packet)

        client_socket.close()
        print("Client connection closed.")

    def receive_packet(self, client_socket):
        raw_data = client_socket.recv(4096)
        if not raw_data:
            return None
        return IP(raw_data)

    def process_packet(self, packet):
        if TCP in packet and packet[TCP].dport == self.port:
            payload = packet[TCP].payload
            print(f"Received TCP payload: {payload}")

            # Check for FIN-ACK and respond accordingly
            if packet[TCP].flags == (0x01 | 0x10):
                print("Received FIN-ACK. Sending ACK response.")
                self.reply_fin_ack(packet)
            elif packet[TCP].flags == (0x02 | 0x10):
                print("Received SYN-ACK. Preparing to terminate connection.")
                self.terminate_connection(packet)

    def reply_fin_ack(self, packet):
        ip = IP(
            src=packet[IP].dst, dst=packet[IP].src
        )  # Swap source and destination IPs
        tcp = TCP(
            sport=packet[TCP].dport,
            dport=packet[TCP].sport,
            flags="A",
            ack=packet[TCP].seq + 1,
        )
        send(ip / tcp)

    def terminate_connection(self, packet):
        # Send FIN packet to the client to terminate the connection
        print("Initiating connection termination...")
        ip = IP(src=packet[IP].dst, dst=packet[IP].src)
        tcp = TCP(
            sport=packet[TCP].dport,
            dport=packet[TCP].sport,
            flags="F",
            ack=packet[TCP].seq,
        )
        send(ip / tcp)

        # Wait for final ACK from client
        print("Waiting for final ACK from client...")
        ack_packet = self.receive_packet(packet[TCP].sport)
        if ack_packet and ack_packet.haslayer(TCP) and ack_packet[TCP].flags == 0x10:
            print("Connection termination complete.")
