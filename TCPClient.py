#!/usr/bin/env python

from scapy.all import *
from scapy.layers.inet import TCP, IP
import socket
import sys


class TCPClient:
    def __init__(self, server_ip="127.0.0.1", server_port=12345):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_socket = None

    def test(self):
        """
        Performing a 3 way TCP handshake test.
        """
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_ip, self.server_port))

            self.perform_handshake()
            self.terminate_connection()
        except ConnectionRefusedError as e:
            print(f"Make sure the server {self.server_ip}:{self.server_port} is up and running.\n{e} ...")
        finally:
            self.client_socket.close()
            print("Connection closed.")
            sys.exit(0)

    def run(self):
        """
        Initiate the connection with the server.
        """
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_ip, self.server_port))
            self.send_messages()
        except ConnectionRefusedError as e:
            print(f"Make sure the server {self.server_ip}:{self.server_port} is up and running.\n{e} ...")
        finally:
            self.client_socket.close()
            print("Connection closed.")
            sys.exit(0)

    # todo - move to PacketBuilder
    def perform_handshake(self):
        print("Performing TCP 3-way handshake...")

        # Send SYN packet
        syn = IP(dst=self.server_ip) / TCP(dport=self.server_port, flags="S")
        ans = sr1(syn)

        # Check for SYN-ACK response
        if ans and ans.haslayer(TCP) and ans[TCP].flags == (0x02 | 0x10):
            print("Received SYN-ACK. Sending ACK...")
            ack = IP(dst=self.server_ip) / TCP(
                dport=self.server_port, flags="A", ack=ans[TCP].seq + 1
            )
            send(ack)
            print("Handshake complete.")
        else:
            print("Handshake failed.")

    # todo - move to PacketBuilder
    def terminate_connection(self):
        print("Terminating TCP connection...")
        # Send FIN packet to terminate the connection
        fin_packet = IP(dst=self.server_ip) / TCP(dport=self.server_port, flags="F")
        ans = sr1(fin_packet)

        # Wait for FIN-ACK from the server
        if ans and ans.haslayer(TCP) and ans[TCP].flags == (0x01 | 0x10):
            print("Received FIN-ACK from server. Sending final ACK...")
            final_ack = IP(dst=self.server_ip) / TCP(
                dport=self.server_port, flags="A", ack=ans[TCP].seq + 1
            )
            send(final_ack)
            print("Connection terminated successfully.")

        sys.exit(0)

    # todo - add reading from file
    def send_messages(self):
        try:
            while True:
                message = input("Enter message (or 'exit' to quit): ")
                if message.lower() == "exit":
                    break
                self.client_socket.send(message.encode())
        finally:
            self.client_socket.close()
            print("Connection closed.")

