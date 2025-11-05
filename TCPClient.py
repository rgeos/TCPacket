#!/usr/bin/env python

from scapy.all import *
from scapy.layers.inet import TCP, IP
import socket
import sys

from FileReader import FileReader


class TCPClient:
    def __init__(self, server_ip="127.0.0.1", server_port=12345):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_socket = None

    def send_test_data(self):
        """
        Initiate the connection with the server.
        Performing a 3 way TCP handshake test.
        """
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_ip, self.server_port))

            self.perform_handshake()
            self.terminate_connection()
        except ConnectionRefusedError as e:
            print(
                f"Make sure the server {self.server_ip}:{self.server_port} is up and running.\n{e} ..."
            )
        finally:
            self.client_socket.close()
            print("Connection closed.")
            sys.exit(0)

    def perform_handshake(self):
        print("Performing TCP 3-way handshake...")

        # Send SYN packet
        syn = IP(dst=self.server_ip) / TCP(dport=self.server_port, flags="S")
        ans = sr1(syn)

        # Check for SYN-ACK response
        if ans and ans.haslayer(TCP) and ans[TCP].flags == "SA":
            print("Received SYN-ACK. Sending ACK...")
            ack = IP(dst=self.server_ip) / TCP(
                dport=self.server_port, flags="A", ack=ans[TCP].seq + 1
            )
            send(ack)
            print("Handshake complete.")
        else:
            print("Handshake failed.")

    def terminate_connection(self):
        print("Terminating TCP connection...")
        # Send FIN packet to terminate the connection
        fin_packet = IP(dst=self.server_ip) / TCP(dport=self.server_port, flags="F")
        ans = sr1(fin_packet)

        # Wait for FIN-ACK from the server
        if ans and ans.haslayer(TCP) and ans[TCP].flags == "FA":
            print("Received FIN-ACK from server. Sending final ACK...")
            final_ack = IP(dst=self.server_ip) / TCP(
                dport=self.server_port, flags="A", ack=ans[TCP].seq + 1
            )
            send(final_ack)
            print("Connection terminated successfully.")

        sys.exit(0)

    def send_cli_data(self):
        """
        Initiate the connection with the server.
        Send data from CLI
        """
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_ip, self.server_port))
            self.cli_input()
        except ConnectionRefusedError as e:
            print(
                f"Make sure the server {self.server_ip}:{self.server_port} is up and running.\n{e} ..."
            )
        finally:
            self.client_socket.close()
            print("Connection closed.")
            sys.exit(0)

    def cli_input(self):
        try:
            while True:
                message = input("Enter message (or 'exit' to quit): ")
                if message.lower() == "exit":
                    break
                self.client_socket.send(message.encode())
        finally:
            self.client_socket.close()
            print("Connection closed.")

    def send_file_data(self, payload):
        """
        Initiate the connection with the server.
        Send data from FILE
        """
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_ip, self.server_port))
            self.client_socket.sendall(payload)
        except ConnectionRefusedError as e:
            print(
                f"Make sure the server {self.server_ip}:{self.server_port} is up and running.\n{e} ..."
            )
        finally:
            self.client_socket.close()
            print("Connection closed.")

    def create_packet(self, data):
        """
        Creating a packet from data
        """
        ip = IP(dst=self.server_ip)
        tcp = TCP(dport=self.server_port)
        payload = Raw(load=data)

        return ip / tcp / payload

    def file_data(self, file_path):
        """
        Reading data from file
        Sending each line as payload in its own packet
        """
        try:
            reader = FileReader(file_path)
            # read the files form the file
            lines = reader.read_lines()

            # iterate through each line (assumes the data is in HEX in the file)
            for line in lines:
                # comment out this line if the file is not HEX
                payload_bytes = reader.hex_to_bytes(line)
                payload = self.create_packet(payload_bytes)
                self.send_file_data(bytes(payload))

        except FileNotFoundError:
            print("File not found.")
        finally:
            self.client_socket.close()
            sys.exit(0)
