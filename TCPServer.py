#!/usr/bin/env python

from scapy.all import *
from scapy.layers.inet import TCP, IP
import threading
import socket
import sys


class TCPServer:
    """
    A simple TCP server that listens for incoming TCP packets.
    """

    def __init__(self, ip="0.0.0.0", port=12345):
        self.ip = ip
        self.port = port
        self.server_socket = None
        self.seq_number = 0

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.ip, self.port))
        self.server_socket.listen(5)
        print(f"Server started on  {self.ip}:{self.port}. Press Ctrl+C to stop.")

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

            # Check for SYN (0x02) and respond accordingly
            if packet[TCP].flags == "S":
                print("Received SYN. Acknowledging client...")
                self.tcp_ack_packet(packet, True)
            # Check for SYN-ACK (0x12) and respond accordingly
            elif packet[TCP].flags == "SA":
                print("Received SYN-ACK. Acknowledging client...")
                self.tcp_ack_packet(packet)
            # Check for PUSH (0x08) and respond accordingly
            elif packet[TCP].flags == "P":
                print("Received PUSH, Acknowledging client...")
                self.tcp_ack_packet(packet)
            # Check for FIN (0x01) and respond accordingly
            elif packet[TCP].flags == "F":
                print("Received FIN. Closing connection...")
                self.tcp_ack_packet(packet)
                self.tcp_terminate_connection(packet)
            # Check for RST (0x04) and respond accordingly
            elif packet[TCP].flags == "R":
                print("Received RESET. Closing connection...")

    def tcp_ack_packet(self, packet, is_syn_ack=False):
        """
        Send ACK or SYN-ACK responses
        """
        print(
            f"{'SYN-ACK' if is_syn_ack else 'ACK'} packet sent to {packet[IP].dst}:{packet[TCP].dport}"
        )
        ip = IP(
            src=packet[IP].dst, dst=packet[IP].src
        )  # Swap source and destination IPs
        if is_syn_ack:
            tcp = TCP(
                sport=packet[TCP].dport,
                dport=packet[TCP].sport,
                flags="SA",
                ack=packet[TCP].seq + 1,
            )
        else:
            tcp = TCP(
                sport=packet[TCP].dport,
                dport=packet[TCP].sport,
                flags="A",
                ack=packet[TCP].seq + 1,
            )
        send(ip / tcp)

    def tcp_terminate_connection(self, packet):
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
        if ack_packet and ack_packet.haslayer(TCP) and ack_packet[TCP].flags == "A":
            print("Connection termination complete.")

    def tcp_3_way_handshake(self, packet):
        # Step 1: Send SYN
        syn = IP(src=packet[IP].src, dst=packet[IP].dst) / TCP(
            sport=packet[TCP].sport,
            dport=packet[TCP].dport,
            flags="S",
            seq=self.seq_number,
        )
        send(syn)

        # Step 2: Wait for SYN-ACK
        syn_ack = sniff(
            filter=f"tcp and src host {packet[IP].dst} and tcp port {packet[TCP].dport}",
            prn=lambda x: x,
            count=1,
            store=0,
        )

        if not syn_ack:
            print("No SYN-ACK received")
            return False

        # Step 3: Send ACK
        self.seq_number += 1  # Increment sequence number for ACK
        ack = IP(src=packet[IP].dst, dst=packet[IP].src) / TCP(
            sport=packet[TCP].dport,
            dport=packet[TCP].sport,
            flags="A",
            seq=self.seq_number,
            ack=syn_ack[0][TCP].seq + 1,
        )
        send(ack)

        print("Three-way handshake completed successfully.")
        return True

    def tcp_initiate_connection_close(self, packet):
        """
        Terminate connection initiated by server
        """
        # Step 1: Send FIN
        fin = IP(src=packet[IP].dst, dst=packet[IP].src) / TCP(
            sport=packet[TCP].dport,
            dport=packet[TCP].sport,
            flags="F",
            ack=packet[TCP].seq,
        )
        send(fin)

        # Step 2: Wait for FIN-ACK
        fin_ack = sniff(
            filter=f"tcp and src host {packet[IP].dst} and tcp port {packet[IP].sport}",
            prn=lambda x: x,
            count=1,
            store=0,
        )

        if not fin_ack:
            print("No FIN-ACK received")
            return False

        # Step 3: Send final ACK
        self.seq_number += 1  # Increment sequence number for final ACK
        final_ack = IP(src=packet[IP].dst, dst=packet[IP].src) / TCP(
            sport=packet[TCP].dport,
            dport=packet[TCP].sport,
            flags="A",
            seq=self.seq_number,
            ack=fin_ack[0][TCP].seq + 1,
        )
        send(final_ack)

        print("Connection closed gracefully.")
        return True


# run
# if __name__ == "__main__":
#     server = TCPServer(port=99)
#     server.start()
