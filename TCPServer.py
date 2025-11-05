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
        self.seq_number = 0
        self.db_manager = DatabaseManager()

    def start(self):
        self.server_socket.bind((self.ip, self.port))
        self.server_socket.listen(5)
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

    def handle_client(self, client_socket):
        while True:
            pkt = self.receive_packet(client_socket)
            if not pkt:
                break  # Exit if no packet received

            self.process_packet(pkt)

        client_socket.close()
        print("Client connection closed.")

    @staticmethod
    def receive_packet(client_socket):
        raw_data = client_socket.recv(4096)  # adjust the buffer as needed
        if not raw_data:
            return None
        return IP(raw_data)

    def process_packet(self, pkt):
        if TCP in pkt and pkt[TCP].dport == self.port:
            payload = pkt[TCP].payload
            print(f"Received TCP payload: {payload}")

            # Check for SYN (0x02) and respond accordingly
            if pkt[TCP].flags == "S":
                print("Received SYN. Acknowledging client...")
                self.tcp_ack_packet(pkt, True)

            # Check for SYN-ACK (0x12) and respond accordingly
            elif pkt[TCP].flags == "SA":
                print("Received SYN-ACK. Acknowledging client...")
                self.tcp_ack_packet(pkt)

            # Check for PSH (0x08) or PSH-ACK (0x18)and respond accordingly
            # we will be writing to the DB the payload
            elif pkt[TCP].flags == (0x08 | 0x18):
                print("Received PUSH Acknowledging client...")
                self.tcp_ack_packet(pkt)

            # Check for FIN (0x01) and respond accordingly
            elif pkt[TCP].flags == "F":
                print("Received FIN. Closing connection...")
                self.tcp_ack_packet(pkt)
                self.tcp_terminate_connection(pkt)

            # Check for RST (0x04) and respond accordingly
            elif pkt[TCP].flags == "R":
                print("Received RESET. Closing connection...")

    def tcp_ack_packet(self, pkt, is_syn_ack=False):
        """Send ACK or SYN-ACK responses"""
        print(
            f"{'SYN-ACK' if is_syn_ack else 'ACK'} packet sent to {pkt[IP].dst}:{pkt[TCP].dport}"
        )
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)  # Swap source and destination IPs
        if is_syn_ack:
            tcp = TCP(
                sport=pkt[TCP].dport,
                dport=pkt[TCP].sport,
                flags="SA",
                ack=pkt[TCP].seq + 1,
            )
        else:
            tcp = TCP(
                sport=pkt[TCP].dport,
                dport=pkt[TCP].sport,
                flags="A",
                ack=pkt[TCP].seq + 1,
            )
        send(ip / tcp)

    def tcp_terminate_connection(self, pkt):
        # Send FIN packet to the client to terminate the connection
        print("Initiating connection termination...")
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        tcp = TCP(
            sport=pkt[TCP].dport,
            dport=pkt[TCP].sport,
            flags="F",
            ack=pkt[TCP].seq,
        )
        send(ip / tcp)

        # Wait for final ACK from client
        print("Waiting for final ACK from client...")
        ack_packet = self.receive_packet(pkt[TCP].sport)
        if ack_packet and ack_packet.haslayer(TCP) and ack_packet[TCP].flags == "A":
            print("Connection termination complete.")

    def tcp_3_way_handshake(self, pkt):
        # Step 1: Send SYN
        syn = IP(src=pkt[IP].src, dst=pkt[IP].dst) / TCP(
            sport=pkt[TCP].sport,
            dport=pkt[TCP].dport,
            flags="S",
            seq=self.seq_number,
        )
        send(syn)

        # Step 2: Wait for SYN-ACK
        syn_ack = sniff(
            filter=f"tcp and src host {pkt[IP].dst} and tcp port {pkt[TCP].dport}",
            prn=lambda x: x,
            count=1,
            store=0,
        )

        if not syn_ack:
            print("No SYN-ACK received")
            return False

        # Step 3: Send ACK
        self.seq_number += 1  # Increment sequence number for ACK
        ack = IP(src=pkt[IP].dst, dst=pkt[IP].src) / TCP(
            sport=pkt[TCP].dport,
            dport=pkt[TCP].sport,
            flags="A",
            seq=self.seq_number,
            ack=syn_ack[0][TCP].seq + 1,
        )
        send(ack)

        print("Three-way handshake completed successfully.")
        return True

    def tcp_initiate_connection_close(self, pkt):
        """
        Terminate connection initiated by server
        """
        # Step 1: Send FIN
        fin = IP(src=pkt[IP].dst, dst=pkt[IP].src) / TCP(
            sport=pkt[TCP].dport,
            dport=pkt[TCP].sport,
            flags="F",
            ack=pkt[TCP].seq,
        )
        send(fin)

        # Step 2: Wait for FIN-ACK
        fin_ack = sniff(
            filter=f"tcp and src host {pkt[IP].dst} and tcp port {pkt[IP].sport}",
            prn=lambda x: x,
            count=1,
            store=0,
        )

        if not fin_ack:
            print("No FIN-ACK received")
            return False

        # Step 3: Send final ACK
        self.seq_number += 1  # Increment sequence number for final ACK
        final_ack = IP(src=pkt[IP].dst, dst=pkt[IP].src) / TCP(
            sport=pkt[TCP].dport,
            dport=pkt[TCP].sport,
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
