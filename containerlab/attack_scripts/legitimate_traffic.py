#!/usr/bin/env python3
"""
Legitimate Traffic Generator for Baseline Testing

Bu script, normal ağ trafiği simüle eder.
IDS'in yanlış pozitif oranını test etmek için kullanılır.

Author: PhD Research - SDN Security
"""

import socket
import time
import random
import threading
import argparse
from datetime import datetime

class LegitimateTrafficGenerator:
    """Generate normal network traffic patterns"""

    def __init__(self, targets):
        self.targets = targets
        self.running = False
        self.stats = {
            'http_requests': 0,
            'ping_packets': 0,
            'dns_queries': 0,
            'file_transfers': 0
        }

    def http_requests(self, duration=60, interval=1.0):
        """Simulate normal HTTP browsing"""
        print("[HTTP] Starting normal HTTP traffic...")

        self.running = True
        start_time = time.time()

        while self.running and (time.time() - start_time) < duration:
            target = random.choice(self.targets)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target, 80))

                pages = ['/', '/index.html', '/about', '/contact', '/api/data']
                page = random.choice(pages)

                request = f"GET {page} HTTP/1.1\r\n"
                request += f"Host: {target}\r\n"
                request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                request += "Accept: text/html,application/json\r\n"
                request += "Connection: close\r\n\r\n"

                sock.send(request.encode())
                response = sock.recv(4096)
                sock.close()

                self.stats['http_requests'] += 1

            except Exception as e:
                pass

            # Variable delay (human-like behavior)
            time.sleep(interval + random.uniform(-0.3, 0.5))

        print(f"[HTTP] Complete. Requests: {self.stats['http_requests']}")

    def ping_hosts(self, duration=60, interval=2.0):
        """Simulate ICMP ping for connectivity checks"""
        import subprocess

        print("[PING] Starting normal ICMP traffic...")

        self.running = True
        start_time = time.time()

        while self.running and (time.time() - start_time) < duration:
            target = random.choice(self.targets)
            try:
                subprocess.run(
                    ['ping', '-c', '1', '-W', '1', target],
                    capture_output=True,
                    timeout=2
                )
                self.stats['ping_packets'] += 1
            except:
                pass

            time.sleep(interval)

        print(f"[PING] Complete. Packets: {self.stats['ping_packets']}")

    def dns_queries(self, duration=60, interval=3.0):
        """Simulate normal DNS lookups"""
        print("[DNS] Starting normal DNS traffic...")

        domains = [
            'google.com', 'github.com', 'stackoverflow.com',
            'wikipedia.org', 'python.org', 'microsoft.com'
        ]

        self.running = True
        start_time = time.time()

        while self.running and (time.time() - start_time) < duration:
            domain = random.choice(domains)
            try:
                socket.gethostbyname(domain)
                self.stats['dns_queries'] += 1
            except:
                pass

            time.sleep(interval + random.uniform(-0.5, 1.0))

        print(f"[DNS] Complete. Queries: {self.stats['dns_queries']}")

    def file_transfer(self, duration=60, chunk_size=1024):
        """Simulate file transfer / data exchange"""
        print("[FTP] Starting file transfer simulation...")

        self.running = True
        start_time = time.time()

        while self.running and (time.time() - start_time) < duration:
            target = random.choice(self.targets)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target, 80))

                # Simulate data upload
                data = b'X' * chunk_size
                sock.send(data)
                self.stats['file_transfers'] += 1
                sock.close()

            except:
                pass

            time.sleep(random.uniform(0.5, 2.0))

        print(f"[FTP] Complete. Transfers: {self.stats['file_transfers']}")

    def mixed_traffic(self, duration=60):
        """Generate mixed normal traffic pattern"""
        print("[MIXED] Starting mixed traffic generation...")
        print(f"[MIXED] Duration: {duration}s")
        print(f"[MIXED] Targets: {self.targets}")
        print("-" * 40)

        threads = [
            threading.Thread(target=self.http_requests, args=(duration, 1.5)),
            threading.Thread(target=self.ping_hosts, args=(duration, 3.0)),
            threading.Thread(target=self.dns_queries, args=(duration, 5.0)),
            threading.Thread(target=self.file_transfer, args=(duration,))
        ]

        for t in threads:
            t.daemon = True
            t.start()

        for t in threads:
            t.join()

        print("-" * 40)
        print("[MIXED] Traffic generation complete")
        print(f"Total HTTP requests: {self.stats['http_requests']}")
        print(f"Total PING packets: {self.stats['ping_packets']}")
        print(f"Total DNS queries: {self.stats['dns_queries']}")
        print(f"Total file transfers: {self.stats['file_transfers']}")

    def stop(self):
        self.running = False


def main():
    parser = argparse.ArgumentParser(description='Legitimate Traffic Generator')
    parser.add_argument('targets', nargs='+', help='Target IP addresses')
    parser.add_argument('-d', '--duration', type=int, default=60, help='Duration in seconds')
    parser.add_argument('-t', '--type', choices=['http', 'ping', 'dns', 'ftp', 'mixed'],
                       default='mixed', help='Traffic type')

    args = parser.parse_args()

    generator = LegitimateTrafficGenerator(args.targets)

    print("=" * 50)
    print("Legitimate Traffic Generator")
    print(f"Started: {datetime.now()}")
    print("=" * 50)

    try:
        if args.type == 'http':
            generator.http_requests(args.duration)
        elif args.type == 'ping':
            generator.ping_hosts(args.duration)
        elif args.type == 'dns':
            generator.dns_queries(args.duration)
        elif args.type == 'ftp':
            generator.file_transfer(args.duration)
        else:
            generator.mixed_traffic(args.duration)
    except KeyboardInterrupt:
        print("\n[STOPPED] Generator interrupted")
        generator.stop()


if __name__ == '__main__':
    main()
