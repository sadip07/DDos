#!/usr/bin/env python3
"""
Traffic analyzer for DDoS detection

This script monitors network traffic to detect potential DDoS attacks
by analyzing traffic patterns, connection rates, and packet characteristics.
"""

import argparse
import time
import logging
import signal
import sys
from collections import defaultdict, deque
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP
except ImportError:
    print("Scapy not installed. Please install with: pip install scapy")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TrafficAnalyzer:
    def __init__(self, interface=None, threshold=100, window=60):
        """
        Initialize the traffic analyzer
        
        Args:
            interface (str): Network interface to monitor
            threshold (int): Number of packets per second considered suspicious
            window (int): Time window in seconds for rate calculations
        """
        self.interface = interface
        self.threshold = threshold
        self.window = window
        self.packet_count = 0
        self.start_time = time.time()
        
        # Traffic statistics
        self.ip_counts = defaultdict(int)
        self.src_port_counts = defaultdict(int)
        self.dst_port_counts = defaultdict(int)
        self.connection_count = defaultdict(int)
        
        # Sliding window for rate calculations
        self.packet_times = deque()
        self.running = True
        
        # Register signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.handle_shutdown)
        
    def handle_shutdown(self, sig, frame):
        """Handle CTRL+C gracefully"""
        print("\nShutting down traffic analyzer...")
        self.running = False
        self.print_stats()
        sys.exit(0)
        
    def process_packet(self, packet):
        """Process a single packet and update statistics"""
        self.packet_count += 1
        
        # Store packet arrival time for rate calculations
        current_time = time.time()
        self.packet_times.append(current_time)
        
        # Remove old packets from the window
        while self.packet_times and self.packet_times[0] < current_time - self.window:
            self.packet_times.popleft()
        
        # Calculate current packet rate
        rate = len(self.packet_times) / self.window
        
        # Extract IP layer information if present
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            self.ip_counts[src_ip] += 1
            
            # Create a connection identifier (source -> destination)
            connection = f"{src_ip} -> {dst_ip}"
            self.connection_count[connection] += 1
            
            # Extract transport layer information
            if TCP in packet:
                self.src_port_counts[packet[TCP].sport] += 1
                self.dst_port_counts[packet[TCP].dport] += 1
                proto = "TCP"
            elif UDP in packet:
                self.src_port_counts[packet[UDP].sport] += 1
                self.dst_port_counts[packet[UDP].dport] += 1
                proto = "UDP"
            else:
                proto = "Other"
        
            # Check for potential attack indicators
            if rate > self.threshold:
                logger.warning(f"High traffic rate detected: {rate:.2f} packets/sec")
                if self.ip_counts[src_ip] > rate * 0.8:
                    logger.warning(f"Possible DDoS attack from {src_ip} - {self.ip_counts[src_ip]} packets ({proto})")
        
        # Print status periodically
        if self.packet_count % 100 == 0:
            elapsed = current_time - self.start_time
            logger.info(f"Processed {self.packet_count} packets in {elapsed:.2f} seconds - Current rate: {rate:.2f} packets/sec")
            
            # Find the top sources
            top_sources = sorted(self.ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            if top_sources:
                logger.info(f"Top 5 sources: {', '.join([f'{ip} ({count})' for ip, count in top_sources])}")
    
    def start_sniffing(self):
        """Start capturing and analyzing packets"""
        logger.info(f"Starting traffic analysis on {self.interface or 'all interfaces'}")
        logger.info(f"Alert threshold: {self.threshold} packets/sec over {self.window} seconds")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                store=False,
                stop_filter=lambda p: not self.running
            )
        except Exception as e:
            logger.error(f"Error while sniffing: {e}")
    
    def print_stats(self):
        """Print the collected statistics"""
        elapsed = time.time() - self.start_time
        logger.info(f"\nTraffic Analysis Summary:")
        logger.info(f"Duration: {elapsed:.2f} seconds")
        logger.info(f"Total packets: {self.packet_count}")
        logger.info(f"Average rate: {self.packet_count / elapsed:.2f} packets/sec")
        
        # Top 10 source IPs
        print("\nTop 10 Source IPs:")
        for ip, count in sorted(self.ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {ip}: {count} packets ({count/self.packet_count*100:.2f}%)")
        
        # Top destination ports
        print("\nTop 5 Destination Ports:")
        for port, count in sorted(self.dst_port_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  Port {port}: {count} packets")

def main():
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer for DDoS Detection")
    parser.add_argument("-i", "--interface", help="Network interface to monitor")
    parser.add_argument("-t", "--threshold", type=int, default=100, 
                        help="Packet rate threshold for DDoS detection (packets/sec)")
    parser.add_argument("-w", "--window", type=int, default=60,
                        help="Time window in seconds for rate calculation")
    args = parser.parse_args()
    
    analyzer = TrafficAnalyzer(
        interface=args.interface,
        threshold=args.threshold,
        window=args.window
    )
    
    analyzer.start_sniffing()

if __name__ == "__main__":
    main() 