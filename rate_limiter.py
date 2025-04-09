#!/usr/bin/env python3
"""
Rate Limiter for DDoS Mitigation

This tool implements a simple rate limiting mechanism that can be used 
to mitigate DDoS attacks by limiting the number of connections from a single IP.
It uses netfilterqueue to intercept and process packets.
"""

import argparse
import logging
import signal
import sys
import time
from collections import defaultdict, deque
import socket
import struct

try:
    import netfilterqueue
except ImportError:
    print("netfilterqueue module not installed. Please install with: pip install netfilterqueue")
    sys.exit(1)

try:
    from scapy.all import IP, TCP, UDP
except ImportError:
    print("Scapy not installed. Please install with: pip install scapy")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self, max_rate=100, window=60, blacklist_threshold=1000, queue_num=1):
        """
        Initialize the rate limiter
        
        Args:
            max_rate (int): Maximum number of packets per second allowed from a single IP
            window (int): Time window in seconds for rate calculations
            blacklist_threshold (int): Number of packets that triggers automatic blacklisting
            queue_num (int): The netfilter queue number to bind to
        """
        self.max_rate = max_rate
        self.window = window
        self.blacklist_threshold = blacklist_threshold
        self.queue_num = queue_num
        
        # IP tracking data structures
        self.ip_packet_times = defaultdict(deque)
        self.blacklisted_ips = set()
        
        # Statistics
        self.total_accepted = 0
        self.total_dropped = 0
        self.start_time = time.time()
        
        # Initialize the netfilterqueue
        self.queue = netfilterqueue.NetfilterQueue()
        
        # Register signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.handle_shutdown)
        logger.info(f"Rate limiter initialized with max rate of {max_rate} packets/sec over {window} seconds")
        
    def handle_shutdown(self, sig, frame):
        """Handle CTRL+C gracefully"""
        logger.info("\nShutting down rate limiter...")
        self.print_stats()
        self.queue.unbind()
        sys.exit(0)
        
    def get_current_rate(self, ip):
        """Calculate the current rate for a given IP"""
        times = self.ip_packet_times[ip]
        current_time = time.time()
        
        # Remove old packets outside the window
        while times and times[0] < current_time - self.window:
            times.popleft()
            
        # Calculate the current rate
        return len(times) / self.window
    
    def process_packet(self, pkt):
        """Process a packet and decide whether to accept or drop it"""
        payload = pkt.get_payload()
        
        # Use Scapy to parse the packet
        try:
            packet = IP(payload)
            src_ip = packet.src
            current_time = time.time()
            
            # Skip processing for already blacklisted IPs
            if src_ip in self.blacklisted_ips:
                logger.debug(f"Dropping packet from blacklisted IP: {src_ip}")
                pkt.drop()
                self.total_dropped += 1
                return
            
            # Add current time to the IP's packet times
            self.ip_packet_times[src_ip].append(current_time)
            
            # Calculate current rate for this IP
            current_rate = self.get_current_rate(src_ip)
            
            # Check if the rate exceeds the maximum allowed
            if current_rate > self.max_rate:
                if len(self.ip_packet_times[src_ip]) > self.blacklist_threshold:
                    logger.warning(f"Blacklisting IP {src_ip} - rate: {current_rate:.2f} pkts/sec")
                    self.blacklisted_ips.add(src_ip)
                else:
                    logger.info(f"Rate limiting IP {src_ip} - rate: {current_rate:.2f} pkts/sec")
                
                pkt.drop()
                self.total_dropped += 1
            else:
                pkt.accept()
                self.total_accepted += 1
                
            # Print periodic status updates
            if (self.total_accepted + self.total_dropped) % 1000 == 0:
                self.print_stats()
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            pkt.accept()  # Accept in case of error
            self.total_accepted += 1
    
    def print_stats(self):
        """Print the rate limiter statistics"""
        elapsed = time.time() - self.start_time
        logger.info(f"\nRate Limiter Statistics:")
        logger.info(f"Running time: {elapsed:.2f} seconds")
        logger.info(f"Total packets: {self.total_accepted + self.total_dropped}")
        logger.info(f"Accepted packets: {self.total_accepted}")
        logger.info(f"Dropped packets: {self.total_dropped}")
        logger.info(f"Drop rate: {self.total_dropped/(self.total_accepted + self.total_dropped)*100:.2f}%")
        
        # Top offenders
        logger.info("\nTop 5 rate-limited IPs:")
        sorted_ips = sorted(
            [(ip, self.get_current_rate(ip)) for ip in self.ip_packet_times],
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        for ip, rate in sorted_ips:
            status = "BLACKLISTED" if ip in self.blacklisted_ips else "Rate limited"
            logger.info(f"  {ip}: {rate:.2f} pkts/sec - {status}")
    
    def start(self):
        """Start the rate limiter"""
        try:
            # Bind to the queue
            self.queue.bind(self.queue_num, self.process_packet)
            logger.info(f"Rate limiter bound to netfilter queue {self.queue_num}")
            logger.info("Run the following command as root to direct traffic to this queue:")
            logger.info(f"iptables -A INPUT -j NFQUEUE --queue-num {self.queue_num}")
            
            # Start processing packets
            self.queue.run()
        except Exception as e:
            logger.error(f"Error starting rate limiter: {e}")
            if "permission denied" in str(e).lower():
                logger.error("This script requires root privileges. Please run with sudo.")
            sys.exit(1)

def setup_iptables(queue_num, port=None):
    """Set up iptables rules to direct traffic to our queue"""
    try:
        # Flush existing rules
        os.system("iptables -F")
        
        # Create basic rule
        cmd = f"iptables -A INPUT -j NFQUEUE --queue-num {queue_num}"
        
        # Add port filter if specified
        if port:
            cmd = f"iptables -A INPUT -p tcp --dport {port} -j NFQUEUE --queue-num {queue_num}"
            
        os.system(cmd)
        logger.info(f"Set up iptables rule: {cmd}")
    except Exception as e:
        logger.error(f"Failed to set up iptables: {e}")

def main():
    parser = argparse.ArgumentParser(description="Network Rate Limiter for DDoS Mitigation")
    parser.add_argument("-r", "--rate", type=int, default=100, 
                        help="Maximum packet rate per second from a single IP")
    parser.add_argument("-w", "--window", type=int, default=60,
                        help="Time window in seconds for rate calculation")
    parser.add_argument("-b", "--blacklist", type=int, default=1000,
                        help="Packet threshold for automatic blacklisting")
    parser.add_argument("-q", "--queue", type=int, default=1,
                        help="Netfilter queue number to use")
    parser.add_argument("-p", "--port", type=int, 
                        help="Optional: Only process packets to this destination port")
    parser.add_argument("--setup", action="store_true",
                        help="Automatically set up iptables rules")
    
    args = parser.parse_args()
    
    # Set up iptables if requested
    if args.setup:
        import os
        if os.geteuid() != 0:
            logger.error("Setting up iptables requires root privileges. Please run with sudo.")
            sys.exit(1)
        setup_iptables(args.queue, args.port)
    
    # Create and start the rate limiter
    limiter = RateLimiter(
        max_rate=args.rate,
        window=args.window,
        blacklist_threshold=args.blacklist,
        queue_num=args.queue
    )
    
    limiter.start()

if __name__ == "__main__":
    main() 