#!/usr/bin/env python3
"""
Network Security Configuration

This script helps configure the system network security settings for DDoS protection.
It can set up firewall rules, sysctl parameters, and other security configurations.
"""

import argparse
import logging
import os
import platform
import subprocess
import sys
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecurityConfigurator:
    def __init__(self):
        """Initialize the security configurator"""
        self.system = platform.system().lower()
        self.is_admin = self._check_admin_privileges()
        self.recommendations = []
        
        if not self.is_admin:
            logger.warning("Running without admin privileges. Some operations will require elevated permissions.")
    
    def _check_admin_privileges(self):
        """Check if the script is running with administrative privileges"""
        try:
            if self.system == 'windows':
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False
            
    def _run_command(self, command, check=True):
        """Run a system command and return the result"""
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=True,
                check=check
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {e.stderr.strip()}")
            return None
            
    def check_system(self):
        """Check the current system configuration and generate recommendations"""
        logger.info("Checking system configuration...")
        
        if self.system == 'linux':
            self._check_linux_config()
        elif self.system == 'windows':
            self._check_windows_config()
        else:
            logger.warning(f"Unsupported operating system: {self.system}")
        
        return self.recommendations
        
    def _check_linux_config(self):
        """Check Linux system configuration"""
        # Check if SYN cookies are enabled
        syn_cookies = self._run_command("sysctl -n net.ipv4.tcp_syncookies", check=False)
        if syn_cookies != "1":
            self.recommendations.append({
                "title": "Enable SYN cookies",
                "description": "SYN cookies protect against SYN flood attacks",
                "command": "sysctl -w net.ipv4.tcp_syncookies=1",
                "permanent_command": "echo 'net.ipv4.tcp_syncookies=1' >> /etc/sysctl.conf"
            })
        
        # Check TCP SYN backlog
        syn_backlog = self._run_command("sysctl -n net.ipv4.tcp_max_syn_backlog", check=False)
        if syn_backlog and int(syn_backlog) < 2048:
            self.recommendations.append({
                "title": "Increase TCP SYN backlog",
                "description": "A larger SYN backlog can help during SYN flood attacks",
                "command": "sysctl -w net.ipv4.tcp_max_syn_backlog=2048",
                "permanent_command": "echo 'net.ipv4.tcp_max_syn_backlog=2048' >> /etc/sysctl.conf"
            })
        
        # Check ICMP rate limiting
        icmp_ratelimit = self._run_command("sysctl -n net.ipv4.icmp_ratelimit", check=False)
        if icmp_ratelimit and int(icmp_ratelimit) < 100:
            self.recommendations.append({
                "title": "Enable ICMP rate limiting",
                "description": "Limits the rate of ICMP messages to prevent ICMP floods",
                "command": "sysctl -w net.ipv4.icmp_ratelimit=100",
                "permanent_command": "echo 'net.ipv4.icmp_ratelimit=100' >> /etc/sysctl.conf"
            })
        
        # Check if iptables is installed
        iptables_version = self._run_command("iptables --version", check=False)
        if not iptables_version:
            self.recommendations.append({
                "title": "Install iptables firewall",
                "description": "iptables is essential for network traffic filtering",
                "command": "apt-get update && apt-get install -y iptables" if self._run_command("which apt-get", check=False) else
                          "yum install -y iptables" if self._run_command("which yum", check=False) else
                          "pacman -S iptables" if self._run_command("which pacman", check=False) else
                          "Unknown package manager"
            })
            
        # Check if fail2ban is installed
        fail2ban_version = self._run_command("fail2ban-server --version", check=False)
        if not fail2ban_version:
            self.recommendations.append({
                "title": "Install fail2ban",
                "description": "fail2ban can automatically block suspicious IP addresses",
                "command": "apt-get update && apt-get install -y fail2ban" if self._run_command("which apt-get", check=False) else
                          "yum install -y fail2ban" if self._run_command("which yum", check=False) else
                          "pacman -S fail2ban" if self._run_command("which pacman", check=False) else
                          "Unknown package manager"
            })
            
    def _check_windows_config(self):
        """Check Windows system configuration"""
        # Check Windows Firewall status
        firewall_status = self._run_command("netsh advfirewall show allprofiles state", check=False)
        if firewall_status and "OFF" in firewall_status:
            self.recommendations.append({
                "title": "Enable Windows Firewall",
                "description": "Windows Firewall should be enabled for all profiles",
                "command": "netsh advfirewall set allprofiles state on"
            })
            
        # Check SYN attack protection
        syn_attack_protection = self._run_command("netsh interface tcp show security", check=False)
        if syn_attack_protection and "SYN attack protection: Disabled" in syn_attack_protection:
            self.recommendations.append({
                "title": "Enable SYN attack protection",
                "description": "SYN attack protection should be enabled in Windows TCP/IP stack",
                "command": "netsh interface tcp set security mpp=enabled"
            })
            
    def apply_recommendation(self, recommendation):
        """Apply a specific security recommendation"""
        if not self.is_admin:
            logger.error("Administrative privileges required to apply recommendations")
            return False
            
        logger.info(f"Applying recommendation: {recommendation['title']}")
        result = self._run_command(recommendation["command"], check=False)
        
        if "permanent_command" in recommendation:
            logger.info("Applying permanent configuration...")
            self._run_command(recommendation["permanent_command"], check=False)
            
        return True
        
    def configure_iptables_rules(self):
        """Configure iptables rules for DDoS protection"""
        if self.system != 'linux':
            logger.error("iptables is only available on Linux")
            return False
            
        if not self.is_admin:
            logger.error("Administrative privileges required to configure iptables")
            return False
            
        logger.info("Configuring iptables rules for DDoS protection...")
        
        # Basic rules to protect against common DDoS vectors
        rules = [
            # Limit new TCP connections
            "iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT",
            
            # Drop invalid packets
            "iptables -A INPUT -m state --state INVALID -j DROP",
            
            # Limit ICMP packets
            "iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 4 -j ACCEPT",
            "iptables -A INPUT -p icmp -j DROP",
            
            # Protect against port scanning
            "iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP",
            
            # Limit RST packets
            "iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT",
            
            # Limit new connections per IP (adjust limits as needed)
            "iptables -A INPUT -p tcp -m state --state NEW -m recent --set",
            "iptables -A INPUT -p tcp -m state --state NEW -m recent --update --seconds 60 --hitcount 20 -j DROP"
        ]
        
        # Save current rules
        self._run_command("iptables-save > /tmp/iptables.backup", check=False)
        logger.info("Current iptables rules backed up to /tmp/iptables.backup")
        
        # Apply new rules
        for rule in rules:
            result = self._run_command(rule, check=False)
            if result is None:
                logger.warning(f"Failed to apply rule: {rule}")
                
        # Save the rules to make them persistent
        if self._run_command("which iptables-save", check=False):
            save_command = "iptables-save"
            if self._run_command("test -d /etc/iptables", check=False) is not None:
                save_command += " > /etc/iptables/rules.v4"
            elif self._run_command("test -d /etc/sysconfig", check=False) is not None:
                save_command += " > /etc/sysconfig/iptables"
            else:
                save_command += " > /etc/iptables.rules"
                
            self._run_command(save_command, check=False)
            logger.info("Saved iptables rules permanently")
            
        return True
        
    def configure_sysctl_params(self):
        """Configure sysctl parameters for DDoS protection"""
        if self.system != 'linux':
            logger.error("sysctl is only available on Linux")
            return False
            
        if not self.is_admin:
            logger.error("Administrative privileges required to configure sysctl")
            return False
            
        logger.info("Configuring sysctl parameters for DDoS protection...")
        
        # Parameters for DDoS protection
        params = {
            # TCP/IP stack hardening
            "net.ipv4.tcp_syncookies": "1",
            "net.ipv4.tcp_max_syn_backlog": "2048",
            "net.ipv4.tcp_synack_retries": "2",
            "net.ipv4.tcp_syn_retries": "5",
            
            # Increase netdev backlog
            "net.core.netdev_max_backlog": "2000",
            
            # Increase connection tracking limits
            "net.netfilter.nf_conntrack_max": "2000000",
            "net.netfilter.nf_conntrack_tcp_timeout_established": "1800",
            
            # Enable source validation
            "net.ipv4.conf.all.rp_filter": "1",
            "net.ipv4.conf.default.rp_filter": "1",
            
            # Disable ICMP redirect acceptance
            "net.ipv4.conf.all.accept_redirects": "0",
            "net.ipv4.conf.default.accept_redirects": "0",
            "net.ipv4.conf.all.secure_redirects": "0",
            "net.ipv4.conf.default.secure_redirects": "0",
            
            # Increase TCP read/write memory
            "net.ipv4.tcp_rmem": "4096 87380 16777216",
            "net.ipv4.tcp_wmem": "4096 65536 16777216",
            
            # Disable source routing
            "net.ipv4.conf.all.accept_source_route": "0"
        }
        
        # Apply each parameter
        for param, value in params.items():
            command = f"sysctl -w {param}={value}"
            result = self._run_command(command, check=False)
            if result is None:
                logger.warning(f"Failed to set {param}={value}")
                
        # Make changes permanent
        with open("/etc/sysctl.d/99-ddos-protection.conf", "w") as f:
            for param, value in params.items():
                f.write(f"{param} = {value}\n")
                
        logger.info("Applied sysctl parameters and saved to /etc/sysctl.d/99-ddos-protection.conf")
        self._run_command("sysctl -p /etc/sysctl.d/99-ddos-protection.conf", check=False)
        
        return True
        
    def generate_report(self, output_file=None):
        """Generate a security report"""
        logger.info("Generating security report...")
        
        report = {
            "system": self.system,
            "admin_privileges": self.is_admin,
            "timestamp": self._run_command("date", check=False),
            "recommendations": self.recommendations
        }
        
        # Add system-specific information
        if self.system == 'linux':
            report["kernel_version"] = self._run_command("uname -r", check=False)
            report["iptables_version"] = self._run_command("iptables --version", check=False)
            report["current_connections"] = self._run_command("netstat -ant | wc -l", check=False)
        elif self.system == 'windows':
            report["windows_version"] = self._run_command("ver", check=False)
            report["firewall_status"] = self._run_command("netsh advfirewall show allprofiles state", check=False)
            
        # Format and output the report
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report saved to {output_file}")
        else:
            print(json.dumps(report, indent=2))
            
        return report

def main():
    parser = argparse.ArgumentParser(description="Network Security Configuration for DDoS Protection")
    parser.add_argument("--check", action="store_true", 
                       help="Check system configuration and generate recommendations")
    parser.add_argument("--apply-all", action="store_true", 
                       help="Apply all recommended security configurations")
    parser.add_argument("--configure-iptables", action="store_true", 
                       help="Configure iptables rules for DDoS protection")
    parser.add_argument("--configure-sysctl", action="store_true", 
                       help="Configure sysctl parameters for DDoS protection")
    parser.add_argument("--report", action="store_true", 
                       help="Generate a security report")
    parser.add_argument("--output", help="Output file for the security report")
    
    args = parser.parse_args()
    
    configurator = SecurityConfigurator()
    
    if args.check or not any([args.apply_all, args.configure_iptables, 
                              args.configure_sysctl, args.report]):
        recommendations = configurator.check_system()
        print(f"\nFound {len(recommendations)} recommendations:")
        for i, rec in enumerate(recommendations, 1):
            print(f"\n{i}. {rec['title']}")
            print(f"   Description: {rec['description']}")
            print(f"   Command: {rec['command']}")
            if 'permanent_command' in rec:
                print(f"   Permanent: {rec['permanent_command']}")
    
    if args.apply_all:
        recommendations = configurator.check_system()
        for rec in recommendations:
            configurator.apply_recommendation(rec)
    
    if args.configure_iptables:
        configurator.configure_iptables_rules()
    
    if args.configure_sysctl:
        configurator.configure_sysctl_params()
    
    if args.report:
        configurator.generate_report(args.output)

if __name__ == "__main__":
    main() 