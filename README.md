# DDoS Protection Tools

This directory contains various tools for DDoS detection, analysis, and mitigation.

## Tools Overview

1. **Traffic Analyzer** (`traffic_analyzer.py`): 
   - Monitors network traffic to detect potential DDoS attacks
   - Analyzes traffic patterns, connection rates, and packet characteristics
   - Outputs real-time alerts and statistics

2. **Rate Limiter** (`rate_limiter.py`):
   - Implements rate limiting to mitigate DDoS attacks
   - Filters packets based on source IP and rate thresholds
   - Can automatically blacklist offending IPs

3. **Web Monitor** (`web_monitor.py`):
   - Provides a web interface for monitoring network traffic 
   - Visualizes traffic patterns and potential attacks
   - Displays alerting and historical data

4. **Security Configuration** (`security_config.py`):
   - Configures system settings for DDoS protection
   - Implements firewall rules and network hardening
   - Generates security recommendations

5. **Test Generator** (`test_generator.py`):
   - Generates test traffic to evaluate defense mechanisms
   - Simulates various types of DDoS attacks
   - **For testing purposes only in controlled environments**

## Usage Examples

### Traffic Analyzer

```bash
# Monitor all interfaces
python traffic_analyzer.py

# Monitor a specific interface with custom threshold
python traffic_analyzer.py -i eth0 -t 200
```

### Rate Limiter

```bash
# Basic rate limiting
sudo python rate_limiter.py

# Limit traffic to a specific port with custom rate
sudo python rate_limiter.py -p 80 -r 50
```

### Web Monitor

```bash
# Start the web monitor on default port (5000)
python web_monitor.py

# Use a custom port
python web_monitor.py -p 8080
```

### Security Configuration

```bash
# Check system configuration and get recommendations
python security_config.py --check

# Apply all recommended configurations
sudo python security_config.py --apply-all

# Configure iptables rules
sudo python security_config.py --configure-iptables
```

### Test Generator (For authorized testing only)

```bash
# Generate SYN flood test traffic
python test_generator.py -t 127.0.0.1 -a syn -d 10

# Generate HTTP flood test traffic
python test_generator.py -t 127.0.0.1 -a http -p 8080 -d 30
```

## Warning

The test generator tool should **ONLY** be used in controlled environments with proper authorization. Using this tool against systems without explicit permission is illegal and unethical.

## Requirements

See the main `requirements.txt` file in the parent directory for the required Python packages. 