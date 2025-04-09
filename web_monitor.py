#!/usr/bin/env python3
"""
Web Monitor for DDoS Attacks

This tool provides a web interface for monitoring network traffic
and potential DDoS attacks in real-time.
"""

import argparse
import datetime
import json
import logging
import os
import subprocess
import threading
import time
from collections import defaultdict, deque

try:
    from flask import Flask, render_template, jsonify, request
except ImportError:
    print("Flask not installed. Please install with: pip install flask")
    exit(1)

try:
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend
    import matplotlib.pyplot as plt
    import numpy as np
    from matplotlib.dates import DateFormatter
    import io
    import base64
except ImportError:
    print("Matplotlib not installed. Please install with: pip install matplotlib")
    exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), 'templates'))

# Global data structures
traffic_data = {
    'timestamps': deque(maxlen=300),  # Store 5 minutes of data
    'packet_counts': deque(maxlen=300),
    'rates': deque(maxlen=300),
    'top_ips': defaultdict(int),
    'top_ports': defaultdict(int),
    'alerts': deque(maxlen=50),  # Store the last 50 alerts
    'status': 'Normal',
    'last_update': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
}

# Create templates directory if it doesn't exist
os.makedirs(os.path.join(os.path.dirname(__file__), 'templates'), exist_ok=True)

# Create the HTML template
@app.route('/')
def index():
    return render_template('index.html')

# Create the main index.html template
def create_template():
    template_path = os.path.join(os.path.dirname(__file__), 'templates', 'index.html')
    
    with open(template_path, 'w') as f:
        f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDoS Monitoring Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            padding-top: 20px;
            background-color: #f5f5f5;
        }
        .card {
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .alert-card {
            max-height: 300px;
            overflow-y: auto;
        }
        .status-normal { color: green; }
        .status-warning { color: orange; }
        .status-danger { color: red; }
        #traffic-chart {
            width: 100%;
            height: 300px;
        }
        .refresh-btn {
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="text-center mb-4">DDoS Monitoring Dashboard</h1>
        
        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5>Network Traffic</h5>
                        <button class="btn btn-sm btn-primary refresh-btn" onclick="refreshData()">Refresh</button>
                    </div>
                    <div class="card-body">
                        <img id="traffic-chart" src="/traffic-chart" alt="Traffic Chart">
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>System Status</h5>
                    </div>
                    <div class="card-body">
                        <p><strong>Current Status:</strong> <span id="status-indicator" class="status-normal">Normal</span></p>
                        <p><strong>Last Update:</strong> <span id="last-update"></span></p>
                        <p><strong>Current Rate:</strong> <span id="current-rate">0</span> packets/sec</p>
                        <p><strong>Total Packets:</strong> <span id="total-packets">0</span></p>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h5>Top Source IPs</h5>
                    </div>
                    <div class="card-body">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Packet Count</th>
                                </tr>
                            </thead>
                            <tbody id="top-ips">
                                <!-- Data will be filled dynamically -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Top Destination Ports</h5>
                    </div>
                    <div class="card-body">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Port</th>
                                    <th>Packet Count</th>
                                </tr>
                            </thead>
                            <tbody id="top-ports">
                                <!-- Data will be filled dynamically -->
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h5>Recent Alerts</h5>
                    </div>
                    <div class="card-body alert-card">
                        <div id="alerts">
                            <!-- Alerts will be filled dynamically -->
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Function to refresh data
        function refreshData() {
            fetch('/api/data')
                .then(response => response.json())
                .then(data => {
                    // Update status
                    const statusIndicator = document.getElementById('status-indicator');
                    statusIndicator.textContent = data.status;
                    statusIndicator.className = 'status-' + 
                        (data.status === 'Normal' ? 'normal' : 
                         data.status === 'Warning' ? 'warning' : 'danger');
                    
                    // Update other metrics
                    document.getElementById('last-update').textContent = data.last_update;
                    document.getElementById('current-rate').textContent = 
                        data.rates.length > 0 ? data.rates[data.rates.length - 1].toFixed(2) : '0';
                    document.getElementById('total-packets').textContent = 
                        data.packet_counts.reduce((a, b) => a + b, 0);
                    
                    // Update top IPs
                    const topIpsTable = document.getElementById('top-ips');
                    topIpsTable.innerHTML = '';
                    data.top_ips.forEach(ip => {
                        const row = document.createElement('tr');
                        row.innerHTML = `<td>${ip.ip}</td><td>${ip.count}</td>`;
                        topIpsTable.appendChild(row);
                    });
                    
                    // Update top ports
                    const topPortsTable = document.getElementById('top-ports');
                    topPortsTable.innerHTML = '';
                    data.top_ports.forEach(port => {
                        const row = document.createElement('tr');
                        row.innerHTML = `<td>${port.port}</td><td>${port.count}</td>`;
                        topPortsTable.appendChild(row);
                    });
                    
                    // Update alerts
                    const alertsDiv = document.getElementById('alerts');
                    alertsDiv.innerHTML = '';
                    data.alerts.forEach(alert => {
                        const alertElem = document.createElement('div');
                        alertElem.className = `alert alert-${alert.level === 'WARNING' ? 'warning' : 'danger'}`;
                        alertElem.textContent = `[${alert.timestamp}] ${alert.message}`;
                        alertsDiv.appendChild(alertElem);
                    });
                    
                    // Refresh the chart
                    document.getElementById('traffic-chart').src = '/traffic-chart?' + new Date().getTime();
                })
                .catch(error => console.error('Error fetching data:', error));
        }
        
        // Initial load and then refresh every 5 seconds
        refreshData();
        setInterval(refreshData, 5000);
    </script>
</body>
</html>""")
    
    logger.info(f"Created template file at {template_path}")

# API for fetching data
@app.route('/api/data')
def get_data():
    global traffic_data
    
    # Format data for JSON response
    response = {
        'status': traffic_data['status'],
        'last_update': traffic_data['last_update'],
        'timestamps': list(traffic_data['timestamps']),
        'packet_counts': list(traffic_data['packet_counts']),
        'rates': list(traffic_data['rates']),
        'top_ips': [{'ip': ip, 'count': count} for ip, count in sorted(traffic_data['top_ips'].items(), key=lambda x: x[1], reverse=True)[:10]],
        'top_ports': [{'port': port, 'count': count} for port, count in sorted(traffic_data['top_ports'].items(), key=lambda x: x[1], reverse=True)[:10]],
        'alerts': list(traffic_data['alerts'])
    }
    
    return jsonify(response)

# Generate traffic chart
@app.route('/traffic-chart')
def traffic_chart():
    plt.figure(figsize=(10, 5))
    
    # Convert timestamps to datetime objects
    timestamps = [datetime.datetime.strptime(ts, '%Y-%m-%d %H:%M:%S') for ts in traffic_data['timestamps']]
    
    if not timestamps:
        # Return empty plot if no data
        plt.title('No traffic data available')
        plt.xlabel('Time')
        plt.ylabel('Packets/sec')
        
        # Convert plot to a PNG image
        img = io.BytesIO()
        plt.savefig(img, format='png', bbox_inches='tight')
        img.seek(0)
        plt.close()
        
        return base64.b64encode(img.getvalue()).decode('utf8')
    
    # Plot packet rate
    plt.plot(timestamps, traffic_data['rates'], 'b-', label='Packet Rate')
    
    # Add warning threshold line
    if traffic_data['rates']:
        threshold = max(max(traffic_data['rates']) * 0.7, 100)  # 70% of max or at least 100
        plt.axhline(y=threshold, color='r', linestyle='--', label=f'Warning Threshold ({threshold:.0f} pkts/sec)')
    
    # Format the plot
    plt.title('Network Traffic Rate')
    plt.xlabel('Time')
    plt.ylabel('Packets/sec')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend()
    
    # Format x-axis to show time properly
    plt.gcf().autofmt_xdate()
    plt.gca().xaxis.set_major_formatter(DateFormatter('%H:%M:%S'))
    
    # Convert plot to a PNG image
    img = io.BytesIO()
    plt.savefig(img, format='png', bbox_inches='tight')
    img.seek(0)
    plt.close()
    
    response = app.make_response(img.getvalue())
    response.headers['Content-Type'] = 'image/png'
    return response

def capture_traffic():
    """
    Captures traffic data in the background using tcpdump or similar tools
    and updates the global traffic_data structure.
    """
    global traffic_data
    
    logger.info("Starting traffic monitoring")
    
    try:
        # Initialize counters
        last_count = 0
        last_time = time.time()
        packet_count = 0
        
        while True:
            # In a real implementation, this would use actual network monitoring
            # For demo purposes, we'll simulate traffic patterns
            current_time = time.time()
            elapsed = current_time - last_time
            
            # Add some randomness to the simulated traffic
            new_packets = int(np.random.poisson(50))  # Average 50 packets per interval
            
            # Occasionally simulate a traffic spike (potential DDoS)
            if np.random.random() < 0.02:  # 2% chance of a spike
                new_packets *= 10
                message = f"Unusual traffic spike detected: {new_packets} packets in {elapsed:.2f} seconds"
                traffic_data['alerts'].append({
                    'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'level': 'WARNING',
                    'message': message
                })
                traffic_data['status'] = 'Warning'
                logger.warning(message)
                
                # Simulate some attacking IPs during the spike
                attack_ips = [f"192.168.1.{np.random.randint(1, 255)}" for _ in range(3)]
                for ip in attack_ips:
                    traffic_data['top_ips'][ip] += new_packets // 3
                    
                # Add an alert for a suspected DDoS
                if new_packets > 500:
                    alert_msg = f"Possible DDoS attack detected from {', '.join(attack_ips)}"
                    traffic_data['alerts'].append({
                        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'level': 'DANGER',
                        'message': alert_msg
                    })
                    traffic_data['status'] = 'Alert'
                    logger.error(alert_msg)
            else:
                # Normal traffic distribution across IPs
                for _ in range(5):  # Distribute across 5 random IPs
                    ip = f"10.0.0.{np.random.randint(1, 255)}"
                    traffic_data['top_ips'][ip] += new_packets // 5
                
                # If previously in warning/alert state, check if we can return to normal
                if traffic_data['status'] != 'Normal' and np.random.random() < 0.3:  # 30% chance to return to normal
                    traffic_data['status'] = 'Normal'
                    traffic_data['alerts'].append({
                        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'level': 'WARNING',
                        'message': "Traffic returned to normal levels"
                    })
            
            # Update packet count
            packet_count += new_packets
            
            # Distribute traffic across common ports
            common_ports = [80, 443, 22, 25, 53]
            for port in common_ports:
                traffic_data['top_ports'][port] += int(new_packets * np.random.random() * 0.3)
            
            # Calculate rate
            rate = new_packets / elapsed if elapsed > 0 else 0
            
            # Update traffic data
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            traffic_data['timestamps'].append(timestamp)
            traffic_data['packet_counts'].append(new_packets)
            traffic_data['rates'].append(rate)
            traffic_data['last_update'] = timestamp
            
            # Update tracking variables
            last_count = packet_count
            last_time = current_time
            
            # Sleep for a bit
            time.sleep(1)
            
    except Exception as e:
        logger.error(f"Error in traffic capture thread: {e}")

def main():
    parser = argparse.ArgumentParser(description="Web Monitor for DDoS Detection")
    parser.add_argument("-p", "--port", type=int, default=5000, 
                        help="Port to run the web server on")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Run Flask in debug mode")
    
    args = parser.parse_args()
    
    # Create the template file if it doesn't exist
    create_template()
    
    # Start the traffic capture thread
    traffic_thread = threading.Thread(target=capture_traffic)
    traffic_thread.daemon = True  # Thread will exit when main program exits
    traffic_thread.start()
    
    logger.info(f"Starting web monitor on port {args.port}")
    logger.info(f"Open http://localhost:{args.port} in your browser to view the dashboard")
    
    # Start the Flask app
    app.run(host='0.0.0.0', port=args.port, debug=args.debug)

if __name__ == "__main__":
    main() 