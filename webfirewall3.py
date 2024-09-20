from flask import Flask, request, abort, Response
from flask_cors import CORS
import requests
import ipaddress
import logging
import time
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

# List of blocked IPs and IP ranges
blocked_ips = set()
blocked_ip_ranges = set()

# Dictionary to keep track of IP request counts for time-based checks
ip_request_count = {}

# Threshold for requests in a minute before blocking
REQUEST_THRESHOLD = 100
TIME_WINDOW = timedelta(minutes=1)

# The external website to protect
protected_website = "https://portfolio-kappa-six-38.vercel.app"

# Set up logging for blocked requests
logging.basicConfig(filename='firewall.log', level=logging.INFO)

# Function to get /24 IP range
def get_ip_range(ip):
    ip_obj = ipaddress.ip_address(ip)
    network = ipaddress.ip_network(f"{ip_obj}/24", strict=False)
    return str(network)

# Middleware to block IPs and IP ranges
@app.before_request
def block_malicious_ips():
    client_ip = request.remote_addr  # Get the client's IP address
    current_time = datetime.now()

    # Check if the IP is already blocked
    if client_ip in blocked_ips:
        logging.info(f"Blocked request from {client_ip}")
        abort(403)  # Return 403 Forbidden
    
    # Check if the IP range is blocked
    client_ip_range = get_ip_range(client_ip)
    if client_ip_range in blocked_ip_ranges:
        logging.info(f"Blocked request from {client_ip} (range {client_ip_range})")
        abort(403)  # Return 403 Forbidden

    # Log the request
    logging.info(f"Request from {client_ip} at {current_time}")

    # Call the function to check IP rate limit
    check_ip_rate_limit(client_ip, current_time)

def check_ip_rate_limit(ip, current_time):
    # Clean up old entries beyond the time window
    if ip not in ip_request_count:
        ip_request_count[ip] = []

    # Add the current request time
    ip_request_count[ip].append(current_time)

    # Remove timestamps older than TIME_WINDOW
    ip_request_count[ip] = [req_time for req_time in ip_request_count[ip] if current_time - req_time <= TIME_WINDOW]

    # Block the IP if it exceeds the threshold within the time window
    if len(ip_request_count[ip]) > REQUEST_THRESHOLD:
        blocked_ips.add(ip)
        logging.info(f"Blocked IP {ip} after exceeding {REQUEST_THRESHOLD} requests in 1 minute")

# Function to proxy requests to the protected website
def proxy_request(path):
    url = f"{protected_website}{path}"
    print(f"Forwarding request to: {url}")
    response = requests.request(
        method=request.method,
        url=url,
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=True,
        verify=False  # Disable SSL certificate verification for now
    )
    print(f"Received response: {response.status_code}")
    return Response(response.content, response.status_code, response.headers.items())

# Route to proxy all traffic to the protected website
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    logging.info(f"Request to {path}")
    return proxy_request(path)

if __name__ == '__main__':
    app.run(debug=True, port=8080)