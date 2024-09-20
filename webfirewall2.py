from flask import Flask, request, abort, Response
from flask_cors import CORS
import requests
import ipaddress
import logging

app = Flask(__name__)
CORS(app)

# Dictionary to keep track of IP range request counts
ip_range_counter = {}

# List of blocked IP ranges
blocked_ip_ranges = []

# Threshold for requests from the same range before blocking
REQUEST_THRESHOLD = 10

# The external website to protect
protected_website = "https://portfolio-kappa-six-38.vercel.app"

# Set up logging for blocked requests
logging.basicConfig(filename='firewall.log', level=logging.INFO)

# Function to get /24 IP range (change to /16 or other range sizes if needed)
def get_ip_range(ip):
    ip_obj = ipaddress.ip_address(ip)
    network = ipaddress.ip_network(f"{ip_obj}/24", strict=False)  # Adjust the prefix length as needed
    return str(network)

# Middleware to block IPs and IP ranges
@app.before_request
def block_malicious_ips():
    client_ip = request.remote_addr  # Get the client's IP address
    
    # Check if the IP falls within the blocked IP ranges
    client_ip_range = get_ip_range(client_ip)
    if client_ip_range in blocked_ip_ranges:
        logging.info(f"Blocked request from {client_ip} (range {client_ip_range})")
        abort(403)  # Return 403 Forbidden

    # If not blocked, increase the counter for this range
    if client_ip_range in ip_range_counter:
        ip_range_counter[client_ip_range] += 1
    else:
        ip_range_counter[client_ip_range] = 1

    # Check if the request count exceeds the threshold, if so block the range
    if ip_range_counter[client_ip_range] >= REQUEST_THRESHOLD:
        blocked_ip_ranges.append(client_ip_range)
        logging.info(f"Blocked entire range {client_ip_range} after {REQUEST_THRESHOLD} requests")

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
