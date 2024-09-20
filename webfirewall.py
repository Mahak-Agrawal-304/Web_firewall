from flask import Flask, request, abort, Response
import requests
import logging

app = Flask(__name__)

# List of known malicious IPs (you can expand this list)
blocked_ips = ['122.179.76.158', '203.0.113.15', '216.58.200.206',
'116.119.99.141','182.79.143.210','185.220.100.240','185.220.101.7','185.220.101.19','12.199.3.138','185.220.100.241','192.42.116.198','188.68.52.231','192.42.116.192','185.220.101.21','192.42.116.217','185.220.100.252','2a0b:f4c2:1::1','185.107.57.64','45.148.10.169','185.241.208.206','192.42.116.185','192.42.116.193','185.220.101.5','192.42.116.186','185.220.100.255','202.61.226.98','71.178.15.252','109.70.100.69','192.42.116.176','2.58.56.43','185.220.101.2','192.42.116.215','192.42.116.180','96.241.214.226','192.42.116.174','185.132.53.12','162.205.142.3','192.42.116.184','80.94.92.106','185.220.101.27','185.220.101.22','109.70.100.5','185.220.101.12','104.244.72.115','185.220.101.175','185.220.101.29','192.42.116.181','47.189.167.104','109.70.100.1','185.56.83.83','50.209.77.109','109.70.100.65','185.220.101.6','192.42.116.208','45.94.31.68','109.70.100.6','97.88.87.91','45.134.225.36','103.251.167.20','185.220.100.254','192.42.116.197','192.42.116.179','192.42.116.196','109.70.100.67','185.220.101.72','78.142.18.219','192.42.116.195','45.148.10.111','45.139.122.176','51.89.153.112','94.16.121.226','50.253.150.54','192.42.116.194','192.42.116.200','192.42.116.173','109.70.100.71','109.70.100.4','192.42.116.199','96.66.227.110','96.74.114.107','192.42.116.178','109.70.100.3','185.40.4.149','71.40.231.170','108.21.232.170','80.67.167.81','185.129.62.62','109.70.100.70','192.42.116.213','192.42.116.219','185.220.101.30','109.70.100.68','23.155.24.4','185.220.101.31','45.141.215.169','185.220.101.16','15.204.238.148','185.220.100.243','185.220.101.26','23.137.253.110','193.218.118.155','192.42.116.177','185.220.101.9','96.73.120.98','69.146.134.131','70.116.251.154','24.173.69.150','185.107.57.66','185.220.101.3','192.42.116.175','108.29.175.36','185.195.71.244','185.220.101.17','107.4.61.108','185.220.100.253','185.220.101.90','185.107.57.65','2.58.56.35','136.52.62.147','109.70.100.2','178.20.55.182']  # Example blocked IPs


# The protected website (your actual website hosted on Vercel)
protected_website = "https://portfolio-kappa-six-38.vercel.app"

# Set up logging to track blocked IPs
logging.basicConfig(filename='firewall.log', level=logging.INFO)

# Function to proxy the requests to the protected website
def proxy_request(path):
    url = f"{protected_website}{path}"
    print(f"Forwarding request to: {url}")
    response = requests.request(    
        method=request.method,
        url=url,
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False,  # Disable redirect handling in proxy
        verify=False  # Disable SSL verification for simplicity
    )
    print(f"Received response: {response.status_code}")
    return Response(response.content, response.status_code, response.headers.items())

# Middleware to block malicious IPs before forwarding the requests
@app.before_request
def block_malicious_ips():
    client_ip = request.remote_addr  # Get the IP of the client making the request
    print(f"Client IP: {client_ip}")

    if client_ip in blocked_ips:
        logging.info(f"Blocked request from {client_ip}")
        abort(403)  # Deny the request if the IP is in the blocked list

# Catch all routes and forward them to the protected website
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    logging.info(f"Request to {path}")
    return proxy_request(path)

# Run the firewall
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

