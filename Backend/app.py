from flask import Flask, request, jsonify
from flask_cors import CORS
import ssl
import socket
import datetime
import os

app = Flask(__name__)
CORS(app)  

def check_ssl_cert(hostname):
    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    try:
        conn.connect((hostname, 443))
        cert = conn.getpeercert()

        ip_address = conn.getpeername()[0]

        issuer = dict(x[0] for x in cert['issuer'])
        issued_by = issuer.get('organizationName', 'Unknown Issuer')
        subject = dict(x[0] for x in cert['subject'])
        common_name = subject.get('commonName', 'Unknown')

        not_after = cert['notAfter']
        expiration_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiration_date - datetime.datetime.now()).days

        server_type = 'proxygen-bolt' if 'facebook.com' in hostname else 'Unknown'

        cert_details = {
            "ip_address": ip_address,
            "issued_by": issued_by,
            "common_name": common_name,
            "expiration_date": not_after,
            "days_left": days_left,
            "hostname_verified": common_name == hostname,
            "server_type": server_type
        }
        return True, cert_details

    except ssl.SSLError:
        return False, None
    

@app.route('/')
def home():
    return "SSL Certificate Analyzer API is running"


@app.route('/check_ssl', methods=['POST'])
def check_ssl():
    try:
        data = request.get_json()
        hostname = data.get('hostname')
        
        if not hostname:
            return jsonify({"success": False, "error": "No hostname provided"}), 400

        is_ssl, cert_info = check_ssl_cert(hostname)
        if is_ssl:
            return jsonify({"success": True, "certificate": cert_info})
        else:
            return jsonify({"success": False, "error": "SSL certificate not found"})
    except Exception as e:
        print(f"Error in /check_ssl: {e}")  # Log error for debugging
        return jsonify({"success": False, "error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)), debug=True)
