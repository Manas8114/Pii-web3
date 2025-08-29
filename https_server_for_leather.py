#!/usr/bin/env python3
"""
HTTPS Server for Leather Wallet Integration
===========================================
Serves the PII dashboard on https://localhost:7000 so Leather can connect securely.
"""

import http.server
import ssl
import socketserver
import os
from pathlib import Path

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Add CORS headers for API calls
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

def create_self_signed_cert():
    """Create a self-signed certificate for local HTTPS"""
    cert_file = 'localhost.pem'
    key_file = 'localhost-key.pem'
    
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print(f"✅ Using existing certificate: {cert_file}")
        return cert_file, key_file
    
    try:
        # Try to create self-signed certificate using openssl
        import subprocess
        print("🔐 Creating self-signed certificate...")
        
        cmd = [
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048', 
            '-keyout', key_file, '-out', cert_file, '-days', '365', 
            '-nodes', '-subj', '/CN=localhost'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"✅ Created certificate: {cert_file}")
            return cert_file, key_file
        else:
            print(f"❌ OpenSSL failed: {result.stderr}")
            
    except FileNotFoundError:
        print("❌ OpenSSL not found")
    
    # Fallback: create simple certificate with Python
    print("📝 Creating certificate with Python...")
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import datetime
        
        # Generate private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            name
        ).issuer_name(
            name
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
            ]),
            critical=False,
        ).sign(key, hashes.SHA256())
        
        # Write key
        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Write certificate
        with open(cert_file, "wb") as f:
            f.write(cert.to_pem())
        
        print(f"✅ Created certificate with Python: {cert_file}")
        return cert_file, key_file
        
    except ImportError:
        print("❌ cryptography package not installed")
        print("💡 Install with: pip install cryptography")
        return None, None

def start_https_server():
    """Start HTTPS server on port 7000"""
    port = 7000
    
    print("🔐 PII Blockchain Dashboard - HTTPS Server")
    print("=" * 50)
    
    # Check if dashboard file exists
    dashboard_file = "pii_dashboard_standalone.html"
    if not os.path.exists(dashboard_file):
        print(f"❌ Dashboard file not found: {dashboard_file}")
        print("💡 Make sure you're running this from the project directory")
        return
    
    print(f"📄 Serving dashboard: {dashboard_file}")
    
    # Create or find SSL certificate
    cert_file, key_file = create_self_signed_cert()
    
    if not cert_file or not key_file:
        print("❌ Could not create SSL certificate")
        print("💡 Try installing: pip install cryptography")
        print("💡 Or install OpenSSL and add it to PATH")
        return
    
    # Create HTTPS server
    try:
        with socketserver.TCPServer(("", port), MyHTTPRequestHandler) as httpd:
            # Wrap with SSL
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(cert_file, key_file)
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            
            print(f"🚀 HTTPS Server starting on port {port}...")
            print(f"🌐 Dashboard URL: https://localhost:{port}/{dashboard_file}")
            print()
            print("📋 Instructions:")
            print(f"1. Open: https://localhost:{port}/{dashboard_file}")
            print("2. Accept the self-signed certificate warning")
            print("3. Click 'Connect Wallet' to connect Leather")
            print("4. Your real transactions will appear!")
            print()
            print("⚠️  Browser Security Warning:")
            print("   Click 'Advanced' → 'Proceed to localhost (unsafe)'")
            print("   This is safe for local development")
            print()
            print("🛑 Press Ctrl+C to stop")
            print("=" * 50)
            
            httpd.serve_forever()
            
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")
    except Exception as e:
        print(f"❌ Server error: {e}")

if __name__ == '__main__':
    start_https_server()
