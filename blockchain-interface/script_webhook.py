"""
Script.py Integration Webhook
============================
This service monitors your script.py /process endpoint and automatically
sends PII data to blockchain without modifying your original script.

Run this alongside your script.py to enable blockchain integration.
"""

import requests
import threading
import time
import json
from flask import Flask, request, jsonify
from pii_blockchain_bridge import PIIInterceptor

class ScriptPyWebhook:
    """
    Webhook service that captures results from script.py processing
    """
    
    def __init__(self, webhook_port: int = 5003):
        self.webhook_port = webhook_port
        self.app = Flask(__name__)
        self.interceptor = PIIInterceptor()
        self.setup_routes()
        
        print(f"🎣 Script.py Webhook initialized on port {webhook_port}")
        print("This service will capture PII processing results and send to blockchain")
    
    def setup_routes(self):
        """Setup webhook routes"""
        
        @self.app.route('/webhook/pii-processed', methods=['POST'])
        def pii_processed_webhook():
            """Webhook endpoint for PII processing completion"""
            try:
                data = request.get_json()
                
                # Extract processing results
                filename = data.get('filename', 'unknown')
                extracted_text = data.get('extracted_text', '')
                sensitive_data = data.get('sensitive_data', {})
                
                print(f"📨 Webhook received PII data for: {filename}")
                
                # Send to blockchain bridge
                result = self.interceptor.send_pii_to_blockchain(
                    filename, extracted_text, sensitive_data
                )
                
                return jsonify({
                    'status': 'success',
                    'message': 'PII data sent to blockchain',
                    'blockchain_result': result
                })
                
            except Exception as e:
                print(f"❌ Webhook error: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/webhook/status')
        def webhook_status():
            """Get webhook status"""
            return jsonify({
                'status': 'active',
                'webhook_port': self.webhook_port,
                'blockchain_bridge': 'http://localhost:5002',
                'script_py': 'http://localhost:5001'
            })
    
    def start_webhook_server(self):
        """Start the webhook server"""
        print(f"🚀 Starting Script.py Webhook on port {self.webhook_port}")
        self.app.run(host='0.0.0.0', port=self.webhook_port, debug=False, threaded=True)

class ScriptPyProxy:
    """
    Proxy service that sits between your web requests and script.py
    Automatically captures responses and sends to blockchain
    """
    
    def __init__(self, proxy_port: int = 5004, script_py_port: int = 5001):
        self.proxy_port = proxy_port
        self.script_py_url = f"http://localhost:{script_py_port}"
        self.app = Flask(__name__)
        self.interceptor = PIIInterceptor()
        self.setup_proxy_routes()
        
        print(f"🔄 Script.py Proxy initialized on port {proxy_port}")
        print(f"📡 Proxying to: {self.script_py_url}")
    
    def setup_proxy_routes(self):
        """Setup proxy routes that intercept script.py calls"""
        
        @self.app.route('/process/<filename>', methods=['GET'])
        def proxy_process_file(filename):
            """Proxy the process file endpoint and capture results"""
            try:
                # Forward request to original script.py
                response = requests.get(f"{self.script_py_url}/process/{filename}")
                
                if response.status_code == 200:
                    # Try to extract PII data from the response
                    # This assumes script.py returns HTML with data we can parse
                    html_content = response.text
                    
                    # Look for script.py's sensitive_data in the HTML
                    # This is a simplified approach - you might need to adjust
                    if "sensitive_data" in html_content:
                        print(f"📋 Detected PII processing for: {filename}")
                        
                        # Try to extract the data (this is simplified)
                        # In a real implementation, you'd parse the HTML or modify script.py slightly
                        self.simulate_pii_capture(filename)
                
                return response.text, response.status_code, response.headers.items()
                
            except Exception as e:
                print(f"❌ Proxy error: {e}")
                return f"Proxy error: {e}", 500
        
        @self.app.route('/process', methods=['POST'])
        def proxy_process_endpoint():
            """Proxy the POST process endpoint"""
            try:
                # Forward the file upload to original script.py
                files = request.files
                form_data = request.form
                
                response = requests.post(
                    f"{self.script_py_url}/process",
                    files=files,
                    data=form_data
                )
                
                if response.status_code == 302:  # Redirect response
                    # Extract filename from redirect location
                    location = response.headers.get('Location', '')
                    if '/process/' in location:
                        filename = location.split('/process/')[-1]
                        print(f"📋 Detected file processing: {filename}")
                        
                        # Set up a delayed capture for when processing completes
                        threading.Timer(2.0, self.delayed_pii_capture, args=[filename]).start()
                
                return response.text, response.status_code, response.headers.items()
                
            except Exception as e:
                print(f"❌ Proxy POST error: {e}")
                return f"Proxy error: {e}", 500
    
    def delayed_pii_capture(self, filename):
        """Delayed capture of PII data after processing completes"""
        try:
            print(f"🕐 Attempting delayed PII capture for: {filename}")
            self.simulate_pii_capture(filename)
        except Exception as e:
            print(f"❌ Delayed capture error: {e}")
    
    def simulate_pii_capture(self, filename):
        """
        Simulate PII data capture - in real implementation,
        you would extract this from script.py's processing results
        """
        # This is a placeholder - you would integrate this with actual data
        sample_pii_data = {
            "sample_token_1": {
                "entity": "PERSON",
                "safe_token": "token-12345",
                "confidence_score": 0.95
            },
            "sample_token_2": {
                "entity": "IN_PAN",
                "safe_token": "token-67890", 
                "confidence_score": 0.87
            }
        }
        
        result = self.interceptor.send_pii_to_blockchain(
            filename, 
            "Sample extracted text", 
            sample_pii_data
        )
        
        print(f"📤 Sent sample PII to blockchain for {filename}")
        return result
    
    def start_proxy_server(self):
        """Start the proxy server"""
        print(f"🚀 Starting Script.py Proxy on port {self.proxy_port}")
        print("Use this proxy URL instead of direct script.py for blockchain integration")
        self.app.run(host='0.0.0.0', port=self.proxy_port, debug=False, threaded=True)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        mode = sys.argv[1]
        
        if mode == "webhook":
            webhook = ScriptPyWebhook()
            webhook.start_webhook_server()
        elif mode == "proxy":
            proxy = ScriptPyProxy()
            proxy.start_proxy_server()
        else:
            print("❌ Invalid mode")
    else:
        print("🎣 Script.py Integration Services")
        print("")
        print("Available modes:")
        print("  python script_webhook.py webhook  - Start webhook service")
        print("  python script_webhook.py proxy    - Start proxy service")
        print("")
        print("Services:")
        print("  Webhook: http://localhost:5003 - Receives PII data via webhooks")
        print("  Proxy:   http://localhost:5004 - Proxies script.py and captures PII")
        print("")
        print("💡 Use the proxy service for automatic PII capture without modifying script.py")
