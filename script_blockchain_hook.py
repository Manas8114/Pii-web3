#!/usr/bin/env python3
"""
Script.py Blockchain Hook
========================
Simple integration to capture PII data from your script.py and send to blockchain.
Just import this file in your script.py and call send_to_blockchain() with your PII data.
"""

import requests
import json
from datetime import datetime
import threading

class BlockchainHook:
    def __init__(self):
        self.bridge_url = "http://localhost:5002"  # PII Bridge service
        self.enabled = True
        
    def send_to_blockchain_async(self, document_id, pii_data):
        """Send PII data to blockchain in background thread"""
        def _send():
            try:
                payload = {
                    'document_id': document_id,
                    'pii_data': pii_data,
                    'timestamp': datetime.now().isoformat()
                }
                
                response = requests.post(
                    f"{self.bridge_url}/capture-pii",
                    json=payload,
                    timeout=5  # Quick timeout so it doesn't block your script.py
                )
                
                if response.status_code == 200:
                    print(f"✅ PII sent to blockchain for: {document_id}")
                else:
                    print(f"⚠️  Blockchain bridge error: {response.status_code}")
                    
            except requests.exceptions.ConnectionError:
                print("⚠️  Blockchain bridge not running - PII not sent to blockchain")
            except Exception as e:
                print(f"⚠️  Error sending to blockchain: {e}")
        
        # Run in background thread so it doesn't slow down your script.py
        if self.enabled:
            thread = threading.Thread(target=_send)
            thread.daemon = True
            thread.start()
    
    def send_to_blockchain(self, document_id, pii_data):
        """Main method to send PII to blockchain"""
        if not pii_data:
            return
            
        print(f"📡 Sending PII to blockchain: {document_id}")
        self.send_to_blockchain_async(document_id, pii_data)

# Global instance
blockchain_hook = BlockchainHook()

def send_pii_to_blockchain(document_id, pii_data):
    """Simple function to call from your script.py"""
    blockchain_hook.send_to_blockchain(document_id, pii_data)

# Example of how to integrate with your script.py:
"""
# Add this import at the top of your script.py:
from script_blockchain_hook import send_pii_to_blockchain

# Then in your /process endpoint (around line 450 where you have the PII results):
# After you extract PII data and before returning the response, add:

if pii_results:  # Your extracted PII data
    document_id = f"doc_{int(time.time())}"  # Use your document ID
    send_pii_to_blockchain(document_id, pii_results)

# That's it! Your PII data will now go to blockchain automatically.
"""

if __name__ == '__main__':
    # Test the hook
    print("🧪 Testing blockchain hook...")
    test_pii = {
        "name": {"value": "John Doe", "confidence": 0.95},
        "email": {"value": "john@example.com", "confidence": 0.90},
        "phone": {"value": "+1-555-0123", "confidence": 0.85}
    }
    
    send_pii_to_blockchain("test_doc_001", test_pii)
    print("✅ Test sent to blockchain bridge")
