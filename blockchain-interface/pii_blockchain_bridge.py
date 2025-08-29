import asyncio
import hashlib
import json
import os
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import requests
import threading
from flask import Flask, request, jsonify
import sqlite3

class PIIBlockchainBridge:
    """
    Bridge service that captures PII data from script.py and sends to blockchain
    """
    
    def __init__(self, bridge_port: int = 5002):
        self.bridge_port = bridge_port
        self.app = Flask(__name__)
        self.setup_routes()
        
        # Configuration
        self.stacks_node_url = os.getenv("STACKS_NODE_URL", "http://localhost:3999")
        self.contract_address = os.getenv("CONTRACT_ADDRESS", "")
        self.contract_name = "pii-storage-system"
        
        # Local storage for pending transactions
        self.init_local_db()
        
        # Event callbacks for real-time updates
        self.event_callbacks = []
        
        print(f"🔗 PII Blockchain Bridge initialized on port {bridge_port}")
        print(f"📡 Stacks Node: {self.stacks_node_url}")
        print(f"📋 Contract: {self.contract_address}.{self.contract_name}")
    
    def init_local_db(self):
        """Initialize local database for tracking transactions"""
        conn = sqlite3.connect('pii_blockchain_bridge.db')
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pii_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_hash TEXT,
                safe_token TEXT UNIQUE,
                entity_type TEXT,
                confidence_score REAL,
                is_sensitive BOOLEAN,
                original_text_hash TEXT,
                blockchain_status TEXT DEFAULT 'pending',
                tx_id TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS document_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_hash TEXT UNIQUE,
                filename TEXT,
                total_pii_count INTEGER,
                sensitive_count INTEGER,
                processing_status TEXT DEFAULT 'processing',
                blockchain_tx_id TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
    
    def setup_routes(self):
        """Setup Flask routes for PII interception"""
        
        @self.app.route('/capture-pii', methods=['POST'])
        def capture_pii():
            """Endpoint to capture PII data from script.py processing"""
            try:
                data = request.get_json()
                
                # Extract data
                filename = data.get('filename', 'unknown')
                extracted_text = data.get('extracted_text', '')
                sensitive_data = data.get('sensitive_data', {})
                
                print(f"📋 Captured PII data for: {filename}")
                print(f"🔍 Found {len(sensitive_data)} PII entities")
                
                # Process and send to blockchain
                result = self.process_pii_data(filename, extracted_text, sensitive_data)
                
                return jsonify({
                    'status': 'success',
                    'message': 'PII data captured and processed',
                    'document_hash': result['document_hash'],
                    'pii_count': result['pii_count'],
                    'blockchain_status': result['blockchain_status']
                })
                
            except Exception as e:
                print(f"❌ Error capturing PII data: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/blockchain-status/<document_hash>')
        def get_blockchain_status(document_hash):
            """Get blockchain status for a document"""
            try:
                conn = sqlite3.connect('pii_blockchain_bridge.db')
                cursor = conn.cursor()
                
                # Get document session
                cursor.execute("""
                    SELECT * FROM document_sessions WHERE document_hash = ?
                """, (document_hash,))
                session = cursor.fetchone()
                
                # Get PII transactions
                cursor.execute("""
                    SELECT * FROM pii_transactions WHERE document_hash = ?
                """, (document_hash,))
                transactions = cursor.fetchall()
                
                conn.close()
                
                return jsonify({
                    'document_hash': document_hash,
                    'session': dict(zip([col[0] for col in cursor.description], session)) if session else None,
                    'pii_transactions': len(transactions),
                    'blockchain_confirmed': sum(1 for tx in transactions if tx[8] == 'confirmed')  # blockchain_status column
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/recent-pii')
        def get_recent_pii():
            """Get recent PII processing activity"""
            try:
                conn = sqlite3.connect('pii_blockchain_bridge.db')
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT 
                        p.document_hash,
                        p.entity_type,
                        p.confidence_score,
                        p.is_sensitive,
                        p.blockchain_status,
                        p.timestamp,
                        d.filename
                    FROM pii_transactions p
                    LEFT JOIN document_sessions d ON p.document_hash = d.document_hash
                    ORDER BY p.timestamp DESC
                    LIMIT 50
                """)
                
                results = []
                for row in cursor.fetchall():
                    results.append({
                        'document_hash': row[0],
                        'entity_type': row[1],
                        'confidence_score': row[2],
                        'is_sensitive': bool(row[3]),
                        'blockchain_status': row[4],
                        'timestamp': row[5],
                        'filename': row[6]
                    })
                
                conn.close()
                return jsonify(results)
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
    
    def process_pii_data(self, filename: str, extracted_text: str, sensitive_data: Dict) -> Dict:
        """Process PII data and prepare for blockchain storage"""
        
        # Generate document hash
        document_content = f"{filename}:{extracted_text}"
        document_hash = hashlib.sha256(document_content.encode()).hexdigest()
        
        # Store document session
        conn = sqlite3.connect('pii_blockchain_bridge.db')
        cursor = conn.cursor()
        
        pii_count = len(sensitive_data)
        sensitive_count = sum(1 for data in sensitive_data.values() 
                            if self.is_sensitive_entity(data.get('entity', '')))
        
        cursor.execute("""
            INSERT OR REPLACE INTO document_sessions 
            (document_hash, filename, total_pii_count, sensitive_count)
            VALUES (?, ?, ?, ?)
        """, (document_hash, filename, pii_count, sensitive_count))
        
        # Process each PII entity
        for original_text, pii_info in sensitive_data.items():
            safe_token = pii_info.get('safe_token', '')
            entity_type = pii_info.get('entity', '')
            confidence_score = pii_info.get('confidence_score', 0.0)
            is_sensitive = self.is_sensitive_entity(entity_type)
            
            # Hash the original text for privacy
            original_text_hash = hashlib.sha256(original_text.encode()).hexdigest()
            
            cursor.execute("""
                INSERT OR REPLACE INTO pii_transactions 
                (document_hash, safe_token, entity_type, confidence_score, 
                 is_sensitive, original_text_hash, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                document_hash, safe_token, entity_type, confidence_score,
                is_sensitive, original_text_hash, json.dumps({
                    'filename': filename,
                    'processing_timestamp': datetime.now().isoformat()
                })
            ))
        
        conn.commit()
        conn.close()
        
        # Prepare blockchain transaction (this would normally use Leather wallet)
        blockchain_status = "pending_wallet_signature"
        
        # Notify event callbacks
        self._notify_callbacks({
            'event': 'pii_processed',
            'document_hash': document_hash,
            'filename': filename,
            'pii_count': pii_count,
            'sensitive_count': sensitive_count,
            'timestamp': datetime.now().isoformat()
        })
        
        print(f"✅ Processed PII data for {filename}")
        print(f"   📄 Document Hash: {document_hash[:16]}...")
        print(f"   🔍 PII Entities: {pii_count} ({sensitive_count} sensitive)")
        
        return {
            'document_hash': document_hash,
            'pii_count': pii_count,
            'sensitive_count': sensitive_count,
            'blockchain_status': blockchain_status
        }
    
    def is_sensitive_entity(self, entity_type: str) -> bool:
        """Determine if an entity type is considered sensitive"""
        sensitive_types = {
            'PERSON', 'IN_PAN', 'IN_AADHAAR', 'IN_PHONE', 
            'IN_PHONE_WITHOUT_CODE', 'PHONE_NUMBER', 'EMAIL_ADDRESS',
            'CREDIT_CARD', 'SSN', 'PASSPORT'
        }
        return entity_type in sensitive_types
    
    def add_event_callback(self, callback):
        """Add callback for real-time events"""
        self.event_callbacks.append(callback)
    
    def _notify_callbacks(self, event_data: Dict):
        """Notify all event callbacks"""
        for callback in self.event_callbacks:
            try:
                callback(event_data)
            except Exception as e:
                print(f"❌ Callback error: {e}")
    
    def start_bridge_server(self):
        """Start the bridge server"""
        print(f"🚀 Starting PII Blockchain Bridge on port {self.bridge_port}")
        self.app.run(host='0.0.0.0', port=self.bridge_port, debug=False, threaded=True)

class PIIInterceptor:
    """
    Service that monitors script.py processing and sends data to blockchain bridge
    """
    
    def __init__(self, script_py_url: str = "http://localhost:5001", bridge_url: str = "http://localhost:5002"):
        self.script_py_url = script_py_url
        self.bridge_url = bridge_url
        
    def send_pii_to_blockchain(self, filename: str, extracted_text: str, sensitive_data: Dict):
        """Send PII data to blockchain bridge"""
        try:
            response = requests.post(f"{self.bridge_url}/capture-pii", json={
                'filename': filename,
                'extracted_text': extracted_text,
                'sensitive_data': sensitive_data
            }, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ PII sent to blockchain: {result['message']}")
                return result
            else:
                print(f"❌ Error sending PII to blockchain: {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Error connecting to blockchain bridge: {e}")
            return None

# Modified version of your script.py functions that integrate with blockchain
def enhanced_process_pdf_with_blockchain(pdf_path, output_pdf, filename, blur=False):
    """Enhanced version that sends PII data to blockchain"""
    from script import process_pdf, get_sensitive_data, store_sensitive_data_firestore
    
    # Process normally
    output_path, extracted_text = process_pdf(pdf_path, output_pdf, blur)
    sensitive_data = get_sensitive_data(extracted_text)
    
    # Store in Firebase (your existing flow)
    store_sensitive_data_firestore(sensitive_data)
    
    # Send to blockchain bridge
    interceptor = PIIInterceptor()
    blockchain_result = interceptor.send_pii_to_blockchain(filename, extracted_text, sensitive_data)
    
    return output_path, extracted_text, sensitive_data, blockchain_result

def enhanced_process_image_with_blockchain(image_path, output_image_path, filename, blur=False):
    """Enhanced version that sends PII data to blockchain"""
    from script import process_image, get_sensitive_data, store_sensitive_data_firestore
    
    # Process normally
    output_path, extracted_text = process_image(image_path, output_image_path, blur)
    sensitive_data = get_sensitive_data(extracted_text)
    
    # Store in Firebase (your existing flow)
    store_sensitive_data_firestore(sensitive_data)
    
    # Send to blockchain bridge
    interceptor = PIIInterceptor()
    blockchain_result = interceptor.send_pii_to_blockchain(filename, extracted_text, sensitive_data)
    
    return output_path, extracted_text, sensitive_data, blockchain_result

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "bridge":
        # Start the blockchain bridge server
        bridge = PIIBlockchainBridge()
        bridge.start_bridge_server()
    else:
        print("🔗 PII Blockchain Bridge")
        print("Usage:")
        print("  python pii_blockchain_bridge.py bridge    - Start bridge server")
        print("")
        print("Bridge will run on http://localhost:5002")
        print("Ready to receive PII data from script.py processing!")
