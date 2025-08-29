#!/usr/bin/env python3
"""
PII Blockchain Integration Middleware
=====================================
This script runs alongside your script.py to capture PII data and send it to blockchain.
It monitors the process endpoint and automatically sends extracted PII to Clarity smart contract.
"""

import sqlite3
import threading
import time
import json
import requests
from datetime import datetime
import hashlib
from flask import Flask, request, jsonify
from flask_cors import CORS
import os

class PIIBlockchainBridge:
    def __init__(self):
        self.db_path = "pii_blockchain.db"
        self.blockchain_service_url = "http://localhost:5001"
        self.script_service_url = "http://localhost:5000"  # Your script.py Flask app
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for PII tracking"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS pii_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id TEXT UNIQUE,
            pii_hash TEXT,
            pii_data TEXT,
            blockchain_tx_id TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            blockchain_stored_at TIMESTAMP
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS pii_extracts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id TEXT,
            field_name TEXT,
            field_value TEXT,
            confidence REAL,
            extracted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (document_id) REFERENCES pii_transactions (document_id)
        )
        ''')
        
        conn.commit()
        conn.close()
        print("✅ PII Database initialized")

    def hash_pii_data(self, pii_data):
        """Create hash of PII data for blockchain storage"""
        data_string = json.dumps(pii_data, sort_keys=True)
        return hashlib.sha256(data_string.encode()).hexdigest()

    def store_pii_transaction(self, document_id, pii_data):
        """Store PII transaction in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        pii_hash = self.hash_pii_data(pii_data)
        pii_json = json.dumps(pii_data)
        
        try:
            cursor.execute('''
            INSERT OR REPLACE INTO pii_transactions 
            (document_id, pii_hash, pii_data, status) 
            VALUES (?, ?, ?, 'captured')
            ''', (document_id, pii_hash, pii_json))
            
            # Store individual PII fields
            for field_name, field_info in pii_data.items():
                if isinstance(field_info, dict) and 'value' in field_info:
                    cursor.execute('''
                    INSERT INTO pii_extracts 
                    (document_id, field_name, field_value, confidence) 
                    VALUES (?, ?, ?, ?)
                    ''', (document_id, field_name, field_info['value'], 
                          field_info.get('confidence', 0.0)))
            
            conn.commit()
            print(f"✅ Stored PII data for document: {document_id}")
            return True
            
        except Exception as e:
            print(f"❌ Error storing PII: {e}")
            return False
        finally:
            conn.close()

    def send_to_blockchain(self, document_id, pii_data):
        """Send PII data to blockchain via blockchain service"""
        try:
            payload = {
                'document_id': document_id,
                'pii_hash': self.hash_pii_data(pii_data),
                'pii_fields': list(pii_data.keys()),
                'timestamp': datetime.now().isoformat(),
                'field_count': len(pii_data)
            }
            
            response = requests.post(
                f"{self.blockchain_service_url}/store-pii",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                blockchain_tx_id = result.get('transaction_id')
                
                # Update database with blockchain transaction ID
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('''
                UPDATE pii_transactions 
                SET blockchain_tx_id = ?, status = 'blockchain_stored', 
                    blockchain_stored_at = CURRENT_TIMESTAMP 
                WHERE document_id = ?
                ''', (blockchain_tx_id, document_id))
                conn.commit()
                conn.close()
                
                print(f"✅ Sent to blockchain - TX: {blockchain_tx_id}")
                return blockchain_tx_id
            else:
                print(f"❌ Blockchain service error: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ Error sending to blockchain: {e}")
            return None

    def process_pii_data(self, document_id, pii_data):
        """Main method to process captured PII data"""
        print(f"\n🔍 Processing PII for document: {document_id}")
        print(f"📊 Fields extracted: {list(pii_data.keys())}")
        
        # Store locally
        if self.store_pii_transaction(document_id, pii_data):
            # Send to blockchain
            tx_id = self.send_to_blockchain(document_id, pii_data)
            if tx_id:
                print(f"✅ Complete: {document_id} -> Blockchain TX: {tx_id}")
                return True
        
        return False

# Flask app to capture PII data
app = Flask(__name__)
CORS(app)
bridge = PIIBlockchainBridge()

@app.route('/capture-pii', methods=['POST'])
def capture_pii():
    """Endpoint to receive PII data from script.py integration"""
    try:
        data = request.json
        document_id = data.get('document_id')
        pii_data = data.get('pii_data', {})
        
        if not document_id or not pii_data:
            return jsonify({'error': 'Missing document_id or pii_data'}), 400
        
        success = bridge.process_pii_data(document_id, pii_data)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'PII data captured and sent to blockchain',
                'document_id': document_id
            })
        else:
            return jsonify({
                'status': 'error', 
                'message': 'Failed to process PII data'
            }), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/pii-status/<document_id>')
def pii_status(document_id):
    """Check status of PII processing for a document"""
    conn = sqlite3.connect(bridge.db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT document_id, blockchain_tx_id, status, created_at, blockchain_stored_at
    FROM pii_transactions WHERE document_id = ?
    ''', (document_id,))
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return jsonify({
            'document_id': result[0],
            'blockchain_tx_id': result[1],
            'status': result[2],
            'created_at': result[3],
            'blockchain_stored_at': result[4]
        })
    else:
        return jsonify({'error': 'Document not found'}), 404

@app.route('/pii-dashboard')
def pii_dashboard():
    """Simple dashboard to view PII transactions"""
    conn = sqlite3.connect(bridge.db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT document_id, blockchain_tx_id, status, created_at, blockchain_stored_at
    FROM pii_transactions ORDER BY created_at DESC LIMIT 50
    ''')
    
    transactions = []
    for row in cursor.fetchall():
        transactions.append({
            'document_id': row[0],
            'blockchain_tx_id': row[1],
            'status': row[2],
            'created_at': row[3],
            'blockchain_stored_at': row[4]
        })
    
    conn.close()
    
    return jsonify({
        'transactions': transactions,
        'total_count': len(transactions)
    })

if __name__ == '__main__':
    print("🔗 PII Blockchain Integration Bridge")
    print("===================================")
    print("🔧 Starting PII capture service on port 5002...")
    print("📡 Monitoring for PII data from script.py")
    print("🏗️  Sending captured PII to blockchain")
    print("\n📋 Usage:")
    print("   POST /capture-pii - Capture PII data")
    print("   GET  /pii-status/<doc_id> - Check status")
    print("   GET  /pii-dashboard - View transactions")
    print("===================================")
    
    app.run(host='localhost', port=5002, debug=True)
