import json
import os
import sys
import hashlib
from datetime import datetime
from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_socketio import SocketIO, emit
import sqlite3
import requests

# Add parent directory to path to import our modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'blockchain-interface'))
from pii_blockchain_bridge import PIIBlockchainBridge
from stacks_client import TxMonitor, set_contract

app = Flask(__name__)
app.config['SECRET_KEY'] = 'pii_blockchain_dashboard_2025'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global instances
bridge = None
blockchain_monitor = None

class PIIDashboardNotifier:
    """WebSocket notifier for PII blockchain events"""
    
    def __init__(self, socketio):
        self.socketio = socketio
    
    def notify_pii_processed(self, event_data):
        """Notify clients when new PII is processed"""
        self.socketio.emit('pii_processed', {
            'event': 'pii_processed',
            'document_hash': event_data.get('document_hash'),
            'filename': event_data.get('filename'),
            'pii_count': event_data.get('pii_count'),
            'sensitive_count': event_data.get('sensitive_count'),
            'timestamp': event_data.get('timestamp')
        })
    
    def notify_blockchain_transaction(self, tx_data):
        """Notify clients of new blockchain transactions"""
        self.socketio.emit('blockchain_transaction', {
            'txid': tx_data['txid'],
            'status': tx_data.get('status'),
            'contract_id': tx_data.get('contract_id'),
            'events': tx_data.get('events', []),
            'timestamp': datetime.now().isoformat()
        })

notifier = PIIDashboardNotifier(socketio)

@app.route('/')
def dashboard():
    """Main PII blockchain dashboard"""
    return render_template('pii_dashboard.html')

@app.route('/leather-integration')
def leather_integration():
    """Leather wallet integration page"""
    return redirect(url_for('static', filename='leather_integration.html'))

@app.route('/api/pii/recent')
def get_recent_pii():
    """Get recent PII processing activity"""
    try:
        response = requests.get('http://localhost:5002/recent-pii', timeout=5)
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify([])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/pii/document/<document_hash>')
def get_document_pii(document_hash):
    """Get PII data for a specific document"""
    try:
        response = requests.get(f'http://localhost:5002/blockchain-status/{document_hash}', timeout=5)
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({'error': 'Document not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/pii/stats')
def get_pii_stats():
    """Get PII processing statistics"""
    try:
        # Get stats from bridge service
        response = requests.get('http://localhost:5002/recent-pii', timeout=5)
        if response.status_code == 200:
            pii_data = response.json()
            
            stats = {
                'total_pii_records': len(pii_data),
                'sensitive_records': sum(1 for item in pii_data if item.get('is_sensitive', False)),
                'blockchain_confirmed': sum(1 for item in pii_data if item.get('blockchain_status') == 'confirmed'),
                'recent_documents': len(set(item.get('document_hash') for item in pii_data)),
                'entity_types': {}
            }
            
            # Count entity types
            for item in pii_data:
                entity_type = item.get('entity_type', 'unknown')
                stats['entity_types'][entity_type] = stats['entity_types'].get(entity_type, 0) + 1
            
            return jsonify(stats)
        else:
            return jsonify({
                'total_pii_records': 0,
                'sensitive_records': 0,
                'blockchain_confirmed': 0,
                'recent_documents': 0,
                'entity_types': {}
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blockchain/start-monitoring')
def start_blockchain_monitoring():
    """Start monitoring blockchain for PII transactions"""
    global blockchain_monitor
    
    contract_address = request.args.get('address', '')
    contract_name = request.args.get('name', 'pii-storage-system')
    
    if not contract_address:
        return jsonify({'error': 'Contract address required'}), 400
    
    try:
        if blockchain_monitor:
            blockchain_monitor.stop()
        
        set_contract(contract_address, contract_name)
        blockchain_monitor = TxMonitor(poll_interval=3.0)
        blockchain_monitor.subscribe(notifier.notify_blockchain_transaction)
        blockchain_monitor.start()
        
        return jsonify({
            'status': 'started',
            'contract_address': contract_address,
            'contract_name': contract_name
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blockchain/stop-monitoring')
def stop_blockchain_monitoring():
    """Stop blockchain monitoring"""
    global blockchain_monitor
    
    if blockchain_monitor:
        blockchain_monitor.stop()
        blockchain_monitor = None
    
    return jsonify({'status': 'stopped'})

@app.route('/api/simulate-pii')
def simulate_pii_processing():
    """Simulate PII processing for demo purposes"""
    try:
        # Simulate processing a document
        filename = f"demo_document_{int(datetime.now().timestamp())}.pdf"
        extracted_text = "This is John Doe's PAN card number ABCDE1234F and phone 9876543210"
        
        # Simulate PII data extraction
        sample_pii = {
            "John Doe": {
                "entity": "PERSON",
                "safe_token": f"token_{hashlib.md5('John Doe'.encode()).hexdigest()[:8]}",
                "confidence_score": 0.95
            },
            "ABCDE1234F": {
                "entity": "IN_PAN", 
                "safe_token": f"token_{hashlib.md5('ABCDE1234F'.encode()).hexdigest()[:8]}",
                "confidence_score": 0.87
            },
            "9876543210": {
                "entity": "IN_PHONE",
                "safe_token": f"token_{hashlib.md5('9876543210'.encode()).hexdigest()[:8]}",
                "confidence_score": 0.92
            }
        }
        
        # Send to bridge
        response = requests.post('http://localhost:5002/capture-pii', json={
            'filename': filename,
            'extracted_text': extracted_text,
            'sensitive_data': sample_pii
        }, timeout=10)
        
        if response.status_code == 200:
            return jsonify({
                'status': 'success',
                'message': 'Demo PII data processed',
                'result': response.json()
            })
        else:
            return jsonify({'error': 'Failed to process demo data'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    print('Client connected to PII dashboard')
    emit('status', {'connected': True})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    print('Client disconnected from PII dashboard')

@socketio.on('request_pii_stats')
def handle_pii_stats_request():
    """Handle request for latest PII statistics"""
    try:
        response = requests.get('http://localhost:5002/recent-pii', timeout=5)
        if response.status_code == 200:
            pii_data = response.json()
            emit('pii_stats_update', {
                'total_records': len(pii_data),
                'recent_activity': pii_data[:10]  # Last 10 items
            })
    except Exception as e:
        emit('error', {'message': str(e)})

def init_services():
    """Initialize background services"""
    global bridge
    
    # Start PII bridge if not already running
    try:
        response = requests.get('http://localhost:5002/recent-pii', timeout=2)
        print("✅ PII Bridge service is already running")
    except:
        print("🚀 Starting PII Bridge service...")
        # In production, you'd start this as a separate process
        # For now, just indicate it should be started separately

if __name__ == '__main__':
    init_services()
    
    print("🚀 Starting PII Blockchain Dashboard...")
    print("📊 Dashboard available at: http://localhost:5005")
    print("🔗 Leather integration at: http://localhost:5005/leather-integration")
    print("")
    print("🔧 Required services:")
    print("   - PII Bridge: python blockchain-interface/pii_blockchain_bridge.py bridge")
    print("   - Your script.py: python Models/script.py (port 5001)")
    print("")
    print("💡 Use the simulate endpoint to test: http://localhost:5005/api/simulate-pii")
    
    socketio.run(app, host='0.0.0.0', port=5005, debug=True)
