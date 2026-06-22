import os
import sys
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

# Add parent directory to path to import our modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'blockchain-interface'))
from transaction_monitor import RealTimeMonitor, TransactionStorage

app = Flask(__name__)
app.config['SECRET_KEY'] = 'blockchain_dashboard_secret_2025'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global monitor instance
monitor = None
storage = TransactionStorage()

class WebSocketNotifier:
    """Notify web clients of new transactions via WebSocket"""
    
    def __init__(self, socketio):
        self.socketio = socketio
    
    def notify_new_transaction(self, tx_data):
        """Emit new transaction to all connected clients"""
        self.socketio.emit('new_transaction', {
            'txid': tx_data['txid'],
            'status': tx_data.get('status', 'unknown'),
            'block_height': tx_data.get('block_height', 'pending'),
            'contract_id': tx_data.get('contract_id', ''),
            'events_count': len(tx_data.get('events', [])),
            'timestamp': datetime.now().isoformat(),
            'events': tx_data.get('events', [])
        })

notifier = WebSocketNotifier(socketio)

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/transactions')
def get_transactions():
    """API endpoint to get recent transactions"""
    limit = request.args.get('limit', 50, type=int)
    transactions = storage.get_recent_transactions(limit)
    return jsonify(transactions)

@app.route('/api/stats')
def get_stats():
    """API endpoint to get transaction statistics"""
    stats = storage.get_stats()
    return jsonify(stats)

@app.route('/api/monitor/start')
def start_monitoring():
    """Start blockchain monitoring"""
    global monitor
    
    contract_address = request.args.get('address', '')
    contract_name = request.args.get('name', 'tokenization-system')
    
    if monitor:
        monitor.stop_monitoring()
    
    monitor = RealTimeMonitor(contract_address, contract_name)
    monitor.add_event_callback(notifier.notify_new_transaction)
    monitor.start_monitoring()
    
    return jsonify({
        'status': 'started',
        'contract_address': contract_address,
        'contract_name': contract_name
    })

@app.route('/api/monitor/stop')
def stop_monitoring():
    """Stop blockchain monitoring"""
    global monitor
    
    if monitor:
        monitor.stop_monitoring()
        monitor = None
    
    return jsonify({'status': 'stopped'})

@app.route('/api/monitor/status')
def monitor_status():
    """Get monitoring status"""
    return jsonify({
        'active': monitor is not None,
        'contract_configured': bool(monitor and hasattr(monitor, 'storage'))
    })

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    print('Client connected to dashboard')
    emit('status', {'connected': True})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    print('Client disconnected from dashboard')

@socketio.on('request_stats')
def handle_stats_request():
    """Handle request for latest statistics"""
    stats = storage.get_stats()
    emit('stats_update', stats)

if __name__ == '__main__':
    # Create sample data for testing
    if '--sample-data' in sys.argv:
        from transaction_monitor import create_sample_data
        create_sample_data()
        print("✅ Sample data created")
    
    print("🚀 Starting Blockchain Dashboard...")
    print("📊 Dashboard will be available at: http://localhost:5000")
    print("🔗 API endpoints:")
    print("   GET /api/transactions - Recent transactions")
    print("   GET /api/stats - Transaction statistics")
    print("   GET /api/monitor/start?address=<addr>&name=<name> - Start monitoring")
    print("   GET /api/monitor/stop - Stop monitoring")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
