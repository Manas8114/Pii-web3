import json
import sqlite3
import time
from typing import Dict, Any, List
from stacks_client import TxMonitor, set_contract

class TransactionStorage:
    """Store transaction data locally for real-time dashboard"""
    
    def __init__(self, db_path: str = "blockchain_transactions.db"):
        self.db_path = db_path
        self.init_db()
        
    def init_db(self):
        """Initialize SQLite database for storing transactions"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    txid TEXT UNIQUE NOT NULL,
                    status TEXT,
                    block_height INTEGER,
                    contract_id TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    events_count INTEGER,
                    raw_data TEXT,
                    parsed_events TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS contract_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    txid TEXT,
                    event_type TEXT,
                    event_data TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (txid) REFERENCES transactions (txid)
                )
            """)
            
            conn.commit()
        
    def store_transaction(self, tx_data: Dict[str, Any]):
        """Store a new transaction with its events"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Insert transaction
                cursor.execute("""
                    INSERT OR REPLACE INTO transactions 
                    (txid, status, block_height, contract_id, events_count, raw_data, parsed_events)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    tx_data['txid'],
                    tx_data.get('status'),
                    tx_data.get('block_height'),
                    tx_data.get('contract_id'),
                    len(tx_data.get('events', [])),
                    json.dumps(tx_data.get('raw', {})),
                    json.dumps(tx_data.get('events', []))
                ))
                
                # Insert events
                for event in tx_data.get('events', []):
                    cursor.execute("""
                        INSERT INTO contract_events (txid, event_type, event_data)
                        VALUES (?, ?, ?)
                    """, (
                        tx_data['txid'],
                        event.get('type'),
                        json.dumps(event.get('data', {}))
                    ))
                
                conn.commit()
                print(f"✅ Stored transaction: {tx_data['txid']}")
                
        except sqlite3.IntegrityError:
            print(f"⚠️  Transaction already exists: {tx_data['txid']}")
        except Exception as e:
            print(f"❌ Error storing transaction: {e}")
    
    def get_recent_transactions(self, limit: int = 50) -> List[Dict]:
        """Get recent transactions for dashboard"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT txid, status, block_height, contract_id, timestamp, events_count, parsed_events
                FROM transactions 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    'txid': row[0],
                    'status': row[1],
                    'block_height': row[2],
                    'contract_id': row[3],
                    'timestamp': row[4],
                    'events_count': row[5],
                    'events': json.loads(row[6]) if row[6] else []
                })
            
            return results
    
    def get_stats(self) -> Dict:
        """Get transaction statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Total transactions
            cursor.execute("SELECT COUNT(*) FROM transactions")
            total_txs = cursor.fetchone()[0]
            
            # Success transactions
            cursor.execute("SELECT COUNT(*) FROM transactions WHERE status = 'success'")
            success_txs = cursor.fetchone()[0]
            
            # Recent transactions (last hour)
            cursor.execute("""
                SELECT COUNT(*) FROM transactions 
                WHERE timestamp > datetime('now', '-1 hour')
            """)
            recent_txs = cursor.fetchone()[0]
            
            return {
            'total_transactions': total_txs,
            'successful_transactions': success_txs,
            'recent_transactions': recent_txs,
            'success_rate': (success_txs / total_txs * 100) if total_txs > 0 else 0
        }

class RealTimeMonitor:
    """Real-time blockchain transaction monitor"""
    
    def __init__(self, contract_address: str = "", contract_name: str = "tokenization-system"):
        self.storage = TransactionStorage()
        self.monitor = TxMonitor(poll_interval=2.0)  # Poll every 2 seconds
        self.event_callbacks = []
        
        if contract_address:
            set_contract(contract_address, contract_name)
        
        # Set up monitoring
        self.monitor.subscribe(self._on_new_transaction)
        
    def add_event_callback(self, callback):
        """Add callback for real-time events"""
        self.event_callbacks.append(callback)
        
    def _on_new_transaction(self, tx_data: Dict[str, Any]):
        """Handle new transaction from monitor"""
        print(f"🔄 Processing new transaction: {tx_data['txid']}")
        
        # Store in database
        self.storage.store_transaction(tx_data)
        
        # Notify callbacks (for real-time updates)
        for callback in self.event_callbacks:
            try:
                callback(tx_data)
            except Exception as e:
                print(f"❌ Callback error: {e}")
        
        # Print transaction details
        self._print_transaction_details(tx_data)
    
    def _print_transaction_details(self, tx_data: Dict[str, Any]):
        """Pretty print transaction details"""
        print("\n🌟 NEW BLOCKCHAIN TRANSACTION")
        print(f"   TX ID: {tx_data['txid']}")
        print(f"   Status: {tx_data.get('status', 'unknown')}")
        print(f"   Block: {tx_data.get('block_height', 'pending')}")
        print(f"   Contract: {tx_data.get('contract_id', 'N/A')}")
        print(f"   Events: {len(tx_data.get('events', []))}")
        
        for i, event in enumerate(tx_data.get('events', []), 1):
            print(f"     Event {i}: {event.get('type', 'unknown')}")
            if 'data' in event:
                data = event['data']
                if isinstance(data, dict):
                    for key, value in data.items():
                        print(f"       {key}: {value}")
        print("-" * 60)
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        print("🚀 Starting real-time blockchain monitoring...")
        self.monitor.start()
        
    def stop_monitoring(self):
        """Stop monitoring"""
        print("⏹️  Stopping blockchain monitoring...")
        self.monitor.stop()
    
    def get_recent_transactions(self, limit: int = 20):
        """Get recent transactions for dashboard"""
        return self.storage.get_recent_transactions(limit)
    
    def get_statistics(self):
        """Get monitoring statistics"""
        return self.storage.get_stats()

def create_sample_data():
    """Create sample transaction data for testing"""
    storage = TransactionStorage()
    
    sample_transactions = [
        {
            'txid': 'sample_tx_001',
            'status': 'success',
            'block_height': 1000,
            'contract_id': 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.tokenization-system',
            'events': [
                {
                    'type': 'print_event',
                    'data': {
                        'event': 'token-created',
                        'token-id': 1,
                        'name': 'TestToken',
                        'symbol': 'TT',
                        'creator': 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM'
                    }
                }
            ]
        },
        {
            'txid': 'sample_tx_002',
            'status': 'success',
            'block_height': 1001,
            'contract_id': 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.tokenization-system',
            'events': [
                {
                    'type': 'print_event',
                    'data': {
                        'event': 'transaction',
                        'tx-id': 1,
                        'from': 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM',
                        'to': 'ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG',
                        'amount': 100,
                        'token-id': 1
                    }
                }
            ]
        }
    ]
    
    for tx in sample_transactions:
        storage.store_transaction(tx)
    
    print("✅ Sample data created successfully!")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Real-time blockchain transaction monitor")
    parser.add_argument("--contract-address", help="Smart contract address")
    parser.add_argument("--contract-name", default="tokenization-system", help="Contract name")
    parser.add_argument("--sample-data", action="store_true", help="Create sample data")
    
    args = parser.parse_args()
    
    if args.sample_data:
        create_sample_data()
        exit(0)
    
    # Initialize monitor
    monitor = RealTimeMonitor(
        contract_address=args.contract_address or "",
        contract_name=args.contract_name
    )
    
    # Start monitoring
    monitor.start_monitoring()
    
    try:
        print("📊 Real-time monitoring active. Press Ctrl+C to stop...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop_monitoring()
        print("\n✅ Monitoring stopped.")
