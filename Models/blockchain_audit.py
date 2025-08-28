"""
Blockchain Audit Integration for SecuredDoc
Handles document registration and audit trail on Stacks blockchain
"""

import hashlib
import json
import requests
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
import time
import os

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BlockchainAuditManager:
    """Manages blockchain audit operations for document processing"""
    
    def __init__(self, network="testnet"):
        self.network = network
        self.api_base = "https://stacks-node-api.testnet.stacks.co" if network == "testnet" else "https://stacks-node-api.mainnet.stacks.co"
        self.fallback_log_file = "blockchain_audit_fallback.log"
        self.metadata_log_file = "blockchain_metadata_fallback.log"
        
        # Service fees (in microSTX)
        self.service_fees = {
            "registration": {"amount": 1000000, "display": "1.0 STX"},  # 1 STX
            "verification": {"amount": 500000, "display": "0.5 STX"},   # 0.5 STX
            "access": {"amount": 250000, "display": "0.25 STX"},        # 0.25 STX
            "premium_storage": {"amount": 2000000, "display": "2.0 STX"} # 2 STX
        }
    
    def generate_document_hash(self, file_content: bytes, metadata: Dict[str, Any]) -> str:
        """Generate SHA-256 hash of document content and metadata"""
        try:
            # Combine file content with metadata for comprehensive hash
            metadata_str = json.dumps(metadata, sort_keys=True)
            combined_content = file_content + metadata_str.encode('utf-8')
            
            hash_obj = hashlib.sha256()
            hash_obj.update(combined_content)
            document_hash = hash_obj.hexdigest()
            
            logger.info(f"Generated document hash: {document_hash[:16]}...")
            return document_hash
            
        except Exception as e:
            logger.error(f"Error generating document hash: {str(e)}")
            raise
    
    def get_service_fees(self) -> Dict[str, Any]:
        """Get current service fees from blockchain or return cached values"""
        try:
            # In a real implementation, this would query the smart contract
            # For now, return predefined fees
            return {
                "success": True,
                "fees": self.service_fees,
                "network": self.network,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error fetching service fees: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "fees": self.service_fees  # Return default fees as fallback
            }
    
    def register_document(self, document_hash: str, metadata: Dict[str, Any], 
                         wallet_address: str = None) -> Dict[str, Any]:
        """Register document on blockchain"""
        try:
            # Prepare registration data
            registration_data = {
                "document_hash": document_hash,
                "timestamp": datetime.now().isoformat(),
                "metadata": metadata,
                "wallet_address": wallet_address,
                "network": self.network,
                "service_type": "registration"
            }
            
            # In a real implementation, this would interact with Stacks blockchain
            # For now, simulate blockchain registration
            tx_hash = self._simulate_blockchain_transaction(registration_data)
            
            # Log to fallback file
            self._log_to_fallback(registration_data, tx_hash)
            
            return {
                "success": True,
                "transaction_hash": tx_hash,
                "document_hash": document_hash,
                "block_height": self._get_simulated_block_height(),
                "cost": self.service_fees["registration"]["display"],
                "network": self.network,
                "timestamp": registration_data["timestamp"]
            }
            
        except Exception as e:
            logger.error(f"Error registering document on blockchain: {str(e)}")
            # Still log to fallback even on error
            try:
                self._log_to_fallback({
                    "error": str(e),
                    "document_hash": document_hash,
                    "timestamp": datetime.now().isoformat()
                }, "error")
            except:
                pass
                
            return {
                "success": False,
                "error": str(e),
                "document_hash": document_hash
            }
    
    def verify_document(self, document_hash: str) -> Dict[str, Any]:
        """Verify document exists on blockchain"""
        try:
            # In a real implementation, this would query the blockchain
            # For now, check fallback log
            verification_result = self._check_fallback_log(document_hash)
            
            if verification_result:
                return {
                    "success": True,
                    "verified": True,
                    "document_hash": document_hash,
                    "registration_data": verification_result,
                    "network": self.network
                }
            else:
                return {
                    "success": True,
                    "verified": False,
                    "document_hash": document_hash,
                    "message": "Document not found on blockchain"
                }
                
        except Exception as e:
            logger.error(f"Error verifying document: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "document_hash": document_hash
            }
    
    def create_audit_trail(self, document_hash: str, processing_steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create audit trail for document processing"""
        try:
            audit_data = {
                "document_hash": document_hash,
                "processing_steps": processing_steps,
                "timestamp": datetime.now().isoformat(),
                "network": self.network,
                "service_type": "audit_trail"
            }
            
            # Simulate blockchain audit trail creation
            tx_hash = self._simulate_blockchain_transaction(audit_data)
            
            # Log audit trail
            self._log_audit_trail(audit_data, tx_hash)
            
            return {
                "success": True,
                "transaction_hash": tx_hash,
                "document_hash": document_hash,
                "audit_steps": len(processing_steps),
                "cost": self.service_fees["verification"]["display"],
                "timestamp": audit_data["timestamp"]
            }
            
        except Exception as e:
            logger.error(f"Error creating audit trail: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "document_hash": document_hash
            }
    
    def grant_access(self, document_hash: str, recipient_address: str, 
                    permissions: List[str]) -> Dict[str, Any]:
        """Grant access to document for specific address"""
        try:
            access_data = {
                "document_hash": document_hash,
                "recipient_address": recipient_address,
                "permissions": permissions,
                "timestamp": datetime.now().isoformat(),
                "service_type": "access_grant"
            }
            
            tx_hash = self._simulate_blockchain_transaction(access_data)
            
            return {
                "success": True,
                "transaction_hash": tx_hash,
                "document_hash": document_hash,
                "recipient": recipient_address,
                "permissions": permissions,
                "cost": self.service_fees["access"]["display"]
            }
            
        except Exception as e:
            logger.error(f"Error granting access: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "document_hash": document_hash
            }
    
    def get_document_history(self, document_hash: str) -> Dict[str, Any]:
        """Get complete history of document from blockchain"""
        try:
            # Check fallback logs for document history
            history = self._get_document_history_from_logs(document_hash)
            
            return {
                "success": True,
                "document_hash": document_hash,
                "history": history,
                "total_entries": len(history)
            }
            
        except Exception as e:
            logger.error(f"Error getting document history: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "document_hash": document_hash
            }
    
    def _simulate_blockchain_transaction(self, data: Dict[str, Any]) -> str:
        """Simulate blockchain transaction and return mock transaction hash"""
        # Create a deterministic but unique transaction hash
        tx_data = json.dumps(data, sort_keys=True)
        tx_hash = hashlib.sha256(tx_data.encode()).hexdigest()
        
        # Add some randomness for realism
        import random
        random.seed(int(time.time()))
        tx_hash = tx_hash[:56] + f"{random.randint(1000, 9999):04x}"
        
        logger.info(f"Simulated blockchain transaction: {tx_hash[:16]}...")
        return f"0x{tx_hash}"
    
    def _get_simulated_block_height(self) -> int:
        """Get simulated block height"""
        # Return a realistic block height based on time
        base_height = 150000  # Approximate testnet height
        time_offset = int((datetime.now().timestamp() - 1640995200) / 600)  # ~10 minute blocks
        return base_height + time_offset
    
    def _log_to_fallback(self, data: Dict[str, Any], tx_hash: str):
        """Log transaction to fallback file"""
        try:
            log_entry = {
                "transaction_hash": tx_hash,
                "data": data,
                "logged_at": datetime.now().isoformat()
            }
            
            # Ensure the directory exists
            os.makedirs(os.path.dirname(self.fallback_log_file) if os.path.dirname(self.fallback_log_file) else ".", exist_ok=True)
            
            with open(self.fallback_log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
                
        except Exception as e:
            logger.error(f"Error writing to fallback log: {str(e)}")
    
    def _log_audit_trail(self, data: Dict[str, Any], tx_hash: str):
        """Log audit trail to metadata file"""
        try:
            metadata_entry = {
                "transaction_hash": tx_hash,
                "audit_data": data,
                "logged_at": datetime.now().isoformat()
            }
            
            # Ensure the directory exists
            os.makedirs(os.path.dirname(self.metadata_log_file) if os.path.dirname(self.metadata_log_file) else ".", exist_ok=True)
            
            with open(self.metadata_log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(metadata_entry) + "\n")
                
        except Exception as e:
            logger.error(f"Error writing to metadata log: {str(e)}")
    
    def _check_fallback_log(self, document_hash: str) -> Optional[Dict[str, Any]]:
        """Check fallback log for document"""
        try:
            if not os.path.exists(self.fallback_log_file):
                return None
                
            with open(self.fallback_log_file, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        if entry.get("data", {}).get("document_hash") == document_hash:
                            return entry
                    except json.JSONDecodeError:
                        continue
            return None
            
        except Exception as e:
            logger.error(f"Error checking fallback log: {str(e)}")
            return None
    
    def _get_document_history_from_logs(self, document_hash: str) -> List[Dict[str, Any]]:
        """Get document history from log files"""
        history = []
        
        try:
            # Check main fallback log
            if os.path.exists(self.fallback_log_file):
                with open(self.fallback_log_file, "r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            if entry.get("data", {}).get("document_hash") == document_hash:
                                history.append({
                                    "type": "registration",
                                    "transaction_hash": entry.get("transaction_hash"),
                                    "timestamp": entry.get("data", {}).get("timestamp"),
                                    "details": entry.get("data", {})
                                })
                        except json.JSONDecodeError:
                            continue
            
            # Check metadata log
            if os.path.exists(self.metadata_log_file):
                with open(self.metadata_log_file, "r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            if entry.get("audit_data", {}).get("document_hash") == document_hash:
                                history.append({
                                    "type": "audit_trail",
                                    "transaction_hash": entry.get("transaction_hash"),
                                    "timestamp": entry.get("audit_data", {}).get("timestamp"),
                                    "details": entry.get("audit_data", {})
                                })
                        except json.JSONDecodeError:
                            continue
            
            # Sort by timestamp
            history.sort(key=lambda x: x.get("timestamp", ""))
            
        except Exception as e:
            logger.error(f"Error getting document history: {str(e)}")
        
        return history

# Utility functions for integration
def create_audit_manager(network="testnet"):
    """Create and return a blockchain audit manager instance"""
    return BlockchainAuditManager(network=network)

def hash_document_content(file_path: str, metadata: Dict[str, Any] = None) -> str:
    """Hash document file content with optional metadata"""
    try:
        with open(file_path, 'rb') as f:
            file_content = f.read()
        
        manager = BlockchainAuditManager()
        return manager.generate_document_hash(file_content, metadata or {})
        
    except Exception as e:
        logger.error(f"Error hashing document: {str(e)}")
        raise

def register_document_on_blockchain(file_path: str, metadata: Dict[str, Any], 
                                  wallet_address: str = None) -> Dict[str, Any]:
    """Convenience function to register a document"""
    try:
        document_hash = hash_document_content(file_path, metadata)
        manager = BlockchainAuditManager()
        return manager.register_document(document_hash, metadata, wallet_address)
        
    except Exception as e:
        logger.error(f"Error registering document: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

if __name__ == "__main__":
    # Test the blockchain audit functionality
    print("Testing Blockchain Audit Manager...")
    
    # Create manager
    manager = BlockchainAuditManager(network="testnet")
    
    # Test service fees
    fees = manager.get_service_fees()
    print(f"Service fees: {fees}")
    
    # Test document registration
    test_metadata = {
        "filename": "test_document.pdf",
        "filesize": 1024,
        "upload_time": datetime.now().isoformat(),
        "pii_detected": 5,
        "fraud_score": 0.23
    }
    
    test_hash = manager.generate_document_hash(b"test content", test_metadata)
    print(f"Generated hash: {test_hash}")
    
    # Register document
    registration_result = manager.register_document(test_hash, test_metadata, "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM")
    print(f"Registration result: {registration_result}")
    
    # Verify document
    verification_result = manager.verify_document(test_hash)
    print(f"Verification result: {verification_result}")
    
    print("Blockchain Audit Manager test completed!")
