#!/usr/bin/env python3
"""
Complete PII Blockchain System Launcher
=======================================
Launches all services needed for PII blockchain monitoring:
1. PII Blockchain Integration Bridge (port 5002) 
2. Blockchain Service (port 5001)
3. PII Dashboard (port 5003)
4. Integration instructions for your script.py
"""

import subprocess
import sys
import time
import os
import importlib
import webbrowser

from typing import List, Dict, Any

class PIIBlockchainSystemLauncher:
    def __init__(self):
        self.processes: List[Dict[str, Any]] = []
        self.services = {
            'pii_bridge': {
                'script': 'pii_blockchain_integration.py',
                'port': 5002,
                'name': 'PII Bridge',
                'description': 'Captures PII data and sends to blockchain'
            },
            'blockchain_service': {
                'script': 'blockchain-interface/blockchain_service.py', 
                'port': 5001,
                'name': 'Blockchain Service',
                'description': 'Handles Clarity smart contract interactions'
            },
            'dashboard': {
                'script': 'web-dashboard/pii_blockchain_dashboard.py',
                'port': 5003, 
                'name': 'PII Dashboard',
                'description': 'Real-time PII monitoring dashboard'
            }
        }
        
    def print_banner(self):
        print("="*70)
        print("🔐 PII BLOCKCHAIN MONITORING SYSTEM")
        print("Standard Chartered Hackathon - Complete Integration")
        print("="*70)
        print()
        print("🔧 System Components:")
        for service in self.services.values():
            print(f"   • {service['name']} (:{service['port']}) - {service['description']}")
        print()
        
    def check_dependencies(self):
        """Check if all required Python packages are installed"""
        print("🔍 Checking dependencies...")
        
        required_packages = [
            'flask', 'flask_socketio', 'requests', 'sqlite3', 
            'threading', 'json', 'hashlib', 'datetime'
        ]
        
        missing_packages = []
        
        for package in required_packages:
            try:
                importlib.import_module(package)
                print(f"   ✅ {package}")
            except ImportError:
                missing_packages.append(package)
                print(f"   ❌ {package}")
        
        if missing_packages:
            print(f"\n⚠️  Missing packages: {', '.join(missing_packages)}")
            print("📦 Install them with:")
            print("   pip install -r blockchain_requirements.txt")
            return False
        
        print("✅ All dependencies satisfied!")
        return True
    
    def check_files_exist(self):
        """Check if all required files exist"""
        print("\n📂 Checking system files...")
        
        required_files = [
            'pii_blockchain_integration.py',
            'script_blockchain_hook.py',
            'contracts/pii-secure-storage.clar',
            'web-dashboard/pii_blockchain_dashboard.py',
            'web-dashboard/templates/pii_dashboard.html',
            'web-dashboard/static/leather_pii_integration.js'
        ]
        
        missing_files = []
        
        for file_path in required_files:
            if os.path.exists(file_path):
                print(f"   ✅ {file_path}")
            else:
                missing_files.append(file_path)
                print(f"   ❌ {file_path}")
        
        if missing_files:
            print(f"\n⚠️  Missing files: {missing_files}")
            return False
        
        print("✅ All system files present!")
        return True
    
    def create_blockchain_service_if_missing(self):
        """Verify blockchain service exists"""
        service_path = 'blockchain-interface/blockchain_service.py'
        
        if not os.path.exists(service_path):
            raise FileNotFoundError(f"Missing required service: {service_path}")
            
    def create_dashboard_service_if_missing(self):
        """Verify dashboard service exists"""
        dashboard_path = 'web-dashboard/pii_blockchain_dashboard.py'
        
        if not os.path.exists(dashboard_path):
            raise FileNotFoundError(f"Missing required service: {dashboard_path}")
    
    def start_service(self, service_name, service_info):
        """Start a service in background"""
        try:
            print(f"🚀 Starting {service_info['name']}...")
            
            process = subprocess.Popen([
                sys.executable, service_info['script']
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            self.processes.append({
                'name': service_name,
                'process': process,
                'info': service_info
            })
            
            print(f"   ✅ {service_info['name']} started on port {service_info['port']}")
            return True
            
        except Exception as e:
            print(f"   ❌ Failed to start {service_info['name']}: {e}")
            return False
    
    def start_all_services(self):
        """Start all services"""
        print("\n🚀 Starting all services...\n")
        
        # Create missing services
        self.create_blockchain_service_if_missing()
        self.create_dashboard_service_if_missing()
        
        success_results = []
        
        for service_name, service_info in self.services.items():
            if self.start_service(service_name, service_info):
                success_results.append(1)
            time.sleep(2)  # Wait between services
        
        success_count = len(success_results)
        print(f"\n✅ Started {success_count}/{len(self.services)} services")
        
        if success_count == len(self.services):
            self.show_usage_instructions()
            return True
        return False
    
    def show_usage_instructions(self):
        """Show usage instructions"""
        print("\n" + "="*70)
        print("🎯 SYSTEM READY! Usage Instructions")
        print("="*70)
        
        print("\n1. 🌐 Access PII Dashboard:")
        print("   • Open: http://localhost:5003")
        print("   • Connect Leather wallet")
        print("   • Monitor real-time PII transactions")
        
        print("\n2. 🔧 Integrate with your script.py:")
        print("   • Add this import at the top:")
        print("     from script_blockchain_hook import send_pii_to_blockchain")
        print()
        print("   • Add this after PII extraction (around line 450):")
        print("     if pii_data:  # Your extracted PII")
        print("         doc_id = f'doc_{int(time.time())}'") 
        print("         send_pii_to_blockchain(doc_id, pii_data)")
        
        print("\n3. 📊 Services Running:")
        for service_info in self.services.values():
            print(f"   • {service_info['name']}: http://localhost:{service_info['port']}")
        
        print("\n4. 🧪 Test the System:")
        print("   • Process a document through your script.py")
        print("   • Watch PII data appear in real-time dashboard")
        print("   • Transactions automatically sent to blockchain")
        
        print("\n" + "="*70)
        
        # Auto-open dashboard
        try:
            time.sleep(3)
            print("🌐 Opening PII dashboard in browser...")
            webbrowser.open('http://localhost:5003')
        except Exception:
            pass
    
    def cleanup(self):
        """Stop all services"""
        print("\n🛑 Stopping all services...")
        
        for service in self.processes:
            try:
                service['process'].terminate()
                print(f"   ✅ Stopped {service['info']['name']}")
            except Exception:
                pass
        
        print("👋 PII Blockchain System stopped.")
    
    def run(self):
        """Main run method"""
        try:
            self.print_banner()
            
            if not self.check_dependencies():
                print("\n❌ Please install required packages first!")
                return False
            
            if not self.check_files_exist():
                print("\n❌ Please ensure all system files are present!")
                return False
            
            if self.start_all_services():
                print("\n⏳ System running... Press Ctrl+C to stop")
                
                # Keep running until interrupted
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n\n🛑 Received stop signal...")
                    
            else:
                print("\n❌ Failed to start all services!")
                return False
                
        except KeyboardInterrupt:
            print("\n\n🛑 System interrupted...")
        finally:
            self.cleanup()

if __name__ == '__main__':
    launcher = PIIBlockchainSystemLauncher()
    launcher.run()
