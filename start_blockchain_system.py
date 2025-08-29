#!/usr/bin/env python3
"""
🚀 Standard Chartered Hackathon - Blockchain System Launcher
==========================================================
This script helps you quickly start the blockchain monitoring system
"""

import os
import sys
import subprocess
import time
from pathlib import Path

def print_banner():
    print("""
🔗 STANDARD CHARTERED HACKATHON - BLOCKCHAIN SYSTEM
====================================================
   
🎯 Tokenization Smart Contract System
📊 Real-time Transaction Monitoring  
🌐 Web Dashboard Interface
💾 Local Data Storage

====================================================
""")

def check_python_packages():
    """Check if required Python packages are installed"""
    print("🔍 Checking Python dependencies...")
    
    required_packages = [
        'flask', 'flask_socketio', 'requests', 
        'sqlite3', 'threading', 'json'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            if package == 'sqlite3':
                import sqlite3
            elif package == 'flask_socketio':
                import flask_socketio
            else:
                __import__(package)
            print(f"   ✅ {package}")
        except ImportError:
            missing_packages.append(package)
            print(f"   ❌ {package}")
    
    if missing_packages:
        print(f"\n⚠️  Missing packages: {', '.join(missing_packages)}")
        print("📦 Install them with:")
        print("   pip install -r blockchain_requirements.txt")
        return False
    
    return True

def create_sample_data():
    """Create sample transaction data for testing"""
    print("\n📝 Creating sample data for testing...")
    
    try:
        sys.path.append(str(Path(__file__).parent / "blockchain-interface"))
        from transaction_monitor import create_sample_data
        create_sample_data()
        print("   ✅ Sample data created successfully!")
        return True
    except Exception as e:
        print(f"   ❌ Error creating sample data: {e}")
        return False

def start_dashboard():
    """Start the web dashboard"""
    print("\n🌐 Starting web dashboard...")
    
    dashboard_path = Path(__file__).parent / "web-dashboard" / "blockchain_dashboard.py"
    
    if not dashboard_path.exists():
        print(f"   ❌ Dashboard not found at {dashboard_path}")
        return False
    
    try:
        print("   🚀 Launching dashboard at http://localhost:5000")
        print("   📊 Use Ctrl+C to stop the server")
        
        # Change to dashboard directory and run
        os.chdir(dashboard_path.parent)
        subprocess.run([sys.executable, "blockchain_dashboard.py"], check=True)
        
    except KeyboardInterrupt:
        print("\n   ⏹️  Dashboard stopped by user")
        return True
    except Exception as e:
        print(f"   ❌ Error starting dashboard: {e}")
        return False

def check_clarinet():
    """Check if Clarinet is installed for local development"""
    print("\n🔧 Checking Clarinet installation...")
    
    try:
        result = subprocess.run(['clarinet', '--version'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"   ✅ Clarinet installed: {result.stdout.strip()}")
            return True
        else:
            print("   ⚠️  Clarinet not found")
            return False
    except FileNotFoundError:
        print("   ⚠️  Clarinet not installed")
        print("   📦 Install from: https://docs.hiro.so/clarinet")
        return False

def show_usage_instructions():
    """Show how to use the system"""
    print("""
📋 USAGE INSTRUCTIONS
===================

1. 🌐 Web Dashboard:
   • Open http://localhost:5000 in your browser
   • Enter a contract address to monitor
   • Click "Start Monitoring" to begin tracking

2. 🔧 Local Development (with Clarinet):
   • Run: clarinet console
   • Deploy contract: (contract-deploy tokenization-system)
   • Test functions: (contract-call tokenization-system create-token ...)

3. 📊 Monitoring Options:
   • Real-time transactions appear automatically
   • View statistics and transaction history
   • Monitor contract events and print statements

4. 🔗 Connect to Networks:
   • Testnet: Default configuration
   • Local devnet: Set STACKS_API_BASE=http://localhost:3999
   • Mainnet: Set STACKS_API_BASE=https://api.hiro.so

📝 Sample contract addresses for testing:
   • ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM (devnet)
   • Use your deployed contract address for real monitoring

====================================================
""")

def main():
    """Main launcher function"""
    print_banner()
    
    # Check dependencies
    if not check_python_packages():
        print("\n❌ Please install required packages first!")
        return 1
    
    # Check Clarinet
    check_clarinet()
    
    # Create sample data
    create_sample_data()
    
    # Show instructions
    show_usage_instructions()
    
    # Ask user what to do
    print("🚀 What would you like to do?")
    print("   1. Start web dashboard")
    print("   2. Run CLI transaction monitor")
    print("   3. Exit")
    
    try:
        choice = input("\nEnter choice (1-3): ").strip()
        
        if choice == "1":
            start_dashboard()
        elif choice == "2":
            print("\n📊 CLI Monitor mode:")
            print("Run: python blockchain-interface/transaction_monitor.py --contract-address YOUR_ADDRESS")
        elif choice == "3":
            print("👋 Goodbye!")
        else:
            print("❌ Invalid choice")
            
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
