# 🔗 Clarity Smart Contract & Real-Time Blockchain Monitor

## Standard Chartered Hackathon 2025 - Tokenization System

A comprehensive blockchain solution featuring:
- **🎯 Clarity Smart Contract** for tokenization with transaction logging
- **📊 Real-time Transaction Monitoring** via Stacks API polling
- **🌐 Web Dashboard** with live updates using WebSockets
- **💾 Local Data Storage** with SQLite for transaction history

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r blockchain_requirements.txt
```

### 2. Run the System
```bash
python start_blockchain_system.py
```

### 3. Access Dashboard
Open your browser to: **http://localhost:5000**

---

## 📁 Project Structure

```
├── contracts/
│   └── tokenization-system.clar      # Main smart contract
├── blockchain-interface/
│   ├── stacks_client.py              # Stacks API client
│   └── transaction_monitor.py        # Real-time monitoring
├── web-dashboard/
│   ├── blockchain_dashboard.py       # Flask web app
│   └── templates/dashboard.html      # Web interface
├── Clarinet.toml                     # Clarinet configuration
├── blockchain_requirements.txt       # Python dependencies
└── start_blockchain_system.py       # Quick launcher
```

---

## 🎯 Smart Contract Features

### Core Functions
- **`create-token`** - Create new tokenized assets
- **`transfer`** - Transfer tokens between addresses
- **`mint-tokens`** - Mint new tokens (owner only)
- **`burn-tokens`** - Burn existing tokens
- **`get-balance`** - Query token balances
- **`get-transaction`** - Get transaction details

### Real-time Logging
Every transaction is automatically logged with:
- Transaction ID and timestamp
- From/to addresses
- Token amounts and types
- Event metadata
- Block height information

---

## 📊 Monitoring System

### Features
- **Real-time Polling** of Stacks API every 2 seconds
- **Local SQLite Storage** for transaction history
- **WebSocket Updates** for instant dashboard refresh
- **Event Filtering** for contract-specific transactions
- **Statistics Tracking** (success rates, volume, etc.)

### Supported Networks
- **Testnet** (default): `https://api.testnet.hiro.so`
- **Mainnet**: `https://api.hiro.so`
- **Local Devnet**: `http://localhost:3999` (with Clarinet)

---

## 🌐 Web Dashboard

### Real-time Features
- **Live Transaction Feed** with WebSocket updates
- **Contract Statistics** (total txs, success rate, etc.)
- **Event Visualization** with parsed contract data
- **Monitoring Controls** (start/stop, configure contracts)
- **Mobile-responsive Design**

### Usage
1. Enter your contract address
2. Click "Start Monitoring"
3. Watch transactions appear in real-time
4. View detailed event data and statistics

---

## 🔧 Development Setup

### With Clarinet (Recommended)
```bash
# Install Clarinet
# Visit: https://docs.hiro.so/clarinet

# Start local devnet
clarinet devnet start

# Deploy contract
clarinet deploy --devnet

# Open console for testing
clarinet console
```

### Manual Testing
```clarity
;; Create a token
(contract-call .tokenization-system create-token 
  "TestToken" "TT" u1000000 u6 "Test token metadata")

;; Transfer tokens
(contract-call .tokenization-system transfer u1 u100 'ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG)

;; Check balance
(contract-call .tokenization-system get-balance u1 tx-sender)
```

---

## 🏗️ Architecture

### Components
1. **Smart Contract Layer**: Clarity contract with event emission
2. **API Interface Layer**: Python client for Stacks API
3. **Data Layer**: SQLite for local transaction storage  
4. **Application Layer**: Flask web app with real-time monitoring
5. **Presentation Layer**: WebSocket-enabled dashboard

### Data Flow
```
Stacks Blockchain → API Polling → Local Storage → WebSocket → Dashboard
```

---

## 🎮 Testing & Demo

### Sample Data
The system includes sample transaction data for testing:
```bash
python blockchain-interface/transaction_monitor.py --sample-data
```

### Demo Contract
For testing without deployment, use these sample addresses:
- **Devnet**: `ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM`
- **Contract**: `tokenization-system`

---

## 🔒 Security Features

- **Access Control**: Contract owner privileges
- **Input Validation**: Amount and address checks
- **Error Handling**: Comprehensive error constants
- **Event Logging**: Immutable transaction audit trail

---

## 🚨 Troubleshooting

### Common Issues

**Dashboard won't start:**
- Check Python dependencies: `pip install -r blockchain_requirements.txt`
- Verify port 5000 is available

**No transactions appearing:**
- Verify contract address is correct
- Check network configuration (testnet vs mainnet)
- Ensure contract has recent activity

**Clarinet not working:**
- Install from: https://docs.hiro.so/clarinet
- Check PATH environment variable

### Debug Mode
```bash
# Enable debug logging
export FLASK_DEBUG=1
python web-dashboard/blockchain_dashboard.py
```

---

## 🔄 Return to Original State

If you need to return to your original codebase:

```bash
# View stash list
git stash list

# Apply the saved state
git stash apply stash@{0}

# Or restore completely
git stash pop stash@{0}
```

---

## 🏆 Standard Chartered Hackathon

This system demonstrates:
- **Real-time blockchain monitoring**
- **Smart contract development** 
- **Web3 integration**
- **Modern web development**
- **Data visualization**

Perfect for demonstrating tokenization use cases, transaction tracking, and blockchain transparency.

---

## 📞 Support

For questions or issues:
1. Check the troubleshooting section
2. Review console logs for error messages
3. Verify network connectivity and API endpoints
4. Test with sample data first

**Happy coding! 🚀**
