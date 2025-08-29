# 🦬 Leather Wallet Integration - Complete Setup

## ✅ **What We've Built**

Your PII dashboard now has **real Leather wallet integration** with:
- ✅ **Real Stacks addresses** and transactions
- ✅ **Live transaction monitoring** from Hiro API
- ✅ **HTTPS server** for secure wallet connections
- ✅ **Auto-polling** every 8 seconds for new transactions

---

## 🚀 **Quick Start (2 Steps)**

### **Step 1: Start HTTPS Server**
```bash
python https_server_for_leather.py
```

### **Step 2: Open Dashboard**
```
https://localhost:7000/pii_dashboard_standalone.html
```

**Accept the certificate warning** (click Advanced → Proceed)

---

## 🔧 **Detailed Setup**

### **1. Install Leather Wallet**
- Go to [leather.io](https://leather.io)
- Install browser extension
- Create/import wallet
- Get some testnet STX from [faucet.hiro.so](https://faucet.hiro.so)

### **2. Start the HTTPS Server**
```bash
cd /d/CodeFest\(tokenization\)/Standard-Chartered-Hackthon
python https_server_for_leather.py
```

**You'll see:**
```
🔐 PII Blockchain Dashboard - HTTPS Server
==================================================
📄 Serving dashboard: pii_dashboard_standalone.html
🔐 Creating self-signed certificate...
✅ Created certificate: localhost.pem
🚀 HTTPS Server starting on port 7000...
🌐 Dashboard URL: https://localhost:7000/pii_dashboard_standalone.html
```

### **3. Open Dashboard**
- Navigate to: **https://localhost:7000/pii_dashboard_standalone.html**
- **Accept certificate warning** (Advanced → Proceed to localhost)
- You'll see the beautiful PII dashboard

### **4. Connect Leather**
- Click **"🔌 Connect Leather Wallet"**
- Leather popup will appear
- **Approve the connection**
- Your address appears: `Connected: ST1HTBV...`

### **5. See Real Transactions**
- Your **real wallet transactions** will appear automatically
- Links to **Hiro Explorer** for each transaction
- **Auto-updates every 8 seconds**

---

## 🧪 **Testing the Integration**

### **Make a Test Transaction:**
1. Open Leather wallet
2. Send 0.001 STX to any address
3. **Watch it appear in dashboard within 8 seconds!**

### **Call a Contract:**
1. Use Leather to interact with any contract
2. See contract calls appear in real-time

### **Switch Networks:**
- Change `NETWORK = 'mainnet'` in the JavaScript
- See your mainnet transactions

---

## 🎯 **Perfect for Demo!**

This setup shows:
- ✅ **Real blockchain connectivity**
- ✅ **Professional Leather integration**
- ✅ **Live transaction monitoring**
- ✅ **Beautiful dashboard UI**
- ✅ **Secure HTTPS connection**

---

## 🛠️ **Troubleshooting**

### **Certificate Issues:**
```bash
pip install cryptography
```

### **Port 7000 in Use:**
- Change `port = 7000` to `port = 7001` in the script
- Update URL to `https://localhost:7001/...`

### **Leather Not Connecting:**
- Make sure you're using **https://** (not http)
- Try refreshing the page
- Check browser developer console for errors

---

## 🏆 **Demo Script**

**Perfect for hackathon presentation:**

1. **"First, let me show our secure HTTPS setup..."**
   - `python https_server_for_leather.py`
   
2. **"Here's our beautiful dashboard with real-time monitoring..."**
   - Open `https://localhost:7000/pii_dashboard_standalone.html`
   
3. **"Now let's connect a real Leather wallet..."**
   - Click Connect → Show Leather popup → Connect
   
4. **"And here are my real blockchain transactions..."**
   - Point to live transaction list with links to explorer
   
5. **"Watch this update in real-time as I make a transaction..."**
   - Send STX in Leather → Watch it appear in dashboard

**Judges will be amazed! 🎉**

---

## 📋 **Integration with Your PII System**

Your dashboard is ready! When you add the 2 lines to `Models/script.py`:

```python
from script_blockchain_hook import send_pii_to_blockchain
send_pii_to_blockchain(doc_id, pii_data)
```

The PII data will flow through your backend services and appear alongside the real Leather transactions!

**Complete end-to-end PII blockchain system! 🚀**
