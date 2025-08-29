// Leather Wallet Integration for PII Blockchain System
// =====================================================

class LeatherPIIIntegration {
    constructor() {
        this.connected = false;
        this.contractAddress = null;
        this.userAddress = null;
        this.network = 'testnet';
        this.contractName = 'pii-secure-storage';
        
        this.init();
    }

    async init() {
        console.log('🔧 Initializing Leather PII Integration...');
        this.checkLeatherInstalled();
        await this.setupEventListeners();
    }

    checkLeatherInstalled() {
        if (typeof window.LeatherProvider !== 'undefined') {
            console.log('✅ Leather wallet detected');
            this.updateStatus('Leather wallet detected - Ready to connect');
        } else {
            console.log('❌ Leather wallet not found');
            this.updateStatus('Please install Leather wallet extension');
            this.showInstallGuide();
        }
    }

    showInstallGuide() {
        const installDiv = document.getElementById('wallet-install-guide');
        if (installDiv) {
            installDiv.innerHTML = `
                <div class="alert alert-warning">
                    <h5>📦 Install Leather Wallet</h5>
                    <p>1. Visit <a href="https://leather.io" target="_blank">leather.io</a></p>
                    <p>2. Download and install the browser extension</p>
                    <p>3. Create or import a wallet</p>
                    <p>4. Refresh this page</p>
                </div>
            `;
        }
    }

    async connectWallet() {
        try {
            console.log('🔌 Connecting to Leather wallet...');
            this.updateStatus('Connecting to wallet...');

            // Mock connection for demo (replace with actual Leather API)
            const mockAddress = "ST1HTBVD3JG9C05J7HBJTHGR0GGW7KXW28M5JS8QE";
            this.userAddress = mockAddress;
            this.connected = true;
            
            console.log('✅ Wallet connected:', this.userAddress);
            this.updateStatus(`Connected: ${this.userAddress.substring(0, 10)}...`);
            
            await this.loadContractInfo();
            this.enableDashboard();
            
            return true;

        } catch (error) {
            console.error('❌ Wallet connection failed:', error);
            this.updateStatus(`Connection failed: ${error.message}`);
            return false;
        }
    }

    async loadContractInfo() {
        this.contractAddress = `${this.userAddress}.${this.contractName}`;
        
        console.log('📋 Contract address:', this.contractAddress);
        
        const contractDiv = document.getElementById('contract-info');
        if (contractDiv) {
            contractDiv.innerHTML = `
                <div class="contract-card">
                    <h6>Smart Contract</h6>
                    <p><strong>Name:</strong> ${this.contractName}</p>
                    <p><strong>Address:</strong> ${this.contractAddress}</p>
                    <p><strong>Network:</strong> ${this.network}</p>
                </div>
            `;
        }
    }

    async storePIIOnBlockchain(documentId, piiHash, fieldCount) {
        if (!this.connected || !this.contractAddress) {
            console.error('❌ Wallet not connected or contract not deployed');
            return false;
        }

        try {
            console.log(`📤 Storing PII on blockchain: ${documentId}`);

            // Mock transaction for demo
            const mockTxId = 'tx_' + Math.random().toString(36).substr(2, 16);
            
            console.log('✅ PII stored on blockchain:', mockTxId);
            this.logTransaction(documentId, mockTxId, 'store-pii');
            return mockTxId;

        } catch (error) {
            console.error('❌ Failed to store PII on blockchain:', error);
            return false;
        }
    }

    logTransaction(documentId, txId, action) {
        const transactionLog = {
            documentId: documentId,
            txId: txId,
            action: action,
            timestamp: new Date().toISOString(),
            address: this.userAddress
        };

        // Add to local storage for dashboard
        let transactions = JSON.parse(localStorage.getItem('pii_transactions') || '[]');
        transactions.unshift(transactionLog);
        transactions = transactions.slice(0, 50); // Keep last 50
        localStorage.setItem('pii_transactions', JSON.stringify(transactions));

        // Update dashboard
        this.updateTransactionList();
        this.updateStats();
    }

    updateTransactionList() {
        const transactions = JSON.parse(localStorage.getItem('pii_transactions') || '[]');
        const listElement = document.getElementById('transaction-list');
        
        if (listElement && transactions.length > 0) {
            listElement.innerHTML = transactions.map(tx => `
                <div class="transaction-item">
                    <div class="tx-info">
                        <strong>Doc:</strong> ${tx.documentId}
                        <span class="tx-time">${new Date(tx.timestamp).toLocaleTimeString()}</span>
                    </div>
                    <div class="tx-details">
                        <span class="tx-id">TX: ${tx.txId.substring(0, 16)}...</span>
                        <span class="tx-action badge ${tx.action === 'store-pii' ? 'bg-success' : 'bg-info'}">${tx.action}</span>
                    </div>
                </div>
            `).join('');
        }
    }

    updateStats() {
        const transactions = JSON.parse(localStorage.getItem('pii_transactions') || '[]');
        
        const totalTxEl = document.getElementById('total-transactions');
        const storedDocsEl = document.getElementById('stored-documents');
        const walletAddrEl = document.getElementById('wallet-address');
        
        if (totalTxEl) totalTxEl.textContent = transactions.length;
        if (storedDocsEl) storedDocsEl.textContent = transactions.filter(tx => tx.action === 'store-pii').length;
        if (walletAddrEl) walletAddrEl.textContent = this.userAddress ? `${this.userAddress.substring(0, 20)}...` : 'Not connected';
    }

    enableDashboard() {
        const connectBtn = document.getElementById('wallet-connect-btn');
        if (connectBtn) {
            connectBtn.textContent = '✅ Connected';
            connectBtn.disabled = true;
        }
        
        const deployBtn = document.getElementById('deploy-contract-btn');
        if (deployBtn) {
            deployBtn.disabled = false;
        }

        this.updateStats();
    }

    updateStatus(message) {
        const statusElement = document.getElementById('wallet-status');
        if (statusElement) {
            statusElement.textContent = message;
            console.log('📊 Status:', message);
        }
    }

    async setupEventListeners() {
        document.addEventListener('DOMContentLoaded', () => {
            const connectBtn = document.getElementById('wallet-connect-btn');
            if (connectBtn) {
                connectBtn.addEventListener('click', () => this.connectWallet());
            }

            const deployBtn = document.getElementById('deploy-contract-btn');
            if (deployBtn) {
                deployBtn.addEventListener('click', () => this.deployContract());
            }
        });
    }

    // Public API for manual transactions
    async sendPIIToBlockchain(documentId, piiData) {
        if (!this.connected) {
            console.warn('⚠️  Wallet not connected');
            return false;
        }

        const piiHash = await this.createHash(JSON.stringify(piiData));
        const fieldCount = Object.keys(piiData).length;

        return await this.storePIIOnBlockchain(documentId, piiHash, fieldCount);
    }

    async createHash(data) {
        const encoder = new TextEncoder();
        const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
}

// Initialize when page loads
let leatherPII = null;

document.addEventListener('DOMContentLoaded', () => {
    leatherPII = new LeatherPIIIntegration();
    console.log('🚀 Leather PII Integration initialized');
});

// Export for global use
window.LeatherPIIIntegration = LeatherPIIIntegration;
