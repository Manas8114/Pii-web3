from web3 import Web3  
BLOCKCHAIN_PROVIDER_URL = "https://sepolia.infura.io/v3/2baecf4884314ac4ba5bc178092bc828"
w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_PROVIDER_URL))
if w3.is_connected():
    print("Connected to Sepolia testnet")
else:
    print("Connection failed")
