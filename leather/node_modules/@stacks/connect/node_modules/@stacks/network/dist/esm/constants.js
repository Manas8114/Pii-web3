export var ChainId;
(function (ChainId) {
    ChainId[ChainId["Mainnet"] = 1] = "Mainnet";
    ChainId[ChainId["Testnet"] = 2147483648] = "Testnet";
})(ChainId || (ChainId = {}));
export var PeerNetworkId;
(function (PeerNetworkId) {
    PeerNetworkId[PeerNetworkId["Mainnet"] = 385875968] = "Mainnet";
    PeerNetworkId[PeerNetworkId["Testnet"] = 4278190080] = "Testnet";
})(PeerNetworkId || (PeerNetworkId = {}));
export const DEFAULT_CHAIN_ID = ChainId.Mainnet;
export var TransactionVersion;
(function (TransactionVersion) {
    TransactionVersion[TransactionVersion["Mainnet"] = 0] = "Mainnet";
    TransactionVersion[TransactionVersion["Testnet"] = 128] = "Testnet";
})(TransactionVersion || (TransactionVersion = {}));
export var AddressVersion;
(function (AddressVersion) {
    AddressVersion[AddressVersion["MainnetSingleSig"] = 22] = "MainnetSingleSig";
    AddressVersion[AddressVersion["MainnetMultiSig"] = 20] = "MainnetMultiSig";
    AddressVersion[AddressVersion["TestnetSingleSig"] = 26] = "TestnetSingleSig";
    AddressVersion[AddressVersion["TestnetMultiSig"] = 21] = "TestnetMultiSig";
})(AddressVersion || (AddressVersion = {}));
export const DEFAULT_TRANSACTION_VERSION = TransactionVersion.Mainnet;
export function whenTransactionVersion(transactionVersion) {
    return (map) => map[transactionVersion];
}
//# sourceMappingURL=constants.js.map