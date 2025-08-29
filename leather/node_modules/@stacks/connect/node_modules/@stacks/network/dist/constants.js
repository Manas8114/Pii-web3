"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.whenTransactionVersion = exports.DEFAULT_TRANSACTION_VERSION = exports.AddressVersion = exports.TransactionVersion = exports.DEFAULT_CHAIN_ID = exports.PeerNetworkId = exports.ChainId = void 0;
var ChainId;
(function (ChainId) {
    ChainId[ChainId["Mainnet"] = 1] = "Mainnet";
    ChainId[ChainId["Testnet"] = 2147483648] = "Testnet";
})(ChainId || (exports.ChainId = ChainId = {}));
var PeerNetworkId;
(function (PeerNetworkId) {
    PeerNetworkId[PeerNetworkId["Mainnet"] = 385875968] = "Mainnet";
    PeerNetworkId[PeerNetworkId["Testnet"] = 4278190080] = "Testnet";
})(PeerNetworkId || (exports.PeerNetworkId = PeerNetworkId = {}));
exports.DEFAULT_CHAIN_ID = ChainId.Mainnet;
var TransactionVersion;
(function (TransactionVersion) {
    TransactionVersion[TransactionVersion["Mainnet"] = 0] = "Mainnet";
    TransactionVersion[TransactionVersion["Testnet"] = 128] = "Testnet";
})(TransactionVersion || (exports.TransactionVersion = TransactionVersion = {}));
var AddressVersion;
(function (AddressVersion) {
    AddressVersion[AddressVersion["MainnetSingleSig"] = 22] = "MainnetSingleSig";
    AddressVersion[AddressVersion["MainnetMultiSig"] = 20] = "MainnetMultiSig";
    AddressVersion[AddressVersion["TestnetSingleSig"] = 26] = "TestnetSingleSig";
    AddressVersion[AddressVersion["TestnetMultiSig"] = 21] = "TestnetMultiSig";
})(AddressVersion || (exports.AddressVersion = AddressVersion = {}));
exports.DEFAULT_TRANSACTION_VERSION = TransactionVersion.Mainnet;
function whenTransactionVersion(transactionVersion) {
    return (map) => map[transactionVersion];
}
exports.whenTransactionVersion = whenTransactionVersion;
//# sourceMappingURL=constants.js.map