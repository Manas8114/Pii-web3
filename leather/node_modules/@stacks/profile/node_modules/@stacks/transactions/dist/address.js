"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.addressHashModeToVersion = void 0;
const network_1 = require("@stacks/network");
const constants_1 = require("./constants");
function addressHashModeToVersion(hashMode, network) {
    network = (0, network_1.networkFrom)(network ?? network_1.STACKS_MAINNET);
    switch (hashMode) {
        case constants_1.AddressHashMode.P2PKH:
            switch (network.transactionVersion) {
                case network_1.TransactionVersion.Mainnet:
                    return constants_1.AddressVersion.MainnetSingleSig;
                case network_1.TransactionVersion.Testnet:
                    return constants_1.AddressVersion.TestnetSingleSig;
                default:
                    throw new Error(`Unexpected transactionVersion ${network.transactionVersion} for hashMode ${hashMode}`);
            }
        case constants_1.AddressHashMode.P2SH:
        case constants_1.AddressHashMode.P2SHNonSequential:
        case constants_1.AddressHashMode.P2WPKH:
        case constants_1.AddressHashMode.P2WSH:
        case constants_1.AddressHashMode.P2WSHNonSequential:
            switch (network.transactionVersion) {
                case network_1.TransactionVersion.Mainnet:
                    return constants_1.AddressVersion.MainnetMultiSig;
                case network_1.TransactionVersion.Testnet:
                    return constants_1.AddressVersion.TestnetMultiSig;
                default:
                    throw new Error(`Unexpected transactionVersion ${network.transactionVersion} for hashMode ${hashMode}`);
            }
        default:
            throw new Error(`Unexpected hashMode ${hashMode}`);
    }
}
exports.addressHashModeToVersion = addressHashModeToVersion;
//# sourceMappingURL=address.js.map