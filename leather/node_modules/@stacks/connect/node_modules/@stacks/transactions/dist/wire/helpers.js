"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parsePrincipalString = exports.parseAssetString = exports.isCoinbasePayload = exports.isPoisonPayload = exports.isSmartContractPayload = exports.isContractCallPayload = exports.isTokenTransferPayload = exports.addressToString = exports.addressFromVersionHash = exports.addressFromPublicKeys = void 0;
const c32check_1 = require("c32check");
const constants_1 = require("../constants");
const keys_1 = require("../keys");
const utils_1 = require("../utils");
const create_1 = require("./create");
const serialization_1 = require("./serialization");
const types_1 = require("./types");
function addressFromPublicKeys(version, hashMode, numSigs, publicKeys) {
    if (publicKeys.length === 0) {
        throw Error('Invalid number of public keys');
    }
    if (hashMode === constants_1.AddressHashMode.P2PKH || hashMode === constants_1.AddressHashMode.P2WPKH) {
        if (publicKeys.length !== 1 || numSigs !== 1) {
            throw Error('Invalid number of public keys or signatures');
        }
    }
    if (hashMode === constants_1.AddressHashMode.P2WPKH ||
        hashMode === constants_1.AddressHashMode.P2WSH ||
        hashMode === constants_1.AddressHashMode.P2WSHNonSequential) {
        if (!publicKeys.map(p => p.data).every(keys_1.publicKeyIsCompressed)) {
            throw Error('Public keys must be compressed for segwit');
        }
    }
    switch (hashMode) {
        case constants_1.AddressHashMode.P2PKH:
            return addressFromVersionHash(version, (0, utils_1.hashP2PKH)(publicKeys[0].data));
        case constants_1.AddressHashMode.P2WPKH:
            return addressFromVersionHash(version, (0, utils_1.hashP2WPKH)(publicKeys[0].data));
        case constants_1.AddressHashMode.P2SH:
        case constants_1.AddressHashMode.P2SHNonSequential:
            return addressFromVersionHash(version, (0, utils_1.hashP2SH)(numSigs, publicKeys.map(serialization_1.serializePublicKeyBytes)));
        case constants_1.AddressHashMode.P2WSH:
        case constants_1.AddressHashMode.P2WSHNonSequential:
            return addressFromVersionHash(version, (0, utils_1.hashP2WSH)(numSigs, publicKeys.map(serialization_1.serializePublicKeyBytes)));
    }
}
exports.addressFromPublicKeys = addressFromPublicKeys;
function addressFromVersionHash(version, hash) {
    return { type: types_1.StacksWireType.Address, version, hash160: hash };
}
exports.addressFromVersionHash = addressFromVersionHash;
function addressToString(address) {
    return (0, c32check_1.c32address)(address.version, address.hash160);
}
exports.addressToString = addressToString;
function isTokenTransferPayload(p) {
    return p.payloadType === constants_1.PayloadType.TokenTransfer;
}
exports.isTokenTransferPayload = isTokenTransferPayload;
function isContractCallPayload(p) {
    return p.payloadType === constants_1.PayloadType.ContractCall;
}
exports.isContractCallPayload = isContractCallPayload;
function isSmartContractPayload(p) {
    return p.payloadType === constants_1.PayloadType.SmartContract;
}
exports.isSmartContractPayload = isSmartContractPayload;
function isPoisonPayload(p) {
    return p.payloadType === constants_1.PayloadType.PoisonMicroblock;
}
exports.isPoisonPayload = isPoisonPayload;
function isCoinbasePayload(p) {
    return p.payloadType === constants_1.PayloadType.Coinbase;
}
exports.isCoinbasePayload = isCoinbasePayload;
function parseAssetString(id) {
    const [assetAddress, assetContractName, assetTokenName] = id.split(/\.|::/);
    const asset = (0, create_1.createAsset)(assetAddress, assetContractName, assetTokenName);
    return asset;
}
exports.parseAssetString = parseAssetString;
function parsePrincipalString(principalString) {
    if (principalString.includes('.')) {
        const [address, contractName] = principalString.split('.');
        return (0, create_1.createContractPrincipal)(address, contractName);
    }
    else {
        return (0, create_1.createStandardPrincipal)(principalString);
    }
}
exports.parsePrincipalString = parsePrincipalString;
//# sourceMappingURL=helpers.js.map