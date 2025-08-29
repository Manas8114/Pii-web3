import { c32address } from 'c32check';
import { AddressHashMode, PayloadType } from '../constants';
import { publicKeyIsCompressed } from '../keys';
import { hashP2PKH, hashP2SH, hashP2WPKH, hashP2WSH } from '../utils';
import { createAsset, createContractPrincipal, createStandardPrincipal } from './create';
import { serializePublicKeyBytes } from './serialization';
import { StacksWireType, } from './types';
export function addressFromPublicKeys(version, hashMode, numSigs, publicKeys) {
    if (publicKeys.length === 0) {
        throw Error('Invalid number of public keys');
    }
    if (hashMode === AddressHashMode.P2PKH || hashMode === AddressHashMode.P2WPKH) {
        if (publicKeys.length !== 1 || numSigs !== 1) {
            throw Error('Invalid number of public keys or signatures');
        }
    }
    if (hashMode === AddressHashMode.P2WPKH ||
        hashMode === AddressHashMode.P2WSH ||
        hashMode === AddressHashMode.P2WSHNonSequential) {
        if (!publicKeys.map(p => p.data).every(publicKeyIsCompressed)) {
            throw Error('Public keys must be compressed for segwit');
        }
    }
    switch (hashMode) {
        case AddressHashMode.P2PKH:
            return addressFromVersionHash(version, hashP2PKH(publicKeys[0].data));
        case AddressHashMode.P2WPKH:
            return addressFromVersionHash(version, hashP2WPKH(publicKeys[0].data));
        case AddressHashMode.P2SH:
        case AddressHashMode.P2SHNonSequential:
            return addressFromVersionHash(version, hashP2SH(numSigs, publicKeys.map(serializePublicKeyBytes)));
        case AddressHashMode.P2WSH:
        case AddressHashMode.P2WSHNonSequential:
            return addressFromVersionHash(version, hashP2WSH(numSigs, publicKeys.map(serializePublicKeyBytes)));
    }
}
export function addressFromVersionHash(version, hash) {
    return { type: StacksWireType.Address, version, hash160: hash };
}
export function addressToString(address) {
    return c32address(address.version, address.hash160);
}
export function isTokenTransferPayload(p) {
    return p.payloadType === PayloadType.TokenTransfer;
}
export function isContractCallPayload(p) {
    return p.payloadType === PayloadType.ContractCall;
}
export function isSmartContractPayload(p) {
    return p.payloadType === PayloadType.SmartContract;
}
export function isPoisonPayload(p) {
    return p.payloadType === PayloadType.PoisonMicroblock;
}
export function isCoinbasePayload(p) {
    return p.payloadType === PayloadType.Coinbase;
}
export function parseAssetString(id) {
    const [assetAddress, assetContractName, assetTokenName] = id.split(/\.|::/);
    const asset = createAsset(assetAddress, assetContractName, assetTokenName);
    return asset;
}
export function parsePrincipalString(principalString) {
    if (principalString.includes('.')) {
        const [address, contractName] = principalString.split('.');
        return createContractPrincipal(address, contractName);
    }
    else {
        return createStandardPrincipal(principalString);
    }
}
//# sourceMappingURL=helpers.js.map