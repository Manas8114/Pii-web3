import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { getPublicKey as nobleGetPublicKey, Point, Signature, signSync, utils, } from '@noble/secp256k1';
import { bytesToHex, hexToBigInt, hexToBytes, intToHex, parseRecoverableSignatureVrs, PRIVATE_KEY_BYTES_COMPRESSED, privateKeyToBytes, signatureRsvToVrs, signatureVrsToRsv, } from '@stacks/common';
import { networkFrom, STACKS_MAINNET } from '@stacks/network';
import { c32address } from 'c32check';
import { addressHashModeToVersion } from './address';
import { AddressHashMode, PubKeyEncoding } from './constants';
import { hash160, hashP2PKH } from './utils';
import { addressFromVersionHash, addressToString, StacksWireType } from './wire';
utils.hmacSha256Sync = (key, ...msgs) => {
    const h = hmac.create(sha256, key);
    msgs.forEach(msg => h.update(msg));
    return h.digest();
};
export function getAddressFromPrivateKey(privateKey, network = 'mainnet') {
    network = networkFrom(network);
    const publicKey = privateKeyToPublic(privateKey);
    return getAddressFromPublicKey(publicKey, network);
}
export function getAddressFromPublicKey(publicKey, network = 'mainnet') {
    network = networkFrom(network);
    publicKey = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;
    const addrVer = addressHashModeToVersion(AddressHashMode.P2PKH, network);
    const addr = addressFromVersionHash(addrVer, hashP2PKH(publicKey));
    const addrString = addressToString(addr);
    return addrString;
}
export function createStacksPublicKey(publicKey) {
    publicKey = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;
    return {
        type: StacksWireType.PublicKey,
        data: publicKey,
    };
}
export function publicKeyFromSignatureVrs(messageHash, messageSignature, pubKeyEncoding = PubKeyEncoding.Compressed) {
    const parsedSignature = parseRecoverableSignatureVrs(messageSignature);
    const signature = new Signature(hexToBigInt(parsedSignature.r), hexToBigInt(parsedSignature.s));
    const point = Point.fromSignature(messageHash, signature, parsedSignature.recoveryId);
    const compressed = pubKeyEncoding === PubKeyEncoding.Compressed;
    return point.toHex(compressed);
}
export function publicKeyFromSignatureRsv(messageHash, messageSignature, pubKeyEncoding = PubKeyEncoding.Compressed) {
    return publicKeyFromSignatureVrs(messageHash, signatureRsvToVrs(messageSignature), pubKeyEncoding);
}
export function privateKeyToHex(publicKey) {
    return typeof publicKey === 'string' ? publicKey : bytesToHex(publicKey);
}
export const publicKeyToHex = privateKeyToHex;
export const isPrivateKeyCompressed = privateKeyIsCompressed;
export function privateKeyIsCompressed(privateKey) {
    const length = typeof privateKey === 'string' ? privateKey.length / 2 : privateKey.byteLength;
    return length === PRIVATE_KEY_BYTES_COMPRESSED;
}
export const isPublicKeyCompressed = publicKeyIsCompressed;
export function publicKeyIsCompressed(publicKey) {
    return !publicKeyToHex(publicKey).startsWith('04');
}
export function privateKeyToPublic(privateKey) {
    privateKey = privateKeyToBytes(privateKey);
    const isCompressed = privateKeyIsCompressed(privateKey);
    return bytesToHex(nobleGetPublicKey(privateKey.slice(0, 32), isCompressed));
}
export function compressPublicKey(publicKey) {
    return Point.fromHex(publicKeyToHex(publicKey)).toHex(true);
}
export function uncompressPublicKey(publicKey) {
    return Point.fromHex(publicKeyToHex(publicKey)).toHex(false);
}
export const makeRandomPrivKey = randomPrivateKey;
export function randomPrivateKey() {
    return compressPrivateKey(utils.randomPrivateKey());
}
export function signWithKey(privateKey, messageHash) {
    privateKey = privateKeyToBytes(privateKey);
    const [rawSignature, recoveryId] = signSync(messageHash, privateKey.slice(0, 32), {
        canonical: true,
        recovered: true,
    });
    if (recoveryId == null) {
        throw new Error('No signature recoveryId received');
    }
    const recoveryIdHex = intToHex(recoveryId, 1);
    return recoveryIdHex + Signature.fromHex(rawSignature).toCompactHex();
}
export function signMessageHashRsv({ messageHash, privateKey, }) {
    return signatureVrsToRsv(signWithKey(privateKey, messageHash));
}
export function compressPrivateKey(privateKey) {
    privateKey = privateKeyToHex(privateKey);
    return privateKey.length == PRIVATE_KEY_BYTES_COMPRESSED * 2
        ? privateKey
        : `${privateKey}01`;
}
export function privateKeyToAddress(privateKey, network) {
    const publicKey = privateKeyToPublic(privateKey);
    return publicKeyToAddressSingleSig(publicKey, network);
}
export function publicKeyToAddress(...args) {
    if (typeof args[0] === 'number')
        return _publicKeyToAddress(...args);
    return publicKeyToAddressSingleSig(...args);
}
function _publicKeyToAddress(version, publicKey) {
    publicKey = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;
    return c32address(version, bytesToHex(hash160(publicKey)));
}
export function publicKeyToAddressSingleSig(publicKey, network) {
    network = network ? networkFrom(network) : STACKS_MAINNET;
    publicKey = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;
    return c32address(network.addressVersion.singleSig, bytesToHex(hash160(publicKey)));
}
//# sourceMappingURL=keys.js.map