"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.publicKeyToAddressSingleSig = exports.publicKeyToAddress = exports.privateKeyToAddress = exports.compressPrivateKey = exports.signMessageHashRsv = exports.signWithKey = exports.randomPrivateKey = exports.makeRandomPrivKey = exports.uncompressPublicKey = exports.compressPublicKey = exports.privateKeyToPublic = exports.publicKeyIsCompressed = exports.isPublicKeyCompressed = exports.privateKeyIsCompressed = exports.isPrivateKeyCompressed = exports.publicKeyToHex = exports.privateKeyToHex = exports.publicKeyFromSignatureRsv = exports.publicKeyFromSignatureVrs = exports.createStacksPublicKey = exports.getAddressFromPublicKey = exports.getAddressFromPrivateKey = void 0;
const hmac_1 = require("@noble/hashes/hmac");
const sha256_1 = require("@noble/hashes/sha256");
const secp256k1_1 = require("@noble/secp256k1");
const common_1 = require("@stacks/common");
const network_1 = require("@stacks/network");
const c32check_1 = require("c32check");
const address_1 = require("./address");
const constants_1 = require("./constants");
const utils_1 = require("./utils");
const wire_1 = require("./wire");
secp256k1_1.utils.hmacSha256Sync = (key, ...msgs) => {
    const h = hmac_1.hmac.create(sha256_1.sha256, key);
    msgs.forEach(msg => h.update(msg));
    return h.digest();
};
function getAddressFromPrivateKey(privateKey, network = 'mainnet') {
    network = (0, network_1.networkFrom)(network);
    const publicKey = privateKeyToPublic(privateKey);
    return getAddressFromPublicKey(publicKey, network);
}
exports.getAddressFromPrivateKey = getAddressFromPrivateKey;
function getAddressFromPublicKey(publicKey, network = 'mainnet') {
    network = (0, network_1.networkFrom)(network);
    publicKey = typeof publicKey === 'string' ? (0, common_1.hexToBytes)(publicKey) : publicKey;
    const addrVer = (0, address_1.addressHashModeToVersion)(constants_1.AddressHashMode.P2PKH, network);
    const addr = (0, wire_1.addressFromVersionHash)(addrVer, (0, utils_1.hashP2PKH)(publicKey));
    const addrString = (0, wire_1.addressToString)(addr);
    return addrString;
}
exports.getAddressFromPublicKey = getAddressFromPublicKey;
function createStacksPublicKey(publicKey) {
    publicKey = typeof publicKey === 'string' ? (0, common_1.hexToBytes)(publicKey) : publicKey;
    return {
        type: wire_1.StacksWireType.PublicKey,
        data: publicKey,
    };
}
exports.createStacksPublicKey = createStacksPublicKey;
function publicKeyFromSignatureVrs(messageHash, messageSignature, pubKeyEncoding = constants_1.PubKeyEncoding.Compressed) {
    const parsedSignature = (0, common_1.parseRecoverableSignatureVrs)(messageSignature);
    const signature = new secp256k1_1.Signature((0, common_1.hexToBigInt)(parsedSignature.r), (0, common_1.hexToBigInt)(parsedSignature.s));
    const point = secp256k1_1.Point.fromSignature(messageHash, signature, parsedSignature.recoveryId);
    const compressed = pubKeyEncoding === constants_1.PubKeyEncoding.Compressed;
    return point.toHex(compressed);
}
exports.publicKeyFromSignatureVrs = publicKeyFromSignatureVrs;
function publicKeyFromSignatureRsv(messageHash, messageSignature, pubKeyEncoding = constants_1.PubKeyEncoding.Compressed) {
    return publicKeyFromSignatureVrs(messageHash, (0, common_1.signatureRsvToVrs)(messageSignature), pubKeyEncoding);
}
exports.publicKeyFromSignatureRsv = publicKeyFromSignatureRsv;
function privateKeyToHex(publicKey) {
    return typeof publicKey === 'string' ? publicKey : (0, common_1.bytesToHex)(publicKey);
}
exports.privateKeyToHex = privateKeyToHex;
exports.publicKeyToHex = privateKeyToHex;
exports.isPrivateKeyCompressed = privateKeyIsCompressed;
function privateKeyIsCompressed(privateKey) {
    const length = typeof privateKey === 'string' ? privateKey.length / 2 : privateKey.byteLength;
    return length === common_1.PRIVATE_KEY_BYTES_COMPRESSED;
}
exports.privateKeyIsCompressed = privateKeyIsCompressed;
exports.isPublicKeyCompressed = publicKeyIsCompressed;
function publicKeyIsCompressed(publicKey) {
    return !(0, exports.publicKeyToHex)(publicKey).startsWith('04');
}
exports.publicKeyIsCompressed = publicKeyIsCompressed;
function privateKeyToPublic(privateKey) {
    privateKey = (0, common_1.privateKeyToBytes)(privateKey);
    const isCompressed = privateKeyIsCompressed(privateKey);
    return (0, common_1.bytesToHex)((0, secp256k1_1.getPublicKey)(privateKey.slice(0, 32), isCompressed));
}
exports.privateKeyToPublic = privateKeyToPublic;
function compressPublicKey(publicKey) {
    return secp256k1_1.Point.fromHex((0, exports.publicKeyToHex)(publicKey)).toHex(true);
}
exports.compressPublicKey = compressPublicKey;
function uncompressPublicKey(publicKey) {
    return secp256k1_1.Point.fromHex((0, exports.publicKeyToHex)(publicKey)).toHex(false);
}
exports.uncompressPublicKey = uncompressPublicKey;
exports.makeRandomPrivKey = randomPrivateKey;
function randomPrivateKey() {
    return compressPrivateKey(secp256k1_1.utils.randomPrivateKey());
}
exports.randomPrivateKey = randomPrivateKey;
function signWithKey(privateKey, messageHash) {
    privateKey = (0, common_1.privateKeyToBytes)(privateKey);
    const [rawSignature, recoveryId] = (0, secp256k1_1.signSync)(messageHash, privateKey.slice(0, 32), {
        canonical: true,
        recovered: true,
    });
    if (recoveryId == null) {
        throw new Error('No signature recoveryId received');
    }
    const recoveryIdHex = (0, common_1.intToHex)(recoveryId, 1);
    return recoveryIdHex + secp256k1_1.Signature.fromHex(rawSignature).toCompactHex();
}
exports.signWithKey = signWithKey;
function signMessageHashRsv({ messageHash, privateKey, }) {
    return (0, common_1.signatureVrsToRsv)(signWithKey(privateKey, messageHash));
}
exports.signMessageHashRsv = signMessageHashRsv;
function compressPrivateKey(privateKey) {
    privateKey = privateKeyToHex(privateKey);
    return privateKey.length == common_1.PRIVATE_KEY_BYTES_COMPRESSED * 2
        ? privateKey
        : `${privateKey}01`;
}
exports.compressPrivateKey = compressPrivateKey;
function privateKeyToAddress(privateKey, network) {
    const publicKey = privateKeyToPublic(privateKey);
    return publicKeyToAddressSingleSig(publicKey, network);
}
exports.privateKeyToAddress = privateKeyToAddress;
function publicKeyToAddress(...args) {
    if (typeof args[0] === 'number')
        return _publicKeyToAddress(...args);
    return publicKeyToAddressSingleSig(...args);
}
exports.publicKeyToAddress = publicKeyToAddress;
function _publicKeyToAddress(version, publicKey) {
    publicKey = typeof publicKey === 'string' ? (0, common_1.hexToBytes)(publicKey) : publicKey;
    return (0, c32check_1.c32address)(version, (0, common_1.bytesToHex)((0, utils_1.hash160)(publicKey)));
}
function publicKeyToAddressSingleSig(publicKey, network) {
    network = network ? (0, network_1.networkFrom)(network) : network_1.STACKS_MAINNET;
    publicKey = typeof publicKey === 'string' ? (0, common_1.hexToBytes)(publicKey) : publicKey;
    return (0, c32check_1.c32address)(network.addressVersion.singleSig, (0, common_1.bytesToHex)((0, utils_1.hash160)(publicKey)));
}
exports.publicKeyToAddressSingleSig = publicKeyToAddressSingleSig;
//# sourceMappingURL=keys.js.map