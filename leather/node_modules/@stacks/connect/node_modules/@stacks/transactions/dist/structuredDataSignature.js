"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.signStructuredData = exports.decodeStructuredDataSignatureBytes = exports.decodeStructuredDataSignature = exports.encodeStructuredDataBytes = exports.encodeStructuredData = exports.hashStructuredDataBytes = exports.hashStructuredData = exports.STRUCTURED_DATA_PREFIX = void 0;
const sha256_1 = require("@noble/hashes/sha256");
const common_1 = require("@stacks/common");
const clarity_1 = require("./clarity");
const keys_1 = require("./keys");
exports.STRUCTURED_DATA_PREFIX = new Uint8Array([0x53, 0x49, 0x50, 0x30, 0x31, 0x38]);
function hashStructuredData(structuredData) {
    return (0, common_1.bytesToHex)((0, sha256_1.sha256)((0, clarity_1.serializeCVBytes)(structuredData)));
}
exports.hashStructuredData = hashStructuredData;
function hashStructuredDataBytes(structuredData) {
    return (0, sha256_1.sha256)((0, clarity_1.serializeCVBytes)(structuredData));
}
exports.hashStructuredDataBytes = hashStructuredDataBytes;
const hash256BytesLength = 32;
function isDomain(value) {
    if (value.type !== clarity_1.ClarityType.Tuple)
        return false;
    if (!['name', 'version', 'chain-id'].every(key => key in value.value))
        return false;
    if (!['name', 'version'].every(key => value.value[key].type === clarity_1.ClarityType.StringASCII))
        return false;
    if (value.value['chain-id'].type !== clarity_1.ClarityType.UInt)
        return false;
    return true;
}
function encodeStructuredData(opts) {
    const bytes = encodeStructuredDataBytes(opts);
    return (0, common_1.bytesToHex)(bytes);
}
exports.encodeStructuredData = encodeStructuredData;
function encodeStructuredDataBytes({ message, domain, }) {
    const structuredDataHash = hashStructuredDataBytes(message);
    if (!isDomain(domain)) {
        throw new Error("domain parameter must be a valid domain of type TupleCV with keys 'name', 'version', 'chain-id' with respective types StringASCII, StringASCII, UInt");
    }
    const domainHash = hashStructuredDataBytes(domain);
    return (0, common_1.concatBytes)(exports.STRUCTURED_DATA_PREFIX, domainHash, structuredDataHash);
}
exports.encodeStructuredDataBytes = encodeStructuredDataBytes;
function decodeStructuredDataSignature(signature) {
    const bytes = decodeStructuredDataSignatureBytes(signature);
    return {
        domainHash: (0, common_1.bytesToHex)(bytes.domainHash),
        messageHash: (0, common_1.bytesToHex)(bytes.messageHash),
    };
}
exports.decodeStructuredDataSignature = decodeStructuredDataSignature;
function decodeStructuredDataSignatureBytes(signature) {
    const encodedMessageBytes = typeof signature === 'string' ? (0, common_1.hexToBytes)(signature) : signature;
    const domainHash = encodedMessageBytes.slice(exports.STRUCTURED_DATA_PREFIX.length, exports.STRUCTURED_DATA_PREFIX.length + hash256BytesLength);
    const messageHash = encodedMessageBytes.slice(exports.STRUCTURED_DATA_PREFIX.length + hash256BytesLength);
    return {
        domainHash,
        messageHash,
    };
}
exports.decodeStructuredDataSignatureBytes = decodeStructuredDataSignatureBytes;
function signStructuredData({ message, domain, privateKey, }) {
    const structuredDataHash = (0, common_1.bytesToHex)((0, sha256_1.sha256)(encodeStructuredDataBytes({ message, domain })));
    return (0, keys_1.signMessageHashRsv)({
        messageHash: structuredDataHash,
        privateKey,
    });
}
exports.signStructuredData = signStructuredData;
//# sourceMappingURL=structuredDataSignature.js.map