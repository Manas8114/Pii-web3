import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes, hexToBytes } from '@stacks/common';
import { ClarityType, serializeCVBytes } from './clarity';
import { signMessageHashRsv } from './keys';
export const STRUCTURED_DATA_PREFIX = new Uint8Array([0x53, 0x49, 0x50, 0x30, 0x31, 0x38]);
export function hashStructuredData(structuredData) {
    return bytesToHex(sha256(serializeCVBytes(structuredData)));
}
export function hashStructuredDataBytes(structuredData) {
    return sha256(serializeCVBytes(structuredData));
}
const hash256BytesLength = 32;
function isDomain(value) {
    if (value.type !== ClarityType.Tuple)
        return false;
    if (!['name', 'version', 'chain-id'].every(key => key in value.value))
        return false;
    if (!['name', 'version'].every(key => value.value[key].type === ClarityType.StringASCII))
        return false;
    if (value.value['chain-id'].type !== ClarityType.UInt)
        return false;
    return true;
}
export function encodeStructuredData(opts) {
    const bytes = encodeStructuredDataBytes(opts);
    return bytesToHex(bytes);
}
export function encodeStructuredDataBytes({ message, domain, }) {
    const structuredDataHash = hashStructuredDataBytes(message);
    if (!isDomain(domain)) {
        throw new Error("domain parameter must be a valid domain of type TupleCV with keys 'name', 'version', 'chain-id' with respective types StringASCII, StringASCII, UInt");
    }
    const domainHash = hashStructuredDataBytes(domain);
    return concatBytes(STRUCTURED_DATA_PREFIX, domainHash, structuredDataHash);
}
export function decodeStructuredDataSignature(signature) {
    const bytes = decodeStructuredDataSignatureBytes(signature);
    return {
        domainHash: bytesToHex(bytes.domainHash),
        messageHash: bytesToHex(bytes.messageHash),
    };
}
export function decodeStructuredDataSignatureBytes(signature) {
    const encodedMessageBytes = typeof signature === 'string' ? hexToBytes(signature) : signature;
    const domainHash = encodedMessageBytes.slice(STRUCTURED_DATA_PREFIX.length, STRUCTURED_DATA_PREFIX.length + hash256BytesLength);
    const messageHash = encodedMessageBytes.slice(STRUCTURED_DATA_PREFIX.length + hash256BytesLength);
    return {
        domainHash,
        messageHash,
    };
}
export function signStructuredData({ message, domain, privateKey, }) {
    const structuredDataHash = bytesToHex(sha256(encodeStructuredDataBytes({ message, domain })));
    return signMessageHashRsv({
        messageHash: structuredDataHash,
        privateKey,
    });
}
//# sourceMappingURL=structuredDataSignature.js.map