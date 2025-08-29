import { PrivateKey } from '@stacks/common';
import { ClarityValue } from './clarity';
export declare const STRUCTURED_DATA_PREFIX: Uint8Array;
export declare function hashStructuredData(structuredData: ClarityValue): string;
export declare function hashStructuredDataBytes(structuredData: ClarityValue): Uint8Array;
export declare function encodeStructuredData(opts: {
    message: ClarityValue;
    domain: ClarityValue;
}): string;
export declare function encodeStructuredDataBytes({ message, domain, }: {
    message: ClarityValue;
    domain: ClarityValue;
}): Uint8Array;
export declare function decodeStructuredDataSignature(signature: string | Uint8Array): {
    domainHash: string;
    messageHash: string;
};
export declare function decodeStructuredDataSignatureBytes(signature: string | Uint8Array): {
    domainHash: Uint8Array;
    messageHash: Uint8Array;
};
export declare function signStructuredData({ message, domain, privateKey, }: {
    message: ClarityValue;
    domain: ClarityValue;
    privateKey: PrivateKey;
}): string;
