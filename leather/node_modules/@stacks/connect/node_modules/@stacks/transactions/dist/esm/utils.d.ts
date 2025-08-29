import { ClarityValue } from './clarity';
import { ContractIdString } from './types';
export { verify as verifySignature } from '@noble/secp256k1';
export declare const randomBytes: (bytesLength?: number) => Uint8Array;
export declare const leftPadHex: (hexString: string) => string;
export declare const leftPadHexToLength: (hexString: string, length: number) => string;
export declare const rightPadHexToLength: (hexString: string, length: number) => string;
export declare const exceedsMaxLengthBytes: (string: string, maxLengthBytes: number) => boolean;
export declare function omit<T, K extends keyof any>(obj: T, prop: K): Omit<T, K>;
export declare const hash160: (input: Uint8Array) => Uint8Array;
export declare const txidFromData: (data: Uint8Array) => string;
export declare const txidFromBytes: (data: Uint8Array) => string;
export declare function isClarityName(name: string): boolean;
export declare function cvToHex(cv: ClarityValue): string;
export declare function hexToCV(hex: string): ClarityValue;
export interface ReadOnlyFunctionSuccessResponse {
    okay: true;
    result: string;
}
export interface ReadOnlyFunctionErrorResponse {
    okay: false;
    cause: string;
}
export type ReadOnlyFunctionResponse = ReadOnlyFunctionSuccessResponse | ReadOnlyFunctionErrorResponse;
export declare const parseReadOnlyResponse: (response: ReadOnlyFunctionResponse) => ClarityValue;
export declare const validateStacksAddress: (address: string) => boolean;
export declare function parseContractId(contractId: ContractIdString): string[];
