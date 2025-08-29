import { IntegerType, PrivateKey, PublicKey } from '@stacks/common';
import { BytesReader } from './BytesReader';
import { AddressHashMode, AuthType, MultiSigHashMode, PubKeyEncoding, SingleSigHashMode } from './constants';
import { MessageSignatureWire, PublicKeyWire, TransactionAuthFieldWire } from './wire';
export declare function emptyMessageSignature(): MessageSignatureWire;
export interface SingleSigSpendingCondition {
    hashMode: SingleSigHashMode;
    signer: string;
    nonce: bigint;
    fee: bigint;
    keyEncoding: PubKeyEncoding;
    signature: MessageSignatureWire;
}
export interface SingleSigSpendingConditionOpts extends Omit<SingleSigSpendingCondition, 'nonce' | 'fee'> {
    nonce: IntegerType;
    fee: IntegerType;
}
export interface MultiSigSpendingCondition {
    hashMode: MultiSigHashMode;
    signer: string;
    nonce: bigint;
    fee: bigint;
    fields: TransactionAuthFieldWire[];
    signaturesRequired: number;
}
export interface MultiSigSpendingConditionOpts extends Omit<MultiSigSpendingCondition, 'nonce' | 'fee'> {
    nonce: IntegerType;
    fee: IntegerType;
}
export type SpendingCondition = SingleSigSpendingCondition | MultiSigSpendingCondition;
export type SpendingConditionOpts = SingleSigSpendingConditionOpts | MultiSigSpendingConditionOpts;
export declare function createSpendingCondition(options: {
    publicKey: string;
    nonce: IntegerType;
    fee: IntegerType;
} | {
    publicKeys: string[];
    numSignatures: number;
    nonce: IntegerType;
    fee: IntegerType;
}): SingleSigSpendingCondition | MultiSigSpendingCondition;
export declare function createSingleSigSpendingCondition(hashMode: SingleSigHashMode, pubKey: PublicKey, nonce: IntegerType, fee: IntegerType): SingleSigSpendingCondition;
export declare function createMultiSigSpendingCondition(hashMode: MultiSigHashMode, numSigs: number, pubKeys: string[], nonce: IntegerType, fee: IntegerType): MultiSigSpendingCondition;
export declare function isSingleSig(condition: SpendingConditionOpts): condition is SingleSigSpendingConditionOpts;
export declare function isSequentialMultiSig(hashMode: AddressHashMode): boolean;
export declare function isNonSequentialMultiSig(hashMode: AddressHashMode): boolean;
export declare function serializeSingleSigSpendingCondition(condition: SingleSigSpendingConditionOpts): string;
export declare function serializeSingleSigSpendingConditionBytes(condition: SingleSigSpendingConditionOpts): Uint8Array;
export declare function serializeMultiSigSpendingCondition(condition: MultiSigSpendingConditionOpts): string;
export declare function serializeMultiSigSpendingConditionBytes(condition: MultiSigSpendingConditionOpts): Uint8Array;
export declare function deserializeSingleSigSpendingCondition(hashMode: SingleSigHashMode, bytesReader: BytesReader): SingleSigSpendingCondition;
export declare function deserializeMultiSigSpendingCondition(hashMode: MultiSigHashMode, bytesReader: BytesReader): MultiSigSpendingCondition;
export declare function serializeSpendingCondition(condition: SpendingConditionOpts): string;
export declare function serializeSpendingConditionBytes(condition: SpendingConditionOpts): Uint8Array;
export declare function deserializeSpendingCondition(bytesReader: BytesReader): SpendingCondition;
export declare function sigHashPreSign(curSigHash: string, authType: AuthType, fee: IntegerType, nonce: IntegerType): string;
export declare function nextSignature(curSigHash: string, authType: AuthType, fee: IntegerType, nonce: IntegerType, privateKey: PrivateKey): {
    nextSig: string;
    nextSigHash: string;
};
export declare function nextVerification(initialSigHash: string, authType: AuthType, fee: IntegerType, nonce: IntegerType, pubKeyEncoding: PubKeyEncoding, signature: string): {
    pubKey: PublicKeyWire;
    nextSigHash: string;
};
export type Authorization = StandardAuthorization | SponsoredAuthorization;
export interface StandardAuthorization {
    authType: AuthType.Standard;
    spendingCondition: SpendingCondition;
}
export interface SponsoredAuthorization {
    authType: AuthType.Sponsored;
    spendingCondition: SpendingCondition;
    sponsorSpendingCondition: SpendingCondition;
}
export declare function createStandardAuth(spendingCondition: SpendingCondition): StandardAuthorization;
export declare function createSponsoredAuth(spendingCondition: SpendingCondition, sponsorSpendingCondition?: SpendingCondition): Authorization;
export declare function intoInitialSighashAuth(auth: Authorization): Authorization;
export declare function verifyOrigin(auth: Authorization, initialSigHash: string): string;
export declare function setFee(auth: Authorization, amount: IntegerType): Authorization;
export declare function getFee(auth: Authorization): bigint;
export declare function setNonce(auth: Authorization, nonce: IntegerType): Authorization;
export declare function setSponsorNonce(auth: SponsoredAuthorization, nonce: IntegerType): Authorization;
export declare function setSponsor(auth: SponsoredAuthorization, sponsorSpendingCondition: SpendingConditionOpts): Authorization;
export declare function serializeAuthorization(auth: Authorization): string;
export declare function serializeAuthorizationBytes(auth: Authorization): Uint8Array;
export declare function deserializeAuthorization(bytesReader: BytesReader): Authorization;
