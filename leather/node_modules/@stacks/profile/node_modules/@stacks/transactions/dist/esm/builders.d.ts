import { IntegerType, PrivateKey, PublicKey } from '@stacks/common';
import { NetworkClientParam } from '@stacks/network';
import { ClarityValue, PrincipalCV } from './clarity';
import { AddressHashMode, ClarityVersion, PostConditionMode } from './constants';
import { ClarityAbi } from './contract-abi';
import { PostCondition, PostConditionModeName } from './postcondition-types';
import { StacksTransactionWire } from './transaction';
import { PostConditionWire } from './wire';
export interface MultiSigOptions {
    numSignatures: number;
    publicKeys: string[];
    signerKeys?: string[];
}
export interface UnsignedMultiSigOptions {
    numSignatures: number;
    publicKeys: PublicKey[];
    address?: string;
    useNonSequentialMultiSig?: boolean;
}
export type SignedMultiSigOptions = UnsignedMultiSigOptions & {
    signerKeys: PrivateKey[];
};
export type TokenTransferOptions = {
    recipient: string | PrincipalCV;
    amount: IntegerType;
    fee?: IntegerType;
    nonce?: IntegerType;
    memo?: string;
    sponsored?: boolean;
} & NetworkClientParam;
export interface UnsignedTokenTransferOptions extends TokenTransferOptions {
    publicKey: PublicKey;
}
export interface SignedTokenTransferOptions extends TokenTransferOptions {
    senderKey: PrivateKey;
}
export type UnsignedMultiSigTokenTransferOptions = TokenTransferOptions & UnsignedMultiSigOptions;
export type SignedMultiSigTokenTransferOptions = TokenTransferOptions & SignedMultiSigOptions;
export declare function makeUnsignedSTXTokenTransfer(txOptions: UnsignedTokenTransferOptions | UnsignedMultiSigTokenTransferOptions): Promise<StacksTransactionWire>;
export declare function makeSTXTokenTransfer(txOptions: SignedTokenTransferOptions | SignedMultiSigTokenTransferOptions): Promise<StacksTransactionWire>;
export type BaseContractDeployOptions = {
    clarityVersion?: ClarityVersion;
    contractName: string;
    codeBody: string;
    fee?: IntegerType;
    nonce?: IntegerType;
    postConditionMode?: PostConditionModeName | PostConditionMode;
    postConditions?: (PostCondition | PostConditionWire | string)[];
    sponsored?: boolean;
} & NetworkClientParam;
export interface UnsignedContractDeployOptions extends BaseContractDeployOptions {
    publicKey: PublicKey;
}
export interface SignedContractDeployOptions extends BaseContractDeployOptions {
    senderKey: PrivateKey;
}
export interface ContractDeployOptions extends SignedContractDeployOptions {
}
export type UnsignedMultiSigContractDeployOptions = BaseContractDeployOptions & UnsignedMultiSigOptions;
export type SignedMultiSigContractDeployOptions = BaseContractDeployOptions & SignedMultiSigOptions;
export declare function makeContractDeploy(txOptions: SignedContractDeployOptions | SignedMultiSigContractDeployOptions): Promise<StacksTransactionWire>;
export declare function makeUnsignedContractDeploy(txOptions: UnsignedContractDeployOptions | UnsignedMultiSigContractDeployOptions): Promise<StacksTransactionWire>;
export type ContractCallOptions = {
    contractAddress: string;
    contractName: string;
    functionName: string;
    functionArgs: ClarityValue[];
    fee?: IntegerType;
    nonce?: IntegerType;
    postConditionMode?: PostConditionModeName | PostConditionMode;
    postConditions?: (PostCondition | PostConditionWire | string)[];
    validateWithAbi?: boolean | ClarityAbi;
    sponsored?: boolean;
} & NetworkClientParam;
export interface UnsignedContractCallOptions extends ContractCallOptions {
    publicKey: PrivateKey;
}
export interface SignedContractCallOptions extends ContractCallOptions {
    senderKey: PublicKey;
}
export type UnsignedMultiSigContractCallOptions = ContractCallOptions & UnsignedMultiSigOptions;
export type SignedMultiSigContractCallOptions = ContractCallOptions & SignedMultiSigOptions;
export declare function makeUnsignedContractCall(txOptions: UnsignedContractCallOptions | UnsignedMultiSigContractCallOptions): Promise<StacksTransactionWire>;
export declare function makeContractCall(txOptions: SignedContractCallOptions | SignedMultiSigContractCallOptions): Promise<StacksTransactionWire>;
export type SponsorOptionsOpts = {
    transaction: StacksTransactionWire;
    sponsorPrivateKey: PrivateKey;
    fee?: IntegerType;
    sponsorNonce?: IntegerType;
    sponsorAddressHashmode?: AddressHashMode;
} & NetworkClientParam;
export declare function sponsorTransaction(sponsorOptions: SponsorOptionsOpts): Promise<StacksTransactionWire>;
