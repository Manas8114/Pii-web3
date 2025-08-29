import { IntegerType } from '@stacks/common';
import { ClarityValue, PrincipalCV } from '../clarity';
import { AddressVersion, ClarityVersion, FungibleConditionCode, NonFungibleConditionCode, PayloadType, PostConditionPrincipalId, PostConditionType, PubKeyEncoding, TenureChangeCause } from '../constants';
export declare enum StacksWireType {
    Address = 0,
    Principal = 1,
    LengthPrefixedString = 2,
    MemoString = 3,
    Asset = 4,
    PostCondition = 5,
    PublicKey = 6,
    LengthPrefixedList = 7,
    Payload = 8,
    MessageSignature = 9,
    StructuredDataSignature = 10,
    TransactionAuthField = 11
}
type WhenWireTypeMap<T> = Record<StacksWireType, T>;
export declare function whenWireType(wireType: StacksWireType): <T>(wireTypeMap: WhenWireTypeMap<T>) => T;
export type StacksWire = AddressWire | PostConditionPrincipalWire | LengthPrefixedStringWire | LengthPrefixedList | PayloadWire | MemoStringWire | AssetWire | PostConditionWire | PublicKeyWire | TransactionAuthFieldWire | MessageSignatureWire;
export interface MemoStringWire {
    readonly type: StacksWireType.MemoString;
    readonly content: string;
}
export interface PublicKeyWire {
    readonly type: StacksWireType.PublicKey;
    readonly data: Uint8Array;
}
export interface LengthPrefixedList<TWire extends StacksWire = StacksWire> {
    readonly type: StacksWireType.LengthPrefixedList;
    readonly lengthPrefixBytes: number;
    readonly values: TWire[];
}
export interface AddressWire {
    readonly type: StacksWireType.Address;
    readonly version: AddressVersion;
    readonly hash160: string;
}
export interface MessageSignatureWire {
    readonly type: StacksWireType.MessageSignature;
    data: string;
}
export type PayloadWire = TokenTransferPayloadWire | ContractCallPayload | SmartContractPayloadWire | VersionedSmartContractPayloadWire | PoisonPayloadWire | CoinbasePayloadWire | CoinbasePayloadToAltRecipient | NakamotoCoinbasePayloadWire | TenureChangePayloadWire;
export interface TokenTransferPayloadWire {
    readonly type: StacksWireType.Payload;
    readonly payloadType: PayloadType.TokenTransfer;
    readonly recipient: PrincipalCV;
    readonly amount: bigint;
    readonly memo: MemoStringWire;
}
export type PayloadInput = (TokenTransferPayloadWire | (Omit<TokenTransferPayloadWire, 'amount'> & {
    amount: IntegerType;
})) | ContractCallPayload | SmartContractPayloadWire | VersionedSmartContractPayloadWire | PoisonPayloadWire | CoinbasePayloadWire | CoinbasePayloadToAltRecipient | NakamotoCoinbasePayloadWire | TenureChangePayloadWire;
export interface ContractCallPayload {
    readonly type: StacksWireType.Payload;
    readonly payloadType: PayloadType.ContractCall;
    readonly contractAddress: AddressWire;
    readonly contractName: LengthPrefixedStringWire;
    readonly functionName: LengthPrefixedStringWire;
    readonly functionArgs: ClarityValue[];
}
export interface SmartContractPayloadWire {
    readonly type: StacksWireType.Payload;
    readonly payloadType: PayloadType.SmartContract;
    readonly contractName: LengthPrefixedStringWire;
    readonly codeBody: LengthPrefixedStringWire;
}
export interface VersionedSmartContractPayloadWire {
    readonly type: StacksWireType.Payload;
    readonly payloadType: PayloadType.VersionedSmartContract;
    readonly clarityVersion: ClarityVersion;
    readonly contractName: LengthPrefixedStringWire;
    readonly codeBody: LengthPrefixedStringWire;
}
export interface PoisonPayloadWire {
    readonly type: StacksWireType.Payload;
    readonly payloadType: PayloadType.PoisonMicroblock;
}
export interface CoinbasePayloadWire {
    readonly type: StacksWireType.Payload;
    readonly payloadType: PayloadType.Coinbase;
    readonly coinbaseBytes: Uint8Array;
}
export interface CoinbasePayloadToAltRecipient {
    readonly type: StacksWireType.Payload;
    readonly payloadType: PayloadType.CoinbaseToAltRecipient;
    readonly coinbaseBytes: Uint8Array;
    readonly recipient: PrincipalCV;
}
export interface NakamotoCoinbasePayloadWire {
    readonly type: StacksWireType.Payload;
    readonly payloadType: PayloadType.NakamotoCoinbase;
    readonly coinbaseBytes: Uint8Array;
    readonly recipient?: PrincipalCV;
    readonly vrfProof: Uint8Array;
}
export interface TenureChangePayloadWire {
    readonly type: StacksWireType.Payload;
    readonly payloadType: PayloadType.TenureChange;
    readonly tenureHash: string;
    readonly previousTenureHash: string;
    readonly burnViewHash: string;
    readonly previousTenureEnd: string;
    readonly previousTenureBlocks: number;
    readonly cause: TenureChangeCause;
    readonly publicKeyHash: string;
}
export interface OriginPrincipalWire {
    readonly type: StacksWireType.Principal;
    readonly prefix: PostConditionPrincipalId.Origin;
}
export interface StandardPrincipalWire {
    readonly type: StacksWireType.Principal;
    readonly prefix: PostConditionPrincipalId.Standard;
    readonly address: AddressWire;
}
export interface ContractPrincipalWire {
    readonly type: StacksWireType.Principal;
    readonly prefix: PostConditionPrincipalId.Contract;
    readonly address: AddressWire;
    readonly contractName: LengthPrefixedStringWire;
}
export interface LengthPrefixedStringWire {
    readonly type: StacksWireType.LengthPrefixedString;
    readonly content: string;
    readonly lengthPrefixBytes: number;
    readonly maxLengthBytes: number;
}
export interface AssetWire {
    readonly type: StacksWireType.Asset;
    readonly address: AddressWire;
    readonly contractName: LengthPrefixedStringWire;
    readonly assetName: LengthPrefixedStringWire;
}
export interface STXPostConditionWire {
    readonly type: StacksWireType.PostCondition;
    readonly conditionType: PostConditionType.STX;
    readonly principal: PostConditionPrincipalWire;
    readonly conditionCode: FungibleConditionCode;
    readonly amount: bigint;
}
export interface FungiblePostConditionWire {
    readonly type: StacksWireType.PostCondition;
    readonly conditionType: PostConditionType.Fungible;
    readonly principal: PostConditionPrincipalWire;
    readonly conditionCode: FungibleConditionCode;
    readonly amount: bigint;
    readonly asset: AssetWire;
}
export interface NonFungiblePostConditionWire {
    readonly type: StacksWireType.PostCondition;
    readonly conditionType: PostConditionType.NonFungible;
    readonly principal: PostConditionPrincipalWire;
    readonly conditionCode: NonFungibleConditionCode;
    readonly asset: AssetWire;
    readonly assetName: ClarityValue;
}
export type PostConditionWire = STXPostConditionWire | FungiblePostConditionWire | NonFungiblePostConditionWire;
export type PostConditionPrincipalWire = OriginPrincipalWire | StandardPrincipalWire | ContractPrincipalWire;
export interface TransactionAuthFieldWire {
    type: StacksWireType.TransactionAuthField;
    pubKeyEncoding: PubKeyEncoding;
    contents: TransactionAuthFieldContentsWire;
}
export type TransactionAuthFieldContentsWire = PublicKeyWire | MessageSignatureWire;
export interface TransactionAuthFieldWire {
    type: StacksWireType.TransactionAuthField;
    pubKeyEncoding: PubKeyEncoding;
    contents: TransactionAuthFieldContentsWire;
}
export interface StructuredDataSignatureWire {
    readonly type: StacksWireType.StructuredDataSignature;
    data: string;
}
export {};
