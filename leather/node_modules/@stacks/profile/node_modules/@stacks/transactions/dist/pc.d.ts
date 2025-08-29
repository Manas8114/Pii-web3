import { IntegerType } from '@stacks/common';
import { ClarityValue } from './clarity';
import { FungibleComparator, FungiblePostCondition, NonFungibleComparator, NonFungiblePostCondition, PostCondition, StxPostCondition } from './postcondition-types';
import { AddressString, AssetString, ContractIdString } from './types';
export declare function principal(principal: AddressString | ContractIdString): PartialPcWithPrincipal;
export declare function origin(): PartialPcWithPrincipal;
declare class PartialPcWithPrincipal {
    private address;
    constructor(address: string);
    willSendEq(amount: IntegerType): PartialPcFtWithCode;
    willSendLte(amount: IntegerType): PartialPcFtWithCode;
    willSendLt(amount: IntegerType): PartialPcFtWithCode;
    willSendGte(amount: IntegerType): PartialPcFtWithCode;
    willSendGt(amount: IntegerType): PartialPcFtWithCode;
    willSendAsset(): PartialPcNftWithCode;
    willNotSendAsset(): PartialPcNftWithCode;
}
declare class PartialPcFtWithCode {
    private address;
    private amount;
    private code;
    constructor(address: string, amount: IntegerType, code: FungibleComparator);
    ustx(): StxPostCondition;
    ft(contractId: ContractIdString, tokenName: string): FungiblePostCondition;
}
declare class PartialPcNftWithCode {
    private address;
    private code;
    constructor(address: string, code: NonFungibleComparator);
    nft(assetName: AssetString, assetId: ClarityValue): NonFungiblePostCondition;
    nft(contractId: ContractIdString, tokenName: string, assetId: ClarityValue): NonFungiblePostCondition;
}
export declare function fromHex(hex: string): PostCondition;
export {};
