import { ClarityValue } from './clarity';
import { AssetString } from './types';
export type FungibleComparator = 'eq' | 'gt' | 'gte' | 'lt' | 'lte';
export interface StxPostCondition {
    type: 'stx-postcondition';
    address: string;
    condition: `${FungibleComparator}`;
    amount: string | bigint | number;
}
export type FungiblePostCondition = {
    type: 'ft-postcondition';
    address: string;
    condition: `${FungibleComparator}`;
    asset: AssetString;
    amount: string | bigint | number;
};
export type NonFungibleComparator = 'sent' | 'not-sent';
export type NonFungiblePostCondition = {
    type: 'nft-postcondition';
    address: string;
    condition: `${NonFungibleComparator}`;
    asset: AssetString;
    assetId: ClarityValue;
};
export type PostCondition = StxPostCondition | FungiblePostCondition | NonFungiblePostCondition;
export type PostConditionModeName = 'allow' | 'deny';
