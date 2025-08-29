import { NetworkClientParam } from '@stacks/network';
import { ClarityValue, NoneCV } from './clarity';
import { ClarityAbi } from './contract-abi';
import { StacksTransactionWire } from './transaction';
import { FeeEstimation, TxBroadcastResult } from './types';
export declare const BROADCAST_PATH = "/v2/transactions";
export declare const TRANSFER_FEE_ESTIMATE_PATH = "/v2/fees/transfer";
export declare const TRANSACTION_FEE_ESTIMATE_PATH = "/v2/fees/transaction";
export declare const ACCOUNT_PATH = "/v2/accounts";
export declare const CONTRACT_ABI_PATH = "/v2/contracts/interface";
export declare const READONLY_FUNCTION_CALL_PATH = "/v2/contracts/call-read";
export declare const MAP_ENTRY_PATH = "/v2/map_entry";
export declare function broadcastTransaction({ transaction: txOpt, attachment: attachOpt, network: _network, client: _client, }: {
    transaction: StacksTransactionWire;
    attachment?: Uint8Array | string;
} & NetworkClientParam): Promise<TxBroadcastResult>;
export declare function fetchNonce(opts: {
    address: string;
} & NetworkClientParam): Promise<bigint>;
export declare function fetchFeeEstimateTransfer({ transaction: txOpt, network: _network, client: _client, }: {
    transaction: StacksTransactionWire | number;
} & NetworkClientParam): Promise<bigint>;
export declare function fetchFeeEstimateTransaction({ payload, estimatedLength, network, client: _client, }: {
    payload: string;
    estimatedLength?: number;
} & NetworkClientParam): Promise<[FeeEstimation, FeeEstimation, FeeEstimation]>;
export declare function fetchFeeEstimate({ transaction: txOpt, network: _network, client: _client, }: {
    transaction: StacksTransactionWire;
} & NetworkClientParam): Promise<bigint | number>;
export declare function fetchAbi({ contractAddress: address, contractName: name, network, client: _client, }: {
    contractAddress: string;
    contractName: string;
} & NetworkClientParam): Promise<ClarityAbi>;
export declare function fetchCallReadOnlyFunction({ contractName, contractAddress, functionName, functionArgs, senderAddress, network, client: _client, }: {
    contractName: string;
    contractAddress: string;
    functionName: string;
    functionArgs: ClarityValue[];
    senderAddress: string;
} & NetworkClientParam): Promise<ClarityValue>;
export declare function fetchContractMapEntry<T extends ClarityValue = ClarityValue>({ contractAddress, contractName, mapName, mapKey, network, client: _client, }: {
    contractAddress: string;
    contractName: string;
    mapName: string;
    mapKey: ClarityValue;
} & NetworkClientParam): Promise<T | NoneCV>;
