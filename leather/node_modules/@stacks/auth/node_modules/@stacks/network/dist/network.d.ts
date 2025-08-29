import { FetchFn, ClientOpts, ApiKeyMiddlewareOpts } from '@stacks/common';
import { ClientParam } from '@stacks/common';
export type StacksNetwork = {
    chainId: number;
    transactionVersion: number;
    peerNetworkId: number;
    magicBytes: string;
    bootAddress: string;
    addressVersion: {
        singleSig: number;
        multiSig: number;
    };
    client: {
        baseUrl: string;
        fetch?: FetchFn;
    };
};
export interface NetworkParam {
    network?: StacksNetworkName | StacksNetwork;
}
export type NetworkClientParam = NetworkParam & ClientParam;
export declare const STACKS_MAINNET: StacksNetwork;
export declare const STACKS_TESTNET: StacksNetwork;
export declare const STACKS_DEVNET: StacksNetwork;
export declare const STACKS_MOCKNET: StacksNetwork;
export declare const StacksNetworks: readonly ["mainnet", "testnet", "devnet", "mocknet"];
export type StacksNetworkName = (typeof StacksNetworks)[number];
export declare function networkFromName(name: StacksNetworkName): StacksNetwork;
export declare function networkFrom(network: StacksNetworkName | StacksNetwork): StacksNetwork;
export declare function defaultUrlFromNetwork(network?: StacksNetworkName | StacksNetwork): "https://api.mainnet.hiro.so" | "https://api.testnet.hiro.so" | "http://localhost:3999";
export declare function clientFromNetwork(network: StacksNetwork): Required<ClientOpts>;
export declare function createNetwork(network: StacksNetworkName | StacksNetwork): StacksNetwork;
export declare function createNetwork(network: StacksNetworkName | StacksNetwork, apiKey: string): StacksNetwork;
export declare function createNetwork(options: {
    network: StacksNetworkName | StacksNetwork;
    client?: ClientOpts;
} & Partial<ApiKeyMiddlewareOpts>): StacksNetwork;
