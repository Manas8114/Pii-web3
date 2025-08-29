import { DEVNET_URL, HIRO_MAINNET_URL, HIRO_TESTNET_URL, createFetchFn, createApiKeyMiddleware, } from '@stacks/common';
import { AddressVersion, ChainId, PeerNetworkId, TransactionVersion } from './constants';
export const STACKS_MAINNET = {
    chainId: ChainId.Mainnet,
    transactionVersion: TransactionVersion.Mainnet,
    peerNetworkId: PeerNetworkId.Mainnet,
    magicBytes: 'X2',
    bootAddress: 'SP000000000000000000002Q6VF78',
    addressVersion: {
        singleSig: AddressVersion.MainnetSingleSig,
        multiSig: AddressVersion.MainnetMultiSig,
    },
    client: { baseUrl: HIRO_MAINNET_URL },
};
export const STACKS_TESTNET = {
    chainId: ChainId.Testnet,
    transactionVersion: TransactionVersion.Testnet,
    peerNetworkId: PeerNetworkId.Testnet,
    magicBytes: 'T2',
    bootAddress: 'ST000000000000000000002AMW42H',
    addressVersion: {
        singleSig: AddressVersion.TestnetSingleSig,
        multiSig: AddressVersion.TestnetMultiSig,
    },
    client: { baseUrl: HIRO_TESTNET_URL },
};
export const STACKS_DEVNET = {
    ...STACKS_TESTNET,
    addressVersion: { ...STACKS_TESTNET.addressVersion },
    magicBytes: 'id',
    client: { baseUrl: DEVNET_URL },
};
export const STACKS_MOCKNET = {
    ...STACKS_DEVNET,
    addressVersion: { ...STACKS_DEVNET.addressVersion },
    client: { ...STACKS_DEVNET.client },
};
export const StacksNetworks = ['mainnet', 'testnet', 'devnet', 'mocknet'];
export function networkFromName(name) {
    switch (name) {
        case 'mainnet':
            return STACKS_MAINNET;
        case 'testnet':
            return STACKS_TESTNET;
        case 'devnet':
            return STACKS_DEVNET;
        case 'mocknet':
            return STACKS_MOCKNET;
        default:
            throw new Error(`Unknown network name: ${name}`);
    }
}
export function networkFrom(network) {
    if (typeof network === 'string')
        return networkFromName(network);
    return network;
}
export function defaultUrlFromNetwork(network) {
    if (!network)
        return HIRO_MAINNET_URL;
    network = networkFrom(network);
    return !network || network.transactionVersion === TransactionVersion.Mainnet
        ? HIRO_MAINNET_URL
        : network.magicBytes === 'id'
            ? DEVNET_URL
            : HIRO_TESTNET_URL;
}
export function clientFromNetwork(network) {
    if (network.client.fetch)
        return network.client;
    return {
        ...network.client,
        fetch: createFetchFn(),
    };
}
export function createNetwork(arg1, arg2) {
    const baseNetwork = networkFrom(typeof arg1 === 'object' && 'network' in arg1 ? arg1.network : arg1);
    const newNetwork = {
        ...baseNetwork,
        addressVersion: { ...baseNetwork.addressVersion },
        client: { ...baseNetwork.client },
    };
    if (typeof arg1 === 'object' && 'network' in arg1) {
        if (arg1.client) {
            newNetwork.client.baseUrl = arg1.client.baseUrl ?? newNetwork.client.baseUrl;
            newNetwork.client.fetch = arg1.client.fetch ?? newNetwork.client.fetch;
        }
        if (typeof arg1.apiKey === 'string') {
            const middleware = createApiKeyMiddleware(arg1);
            newNetwork.client.fetch = newNetwork.client.fetch
                ? createFetchFn(newNetwork.client.fetch, middleware)
                : createFetchFn(middleware);
        }
        return newNetwork;
    }
    if (typeof arg2 === 'string') {
        const middleware = createApiKeyMiddleware({ apiKey: arg2 });
        newNetwork.client.fetch = newNetwork.client.fetch
            ? createFetchFn(newNetwork.client.fetch, middleware)
            : createFetchFn(middleware);
        return newNetwork;
    }
    return newNetwork;
}
//# sourceMappingURL=network.js.map