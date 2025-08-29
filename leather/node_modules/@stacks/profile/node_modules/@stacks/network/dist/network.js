"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createNetwork = exports.clientFromNetwork = exports.defaultUrlFromNetwork = exports.networkFrom = exports.networkFromName = exports.StacksNetworks = exports.STACKS_MOCKNET = exports.STACKS_DEVNET = exports.STACKS_TESTNET = exports.STACKS_MAINNET = void 0;
const common_1 = require("@stacks/common");
const constants_1 = require("./constants");
exports.STACKS_MAINNET = {
    chainId: constants_1.ChainId.Mainnet,
    transactionVersion: constants_1.TransactionVersion.Mainnet,
    peerNetworkId: constants_1.PeerNetworkId.Mainnet,
    magicBytes: 'X2',
    bootAddress: 'SP000000000000000000002Q6VF78',
    addressVersion: {
        singleSig: constants_1.AddressVersion.MainnetSingleSig,
        multiSig: constants_1.AddressVersion.MainnetMultiSig,
    },
    client: { baseUrl: common_1.HIRO_MAINNET_URL },
};
exports.STACKS_TESTNET = {
    chainId: constants_1.ChainId.Testnet,
    transactionVersion: constants_1.TransactionVersion.Testnet,
    peerNetworkId: constants_1.PeerNetworkId.Testnet,
    magicBytes: 'T2',
    bootAddress: 'ST000000000000000000002AMW42H',
    addressVersion: {
        singleSig: constants_1.AddressVersion.TestnetSingleSig,
        multiSig: constants_1.AddressVersion.TestnetMultiSig,
    },
    client: { baseUrl: common_1.HIRO_TESTNET_URL },
};
exports.STACKS_DEVNET = {
    ...exports.STACKS_TESTNET,
    addressVersion: { ...exports.STACKS_TESTNET.addressVersion },
    magicBytes: 'id',
    client: { baseUrl: common_1.DEVNET_URL },
};
exports.STACKS_MOCKNET = {
    ...exports.STACKS_DEVNET,
    addressVersion: { ...exports.STACKS_DEVNET.addressVersion },
    client: { ...exports.STACKS_DEVNET.client },
};
exports.StacksNetworks = ['mainnet', 'testnet', 'devnet', 'mocknet'];
function networkFromName(name) {
    switch (name) {
        case 'mainnet':
            return exports.STACKS_MAINNET;
        case 'testnet':
            return exports.STACKS_TESTNET;
        case 'devnet':
            return exports.STACKS_DEVNET;
        case 'mocknet':
            return exports.STACKS_MOCKNET;
        default:
            throw new Error(`Unknown network name: ${name}`);
    }
}
exports.networkFromName = networkFromName;
function networkFrom(network) {
    if (typeof network === 'string')
        return networkFromName(network);
    return network;
}
exports.networkFrom = networkFrom;
function defaultUrlFromNetwork(network) {
    if (!network)
        return common_1.HIRO_MAINNET_URL;
    network = networkFrom(network);
    return !network || network.transactionVersion === constants_1.TransactionVersion.Mainnet
        ? common_1.HIRO_MAINNET_URL
        : network.magicBytes === 'id'
            ? common_1.DEVNET_URL
            : common_1.HIRO_TESTNET_URL;
}
exports.defaultUrlFromNetwork = defaultUrlFromNetwork;
function clientFromNetwork(network) {
    if (network.client.fetch)
        return network.client;
    return {
        ...network.client,
        fetch: (0, common_1.createFetchFn)(),
    };
}
exports.clientFromNetwork = clientFromNetwork;
function createNetwork(arg1, arg2) {
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
            const middleware = (0, common_1.createApiKeyMiddleware)(arg1);
            newNetwork.client.fetch = newNetwork.client.fetch
                ? (0, common_1.createFetchFn)(newNetwork.client.fetch, middleware)
                : (0, common_1.createFetchFn)(middleware);
        }
        return newNetwork;
    }
    if (typeof arg2 === 'string') {
        const middleware = (0, common_1.createApiKeyMiddleware)({ apiKey: arg2 });
        newNetwork.client.fetch = newNetwork.client.fetch
            ? (0, common_1.createFetchFn)(newNetwork.client.fetch, middleware)
            : (0, common_1.createFetchFn)(middleware);
        return newNetwork;
    }
    return newNetwork;
}
exports.createNetwork = createNetwork;
//# sourceMappingURL=network.js.map