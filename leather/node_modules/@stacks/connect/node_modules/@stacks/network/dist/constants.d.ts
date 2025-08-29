export declare enum ChainId {
    Mainnet = 1,
    Testnet = 2147483648
}
export declare enum PeerNetworkId {
    Mainnet = 385875968,
    Testnet = 4278190080
}
export declare const DEFAULT_CHAIN_ID = ChainId.Mainnet;
export declare enum TransactionVersion {
    Mainnet = 0,
    Testnet = 128
}
export declare enum AddressVersion {
    MainnetSingleSig = 22,
    MainnetMultiSig = 20,
    TestnetSingleSig = 26,
    TestnetMultiSig = 21
}
export declare const DEFAULT_TRANSACTION_VERSION = TransactionVersion.Mainnet;
export declare function whenTransactionVersion(transactionVersion: TransactionVersion): <T>(map: Record<TransactionVersion, T>) => T;
