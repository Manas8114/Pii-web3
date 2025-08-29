import { AddressVersion } from '../constants';
import { privateKeyToAddress, publicKeyToAddressSingleSig } from '../keys';
import { AddressString, ContractIdString } from '../types';
export type AddressRepr = {
    hash160: string;
    contractName?: string;
} & ({
    version: AddressVersion;
    versionChar: string;
} | {
    version: AddressVersion;
} | {
    versionChar: string;
});
export declare function parse(address: AddressString | ContractIdString): AddressRepr;
export declare function stringify(address: AddressRepr): string;
export declare const fromPrivateKey: typeof privateKeyToAddress;
export declare const fromPublicKey: typeof publicKeyToAddressSingleSig;
