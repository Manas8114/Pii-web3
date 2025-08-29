import { StacksNetwork, StacksNetworkName } from '@stacks/network';
import { AddressHashMode, AddressVersion } from './constants';
export declare function addressHashModeToVersion(hashMode: AddressHashMode, network?: StacksNetworkName | StacksNetwork): AddressVersion;
