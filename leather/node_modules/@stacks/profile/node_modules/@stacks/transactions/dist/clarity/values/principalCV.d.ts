import { AddressWire, LengthPrefixedStringWire } from '../../wire';
import { ContractPrincipalCV, PrincipalCV, StandardPrincipalCV } from '../types';
export declare function principalCV(principal: string): PrincipalCV;
export declare function standardPrincipalCV(addressString: string): StandardPrincipalCV;
export declare function standardPrincipalCVFromAddress(address: AddressWire): StandardPrincipalCV;
export declare function contractPrincipalCV(addressString: string, contractName: string): ContractPrincipalCV;
export declare function contractPrincipalCVFromAddress(address: AddressWire, contractName: LengthPrefixedStringWire): ContractPrincipalCV;
export declare function contractPrincipalCVFromStandard(sp: StandardPrincipalCV, contractName: string): ContractPrincipalCV;
