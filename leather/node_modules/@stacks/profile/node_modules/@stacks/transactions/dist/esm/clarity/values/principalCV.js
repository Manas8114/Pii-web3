import { utf8ToBytes } from '@stacks/common';
import { addressToString, createAddress, createLPString, } from '../../wire';
import { ClarityType } from '../constants';
export function principalCV(principal) {
    if (principal.includes('.')) {
        const [address, contractName] = principal.split('.');
        return contractPrincipalCV(address, contractName);
    }
    else {
        return standardPrincipalCV(principal);
    }
}
export function standardPrincipalCV(addressString) {
    const addr = createAddress(addressString);
    return { type: ClarityType.PrincipalStandard, value: addressToString(addr) };
}
export function standardPrincipalCVFromAddress(address) {
    return { type: ClarityType.PrincipalStandard, value: addressToString(address) };
}
export function contractPrincipalCV(addressString, contractName) {
    const addr = createAddress(addressString);
    const lengthPrefixedContractName = createLPString(contractName);
    return contractPrincipalCVFromAddress(addr, lengthPrefixedContractName);
}
export function contractPrincipalCVFromAddress(address, contractName) {
    if (utf8ToBytes(contractName.content).byteLength >= 128) {
        throw new Error('Contract name must be less than 128 bytes');
    }
    return {
        type: ClarityType.PrincipalContract,
        value: `${addressToString(address)}.${contractName.content}`,
    };
}
export function contractPrincipalCVFromStandard(sp, contractName) {
    return {
        type: ClarityType.PrincipalContract,
        value: `${sp.value}.${contractName}`,
    };
}
//# sourceMappingURL=principalCV.js.map