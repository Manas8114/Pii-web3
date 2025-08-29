"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.contractPrincipalCVFromStandard = exports.contractPrincipalCVFromAddress = exports.contractPrincipalCV = exports.standardPrincipalCVFromAddress = exports.standardPrincipalCV = exports.principalCV = void 0;
const common_1 = require("@stacks/common");
const wire_1 = require("../../wire");
const constants_1 = require("../constants");
function principalCV(principal) {
    if (principal.includes('.')) {
        const [address, contractName] = principal.split('.');
        return contractPrincipalCV(address, contractName);
    }
    else {
        return standardPrincipalCV(principal);
    }
}
exports.principalCV = principalCV;
function standardPrincipalCV(addressString) {
    const addr = (0, wire_1.createAddress)(addressString);
    return { type: constants_1.ClarityType.PrincipalStandard, value: (0, wire_1.addressToString)(addr) };
}
exports.standardPrincipalCV = standardPrincipalCV;
function standardPrincipalCVFromAddress(address) {
    return { type: constants_1.ClarityType.PrincipalStandard, value: (0, wire_1.addressToString)(address) };
}
exports.standardPrincipalCVFromAddress = standardPrincipalCVFromAddress;
function contractPrincipalCV(addressString, contractName) {
    const addr = (0, wire_1.createAddress)(addressString);
    const lengthPrefixedContractName = (0, wire_1.createLPString)(contractName);
    return contractPrincipalCVFromAddress(addr, lengthPrefixedContractName);
}
exports.contractPrincipalCV = contractPrincipalCV;
function contractPrincipalCVFromAddress(address, contractName) {
    if ((0, common_1.utf8ToBytes)(contractName.content).byteLength >= 128) {
        throw new Error('Contract name must be less than 128 bytes');
    }
    return {
        type: constants_1.ClarityType.PrincipalContract,
        value: `${(0, wire_1.addressToString)(address)}.${contractName.content}`,
    };
}
exports.contractPrincipalCVFromAddress = contractPrincipalCVFromAddress;
function contractPrincipalCVFromStandard(sp, contractName) {
    return {
        type: constants_1.ClarityType.PrincipalContract,
        value: `${sp.value}.${contractName}`,
    };
}
exports.contractPrincipalCVFromStandard = contractPrincipalCVFromStandard;
//# sourceMappingURL=principalCV.js.map