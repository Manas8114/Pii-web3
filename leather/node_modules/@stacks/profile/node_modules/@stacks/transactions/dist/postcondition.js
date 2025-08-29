"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.postConditionModeFrom = exports.postConditionToHex = exports.conditionByteToType = exports.conditionTypeToByte = exports.wireToPostCondition = exports.postConditionToWire = void 0;
const constants_1 = require("./constants");
const wire_1 = require("./wire");
var PostConditionCodeWireType;
(function (PostConditionCodeWireType) {
    PostConditionCodeWireType[PostConditionCodeWireType["eq"] = 1] = "eq";
    PostConditionCodeWireType[PostConditionCodeWireType["gt"] = 2] = "gt";
    PostConditionCodeWireType[PostConditionCodeWireType["lt"] = 4] = "lt";
    PostConditionCodeWireType[PostConditionCodeWireType["gte"] = 3] = "gte";
    PostConditionCodeWireType[PostConditionCodeWireType["lte"] = 5] = "lte";
    PostConditionCodeWireType[PostConditionCodeWireType["sent"] = 16] = "sent";
    PostConditionCodeWireType[PostConditionCodeWireType["not-sent"] = 17] = "not-sent";
})(PostConditionCodeWireType || (PostConditionCodeWireType = {}));
function postConditionToWire(postcondition) {
    switch (postcondition.type) {
        case 'stx-postcondition':
            return {
                type: wire_1.StacksWireType.PostCondition,
                conditionType: constants_1.PostConditionType.STX,
                principal: postcondition.address === 'origin'
                    ? { type: wire_1.StacksWireType.Principal, prefix: constants_1.PostConditionPrincipalId.Origin }
                    : (0, wire_1.parsePrincipalString)(postcondition.address),
                conditionCode: conditionTypeToByte(postcondition.condition),
                amount: BigInt(postcondition.amount),
            };
        case 'ft-postcondition':
            return {
                type: wire_1.StacksWireType.PostCondition,
                conditionType: constants_1.PostConditionType.Fungible,
                principal: postcondition.address === 'origin'
                    ? { type: wire_1.StacksWireType.Principal, prefix: constants_1.PostConditionPrincipalId.Origin }
                    : (0, wire_1.parsePrincipalString)(postcondition.address),
                conditionCode: conditionTypeToByte(postcondition.condition),
                amount: BigInt(postcondition.amount),
                asset: (0, wire_1.parseAssetString)(postcondition.asset),
            };
        case 'nft-postcondition':
            return {
                type: wire_1.StacksWireType.PostCondition,
                conditionType: constants_1.PostConditionType.NonFungible,
                principal: postcondition.address === 'origin'
                    ? { type: wire_1.StacksWireType.Principal, prefix: constants_1.PostConditionPrincipalId.Origin }
                    : (0, wire_1.parsePrincipalString)(postcondition.address),
                conditionCode: conditionTypeToByte(postcondition.condition),
                asset: (0, wire_1.parseAssetString)(postcondition.asset),
                assetName: postcondition.assetId,
            };
        default:
            throw new Error('Invalid post condition type');
    }
}
exports.postConditionToWire = postConditionToWire;
function wireToPostCondition(wire) {
    switch (wire.conditionType) {
        case constants_1.PostConditionType.STX:
            return {
                type: 'stx-postcondition',
                address: principalWireToString(wire.principal),
                condition: conditionByteToType(wire.conditionCode),
                amount: wire.amount.toString(),
            };
        case constants_1.PostConditionType.Fungible:
            return {
                type: 'ft-postcondition',
                address: principalWireToString(wire.principal),
                condition: conditionByteToType(wire.conditionCode),
                amount: wire.amount.toString(),
                asset: assetWireToString(wire.asset),
            };
        case constants_1.PostConditionType.NonFungible:
            return {
                type: 'nft-postcondition',
                address: principalWireToString(wire.principal),
                condition: conditionByteToType(wire.conditionCode),
                asset: assetWireToString(wire.asset),
                assetId: wire.assetName,
            };
        default: {
            const _exhaustiveCheck = wire;
            throw new Error(`Invalid post condition type: ${_exhaustiveCheck}`);
        }
    }
}
exports.wireToPostCondition = wireToPostCondition;
function conditionTypeToByte(condition) {
    return PostConditionCodeWireType[condition];
}
exports.conditionTypeToByte = conditionTypeToByte;
function conditionByteToType(wireType) {
    return PostConditionCodeWireType[wireType];
}
exports.conditionByteToType = conditionByteToType;
function postConditionToHex(postcondition) {
    const wire = postConditionToWire(postcondition);
    return (0, wire_1.serializePostConditionWire)(wire);
}
exports.postConditionToHex = postConditionToHex;
function postConditionModeFrom(mode) {
    if (typeof mode === 'number')
        return mode;
    if (mode === 'allow')
        return constants_1.PostConditionMode.Allow;
    if (mode === 'deny')
        return constants_1.PostConditionMode.Deny;
    throw new Error(`Invalid post condition mode: ${mode}`);
}
exports.postConditionModeFrom = postConditionModeFrom;
function assetWireToString(asset) {
    const address = (0, wire_1.addressToString)(asset.address);
    const contractId = `${address}.${asset.contractName.content}`;
    return `${contractId}::${asset.assetName.content}`;
}
function principalWireToString(principal) {
    switch (principal.prefix) {
        case constants_1.PostConditionPrincipalId.Origin:
            return 'origin';
        case constants_1.PostConditionPrincipalId.Standard:
            return (0, wire_1.addressToString)(principal.address);
        case constants_1.PostConditionPrincipalId.Contract:
            const address = (0, wire_1.addressToString)(principal.address);
            return `${address}.${principal.contractName.content}`;
        default:
            const _exhaustiveCheck = principal;
            throw new Error(`Invalid principal type: ${_exhaustiveCheck}`);
    }
}
//# sourceMappingURL=postcondition.js.map