import { PostConditionMode, PostConditionPrincipalId, PostConditionType, } from './constants';
import { StacksWireType, addressToString, parseAssetString, parsePrincipalString, serializePostConditionWire, } from './wire';
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
export function postConditionToWire(postcondition) {
    switch (postcondition.type) {
        case 'stx-postcondition':
            return {
                type: StacksWireType.PostCondition,
                conditionType: PostConditionType.STX,
                principal: postcondition.address === 'origin'
                    ? { type: StacksWireType.Principal, prefix: PostConditionPrincipalId.Origin }
                    : parsePrincipalString(postcondition.address),
                conditionCode: conditionTypeToByte(postcondition.condition),
                amount: BigInt(postcondition.amount),
            };
        case 'ft-postcondition':
            return {
                type: StacksWireType.PostCondition,
                conditionType: PostConditionType.Fungible,
                principal: postcondition.address === 'origin'
                    ? { type: StacksWireType.Principal, prefix: PostConditionPrincipalId.Origin }
                    : parsePrincipalString(postcondition.address),
                conditionCode: conditionTypeToByte(postcondition.condition),
                amount: BigInt(postcondition.amount),
                asset: parseAssetString(postcondition.asset),
            };
        case 'nft-postcondition':
            return {
                type: StacksWireType.PostCondition,
                conditionType: PostConditionType.NonFungible,
                principal: postcondition.address === 'origin'
                    ? { type: StacksWireType.Principal, prefix: PostConditionPrincipalId.Origin }
                    : parsePrincipalString(postcondition.address),
                conditionCode: conditionTypeToByte(postcondition.condition),
                asset: parseAssetString(postcondition.asset),
                assetName: postcondition.assetId,
            };
        default:
            throw new Error('Invalid post condition type');
    }
}
export function wireToPostCondition(wire) {
    switch (wire.conditionType) {
        case PostConditionType.STX:
            return {
                type: 'stx-postcondition',
                address: principalWireToString(wire.principal),
                condition: conditionByteToType(wire.conditionCode),
                amount: wire.amount.toString(),
            };
        case PostConditionType.Fungible:
            return {
                type: 'ft-postcondition',
                address: principalWireToString(wire.principal),
                condition: conditionByteToType(wire.conditionCode),
                amount: wire.amount.toString(),
                asset: assetWireToString(wire.asset),
            };
        case PostConditionType.NonFungible:
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
export function conditionTypeToByte(condition) {
    return PostConditionCodeWireType[condition];
}
export function conditionByteToType(wireType) {
    return PostConditionCodeWireType[wireType];
}
export function postConditionToHex(postcondition) {
    const wire = postConditionToWire(postcondition);
    return serializePostConditionWire(wire);
}
export function postConditionModeFrom(mode) {
    if (typeof mode === 'number')
        return mode;
    if (mode === 'allow')
        return PostConditionMode.Allow;
    if (mode === 'deny')
        return PostConditionMode.Deny;
    throw new Error(`Invalid post condition mode: ${mode}`);
}
function assetWireToString(asset) {
    const address = addressToString(asset.address);
    const contractId = `${address}.${asset.contractName.content}`;
    return `${contractId}::${asset.assetName.content}`;
}
function principalWireToString(principal) {
    switch (principal.prefix) {
        case PostConditionPrincipalId.Origin:
            return 'origin';
        case PostConditionPrincipalId.Standard:
            return addressToString(principal.address);
        case PostConditionPrincipalId.Contract:
            const address = addressToString(principal.address);
            return `${address}.${principal.contractName.content}`;
        default:
            const _exhaustiveCheck = principal;
            throw new Error(`Invalid principal type: ${_exhaustiveCheck}`);
    }
}
//# sourceMappingURL=postcondition.js.map