"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.fromHex = exports.origin = exports.principal = void 0;
const common_1 = require("@stacks/common");
const utils_1 = require("./utils");
const wire_1 = require("./wire");
const postcondition_1 = require("./postcondition");
function principal(principal) {
    const [address, name] = principal.split('.');
    if (!address || !(0, utils_1.validateStacksAddress)(address) || (typeof name === 'string' && !name)) {
        throw new Error(`Invalid contract id: ${principal}`);
    }
    return new PartialPcWithPrincipal(principal);
}
exports.principal = principal;
function origin() {
    return new PartialPcWithPrincipal('origin');
}
exports.origin = origin;
class PartialPcWithPrincipal {
    constructor(address) {
        this.address = address;
    }
    willSendEq(amount) {
        return new PartialPcFtWithCode(this.address, amount, 'eq');
    }
    willSendLte(amount) {
        return new PartialPcFtWithCode(this.address, amount, 'lte');
    }
    willSendLt(amount) {
        return new PartialPcFtWithCode(this.address, amount, 'lt');
    }
    willSendGte(amount) {
        return new PartialPcFtWithCode(this.address, amount, 'gte');
    }
    willSendGt(amount) {
        return new PartialPcFtWithCode(this.address, amount, 'gt');
    }
    willSendAsset() {
        return new PartialPcNftWithCode(this.address, 'sent');
    }
    willNotSendAsset() {
        return new PartialPcNftWithCode(this.address, 'not-sent');
    }
}
class PartialPcFtWithCode {
    constructor(address, amount, code) {
        this.address = address;
        this.amount = amount;
        this.code = code;
    }
    ustx() {
        return {
            type: 'stx-postcondition',
            address: this.address,
            condition: this.code,
            amount: (0, common_1.intToBigInt)(this.amount).toString(),
        };
    }
    ft(contractId, tokenName) {
        const [address, name] = contractId.split('.');
        if (!address || !(0, utils_1.validateStacksAddress)(address) || (typeof name === 'string' && !name)) {
            throw new Error(`Invalid contract id: ${contractId}`);
        }
        return {
            type: 'ft-postcondition',
            address: this.address,
            condition: this.code,
            amount: (0, common_1.intToBigInt)(this.amount).toString(),
            asset: `${contractId}::${tokenName}`,
        };
    }
}
class PartialPcNftWithCode {
    constructor(address, code) {
        this.address = address;
        this.code = code;
    }
    nft(...args) {
        const { contractAddress, contractName, tokenName, assetId } = getNftArgs(...args);
        if (!(0, utils_1.validateStacksAddress)(contractAddress)) {
            throw new Error(`Invalid contract id: ${contractAddress}`);
        }
        return {
            type: 'nft-postcondition',
            address: this.address,
            condition: this.code,
            asset: `${contractAddress}.${contractName}::${tokenName}`,
            assetId,
        };
    }
}
function parseNft(nftAssetName) {
    const [principal, tokenName] = nftAssetName.split('::');
    if (!principal || !tokenName)
        throw new Error(`Invalid fully-qualified nft asset name: ${nftAssetName}`);
    const [address, name] = (0, utils_1.parseContractId)(principal);
    return { contractAddress: address, contractName: name, tokenName };
}
function fromHex(hex) {
    const wire = (0, wire_1.deserializePostConditionWire)(hex);
    return (0, postcondition_1.wireToPostCondition)(wire);
}
exports.fromHex = fromHex;
function getNftArgs(...args) {
    if (args.length === 2) {
        const [assetName, assetId] = args;
        return { ...parseNft(assetName), assetId };
    }
    const [contractId, tokenName, assetId] = args;
    const [address, name] = (0, utils_1.parseContractId)(contractId);
    return { contractAddress: address, contractName: name, tokenName, assetId };
}
//# sourceMappingURL=pc.js.map