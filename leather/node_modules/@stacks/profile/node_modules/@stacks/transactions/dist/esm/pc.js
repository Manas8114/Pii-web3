import { intToBigInt } from '@stacks/common';
import { parseContractId, validateStacksAddress } from './utils';
import { deserializePostConditionWire } from './wire';
import { wireToPostCondition } from './postcondition';
export function principal(principal) {
    const [address, name] = principal.split('.');
    if (!address || !validateStacksAddress(address) || (typeof name === 'string' && !name)) {
        throw new Error(`Invalid contract id: ${principal}`);
    }
    return new PartialPcWithPrincipal(principal);
}
export function origin() {
    return new PartialPcWithPrincipal('origin');
}
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
            amount: intToBigInt(this.amount).toString(),
        };
    }
    ft(contractId, tokenName) {
        const [address, name] = contractId.split('.');
        if (!address || !validateStacksAddress(address) || (typeof name === 'string' && !name)) {
            throw new Error(`Invalid contract id: ${contractId}`);
        }
        return {
            type: 'ft-postcondition',
            address: this.address,
            condition: this.code,
            amount: intToBigInt(this.amount).toString(),
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
        if (!validateStacksAddress(contractAddress)) {
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
    const [address, name] = parseContractId(principal);
    return { contractAddress: address, contractName: name, tokenName };
}
export function fromHex(hex) {
    const wire = deserializePostConditionWire(hex);
    return wireToPostCondition(wire);
}
function getNftArgs(...args) {
    if (args.length === 2) {
        const [assetName, assetId] = args;
        return { ...parseNft(assetName), assetId };
    }
    const [contractId, tokenName, assetId] = args;
    const [address, name] = parseContractId(contractId);
    return { contractAddress: address, contractName: name, tokenName, assetId };
}
//# sourceMappingURL=pc.js.map