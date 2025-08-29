"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.fromPublicKey = exports.fromPrivateKey = exports.stringify = exports.parse = void 0;
const c32check_1 = require("c32check");
const keys_1 = require("../keys");
const C32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
function parse(address) {
    const [addr, contractName] = address.split('.');
    const parsed = (0, c32check_1.c32addressDecode)(addr);
    return {
        version: parsed[0],
        versionChar: C32[parsed[0]],
        hash160: parsed[1],
        contractName: contractName,
    };
}
exports.parse = parse;
function stringify(address) {
    const version = 'version' in address ? address.version : C32.indexOf(address.versionChar.toUpperCase());
    const addr = (0, c32check_1.c32address)(version, address.hash160);
    if (address.contractName)
        return `${addr}.${address.contractName}`;
    return addr;
}
exports.stringify = stringify;
exports.fromPrivateKey = keys_1.privateKeyToAddress;
exports.fromPublicKey = keys_1.publicKeyToAddressSingleSig;
//# sourceMappingURL=address.js.map