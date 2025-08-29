import { c32address, c32addressDecode } from 'c32check';
import { privateKeyToAddress, publicKeyToAddressSingleSig } from '../keys';
const C32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export function parse(address) {
    const [addr, contractName] = address.split('.');
    const parsed = c32addressDecode(addr);
    return {
        version: parsed[0],
        versionChar: C32[parsed[0]],
        hash160: parsed[1],
        contractName: contractName,
    };
}
export function stringify(address) {
    const version = 'version' in address ? address.version : C32.indexOf(address.versionChar.toUpperCase());
    const addr = c32address(version, address.hash160);
    if (address.contractName)
        return `${addr}.${address.contractName}`;
    return addr;
}
export const fromPrivateKey = privateKeyToAddress;
export const fromPublicKey = publicKeyToAddressSingleSig;
//# sourceMappingURL=address.js.map