"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateHash256 = exports.isInstance = exports.concatArray = exports.concatBytes = exports.octetsToBytes = exports.bytesToAscii = exports.asciiToBytes = exports.bytesToUtf8 = exports.utf8ToBytes = exports.hexToBytes = exports.bytesToHex = exports.fromTwos = exports.bytesToTwosBigInt = exports.toTwos = exports.bigIntToBytes = exports.hexToInt = exports.intToHex = exports.hexToBigInt = exports.without0x = exports.with0x = exports.intToBigInt = exports.intToBytes = exports.getGlobalObjects = exports.getGlobalObject = exports.getGlobalScope = exports.isSameOriginAbsoluteUrl = exports.makeUUID4 = exports.isLaterVersion = exports.updateQueryStringParameter = exports.getBase64OutputLength = exports.getAesCbcOutputLength = exports.megabytesToBytes = exports.nextHour = exports.nextMonth = exports.nextYear = exports.BLOCKSTACK_HANDLER = void 0;
const logger_1 = require("./logger");
exports.BLOCKSTACK_HANDLER = 'blockstack';
function nextYear() {
    return new Date(new Date().setFullYear(new Date().getFullYear() + 1));
}
exports.nextYear = nextYear;
function nextMonth() {
    return new Date(new Date().setMonth(new Date().getMonth() + 1));
}
exports.nextMonth = nextMonth;
function nextHour() {
    return new Date(new Date().setHours(new Date().getHours() + 1));
}
exports.nextHour = nextHour;
function megabytesToBytes(megabytes) {
    if (!Number.isFinite(megabytes)) {
        return 0;
    }
    return Math.floor(megabytes * 1024 * 1024);
}
exports.megabytesToBytes = megabytesToBytes;
function getAesCbcOutputLength(inputByteLength) {
    const cipherTextLength = (Math.floor(inputByteLength / 16) + 1) * 16;
    return cipherTextLength;
}
exports.getAesCbcOutputLength = getAesCbcOutputLength;
function getBase64OutputLength(inputByteLength) {
    const encodedLength = Math.ceil(inputByteLength / 3) * 4;
    return encodedLength;
}
exports.getBase64OutputLength = getBase64OutputLength;
function updateQueryStringParameter(uri, key, value) {
    const re = new RegExp(`([?&])${key}=.*?(&|$)`, 'i');
    const separator = uri.indexOf('?') !== -1 ? '&' : '?';
    if (uri.match(re)) {
        return uri.replace(re, `$1${key}=${value}$2`);
    }
    else {
        return `${uri}${separator}${key}=${value}`;
    }
}
exports.updateQueryStringParameter = updateQueryStringParameter;
function isLaterVersion(v1, v2) {
    if (v1 === undefined || v1 === '') {
        v1 = '0.0.0';
    }
    if (v2 === undefined || v1 === '') {
        v2 = '0.0.0';
    }
    const v1tuple = v1.split('.').map(x => parseInt(x, 10));
    const v2tuple = v2.split('.').map(x => parseInt(x, 10));
    for (let index = 0; index < v2.length; index++) {
        if (index >= v1.length) {
            v2tuple.push(0);
        }
        if (v1tuple[index] < v2tuple[index]) {
            return false;
        }
    }
    return true;
}
exports.isLaterVersion = isLaterVersion;
function makeUUID4() {
    let d = new Date().getTime();
    if (typeof performance !== 'undefined' && typeof performance.now === 'function') {
        d += performance.now();
    }
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = (d + Math.random() * 16) % 16 | 0;
        d = Math.floor(d / 16);
        return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
}
exports.makeUUID4 = makeUUID4;
function isSameOriginAbsoluteUrl(uri1, uri2) {
    try {
        const parsedUri1 = new URL(uri1);
        const parsedUri2 = new URL(uri2);
        const port1 = parseInt(parsedUri1.port || '0', 10) | 0 || (parsedUri1.protocol === 'https:' ? 443 : 80);
        const port2 = parseInt(parsedUri2.port || '0', 10) | 0 || (parsedUri2.protocol === 'https:' ? 443 : 80);
        const match = {
            scheme: parsedUri1.protocol === parsedUri2.protocol,
            hostname: parsedUri1.hostname === parsedUri2.hostname,
            port: port1 === port2,
            absolute: (uri1.includes('http://') || uri1.includes('https://')) &&
                (uri2.includes('http://') || uri2.includes('https://')),
        };
        return match.scheme && match.hostname && match.port && match.absolute;
    }
    catch (error) {
        console.log(error);
        console.log('Parsing error in same URL origin check');
        return false;
    }
}
exports.isSameOriginAbsoluteUrl = isSameOriginAbsoluteUrl;
function getGlobalScope() {
    if (typeof self !== 'undefined') {
        return self;
    }
    if (typeof window !== 'undefined') {
        return window;
    }
    if (typeof global !== 'undefined') {
        return global;
    }
    throw new Error('Unexpected runtime environment - no supported global scope (`window`, `self`, `global`) available');
}
exports.getGlobalScope = getGlobalScope;
function getAPIUsageErrorMessage(scopeObject, apiName, usageDesc) {
    if (usageDesc) {
        return `Use of '${usageDesc}' requires \`${apiName}\` which is unavailable on the '${scopeObject}' object within the currently executing environment.`;
    }
    else {
        return `\`${apiName}\` is unavailable on the '${scopeObject}' object within the currently executing environment.`;
    }
}
function getGlobalObject(name, { throwIfUnavailable, usageDesc, returnEmptyObject } = {}) {
    let globalScope = undefined;
    try {
        globalScope = getGlobalScope();
        if (globalScope) {
            const obj = globalScope[name];
            if (obj) {
                return obj;
            }
        }
    }
    catch (error) {
        logger_1.Logger.error(`Error getting object '${name}' from global scope '${globalScope}': ${error}`);
    }
    if (throwIfUnavailable) {
        const errMsg = getAPIUsageErrorMessage(globalScope, name.toString(), usageDesc);
        logger_1.Logger.error(errMsg);
        throw new Error(errMsg);
    }
    if (returnEmptyObject) {
        return {};
    }
    return undefined;
}
exports.getGlobalObject = getGlobalObject;
function getGlobalObjects(names, { throwIfUnavailable, usageDesc, returnEmptyObject } = {}) {
    let globalScope;
    try {
        globalScope = getGlobalScope();
    }
    catch (error) {
        logger_1.Logger.error(`Error getting global scope: ${error}`);
        if (throwIfUnavailable) {
            const errMsg = getAPIUsageErrorMessage(globalScope, names[0].toString(), usageDesc);
            logger_1.Logger.error(errMsg);
            throw errMsg;
        }
        else if (returnEmptyObject) {
            globalScope = {};
        }
    }
    const result = {};
    for (let i = 0; i < names.length; i++) {
        const name = names[i];
        try {
            if (globalScope) {
                const obj = globalScope[name];
                if (obj) {
                    result[name] = obj;
                }
                else if (throwIfUnavailable) {
                    const errMsg = getAPIUsageErrorMessage(globalScope, name.toString(), usageDesc);
                    logger_1.Logger.error(errMsg);
                    throw new Error(errMsg);
                }
                else if (returnEmptyObject) {
                    result[name] = {};
                }
            }
        }
        catch (error) {
            if (throwIfUnavailable) {
                const errMsg = getAPIUsageErrorMessage(globalScope, name.toString(), usageDesc);
                logger_1.Logger.error(errMsg);
                throw new Error(errMsg);
            }
        }
    }
    return result;
}
exports.getGlobalObjects = getGlobalObjects;
function intToBytes(value, byteLength) {
    return bigIntToBytes(intToBigInt(value), byteLength);
}
exports.intToBytes = intToBytes;
function intToBigInt(value) {
    if (typeof value === 'bigint')
        return value;
    if (typeof value === 'string')
        return BigInt(value);
    if (typeof value === 'number') {
        if (!Number.isInteger(value)) {
            throw new RangeError(`Invalid value. Values of type 'number' must be an integer.`);
        }
        if (value > Number.MAX_SAFE_INTEGER) {
            throw new RangeError(`Invalid value. Values of type 'number' must be less than or equal to ${Number.MAX_SAFE_INTEGER}. For larger values, try using a BigInt instead.`);
        }
        return BigInt(value);
    }
    if (isInstance(value, Uint8Array))
        return BigInt(`0x${bytesToHex(value)}`);
    throw new TypeError(`intToBigInt: Invalid value type. Must be a number, bigint, BigInt-compatible string, or Uint8Array.`);
}
exports.intToBigInt = intToBigInt;
function with0x(value) {
    return /^0x/i.test(value)
        ? value
        : `0x${value}`;
}
exports.with0x = with0x;
function without0x(value) {
    return /^0x/i.test(value)
        ? value.slice(2)
        : value;
}
exports.without0x = without0x;
function hexToBigInt(hex) {
    if (typeof hex !== 'string')
        throw new TypeError(`hexToBigInt: expected string, got ${typeof hex}`);
    return BigInt(`0x${hex}`);
}
exports.hexToBigInt = hexToBigInt;
function intToHex(integer, byteLength = 8) {
    const value = typeof integer === 'bigint' ? integer : intToBigInt(integer);
    return value.toString(16).padStart(byteLength * 2, '0');
}
exports.intToHex = intToHex;
function hexToInt(hex) {
    return parseInt(hex, 16);
}
exports.hexToInt = hexToInt;
function bigIntToBytes(value, length = 16) {
    const hex = intToHex(value, length);
    return hexToBytes(hex);
}
exports.bigIntToBytes = bigIntToBytes;
function toTwos(value, width) {
    if (value < -(BigInt(1) << (width - BigInt(1))) ||
        (BigInt(1) << (width - BigInt(1))) - BigInt(1) < value) {
        throw `Unable to represent integer in width: ${width}`;
    }
    if (value >= BigInt(0)) {
        return BigInt(value);
    }
    return value + (BigInt(1) << width);
}
exports.toTwos = toTwos;
function nthBit(value, n) {
    return value & (BigInt(1) << n);
}
function bytesToTwosBigInt(bytes) {
    return fromTwos(BigInt(`0x${bytesToHex(bytes)}`), BigInt(bytes.byteLength * 8));
}
exports.bytesToTwosBigInt = bytesToTwosBigInt;
function fromTwos(value, width) {
    if (nthBit(value, width - BigInt(1))) {
        return value - (BigInt(1) << width);
    }
    return value;
}
exports.fromTwos = fromTwos;
const hexes = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
function bytesToHex(uint8a) {
    if (!(uint8a instanceof Uint8Array))
        throw new Error('Uint8Array expected');
    let hex = '';
    for (const u of uint8a) {
        hex += hexes[u];
    }
    return hex;
}
exports.bytesToHex = bytesToHex;
function hexToBytes(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError(`hexToBytes: expected string, got ${typeof hex}`);
    }
    hex = without0x(hex);
    hex = hex.length % 2 ? `0${hex}` : hex;
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        const hexByte = hex.slice(j, j + 2);
        const byte = Number.parseInt(hexByte, 16);
        if (Number.isNaN(byte) || byte < 0)
            throw new Error('Invalid byte sequence');
        array[i] = byte;
    }
    return array;
}
exports.hexToBytes = hexToBytes;
function utf8ToBytes(str) {
    return new TextEncoder().encode(str);
}
exports.utf8ToBytes = utf8ToBytes;
function bytesToUtf8(arr) {
    return new TextDecoder().decode(arr);
}
exports.bytesToUtf8 = bytesToUtf8;
function asciiToBytes(str) {
    const byteArray = [];
    for (let i = 0; i < str.length; i++) {
        byteArray.push(str.charCodeAt(i) & 0xff);
    }
    return new Uint8Array(byteArray);
}
exports.asciiToBytes = asciiToBytes;
function bytesToAscii(arr) {
    return String.fromCharCode.apply(null, arr);
}
exports.bytesToAscii = bytesToAscii;
function isNotOctet(octet) {
    return !Number.isInteger(octet) || octet < 0 || octet > 255;
}
function octetsToBytes(numbers) {
    if (numbers.some(isNotOctet))
        throw new Error('Some values are invalid bytes.');
    return new Uint8Array(numbers);
}
exports.octetsToBytes = octetsToBytes;
function concatBytes(...arrays) {
    if (!arrays.every(a => a instanceof Uint8Array))
        throw new Error('Uint8Array list expected');
    if (arrays.length === 1)
        return arrays[0];
    const length = arrays.reduce((a, arr) => a + arr.length, 0);
    const result = new Uint8Array(length);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const arr = arrays[i];
        result.set(arr, pad);
        pad += arr.length;
    }
    return result;
}
exports.concatBytes = concatBytes;
function concatArray(elements) {
    return concatBytes(...elements.map(e => {
        if (typeof e === 'number')
            return octetsToBytes([e]);
        if (e instanceof Array)
            return octetsToBytes(e);
        return e;
    }));
}
exports.concatArray = concatArray;
function isInstance(object, clazz) {
    return object instanceof clazz || object?.constructor?.name?.toLowerCase() === clazz.name;
}
exports.isInstance = isInstance;
function validateHash256(hex) {
    hex = without0x(hex);
    if (hex.length !== 64)
        return false;
    return /^[0-9a-fA-F]+$/.test(hex);
}
exports.validateHash256 = validateHash256;
//# sourceMappingURL=utils.js.map