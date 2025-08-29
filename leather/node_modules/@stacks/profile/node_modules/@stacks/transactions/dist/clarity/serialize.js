"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.serializeCVBytes = exports.serializeCV = void 0;
const common_1 = require("@stacks/common");
const constants_1 = require("../constants");
const errors_1 = require("../errors");
const utils_1 = require("../utils");
const wire_1 = require("../wire");
const constants_2 = require("./constants");
function bytesWithTypeID(typeId, bytes) {
    return (0, common_1.concatArray)([(0, constants_2.clarityTypeToByte)(typeId), bytes]);
}
function serializeBoolCV(value) {
    return new Uint8Array([(0, constants_2.clarityTypeToByte)(value.type)]);
}
function serializeOptionalCV(cv) {
    if (cv.type === constants_2.ClarityType.OptionalNone) {
        return new Uint8Array([(0, constants_2.clarityTypeToByte)(cv.type)]);
    }
    else {
        return bytesWithTypeID(cv.type, serializeCVBytes(cv.value));
    }
}
function serializeBufferCV(cv) {
    const length = new Uint8Array(4);
    (0, common_1.writeUInt32BE)(length, Math.ceil(cv.value.length / 2), 0);
    return bytesWithTypeID(cv.type, (0, common_1.concatBytes)(length, (0, common_1.hexToBytes)(cv.value)));
}
function serializeIntCV(cv) {
    const bytes = (0, common_1.bigIntToBytes)((0, common_1.toTwos)(BigInt(cv.value), BigInt(constants_1.CLARITY_INT_SIZE)), constants_1.CLARITY_INT_BYTE_SIZE);
    return bytesWithTypeID(cv.type, bytes);
}
function serializeUIntCV(cv) {
    const bytes = (0, common_1.bigIntToBytes)(BigInt(cv.value), constants_1.CLARITY_INT_BYTE_SIZE);
    return bytesWithTypeID(cv.type, bytes);
}
function serializeStandardPrincipalCV(cv) {
    return bytesWithTypeID(cv.type, (0, wire_1.serializeAddressBytes)((0, wire_1.createAddress)(cv.value)));
}
function serializeContractPrincipalCV(cv) {
    const [address, name] = (0, utils_1.parseContractId)(cv.value);
    return bytesWithTypeID(cv.type, (0, common_1.concatBytes)((0, wire_1.serializeAddressBytes)((0, wire_1.createAddress)(address)), (0, wire_1.serializeLPStringBytes)((0, wire_1.createLPString)(name))));
}
function serializeResponseCV(cv) {
    return bytesWithTypeID(cv.type, serializeCVBytes(cv.value));
}
function serializeListCV(cv) {
    const bytesArray = [];
    const length = new Uint8Array(4);
    (0, common_1.writeUInt32BE)(length, cv.value.length, 0);
    bytesArray.push(length);
    for (const value of cv.value) {
        const serializedValue = serializeCVBytes(value);
        bytesArray.push(serializedValue);
    }
    return bytesWithTypeID(cv.type, (0, common_1.concatArray)(bytesArray));
}
function serializeTupleCV(cv) {
    const bytesArray = [];
    const length = new Uint8Array(4);
    (0, common_1.writeUInt32BE)(length, Object.keys(cv.value).length, 0);
    bytesArray.push(length);
    const lexicographicOrder = Object.keys(cv.value).sort((a, b) => a.localeCompare(b));
    for (const key of lexicographicOrder) {
        const nameWithLength = (0, wire_1.createLPString)(key);
        bytesArray.push((0, wire_1.serializeLPStringBytes)(nameWithLength));
        const serializedValue = serializeCVBytes(cv.value[key]);
        bytesArray.push(serializedValue);
    }
    return bytesWithTypeID(cv.type, (0, common_1.concatArray)(bytesArray));
}
function serializeStringCV(cv, encoding) {
    const bytesArray = [];
    const str = encoding == 'ascii' ? (0, common_1.asciiToBytes)(cv.value) : (0, common_1.utf8ToBytes)(cv.value);
    const len = new Uint8Array(4);
    (0, common_1.writeUInt32BE)(len, str.length, 0);
    bytesArray.push(len);
    bytesArray.push(str);
    return bytesWithTypeID(cv.type, (0, common_1.concatArray)(bytesArray));
}
function serializeStringAsciiCV(cv) {
    return serializeStringCV(cv, 'ascii');
}
function serializeStringUtf8CV(cv) {
    return serializeStringCV(cv, 'utf8');
}
function serializeCV(value) {
    return (0, common_1.bytesToHex)(serializeCVBytes(value));
}
exports.serializeCV = serializeCV;
function serializeCVBytes(value) {
    switch (value.type) {
        case constants_2.ClarityType.BoolTrue:
        case constants_2.ClarityType.BoolFalse:
            return serializeBoolCV(value);
        case constants_2.ClarityType.OptionalNone:
        case constants_2.ClarityType.OptionalSome:
            return serializeOptionalCV(value);
        case constants_2.ClarityType.Buffer:
            return serializeBufferCV(value);
        case constants_2.ClarityType.UInt:
            return serializeUIntCV(value);
        case constants_2.ClarityType.Int:
            return serializeIntCV(value);
        case constants_2.ClarityType.PrincipalStandard:
            return serializeStandardPrincipalCV(value);
        case constants_2.ClarityType.PrincipalContract:
            return serializeContractPrincipalCV(value);
        case constants_2.ClarityType.ResponseOk:
        case constants_2.ClarityType.ResponseErr:
            return serializeResponseCV(value);
        case constants_2.ClarityType.List:
            return serializeListCV(value);
        case constants_2.ClarityType.Tuple:
            return serializeTupleCV(value);
        case constants_2.ClarityType.StringASCII:
            return serializeStringAsciiCV(value);
        case constants_2.ClarityType.StringUTF8:
            return serializeStringUtf8CV(value);
        default:
            throw new errors_1.SerializationError('Unable to serialize. Invalid Clarity Value.');
    }
}
exports.serializeCVBytes = serializeCVBytes;
//# sourceMappingURL=serialize.js.map