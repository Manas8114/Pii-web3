"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isClarityType = exports.getCVTypeString = exports.cvToJSON = exports.cvToValue = exports.cvToString = void 0;
const constants_1 = require("./constants");
const common_1 = require("@stacks/common");
function cvToString(val, encoding = 'hex') {
    switch (val.type) {
        case constants_1.ClarityType.BoolTrue:
            return 'true';
        case constants_1.ClarityType.BoolFalse:
            return 'false';
        case constants_1.ClarityType.Int:
            return val.value.toString();
        case constants_1.ClarityType.UInt:
            return `u${val.value.toString()}`;
        case constants_1.ClarityType.Buffer:
            if (encoding === 'tryAscii') {
                const str = (0, common_1.bytesToAscii)((0, common_1.hexToBytes)(val.value));
                if (/[ -~]/.test(str)) {
                    return JSON.stringify(str);
                }
            }
            return `0x${val.value}`;
        case constants_1.ClarityType.OptionalNone:
            return 'none';
        case constants_1.ClarityType.OptionalSome:
            return `(some ${cvToString(val.value, encoding)})`;
        case constants_1.ClarityType.ResponseErr:
            return `(err ${cvToString(val.value, encoding)})`;
        case constants_1.ClarityType.ResponseOk:
            return `(ok ${cvToString(val.value, encoding)})`;
        case constants_1.ClarityType.PrincipalStandard:
        case constants_1.ClarityType.PrincipalContract:
            return val.value;
        case constants_1.ClarityType.List:
            return `(list ${val.value.map(v => cvToString(v, encoding)).join(' ')})`;
        case constants_1.ClarityType.Tuple:
            return `(tuple ${Object.keys(val.value)
                .map(key => `(${key} ${cvToString(val.value[key], encoding)})`)
                .join(' ')})`;
        case constants_1.ClarityType.StringASCII:
            return `"${val.value}"`;
        case constants_1.ClarityType.StringUTF8:
            return `u"${val.value}"`;
    }
}
exports.cvToString = cvToString;
function cvToValue(val, strictJsonCompat = false) {
    switch (val.type) {
        case constants_1.ClarityType.BoolTrue:
            return true;
        case constants_1.ClarityType.BoolFalse:
            return false;
        case constants_1.ClarityType.Int:
        case constants_1.ClarityType.UInt:
            if (strictJsonCompat) {
                return val.value.toString();
            }
            return val.value;
        case constants_1.ClarityType.Buffer:
            return `0x${val.value}`;
        case constants_1.ClarityType.OptionalNone:
            return null;
        case constants_1.ClarityType.OptionalSome:
            return cvToJSON(val.value);
        case constants_1.ClarityType.ResponseErr:
            return cvToJSON(val.value);
        case constants_1.ClarityType.ResponseOk:
            return cvToJSON(val.value);
        case constants_1.ClarityType.PrincipalStandard:
        case constants_1.ClarityType.PrincipalContract:
            return val.value;
        case constants_1.ClarityType.List:
            return val.value.map(v => cvToJSON(v));
        case constants_1.ClarityType.Tuple:
            const result = {};
            Object.keys(val.value).forEach(key => {
                result[key] = cvToJSON(val.value[key]);
            });
            return result;
        case constants_1.ClarityType.StringASCII:
            return val.value;
        case constants_1.ClarityType.StringUTF8:
            return val.value;
    }
}
exports.cvToValue = cvToValue;
function cvToJSON(val) {
    switch (val.type) {
        case constants_1.ClarityType.ResponseErr:
            return { type: getCVTypeString(val), value: cvToValue(val, true), success: false };
        case constants_1.ClarityType.ResponseOk:
            return { type: getCVTypeString(val), value: cvToValue(val, true), success: true };
        default:
            return { type: getCVTypeString(val), value: cvToValue(val, true) };
    }
}
exports.cvToJSON = cvToJSON;
function getCVTypeString(val) {
    switch (val.type) {
        case constants_1.ClarityType.BoolTrue:
        case constants_1.ClarityType.BoolFalse:
            return 'bool';
        case constants_1.ClarityType.Int:
            return 'int';
        case constants_1.ClarityType.UInt:
            return 'uint';
        case constants_1.ClarityType.Buffer:
            return `(buff ${Math.ceil(val.value.length / 2)})`;
        case constants_1.ClarityType.OptionalNone:
            return '(optional none)';
        case constants_1.ClarityType.OptionalSome:
            return `(optional ${getCVTypeString(val.value)})`;
        case constants_1.ClarityType.ResponseErr:
            return `(response UnknownType ${getCVTypeString(val.value)})`;
        case constants_1.ClarityType.ResponseOk:
            return `(response ${getCVTypeString(val.value)} UnknownType)`;
        case constants_1.ClarityType.PrincipalStandard:
        case constants_1.ClarityType.PrincipalContract:
            return 'principal';
        case constants_1.ClarityType.List:
            return `(list ${val.value.length} ${val.value.length ? getCVTypeString(val.value[0]) : 'UnknownType'})`;
        case constants_1.ClarityType.Tuple:
            return `(tuple ${Object.keys(val.value)
                .map(key => `(${key} ${getCVTypeString(val.value[key])})`)
                .join(' ')})`;
        case constants_1.ClarityType.StringASCII:
            return `(string-ascii ${(0, common_1.asciiToBytes)(val.value).length})`;
        case constants_1.ClarityType.StringUTF8:
            return `(string-utf8 ${(0, common_1.utf8ToBytes)(val.value).length})`;
    }
}
exports.getCVTypeString = getCVTypeString;
function isClarityType(input, withType) {
    return input.type === withType;
}
exports.isClarityType = isClarityType;
//# sourceMappingURL=clarityValue.js.map