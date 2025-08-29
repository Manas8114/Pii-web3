import { ClarityType } from './constants';
import { asciiToBytes, bytesToAscii, hexToBytes, utf8ToBytes } from '@stacks/common';
export function cvToString(val, encoding = 'hex') {
    switch (val.type) {
        case ClarityType.BoolTrue:
            return 'true';
        case ClarityType.BoolFalse:
            return 'false';
        case ClarityType.Int:
            return val.value.toString();
        case ClarityType.UInt:
            return `u${val.value.toString()}`;
        case ClarityType.Buffer:
            if (encoding === 'tryAscii') {
                const str = bytesToAscii(hexToBytes(val.value));
                if (/[ -~]/.test(str)) {
                    return JSON.stringify(str);
                }
            }
            return `0x${val.value}`;
        case ClarityType.OptionalNone:
            return 'none';
        case ClarityType.OptionalSome:
            return `(some ${cvToString(val.value, encoding)})`;
        case ClarityType.ResponseErr:
            return `(err ${cvToString(val.value, encoding)})`;
        case ClarityType.ResponseOk:
            return `(ok ${cvToString(val.value, encoding)})`;
        case ClarityType.PrincipalStandard:
        case ClarityType.PrincipalContract:
            return val.value;
        case ClarityType.List:
            return `(list ${val.value.map(v => cvToString(v, encoding)).join(' ')})`;
        case ClarityType.Tuple:
            return `(tuple ${Object.keys(val.value)
                .map(key => `(${key} ${cvToString(val.value[key], encoding)})`)
                .join(' ')})`;
        case ClarityType.StringASCII:
            return `"${val.value}"`;
        case ClarityType.StringUTF8:
            return `u"${val.value}"`;
    }
}
export function cvToValue(val, strictJsonCompat = false) {
    switch (val.type) {
        case ClarityType.BoolTrue:
            return true;
        case ClarityType.BoolFalse:
            return false;
        case ClarityType.Int:
        case ClarityType.UInt:
            if (strictJsonCompat) {
                return val.value.toString();
            }
            return val.value;
        case ClarityType.Buffer:
            return `0x${val.value}`;
        case ClarityType.OptionalNone:
            return null;
        case ClarityType.OptionalSome:
            return cvToJSON(val.value);
        case ClarityType.ResponseErr:
            return cvToJSON(val.value);
        case ClarityType.ResponseOk:
            return cvToJSON(val.value);
        case ClarityType.PrincipalStandard:
        case ClarityType.PrincipalContract:
            return val.value;
        case ClarityType.List:
            return val.value.map(v => cvToJSON(v));
        case ClarityType.Tuple:
            const result = {};
            Object.keys(val.value).forEach(key => {
                result[key] = cvToJSON(val.value[key]);
            });
            return result;
        case ClarityType.StringASCII:
            return val.value;
        case ClarityType.StringUTF8:
            return val.value;
    }
}
export function cvToJSON(val) {
    switch (val.type) {
        case ClarityType.ResponseErr:
            return { type: getCVTypeString(val), value: cvToValue(val, true), success: false };
        case ClarityType.ResponseOk:
            return { type: getCVTypeString(val), value: cvToValue(val, true), success: true };
        default:
            return { type: getCVTypeString(val), value: cvToValue(val, true) };
    }
}
export function getCVTypeString(val) {
    switch (val.type) {
        case ClarityType.BoolTrue:
        case ClarityType.BoolFalse:
            return 'bool';
        case ClarityType.Int:
            return 'int';
        case ClarityType.UInt:
            return 'uint';
        case ClarityType.Buffer:
            return `(buff ${Math.ceil(val.value.length / 2)})`;
        case ClarityType.OptionalNone:
            return '(optional none)';
        case ClarityType.OptionalSome:
            return `(optional ${getCVTypeString(val.value)})`;
        case ClarityType.ResponseErr:
            return `(response UnknownType ${getCVTypeString(val.value)})`;
        case ClarityType.ResponseOk:
            return `(response ${getCVTypeString(val.value)} UnknownType)`;
        case ClarityType.PrincipalStandard:
        case ClarityType.PrincipalContract:
            return 'principal';
        case ClarityType.List:
            return `(list ${val.value.length} ${val.value.length ? getCVTypeString(val.value[0]) : 'UnknownType'})`;
        case ClarityType.Tuple:
            return `(tuple ${Object.keys(val.value)
                .map(key => `(${key} ${getCVTypeString(val.value[key])})`)
                .join(' ')})`;
        case ClarityType.StringASCII:
            return `(string-ascii ${asciiToBytes(val.value).length})`;
        case ClarityType.StringUTF8:
            return `(string-utf8 ${utf8ToBytes(val.value).length})`;
    }
}
export function isClarityType(input, withType) {
    return input.type === withType;
}
//# sourceMappingURL=clarityValue.js.map