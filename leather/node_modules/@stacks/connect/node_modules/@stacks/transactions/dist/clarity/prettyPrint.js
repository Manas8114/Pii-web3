"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.prettyPrint = exports.stringify = void 0;
const _1 = require(".");
function escape(value) {
    return JSON.stringify(value).slice(1, -1);
}
function formatSpace(space, depth, end = false) {
    if (!space)
        return ' ';
    return `\n${' '.repeat(space * (depth - (end ? 1 : 0)))}`;
}
function formatList(cv, space, depth = 1) {
    if (cv.value.length === 0)
        return '(list)';
    const spaceBefore = formatSpace(space, depth, false);
    const endSpace = space ? formatSpace(space, depth, true) : '';
    const items = cv.value.map(v => prettyPrintWithDepth(v, space, depth)).join(spaceBefore);
    return `(list${spaceBefore}${items}${endSpace})`;
}
function formatTuple(cv, space, depth = 1) {
    if (Object.keys(cv.value).length === 0)
        return '{}';
    const items = [];
    for (const [key, value] of Object.entries(cv.value)) {
        items.push(`${key}: ${prettyPrintWithDepth(value, space, depth)}`);
    }
    const spaceBefore = formatSpace(space, depth, false);
    const endSpace = formatSpace(space, depth, true);
    return `{${spaceBefore}${items.sort().join(`,${spaceBefore}`)}${endSpace}}`;
}
function exhaustiveCheck(param) {
    throw new Error(`invalid clarity value type: ${param}`);
}
function prettyPrintWithDepth(cv, space = 0, depth) {
    if (cv.type === _1.ClarityType.BoolFalse)
        return 'false';
    if (cv.type === _1.ClarityType.BoolTrue)
        return 'true';
    if (cv.type === _1.ClarityType.Int)
        return cv.value.toString();
    if (cv.type === _1.ClarityType.UInt)
        return `u${cv.value.toString()}`;
    if (cv.type === _1.ClarityType.StringASCII)
        return `"${escape(cv.value)}"`;
    if (cv.type === _1.ClarityType.StringUTF8)
        return `u"${escape(cv.value)}"`;
    if (cv.type === _1.ClarityType.PrincipalContract)
        return `'${cv.value}`;
    if (cv.type === _1.ClarityType.PrincipalStandard)
        return `'${cv.value}`;
    if (cv.type === _1.ClarityType.Buffer)
        return `0x${cv.value}`;
    if (cv.type === _1.ClarityType.OptionalNone)
        return 'none';
    if (cv.type === _1.ClarityType.OptionalSome)
        return `(some ${prettyPrintWithDepth(cv.value, space, depth)})`;
    if (cv.type === _1.ClarityType.ResponseOk)
        return `(ok ${prettyPrintWithDepth(cv.value, space, depth)})`;
    if (cv.type === _1.ClarityType.ResponseErr)
        return `(err ${prettyPrintWithDepth(cv.value, space, depth)})`;
    if (cv.type === _1.ClarityType.List) {
        return formatList(cv, space, depth + 1);
    }
    if (cv.type === _1.ClarityType.Tuple) {
        return formatTuple(cv, space, depth + 1);
    }
    exhaustiveCheck(cv);
}
function stringify(cv, space = 0) {
    return prettyPrintWithDepth(cv, space, 0);
}
exports.stringify = stringify;
exports.prettyPrint = stringify;
//# sourceMappingURL=prettyPrint.js.map