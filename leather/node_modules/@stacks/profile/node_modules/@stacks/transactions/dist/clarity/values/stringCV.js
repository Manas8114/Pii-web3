"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.stringCV = exports.stringUtf8CV = exports.stringAsciiCV = void 0;
const constants_1 = require("../constants");
const stringAsciiCV = (data) => {
    return { type: constants_1.ClarityType.StringASCII, value: data };
};
exports.stringAsciiCV = stringAsciiCV;
const stringUtf8CV = (data) => {
    return { type: constants_1.ClarityType.StringUTF8, value: data };
};
exports.stringUtf8CV = stringUtf8CV;
const stringCV = (data, encoding) => {
    switch (encoding) {
        case 'ascii':
            return (0, exports.stringAsciiCV)(data);
        case 'utf8':
            return (0, exports.stringUtf8CV)(data);
    }
};
exports.stringCV = stringCV;
//# sourceMappingURL=stringCV.js.map