"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.bufferCVFromString = exports.bufferCV = void 0;
const common_1 = require("@stacks/common");
const constants_1 = require("../constants");
const bufferCV = (buffer) => {
    if (buffer.byteLength > 1048576) {
        throw new Error('Cannot construct clarity buffer that is greater than 1MB');
    }
    return { type: constants_1.ClarityType.Buffer, value: (0, common_1.bytesToHex)(buffer) };
};
exports.bufferCV = bufferCV;
const bufferCVFromString = (str) => (0, exports.bufferCV)((0, common_1.utf8ToBytes)(str));
exports.bufferCVFromString = bufferCVFromString;
//# sourceMappingURL=bufferCV.js.map