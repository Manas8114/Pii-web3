"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.boolCV = exports.falseCV = exports.trueCV = void 0;
const constants_1 = require("../constants");
const trueCV = () => ({ type: constants_1.ClarityType.BoolTrue });
exports.trueCV = trueCV;
const falseCV = () => ({ type: constants_1.ClarityType.BoolFalse });
exports.falseCV = falseCV;
const boolCV = (bool) => (bool ? (0, exports.trueCV)() : (0, exports.falseCV)());
exports.boolCV = boolCV;
//# sourceMappingURL=booleanCV.js.map