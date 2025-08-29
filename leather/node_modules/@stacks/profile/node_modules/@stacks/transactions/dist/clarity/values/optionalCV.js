"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.optionalCVOf = exports.someCV = exports.noneCV = void 0;
const constants_1 = require("../constants");
function noneCV() {
    return { type: constants_1.ClarityType.OptionalNone };
}
exports.noneCV = noneCV;
function someCV(value) {
    return { type: constants_1.ClarityType.OptionalSome, value };
}
exports.someCV = someCV;
function optionalCVOf(value) {
    return value ? someCV(value) : noneCV();
}
exports.optionalCVOf = optionalCVOf;
//# sourceMappingURL=optionalCV.js.map