"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.stxToMicroStx = exports.microStxToStx = exports.MICROSTX_IN_STX = void 0;
exports.MICROSTX_IN_STX = 1000000;
function microStxToStx(amountInMicroStx) {
    return amountInMicroStx / exports.MICROSTX_IN_STX;
}
exports.microStxToStx = microStxToStx;
function stxToMicroStx(amountInStx) {
    return amountInStx * exports.MICROSTX_IN_STX;
}
exports.stxToMicroStx = stxToMicroStx;
//# sourceMappingURL=units.js.map