export const MICROSTX_IN_STX = 1000000;
export function microStxToStx(amountInMicroStx) {
    return amountInMicroStx / MICROSTX_IN_STX;
}
export function stxToMicroStx(amountInStx) {
    return amountInStx * MICROSTX_IN_STX;
}
//# sourceMappingURL=units.js.map