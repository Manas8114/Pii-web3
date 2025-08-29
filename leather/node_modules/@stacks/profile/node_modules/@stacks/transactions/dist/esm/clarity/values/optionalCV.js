import { ClarityType } from '../constants';
export function noneCV() {
    return { type: ClarityType.OptionalNone };
}
export function someCV(value) {
    return { type: ClarityType.OptionalSome, value };
}
export function optionalCVOf(value) {
    return value ? someCV(value) : noneCV();
}
//# sourceMappingURL=optionalCV.js.map