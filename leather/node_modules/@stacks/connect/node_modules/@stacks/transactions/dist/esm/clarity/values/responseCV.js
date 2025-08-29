import { ClarityType } from '../constants';
export function responseErrorCV(value) {
    return { type: ClarityType.ResponseErr, value };
}
export function responseOkCV(value) {
    return { type: ClarityType.ResponseOk, value };
}
//# sourceMappingURL=responseCV.js.map