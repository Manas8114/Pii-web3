import { ClarityType } from '../constants';
export const trueCV = () => ({ type: ClarityType.BoolTrue });
export const falseCV = () => ({ type: ClarityType.BoolFalse });
export const boolCV = (bool) => (bool ? trueCV() : falseCV());
//# sourceMappingURL=booleanCV.js.map