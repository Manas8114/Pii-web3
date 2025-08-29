import { ClarityType } from '../constants';
import { isClarityName } from '../../utils';
export function tupleCV(data) {
    for (const key in data) {
        if (!isClarityName(key)) {
            throw new Error(`"${key}" is not a valid Clarity name`);
        }
    }
    return { type: ClarityType.Tuple, value: data };
}
//# sourceMappingURL=tupleCV.js.map