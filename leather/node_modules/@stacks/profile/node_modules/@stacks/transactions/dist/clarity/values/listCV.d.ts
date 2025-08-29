import { ClarityValue } from '../clarityValue';
import { ListCV } from '../types';
export declare function listCV<T extends ClarityValue = ClarityValue>(values: T[]): ListCV<T>;
