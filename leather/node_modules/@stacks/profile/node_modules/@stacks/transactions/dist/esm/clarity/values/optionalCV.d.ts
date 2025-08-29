import { ClarityValue } from '../clarityValue';
import { NoneCV, OptionalCV } from '../types';
export declare function noneCV(): NoneCV;
export declare function someCV<T extends ClarityValue = ClarityValue>(value: T): OptionalCV<T>;
export declare function optionalCVOf<T extends ClarityValue = ClarityValue>(value?: T): OptionalCV<T>;
