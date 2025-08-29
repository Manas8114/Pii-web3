import { ClarityValue } from '../clarityValue';
import { ResponseErrorCV, ResponseOkCV } from '../types';
export declare function responseErrorCV<T extends ClarityValue = ClarityValue>(value: T): ResponseErrorCV<T>;
export declare function responseOkCV<T extends ClarityValue = ClarityValue>(value: T): ResponseOkCV<T>;
