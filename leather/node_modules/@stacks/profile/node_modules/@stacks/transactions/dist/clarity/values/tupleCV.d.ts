import { ClarityValue } from '../clarityValue';
import { TupleCV, TupleData } from '../types';
export declare function tupleCV<T extends ClarityValue = ClarityValue>(data: TupleData<T>): TupleCV<TupleData<T>>;
