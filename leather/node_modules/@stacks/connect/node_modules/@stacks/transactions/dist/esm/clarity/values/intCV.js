import { bytesToTwosBigInt, hexToBytes, intToBigInt, isInstance, } from '@stacks/common';
import { ClarityType } from '../constants';
const MAX_U128 = BigInt('0xffffffffffffffffffffffffffffffff');
const MIN_U128 = BigInt(0);
const MAX_I128 = BigInt('0x7fffffffffffffffffffffffffffffff');
const MIN_I128 = BigInt('-170141183460469231731687303715884105728');
export const intCV = (value) => {
    if (typeof value === 'string' && value.toLowerCase().startsWith('0x')) {
        value = bytesToTwosBigInt(hexToBytes(value));
    }
    if (isInstance(value, Uint8Array))
        value = bytesToTwosBigInt(value);
    const bigInt = intToBigInt(value);
    if (bigInt > MAX_I128) {
        throw new RangeError(`Cannot construct clarity integer from value greater than ${MAX_I128}`);
    }
    else if (bigInt < MIN_I128) {
        throw new RangeError(`Cannot construct clarity integer form value less than ${MIN_I128}`);
    }
    return { type: ClarityType.Int, value: bigInt };
};
export const uintCV = (value) => {
    const bigInt = intToBigInt(value);
    if (bigInt < MIN_U128) {
        throw new RangeError('Cannot construct unsigned clarity integer from negative value');
    }
    else if (bigInt > MAX_U128) {
        throw new RangeError(`Cannot construct unsigned clarity integer greater than ${MAX_U128}`);
    }
    return { type: ClarityType.UInt, value: bigInt };
};
//# sourceMappingURL=intCV.js.map