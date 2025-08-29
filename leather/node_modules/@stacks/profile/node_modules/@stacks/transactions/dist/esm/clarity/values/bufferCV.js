import { bytesToHex, utf8ToBytes } from '@stacks/common';
import { ClarityType } from '../constants';
export const bufferCV = (buffer) => {
    if (buffer.byteLength > 1048576) {
        throw new Error('Cannot construct clarity buffer that is greater than 1MB');
    }
    return { type: ClarityType.Buffer, value: bytesToHex(buffer) };
};
export const bufferCVFromString = (str) => bufferCV(utf8ToBytes(str));
//# sourceMappingURL=bufferCV.js.map