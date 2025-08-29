import { ClarityType } from '../constants';
export const stringAsciiCV = (data) => {
    return { type: ClarityType.StringASCII, value: data };
};
export const stringUtf8CV = (data) => {
    return { type: ClarityType.StringUTF8, value: data };
};
export const stringCV = (data, encoding) => {
    switch (encoding) {
        case 'ascii':
            return stringAsciiCV(data);
        case 'utf8':
            return stringUtf8CV(data);
    }
};
//# sourceMappingURL=stringCV.js.map