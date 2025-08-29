import { bytesToAscii, bytesToTwosBigInt, bytesToUtf8, hexToBytes } from '@stacks/common';
import { ClarityWireType, bufferCV, contractPrincipalCVFromAddress, falseCV, intCV, listCV, noneCV, responseErrorCV, responseOkCV, someCV, standardPrincipalCVFromAddress, stringAsciiCV, stringUtf8CV, trueCV, tupleCV, uintCV, } from '.';
import { BytesReader } from '../BytesReader';
import { DeserializationError } from '../errors';
import { deserializeAddress, deserializeLPString } from '../wire';
export function deserializeCV(serializedClarityValue) {
    let bytesReader;
    if (typeof serializedClarityValue === 'string') {
        const hasHexPrefix = serializedClarityValue.slice(0, 2).toLowerCase() === '0x';
        bytesReader = new BytesReader(hexToBytes(hasHexPrefix ? serializedClarityValue.slice(2) : serializedClarityValue));
    }
    else if (serializedClarityValue instanceof Uint8Array) {
        bytesReader = new BytesReader(serializedClarityValue);
    }
    else {
        bytesReader = serializedClarityValue;
    }
    const type = bytesReader.readUInt8Enum(ClarityWireType, n => {
        throw new DeserializationError(`Cannot recognize Clarity Type: ${n}`);
    });
    switch (type) {
        case ClarityWireType.int:
            return intCV(bytesToTwosBigInt(bytesReader.readBytes(16)));
        case ClarityWireType.uint:
            return uintCV(bytesReader.readBytes(16));
        case ClarityWireType.buffer:
            const bufferLength = bytesReader.readUInt32BE();
            return bufferCV(bytesReader.readBytes(bufferLength));
        case ClarityWireType.true:
            return trueCV();
        case ClarityWireType.false:
            return falseCV();
        case ClarityWireType.address:
            const sAddress = deserializeAddress(bytesReader);
            return standardPrincipalCVFromAddress(sAddress);
        case ClarityWireType.contract:
            const cAddress = deserializeAddress(bytesReader);
            const contractName = deserializeLPString(bytesReader);
            return contractPrincipalCVFromAddress(cAddress, contractName);
        case ClarityWireType.ok:
            return responseOkCV(deserializeCV(bytesReader));
        case ClarityWireType.err:
            return responseErrorCV(deserializeCV(bytesReader));
        case ClarityWireType.none:
            return noneCV();
        case ClarityWireType.some:
            return someCV(deserializeCV(bytesReader));
        case ClarityWireType.list:
            const listLength = bytesReader.readUInt32BE();
            const listContents = [];
            for (let i = 0; i < listLength; i++) {
                listContents.push(deserializeCV(bytesReader));
            }
            return listCV(listContents);
        case ClarityWireType.tuple:
            const tupleLength = bytesReader.readUInt32BE();
            const tupleContents = {};
            for (let i = 0; i < tupleLength; i++) {
                const clarityName = deserializeLPString(bytesReader).content;
                if (clarityName === undefined) {
                    throw new DeserializationError('"content" is undefined');
                }
                tupleContents[clarityName] = deserializeCV(bytesReader);
            }
            return tupleCV(tupleContents);
        case ClarityWireType.ascii:
            const asciiStrLen = bytesReader.readUInt32BE();
            const asciiStr = bytesToAscii(bytesReader.readBytes(asciiStrLen));
            return stringAsciiCV(asciiStr);
        case ClarityWireType.utf8:
            const utf8StrLen = bytesReader.readUInt32BE();
            const utf8Str = bytesToUtf8(bytesReader.readBytes(utf8StrLen));
            return stringUtf8CV(utf8Str);
        default:
            throw new DeserializationError('Unable to deserialize Clarity Value from Uint8Array. Could not find valid Clarity Type.');
    }
}
//# sourceMappingURL=deserialize.js.map