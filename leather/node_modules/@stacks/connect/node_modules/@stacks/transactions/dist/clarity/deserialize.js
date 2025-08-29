"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deserializeCV = void 0;
const common_1 = require("@stacks/common");
const _1 = require(".");
const BytesReader_1 = require("../BytesReader");
const errors_1 = require("../errors");
const wire_1 = require("../wire");
function deserializeCV(serializedClarityValue) {
    let bytesReader;
    if (typeof serializedClarityValue === 'string') {
        const hasHexPrefix = serializedClarityValue.slice(0, 2).toLowerCase() === '0x';
        bytesReader = new BytesReader_1.BytesReader((0, common_1.hexToBytes)(hasHexPrefix ? serializedClarityValue.slice(2) : serializedClarityValue));
    }
    else if (serializedClarityValue instanceof Uint8Array) {
        bytesReader = new BytesReader_1.BytesReader(serializedClarityValue);
    }
    else {
        bytesReader = serializedClarityValue;
    }
    const type = bytesReader.readUInt8Enum(_1.ClarityWireType, n => {
        throw new errors_1.DeserializationError(`Cannot recognize Clarity Type: ${n}`);
    });
    switch (type) {
        case _1.ClarityWireType.int:
            return (0, _1.intCV)((0, common_1.bytesToTwosBigInt)(bytesReader.readBytes(16)));
        case _1.ClarityWireType.uint:
            return (0, _1.uintCV)(bytesReader.readBytes(16));
        case _1.ClarityWireType.buffer:
            const bufferLength = bytesReader.readUInt32BE();
            return (0, _1.bufferCV)(bytesReader.readBytes(bufferLength));
        case _1.ClarityWireType.true:
            return (0, _1.trueCV)();
        case _1.ClarityWireType.false:
            return (0, _1.falseCV)();
        case _1.ClarityWireType.address:
            const sAddress = (0, wire_1.deserializeAddress)(bytesReader);
            return (0, _1.standardPrincipalCVFromAddress)(sAddress);
        case _1.ClarityWireType.contract:
            const cAddress = (0, wire_1.deserializeAddress)(bytesReader);
            const contractName = (0, wire_1.deserializeLPString)(bytesReader);
            return (0, _1.contractPrincipalCVFromAddress)(cAddress, contractName);
        case _1.ClarityWireType.ok:
            return (0, _1.responseOkCV)(deserializeCV(bytesReader));
        case _1.ClarityWireType.err:
            return (0, _1.responseErrorCV)(deserializeCV(bytesReader));
        case _1.ClarityWireType.none:
            return (0, _1.noneCV)();
        case _1.ClarityWireType.some:
            return (0, _1.someCV)(deserializeCV(bytesReader));
        case _1.ClarityWireType.list:
            const listLength = bytesReader.readUInt32BE();
            const listContents = [];
            for (let i = 0; i < listLength; i++) {
                listContents.push(deserializeCV(bytesReader));
            }
            return (0, _1.listCV)(listContents);
        case _1.ClarityWireType.tuple:
            const tupleLength = bytesReader.readUInt32BE();
            const tupleContents = {};
            for (let i = 0; i < tupleLength; i++) {
                const clarityName = (0, wire_1.deserializeLPString)(bytesReader).content;
                if (clarityName === undefined) {
                    throw new errors_1.DeserializationError('"content" is undefined');
                }
                tupleContents[clarityName] = deserializeCV(bytesReader);
            }
            return (0, _1.tupleCV)(tupleContents);
        case _1.ClarityWireType.ascii:
            const asciiStrLen = bytesReader.readUInt32BE();
            const asciiStr = (0, common_1.bytesToAscii)(bytesReader.readBytes(asciiStrLen));
            return (0, _1.stringAsciiCV)(asciiStr);
        case _1.ClarityWireType.utf8:
            const utf8StrLen = bytesReader.readUInt32BE();
            const utf8Str = (0, common_1.bytesToUtf8)(bytesReader.readBytes(utf8StrLen));
            return (0, _1.stringUtf8CV)(utf8Str);
        default:
            throw new errors_1.DeserializationError('Unable to deserialize Clarity Value from Uint8Array. Could not find valid Clarity Type.');
    }
}
exports.deserializeCV = deserializeCV;
//# sourceMappingURL=deserialize.js.map