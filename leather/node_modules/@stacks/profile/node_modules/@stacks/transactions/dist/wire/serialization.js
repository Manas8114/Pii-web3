"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deserializePublicKey = exports.serializePublicKeyBytes = exports.serializePublicKey = exports.serializeTransactionAuthFieldBytes = exports.serializeTransactionAuthField = exports.serializeMessageSignatureBytes = exports.serializeMessageSignature = exports.deserializeTransactionAuthField = exports.deserializeMessageSignature = exports.deserializePayload = exports.serializePayloadBytes = exports.serializePayload = exports.deserializePostConditionWire = exports.serializePostConditionWireBytes = exports.serializePostConditionWire = exports.deserializeLPList = exports.serializeLPListBytes = exports.serializeLPList = exports.deserializeAsset = exports.serializeAssetBytes = exports.serializeAsset = exports.deserializeMemoString = exports.serializeMemoStringBytes = exports.serializeMemoString = exports.deserializeLPString = exports.serializeLPStringBytes = exports.serializeLPString = exports.deserializePrincipal = exports.serializePrincipalBytes = exports.serializePrincipal = exports.deserializeAddress = exports.serializeAddressBytes = exports.serializeAddress = exports.deserializeStacksWire = exports.serializeStacksWireBytes = exports.serializeStacksWire = void 0;
const common_1 = require("@stacks/common");
const BytesReader_1 = require("../BytesReader");
const clarity_1 = require("../clarity");
const constants_1 = require("../constants");
const errors_1 = require("../errors");
const keys_1 = require("../keys");
const utils_1 = require("../utils");
const create_1 = require("./create");
const types_1 = require("./types");
function serializeStacksWire(wire) {
    return (0, common_1.bytesToHex)(serializeStacksWireBytes(wire));
}
exports.serializeStacksWire = serializeStacksWire;
function serializeStacksWireBytes(wire) {
    switch (wire.type) {
        case types_1.StacksWireType.Address:
            return serializeAddressBytes(wire);
        case types_1.StacksWireType.Principal:
            return serializePrincipalBytes(wire);
        case types_1.StacksWireType.LengthPrefixedString:
            return serializeLPStringBytes(wire);
        case types_1.StacksWireType.MemoString:
            return serializeMemoStringBytes(wire);
        case types_1.StacksWireType.Asset:
            return serializeAssetBytes(wire);
        case types_1.StacksWireType.PostCondition:
            return serializePostConditionWireBytes(wire);
        case types_1.StacksWireType.PublicKey:
            return serializePublicKeyBytes(wire);
        case types_1.StacksWireType.LengthPrefixedList:
            return serializeLPListBytes(wire);
        case types_1.StacksWireType.Payload:
            return serializePayloadBytes(wire);
        case types_1.StacksWireType.TransactionAuthField:
            return serializeTransactionAuthFieldBytes(wire);
        case types_1.StacksWireType.MessageSignature:
            return serializeMessageSignatureBytes(wire);
    }
}
exports.serializeStacksWireBytes = serializeStacksWireBytes;
function deserializeStacksWire(bytesReader, type, listType) {
    switch (type) {
        case types_1.StacksWireType.Address:
            return deserializeAddress(bytesReader);
        case types_1.StacksWireType.Principal:
            return deserializePrincipal(bytesReader);
        case types_1.StacksWireType.LengthPrefixedString:
            return deserializeLPString(bytesReader);
        case types_1.StacksWireType.MemoString:
            return deserializeMemoString(bytesReader);
        case types_1.StacksWireType.Asset:
            return deserializeAsset(bytesReader);
        case types_1.StacksWireType.PostCondition:
            return deserializePostConditionWire(bytesReader);
        case types_1.StacksWireType.PublicKey:
            return deserializePublicKey(bytesReader);
        case types_1.StacksWireType.Payload:
            return deserializePayload(bytesReader);
        case types_1.StacksWireType.LengthPrefixedList:
            if (!listType) {
                throw new errors_1.DeserializationError('No list type specified');
            }
            return deserializeLPList(bytesReader, listType);
        case types_1.StacksWireType.MessageSignature:
            return deserializeMessageSignature(bytesReader);
        default:
            throw new Error('Could not recognize StacksWireType');
    }
}
exports.deserializeStacksWire = deserializeStacksWire;
function serializeAddress(address) {
    return (0, common_1.bytesToHex)(serializeAddressBytes(address));
}
exports.serializeAddress = serializeAddress;
function serializeAddressBytes(address) {
    const bytesArray = [];
    bytesArray.push((0, common_1.hexToBytes)((0, common_1.intToHex)(address.version, 1)));
    bytesArray.push((0, common_1.hexToBytes)(address.hash160));
    return (0, common_1.concatArray)(bytesArray);
}
exports.serializeAddressBytes = serializeAddressBytes;
function deserializeAddress(serialized) {
    const bytesReader = (0, common_1.isInstance)(serialized, BytesReader_1.BytesReader)
        ? serialized
        : new BytesReader_1.BytesReader(serialized);
    const version = (0, common_1.hexToInt)((0, common_1.bytesToHex)(bytesReader.readBytes(1)));
    const data = (0, common_1.bytesToHex)(bytesReader.readBytes(20));
    return { type: types_1.StacksWireType.Address, version, hash160: data };
}
exports.deserializeAddress = deserializeAddress;
function serializePrincipal(principal) {
    return (0, common_1.bytesToHex)(serializePrincipalBytes(principal));
}
exports.serializePrincipal = serializePrincipal;
function serializePrincipalBytes(principal) {
    const bytesArray = [];
    bytesArray.push(principal.prefix);
    if (principal.prefix === constants_1.PostConditionPrincipalId.Standard ||
        principal.prefix === constants_1.PostConditionPrincipalId.Contract) {
        bytesArray.push(serializeAddressBytes(principal.address));
    }
    if (principal.prefix === constants_1.PostConditionPrincipalId.Contract) {
        bytesArray.push(serializeLPStringBytes(principal.contractName));
    }
    return (0, common_1.concatArray)(bytesArray);
}
exports.serializePrincipalBytes = serializePrincipalBytes;
function deserializePrincipal(serialized) {
    const bytesReader = (0, common_1.isInstance)(serialized, BytesReader_1.BytesReader)
        ? serialized
        : new BytesReader_1.BytesReader(serialized);
    const prefix = bytesReader.readUInt8Enum(constants_1.PostConditionPrincipalId, n => {
        throw new errors_1.DeserializationError(`Unexpected Principal payload type: ${n}`);
    });
    if (prefix === constants_1.PostConditionPrincipalId.Origin) {
        return { type: types_1.StacksWireType.Principal, prefix };
    }
    const address = deserializeAddress(bytesReader);
    if (prefix === constants_1.PostConditionPrincipalId.Standard) {
        return { type: types_1.StacksWireType.Principal, prefix, address };
    }
    const contractName = deserializeLPString(bytesReader);
    return {
        type: types_1.StacksWireType.Principal,
        prefix,
        address,
        contractName,
    };
}
exports.deserializePrincipal = deserializePrincipal;
function serializeLPString(lps) {
    return (0, common_1.bytesToHex)(serializeLPStringBytes(lps));
}
exports.serializeLPString = serializeLPString;
function serializeLPStringBytes(lps) {
    const bytesArray = [];
    const contentBytes = (0, common_1.utf8ToBytes)(lps.content);
    const length = contentBytes.byteLength;
    bytesArray.push((0, common_1.hexToBytes)((0, common_1.intToHex)(length, lps.lengthPrefixBytes)));
    bytesArray.push(contentBytes);
    return (0, common_1.concatArray)(bytesArray);
}
exports.serializeLPStringBytes = serializeLPStringBytes;
function deserializeLPString(serialized, prefixBytes, maxLength) {
    prefixBytes = prefixBytes ? prefixBytes : 1;
    const bytesReader = (0, common_1.isInstance)(serialized, BytesReader_1.BytesReader)
        ? serialized
        : new BytesReader_1.BytesReader(serialized);
    const length = (0, common_1.hexToInt)((0, common_1.bytesToHex)(bytesReader.readBytes(prefixBytes)));
    const content = (0, common_1.bytesToUtf8)(bytesReader.readBytes(length));
    return (0, create_1.createLPString)(content, prefixBytes, maxLength ?? 128);
}
exports.deserializeLPString = deserializeLPString;
function serializeMemoString(memoString) {
    return (0, common_1.bytesToHex)(serializeMemoStringBytes(memoString));
}
exports.serializeMemoString = serializeMemoString;
function serializeMemoStringBytes(memoString) {
    const bytesArray = [];
    const contentBytes = (0, common_1.utf8ToBytes)(memoString.content);
    const paddedContent = (0, utils_1.rightPadHexToLength)((0, common_1.bytesToHex)(contentBytes), constants_1.MEMO_MAX_LENGTH_BYTES * 2);
    bytesArray.push((0, common_1.hexToBytes)(paddedContent));
    return (0, common_1.concatArray)(bytesArray);
}
exports.serializeMemoStringBytes = serializeMemoStringBytes;
function deserializeMemoString(serialized) {
    const bytesReader = (0, common_1.isInstance)(serialized, BytesReader_1.BytesReader)
        ? serialized
        : new BytesReader_1.BytesReader(serialized);
    let content = (0, common_1.bytesToUtf8)(bytesReader.readBytes(constants_1.MEMO_MAX_LENGTH_BYTES));
    content = content.replace(/\u0000*$/, '');
    return { type: types_1.StacksWireType.MemoString, content };
}
exports.deserializeMemoString = deserializeMemoString;
function serializeAsset(info) {
    return (0, common_1.bytesToHex)(serializeAssetBytes(info));
}
exports.serializeAsset = serializeAsset;
function serializeAssetBytes(info) {
    const bytesArray = [];
    bytesArray.push(serializeAddressBytes(info.address));
    bytesArray.push(serializeLPStringBytes(info.contractName));
    bytesArray.push(serializeLPStringBytes(info.assetName));
    return (0, common_1.concatArray)(bytesArray);
}
exports.serializeAssetBytes = serializeAssetBytes;
function deserializeAsset(serialized) {
    const bytesReader = (0, common_1.isInstance)(serialized, BytesReader_1.BytesReader)
        ? serialized
        : new BytesReader_1.BytesReader(serialized);
    return {
        type: types_1.StacksWireType.Asset,
        address: deserializeAddress(bytesReader),
        contractName: deserializeLPString(bytesReader),
        assetName: deserializeLPString(bytesReader),
    };
}
exports.deserializeAsset = deserializeAsset;
function serializeLPList(lpList) {
    return (0, common_1.bytesToHex)(serializeLPListBytes(lpList));
}
exports.serializeLPList = serializeLPList;
function serializeLPListBytes(lpList) {
    const list = lpList.values;
    const bytesArray = [];
    bytesArray.push((0, common_1.hexToBytes)((0, common_1.intToHex)(list.length, lpList.lengthPrefixBytes)));
    for (const l of list) {
        bytesArray.push(serializeStacksWireBytes(l));
    }
    return (0, common_1.concatArray)(bytesArray);
}
exports.serializeLPListBytes = serializeLPListBytes;
function deserializeLPList(serialized, type, lengthPrefixBytes) {
    const bytesReader = (0, common_1.isInstance)(serialized, BytesReader_1.BytesReader)
        ? serialized
        : new BytesReader_1.BytesReader(serialized);
    const length = (0, common_1.hexToInt)((0, common_1.bytesToHex)(bytesReader.readBytes(lengthPrefixBytes || 4)));
    const l = [];
    for (let index = 0; index < length; index++) {
        switch (type) {
            case types_1.StacksWireType.Address:
                l.push(deserializeAddress(bytesReader));
                break;
            case types_1.StacksWireType.LengthPrefixedString:
                l.push(deserializeLPString(bytesReader));
                break;
            case types_1.StacksWireType.MemoString:
                l.push(deserializeMemoString(bytesReader));
                break;
            case types_1.StacksWireType.Asset:
                l.push(deserializeAsset(bytesReader));
                break;
            case types_1.StacksWireType.PostCondition:
                l.push(deserializePostConditionWire(bytesReader));
                break;
            case types_1.StacksWireType.PublicKey:
                l.push(deserializePublicKey(bytesReader));
                break;
            case types_1.StacksWireType.TransactionAuthField:
                l.push(deserializeTransactionAuthField(bytesReader));
                break;
        }
    }
    return (0, create_1.createLPList)(l, lengthPrefixBytes);
}
exports.deserializeLPList = deserializeLPList;
function serializePostConditionWire(postCondition) {
    return (0, common_1.bytesToHex)(serializePostConditionWireBytes(postCondition));
}
exports.serializePostConditionWire = serializePostConditionWire;
function serializePostConditionWireBytes(postCondition) {
    const bytesArray = [];
    bytesArray.push(postCondition.conditionType);
    bytesArray.push(serializePrincipalBytes(postCondition.principal));
    if (postCondition.conditionType === constants_1.PostConditionType.Fungible ||
        postCondition.conditionType === constants_1.PostConditionType.NonFungible) {
        bytesArray.push(serializeAssetBytes(postCondition.asset));
    }
    if (postCondition.conditionType === constants_1.PostConditionType.NonFungible) {
        bytesArray.push((0, clarity_1.serializeCVBytes)(postCondition.assetName));
    }
    bytesArray.push(postCondition.conditionCode);
    if (postCondition.conditionType === constants_1.PostConditionType.STX ||
        postCondition.conditionType === constants_1.PostConditionType.Fungible) {
        if (postCondition.amount > BigInt('0xffffffffffffffff'))
            throw new errors_1.SerializationError('The post-condition amount may not be larger than 8 bytes');
        bytesArray.push((0, common_1.intToBytes)(postCondition.amount, 8));
    }
    return (0, common_1.concatArray)(bytesArray);
}
exports.serializePostConditionWireBytes = serializePostConditionWireBytes;
function deserializePostConditionWire(serialized) {
    const bytesReader = (0, common_1.isInstance)(serialized, BytesReader_1.BytesReader)
        ? serialized
        : new BytesReader_1.BytesReader(serialized);
    const postConditionType = bytesReader.readUInt8Enum(constants_1.PostConditionType, n => {
        throw new errors_1.DeserializationError(`Could not read ${n} as PostConditionType`);
    });
    const principal = deserializePrincipal(bytesReader);
    let conditionCode;
    let asset;
    let amount;
    switch (postConditionType) {
        case constants_1.PostConditionType.STX:
            conditionCode = bytesReader.readUInt8Enum(constants_1.FungibleConditionCode, n => {
                throw new errors_1.DeserializationError(`Could not read ${n} as FungibleConditionCode`);
            });
            amount = BigInt(`0x${(0, common_1.bytesToHex)(bytesReader.readBytes(8))}`);
            return {
                type: types_1.StacksWireType.PostCondition,
                conditionType: constants_1.PostConditionType.STX,
                principal,
                conditionCode,
                amount,
            };
        case constants_1.PostConditionType.Fungible:
            asset = deserializeAsset(bytesReader);
            conditionCode = bytesReader.readUInt8Enum(constants_1.FungibleConditionCode, n => {
                throw new errors_1.DeserializationError(`Could not read ${n} as FungibleConditionCode`);
            });
            amount = BigInt(`0x${(0, common_1.bytesToHex)(bytesReader.readBytes(8))}`);
            return {
                type: types_1.StacksWireType.PostCondition,
                conditionType: constants_1.PostConditionType.Fungible,
                principal,
                conditionCode,
                amount,
                asset: asset,
            };
        case constants_1.PostConditionType.NonFungible:
            asset = deserializeAsset(bytesReader);
            const assetName = (0, clarity_1.deserializeCV)(bytesReader);
            conditionCode = bytesReader.readUInt8Enum(constants_1.NonFungibleConditionCode, n => {
                throw new errors_1.DeserializationError(`Could not read ${n} as FungibleConditionCode`);
            });
            return {
                type: types_1.StacksWireType.PostCondition,
                conditionType: constants_1.PostConditionType.NonFungible,
                principal,
                conditionCode,
                asset,
                assetName,
            };
    }
}
exports.deserializePostConditionWire = deserializePostConditionWire;
function serializePayload(payload) {
    return (0, common_1.bytesToHex)(serializePayloadBytes(payload));
}
exports.serializePayload = serializePayload;
function serializePayloadBytes(payload) {
    const bytesArray = [];
    bytesArray.push(payload.payloadType);
    switch (payload.payloadType) {
        case constants_1.PayloadType.TokenTransfer:
            bytesArray.push((0, clarity_1.serializeCVBytes)(payload.recipient));
            bytesArray.push((0, common_1.intToBytes)(payload.amount, 8));
            bytesArray.push(serializeStacksWireBytes(payload.memo));
            break;
        case constants_1.PayloadType.ContractCall:
            bytesArray.push(serializeStacksWireBytes(payload.contractAddress));
            bytesArray.push(serializeStacksWireBytes(payload.contractName));
            bytesArray.push(serializeStacksWireBytes(payload.functionName));
            const numArgs = new Uint8Array(4);
            (0, common_1.writeUInt32BE)(numArgs, payload.functionArgs.length, 0);
            bytesArray.push(numArgs);
            payload.functionArgs.forEach(arg => {
                bytesArray.push((0, clarity_1.serializeCVBytes)(arg));
            });
            break;
        case constants_1.PayloadType.SmartContract:
            bytesArray.push(serializeStacksWireBytes(payload.contractName));
            bytesArray.push(serializeStacksWireBytes(payload.codeBody));
            break;
        case constants_1.PayloadType.VersionedSmartContract:
            bytesArray.push(payload.clarityVersion);
            bytesArray.push(serializeStacksWireBytes(payload.contractName));
            bytesArray.push(serializeStacksWireBytes(payload.codeBody));
            break;
        case constants_1.PayloadType.PoisonMicroblock:
            break;
        case constants_1.PayloadType.Coinbase:
            bytesArray.push(payload.coinbaseBytes);
            break;
        case constants_1.PayloadType.CoinbaseToAltRecipient:
            bytesArray.push(payload.coinbaseBytes);
            bytesArray.push((0, clarity_1.serializeCVBytes)(payload.recipient));
            break;
        case constants_1.PayloadType.NakamotoCoinbase:
            bytesArray.push(payload.coinbaseBytes);
            bytesArray.push((0, clarity_1.serializeCVBytes)(payload.recipient ? (0, clarity_1.someCV)(payload.recipient) : (0, clarity_1.noneCV)()));
            bytesArray.push(payload.vrfProof);
            break;
        case constants_1.PayloadType.TenureChange:
            bytesArray.push((0, common_1.hexToBytes)(payload.tenureHash));
            bytesArray.push((0, common_1.hexToBytes)(payload.previousTenureHash));
            bytesArray.push((0, common_1.hexToBytes)(payload.burnViewHash));
            bytesArray.push((0, common_1.hexToBytes)(payload.previousTenureEnd));
            bytesArray.push((0, common_1.writeUInt32BE)(new Uint8Array(4), payload.previousTenureBlocks));
            bytesArray.push((0, common_1.writeUInt8)(new Uint8Array(1), payload.cause));
            bytesArray.push((0, common_1.hexToBytes)(payload.publicKeyHash));
            break;
    }
    return (0, common_1.concatArray)(bytesArray);
}
exports.serializePayloadBytes = serializePayloadBytes;
function deserializePayload(serialized) {
    const bytesReader = (0, common_1.isInstance)(serialized, BytesReader_1.BytesReader)
        ? serialized
        : new BytesReader_1.BytesReader(serialized);
    const payloadType = bytesReader.readUInt8Enum(constants_1.PayloadType, n => {
        throw new Error(`Cannot recognize PayloadType: ${n}`);
    });
    switch (payloadType) {
        case constants_1.PayloadType.TokenTransfer:
            const recipient = (0, clarity_1.deserializeCV)(bytesReader);
            const amount = (0, common_1.intToBigInt)(bytesReader.readBytes(8));
            const memo = deserializeMemoString(bytesReader);
            return (0, create_1.createTokenTransferPayload)(recipient, amount, memo);
        case constants_1.PayloadType.ContractCall:
            const contractAddress = deserializeAddress(bytesReader);
            const contractCallName = deserializeLPString(bytesReader);
            const functionName = deserializeLPString(bytesReader);
            const functionArgs = [];
            const numberOfArgs = bytesReader.readUInt32BE();
            for (let i = 0; i < numberOfArgs; i++) {
                const clarityValue = (0, clarity_1.deserializeCV)(bytesReader);
                functionArgs.push(clarityValue);
            }
            return (0, create_1.createContractCallPayload)(contractAddress, contractCallName, functionName, functionArgs);
        case constants_1.PayloadType.SmartContract:
            const smartContractName = deserializeLPString(bytesReader);
            const codeBody = deserializeLPString(bytesReader, 4, 100000);
            return (0, create_1.createSmartContractPayload)(smartContractName, codeBody);
        case constants_1.PayloadType.VersionedSmartContract: {
            const clarityVersion = bytesReader.readUInt8Enum(constants_1.ClarityVersion, n => {
                throw new Error(`Cannot recognize ClarityVersion: ${n}`);
            });
            const smartContractName = deserializeLPString(bytesReader);
            const codeBody = deserializeLPString(bytesReader, 4, constants_1.STRING_MAX_LENGTH);
            return (0, create_1.createSmartContractPayload)(smartContractName, codeBody, clarityVersion);
        }
        case constants_1.PayloadType.PoisonMicroblock:
            return (0, create_1.createPoisonPayload)();
        case constants_1.PayloadType.Coinbase: {
            const coinbaseBytes = bytesReader.readBytes(constants_1.COINBASE_BYTES_LENGTH);
            return (0, create_1.createCoinbasePayload)(coinbaseBytes);
        }
        case constants_1.PayloadType.CoinbaseToAltRecipient: {
            const coinbaseBytes = bytesReader.readBytes(constants_1.COINBASE_BYTES_LENGTH);
            const altRecipient = (0, clarity_1.deserializeCV)(bytesReader);
            return (0, create_1.createCoinbasePayload)(coinbaseBytes, altRecipient);
        }
        case constants_1.PayloadType.NakamotoCoinbase: {
            const coinbaseBytes = bytesReader.readBytes(constants_1.COINBASE_BYTES_LENGTH);
            const recipient = (0, clarity_1.deserializeCV)(bytesReader);
            const vrfProof = bytesReader.readBytes(constants_1.VRF_PROOF_BYTES_LENGTH);
            return (0, create_1.createNakamotoCoinbasePayload)(coinbaseBytes, recipient, vrfProof);
        }
        case constants_1.PayloadType.TenureChange:
            const tenureHash = (0, common_1.bytesToHex)(bytesReader.readBytes(20));
            const previousTenureHash = (0, common_1.bytesToHex)(bytesReader.readBytes(20));
            const burnViewHash = (0, common_1.bytesToHex)(bytesReader.readBytes(20));
            const previousTenureEnd = (0, common_1.bytesToHex)(bytesReader.readBytes(32));
            const previousTenureBlocks = bytesReader.readUInt32BE();
            const cause = bytesReader.readUInt8Enum(constants_1.TenureChangeCause, n => {
                throw new Error(`Cannot recognize TenureChangeCause: ${n}`);
            });
            const publicKeyHash = (0, common_1.bytesToHex)(bytesReader.readBytes(20));
            return (0, create_1.createTenureChangePayload)(tenureHash, previousTenureHash, burnViewHash, previousTenureEnd, previousTenureBlocks, cause, publicKeyHash);
    }
}
exports.deserializePayload = deserializePayload;
function deserializeMessageSignature(serialized) {
    const bytesReader = (0, common_1.isInstance)(serialized, BytesReader_1.BytesReader)
        ? serialized
        : new BytesReader_1.BytesReader(serialized);
    return (0, create_1.createMessageSignature)((0, common_1.bytesToHex)(bytesReader.readBytes(constants_1.RECOVERABLE_ECDSA_SIG_LENGTH_BYTES)));
}
exports.deserializeMessageSignature = deserializeMessageSignature;
function deserializeTransactionAuthField(serialized) {
    const bytesReader = (0, common_1.isInstance)(serialized, BytesReader_1.BytesReader)
        ? serialized
        : new BytesReader_1.BytesReader(serialized);
    const authFieldType = bytesReader.readUInt8Enum(constants_1.AuthFieldType, n => {
        throw new errors_1.DeserializationError(`Could not read ${n} as AuthFieldType`);
    });
    switch (authFieldType) {
        case constants_1.AuthFieldType.PublicKeyCompressed:
            return (0, create_1.createTransactionAuthField)(constants_1.PubKeyEncoding.Compressed, deserializePublicKey(bytesReader));
        case constants_1.AuthFieldType.PublicKeyUncompressed:
            return (0, create_1.createTransactionAuthField)(constants_1.PubKeyEncoding.Uncompressed, (0, keys_1.createStacksPublicKey)((0, keys_1.uncompressPublicKey)(deserializePublicKey(bytesReader).data)));
        case constants_1.AuthFieldType.SignatureCompressed:
            return (0, create_1.createTransactionAuthField)(constants_1.PubKeyEncoding.Compressed, deserializeMessageSignature(bytesReader));
        case constants_1.AuthFieldType.SignatureUncompressed:
            return (0, create_1.createTransactionAuthField)(constants_1.PubKeyEncoding.Uncompressed, deserializeMessageSignature(bytesReader));
        default:
            throw new Error(`Unknown auth field type: ${JSON.stringify(authFieldType)}`);
    }
}
exports.deserializeTransactionAuthField = deserializeTransactionAuthField;
function serializeMessageSignature(messageSignature) {
    return (0, common_1.bytesToHex)(serializeMessageSignatureBytes(messageSignature));
}
exports.serializeMessageSignature = serializeMessageSignature;
function serializeMessageSignatureBytes(messageSignature) {
    return (0, common_1.hexToBytes)(messageSignature.data);
}
exports.serializeMessageSignatureBytes = serializeMessageSignatureBytes;
function serializeTransactionAuthField(field) {
    return (0, common_1.bytesToHex)(serializeTransactionAuthFieldBytes(field));
}
exports.serializeTransactionAuthField = serializeTransactionAuthField;
function serializeTransactionAuthFieldBytes(field) {
    const bytesArray = [];
    switch (field.contents.type) {
        case types_1.StacksWireType.PublicKey:
            bytesArray.push(field.pubKeyEncoding === constants_1.PubKeyEncoding.Compressed
                ? constants_1.AuthFieldType.PublicKeyCompressed
                : constants_1.AuthFieldType.PublicKeyUncompressed);
            bytesArray.push((0, common_1.hexToBytes)((0, keys_1.compressPublicKey)(field.contents.data)));
            break;
        case types_1.StacksWireType.MessageSignature:
            bytesArray.push(field.pubKeyEncoding === constants_1.PubKeyEncoding.Compressed
                ? constants_1.AuthFieldType.SignatureCompressed
                : constants_1.AuthFieldType.SignatureUncompressed);
            bytesArray.push(serializeMessageSignatureBytes(field.contents));
            break;
    }
    return (0, common_1.concatArray)(bytesArray);
}
exports.serializeTransactionAuthFieldBytes = serializeTransactionAuthFieldBytes;
function serializePublicKey(key) {
    return (0, common_1.bytesToHex)(serializePublicKeyBytes(key));
}
exports.serializePublicKey = serializePublicKey;
function serializePublicKeyBytes(key) {
    return key.data.slice();
}
exports.serializePublicKeyBytes = serializePublicKeyBytes;
function deserializePublicKey(serialized) {
    const bytesReader = (0, common_1.isInstance)(serialized, BytesReader_1.BytesReader)
        ? serialized
        : new BytesReader_1.BytesReader(serialized);
    const fieldId = bytesReader.readUInt8();
    const keyLength = fieldId === 4 ? constants_1.UNCOMPRESSED_PUBKEY_LENGTH_BYTES : constants_1.COMPRESSED_PUBKEY_LENGTH_BYTES;
    return (0, keys_1.createStacksPublicKey)((0, common_1.concatArray)([fieldId, bytesReader.readBytes(keyLength)]));
}
exports.deserializePublicKey = deserializePublicKey;
//# sourceMappingURL=serialization.js.map