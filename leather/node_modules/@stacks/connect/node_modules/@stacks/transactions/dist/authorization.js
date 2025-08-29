"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deserializeAuthorization = exports.serializeAuthorizationBytes = exports.serializeAuthorization = exports.setSponsor = exports.setSponsorNonce = exports.setNonce = exports.getFee = exports.setFee = exports.verifyOrigin = exports.intoInitialSighashAuth = exports.createSponsoredAuth = exports.createStandardAuth = exports.nextVerification = exports.nextSignature = exports.sigHashPreSign = exports.deserializeSpendingCondition = exports.serializeSpendingConditionBytes = exports.serializeSpendingCondition = exports.deserializeMultiSigSpendingCondition = exports.deserializeSingleSigSpendingCondition = exports.serializeMultiSigSpendingConditionBytes = exports.serializeMultiSigSpendingCondition = exports.serializeSingleSigSpendingConditionBytes = exports.serializeSingleSigSpendingCondition = exports.isNonSequentialMultiSig = exports.isSequentialMultiSig = exports.isSingleSig = exports.createMultiSigSpendingCondition = exports.createSingleSigSpendingCondition = exports.createSpendingCondition = exports.emptyMessageSignature = void 0;
const common_1 = require("@stacks/common");
const constants_1 = require("./constants");
const errors_1 = require("./errors");
const keys_1 = require("./keys");
const utils_1 = require("./utils");
const wire_1 = require("./wire");
function emptyMessageSignature() {
    return {
        type: wire_1.StacksWireType.MessageSignature,
        data: (0, common_1.bytesToHex)(new Uint8Array(constants_1.RECOVERABLE_ECDSA_SIG_LENGTH_BYTES)),
    };
}
exports.emptyMessageSignature = emptyMessageSignature;
function createSpendingCondition(options) {
    if ('publicKey' in options) {
        return createSingleSigSpendingCondition(constants_1.AddressHashMode.P2PKH, options.publicKey, options.nonce, options.fee);
    }
    return createMultiSigSpendingCondition(constants_1.AddressHashMode.P2SH, options.numSignatures, options.publicKeys, options.nonce, options.fee);
}
exports.createSpendingCondition = createSpendingCondition;
function createSingleSigSpendingCondition(hashMode, pubKey, nonce, fee) {
    const signer = (0, wire_1.addressFromPublicKeys)(0, hashMode, 1, [(0, keys_1.createStacksPublicKey)(pubKey)]).hash160;
    const keyEncoding = (0, keys_1.publicKeyIsCompressed)(pubKey)
        ? constants_1.PubKeyEncoding.Compressed
        : constants_1.PubKeyEncoding.Uncompressed;
    return {
        hashMode,
        signer,
        nonce: (0, common_1.intToBigInt)(nonce),
        fee: (0, common_1.intToBigInt)(fee),
        keyEncoding,
        signature: emptyMessageSignature(),
    };
}
exports.createSingleSigSpendingCondition = createSingleSigSpendingCondition;
function createMultiSigSpendingCondition(hashMode, numSigs, pubKeys, nonce, fee) {
    const stacksPublicKeys = pubKeys.map(keys_1.createStacksPublicKey);
    const signer = (0, wire_1.addressFromPublicKeys)(0, hashMode, numSigs, stacksPublicKeys).hash160;
    return {
        hashMode,
        signer,
        nonce: (0, common_1.intToBigInt)(nonce),
        fee: (0, common_1.intToBigInt)(fee),
        fields: [],
        signaturesRequired: numSigs,
    };
}
exports.createMultiSigSpendingCondition = createMultiSigSpendingCondition;
function isSingleSig(condition) {
    return 'signature' in condition;
}
exports.isSingleSig = isSingleSig;
function isSequentialMultiSig(hashMode) {
    return hashMode === constants_1.AddressHashMode.P2SH || hashMode === constants_1.AddressHashMode.P2WSH;
}
exports.isSequentialMultiSig = isSequentialMultiSig;
function isNonSequentialMultiSig(hashMode) {
    return (hashMode === constants_1.AddressHashMode.P2SHNonSequential ||
        hashMode === constants_1.AddressHashMode.P2WSHNonSequential);
}
exports.isNonSequentialMultiSig = isNonSequentialMultiSig;
function clearCondition(condition) {
    const cloned = (0, utils_1.cloneDeep)(condition);
    cloned.nonce = 0;
    cloned.fee = 0;
    if (isSingleSig(cloned)) {
        cloned.signature = emptyMessageSignature();
    }
    else {
        cloned.fields = [];
    }
    return {
        ...cloned,
        nonce: BigInt(0),
        fee: BigInt(0),
    };
}
function serializeSingleSigSpendingCondition(condition) {
    return (0, common_1.bytesToHex)(serializeSingleSigSpendingConditionBytes(condition));
}
exports.serializeSingleSigSpendingCondition = serializeSingleSigSpendingCondition;
function serializeSingleSigSpendingConditionBytes(condition) {
    const bytesArray = [
        condition.hashMode,
        (0, common_1.hexToBytes)(condition.signer),
        (0, common_1.intToBytes)(condition.nonce, 8),
        (0, common_1.intToBytes)(condition.fee, 8),
        condition.keyEncoding,
        (0, wire_1.serializeMessageSignatureBytes)(condition.signature),
    ];
    return (0, common_1.concatArray)(bytesArray);
}
exports.serializeSingleSigSpendingConditionBytes = serializeSingleSigSpendingConditionBytes;
function serializeMultiSigSpendingCondition(condition) {
    return (0, common_1.bytesToHex)(serializeMultiSigSpendingConditionBytes(condition));
}
exports.serializeMultiSigSpendingCondition = serializeMultiSigSpendingCondition;
function serializeMultiSigSpendingConditionBytes(condition) {
    const bytesArray = [
        condition.hashMode,
        (0, common_1.hexToBytes)(condition.signer),
        (0, common_1.intToBytes)(condition.nonce, 8),
        (0, common_1.intToBytes)(condition.fee, 8),
    ];
    const fields = (0, wire_1.createLPList)(condition.fields);
    bytesArray.push((0, wire_1.serializeLPListBytes)(fields));
    const numSigs = new Uint8Array(2);
    (0, common_1.writeUInt16BE)(numSigs, condition.signaturesRequired, 0);
    bytesArray.push(numSigs);
    return (0, common_1.concatArray)(bytesArray);
}
exports.serializeMultiSigSpendingConditionBytes = serializeMultiSigSpendingConditionBytes;
function deserializeSingleSigSpendingCondition(hashMode, bytesReader) {
    const signer = (0, common_1.bytesToHex)(bytesReader.readBytes(20));
    const nonce = BigInt(`0x${(0, common_1.bytesToHex)(bytesReader.readBytes(8))}`);
    const fee = BigInt(`0x${(0, common_1.bytesToHex)(bytesReader.readBytes(8))}`);
    const keyEncoding = bytesReader.readUInt8Enum(constants_1.PubKeyEncoding, n => {
        throw new errors_1.DeserializationError(`Could not parse ${n} as PubKeyEncoding`);
    });
    if (hashMode === constants_1.AddressHashMode.P2WPKH && keyEncoding != constants_1.PubKeyEncoding.Compressed) {
        throw new errors_1.DeserializationError('Failed to parse singlesig spending condition: incomaptible hash mode and key encoding');
    }
    const signature = (0, wire_1.deserializeMessageSignature)(bytesReader);
    return {
        hashMode,
        signer,
        nonce,
        fee,
        keyEncoding,
        signature,
    };
}
exports.deserializeSingleSigSpendingCondition = deserializeSingleSigSpendingCondition;
function deserializeMultiSigSpendingCondition(hashMode, bytesReader) {
    const signer = (0, common_1.bytesToHex)(bytesReader.readBytes(20));
    const nonce = BigInt('0x' + (0, common_1.bytesToHex)(bytesReader.readBytes(8)));
    const fee = BigInt('0x' + (0, common_1.bytesToHex)(bytesReader.readBytes(8)));
    const fields = (0, wire_1.deserializeLPList)(bytesReader, wire_1.StacksWireType.TransactionAuthField)
        .values;
    let haveUncompressed = false;
    let numSigs = 0;
    for (const field of fields) {
        switch (field.contents.type) {
            case wire_1.StacksWireType.PublicKey:
                if (!(0, keys_1.publicKeyIsCompressed)(field.contents.data))
                    haveUncompressed = true;
                break;
            case wire_1.StacksWireType.MessageSignature:
                if (field.pubKeyEncoding === constants_1.PubKeyEncoding.Uncompressed)
                    haveUncompressed = true;
                numSigs += 1;
                if (numSigs === 65536)
                    throw new errors_1.VerificationError('Failed to parse multisig spending condition: too many signatures');
                break;
        }
    }
    const signaturesRequired = bytesReader.readUInt16BE();
    if (haveUncompressed &&
        (hashMode === constants_1.AddressHashMode.P2WSH || hashMode === constants_1.AddressHashMode.P2WSHNonSequential)) {
        throw new errors_1.VerificationError('Uncompressed keys are not allowed in this hash mode');
    }
    return {
        hashMode,
        signer,
        nonce,
        fee,
        fields,
        signaturesRequired,
    };
}
exports.deserializeMultiSigSpendingCondition = deserializeMultiSigSpendingCondition;
function serializeSpendingCondition(condition) {
    return (0, common_1.bytesToHex)(serializeSpendingConditionBytes(condition));
}
exports.serializeSpendingCondition = serializeSpendingCondition;
function serializeSpendingConditionBytes(condition) {
    if (isSingleSig(condition))
        return serializeSingleSigSpendingConditionBytes(condition);
    return serializeMultiSigSpendingConditionBytes(condition);
}
exports.serializeSpendingConditionBytes = serializeSpendingConditionBytes;
function deserializeSpendingCondition(bytesReader) {
    const hashMode = bytesReader.readUInt8Enum(constants_1.AddressHashMode, n => {
        throw new errors_1.DeserializationError(`Could not parse ${n} as AddressHashMode`);
    });
    if (hashMode === constants_1.AddressHashMode.P2PKH || hashMode === constants_1.AddressHashMode.P2WPKH) {
        return deserializeSingleSigSpendingCondition(hashMode, bytesReader);
    }
    else {
        return deserializeMultiSigSpendingCondition(hashMode, bytesReader);
    }
}
exports.deserializeSpendingCondition = deserializeSpendingCondition;
function sigHashPreSign(curSigHash, authType, fee, nonce) {
    const hashLength = 32 + 1 + 8 + 8;
    const sigHash = curSigHash +
        (0, common_1.bytesToHex)(new Uint8Array([authType])) +
        (0, common_1.bytesToHex)((0, common_1.intToBytes)(fee, 8)) +
        (0, common_1.bytesToHex)((0, common_1.intToBytes)(nonce, 8));
    if ((0, common_1.hexToBytes)(sigHash).byteLength !== hashLength) {
        throw Error('Invalid signature hash length');
    }
    return (0, utils_1.txidFromData)((0, common_1.hexToBytes)(sigHash));
}
exports.sigHashPreSign = sigHashPreSign;
function sigHashPostSign(curSigHash, pubKey, signature) {
    const hashLength = 32 + 1 + constants_1.RECOVERABLE_ECDSA_SIG_LENGTH_BYTES;
    const pubKeyEncoding = (0, keys_1.publicKeyIsCompressed)(pubKey.data)
        ? constants_1.PubKeyEncoding.Compressed
        : constants_1.PubKeyEncoding.Uncompressed;
    const sigHash = curSigHash + (0, utils_1.leftPadHex)(pubKeyEncoding.toString(16)) + signature;
    const sigHashBytes = (0, common_1.hexToBytes)(sigHash);
    if (sigHashBytes.byteLength > hashLength) {
        throw Error('Invalid signature hash length');
    }
    return (0, utils_1.txidFromData)(sigHashBytes);
}
function nextSignature(curSigHash, authType, fee, nonce, privateKey) {
    const sigHashPre = sigHashPreSign(curSigHash, authType, fee, nonce);
    const signature = (0, keys_1.signWithKey)(privateKey, sigHashPre);
    const publicKey = (0, keys_1.createStacksPublicKey)((0, keys_1.privateKeyToPublic)(privateKey));
    const nextSigHash = sigHashPostSign(sigHashPre, publicKey, signature);
    return {
        nextSig: signature,
        nextSigHash,
    };
}
exports.nextSignature = nextSignature;
function nextVerification(initialSigHash, authType, fee, nonce, pubKeyEncoding, signature) {
    const sigHashPre = sigHashPreSign(initialSigHash, authType, fee, nonce);
    const publicKey = (0, keys_1.createStacksPublicKey)((0, keys_1.publicKeyFromSignatureVrs)(sigHashPre, signature, pubKeyEncoding));
    const nextSigHash = sigHashPostSign(sigHashPre, publicKey, signature);
    return {
        pubKey: publicKey,
        nextSigHash,
    };
}
exports.nextVerification = nextVerification;
function newInitialSigHash() {
    const spendingCondition = createSingleSigSpendingCondition(constants_1.AddressHashMode.P2PKH, '', 0, 0);
    spendingCondition.signer = (0, wire_1.createEmptyAddress)().hash160;
    spendingCondition.keyEncoding = constants_1.PubKeyEncoding.Compressed;
    spendingCondition.signature = emptyMessageSignature();
    return spendingCondition;
}
function verify(condition, initialSigHash, authType) {
    if (isSingleSig(condition)) {
        return verifySingleSig(condition, initialSigHash, authType);
    }
    else {
        return verifyMultiSig(condition, initialSigHash, authType);
    }
}
function verifySingleSig(condition, initialSigHash, authType) {
    const { pubKey, nextSigHash } = nextVerification(initialSigHash, authType, condition.fee, condition.nonce, condition.keyEncoding, condition.signature.data);
    const addrBytes = (0, wire_1.addressFromPublicKeys)(0, condition.hashMode, 1, [pubKey]).hash160;
    if (addrBytes !== condition.signer)
        throw new errors_1.VerificationError(`Signer hash does not equal hash of public key(s): ${addrBytes} != ${condition.signer}`);
    return nextSigHash;
}
function verifyMultiSig(condition, initialSigHash, authType) {
    const publicKeys = [];
    let curSigHash = initialSigHash;
    let haveUncompressed = false;
    let numSigs = 0;
    for (const field of condition.fields) {
        switch (field.contents.type) {
            case wire_1.StacksWireType.PublicKey:
                if (!(0, keys_1.publicKeyIsCompressed)(field.contents.data))
                    haveUncompressed = true;
                publicKeys.push(field.contents);
                break;
            case wire_1.StacksWireType.MessageSignature:
                if (field.pubKeyEncoding === constants_1.PubKeyEncoding.Uncompressed)
                    haveUncompressed = true;
                const { pubKey, nextSigHash } = nextVerification(curSigHash, authType, condition.fee, condition.nonce, field.pubKeyEncoding, field.contents.data);
                if (isSequentialMultiSig(condition.hashMode)) {
                    curSigHash = nextSigHash;
                }
                publicKeys.push(pubKey);
                numSigs += 1;
                if (numSigs === 65536)
                    throw new errors_1.VerificationError('Too many signatures');
                break;
        }
    }
    if ((isSequentialMultiSig(condition.hashMode) && numSigs !== condition.signaturesRequired) ||
        (isNonSequentialMultiSig(condition.hashMode) && numSigs < condition.signaturesRequired))
        throw new errors_1.VerificationError('Incorrect number of signatures');
    if (haveUncompressed &&
        (condition.hashMode === constants_1.AddressHashMode.P2WSH ||
            condition.hashMode === constants_1.AddressHashMode.P2WSHNonSequential))
        throw new errors_1.VerificationError('Uncompressed keys are not allowed in this hash mode');
    const addrBytes = (0, wire_1.addressFromPublicKeys)(0, condition.hashMode, condition.signaturesRequired, publicKeys).hash160;
    if (addrBytes !== condition.signer)
        throw new errors_1.VerificationError(`Signer hash does not equal hash of public key(s): ${addrBytes} != ${condition.signer}`);
    return curSigHash;
}
function createStandardAuth(spendingCondition) {
    return {
        authType: constants_1.AuthType.Standard,
        spendingCondition,
    };
}
exports.createStandardAuth = createStandardAuth;
function createSponsoredAuth(spendingCondition, sponsorSpendingCondition) {
    return {
        authType: constants_1.AuthType.Sponsored,
        spendingCondition,
        sponsorSpendingCondition: sponsorSpendingCondition
            ? sponsorSpendingCondition
            : createSingleSigSpendingCondition(constants_1.AddressHashMode.P2PKH, '0'.repeat(66), 0, 0),
    };
}
exports.createSponsoredAuth = createSponsoredAuth;
function intoInitialSighashAuth(auth) {
    if (auth.spendingCondition) {
        switch (auth.authType) {
            case constants_1.AuthType.Standard:
                return createStandardAuth(clearCondition(auth.spendingCondition));
            case constants_1.AuthType.Sponsored:
                return createSponsoredAuth(clearCondition(auth.spendingCondition), newInitialSigHash());
            default:
                throw new errors_1.SigningError('Unexpected authorization type for signing');
        }
    }
    throw new Error('Authorization missing SpendingCondition');
}
exports.intoInitialSighashAuth = intoInitialSighashAuth;
function verifyOrigin(auth, initialSigHash) {
    switch (auth.authType) {
        case constants_1.AuthType.Standard:
            return verify(auth.spendingCondition, initialSigHash, constants_1.AuthType.Standard);
        case constants_1.AuthType.Sponsored:
            return verify(auth.spendingCondition, initialSigHash, constants_1.AuthType.Standard);
        default:
            throw new errors_1.SigningError('Invalid origin auth type');
    }
}
exports.verifyOrigin = verifyOrigin;
function setFee(auth, amount) {
    switch (auth.authType) {
        case constants_1.AuthType.Standard:
            const spendingCondition = {
                ...auth.spendingCondition,
                fee: (0, common_1.intToBigInt)(amount),
            };
            return { ...auth, spendingCondition };
        case constants_1.AuthType.Sponsored:
            const sponsorSpendingCondition = {
                ...auth.sponsorSpendingCondition,
                fee: (0, common_1.intToBigInt)(amount),
            };
            return { ...auth, sponsorSpendingCondition };
    }
}
exports.setFee = setFee;
function getFee(auth) {
    switch (auth.authType) {
        case constants_1.AuthType.Standard:
            return auth.spendingCondition.fee;
        case constants_1.AuthType.Sponsored:
            return auth.sponsorSpendingCondition.fee;
    }
}
exports.getFee = getFee;
function setNonce(auth, nonce) {
    const spendingCondition = {
        ...auth.spendingCondition,
        nonce: (0, common_1.intToBigInt)(nonce),
    };
    return {
        ...auth,
        spendingCondition,
    };
}
exports.setNonce = setNonce;
function setSponsorNonce(auth, nonce) {
    const sponsorSpendingCondition = {
        ...auth.sponsorSpendingCondition,
        nonce: (0, common_1.intToBigInt)(nonce),
    };
    return {
        ...auth,
        sponsorSpendingCondition,
    };
}
exports.setSponsorNonce = setSponsorNonce;
function setSponsor(auth, sponsorSpendingCondition) {
    const sc = {
        ...sponsorSpendingCondition,
        nonce: (0, common_1.intToBigInt)(sponsorSpendingCondition.nonce),
        fee: (0, common_1.intToBigInt)(sponsorSpendingCondition.fee),
    };
    return {
        ...auth,
        sponsorSpendingCondition: sc,
    };
}
exports.setSponsor = setSponsor;
function serializeAuthorization(auth) {
    return (0, common_1.bytesToHex)(serializeAuthorizationBytes(auth));
}
exports.serializeAuthorization = serializeAuthorization;
function serializeAuthorizationBytes(auth) {
    const bytesArray = [];
    bytesArray.push(auth.authType);
    switch (auth.authType) {
        case constants_1.AuthType.Standard:
            bytesArray.push(serializeSpendingConditionBytes(auth.spendingCondition));
            break;
        case constants_1.AuthType.Sponsored:
            bytesArray.push(serializeSpendingConditionBytes(auth.spendingCondition));
            bytesArray.push(serializeSpendingConditionBytes(auth.sponsorSpendingCondition));
            break;
    }
    return (0, common_1.concatArray)(bytesArray);
}
exports.serializeAuthorizationBytes = serializeAuthorizationBytes;
function deserializeAuthorization(bytesReader) {
    const authType = bytesReader.readUInt8Enum(constants_1.AuthType, n => {
        throw new errors_1.DeserializationError(`Could not parse ${n} as AuthType`);
    });
    let spendingCondition;
    switch (authType) {
        case constants_1.AuthType.Standard:
            spendingCondition = deserializeSpendingCondition(bytesReader);
            return createStandardAuth(spendingCondition);
        case constants_1.AuthType.Sponsored:
            spendingCondition = deserializeSpendingCondition(bytesReader);
            const sponsorSpendingCondition = deserializeSpendingCondition(bytesReader);
            return createSponsoredAuth(spendingCondition, sponsorSpendingCondition);
    }
}
exports.deserializeAuthorization = deserializeAuthorization;
//# sourceMappingURL=authorization.js.map