import { bytesToHex, concatArray, hexToBytes, intToBigInt, intToBytes, writeUInt16BE, } from '@stacks/common';
import { AddressHashMode, AuthType, PubKeyEncoding, RECOVERABLE_ECDSA_SIG_LENGTH_BYTES, } from './constants';
import { DeserializationError, SigningError, VerificationError } from './errors';
import { createStacksPublicKey, privateKeyToPublic, publicKeyFromSignatureVrs, publicKeyIsCompressed, signWithKey, } from './keys';
import { cloneDeep, leftPadHex, txidFromData } from './utils';
import { addressFromPublicKeys, createEmptyAddress, createLPList, deserializeLPList, deserializeMessageSignature, serializeLPListBytes, serializeMessageSignatureBytes, StacksWireType, } from './wire';
export function emptyMessageSignature() {
    return {
        type: StacksWireType.MessageSignature,
        data: bytesToHex(new Uint8Array(RECOVERABLE_ECDSA_SIG_LENGTH_BYTES)),
    };
}
export function createSpendingCondition(options) {
    if ('publicKey' in options) {
        return createSingleSigSpendingCondition(AddressHashMode.P2PKH, options.publicKey, options.nonce, options.fee);
    }
    return createMultiSigSpendingCondition(AddressHashMode.P2SH, options.numSignatures, options.publicKeys, options.nonce, options.fee);
}
export function createSingleSigSpendingCondition(hashMode, pubKey, nonce, fee) {
    const signer = addressFromPublicKeys(0, hashMode, 1, [createStacksPublicKey(pubKey)]).hash160;
    const keyEncoding = publicKeyIsCompressed(pubKey)
        ? PubKeyEncoding.Compressed
        : PubKeyEncoding.Uncompressed;
    return {
        hashMode,
        signer,
        nonce: intToBigInt(nonce),
        fee: intToBigInt(fee),
        keyEncoding,
        signature: emptyMessageSignature(),
    };
}
export function createMultiSigSpendingCondition(hashMode, numSigs, pubKeys, nonce, fee) {
    const stacksPublicKeys = pubKeys.map(createStacksPublicKey);
    const signer = addressFromPublicKeys(0, hashMode, numSigs, stacksPublicKeys).hash160;
    return {
        hashMode,
        signer,
        nonce: intToBigInt(nonce),
        fee: intToBigInt(fee),
        fields: [],
        signaturesRequired: numSigs,
    };
}
export function isSingleSig(condition) {
    return 'signature' in condition;
}
export function isSequentialMultiSig(hashMode) {
    return hashMode === AddressHashMode.P2SH || hashMode === AddressHashMode.P2WSH;
}
export function isNonSequentialMultiSig(hashMode) {
    return (hashMode === AddressHashMode.P2SHNonSequential ||
        hashMode === AddressHashMode.P2WSHNonSequential);
}
function clearCondition(condition) {
    const cloned = cloneDeep(condition);
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
export function serializeSingleSigSpendingCondition(condition) {
    return bytesToHex(serializeSingleSigSpendingConditionBytes(condition));
}
export function serializeSingleSigSpendingConditionBytes(condition) {
    const bytesArray = [
        condition.hashMode,
        hexToBytes(condition.signer),
        intToBytes(condition.nonce, 8),
        intToBytes(condition.fee, 8),
        condition.keyEncoding,
        serializeMessageSignatureBytes(condition.signature),
    ];
    return concatArray(bytesArray);
}
export function serializeMultiSigSpendingCondition(condition) {
    return bytesToHex(serializeMultiSigSpendingConditionBytes(condition));
}
export function serializeMultiSigSpendingConditionBytes(condition) {
    const bytesArray = [
        condition.hashMode,
        hexToBytes(condition.signer),
        intToBytes(condition.nonce, 8),
        intToBytes(condition.fee, 8),
    ];
    const fields = createLPList(condition.fields);
    bytesArray.push(serializeLPListBytes(fields));
    const numSigs = new Uint8Array(2);
    writeUInt16BE(numSigs, condition.signaturesRequired, 0);
    bytesArray.push(numSigs);
    return concatArray(bytesArray);
}
export function deserializeSingleSigSpendingCondition(hashMode, bytesReader) {
    const signer = bytesToHex(bytesReader.readBytes(20));
    const nonce = BigInt(`0x${bytesToHex(bytesReader.readBytes(8))}`);
    const fee = BigInt(`0x${bytesToHex(bytesReader.readBytes(8))}`);
    const keyEncoding = bytesReader.readUInt8Enum(PubKeyEncoding, n => {
        throw new DeserializationError(`Could not parse ${n} as PubKeyEncoding`);
    });
    if (hashMode === AddressHashMode.P2WPKH && keyEncoding != PubKeyEncoding.Compressed) {
        throw new DeserializationError('Failed to parse singlesig spending condition: incomaptible hash mode and key encoding');
    }
    const signature = deserializeMessageSignature(bytesReader);
    return {
        hashMode,
        signer,
        nonce,
        fee,
        keyEncoding,
        signature,
    };
}
export function deserializeMultiSigSpendingCondition(hashMode, bytesReader) {
    const signer = bytesToHex(bytesReader.readBytes(20));
    const nonce = BigInt('0x' + bytesToHex(bytesReader.readBytes(8)));
    const fee = BigInt('0x' + bytesToHex(bytesReader.readBytes(8)));
    const fields = deserializeLPList(bytesReader, StacksWireType.TransactionAuthField)
        .values;
    let haveUncompressed = false;
    let numSigs = 0;
    for (const field of fields) {
        switch (field.contents.type) {
            case StacksWireType.PublicKey:
                if (!publicKeyIsCompressed(field.contents.data))
                    haveUncompressed = true;
                break;
            case StacksWireType.MessageSignature:
                if (field.pubKeyEncoding === PubKeyEncoding.Uncompressed)
                    haveUncompressed = true;
                numSigs += 1;
                if (numSigs === 65536)
                    throw new VerificationError('Failed to parse multisig spending condition: too many signatures');
                break;
        }
    }
    const signaturesRequired = bytesReader.readUInt16BE();
    if (haveUncompressed &&
        (hashMode === AddressHashMode.P2WSH || hashMode === AddressHashMode.P2WSHNonSequential)) {
        throw new VerificationError('Uncompressed keys are not allowed in this hash mode');
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
export function serializeSpendingCondition(condition) {
    return bytesToHex(serializeSpendingConditionBytes(condition));
}
export function serializeSpendingConditionBytes(condition) {
    if (isSingleSig(condition))
        return serializeSingleSigSpendingConditionBytes(condition);
    return serializeMultiSigSpendingConditionBytes(condition);
}
export function deserializeSpendingCondition(bytesReader) {
    const hashMode = bytesReader.readUInt8Enum(AddressHashMode, n => {
        throw new DeserializationError(`Could not parse ${n} as AddressHashMode`);
    });
    if (hashMode === AddressHashMode.P2PKH || hashMode === AddressHashMode.P2WPKH) {
        return deserializeSingleSigSpendingCondition(hashMode, bytesReader);
    }
    else {
        return deserializeMultiSigSpendingCondition(hashMode, bytesReader);
    }
}
export function sigHashPreSign(curSigHash, authType, fee, nonce) {
    const hashLength = 32 + 1 + 8 + 8;
    const sigHash = curSigHash +
        bytesToHex(new Uint8Array([authType])) +
        bytesToHex(intToBytes(fee, 8)) +
        bytesToHex(intToBytes(nonce, 8));
    if (hexToBytes(sigHash).byteLength !== hashLength) {
        throw Error('Invalid signature hash length');
    }
    return txidFromData(hexToBytes(sigHash));
}
function sigHashPostSign(curSigHash, pubKey, signature) {
    const hashLength = 32 + 1 + RECOVERABLE_ECDSA_SIG_LENGTH_BYTES;
    const pubKeyEncoding = publicKeyIsCompressed(pubKey.data)
        ? PubKeyEncoding.Compressed
        : PubKeyEncoding.Uncompressed;
    const sigHash = curSigHash + leftPadHex(pubKeyEncoding.toString(16)) + signature;
    const sigHashBytes = hexToBytes(sigHash);
    if (sigHashBytes.byteLength > hashLength) {
        throw Error('Invalid signature hash length');
    }
    return txidFromData(sigHashBytes);
}
export function nextSignature(curSigHash, authType, fee, nonce, privateKey) {
    const sigHashPre = sigHashPreSign(curSigHash, authType, fee, nonce);
    const signature = signWithKey(privateKey, sigHashPre);
    const publicKey = createStacksPublicKey(privateKeyToPublic(privateKey));
    const nextSigHash = sigHashPostSign(sigHashPre, publicKey, signature);
    return {
        nextSig: signature,
        nextSigHash,
    };
}
export function nextVerification(initialSigHash, authType, fee, nonce, pubKeyEncoding, signature) {
    const sigHashPre = sigHashPreSign(initialSigHash, authType, fee, nonce);
    const publicKey = createStacksPublicKey(publicKeyFromSignatureVrs(sigHashPre, signature, pubKeyEncoding));
    const nextSigHash = sigHashPostSign(sigHashPre, publicKey, signature);
    return {
        pubKey: publicKey,
        nextSigHash,
    };
}
function newInitialSigHash() {
    const spendingCondition = createSingleSigSpendingCondition(AddressHashMode.P2PKH, '', 0, 0);
    spendingCondition.signer = createEmptyAddress().hash160;
    spendingCondition.keyEncoding = PubKeyEncoding.Compressed;
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
    const addrBytes = addressFromPublicKeys(0, condition.hashMode, 1, [pubKey]).hash160;
    if (addrBytes !== condition.signer)
        throw new VerificationError(`Signer hash does not equal hash of public key(s): ${addrBytes} != ${condition.signer}`);
    return nextSigHash;
}
function verifyMultiSig(condition, initialSigHash, authType) {
    const publicKeys = [];
    let curSigHash = initialSigHash;
    let haveUncompressed = false;
    let numSigs = 0;
    for (const field of condition.fields) {
        switch (field.contents.type) {
            case StacksWireType.PublicKey:
                if (!publicKeyIsCompressed(field.contents.data))
                    haveUncompressed = true;
                publicKeys.push(field.contents);
                break;
            case StacksWireType.MessageSignature:
                if (field.pubKeyEncoding === PubKeyEncoding.Uncompressed)
                    haveUncompressed = true;
                const { pubKey, nextSigHash } = nextVerification(curSigHash, authType, condition.fee, condition.nonce, field.pubKeyEncoding, field.contents.data);
                if (isSequentialMultiSig(condition.hashMode)) {
                    curSigHash = nextSigHash;
                }
                publicKeys.push(pubKey);
                numSigs += 1;
                if (numSigs === 65536)
                    throw new VerificationError('Too many signatures');
                break;
        }
    }
    if ((isSequentialMultiSig(condition.hashMode) && numSigs !== condition.signaturesRequired) ||
        (isNonSequentialMultiSig(condition.hashMode) && numSigs < condition.signaturesRequired))
        throw new VerificationError('Incorrect number of signatures');
    if (haveUncompressed &&
        (condition.hashMode === AddressHashMode.P2WSH ||
            condition.hashMode === AddressHashMode.P2WSHNonSequential))
        throw new VerificationError('Uncompressed keys are not allowed in this hash mode');
    const addrBytes = addressFromPublicKeys(0, condition.hashMode, condition.signaturesRequired, publicKeys).hash160;
    if (addrBytes !== condition.signer)
        throw new VerificationError(`Signer hash does not equal hash of public key(s): ${addrBytes} != ${condition.signer}`);
    return curSigHash;
}
export function createStandardAuth(spendingCondition) {
    return {
        authType: AuthType.Standard,
        spendingCondition,
    };
}
export function createSponsoredAuth(spendingCondition, sponsorSpendingCondition) {
    return {
        authType: AuthType.Sponsored,
        spendingCondition,
        sponsorSpendingCondition: sponsorSpendingCondition
            ? sponsorSpendingCondition
            : createSingleSigSpendingCondition(AddressHashMode.P2PKH, '0'.repeat(66), 0, 0),
    };
}
export function intoInitialSighashAuth(auth) {
    if (auth.spendingCondition) {
        switch (auth.authType) {
            case AuthType.Standard:
                return createStandardAuth(clearCondition(auth.spendingCondition));
            case AuthType.Sponsored:
                return createSponsoredAuth(clearCondition(auth.spendingCondition), newInitialSigHash());
            default:
                throw new SigningError('Unexpected authorization type for signing');
        }
    }
    throw new Error('Authorization missing SpendingCondition');
}
export function verifyOrigin(auth, initialSigHash) {
    switch (auth.authType) {
        case AuthType.Standard:
            return verify(auth.spendingCondition, initialSigHash, AuthType.Standard);
        case AuthType.Sponsored:
            return verify(auth.spendingCondition, initialSigHash, AuthType.Standard);
        default:
            throw new SigningError('Invalid origin auth type');
    }
}
export function setFee(auth, amount) {
    switch (auth.authType) {
        case AuthType.Standard:
            const spendingCondition = {
                ...auth.spendingCondition,
                fee: intToBigInt(amount),
            };
            return { ...auth, spendingCondition };
        case AuthType.Sponsored:
            const sponsorSpendingCondition = {
                ...auth.sponsorSpendingCondition,
                fee: intToBigInt(amount),
            };
            return { ...auth, sponsorSpendingCondition };
    }
}
export function getFee(auth) {
    switch (auth.authType) {
        case AuthType.Standard:
            return auth.spendingCondition.fee;
        case AuthType.Sponsored:
            return auth.sponsorSpendingCondition.fee;
    }
}
export function setNonce(auth, nonce) {
    const spendingCondition = {
        ...auth.spendingCondition,
        nonce: intToBigInt(nonce),
    };
    return {
        ...auth,
        spendingCondition,
    };
}
export function setSponsorNonce(auth, nonce) {
    const sponsorSpendingCondition = {
        ...auth.sponsorSpendingCondition,
        nonce: intToBigInt(nonce),
    };
    return {
        ...auth,
        sponsorSpendingCondition,
    };
}
export function setSponsor(auth, sponsorSpendingCondition) {
    const sc = {
        ...sponsorSpendingCondition,
        nonce: intToBigInt(sponsorSpendingCondition.nonce),
        fee: intToBigInt(sponsorSpendingCondition.fee),
    };
    return {
        ...auth,
        sponsorSpendingCondition: sc,
    };
}
export function serializeAuthorization(auth) {
    return bytesToHex(serializeAuthorizationBytes(auth));
}
export function serializeAuthorizationBytes(auth) {
    const bytesArray = [];
    bytesArray.push(auth.authType);
    switch (auth.authType) {
        case AuthType.Standard:
            bytesArray.push(serializeSpendingConditionBytes(auth.spendingCondition));
            break;
        case AuthType.Sponsored:
            bytesArray.push(serializeSpendingConditionBytes(auth.spendingCondition));
            bytesArray.push(serializeSpendingConditionBytes(auth.sponsorSpendingCondition));
            break;
    }
    return concatArray(bytesArray);
}
export function deserializeAuthorization(bytesReader) {
    const authType = bytesReader.readUInt8Enum(AuthType, n => {
        throw new DeserializationError(`Could not parse ${n} as AuthType`);
    });
    let spendingCondition;
    switch (authType) {
        case AuthType.Standard:
            spendingCondition = deserializeSpendingCondition(bytesReader);
            return createStandardAuth(spendingCondition);
        case AuthType.Sponsored:
            spendingCondition = deserializeSpendingCondition(bytesReader);
            const sponsorSpendingCondition = deserializeSpendingCondition(bytesReader);
            return createSponsoredAuth(spendingCondition, sponsorSpendingCondition);
    }
}
//# sourceMappingURL=authorization.js.map