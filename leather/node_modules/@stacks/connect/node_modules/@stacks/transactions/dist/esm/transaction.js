import { bytesToHex, concatArray, intToBigInt, isInstance, writeUInt32BE, } from '@stacks/common';
import { STACKS_MAINNET, STACKS_TESTNET, TransactionVersion, networkFrom, whenTransactionVersion, } from '@stacks/network';
import { serializePayloadBytes } from '.';
import { BytesReader } from './BytesReader';
import { deserializeAuthorization, intoInitialSighashAuth, isSingleSig, nextSignature, serializeAuthorizationBytes, setFee, setNonce, setSponsor, setSponsorNonce, verifyOrigin, } from './authorization';
import { AddressHashMode, AnchorMode, AuthType, PostConditionMode, PubKeyEncoding, RECOVERABLE_ECDSA_SIG_LENGTH_BYTES, } from './constants';
import { SerializationError, SigningError } from './errors';
import { createStacksPublicKey, privateKeyIsCompressed, publicKeyIsCompressed } from './keys';
import { cloneDeep, txidFromData } from './utils';
import { StacksWireType, createLPList, createMessageSignature, createTransactionAuthField, deserializeLPList, deserializePayload, serializeLPListBytes, } from './wire';
export class StacksTransactionWire {
    constructor({ auth, payload, postConditions = createLPList([]), postConditionMode = PostConditionMode.Deny, transactionVersion, chainId, network = 'mainnet', }) {
        network = networkFrom(network);
        this.transactionVersion = transactionVersion ?? network.transactionVersion;
        this.chainId = chainId ?? network.chainId;
        this.auth = auth;
        if ('amount' in payload) {
            this.payload = {
                ...payload,
                amount: intToBigInt(payload.amount),
            };
        }
        else {
            this.payload = payload;
        }
        this.postConditionMode = postConditionMode;
        this.postConditions = postConditions;
        this.anchorMode = AnchorMode.Any;
    }
    signBegin() {
        const tx = cloneDeep(this);
        tx.auth = intoInitialSighashAuth(tx.auth);
        return tx.txid();
    }
    verifyBegin() {
        const tx = cloneDeep(this);
        tx.auth = intoInitialSighashAuth(tx.auth);
        return tx.txid();
    }
    verifyOrigin() {
        return verifyOrigin(this.auth, this.verifyBegin());
    }
    signNextOrigin(sigHash, privateKey) {
        if (this.auth.spendingCondition === undefined) {
            throw new Error('"auth.spendingCondition" is undefined');
        }
        if (this.auth.authType === undefined) {
            throw new Error('"auth.authType" is undefined');
        }
        return this.signAndAppend(this.auth.spendingCondition, sigHash, AuthType.Standard, privateKey);
    }
    signNextSponsor(sigHash, privateKey) {
        if (this.auth.authType === AuthType.Sponsored) {
            return this.signAndAppend(this.auth.sponsorSpendingCondition, sigHash, AuthType.Sponsored, privateKey);
        }
        else {
            throw new Error('"auth.sponsorSpendingCondition" is undefined');
        }
    }
    appendPubkey(publicKey) {
        const wire = typeof publicKey === 'object' && 'type' in publicKey
            ? publicKey
            : createStacksPublicKey(publicKey);
        const cond = this.auth.spendingCondition;
        if (cond && !isSingleSig(cond)) {
            const compressed = publicKeyIsCompressed(wire.data);
            cond.fields.push(createTransactionAuthField(compressed ? PubKeyEncoding.Compressed : PubKeyEncoding.Uncompressed, wire));
        }
        else {
            throw new Error(`Can't append public key to a singlesig condition`);
        }
    }
    signAndAppend(condition, curSigHash, authType, privateKey) {
        const { nextSig, nextSigHash } = nextSignature(curSigHash, authType, condition.fee, condition.nonce, privateKey);
        if (isSingleSig(condition)) {
            condition.signature = createMessageSignature(nextSig);
        }
        else {
            const compressed = privateKeyIsCompressed(privateKey);
            condition.fields.push(createTransactionAuthField(compressed ? PubKeyEncoding.Compressed : PubKeyEncoding.Uncompressed, createMessageSignature(nextSig)));
        }
        return nextSigHash;
    }
    txid() {
        const serialized = this.serializeBytes();
        return txidFromData(serialized);
    }
    setSponsor(sponsorSpendingCondition) {
        if (this.auth.authType != AuthType.Sponsored) {
            throw new SigningError('Cannot sponsor sign a non-sponsored transaction');
        }
        this.auth = setSponsor(this.auth, sponsorSpendingCondition);
    }
    setFee(amount) {
        this.auth = setFee(this.auth, amount);
    }
    setNonce(nonce) {
        this.auth = setNonce(this.auth, nonce);
    }
    setSponsorNonce(nonce) {
        if (this.auth.authType != AuthType.Sponsored) {
            throw new SigningError('Cannot sponsor sign a non-sponsored transaction');
        }
        this.auth = setSponsorNonce(this.auth, nonce);
    }
    serialize() {
        return bytesToHex(this.serializeBytes());
    }
    serializeBytes() {
        if (this.transactionVersion === undefined) {
            throw new SerializationError('"transactionVersion" is undefined');
        }
        if (this.chainId === undefined) {
            throw new SerializationError('"chainId" is undefined');
        }
        if (this.auth === undefined) {
            throw new SerializationError('"auth" is undefined');
        }
        if (this.payload === undefined) {
            throw new SerializationError('"payload" is undefined');
        }
        const bytesArray = [];
        bytesArray.push(this.transactionVersion);
        const chainIdBytes = new Uint8Array(4);
        writeUInt32BE(chainIdBytes, this.chainId, 0);
        bytesArray.push(chainIdBytes);
        bytesArray.push(serializeAuthorizationBytes(this.auth));
        bytesArray.push(this.anchorMode);
        bytesArray.push(this.postConditionMode);
        bytesArray.push(serializeLPListBytes(this.postConditions));
        bytesArray.push(serializePayloadBytes(this.payload));
        return concatArray(bytesArray);
    }
}
export function deserializeTransaction(tx) {
    const bytesReader = isInstance(tx, BytesReader) ? tx : new BytesReader(tx);
    const transactionVersion = bytesReader.readUInt8Enum(TransactionVersion, n => {
        throw new Error(`Could not parse ${n} as TransactionVersion`);
    });
    const chainId = bytesReader.readUInt32BE();
    const auth = deserializeAuthorization(bytesReader);
    const anchorMode = bytesReader.readUInt8Enum(AnchorMode, n => {
        throw new Error(`Could not parse ${n} as AnchorMode`);
    });
    const postConditionMode = bytesReader.readUInt8Enum(PostConditionMode, n => {
        throw new Error(`Could not parse ${n} as PostConditionMode`);
    });
    const postConditions = deserializeLPList(bytesReader, StacksWireType.PostCondition);
    const payload = deserializePayload(bytesReader);
    const transaction = new StacksTransactionWire({
        transactionVersion,
        chainId,
        auth,
        payload,
        postConditions,
        postConditionMode,
    });
    transaction.anchorMode = anchorMode;
    return transaction;
}
export function deriveNetworkFromTx(transaction) {
    return whenTransactionVersion(transaction.transactionVersion)({
        [TransactionVersion.Mainnet]: STACKS_MAINNET,
        [TransactionVersion.Testnet]: STACKS_TESTNET,
    });
}
export function estimateTransactionByteLength(transaction) {
    const hashMode = transaction.auth.spendingCondition.hashMode;
    const multiSigHashModes = [AddressHashMode.P2SH, AddressHashMode.P2WSH];
    if (multiSigHashModes.includes(hashMode)) {
        const multiSigSpendingCondition = transaction.auth
            .spendingCondition;
        const existingSignatures = multiSigSpendingCondition.fields.filter(field => field.contents.type === StacksWireType.MessageSignature).length;
        const totalSignatureLength = (multiSigSpendingCondition.signaturesRequired - existingSignatures) *
            (RECOVERABLE_ECDSA_SIG_LENGTH_BYTES + 1);
        return transaction.serializeBytes().byteLength + totalSignatureLength;
    }
    else {
        return transaction.serializeBytes().byteLength;
    }
}
export function serializeTransaction(transaction) {
    return transaction.serialize();
}
export function serializeTransactionBytes(transaction) {
    return transaction.serializeBytes();
}
export function transactionToHex(transaction) {
    return transaction.serialize();
}
//# sourceMappingURL=transaction.js.map