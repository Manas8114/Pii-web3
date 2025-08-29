"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.transactionToHex = exports.serializeTransactionBytes = exports.serializeTransaction = exports.estimateTransactionByteLength = exports.deriveNetworkFromTx = exports.deserializeTransaction = exports.StacksTransactionWire = void 0;
const common_1 = require("@stacks/common");
const network_1 = require("@stacks/network");
const _1 = require(".");
const BytesReader_1 = require("./BytesReader");
const authorization_1 = require("./authorization");
const constants_1 = require("./constants");
const errors_1 = require("./errors");
const keys_1 = require("./keys");
const utils_1 = require("./utils");
const wire_1 = require("./wire");
class StacksTransactionWire {
    constructor({ auth, payload, postConditions = (0, wire_1.createLPList)([]), postConditionMode = constants_1.PostConditionMode.Deny, transactionVersion, chainId, network = 'mainnet', }) {
        network = (0, network_1.networkFrom)(network);
        this.transactionVersion = transactionVersion ?? network.transactionVersion;
        this.chainId = chainId ?? network.chainId;
        this.auth = auth;
        if ('amount' in payload) {
            this.payload = {
                ...payload,
                amount: (0, common_1.intToBigInt)(payload.amount),
            };
        }
        else {
            this.payload = payload;
        }
        this.postConditionMode = postConditionMode;
        this.postConditions = postConditions;
        this.anchorMode = constants_1.AnchorMode.Any;
    }
    signBegin() {
        const tx = (0, utils_1.cloneDeep)(this);
        tx.auth = (0, authorization_1.intoInitialSighashAuth)(tx.auth);
        return tx.txid();
    }
    verifyBegin() {
        const tx = (0, utils_1.cloneDeep)(this);
        tx.auth = (0, authorization_1.intoInitialSighashAuth)(tx.auth);
        return tx.txid();
    }
    verifyOrigin() {
        return (0, authorization_1.verifyOrigin)(this.auth, this.verifyBegin());
    }
    signNextOrigin(sigHash, privateKey) {
        if (this.auth.spendingCondition === undefined) {
            throw new Error('"auth.spendingCondition" is undefined');
        }
        if (this.auth.authType === undefined) {
            throw new Error('"auth.authType" is undefined');
        }
        return this.signAndAppend(this.auth.spendingCondition, sigHash, constants_1.AuthType.Standard, privateKey);
    }
    signNextSponsor(sigHash, privateKey) {
        if (this.auth.authType === constants_1.AuthType.Sponsored) {
            return this.signAndAppend(this.auth.sponsorSpendingCondition, sigHash, constants_1.AuthType.Sponsored, privateKey);
        }
        else {
            throw new Error('"auth.sponsorSpendingCondition" is undefined');
        }
    }
    appendPubkey(publicKey) {
        const wire = typeof publicKey === 'object' && 'type' in publicKey
            ? publicKey
            : (0, keys_1.createStacksPublicKey)(publicKey);
        const cond = this.auth.spendingCondition;
        if (cond && !(0, authorization_1.isSingleSig)(cond)) {
            const compressed = (0, keys_1.publicKeyIsCompressed)(wire.data);
            cond.fields.push((0, wire_1.createTransactionAuthField)(compressed ? constants_1.PubKeyEncoding.Compressed : constants_1.PubKeyEncoding.Uncompressed, wire));
        }
        else {
            throw new Error(`Can't append public key to a singlesig condition`);
        }
    }
    signAndAppend(condition, curSigHash, authType, privateKey) {
        const { nextSig, nextSigHash } = (0, authorization_1.nextSignature)(curSigHash, authType, condition.fee, condition.nonce, privateKey);
        if ((0, authorization_1.isSingleSig)(condition)) {
            condition.signature = (0, wire_1.createMessageSignature)(nextSig);
        }
        else {
            const compressed = (0, keys_1.privateKeyIsCompressed)(privateKey);
            condition.fields.push((0, wire_1.createTransactionAuthField)(compressed ? constants_1.PubKeyEncoding.Compressed : constants_1.PubKeyEncoding.Uncompressed, (0, wire_1.createMessageSignature)(nextSig)));
        }
        return nextSigHash;
    }
    txid() {
        const serialized = this.serializeBytes();
        return (0, utils_1.txidFromData)(serialized);
    }
    setSponsor(sponsorSpendingCondition) {
        if (this.auth.authType != constants_1.AuthType.Sponsored) {
            throw new errors_1.SigningError('Cannot sponsor sign a non-sponsored transaction');
        }
        this.auth = (0, authorization_1.setSponsor)(this.auth, sponsorSpendingCondition);
    }
    setFee(amount) {
        this.auth = (0, authorization_1.setFee)(this.auth, amount);
    }
    setNonce(nonce) {
        this.auth = (0, authorization_1.setNonce)(this.auth, nonce);
    }
    setSponsorNonce(nonce) {
        if (this.auth.authType != constants_1.AuthType.Sponsored) {
            throw new errors_1.SigningError('Cannot sponsor sign a non-sponsored transaction');
        }
        this.auth = (0, authorization_1.setSponsorNonce)(this.auth, nonce);
    }
    serialize() {
        return (0, common_1.bytesToHex)(this.serializeBytes());
    }
    serializeBytes() {
        if (this.transactionVersion === undefined) {
            throw new errors_1.SerializationError('"transactionVersion" is undefined');
        }
        if (this.chainId === undefined) {
            throw new errors_1.SerializationError('"chainId" is undefined');
        }
        if (this.auth === undefined) {
            throw new errors_1.SerializationError('"auth" is undefined');
        }
        if (this.payload === undefined) {
            throw new errors_1.SerializationError('"payload" is undefined');
        }
        const bytesArray = [];
        bytesArray.push(this.transactionVersion);
        const chainIdBytes = new Uint8Array(4);
        (0, common_1.writeUInt32BE)(chainIdBytes, this.chainId, 0);
        bytesArray.push(chainIdBytes);
        bytesArray.push((0, authorization_1.serializeAuthorizationBytes)(this.auth));
        bytesArray.push(this.anchorMode);
        bytesArray.push(this.postConditionMode);
        bytesArray.push((0, wire_1.serializeLPListBytes)(this.postConditions));
        bytesArray.push((0, _1.serializePayloadBytes)(this.payload));
        return (0, common_1.concatArray)(bytesArray);
    }
}
exports.StacksTransactionWire = StacksTransactionWire;
function deserializeTransaction(tx) {
    const bytesReader = (0, common_1.isInstance)(tx, BytesReader_1.BytesReader) ? tx : new BytesReader_1.BytesReader(tx);
    const transactionVersion = bytesReader.readUInt8Enum(network_1.TransactionVersion, n => {
        throw new Error(`Could not parse ${n} as TransactionVersion`);
    });
    const chainId = bytesReader.readUInt32BE();
    const auth = (0, authorization_1.deserializeAuthorization)(bytesReader);
    const anchorMode = bytesReader.readUInt8Enum(constants_1.AnchorMode, n => {
        throw new Error(`Could not parse ${n} as AnchorMode`);
    });
    const postConditionMode = bytesReader.readUInt8Enum(constants_1.PostConditionMode, n => {
        throw new Error(`Could not parse ${n} as PostConditionMode`);
    });
    const postConditions = (0, wire_1.deserializeLPList)(bytesReader, wire_1.StacksWireType.PostCondition);
    const payload = (0, wire_1.deserializePayload)(bytesReader);
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
exports.deserializeTransaction = deserializeTransaction;
function deriveNetworkFromTx(transaction) {
    return (0, network_1.whenTransactionVersion)(transaction.transactionVersion)({
        [network_1.TransactionVersion.Mainnet]: network_1.STACKS_MAINNET,
        [network_1.TransactionVersion.Testnet]: network_1.STACKS_TESTNET,
    });
}
exports.deriveNetworkFromTx = deriveNetworkFromTx;
function estimateTransactionByteLength(transaction) {
    const hashMode = transaction.auth.spendingCondition.hashMode;
    const multiSigHashModes = [constants_1.AddressHashMode.P2SH, constants_1.AddressHashMode.P2WSH];
    if (multiSigHashModes.includes(hashMode)) {
        const multiSigSpendingCondition = transaction.auth
            .spendingCondition;
        const existingSignatures = multiSigSpendingCondition.fields.filter(field => field.contents.type === wire_1.StacksWireType.MessageSignature).length;
        const totalSignatureLength = (multiSigSpendingCondition.signaturesRequired - existingSignatures) *
            (constants_1.RECOVERABLE_ECDSA_SIG_LENGTH_BYTES + 1);
        return transaction.serializeBytes().byteLength + totalSignatureLength;
    }
    else {
        return transaction.serializeBytes().byteLength;
    }
}
exports.estimateTransactionByteLength = estimateTransactionByteLength;
function serializeTransaction(transaction) {
    return transaction.serialize();
}
exports.serializeTransaction = serializeTransaction;
function serializeTransactionBytes(transaction) {
    return transaction.serializeBytes();
}
exports.serializeTransactionBytes = serializeTransactionBytes;
function transactionToHex(transaction) {
    return transaction.serialize();
}
exports.transactionToHex = transactionToHex;
//# sourceMappingURL=transaction.js.map