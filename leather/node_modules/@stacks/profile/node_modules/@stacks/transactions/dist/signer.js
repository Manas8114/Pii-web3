"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TransactionSigner = void 0;
const authorization_1 = require("./authorization");
const constants_1 = require("./constants");
const errors_1 = require("./errors");
const utils_1 = require("./utils");
const wire_1 = require("./wire");
const keys_1 = require("./keys");
class TransactionSigner {
    constructor(transaction) {
        this.transaction = transaction;
        this.sigHash = transaction.signBegin();
        this.originDone = false;
        this.checkOversign = true;
        this.checkOverlap = true;
        const spendingCondition = transaction.auth.spendingCondition;
        if (spendingCondition && !(0, authorization_1.isSingleSig)(spendingCondition)) {
            if (spendingCondition.fields.filter(field => field.contents.type === wire_1.StacksWireType.MessageSignature).length >= spendingCondition.signaturesRequired) {
                throw new Error('SpendingCondition has more signatures than are expected');
            }
            spendingCondition.fields.forEach(field => {
                if (field.contents.type !== wire_1.StacksWireType.MessageSignature)
                    return;
                const signature = field.contents;
                const nextVerify = (0, authorization_1.nextVerification)(this.sigHash, transaction.auth.authType, spendingCondition.fee, spendingCondition.nonce, constants_1.PubKeyEncoding.Compressed, signature.data);
                if (!(0, authorization_1.isNonSequentialMultiSig)(spendingCondition.hashMode)) {
                    this.sigHash = nextVerify.nextSigHash;
                }
            });
        }
    }
    static createSponsorSigner(transaction, spendingCondition) {
        if (transaction.auth.authType != constants_1.AuthType.Sponsored) {
            throw new errors_1.SigningError('Cannot add sponsor to non-sponsored transaction');
        }
        const tx = (0, utils_1.cloneDeep)(transaction);
        tx.setSponsor(spendingCondition);
        const originSigHash = tx.verifyOrigin();
        const signer = new this(tx);
        signer.originDone = true;
        signer.sigHash = originSigHash;
        signer.checkOversign = true;
        signer.checkOverlap = true;
        return signer;
    }
    signOrigin(privateKey) {
        if (this.checkOverlap && this.originDone) {
            throw new errors_1.SigningError('Cannot sign origin after sponsor key');
        }
        if (this.transaction.auth === undefined) {
            throw new errors_1.SigningError('"transaction.auth" is undefined');
        }
        if (this.transaction.auth.spendingCondition === undefined) {
            throw new errors_1.SigningError('"transaction.auth.spendingCondition" is undefined');
        }
        const spendingCondition = this.transaction.auth.spendingCondition;
        if (spendingCondition.hashMode === constants_1.AddressHashMode.P2SH ||
            spendingCondition.hashMode === constants_1.AddressHashMode.P2WSH) {
            if (this.checkOversign &&
                spendingCondition.fields.filter(field => field.contents.type === wire_1.StacksWireType.MessageSignature).length >= spendingCondition.signaturesRequired) {
                throw new Error('Origin would have too many signatures');
            }
        }
        const nextSighash = this.transaction.signNextOrigin(this.sigHash, privateKey);
        if ((0, authorization_1.isSingleSig)(this.transaction.auth.spendingCondition) ||
            (0, authorization_1.isSequentialMultiSig)(this.transaction.auth.spendingCondition.hashMode)) {
            this.sigHash = nextSighash;
        }
    }
    appendOrigin(publicKey) {
        const wire = typeof publicKey === 'object' && 'type' in publicKey
            ? publicKey
            : (0, keys_1.createStacksPublicKey)(publicKey);
        if (this.checkOverlap && this.originDone) {
            throw Error('Cannot append public key to origin after sponsor key');
        }
        if (this.transaction.auth === undefined) {
            throw new Error('"transaction.auth" is undefined');
        }
        if (this.transaction.auth.spendingCondition === undefined) {
            throw new Error('"transaction.auth.spendingCondition" is undefined');
        }
        this.transaction.appendPubkey(wire);
    }
    signSponsor(privateKey) {
        if (this.transaction.auth === undefined) {
            throw new errors_1.SigningError('"transaction.auth" is undefined');
        }
        if (this.transaction.auth.authType !== constants_1.AuthType.Sponsored) {
            throw new errors_1.SigningError('"transaction.auth.authType" is not AuthType.Sponsored');
        }
        const nextSighash = this.transaction.signNextSponsor(this.sigHash, privateKey);
        this.sigHash = nextSighash;
        this.originDone = true;
    }
    getTxInComplete() {
        return (0, utils_1.cloneDeep)(this.transaction);
    }
    resume(transaction) {
        this.transaction = (0, utils_1.cloneDeep)(transaction);
        this.sigHash = transaction.signBegin();
    }
}
exports.TransactionSigner = TransactionSigner;
//# sourceMappingURL=signer.js.map