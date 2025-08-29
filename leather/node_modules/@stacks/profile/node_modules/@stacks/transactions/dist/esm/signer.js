import { isNonSequentialMultiSig, isSequentialMultiSig, isSingleSig, nextVerification, } from './authorization';
import { AddressHashMode, AuthType, PubKeyEncoding } from './constants';
import { SigningError } from './errors';
import { cloneDeep } from './utils';
import { StacksWireType } from './wire';
import { createStacksPublicKey } from './keys';
export class TransactionSigner {
    constructor(transaction) {
        this.transaction = transaction;
        this.sigHash = transaction.signBegin();
        this.originDone = false;
        this.checkOversign = true;
        this.checkOverlap = true;
        const spendingCondition = transaction.auth.spendingCondition;
        if (spendingCondition && !isSingleSig(spendingCondition)) {
            if (spendingCondition.fields.filter(field => field.contents.type === StacksWireType.MessageSignature).length >= spendingCondition.signaturesRequired) {
                throw new Error('SpendingCondition has more signatures than are expected');
            }
            spendingCondition.fields.forEach(field => {
                if (field.contents.type !== StacksWireType.MessageSignature)
                    return;
                const signature = field.contents;
                const nextVerify = nextVerification(this.sigHash, transaction.auth.authType, spendingCondition.fee, spendingCondition.nonce, PubKeyEncoding.Compressed, signature.data);
                if (!isNonSequentialMultiSig(spendingCondition.hashMode)) {
                    this.sigHash = nextVerify.nextSigHash;
                }
            });
        }
    }
    static createSponsorSigner(transaction, spendingCondition) {
        if (transaction.auth.authType != AuthType.Sponsored) {
            throw new SigningError('Cannot add sponsor to non-sponsored transaction');
        }
        const tx = cloneDeep(transaction);
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
            throw new SigningError('Cannot sign origin after sponsor key');
        }
        if (this.transaction.auth === undefined) {
            throw new SigningError('"transaction.auth" is undefined');
        }
        if (this.transaction.auth.spendingCondition === undefined) {
            throw new SigningError('"transaction.auth.spendingCondition" is undefined');
        }
        const spendingCondition = this.transaction.auth.spendingCondition;
        if (spendingCondition.hashMode === AddressHashMode.P2SH ||
            spendingCondition.hashMode === AddressHashMode.P2WSH) {
            if (this.checkOversign &&
                spendingCondition.fields.filter(field => field.contents.type === StacksWireType.MessageSignature).length >= spendingCondition.signaturesRequired) {
                throw new Error('Origin would have too many signatures');
            }
        }
        const nextSighash = this.transaction.signNextOrigin(this.sigHash, privateKey);
        if (isSingleSig(this.transaction.auth.spendingCondition) ||
            isSequentialMultiSig(this.transaction.auth.spendingCondition.hashMode)) {
            this.sigHash = nextSighash;
        }
    }
    appendOrigin(publicKey) {
        const wire = typeof publicKey === 'object' && 'type' in publicKey
            ? publicKey
            : createStacksPublicKey(publicKey);
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
            throw new SigningError('"transaction.auth" is undefined');
        }
        if (this.transaction.auth.authType !== AuthType.Sponsored) {
            throw new SigningError('"transaction.auth.authType" is not AuthType.Sponsored');
        }
        const nextSighash = this.transaction.signNextSponsor(this.sigHash, privateKey);
        this.sigHash = nextSighash;
        this.originDone = true;
    }
    getTxInComplete() {
        return cloneDeep(this.transaction);
    }
    resume(transaction) {
        this.transaction = cloneDeep(transaction);
        this.sigHash = transaction.signBegin();
    }
}
//# sourceMappingURL=signer.js.map