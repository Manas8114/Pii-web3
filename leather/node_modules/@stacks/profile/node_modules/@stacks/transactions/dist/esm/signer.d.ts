import { PrivateKey, PublicKey } from '@stacks/common';
import { SpendingConditionOpts } from './authorization';
import { StacksTransactionWire } from './transaction';
import { PublicKeyWire } from './wire';
export declare class TransactionSigner {
    transaction: StacksTransactionWire;
    sigHash: string;
    originDone: boolean;
    checkOversign: boolean;
    checkOverlap: boolean;
    constructor(transaction: StacksTransactionWire);
    static createSponsorSigner(transaction: StacksTransactionWire, spendingCondition: SpendingConditionOpts): TransactionSigner;
    signOrigin(privateKey: PrivateKey): void;
    appendOrigin(publicKey: PublicKey): void;
    appendOrigin(publicKey: PublicKeyWire): void;
    signSponsor(privateKey: PrivateKey): void;
    getTxInComplete(): StacksTransactionWire;
    resume(transaction: StacksTransactionWire): void;
}
