import { NetworkClientParam } from '@stacks/network';
import { ClarityValue } from './clarity';
export type AddressString = string;
export type ContractIdString = `${string}.${string}`;
export type AssetString = `${ContractIdString}::${string}`;
export type BaseRejection = {
    error: string;
    reason: string;
    txid: string;
};
export type SerializationRejection = {
    reason: 'Serialization';
    reason_data: {
        message: string;
    };
} & BaseRejection;
export type DeserializationRejection = {
    reason: 'Deserialization';
    reason_data: {
        message: string;
    };
} & BaseRejection;
export type SignatureValidationRejection = {
    reason: 'SignatureValidation';
    reason_data: {
        message: string;
    };
} & BaseRejection;
export type BadNonceRejection = {
    reason: 'BadNonce';
    reason_data: {
        expected: number;
        actual: number;
        is_origin: boolean;
        principal: boolean;
    };
} & BaseRejection;
export type FeeTooLowRejection = {
    reason: 'FeeTooLow';
    reason_data: {
        expected: number;
        actual: number;
    };
} & BaseRejection;
export type NotEnoughFundsRejection = {
    reason: 'NotEnoughFunds';
    reason_data: {
        expected: string;
        actual: string;
    };
} & BaseRejection;
export type NoSuchContractRejection = {
    reason: 'NoSuchContract';
} & BaseRejection;
export type NoSuchPublicFunctionRejection = {
    reason: 'NoSuchPublicFunction';
} & BaseRejection;
export type BadFunctionArgumentRejection = {
    reason: 'BadFunctionArgument';
    reason_data: {
        message: string;
    };
} & BaseRejection;
export type ContractAlreadyExistsRejection = {
    reason: 'ContractAlreadyExists';
    reason_data: {
        contract_identifier: string;
    };
} & BaseRejection;
export type PoisonMicroblocksDoNotConflictRejection = {
    reason: 'PoisonMicroblocksDoNotConflict';
} & BaseRejection;
export type PoisonMicroblockHasUnknownPubKeyHashRejection = {
    reason: 'PoisonMicroblockHasUnknownPubKeyHash';
} & BaseRejection;
export type PoisonMicroblockIsInvalidRejection = {
    reason: 'PoisonMicroblockIsInvalid';
} & BaseRejection;
export type BadAddressVersionByteRejection = {
    reason: 'BadAddressVersionByte';
} & BaseRejection;
export type NoCoinbaseViaMempoolRejection = {
    reason: 'NoCoinbaseViaMempool';
} & BaseRejection;
export type ServerFailureNoSuchChainTipRejection = {
    reason: 'ServerFailureNoSuchChainTip';
} & BaseRejection;
export type ServerFailureDatabaseRejection = {
    reason: 'ServerFailureDatabase';
    reason_data: {
        message: string;
    };
} & BaseRejection;
export type ServerFailureOtherRejection = {
    reason: 'ServerFailureOther';
    reason_data: {
        message: string;
    };
} & BaseRejection;
export type TxBroadcastResultOk = {
    txid: string;
};
export type TxBroadcastResultRejected = SerializationRejection | DeserializationRejection | SignatureValidationRejection | BadNonceRejection | FeeTooLowRejection | NotEnoughFundsRejection | NoSuchContractRejection | NoSuchPublicFunctionRejection | BadFunctionArgumentRejection | ContractAlreadyExistsRejection | PoisonMicroblocksDoNotConflictRejection | PoisonMicroblockHasUnknownPubKeyHashRejection | PoisonMicroblockIsInvalidRejection | BadAddressVersionByteRejection | NoCoinbaseViaMempoolRejection | ServerFailureNoSuchChainTipRejection | ServerFailureDatabaseRejection | ServerFailureOtherRejection;
export type TxBroadcastResult = TxBroadcastResultOk | TxBroadcastResultRejected;
export interface FeeEstimation {
    fee: number;
    fee_rate: number;
}
export interface FeeEstimateResponse {
    cost_scalar_change_by_byte: bigint;
    estimated_cost: {
        read_count: bigint;
        read_length: bigint;
        runtime: bigint;
        write_count: bigint;
        write_length: bigint;
    };
    estimated_cost_scalar: bigint;
    estimations: [FeeEstimation, FeeEstimation, FeeEstimation];
}
export type ReadOnlyFunctionOptions = {
    contractName: string;
    contractAddress: string;
    functionName: string;
    functionArgs: ClarityValue[];
    senderAddress: string;
} & NetworkClientParam;
