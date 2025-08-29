import { hexToBytes, intToBigInt } from '@stacks/common';
import { c32addressDecode } from 'c32check';
import { ClarityType, principalCV } from '../clarity';
import { AddressVersion, COINBASE_BYTES_LENGTH, MAX_STRING_LENGTH_BYTES, MEMO_MAX_LENGTH_BYTES, PayloadType, PostConditionPrincipalId, RECOVERABLE_ECDSA_SIG_LENGTH_BYTES, VRF_PROOF_BYTES_LENGTH, } from '../constants';
import { exceedsMaxLengthBytes } from '../utils';
import { StacksWireType, } from './types';
export function createEmptyAddress() {
    return {
        type: StacksWireType.Address,
        version: AddressVersion.MainnetSingleSig,
        hash160: '0'.repeat(40),
    };
}
export function createMemoString(content) {
    if (content && exceedsMaxLengthBytes(content, MEMO_MAX_LENGTH_BYTES)) {
        throw new Error(`Memo exceeds maximum length of ${MEMO_MAX_LENGTH_BYTES} bytes`);
    }
    return { type: StacksWireType.MemoString, content };
}
export function createLPList(values, lengthPrefixBytes) {
    return {
        type: StacksWireType.LengthPrefixedList,
        lengthPrefixBytes: lengthPrefixBytes || 4,
        values,
    };
}
export function createMessageSignature(signature) {
    const length = hexToBytes(signature).byteLength;
    if (length != RECOVERABLE_ECDSA_SIG_LENGTH_BYTES) {
        throw Error('Invalid signature');
    }
    return {
        type: StacksWireType.MessageSignature,
        data: signature,
    };
}
export function createTokenTransferPayload(recipient, amount, memo) {
    if (typeof recipient === 'string') {
        recipient = principalCV(recipient);
    }
    if (typeof memo === 'string') {
        memo = createMemoString(memo);
    }
    return {
        type: StacksWireType.Payload,
        payloadType: PayloadType.TokenTransfer,
        recipient,
        amount: intToBigInt(amount),
        memo: memo ?? createMemoString(''),
    };
}
export function createContractCallPayload(contractAddress, contractName, functionName, functionArgs) {
    if (typeof contractName === 'string') {
        contractName = createLPString(contractName);
    }
    if (typeof functionName === 'string') {
        functionName = createLPString(functionName);
    }
    return {
        type: StacksWireType.Payload,
        payloadType: PayloadType.ContractCall,
        contractAddress: typeof contractAddress === 'string' ? createAddress(contractAddress) : contractAddress,
        contractName,
        functionName,
        functionArgs,
    };
}
export function codeBodyString(content) {
    return createLPString(content, 4, 100000);
}
export function createSmartContractPayload(contractName, codeBody, clarityVersion) {
    if (typeof contractName === 'string') {
        contractName = createLPString(contractName);
    }
    if (typeof codeBody === 'string') {
        codeBody = codeBodyString(codeBody);
    }
    if (typeof clarityVersion === 'number') {
        return {
            type: StacksWireType.Payload,
            payloadType: PayloadType.VersionedSmartContract,
            clarityVersion,
            contractName,
            codeBody,
        };
    }
    return {
        type: StacksWireType.Payload,
        payloadType: PayloadType.SmartContract,
        contractName,
        codeBody,
    };
}
export function createPoisonPayload() {
    return { type: StacksWireType.Payload, payloadType: PayloadType.PoisonMicroblock };
}
export function createCoinbasePayload(coinbaseBytes, altRecipient) {
    if (coinbaseBytes.byteLength != COINBASE_BYTES_LENGTH) {
        throw Error(`Coinbase buffer size must be ${COINBASE_BYTES_LENGTH} bytes`);
    }
    if (altRecipient != undefined) {
        return {
            type: StacksWireType.Payload,
            payloadType: PayloadType.CoinbaseToAltRecipient,
            coinbaseBytes,
            recipient: altRecipient,
        };
    }
    return {
        type: StacksWireType.Payload,
        payloadType: PayloadType.Coinbase,
        coinbaseBytes,
    };
}
export function createNakamotoCoinbasePayload(coinbaseBytes, recipient, vrfProof) {
    if (coinbaseBytes.byteLength != COINBASE_BYTES_LENGTH) {
        throw Error(`Coinbase buffer size must be ${COINBASE_BYTES_LENGTH} bytes`);
    }
    if (vrfProof.byteLength != VRF_PROOF_BYTES_LENGTH) {
        throw Error(`VRF proof buffer size must be ${VRF_PROOF_BYTES_LENGTH} bytes`);
    }
    return {
        type: StacksWireType.Payload,
        payloadType: PayloadType.NakamotoCoinbase,
        coinbaseBytes,
        recipient: recipient.type === ClarityType.OptionalSome ? recipient.value : undefined,
        vrfProof,
    };
}
export function createTenureChangePayload(tenureHash, previousTenureHash, burnViewHash, previousTenureEnd, previousTenureBlocks, cause, publicKeyHash) {
    return {
        type: StacksWireType.Payload,
        payloadType: PayloadType.TenureChange,
        tenureHash,
        previousTenureHash,
        burnViewHash,
        previousTenureEnd,
        previousTenureBlocks,
        cause,
        publicKeyHash,
    };
}
export function createLPString(content, lengthPrefixBytes, maxLengthBytes) {
    const prefixLength = lengthPrefixBytes || 1;
    const maxLength = maxLengthBytes || MAX_STRING_LENGTH_BYTES;
    if (exceedsMaxLengthBytes(content, maxLength)) {
        throw new Error(`String length exceeds maximum bytes ${maxLength}`);
    }
    return {
        type: StacksWireType.LengthPrefixedString,
        content,
        lengthPrefixBytes: prefixLength,
        maxLengthBytes: maxLength,
    };
}
export function createAsset(addressString, contractName, assetName) {
    return {
        type: StacksWireType.Asset,
        address: createAddress(addressString),
        contractName: createLPString(contractName),
        assetName: createLPString(assetName),
    };
}
export function createAddress(c32AddressString) {
    const addressData = c32addressDecode(c32AddressString);
    return {
        type: StacksWireType.Address,
        version: addressData[0],
        hash160: addressData[1],
    };
}
export function createContractPrincipal(addressString, contractName) {
    const addr = createAddress(addressString);
    const name = createLPString(contractName);
    return {
        type: StacksWireType.Principal,
        prefix: PostConditionPrincipalId.Contract,
        address: addr,
        contractName: name,
    };
}
export function createStandardPrincipal(addressString) {
    const addr = createAddress(addressString);
    return {
        type: StacksWireType.Principal,
        prefix: PostConditionPrincipalId.Standard,
        address: addr,
    };
}
export function createTransactionAuthField(pubKeyEncoding, contents) {
    return {
        pubKeyEncoding,
        type: StacksWireType.TransactionAuthField,
        contents,
    };
}
//# sourceMappingURL=create.js.map