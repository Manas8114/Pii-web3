"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createTransactionAuthField = exports.createStandardPrincipal = exports.createContractPrincipal = exports.createAddress = exports.createAsset = exports.createLPString = exports.createTenureChangePayload = exports.createNakamotoCoinbasePayload = exports.createCoinbasePayload = exports.createPoisonPayload = exports.createSmartContractPayload = exports.codeBodyString = exports.createContractCallPayload = exports.createTokenTransferPayload = exports.createMessageSignature = exports.createLPList = exports.createMemoString = exports.createEmptyAddress = void 0;
const common_1 = require("@stacks/common");
const c32check_1 = require("c32check");
const clarity_1 = require("../clarity");
const constants_1 = require("../constants");
const utils_1 = require("../utils");
const types_1 = require("./types");
function createEmptyAddress() {
    return {
        type: types_1.StacksWireType.Address,
        version: constants_1.AddressVersion.MainnetSingleSig,
        hash160: '0'.repeat(40),
    };
}
exports.createEmptyAddress = createEmptyAddress;
function createMemoString(content) {
    if (content && (0, utils_1.exceedsMaxLengthBytes)(content, constants_1.MEMO_MAX_LENGTH_BYTES)) {
        throw new Error(`Memo exceeds maximum length of ${constants_1.MEMO_MAX_LENGTH_BYTES} bytes`);
    }
    return { type: types_1.StacksWireType.MemoString, content };
}
exports.createMemoString = createMemoString;
function createLPList(values, lengthPrefixBytes) {
    return {
        type: types_1.StacksWireType.LengthPrefixedList,
        lengthPrefixBytes: lengthPrefixBytes || 4,
        values,
    };
}
exports.createLPList = createLPList;
function createMessageSignature(signature) {
    const length = (0, common_1.hexToBytes)(signature).byteLength;
    if (length != constants_1.RECOVERABLE_ECDSA_SIG_LENGTH_BYTES) {
        throw Error('Invalid signature');
    }
    return {
        type: types_1.StacksWireType.MessageSignature,
        data: signature,
    };
}
exports.createMessageSignature = createMessageSignature;
function createTokenTransferPayload(recipient, amount, memo) {
    if (typeof recipient === 'string') {
        recipient = (0, clarity_1.principalCV)(recipient);
    }
    if (typeof memo === 'string') {
        memo = createMemoString(memo);
    }
    return {
        type: types_1.StacksWireType.Payload,
        payloadType: constants_1.PayloadType.TokenTransfer,
        recipient,
        amount: (0, common_1.intToBigInt)(amount),
        memo: memo ?? createMemoString(''),
    };
}
exports.createTokenTransferPayload = createTokenTransferPayload;
function createContractCallPayload(contractAddress, contractName, functionName, functionArgs) {
    if (typeof contractName === 'string') {
        contractName = createLPString(contractName);
    }
    if (typeof functionName === 'string') {
        functionName = createLPString(functionName);
    }
    return {
        type: types_1.StacksWireType.Payload,
        payloadType: constants_1.PayloadType.ContractCall,
        contractAddress: typeof contractAddress === 'string' ? createAddress(contractAddress) : contractAddress,
        contractName,
        functionName,
        functionArgs,
    };
}
exports.createContractCallPayload = createContractCallPayload;
function codeBodyString(content) {
    return createLPString(content, 4, 100000);
}
exports.codeBodyString = codeBodyString;
function createSmartContractPayload(contractName, codeBody, clarityVersion) {
    if (typeof contractName === 'string') {
        contractName = createLPString(contractName);
    }
    if (typeof codeBody === 'string') {
        codeBody = codeBodyString(codeBody);
    }
    if (typeof clarityVersion === 'number') {
        return {
            type: types_1.StacksWireType.Payload,
            payloadType: constants_1.PayloadType.VersionedSmartContract,
            clarityVersion,
            contractName,
            codeBody,
        };
    }
    return {
        type: types_1.StacksWireType.Payload,
        payloadType: constants_1.PayloadType.SmartContract,
        contractName,
        codeBody,
    };
}
exports.createSmartContractPayload = createSmartContractPayload;
function createPoisonPayload() {
    return { type: types_1.StacksWireType.Payload, payloadType: constants_1.PayloadType.PoisonMicroblock };
}
exports.createPoisonPayload = createPoisonPayload;
function createCoinbasePayload(coinbaseBytes, altRecipient) {
    if (coinbaseBytes.byteLength != constants_1.COINBASE_BYTES_LENGTH) {
        throw Error(`Coinbase buffer size must be ${constants_1.COINBASE_BYTES_LENGTH} bytes`);
    }
    if (altRecipient != undefined) {
        return {
            type: types_1.StacksWireType.Payload,
            payloadType: constants_1.PayloadType.CoinbaseToAltRecipient,
            coinbaseBytes,
            recipient: altRecipient,
        };
    }
    return {
        type: types_1.StacksWireType.Payload,
        payloadType: constants_1.PayloadType.Coinbase,
        coinbaseBytes,
    };
}
exports.createCoinbasePayload = createCoinbasePayload;
function createNakamotoCoinbasePayload(coinbaseBytes, recipient, vrfProof) {
    if (coinbaseBytes.byteLength != constants_1.COINBASE_BYTES_LENGTH) {
        throw Error(`Coinbase buffer size must be ${constants_1.COINBASE_BYTES_LENGTH} bytes`);
    }
    if (vrfProof.byteLength != constants_1.VRF_PROOF_BYTES_LENGTH) {
        throw Error(`VRF proof buffer size must be ${constants_1.VRF_PROOF_BYTES_LENGTH} bytes`);
    }
    return {
        type: types_1.StacksWireType.Payload,
        payloadType: constants_1.PayloadType.NakamotoCoinbase,
        coinbaseBytes,
        recipient: recipient.type === clarity_1.ClarityType.OptionalSome ? recipient.value : undefined,
        vrfProof,
    };
}
exports.createNakamotoCoinbasePayload = createNakamotoCoinbasePayload;
function createTenureChangePayload(tenureHash, previousTenureHash, burnViewHash, previousTenureEnd, previousTenureBlocks, cause, publicKeyHash) {
    return {
        type: types_1.StacksWireType.Payload,
        payloadType: constants_1.PayloadType.TenureChange,
        tenureHash,
        previousTenureHash,
        burnViewHash,
        previousTenureEnd,
        previousTenureBlocks,
        cause,
        publicKeyHash,
    };
}
exports.createTenureChangePayload = createTenureChangePayload;
function createLPString(content, lengthPrefixBytes, maxLengthBytes) {
    const prefixLength = lengthPrefixBytes || 1;
    const maxLength = maxLengthBytes || constants_1.MAX_STRING_LENGTH_BYTES;
    if ((0, utils_1.exceedsMaxLengthBytes)(content, maxLength)) {
        throw new Error(`String length exceeds maximum bytes ${maxLength}`);
    }
    return {
        type: types_1.StacksWireType.LengthPrefixedString,
        content,
        lengthPrefixBytes: prefixLength,
        maxLengthBytes: maxLength,
    };
}
exports.createLPString = createLPString;
function createAsset(addressString, contractName, assetName) {
    return {
        type: types_1.StacksWireType.Asset,
        address: createAddress(addressString),
        contractName: createLPString(contractName),
        assetName: createLPString(assetName),
    };
}
exports.createAsset = createAsset;
function createAddress(c32AddressString) {
    const addressData = (0, c32check_1.c32addressDecode)(c32AddressString);
    return {
        type: types_1.StacksWireType.Address,
        version: addressData[0],
        hash160: addressData[1],
    };
}
exports.createAddress = createAddress;
function createContractPrincipal(addressString, contractName) {
    const addr = createAddress(addressString);
    const name = createLPString(contractName);
    return {
        type: types_1.StacksWireType.Principal,
        prefix: constants_1.PostConditionPrincipalId.Contract,
        address: addr,
        contractName: name,
    };
}
exports.createContractPrincipal = createContractPrincipal;
function createStandardPrincipal(addressString) {
    const addr = createAddress(addressString);
    return {
        type: types_1.StacksWireType.Principal,
        prefix: constants_1.PostConditionPrincipalId.Standard,
        address: addr,
    };
}
exports.createStandardPrincipal = createStandardPrincipal;
function createTransactionAuthField(pubKeyEncoding, contents) {
    return {
        pubKeyEncoding,
        type: types_1.StacksWireType.TransactionAuthField,
        contents,
    };
}
exports.createTransactionAuthField = createTransactionAuthField;
//# sourceMappingURL=create.js.map