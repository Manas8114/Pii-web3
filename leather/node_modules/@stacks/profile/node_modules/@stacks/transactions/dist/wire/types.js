"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.whenWireType = exports.StacksWireType = void 0;
var StacksWireType;
(function (StacksWireType) {
    StacksWireType[StacksWireType["Address"] = 0] = "Address";
    StacksWireType[StacksWireType["Principal"] = 1] = "Principal";
    StacksWireType[StacksWireType["LengthPrefixedString"] = 2] = "LengthPrefixedString";
    StacksWireType[StacksWireType["MemoString"] = 3] = "MemoString";
    StacksWireType[StacksWireType["Asset"] = 4] = "Asset";
    StacksWireType[StacksWireType["PostCondition"] = 5] = "PostCondition";
    StacksWireType[StacksWireType["PublicKey"] = 6] = "PublicKey";
    StacksWireType[StacksWireType["LengthPrefixedList"] = 7] = "LengthPrefixedList";
    StacksWireType[StacksWireType["Payload"] = 8] = "Payload";
    StacksWireType[StacksWireType["MessageSignature"] = 9] = "MessageSignature";
    StacksWireType[StacksWireType["StructuredDataSignature"] = 10] = "StructuredDataSignature";
    StacksWireType[StacksWireType["TransactionAuthField"] = 11] = "TransactionAuthField";
})(StacksWireType || (exports.StacksWireType = StacksWireType = {}));
function whenWireType(wireType) {
    return (wireTypeMap) => wireTypeMap[wireType];
}
exports.whenWireType = whenWireType;
//# sourceMappingURL=types.js.map