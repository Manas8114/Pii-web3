export var ClarityType;
(function (ClarityType) {
    ClarityType["Int"] = "int";
    ClarityType["UInt"] = "uint";
    ClarityType["Buffer"] = "buffer";
    ClarityType["BoolTrue"] = "true";
    ClarityType["BoolFalse"] = "false";
    ClarityType["PrincipalStandard"] = "address";
    ClarityType["PrincipalContract"] = "contract";
    ClarityType["ResponseOk"] = "ok";
    ClarityType["ResponseErr"] = "err";
    ClarityType["OptionalNone"] = "none";
    ClarityType["OptionalSome"] = "some";
    ClarityType["List"] = "list";
    ClarityType["Tuple"] = "tuple";
    ClarityType["StringASCII"] = "ascii";
    ClarityType["StringUTF8"] = "utf8";
})(ClarityType || (ClarityType = {}));
export var ClarityWireType;
(function (ClarityWireType) {
    ClarityWireType[ClarityWireType["int"] = 0] = "int";
    ClarityWireType[ClarityWireType["uint"] = 1] = "uint";
    ClarityWireType[ClarityWireType["buffer"] = 2] = "buffer";
    ClarityWireType[ClarityWireType["true"] = 3] = "true";
    ClarityWireType[ClarityWireType["false"] = 4] = "false";
    ClarityWireType[ClarityWireType["address"] = 5] = "address";
    ClarityWireType[ClarityWireType["contract"] = 6] = "contract";
    ClarityWireType[ClarityWireType["ok"] = 7] = "ok";
    ClarityWireType[ClarityWireType["err"] = 8] = "err";
    ClarityWireType[ClarityWireType["none"] = 9] = "none";
    ClarityWireType[ClarityWireType["some"] = 10] = "some";
    ClarityWireType[ClarityWireType["list"] = 11] = "list";
    ClarityWireType[ClarityWireType["tuple"] = 12] = "tuple";
    ClarityWireType[ClarityWireType["ascii"] = 13] = "ascii";
    ClarityWireType[ClarityWireType["utf8"] = 14] = "utf8";
})(ClarityWireType || (ClarityWireType = {}));
export function clarityTypeToByte(type) {
    return ClarityWireType[type];
}
export function clarityByteToType(wireType) {
    return ClarityWireType[wireType];
}
//# sourceMappingURL=constants.js.map