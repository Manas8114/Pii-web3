export declare enum ClarityType {
    Int = "int",
    UInt = "uint",
    Buffer = "buffer",
    BoolTrue = "true",
    BoolFalse = "false",
    PrincipalStandard = "address",
    PrincipalContract = "contract",
    ResponseOk = "ok",
    ResponseErr = "err",
    OptionalNone = "none",
    OptionalSome = "some",
    List = "list",
    Tuple = "tuple",
    StringASCII = "ascii",
    StringUTF8 = "utf8"
}
export declare enum ClarityWireType {
    int = 0,
    uint = 1,
    buffer = 2,
    true = 3,
    false = 4,
    address = 5,
    contract = 6,
    ok = 7,
    err = 8,
    none = 9,
    some = 10,
    list = 11,
    tuple = 12,
    ascii = 13,
    utf8 = 14
}
export declare function clarityTypeToByte(type: ClarityType): ClarityWireType;
export declare function clarityByteToType(wireType: ClarityWireType): ClarityType;
