import { Cl } from '..';
function regex(pattern, map) {
    return (s) => {
        const match = s.match(pattern);
        if (!match || match.index !== 0)
            return { success: false };
        return {
            success: true,
            value: match[0],
            rest: s.substring(match[0].length),
            capture: map ? map(match[0]) : undefined,
        };
    };
}
function whitespace() {
    return regex(/\s+/);
}
function lazy(c) {
    return (s) => c()(s);
}
function either(combinators) {
    return (s) => {
        for (const c of combinators) {
            const result = c(s);
            if (result.success)
                return result;
        }
        return { success: false };
    };
}
function entire(combinator) {
    return (s) => {
        const result = combinator(s);
        if (!result.success || result.rest)
            return { success: false };
        return result;
    };
}
function optional(c) {
    return (s) => {
        const result = c(s);
        if (result.success)
            return result;
        return {
            success: true,
            value: '',
            rest: s,
        };
    };
}
function sequence(combinators, reduce = v => v[0]) {
    return (s) => {
        let rest = s;
        let value = '';
        const captures = [];
        for (const c of combinators) {
            const result = c(rest);
            if (!result.success)
                return { success: false };
            rest = result.rest;
            value += result.value;
            if (result.capture)
                captures.push(result.capture);
        }
        return {
            success: true,
            value,
            rest,
            capture: reduce(captures),
        };
    };
}
function chain(combinators, reduce = v => v[0]) {
    const joined = combinators.flatMap((combinator, index) => index === 0 ? [combinator] : [optional(whitespace()), combinator]);
    return sequence(joined, reduce);
}
function parens(combinator) {
    return chain([regex(/\(/), combinator, regex(/\)/)]);
}
function greedy(min, combinator, reduce = v => v[v.length - 1], separator) {
    return (s) => {
        let rest = s;
        let value = '';
        const captures = [];
        let count;
        for (count = 0;; count++) {
            const result = combinator(rest);
            if (!result.success)
                break;
            rest = result.rest;
            value += result.value;
            if (result.capture)
                captures.push(result.capture);
            if (separator) {
                const sepResult = separator(rest);
                if (!sepResult.success) {
                    count++;
                    break;
                }
                rest = sepResult.rest;
                value += sepResult.value;
            }
        }
        if (count < min)
            return { success: false };
        return {
            success: true,
            value,
            rest,
            capture: reduce(captures),
        };
    };
}
function capture(combinator, map) {
    return (s) => {
        const result = combinator(s);
        if (!result.success)
            return { success: false };
        return {
            success: true,
            value: result.value,
            rest: result.rest,
            capture: map ? map(result.value) : result.value,
        };
    };
}
function clInt() {
    return capture(regex(/\-?[0-9]+/), v => Cl.int(parseInt(v)));
}
function clUint() {
    return sequence([regex(/u/), capture(regex(/[0-9]+/), v => Cl.uint(parseInt(v)))]);
}
function clBool() {
    return capture(regex(/true|false/), v => Cl.bool(v === 'true'));
}
function clPrincipal() {
    return sequence([
        regex(/\'/),
        capture(sequence([regex(/[A-Z0-9]+/), optional(sequence([regex(/\./), regex(/[a-zA-Z0-9\-]+/)]))]), Cl.address),
    ]);
}
function clBuffer() {
    return sequence([regex(/0x/), capture(regex(/[0-9a-fA-F]+/), Cl.bufferFromHex)]);
}
function unescape(input) {
    try {
        return JSON.parse(`"${input}"`);
    }
    catch (error) {
        throw new Error(`Failed to unescape string: "${input}" ${error instanceof Error ? error.message : error}`);
    }
}
function clAscii() {
    return sequence([
        regex(/"/),
        capture(regex(/(\\.|[^"])*/), t => Cl.stringAscii(unescape(t))),
        regex(/"/),
    ]);
}
function clUtf8() {
    return sequence([
        regex(/u"/),
        capture(regex(/(\\.|[^"])*/), t => Cl.stringUtf8(unescape(t))),
        regex(/"/),
    ]);
}
function clList() {
    return parens(sequence([
        regex(/list/),
        greedy(0, sequence([whitespace(), clValue()]), c => Cl.list(c)),
    ]));
}
function clTuple() {
    const tupleCurly = chain([
        regex(/\{/),
        greedy(1, sequence([
            capture(regex(/[a-zA-Z][a-zA-Z0-9_]*/)),
            regex(/\s*\:/),
            whitespace(),
            clValue(),
        ], ([k, v]) => Cl.tuple({ [k]: v })), c => Cl.tuple(Object.assign({}, ...c.map(t => t.value))), regex(/\s*\,\s*/)),
        regex(/\}/),
    ]);
    const tupleFunction = parens(sequence([
        optional(whitespace()),
        regex(/tuple/),
        whitespace(),
        greedy(1, parens(sequence([
            optional(whitespace()),
            capture(regex(/[a-zA-Z][a-zA-Z0-9_]*/)),
            whitespace(),
            clValue(),
            optional(whitespace()),
        ], ([k, v]) => Cl.tuple({ [k]: v }))), c => Cl.tuple(Object.assign({}, ...c.map(t => t.value))), whitespace()),
    ]));
    return either([tupleCurly, tupleFunction]);
}
function clNone() {
    return capture(regex(/none/), Cl.none);
}
function clSome() {
    return parens(sequence([regex(/some/), whitespace(), clValue()], c => Cl.some(c[0])));
}
function clOk() {
    return parens(sequence([regex(/ok/), whitespace(), clValue()], c => Cl.ok(c[0])));
}
function clErr() {
    return parens(sequence([regex(/err/), whitespace(), clValue()], c => Cl.error(c[0])));
}
function clValue(map = v => v) {
    return either([
        clBuffer,
        clAscii,
        clUtf8,
        clInt,
        clUint,
        clBool,
        clPrincipal,
        clList,
        clTuple,
        clNone,
        clSome,
        clOk,
        clErr,
    ]
        .map(lazy)
        .map(map));
}
export function parse(clarityValueString) {
    const result = clValue(entire)(clarityValueString);
    if (!result.success || !result.capture)
        throw 'Parse error';
    return result.capture;
}
export function internal_parseCommaSeparated(clarityValueString) {
    const combinator = entire(greedy(1, clValue(), c => Cl.list(c), regex(/\s*,\s*/)));
    const result = combinator(clarityValueString);
    if (!result.success || !result.capture)
        throw `Error trying to parse string: ${clarityValueString}`;
    return result.capture.value;
}
//# sourceMappingURL=parser.js.map