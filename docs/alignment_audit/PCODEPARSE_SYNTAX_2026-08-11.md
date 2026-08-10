# PcodeSnippet mandatory-syntax audit — 2026-08-11

## Scope and oracle

- Ghidra oracle: `Ghidra_12.0.4_build`, commit
  `e40ed13014025f82488b1f8f7bca566894ac376b`.
- Ghidra sources read in full for this boundary:
  `pcodeparse.y:98-225`, `pcodeparse.cc:3130-3301`, and
  `pcodeparse.hh:72-98`.
- Rugra boundary: `PcodeSnippet::parse_stream` and its recursive-descent
  statement parsers in `src/pcodeparse.rs:3106-3616`.

Status: **MISMATCH**. This is a source-level deterministic mismatch; exact
Ghidra runtime error text remains `NO_ORACLE` until `SLEIGH-0001` makes the
C++ snippet fixture linkable.

## Reproduced counterexamples

The following probe used the current compiled Rugra library and a fresh
`PcodeSnippet` for every input:

| Invalid input | Rugra `parse_stream` |
|---|---:|
| `goto [0x1000:8;` | `true` |
| `goto 0x1000` | `true` |
| `if 0x1:1 goto 0x10` | `true` |
| `call [0x2000:8;` | `true` |
| `call 0x2000` | `true` |
| `return [0x0:4;` | `true` |
| `local x:4 = 0x1:4` | `true` |
| `local x:4` | `true` |
| `local x` | `true` |

Ghidra's locked grammar has only productions containing the missing `]` or
`;` (`pcodeparse.y:103-123`). These token literals are mandatory. A parse
failure makes `yyparse()` non-zero, and `PcodeSnippet::parseStream` returns
`false` at `pcodeparse.cc:3273-3277`.

## Root causes

1. Twenty-seven `expect_punct(...) -> Result` calls at
   `src/pcodeparse.rs:3293-3615` discard the result. The parser therefore
   builds an op even when a grammar token is absent.
2. The special `LOCAL STRING ':' INTEGER ...` paths at
   `src/pcodeparse.rs:3193-3216` use a boolean expression whose result is
   discarded, so three declaration/assignment paths accept a missing `;`.
3. On syntax errors Rugra often records `Some(partial_construct)` and attempts
   statement-boundary recovery. Ghidra calls `setResult` only when the full
   `rtl: rtlmid ENDOFSTREAM` reduction succeeds (`pcodeparse.y:99`); the
   failure-state result ownership must be checked and matched, not guessed.
4. Several comments cite obsolete `pcodeparse.y:700+` lines. In locked 12.0.4
   the grammar ends at line 226 and `parseStream` is `pcodeparse.cc:3268`.

## Four decisive semantics

- Reference/output state: both parsers mutate the snippet's symbol/error/temp
  state and produce an owned `ConstructTpl`; a boolean return alone is not the
  full observation. Failure must also match `errorcount`, first error, symbol
  mutations, unique-base movement, and whether `releaseResult` is null.
- Traversal/order: token consumption is strictly left-to-right. Every literal
  token in a Bison production is mandatory; no statement may construct its op
  before all trailing punctuation has matched.
- Counters/accumulators: `errorcount` starts at zero and increments on every
  `reportError`; `firsterror` is written only for the first error. Label and
  unique-temp counters must not advance for a rejected semantic action unless
  the Ghidra parser does so at the same point.
- Comparison/sort keys: no sorting. Parser decisions compare the current token
  kind and follow Bison's declared precedence/shift behavior; punctuation
  equality is exact.

## Required atomic fix (`PARSER-0001`)

1. Propagate every mandatory `expect_punct` failure.
2. Make all three special local paths require `;`.
3. Match Ghidra's failed-parse result/error/counter state; do not preserve a
   partial result merely to make recovery convenient.
4. Correct affected source annotations to 12.0.4 lines.
5. Add a punctuation-deletion matrix over every statement production, plus
   valid-neighbor tests and failure-state assertions.
6. Run the same malformed corpus through an actual Ghidra `PcodeSnippet`
   fixture once `SLEIGH-0001` is closed; record return value, first error,
   error count, unique base, symbols, and result presence.

Do not fix this by silencing `unused_must_use` with `let _ = ...`; that would
preserve the semantic defect.
