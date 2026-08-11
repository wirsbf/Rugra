# pcodeparse.rs — P-code snippet parser & `<op>`/`<varnode>` XML decode API

Partial port of Ghidra's `pcodeparse.hh` / `pcodeparse.cc` (3303 lines,
Bison-generated) + `pcodeparse.y` (805 lines, grammar source). This module
also ports the `<op>` / `<varnode>` XML decode path that Ghidra spreads across
`pcoderaw.cc` (`PcodeOpRaw::decode`, `VarnodeData::decode`) and `translate.cc`
(`PcodeEmit::decodeOp`), since those are the XML entry points that consume the
P-code emitted by this parser.

**Status:** L3 (2026-07-22 complete lexer + XML decode alignment). The full
Bison state-machine lexer (`moveState` + `getNextToken`) with all 57 token
kinds, the `IDENTREC_SIZE=46` keyword/operator table, and the `<op>` /
`<varnode>` XML decode path are all faithful to Ghidra. The ConstructTpl
assembly half of the parser (the Bison grammar's semantic actions) remains an
L3 gap that requires SLEIGH integration; the lexer, symbol table, error
reporting, temp allocation, and XML decode are complete. 43 unit tests.

Ghidra reference: `ghidra/.../cpp/pcodeparse.{hh,cc,y}`, `sleigh.hh`
(PcodeData), `pcoderaw.{hh,cc}`, `translate.cc`.

## Enums

### `PcodeTokenKind`
The full Bison `pcodetokentype` enum (pcodeparse.cc:152-211): 57 token kinds
mirroring the numeric ids 258-314. Variants cover:
- Multi-char operators: `BoolOr` (`||`), `BoolAnd` (`&&`), `Equal` (`==`),
  `NotEqual` (`!=`), `LessEqual` (`<=`), `GreatEqual` (`>=`), `Left` (`<<`),
  `Right` (`>>`), `BoolXor` (`^^`).
- Signed-family (`s<`, `s<=`, `s>`, `s>=`, `s>>`, `s/`, `s%`): `SLess`,
  `SLessEqual`, `SGreat`, `SGreatEqual`, `SRight`, `SDiv`, `SRem`.
- Float-family (`f+`, `f-`, `f*`, `f/`, `f==`, `f!=`, `f<`, `f>`, `f<=`,
  `f>=`): `FAdd`, `FSub`, `FMult`, `FDiv`, `FEqual`, `FNotEqual`, `FLess`,
  `FGreat`, `FLessEqual`, `FGreatEqual`.
- Builtins: `Zext`, `Carry`, `Borrow`, `Sext`, `SCarry`, `SBorrow`, `Nan`,
  `Abs`, `Sqrt`, `Ceil`, `Floor`, `Round`, `Int2Float`, `Float2Float`,
  `Trunc`, `New`.
- Keywords: `GotoKey`, `CallKey`, `ReturnKey`, `IfKey`, `LocalKey`.
- Literals/symbols: `Integer`, `BadInteger`, `String`, `SpaceSym`,
  `UserOpSym`, `VarSym`, `OperandSym`, `JumpSym`, `LabelSym`.
- `Punct(char)` — single-character punctuation carries the source char.
- `Illegal` — unclassifiable character (Bison's `0`/EOF).

Methods:
- `as_token_id() -> i32` (`const`) — Bison numeric id (258-314, or ASCII for
  `Punct`, or `0` for `Illegal`).
- `from_token_id(id) -> Option<PcodeTokenKind>` (`const`) — inverse lookup.

### `PcodeToken`
Coarse 14-variant projection retained for callers that only need the broad
category (Eof, Illegal, Identifier, HexNumber, DecNumber, LParen, RParen,
Comma, Semicolon, LBracket, RBracket, Assign, Dollar, DoubleDollars).
- `from_kind(kind) -> PcodeToken` — project a `PcodeTokenKind` down.

### `LexerState` (private)
The Bison lexer states (pcodeparse.hh:33-45): `Start`, `Special2`, `Special3`,
`Special32`, `Comment`, `Punctuation`, `Identifier`, `Hexstring`,
`Decstring`, `Endstream`, `Illegal`.

### `SleightSymbolKind`
Tagged enum mirroring the `SleighSymbol` type switch in
`PcodeSnippet::lex` (pcodeparse.y:730-758): `Space(AddressSpace)`,
`UserOp(u32)`, `Varnode(VarnodeData)`, `Operand(String, i32)`,
`JumpTarget(String)`, `Label(String, u32)`.

The `UserOp` payload is the `UserOpSymbol::getIndex()` value, not the symbol
name. Both statement and expression forms place that value in the 4-byte
constant input 0 of `CPUI_CALLOTHER`, matching `createUserOpNoOut`
(`pcodecompile.cc:529`).

`tools/run_userop_index_oracle.sh` compiles the locked Ghidra 12.0.4
`SleighCompile`/`PcodeCompile` implementation and verifies the observable
contract: user-op indices increase globally across declaration batches,
parameter expressions and inputs keep source order, input 0 is
`const/index/4`, and only the expression form has an output. The paired Rust
test exercises both parser paths with distinct non-zero indices.

## Structs

### `IdentRec` (pcodeparse.hh:26)
`{ name: &'static str, id: i32 }` — keyword/operator table entry.

### `PCODE_IDENTS` (static, `IDENTREC_SIZE = 46`)
Sorted table of p-code keywords/multi-char operators, faithful to
`PcodeLexer::idents[]` (pcodeparse.y:229-276). Lexicographically ordered so
`find_identifier`'s binary search matches Ghidra. Uses inlined integer ids
because Rust statics cannot call non-const fn; the values are identical to
`PcodeTokenKind::as_token_id`.

### `SleighSymbol`
`{ name: String, kind: SleightSymbolKind }` — a resolved SLEIGH symbol
produced by `PcodeSnippet::lex`.

### `PcodeLexer` (pcodeparse.hh:31)
The lookahead-2 state-machine lexer.
- `new()`, `initialize(text)`.
- `get_next_token() -> PcodeTokenKind` — drives `move_state`
  (pcodeparse.y:297) one char at a time, sliding the lookahead window
  (`curchar <- lookahead1 <- lookahead2 <- stream`), until a non-`Start`
  state is reported. Identifiers get keyword-resolved via `find_identifier`;
  hex/dec strings parse to `Integer` (or `BadInteger` on overflow).
- `get_identifier() -> &str`, `get_number() -> u64`.
- `tokenize_all(text) -> Vec<PcodeTokenKind>` — convenience helper.

Handles: all multi-char operators including the 3-char `s>>` / `f<=` family
(requires the full lookahead-2 buffer), `#` end-of-line comments, `0x`-prefixed
and bare hex/dec numbers.

### `PcodeData` (sleigh.hh:44)
Raw p-code op record: `{ opc: OpCode, outvar: Option<VarnodeData>, invar:
Vec<VarnodeData> }`.
- `new(opc)`, `set_output(vn)`, `add_input(vn)`, `clear_inputs()`,
  `num_input()`, `get_output()`.

### `PcodeSnippet` (pcodeparse.hh:72)
The snippet compiler.
- `new()`, `set_unique_base(val)`, `get_unique_base()`.
- `clear()` — drops non-space symbols, resets errors (pcodeparse.y:652).
- `has_errors()`, `get_error_message()`, `report_error(msg)`,
  `report_warning(msg)` (no-op, matching pcodeparse.hh:89).
- `allocate_temp() -> u64` — reserves 16 bytes of unique space per temp
  (pcodeparse.y:632).
- `add_symbol(sym)` — duplicate insertions report an error (pcodeparse.y:640).
- `lookup_symbol(name)`, `add_operand(name, index)` (pcodeparse.y:787).
- `lex() -> PcodeTokenKind` — full SLEIGH symbol resolution for STRING tokens
  (pcodeparse.y:717): maps hits to `SpaceSym`/`UserOpSym`/`VarSym`/
  `OperandSym`/`JumpSym`/`LabelSym`.
- `parse_stream(text) -> bool` — tokenize + validate (pcodeparse.y:770).
- `get_location(sym)` — always `None` (pcodeparse.hh:87).

## XML decode functions (the `<op>` / `<varnode>` path)

These port the decode half of `pcoderaw.cc` / `translate.cc` into this module
because they are the XML entry points for the P-code this parser emits.

### Element / attribute id helpers
`elem_op()` (ELEM_OP, translate.cc:25), `elem_varnode()` (ELEM_VARNODE,
address.cc:30), `elem_addr()`, `elem_register()`, `elem_void()`,
`elem_spaceid()`; `attrib_code()`, `attrib_size()`, `attrib_space()`,
`attrib_name()`, `attrib_offset()`.

### `parse_space_name(name) -> AddressSpace`
Resolve a space spelling (`ram`/`register`/`unique`/`const`/`stack`/`join`/
`iop`) to an `AddressSpace`. Mirrors `decoder.readSpace()`.

### `decode_varnode_from_attributes(decoder) -> VarnodeData`
Faithful to `VarnodeData::decodeFromAttributes` (pcoderaw.cc:33-55): dispatches
on `space=` (then `offset`/`size`) or `name=` (register lookup).

### `decode_varnode(decoder) -> VarnodeData`
Faithful to `VarnodeData::decode` (pcoderaw.cc:23): opens the `<addr>` /
`<register>` / `<varnode>` element, delegates, closes.

### `decode_pcode_op_raw(decoder, isize) -> Option<PcodeData>`
Faithful to `PcodeOpRaw::decode` (pcoderaw.cc:96-122): reads `code` attr as
opcode, handles `<void>` output, decodes `isize` inputs with special
`<spaceid>` handling.

### `decode_op(decoder) -> Option<PcodeData>`
Faithful to `PcodeEmit::decodeOp` (translate.cc:996-1016): opens `<op>`, reads
`size` attr, delegates to `decode_pcode_op_raw`, closes.

### `find_identifier(s) -> Option<usize>`
Binary search of `PCODE_IDENTS` (pcodeparse.y:278).

## L3 gaps
- Mandatory punctuation and parser failure state are not yet equivalent to
  the Bison grammar; see `PARSER-0001` and the syntax audit.
- SLEIGH integration (`SleighBase`/`SymbolTree`) for global symbol lookup
  beyond the local scope.
- Register name resolution in `decode_varnode_from_attributes` (needs a
  `Translate`).

## Annotation provenance

ANN-G records source provenance without changing behavior. `find_identifier`
maps to `PcodeLexer::findIdentifier` at locked `pcodeparse.cc:2776`; the four
decode entry points map to `pcoderaw.cc:23,33,96` and `translate.cc:996`.
Element/attribute constructors and recursive-descent token helpers are marked
as Rust glue because Ghidra uses file-scope IDs and generated Bison machinery.
Known wire-ID, decoder/space-registry, and parser-lifecycle differences remain
owned by `MARSHAL-ID-0001`, `MARSHAL-PACKED-0001`, `SPACE-0001`, and
`PARSER-0001` respectively.
