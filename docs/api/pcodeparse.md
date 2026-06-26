# pcodeparse.rs — P-code snippet parser API

Faithful port of Ghidra's `pcodeparse.hh` / `pcodeparse.cc` (3303 lines, Bison-generated) + `pcodecompile.hh` / `pcodecompile.cc` (889 lines).

**Status:** L1 → L2. PcodeLexer with state-machine tokenization is complete. PcodeSnippet framework with symbol table + temp allocation is complete. Full recursive-descent parser semantic actions (ConstructTpl assembly) are L3 gap pending SLEIGH integration.

Ghidra reference: `ghidra/.../cpp/pcodeparse.{hh,cc}`, pcodecompile.{hh,cc}`.

## Enums

### `PcodeToken`
Token types: Eof, Illegal, Identifier, HexNumber, DecNumber, LParen, RParen, Comma, Semicolon, LBracket, RBracket, Assign, Dollar, DoubleDollar.

## Structs

### `PcodeLexer`
P-code snippet lexer (pcodeparse.hh:31).
- `new()`, `initialize(text)`.
- `get_next_token() -> PcodeToken` — state-machine tokenization.
- `get_identifier() -> &str`, `get_number() -> u64`.
- Handles: identifiers, hex (0x... and bare hex), decimal, punctuation,
  `$`/`$$` operators, `#` end-of-line comments.

### `PcodeSnippet`
P-code snippet compiler (pcodeparse.hh:72).
- `new()`, `set_unique_base(val)`, `get_unique_base()`.
- `clear()`, `has_errors()`, `get_error_message()`, `report_error(msg)`.
- `allocate_temp() -> u64` — temporary varnode allocation.
- `add_symbol(name, offset)`, `lookup_symbol(name) -> Option<u64>`.
- `add_operand(name, index)`.
- `lex() -> PcodeToken` — delegate to lexer.
- `parse_stream(text) -> bool` — tokenize + validate (full parse needs SLEIGH).

## L3 gaps
- Full recursive-descent parser semantic actions (ConstructTpl assembly).
- SLEIGH integration (SleighBase/SymbolTree).
- PcodeCompile (pcodecompile.cc) — op compilation helpers.
