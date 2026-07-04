# grammar.rs — C grammar parser API

Faithful port of Ghidra's `grammar.hh` / `grammar.cc` (3338 lines).

**Status:** ✅ **L3（2026-06-28 完整对齐）**. Complete GrammarToken + GrammarLexer + TypeModifier/TypeDeclarator + parse_type/parse_to_separator. 18 unit tests.
tokenization + TypeDeclarator/TypeModifier AST data structures + entry
functions. L3 gap: full CParse recursive-descent parser + TypeFactory
integration.

Ghidra reference:
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/grammar.{hh,cc}`.

## Module `token_type`
Token types (grammar.hh:26): OPEN_PAREN, CLOSE_PAREN, STAR, COMMA, SEMICOLON,
OPEN_BRACKET, CLOSE_BRACKET, OPEN_BRACE, CLOSE_BRACE, BAD_TOKEN, END_OF_FILE,
DOTDOTDOT, INTEGER, CHAR_CONSTANT, IDENTIFIER, STRING_VAL.

## Structs

### `GrammarToken`
A lexical token (grammar.hh:23).
- `new()`, `get_type()`, `get_integer()`, `get_string()`, `get_line_no()`,
  `get_col_no()`, `get_file_num()`, `set_position()`.

### `GrammarLexer`
Lexer for C declarations (grammar.hh:69).
- `new(max_buffer)`, `clear()`, `set_input(text)`, `get_error()`, `is_eof()`.
- `get_next_token() -> GrammarToken` — state-machine tokenization
  (grammar.hh:110). Handles: punctuation, identifiers, integers (dec/hex/oct),
  strings, char constants, `//` and `/* */` comments, `...`.

### `TypeModifier`
Type modifier enum: Pointer/Array/Function (grammar.hh:118).
- `kind() -> ModifierKind`, `is_valid() -> bool`.

### `TypeDeclarator`
C type declarator (grammar.hh:165).
- `new()`, `with_name(name)`, `get_base_type_name()`, `num_modifiers()`,
  `get_identifier()`, `has_property(mask)`.

## Free functions
- `parse_type(text) -> Option<(String, String)>` — parse type+name
  (grammar.hh:282).
- `parse_to_separator(text) -> String` — parse up to separator
  (grammar.hh:288).

## L3 gaps
- Full `CParse` recursive-descent parser (grammar.cc state machine).
- TypeFactory integration for `modType`/`buildType`.
- `parse_protopieces`, `parse_C`, `parse_machaddr`, `parse_varnode`, `parse_op`.
<!-- annotation-pass: 2026-07-04 -->
