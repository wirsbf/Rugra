# stringmanage.rs — String management API

Faithful port of Ghidra's `stringmanage.hh` / `stringmanage.cc` (477 lines).

**Status:** L1 → L2. Complete UTF8/UTF16/UTF32 decoding + StringManager +
StringManagerUnicode with LoadImage integration. L3 gap: XML encode/decode +
Datatype-based charsize inference.

Ghidra reference: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/stringmanage.{hh,cc}`.

## Structs

### `StringData`
String data stored by StringManager (stringmanage.hh:43).
- Fields: `is_truncated: bool`, `byte_data: Vec<u8>`.

### `StringManager`
Storage for decoding and storing strings (stringmanage.hh:40).
- `new(max)`, `clear()`, `is_string(addr)`, `get_string_data(addr)`,
  `insert_string_data(addr, data)`, `num_strings()`, `get_maximum_chars()`.

### `StringManagerUnicode`
Implementation understanding terminated unicode strings (stringmanage.hh:86).
- `new(loader, max)`.
- `get_string_data(addr, charsize, bigend) -> Vec<u8>` — reads from load image,
  validates, caches (stringmanage.cc:427).
- `is_string(addr, charsize, bigend) -> bool`.

## Free functions (UTF helpers)
- `write_utf8(out, codepoint)` — encode codepoint as UTF8 (stringmanage.cc:124).
- `read_utf16(buf, bigend) -> i32` — read UTF16 element (stringmanage.cc:297).
- `get_codepoint(buf, charsize, bigend) -> (i32, i32)` — extract next codepoint
  + bytes consumed (stringmanage.cc:347). Supports UTF8/UTF16/UTF32 + surrogates.
- `check_characters(buf, charsize, bigend) -> i32` — count chars or -1
  (stringmanage.cc:324).
- `has_char_terminator(buf, charsize) -> bool` — check for null terminator
  (stringmanage.cc:277).
- `write_unicode(out, buf, charsize, bigend, max) -> bool` — translate to UTF8
  (stringmanage.cc:36).
- `assign_string_data(data, buf, charsize, num_chars, bigend, max)` — populate
  StringData (stringmanage.cc:66).

## L3 gaps
- XML encode/decode (`<stringmanage>`/`<string>`/`<bytes>` elements).
- Datatype-based charsize inference (currently passed explicitly).
- `registerInternalStringData` with hash-based constant address.

## 2026-06-27（续）：XML encode/decode

**StringManager 新增方法**：
- `encode(encoder)`（stringmanage.cc:203）：编码 `<stringmanage>` + `<string>` 子元素（addr + bytes + trunc + hex 内容）。
- `decode(decoder)`（stringmanage.cc:230）：解码恢复字符串缓存。
