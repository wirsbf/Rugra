# compression.rs — Compression API

Faithful port of Ghidra's `compression.hh` / `compression.cc` (165 lines).

**Status:** L1 → L2. Structure complete with stub compression (pass-through).
L3 gap: actual deflate/inflate requires the `flate2` crate.

Ghidra reference: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/compression.{hh,cc}`.

## Structs

### `Compress`
Wrapper for the deflate algorithm (compression.hh:34).
- `new(level)` — initialize (compression.hh:37).
- `input(buffer)` — provide bytes to compress (compression.hh:44).
- `deflate(buffer, finish) -> i32` — compress into buffer (compression.hh:48).

### `Decompress`
Wrapper for the inflate algorithm (compression.hh:55).
- `new()` — initialize (compression.hh:59).
- `input(buffer)` — provide compressed bytes (compression.hh:66).
- `is_finished() -> bool` — end of stream reached.
- `inflate(buffer) -> i32` — decompress into buffer (compression.hh:72).

## Free functions
- `compress_all(data, level) -> Vec<u8>` — one-shot deflate.
- `decompress_all(data) -> Vec<u8>` — one-shot inflate.

## L3 gap
- Actual deflate/inflate via `flate2` crate. Current implementation is a
  pass-through stub (no compression applied).
