# crc32.rs — CRC32 API

Faithful port of Ghidra's `crc32.hh` / `crc32.cc` (74 lines).

**Status:** L3. Fully self-contained implementation.

Ghidra reference: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/crc32.{hh,cc}`.

## Constants
- `CRC32_TABLE` — 256-entry lookup table for CRC32 (polynomial 0xEDB88320).

## Functions
- `crc_update(reg, val) -> u32` — feed 8 bits into CRC register (crc32.hh:33).

> Note: the non-Ghidra convenience wrappers `crc32` / `crc32_with_init` were
> removed (they had no callers and were not part of `crc32.hh`/`.cc`).
