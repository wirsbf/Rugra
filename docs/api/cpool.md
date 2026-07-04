# cpool.rs — Constant pool API

Faithful port of Ghidra's `cpool.hh` / `cpool.cc` (245 lines).

**Status:** L1 → L2. Complete CPoolRecord + ConstantPool trait +
ConstantPoolInternal + CheapSorter. L3 gap: XML encode/decode (requires
TypeFactory integration).

Ghidra reference: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/cpool.{hh,cc}`.

## Modules

### `cpool_tag`
Constant pool tag types (cpool.hh:59):
- `PRIMITIVE = 0`, `STRING_LITERAL = 1`, `CLASS_REFERENCE = 2`,
  `POINTER_METHOD = 3`, `POINTER_FIELD = 4`, `ARRAY_LENGTH = 5`,
  `INSTANCE_OF = 6`, `CHECK_CAST = 7`.

### `cpool_flags`
- `IS_CONSTRUCTOR = 0x1`, `IS_DESTRUCTOR = 0x2`.

## Structs

### `CPoolRecord`
A description of a byte-code object referenced by a constant (cpool.hh:56).
- `new()`, `get_tag()`, `get_token()`, `get_byte_data()`,
  `get_byte_data_length()`, `get_type_name()`, `get_value()`,
  `is_constructor()`, `is_destructor()`.
- `tag_to_string(tag)` / `string_to_tag(s)` — tag↔string conversion.

### `CheapSorter`
Efficient 2-integer reference placeholder (cpool.hh:175).
- `from_refs(refs)`, `apply() -> Vec<u64>`.
- Derives `Ord` for BTreeMap keying.

## Trait `ConstantPool`
Interface to the constant pool (cpool.hh:104).
- `get_record(refs) -> Option<&CPoolRecord>`.
- `create_record(refs) -> Result<&mut CPoolRecord, String>`.
- `put_record(refs, tag, tok, type_name)`.
- `is_empty() -> bool`, `clear()`.

## `ConstantPoolInternal`
In-memory implementation (cpool.hh:165).
- `new()`, `num_records()`, `records()`.
- Implements `ConstantPool`.

## 2026-06-27（续）：XML encode/decode

**ConstantPoolInternal 新增方法**：
- `encode(encoder)`（cpool.cc:218）：编码 `<constantpool>` + `<ref>` + `<cpoolrec>` 子元素。
- `decode(decoder)`（cpool.cc:230）：解码恢复常量池记录。
<!-- annotation-pass: 2026-07-04 -->
