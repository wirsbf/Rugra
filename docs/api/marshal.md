# marshal.rs — Serialization / marshaling API

Serialization layer corresponding to Ghidra's `marshal.hh` / `marshal.cc` and
`xml.hh` / `xml.cc`.

**Status:** L1 → L2. The registry, DOM tree, and Encoder/Decoder traits are
present with a working in-memory `TreeEncoder`/`TreeDecoder` round-trip. The
registry is not protocol-compatible: locked 12.0.4 uses explicit process-wide
IDs and zero as an iteration sentinel, while Rugra allocates per-instance IDs
and treats zero as unknown. PackedDecode's single `pos+pending` model also
differs from the locked start/cur/end/attributeRead state machine: unread
attributes, nested close/skip, typed errors, EOF, and raw strings have concrete
counterexamples. The Decoder trait has no error channel. See
`docs/alignment_audit/MARSHAL_PACKED_2026-08-11.md`.

2026-08-12 ANN-N 仅补 provenance：`AttributeId::new_static` 是 Rust const
占位胶水；它不能保留名称或执行 Ghidra 构造器的全局注册。本次未改变行为或模块状态。

Ghidra reference:
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/{marshal,xml}.{hh,cc}`.

## Constants

| Name | Value | Description |
|---|---|---|
| `ATTRIB_UNKNOWN` | 0 | "No attribute" sentinel. |
| `ATTRIB_CONTENT` | 1 | Element text content attribute. |

## Structs

### `AttributeId`
An annotation for a data element (marshal.hh:41).
- `new(name, id)`, `new_static(name, id)`, `get_name()`, `get_id()`.
- Equality by id.

### `ElementId`
An annotation for a collection of hierarchical data (marshal.hh:65).
- `new(name, id)`, `get_name()`, `get_id()`.
- Equality by id.

### `IdRegistry`
Global registry of attribute/element ids, mirroring Ghidra's static
hashtables (marshal.hh:42, 67).
- `new()` — empty with reserved ids 0/1.
- `register_attribute(name) -> u32`, `register_attribute_with_id(name, id)`.
- `find_attribute(name) -> u32`, `attribute_name(id) -> Option<&str>`.
- `register_element(name) -> u32`, `register_element_with_id(name, id)`.
- `find_element(name) -> u32`, `element_name(id) -> Option<&str>`.

### `Element`
An XML element — a DOM tree node (xml.hh:159).
- `new()`, `set_name(name)`, `add_content(s)`, `add_child(child)`,
  `add_attribute(name, value)`.
- `get_name()`, `get_content()`, `get_children()`,
  `get_attribute_value(name) -> Option<&str>`, `get_num_attributes()`,
  `get_attribute_name(i)`, `get_attribute_value_at(i)`.

### `Document`
A complete in-memory XML document (xml.hh:215).
- `new()`, `get_root() -> Option<&Arc<RwLock<Element>>>`, `set_root(root)`.

## Traits

### `Encoder`
Write structured data (marshal.hh). Methods:
- `open_element(elem_id)`, `close_element(elem_id)`.
- `write_bool(attrib_id, val)`, `write_signed_integer(attrib_id, val)`,
  `write_unsigned_integer(attrib_id, val)`, `write_string(attrib_id, val)`,
  `write_string_indexed(attrib_id, index, val)`.

### `Decoder`
Read structured data (marshal.hh:99). Methods:
- `peek_element() -> u32`, `open_element() -> u32`,
  `open_element_matching(elem_id) -> u32`, `close_element(id)`,
  `close_element_skipping(id)`.
- `next_attribute_id() -> u32`, `rewind_attributes()`.
- `read_bool()`, `read_bool_attr(attrib_id)`, `read_signed_integer()`,
  `read_signed_integer_attr(attrib_id)`, `read_unsigned_integer()`,
  `read_unsigned_integer_attr(attrib_id)`, `read_string()`,
  `read_string_attr(attrib_id)`.

## Implementations

### `TreeEncoder`
In-memory Encoder that builds an Element tree (equivalent of Ghidra's
TreeHandler).
- `new(registry)`, `into_document() -> Document`, `root()`.
- Implements `Encoder`.

### `TreeDecoder`
In-memory Decoder that reads from an Element tree (equivalent of Ghidra's
XmlDecode).
- `new(root, registry)`, `from_document(doc, registry)`.
- Implements `Decoder`.

## L3 gaps
- `PackedEncode`/`PackedDecode` — the binary marshaling format
  (marshal.hh:480-594, marshal.cc).
- Actual XML text parsing (`XmlScan`, `ContentHandler`) and serialization to
  XML text.
- `readSpace`/`writeSpace`/`readOpcode`/`writeOpcode` (require AddressSpace/
  OpCode integration).
- `readSignedIntegerExpectString`.

## 2026-06-27（续）：Decoder trait 新增 attribute_name/element_name

- `Decoder::attribute_name(id: u32) -> Option<String>`：按 id 查找属性名（通过 registry），支持按名称分发的解码（database.rs 的 decode_header 使用）。
- `Decoder::element_name(id: u32) -> Option<String>`：按 id 查找元素名，支持按名称匹配的元素解码。
- TreeDecoder 实现两者（通过内部 registry 的 read lock）。

## 2026-06-27（续）：PackedEncode + PackedDecode（二进制格式）

**packed_format 模块**（marshal.hh:480）：HEADER_MASK/ELEMENT_START/ELEMENT_END/ATTRIBUTE/HEADEREXTEND_MASK/ELEMENTID_MASK/RAWDATA_MASK/RAWDATA_MARKER/TYPECODE_* 常量。

### `PackedEncode`
二进制编码器，实现 Encoder trait（marshal.hh:579）。
- `new()`，`into_bytes() -> Vec<u8>`。
- open_element/close_element/write_bool/write_signed_integer/write_unsigned_integer/write_string/write_string_indexed。
- write_header（短/扩展 ID 编码）+ write_integer（长度编码变长整数）。

### `PackedDecode`
二进制解码器，实现 Decoder trait（marshal.hh:512）。
- `new(input, registry)`。
- open_element/close_element/peek_element/next_attribute_id/read_*/rewind_attributes。
- 支持 BOOLEAN/SIGNEDINT_POSITIVE/NEGATIVE/UNSIGNEDINT/STRING 类型解码。
<!-- annotation-pass: 2026-07-04 -->
