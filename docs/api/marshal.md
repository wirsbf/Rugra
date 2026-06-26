# marshal.rs — Serialization / marshaling API

Faithful port of Ghidra's `marshal.hh` / `marshal.cc` (1273 lines) + `xml.hh` /
`xml.cc` (2510 lines, the in-memory DOM tree).

**Status:** L1 → L2. The registry, DOM tree, and Encoder/Decoder traits are
complete with a working in-memory `TreeEncoder`/`TreeDecoder` round-trip. The
Packed binary format (`PackedEncode`/`PackedDecode`) and actual XML text
parsing are L3 gaps.

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
