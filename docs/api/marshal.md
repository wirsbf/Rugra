# marshal.rs — Serialization / marshaling API

Serialization layer corresponding to Ghidra's `marshal.hh` / `marshal.cc` and
`xml.hh` / `xml.cc`.

**Status:** L2. `AttributeId`/`ElementId` use immutable process-wide tables with
the locked Ghidra 12.0.4 scope-0 name/ID assignments. Zero is reserved for
element/attribute traversal exhaustion; unknown names map to 159/289. This does
not lift the full module above L2: PackedDecode's single `pos+pending` model
still differs from the locked start/cur/end/attributeRead state machine, and
the Decoder trait still lacks Ghidra's error channel. See
`docs/alignment_audit/MARSHAL_PACKED_2026-08-11.md`.

2026-08-12 ANN-N 仅补 provenance：`AttributeId::new_static` 是 Rust const
占位胶水；它不能保留名称或执行 Ghidra 构造器的全局注册。本次未改变行为或模块状态。

Ghidra reference:
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/{marshal,xml}.{hh,cc}`.

## Constants

| Name | Value | Description |
|---|---|---|
| `ATTRIB_UNKNOWN` | 159 | Unrecognized scope-0 attribute name. |
| `ELEM_UNKNOWN` | 289 | Unrecognized scope-0 element name. |
| `ATTRIB_CONTENT` | 1 | Element text content attribute. |
| `ATTRIBUTE_ID_TABLE` | 146 pairs | Complete 12.0.4 source-manifest scope-0 attribute table. |
| `ELEMENT_ID_TABLE` | 274 pairs | Complete 12.0.4 source-manifest scope-0 element table. |

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
Immutable process-wide registry mirroring Ghidra's static scope-0 hashtables
(marshal.hh:42, 67). `new()` and repeated `initialize()` calls address the same
table and cannot allocate or renumber IDs.

- `find_attribute(name)` / `find_element(name)` return 159/289 for unknown names.
- `find_attribute_in_scope(name, scope)` / `find_element_in_scope(name, scope)`
  only reverse-map scope 0, as in locked Ghidra.
- `attribute_name(id)` / `element_name(id)` provide Rust reverse lookup over the
  exact table; ID 0 and numeric gaps return `None`.
- Legacy `register_attribute` / `register_element` are lookup-only compatibility
  methods. `register_*_with_id` validates a fixed pair and returns `bool`; none
  of these methods mutates the table.

The tables are a synthetic union of all 114 locked `.cc` source definitions:
146 attributes plus 274 elements. The standard `libdecomp.a` runtime closure
contains 136 plus 243 (379 total); 41 entries belong to alternate Ghidra/SLEIGH
front ends. The locked fixture records this projection explicitly and does not
claim that one standard runtime links every source-manifest object. Its C++
side uses the real standard 379-object registration and generates the remaining
41 same-name/same-ID objects from eight hash-locked source manifests. Fixture
ID-to-name output is an object-table scan of that source projection; locked
Ghidra exposes name-to-ID `find`, not a corresponding reverse-lookup API.
This linkage-dependent registration set remains a production `MISMATCH`:
those 41 names resolve to UNKNOWN in the standard locked runtime, while the
single Rust process table recognizes the full union.

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
- `peek_element()`, `open_element()`, and `next_attribute_id()` use `0` only for
  traversal exhaustion; unrecognized DOM names return 289/159 without ending
  traversal. Attribute and child order remain source order.

## L3 gaps
- Actual XML text serialization (writing the DOM back out as XML bytes) —
  ingestion is now covered (see MARSHAL-XML-TEXT-0001 below).
- `readSpace`/`writeSpace`/`readOpcode`/`writeOpcode` (require AddressSpace/
  OpCode integration).
- `readSignedIntegerExpectString`.

## MARSHAL-ID-0001 oracle status

The locked same-input fixture covers all 420 source-manifest pairs in both
directions, unknown names, nonzero scope fallback, repeated initialization,
`size=19`, `space=20`, and TreeDecoder end/unknown/order behavior. Its aggregate
status remains `MISMATCH`: the source-manifest ID observations match, while the
standard-runtime 379-versus-420 registration set and strict TreeDecoder
close/open error behavior remain registered residuals.

## MARSHAL-XML-TEXT-0001：XML 文本 ingestion（2026-08-16）

`src/marshal.rs` 新增 XML bytes → 有序 DOM 的完整解析链，1:1 移植 Ghidra
`xml.cc`/`xml.y`：

### `XmlScan`（xml.cc:111-177, 2080-2375）
- 4 字节环形 lookahead（`getxmlchar`/`next`），EOF 时补一个合成 `'\n'` 再产生
  `-1`（NUL 字节同样终止流）。
- 9 种 one-shot 扫描模式（CharData/CData/AttValue×2/Comment/CharRef/Name/SName/
  Single），`nexttoken` 派发后重置为 Single。
- `scanSName` 消费空白后无 Name 时返回字面 `' '` token（S 的物化）。

### 语法驱动（xml.y 141-219 的编译动作，xml.cc:1594-1845）
- 递归下降实现同一 LALR 文法；所有 mode 切换动作在 bison 中均为 default
  reduction（单完整项/唯一动作状态），故在"shift 最后一个 token 之后、读下一个
  token 之前"执行——parser 用 `tok_valid`+`ensure()` 的惰性单 lookahead 精确
  复现该时序。
- 关键忠实细节：尾随 root 的注释必然 syntax error（`document: element Misc`
  仅一个 Misc + 合成 `'\n'`）；`<!DOCTYPE` 首位不可达（plain syntax error），
  仅在 prologpre 非空后报 `DTD's not supported`；`<?` 一律 PI 错误（`<?xml`
  除外）；end tag 名不校验；纯空白 chardata/CDATA 经 `print_content` 走
  `ignorableWhitespace` 丢弃；注释文本丢弃；同名属性按源序全保留。

### `DecoderError`（xml.hh:297）
- `{ explain: String }`，消息与 Ghidra 逐字一致（`syntax error`、
  `Processing instructions are not supported`、`DTD's not supported`、
  `Unable to open xml document <name>`、`Unknown attribute: <nm>`）。

### `DocumentStorage`（xml.hh:258, xml.cc:2435-2477）
- `parse_document(&[u8]) -> Result<&Document, DecoderError>`：先追加 null slot
  再解析（失败时保留 null slot 的部分状态）。
- `open_document(filename)`、`register_tag`（同名覆盖）、`get_tag`。
- `doclist_len()` 为 RUGRA-GLUE 观察访问器（Ghidra doclist 私有无 API）。

### `xml_tree(&[u8]) -> Result<Document, DecoderError>`（xml.cc:2480）

### 已登记残余（fixture metadata）
1. MISMATCH：≥0x80 的数值字符引用与未知实体 `(char)0xFF` 标记——Ghidra 追加
   单字节，Rust String 以 UTF-8 编码（ASCII 域 byte-exact）。
2. UNTESTED：bison YYMAXDEPTH=10000 的 `memory exhausted` 深嵌套路径。

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

# 2026-08-16：XmlDecode 整数属性 hex/octal 自动识别（CSPEC-TEXT-INGEST 复核 F3）

`TreeDecoder` 的 `read_unsigned_integer`/`read_unsigned_integer_attr`/
`read_signed_integer`/`read_signed_integer_attr` 原为十进制-only
`.parse()`，与 Ghidra `XmlDecode` 经 `istringstream` `unsetf(dec|hex|oct)`
的自动进制识别不符（生产 cspec `<localrange>` 的 `0x…` hex 偏移会被解为
0）。现按 marshal.cc:296-330/353-381 语义实现 `cpp_stream_unsigned`/
`cpp_stream_signed`（前导空白跳过、可选符号、`0x`/`0X` hex、前导 `0`
八进制、最长合法前缀、无数字→0=流失败初值、溢出饱和），四个函数标注
改为 `// Ghidra: marshal.cc:<line> XmlDecode::read…`（原 RUGRA-GLUE 注释
不实）。新增单元测试 `test_cpp_stream_integer_bases`。
