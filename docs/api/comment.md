# comment.rs — Comment database API

Faithful port of Ghidra's `comment.hh` / `comment.cc` (406 lines).

**Status:** L2. The in-memory ordering/database projection and the observed
comment codec state match the locked 12.0.4 oracle. Full codec L3 remains
blocked on restoring the decoded `AddrSpace` handle through `Decoder`/
`AddrSpaceManager` (`ADDRESS-0001`, `MARSHAL-PACKED-0001`).

Ghidra reference: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/comment.{hh,cc}`.

## Module `comment_type`
Comment property flags (comment.hh:53):
- `USER1 = 1`, `USER2 = 2`, `USER3 = 4`, `HEADER = 8`, `WARNING = 16`,
  `WARNINGHEADER = 32`.

## Module `header_type`
CommentSorter header types (comment.hh:197):
- `HEADER_BASIC = 0`, `HEADER_UNPLACED = 1`.

## Structs

### `Comment`
A comment attached to a specific function and code address (comment.hh:43).
- `new(tp, fad, ad, uq, txt)`, `new_empty()`.
- `get_type()`, `get_func_addr()`, `get_addr()`, `get_uniq()`, `get_text()`,
  `set_emitted(val)`, `is_emitted()`.
- `encode(encoder) -> Result<()>` (comment.cc:37),
  `decode(decoder) -> Result<()>` (comment.cc:57).
  Address children use distinct `space` and `offset` attributes through the
  `AddrSpace::encodeAttributes` wire shape; text uses the special
  `XMLcontent` attribute ID corresponding to Ghidra's `ATTRIB_CONTENT`.

### Free functions
- `encode_comment_type(name) -> Result<u32>` (comment.cc:77).
- `decode_comment_type(val) -> Result<String>` (comment.cc:97).

Both return an error for unknown values, mirroring Ghidra's `LowlevelError`
instead of silently mapping them to zero or an empty string.

### `CommentDatabaseInternal`
In-memory CommentDatabase (comment.hh:161).
- `new()`, `clear()`, `clear_type(fad, tp)` (comment.cc:158).
- `add_comment(tp, fad, ad, txt)` (comment.cc:178).
- `add_comment_no_duplicate(tp, fad, ad, txt) -> bool` (comment.cc:196).
- `num_comments()`, `comments_for_function(fad)`, `all_comments()`.
- `encode(encoder) -> Result<()>` (comment.cc:242),
  `decode(decoder) -> Result<()>` (comment.cc:253).

### `Subsort`
Sorting key for placing a Comment within a basic block (comment.hh:203).
- `set_header(header_type)`, `set_block(index, order)`.
- Derives `Ord` for BTreeMap compatibility.

### `CommentSorter`
Sorts comments into and within basic blocks (comment.hh:195).
- `new()`, `setup_function_list(tp, fd_addr, db, display_unplaced)`
  (comment.cc:334).
- `has_header_comments()`, `header_comments()`.
- `setup_block_list`/`setup_op_list` currently return collected vectors instead
  of mutating the shared `start/stop/opstop` iterator state. `setup_header` is
  still a no-op. The exact iterator-state closure is tracked by
  `COMMENT-SORTER-ITERATORS-0001`.

## Codec evidence and residual

`COMMENT-WARNING-CODEC-0001` runs paired Ghidra/Rugra fixtures against oracle
commit `e40ed13014025f82488b1f8f7bca566894ac376b`. The byte-compared projection
covers:

- WARNING at `ram:0x2000` round-tripping type, function/address offsets, text,
  `uniq`, and deterministic comment order;
- `addCommentNoDuplicate` comparing address plus text independent of type;
- `clearType` filtering only the selected function and bit-mask types;
- unknown decoded type-name, unknown encoded property, and missing address
  offset errors, including partial object/encoder state.

Projection status is `MATCH`. Overall status remains `MISMATCH`: Ghidra's
`Address::decode` obtains the architecture-owned space through the decoder's
`AddrSpaceManager`; Rugra's current `Decoder` trait exposes no equivalent.
The Rust decoder therefore validates and consumes the encoded space name but
can only return the legacy offset-only `Address`. Unknown space-name rejection
and exact address-space identity remain with `ADDRESS-0001` and
`MARSHAL-PACKED-0001`; this module must not be promoted to L3 before they land.

## 2026-06-27（续）：CommentSorter::findPosition 实现记录

- **CommentSorter::find_position**：完整实现——遍历 Funcdata 的基本块和 ops，查找注释地址对应的 op，将注释关联到基本块。支持 3 种情况：
  1. Header 注释在函数地址 → HEADER_BASIC
  2. 注释地址有对应 op → 关联到该 op 的基本块 + seq order
  3. 注释地址无 op 但在块范围内 → 关联到块末尾
  4. 无法定位 → HEADER_UNPLACED（如果 displayUnplaced=true）
- **setup_function_list**：现接受 Funcdata 参数（而非 Address），调用 find_position。
- **setup_block_list**：现返回指定块的注释列表（Vec<&Comment>）。
- **setup_op_list**：现返回指定块中 op_order 之前的注释列表。
- `find_position` 的放置分类已实现，但 `setup_block_list/setup_op_list/
  setup_header` 尚未复现同一共享 iterator 状态；此前“缺口已关闭”的声明不成立，
  现绑定 `COMMENT-SORTER-ITERATORS-0001`。模块同时受前述 codec 地址空间残差约束。
<!-- annotation-pass: 2026-07-04 -->
