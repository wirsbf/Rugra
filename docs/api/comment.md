# comment.rs — Comment database API

Faithful port of Ghidra's `comment.hh` / `comment.cc` (406 lines).

**Status:** L1 → L2. Complete in-memory implementation with XML encode/decode.
CommentSorter block-level walking is an L3 gap (requires Funcdata op-tree
access).

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
- `encode(encoder)` (comment.cc:37), `decode(decoder)` (comment.cc:57).

### Free functions
- `encode_comment_type(name) -> u32` (comment.cc:77).
- `decode_comment_type(val) -> String` (comment.cc:97).

### `CommentDatabaseInternal`
In-memory CommentDatabase (comment.hh:161).
- `new()`, `clear()`, `clear_type(fad, tp)` (comment.cc:158).
- `add_comment(tp, fad, ad, txt)` (comment.cc:178).
- `add_comment_no_duplicate(tp, fad, ad, txt) -> bool` (comment.cc:196).
- `num_comments()`, `comments_for_function(fad)`, `all_comments()`.
- `encode(encoder)` (comment.cc:242), `decode(decoder)` (comment.cc:253).

### `Subsort`
Sorting key for placing a Comment within a basic block (comment.hh:203).
- `set_header(header_type)`, `set_block(index, order)`.
- Derives `Ord` for BTreeMap compatibility.

### `CommentSorter`
Sorts comments into and within basic blocks (comment.hh:195).
- `new()`, `setup_function_list(tp, fd_addr, db, display_unplaced)`
  (comment.cc:334).
- `has_header_comments()`, `header_comments()`.
- L3 gap: `setup_block_list`/`setup_op_list`/`findPosition` require Funcdata
  op-tree access for full block-level comment placement.

## L3 gaps
- `CommentSorter::findPosition` (comment.cc:270): associate comments with
  basic blocks via `Funcdata::beginOp`/op address lookup.
- Full `setup_block_list`/`setup_op_list` iterator walking within a block.
