# Packed marshal state-machine audit — 2026-08-11

## Scope and evidence status

- oracle: `Ghidra_12.0.4_build`
- commit: `e40ed13014025f82488b1f8f7bca566894ac376b`
- locked code read for `PackedDecode`/`PackedEncode` declarations and decoder
  cursor, open/close/skip, attribute, scalar, string, space, and opcode methods
  in `marshal.hh:512-579` and `marshal.cc:603-1044`
- Rust closure: `src/marshal.rs:811-1370`

Temporary wire probes established the diagnostic differences below, but the
probe sources and metadata are not tracked. Formal B2 status is therefore
`NO_ORACLE`; the result rejects parity but is not reusable `MATCH` or durable
fixture-backed `MISMATCH` evidence.

## Result

PackedDecode is not a partially complete equivalent decoder. Its cursor model
is structurally different:

```text
Ghidra
  startPos       first attribute of current element
  curPos         next/current attribute
  endPos         first child or closing tag after all attributes
  attributeRead  whether the last enumerated attribute was consumed

Rugra
  pos            one global cursor
  stack          element id + approximate attribute positions
  pending_*      type and length already consumed by next_attribute_id
```

The locked `openElement` scans all attributes once to establish `endPos`, then
resets `curPos` to `startPos`. Child traversal and attribute traversal are
independent. `getNextAttributeId` leaves `curPos` on the attribute header; the
matching `read*` consumes header, type, and payload. If the caller requests the
next ID without reading the previous value, `skipAttribute` advances exactly
one record.

Rugra's `open_element` does not establish an attribute boundary.
`next_attribute_id` immediately consumes the header, type byte, and string
length, then stores partial pending state. Opening a child, closing an element,
rewinding, searching by ID, and reading a differently typed value all observe
the same global cursor. This cannot be repaired with a missing guard; the
four-state decoder must be ported.

## Deterministic wire counterexamples

In the examples below, `42/82` encode element 2 start/end, `43/83` encode
element 3, and `c2 41 aa` encodes unsigned attribute 2 with value 42.

| Case | Wire and calls | Locked behavior | Current behavior |
|---|---|---|---|
| open child with unread attribute | `42 c2 41 aa 43 83 82`; `open,open` | opens 2 then 3 | opens 2 then misreads the type byte as an element |
| enumerate without reading | two attributes; `next,next` | returns IDs 2,3, skipping value 2 | second enumeration ends or starts inside payload |
| read by ID | attributes 2=42, 3=7; `readUnsigned(3),next` | returns 7 and rewinds traversal to ID 2 | returns the wrong pending value/cursor |
| type mismatch | unsigned attribute; `next,readBool` | `DecoderError("Expecting boolean attribute")` after exact skip | returns true and leaves integer payload unread |
| wrong close ID | element 2; `open2,close(3)` | `DecoderError("Did not see expected closing element")` | `_id` is ignored and close succeeds |
| unread child on strict close | nested element; `open2,close2` | `DecoderError("Expecting element close")` | scans until an end marker and silently succeeds |
| recursive skip | parent+child then sibling; `closeSkipping,parent;peek` | skips the entire subtree and sees sibling | consumes one end marker and loses position |
| open on end marker | end marker followed by element 3 | returns 0 without searching forward | skips the end marker and opens element 3 |
| non-UTF-8 string | one-byte payload `ff` | preserves raw byte `ff` in `std::string` | `from_utf8_lossy` rewrites to UTF-8 replacement `ef bf bd` |
| truncated record | truncated header/type/integer/string | `DecoderError("Unexpected end of stream")` | returns 0/false/empty or silently short-reads |

The same issue affects unknown type codes. Locked typed reads call
`skipAttributeRemaining`, set `attributeRead`, and throw the requested-type
error. Rust reads pending length/type without validating the type and can
return an ordinary value.

## Error and interface contract

The locked `Decoder` API uses exceptions for missing required attributes,
wrong expected or closing IDs, wrong scalar/string/space type, unknown spaces,
unsupported special spaces, corrupt nesting, and unexpected EOF. Rust's
`Decoder` trait has no error channel. Implementations substitute zero, false,
empty string, `None`, stale pending state, or silent success. Changing only
PackedDecode internals cannot preserve the contract while callers cannot
receive an error.

The class closure is also incomplete:

- input-stream chunk ingestion and indexed attribute lookup;
- both `readSignedIntegerExpectString` overloads;
- both `readSpace` overloads and the five special-space codes;
- both `readOpcode` overloads;
- encoder `writeSpace` and `writeOpcode`;
- AddrSpaceManager ownership/state.

The Rust happy-path tests encode and decode with the same implementation. Such
self-roundtrips can make a shared wire error cancel itself and cannot prove
protocol parity.

## Four decisive semantic classes

- References / outputs: Ghidra's three Position objects are independent copies
  into a chunked stream. Attribute-by-ID reads restore `curPos` to `startPos`;
  child traversal retains `endPos`. Rust mutates one cursor and pending scalar
  fields, so a read changes unrelated traversal state.
- Traversal / boundaries: `openElement` scans `ATTRIBUTE*` exactly once;
  `getNextAttributeId` skips the previous record only when it was not read;
  strict close accepts only the immediate matching end, while skipping close
  uses an explicit nested ID stack. Rust searches forward and conflates these
  boundaries.
- Counters / accumulators: string/integer length uses 7-bit chunks; Ghidra
  advances Position across fixed 1024-byte chunks and throws on exhaustion.
  Rust accumulates into `usize` and clamps payload reads to available bytes.
- Sort / comparison keys: element/attribute identity is the decoded numeric
  ID, and closing IDs must equal the caller's open ID. Attribute search always
  restarts at the first attribute. Rust ignores the close key and can use
  pending/insertion position as an implicit key.

## Repair order

1. Make Decoder operations capable of returning the locked error channel and
   migrate callers without replacing required errors with defaults.
2. Introduce chunk-aware `Position` plus `startPos/curPos/endPos` and
   `attributeRead` with exact copy/advance/EOF semantics.
3. Port matching, skipping, typed reads, strict close, and recursive skipping
   in locked order.
4. Preserve string payload bytes rather than applying UTF-8 loss recovery.
5. Add the missing expect-string, space, opcode, indexed-ID, and ingest APIs.
6. Integrate `MARSHAL-ID-0001` and the architecture space registry.
7. Run direct locked wire-output and decode-state diffs before migrating
   database/type/block/architecture codecs.

## Durable fixture

Add:

```text
tests/oracle/marshal_packed_1204.cc
tests/oracle/marshal_packed_1204.rs
tests/oracle/marshal_packed_1204.metadata.json
tools/run_marshal_packed_oracle.sh
```

The runner must verify the locked commit and fixture hashes, compile both
drivers, and directly diff an ordered observation stream containing return or
exact error text, raw output/input hex, and the next traversal result after
every case. It must cover:

- IDs 31/32/4095 and fixed unknown/end sentinels;
- unsigned and signed 7-bit length thresholds through 64 bits;
- booleans, strings of length 0/1/127/128/1024/1025, and non-UTF-8 bytes;
- every truncated header/type/integer/string position;
- unknown IDs/type codes, missing attributes, and type mismatch;
- multiple unread/read attributes, rewind, nested strict close, and recursive
  skipping across the 1024-byte chunk boundary;
- normal and special spaces plus opcodes.

Decode wires must be fixed inputs or produced by the locked encoder, never
only `Rugra encoder -> Rugra decoder` self-roundtrips.
