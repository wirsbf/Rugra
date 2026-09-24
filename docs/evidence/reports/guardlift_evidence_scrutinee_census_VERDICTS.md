# FJ lane — scrutinee read-guard family census (LOCKHYGIENE-SCRUTINEE-FAMILY-0001)

Date: 2026-09-23 · Tree: wt/guardlift @ 84050b2a (base aaa1ab1d) · oracle e40ed130

Family definition (ER/EW/EM3): `if let Some(x) = OBJ.read().unwrap().M()` — the
scrutinee RwLockReadGuard on OBJ lives through the whole if-let body; a body
write-lock on the SAME OBJ self-deadlocks (std RwLock non-reentrant).

Scan: single-line scrutinee regex over src/*.rs (tests excluded) = 51 hits +
1 multi-line scrutinee (typeop.rs:1023, `if let Some(base) =` then
`factory.read().unwrap().get_base(...)` on the next line) = **52 production
sites**. Raw machine output: scrutinee_census.txt.

## Fixed in this lane (the registered latent pair + same-function sibling)

| site | scrutinee object | status |
|---|---|---|
| src/coreaction.rs:5634 mark_explicit_unsigned lone arm (cast.cc:63-66; ER-era line 5605) | outvn (Varnode) | LIFTED (commit dc977085), body read-only (lone opcode) — latent, unit-pinned |
| src/dynamic.rs:911 gather_first_level_vars slot<0 arm (dynamic.cc:663) | vn (Varnode) | LIFTED (dc977085), body read-only — latent, unit-pinned |
| src/dynamic.rs:924 gather_first_level_vars slot>=0 arm (dynamic.cc:677) | vn (Varnode) | LIFTED (dc977085), body read-only — latent (same-function sibling found by this census) |

## Manual review of every site whose body contains lock-taking calls (12)

Write targets are **different objects** (new ops / other varnodes / highs /
groups) in all 12 — zero body writes the scrutinee object itself:

| site | scrutinee | body writes | verdict |
|---|---|---|---|
| condexe.rs:585 | op (PcodeOp) | fd.op_set_input(&new_op, extra, i) | writes new_op + varnode extra; op untouched → SAFE |
| funcdata.rs:1507 | vn (Varnode) | high.write() (set_symbol/name) | writes HighVariable ≠ vn → SAFE |
| funcdata.rs:2205 | cvn (Varnode) | high.write() (type_dirty/set_symbol(&cvn)) | writes high; set_symbol only reads cvn → SAFE (recursive-read note only) |
| funcdata.rs:5433 | vn (Varnode) | high.write() | writes high → SAFE |
| funcdata.rs:5768 | indop.0 (PcodeOp) | in0.write() (set_flags) | writes input varnode; guard is on the op → SAFE |
| heritage.rs:3052 | force_op (PcodeOp) | out_vn.write() (ADDRFORCE) | writes output varnode; force_op.write() at :3067 is AFTER the if-let closes → SAFE |
| heritage.rs:6661 | block_arc (Block) | op_ref.0.write() + set_input/destroy_varnode on successor ops | writes ops/varnodes, never the block → SAFE |
| merge.rs:4874 | vn_arc (Varnode) | mark_high_cover_dirty(&high) | writes high; update_cover_locked(&vn_arc) at :4882 is AFTER the if-let closes (EM3-fixed neighborhood) → SAFE |
| ruleaction.rs:13177 | op (PcodeOp) | fd.op_set_input(&new_op, in1, 1) | writes new_op; fd.op_destroy(&op_ref) at :13184 is AFTER the if-let closes → SAFE |
| ruleaction.rs:17524 | out_vn (Varnode) | new_out.write() (update_type) | new_out is a fresh varnode from build_varnode_out ≠ out_vn → SAFE |
| ruleaction.rs:18581 | newop.0 (PcodeOp) | out.write() (update_type) | writes output varnode; guard is on the op → SAFE |
| variable.rs:746 | piece_arc (VariablePiece) | g.write() (adjust_offsets) | writes group ≠ piece → SAFE |

Remaining 40 sites: bodies contain no lock-taking calls at all (pure reads /
clones / pushes). typeop.rs:1023 (multi-line, TypeFactory guard) body is
`return base;` — pure read.

## Verdict

**Zero new latent family members.** The two registered sites (plus the
same-function sibling at dynamic.rs:924) were the complete family tail; after
dc977085 the production tree has no if-let scrutinee read guard whose body
write-locks the guarded object.

Caveats (out of family scope, tracked elsewhere):
- Named long-lived read guards (`let g = x.read().unwrap()` held across
  mutation) are a different pattern, mechanically audited by
  RULE-SUBCANCEL-RWLOCK-0001 (137 apply_ops, single hit fixed) — not re-scanned
  here.
- Same-thread recursive READ locks (BLOCK-RWLOCK-RECURSIVE-READ-0001 family)
  are a separate std-RwLock concern.
