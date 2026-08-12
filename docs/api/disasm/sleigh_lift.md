# sleigh_lift.rs — SLEIGH P-code bridge

`src/disasm/sleigh_lift.rs` converts the owned, dynamic result from
`SleighCtx::one_instruction` into Rugra `PcodeOpRaw` values. The locked source oracle is
Ghidra 12.0.4 commit `e40ed13014025f82488b1f8f7bca566894ac376b`, principally
`Sleigh::oneInstruction` (`sleigh.cc:741`) and the `Translate::oneInstruction`
contract (`translate.hh:419`).

## Status

This module is **L2 / MISMATCH**. It is now used by the production CLI and canonical curl
example, but neither the SLEIGH context path nor the surrounding Flow pipeline is fully
equivalent to Ghidra.

- `SleighLifter::configure_x86_64` owns one translator and one copied ELF-section image for
  a function-flow run. It loads the repository x86-64 pspec compatibility path before the
  first decode. Full `ContextInternal::decodeFromSpec` behavior remains
  `SLEIGH-0002C`.
- `SleighLifter::lift_instruction` makes exactly one strict `one_instruction` call and
  returns its step together with every emitted op. A legal zero-op instruction remains a
  successful decode. Typed errors are preserved for `FlowInfo`.
- `convert` no longer applies the legacy 16-input cap. It preserves callback op/input
  order, while the Address/AddrSpace model and branch/call constant-space conversion still
  depend on `ADDR-0001` and `SLEIGH-FLOW-0001`.
- `lift_function` and `lift_from_func` remain compatibility helpers. They fold strict errors
  into omitted/empty output and therefore are not behavior-oracle entry points.

## 2026-08-13 reachable-flow integration

`PIPE-REACH-0001` replaced the canonical linear iced-x86 address sweep with a single
configured `SleighLifter` consumed by `FlowInfo`. On locked `examples/curl` / `GetStr`, the
reachable raw sequence is now 103 ops on both sides; the numeric tuple
`(address, opcode, input_count, has_output)` agrees for every op. Full raw state remains
`MISMATCH`: emitted Varnode type/cover flags differ, and direct CALL annotations use
Rugra's synthetic Iop space because it has no dynamic Fspec address space.

Behavior evidence is produced by:

```bash
tools/run_getstr_pipeline_oracle.sh
```

The fixture uses the release profile because two independently reviewed core-algorithm
repairs are still pending (`VARMAP-GATHEROFFSET-0001` and
`RULE-COLLECTTERMS-0001`). This evidence does not promote the module to L3.
