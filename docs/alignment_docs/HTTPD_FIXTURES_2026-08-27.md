# HTTPD vhost/path fixture design (2026-08-27)

**Task:** HTTPD-BUCKET2-2026-08-27.
**Oracle:** Ghidra 12.0.4 `e40ed13014025f82488b1f8f7bca566894ac376b`, tag `Ghidra_12.0.4_build`.
**Input:** locked HTTPD ELF corpus consumed by `examples/httpd_decompile.rs`; x86-64, compiler spec `x86:LE:64:default`, locked driver analysis options.

## Fixture contract

`tests/oracle/httpd_vhost_cfg_1204.cc` is a compileable contract census for the two top HTTPD residuals. It records the structural anchors extracted from `tests/golden/ghidra_httpd_1204.c`: `ap_fini_vhost_config` (217 lines, 22 if, 3 for, 8 while, 5 goto, 62 calls) and `ap_getparents` (149 lines, 18 if, 0 for, 7 while, 6 goto, 27 calls). The C++ design intentionally observes the pre-print shape rather than final C text: the eventual full harness must dump ordered basic blocks, block types, incoming/outgoing slot and flags, and each block's ordered p-code opcode stream.

`tests/oracle/httpd_vhost_cfg_1204.rs` is a compileable `NO_ORACLE` placeholder. Once CFG recovery is available, it must run the production `Funcdata`/`BlockGraph` path for the same function entry addresses and emit the same projection fields. It must not be upgraded to MATCH from hand-written expected counts.

`tools/run_httpd_vhost_cfg_oracle.sh` compiles and runs both sides. It deliberately reports `fixture_status=NO_ORACLE` while the Rust side remains TODO. This makes the fixture useful as a build/contract check without falsely claiming behavioral parity.

## Function-specific observations

* `ap_fini_vhost_config` is a multi-level hash-bucket/list routine: bucket initialization, outer and inner list walks, `memcmp` split, collision insertion, overlap handling, and optional dump traversal. The expected loop structure is the principal boundary for the future BlockGraph projection.
* `ap_getparents` is iterative path normalization: scan dot components, compact `./`, remove `../` by reverse slash search, and terminate on empty/leading parent components. Its character constants (`'\\0'`, `'.'`, `'/'`) are not STRCONST string literals.

## Activation and dependencies

The fixture is intentionally queued for activation after regB/irreducible CFG integration. Required future write-set is the Rust fixture only (plus paired metadata/runner updates): production pre-print observation, no printc fallback. Any printer work is a separate lease and may only start after the CFG projection shows the corresponding loops/case boundaries. Acceptance is a real Ghidra-vs-Rugra projection with matching block/op/edge order and flags for both functions; current status remains `NO_ORACLE`.
