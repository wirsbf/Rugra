# Projection Bank — mechanism B2 solidified fixtures

Per-function stage-projection fixture bank: for each banked function, the
frozen oracle-side and rugra-side v1.2 stage projections plus a manifest
that pins provenance and byte identity. This directory is the durable,
in-repo form of the RAM-disk lane evidence (the `/dev/shm/rugra-tests/sb-*`
projection products are lost on reboot); it exists so that the banked
proven-MATCH functions cannot silently regress.
projection products are lost on reboot); it exists so that every
banked proven-MATCH function cannot silently regress.

## Layout

```
tests/fixtures/projections/
  README.md                          <- this manifest
  curl_<function>/
    oracle.projection                <- locked-oracle capture (frozen)
    rugra.projection                 <- rugra driver capture (frozen)
    manifest.toml                    <- provenance + sha256 pins + status
```

## Banked functions (all MATCH, verified 2026-09-24)

| entry | function | entry addr | stages | ops | oracle pin |
|---|---|---|---|---|---|
| curl_next_url | next_url | 0x4ff0 | 335 | 96,457 | metadata (default-mode, cross-mode byte-verified) |
| curl_match_url | match_url | 0x5220 | 340 | 80,385 | bank sha256 |
| curl_parseconfig.constprop.0 | parseconfig.constprop.0 | 0x3c80 | 335 | 130,099 | bank sha256 (== lane pin b2ace56a…) |
| curl_myprogress | myprogress | 0x34d0 | 402 | 84,249 | bank sha256 |
| curl_getparameter.constprop.0 | getparameter.constprop.0 | 0x3f00 | 371 | 913,373 | metadata functions map |
| curl_glob_set | glob_set | 0x4bc0 | 366 | 141,943 | bank sha256 (capture-mode first, then frozen) |
| curl_glob_word | glob_word | 0x4a60 | 335 | 208,414 | bank sha256 (capture mode, re-capture byte-verified) |
| curl_glob_range | glob_range | 0x4d60 | 299 | 68,330 | bank sha256 (capture mode, double-run byte-verified) |
| curl_file2string.part.0 | file2string.part.0 | 0x3a90 | 340 | 87,957 | bank sha256 (== sb-oracle pin c0981445…) |
| curl_my_get_token | my_get_token | 0x3720 | 520 | 53,359 | bank sha256 (capture mode, direct MATCH, no fix needed) |

Common provenance (also recorded per manifest):

- oracle: Ghidra `Ghidra_12.0.4_build`, commit
  `e40ed13014025f82488b1f8f7bca566894ac376b` (the project's locked oracle)
- architecture `x86:LE:64:default`, compiler spec `gcc`,
  analysis_options `default`, build_flags `v1-no-OPACTION_DEBUG`
- corpus binary: `examples/curl`
  (sha256 `8af50bca2f812580933fbbf125b66ce8ba4acfe88ef4435c89ac72356f122d41`)
- rugra driver commit at capture: `dc7a0d0ad5ba94cebb9488549ff17db3a0a0c0ca`
  for the original five (master when the bank was cut); the bank commit
  itself only adds fixtures. `curl_glob_set` was captured later at
  `cd071239883d9e536aca5ed71adc6f6d6ee52b04` (per its manifest).

## Verification

```bash
tools/verify_projection_bank.sh                     # all entries
tools/verify_projection_bank.sh curl_next_url       # single entry
```

Exit 0 only when every entry is complete, both projections still match
their manifest sha256 pins, and `tools/run_stage_bisect.sh` (=
`stage_bisect.py --v1`, strict offsets, no relax-unique) reports
`kind: MATCH`. The runner is the CI-gate form of mechanism B2 for these
functions; a failure names the entry and the offending check.

Advisory-only META differences between the two sides (expected, reported
as warnings by the bisect, never identity failures): `side`, `producer`
(rugra-tree commit vs oracle fixture blob), `unique_base` (driver prints
its allocation base; strict op offsets still compare), and
`func_name` for the two GCC constprop clones (the rugra driver's FuncInfo
layer carries the DWARF spelling `parseconfig`/`getparameter`; the oracle
fixture carries the BFD spelling — identity is entry-address based).

## Re-capture recipes (byte-identical reproduction)

Both producers must be re-run and re-bisected before any projection byte
may change; a re-capture that produces different bytes is a regression to
investigate, not a pin to update silently.

Oracle side (requires the locked ghidra tree + binutils 2.38 BFD, see
`tools/run_stage_projection_oracle.sh` header for the environment
contract; `/tmp/rugra-ghidra-bfd-2.38` is the usual include root):

```bash
RUGRA_STAGE_PROJECTION_OUT=tests/fixtures/projections/curl_<fn>/oracle.projection \
  bash tools/run_stage_projection_oracle.sh curl <entry-hex> <function>
# next_url may equivalently use the zero-arg default mode (same bytes).
```

Rugra side (cwd = repo root; projection lands via RUGRA_STAGE_PROJ_OUT;
each capture is run twice and `cmp`-verified deterministic before banking):

```bash
RUGRA_MIRROR=1 RUGRA_STAGE_PROJ=1 RUGRA_STAGE_FUNC=<selector> \
  RUGRA_STAGE_PROJ_OUT=tests/fixtures/projections/curl_<fn>/rugra.projection \
  cargo run --profile fast-release --example curl_decompile
```

Selector spellings: `next_url`, `match_url`, `myprogress`, `glob_set`,
`parseconfig` (DWARF spelling of `parseconfig.constprop.0`),
`getparameter` (DWARF spelling of `getparameter.constprop.0`),
`glob_word`, `glob_range`; the address form `0x<entry>` is
observation-equivalent (verified byte-identical on parseconfig).
`file2string` (DWARF spelling of `file2string.part.0`); the
address form `0x<entry>` is observation-equivalent (verified byte-identical
on parseconfig). The `file2string` entry's advisory-only `func_name` META
difference is the same constprop-clone BFD/DWARF spelling class.

## Adding a function

1. capture both sides with the recipes above (double-run determinism check
   on the rugra side);
2. `bash tools/run_stage_bisect.sh <oracle> <rugra>` must print
   `kind: MATCH`;
3. create `manifest.toml` (copy a sibling; update function/entry/selector,
   sha256 pins, stages/ops, date, pin_mode);
4. add the row here and to the table above;
5. run `tools/verify_projection_bank.sh` — must print OK for the new entry.
