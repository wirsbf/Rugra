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

## Banked functions (all MATCH; 10 original + 15 cascade-harvest + helpf + 45 PLT-thunk address-arm harvest = 71)

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
| curl_main_free | main_free | 0x4970 | 150 | 200 | bank sha256 (capture mode, cascade harvest) |
| curl_main_init | main_init | 0x4960 | 155 | 615 | bank sha256 (capture mode, cascade harvest) |
| curl_SetHTTPrequest.part.0 | SetHTTPrequest.part.0 | 0x3c50 | 191 | 1,655 | bank sha256 (capture mode, cascade harvest) |
| curl_SetHTTPrequest | SetHTTPrequest | 0x4980 | 191 | 4,511 | bank sha256 (capture mode, cascade harvest) |
| curl_glob_url | glob_url | 0x4f70 | 191 | 7,288 | bank sha256 (capture mode, cascade harvest) |
| curl_frame_dummy | frame_dummy | 0x3450 | 186 | 2,785 | bank sha256 (capture mode, cascade harvest) |
| curl___do_global_dtors_aux | __do_global_dtors_aux | 0x3410 | 191 | 5,363 | bank sha256 (capture mode, cascade harvest) |
| curl__init | _init | 0x2000 | 191 | 2,149 | bank sha256 (capture mode, cascade harvest) |
| curl__fini | _fini | 0x5478 | 150 | 506 | bank sha256 (capture mode, cascade harvest) |
| curl___libc_csu_fini | __libc_csu_fini | 0x5470 | 150 | 200 | bank sha256 (capture mode, cascade harvest) |
| curl___libc_csu_init | __libc_csu_init | 0x5400 | 227 | 7,064 | bank sha256 (capture mode, cascade harvest) |
| curl_deregister_tm_clones | deregister_tm_clones | 0x33a0 | 186 | 1,172 | bank sha256 (capture mode, cascade harvest) |
| curl_register_tm_clones | register_tm_clones | 0x33d0 | 186 | 2,747 | bank sha256 (capture mode, cascade harvest) |
| curl_GetStr | GetStr | 0x36d0 | 191 | 5,349 | bank sha256 (capture mode, cascade harvest) |
| curl_my_fwrite | my_fwrite | 0x3460 | 268 | 7,788 | bank sha256 (capture mode, cascade harvest) |
| curl_helpf | helpf | 0x3980 | 345 | 195,009 | bank sha256 (capture mode; PM-HF lane, mark_unaliased range-walk fix) |

PLT-thunk entries (2026-09-25, lane ADDRARM2; all captured through the
oracle harness **address-only arm** — these entries carry no BFD symbol
in any table, so the runner CLI passes `-` as the function token and the
fixture registers the function at the entry exactly like the console
`load <addr>` command; the rugra side uses the address-form selector).
44 of the 45 share the uniform stub shape 186 stages / 742 ops; PLT0 is
richer (191 / 1,240):

| entry | function | entry addr | stages | ops |
|---|---|---|---|---|
| curl_plt_plt0 | FUN_00102020 (PLT0 header) | 0x2020 | 191 | 1,240 |
| curl_plt___cxa_finalize | __cxa_finalize (.plt.got) | 0x22e0 | 186 | 742 |
| curl_plt_free | free | 0x22f0 | 186 | 742 |
| curl_plt___vfprintf_chk | __vfprintf_chk | 0x2300 | 186 | 742 |
| curl_plt_strcpy | strcpy | 0x2310 | 186 | 742 |
| curl_plt_puts | puts | 0x2320 | 186 | 742 |
| curl_plt_isatty | isatty | 0x2330 | 186 | 742 |
| curl_plt_curl_easy_perform | curl_easy_perform | 0x2340 | 186 | 742 |
| curl_plt_curl_slist_append | curl_slist_append | 0x2350 | 186 | 742 |
| curl_plt_fclose | fclose | 0x2360 | 186 | 742 |
| curl_plt_strlen | strlen | 0x2370 | 186 | 742 |
| curl_plt___stack_chk_fail | __stack_chk_fail | 0x2380 | 186 | 742 |
| curl_plt_strchr | strchr | 0x2390 | 186 | 742 |
| curl_plt_strrchr | strrchr | 0x23a0 | 186 | 742 |
| curl_plt_maprintf | maprintf | 0x23b0 | 186 | 742 |
| curl_plt_fputc | fputc | 0x23c0 | 186 | 742 |
| curl_plt_fgets | fgets | 0x23d0 | 186 | 742 |
| curl_plt_strtol | strtol | 0x23e0 | 186 | 742 |
| curl_plt_memcpy | memcpy | 0x23f0 | 186 | 742 |
| curl_plt_time | time | 0x2400 | 186 | 742 |
| curl_plt_fileno | fileno | 0x2410 | 186 | 742 |
| curl_plt___xstat | __xstat | 0x2420 | 186 | 742 |
| curl_plt_malloc | malloc | 0x2430 | 186 | 742 |
| curl_plt___isoc99_sscanf | __isoc99_sscanf | 0x2440 | 186 | 742 |
| curl_plt_curl_easy_init | curl_easy_init | 0x2450 | 186 | 742 |
| curl_plt_curl_getenv | curl_getenv | 0x2460 | 186 | 742 |
| curl_plt_realloc | realloc | 0x2470 | 186 | 742 |
| curl_plt___printf_chk | __printf_chk | 0x2480 | 186 | 742 |
| curl_plt_curl_version | curl_version | 0x2490 | 186 | 742 |
| curl_plt_curl_slist_free_all | curl_slist_free_all | 0x24a0 | 186 | 742 |
| curl_plt_fopen | fopen | 0x24b0 | 186 | 742 |
| curl_plt_strcat | strcat | 0x24c0 | 186 | 742 |
| curl_plt_curl_easy_setopt | curl_easy_setopt | 0x24d0 | 186 | 742 |
| curl_plt_curl_getdate | curl_getdate | 0x24e0 | 186 | 742 |
| curl_plt_exit | exit | 0x24f0 | 186 | 742 |
| curl_plt_fwrite | fwrite | 0x2500 | 186 | 742 |
| curl_plt___fprintf_chk | __fprintf_chk | 0x2510 | 186 | 742 |
| curl_plt_curl_easy_cleanup | curl_easy_cleanup | 0x2520 | 186 | 742 |
| curl_plt_strdup | strdup | 0x2530 | 186 | 742 |
| curl_plt_strequal | strequal | 0x2540 | 186 | 742 |
| curl_plt_curl_formparse | curl_formparse | 0x2550 | 186 | 742 |
| curl_plt_strstr | strstr | 0x2560 | 186 | 742 |
| curl_plt_strnequal | strnequal | 0x2570 | 186 | 742 |
| curl_plt___ctype_b_loc | __ctype_b_loc | 0x2580 | 186 | 742 |
| curl_plt___sprintf_chk | __sprintf_chk | 0x2590 | 186 | 742 |

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
fixture carries the BFD spelling — identity is entry-address based), and
`func_name` for the PLT-thunk entries (oracle `func_0x…` nameFunction
default vs driver ledger spelling — same entry-address identity basis).

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
# PLT-thunk entries (no BFD symbol): pass "-" as the function token to
# take the address-only arm, e.g. ... curl 22f0 -   (see curl_plt_*).
# Batch drivers may set RUGRA_STAGE_PROJECTION_BUILD=<dir> to cache the
# instrumented oracle build across invocations.
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
`helpf` (local symbol; no spelling divergence — BFD and the driver's
FuncInfo layer agree on this name).

The 15 cascade-harvest entries (2026-09-24, lane HARVEST) were captured
with the address-form selector `RUGRA_STAGE_FUNC=0x<entry>`
(`main_free`, `main_init`, `SetHTTPrequest.part.0`, `SetHTTPrequest`,
`glob_url`, `frame_dummy`, `__do_global_dtors_aux`, `_init`, `_fini`,
`__libc_csu_fini`, `__libc_csu_init`, `deregister_tm_clones`,
`register_tm_clones`, `GetStr`, `my_fwrite`); their manifests record
the exact per-entry commands. All entries and pins use the oracle
harness's nm-style address convention (no 0x100000 image base), the
same convention as `main@0x25a0` in the metadata functions map.

Non-MATCH scan residue from the same harvest pass (first divergence
recorded for later lanes; not banked):

| function | entry | kind | first divergence |
|---|---|---|---|
| hugehelp | 0x4a00 | op-line | ordinal 2 `universal:start` op 14: oracle `BRANCH in=n:ram:2320:1` vs rugra `CALL in=f:4a0f:c`; op totals 1,699 vs 4,314 |
| main | 0x25a0 | op-line | ordinal 5 `universal:extrapopsetup` op 1792: identical INT_ADD at differing op-creation ordinal (`2d04:c15` oracle vs `2d04:c0e` rugra, +7 pool offset); op totals 2,414,145 vs 2,413,566 |
| my_get_line | 0x3840 | result-count | ordinal 52 `universal:fullloop:mainloop:condconst`: result/count 2 vs 1 |
| helpf | 0x3980 | result-count | ordinal 70 `universal:fullloop:mainloop:stackstall:oppool1`: result/count 118 vs 110 |
| _start | 0x3370 | result-count | ordinal 149 `universal:fullloop:mainloop:constantptr`: result/count/apply 3/3/1 vs 0/0/0 (ACTION-SYMDB-DATASYM-0001 class) |
| progressbarinit | 0x49a0 | op-line | ordinal 123 `universal:fullloop:activereturn` op 9: CALL out `n:register:0:8` vs `u:0:8` |

Oracle-side capture limitation observed in the 2026-09-24 harvest pass
and **resolved 2026-09-25 (lane ADDRARM2)**: PLT thunk functions (the
`.plt.sec`/`.plt.got` stubs and the PLT0 header, e.g. `free@0x22f0`)
carry no BFD symbol in any table (static `.symtab` has nothing; the
dynamic table only carries the undefined import), so the harness's
`STAGE_PROJ_FUNC` name lookup could not target them. The runner now has
an address-only arm: `bash tools/run_stage_projection_oracle.sh curl
<entry-hex> -` passes `STAGE_PROJ_ADDR` without `STAGE_PROJ_FUNC`, and
the fixture then registers the function at the entry exactly like the
Ghidra console `load <addr>` command (IfcAddrrangeLoad,
ifacedecomp.cc:496-514: `Architecture::nameFunction` default name +
global-scope `addFunction`). The full ledger-populated thunk population
(45 entries, 0x2020 + 0x22e0-0x2590 nm-form) was swept through this arm
and every one of them matched on first verification (see the PLT table
above). The `func_name` META field differs by construction on these
entries (oracle `func_0x000022f0`-style default vs the driver's ledger
spelling) and is advisory under the bisect contract — the same class as
the constprop BFD/DWARF spellings. The remaining out-of-reach golden
corpus entries are the EXTERNAL-block pseudo functions at 0x19xxx-nm
(they have no backing ELF section at all — no code to follow on either
side; the driver prints stub sections, the oracle has nothing to load).

Fixture producer re-pin (same lane): the fixture grew the address arm,
so its git blob (the META `producer=` value inside every oracle
projection) changed from `f6cb61d1…` to `24a4bec2…`; all 26 pre-existing
entries' oracle projections were re-captured and re-pinned with the
producer line verified as the only byte difference.

## httpd PLT-thunk population (2026-09-25, lane HBANK — inventoried and
oracle-captured, not yet banked)

The httpd corpus carries the same first-section PLT thunk family curl
has, at a larger scale. Enumerated with the same readelf `-S`/`-r`
method as the curl sweep (only real code slots in the executable PLT
sections enter — EXTERNAL pseudo-functions have no code bytes and are
excluded by construction):

| segment | entries | stages/ops |
|---|---|---|
| PLT0 header @0x29020 | 1 | 191 / 1,240 |
| .plt.got (apr_bucket_free @0x2a400, __cxa_finalize @0x2a410) | 2 | 186 / 742 |
| .plt.sec @0x2a420-0x2b7e0 | 317 | 186 / 742 |

320 entries total (ledger: `/dev/shm/rugra-tests/hbank/httpd_thunks.tsv`,
regenerable via `make_inventory.py` in the same directory). httpd is
stripped, so unlike curl none of these thunks appear in any BFD symbol
table — the address-only arm is the only oracle capture channel, and all
320 oracle projections were captured deterministically (double-run cmp)
through it with the shared build cache (`RUGRA_STAGE_PROJECTION_BUILD`).

Banking is blocked on the rugra side: the httpd driver's stage-selectable
function ledger is dynsym-defined-only (473 entries, first at 0x2b820), so
`RUGRA_STAGE_FUNC=0x2a430` exits 1 ("matched no function in the ELF symbol
tables") — unlike curl, whose driver ledger (GOLDEN_CORPUS_LEDGER) bakes
the thunks in. Registered as TODO `HBANK-DRIVER-STAGELEDGER-0001`. The
frozen oracle-side captures live under `/dev/shm/rugra-tests/hbank/
oracle_thunks/` for the follow-up lane (RAM disk — re-capture recipe:
`RUGRA_STAGE_PROJECTION_OUT=… bash tools/run_stage_projection_oracle.sh
httpd <entry> -`).

## Adding a function

1. capture both sides with the recipes above (double-run determinism check
   on the rugra side);
2. `bash tools/run_stage_bisect.sh <oracle> <rugra>` must print
   `kind: MATCH`;
3. create `manifest.toml` (copy a sibling; update function/entry/selector,
   sha256 pins, stages/ops, date, pin_mode);
4. add the row here and to the table above;
5. run `tools/verify_projection_bank.sh` — must print OK for the new entry.
