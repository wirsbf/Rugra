# HTTPD corpus / language inventory

Read-only investigation at `/home/ls/Rugra`. No repository files were changed and no build was run. Baseline inputs are `/dev/shm/rugra-tests/sb-baseline/httpd_new.c` and `httpd_new.err`.

## Executive conclusion

The 29-function result is **not** a hard-coded function list, config file, reachability walk, or early failure. `examples/httpd_decompile.rs` collects 473 ELF-defined functions, sorts them by address, defaults `MAX_FUNCS` to 30, and processes only the first 30 vector entries; `_start` is explicitly skipped, yielding 29 successful output blocks. `MAX_FUNCS` is the only selection knob, but it selects an address prefix rather than arbitrary/top-diff names.

## 1. Exact source of the 29

Selection points in `examples/httpd_decompile.rs`:

- Lines 57-99: build `functions` from `elf.syms` and `elf.dynsyms`; only nonzero function symbols with a mapped file offset are appended. Dynsym entries are deduplicated by entry address (line 96).
- Line 163: `functions.sort_by_key(|f| f.0)`.
- Line 165: `let max_functions = std::env::var("MAX_FUNCS")...unwrap_or(30);`.
- Lines 184-217: prototype prepass uses `functions.iter().take(max_functions + 50)`; this does **not** control emitted output, but gathers prototypes and call targets.
- Lines 277-283: tail-call known-entry set combines ELF function addresses and discovered call targets.
- Lines 300-303: output pass enumerates sorted functions, breaks at `idx >= max_functions`, and skips `size < 5`, `_start`, `register_tm_clones*`, `deregister_tm_clones*`, `__libc_csu_init`, `__libc_csu_fini`, and `frame_dummy`.
- Lines 306-316: each remaining function is disassembled/lifted; invalid disassembly increments `total_fail` and continues.
- Lines 436-448: each function has a 15-second `recv_timeout`; timeout emits a `TIMEOUT (>15s)` block and increments failure count.

The first 30 sorted ELF entries are `main`, `_start`, then the 28 functions from `ap_get_server_built` through `ap_getword_nc`. `_start` is the only explicitly skipped member of that prefix in this baseline, so the stdout contains 29 functions. Baseline stderr confirms `[DECOMP]` occurred 29 times and reports no timeout/failure.

The exact 29 baseline headers are:

| # | Entry | Function | Bytes |
|---:|---:|---|---:|
| 1 | `0x2b820` | `main` | 3062 |
| 2 | `0x2c510` | `ap_get_server_built` | 12 |
| 3 | `0x2c8d0` | `suck_in_APR` | 12 |
| 4 | `0x2cef0` | `ap_init_vhost_config` | 61 |
| 5 | `0x2cf30` | `ap_parse_vhost_addrs` | 203 |
| 6 | `0x2d000` | `ap_set_name_virtual_host` | 31 |
| 7 | `0x2d020` | `ap_fini_vhost_config` | 1615 |
| 8 | `0x2d670` | `ap_matches_request_vhost` | 134 |
| 9 | `0x2d700` | `ap_update_vhost_from_headers` | 841 |
| 10 | `0x2da50` | `ap_vhost_iterate_given_conn` | 157 |
| 11 | `0x2daf0` | `ap_update_vhost_given_ip` | 229 |
| 12 | `0x2dd30` | `ap_field_noparam` | 131 |
| 13 | `0x2ddc0` | `ap_ht_time` | 347 |
| 14 | `0x2df20` | `ap_strcmp_match` | 197 |
| 15 | `0x2dff0` | `ap_strcasecmp_match` | 230 |
| 16 | `0x2e0e0` | `ap_os_is_path_absolute` | 129 |
| 17 | `0x2e170` | `ap_is_matchexp` | 54 |
| 18 | `0x2e1b0` | `ap_pregcomp` | 114 |
| 19 | `0x2e230` | `ap_pregfree` | 50 |
| 20 | `0x2e270` | `ap_strcasestr` | 142 |
| 21 | `0x2e300` | `ap_stripprefix` | 68 |
| 22 | `0x2e350` | `ap_pregsub` | 695 |
| 23 | `0x2e610` | `ap_getparents` | 580 |
| 24 | `0x2e860` | `ap_no2slash` | 88 |
| 25 | `0x2e8c0` | `ap_make_dirstr_prefix` | 121 |
| 26 | `0x2e940` | `ap_make_dirstr_parent` | 107 |
| 27 | `0x2e9b0` | `ap_count_dirs` | 63 |
| 28 | `0x2e9f0` | `ap_getword` | 170 |
| 29 | `0x2eaa0` | `ap_getword_nc` | 12 |

## 2. Golden 2010 vs Rugra 29

The locked golden was parsed from header lines of the form:

```text
/* ---- 0xADDR: NAME (SIZE bytes) ---- */
```

The complete machine-readable golden list (2010 `address<TAB>name<TAB>size` rows) is at:

```text
/dev/shm/rugra-tests/sb-corpus/httpd_names_ghidra_httpd_1204.tsv
```

The extracted baseline list is at:

```text
/dev/shm/rugra-tests/sb-corpus/httpd_names_httpd_new.tsv
```

For matching, golden addresses were rebased by subtracting Ghidra's PIE image base `0x100000`. The comparison is 29/29 matched on the 29 Rugra entries, with 1981 golden entries absent from the baseline.

The 2010 golden partitions by address/function source as follows:

| Golden region / interpretation | Total | Present in 29 | Missing |
|---|---:|---:|---:|
| init/pre-PLT (`_DT_INIT`, `FUN_00129020`) | 2 | 0 | 2 |
| `.plt`/`.plt.sec` thunk functions | 319 | 0 | 319 |
| defined `.text` functions | 947 | 29 | 918 |
| artificial external import block | 742 | 0 | 742 |
| **Total** | **2010** | **29** | **1981** |

Among the 918 missing defined-`.text` functions, 463 have `FUN_...` names (analysis-created/unnamed internal chunks), 443 are named-but-unselected text functions, 4 are startup/init/fini entries, 3 are `default`, 3 are `caseD_0`, and 2 are `thunk_...`. Thus the dominant code gap is the unselected internal/whole-program `.text` set, not a reachability failure in the current loop. The other large gaps are explicit Ghidra platform artifacts: 319 PLT thunks and 742 one-byte artificial external import entries. The current driver has no Ghidra-style full analyzer function-discovery pass and does not emit those artifact classes.

## 3. Expansion cost and known bail conditions

### Top-N / address-prefix expansion

For an address-prefix corpus, changing `MAX_FUNCS=N` is mechanically sufficient to attempt the first N ELF entries. However:

- `MAX_FUNCS` counts vector indices, including skipped housekeeping entries, so output count is not exactly N.
- It cannot select the top-diff functions directly; the top-10 are spread across the first 30, but an arbitrary top-N list needs a new name/address filter or explicit target list.
- The prototype prepass grows to `N + 50`; it is bounded by the 473 ELF function entries in this driver. It also discovers call-target prototypes, but does not append those call targets to `functions` for output.
- Existing per-function construction is already complete enough for the current 29: ELF bytes, architecture attachment, symbols/strings, tail-call overrides, action pipeline, and stdout printing are present.

### Full 2010 expansion

Changing only `MAX_FUNCS` cannot produce the canonical 2010 corpus. A full corpus driver would need, at minimum:

1. A corpus/target model that includes ELF functions, PLT thunk entries, analyzer-discovered symbol-less `.text` entries, startup entries, and Ghidra's artificial external import block entries.
2. Function discovery beyond the current 473 ELF symbols. The current call-target pass only adds names/prototypes to tables; it does not create output `FuncInfo` rows for every discovered target.
3. External/PLT projection or loader support. The 319 PLT entries and 742 external slots have no normal local `.text` body; they need the same kind of explicit stub handling as the curl driver, or equivalent loader-backed semantics.
4. Corpus naming/address normalization matching the headless golden (`0x100000` image-base addresses and `FUN_001xxxxx` labels).
5. A selection/worker protocol suitable for thousands of independent functions, rather than the current address-prefix loop.

### Existing limits / bails

- `MAX_ALLOC` at lines 11-19 blocks any individual allocation over **512 MiB** by aborting the process.
- The prototype prepass truncates each function's inspected bytes to **4096** (`lines 184-189`); output decompilation truncates to **8192** (`lines 308-311`). This is a semantic ceiling for functions whose body exceeds 8192 bytes.
- Zero-size ELF symbols are assigned a guessed size of **512** bytes at lines 77 and 97, which is not sufficient for exact full-corpus extents.
- Invalid/unmapped file offsets and disassembly errors are silently skipped in several `continue` paths; output-pass disassembly failures increment `total_fail`.
- Explicit housekeeping filters at line 302 suppress `_start`, clone registration helpers, CSU init/fini, and `frame_dummy` even if within the requested prefix.
- Each worker has a **15-second** timeout (`recv_timeout(Duration::from_secs(15))`). Timeout prints a marker and increments failure, but the underlying thread is not forcibly cancelled; at large N, timed-out detached work can accumulate resource pressure.
- The baseline stderr shows no timeout or failure for the 29, but full expansion should expect the 15-second wall budget and 512 MiB allocation guard to become active risk points.
- The golden provenance records a **30-second** Ghidra per-function timeout, so the current 15-second Rugra budget is not equivalent to the oracle budget.

## 4. Current 29-function top-diff ranking

Command used, with stderr discarded to keep `[SYM]`/`[STEP]` noise out:

```text
python3 tools/compare_ghidra.py \
  /dev/shm/rugra-tests/sb-baseline/httpd_new.c \
  tests/golden/ghidra_httpd_1204.c --summary-only
```

Baseline result: Rugra 29, Ghidra 2010, matched 29; total skeleton diff **3576**, defects **0**, numbering issues **0**. Each function was also queried with `--func NAME -v`. Raw `-`/`+` counts below are complete unified-diff deletion/addition counts from the underlying comparison (excluding `---`/`+++` headers).

| Rank | Function | Skeleton diff | Raw `-` | Raw `+` | Defects | Numbering |
|---:|---|---:|---:|---:|---:|---:|
| 1 | `main` | 1180 | 524 | 656 | 0 | OK |
| 2 | `ap_fini_vhost_config` | 625 | 198 | 427 | 0 | OK |
| 3 | `ap_pregsub` | 345 | 119 | 226 | 0 | OK |
| 4 | `ap_update_vhost_from_headers` | 319 | 121 | 198 | 0 | OK |
| 5 | `ap_getparents` | 213 | 93 | 120 | 0 | OK |
| 6 | `ap_strcasecmp_match` | 103 | 47 | 56 | 0 | OK |
| 7 | `ap_ht_time` | 94 | 46 | 48 | 0 | OK |
| 8 | `ap_strcmp_match` | 77 | 40 | 37 | 0 | OK |
| 9 | `ap_parse_vhost_addrs` | 63 | 30 | 33 | 0 | OK |
| 10 | `ap_update_vhost_given_ip` | 62 | 28 | 34 | 0 | OK |
| 11 | `ap_strcasestr` | 60 | 27 | 33 | 0 | OK |
| 12 | `ap_getword` | 56 | 24 | 32 | 0 | OK |
| 13 | `ap_matches_request_vhost` | 46 | 16 | 30 | 0 | OK |
| 14 | `ap_make_dirstr_prefix` | 45 | 21 | 24 | 0 | OK |
| 15 | `ap_vhost_iterate_given_conn` | 43 | 20 | 23 | 0 | OK |
| 16 | `ap_field_noparam` | 37 | 17 | 20 | 0 | OK |
| 17 | `ap_os_is_path_absolute` | 35 | 19 | 16 | 0 | OK |
| 18 | `ap_no2slash` | 29 | 11 | 18 | 0 | OK |
| 19 | `ap_make_dirstr_parent` | 27 | 13 | 14 | 0 | OK |
| 20 | `ap_stripprefix` | 27 | 19 | 8 | 0 | OK |
| 21 | `ap_count_dirs` | 19 | 12 | 7 | 0 | OK |
| 22 | `ap_pregcomp` | 17 | 9 | 8 | 0 | OK |
| 23 | `ap_init_vhost_config` | 16 | 11 | 5 | 0 | OK |
| 24 | `ap_is_matchexp` | 15 | 10 | 5 | 0 | OK |
| 25 | `ap_pregfree` | 6 | 3 | 3 | 0 | OK |
| 26 | `ap_set_name_virtual_host` | 5 | 3 | 2 | 0 | OK |
| 27 | `ap_get_server_built` | 4 | 2 | 2 | 0 | OK |
| 28 | `ap_getword_nc` | 4 | 2 | 2 | 0 | OK |
| 29 | `suck_in_APR` | 4 | 2 | 2 | 0 | OK |

Raw `--func -v` captures are in `/dev/shm/rugra-tests/sb-corpus/httpd_verbose/`; the aggregate summary is `/dev/shm/rugra-tests/sb-corpus/httpd_summary.txt`.

## 5. Top-10 entry addresses

`nm -n --defined-only examples/httpd` reports `no symbols` because the binary is stripped. `readelf -sW examples/httpd` still exposes the required defined `FUNC` entries; those are recorded below as ELF-relative VMAs. No `.constprop`, `.cold`, `.part`, or `.isra` suffix-bearing symbol appears in the top 10.

| Rank | Function | Entry address | Readelf size | Binding/type |
|---:|---|---:|---:|---|
| 1 | `main` | `0x2b820` | 3062 | GLOBAL FUNC |
| 2 | `ap_fini_vhost_config` | `0x2d020` | 1615 | GLOBAL FUNC |
| 3 | `ap_pregsub` | `0x2e350` | 695 | GLOBAL FUNC |
| 4 | `ap_update_vhost_from_headers` | `0x2d700` | 841 | GLOBAL FUNC |
| 5 | `ap_getparents` | `0x2e610` | 580 | GLOBAL FUNC |
| 6 | `ap_strcasecmp_match` | `0x2dff0` | 230 | GLOBAL FUNC |
| 7 | `ap_ht_time` | `0x2ddc0` | 347 | GLOBAL FUNC |
| 8 | `ap_strcmp_match` | `0x2df20` | 197 | GLOBAL FUNC |
| 9 | `ap_parse_vhost_addrs` | `0x2cf30` | 203 | GLOBAL FUNC |
| 10 | `ap_update_vhost_given_ip` | `0x2daf0` | 229 | GLOBAL FUNC |

## 6. Phase 3 recommendation

Do **not** make the full 2010-function HTTPD corpus the first stage-bisect batch. First stabilize the curl full-corpus attribution workflow, because curl already has a 124/124 corpus and isolated single-function controls. HTTPD is still valuable as a **small follow-on pilot**: its current top five (`main`, `ap_fini_vhost_config`, `ap_pregsub`, `ap_update_vhost_from_headers`, `ap_getparents`) are real large semantic diffs, and the existing driver already handles architecture attachment, PLT name seeding, tail-call overrides, per-function actions, and diagnostics.

Recommended order:

1. Finish/validate curl stage-bisect controls and attribution output.
2. Add an HTTPD explicit name/address target filter (or equivalent top-diff target list), since `MAX_FUNCS` is only an address-prefix selector.
3. Run an HTTPD top-5 or top-10 pilot with the existing 15-second isolation and `RUGRA_DUMP_FUNC`/rule-stat hooks.
4. Only then design the full-corpus expansion: analyzer-discovered function entries, PLT/external stubs, 8192-byte/15-second limits, and detached-timeout resource management must be addressed first.

This makes HTTPD suitable for a controlled second wave, but not yet a first-wave full-corpus attribution target.
