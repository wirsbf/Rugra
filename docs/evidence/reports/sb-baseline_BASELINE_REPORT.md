# Fresh E2E Baseline — Stage Bisect Lane H

- Date: 2026-09-21 (Asia/Shanghai)
- Repository: `/home/ls/Rugra`
- HEAD: `0acde304d27b2d659635f0416a2307757fc9bcfe` (`0acde30`)
- Build: `cargo build --release --example curl_decompile --example httpd_decompile`
- No repository files were modified; generated files are under `/dev/shm/rugra-tests/sb-baseline/` only.

## Commands and output routing

The examples were read before execution. Both emit decompiled C with `println!` to stdout and diagnostics (`[SYM]`, `[STEP]`, etc.) with `eprintln!` to stderr. Runs used:

```text
target/release/examples/curl_decompile  > curl_new.c  2> curl_new.err
target/release/examples/httpd_decompile > httpd_new.c 2> httpd_new.err
```

The comparison inputs were the stdout files only; stderr was not mixed into the comparisons.

## Build/run timing

| Operation | elapsed | user | sys | result |
|---|---:|---:|---:|---|
| release build (both examples) | 26.00 s | 0.29 s | 1.24 s | PASS |
| curl E2E | 44.90 s | 39.98 s | 4.14 s | PASS |
| httpd E2E | 14.74 s | 14.35 s | 0.22 s | PASS |

The release build completed successfully with warnings only.

## Fresh corpus results

Compared with the canonical 12.0.4 goldens using `tools/compare_ghidra.py --summary-only`:

| corpus | matched / Rugra functions | Ghidra functions | skeleton / defects / numbering | stdout bytes / lines | sha256 |
|---|---:|---:|---:|---:|---|
| curl | 124 / 124 | 124 | **3711 / 0 / 0** | 109987 / 3761 | `023d6ab572421fed0151cdb807b646c7a1397b2ade480c843fb130f9eea68ea4` |
| httpd | 29 / 29 | 2010 | **3576 / 0 / 0** | 60938 / 2577 | `6535cbdc5cd08d33d6fab8dadde285ceb5e6ab1264d1917dd23330b435e3a710` |

Golden files: `tests/golden/ghidra_curl_1204.c` and `tests/golden/ghidra_httpd_1204.c`.

## Drift from recorded W4 baseline

The recorded W4 baseline was curl `3718/0/0`, sha prefix `a08dd3b0`, and httpd `2344/0/0`, sha prefix `429433e7`. The exact archived W4 files were also available as `/tmp/rugra-postw4-{curl,httpd}.c` and have full hashes:

- curl old: `a08dd3b08111a2179185be9fb19f1396067ccd328b618b93d04d5243210bd0b7`
- httpd old: `429433e774c7d7e06121e0acd0e8fdadbcdd8494397048b28b1613f7c1a4e737`

| corpus | W4 recorded | fresh | drift (fresh - W4) | sha drift |
|---|---:|---:|---:|---|
| curl | 3718 / 0 / 0 | **3711 / 0 / 0** | **-7 / 0 / 0** | changed (`a08dd3b0…` → `023d6ab5…`) |
| httpd | 2344 / 0 / 0 | **3576 / 0 / 0** | **+1232 / 0 / 0** | changed (`429433e7…` → `6535cbdc…`) |

The fresh httpd run therefore confirms a substantial post-W4 drift; it is not a stale-result artifact.

## Drift from `result/curl_cur.c`

`result/curl_cur.c` is not modified by this lane.

- old result sha256: `0c5c9cd3717220168133fb653a8099d74747d2c600da287df367d3c88c3de9a2`
- fresh sha256: `023d6ab572421fed0151cdb807b646c7a1397b2ade480c843fb130f9eea68ea4`
- old result: 110040 bytes / 3764 lines, mtime `2026-09-01 10:06:56.820845 +0800`
- fresh: 109987 bytes / 3761 lines, mtime `2026-09-21 23:25:32.421873 +0800`
- byte delta: **-53 bytes**; line delta: **-3 lines**; mtime delta: **+1,775,915.601 s** (~20d 13h 18m 35.6s)
- compare summary: `3713/0/0` (result) → **`3711/0/0`** (fresh), i.e. **-2/0/0**

There is no `result/httpd_cur.c` in the repository, so no result-file sha/mtime comparison exists for httpd.

## Top function raw skeleton differences (`--func ... -v`)

Values below are the tool's raw `[Skeleton] N lines differ` counts; every listed function also reported defects=0 and numbering=0.

### curl

Exact W4 archive → fresh:

| rank/function | W4 | fresh | delta |
|---|---:|---:|---:|
| 1. `main` | 1248 | **1248** | 0 |
| 2. `getparameter.constprop.0` | 869 | **869** | 0 |
| 3. `parseconfig.constprop.0` | 199 | **199** | 0 |
| 4. `next_url` | 147 | **144** | **-3** |
| 5. `file2string.part.0` | 144 | **144** | 0 |

The new ordering has `next_url` and `file2string.part.0` tied at 144. The next unchanged functions are `match_url` 100, `myprogress` 96, and `glob_set`/`helpf` 91. Thus the previously listed `next_url` rank moves into a tie; the dominant `main` and `getparameter` differences are unchanged.

### httpd

Exact W4 archive → fresh:

| rank/function | W4 | fresh | delta |
|---|---:|---:|---:|
| 1. `main` | 653 | **1180** | **+527** |
| 2. `ap_fini_vhost_config` | 258 | **625** | **+367** |
| 3. `ap_pregsub` | 222 | **345** | **+123** |
| 4. `ap_getparents` | 213 | **213** | 0 |
| 5. `ap_update_vhost_from_headers` | 221 | **319** | **+98** |

The new rank order is `main`, `ap_fini_vhost_config`, `ap_pregsub`, `ap_update_vhost_from_headers`, `ap_getparents`: `ap_update_vhost_from_headers` overtakes `ap_getparents`. The board prose rounded/listed different per-function counts (e.g. 656/278); the table above uses direct `--func` measurements against the archived W4 bytes whose aggregate is exactly 2344.

## Verification status

- Build: PASS.
- curl compare: `124` matched; `3711/0/0`.
- httpd compare: `29` matched; `3576/0/0`.
- Repository status was checked before/after; no lane-owned repository changes were made.
