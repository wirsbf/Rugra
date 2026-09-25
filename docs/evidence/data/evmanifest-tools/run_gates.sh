#!/bin/bash
# EVMANIFEST: wave-final gate chain at master dc7a0d0a (read-only verification)
set -o pipefail
WT=/dev/shm/rugra-worktrees/evmanifest
TGT=/dev/shm/rugra-targets/sb-evmanifest
OUT=/dev/shm/rugra-tests/sb-evmanifest/gates
ORA=/dev/shm/rugra-tests/sb-oracle
mkdir -p "$OUT"
cd "$WT" || exit 1
export CARGO_TARGET_DIR="$TGT"
BIN=$TGT/release/examples

echo "== curl E2E =="
RUST_BACKTRACE=full timeout 1200 $BIN/curl_decompile > "$OUT/curl.c" 2> "$OUT/curl.stderr.log"
echo "curl exit=$?"

echo "== httpd gate plane =="
RUST_BACKTRACE=full timeout 1200 $BIN/httpd_decompile > "$OUT/httpd_gate.c" 2> "$OUT/httpd_gate.stderr.log"
echo "httpd gate exit=$?"

echo "== curl determinism run2 =="
RUST_BACKTRACE=full timeout 1200 $BIN/curl_decompile > "$OUT/curl_run2.c" 2> /dev/null
echo "run2 exit=$?"
cmp -s "$OUT/curl.c" "$OUT/curl_run2.c" && echo "curl double-run: IDENTICAL" || echo "curl double-run: DIFFER"

echo "== gate compares =="
python3 tools/compare_ghidra.py "$OUT/curl.c" tests/golden/ghidra_curl_1204.c --summary-only | tee "$OUT/curl.compare.txt"
python3 tools/compare_ghidra.py "$OUT/httpd_gate.c" tests/golden/ghidra_httpd_1204.c --summary-only | tee "$OUT/httpd_gate.compare.txt"

echo "== byte-exact L1 scan =="
python3 /dev/shm/rugra-tests/sb-evmanifest/byte_exact_scan_ev.py "$OUT/curl.c" tests/golden/ghidra_curl_1204.c curl | tee "$OUT/curl.byteexact.txt"
python3 /dev/shm/rugra-tests/sb-evmanifest/byte_exact_scan_ev.py "$OUT/httpd_gate.c" tests/golden/ghidra_httpd_1204.c httpd | tee "$OUT/httpd_gate.byteexact.txt"

echo "== projections (curl driver, RUGRA_MIRROR=1 canonical bundle) =="
for fn in next_url match_url parseconfig.constprop.0 getparameter.constprop.0 myprogress main; do
  RUGRA_MIRROR=1 RUGRA_STAGE_PROJ=1 RUGRA_STAGE_FUNC=$fn RUGRA_STAGE_PROJ_OUT="$OUT/$fn.projection" \
    $BIN/curl_decompile > /dev/null 2> "$OUT/$fn.stderr.log"; echo "$fn exit=$?"
done
echo "== httpd main projection =="
RUGRA_MIRROR=1 RUGRA_STAGE_PROJ=1 RUGRA_STAGE_FUNC=main RUGRA_STAGE_PROJ_OUT="$OUT/httpd_main.projection" \
  $BIN/httpd_decompile > /dev/null 2> "$OUT/httpd_main.stderr.log"; echo "httpd main exit=$?"

echo "== projection bisect vs locked oracle =="
pair() {
  echo "===== $1 ====="
  timeout 600 python3 tools/stage_bisect.py --v1 "$2" "$3" > "$OUT/$1.bisect.txt" 2>&1
  echo "exit=$?"; head -8 "$OUT/$1.bisect.txt"
}
pair next_url     "$ORA/next_url.oracle.projection"                                     "$OUT/next_url.projection"
pair match_url    "$ORA/curl.match_url.oracle.projection"                               "$OUT/match_url.projection"
pair parseconfig  "/dev/shm/rugra-tests/sb-parseconfig/curl.parseconfig.oracle.projection" "$OUT/parseconfig.constprop.0.projection"
pair getparameter "$ORA/curl.getparameter.constprop.0.oracle.projection"                 "$OUT/getparameter.constprop.0.projection"
pair myprogress   "$ORA/curl.myprogress.oracle.projection"                               "$OUT/myprogress.projection"
pair curl_main    "$ORA/curl.main.oracle.projection"                                    "$OUT/main.projection"
pair httpd_main   "$ORA/httpd.main.oracle.projection"                                   "$OUT/httpd_main.projection"
echo "== done $OUT =="
