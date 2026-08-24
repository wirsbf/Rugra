#!/usr/bin/env bash
set -euo pipefail

# MERGE-FORCEMERGE-PANIC-0001: locked 12.0.4 bilateral runner.  Proves the
# merge action survival contract: ActionMergeType must run
# Merge::mergeByDatatype only (coreaction.hh:414) and never re-enter
# mergeAddrTied/mergeRangeMust after ActionMarkImplied, so an implied
# member of a (late-gated) address-tied exact-location range can never
# reach Merge::mergeTestMust at mergetype time.
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rugra_base_commit=8dc17e4453d4f14a26318de92d6a8120f6e0bceb
rugra_base_tree=b6206fbd14a5542d69d4432336b205d202214fd4
rugra_base_src_tree=d146e6d16a84c1d8084fe6fd9485a37284ab15eb
rugra_base_coreaction_blob=dffd02708768be2044b298d33e425505fac8c9c4

ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/merge_forcepanic_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/merge_forcepanic_1204.cc"
rust_fixture="$repo_root/tests/oracle/merge_forcepanic_1204.rs"
runner="$repo_root/tools/run_merge_forcepanic_oracle.sh"

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$runner"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
actual_tag=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$actual_tag" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
  Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

for binding in \
  "$rugra_base_commit^{commit}:$rugra_base_commit" \
  "$rugra_base_commit^{tree}:$rugra_base_tree" \
  "$rugra_base_commit:src:$rugra_base_src_tree" \
  "$rugra_base_commit:src/coreaction.rs:$rugra_base_coreaction_blob"; do
  expression=${binding%:*}
  expected=${binding##*:}
  actual=$(git -C "$repo_root" rev-parse "$expression")
  if [[ "$actual" != "$expected" ]]; then
    echo "pinned Rugra base identity mismatch: $expression" >&2
    exit 1
  fi
done

runner_sha=$(sha256sum "$runner" | awk '{print $1}')
python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$runner_sha" <<'PY'
import hashlib
import json
import pathlib
import sys

(metadata_raw, cpp_raw, rust_raw, runner_sha) = sys.argv[1:]

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

data = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
require("fixture", data["fixture_id"], "MERGE-FORCEMERGE-PANIC-0001")
require("overall", data["overall_status"], "MISMATCH")
comparand = data["comparand"]
for key, path in (
    ("cpp_fixture_sha256", cpp_raw),
    ("rust_fixture_sha256", rust_raw),
):
    require(key, sha(path), comparand[key])
require("runner sha", runner_sha, comparand["runner_sha256"])

fingerprinted = {
    "architecture": data["architecture"],
    "compiler_spec": data["compiler_spec"],
    "analysis_options": data["analysis_options"],
    "inputs": data["input_manifest"]["inputs"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("input manifest sha", hashlib.sha256(canonical).hexdigest(),
        data["input_manifest"]["sha256"])
PY

oracle_tmp=$(mktemp -d /tmp/rugra-merge-forcepanic-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-merge-forcepanic-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

snapshot="$oracle_tmp/workspace"
mkdir -p "$snapshot/tests/oracle" \
  "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile"
git -C "$repo_root" archive --format=tar --output="$oracle_tmp/rugra.tar" \
  "$rugra_base_commit" Cargo.toml Cargo.lock build.rs README.md \
  benches/decompile_bench.rs tests/oracle/decompress_1204.rs \
  tests/oracle/funcproto_lock_1204.rs src sleigh_shim
tar -xf "$oracle_tmp/rugra.tar" -C "$snapshot"
cp "$rust_fixture" "$snapshot/tests/oracle/merge_forcepanic_1204.rs"

git -C "$ghidra_root" archive --format=tar --output="$oracle_tmp/ghidra.tar" \
  "$oracle_commit" Ghidra/Features/Decompiler/src/decompile/cpp
mkdir -p "$oracle_tmp/oracle"
tar -xf "$oracle_tmp/ghidra.tar" -C "$oracle_tmp/oracle"
oracle_cpp="$oracle_tmp/oracle/Ghidra/Features/Decompiler/src/decompile/cpp"
ln -s "$oracle_cpp" \
  "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$oracle_cpp" -j "$jobs" \
  CXX="g++ -std=c++11" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$oracle_cpp" "$cpp_fixture" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" \
  -Wl,--whole-archive "$oracle_cpp/libdecomp.a" -Wl,--no-whole-archive -lz \
  -o "$oracle_tmp/merge_forcepanic_cpp"

flock /tmp/rugra-cargo-build.lock -c \
  "CARGO_TARGET_DIR=/tmp/rugra-target-merge-forcepanic cargo build --offline --locked --quiet --manifest-path '$snapshot/Cargo.toml' --lib"
rustc --edition=2021 -O \
  -L dependency=/tmp/rugra-target-merge-forcepanic/debug/deps \
  --extern rugra=/tmp/rugra-target-merge-forcepanic/debug/librugra.rlib \
  "$snapshot/tests/oracle/merge_forcepanic_1204.rs" \
  -o "$oracle_tmp/merge_forcepanic_rust"

set +e
"$oracle_tmp/merge_forcepanic_cpp" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/merge_forcepanic_rust" \
  >"$oracle_tmp/rugra.stdout" 2>"$oracle_tmp/rugra.stderr"
rugra_status=$?
set -e

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" \
  "$oracle_tmp/rugra.stdout" "$ghidra_status" "$rugra_status" \
  "$oracle_tmp/ghidra.stderr" "$oracle_tmp/rugra.stderr" <<'PY'
import hashlib
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra_stdout = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
rugra_stdout = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
ghidra_status = int(sys.argv[4])
rugra_status = int(sys.argv[5])
ghidra_stderr = pathlib.Path(sys.argv[6]).read_text(encoding="utf-8")
rugra_stderr = pathlib.Path(sys.argv[7]).read_text(encoding="utf-8")

if ghidra_status != 0 or rugra_status != 0:
    raise SystemExit(
        f"fixture exit codes must be 0: ghidra={ghidra_status} rugra={rugra_status}"
    )
if ghidra_stderr or rugra_stderr:
    raise SystemExit("fixture stderr must be empty")

def line_sha(text):
    return hashlib.sha256(text.encode()).hexdigest()

expected = data["expected_stdout"]
if line_sha(ghidra_stdout) != expected["ghidra_stdout_sha256"]:
    raise SystemExit("ghidra stdout hash mismatch")
if line_sha(rugra_stdout) != expected["rugra_stdout_sha256"]:
    raise SystemExit("rugra stdout hash mismatch")

glines = ghidra_stdout.splitlines()
rlines = rugra_stdout.splitlines()
if len(glines) != len(rlines):
    raise SystemExit("stdout line-count mismatch")
registered = data["registered_divergence_lines"]
mismatches = []
for index, (gl, rl) in enumerate(zip(glines, rlines)):
    if gl == rl:
        continue
    if gl not in registered:
        raise SystemExit(f"unregistered divergence on line {index + 1}: {gl!r}")
    entry = registered[gl]
    if line_sha(rl) != entry["rugra_line_sha256"]:
        raise SystemExit(f"registered divergence rugra line drifted: {gl!r}")
    mismatches.append((gl, entry["reason"]))
for gl, reason in mismatches:
    print(f"registered MISMATCH: {gl} ({reason})")

verdicts = [line for line in rlines if line.startswith("verdict=")]
if verdicts != ["verdict=PIPELINE-OK"]:
    raise SystemExit(f"rugra verdict must be PIPELINE-OK: {verdicts!r}")
mergetype = [line for line in rlines if line.startswith("act=mergetype|")]
if not mergetype or mergetype[0] != "act=mergetype|res=0|exc=none":
    raise SystemExit(f"mergetype must complete without panic: {mergetype!r}")
print("merge_forcepanic_1204: decisive_projection=MATCH "
      "registered_mismatch=%d overall=MISMATCH" % len(mismatches))
PY
