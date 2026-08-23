#!/usr/bin/env bash
# JUMPTABLE-THUNK-CLASSIFY-0001 — locked Ghidra 12.0.4 differential gate
# for JumpTable::sanityCheck/recoverAddresses exception classification and
# mutation ordering. Synthetic FixtureArchitecture; no loader, BFD, or SLEIGH
# language assets are involved.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rugra_source_commit=8d3a5561f259420d00ec3ecb54e766b206f89331
rugra_source_tree=c8ee095912b9d56b80c38d72f0bea447ebc998c4
rugra_source_src_tree=004b20c8ed6da74cf6457a4386570bae4801bc78
rugra_jumptable_blob=64c824f03f41040696c9c6242f05e83a23e1ef55
rugra_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rugra_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rugra_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/jt_thunk_classify_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/jt_thunk_classify_1204.cc"
rust_fixture="$repo_root/tests/oracle/jt_thunk_classify_1204.rs"
jumptable_overlay="$repo_root/src/jumptable.rs"
runner="$repo_root/tools/run_jt_thunk_classify_oracle.sh"

oracle_tmp=$(mktemp -d /tmp/rugra-jt-thunk-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-jt-thunk-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$jumptable_overlay" "$runner"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || \
      "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
  Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

for binding in \
  "$rugra_source_commit^{commit}:$rugra_source_commit" \
  "$rugra_source_commit^{tree}:$rugra_source_tree" \
  "$rugra_source_commit:src:$rugra_source_src_tree" \
  "$rugra_source_commit:src/jumptable.rs:$rugra_jumptable_blob" \
  "$rugra_source_commit:Cargo.toml:$rugra_cargo_toml_blob" \
  "$rugra_source_commit:Cargo.lock:$rugra_cargo_lock_blob" \
  "$rugra_source_commit:build.rs:$rugra_build_rs_blob"; do
  expression=${binding%:*}
  expected=${binding##*:}
  actual=$(git -C "$repo_root" rev-parse "$expression")
  if [[ "$actual" != "$expected" ]]; then
    echo "pinned Rugra source identity mismatch: $expression" >&2
    exit 1
  fi
done

snapshot_root="$oracle_tmp/workspace"
mkdir -p "$snapshot_root/tests/oracle" "$snapshot_root/tools"
git -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rugra-source.tar" "$rugra_source_commit" \
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  src sleigh_shim
tar -xf "$oracle_tmp/rugra-source.tar" -C "$snapshot_root"
cp "$jumptable_overlay" "$snapshot_root/src/jumptable.rs"
cp "$cpp_fixture" "$snapshot_root/tests/oracle/jt_thunk_classify_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/jt_thunk_classify_1204.rs"
cp "$metadata" "$snapshot_root/tests/oracle/jt_thunk_classify_1204.metadata.json"
cp "$runner" "$snapshot_root/tools/run_jt_thunk_classify_oracle.sh"

runner_sha=$(sha256sum "$runner" | awk '{print $1}')
python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$jumptable_overlay" "$runner_sha" "$oracle_commit" "$oracle_tag" \
  "$oracle_cpp_tree" "$oracle_makefile_blob" "$rugra_source_commit" \
  "$rugra_source_tree" "$rugra_source_src_tree" "$rugra_jumptable_blob" \
  "$rugra_cargo_toml_blob" "$rugra_cargo_lock_blob" "$rugra_build_rs_blob" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    metadata_raw, cpp_raw, rust_raw, overlay_raw, runner_sha,
    oracle_commit, oracle_tag, cpp_tree, makefile_blob, source_commit,
    source_tree, source_src_tree, jumptable_blob, cargo_toml_blob,
    cargo_lock_blob, build_rs_blob,
) = sys.argv[1:]

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
require("schema", metadata["schema_version"], 2)
require("fixture", metadata["fixture_id"], "JT-THUNK-CLASSIFY-1204")
if not metadata.get("status_note"):
    raise SystemExit("status_note must be non-empty")
expected_decisive = {
    "reference_output_parameters", "loop_bounds_traversal_order",
    "counter_accumulator_lifecycle", "sorting_comparison_keys",
}
decisive = metadata.get("decisive_semantics")
require("decisive semantic classes", set(decisive), expected_decisive)
if any(not isinstance(value, str) or not value.strip() for value in decisive.values()):
    raise SystemExit("each decisive semantic class must be non-empty")

oracle = metadata["oracle"]
for label, actual, expected in (
    ("oracle tag", oracle["tag"], oracle_tag),
    ("oracle commit", oracle["commit"], oracle_commit),
    ("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree),
    ("oracle Makefile", oracle["decompiler_makefile_blob"], makefile_blob),
):
    require(label, actual, expected)
source = metadata["rugra_source"]
for label, actual, expected in (
    ("source commit", source["base_commit"], source_commit),
    ("source tree", source["base_tree"], source_tree),
    ("source src tree", source["base_src_tree"], source_src_tree),
    ("source jumptable blob", source["base_jumptable_blob"], jumptable_blob),
    ("Cargo.toml blob", source["cargo_toml_blob"], cargo_toml_blob),
    ("Cargo.lock blob", source["cargo_lock_blob"], cargo_lock_blob),
    ("build.rs blob", source["build_rs_blob"], build_rs_blob),
):
    require(label, actual, expected)
comparand = metadata["comparand"]
for key, path in (
    ("cpp_fixture_sha256", pathlib.Path(cpp_raw)),
    ("rust_fixture_sha256", pathlib.Path(rust_raw)),
    ("jumptable_overlay_sha256", pathlib.Path(overlay_raw)),
):
    require(key, sha(path.read_bytes()), comparand[key])
require("runner sha", runner_sha, comparand["runner_sha256"])

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "cases": manifest["cases"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("manifest sha", sha(canonical), manifest["sha256"])
require("projection", metadata["projection_status"], "MATCH")
require("overall", metadata["overall_status"], "MISMATCH")

expected_matches = {
    "single_target_boundary", "multi_target_bypass", "partial_before_thunk",
    "override_short_circuit_and_collapse", "lowlevel_partial_mutation",
}
expected_residuals = {"production_typed_stage_consumption"}
coverage = metadata["coverage"]
require("coverage keys", set(coverage), expected_matches | expected_residuals)
valid_statuses = {"MATCH", "MISMATCH", "NO_ORACLE", "UNTESTED"}
coverage_residual_ids = set()
for key, record in coverage.items():
    require(
        f"coverage.{key} fields", set(record),
        {"status", "covers", "residual_todo_ids"},
    )
    if record["status"] not in valid_statuses or not record["covers"]:
        raise SystemExit(f"invalid coverage record: {key}")
    if record["status"] == "MATCH":
        require(f"coverage.{key} MATCH residuals", record["residual_todo_ids"], [])
    elif not record["residual_todo_ids"]:
        raise SystemExit(f"coverage.{key} non-MATCH lacks residual id")
    coverage_residual_ids.update(record["residual_todo_ids"])
for key in expected_matches:
    require(f"coverage.{key}.status", coverage[key]["status"], "MATCH")
for key in expected_residuals:
    require(f"coverage.{key}.status", coverage[key]["status"], "MISMATCH")
require("known diffs", metadata["known_diffs"], [])
residuals = metadata["residuals"]
require("residual count", len(residuals), 1)
require("residual id", residuals[0]["todo_id"], "JUMPTABLE-PIPELINE-0001")
require("residual status", residuals[0]["status"], "MISMATCH")
require("coverage/residual union", coverage_residual_ids, {residuals[0]["todo_id"]})
if not residuals[0].get("detail") or not residuals[0].get("branches"):
    raise SystemExit("residual detail/branches must be non-empty")
PY

git -C "$ghidra_root" archive --format=tar \
  --output="$oracle_tmp/ghidra-cpp.tar" "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp
mkdir -p "$oracle_tmp/source"
tar -xf "$oracle_tmp/ghidra-cpp.tar" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"
mkdir -p "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
ln -s "$oracle_cpp" "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
nice -n 10 make --silent -C "$oracle_cpp" -j "$jobs" \
  CXX="g++ -std=c++11" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/jt_thunk_classify_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/libdecomp.a" \
  -lz -o "$oracle_tmp/jt_thunk_classify_1204_cpp"

(
  cd "$snapshot_root"
  flock /tmp/rugra-cargo-build.lock -c \
    'CARGO_TARGET_DIR=/tmp/rugra-target-jt-thunk cargo build --offline --locked --quiet --lib'
)
native_archive=$(find /tmp/rugra-target-jt-thunk/debug/build \
  -path '*/out/librugra_sleigh.a' -printf '%T@ %p\n' | \
  sort -nr | awk 'NR == 1 { sub(/^[^ ]+ /, ""); print }')
if [[ ! -f "$native_archive" ]]; then
  echo "Rugra build did not produce librugra_sleigh.a" >&2
  exit 1
fi
rustc --edition=2021 -O \
  -L "dependency=/tmp/rugra-target-jt-thunk/debug/deps" \
  -L "native=$(dirname "$native_archive")" \
  --extern "rugra=/tmp/rugra-target-jt-thunk/debug/librugra.rlib" \
  -l static=rugra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$snapshot_root/tests/oracle/jt_thunk_classify_1204.rs" \
  -o "$oracle_tmp/jt_thunk_classify_1204_rust"

set +e
"$oracle_tmp/jt_thunk_classify_1204_cpp" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/jt_thunk_classify_1204_rust" \
  >"$oracle_tmp/rugra.stdout" 2>"$oracle_tmp/rugra.stderr"
rugra_status=$?
diff -u --label ghidra --label rugra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout" >"$oracle_tmp/raw.diff"
diff_status=$?
set -e

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" \
  "$oracle_tmp/ghidra.stderr" "$oracle_tmp/rugra.stdout" \
  "$oracle_tmp/rugra.stderr" "$oracle_tmp/raw.diff" \
  "$ghidra_status" "$rugra_status" "$diff_status" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
paths = {
    "ghidra_stdout_sha256": pathlib.Path(sys.argv[2]),
    "ghidra_stderr_sha256": pathlib.Path(sys.argv[3]),
    "rugra_stdout_sha256": pathlib.Path(sys.argv[4]),
    "rugra_stderr_sha256": pathlib.Path(sys.argv[5]),
    "raw_diff_sha256": pathlib.Path(sys.argv[6]),
}
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = metadata["expected_results"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: expected={expected} actual={actual}")
for key, actual in (
    ("ghidra_exit_code", int(sys.argv[7])),
    ("rugra_exit_code", int(sys.argv[8])),
    ("diff_exit_code", int(sys.argv[9])),
):
    expected = metadata["expected_results"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: expected={expected} actual={actual}")
PY

if [[ "$ghidra_status" -ne 0 || "$rugra_status" -ne 0 || "$diff_status" -ne 0 ]]; then
  cat "$oracle_tmp/ghidra.stderr" >&2
  cat "$oracle_tmp/rugra.stderr" >&2
  cat "$oracle_tmp/raw.diff" >&2
  exit 1
fi

echo "JT-THUNK-CLASSIFY-1204: projection MATCH (8/8 byte-identical); overall MISMATCH: JUMPTABLE-PIPELINE-0001"
