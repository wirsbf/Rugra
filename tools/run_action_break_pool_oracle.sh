#!/usr/bin/env bash
set -euo pipefail

# ACTION-EXECUTOR-BREAKPOOL-0001: locked 12.0.4 differential runner.
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rugra_base_commit=dd5f992a2bcd713b7adcfc9687b70a6b198cbbb9
rugra_base_tree=24fe255151edd23f9a433c6d5456a6dbf39d7895
rugra_base_src_tree=004b20c8ed6da74cf6457a4386570bae4801bc78
rugra_base_action_blob=4ab1068cde61e05570d0941243b5e89ab098934f
rugra_base_sleigh_tree=c7729d9d1554dc62c486bcd7d58fdbf44bebb97d
rugra_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rugra_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rugra_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5

ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/action_break_pool_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/action_break_pool_1204.cc"
rust_fixture="$repo_root/tests/oracle/action_break_pool_1204.rs"
action_overlay="$repo_root/src/action.rs"
runner="$repo_root/tools/run_action_break_pool_oracle.sh"

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$action_overlay" "$runner"; do
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
  "$rugra_base_commit:src/action.rs:$rugra_base_action_blob" \
  "$rugra_base_commit:sleigh_shim:$rugra_base_sleigh_tree" \
  "$rugra_base_commit:Cargo.toml:$rugra_cargo_toml_blob" \
  "$rugra_base_commit:Cargo.lock:$rugra_cargo_lock_blob" \
  "$rugra_base_commit:build.rs:$rugra_build_rs_blob"; do
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
  "$action_overlay" "$runner_sha" "$oracle_commit" "$oracle_tag" \
  "$oracle_cpp_tree" "$oracle_makefile_blob" "$rugra_base_commit" \
  "$rugra_base_tree" "$rugra_base_src_tree" "$rugra_base_action_blob" \
  "$rugra_base_sleigh_tree" "$rugra_cargo_toml_blob" \
  "$rugra_cargo_lock_blob" "$rugra_build_rs_blob" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    metadata_raw, cpp_raw, rust_raw, action_raw, runner_sha,
    oracle_commit, oracle_tag, cpp_tree, makefile_blob,
    base_commit, base_tree, base_src_tree, base_action_blob, base_sleigh_tree,
    cargo_toml_blob, cargo_lock_blob, build_rs_blob,
) = sys.argv[1:]

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

data = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
require("schema", data["schema_version"], 2)
require("fixture", data["fixture_id"], "ACTION-EXECUTOR-BREAKPOOL-0001")
require("overall", data["overall_status"], "MISMATCH")
oracle = data["oracle"]
for label, actual, expected in (
    ("oracle commit", oracle["commit"], oracle_commit),
    ("oracle tag", oracle["tag"], oracle_tag),
    ("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree),
    ("oracle Makefile", oracle["decompiler_makefile_blob"], makefile_blob),
):
    require(label, actual, expected)
source = data["rugra_source"]
for label, actual, expected in (
    ("base commit", source["base_commit"], base_commit),
    ("base tree", source["base_tree"], base_tree),
    ("base src tree", source["base_src_tree"], base_src_tree),
    ("base action blob", source["base_action_blob"], base_action_blob),
    ("base sleigh tree", source["base_sleigh_tree"], base_sleigh_tree),
    ("Cargo.toml blob", source["cargo_toml_blob"], cargo_toml_blob),
    ("Cargo.lock blob", source["cargo_lock_blob"], cargo_lock_blob),
    ("build.rs blob", source["build_rs_blob"], build_rs_blob),
):
    require(label, actual, expected)
comparand = data["comparand"]
for key, path in (
    ("cpp_fixture_sha256", cpp_raw),
    ("rust_fixture_sha256", rust_raw),
    ("action_overlay_sha256", action_raw),
):
    require(key, sha(path), comparand[key])
require("runner sha", runner_sha, comparand["runner_sha256"])
require(
    "decisive classes", set(data["decisive_semantics"]),
    {"reference_output_parameters", "loop_bounds_traversal_order",
     "counter_accumulator_lifecycle", "sorting_comparison_keys"},
)
expected_coverage = {
    "action_break_warning_resume": ("MATCH", []),
    "group_cursor": ("MATCH", []),
    "pool_live_resume_dead": ("MATCH", []),
    "lookup_ambiguity": ("MATCH", []),
    "virtual_reset_dispatch":
        ("MISMATCH", ["PIPE-BREAK-0001", "PIPE-POOL-0001"]),
    "restart_group_inherited_breakpoint":
        ("MISMATCH", ["PIPE-BREAK-0001", "PIPE-RESTART-0001"]),
    "derived_root_clone_filtering": ("MISMATCH", ["PIPE-POOL-0001"]),
    "opbank_creation_lifecycle": ("MISMATCH", ["OPBANK-0001"]),
}
require("coverage keys", set(data["coverage"]), set(expected_coverage))
for name, (status, residuals) in expected_coverage.items():
    record = data["coverage"][name]
    require(f"coverage {name}", record["status"], status)
    require(f"coverage {name} residuals", record["residual_todo_ids"], residuals)
require(
    "top-level residuals",
    data["residual_todo_ids"],
    ["PIPE-BREAK-0001", "PIPE-POOL-0001", "PIPE-RESTART-0001", "OPBANK-0001"],
)
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

oracle_tmp=$(mktemp -d /tmp/rugra-action-break-pool-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-action-break-pool-1204.??????) rm -rf -- "$oracle_tmp" ;;
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
cp "$action_overlay" "$snapshot/src/action.rs"
cp "$rust_fixture" "$snapshot/tests/oracle/action_break_pool_1204.rs"

git -C "$ghidra_root" archive --format=tar --output="$oracle_tmp/ghidra.tar" \
  "$oracle_commit" Ghidra/Features/Decompiler/src/decompile/cpp
mkdir -p "$oracle_tmp/oracle"
tar -xf "$oracle_tmp/ghidra.tar" -C "$oracle_tmp/oracle"
oracle_cpp="$oracle_tmp/oracle/Ghidra/Features/Decompiler/src/decompile/cpp"
ln -s "$oracle_cpp" \
  "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

# Add observation-only accessors to the temporary archive. No algorithm body
# and no repository oracle source is changed.
python3 -I -S - "$oracle_cpp/action.hh" "$metadata" <<'PY'
import hashlib
import json
import pathlib
import sys

header = pathlib.Path(sys.argv[1])
metadata = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
text = header.read_text(encoding="utf-8")
anchor = (
    "  int4 processOp(PcodeOp *op,Funcdata &data);\t\t"
    "///< Apply the next possible Rule to a PcodeOp\npublic:\n"
)
replacement = anchor + (
    "  const PcodeOpTree::const_iterator &fixtureGetOpState(void) const "
    "{ return op_state; }\n"
    "  int4 fixtureGetRuleIndex(void) const { return rule_index; }\n"
)
if text.count(anchor) != 1:
    raise SystemExit("ActionPool instrumentation anchor drifted")
header.write_text(text.replace(anchor, replacement), encoding="utf-8")
actual = hashlib.sha256(header.read_bytes()).hexdigest()
expected = metadata["comparand"]["ghidra_instrumented_action_hh_sha256"]
if actual != expected:
    raise SystemExit(f"instrumented action.hh mismatch: expected={expected} actual={actual}")
PY

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$oracle_cpp" -j "$jobs" \
  CXX="g++ -std=c++11" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$oracle_cpp" "$cpp_fixture" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" \
  -Wl,--whole-archive "$oracle_cpp/libdecomp.a" -Wl,--no-whole-archive -lz \
  -o "$oracle_tmp/action_break_pool_cpp"

flock /tmp/rugra-cargo-build.lock -c \
  "CARGO_TARGET_DIR=/tmp/rugra-target-action-break-pool cargo build --offline --locked --quiet --manifest-path '$snapshot/Cargo.toml' --lib"
rustc --edition=2021 -O \
  -L dependency=/tmp/rugra-target-action-break-pool/debug/deps \
  --extern rugra=/tmp/rugra-target-action-break-pool/debug/librugra.rlib \
  "$snapshot/tests/oracle/action_break_pool_1204.rs" \
  -o "$oracle_tmp/action_break_pool_rust"

set +e
"$oracle_tmp/action_break_pool_cpp" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/action_break_pool_rust" \
  >"$oracle_tmp/rugra.stdout" 2>"$oracle_tmp/rugra.stderr"
rugra_status=$?
cmp -s "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout"
stdout_cmp=$?
cmp -s "$oracle_tmp/ghidra.stderr" "$oracle_tmp/rugra.stderr"
stderr_cmp=$?
set -e

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" \
  "$oracle_tmp/ghidra.stderr" "$oracle_tmp/rugra.stdout" \
  "$oracle_tmp/rugra.stderr" "$ghidra_status" "$rugra_status" \
  "$stdout_cmp" "$stderr_cmp" <<'PY'
import hashlib
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
paths = {
    "ghidra_stdout_sha256": pathlib.Path(sys.argv[2]),
    "ghidra_stderr_sha256": pathlib.Path(sys.argv[3]),
    "rugra_stdout_sha256": pathlib.Path(sys.argv[4]),
    "rugra_stderr_sha256": pathlib.Path(sys.argv[5]),
}
expected = data["expected_results"]
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected[key]:
        raise SystemExit(f"{key} mismatch: expected={expected[key]} actual={actual}")
for key, actual in (
    ("ghidra_exit_code", int(sys.argv[6])),
    ("rugra_exit_code", int(sys.argv[7])),
    ("stdout_cmp_exit_code", int(sys.argv[8])),
    ("stderr_cmp_exit_code", int(sys.argv[9])),
):
    if actual != expected[key]:
        raise SystemExit(f"{key} mismatch: expected={expected[key]} actual={actual}")
lines = paths["ghidra_stdout_sha256"].read_text(encoding="utf-8").splitlines()
if len(lines) != 22:
    raise SystemExit(f"fixture line count drifted: {len(lines)}")
if not any("event=rule_break|return=-1|cursor=4096@1|rule_index=2" in line
           for line in lines):
    raise SystemExit("retained pool cursor/index observation is missing")
if not any("event=fresh_pass" in line and "mutate@2304" in line for line in lines):
    raise SystemExit("before-cursor insertion was not observed on the fresh pass")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'action_break_pool_1204: covered_projection=MATCH overall=MISMATCH stdout_sha256=%s stderr_sha256=%s\n' \
  "$(sha256sum "$oracle_tmp/ghidra.stdout" | awk '{print $1}')" \
  "$(sha256sum "$oracle_tmp/ghidra.stderr" | awk '{print $1}')"
