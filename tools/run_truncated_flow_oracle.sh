#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rugra_source_commit=4c4808d12dfabeecd7043c49da852adf9a10e68f
rugra_source_tree=71ed04342212855062188a1ed1dff27c1ebf4892
rugra_source_src_tree=004b20c8ed6da74cf6457a4386570bae4801bc78
rugra_source_funcdata_blob=9800c38b1c1bb37d9c2c28841151e0ad2bf9c148
rugra_source_flow_blob=c76bd681b78b55e7855769e5e6d438df8c8c4cc2
rugra_source_op_blob=1f8908d74c0e5b72e41a910e46313066d48ce919
rugra_source_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rugra_source_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rugra_source_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
spec_input_commit=87aaef2262c85f4e6ffba488881fa4c1c8c2930f
bfd_header_sha256=c8c9c20823ebd8d427d9f91dd642b82b263fca2245a8ef4eb34f0de0cde25702
bfd_library_sha256=f9ca64d035c483bbfac32ca550074c20398ae2f0bb84dd989059dadb9cea8a1e

ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/truncated_flow_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/truncated_flow_1204.cc"
rust_fixture="$repo_root/tests/oracle/truncated_flow_1204.rs"
funcdata_overlay="$repo_root/src/funcdata.rs"
flow_overlay="$repo_root/src/flow.rs"
op_overlay="$repo_root/src/op.rs"
funcdata_doc="$repo_root/docs/api/funcdata.md"
flow_doc="$repo_root/docs/api/flow.md"
op_doc="$repo_root/docs/api/op.md"
runner="$repo_root/tools/run_truncated_flow_oracle.sh"

oracle_tmp=$(mktemp -d /tmp/rugra-truncated-flow-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-truncated-flow-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$funcdata_overlay" "$flow_overlay" "$op_overlay" \
  "$funcdata_doc" "$flow_doc" "$op_doc" "$runner"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_language_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Processors/x86/data/languages")
actual_makefile_blob=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_language_tree" != "$oracle_language_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp \
    Ghidra/Processors/x86/data/languages; then
  echo "locked Ghidra decompiler/x86 source is dirty" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --cached --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp \
    Ghidra/Processors/x86/data/languages; then
  echo "locked Ghidra decompiler/x86 source has staged changes" >&2
  exit 1
fi

for binding in \
  "$rugra_source_commit^{commit}:$rugra_source_commit" \
  "$rugra_source_commit^{tree}:$rugra_source_tree" \
  "$rugra_source_commit:src:$rugra_source_src_tree" \
  "$rugra_source_commit:src/funcdata.rs:$rugra_source_funcdata_blob" \
  "$rugra_source_commit:src/flow.rs:$rugra_source_flow_blob" \
  "$rugra_source_commit:src/op.rs:$rugra_source_op_blob" \
  "$rugra_source_commit:Cargo.toml:$rugra_source_cargo_toml_blob" \
  "$rugra_source_commit:Cargo.lock:$rugra_source_cargo_lock_blob" \
  "$rugra_source_commit:build.rs:$rugra_source_build_rs_blob"; do
  expression=${binding%:*}
  expected=${binding##*:}
  actual=$(git -C "$repo_root" rev-parse "$expression")
  if [[ "$actual" != "$expected" ]]; then
    echo "pinned Rugra source identity mismatch: $expression" >&2
    exit 1
  fi
done

bfd_include=${RUGRA_BFD_INCLUDE:-}
if [[ -z "$bfd_include" ]]; then
  for candidate in /tmp/rugra-ghidra-bfd-2.38/usr/include /usr/include; do
    if [[ -f "$candidate/bfd.h" ]] && \
        [[ "$(sha256sum "$candidate/bfd.h" | awk '{print $1}')" == "$bfd_header_sha256" ]]; then
      bfd_include=$candidate
      break
    fi
  done
fi
bfd_library=${RUGRA_BFD_LIBRARY:-}
if [[ -z "$bfd_library" ]]; then
  for candidate in \
      /tmp/rugra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so \
      /usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so; do
    if [[ -f "$candidate" ]] && \
        [[ "$(sha256sum "$candidate" | awk '{print $1}')" == "$bfd_library_sha256" ]]; then
      bfd_library=$candidate
      break
    fi
  done
fi
if [[ -z "$bfd_include" || ! -f "$bfd_include/bfd.h" || \
      -z "$bfd_library" || ! -f "$bfd_library" ]]; then
  echo "binutils 2.38 BFD development files are unavailable" >&2
  exit 1
fi
if [[ "$(sha256sum "$bfd_include/bfd.h" | awk '{print $1}')" != "$bfd_header_sha256" || \
      "$(sha256sum "$bfd_library" | awk '{print $1}')" != "$bfd_library_sha256" ]]; then
  echo "BFD input fingerprint mismatch" >&2
  exit 1
fi

snapshot_root="$oracle_tmp/workspace"
mkdir -p "$snapshot_root" "$snapshot_root/tests/oracle" \
  "$snapshot_root/tools" "$snapshot_root/sleigh_specs"
git -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rugra-source.tar" "$rugra_source_commit" \
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  src sleigh_shim
tar -xf "$oracle_tmp/rugra-source.tar" -C "$snapshot_root"
cp "$funcdata_overlay" "$snapshot_root/src/funcdata.rs"
cp "$flow_overlay" "$snapshot_root/src/flow.rs"
cp "$op_overlay" "$snapshot_root/src/op.rs"
cp "$cpp_fixture" "$snapshot_root/tests/oracle/truncated_flow_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/truncated_flow_1204.rs"
cp "$metadata" "$snapshot_root/tests/oracle/truncated_flow_1204.metadata.json"
cp "$runner" "$snapshot_root/tools/run_truncated_flow_oracle.sh"
for asset in sleigh_specs/x86-64.sla sleigh_specs/x86-64.pspec \
  sleigh_specs/x86-64-gcc.cspec sleigh_specs/x86.ldefs; do
  git -C "$repo_root" cat-file blob "$spec_input_commit:$asset" \
    >"$snapshot_root/$asset"
done

runner_sha=$(sha256sum "$runner" | awk '{print $1}')
python3 -I -S - "$repo_root" "$snapshot_root" "$metadata" "$cpp_fixture" \
  "$rust_fixture" "$funcdata_overlay" "$flow_overlay" "$op_overlay" \
  "$funcdata_doc" "$flow_doc" "$op_doc" "$runner_sha" \
  "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" "$oracle_language_tree" \
  "$oracle_makefile_blob" "$rugra_source_commit" "$rugra_source_tree" \
  "$rugra_source_src_tree" "$rugra_source_funcdata_blob" \
  "$rugra_source_flow_blob" "$rugra_source_op_blob" \
  "$rugra_source_cargo_toml_blob" "$rugra_source_cargo_lock_blob" \
  "$rugra_source_build_rs_blob" "$spec_input_commit" \
  "$bfd_include/bfd.h" "$bfd_library" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    repo_raw, snapshot_raw, metadata_raw, cpp_raw, rust_raw,
    funcdata_raw, flow_raw, op_raw, funcdata_doc_raw, flow_doc_raw,
    op_doc_raw, runner_sha, oracle_commit, oracle_tag, cpp_tree,
    language_tree, makefile_blob, source_commit, source_tree,
    source_src_tree, source_funcdata_blob, source_flow_blob, source_op_blob,
    source_cargo_toml_blob, source_cargo_lock_blob, source_build_rs_blob,
    spec_input_commit, bfd_header_raw, bfd_library_raw,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()
snapshot = pathlib.Path(snapshot_raw)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(
            f"{label} mismatch: expected={expected!r} actual={actual!r}"
        )

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
require("schema", metadata["schema_version"], 2)
require("fixture", metadata["fixture_id"], "FLOW-TRUNCATED-0001")
if not isinstance(metadata.get("status_note"), str) or not metadata["status_note"].strip():
    raise SystemExit("status_note must be a non-empty string")
decisive = metadata.get("decisive_semantics")
expected_decisive = {
    "reference_output_parameters",
    "loop_bounds_traversal_order",
    "counter_accumulator_lifecycle",
    "sorting_comparison_keys",
}
if not isinstance(decisive, dict):
    raise SystemExit("decisive_semantics must be an object")
require("decisive semantic classes", set(decisive), expected_decisive)
for key, value in decisive.items():
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"decisive_semantics.{key} must be non-empty")

oracle = metadata["oracle"]
for label, actual, expected in (
    ("oracle tag", oracle["tag"], oracle_tag),
    ("oracle commit", oracle["commit"], oracle_commit),
    ("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree),
    ("oracle language tree", oracle["x86_language_tree"], language_tree),
    ("oracle Makefile", oracle["decompiler_makefile_blob"], makefile_blob),
):
    require(label, actual, expected)
require("architecture", metadata["architecture"], "x86:LE:64:default")
require("compiler id", metadata["compiler_spec"]["id"], "gcc")

source = metadata["rugra_source"]
for label, actual, expected in (
    ("source commit", source["base_commit"], source_commit),
    ("source tree", source["base_tree"], source_tree),
    ("source src tree", source["base_src_tree"], source_src_tree),
    ("source funcdata blob", source["base_funcdata_blob"], source_funcdata_blob),
    ("source flow blob", source["base_flow_blob"], source_flow_blob),
    ("source op blob", source["base_op_blob"], source_op_blob),
    ("Cargo.toml blob", source["cargo_toml_blob"], source_cargo_toml_blob),
    ("Cargo.lock blob", source["cargo_lock_blob"], source_cargo_lock_blob),
    ("build.rs blob", source["build_rs_blob"], source_build_rs_blob),
):
    require(label, actual, expected)

comparand = metadata["comparand"]
comparands = {
    "cpp_fixture_sha256": pathlib.Path(cpp_raw),
    "rust_fixture_sha256": pathlib.Path(rust_raw),
    "funcdata_overlay_sha256": pathlib.Path(funcdata_raw),
    "flow_overlay_sha256": pathlib.Path(flow_raw),
    "op_overlay_sha256": pathlib.Path(op_raw),
    "funcdata_doc_sha256": pathlib.Path(funcdata_doc_raw),
    "flow_doc_sha256": pathlib.Path(flow_doc_raw),
    "op_doc_sha256": pathlib.Path(op_doc_raw),
}
for key, path in comparands.items():
    require(key, sha(path.read_bytes()), comparand[key])
require("runner sha", runner_sha, comparand["runner_sha256"])
overlays = {entry["path"]: entry for entry in source["overlays"]}
require("overlay paths", set(overlays), {"src/funcdata.rs", "src/flow.rs", "src/op.rs"})
for relative, path in (
    ("src/funcdata.rs", pathlib.Path(funcdata_raw)),
    ("src/flow.rs", pathlib.Path(flow_raw)),
    ("src/op.rs", pathlib.Path(op_raw)),
):
    require(f"{relative} overlay sha", sha(path.read_bytes()), overlays[relative]["sha256"])

assets = metadata["assets"]
for key, relative in (
    ("sla", "sleigh_specs/x86-64.sla"),
    ("processor_spec", "sleigh_specs/x86-64.pspec"),
    ("compiler_spec", "sleigh_specs/x86-64-gcc.cspec"),
    ("language_definitions", "sleigh_specs/x86.ldefs"),
):
    record = assets[key]
    require(f"{key} path", record["path"], relative)
    require(f"{key} source commit", record["source_repository_commit"], spec_input_commit)
    oid = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", f"{spec_input_commit}:{relative}"],
        text=True,
    ).strip()
    require(f"{key} blob", oid, record["git_blob_oid"])
    data = (snapshot / relative).read_bytes()
    require(f"{key} sha", sha(data), record["sha256"])
    require(f"{key} size", len(data), record["size"])
require("BFD header metadata", assets["bfd"]["header_sha256"], sha(pathlib.Path(bfd_header_raw).read_bytes()))
require("BFD library metadata", assets["bfd"]["library_sha256"], sha(pathlib.Path(bfd_library_raw).read_bytes()))

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "construction": manifest["construction"],
    "cases": manifest["cases"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("input manifest sha", sha(canonical), manifest["sha256"])

require("projection", metadata["projection_status"], "MATCH")
require("overall", metadata["overall_status"], "MISMATCH")
expected_statuses = {
    "raw_op_seqnum_list_order_and_uniqid": "MATCH",
    "callspec_fspec_rebind_projection": "MATCH",
    "callspec_complete_identity_and_fields": "MISMATCH",
    "jumptable_partial_copy_skip_and_identity": "MATCH",
    "splitbasic_per_op_lifecycle_and_order": "MATCH",
    "nonempty_precondition_exception": "MATCH",
    "missing_jumptable_exception_and_partial_mutation": "MATCH",
    "clone_varnode_type_and_complete_flag_mask": "UNTESTED",
    "flowinfo_private_state_and_branch_stubs": "UNTESTED",
    "truncated_injection_branch": "UNTESTED",
    "splitbasic_missing_entry_error": "MATCH",
    "insert_after_dead_invalid_state": "MISMATCH",
}
coverage = metadata.get("coverage")
if not isinstance(coverage, dict):
    raise SystemExit("coverage must be an object")
require("coverage keys", set(coverage), set(expected_statuses))
valid_statuses = {"MATCH", "MISMATCH", "NO_ORACLE", "UNTESTED"}
coverage_residual_ids = set()
for key, expected_status in expected_statuses.items():
    record = coverage[key]
    require(f"coverage.{key} fields", set(record), {"status", "covers", "residual_todo_ids"})
    status = record["status"]
    if status not in valid_statuses:
        raise SystemExit(f"coverage.{key}.status is invalid: {status!r}")
    require(f"coverage.{key}.status", status, expected_status)
    if not isinstance(record["covers"], str) or not record["covers"].strip():
        raise SystemExit(f"coverage.{key}.covers must be non-empty")
    residual_ids = record["residual_todo_ids"]
    if not isinstance(residual_ids, list) or any(
        not isinstance(item, str) or not item for item in residual_ids
    ):
        raise SystemExit(f"coverage.{key}.residual_todo_ids is invalid")
    if len(residual_ids) != len(set(residual_ids)):
        raise SystemExit(f"coverage.{key}.residual_todo_ids contains duplicates")
    if status == "MATCH":
        require(f"coverage.{key} MATCH residuals", residual_ids, [])
    elif not residual_ids:
        raise SystemExit(f"coverage.{key} non-MATCH status lacks a residual TODO")
    coverage_residual_ids.update(residual_ids)
top_residual_ids = metadata.get("residual_todo_ids")
if not isinstance(top_residual_ids, list) or len(top_residual_ids) != len(set(top_residual_ids)):
    raise SystemExit("top-level residual_todo_ids is invalid")
require("coverage/top-level residual union", coverage_residual_ids, set(top_residual_ids))

observations = metadata.get("out_of_scope_observations")
if not isinstance(observations, list):
    raise SystemExit("out_of_scope_observations must be a list")
for observation in observations:
    require(f"observation {observation.get('id')!r} fields", set(observation), {"id", "note"})
    if not observation["id"] or not observation["note"]:
        raise SystemExit("out_of_scope_observations entries must be non-empty")
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
if ! make --silent -C "$oracle_cpp" -j "$jobs" CXX="g++ -std=c++11" \
    EXTRA= libdecomp.a >"$oracle_tmp/make.stdout" 2>"$oracle_tmp/make.stderr"; then
  cat "$oracle_tmp/make.stdout" "$oracle_tmp/make.stderr" >&2
  exit 1
fi
g++ -std=c++11 -O0 -fno-pie -no-pie -Wl,--build-id=none \
  -I"$bfd_include" -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/truncated_flow_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$bfd_library" -lz -o "$oracle_tmp/truncated_flow_cpp"

if ! flock /tmp/rugra-cargo-build.lock -c \
    "CARGO_TARGET_DIR=/tmp/rugra-target-flow-writer cargo build --offline --locked --quiet --manifest-path '$snapshot_root/Cargo.toml' --lib" \
    >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"; then
  cat "$oracle_tmp/cargo.stdout" "$oracle_tmp/cargo.stderr" >&2
  exit 1
fi
rustc --edition=2021 -C opt-level=0 \
  "$snapshot_root/tests/oracle/truncated_flow_1204.rs" \
  --extern rugra=/tmp/rugra-target-flow-writer/debug/librugra.rlib \
  -L dependency=/tmp/rugra-target-flow-writer/debug/deps \
  -o "$oracle_tmp/truncated_flow_rust"

symbol_args=()
for symbol in truncated_flow_source truncated_flow_target truncated_flow_callee \
  truncated_flow_nonempty truncated_flow_error_source truncated_flow_error_target \
  truncated_flow_entry_source truncated_flow_entry_target; do
  address=$(nm -n --defined-only "$oracle_tmp/truncated_flow_cpp" | \
    awk -v name="$symbol" '$3 == name && value == "" { value=$1 } END { print value }')
  if [[ -z "$address" ]]; then
    echo "failed to resolve fixture symbol: $symbol" >&2
    exit 1
  fi
  symbol_args+=("$address")
done

bfd_runtime=$(dirname "$bfd_library")
if [[ -n ${LD_LIBRARY_PATH:-} ]]; then
  bfd_runtime="$bfd_runtime:$LD_LIBRARY_PATH"
fi
set +e
LD_LIBRARY_PATH="$bfd_runtime" "$oracle_tmp/truncated_flow_cpp" \
  "$snapshot_root/sleigh_specs" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/truncated_flow_rust" "${symbol_args[@]}" \
  >"$oracle_tmp/rugra.stdout" 2>"$oracle_tmp/rugra.stderr"
rugra_status=$?
diff -u --label ghidra --label rugra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout" \
  >"$oracle_tmp/raw.diff"
diff_status=$?
set -e

objcopy --dump-section .text="$oracle_tmp/fixture.text" \
  "$oracle_tmp/truncated_flow_cpp"
python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" \
  "$oracle_tmp/ghidra.stderr" "$oracle_tmp/rugra.stdout" \
  "$oracle_tmp/rugra.stderr" "$oracle_tmp/raw.diff" \
  "$oracle_tmp/fixture.text" "$ghidra_status" "$rugra_status" \
  "$diff_status" <<'PY'
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
    ("ghidra_exit_code", int(sys.argv[8])),
    ("rugra_exit_code", int(sys.argv[9])),
    ("diff_exit_code", int(sys.argv[10])),
):
    expected = metadata["expected_results"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: expected={expected} actual={actual}")
fixture_text = hashlib.sha256(pathlib.Path(sys.argv[7]).read_bytes()).hexdigest()
expected_text = metadata["machine_input_sha256"]["fixture_text"]
if fixture_text != expected_text:
    raise SystemExit(
        f"fixture text mismatch: expected={expected_text} actual={fixture_text}"
    )
if paths["ghidra_stderr_sha256"].stat().st_size != 0:
    raise SystemExit("unexpected Ghidra stderr output")
if paths["rugra_stderr_sha256"].stat().st_size != 0:
    raise SystemExit("unexpected Rugra stderr output")
records = paths["ghidra_stdout_sha256"].read_text(encoding="utf-8").splitlines()
if len(records) != 16:
    raise SystemExit(f"unexpected observation line count: {len(records)}")
if records[0] != "case=success":
    raise SystemExit("success case is not first")
if not records[12].startswith("case=nonempty error=Trying to do truncated flow"):
    raise SystemExit("nonempty exception observation missing or reordered")
if not records[13].startswith("case=missing_jumptable error=Could not trace jumptable"):
    raise SystemExit("missing-jumptable exception observation missing or reordered")
if not records[14].startswith("case=missing_entry before_all=0 before_dead=0"):
    raise SystemExit("missing-entry pre-state observation missing or reordered")
if not records[15].startswith("case=missing_entry error=First op not marked as entry point"):
    raise SystemExit("missing-entry exception observation missing or reordered")
print(
    "truncated_flow_1204 oracle gate: covered projection MATCH; "
    "overall MISMATCH (registered residuals)"
)
PY
