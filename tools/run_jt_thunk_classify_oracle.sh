#!/usr/bin/env bash
# JUMPTABLE-THUNK-CLASSIFY-0001 — locked Ghidra 12.0.4 differential gate.
# Comparands run from a read-only source snapshot and a fresh run-local Cargo
# target. One focused Cargo invocation also emits the exact rlib under test.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
oracle_cpp_archive_sha=af395e99858451acebc2746c3bab6a9142454ab91ce1bf8d2ddbe257986b2a0e
rugra_source_commit=8d3a5561f259420d00ec3ecb54e766b206f89331
rugra_source_tree=c8ee095912b9d56b80c38d72f0bea447ebc998c4
rugra_source_src_tree=004b20c8ed6da74cf6457a4386570bae4801bc78
rugra_jumptable_blob=64c824f03f41040696c9c6242f05e83a23e1ef55
rugra_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rugra_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rugra_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
rugra_base_archive_sha=b310d8a9012a785b040a83357a5645e880d09c99f3a09baa40d6df54f6ddc20f

cxx_path=/usr/bin/g++
cxx_version='g++ (GCC) 16.2.1 20260810'
cxx_sha=f04191f6a7b2cd7d9a62e1745872b8a6088791e5af6955488c69c9b2c4668bc9
libstdcpp_path=/usr/lib/libstdc++.so.6.0.36
libstdcpp_sha=f5fc7380f2ae46fa4053a64be04e7b98109f1066a4bbfff3c37042488aa0be0e
stl_algo_path=/usr/include/c++/16/bits/stl_algo.h
stl_algo_sha=b1b7526cce2cbc6e734eaec98efbe30daaa8029f489bffbd9f0b5adb266b2241
stl_heap_path=/usr/include/c++/16/bits/stl_heap.h
stl_heap_sha=2f046a6e3441ae683e56fbce2584d8c5a0703b01d95f80b11cd7ae75ecea76f5
stl_algobase_path=/usr/include/c++/16/bits/stl_algobase.h
stl_algobase_sha=d4526f229676944d321e4884cd854b6fab142278676e662fc776389d50c55a49
predefined_ops_path=/usr/include/c++/16/bits/predefined_ops.h
predefined_ops_sha=420506532d36ef29350163fa55318ea5a573875857660cf0b41e782ae48b964c
rustc_version='rustc 1.97.1 (8bab26f4f 2026-07-14) (Arch Linux rust 1:1.97.1-1)'
cargo_version='cargo 1.97.1 (c980f4866 2026-06-30) (Arch Linux rust 1:1.97.1-1)'

ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/jt_thunk_classify_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/jt_thunk_classify_1204.cc"
rust_fixture="$repo_root/tests/oracle/jt_thunk_classify_1204.rs"
jumptable_overlay="$repo_root/src/jumptable.rs"
runner="$repo_root/tools/run_jt_thunk_classify_oracle.sh"

oracle_tmp=$(mktemp -d /tmp/rugra-jt-thunk-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-jt-thunk-1204.??????)
      chmod -R u+w "$oracle_tmp" 2>/dev/null || true
      rm -rf -- "$oracle_tmp"
      ;;
    *) printf 'refusing unsafe cleanup target: %s\n' "$oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$jumptable_overlay" "$runner"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    printf 'required input is not a regular non-symlink file: %s\n' "$required" >&2
    exit 1
  fi
done

capture_repo_state() {
  printf '%s\n' '[index-diff]'
  git -C "$repo_root" diff --cached --binary
  printf '%s\n' '[worktree-diff]'
  git -C "$repo_root" diff --binary
  printf '%s\n' '[porcelain-v2]'
  git -C "$repo_root" status --porcelain=v2 --untracked-files=all
  printf '%s\n' '[runtime-input-sha256]'
  sha256sum "$metadata" "$cpp_fixture" "$rust_fixture" "$jumptable_overlay" "$runner"
}

capture_toolchain_state() {
  "$cxx_path" --version | sed -n '1p'
  rustc --version
  cargo --version
  sha256sum "$cxx_path" "$libstdcpp_path" "$stl_algo_path" "$stl_heap_path" \
    "$stl_algobase_path" "$predefined_ops_path"
}

capture_repo_state >"$oracle_tmp/repo.before"
capture_toolchain_state >"$oracle_tmp/toolchain.before"

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  printf '%s\n' 'locked Ghidra oracle identity mismatch' >&2
  exit 1
fi
git -C "$ghidra_root" status --porcelain=v2 --untracked-files=all -- \
  Ghidra/Features/Decompiler/src/decompile/cpp >"$oracle_tmp/ghidra.before"
if [[ -s "$oracle_tmp/ghidra.before" ]]; then
  printf '%s\n' 'locked Ghidra decompiler source is dirty' >&2
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
    printf 'pinned Rugra source identity mismatch: %s\n' "$expression" >&2
    exit 1
  fi
done

for file_hash in \
  "$cxx_path:$cxx_sha" \
  "$libstdcpp_path:$libstdcpp_sha" \
  "$stl_algo_path:$stl_algo_sha" \
  "$stl_heap_path:$stl_heap_sha" \
  "$stl_algobase_path:$stl_algobase_sha" \
  "$predefined_ops_path:$predefined_ops_sha"; do
  path=${file_hash%:*}
  expected=${file_hash##*:}
  actual=$(sha256sum "$path" | awk '{print $1}')
  if [[ "$actual" != "$expected" ]]; then
    printf 'oracle toolchain file mismatch: %s\n' "$path" >&2
    exit 1
  fi
done
if [[ "$("$cxx_path" --version | sed -n '1p')" != "$cxx_version" || \
      "$(rustc --version)" != "$rustc_version" || \
      "$(cargo --version)" != "$cargo_version" || \
      "$(readlink -f "$("$cxx_path" -print-file-name=libstdc++.so)")" != "$libstdcpp_path" ]]; then
  printf '%s\n' 'oracle toolchain version/path mismatch' >&2
  exit 1
fi

runner_sha=$(sha256sum "$runner" | awk '{print $1}')
python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$jumptable_overlay" "$runner_sha" "$oracle_commit" "$oracle_tag" \
  "$oracle_cpp_tree" "$oracle_makefile_blob" "$oracle_cpp_archive_sha" \
  "$rugra_source_commit" "$rugra_source_tree" "$rugra_source_src_tree" \
  "$rugra_jumptable_blob" "$rugra_cargo_toml_blob" "$rugra_cargo_lock_blob" \
  "$rugra_build_rs_blob" "$rugra_base_archive_sha" "$cxx_version" "$cxx_sha" \
  "$libstdcpp_path" "$libstdcpp_sha" "$stl_algo_sha" "$stl_heap_sha" \
  "$stl_algobase_sha" "$predefined_ops_sha" "$rustc_version" "$cargo_version" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    metadata_raw, cpp_raw, rust_raw, overlay_raw, runner_sha,
    oracle_commit, oracle_tag, cpp_tree, makefile_blob, oracle_archive_sha,
    source_commit, source_tree, source_src_tree, jumptable_blob,
    cargo_toml_blob, cargo_lock_blob, build_rs_blob, base_archive_sha,
    cxx_version, cxx_sha, libstdcpp_path, libstdcpp_sha, stl_algo_sha,
    stl_heap_sha, stl_algobase_sha, predefined_ops_sha, rustc_version,
    cargo_version,
) = sys.argv[1:]

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
require("schema", metadata["schema_version"], 3)
require("fixture", metadata["fixture_id"], "JT-THUNK-CLASSIFY-1204")
if not metadata.get("status_note"):
    raise SystemExit("status_note must be non-empty")
require(
    "decisive semantics", set(metadata["decisive_semantics"]),
    {
        "reference_output_parameters", "loop_bounds_traversal_order",
        "counter_accumulator_lifecycle", "sorting_comparison_keys",
    },
)
if any(not isinstance(value, str) or not value.strip()
       for value in metadata["decisive_semantics"].values()):
    raise SystemExit("each decisive semantic class must be non-empty")

oracle = metadata["oracle"]
for label, actual, expected in (
    ("oracle tag", oracle["tag"], oracle_tag),
    ("oracle commit", oracle["commit"], oracle_commit),
    ("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree),
    ("oracle Makefile", oracle["decompiler_makefile_blob"], makefile_blob),
    ("oracle archive", oracle["decompiler_cpp_archive_sha256"], oracle_archive_sha),
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
    ("base archive", source["base_archive_sha256"], base_archive_sha),
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

toolchain = metadata["oracle_toolchain"]
for label, actual, expected in (
    ("cxx version", toolchain["cxx_version"], cxx_version),
    ("cxx sha", toolchain["cxx_sha256"], cxx_sha),
    ("libstdc++ path", toolchain["libstdcxx_path"], libstdcpp_path),
    ("libstdc++ sha", toolchain["libstdcxx_sha256"], libstdcpp_sha),
    ("stl_algo sha", toolchain["headers"]["stl_algo.h"], stl_algo_sha),
    ("stl_heap sha", toolchain["headers"]["stl_heap.h"], stl_heap_sha),
    ("stl_algobase sha", toolchain["headers"]["stl_algobase.h"], stl_algobase_sha),
    ("predefined_ops sha", toolchain["headers"]["predefined_ops.h"], predefined_ops_sha),
    ("rustc version", toolchain["rustc_version"], rustc_version),
    ("cargo version", toolchain["cargo_version"], cargo_version),
):
    require(label, actual, expected)

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "oracle_toolchain": toolchain,
    "cases": manifest["cases"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("manifest sha", sha(canonical), manifest["sha256"])
require("case count", len(manifest["cases"]), 24)
require("projection before this evidence run", metadata["projection_status"], "UNTESTED")
require("overall", metadata["overall_status"], "MISMATCH")
require("known diffs", metadata["known_diffs"], [])

valid_statuses = {"MATCH", "MISMATCH", "NO_ORACLE", "UNTESTED"}
coverage_residual_ids = set()
for key, record in metadata["coverage"].items():
    require(
        f"coverage.{key} fields", set(record),
        {"status", "covers", "residual_todo_ids"},
    )
    if record["status"] not in valid_statuses or not record["covers"]:
        raise SystemExit(f"invalid coverage record: {key}")
    if record["status"] in {"MATCH", "UNTESTED"}:
        require(f"coverage.{key} non-semantic residuals", record["residual_todo_ids"], [])
    elif not record["residual_todo_ids"]:
        raise SystemExit(f"coverage.{key} non-MATCH lacks residual id")
    coverage_residual_ids.update(record["residual_todo_ids"])

residuals = metadata["residuals"]
require(
    "residual ids", {record["todo_id"] for record in residuals},
    {"JUMPTABLE-PIPELINE-0001", "JUMPTABLE-SORT-TOOLCHAIN-0001"},
)
if any(record["status"] != "MISMATCH" or not record.get("detail")
       or not record.get("branches") for record in residuals):
    raise SystemExit("each residual needs MISMATCH/detail/branches")
require(
    "coverage/residual union", coverage_residual_ids,
    {"JUMPTABLE-PIPELINE-0001", "JUMPTABLE-SORT-TOOLCHAIN-0001"},
)
PY

base_archive="$oracle_tmp/rugra-source.tar"
git -C "$repo_root" archive --format=tar --output="$base_archive" \
  "$rugra_source_commit" Cargo.toml Cargo.lock build.rs README.md \
  benches/decompile_bench.rs tests/doc_sync.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  src sleigh_shim
if [[ "$(sha256sum "$base_archive" | awk '{print $1}')" != "$rugra_base_archive_sha" ]]; then
  printf '%s\n' 'pinned Rugra source archive mismatch' >&2
  exit 1
fi

oracle_archive="$oracle_tmp/ghidra-cpp.tar"
git -C "$ghidra_root" archive --format=tar --output="$oracle_archive" \
  "$oracle_commit" Ghidra/Features/Decompiler/src/decompile/cpp
if [[ "$(sha256sum "$oracle_archive" | awk '{print $1}')" != "$oracle_cpp_archive_sha" ]]; then
  printf '%s\n' 'pinned Ghidra C++ archive mismatch' >&2
  exit 1
fi

snapshot_root="$oracle_tmp/workspace"
mkdir -p "$snapshot_root/tests/oracle" "$snapshot_root/tools" \
  "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
tar -xf "$base_archive" -C "$snapshot_root"
cp "$jumptable_overlay" "$snapshot_root/src/jumptable.rs"
cp "$cpp_fixture" "$snapshot_root/tests/oracle/jt_thunk_classify_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/jt_thunk_classify_1204.rs"
cp "$metadata" "$snapshot_root/tests/oracle/jt_thunk_classify_1204.metadata.json"
cp "$runner" "$snapshot_root/tools/run_jt_thunk_classify_oracle.sh"

mkdir -p "$oracle_tmp/oracle-build"
tar -xf "$oracle_archive" -C "$oracle_tmp/oracle-build"
oracle_cpp="$oracle_tmp/oracle-build/Ghidra/Features/Decompiler/src/decompile/cpp"
ln -s "$oracle_cpp" \
  "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

find "$snapshot_root" -type f -print0 | sort -z | xargs -0 sha256sum \
  >"$oracle_tmp/snapshot.before"
chmod -R a-w "$snapshot_root"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
nice -n 10 make --silent -C "$oracle_cpp" -j "$jobs" \
  CXX="$cxx_path -std=c++11" EXTRA= libdecomp.a
"$cxx_path" -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/jt_thunk_classify_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/libdecomp.a" \
  -lz -o "$oracle_tmp/jt_thunk_classify_1204_cpp"

cargo_target="$oracle_tmp/cargo-target"
set +e
(
  cd "$snapshot_root"
  flock /tmp/rugra-cargo-build.lock -c \
    "CARGO_TARGET_DIR='$cargo_target' CARGO_INCREMENTAL=0 cargo test --offline --locked --jobs 2 --lib --test doc_sync 'jumptable::tests::' -- --nocapture"
) >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"
cargo_status=$?
set -e
if [[ "$cargo_status" -ne 0 ]]; then
  failure_log="/tmp/rugra-jt-thunk-cargo-failure.$$.log"
  {
    printf 'cargo_exit=%s\n' "$cargo_status"
    cat "$oracle_tmp/cargo.stdout"
    cat "$oracle_tmp/cargo.stderr"
  } >"$failure_log"
  printf 'preserved complete Cargo failure log: %s\n' "$failure_log" >&2
  cat "$oracle_tmp/cargo.stdout"
  cat "$oracle_tmp/cargo.stderr" >&2
  exit "$cargo_status"
fi
focused_result=$(grep '^test result:' "$oracle_tmp/cargo.stdout" | sed -n '1p')
case "$focused_result" in
  'test result: ok. 31 passed; 0 failed;'*) ;;
  *) printf 'unexpected focused jumptable result: %s\n' "$focused_result" >&2; exit 1 ;;
esac
printf '%s\n' "$focused_result"

mapfile -t root_outputs < <(
  find "$cargo_target/debug/build" -mindepth 2 -maxdepth 2 -type f \
    -name root-output -print0 |
    while IFS= read -r -d '' candidate; do
      candidate_parent=${candidate%/*}
      case "${candidate_parent##*/}" in
        rugra-*) printf '%s\n' "$candidate" ;;
      esac
    done | sort
)
if [[ ${#root_outputs[@]} -ne 1 ]]; then
  printf 'expected one run-local Rugra root-output, found %s\n' \
    "${#root_outputs[@]}" >&2
  exit 1
fi
native_output=$(<"${root_outputs[0]}")
case "$native_output" in
  "$cargo_target"/debug/build/rugra-*/out) ;;
  *) printf 'root-output escaped run-local target: %s\n' "$native_output" >&2; exit 1 ;;
esac
native_archive="$native_output/librugra_sleigh.a"
if [[ ! -f "$native_archive" ]]; then
  printf '%s\n' 'current root-output did not contain librugra_sleigh.a' >&2
  exit 1
fi

mapfile -t rugra_rlibs < <(find "$cargo_target/debug/deps" -maxdepth 1 -type f \
  -name 'librugra-*.rlib' -print | sort)
if [[ ${#rugra_rlibs[@]} -ne 1 ]]; then
  printf 'expected one run-local Rugra rlib, found %s\n' "${#rugra_rlibs[@]}" >&2
  exit 1
fi
rugra_rlib=${rugra_rlibs[0]}
sha256sum "$native_archive" "$rugra_rlib" >"$oracle_tmp/cargo-artifacts.before"

rustc --edition=2021 -O \
  -L "dependency=$cargo_target/debug/deps" \
  -L "native=$native_output" \
  --extern "rugra=$rugra_rlib" \
  -l static=rugra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$snapshot_root/tests/oracle/jt_thunk_classify_1204.rs" \
  -o "$oracle_tmp/jt_thunk_classify_1204_rust"
sha256sum "$native_archive" "$rugra_rlib" >"$oracle_tmp/cargo-artifacts.after"
cmp "$oracle_tmp/cargo-artifacts.before" "$oracle_tmp/cargo-artifacts.after"

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

find "$snapshot_root" -type f -print0 | sort -z | xargs -0 sha256sum \
  >"$oracle_tmp/snapshot.after"
cmp "$oracle_tmp/snapshot.before" "$oracle_tmp/snapshot.after"
capture_toolchain_state >"$oracle_tmp/toolchain.after"
cmp "$oracle_tmp/toolchain.before" "$oracle_tmp/toolchain.after"
git -C "$ghidra_root" status --porcelain=v2 --untracked-files=all -- \
  Ghidra/Features/Decompiler/src/decompile/cpp >"$oracle_tmp/ghidra.after"
cmp "$oracle_tmp/ghidra.before" "$oracle_tmp/ghidra.after"
if [[ "$(git -C "$ghidra_root" rev-parse HEAD)" != "$oracle_commit" ]]; then
  printf '%s\n' 'Ghidra HEAD drifted during run' >&2
  exit 1
fi
capture_repo_state >"$oracle_tmp/repo.after"
if ! cmp -s "$oracle_tmp/repo.before" "$oracle_tmp/repo.after"; then
  diff -u "$oracle_tmp/repo.before" "$oracle_tmp/repo.after" >&2 || true
  printf '%s\n' 'Rugra index/worktree/runtime inputs drifted during run' >&2
  exit 1
fi

native_sha=$(sha256sum "$native_archive" | awk '{print $1}')
rlib_sha=$(sha256sum "$rugra_rlib" | awk '{print $1}')
printf 'JT-THUNK-CLASSIFY-1204: projection MATCH (24/24 byte-identical); focused jumptable tests PASS; current native=%s rlib=%s; overall MISMATCH: JUMPTABLE-PIPELINE-0001,JUMPTABLE-SORT-TOOLCHAIN-0001\n' \
  "$native_sha" "$rlib_sha"
