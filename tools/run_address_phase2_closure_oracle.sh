#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
pinned_base=4f42981d2ed723e6ac53ebb787d90f4b89e889df
pinned_tree=17fd780210a7139a8b3dc30459e627b1926d763e
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/address_phase2_closure_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/address_phase2_closure_1204.cc"
rust_fixture="$repo_root/tests/oracle/address_phase2_closure_1204.rs"
runner="$repo_root/tools/run_address_phase2_closure_oracle.sh"
cargo_target=/tmp/rugra-target-address-phase2
cargo_lock=/tmp/rugra-cargo-build.lock

for input in "$metadata" "$cpp_fixture" "$rust_fixture" "$runner"; do
  if [[ ! -f "$input" || -L "$input" ]]; then
    echo "required regular input is missing or a symlink: $input" >&2
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
if [[ -n "$(git -C "$ghidra_root" status --porcelain -- \
  Ghidra/Features/Decompiler/src/decompile/cpp)" ]]; then
  echo "locked Ghidra decompiler sources are dirty" >&2
  exit 1
fi

python3 -I -S - "$metadata" "$repo_root" "$ghidra_root" "$cpp_fixture" \
  "$rust_fixture" "$runner" "$oracle_commit" "$oracle_tag" \
  "$oracle_cpp_tree" "$oracle_makefile_blob" "$pinned_base" "$pinned_tree" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_raw, repo_raw, ghidra_raw, cpp_raw, rust_raw, runner_raw,
    oracle_commit, oracle_tag, cpp_tree, makefile_blob, pinned_base,
    pinned_tree,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
repo = pathlib.Path(repo_raw)
ghidra = pathlib.Path(ghidra_raw)

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

require("schema", metadata["schema_version"], 1)
require("fixture id", metadata["fixture_id"], "ADDRESS-PHASE2-CLOSURE-0001")
require("oracle tag", metadata["oracle"]["tag"], oracle_tag)
require("oracle commit", metadata["oracle"]["commit"], oracle_commit)
require("oracle cpp tree", metadata["oracle"]["decompiler_cpp_tree"], cpp_tree)
require("oracle Makefile", metadata["oracle"]["decompiler_makefile_blob"], makefile_blob)
require("architecture", metadata["architecture"], "x86:LE:64:default")
require("compiler spec", metadata["compiler_spec"]["id"], "gcc")
require("overall status", metadata["observation"]["overall_status"], "MISMATCH")
require("pinned base", metadata["comparand"]["pinned_base_commit"], pinned_base)
require("pinned tree", metadata["comparand"]["pinned_base_tree"], pinned_tree)

canonical_input = json.dumps(
    metadata["input"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require(
    "input fingerprint",
    metadata["input_fingerprint"],
    "sha256:" + hashlib.sha256(canonical_input).hexdigest(),
)

file_hashes = {
    "cpp_fixture_sha256": sha(cpp_raw),
    "rust_fixture_sha256": sha(rust_raw),
    "runner_sha256": sha(runner_raw),
}
for key, actual in file_hashes.items():
    require(key, metadata["comparand"][key], actual)

for relative, expected_blob in metadata["comparand"]["source_blobs"].items():
    actual = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", f"{pinned_base}:{relative}"],
        text=True,
    ).strip()
    require(f"Rugra source blob {relative}", actual, expected_blob)

cpp_prefix = "Ghidra/Features/Decompiler/src/decompile/cpp/"
for relative, expected_blob in metadata["oracle"]["source_blobs"].items():
    actual = subprocess.check_output(
        ["git", "-C", str(ghidra), "rev-parse", f"{oracle_commit}:{cpp_prefix}{relative}"],
        text=True,
    ).strip()
    require(f"Ghidra source blob {relative}", actual, expected_blob)

for key, asset in metadata["assets"].items():
    path = repo / asset["path"]
    require(f"asset hash {key}", sha(path), asset["sha256"])

for key, value in metadata["expected"].items():
    if not isinstance(value, str) or len(value) != 64 or value.startswith("PENDING"):
        raise SystemExit(f"expected output pin is invalid: {key}={value!r}")

statuses = {case["id"]: case["status"] for case in metadata["observation"]["cases"]}
required = {
    "address_space_identity_order": "MATCH",
    "bank_create_lifecycle": "MISMATCH",
    "bank_destroy_alive_exception": "MISMATCH",
    "split_parent_order": "MATCH",
    "split_entry_start_stop_cover": "MISMATCH",
    "split_missing_start_exception": "MISMATCH",
    "flow_ram_tagged_entry": "MISMATCH",
    "flow_overlay_tagged_entry": "MISMATCH",
    "flow_stack_tagged_entry": "MISMATCH",
    "combined_cross_space_visited": "UNTESTED",
}
require("case status matrix", statuses, required)
PY

cache_root=${XDG_CACHE_HOME:-$HOME/.cache}
mkdir -p "$cache_root"
oracle_tmp=$(mktemp -d "$cache_root/rugra-address-phase2-1204.XXXXXX")
cleanup() {
  if [[ "$(dirname "$oracle_tmp")" != "$cache_root" || \
        "$(basename "$oracle_tmp")" != rugra-address-phase2-1204.?????? || \
        ! -d "$oracle_tmp" || -L "$oracle_tmp" ]]; then
    echo "refusing unsafe temporary cleanup target: $oracle_tmp" >&2
    return 1
  fi
  rm -rf -- "$oracle_tmp"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$oracle_tmp/oracle" "$oracle_tmp/workspace"
git -C "$ghidra_root" archive --format=tar "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  tar -xf - -C "$oracle_tmp/oracle"
oracle_cpp="$oracle_tmp/oracle/Ghidra/Features/Decompiler/src/decompile/cpp"
git -C "$repo_root" archive --format=tar "$pinned_base" | \
  tar -xf - -C "$oracle_tmp/workspace"
snapshot="$oracle_tmp/workspace"
mkdir -p "$snapshot/tests/oracle" \
  "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile"
cp -- "$rust_fixture" "$snapshot/tests/oracle/address_phase2_closure_1204.rs"
ln -s "$oracle_cpp" "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
TMPDIR="$oracle_tmp" make --silent -C "$oracle_cpp" -j "$jobs" CXX="g++ -std=c++11" EXTRA= libdecomp.a \
  >"$oracle_tmp/make.stdout" 2>"$oracle_tmp/make.stderr"
TMPDIR="$oracle_tmp" g++ -std=c++11 -O2 -Wall -Wno-sign-compare -I"$oracle_cpp" \
  "$cpp_fixture" \
  "$oracle_cpp/libdecomp.cc" \
  "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" \
  "$oracle_cpp/raw_arch.cc" \
  "$oracle_cpp/libdecomp.a" -lz \
  -o "$oracle_tmp/address_phase2_closure_cpp"
objcopy --dump-section ".rugra_input=$oracle_tmp/input.bin" \
  "$oracle_tmp/address_phase2_closure_cpp"
python3 -I -S - "$oracle_tmp/input.bin" <<'PY'
import pathlib
import sys
data = pathlib.Path(sys.argv[1]).read_bytes()
if data != bytes.fromhex("750190c3"):
    raise SystemExit(f"raw input bytes differ: {data.hex()}")
PY

(
  cd "$snapshot"
  "$oracle_tmp/address_phase2_closure_cpp" sleigh_specs "$oracle_tmp/input.bin" \
    >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
)

# This task has one fixed, isolated Cargo target.  flock serializes the
# expensive Ghidra-backed build with all other Rugra fixture writers.
flock "$cargo_lock" -c \
  "cd '$snapshot' && CARGO_NET_OFFLINE=true CARGO_TARGET_DIR='$cargo_target' cargo build --offline --locked --lib" \
  >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"
rugra_rlib="$cargo_target/debug/librugra.rlib"
if [[ ! -f "$rugra_rlib" ]]; then
  echo "Cargo did not produce $rugra_rlib" >&2
  exit 1
fi
mapfile -t native_archives < <(find "$cargo_target/debug/build" \
  -path '*/out/librugra_sleigh.a' -type f | sort)
if [[ "${#native_archives[@]}" -ne 1 ]]; then
  echo "expected one librugra_sleigh.a, found ${#native_archives[@]}" >&2
  exit 1
fi
native_dir=$(dirname "${native_archives[0]}")
TMPDIR="$oracle_tmp" rustc --edition=2021 -O -C linker-features=-lld \
  -L "dependency=$cargo_target/debug/deps" -L "native=$native_dir" \
  --extern "rugra=$rugra_rlib" \
  -l static=rugra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$snapshot/tests/oracle/address_phase2_closure_1204.rs" \
  -o "$oracle_tmp/address_phase2_closure_rust"
(
  cd "$snapshot"
  "$oracle_tmp/address_phase2_closure_rust" \
    >"$oracle_tmp/rugra.stdout" 2>"$oracle_tmp/rugra.stderr"
)

if diff --label ghidra --label rugra -u \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout" \
  >"$oracle_tmp/output.diff"; then
  echo "fixture unexpectedly became byte-identical; metadata status is stale" >&2
  exit 1
fi

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" \
  "$oracle_tmp/ghidra.stderr" "$oracle_tmp/rugra.stdout" \
  "$oracle_tmp/rugra.stderr" "$oracle_tmp/output.diff" <<'PY'
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
    "unified_diff_sha256": pathlib.Path(sys.argv[6]),
}
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = metadata["expected"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: expected={expected} actual={actual}")

ghidra = paths["ghidra_stdout_sha256"].read_text(encoding="utf-8").splitlines()
rugra = paths["rugra_stdout_sha256"].read_text(encoding="utf-8").splitlines()

def selected(lines, prefix):
    return [line for line in lines if line.startswith(prefix)]

for side, lines in (("ghidra", ghidra), ("rugra", rugra)):
    if len(selected(lines, "record=header ")) != 1:
        raise SystemExit(f"{side}: missing unique header")
    if len(selected(lines, "record=coverage ")) != 1:
        raise SystemExit(f"{side}: missing unique UNTESTED coverage record")
    for case in ("flow_ram", "flow_code_overlay", "flow_stack"):
        if len(selected(lines, f"case={case} record=run ")) != 1:
            raise SystemExit(f"{side}: missing independent run for {case}")
        if len(selected(lines, f"case={case} record=generated ")) != 1:
            raise SystemExit(f"{side}: missing production generation for {case}")
        if len(selected(lines, f"case={case} record=visited ")) != 3:
            raise SystemExit(f"{side}: expected three visited records for {case}")

mismatch_prefixes = [
    "case=bank_spaces record=membership phase=create ",
    "case=bank_spaces record=destroy_alive ",
    "case=split_spaces record=block ",
    "case=split_missing_start record=exception ",
    "case=flow_ram record=generated ",
    "case=flow_code_overlay record=exception ",
    "case=flow_stack record=exception ",
]
for prefix in mismatch_prefixes:
    if selected(ghidra, prefix) == selected(rugra, prefix):
        raise SystemExit(f"registered MISMATCH disappeared for {prefix!r}")

coverage = selected(rugra, "record=coverage ")[0]
if "combined_cross_space_visited=UNTESTED" not in coverage:
    raise SystemExit("combined cross-space visited residual was not retained")
PY

echo "address_phase2_closure_1204: MISMATCH (expected, real dual execution)"
echo "address_phase2_closure_1204: combined_cross_space_visited=UNTESTED"
