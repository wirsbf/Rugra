#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

# HERITAGE-FREE-SSA-FIXTURE-0001.  The runner snapshots the locked Ghidra
# source at e40ed130, pins the complete current Rust crate comparand, serializes
# Cargo through the repository-wide lock, and compares stdout byte-for-byte.

runner_fd_path="/proc/$$/fd/3"
if [[ "${BASH_SOURCE[0]}" != "$runner_fd_path" ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash "$runner_fd_path" "$@"
fi
if [[ $# -ne 0 ]]; then
  echo "usage: tools/run_heritage_free_ssa_oracle.sh" >&2
  exit 2
fi
runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
repo_root=$(builtin cd "$({ /usr/bin/dirname "$runner_source"; })/.." && builtin pwd -P)
runner="$repo_root/tools/run_heritage_free_ssa_oracle.sh"
if [[ "$runner_source" != "$runner" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "runner did not resolve to the expected regular file" >&2
  exit 1
fi

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rugra_base_commit=2be910a2513a9a049eb8bad0bd0a7c13a566bd6a
rugra_base_tree=4810d810e0f1932537cd849a634ce51f19f067d9
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/heritage_free_ssa_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/heritage_free_ssa_1204.cc"
rust_fixture="$repo_root/tests/oracle/heritage_free_ssa_1204.rs"
cargo_target=/tmp/rugra-target-heritage-free-ssa
cargo_lock=/tmp/rugra-cargo-build.lock
user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve user home" >&2
  exit 1
fi
cargo_storage="$user_home/.cache/rugra-target-heritage-free-ssa"
if [[ -L "$cargo_storage" || ( -e "$cargo_storage" && ! -d "$cargo_storage" ) ]]; then
  echo "Cargo backing path must be a real directory: $cargo_storage" >&2
  exit 1
fi
/usr/bin/mkdir -p "$cargo_storage"
if [[ ! -e "$cargo_target" && ! -L "$cargo_target" ]]; then
  /usr/bin/ln -s "$cargo_storage" "$cargo_target"
fi
if [[ ! -L "$cargo_target" || "$(/usr/bin/readlink -f "$cargo_target")" != "$cargo_storage" ]]; then
  echo "dedicated Cargo target must resolve $cargo_target -> $cargo_storage" >&2
  exit 1
fi

for path in "$metadata" "$cpp_fixture" "$rust_fixture" "$runner"; do
  if [[ ! -f "$path" || -L "$path" ]]; then
    echo "required input is not a regular non-symlink file: $path" >&2
    exit 1
  fi
done

actual_commit=$(/usr/bin/git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(/usr/bin/git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
cpp_tree=$(/usr/bin/git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
makefile_blob=$(/usr/bin/git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$cpp_tree" != "$oracle_cpp_tree" || "$makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra identity mismatch" >&2
  exit 1
fi
if [[ -n "$(/usr/bin/git -C "$ghidra_root" status --porcelain -- \
  Ghidra/Features/Decompiler/src/decompile/cpp)" ]]; then
  echo "locked Ghidra decompiler tree is dirty" >&2
  exit 1
fi
if [[ "$(/usr/bin/git -C "$repo_root" rev-parse "$rugra_base_commit^{commit}")" != "$rugra_base_commit" || \
      "$(/usr/bin/git -C "$repo_root" rev-parse "$rugra_base_commit^{tree}")" != "$rugra_base_tree" ]]; then
  echo "pinned Rugra base identity mismatch" >&2
  exit 1
fi

runner_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')
/usr/bin/python3 -I -S - "$repo_root" "$metadata" "$cpp_fixture" \
  "$rust_fixture" "$runner_sha" "$oracle_tag" "$oracle_commit" \
  "$oracle_cpp_tree" "$oracle_makefile_blob" "$rugra_base_commit" \
  "$rugra_base_tree" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(repo_raw, metadata_raw, cpp_raw, rust_raw, runner_sha, oracle_tag,
 oracle_commit, cpp_tree, makefile_blob, base_commit, base_tree) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()
metadata_path = pathlib.Path(metadata_raw)
cpp_path = pathlib.Path(cpp_raw)
rust_path = pathlib.Path(rust_raw)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
oracle = metadata["oracle"]
require("oracle tag", oracle["tag"], oracle_tag)
require("oracle commit", oracle["commit"], oracle_commit)
require("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree)
require("oracle Makefile", oracle["decompiler_makefile_blob"], makefile_blob)
comparand = metadata["comparand"]
require("base commit", comparand["rugra_base_commit"], base_commit)
require("base tree", comparand["rugra_base_tree"], base_tree)
require("C++ fixture hash", sha(cpp_path.read_bytes()), comparand["cpp_fixture_sha256"])
require("Rust fixture hash", sha(rust_path.read_bytes()), comparand["rust_fixture_sha256"])
require("runner hash", runner_sha, comparand["runner_sha256"])

raw_paths = subprocess.check_output([
    "/usr/bin/git", "-C", str(repo), "ls-files", "-z", "--",
    "Cargo.toml", "Cargo.lock", "build.rs", "src", "sleigh_shim",
])
paths = sorted(
    (pathlib.Path(item.decode()) for item in raw_paths.split(b"\0") if item),
    key=lambda path: path.as_posix(),
)
hasher = hashlib.sha256()
hasher.update(b"rugra-heritage-free-ssa-current-crate-v1\0")
for relative in paths:
    source = repo / relative
    if source.is_symlink() or not source.is_file():
        raise SystemExit(f"crate input is not a regular file: {relative}")
    data = source.read_bytes()
    encoded = relative.as_posix().encode()
    hasher.update(len(encoded).to_bytes(8, "big"))
    hasher.update(encoded)
    hasher.update(len(data).to_bytes(8, "big"))
    hasher.update(data)
require("crate hash scheme", comparand["rust_crate_tree_hash_scheme"],
        "sha256 of rugra-heritage-free-ssa-current-crate-v1 plus sorted length-prefixed tracked Cargo.toml/Cargo.lock/build.rs/src/sleigh_shim paths and bytes")
require("current crate hash", hasher.hexdigest(), comparand["rust_crate_tree_sha256"])
for relative, key in (
    ("src/heritage.rs", "heritage_rs_sha256"),
    ("src/funcdata.rs", "funcdata_rs_sha256"),
    ("src/varnode.rs", "varnode_rs_sha256"),
    ("src/op.rs", "op_rs_sha256"),
    ("src/block.rs", "block_rs_sha256"),
):
    require(key, sha((repo / relative).read_bytes()), comparand[key])

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "cases": manifest["cases"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode()
require("input fingerprint", sha(canonical), manifest["sha256"])
require("covered projection", metadata["covered_projection_status"], "MATCH")
if not metadata["overall_status"].startswith("PARTIAL_MATCH:"):
    raise SystemExit("overall_status must remain conservative PARTIAL_MATCH")
PY

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rugra-heritage-free-ssa-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-heritage-free-ssa-1204.??????)
      [[ ! -e "$oracle_tmp" || ( -d "$oracle_tmp" && ! -L "$oracle_tmp" ) ]] || return 1
      /usr/bin/rm -rf -- "$oracle_tmp"
      ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2; return 1 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

owned=("$metadata" "$cpp_fixture" "$rust_fixture" "$runner")
/usr/bin/sha256sum "${owned[@]}" >"$oracle_tmp/owned.before"
/usr/bin/mkdir -p "$oracle_tmp/source"
/usr/bin/git -C "$ghidra_root" archive --format=tar "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/tar -xf - -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"
jobs=$(/usr/bin/getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
if (( jobs > 8 )); then jobs=8; fi
/usr/bin/nice -n 10 /usr/bin/make --silent -C "$oracle_cpp" -j "$jobs" \
  CXX="/usr/bin/g++ -std=c++11" EXTRA= libdecomp.a
/usr/bin/g++ -std=c++11 -O2 -Wall -Wno-sign-compare -m64 -I"$oracle_cpp" \
  "$cpp_fixture" "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" -Wl,--whole-archive "$oracle_cpp/libdecomp.a" \
  -Wl,--no-whole-archive -lz -o "$oracle_tmp/fixture_cpp"

/usr/bin/flock "$cargo_lock" -c \
  "CARGO_TARGET_DIR='$cargo_target' /usr/bin/cargo build --offline --locked --quiet --lib --manifest-path '$repo_root/Cargo.toml'"
/usr/bin/rustc --edition=2021 -O "$rust_fixture" \
  --extern "rugra=$cargo_target/debug/librugra.rlib" \
  -L "dependency=$cargo_target/debug/deps" \
  -o "$oracle_tmp/fixture_rust"

/usr/bin/timeout 60s "$oracle_tmp/fixture_cpp" >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
/usr/bin/timeout 60s "$oracle_tmp/fixture_rust" >"$oracle_tmp/rugra.stdout" 2>"$oracle_tmp/rugra.stderr"
if [[ -s "$oracle_tmp/ghidra.stderr" || -s "$oracle_tmp/rugra.stderr" ]]; then
  echo "fixture stderr must be empty" >&2
  /usr/bin/cat "$oracle_tmp/ghidra.stderr" "$oracle_tmp/rugra.stderr" >&2
  exit 1
fi
/usr/bin/diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout"

/usr/bin/python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib, json, pathlib, sys
metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
data = pathlib.Path(sys.argv[2]).read_bytes()
actual = hashlib.sha256(data).hexdigest()
if actual != metadata["expected_stdout_sha256"]:
    raise SystemExit(
        f"stdout hash mismatch: expected={metadata['expected_stdout_sha256']} actual={actual}"
    )
lines = data.decode().splitlines()
if len(lines) != metadata["expected_stdout_lines"]:
    raise SystemExit("stdout line-count mismatch")
prefixes = (
    "schema=1|fixture=HERITAGE-FREE-SSA-FIXTURE-0001|",
    "case=single_free_promotion|",
    "case=double_descendant_error|",
    "case=indirect_simultaneous|",
    "case=loop_phi_reverse_slot|",
)
if tuple(line.startswith(prefix) for line, prefix in zip(lines, prefixes)) != (True,) * 5:
    raise SystemExit("stdout case order mismatch")
PY

/usr/bin/sha256sum "${owned[@]}" >"$oracle_tmp/owned.after"
/usr/bin/diff -u "$oracle_tmp/owned.before" "$oracle_tmp/owned.after"
/usr/bin/cat "$oracle_tmp/ghidra.stdout"
echo "heritage_free_ssa_1204: covered_projection=MATCH overall=PARTIAL_MATCH cases=4"
