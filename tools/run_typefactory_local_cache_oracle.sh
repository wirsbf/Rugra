#!/usr/bin/env bash
# TYPEFACTORY-LOCALTYPE-CACHE-0001 locked Ghidra/Rugra differential runner.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
rugra_base_commit=71971b2a2bf8e3611f8690bcb6a0bcad34d29f34
rugra_base_tree=894f93b5c8cc991f1de43df2cc4d1368a3a2fcc1
rugra_typefactory_base_blob=d3010e85ee10ef0b37c0cc8ac225c213c995acb3
rugra_datatype_base_blob=1abf0bb062b1c57c336d38f3c5c2fafa5cba9aee
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
metadata="$repo_root/tests/oracle/typefactory_local_cache_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/typefactory_local_cache_1204.cc"
rust_fixture="$repo_root/tests/oracle/typefactory_local_cache_1204.rs"
typefactory_source="$repo_root/src/type_system/typefactory.rs"
runner="$repo_root/tools/run_typefactory_local_cache_oracle.sh"
spec_root="$repo_root/sleigh_specs"
binary="$repo_root/examples/curl"
bfd_include=/tmp/rugra-ghidra-bfd-2.38/usr/include
bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$typefactory_source" "$runner" \
  "$spec_root/x86-64.sla" "$spec_root/x86-64.pspec" \
  "$spec_root/x86-64-gcc.cspec" "$spec_root/x86.ldefs" "$binary" \
  "$bfd_include/bfd.h" "$bfd_library"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required regular non-symlink input is missing: $required" >&2
    exit 1
  fi
done

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
actual_tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$actual_tag_commit" != "$oracle_commit" ]]; then
  echo "locked Ghidra HEAD/tag mismatch: HEAD=$actual_commit tag=$actual_tag_commit" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
  Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

resolved_base_commit=$(git -C "$repo_root" rev-parse "$rugra_base_commit^{commit}")
resolved_base_tree=$(git -C "$repo_root" rev-parse "$rugra_base_commit^{tree}")
resolved_typefactory_blob=$(git -C "$repo_root" rev-parse \
  "$rugra_base_commit:src/type_system/typefactory.rs")
resolved_datatype_blob=$(git -C "$repo_root" rev-parse \
  "$rugra_base_commit:src/type_system/datatype.rs")
if [[ "$resolved_base_commit" != "$rugra_base_commit" || \
      "$resolved_base_tree" != "$rugra_base_tree" || \
      "$resolved_typefactory_blob" != "$rugra_typefactory_base_blob" || \
      "$resolved_datatype_blob" != "$rugra_datatype_base_blob" ]]; then
  echo "pinned Rugra source identity mismatch" >&2
  exit 1
fi

verify_inputs() {
  python3 - "$metadata" "$cpp_fixture" "$rust_fixture" \
    "$typefactory_source" "$runner" \
    "$spec_root/x86-64.sla" "$spec_root/x86-64.pspec" \
    "$spec_root/x86-64-gcc.cspec" "$spec_root/x86.ldefs" "$binary" \
    "$repo_root/Cargo.toml" "$repo_root/Cargo.lock" "$oracle_commit" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    metadata_raw,
    cpp_raw,
    rust_raw,
    typefactory_raw,
    runner_raw,
    sla_raw,
    pspec_raw,
    cspec_raw,
    ldefs_raw,
    binary_raw,
    cargo_toml_raw,
    cargo_lock_raw,
    oracle_commit,
) = sys.argv[1:]

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
if metadata["oracle"]["commit"] != oracle_commit:
    raise SystemExit("metadata oracle commit does not match runner")

inputs = {
    "cpp_fixture_sha256": pathlib.Path(cpp_raw),
    "rust_fixture_sha256": pathlib.Path(rust_raw),
    "typefactory_rs_sha256": pathlib.Path(typefactory_raw),
    "runner_sha256": pathlib.Path(runner_raw),
    "sla_sha256": pathlib.Path(sla_raw),
    "pspec_sha256": pathlib.Path(pspec_raw),
    "cspec_sha256": pathlib.Path(cspec_raw),
    "ldefs_sha256": pathlib.Path(ldefs_raw),
    "binary_sha256": pathlib.Path(binary_raw),
    "cargo_toml_sha256": pathlib.Path(cargo_toml_raw),
    "cargo_lock_sha256": pathlib.Path(cargo_lock_raw),
}
declared = metadata["comparand"] | metadata["assets"]
for key, path in inputs.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = declared[key]
    if actual != expected:
        raise SystemExit(
            f"input hash mismatch for {path.name}: metadata={expected} actual={actual}"
        )
PY
}

verify_inputs

oracle_tmp=$(mktemp -d /tmp/rugra-typefactory-local-cache-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-typefactory-local-cache-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

snapshot_root="$oracle_tmp/rugra"
mkdir -p "$snapshot_root"
git -C "$repo_root" archive --format=tar "$rugra_base_commit" \
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  src sleigh_shim | tar -xf - -C "$snapshot_root"
cp -- "$typefactory_source" "$snapshot_root/src/type_system/typefactory.rs"
snapshot_decompiler="$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
mkdir -p "$snapshot_decompiler"
ln -s "$cpp_root" "$snapshot_decompiler/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$cpp_root" -j "$jobs" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$bfd_include" -I"$cpp_root" \
  "$cpp_fixture" "$cpp_root/libdecomp.cc" "$cpp_root/sleigh_arch.cc" \
  "$cpp_root/inject_sleigh.cc" "$cpp_root/bfd_arch.cc" \
  "$cpp_root/loadimage_bfd.cc" \
  "$cpp_root/libdecomp.a" "$bfd_library" -lz \
  -o "$oracle_tmp/typefactory_local_cache_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --quiet --locked --offline --manifest-path "$snapshot_root/Cargo.toml" --lib
rustc --edition=2021 -O \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  --extern "rugra=$oracle_tmp/cargo-target/debug/librugra.rlib" \
  "$rust_fixture" -o "$oracle_tmp/typefactory_local_cache_rust"

"$oracle_tmp/typefactory_local_cache_cpp" "$spec_root" "$binary" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/typefactory_local_cache_rust" \
  >"$oracle_tmp/rugra.stdout" 2>"$oracle_tmp/rugra.stderr"
rugra_status=$?
if [[ "$ghidra_status" != 0 || "$rugra_status" != 0 ]]; then
  echo "fixture exit codes: ghidra=$ghidra_status rugra=$rugra_status" >&2
  tail -5 "$oracle_tmp/ghidra.stderr" >&2
  tail -5 "$oracle_tmp/rugra.stderr" >&2
  exit 1
fi
if [[ -s "$oracle_tmp/rugra.stderr" ]]; then
  echo "Rugra fixture stderr is not empty" >&2
  tail -5 "$oracle_tmp/rugra.stderr" >&2
  exit 1
fi

diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout"
verify_inputs

python3 - "$metadata" "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
output = pathlib.Path(sys.argv[2]).read_bytes()
actual = hashlib.sha256(output).hexdigest()
expected = metadata["expected_stdout_sha256"]
if actual != expected:
    raise SystemExit(f"oracle output hash mismatch: metadata={expected} actual={actual}")
if metadata["projection_status"] != "MATCH" or metadata["overall_status"] != "MISMATCH":
    raise SystemExit("metadata status must remain projection MATCH / overall MISMATCH")
print(f"records={len(output.decode('utf-8').splitlines())}")
print(f"stdout_sha256={actual}")
PY
printf 'typefactory_local_cache_1204: projection_status=MATCH overall_status=MISMATCH\n'
