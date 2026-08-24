#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
metadata="$repo_root/tests/oracle/type_ptrwidth_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/type_ptrwidth_1204.cc"
rust_fixture="$repo_root/tests/oracle/type_ptrwidth_1204.rs"
target_dir=${RUGRA_TYPE_PTRWIDTH_TARGET_DIR:-/home/wirs/.cache/rugra-type-ptrwidth-target}
build_tmp=${RUGRA_TYPE_PTRWIDTH_TMP_DIR:-/home/wirs/.cache/rugra-type-ptrwidth-tmp}

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
actual_tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
if [[ "$actual_commit" != "$oracle_commit" || \
      "$actual_tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" ]]; then
  echo "locked Ghidra identity mismatch" >&2
  exit 1
fi
if [[ -n $(git -C "$ghidra_root" status --porcelain -- \
  Ghidra/Features/Decompiler/src/decompile/cpp) ]]; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

python3 - "$repo_root" "$metadata" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
metadata = json.loads(pathlib.Path(sys.argv[2]).read_text())
for relative, expected in metadata["comparand"]["overlay_sha256"].items():
    actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"comparand hash mismatch: {relative}: {actual}")
PY

tmpdir=$(mktemp -d /tmp/rugra-type-ptrwidth-1204.XXXXXX)
rust_binary="$build_tmp/rugra-type-ptrwidth-fixture.$$"
cleanup() {
  if [[ "$rust_binary" == "$build_tmp"/rugra-type-ptrwidth-fixture.* ]]; then
    rm -f -- "$rust_binary"
  fi
  case "$tmpdir" in
    /tmp/rugra-type-ptrwidth-1204.??????) rm -rf -- "$tmpdir" ;;
    *) echo "refusing to remove unexpected temp path: $tmpdir" >&2; exit 1 ;;
  esac
}
trap cleanup EXIT

if [[ ! -f "$cpp_root/libdecomp.a" ]]; then
  make -C "$cpp_root" -j2 libdecomp.a
fi
g++ -std=c++11 -O2 -I"$cpp_root" "$cpp_fixture" \
  -Wl,--whole-archive "$cpp_root/libdecomp.a" -Wl,--no-whole-archive -lz \
  -o "$tmpdir/ghidra_fixture"
"$tmpdir/ghidra_fixture" >"$tmpdir/ghidra.out"

mkdir -p "$target_dir" "$build_tmp"
if ! flock /tmp/rugra-cargo-build.lock env CARGO_INCREMENTAL=0 TMPDIR="$build_tmp" \
  CARGO_TARGET_DIR="$target_dir" cargo build --manifest-path "$repo_root/Cargo.toml" \
  --lib --quiet >"$tmpdir/cargo.log" 2>&1; then
  cat "$tmpdir/cargo.log" >&2
  exit 1
fi
rlib=$(find "$target_dir/debug/deps" -maxdepth 1 -name 'librugra-*.rlib' \
  -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
if [[ -z "$rlib" || ! -f "$rlib" ]]; then
  echo "could not locate built Rugra rlib" >&2
  exit 1
fi
TMPDIR="$build_tmp" rustc --edition=2021 "$rust_fixture" --extern "rugra=$rlib" \
  -L "dependency=$target_dir/debug/deps" -o "$rust_binary"
"$rust_binary" >"$tmpdir/rugra.out"

if ! cmp -s "$tmpdir/ghidra.out" "$tmpdir/rugra.out"; then
  diff -u "$tmpdir/ghidra.out" "$tmpdir/rugra.out" >&2 || true
  exit 1
fi
actual_stdout_sha=$(sha256sum "$tmpdir/ghidra.out" | awk '{print $1}')
expected_stdout_sha=$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["expected_stdout_sha256"])' \
  "$metadata")
if [[ "$actual_stdout_sha" != "$expected_stdout_sha" ]]; then
  echo "stdout hash mismatch: $actual_stdout_sha" >&2
  exit 1
fi

cat "$tmpdir/ghidra.out"
echo "TYPE-PTRWIDTH-PTRSUB-0001 targeted cases: MATCH" >&2
