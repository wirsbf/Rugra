#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
fixture="$repo_root/tests/oracle/userop_index_1204.cc"
metadata="$repo_root/tests/oracle/userop_index_1204.metadata.json"

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
if [[ "$actual_commit" != "$oracle_commit" ]]; then
  echo "expected Ghidra $oracle_commit, found $actual_commit" >&2
  exit 1
fi

python3 - "$metadata" "$fixture" "$oracle_commit" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata_path = pathlib.Path(sys.argv[1])
fixture_path = pathlib.Path(sys.argv[2])
oracle_commit = sys.argv[3]
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
if metadata["oracle"]["commit"] != oracle_commit:
    raise SystemExit("metadata oracle commit does not match runner")
actual_hash = hashlib.sha256(fixture_path.read_bytes()).hexdigest()
if metadata["input_sha256"] != actual_hash:
    raise SystemExit(
        f"fixture hash mismatch: metadata={metadata['input_sha256']} actual={actual_hash}"
    )
PY

oracle_tmp=$(mktemp -d)
trap 'rm -rf "$oracle_tmp"' EXIT

sources=(
  xml marshal space float address pcoderaw translate opcodes globalcontext
  pcodecompile sleighbase slghsymbol slghpatexpress slghpattern semantics
  context slaformat filemanage slgh_compile
)
objects=()
for source in "${sources[@]}"; do
  extra_flags=()
  if [[ "$source" == slgh_compile ]]; then
    # slgh_compile.cc also contains the standalone compiler's main(). Rename
    # only that entry point so the fixture can link the real SleighCompile.
    extra_flags=(-Dmain=ghidra_sleigh_standalone_main)
  fi
  g++ -std=c++11 -O2 -ffunction-sections -fdata-sections \
    "${extra_flags[@]}" -I"$cpp_root" -c "$cpp_root/$source.cc" \
    -o "$oracle_tmp/$source.o"
  objects+=("$oracle_tmp/$source.o")
done

g++ -std=c++11 -O2 -Wl,--gc-sections -I"$cpp_root" \
  "$fixture" \
  "${objects[@]}" \
  -o "$oracle_tmp/userop_index_1204"

"$oracle_tmp/userop_index_1204"
