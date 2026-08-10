#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
if [[ "$actual_commit" != "$oracle_commit" ]]; then
  echo "expected Ghidra $oracle_commit, found $actual_commit" >&2
  exit 1
fi

oracle_tmp=$(mktemp -d)
trap 'rm -rf "$oracle_tmp"' EXIT

g++ -std=c++11 -O2 -ffunction-sections -fdata-sections \
  -I"$cpp_root" \
  -c "$cpp_root/typeop.cc" \
  -o "$oracle_tmp/typeop.o"
g++ -std=c++11 -O2 -Wl,--gc-sections \
  -I"$cpp_root" \
  "$repo_root/tests/oracle/preferred_zext_size.cc" \
  "$oracle_tmp/typeop.o" \
  -o "$oracle_tmp/preferred_zext_size"

if [[ $# -eq 0 ]]; then
  set -- 1 2 3 4 7 8 16
fi

"$oracle_tmp/preferred_zext_size" "$@"
