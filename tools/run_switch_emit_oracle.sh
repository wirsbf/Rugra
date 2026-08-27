#!/usr/bin/env bash
# PRINTC-SWITCH-EMIT-0001 stage-A fixture runner.
# Oracle pin: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd -P)
tmp=${TMPDIR:-/tmp}/rugra-switch-emit-$$
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp"
/usr/bin/g++ -std=c++17 -O2 -Wall -Wextra "$root/tests/oracle/switch_emit_1204.cc" -o "$tmp/switch_emit_1204"
"$tmp/switch_emit_1204" > "$tmp/ghidra-contract.out"
# Stage A intentionally leaves the Rust producer unimplemented: printc.rs is
# leased to strconst2.  Do not claim MATCH from this contract-only comparison.
if [[ ${1:-} == --rust ]]; then
  echo "RUST_TODO: run the Rust switch emitter after PRINTC lease release" >&2
  exit 2
fi
cat "$tmp/ghidra-contract.out"
printf 'fixture_status=NO_ORACLE rust_side=TODO\n' >&2
