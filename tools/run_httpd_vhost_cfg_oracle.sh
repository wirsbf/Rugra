#!/usr/bin/env bash
# HTTPD-BUCKET2-2026-08-27 structural fixture skeleton.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd -P)
tmp=${TMPDIR:-/tmp}/rugra-httpd-vhost-cfg-$$
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp"
/usr/bin/g++ -std=c++17 -O2 -Wall -Wextra \
  "$root/tests/oracle/httpd_vhost_cfg_1204.cc" -o "$tmp/oracle"
"$tmp/oracle" > "$tmp/oracle.stdout"
/usr/bin/rustc --edition=2021 -O "$root/tests/oracle/httpd_vhost_cfg_1204.rs" \
  -o "$tmp/rust"
"$tmp/rust" > "$tmp/rust.stdout"
cat "$tmp/oracle.stdout"
cat "$tmp/rust.stdout" >&2
printf 'fixture_status=NO_ORACLE rust_side=TODO\n' >&2
