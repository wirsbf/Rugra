#!/bin/sh
# Rebuild the tracked x86-64 SLEIGH assets from the locked Ghidra 12.0.4 tree.

set -eu

LOCKED_ORACLE=e40ed13014025f82488b1f8f7bca566894ac376b
EXPECTED_CPP_TREE=b02e230a539c65de14e50f357d0ba834d8184f4f
EXPECTED_LANGUAGE_TREE=84265e1e6fe7ac9725367b57fb861253e4915984
EXPECTED_SLASPEC_SHA=9d66a01a4219ab0bee0697caf2d1ee389e094e927a857299cebb6182e40a4e6e
EXPECTED_SLA_SHA=d5adc314e2278228b380d8f653b2b579fa4a65986bb1d39b095e461fd5432481
EXPECTED_SLA_SIZE=487659
EXPECTED_PSPEC_SHA=3c3dab75a2ac0b98b0552856f690e613d661e0df7cf94d6252e5604d9821629f
EXPECTED_CSPEC_SHA=5eaa848f3eba7ebd4023541f9f37645dae077e8426fb562592f398d599530a9e
EXPECTED_LDEFS_SHA=b2aa14d94a6162844b18bf47f2aed8579bf90cef3459f6e322b9c1f58146098b

repo_root=$(git rev-parse --show-toplevel)
ghidra_repo=${RUGRA_GHIDRA_DIR:-"$repo_root/ghidra"}
output_dir=${1:-"$repo_root/sleigh_specs"}

die() {
    echo "build_locked_x86_64_sla: $*" >&2
    exit 1
}

file_sha256() {
    digest=$(sha256sum "$1")
    printf '%s\n' "${digest%% *}"
}

check_sha256() {
    actual=$(file_sha256 "$1")
    [ "$actual" = "$2" ] || die "$1 sha256=$actual; expected $2"
}

git -C "$ghidra_repo" rev-parse --is-inside-work-tree >/dev/null 2>&1 || \
    die "missing Ghidra repository: $ghidra_repo"
oracle_head=$(git -C "$ghidra_repo" rev-parse HEAD)
[ "$oracle_head" = "$LOCKED_ORACLE" ] || \
    die "Ghidra HEAD=$oracle_head; expected $LOCKED_ORACLE"

cpp_tree=$(git -C "$ghidra_repo" rev-parse \
    "$LOCKED_ORACLE:Ghidra/Features/Decompiler/src/decompile/cpp")
language_tree=$(git -C "$ghidra_repo" rev-parse \
    "$LOCKED_ORACLE:Ghidra/Processors/x86/data/languages")
[ "$cpp_tree" = "$EXPECTED_CPP_TREE" ] || \
    die "decompiler cpp tree=$cpp_tree; expected $EXPECTED_CPP_TREE"
[ "$language_tree" = "$EXPECTED_LANGUAGE_TREE" ] || \
    die "x86 language tree=$language_tree; expected $EXPECTED_LANGUAGE_TREE"

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/rugra-x86-64-sla.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

source_archive="$work_dir/locked-source.tar"
git -C "$ghidra_repo" archive --format=tar --output="$source_archive" "$LOCKED_ORACLE" \
    Ghidra/Features/Decompiler/src/decompile/cpp \
    Ghidra/Processors/x86/data/languages
tar -xf "$source_archive" -C "$work_dir"

cpp_dir="$work_dir/Ghidra/Features/Decompiler/src/decompile/cpp"
language_dir="$work_dir/Ghidra/Processors/x86/data/languages"
compiler="$cpp_dir/sleigh_opt"
slaspec="$language_dir/x86-64.slaspec"
first_sla="$work_dir/x86-64.first.sla"
second_sla="$work_dir/x86-64.second.sla"

check_sha256 "$slaspec" "$EXPECTED_SLASPEC_SHA"
check_sha256 "$language_dir/x86-64.pspec" "$EXPECTED_PSPEC_SHA"
check_sha256 "$language_dir/x86-64-gcc.cspec" "$EXPECTED_CSPEC_SHA"
check_sha256 "$language_dir/x86.ldefs" "$EXPECTED_LDEFS_SHA"

jobs=${RUGRA_SLEIGH_JOBS:-2}

export LC_ALL=C
export TZ=UTC
make -s -C "$cpp_dir" -j"$jobs" sleigh_opt

"$compiler" "$slaspec" "$first_sla"
"$compiler" "$slaspec" "$second_sla"
cmp -s "$first_sla" "$second_sla" || \
    die "two locked SLEIGH compilations produced different bytes"
check_sha256 "$first_sla" "$EXPECTED_SLA_SHA"

sla_size=$(wc -c < "$first_sla")
sla_size=$(printf '%s' "$sla_size" | tr -d '[:space:]')
[ "$sla_size" = "$EXPECTED_SLA_SIZE" ] || \
    die "generated SLA size=$sla_size; expected $EXPECTED_SLA_SIZE"

mkdir -p "$output_dir"
install -m 0644 "$first_sla" "$output_dir/x86-64.sla"
install -m 0644 "$language_dir/x86-64.pspec" "$output_dir/x86-64.pspec"
install -m 0644 "$language_dir/x86-64-gcc.cspec" "$output_dir/x86-64-gcc.cspec"

echo "build_locked_x86_64_sla: OK"
echo "  oracle=$LOCKED_ORACLE"
echo "  sla_sha256=$EXPECTED_SLA_SHA"
echo "  pspec_sha256=$EXPECTED_PSPEC_SHA"
echo "  cspec_sha256=$EXPECTED_CSPEC_SHA"
echo "  ldefs_sha256=$EXPECTED_LDEFS_SHA"
