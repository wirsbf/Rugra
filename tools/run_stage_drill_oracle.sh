#!/usr/bin/env bash
# Verified runner for the locked-oracle OPACTION_DEBUG stage drill
# (tests/oracle/stage_drill_1204.cc).  Mirrors the guard structure of
# tools/run_pipeline_lifecycle_oracle.sh: oracle identity + dirty-tree
# checks, metadata validation, isolated build, run, and output pinning.
# The oracle library is built with -DOPACTION_DEBUG in a stamp-guarded
# git-archive tree (tools/build_stage_drill_oracle.sh); the shared ghidra
# checkout is never built with the debug define.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/stage_drill_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/stage_drill_1204.cc"
build_script="$repo_root/tools/build_stage_drill_oracle.sh"
binary="$repo_root/examples/curl"
spec_root="$repo_root/sleigh_specs"

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "expected $oracle_tag at $oracle_commit; HEAD=$actual_commit tag=$tag_commit" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp \
    Ghidra/Processors/x86/data/languages; then
  echo "locked Ghidra decompiler/x86 language source is dirty" >&2
  exit 1
fi

bfd_include=${RUGRA_BFD_INCLUDE:-}
if [[ -z "$bfd_include" && -f /usr/include/bfd.h ]]; then
  bfd_include=/usr/include
fi
if [[ -z "$bfd_include" && -f /tmp/rugra-ghidra-bfd-2.38/usr/include/bfd.h ]]; then
  bfd_include=/tmp/rugra-ghidra-bfd-2.38/usr/include
fi
if [[ -z "$bfd_include" || ! -f "$bfd_include/bfd.h" ]]; then
  echo "binutils 2.38 bfd.h not found; set RUGRA_BFD_INCLUDE" >&2
  exit 1
fi
bfd_library=${RUGRA_BFD_LIBRARY:-/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so}
if [[ ! -f "$bfd_library" ]]; then
  echo "binutils 2.38 BFD library not found: $bfd_library" >&2
  exit 1
fi

python3 -I -S - "$metadata" "$cpp_fixture" "$build_script" \
  "$binary" "$spec_root" "$bfd_include/bfd.h" "$bfd_library" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_name,
    cpp_name,
    build_script_name,
    binary_name,
    spec_root_name,
    bfd_header_name,
    bfd_library_name,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))
if metadata.get("oracle") != {
    "tag": "Ghidra_12.0.4_build",
    "commit": "e40ed13014025f82488b1f8f7bca566894ac376b",
}:
    raise SystemExit("metadata oracle mismatch")
if metadata.get("architecture") != "x86:LE:64:default":
    raise SystemExit("unexpected architecture metadata")
if metadata.get("compiler_spec") != "gcc":
    raise SystemExit("unexpected compiler-spec metadata")
if metadata.get("build_flags") != "-DOPACTION_DEBUG":
    raise SystemExit("a drill fixture must record build_flags=-DOPACTION_DEBUG")

def digest(name):
    return hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()

actual_input = json.dumps(
    metadata["input"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode()
fingerprint = "sha256:" + hashlib.sha256(actual_input).hexdigest()
if metadata.get("input_fingerprint") != fingerprint:
    raise SystemExit("input fingerprint mismatch")
comparands = {
    "cpp_fixture": cpp_name,
    "build_script": build_script_name,
}
for key, name in comparands.items():
    actual = digest(name)
    if metadata["comparand_sha256"].get(key) != actual:
        raise SystemExit(f"{key} hash mismatch: {actual}")
assets = {
    "binary_sha256": binary_name,
    "sla_sha256": pathlib.Path(spec_root_name) / "x86-64.sla",
    "pspec_sha256": pathlib.Path(spec_root_name) / "x86-64.pspec",
    "cspec_sha256": pathlib.Path(spec_root_name) / "x86-64-gcc.cspec",
    "ldefs_sha256": pathlib.Path(spec_root_name) / "x86.ldefs",
    "bfd_header_sha256": bfd_header_name,
    "bfd_library_sha256": bfd_library_name,
}
for key, name in assets.items():
    actual = digest(name)
    if metadata["assets"].get(key) != actual:
        raise SystemExit(f"{key} mismatch: {actual}")
compiler = subprocess.check_output(["g++", "--version"], text=True).splitlines()[0]
if metadata.get("host_compiler") != compiler:
    raise SystemExit(f"host compiler mismatch: {compiler}")
PY

bash "$build_script"
drill_bin=${RUGRA_DRILL_WORKROOT:-/dev/shm/rugra-tests/sb-drill/build}/stage_drill_1204
if [[ ! -x "$drill_bin" ]]; then
  echo "drill binary not found after build: $drill_bin" >&2
  exit 1
fi

oracle_tmp=$(mktemp -d /tmp/rugra-stage-drill-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-stage-drill-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

if ! "$drill_bin" "$spec_root" "$binary" \
  >"$oracle_tmp/stage_drill.stdout" 2>"$oracle_tmp/stage_drill.stderr"; then
  cat "$oracle_tmp/stage_drill.stderr" >&2
  exit 1
fi

python3 -I -S - "$metadata" "$oracle_tmp/stage_drill.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
stdout_path = pathlib.Path(sys.argv[2])
text = stdout_path.read_text(encoding="utf-8")
actual = hashlib.sha256(stdout_path.read_bytes()).hexdigest()
expected = metadata["expected_stdout_sha256"]["ghidra"]
if actual != expected:
    raise SystemExit(f"drill stdout drifted: sha256={actual}")
lines = text.splitlines()
meta_line = lines[0] if lines and lines[0].startswith("META ") else ""
for token in ("build_flags=OPACTION_DEBUG", "oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b"):
    if token not in meta_line:
        raise SystemExit(f"META line missing {token}")
done_line = [line for line in lines if line.startswith("@DONE ")]
if len(done_line) != 1:
    raise SystemExit("expected exactly one @DONE line")
done = dict(item.split("=", 1) for item in done_line[0].split()[1:])
for key, value in metadata["observation"]["expected_done"].items():
    if done.get(key) != str(value):
        raise SystemExit(f"@DONE {key} drifted: {done.get(key)} (pinned {value})")
seqs = [
    int(line.split()[1].rstrip(":"))
    for line in lines
    if line.startswith("DEBUG ")
]
if seqs != list(range(len(seqs))):
    raise SystemExit("native DEBUG seq is not strictly 0..N-1")
if len(seqs) != int(done["records"]) or len(seqs) != int(done["opactdbg_final"]):
    raise SystemExit("record count / opactdbg_final disagree with DEBUG headers")
print(f"records={done['records']} opactdbg_final={done['opactdbg_final']} "
      f"applications={done['applications']} perform_calls={done['perform_calls']}")
PY

if [[ -d /dev/shm/rugra-tests/sb-drill ]]; then
  cp "$oracle_tmp/stage_drill.stdout" /dev/shm/rugra-tests/sb-drill/next_url.oracle.drill
fi
printf 'stage_drill_1204: raw oracle capture verified (sha256 pinned in metadata)\n'
