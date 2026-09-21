#!/usr/bin/env bash
# Locked-oracle stage projection producer for the next_url pilot of the
# stage-bisect harness (spec v1.1).  Verifies the locked Ghidra tree,
# rebuilds the fixture against an instrumented temporary copy of the
# oracle source, runs the stepping walk, validates the full v1.1 stream,
# and installs the projection at the RAM-disk product path.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/stage_projection_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/stage_projection_1204.cc"
binary="$repo_root/examples/curl"
spec_root="$repo_root/sleigh_specs"
func_entry=4ff0
func_name=next_url
analysis_options=default
projection_out=${RUGRA_STAGE_PROJECTION_OUT:-/dev/shm/rugra-tests/sb-oracle/next_url.oracle.projection}

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
if [[ -n "$(git -C "$repo_root" status --porcelain -- "$cpp_fixture" "$metadata")" ]]; then
  echo "fixture or metadata has uncommitted changes" >&2
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

python3 -I -S - "$metadata" "$cpp_fixture" "$binary" "$spec_root" \
  "$bfd_include/bfd.h" "$bfd_library" "$oracle_commit" "$oracle_tag" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_name,
    cpp_name,
    binary_name,
    spec_root_name,
    bfd_header_name,
    bfd_library_name,
    oracle_commit,
    oracle_tag,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))
if metadata.get("oracle") != {"tag": oracle_tag, "commit": oracle_commit}:
    raise SystemExit("metadata oracle mismatch")
if metadata.get("architecture") != "x86:LE:64:default":
    raise SystemExit("unexpected architecture metadata")
if metadata.get("compiler_spec") != "gcc":
    raise SystemExit("unexpected compiler-spec metadata")

def digest(name):
    return hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()

actual_input = json.dumps(
    metadata["input"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode()
fingerprint = "sha256:" + hashlib.sha256(actual_input).hexdigest()
if metadata.get("input_fingerprint") != fingerprint:
    raise SystemExit("input fingerprint mismatch")
comparands = {"cpp_fixture": cpp_name}
for key, name in comparands.items():
    actual = digest(name)
    if metadata["comparand_sha256"].get(key) != actual:
        raise SystemExit(f"{key} hash mismatch: {actual}")
producer = subprocess.check_output(
    ["git", "hash-object", cpp_name], text=True
).strip()
if metadata["projection_expectations"].get("producer_blob") != producer:
    raise SystemExit(f"producer blob drifted: {producer}")
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

oracle_tmp=$(mktemp -d /tmp/rugra-stage-projection-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-stage-projection-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

git -C "$ghidra_root" archive --format=tar --output="$oracle_tmp/ghidra.tar" \
  "$oracle_commit" Ghidra/Features/Decompiler/src/decompile/cpp
mkdir -p "$oracle_tmp/oracle"
tar -xf "$oracle_tmp/ghidra.tar" -C "$oracle_tmp/oracle"
oracle_cpp="$oracle_tmp/oracle/Ghidra/Features/Decompiler/src/decompile/cpp"

# Observation-only accessor for ActionRestartGroup::curstart (implicitly
# private members; the fixture's access-macro include wrapper only rewrites
# explicit labels).  Same instrumentation as run_action_break_pool_oracle.sh.
python3 -I -S - "$oracle_cpp/action.hh" "$metadata" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
header = pathlib.Path(sys.argv[1])
text = header.read_text(encoding="utf-8")
anchor = (
    "class ActionRestartGroup : public ActionGroup {\n"
    "  int4 maxrestarts;\t\t\t///< Maximum number of restarts allowed\n"
    "  int4 curstart;\t\t\t///< Current restart iteration\n"
    "public:\n"
)
insertion = "  int4 fixtureGetCurstart(void) const { return curstart; }\n"
if text.count(anchor) != 1:
    raise SystemExit("action.hh instrumentation anchor drifted")
text = text.replace(anchor, anchor + insertion)
header.write_text(text, encoding="utf-8")
actual = hashlib.sha256(header.read_bytes()).hexdigest()
expected = metadata["comparand_sha256"]["ghidra_instrumented_action_hh_sha256"]
if actual != expected:
    raise SystemExit(f"instrumented action.hh mismatch: expected={expected} actual={actual}")
PY

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$oracle_cpp" -j "$jobs" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -I"$bfd_include" -I"$oracle_cpp" \
  "$cpp_fixture" \
  "$oracle_cpp/libdecomp.cc" \
  "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" \
  "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" \
  "$oracle_cpp/libdecomp.a" "$bfd_library" -lz \
  -o "$oracle_tmp/stage_projection_1204"

binary_sha=$(sha256sum "$binary" | cut -d' ' -f1)
producer=$(git hash-object "$cpp_fixture")
"$oracle_tmp/stage_projection_1204" "$spec_root" "$binary" "$func_entry" \
  "$oracle_tmp/projection.txt" "$binary_sha" "$producer" "$analysis_options" \
  2>"$oracle_tmp/run.stderr"

python3 -I -S - "$oracle_tmp/projection.txt" "$metadata" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

projection = pathlib.Path(sys.argv[1])
metadata = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
expect = metadata["projection_expectations"]

raw = projection.read_bytes()
if hashlib.sha256(raw).hexdigest() != expect["sha256"]:
    raise SystemExit(f"projection sha256 drifted: {hashlib.sha256(raw).hexdigest()}")
if len(raw) != expect["bytes"]:
    raise SystemExit(f"projection size drifted: {len(raw)}")

lines = raw.decode("utf-8").splitlines()
meta = {}
for line in lines[:4]:
    if not line.startswith("META "):
        raise SystemExit(f"missing META header line: {line[:40]!r}")
    for item in line[5:].split(" "):
        key, _, value = item.partition("=")
        meta[key] = value
fields = {
    "side": "oracle",
    "oracle_commit": metadata["oracle"]["commit"],
    "arch": metadata["architecture"],
    "cspec": metadata["compiler_spec"],
    "analysis_options": "default",
    "build_flags": "v1-no-OPACTION_DEBUG",
    "binary_sha256": metadata["input"]["binary_sha256"],
    "load_mode": metadata["analysis_options"]["load_mode"],
    "producer": expect["producer_blob"],
    "maxrestarts": str(metadata["input"]["maxrestarts"]),
    "unique_base": metadata["input"]["unique_base"],
    "func_name": metadata["input"]["function"],
}
for key, value in fields.items():
    if meta.get(key) != value:
        raise SystemExit(f"META field {key} drifted: {meta.get(key)!r} != {value!r}")

begins, ends, snaps, restarts = {}, {}, [], 0
stack = []
op_lines = 0
pending = None
op_re = re.compile(r"^[0-9a-f]+:[0-9a-f]+ \S+ d=[01] out=\S+ in=\S+$")
vn_re = re.compile(
    r"^(c:[0-9a-f]+:\d+|n:[A-Za-z0-9_]+:[0-9a-f]+:\d+|u:[0-9a-f]+:\d+"
    r"|s:[A-Za-z0-9_]+|f:[0-9a-f]+:[0-9a-f]+|o:[0-9a-f]+:[0-9a-f]+|o:-|-)$"
)
for ln, line in enumerate(lines, 1):
    if line.startswith("META") or line.startswith("@"):
        if pending is not None:
            raise SystemExit(f"line {ln}: @SNAP block truncated")
        if line.startswith("@BEGIN"):
            seq = int(line.split()[1]); begins[seq] = line.split()[2]
            stack.append(seq)
        elif line.startswith("@END"):
            part = line.split()
            seq = int(part[1])
            ends[seq] = part[2]
            if begins.get(seq) != part[2]:
                raise SystemExit(f"line {ln}: seq {seq} path mismatch")
            if not stack or stack[-1] != seq:
                raise SystemExit(f"line {ln}: nesting violation closing seq {seq}")
            stack.pop()
            if not re.match(
                r"^@END \d+ \S+ result=-?\d+ count=-?\d+ tests=\d+ apply=\d+$", line
            ):
                raise SystemExit(f"line {ln}: @END grammar")
        elif line.startswith("@SNAP"):
            pending = int(line.split()[3]); snaps.append(pending)
        elif line.startswith("@RESTART"):
            restarts += 1
    elif pending is not None:
        if not op_re.match(line):
            raise SystemExit(f"line {ln}: op-line grammar: {line[:80]}")
        for token in re.split(r"out=|in=|,", line.split(" ", 3)[3]):
            token = token.strip()
            if token and not vn_re.match(token):
                raise SystemExit(f"line {ln}: varnode descriptor {token!r}")
        op_lines += 1; pending -= 1
        if pending == 0: pending = None
    else:
        raise SystemExit(f"line {ln}: stray record outside @SNAP: {line[:60]!r}")

if len(begins) != expect["begins"] or len(ends) != expect["ends"]:
    raise SystemExit(f"event count drifted: {len(begins)}/{len(ends)}")
if len(snaps) != expect["snaps"]:
    raise SystemExit(f"snapshot count drifted: {len(snaps)}")
if restarts != expect["restarts"]:
    raise SystemExit(f"restart count drifted: {restarts}")
if sorted(begins) != list(range(1, len(begins) + 1)):
    raise SystemExit("seq numbers are not contiguous 1-based")
if set(begins) != set(ends):
    raise SystemExit("@BEGIN/@END seq sets differ")
if stack:
    raise SystemExit(f"unclosed events at EOF: {stack}")
if op_lines != expect["total_op_lines"]:
    raise SystemExit(f"op-line total drifted: {op_lines}")
if max(snaps) != expect["max_snap_ops"] or min(snaps) != expect["min_snap_ops"]:
    raise SystemExit("snapshot size extremes drifted")
PY

install -D -m 0644 "$oracle_tmp/projection.txt" "$projection_out"
python3 -I -S - "$metadata" <<'PY'
import json
import pathlib
import sys

expect = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))[
    "projection_expectations"
]
print(
    "stage_projection_1204: events={begins} snaps={snaps} "
    "ops={total_op_lines} restarts={restarts}".format(**expect)
)
PY
printf 'projection installed at %s\n' "$projection_out"
