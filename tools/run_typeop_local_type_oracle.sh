#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

# TYPEOP-LOCALTYPE-DISPATCH-0001 locked Ghidra 12.0.4 oracle-only runner.
# The Rust fixture is pinned but intentionally not compiled in this phase: the
# current source has no TypeOpCall::get_input_local override and no legacy
# AddressSpace::Fspec representation.  A later production slice can extend
# this runner to a bilateral build without changing the captured oracle.

runner_fd_path="/proc/$$/fd/3"
if [[ "${BASH_SOURCE[0]}" != "$runner_fd_path" ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash "$runner_fd_path" "$@"
fi
runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
if [[ -z "$runner_source" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "immutable runner fd does not resolve to a regular file" >&2
  exit 1
fi
repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
runner="$repo_root/tools/run_typeop_local_type_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside the expected repository path" >&2
  exit 1
fi
runner_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')
runner_mode=$(/usr/bin/stat -Lc '%a' "$runner_fd_path")
if [[ "$runner_mode" != 755 ]]; then
  echo "immutable runner mode mismatch: expected=755 actual=$runner_mode" >&2
  exit 1
fi
if [[ $# -ne 0 ]]; then
  echo "usage: $0" >&2
  exit 2
fi

clean_path=/usr/bin:/bin
user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve current user home" >&2
  exit 1
fi
cache_root="$user_home/.cache"
if [[ ! -d "$cache_root" || -L "$cache_root" ]]; then
  echo "cache root is not a real directory: $cache_root" >&2
  exit 1
fi

host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
for tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" \
  "$host_make_bin" "$host_python_bin" "$host_git_bin"; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rugra_base_commit=33793c130fed5a7d0ecb858293dfcfd7bc23b88e
rugra_base_tree=c8b9cd78dc930a00e4ad51d542f7df5d92e7d8dd
rugra_typeop_blob=754391522125b69d12f73bdf301598c773afca38
rugra_funcdata_blob=6607bf4acdc7a2b54a47623d473a999f6996d42e
rugra_space_blob=d3ea6840982f4361845f672862fab3267626ed9d
rugra_fspec_blob=0d186b599d149430849b0c4e8b3a2453746690cd
rugra_op_blob=3198215f593f49ffcd6a97ae7945493209228882
ghidra_root="$repo_root/ghidra"
metadata_live="$repo_root/tests/oracle/typeop_local_type_1204.metadata.json"
cpp_fixture_live="$repo_root/tests/oracle/typeop_local_type_1204.cc"
rust_fixture_live="$repo_root/tests/oracle/typeop_local_type_1204.rs"
bfd_include=/tmp/rugra-ghidra-bfd-2.38/usr/include
bfd_library=/tmp/rugra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so
bfd_library_dir=$(/usr/bin/dirname "$bfd_library")

for required in "$metadata_live" "$cpp_fixture_live" "$rust_fixture_live" \
  "$bfd_include/bfd.h" "$bfd_library"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

actual_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
actual_base_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rugra_base_commit^{tree}")
if [[ "$actual_base_tree" != "$rugra_base_tree" ]]; then
  echo "locked Rugra base tree mismatch" >&2
  exit 1
fi
actual_typeop_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rugra_base_commit:src/typeop.rs")
actual_funcdata_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rugra_base_commit:src/funcdata.rs")
actual_space_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rugra_base_commit:src/space.rs")
actual_fspec_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rugra_base_commit:src/fspec.rs")
actual_op_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rugra_base_commit:src/op.rs")
if [[ "$actual_typeop_blob" != "$rugra_typeop_blob" || \
      "$actual_funcdata_blob" != "$rugra_funcdata_blob" || \
      "$actual_space_blob" != "$rugra_space_blob" || \
      "$actual_fspec_blob" != "$rugra_fspec_blob" || \
      "$actual_op_blob" != "$rugra_op_blob" ]]; then
  echo "locked Rugra source blob mismatch" >&2
  exit 1
fi

verify_owned_inputs() {
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
    - "$metadata_live" "$cpp_fixture_live" "$rust_fixture_live" \
    "$runner_sha" "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" \
    "$oracle_makefile_blob" "$rugra_base_commit" "$rugra_base_tree" \
    "$rugra_typeop_blob" "$rugra_funcdata_blob" "$rugra_space_blob" \
    "$rugra_fspec_blob" "$rugra_op_blob" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    metadata_raw, cpp_raw, rust_raw, runner_sha, oracle_commit, oracle_tag,
    cpp_tree, makefile_blob, base_commit, base_tree, typeop_blob,
    funcdata_blob, space_blob, fspec_blob, op_blob,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

require("metadata schema", metadata["schema_version"], 1)
require("fixture id", metadata["fixture_id"], "TYPEOP-LOCALTYPE-DISPATCH-0001")
require("overall status", metadata["overall_status"], "MISMATCH")
require("oracle capture status", metadata["covered_projection"]["oracle_capture"]["status"], "ORACLE_CAPTURED")
require("Rugra execution status", metadata["covered_projection"]["rugra_execution"]["status"], "UNTESTED")
require("bilateral status", metadata["covered_projection"]["bilateral_comparison"]["status"], "UNTESTED")
require("oracle commit", metadata["oracle"]["commit"], oracle_commit)
require("oracle tag", metadata["oracle"]["tag"], oracle_tag)
require("oracle C++ tree", metadata["oracle"]["decompiler_cpp_tree"], cpp_tree)
require("oracle Makefile blob", metadata["oracle"]["decompiler_makefile_blob"], makefile_blob)
require("base commit", metadata["comparand"]["rugra_base_commit"], base_commit)
require("base tree", metadata["comparand"]["rugra_base_tree"], base_tree)
require("typeop source blob", metadata["comparand"]["source_blobs"]["src/typeop.rs"], typeop_blob)
require("funcdata source blob", metadata["comparand"]["source_blobs"]["src/funcdata.rs"], funcdata_blob)
require("space source blob", metadata["comparand"]["source_blobs"]["src/space.rs"], space_blob)
require("fspec source blob", metadata["comparand"]["source_blobs"]["src/fspec.rs"], fspec_blob)
require("op source blob", metadata["comparand"]["source_blobs"]["src/op.rs"], op_blob)
require("snapshot model", metadata["comparand"]["snapshot_model"], "locked Ghidra archive plus locked Rugra assets; Rust fixture pinned but not compiled")
require("C++ fixture hash", sha(cpp_raw), metadata["comparand"]["cpp_fixture_sha256"])
require("Rust fixture hash", sha(rust_raw), metadata["comparand"]["rust_fixture_sha256"])
require("runner hash", runner_sha, metadata["comparand"]["runner_sha256"])
PY
}

verify_owned_inputs

oracle_tmp=$(/usr/bin/mktemp -d "$cache_root/rugra-typeop-localtype-1204.XXXXXX")
cleanup() {
  case "$oracle_tmp" in
    "$cache_root"/rugra-typeop-localtype-1204.??????) /usr/bin/rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

oracle_source="$oracle_tmp/oracle-source"
rugra_assets="$oracle_tmp/rugra-assets"
/usr/bin/mkdir -p "$oracle_source" "$rugra_assets"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -xf - -C "$oracle_source"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" archive "$rugra_base_commit" \
  examples/curl sleigh_specs | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -xf - -C "$rugra_assets"
oracle_cpp="$oracle_source/Ghidra/Features/Decompiler/src/decompile/cpp"
spec_root="$rugra_assets/sleigh_specs"
binary="$rugra_assets/examples/curl"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$metadata_live" "$oracle_cpp" "$spec_root" "$binary" \
  "$bfd_include/bfd.h" "$bfd_library" "$host_cxx_bin" "$host_cc_bin" \
  "$host_ar_bin" "$host_make_bin" "$host_python_bin" "$host_git_bin" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_raw, cpp_raw, spec_raw, binary_raw, bfd_header_raw,
    bfd_library_raw, host_cxx, host_cc, host_ar, host_make, host_python,
    host_git,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
cpp = pathlib.Path(cpp_raw)
spec = pathlib.Path(spec_raw)

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

source_paths = {
    "typeop_cc_sha256": cpp / "typeop.cc",
    "typeop_hh_sha256": cpp / "typeop.hh",
    "funcdata_varnode_cc_sha256": cpp / "funcdata_varnode.cc",
}
for key, path in source_paths.items():
    require(key, sha(path), metadata["oracle"][key])

asset_paths = {
    "sla_sha256": spec / "x86-64.sla",
    "pspec_sha256": spec / "x86-64.pspec",
    "cspec_sha256": spec / "x86-64-gcc.cspec",
    "ldefs_sha256": spec / "x86.ldefs",
    "binary_sha256": pathlib.Path(binary_raw),
    "bfd_header_sha256": pathlib.Path(bfd_header_raw),
    "bfd_library_sha256": pathlib.Path(bfd_library_raw),
}
for key, path in asset_paths.items():
    require(key, sha(path), metadata["assets"][key])

host = metadata["host_tools"]
require("host cxx", subprocess.check_output([host_cxx, "--version"], text=True).splitlines()[0], host["cxx"])
require("host cxx target", subprocess.check_output([host_cxx, "-dumpmachine"], text=True).strip(), host["cxx_target"])
require("host cc", subprocess.check_output([host_cc, "--version"], text=True).splitlines()[0], host["cc"])
require("host cc target", subprocess.check_output([host_cc, "-dumpmachine"], text=True).strip(), host["cc_target"])
require("host ar", subprocess.check_output([host_ar, "--version"], text=True).splitlines()[0], host["ar"])
require("host make", subprocess.check_output([host_make, "--version"], text=True).splitlines()[0], host["make"])
require("host python", subprocess.check_output([host_python, "--version"], text=True).strip(), host["python"])
require("host git", subprocess.check_output([host_git, "--version"], text=True).strip(), host["git"])
PY

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_make_bin" --no-print-directory -C "$oracle_cpp" -j4 \
  "CXX=$host_cxx_bin -std=c++11" "EXTRA=" libdecomp.a \
  >"$oracle_tmp/make.stdout" 2>"$oracle_tmp/make.stderr"; then
  /usr/bin/cat "$oracle_tmp/make.stdout" >&2
  /usr/bin/cat "$oracle_tmp/make.stderr" >&2
  exit 1
fi
standard_archive="$oracle_cpp/libdecomp.a"
if [[ ! -f "$standard_archive" || -L "$standard_archive" ]]; then
  echo "locked Makefile did not produce a regular libdecomp.a" >&2
  exit 1
fi

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" \
  -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$bfd_include" -I"$oracle_cpp" \
  "$cpp_fixture_live" "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$standard_archive" \
  "$bfd_library" -lz -o "$oracle_tmp/typeop_local_type_1204_cpp" \
  >"$oracle_tmp/cxx.stdout" 2>"$oracle_tmp/cxx.stderr"; then
  /usr/bin/cat "$oracle_tmp/cxx.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cxx.stderr" >&2
  exit 1
fi

for run in 1 2; do
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C LD_LIBRARY_PATH="$bfd_library_dir" \
    "$oracle_tmp/typeop_local_type_1204_cpp" "$spec_root" "$binary" \
    >"$oracle_tmp/ghidra.$run.stdout" 2>"$oracle_tmp/ghidra.$run.stderr"
done
if ! /usr/bin/cmp -s "$oracle_tmp/ghidra.1.stdout" "$oracle_tmp/ghidra.2.stdout" || \
   ! /usr/bin/cmp -s "$oracle_tmp/ghidra.1.stderr" "$oracle_tmp/ghidra.2.stderr"; then
  echo "locked oracle repeated runs diverged" >&2
  /usr/bin/diff -u "$oracle_tmp/ghidra.1.stdout" "$oracle_tmp/ghidra.2.stdout" >&2 || true
  /usr/bin/diff -u "$oracle_tmp/ghidra.1.stderr" "$oracle_tmp/ghidra.2.stderr" >&2 || true
  exit 1
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$metadata_live" "$oracle_tmp/ghidra.1.stdout" \
  "$oracle_tmp/ghidra.1.stderr" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
stdout = pathlib.Path(sys.argv[2]).read_bytes()
stderr = pathlib.Path(sys.argv[3]).read_bytes()
capture = metadata["locked_capture"]

if not stdout.endswith(b"\n"):
    raise SystemExit("oracle stdout lacks final newline")
records = stdout.decode("utf-8").splitlines()
stdout_sha = hashlib.sha256(stdout).hexdigest()
stderr_sha = hashlib.sha256(stderr).hexdigest()
if len(records) != capture["records"] or len(stdout) != capture["bytes"]:
    raise SystemExit("locked oracle capture size mismatch")
if stdout_sha != capture["stdout_sha256"]:
    raise SystemExit("locked oracle stdout hash mismatch")
if stderr_sha != capture["stderr_sha256"]:
    raise SystemExit("locked oracle stderr hash mismatch")
if stderr:
    raise SystemExit("locked oracle unexpectedly wrote stderr")

print(f"oracle_records={len(records)} oracle_bytes={len(stdout)} oracle_stdout_sha256={stdout_sha}")
print(f"oracle_stderr_sha256={stderr_sha}")
print("typeop_local_type_1204: oracle_status=ORACLE_CAPTURED rugra_status=UNTESTED overall_status=MISMATCH")
PY

verify_owned_inputs
