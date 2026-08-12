#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
metadata="$repo_root/tests/oracle/getstr_pipeline_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/getstr_pipeline_1204.cc"
rust_example="$repo_root/examples/getstr_stage_snapshot.rs"
binary="$repo_root/examples/curl"
spec_root="$repo_root/sleigh_specs"
stage_diff="$repo_root/tools/stage_diff.py"
output_root="$repo_root/result/pipeline_snapshots/getstr"

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
  echo "binutils 2.38 bfd.h not found; set RUGRA_BFD_INCLUDE to its include directory" >&2
  exit 1
fi
bfd_library=${RUGRA_BFD_LIBRARY:-/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so}
if [[ ! -f "$bfd_library" ]]; then
  echo "binutils 2.38 BFD library not found: $bfd_library" >&2
  exit 1
fi

cpp_tree=$(git -C "$ghidra_root" rev-parse HEAD:Ghidra/Features/Decompiler/src/decompile/cpp)
x86_tree=$(git -C "$ghidra_root" rev-parse HEAD:Ghidra/Processors/x86/data/languages)
python3 -I -S - "$metadata" "$cpp_fixture" "$rust_example" "$binary" \
  "$stage_diff" "$spec_root" "$bfd_include/bfd.h" "$bfd_library" \
  "$oracle_commit" "$oracle_tag" "$cpp_tree" "$x86_tree" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_name,
    cpp_fixture_name,
    rust_example_name,
    binary_name,
    stage_diff_name,
    spec_root_name,
    bfd_header_name,
    bfd_library_name,
    oracle_commit,
    oracle_tag,
    cpp_tree,
    x86_tree,
) = sys.argv[1:]

metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))
if metadata.get("oracle") != {"tag": oracle_tag, "commit": oracle_commit}:
    raise SystemExit("metadata oracle tag/commit mismatch")
if metadata.get("architecture") != "x86:LE:64:default":
    raise SystemExit("unexpected architecture metadata")
if metadata.get("compiler_spec") != "gcc":
    raise SystemExit("unexpected compiler spec metadata")
if metadata.get("observation", {}).get("overall_status") != "MISMATCH":
    raise SystemExit("pipeline snapshot must remain MISMATCH until all six layers match")

def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

input_bytes = json.dumps(
    metadata["input"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode()
actual_input_fingerprint = "sha256:" + hashlib.sha256(input_bytes).hexdigest()
if metadata.get("input_fingerprint") != actual_input_fingerprint:
    raise SystemExit("metadata input fingerprint mismatch")

comparands = {
    "cpp_fixture": cpp_fixture_name,
    "rust_example": rust_example_name,
    "stage_diff": stage_diff_name,
}
for key, path in comparands.items():
    actual = digest(path)
    expected = metadata["comparand_sha256"].get(key)
    if actual != expected:
        raise SystemExit(f"comparand hash mismatch for {key}: {actual} != {expected}")

assets = metadata["assets"]
asset_paths = {
    "sla_sha256": pathlib.Path(spec_root_name) / "x86-64.sla",
    "pspec_sha256": pathlib.Path(spec_root_name) / "x86-64.pspec",
    "cspec_sha256": pathlib.Path(spec_root_name) / "x86-64-gcc.cspec",
    "ldefs_sha256": pathlib.Path(spec_root_name) / "x86.ldefs",
    "bfd_header_sha256": pathlib.Path(bfd_header_name),
    "bfd_library_sha256": pathlib.Path(bfd_library_name),
}
for key, path in asset_paths.items():
    actual = digest(path)
    if assets.get(key) != actual:
        raise SystemExit(f"asset hash mismatch for {key}: {actual} != {assets.get(key)}")
if assets.get("ghidra_cpp_tree") != cpp_tree:
    raise SystemExit("locked Ghidra C++ tree mismatch")
if assets.get("ghidra_x86_language_tree") != x86_tree:
    raise SystemExit("locked Ghidra x86 language tree mismatch")
if digest(binary_name) != metadata["input"]["binary_sha256"]:
    raise SystemExit("curl input hash mismatch")

compiler = subprocess.check_output(["g++", "--version"], text=True).splitlines()[0]
rustc = subprocess.check_output(["rustc", "--version"], text=True).strip()
if metadata.get("host_compiler") != compiler:
    raise SystemExit(f"host compiler mismatch: {compiler}")
if metadata.get("host_rustc") != rustc:
    raise SystemExit(f"host rustc mismatch: {rustc}")
PY

source_tree_hash() {
  python3 -I -S - "$repo_root/src" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
digest = hashlib.sha256()
for path in sorted(root.rglob("*.rs")):
    relative = path.relative_to(root).as_posix().encode()
    data = path.read_bytes()
    digest.update(len(relative).to_bytes(8, "big"))
    digest.update(relative)
    digest.update(len(data).to_bytes(8, "big"))
    digest.update(data)
print(digest.hexdigest())
PY
}

rugra_source_before=$(source_tree_hash)
oracle_tmp=$(mktemp -d /tmp/rugra-getstr-pipeline-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-getstr-pipeline-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$oracle_tmp/ghidra" "$oracle_tmp/rugra" "$oracle_tmp/rugra-repeat"
mkdir -p "$output_root/ghidra" "$output_root/rugra" "$output_root/rugra-repeat"
jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$cpp_root" -j "$jobs" EXTRA= libdecomp.a
cp "$cpp_fixture" "$oracle_tmp/fixture.cc"
g++ -std=c++11 -O2 -I"$bfd_include" -I"$cpp_root" \
  "$oracle_tmp/fixture.cc" \
  "$cpp_root/libdecomp.cc" \
  "$cpp_root/sleigh_arch.cc" \
  "$cpp_root/inject_sleigh.cc" \
  "$cpp_root/bfd_arch.cc" \
  "$cpp_root/loadimage_bfd.cc" \
  "$cpp_root/libdecomp.a" "$bfd_library" -lz \
  -o "$oracle_tmp/getstr_pipeline_1204"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --offline --locked --quiet --manifest-path "$repo_root/Cargo.toml" \
  --example getstr_stage_snapshot
rugra_fixture="$oracle_tmp/cargo-target/debug/examples/getstr_stage_snapshot"
if [[ ! -x "$rugra_fixture" ]]; then
  echo "cargo did not produce the GetStr snapshot example" >&2
  exit 1
fi

"$oracle_tmp/getstr_pipeline_1204" "$spec_root" "$binary" "$oracle_tmp/ghidra"
"$rugra_fixture" "$binary" "$oracle_tmp/rugra"
"$rugra_fixture" "$binary" "$oracle_tmp/rugra-repeat"
rugra_source_after=$(source_tree_hash)
if [[ "$rugra_source_before" != "$rugra_source_after" ]]; then
  echo "Rugra source tree changed while the fixture was running" >&2
  exit 1
fi

python3 -I -S - "$oracle_tmp/ghidra" "$oracle_tmp/rugra" "$oracle_tmp/rugra-repeat" <<'PY'
import json
import pathlib
import sys

stages = (
    "00_raw_pcode.json",
    "01_cfg.json",
    "02_heritage_ssa.json",
    "03_action_ir.json",
    "04_structure.json",
    "05_c.json",
)
for directory_name in sys.argv[1:]:
    directory = pathlib.Path(directory_name)
    for expected_stage, name in zip((item[:-5] for item in stages), stages):
        path = directory / name
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("schema") != 1 or document.get("state") != "OK":
            raise SystemExit(f"invalid snapshot envelope: {path}")
        if document.get("stage") != expected_stage:
            raise SystemExit(f"stage label mismatch: {path}")
        path.write_text(
            json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            + "\n",
            encoding="utf-8",
        )
PY

for stage in 00_raw_pcode 01_cfg 02_heritage_ssa 03_action_ir 04_structure 05_c; do
  cp "$oracle_tmp/ghidra/$stage.json" "$output_root/ghidra/$stage.json"
  cp "$oracle_tmp/rugra/$stage.json" "$output_root/rugra/$stage.json"
  cp "$oracle_tmp/rugra-repeat/$stage.json" "$output_root/rugra-repeat/$stage.json"
done

common_context=(
  --context "binary_sha256=4ee4002baf3525d9fef062f9fcb9b7a9a890509b8bc5211740d0155d7c6b5d1a"
  --context "function=GetStr@0x36d0+74"
  --context "rugra_commit=$(git -C "$repo_root" rev-parse HEAD)"
  --context "rugra_src_tree=$rugra_source_before"
)
common_stages=(
  --stage "00_raw_pcode=$output_root/ghidra/00_raw_pcode.json"
  --stage "01_cfg=$output_root/ghidra/01_cfg.json"
  --stage "02_heritage_ssa=$output_root/ghidra/02_heritage_ssa.json"
  --stage "03_action_ir=$output_root/ghidra/03_action_ir.json"
  --stage "04_structure=$output_root/ghidra/04_structure.json"
  --stage "05_c=$output_root/ghidra/05_c.json"
)
python3 "$stage_diff" snapshot --metadata "$metadata" --producer ghidra-12.0.4 \
  "${common_context[@]}" "${common_stages[@]}" \
  --output "$output_root/ghidra.manifest.json"

common_stages=(
  --stage "00_raw_pcode=$output_root/rugra/00_raw_pcode.json"
  --stage "01_cfg=$output_root/rugra/01_cfg.json"
  --stage "02_heritage_ssa=$output_root/rugra/02_heritage_ssa.json"
  --stage "03_action_ir=$output_root/rugra/03_action_ir.json"
  --stage "04_structure=$output_root/rugra/04_structure.json"
  --stage "05_c=$output_root/rugra/05_c.json"
)
python3 "$stage_diff" snapshot --metadata "$metadata" --producer rugra \
  "${common_context[@]}" "${common_stages[@]}" \
  --output "$output_root/rugra.manifest.json"

set +e
python3 "$stage_diff" compare "$output_root/ghidra.manifest.json" \
  "$output_root/rugra.manifest.json" --pretty --report "$output_root/stage-manifest-diff.json"
manifest_status=$?
set -e
if [[ $manifest_status -ne 1 ]]; then
  echo "expected a known stage mismatch, stage_diff rc=$manifest_status" >&2
  exit 1
fi

python3 -I -S - "$metadata" "$output_root" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
root = pathlib.Path(sys.argv[2])
stage_names = (
    "00_raw_pcode",
    "01_cfg",
    "02_heritage_ssa",
    "03_action_ir",
    "04_structure",
    "05_c",
)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def counts(document):
    result = {}
    if document.get("ops"):
        result["ops"] = len(document["ops"])
    if document.get("varnodes"):
        result["varnodes"] = len(document["varnodes"])
    if document.get("blocks"):
        result["blocks"] = len(document["blocks"])
    structure = document.get("structure")
    if isinstance(structure, dict):
        result["root_children"] = len(structure.get("children", []))
    text = document.get("text")
    if isinstance(text, str):
        result["text_bytes"] = len(text.encode())
    return result

def validate_expected(actual, expected, producer, stage):
    for key, value in expected.items():
        if key == "nondeterministic":
            if value is not True:
                raise SystemExit(f"invalid nondeterministic expectation for {producer} {stage}")
        elif key.startswith("min_"):
            field = key[4:]
            if actual.get(field, -1) < value:
                raise SystemExit(
                    f"{producer} {stage} {field}={actual.get(field)} is below minimum {value}"
                )
        elif actual.get(key) != value:
            raise SystemExit(
                f"unexpected {producer} {stage} {key}: "
                f"actual={actual.get(key)} expected={value}"
            )

def first_difference(left, right, path="$", left_label="ghidra", right_label="rugra"):
    if type(left) is not type(right):
        return {"path": path, "kind": "type", left_label: type(left).__name__, right_label: type(right).__name__}
    if isinstance(left, dict):
        left_keys = set(left)
        right_keys = set(right)
        if left_keys != right_keys:
            return {"path": path, "kind": "keys", "ghidra_only": sorted(left_keys-right_keys), "rugra_only": sorted(right_keys-left_keys)}
        for key in sorted(left_keys):
            result = first_difference(left[key], right[key], f"{path}.{key}", left_label, right_label)
            if result is not None:
                return result
        return None
    if isinstance(left, list):
        if len(left) != len(right):
            return {"path": f"{path}.length", "kind": "value", left_label: len(left), right_label: len(right)}
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            result = first_difference(left_item, right_item, f"{path}[{index}]", left_label, right_label)
            if result is not None:
                return result
        return None
    if left != right:
        return {"path": path, "kind": "value", left_label: left, right_label: right}
    return None

documents = {"ghidra": {}, "rugra": {}}
stage_report = []
for stage in stage_names:
    for producer in documents:
        path = root / producer / f"{stage}.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        documents[producer][stage] = document
        expected = metadata["expected"][producer][stage]
        actual = {"sha256": digest(path), **counts(document)}
        validate_expected(actual, expected, producer, stage)
    stage_report.append(
        {
            "stage": stage,
            "ghidra": counts(documents["ghidra"][stage]),
            "rugra": counts(documents["rugra"][stage]),
            "first_difference": first_difference(
                documents["ghidra"][stage], documents["rugra"][stage]
            ),
        }
    )

first = stage_report[0]["first_difference"]
expected_first = metadata["observation"]["first_difference"]
if first != {
    "path": expected_first["path"],
    "kind": "value",
    "ghidra": expected_first["ghidra"],
    "rugra": expected_first["rugra"],
}:
    raise SystemExit(f"first pipeline difference changed: {first}")

ghidra_ops = documents["ghidra"]["00_raw_pcode"]["ops"]
rugra_ops = documents["rugra"]["00_raw_pcode"]["ops"]
substantive = None
for index, (left, right) in enumerate(zip(ghidra_ops, rugra_ops)):
    left_key = (left["address"]["offset"], left["opcode"], len(left["inputs"]))
    right_key = (right["address"]["offset"], right["opcode"], len(right["inputs"]))
    if left_key != right_key:
        substantive = {
            "index": index,
            "ghidra": {"address": left_key[0], "opcode": left_key[1], "input_count": left_key[2]},
            "rugra": {"address": right_key[0], "opcode": right_key[1], "input_count": right_key[2]},
        }
        break
expected_substantive = metadata["observation"]["first_substantive_op_difference"]
for key in ("index", "ghidra", "rugra"):
    if substantive.get(key) != expected_substantive[key]:
        raise SystemExit(f"substantive op difference changed: {substantive}")
substantive["diagnosis"] = expected_substantive["diagnosis"]

repeat_documents = {}
repeat_report = []
for stage in stage_names:
    path = root / "rugra-repeat" / f"{stage}.json"
    repeat = json.loads(path.read_text(encoding="utf-8"))
    repeat_documents[stage] = repeat
    difference = first_difference(
        documents["rugra"][stage], repeat, left_label="primary", right_label="repeat"
    )
    repeat_report.append(
        {
            "stage": stage,
            "first_difference": difference,
            "primary": counts(documents["rugra"][stage]),
            "repeat": counts(repeat),
        }
    )
for item in repeat_report[:3]:
    if item["first_difference"] is not None:
        raise SystemExit(f"Rugra pre-Action stage is unexpectedly nondeterministic: {item}")
first_repeat_difference = next(
    (item for item in repeat_report if item["first_difference"] is not None), None
)
if first_repeat_difference is None or first_repeat_difference["stage"] != "03_action_ir":
    raise SystemExit(
        f"expected first Rugra repeatability difference at 03_action_ir: {first_repeat_difference}"
    )

manifest_diff = json.loads((root / "stage-manifest-diff.json").read_text(encoding="utf-8"))
comparison = {
    "schema": 1,
    "state": "MISMATCH",
    "fixture_id": metadata["fixture_id"],
    "oracle": metadata["oracle"],
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "input_fingerprint": metadata["input_fingerprint"],
    "first_stage_difference": {"stage": stage_names[0], **first},
    "first_substantive_op_difference": substantive,
    "stages": stage_report,
    "rugra_determinism": {
        "state": "MISMATCH" if first_repeat_difference is not None else "NOT_OBSERVED",
        "first_difference": first_repeat_difference,
        "runs": repeat_report,
        "note": metadata["observation"]["rugra_determinism_note"],
    },
    "manifest_comparison": manifest_diff,
    "limitations": metadata["observation"]["untested"],
}
(root / "comparison.json").write_text(
    json.dumps(comparison, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
    encoding="utf-8",
)
(root / "ghidra.c").write_text(documents["ghidra"]["05_c"]["text"], encoding="utf-8")
(root / "rugra.c").write_text(documents["rugra"]["05_c"]["text"], encoding="utf-8")
(root / "rugra-repeat.c").write_text(
    repeat_documents["05_c"]["text"], encoding="utf-8"
)

summary = [
    "# GetStr layered pipeline snapshot",
    "",
    "- Oracle: Ghidra 12.0.4 `e40ed13014025f82488b1f8f7bca566894ac376b`",
    "- Input: `examples/curl`, `GetStr` at `0x36d0`, 74 bytes",
    "- Overall: `MISMATCH`",
    f"- First difference: `{stage_names[0]}` `{first['path']}` = {first['ghidra']} vs {first['rugra']}",
    f"- First substantive op: index {substantive['index']}, Ghidra `0x{substantive['ghidra']['address']:x}` vs Rugra `0x{substantive['rugra']['address']:x}`",
    f"- Diagnosis: {substantive['diagnosis']}",
    f"- Rugra repeatability: {comparison['rugra_determinism']['state']}",
    "",
    "| Stage | Ghidra | Rugra | First structural difference |",
    "|---|---:|---:|---|",
]
for item in stage_report:
    left = ", ".join(f"{key}={value}" for key, value in item["ghidra"].items()) or "envelope"
    right = ", ".join(f"{key}={value}" for key, value in item["rugra"].items()) or "envelope"
    summary.append(f"| `{item['stage']}` | {left} | {right} | `{item['first_difference']['path']}` |")
(root / "README.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
PY

printf 'getstr_pipeline_1204: MISMATCH expected; first=00_raw_pcode $.ops.length 103!=105; Rugra post-Action nondeterminism retained; artifacts=%s\n' "$output_root"
