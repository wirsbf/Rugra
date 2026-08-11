#!/usr/bin/env python3
"""Generate Rugra's locked-Ghidra function ledger and dependency inventories.

The generated files are observations, not alignment claims.  In particular,
an exact source annotation proves provenance only; behavior remains UNTESTED
until a locked oracle fixture records a complete MATCH.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

try:
    from .rust_fn_scanner import RustFunction, mask_non_code, scan_rust_functions
except ImportError:
    from rust_fn_scanner import RustFunction, mask_non_code, scan_rust_functions


ORACLE_COMMIT = "e40ed13014025f82488b1f8f7bca566894ac376b"
EXPECTED_COUNTS = {
    "cc_definition": 5691,
    "cc_prototype": 101,
    "hh_definition": 3803,
    "hh_prototype": 6216,
}
GHIDRA_MARKER_RE = re.compile(
    r"//\s*Ghidra:\s*(?P<file>[A-Za-z0-9_.-]+\.(?:cc|hh)):(?P<line>\d+)(?:\s+(?P<label>.*?))?\s*$"
)
GLUE_MARKER_RE = re.compile(r"//\s*RUGRA-GLUE:\s*(?P<reason>.*?)\s*$")
CPP_ASSIGN_RE = re.compile(r"(?<![A-Za-z0-9_])(?P<name>[A-Z][A-Z0-9_]{2,})\s*=\s*(?P<value>[^,;/}]+)")
CPP_ID_RE = re.compile(
    r"\b(?P<kind>AttributeId|ElementId)\s+(?P<name>[A-Z][A-Z0-9_]+)\s*\([^,]+,\s*(?P<value>[^)]+)\)"
)
RUST_CONST_RE = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?const\s+(?P<name>[A-Z][A-Z0-9_]{2,})\s*:[^=;]+\s*=\s*(?P<value>[^;]+);"
)
RUST_CRATE_REF_RE = re.compile(r"\bcrate::(?P<path>[A-Za-z_][A-Za-z0-9_:]*)")
CPP_INCLUDE_RE = re.compile(r'^\s*#\s*include\s+"(?P<name>[A-Za-z0-9_.-]+\.hh)"', re.MULTILINE)
TODO_ID_RE = re.compile(r"`(?P<id>[A-Z][A-Z0-9_-]+)`")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_id(prefix: str, parts: Iterable[object]) -> str:
    digest = hashlib.sha256()
    for part in parts:
        encoded = str(part).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return f"{prefix}-{digest.hexdigest()[:20]}"


def command_output(command: list[str], cwd: Path) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n{result.stderr}"
        )
    return result.stdout


def verify_oracle(root: Path) -> Path:
    ghidra = root / "ghidra"
    commit = command_output(["git", "rev-parse", "HEAD"], ghidra).strip()
    if commit != ORACLE_COMMIT:
        raise RuntimeError(f"wrong Ghidra oracle: expected {ORACLE_COMMIT}, got {commit}")
    dirty = command_output(
        ["git", "status", "--porcelain", "--untracked-files=no"], ghidra
    ).strip()
    if dirty:
        raise RuntimeError(f"locked Ghidra worktree has tracked changes:\n{dirty}")
    cpp = ghidra / "Ghidra/Features/Decompiler/src/decompile/cpp"
    cc_count = len(list(cpp.glob("*.cc")))
    if cc_count != 114:
        raise RuntimeError(f"wrong Ghidra source closure: expected 114 .cc, got {cc_count}")
    return cpp


def ctags_entries(root: Path, cpp: Path) -> tuple[list[dict[str, object]], str]:
    ctags = shutil.which("ctags")
    if ctags is None:
        raise RuntimeError("Universal Ctags is required")
    version = command_output([ctags, "--version"], root).splitlines()[0]
    if "Universal Ctags" not in version:
        raise RuntimeError(f"unsupported ctags implementation: {version}")
    files = sorted(cpp.glob("*.cc")) + sorted(cpp.glob("*.hh"))
    command = [
        ctags,
        "--output-format=json",
        "--fields=+neKStz",
        "--extras=+F",
        "--kinds-C++=+p",
        "-o",
        "-",
        *[str(path.relative_to(root)) for path in files],
    ]
    raw = command_output(command, root)
    entries: list[dict[str, object]] = []
    for line in raw.splitlines():
        item = json.loads(line)
        if item.get("_type") != "tag" or item.get("kind") not in ("function", "prototype"):
            continue
        path = str(item["path"])
        line_number = int(item["line"])
        end = int(item.get("end", line_number))
        kind = "definition" if item["kind"] == "function" else "prototype"
        suffix = Path(path).suffix[1:]
        scope = str(item.get("scope", ""))
        name = str(item["name"])
        arguments = str(item.get("signature", ""))
        typeref = str(item.get("typeref", ""))
        return_type = typeref.removeprefix("typename:")
        qualified_name = f"{scope}::{name}" if scope else name
        complete_signature = f"{qualified_name}{arguments}"
        if return_type:
            complete_signature = f"{return_type} {complete_signature}"
        entries.append(
            {
                "path": path,
                "file": Path(path).name,
                "source_kind": suffix,
                "entry_kind": kind,
                "line": line_number,
                "end_line": max(line_number, end),
                "name": name,
                "scope": scope,
                "qualified_name": qualified_name,
                "arguments": arguments,
                "return_type": return_type,
                "signature": complete_signature,
                "file_scope": bool(item.get("file")),
                "rust_mappings": [],
                "behavior_status": "UNTESTED" if kind == "definition" else "DECLARATION",
            }
        )
    entries.sort(
        key=lambda entry: (
            entry["path"],
            entry["line"],
            entry["entry_kind"],
            entry["scope"],
            entry["name"],
            entry["arguments"],
        )
    )
    assign_unique_ids(entries, "GH12-F")
    return entries, version


def assign_unique_ids(entries: list[dict[str, object]], prefix: str) -> None:
    groups: dict[str, list[dict[str, object]]] = defaultdict(list)
    for entry in entries:
        base = stable_id(
            prefix,
            (
                entry.get("path", ""),
                entry.get("entry_kind", ""),
                entry.get("scope", ""),
                entry.get("name", ""),
                entry.get("arguments", ""),
            ),
        )
        groups[base].append(entry)
    for base, group in groups.items():
        for ordinal, entry in enumerate(group, 1):
            entry["id"] = base if len(group) == 1 else f"{base}-{ordinal:02d}"


def validate_ctags_counts(entries: list[dict[str, object]]) -> dict[str, int]:
    counts = Counter(
        f"{entry['source_kind']}_{entry['entry_kind']}" for entry in entries
    )
    actual = {key: counts.get(key, 0) for key in EXPECTED_COUNTS}
    if actual != EXPECTED_COUNTS:
        raise RuntimeError(f"ctags denominator drift: expected {EXPECTED_COUNTS}, got {actual}")
    return actual


def marker_above(lines: list[str], record: RustFunction) -> tuple[str, dict[str, object]]:
    position = record.start_line - 1
    while position >= 0:
        stripped = lines[position].strip()
        if not stripped or stripped.startswith("#[") or stripped.startswith("#!["):
            position -= 1
            continue
        if stripped.startswith("//"):
            ghidra = GHIDRA_MARKER_RE.search(stripped)
            if ghidra:
                return (
                    "ghidra",
                    {
                        "file": ghidra.group("file"),
                        "line": int(ghidra.group("line")),
                        "label": (ghidra.group("label") or "").strip(),
                    },
                )
            glue = GLUE_MARKER_RE.search(stripped)
            if glue:
                return "glue", {"reason": glue.group("reason").strip()}
            position -= 1
            continue
        break
    return "missing", {}


def rust_entries(root: Path, ghidra_entries: list[dict[str, object]]) -> list[dict[str, object]]:
    exact_index: dict[tuple[str, int], list[dict[str, object]]] = defaultdict(list)
    span_index: dict[str, list[dict[str, object]]] = defaultdict(list)
    for entry in ghidra_entries:
        exact_index[(str(entry["file"]), int(entry["line"]))].append(entry)
        span_index[str(entry["file"])].append(entry)

    rust: list[dict[str, object]] = []
    for path in sorted((root / "src").rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        relative = path.relative_to(root).as_posix()
        name_ordinals: Counter[str] = Counter()
        for record in scan_rust_functions(text):
            name_ordinals[record.name] += 1
            annotation_kind, annotation = marker_above(lines, record)
            rust_entry: dict[str, object] = {
                "id": stable_id("RG-F", (relative, record.name, name_ordinals[record.name])),
                "path": relative,
                "name": record.name,
                "name_ordinal": name_ordinals[record.name],
                "line": record.start_line + 1,
                "end_line": record.end_line + 1,
                "is_test": record.is_test,
                "is_declaration": record.is_declaration,
                "annotation_kind": "test" if record.is_test else annotation_kind,
                "annotation": annotation,
                "ghidra_mappings": [],
                "behavior_status": "TEST" if record.is_test else "UNTESTED",
            }
            if not record.is_test and annotation_kind == "ghidra":
                file_name = str(annotation["file"])
                line_number = int(annotation["line"])
                candidates = exact_index.get((file_name, line_number), [])
                exact = bool(candidates)
                mapping_kind = "exact_source_start"
                if not candidates:
                    containing = [
                        entry
                        for entry in span_index.get(file_name, [])
                        if int(entry["line"]) <= line_number <= int(entry["end_line"])
                    ]
                    if containing:
                        smallest = min(int(item["end_line"]) - int(item["line"]) for item in containing)
                        candidates = [
                            item
                            for item in containing
                            if int(item["end_line"]) - int(item["line"]) == smallest
                        ]
                        mapping_kind = "inside_function_body"
                    else:
                        mapping_kind = "unresolved_reference"
                for candidate in candidates:
                    candidate_mapping_kind = mapping_kind
                    if exact:
                        candidate_mapping_kind = (
                            "exact_definition_start"
                            if candidate["entry_kind"] == "definition"
                            else "exact_declaration_start"
                        )
                    mapping = {"ghidra_id": candidate["id"], "kind": candidate_mapping_kind}
                    rust_entry["ghidra_mappings"].append(mapping)
                    candidate["rust_mappings"].append(
                        {"rust_id": rust_entry["id"], "kind": candidate_mapping_kind}
                    )
                if mapping_kind == "unresolved_reference":
                    rust_entry["behavior_status"] = "NO_ORACLE"
            elif not record.is_test and annotation_kind == "missing":
                rust_entry["behavior_status"] = "NO_ORACLE"
            rust.append(rust_entry)
    rust.sort(key=lambda entry: (entry["path"], entry["line"], entry["name"]))
    return rust


def clean_value(value: str) -> str:
    return " ".join(value.strip().split())


def protocol_entries(root: Path, cpp: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for path in sorted(cpp.glob("*.cc")) + sorted(cpp.glob("*.hh")):
        relative = path.relative_to(root).as_posix()
        source = path.read_text(encoding="utf-8", errors="replace")
        for line_number, line in enumerate(mask_non_code(source).splitlines(), 1):
            for match in CPP_ID_RE.finditer(line):
                entries.append(
                    {
                        "language": "cpp",
                        "kind": match.group("kind"),
                        "name": match.group("name"),
                        "value": clean_value(match.group("value")),
                        "path": relative,
                        "line": line_number,
                    }
                )
            for match in CPP_ASSIGN_RE.finditer(line):
                value = clean_value(match.group("value"))
                if value and len(value) <= 120:
                    entries.append(
                        {
                            "language": "cpp",
                            "kind": "constant_assignment",
                            "name": match.group("name"),
                            "value": value,
                            "path": relative,
                            "line": line_number,
                        }
                    )
    for path in sorted((root / "src").rglob("*.rs")):
        relative = path.relative_to(root).as_posix()
        source = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(mask_non_code(source).splitlines(), 1):
            for match in RUST_CONST_RE.finditer(line):
                value = clean_value(match.group("value"))
                if value and len(value) <= 120:
                    entries.append(
                        {
                            "language": "rust",
                            "kind": "const",
                            "name": match.group("name"),
                            "value": value,
                            "path": relative,
                            "line": line_number,
                        }
                    )
    deduplicated: dict[tuple[object, ...], dict[str, object]] = {}
    for entry in entries:
        key = tuple(entry[field] for field in ("language", "kind", "name", "value", "path", "line"))
        deduplicated[key] = entry
    result = sorted(
        deduplicated.values(),
        key=lambda entry: (entry["name"], entry["language"], entry["path"], entry["line"]),
    )
    for entry in result:
        entry["id"] = stable_id(
            "PROTO", (entry["language"], entry["kind"], entry["name"], entry["path"], entry["line"])
        )
    return result


def protocol_document(entries: list[dict[str, object]]) -> dict[str, object]:
    by_name: dict[str, list[dict[str, object]]] = defaultdict(list)
    for entry in entries:
        by_name[str(entry["name"])].append(entry)
    candidates = []
    for name, group in sorted(by_name.items()):
        languages = {str(entry["language"]) for entry in group}
        if languages != {"cpp", "rust"}:
            continue
        candidates.append(
            {
                "name": name,
                "status": "CANDIDATE_ONLY",
                "cpp_values": sorted({str(entry["value"]) for entry in group if entry["language"] == "cpp"}),
                "rust_values": sorted({str(entry["value"]) for entry in group if entry["language"] == "rust"}),
            }
        )
    return {
        "schema": 1,
        "oracle_commit": ORACLE_COMMIT,
        "semantics": "Raw protocol-sensitive observations; equal names are candidates, not equivalence claims.",
        "entries": entries,
        "cross_language_candidates": candidates,
    }


def rust_module_name(root: Path, path: Path) -> str:
    relative = path.relative_to(root / "src").with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "mod":
        parts = parts[:-1]
    return "::".join(parts)


def dependency_dag(root: Path, cpp: Path) -> dict[str, object]:
    rust_paths = sorted((root / "src").rglob("*.rs"))
    module_by_path = {path: rust_module_name(root, path) for path in rust_paths}
    modules = set(module_by_path.values())
    rust_edges: set[tuple[str, str]] = set()
    for path, source in module_by_path.items():
        text = path.read_text(encoding="utf-8")
        for match in RUST_CRATE_REF_RE.finditer(text):
            parts = match.group("path").split("::")
            targets = ["::".join(parts[:size]) for size in range(len(parts), 0, -1)]
            target = next((candidate for candidate in targets if candidate in modules), None)
            if target and target != source:
                rust_edges.add((source, target))

    ghidra_edges: set[tuple[str, str]] = set()
    ghidra_nodes = {path.name for path in cpp.glob("*.cc")} | {path.name for path in cpp.glob("*.hh")}
    for path in sorted(cpp.glob("*.cc")) + sorted(cpp.glob("*.hh")):
        for match in CPP_INCLUDE_RE.finditer(path.read_text(encoding="utf-8", errors="replace")):
            target = match.group("name")
            if target in ghidra_nodes and target != path.name:
                ghidra_edges.add((path.name, target))

    todo_edges: set[tuple[str, str]] = set()
    todo_nodes: set[str] = set()
    for line in (root / "docs/TODO_BOARD.md").read_text(encoding="utf-8").splitlines():
        if not line.startswith("| `"):
            continue
        fields = line.split("|")
        if len(fields) < 8:
            continue
        source_match = TODO_ID_RE.search(fields[1])
        if not source_match:
            continue
        source = source_match.group("id")
        todo_nodes.add(source)
        for match in TODO_ID_RE.finditer(fields[7]):
            target = match.group("id")
            todo_nodes.add(target)
            if target != source:
                todo_edges.add((source, target))
    return {
        "schema": 1,
        "oracle_commit": ORACLE_COMMIT,
        "rust_modules": sorted(modules),
        "rust_edges": [{"from": source, "to": target} for source, target in sorted(rust_edges)],
        "ghidra_files": sorted(ghidra_nodes),
        "ghidra_include_edges": [
            {"from": source, "to": target} for source, target in sorted(ghidra_edges)
        ],
        "todo_nodes": sorted(todo_nodes),
        "todo_dependency_edges": [
            {"from": source, "to": target} for source, target in sorted(todo_edges)
        ],
    }


def ledger_document(
    root: Path,
    ghidra: list[dict[str, object]],
    rust: list[dict[str, object]],
    ctags_version: str,
    counts: dict[str, int],
) -> dict[str, object]:
    exact = sum(
        1
        for entry in ghidra
        if any(mapping["kind"] == "exact_definition_start" for mapping in entry["rust_mappings"])
    )
    body = sum(
        1
        for entry in ghidra
        if any(mapping["kind"] == "inside_function_body" for mapping in entry["rust_mappings"])
    )
    definitions = counts["cc_definition"] + counts["hh_definition"]
    declarations = counts["cc_prototype"] + counts["hh_prototype"]
    production = [entry for entry in rust if not entry["is_test"]]
    return {
        "schema": 1,
        "oracle": {
            "tag": "Ghidra_12.0.4_build",
            "commit": ORACLE_COMMIT,
            "cc_file_count": 114,
            "ctags": ctags_version,
        },
        "semantics": {
            "annotation_is_provenance_only": True,
            "default_behavior_status": "UNTESTED",
            "completion_rule": "Only a complete locked-oracle MATCH may change a definition to MATCH.",
        },
        "summary": {
            **counts,
            "behavior_definition_denominator": definitions,
            "declaration_reference_count": declarations,
            "raw_function_records": len(ghidra),
            "ghidra_records_with_exact_rust_mapping": exact,
            "ghidra_records_with_body_reference": body,
            "rugra_function_records": len(rust),
            "rugra_production_functions": len(production),
            "rugra_test_functions": len(rust) - len(production),
            "rugra_declarations": sum(bool(entry["is_declaration"]) for entry in rust),
            "rugra_glue_functions": sum(entry["annotation_kind"] == "glue" for entry in production),
            "rugra_unresolved_or_missing": sum(
                entry["behavior_status"] == "NO_ORACLE" for entry in production
            ),
        },
        "inputs": {
            "generator_sha256": sha256_file(Path(__file__).resolve()),
            "rust_scanner_sha256": sha256_file(root / "tools/rust_fn_scanner.py"),
        },
        "ghidra_functions": ghidra,
        "rugra_functions": rust,
    }


def markdown_summary(ledger: dict[str, object]) -> str:
    summary = ledger["summary"]
    rows: dict[str, Counter[str]] = defaultdict(Counter)
    for entry in ledger["ghidra_functions"]:
        if entry["entry_kind"] != "definition":
            continue
        mappings = entry["rust_mappings"]
        status = "unmapped"
        if any(mapping["kind"] == "exact_definition_start" for mapping in mappings):
            status = "exact"
        elif any(mapping["kind"] == "inside_function_body" for mapping in mappings):
            status = "body-ref"
        rows[entry["file"]][status] += 1
        rows[entry["file"]]["definitions"] += 1
    lines = [
        "# Generated Ghidra 12.0.4 Function Map",
        "",
        "> Generated by `tools/generate_function_ledger.py`; do not edit by hand.",
        "> An annotation is provenance only. Every behavior status defaults to `UNTESTED`.",
        "",
        f"- Oracle commit: `{ORACLE_COMMIT}`",
        f"- Behavior definition denominator: **{summary['behavior_definition_denominator']}**",
        f"  ({summary['cc_definition']} `.cc` + {summary['hh_definition']} inline `.hh` definitions)",
        f"- Declaration references: {summary['declaration_reference_count']}",
        f"- Raw Ctags function records: {summary['raw_function_records']}",
        f"- Rugra functions: {summary['rugra_function_records']}",
        f"  ({summary['rugra_production_functions']} production + {summary['rugra_test_functions']} test)",
        f"- Exact definition-start mappings: {summary['ghidra_records_with_exact_rust_mapping']}",
        f"- Body-line references requiring audit: {summary['ghidra_records_with_body_reference']}",
        "",
        "The old hand-maintained `~2055` denominator is not a completion metric. The generated",
        "9494-definition denominator remains entirely `UNTESTED` unless a locked behavior fixture",
        "records complete same-input/same-output evidence.",
        "",
        "## Definition coverage by oracle file",
        "",
        "| File | Definitions | Exact marker | Body-line marker | Unmapped |",
        "|---|---:|---:|---:|---:|",
    ]
    for file_name in sorted(rows):
        counter = rows[file_name]
        lines.append(
            f"| `{file_name}` | {counter['definitions']} | {counter['exact']} | "
            f"{counter['body-ref']} | {counter['unmapped']} |"
        )
    lines.extend(
        [
            "",
            "Machine-readable records, stable IDs, signatures, spans, mapping kinds, and statuses",
            "are in `FUNCTION_LEDGER.json`. Protocol constants and dependency edges are emitted",
            "separately so fixture selection never has to scrape this Markdown table.",
            "",
        ]
    )
    return "\n".join(lines)


def canonical_json(document: object) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_or_check(path: Path, content: str, check: bool) -> None:
    if check:
        existing = path.read_text(encoding="utf-8") if path.is_file() else ""
        if existing != content:
            raise RuntimeError(f"generated file is stale: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def self_test() -> int:
    first = stable_id("X", ("a", 1, "b"))
    assert first == stable_id("X", ("a", 1, "b"))
    assert first != stable_id("X", ("a", 2, "b"))
    fixture = [
        {"path": "x.cc", "entry_kind": "definition", "scope": "A", "name": "f", "arguments": "()", "line": 1},
        {"path": "x.cc", "entry_kind": "definition", "scope": "A", "name": "f", "arguments": "()", "line": 9},
    ]
    assign_unique_ids(fixture, "X")
    assert fixture[0]["id"].endswith("-01") and fixture[1]["id"].endswith("-02")
    lines = ["// Ghidra: x.cc:7 A::f", "fn f() {}"]
    record = scan_rust_functions("\n".join(lines))[0]
    kind, marker = marker_above(lines, record)
    assert kind == "ghidra" and marker["file"] == "x.cc" and marker["line"] == 7
    print("generate_function_ledger: self-test OK")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    root = Path(__file__).resolve().parent.parent
    output_dir = args.output_dir.resolve() if args.output_dir else root / "docs/alignment_audit"
    try:
        cpp = verify_oracle(root)
        ghidra, ctags_version = ctags_entries(root, cpp)
        counts = validate_ctags_counts(ghidra)
        rust = rust_entries(root, ghidra)
        ledger = ledger_document(root, ghidra, rust, ctags_version, counts)
        protocols = protocol_document(protocol_entries(root, cpp))
        dag = dependency_dag(root, cpp)
        outputs = {
            output_dir / "FUNCTION_LEDGER.json": canonical_json(ledger),
            output_dir / "FUNCTION_MAP.generated.md": markdown_summary(ledger),
            output_dir / "PROTOCOL_TABLE.json": canonical_json(protocols),
            output_dir / "DEPENDENCY_DAG.json": canonical_json(dag),
        }
        for path, content in outputs.items():
            write_or_check(path, content, args.check)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"generate_function_ledger: {error}", file=sys.stderr)
        return 1
    action = "verified" if args.check else "generated"
    print(
        f"generate_function_ledger: {action} definitions={ledger['summary']['behavior_definition_denominator']} "
        f"raw={ledger['summary']['raw_function_records']} rust={ledger['summary']['rugra_function_records']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
