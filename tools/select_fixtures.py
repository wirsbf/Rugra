#!/usr/bin/env python3
"""Select locked oracle fixtures from changed paths and Rust function spans."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

try:
    from .rust_fn_scanner import scan_rust_functions
except ImportError:
    from rust_fn_scanner import scan_rust_functions


HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_git(root: Path, args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def parse_name_status(text: str) -> list[tuple[str, str]]:
    changes: list[tuple[str, str]] = []
    for line in text.splitlines():
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 2:
            raise ValueError(f"unsupported git name-status record: {line!r}")
        changes.append((fields[0][0], fields[1]))
    return changes


def parse_hunks(text: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for line in text.splitlines():
        match = HUNK_RE.match(line)
        if not match:
            continue
        start = int(match.group("start"))
        count = int(match.group("count") or "1")
        ranges.append((start, count))
    return ranges


def diff_arguments(args: argparse.Namespace) -> list[str]:
    if args.staged:
        return ["diff", "--cached", "--no-renames", "HEAD"]
    if args.base:
        return ["diff", "--no-renames", f"{args.base}...HEAD"]
    return ["diff", "--no-renames", "HEAD"]


def changed_paths(root: Path, args: argparse.Namespace) -> list[tuple[str, str]]:
    if args.path:
        return [("M", path) for path in args.path]
    if args.function and not args.staged and not args.base:
        return []
    command = [*diff_arguments(args), "--name-status"]
    changes = parse_name_status(run_git(root, command))
    if not args.staged and not args.base:
        untracked = run_git(root, ["ls-files", "--others", "--exclude-standard"])
        known = {path for _, path in changes}
        changes.extend(("A", path) for path in untracked.splitlines() if path and path not in known)
    return sorted(changes, key=lambda item: item[1])


def hunk_ranges(root: Path, args: argparse.Namespace, path: str) -> list[tuple[int, int]]:
    if args.path:
        return []
    command = [*diff_arguments(args), "--unified=0", "--", path]
    return parse_hunks(run_git(root, command))


def load_json(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema") != 1:
        raise ValueError(f"unsupported schema in {path}")
    return document


def validate_registry(root: Path, registry: dict[str, object]) -> None:
    if registry.get("oracle_commit") != "e40ed13014025f82488b1f8f7bca566894ac376b":
        raise ValueError("fixture registry does not name the locked Ghidra 12.0.4 commit")
    fixture_ids = [str(fixture.get("id", "")) for fixture in registry.get("fixtures", [])]
    if not fixture_ids or len(fixture_ids) != len(set(fixture_ids)) or any(not item for item in fixture_ids):
        raise ValueError("fixture IDs must be non-empty and unique")
    for fixture in registry["fixtures"]:
        runner = fixture.get("runner")
        if not isinstance(runner, list) or not runner:
            raise ValueError(f"fixture {fixture['id']} has no runner argv")
        executable = root / str(runner[0])
        if not executable.is_file() or not executable.stat().st_mode & 0o111:
            raise ValueError(f"fixture runner is missing or not executable: {executable}")
        if int(fixture.get("timeout_seconds", 0)) <= 0:
            raise ValueError(f"fixture {fixture['id']} has an invalid timeout")


def functions_by_path(
    root: Path, ledger: dict[str, object], selected_paths: set[str]
) -> dict[str, list[dict[str, object]]]:
    ledger_index = {
        (str(entry["path"]), str(entry["name"]), int(entry["name_ordinal"])): entry
        for entry in ledger["rugra_functions"]
    }
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for relative in sorted(selected_paths):
        if not (relative.startswith("src/") and relative.endswith(".rs")):
            continue
        path = root / relative
        if not path.is_file():
            continue
        ordinals: Counter[str] = Counter()
        for record in scan_rust_functions(path.read_text(encoding="utf-8")):
            ordinals[record.name] += 1
            if record.is_test:
                continue
            ledger_entry = ledger_index.get((relative, record.name, ordinals[record.name]))
            function_id = (
                str(ledger_entry["id"])
                if ledger_entry
                else "UNLEDGERED-"
                + hashlib.sha256(
                    f"{relative}\0{record.name}\0{ordinals[record.name]}".encode("utf-8")
                ).hexdigest()[:20]
            )
            grouped[relative].append(
                {
                    "id": function_id,
                    "path": relative,
                    "name": record.name,
                    "name_ordinal": ordinals[record.name],
                    "line": record.start_line + 1,
                    "end_line": record.end_line + 1,
                }
            )
    for entries in grouped.values():
        entries.sort(key=lambda entry: (entry["line"], entry["end_line"], entry["id"]))
    return grouped


def functions_for_change(
    path: str,
    status: str,
    ranges: list[tuple[int, int]],
    grouped: dict[str, list[dict[str, object]]],
) -> tuple[list[dict[str, object]], bool]:
    entries = grouped.get(path, [])
    if status in ("A", "D") or not ranges:
        return list(entries), path.startswith("src/") and path.endswith(".rs") and not entries
    selected: dict[str, dict[str, object]] = {}
    top_level = False
    for start, count in ranges:
        if count == 0:
            matches = [entry for entry in entries if int(entry["line"]) <= start <= int(entry["end_line"])]
        else:
            finish = start + count - 1
            matches = [
                entry
                for entry in entries
                if start <= int(entry["end_line"]) and finish >= int(entry["line"])
            ]
        if not matches:
            top_level = True
        for entry in matches:
            selected[str(entry["id"])] = entry
    return sorted(selected.values(), key=lambda entry: entry["id"]), top_level


def resolve_explicit_functions(
    selectors: Iterable[str], ledger: dict[str, object]
) -> list[dict[str, object]]:
    entries = [entry for entry in ledger["rugra_functions"] if not entry["is_test"]]
    resolved: dict[str, dict[str, object]] = {}
    for selector in selectors:
        matches = []
        for entry in entries:
            path_name = f"{entry['path']}::{entry['name']}"
            if selector in (entry["id"], entry["name"], path_name):
                matches.append(entry)
        if not matches:
            raise ValueError(f"Rust function selector did not match: {selector}")
        if len(matches) > 1 and "::" not in selector and not selector.startswith("RG-F-"):
            raise ValueError(f"ambiguous Rust function selector: {selector}")
        for entry in matches:
            resolved[str(entry["id"])] = entry
    return sorted(resolved.values(), key=lambda entry: entry["id"])


def matches_any(path: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def select_fixtures(
    registry: dict[str, object],
    changed: list[dict[str, object]],
    explicit_functions: list[dict[str, object]],
    tier: str | None,
) -> tuple[list[dict[str, object]], list[dict[str, object]], bool]:
    fixtures = registry["fixtures"]
    global_change = any(
        matches_any(str(change["path"]), registry.get("global_paths", [])) for change in changed
    )
    reasons: dict[str, set[str]] = defaultdict(set)
    all_changed_functions = {
        str(function["id"]): function
        for change in changed
        for function in change["functions"]
    }
    all_changed_functions.update({str(entry["id"]): entry for entry in explicit_functions})

    for fixture in fixtures:
        fixture_id = str(fixture["id"])
        impact = fixture["impact"]
        if global_change:
            reasons[fixture_id].add("global-path")
        if tier and tier in fixture.get("always_tiers", []):
            reasons[fixture_id].add(f"tier:{tier}")
        for change in changed:
            path = str(change["path"])
            if matches_any(path, impact.get("paths", [])):
                reasons[fixture_id].add(f"path:{path}")
        fixture_functions = set(impact.get("rust_function_ids", []))
        for function_id in sorted(fixture_functions & set(all_changed_functions)):
            reasons[fixture_id].add(f"function:{function_id}")

    covered_ids = {
        str(function_id)
        for fixture in fixtures
        for function_id in fixture["impact"].get("rust_function_ids", [])
    }
    uncovered: list[dict[str, object]] = []
    for change in changed:
        path = str(change["path"])
        if not (path.startswith("src/") and path.endswith(".rs")):
            continue
        path_fixtures = [
            fixture
            for fixture in fixtures
            if matches_any(path, fixture["impact"].get("paths", []))
        ]
        if path_fixtures:
            continue
        missing_functions = [
            function
            for function in change["functions"]
            if str(function["id"]) not in covered_ids
        ]
        if change["top_level"] or not change["functions"] or missing_functions:
            uncovered.append(
                {
                    "path": path,
                    "top_level": bool(change["top_level"]),
                    "function_ids": [str(function["id"]) for function in missing_functions],
                }
            )

    missing_explicit = [entry for entry in explicit_functions if str(entry["id"]) not in covered_ids]
    for entry in missing_explicit:
        uncovered.append(
            {
                "path": entry["path"],
                "top_level": False,
                "function_ids": [str(entry["id"])],
                "source": "explicit-function",
            }
        )

    fail_closed_all = bool(uncovered)
    if fail_closed_all:
        for fixture in fixtures:
            reasons[str(fixture["id"])].add("fail-closed-uncovered-source")
    selected = []
    for fixture in fixtures:
        fixture_id = str(fixture["id"])
        if fixture_id not in reasons:
            continue
        selected.append({**fixture, "selection_reasons": sorted(reasons[fixture_id])})
    return selected, uncovered, fail_closed_all


def selection_document(root: Path, args: argparse.Namespace) -> dict[str, object]:
    registry_path = root / "tests/oracle/fixture_registry.json"
    ledger_path = root / "docs/alignment_audit/FUNCTION_LEDGER.json"
    registry = load_json(registry_path)
    ledger = load_json(ledger_path)
    validate_registry(root, registry)
    registered_ids = {
        str(function_id)
        for fixture in registry["fixtures"]
        for function_id in fixture["impact"].get("rust_function_ids", [])
    }
    ledger_ids = {str(entry["id"]) for entry in ledger["rugra_functions"]}
    stale_ids = sorted(registered_ids - ledger_ids)
    if stale_ids:
        raise ValueError(f"fixture registry contains stale Rust function IDs: {stale_ids}")
    path_changes = changed_paths(root, args)
    grouped = functions_by_path(root, ledger, {path for _, path in path_changes})
    changed = []
    for status, path in path_changes:
        ranges = hunk_ranges(root, args, path)
        functions, top_level = functions_for_change(path, status, ranges, grouped)
        changed.append(
            {
                "status": status,
                "path": path,
                "hunks": [{"start": start, "count": count} for start, count in ranges],
                "functions": [
                    {"id": entry["id"], "name": entry["name"], "line": entry["line"], "end_line": entry["end_line"]}
                    for entry in functions
                ],
                "top_level": top_level,
            }
        )
    explicit = resolve_explicit_functions(args.function, ledger)
    selected, uncovered, fail_closed = select_fixtures(registry, changed, explicit, args.tier)
    return {
        "schema": 1,
        "oracle_commit": registry["oracle_commit"],
        "mode": "staged" if args.staged else (f"base:{args.base}" if args.base else "worktree"),
        "tier": args.tier,
        "registry_sha256": sha256_file(registry_path),
        "ledger_sha256": sha256_file(ledger_path),
        "changed": changed,
        "explicit_functions": [
            {"id": entry["id"], "path": entry["path"], "name": entry["name"]} for entry in explicit
        ],
        "selected_fixtures": selected,
        "uncovered_source_changes": uncovered,
        "fail_closed_all": fail_closed,
    }


def self_test() -> int:
    assert parse_name_status("M\tsrc/a.rs\nA\tsrc/b.rs\nD\tsrc/c.rs\n") == [
        ("M", "src/a.rs"),
        ("A", "src/b.rs"),
        ("D", "src/c.rs"),
    ]
    assert parse_hunks("@@ -4,2 +7,3 @@\n@@ -20 +23,0 @@\n") == [(7, 3), (23, 0)]
    grouped = {
        "src/a.rs": [
            {"id": "RG-F-a", "line": 5, "end_line": 10},
            {"id": "RG-F-b", "line": 20, "end_line": 30},
        ]
    }
    functions, top = functions_for_change("src/a.rs", "M", [(8, 1)], grouped)
    assert [entry["id"] for entry in functions] == ["RG-F-a"] and not top
    functions, top = functions_for_change("src/a.rs", "M", [(15, 1)], grouped)
    assert not functions and top
    functions, top = functions_for_change("src/a.rs", "A", [], grouped)
    assert len(functions) == 2 and not top
    functions, top = functions_for_change("src/deleted.rs", "D", [], grouped)
    assert not functions and top
    print("select_fixtures: self-test OK")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--base")
    parser.add_argument("--path", action="append", default=[])
    parser.add_argument("--function", action="append", default=[])
    parser.add_argument("--tier", choices=("edit", "commit", "wave", "nightly"))
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    root = Path(__file__).resolve().parent.parent
    try:
        document = selection_document(root, args)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"select_fixtures: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            document,
            indent=2 if args.pretty else None,
            sort_keys=True,
            ensure_ascii=False,
        )
    )
    if args.strict and document["uncovered_source_changes"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
