#!/usr/bin/env python3
"""Generate Rugra's locked-Ghidra function ledger and dependency inventories.

The generated files are observations, not alignment claims.  In particular,
an exact source annotation proves provenance only; behavior remains UNTESTED
until a locked oracle fixture records a complete MATCH.

Function IDs (id scheme 2) are position-independent and ordinal-free:

* Ghidra ``GH12-F-...`` = sha256 over (locked path, entry_kind, complete
  qualified signature) plus, only for otherwise indistinguishable duplicates
  (conditionally compiled macro variants), the preprocessor guard context of
  the definition.  Line numbers and same-name ordinals never enter the ID.
* Rust ``RG-F-...`` = sha256 over (module, owner context, normalized
  signature).  The owner context renders trait impls as ``Type as Trait``,
  records ``macro_rules!`` template scopes by macro name, and qualifies
  nested functions by their parent signature.  ``name_ordinal`` is recorded
  as an observation for legacy consumers but never participates in the ID.

``--migrate`` performs the one-time scheme-1 to scheme-2 rewrite and emits
``FUNCTION_ID_MIGRATION.json``.  ``--reconcile-migration`` is deliberately a
separate operation: it replays the pinned first-parent Rust history from that
immutable source table to the pinned current ledger.  Keeping these two
operations separate prevents a later ledger refresh from silently replacing
the migration's historical origin.  ``--reconcile-continuity`` extends that
immutable baseline through a later pinned source checkpoint without changing
the raw scheme-2 hash or rewriting the baseline migration.
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
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Sequence

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
# A TODO identifier must contain at least one hyphen-separated component.
# This deliberately excludes evidence/status literals such as `MATCH`,
# `MISMATCH`, `NO_ORACLE`, and `UNTESTED` from the dependency graph.
TODO_ID_RE = re.compile(r"`(?P<id>[A-Z][A-Z0-9_]*(?:-[A-Z0-9_]+)+)`")
MARKDOWN_SEPARATOR_RE = re.compile(r"^:?-{3,}:?$")
DEPENDENCY_LABEL_RE = re.compile(
    r"(?:^|[；;])\s*(?:依赖|dependency|dependencies)\s*(?:=|:|：)?\s*"
    r"(?P<body>.*?)(?=[；;]|$)",
    re.IGNORECASE,
)

# Preprocessor conditionals, used only to derive a stable, content-based
# disambiguator for duplicate Ghidra definitions (``#ifdef`` variants).
CPP_CONDITIONAL_RE = re.compile(
    r"^\s*#\s*(?P<kw>if|ifdef|ifndef|elif|else|endif)\b\s*(?P<expr>.*)$"
)

# Rust scope classification for the owner context of a function item.
RUST_MACRO_RULES_RE = re.compile(r"^macro_rules\s*!\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)")
RUST_ITEM_KW_RE = re.compile(
    r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:unsafe\s+|default\s+|auto\s+)*"
    r"(?P<kw>impl|trait|mod|fn|extern)\b"
)
RUST_VIS_PREFIX_RE = re.compile(r"^\s*pub(?:\s*\([^)]*\))?\s+")

ID_SCHEME = {
    "schema": 2,
    "ghidra": (
        "GH12-F = stable_id(prefix, locked_path, entry_kind, complete_qualified_signature"
        "[, preprocessor_guard_disambiguator])"
    ),
    "rust": (
        "RG-F = stable_id(prefix, module, owner_context, normalized_signature); "
        "owner_context renders trait impls as 'Type as Trait', macro_rules! template "
        "scopes as 'macro:NAME', nested functions as 'fn:<parent signature>'; "
        "name_ordinal and line numbers never participate"
    ),
}


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


def preprocessor_guard_context(lines: Sequence[str], target_index: int) -> str:
    """Render the active preprocessor conditional chain at a source line.

    The value is derived from file content only (macro guard expressions),
    never from the line number itself, so it stays stable across unrelated
    insertions, deletions, and moves elsewhere in the file.
    """

    stack: list[list[str | None]] = []
    for index in range(target_index):
        match = CPP_CONDITIONAL_RE.match(lines[index])
        if not match:
            continue
        keyword = match.group("kw")
        expression = match.group("expr").strip()
        if keyword in ("if", "ifdef", "ifndef"):
            if keyword == "ifdef":
                condition = f"defined({expression})"
            elif keyword == "ifndef":
                condition = f"!defined({expression})"
            else:
                condition = f"({expression})"
            stack.append([condition])
        elif keyword == "elif" and stack:
            stack[-1].append(f"({expression})")
        elif keyword == "else" and stack:
            stack[-1].append(None)
        elif keyword == "endif" and stack:
            stack.pop()
    parts: list[str] = []
    for frame in stack:
        if len(frame) == 1:
            parts.append(str(frame[0]))
        elif frame[-1] is None:
            parts.append("!(" + " || ".join(str(item) for item in frame[:-1]) + ")")
        else:
            parts.append(str(frame[-1]))
    return " && ".join(parts)


def assign_ghidra_locked_ids(
    entries: list[dict[str, object]], cpp: Path
) -> list[dict[str, object]]:
    """Assign position-independent Ghidra IDs.

    Collisions (same path + signature + category, e.g. conditionally compiled
    macro variants) are disambiguated by preprocessor guard context; if that
    cannot separate them the assignment fails closed rather than falling back
    to ordinals or line numbers.
    """

    for entry in entries:
        entry["id_disambiguator"] = None
    groups: dict[str, list[dict[str, object]]] = defaultdict(list)
    for entry in entries:
        base = stable_id(
            "GH12-F",
            (entry.get("path", ""), entry.get("entry_kind", ""), entry.get("signature", "")),
        )
        entry["id"] = base
        groups[base].append(entry)
    disambiguated: list[dict[str, object]] = []
    for base, group in groups.items():
        if len(group) == 1:
            continue
        lines_cache: dict[str, list[str]] = {}

        def guard_for(entry: dict[str, object]) -> str:
            file_name = str(entry["file"])
            if file_name not in lines_cache:
                lines_cache[file_name] = (cpp / file_name).read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            return preprocessor_guard_context(lines_cache[file_name], int(entry["line"]) - 1)

        contexts = [guard_for(entry) for entry in group]
        # An empty context ("unconditional") is itself a distinct value; only
        # genuinely indistinguishable members fail closed.
        if len(set(contexts)) == len(contexts):
            for entry, context in zip(group, contexts):
                entry["id"] = stable_id(
                    "GH12-F",
                    (
                        entry.get("path", ""),
                        entry.get("entry_kind", ""),
                        entry.get("signature", ""),
                        context,
                    ),
                )
                entry["id_disambiguator"] = {
                    "kind": "preprocessor_guard",
                    "value": context,
                }
                disambiguated.append(entry)
            continue
        raise RuntimeError(
            "indistinguishable Ghidra function records share one ID key and their "
            "preprocessor guard contexts do not separate them; refusing to guess an "
            "ordinal-free disambiguator:\n"
            + "\n".join(
                f"  {item['path']}:{item['line']} {item['signature']} guard={context!r}"
                for item, context in zip(group, contexts)
            )
        )
    return disambiguated


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
    assign_ghidra_locked_ids(entries, cpp)
    return entries, version


def validate_ctags_counts(entries: list[dict[str, object]]) -> dict[str, int]:
    counts = Counter(
        f"{entry['source_kind']}_{entry['entry_kind']}" for entry in entries
    )
    actual = {key: counts.get(key, 0) for key in EXPECTED_COUNTS}
    if actual != EXPECTED_COUNTS:
        raise RuntimeError(f"ctags denominator drift: expected {EXPECTED_COUNTS}, got {actual}")
    return actual


def marker_above(lines: list[str], start_line: int) -> tuple[str, dict[str, object]]:
    """Find the provenance marker above a function starting at ``start_line``.

    ``start_line`` is the zero-based index of the function's first line, as
    produced by the scanner.
    """

    position = start_line - 1
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


# --- Rust identity extraction (module, owner context, normalized signature) ---


def rust_brace_pairs(code: str) -> dict[int, int]:
    stack: list[int] = []
    pairs: dict[int, int] = {}
    for pos, ch in enumerate(code):
        if ch == "{":
            stack.append(pos)
        elif ch == "}" and stack:
            pairs[stack.pop()] = pos
    return pairs


def rust_skip_attributes(code: str, start: int) -> int:
    pos = start
    while True:
        while pos < len(code) and code[pos].isspace():
            pos += 1
        if pos >= len(code) or code[pos] != "#":
            return pos
        opening = pos + 1
        while opening < len(code) and code[opening].isspace():
            opening += 1
        if opening >= len(code) or code[opening] != "[":
            return pos
        depth = 1
        pos = opening + 1
        while pos < len(code) and depth:
            if code[pos] == "[":
                depth += 1
            elif code[pos] == "]":
                depth -= 1
            pos += 1


def rust_signature_end(code: str, pairs: dict[int, int], search_from: int) -> int:
    """Offset where a function item's signature ends (body ``{`` or ``;``)."""

    paren = 0
    bracket = 0
    angle = 0
    pos = search_from
    while pos < len(code):
        ch = code[pos]
        if ch == "(":
            paren += 1
        elif ch == ")" and paren:
            paren -= 1
        elif ch == "[":
            bracket += 1
        elif ch == "]" and bracket:
            bracket -= 1
        elif ch == "<" and paren == 0 and bracket == 0:
            angle += 1
        elif ch == ">" and angle:
            angle -= 1
        elif ch == ";" and paren == 0 and bracket == 0 and angle == 0:
            return pos
        elif ch == "{" and paren == 0 and bracket == 0 and angle == 0:
            previous = pos - 1
            while previous >= search_from and code[previous].isspace():
                previous -= 1
            # A macro in a return type can use braces before the body.
            if previous >= search_from and code[previous] == "!" and pairs.get(pos) is not None:
                pos = pairs[pos] + 1
                continue
            return pos
        pos += 1
    return len(code)


def _top_level_index(text: str, separator: str) -> int | None:
    paren = 0
    bracket = 0
    angle = 0
    for index, ch in enumerate(text):
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren -= 1
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket -= 1
        elif ch == "<" and paren == 0 and bracket == 0:
            angle += 1
        elif ch == ">" and angle:
            angle -= 1
        if paren == 0 and bracket == 0 and angle == 0 and text.startswith(separator, index):
            return index
    return None


def rust_cut_top_level(text: str, keyword: str) -> str:
    index = _top_level_index(text, keyword)
    return text if index is None else text[:index]


def rust_render_scope_header(header: str) -> tuple[str, str] | None:
    """Classify one enclosing block header as an owner-context segment."""

    header = " ".join(header.strip().split())
    if not header:
        return None
    macro = RUST_MACRO_RULES_RE.match(header)
    if macro:
        return ("macro", macro.group("name"))
    pos = rust_skip_attributes(header, 0)
    match = RUST_ITEM_KW_RE.match(header, pos)
    if not match:
        return None
    keyword = match.group("kw")
    rest = header[match.end("kw"):]
    if keyword == "mod":
        name = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", rest)
        return ("mod", name.group(1) if name else "?")
    if keyword == "trait":
        return ("trait", rust_cut_top_level(rest, " where").strip())
    if keyword == "fn":
        return ("fn", " ".join(header[match.start("kw"):].split()))
    if keyword == "extern":
        return ("extern", rest.strip())
    if keyword == "impl":
        rest = rest.strip()
        if rest.startswith("<"):
            depth = 0
            end = 0
            for end, ch in enumerate(rest):
                if ch == "<":
                    depth += 1
                elif ch == ">":
                    depth -= 1
                    if depth == 0:
                        break
            rest = rest[end + 1:].strip()
        rest = rust_cut_top_level(rest, " where")
        split = _top_level_index(rest, " for ")
        if split is not None:
            trait_part = rest[:split].strip()
            type_part = rest[split + len(" for "):].strip()
            return ("impl", f"{type_part} as {trait_part}")
        return ("impl", rest.strip())
    return None


def rust_scope_chain(code: str, pairs: dict[int, int], item_start: int) -> list[tuple[str, str]]:
    chain: list[tuple[str, str]] = []
    for open_pos in sorted(pos for pos, close in pairs.items() if pos < item_start < close):
        boundary = max(
            code.rfind("{", 0, open_pos),
            code.rfind("}", 0, open_pos),
            code.rfind(";", 0, open_pos),
        )
        segment = rust_render_scope_header(code[boundary + 1:open_pos])
        if segment:
            chain.append(segment)
    return chain


def collect_rust_identities(relative: str, text: str, module: str) -> list[dict[str, object]]:
    """Scan one Rust file and derive identity fields for every function item.

    The returned records carry the scanner observations plus the new-scheme
    ID parts; the ID itself is assigned later by ``assign_rust_locked_ids``
    so collisions can be handled globally across files.
    """

    code = mask_non_code(text)
    pairs = rust_brace_pairs(code)
    records: list[dict[str, object]] = []
    ordinals: Counter[str] = Counter()
    for record in scan_rust_functions(text):
        ordinals[record.name] += 1
        signature_end = rust_signature_end(code, pairs, record.start)
        signature = RUST_VIS_PREFIX_RE.sub(
            "", " ".join(code[record.start:signature_end].split())
        ).strip()
        chain = rust_scope_chain(code, pairs, record.start)
        inner_mods = [name for kind, name in chain if kind == "mod"]
        full_module = "::".join([module, *inner_mods])
        scopes = [f"{kind}:{name}" for kind, name in chain if kind != "mod"]
        owner = "/".join(scopes) if scopes else "free"
        records.append(
            {
                "path": relative,
                "name": record.name,
                "name_ordinal": ordinals[record.name],
                "line": record.start_line + 1,
                "end_line": record.end_line + 1,
                "is_test": record.is_test,
                "is_declaration": record.is_declaration,
                "start": record.start,
                "end": record.end,
                "module": full_module,
                "owner": owner,
                "signature": signature,
            }
        )
    return records


def assign_rust_locked_ids(records: list[dict[str, object]]) -> None:
    """Assign new-scheme RG-F IDs; colliding identities fail closed."""

    for record in records:
        record["id"] = stable_id(
            "RG-F", (record["module"], record["owner"], record["signature"])
        )
        record["id_disambiguator"] = None
    collisions: dict[str, list[dict[str, object]]] = defaultdict(list)
    for record in records:
        collisions[str(record["id"])].append(record)
    duplicates = {key: group for key, group in collisions.items() if len(group) > 1}
    if duplicates:
        details = []
        for group in duplicates.values():
            for record in group:
                details.append(
                    f"  {record['path']}:{record['line']} {record['name']} "
                    f"module={record['module']} owner={record['owner']} "
                    f"signature={record['signature']}"
                )
        raise RuntimeError(
            "indistinguishable Rust function items share one ID key (module + owner "
            "+ signature); refusing to guess an ordinal-free disambiguator:\n"
            + "\n".join(details)
        )


def module_from_relative(relative: str) -> str:
    parts = relative.split("/")
    if parts and parts[0] == "src":
        parts = parts[1:]
    if not parts:
        return ""
    parts[-1] = parts[-1].removesuffix(".rs")
    if parts[-1] == "mod":
        parts = parts[:-1]
    return "::".join(parts)


def rust_entries(root: Path, ghidra_entries: list[dict[str, object]]) -> list[dict[str, object]]:
    exact_index: dict[tuple[str, int], list[dict[str, object]]] = defaultdict(list)
    span_index: dict[str, list[dict[str, object]]] = defaultdict(list)
    for entry in ghidra_entries:
        exact_index[(str(entry["file"]), int(entry["line"]))].append(entry)
        span_index[str(entry["file"])].append(entry)

    rust: list[dict[str, object]] = []
    identities: list[dict[str, object]] = []
    for path in sorted((root / "src").rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        relative = path.relative_to(root).as_posix()
        module = module_from_relative(relative)
        for identity in collect_rust_identities(relative, text, module):
            annotation_kind, annotation = marker_above(lines, int(identity["line"]) - 1)
            rust_entry: dict[str, object] = {
                "path": relative,
                "name": identity["name"],
                "name_ordinal": identity["name_ordinal"],
                "line": identity["line"],
                "end_line": identity["end_line"],
                "is_test": identity["is_test"],
                "is_declaration": identity["is_declaration"],
                "module": identity["module"],
                "owner": identity["owner"],
                "signature": identity["signature"],
                "annotation_kind": "test" if identity["is_test"] else annotation_kind,
                "annotation": annotation,
                "ghidra_mappings": [],
                "behavior_status": "TEST" if identity["is_test"] else "UNTESTED",
            }
            if not identity["is_test"] and annotation_kind == "ghidra":
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
                    rust_entry["ghidra_mappings"].append(
                        {"ghidra_id": candidate["id"], "kind": candidate_mapping_kind}
                    )
                if mapping_kind == "unresolved_reference":
                    rust_entry["behavior_status"] = "NO_ORACLE"
            elif not identity["is_test"] and annotation_kind == "missing":
                rust_entry["behavior_status"] = "NO_ORACLE"
            rust.append(rust_entry)
            identities.append(identity)
    sort_key = lambda entry: (entry["path"], entry["line"], entry["name"])  # noqa: E731
    rust.sort(key=sort_key)
    identities.sort(key=sort_key)
    # IDs are assigned globally (module strings can repeat across a `foo.rs`
    # and a nested `mod foo`), so mapping edges are stitched afterwards.
    assign_rust_locked_ids(identities)
    for entry, identity in zip(rust, identities):
        entry["id"] = identity["id"]
        entry["id_disambiguator"] = identity["id_disambiguator"]
    ghidra_by_id = {str(entry["id"]): entry for entry in ghidra_entries}
    for entry in ghidra_entries:
        entry["rust_mappings"] = []
    for entry in rust:
        for mapping in entry["ghidra_mappings"]:
            ghidra_entry = ghidra_by_id[str(mapping["ghidra_id"])]
            ghidra_entry["rust_mappings"].append(
                {"rust_id": entry["id"], "kind": mapping["kind"]}
            )
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


def markdown_table_cells(line: str) -> list[str]:
    """Split one Markdown table row without splitting pipes in code spans."""

    stripped = line.strip()
    if not stripped.startswith("|"):
        return []
    cells: list[str] = []
    current: list[str] = []
    in_code = False
    escaped = False
    for character in stripped[1:]:
        if escaped:
            current.append(character)
            escaped = False
            continue
        if character == "\\":
            current.append(character)
            escaped = True
            continue
        if character == "`":
            in_code = not in_code
            current.append(character)
            continue
        if character == "|" and not in_code:
            cells.append("".join(current).strip())
            current = []
            continue
        current.append(character)
    if current or not stripped.endswith("|"):
        cells.append("".join(current).strip())
    if cells and not cells[-1]:
        cells.pop()
    return cells


def dependency_fragments(header: str, cell: str) -> list[str]:
    """Return only dependency clauses from a TODO table cell.

    Some board tables dedicate a whole column to dependencies, while newer
    tables combine dependencies, acceptance, evidence, and timestamps.  The
    combined form must be narrowed to explicit ``依赖=...`` clauses so status
    and evidence tokens cannot become graph edges.
    """

    normalized = header.strip().lower()
    mixed = any(
        marker in normalized
        for marker in ("/", "验收", "证据", "evidence", "更新", "acceptance")
    )
    if not mixed:
        return [cell]
    return [match.group("body").strip() for match in DEPENDENCY_LABEL_RE.finditer(cell)]


def todo_dependency_inventory(text: str) -> tuple[set[str], set[tuple[str, str]]]:
    """Extract TODO nodes and true dependency edges from Markdown tables."""

    nodes: set[str] = set()
    edges: set[tuple[str, str]] = set()
    headers: list[str] | None = None
    for line in text.splitlines():
        cells = markdown_table_cells(line)
        if not cells:
            headers = None
            continue
        if all(MARKDOWN_SEPARATOR_RE.fullmatch(cell) for cell in cells):
            continue
        first = cells[0].strip().lower()
        if first in {"id", "todo id", "任务 id", "任务id"}:
            headers = cells
            continue
        # Historical rows sometimes append a state note after the leading
        # stable ID.  The ID must still be the first complete code span.
        source_match = TODO_ID_RE.match(cells[0])
        if source_match is None:
            continue
        source = source_match.group("id")
        nodes.add(source)
        if headers is None:
            continue
        for index, header in enumerate(headers):
            if index >= len(cells):
                continue
            normalized = header.lower()
            if "依赖" not in header and "dependenc" not in normalized:
                continue
            for fragment in dependency_fragments(header, cells[index]):
                for match in TODO_ID_RE.finditer(fragment):
                    target = match.group("id")
                    edges.add((source, target))
    unknown = sorted({target for _, target in edges} - nodes)
    if unknown:
        raise ValueError(
            "TODO dependency targets have no stable row (refusing implicit nodes): "
            + ", ".join(unknown)
        )

    adjacency: dict[str, list[str]] = {node: [] for node in nodes}
    for source, target in sorted(edges):
        adjacency[source].append(target)
    visiting: set[str] = set()
    visited: set[str] = set()
    path: list[str] = []

    def visit(node: str) -> None:
        if node in visited:
            return
        if node in visiting:
            start = path.index(node)
            cycle = path[start:] + [node]
            raise ValueError("TODO dependency cycle: " + " -> ".join(cycle))
        visiting.add(node)
        path.append(node)
        for target in adjacency[node]:
            visit(target)
        path.pop()
        visiting.remove(node)
        visited.add(node)

    for node in sorted(nodes):
        visit(node)
    return nodes, edges


def dependency_dag(root: Path, cpp: Path) -> dict[str, object]:
    rust_paths = sorted((root / "src").rglob("*.rs"))
    module_by_path = {path: rust_module_name(root, path) for path in rust_paths}
    modules = set(module_by_path.values())
    rust_edges: set[tuple[str, str]] = set()
    for path, source in module_by_path.items():
        text = mask_non_code(path.read_text(encoding="utf-8"))
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

    todo_nodes, todo_edges = todo_dependency_inventory(
        (root / "docs/TODO_BOARD.md").read_text(encoding="utf-8")
    )
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
        "id_scheme": ID_SCHEME,
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
            "ghidra_ids_with_guard_disambiguator": sum(
                1 for entry in ghidra if entry.get("id_disambiguator")
            ),
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
        f"- Ghidra IDs carrying a guard disambiguator: {summary['ghidra_ids_with_guard_disambiguator']}",
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


# --- Migration: rewrite an existing ledger's ID space into scheme 2 ---


OLD_RUST_ID_PREFIX = "RG-F"
ORDINAL_SUFFIX_RE = re.compile(r"-\d{2}$")


class MigrationHarnessError(RuntimeError):
    """A pinned migration input is unusable (CLI exit 2, never a traceback)."""


# FUNCTION-ID-MIGRATE-REKEY-0001 immutable replay boundary.  These pins name
# git objects rather than mutable paths.  The reconciler additionally checks
# the current worktree's src tree and ledger bytes against the target objects.
REKEY_SOURCE_COMMIT = "235b91bb552261fb3f94b7974926ef6db9b21515"
REKEY_SOURCE_COMMIT_TREE = "6f49b977e46af96c0934114836d457f680caa057"
REKEY_SOURCE_SRC_TREE = "7a9746660c9c569edf1ea922618bcad2ac9860ae"
REKEY_SOURCE_LEDGER_BLOB = "4d06b6c71f84c6bc5f05489b809754fe2b263cbf"
REKEY_TARGET_COMMIT = "8d129628c84eb87f4094b5012833b8970ff21ae9"
REKEY_TARGET_COMMIT_TREE = "5d46f835125307cf7ff83d41274373ec8bb19f45"
REKEY_TARGET_SRC_TREE = "004b20c8ed6da74cf6457a4386570bae4801bc78"
REKEY_TARGET_LEDGER_BLOB = "840bac842767797f62ddf598a6e93574be47d282"
REKEY_SOURCE_MIGRATION_BLOB = "4deb7ee4f17582c508f248b060cf13f7090b475b"
REKEY_FIRST_PARENT_COMMIT_COUNT = 332
REKEY_ORIGIN_COUNT = 24_370
REKEY_LIVE_ORIGIN_COUNT = 24_323
REKEY_GAP_COUNT = 193
REKEY_AUTO_EVENT_COUNT = 135
REKEY_AUTO_LINEAGE_COUNT = 132
REKEY_REVIEWED_SAME_NAME_COUNT = 6
REKEY_REVIEWED_SUCCESSOR_COUNT = 8
REKEY_LIVE_REKEY_LINEAGE_COUNT = 146
REKEY_ALIAS_TOKEN_COUNT = 149
REKEY_TOMBSTONE_COUNT = 47

# Post-baseline scheme-2 continuity boundary.  This is intentionally separate
# from FUNCTION_ID_MIGRATION.json: the latter remains the immutable scheme-1
# origin closure, while this checkpoint records later raw scheme-2 ID changes.
# Checkpoint advanced 2026-08-29 (ORACLE-REGISTRY-IMPACT-CONTINUITY-0001) from
# 1f3aea4a (10058 Rust records) to the reviewed src tree of 3fb97c11; every
# extension-window transition/tombstone/ephemeral decision below is pinned to
# exact commit/path/blob evidence.
CONTINUITY_CHECKPOINT_COMMIT = "3fb97c113e3128c78b5856099d0bffe5deeda496"
CONTINUITY_CHECKPOINT_COMMIT_TREE = "62e966b25e0edb9f867f849dc08021337e7d45cc"
CONTINUITY_CHECKPOINT_SRC_TREE = "e05fcb0a3f03984d699bbe964d28b47b0663439d"
CONTINUITY_CHECKPOINT_PARENT = "8406003e1db9162d17193d0df3e076471ab0f17c"
CONTINUITY_BASELINE_MIGRATION_BLOB = "8ecab1e6160b7d4d28a15aba0cad89c2fe8fc171"
CONTINUITY_BASELINE_MIGRATION_SHA256 = (
    "16236201f0b4920d2a3e33a848df05d3d601ee60998f7f7c51464d4eeb7739e9"
)
CONTINUITY_FIRST_PARENT_COMMIT_COUNT = 392
CONTINUITY_FIRST_COMMIT = "7ae30f5bcfba5e1adce2a4e8cdeebc23d96964cb"
CONTINUITY_BASELINE_RUST_RECORDS = 9_639
CONTINUITY_CHECKPOINT_RUST_RECORDS = 10_457
CONTINUITY_EXPECTED_TRANSITIONS = {
    ("RG-F-0746077b8faf709f4115", "RG-F-1e70a0af95480224f97e"),
    ("RG-F-09d0ffc3ccbb554e789c", "RG-F-cd924c7bc3e50d8e6a9b"),
    ("RG-F-0e57c9f536067337d286", "RG-F-5d4cb90317ed3e77a0b1"),
    ("RG-F-12a1ac7520a2936215cc", "RG-F-90a0ee5d5692ac0705d6"),
    ("RG-F-140645eda9c6178626bb", "RG-F-d336771e87bc3eea28e2"),
    ("RG-F-1500b403d31dc09fa484", "RG-F-bc273d6ed95b82759e0b"),
    ("RG-F-1696a469c1e4f234a381", "RG-F-0725ce4eafd7506761ce"),
    ("RG-F-1a0de177364519004226", "RG-F-7877c3db7566ba00b383"),
    ("RG-F-1b1d42d39302829f8e72", "RG-F-dc54176d68b572318a13"),
    ("RG-F-208f18dc3bc2543b44b9", "RG-F-bdbde6f78df46af9dd05"),
    ("RG-F-2282417c93d08f203cd9", "RG-F-5c1a94676a8a8172bfdd"),
    ("RG-F-29b64f515e2cc6b8a2d7", "RG-F-55f51939bbaf977e476c"),
    ("RG-F-29f1bd831bde716de5c4", "RG-F-813b027ebcd5353c4236"),
    ("RG-F-2c8bc5541245d8b6fec5", "RG-F-3bb2edeafbf9ec2e3fef"),
    ("RG-F-2c988c04aca0f061a836", "RG-F-8ba6690d9b3d452c451e"),
    ("RG-F-2ffe7f84827bd91a7a70", "RG-F-fdc4cfca398f53a8cc43"),
    ("RG-F-32b69c55e48850549780", "RG-F-914ebd32697eb67d4df6"),
    ("RG-F-353d179342f1b8c88e5b", "RG-F-4fc23f9164942392a358"),
    ("RG-F-3840b2aa55741a564b42", "RG-F-b8ad1086fc47b0b0e8f8"),
    ("RG-F-39e123daf5f57401f23b", "RG-F-e2da956f10d8f38b8bfd"),
    ("RG-F-3dde2c94bf8d902d5057", "RG-F-bc69c26bf6c937ea608a"),
    ("RG-F-420b7f1781eaae99bb0c", "RG-F-da6d2d3c6a3a39b28deb"),
    ("RG-F-44fcf9a5c35080fabaf4", "RG-F-4e04105edbeff7dd0eaa"),
    ("RG-F-471897415751e5d275d8", "RG-F-dde1a3ccdb9db5f6d490"),
    ("RG-F-48cebeae7b1f1b743e6f", "RG-F-328f0cee2b4153e006ab"),
    ("RG-F-4cdd5bd19c95d3404ef9", "RG-F-e2b08074d7ef80d46a19"),
    ("RG-F-51aa66bc4efbef5ce41c", "RG-F-68b7284fc2778ca40e41"),
    ("RG-F-53d171f3bfd9713df232", "RG-F-3104bf41dea30e902230"),
    ("RG-F-56aa5a2cb39adcdaa0e7", "RG-F-665caf5de788197a7ddb"),
    ("RG-F-5833ec87d885664efa5f", "RG-F-85943640e89de9a361c8"),
    ("RG-F-5923eb2467cb55ffa55f", "RG-F-7f644254abac1693b1ff"),
    ("RG-F-59a3a5731573081b334f", "RG-F-e10b314f1c23d10fa36f"),
    ("RG-F-5da2232cfccfbc48236b", "RG-F-147b2914b0460c3b7e89"),
    ("RG-F-664cdbe7f00113f64327", "RG-F-23ff4924c25b1bbdf96d"),
    ("RG-F-67827efc2b3b4d4016b9", "RG-F-3cd23de12de85f61b589"),
    ("RG-F-681b63f29b27de3a4123", "RG-F-b0bd0fd9650c8dc041d9"),
    ("RG-F-6875a1df88043187e59d", "RG-F-aeed1ce92fc04c5aaf17"),
    ("RG-F-6e9e5fc5dff33182265c", "RG-F-60ce0f7505bfbf56fd42"),
    ("RG-F-6f6a818a4e632357b615", "RG-F-0345c93508ad882e10c3"),
    ("RG-F-72110be65453cf3d1587", "RG-F-49837dd5483eee6ce607"),
    ("RG-F-7472347f6d20c447c6ef", "RG-F-4eb112e335ddc8f1c3b5"),
    ("RG-F-7622630fcd5425152c42", "RG-F-2e7d8eae51d63d1dcc39"),
    ("RG-F-7d56bab7c0eede6b219e", "RG-F-493eb3dfad4a42d40802"),
    ("RG-F-7e4b009ae1d8d5f62495", "RG-F-8ae418e1953a52a1525c"),
    ("RG-F-81748a75f8538c62a9f7", "RG-F-ffc6810a059dd112231b"),
    ("RG-F-81f4ae9753655126716c", "RG-F-9555f089ef1a40cbf80e"),
    ("RG-F-83f03eae691bb0f57956", "RG-F-5722d20b8628b430605b"),
    ("RG-F-85317e7aebd33b457844", "RG-F-e1751080679995008f76"),
    ("RG-F-85bdc46a384c692a66c3", "RG-F-a5c06a03ffec24675436"),
    ("RG-F-885b524a8f76bbb842bd", "RG-F-fb859141aef85785ef0f"),
    ("RG-F-89d1a3bc65108b92a474", "RG-F-02aff009ce146122520e"),
    ("RG-F-903e4bede9d3b38af7ac", "RG-F-3d84fca029aa0db125c4"),
    ("RG-F-944ce9ba0db019417ecc", "RG-F-f37cb83185100090045d"),
    ("RG-F-9a532c938b1d72c03c1d", "RG-F-1692e4d449f0e322a223"),
    ("RG-F-9b9f309fc6f60e4b3272", "RG-F-a3e8132b5200c04bc8bc"),
    ("RG-F-9e35fb6c959b18a5a1ba", "RG-F-9e79bde7c5d1fb8f92c3"),
    ("RG-F-9f084ffd4f7bca8a8785", "RG-F-ecbbaedaac3eea1407e1"),
    ("RG-F-9f45a266fb8458156812", "RG-F-8da24b5ec162432b2e21"),
    ("RG-F-a0778ccb56479e37c576", "RG-F-7f5eae81c0f3bc99e3f3"),
    ("RG-F-a33c0fce3605345a648e", "RG-F-591ad2963b9ceb809480"),
    ("RG-F-a579c006e0aba9709bc6", "RG-F-a3f39e93d5b9660d6899"),
    ("RG-F-a952489a1e2a692af4c1", "RG-F-19772f7e6c72893d19e5"),
    ("RG-F-afcc95cc17357bffe136", "RG-F-25034d16aceabddf9230"),
    ("RG-F-b1c59d7c1ce83f3fc877", "RG-F-bdbeb8a17dfc1773937a"),
    ("RG-F-b5ab805b4b3320aeb1fa", "RG-F-32dc11b88842073b5fec"),
    ("RG-F-b7b473477f7a70c35483", "RG-F-12e5d41fb77844c41884"),
    ("RG-F-b963ca1fc0328358033f", "RG-F-333df7b03f2b23fe523c"),
    ("RG-F-ba5f8ef92122364caff2", "RG-F-9abcbe19cd51f069dcce"),
    ("RG-F-bb20c591cf86c2a9f868", "RG-F-c9feebcf8cdadccd5d46"),
    ("RG-F-c07f97463d7249eed59e", "RG-F-edd4713c9bdadd7ab3e4"),
    ("RG-F-c1ee72b6e2546281e74f", "RG-F-0eb65941d5d8f3ff01fc"),
    ("RG-F-c292ca37d2c29dfc9361", "RG-F-ff7130f442132a11fd55"),
    ("RG-F-c76e93f7b514cc307344", "RG-F-68db795ba78535d5e6e6"),
    ("RG-F-c9811edb9fb50bdcbb02", "RG-F-3e640a9b136c4a824063"),
    ("RG-F-cb1453367426bab70b42", "RG-F-14308901657e8b225fe7"),
    ("RG-F-cc32cb3caeaee660aa33", "RG-F-0cd5548a65347108ceb2"),
    ("RG-F-cf9c7ee152384ba37e38", "RG-F-873b743824356fbc98b7"),
    ("RG-F-d21d7ad7d37f851c09ed", "RG-F-73c5c36f5fc7758afb22"),
    ("RG-F-d8e0a50ea15b7f15c23f", "RG-F-d03ae0650e666c500a8e"),
    ("RG-F-d9bbc5bf257eba661cde", "RG-F-a87f5098b9cb3d94a709"),
    ("RG-F-dae04c9c907df09546fa", "RG-F-278468edac56855d183b"),
    ("RG-F-db63a0620cae7f35a1e5", "RG-F-58043a6f46ae1c9b28c7"),
    ("RG-F-dbcf028e82133b9565c3", "RG-F-070808d769156b8f203d"),
    ("RG-F-dd1379a84ce1f896ce22", "RG-F-0b56e116e3afefd18da3"),
    ("RG-F-de86f142eac0c451b496", "RG-F-4b68743471f19aa81df9"),
    ("RG-F-e1c8120aff0b2b2ab02d", "RG-F-92442e738d9250d093f2"),
    ("RG-F-e4e3f26824bc65a83baf", "RG-F-150fcf46b07d4de67214"),
    ("RG-F-e74efd0e7cd7b12c51d9", "RG-F-165d45a203c4b7b0a40d"),
    ("RG-F-e7ba51c17a135fa5e918", "RG-F-746a8b9fa443b0ba04a6"),
    ("RG-F-ec2d50c00923e0d5796d", "RG-F-0706966789d474fb68e6"),
    ("RG-F-ef67f0f933f00d59516d", "RG-F-601eb1ab580c9774525d"),
    ("RG-F-efcf794f8358682dd6e9", "RG-F-94a2b6bd1410db433619"),
    ("RG-F-f828f9d8a2f59aebb57b", "RG-F-9e79ed98d1092ec72737"),
    ("RG-F-fd655d6b3856412c7d46", "RG-F-e45cf642507c156f4831"),
}
CONTINUITY_EXPECTED_TOMBSTONES = {
    ("RG-F-002a9ec13d8e062540b9", "RG-F-002a9ec13d8e062540b9",
     "874e81f7b9877b519c8ab55b57cbac24de0918f0"),
    ("RG-F-069b0702a18335d9be0c", "RG-F-069b0702a18335d9be0c",
     "73b5ef26453372a2b562051f113f9b299bcebeef"),
    ("RG-F-080a097af2330629ba3f", "RG-F-080a097af2330629ba3f",
     "73b5ef26453372a2b562051f113f9b299bcebeef"),
    ("RG-F-15a6b977326f7c0a9e15", "RG-F-15a6b977326f7c0a9e15",
     "73b5ef26453372a2b562051f113f9b299bcebeef"),
    ("RG-F-23e0cdef45d8a01764a7", "RG-F-23e0cdef45d8a01764a7",
     "1644180de42b58cd0155f62c9b3ad82efc820a57"),
    ("RG-F-255edda2318d460e2e4b", "RG-F-255edda2318d460e2e4b",
     "26d675e7f6131ed17e8de6a689b5b3d85ec21470"),
    ("RG-F-2f5c843a5f5bb2d862e9", "RG-F-2f5c843a5f5bb2d862e9",
     "cddcefd88006dd68ed69284ed31562a08fda3107"),
    ("RG-F-30101d742841018ea6b2", "RG-F-30101d742841018ea6b2",
     "b8da22a86f28cb2750fe85e1a7c69391c900a1fc"),
    ("RG-F-4a37bb3ab1d3734f0c77", "RG-F-4a37bb3ab1d3734f0c77",
     "cddcefd88006dd68ed69284ed31562a08fda3107"),
    ("RG-F-53ed24ee2a9a1e691b6b", "RG-F-53ed24ee2a9a1e691b6b",
     "73b5ef26453372a2b562051f113f9b299bcebeef"),
    ("RG-F-56411d1c69a8e636a9cc", "RG-F-56411d1c69a8e636a9cc",
     "bdc7f341d3a588045832a670f02cf384d3b12e1a"),
    ("RG-F-5ec71c480ba4438dca3a", "RG-F-5ec71c480ba4438dca3a",
     "92daed300bcce3c4d855b311cf9667ba21eb475a"),
    ("RG-F-8544a0e173d594065ca7", "RG-F-8544a0e173d594065ca7",
     "11371d512e9b374ec73d5a7e7181e6ed52eba296"),
    ("RG-F-88d87eaf0e792af4c255", "RG-F-88d87eaf0e792af4c255",
     "4495eb601d22f959bad64a6c085f516431195b42"),
    ("RG-F-8e4485d9f15252be0689", "RG-F-8e4485d9f15252be0689",
     "b8da22a86f28cb2750fe85e1a7c69391c900a1fc"),
    ("RG-F-8e6f7437052ad650c6c7", "RG-F-8e6f7437052ad650c6c7",
     "8e5944cad072ae10595214016a5f70e64fcae015"),
    ("RG-F-93890c76dc270880c224", "RG-F-93890c76dc270880c224",
     "f87e4d802652244e1b5792097d53a746d164dc07"),
    ("RG-F-95a861f4477ffddc9d35", "RG-F-95a861f4477ffddc9d35",
     "bdc7f341d3a588045832a670f02cf384d3b12e1a"),
    ("RG-F-9712364a6d3cf8e6a6a9", "RG-F-9712364a6d3cf8e6a6a9",
     "8e5944cad072ae10595214016a5f70e64fcae015"),
    ("RG-F-98eb48688773519607ba", "RG-F-98eb48688773519607ba",
     "26d675e7f6131ed17e8de6a689b5b3d85ec21470"),
    ("RG-F-9e46078d26f5ecc6cd37", "RG-F-9e46078d26f5ecc6cd37",
     "11371d512e9b374ec73d5a7e7181e6ed52eba296"),
    ("RG-F-9f52bbaae4d239936a07", "RG-F-9f52bbaae4d239936a07",
     "e956e963b167ed1d57a7a4daed2a3566f2425999"),
    ("RG-F-addd45c134e9c47b4617", "RG-F-addd45c134e9c47b4617",
     "cddcefd88006dd68ed69284ed31562a08fda3107"),
    ("RG-F-aeb06d1101df113fd3b2", "RG-F-aeb06d1101df113fd3b2",
     "b8da22a86f28cb2750fe85e1a7c69391c900a1fc"),
    ("RG-F-b04bd21a5d624e1fc06f", "RG-F-b04bd21a5d624e1fc06f",
     "26d675e7f6131ed17e8de6a689b5b3d85ec21470"),
    ("RG-F-b2cb4f664723372b7400", "RG-F-b2cb4f664723372b7400",
     "11371d512e9b374ec73d5a7e7181e6ed52eba296"),
    ("RG-F-bd201b6f89048574b546", "RG-F-bd201b6f89048574b546",
     "1644180de42b58cd0155f62c9b3ad82efc820a57"),
    ("RG-F-bd9141cd6ae9f5a4ddad", "RG-F-bd9141cd6ae9f5a4ddad",
     "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db"),
    ("RG-F-c261bf862e86c3ae27dd", "RG-F-c261bf862e86c3ae27dd",
     "73b5ef26453372a2b562051f113f9b299bcebeef"),
    ("RG-F-cb2c742a239b918218ca", "RG-F-cb2c742a239b918218ca",
     "cddcefd88006dd68ed69284ed31562a08fda3107"),
    ("RG-F-dda630121a5380c159b1", "RG-F-dda630121a5380c159b1",
     "73b5ef26453372a2b562051f113f9b299bcebeef"),
    ("RG-F-ded5b6e2aef38fd29e5a", "RG-F-ded5b6e2aef38fd29e5a",
     "f87e4d802652244e1b5792097d53a746d164dc07"),
    ("RG-F-deed2231a6bf3a9a609f", "RG-F-deed2231a6bf3a9a609f",
     "b8da22a86f28cb2750fe85e1a7c69391c900a1fc"),
    ("RG-F-e43c2d78ba8a0472a781", "RG-F-e43c2d78ba8a0472a781",
     "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db"),
    ("RG-F-e6a5ca59c7df4b468e28", "RG-F-e6a5ca59c7df4b468e28",
     "73b5ef26453372a2b562051f113f9b299bcebeef"),
    ("RG-F-ef02d5e77634269ac883", "RG-F-ef02d5e77634269ac883",
     "4495eb601d22f959bad64a6c085f516431195b42"),
}
CONTINUITY_EXPECTED_INTRODUCED = {
    "RG-F-00572f8089ee0282e3c8", "RG-F-008926b22d962c23a872", "RG-F-00dab665b85c27184c35", "RG-F-0107d69c97706422234d", "RG-F-01a8d0c683cbeb72e170", "RG-F-02b973adc674e2dafcca",
    "RG-F-02d22322d9306d6a1957", "RG-F-02e4be08c92e34abfe47", "RG-F-02e699d2b96d435be309", "RG-F-0380ee661ebfe004db50", "RG-F-05acefb94c19229397b1", "RG-F-05b7edb1beaf4beabe97",
    "RG-F-05f0a4639ffe477dfe29", "RG-F-064534368e4fa9d14c73", "RG-F-065555eea9ebf23bec7b", "RG-F-08dac8072bdc637b124d", "RG-F-0a95ba0e6234251b69a3", "RG-F-0acecfe59a00b24053c1",
    "RG-F-0b92a896aa73cc3725f7", "RG-F-0bb902ae9804cb180414", "RG-F-0c9b722a5e2a1f5950bb", "RG-F-0cecf0aca3dd73da1a6a", "RG-F-0dc1ec134f52889b4c7f", "RG-F-0ea64a6087c7f3bdb86f",
    "RG-F-100a612aa7212bc23cbf", "RG-F-1032be3fd4ff172cc745", "RG-F-104e7177e37c491be519", "RG-F-104ea5cc2fcc8b0d8a7e", "RG-F-10821d77db3ea7d39567", "RG-F-10e53934244421ea0176",
    "RG-F-1149be944c98f817e88f", "RG-F-114d6190a80e5e9307af", "RG-F-118a32c68dd9ab577f9b", "RG-F-1219325c4812c1dd23f2", "RG-F-1277c8a2b5a31d093c26", "RG-F-127afe7d95fd856b3311",
    "RG-F-12f506606145bce1a4e0", "RG-F-146ca46957e23e82feb1", "RG-F-1525650de5bcfd435631", "RG-F-1548dbf86c773e571bf5", "RG-F-1575e8b8dd6563a8cb24", "RG-F-162be04d1ee0cee22ad3",
    "RG-F-16631043521a9cd28528", "RG-F-17fefe80512bbd3c0d38", "RG-F-1816b9129452b10d63d5", "RG-F-181d5bf28272c632dc3e", "RG-F-183a5020c9c4df2954fd", "RG-F-1858875b41476176edc8",
    "RG-F-193774d891bb395d9cf0", "RG-F-19447bb36d2f795e7478", "RG-F-19cbcfb43b2ad638307e", "RG-F-19f5afa199e2f612b42f", "RG-F-1b285a9f7036553830fd", "RG-F-1b9d2bfe545242131544",
    "RG-F-1bc0ac24d1e44e2c92c9", "RG-F-1dfdfcf477b746124c4e", "RG-F-1e16dfd27039b6c1d6d0", "RG-F-1e379133c5e93eb237e8", "RG-F-1e82270e64ae136e1ff1", "RG-F-1f22a873b53c9605f9f5",
    "RG-F-1f3866bdca3f1386b405", "RG-F-1fdec6ae394eb2ecbfa2", "RG-F-202372b8209f4c235b2d", "RG-F-20b73ffb7717bb1106e6", "RG-F-212ddea625b7443d63cb", "RG-F-21349bc241c63414c350",
    "RG-F-216c139e84414e8ffbf9", "RG-F-22c46fc05bddb2d4345b", "RG-F-245ec46f5966d1227505", "RG-F-24758d9c4cdfb2c0f18b", "RG-F-247f395d88b998db5284", "RG-F-25067204f5b3e34f9798",
    "RG-F-255c1493a10ab3495460", "RG-F-259a9c49bba099f03b24", "RG-F-25b5a88855b12eec4e4b", "RG-F-2646dcd008a8290bb207", "RG-F-2712f2145ebb3e4de196", "RG-F-27b427b38ad2b76de539",
    "RG-F-27f807b8573d302b02d7", "RG-F-28a09579aa1e40998b98", "RG-F-29cbee7248ef3411c05b", "RG-F-29dc4b50b4e765955d48", "RG-F-29dd30a286d080d5a21a", "RG-F-2c1c46e7eb41d9d0fba1",
    "RG-F-2c614e4f0fe5fd220752", "RG-F-2cae510ca54daac7111b", "RG-F-2d396aa34969d8131811", "RG-F-2de92d72d9fdbccc7507", "RG-F-2e96dea7b92ff0ef2a96", "RG-F-2f933d5a214cba4925e5",
    "RG-F-30bb9f76b19c56515ae1", "RG-F-312b2c7055621e1bf498", "RG-F-31d6967fc8ada4cb91eb", "RG-F-31f38bae5f34dbe01257", "RG-F-324dc7e55c75bc7ef877", "RG-F-3364b2b484f2fafba596",
    "RG-F-348572e48805a57c238a", "RG-F-34d00aa7b73b80b7e06b", "RG-F-355de159045fc5a3fb40", "RG-F-366f5f5ff89810017f5a", "RG-F-368f07c936246d7f38ca", "RG-F-36ae6a0a421f7db68ddf",
    "RG-F-377d2765e85223c4a653", "RG-F-37fe618e1633b505056f", "RG-F-385fc5a3f59720c4cea6", "RG-F-397dbed441e7d806e74b", "RG-F-39ef8a715e72c7d8cdae", "RG-F-3a4c2cb6610ed696ff72",
    "RG-F-3ab3e7c341eff7a06dc3", "RG-F-3ae4f3955581989a9dd0", "RG-F-3b710a409ce34f951cbd", "RG-F-3ce54e6ad0d15b9e87a6", "RG-F-3dc78accde9de57c71dc", "RG-F-3e09c3afa10e851b1219",
    "RG-F-3e4ee50c3bbc358ad164", "RG-F-3e946fd54fe20f6f8f01", "RG-F-3ea17351735f97af1eb6", "RG-F-3ea726c76a58c7dd4800", "RG-F-3f02c3348e79ed0c243c", "RG-F-3f934fcc0af020d37335",
    "RG-F-418f664310446b269914", "RG-F-41f64260f48f0ecc9ce1", "RG-F-4269e256e1890ee9c4fd", "RG-F-428eff40e78b1400b16f", "RG-F-439be28c753d959db436", "RG-F-44fcf9a5c35080fabaf4",
    "RG-F-456463060527a73a63e7", "RG-F-457da052b0c6e2e7dff4", "RG-F-46555960b50ff8a7af36", "RG-F-4655dc12b17bbd1c9327", "RG-F-47b0abacb8c8d893905d", "RG-F-47cfe058e966a6231980",
    "RG-F-47f1ac1e4f13a8573ee7", "RG-F-484ed51a1834115a3a27", "RG-F-48a56f7995926edcd9b1", "RG-F-49a8a8820a93d8c302f3", "RG-F-4a7726c0d1b089f59ff8", "RG-F-4b890dfe1c63bb81ad5c",
    "RG-F-4be82fedb54a135be9ca", "RG-F-4d0d944ef8c3713a9359", "RG-F-4d4627dace046260c244", "RG-F-4e9f597e3cbe737fd971", "RG-F-4f24b91261d816418d21", "RG-F-5012f5b1447e3445b75c",
    "RG-F-503a03cb217c238099fb", "RG-F-5127056353d49f4f310b", "RG-F-5162171a14116caec8bf", "RG-F-533a1caf5ebd8375cca0", "RG-F-534803143f7406228719", "RG-F-53988f8b76d85c9de969",
    "RG-F-549bf8604d3554dc7e17", "RG-F-54beaf76ae263bbffb72", "RG-F-550f975b4cfbd7f3bdf7", "RG-F-560d456a098aa701eab0", "RG-F-5632337a8cde056439c9", "RG-F-56d3aaa705ffa0f500a3",
    "RG-F-56edae331542672fea78", "RG-F-57cd91545cb9a99bf507", "RG-F-58305d699a1d71bcd4ce", "RG-F-5840c92b94183fda5078", "RG-F-58671daf0cf269ceff9e", "RG-F-5954ddef465e441c7f32",
    "RG-F-598f7fd49db8a0469f2f", "RG-F-599925663bf4d9151f1b", "RG-F-59c782a851bb95fa70ef", "RG-F-59eb223f5cd10b89be89", "RG-F-5b479c2059d687138b32", "RG-F-5c1c47d1da97bfa24019",
    "RG-F-5c56fd8c342438530acb", "RG-F-5d34a11fd820a7e53206", "RG-F-5d6bbe8bd95dd66461dc", "RG-F-5dc1f02ffa0a44a2745a", "RG-F-5f6b775ce05e2aa3a3a1", "RG-F-605cccf75283f3057463",
    "RG-F-60c8e02b13caa1a887e7", "RG-F-6140eb4da25391919c18", "RG-F-6159293fccdff9939225", "RG-F-61659f5a98e9b24e0927", "RG-F-617d45c1dd4eaca81c67", "RG-F-63eb2e852641a54b43bb",
    "RG-F-64059e0f20c8611d48e3", "RG-F-669c87153eeca2260979", "RG-F-66cf355b52e2e8d2fa18", "RG-F-673ad79cd3ddee674eb2", "RG-F-677d167932e38cfd8059", "RG-F-67ca390476519fd99ec9",
    "RG-F-6801c1cf2e5e395a80ca", "RG-F-682e5586723e322580ec", "RG-F-6a6339cc2bfa77c6f794", "RG-F-6ac6f45740286b3a48c5", "RG-F-6ae93072db274bd7f8f6", "RG-F-6afebac8a424ec5586a0",
    "RG-F-6be9645b3c8142df8a33", "RG-F-6c3437711cb053146335", "RG-F-6cc551ee1fd7a7467895", "RG-F-6d72c6dd6b163aefba91", "RG-F-6e0463d70306112395a2", "RG-F-6e1871d56adcb2e298de",
    "RG-F-6f3483fcb562a345f033", "RG-F-6f7f59e3cda2fc6eb79b", "RG-F-6f81ff4d1ca421b38c3e", "RG-F-6f83ce5c135bfd13e648", "RG-F-6faca00e16168f0d41ef", "RG-F-6fc6d4a71ef6637ac545",
    "RG-F-6fd877ebe33c4959701e", "RG-F-70f0eedccca9fb13d7d1", "RG-F-71aaf4c2c8a8f3873677", "RG-F-72160c629d357567dbbe", "RG-F-72d324a426688135fff9", "RG-F-73294745c8e1ba6cbe0c",
    "RG-F-7336aaebd198e98b8e5c", "RG-F-73550a6421596c5f5a38", "RG-F-737889481a3284ff5eaf", "RG-F-741cd63b1cd97b9be937", "RG-F-747987b7456e5577b083", "RG-F-75a7ceddf65ab6560bc3",
    "RG-F-761e0935fde69ba1a2ed", "RG-F-761ff7e2ac19702ffc0c", "RG-F-7643d54c86c72af40d4d", "RG-F-768f646bdc051192b889", "RG-F-769776db0caf758a7fac", "RG-F-777aeae0f3f078555f0f",
    "RG-F-7795ec675c08d08fadc1", "RG-F-7909a29462b00fbbdb9c", "RG-F-79123f1b829342ee6c79", "RG-F-7956dcf231ce5f01e9fd", "RG-F-7a3b472134bccd5a97f6", "RG-F-7be175134af266d24a85",
    "RG-F-7c79e5490d051ae0608d", "RG-F-7cb6625ae84bc31cae67", "RG-F-7d16faddb640f830df37", "RG-F-7d949a2dc82972bb9f60", "RG-F-7de827d003e76d6c30e5", "RG-F-7ed78f16069a0f084e9b",
    "RG-F-7f4499a24e9d5f6e00f6", "RG-F-7f4c48378d23c1a5e5ea", "RG-F-7fc25f0ba8f3590f8ce5", "RG-F-80be11223c7b4a4b7bbc", "RG-F-8103478fa5632787566b", "RG-F-826b449b376d040fa113",
    "RG-F-82ed5ecaeb15a4ea56b7", "RG-F-82f08ff8f803b2ee3aa0", "RG-F-836f64d548ebdf5f7622", "RG-F-83e853484f56821c1812", "RG-F-84749c9d1107aad23889", "RG-F-84b9c2374fd31d45ad7d",
    "RG-F-854abd426f8d906293fc", "RG-F-856104de7b4b35b3b196", "RG-F-85a9a9cb05cba5cd73c7", "RG-F-85ce0eb54798067006cd", "RG-F-85f37911e4cc908d94be", "RG-F-8644167dba914511af35",
    "RG-F-872e0420b1f365b847b9", "RG-F-87c6821a687f43ed3cca", "RG-F-88afc95ae2cd730cbcbc", "RG-F-88bb8c20631231472f93", "RG-F-88e0290b444504b3758a", "RG-F-8a7993e2ea925d23366f",
    "RG-F-8aee319041fc15885aa0", "RG-F-8d0f69692399436cc2b0", "RG-F-8d5656235b795f8ebb31", "RG-F-8d622e878f47dfb5761e", "RG-F-8d7818eecf4c25ea2fdc", "RG-F-8dad27cd32cd1e3eed3c",
    "RG-F-8e553bd6c64dac2af697", "RG-F-8eb776b3fa088a50b624", "RG-F-8ebed3fdf1b95247ed33", "RG-F-8ee0e817a068fbd9f977", "RG-F-9065e79950510f8deebc", "RG-F-90f2e325176921f26d08",
    "RG-F-914a13726dfd0b09b621", "RG-F-914a4c2787820475d450", "RG-F-91b17d759f4c4509c185", "RG-F-91b8fbbf0b62f18f97f6", "RG-F-91c0b321491c2cf648d3", "RG-F-91c1ee30572b68352ee7",
    "RG-F-922b6bc020ee1c31087b", "RG-F-92484cc621f01015c275", "RG-F-92ad84047e3bac2f3830", "RG-F-9382f4598eb174593d93", "RG-F-94f2502fa3cf379178d7", "RG-F-959f407b5d68573d1229",
    "RG-F-95d1a6f481d56bd88dc9", "RG-F-95dfff513f38d7e862f5", "RG-F-96bc01a1e64206e70c4c", "RG-F-987c0c4685c579ad3ef3", "RG-F-9a5919c0f999202c5bcd", "RG-F-9b5baba65cd5c883caaa",
    "RG-F-9dcc3492039b01a007b8", "RG-F-9de168de7406c59884f3", "RG-F-9e25ba491c2ebdd3f0f0", "RG-F-9e36c0fb5daa89f6e75b", "RG-F-9efd056431f8364d0be8", "RG-F-9f1935e81471cf88494a",
    "RG-F-9f411e55f3dd548b1f5d", "RG-F-a0d564af318c54be62c0", "RG-F-a10d860ce8bc8dd86327", "RG-F-a11a156c6318c2df9ed2", "RG-F-a1284b983985a442d8d1", "RG-F-a17aa78c11cf76e74c62",
    "RG-F-a23181f8846012d8bdc9", "RG-F-a43b43b4851399cb487b", "RG-F-a5b69ac71c7042021efd", "RG-F-a6bd125935c53df33d0a", "RG-F-a6e0a49a2ee23cbd31aa", "RG-F-a7b190a9cc6699355ab8",
    "RG-F-a7f678a9f1d3c48ba8e1", "RG-F-a90a8498ecb52ff4ac8c", "RG-F-aac3e8659132fb196a16", "RG-F-aad4662f2d4def75a3fd", "RG-F-ac385b3896fbc69af1ad", "RG-F-ac69b64441781fc5ee72",
    "RG-F-adba82208d7b6be78431", "RG-F-af1e44fa513e12f2bb5a", "RG-F-af1fad6c42c639175c6f", "RG-F-b0f297ffd0622fb16d72", "RG-F-b34be787885cf85b976b", "RG-F-b3947087ae26a6f102b2",
    "RG-F-b3aaa93c05ec91982298", "RG-F-b419087b6863a23e74dd", "RG-F-b445c51b636b8d0099bb", "RG-F-b45202de116db26f14a2", "RG-F-b4991bba97dbd3b2549c", "RG-F-b5b381eed8d0ca59a904",
    "RG-F-b5c5ee2f99e92a814e05", "RG-F-b627a7fe79b11f4af086", "RG-F-b63c109e5666f5d8fd7e", "RG-F-b6ae11ee0ecf46345b5d", "RG-F-b6f2e000999425bf7813", "RG-F-b992a7f938634f6aee23",
    "RG-F-ba374c84c3bc3a1660b9", "RG-F-ba5f8ef92122364caff2", "RG-F-bc3a4504b8d4a435467f", "RG-F-bc5692de9cbfe20564c0", "RG-F-bce2035ffbf33cf838cb", "RG-F-bd228d392b15d2344020",
    "RG-F-bdc84c53fafd339065cc", "RG-F-be2959aa06baf0410c5d", "RG-F-be2cb35dfbde1d5bba30", "RG-F-be924328dfc5e9be99a7", "RG-F-bfe8d60ff5c1ca111f37", "RG-F-c004a34a7e50854e247c",
    "RG-F-c02df23a1a402a7a4d59", "RG-F-c0663e763062272fc331", "RG-F-c0cf3926f855614f56d8", "RG-F-c0d24bb320a86779a09e", "RG-F-c155aba255b133d73969", "RG-F-c1c5fb6d272cef0aa292",
    "RG-F-c24d81aefca155bcc5ed", "RG-F-c2cd9b1cd1190a6f589e", "RG-F-c2e996b203ef8de56806", "RG-F-c3984e736a01c5b32cb9", "RG-F-c414e1f8cd6e0c6c3004", "RG-F-c46a6290a40a2a73174d",
    "RG-F-c5628e833406f73b2da0", "RG-F-c58bd5e5d630cc315643", "RG-F-c590866258cd2260a9b8", "RG-F-c60f417aacae8dc4e4be", "RG-F-c67125dc3be16b3a668e", "RG-F-c8b4eb9f35f49bca9617",
    "RG-F-c9aacc1c4a51b4569b4d", "RG-F-c9d5dc000041096d3298", "RG-F-c9f5376f0271a331ad38", "RG-F-ca68513b5a09b7bfc884", "RG-F-ca73f21f3aed9f1fd25b", "RG-F-cac4e168c42e02cc2398",
    "RG-F-cb37147022180eeb9575", "RG-F-cba1ca033fe56fb95dc4", "RG-F-cc32d670f33a582bd625", "RG-F-cc58a2a17a33c2df4d83", "RG-F-d0be2b9c83077fbada35", "RG-F-d1271f08594059b16449",
    "RG-F-d174fbfcace857dd19b9", "RG-F-d26508b5acc22dd2c8ba", "RG-F-d26ff0730f4dd1953bd7", "RG-F-d2a6efd33943f99876b9", "RG-F-d3d09a0ed811a54e22ce", "RG-F-d4c64aed03a3a7a894ae",
    "RG-F-d5b62cebb39f2db34ea5", "RG-F-d84d923a6982ef17c93e", "RG-F-d8a98b8e42974ba30f33", "RG-F-d8e0a50ea15b7f15c23f", "RG-F-d8ffb7a35df5c67c2d49", "RG-F-d9d3da946c12ed8260f7",
    "RG-F-dafcb780cdc32cfd54f0", "RG-F-db6a99a982c10626a563", "RG-F-ddcca3e697279ebe7c54", "RG-F-de5a4f22e8c1a8add747", "RG-F-de6224893317e5fbfb2e", "RG-F-deba560ad7910c30291e",
    "RG-F-dec293bcd6b0000c8d1f", "RG-F-dfc91dc60e9bcaeea46d", "RG-F-e2018b945a2a552a7822", "RG-F-e2ae768e78b0f9d2407f", "RG-F-e30cadbed26529bf4283", "RG-F-e43529c7de5adfc21cb9",
    "RG-F-e4e606b96ec0762b2786", "RG-F-e4f898ef03faf91f8f23", "RG-F-e6d44fe6157734ea6fa8", "RG-F-e6e93636b838c329c329", "RG-F-e6f7a196c2cd7dc7d374", "RG-F-e70d8901d08c59cf4f17",
    "RG-F-e75e2b91e06438896f05", "RG-F-e870edfc62e77b4c067f", "RG-F-e8f4c2cca65795f7aab1", "RG-F-e9bdf0cf00b82d833119", "RG-F-eb1349863e98d980d3e3", "RG-F-eb6a1384046628b4ae4f",
    "RG-F-eb9dfdbc7087f2eb1485", "RG-F-ec0b6eece1b8d0ce4a55", "RG-F-ec5918a7c276fe9f0d78", "RG-F-ec7149a3f12e21885a05", "RG-F-ec78931ef77b110a71e0", "RG-F-ed543a215c3691361673",
    "RG-F-eea7497cf84727c9d5e8", "RG-F-ef2a045480d66e75091c", "RG-F-efcf794f8358682dd6e9", "RG-F-f011b1701c64da6523fc", "RG-F-f03bae6585682e8447b8", "RG-F-f0c872a033d6ed8d2afc",
    "RG-F-f0cecbc341fcb11177b2", "RG-F-f0f21aeddd1a5c16311d", "RG-F-f1573abb1a956c17b6c2", "RG-F-f2584f2f4f7724c0459d", "RG-F-f2afae8f6d9c3f4fe90e", "RG-F-f2b3b16ba32af9e3e34d",
    "RG-F-f2d88551b79c980795da", "RG-F-f38af2d94a8509c75a54", "RG-F-f41320c540657f4c06f5", "RG-F-f41d129cd8c5f74d04ce", "RG-F-f44ba1e7583dd76ff22a", "RG-F-f4a37fc066f4a7fa7875",
    "RG-F-f4f223640f8b96bee830", "RG-F-f596e70e9ca6b6981c7d", "RG-F-f6ec13ccf523ead15526", "RG-F-f6f561f5e4f521efc203", "RG-F-f7da420b609916e78b68", "RG-F-f8305f268aaa07bf8676",
    "RG-F-f83534827af595642dff", "RG-F-f84373ff1e155a4acd7f", "RG-F-f9b4694d60058a4b24e0", "RG-F-fa6e23e05a0058769ae2", "RG-F-fa7f7686c00b62605ebb", "RG-F-fa8ec6d371b37cee7587",
    "RG-F-fabd6ed370dadf216dfc", "RG-F-fb4b6c06d2934461776d", "RG-F-fbba2371c1e3ee574c60", "RG-F-fc9614ae62a5ca22047d", "RG-F-fd82c9d5598cf4e2837b", "RG-F-fdc56656082534066c8d",
    "RG-F-fe9b0a62c42abc10fcab", "RG-F-fefdb48c92ee9155d8c7", "RG-F-ff1924f87ac5baa0fb04", "RG-F-ff741eec389f6e2c6e18", "RG-F-ff9e56b34d4facda44b5",
}

# Non-mut-binding successors must be added here with exact commit, ID, path,
# and blob pins; every rule fires exactly once and the replay refuses any
# removal that no rule proves.  Deletions get reviewed tombstone rules; a
# class introduced and deleted entirely inside the window (never pinned in
# any ledger) is retired by an ephemeral rule instead, because schema 1
# cannot encode an introduced-then-deleted origin.
CONTINUITY_REVIEWED_TRANSITIONS: tuple[dict[str, str], ...] = (
    {
        "base_id": "RG-F-72110be65453cf3d1587",
        "from_id": "RG-F-72110be65453cf3d1587",
        "to_id": "RG-F-49837dd5483eee6ce607",
        "commit": "0d2252dd631677ef221d8266f1267090fecd45da",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "a51548151141f22102a5d5440332a795b31bb289",
        "child_blob": "8907ccac7517b1044b0921bffcecc1344b4eab11",
        "review": "set_block_range: block-range bounds u64 to Address (0d2252d)",
    },
    {
        "base_id": "RG-F-09d0ffc3ccbb554e789c",
        "from_id": "RG-F-09d0ffc3ccbb554e789c",
        "to_id": "RG-F-cd924c7bc3e50d8e6a9b",
        "commit": "33793c130fed5a7d0ecb858293dfcfd7bc23b88e",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "8907ccac7517b1044b0921bffcecc1344b4eab11",
        "child_blob": "6d8cd933d880d5c104ae30410e82538087282e1d",
        "review": "fallthru: shared-return override consumption (Result returns) (33793c1)",
    },
    {
        "base_id": "RG-F-29f1bd831bde716de5c4",
        "from_id": "RG-F-29f1bd831bde716de5c4",
        "to_id": "RG-F-813b027ebcd5353c4236",
        "commit": "33793c130fed5a7d0ecb858293dfcfd7bc23b88e",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "8907ccac7517b1044b0921bffcecc1344b4eab11",
        "child_blob": "6d8cd933d880d5c104ae30410e82538087282e1d",
        "review": "finish_process_instruction: shared-return override consumption "
                  "(Result returns) (33793c1)",
    },
    {
        "base_id": "RG-F-c9811edb9fb50bdcbb02",
        "from_id": "RG-F-c9811edb9fb50bdcbb02",
        "to_id": "RG-F-3e640a9b136c4a824063",
        "commit": "33793c130fed5a7d0ecb858293dfcfd7bc23b88e",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "8907ccac7517b1044b0921bffcecc1344b4eab11",
        "child_blob": "6d8cd933d880d5c104ae30410e82538087282e1d",
        "review": "generate_ops: shared-return override consumption (Result returns) (33793c1)",
    },
    {
        "base_id": "RG-F-7d56bab7c0eede6b219e",
        "from_id": "RG-F-7d56bab7c0eede6b219e",
        "to_id": "RG-F-493eb3dfad4a42d40802",
        "commit": "33793c130fed5a7d0ecb858293dfcfd7bc23b88e",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "5f8dbeb93c233836b195418d007da8291f4483e5",
        "child_blob": "6607bf4acdc7a2b54a47623d473a999f6996d42e",
        "review": "override_flow: shared-return override consumption (Result returns) (33793c1)",
    },
    {
        "base_id": "RG-F-fd655d6b3856412c7d46",
        "from_id": "RG-F-fd655d6b3856412c7d46",
        "to_id": "RG-F-e45cf642507c156f4831",
        "commit": "33793c130fed5a7d0ecb858293dfcfd7bc23b88e",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "8907ccac7517b1044b0921bffcecc1344b4eab11",
        "child_blob": "6d8cd933d880d5c104ae30410e82538087282e1d",
        "review": "process_instruction: shared-return override consumption "
                  "(Result returns) (33793c1)",
    },
    {
        "base_id": "RG-F-2c988c04aca0f061a836",
        "from_id": "RG-F-2c988c04aca0f061a836",
        "to_id": "RG-F-8ba6690d9b3d452c451e",
        "commit": "3be7b24cf66fdea133cbbb748ba771586d420b5d",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "c76bd681b78b55e7855769e5e6d438df8c8c4cc2",
        "child_blob": "a51548151141f22102a5d5440332a795b31bb289",
        "review": "build_callother_op: flow truncation error channel (Result returns) (3be7b24)",
    },
    {
        "base_id": "RG-F-c292ca37d2c29dfc9361",
        "from_id": "RG-F-c292ca37d2c29dfc9361",
        "to_id": "RG-F-ff7130f442132a11fd55",
        "commit": "3be7b24cf66fdea133cbbb748ba771586d420b5d",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "c76bd681b78b55e7855769e5e6d438df8c8c4cc2",
        "child_blob": "a51548151141f22102a5d5440332a795b31bb289",
        "review": "follow_flow: flow truncation error channel (Result returns) (3be7b24)",
    },
    {
        "base_id": "RG-F-681b63f29b27de3a4123",
        "from_id": "RG-F-681b63f29b27de3a4123",
        "to_id": "RG-F-b0bd0fd9650c8dc041d9",
        "commit": "3be7b24cf66fdea133cbbb748ba771586d420b5d",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "c76bd681b78b55e7855769e5e6d438df8c8c4cc2",
        "child_blob": "a51548151141f22102a5d5440332a795b31bb289",
        "review": "generate_blocks: flow truncation error channel (Result returns) (3be7b24)",
    },
    {
        "base_id": "RG-F-420b7f1781eaae99bb0c",
        "from_id": "RG-F-420b7f1781eaae99bb0c",
        "to_id": "RG-F-da6d2d3c6a3a39b28deb",
        "commit": "3be7b24cf66fdea133cbbb748ba771586d420b5d",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "c76bd681b78b55e7855769e5e6d438df8c8c4cc2",
        "child_blob": "a51548151141f22102a5d5440332a795b31bb289",
        "review": "split_basic: flow truncation error channel (Result returns) (3be7b24)",
    },
    {
        "base_id": "RG-F-d21d7ad7d37f851c09ed",
        "from_id": "RG-F-d21d7ad7d37f851c09ed",
        "to_id": "RG-F-73c5c36f5fc7758afb22",
        "commit": "577e54bb32aa0ff6c167f5b3bff5a71807439a0a",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "754391522125b69d12f73bdf301598c773afca38",
        "child_blob": "8b0b009a152525dae09c3977072ce86742b8b86c",
        "review": "propagate_from_pointer: pointee propagation gated by dereference width (577e54b)",
    },
    {
        "base_id": "RG-F-9a532c938b1d72c03c1d",
        "from_id": "RG-F-9a532c938b1d72c03c1d",
        "to_id": "RG-F-1692e4d449f0e322a223",
        "commit": "594ed4fa74e895390cbe105e1b0af8afed3aeb7f",
        "from_path": "src/type_system/typefactory.rs",
        "to_path": "src/type_system/typefactory.rs",
        "parent_blob": "3f1abd38c977843feb98f9cac30d6bf0779a9ac8",
        "child_blob": "4fef0e1b7cbaf0ac1508b64cb5e7e0966748a588",
        "review": "order_recurse: typefactory layout-preserving definitions (594ed4f)",
    },
    {
        "base_id": "RG-F-b5ab805b4b3320aeb1fa",
        "from_id": "RG-F-b5ab805b4b3320aeb1fa",
        "to_id": "RG-F-32dc11b88842073b5fec",
        "commit": "594ed4fa74e895390cbe105e1b0af8afed3aeb7f",
        "from_path": "src/type_system/typefactory.rs",
        "to_path": "src/type_system/typefactory.rs",
        "parent_blob": "3f1abd38c977843feb98f9cac30d6bf0779a9ac8",
        "child_blob": "4fef0e1b7cbaf0ac1508b64cb5e7e0966748a588",
        "review": "resolve_incomplete_typedefs: typefactory layout-preserving definitions (594ed4f)",
    },
    {
        "base_id": "RG-F-cb1453367426bab70b42",
        "from_id": "RG-F-cb1453367426bab70b42",
        "to_id": "RG-F-14308901657e8b225fe7",
        "commit": "805cf887d96b97f85a4b979bf408145e87a22a45",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "a93b1fbde0c5fbc4e287544752e5761c0affe202",
        "child_blob": "0d186b599d149430849b0c4e8b3a2453746690cd",
        "review": "register_trial: register_trial returns bool for tagged spaces (805cf88)",
    },
    {
        "base_id": "RG-F-9f45a266fb8458156812",
        "from_id": "RG-F-9f45a266fb8458156812",
        "to_id": "RG-F-8da24b5ec162432b2e21",
        "commit": "87f9309b5a98af929c765925dbf55b427121d8f7",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "2abd23b88562e6aa23712d78c9edd7a3ac3ffa63",
        "child_blob": "a93b1fbde0c5fbc4e287544752e5761c0affe202",
        "review": "decode: fspec paramlist output dispatch expansion (87f9309)",
    },
    {
        "base_id": "RG-F-e74efd0e7cd7b12c51d9",
        "from_id": "RG-F-e74efd0e7cd7b12c51d9",
        "to_id": "RG-F-165d45a203c4b7b0a40d",
        "commit": "87f9309b5a98af929c765925dbf55b427121d8f7",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "2abd23b88562e6aa23712d78c9edd7a3ac3ffa63",
        "child_blob": "a93b1fbde0c5fbc4e287544752e5761c0affe202",
        "review": "possible_param: fspec paramlist output dispatch expansion (87f9309)",
    },
    {
        "base_id": "RG-F-7472347f6d20c447c6ef",
        "from_id": "RG-F-7472347f6d20c447c6ef",
        "to_id": "RG-F-4eb112e335ddc8f1c3b5",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "0d186b599d149430849b0c4e8b3a2453746690cd",
        "child_blob": "a9179e6432deabd7f9dfd228ed71a94a5d1ff2ba",
        "review": "clone_for_op: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-ec2d50c00923e0d5796d",
        "from_id": "RG-F-ec2d50c00923e0d5796d",
        "to_id": "RG-F-0706966789d474fb68e6",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "6607bf4acdc7a2b54a47623d473a999f6996d42e",
        "child_blob": "f4f0308e571b0ca56af88ab627a6eab2aebb6c7a",
        "review": "compare_callspecs: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-e4e3f26824bc65a83baf",
        "from_id": "RG-F-e4e3f26824bc65a83baf",
        "to_id": "RG-F-150fcf46b07d4de67214",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "6d8cd933d880d5c104ae30410e82538087282e1d",
        "child_blob": "f7722f4fb73c31cfbf562222f5767e11864f2ab5",
        "review": "delete_call_spec: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-56aa5a2cb39adcdaa0e7",
        "from_id": "RG-F-56aa5a2cb39adcdaa0e7",
        "to_id": "RG-F-665caf5de788197a7ddb",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "0d186b599d149430849b0c4e8b3a2453746690cd",
        "child_blob": "a9179e6432deabd7f9dfd228ed71a94a5d1ff2ba",
        "review": "find_call_op: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-cf9c7ee152384ba37e38",
        "from_id": "RG-F-cf9c7ee152384ba37e38",
        "to_id": "RG-F-873b743824356fbc98b7",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "6d8cd933d880d5c104ae30410e82538087282e1d",
        "child_blob": "f7722f4fb73c31cfbf562222f5767e11864f2ab5",
        "review": "find_callspec_for_op: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-89d1a3bc65108b92a474",
        "from_id": "RG-F-89d1a3bc65108b92a474",
        "to_id": "RG-F-02aff009ce146122520e",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "6607bf4acdc7a2b54a47623d473a999f6996d42e",
        "child_blob": "f4f0308e571b0ca56af88ab627a6eab2aebb6c7a",
        "review": "get_call_specs: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-b1c59d7c1ce83f3fc877",
        "from_id": "RG-F-b1c59d7c1ce83f3fc877",
        "to_id": "RG-F-bdbeb8a17dfc1773937a",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "6607bf4acdc7a2b54a47623d473a999f6996d42e",
        "child_blob": "f4f0308e571b0ca56af88ab627a6eab2aebb6c7a",
        "review": "get_call_specs_mut: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-6875a1df88043187e59d",
        "from_id": "RG-F-6875a1df88043187e59d",
        "to_id": "RG-F-aeed1ce92fc04c5aaf17",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "6607bf4acdc7a2b54a47623d473a999f6996d42e",
        "child_blob": "f4f0308e571b0ca56af88ab627a6eab2aebb6c7a",
        "review": "get_call_specs_of_op: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-5923eb2467cb55ffa55f",
        "from_id": "RG-F-5923eb2467cb55ffa55f",
        "to_id": "RG-F-7f644254abac1693b1ff",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "6607bf4acdc7a2b54a47623d473a999f6996d42e",
        "child_blob": "f4f0308e571b0ca56af88ab627a6eab2aebb6c7a",
        "review": "new_varnode_call_specs: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-5833ec87d885664efa5f",
        "from_id": "RG-F-5833ec87d885664efa5f",
        "to_id": "RG-F-85943640e89de9a361c8",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/unionresolve.rs",
        "to_path": "src/unionresolve.rs",
        "parent_blob": "cffe8789412f9984882e1fc52b3a20bda46e8b2b",
        "child_blob": "14b3650eee3f6c0d9cb78c70cbde8ec80e9a276a",
        "review": "score_parameter: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-e7ba51c17a135fa5e918",
        "from_id": "RG-F-e7ba51c17a135fa5e918",
        "to_id": "RG-F-746a8b9fa443b0ba04a6",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/unionresolve.rs",
        "to_path": "src/unionresolve.rs",
        "parent_blob": "cffe8789412f9984882e1fc52b3a20bda46e8b2b",
        "child_blob": "14b3650eee3f6c0d9cb78c70cbde8ec80e9a276a",
        "review": "score_return_type: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-f828f9d8a2f59aebb57b",
        "from_id": "RG-F-f828f9d8a2f59aebb57b",
        "to_id": "RG-F-9e79ed98d1092ec72737",
        "commit": "e9a0b7a8911af7f85fb180bef7b50d43f19712c5",
        "from_path": "src/merge.rs",
        "to_path": "src/merge.rs",
        "parent_blob": "3c69834d53507811ff1d34c5fdd40086c65f3ab4",
        "child_blob": "365be16020196337d386eb215f0b280ece383847",
        "review": "merge_test_must: merge_test_must returns Result under address-tied gates (e9a0b7a)",
    },
    {
        "base_id": "RG-F-0746077b8faf709f4115",
        "from_id": "RG-F-0746077b8faf709f4115",
        "to_id": "RG-F-1e70a0af95480224f97e",
        "commit": "bd8e38e474d1402592d25c6b97749bfe42e2ab50",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "4ab1068cde61e05570d0941243b5e89ab098934f",
        "child_blob": "15d1b123a975915a62ee661414b16c4e9cbba5dc",
        "review": "register_action_named: action pool cloning allows optional action (bd8e38e)",
    },
    {
        "base_id": "RG-F-140645eda9c6178626bb",
        "from_id": "RG-F-140645eda9c6178626bb",
        "to_id": "RG-F-d336771e87bc3eea28e2",
        "commit": "bd8e38e474d1402592d25c6b97749bfe42e2ab50",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "4ab1068cde61e05570d0941243b5e89ab098934f",
        "child_blob": "15d1b123a975915a62ee661414b16c4e9cbba5dc",
        "review": "add_action_in_group: ActionRestartGroup group lifetime &'static str to &str (bd8e38e)",
    },
    {
        "base_id": "RG-F-944ce9ba0db019417ecc",
        "from_id": "RG-F-944ce9ba0db019417ecc",
        "to_id": "RG-F-f37cb83185100090045d",
        "commit": "bd8e38e474d1402592d25c6b97749bfe42e2ab50",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "4ab1068cde61e05570d0941243b5e89ab098934f",
        "child_blob": "15d1b123a975915a62ee661414b16c4e9cbba5dc",
        "review": "child_group: ActionRestartGroup group lifetime &'static str to &str (bd8e38e)",
    },
    {
        "base_id": "RG-F-a579c006e0aba9709bc6",
        "from_id": "RG-F-a579c006e0aba9709bc6",
        "to_id": "RG-F-a3f39e93d5b9660d6899",
        "commit": "bd8e38e474d1402592d25c6b97749bfe42e2ab50",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "4ab1068cde61e05570d0941243b5e89ab098934f",
        "child_blob": "15d1b123a975915a62ee661414b16c4e9cbba5dc",
        "review": "add_action_in_group: ActionGroup group lifetime &'static str to &str (bd8e38e)",
    },
    {
        "base_id": "RG-F-dd1379a84ce1f896ce22",
        "from_id": "RG-F-dd1379a84ce1f896ce22",
        "to_id": "RG-F-0b56e116e3afefd18da3",
        "commit": "bd8e38e474d1402592d25c6b97749bfe42e2ab50",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "4ab1068cde61e05570d0941243b5e89ab098934f",
        "child_blob": "15d1b123a975915a62ee661414b16c4e9cbba5dc",
        "review": "child_group: ActionGroup group lifetime &'static str to &str (bd8e38e)",
    },
    {
        "base_id": "RG-F-664cdbe7f00113f64327",
        "from_id": "RG-F-664cdbe7f00113f64327",
        "to_id": "RG-F-23ff4924c25b1bbdf96d",
        "commit": "e3e005336fc86b80542430416b849b9696907d80",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "1dd8e20179e169cd354864f6bac696238ce36069",
        "child_blob": "de0f7b944502d199e4a531307d04bff6e8da7a78",
        "review": "new: TypeOpManager takes shared type factory (e3e0053)",
    },
    {
        "base_id": "RG-F-53d171f3bfd9713df232",
        "from_id": "RG-F-53d171f3bfd9713df232",
        "to_id": "RG-F-3104bf41dea30e902230",
        "commit": "f87e4d802652244e1b5792097d53a746d164dc07",
        "from_path": "src/variable.rs",
        "to_path": "src/variable.rs",
        "parent_blob": "20b3f095aa2ae9b813e78281140c8a9304fec9fb",
        "child_blob": "6060cb596b31185d8a395bc78816c4082ea9ef32",
        "review": "finalize_datatype: exact-piece threading through TypeFactory (f87e4d8)",
    },
    {
        "base_id": "RG-F-59a3a5731573081b334f",
        "from_id": "RG-F-59a3a5731573081b334f",
        "to_id": "RG-F-e10b314f1c23d10fa36f",
        "commit": "f87e4d802652244e1b5792097d53a746d164dc07",
        "from_path": "src/database.rs",
        "to_path": "src/database.rs",
        "parent_blob": "840e08ae133f285857b0b5ab2a19839976f96c0e",
        "child_blob": "64fad62b6c9ad3ec69cb293947c3931d5568bc00",
        "review": "update_type: exact-piece threading through TypeFactory (f87e4d8)",
    },
    {
        "base_id": "RG-F-81f4ae9753655126716c",
        "from_id": "RG-F-81f4ae9753655126716c",
        "to_id": "RG-F-9555f089ef1a40cbf80e",
        "commit": "f87e4d802652244e1b5792097d53a746d164dc07",
        "from_path": "src/database.rs",
        "to_path": "src/database.rs",
        "parent_blob": "840e08ae133f285857b0b5ab2a19839976f96c0e",
        "child_blob": "64fad62b6c9ad3ec69cb293947c3931d5568bc00",
        "review": "get_sized_type: exact-piece threading through TypeFactory (f87e4d8)",
    },
    {
        "base_id": "RG-F-de86f142eac0c451b496",
        "from_id": "RG-F-de86f142eac0c451b496",
        "to_id": "RG-F-4b68743471f19aa81df9",
        "commit": "f87e4d802652244e1b5792097d53a746d164dc07",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "f4f0308e571b0ca56af88ab627a6eab2aebb6c7a",
        "child_blob": "de9ecc914f2fc2cc65b246f8462dfbf26b39f33c",
        "review": "local_symbol_sized_type: exact-piece threading through TypeFactory (f87e4d8)",
    },
    {
        "base_id": "RG-F-81748a75f8538c62a9f7",
        "from_id": "RG-F-81748a75f8538c62a9f7",
        "to_id": "RG-F-ffc6810a059dd112231b",
        "commit": "3fa28023bf4cb0356b23747a97b798df97a57f3c",
        "from_path": "src/type_system/typefactory.rs",
        "to_path": "src/type_system/typefactory.rs",
        "parent_blob": "93b94c83a3c33fc218170cc559c266fbf4ab4f22",
        "child_blob": "fc60ceb1de127ce56f1a0adf6088b54e388fcba7",
        "review": "down_chain: virtual dispatch takes orig datatype not TypePointer (3fa2802)",
    },
    {
        "base_id": "RG-F-85bdc46a384c692a66c3",
        "from_id": "RG-F-85bdc46a384c692a66c3",
        "to_id": "RG-F-a5c06a03ffec24675436",
        "commit": "3fa28023bf4cb0356b23747a97b798df97a57f3c",
        "from_path": "src/type_system/typefactory.rs",
        "to_path": "src/type_system/typefactory.rs",
        "parent_blob": "93b94c83a3c33fc218170cc559c266fbf4ab4f22",
        "child_blob": "fc60ceb1de127ce56f1a0adf6088b54e388fcba7",
        "review": "down_chain_pointer: virtual dispatch takes orig datatype not TypePointer (3fa2802)",
    },
    {
        "base_id": "RG-F-2c8bc5541245d8b6fec5",
        "from_id": "RG-F-2c8bc5541245d8b6fec5",
        "to_id": "RG-F-3bb2edeafbf9ec2e3fef",
        "commit": "0f0a060ccd79bdfd78723d33056906778ce2ed7b",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "de0f7b944502d199e4a531307d04bff6e8da7a78",
        "child_blob": "d1cf58c87fe4869cd8aa9c8aa0cc9cb042328288",
        "review": "get_input_local: TypeOp local defaults drop underscore bindings (0f0a060)",
    },
    {
        "base_id": "RG-F-3840b2aa55741a564b42",
        "from_id": "RG-F-3840b2aa55741a564b42",
        "to_id": "RG-F-b8ad1086fc47b0b0e8f8",
        "commit": "0f0a060ccd79bdfd78723d33056906778ce2ed7b",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "de0f7b944502d199e4a531307d04bff6e8da7a78",
        "child_blob": "d1cf58c87fe4869cd8aa9c8aa0cc9cb042328288",
        "review": "get_output_local: TypeOp local defaults drop underscore bindings (0f0a060)",
    },
    {
        "base_id": "RG-F-2282417c93d08f203cd9",
        "from_id": "RG-F-2282417c93d08f203cd9",
        "to_id": "RG-F-5c1a94676a8a8172bfdd",
        "commit": "11371d512e9b374ec73d5a7e7181e6ed52eba296",
        "from_path": "src/stringmanage.rs",
        "to_path": "src/stringmanage.rs",
        "parent_blob": "a5c0c6f9557598bc6a1de70606b74d5d71c7f8ab",
        "child_blob": "33ee849f1de230fd087e1131d1104c3c3522a955",
        "review": "get_string_data: GhidraStringManager Java contract signature (11371d5)",
    },
    {
        "base_id": "RG-F-9f084ffd4f7bca8a8785",
        "from_id": "RG-F-9f084ffd4f7bca8a8785",
        "to_id": "RG-F-ecbbaedaac3eea1407e1",
        "commit": "7b1da21a3a874598423a4b6b941eb2209545fc15",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "a9179e6432deabd7f9dfd228ed71a94a5d1ff2ba",
        "child_blob": "e5f011d57cba1ed13a4690af964c25a92de3b9af",
        "review": "deindirect: noreturn predicate removed from inherited surface (7b1da21)",
    },
    {
        "base_id": "RG-F-353d179342f1b8c88e5b",
        "from_id": "RG-F-353d179342f1b8c88e5b",
        "to_id": "RG-F-4fc23f9164942392a358",
        "commit": "c042d9a2fac9934806c6e93702fbaaf5d1859a04",
        "from_path": "src/varmap.rs",
        "to_path": "src/varmap.rs",
        "parent_blob": "af7630a51fb0912a494c87fbb34d2a8c513584d5",
        "child_blob": "669fb3487998479941a2a28d1fe4fd70fff422ad",
        "review": "new_with_default: MapState window range vector (c042d9a)",
    },
    {
        "base_id": "RG-F-4cdd5bd19c95d3404ef9",
        "from_id": "RG-F-4cdd5bd19c95d3404ef9",
        "to_id": "RG-F-e2b08074d7ef80d46a19",
        "commit": "c042d9a2fac9934806c6e93702fbaaf5d1859a04",
        "from_path": "src/varmap.rs",
        "to_path": "src/varmap.rs",
        "parent_blob": "af7630a51fb0912a494c87fbb34d2a8c513584d5",
        "child_blob": "669fb3487998479941a2a28d1fe4fd70fff422ad",
        "review": "new: MapState window range vector (c042d9a)",
    },

    {
        "base_id": "RG-F-7e4b009ae1d8d5f62495",
        "from_id": "RG-F-7e4b009ae1d8d5f62495",
        "to_id": "RG-F-8ae418e1953a52a1525c",
        "commit": "01712a22f679a8edfee0fa7483aca179f243286c",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "2c664422614089f21dc74d6444c220ce2e650266",
        "child_blob": "4a49544aeb54f863fbdc8b30cee076e2099fb59f",
        "review": "push_constant_typed: gains vn/op context for the TYPE_SPACEBASE &DAT arm (01712a22)",
    },
    {
        "base_id": "RG-F-dae04c9c907df09546fa",
        "from_id": "RG-F-dae04c9c907df09546fa",
        "to_id": "RG-F-278468edac56855d183b",
        "commit": "01712a22f679a8edfee0fa7483aca179f243286c",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "2c664422614089f21dc74d6444c220ce2e650266",
        "child_blob": "4a49544aeb54f863fbdc8b30cee076e2099fb59f",
        "review": "push_partial_symbol: gains space context for the TYPE_SPACEBASE &DAT arm (01712a22)",
    },
    {
        "base_id": "RG-F-3dde2c94bf8d902d5057",
        "from_id": "RG-F-3dde2c94bf8d902d5057",
        "to_id": "RG-F-bc69c26bf6c937ea608a",
        "commit": "01712a22f679a8edfee0fa7483aca179f243286c",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "2c664422614089f21dc74d6444c220ce2e650266",
        "child_blob": "4a49544aeb54f863fbdc8b30cee076e2099fb59f",
        "review": "push_ptr_char_constant: gains ct/op context for the pointer-char constant arm (01712a22)",
    },
    {
        "base_id": "RG-F-85317e7aebd33b457844",
        "from_id": "RG-F-85317e7aebd33b457844",
        "to_id": "RG-F-98be7769343f7b648186",
        "commit": "0e9aadfb57ea395905fd20bb289539b98eba3d98",
        "from_path": "src/varnode.rs",
        "to_path": "src/varnode.rs",
        "parent_blob": "8cc5d32fece98f1bf7cf6e01cfa85d24b16b8415",
        "child_blob": "1c05d7e2d2a27dbb3e971c9b428dc9afefae4747",
        "review": "get_local_type: gains type_factory param; STOP early-return + full localType dispatch (0e9aadfb)",
    },
    {
        "base_id": "RG-F-d9bbc5bf257eba661cde",
        "from_id": "RG-F-d9bbc5bf257eba661cde",
        "to_id": "RG-F-a87f5098b9cb3d94a709",
        "commit": "1644180de42b58cd0155f62c9b3ad82efc820a57",
        "from_path": "src/options.rs",
        "to_path": "src/options.rs",
        "parent_blob": "a94e6f58f60a02e2b5ac52e68ed822ccc7ab3f0d",
        "child_blob": "b8734eb52066baf8a30f8e81846f9df3d3855932",
        "review": "apply: p3 binding now consumed by the 12.0.4 bit semantics (1644180d)",
    },
    {
        "base_id": "RG-F-6f6a818a4e632357b615",
        "from_id": "RG-F-6f6a818a4e632357b615",
        "to_id": "RG-F-0345c93508ad882e10c3",
        "commit": "17e0a639318c0d1248ace608f6a975b8ced85d2c",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "15d1b123a975915a62ee661414b16c4e9cbba5dc",
        "child_blob": "d135ae48b234a97c157a019368b938ef5a5c0ac9",
        "review": "reset: fd binding now consumed by the breakpoint-aware pool executor (17e0a639)",
    },
    {
        "base_id": "RG-F-c1ee72b6e2546281e74f",
        "from_id": "RG-F-c1ee72b6e2546281e74f",
        "to_id": "RG-F-0eb65941d5d8f3ff01fc",
        "commit": "26d675e7f6131ed17e8de6a689b5b3d85ec21470",
        "from_path": "src/subflow.rs",
        "to_path": "src/subflow.rs",
        "parent_blob": "5b0ddb920d904ae2b396c4535713ae28f47d9ac3",
        "child_blob": "cae7b73c4da887e634cd5fde6dff16b0343d1933",
        "review": "split_load: gains in_type param for the exact-piece gate chain (26d675e7)",
    },
    {
        "base_id": "RG-F-0e57c9f536067337d286",
        "from_id": "RG-F-0e57c9f536067337d286",
        "to_id": "RG-F-5d4cb90317ed3e77a0b1",
        "commit": "26d675e7f6131ed17e8de6a689b5b3d85ec21470",
        "from_path": "src/subflow.rs",
        "to_path": "src/subflow.rs",
        "parent_blob": "5b0ddb920d904ae2b396c4535713ae28f47d9ac3",
        "child_blob": "cae7b73c4da887e634cd5fde6dff16b0343d1933",
        "review": "split_store: gains out_type param for the exact-piece gate chain (26d675e7)",
    },
    {
        "base_id": "RG-F-a952489a1e2a692af4c1",
        "from_id": "RG-F-a952489a1e2a692af4c1",
        "to_id": "RG-F-19772f7e6c72893d19e5",
        "commit": "28a28b1f2059d6f6e854df9bfaa544e4a9fb2a51",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "b1b03416fc4a292ce8b744318b0cb653f440f823",
        "child_blob": "b822eb0d2cd3f8dc9b59bf0217902c42e3695390",
        "review": "justified_contain_range: gains space endianness param (FSPEC-JUSTIFIED-ENDIAN-0002) (28a28b1f)",
    },
    {
        "base_id": "RG-F-51aa66bc4efbef5ce41c",
        "from_id": "RG-F-51aa66bc4efbef5ce41c",
        "to_id": "RG-F-68b7284fc2778ca40e41",
        "commit": "55ef99439ea5944369cd1e9ad19607c84d3e08b8",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "60dce4ad46631a8ba4521e2da55f6f115b153731",
        "child_blob": "c17f052efa3d89a485c275022967d0d58c5b07a1",
        "review": "assumed_extension: gains leading space param (space-aware possible_param) (55ef9943)",
    },
    {
        "base_id": "RG-F-67827efc2b3b4d4016b9",
        "from_id": "RG-F-67827efc2b3b4d4016b9",
        "to_id": "RG-F-3cd23de12de85f61b589",
        "commit": "55ef99439ea5944369cd1e9ad19607c84d3e08b8",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "60dce4ad46631a8ba4521e2da55f6f115b153731",
        "child_blob": "c17f052efa3d89a485c275022967d0d58c5b07a1",
        "review": "assumed_extension: gains query_space param (space-aware possible_param) (55ef9943)",
    },
    {
        "base_id": "RG-F-29b64f515e2cc6b8a2d7",
        "from_id": "RG-F-29b64f515e2cc6b8a2d7",
        "to_id": "RG-F-55f51939bbaf977e476c",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "build_addresses: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-48cebeae7b1f1b743e6f",
        "from_id": "RG-F-48cebeae7b1f1b743e6f",
        "to_id": "RG-F-328f0cee2b4153e006ab",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "build_addresses: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-6e9e5fc5dff33182265c",
        "from_id": "RG-F-6e9e5fc5dff33182265c",
        "to_id": "RG-F-60ce0f7505bfbf56fd42",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "build_addresses: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-903e4bede9d3b38af7ac",
        "from_id": "RG-F-903e4bede9d3b38af7ac",
        "to_id": "RG-F-3d84fca029aa0db125c4",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "build_addresses: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-b7b473477f7a70c35483",
        "from_id": "RG-F-b7b473477f7a70c35483",
        "to_id": "RG-F-12e5d41fb77844c41884",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "build_addresses: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-db63a0620cae7f35a1e5",
        "from_id": "RG-F-db63a0620cae7f35a1e5",
        "to_id": "RG-F-58043a6f46ae1c9b28c7",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "build_addresses: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-2ffe7f84827bd91a7a70",
        "from_id": "RG-F-2ffe7f84827bd91a7a70",
        "to_id": "RG-F-fdc4cfca398f53a8cc43",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "find_normalized: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-12a1ac7520a2936215cc",
        "from_id": "RG-F-12a1ac7520a2936215cc",
        "to_id": "RG-F-90a0ee5d5692ac0705d6",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "recover_model: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-1500b403d31dc09fa484",
        "from_id": "RG-F-1500b403d31dc09fa484",
        "to_id": "RG-F-bc273d6ed95b82759e0b",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "recover_model: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-1a0de177364519004226",
        "from_id": "RG-F-1a0de177364519004226",
        "to_id": "RG-F-7877c3db7566ba00b383",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "recover_model: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-83f03eae691bb0f57956",
        "from_id": "RG-F-83f03eae691bb0f57956",
        "to_id": "RG-F-5722d20b8628b430605b",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "recover_model: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-9b9f309fc6f60e4b3272",
        "from_id": "RG-F-9b9f309fc6f60e4b3272",
        "to_id": "RG-F-a3e8132b5200c04bc8bc",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "recover_model: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-a0778ccb56479e37c576",
        "from_id": "RG-F-a0778ccb56479e37c576",
        "to_id": "RG-F-7f5eae81c0f3bc99e3f3",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "recover_model: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-dbcf028e82133b9565c3",
        "from_id": "RG-F-dbcf028e82133b9565c3",
        "to_id": "RG-F-070808d769156b8f203d",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "recover_model: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-ef67f0f933f00d59516d",
        "from_id": "RG-F-ef67f0f933f00d59516d",
        "to_id": "RG-F-601eb1ab580c9774525d",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "sanity_check: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-ba5f8ef92122364caff2",
        "from_id": "RG-F-ba5f8ef92122364caff2",
        "to_id": "RG-F-9abcbe19cd51f069dcce",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "review": "base_local_type: gains metatype param for getBase(size, ctor meta) (8e5944ca)",
    },
    {
        "base_id": "RG-F-1696a469c1e4f234a381",
        "from_id": "RG-F-1696a469c1e4f234a381",
        "to_id": "RG-F-0725ce4eafd7506761ce",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "review": "get_input_local: slot binding now consumed by the getBase dispatch (8e5944ca)",
    },
    {
        "base_id": "RG-F-39e123daf5f57401f23b",
        "from_id": "RG-F-39e123daf5f57401f23b",
        "to_id": "RG-F-e2da956f10d8f38b8bfd",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "review": "get_input_local: slot binding now consumed by the getBase dispatch (8e5944ca)",
    },
    {
        "base_id": "RG-F-471897415751e5d275d8",
        "from_id": "RG-F-471897415751e5d275d8",
        "to_id": "RG-F-dde1a3ccdb9db5f6d490",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "review": "get_input_local: slot binding now consumed by the getBase dispatch (8e5944ca)",
    },
    {
        "base_id": "RG-F-885b524a8f76bbb842bd",
        "from_id": "RG-F-885b524a8f76bbb842bd",
        "to_id": "RG-F-fb859141aef85785ef0f",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "review": "get_input_local: slot binding now consumed by the getBase dispatch (8e5944ca)",
    },
    {
        "base_id": "RG-F-a33c0fce3605345a648e",
        "from_id": "RG-F-a33c0fce3605345a648e",
        "to_id": "RG-F-591ad2963b9ceb809480",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "review": "get_input_local: slot binding now consumed by the getBase dispatch (8e5944ca)",
    },
    {
        "base_id": "RG-F-afcc95cc17357bffe136",
        "from_id": "RG-F-afcc95cc17357bffe136",
        "to_id": "RG-F-25034d16aceabddf9230",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "review": "get_input_local: slot binding now consumed by the getBase dispatch (8e5944ca)",
    },
    {
        "base_id": "RG-F-cc32cb3caeaee660aa33",
        "from_id": "RG-F-cc32cb3caeaee660aa33",
        "to_id": "RG-F-0cd5548a65347108ceb2",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "review": "get_input_local: slot binding now consumed by the getBase dispatch (8e5944ca)",
    },
    {
        "base_id": "RG-F-32b69c55e48850549780",
        "from_id": "RG-F-32b69c55e48850549780",
        "to_id": "RG-F-914ebd32697eb67d4df6",
        "commit": "b8da22a86f28cb2750fe85e1a7c69391c900a1fc",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "0dcdf7eb67c8994d71e8e80951c0dd71644e2a2e",
        "child_blob": "23cca3811e8d92f034f150dde3216b255206dc96",
        "review": "truncate_indirect_jump: fail_mode u8 becomes the typed truncation mode (b8da22a8)",
    },
    {
        "base_id": "RG-F-b963ca1fc0328358033f",
        "from_id": "RG-F-b963ca1fc0328358033f",
        "to_id": "RG-F-333df7b03f2b23fe523c",
        "commit": "c37044b8420f80a73ffa16fed6941f760c5b02ba",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "b822eb0d2cd3f8dc9b59bf0217902c42e3695390",
        "child_blob": "60dce4ad46631a8ba4521e2da55f6f115b153731",
        "review": "find_entry: space Option becomes a required AddressSpace (resolver find-window gating) (c37044b8)",
    },
    {
        "base_id": "RG-F-85317e7aebd33b457844",
        "from_id": "RG-F-98be7769343f7b648186",
        "to_id": "RG-F-e1751080679995008f76",
        "commit": "c5a421dd82cff21c6abcd754008a275657b2a86f",
        "from_path": "src/varnode.rs",
        "to_path": "src/varnode.rs",
        "parent_blob": "1c05d7e2d2a27dbb3e971c9b428dc9afefae4747",
        "child_blob": "4f6dc0fb33ad2bf574b2c1699af712036e837976",
        "review": "get_local_type: CALLOTHER arm added to the localType dispatch (userops thread) (c5a421dd)",
    },
    {
        "base_id": "RG-F-44fcf9a5c35080fabaf4",
        "from_id": "RG-F-44fcf9a5c35080fabaf4",
        "to_id": "RG-F-4e04105edbeff7dd0eaa",
        "commit": "c5a421dd82cff21c6abcd754008a275657b2a86f",
        "from_path": "src/varnode.rs",
        "to_path": "src/varnode.rs",
        "parent_blob": "1c05d7e2d2a27dbb3e971c9b428dc9afefae4747",
        "child_blob": "4f6dc0fb33ad2bf574b2c1699af712036e837976",
        "review": "op_input_type_local: CALLOTHER arm added to the input localType dispatch (c5a421dd)",
    },
    {
        "base_id": "RG-F-efcf794f8358682dd6e9",
        "from_id": "RG-F-efcf794f8358682dd6e9",
        "to_id": "RG-F-94a2b6bd1410db433619",
        "commit": "c5a421dd82cff21c6abcd754008a275657b2a86f",
        "from_path": "src/varnode.rs",
        "to_path": "src/varnode.rs",
        "parent_blob": "1c05d7e2d2a27dbb3e971c9b428dc9afefae4747",
        "child_blob": "4f6dc0fb33ad2bf574b2c1699af712036e837976",
        "review": "op_output_type_local: CALLOTHER arm added to the output localType dispatch (c5a421dd)",
    },
    {
        "base_id": "RG-F-5da2232cfccfbc48236b",
        "from_id": "RG-F-5da2232cfccfbc48236b",
        "to_id": "RG-F-147b2914b0460c3b7e89",
        "commit": "c9daaeb58d8c2d8fe2872ae1e015303a35ef42b0",
        "from_path": "src/database.rs",
        "to_path": "src/database.rs",
        "parent_blob": "64fad62b6c9ad3ec69cb293947c3931d5568bc00",
        "child_blob": "4c78b645cd26782006884344fbb68b1f27f5a6de",
        "review": "map_scope: qpoint binding now consumed by queryContainer/queryProperties (c9daaeb5)",
    },
    {
        "base_id": "RG-F-9e35fb6c959b18a5a1ba",
        "from_id": "RG-F-9e35fb6c959b18a5a1ba",
        "to_id": "RG-F-9e79bde7c5d1fb8f92c3",
        "commit": "cddcefd88006dd68ed69284ed31562a08fda3107",
        "from_path": "src/tracedag.rs",
        "to_path": "src/tracedag.rs",
        "parent_blob": "86545928d1c129fe81f7b015e96d0423587227b9",
        "child_blob": "e12d39bf91c0512f3c20e9b37bba4cb7d49ce74f",
        "review": "open_branch: returns Option<usize> under the goto-cascade oracle (cddcefd8)",
    },
    {
        "base_id": "RG-F-e1c8120aff0b2b2ab02d",
        "from_id": "RG-F-e1c8120aff0b2b2ab02d",
        "to_id": "RG-F-92442e738d9250d093f2",
        "commit": "cddcefd88006dd68ed69284ed31562a08fda3107",
        "from_path": "src/tracedag.rs",
        "to_path": "src/tracedag.rs",
        "parent_blob": "86545928d1c129fe81f7b015e96d0423587227b9",
        "child_blob": "e12d39bf91c0512f3c20e9b37bba4cb7d49ce74f",
        "review": "retire_branch: returns Option<usize> under the goto-cascade oracle (cddcefd8)",
    },
    {
        "base_id": "RG-F-bb20c591cf86c2a9f868",
        "from_id": "RG-F-bb20c591cf86c2a9f868",
        "to_id": "RG-F-c9feebcf8cdadccd5d46",
        "commit": "cddcefd88006dd68ed69284ed31562a08fda3107",
        "from_path": "src/tracedag.rs",
        "to_path": "src/tracedag.rs",
        "parent_blob": "86545928d1c129fe81f7b015e96d0423587227b9",
        "child_blob": "e12d39bf91c0512f3c20e9b37bba4cb7d49ce74f",
        "review": "select_bad_edge: &self becomes &mut self under the goto-cascade oracle (cddcefd8)",
    },
    {
        "base_id": "RG-F-d8e0a50ea15b7f15c23f",
        "from_id": "RG-F-d8e0a50ea15b7f15c23f",
        "to_id": "RG-F-d03ae0650e666c500a8e",
        "commit": "d9171ef107031ef5e21dea980319fe6e9982311f",
        "from_path": "src/space.rs",
        "to_path": "src/space.rs",
        "parent_blob": "b27aad8584fe8e4b87b19b35c330e31e66a6ab17",
        "child_blob": "97f05c9ebace339d9ad904438687c8134c0acf4b",
        "review": "decode_attributes: gains spc_manager codec context (packed special-space codec) (d9171ef1)",
    },
    {
        "base_id": "RG-F-208f18dc3bc2543b44b9",
        "from_id": "RG-F-208f18dc3bc2543b44b9",
        "to_id": "RG-F-bdbde6f78df46af9dd05",
        "commit": "f95369a92955988783e0148c496f3a91a95d47ed",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "94730ba339462aabed58e22d45748196acae1095",
        "child_blob": "402ff52d848e396d0cfffaab35167e0e658f2060",
        "review": "call_op_indirect_effect: gains leading space param (guard fl query) (f95369a9)",
    },
    {
        "base_id": "RG-F-c07f97463d7249eed59e",
        "from_id": "RG-F-c07f97463d7249eed59e",
        "to_id": "RG-F-edd4713c9bdadd7ab3e4",
        "commit": "f95369a92955988783e0148c496f3a91a95d47ed",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "94730ba339462aabed58e22d45748196acae1095",
        "child_blob": "402ff52d848e396d0cfffaab35167e0e658f2060",
        "review": "normalize_write_size: gains leading space param (guard fl query) (f95369a9)",
    },

    # --- extension window 1f3aea4a..3fb97c11 (ORACLE-REGISTRY-IMPACT-CONTINUITY-0001) ---
    {
        "base_id": "RG-F-3a923bfee6882417fc96",
        "from_id": "RG-F-057e8e805c9d6f3e0545",
        "to_id": "RG-F-2a34c9f6095ee64fb93b",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/debugproto.rs",
        "to_path": "src/debugproto.rs",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "review": "locked_proto: drop param [storage: &X86_64GccStorage]; gain param [model_carrier: &FuncProto] (26eee4ad)",
    },
    {
        "base_id": "RG-F-0dbef8d4c630c37f0f20",
        "from_id": "RG-F-0dbef8d4c630c37f0f20",
        "to_id": "RG-F-10bd03523f37860dd01b",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "dd96fa9045a1c139a553a12d011fb5e2206b2db0",
        "child_blob": "da974cb01433fd7580dd3cfb1b1d03ca721263d7",
        "review": "get_active_output: returns -> Option<&ParamActive> -> -> &ParamActive (26eee4ad)",
    },
    {
        "base_id": "RG-F-24db94981a0293b2e2b5",
        "from_id": "RG-F-24db94981a0293b2e2b5",
        "to_id": "RG-F-25ed035b36f7473c2032",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/debugproto.rs",
        "to_path": "src/debugproto.rs",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "review": "locked_callsite_proto: drop param [storage: &X86_64GccStorage] (26eee4ad)",
    },
    {
        "base_id": "RG-F-9e895a3a0250ae83b691",
        "from_id": "RG-F-36f312ac16b8aeb056bf",
        "to_id": "RG-F-56e4e3f45e08c5c2f01d",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "a07b84aa844f90a3f2f3656729b449360dbd77df",
        "child_blob": "b03c2682c3c0301b34b14fe273f297b4c067bcc3",
        "review": "func_link_input: returns  -> -> Result<()> (26eee4ad)",
    },
    {
        "base_id": "RG-F-403c62b545e4c4c6862a",
        "from_id": "RG-F-403c62b545e4c4c6862a",
        "to_id": "RG-F-d767ef0840705c775605",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "dd96fa9045a1c139a553a12d011fb5e2206b2db0",
        "child_blob": "da974cb01433fd7580dd3cfb1b1d03ca721263d7",
        "review": "get_active_input: returns -> Option<&ParamActive> -> -> &ParamActive (26eee4ad)",
    },
    {
        "base_id": "RG-F-407c79f6fb505c89bd8b",
        "from_id": "RG-F-407c79f6fb505c89bd8b",
        "to_id": "RG-F-f6c32b17adf47c37ff5f",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/debugproto.rs",
        "to_path": "src/debugproto.rs",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "review": "void_signature_dwarf_prototype_pins_unknown_model: rename: void input list keeps the caller-bound model (fspec.cc decode modellock) (26eee4ad)",
    },
    {
        "base_id": "RG-F-73f78dcee4467e087cd2",
        "from_id": "RG-F-73f78dcee4467e087cd2",
        "to_id": "RG-F-1eb0987634d9064bb18a",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "a07b84aa844f90a3f2f3656729b449360dbd77df",
        "child_blob": "b03c2682c3c0301b34b14fe273f297b4c067bcc3",
        "review": "proto_has_input_errors: param _proto:&crate -> &crate (26eee4ad)",
    },
    {
        "base_id": "RG-F-9bc90d81a5b23d53a9f8",
        "from_id": "RG-F-9bc90d81a5b23d53a9f8",
        "to_id": "RG-F-2a845dc07da7597798b6",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/debugproto.rs",
        "to_path": "src/debugproto.rs",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "review": "locked_proto: drop param [storage: &X86_64GccStorage] (26eee4ad)",
    },
    {
        "base_id": "RG-F-a99abc66852a3dff734e",
        "from_id": "RG-F-a99abc66852a3dff734e",
        "to_id": "RG-F-1ce28154f6b860b85d1e",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/debugproto.rs",
        "to_path": "src/debugproto.rs",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "review": "apply: drop param [storage: &X86_64GccStorage] (26eee4ad)",
    },
    {
        "base_id": "RG-F-c0ee2922e77c9119c79f",
        "from_id": "RG-F-c0ee2922e77c9119c79f",
        "to_id": "RG-F-f69d8955656e7dadd499",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "dd96fa9045a1c139a553a12d011fb5e2206b2db0",
        "child_blob": "da974cb01433fd7580dd3cfb1b1d03ca721263d7",
        "review": "assign_address: param dt:&Datatype -> &Arc<Datatype> (26eee4ad)",
    },
    {
        "base_id": "RG-F-c385cd66a20c157f5332",
        "from_id": "RG-F-c385cd66a20c157f5332",
        "to_id": "RG-F-9fcd346dc88678c0690c",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "dd96fa9045a1c139a553a12d011fb5e2206b2db0",
        "child_blob": "da974cb01433fd7580dd3cfb1b1d03ca721263d7",
        "review": "assign_address_fallback: param tp:&Datatype -> &Arc<Datatype> (26eee4ad)",
    },
    {
        "base_id": "RG-F-02af378dcb9608ea64b2",
        "from_id": "RG-F-02af378dcb9608ea64b2",
        "to_id": "RG-F-92db0ea13919ec8be271",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "5294bda8f0e39fa14facd6b59d066c379a416b35",
        "child_blob": "5f43cf8954f5a62b8573be019c88a3a608d9ccd2",
        "review": "set_default_switch: move: trait default re-hosted as mirroring free fn (block.cc:318 FlowBlock::setDefaultSwitch) (2d78b5af)",
    },
    {
        "base_id": "RG-F-183a83727d39b25f669d",
        "from_id": "RG-F-183a83727d39b25f669d",
        "to_id": "RG-F-0f8fe610df74d4044b50",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "from_path": "src/blockaction.rs",
        "to_path": "src/block.rs",
        "parent_blob": "22707482e6a340dfad8f51f8549825816b7426f6",
        "child_blob": "5f43cf8954f5a62b8573be019c88a3a608d9ccd2",
        "review": "build_copy: move: free build_copy(sblocks, bblocks) becomes BlockGraph::build_copy(&mut self, graph) (2d78b5af)",
    },
    {
        "base_id": "RG-F-1847710578ba36f41a2c",
        "from_id": "RG-F-1847710578ba36f41a2c",
        "to_id": "RG-F-fdec08b5119c673abb6c",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "5294bda8f0e39fa14facd6b59d066c379a416b35",
        "child_blob": "5f43cf8954f5a62b8573be019c88a3a608d9ccd2",
        "review": "get_out: param _slot:usize -> usize (2d78b5af)",
    },
    {
        "base_id": "RG-F-1a0435a14acc3aa3522b",
        "from_id": "RG-F-1a0435a14acc3aa3522b",
        "to_id": "RG-F-f2222bbb6aa727fbb4d8",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "5294bda8f0e39fa14facd6b59d066c379a416b35",
        "child_blob": "5f43cf8954f5a62b8573be019c88a3a608d9ccd2",
        "review": "get_in: param _slot:usize -> usize (2d78b5af)",
    },
    {
        "base_id": "RG-F-2030541ea9b02a722a22",
        "from_id": "RG-F-2030541ea9b02a722a22",
        "to_id": "RG-F-6fe47f3146f53627e732",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "5294bda8f0e39fa14facd6b59d066c379a416b35",
        "child_blob": "5f43cf8954f5a62b8573be019c88a3a608d9ccd2",
        "review": "add_out_edge: param _edge:BlockEdge -> BlockEdge (2d78b5af)",
    },
    {
        "base_id": "RG-F-24364fbcca97705e6585",
        "from_id": "RG-F-24364fbcca97705e6585",
        "to_id": "RG-F-1dd7a348a0462e68228e",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "5294bda8f0e39fa14facd6b59d066c379a416b35",
        "child_blob": "5f43cf8954f5a62b8573be019c88a3a608d9ccd2",
        "review": "add_in_edge: param _edge:BlockEdge -> BlockEdge (2d78b5af)",
    },
    {
        "base_id": "RG-F-5b884c90f4650cb85895",
        "from_id": "RG-F-5b884c90f4650cb85895",
        "to_id": "RG-F-59926f42e76a1316cad6",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "from_path": "src/blockaction.rs",
        "to_path": "src/blockaction.rs",
        "parent_blob": "22707482e6a340dfad8f51f8549825816b7426f6",
        "child_blob": "86fc48bd21f36999a488fed88ee221763c9d6eae",
        "review": "_get_change_count: rename: LoopBody::GetChangeCount moved to CollapseStructure::getChangeCount annotation (2d78b5af)",
    },
    {
        "base_id": "RG-F-bbd8e4d05192bc9c2e93",
        "from_id": "RG-F-bbd8e4d05192bc9c2e93",
        "to_id": "RG-F-08a1b796e1c02e6be764",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "5294bda8f0e39fa14facd6b59d066c379a416b35",
        "child_blob": "5f43cf8954f5a62b8573be019c88a3a608d9ccd2",
        "review": "negate_condition: param toporbottom:bool -> bool (2d78b5af)",
    },
    {
        "base_id": "RG-F-abf77d064f1ec656081b",
        "from_id": "RG-F-abf77d064f1ec656081b",
        "to_id": "RG-F-426390a6112c3dbc6c2b",
        "commit": "3dc4b2ae3c2b7a29104a26aa54c56d36380bdb70",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "add44383796bbd787055caae7aa406d02d236d4f",
        "child_blob": "8bf645e06a62cffeda585f4d853cf5895ce4fc05",
        "review": "try_output_stack_guard: gain param [locked_output_storage: Option<(Address, i32)>] (3dc4b2ae)",
    },
    {
        "base_id": "RG-F-003416535aaee2f83d44",
        "from_id": "RG-F-003416535aaee2f83d44",
        "to_id": "RG-F-81062ccc03179475b483",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "f8215674fd7558ef4d609c8a296dd8b4d67ea47b",
        "child_blob": "1d914b9597164fd5cc46518d1384d1ed2eb67862",
        "review": "query_container_entry_parent_scope: returns -> Option<(u64, std::sync::Arc<std::sync::RwLock<crate::data -> -> Option<( u64, std::sync::Arc<std::sync::RwLock<crate::dat (3fb97c11)",
    },
    {
        "base_id": "RG-F-11a5ff425fc4c01b4da8",
        "from_id": "RG-F-11a5ff425fc4c01b4da8",
        "to_id": "RG-F-bfadcbc9981a3a281fff",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "03efffda74f9c4aaa212407845eb2d963111474b",
        "child_blob": "659bbea603929d97c83ef8ecdf77c42364e293cd",
        "review": "get_mult_coeff: returns -> (std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode -> -> ( std::sync::Arc<std::sync::RwLock<crate::varnode::Varnod (3fb97c11)",
    },
    {
        "base_id": "RG-F-13b326553ae8f9898f77",
        "from_id": "RG-F-13b326553ae8f9898f77",
        "to_id": "RG-F-c43098d7d6918b6b28b5",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/type_system/cast.rs",
        "to_path": "src/type_system/cast.rs",
        "parent_blob": "ea420513dfb61cf6dc7be78d03c5910a2cc88bb5",
        "child_blob": "f66af728bc8fe488919cedfb1687368060b20c95",
        "review": "check_int_promotion_for_compare: drop param [op_type: &Datatype]; gain param [op: &PcodeOp; slot: usize] (3fb97c11)",
    },
    {
        "base_id": "RG-F-1a31e6c2b34252958c71",
        "from_id": "RG-F-1a31e6c2b34252958c71",
        "to_id": "RG-F-051d6dc01af5e493d722",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "flow_last_op: param block_arc:&std -> &std (3fb97c11)",
    },
    {
        "base_id": "RG-F-1f9c977e2c885a2fcd1c",
        "from_id": "RG-F-1f9c977e2c885a2fcd1c",
        "to_id": "RG-F-9e8d3ad4aa0167ab2793",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "03efffda74f9c4aaa212407845eb2d963111474b",
        "child_blob": "659bbea603929d97c83ef8ecdf77c42364e293cd",
        "review": "test_early_removal_register_output_blocked: rename: REGISTER output now removed under pass-1 strict delay instead of blanket block (3fb97c11)",
    },
    {
        "base_id": "RG-F-35caa9e455d7c3452c64",
        "from_id": "RG-F-35caa9e455d7c3452c64",
        "to_id": "RG-F-00bc5c5c59d8e247f17e",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "03efffda74f9c4aaa212407845eb2d963111474b",
        "child_blob": "659bbea603929d97c83ef8ecdf77c42364e293cd",
        "review": "build_op: returns -> (crate::op::PcodeOpRef, std::sync::Arc<RwLock<crate::varn -> -> ( crate::op::PcodeOpRef, std::sync::Arc<RwLock<crate::var (3fb97c11)",
    },
    {
        "base_id": "RG-F-3aae0be2241ef765314f",
        "from_id": "RG-F-3aae0be2241ef765314f",
        "to_id": "RG-F-2160ffb27d9d6b5a7f8d",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "03efffda74f9c4aaa212407845eb2d963111474b",
        "child_blob": "659bbea603929d97c83ef8ecdf77c42364e293cd",
        "review": "get_boolean_result: returns -> (Option<std::sync::Arc<std::sync::RwLock<crate::varnode:: -> -> ( Option<std::sync::Arc<std::sync::RwLock<crate::varnode: (3fb97c11)",
    },
    {
        "base_id": "RG-F-4519b750d13bed433120",
        "from_id": "RG-F-4519b750d13bed433120",
        "to_id": "RG-F-7ab0b03534ee5b2ef25c",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/type_system/cast.rs",
        "to_path": "src/type_system/cast.rs",
        "parent_blob": "ea420513dfb61cf6dc7be78d03c5910a2cc88bb5",
        "child_blob": "f66af728bc8fe488919cedfb1687368060b20c95",
        "review": "check_int_promotion_for_compare: drop param [op_type: &Datatype]; gain param [op: &PcodeOp; slot: usize] (3fb97c11)",
    },
    {
        "base_id": "RG-F-78f6c10072ae947b9b26",
        "from_id": "RG-F-78f6c10072ae947b9b26",
        "to_id": "RG-F-29239adf25ac56679a79",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "5135162a626b55df13c381c54d7efa669d8db4f9",
        "child_blob": "8c3af8f0602f09477975f38d601c803c60a2375c",
        "review": "check_clog: returns -> ( i32, Option<(crate::address::Address, usize)>, ) -> -> ( i32, Option<(crate::address::Address, usize)>) (3fb97c11)",
    },
    {
        "base_id": "RG-F-856e53a8550be68cc92e",
        "from_id": "RG-F-856e53a8550be68cc92e",
        "to_id": "RG-F-bf6865da3e03b11eafae",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/blockaction.rs",
        "to_path": "src/blockaction.rs",
        "parent_blob": "86fc48bd21f36999a488fed88ee221763c9d6eae",
        "child_blob": "a7dea226400f647d5db435bc4f1302236c6ecb16",
        "review": "new_block_if: drop param [negated: bool] (3fb97c11)",
    },
    {
        "base_id": "RG-F-5c67bfa2b4dafad127e9",
        "from_id": "RG-F-885ac55c9454c2379e9b",
        "to_id": "RG-F-55b083f921edad907204",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "emit_block_structured: param block_arc:&std -> &std (3fb97c11)",
    },
    {
        "base_id": "RG-F-8d0c27bf0ef286bbf8b4",
        "from_id": "RG-F-8d0c27bf0ef286bbf8b4",
        "to_id": "RG-F-b970909461534a9c9b3e",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "make_atom_for_vn: param _op:&PcodeOp -> &PcodeOp (3fb97c11)",
    },
    {
        "base_id": "RG-F-8fbf2f389d0c6c824c78",
        "from_id": "RG-F-8fbf2f389d0c6c824c78",
        "to_id": "RG-F-2303c505805d68842c9a",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "flow_entry_address: param block_arc:&std -> &std (3fb97c11)",
    },
    {
        "base_id": "RG-F-a176e923c63403710964",
        "from_id": "RG-F-a176e923c63403710964",
        "to_id": "RG-F-0e446c2b7aa88ef6b4a2",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "emit_flow_basic: param block_arc:&std -> &std (3fb97c11)",
    },
    {
        "base_id": "RG-F-cbd102e6173cd8cf0653",
        "from_id": "RG-F-ac045b62b01e997d6bab",
        "to_id": "RG-F-5701b1ca48b5f80a7e9f",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "is_block_body_empty: param block_arc:&std -> &std (3fb97c11)",
    },
    {
        "base_id": "RG-F-c1f21ae5ca7ac7e7aa3c",
        "from_id": "RG-F-c1f21ae5ca7ac7e7aa3c",
        "to_id": "RG-F-3a3073abf02fbff97aca",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "03efffda74f9c4aaa212407845eb2d963111474b",
        "child_blob": "659bbea603929d97c83ef8ecdf77c42364e293cd",
        "review": "build_near_mult: returns -> (crate::op::PcodeOpRef, std::sync::Arc<RwLock<crate::varn -> -> ( crate::op::PcodeOpRef, std::sync::Arc<RwLock<crate::var (3fb97c11)",
    },
    {
        "base_id": "RG-F-c7d3359e93081883b23e",
        "from_id": "RG-F-c7d3359e93081883b23e",
        "to_id": "RG-F-e5567279d4d848c68284",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "emit_flow_block: param block_arc:&std -> &std (3fb97c11)",
    },
    {
        "base_id": "RG-F-cffb162ddc3991a0c693",
        "from_id": "RG-F-cffb162ddc3991a0c693",
        "to_id": "RG-F-b98549747f90bdc02553",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/blockaction.rs",
        "to_path": "src/blockaction.rs",
        "parent_blob": "86fc48bd21f36999a488fed88ee221763c9d6eae",
        "child_blob": "a7dea226400f647d5db435bc4f1302236c6ecb16",
        "review": "new_block_if_else: drop param [negated: bool] (3fb97c11)",
    },
    {
        "base_id": "RG-F-dfc7d3bfa1c1d97086b3",
        "from_id": "RG-F-dfc7d3bfa1c1d97086b3",
        "to_id": "RG-F-5d59c2f260f92a5d1e58",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "flow_next_in_flow: param block_arc:&std -> &std; returns -> Option< std::sync::Arc< std::sync::RwLock<dyn crate::bloc -> -> Option< std::sync::Arc< std::sync::RwLock<dyn crate::bloc (3fb97c11)",
    },
    {
        "base_id": "RG-F-8f4e504512ee200863f5",
        "from_id": "RG-F-e52849a77a9002740164",
        "to_id": "RG-F-4c2d5f93a06006739d44",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "5135162a626b55df13c381c54d7efa669d8db4f9",
        "child_blob": "8c3af8f0602f09477975f38d601c803c60a2375c",
        "review": "propagate_type_edge: gain param [active_path: &std::collections::HashSet<u64>]; param temps:&TempTypes -> &mut TempTypes (3fb97c11)",
    },
    {
        "base_id": "RG-F-f64771d7c6cdb9599854",
        "from_id": "RG-F-f64771d7c6cdb9599854",
        "to_id": "RG-F-bcee4c5acad4b0d3d723",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "5135162a626b55df13c381c54d7efa669d8db4f9",
        "child_blob": "8c3af8f0602f09477975f38d601c803c60a2375c",
        "review": "build_localtypes: param int_types:&IntTypes -> &IntTypes; param ptr_size:usize -> usize; returns  -> -> Result<()> (3fb97c11)",
    },
    {
        "base_id": "RG-F-3175e312a1638de63b65",
        "from_id": "RG-F-3175e312a1638de63b65",
        "to_id": "RG-F-f10f42d013ccec324dcb",
        "commit": "463664610f23956530f627e28f9388a6af858a99",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "70ee13a05dcdc6ee28edbf84bdee655b9619db4b",
        "child_blob": "adca5bb67309ddb2bea742395b05ec87c4e97426",
        "review": "propagate_type: gain param [type_factory: Option<&Arc<RwLock<crate::type_system::typefac] (46366461)",
    },
    {
        "base_id": "RG-F-45d25c0eb3e56e0ece17",
        "from_id": "RG-F-45d25c0eb3e56e0ece17",
        "to_id": "RG-F-d4778a26bbcf40edc07f",
        "commit": "463664610f23956530f627e28f9388a6af858a99",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "70ee13a05dcdc6ee28edbf84bdee655b9619db4b",
        "child_blob": "adca5bb67309ddb2bea742395b05ec87c4e97426",
        "review": "propagate_across_returns: gain param [type_factory: Option<&Arc<RwLock<crate::type_system::typefac] (46366461)",
    },
    {
        "base_id": "RG-F-69082e1a1446056c0929",
        "from_id": "RG-F-69082e1a1446056c0929",
        "to_id": "RG-F-68019a8fe1aec0a0531a",
        "commit": "463664610f23956530f627e28f9388a6af858a99",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "70ee13a05dcdc6ee28edbf84bdee655b9619db4b",
        "child_blob": "adca5bb67309ddb2bea742395b05ec87c4e97426",
        "review": "propagate_one_type: gain param [type_factory: Option<&Arc<RwLock<crate::type_system::typefac] (46366461)",
    },
    {
        "base_id": "RG-F-8f4e504512ee200863f5",
        "from_id": "RG-F-8f4e504512ee200863f5",
        "to_id": "RG-F-e52849a77a9002740164",
        "commit": "463664610f23956530f627e28f9388a6af858a99",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "70ee13a05dcdc6ee28edbf84bdee655b9619db4b",
        "child_blob": "adca5bb67309ddb2bea742395b05ec87c4e97426",
        "review": "propagate_type_edge: gain param [type_factory: Option<&Arc<RwLock<crate::type_system::typefac] (46366461)",
    },
    {
        "base_id": "RG-F-77adb336f064e67308a6",
        "from_id": "RG-F-77adb336f064e67308a6",
        "to_id": "RG-F-e659f766cf51c63bdac0",
        "commit": "4a4bd5c626a32c491be8cd4a2283890118bf92ae",
        "from_path": "src/blockaction.rs",
        "to_path": "src/blockaction.rs",
        "parent_blob": "18d3743bfc296841f92b9e60cff2157445b993ff",
        "child_blob": "19783ed47f4dd8ec46a0f8aa5c09945068d22068",
        "review": "emit_likely_edges: drop param [&self]; gain param [&mut self] (4a4bd5c6)",
    },
    {
        "base_id": "RG-F-3a923bfee6882417fc96",
        "from_id": "RG-F-3a923bfee6882417fc96",
        "to_id": "RG-F-057e8e805c9d6f3e0545",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/debugproto.rs",
        "to_path": "src/debugproto.rs",
        "parent_blob": "8c3eafbe1797839b0530ec4d05e8aac7db5d435e",
        "child_blob": "4f631611c0899990cd78cb2070603aaf58ed691b",
        "review": "locked_proto: gain param [type_names: Option<&HashMap<String, Arc<Datatype>>>] (4d1bcf29)",
    },
    {
        "base_id": "RG-F-55e8785cf6c756440521",
        "from_id": "RG-F-55e8785cf6c756440521",
        "to_id": "RG-F-c1d047496cda7d91d86b",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/debugproto.rs",
        "to_path": "src/debugproto.rs",
        "parent_blob": "8c3eafbe1797839b0530ec4d05e8aac7db5d435e",
        "child_blob": "4f631611c0899990cd78cb2070603aaf58ed691b",
        "review": "parse_c_type: gain param [type_names: Option<&HashMap<String, Arc<Datatype>>>] (4d1bcf29)",
    },
    {
        "base_id": "RG-F-665e889efe29adc78c07",
        "from_id": "RG-F-665e889efe29adc78c07",
        "to_id": "RG-F-08f7654728d229dc7238",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "23cca3811e8d92f034f150dde3216b255206dc96",
        "child_blob": "138bd3d6ed7356e95a0936ff1f2c187d933e9975",
        "review": "check_multistage_jumptables: drop param [&self]; gain param [&mut self]; returns -> Vec<crate::op::PcodeOpRef> ->  (4d1bcf29)",
    },
    {
        "base_id": "RG-F-6f57a74143457c1e6f5d",
        "from_id": "RG-F-6f57a74143457c1e6f5d",
        "to_id": "RG-F-c0396163cb5428d9eb7d",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "1b243873b6dec9e5d097851afa5145dd47423de6",
        "child_blob": "2077fc815895a435d64db91af6ab62c8104b248c",
        "review": "recover_jump_table: gain param [flow_state: &crate::flow::TruncatedFlowState]; returns -> Option<Arc<RwLock<crate::jumptable::JumpTable>>> -> -> crate::error::Result<Option<Arc<RwLock<crate::jumptable:: (4d1bcf29)",
    },
    {
        "base_id": "RG-F-9a81adb6d00ac21cfb47",
        "from_id": "RG-F-9a81adb6d00ac21cfb47",
        "to_id": "RG-F-d4922f3dbfb37b66e235",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "bd4a0a1de7286167b07d6a3d9e1fa9ebcbb36d74",
        "child_blob": "5a72e2f171b8195a063ef7c9d95ec705510a04c6",
        "review": "remove_in_edge_from: param _exclude_indices:&[i32] -> &[i32] (4d1bcf29)",
    },
    {
        "base_id": "RG-F-a7c613aedf13259c0b0f",
        "from_id": "RG-F-a7c613aedf13259c0b0f",
        "to_id": "RG-F-b1b28afdc0d96c99bac2",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "7078a20f3353a3787098f5aeea97fac3772ed65b",
        "child_blob": "a789d82eaa3831e15a17e4ab9e08716e51e0a8c0",
        "review": "new: gain param [propagate_indirect: bool] (4d1bcf29)",
    },
    {
        "base_id": "RG-F-abb3bf756fd20450f68c",
        "from_id": "RG-F-abb3bf756fd20450f68c",
        "to_id": "RG-F-ca618a5a3392bc3c59c3",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "1b243873b6dec9e5d097851afa5145dd47423de6",
        "child_blob": "2077fc815895a435d64db91af6ab62c8104b248c",
        "review": "remove_unreachable_blocks: gain param [issuewarning: bool; checkexistence: bool] (4d1bcf29)",
    },
    {
        "base_id": "RG-F-cf52e890ee8a36a0f5d2",
        "from_id": "RG-F-cf52e890ee8a36a0f5d2",
        "to_id": "RG-F-695928e52bc3d1243201",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "1b243873b6dec9e5d097851afa5145dd47423de6",
        "child_blob": "2077fc815895a435d64db91af6ab62c8104b248c",
        "review": "stage_jump_table: gain param [flow_state: &crate::flow::TruncatedFlowState]; returns -> crate::jumptable::RecoveryMode -> -> crate::error::Result<crate::jumptable::RecoveryMode> (4d1bcf29)",
    },
    {
        "base_id": "RG-F-e1ee4372589486b36d70",
        "from_id": "RG-F-e1ee4372589486b36d70",
        "to_id": "RG-F-211fba91cd3ce658fac7",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "23cca3811e8d92f034f150dde3216b255206dc96",
        "child_blob": "138bd3d6ed7356e95a0936ff1f2c187d933e9975",
        "review": "recover_jump_tables: param new_tables:&mut Vec<Option<crate -> &mut Vec<Option<Arc<RwLock<crate; returns  -> -> crate::error::Result<()> (4d1bcf29)",
    },
    {
        "base_id": "RG-F-3175e312a1638de63b65",
        "from_id": "RG-F-f10f42d013ccec324dcb",
        "to_id": "RG-F-cc2efb8ee4aead475a92",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "7078a20f3353a3787098f5aeea97fac3772ed65b",
        "child_blob": "a789d82eaa3831e15a17e4ab9e08716e51e0a8c0",
        "review": "propagate_type: param ptr_size:usize -> usize (4d1bcf29)",
    },
    {
        "base_id": "RG-F-0b65260ce004a84337c9",
        "from_id": "RG-F-0b65260ce004a84337c9",
        "to_id": "RG-F-98082c2ff9434b0485d1",
        "commit": "4d5e89fd7023ca3539f75d062b0f2c5614dd20fb",
        "from_path": "src/varnode.rs",
        "to_path": "src/varnode.rs",
        "parent_blob": "613b9a9e794903c5680947f8269788ad2a2f4dac",
        "child_blob": "0d0b051638992e86071e186ef19f499b15d78cf8",
        "review": "transition_def: returns -> Arc<RwLock<Varnode>> -> -> Option<Arc<RwLock<Varnode>>> (4d5e89fd)",
    },
    {
        "base_id": "RG-F-b3157b943066d8e74d4f",
        "from_id": "RG-F-b3157b943066d8e74d4f",
        "to_id": "RG-F-131206e2dc76ecaa0ea8",
        "commit": "8474ec13393f4f15e6a0095c7ee5d166d5e7b452",
        "from_path": "src/varmap.rs",
        "to_path": "src/varmap.rs",
        "parent_blob": "03b547186bc9498c0bf1c2f39f89ceb892b292e6",
        "child_blob": "3659b164797c3d6cb819214cca650be0eae79efa",
        "review": "get_register_name: param _space:crate -> crate (8474ec13)",
    },
    {
        "base_id": "RG-F-f9711768905eb5bf056c",
        "from_id": "RG-F-f9711768905eb5bf056c",
        "to_id": "RG-F-f873313f735f02cf3937",
        "commit": "8474ec13393f4f15e6a0095c7ee5d166d5e7b452",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "d2bcd5b8ba6b2d9ea010b10b637528b98d49103f",
        "child_blob": "9d3462025e11e47da872d6bb7fa05e75181074dc",
        "review": "spacebase_constant: gain param [entry: &crate::database::QueryContainerHit; spaceid: crate::space::AddressSpace] (8474ec13)",
    },
    {
        "base_id": "RG-F-abf77d064f1ec656081b",
        "from_id": "RG-F-426390a6112c3dbc6c2b",
        "to_id": "RG-F-abf77d064f1ec656081b",
        "commit": "8b387a8d288153a8fccd47673177f7ab9d2a220b",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "8bf645e06a62cffeda585f4d853cf5895ce4fc05",
        "child_blob": "13fa2528105649591841c0b0ba283929cb63a111",
        "review": "try_output_stack_guard: drop param [locked_output_storage: Option<(Address, i32)>] (8b387a8d)",
    },
    {
        "base_id": "RG-F-7d3ec36cb92d748b7de3",
        "from_id": "RG-F-7d3ec36cb92d748b7de3",
        "to_id": "RG-F-13f03568eb3480914790",
        "commit": "8b387a8d288153a8fccd47673177f7ab9d2a220b",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "60ff6efbb9f766bb1677513cbd111545708b444c",
        "child_blob": "fd2a0b2e6d4fe570895ad5df84056978864d7f37",
        "review": "set_output_parameter: gain param [space: AddressSpace] (8b387a8d)",
    },
    {
        "base_id": "RG-F-8dd367f8f6d2e6b25a9f",
        "from_id": "RG-F-8dd367f8f6d2e6b25a9f",
        "to_id": "RG-F-4179788f33f6e4b9f744",
        "commit": "8d9aaf66cf3dffbace3de5b7843835d1a778c734",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "c17f052efa3d89a485c275022967d0d58c5b07a1",
        "child_blob": "60ff6efbb9f766bb1677513cbd111545708b444c",
        "review": "unjustified_container: gain param [space: AddressSpace] (8d9aaf66)",
    },
    {
        "base_id": "RG-F-22aafcc017427cf69c66",
        "from_id": "RG-F-22aafcc017427cf69c66",
        "to_id": "RG-F-fd6c2f138f07d6a434c2",
        "commit": "90d0ec88107a7ceb8876a8c1a78a63cf5d28adb5",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "9d3462025e11e47da872d6bb7fa05e75181074dc",
        "child_blob": "f6936829030cca5446aadff17186116dd4416b5a",
        "review": "map_globals: returns  -> -> Result<(), crate::error::Error> (90d0ec88)",
    },
    {
        "base_id": "RG-F-e2f8fd9656b544eb364c",
        "from_id": "RG-F-e2f8fd9656b544eb364c",
        "to_id": "RG-F-bee721d4d0c8d4474c66",
        "commit": "90d0ec88107a7ceb8876a8c1a78a63cf5d28adb5",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "b7167aba78eee138e9f0068bbafb95f7a025a801",
        "child_blob": "7078a20f3353a3787098f5aeea97fac3772ed65b",
        "review": "test_action_mapglobals_marks_persistent_ram_varnodes: rename: test now asserts Symbol creation instead of flag-only marking (90d0ec88)",
    },
    {
        "base_id": "RG-F-0f440fb28a621f11a2e5",
        "from_id": "RG-F-0f440fb28a621f11a2e5",
        "to_id": "RG-F-506fcb9f9b16958229e0",
        "commit": "980f08317308b104fb02cc0094d2845555f98b3d",
        "from_path": "src/prettyprint.rs",
        "to_path": "src/prettyprint.rs",
        "parent_blob": "835cc04e8334d8eea5c9418bcdc2cf9085b49714",
        "child_blob": "9d0eb152509f2bf05c2366a3afe930354e70af5f",
        "review": "close_paren: gain param [_paren: &str; _id: i32] (980f0831)",
    },
    {
        "base_id": "RG-F-350bfd7ce36aafc87bc5",
        "from_id": "RG-F-350bfd7ce36aafc87bc5",
        "to_id": "RG-F-df24ec62e96f58098106",
        "commit": "980f08317308b104fb02cc0094d2845555f98b3d",
        "from_path": "src/prettyprint.rs",
        "to_path": "src/prettyprint.rs",
        "parent_blob": "835cc04e8334d8eea5c9418bcdc2cf9085b49714",
        "child_blob": "9d0eb152509f2bf05c2366a3afe930354e70af5f",
        "review": "open_paren: gain param [_paren: &str]; returns  -> -> i32 (980f0831)",
    },
    {
        "base_id": "RG-F-4cebbe80d33d76389015",
        "from_id": "RG-F-4cebbe80d33d76389015",
        "to_id": "RG-F-b8398d937fc990bf2792",
        "commit": "980f08317308b104fb02cc0094d2845555f98b3d",
        "from_path": "src/prettyprint.rs",
        "to_path": "src/prettyprint.rs",
        "parent_blob": "835cc04e8334d8eea5c9418bcdc2cf9085b49714",
        "child_blob": "9d0eb152509f2bf05c2366a3afe930354e70af5f",
        "review": "close_paren: gain param [_paren: &str; _id: i32] (980f0831)",
    },
    {
        "base_id": "RG-F-6a422bdc9f26aad48fad",
        "from_id": "RG-F-6a422bdc9f26aad48fad",
        "to_id": "RG-F-d548b0dad163f4e73bb7",
        "commit": "980f08317308b104fb02cc0094d2845555f98b3d",
        "from_path": "src/prettyprint.rs",
        "to_path": "src/prettyprint.rs",
        "parent_blob": "835cc04e8334d8eea5c9418bcdc2cf9085b49714",
        "child_blob": "9d0eb152509f2bf05c2366a3afe930354e70af5f",
        "review": "close_paren: gain param [paren: &str; _id: i32] (980f0831)",
    },
    {
        "base_id": "RG-F-7bb1826a9a24ff75f90d",
        "from_id": "RG-F-7bb1826a9a24ff75f90d",
        "to_id": "RG-F-135975b0c3b697afb894",
        "commit": "980f08317308b104fb02cc0094d2845555f98b3d",
        "from_path": "src/prettyprint.rs",
        "to_path": "src/prettyprint.rs",
        "parent_blob": "835cc04e8334d8eea5c9418bcdc2cf9085b49714",
        "child_blob": "9d0eb152509f2bf05c2366a3afe930354e70af5f",
        "review": "open_paren: gain param [_paren: &str]; returns  -> -> i32 (980f0831)",
    },
    {
        "base_id": "RG-F-b45a4aaf0ba46f015ebf",
        "from_id": "RG-F-b45a4aaf0ba46f015ebf",
        "to_id": "RG-F-4a2d7b2f308abdd4878d",
        "commit": "980f08317308b104fb02cc0094d2845555f98b3d",
        "from_path": "src/prettyprint.rs",
        "to_path": "src/prettyprint.rs",
        "parent_blob": "835cc04e8334d8eea5c9418bcdc2cf9085b49714",
        "child_blob": "9d0eb152509f2bf05c2366a3afe930354e70af5f",
        "review": "close_paren: gain param [paren: &str; _id: i32] (980f0831)",
    },
    {
        "base_id": "RG-F-c0d432026d80a6803402",
        "from_id": "RG-F-c0d432026d80a6803402",
        "to_id": "RG-F-f3ad82fa5257af315995",
        "commit": "980f08317308b104fb02cc0094d2845555f98b3d",
        "from_path": "src/prettyprint.rs",
        "to_path": "src/prettyprint.rs",
        "parent_blob": "835cc04e8334d8eea5c9418bcdc2cf9085b49714",
        "child_blob": "9d0eb152509f2bf05c2366a3afe930354e70af5f",
        "review": "open_paren: gain param [paren: &str]; returns  -> -> i32 (980f0831)",
    },
    {
        "base_id": "RG-F-d0c6ed811bdd75fca718",
        "from_id": "RG-F-d0c6ed811bdd75fca718",
        "to_id": "RG-F-6cc79925c1152ad3d51e",
        "commit": "980f08317308b104fb02cc0094d2845555f98b3d",
        "from_path": "src/printlanguage.rs",
        "to_path": "src/printlanguage.rs",
        "parent_blob": "d6fdc2cf7ae57faf540fed33987a0ab0ea080d9d",
        "child_blob": "a0fc455cd11002cd71cd2de4845830fe604fbe65",
        "review": "emit_spaces: param _bump:i32 -> i32 (980f0831)",
    },
    {
        "base_id": "RG-F-e03451a738bd548e1f31",
        "from_id": "RG-F-e03451a738bd548e1f31",
        "to_id": "RG-F-d6fe7b4d2a2591f3f51c",
        "commit": "980f08317308b104fb02cc0094d2845555f98b3d",
        "from_path": "src/prettyprint.rs",
        "to_path": "src/prettyprint.rs",
        "parent_blob": "835cc04e8334d8eea5c9418bcdc2cf9085b49714",
        "child_blob": "9d0eb152509f2bf05c2366a3afe930354e70af5f",
        "review": "open_paren: gain param [paren: &str]; returns  -> -> i32 (980f0831)",
    },
    {
        "base_id": "RG-F-5c67bfa2b4dafad127e9",
        "from_id": "RG-F-5c67bfa2b4dafad127e9",
        "to_id": "RG-F-885ac55c9454c2379e9b",
        "commit": "a5362afcfcccc25d87e4853552440d4fad619d1b",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "8fd771c35277d4ff21739b78b3a3859cfc65ad2b",
        "child_blob": "d57fce1e6051f9980132f919976b4a03ab107192",
        "review": "emit_block_structured: param block_arc:&std -> &std (a5362afc)",
    },
    {
        "base_id": "RG-F-cbd102e6173cd8cf0653",
        "from_id": "RG-F-cbd102e6173cd8cf0653",
        "to_id": "RG-F-ac045b62b01e997d6bab",
        "commit": "a5362afcfcccc25d87e4853552440d4fad619d1b",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "8fd771c35277d4ff21739b78b3a3859cfc65ad2b",
        "child_blob": "d57fce1e6051f9980132f919976b4a03ab107192",
        "review": "is_block_body_empty: param block_arc:&std -> &std (a5362afc)",
    },
    {
        "base_id": "RG-F-02b973adc674e2dafcca",
        "from_id": "RG-F-02b973adc674e2dafcca",
        "to_id": "RG-F-818e9e9dd2f555e6186c",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "reset_for_function: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-02e4be08c92e34abfe47",
        "from_id": "RG-F-02e4be08c92e34abfe47",
        "to_id": "RG-F-22ed1eb12bc5abac17fe",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "set_warning: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-0c9b722a5e2a1f5950bb",
        "from_id": "RG-F-0c9b722a5e2a1f5950bb",
        "to_id": "RG-F-1e3090fe8bc992c441dc",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "set_break_point: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-104e7177e37c491be519",
        "from_id": "RG-F-104e7177e37c491be519",
        "to_id": "RG-F-4fcc20c778fd1c00a6e5",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "mutate_rule_target: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-1e379133c5e93eb237e8",
        "from_id": "RG-F-1e379133c5e93eb237e8",
        "to_id": "RG-F-3cbd3b212adf5233023c",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "add_action_factory_in_group: returns where F: Fn() -> Box<dyn Action> + 'static, -> where F: Fn() -> Box<dyn Action> + Send + Sync + 'static, (b5a554d9)",
    },
    {
        "base_id": "RG-F-22c46fc05bddb2d4345b",
        "from_id": "RG-F-22c46fc05bddb2d4345b",
        "to_id": "RG-F-766b5e4ed8fc866214d8",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "disable_rule: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-2837daddc938af793d3c",
        "from_id": "RG-F-2837daddc938af793d3c",
        "to_id": "RG-F-8015705770472a5fdead",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_opcodes: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-2de92d72d9fdbccc7507",
        "from_id": "RG-F-2de92d72d9fdbccc7507",
        "to_id": "RG-F-630ddcebbfe93b0e818c",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "apply_with_state: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-2e96dea7b92ff0ef2a96",
        "from_id": "RG-F-2e96dea7b92ff0ef2a96",
        "to_id": "RG-F-4275c5418379b85fb462",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_rule_flags: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-3f54231b0de2609dc1e5",
        "from_id": "RG-F-3f54231b0de2609dc1e5",
        "to_id": "RG-F-3f316f0a983f0169c0f8",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_flags: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-418f3036e9876a352e13",
        "from_id": "RG-F-418f3036e9876a352e13",
        "to_id": "RG-F-e2bffedfda38a0041452",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "as_action_group: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-41f64260f48f0ecc9ce1",
        "from_id": "RG-F-41f64260f48f0ecc9ce1",
        "to_id": "RG-F-0ae09e97f158088ac2d3",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "mutate_action_target: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-4269e256e1890ee9c4fd",
        "from_id": "RG-F-4269e256e1890ee9c4fd",
        "to_id": "RG-F-d529f1aba80316f7645c",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "sub_action_match_count: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-46555960b50ff8a7af36",
        "from_id": "RG-F-46555960b50ff8a7af36",
        "to_id": "RG-F-677424a69f8543c266ce",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_num_tests: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-484ed51a1834115a3a27",
        "from_id": "RG-F-484ed51a1834115a3a27",
        "to_id": "RG-F-c5d4b0a7203f6792e696",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "add_rule_factory_in_group: returns where F: Fn() -> Box<dyn Rule> + 'static, -> where F: Fn() -> Box<dyn Rule> + Send + Sync + 'static, (b5a554d9)",
    },
    {
        "base_id": "RG-F-4e9f597e3cbe737fd971",
        "from_id": "RG-F-4e9f597e3cbe737fd971",
        "to_id": "RG-F-7145804dcf3c378fbd8d",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_flags: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-503a03cb217c238099fb",
        "from_id": "RG-F-503a03cb217c238099fb",
        "to_id": "RG-F-a7d1311516103ceec64f",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "as_action_pool_mut: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-599925663bf4d9151f1b",
        "from_id": "RG-F-599925663bf4d9151f1b",
        "to_id": "RG-F-c40817108c16ed8cd523",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "clone_for_groups: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-677d167932e38cfd8059",
        "from_id": "RG-F-677d167932e38cfd8059",
        "to_id": "RG-F-6b77b0a1166c681a2da7",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "add_action_factory_in_group: returns where F: Fn() -> Box<dyn Action> + 'static, -> where F: Fn() -> Box<dyn Action> + Send + Sync + 'static, (b5a554d9)",
    },
    {
        "base_id": "RG-F-6c712f998590fc4f4ea4",
        "from_id": "RG-F-6c712f998590fc4f4ea4",
        "to_id": "RG-F-ba27d12fe911a3f2c401",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "apply_op: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-6faca00e16168f0d41ef",
        "from_id": "RG-F-6faca00e16168f0d41ef",
        "to_id": "RG-F-e9a648e8c1f60e0e96fa",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "clear_break_points: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-782b5bf849af80f65d5c",
        "from_id": "RG-F-782b5bf849af80f65d5c",
        "to_id": "RG-F-5923943cda2aaa09d13d",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_name: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-7c5932644e877daca86f",
        "from_id": "RG-F-7c5932644e877daca86f",
        "to_id": "RG-F-687e0eee77e05580bac1",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "take_count_delta: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-842ae1fa8dfa0b9daf76",
        "from_id": "RG-F-842ae1fa8dfa0b9daf76",
        "to_id": "RG-F-fc454bde9c77551f1734",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_name: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-8d7818eecf4c25ea2fdc",
        "from_id": "RG-F-8d7818eecf4c25ea2fdc",
        "to_id": "RG-F-e2019417ba9532fd82ab",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "reset_for_function: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-959f407b5d68573d1229",
        "from_id": "RG-F-959f407b5d68573d1229",
        "to_id": "RG-F-ad0f5edfae77eb1ce2c7",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "reset: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-a10d860ce8bc8dd86327",
        "from_id": "RG-F-a10d860ce8bc8dd86327",
        "to_id": "RG-F-23956b20a1c593a174b0",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "reset_stats: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-b6563b02f21bb001353d",
        "from_id": "RG-F-b6563b02f21bb001353d",
        "to_id": "RG-F-5702dd3779ca70860cbb",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "apply: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-c677af856e21301a1be7",
        "from_id": "RG-F-c677af856e21301a1be7",
        "to_id": "RG-F-944b96880e55bb88cc25",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "prepare_apply: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-d2a6efd33943f99876b9",
        "from_id": "RG-F-d2a6efd33943f99876b9",
        "to_id": "RG-F-372d591b6a8a3aca4941",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "clone_for_groups: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-d421f5a0561e50936f18",
        "from_id": "RG-F-d421f5a0561e50936f18",
        "to_id": "RG-F-144b2303dbaaaa3c0906",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "as_action_pool: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-df138e1608414f13f855",
        "from_id": "RG-F-df138e1608414f13f855",
        "to_id": "RG-F-97e2e72a7bad8ffb35cc",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "reset: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-e6d44fe6157734ea6fa8",
        "from_id": "RG-F-e6d44fe6157734ea6fa8",
        "to_id": "RG-F-66a413c393915c485061",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_num_apply: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-e7700e3314cd8bda7097",
        "from_id": "RG-F-e7700e3314cd8bda7097",
        "to_id": "RG-F-7c1d3d4135d705d2ffcb",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "as_action_group_mut: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-ecb07ecfbc33e6ed366d",
        "from_id": "RG-F-ecb07ecfbc33e6ed366d",
        "to_id": "RG-F-c6f2b9c34e68bbcee2ed",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "perform: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-f0c872a033d6ed8d2afc",
        "from_id": "RG-F-f0c872a033d6ed8d2afc",
        "to_id": "RG-F-46888848014d136d6b50",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_group: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-f83534827af595642dff",
        "from_id": "RG-F-f83534827af595642dff",
        "to_id": "RG-F-62677f02a16f1130b552",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "reset_stats: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-fd82c9d5598cf4e2837b",
        "from_id": "RG-F-fd82c9d5598cf4e2837b",
        "to_id": "RG-F-4d35f2595074be762e86",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_breakpoint: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-fefdb48c92ee9155d8c7",
        "from_id": "RG-F-fefdb48c92ee9155d8c7",
        "to_id": "RG-F-aee8d565c0bd52e44f5c",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "sub_rule_match_count: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-ff9e56b34d4facda44b5",
        "from_id": "RG-F-ff9e56b34d4facda44b5",
        "to_id": "RG-F-ddbc2a4da7caf5c794ea",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "enable_rule: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-657993bd9ae7c40f453c",
        "from_id": "RG-F-657993bd9ae7c40f453c",
        "to_id": "RG-F-bc367e56a6c33dd53e16",
        "commit": "cac8f60aa1043e87266052478e44eafc9c9e01fd",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "adca5bb67309ddb2bea742395b05ec87c4e97426",
        "child_blob": "8552e471deaf118387c53573cf45467b327b6e10",
        "review": "base_explicit: drop param [vn: &crate::varnode::Varnode]; gain param [vn_arc: &std::sync::Arc<std::sync::RwLock<crate::varnode::Va] (cac8f60a)",
    },
    {
        "base_id": "RG-F-3dc7c42e2821d00cea8a",
        "from_id": "RG-F-3dc7c42e2821d00cea8a",
        "to_id": "RG-F-a02dabc4695772d39068",
        "commit": "d1d86c5ce1af19ec3f447e0f4ae4b2de3741d783",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "fdcf0b595add596e3fe214c0a51ee918cc5ee6ab",
        "child_blob": "9baff6df1b8904848fc7313fed7e5cc9895faa00",
        "review": "push_constant: param _vn:&Varnode -> &Varnode (d1d86c5c)",
    },
    {
        "base_id": "RG-F-89e016fe2736366562e6",
        "from_id": "RG-F-89e016fe2736366562e6",
        "to_id": "RG-F-32e49f1cfa2f76dd9b1a",
        "commit": "dc6f0bfa57ee8d4b20d4edbab9d486b603253cc6",
        "from_path": "src/varmap.rs",
        "to_path": "src/varmap.rs",
        "parent_blob": "efef9d895948d8fbf821c09b3df3d3acd3a6e199",
        "child_blob": "d8941aedb090417d82b478e0d42d899e3c8d926f",
        "review": "restructure_varnode: param fd:&crate -> &mut crate (dc6f0bfa)",
    },
    {
        "base_id": "RG-F-e168755a3d3ef1e682d7",
        "from_id": "RG-F-e168755a3d3ef1e682d7",
        "to_id": "RG-F-2fb18593bd567569c47b",
        "commit": "dc6f0bfa57ee8d4b20d4edbab9d486b603253cc6",
        "from_path": "src/varmap.rs",
        "to_path": "src/varmap.rs",
        "parent_blob": "efef9d895948d8fbf821c09b3df3d3acd3a6e199",
        "child_blob": "d8941aedb090417d82b478e0d42d899e3c8d926f",
        "review": "gather_open: drop param [checker: &AliasChecker]; gain param [types: &Arc<RwLock<crate::type_system::typefactory::TypeFact] (dc6f0bfa)",
    },
    {
        "base_id": "RG-F-e5c3f2b033d412a9ff3c",
        "from_id": "RG-F-e5c3f2b033d412a9ff3c",
        "to_id": "RG-F-a3c894580ae5233ca84f",
        "commit": "dc6f0bfa57ee8d4b20d4edbab9d486b603253cc6",
        "from_path": "src/varmap.rs",
        "to_path": "src/varmap.rs",
        "parent_blob": "efef9d895948d8fbf821c09b3df3d3acd3a6e199",
        "child_blob": "d8941aedb090417d82b478e0d42d899e3c8d926f",
        "review": "derive_boundaries: drop param [local_boundary: u64]; gain param [localrange: &[(u64, u64)]; paramrange: &[(u64, u64)]; has_model: bool] (dc6f0bfa)",
    },
    {
        "base_id": "RG-F-3dd8a09502c79e668db5",
        "from_id": "RG-F-3dd8a09502c79e668db5",
        "to_id": "RG-F-6366ebc7c4d1ef5e164b",
        "commit": "e4c122dd1a259c4c7f9a260bde1d00937a6007e5",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "1739800d4db19500d93b0bcbd955d2434c00e4f4",
        "child_blob": "c135f9ad53b9d9635769b5449b77af68967a15a1",
        "review": "build_subpiece: returns -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode> -> -> Result<std::sync::Arc<std::sync::RwLock<crate::varnode::V (e4c122dd)",
    },
    {
        "base_id": "RG-F-912fef162cc89fe0bf88",
        "from_id": "RG-F-912fef162cc89fe0bf88",
        "to_id": "RG-F-13e779331bc0e4e025d1",
        "commit": "e65172c82933d7fef46ce68b5342ae121cdb3ae6",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "87e2e62276218b859ff357ad110d936ca8c45e63",
        "child_blob": "48d5fa808e3977b275de74c9029b3d7f5a32774e",
        "review": "build_input_from_trials: gain param [fd: &mut crate::funcdata::Funcdata; call_op: &crate::op::PcodeOpRef]; returns -> Vec<(Address, i32)> ->  (e65172c8)",
    },
    {
        "base_id": "RG-F-9e895a3a0250ae83b691",
        "from_id": "RG-F-9e895a3a0250ae83b691",
        "to_id": "RG-F-36f312ac16b8aeb056bf",
        "commit": "e65172c82933d7fef46ce68b5342ae121cdb3ae6",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "a789d82eaa3831e15a17e4ab9e08716e51e0a8c0",
        "child_blob": "60b5e94997c0074ae62f61d5e3dc4758c2bbf1e3",
        "review": "func_link_input: drop param [callee_name: Option<&str>]; gain param [fc_idx: usize] (e65172c8)",
    },
    {
        "base_id": "RG-F-c58bd5e5d630cc315643",
        "from_id": "RG-F-c58bd5e5d630cc315643",
        "to_id": "RG-F-cc05e9e6d69e72d76759",
        "commit": "e65172c82933d7fef46ce68b5342ae121cdb3ae6",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "87e2e62276218b859ff357ad110d936ca8c45e63",
        "child_blob": "48d5fa808e3977b275de74c9029b3d7f5a32774e",
        "review": "new_for_op: drop param [prototype: FuncProto]; gain param [_caller_funcp: FuncProto] (e65172c8)",
    },
    {
        "base_id": "RG-F-636713cd718416eda469",
        "from_id": "RG-F-636713cd718416eda469",
        "to_id": "RG-F-3f1bd88d4b4e89d8f38f",
        "commit": "ed8279383546ab76f57d50c08204cbf2a1030161",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "28b7501b50858acb11ecca078f174bb7c691431c",
        "child_blob": "ebceddc7cfd31423381303edf3fe8f3a4fbe7b2a",
        "review": "bump_deadcode_delay: gain param [fd: &mut Funcdata] (ed827938)",
    },
    {
        "base_id": "RG-F-e5118215bbe2945b9480",
        "from_id": "RG-F-e5118215bbe2945b9480",
        "to_id": "RG-F-67c7a43469ad14fb90af",
        "commit": "ee7f8f02db93740962d69fae35606fb14e398d16",
        "from_path": "src/database.rs",
        "to_path": "src/database.rs",
        "parent_blob": "93e388f0ebbbfdb2f203f7c0d7f3adca8df0f7e0",
        "child_blob": "c37f65cb7c79a63f780c462ed30484dc2370c722",
        "review": "find_container: gain param [usepoint: Address]; returns -> Option<&SymbolEntry> -> -> Option<usize> (ee7f8f02)",
    },
    {
        "base_id": "RG-F-74239bf8f5f8e8e31fc7",
        "from_id": "RG-F-74239bf8f5f8e8e31fc7",
        "to_id": "RG-F-079b0a68815cef04e6b9",
        "commit": "f35f29d7ae2d4f241283f4553230426ecf3c1f66",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "48d5fa808e3977b275de74c9029b3d7f5a32774e",
        "child_blob": "75dcc22fbb4f1b5cf6d82da28db6bf9ca76d4857",
        "review": "build_output_from_trials: param trial_vn:&[std -> &[Option<std (f35f29d7)",
    },
    {
        "base_id": "RG-F-614df5b0ab663eee9561",
        "from_id": "RG-F-614df5b0ab663eee9561",
        "to_id": "RG-F-c6622ea88f98cd771ceb",
        "commit": "f44f641545188578706e0b5912317cee3402d794",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "9d59388d6012e7a01d71ade00fa7b0f2d6e7d8c9",
        "child_blob": "581421ce4c37aea1173dfda9cbe198d88fcb359a",
        "review": "get_input_cast: param _op:&PcodeOp -> &PcodeOp; param _slot:usize -> usize (f44f6415)",
    },
    {
        "base_id": "RG-F-8afa232b7531c9dbdfd3",
        "from_id": "RG-F-8afa232b7531c9dbdfd3",
        "to_id": "RG-F-ea42b78a0f4dad50a82f",
        "commit": "f9245e16e318581b3c1e131c4e4abd8482e9742b",
        "from_path": "src/merge.rs",
        "to_path": "src/merge.rs",
        "parent_blob": "f2f54c1daaef757603b0545acb686ed58a309230",
        "child_blob": "48696998ddeea6c8fc6fb09a237cc606108b6bb5",
        "review": "group_partials: param _fd:&mut Funcdata -> &mut Funcdata (f9245e16)",
    },

    # w-registry2 continuation of ORACLE-REGISTRY-IMPACT-CONTINUITY-0001: the
    # remaining seven window removals are rustfmt multi-line signature splits
    # whose only difference is the trailing parameter separator.  The automatic
    # alias rule cannot fire because none of these functions carries a
    # strict-regex-matching non-empty annotation above the fn line (lineless
    # `// Ghidra: block.hh Fn` markers or plain doc comments), so each alias is
    # pinned here on git-diff evidence that the body is unchanged formatting.
    {
        "base_id": "RG-F-ad4cafa74f583abfbe4f",
        "from_id": "RG-F-ad4cafa74f583abfbe4f",
        "to_id": "RG-F-425cd5352ccd5db995c9",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "5294bda8f0e39fa14facd6b59d066c379a416b35",
        "child_blob": "5f43cf8954f5a62b8573be019c88a3a608d9ccd2",
        "review": "print_raw_implied_goto_trait: rustfmt split adds the trailing parameter separator only; marker line-numberless so automatic evidence is unavailable (2d78b5af)",
    },
    {
        "base_id": "RG-F-098edc738e5a43908809",
        "from_id": "RG-F-098edc738e5a43908809",
        "to_id": "RG-F-b6bfd7d98562fbfd99d7",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "child_needs_parens: rustfmt split adds the trailing parameter separator only; doc-comment header so automatic evidence is unavailable (3fb97c11)",
    },
    {
        "base_id": "RG-F-17ef2d9d23d6d220f407",
        "from_id": "RG-F-17ef2d9d23d6d220f407",
        "to_id": "RG-F-343f5a5b111fa2a66a95",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "var_prefix: rustfmt split adds the trailing parameter separator only; doc-comment header so automatic evidence is unavailable (3fb97c11)",
    },
    {
        "base_id": "RG-F-48cac975d49aaa45fbc4",
        "from_id": "RG-F-48cac975d49aaa45fbc4",
        "to_id": "RG-F-8fdef7ef5f62224b9392",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "array_sub_entry: rustfmt split adds the trailing parameter separator only; Ghidra marker has no line number so automatic evidence is unavailable (3fb97c11)",
    },
    {
        "base_id": "RG-F-49047a901b0905807ad4",
        "from_id": "RG-F-49047a901b0905807ad4",
        "to_id": "RG-F-e24c59a91e3095bd3774",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "find_partial_field: rustfmt split adds the trailing parameter separator only; Ghidra marker has no line number so automatic evidence is unavailable (3fb97c11)",
    },
    {
        "base_id": "RG-F-d4793f1f2dc45770289c",
        "from_id": "RG-F-d4793f1f2dc45770289c",
        "to_id": "RG-F-5351aec1c6466b1b9859",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "03efffda74f9c4aaa212407845eb2d963111474b",
        "child_blob": "659bbea603929d97c83ef8ecdf77c42364e293cd",
        "review": "make_input_vn: rustfmt split adds the trailing parameter separator only (body expression reformat aside); doc-comment header so automatic evidence is unavailable (3fb97c11)",
    },
    {
        "base_id": "RG-F-daa603fd8f42abcfe2fb",
        "from_id": "RG-F-daa603fd8f42abcfe2fb",
        "to_id": "RG-F-b28ed8113612c1d70101",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "18c72f2088c9246030dc852601ac67a335b4726e",
        "child_blob": "d6cbd815b82967b83e6ae6752007f351a20114c2",
        "review": "insert_end: rustfmt split adds the trailing parameter separator only; no annotation header so automatic evidence is unavailable (3fb97c11)",
    },

    # The mapglobals merge resolved both reciprocal half-delete ports to
    # master's non-mut signatures; the first-parent mut variants die and the
    # second-parent variants (same FlowBlock port, mut binding moved into the
    # body) survive into the checkpoint tree, so these are continuity
    # transitions, not retirements.
    {
        "base_id": "RG-F-7622630fcd5425152c42",
        "from_id": "RG-F-2e7d8eae51d63d1dcc39",
        "to_id": "RG-F-87ecf60944cd017f0272",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "bd4a0a1de7286167b07d6a3d9e1fa9ebcbb36d74",
        "child_blob": "5a72e2f171b8195a063ef7c9d95ec705510a04c6",
        "review": "half_delete_in_edge: merge resolved to master's non-mut signature with the mut binding moved into the body; same FlowBlock::halfDeleteInEdge port block.cc:100 (4d1bcf29)",
    },
    {
        "base_id": "RG-F-c76e93f7b514cc307344",
        "from_id": "RG-F-68db795ba78535d5e6e6",
        "to_id": "RG-F-30f67e8116795adbb6b2",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "bd4a0a1de7286167b07d6a3d9e1fa9ebcbb36d74",
        "child_blob": "5a72e2f171b8195a063ef7c9d95ec705510a04c6",
        "review": "half_delete_out_edge: merge resolved to master's non-mut signature with the mut binding moved into the body; same FlowBlock::halfDeleteOutEdge port block.cc:115 (4d1bcf29)",
    },
)
CONTINUITY_REVIEWED_TOMBSTONES: tuple[dict[str, str], ...] = (
    {
        "base_id": "RG-F-5ec71c480ba4438dca3a",
        "from_id": "RG-F-5ec71c480ba4438dca3a",
        "commit": "92daed300bcce3c4d855b311cf9667ba21eb475a",
        "parent_blob": "ae2cf089a3f644385d8a64ce213f7f1b0b88103a",
        "child_blob": "b44b6b2204becc01234d3dab8415899d83c7f777",
        "reason": "removed by access-width gating; no successor (92daed3)",
    },
    {
        "base_id": "RG-F-002a9ec13d8e062540b9",
        "from_id": "RG-F-002a9ec13d8e062540b9",
        "commit": "874e81f7b9877b519c8ab55b57cbac24de0918f0",
        "parent_blob": "4fef0e1b7cbaf0ac1508b64cb5e7e0966748a588",
        "child_blob": "f2e73aa6795f35c93f8bceb6e2290a43c427b357",
        "reason": "superseded by canonical type-tree keys; no successor (874e81f)",
    },
    {
        "base_id": "RG-F-bd9141cd6ae9f5a4ddad",
        "from_id": "RG-F-bd9141cd6ae9f5a4ddad",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "parent_blob": "6607bf4acdc7a2b54a47623d473a999f6996d42e",
        "child_blob": "f4f0308e571b0ca56af88ab627a6eab2aebb6c7a",
        "reason": "replaced by owner-handle call-spec lookup; no successor (cad41c2)",
    },
    {
        "base_id": "RG-F-e43c2d78ba8a0472a781",
        "from_id": "RG-F-e43c2d78ba8a0472a781",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "parent_blob": "b01176babb67aa227a2a00ed1ac402221dac2449",
        "child_blob": "81f6344ef0bdecaba1c994c1b0cdfb9a53b5de1a",
        "reason": "replaced by owner-handle call-spec lookup; no successor (cad41c2)",
    },
    {
        "base_id": "RG-F-93890c76dc270880c224",
        "from_id": "RG-F-93890c76dc270880c224",
        "commit": "f87e4d802652244e1b5792097d53a746d164dc07",
        "parent_blob": "81f6344ef0bdecaba1c994c1b0cdfb9a53b5de1a",
        "child_blob": "97f66c8ac70b5cc2f1795ad4c45647824a5b80a5",
        "reason": "superseded by canonical TypeFactory get_exact_piece; no successor (f87e4d8)",
    },
    {
        "base_id": "RG-F-ded5b6e2aef38fd29e5a",
        "from_id": "RG-F-ded5b6e2aef38fd29e5a",
        "commit": "f87e4d802652244e1b5792097d53a746d164dc07",
        "parent_blob": "f4f0308e571b0ca56af88ab627a6eab2aebb6c7a",
        "child_blob": "de9ecc914f2fc2cc65b246f8462dfbf26b39f33c",
        "reason": "superseded by canonical TypeFactory get_exact_piece; no successor (f87e4d8)",
    },
    {
        "base_id": "RG-F-56411d1c69a8e636a9cc",
        "from_id": "RG-F-56411d1c69a8e636a9cc",
        "commit": "bdc7f341d3a588045832a670f02cf384d3b12e1a",
        "parent_blob": "f7722f4fb73c31cfbf562222f5767e11864f2ab5",
        "child_blob": "0dcdf7eb67c8994d71e8e80951c0dd71644e2a2e",
        "reason": "FuncCallSpecsExt retired with its trait+impl pair; absorbed into FlowInfo queryCall (bdc7f34)",
    },
    {
        "base_id": "RG-F-95a861f4477ffddc9d35",
        "from_id": "RG-F-95a861f4477ffddc9d35",
        "commit": "bdc7f341d3a588045832a670f02cf384d3b12e1a",
        "parent_blob": "f7722f4fb73c31cfbf562222f5767e11864f2ab5",
        "child_blob": "0dcdf7eb67c8994d71e8e80951c0dd71644e2a2e",
        "reason": "FuncCallSpecsExt retired with its trait+impl pair; absorbed into FlowInfo queryCall (bdc7f34)",
    },
    {
        "base_id": "RG-F-8544a0e173d594065ca7",
        "from_id": "RG-F-8544a0e173d594065ca7",
        "commit": "11371d512e9b374ec73d5a7e7181e6ed52eba296",
        "parent_blob": "a5c0c6f9557598bc6a1de70606b74d5d71c7f8ab",
        "child_blob": "33ee849f1de230fd087e1131d1104c3c3522a955",
        "reason": "impl:StringManagerUnicode retired by GhidraStringManager Java contract port; no same-class successor (11371d5)",
    },
    {
        "base_id": "RG-F-9e46078d26f5ecc6cd37",
        "from_id": "RG-F-9e46078d26f5ecc6cd37",
        "commit": "11371d512e9b374ec73d5a7e7181e6ed52eba296",
        "parent_blob": "a5c0c6f9557598bc6a1de70606b74d5d71c7f8ab",
        "child_blob": "33ee849f1de230fd087e1131d1104c3c3522a955",
        "reason": "impl:StringManagerUnicode retired by GhidraStringManager Java contract port; no same-class successor (11371d5)",
    },
    {
        "base_id": "RG-F-b2cb4f664723372b7400",
        "from_id": "RG-F-b2cb4f664723372b7400",
        "commit": "11371d512e9b374ec73d5a7e7181e6ed52eba296",
        "parent_blob": "a5c0c6f9557598bc6a1de70606b74d5d71c7f8ab",
        "child_blob": "33ee849f1de230fd087e1131d1104c3c3522a955",
        "reason": "impl:StringManagerUnicode retired by GhidraStringManager Java contract port; no same-class successor (11371d5)",
    },

    {
        "base_id": "RG-F-bd201b6f89048574b546",
        "from_id": "RG-F-bd201b6f89048574b546",
        "commit": "1644180de42b58cd0155f62c9b3ad82efc820a57",
        "parent_blob": "a94e6f58f60a02e2b5ac52e68ed822ccc7ab3f0d",
        "child_blob": "b8734eb52066baf8a30f8e81846f9df3d3855932",
        "reason": "superseded by the 12.0.4 struct/array/pointer bit semantics; no successor (1644180d)",
    },
    {
        "base_id": "RG-F-23e0cdef45d8a01764a7",
        "from_id": "RG-F-23e0cdef45d8a01764a7",
        "commit": "1644180de42b58cd0155f62c9b3ad82efc820a57",
        "parent_blob": "a94e6f58f60a02e2b5ac52e68ed822ccc7ab3f0d",
        "child_blob": "b8734eb52066baf8a30f8e81846f9df3d3855932",
        "reason": "test retired with get_split_datatype_bit; no successor (1644180d)",
    },
    {
        "base_id": "RG-F-b04bd21a5d624e1fc06f",
        "from_id": "RG-F-b04bd21a5d624e1fc06f",
        "commit": "26d675e7f6131ed17e8de6a689b5b3d85ec21470",
        "parent_blob": "5b0ddb920d904ae2b396c4535713ae28f47d9ac3",
        "child_blob": "cae7b73c4da887e634cd5fde6dff16b0343d1933",
        "reason": "superseded by the exact-piece gate chain (TypeFactory get_exact_piece); no successor (26d675e7)",
    },
    {
        "base_id": "RG-F-98eb48688773519607ba",
        "from_id": "RG-F-98eb48688773519607ba",
        "commit": "26d675e7f6131ed17e8de6a689b5b3d85ec21470",
        "parent_blob": "5b0ddb920d904ae2b396c4535713ae28f47d9ac3",
        "child_blob": "cae7b73c4da887e634cd5fde6dff16b0343d1933",
        "reason": "superseded by the exact-piece gate chain; no successor (26d675e7)",
    },
    {
        "base_id": "RG-F-255edda2318d460e2e4b",
        "from_id": "RG-F-255edda2318d460e2e4b",
        "commit": "26d675e7f6131ed17e8de6a689b5b3d85ec21470",
        "parent_blob": "5b0ddb920d904ae2b396c4535713ae28f47d9ac3",
        "child_blob": "cae7b73c4da887e634cd5fde6dff16b0343d1933",
        "reason": "test replaced by exact-piece gate coverage; no successor (26d675e7)",
    },
    {
        "base_id": "RG-F-88d87eaf0e792af4c255",
        "from_id": "RG-F-88d87eaf0e792af4c255",
        "commit": "4495eb601d22f959bad64a6c085f516431195b42",
        "parent_blob": "80a82de9b2e16872177748299aa8dd325e8ccb64",
        "child_blob": "9d4ffe1a072d45accd3e7eb87e3d9942d43d054c",
        "reason": "reset retired from the Rule surface by the breakpoint-aware pool executor; no successor (4495eb60)",
    },
    {
        "base_id": "RG-F-ef02d5e77634269ac883",
        "from_id": "RG-F-ef02d5e77634269ac883",
        "commit": "4495eb601d22f959bad64a6c085f516431195b42",
        "parent_blob": "e42479af547350de04a1eb368263bd9b8c689c1a",
        "child_blob": "5b0ddb920d904ae2b396c4535713ae28f47d9ac3",
        "reason": "reset retired from the Rule surface by the breakpoint-aware pool executor; no successor (4495eb60)",
    },
    {
        "base_id": "RG-F-069b0702a18335d9be0c",
        "from_id": "RG-F-069b0702a18335d9be0c",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "reason": "EmulateFunction methods retired by the loader/error channel rework; no successor (73b5ef26)",
    },
    {
        "base_id": "RG-F-c261bf862e86c3ae27dd",
        "from_id": "RG-F-c261bf862e86c3ae27dd",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "reason": "EmulateFunction methods retired by the loader/error channel rework; no successor (73b5ef26)",
    },
    {
        "base_id": "RG-F-15a6b977326f7c0a9e15",
        "from_id": "RG-F-15a6b977326f7c0a9e15",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "reason": "EmulateFunction methods retired by the loader/error channel rework; no successor (73b5ef26)",
    },
    {
        "base_id": "RG-F-dda630121a5380c159b1",
        "from_id": "RG-F-dda630121a5380c159b1",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "reason": "EmulateFunction methods retired by the loader/error channel rework; no successor (73b5ef26)",
    },
    {
        "base_id": "RG-F-53ed24ee2a9a1e691b6b",
        "from_id": "RG-F-53ed24ee2a9a1e691b6b",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "reason": "EmulateFunction methods retired by the loader/error channel rework; no successor (73b5ef26)",
    },
    {
        "base_id": "RG-F-080a097af2330629ba3f",
        "from_id": "RG-F-080a097af2330629ba3f",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "reason": "EmulateFunction methods retired by the loader/error channel rework; no successor (73b5ef26)",
    },
    {
        "base_id": "RG-F-e6a5ca59c7df4b468e28",
        "from_id": "RG-F-e6a5ca59c7df4b468e28",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "reason": "EmulateFunction methods retired by the loader/error channel rework; no successor (73b5ef26)",
    },
    {
        "base_id": "RG-F-8e6f7437052ad650c6c7",
        "from_id": "RG-F-8e6f7437052ad650c6c7",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "reason": "TypeOpCopy input locals superseded by the getBase(size, ctor meta) dispatch; no successor (8e5944ca)",
    },
    {
        "base_id": "RG-F-9712364a6d3cf8e6a6a9",
        "from_id": "RG-F-9712364a6d3cf8e6a6a9",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "reason": "TypeOpCopy output locals superseded by the getBase(size, ctor meta) dispatch; no successor (8e5944ca)",
    },
    {
        "base_id": "RG-F-30101d742841018ea6b2",
        "from_id": "RG-F-30101d742841018ea6b2",
        "commit": "b8da22a86f28cb2750fe85e1a7c69391c900a1fc",
        "parent_blob": "0dcdf7eb67c8994d71e8e80951c0dd71644e2a2e",
        "child_blob": "23cca3811e8d92f034f150dde3216b255206dc96",
        "reason": "FuncCallSpecsExt predicates absorbed into queryCall copyFlowEffects; no successor (b8da22a8)",
    },
    {
        "base_id": "RG-F-aeb06d1101df113fd3b2",
        "from_id": "RG-F-aeb06d1101df113fd3b2",
        "commit": "b8da22a86f28cb2750fe85e1a7c69391c900a1fc",
        "parent_blob": "0dcdf7eb67c8994d71e8e80951c0dd71644e2a2e",
        "child_blob": "23cca3811e8d92f034f150dde3216b255206dc96",
        "reason": "FuncCallSpecsExt predicates absorbed into queryCall copyFlowEffects; no successor (b8da22a8)",
    },
    {
        "base_id": "RG-F-8e4485d9f15252be0689",
        "from_id": "RG-F-8e4485d9f15252be0689",
        "commit": "b8da22a86f28cb2750fe85e1a7c69391c900a1fc",
        "parent_blob": "0dcdf7eb67c8994d71e8e80951c0dd71644e2a2e",
        "child_blob": "23cca3811e8d92f034f150dde3216b255206dc96",
        "reason": "FuncCallSpecsExt predicates absorbed into queryCall copyFlowEffects; no successor (b8da22a8)",
    },
    {
        "base_id": "RG-F-deed2231a6bf3a9a609f",
        "from_id": "RG-F-deed2231a6bf3a9a609f",
        "commit": "b8da22a86f28cb2750fe85e1a7c69391c900a1fc",
        "parent_blob": "0dcdf7eb67c8994d71e8e80951c0dd71644e2a2e",
        "child_blob": "23cca3811e8d92f034f150dde3216b255206dc96",
        "reason": "FuncCallSpecsExt predicates absorbed into queryCall copyFlowEffects; no successor (b8da22a8)",
    },
    {
        "base_id": "RG-F-cb2c742a239b918218ca",
        "from_id": "RG-F-cb2c742a239b918218ca",
        "commit": "cddcefd88006dd68ed69284ed31562a08fda3107",
        "parent_blob": "f59e4cdb2e320c7b0ddd3a718f3c0710c42087de",
        "child_blob": "76c7fd80219848d352c7ee156e2cbfa5a90ad221",
        "reason": "goto-cascade internals replaced by the TraceDAG oracle chain; no successor (cddcefd8)",
    },
    {
        "base_id": "RG-F-4a37bb3ab1d3734f0c77",
        "from_id": "RG-F-4a37bb3ab1d3734f0c77",
        "commit": "cddcefd88006dd68ed69284ed31562a08fda3107",
        "parent_blob": "f59e4cdb2e320c7b0ddd3a718f3c0710c42087de",
        "child_blob": "76c7fd80219848d352c7ee156e2cbfa5a90ad221",
        "reason": "goto-cascade internals replaced by the TraceDAG oracle chain; no successor (cddcefd8)",
    },
    {
        "base_id": "RG-F-addd45c134e9c47b4617",
        "from_id": "RG-F-addd45c134e9c47b4617",
        "commit": "cddcefd88006dd68ed69284ed31562a08fda3107",
        "parent_blob": "f59e4cdb2e320c7b0ddd3a718f3c0710c42087de",
        "child_blob": "76c7fd80219848d352c7ee156e2cbfa5a90ad221",
        "reason": "goto-cascade internals replaced by the TraceDAG oracle chain; no successor (cddcefd8)",
    },
    {
        "base_id": "RG-F-2f5c843a5f5bb2d862e9",
        "from_id": "RG-F-2f5c843a5f5bb2d862e9",
        "commit": "cddcefd88006dd68ed69284ed31562a08fda3107",
        "parent_blob": "f59e4cdb2e320c7b0ddd3a718f3c0710c42087de",
        "child_blob": "76c7fd80219848d352c7ee156e2cbfa5a90ad221",
        "reason": "goto-cascade internals replaced by the TraceDAG oracle chain; no successor (cddcefd8)",
    },
    {
        "base_id": "RG-F-9f52bbaae4d239936a07",
        "from_id": "RG-F-9f52bbaae4d239936a07",
        "commit": "e956e963b167ed1d57a7a4daed2a3566f2425999",
        "parent_blob": "5db2d8861d2c0be679645503b11acd3679f2a157",
        "child_blob": "5cde46e8aa9a67d5c19e80566aeead7cbbda72db",
        "reason": "retired by the condexe success-channel rework; no successor (e956e963)",
    },

    # --- extension window 1f3aea4a..3fb97c11 (ORACLE-REGISTRY-IMPACT-CONTINUITY-0001) ---
    {
        "base_id": "RG-F-16c31deda08795ad3093",
        "from_id": "RG-F-16c31deda08795ad3093",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "parent_blob": "a07b84aa844f90a3f2f3656729b449360dbd77df",
        "child_blob": "b03c2682c3c0301b34b14fe273f297b4c067bcc3",
        "reason": "callspec setup retired onto FlowInfo::setup_call_specs (26eee4ad)",
    },
    {
        "base_id": "RG-F-4991980ba6d7be445656",
        "from_id": "RG-F-4991980ba6d7be445656",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "reason": "X86_64GccStorage test helper retired with the storage carrier rework (26eee4ad)",
    },
    {
        "base_id": "RG-F-91b02db0f11bf77a4794",
        "from_id": "RG-F-91b02db0f11bf77a4794",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "parent_blob": "a07b84aa844f90a3f2f3656729b449360dbd77df",
        "child_blob": "b03c2682c3c0301b34b14fe273f297b4c067bcc3",
        "reason": "known-callee return-type table retired; no successor (26eee4ad)",
    },
    {
        "base_id": "RG-F-96f8a3e95e70159bece0",
        "from_id": "RG-F-96f8a3e95e70159bece0",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "reason": "X86_64GccStorage::from_sleigh retired with the storage carrier rework (26eee4ad)",
    },
    {
        "base_id": "RG-F-9b222eeba49a70df3b79",
        "from_id": "RG-F-9b222eeba49a70df3b79",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "reason": "test retired with the model-binding rework; no successor (26eee4ad)",
    },
    {
        "base_id": "RG-F-9f7e83ffb52973d9aec4",
        "from_id": "RG-F-9f7e83ffb52973d9aec4",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "reason": "X86_64GccStorage::assign retired with the storage carrier rework (26eee4ad)",
    },
    {
        "base_id": "RG-F-b8da745f71c85226ca7e",
        "from_id": "RG-F-b8da745f71c85226ca7e",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "reason": "X86_64GccStorage::from_registers retired with the storage carrier rework (26eee4ad)",
    },
    {
        "base_id": "RG-F-b08ab6d33575c1274bd2",
        "from_id": "RG-F-b08ab6d33575c1274bd2",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "parent_blob": "22707482e6a340dfad8f51f8549825816b7426f6",
        "child_blob": "86fc48bd21f36999a488fed88ee221763c9d6eae",
        "reason": "bblocks staleness fingerprint helper retired; no successor (2d78b5af)",
    },
    {
        "base_id": "RG-F-d5b104b5737433f9258f",
        "from_id": "RG-F-d5b104b5737433f9258f",
        "commit": "3b6e3139f3f6e9ba3d8d999b046fe7d30310c224",
        "parent_blob": "73226c089b941c9025aedf39b4d65e6af170403f",
        "child_blob": "f7760d99ae8f2ddaf0690e786d0b7cf964737b0f",
        "reason": "replaced by the ported RootPointer::buildPointers chain; no 1:1 successor (3b6e3139)",
    },
    {
        "base_id": "RG-F-19f611a02beef2ac0b9b",
        "from_id": "RG-F-19f611a02beef2ac0b9b",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "reason": "textual De Morgan helper retired with the structured-negate rework (3fb97c11)",
    },
    {
        "base_id": "RG-F-34ac6f9501dab285e4c2",
        "from_id": "RG-F-34ac6f9501dab285e4c2",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "parent_blob": "03efffda74f9c4aaa212407845eb2d963111474b",
        "child_blob": "659bbea603929d97c83ef8ecdf77c42364e293cd",
        "reason": "blanket memory-output block retired with the strict deadcode delay port (3fb97c11)",
    },
    {
        "base_id": "RG-F-abbb15fe53c1fe59162d",
        "from_id": "RG-F-abbb15fe53c1fe59162d",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "reason": "paren-strip helper retired with the textual De Morgan composition (3fb97c11)",
    },
    {
        "base_id": "RG-F-69a24b4aa7a5774bcbbc",
        "from_id": "RG-F-69a24b4aa7a5774bcbbc",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "parent_blob": "8f1456eae2533968f04d4c5f50c12c2470bce926",
        "child_blob": "754437b93519caef298467a78341bbf0b330d54e",
        "reason": "RPN constant formatting folded into constant_leaf_text/integer_text; no 1:1 successor (4d1bcf29)",
    },
    {
        "base_id": "RG-F-935389e7c53de5c13756",
        "from_id": "RG-F-935389e7c53de5c13756",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "parent_blob": "8f1456eae2533968f04d4c5f50c12c2470bce926",
        "child_blob": "754437b93519caef298467a78341bbf0b330d54e",
        "reason": "folded into PrintC::constant_leaf_text pushConstant dispatch; no 1:1 successor (4d1bcf29)",
    },
    {
        "base_id": "RG-F-ca8e5e48082eb933ed01",
        "from_id": "RG-F-ca8e5e48082eb933ed01",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "parent_blob": "bd4a0a1de7286167b07d6a3d9e1fa9ebcbb36d74",
        "child_blob": "5a72e2f171b8195a063ef7c9d95ec705510a04c6",
        "reason": "ruleBlockGoto no-op stub removed in mapglobals finalize; no successor (4d1bcf29)",
    },
    {
        "base_id": "RG-F-be28b0ba758951601dda",
        "from_id": "RG-F-be28b0ba758951601dda",
        "commit": "8dae10d3c2b02df7424beaba2abf9fdf72bbdb66",
        "parent_blob": "0d976f2593b57a67e2295c82ab0c1576d5c68cb6",
        "child_blob": "9d59388d6012e7a01d71ade00fa7b0f2d6e7d8c9",
        "reason": "TypeOpStore::getInputLocal override removed; base TypeOp dispatch remains (8dae10d3)",
    },
    {
        "base_id": "RG-F-1e84c830545d01637f72",
        "from_id": "RG-F-1e84c830545d01637f72",
        "commit": "a5362afcfcccc25d87e4853552440d4fad619d1b",
        "parent_blob": "8fd771c35277d4ff21739b78b3a3859cfc65ad2b",
        "child_blob": "d57fce1e6051f9980132f919976b4a03ab107192",
        "reason": "DepthDec Drop impl retired with the emit-depth rework; no successor (a5362afc)",
    },
)
CONTINUITY_REVIEWED_EPHEMERAL: tuple[dict[str, str], ...] = (
    {
        "base_id": "RG-F-763fefee4ab8d71f0289",
        "from_id": "RG-F-763fefee4ab8d71f0289",
        "commit": "23ef9c90a66be480f91ded91fa7e1e180faa57ce",
        "parent_blob": "f2e73aa6795f35c93f8bceb6e2290a43c427b357",
        "child_blob": "78d21a337d0ea2de3852bf6edb948d2334225573",
    },

    {
        "base_id": "RG-F-1bb5904495b9e4cb393e",
        "from_id": "RG-F-1bb5904495b9e4cb393e",
        "commit": "b15bd104b26bf4977a5d8e06307de44596073fdc",
        "parent_blob": "cae7b73c4da887e634cd5fde6dff16b0343d1933",
        "child_blob": "73226c089b941c9025aedf39b4d65e6af170403f",
    },
    # --- extension window 1f3aea4a..3fb97c11 (ORACLE-REGISTRY-IMPACT-CONTINUITY-0001) ---
    {
        "base_id": "RG-F-170873abbea5dabfb13a",
        "from_id": "RG-F-170873abbea5dabfb13a",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "parent_blob": "1323dc37c5e45e5990dbf612f11784fb41b42edf",
        "child_blob": "5a6dd28914b4a7251fb9db562b17674e2084e02b",
    },
)


def _reviewed_transition(
    legacy: str,
    source: str,
    target: str,
    commit: str,
    kind: str,
    label: str,
    parent_blob_prefix: str,
    child_blob_prefix: str,
) -> dict[str, str]:
    return {
        "legacy_id": legacy,
        "from_id": source,
        "to_id": target,
        "commit": commit,
        "kind": kind,
        "label": label,
        "parent_blob_prefix": parent_blob_prefix,
        "child_blob_prefix": child_blob_prefix,
    }


# These are evidence-bearing exceptions, not name-based heuristics.  Every
# token, commit, record shape and full blob resolved from the named commit is
# checked before a row is accepted.
REKEY_REVIEWED_TRANSITIONS = (
    _reviewed_transition(
        "RG-F-a1792e61b73118f8c5eb", "RG-F-a0b9aaf1d4e29189ddf4",
        "RG-F-afd2f193d11f7fded2d4", "eb8ad57b5f472c182f25dd245460abdc3c9f33e6",
        "same_name", "ActionDatabase::get_action_mut", "e3032afa", "e6aa9b91",
    ),
    _reviewed_transition(
        "RG-F-c642b079af3e97d8a10d", "RG-F-4a5cecef4b93ac919596",
        "RG-F-360279f7e03f1c7fe438", "126b56fdefde1e0820ef4126968473d679e1ddd8",
        "same_name", "FuncCallSpecs::characterize_as_output", "bd37797c", "6a4f2a05",
    ),
    _reviewed_transition(
        "RG-F-2efd70f01473014375c2", "RG-F-7a2548c2349bb5f75bc3",
        "RG-F-3e61b4c85c446db8dc90", "126b56fdefde1e0820ef4126968473d679e1ddd8",
        "same_name", "FuncCallSpecs::characterize_as_input_param", "bd37797c", "6a4f2a05",
    ),
    _reviewed_transition(
        "RG-F-52518230ca5f60ac71e5", "RG-F-da09d8757211d48d7bf6",
        "RG-F-6fb4acf7c117efe31588", "126b56fdefde1e0820ef4126968473d679e1ddd8",
        "same_name", "FuncCallSpecs::has_effect", "bd37797c", "6a4f2a05",
    ),
    _reviewed_transition(
        "RG-F-e4c1a4d9c31459eadc79", "RG-F-ea38acbd08840b54a14b",
        "RG-F-7a1cd2752ad576a23195", "126b56fdefde1e0820ef4126968473d679e1ddd8",
        "same_name", "Heritage::guard_calls", "9e3afa32", "f49d3f8f",
    ),
    _reviewed_transition(
        "RG-F-0695ea49a55e99ff2807", "RG-F-6e4fe065a522eb9bbc94",
        "RG-F-f23c84cf58035a9ebe14", "704699811626f01fc029f284e04e09815b06a39f",
        "same_name", "Merge::merge_speculative_by_vn", "9729b200", "53f856f1",
    ),
    _reviewed_transition(
        "RG-F-24df7359099d9878a582", "RG-F-9b8bb1a4809cd7ca6b16",
        "RG-F-ff1783edd76bcabdc140", "032419b344e973682076bf5c21109b7f05fee192",
        "successor", "Cover::order_of_op -> CoverEndpoint::from_op", "7b8a196e", "d6a5931f",
    ),
    _reviewed_transition(
        "RG-F-700e12a6872c24d82498", "RG-F-0d974b12c723b8e02471",
        "RG-F-2b387a75cbdd7e41a31c", "253707fadb0735ec211289132792934d9ae48e05",
        "successor", "default_alignment_map -> set_default_alignment_map", "c373c0e5", "00d4ac38",
    ),
    _reviewed_transition(
        "RG-F-439b1c3cd8210321d15e", "RG-F-73adae5df6d49b818459",
        "RG-F-d5be9719af51f5bf1fdc", "34940227825405eabd5358c108fbbead2ddb8581",
        "successor", "c_binary_op_str -> optoken::binary_token", "058e2633", "342d87e7",
    ),
    _reviewed_transition(
        "RG-F-a7a04409bf4b8d92ce15", "RG-F-19126ae1c4f800e1531b",
        "RG-F-39a5f83df9995b8bf34b", "38af1fd81973e29fb27071b18144f7b4db4ad428",
        "successor", "unknown_datatype -> default_unknown_type", "a5e0bf66", "9c3db2d2",
    ),
    _reviewed_transition(
        "RG-F-473f9d99b18f17fd9922", "RG-F-9c1b0bf6f51e30a77096",
        "RG-F-c2a760d91fd95478a016", "eb8ad57b5f472c182f25dd245460abdc3c9f33e6",
        "successor", "build_simplify_pool -> build_oppool1", "e3032afa", "e6aa9b91",
    ),
    _reviewed_transition(
        "RG-F-bf22c6ec4313930a2bb3", "RG-F-36cb30229138ce0e46f0",
        "RG-F-7f7a36379bbf2cb1f39f", "ee29a32487702a8044d910202903e83a23996c9e",
        "successor", "update_cover -> update_cover_locked", "54ff245d", "5b4a422d",
    ),
    _reviewed_transition(
        "RG-F-61dfe59ce876d87bb8ad", "RG-F-3c8e1df9334b3c78363a",
        "RG-F-2b52235062c1427143fa", "8ec6bee8fce58231b4ff093290457497206aeab5",
        "successor", "RangeRecord::first successor", "abb9260b", "73cacc26",
    ),
    _reviewed_transition(
        "RG-F-ef3f516520136385508d", "RG-F-32ca3afaf5f64455aa9e",
        "RG-F-9a07be81379bfc511a61", "8ec6bee8fce58231b4ff093290457497206aeab5",
        "successor", "RangeRecord::last successor", "abb9260b", "73cacc26",
    ),
)


def _tombstone(legacy: str, base: str, commit: str, name: str) -> dict[str, str]:
    return {
        "legacy_id": f"RG-F-{legacy}",
        "base_id": f"RG-F-{base}",
        "commit": commit,
        "name": name,
    }


REKEY_REVIEWED_TOMBSTONES = (
    _tombstone("6fccfccb5487c98f7997", "545a2fa83e26f9e8716d", "9825db126fb72f6d7652536f4516a6ea38c77da1", "intersect"),
    _tombstone("0f1afd435338b39ae1c4", "01c37763d9a53ef73ace", "9825db126fb72f6d7652536f4516a6ea38c77da1", "dfs_visit"),
    _tombstone("d051f78879b4ecfbdffb", "df80e19385aea19c30b5", "69ea4e048cb2185f0686b136b044217fc44fc88b", "find_spanning_tree"),
    _tombstone("a515040ca21e3a40b3bd", "965ea4deca6789b2653a", "c5e685c55e775192dae7b26f0631f6ac8ff85df6", "setup_block_list"),
    _tombstone("e2e407c3cfa4cb808159", "63f228446a519e0c8d80", "c5e685c55e775192dae7b26f0631f6ac8ff85df6", "setup_op_list"),
    _tombstone("c594237c5aae750c1651", "a679e28185a5cd97f9db", "c5e685c55e775192dae7b26f0631f6ac8ff85df6", "has_header_comments"),
    _tombstone("e56c7a580c5fbf1735b5", "07a5cf7058ae8cf06026", "c5e685c55e775192dae7b26f0631f6ac8ff85df6", "header_comments"),
    _tombstone("b56384676d5805afa616", "c1c6b7597b9723bcd50a", "bed6ef5605767811fe641201d86da80fe9f96b9e", "is_true_out_to"),
    _tombstone("0144832f561c7cd8e30f", "78de6b876155d5b7f967", "a9d68f779e7d6d47e4dd0b3da1569f9ce6c5fdc0", "flip_comparison"),
    _tombstone("44f5ea5f0b19361842c0", "ab960b0c66138f0a51af", "a9d68f779e7d6d47e4dd0b3da1569f9ce6c5fdc0", "test_prefercomplement_flips_boolean_flip"),
    _tombstone("07f6d8c1c408863b8543", "e1027492465f482180db", "a9d68f779e7d6d47e4dd0b3da1569f9ce6c5fdc0", "test_prefercomplement_flip_comparison"),
    _tombstone("f5f60231b4dcbaf7a838", "7bba63e94d32b61c1eec", "dd76d37866dcd2e4dc0a354323e0f016bb62fb35", "build_full_pipeline_actions"),
    _tombstone("c6ceca66030b18e666d1", "afd0a253ec7939ceb0d7", "dd76d37866dcd2e4dc0a354323e0f016bb62fb35", "test_build_full_pipeline_actions_nonempty"),
    _tombstone("2772e14a50d16aa73c41", "b89ca9c78de4d43b0641", "dd76d37866dcd2e4dc0a354323e0f016bb62fb35", "test_build_full_pipeline_actions_unique_names"),
    _tombstone("1291ed91ecdc95aa474f", "8a03aee5400b8f1aec82", "dd76d37866dcd2e4dc0a354323e0f016bb62fb35", "test_build_full_pipeline_actions_has_new_actions"),
    _tombstone("0036b1e6159131b90d5e", "828769ed1d87903b2f49", "dd76d37866dcd2e4dc0a354323e0f016bb62fb35", "test_build_full_pipeline_actions_excludes_block_mutators_and_stubs"),
    _tombstone("f89ffb08d7df8a69b93f", "3f721750f2a9d6acb761", "e034f80ba06d9acff0952ee50be4be39c3f8580a", "target_op_for_branch"),
    _tombstone("3724985bbd4374850d46", "60ba7907d4b5be14485c", "e034f80ba06d9acff0952ee50be4be39c3f8580a", "target_op_by_addr"),
    _tombstone("3864f2c13cdb9e6fdb97", "232322f83bab558eabb2", "3ee30ba0de3e55eb8b8e2cdbe52153df136d8bf9", "address_space_as_u32"),
    _tombstone("82eb3b5be5e838caa58e", "811518e6a28c130e573b", "3ee30ba0de3e55eb8b8e2cdbe52153df136d8bf9", "resolve_callother_payload_name"),
    _tombstone("be571c7397c18d59d8e4", "62677ad8d8248a7ab7c3", "126b56fdefde1e0820ef4126968473d679e1ddd8", "guard_returns"),
    _tombstone("110e7cb3a979adc595e0", "00414dcba113eb1cf787", "126b56fdefde1e0820ef4126968473d679e1ddd8", "guard_calls_range"),
    _tombstone("5b9bee2c44266559a724", "535aac7994cb2a0df898", "126b56fdefde1e0820ef4126968473d679e1ddd8", "guard_calls_range_with_space"),
    _tombstone("f2c70dc54daf5faaccad", "58223aa5b23fb6ffa6b1", "c30913076c0bc0033c0a688462030444c95fc264", "insert_multiequal"),
    _tombstone("e8440bf2ca995df09185", "0bb352245a43b1009d50", "0e4c6f45f32cf8ddd48849d1895fb29f68db620b", "assign_names"),
    _tombstone("b864c8440d57e0be0aed", "e0b261758e01fee35673", "0e4c6f45f32cf8ddd48849d1895fb29f68db620b", "register_name"),
    _tombstone("9b3ba477324abf563e92", "df77030350cd56f16c06", "7721b0d722cc8b507696f62922e978c0314fae3f", "register_payload"),
    _tombstone("fb4e57eb1fc08da9b754", "79cd9be355b367b91bea", "7721b0d722cc8b507696f62922e978c0314fae3f", "get_id"),
    _tombstone("ea847040afb0a57a335f", "72bab767946d70c663c6", "7721b0d722cc8b507696f62922e978c0314fae3f", "num_payloads"),
    _tombstone("66eeea2a761b604a28ba", "52ccd48128e40d6f37b0", "7721b0d722cc8b507696f62922e978c0314fae3f", "test_pcode_inject_library"),
    _tombstone("a22612c4dceb25126c6b", "5d67242db4fbc2603002", "7721b0d722cc8b507696f62922e978c0314fae3f", "test_register_call_fixup"),
    _tombstone("cb791532f7bd0a7f57c0", "7edaa9a420184bde51c6", "7721b0d722cc8b507696f62922e978c0314fae3f", "test_register_call_other_fixup"),
    _tombstone("3cca09c07784d1994f78", "d9e5720a4033361bb683", "7721b0d722cc8b507696f62922e978c0314fae3f", "test_register_call_mechanism"),
    _tombstone("ecc37431989bf168a937", "291fd9ff2aeafadcec76", "df0da852bba0fe3f857199fbc5b416e004df8f1c", "compact_name_for"),
    _tombstone("3d3c79e1fd7d70a102d4", "981f70767c5c8c5729cb", "df0da852bba0fe3f857199fbc5b416e004df8f1c", "preallocate_register_compact_names"),
    _tombstone("dcb5c56857185e0ff75c", "afc5544707c4f91fee45", "df0da852bba0fe3f857199fbc5b416e004df8f1c", "doc_variable_decls_from_funcdata"),
    _tombstone("0b63894a79fa2310c9ce", "98cadcff50035dc0db81", "df0da852bba0fe3f857199fbc5b416e004df8f1c", "test_compact_name_for"),
    _tombstone("9457bf91be8c7fd0b8c4", "27f74050a459dcc39ae2", "192e89407f5af7a419d1fe7bb30d119af8a231e0", "rename_scope_symbol"),
    _tombstone("ab891945fe45a58b7be9", "1aeb4fa12758eb2b41f6", "79a8faa198a23bc0a7c19e11dc360c66a63f1fd4", "new"),
    _tombstone("fae83367c2e7db8035b6", "4b1c37948f6503fb22e4", "79a8faa198a23bc0a7c19e11dc360c66a63f1fd4", "apply_op"),
    _tombstone("1e978e7c99761b05d41c", "2d887962c3671a23a057", "79a8faa198a23bc0a7c19e11dc360c66a63f1fd4", "get_name"),
    _tombstone("79f85567e39a8f3da854", "396b06cb2c37b5ef8bc0", "79a8faa198a23bc0a7c19e11dc360c66a63f1fd4", "get_opcodes"),
    _tombstone("b83de19c3204b2d095f3", "64f3fe19484db472dc7e", "a770ed10df7806bf03e34d798b3f3712a08ec2bd", "test_shift_by_nonzero_unchanged"),
    _tombstone("a72bb5e89b3cb6c78685", "295a58b7a7a62200fc52", "34fd254755441def6e17197cf2431f7fcf920c24", "next_document"),
    _tombstone("b0e2c5a6cf989f5042de", "5fab4d997916a47717d6", "5fb36f0225c6efe606b5e8b5213163d956e9f2f1", "comparable_flags"),
    _tombstone("c2362bc96e45d55b5ca3", "a73a582f615d89a9c4f3", "83a900efd41c9222c74b5e3be9d790fcbe86c645", "query_by_addr"),
    _tombstone("f83ff911cc781b9fd152", "ffc8a907ea67daf0c0c5", "e87ebfc54444d5f043a321ea1a46e3c8004eff23", "collect_copy_sources"),
)


def old_rust_records_at_tree(root: Path, commit: str) -> list[dict[str, object]]:
    """Recompute legacy-scheme Rust IDs (path + name + ordinal) at a commit."""

    listing = command_output(
        ["git", "ls-tree", "-r", "--name-only", commit, "src/"], root
    ).splitlines()
    records: list[dict[str, object]] = []
    for relative in sorted(line for line in listing if line.endswith(".rs")):
        text = command_output(["git", "show", f"{commit}:{relative}"], root)
        ordinals: Counter[str] = Counter()
        for record in scan_rust_functions(text):
            ordinals[record.name] += 1
            records.append(
                {
                    "id": stable_id(
                        OLD_RUST_ID_PREFIX, (relative, record.name, ordinals[record.name])
                    ),
                    "path": relative,
                    "name": record.name,
                    "line": record.start_line + 1,
                    "name_ordinal": ordinals[record.name],
                }
            )
    return records


def old_rust_projection(entries: list[dict[str, object]]) -> list[tuple[object, ...]]:
    return [
        (
            entry["path"],
            entry["name"],
            int(entry["line"]),
            int(entry["name_ordinal"]),
            str(entry["id"]),
        )
        for entry in entries
    ]


def detect_old_ledger_tree(
    root: Path, ledger_path: Path, old_rust: list[dict[str, object]], override: str | None
) -> str:
    """Find the commit whose tree reproduces the existing ledger's Rust scan."""

    target = old_rust_projection(old_rust)
    candidates: list[str] = []
    if override:
        candidates.append(override)
    relative_ledger = ledger_path.relative_to(root).as_posix()
    last_touch = command_output(
        ["git", "log", "-1", "--format=%H", "--", relative_ledger], root
    ).strip()
    if last_touch:
        candidates.append(last_touch)
    candidates.append(command_output(["git", "rev-parse", "HEAD"], root).strip())
    candidates.extend(
        line for line in command_output(["git", "log", "--format=%H", "-n", "30"], root).splitlines()
    )
    seen: set[str] = set()
    for commit in candidates:
        if not commit or commit in seen:
            continue
        seen.add(commit)
        try:
            records = old_rust_records_at_tree(root, commit)
        except RuntimeError:
            continue
        if old_rust_projection(records) == target:
            return commit
    raise RuntimeError(
        "cannot reproduce the existing ledger's Rust records from --migrate-base, the "
        "ledger's last-touching commit, HEAD, or the 30 most recent commits; refusing "
        "to migrate against an unknown source tree"
    )


def migration_rows(
    old_ghidra: list[dict[str, object]],
    new_ghidra: list[dict[str, object]],
    old_rust: list[dict[str, object]],
    new_rust: list[dict[str, object]],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Correlate old ledger entries with new-scheme IDs, fail-closed.

    Returns (rows, disambiguators).  Every old entry must correlate with
    exactly one new entry and vice versa; any ambiguity raises instead of
    being guessed.
    """

    ghidra_index: dict[tuple[object, ...], dict[str, object]] = {}
    for entry in new_ghidra:
        key = (entry["path"], int(entry["line"]), entry["entry_kind"], entry["name"])
        if key in ghidra_index:
            raise RuntimeError(f"fresh Ghidra scan is self-ambiguous at {key}")
        ghidra_index[key] = entry
    rust_index: dict[tuple[object, ...], dict[str, object]] = {}
    for record in new_rust:
        key = (record["path"], int(record["line"]), record["name"])
        if key in rust_index:
            raise RuntimeError(f"new Rust scan is self-ambiguous at {key}")
        rust_index[key] = record

    rows: list[dict[str, object]] = []
    disambiguators: list[dict[str, object]] = []
    if len(old_ghidra) != len(ghidra_index):
        raise RuntimeError(
            f"Ghidra record count changed against the locked oracle: old={len(old_ghidra)} new={len(ghidra_index)}"
        )
    for entry in old_ghidra:
        key = (entry["path"], int(entry["line"]), entry["entry_kind"], entry["name"])
        fresh = ghidra_index.get(key)
        if fresh is None:
            raise RuntimeError(f"old Ghidra entry has no locked-oracle counterpart: {key}")
        new_id = str(fresh["id"])
        old_id = str(entry["id"])
        reason = "ghidra_signature_rekey"
        if ORDINAL_SUFFIX_RE.search(old_id):
            reason = "ghidra_ordinal_replaced_by_guard_disambiguator"
        rows.append(
            {
                "old_id": old_id,
                "new_id": new_id,
                "language": "ghidra",
                "reason": reason if old_id != new_id else "unchanged",
            }
        )
        if fresh.get("id_disambiguator"):
            disambiguators.append(
                {
                    "old_id": old_id,
                    "new_id": new_id,
                    "language": "ghidra",
                    "path": fresh["path"],
                    "entry_kind": fresh["entry_kind"],
                    "signature": fresh["signature"],
                    "disambiguator_kind": "preprocessor_guard",
                    "disambiguator": fresh["id_disambiguator"]["value"],
                }
            )
    if len(old_rust) != len(rust_index):
        raise RuntimeError(
            f"Rust record count differs between the old ledger tree and recomputation: "
            f"old={len(old_rust)} new={len(rust_index)}"
        )
    for entry in old_rust:
        key = (entry["path"], int(entry["line"]), entry["name"])
        fresh = rust_index.get(key)
        if fresh is None:
            raise RuntimeError(f"old Rust entry has no counterpart on the ledger tree: {key}")
        old_id = str(entry["id"])
        new_id = str(fresh["id"])
        rows.append(
            {
                "old_id": old_id,
                "new_id": new_id,
                "language": "rust",
                "reason": "rust_identity_rekey" if old_id != new_id else "unchanged",
            }
        )
    return rows, disambiguators


def check_migration_rows(rows: list[dict[str, object]]) -> dict[str, object]:
    """Fail closed on any old-ID ambiguity or new-ID collision."""

    by_old: dict[str, set[str]] = defaultdict(set)
    by_new: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        by_old[str(row["old_id"])].add(str(row["new_id"]))
        by_new[str(row["new_id"])].add(str(row["old_id"]))
    ambiguous_old = sorted(
        {old: sorted(news) for old, news in by_old.items() if len(news) > 1}.items()
    )
    colliding_new = sorted(
        {new: sorted(olds) for new, olds in by_new.items() if len(olds) > 1}.items()
    )
    if ambiguous_old or colliding_new:
        details = []
        for old_id, news in ambiguous_old:
            details.append(f"old id {old_id} maps to multiple new ids: {news}")
        for new_id, olds in colliding_new:
            details.append(f"new id {new_id} would absorb multiple old ids: {olds}")
        raise RuntimeError("migration ambiguity (fail-closed, refusing to guess):\n" + "\n".join(details))
    stable = sum(1 for row in rows if row["old_id"] == row["new_id"])
    return {
        "total": len(rows),
        "stable_unchanged": stable,
        "changed": len(rows) - stable,
        "ambiguous_old_ids": len(ambiguous_old),
        "colliding_new_ids": len(colliding_new),
    }


def migration_document(
    root: Path,
    old_ledger_path: Path,
    output_dir: Path,
    migrate_base: str | None,
) -> dict[str, object]:
    old_ledger = json.loads(old_ledger_path.read_text(encoding="utf-8"))
    old_ghidra = list(old_ledger["ghidra_functions"])
    old_rust = list(old_ledger["rugra_functions"])

    cpp = verify_oracle(root)
    fresh_ghidra, _ = ctags_entries(root, cpp)
    validate_ctags_counts(fresh_ghidra)

    tree = detect_old_ledger_tree(root, old_ledger_path, old_rust, migrate_base)
    tree_rust: list[dict[str, object]] = []
    listing = command_output(["git", "ls-tree", "-r", "--name-only", tree, "src/"], root).splitlines()
    for relative in sorted(line for line in listing if line.endswith(".rs")):
        text = command_output(["git", "show", f"{tree}:{relative}"], root)
        tree_rust.extend(
            collect_rust_identities(relative, text, module_from_relative(relative))
        )
    assign_rust_locked_ids(tree_rust)

    rows, disambiguators = migration_rows(old_ghidra, fresh_ghidra, old_rust, tree_rust)
    stats = check_migration_rows(rows)
    reasons: Counter[str] = Counter(str(row["reason"]) for row in rows)
    per_language: dict[str, dict[str, object]] = {}
    for language in ("ghidra", "rust"):
        language_rows = [row for row in rows if row["language"] == language]
        language_reasons = Counter(str(row["reason"]) for row in language_rows)
        per_language[language] = {
            "total": len(language_rows),
            "stable_unchanged": sum(row["old_id"] == row["new_id"] for row in language_rows),
            **{f"changed_{reason}": count for reason, count in sorted(language_reasons.items()) if reason != "unchanged"},
        }
    subject = command_output(["git", "show", "-s", "--format=%s", tree], root).strip()
    return {
        "schema": 1,
        "oracle_commit": ORACLE_COMMIT,
        "id_scheme": ID_SCHEME,
        "old_ledger": {
            "path": old_ledger_path.relative_to(root).as_posix(),
            "tree_commit": tree,
            "tree_subject": subject,
        },
        "semantics": (
            "Rust new IDs are computed on the verified old-ledger tree so old-to-new "
            "correlation is positional and exact; Ghidra new IDs recompute from the "
            "locked oracle. Every collision disambiguator is listed explicitly; "
            "ordinal- or line-derived tokens never participate."
        ),
        "stats": {
            **stats,
            "reasons": dict(sorted(reasons.items())),
            "per_language": per_language,
        },
        "disambiguators": disambiguators,
        "entries": rows,
    }


# --- Migration reconciliation: pinned scheme-2 history replay --------------


REKEY_HUNK_RE = re.compile(
    r"^@@ -(?P<old>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new>\d+)(?:,(?P<new_count>\d+))? @@"
)


def _migration_git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        environment.pop(name, None)
    environment.update(
        {"LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    )
    return environment


def _migration_git(root: Path, command: list[str]) -> str:
    result = subprocess.run(
        ["git", *command],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_migration_git_environment(),
    )
    if result.returncode != 0:
        raise MigrationHarnessError(
            f"command failed ({result.returncode}): git {' '.join(command)}\n{result.stderr}"
        )
    return result.stdout


def _migration_json_from_git(root: Path, revision: str, relative: str) -> dict[str, object]:
    try:
        document = json.loads(_migration_git(root, ["show", f"{revision}:{relative}"]))
    except json.JSONDecodeError as error:
        raise MigrationHarnessError(
            f"pinned JSON is malformed at {revision}:{relative}: {error}"
        ) from error
    if not isinstance(document, dict):
        raise MigrationHarnessError(f"pinned JSON root is not an object: {revision}:{relative}")
    return document


def _expect_git_object(root: Path, revision: str, expected: str, label: str) -> str:
    actual = _migration_git(root, ["rev-parse", revision]).strip()
    if actual != expected:
        raise MigrationHarnessError(f"{label} mismatch: expected {expected}, got {actual}")
    return actual


def verify_rekey_boundary(root: Path, *, verify_locked_oracle: bool = True) -> list[str]:
    """Validate every immutable input before replaying or writing output."""

    _expect_git_object(
        root, f"{REKEY_SOURCE_COMMIT}^{{commit}}", REKEY_SOURCE_COMMIT, "source commit"
    )
    _expect_git_object(
        root, f"{REKEY_SOURCE_COMMIT}^{{tree}}", REKEY_SOURCE_COMMIT_TREE,
        "source commit tree",
    )
    _expect_git_object(
        root, f"{REKEY_SOURCE_COMMIT}:src", REKEY_SOURCE_SRC_TREE, "source src tree"
    )
    _expect_git_object(
        root,
        f"{REKEY_SOURCE_COMMIT}:docs/alignment_audit/FUNCTION_LEDGER.json",
        REKEY_SOURCE_LEDGER_BLOB,
        "source ledger blob",
    )
    _expect_git_object(
        root, f"{REKEY_TARGET_COMMIT}^{{commit}}", REKEY_TARGET_COMMIT, "target commit"
    )
    _expect_git_object(
        root, f"{REKEY_TARGET_COMMIT}^{{tree}}", REKEY_TARGET_COMMIT_TREE,
        "target commit tree",
    )
    _expect_git_object(
        root, f"{REKEY_TARGET_COMMIT}:src", REKEY_TARGET_SRC_TREE, "target src tree"
    )
    _expect_git_object(
        root,
        f"{REKEY_TARGET_COMMIT}:docs/alignment_audit/FUNCTION_LEDGER.json",
        REKEY_TARGET_LEDGER_BLOB,
        "target ledger blob",
    )
    _expect_git_object(
        root,
        f"{REKEY_TARGET_COMMIT}:docs/alignment_audit/FUNCTION_ID_MIGRATION.json",
        REKEY_SOURCE_MIGRATION_BLOB,
        "source migration blob",
    )

    for ancestor, descendant, label in (
        (REKEY_SOURCE_COMMIT, REKEY_TARGET_COMMIT, "source is not an ancestor of target"),
        (REKEY_TARGET_COMMIT, "HEAD", "target is not an ancestor of HEAD"),
    ):
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_migration_git_environment(),
        )
        if result.returncode != 0:
            raise MigrationHarnessError(label)

    commits = _migration_git(
        root,
        ["rev-list", "--first-parent", "--reverse", f"{REKEY_SOURCE_COMMIT}..{REKEY_TARGET_COMMIT}"],
    ).splitlines()
    if len(commits) != REKEY_FIRST_PARENT_COMMIT_COUNT:
        raise MigrationHarnessError(
            "first-parent history length mismatch: "
            f"expected {REKEY_FIRST_PARENT_COMMIT_COUNT}, got {len(commits)}"
        )
    previous = REKEY_SOURCE_COMMIT
    for commit in commits:
        first_parent = _migration_git(root, ["rev-parse", f"{commit}^1"]).strip()
        if first_parent != previous:
            raise MigrationHarnessError(
                f"first-parent discontinuity at {commit}: expected {previous}, got {first_parent}"
            )
        previous = commit
    if previous != REKEY_TARGET_COMMIT:
        raise MigrationHarnessError(
            f"first-parent replay ended at {previous}, not {REKEY_TARGET_COMMIT}"
        )

    head_src = _migration_git(root, ["rev-parse", "HEAD:src"]).strip()
    if head_src != REKEY_TARGET_SRC_TREE:
        raise MigrationHarnessError(
            f"HEAD src tree mismatch: expected {REKEY_TARGET_SRC_TREE}, got {head_src}"
        )
    dirty_src = _migration_git(
        root, ["status", "--porcelain=v1", "--untracked-files=all", "--", "src"]
    ).strip()
    if dirty_src:
        raise MigrationHarnessError(f"target src worktree is dirty:\n{dirty_src}")
    ledger_path = root / "docs/alignment_audit/FUNCTION_LEDGER.json"
    if not ledger_path.is_file():
        raise MigrationHarnessError("target ledger is missing from the worktree")
    ledger_blob = _migration_git(root, ["hash-object", str(ledger_path)]).strip()
    if ledger_blob != REKEY_TARGET_LEDGER_BLOB:
        raise MigrationHarnessError(
            f"worktree ledger blob mismatch: expected {REKEY_TARGET_LEDGER_BLOB}, got {ledger_blob}"
        )
    if verify_locked_oracle:
        oracle_root = root / "ghidra"
        oracle_head = _migration_git(oracle_root, ["rev-parse", "HEAD"]).strip()
        if oracle_head != ORACLE_COMMIT:
            raise MigrationHarnessError(
                f"wrong Ghidra oracle: expected {ORACLE_COMMIT}, got {oracle_head}"
            )
        oracle_dirty = _migration_git(
            oracle_root, ["status", "--porcelain", "--untracked-files=no"]
        ).strip()
        if oracle_dirty:
            raise MigrationHarnessError(
                f"locked Ghidra worktree has tracked changes:\n{oracle_dirty}"
            )
        cpp = oracle_root / "Ghidra/Features/Decompiler/src/decompile/cpp"
        cc_count = len(list(cpp.glob("*.cc")))
        if cc_count != 114:
            raise MigrationHarnessError(
                f"wrong Ghidra source closure: expected 114 .cc, got {cc_count}"
            )
    return commits


def _validate_rekey_source_tables(
    source_ledger: dict[str, object],
    target_ledger: dict[str, object],
    source_migration: dict[str, object],
) -> tuple[list[dict[str, object]], set[str], dict[str, dict[str, object]]]:
    for label, ledger in (("source", source_ledger), ("target", target_ledger)):
        # The pinned source is the pre-scheme-2 ledger by construction and
        # therefore has no id_scheme block.  The target must carry scheme 2.
        if ledger.get("schema") != 1:
            raise MigrationHarnessError(f"{label} ledger schema mismatch")
        if label == "target" and not isinstance(ledger.get("id_scheme"), dict):
            raise MigrationHarnessError("target ledger id_scheme is missing")
        for field in ("ghidra_functions", "rugra_functions"):
            if not isinstance(ledger.get(field), list):
                raise MigrationHarnessError(f"{label} ledger {field} is not an array")
    if source_migration.get("schema") != 1:
        raise MigrationHarnessError("source migration must be immutable schema 1")
    for field in ("entries", "disambiguators"):
        if not isinstance(source_migration.get(field), list):
            raise MigrationHarnessError(f"source migration {field} is not an array")
    entries = list(source_migration["entries"])
    if len(entries) != REKEY_ORIGIN_COUNT:
        raise MigrationHarnessError(
            f"source migration origin count mismatch: expected {REKEY_ORIGIN_COUNT}, got {len(entries)}"
        )
    try:
        source_stats = check_migration_rows(entries)
    except RuntimeError as error:
        raise MigrationHarnessError(str(error)) from error
    if source_stats["total"] != REKEY_ORIGIN_COUNT:
        raise MigrationHarnessError("source migration collision audit did not cover every origin")
    old_ledger = source_migration.get("old_ledger")
    if not isinstance(old_ledger, dict) or old_ledger.get("tree_commit") != REKEY_SOURCE_COMMIT:
        raise MigrationHarnessError("source migration old-ledger commit pin mismatch")
    if source_migration.get("oracle_commit") != ORACLE_COMMIT:
        raise MigrationHarnessError("source migration oracle commit mismatch")
    target_oracle = target_ledger.get("oracle")
    if not isinstance(target_oracle, dict) or target_oracle.get("commit") != ORACLE_COMMIT:
        raise MigrationHarnessError("target ledger oracle commit mismatch")

    target_ids: set[str] = set()
    for field in ("ghidra_functions", "rugra_functions"):
        for record in target_ledger[field]:
            if not isinstance(record, dict) or not isinstance(record.get("id"), str):
                raise MigrationHarnessError(f"target ledger contains a malformed {field} record")
            fid = str(record["id"])
            if fid in target_ids:
                raise MigrationHarnessError(f"target ledger contains duplicate function id {fid}")
            target_ids.add(fid)

    source_rust_by_legacy: dict[str, dict[str, object]] = {}
    for record in source_ledger["rugra_functions"]:
        if not isinstance(record, dict) or not isinstance(record.get("id"), str):
            raise MigrationHarnessError("source ledger contains a malformed Rust record")
        source_rust_by_legacy[str(record["id"])] = record
    return entries, target_ids, source_rust_by_legacy


def _identity_projection(record: dict[str, object]) -> tuple[object, ...]:
    return tuple(
        record.get(field)
        for field in (
            "id", "path", "name", "line", "end_line", "module", "owner", "signature",
            "is_test", "is_declaration",
        )
    )


def _fresh_target_rust(root: Path, target_ledger: dict[str, object]) -> list[dict[str, object]]:
    fresh: list[dict[str, object]] = []
    for path in sorted((root / "src").rglob("*.rs")):
        relative = path.relative_to(root).as_posix()
        text_value = path.read_text(encoding="utf-8")
        fresh.extend(
            collect_rust_identities(relative, text_value, module_from_relative(relative))
        )
    try:
        assign_rust_locked_ids(fresh)
    except RuntimeError as error:
        raise MigrationHarnessError(str(error)) from error
    pinned = list(target_ledger["rugra_functions"])
    fresh_projection = sorted(_identity_projection(record) for record in fresh)
    pinned_projection = sorted(_identity_projection(record) for record in pinned)
    if fresh_projection != pinned_projection:
        missing = sorted(set(pinned_projection) - set(fresh_projection))[:3]
        extra = sorted(set(fresh_projection) - set(pinned_projection))[:3]
        raise MigrationHarnessError(
            "fresh Rust scan does not reproduce the pinned target ledger: "
            f"pinned={len(pinned_projection)} fresh={len(fresh_projection)} "
            f"missing={missing} extra={extra}"
        )
    return fresh


def _blob_text(root: Path, blob: str, cache: dict[str, str]) -> str:
    if blob == "0" * 40:
        return ""
    if blob not in cache:
        cache[blob] = _migration_git(root, ["cat-file", "blob", blob])
    return cache[blob]


def _scan_rekey_blob(
    root: Path,
    relative: str,
    blob: str,
    text_cache: dict[str, str],
    scan_cache: dict[tuple[str, str], list[dict[str, object]]],
) -> list[dict[str, object]]:
    if blob == "0" * 40 or not relative.endswith(".rs"):
        return []
    cache_key = (relative, blob)
    if cache_key in scan_cache:
        return scan_cache[cache_key]
    source = _blob_text(root, blob, text_cache)
    records = collect_rust_identities(relative, source, module_from_relative(relative))
    try:
        assign_rust_locked_ids(records)
    except RuntimeError as error:
        raise MigrationHarnessError(f"{relative}@{blob}: {error}") from error
    code = mask_non_code(source)
    pairs = rust_brace_pairs(code)
    lines = source.splitlines()
    for record in records:
        annotation_kind, annotation = marker_above(lines, int(record["line"]) - 1)
        record["_annotation"] = (
            (annotation_kind, json.dumps(annotation, sort_keys=True, separators=(",", ":")))
            if annotation
            else None
        )
        signature_end = rust_signature_end(code, pairs, int(record["start"]))
        body = " ".join(code[signature_end:int(record["end"])].split())
        record["_masked_body"] = body if body and body != ";" else None
        record["_annotation_kind"] = annotation_kind
        record["_annotation_value"] = annotation
    scan_cache[cache_key] = records
    return records


def _rust_changes(root: Path, parent: str, commit: str) -> list[dict[str, str]]:
    raw = _migration_git(
        root,
        ["diff-tree", "--no-commit-id", "--raw", "-r", "--no-abbrev", "--no-renames",
         parent, commit, "--", "src"],
    )
    changes: list[dict[str, str]] = []
    for line in raw.splitlines():
        if not line:
            continue
        parts = line.split("\t")
        header = parts[0].split()
        if len(header) != 5 or not header[0].startswith(":"):
            raise MigrationHarnessError(f"cannot parse raw diff row at {commit}: {line}")
        old_blob, new_blob, status = header[2], header[3], header[4]
        if status.startswith(("R", "C")):
            if len(parts) != 3:
                raise MigrationHarnessError(f"cannot parse rename/copy row at {commit}: {line}")
            old_path, new_path = parts[1], parts[2]
        else:
            if len(parts) != 2:
                raise MigrationHarnessError(f"cannot parse diff path at {commit}: {line}")
            old_path = new_path = parts[1]
        if not old_path.endswith(".rs") and not new_path.endswith(".rs"):
            continue
        changes.append(
            {
                "old_path": old_path,
                "new_path": new_path,
                "old_blob": old_blob,
                "new_blob": new_blob,
                "status": status,
            }
        )
    changes.sort(key=lambda item: (item["old_path"], item["new_path"], item["status"]))
    return changes


def _record_intersects_hunk(record: dict[str, object], start: int, count: int) -> bool:
    if count == 0:
        return int(record["line"]) <= start <= int(record["end_line"]) + 1
    end = start + count - 1
    return int(record["line"]) <= end and start <= int(record["end_line"])


def _diff_hunks(
    root: Path,
    parent: str,
    commit: str,
    path: str,
    cache: dict[tuple[str, str], list[tuple[int, int, int, int]]],
) -> list[tuple[int, int, int, int]]:
    key = (commit, path)
    if key in cache:
        return cache[key]
    diff = _migration_git(
        root, ["diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--unified=0",
               parent, commit, "--", path]
    )
    hunks: list[tuple[int, int, int, int]] = []
    for line in diff.splitlines():
        match = REKEY_HUNK_RE.match(line)
        if match:
            hunks.append(
                (
                    int(match.group("old")),
                    int(match.group("old_count") or 1),
                    int(match.group("new")),
                    int(match.group("new_count") or 1),
                )
            )
    cache[key] = hunks
    return hunks


def strict_transition_evidence(
    old: dict[str, object],
    new: dict[str, object],
    hunks: list[tuple[int, int, int, int]],
) -> list[str]:
    evidence: list[str] = []
    if any(
        _record_intersects_hunk(old, old_start, old_count)
        and _record_intersects_hunk(new, new_start, new_count)
        for old_start, old_count, new_start, new_count in hunks
    ):
        evidence.append("same_patch_hunk")
    if old.get("_annotation") and old.get("_annotation") == new.get("_annotation"):
        evidence.append("identical_nonempty_annotation")
    if old.get("_masked_body") and old.get("_masked_body") == new.get("_masked_body"):
        evidence.append("identical_masked_body")
    return evidence


def select_unique_strict_transition(
    commit: str,
    key: tuple[object, ...],
    old_tokens: list[str],
    new_tokens: list[str],
    before: dict[str, tuple[dict[str, object], str]],
    after: dict[str, tuple[dict[str, object], str]],
    hunks: list[tuple[int, int, int, int]],
) -> tuple[str, str, list[str]] | None:
    """Select one evidence-bearing 1->1 transition, or fail on ambiguity."""

    if not new_tokens:
        return None
    if len(old_tokens) != 1 or len(new_tokens) != 1:
        raise MigrationHarnessError(
            f"ambiguous automatic transition at {commit} for {key}: "
            f"removed={old_tokens} added={new_tokens}"
        )
    source_token, target_token = old_tokens[0], new_tokens[0]
    evidence = strict_transition_evidence(
        before[source_token][0], after[target_token][0], hunks
    )
    return (source_token, target_token, evidence) if evidence else None


def _lineage_event(
    old: dict[str, object],
    new: dict[str, object],
    commit: str,
    parent_blob: str,
    child_blob: str,
    evidence: list[str],
) -> dict[str, object]:
    return {
        "from_id": old["id"],
        "to_id": new["id"],
        "commit": commit,
        "from_path": old["path"],
        "to_path": new["path"],
        "parent_blob": parent_blob,
        "child_blob": child_blob,
        "evidence": evidence,
    }


# --- Post-baseline function-ID continuity ---------------------------------


def rust_parameter_binding_mut_normalized_signature(signature: str) -> str:
    """Remove only a leading, top-level Rust parameter binding ``mut``.

    This canonical form is evidence for a continuity event; it is never fed
    to :func:`stable_id`.  In particular, ``&mut T`` and ``*mut T`` stay byte
    significant because their ``mut`` token is not the leading binding token.
    """

    match = re.search(r"\bfn\s+(?:r#)?[A-Za-z_][A-Za-z0-9_]*", signature)
    if match is None:
        return " ".join(signature.split())
    angle_depth = 0
    open_paren = None
    for index in range(match.end(), len(signature)):
        ch = signature[index]
        if ch == "<":
            angle_depth += 1
        elif ch == ">" and angle_depth:
            angle_depth -= 1
        elif ch == "(" and angle_depth == 0:
            open_paren = index
            break
    if open_paren is None:
        return " ".join(signature.split())

    depth = 0
    close_paren = None
    for index in range(open_paren, len(signature)):
        ch = signature[index]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                close_paren = index
                break
    if close_paren is None:
        return " ".join(signature.split())

    inner = signature[open_paren + 1:close_paren]
    parameters: list[str] = []
    start = 0
    depths = {"(": 0, "[": 0, "{": 0, "<": 0}
    closer = {")": "(", "]": "[", "}": "{", ">": "<"}
    for index, ch in enumerate(inner):
        if ch in depths:
            depths[ch] += 1
        elif ch in closer and depths[closer[ch]]:
            depths[closer[ch]] -= 1
        elif ch == "," and not any(depths.values()):
            parameters.append(inner[start:index])
            start = index + 1
    parameters.append(inner[start:])

    normalized: list[str] = []
    for parameter in parameters:
        value = parameter.strip()
        attribute_prefix = ""
        # Parameter outer attributes precede the binding pattern.  Preserve
        # them and only inspect the first token after every complete #[...].
        while value.startswith("#["):
            attr_depth = 0
            attr_end = None
            for index, ch in enumerate(value):
                if ch == "[":
                    attr_depth += 1
                elif ch == "]":
                    attr_depth -= 1
                    if attr_depth == 0:
                        attr_end = index + 1
                        break
            if attr_end is None:
                break
            attribute_prefix += value[:attr_end].strip() + " "
            value = value[attr_end:].lstrip()
        value = re.sub(r"^mut\b\s*", "", value, count=1)
        normalized.append((attribute_prefix + value).strip())
    rebuilt = (
        signature[:open_paren]
        + "("
        + ", ".join(normalized)
        + ")"
        + signature[close_paren + 1:]
    )
    return " ".join(rebuilt.split())


def rust_trailing_comma_normalized_signature(signature: str) -> str:
    """Drop only the trailing parameter separator of the top-level parameter list.

    This canonical form is evidence for a continuity event; it is never fed to
    :func:`stable_id`.  Only the comma immediately before the *top-level*
    parameter-list closing paren is dropped, and whitespace is collapsed, so a
    semantically significant separator inside a nested type (for example the
    1-tuple ``(u8,)``) stays byte significant and mixed changes keep requiring
    a reviewed rule.
    """

    match = re.search(r"\bfn\s+(?:r#)?[A-Za-z_][A-Za-z0-9_]*", signature)
    if match is None:
        return " ".join(signature.split())
    angle_depth = 0
    open_paren = None
    for index in range(match.end(), len(signature)):
        ch = signature[index]
        if ch == "<":
            angle_depth += 1
        elif ch == ">" and angle_depth:
            angle_depth -= 1
        elif ch == "(" and angle_depth == 0:
            open_paren = index
            break
    if open_paren is None:
        return " ".join(signature.split())
    depth = 0
    close_paren = None
    for index in range(open_paren, len(signature)):
        if signature[index] == "(":
            depth += 1
        elif signature[index] == ")":
            depth -= 1
            if depth == 0:
                close_paren = index
                break
    if close_paren is None:
        return " ".join(signature.split())
    inner = " ".join(signature[open_paren + 1:close_paren].split())
    if inner.endswith(","):
        inner = inner[:-1].rstrip()
    return " ".join(
        (signature[:open_paren + 1] + inner + signature[close_paren:]).split()
    )


RUST_PROJECTION_FIELDS = (
    "id", "path", "name", "line", "end_line", "module", "owner", "signature",
    "is_test", "is_declaration",
)


def rust_identity_projection(records: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    projection = [
        {field: record.get(field) for field in RUST_PROJECTION_FIELDS}
        for record in records
    ]
    projection.sort(
        key=lambda record: (
            str(record.get("id")), str(record.get("path")),
            int(record.get("line") or 0), str(record.get("signature")),
        )
    )
    return projection


def rust_identity_projection_sha256(records: Iterable[dict[str, object]]) -> str:
    encoded = json.dumps(
        rust_identity_projection(records),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _scan_rust_revision(root: Path, revision: str) -> list[dict[str, object]]:
    listing = _migration_git(
        root, ["ls-tree", "-r", "--name-only", revision, "--", "src"]
    ).splitlines()
    records: list[dict[str, object]] = []
    for relative in sorted(path for path in listing if path.endswith(".rs")):
        source = _migration_git(root, ["show", f"{revision}:{relative}"])
        records.extend(
            collect_rust_identities(relative, source, module_from_relative(relative))
        )
    try:
        assign_rust_locked_ids(records)
    except RuntimeError as error:
        raise MigrationHarnessError(f"{revision} Rust scan: {error}") from error
    return records


def _load_worktree_ledger(root: Path) -> dict[str, object]:
    path = root / "docs/alignment_audit/FUNCTION_LEDGER.json"
    if not path.is_file():
        raise MigrationHarnessError("current ledger is missing from the worktree")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise MigrationHarnessError(f"current ledger JSON is malformed: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get("rugra_functions"), list):
        raise MigrationHarnessError("current ledger rugra_functions must be an array")
    return document


def _verify_locked_oracle_for_continuity(root: Path) -> None:
    oracle_root = root / "ghidra"
    oracle_head = _migration_git(oracle_root, ["rev-parse", "HEAD"]).strip()
    if oracle_head != ORACLE_COMMIT:
        raise MigrationHarnessError(
            f"wrong Ghidra oracle: expected {ORACLE_COMMIT}, got {oracle_head}"
        )
    oracle_dirty = _migration_git(
        oracle_root, ["status", "--porcelain", "--untracked-files=no"]
    ).strip()
    if oracle_dirty:
        raise MigrationHarnessError(
            f"locked Ghidra worktree has tracked changes:\n{oracle_dirty}"
        )
    cpp = oracle_root / "Ghidra/Features/Decompiler/src/decompile/cpp"
    cc_count = len(list(cpp.glob("*.cc")))
    if cc_count != 114:
        raise MigrationHarnessError(
            f"wrong Ghidra source closure: expected 114 .cc, got {cc_count}"
        )


def verify_continuity_boundary(
    root: Path, *, verify_locked_oracle: bool = True
) -> tuple[list[str], dict[str, object], dict[str, object], list[dict[str, object]]]:
    """Verify the baseline, checkpoint, worktree ledger, and source projection."""

    for revision, expected, label in (
        (f"{REKEY_TARGET_COMMIT}^{{commit}}", REKEY_TARGET_COMMIT, "baseline commit"),
        (f"{REKEY_TARGET_COMMIT}^{{tree}}", REKEY_TARGET_COMMIT_TREE, "baseline commit tree"),
        (f"{REKEY_TARGET_COMMIT}:src", REKEY_TARGET_SRC_TREE, "baseline src tree"),
        (
            f"{REKEY_TARGET_COMMIT}:docs/alignment_audit/FUNCTION_LEDGER.json",
            REKEY_TARGET_LEDGER_BLOB,
            "baseline ledger blob",
        ),
        (
            f"{CONTINUITY_CHECKPOINT_COMMIT}^{{commit}}",
            CONTINUITY_CHECKPOINT_COMMIT,
            "checkpoint commit",
        ),
        (
            f"{CONTINUITY_CHECKPOINT_COMMIT}^{{tree}}",
            CONTINUITY_CHECKPOINT_COMMIT_TREE,
            "checkpoint commit tree",
        ),
        (
            f"{CONTINUITY_CHECKPOINT_COMMIT}:src",
            CONTINUITY_CHECKPOINT_SRC_TREE,
            "checkpoint src tree",
        ),
        (
            f"{CONTINUITY_CHECKPOINT_COMMIT}:docs/alignment_audit/FUNCTION_ID_MIGRATION.json",
            CONTINUITY_BASELINE_MIGRATION_BLOB,
            "baseline migration blob at checkpoint",
        ),
    ):
        _expect_git_object(root, revision, expected, label)
    _expect_git_object(
        root, f"{CONTINUITY_CHECKPOINT_COMMIT}^1",
        CONTINUITY_CHECKPOINT_PARENT, "checkpoint first parent",
    )

    for ancestor, descendant, label in (
        (REKEY_TARGET_COMMIT, CONTINUITY_CHECKPOINT_COMMIT,
         "baseline is not an ancestor of checkpoint"),
        (CONTINUITY_CHECKPOINT_COMMIT, "HEAD",
         "continuity checkpoint is not an ancestor of HEAD"),
    ):
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_migration_git_environment(),
        )
        if result.returncode != 0:
            raise MigrationHarnessError(label)

    commits = _migration_git(
        root,
        ["rev-list", "--first-parent", "--reverse",
         f"{REKEY_TARGET_COMMIT}..{CONTINUITY_CHECKPOINT_COMMIT}"],
    ).splitlines()
    if len(commits) != CONTINUITY_FIRST_PARENT_COMMIT_COUNT:
        raise MigrationHarnessError(
            "continuity first-parent history length mismatch: "
            f"expected {CONTINUITY_FIRST_PARENT_COMMIT_COUNT}, got {len(commits)}"
        )
    if not commits or commits[0] != CONTINUITY_FIRST_COMMIT:
        raise MigrationHarnessError(
            f"continuity first commit mismatch: {commits[0] if commits else None}"
        )
    previous = REKEY_TARGET_COMMIT
    for commit in commits:
        first_parent = _migration_git(root, ["rev-parse", f"{commit}^1"]).strip()
        if first_parent != previous:
            raise MigrationHarnessError(
                f"continuity first-parent discontinuity at {commit}: "
                f"expected {previous}, got {first_parent}"
            )
        previous = commit
    if previous != CONTINUITY_CHECKPOINT_COMMIT:
        raise MigrationHarnessError(
            f"continuity replay ended at {previous}, not {CONTINUITY_CHECKPOINT_COMMIT}"
        )

    head_src = _migration_git(root, ["rev-parse", "HEAD:src"]).strip()
    if head_src != CONTINUITY_CHECKPOINT_SRC_TREE:
        raise MigrationHarnessError(
            f"HEAD src tree mismatch: expected {CONTINUITY_CHECKPOINT_SRC_TREE}, got {head_src}"
        )
    dirty_src = _migration_git(
        root, ["status", "--porcelain=v1", "--untracked-files=all", "--", "src"]
    ).strip()
    if dirty_src:
        raise MigrationHarnessError(f"checkpoint src worktree is dirty:\n{dirty_src}")

    migration_path = root / "docs/alignment_audit/FUNCTION_ID_MIGRATION.json"
    if not migration_path.is_file():
        raise MigrationHarnessError("baseline migration is missing from the worktree")
    migration_blob = _migration_git(root, ["hash-object", str(migration_path)]).strip()
    migration_sha = sha256_file(migration_path)
    if migration_blob != CONTINUITY_BASELINE_MIGRATION_BLOB:
        raise MigrationHarnessError(
            "worktree baseline migration blob mismatch: expected "
            f"{CONTINUITY_BASELINE_MIGRATION_BLOB}, got {migration_blob}"
        )
    if migration_sha != CONTINUITY_BASELINE_MIGRATION_SHA256:
        raise MigrationHarnessError(
            "worktree baseline migration sha256 mismatch: expected "
            f"{CONTINUITY_BASELINE_MIGRATION_SHA256}, got {migration_sha}"
        )
    try:
        baseline_migration = json.loads(migration_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise MigrationHarnessError(f"baseline migration JSON is malformed: {error}") from error
    if not isinstance(baseline_migration, dict) or baseline_migration.get("schema") != 2:
        raise MigrationHarnessError("baseline migration must remain reconciled schema 2")
    target = baseline_migration.get("target")
    expected_target = {
        "commit": REKEY_TARGET_COMMIT,
        "commit_tree": REKEY_TARGET_COMMIT_TREE,
        "src_tree": REKEY_TARGET_SRC_TREE,
        "ledger_blob": REKEY_TARGET_LEDGER_BLOB,
    }
    if not isinstance(target, dict) or any(target.get(k) != v for k, v in expected_target.items()):
        raise MigrationHarnessError("baseline migration target pins drifted")

    baseline_ledger = _migration_json_from_git(
        root, REKEY_TARGET_COMMIT, "docs/alignment_audit/FUNCTION_LEDGER.json"
    )
    current_ledger = _load_worktree_ledger(root)
    baseline_rust = _scan_rust_revision(root, REKEY_TARGET_COMMIT)
    pinned_baseline = list(baseline_ledger.get("rugra_functions", []))
    if sorted(_identity_projection(row) for row in baseline_rust) != sorted(
        _identity_projection(row) for row in pinned_baseline
    ):
        raise MigrationHarnessError("fresh baseline Rust scan does not reproduce pinned ledger")
    if len(baseline_rust) != CONTINUITY_BASELINE_RUST_RECORDS:
        raise MigrationHarnessError(
            f"baseline Rust record count mismatch: {len(baseline_rust)}"
        )
    fresh_current = _fresh_target_rust(root, current_ledger)
    if len(fresh_current) != CONTINUITY_CHECKPOINT_RUST_RECORDS:
        raise MigrationHarnessError(
            f"checkpoint Rust record count mismatch: {len(fresh_current)}"
        )
    if verify_locked_oracle:
        _verify_locked_oracle_for_continuity(root)
    return commits, baseline_ledger, current_ledger, fresh_current


def continuity_transition_evidence(
    old: dict[str, object],
    new: dict[str, object],
    hunks: list[tuple[int, int, int, int]],
) -> list[str]:
    old_signature = str(old.get("signature") or "")
    new_signature = str(new.get("signature") or "")
    if old_signature == new_signature:
        return []
    if (rust_parameter_binding_mut_normalized_signature(old_signature)
            == rust_parameter_binding_mut_normalized_signature(new_signature)):
        kind = "parameter_binding_mut_only"
    elif (rust_trailing_comma_normalized_signature(old_signature)
            == rust_trailing_comma_normalized_signature(new_signature)):
        # A formatting-only separator change re-keys the raw ID because the
        # scheme-2 signature keeps the separator; the function itself did not
        # change, so the alias is proven without a reviewed rule.
        kind = "signature_trailing_comma_only"
    else:
        return []
    strict = strict_transition_evidence(old, new, hunks)
    # A post-baseline automatic transition is deliberately narrower than the
    # original historical reconciler: both structural pins are mandatory.
    if "same_patch_hunk" not in strict or "identical_nonempty_annotation" not in strict:
        return []
    return ["same_patch_hunk", "identical_nonempty_annotation", kind]


def _continuity_event(
    old: dict[str, object],
    new: dict[str, object],
    commit: str,
    parent_blob: str,
    child_blob: str,
    evidence: list[str],
) -> dict[str, object]:
    return {
        "from_id": old["id"],
        "to_id": new["id"],
        "commit": commit,
        "from_path": old["path"],
        "to_path": new["path"],
        "from_module": old["module"],
        "to_module": new["module"],
        "from_owner": old["owner"],
        "to_owner": new["owner"],
        "from_name": old["name"],
        "to_name": new["name"],
        "from_signature": old["signature"],
        "to_signature": new["signature"],
        "parent_blob": parent_blob,
        "child_blob": child_blob,
        "evidence": evidence,
    }


def _continuity_record_index(
    rows: Iterable[tuple[dict[str, object], str]], label: str
) -> dict[str, tuple[dict[str, object], str]]:
    result: dict[str, tuple[dict[str, object], str]] = {}
    for record, blob in rows:
        token = str(record["id"])
        if token in result:
            raise MigrationHarnessError(f"{label} contains colliding raw ID {token}")
        result[token] = (record, blob)
    return result


def function_id_continuity_document(
    root: Path, *, verify_locked_oracle: bool = True
) -> dict[str, object]:  # noqa: C901
    """Reconcile raw scheme-2 IDs from the immutable baseline to checkpoint."""

    commits, baseline_ledger, current_ledger, fresh_current = verify_continuity_boundary(
        root, verify_locked_oracle=verify_locked_oracle
    )
    baseline_records = list(baseline_ledger["rugra_functions"])
    current_ids = {str(record["id"]) for record in fresh_current}
    baseline_ids = {str(record["id"]) for record in baseline_records}
    if len(baseline_ids) != len(baseline_records):
        raise MigrationHarnessError("baseline ledger contains duplicate Rust IDs")

    states: dict[str, dict[str, object]] = {
        token: {
            "base_id": token,
            "current_id": token,
            "origin_kind": "baseline",
            "events": [],
            "status": "live",
        }
        for token in sorted(baseline_ids)
    }
    tracked = {token: token for token in sorted(baseline_ids)}
    introduced: dict[str, dict[str, object]] = {}
    tombstones: list[dict[str, object]] = []
    text_cache: dict[str, str] = {}
    scan_cache: dict[tuple[str, str], list[dict[str, object]]] = {}
    hunk_cache: dict[tuple[str, str], list[tuple[int, int, int, int]]] = {}
    reviewed_by_commit: dict[str, list[dict[str, str]]] = defaultdict(list)
    for rule in CONTINUITY_REVIEWED_TRANSITIONS:
        reviewed_by_commit[rule["commit"]].append(rule)
    reviewed_keys = [
        (rule.get("base_id"), rule.get("from_id"), rule.get("commit"))
        for rule in CONTINUITY_REVIEWED_TRANSITIONS
    ]
    if len(reviewed_keys) != len(set(reviewed_keys)):
        raise MigrationHarnessError("reviewed continuity transition allowlist has duplicates")
    tombstone_rows = [
        ((rule.get("base_id"), rule.get("from_id"), rule.get("commit")), rule)
        for rule in CONTINUITY_REVIEWED_TOMBSTONES
    ]
    if len(tombstone_rows) != len({key for key, _ in tombstone_rows}):
        raise MigrationHarnessError("reviewed continuity tombstone allowlist has duplicates")
    tombstone_by_key = dict(tombstone_rows)
    ephemeral_rows = [
        ((rule.get("base_id"), rule.get("from_id"), rule.get("commit")), rule)
        for rule in CONTINUITY_REVIEWED_EPHEMERAL
    ]
    if len(ephemeral_rows) != len({key for key, _ in ephemeral_rows}):
        raise MigrationHarnessError("reviewed continuity ephemeral allowlist has duplicates")
    ephemeral_by_key = dict(ephemeral_rows)
    used_reviewed: set[tuple[str, str, str]] = set()
    used_tombstones: set[tuple[str, str, str]] = set()
    used_ephemeral: set[tuple[str, str, str]] = set()
    historical_owner_by_token = {token: token for token in baseline_ids}

    def claim_historical_token(token: str, base_id: str, role: str) -> None:
        previous_owner = historical_owner_by_token.get(token)
        if previous_owner is not None and previous_owner != base_id:
            raise MigrationHarnessError(
                f"continuity historical token collision for {token} ({role}): "
                f"{previous_owner}, {base_id}"
            )
        historical_owner_by_token[token] = base_id

    previous = REKEY_TARGET_COMMIT
    for commit in commits:
        changes = _rust_changes(root, previous, commit)
        before_rows: list[tuple[dict[str, object], str]] = []
        after_rows: list[tuple[dict[str, object], str]] = []
        parent_blob_by_path: dict[str, str] = {}
        child_blob_by_path: dict[str, str] = {}
        for change in changes:
            old_path, new_path = change["old_path"], change["new_path"]
            old_blob, new_blob = change["old_blob"], change["new_blob"]
            if old_path.endswith(".rs"):
                parent_blob_by_path[old_path] = old_blob
                before_rows.extend(
                    (record, old_blob) for record in _scan_rekey_blob(
                        root, old_path, old_blob, text_cache, scan_cache
                    )
                )
            if new_path.endswith(".rs"):
                child_blob_by_path[new_path] = new_blob
                after_rows.extend(
                    (record, new_blob) for record in _scan_rekey_blob(
                        root, new_path, new_blob, text_cache, scan_cache
                    )
                )
        before = _continuity_record_index(before_rows, f"{commit} parent")
        after = _continuity_record_index(after_rows, f"{commit} child")
        for token in sorted(set(before).intersection(after)):
            old_record, new_record = before[token][0], after[token][0]
            identity_fields = (
                "path", "module", "owner", "name", "signature", "is_test",
                "is_declaration",
            )
            if any(old_record.get(field) != new_record.get(field) for field in identity_fields):
                raise MigrationHarnessError(
                    f"same raw ID masks a changed identity at {commit}: {token}"
                )
        removed = {
            token: before[token]
            for token in sorted(set(tracked).intersection(before).difference(after))
        }
        newly_added = {
            token: after[token]
            for token in sorted(set(after).difference(before))
        }
        for token in newly_added:
            if token in tracked and token not in removed:
                raise MigrationHarnessError(
                    f"new raw ID collides with an unchanged live function at {commit}: {token}"
                )
        claimed_targets: set[str] = set()
        transitioned_sources: set[str] = set()

        for rule in reviewed_by_commit.get(commit, []):
            required = (
                "base_id", "from_id", "to_id", "commit", "from_path", "to_path",
                "parent_blob", "child_blob", "review",
            )
            if any(not rule.get(field) for field in required):
                raise MigrationHarnessError(f"malformed reviewed continuity rule at {commit}")
            source_token, target_token = rule["from_id"], rule["to_id"]
            base_id = tracked.get(source_token)
            if base_id != rule["base_id"] or source_token not in removed:
                raise MigrationHarnessError(
                    f"reviewed continuity source is not the unique live removal: {source_token}"
                )
            if target_token not in newly_added or target_token in claimed_targets:
                raise MigrationHarnessError(
                    f"reviewed continuity target is not a unique new function: {target_token}"
                )
            old_record, parent_blob = removed[source_token]
            new_record, child_blob = newly_added[target_token]
            pins = {
                "from_path": old_record["path"], "to_path": new_record["path"],
                "parent_blob": parent_blob, "child_blob": child_blob,
            }
            if any(str(rule[field]) != str(value) for field, value in pins.items()):
                raise MigrationHarnessError(
                    f"reviewed continuity path/blob pin mismatch for {source_token}"
                )
            event = _continuity_event(
                old_record, new_record, commit, parent_blob, child_blob,
                ["reviewed_successor_allowlist", str(rule["review"])],
            )
            states[base_id]["events"].append(event)
            states[base_id]["current_id"] = target_token
            del tracked[source_token]
            tracked[target_token] = base_id
            claim_historical_token(target_token, base_id, "reviewed target")
            transitioned_sources.add(source_token)
            claimed_targets.add(target_token)
            used_reviewed.add((base_id, source_token, commit))

        removed_groups: dict[tuple[object, ...], list[str]] = defaultdict(list)
        added_groups: dict[tuple[object, ...], list[str]] = defaultdict(list)
        for token, (record, _) in removed.items():
            if token not in transitioned_sources:
                removed_groups[(record["path"], record["module"], record["owner"], record["name"])].append(token)
        for token, (record, _) in newly_added.items():
            if token not in claimed_targets:
                added_groups[(record["path"], record["module"], record["owner"], record["name"])].append(token)

        for key in sorted(removed_groups, key=lambda value: tuple(str(part) for part in value)):
            old_tokens = sorted(removed_groups[key])
            new_tokens = sorted(added_groups.get(key, []))
            if not new_tokens:
                continue
            if len(old_tokens) != 1 or len(new_tokens) != 1:
                raise MigrationHarnessError(
                    f"ambiguous continuity transition at {commit} for {key}: "
                    f"removed={old_tokens} added={new_tokens}"
                )
            source_token, target_token = old_tokens[0], new_tokens[0]
            old_record, parent_blob = removed[source_token]
            new_record, child_blob = newly_added[target_token]
            hunks = _diff_hunks(root, previous, commit, str(old_record["path"]), hunk_cache)
            evidence = continuity_transition_evidence(old_record, new_record, hunks)
            if not evidence:
                continue
            if target_token in tracked or target_token in claimed_targets:
                raise MigrationHarnessError(
                    f"continuity transition target collision at {commit}: {target_token}"
                )
            base_id = tracked[source_token]
            states[base_id]["events"].append(
                _continuity_event(
                    old_record, new_record, commit, parent_blob, child_blob, evidence
                )
            )
            states[base_id]["current_id"] = target_token
            del tracked[source_token]
            tracked[target_token] = base_id
            claim_historical_token(target_token, base_id, "automatic target")
            transitioned_sources.add(source_token)
            claimed_targets.add(target_token)

        for source_token in sorted(set(removed).difference(transitioned_sources)):
            old_record, parent_blob = removed[source_token]
            base_id = tracked[source_token]
            rule_key = (base_id, source_token, commit)
            rule = tombstone_by_key.get(rule_key)
            ephemeral_rule = ephemeral_by_key.get(rule_key)
            if rule is None and ephemeral_rule is not None:
                # Schema 1 cannot encode a class introduced and deleted entirely
                # inside the window (its introduced_live terminal must be current
                # while its tombstone origin must predate the checkpoint).  Such a
                # class was never pinned in any ledger, so the exact reviewed
                # allowlist retires it from the replay instead of emitting a row.
                if states[base_id]["origin_kind"] != "introduced_live":
                    raise MigrationHarnessError(
                        "reviewed continuity ephemeral rule must target an "
                        f"introduced-live class: {base_id}"
                    )
                child_blob = child_blob_by_path.get(str(old_record["path"]))
                required = ("parent_blob", "child_blob")
                if (child_blob is None
                        or any(not ephemeral_rule.get(field) for field in required)
                        or ephemeral_rule["parent_blob"] != parent_blob
                        or ephemeral_rule["child_blob"] != child_blob):
                    raise MigrationHarnessError(
                        f"reviewed continuity ephemeral blob pins mismatch for {base_id}"
                    )
                del states[base_id]
                introduced.pop(base_id, None)
                del tracked[source_token]
                used_ephemeral.add(rule_key)
                continue
            if rule is None:
                raise MigrationHarnessError(
                    "unproved post-baseline removal requires an exact reviewed transition "
                    f"or tombstone: {base_id} {source_token} at {commit} "
                    f"({old_record['path']}::{old_record['name']})"
                )
            if states[base_id]["origin_kind"] != "baseline":
                raise MigrationHarnessError(
                    "continuity schema 1 cannot encode a post-baseline introduced origin "
                    f"that is later tombstoned: {base_id}; require a reviewed schema extension"
                )
            child_blob = child_blob_by_path.get(str(old_record["path"]))
            required = ("parent_blob", "child_blob", "reason")
            if (child_blob is None or any(not rule.get(field) for field in required)
                    or rule["parent_blob"] != parent_blob or rule["child_blob"] != child_blob):
                raise MigrationHarnessError(
                    f"reviewed continuity tombstone blob pins mismatch for {base_id}"
                )
            aliases = [str(event["from_id"]) for event in states[base_id]["events"]]
            if source_token not in aliases:
                aliases.append(source_token)
            tombstones.append({
                "base_id": base_id,
                "aliases": aliases,
                "path": old_record["path"],
                "module": old_record["module"],
                "owner": old_record["owner"],
                "name": old_record["name"],
                "signature": old_record["signature"],
                "deleted_at_commit": commit,
                "parent_blob": parent_blob,
                "child_blob": child_blob,
                "reason": rule["reason"],
                "events": list(states[base_id]["events"]),
            })
            states[base_id]["status"] = "tombstone"
            states[base_id]["current_id"] = None
            del tracked[source_token]
            used_tombstones.add(rule_key)

        for token in sorted(set(newly_added).difference(claimed_targets)):
            if token in tracked or token in states:
                raise MigrationHarnessError(
                    f"introduced raw ID collides with an existing continuity class: {token}"
                )
            record, child_blob = newly_added[token]
            row = {
                "base_id": token,
                "new_id": token,
                "introduced_at_commit": commit,
                "path": record["path"],
                "module": record["module"],
                "owner": record["owner"],
                "name": record["name"],
                "signature": record["signature"],
                "parent_blob": parent_blob_by_path.get(str(record["path"]), "0" * 40),
                "child_blob": child_blob,
            }
            introduced[token] = row
            states[token] = {
                "base_id": token,
                "current_id": token,
                "origin_kind": "introduced_live",
                "events": [],
                "status": "live",
            }
            tracked[token] = token
            claim_historical_token(token, token, "introduced live")
        previous = commit

    expected_reviewed = {
        (rule["base_id"], rule["from_id"], rule["commit"])
        for rule in CONTINUITY_REVIEWED_TRANSITIONS
    }
    if used_reviewed != expected_reviewed:
        raise MigrationHarnessError("reviewed continuity transition coverage mismatch")
    if used_tombstones != set(tombstone_by_key):
        raise MigrationHarnessError("reviewed continuity tombstone coverage mismatch")
    if used_ephemeral != set(ephemeral_by_key):
        raise MigrationHarnessError(
            "reviewed continuity ephemeral coverage mismatch: "
            f"missing={sorted(set(ephemeral_by_key)-used_ephemeral)} "
            f"extra={sorted(used_ephemeral-set(ephemeral_by_key))}"
        )
    if set(tracked) != current_ids:
        raise MigrationHarnessError(
            "continuity replay does not equal current ledger IDs: "
            f"missing={sorted(current_ids-set(tracked))[:3]} "
            f"extra={sorted(set(tracked)-current_ids)[:3]}"
        )

    lineages = []
    for base_id in sorted(states):
        state = states[base_id]
        events = list(state["events"])
        if state["status"] != "live" or not events:
            continue
        aliases = [str(event["from_id"]) for event in events]
        lineages.append({
            "base_id": base_id,
            "new_id": state["current_id"],
            "origin_kind": state["origin_kind"],
            "aliases": aliases,
            "events": events,
        })
    transitions = {
        (str(row["base_id"]), str(row["new_id"])) for row in lineages
    }
    if transitions != CONTINUITY_EXPECTED_TRANSITIONS:
        raise MigrationHarnessError(
            f"unexpected checkpoint continuity transitions: {sorted(transitions)}"
        )
    live_introduced = {
        token: row for token, row in introduced.items()
        if states[token]["status"] == "live"
    }
    if set(live_introduced) != CONTINUITY_EXPECTED_INTRODUCED:
        raise MigrationHarnessError(
            f"unexpected introduced-live functions: {sorted(live_introduced)}"
        )
    tombstone_keys = {
        (str(row["base_id"]), str(row["aliases"][-1]), str(row["deleted_at_commit"]))
        for row in tombstones
    }
    if tombstone_keys != CONTINUITY_EXPECTED_TOMBSTONES:
        raise MigrationHarnessError(
            f"unexpected checkpoint continuity tombstones: {sorted(tombstone_keys)}"
        )
    for token, row in live_introduced.items():
        row["new_id"] = states[token]["current_id"]

    baseline_bytes = _migration_git(
        root, ["show", f"{REKEY_TARGET_COMMIT}:docs/alignment_audit/FUNCTION_LEDGER.json"]
    ).encode("utf-8")
    current_projection_sha = rust_identity_projection_sha256(fresh_current)
    baseline_projection_sha = rust_identity_projection_sha256(baseline_records)
    return {
        "schema": 1,
        "oracle_commit": ORACLE_COMMIT,
        "id_scheme": ID_SCHEME,
        "baseline": {
            "commit": REKEY_TARGET_COMMIT,
            "commit_tree": REKEY_TARGET_COMMIT_TREE,
            "src_tree": REKEY_TARGET_SRC_TREE,
            "ledger_blob": REKEY_TARGET_LEDGER_BLOB,
            "ledger_sha256": hashlib.sha256(baseline_bytes).hexdigest(),
            "rust_projection_sha256": baseline_projection_sha,
            "rust_function_records": len(baseline_records),
            "migration_blob_at_checkpoint": CONTINUITY_BASELINE_MIGRATION_BLOB,
            "migration_sha256": CONTINUITY_BASELINE_MIGRATION_SHA256,
        },
        "checkpoint": {
            "commit": CONTINUITY_CHECKPOINT_COMMIT,
            "commit_tree": CONTINUITY_CHECKPOINT_COMMIT_TREE,
            "src_tree": CONTINUITY_CHECKPOINT_SRC_TREE,
            "rust_projection_sha256": current_projection_sha,
            "rust_function_records": len(fresh_current),
        },
        "history": {
            "mode": "first_parent",
            "commit_count": len(commits),
            "first_commit": commits[0],
            "last_commit": commits[-1],
        },
        "semantics": (
            "Raw scheme-2 IDs remain stable_id(module, owner, normalized_signature). "
            "This separate post-baseline layer composes historical aliases to the raw "
            "checkpoint IDs. Automatic transitions require a unique 1-to-1, same "
            "path/module/owner/name pair whose only signature difference is either a "
            "leading parameter binding mut or the trailing parameter separator, in the "
            "same patch hunk with the same non-empty annotation. Tombstones are "
            "diagnostic only; introduced_live rows are new checkpoint definitions, not "
            "fabricated historical origins."
        ),
        "stats": {
            "baseline_records": len(baseline_records),
            "current_records": len(fresh_current),
            "introduced_live": len(live_introduced),
            "lineages": len(lineages),
            "events": sum(len(row["events"]) for row in lineages),
            "tombstones": len(tombstones),
            "alias_tokens": sum(len(row["aliases"]) for row in lineages),
            "reviewed_transitions": len(used_reviewed),
            "ambiguous": 0,
            "collisions": 0,
        },
        "lineages": lineages,
        "introduced_live": [live_introduced[token] for token in sorted(live_introduced)],
        "tombstones": sorted(tombstones, key=lambda row: str(row["base_id"])),
    }


def validate_reviewed_transition(
    rule: dict[str, str],
    tracked: dict[str, str],
    removed: dict[str, tuple[dict[str, object], str]],
    newly_added: dict[str, tuple[dict[str, object], str]],
    claimed_targets: set[str],
) -> tuple[str, dict[str, object], str, dict[str, object], str]:
    """Validate an exact reviewed transition; name-only lookup is forbidden."""

    source_token, target_token = rule["from_id"], rule["to_id"]
    legacy = tracked.get(source_token)
    if legacy != rule["legacy_id"] or source_token not in removed:
        raise MigrationHarnessError(
            f"reviewed transition source is not the unique live removal at {rule['commit']}: "
            f"{rule['legacy_id']} {source_token}"
        )
    # Requiring membership in newly_added rejects wrapper/deletion rows that
    # attempt to point at a function which already existed before the commit.
    if target_token not in newly_added:
        raise MigrationHarnessError(
            f"reviewed transition target is not newly added at {rule['commit']}: {target_token}"
        )
    if target_token in tracked or target_token in claimed_targets:
        raise MigrationHarnessError(f"reviewed transition target collision: {target_token}")
    old_record, parent_blob = removed[source_token]
    new_record, child_blob = newly_added[target_token]
    if not parent_blob.startswith(rule["parent_blob_prefix"]):
        raise MigrationHarnessError(
            f"reviewed parent blob mismatch for {source_token}: {parent_blob}"
        )
    if not child_blob.startswith(rule["child_blob_prefix"]):
        raise MigrationHarnessError(
            f"reviewed child blob mismatch for {target_token}: {child_blob}"
        )
    if rule["kind"] == "same_name":
        old_key = (
            old_record["path"], old_record["module"], old_record["owner"], old_record["name"]
        )
        new_key = (
            new_record["path"], new_record["module"], new_record["owner"], new_record["name"]
        )
        if old_key != new_key:
            raise MigrationHarnessError(
                f"reviewed same-name record shape drift for {rule['label']}: {old_key} != {new_key}"
            )
    return legacy, old_record, parent_blob, new_record, child_blob


def _tombstone_record(
    state: dict[str, object],
    old: dict[str, object],
    commit: str,
    parent_blob: str,
    child_blob: str,
) -> dict[str, object]:
    aliases = [str(event["from_id"]) for event in state["lineage"]]
    aliases.append(str(old["id"]))
    aliases = list(dict.fromkeys(aliases))
    result: dict[str, object] = {
        "old_id": state["legacy_id"],
        "aliases": aliases,
        "deleted_id": old["id"],
        "path": old["path"],
        "module": old["module"],
        "owner": old["owner"],
        "name": old["name"],
        "signature": old["signature"],
        "line": old["line"],
        "end_line": old["end_line"],
        "is_test": old["is_test"],
        "is_declaration": old["is_declaration"],
        "annotation_kind": old["_annotation_kind"],
        "annotation": old["_annotation_value"],
        "deleted_at_commit": commit,
        "parent_blob": parent_blob,
        "child_blob": child_blob,
        "reason": "deleted_without_reviewed_successor",
    }
    if state["lineage"]:
        result["lineage"] = list(state["lineage"])
    return result


def _validate_reconciled_classes(
    entries: list[dict[str, object]],
    tombstones: list[dict[str, object]],
    target_ids: set[str],
    *,
    expected_origin_count: int = REKEY_ORIGIN_COUNT,
    expected_live_count: int = REKEY_LIVE_ORIGIN_COUNT,
    expected_tombstone_count: int = REKEY_TOMBSTONE_COUNT,
    expected_alias_count: int = REKEY_ALIAS_TOKEN_COUNT,
) -> dict[str, int]:
    if len(entries) != expected_live_count:
        raise MigrationHarnessError(
            f"live origin count mismatch: expected {expected_live_count}, got {len(entries)}"
        )
    if len(tombstones) != expected_tombstone_count:
        raise MigrationHarnessError(
            f"tombstone count mismatch: expected {expected_tombstone_count}, got {len(tombstones)}"
        )
    owner_by_token: dict[str, str] = {}
    final_by_origin: dict[str, str] = {}
    alias_count = 0

    def claim(token: object, origin: str, role: str) -> None:
        token_pattern = (
            r"(?:RG-F-[0-9a-f]{20}|GH12-F-[0-9a-f]{20}(?:-\d{2})?)"
            if "old_id" in role
            else r"(?:RG-F|GH12-F)-[0-9a-f]{20}"
        )
        if not isinstance(token, str) or not re.fullmatch(token_pattern, token):
            raise MigrationHarnessError(f"malformed {role} token in origin {origin}: {token!r}")
        previous = owner_by_token.get(token)
        if previous is not None and previous != origin:
            raise MigrationHarnessError(
                f"function token {token} belongs to two origin classes: {previous}, {origin}"
            )
        owner_by_token[token] = origin

    for entry in entries:
        origin = str(entry.get("old_id"))
        target = str(entry.get("new_id"))
        claim(origin, origin, "old_id")
        claim(target, origin, "new_id")
        if target not in target_ids:
            raise MigrationHarnessError(f"live target {target} for {origin} is absent from target ledger")
        if target in final_by_origin and final_by_origin[target] != origin:
            raise MigrationHarnessError(
                f"two origins converge on target {target}: {final_by_origin[target]}, {origin}"
            )
        final_by_origin[target] = origin
        aliases = entry.get("aliases", [])
        if not isinstance(aliases, list):
            raise MigrationHarnessError(f"aliases for {origin} are not an array")
        if len(aliases) != len(set(aliases)):
            raise MigrationHarnessError(f"origin {origin} repeats an alias token")
        for alias in aliases:
            if alias == target:
                raise MigrationHarnessError(f"alias {alias} equals its live final target for {origin}")
            if alias in target_ids:
                raise MigrationHarnessError(
                    f"alias {alias} for {origin} is an unrelated current-ledger function id"
                )
            claim(alias, origin, "alias")
            alias_count += 1

    for tombstone in tombstones:
        origin = str(tombstone.get("old_id"))
        claim(origin, origin, "tombstone old_id")
        aliases = tombstone.get("aliases")
        required = (
            "path", "module", "owner", "name", "signature", "deleted_at_commit",
            "parent_blob", "child_blob", "reason",
        )
        if not isinstance(aliases, list) or not aliases or any(not tombstone.get(k) for k in required):
            raise MigrationHarnessError(f"tombstone {origin} is missing aliases/commit/blob/signature metadata")
        if len(aliases) != len(set(aliases)):
            raise MigrationHarnessError(f"tombstone {origin} repeats an alias token")
        for field in ("deleted_at_commit", "parent_blob", "child_blob"):
            if not re.fullmatch(r"[0-9a-f]{40}", str(tombstone[field])):
                raise MigrationHarnessError(f"tombstone {origin} has malformed {field}")
        for alias in aliases:
            if alias in target_ids:
                raise MigrationHarnessError(
                    f"tombstone alias {alias} for {origin} is still in the target ledger"
                )
            claim(alias, origin, "tombstone alias")

    if len(entries) + len(tombstones) != expected_origin_count:
        raise MigrationHarnessError("live/tombstone classes do not cover every source origin")
    if alias_count != expected_alias_count:
        raise MigrationHarnessError(
            f"live alias token count mismatch: expected {expected_alias_count}, got {alias_count}"
        )
    return {
        "origin_entries": len(entries),
        "tombstones": len(tombstones),
        "alias_tokens": alias_count,
        "class_tokens": len(owner_by_token),
    }


def migration_reconciliation_document(root: Path) -> dict[str, object]:  # noqa: C901
    commits = verify_rekey_boundary(root)
    source_ledger = _migration_json_from_git(
        root, REKEY_SOURCE_COMMIT, "docs/alignment_audit/FUNCTION_LEDGER.json"
    )
    target_ledger = _migration_json_from_git(
        root, REKEY_TARGET_COMMIT, "docs/alignment_audit/FUNCTION_LEDGER.json"
    )
    source_migration = _migration_json_from_git(
        root, REKEY_TARGET_COMMIT, "docs/alignment_audit/FUNCTION_ID_MIGRATION.json"
    )
    source_entries, target_ids, source_rust_by_legacy = _validate_rekey_source_tables(
        source_ledger, target_ledger, source_migration
    )
    fresh_rust = _fresh_target_rust(root, target_ledger)
    fresh_ids = {str(record["id"]) for record in fresh_rust}
    pinned_rust_ids = {
        str(record["id"]) for record in target_ledger["rugra_functions"]
    }
    if fresh_ids != pinned_rust_ids:
        raise MigrationHarnessError("fresh target Rust ID set differs from the pinned ledger")

    gap_rows = [entry for entry in source_entries if entry.get("new_id") not in target_ids]
    if len(gap_rows) != REKEY_GAP_COUNT or any(entry.get("language") != "rust" for entry in gap_rows):
        raise MigrationHarnessError(
            f"source rekey gap mismatch: expected {REKEY_GAP_COUNT} Rust rows, got {len(gap_rows)}"
        )
    original_by_legacy = {str(entry["old_id"]): entry for entry in source_entries}
    original_base_ids = {str(entry["new_id"]) for entry in source_entries}
    if len(original_by_legacy) != len(source_entries) or len(original_base_ids) != len(source_entries):
        raise MigrationHarnessError("source migration origin/base IDs are not one-to-one")

    text_cache: dict[str, str] = {}
    scan_cache: dict[tuple[str, str], list[dict[str, object]]] = {}
    source_path_blobs: dict[str, str] = {}
    source_records_by_id: dict[str, dict[str, object]] = {}
    for row in gap_rows:
        legacy = str(row["old_id"])
        old_record = source_rust_by_legacy.get(legacy)
        if old_record is None:
            raise MigrationHarnessError(f"gap origin {legacy} is absent from source ledger")
        path = str(old_record.get("path"))
        if path not in source_path_blobs:
            source_path_blobs[path] = _migration_git(
                root, ["rev-parse", f"{REKEY_SOURCE_COMMIT}:{path}"]
            ).strip()
            for record in _scan_rekey_blob(
                root, path, source_path_blobs[path], text_cache, scan_cache
            ):
                source_records_by_id[str(record["id"])] = record
        base = str(row["new_id"])
        base_record = source_records_by_id.get(base)
        if base_record is None:
            raise MigrationHarnessError(f"gap base {base} is absent from pinned source scan")
        positional = (base_record["path"], base_record["line"], base_record["name"])
        expected = (old_record.get("path"), old_record.get("line"), old_record.get("name"))
        if positional != expected:
            raise MigrationHarnessError(
                f"source legacy/base positional proof failed for {legacy}: {expected} != {positional}"
            )

    states: dict[str, dict[str, object]] = {
        str(row["old_id"]): {
            "legacy_id": str(row["old_id"]),
            "base_id": str(row["new_id"]),
            "current_id": str(row["new_id"]),
            "lineage": [],
            "status": "live",
        }
        for row in gap_rows
    }
    tracked: dict[str, str] = {
        str(row["new_id"]): str(row["old_id"]) for row in gap_rows
    }
    reviewed_by_commit: dict[str, list[dict[str, str]]] = defaultdict(list)
    for rule in REKEY_REVIEWED_TRANSITIONS:
        reviewed_by_commit[rule["commit"]].append(rule)
        source = original_by_legacy.get(rule["legacy_id"])
        if source is None or source.get("new_id") != rule["from_id"]:
            raise MigrationHarnessError(
                f"reviewed transition source pin mismatch for {rule['legacy_id']}"
            )
        if rule["kind"] == "successor" and rule["to_id"] in original_base_ids:
            raise MigrationHarnessError(
                f"reviewed successor {rule['to_id']} already has a source migration predecessor"
            )
    tombstone_by_key = {
        (rule["legacy_id"], rule["base_id"], rule["commit"]): rule
        for rule in REKEY_REVIEWED_TOMBSTONES
    }
    if len(tombstone_by_key) != REKEY_TOMBSTONE_COUNT:
        raise MigrationHarnessError("reviewed tombstone allowlist contains duplicate keys")

    used_reviewed: set[tuple[str, str]] = set()
    used_tombstones: set[tuple[str, str, str]] = set()
    tombstones: list[dict[str, object]] = []
    automatic_events = 0
    automatic_origins: set[str] = set()
    reviewed_counts: Counter[str] = Counter()
    hunk_cache: dict[tuple[str, str], list[tuple[int, int, int, int]]] = {}

    previous = REKEY_SOURCE_COMMIT
    for commit in commits:
        changes = _rust_changes(root, previous, commit)
        before: dict[str, tuple[dict[str, object], str]] = {}
        after: dict[str, tuple[dict[str, object], str]] = {}
        child_blob_by_path: dict[str, str] = {}
        for change in changes:
            old_path, new_path = change["old_path"], change["new_path"]
            old_blob, new_blob = change["old_blob"], change["new_blob"]
            if old_path.endswith(".rs"):
                for record in _scan_rekey_blob(root, old_path, old_blob, text_cache, scan_cache):
                    before[str(record["id"])] = (record, old_blob)
            if new_path.endswith(".rs"):
                child_blob_by_path[new_path] = new_blob
                for record in _scan_rekey_blob(root, new_path, new_blob, text_cache, scan_cache):
                    after[str(record["id"])] = (record, new_blob)

        removed = {
            token: before[token]
            for token in sorted(set(tracked).intersection(before).difference(after))
        }
        newly_added = {
            token: after[token]
            for token in sorted(set(after).difference(before))
        }
        claimed_targets: set[str] = set()

        for rule in reviewed_by_commit.get(commit, []):
            source_token, target_token = rule["from_id"], rule["to_id"]
            legacy, old_record, parent_blob, new_record, child_blob = (
                validate_reviewed_transition(
                    rule, tracked, removed, newly_added, claimed_targets
                )
            )
            event = _lineage_event(
                old_record,
                new_record,
                commit,
                parent_blob,
                child_blob,
                [f"reviewed_{rule['kind']}_allowlist", rule["label"]],
            )
            states[legacy]["lineage"].append(event)
            states[legacy]["current_id"] = target_token
            del tracked[source_token]
            tracked[target_token] = legacy
            removed.pop(source_token)
            claimed_targets.add(target_token)
            used_reviewed.add((rule["legacy_id"], commit))
            reviewed_counts[rule["kind"]] += 1

        removed_groups: dict[tuple[object, ...], list[str]] = defaultdict(list)
        added_groups: dict[tuple[object, ...], list[str]] = defaultdict(list)
        for token, (record, _) in removed.items():
            key = (record["path"], record["module"], record["owner"], record["name"])
            removed_groups[key].append(token)
        for token, (record, _) in newly_added.items():
            if token in claimed_targets:
                continue
            key = (record["path"], record["module"], record["owner"], record["name"])
            added_groups[key].append(token)

        transitioned: set[str] = set()
        for key in sorted(removed_groups, key=lambda value: tuple(str(part) for part in value)):
            old_tokens = sorted(removed_groups[key])
            new_tokens = sorted(added_groups.get(key, []))
            if not new_tokens:
                continue
            old_record_for_hunk = removed[old_tokens[0]][0]
            hunks = _diff_hunks(
                root, previous, commit, str(old_record_for_hunk["path"]), hunk_cache
            )
            selected = select_unique_strict_transition(
                commit, key, old_tokens, new_tokens, removed, newly_added, hunks
            )
            if selected is None:
                continue
            source_token, target_token, evidence = selected
            old_record, parent_blob = removed[source_token]
            new_record, child_blob = newly_added[target_token]
            legacy = tracked[source_token]
            if target_token in tracked or target_token in claimed_targets:
                raise MigrationHarnessError(
                    f"automatic transition target collision at {commit}: {target_token}"
                )
            event = _lineage_event(
                old_record, new_record, commit, parent_blob, child_blob, evidence
            )
            states[legacy]["lineage"].append(event)
            states[legacy]["current_id"] = target_token
            del tracked[source_token]
            tracked[target_token] = legacy
            claimed_targets.add(target_token)
            transitioned.add(source_token)
            automatic_events += 1
            automatic_origins.add(legacy)

        for source_token in sorted(set(removed).difference(transitioned)):
            old_record, parent_blob = removed[source_token]
            legacy = tracked[source_token]
            key = (legacy, source_token, commit)
            rule = tombstone_by_key.get(key)
            if rule is None:
                candidates = added_groups.get(
                    (old_record["path"], old_record["module"], old_record["owner"], old_record["name"]),
                    [],
                )
                raise MigrationHarnessError(
                    f"unproved removal is neither reviewed transition nor tombstone at {commit}: "
                    f"{legacy} {source_token} {old_record['path']}::{old_record['name']} "
                    f"same-key-added={sorted(candidates)}"
                )
            if rule["name"] != old_record["name"]:
                raise MigrationHarnessError(
                    f"reviewed tombstone name drift for {legacy}: "
                    f"expected {rule['name']}, got {old_record['name']}"
                )
            child_blob = child_blob_by_path.get(str(old_record["path"]))
            if child_blob is None or not re.fullmatch(r"[0-9a-f]{40}", child_blob):
                raise MigrationHarnessError(
                    f"cannot resolve tombstone child blob for {legacy} at {commit}"
                )
            tombstones.append(
                _tombstone_record(
                    states[legacy], old_record, commit, parent_blob, child_blob
                )
            )
            states[legacy]["current_id"] = None
            states[legacy]["status"] = "tombstone"
            del tracked[source_token]
            used_tombstones.add(key)
        previous = commit

    expected_reviewed = {
        (rule["legacy_id"], rule["commit"]) for rule in REKEY_REVIEWED_TRANSITIONS
    }
    if used_reviewed != expected_reviewed:
        raise MigrationHarnessError(
            f"reviewed transition coverage mismatch: missing={sorted(expected_reviewed-used_reviewed)} "
            f"extra={sorted(used_reviewed-expected_reviewed)}"
        )
    if used_tombstones != set(tombstone_by_key):
        raise MigrationHarnessError(
            f"reviewed tombstone coverage mismatch: missing={sorted(set(tombstone_by_key)-used_tombstones)}"
        )
    if automatic_events != REKEY_AUTO_EVENT_COUNT or len(automatic_origins) != REKEY_AUTO_LINEAGE_COUNT:
        raise MigrationHarnessError(
            "automatic history replay count mismatch: "
            f"events={automatic_events}/{REKEY_AUTO_EVENT_COUNT} "
            f"origins={len(automatic_origins)}/{REKEY_AUTO_LINEAGE_COUNT}"
        )
    if reviewed_counts != Counter(
        {"same_name": REKEY_REVIEWED_SAME_NAME_COUNT, "successor": REKEY_REVIEWED_SUCCESSOR_COUNT}
    ):
        raise MigrationHarnessError(f"reviewed transition counts mismatch: {dict(reviewed_counts)}")
    live_rekey = [state for state in states.values() if state["status"] == "live"]
    if len(live_rekey) != REKEY_LIVE_REKEY_LINEAGE_COUNT or len(tracked) != len(live_rekey):
        raise MigrationHarnessError(
            f"live rekey lineage mismatch: states={len(live_rekey)} tracked={len(tracked)}"
        )
    two_hop = sorted(
        state["legacy_id"] for state in live_rekey if len(state["lineage"]) == 2
    )
    expected_two_hop = sorted(
        (
            "RG-F-2d786ec5c86965bc0302",
            "RG-F-3c4065b2a0d827d950cc",
            "RG-F-aed699f2484f67f4d52d",
        )
    )
    if two_hop != expected_two_hop or any(len(state["lineage"]) not in (1, 2) for state in live_rekey):
        raise MigrationHarnessError(f"two-hop lineage set mismatch: {two_hop}")
    for token, legacy in tracked.items():
        if token not in target_ids or states[legacy]["current_id"] != token:
            raise MigrationHarnessError(f"live replay target is absent/inconsistent: {legacy} -> {token}")

    live_rows: list[dict[str, object]] = []
    for source in source_entries:
        legacy = str(source["old_id"])
        state = states.get(legacy)
        if state is not None and state["status"] == "tombstone":
            continue
        if state is None:
            live_rows.append(dict(source))
            continue
        lineage = list(state["lineage"])
        aliases = [str(event["from_id"]) for event in lineage]
        live_rows.append(
            {
                "old_id": legacy,
                "new_id": state["current_id"],
                "language": "rust",
                "reason": "rust_history_rekey",
                "aliases": aliases,
                "lineage": lineage,
            }
        )
    tombstones.sort(key=lambda item: str(item["old_id"]))
    class_stats = _validate_reconciled_classes(live_rows, tombstones, target_ids)

    source_ledger_bytes = _migration_git(
        root, ["show", f"{REKEY_SOURCE_COMMIT}:docs/alignment_audit/FUNCTION_LEDGER.json"]
    ).encode("utf-8")
    target_ledger_bytes = _migration_git(
        root, ["show", f"{REKEY_TARGET_COMMIT}:docs/alignment_audit/FUNCTION_LEDGER.json"]
    ).encode("utf-8")
    source_migration_bytes = _migration_git(
        root, ["show", f"{REKEY_TARGET_COMMIT}:docs/alignment_audit/FUNCTION_ID_MIGRATION.json"]
    ).encode("utf-8")
    return {
        "schema": 2,
        "oracle_commit": ORACLE_COMMIT,
        "id_scheme": source_migration["id_scheme"],
        "old_ledger": {
            "path": "docs/alignment_audit/FUNCTION_LEDGER.json",
            "tree_commit": REKEY_SOURCE_COMMIT,
            "tree_subject": _migration_git(
                root, ["show", "-s", "--format=%s", REKEY_SOURCE_COMMIT]
            ).strip(),
        },
        "source": {
            "commit": REKEY_SOURCE_COMMIT,
            "commit_tree": REKEY_SOURCE_COMMIT_TREE,
            "src_tree": REKEY_SOURCE_SRC_TREE,
            "ledger_blob": REKEY_SOURCE_LEDGER_BLOB,
            "ledger_sha256": hashlib.sha256(source_ledger_bytes).hexdigest(),
            "migration_blob": REKEY_SOURCE_MIGRATION_BLOB,
            "migration_sha256": hashlib.sha256(source_migration_bytes).hexdigest(),
        },
        "target": {
            "commit": REKEY_TARGET_COMMIT,
            "commit_tree": REKEY_TARGET_COMMIT_TREE,
            "src_tree": REKEY_TARGET_SRC_TREE,
            "ledger_blob": REKEY_TARGET_LEDGER_BLOB,
            "ledger_sha256": hashlib.sha256(target_ledger_bytes).hexdigest(),
        },
        "history": {
            "mode": "first_parent",
            "commit_count": len(commits),
            "first_commit": commits[0],
            "last_commit": commits[-1],
        },
        "semantics": (
            "Each source origin is reconciled by deterministic first-parent history replay. "
            "Automatic transitions require a unique same-file/module/owner/name pair plus "
            "same-hunk, identical non-empty annotation, or identical masked-body evidence. "
            "Reviewed exceptions are pinned by IDs, commit and blobs. Tombstones are diagnostic "
            "and are never automatic replacement targets."
        ),
        "stats": {
            **class_stats,
            "original_definitions": REKEY_ORIGIN_COUNT,
            "source_rekey_gaps": len(gap_rows),
            "live_rekey_lineages": len(live_rekey),
            "automatic_transition_events": automatic_events,
            "automatic_lineages": len(automatic_origins),
            "reviewed_same_name": reviewed_counts["same_name"],
            "reviewed_successors": reviewed_counts["successor"],
            "two_hop_lineages": len(two_hop),
            "ambiguous_old_ids": 0,
            "colliding_new_ids": 0,
        },
        "disambiguators": list(source_migration["disambiguators"]),
        "entries": live_rows,
        "tombstones": tombstones,
    }


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


def _ids_by_signature(records: list[dict[str, object]]) -> dict[str, str]:
    return {str(record["signature"]): str(record["id"]) for record in records}


def _git_state_fixture_ids(repo: Path, relative: str, revision_spec: str) -> dict[str, str]:
    text = command_output(["git", "show", revision_spec], repo)
    records = collect_rust_identities(relative, text, module_from_relative(relative))
    assign_rust_locked_ids(records)
    return _ids_by_signature(records)


def self_test() -> int:  # noqa: C901 - self-test is intentionally linear
    first = stable_id("X", ("a", 1, "b"))
    assert first == stable_id("X", ("a", 1, "b"))
    assert first != stable_id("X", ("a", 2, "b"))

    # Dependency extraction must use the named dependency column, preserve
    # code-span pipes, and ignore status/evidence tokens in a mixed cell.
    todo_fixture = """
| ID | write-set | 依赖 / 验收 / 证据 |
|---|---|---|
| `TASK-A-0001` | `left | right` | 依赖=`TASK-B-0001`；验收=`MATCH`；证据提及 `TASK-C-0001` |
| `TASK-B-0001` | none | 依赖=无；状态=`UNTESTED` |
| `TASK-C-0001` | none | 依赖=无 |
| `TASK-E-0001`（历史状态） | none | 依赖=无 |

| ID | 标题 | 依赖 |
|---|---|---|
| `TASK-D-0001` | pure dependency column | `TASK-A-0001`、`TASK-C-0001` |
"""
    todo_nodes, todo_edges = todo_dependency_inventory(todo_fixture)
    assert todo_nodes == {
        "TASK-A-0001",
        "TASK-B-0001",
        "TASK-C-0001",
        "TASK-D-0001",
        "TASK-E-0001",
    }
    assert todo_edges == {
        ("TASK-A-0001", "TASK-B-0001"),
        ("TASK-D-0001", "TASK-A-0001"),
        ("TASK-D-0001", "TASK-C-0001"),
    }
    assert not TODO_ID_RE.search("`MATCH` `MISMATCH` `NO_ORACLE` `UNTESTED`")

    try:
        todo_dependency_inventory(
            "| ID | 依赖 |\n|---|---|\n| `TASK-A-0001` | `TASK-Z-0001` |\n"
        )
    except ValueError as error:
        assert "no stable row" in str(error)
    else:
        raise AssertionError("undefined TODO dependencies must fail closed")

    try:
        todo_dependency_inventory(
            "| ID | 依赖 |\n|---|---|\n"
            "| `TASK-A-0001` | `TASK-B-0001` |\n"
            "| `TASK-B-0001` | `TASK-A-0001` |\n"
        )
    except ValueError as error:
        assert "dependency cycle" in str(error)
    else:
        raise AssertionError("cyclic TODO dependencies must fail closed")

    try:
        todo_dependency_inventory(
            "| ID | 依赖 |\n|---|---|\n| `TASK-A-0001` | `TASK-A-0001` |\n"
        )
    except ValueError as error:
        assert "TASK-A-0001 -> TASK-A-0001" in str(error)
    else:
        raise AssertionError("self-dependent TODOs must fail closed")

    rust_refs = "crate::real::module; // crate::comment::fake\n\"crate::literal::fake\";"
    masked_refs = [
        match.group("path")
        for match in RUST_CRATE_REF_RE.finditer(mask_non_code(rust_refs))
    ]
    assert masked_refs == ["real::module"], "comments and literals must not create Rust edges"

    # --- Ghidra guard-context disambiguation -------------------------------
    guarded = [
        "#define A 1",
        "void f(void) { A; }",
        "#ifdef _WIN32",
        "void f(void) { B; }",
        "#else",
        "void f(void) { C; }",
        "#endif",
    ]
    entries = [
        {"path": "x.cc", "file": "x.cc", "entry_kind": "definition", "signature": "void f(void)", "line": 2, "name": "f"},
        {"path": "x.cc", "file": "x.cc", "entry_kind": "definition", "signature": "void f(void)", "line": 4, "name": "f"},
        {"path": "x.cc", "file": "x.cc", "entry_kind": "definition", "signature": "void f(void)", "line": 6, "name": "f"},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        cpp = Path(tmp)
        (cpp / "x.cc").write_text("\n".join(guarded) + "\n", encoding="utf-8")
        disambiguated = assign_ghidra_locked_ids(entries, cpp)
        assert len({entry["id"] for entry in entries}) == 3, "guard contexts must separate duplicates"
        assert len(disambiguated) == 3
        assert {entry["id_disambiguator"]["value"] for entry in disambiguated} == {
            "",
            "defined(_WIN32)",
            "!(defined(_WIN32))",
        }
        # Inserting unrelated lines above must not change any ID: guards are
        # content-derived, and the unguarded entry keeps its plain signature ID.
        shifted = [entries[0]["id"], entries[1]["id"], entries[2]["id"]]
        padded = ["", "// new", "#define Z 9", *guarded]
        padded_entries = [
            {**entry, "line": entry["line"] + 3} for entry in entries
        ]
        (cpp / "x.cc").write_text("\n".join(padded) + "\n", encoding="utf-8")
        assign_ghidra_locked_ids(padded_entries, cpp)
        assert [entry["id"] for entry in padded_entries] == shifted, "IDs must survive line insertion"
        # Two indistinguishable entries with no guards must fail closed.
        twins = [
            {"path": "y.cc", "file": "y.cc", "entry_kind": "definition", "signature": "void g(void)", "line": 1, "name": "g"},
            {"path": "y.cc", "file": "y.cc", "entry_kind": "definition", "signature": "void g(void)", "line": 2, "name": "g"},
        ]
        (cpp / "y.cc").write_text("void g(void) {}\nvoid g(void) {}\n", encoding="utf-8")
        try:
            assign_ghidra_locked_ids(twins, cpp)
        except RuntimeError as error:
            assert "indistinguishable" in str(error)
        else:
            raise AssertionError("unguarded Ghidra duplicates must fail closed")

    # --- Rust identity extraction ------------------------------------------
    trait_fixture = r'''
pub struct Foo;
pub trait Display { fn fmt(&self); }
pub trait Debug { fn fmt(&self); }
impl Display for Foo { pub fn fmt(&self) { } }
impl Debug for Foo { pub fn fmt(&self) { } }
impl<'a> Iterator for &'a mut Foo {
    fn next(&mut self) -> Option<u32> { None }
}
'''
    records = collect_rust_identities("src/trait_fixture.rs", trait_fixture, "trait_fixture")
    assign_rust_locked_ids(records)
    fmt_records = [
        record
        for record in records
        if record["name"] == "fmt" and str(record["owner"]).startswith("impl:")
    ]
    assert {record["owner"] for record in fmt_records} == {
        "impl:Foo as Display",
        "impl:Foo as Debug",
    }, "trait impls must render as 'Type as Trait'"
    assert len({record["id"] for record in records}) == len(records), (
        "same-Type multi-trait same-signature methods must stay distinct"
    )
    next_record = next(record for record in records if record["name"] == "next")
    assert next_record["owner"] == "impl:&'a mut Foo as Iterator"
    assert next_record["module"] == "trait_fixture"
    plain = next(record for record in records if record["name"] == "fmt")
    assert plain["signature"].startswith("fn fmt(&self)"), "visibility must be normalized away"

    # Same-name insert/delete/move must not disturb existing Rust IDs.
    v1 = "fn alpha(x: u32) -> u32 { x + 1 }\nfn beta() {}\n"
    v2 = "fn alpha(y: u64) -> u64 { y + 2 }\n" + v1  # same-name insertion above
    v3 = "fn alpha(x: u32) -> u32 { x + 1 }\n"  # deletion of beta
    v4 = "fn beta() {}\nfn alpha(x: u32) -> u32 { x + 1 }\n"  # move/swap
    base_ids = _ids_by_signature(
        assign_or_fail("src/move.rs", v1)
    )
    inserted_ids = _ids_by_signature(assign_or_fail("src/move.rs", v2))
    deleted_ids = _ids_by_signature(assign_or_fail("src/move.rs", v3))
    moved_ids = _ids_by_signature(assign_or_fail("src/move.rs", v4))
    assert base_ids["fn alpha(x: u32) -> u32"] == inserted_ids["fn alpha(x: u32) -> u32"]
    assert base_ids["fn alpha(x: u32) -> u32"] == deleted_ids["fn alpha(x: u32) -> u32"]
    assert base_ids == moved_ids, "moving functions must not change IDs"

    # Macro template scopes separate identical template functions.
    macro_fixture = r'''
macro_rules! gen_a { ($t:ty) => { impl Helper for $t { fn same(&self) -> u8 { 1 } } } }
macro_rules! gen_b { ($t:ty) => { impl Helper for $t { fn same(&self) -> u8 { 2 } } } }
fn after_macros() {}
'''
    records = collect_rust_identities("src/macro_fixture.rs", macro_fixture, "macro_fixture")
    assign_rust_locked_ids(records)
    same = [record for record in records if record["name"] == "same"]
    assert {record["owner"] for record in same} == {
        "macro:gen_a/impl:$t as Helper",
        "macro:gen_b/impl:$t as Helper",
    }, "macro template scopes must enter the owner context"
    assert len({record["id"] for record in same}) == 2

    # Two truly indistinguishable Rust items must fail closed.
    try:
        assign_rust_locked_ids(
            collect_rust_identities("src/twin.rs", "fn twin() {}\nfn twin() {}\n", "twin")
        )
    except RuntimeError as error:
        assert "indistinguishable" in str(error)
    else:
        raise AssertionError("identical Rust items must fail closed")

    # --- staged / base / dirty git states -----------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        command_output(["git", "init", "-q", "."], repo)
        command_output(["git", "config", "user.email", "self-test@rugra"], repo)
        command_output(["git", "config", "user.name", "rugra self-test"], repo)
        relative = "src/main.rs"
        (repo / "src").mkdir()
        (repo / relative).write_text(v1, encoding="utf-8")
        command_output(["git", "add", relative], repo)
        command_output(["git", "commit", "-qm", "v1"], repo)
        head_ids = _git_state_fixture_ids(repo, relative, f"HEAD:{relative}")
        # staged: same-name insertion lives in the index only.
        (repo / relative).write_text(v2, encoding="utf-8")
        command_output(["git", "add", relative], repo)
        index_ids = _git_state_fixture_ids(repo, relative, f":{relative}")  # stage 0
        assert head_ids["fn alpha(x: u32) -> u32"] == index_ids["fn alpha(x: u32) -> u32"]
        # dirty: worktree deletes beta while the index still holds v2.
        (repo / relative).write_text(v3, encoding="utf-8")
        worktree_ids = _ids_by_signature(
            assign_or_fail(relative, (repo / relative).read_text(encoding="utf-8"))
        )
        assert index_ids["fn alpha(x: u32) -> u32"] == worktree_ids["fn alpha(x: u32) -> u32"]
        # base: commit and compare across the commit range.
        command_output(["git", "add", relative], repo)
        command_output(["git", "commit", "-qm", "v3"], repo)
        new_head_ids = _git_state_fixture_ids(repo, relative, f"HEAD:{relative}")
        base_ids = _git_state_fixture_ids(repo, relative, f"HEAD~1:{relative}")
        assert new_head_ids["fn alpha(x: u32) -> u32"] == base_ids["fn alpha(x: u32) -> u32"]
        assert head_ids["fn alpha(x: u32) -> u32"] == new_head_ids["fn alpha(x: u32) -> u32"], (
            "ID must be identical across staged, base, dirty, and committed states"
        )

    # --- migration fail-closed behavior --------------------------------------
    fresh_ghidra = [
        {"path": "x.cc", "line": 2, "entry_kind": "definition", "name": "f", "id": "GH12-F-new1"},
        {"path": "x.cc", "line": 4, "entry_kind": "definition", "name": "f", "id": "GH12-F-new2"},
    ]
    old_ghidra = [
        {"path": "x.cc", "line": 2, "entry_kind": "definition", "name": "f", "id": "GH12-F-old1"},
        {"path": "x.cc", "line": 4, "entry_kind": "definition", "name": "f", "id": "GH12-F-old2-01"},
    ]
    rows, disambiguators = migration_rows(
        old_ghidra,
        [dict(entry) for entry in fresh_ghidra],
        [],
        [],
    )
    assert [row["old_id"] for row in rows] == ["GH12-F-old1", "GH12-F-old2-01"]
    assert rows[1]["reason"] == "ghidra_ordinal_replaced_by_guard_disambiguator"
    stats = check_migration_rows(rows)
    assert stats["total"] == 2 and stats["ambiguous_old_ids"] == 0
    # same old id mapping to two new ids must be rejected
    try:
        check_migration_rows(
            [
                {"old_id": "GH12-F-old", "new_id": "GH12-F-a"},
                {"old_id": "GH12-F-old", "new_id": "GH12-F-b"},
            ]
        )
    except RuntimeError as error:
        assert "ambiguity" in str(error)
    else:
        raise AssertionError("ambiguous old ids must fail closed")
    # several old ids collapsing onto one new id must be rejected
    try:
        check_migration_rows(
            [
                {"old_id": "RG-F-old1", "new_id": "RG-F-same"},
                {"old_id": "RG-F-old2", "new_id": "RG-F-same"},
            ]
        )
    except RuntimeError as error:
        assert "ambiguity" in str(error)
    else:
        raise AssertionError("colliding new ids must fail closed")

    # --- reconciled migration lineage and failure matrix ------------------
    def synthetic_record(fid: str, signature: str, *, owner: str = "impl:Demo",
                         name: str = "step", line: int = 10,
                         body: str | None = "{ value }") -> dict[str, object]:
        return {
            "id": fid,
            "path": "src/demo.rs",
            "module": "demo",
            "owner": owner,
            "name": name,
            "signature": signature,
            "line": line,
            "end_line": line + 2,
            "is_test": False,
            "is_declaration": False,
            "_annotation": ("ghidra", '{"file":"x.cc","line":1}'),
            "_annotation_kind": "ghidra",
            "_annotation_value": {"file": "x.cc", "line": 1},
            "_masked_body": body,
        }

    old_token = "RG-F-" + "10" * 10
    new_token = "RG-F-" + "11" * 10
    old_record = synthetic_record(old_token, "fn step(&self, x: u8)")
    new_record = synthetic_record(new_token, "fn step(&self, x: u16)")
    evidence = strict_transition_evidence(old_record, new_record, [(10, 1, 10, 1)])
    assert evidence == [
        "same_patch_hunk", "identical_nonempty_annotation", "identical_masked_body"
    ], "one-hop signature change must retain all deterministic evidence"
    selected = select_unique_strict_transition(
        "a" * 40,
        ("src/demo.rs", "demo", "impl:Demo", "step"),
        [old_token],
        [new_token],
        {old_token: (old_record, "1" * 40)},
        {new_token: (new_record, "2" * 40)},
        [(10, 1, 10, 1)],
    )
    assert selected and selected[:2] == (old_token, new_token)

    # Post-baseline evidence canonicalizes binding modifiers only.  Pointer
    # and reference mutability are part of the function type and stay intact.
    mut_old = synthetic_record(old_token, "fn step(&mut self, slot: usize)")
    mut_new = synthetic_record(new_token, "fn step(&mut self, mut slot: usize)")
    assert rust_parameter_binding_mut_normalized_signature(mut_old["signature"]) == (
        rust_parameter_binding_mut_normalized_signature(mut_new["signature"])
    )
    assert continuity_transition_evidence(mut_old, mut_new, [(10, 1, 10, 1)]) == [
        "same_patch_hunk", "identical_nonempty_annotation", "parameter_binding_mut_only"
    ]
    for signature in (
        "fn borrow(x: &mut T)",
        "fn borrow(x: &'a mut T)",
        "fn pointer(x: *mut T)",
        "fn pattern(&mut x: &mut T)",
    ):
        assert rust_parameter_binding_mut_normalized_signature(signature) == signature
    assert (
        rust_parameter_binding_mut_normalized_signature("fn take(mut self, #[cfg(x)] mut y: T)")
        == "fn take(self, #[cfg(x)] y: T)"
    )
    non_mut_new = synthetic_record(new_token, "fn step(&mut self, slot: u64)")
    assert not continuity_transition_evidence(mut_old, non_mut_new, [(10, 1, 10, 1)])
    no_annotation = dict(mut_new)
    no_annotation["_annotation"] = None
    assert not continuity_transition_evidence(mut_old, no_annotation, [(10, 1, 10, 1)])
    assert not continuity_transition_evidence(mut_old, mut_new, [])

    # A separator-only signature reformat is an automatic alias; the nested
    # 1-tuple separator and a mixed separator+binding change are not.
    comma_old = synthetic_record(old_token, "fn step(&self, slot: usize,)")
    comma_new = synthetic_record(new_token, "fn step(&self, slot: usize)")
    assert continuity_transition_evidence(comma_old, comma_new, [(10, 1, 10, 1)]) == [
        "same_patch_hunk", "identical_nonempty_annotation", "signature_trailing_comma_only"
    ]
    assert not continuity_transition_evidence(comma_old, comma_new, [])
    assert rust_trailing_comma_normalized_signature("fn take(x: u8,) -> u8") == (
        rust_trailing_comma_normalized_signature("fn take(x: u8) -> u8")
    )
    nested_old = synthetic_record(old_token, "fn step(&self, slot: (u8,))")
    nested_new = synthetic_record(new_token, "fn step(&self, slot: (u8))")
    assert rust_trailing_comma_normalized_signature(nested_old["signature"]) != (
        rust_trailing_comma_normalized_signature(nested_new["signature"])
    )
    assert not continuity_transition_evidence(nested_old, nested_new, [(10, 1, 10, 1)])
    mixed_old = synthetic_record(old_token, "fn step(&self, mut slot: usize,)")
    mixed_new = synthetic_record(new_token, "fn step(&self, slot: usize)")
    assert not continuity_transition_evidence(mixed_old, mixed_new, [(10, 1, 10, 1)])

    # Owner-header drift, or a rename plus body rewrite, is not an automatic
    # successor merely because a nearby function appeared.
    owner_drift = synthetic_record(
        "RG-F-" + "12" * 10, "fn step(&self, x: u16)", owner="impl:Demo as Trait"
    )
    renamed = synthetic_record(
        "RG-F-" + "13" * 10, "fn replacement(&self)", name="replacement", body="{ other }"
    )
    assert (old_record["owner"], old_record["name"]) != (owner_drift["owner"], owner_drift["name"])
    assert (old_record["owner"], old_record["name"]) != (renamed["owner"], renamed["name"])
    no_proof = dict(new_record)
    no_proof["_annotation"] = None
    no_proof["_masked_body"] = "{ rewritten }"
    assert not strict_transition_evidence(old_record, no_proof, [])

    reviewed_target = "RG-F-" + "16" * 10
    moved_record = synthetic_record(
        reviewed_target, "fn replacement()", owner="free", name="replacement"
    )
    moved_record["path"] = "src/replacement.rs"
    moved_record["module"] = "replacement"
    reviewed_rule = {
        "legacy_id": "RG-F-" + "17" * 10,
        "from_id": old_token,
        "to_id": reviewed_target,
        "commit": "6" * 40,
        "kind": "successor",
        "label": "reviewed rename and move",
        "parent_blob_prefix": "1" * 8,
        "child_blob_prefix": "2" * 8,
    }
    validated = validate_reviewed_transition(
        reviewed_rule,
        {old_token: reviewed_rule["legacy_id"]},
        {old_token: (old_record, "1" * 40)},
        {reviewed_target: (moved_record, "2" * 40)},
        set(),
    )
    assert validated[0] == reviewed_rule["legacy_id"], "explicit rename+move must use exact pins"
    try:
        validate_reviewed_transition(
            reviewed_rule,
            {old_token: reviewed_rule["legacy_id"]},
            {old_token: (old_record, "1" * 40)},
            {},  # target existed before the commit, so it is not newly added
            set(),
        )
    except MigrationHarnessError as error:
        assert "not newly added" in str(error)
    else:
        raise AssertionError("wrapper/deletion -> existing function must be rejected")
    wrong_blob_rule = dict(reviewed_rule)
    wrong_blob_rule["child_blob_prefix"] = "9" * 8
    try:
        validate_reviewed_transition(
            wrong_blob_rule,
            {old_token: reviewed_rule["legacy_id"]},
            {old_token: (old_record, "1" * 40)},
            {reviewed_target: (moved_record, "2" * 40)},
            set(),
        )
    except MigrationHarnessError as error:
        assert "child blob mismatch" in str(error)
    else:
        raise AssertionError("reviewed transition blob drift must fail closed")

    # 1->2, 2->1, and overload candidate sets are ambiguous even when one
    # candidate happens to have matching body/annotation evidence.
    other_old = "RG-F-" + "14" * 10
    other_new = "RG-F-" + "15" * 10
    before = {
        old_token: (old_record, "1" * 40),
        other_old: (synthetic_record(other_old, "fn step(&self, x: u32)"), "1" * 40),
    }
    after = {
        new_token: (new_record, "2" * 40),
        other_new: (synthetic_record(other_new, "fn step(&self, x: u64)"), "2" * 40),
    }
    for old_ids, new_ids in (
        ([old_token], [new_token, other_new]),
        ([old_token, other_old], [new_token]),
        ([old_token, other_old], [new_token, other_new]),
    ):
        try:
            select_unique_strict_transition(
                "b" * 40, ("src/demo.rs", "demo", "impl:Demo", "step"),
                old_ids, new_ids, before, after, [(10, 2, 10, 2)],
            )
        except MigrationHarnessError as error:
            assert "ambiguous automatic transition" in str(error)
        else:
            raise AssertionError("ambiguous transition cardinality must fail closed")

    def live_row(old: str, new: str, aliases: list[str]) -> dict[str, object]:
        return {"old_id": old, "new_id": new, "aliases": aliases}

    def dead_row(old: str, aliases: list[str]) -> dict[str, object]:
        return {
            "old_id": old,
            "aliases": aliases,
            "path": "src/deleted.rs",
            "module": "deleted",
            "owner": "free",
            "name": "gone",
            "signature": "fn gone()",
            "deleted_at_commit": "3" * 40,
            "parent_blob": "4" * 40,
            "child_blob": "5" * 40,
            "reason": "deleted_without_reviewed_successor",
        }

    legacy_live = "RG-F-" + "20" * 10
    final_live = "RG-F-" + "21" * 10
    base_live = "RG-F-" + "22" * 10
    middle_live = "RG-F-" + "23" * 10
    legacy_dead = "RG-F-" + "30" * 10
    base_dead = "RG-F-" + "31" * 10
    healthy_stats = _validate_reconciled_classes(
        [live_row(legacy_live, final_live, [base_live, middle_live])],
        [dead_row(legacy_dead, [base_dead])],
        {final_live},
        expected_origin_count=2,
        expected_live_count=1,
        expected_tombstone_count=1,
        expected_alias_count=2,
    )
    assert healthy_stats["alias_tokens"] == 2, "two-hop compression must retain intermediate alias"

    def expect_rekey_failure(label: str, thunk) -> None:
        try:
            thunk()
        except MigrationHarnessError:
            return
        raise AssertionError(f"{label} must fail closed")

    # Duplicate aliases across origin classes and 2->1 final convergence.
    second_old = "RG-F-" + "40" * 10
    second_final = "RG-F-" + "41" * 10
    expect_rekey_failure(
        "duplicate alias across classes",
        lambda: _validate_reconciled_classes(
            [
                live_row(legacy_live, final_live, [base_live]),
                live_row(second_old, second_final, [base_live]),
            ], [], {final_live, second_final}, expected_origin_count=2,
            expected_live_count=2, expected_tombstone_count=0, expected_alias_count=2,
        ),
    )
    expect_rekey_failure(
        "two origins converging on one final",
        lambda: _validate_reconciled_classes(
            [live_row(legacy_live, final_live, []), live_row(second_old, final_live, [])],
            [], {final_live}, expected_origin_count=2, expected_live_count=2,
            expected_tombstone_count=0, expected_alias_count=0,
        ),
    )
    expect_rekey_failure(
        "alias equals unrelated current id",
        lambda: _validate_reconciled_classes(
            [live_row(legacy_live, final_live, [second_final])], [],
            {final_live, second_final}, expected_origin_count=1, expected_live_count=1,
            expected_tombstone_count=0, expected_alias_count=1,
        ),
    )
    expect_rekey_failure(
        "live target absent ledger",
        lambda: _validate_reconciled_classes(
            [live_row(legacy_live, final_live, [])], [], set(),
            expected_origin_count=1, expected_live_count=1,
            expected_tombstone_count=0, expected_alias_count=0,
        ),
    )
    malformed_tombstone = dead_row(legacy_dead, [base_dead])
    del malformed_tombstone["parent_blob"]
    expect_rekey_failure(
        "tombstone missing commit/blob/signature",
        lambda: _validate_reconciled_classes(
            [], [malformed_tombstone], set(), expected_origin_count=1,
            expected_live_count=0, expected_tombstone_count=1, expected_alias_count=0,
        ),
    )
    # A lineage that transitions and is later deleted retains both its base
    # and intermediate tokens in the tombstone class.
    intermediate_dead = dead_row(legacy_dead, [base_dead, middle_live])
    _validate_reconciled_classes(
        [], [intermediate_dead], set(), expected_origin_count=1,
        expected_live_count=0, expected_tombstone_count=1, expected_alias_count=0,
    )

    # Pinned git boundary: commit/tree/blob mismatches, unrelated history,
    # dirty src and dirty ledger are harness errors (the CLI maps these to 2).
    pin_names = (
        "REKEY_SOURCE_COMMIT", "REKEY_SOURCE_COMMIT_TREE", "REKEY_SOURCE_SRC_TREE",
        "REKEY_SOURCE_LEDGER_BLOB", "REKEY_TARGET_COMMIT", "REKEY_TARGET_COMMIT_TREE",
        "REKEY_TARGET_SRC_TREE", "REKEY_TARGET_LEDGER_BLOB",
        "REKEY_SOURCE_MIGRATION_BLOB", "REKEY_FIRST_PARENT_COMMIT_COUNT",
    )
    saved_pins = {name: globals()[name] for name in pin_names}
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        command_output(["git", "init", "-q", "."], repo)
        command_output(["git", "config", "user.email", "self-test@rugra"], repo)
        command_output(["git", "config", "user.name", "rugra self-test"], repo)
        (repo / "src").mkdir()
        (repo / "docs/alignment_audit").mkdir(parents=True)
        source_text = "fn source() {}\n"
        target_text = "fn source(x: u8) {}\n"
        ledger_path = repo / "docs/alignment_audit/FUNCTION_LEDGER.json"
        migration_path = repo / "docs/alignment_audit/FUNCTION_ID_MIGRATION.json"
        bad_json_path = repo / "docs/alignment_audit/bad.json"
        (repo / "src/main.rs").write_text(source_text, encoding="utf-8")
        ledger_path.write_text("{}\n", encoding="utf-8")
        command_output(["git", "add", "src/main.rs", "docs/alignment_audit/FUNCTION_LEDGER.json"], repo)
        command_output(["git", "commit", "-qm", "source"], repo)
        source_commit = command_output(["git", "rev-parse", "HEAD"], repo).strip()
        (repo / "src/main.rs").write_text(target_text, encoding="utf-8")
        ledger_path.write_text('{"target":true}\n', encoding="utf-8")
        migration_path.write_text('{"source":true}\n', encoding="utf-8")
        bad_json_path.write_text("{broken\n", encoding="utf-8")
        command_output(
            ["git", "add", "src/main.rs", "docs/alignment_audit/FUNCTION_LEDGER.json",
             "docs/alignment_audit/FUNCTION_ID_MIGRATION.json",
             "docs/alignment_audit/bad.json"], repo,
        )
        command_output(["git", "commit", "-qm", "target"], repo)
        target_commit = command_output(["git", "rev-parse", "HEAD"], repo).strip()
        synthetic_pins = {
            "REKEY_SOURCE_COMMIT": source_commit,
            "REKEY_SOURCE_COMMIT_TREE": command_output(
                ["git", "rev-parse", f"{source_commit}^{{tree}}"], repo
            ).strip(),
            "REKEY_SOURCE_SRC_TREE": command_output(
                ["git", "rev-parse", f"{source_commit}:src"], repo
            ).strip(),
            "REKEY_SOURCE_LEDGER_BLOB": command_output(
                ["git", "rev-parse", f"{source_commit}:docs/alignment_audit/FUNCTION_LEDGER.json"], repo
            ).strip(),
            "REKEY_TARGET_COMMIT": target_commit,
            "REKEY_TARGET_COMMIT_TREE": command_output(
                ["git", "rev-parse", f"{target_commit}^{{tree}}"], repo
            ).strip(),
            "REKEY_TARGET_SRC_TREE": command_output(
                ["git", "rev-parse", f"{target_commit}:src"], repo
            ).strip(),
            "REKEY_TARGET_LEDGER_BLOB": command_output(
                ["git", "rev-parse", f"{target_commit}:docs/alignment_audit/FUNCTION_LEDGER.json"], repo
            ).strip(),
            "REKEY_SOURCE_MIGRATION_BLOB": command_output(
                ["git", "rev-parse", f"{target_commit}:docs/alignment_audit/FUNCTION_ID_MIGRATION.json"], repo
            ).strip(),
            "REKEY_FIRST_PARENT_COMMIT_COUNT": 1,
        }
        try:
            globals().update(synthetic_pins)
            assert verify_rekey_boundary(repo, verify_locked_oracle=False) == [target_commit]
            expect_rekey_failure(
                "malformed pinned JSON",
                lambda: _migration_json_from_git(
                    repo, target_commit, "docs/alignment_audit/bad.json"
                ),
            )

            (repo / "src/main.rs").write_text(target_text + "// dirty\n", encoding="utf-8")
            expect_rekey_failure(
                "dirty target src", lambda: verify_rekey_boundary(repo, verify_locked_oracle=False)
            )
            (repo / "src/main.rs").write_text(target_text, encoding="utf-8")

            globals()["REKEY_TARGET_SRC_TREE"] = "0" * 40
            expect_rekey_failure(
                "target src tree mismatch",
                lambda: verify_rekey_boundary(repo, verify_locked_oracle=False),
            )
            globals()["REKEY_TARGET_SRC_TREE"] = synthetic_pins["REKEY_TARGET_SRC_TREE"]

            ledger_path.write_text('{"dirty":true}\n', encoding="utf-8")
            expect_rekey_failure(
                "target ledger mismatch",
                lambda: verify_rekey_boundary(repo, verify_locked_oracle=False),
            )
            ledger_path.write_text('{"target":true}\n', encoding="utf-8")

            expect_rekey_failure(
                "object pin mismatch",
                lambda: _expect_git_object(repo, "HEAD^{commit}", "0" * 40, "test commit"),
            )

            unrelated = command_output(
                ["git", "commit-tree", synthetic_pins["REKEY_TARGET_COMMIT_TREE"], "-m", "unrelated"],
                repo,
            ).strip()
            globals()["REKEY_SOURCE_COMMIT"] = unrelated
            globals()["REKEY_SOURCE_COMMIT_TREE"] = synthetic_pins["REKEY_TARGET_COMMIT_TREE"]
            globals()["REKEY_SOURCE_SRC_TREE"] = synthetic_pins["REKEY_TARGET_SRC_TREE"]
            globals()["REKEY_SOURCE_LEDGER_BLOB"] = synthetic_pins["REKEY_TARGET_LEDGER_BLOB"]
            expect_rekey_failure(
                "source not ancestor",
                lambda: verify_rekey_boundary(repo, verify_locked_oracle=False),
            )
        finally:
            globals().update(saved_pins)

    expect_rekey_failure(
        "malformed migration schema",
        lambda: _validate_rekey_source_tables({}, {}, {}),
    )

    lines = ["// Ghidra: x.cc:7 A::f", "fn f() {}"]
    record = scan_rust_functions("\n".join(lines))[0]
    kind, marker = marker_above(lines, record.start_line)
    assert kind == "ghidra" and marker["file"] == "x.cc" and marker["line"] == 7
    print("generate_function_ledger: self-test OK")
    return 0


def assign_or_fail(relative: str, text: str) -> list[dict[str, object]]:
    records = collect_rust_identities(relative, text, module_from_relative(relative))
    assign_rust_locked_ids(records)
    return records


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    migration_mode = parser.add_mutually_exclusive_group()
    migration_mode.add_argument(
        "--migrate",
        action="store_true",
        help="rewrite the existing ledger's ID space into scheme 2 and emit "
        "FUNCTION_ID_MIGRATION.json",
    )
    migration_mode.add_argument(
        "--reconcile-migration",
        action="store_true",
        help="replay the separately pinned scheme-2 source history into the pinned "
        "target ledger; never replaces the --migrate origin",
    )
    migration_mode.add_argument(
        "--reconcile-continuity",
        action="store_true",
        help="compose post-baseline raw scheme-2 ID continuity through the pinned "
        "source checkpoint; never rewrites FUNCTION_ID_MIGRATION.json",
    )
    parser.add_argument(
        "--migrate-base",
        help="commit whose tree reproduces the existing ledger (default: auto-detect)",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    root = Path(__file__).resolve().parent.parent
    output_dir = args.output_dir.resolve() if args.output_dir else root / "docs/alignment_audit"
    try:
        if args.reconcile_continuity:
            try:
                continuity = function_id_continuity_document(root)
            except MigrationHarnessError:
                raise
            except (
                OSError,
                RuntimeError,
                ValueError,
                KeyError,
                TypeError,
                IndexError,
                UnicodeError,
                json.JSONDecodeError,
            ) as error:
                raise MigrationHarnessError(
                    f"{type(error).__name__}: {error}"
                ) from error
            write_or_check(
                output_dir / "FUNCTION_ID_CONTINUITY.json",
                canonical_json(continuity),
                args.check,
            )
            stats = continuity["stats"]
            print(
                "generate_function_ledger: reconciled continuity "
                f"baseline={stats['baseline_records']} current={stats['current_records']} "
                f"lineages={stats['lineages']} introduced={stats['introduced_live']} "
                f"tombstones={stats['tombstones']}"
            )
            return 0
        if args.reconcile_migration:
            try:
                migration = migration_reconciliation_document(root)
            except MigrationHarnessError:
                raise
            except (
                OSError,
                RuntimeError,
                ValueError,
                KeyError,
                TypeError,
                IndexError,
                UnicodeError,
                json.JSONDecodeError,
            ) as error:
                raise MigrationHarnessError(
                    f"{type(error).__name__}: {error}"
                ) from error
            write_or_check(
                output_dir / "FUNCTION_ID_MIGRATION.json",
                canonical_json(migration),
                args.check,
            )
            stats = migration["stats"]
            print(
                "generate_function_ledger: reconciled migration "
                f"origins={stats['origin_entries']} tombstones={stats['tombstones']} "
                f"lineages={stats['live_rekey_lineages']} aliases={stats['alias_tokens']} "
                f"auto_events={stats['automatic_transition_events']}"
            )
            return 0
        if args.migrate:
            ledger_path = root / "docs/alignment_audit/FUNCTION_LEDGER.json"
            migration = migration_document(root, ledger_path, output_dir, args.migrate_base)
            write_or_check(
                output_dir / "FUNCTION_ID_MIGRATION.json",
                canonical_json(migration),
                args.check,
            )
            stats = migration["stats"]
            print(
                f"generate_function_ledger: migration entries={stats['total']} "
                f"stable={stats['stable_unchanged']} changed={stats['changed']} "
                f"ambiguous={stats['ambiguous_old_ids']} collisions={stats['colliding_new_ids']} "
                f"disambiguators={len(migration['disambiguators'])}"
            )
            return 0
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
    except MigrationHarnessError as error:
        print(f"generate_function_ledger: migration harness input error: {error}", file=sys.stderr)
        return 2
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
