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
CONTINUITY_CHECKPOINT_COMMIT = "36633d9dd88ea5ee1c85d39b7cdf515f4309e3ba"
CONTINUITY_CHECKPOINT_COMMIT_TREE = "320c207975ee2d3157e4821c15336858fbb8bdd4"
CONTINUITY_CHECKPOINT_SRC_TREE = "ae8f4a750f671d6b875dacba308877321540ed8d"
CONTINUITY_CHECKPOINT_PARENT = "61631f238f0e6db58aea9f6e308cba1c8af990aa"
CONTINUITY_BASELINE_MIGRATION_BLOB = "8ecab1e6160b7d4d28a15aba0cad89c2fe8fc171"
CONTINUITY_BASELINE_MIGRATION_SHA256 = (
    "16236201f0b4920d2a3e33a848df05d3d601ee60998f7f7c51464d4eeb7739e9"
)
CONTINUITY_FIRST_PARENT_COMMIT_COUNT = 31
CONTINUITY_FIRST_COMMIT = "7ae30f5bcfba5e1adce2a4e8cdeebc23d96964cb"
CONTINUITY_BASELINE_RUST_RECORDS = 9_639
CONTINUITY_CHECKPOINT_RUST_RECORDS = 9_640
CONTINUITY_EXPECTED_TRANSITIONS = {
    ("RG-F-7622630fcd5425152c42", "RG-F-2e7d8eae51d63d1dcc39"),
    ("RG-F-c76e93f7b514cc307344", "RG-F-68db795ba78535d5e6e6"),
}
CONTINUITY_EXPECTED_INTRODUCED = {"RG-F-2646dcd008a8290bb207"}

# Future non-mut-binding successors/deletions must be added here with exact
# commit, ID, path, and blob pins.  Empty is meaningful: this checkpoint has
# no reviewed exception and no deletion.
CONTINUITY_REVIEWED_TRANSITIONS: tuple[dict[str, str], ...] = ()
CONTINUITY_REVIEWED_TOMBSTONES: tuple[dict[str, str], ...] = ()


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
            != rust_parameter_binding_mut_normalized_signature(new_signature)):
        return []
    strict = strict_transition_evidence(old, new, hunks)
    # A post-baseline automatic transition is deliberately narrower than the
    # original historical reconciler: both structural pins are mandatory.
    if "same_patch_hunk" not in strict or "identical_nonempty_annotation" not in strict:
        return []
    return ["same_patch_hunk", "identical_nonempty_annotation", "parameter_binding_mut_only"]


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
    used_reviewed: set[tuple[str, str, str]] = set()
    used_tombstones: set[tuple[str, str, str]] = set()
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
            if rule is None:
                raise MigrationHarnessError(
                    "unproved post-baseline removal requires an exact reviewed transition "
                    f"or tombstone: {base_id} {source_token} at {commit} "
                    f"({old_record['path']}::{old_record['name']})"
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
    if tombstones:
        raise MigrationHarnessError("checkpoint unexpectedly contains continuity tombstones")
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
            "path/module/owner/name pair whose only signature difference is a leading "
            "parameter binding mut, in the same patch hunk with the same non-empty "
            "annotation. Tombstones are diagnostic only; introduced_live rows are new "
            "checkpoint definitions, not fabricated historical origins."
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
