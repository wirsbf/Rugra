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

``--migrate`` rewrites the ID space of an existing ledger into the new
scheme and emits ``FUNCTION_ID_MIGRATION.json``.  Rust identities are
recomputed on the very tree the old ledger was generated from (auto-detected
and verified), so old-to-new correlation is exact; ambiguous or unmapped old
IDs fail closed instead of being guessed.
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
TODO_ID_RE = re.compile(r"`(?P<id>[A-Z][A-Z0-9_-]+)`")

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
    parser.add_argument(
        "--migrate",
        action="store_true",
        help="rewrite the existing ledger's ID space into scheme 2 and emit "
        "FUNCTION_ID_MIGRATION.json",
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
