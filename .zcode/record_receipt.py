#!/usr/bin/env python3
"""
record_receipt.py — PostToolUse hook (on Read) + manual receipt recorder.

Records that an agent READ a Ghidra cpp source file, so the PreToolUse gate
(align_gate.py) can enforce "re-read the Ghidra function before editing its
Rust counterpart" (AGENTS.md 铁律 5.5/6).

Two invocation modes:

1. PostToolUse on Read (automatic): ZCode pipes the hook payload on stdin:
     { tool_name: "Read", tool_input: { file_path, offset, limit }, ... }
   If file_path is inside the Ghidra cpp source tree, record a receipt keyed
   by the relative ghidra filename (e.g. "coreaction.cc") with the line range
   read + timestamp.

2. Manual (fallback / for reads done outside the tool, e.g. via WebFetch):
     python record_receipt.py <ghidra_file> [<line_start> [<line_end>]]
   e.g. python record_receipt.py coreaction.cc 4886 4960

Receipt store: .alignment_receipts.json
  {
    "reads": { "<ghidra_file>": { "ts": <epoch>, "ranges": [[s,e],...] } },
    "gated_edits": { "<rs_file>::<rs_fn>::<ghidra_file>": <epoch> }
  }
"""
from __future__ import annotations
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECEIPTS = ROOT / ".alignment_receipts.json"
GHIDRA_CPP = ROOT / "ghidra" / "Ghidra" / "Features" / "Decompiler" / "src" / "decompile" / "cpp"
LOG = ROOT / ".zcode" / "align_gate.log"

GHIDRA_EXT = (".cc", ".hh", ".h", ".c")


def _log(msg: str) -> None:
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(f"[{time.time():.0f}] [RECEIPT] {msg}\n")
    except Exception:
        pass


def _load() -> dict:
    try:
        return json.loads(RECEIPTS.read_text(encoding="utf-8")) if RECEIPTS.exists() else {}
    except Exception:
        return {}


def _save(d: dict) -> None:
    RECEIPTS.write_text(json.dumps(d, indent=2), encoding="utf-8")


def _normalize_ghidra_file(file_path: str) -> str | None:
    """Return the ghidra-relative filename (e.g. 'coreaction.cc') if the path
    is inside the Ghidra cpp tree and has a C/C++ extension, else None."""
    p = Path(file_path)
    name = p.name
    if not name.lower().endswith(GHIDRA_EXT):
        return None
    try:
        rel = p.resolve().relative_to(GHIDRA_CPP.resolve())
        return str(rel).replace("\\", "/")
    except Exception:
        # Also accept bare filenames like 'coreaction.cc' (manual mode)
        if "/" not in file_path and "\\" not in file_path:
            return name
    return None


def record(ghidra_rel: str, line_start: int | None, line_end: int | None) -> None:
    d = _load()
    reads = d.setdefault("reads", {})
    entry = reads.get(ghidra_rel, {"ts": 0.0, "ranges": []})
    entry["ts"] = time.time()
    if line_start is not None:
        rng = [line_start, line_end if line_end is not None else line_start]
        entry["ranges"].append(rng)
        # cap memory
        if len(entry["ranges"]) > 64:
            entry["ranges"] = entry["ranges"][-64:]
    reads[ghidra_rel] = entry
    d["reads"] = reads
    _save(d)
    _log(f"recorded read {ghidra_rel}:{line_start}-{line_end}")


def main() -> int:
    # Manual mode: argv
    if len(sys.argv) > 1:
        ghidra_rel = _normalize_ghidra_file(sys.argv[1])
        if not ghidra_rel:
            sys.stderr.write(f"record_receipt: not a Ghidra cpp file: {sys.argv[1]}\n")
            return 1
        ls = int(sys.argv[2]) if len(sys.argv) > 2 else None
        le = int(sys.argv[3]) if len(sys.argv) > 3 else ls
        record(ghidra_rel, ls, le)
        return 0

    # PostToolUse mode: stdin JSON
    try:
        if sys.stdin.isatty():
            return 0
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        return 0

    if payload.get("tool_name") != "Read":
        return 0
    ti = payload.get("tool_input", {}) or {}
    file_path = ti.get("file_path") or ti.get("path") or ""
    ghidra_rel = _normalize_ghidra_file(file_path)
    if not ghidra_rel:
        return 0
    offset = ti.get("offset")
    limit = ti.get("limit")
    line_start = int(offset) + 1 if isinstance(offset, int) else None
    line_end = None
    if line_start is not None and isinstance(limit, int):
        line_end = line_start + limit - 1
    record(ghidra_rel, line_start, line_end)
    return 0


if __name__ == "__main__":
    sys.exit(main())
