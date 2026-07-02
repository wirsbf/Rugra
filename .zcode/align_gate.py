#!/usr/bin/env python3
"""
align_gate.py — PreToolUse gate enforcing AGENTS.md 铁律 5.5/6:
"修改一个函数的代码前,必须重新先看对应的 Ghidra 函数代码".

Mechanism (two cooperating hooks, see HOOK_GUIDE.md):
  - PostToolUse on Read:  records every read of a Ghidra cpp source file into
                           .alignment_receipts.json  (record_receipt.py)
  - THIS FILE (PreToolUse on Edit|Write|MultiEdit):
      For each src/*.rs function touched by the edit, find its `// Ghidra:
      <file>:<line> <ghidraFn>` annotation, and require a receipt proving the
      named Ghidra file was read in the current session AFTER the function's
      last edit. No receipt -> BLOCK the edit with a precise message telling
      the agent which Ghidra file/function to read first.

Input:  JSON on stdin (ZCode PreToolUse payload):
          { "tool_name": "Edit", "tool_input": { "file_path",
            "old_string", "new_string" } }
Output: JSON on stdout with {"hookSpecificOutput":{"hookEventName":"PreToolUse",
          "permissionDecision":"deny"|"allow",
          "permissionDecisionReason":"..."}}
        Exit 0 = allow, 2 = block (Claude-Code convention).

Bypass rules (do NOT block):
  - file not under src/*.rs          (only Rust source gated)
  - test fns (#[test] / cfg(test))   (no Ghidra counterpart)
  - fns with NO // Ghidra: annotation but a // RUGRA-GLUE: marker
  - edits that don't fall inside any fn body (e.g. top-level use/docs)
  - first-time creation of a fn whose annotation is being added in THIS edit
  - ZCODE_ALIGN_GATE=0 in env (escape hatch, log it)

Receipt freshness: a receipt for ghidra file F counts if its read timestamp is
>= the mtime-stamp of the receipt entry recording the *previous* successful
gate for that (rs_fn, F) pair — i.e. "re-read after each edit cycle". Concretely
we require: last_read_ts(F) >= last_gated_edit_ts(rs_fn). For the very first
edit of a fn in a session we only require last_read_ts(F) to exist (>= the
session's start, tracked by a session_start marker).
"""
from __future__ import annotations
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]          # .../rugra
SRC = ROOT / "src"
GHIDRA_CPP = ROOT / "ghidra" / "Ghidra" / "Features" / "Decompiler" / "src" / "decompile" / "cpp"
RECEIPTS = ROOT / ".alignment_receipts.json"
SESSION_START = ROOT / ".alignment_session_start"
LOG = ROOT / ".zcode" / "align_gate.log"

ENV_OFF = os.environ.get("ZCODE_ALIGN_GATE", "").strip() == "0"

# --- Rust fn detection (must mirror check_ghidra_annotations.py) -------------
FN_RE = re.compile(r"^\s*(pub\s+)?(async\s+)?(unsafe\s+)?(const\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]")
# Canonical above-block annotation: `// Ghidra: <file>:<line> <rest...>`
GHIDRA_RE = re.compile(r"//\s*Ghidra:\s*([A-Za-z0-9_./-]+\.(?:cc|hh|h|c))\s*:(\d+)\s*(.*)")
# Inline reference: any `// ... <file>.<ext>:<digits> ...` inside a comment,
# covering `(coreaction.cc:4886)`, `coreaction.cc:4886`, `(varnode.hh:235)` etc.
GHIDRA_INLINE_RE = re.compile(r"([A-Za-z0-9_]+\.(?:cc|hh|h|c))\s*[:#]\s*(\d+)")
GLUE_RE = re.compile(r"//\s*RUGRA-GLUE:")
TEST_ATTR_RE = re.compile(r"#\[\s*(test|cfg\s*\(\s*test\s*\))")
CFG_TEST_RE = re.compile(r"^#\[\s*cfg\s*\(\s*test\s*\)\s*\]")
MOD_TESTS_RE = re.compile(r"^\s*(pub\s+)?mod\s+(tests?|common)\s*\{")


def log(msg: str) -> None:
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(f"[{time.time():.0f}] {msg}\n")
    except Exception:
        pass


# ----------------------------------------------------------------------------
# Receipt store
# ----------------------------------------------------------------------------
def _load_json(p: Path, default):
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default
    except Exception:
        return default


def _save_json(p: Path, data) -> None:
    try:
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass


def session_start_ts() -> float:
    try:
        return float(SESSION_START.read_text(encoding="utf-8").strip()) if SESSION_START.exists() else 0.0
    except Exception:
        return 0.0


def receipts() -> dict:
    return _load_json(RECEIPTS, {"reads": {}, "gated_edits": {}})


def touch_session_start() -> None:
    """Stamp session start on first gate invocation if not yet stamped.
    The authoritative stamper is the SessionStart hook, but this is a fallback
    so the gate works even without that hook registered."""
    if not SESSION_START.exists():
        _save_json(SESSION_START, {})  # create file presence
        try:
            SESSION_START.write_text(str(time.time()), encoding="utf-8")
        except Exception:
            pass


# ----------------------------------------------------------------------------
# Locating Rust fns affected by an edit
# ----------------------------------------------------------------------------
def find_fn_for_line(lines: list[str], target: int) -> tuple[int, str, bool] | None:
    """Walk backwards from `target` (0-based) to find the enclosing fn.
    Returns (fn_line_0based, name, is_test)."""
    fn_line = None
    fn_name = None
    in_test_mod = 0
    # crude: track whether we are inside a #[cfg(test)] mod by scanning upward
    for i in range(target, -1, -1):
        line = lines[i]
        m = FN_RE.match(line)
        if m:
            # is this fn inside a test mod? scan further up for cfg(test) mod
            test_mod = _inside_test_mod(lines, i)
            return (i, m.group(5), test_mod)
    return None


def _inside_test_mod(lines: list[str], fn_idx: int) -> bool:
    """Heuristic: scan upward for a #[cfg(test)] ... mod tests { that opens
    before fn_idx without a matching close before fn_idx."""
    depth = 0
    for i in range(fn_idx, -1, -1):
        s = lines[i]
        if CFG_TEST_RE.match(s):
            # next non-empty/non-attr line a mod tests?
            j = i + 1
            while j < len(lines) and (lines[j].strip() == "" or lines[j].strip().startswith("#[")):
                j += 1
            if j < len(lines) and MOD_TESTS_RE.match(lines[j]):
                return True
    return False


def fn_annotation(lines: list[str], fn_idx: int) -> tuple[str, int, str] | None:
    """Find the Ghidra source location this Rust fn corresponds to.

    Search order:
      1. The comment/attribute block immediately ABOVE fn_idx, for an explicit
         `// Ghidra: <file>:<line> ...` annotation (canonical form).
      2. The fn BODY, for the first `// ... Ghidra: ... (<file>:<line>)` or
         `// Ghidra: ... <file>:<line> ...` reference — covers the common
         inline-comment style used across this codebase (302 distinct refs).
      3. An explicit `// RUGRA-GLUE:` marker above -> None (exempt).

    Returns (ghidra_file, ghidra_line, rest) or None.
    """
    # --- (1) above-block explicit annotation ---
    j = fn_idx - 1
    while j >= 0:
        s = lines[j].rstrip()
        stripped = s.strip()
        if stripped == "":
            j -= 1
            continue
        if stripped.startswith("#["):
            j -= 1
            continue
        if stripped.startswith("//"):
            m = GHIDRA_RE.search(stripped)
            if m:
                return (m.group(1), int(m.group(2)), m.group(3))
            if GLUE_RE.search(stripped):
                return None  # explicit glue exemption
            j -= 1
            continue
        break

    # --- (2) inline references in the fn body ---
    start, end = line_range_of_fn(lines, fn_idx)
    for k in range(start, end + 1):
        s = lines[k].strip() if k < len(lines) else ""
        if not s.startswith("//"):
            continue
        if GLUE_RE.search(s):
            return None
        m = GHIDRA_INLINE_RE.search(s)
        if m:
            return (m.group(1), int(m.group(2)), s)
    return None


def line_range_of_fn(lines: list[str], fn_idx: int) -> tuple[int, int]:
    """Return (start, end) 0-based line range of the fn body (to first brace
    match then to its close). Used to decide if an edit touches the body."""
    # find opening brace
    depth = 0
    started = False
    end = len(lines) - 1
    for i in range(fn_idx, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
                if started and depth == 0:
                    return (fn_idx, i)
    return (fn_idx, end)


# ----------------------------------------------------------------------------
# Edits → affected fns
# ----------------------------------------------------------------------------
def affected_fns(file_path: Path, old_string: str | None, new_string: str | None) -> list[dict]:
    """Determine which fns an Edit touches. Returns list of dicts:
       {fn_name, ghidra_file, ghidra_line, ghidra_rest, is_test, has_annotation}.
    """
    try:
        text = file_path.read_text(encoding="utf-8")
    except Exception:
        return []
    lines = text.split("\n")

    # Map edit location: find first occurrence of old_string (Edit semantics)
    target_line = None
    if old_string:
        # Reconstruct line-based location of old_string
        full = "\n".join(lines)
        idx = full.find(old_string)
        if idx < 0:
            # old_string not found (maybe new fn / write). Fall back to new_string
            if new_string:
                idx = full.find(new_string)
        if idx >= 0:
            target_line = full[:idx].count("\n")
    if target_line is None:
        # Write/MultiEdit fallback: scan whole file for fns with annotations
        targets = _all_annotated_fns(lines)
    else:
        fn = find_fn_for_line(lines, target_line)
        targets = [fn] if fn else []

    out = []
    for fn_idx, name, is_test in targets:
        ann = fn_annotation(lines, fn_idx)
        start, end = line_range_of_fn(lines, fn_idx)
        out.append({
            "name": name,
            "fn_line": fn_idx + 1,
            "is_test": is_test,
            "has_annotation": ann is not None,
            "ghidra_file": ann[0] if ann else None,
            "ghidra_line": ann[1] if ann else None,
            "ghidra_rest": ann[2] if ann else None,
            "body_end": end + 1,
        })
    return out


def _all_annotated_fns(lines: list[str]) -> list[tuple[int, str, bool]]:
    out = []
    for i, line in enumerate(lines):
        m = FN_RE.match(line)
        if m:
            out.append((i, m.group(5), _inside_test_mod(lines, i)))
    return out


# ----------------------------------------------------------------------------
# Decision
# ----------------------------------------------------------------------------
def decide(file_rel: str, affected: list[dict], rec: dict, sess_ts: float) -> tuple[bool, str]:
    """Return (allow, reason)."""
    # Only gate src/*.rs
    if not file_rel.replace("\\", "/").startswith("src/") or not file_rel.endswith(".rs"):
        return (True, "non-src-rust file")

    # Filter out test fns
    real = [f for f in affected if not f["is_test"]]
    if not real:
        return (True, "only test fns / no fn affected")

    # For each affected fn with a Ghidra annotation, require a receipt proving
    # the corresponding Ghidra file was read AFTER this session started.
    # (Per AGENTS.md 铁律 5.5/6: "re-read the Ghidra function before editing".)
    # One read per session covers all subsequent edits to that fn within the
    # same session — practical, while still forcing a re-read every new
    # session (so stale memory of Ghidra semantics can't carry across).
    reads = rec.get("reads", {})
    gated = rec.get("gated_edits", {})
    now = time.time()
    missing = []
    for f in real:
        if not f["has_annotation"]:
            # No annotation: don't block here (check_ghidra_annotations.py
            # already enforces annotations at commit time). Allow.
            continue
        gfile = f["ghidra_file"]
        key = f"{gfile}"
        last_read = reads.get(key, {}).get("ts", 0.0)
        gate_key = f"{file_rel}::{f['name']}::{gfile}"
        # Receipt counts if read happened at/after session start.
        fresh = last_read >= sess_ts
        if not fresh:
            missing.append({
                "fn": f["name"],
                "ghidra_file": gfile,
                "ghidra_line": f["ghidra_line"],
                "ghidra_rest": f["ghidra_rest"],
                "last_read_ts": last_read,
                "sess_ts": sess_ts,
            })
        else:
            # audit-stamp this gate
            gated[gate_key] = now
    rec["gated_edits"] = gated
    _save_json(RECEIPTS, rec)

    if missing:
        lines = ["BLOCKED by align_gate (AGENTS.md 铁律 5.5/6): edit would modify "
                 "Rust fn(s) whose corresponding Ghidra function was not re-read "
                 "in this session. Re-read FIRST, then retry the edit:"]
        for m in missing:
            lines.append(
                f"  - fn `{m['fn']}` ({file_rel}) -> Ghidra "
                f"{m['ghidra_file']}:{m['ghidra_line']}  {m['ghidra_rest'] or ''}".rstrip()
            )
        lines.append(f"Read each listed Ghidra source (the file:line above), "
                     f"then re-issue the edit. Receipt file: {RECEIPTS.name}")
        return (False, "\n".join(lines))
    return (True, "all annotated fns have a fresh Ghidra-read receipt")


# ----------------------------------------------------------------------------
# SessionStart handling
# ----------------------------------------------------------------------------
def handle_session_start() -> int:
    """Stamp the session-start marker. Reads of Ghidra files after this ts
    count as fresh receipts. Invoked by the SessionStart hook so the gate has
    a correct baseline even on the first edit of a new session."""
    try:
        SESSION_START.write_text(f"{time.time():.0f}", encoding="utf-8")
    except Exception as e:
        log(f"session-start stamp FAILED: {e}")
    log(f"session-start stamped")
    return 0


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def read_payload() -> dict:
    """Read the ZCode hook JSON from stdin without blocking when no stdin is
    attached (the hook is always invoked with a piped stdin per the contract,
    but be defensive)."""
    try:
        if sys.stdin.isatty():
            return {}
        raw = sys.stdin.read()
        return json.loads(raw) if raw.strip() else {}
    except Exception:
        return {}


def emit_decision(allow: bool, reason: str) -> int:
    """Emit the decision both as structured JSON (preferred) and via the
    exit-code-2 + stderr fallback (most reliable deny path, per the reverse-
    engineered contract: Gcn() in zcode.cjs derives the deny reason from
    stderr/stdout text on exit != 0)."""
    decision = "allow" if allow else "deny"
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }
    try:
        sys.stdout.write(json.dumps(out))
        sys.stdout.flush()
    except Exception:
        pass
    if not allow:
        # Belt-and-suspenders: also write reason to stderr so even if the JSON
        # path isn't honored, exit 2 + stderr still blocks with the message.
        sys.stderr.write(reason + "\n")
        return 2
    return 0


def main() -> int:
    args = sys.argv[1:]
    if "--session-start" in args:
        return handle_session_start()

    payload = read_payload()
    tool = payload.get("tool_name", "?")
    ti = payload.get("tool_input", {}) or {}
    file_path_str = ti.get("file_path") or ti.get("path") or ""
    file_path = Path(file_path_str)
    try:
        file_rel = str(file_path.relative_to(ROOT)).replace("\\", "/")
    except Exception:
        file_rel = file_path_str.replace("\\", "/")

    if ENV_OFF:
        log(f"SKIP (ZCODE_ALIGN_GATE=0) tool={tool} file={file_rel}")
        return 0

    # Only care about src/*.rs
    if not (file_rel.startswith("src/") and file_rel.endswith(".rs")):
        return 0

    touch_session_start()
    sess_ts = session_start_ts()
    rec = receipts()
    affected = affected_fns(file_path, ti.get("old_string"), ti.get("new_string"))
    allow, reason = decide(file_rel, affected, rec, sess_ts)
    log(f"tool={tool} file={file_rel} affected={len(affected)} allow={allow} :: {reason[:120]}")
    return emit_decision(allow, reason)


if __name__ == "__main__":
    sys.exit(main())
