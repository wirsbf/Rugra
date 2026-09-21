#!/usr/bin/env python3
# RUGRA-GLUE: no oracle counterpart. This tool is a pure consumer of stage
# projection files produced by fixture harnesses around the locked oracle
# (Ghidra 12.0.4, commit e40ed13014025f82488b1f8f7bca566894ac376b) and around
# the Rugra driver layer. It changes no pipeline semantics, produces no IR, and
# injects no state; per docs/alignment_docs/PIPELINE_STAGES_1204.md section 5
# such tooling must live outside the perform() tree and must never be required
# for semantic equivalence. The native observation mechanisms it consumes are:
#
#   - funcdata.cc:1010-1052  Funcdata::debugModCheck/debugModClear/debugModPrint
#     (#ifdef OPACTION_DEBUG): after every Action::apply (action.cc:317-321) or
#     Rule::applyOp (action.cc:839-845, ActionPool::processOp) each modified
#     PcodeOp in the debug range is printed as a before/after printDebug pair,
#     prefixed by "DEBUG <n>: <name>" where <n> is the globally monotonic
#     opactdbg_count (funcdata.hh:584-602) that only advances when the
#     application actually modified a traced op.
#   - op.cc:376              PcodeOp::printDebug: "<seqnum-addr>: <printRaw>"
#     (or "<seqnum-addr>: **" for dead/unattached ops).
#   - action.cc:265-282      getSubAction/getSubRule colon-separated name-path
#     addressing ("universal:fullloop:mainloop"), the same path space used by
#     setBreakPoint (ifacedecomp.cc:1196/1222).
#   - action.cc:298-340      Action::perform state machine; a breakpoint makes
#     perform() return -1 and "a successive call to perform() will 'continue'
#     from the break point", which is how a harness walks stage by stage.
#   - action.cc:506/553-580/877 ActionGroup::apply (child iteration + count
#     accumulation), ActionRestartGroup::apply (curstart restart rounds),
#     ActionPool::apply (per-op per-rule traversal).
#   - architecture.hh:255-256 Architecture::setDebugStream/printDebug sink used
#     by harnesses to capture the DEBUG stream.
#   - ifacedecomp.cc:149-155 console commands: "debug action <name>",
#     "trace break <n>", "trace address <pclo> <pchi> [uqlo uqhi]",
#     "trace enable|disable|clear|list".
#
# Projection generators (see tools/stage_bisect_projection.cc for the Ghidra
# harness skeleton and command templates) are expected to prefix the native
# per-application name with the full tree path and to interleave boundary
# markers, because the oracle's own DEBUG stream carries neither.

"""Locate the first divergence boundary between two pipeline stage projections.

A projection file is a line-oriented trace of one decompilation run:

  # comment                       (ignored)
  META side=ghidra commit=e40ed13014025f82488b1f8f7bca566894ac376b \\
        func=FUN_00401000 arch=x86:LE:64:default
  @BEGIN <stage_path> [k=v ...]   one application of a stage starts
  <seq> <action_path> <before>|<after>
                                  one modified PcodeOp: global opactdbg_count
                                  sequence number, full ':'-separated action
                                  path, then before/after printDebug strings
  @END <stage_path> [k=v ...]     application finished (canonical keys:
                                  changes/tests/apply)
  @CONVERGED <stage_path> [k=v ...]
                                  sugar for "@END <path> changes=0" of a
                                  repeatapply group pass that changed nothing
  @RESTART <curstart>             universal ActionRestartGroup restart round

Escaping: inside before/after, '|' must be written '\\|' and '\\' as '\\\\'
(relevant because printRaw emits '|' as the INT_OR operator spelling).

Round derivation (docs/alignment_docs/PIPELINE_STAGES_1204.md section 4):
restart round = curstart from @RESTART markers (0 before any); per-group pass
counters are derived by counting @BEGIN occurrences per path since the last
@RESTART, so every divergence report carries stage path + restart round +
repeatapply pass state as the stable boundary address.

Exit codes: 0 projections identical, 1 first divergence reported, 2 usage or
format error. Selftest: 0 pass, 1 fail.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from pathlib import Path

SCHEMA = 1
TOOL = "stage_bisect"

KIND_MATCH = "MATCH"
KIND_AFTER = "AFTER_DIVERGENCE"
KIND_BEFORE = "BEFORE_DIVERGENCE"
KIND_PATH = "PATH_DIVERGENCE"
KIND_SEQ = "SEQ_DIVERGENCE"
KIND_STREAM = "STREAM_KIND_DIVERGENCE"
KIND_BOUNDARY = "BOUNDARY_DIVERGENCE"
KIND_LENGTH = "LENGTH_DIVERGENCE"

PATH_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
UNIQUE_RE = re.compile(r"(?<![A-Za-z0-9_])(?:unique|uni|u_)[0-9a-fA-F]+")

ATTRIBUTIONS = {
    KIND_AFTER: (
        "Same application, same before-state, different after-state: the defect "
        "is inside this stage's apply at this round (or its direct closure)."
    ),
    KIND_BEFORE: (
        "The before-state entering this application already differs: the defect "
        "is at or before the previous application of this stage or an earlier "
        "stage; bisect back to the last good boundary and rerun projections "
        "with a wider/finer debug range."
    ),
    KIND_PATH: (
        "A different stage fired at the same stream position: traversal order, "
        "dispatch, or convergence behavior of the enclosing group diverges."
    ),
    KIND_SEQ: (
        "Global opactdbg sequence numbers drifted apart: one side recorded an "
        "application the other did not (generator or counting divergence)."
    ),
    KIND_STREAM: (
        "One side emitted a boundary marker where the other emitted an op "
        "record at the same position: the two streams are not event-aligned."
    ),
    KIND_BOUNDARY: (
        "Stage boundary observation differs while all prior items matched: "
        "count accounting, completion state, or traversal diverges at this "
        "stage (see boundary_diff for the exact keys)."
    ),
    KIND_LENGTH: (
        "One projection is a strict prefix of the other: the shorter side "
        "stalled, terminated early, or stopped emitting at the reported "
        "boundary."
    ),
}


class FormatError(RuntimeError):
    """A projection file violates the stage-bisect format."""


class Meta:
    __slots__ = ("kv", "line_no", "raw")

    def __init__(self, kv, line_no, raw):
        self.kv = kv
        self.line_no = line_no
        self.raw = raw


class Boundary:
    __slots__ = ("kind", "path", "kv", "line_no", "raw")

    def __init__(self, kind, path, kv, line_no, raw):
        self.kind = kind  # BEGIN | END | RESTART
        self.path = path  # '' for @RESTART
        self.kv = kv
        self.line_no = line_no
        self.raw = raw


class Record:
    __slots__ = ("seq", "path", "before", "after", "line_no", "raw")

    def __init__(self, seq, path, before, after, line_no, raw):
        self.seq = seq
        self.path = path
        self.before = before
        self.after = after
        self.line_no = line_no
        self.raw = raw


# v1.1 is deliberately an extension of the original boundary grammar.  It
# uses the same META/@BEGIN/@END/@CONVERGED/@RESTART skeleton, but puts the
# observable operation list in an @SNAP block instead of the old
# OPACTION_DEBUG record stream.
V1_REQUIRED_META = (
    "side", "oracle_commit", "arch", "cspec", "analysis_options",
    "build_flags", "binary_sha256", "func_entry", "func_name", "load_mode",
    "producer", "maxrestarts", "unique_base",
)
V1_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
V1_HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]+$")
V1_LOCATION_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]+:(?:0x)?[0-9a-fA-F]+$")
V1_OPCODE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
V1_VN_RE = re.compile(
    r"^(?:c:(?:0x)?[0-9a-fA-F]+:[0-9]+|"
    r"n:[^:,\s]+:(?:0x)?[0-9a-fA-F]+:[0-9]+|"
    r"u:(?:0x)?[0-9a-fA-F]+:[0-9]+)$"
)


class V1Op:
    __slots__ = ("location", "opcode", "dead", "output", "inputs", "line_no", "raw")

    def __init__(self, location, opcode, dead, output, inputs, line_no, raw):
        self.location = location
        self.opcode = opcode
        self.dead = dead
        self.output = output
        self.inputs = inputs
        self.line_no = line_no
        self.raw = raw


class V1Stage:
    __slots__ = ("round", "seq", "path", "begin_line", "end_line", "snap_line", "attrs", "ops")

    def __init__(self, round_no, seq, path, begin_line):
        self.round = round_no
        self.seq = seq
        self.path = path
        self.begin_line = begin_line
        self.end_line = None
        self.snap_line = None
        self.attrs = None
        self.ops = []


class V1Projection:
    def __init__(self, name, path):
        self.name = name
        self.path = path
        self.meta = None
        self.stages = []
        self.converged = []

    @property
    def records(self):
        return sum(len(stage.ops) for stage in self.stages)

    @property
    def boundaries(self):
        return len(self.stages) * 3 + len(self.converged)


def parse_v1_op(line, line_no):
    """Parse one v1.1 snapshot operation line."""
    parts = line.strip().split()
    if len(parts) != 5:
        raise FormatError(
            f"line {line_no}: v1 op-line expects location OPC d= out= in=, got: {line!r}"
        )
    location, opcode, dead, output, inputs = parts
    if not V1_LOCATION_RE.fullmatch(location):
        raise FormatError(f"line {line_no}: invalid op location {location!r}")
    if not V1_OPCODE_RE.fullmatch(opcode):
        raise FormatError(f"line {line_no}: invalid opcode {opcode!r}")
    if not dead.startswith("d=") or dead[2:] not in ("0", "1"):
        raise FormatError(f"line {line_no}: d= must be 0 or 1")
    if not output.startswith("out=") or not inputs.startswith("in="):
        raise FormatError(f"line {line_no}: op-line requires out= and in= fields")
    output = output[4:]
    input_text = inputs[3:]
    if output != "-" and not V1_VN_RE.fullmatch(output):
        raise FormatError(f"line {line_no}: invalid output varnode {output!r}")
    if input_text == "-":
        input_values = ()
    else:
        input_values = tuple(input_text.split(","))
        if any(not V1_VN_RE.fullmatch(value) for value in input_values):
            raise FormatError(f"line {line_no}: invalid input varnode list {input_text!r}")
    return V1Op(location, opcode, int(dead[2:]), output, input_values, line_no, line.strip())


def _v1_int(value, field, line_no, minimum=None, allow_negative=False):
    pattern = r"-?[0-9]+" if allow_negative else r"[0-9]+"
    if not re.fullmatch(pattern, value):
        raise FormatError(f"line {line_no}: {field} must be an integer, got {value!r}")
    result = int(value)
    if minimum is not None and result < minimum:
        raise FormatError(f"line {line_no}: {field} must be >= {minimum}")
    return result


def _validate_v1_meta(meta, line_no):
    missing = [key for key in V1_REQUIRED_META if key not in meta]
    if missing:
        raise FormatError(f"line {line_no}: META missing fields: {', '.join(missing)}")
    if meta["side"] not in ("oracle", "rugra"):
        raise FormatError(f"line {line_no}: META side must be oracle or rugra")
    if not V1_SHA256_RE.fullmatch(meta["binary_sha256"]):
        raise FormatError(f"line {line_no}: META binary_sha256 is not a SHA-256")
    if not V1_HEX_RE.fullmatch(meta["func_entry"]):
        raise FormatError(f"line {line_no}: META func_entry is not hexadecimal")
    if not V1_HEX_RE.fullmatch(meta["unique_base"]):
        raise FormatError(f"line {line_no}: META unique_base is not hexadecimal")
    _v1_int(meta["maxrestarts"], "maxrestarts", line_no, minimum=0)


def load_v1_projection(file_path):
    """Load the v1.1 projection extension without accepting old op records."""
    path = Path(file_path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FormatError(f"cannot read {path}: {exc}") from exc
    projection = V1Projection(str(path), path)
    current = None
    restart = 0
    last_seq = 0
    stream_started = False
    meta_line = 0
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line_no = index + 1
        line = lines[index]
        index += 1
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("META"):
            if stream_started:
                raise FormatError(f"line {line_no}: META line after stream start")
            tokens = stripped.split()[1:]
            values = parse_key_values(tokens, line_no, stripped, "META")
            if projection.meta is None:
                projection.meta = Meta({}, line_no, stripped)
            for key, value in values.items():
                if key in projection.meta.kv:
                    raise FormatError(f"line {line_no}: duplicate META key {key!r}")
                projection.meta.kv[key] = value
            projection.meta.raw += " " + " ".join(tokens)
            meta_line = line_no
            continue
        stream_started = True
        tokens = stripped.split()
        head = tokens[0]
        if head == "@RESTART":
            if current is not None or len(tokens) != 2:
                raise FormatError(f"line {line_no}: invalid @RESTART placement or arity")
            restart = _v1_int(tokens[1], "curstart", line_no, minimum=0)
            continue
        if head == "@CONVERGED":
            # Kept solely for old producers; v1 production never emits it.
            if current is not None or len(tokens) < 2:
                raise FormatError(f"line {line_no}: invalid @CONVERGED")
            path_name = tokens[1]
            if not PATH_RE.fullmatch(path_name):
                raise FormatError(f"line {line_no}: invalid converged path")
            attrs = parse_key_values(tokens[2:], line_no, stripped, "@CONVERGED")
            if "changes" in attrs and attrs["changes"] != "0":
                raise FormatError(f"line {line_no}: @CONVERGED changes must be 0")
            projection.converged.append((restart, path_name, line_no, stripped))
            continue
        if head == "@BEGIN":
            if current is not None or len(tokens) != 3:
                raise FormatError(f"line {line_no}: @BEGIN expects '<seq> <tree-path>'")
            seq = _v1_int(tokens[1], "stage seq", line_no, minimum=1)
            path_name = tokens[2]
            if not PATH_RE.fullmatch(path_name):
                raise FormatError(f"line {line_no}: invalid stage path {path_name!r}")
            if seq <= last_seq:
                raise FormatError(f"line {line_no}: stage seq must increase globally")
            current = V1Stage(restart, seq, path_name, line_no)
            last_seq = seq
            continue
        if head == "@END":
            if current is None or len(tokens) != 7:
                raise FormatError(
                    f"line {line_no}: @END expects '<seq> <tree-path> result= count= tests= apply='"
                )
            seq = _v1_int(tokens[1], "stage seq", line_no, minimum=1)
            path_name = tokens[2]
            if not PATH_RE.fullmatch(path_name):
                raise FormatError(f"line {line_no}: invalid stage path {path_name!r}")
            attrs = parse_key_values(tokens[3:], line_no, stripped, "@END")
            if seq != current.seq or path_name != current.path:
                raise FormatError(f"line {line_no}: @END does not match @BEGIN")
            if set(attrs) != {"result", "count", "tests", "apply"}:
                raise FormatError(f"line {line_no}: @END requires result/count/tests/apply")
            _v1_int(attrs["result"], "result", line_no, allow_negative=True)
            for field in ("count", "tests", "apply"):
                _v1_int(attrs[field], field, line_no, minimum=0)
            current.end_line = line_no
            current.attrs = attrs
            continue
        if head == "@SNAP":
            if current is None or current.attrs is None or len(tokens) != 4 or tokens[2] != "ops":
                raise FormatError(f"line {line_no}: @SNAP must immediately follow matching @END")
            seq = _v1_int(tokens[1], "snapshot seq", line_no, minimum=1)
            count = _v1_int(tokens[3], "snapshot op count", line_no, minimum=0)
            if seq != current.seq:
                raise FormatError(f"line {line_no}: @SNAP seq does not match @END")
            current.snap_line = line_no
            for _ in range(count):
                if index >= len(lines):
                    raise FormatError(f"line {line_no}: @SNAP ends before {count} op-lines")
                op_line_no = index + 1
                op_text = lines[index].strip()
                index += 1
                if not op_text or op_text.startswith("#") or op_text.startswith("@"):
                    raise FormatError(f"line {op_line_no}: snapshot op-line expected")
                current.ops.append(parse_v1_op(op_text, op_line_no))
            projection.stages.append(current)
            current = None
            continue
        if current is None or current.attrs is not None:
            raise FormatError(f"line {line_no}: unexpected v1 record line")
        raise FormatError(f"line {line_no}: v1 projection expects @END, got {head!r}")
    if projection.meta is None:
        raise FormatError("v1 projection has no META")
    _validate_v1_meta(projection.meta.kv, meta_line)
    if current is not None:
        raise FormatError(f"v1 projection ends before @SNAP for seq {current.seq}")
    return projection


V1_KIND_MATCH = "MATCH"
V1_KIND_STAGE = "V1_STAGE_SEQUENCE_DIVERGENCE"
V1_KIND_RESULT = "V1_RESULT_COUNT_DIVERGENCE"
V1_KIND_OP = "V1_OP_LINE_DIVERGENCE"


def _mask_v1_unique(value):
    return re.sub(r"u:(?:0x)?[0-9a-fA-F]+:(\d+)", r"u:*:\1", value)


def _v1_stage_key(stage):
    return (stage.round, stage.seq, stage.path)


def _v1_op_key(op, relax_unique=False):
    output = _mask_v1_unique(op.output) if relax_unique else op.output
    inputs = tuple(_mask_v1_unique(value) for value in op.inputs) if relax_unique else op.inputs
    return (op.location, op.opcode, op.dead, output, inputs)


def _v1_meta_warnings(left, right):
    warnings = []
    left_meta = left.meta.kv
    right_meta = right.meta.kv
    for key in sorted(set(left_meta) | set(right_meta)):
        if key == "side":
            continue
        if left_meta.get(key) != right_meta.get(key):
            warnings.append(
                f"META {key} differs (left={left_meta.get(key)!r}, "
                f"right={right_meta.get(key)!r})"
            )
    return warnings


def _v1_context_diff(left_ops, right_ops, index, context=3):
    """Return a unified-diff excerpt centered on the first differing op."""
    start = max(0, index - context)
    stop = min(max(len(left_ops), len(right_ops)), index + context + 1)
    left_lines = [op.raw for op in left_ops[start:stop]]
    right_lines = [op.raw for op in right_ops[start:stop]]
    return list(difflib.unified_diff(
        left_lines,
        right_lines,
        fromfile="oracle op-lines",
        tofile="rugra op-lines",
        n=context,
        lineterm="",
    ))


def _v1_report(left, right, kind, stage_index=None, op_index=None,
               differing=None, warnings=None, relax_unique=False):
    warnings = list(warnings or [])
    report = {
        "schema": SCHEMA,
        "tool": TOOL,
        "version": "v1.1",
        "kind": kind,
        "relax_unique": relax_unique,
        "left": {"file": left.name, "stages": len(left.stages), "records": left.records},
        "right": {"file": right.name, "stages": len(right.stages), "records": right.records},
        "warnings": warnings,
    }
    if stage_index is None:
        report["attribution"] = "v1.1 projections are stage and snapshot identical"
        return report
    ls = left.stages[stage_index] if stage_index < len(left.stages) else None
    rs = right.stages[stage_index] if stage_index < len(right.stages) else None
    ref = ls or rs
    report["stage"] = {
        "index": stage_index,
        "round": {"left": ls.round if ls else None, "right": rs.round if rs else None},
        "ordinal": {"left": ls.seq if ls else None, "right": rs.seq if rs else None},
        "tree_path": {"left": ls.path if ls else None, "right": rs.path if rs else None},
    }
    if kind == V1_KIND_STAGE:
        report["attribution"] = "stage sequence differs: round, ordinal, or tree topology diverged"
        report["left_stage"] = _v1_stage_key(ls) if ls else None
        report["right_stage"] = _v1_stage_key(rs) if rs else None
    elif kind == V1_KIND_RESULT:
        report["attribution"] = "stage completion result/count/tests/apply differs"
        report["end"] = {
            "left": dict(ls.attrs) if ls else None,
            "right": dict(rs.attrs) if rs else None,
            "differing": differing or {},
        }
    else:
        report["attribution"] = "snapshot operation line differs"
        report["op_index"] = op_index
        report["op_line"] = {
            "left": ls.ops[op_index].raw if ls and op_index < len(ls.ops) else None,
            "right": rs.ops[op_index].raw if rs and op_index < len(rs.ops) else None,
        }
        report["unified_diff"] = _v1_context_diff(
            ls.ops if ls else [], rs.ops if rs else [], op_index
        )
    return report


def compare_v1_projections(left, right, relax_unique=False):
    """Compare v1.1 application stages, then @END attributes, then @SNAP ops."""
    warnings = _v1_meta_warnings(left, right)
    if left.meta.kv.get("unique_base") != right.meta.kv.get("unique_base"):
        warnings.append("META unique_base differs; strict op offsets remain observable")
    shared = min(len(left.stages), len(right.stages))
    for index in range(shared):
        ls, rs = left.stages[index], right.stages[index]
        if _v1_stage_key(ls) != _v1_stage_key(rs):
            return _v1_report(left, right, V1_KIND_STAGE, index, warnings=warnings,
                              relax_unique=relax_unique)
        differing = {
            key: {"left": ls.attrs.get(key), "right": rs.attrs.get(key)}
            for key in ("result", "count", "tests", "apply")
            if ls.attrs.get(key) != rs.attrs.get(key)
        }
        if differing:
            return _v1_report(left, right, V1_KIND_RESULT, index, differing=differing,
                              warnings=warnings, relax_unique=relax_unique)
        op_count = min(len(ls.ops), len(rs.ops))
        for op_index in range(op_count):
            if _v1_op_key(ls.ops[op_index], relax_unique) != _v1_op_key(rs.ops[op_index], relax_unique):
                return _v1_report(left, right, V1_KIND_OP, index, op_index=op_index,
                                  warnings=warnings, relax_unique=relax_unique)
        if len(ls.ops) != len(rs.ops):
            return _v1_report(left, right, V1_KIND_OP, index, op_index=op_count,
                              warnings=warnings, relax_unique=relax_unique)
    if len(left.stages) != len(right.stages):
        return _v1_report(left, right, V1_KIND_STAGE, shared, warnings=warnings,
                          relax_unique=relax_unique)
    return _v1_report(left, right, V1_KIND_MATCH, warnings=warnings,
                      relax_unique=relax_unique)


def human_v1_report(report, context=3):
    lines = ["== stage_bisect v1.1: first divergence =="]
    lines.append(f"left:  {report['left']['file']} (stages={report['left']['stages']}, ops={report['left']['records']})")
    lines.append(f"right: {report['right']['file']} (stages={report['right']['stages']}, ops={report['right']['records']})")
    for warning in report.get("warnings", []):
        lines.append(f"warning: {warning}")
    lines.append(f"kind: {report['kind']}")
    if report["kind"] == V1_KIND_MATCH:
        lines.append(report["attribution"])
        return "\n".join(lines)
    stage = report["stage"]
    lines.append(f"round: oracle={stage['round']['left']} rugra={stage['round']['right']}")
    lines.append(f"stage ordinal: oracle={stage['ordinal']['left']} rugra={stage['ordinal']['right']}")
    lines.append(f"tree-path: oracle={stage['tree_path']['left']} rugra={stage['tree_path']['right']}")
    if report["kind"] == V1_KIND_RESULT:
        lines.append(f"result/count: {report['end']['differing']}")
    elif report["kind"] == V1_KIND_OP:
        lines.append(f"op-line index: {report['op_index']}")
        lines.extend(report.get("unified_diff", []))
    lines.append(f"attribution: {report['attribution']}")
    return "\n".join(lines)


def split_escaped(text):
    """Split text at the first unescaped '|'.

    Returns (before, after); raises FormatError when no unescaped separator
    exists or when a trailing lone backslash precedes the end of the string.
    """
    out = []
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if ch == "\\":
            if i + 1 >= length:
                raise FormatError(f"dangling escape at end of field: {text!r}")
            if text[i + 1] == "|":
                out.append("|")
            elif text[i + 1] == "\\":
                out.append("\\")
            else:
                raise FormatError(
                    f"unknown escape \\{text[i + 1]!r} in field: {text!r}"
                )
            i += 2
            continue
        if ch == "|":
            before = "".join(out)
            after_unescaped = unescape(text[i + 1 :])
            return before, after_unescaped
        out.append(ch)
        i += 1
    raise FormatError(f"missing unescaped '|' separator in record: {text!r}")


def unescape(text):
    out = []
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if ch == "\\":
            if i + 1 >= length:
                raise FormatError(f"dangling escape at end of field: {text!r}")
            if text[i + 1] == "|":
                out.append("|")
            elif text[i + 1] == "\\":
                out.append("\\")
            else:
                raise FormatError(
                    f"unknown escape \\{text[i + 1]!r} in field: {text!r}"
                )
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def parse_key_values(tokens, line_no, raw, what):
    kv = {}
    for token in tokens:
        if "=" not in token:
            raise FormatError(
                f"line {line_no}: {what} expects key=value tokens, got {token!r}"
                f" in: {raw!r}"
            )
        key, value = token.split("=", 1)
        if not key or not value:
            raise FormatError(
                f"line {line_no}: empty key or value in token {token!r}"
                f" in: {raw!r}"
            )
        if key in kv:
            raise FormatError(
                f"line {line_no}: duplicate key {key!r} in: {raw!r}"
            )
        kv[key] = value
    return kv


def parse_line(line, line_no):
    """Parse one non-empty, non-comment line into Meta/Boundary/Record."""
    stripped = line.strip()
    if stripped.startswith("META"):
        tokens = stripped.split()[1:]
        kv = parse_key_values(tokens, line_no, stripped, "META")
        return Meta(kv, line_no, stripped)
    if stripped.startswith("@"):
        tokens = stripped.split()
        head = tokens[0]
        if head == "@RESTART":
            if len(tokens) != 2:
                raise FormatError(
                    f"line {line_no}: @RESTART expects one integer, got: {stripped!r}"
                )
            value = tokens[1]
            if not value.isdigit():
                raise FormatError(
                    f"line {line_no}: @RESTART expects an integer, got {value!r}"
                )
            return Boundary("RESTART", "", {"curstart": value}, line_no, stripped)
        if head not in ("@BEGIN", "@END", "@CONVERGED"):
            raise FormatError(
                f"line {line_no}: unknown boundary marker {head!r} in: {stripped!r}"
            )
        if len(tokens) < 2:
            raise FormatError(
                f"line {line_no}: {head} expects a stage path in: {stripped!r}"
            )
        path = tokens[1]
        if not PATH_RE.match(path):
            raise FormatError(
                f"line {line_no}: invalid stage path {path!r} in: {stripped!r}"
            )
        kv = parse_key_values(tokens[2:], line_no, stripped, head)
        if head == "@CONVERGED":
            if "changes" in kv and kv["changes"] != "0":
                raise FormatError(
                    f"line {line_no}: @CONVERGED with changes={kv['changes']!r}"
                    f" (must be 0): {stripped!r}"
                )
            kv.setdefault("changes", "0")
            return Boundary("END", path, kv, line_no, stripped)
        if head == "@BEGIN":
            return Boundary("BEGIN", path, kv, line_no, stripped)
        return Boundary("END", path, kv, line_no, stripped)
    # Record line: <seq> <action_path> <before>|<after>
    parts = stripped.split(None, 2)
    if len(parts) < 3:
        raise FormatError(
            f"line {line_no}: record expects '<seq> <action_path> <before>|<after>',"
            f" got: {stripped!r}"
        )
    seq_text, path, rest = parts
    if not seq_text.isdigit():
        raise FormatError(
            f"line {line_no}: sequence number must be a decimal integer, got"
            f" {seq_text!r} in: {stripped!r}"
        )
    if not PATH_RE.match(path):
        raise FormatError(
            f"line {line_no}: invalid action path {path!r} in: {stripped!r}"
        )
    before, after = split_escaped(rest)
    return Record(int(seq_text), path, before, after, line_no, stripped)


class Projection:
    """Parsed projection file plus derived per-item round state."""

    def __init__(self, name, path):
        self.name = name
        self.path = path
        self.meta = None  # first META line if present
        self.items = []  # Boundary | Record in stream order
        self.item_rounds = []  # (restart:int, passes:dict) parallel to items

    @property
    def records(self):
        return sum(1 for item in self.items if isinstance(item, Record))

    @property
    def boundaries(self):
        return sum(1 for item in self.items if isinstance(item, Boundary))

    def derive_rounds(self):
        restart = 0
        passes = {}
        for item in self.items:
            if isinstance(item, Boundary):
                if item.kind == "RESTART":
                    restart = int(item.kv["curstart"])
                    passes = {}
                else:
                    if item.kind == "BEGIN":
                        passes[item.path] = passes.get(item.path, 0) + 1
            self.item_rounds.append((restart, dict(passes)))

    def counters_for_path(self, index):
        """Latest boundary kv for the item's own path at or before index."""
        if not 0 <= index < len(self.items):
            return {}
        path = self.items[index].path
        for item in reversed(self.items[: index + 1]):
            if isinstance(item, Boundary) and item.path == path:
                return dict(item.kv)
        return {}

    def last_boundary_before(self, index):
        for pos in range(index - 1, -1, -1):
            item = self.items[pos]
            if isinstance(item, Boundary):
                return pos, item
        return None, None


def load_projection(file_path):
    path = Path(file_path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FormatError(f"cannot read {path}: {exc}") from exc
    projection = Projection(str(path), path)
    stream_started = False
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        item = parse_line(stripped, line_no)
        if isinstance(item, Meta):
            if stream_started:
                raise FormatError(
                    f"line {line_no}: META line after stream start in {path}"
                )
            if projection.meta is None:
                projection.meta = item
            continue
        stream_started = True
        projection.items.append(item)
    projection.derive_rounds()
    return projection


def mask_unique(text):
    """Mask unique-space varnode ids (triage aid only, not alignment evidence).

    "uni2a" -> "uni*", "unique123" -> "unique*", "u_9" -> "u_*": the space
    spelling is kept so that remaining real differences stay visible.
    """
    return UNIQUE_RE.sub(
        lambda m: re.sub(r"[0-9a-fA-F]+$", "*", m.group(0)), text
    )


def compare_projections(left, right, relax_unique=False):
    """Positionally compare both item streams; return the report dict."""
    warnings = []
    if left.meta and right.meta:
        for key in sorted(set(left.meta.kv) | set(right.meta.kv)):
            lv = left.meta.kv.get(key)
            rv = right.meta.kv.get(key)
            if lv != rv:
                warnings.append(
                    f"META {key} differs (left={lv!r}, right={rv!r}); the "
                    "comparison may be meaningless if func/arch differ"
                )
    elif left.meta is None or right.meta is None:
        warnings.append("META line missing on at least one side")

    relax_before = relax_after = (lambda s: s)
    if relax_unique:
        relax_before = relax_after = mask_unique

    count = min(len(left.items), len(right.items))
    for index in range(count):
        li = left.items[index]
        ri = right.items[index]
        left_is_boundary = isinstance(li, Boundary)
        right_is_boundary = isinstance(ri, Boundary)
        if left_is_boundary != right_is_boundary:
            return build_report(
                left, right, index, KIND_STREAM, warnings, relax_unique
            )
        if left_is_boundary:
            diff = boundary_diff(li, ri)
            if diff is not None:
                return build_report(
                    left, right, index, KIND_BOUNDARY, warnings,
                    relax_unique, boundary_diff=diff,
                )
            continue
        if li.seq != ri.seq:
            return build_report(
                left, right, index, KIND_SEQ, warnings, relax_unique
            )
        if li.path != ri.path:
            return build_report(
                left, right, index, KIND_PATH, warnings, relax_unique
            )
        if relax_before(li.before) != relax_before(ri.before):
            return build_report(
                left, right, index, KIND_BEFORE, warnings, relax_unique
            )
        if relax_after(li.after) != relax_after(ri.after):
            return build_report(
                left, right, index, KIND_AFTER, warnings, relax_unique
            )
    if len(left.items) != len(right.items):
        return build_report(
            left, right, count, KIND_LENGTH, warnings, relax_unique
        )
    return build_report(left, right, None, KIND_MATCH, warnings, relax_unique)


def boundary_diff(left, right):
    """Return None when equal, else a dict describing the mismatch."""
    if left.kind != right.kind:
        return {
            "field": "kind",
            "left": left.kind,
            "right": right.kind,
            "detail": f"@{left.kind} vs @{right.kind}",
        }
    if left.path != right.path:
        return {
            "field": "path",
            "left": left.path,
            "right": right.path,
            "detail": f"path {left.path!r} vs {right.path!r}",
        }
    differing = {}
    for key in sorted(set(left.kv) | set(right.kv)):
        lv = left.kv.get(key)
        rv = right.kv.get(key)
        if lv != rv:
            differing[key] = {"left": lv, "right": rv}
    if differing:
        return {
            "field": "counters",
            "left": dict(left.kv),
            "right": dict(right.kv),
            "detail": "; ".join(
                f"{key}: left={entry['left']!r} right={entry['right']!r}"
                for key, entry in differing.items()
            ),
            "differing": differing,
        }
    return None


def round_state(projection, index, path):
    """Snapshot (restart, ancestor passes) for the item at index."""
    if index >= len(projection.item_rounds):
        return {"restart": 0, "passes": {}}
    restart, passes = projection.item_rounds[index]
    ancestors = ancestor_paths(path)
    filtered = {k: v for k, v in passes.items() if k in ancestors}
    return {"restart": restart, "passes": filtered}


def ancestor_paths(path):
    parts = path.split(":")
    return {":".join(parts[: i + 1]) for i in range(len(parts))} if path else set()


def item_path(item):
    return item.path


def build_report(
    left, right, index, kind, warnings, relax_unique, boundary_diff=None
):
    report = {
        "schema": SCHEMA,
        "tool": TOOL,
        "relax_unique": relax_unique,
        "kind": kind,
        "index": index,
        "left": {
            "file": left.name,
            "meta": dict(left.meta.kv) if left.meta else None,
            "records": left.records,
            "boundaries": left.boundaries,
        },
        "right": {
            "file": right.name,
            "meta": dict(right.meta.kv) if right.meta else None,
            "records": right.records,
            "boundaries": right.boundaries,
        },
        "warnings": warnings,
    }
    if kind == KIND_MATCH:
        report["attribution"] = (
            "Projections are item-for-item identical"
            + (" after unique-id masking (triage only, not alignment evidence)"
               if relax_unique else "")
            + "."
        )
        return report

    report["attribution"] = ATTRIBUTIONS[kind]
    li = left.items[index] if index is not None and index < len(left.items) else None
    ri = right.items[index] if index is not None and index < len(right.items) else None
    report["left_item"] = describe_item(li)
    report["right_item"] = describe_item(ri)

    ref = li or ri
    path = ref.path if ref is not None else ""
    if kind == KIND_LENGTH:
        shorter = left if len(left.items) < len(right.items) else right
        pos, boundary = shorter.last_boundary_before(len(shorter.items))
        report["stage"] = {
            "path": boundary.path if boundary else "",
            "round": (
                round_state(shorter, pos, boundary.path) if boundary is not None
                else {"restart": 0, "passes": {}}
            ),
            "detail": (
                f"{shorter.name} ended after item {len(shorter.items)}"
                f" (last boundary: {boundary.raw})" if boundary is not None
                else f"{shorter.name} ended after item {len(shorter.items)}"
            ),
        }
    else:
        report["stage"] = {
            "path": path,
            "round": {
                "left": round_state(left, index, path),
                "right": round_state(right, index, path),
            },
            "counters": {
                "left": left.counters_for_path(index),
                "right": right.counters_for_path(index),
            },
        }
    if boundary_diff is not None:
        report["boundary_diff"] = boundary_diff
    pos, boundary = left.last_boundary_before(index if index is not None else 0)
    if boundary is not None:
        report["last_good_boundary"] = {
            "raw": boundary.raw,
            "kind": boundary.kind,
            "path": boundary.path,
            "counters": dict(boundary.kv),
            "round": round_state(left, pos, boundary.path),
        }
    else:
        report["last_good_boundary"] = None
    return report


def describe_item(item):
    if item is None:
        return None
    if isinstance(item, Boundary):
        return {
            "type": "boundary",
            "kind": item.kind,
            "path": item.path,
            "counters": dict(item.kv),
            "line": item.line_no,
            "raw": item.raw,
        }
    return {
        "type": "record",
        "seq": item.seq,
        "path": item.path,
        "before": item.before,
        "after": item.after,
        "line": item.line_no,
        "raw": item.raw,
    }


def human_report(report, context=6):
    lines = []
    kind = report["kind"]
    left = report["left"]
    right = report["right"]
    lines.append("== stage_bisect: first divergence ==")
    lines.append(
        f"left:  {left['file']} (records={left['records']},"
        f" boundaries={left['boundaries']})"
    )
    lines.append(
        f"right: {right['file']} (records={right['records']},"
        f" boundaries={right['boundaries']})"
    )
    for warning in report["warnings"]:
        lines.append(f"warning: {warning}")
    if report.get("relax_unique"):
        lines.append(
            "note: --relax-unique active; unique-id masking is triage only and"
            " is not alignment evidence"
        )
    if kind == KIND_MATCH:
        lines.append("kind: MATCH")
        lines.append(f"attribution: {report['attribution']}")
        return "\n".join(lines)

    index = report["index"]
    lines.append(f"kind:  {kind}")
    lines.append(f"index: {index}")
    stage = report["stage"]
    if kind == KIND_LENGTH:
        lines.append(f"stage: {stage['detail']}")
        if stage.get("path"):
            rr = stage["round"]
            passes = ", ".join(f"{k}:{v}" for k, v in sorted(rr["passes"].items()))
            lines.append(
                f"round: restart={rr['restart']}"
                + (f" passes={{{passes}}}" if passes else "")
            )
    else:
        li = report["left_item"] or {}
        ri = report["right_item"] or {}
        lines.append(f"stage: {stage['path']}")
        rl = stage["round"]["left"]
        passes = ", ".join(f"{k}:{v}" for k, v in sorted(rl["passes"].items()))
        lines.append(
            f"round: restart={rl['restart']}"
            + (f" passes={{{passes}}}" if passes else "")
        )
        if li.get("type") == "record":
            lines.append(f"seq:   left={li.get('seq')} right={ri.get('seq')}")
        counters = stage["counters"]
        for side, entry in (("left", counters["left"]), ("right", counters["right"])):
            rendered = " ".join(
                f"{k}={v}" for k, v in sorted(entry.items())
            ) or "(none)"
            lines.append(f"counters[{side}]: {rendered}")
        if "boundary_diff" in report:
            lines.append(f"boundary_diff: {report['boundary_diff']['detail']}")
        if li.get("type") == "record":
            lines.append(f"line:  left={li.get('line')} right={ri.get('line')}")
            lines.append(f"before (left):  {li.get('before')}")
            lines.append(f"before (right): {ri.get('before')}")
            lines.append(f"after  (left):  {li.get('after')}")
            lines.append(f"after  (right): {ri.get('after')}")
    good = report.get("last_good_boundary")
    if good:
        lines.append(f"last good boundary: {good['raw']}")
    else:
        lines.append("last good boundary: (none; divergence at stream start)")
    lines.append(f"attribution: {report['attribution']}")
    left_projection = report.get("_left_projection")
    right_projection = report.get("_right_projection")
    if context > 0 and index is not None and left_projection and right_projection:
        lines.append(f"context (left, up to {context} items before):")
        lines.extend(context_lines(left_projection, index, context))
        lines.append(f"context (right, up to {context} items before):")
        lines.extend(context_lines(right_projection, index, context))
    return "\n".join(lines)


def context_lines(projection, index, count):
    start = max(0, index - count)
    out = []
    for pos in range(start, index):
        item = projection.items[pos]
        marker = "  | "
        out.append(f"{pos:>6}{marker}{item.raw}")
    return out


def json_report(report):
    payload = {k: v for k, v in report.items() if not k.startswith("_")}
    return json.dumps(payload, indent=2, sort_keys=False, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Selftest: synthetic projections with known divergence points.
# ---------------------------------------------------------------------------

COMMON_PREFIX = [
    "META side=ghidra commit=e40ed13014025f82488b1f8f7bca566894ac376b "
    "func=FUN_00401000 arch=x86:LE:64:default",
    "@BEGIN universal",
    "@END universal changes=0",
    "@BEGIN universal:fullloop:mainloop",
    "@BEGIN universal:fullloop:mainloop:ActionHeritage",
    "0 universal:fullloop:mainloop:ActionHeritage "
    "00401000: (COPY,3) uni1 = ECX|00401000: (COPY,3) uni1 = uni9",
    "@END universal:fullloop:mainloop:ActionHeritage changes=1 tests=1 apply=1",
    "@END universal:fullloop:mainloop changes=1",
    "@BEGIN universal:fullloop:mainloop",
    "@BEGIN universal:fullloop:mainloop:stackstall",
    "@BEGIN universal:fullloop:mainloop:stackstall:oppool1",
    "@BEGIN universal:fullloop:mainloop:stackstall:oppool1:RulePushPtr",
    "1 universal:fullloop:mainloop:stackstall:oppool1:RulePushPtr "
    "0040102c: (PTRADD,20) uni4 = uni3 4|0040102c: (PTRSUB,20) uni4 = uni3 4",
    "1 universal:fullloop:mainloop:stackstall:oppool1:RulePushPtr "
    "00401033: (PTRADD,21) uni5 = uni3 8|00401033: (PTRSUB,21) uni5 = uni3 8",
    "@END universal:fullloop:mainloop:stackstall:oppool1:RulePushPtr "
    "changes=2 tests=6 apply=2",
]

MAINLOOP_TAIL = [
    "@END universal:fullloop:mainloop:stackstall:oppool1 changes=2",
    "@END universal:fullloop:mainloop:stackstall changes=2",
    "@END universal:fullloop:mainloop changes=2",
    "@CONVERGED universal:fullloop changes=0",
    "@BEGIN universal:ActionMappedLocalSync",
    "2 universal:ActionMappedLocalSync "
    "00401048: (STORE,25) ram00401048 = uni4|00401048: (STORE,25) ram00401048 = uni6",
    "@END universal:ActionMappedLocalSync changes=1 tests=1 apply=1",
]


def make_projection(lines, name="synthetic"):
    """Build a Projection from raw lines via the real load path (temp file)."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / f"{name}.proj"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return load_projection(path)


class SelftestFailure(AssertionError):
    pass


def check(condition, message):
    if not condition:
        raise SelftestFailure(message)


def scenario_after_divergence():
    left = make_projection(
        COMMON_PREFIX
        + [
            "@BEGIN universal:fullloop:mainloop:stackstall:oppool1:RuleRightShift",
            "2 universal:fullloop:mainloop:stackstall:oppool1:RuleRightShift "
            "00401055: (INT_RIGHT,30) uni7 = uni6 3|00401055: (INT_RIGHT,30) uni7 = uni6 1",
        ]
        + MAINLOOP_TAIL,
        "ghidra.proj",
    )
    right_lines = (
        COMMON_PREFIX
        + [
            "@BEGIN universal:fullloop:mainloop:stackstall:oppool1:RuleRightShift",
            "2 universal:fullloop:mainloop:stackstall:oppool1:RuleRightShift "
            "00401055: (INT_RIGHT,30) uni7 = uni6 3|00401055: (INT_RIGHT,30) uni7 = uni6 2",
        ]
        + MAINLOOP_TAIL
    )
    right = make_projection(right_lines, "rugra.proj")
    report = compare_projections(left, right)
    check(report["kind"] == KIND_AFTER, f"expected AFTER, got {report['kind']}")
    # COMMON_PREFIX[0] is the META line (not a stream item); the @BEGIN for
    # RuleRightShift is item len(COMMON_PREFIX)-1, so the record is the next
    # one at len(COMMON_PREFIX).
    expected_index = len(COMMON_PREFIX)
    check(
        report["index"] == expected_index,
        f"expected index {expected_index}, got {report['index']}",
    )
    check(
        report["stage"]["path"]
        == "universal:fullloop:mainloop:stackstall:oppool1:RuleRightShift",
        "stage path mismatch",
    )
    round_left = report["stage"]["round"]["left"]
    check(round_left["restart"] == 0, "restart should be 0")
    check(
        round_left["passes"].get("universal:fullloop:mainloop") == 2
        and round_left["passes"].get(
            "universal:fullloop:mainloop:stackstall:oppool1"
        )
        == 1,
        f"derived passes wrong: {round_left['passes']}",
    )
    check(
        report["left_item"]["before"] == report["right_item"]["before"],
        "before must be identical for AFTER divergence",
    )
    check(
        report["left_item"]["after"].endswith("1")
        and report["right_item"]["after"].endswith("2"),
        "after strings must carry the injected difference",
    )
    check(
        report["last_good_boundary"]["raw"].startswith("@BEGIN universal:fullloop")
        and "RuleRightShift" in report["last_good_boundary"]["raw"],
        f"last good boundary wrong: {report['last_good_boundary']}",
    )
    return report


def scenario_before_divergence():
    prefix = COMMON_PREFIX + [
        "@BEGIN universal:fullloop:mainloop:stackstall:oppool1:RuleRightShift",
    ]
    left = make_projection(
        prefix
        + [
            "2 universal:fullloop:mainloop:stackstall:oppool1:RuleRightShift "
            "00401055: (INT_RIGHT,30) uni7 = uni6 3|00401055: (INT_RIGHT,30) uni7 = uni6 3",
        ]
        + MAINLOOP_TAIL
    )
    right = make_projection(
        prefix
        + [
            "2 universal:fullloop:mainloop:stackstall:oppool1:RuleRightShift "
            "00401055: (INT_RIGHT,30) uni7 = uni6 4|00401055: (INT_RIGHT,30) uni7 = uni6 3",
        ]
        + MAINLOOP_TAIL
    )
    report = compare_projections(left, right)
    check(report["kind"] == KIND_BEFORE, f"expected BEFORE, got {report['kind']}")
    check("bisect back" in report["attribution"], "attribution should direct earlier")
    return report


def scenario_path_divergence():
    prefix = COMMON_PREFIX
    left = make_projection(
        prefix
        + [
            "2 universal:fullloop:mainloop:stackstall:oppool1:RuleRightShift "
            "00401055: (INT_RIGHT,30) uni7 = uni6 3|00401055: (INT_RIGHT,30) uni7 = uni6 3",
        ]
        + MAINLOOP_TAIL
    )
    right = make_projection(
        prefix
        + [
            "2 universal:fullloop:mainloop:stackstall:oppool1:RuleLeftShift "
            "00401055: (INT_RIGHT,30) uni7 = uni6 3|00401055: (INT_RIGHT,30) uni7 = uni6 3",
        ]
        + MAINLOOP_TAIL
    )
    report = compare_projections(left, right)
    check(report["kind"] == KIND_PATH, f"expected PATH, got {report['kind']}")
    return report


def scenario_seq_divergence():
    left = make_projection(
        COMMON_PREFIX
        + [
            "2 universal:ActionMappedLocalSync a|b",
        ]
    )
    right = make_projection(
        COMMON_PREFIX
        + [
            "3 universal:ActionMappedLocalSync a|b",
        ]
    )
    report = compare_projections(left, right)
    check(report["kind"] == KIND_SEQ, f"expected SEQ, got {report['kind']}")
    return report


def scenario_boundary_divergence():
    left = make_projection(
        COMMON_PREFIX
        + [
            "@END universal:fullloop:mainloop:stackstall:oppool1:RulePushPtr "
            "changes=2 tests=6 apply=2",
            "2 universal:ActionMappedLocalSync a|b",
        ],
        "ghidra.proj",
    )
    right = make_projection(
        COMMON_PREFIX
        + [
            "@END universal:fullloop:mainloop:stackstall:oppool1:RulePushPtr "
            "changes=3 tests=6 apply=2",
            "2 universal:ActionMappedLocalSync a|b",
        ],
        "rugra.proj",
    )
    report = compare_projections(left, right)
    check(
        report["kind"] == KIND_BOUNDARY, f"expected BOUNDARY, got {report['kind']}"
    )
    check(
        report["boundary_diff"]["differing"]["changes"]
        == {"left": "2", "right": "3"},
        f"changes diff wrong: {report['boundary_diff']}",
    )
    return report


def scenario_length_divergence():
    left = make_projection(COMMON_PREFIX + MAINLOOP_TAIL)
    right = make_projection(COMMON_PREFIX + MAINLOOP_TAIL[:1])
    report = compare_projections(left, right)
    check(report["kind"] == KIND_LENGTH, f"expected LENGTH, got {report['kind']}")
    check(
        report["index"] == len(COMMON_PREFIX),
        f"expected divergence at first extra item, got {report['index']}",
    )
    return report


def scenario_match():
    lines = COMMON_PREFIX + MAINLOOP_TAIL
    left = make_projection(lines, "ghidra.proj")
    right = make_projection(lines, "rugra.proj")
    report = compare_projections(left, right)
    check(report["kind"] == KIND_MATCH, f"expected MATCH, got {report['kind']}")
    return report


def scenario_escaping_and_pipes():
    left_lines = [
        "META side=ghidra func=F arch=A",
        "0 p:q:RuleOr 0041: (INT_OR,5) v1 = v2 \\| v3|0041: (INT_OR,5) v1 = v2 \\| v3",
        "1 p:q:RuleOr back\\\\slash \\| pipe|ok",
    ]
    left = make_projection(left_lines)
    right = make_projection(left_lines)
    report = compare_projections(left, right)
    check(report["kind"] == KIND_MATCH, f"expected MATCH, got {report['kind']}")
    rec = left.items[0]
    check(
        rec.before == "0041: (INT_OR,5) v1 = v2 | v3"
        and rec.after == "0041: (INT_OR,5) v1 = v2 | v3",
        f"pipe unescaping wrong: before={rec.before!r} after={rec.after!r}",
    )
    rec2 = left.items[1]
    check(
        rec2.before == "back\\slash | pipe" and rec2.after == "ok",
        f"mixed escaping wrong: before={rec2.before!r}",
    )
    # An UNESCAPED pipe inside content does not crash the parser; it silently
    # shifts the split point (documented hazard: generators must escape).
    shifted = parse_line("0 p:q 0041: (INT_OR,5) v1 = v2 | v3|after", 1)
    check(
        isinstance(shifted, Record)
        and shifted.before == "0041: (INT_OR,5) v1 = v2 "
        and shifted.after == " v3|after",
        f"split must stop at the first unescaped pipe: {shifted.after!r}",
    )
    return report


def scenario_converged_canonicalization():
    left = make_projection(
        [
            "@BEGIN universal:fullloop",
            "@CONVERGED universal:fullloop",
            "0 universal:ActionStop a|b",
        ]
    )
    right = make_projection(
        [
            "@BEGIN universal:fullloop",
            "@END universal:fullloop changes=0",
            "0 universal:ActionStop a|b",
        ]
    )
    report = compare_projections(left, right)
    check(report["kind"] == KIND_MATCH, f"expected MATCH, got {report['kind']}")
    return report


def scenario_restart_derivation():
    left = make_projection(
        [
            "META side=ghidra func=F",
            "@BEGIN universal:fullloop:mainloop",
            "@END universal:fullloop:mainloop changes=1",
            "@RESTART 1",
            "@BEGIN universal:fullloop:mainloop",
            "0 universal:fullloop:mainloop:ActionHeritage a|b",
            "@END universal:fullloop:mainloop:ActionHeritage changes=1",
            "@END universal:fullloop:mainloop changes=1",
        ]
    )
    right = make_projection(
        [
            "META side=rugra func=F",
            "@BEGIN universal:fullloop:mainloop",
            "@END universal:fullloop:mainloop changes=1",
            "@RESTART 1",
            "@BEGIN universal:fullloop:mainloop",
            "0 universal:fullloop:mainloop:ActionHeritage a|b",
            "@END universal:fullloop:mainloop:ActionHeritage changes=1",
            "@END universal:fullloop:mainloop changes=1",
        ]
    )
    report = compare_projections(left, right)
    check(report["kind"] == KIND_MATCH, "restart scenario should match")
    restart, passes = left.item_rounds[4]
    check(restart == 1, f"restart must be 1 after @RESTART, got {restart}")
    check(
        passes.get("universal:fullloop:mainloop") == 1,
        f"passes must reset on @RESTART, got {passes}",
    )
    check(len(report["warnings"]) == 1 and "side" in report["warnings"][0],
          f"meta side mismatch should warn: {report['warnings']}")
    return report


def scenario_relax_unique():
    base = [
        "META side=ghidra func=F",
        "0 p:q:RuleX 0041: (COPY,3) uni10 = uni20|0041: (COPY,3) uni10 = uni21",
    ]
    left = make_projection(base)
    right = make_projection(
        [
            "META side=rugra func=F",
            "0 p:q:RuleX 0041: (COPY,3) uni10 = uni20|0041: (COPY,3) uni10 = uni2a",
        ]
    )
    strict = compare_projections(left, right)
    check(strict["kind"] == KIND_AFTER, "strict mode must see unique-id diff")
    relaxed = compare_projections(left, right, relax_unique=True)
    check(relaxed["kind"] == KIND_MATCH, f"relax must mask unique ids: {relaxed['kind']}")
    # A real opcode difference must survive relaxation.
    left2 = make_projection(
        [
            "META side=ghidra func=F",
            "0 p:q:RuleX (COPY,3) uni10 = uni20|(COPY,3) uni10 = uni20",
        ]
    )
    right2 = make_projection(
        [
            "META side=rugra func=F",
            "0 p:q:RuleX (COPY,3) uni10 = uni20|(LOAD,3) uni10 = uni20",
        ]
    )
    still = compare_projections(left2, right2, relax_unique=True)
    check(still["kind"] == KIND_AFTER, "real diffs must survive relax_unique")
    return relaxed


def scenario_json_output():
    block_left = [
        "@BEGIN universal:fullloop:mainloop:stackstall:oppool1:RuleRightShift",
        "2 universal:fullloop:mainloop:stackstall:oppool1:RuleRightShift "
        "00401055: (INT_RIGHT,30) uni7 = uni6 3|00401055: (INT_RIGHT,30) uni7 = uni6 1",
    ]
    block_right = [
        "@BEGIN universal:fullloop:mainloop:stackstall:oppool1:RuleRightShift",
        "2 universal:fullloop:mainloop:stackstall:oppool1:RuleRightShift "
        "00401055: (INT_RIGHT,30) uni7 = uni6 3|00401055: (INT_RIGHT,30) uni7 = uni6 9",
    ]
    left = make_projection(COMMON_PREFIX + block_left + MAINLOOP_TAIL)
    right = make_projection(COMMON_PREFIX + block_right + MAINLOOP_TAIL)
    report = compare_projections(left, right)
    payload = json.loads(json_report(report))
    for key in (
        "schema", "tool", "kind", "index", "left", "right",
        "stage", "last_good_boundary", "attribution",
    ):
        check(key in payload, f"json report missing key {key}")
    check(payload["kind"] == KIND_AFTER, "json kind must be AFTER")
    # MATCH report also round-trips.
    ok = json.loads(json_report(compare_projections(left, left)))
    check(ok["kind"] == KIND_MATCH, "match json must round-trip")
    return payload


def scenario_format_errors():
    bad_lines = [
        ("notanumber p:q a|b", "non-decimal seq"),
        ("123 p!q a|b", "invalid path charset"),
        ("123 p:q no separator here", "missing separator"),
        ("123 p:q dangling\\", "dangling escape"),
        ("123 p:q bad\\x escape|after", "unknown escape"),
        ("@BEGIN", "BEGIN without path"),
        ("@END p:q badtoken", "boundary token without ="),
        ("@END p:q =2", "empty key"),
        ("@RESTART x", "RESTART with non-integer"),
        ("@RESTART 1 2", "RESTART with extra token"),
        ("@CONVERGED p:q changes=2", "CONVERGED with nonzero changes"),
    ]
    for line, why in bad_lines:
        try:
            parse_line(line, 1)
            ok = False
        except FormatError:
            ok = True
        check(ok, f"line must be rejected ({why}): {line!r}")
    # Later unescaped pipes stay literal inside the after field.
    item = parse_line("123 p:q a|b\\|c", 1)
    check(
        isinstance(item, Record) and item.after == "b|c",
        f"after must keep later pipes literal: {item.after!r}",
    )
    # Duplicate boundary keys are rejected.
    try:
        parse_line("@END p:q changes=1 changes=2", 1)
        ok = False
    except FormatError:
        ok = True
    check(ok, "duplicate boundary keys must be rejected")
    return True


V1_META = [
    "META side=oracle oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b",
    "META arch=x86:LE:64:default cspec=default analysis_options=stable",
    "META build_flags=v1-no-OPACTION_DEBUG binary_sha256=" + "a" * 64,
    "META func_entry=0x401000 func_name=FUN_00401000 load_mode=single_function_bfd",
    "META producer=synthetic maxrestarts=1 unique_base=0x1000",
]


def v1_ops(constant="0x1", opcode="COPY", swapped=False):
    values = [
        "401000:1 COPY d=0 out=u:1000:8 in=c:1:8",
        "401004:2 LOAD d=0 out=n:ram:2000:8 in=u:1008:8",
        f"401008:3 {opcode} d=0 out=u:{'1010' if not swapped else '1020'}:8 in=u:{'1020' if not swapped else '1010'}:8",
        f"40100c:4 INT_ADD d=1 out=- in=c:{constant}:8,c:2:8",
        "401010:5 STORE d=0 out=- in=n:ram:2000:8,u:1010:8",
    ]
    return values


def make_v1_lines(stages, side="oracle", meta=None):
    header = list(meta or V1_META)
    header = [line.replace("side=oracle", f"side={side}") for line in header]
    result = header[:]
    for stage in stages:
        result.extend([
            f"@BEGIN {stage['seq']} {stage['path']}",
            f"@END {stage['seq']} {stage['path']} result={stage.get('result', 0)} "
            f"count={stage.get('count', 1)} tests={stage.get('tests', len(stage['ops']))} "
            f"apply={stage.get('apply', 1)}",
            f"@SNAP {stage['seq']} ops {len(stage['ops'])}",
            *stage["ops"],
        ])
        if stage.get("restart") is not None:
            result.append(f"@RESTART {stage['restart']}")
    return result


def make_v1_projection(lines, name="synthetic-v1"):
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / f"{name}.proj"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return load_v1_projection(path)


def v1_base_stages():
    return [{"seq": 1, "path": "universal:fullloop", "ops": v1_ops()}]


def scenario_v1_match():
    stages = v1_base_stages()
    left = make_v1_projection(make_v1_lines(stages, "oracle"), "oracle-v1")
    right = make_v1_projection(make_v1_lines(stages, "rugra"), "rugra-v1")
    report = compare_v1_projections(left, right)
    check(report["kind"] == V1_KIND_MATCH, "v1 identical snapshots must match")
    return report


def scenario_v1_stage_count():
    left_stages = v1_base_stages()
    right_stages = left_stages + [{"seq": 2, "path": "universal:fullloop:child", "ops": []}]
    report = compare_v1_projections(
        make_v1_projection(make_v1_lines(left_stages), "oracle-v1"),
        make_v1_projection(make_v1_lines(right_stages, "rugra"), "rugra-v1"),
    )
    check(report["kind"] == V1_KIND_STAGE, "stage count must be a sequence divergence")
    check(report["stage"]["ordinal"]["right"] == 2, "missing stage ordinal must be reported")
    return report


def scenario_v1_op_content():
    left = v1_base_stages()
    right = v1_base_stages()
    right[0] = dict(right[0], ops=v1_ops(constant="0x9"))
    report = compare_v1_projections(
        make_v1_projection(make_v1_lines(left), "oracle-v1"),
        make_v1_projection(make_v1_lines(right, "rugra"), "rugra-v1"),
    )
    check(report["kind"] == V1_KIND_OP and report["op_index"] == 3, "constant op diff missing")
    check(any(line.startswith("@@") for line in report["unified_diff"]), "unified context missing")
    return report


def scenario_v1_opcode_name():
    left = v1_base_stages()
    right = v1_base_stages()
    right[0] = dict(right[0], ops=v1_ops(opcode="COPY_ALT"))
    report = compare_v1_projections(
        make_v1_projection(make_v1_lines(left), "oracle-v1"),
        make_v1_projection(make_v1_lines(right, "rugra"), "rugra-v1"),
    )
    check(report["kind"] == V1_KIND_OP and report["op_index"] == 2, "opcode diff missing")
    return report


def scenario_v1_unique_and_empty_slots():
    left_ops = v1_ops(swapped=False)
    right_ops = v1_ops(swapped=True)
    # Keep the no-output/no-input spelling observable while swapping only the
    # original unique offsets in one op.
    left = make_v1_projection(make_v1_lines([{"seq": 1, "path": "universal", "ops": left_ops}]))
    right = make_v1_projection(make_v1_lines([{"seq": 1, "path": "universal", "ops": right_ops}], "rugra"))
    check(left.stages[0].ops[3].output == "-" and left.stages[0].ops[3].inputs[0].startswith("c:"),
          "empty output slot must parse")
    report = compare_v1_projections(left, right)
    check(report["kind"] == V1_KIND_OP and report["op_index"] == 2,
          "unique original offset position swap must remain visible")
    relaxed = compare_v1_projections(left, right, relax_unique=True)
    check(relaxed["kind"] == V1_KIND_MATCH, "relax-unique should be triage-only")
    return report


def scenario_v1_result_count():
    left = v1_base_stages()
    right = [dict(left[0], count=2)]
    report = compare_v1_projections(
        make_v1_projection(make_v1_lines(left), "oracle-v1"),
        make_v1_projection(make_v1_lines(right, "rugra"), "rugra-v1"),
    )
    check(report["kind"] == V1_KIND_RESULT, "count mismatch must be result/count divergence")
    return report


def scenario_v1_restart_interleaving():
    stages = [
        {"seq": 1, "path": "universal", "ops": v1_ops()[:1]},
        {"seq": 2, "path": "universal:fullloop", "ops": v1_ops()[1:2], "restart": 1},
        {"seq": 3, "path": "universal:fullloop:child", "ops": v1_ops()[2:3]},
    ]
    left = make_v1_projection(make_v1_lines(stages), "oracle-v1")
    right = make_v1_projection(make_v1_lines(stages, "rugra"), "rugra-v1")
    report = compare_v1_projections(left, right)
    check(report["kind"] == V1_KIND_MATCH, "interleaved group/restart sequence must match")
    check(left.stages[2].round == 1, "curstart must be attached as zero-based round")
    return report


def run_selftest():
    scenarios = [
        ("after_divergence", scenario_after_divergence),
        ("before_divergence", scenario_before_divergence),
        ("path_divergence", scenario_path_divergence),
        ("seq_divergence", scenario_seq_divergence),
        ("boundary_divergence", scenario_boundary_divergence),
        ("length_divergence", scenario_length_divergence),
        ("match", scenario_match),
        ("escaping_and_pipes", scenario_escaping_and_pipes),
        ("converged_canonicalization", scenario_converged_canonicalization),
        ("restart_derivation", scenario_restart_derivation),
        ("relax_unique", scenario_relax_unique),
        ("json_output", scenario_json_output),
        ("format_errors", scenario_format_errors),
        ("v1_match", scenario_v1_match),
        ("v1_stage_count", scenario_v1_stage_count),
        ("v1_op_content", scenario_v1_op_content),
        ("v1_opcode_name", scenario_v1_opcode_name),
        ("v1_unique_and_empty_slots", scenario_v1_unique_and_empty_slots),
        ("v1_result_count", scenario_v1_result_count),
        ("v1_restart_interleaving", scenario_v1_restart_interleaving),
    ]
    passed = 0
    failures = []
    for name, func in scenarios:
        try:
            func()
            passed += 1
            print(f"PASS {name}")
        except Exception as exc:  # noqa: BLE001 - report every failure
            failures.append((name, exc))
            print(f"FAIL {name}: {exc}")
    total = len(scenarios)
    print(f"stage_bisect selftest: {passed}/{total} scenarios passed")
    if failures:
        for name, exc in failures:
            print(f"  failed: {name}: {exc}", file=sys.stderr)
        return 1
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def emit_harness(output=None):
    skeleton = Path(__file__).resolve().parent / "stage_bisect_projection.cc"
    try:
        text = skeleton.read_text(encoding="utf-8")
    except OSError as exc:
        print(
            f"error: cannot read harness skeleton {skeleton}: {exc}",
            file=sys.stderr,
        )
        return 2
    if output:
        Path(output).write_text(text, encoding="utf-8")
        print(f"wrote {output}")
    else:
        sys.stdout.write(text)
    return 0


def format_spec():
    return __doc__


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="stage_bisect.py",
        description=(
            "Locate the first divergence boundary between two pipeline stage "
            "projections (Ghidra-side vs Rugra-side OPACTION_DEBUG-derived "
            "traces). Pure consumer of projections; changes no pipeline "
            "semantics (RUGRA-GLUE)."
        ),
    )
    parser.add_argument(
        "left", nargs="?", help="left projection file (typically Ghidra side)"
    )
    parser.add_argument(
        "right", nargs="?", help="right projection file (typically Rugra side)"
    )
    parser.add_argument(
        "--json", action="store_true", help="emit a machine-readable JSON report"
    )
    parser.add_argument(
        "--v1", action="store_true",
        help="parse and compare the v1.1 @SNAP projection extension",
    )
    parser.add_argument(
        "--context",
        type=int,
        default=6,
        metavar="N",
        help="show N preceding stream items in the human report (default 6)",
    )
    parser.add_argument(
        "--relax-unique",
        action="store_true",
        help=(
            "mask unique-space varnode ids (uni*/unique*/u_*) before comparing "
            "before/after strings; triage aid only, NOT alignment evidence"
        ),
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="run built-in synthetic selftest (exit 0 on pass)",
    )
    parser.add_argument(
        "--emit-harness",
        action="store_true",
        help=(
            "print the Ghidra-side projection harness skeleton "
            "(tools/stage_bisect_projection.cc) with build command templates"
        ),
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="with --emit-harness: write the skeleton to FILE instead of stdout",
    )
    parser.add_argument(
        "--format",
        action="store_true",
        help="print the projection format specification and exit",
    )
    args = parser.parse_args(argv)

    if args.selftest:
        return run_selftest()
    if args.format:
        print(format_spec())
        return 0
    if args.emit_harness:
        return emit_harness(args.output)
    if not args.left or not args.right:
        parser.error("two projection files are required (left right)")

    try:
        if args.v1:
            left = load_v1_projection(args.left)
            right = load_v1_projection(args.right)
        else:
            left = load_projection(args.left)
            right = load_projection(args.right)
    except FormatError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.v1:
        report = compare_v1_projections(left, right, relax_unique=args.relax_unique)
    else:
        report = compare_projections(left, right, relax_unique=args.relax_unique)
        report["_left_projection"] = left
        report["_right_projection"] = right

    if args.json:
        print(json_report(report))
    else:
        if args.v1:
            print(human_v1_report(report, context=3))
        else:
            print(human_report(report, context=max(0, args.context)))

    if report["kind"] == KIND_MATCH:
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
