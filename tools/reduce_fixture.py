#!/usr/bin/env python3
"""Delta-reduce a deterministic oracle mismatch fixture without invoking a shell."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

try:
    from .oracle_cache import (
        DEFAULT_ENV_KEYS,
        display_path,
        sha256_bytes,
        sha256_file,
        stable_file_record,
        user_path,
    )
except ImportError:
    from oracle_cache import (
        DEFAULT_ENV_KEYS,
        display_path,
        sha256_bytes,
        sha256_file,
        stable_file_record,
        user_path,
    )


SCHEMA = 1
PLACEHOLDER = "{input}"
REDUCER_ENV_KEYS = (*DEFAULT_ENV_KEYS, "HOME", "LD_LIBRARY_PATH", "TMPDIR")


class ReduceError(RuntimeError):
    """The fixture, predicate, or reduction contract is invalid."""


@dataclass(frozen=True)
class Codec:
    kind: str
    units: list[Any]
    render: Callable[[list[Any]], bytes]
    suffix: str


def atomic_bytes(path: Path, data: bytes) -> None:
    if path.exists():
        raise ReduceError(f"output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(data)
        os.link(temporary, path)
        temporary.unlink()
    except Exception:
        if temporary.exists():
            temporary.unlink()
        raise


def atomic_json(path: Path, document: dict[str, Any]) -> None:
    atomic_bytes(
        path,
        (
            json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8"),
    )


def json_bytes(document: Any) -> bytes:
    return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def pointer_tokens(pointer: str) -> list[str]:
    if not pointer.startswith("/"):
        raise ReduceError("--field must be an RFC 6901 JSON Pointer beginning with '/'")
    if pointer == "/":
        return [""]
    tokens = pointer[1:].split("/")
    result = []
    for token in tokens:
        index = 0
        decoded = ""
        while index < len(token):
            if token[index] != "~":
                decoded += token[index]
                index += 1
                continue
            if index + 1 >= len(token) or token[index + 1] not in "01":
                raise ReduceError(f"invalid JSON Pointer escape in {pointer!r}")
            decoded += "~" if token[index + 1] == "0" else "/"
            index += 2
        result.append(decoded)
    return result


def child(container: Any, token: str, pointer: str) -> Any:
    if isinstance(container, dict):
        if token not in container:
            raise ReduceError(f"JSON Pointer {pointer!r} does not exist")
        return container[token]
    if isinstance(container, list):
        if not token.isdigit():
            raise ReduceError(f"JSON Pointer list token must be an index: {token!r}")
        index = int(token)
        if index >= len(container):
            raise ReduceError(f"JSON Pointer index is out of range: {token}")
        return container[index]
    raise ReduceError(f"JSON Pointer traverses a scalar at token {token!r}")


def list_at_pointer(document: Any, pointer: str) -> list[Any]:
    value = document
    for token in pointer_tokens(pointer):
        value = child(value, token, pointer)
    if not isinstance(value, list):
        raise ReduceError(f"JSON Pointer {pointer!r} does not select a list")
    return value


def replace_at_pointer(document: Any, pointer: str, replacement: list[Any]) -> Any:
    result = copy.deepcopy(document)
    tokens = pointer_tokens(pointer)
    parent = result
    for token in tokens[:-1]:
        parent = child(parent, token, pointer)
    final = tokens[-1]
    if isinstance(parent, dict):
        if final not in parent:
            raise ReduceError(f"JSON Pointer {pointer!r} does not exist")
        parent[final] = replacement
    elif isinstance(parent, list):
        if not final.isdigit() or int(final) >= len(parent):
            raise ReduceError(f"JSON Pointer final index is invalid: {final!r}")
        parent[int(final)] = replacement
    else:
        raise ReduceError(f"JSON Pointer parent is a scalar: {pointer!r}")
    return result


def parse_hex(data: bytes) -> list[int]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise ReduceError("hex fixture must be ASCII") from error
    compact = "".join(text.split())
    if compact.startswith(("0x", "0X")):
        compact = compact[2:]
    if len(compact) % 2 or any(character not in "0123456789abcdefABCDEF" for character in compact):
        raise ReduceError("hex fixture must contain an even number of hexadecimal digits")
    return list(bytes.fromhex(compact))


def codec_for(data: bytes, requested: str, field: str | None) -> Codec:
    parsed: Any = None
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    kind = requested
    if kind == "auto":
        if isinstance(parsed, list) and field is None:
            kind = "json-list"
        elif isinstance(parsed, dict) and field is not None:
            kind = "json-field"
        else:
            kind = "hex"
    if kind == "json-list":
        if field is not None:
            raise ReduceError("--field is only valid with json-field")
        if not isinstance(parsed, list):
            raise ReduceError("json-list format requires a top-level JSON list")
        return Codec(kind, parsed, json_bytes, ".json")
    if kind == "json-field":
        if parsed is None or field is None:
            raise ReduceError("json-field format requires JSON input and --field")
        units = list_at_pointer(parsed, field)
        return Codec(
            kind,
            list(units),
            lambda reduced: json_bytes(replace_at_pointer(parsed, field, reduced)),
            ".json",
        )
    if field is not None:
        raise ReduceError("--field is only valid with json-field")
    units = parse_hex(data)
    return Codec(
        "hex",
        units,
        lambda reduced: (bytes(reduced).hex() + "\n").encode("ascii"),
        ".hex",
    )


def resolve_executable(root: Path, command: str) -> Path:
    resolved = shutil.which(command)
    if resolved is None:
        candidate = user_path(root, command)
        if candidate.is_file():
            resolved = str(candidate)
    if resolved is None:
        raise ReduceError(f"predicate executable not found: {command}")
    return Path(resolved).resolve()


def command_for(template: list[str], candidate: Path) -> list[str]:
    if PLACEHOLDER not in template:
        raise ReduceError(f"predicate command must contain an exact {PLACEHOLDER!r} argument")
    return [str(candidate) if argument == PLACEHOLDER else argument for argument in template]


def stable_read(path: Path) -> bytes:
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_identity != after_identity or len(data) != after.st_size:
        raise ReduceError(f"input changed while being read: {path}")
    return data


class PredicateRunner:
    def __init__(
        self,
        root: Path,
        template: list[str],
        interesting_exit: int,
        boring_exit: int,
        timeout: float,
        retries: int,
        max_evaluations: int,
        temp: Path,
        suffix: str,
        environment_names: list[str],
    ) -> None:
        if not template:
            raise ReduceError("predicate command is empty")
        if interesting_exit == boring_exit:
            raise ReduceError("interesting and boring exit codes must differ")
        if timeout <= 0 or retries <= 0 or max_evaluations <= 0:
            raise ReduceError("timeout, retries, and max-evaluations must be positive")
        command_for(template, temp / f"probe{suffix}")
        self.root = root
        self.template = template
        self.interesting_exit = interesting_exit
        self.boring_exit = boring_exit
        self.timeout = timeout
        self.retries = retries
        self.max_evaluations = max_evaluations
        self.temp = temp
        self.suffix = suffix
        self.memo: dict[str, bool] = {}
        self.trace: list[dict[str, Any]] = []
        self.evaluations = 0
        self.process_runs = 0
        self.cache_hits = 0
        executable = resolve_executable(root, template[0])
        size, digest = stable_file_record(executable)
        self.executable = {
            "argv0": template[0],
            "path": display_path(executable, root),
            "size": size,
            "sha256": digest,
        }
        names = sorted(set(REDUCER_ENV_KEYS).union(environment_names))
        self.environment_record = {name: os.environ.get(name) for name in names}
        self.environment_record.update(
            {"CARGO_NET_OFFLINE": "true", "LC_ALL": "C", "TZ": "UTC"}
        )
        self.environment = {
            name: value for name, value in self.environment_record.items() if value is not None
        }
        command_files = []
        seen_files: set[str] = set()
        for argument in template[1:]:
            if argument == PLACEHOLDER:
                continue
            candidate = user_path(root, argument)
            if not candidate.is_file():
                continue
            resolved_candidate = candidate.resolve()
            key = resolved_candidate.as_posix()
            if key in seen_files:
                continue
            seen_files.add(key)
            file_size, file_digest = stable_file_record(resolved_candidate)
            command_files.append(
                {
                    "argument": argument,
                    "path": display_path(resolved_candidate, root),
                    "size": file_size,
                    "sha256": file_digest,
                }
            )
        self.command_files = command_files

    def evaluate(self, data: bytes, unit_count: int) -> bool:
        digest = sha256_bytes(data)
        if digest in self.memo:
            self.cache_hits += 1
            result = self.memo[digest]
            self.trace.append(
                {
                    "sha256": digest,
                    "size": len(data),
                    "unit_count": unit_count,
                    "cache_hit": True,
                    "interesting": result,
                }
            )
            return result
        if self.evaluations >= self.max_evaluations:
            raise ReduceError(f"predicate exceeded max evaluations ({self.max_evaluations})")
        self.evaluations += 1
        candidate = self.temp / f"candidate-{digest}{self.suffix}"
        candidate.write_bytes(data)
        outcomes: list[int] = []
        elapsed: list[float] = []
        stdout_hashes: list[str] = []
        stderr_hashes: list[str] = []
        try:
            for _ in range(self.retries):
                command = command_for(self.template, candidate)
                started = time.monotonic()
                process = subprocess.Popen(
                    command,
                    cwd=self.root,
                    env=self.environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
                self.process_runs += 1
                try:
                    stdout, stderr = process.communicate(timeout=self.timeout)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.communicate()
                    raise ReduceError(
                        f"predicate timed out after {self.timeout}s for candidate {digest}"
                    )
                elapsed.append(round(time.monotonic() - started, 6))
                outcomes.append(int(process.returncode))
                stdout_hashes.append(sha256_bytes(stdout))
                stderr_hashes.append(sha256_bytes(stderr))
                if sha256_file(candidate) != digest:
                    raise ReduceError("predicate modified its candidate input")
            if len(set(outcomes)) != 1:
                raise ReduceError(
                    f"predicate is nondeterministic for {digest}: exit codes {outcomes}"
                )
            outcome = outcomes[0]
            if outcome not in (self.interesting_exit, self.boring_exit):
                raise ReduceError(
                    f"predicate harness error for {digest}: unexpected exit code {outcome}"
                )
            interesting = outcome == self.interesting_exit
            self.memo[digest] = interesting
            self.trace.append(
                {
                    "sha256": digest,
                    "size": len(data),
                    "unit_count": unit_count,
                    "cache_hit": False,
                    "interesting": interesting,
                    "exit_codes": outcomes,
                    "elapsed_seconds": elapsed,
                    "stdout_sha256": stdout_hashes,
                    "stderr_sha256": stderr_hashes,
                }
            )
            return interesting
        finally:
            if candidate.exists():
                candidate.unlink()


def chunks(length: int, count: int) -> list[tuple[int, int]]:
    return [
        (index * length // count, (index + 1) * length // count)
        for index in range(count)
        if index * length // count < (index + 1) * length // count
    ]


def ddmin(units: list[Any], interesting: Callable[[list[Any]], bool]) -> list[Any]:
    current = list(units)
    granularity = 2
    while len(current) >= 2:
        reduced = False
        for start, finish in chunks(len(current), granularity):
            candidate = current[:start] + current[finish:]
            if interesting(candidate):
                current = candidate
                granularity = max(2, granularity - 1)
                reduced = True
                break
        if reduced:
            continue
        if granularity >= len(current):
            break
        granularity = min(len(current), granularity * 2)
    index = 0
    while index < len(current):
        candidate = current[:index] + current[index + 1 :]
        if interesting(candidate):
            current = candidate
        else:
            index += 1
    return current


def one_minimal(units: list[Any], interesting: Callable[[list[Any]], bool]) -> bool:
    return all(
        not interesting(units[:index] + units[index + 1 :])
        for index in range(len(units))
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--trace", type=Path)
    parser.add_argument("--format", choices=("auto", "json-list", "json-field", "hex"), default="auto")
    parser.add_argument("--field")
    parser.add_argument("--interesting-exit", type=int, default=1)
    parser.add_argument("--boring-exit", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--max-evaluations", type=int, default=10000)
    parser.add_argument("--env", action="append", default=[])
    parser.add_argument("predicate", nargs=argparse.REMAINDER)
    return parser.parse_args(argv)


def self_test() -> int:
    def predicate(values: list[int]) -> bool:
        return 2 in values and 4 in values

    first = ddmin([1, 2, 3, 4, 5, 6], predicate)
    second = ddmin([1, 2, 3, 4, 5, 6], predicate)
    assert first == second == [2, 4]
    assert one_minimal(first, predicate)
    document = {"outer": {"ops": [1, 2, 3]}, "keep": [9]}
    replaced = replace_at_pointer(document, "/outer/ops", [2])
    assert replaced == {"outer": {"ops": [2]}, "keep": [9]}
    assert document["outer"]["ops"] == [1, 2, 3]
    assert parse_hex(b"0x00 ff 10\n") == [0, 255, 16]
    with tempfile.TemporaryDirectory(prefix="rugra-reducer-test-") as raw_temp:
        temp = Path(raw_temp)
        helper = temp / "predicate.py"
        helper.write_text(
            "import json,sys\n"
            "mode,path=sys.argv[1:]\n"
            "if mode=='json-list': values=json.load(open(path,encoding='utf-8'))\n"
            "elif mode=='json-field': values=json.load(open(path,encoding='utf-8'))['ops']\n"
            "else: values=list(bytes.fromhex(open(path,encoding='ascii').read()))\n"
            "raise SystemExit(1 if 2 in values and 4 in values else 0)\n",
            encoding="utf-8",
        )
        codecs = [
            ("json-list", codec_for(b"[1,2,3,4,5,6]", "json-list", None)),
            (
                "json-field",
                codec_for(b'{"ops":[1,2,3,4,5,6],"keep":9}', "json-field", "/ops"),
            ),
            ("hex", codec_for(b"010203040506", "hex", None)),
        ]
        for mode, codec in codecs:
            with tempfile.TemporaryDirectory(prefix="candidates-", dir=temp) as raw_candidates:
                runner = PredicateRunner(
                    Path(__file__).resolve().parent.parent,
                    [sys.executable, str(helper), mode, PLACEHOLDER],
                    1,
                    0,
                    5.0,
                    2,
                    100,
                    Path(raw_candidates),
                    codec.suffix,
                    [],
                )
                reduced = ddmin(
                    codec.units,
                    lambda units: runner.evaluate(codec.render(units), len(units)),
                )
                assert reduced == [2, 4]
                assert one_minimal(
                    reduced,
                    lambda units: runner.evaluate(codec.render(units), len(units)),
                )
                previous_runs = runner.process_runs
                assert runner.evaluate(codec.render(reduced), len(reduced))
                assert runner.process_runs == previous_runs and runner.cache_hits > 0
    print("reduce_fixture: self-test OK")
    return 0


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    if args.input is None or args.output is None or args.trace is None:
        print("reduce_fixture: --input, --output, and --trace are required", file=sys.stderr)
        return 2
    predicate = args.predicate
    if predicate and predicate[0] == "--":
        predicate = predicate[1:]
    root = Path(__file__).resolve().parent.parent
    input_path = user_path(root, args.input)
    output_path = user_path(root, args.output)
    trace_path = user_path(root, args.trace)
    try:
        if input_path.is_symlink() or not input_path.is_file():
            raise ReduceError(f"input must be a regular non-symlink file: {input_path}")
        if len({input_path.resolve(), output_path.resolve(), trace_path.resolve()}) != 3:
            raise ReduceError("input, output, and trace paths must be distinct")
        if output_path.exists() or trace_path.exists():
            raise ReduceError("output and trace paths must not already exist")
        original = stable_read(input_path)
        codec = codec_for(original, args.format, args.field)
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="rugra-reducer-") as raw_temp:
            runner = PredicateRunner(
                root,
                predicate,
                args.interesting_exit,
                args.boring_exit,
                args.timeout,
                args.retries,
                args.max_evaluations,
                Path(raw_temp),
                codec.suffix,
                args.env,
            )

            def is_interesting(units: list[Any]) -> bool:
                return runner.evaluate(codec.render(units), len(units))

            if not is_interesting(codec.units):
                raise ReduceError("initial fixture is not interesting")
            reduced = ddmin(codec.units, is_interesting)
            final = codec.render(reduced)
            if not is_interesting(reduced):
                raise ReduceError("reduced fixture lost the interesting predicate")
            minimal = one_minimal(reduced, is_interesting)
            if not minimal:
                raise ReduceError("reducer failed the 1-minimal verification")
            trace = {
                "schema": SCHEMA,
                "format": codec.kind,
                "field": args.field,
                "input": display_path(input_path, root),
                "output": display_path(output_path, root),
                "trace": display_path(trace_path, root),
                "original": {
                    "sha256": sha256_bytes(original),
                    "size": len(original),
                    "unit_count": len(codec.units),
                },
                "minimized": {
                    "sha256": sha256_bytes(final),
                    "size": len(final),
                    "unit_count": len(reduced),
                    "one_minimal": minimal,
                },
                "predicate": {
                    "command": predicate,
                    "executable": runner.executable,
                    "command_files": runner.command_files,
                    "environment": runner.environment_record,
                    "placeholder": PLACEHOLDER,
                    "interesting_exit": args.interesting_exit,
                    "boring_exit": args.boring_exit,
                    "timeout_seconds": args.timeout,
                    "retries": args.retries,
                },
                "evaluation_count": runner.evaluations,
                "process_run_count": runner.process_runs,
                "cache_hits": runner.cache_hits,
                "elapsed_seconds": round(time.monotonic() - started, 6),
                "evaluations": runner.trace,
            }
        atomic_bytes(output_path, final)
        try:
            atomic_json(trace_path, trace)
        except Exception:
            output_path.unlink(missing_ok=True)
            raise
        print(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "status": "REDUCED",
                    "format": codec.kind,
                    "original_units": len(codec.units),
                    "minimized_units": len(reduced),
                    "evaluations": trace["evaluation_count"],
                    "cache_hits": trace["cache_hits"],
                    "one_minimal": True,
                    "output": display_path(output_path, root),
                    "trace": display_path(trace_path, root),
                },
                sort_keys=True,
            )
        )
        return 0
    except (OSError, ReduceError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f"reduce_fixture: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
