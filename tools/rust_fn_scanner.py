#!/usr/bin/env python3
"""Small, dependency-free Rust function-item scanner used by source gates.

This is deliberately a lexical scanner, not a Rust parser.  It masks comments
and literals without changing offsets, finds function items (including items
inside one-line ``impl`` blocks), pairs braces, and records exact item ranges.
Both the commit-time annotation checker and the edit-time alignment gate must
consume these records so their view of Rust syntax cannot drift.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
import re


_VISIBILITY = r"(?:pub(?:\s*\([^)]*\))?\s+)?"
_ATTRIBUTES = r"(?:#\s*\[[^\]]*\]\s*)*"
_QUALIFIERS = (
    r"(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:(?:safe|unsafe)\s+)?"
    r"(?:extern(?:\s+\"[^\"]+\")?\s+)?"
)

# The prefix limits matches to item boundaries while still recognizing compact
# source such as ``impl T { pub fn new() {} }``.  Run this only on masked code.
FN_RE = re.compile(
    r"(?:^|[{};])\s*"
    + _ATTRIBUTES
    + r"(?P<item>"
    + _VISIBILITY
    + _QUALIFIERS
    + r"(?P<fn_kw>fn)\s+(?P<name>(?:r#)?[A-Za-z_][A-Za-z0-9_]*)\s*[<(])",
    re.MULTILINE,
)
_FN_ITEM_HEAD_RE = re.compile(_VISIBILITY + _QUALIFIERS + r"fn\b")

_DIRECT_TEST_ATTR_RE = re.compile(
    r"#\s*\[\s*(?:(?:[A-Za-z_][A-Za-z0-9_]*)::)*test"
    r"(?:\s*\([^\]]*\))?\s*\]"
)
_CFG_TEST_ATTR_RE = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
_RAW_STRING_RE = re.compile(r"(?:br|cr|r)(?P<hashes>#{0,255})\"")


@dataclass(frozen=True)
class RustFunction:
    """One Rust function item, with zero-based offsets and line numbers."""

    name: str
    start: int
    end: int
    start_line: int
    end_line: int
    is_test: bool
    is_declaration: bool


def _blank(out: list[str], text: str, start: int, end: int) -> None:
    for pos in range(start, min(end, len(out))):
        if text[pos] not in "\r\n":
            out[pos] = " "


def _quoted_end(text: str, start: int, quote: str) -> int:
    pos = start + 1
    while pos < len(text):
        ch = text[pos]
        if ch == "\\":
            pos += 2
            continue
        if ch == quote:
            return pos + 1
        if ch in "\r\n" and quote == "'":
            return start + 1
        pos += 1
    return len(text)


def _char_literal_end(text: str, start: int) -> int | None:
    if start + 2 >= len(text) or text[start] != "'":
        return None
    if text[start + 1] != "\\":
        return start + 3 if text[start + 2] == "'" else None
    pos = start + 2
    if text[pos] == "u" and pos + 1 < len(text) and text[pos + 1] == "{":
        close = text.find("}", pos + 2)
        if close >= 0 and close + 1 < len(text) and text[close + 1] == "'":
            return close + 2
        return None
    width = 3 if text[pos] == "x" else 1
    close = pos + width
    return close + 1 if close < len(text) and text[close] == "'" else None


def mask_non_code(text: str) -> str:
    """Replace comments and literals with spaces while preserving offsets."""

    out = list(text)
    pos = 0
    size = len(text)
    while pos < size:
        if text.startswith("//", pos):
            end = text.find("\n", pos + 2)
            end = size if end < 0 else end
            _blank(out, text, pos, end)
            pos = end
            continue
        if text.startswith("/*", pos):
            depth = 1
            end = pos + 2
            while end < size and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            _blank(out, text, pos, end)
            pos = end
            continue

        raw = _RAW_STRING_RE.match(text, pos)
        if raw and (pos == 0 or not (text[pos - 1].isalnum() or text[pos - 1] == "_")):
            terminator = '"' + raw.group("hashes")
            close = text.find(terminator, raw.end())
            end = size if close < 0 else close + len(terminator)
            _blank(out, text, pos, end)
            pos = end
            continue
        if text[pos] == '"':
            end = _quoted_end(text, pos, '"')
            _blank(out, text, pos, end)
            pos = end
            continue
        if text[pos] == "'":
            end = _char_literal_end(text, pos)
            if end is not None:
                _blank(out, text, pos, end)
                pos = end
                continue
        pos += 1
    return "".join(out)


def _brace_pairs(code: str) -> dict[int, int]:
    stack: list[int] = []
    pairs: dict[int, int] = {}
    for pos, ch in enumerate(code):
        if ch == "{":
            stack.append(pos)
        elif ch == "}" and stack:
            opening = stack.pop()
            pairs[opening] = pos
    return pairs


def _line_starts(text: str) -> list[int]:
    starts = [0]
    starts.extend(pos + 1 for pos, ch in enumerate(text) if ch == "\n")
    return starts


def _line_for(starts: list[int], offset: int) -> int:
    return max(0, bisect_right(starts, offset) - 1)


def _find_item_end(code: str, search_from: int, pairs: dict[int, int]) -> tuple[int, bool]:
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
            return pos + 1, True
        elif ch == "{" and paren == 0 and bracket == 0 and angle == 0:
            close = pairs.get(pos)
            previous = pos - 1
            while previous >= search_from and code[previous].isspace():
                previous -= 1
            # A macro in a return type/where-clause can use braces before the
            # actual function body: ``fn f() -> ty!{u8} { 0 }``.
            if previous >= search_from and code[previous] == "!" and close is not None:
                pos = close + 1
                continue
            return (len(code) if close is None else close + 1), False
        pos += 1
    return len(code), False


def _skip_attributes(code: str, start: int) -> int:
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


def _cfg_test_scope_ranges(code: str, pairs: dict[int, int]) -> list[tuple[int, int]]:
    """Ranges of any braced item carrying an exact ``#[cfg(test)]``."""

    ranges: list[tuple[int, int]] = []
    for match in _CFG_TEST_ATTR_RE.finditer(code):
        pos = _skip_attributes(code, match.end())
        is_function_item = bool(_FN_ITEM_HEAD_RE.match(code, pos))
        paren = 0
        bracket = 0
        angle = 0
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
                break
            elif ch == "{" and paren == 0 and bracket == 0 and angle == 0:
                close = pairs.get(pos)
                previous = pos - 1
                while previous >= match.end() and code[previous].isspace():
                    previous -= 1
                if (
                    is_function_item
                    and previous >= match.end()
                    and code[previous] == "!"
                    and close is not None
                ):
                    pos = close + 1
                    continue
                if close is not None:
                    ranges.append((pos, close + 1))
                break
            pos += 1
    return ranges


def _has_test_attribute(code: str, item_start: int) -> bool:
    boundary = max(
        code.rfind("{", 0, item_start),
        code.rfind("}", 0, item_start),
        code.rfind(";", 0, item_start),
    )
    # Attributes remain visible in ``code`` while comments and literals have
    # been blanked, preventing prose such as ``// #[cfg(test)]`` from exempting
    # a production function.
    attribute_block = code[boundary + 1:item_start]
    return bool(
        _DIRECT_TEST_ATTR_RE.search(attribute_block)
        or _CFG_TEST_ATTR_RE.search(attribute_block)
    )


def scan_rust_functions(text: str) -> list[RustFunction]:
    """Return all lexically present Rust function items in source order."""

    code = mask_non_code(text)
    pairs = _brace_pairs(code)
    test_ranges = _cfg_test_scope_ranges(code, pairs)
    starts = _line_starts(text)
    records: list[RustFunction] = []
    for match in FN_RE.finditer(code):
        item_start = match.start("item")
        end, is_declaration = _find_item_end(code, match.end("name"), pairs)
        is_test_module = any(start < item_start < finish for start, finish in test_ranges)
        is_test = is_test_module or _has_test_attribute(code, item_start)
        records.append(
            RustFunction(
                name=match.group("name"),
                start=item_start,
                end=end,
                start_line=_line_for(starts, item_start),
                end_line=_line_for(starts, max(item_start, end - 1)),
                is_test=is_test,
                is_declaration=is_declaration,
            )
        )
    return records


def functions_overlapping(
    records: list[RustFunction], start: int, end: int
) -> list[RustFunction]:
    """Return functions intersecting ``[start,end)`` (or insertion at start)."""

    if end <= start:
        return [record for record in records if record.start <= start < record.end]
    return [record for record in records if start < record.end and end > record.start]


def run_self_test() -> None:
    fixture = r'''
// fn fake_comment() {}
const S: &str = "fn fake_string() { }";
pub const fn const_item() {}
pub(crate) fn restricted() {}
pub extern "C" fn exported() {}
pub unsafe extern "C" fn unsafe_exported() {}
#[inline] pub fn same_line_attribute() {}
#[test] fn individual_test() {}
trait T { fn declared(&self); }
unsafe extern "C" { #[link_name = "foreign"] safe fn foreign_safe(); }
struct Compact;
impl Compact { pub fn compact() {} fn second() {} }
fn weird() -> ty!{u8} { 0 }
fn after_weird() {}
#[cfg(test)]
mod arbitrary_name {
    mod nested { fn nested_test() {} }
}
struct TestOnly;
#[cfg(test)] impl TestOnly { fn impl_test() {} }
#[cfg(test)] noop!{}
fn production_after_cfg_macro() { fn nested_after_cfg_macro() {} }
fn production_after_test() {}
mod production_module {
    #[cfg(test)]
    mod fixtures { fn nested_test_two() {} }
    fn nested_production() {}
}
#[cfg(not(test))]
fn cfg_not_test() {}
'''
    records = scan_rust_functions(fixture)
    by_name = {record.name: record for record in records}
    expected = {
        "const_item", "restricted", "exported", "unsafe_exported",
        "same_line_attribute", "individual_test", "declared", "foreign_safe",
        "compact", "second", "weird", "after_weird", "nested_test", "impl_test",
        "production_after_cfg_macro", "nested_after_cfg_macro", "production_after_test",
        "nested_test_two", "nested_production", "cfg_not_test",
    }
    assert set(by_name) == expected, (set(by_name), expected)
    assert by_name["declared"].is_declaration
    assert by_name["foreign_safe"].is_declaration
    assert by_name["declared"].start_line == by_name["declared"].end_line
    weird_text = fixture[by_name["weird"].start:by_name["weird"].end]
    assert weird_text.rstrip().endswith("{ 0 }")
    assert by_name["weird"].end < by_name["after_weird"].start
    assert by_name["individual_test"].is_test
    assert by_name["nested_test"].is_test
    assert by_name["impl_test"].is_test
    assert not by_name["production_after_cfg_macro"].is_test
    assert not by_name["nested_after_cfg_macro"].is_test
    assert by_name["nested_test_two"].is_test
    assert not by_name["production_after_test"].is_test
    assert not by_name["nested_production"].is_test
    assert not by_name["cfg_not_test"].is_test
    assert "fake_comment" not in by_name and "fake_string" not in by_name


if __name__ == "__main__":
    run_self_test()
    print("✅ rust_fn_scanner self-test passed")
