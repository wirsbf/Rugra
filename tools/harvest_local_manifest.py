#!/usr/bin/env python3
"""harvest_local_manifest.py — C1 TYPE-SEED-LOCAL manifest harvester.

Harvests the committed-local seed manifest from a canonical analyzeHeadless
golden (HEADLESS_BRIDGE_V1_DESIGN.md 5.1): per function, the declaration
block between the opening '{' and the first non-declaration line yields
(type, name, array dims) for every `local_[0-9a-f]+` declarator.  Stack
offset = -int(name[6:], 16) (the offset is embedded in the name by Ghidra's
stack buildDefaultName).

C2 DWARF mode (`--dwarf BINARY GOLDEN.c ...`) harvests the DWARF
semantic-name seed channel instead: variable names come from .debug_info
and their stack offsets from inline DW_OP_fbreg locations (see
DWARF_HARVEST_RULE below for the domain rules, each pinned by locked-oracle
pre-validation).

Output manifest records oracle commit + golden sha256 (B2 provenance).

Usage (C1 golden-decl mode):
  harvest_local_manifest.py GOLDEN.c CORPUS ORACLE_COMMIT OUT.json [--typed-only]
Usage (C2 DWARF-name mode):
  harvest_local_manifest.py --dwarf BINARY GOLDEN.c CORPUS ORACLE_COMMIT OUT.json [--dwarf-raw-types]
Usage (C4 DWARF-struct mode):
  harvest_local_manifest.py --struct BINARY GOLDEN.c CORPUS ORACLE_COMMIT OUT.json
"""
import hashlib
import json
import re
import sys

FUNC_HEADER = re.compile(r"^/\* ---- 0x([0-9a-f]+): (.+) \(\d+ bytes\) ---- \*/$")
DECL = re.compile(
    r"^\s*(?P<type>[A-Za-z_][A-Za-z0-9_]*(?:\s+[A-Za-z_][A-Za-z0-9_]*)*?)"
    r"(?P<stars>\s*\*+\s*|\s+)"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<arr>(?:\s*\[\d+\])+)?"
    r";\s*$"
)
LOCAL_NAME = re.compile(r"^local_[0-9a-f]+$")
# Parenthesized declarators (function pointers / array-of pointers to
# arrays): `undefined1 (*pauVar6) [16];` — must not end the decl block.
DECL_PAREN = re.compile(
    r"^\s*[A-Za-z_][A-Za-z0-9_ ]*?\(\s*\*\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)"
    r"(?P<arr>(?:\s*\[\d+\])+)?"
    r"\s*;\s*$"
)


# Bases the C1 v1 seed channel can install with faithful size/metatype
# (scalar/pointer/array domain). Struct-typed committed locals (sigaction,
# sigset_t, ...) are C4 composite-channel domain and are skipped here so the
# manifest never carries a type the channel would mistype.
KNOWN_BASES = {
    "void", "char", "byte",
    "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
    "short", "ushort", "int", "uint", "long", "ulong", "size_t", "time_t",
    "__pid_t", "float", "double", "bool",
}


def base_of(type_expr):
    return type_expr.split("[")[0].rstrip("*").strip()


def parse_type_expr(type_text, stars, arr):
    base = " ".join(type_text.split())
    if not base:
        return None
    nstars = stars.count("*")
    ptr = " " + "*" * nstars if nstars else ""
    dims = "".join("[%d]" % int(d) for d in re.findall(r"\[(\d+)\]", arr or ""))
    return base + ptr + dims


def split_functions(text):
    """Yield (addr, name, [lines]) per golden function block."""
    cur_addr = None
    cur_name = None
    cur_lines = []
    for line in text.split("\n"):
        m = FUNC_HEADER.match(line)
        if m:
            if cur_addr is not None:
                yield cur_addr, cur_name, cur_lines
            cur_addr, cur_name, cur_lines = "0x" + m.group(1), m.group(2), []
        elif cur_addr is not None:
            cur_lines.append(line)
    if cur_addr is not None:
        yield cur_addr, cur_name, cur_lines


def harvest_function(lines):
    locals_ = []
    started = False
    for line in lines:
        stripped = line.strip()
        if not started:
            if stripped == "{":
                started = True
            continue
        if not stripped:
            continue
        dm = DECL.match(line)
        if dm is None:
            dm = DECL_PAREN.match(line)
            if dm is not None:
                continue  # parenthesized declarator: never a local_ seed (v1 domain)
        if dm is None:
            break  # first statement ends the declaration block
        if not LOCAL_NAME.match(dm.group("name")):
            continue
        type_expr = parse_type_expr(dm.group("type"), dm.group("stars"), dm.group("arr"))
        if type_expr is None:
            continue
        if base_of(type_expr) not in KNOWN_BASES:
            continue  # C4 composite domain: outside the v1 seed channel
        name = dm.group("name")
        locals_.append(
            {"offset": -int(name[6:], 16), "name": name, "type": type_expr, "typelock": True}
        )
    return locals_


def harvest(path):
    text = open(path, "r", encoding="utf-8").read()
    functions = {}
    for addr, name, lines in split_functions(text):
        locs = harvest_function(lines)
        if locs:
            functions[addr] = {"name": name, "locals": locs}
    return functions


# ---------------------------------------------------------------------------
# C2 DWARF semantic-name mode (HEADLESS_BRIDGE_V1 C2 lane; W1B residual
# attribution: the curl -45 balance's bulk is the DWARF-named domain).
#
# Domain rules, each pinned by locked-oracle (e40ed130) pre-validation via
# stage_seed_diag <localdb> seeding (oracle-level reproduction of the canon
# named decl layer) plus canon-golden observation:
#   - Only DW_FORM_exprloc single-op DW_OP_fbreg(N) locations are seeded.
#     Ghidra's DWARF importer drops sec_offset location lists — canon never
#     names main's i/res/url (all loc-list vars) while it does name every
#     exprloc var; seeding loc-list vars would over-seed vs canon.
#   - DW_OP_addr (static storage) vars are skipped: global-symbol channel.
#   - Variables only. Formal parameters are the C3 prototype domain
#     (match_url's by-value stack param `glob` prints in canon's signature).
#   - offset = fbreg(N) + 8: frame_base is DW_OP_call_frame_cfa here, CFA =
#     RSP_entry + 8, and the Ghidra stack-space offset 0 is the RSP_entry
#     slot. Calibrated on main: urlnum fbreg(-0x22c) -> cmpl 0x34(%rsp)
#     (prologue 6 pushes + sub 0x228) -> Ghidra -0x224; errorbuffer
#     fbreg(-0x150) -> lea 0x110(%rsp).
#   - Canon-committed typing: the [256]/[4096] char arrays print `bool` in
#     canon (usedarg-family boolean usage; stage_seed_diag confirms
#     bool-seeds reproduce the canon decl layer and char-seeds do not), so
#     the default maps those arrays to bool; --dwarf-raw-types keeps the
#     raw DWARF spelling for attribution experiments.
#   - Slot ownership: the first DWARF claim on a stack slot decides its
#     fate (canon main: progressbar's slot -504 never prints passarg); a
#     slot first claimed by an unservable (C4) var is a residual and later
#     servable same-slot vars drop with it.
#   - KNOWN_BASES-only (TYPEFIX rule): an unknown base spelling is a dead
#     entry under parse_c_type's no-fallback bail, so the harvest drops it.
# ---------------------------------------------------------------------------

DWARF_HARVEST_RULE = (
    "DWARF .debug_info walk (pyelftools): DW_TAG_variable under "
    "subprogram/lexical_block/inlined_subroutine with abstract-origin "
    "chasing; location must be DW_FORM_exprloc single-op DW_OP_fbreg(N) "
    "(sec_offset loc-lists are dropped by Ghidra's importer — canon never "
    "names them; DW_OP_addr statics are the global channel; formal "
    "parameters are C3); offset = fbreg(N)+8 (frame_base=call_frame_cfa, "
    "Ghidra stack offset 0 = RSP_entry slot; calibrated urlnum "
    "fbreg(-0x22c) -> -0x224); canon key = DW_AT_low_pc + 0x100000; "
    "types: KNOWN_BASES bases only (parse_c_type no-fallback), array "
    "count = upper_bound+1, char[256]/char[4096] remap to bool (canon-"
    "committed typing, stage_seed_diag-validated; --dwarf-raw-types keeps "
    "raw), first-DIE slot claim wins and unservable first claims shadow "
    "the slot (progressbar/passarg). Canon-decl adjacency adoption: a "
    "canon-committed synthesized stack slot (uStack_/iStack_/... form, "
    "offset embedded in the name) whose extent borders a DWARF-seeded "
    "slot is adopted with source='canon-decl' — the seed's typelock "
    "would otherwise absorb the uncommitted neighbor into the array "
    "(oracle-verified: file2string buffer-only seeding yields 'bool "
    "abStack_150[8]' in the locked oracle too, while canon commits "
    "undefined8 uStack_150 and keeps the partition; both-seeded oracle "
    "reproduces canon's separate slots)"
)

# C4 STRUCT-SEED domain rule (HEADLESS-BRIDGE-V1 C3NEXT, the §11.4 residual
# set: urls/outs/heads/progressbar+passarg/fileinfo/glob x2/ap/statbuf/
# aliases). Names/offsets from .debug_info exactly like the C2 DWARF-name
# channel, but the type spelling names a DWARF composite (structure/union/
# enum) or a typedef over a composite/array, which parse_c_type resolves
# through the shared TypeFactory name tree (glb->types->findByName mirror,
# grammar.cc:2989; the factory is populated by the driver's unconditional
# parse_type_names DWARF import). Locked-oracle pre-validation
# (stage_seed_diag, /dev/shm/rugra-tests/c3next): the struct seed set
# reproduces canon's committed declaration layer (URLGlob *urls; OutStruct
# outs/heads; ProgressData progressbar; stat fileinfo; stat statbuf;
# LongShort aliases [50]; Configurable *local_5b8; HttpPost *local_5a8;
# va_list ap) and the field-form family (outs.stream/outs.filename/
# heads.stream/fileinfo.st_size/progressbar.total/ap[0].gp_offset,
# by-value ap passing). va_list must seed as the ARRAY form (typedef over
# __va_list_tag[1]): the struct-collapsed variant prints ap.field and
# passes &ap, the array form prints ap[0].field and passes ap — canon is
# the array form (oracle-verified). Canon-decl adoption: local_[0-9a-f]+
# declarators whose base names a DWARF composite (getparameter
# Configurable *local_5b8 / HttpPost *local_5a8) adopt name+offset from
# the golden decl layer, base must exist in the DWARF named-type set
# (TYPEFIX-equivalent: an unknown base is a dead entry under the factory
# name lookup). KNOWN_BASES spellings stay in the C1/C2 manifests
# (disjoint by construction); first-DIE slot claim keeps the
# progressbar-over-passarg shadowing.
STRUCT_HARVEST_RULE = (
    "DWARF walk as DWARF_HARVEST_RULE but the type domain is DWARF-named "
    "composites/typedefs (base must exist in the .debug_info named-type "
    "set with a size; arrays as Base[N], pointers as Base *); local_[hex] "
    "canon-decl adoption for struct-pointer bases; KNOWN_BASES domain "
    "excluded (C1/C2 manifests); slot ownership first-DIE-claim; oracle "
    "prevalidation stage_seed_diag witness in "
    "/dev/shm/rugra-tests/c3next (seed_*.xml + oracle_*_seeded.c)"
)

# canon synthesized stack-name forms with the offset embedded in the name
# (uStack_150 / iStack_160 / pcStack_218 / ...); in_stack_ (positive
# full-width hex) and local_ (W1B C1 domain) are deliberately not matched.
STACK_NAME = re.compile(r"^[A-Za-z]*[Ss]tack_([0-9a-f]{1,6})$")

BASE_SIZES = {
    "void": 0, "char": 1, "byte": 1,
    "undefined": 1, "undefined1": 1, "undefined2": 2, "undefined4": 4,
    "undefined8": 8, "short": 2, "ushort": 2, "int": 4, "uint": 4,
    "long": 8, "ulong": 8, "size_t": 8, "time_t": 8, "__pid_t": 4,
    "float": 4, "double": 8, "bool": 1,
}


def _spelling_size(spelling):
    """Byte size of a servable seed spelling (pointer=8, arrays multiply)."""
    dims = [int(d) for d in re.findall(r"\[(\d+)\]", spelling)]
    base = spelling.split("[")[0]
    if base.endswith("*"):
        size = 8
    else:
        size = BASE_SIZES.get(base.strip())
        if size is None:
            return None
    for dim in dims:
        size *= dim
    return size


def _canon_neighbor_seeds(golden_text, dwarf_functions):
    """Adopt canon-committed synthesized slots bordering a DWARF seed.

    The canon decl layer is the committed-symbol truth (W1B harvest
    source); a slot the analyzer committed (and canon prints separately)
    must also be committed on our side, or the DWARF seed's typelock
    absorbs the uncommitted neighbor (file2string uStack_150, oracle-
    verified). Only immediately-bordering KNOWN_BASES-typed slots are
    adopted — the minimal evidence-backed set."""
    adopted = {}
    for addr, name, lines in split_functions(golden_text):
        if addr not in dwarf_functions:
            continue
        seeds = dwarf_functions[addr]["locals"]
        seed_extents = []
        for seed in seeds:
            size = _spelling_size(seed["type"])
            if size:
                seed_extents.append((seed["offset"], seed["offset"] + size))
        neighbors = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            dm = DECL.match(line)
            if dm is None:
                continue
            nm = STACK_NAME.match(dm.group("name"))
            if nm is None:
                continue
            type_expr = parse_type_expr(
                dm.group("type"), dm.group("stars"), dm.group("arr")
            )
            if type_expr is None or base_of(type_expr) not in KNOWN_BASES:
                continue
            nsize = _spelling_size(type_expr)
            if not nsize:
                continue
            noff = -int(nm.group(1), 16)
            nrange = (noff, noff + nsize)
            borders = any(
                nrange[1] == s[0] or s[1] == nrange[0] for s in seed_extents
            )
            if not borders:
                continue
            if any(s["offset"] == noff for s in seeds):
                continue  # already DWARF-seeded
            neighbors.append(
                {
                    "offset": noff,
                    "name": dm.group("name"),
                    "type": type_expr,
                    "typelock": True,
                    "source": "canon-decl",
                    "adopt_reason": "borders DWARF seed (partition guard)",
                }
            )
        if neighbors:
            adopted.setdefault(addr, []).extend(neighbors)
    return adopted


def _sleb128(blob, i):
    val = 0
    shift = 0
    while True:
        b = blob[i]
        i += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                val -= 1 << shift
            return val, i


def _decode_fbreg(blob):
    """Single-op DW_OP_fbreg(N) -> N; any other expression -> None."""
    if len(blob) >= 2 and blob[0] == 0x91:
        try:
            n, i = _sleb128(blob, 1)
        except IndexError:
            return None
        if i == len(blob):
            return n
    return None


def _ref_abs(unit, attr):
    """DIE reference value -> section-absolute offset (ref1/2/4/8/udata are
    CU-relative; DW_FORM_ref_addr already absolute)."""
    if attr.form == "DW_FORM_ref_addr":
        return attr.value
    return unit.cu_offset + attr.value


def _die_attr(die, name):
    return die.attributes.get(name)


def _attr_str(attr):
    return attr.value.decode() if attr and isinstance(attr.value, bytes) else None


def _origin_chain(unit, die):
    """[die, origin...] — the concrete DIE first, then abstract-origin /
    specification targets (location/name/type lookups walk the chain)."""
    chain = [die]
    cur = die
    for _ in range(16):
        ref = _die_attr(cur, "DW_AT_abstract_origin") or _die_attr(
            cur, "DW_AT_specification"
        )
        if ref is None:
            break
        nxt = unit.get_DIE_from_refaddr(_ref_abs(unit, ref))
        if nxt is None:
            break
        chain.append(nxt)
        cur = nxt
    return chain


def _chain_attr(chain, name):
    for die in chain:
        attr = _die_attr(die, name)
        if attr is not None:
            return attr
    return None


def _type_spell(unit, tattr, bool_arrays, depth=0):
    """DW_AT_type attr -> (spelling|None, reason) in the seed channel's
    servable domain (KNOWN_BASES + pointer/array composition)."""
    if depth > 12 or tattr is None:
        return None, "no-type"
    tdir = unit.get_DIE_from_refaddr(_ref_abs(unit, tattr))
    if tdir is None:
        return None, "unresolved-type"
    if tdir.tag == "DW_TAG_base_type":
        name = _attr_str(_die_attr(tdir, "DW_AT_name")) or ""
        if name in ("int", "char"):
            return name, None
        return None, "base-" + name
    if tdir.tag in ("DW_TAG_const_type", "DW_TAG_volatile_type"):
        return _type_spell(
            unit, _die_attr(tdir, "DW_AT_type"), bool_arrays, depth + 1
        )
    if tdir.tag == "DW_TAG_typedef":
        name = _attr_str(_die_attr(tdir, "DW_AT_name")) or ""
        if name in KNOWN_BASES:
            return name, None
        return None, "typedef-" + name
    if tdir.tag == "DW_TAG_pointer_type":
        inner = _die_attr(tdir, "DW_AT_type")
        spell, why = _type_spell(unit, inner, bool_arrays, depth + 1)
        if spell is None:
            return None, why or "ptr-inner"
        return spell + " *", None
    if tdir.tag == "DW_TAG_array_type":
        count = None
        for child in tdir.iter_children():
            if child.tag == "DW_TAG_subrange_type":
                cnt = _die_attr(child, "DW_AT_count")
                if cnt is not None:
                    count = cnt.value
                else:
                    ub = _die_attr(child, "DW_AT_upper_bound")
                    if ub is not None and isinstance(ub.value, int):
                        count = ub.value + 1  # lower bound defaults to 0
        inner_spell, why = _type_spell(
            unit, _die_attr(tdir, "DW_AT_type"), bool_arrays, depth + 1
        )
        if inner_spell is None:
            return None, why or "array-inner"
        if count is None:
            return None, "array-unknown-count"
        if bool_arrays and inner_spell == "char" and count in (256, 4096):
            # canon-committed boolean typing (stage_seed_diag-validated)
            return "bool[%d]" % count, None
        return "%s[%d]" % (inner_spell, count), None
    if tdir.tag in (
        "DW_TAG_structure_type",
        "DW_TAG_union_type",
        "DW_TAG_class_type",
        "DW_TAG_enumeration_type",
    ):
        return None, "composite"
    return None, tdir.tag


def _scope_range(die):
    lo = _die_attr(die, "DW_AT_low_pc")
    if lo is None:
        return None
    hi = _die_attr(die, "DW_AT_high_pc")
    hi_v = hi.value if hi is not None else 0
    if hi is not None and hi.form.startswith("DW_FORM_data"):
        hi_v = lo.value + hi.value  # offset form
    return [lo.value, hi_v]


def _named_composite_set(dw):
    """DWARF names resolvable by the Rust factory name lookup (the
    parse_type_names mirror): typedefs over composite/enum/array-with-size
    and named structure/union/enumeration DIEs with byte_size."""
    named = set()
    for unit in dw.iter_CUs():
        for die in unit.iter_DIEs():
            if die.tag in (
                "DW_TAG_structure_type",
                "DW_TAG_union_type",
                "DW_TAG_enumeration_type",
            ):
                name = _attr_str(_die_attr(die, "DW_AT_name"))
                size = _die_attr(die, "DW_AT_byte_size")
                if name and size is not None and size.value > 0:
                    named.add(name)
            elif die.tag == "DW_TAG_typedef":
                name = _attr_str(_die_attr(die, "DW_AT_name"))
                if not name:
                    continue
                tattr = _die_attr(die, "DW_AT_type")
                if tattr is None:
                    continue
                tdir = unit.get_DIE_from_refaddr(_ref_abs(unit, tattr))
                # chase through typedef/qualifier layers to a sized carrier
                for _ in range(16):
                    if tdir is None:
                        break
                    if tdir.tag in (
                        "DW_TAG_typedef",
                        "DW_TAG_const_type",
                        "DW_TAG_volatile_type",
                    ):
                        nxt = _die_attr(tdir, "DW_AT_type")
                        tdir = (
                            unit.get_DIE_from_refaddr(_ref_abs(unit, nxt))
                            if nxt is not None
                            else None
                        )
                        continue
                    break
                if tdir is None:
                    continue
                if tdir.tag in (
                    "DW_TAG_structure_type",
                    "DW_TAG_union_type",
                    "DW_TAG_enumeration_type",
                ):
                    size = _die_attr(tdir, "DW_AT_byte_size")
                    if size is not None and size.value > 0:
                        named.add(name)
                elif tdir.tag == "DW_TAG_array_type":
                    named.add(name)  # va_list-class: array typedef
    return named


def _type_spell_struct(unit, tattr, named, depth=0):
    """DW_AT_type attr -> (spelling|None, reason) in the C4 struct domain:
    bases must be DWARF-named composites/typedefs (factory name lookup);
    KNOWN_BASES spellings are the C1/C2 channel's domain, dropped here."""
    if depth > 12 or tattr is None:
        return None, "no-type"
    tdir = unit.get_DIE_from_refaddr(_ref_abs(unit, tattr))
    if tdir is None:
        return None, "unresolved-type"
    if tdir.tag in ("DW_TAG_const_type", "DW_TAG_volatile_type"):
        return _type_spell_struct(
            unit, _die_attr(tdir, "DW_AT_type"), named, depth + 1
        )
    if tdir.tag == "DW_TAG_typedef":
        name = _attr_str(_die_attr(tdir, "DW_AT_name")) or ""
        if name in named:
            return name, None
        return None, "typedef-unservable-" + name
    if tdir.tag == "DW_TAG_pointer_type":
        inner = _die_attr(tdir, "DW_AT_type")
        spell, why = _type_spell_struct(unit, inner, named, depth + 1)
        if spell is None:
            return None, why or "ptr-inner"
        return spell + " *", None
    if tdir.tag == "DW_TAG_array_type":
        count = None
        for child in tdir.iter_children():
            if child.tag == "DW_TAG_subrange_type":
                cnt = _die_attr(child, "DW_AT_count")
                if cnt is not None:
                    count = cnt.value
                else:
                    ub = _die_attr(child, "DW_AT_upper_bound")
                    if ub is not None and isinstance(ub.value, int):
                        count = ub.value + 1
        inner_spell, why = _type_spell_struct(
            unit, _die_attr(tdir, "DW_AT_type"), named, depth + 1
        )
        if inner_spell is None:
            return None, why or "array-inner"
        if count is None:
            return None, "array-unknown-count"
        return "%s[%d]" % (inner_spell, count), None
    if tdir.tag in (
        "DW_TAG_structure_type",
        "DW_TAG_union_type",
        "DW_TAG_class_type",
        "DW_TAG_enumeration_type",
    ):
        name = _attr_str(_die_attr(tdir, "DW_AT_name"))
        if name and name in named:
            return name, None
        return None, "composite-unnamed"
    if tdir.tag == "DW_TAG_base_type":
        name = _attr_str(_die_attr(tdir, "DW_AT_name")) or ""
        return None, "c1c2-domain-" + name
    return None, tdir.tag


def _warn_if_no_dwarf(binary, elf):
    """Loud zero-yield verdict for DWARF-less corpora (HSEED lane: the
    httpd corpus is stripped — no .debug_* sections — so the C2/C4 channels
    are corpus-inapplicable, not merely empty). stdout stays parseable;
    the manifest bytes are unchanged (curl determinism preserved)."""
    if not any(s.name == ".debug_info" for s in elf.iter_sections()):
        sys.stderr.write(
            "WARNING: %s carries no .debug_info section (stripped corpus): "
            "the DWARF seed channel is corpus-inapplicable; harvest yield "
            "is provably 0 (C2/C4 need a DWARF-bearing binary)\n" % binary
        )


def harvest_struct(binary, golden_path):
    """C4 struct-seed table: DWARF-named composite locals + canon-decl
    struct-pointer local_[hex] adoption. Returns (functions, drops)."""
    from elftools.elf.elffile import ELFFile

    inventory = []
    dwarf_functions = set()
    with open(binary, "rb") as fh:
        elf = ELFFile(fh)
        _warn_if_no_dwarf(binary, elf)
        dw = elf.get_dwarf_info()
        named = _named_composite_set(dw)
        for unit in dw.iter_CUs():
            for top in unit.iter_DIEs():
                if top.tag != "DW_TAG_subprogram":
                    continue
                low = _die_attr(top, "DW_AT_low_pc")
                if low is None:
                    continue
                fn_name = None
                for die in _origin_chain(unit, top):
                    fn_name = _attr_str(_die_attr(die, "DW_AT_name"))
                    if fn_name:
                        break
                dwarf_functions.add((low.value, fn_name))
                stack = [(top, None)]
                while stack:
                    node, scope = stack.pop()
                    for child in node.iter_children():
                        if child.tag == "DW_TAG_subprogram":
                            if _die_attr(child, "DW_AT_low_pc") is not None:
                                stack.append((child, None))
                        elif child.tag in (
                            "DW_TAG_lexical_block",
                            "DW_TAG_inlined_subroutine",
                        ):
                            stack.append((child, child))
                        elif child.tag == "DW_TAG_variable":
                            inventory.append((low.value, fn_name, unit, child))
        functions = {}
        drops = []
        entries = []
        for low_pc, fn_name, unit, die in inventory:
            chain = _origin_chain(unit, die)
            name = None
            for cdie in chain:
                name = _attr_str(_die_attr(cdie, "DW_AT_name"))
                if name:
                    break
            loc = _chain_attr(chain, "DW_AT_location")
            if loc is None:
                continue
            if loc.form not in (
                "DW_FORM_exprloc",
                "DW_FORM_block",
                "DW_FORM_block1",
                "DW_FORM_block2",
                "DW_FORM_block4",
            ):
                continue
            fbreg = _decode_fbreg(bytes(loc.value))
            if fbreg is None:
                continue
            tattr = _chain_attr(chain, "DW_AT_type")
            spell, why = _type_spell_struct(unit, tattr, named)
            entries.append(
                {
                    "fn": fn_name or "<anon>",
                    "name": name,
                    "canon": "0x%x" % (low_pc + 0x100000),
                    "offset": fbreg + 8,
                    "type": spell,
                    "drop": why,
                }
            )
        # first DWARF claim per (function, slot) owns the slot (the
        # progressbar/passarg shadowing rule carries over verbatim)
        slot_owner = {}
        for e in entries:
            key = (e["canon"], e["offset"])
            if key not in slot_owner:
                slot_owner[key] = e
        seen = set()
        for e in entries:
            label = "%s/%s@%d" % (e["fn"], e["name"], e["offset"])
            if label in seen:
                drops.append((e["fn"], e["name"], "duplicate"))
                continue
            seen.add(label)
            if e["type"] is None:
                drops.append((e["fn"], e["name"], e["drop"] or "unservable"))
                continue
            owner = slot_owner[(e["canon"], e["offset"])]
            if owner is not e:
                drops.append(
                    (
                        e["fn"],
                        e["name"],
                        "slot-owned-by-%s(%s)"
                        % (owner["name"], owner["drop"] or owner["type"]),
                    )
                )
                continue
            fn = functions.setdefault(
                e["canon"], {"name": e["fn"], "locals": []}
            )
            fn["locals"].append(
                {
                    "offset": e["offset"],
                    "name": e["name"],
                    "type": e["type"],
                    "typelock": True,
                    "source": "dwarf-struct",
                }
            )
        # canon-decl adoption: local_[hex] declarators whose base names a
        # DWARF composite (getparameter Configurable *local_5b8 /
        # HttpPost *local_5a8); the function must itself be a DWARF
        # subprogram (the committed type's provenance).
        by_lowpc = {low: nm for low, nm in dwarf_functions}
        golden_text = open(golden_path, "r", encoding="utf-8").read()
        for addr, fn_name, lines in split_functions(golden_text):
            low = int(addr, 16) - 0x100000 if int(addr, 16) >= 0x100000 else None
            if low is None or low not in by_lowpc:
                continue
            for line in lines:
                dm = re.match(
                    r"^\s*([A-Za-z_][A-Za-z0-9_ ]*?)\s*(\*+)\s*"
                    r"(local_[0-9a-f]+)\s*((?:\[\d+\])*)\s*;",
                    line,
                )
                if dm is None:
                    continue
                base = dm.group(1).strip()
                if base not in named:
                    continue
                type_expr = parse_type_expr(dm.group(1), dm.group(2), dm.group(4))
                if type_expr is None:
                    continue
                name = dm.group(3)
                fn = functions.setdefault(addr, {"name": fn_name, "locals": []})
                if any(l["offset"] == -int(name[6:], 16) for l in fn["locals"]):
                    continue
                fn["locals"].append(
                    {
                        "offset": -int(name[6:], 16),
                        "name": name,
                        "type": type_expr,
                        "typelock": True,
                        "source": "canon-decl",
                        "adopt_reason": "struct-pointer base in DWARF named-type set",
                    }
                )
        for fn in functions.values():
            fn["locals"].sort(key=lambda local: local["offset"])
    return functions, drops


def harvest_dwarf(binary, golden_path=None, canon_types=True):
    """Walk the binary's .debug_info and build the DWARF-name seed table
    keyed by canon golden addresses (low_pc + 0x100000). Returns
    (functions, drops) where drops is the accounting list for the manifest."""
    from elftools.elf.elffile import ELFFile

    inventory = []
    with open(binary, "rb") as fh:
        elf = ELFFile(fh)
        _warn_if_no_dwarf(binary, elf)
        dw = elf.get_dwarf_info()
        for unit in dw.iter_CUs():
            for top in unit.iter_DIEs():
                if top.tag != "DW_TAG_subprogram":
                    continue
                low = _die_attr(top, "DW_AT_low_pc")
                if low is None:
                    continue
                fn_name = None
                for die in _origin_chain(unit, top):
                    fn_name = _attr_str(_die_attr(die, "DW_AT_name"))
                    if fn_name:
                        break
                stack = [(top, None)]
                while stack:
                    node, scope = stack.pop()
                    for child in node.iter_children():
                        if child.tag == "DW_TAG_subprogram":
                            if _die_attr(child, "DW_AT_low_pc") is not None:
                                stack.append((child, None))
                        elif child.tag in (
                            "DW_TAG_lexical_block",
                            "DW_TAG_inlined_subroutine",
                        ):
                            stack.append((child, child))
                        elif child.tag == "DW_TAG_variable":
                            inventory.append((low.value, fn_name, unit, child, scope))
                            stack.append((child, scope))
        # first DWARF claim per (function, slot) owns the slot
        slot_owner = {}
        entries = []
        for low_pc, fn_name, unit, die, scope in inventory:
            chain = _origin_chain(unit, die)
            name = None
            for cdie in chain:
                name = _attr_str(_die_attr(cdie, "DW_AT_name"))
                if name:
                    break
            loc = _chain_attr(chain, "DW_AT_location")
            if loc is None:
                continue
            if loc.form not in (
                "DW_FORM_exprloc",
                "DW_FORM_block",
                "DW_FORM_block1",
                "DW_FORM_block2",
                "DW_FORM_block4",
            ):
                continue  # sec_offset loc-list: Ghidra's importer drops it
            fbreg = _decode_fbreg(bytes(loc.value))
            if fbreg is None:
                continue  # DW_OP_addr static / piece / multi-op: other channels
            tattr = _chain_attr(chain, "DW_AT_type")
            spell, why = _type_spell(unit, tattr, canon_types)
            entries.append(
                {
                    "fn": fn_name or "<anon>",
                    "name": name,
                    "canon": "0x%x" % (low_pc + 0x100000),
                    "offset": fbreg + 8,
                    "type": spell,
                    "drop": why,
                    "inline": scope is not None
                    and scope.tag == "DW_TAG_inlined_subroutine",
                    "scope": _scope_range(scope) if scope is not None else None,
                }
            )
        slot_owner = {}
        for e in entries:
            key = (e["canon"], e["offset"])
            if key not in slot_owner:
                slot_owner[key] = e
        functions = {}
        drops = []
        seen = set()
        for e in entries:
            label = "%s/%s@%d" % (e["fn"], e["name"], e["offset"])
            if label in seen:
                drops.append((e["fn"], e["name"], "duplicate"))
                continue
            seen.add(label)
            if e["type"] is None:
                reason = e["drop"] or "unservable"
                drops.append((e["fn"], e["name"], reason))
                continue
            owner = slot_owner[(e["canon"], e["offset"])]
            if owner is not e:
                drops.append(
                    (
                        e["fn"],
                        e["name"],
                        "slot-owned-by-%s(%s)" % (owner["name"], owner["drop"] or owner["type"]),
                    )
                )
                continue
            fn = functions.setdefault(
                e["canon"], {"name": e["fn"], "locals": []}
            )
            fn["locals"].append(
                {
                    "offset": e["offset"],
                    "name": e["name"],
                    "type": e["type"],
                    "typelock": True,
                    "lex_scope": e["scope"] is not None,
                    "inline_origin": e["inline"],
                    "scope_range": e["scope"],
                }
            )
        for fn in functions.values():
            fn["locals"].sort(key=lambda local: local["offset"])
    if golden_path is not None:
        adopted = _canon_neighbor_seeds(
            open(golden_path, "r", encoding="utf-8").read(), functions
        )
        for addr, neighbors in adopted.items():
            functions[addr]["locals"].extend(neighbors)
            functions[addr]["locals"].sort(key=lambda local: local["offset"])
    return functions, drops


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--struct":
        if len(sys.argv) < 6:
            print(__doc__)
            return 2
        binary, golden, corpus, oracle_commit, out = sys.argv[2:7]
        funcs, drops = harvest_struct(binary, golden)
        nlocals = sum(len(f["locals"]) for f in funcs.values())
        # HSEED lane: the residual ledger below is curl-corpus truth (the
        # C3NEXT §12.4 registration); any other corpus must not inherit
        # curl's residual claims. Curl keeps the exact historical notes so
        # a re-harvest stays byte-identical to the committed manifest.
        if corpus == "curl":
            residual_notes = [
                "main `URLGlob glob` (canon-only inlined glob_url param): "
                "no DWARF variable location; C3+C4 residual",
                "match_url `glob` (by-value stack formal): C3 prototype domain",
                "main `Configurable *config` (register variable, no stack "
                "slot): localdb register-symbol domain residual",
                "sec_offset loc-list variables: Ghidra's own importer drops "
                "them (canon never names i/res/url); pre-registered domain",
                "canon `/* Unresolved local var */` comment blocks: Java "
                "front-end artifact (not in decompile/cpp), comment-channel "
                "residual",
            ]
        else:
            residual_notes = [
                "corpus residual ledger not yet established (non-curl "
                "first harvest); register per-residual after oracle "
                "prevalidation",
                "sec_offset loc-list variables: Ghidra's own importer drops "
                "them (corpus-independent domain)",
            ]
        manifest = {
            "oracle_commit": oracle_commit,
            "corpus": corpus,
            "source": "dwarf-struct",
            "binary_sha256": hashlib.sha256(open(binary, "rb").read()).hexdigest(),
            "golden_sha256": hashlib.sha256(open(golden, "rb").read()).hexdigest(),
            "harvest_rule": STRUCT_HARVEST_RULE,
            "functions": funcs,
            "harvest_drops": [
                {"function": f, "name": n or "<anon>", "reason": r}
                for f, n, r in drops
            ],
            "residual_notes": residual_notes,
        }
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=1)
        print(
            "harvested %d functions / %d struct-typed locals (%d drops) -> %s"
            % (len(funcs), nlocals, len(drops), out)
        )
        return 0
    if len(sys.argv) >= 2 and sys.argv[1] == "--dwarf":
        if len(sys.argv) < 6:
            print(__doc__)
            return 2
        binary, golden, corpus, oracle_commit, out = sys.argv[2:7]
        raw_types = "--dwarf-raw-types" in sys.argv[7:]
        funcs, drops = harvest_dwarf(binary, golden_path=golden, canon_types=not raw_types)
        nlocals = sum(len(f["locals"]) for f in funcs.values())
        manifest = {
            "oracle_commit": oracle_commit,
            "corpus": corpus,
            "source": "dwarf",
            "binary_sha256": hashlib.sha256(open(binary, "rb").read()).hexdigest(),
            "golden_sha256": hashlib.sha256(open(golden, "rb").read()).hexdigest(),
            "harvest_rule": DWARF_HARVEST_RULE
            + (" [raw DWARF typing]" if raw_types else ""),
            "functions": funcs,
            "harvest_drops": [
                {"function": f, "name": n or "<anon>", "reason": r}
                for f, n, r in drops
            ],
        }
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=1)
        print(
            "harvested %d functions / %d DWARF-named locals (%d drops) -> %s"
            % (len(funcs), nlocals, len(drops), out)
        )
        return 0
    if len(sys.argv) < 5:
        print(__doc__)
        return 2
    golden, corpus, oracle_commit, out = sys.argv[1:5]
    typed_only = "--typed-only" in sys.argv[5:]
    funcs = harvest(golden)
    if typed_only:
        for fn in funcs.values():
            fn["locals"] = [l for l in fn["locals"] if not l["type"].startswith("undefined")]
        funcs = {k: v for k, v in funcs.items() if v["locals"]}
    nlocals = sum(len(f["locals"]) for f in funcs.values())
    manifest = {
        "oracle_commit": oracle_commit,
        "corpus": corpus,
        "golden_sha256": hashlib.sha256(open(golden, "rb").read()).hexdigest(),
        "harvest_rule": (
            "decl-block lines matching '(type)([*]*)local_[0-9a-f]+([N])*;' before "
            "first statement; offset = -int(name[6:],16)"
        ),
        "functions": funcs,
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1)
    print(
        "harvested %d functions / %d committed locals (%s) -> %s"
        % (len(funcs), nlocals, "typed-only" if typed_only else "all", out)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
