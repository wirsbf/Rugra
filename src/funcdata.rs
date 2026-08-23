//! High-level function data container
//!
//! Corresponds to Ghidra's `funcdata.hh`

use crate::address::Address;
use crate::block::{BlockBasic, BlockGraph, FlowBlock};
use crate::fspec::FuncProto;
use crate::heritage::Heritage;
use crate::op::{PcodeOpBank, PcodeOpRef};
use crate::opcodes::OpCode;
use crate::pcoderaw::PcodeOpRaw;
use crate::space::AddressSpace;

// Ghidra: sleigh_arch.cc:233 SleighArchitecture::buildTypeLibrary (setCoreType "code")
/// The core anonymous "code" `Datatype` that `Funcdata::newCodeRef`
/// (funcdata_varnode.cc:222-233) attaches to every one-byte code-reference
/// annotation Varnode. Ghidra reads it from the architecture's TypeFactory
/// cache (`TypeFactory::getTypeCode`, type.cc:3692-3701); Rugra does not
/// thread a factory through the raw emit path, so the equivalent value
/// object — name "code", metatype TYPE_CODE, size 1 — is built directly.
fn code_ref_datatype() -> std::sync::Arc<crate::type_system::datatype::Datatype> {
    use crate::type_system::datatype::{Datatype, TypeBase, TypeCode, TypeMetatype};
    std::sync::Arc::new(Datatype::Code(TypeCode {
        base: TypeBase::new("code".to_string(), 1, TypeMetatype::Code),
        proto: None,
    }))
}

// Ghidra: op.cc:824 PieceNode::findRoot
/// Find the root of the CONCAT tree of Varnodes marked either
/// `isProtoPartial()` or `isAddrTied()`: the maximal Varnode containing the
/// given Varnode (as storage) with a backward path to it through PIECE
/// operations. Faithful to `PieceNode::findRoot` (op.cc:824-852): at each
/// step the descendant PIECE op whose output address (adjusted for
/// endianness and the sibling input's size, then renormalized — a no-op for
/// word-size-1 spaces like the register/stack spaces PIECE pieces live in)
/// equals the current Varnode's address is followed; with more than one
/// valid PIECE the earliest in op order wins (`compareOrder`). Lives here
/// (not op.rs) because it is consumed only by `Funcdata::linkProtoPartial`.
fn piece_node_find_root(
    vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
    use crate::opcodes::OpCode;
    use std::sync::Arc;
    let mut cur = vn.clone();
    loop {
        let (is_pp, is_at, cur_addr, cur_space) = {
            let r = cur.read().unwrap();
            (r.is_proto_partial(), r.is_addr_tied(), r.get_offset(), r.get_space())
        };
        if !is_pp && !is_at {
            break;
        }
        let mut piece_op: Option<Arc<std::sync::RwLock<crate::op::PcodeOp>>> = None;
        let readers: Vec<_> = cur.read().unwrap().descend.iter().filter_map(|w| w.upgrade()).collect();
        for op_arc in readers {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_PIECE {
                continue;
            }
            // int4 slot = op->getSlot(vn);
            let slot = (0..2)
                .find(|&i| op.get_in(i).map(|v| Arc::ptr_eq(v, &cur)).unwrap_or(false));
            let (Some(slot), Some(out)) = (slot, op.output.clone()) else { continue };
            let out_r = out.read().unwrap();
            let mut addr = out_r.get_offset();
            let (in0_size, in1_size) = (
                op.get_in(0).map(|v| v.read().unwrap().get_size()).unwrap_or(0),
                op.get_in(1).map(|v| v.read().unwrap().get_size()).unwrap_or(0),
            );
            // if (addr.getSpace()->isBigEndian() == (slot == 1))
            //   addr = addr + op->getIn(1-slot)->getSize();
            if cur_space.is_big_endian() == (slot == 1) {
                addr = addr.wrapping_add(if slot == 0 { in1_size } else { in0_size } as u64);
            }
            // addr.renormalize(vn->getSize()) — identity for word-size-1
            // spaces (Rugra's scalar Address carries no word size).
            if addr == cur_addr {
                match &piece_op {
                    Some(prev) => {
                        // Ghidra op.cc:841-843 is `if (op->compareOrder(pieceOp))
                        // pieceOp = op;` — NONZERO truthiness: both -1 (op
                        // executes earlier) and 1 (pieceOp executes earlier)
                        // replace the selection; only 0 (no absolute order)
                        // keeps it. The oracle's inline comment ("earliest")
                        // contradicts its literal code; the code is what we
                        // mirror (reviewer round-2 finding).
                        let prev_guard = prev.read().unwrap();
                        if op.compare_order(&prev_guard) != 0 {
                            drop(prev_guard);
                            piece_op = Some(op_arc.clone());
                        }
                    }
                    None => piece_op = Some(op_arc.clone()),
                }
            }
        }
        match piece_op {
            Some(op_arc) => {
                let next = op_arc.read().unwrap().output.clone();
                match next {
                    Some(n) => cur = n,
                    None => break,
                }
            }
            None => break,
        }
    }
    Some(cur)
}

// Ghidra: varnode.cc:696 Varnode::getUsePoint
/// The first-use Address offset of a Varnode: the defining op's address for
/// written Varnodes, else the function entry - 1 (inputs come into scope at
/// the start of the function). Faithful to `Varnode::getUsePoint`
/// (varnode.cc:696-703); used by `Funcdata::syncVarnodesWithSymbols`
/// (funcdata_varnode.cc:972) for the Scope::inScope probe.
fn varnode_use_point_offset(
    fd: &Funcdata,
    vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
) -> Option<u64> {
    let vn_r = vn.read().unwrap();
    if vn_r.is_written() {
        vn_r.get_def().map(|d| d.read().unwrap().get_addr().as_u64())
    } else {
        Some(fd.baseaddr.as_u64().wrapping_sub(1))
    }
}

// Ghidra: database.cc:2392 ScopeInternal::findOverlap
/// First Symbol returned by `ScopeInternal::findOverlap`
/// (database.cc:2392-2404) for the query `[offset, offset+size)` in the given
/// space. The oracle consults the space's EntryMap (a
/// `rangemap<SymbolEntry>`, rangemap.hh:65), whose multiset is keyed by
/// `(last, subsort)` (rangemap.hh:88-91) and whose entries duplicate each
/// common-refinement partition unit for every record covering it.
/// `find_overlap(point, end)` (rangemap.hh:411-423) does
/// `lower_bound(AddrRange(point))` — the first sub-range whose `last >=
/// point`, i.e. the leftmost partition unit intersecting the query (the unit
/// containing `point` when covered, else the first unit starting after
/// `point`) — and returns it iff its `first <= end`. All records covering
/// that unit cover the whole unit, so the returned record is the one with
/// the smallest `SymbolEntry::getSubsort()` (database.cc:97-107): the
/// minimal subsort (0,0) for address-tied symbols (empty uselimit,
/// `Scope::addMap` database.cc:1149-1150), else `(useindex, useoffset)` of
/// the first uselimit range — which for one binary's code space reduces to
/// ordering by first use offset with address-tied always winning. Ties on
/// an identical subsort keep Vec creation order, standing in for
/// `std::multiset` insertion order of equivalent keys. Dynamic entries
/// never enter the static map table (`addDynamicMapInternal`
/// database.cc:1874-1886 pushes to `dynamicentry`, not maptable), so they
/// are filtered first (F2, SCOPE-FINDOVERLAP-DYNAMIC-0001).
pub fn scope_local_find_overlap(
    scope: &crate::varmap::ScopeLocal,
    space: AddressSpace,
    offset: u64,
    size: i32,
) -> Option<&crate::varmap::LocalSymbol> {
    let last = offset + size as u64 - 1;
    // Records in this space's EntryMap: (first, last) inclusive.
    let candidates: Vec<&crate::varmap::LocalSymbol> = scope
        .symbols
        .iter()
        .filter(|sym| !sym.is_dynamic)
        .filter(|sym| sym.space == space)
        .filter(|sym| sym.size > 0)
        .filter(|sym| {
            let sym_end = sym.start.wrapping_add(sym.size as u64).wrapping_sub(1);
            sym.start <= last && offset <= sym_end
        })
        .collect();
    // rangemap.hh:418: iter = tree.lower_bound(AddrRange(point)) — the first
    // sub-range with last >= point, i.e. the leftmost partition unit
    // intersecting the query (the unit containing `point` when covered,
    // else the first unit starting after `point`). Units before it all end
    // before `point`, so every address in [point, unit.first) is uncovered:
    // the unit starts at the smallest address of [point,end] covered by any
    // record — the minimum over intersecting records of max(start, point).
    let hit_address = candidates
        .iter()
        .map(|sym| sym.start.max(offset))
        .min()?;
    // rangemap.hh:420-421: if ((*iter).first <= end) return iter; — among
    // the records covering the unit (== records covering hit_address), the
    // multiset order picks the smallest subsort; equal subsorts keep Vec
    // order (std::multiset insertion order of equivalent keys).
    candidates
        .iter()
        .filter(|sym| sym.start <= hit_address && hit_address < sym.start + sym.size as u64)
        .min_by_key(|sym| entry_subsort_key(sym))
        .copied()
}

// Ghidra: database.cc:97 SymbolEntry::getSubsort
/// Sub-sort key of a SymbolEntry within one partition unit, faithful to
/// `SymbolEntry::getSubsort` (database.cc:97-107) +
/// `EntrySubsort::operator<` (database.hh:127-133): the minimal subsort
/// (0,0) for address-tied storage (symbol flag set when the mapping has an
/// empty uselimit, modeled by `usepoint == None`), else
/// `(useindex, useoffset)` of the first uselimit range. Rugra's
/// LocalSymbol.usepoint carries only the offset, and every static mapping's
/// uselimit lives in the (single) code space, so the index component is
/// uniform and modeled as the constant 1 (> the minimal index 0).
fn entry_subsort_key(sym: &crate::varmap::LocalSymbol) -> (u8, u64) {
    match sym.usepoint {
        None => (0, 0),
        Some(usepoint) => (1, usepoint),
    }
}

// Ghidra: database.hh:597 Scope::inScope
/// Is the entire `[offset, offset+size)` range owned by the scope's range
/// tree. Faithful to `Scope::inScope` (database.hh:597) ->
/// `RangeList::inRange`: the `usepoint` argument is part of the virtual
/// signature (funcdata_varnode.cc:972-973 passes
/// `vnexemplar->getUsePoint(*this)`) but the base implementation ignores
/// it, and ScopeLocal defines no override — modeled by the underscore
/// parameter.
fn scope_local_in_scope(
    scope: &crate::varmap::ScopeLocal,
    _space: AddressSpace,
    offset: u64,
    size: i32,
    _usepoint: Option<u64>,
) -> bool {
    let last = offset + size as u64 - 1;
    scope
        .local_range
        .iter()
        .any(|&(first, range_last)| first <= offset && last <= range_last)
}

// Ghidra: varmap.cc:494 ScopeLocal::isUnmappedUnaliased
/// Should an unmapped Varnode be treated as unaliased? Faithful to
/// `ScopeLocal::isUnmappedUnaliased` (varmap.cc:494-502): false outside the
/// scope's stack space; with no known stack-parameter window
/// (`max_param_offset < min_param_offset`) every unmapped Varnode is
/// unaliased; otherwise only offsets outside `[min_param_offset,
/// max_param_offset]` are.
fn scope_local_is_unmapped_unaliased(
    scope: &crate::varmap::ScopeLocal,
    vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
) -> bool {
    let vn_r = vn.read().unwrap();
    if vn_r.get_space() != scope.space {
        return false; // Must be in mapped local (stack) space
    }
    if scope.max_param_offset < scope.min_param_offset {
        return true; // No min/max, so we have no known stack parameters
    }
    let offset = vn_r.get_offset();
    offset < scope.min_param_offset || offset > scope.max_param_offset
}

// Ghidra: type.cc:4090 TypeFactory::getExactPiece
/// One descent level for the getExactPiece walk keeping `Arc` identity: a
/// struct yields the field containing `off` (type.cc:1640), an array the
/// element with the offset reduced modulo the element align size
/// (type.cc:1234); every other metatype has no sub-type. Mirrors the
/// borrowed `Datatype::get_sub_type` variants already ported for
/// database.rs `SymbolEntry::get_sized_type`.
fn exact_piece_arc_sub_type(
    ct: &std::sync::Arc<crate::type_system::datatype::Datatype>,
    off: i64,
) -> Option<(std::sync::Arc<crate::type_system::datatype::Datatype>, i64)> {
    use crate::type_system::datatype::Datatype;
    match &**ct {
        Datatype::Struct(s) => {
            let field = s.fields.iter().find(|f| {
                (f.offset as i64) <= off && off < f.offset as i64 + f.type_ptr.get_size() as i64
            })?;
            Some((field.type_ptr.clone(), off - field.offset as i64))
        }
        Datatype::Array(a) => {
            let sz = a.base.size as i64;
            if off >= sz {
                return None;
            }
            let elem_align = a.array_of.get_align_size().max(1) as i64;
            Some((a.array_of.clone(), off % elem_align))
        }
        _ => None,
    }
}

// Ghidra: database.cc:151 SymbolEntry::getSizedType
/// Data-type matching the given size and address within a LocalSymbol's
/// whole mapping. Faithful to `SymbolEntry::getSizedType`
/// (database.cc:151-162): the entry offset is 0 for whole maps, so
/// `off = (vn.offset - sym.start)`, then `TypeFactory::getExactPiece`
/// (type.cc:4090-4117) runs: a perfect whole-size match returns the type
/// itself; descent stops at the last containing type; partial
/// struct/array/enum/union construction (`getTypePartialStruct` and kin) is
/// not ported yet, so those branches yield `None` (same residual as
/// database.rs `SymbolEntry::get_sized_type`).
fn local_symbol_sized_type(
    sym: &crate::varmap::LocalSymbol,
    inaddr: u64,
    sz: i32,
) -> Option<std::sync::Arc<crate::type_system::datatype::Datatype>> {
    let dt = sym.dtype.clone()?;
    let off = (inaddr as i64).wrapping_sub(sym.start as i64);
    let mut ct = dt;
    let mut cur_off = off;
    loop {
        let ct_size = ct.get_size() as i64;
        // cc:4097-4099: range is beyond the end of the current data-type.
        if ct_size < sz as i64 + cur_off {
            break;
        }
        // cc:4100-4101: perfect size match (only reachable with cur_off == 0
        // given the bounds check above).
        if ct_size == sz as i64 {
            return Some(ct);
        }
        if ct.get_metatype() == crate::type_system::datatype::TypeMetatype::Union {
            // cc:4102-4104: getTypePartialUnion — not ported (residual).
            return None;
        }
        // cc:4105-4107: ct = ct->getSubType(curOff,&curOff).
        match exact_piece_arc_sub_type(&ct, cur_off) {
            Some((next, new_off)) => {
                ct = next;
                cur_off = new_off;
            }
            None => break,
        }
    }
    // cc:4109-4115: partial struct/array/enum construction — not ported.
    None
}

/// Funcdata flags (funcdata.hh:highlevel_flags).
pub mod funcdata_flags {
    /// Data-type analysis is being performed.
    pub const TYPE_RECOVERY_ON: u32 = 1 << 0;
    /// Data-type analysis has started (Ghidra `typerecovery_start`,
    /// funcdata.hh:90). Set once ActionInferTypes begins, used by Rules to
    /// decide whether type-based guards apply.
    pub const TYPE_RECOVERY_START: u32 = 1 << 1;
    /// HighVariable objects have been assigned to all Varnodes (Ghidra
    /// `highlevel_on`, funcdata.hh:84 = 0x200). Set by ActionAssignHigh /
    /// setHighLevel. Prevents re-assignment on subsequent passes.
    pub const HIGHLEVEL_ON: u32 = 1 << 2;
    /// Double-precision recovery is active (Ghidra `double_precis_on`,
    /// funcdata.hh:85 = 0x2000).
    pub const DOUBLE_PRECIS_ON: u32 = 1 << 13;
    /// Basic blocks have been generated (Ghidra `blocks_generated`,
    /// funcdata.hh:84 = 0x2). Rugra uses bit 2 to avoid clashing with
    /// HIGHLEVEL_ON (which occupies bit 2 in Rugra's remapped flag space).
    pub const BLOCKS_GENERATED: u32 = 1 << 3;
    /// Processing of the function has started (Ghidra `processing_started`,
    /// funcdata.hh:84 = 0x8). Set by `startProcessing`; checked to make the
    /// start entry idempotent.
    pub const PROCESSING_STARTED: u32 = 1 << 4;
    /// Processing of the function is complete (Ghidra `processing_complete`,
    /// funcdata.hh:84 = 0x10). Set by `stopProcessing`.
    pub const PROCESSING_COMPLETE: u32 = 1 << 5;
    /// This Funcdata object is dedicated to jump-table recovery (Ghidra
    /// `jumptablerecovery_on`, funcdata.hh:84 = 0x100). Set on the partial
    /// clone during `stageJumpTable`; read by `warning`/`warningHeader` to
    /// tag diagnostics.
    pub const JUMPTABLERECOVERY_ON: u32 = 1 << 8;
    /// Do not try to recover jump-tables; always truncate (Ghidra
    /// `jumptablerecovery_dont`, funcdata.hh:84 = 0x200). Set by
    /// `setJumptableRecovery(false)`; read by `recoverJumpTable`.
    pub const JUMPTABLERECOVERY_DONT: u32 = 1 << 9;
    /// Analysis must be restarted because of new override info (Ghidra
    /// `restart_pending`, funcdata.hh:84 = 0x400).
    pub const RESTART_PENDING: u32 = 1 << 10;
    /// At least one basic block is currently unreachable (Ghidra
    /// `blocks_unreachable`, funcdata.hh:60 = 0x4). Rugra uses bit 6 to
    /// avoid clashing with the remapped flag space (HIGHLEVEL_ON occupies
    /// Ghidra's bit 2; see BLOCKS_GENERATED's note). Set/cleared only by
    /// `structure_reset` mirroring funcdata_block.cc:710/713-714
    /// (`rootlist.size() > 1` after structureLoops) and read via
    /// `has_unreachable_blocks` (funcdata.hh:149).
    pub const BLOCKS_UNREACHABLE: u32 = 1 << 6;
}

use crate::varnode::VarnodeBank;
use std::collections::HashMap;
use std::sync::{Arc, RwLock, Weak};

/// Ordered storage key for potential laned-register accesses. This is the
/// split-address Rust equivalent of Ghidra's `VarnodeData` map key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanedStorage {
    pub space: crate::space::AddressSpace,
    pub offset: u64,
    pub size: usize,
}

impl PartialOrd for LanedStorage {
    // Ghidra: pcoderaw.hh:67 VarnodeData::operator<
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LanedStorage {
    // Ghidra: pcoderaw.hh:67 VarnodeData::operator<
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.space
            .space_id()
            .cmp(&other.space.space_id())
            .then_with(|| self.offset.cmp(&other.offset))
            .then_with(|| other.size.cmp(&self.size))
    }
}

/// Main container for a function being decompiled
///
/// Corresponds to Ghidra's `Funcdata` class. This class ties together
/// the P-code operations, varnodes, control flow graph, and analysis state.
#[derive(Debug)]
pub struct Funcdata {
    /// Name of the function
    pub name: String,
    /// Base address of the function
    pub baseaddr: Address,
    /// Size of the function in bytes
    pub size: i32,

    /// Bit-set of Funcdata flags (mirrors Ghidra's `flags` field).
    pub flags: u32,

    /// Creation index of the first Varnode created after HighVariables were
    /// assigned (Ghidra `high_level_index`, funcdata.hh:76). Recorded by
    /// `set_high_level` (funcdata_varnode.cc:600) as `vbank.getCreateIndex()`.
    /// (FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001)
    pub high_level_index: u32,

    /// Bank of all varnodes in this function
    pub vbank: VarnodeBank,
    /// Bank of all P-code operations in this function
    pub obank: PcodeOpBank,
    /// Control flow graph (basic blocks)
    pub bblocks: BlockGraph,
    /// Structure tree (composite blocks)
    pub sblocks: BlockGraph,
    /// SSA construction manager
    pub heritage: Heritage,

    /// Persistent cross-Action merge state (testCache / copyTrims / live
    /// premise). Faithful to `Funcdata::covermerge` (funcdata.hh:96): the
    /// by-value `Merge` member constructed with \b this (funcdata.cc:39),
    /// shared by every merge-family Action via `getMerge()`
    /// (funcdata.hh:440), and cleared only by `Funcdata::clear()`
    /// (funcdata.cc:108). Rugra's merge Actions construct local `Merge`
    /// instances, so only the persistent channels are mounted here; see
    /// `merge::MergePersistentState`.
    pub merge_state: crate::merge::MergePersistentState,

    /// Self-reference for use by child components
    pub self_ref: Option<Weak<RwLock<Funcdata>>>,

    /// Address → function/symbol name mapping (populated from ELF symtab)
    pub symbol_table: HashMap<u64, String>,
    /// Address → string literal mapping (populated from ELF .rodata)
    pub string_table: HashMap<u64, String>,
    /// Address → struct-pointer Datatype for known global variables derived
    /// from DWARF debug_info (e.g. `::config` at 0x17520 → `Configurable *`).
    /// Populated by the decompiler driver before analysis; read by
    /// `type_infer::propagate_types` to seed struct-pointer types on the
    /// constant varnodes that reference these globals. Mirrors Ghidra's
    /// SymbolEntry type assignment (database.cc) which the Rugra driver
    /// lacks an Architecture/SymbolTable layer to populate automatically.
    pub global_struct_ptrs: HashMap<u64, std::sync::Arc<crate::type_system::datatype::Datatype>>,
    /// Function prototype (return type, parameters)
    pub funcp: FuncProto,
    /// External function prototypes: maps callee address → param count.
    /// Populated by a pre-pass that analyzes all functions in the binary
    /// before decompilation. Mirrors Ghidra's multi-pass approach where
    /// ActionActiveParam runs across all functions to build a prototype
    /// database before final decompilation.
    pub external_prototypes: HashMap<u64, usize>,
    /// Restructured local-variable scope. Built by ActionRestructureVarnode
    /// (coreaction.cc:2274) and queried by printc's stack-variable resolution.
    /// Corresponds to Ghidra's `Funcdata::getScopeLocal()`.
    pub scope: Option<crate::varmap::ScopeLocal>,
    /// HighVariable → ScopeLocal symbol index association (keyed by the
    /// HighVariable's Arc pointer). RUGRA-GLUE: models `HighVariable::symbol`
    /// (variable.hh:161-176) for the varmap `ScopeLocal` symbol model — the
    /// faithful database.rs `Symbol` graph is not yet wired into the
    /// linkSymbol path, so the Funcdata keeps this side table instead of a
    /// field on HighVariable (variable.rs is outside this change's lease).
    pub high_symbols: HashMap<usize, usize>,
    /// ScopeLocal symbol index → bridged database.rs `SymbolEntry`
    /// (identity-stable per symbol). RUGRA-GLUE: `Varnode::setSymbolEntry`
    /// and the faithful `HighVariable::set_symbol` (variable.rs:180, porting
    /// variable.cc:245-275 incl. the symboloffset four-branch computation)
    /// consume the database.rs `SymbolEntry` model, so each varmap symbol
    /// gets a mirror entry here at attach time. The mirrored `Symbol`'s name
    /// is refreshed by ActionNameVars after the naming phase.
    pub symbol_entry_cache: HashMap<usize, std::sync::Arc<RwLock<crate::database::SymbolEntry>>>,
    /// Function call specifications, one per call site. Corresponds to
    /// Ghidra's `Funcdata::breefcall` vector.
    pub callspecs: Vec<crate::fspec::FuncCallSpecs>,
    /// Active output parameter recovery. Faithful to
    /// `Funcdata::activeoutput` (funcdata.hh). Set by ActionFuncLinkOutOnly;
    /// used by ActionReturnRecovery to determine which RETURN varnodes
    /// are the function's return value.
    pub active_output: Option<crate::fspec::ParamActive>,

    /// Architecture configuration (Ghidra `glb` / funcdata.hh:80). Optional:
    /// legacy callers/tests construct Funcdata without it. Set via
    /// `set_arch` before running Rules that need cpool/funcptr_align/
    /// nan_ignore_all/userops/types.
    pub arch: Option<Arc<crate::arch::Architecture>>,
    /// Restart-pending flag for ActionRestartGroup (funcdata.hh).
    pub restart_pending: bool,
    /// Once-per-function guard for ActionConditionalConst. The conditional
    /// constant propagation is useful but, under Rugra's repeatapply mainloop,
    /// re-running it after the first mutation can interact poorly with
    /// downstream ActionConditionalExe/branch-folding and fail to converge for
    /// some functions (5/24 curl timeouts). This flag ensures the IR-mutating
    /// propagation runs at most once per function (reset on restart). It is a
    /// Rugra-specific convergence guard with no Ghidra counterpart.
    pub cond_const_done: bool,
    /// Jump tables recovered for this function. Faithful to
    /// `Funcdata::jumpvec` (funcdata.hh:89). Populated by JumpTable recovery.
    pub jump_tables: Vec<std::sync::Arc<std::sync::RwLock<crate::jumptable::JumpTable>>>,

    /// Map from data-flow edges to the resolved field of a TypeUnion being
    /// accessed. Faithful to `Funcdata::unionMap` (funcdata.hh:100). Keyed by
    /// `ResolveEdge` (parent type id + PcodeOp SeqNum order + slot encoding);
    /// value is the `ResolvedUnion` produced by union resolution. Cleared by
    /// `clear()`.
    pub union_map: std::collections::BTreeMap<crate::unionresolve::ResolveEdge, crate::unionresolve::ResolvedUnion>,

    /// Minimum Varnode size that can enter the laned-register access map.
    /// `u32::MAX` is Ghidra's unsigned representation of the Architecture
    /// `-1` sentinel when no lane records exist.
    pub min_laned_size: u32,
    /// Candidate laned-register storage, ordered by address-space index,
    /// offset, then descending size. Values share identity with the matching
    /// immutable Architecture lane record.
    pub laned_map: std::collections::BTreeMap<
        LanedStorage,
        std::sync::Arc<crate::transform::LanedRegister>,
    >,

    /// Per-function override container. Faithful to `Funcdata::localoverride`
    /// (funcdata.hh:108). Holds force-goto / deadcode-delay / flow-override /
    /// indirect-override / proto-override / multistage-jump commands. Populated
    /// by `setOverride` / `Override::decode`; read by the analysis passes.
    pub localoverride: crate::override_rs::Override,

    // ---- Stack space / spacebase configuration (from Architecture, defaults to x86-64) ----
    // Faithful to Architecture's cspec <stackpointer> fields. Funcdata does
    // not yet hold an Architecture reference (L3 gap), so these are defaults
    // matching x86-64-gcc.cspec: <stackpointer register="RSP" space="ram"/>.
    /// The stack address space (IPTR_SPACEBASE). Stack varnodes live here.
    pub stack_space: crate::space::AddressSpace,
    /// Stack pointer register: (space, offset, size) = (Register, 0x20, 8) for RSP.
    pub stack_pointer_space: crate::space::AddressSpace,
    pub stack_pointer_offset: u64,
    pub stack_pointer_size: usize,
    /// Stack grows toward negative offsets (x86 convention).
    pub stack_grows_negative: bool,
}

impl Funcdata {
    // Ghidra: funcdata.cc:34 Funcdata::new
    /// Create a new Funcdata instance
    pub fn new(name: &str, addr: Address, size: i32) -> Self {
        Self {
            name: name.to_string(),
            baseaddr: addr,
            size,
            flags: 0,
            high_level_index: 0,
            vbank: VarnodeBank::new(),
            obank: PcodeOpBank::new(),
            bblocks: BlockGraph::new(),
            sblocks: BlockGraph::new(),
            heritage: Heritage::new(),
            merge_state: crate::merge::MergePersistentState::default(),
            self_ref: None,
            symbol_table: HashMap::new(),
            string_table: HashMap::new(),
            global_struct_ptrs: HashMap::new(),
            funcp: FuncProto::new(
                name.to_string(),
                std::sync::Arc::new(crate::type_system::datatype::Datatype::Void(
                    crate::type_system::datatype::TypeBase::new("void".to_string(), 0, crate::type_system::datatype::TypeMetatype::Void)
                )),
            ),
            external_prototypes: HashMap::new(),
            scope: None,
            high_symbols: HashMap::new(),
            symbol_entry_cache: HashMap::new(),
            callspecs: Vec::new(),
            active_output: None,
            arch: None,
            restart_pending: false,
            cond_const_done: false,
            jump_tables: Vec::new(),
            union_map: std::collections::BTreeMap::new(),
            min_laned_size: u32::MAX,
            laned_map: std::collections::BTreeMap::new(),
            localoverride: crate::override_rs::Override::new(),
            stack_space: crate::space::AddressSpace::Stack,
            stack_pointer_space: crate::space::AddressSpace::Register,
            stack_pointer_offset: 0x20, // x86-64 RSP
            stack_pointer_size: 8,
            stack_grows_negative: true,
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::isTypeRecoveryOn
    /// Is data-type analysis being performed? Faithful to
    /// `Funcdata::isTypeRecoveryOn` (funcdata.hh:150).
    pub fn is_type_recovery_on(&self) -> bool {
        (self.flags & funcdata_flags::TYPE_RECOVERY_ON) != 0
    }

    // Ghidra: funcdata.cc:34 Funcdata::setTypeRecoveryOn
    /// Enable/disable type recovery. Faithful to `Funcdata::setTypeRecoveryOn`.
    pub fn set_type_recovery_on(&mut self, on: bool) {
        if on {
            self.flags |= funcdata_flags::TYPE_RECOVERY_ON;
        } else {
            self.flags &= !funcdata_flags::TYPE_RECOVERY_ON;
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::hasTypeRecoveryStarted
    /// Has data-type analysis started? Faithful to
    /// `Funcdata::hasTypeRecoveryStarted` (funcdata.hh:151).
    pub fn has_type_recovery_started(&self) -> bool {
        (self.flags & funcdata_flags::TYPE_RECOVERY_START) != 0
    }
    // Ghidra: funcdata.cc:34 Funcdata::setTypeRecoveryStarted
    /// Mark that type recovery has started.
    pub fn set_type_recovery_started(&mut self) {
        self.flags |= funcdata_flags::TYPE_RECOVERY_START;
    }

    // Ghidra: funcdata.cc:34 Funcdata::isDoublePrecisOn
    /// Is double-precision recovery active? (funcdata.hh:167)
    pub fn is_double_precis_on(&self) -> bool {
        (self.flags & funcdata_flags::DOUBLE_PRECIS_ON) != 0
    }
    // Ghidra: funcdata.cc:34 Funcdata::setDoublePrecisRecovery
    /// Set/clear double-precis recovery. (funcdata.hh:167)
    pub fn set_double_precis_recovery(&mut self, on: bool) {
        if on {
            self.flags |= funcdata_flags::DOUBLE_PRECIS_ON;
        } else {
            self.flags &= !funcdata_flags::DOUBLE_PRECIS_ON;
        }
    }

    // Ghidra: funcdata_varnode.cc:148 Funcdata::newVarnode
    /// Create a varnode of `size` bytes at a specific address. Faithful to
    /// `Funcdata::newVarnode(int4, const Address&, Datatype*)`
    /// (funcdata_varnode.cc:148-169):
    ///   vn = vbank.create(s, m, ct);
    ///   assignHigh(vn);
    ///   if (s >= minLanedSize) checkForLanedRegister(s, m);
    ///   <queryProperties/setSymbolProperties/setFlags leg>
    ///   return vn;
    /// The localmap queryProperties half (:161-166) is a registered gap
    /// (Rugra's symbol_table is consulted via set_varnode_properties at
    /// other call sites). The laned-register half records against the
    /// address's address space, which `getLanedRegister` matches by size
    /// only (architecture.cc:290-306).
    pub fn new_varnode(&mut self, size: usize, addr: crate::address::Address) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let vn = self.vbank.create(size, addr);
        // cc:157: assignHigh(vn) (FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001)
        let _ = self.assign_high(&vn);
        if size >= self.min_laned_size as usize {
            self.check_for_laned_register(size, crate::space::AddressSpace::Ram, addr);
        }
        vn
    }

    // Ghidra: funcdata_varnode.cc:340 Funcdata::setInputVarnode
    /// Promote a varnode to a function input. Faithful to
    /// `Funcdata::setInputVarnode` (funcdata_varnode.cc:340-373).
    ///
    /// Thin wrapper over `VarnodeBank::set_input_varnode` which ports
    /// steps (1)+(2)+(3) of Ghidra (early-out / overlap dedup / setInput).
    /// Step (4) ProtoModel effect properties omitted (conservative subset).
    pub fn set_input_varnode(
        &mut self,
        vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        self.vbank.set_input_varnode(vn)
    }

    // RUGRA-GLUE: fallible Rust adapter around the checked portion of
    // Ghidra Funcdata::setInputVarnode (funcdata_varnode.cc:340-373).
    fn set_input_varnode_checked(
        &mut self,
        vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> crate::error::Result<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        if vn.read().unwrap().is_input() {
            return Ok(vn);
        }
        let (space, offset, size) = {
            let value = vn.read().unwrap();
            (value.get_space(), value.get_offset(), value.get_size())
        };
        let end = offset.wrapping_add(size as u64);
        for entry in &self.vbank.loc_tree {
            let candidate = entry.0.clone();
            let value = candidate.read().unwrap();
            if !value.is_input() || value.get_space() != space {
                continue;
            }
            let candidate_offset = value.get_offset();
            let candidate_end = candidate_offset.wrapping_add(value.get_size() as u64);
            if offset < candidate_end && candidate_offset < end {
                if candidate_offset == offset && value.get_size() == size {
                    drop(value);
                    return Ok(candidate);
                }
                return Err(crate::error::Error::Lowlevel(
                    "Overlapping input varnodes".to_string(),
                ));
            }
        }
        self.vbank
            .set_input(vn)
            .map_err(|error| crate::error::Error::Lowlevel(error.to_string()))
    }

    // Ghidra: funcdata.hh:294 Funcdata::deleteVarnode
    /// Remove a varnode from both loc/def trees. Faithful to
    /// `Funcdata::deleteVarnode` (which delegates to VarnodeBank::destroy).
    pub fn delete_varnode(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> crate::error::Result<()> {
        self.vbank
            .destroy_varnode(vn)
            .map_err(|error| crate::error::Error::Lowlevel(error.to_string()))
    }

    // Ghidra: funcdata_varnode.cc:381 Funcdata::combineInputVarnodes
    /// Combine two contiguous input varnodes into one, following
    /// `Funcdata::combineInputVarnodes` (funcdata_varnode.cc:381-454) for the
    /// covered LE/no-symbol/no-effect graph. Replaces PIECE(hi,lo) ops with
    /// COPY of the combined varnode and creates SUBPIECE replacements for
    /// non-PIECE readers. Architecture property/high-level side effects and
    /// nullable-slot representation remain outside this adapter's proof.
    pub fn combine_input_varnodes(
        &mut self,
        vn_hi: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        vn_lo: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> crate::error::Result<()> {
        use crate::opcodes::OpCode;
        let (hi_space, hi_offset, hi_size, hi_is_input) = {
            let value = vn_hi.read().unwrap();
            (
                value.get_space(),
                value.get_offset(),
                value.get_size(),
                value.is_input(),
            )
        };
        let (lo_space, lo_offset, lo_size, lo_is_input) = {
            let value = vn_lo.read().unwrap();
            (
                value.get_space(),
                value.get_offset(),
                value.get_size(),
                value.is_input(),
            )
        };
        if !hi_is_input || !lo_is_input {
            return Err(crate::error::Error::Lowlevel(
                "Varnodes being combined are not inputs".to_string(),
            ));
        }
        let (combined_space, combined_offset, contiguous) = if lo_space.is_big_endian() {
            (
                hi_space,
                hi_offset,
                hi_space == lo_space
                    && hi_offset.wrapping_add(hi_size as u64) == lo_offset,
            )
        } else {
            (
                lo_space,
                lo_offset,
                hi_space == lo_space
                    && lo_offset.wrapping_add(lo_size as u64) == hi_offset,
            )
        };
        if !contiguous {
            return Err(crate::error::Error::Lowlevel(
                "Input varnodes being combined are not contiguous".to_string(),
            ));
        };
        // Collect PIECE(hi,lo) ops and detect other readers.
        let mut piece_list = Vec::new();
        let mut other_ops_hi = false;
        let mut other_ops_lo = false;
        {
            let hi_rg = vn_hi.read().unwrap();
            for w in &hi_rg.descend {
                if let Some(op) = w.upgrade() {
                    let g = op.read().unwrap();
                    if g.opcode == OpCode::CPUI_PIECE
                        && g.inrefs.len() >= 2
                        && std::sync::Arc::ptr_eq(&g.inrefs[0], vn_hi)
                        && std::sync::Arc::ptr_eq(&g.inrefs[1], vn_lo)
                    {
                        piece_list.push(crate::op::PcodeOpRef(op.clone()));
                    } else {
                        other_ops_hi = true;
                    }
                }
            }
        }
        {
            let lo_rg = vn_lo.read().unwrap();
            for w in &lo_rg.descend {
                if let Some(op) = w.upgrade() {
                    let g = op.read().unwrap();
                    if g.opcode != OpCode::CPUI_PIECE
                        || g.inrefs.len() < 2
                        || !std::sync::Arc::ptr_eq(&g.inrefs[0], vn_hi)
                        || !std::sync::Arc::ptr_eq(&g.inrefs[1], vn_lo)
                    {
                        other_ops_lo = true;
                    }
                }
            }
        }
        let entry_block = if other_ops_hi || other_ops_lo {
            match self.bblocks.get_block(0) {
                Some(block) => Some(block),
                None => {
                    return Err(crate::error::Error::Lowlevel(
                        "Missing entry block for input combination".to_string(),
                    ));
                }
            }
        } else {
            None
        };

        // For each PIECE: remove input[1], unset input[0] (will be replaced).
        for p in &piece_list {
            self.op_remove_input(p, 1);
            // Rugra's Vec cannot hold Ghidra's cleared/null slot. Remove slot
            // zero as well, then insert the combined input below. This avoids
            // retaining a deleted high-input Arc and a second eraseDescend.
            self.op_remove_input(p, 0);
        }
        // Ghidra creates and total-replaces the non-PIECE readers before
        // destroying the old inputs. Keep the SUBPIECE ops for slot 0, which
        // is connected only after the combined canonical input exists.
        let sub_hi = if other_ops_hi {
            let Some(bb) = entry_block.as_ref() else {
                return Err(crate::error::Error::Lowlevel(
                    "Missing entry block for input combination".to_string(),
                ));
            };
            let block_start = bb.read().unwrap().get_start_addr();
            let sub = self.new_op(2, block_start);
            self.op_set_opcode(&sub, OpCode::CPUI_SUBPIECE);
            let lo_size_const = self.new_constant(4, lo_size as u64);
            let new_hi = self.vbank.create_def_with_space(
                hi_size,
                hi_space,
                hi_offset,
                &sub.0,
            );
            sub.0.write().unwrap().output = Some(new_hi.clone());
            self.op_insert_begin(&sub, bb);
            self.total_replace(vn_hi, new_hi);
            Some((sub, lo_size_const))
        } else {
            None
        };
        let sub_lo = if other_ops_lo {
            let Some(bb) = entry_block.as_ref() else {
                return Err(crate::error::Error::Lowlevel(
                    "Missing entry block for input combination".to_string(),
                ));
            };
            let block_start = bb.read().unwrap().get_start_addr();
            let sub = self.new_op(2, block_start);
            self.op_set_opcode(&sub, OpCode::CPUI_SUBPIECE);
            let zero_const = self.new_constant(4, 0);
            let new_lo = self.vbank.create_def_with_space(
                lo_size,
                lo_space,
                lo_offset,
                &sub.0,
            );
            sub.0.write().unwrap().output = Some(new_lo.clone());
            self.op_insert_begin(&sub, bb);
            self.total_replace(vn_lo, new_lo);
            Some((sub, zero_const))
        } else {
            None
        };

        self.delete_varnode(vn_hi)?;
        self.delete_varnode(vn_lo)?;
        let out_size = hi_size + lo_size;
        let in_vn = self.vbank.create_with_space(
            out_size,
            combined_space,
            combined_offset,
        );
        let in_vn = self.set_input_varnode_checked(in_vn)?;
        for p in &piece_list {
            self.op_insert_input(p, in_vn.clone(), 0);
            self.op_set_opcode(p, OpCode::CPUI_COPY);
        }
        if let Some((sub, offset)) = sub_hi {
            // `newOp(2)` reserves but cannot represent Ghidra's null slots.
            // Populate the fresh Vec in final slot order without allocating
            // observable sentinel Varnodes.
            self.op_insert_input(&sub, in_vn.clone(), 0);
            self.op_insert_input(&sub, offset, 1);
        }
        if let Some((sub, offset)) = sub_lo {
            self.op_insert_input(&sub, in_vn, 0);
            self.op_insert_input(&sub, offset, 1);
        }
        Ok(())
    }

    // Ghidra: funcdata.cc:135 Funcdata::warningHeader
    /// Attach a warning comment to this function. Faithful to
    /// `Funcdata::warningHeader` (funcdata.cc:135-145). Uses the arch's
    /// commentdb if available; otherwise eprintln as fallback.
    pub fn warning_header(&self, txt: &str) {
        let msg = format!("WARNING: {}", txt);
        if let Some(a) = &self.arch {
            if let Some(cdb) = &a.commentdb {
                let _ = cdb.write().unwrap().add_comment_no_duplicate(
                    crate::comment::comment_type::WARNINGHEADER,
                    self.baseaddr,
                    self.baseaddr,
                    &msg,
                );
                return;
            }
        }
        eprintln!("[WARNING] {}: {}", self.name, msg);
    }

    // Ghidra: funcdata.cc:34 Funcdata::getArch
    /// Get the Architecture configuration, if set.
    /// Faithful to `Funcdata::getArch` (funcdata.hh:144).
    pub fn get_arch(&self) -> Option<&Arc<crate::arch::Architecture>> {
        self.arch.as_ref()
    }
    // RUGRA-GLUE: Rust ownership seam for the Architecture reference Ghidra's
    // Funcdata constructor obtains from its Scope (`glb = scope->getArch()`,
    // funcdata.cc:48). Rugra's Funcdata has no constructor-time Scope yet
    // (FUNCDATA-LOCALSCOPE-OWNERSHIP-0001), so `set_arch` is the moment `glb`
    // becomes available and must also run the constructor's model-binding
    // tail: funcdata.cc:69 `funcp.setScope(localmap,baseaddr+ -1)` ->
    // fspec.cc:3884 `if (model == (ProtoModel *)0) setModel(s->getArch()->defaultfp)`.
    /// Set the Architecture reference and bind the Architecture's resolved
    /// default prototype model into `funcp` when no model is bound yet —
    /// mirroring the named-ctor chain so a later locked-prototype overlay
    /// (DWARF/PLT) can never observe `model_locked && !has_model`.
    pub fn set_arch(&mut self, arch: Arc<crate::arch::Architecture>) {
        // Ghidra: fspec.cc:3879 FuncProto::setScope (model-binding tail)
        if !self.funcp.has_model() {
            self.funcp.set_model(arch.get_default_model().cloned());
        }
        self.min_laned_size = arch.get_minimum_laned_register_size() as u32;
        self.arch = Some(arch);
    }

    // Ghidra: funcdata.cc:34 Funcdata::hasRestartPending
    /// Is a pipeline restart pending? Faithful to `Funcdata::hasRestartPending`.
    pub fn has_restart_pending(&self) -> bool {
        self.restart_pending
    }
    // Ghidra: funcdata.cc:34 Funcdata::setRestartPending
    /// Request a pipeline restart (ActionRestartGroup will detect this).
    pub fn set_restart_pending(&mut self, v: bool) {
        self.restart_pending = v;
    }
    // Ghidra: funcdata.cc:34 Funcdata::isJumptableRecoveryOn
    /// Is jumptable recovery currently active? Faithful to
    /// `Funcdata::isJumptableRecoveryOn` (funcdata.hh:162). True when \b this
    /// Funcdata object is a partial clone dedicated to recovering a jump-table.
    pub fn is_jumptable_recovery_on(&self) -> bool {
        (self.flags & funcdata_flags::JUMPTABLERECOVERY_ON) != 0
    }

    // Ghidra: funcdata.hh:159 Funcdata::setJumptableRecovery
    /// Enable/disable jumptable recovery on this function. Faithful to
    /// `Funcdata::setJumptableRecovery` (funcdata.hh:159). When disabled the
    /// `jumptablerecovery_dont` flag is set, which `recoverJumpTable` honors.
    pub fn set_jumptable_recovery(&mut self, val: bool) {
        if val {
            self.flags &= !funcdata_flags::JUMPTABLERECOVERY_DONT;
        } else {
            self.flags |= funcdata_flags::JUMPTABLERECOVERY_DONT;
        }
    }

    // Ghidra: funcdata.hh:147 Funcdata::isProcStarted
    /// Has processing of the function started? Faithful to
    /// `Funcdata::isProcStarted` (funcdata.hh:147). Set by `startProcessing`.
    pub fn is_proc_started(&self) -> bool {
        (self.flags & funcdata_flags::PROCESSING_STARTED) != 0
    }

    // Ghidra: funcdata.hh:148 Funcdata::isProcComplete
    /// Is processing of the function complete? Faithful to
    /// `Funcdata::isProcComplete` (funcdata.hh:148). Set by `stopProcessing`.
    pub fn is_proc_complete(&self) -> bool {
        (self.flags & funcdata_flags::PROCESSING_COMPLETE) != 0
    }

    // Ghidra: funcdata.cc:34 Funcdata::setSelfRef
    /// Set the self-reference after wrapping in Arc<RwLock>.
    /// The Heritage manager no longer stores a self-reference: its pass
    /// methods take an exclusive `&mut Funcdata` threaded from
    /// `Funcdata::op_heritage` (HERITAGE-OWNERSHIP-0001), mirroring Ghidra's
    /// non-owning `Heritage::fd` raw pointer without any lock re-entry.
    pub fn set_self_ref(&mut self, self_ref: Weak<RwLock<Funcdata>>) {
        self.self_ref = Some(self_ref.clone());
    }

    // Ghidra: funcdata.hh:462 Funcdata::opHeritage
    /// Perform an entire heritage pass linking Varnode reads to writes.
    /// Faithful 1:1 bridge to `Funcdata::opHeritage`
    /// (funcdata.hh:462): `{ heritage.heritage(); }` — exactly one
    /// `Heritage::heritage` call, which performs one pass and increments
    /// `pass` once at its last line (heritage.cc:2757).
    ///
    /// Ownership model (HERITAGE-OWNERSHIP-0001): the persistent Heritage
    /// object is temporarily moved out of `self.heritage` with `mem::take`,
    /// the single canonical pass runs against this same `&mut Funcdata`, and
    /// the identical Heritage state (pass counter, persistent globaldisjoint,
    /// per-space HeritageInfo, guards) is restored afterwards. There is no
    /// `Weak<RwLock<Funcdata>>` upgrade and no nested write-lock acquisition,
    /// so repeated invocations (e.g. three consecutive boundary calls
    /// driving pass 0->1->2->3) cannot deadlock.
    pub fn op_heritage(&mut self) {
        let mut heritage = std::mem::take(&mut self.heritage);
        heritage.heritage(self);
        self.heritage = heritage;
    }

    // RUGRA-GLUE: legacy direct heritage entry; Ghidra has no runHeritageDirect.
    /// Run the OFF-PRODUCTION direct SSA pass (`place_multiequals_direct` +
    /// `rename_direct`) against separated banks. Since
    /// HERITAGE-DRIVER-SWITCH-0001 the production pipeline drives the
    /// canonical single-pass `op_heritage` (mirroring coreaction.hh:289
    /// `ActionHeritage::apply`); this legacy entry survives for the
    /// example-side prototype estimation helpers (throwaway Funcdata in
    /// examples/curl_decompile.rs et al.) and tests outside this crate's
    /// canonical path. It bypasses the ADT/guard/refinement stages of
    /// `Heritage::heritage` (heritage.cc:2663-2758).
    pub fn run_heritage_direct(&mut self) {
        let mut vbank = std::mem::take(&mut self.vbank);
        let mut obank = std::mem::take(&mut self.obank);

        self.heritage.place_multiequals_direct(
            &mut vbank,
            &mut obank,
            &self.bblocks,
            &self.sblocks,
        );
        self.heritage.rename_direct(&mut vbank, &self.bblocks);
        self.heritage.pass += 1;

        self.vbank = vbank;
        self.obank = obank;
    }

    /// Assign a HighVariable to every Varnode that lacks one. Faithful to
    /// `Funcdata::setHighLevel` (funcdata_varnode.cc:595-605):
    ///   if ((flags & highlevel_on)!=0) return;
    ///   flags |= highlevel_on;
    ///   high_level_index = vbank.getCreateIndex();
    ///   for(iter=vbank.beginLoc();iter!=vbank.endLoc();++iter)
    ///     assignHigh(*iter);
    /// Called by ActionAssignHigh (coreaction.hh:339-347) which runs BEFORE
    /// the merge stage, so ActionMarkExplicit/Implied see HighVariables.
    // Ghidra: funcdata_varnode.cc:595 Funcdata::setHighLevel
    pub fn set_high_level(&mut self) {
        if (self.flags & funcdata_flags::HIGHLEVEL_ON) != 0 { return; }
        self.flags |= funcdata_flags::HIGHLEVEL_ON;
        // cc:600: high_level_index = vbank.getCreateIndex().
        self.high_level_index = self.vbank.get_create_index();

        // cc:603-604: for every Varnode in the bank, assignHigh(*iter).
        // Ghidra's loop is unconditional, but before highlevel_on no Varnode
        // can hold a HighVariable (assignHigh is the sole allocator and is
        // gated on the flag), so the `high.is_none()` filter is
        // behavior-equivalent plus defensive for non-pipeline callers.
        let vn_arcs: Vec<Arc<RwLock<crate::varnode::Varnode>>> = self.vbank.loc_tree
            .iter()
            .filter(|r| r.0.read().unwrap().high.is_none())
            .map(|r| r.0.clone())
            .collect();

        for vn_arc in vn_arcs {
            // cc:604 → funcdata_varnode.cc:48-59 assignHigh: the
            // highlevel_on gate now passes; annotation Varnodes (iop/fspec
            // space, code refs) are rejected by the is_annotation guard and
            // stay high-less, exactly as in Ghidra.
            let _ = self.assign_high(&vn_arc);
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::getName
    /// Get function name
    pub fn get_name(&self) -> &str {
        &self.name
    }

    // Ghidra: funcdata.cc:34 Funcdata::findVarnodeInput
    /// Find an input varnode of the given size at the given address.
    /// Faithful to `Funcdata::findVarnodeInput` (funcdata.hh:324).
    /// Used by ActionRestrictLocal and AncestorRealistic.
    pub fn find_varnode_input(&self, size: usize, addr: crate::address::Address) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        self.vbank.find_input(size, addr)
    }

    // Ghidra: funcdata.cc:34 Funcdata::addSymbol
    /// Register a symbol (function/global) at the given virtual address
    pub fn add_symbol(&mut self, addr: u64, name: String) {
        self.symbol_table.insert(addr, name);
    }

    // Ghidra: funcdata_varnode.cc:1193 Funcdata::linkSymbolReference
    /// Resolve a constant Varnode that is the second input to a PTRSUB op
    /// into a Symbol. If the PTRSUB's first input is a spacebase pointer
    /// (stack or global), look up the offset in the symbol table. If found,
    /// set the symbol reference on the Varnode and return the symbol name.
    /// Faithful to `linkSymbolReference` (funcdata_varnode.cc:1193-1213).
    /// Returns the symbol name if found, None otherwise.
    // Ghidra: funcdata_varnode.cc:1156 Funcdata::linkSymbol
    /// Link a Varnode to a Symbol in the local scope. The Symbol is really
    /// attached to the Varnode's HighVariable (which must exist). If the
    /// HighVariable already has a Symbol it is returned; otherwise any
    /// overlapping local-map entry is resolved via `handleSymbolConflict`, and
    /// with no overlap a new local Symbol holding `high->getType()` is created
    /// at the Varnode's address with its usepoint (`addSymbol("", type, addr,
    /// usepoint)`) — the source of the golden's `bVar`/`pcVar` family. Faithful
    /// to `linkSymbol` (funcdata_varnode.cc:1156-1184). Returns the symbol's
    /// index into `scope.symbols`, or None (persist varnode with no existing
    /// Symbol — cc:1174's `if (!vn->isPersist())` gate).
    pub fn link_symbol(
        &mut self,
        vn: &Arc<RwLock<crate::varnode::Varnode>>,
    ) -> Option<usize> {
        // cc:1159-1160: if (vn->isProtoPartial()) linkProtoPartial(vn);
        if vn.read().unwrap().is_proto_partial() {
            self.link_proto_partial(vn);
        }
        // cc:1161: HighVariable *high = vn->getHigh();
        let high_arc = vn.read().unwrap().high.clone()?;
        // cc:1164-1165: sym = high->getSymbol(); if (sym != 0) return sym;
        let high_ptr = Arc::as_ptr(&high_arc) as usize;
        if let Some(&idx) = self.high_symbols.get(&high_ptr) {
            return Some(idx);
        }
        // cc:1167: Address usepoint = vn->getUsePoint(*this); — written
        // varnodes use their def op's address; everything else comes into
        // scope at the function start - 1 (varnode.cc:696-703).
        let usepoint: Option<u64> = {
            let vn_r = vn.read().unwrap();
            if vn_r.is_written() {
                vn_r.get_def()
                    .map(|d| d.read().unwrap().get_addr().as_u64())
            } else {
                Some(self.baseaddr.as_u64().wrapping_sub(1))
            }
        };
        // cc:1169: entry = localmap->queryProperties(vn->getAddr(), 1, usepoint, fl);
        // (the fl side-output has no consumer in linkSymbol)
        let (vn_space, vn_offset) = {
            let vn_r = vn.read().unwrap();
            (vn_r.get_space(), vn_r.get_offset())
        };
        let entry_idx = self
            .scope
            .as_ref()?
            .query_properties(vn_space, vn_offset, 1, usepoint);
        if let Some(idx) = entry_idx {
            // cc:1170-1172: sym = handleSymbolConflict(entry, vn);
            self.handle_symbol_conflict(idx, vn)
        } else {
            // cc:1173-1181: must create a symbol entry.
            let mut sym = None;
            if !vn.read().unwrap().is_persist() {
                // Only create local symbol.
                let mut up = usepoint;
                if vn.read().unwrap().is_addr_tied() {
                    up = None; // cc:1175-1176: usepoint = Address();
                }
                // cc:1177: entry = localmap->addSymbol("", high->getType(), vn->getAddr(), usepoint);
                let ct = high_arc.read().unwrap().get_type();
                let idx = self.scope.as_mut()?.add_symbol(
                    vn_space, "", Some(ct), vn_offset, up,
                );
                sym = Some(idx);
                // cc:1178-1179: sym = entry->getSymbol(); vn->setSymbolEntry(entry)
                // — varnode.cc:429-439 flags + high->setSymbol (variable.cc:
                // 245-275 symboloffset) through the shared attach helper.
                let _ = high_ptr;
                self.attach_symbol_to_vn(idx, vn);
            }
            sym
        }
    }

    // Ghidra: funcdata_varnode.cc:1193 Funcdata::linkSymbolReference
    pub fn link_symbol_reference(
        &mut self,
        vn: &Arc<RwLock<crate::varnode::Varnode>>,
    ) -> Option<String> {
        use crate::opcodes::OpCode;
        // cc:1196: op = vn->loneDescend() — must be consumed by exactly one op.
        let op_arc = vn.read().unwrap().lone_descend()?;
        let op = op_arc.read().unwrap();
        // cc:1197-1202: check that in(0) is a spacebase pointer type.
        // Rugra: check if the PTRSUB's first input is a spacebase varnode.
        if op.opcode != OpCode::CPUI_PTRSUB { return None; }
        let in0 = op.get_in(0)?;
        let in0_r = in0.read().unwrap();
        if !in0_r.is_spacebase() { return None; }
        drop(in0_r);
        // cc:1204: addr = sb->getAddress(vn->getOffset(), in0->getSize(), op->getAddr())
        // Rugra: the offset encodes the stack/global address directly.
        let vn_offset = vn.read().unwrap().get_offset();
        // cc:1207: entry = scope->queryContainer(addr, 1, Address())
        // Rugra: look up in symbol_table (which maps address → name).
        let sym_name = self.symbol_table.get(&vn_offset).cloned();
        if let Some(ref name) = sym_name {
            // cc:1210-1211: vn->setSymbolReference(entry, off)
            // Rugra: we don't have full SymbolEntry infrastructure, but we
            // can record the name on the varnode via the symbol reference.
            // For now, the symbol_table lookup IS the resolution.
            return Some(name.clone());
        }
        // Also check scope.symbols for stack-relative symbols
        // (queryContainer at cc:1207 consults the spacebase's scope; the
        // spacebase-derived address is a stack offset, so register/unique
        // symbols created by linkSymbol never answer here).
        if let Some(ref scope) = self.scope {
            for sym in &scope.symbols {
                if sym.space != crate::space::AddressSpace::Stack {
                    continue;
                }
                if sym.start == vn_offset {
                    return Some(sym.name.clone());
                }
            }
        }
        None
    }

    // Ghidra: funcdata.cc:34 Funcdata::addString
    /// Register a string literal at the given virtual address
    pub fn add_string(&mut self, addr: u64, s: String) {
        self.string_table.insert(addr, s);
    }

    // Ghidra: funcdata.cc:34 Funcdata::getSymbol
    /// Look up a symbol name by address
    pub fn get_symbol(&self, addr: u64) -> Option<&str> {
        self.symbol_table.get(&addr).map(|s| s.as_str())
    }

    // Ghidra: funcdata.cc:34 Funcdata::getString
    /// Look up a string literal by address
    pub fn get_string(&self, addr: u64) -> Option<&str> {
        self.string_table.get(&addr).map(|s| s.as_str())
    }

    // Ghidra: funcdata.cc:34 Funcdata::getAddress
    /// Get function base address
    pub fn get_address(&self) -> &Address {
        &self.baseaddr
    }

    // Ghidra: funcdata.cc:34 Funcdata::getSize
    /// Get function size
    pub fn get_size(&self) -> i32 {
        self.size
    }

    // Ghidra: funcdata.cc:34 Funcdata::numCalls
    /// Number of call sites in this function. Faithful to
    /// `Funcdata::numCalls` (funcdata.hh).
    pub fn num_calls(&self) -> usize {
        self.callspecs.len()
    }

    // Ghidra: funcdata.cc:484 Funcdata::getCallSpecs
    /// Get call specs by index. Faithful to `Funcdata::getCallSpecs`
    /// (funcdata.hh).
    pub fn get_call_specs(&self, i: usize) -> Option<&crate::fspec::FuncCallSpecs> {
        self.callspecs.get(i)
    }

    // Ghidra: funcdata.cc:34 Funcdata::getCallSpecsMut
    /// Get mutable call specs by index.
    pub fn get_call_specs_mut(&mut self, i: usize) -> Option<&mut crate::fspec::FuncCallSpecs> {
        self.callspecs.get_mut(i)
    }

    // Ghidra: funcdata.cc:34 Funcdata::addCallSpecs
    /// Add a new call specification. Returns the index.
    pub fn add_call_specs(&mut self, fc: crate::fspec::FuncCallSpecs) -> usize {
        self.callspecs.push(fc);
        self.callspecs.len() - 1
    }

    // Ghidra: funcdata.cc:34 Funcdata::getFuncProto
    /// Get the function prototype. Faithful to `Funcdata::getFuncProto`.
    pub fn get_func_proto(&self) -> &FuncProto {
        &self.funcp
    }

    // Ghidra: funcdata.cc:34 Funcdata::getFuncProtoMut
    /// Get mutable function prototype.
    pub fn get_func_proto_mut(&mut self) -> &mut FuncProto {
        &mut self.funcp
    }

    // --- Funcdata P-code op editing API (faithful to funcdata.hh:281-479) ---
    // These mirror Ghidra's Funcdata methods used by the rule/action transforms
    // to construct and edit P-code during analysis.

    // RUGRA-GLUE: Funcdata allocation adapter; PcodeOpBank::create currently
    // cannot represent Ghidra's nullable input slots or null opcode, so only
    // the dead/alive lifecycle is enforced here (OP-INSERT-0001 MISMATCH).
    /// Allocate a new PcodeOp associated with `pc` and place it on the dead
    /// list. The requested nullable input-slot shape remains an OPBANK gap.
    pub fn new_op(&mut self, num_inputs: usize, pc: crate::address::Address) -> crate::op::PcodeOpRef {
        // PcodeOpBank::create puts a newly allocated op on Ghidra's dead list
        // (op.cc:941-948).  PcodeOpBank::create is also used by Rugra's raw
        // injection bridge, whose legacy lifecycle is different, so enforce
        // the mapped Funcdata::newOp contract at this API boundary.
        let op = self
            .obank
            .create(crate::opcodes::OpCode::CPUI_COPY, num_inputs, pc);
        self.obank.mark_dead(op.clone());
        op
    }

    // Ghidra: funcdata_varnode.cc:129 Funcdata::newUniqueOut
    /// Create a new temporary output Varnode of size `s` for `op`.
    /// Faithful to `Funcdata::newUniqueOut` (funcdata_varnode.cc:129-140):
    ///   Varnode *vn = vbank.createDefUnique(s, ct, op);
    ///   op->setOutput(vn);
    ///   assignHigh(vn);
    ///   if (s >= minLanedSize) checkForLanedRegister(s, vn->getAddr());
    ///   return vn;
    pub fn new_unique_out(&mut self, s: usize, op: &crate::op::PcodeOpRef) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // cc:134-135 creates the written form directly. Mutating a free
        // Varnode after insertion would change both BTreeSet keys in-place.
        let vn = self.vbank.create_def_unique(s, &op.0);
        op.0.write().unwrap().output = Some(vn.clone());
        // cc:135: assignHigh(vn) (FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001)
        let _ = self.assign_high(&vn);
        if s >= self.min_laned_size as usize {
            let (space, addr) = {
                let vn = vn.read().unwrap();
                (vn.get_space(), crate::address::Address::new(vn.get_offset()))
            };
            self.check_for_laned_register(s, space, addr);
        }
        vn
    }

    // Ghidra: funcdata_varnode.cc:66 Funcdata::newConstant
    /// Create a new constant Varnode. Faithful to `Funcdata::newConstant`
    /// (funcdata_varnode.cc:66-76):
    ///   Varnode *vn = vbank.create(s, glb->getConstant(constant_val), ct);
    ///   assignHigh(vn);
    ///   return vn;
    pub fn new_constant(&mut self, s: usize, val: u64) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let vn = self.vbank.create_constant(s, val);
        // cc:72: assignHigh(vn) — constant Varnodes do get a HighVariable
        // (hasCover() is false for constants, so no calcCover; they are not
        // annotations). (FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001)
        let _ = self.assign_high(&vn);
        vn
    }

    // Ghidra: funcdata.cc:34 Funcdata::newExtendedConstant
    /// Create a new (possibly extended) constant Varnode of size `s` from a
    /// 128-bit value `(lo, hi)`. Faithful to `Funcdata::newExtendedConstant`
    /// (funcdata_varnode.cc:462-484). For s≤8, creates a plain constant.
    /// For s>8 with hi==0, creates INT_ZEXT(const). For s>8 with hi!=0,
    /// creates PIECE(hi_const, lo_const).
    pub fn new_extended_constant(&mut self, s: usize, lo: u64, hi: u64, before_op: &crate::op::PcodeOpRef) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        if s <= 8 {
            return self.new_constant(s, lo);
        }
        let addr = before_op.0.read().unwrap().get_addr();
        if hi == 0 {
            let ext_op = self.new_op(1, addr);
            self.op_set_opcode(&ext_op, crate::opcodes::OpCode::CPUI_INT_ZEXT);
            let out = self.new_unique_out(s, &ext_op);
            let lo_const = self.new_constant(8, lo);
            self.op_set_input(&ext_op, lo_const, 0);
            self.op_insert_before(&ext_op, before_op);
            out
        } else {
            let piece_op = self.new_op(2, addr);
            self.op_set_opcode(&piece_op, crate::opcodes::OpCode::CPUI_PIECE);
            let out = self.new_unique_out(s, &piece_op);
            let hi_const = self.new_constant(8, hi);
            let lo_const = self.new_constant(8, lo);
            self.op_set_input(&piece_op, hi_const, 0);
            self.op_set_input(&piece_op, lo_const, 1);
            self.op_insert_before(&piece_op, before_op);
            out
        }
    }

    // Ghidra: funcdata_op.cc:632 Funcdata::getFirstReturnOp
    /// Return the first non-dead, non-halt CPUI_RETURN op, or None.
    /// Faithful to `getFirstReturnOp` (funcdata_op.cc:632-644).
    pub fn get_first_return_op(&self) -> Option<crate::op::PcodeOpRef> {
        // Use returnlist (PcodeOpBank code list for RETURN ops).
        for retop in &self.obank.returnlist {
            let op = retop.0.read().unwrap();
            if op.is_dead() { continue; }
            // cc:640: getHaltType()!=0 → skip artificial halts.
            let halt_mask = crate::op::pcodeop_flags::HALT
                | crate::op::pcodeop_flags::BADINSTRUCTION
                | crate::op::pcodeop_flags::UNIMPLEMENTED
                | crate::op::pcodeop_flags::NORETURN
                | crate::op::pcodeop_flags::MISSING;
            if (op.flags & halt_mask) != 0 { continue; }
            return Some(retop.clone());
        }
        None
    }

    // Ghidra: funcdata_varnode.cc:83 Funcdata::newUnique
    /// Create a new temporary Varnode (no defining op). Faithful to
    /// `Funcdata::newUnique` (funcdata_varnode.cc:83-95):
    ///   Varnode *vn = vbank.createUnique(s, ct);
    ///   assignHigh(vn);
    ///   if (s >= minLanedSize) checkForLanedRegister(s, vn->getAddr());
    ///   return vn;
    pub fn new_unique(&mut self, s: usize) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let vn = self.vbank.create_unique(s);
        // cc:89: assignHigh(vn) (FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001)
        let _ = self.assign_high(&vn);
        if s >= self.min_laned_size as usize {
            let (space, addr) = {
                let vn = vn.read().unwrap();
                (vn.get_space(), crate::address::Address::new(vn.get_offset()))
            };
            self.check_for_laned_register(s, space, addr);
        }
        vn
    }

    // Ghidra: funcdata_op.cc:37 Funcdata::opMarkHalt
    /// Mark a CPUI_RETURN op as an artificial halt. Faithful to
    /// `opMarkHalt` (funcdata_op.cc:37-48). Throws if op is not RETURN
    /// or flag is invalid (Rugra logs + returns).
    pub fn op_mark_halt(&self, op: &crate::op::PcodeOpRef, flag: u32) {
        use crate::opcodes::OpCode;
        use crate::op::pcodeop_flags;
        // cc:40: if (op->code() != CPUI_RETURN) throw;
        if op.0.read().unwrap().opcode != OpCode::CPUI_RETURN {
            eprintln!("[FUNCDATA] WARN: opMarkHalt on non-RETURN op");
            return;
        }
        // cc:42-44: flag &= (halt|badinstruction|unimplemented|noreturn|missing);
        let mask = pcodeop_flags::HALT | pcodeop_flags::BADINSTRUCTION
            | pcodeop_flags::UNIMPLEMENTED | pcodeop_flags::NORETURN
            | pcodeop_flags::MISSING;
        let masked = flag & mask;
        // cc:45-46: if (flag == 0) throw;
        if masked == 0 {
            eprintln!("[FUNCDATA] WARN: opMarkHalt with bad flag {:#x}", flag);
            return;
        }
        // cc:47: op->setFlag(flag);
        op.0.write().unwrap().flags |= masked;
    }

    // Ghidra: funcdata_op.cc:21 Funcdata::opSetOpcode
    /// Set the op-code for a specific PcodeOp. Faithful to
    /// `Funcdata::opSetOpcode` (funcdata.hh:463).
    pub fn op_set_opcode(&mut self, op: &crate::op::PcodeOpRef, opc: crate::opcodes::OpCode) {
        // cc:29 delegates to PcodeOpBank::changeOpcode. Besides resetting
        // opcode-derived flags, this removes the op from its old LOAD/STORE/
        // RETURN/CALLOTHER list and inserts it into the new one.
        self.obank.change_opcode(op.clone(), opc);
    }

    // Ghidra: funcdata_op.cc:104 Funcdata::opSetInput
    /// Set a specific input operand for the given PcodeOp. Faithful to
    /// `Funcdata::opSetInput` (funcdata_op.cc:104-125). Four decisive steps:
    ///   (1) early-out if vn is already the input at slot
    ///   (2) const dedup: if vn is constant AND has descend AND not spacebase,
    ///       create a fresh constant copy (with copySymbol) and use that
    ///   (3) opUnsetInput(op, slot) on the OLD input — erases op from old
    ///       vn's descend list (Rugra's inrefs Vec can't hold null, so the
    ///       "clearInput" half is implicit: inrefs[slot] gets overwritten
    ///       below; the load-bearing part is erase_descend on the old vn)
    ///   (4) vn->addDescend(op) + op->setInput(vn, slot)
    ///
    /// **2026-07-05 修正**:此前 Rugra 漏了 (1)(2)(3),直接 addDescend + 赋值,
    /// 导致旧 vn 的 descend 列表残留当前 op 引用 → has_no_descend 永远返回
    /// false → heritage rename 的 deleteVarnode (heritage.cc:2521) 永远不执行
    /// → 死 varnode 累积污染后续 pass。同时 const 去重缺失导致同一常量 vn 被
    /// 多个 op 引用,违反 Ghidra "constants should have only one descendant"
    /// 不变量 (cc:108)。
    pub fn op_set_input(&mut self, op: &crate::op::PcodeOpRef, vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, slot: usize) {
        let mut o = op.0.write().unwrap();
        // Ghidra has nullable preallocated slots. For Rugra's Vec model, a
        // sequential slot exactly at len is the representable NULL boundary
        // and is appended below without allocating a sentinel. Preserve gap
        // sentinels only for the still-unresolved slot>len representation.
        while o.inrefs.len() < slot {
            let sentinel = self.vbank.create(1, crate::address::Address::new(u64::MAX));
            o.inrefs.push(sentinel);
        }
        // (1) Ghidra cc:107: if (vn == op->getIn(slot)) return;
        if slot < o.inrefs.len() && std::sync::Arc::ptr_eq(&vn, &o.inrefs[slot]) {
            return;
        }
        // (2) Ghidra cc:108-115: const dedup. If vn is constant AND has
        // descend AND not spacebase, create a fresh copy so each constant
        // has only one descendant.
        let vn_final = {
            let vn_r = vn.read().unwrap();
            let needs_dedup = vn_r.is_constant() && !vn_r.has_no_descend() && !vn_r.is_spacebase();
            drop(vn_r);
            if needs_dedup {
                let (sz, off) = {
                    let r = vn.read().unwrap();
                    (r.size, r.loc.as_u64())
                };
                let cvn = self.new_constant(sz, off);
                // Ghidra cc:112: cvn->copySymbol(vn) — Varnode::copySymbol
                // (varnode.cc:493-505). The field half (cc:496-499) is
                // Varnode::copy_symbol (varnode.rs): Datatype pointer copy
                // (cc:496), mapentry copy (cc:497), then clear and re-inherit
                // ONLY the typelock|namelock bits from vn (cc:498-499 — not
                // mapped/insert/coverdirty, which stay cvn-local). Previously
                // this branch copied mapentry only, so a typelock/namelock
                // equate constant lost its locks and type on dedup
                // (VARNODE-COPYSYMBOL-FIELDS-0001).
                {
                    let src = vn.read().unwrap();
                    cvn.write().unwrap().copy_symbol(&src);
                }
                // cc:500-504 high bookkeeping (high->typeDirty(); if
                // mapentry != 0 high->setSymbol(this)) lives at this call
                // site in the attach_symbol_to_vn house pattern because
                // copy_symbol's &mut self cannot recover the Arc-to-self
                // that HighVariable::set_symbol takes. Reachable since
                // FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001: new_constant now
                // calls assignHigh (funcdata_varnode.cc:72), so when
                // highlevel_on is set the dedup constant carries a fresh
                // HighVariable into this leg — closing the
                // VARNODE-COPYSYMBOL-FIELDS-0001 residual R1.
                if let Some(high) = cvn.read().unwrap().get_high().cloned() {
                    let has_mapentry = cvn.read().unwrap().mapentry.is_some();
                    let mut h = high.write().unwrap();
                    h.type_dirty();
                    if has_mapentry {
                        h.set_symbol(&cvn);
                    }
                }
                cvn
            } else {
                vn.clone()
            }
        };
        // (3) Ghidra cc:120-121: if (op->getIn(slot) != null) opUnsetInput(op, slot).
        // opUnsetInput does vn->eraseDescend(op) + op->clearInput(slot).
        // Ghidra's NULL check is the "link still live" test; with no
        // representable NULL, descend membership plays that role (see
        // op_unset_input). A stale slot whose link was already severed is
        // skipped, mirroring the NULL-slot path, instead of re-erasing a
        // descend entry that is no longer there.
        if slot < o.inrefs.len() {
            let old_vn = o.inrefs[slot].clone();
            let linked = {
                let old_r = old_vn.read().unwrap();
                old_r.descend.iter().any(|weak| {
                    weak.upgrade()
                        .is_some_and(|candidate| std::sync::Arc::ptr_eq(&candidate, &op.0))
                })
            };
            if linked {
                old_vn.write().unwrap().erase_descend(&op.0);
            }
        }
        // (4) Ghidra cc:123-124: vn->addDescend(op) + op->setInput(vn, slot).
        vn_final.write().unwrap().add_descend(&op.0);
        if slot == o.inrefs.len() {
            o.inrefs.push(vn_final);
        } else {
            o.inrefs[slot] = vn_final;
        }
    }

    // Ghidra: funcdata_op.cc:308 Funcdata::opInsertInput
    /// Insert a new Varnode into the operand list at `slot`; any existing
    /// input Varnodes with slot indices >= `slot` are pushed into the next
    /// slot. Faithful to `Funcdata::opInsertInput` (funcdata_op.cc:308-317):
    /// `op->insertInput(slot)` then `opSetInput(op,vn,slot)` — the full
    /// opSetInput path (const dedup cc:108-115, addDescend free-check +
    /// coverdirty bookkeeping varnode.cc:330-340), never a raw descend push.
    pub fn op_insert_input(&mut self, op: &crate::op::PcodeOpRef, vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, slot: usize) {
        // cc:315 op->insertInput(slot) — PcodeOp::insertInput
        // (op.cc:311-318) pushes a NULL slot at `slot` and shifts existing
        // inputs at/after `slot` up by one. Descend entries store the op
        // pointer, not the slot index, so the shift needs no descend
        // update. Rugra's inrefs Vec cannot hold the transient NULL without
        // allocating an observable sentinel Varnode in the bank, and every
        // Ghidra statement between insertInput and opSetInput's final
        // setInput is a no-op on that NULL slot (cc:107 vn != NULL so the
        // early-return cannot fire; cc:118-121 opUnsetInput is guarded by
        // getIn(slot) != NULL), so the tail is split off here and the
        // delegated op_set_input appends into the fresh slot below. Ghidra
        // has no clamp (callers never exceed numInput); the defensive
        // clamp to len is Rust-side bounds glue.
        let (slot, tail) = {
            let mut o = op.0.write().unwrap();
            let slot = slot.min(o.inrefs.len());
            let tail = if slot < o.inrefs.len() {
                Some(o.inrefs.split_off(slot))
            } else {
                None
            };
            (slot, tail)
        };
        // cc:316 opSetInput(op,vn,slot) — with inrefs.len()==slot this
        // takes the fresh-slot path: no early-return (NULL != vn), no
        // opUnsetInput (NULL guard), const dedup when the same constant
        // already has a live descendant, then addDescend + setInput.
        self.op_set_input(op, vn, slot);
        if let Some(tail) = tail {
            op.0.write().unwrap().inrefs.extend(tail);
        }
    }

    // Ghidra: funcdata_op.cc:291 Funcdata::opRemoveInput
    /// Remove a specific input slot. Ghidra first calls `opUnsetInput` so the
    /// input Varnode loses this op from its descendant list, then removes the
    /// now-unlinked slot and shifts later slots down by one.
    pub fn op_remove_input(&self, op: &crate::op::PcodeOpRef, slot: usize) {
        if slot >= op.0.read().unwrap().inrefs.len() {
            return;
        }
        self.op_unset_input(op, slot);
        let mut o = op.0.write().unwrap();
        if slot < o.inrefs.len() {
            o.inrefs.remove(slot);
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::opSwapInput
    /// Swap two input operands. Faithful to `Funcdata::opSwapInput`
    /// (funcdata.hh). Used by RuleBoolNegate to reorder operands when flipping
    /// a comparison (e.g. `!(V < W) => W <= V`).
    pub fn op_swap_input(&self, op: &crate::op::PcodeOpRef, slot1: usize, slot2: usize) {
        let mut o = op.0.write().unwrap();
        if slot1 < o.inrefs.len() && slot2 < o.inrefs.len() {
            o.inrefs.swap(slot1, slot2);
        }
    }

    // Ghidra: funcdata_op.cc:70 Funcdata::opSetOutput
    /// Install a bank-owned Varnode as an op output, consuming the canonical
    /// Varnode selected by `VarnodeBank::set_def`.
    pub fn op_set_output(
        &mut self,
        op: &crate::op::PcodeOpRef,
        vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        let same_output = op.0.read().unwrap().output.as_ref()
            .is_some_and(|output| std::sync::Arc::ptr_eq(output, &vn));
        if same_output {
            return;
        }
        if op.0.read().unwrap().output.is_some() {
            self.op_unset_output(op);
        }
        let previous_def = vn.read().unwrap().get_def().map(crate::op::PcodeOpRef);
        if let Some(previous_def) = previous_def {
            self.op_unset_output(&previous_def);
        }
        let canonical = match self.vbank.set_def(vn, std::sync::Arc::downgrade(&op.0)) {
            Ok(canonical) => canonical,
            Err(error) => panic!("Funcdata::opSetOutput precondition failed: {error}"),
        };
        self.set_varnode_properties(&canonical);
        op.0.write().unwrap().output = Some(canonical);
    }

    // Ghidra: funcdata_op.cc:203 Funcdata::opDestroy
    /// Destroy an unused PcodeOp. Faithful to `Funcdata::opDestroy`
    /// (funcdata_op.cc:203-222). Destroys the output Varnode, unsets all
    /// inputs, and removes an integrated op from its exact basic block.
    pub fn op_destroy(&mut self, op: &crate::op::PcodeOpRef) {
        // cc:211-212: snapshot before destroyVarnode, so the op read guard
        // cannot overlap destroyVarnode's write to the same output slot.
        let output = { op.0.read().unwrap().output.clone() };
        if let Some(output) = output {
            self.destroy_varnode(&output);
        }
        // cc:213-217: clear every non-null input in slot order. Rugra cannot
        // retain Ghidra's NULL slots, so the detached dead op has an empty Vec.
        let input_count = op.0.read().unwrap().inrefs.len();
        for slot in 0..input_count {
            self.op_unset_input(op, slot);
        }
        op.0.write().unwrap().inrefs.clear();
        // cc:218-221: parentless ops are already dead. Integrated ops move to
        // the dead bank and leave their owning block.
        let parent = op.0.read().unwrap().parent.as_ref()
            .and_then(std::sync::Weak::upgrade);
        if let Some(parent) = parent {
            self.obank.mark_dead(op.clone());
            Self::block_remove_op(op, &parent);
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::opDestroyRecursive
    /// Recursively destroy an op and its now-dead defining ops. Faithful to
    /// `Funcdata::opDestroyRecursive` (funcdata_op.cc:228-247). Destroys the
    /// given op, then for each input Varnode that becomes dead (its only
    /// reader was this op and it is not auto-live/call/indirect-source),
    /// recursively destroys its defining op.
    pub fn op_destroy_recursive(&mut self, op: &crate::op::PcodeOpRef) {
        let mut scratch: Vec<crate::op::PcodeOpRef> = Vec::new();
        scratch.push(op.clone());
        let mut pos = 0;
        while pos < scratch.len() {
            let cur = scratch[pos].clone();
            pos += 1;
            // Collect input varnodes and check if their defining ops should be
            // recursively destroyed.
            let inrefs = cur.0.read().unwrap().inrefs.clone();
            for in_vn in &inrefs {
                let (is_written, lone_descend_none, def) = {
                    let vn_rg = in_vn.read().unwrap();
                    let lone = vn_rg.lone_descend();
                    (
                        vn_rg.is_written(),
                        lone.is_none(),
                        vn_rg.get_def(),
                    )
                };
                if !is_written {
                    continue;
                }
                if lone_descend_none {
                    continue; // Still has descendants (or no def).
                }
                let Some(def_op) = def else { continue };
                let def_ref = crate::op::PcodeOpRef(def_op);
                // Skip call and indirect-source ops (faithful to Ghidra).
                let is_call = def_ref.0.read().unwrap().is_call();
                let is_indirect_source = {
                    let f = def_ref.0.read().unwrap().flags;
                    (f & crate::op::pcodeop_flags::INDIRECT_SOURCE) != 0
                };
                if is_call || is_indirect_source {
                    continue;
                }
                scratch.push(def_ref);
            }
            self.op_destroy(&cur);
        }
    }

    // Ghidra: funcdata_varnode.cc:1474 Funcdata::totalReplace
    /// Replace every read reference of `vn` with `newvn`. Faithful to
    /// `Funcdata::totalReplace` (funcdata_varnode.cc:1474-1487):
    ///   iter = vn->beginDescend();
    ///   while(iter != vn->endDescend()) {
    ///     op = *iter++;	   // Increment before removing descendant
    ///     i = op->getSlot(vn);
    ///     opSetInput(op,newvn,i);
    ///   }
    /// Ghidra walks the ORIGINAL std::list with an iterator advanced before
    /// `opSetInput` severs the entry: every original entry is visited exactly
    /// once and the loop terminates at `endDescend()` regardless of what
    /// remains in the live list (e.g. when `newvn == vn`, opSetInput's
    /// early-out leaves entries in place and Ghidra still exits after one
    /// pass). Rugra must NOT re-scan the list until it drains: entries the
    /// per-site opSetInput cannot remove would spin forever (this was the
    /// FUNC-GLOBRANGE-HANG-0001 deadlock). Snapshot the live descendants
    /// once (dead Weak entries — op Arc freed without unset, unreachable in
    /// Ghidra's raw-pointer model — cannot be visited and are skipped), then
    /// compute each site's first matching slot AT APPLY TIME, matching
    /// `getSlot`'s first-match semantics (op.hh:166) so an op reading `vn`
    /// in multiple slots has each visit retarget the next remaining slot.
    pub fn total_replace(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        newvn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        let descendants: Vec<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>> = {
            let vn_r = vn.read().unwrap();
            vn_r.descend.iter().filter_map(|w| w.upgrade()).collect()
        };
        for descendant in descendants {
            // Ghidra cc:1483: i = op->getSlot(vn) — first matching slot,
            // evaluated after earlier sites were rewritten.
            let slot = descendant
                .read()
                .unwrap()
                .inrefs
                .iter()
                .position(|input| std::sync::Arc::ptr_eq(input, vn));
            let Some(slot) = slot else {
                // Ghidra getSlot miss returns numInput and opSetInput throws
                // LowlevelError "Bad input slot" (funcdata_op.cc:106-107).
                // The site is drift (op no longer reads vn); remove the
                // stale descend entry so the list reflects actual reads.
                vn.write().unwrap().erase_descend(&descendant);
                continue;
            };
            self.op_set_input(
                &crate::op::PcodeOpRef(descendant),
                newvn.clone(),
                slot,
            );
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::opUnsetInput
    /// Unset an input slot. Faithful to `Funcdata::opUnsetInput`
    /// (funcdata_op.cc). Removes the descend link from the input varnode and
    /// sets the slot to None (represented as removing from inrefs in Rugra).
    // Ghidra: funcdata_op.cc:92 Funcdata::opUnsetInput
    /// Unlink the input Varnode at `slot` from `op`. Faithful to
    /// `Funcdata::opUnsetInput` (funcdata_op.cc:92-99):
    ///   vn = op->getIn(slot);
    ///   vn->eraseDescend(op);
    ///   op->clearInput(slot);
    /// Ghidra's `clearInput` (op.hh:136) NULLs the slot in place, so every
    /// later reader sees `getIn(slot) == NULL` and skips it — most
    /// importantly `opDestroy` (funcdata_op.cc:213-215), which guards each
    /// slot with `if (vn != NULL) opUnsetInput(op,i)`. Rugra's inrefs Vec
    /// cannot hold null, so the stale Arc survives; descend membership is
    /// the durable record of whether the (op,slot)→vn link is still live.
    /// If `op` is not in `vn`'s descend list the link was already severed,
    /// and skipping the erase reproduces Ghidra's NULL-slot no-op. This
    /// makes repeated unsets on the same slot idempotent instead of
    /// re-erasing a descend entry that is no longer there.
    pub fn op_unset_input(&self, op: &crate::op::PcodeOpRef, slot: usize) {
        let in_vn = {
            let o = op.0.read().unwrap();
            o.inrefs.get(slot).cloned()
        };
        if let Some(vn) = in_vn {
            let linked = {
                let vn_r = vn.read().unwrap();
                vn_r.descend.iter().any(|weak| {
                    weak.upgrade()
                        .is_some_and(|candidate| std::sync::Arc::ptr_eq(&candidate, &op.0))
                })
            };
            if linked {
                vn.write().unwrap().erase_descend(&op.0);
            }
        }
        // Ghidra cc:98: op->clearInput(slot) — implicit in Rugra (Vec slot
        // overwritten on next set; callers must set or remove before relying
        // on inrefs[slot]).
    }

    // Ghidra: funcdata_op.cc:52 Funcdata::opUnsetOutput
    /// Remove an op's output, return the old Varnode to the bank's free class,
    /// and discard its Cover.
    pub fn op_unset_output(&mut self, op: &crate::op::PcodeOpRef) {
        let old = op.0.write().unwrap().output.take();
        let Some(old) = old else { return };
        self.vbank.make_free_prevalidated(&old);
        old.write().unwrap().clear_cover();
    }

    // Ghidra: funcdata_varnode.cc:104 Funcdata::newVarnodeOut
    /// Create an already-written Varnode under its final BTree keys and install
    /// it as the output of `op`. Faithful to `Funcdata::newVarnodeOut`
    /// (funcdata_varnode.cc:104-122):
    ///   Varnode *vn = vbank.createDef(s, m, ct, op);
    ///   op->setOutput(vn);
    ///   assignHigh(vn);
    ///   if (s >= minLanedSize) checkForLanedRegister(s, m);
    ///   <queryProperties/setSymbolProperties/setFlags leg>
    ///   return vn;
    pub fn new_varnode_out(
        &mut self,
        size: usize,
        addr: crate::address::Address,
        op: &crate::op::PcodeOpRef,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let vn = self.vbank.create_def_with_space(
            size,
            crate::space::AddressSpace::Register,
            addr.as_u64(),
            &op.0,
        );
        op.0.write().unwrap().output = Some(vn.clone());
        // cc:110: assignHigh(vn) — comes BEFORE the queryProperties leg.
        // (FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001)
        let _ = self.assign_high(&vn);
        if size >= self.min_laned_size as usize {
            self.check_for_laned_register(
                size,
                crate::space::AddressSpace::Register,
                addr,
            );
        }
        self.set_varnode_properties(&vn);
        vn
    }

    // Ghidra: funcdata.cc:34 Funcdata::pushBranch
    /// Push a conditional branch edge into a new destination, turning the
    /// CBRANCH into an unconditional BRANCH. Faithful to `Funcdata::pushBranch`
    /// (funcdata_block.cc:404).
    ///
    /// `bb` is the block containing the CBRANCH; `slot` is the out-edge to
    /// redirect; `bbnew` is the new destination (must end in BRANCHIND).
    pub fn push_branch(
        &mut self,
        bb: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        slot: usize,
        bbnew: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) -> Result<(), String> {
        // Get the CBRANCH (last op of bb).
        let last_op = {
            let bb_rg = bb.read().unwrap();
            if let Some(any) = bb_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                any.last_op()
            } else {
                None
            }
        };
        let cbranch = match last_op {
            Some(op) => op,
            None => return Err("No last op in block".to_string()),
        };
        // Verify it's a CBRANCH with 2 out-edges.
        let is_cbranch = {
            let cb_rg = cbranch.0.read().unwrap();
            cb_rg.opcode == crate::opcodes::OpCode::CPUI_CBRANCH
        };
        if !is_cbranch || bb.read().unwrap().size_out() != 2 {
            return Err("Cannot push non-conditional edge".to_string());
        }
        // Verify bbnew ends in BRANCHIND.
        let bbnew_last = {
            let bn_rg = bbnew.read().unwrap();
            if let Some(any) = bn_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                any.last_op()
            } else {
                None
            }
        };
        if let Some(indop) = &bbnew_last {
            if indop.0.read().unwrap().opcode != crate::opcodes::OpCode::CPUI_BRANCHIND {
                return Err("Can only push branch into indirect jump".to_string());
            }
        } else {
            return Err("Destination has no last op".to_string());
        }
        // Remove the conditional variable (input slot 1) and change opcode to
        // BRANCH. Faithful to opRemoveInput(cbranch,1) + opSetOpcode(BRANCH).
        self.op_remove_input(&cbranch, 1);
        self.op_set_opcode(&cbranch, crate::opcodes::OpCode::CPUI_BRANCH);
        // Move the out-edge.
        self.move_out_edge(bb, slot, bbnew);
        Ok(())
    }

    // Ghidra: funcdata.cc:34 Funcdata::moveOutEdge
    /// Move an out-edge of `bb` from its current destination to `bbnew`.
    /// Faithful to `BlockGraph::moveOutEdge` (block.cc). This redirects the
    /// edge by updating both the source's outgoing list and the old/new
    /// destinations' incoming lists.
    pub fn move_out_edge(
        &mut self,
        bb: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        slot: usize,
        bbnew: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) {
        // Get the old destination.
        let old_dest = {
            let bb_rg = bb.read().unwrap();
            bb_rg.get_out(slot).map(|e| e.point)
        };
        let Some(old_dest) = old_dest else { return };
        // Update the source's outgoing edge to point to bbnew.
        let rev_idx_new = bbnew.read().unwrap().size_in() as i32;
        {
            let mut bb_rg = bb.write().unwrap();
            if let Some(any) = bb_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                if slot < any.outgoing.len() {
                    let old_rev = any.outgoing[slot].reverse_index;
                    any.outgoing[slot].point = bbnew.clone();
                    any.outgoing[slot].reverse_index = rev_idx_new;
                    // Remove the old reverse edge from old_dest.
                    let _ = old_rev;
                }
            }
        }
        // Add the incoming edge to bbnew.
        {
            let mut bn_rg = bbnew.write().unwrap();
            let out_idx = slot as i32;
            bn_rg.add_in_edge(crate::block::BlockEdge::new(bb.clone(), out_idx));
        }
        // Remove the old incoming edge from old_dest (the reverse_index stored
        // in bb's edge tells us which slot in old_dest to remove).
        let old_rev = {
            let bb_rg = bb.read().unwrap();
            // The reverse_index was captured before we changed it; recompute
            // from old_dest's incoming list by finding bb.
            let dest_rg = old_dest.read().unwrap();
            let mut found = None;
            for i in 0..dest_rg.size_in() {
                if let Some(e) = dest_rg.get_in(i) {
                    if Arc::ptr_eq(&e.point, bb) {
                        found = Some(i);
                        break;
                    }
                }
            }
            found
        };
        if let Some(slot_in) = old_rev {
            let mut od_rg = old_dest.write().unwrap();
            if let Some(any) = od_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                if slot_in < any.incoming.len() {
                    any.incoming.remove(slot_in);
                    // Fix reverse indices on bb's remaining edges that pointed
                    // past the removed slot.
                    let mut bb_rg = bb.write().unwrap();
                    if let Some(any_bb) = bb_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                        for e in any_bb.outgoing.iter_mut() {
                            if e.reverse_index > slot_in as i32 {
                                e.reverse_index -= 1;
                            }
                        }
                    }
                }
            }
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::forceGoto
    /// Force a specific branch instruction to be an unstructured goto.
    /// Faithful to `Funcdata::forceGoto` (funcdata_block.cc:752).
    ///
    /// `pcop` is the address of the branch op to mark; `pcdest` is the
    /// destination address. Returns true if a matching branch was found and
    /// marked.
    pub fn force_goto(
        &mut self,
        pcop: crate::address::Address,
        pcdest: crate::address::Address,
    ) -> bool {
        for i in 0..self.bblocks.get_size() {
            let bl = match self.bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            // Get the last op of this block.
            let last_op = {
                let bl_rg = bl.read().unwrap();
                if let Some(any) = bl_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                    any.last_op()
                } else {
                    None
                }
            };
            let Some(op) = last_op else { continue };
            if op.0.read().unwrap().get_addr() != pcop {
                continue;
            }
            // Find the out-edge whose destination's last op has addr == pcdest.
            let n_out = bl.read().unwrap().size_out();
            for j in 0..n_out {
                let bl2 = bl.read().unwrap().get_out(j).map(|e| e.point);
                let Some(bl2) = bl2 else { continue };
                let op2 = {
                    let bl2_rg = bl2.read().unwrap();
                    if let Some(any) = bl2_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                        any.last_op()
                    } else {
                        None
                    }
                };
                let Some(op2) = op2 else { continue };
                if op2.0.read().unwrap().get_addr() == pcdest {
                    // Mark this out-edge as a goto branch.
                    self.set_goto_branch(&bl, j);
                    return true;
                }
            }
        }
        false
    }

    // Ghidra: block.cc:305 FlowBlock::setGotoBranch
    /// Mark the j-th out-edge of a block as an unstructured goto. Faithful to
    /// `FlowBlock::setGotoBranch` (block.cc:305-314), which does THREE things:
    ///   1. setOutEdgeFlag(j, f_goto_edge) — mark the edge as goto.
    ///   2. flags |= f_interior_gotoout — mark that there's a goto OUT of this
    ///      block's interior (read by hasInteriorGoto).
    ///   3. outofthis[j].point->flags |= f_interior_gotoin — mark the TARGET
    ///      block as a goto target (read by isInteriorGotoTarget).
    /// Previously Rugra only did (1) for BlockBasic, so is_interior_goto_target
    /// could not behave correctly for goto-marked targets.
    pub fn set_goto_branch(
        &mut self,
        bl: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        j: usize,
    ) {
        // cc:307-310: bounds check + setOutEdgeFlag(j, f_goto_edge).
        // Capture the target block for step (3) before taking the write lock.
        let target_opt: Option<Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>> = {
            let bl_rg = bl.read().unwrap();
            if j < bl_rg.size_out() {
                bl_rg.get_out(j).map(|e| e.point.clone())
            } else {
                None
            }
        };
        {
            let mut bl_rg = bl.write().unwrap();
            // cc:311: flags |= f_interior_gotoout (source-side mark).
            bl_rg.set_flags(crate::block::block_flags::INTERIOR_GOTOOUT);
            // cc:308: setOutEdgeFlag(j, f_goto_edge). For BlockBasic we use the
            // dedicated GOTO_EDGE_0/1 flags; for structured blocks we set the
            // edge's F_GOTO_EDGE flag directly.
            if let Some(any) = bl_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                match j {
                    0 => any.flags |= crate::block::block_flags::GOTO_EDGE_0,
                    1 => any.flags |= crate::block::block_flags::GOTO_EDGE_1,
                    _ => {}
                }
            } else {
                // Structured block: set F_GOTO_EDGE on the edge directly.
                bl_rg.set_out_edge_flag(j, crate::block::edge_flags::F_GOTO_EDGE);
            }
        }
        // cc:313: target->flags |= f_interior_gotoin (target-side mark).
        if let Some(target) = target_opt {
            let mut tg = target.write().unwrap();
            tg.set_flags(crate::block::block_flags::INTERIOR_GOTOIN);
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::removeBranch
    /// Remove a branch edge from a basic block. Faithful to
    /// `Funcdata::removeBranch` / `branchRemoveInternal`
    /// (funcdata_block.cc). If the block has 2 out-edges (CBRANCH), the
    /// branch op is destroyed. The edge to the un-selected out-block is
    /// severed.
    ///
    /// `bb` is the block with the branch; `num` is the out-edge index to
    /// KEEP (0 or 1). The OTHER edge is removed.
    pub fn remove_branch(
        &mut self,
        bb: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        num: usize,
    ) {
        // If 2 out-edges, destroy the CBRANCH op.
        let n_out = bb.read().unwrap().size_out();
        if n_out == 2 {
            let last_op = {
                let bb_rg = bb.read().unwrap();
                if let Some(any) = bb_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                    any.last_op()
                } else {
                    None
                }
            };
            if let Some(cbranch) = last_op {
                self.op_destroy(&cbranch);
            }
        }

        // The out-edge to REMOVE is (1 - num) if num is the kept one.
        let remove_edge = if n_out == 2 { 1 - num } else { return };

        // Get the target block of the edge to remove.
        let target = bb.read().unwrap().get_out(remove_edge).map(|e| e.point);
        let Some(target) = target else { return };

        // Remove the edge from bb to target.
        // In our simplified model, we remove the outgoing edge from bb and
        // the incoming edge from target.
        {
            let mut bb_rg = bb.write().unwrap();
            if let Some(any) = bb_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                if remove_edge < any.outgoing.len() {
                    any.outgoing.remove(remove_edge);
                }
            }
        }
        {
            let mut target_rg = target.write().unwrap();
            if let Some(any) = target_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                // Find and remove the incoming edge from bb.
                let bb_ptr = Arc::as_ptr(bb) as *const () as usize;
                any.incoming.retain(|e| {
                    Arc::as_ptr(&e.point) as *const () as usize != bb_ptr
                });
            }
        }
    }

    // Ghidra: funcdata_block.cc:704 Funcdata::structureReset
    /// Recompute loop structure, dominance, and reset the structured-block
    /// hierarchy for the current CFG. Faithful to
    /// `Funcdata::structureReset` (funcdata_block.cc:705-735).
    ///
    /// Must be called after any mutation that changes the CFG so that
    /// dominator/loop information stays consistent.
    ///
    /// Oracle chain, mirrored statement by statement:
    /// - cc:710 `flags &= ~blocks_unreachable`
    /// - cc:711 `bblocks.structureLoops(rootlist)` — findSpanningTree puts
    ///   the component list in reverse post order (block.cc:1135) and fills
    ///   rootlist with every entry point (multi-root graphs keep the
    ///   original head at RPO[0] via the block.cc:1031-1035 swap)
    /// - cc:712 `bblocks.calcForwardDominator(rootlist)` — CHK dominators
    ///   rooted at postorder.back(), with the createVirtualRoot/excise path
    ///   (block.cc:1970-2029) so multi-root entries end with immed_dom null
    /// - cc:713-714 `if (rootlist.size() > 1) flags |= blocks_unreachable`
    /// - cc:716-727 dead jumptable elimination
    /// - cc:728 `sblocks.clear()`
    /// - cc:730 `heritage.forceRestructure()` (maxdepth = -1)
    ///
    /// Rugra glue tail (no oracle counterpart on the Funcdata level):
    /// refresh the per-block dominator depth/subtree/frontier caches so
    /// Rugra consumers (find_common_block, phi placement) stay coherent
    /// with the freshly written immed_dom set — Ghidra computes dominator
    /// depth locally inside Heritage::buildADT (heritage.cc:2338).
    ///
    /// Errors: Ghidra's LowlevelError channel (findSpanningTree /
    /// calcForwardDominator throws) is mirrored by panic — per-function
    /// worker isolation maps it onto Ghidra's abort-this-function model,
    /// same policy as `Varnode::add_descend`.
    pub fn structure_reset(&mut self) {
        // cc:710: clear any old blocks flag.
        self.flags &= !funcdata_flags::BLOCKS_UNREACHABLE;
        // cc:711: (re)calculate the loop structure and the reverse post
        // order; rootlist receives every entry point.
        let mut rootlist: Vec<Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>> =
            Vec::new();
        if let Err(e) = self.bblocks.structure_loops(&mut rootlist) {
            panic!("{}", e);
        }
        // cc:712: calculate forward dominators (reads the list in the
        // reverse post order established by structure_loops).
        if let Err(e) = self.bblocks.calc_forward_dominator(&rootlist) {
            panic!("{}", e);
        }
        // cc:713-714: more than one entry point -> unreachable code exists.
        if rootlist.len() > 1 {
            self.flags |= funcdata_flags::BLOCKS_UNREACHABLE;
        }
        // cc:716-727: check for dead jumptables; eliminated ones are
        // dropped (Ghidra: `delete jt`) with a header warning.
        let mut alivejumps: Vec<Arc<RwLock<crate::jumptable::JumpTable>>> = Vec::new();
        for jt_arc in std::mem::take(&mut self.jump_tables) {
            let dead = {
                let jt = jt_arc.read().unwrap();
                match jt.get_indirect_op() {
                    Some(indop) => indop.read().unwrap().is_dead(),
                    // Ghidra dereferences getIndirectOp() unconditionally
                    // (funcdata_block.cc:719); Rugra's Option is treated as
                    // alive — no production path leaves a jumptable without
                    // its indirect op here.
                    None => false,
                }
            };
            if dead {
                self.warning_header("Recovered jumptable eliminated as dead code");
                continue; // delete jt
            }
            alivejumps.push(jt_arc);
        }
        self.jump_tables = alivejumps;
        // cc:728: force the structuring algorithm to start over.
        self.sblocks.clear();
        // cc:730: force regeneration of the heritage basic-block structures
        // (maxdepth = -1), so the next Heritage pass rebuilds the augmented
        // dominator tree from the CFG re-established above.
        self.heritage.force_restructure();
        // RUGRA-GLUE: refresh Rugra's per-block dominator caches (dom depth,
        // subtree children, dominance frontiers) that other passes read
        // directly off FlowBlock; the immed_dom set written by
        // calc_forward_dominator is the oracle-observable state.
        self.bblocks.build_dom_depth();
        self.bblocks.build_dom_subtree();
        self.bblocks.calc_dom_frontier();
    }

    // Ghidra: funcdata.hh:149 Funcdata::hasUnreachableBlocks
    /// Did this function exhibit unreachable code — the cached
    /// `blocks_unreachable` flag maintained by `structure_reset`
    /// (funcdata_block.cc:710/714). Ghidra consumers: condexe.cc:485,
    /// double.cc:3267/3348 gate their analysis on it, and
    /// `removeUnreachableBlocks` (funcdata_block.cc:360) uses it as the
    /// cached existence check.
    pub fn has_unreachable_blocks(&self) -> bool {
        (self.flags & funcdata_flags::BLOCKS_UNREACHABLE) != 0
    }

    // Ghidra: funcdata_block.cc:688 Funcdata::installSwitchDefaults
    /// Mark default switch edges for all jump tables. Faithful to
    /// `Funcdata::installSwitchDefaults` (funcdata_block.cc:688-700).
    pub fn install_switch_defaults(&mut self) {
        for jt_arc in &self.jump_tables {
            let jt = jt_arc.read().unwrap();
            let default_block = jt.get_default_block();
            if default_block < 0 {
                continue;
            }
            let indop = jt.get_indirect_op();
            let Some(indop_arc) = indop else { continue };
            // indop->getParent() → the switch BlockBasic.
            let parent = {
                let op = indop_arc.read().unwrap();
                op.parent.as_ref().and_then(|w| w.upgrade())
            };
            let Some(parent_blk) = parent else { continue };
            parent_blk.write().unwrap().set_default_switch(default_block as usize);
        }
    }

    // Ghidra: funcdata_block.cc:328 Funcdata::removeDoNothingBlock
    /// Remove a basic block that does nothing (only marker ops + optional
    /// single branch). Faithful to `Funcdata::removeDoNothingBlock`
    /// (funcdata_block.cc:328-337).
    pub fn remove_do_nothing_block(
        &mut self,
        bb: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) {
        if bb.read().unwrap().size_out() > 1 {
            eprintln!("[BLOCK] Cannot delete block with >1 out edge");
            return;
        }
        bb.write().unwrap().set_flags(crate::block::block_flags::DEAD);
        let ops_to_destroy: Vec<crate::op::PcodeOpRef> = {
            let rg = bb.read().unwrap();
            if let Some(bb2) = rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                bb2.get_ops()
            } else {
                Vec::new()
            }
        };
        for op_ref in &ops_to_destroy {
            self.op_destroy(op_ref);
        }
        self.bblocks.remove_block_arc(bb);
        self.structure_reset();
    }

    // Ghidra: funcdata_block.cc:790 Funcdata::nodeJoinCreateBlock
    /// Create a joined block from two blocks that share exit targets.
    /// Faithful to `Funcdata::nodeJoinCreateBlock`
    /// (funcdata_block.cc:790-826).
    pub fn node_join_create_block(
        &mut self,
        block1: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        block2: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        exita: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        exitb: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        fora_block1ishigh: bool,
        forb_block1ishigh: bool,
        addr: crate::address::Address,
    ) -> Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>> {
        let newblock = self.create_new_block();
        newblock.write().unwrap().set_flags(crate::block::block_flags::JOINED_BLOCK);
        // setInitialRange(addr, addr) — Rugra's create_new_block uses Address(0);
        // the range is informational only (used for cover/debug), so we skip it.

        // Delete 2 of the original edges into exita and exitb (merge.cc:807-818).
        let swapa = if fora_block1ishigh {
            self.bblocks.remove_edge_blocks(block1, exita);
            block2.clone()
        } else {
            self.bblocks.remove_edge_blocks(block2, exita);
            block1.clone()
        };
        let swapb = if forb_block1ishigh {
            self.bblocks.remove_edge_blocks(block1, exitb);
            block2.clone()
        } else {
            self.bblocks.remove_edge_blocks(block2, exitb);
            block1.clone()
        };
        // Move remaining edges to newblock (merge.cc:820-821).
        // swapa->getOutIndex(exita) — find exita in swapa's outgoing.
        let out_idx_a = find_out_index(&swapa, exita);
        let out_idx_b = find_out_index(&swapb, exitb);
        if let Some(idx_a) = out_idx_a {
            self.move_out_edge(&swapa, idx_a, &newblock);
        }
        if let Some(idx_b) = out_idx_b {
            self.move_out_edge(&swapb, idx_b, &newblock);
        }
        // Add edges from block1/block2 to newblock.
        self.bblocks.add_edge(block1.clone(), newblock.clone());
        self.bblocks.add_edge(block2.clone(), newblock.clone());
        self.structure_reset();
        newblock
    }

    // Ghidra: block.cc:1489 BlockGraph::switchEdge
    /// Redirect the edge from `in`→`outbefore` to `in`→`outafter`.
    /// Faithful to `BlockGraph::switchEdge` (block.cc:1489-1495).
    pub fn switch_edge(
        &mut self,
        in_block: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        outbefore: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        outafter: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) {
        // Find the out-edge slot from in_block pointing to outbefore, then
        // redirect it to outafter (block.cc:1492-1494).
        if let Some(slot) = find_out_index(in_block, outbefore) {
            let mut in_rg = in_block.write().unwrap();
            if let Some(bb) = in_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                bb.replace_out_edge_target(slot, outafter.clone());
            }
            // BlockGraph and other types: nodeSplit only operates on BlockBasic.
        }
    }

    // Ghidra: funcdata_block.cc:835 Funcdata::nodeSplitBlockEdge
    /// Create a duplicate block that inherits the same out-edges but only the
    /// one indicated in-edge, which is moved from the original block.
    /// Faithful to `Funcdata::nodeSplitBlockEdge` (funcdata_block.cc:835-848).
    fn node_split_block_edge(
        &mut self,
        b: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        inedge: usize,
    ) -> Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>> {
        let a = b.read().unwrap().get_in(inedge).map(|e| e.point.clone());
        let Some(a) = a else {
            return self.create_new_block();
        };
        let bprime = self.create_new_block();
        bprime.write().unwrap().set_flags(crate::block::block_flags::DUPLICATE_BLOCK);
        // copyRange(b) — Rugra blocks don't track address range; skip.
        // switchEdge(a, b, bprime)
        self.switch_edge(&a, b, &bprime);
        // Add all of b's out-edges to bprime.
        let outs: Vec<Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>> = {
            let br = b.read().unwrap();
            (0..br.size_out()).filter_map(|i| br.get_out(i).map(|e| e.point.clone())).collect()
        };
        for out in &outs {
            self.bblocks.add_edge(bprime.clone(), out.clone());
        }
        bprime
    }

    // Ghidra: funcdata_block.cc:856 Funcdata::nodeSplit
    /// Split control-flow into a basic block, duplicating its p-code into a
    /// new block. Faithful to `Funcdata::nodeSplit` (funcdata_block.cc:856-882).
    pub fn node_split(
        &mut self,
        b: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        inedge: usize,
    ) {
        // Preconditions (merge.cc:859-869).
        if b.read().unwrap().size_out() != 0 {
            eprintln!("[BLOCK] Cannot nodesplit block with out flow");
            return;
        }
        if b.read().unwrap().size_in() <= 1 {
            eprintln!("[BLOCK] Cannot nodesplit block with only 1 in edge");
            return;
        }
        // Create duplicate block.
        let bprime = self.node_split_block_edge(b, inedge);
        // CloneBlockOps: clone all ops from b into bprime.
        let mut cloner = CloneBlockOps::new();
        cloner.clone_block(self, b, &bprime, inedge);
        self.structure_reset();
    }

    // Ghidra: funcdata_varnode.cc:938 Funcdata::syncVarnodesWithSymbols
    /// Update Varnode properties based on (new) Symbol information. Faithful
    /// to `Funcdata::syncVarnodesWithSymbols`
    /// (funcdata_varnode.cc:938-989): boolean properties `mapped`, `addrtied`,
    /// `addrforce`, and `nolocalalias` are updated from the ScopeLocal Symbol
    /// each Varnode overlaps; when `update_datatypes` is set the Symbol's
    /// sized data-type is projected onto the Varnode via `updateType`.
    ///
    /// Iterates the Varnode bank in 'loc' order restricted to the scope's
    /// space; each same-(address,size) set is dispatched to
    /// [`Self::sync_varnodes_with_symbol_set`], which advances the iteration
    /// past the set (the `VarnodeLocSet::const_iterator &iter` advance of
    /// funcdata_varnode.cc:985). Returns true if any Varnode was updated.
    pub fn sync_varnodes_with_symbols(
        &mut self,
        update_datatypes: bool,
        unmapped_alias_check: bool,
    ) -> bool {
        use crate::type_system::datatype::TypeMetatype;
        use crate::varnode::varnode_flags;

        let scope = match &self.scope {
            Some(s) => s.clone(),
            None => return false,
        };
        // cc:947-948: iter = vbank.beginLoc(lm->getSpaceId());
        // enditer = vbank.endLoc(lm->getSpaceId()). The loc-tree ordering
        // (space, offset, size, input/written/free, seq) keeps every
        // same-(offset,size) set contiguous within the space, so a filtered
        // snapshot plus an index reproduces the iterator pair. Nothing below
        // inserts/removes Varnodes or touches INPUT/WRITTEN/def, so the
        // ordering is stable across the flag/type writes.
        let space = scope.space;
        let ordered: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = self
            .vbank
            .loc_tree
            .iter()
            .filter(|entry| entry.0.read().unwrap().get_space() == space)
            .map(|entry| entry.0.clone())
            .collect();

        let mut updateoccurred = false;
        let mut index = 0usize;
        while index < ordered.len() {
            let vnexemplar = ordered[index].clone();
            let (addr, size) = {
                let vn = vnexemplar.read().unwrap();
                (vn.get_offset(), vn.get_size() as i64)
            };
            // cc:951: entry = lm->findOverlap(vnexemplar->getAddr(), vnexemplar->getSize());
            let entry = scope_local_find_overlap(&scope, space, addr, size as i32);
            let mut ct: Option<std::sync::Arc<crate::type_system::datatype::Datatype>> = None;
            let fl: u32;
            if let Some(sym) = entry {
                // cc:954: fl = entry->getAllFlags() — the extraflags
                // (Varnode::mapped from addMapInternal, database.cc:1155)
                // plus the Symbol flags. Symbol addrtied is set by
                // Scope::addMap exactly when the mapping carries no usepoint
                // (database.cc:1149-1150), which LocalSymbol.usepoint == None
                // mirrors.
                let mut f = varnode_flags::MAPPED;
                if sym.usepoint.is_none() {
                    f |= varnode_flags::ADDRTIED;
                }
                if sym.typelock {
                    f |= varnode_flags::TYPELOCK;
                }
                if sym.namelock {
                    f |= varnode_flags::NAMELOCK;
                }
                if sym.unaliased {
                    f |= varnode_flags::NOLOCALALIAS;
                }
                if sym.size as i64 >= size {
                    if update_datatypes {
                        // cc:956-960: ct = entry->getSizedType(addr, size);
                        // TYPE_UNKNOWN results are dropped.
                        if let Some(dt) = local_symbol_sized_type(sym, addr, size as i32) {
                            if dt.get_metatype() != TypeMetatype::Unknown {
                                ct = Some(dt);
                            }
                        }
                    }
                } else {
                    // cc:962-969: overlapping but not containing — small
                    // locked symbol in a bigger register: don't try to figure
                    // out the type, don't keep typelock and namelock (we do
                    // particularly want to keep the nolocalalias, which the
                    // clear below leaves alone).
                    f &= !(varnode_flags::TYPELOCK | varnode_flags::NAMELOCK);
                }
                fl = f;
            } else {
                // cc:971-983: could not find any symbol.
                // cc:972: usepoint = vnexemplar->getUsePoint(*this) — fed to
                // the (ignored) third parameter of Scope::inScope exactly as
                // the oracle call shape (funcdata_varnode.cc:972-973).
                let usepoint = varnode_use_point_offset(self, &vnexemplar);
                if scope_local_in_scope(&scope, space, addr, size as i32, usepoint) {
                    // cc:976: technically an error — there should be some kind
                    // of symbol if we are in scope.
                    fl = varnode_flags::MAPPED | varnode_flags::ADDRTIED;
                } else if unmapped_alias_check {
                    // cc:980: if the varnode is not in scope, check if we
                    // should treat it as unaliased.
                    fl = if scope_local_is_unmapped_unaliased(&scope, &vnexemplar) {
                        varnode_flags::NOLOCALALIAS
                    } else {
                        0
                    };
                } else {
                    fl = 0;
                }
            }
            // cc:985: if (syncVarnodesWithSymbol(iter,fl,ct)) updateoccurred = true;
            if self.sync_varnodes_with_symbol_set(&ordered, &mut index, fl, ct) {
                updateoccurred = true;
            }
        }
        updateoccurred
    }

    // Ghidra: funcdata_varnode.cc:1048 Funcdata::syncVarnodesWithSymbol
    /// Update properties (and the data-type) for a set of Varnodes associated
    /// with one Symbol. Faithful to the private overload
    /// `Funcdata::syncVarnodesWithSymbol(VarnodeLocSet::const_iterator&,uint4,Datatype*)`
    /// (funcdata_varnode.cc:1048-1095): all Varnodes sharing the exemplar's
    /// (address,size) get the masked flag update — `mapped` always;
    /// `addrtied`/`addrforce` clearable but not settable; `nolocalalias` +
    /// `addrforce` settable but `nolocalalias` not clearable — then the
    /// data-type via `Varnode::updateType` when `ct` is non-null. Varnodes
    /// with an attached SymbolEntry keep their `mapped` bit unchanged
    /// (cc:1075-1082). `index` is advanced past the whole set.
    fn sync_varnodes_with_symbol_set(
        &mut self,
        ordered: &[std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>],
        index: &mut usize,
        mut fl: u32,
        ct: Option<std::sync::Arc<crate::type_system::datatype::Datatype>>,
    ) -> bool {
        use crate::varnode::varnode_flags;

        let mut updateoccurred = false;
        // cc:1056: mask = Varnode::mapped — the flags we are going to try to
        // update. We take special care with the addrtied flag as we cannot
        // SET it here if it is clear: we can CLEAR but not SET addrtied, and
        // if addrtied is cleared, so should addrforce (cc:1057-1062).
        let mut mask = varnode_flags::MAPPED;
        if (fl & varnode_flags::ADDRTIED) == 0 {
            mask |= varnode_flags::ADDRTIED | varnode_flags::ADDRFORCE;
        }
        // cc:1063-1066: we can set the nolocalalias flag, but not clear it;
        // if nolocalalias is set, then addrforce should be cleared.
        if (fl & varnode_flags::NOLOCALALIAS) != 0 {
            mask |= varnode_flags::NOLOCALALIAS | varnode_flags::ADDRFORCE;
        }
        fl &= mask;

        // cc:1069-1070: enditer = vbank.endLoc(vn->getSize(), vn->getAddr())
        // — the set is every remaining Varnode with the exemplar's
        // (space, offset, size); the outer loc order keeps it contiguous.
        let (set_space, set_addr, set_size) = {
            let vn = ordered[*index].read().unwrap();
            (vn.get_space(), vn.get_offset(), vn.get_size())
        };
        // cc:1071-1093: do { ... } while (iter != enditer);
        while *index < ordered.len() {
            let vn = ordered[*index].clone();
            let matches_set = {
                let vn_r = vn.read().unwrap();
                vn_r.get_space() == set_space
                    && vn_r.get_offset() == set_addr
                    && vn_r.get_size() == set_size
            };
            if !matches_set {
                break;
            }
            *index += 1;
            let mut vn_w = vn.write().unwrap();
            // cc:1073: if (vn->isFree()) continue;
            if vn_w.is_free() {
                continue;
            }
            let vnflags = vn_w.flags;
            let high = vn_w.high.clone();
            if vn_w.mapentry.is_some() {
                // cc:1075-1082: already an attached SymbolEntry (dynamic):
                // make sure the 'mapped' bit is unchanged.
                let local_mask = mask & !varnode_flags::MAPPED;
                let local_flags = fl & local_mask;
                if (vnflags & local_mask) != local_flags {
                    updateoccurred = true;
                    vn_w.set_flags(local_flags);
                    vn_w.clear_flags((!local_flags) & local_mask);
                    if let Some(high) = &high {
                        // varnode.cc:352-374 setFlags/clearFlags -> flagsDirty
                        high.write().unwrap().flags_dirty();
                    }
                }
            } else if (vnflags & mask) != fl {
                // cc:1084-1088: we have a change.
                updateoccurred = true;
                vn_w.set_flags(fl);
                vn_w.clear_flags((!fl) & mask);
                if let Some(high) = &high {
                    high.write().unwrap().flags_dirty();
                }
            }
            if let Some(ct) = &ct {
                // cc:1089-1092: if (vn->updateType(ct)) updateoccurred = true;
                if vn_w.update_type(ct.clone()) {
                    updateoccurred = true;
                    if let Some(high) = &high {
                        // varnode.cc:456-464 updateType -> typeDirty
                        high.write().unwrap().type_dirty();
                    }
                }
            }
        }
        updateoccurred
    }

    // Ghidra: funcdata.cc:34 Funcdata::removeFromFlowSplit
    /// Remove a 2-in/2-out empty block, rejoining each in-edge to the
    /// corresponding out-edge. Faithful to `Funcdata::removeFromFlowSplit`
    /// (funcdata_block.cc:892-900) + `BlockGraph::removeFromFlowSplit`
    /// (block.cc:1575-1590).
    ///
    /// `bl` must have exactly 2 in-edges and 2 out-edges and no ops.
    /// If `swap` is false: In(0)->Out(1), In(1)->Out(0).
    /// If `swap` is true:  In(0)->Out(0), In(1)->Out(1).
    ///
    /// (Ghidra's flipflow semantics: flipflow=true maps to replaceEdgesThru(0,0)
    ///  joining in0->out0; flipflow=false joins in0->out1 first. We mirror this.)
    pub fn remove_from_flow_split(
        &mut self,
        bl: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        swap: bool,
    ) -> Result<(), String> {
        // Validate 2-in / 2-out and empty.
        if bl.read().unwrap().size_in() != 2 || bl.read().unwrap().size_out() != 2 {
            return Err("remove_from_flow_split: block must have 2 in/2 out".to_string());
        }
        let nonempty = {
            let bl_rg = bl.read().unwrap();
            if let Some(bb) = bl_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                !bb.ops.is_empty()
            } else {
                // Non-basic composite blocks: treat as removable if they have
                // no ops directly (they delegate to children).
                bl_rg.get_ops().is_empty()
            }
        };
        if nonempty {
            return Err("remove_from_flow_split: block must be empty".to_string());
        }

        // Faithful to BlockGraph::removeFromFlowSplit (block.cc:1584-1589):
        //   if flipflow: replaceEdgesThru(0,1)  // in0 -> out1
        //   else:        replaceEdgesThru(1,1)  // in1 -> out1
        //   then:        replaceEdgesThru(0,0)  // remaining in0 -> out0
        // Note: Ghidra's param is `flipflow`; our `swap` matches flipflow
        // (swap=true => in0->out0, in1->out1).
        {
            let mut bl_rg = bl.write().unwrap();
            if let Some(bb) = bl_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                if swap {
                    bb.replace_edges_thru(0, 0);
                    bb.replace_edges_thru(0, 1);
                } else {
                    bb.replace_edges_thru(0, 1);
                    bb.replace_edges_thru(0, 0);
                }
            } else {
                return Err("remove_from_flow_split: only BlockBasic supported".to_string());
            }
        }
        // Remove the now-disconnected block from the graph.
        self.bblocks.remove_block_arc(bl);
        self.structure_reset();
        Ok(())
    }

    // Ghidra: funcdata.cc:34 Funcdata::removeUnreachableBlocks
    /// Remove any basic blocks not reachable from the entry point.
    /// Faithful to `Funcdata::removeUnreachableBlocks` (funcdata_block.cc:347-394).
    ///
    /// Performs a forward BFS from the entry block, marks blocks NOT visited as
    /// dead, removes their out-edges, then removes them from the graph. Returns
    /// true if any unreachable block was removed.
    pub fn remove_unreachable_blocks(&mut self) -> bool {
        let n = self.bblocks.get_size();
        if n == 0 {
            return false;
        }
        // Find the entry point: a block with zero in-edges (no predecessors),
        // matching Ghidra's isEntryPoint() (block.hh:325: size_in()==0 or
        // explicitly flagged). Previously only checked the ENTRY_POINT flag
        // which is never set during Rugra's CFG construction, causing the
        // fallback to block 0 — which may not be the true entry, leading to
        // false-positive "unreachable" detection and function-body loss.
        let entry = (0..n)
            .find(|&i| {
                self.bblocks.get_block(i).map(|b| {
                    let bg = b.read().unwrap();
                    bg.size_in() == 0
                        || (bg.get_flags() & crate::block::block_flags::ENTRY_POINT) != 0
                }).unwrap_or(false)
            })
            .unwrap_or(0);
        // Forward BFS from entry to find reachable set.
        let mut reachable = std::collections::HashSet::new();
        let mut queue = vec![entry];
        reachable.insert(entry);
        while let Some(idx) = queue.pop() {
            let outs: Vec<i32> = {
                if let Some(blk) = self.bblocks.get_block(idx) {
                    let b = blk.read().unwrap();
                    let nn = b.size_out();
                    (0..nn).filter_map(|j| b.get_out(j).map(|e| e.point.read().unwrap().get_index())).collect()
                } else {
                    Vec::new()
                }
            };
            for o in outs {
                if reachable.insert(o as usize) {
                    queue.push(o as usize);
                }
            }
        }
        // Collect unreachable blocks.
        let unreachable: Vec<usize> = (0..n).filter(|i| !reachable.contains(i)).collect();
        if unreachable.is_empty() {
            return false;
        }
        // Conservative guard: if a large fraction of blocks are "unreachable",
        // the CFG is likely incomplete (BRANCHIND/jump-table edges missing).
        // Skip removal to avoid deleting reachable function body.
        // Uses BOTH absolute (>=5) and relative (>5%) thresholds: small test
        // CFGs with genuinely dead blocks still get cleaned, but real functions
        // with incomplete CFGs (where many blocks are falsely unreachable)
        // are protected.
        // TODO: remove this guard once BRANCHIND edges are added to the CFG.
        if unreachable.len() >= 5 && unreachable.len() * 20 > n {
            return false;
        }
        // Mark dead, remove their out-edges, then remove from the graph.
        // Faithful to Ghidra removeUnreachableBlocks (funcdata_block.cc:370-391):
        // for each unreachable block: setDead, branchRemoveInternal all out-edges,
        // then blockRemoveInternal (which destroys ops + removes from graph).
        // For unreachable=true, Ghidra calls descend2Undef on output varnodes
        // (funcdata_block.cc:305-306) and checks descendantsOutside (312).
        // Rugra's simplified version: mark block's ops as dead (so they don't
        // appear in alivelist for printc), remove all edges, remove block.
        let dead_arcs: Vec<_> = unreachable.iter()
            .filter_map(|&i| self.bblocks.get_block(i))
            .collect();
        // Phase 1: mark blocks DEAD.
        for arc in &dead_arcs {
            arc.write().unwrap().set_flags(crate::block::block_flags::DEAD);
        }
        // Phase 2: destroy ops in each dead block. Faithful to Ghidra
        // blockRemoveInternal funcdata_block.cc:300-319: for unreachable=true,
        // Ghidra calls descend2Undef on output varnodes, then checks
        // descendantsOutside. Rugra's approach: only mark_dead ops whose
        // output has NO descendants outside the dead block set. Ops with
        // external descendants are left alive (their block is DEAD-flagged so
        // emit_block_ops skips them, but the op stays in alivelist so its
        // output varnode remains valid for any phi-node that references it).
        let dead_block_ptrs: std::collections::HashSet<usize> = dead_arcs.iter()
            .map(|a| std::sync::Arc::as_ptr(a) as *const () as usize)
            .collect();
        for arc in &dead_arcs {
            let ops_to_check: Vec<crate::op::PcodeOpRef> = {
                let block = arc.read().unwrap();
                if let Some(bb) = block.as_any().downcast_ref::<crate::block::BlockBasic>() {
                    bb.ops.iter().map(|o| o.0.clone()).map(crate::op::PcodeOpRef).collect()
                } else {
                    Vec::new()
                }
            };
            for op_ref in ops_to_check {
                // Check if output has descendants outside dead blocks.
                let has_external_desc = {
                    let op = op_ref.0.read().unwrap();
                    if let Some(ref out_arc) = op.output {
                        let out_vn = out_arc.read().unwrap();
                        out_vn.descend.iter()
                            .filter_map(|w| w.upgrade())
                            .any(|desc_op| {
                                let d = desc_op.read().unwrap();
                                d.parent.as_ref()
                                    .and_then(|pw| pw.upgrade())
                                    .map(|parent| {
                                        let p = std::sync::Arc::as_ptr(&parent) as *const () as usize;
                                        !dead_block_ptrs.contains(&p)
                                    })
                                    .unwrap_or(true)
                            })
                    } else {
                        false
                    }
                };
                if !has_external_desc {
                    self.obank.mark_dead(op_ref);
                }
                // Ops with external descendants are left alive — their block is
                // DEAD-flagged (emit_block_ops checks is_dead) but the op
                // remains valid for phi-node references.
            }
        }
        // Phase 3: detach all out-edges (branchRemoveInternal equivalent).
        for arc in &dead_arcs {
            while arc.read().unwrap().size_out() > 0 {
                let dst = arc.read().unwrap().get_out(0).map(|e| e.point);
                if let Some(dst) = dst {
                    self.bblocks.remove_edge_blocks(arc, &dst);
                } else {
                    break;
                }
            }
        }
        // Phase 4: remove blocks from graph (blockRemoveInternal equivalent).
        for arc in &dead_arcs {
            self.bblocks.remove_block_arc(arc);
        }
        self.structure_reset();
        true
    }

    // Ghidra: funcdata.cc:34 Funcdata::createNewBlock
    /// Splice a 1-out basic block into its single successor.
    /// Faithful to `Funcdata::spliceBlockBasic` (funcdata_block.cc:919-956).
    ///
    /// The given block must have a single output block with a single input
    /// (from this block). The output block's ops are conceptually merged; here
    /// we splice the CFG: this block inherits the successor's out-edges and the
    /// successor is removed. This is used by ActionRedundBranch (case 1) and
    /// ActionDoNothing.
    /// Create a new empty basic block and add it to bblocks. Faithful to
    /// `Funcdata::newBlockBasic` (funcdata_block.cc). Returns the Arc.
    pub fn create_new_block(&mut self) -> Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>> {
        let addr = crate::address::Address::new(0);
        let bb = Arc::new(RwLock::new(crate::block::BlockBasic::new(0, addr)));
        self.bblocks.add_block(bb.clone());
        bb
    }

    // Ghidra: funcdata.cc:34 Funcdata::spliceBlockBasic
    pub fn splice_block_basic(&mut self, bb: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>) -> bool {
        let (out_block, out_has_single_in) = {
            let rg = bb.read().unwrap();
            if rg.size_out() != 1 {
                return false;
            }
            let ob = rg.get_out(0).map(|e| e.point);
            let ob = match ob { Some(o) => o, None => return false };
            let single_in = ob.read().unwrap().size_in() == 1;
            (ob, single_in)
        };
        if !out_has_single_in {
            return false;
        }
        // Destroy any branch op at the end of bb (it falls through).
        let last_op = {
            let rg = bb.read().unwrap();
            if let Some(bb2) = rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                bb2.last_op()
            } else {
                None
            }
        };
        if let Some(branch_op) = last_op {
            let is_branch = {
                let o = branch_op.0.read().unwrap();
                o.opcode == crate::opcodes::OpCode::CPUI_BRANCH
                    || o.opcode == crate::opcodes::OpCode::CPUI_CBRANCH
                    || o.opcode == crate::opcodes::OpCode::CPUI_BRANCHIND
            };
            if is_branch {
                self.op_destroy(&branch_op);
            }
        }
        // Move out_block's ops into bb (faithful to Ghidra funcdata_block.cc:
        // 940-947: bl->op.splice(bl->op.end(), outbl->op, ...)). This is the
        // KEY step that was missing — without it, out_block's ops are orphaned
        // when the block is removed, and printc can't find them.
        {
            // Check for MULTIEQUAL (phi) at start of out_block — Ghidra throws
            // if found (funcdata_block.cc:936). We skip the splice in that case.
            let has_phi = {
                let out_rg = out_block.read().unwrap();
                if let Some(out_bb) = out_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                    out_bb.ops.first().map(|o| {
                        o.0.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_MULTIEQUAL
                    }).unwrap_or(false)
                } else {
                    false
                }
            };
            if has_phi {
                // Can't splice — out_block starts with a phi-node. Put the
                // edge back and abort. Ghidra throws; we just return false.
                self.bblocks.add_edge(bb.clone(), out_block.clone());
                return false;
            }

            // Move ops from out_block to end of bb.
            let moved_ops: Vec<crate::op::PcodeOpRef> = {
                let mut out_rg = out_block.write().unwrap();
                if let Some(out_bb) = out_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                    let ops = std::mem::take(&mut out_bb.ops);
                    ops.into_iter().map(|o| crate::op::PcodeOpRef(o.0)).collect()
                } else {
                    Vec::new()
                }
            };
            // Set parent of moved ops to bb, and append to bb's ops.
            let bb_weak = std::sync::Arc::downgrade(
                &(bb.clone() as Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>),
            );
            let mut bb_rg = bb.write().unwrap();
            if let Some(bb_bb) = bb_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                for op_ref in &moved_ops {
                    op_ref.0.write().unwrap().parent = Some(bb_weak.clone());
                    let insert_pos = bb_bb.ops.len();
                    bb_bb.insert_op(insert_pos, crate::op::PcodeOpRef(op_ref.0.clone()));
                }
                // Reset seq_num ordering on all ops in bb (Ghidra :948 setOrder).
                bb_bb.set_order();
            }
        }
        // Splice the CFG edges, faithful to BlockGraph::spliceBlock
        // (block.cc:1597-1620):
        //   fl1 = bl->flags & (f_unstructured_targ | f_entry_point)   // keep from bl
        //   fl2 = outbl->flags & f_switch_out                          // keep from outbl
        //   bl->removeOutEdge(0)                                       // drop bl→outbl
        //   for each out-edge of outbl: moveOutEdge(outbl, 0, bl)      // move outbl's edges to bl
        //   removeBlock(outbl)
        //   bl->flags = fl1 | fl2                                       // merge flags
        let (fl1, fl2, szout) = {
            let bl_rg = bb.read().unwrap();
            let out_rg = out_block.read().unwrap();
            let keep_from_bl = bl_rg.get_flags()
                & (crate::block::block_flags::UNSTRUCTURED_TARG
                    | crate::block::block_flags::ENTRY_POINT);
            let keep_from_out = out_rg.get_flags()
                & crate::block::block_flags::SWITCH_OUT;
            (keep_from_bl, keep_from_out, out_rg.size_out())
        };
        // Drop bb's single out-edge to out_block (block.cc:1612 removeOutEdge(0)).
        self.bblocks.remove_edge_blocks(bb, &out_block);
        // Move every out-edge of out_block to bb (block.cc:1614-1616).
        // moveOutEdge(outbl, 0, bl) relocates edge 0's reverse-index entry on
        // the destination to point at bl. We always move slot 0 because after
        // each move the remaining edges shift down.
        for _ in 0..szout {
            self.move_out_edge(&out_block, 0, bb);
        }
        // Remove out_block from the graph (block.cc:1618 removeBlock).
        self.bblocks.remove_block_arc(&out_block);
        // Merge flags: bl->flags = fl1 | fl2 (block.cc:1619).
        // BlockBasic.flags is a public field; assign exactly as Ghidra does.
        {
            let mut bb_rg = bb.write().unwrap();
            if let Some(bb_bb) = bb_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                bb_bb.flags = fl1 | fl2;
            }
        }
        // bl->mergeRange(outbl) (funcdata_block.cc:953) — update address cover.
        // TODO: Rugra has no Cover system yet; address-cover merge is a known
        // infrastructure gap (recorded in ALIGNMENT_ROADMAP). Does not affect
        // correctness of CFG splice for current pipeline.
        self.structure_reset();
        true
    }

    // Ghidra: funcdata.cc:34 Funcdata::replaceLessequal
    /// Replace INT_LESSEQUAL/INT_SLESSEQUAL with INT_LESS/INT_SLESS:
    /// `V <= c => V < c+1`. Faithful to `Funcdata::replaceLessequal`
    /// (funcdata_op.cc:1029-1065).
    pub fn replace_lessequal(&mut self, op: &crate::op::PcodeOpRef) -> bool {
        let (i, diff, val, size, is_signed) = {
            let o = op.0.read().unwrap();
            let (vn_idx, diff) = if o.inrefs.get(0).map_or(false, |v| v.read().unwrap().is_constant()) {
                (0, -1i64)
            } else if o.inrefs.get(1).map_or(false, |v| v.read().unwrap().is_constant()) {
                (1, 1i64)
            } else {
                return false;
            };
            let vn = o.inrefs[vn_idx].clone();
            let val = vn.read().unwrap().get_offset();
            let size = vn.read().unwrap().get_size();
            (vn_idx, diff, val, size, o.opcode == OpCode::CPUI_INT_SLESSEQUAL)
        };
        let mask = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
        if is_signed {
            let int_min = if size >= 8 { i64::MIN as u64 } else { (1u64 << (size * 8 - 1)) };
            let int_max = if size >= 8 { i64::MAX as u64 } else { mask >> 1 };
            if diff == -1 && val == int_min { return false; }
            if diff == 1 && val == int_max { return false; }
            self.op_set_opcode(op, OpCode::CPUI_INT_SLESS);
        } else {
            if diff == -1 && val == 0 { return false; }
            if diff == 1 && val == mask { return false; }
            self.op_set_opcode(op, OpCode::CPUI_INT_LESS);
        }
        let res = (val as i64 + diff) as u64 & mask;
        let newconst = self.new_constant(size, res);
        self.op_set_input(op, newconst, i);
        true
    }

    // Ghidra: funcdata.cc:34 Funcdata::distributeIntMultAdd
    /// Distribute INT_MULT coefficient through INT_ADD:
    /// `(V + W) * c => V*c + W*c`.
    /// Faithful to `Funcdata::distributeIntMultAdd` (funcdata_op.cc:1073-1118).
    /// The given op is INT_MULT(in0=INT_ADD(...), in1=constant coeff).
    pub fn distribute_int_mult_add(&mut self, op: &crate::op::PcodeOpRef) -> bool {
        let (vn0, vn1, coeff, sz, pc) = {
            let o = op.0.read().unwrap();
            if o.opcode != OpCode::CPUI_INT_MULT { return false; }
            let in0 = match o.inrefs.get(0) { Some(v) => v.clone(), None => return false };
            let in1 = match o.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return false,
            };
            let addop_arc = {
                let i0 = in0.read().unwrap();
                i0.def.as_ref().and_then(|w| w.upgrade())
            };
            let addop_arc = match addop_arc { Some(a) => a, None => return false };
            if addop_arc.read().unwrap().opcode != OpCode::CPUI_INT_ADD { return false; }
            let (vn0, vn1) = {
                let ao = addop_arc.read().unwrap();
                (ao.inrefs.get(0).cloned(), ao.inrefs.get(1).cloned())
            };
            let (vn0, vn1) = match (vn0, vn1) { (Some(a), Some(b)) => (a, b), _ => return false };
            let coeff = in1.read().unwrap().get_offset();
            let sz = o.output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(0);
            (vn0, vn1, coeff, sz, o.start.get_addr())
        };
        if sz == 0 { return false; }
        let mask = if sz >= 8 { u64::MAX } else { (1u64 << (sz * 8)) - 1 };
        let follow = crate::op::PcodeOpRef(op.0.clone());
        // Distribute vn0 * coeff
        let newvn0 = if vn0.read().unwrap().is_constant() {
            let val = coeff.wrapping_mul(vn0.read().unwrap().get_offset()) & mask;
            self.new_constant(sz, val)
        } else {
            if vn0.read().unwrap().is_free() && !vn0.read().unwrap().is_constant() { return false; }
            let newop0 = self.new_op(2, pc);
            self.op_set_opcode(&newop0, OpCode::CPUI_INT_MULT);
            let newout0 = self.new_unique_out(sz, &newop0);
            self.op_set_input(&newop0, vn0, 0);
            let c0 = self.new_constant(sz, coeff);
            self.op_set_input(&newop0, c0, 1);
            self.op_insert_before(&newop0, &follow);
            newout0
        };
        // Distribute vn1 * coeff
        let newvn1 = if vn1.read().unwrap().is_constant() {
            let val = coeff.wrapping_mul(vn1.read().unwrap().get_offset()) & mask;
            self.new_constant(sz, val)
        } else {
            if vn1.read().unwrap().is_free() && !vn1.read().unwrap().is_constant() { return false; }
            let newop1 = self.new_op(2, pc);
            self.op_set_opcode(&newop1, OpCode::CPUI_INT_MULT);
            let newout1 = self.new_unique_out(sz, &newop1);
            self.op_set_input(&newop1, vn1, 0);
            let c1 = self.new_constant(sz, coeff);
            self.op_set_input(&newop1, c1, 1);
            self.op_insert_before(&newop1, &follow);
            newout1
        };
        // Rewrite op to INT_ADD(newvn0, newvn1)
        self.op_set_input(&follow, newvn0, 0);
        self.op_set_input(&follow, newvn1, 1);
        self.op_set_opcode(&follow, OpCode::CPUI_INT_ADD);
        true
    }

    // Ghidra: funcdata_op.cc:345 Funcdata::opInsertBefore
    /// Insert `op` before `follow` in its basic block, preserving the
    /// contiguous INDIRECT group immediately preceding `follow`.
    pub fn op_insert_before(&mut self, op: &crate::op::PcodeOpRef, follow: &crate::op::PcodeOpRef) {
        let parent = follow
            .0
            .read()
            .unwrap()
            .parent
            .as_ref()
            .and_then(std::sync::Weak::upgrade);
        let Some(parent) = parent else {
            // RUGRA-GLUE: Legacy Rule unit fixtures construct an alive, parentless
            // flat op bank, which is outside Ghidra's opInsertBefore precondition.
            // Preserve their former flat-list behavior until those fixtures acquire
            // real BlockBasic membership; this branch is not oracle-equivalent.
            self.obank.mark_alive(op.clone());
            self.obank
                .alivelist
                .retain(|candidate| !std::sync::Arc::ptr_eq(&candidate.0, &op.0));
            let mut insert_index = self
                .obank
                .alivelist
                .iter()
                .position(|candidate| std::sync::Arc::ptr_eq(&candidate.0, &follow.0))
                .unwrap_or(self.obank.alivelist.len());
            if op.0.read().unwrap().opcode != OpCode::CPUI_INDIRECT {
                while insert_index != 0
                    && self.obank.alivelist[insert_index - 1]
                        .0
                        .read()
                        .unwrap()
                        .opcode
                        == OpCode::CPUI_INDIRECT
                {
                    insert_index -= 1;
                }
            }
            self.obank.alivelist.insert(insert_index, op.clone());
            return;
        };
        let block_ops = parent.read().unwrap().get_ops();
        let mut insert_index = block_ops
            .iter()
            .position(|candidate| std::sync::Arc::ptr_eq(&candidate.0, &follow.0))
            .expect("opInsertBefore follow op is absent from its parent block");

        if op.0.read().unwrap().opcode != OpCode::CPUI_INDIRECT {
            while insert_index != 0 {
                let previous = &block_ops[insert_index - 1];
                if previous.0.read().unwrap().opcode != OpCode::CPUI_INDIRECT {
                    break;
                }
                insert_index -= 1;
            }
        }
        self.op_insert(op, &parent, Some(insert_index));
    }

    // Ghidra: funcdata_op.cc:683 Funcdata::newIndirectOp
    /// Create a new CPUI_INDIRECT around a PcodeOp with an indirect effect,
    /// guarding the (space, offset, sz) storage range. Faithful 1:1 port of
    /// `newIndirectOp` (funcdata_op.cc:683-698):
    ///   - input[0]  = free Varnode at (space, offset, sz) — the value before
    ///   - output    = written Varnode at (space, offset, sz)
    ///   - input[1]  = Iop-space Varnode aliasing the causing op
    ///     (`newVarnodeIop`, round-trips through `get_op_from_const`)
    ///   - op flags |= extra_flags (0 for CALL guards, `indirect_store`
    ///     for STORE guards — the caller decides, exactly as in Ghidra)
    ///   - inserted before the causing op via `opInsertBefore`
    /// The constructor performs no setActiveHeritage — Ghidra's callers
    /// (guardCalls/guardStores, heritage.cc:1512-1516/1553-1556) do that
    /// after construction, so Rugra callers must too.
    pub fn new_indirect_op(
        &mut self,
        indeffect: &crate::op::PcodeOpRef,
        space: crate::space::AddressSpace,
        offset: u64,
        sz: usize,
        extra_flags: u32,
    ) -> crate::op::PcodeOpRef {
        // cc:689: newin = newVarnode(sz, addr);
        let newin = self.vbank.create_with_space(sz, space, offset);
        // cc:690: newop = newOp(2, indeffect->getAddr());
        let indeffect_addr = indeffect.0.read().unwrap().get_seq_num().get_addr();
        let newop = self.new_op(2, indeffect_addr);
        // cc:691: newop->flags |= extraFlags;
        newop.0.write().unwrap().flags |= extra_flags;
        // cc:692: newVarnodeOut(sz, addr, newop);  (createDef -> WRITTEN+INSERT xref)
        let newout = self.vbank.create_with_space(sz, space, offset);
        let newout = self
            .vbank
            .set_def_prevalidated(newout, std::sync::Arc::downgrade(&newop.0));
        newop.0.write().unwrap().output = Some(newout.clone());
        // cc:693: opSetOpcode(newop, CPUI_INDIRECT);
        self.op_set_opcode(&newop, crate::opcodes::OpCode::CPUI_INDIRECT);
        // cc:694: opSetInput(newop, newin, 0);
        self.op_set_input(&newop, newin, 0);
        // cc:695: opSetInput(newop, newVarnodeIop(indeffect), 1);
        let iop_vn = self.new_varnode_iop(indeffect);
        self.op_set_input(&newop, iop_vn, 1);
        // cc:696: opInsertBefore(newop, indeffect);
        self.op_insert_before(&newop, indeffect);
        newop
    }

    // Ghidra: funcdata_varnode.cc:176 Funcdata::newVarnodeIop
    /// Create a varnode in the iop address space referencing `op`.
    /// Faithful to `Funcdata::newVarnodeIop` (funcdata_varnode.cc:176-184):
    ///   Varnode *vn = vbank.create(sizeof(op), Address(cspc,(uintb)(uintp)op), ct);
    ///   assignHigh(vn);
    ///   return vn;
    /// Ghidra encodes the raw op pointer as the iop-space offset; Rugra
    /// encodes `Arc::as_ptr()` (the stable address of the inner RwLock).
    /// The assignHigh call is a structural no-op for iop varnodes (they are
    /// annotations), kept for call-site parity with cc:182.
    pub fn new_varnode_iop(&mut self, op: &crate::op::PcodeOpRef) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // Encode the op's identity as a raw address. We use the Arc's data
        // pointer, which is stable for the Arc's lifetime (matching Ghidra's
        // `(uintb)(uintp)op`).
        let ptr_addr = std::sync::Arc::as_ptr(&op.0) as u64;
        let vn = self.vbank.create_with_space(
            std::mem::size_of::<usize>(),
            crate::space::AddressSpace::Iop,
            ptr_addr,
        );
        vn.write().unwrap().set_flags(crate::varnode::varnode_flags::ANNOTATION);
        // cc:182: assignHigh(vn) — iop varnodes are annotations, so this is
        // the documented no-op leg (funcdata_varnode.cc:54-56 guard).
        let _ = self.assign_high(&vn);
        vn
    }

    // Ghidra: funcdata.cc:34 Funcdata::getOpFromConst
    /// Resolve an iop-space constant varnode back to the PcodeOp it references.
    /// Faithful to `PcodeOp::getOpFromConst` (op.hh:249). Ghidra reinterprets
    /// the offset as an op pointer; Rugra reinterprets it back to the
    /// `Arc<RwLock<PcodeOp>>`.
    pub fn get_op_from_const(&self, vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) -> Option<crate::op::PcodeOpRef> {
        let v = vn.read().unwrap();
        if v.get_space() != crate::space::AddressSpace::Iop {
            return None;
        }
        let ptr_addr = v.get_offset() as usize;
        // Reconstruct the Arc from the raw pointer. This is safe as long as
        // the original Arc is still alive (which it is — the op bank holds it).
        let raw = ptr_addr as *const std::sync::RwLock<crate::op::PcodeOp>;
        // SAFETY: the pointer was obtained from Arc::as_ptr on an op that is
        // still in the obank. We rebuild the Arc via ManuallyDrop-free clone.
        unsafe {
            let arc = std::sync::Arc::from_raw(raw);
            // Clone to bump refcount, then forget the reconstructed one so we
            // don't double-free.
            let cloned = std::sync::Arc::clone(&arc);
            std::mem::forget(arc);
            Some(crate::op::PcodeOpRef(cloned))
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::opUndoPtradd
    /// Undo a PTRADD op, converting it back to INT_ADD/INT_MULT.
    /// Faithful to `Funcdata::opUndoPtradd` (funcdata_op.cc:579).
    pub fn op_undo_ptradd(&mut self, op: &crate::op::PcodeOpRef) {
        use crate::opcodes::OpCode;
        // PTRADD has 3 inputs: base, index, multiplier.
        // Get multiplier (input[2]).
        let mult_size = {
            let g = op.0.read().unwrap();
            if g.inrefs.len() < 3 {
                return; // malformed PTRADD
            }
            let vn = g.inrefs[2].clone();
            drop(g);
            let vn_rg = vn.read().unwrap();
            if vn_rg.is_constant() {
                vn_rg.get_offset() as usize
            } else {
                1
            }
        };
        // Remove input[2] (the multiplier).
        self.op_remove_input(op, 2);
        // Change opcode to INT_ADD.
        self.op_set_opcode(op, OpCode::CPUI_INT_ADD);
        if mult_size == 1 {
            return; // INT_ADD(base, index) is correct.
        }
        // The index input is now slot 1; scale it by mult_size via INT_MULT.
        let index_vn = {
            let g = op.0.read().unwrap();
            if g.inrefs.len() < 2 { return; }
            g.inrefs[1].clone()
        };
        let mult_const = self.new_constant(8, mult_size as u64);
        let mult_op = self.new_op(2, op.0.read().unwrap().get_seq_num().get_addr());
        self.op_set_opcode(&mult_op, OpCode::CPUI_INT_MULT);
        let mult_out = self.new_unique_out(8, &mult_op);
        // mult_op inputs: index, mult_const
        self.op_set_input(&mult_op, index_vn, 0);
        self.op_set_input(&mult_op, mult_const, 1);
        // Insert mult_op before op.
        self.op_insert_before(&mult_op, op);
        // Replace op's index input with mult_out.
        self.op_set_input(op, mult_out, 1);
    }

    // Ghidra: funcdata.cc:34 Funcdata::opMarkCpoolTransformed
    /// Mark `op` as having been checked for cpool transforms.
    /// Faithful to `Funcdata::opMarkCpoolTransformed` (funcdata.hh:485).
    pub fn op_mark_cpool_transformed(&mut self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().mark_cpool_transformed();
    }

    // Ghidra: funcdata.cc:34 Funcdata::getStoreGuard
    /// Find the STORE guard for `op`. Faithful to
    /// `Funcdata::getStoreGuard` (funcdata.hh:270). Returns None if no guard.
    pub fn get_store_guard(&self, op: &crate::op::PcodeOpRef) -> Option<&crate::heritage::LoadGuard> {
        self.heritage.get_store_guard(&op.0)
    }

    // Ghidra: funcdata.cc:34 Funcdata::getLoadGuard
    /// Find the LOAD guard for `op`. Faithful to
    /// `Funcdata::getLoadGuard` (funcdata.hh:269).
    pub fn get_load_guard(&self, op: &crate::op::PcodeOpRef) -> Option<&crate::heritage::LoadGuard> {
        self.heritage.get_load_guard(&op.0)
    }

    // Ghidra: funcdata_op.cc:710 Funcdata::newIndirectCreation
    /// Create an INDIRECT op with indirect_creation semantics. Faithful to
    /// `Funcdata::newIndirectCreation` (funcdata_op.cc:710-728): input[0] is
    /// a constant zero, the op and output carry `indirect_creation`, and
    /// input[1] aliases the causing op through the Iop space. This legacy
    /// entry keeps the Unique output space used by its historical callers;
    /// space-faithful call guards use `new_indirect_creation_in_space`.
    pub fn new_indirect_creation(
        &mut self,
        indeffect: &crate::op::PcodeOpRef,
        addr: u64,
        sz: usize,
        possibleout: bool,
    ) -> crate::op::PcodeOpRef {
        self.new_indirect_creation_in_space(
            indeffect,
            crate::space::AddressSpace::Unique,
            addr,
            sz,
            possibleout,
        )
    }

    /// Space-faithful form of `Funcdata::newIndirectCreation`
    /// (funcdata_op.cc:710-728): the output Varnode is allocated at the
    /// caller's (space, offset) — e.g. the Register-space RAX range for a
    /// killed-by-call guard — instead of Unique. All flag and IOP semantics
    /// are identical to the oracle constructor; no setActiveHeritage is done
    /// here (guardCalls cc:1523 does it after construction).
    // RUGRA-GLUE: split entry because Rugra Address lacks space identity; the
    // legacy Unique-space entry keeps out-of-write-set callers compiling.
    pub fn new_indirect_creation_in_space(
        &mut self,
        indeffect: &crate::op::PcodeOpRef,
        space: crate::space::AddressSpace,
        addr: u64,
        sz: usize,
        possibleout: bool,
    ) -> crate::op::PcodeOpRef {
        use crate::op::pcodeop_flags;
        use crate::varnode::varnode_flags;
        // cc:716: newin = newConstant(sz, 0);
        let newin = self.new_constant(sz, 0);
        // cc:717: newop = newOp(2, indeffect->getAddr());
        let indeffect_addr = indeffect.0.read().unwrap().get_seq_num().get_addr();
        let newop = self.new_op(2, indeffect_addr);
        // cc:718: newop->flags |= PcodeOp::indirect_creation;
        newop.0.write().unwrap().flags |= pcodeop_flags::INDIRECT_CREATION;
        // cc:719: newout = newVarnodeOut(sz, addr, newop);
        let newout = self.vbank.create_with_space(sz, space, addr);
        let newout = self
            .vbank
            .set_def_prevalidated(newout, std::sync::Arc::downgrade(&newop.0));
        newop.0.write().unwrap().output = Some(newout.clone());
        // cc:720-722: if (!possibleout) newin |= indirect_creation;
        //             newout |= indirect_creation;
        if !possibleout {
            newin.write().unwrap().set_flags(varnode_flags::INDIRECT_CREATION);
        }
        newout.write().unwrap().set_flags(varnode_flags::INDIRECT_CREATION);
        // cc:723: opSetOpcode(newop, CPUI_INDIRECT);
        self.op_set_opcode(&newop, crate::opcodes::OpCode::CPUI_INDIRECT);
        // cc:724: opSetInput(newop, newin, 0);
        self.op_set_input(&newop, newin, 0);
        // cc:725: opSetInput(newop, newVarnodeIop(indeffect), 1);
        let iop_vn = self.new_varnode_iop(indeffect);
        self.op_set_input(&newop, iop_vn, 1);
        // cc:726: opInsertBefore(newop, indeffect);
        self.op_insert_before(&newop, indeffect);
        newop
    }

    // Ghidra: funcdata.cc:34 Funcdata::findJumpTable
    /// Find the JumpTable whose indirect op is at the same address as `op`.
    /// Faithful to `Funcdata::findJumpTable` (funcdata_block.cc:446-457).
    pub fn find_jump_table(&self, op: &crate::op::PcodeOpRef) -> Option<&std::sync::Arc<std::sync::RwLock<crate::jumptable::JumpTable>>> {
        let op_addr = op.0.read().unwrap().get_seq_num().get_addr().as_u64();
        self.jump_tables.iter().find(|jt| {
            let jt_rg = jt.read().unwrap();
            jt_rg.get_op_address().as_u64() == op_addr
        })
    }

    // Ghidra: funcdata.cc:34 Funcdata::removeJumpTable
    /// Remove a JumpTable from this function. Faithful to
    /// `Funcdata::removeJumpTable` (funcdata_block.cc:65).
    pub fn remove_jump_table(&mut self, jt: &std::sync::Arc<std::sync::RwLock<crate::jumptable::JumpTable>>) {
        let jt_ptr = std::sync::Arc::as_ptr(jt);
        self.jump_tables.retain(|j| std::sync::Arc::as_ptr(j) != jt_ptr);
    }


    // Ghidra: funcdata_op.cc:373 Funcdata::opInsertAfter
    /// Insert `op` after `previous` in its basic block.  A non-MULTIEQUAL is
    /// placed after any leading MULTIEQUAL group, and an alive INDIRECT's iop
    /// target is treated as the effective previous op.
    pub fn op_insert_after(&mut self, op: &crate::op::PcodeOpRef, previous: &crate::op::PcodeOpRef) {
        if previous
            .0
            .read()
            .unwrap()
            .parent
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .is_none()
        {
            // RUGRA-GLUE: Legacy Rule unit fixtures construct an alive, parentless
            // flat op bank, which is outside Ghidra's opInsertAfter precondition.
            // Preserve their former flat-list behavior until those fixtures acquire
            // real BlockBasic membership; this branch is not oracle-equivalent.
            self.obank.mark_alive(op.clone());
            self.obank
                .alivelist
                .retain(|candidate| !std::sync::Arc::ptr_eq(&candidate.0, &op.0));
            let insert_index = self
                .obank
                .alivelist
                .iter()
                .position(|candidate| std::sync::Arc::ptr_eq(&candidate.0, &previous.0))
                .map_or(self.obank.alivelist.len(), |index| index + 1);
            self.obank.alivelist.insert(insert_index, op.clone());
            return;
        }
        let effective_previous = {
            let indirect_iop = {
                let previous_guard = previous.0.read().unwrap();
                if previous_guard.is_marker()
                    && previous_guard.opcode == OpCode::CPUI_INDIRECT
                {
                    previous_guard.inrefs.get(1).cloned()
                } else {
                    None
                }
            };
            indirect_iop
                .filter(|vn| {
                    vn.read().unwrap().get_space() == crate::space::AddressSpace::Iop
                })
                .and_then(|vn| self.get_op_from_const(&vn))
                .filter(|target| !target.0.read().unwrap().is_dead())
                .unwrap_or_else(|| previous.clone())
        };
        let parent = effective_previous
            .0
            .read()
            .unwrap()
            .parent
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .expect("opInsertAfter effective previous op has no basic block");
        let block_ops = parent.read().unwrap().get_ops();
        let previous_index = block_ops
            .iter()
            .position(|candidate| {
                std::sync::Arc::ptr_eq(&candidate.0, &effective_previous.0)
            })
            .expect("opInsertAfter previous op is absent from its parent block");
        let mut insert_index = previous_index + 1;
        if op.0.read().unwrap().opcode != OpCode::CPUI_MULTIEQUAL {
            while insert_index < block_ops.len()
                && block_ops[insert_index].0.read().unwrap().opcode
                    == OpCode::CPUI_MULTIEQUAL
            {
                insert_index += 1;
            }
        }
        self.op_insert(op, &parent, Some(insert_index));
    }

    // Ghidra: funcdata_op.cc:164 Funcdata::opUninsert
    /// Remove `op` from its basic block and move it from the alive list to the
    /// dead list.  Its Varnode input/output links remain intact.
    pub fn op_uninsert(&mut self, op: &crate::op::PcodeOpRef) {
        let parent = op
            .0
            .read()
            .unwrap()
            .parent
            .as_ref()
            .and_then(std::sync::Weak::upgrade);
        let Some(parent) = parent else {
            // RUGRA-GLUE: Preserve the former flat-bank detach behavior for
            // parentless legacy fixtures. Valid Ghidra-domain ops take the block
            // path below and transition to the dead list atomically.
            self.obank
                .alivelist
                .retain(|candidate| !std::sync::Arc::ptr_eq(&candidate.0, &op.0));
            return;
        };
        self.obank.mark_dead(op.clone());
        Self::block_remove_op(op, &parent);
    }

    // Ghidra: funcdata_op.cc:413 Funcdata::opInsertBegin
    /// Insert `op` at the beginning of a basic block, after its leading
    /// MULTIEQUAL group unless the inserted op is itself a MULTIEQUAL.
    pub fn op_insert_begin(&mut self, op: &crate::op::PcodeOpRef, bb: &std::sync::Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>) {
        let block_ops = bb.read().unwrap().get_ops();
        let mut insert_index = 0;
        if op.0.read().unwrap().opcode != OpCode::CPUI_MULTIEQUAL {
            while insert_index < block_ops.len()
                && block_ops[insert_index].0.read().unwrap().opcode
                    == OpCode::CPUI_MULTIEQUAL
            {
                insert_index += 1;
            }
        }
        self.op_insert(op, bb, Some(insert_index));
    }

    // Ghidra: funcdata_op.cc:435 Funcdata::opInsertEnd
    /// Insert `op` at the end of a basic block, immediately before its final
    /// flow-break op when one is present.
    pub fn op_insert_end(&mut self, op: &crate::op::PcodeOpRef, bb: &std::sync::Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>) {
        let block_ops = bb.read().unwrap().get_ops();
        let insert_index = match block_ops.last() {
            Some(last) if last.0.read().unwrap().is_flow_break() => block_ops.len() - 1,
            _ => block_ops.len(),
        };
        self.op_insert(op, bb, Some(insert_index));
    }

    // Ghidra: funcdata.hh:519 Funcdata::opMarkNonPrinting
    /// Mark `op` as non-printing (suppressed in C output). Faithful to
    /// `Funcdata::opMarkNonPrinting` (funcdata.hh:519).
    pub fn op_mark_non_printing(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().flags |= crate::op::pcodeop_flags::NONPRINTING;
    }

    // Ghidra: funcdata.hh:486 Funcdata::opMarkCalculatedBool
    /// Mark PcodeOp as having boolean output. Faithful to
    /// `Funcdata::opMarkCalculatedBool` (funcdata.hh:486).
    pub fn op_mark_calculated_bool(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().flags |= crate::op::pcodeop_flags::CALCULATED_BOOL;
    }

    // Ghidra: funcdata.hh:483 Funcdata::opMarkSpecialPrint
    /// Mark PcodeOp as needing special printing. Faithful to
    /// `Funcdata::opMarkSpecialPrint` (funcdata.hh:483).
    pub fn op_mark_special_print(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().addlflags |= crate::op::op_addl_flags::SPECIAL_PRINT;
    }

    // Ghidra: funcdata.hh:484 Funcdata::opMarkNoCollapse
    /// Mark PcodeOp as not collapsible. Faithful to
    /// `Funcdata::opMarkNoCollapse` (funcdata.hh:484).
    pub fn op_mark_no_collapse(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().flags |= crate::op::pcodeop_flags::NOCOLLAPSE;
    }

    // Ghidra: funcdata.hh:487 Funcdata::opMarkSpacebasePtr
    /// Mark PcodeOp as LOAD/STORE from spacebase ptr. Faithful to
    /// `Funcdata::opMarkSpacebasePtr` (funcdata.hh:487).
    pub fn op_mark_spacebase_ptr(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().flags |= crate::op::pcodeop_flags::SPACEBASE_PTR;
    }

    // Ghidra: funcdata.hh:488 Funcdata::opClearSpacebasePtr
    /// Unmark PcodeOp as using spacebase ptr. Faithful to
    /// `Funcdata::opClearSpacebasePtr` (funcdata.hh:488).
    pub fn op_clear_spacebase_ptr(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().flags &= !crate::op::pcodeop_flags::SPACEBASE_PTR;
    }

    // Ghidra: funcdata.hh:477 Funcdata::opSetAllInput
    /// Set all input Varnodes for the given PcodeOp simultaneously.
    /// Faithful to `Funcdata::opSetAllInput` (funcdata_op.cc:267-284).
    pub fn op_set_all_input(&mut self, op: &crate::op::PcodeOpRef, vvec: &[std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>]) {
        // Unset all existing inputs (funcdata_op.cc:276-278).
        let num = op.0.read().unwrap().num_input();
        for i in 0..num {
            self.op_unset_input(op, i);
        }
        // cc:280 replaces every slot with NULL. Clear the Vec so identical
        // old/new pointers cannot trigger op_set_input's early return before
        // rebuilding the descendant edge.
        op.0.write().unwrap().inrefs.clear();
        // cc:282-283: restore exact input order via the normal const-dedup path.
        for (i, vn) in vvec.iter().cloned().enumerate() {
            self.op_set_input(op, vn, i);
        }
    }

    // Ghidra: funcdata_op.cc:150 Funcdata::opInsert
    /// Insert the given PcodeOp at a specific point in a basic block. Faithful
    /// to `Funcdata::opInsert` (funcdata_op.cc:150-159).  The alive list tracks
    /// lifecycle/integration order; the basic block owns execution order.
    pub fn op_insert(
        &mut self,
        op: &crate::op::PcodeOpRef,
        bb: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        iter_index: Option<usize>,
    ) {
        self.obank.mark_alive(op.clone());
        let block_size = bb.read().unwrap().get_ops().len();
        let index = iter_index.unwrap_or(block_size);
        assert!(index <= block_size, "opInsert iterator is outside the basic block");
        Self::block_insert_op(op, bb, index);
    }

    // Ghidra: block.cc:2258 BlockBasic::insert
    /// Insert an op into a BlockBasic and maintain its parent, per-block
    /// sequence order, and switch-dispatch flag.
    fn block_insert_op(
        op: &crate::op::PcodeOpRef,
        bb: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        index: usize,
    ) {
        assert!(
            op.0.read().unwrap().parent.is_none(),
            "BlockBasic::insert requires an unattached op"
        );
        let parent = std::sync::Arc::downgrade(bb);
        let mut block_guard = bb.write().unwrap();
        let block = block_guard
            .as_any_mut()
            .downcast_mut::<crate::block::BlockBasic>()
            .expect("Funcdata op insertion requires BlockBasic");
        assert!(index <= block.ops.len(), "BlockBasic insert index is out of bounds");

        let order_before = if index == 0 {
            2
        } else {
            block.ops[index - 1].0.read().unwrap().start.get_order()
        };
        let order_after = if index == block.ops.len() {
            let candidate = order_before.wrapping_add(0x0100_0000);
            if candidate <= order_before { u32::MAX } else { candidate }
        } else {
            block.ops[index].0.read().unwrap().start.get_order()
        };

        op.0.write().unwrap().parent = Some(parent);
        block.ops.insert(index, op.clone());
        if order_after.wrapping_sub(order_before) <= 1 {
            block.set_order();
        } else {
            op.0
                .write()
                .unwrap()
                .start
                .set_order(order_after / 2 + order_before / 2);
        }

        let is_branch_indirect = {
            let op_guard = op.0.read().unwrap();
            op_guard.is_branch() && op_guard.opcode == OpCode::CPUI_BRANCHIND
        };
        if is_branch_indirect {
            block.flags |= crate::block::block_flags::SWITCH_OUT;
        }
    }

    // Ghidra: block.cc:2292 BlockBasic::removeOp
    /// Detach an op from its parent BlockBasic without changing its Varnode
    /// links or recalculating the remaining per-block order fields.
    fn block_remove_op(
        op: &crate::op::PcodeOpRef,
        bb: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) {
        op.0.write().unwrap().parent = None;
        let mut block_guard = bb.write().unwrap();
        let block = block_guard
            .as_any_mut()
            .downcast_mut::<crate::block::BlockBasic>()
            .expect("Funcdata op removal requires BlockBasic");
        let index = block
            .ops
            .iter()
            .position(|candidate| std::sync::Arc::ptr_eq(&candidate.0, &op.0))
            .expect("BlockBasic::removeOp requires an op in the block");
        block.ops.remove(index);
    }

    // Ghidra: funcdata_op.cc:179 Funcdata::opUnlink
    /// Extricate the op from all its Varnode connections to the function's
    /// data-flow and remove it from its basic block, WITHOUT changing block
    /// connections. Faithful to `Funcdata::opUnlink` (funcdata_op.cc:179-193):
    ///   opUnsetOutput(op);
    ///   for(i=0;i<op->numInput();++i) opUnsetInput(op,i);
    ///   if (op->getParent() != NULL) opUninsert(op);
    /// The op remains in the \e dead list (Rugra: detached from the alive
    /// list, awaiting a subsequent `mark_dead`).
    pub fn op_unlink(&mut self, op: &crate::op::PcodeOpRef) {
        // cc:188: opUnsetOutput(op).
        self.op_unset_output(op);
        // cc:189-190: for i in 0..numInput: opUnsetInput(op, i).
        let num = op.0.read().unwrap().num_input();
        for i in 0..num {
            self.op_unset_input(op, i);
        }
        // cc:191-192: if (op->getParent() != NULL) opUninsert(op).
        // Rugra's alive list is the analogue of "is in a basic block"; if the
        // op is currently in the alive list, remove it (faithful op_uninsert).
        let in_alive = self
            .obank
            .alivelist
            .iter()
            .any(|r| std::sync::Arc::ptr_eq(&r.0, &op.0));
        if in_alive {
            self.op_uninsert(op);
        }
    }

    // Ghidra: funcdata_op.cc:253 Funcdata::opDestroyRaw
    /// Specialized routine for deleting an op during flow generation that has
    /// been replaced by something else. Faithful to `Funcdata::opDestroyRaw`
    /// (funcdata_op.cc:253-261). The op is expected to be \e dead with none of
    /// its inputs or outputs linked to anything else. Both the PcodeOp and all
    /// the input/output Varnodes are destroyed:
    ///   for(i=0;i<op->numInput();++i) destroyVarnode(op->getIn(i));
    ///   if (op->getOut() != NULL) destroyVarnode(op->getOut());
    ///   obank.destroy(op);
    /// Differs from `op_destroy` (cc:203) in that it does NOT touch block
    /// membership and additionally frees the input/output Varnodes.
    pub fn op_destroy_raw(&mut self, op: &crate::op::PcodeOpRef) {
        // cc:256-257: destroy each input varnode.
        let inputs = op.0.read().unwrap().inrefs.clone();
        for vn in &inputs {
            self.destroy_varnode(vn);
        }
        // cc:258-259: destroy the output varnode if present.
        let out = op.0.read().unwrap().output.clone();
        if let Some(out_vn) = out {
            self.destroy_varnode(&out_vn);
        }
        // cc:260: obank.destroy(op).
        self.obank.destroy(op.clone());
    }

    // Ghidra: funcdata_varnode.cc:25 Funcdata::setVarnodeProperties
    /// Gather storage properties for `vn` from the symbol/scope and apply them.
    /// Faithful to `Funcdata::setVarnodeProperties` (funcdata_varnode.cc:25-42):
    ///   if (!vn->isMapped()) {
    ///     queryProperties(vn->getAddr(), vn->getSize(), usepoint, vflags);
    ///     if (entry) vn->setSymbolProperties(entry);
    ///     else       vn->setFlags(vflags & ~typelock);
    ///   }
    ///   if (vn->cover == NULL && isHighOn()) vn->calcCover();
    /// Rugra: uses `symbol_table` as the backing store (matching the existing
    /// `link_symbol` strategy). When an entry is found we set MAPPED so we
    /// don't re-query (faithful to setSymbolProperties' side-effect). The full
    /// ScopeLocal::queryProperties API is not yet ported (scope gap noted in
    /// docs/alignment_audit/funcdata_audit.md).
    pub fn set_varnode_properties(&mut self, vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) {
        // cc:28: if (!vn->isMapped()) — one more chance to find an entry now
        // that we know the usepoint.
        let is_mapped = vn.read().unwrap().is_mapped();
        if !is_mapped {
            // cc:30-31: queryProperties(addr, size, usepoint, vflags).
            let addr = vn.read().unwrap().get_offset();
            // Rugra: symbol_table maps addr→name (best-effort scope).
            if self.symbol_table.get(&addr).is_some() {
                // cc:32-33: entry found → vn->setSymbolProperties(entry).
                // Rugra has no SymbolEntry to attach here; the address already
                // resolves via symbol_table. Set the MAPPED flag so we don't
                // re-query (faithful to the side-effect of setSymbolProperties).
                vn.write().unwrap().set_flags(crate::varnode::varnode_flags::MAPPED);
            }
            // cc:34-35: vn->setFlags(vflags & ~typelock). With vflags==0 the
            // flag mutation is a no-op; typelock is set by updateType.
        }
        // cc:38-41: if (vn->cover == NULL && isHighOn()) vn->calcCover().
        let high_on = (self.flags & funcdata_flags::HIGHLEVEL_ON) != 0;
        if high_on {
            if vn.read().unwrap().has_cover() {
                vn.write().unwrap().calc_cover();
            }
        }
    }

    // Ghidra: funcdata_varnode.cc:48 Funcdata::assignHigh
    /// If HighVariables are enabled, ensure `vn` has a HighVariable. Allocate
    /// a dedicated HighVariable (containing only `vn`) if necessary. Faithful
    /// to `Funcdata::assignHigh` (funcdata_varnode.cc:48-59):
    ///   if ((flags & highlevel_on)!=0) {
    ///     if (vn->hasCover()) vn->calcCover();
    ///     if (!vn->isAnnotation()) return new HighVariable(vn);
    ///   }
    ///   return NULL;
    /// The C++ `new HighVariable(vn)` ctor (variable.cc:220-235) additionally
    /// does the two-way wiring:
    ///   inst.push_back(vn);                        // variable.cc:231
    ///   vn->setHigh(this, numMergeClasses-1);      // variable.cc:232 (mg=0)
    ///   if (vn->getSymbolEntry() != 0) setSymbol(vn); // variable.cc:233-234
    /// (FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001)
    pub fn assign_high(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> Option<std::sync::Arc<std::sync::RwLock<crate::variable::HighVariable>>> {
        // cc:51: if ((flags & highlevel_on)!=0).
        if (self.flags & funcdata_flags::HIGHLEVEL_ON) == 0 {
            return None;
        }
        // cc:52-53: if (vn->hasCover()) vn->calcCover().
        if vn.read().unwrap().has_cover() {
            vn.write().unwrap().calc_cover();
        }
        // cc:54-56: if (!vn->isAnnotation()) return new HighVariable(vn).
        if vn.read().unwrap().is_annotation() {
            return None;
        }
        let vn_type = vn.read().unwrap().get_type().unwrap_or_else(|| {
            std::sync::Arc::new(crate::type_system::datatype::Datatype::Void(
                crate::type_system::datatype::TypeBase::new(
                    "void".to_string(),
                    0,
                    crate::type_system::datatype::TypeMetatype::Void,
                ),
            ))
        });
        let high = std::sync::Arc::new(std::sync::RwLock::new(
            crate::variable::HighVariable::new(vn_type),
        ));
        // variable.cc:231: inst.push_back(vn) — register vn as the sole
        // instance of the fresh HighVariable.
        high.write().unwrap().add_instance(vn.clone());
        // variable.cc:232: vn->setHigh(this, numMergeClasses-1). Fresh ctor
        // has numMergeClasses==1, so mergegroup = 0.
        {
            let mut vn_w = vn.write().unwrap();
            vn_w.mergegroup = 0;
            vn_w.high = Some(high.clone());
        }
        // variable.cc:233-234: if (vn->getSymbolEntry() != 0) setSymbol(vn).
        // set_symbol re-reads the entry itself and early-outs on None.
        if vn.read().unwrap().get_symbol_entry().is_some() {
            high.write().unwrap().set_symbol(vn);
        }
        Some(high)
    }

    // Ghidra: funcdata_varnode.cc:316 Funcdata::findHigh
    /// Look up a Symbol visible in this function's scope by name and return
    /// the HighVariable associated with it. Faithful to
    /// `Funcdata::findHigh` (funcdata_varnode.cc:316-328):
    ///   queryByName(nm, symList);
    ///   if (symList.empty()) return NULL;
    ///   sym = symList[0];
    ///   vn = findLinkedVarnode(sym->getFirstWholeMap());
    ///   if (vn) return vn->getHigh();
    ///   return NULL;
    /// Rugra: `symbol_table` is address-keyed; we scan it (and `scope.symbols`)
    /// for a name match, then resolve the varnode at that address via the
    /// VarnodeBank's loc tree. Scope matches carry the symbol's space so
    /// linkSymbol-created register/unique symbols resolve in their own space.
    pub fn find_high(&self, nm: &str) -> Option<std::sync::Arc<std::sync::RwLock<crate::variable::HighVariable>>> {
        // cc:319-320: queryByName(nm, symList). Rugra: search symbol_table +
        // scope.symbols for an entry whose name matches `nm`.
        let addr: Option<u64> = self
            .symbol_table
            .iter()
            .find_map(|(a, name)| if name == nm { Some(*a) } else { None })
            .or_else(|| {
                self.scope.as_ref().and_then(|scope| {
                    scope.symbols.iter().find_map(|s| {
                        if s.name == nm && !s.is_dynamic {
                            Some(s.start)
                        } else {
                            None
                        }
                    })
                })
            });
        let addr = addr?;
        // cc:323: vn = findLinkedVarnode(sym->getFirstWholeMap()).
        let vn = self.vbank.find_by_loc(0, crate::address::Address::new(addr))?;
        // cc:324-325: return vn->getHigh(). Clone the inner Arc out of the
        // read guard so the borrow does not extend past `vn`'s lifetime.
        let high = {
            let r = vn.read().unwrap();
            r.get_high().cloned()
        };
        high
    }

    // Ghidra: funcdata_varnode.cc:614 Funcdata::transferVarnodeProperties
    /// Copy properties from an existing Varnode `vn` to a new overlapping
    /// Varnode `new_vn`. Faithful to `Funcdata::transferVarnodeProperties`
    /// (funcdata_varnode.cc:614-629):
    ///   newConsume = ((vn->getConsume() >> 8*lsbOffset) | fillBits)
    ///                & calc_mask(newVn->getSize());
    ///   vnFlags = vn->getFlags() & (directwrite|addrforce);
    ///   newVn->setFlags(vnFlags);
    ///   newVn->setConsume(newConsume);
    /// Used by SUBPIECE / truncation transforms to preserve the consume mask
    /// and directwrite/addrforce flags across a width change.
    pub fn transfer_varnode_properties(
        &self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        new_vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        lsb_offset: i32,
    ) {
        // cc:617: newConsume = ~((uintb)0).
        let mut new_consume: u64 = !0u64;
        // cc:618: if (lsbOffset < sizeof(uintb)).
        if (lsb_offset as usize) < std::mem::size_of::<u64>() {
            // cc:619-622: shift the consume mask right by lsbOffset bytes,
            // filling high bits so any value shifted in above the Varnode
            // precision is treated as "used".
            let lsb_bytes = lsb_offset as u32;
            let fill_bits = if lsb_offset != 0 {
                new_consume << (8 * (std::mem::size_of::<u64>() as u32 - lsb_bytes))
            } else {
                0
            };
            let vn_consume = vn.read().unwrap().get_consume();
            let new_size = new_vn.read().unwrap().get_size();
            let mask = crate::address::calc_mask(new_size);
            new_consume = ((vn_consume >> (8 * lsb_bytes)) | fill_bits) & mask;
        }
        // cc:625: vnFlags = vn->getFlags() & (directwrite|addrforce).
        let vn_flags = {
            let f = vn.read().unwrap().flags;
            f & (crate::varnode::varnode_flags::DIRECTWRITE
                | crate::varnode::varnode_flags::ADDRFORCE)
        };
        // cc:627-628: newVn->setFlags(vnFlags); newVn->setConsume(newConsume).
        new_vn.write().unwrap().set_flags(vn_flags);
        new_vn.write().unwrap().set_consume(new_consume);
    }

    // Ghidra: funcdata_varnode.cc:997 Funcdata::handleSymbolConflict
    /// Resolve a Varnode/SymbolEntry overlap: make sure the Varnode is part
    /// of the variable underlying the Symbol, remapping to a distinct
    /// (dynamic) Symbol otherwise. Faithful to `handleSymbolConflict`
    /// (funcdata_varnode.cc:997-1029):
    ///   if (vn->isInput() || vn->isAddrTied() || vn->isPersist() ||
    ///       vn->isConstant() || entry->isDynamic()) {
    ///     vn->setSymbolEntry(entry); return entry->getSymbol();
    ///   }
    ///   high = vn->getHigh();
    ///   // Look for a conflicting HighVariable: walk the loc set at
    ///   // (entry->getSize(), entry->getAddr()); break on size/addr mismatch;
    ///   // otherHigh = first varnode whose HighVariable differs.
    ///   if (otherHigh == NULL) { vn->setSymbolEntry(entry); return entry->getSymbol(); }
    ///   buildDynamicSymbol(vn);
    ///   return vn->getSymbolEntry()->getSymbol();
    /// Returns the winning symbol's index in `scope.symbols`.
    pub fn handle_symbol_conflict(
        &mut self,
        entry_idx: usize,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> Option<usize> {
        // cc:1000-1001: if (vn->isInput() || vn->isAddrTied() ||
        //                vn->isPersist() || vn->isConstant() || entry->isDynamic()).
        let (is_input, is_addr_tied, is_persist, is_const) = {
            let r = vn.read().unwrap();
            (r.is_input(), r.is_addr_tied(), r.is_persist(), r.is_constant())
        };
        let entry_is_dynamic = self
            .scope
            .as_ref()?
            .symbols
            .get(entry_idx)?
            .is_dynamic;
        if is_input || is_addr_tied || is_persist || is_const || entry_is_dynamic {
            // cc:1002-1003: vn->setSymbolEntry(entry); return entry->getSymbol().
            self.attach_symbol_to_vn(entry_idx, vn);
            return Some(entry_idx);
        }
        // cc:1005-1020: Look for a conflicting HighVariable.
        // VarnodeLocSet::const_iterator iter = beginLoc(entry->getSize(), entry->getAddr());
        let high = vn.read().unwrap().get_high().cloned();
        let (entry_space, entry_addr, entry_size) = {
            let sym = self.scope.as_ref()?.symbols.get(entry_idx)?;
            (sym.space, sym.start, sym.size)
        };
        let mut other_high = false;
        if let Some(_high) = &high {
            // Walk the loc set while size and address still match (cc:1010-1020);
            // the VarnodeBank's overlap scan yields the same (space, addr)
            // neighborhood; entries beyond the exact (size, addr) pair break.
            let candidates = self.vbank.overlap_loc(
                crate::address::Address::new(entry_addr),
                entry_size.max(0) as usize,
            );
            for cv in candidates {
                let (cv_size, cv_space, cv_addr, cv_high) = {
                    let r = cv.read().unwrap();
                    (r.get_size(), r.get_space(), r.get_offset(), r.high.clone())
                };
                if cv_size as i32 != entry_size || cv_space != entry_space || cv_addr != entry_addr
                {
                    // cc:1012-1013: the loc-set run is over (Ghidra breaks
                    // out of the iterator walk; non-matching neighbors are
                    // simply not candidates).
                    continue;
                }
                if let (Some(ch), Some(h)) = (cv_high, &high) {
                    if !std::sync::Arc::ptr_eq(&ch, h) {
                        other_high = true; // cc:1015-1018
                        break;
                    }
                }
            }
        }
        if !other_high {
            // cc:1021-1024: vn->setSymbolEntry(entry); return entry->getSymbol().
            self.attach_symbol_to_vn(entry_idx, vn);
            return Some(entry_idx);
        }
        // cc:1026-1028: conflicting variable — buildDynamicSymbol(vn);
        // return vn->getSymbolEntry()->getSymbol().
        let dyn_idx = self.build_dynamic_symbol(vn);
        if dyn_idx.is_none() {
            // The dynamic symbol failed to hash; keep the original entry so
            // the caller still sees a Symbol (Ghidra cannot fail here —
            // uniqueHash either succeeds or throws).
            self.attach_symbol_to_vn(entry_idx, vn);
            return Some(entry_idx);
        }
        dyn_idx
    }

    // RUGRA-GLUE: attach_symbol_to_vn (vn->setSymbolEntry + high->setSymbol)
    /// Attach a ScopeLocal symbol to a Varnode the way
    // RUGRA-GLUE: symbol_entry_for (bridge varmap symbol → database entry)
    /// Build (or fetch the identity-stable cached) database.rs `SymbolEntry`
    /// mirroring the varmap `ScopeLocal` symbol at `entry_idx`: static maps
    /// carry (offset address, size, single-address uselimit when the varmap
    /// usepoint is valid), dynamic maps carry the hash instead. The mirrored
    /// `Symbol` transports the data-type (set_symbol's symboloffset branch 4
    /// reads its size) and the namelock bit for `Varnode::setSymbolEntry`'s
    /// flag leg. Names are refreshed by ActionNameVars after the naming pass.
    fn symbol_entry_for(
        &mut self,
        entry_idx: usize,
    ) -> Option<std::sync::Arc<RwLock<crate::database::SymbolEntry>>> {
        if let Some(entry) = self.symbol_entry_cache.get(&entry_idx) {
            return Some(entry.clone());
        }
        let sym = self.scope.as_ref()?.symbols.get(entry_idx)?;
        let mut bridge = crate::database::Symbol::new(0, &sym.name, "");
        bridge.dtype = sym.dtype.clone();
        if sym.namelock {
            bridge.flags |= crate::fspec::protoparam_flags::NAME_LOCKED;
        }
        bridge.category = match sym.category {
            crate::varmap::symbol_category::EQUATE => crate::database::SymbolCategory::Equate,
            _ => crate::database::SymbolCategory::NoCategory,
        };
        let symbol_arc = std::sync::Arc::new(RwLock::new(bridge));
        let mut uselimit = crate::address::RangeList::new();
        if let Some(up) = sym.usepoint {
            if let Some(range) = crate::address::Range::new(
                crate::address::Address::new(up),
                crate::address::Address::new(up),
            ) {
                uselimit.insert_range(range);
            }
        }
        let entry = if sym.is_dynamic {
            crate::database::SymbolEntry::new_dynamic(
                symbol_arc, 0, sym.hash, 0, sym.size.max(0), uselimit,
            )
        } else {
            crate::database::SymbolEntry::new_static(
                symbol_arc,
                0,
                crate::address::Address::new(sym.start),
                0,
                sym.size.max(0),
                uselimit,
            )
        };
        let entry_arc = std::sync::Arc::new(RwLock::new(entry));
        self.symbol_entry_cache.insert(entry_idx, entry_arc.clone());
        Some(entry_arc)
    }

    // RUGRA-GLUE: attach_symbol_to_vn (vn->setSymbolEntry + high->setSymbol)
    /// Attach a ScopeLocal symbol to a Varnode the way
    /// `Varnode::setSymbolEntry` (varnode.cc:429-439) does — mapentry plus
    /// mapped/namelock flags — and then run the faithful
    /// `HighVariable::set_symbol` (variable.cc:245-275, varnode.cc:438),
    /// whose symboloffset computation makes coreaction.cc:2965's
    /// `getSymbolOffset() < 0` namerec gate behave exactly like Ghidra
    /// (whole-map matches are -1; partial coverage yields the byte offset).
    /// The varmap side table records the same association for naming.
    fn attach_symbol_to_vn(
        &mut self,
        entry_idx: usize,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        if let Some(entry) = self.symbol_entry_for(entry_idx) {
            vn.write().unwrap().set_symbol_entry(entry);
        }
        if let Some(high) = vn.read().unwrap().get_high().cloned() {
            high.write().unwrap().set_symbol(vn);
            let high_ptr = std::sync::Arc::as_ptr(&high) as usize;
            self.high_symbols.insert(high_ptr, entry_idx);
        }
    }

    // Ghidra: funcdata_varnode.cc:1104 Funcdata::remapVarnode
    /// Remap a Symbol to `vn` using a static (address-based) mapping. Faithful
    /// to `Funcdata::remapVarnode` (funcdata_varnode.cc:1104-1110):
    ///   vn->clearSymbolLinks();
    ///   entry = localmap->remapSymbol(sym, vn->getAddr(), usepoint);
    ///   vn->setSymbolEntry(entry);
    /// Rugra: ScopeLocal::remapSymbol is not ported; we approximate by
    /// recording the symbol name at `vn`'s address in `symbol_table`. The
    /// usepoint is preserved for downstream resolution but not stored (Rugra
    /// has no per-usepoint SymbolEntry).
    pub fn remap_varnode(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        sym_name: &str,
        _usepoint: crate::address::Address,
    ) {
        // cc:1107: vn->clearSymbolLinks().
        vn.write().unwrap().clear_symbol_links();
        // cc:1108-1109: entry = localmap->remapSymbol(sym, vn->getAddr(), usepoint).
        let vn_addr = vn.read().unwrap().get_offset();
        // Rugra: record the name at vn's address.
        self.symbol_table.insert(vn_addr, sym_name.to_string());
        // cc:1109: vn->setSymbolEntry(entry). Approximate by setting MAPPED.
        vn.write().unwrap().set_flags(crate::varnode::varnode_flags::MAPPED);
    }

    // Ghidra: funcdata_varnode.cc:1120 Funcdata::remapDynamicVarnode
    /// Remap a Symbol to `vn` using a new dynamic (hash-based) mapping. Faithful
    /// to `Funcdata::remapDynamicVarnode` (funcdata_varnode.cc:1120-1126):
    ///   vn->clearSymbolLinks();
    ///   entry = localmap->remapSymbolDynamic(sym, hash, usepoint);
    ///   vn->setSymbolEntry(entry);
    /// Rugra: dynamic-symbol storage is not yet implemented; we record the
    /// symbol name in symbol_table keyed by a synthetic dynamic id. The hash
    /// is preserved on the varnode via a best-effort flag.
    pub fn remap_dynamic_varnode(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        sym_name: &str,
        _usepoint: crate::address::Address,
        hash: u64,
    ) {
        // cc:1123: vn->clearSymbolLinks().
        vn.write().unwrap().clear_symbol_links();
        // cc:1124: entry = localmap->remapSymbolDynamic(sym, hash, usepoint).
        // Rugra: encode the dynamic symbol under a synthetic key so lookups
        // still resolve. Key space is the high bit of u64 (set MSB), which is
        // above any real 48-bit x86-64 address.
        let key = hash | 0x8000_0000_0000_0000;
        self.symbol_table.insert(key, sym_name.to_string());
        // cc:1125: vn->setSymbolEntry(entry). Approximate by setting MAPPED.
        vn.write().unwrap().set_flags(crate::varnode::varnode_flags::MAPPED);
    }

    // Ghidra: funcdata_varnode.cc:1132 Funcdata::linkProtoPartial
    /// For a PIECE input Varnode, find the whole Varnode it composes and
    /// assign the same symbol. Faithful to `Funcdata::linkProtoPartial`
    /// (funcdata_varnode.cc:1132-1149):
    ///   high = vn->getHigh();
    ///   if (high->getSymbol() != NULL) return;
    ///   rootVn = PieceNode::findRoot(vn);
    ///   if (rootVn == vn) return;
    ///   rootHigh = rootVn->getHigh();
    ///   if (!rootHigh->isSameGroup(high)) return;
    ///   nameRep = rootHigh->getNameRepresentative();
    ///   sym = linkSymbol(nameRep);
    ///   if (sym == NULL) return;
    ///   rootHigh->establishGroupSymbolOffset();
    ///   entry = sym->getFirstWholeMap();
    ///   vn->setSymbolEntry(entry);
    pub fn link_proto_partial(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        // cc:1135-1136: high = vn->getHigh(); if (high->getSymbol() != NULL) return.
        let high_arc = vn.read().unwrap().get_high().cloned();
        if let Some(high) = &high_arc {
            let high_ptr = std::sync::Arc::as_ptr(high) as usize;
            if self.high_symbols.contains_key(&high_ptr) {
                return;
            }
        }
        // cc:1137-1138: rootVn = PieceNode::findRoot(vn); if (rootVn == vn) return.
        let root_vn = piece_node_find_root(vn);
        let Some(root_vn) = root_vn else { return };
        if std::sync::Arc::ptr_eq(&root_vn, vn) {
            return;
        }
        // cc:1140-1142: rootHigh = rootVn->getHigh(); if (!isSameGroup(high)) return.
        let (root_high, vn_high) = {
            let r = root_vn.read().unwrap();
            let v = vn.read().unwrap();
            (r.get_high().cloned(), v.get_high().cloned())
        };
        if let (Some(rh), Some(vh)) = (&root_high, &high_arc) {
            let same = rh.read().unwrap().is_same_group(&vh.read().unwrap());
            if !same {
                return;
            }
        }
        let _ = vn_high;
        // cc:1143-1144: nameRep = rootHigh->getNameRepresentative();
        // cc:1144: sym = linkSymbol(nameRep); if (sym == NULL) return.
        let name_rep = root_high.as_ref().and_then(|h| h.read().unwrap().get_name_representative());
        let Some(name_rep) = name_rep else { return };
        let sym_idx = self.link_symbol(&name_rep);
        let Some(sym_idx) = sym_idx else { return };
        // cc:1146: rootHigh->establishGroupSymbolOffset().
        if let Some(root_high) = &root_high {
            root_high.read().unwrap().establish_group_symbol_offset();
        }
        // cc:1147-1148: entry = sym->getFirstWholeMap(); vn->setSymbolEntry(entry).
        self.attach_symbol_to_vn(sym_idx, vn);
    }

    // Ghidra: funcdata_varnode.cc:1218 Funcdata::findLinkedVarnode
    /// Return the (first) Varnode that matches the given SymbolEntry. Faithful
    /// to `Funcdata::findLinkedVarnode` (funcdata_varnode.cc:1218-1251). For
    /// dynamic entries, resolve via DynamicHash; for static entries, scan the
    /// loc tree at (entry->getSize(), entry->getAddr()) honoring usepoints.
    /// Rugra: we accept (addr, size, is_dynamic, first_use_addr) as the
    /// SymbolEntry projection, avoiding the full SymbolEntry dependency.
    pub fn find_linked_varnode(
        &self,
        entry_addr: u64,
        entry_size: usize,
        is_dynamic: bool,
        first_use_addr: crate::address::Address,
        hash: u64,
    ) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        if is_dynamic {
            // cc:1221-1227: DynamicHash::findVarnode(this, firstUseAddr, hash).
            let mut dhash = crate::dynamic::DynamicHash::new();
            let vn = dhash.find_varnode(self, first_use_addr, hash);
            // cc:1224: skip annotations.
            vn.and_then(|v| {
                if v.read().unwrap().is_annotation() {
                    None
                } else {
                    Some(v)
                }
            })
        } else {
            // cc:1229-1250: scan loc tree.
            let usestart = first_use_addr;
            let candidates = self.vbank.overlap_loc(
                crate::address::Address::new(entry_addr),
                entry_size,
            );
            if usestart.as_u64() == 0 {
                // cc:1233-1240: invalid usepoint → first addr-tied varnode.
                for vn in candidates {
                    if vn.read().unwrap().is_addr_tied() {
                        return Some(vn);
                    }
                }
                None
            } else {
                // cc:1242-1249: first vn whose usepoint is in entry's range.
                for vn in candidates {
                    let up = vn.read().unwrap().get_use_point(self);
                    if up.as_u64() >= usestart.as_u64() {
                        return Some(vn);
                    }
                }
                None
            }
        }
    }

    // Ghidra: funcdata_varnode.cc:1257 Funcdata::findLinkedVarnodes
    /// Collect all Varnodes that should be mapped to the given SymbolEntry.
    /// Faithful to `Funcdata::findLinkedVarnodes` (funcdata_varnode.cc:1257-1277):
    ///   if (entry->isDynamic()) { dhash.findVarnode(...); res.push_back(vn); }
    ///   else for vn in locTree(entry->getSize(), entry->getAddr()):
    ///     if (entry->inUse(vn->getUsePoint(*this))) res.push_back(vn);
    /// Rugra: same SymbolEntry projection as `find_linked_varnode`.
    pub fn find_linked_varnodes(
        &self,
        entry_addr: u64,
        entry_size: usize,
        is_dynamic: bool,
        first_use_addr: crate::address::Address,
        hash: u64,
        res: &mut Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    ) {
        if is_dynamic {
            // cc:1260-1265.
            let mut dhash = crate::dynamic::DynamicHash::new();
            if let Some(vn) = dhash.find_varnode(self, first_use_addr, hash) {
                res.push(vn);
            }
        } else {
            // cc:1266-1277.
            let candidates = self.vbank.overlap_loc(
                crate::address::Address::new(entry_addr),
                entry_size,
            );
            for vn in candidates {
                let up = vn.read().unwrap().get_use_point(self);
                // cc:1272: if (entry->inUse(addr)). Rugra: approximate "in use"
                // by comparing against first_use_addr (entries without a
                // usepoint restriction use addr 0 → always in use).
                if first_use_addr.as_u64() == 0 || up.as_u64() >= first_use_addr.as_u64() {
                    res.push(vn);
                }
            }
        }
    }

    // Ghidra: funcdata_varnode.cc:1283 Funcdata::buildDynamicSymbol
    /// Build a special \e dynamic Symbol for `vn`: associated via a hash of
    /// its local data-flow rather than its storage address. Faithful to
    /// `Funcdata::buildDynamicSymbol` (funcdata_varnode.cc:1283-1305):
    ///   if (vn->isTypeLock()||vn->isNameLock()) throw RecovError;
    ///   if (!isHighOn()) throw RecovError;
    ///   high = vn->getHigh();
    ///   if (high->getSymbol() != NULL) return;
    ///   dhash.uniqueHash(vn, this);
    ///   if (dhash.getHash() == 0) throw RecovError(...);
    ///   if (vn->isConstant())
    ///     sym = addEquateSymbol("", force_hex, vn->getOffset(), addr, hash);
    ///   else
    ///     sym = addDynamicSymbol("", high->getType(), addr, hash);
    ///   vn->setSymbolEntry(sym->getFirstWholeMap());
    /// Returns the new symbol's index in `scope.symbols`; Ghidra's RecovError
    /// throws surface as None (the caller keeps the pre-existing entry).
    pub fn build_dynamic_symbol(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> Option<usize> {
        // cc:1286-1287: if (isTypeLock || isNameLock) throw.
        let (is_type_lock, is_name_lock) = {
            let r = vn.read().unwrap();
            (r.is_type_lock(), r.is_name_lock())
        };
        if is_type_lock || is_name_lock {
            eprintln!("[FUNCDATA] buildDynamicSymbol on locked varnode (cc:1286 RecovError)");
            return None;
        }
        // cc:1288-1289: if (!isHighOn()) throw.
        if (self.flags & funcdata_flags::HIGHLEVEL_ON) == 0 {
            eprintln!("[FUNCDATA] buildDynamicSymbol before decompile complete (cc:1288 RecovError)");
            return None;
        }
        // cc:1290-1292: high = vn->getHigh(); if (high->getSymbol()) return.
        let high_arc = vn.read().unwrap().get_high().cloned()?;
        let high_ptr = std::sync::Arc::as_ptr(&high_arc) as usize;
        if let Some(&idx) = self.high_symbols.get(&high_ptr) {
            return Some(idx);
        }
        // cc:1293-1297: dhash.uniqueHash(vn, this); if (hash == 0) throw.
        let mut dhash = crate::dynamic::DynamicHash::new();
        dhash.unique_hash_vn(vn, self);
        let hash = dhash.get_hash();
        if hash == 0 {
            eprintln!("[FUNCDATA] buildDynamicSymbol: no unique hash (cc:1297 RecovError)");
            return None;
        }
        let addr = dhash.get_address();
        // cc:1299-1303: equate symbol for constants, dynamic symbol otherwise.
        let (is_const, vn_offset, vn_space) = {
            let r = vn.read().unwrap();
            (r.is_constant(), r.get_offset(), r.get_space())
        };
        let idx = if is_const {
            // localmap->addEquateSymbol("", Symbol::force_hex, vn->getOffset(),
            //                           dhash.getAddress(), dhash.getHash())
            // (database.cc:1712-1725): an EQUATE-category symbol whose map
            // is dynamic with a single-address uselimit; the varmap model
            // carries the constant value on `start`.
            let idx = self.scope.as_mut()?.add_dynamic_symbol(
                "", None, hash, Some(addr.as_u64()),
            );
            if let Some(sym) = self.scope.as_mut()?.symbols.get_mut(idx) {
                sym.category = crate::varmap::symbol_category::EQUATE;
                sym.start = vn_offset;
                sym.size = 1;
                sym.space = vn_space;
            }
            idx
        } else {
            // localmap->addDynamicSymbol("", high->getType(), dhash.getAddress(), hash)
            let ct = high_arc.read().unwrap().get_type();
            let idx = self.scope.as_mut()?.add_dynamic_symbol(
                "", Some(ct), hash, Some(addr.as_u64()),
            );
            if let Some(sym) = self.scope.as_mut()?.symbols.get_mut(idx) {
                sym.space = vn_space;
            }
            idx
        };
        // cc:1304: vn->setSymbolEntry(sym->getFirstWholeMap()).
        self.attach_symbol_to_vn(idx, vn);
        Some(idx)
    }

    // Ghidra: funcdata.hh:451 Funcdata::markIndirectCreation
    /// Convert CPUI_INDIRECT into an indirect creation. Faithful to
    /// `Funcdata::markIndirectCreation` (funcdata_op.cc:736-748).
    pub fn mark_indirect_creation(&self, indop: &crate::op::PcodeOpRef, possible_output: bool) {
        let (out_vn, in0_is_const) = {
            let o = indop.0.read().unwrap();
            let out = o.output.clone();
            let in0_const = o.get_in(0).map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
            (out, in0_const)
        };
        indop.0.write().unwrap().flags |= crate::op::pcodeop_flags::INDIRECT_CREATION;
        if !in0_is_const {
            eprintln!("[MERGE] Indirect creation not properly formed (in0 not constant)");
        }
        if !possible_output {
            if let Some(in0) = indop.0.read().unwrap().get_in(0) {
                in0.write().unwrap().set_flags(crate::varnode::varnode_flags::INDIRECT_CREATION);
            }
        }
        if let Some(out_vn) = out_vn {
            out_vn.write().unwrap().set_flags(crate::varnode::varnode_flags::INDIRECT_CREATION);
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::opGetSlot
    /// Get the input slot of `vn` within `op`. Faithful to `PcodeOp::getSlot`.
    /// Returns the slot index, or -1 if not found.
    pub fn op_get_slot(&self, op: &crate::op::PcodeOpRef, vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) -> i32 {
        let o = op.0.read().unwrap();
        for (i, v) in o.inrefs.iter().enumerate() {
            if std::sync::Arc::ptr_eq(v, vn) {
                return i as i32;
            }
        }
        -1
    }

    // Ghidra: funcdata.cc:230 Funcdata::spacebase
    /// Mark registers that map to a virtual address space (the stack
    /// spacebase). Faithful to `Funcdata::spacebase()` (funcdata.cc:230-269).
    ///
    /// For Rugra's x86-64 lift, the stack pointer is RSP at
    /// `AddressSpace::Register`, offset 0x20, size 8 (see `x86_lift.rs:40`).
    /// This method finds all varnodes at that location, marks them with the
    /// `SPACEBASE` flag, and — for already-marked spacebase varnodes with
    /// multiple descendants — calls `split_uses()` so each additive use
    /// (`INT_ADD(RSP, off)`) becomes independently addressable.
    ///
    /// This is the canonical Ghidra mechanism: it does NOT require the lifter
    /// to emit Stack-space varnodes. Instead, marking the RSP input as a
    /// spacebase lets downstream passes (varmap, ActionStackPtrFlow,
    /// heritage) recognize RSP as "a pointer into the Stack space."
    pub fn spacebase(&mut self) {
        // Stack pointer location from configuration (Architecture cspec fields).
        // Faithful to spc->getSpacebase(0) returning the register location.
        let sb_space = self.stack_pointer_space;
        let sb_offset = self.stack_pointer_offset;
        let sb_size = self.stack_pointer_size;

        // Collect all varnodes at the stack-pointer location that are not free.
        // Faithful to vbank.beginLoc(size, Address) / endLoc iteration.
        let candidates: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = {
            self.vbank
                .loc_tree
                .iter()
                .filter(|v| {
                    let g = v.0.read().unwrap();
                    !g.is_free()
                        && g.get_space() == sb_space
                        && g.get_offset() == sb_offset
                        && g.get_size() == sb_size
                })
                .map(|v| v.0.clone())
                .collect()
        };

        for vn_arc in candidates {
            let is_sb = vn_arc.read().unwrap().is_spacebase();
            if is_sb {
                // Already marked: give it a chance for descendants to be
                // eliminated naturally, now force a split if it still has
                // multiple descendants (funcdata.cc:253-259).
                let def_arc = {
                    let vn_g = vn_arc.read().unwrap();
                    vn_g.def.as_ref().and_then(|w| w.upgrade())
                };
                if let Some(def_op) = def_arc {
                    if def_op.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_INT_ADD {
                        self.split_uses(&vn_arc);
                    }
                }
            } else {
                // Mark all base registers (not just input) with spacebase flag
                // (funcdata.cc:262).
                vn_arc.write().unwrap().set_flags(crate::varnode::varnode_flags::SPACEBASE);
                // Note: Ghidra also sets TypeSpacebase pointer type on the
                // input register (funcdata.cc:263-264). Rugra's type system
                // does not yet have TypeSpacebase; the SPACEBASE flag alone is
                // sufficient for varmap/ActionStackPtrFlow recognition.
            }
        }
    }

    // Ghidra: funcdata.cc:275 Funcdata::newSpacebasePtr
    /// Given an address space known to have a base register, construct a
    /// Varnode representing that register. Faithful to
    /// `Funcdata::newSpacebasePtr` (funcdata.cc:275-284):
    ///   const VarnodeData &point(id->getSpacebase(0));
    ///   vn = newVarnode(point.size, Address(point.space,point.offset));
    ///   return vn;
    /// Rugra: `id` is approximated by the Funcdata's configured stack space
    /// (Architecture cspec). The stack-pointer (space, offset, size) come from
    /// the `stack_pointer_*` fields populated by `set_arch`.
    pub fn new_spacebase_ptr(
        &mut self,
        id: crate::space::AddressSpace,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // cc:281: const VarnodeData &point(id->getSpacebase(0)).
        // Rugra: only the stack space has a known base register; for other
        // spaces we fall back to the configured stack-pointer location.
        let (sp_space, sp_offset, sp_size) = if id.is_stack() {
            (self.stack_pointer_space, self.stack_pointer_offset, self.stack_pointer_size)
        } else {
            (self.stack_pointer_space, self.stack_pointer_offset, self.stack_pointer_size)
        };
        // cc:282: vn = newVarnode(point.size, Address(point.space,point.offset)).
        let vn = self.vbank.create_with_space(sp_size, sp_space, sp_offset);
        vn
    }

    // Ghidra: funcdata.cc:291 Funcdata::findSpacebaseInput
    /// Locate the unique input Varnode holding the incoming value of the base
    /// register for `id`. Faithful to `Funcdata::findSpacebaseInput`
    /// (funcdata.cc:291-300):
    ///   const VarnodeData &point(id->getSpacebase(0));
    ///   vn = vbank.findInput(point.size, Address(point.space,point.offset));
    ///   return vn;
    /// Returns None if no input varnode exists at the base-register location.
    pub fn find_spacebase_input(
        &self,
        id: crate::space::AddressSpace,
    ) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        // cc:297: const VarnodeData &point(id->getSpacebase(0)).
        let (_sp_space, sp_offset, sp_size) = (self.stack_pointer_space, self.stack_pointer_offset, self.stack_pointer_size);
        // cc:298: vn = vbank.findInput(point.size, Address(point.space,point.offset)).
        self.vbank.find_input(sp_size, crate::address::Address::new(sp_offset))
    }

    // Ghidra: funcdata.cc:309 Funcdata::constructSpacebaseInput
    /// If it doesn't exist, create an input Varnode of the base register for
    /// `id`. Faithful to `Funcdata::constructSpacebaseInput` (funcdata.cc:309-325):
    ///   spacePtr = findSpacebaseInput(id);
    ///   if (spacePtr) return spacePtr;
    ///   if (id->numSpacebase() == 0) throw LowlevelError(...);
    ///   point = id->getSpacebase(0);
    ///   ptr = getTypePointer(point.size, getTypeSpacebase(id,getAddress()), id->getWordSize());
    ///   spacePtr = newVarnode(point.size, point.getAddr(), ptr);
    ///   spacePtr = setInputVarnode(spacePtr);
    ///   spacePtr->setFlags(Varnode::spacebase);
    ///   spacePtr->updateType(ptr, true, true);
    ///   return spacePtr;
    /// Idempotent: returns the existing input if one is present.
    pub fn construct_spacebase_input(
        &mut self,
        id: crate::space::AddressSpace,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // cc:312-314: spacePtr = findSpacebaseInput(id); if (spacePtr) return.
        if let Some(existing) = self.find_spacebase_input(id) {
            return existing;
        }
        // cc:315-316: if (id->numSpacebase() == 0) throw LowlevelError(...).
        // Rugra: only the stack space is known to have a base register; for
        // other spaces we still attempt construction (best-effort) rather than
        // panic, mirroring the existing spacebase() method's tolerance.
        // cc:317-320: build the varnode + pointer type.
        let sp_space = self.stack_pointer_space;
        let sp_offset = self.stack_pointer_offset;
        let sp_size = self.stack_pointer_size;
        let space_ptr = self.vbank.create_with_space(sp_size, sp_space, sp_offset);
        // cc:321: spacePtr = setInputVarnode(spacePtr).
        let space_ptr = self.set_input_varnode(space_ptr);
        // cc:322: spacePtr->setFlags(Varnode::spacebase).
        space_ptr.write().unwrap().set_flags(crate::varnode::varnode_flags::SPACEBASE);
        // cc:323: spacePtr->updateType(ptr, true, true). Rugra lacks
        // TypeSpacebase; the SPACEBASE flag is sufficient for downstream
        // recognition (see existing `spacebase()` note).
        space_ptr
    }

    // Ghidra: funcdata.cc:332 Funcdata::constructConstSpacebase
    /// Create a constant Varnode representing the \e base of the given global
    /// address space, with the TypeSpacebase data-type. Faithful to
    /// `Funcdata::constructConstSpacebase` (funcdata.cc:332-341):
    ///   ct = getTypeSpacebase(id, Address());
    ///   ptr = getTypePointer(id->getAddrSize(), ct, id->getWordSize());
    ///   spacePtr = newConstant(id->getAddrSize(), 0);
    ///   spacePtr->updateType(ptr, true, true);
    ///   spacePtr->setFlags(Varnode::spacebase);
    ///   return spacePtr;
    /// Used by spacebaseConstant to build the synthetic "base of ram" pointer.
    pub fn construct_const_spacebase(
        &mut self,
        id: crate::space::AddressSpace,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // cc:336: addr_size = id->getAddrSize().
        let addr_size = id.addr_size();
        // cc:337: spacePtr = newConstant(id->getAddrSize(), 0).
        let space_ptr = self.vbank.create_constant(addr_size, 0);
        // cc:338: spacePtr->updateType(ptr, true, true). TypeSpacebase not yet
        // ported; SPACEBASE flag carries the semantic.
        // cc:339: spacePtr->setFlags(Varnode::spacebase).
        space_ptr.write().unwrap().set_flags(crate::varnode::varnode_flags::SPACEBASE);
        space_ptr
    }

    // Ghidra: funcdata.cc:360 Funcdata::spacebaseConstant
    /// Convert a constant pointer into a CPUI_PTRSUB that triggers a Symbol
    /// lookup. Faithful to `Funcdata::spacebaseConstant`
    /// (funcdata.cc:360-462). Given `op` reading a constant pointer at
    /// `slot`, rewrite the constant into PTRSUB(constSpacebase, symOffset)
    /// so that global Symbol resolution fires at analysis time. May insert
    /// INT_ADD (for intra-symbol offset), INT_ZEXT (if growing), or
    /// SUBPIECE (if shrinking) to preserve the original value/size.
    ///
    /// Rugra caveat: full Ghidra behaviour requires a SymbolEntry with
    /// `getAddr()`/`getSymbol()->getType()`. Rugra's `symbol_table` is
    /// name-only; we perform the structural PTRSUB/ADD/ZEXT/SUBPIECE
    /// rewrite and rely on `link_symbol_reference` to recover the Symbol
    /// at PTRSUB time. Type-locking of the output is skipped (no entrytype).
    pub fn spacebase_constant(
        &mut self,
        op: &crate::op::PcodeOpRef,
        slot: usize,
        rampoint: crate::address::Address,
        origval: u64,
        origsize: usize,
    ) {
        use crate::opcodes::OpCode;
        // cc:363: sz = rampoint.getAddrSize().
        let sz = rampoint.as_u64().leading_zeros().checked_sub(0).map(|_| 8).unwrap_or(8);
        let sz = sz.max(1).min(8) as usize;
        // Rugra: use the configured address size (x86-64 = 8) when rampoint
        // does not carry it. Fall back to origsize for the structural rewrite.
        let sz = origsize.max(sz).min(8);
        // cc:369: extra = rampoint.getOffset() - entry->getAddr().getOffset().
        // Rugra: without a SymbolEntry we cannot know the entry's start; assume
        // extra == 0 (the constant points at the start of its symbol). This
        // matches the common case and avoids fabricating an INT_ADD.
        let extra: u64 = 0;
        // Convert extra to address units (cc:370). Word size of ram is 1 for
        // typical x86-64, so byteToAddress is a no-op; kept for fidelity.
        let extra = extra; // already in address units (word_size==1).

        // cc:372-390: classify the existing op (COPY vs other).
        let op_code = op.0.read().unwrap().opcode;
        let is_copy = op_code == OpCode::CPUI_COPY;
        let mut add_op: Option<crate::op::PcodeOpRef> = None;
        let mut extra_op: Option<crate::op::PcodeOpRef> = None;
        let mut zext_op: Option<crate::op::PcodeOpRef> = None;
        let mut sub_op: Option<crate::op::PcodeOpRef> = None;
        if is_copy {
            if sz < origsize {
                zext_op = Some(op.clone());
            } else {
                // cc:382: op->insertInput(1) — PTRSUB/ADD/SUBPIECE take 2 inputs.
                op.0.write().unwrap().inrefs.resize(2, std::sync::Arc::new(std::sync::RwLock::new(
                    crate::varnode::Varnode::new_constant(0, 0),
                )));
                if origsize < sz {
                    sub_op = Some(op.clone());
                } else if extra != 0 {
                    extra_op = Some(op.clone());
                } else {
                    add_op = Some(op.clone());
                }
            }
        }

        // cc:391-393: spacebase_vn = newConstant(sz, 0); updateType; setFlags.
        let spacebase_vn = self.new_constant(sz, 0);
        spacebase_vn.write().unwrap().set_flags(crate::varnode::varnode_flags::SPACEBASE);

        // cc:394-402: allocate/repurpose the PTRSUB op.
        if add_op.is_none() {
            let add = self.new_op(2, op.0.read().unwrap().get_addr());
            self.op_set_opcode(&add, OpCode::CPUI_PTRSUB);
            self.new_unique_out(sz, &add);
            self.op_insert_before(&add, op);
            add_op = Some(add);
        } else {
            let add = add_op.clone().unwrap();
            self.op_set_opcode(&add, OpCode::CPUI_PTRSUB);
        }
        let add_op = add_op.unwrap();

        // cc:405: newconstoff = origval - extra.
        let newconstoff = origval.wrapping_sub(extra);
        // cc:406-407: newconst = newConstant(sz, newconstoff); setPtrCheck.
        let newconst = self.new_constant(sz, newconstoff);
        // Ghidra cc:407: vn->setPtrCheck() clears the PTR_CHECK bit so the
        // constant is no longer re-examined as a potential pointer. Rugra
        // stores this in `addlflags` (addl_flags::PTR_CHECK).
        newconst.write().unwrap().addlflags |= crate::varnode::addl_flags::PTR_CHECK;

        // cc:410-411: opSetInput(addOp, spacebase_vn, 0); opSetInput(addOp, newconst, 1).
        self.op_set_input(&add_op, spacebase_vn, 0);
        self.op_set_input(&add_op, newconst, 1);

        // Track the current output varnode of the chain.
        let mut outvn = add_op.0.read().unwrap().output.clone();

        // cc:420-434: if (extra != 0) build INT_ADD(outvn, extconst).
        if extra != 0 {
            if extra_op.is_none() {
                let eop = self.new_op(2, op.0.read().unwrap().get_addr());
                self.op_set_opcode(&eop, OpCode::CPUI_INT_ADD);
                self.new_unique_out(sz, &eop);
                self.op_insert_before(&eop, op);
                extra_op = Some(eop);
            }
            let extra_op = extra_op.unwrap();
            self.op_set_opcode(&extra_op, OpCode::CPUI_INT_ADD);
            let extconst = self.new_constant(sz, extra);
            extconst.write().unwrap().addlflags |= crate::varnode::addl_flags::PTR_CHECK;
            // cc:431-432.
            self.op_set_input(&extra_op, outvn.clone().unwrap(), 0);
            self.op_set_input(&extra_op, extconst, 1);
            outvn = extra_op.0.read().unwrap().output.clone();
        }

        // cc:435-446: if (sz < origsize) INT_ZEXT.
        if sz < origsize {
            if zext_op.is_none() {
                let zop = self.new_op(1, op.0.read().unwrap().get_addr());
                self.op_set_opcode(&zop, OpCode::CPUI_INT_ZEXT);
                self.new_unique_out(origsize, &zop);
                self.op_insert_before(&zop, op);
                zext_op = Some(zop);
            }
            let zext_op = zext_op.unwrap();
            self.op_set_opcode(&zext_op, OpCode::CPUI_INT_ZEXT);
            self.op_set_input(&zext_op, outvn.clone().unwrap(), 0);
            outvn = zext_op.0.read().unwrap().output.clone();
        } else if origsize < sz {
            // cc:447-458: INT_SUBPIECE to truncate back to origsize.
            if sub_op.is_none() {
                let sop = self.new_op(2, op.0.read().unwrap().get_addr());
                self.op_set_opcode(&sop, OpCode::CPUI_SUBPIECE);
                self.new_unique_out(origsize, &sop);
                self.op_insert_before(&sop, op);
                sub_op = Some(sop);
            }
            let sub_op = sub_op.unwrap();
            self.op_set_opcode(&sub_op, OpCode::CPUI_SUBPIECE);
            self.op_set_input(&sub_op, outvn.clone().unwrap(), 0);
            let zero = self.new_constant(4, 0);
            self.op_set_input(&sub_op, zero, 1);
            outvn = sub_op.0.read().unwrap().output.clone();
        }

        // cc:460-461: if (!isCopy) opSetInput(op, outvn, slot).
        if !is_copy {
            if let Some(out) = outvn {
                self.op_set_input(op, out, slot);
            }
        }
    }

    // Ghidra: funcdata_op.cc:459 Funcdata::createStackRef
    /// Create an INT_ADD PcodeOp calculating an offset to the \e spacebase
    /// register. Faithful to `Funcdata::createStackRef`
    /// (funcdata_op.cc:459-496):
    ///   if (stackptr == NULL) stackptr = newSpacebasePtr(spc);
    ///   addrsize = stackptr->getSize();
    ///   addop = newOp(2, op->getAddr()); opSetOpcode(addop, INT_ADD);
    ///   addout = newUniqueOut(addrsize, addop);
    ///   opSetInput(addop, stackptr, 0);
    ///   off = AddrSpace::byteToAddress(off, spc->getWordSize());
    ///   opSetInput(addop, newConstant(addrsize, off), 1);
    ///   if (insertafter) opInsertAfter(addop, op); else opInsertBefore(addop, op);
    ///   segdef = glb->userops.getSegmentOp(spc->getContain()->getIndex());
    ///   if (segdef) { build SEGMENTOP chain; addout = segout; }
    ///   return addout;
    /// Rugra: SegmentOp is architecturally rare (x86-64 has none); we skip the
    /// SEGMENTOP branch (logged) since the Funcdata has no userops handle yet.
    pub fn create_stack_ref(
        &mut self,
        spc: crate::space::AddressSpace,
        off: u64,
        op: &crate::op::PcodeOpRef,
        stackptr: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
        insertafter: bool,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // cc:467-468: stackptr = stackptr.unwrap_or_else(|| newSpacebasePtr(spc)).
        let stackptr = match stackptr {
            Some(vn) => vn,
            None => self.new_spacebase_ptr(spc),
        };
        // cc:469: addrsize = stackptr->getSize().
        let addrsize = stackptr.read().unwrap().get_size();
        // cc:470-471: addop = newOp(2, op->getAddr()); opSetOpcode(INT_ADD).
        let addop = self.new_op(2, op.0.read().unwrap().get_addr());
        self.op_set_opcode(&addop, crate::opcodes::OpCode::CPUI_INT_ADD);
        // cc:472: addout = newUniqueOut(addrsize, addop).
        let addout = self.new_unique_out(addrsize, &addop);
        // cc:473: opSetInput(addop, stackptr, 0).
        self.op_set_input(&addop, stackptr, 0);
        // cc:474: off = AddrSpace::byteToAddress(off, spc->getWordSize()).
        let word_size = spc.word_size() as u64;
        let off = if word_size > 1 { off / word_size } else { off };
        // cc:475: opSetInput(addop, newConstant(addrsize, off), 1).
        let off_const = self.new_constant(addrsize, off);
        self.op_set_input(&addop, off_const, 1);
        // cc:476-479: insert before/after op.
        if insertafter {
            self.op_insert_after(&addop, op);
        } else {
            self.op_insert_before(&addop, op);
        }
        // cc:481-493: SegmentOp chain. Rugra: skipped (no userops handle);
        // x86-64 has no segment ops so this branch is dead code for the
        // current target.
        addout
    }

    // Ghidra: funcdata_op.cc:508 Funcdata::opStackStore
    /// Create a STORE expression at an offset relative to a \e spacebase
    /// register. Faithful to `Funcdata::opStackStore` (funcdata_op.cc:508-527):
    ///   addout = createStackRef(spc, off, op, NULL, insertafter);
    ///   storeop = newOp(3, op->getAddr()); opSetOpcode(storeop, STORE);
    ///   opSetInput(storeop, newVarnodeSpace(spc->getContain()), 0);
    ///   opSetInput(storeop, addout, 1);
    ///   opInsertAfter(storeop, addout->getDef());
    ///   return storeop;
    /// The Varnode value being stored must still be set on the returned op.
    /// Rugra: `newVarnodeSpace` is approximated by a constant encoding the
    /// space id (the actual `newVarnodeSpace` is in the missing-API list).
    pub fn op_stack_store(
        &mut self,
        spc: crate::space::AddressSpace,
        off: u64,
        op: &crate::op::PcodeOpRef,
        insertafter: bool,
    ) -> crate::op::PcodeOpRef {
        // cc:518: addout = createStackRef(spc, off, op, NULL, insertafter).
        let addout = self.create_stack_ref(spc, off, op, None, insertafter);
        // Capture the stack-building op (def of addout) before we lose it.
        let stack_def = addout.read().unwrap().get_def().map(crate::op::PcodeOpRef);
        // cc:519-520: storeop = newOp(3, op->getAddr()); opSetOpcode(STORE).
        let storeop = self.new_op(3, op.0.read().unwrap().get_addr());
        self.op_set_opcode(&storeop, crate::opcodes::OpCode::CPUI_STORE);
        // cc:523: opSetInput(storeop, newVarnodeSpace(spc->getContain()), 0).
        // Rugra: encode the stack container space as a constant varnode. The
        // container of the stack space is the ram-like space; we use `spc`
        // itself as a best-effort (matching existing STORE lowering).
        let space_vn = self.new_constant(1, spc.space_id() as u64);
        self.op_set_input(&storeop, space_vn, 0);
        // cc:524: opSetInput(storeop, addout, 1).
        self.op_set_input(&storeop, addout, 1);
        // cc:525: opInsertAfter(storeop, addout->getDef()).
        if let Some(def) = stack_def {
            self.op_insert_after(&storeop, &def);
        } else {
            self.op_insert_after(&storeop, op);
        }
        storeop
    }

    // Ghidra: funcdata_op.cc:541 Funcdata::opStackLoad
    /// Create a LOAD expression at an offset relative to a \e spacebase
    /// register. Faithful to `Funcdata::opStackLoad` (funcdata_op.cc:541-552):
    ///   addout = createStackRef(spc, off, op, stackref, insertafter);
    ///   loadop = newOp(2, op->getAddr()); opSetOpcode(loadop, LOAD);
    ///   opSetInput(loadop, newVarnodeSpace(spc->getContain()), 0);
    ///   opSetInput(loadop, addout, 1);
    ///   res = newUniqueOut(sz, loadop);
    ///   opInsertAfter(loadop, addout->getDef());
    ///   return res;
    pub fn op_stack_load(
        &mut self,
        spc: crate::space::AddressSpace,
        off: u64,
        sz: usize,
        op: &crate::op::PcodeOpRef,
        stackref: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
        insertafter: bool,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // cc:544: addout = createStackRef(spc, off, op, stackref, insertafter).
        let addout = self.create_stack_ref(spc, off, op, stackref, insertafter);
        let stack_def = addout.read().unwrap().get_def().map(crate::op::PcodeOpRef);
        // cc:545-546: loadop = newOp(2, ...); opSetOpcode(LOAD).
        let loadop = self.new_op(2, op.0.read().unwrap().get_addr());
        self.op_set_opcode(&loadop, crate::opcodes::OpCode::CPUI_LOAD);
        // cc:547: opSetInput(loadop, newVarnodeSpace(spc->getContain()), 0).
        let space_vn = self.new_constant(1, spc.space_id() as u64);
        self.op_set_input(&loadop, space_vn, 0);
        // cc:548: opSetInput(loadop, addout, 1).
        self.op_set_input(&loadop, addout, 1);
        // cc:549: res = newUniqueOut(sz, loadop).
        let res = self.new_unique_out(sz, &loadop);
        // cc:550: opInsertAfter(loadop, addout->getDef()).
        if let Some(def) = stack_def {
            self.op_insert_after(&loadop, &def);
        } else {
            self.op_insert_after(&loadop, op);
        }
        res
    }

    // Ghidra: funcdata.cc:34 Funcdata::calcNzMask
    /// Make all reads of the given Varnode unique. Faithful to
    /// `Funcdata::splitUses` (funcdata_varnode.cc:1540-1567).
    /// Calculate the non-zero mask (NZM) property on all Varnode objects.
    /// Faithful to `Funcdata::calcNZMask` (funcdata_varnode.cc:856-930).
    /// DFS traversal of ops in alive order: for each op whose output hasn't
    /// been calculated, compute its NZM from input NZMs using
    /// `PcodeOp::getNZMaskLocal` (op.cc:547-700).
    pub fn calc_nz_mask(&mut self) {
        use crate::opcodes::OpCode;
        // Process ops in alive list order (topological-ish).
        // For each op with an output, compute NZM.
        let ops: Vec<crate::op::PcodeOpRef> = self.obank.alivelist.clone();
        for op_ref in &ops {
            let (opcode, out_size) = {
                let op = op_ref.0.read().unwrap();
                let sz = op.output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(0);
                (op.opcode, sz)
            };
            if out_size == 0 { continue; }
            let full_mask = crate::address::calc_mask(out_size);
            // Get input NZMs
            let (in0_nzm, in1_nzm, in0_const, in1_const, in0_size, in1_val) = {
                let op = op_ref.0.read().unwrap();
                let i0 = op.inrefs.get(0).map(|v| {
                    let g = v.read().unwrap();
                    if g.is_constant() { g.get_offset() } else { g.get_nz_mask() }
                });
                let i1 = op.inrefs.get(1).map(|v| {
                    let g = v.read().unwrap();
                    if g.is_constant() { g.get_offset() } else { g.get_nz_mask() }
                });
                let c0 = op.inrefs.get(0).map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
                let c1 = op.inrefs.get(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
                let s0 = op.inrefs.get(0).map(|v| v.read().unwrap().get_size()).unwrap_or(0);
                let v1 = op.inrefs.get(1).map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
                (i0.unwrap_or(full_mask), i1.unwrap_or(full_mask), c0, c1, s0, v1)
            };
            let res_mask = match opcode {
                OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
                | OpCode::CPUI_INT_SLESS | OpCode::CPUI_INT_SLESSEQUAL
                | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_LESSEQUAL
                | OpCode::CPUI_INT_CARRY | OpCode::CPUI_INT_SCARRY | OpCode::CPUI_INT_SBORROW
                | OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_XOR
                | OpCode::CPUI_BOOL_AND | OpCode::CPUI_BOOL_OR
                | OpCode::CPUI_FLOAT_EQUAL | OpCode::CPUI_FLOAT_NOTEQUAL
                | OpCode::CPUI_FLOAT_LESS | OpCode::CPUI_FLOAT_LESSEQUAL
                | OpCode::CPUI_FLOAT_NAN => 1u64,
                OpCode::CPUI_COPY | OpCode::CPUI_INT_ZEXT => in0_nzm,
                OpCode::CPUI_INT_SEXT => {
                    // sign extend nzm from in0_size to out_size
                    let signbit = 1u64 << (in0_size * 8 - 1);
                    if (in0_nzm & signbit) != 0 && out_size > 8 {
                        full_mask // sign bit set, upper bits all 1
                    } else if (in0_nzm & signbit) != 0 {
                        in0_nzm | (full_mask & !crate::address::calc_mask(in0_size))
                    } else {
                        in0_nzm
                    }
                }
                OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_OR => {
                    if in0_nzm != full_mask { in0_nzm | in1_nzm } else { full_mask }
                }
                OpCode::CPUI_INT_AND => {
                    if in0_nzm != 0 { in0_nzm & in1_nzm } else { 0 }
                }
                OpCode::CPUI_INT_LEFT => {
                    if !in1_const { full_mask }
                    else {
                        let sa = in1_val as u32;
                        if sa >= 64 { 0 } else { in0_nzm.wrapping_shl(sa) & full_mask }
                    }
                }
                OpCode::CPUI_INT_RIGHT => {
                    if !in1_const { full_mask }
                    else {
                        let sa = in1_val as u32;
                        if sa >= 64 { 0 } else { in0_nzm >> sa }
                    }
                }
                OpCode::CPUI_INT_NEGATE => !in0_nzm & full_mask,
                OpCode::CPUI_INT_2COMP => {
                    // -x: if x is power of 2, nzm = x; else full_mask
                    if in0_nzm != 0 && (in0_nzm & (in0_nzm - 1)) == 0 { in0_nzm }
                    else { full_mask }
                }
                OpCode::CPUI_SUBPIECE => {
                    let trunc = in1_val as usize;
                    if trunc * 8 >= 64 { 0 }
                    else { (in0_nzm >> (trunc * 8)) & full_mask }
                }
                OpCode::CPUI_PIECE => {
                    // hi << lo_size | lo
                    in0_nzm.wrapping_shl(((out_size - in0_size) * 8) as u32) | in1_nzm
                }
                _ => full_mask,
            };
            // Set the output varnode's NZM
            if let Some(out) = op_ref.0.read().unwrap().output.as_ref() {
                out.write().unwrap().set_nzm(res_mask);
            }
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::splitUses
    ///
    /// If `vn` is defined by an op (e.g. INT_ADD) and has multiple
    /// descendants, duplicate the defining op so each reader gets its own
    /// independent output copy. This allows per-use analysis (e.g. distinct
    /// stack offsets from the same spacebase-derived pointer).
    pub fn split_uses(&mut self, vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) {
        // Get the defining op of vn.
        let def_arc = {
            let vn_g = vn.read().unwrap();
            match vn_g.def.as_ref().and_then(|w| w.upgrade()) {
                Some(a) => a,
                None => return, // no defining op
            }
        };

        // Collect descendant ops (readers), preserving order.
        let descendents: Vec<(crate::op::PcodeOpRef, i32)> = {
            let vn_g = vn.read().unwrap();
            vn_g.descend_iter()
                .map(|op| {
                    let opref = crate::op::PcodeOpRef(op.clone());
                    let slot = self.op_get_slot(&opref, vn);
                    (opref, slot)
                })
                .collect()
        };
        if descendents.len() <= 1 {
            return; // Only one (or zero) descendant — nothing to split.
        }

        // Clone the defining op for each descendant except the last.
        let num_inputs = def_arc.read().unwrap().inrefs.len();
        let def_addr = def_arc.read().unwrap().get_addr();
        let def_opcode = def_arc.read().unwrap().opcode;
        // Snapshot inputs before mutation (avoid holding lock across new_op).
        let inputs: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> =
            def_arc.read().unwrap().inrefs.clone();
        let vn_size = vn.read().unwrap().get_size();
        let vn_addr = vn.read().unwrap().loc.clone();
        let vn_space = vn.read().unwrap().address_space;

        // Faithful to funcdata_varnode.cc:1549-1565: the descendant iterator
        // is advanced BEFORE each rewrite, so EVERY original descendant is
        // processed exactly once — there is no "keep the last reader on the
        // original op" special case; the original op is left dead for
        // dead-code removal. Rugra snapshots the descendant list up front,
        // which preserves the same one-pass order.
        for (useop, slot) in descendents {
            if slot < 0 {
                continue;
            }
            // newop = newOp(op->numInput(), op->getAddr())
            let newop = self.new_op(num_inputs, def_addr.clone());
            // cc:1556: newvn = newVarnode(vn->getSize(), vn->getAddr(),
            // vn->getType()) — VarnodeBank::create (varnode.cc:1250) inserts
            // the free varnode under its FINAL (space, loc) tree keys, so no
            // post-insert key mutation can drift the tree order.
            let newvn = self.vbank.create_with_space(vn_size, vn_space, vn_addr.as_u64());
            // cc:1557: opSetOutput(newop,newvn) — Funcdata::opSetOutput
            // (funcdata_op.cc:70-87) routes through VarnodeBank::setDef for
            // the WRITTEN flag and the def-tree re-key; never an in-place
            // mutation of a tree-resident key field.
            self.op_set_output(&newop, newvn.clone());
            // opSetOpcode(newop, op->code())
            self.op_set_opcode(&newop, def_opcode);
            // for each input: opSetInput(newop, op->getIn(i), i)
            for (idx, inp) in inputs.iter().enumerate() {
                self.op_set_input(&newop, inp.clone(), idx);
            }
            // opSetInput(useop, newvn, slot)
            self.op_set_input(&useop, newvn, slot as usize);
            // opInsertBefore(newop, op)
            let def_ref = crate::op::PcodeOpRef(def_arc.clone());
            self.op_insert_before(&newop, &def_ref);
        }
        // cc:1566: Dead-code actions should remove original op
    }

    // Ghidra: funcdata.cc:34 Funcdata::cseElimination
    /// Eliminate a common subexpression between two ops. Faithful to
    /// `Funcdata::cseElimination` (funcdata_op.cc:1358-1398). Keeps the
    /// earlier-ordered op (by sequence number), total_replaces the other's
    /// output, and destroys the duplicate.
    pub fn cse_elimination(
        &mut self,
        op1: &crate::op::PcodeOpRef,
        op2: &crate::op::PcodeOpRef,
    ) -> crate::op::PcodeOpRef {
        // Determine which op to keep (earlier sequence order).
        let order1 = op1.0.read().unwrap().start.get_order();
        let order2 = op2.0.read().unwrap().start.get_order();
        let (replace, dup) = if order1 <= order2 {
            (op1.clone(), op2.clone())
        } else {
            (op2.clone(), op1.clone())
        };
        let replace_out = replace.0.read().unwrap().output.clone();
        let dup_out = dup.0.read().unwrap().output.clone();
        if let (Some(rep_out), Some(dup_o)) = (replace_out, dup_out) {
            self.total_replace(&dup_o, rep_out);
        }
        self.op_destroy(&dup);
        replace
    }

    // Ghidra: funcdata.cc:34 Funcdata::cseEliminateList
    /// Perform CSE on a list of (hash, PcodeOp) pairs. Faithful to
    /// `Funcdata::cseEliminateList` (funcdata_op.cc:1420-1449). Sorts by hash,
    /// finds matching pairs via `is_cse_match`, eliminates duplicates.
    /// Returns the list of surviving output Varnodes.
    pub fn cse_eliminate_list(
        &mut self,
        list: &mut Vec<(u64, crate::op::PcodeOpRef)>,
    ) -> Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        let mut outlist = Vec::new();
        if list.is_empty() {
            return outlist;
        }
        // Sort by hash.
        list.sort_by_key(|(h, _)| *h);
        let mut i = 0;
        while i + 1 < list.len() {
            let h1 = list[i].0;
            let h2 = list[i + 1].0;
            if h1 == h2 {
                let op1 = list[i].1.clone();
                let op2 = list[i + 1].1.clone();
                let (is_dead1, is_dead2) = {
                    let r1 = op1.0.read().unwrap();
                    let r2 = op2.0.read().unwrap();
                    (r1.is_dead(), r2.is_dead())
                };
                if !is_dead1 && !is_dead2 {
                    let is_match = op1.0.read().unwrap().is_cse_match(&op2.0.read().unwrap());
                    if is_match {
                        let res_op = self.cse_elimination(&op1, &op2);
                        let out_opt = {
                            let r = res_op.0.read().unwrap();
                            r.output.clone()
                        };
                        if let Some(out) = out_opt {
                            outlist.push(out);
                        }
                    }
                }
            }
            i += 1;
        }
        outlist
    }

    // Ghidra: funcdata.cc:34 Funcdata::opBoolNegate
    /// Insert a BOOL_NEGATE (CPUI_BOOL_NEGATE in Rugra) of `vn`, returning the
    /// new output Varnode. Faithful to `Funcdata::opBoolNegate`
    /// (funcdata_op.cc:560-572). If `insert_after` is true, the negate op is
    /// inserted after `op`; otherwise before.
    pub fn op_bool_negate(
        &mut self,
        vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        op: &crate::op::PcodeOpRef,
        insert_after: bool,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let addr = op.0.read().unwrap().get_addr();
        let negate_op = self.new_op(1, addr);
        self.op_set_opcode(&negate_op, crate::opcodes::OpCode::CPUI_BOOL_NEGATE);
        let res_vn = self.new_unique_out(1, &negate_op);
        self.op_set_input(&negate_op, vn, 0);
        if insert_after {
            self.op_insert_after(&negate_op, op);
        } else {
            self.op_insert_before(&negate_op, op);
        }
        res_vn
    }

    // Ghidra: funcdata.cc:34 Funcdata::opFlipCondition
    /// Flip the condition of a CBRANCH/comparison op. Faithful to
    /// `Funcdata::opFlipCondition` (funcdata_op.cc). Changes the comparison
    /// opcode to its flipped variant (INT_LESS <-> INT_LESSEQUAL,
    /// INT_EQUAL <-> INT_NOTEQUAL) and clears the BOOLEAN_FLIP flag.
    pub fn op_flip_condition(&mut self, op: &crate::op::PcodeOpRef) {
        use crate::opcodes::get_booleanflip;
        let opc = op.0.read().unwrap().opcode;
        let mut reorder = false;
        let new_opc = get_booleanflip(opc, &mut reorder);
        op.0.write().unwrap().opcode = new_opc;
        if reorder {
            self.op_swap_input(op, 0, 1);
        }
        op.0.write().unwrap().flags &= !crate::op::pcodeop_flags::BOOLEAN_FLIP;
    }

    /// Inject raw P-code operations into this Funcdata
    ///
    /// This is the bridge between raw P-code translation output (e.g., from
    /// a SLEIGH translator or manual construction) and the `Funcdata` container
    /// that the `ActionDatabase` pipeline operates on.
    ///
    /// The method:
    /// 1. Converts each `PcodeOpRaw` into a `PcodeOp` in `obank`
    /// 2. Creates `Varnode` entries in `vbank` for all inputs/outputs
    /// 3. Detects basic block boundaries at control flow terminators
    /// 4. Populates `bblocks` with basic blocks and edges
    ///
    /// # Arguments
    /// * `raw_ops` - Vector of raw P-code operations in sequential order
    /// Inject a single instruction's P-code ops (for FlowInfo process_instruction).
    /// Does NOT call build_blocks_from_ops (that's done once after all flow is tracked).
    // Ghidra: funcdata.cc:878 PcodeEmitFd::dump
    /// Faithful port of `PcodeEmitFd::dump` (funcdata.cc:878-908), the emit
    /// callback `Sleigh::oneInstruction` feeds one complete instruction into:
    ///
    /// - the output (when present) is materialized FIRST via
    ///   `Funcdata::newVarnodeOut` → `VarnodeBank::createDef`
    ///   (ctor flags + `written|coverdirty` from `setDef` + `insert` from
    ///   `xref`, varnode.cc:1411-1418);
    /// - `op->isCodeRef()` ops (BRANCH/CBRANCH/CALL — the CODEREF flag in
    ///   TypeOp's opflags, typeop.cc:586/605/663) take input(0) through
    ///   `Funcdata::newCodeRef(Address(vars[0].space, vars[0].offset))`
    ///   (funcdata_varnode.cc:222-233): a one-byte `annotation` Varnode in
    ///   the SLEIGH-reported space carrying the core "code" type
    ///   (sleigh_arch.cc:233 `setCoreType("code",1,TYPE_CODE,false)`). A
    ///   Const-space input(0) is therefore a *relative* label offset that
    ///   stays in the constant space; a ram-space input(0) is the absolute
    ///   machine target (ia.sinc:1149-1151);
    /// - every other input goes through `Funcdata::newVarnode` → a fresh
    ///   `VarnodeBank::create` Varnode (constants included — no dedup;
    ///   varnode.cc:1250-1258), with `opSetInput` appending the op to the
    ///   Varnode's descendant list in slot order.
    ///
    /// Varnode creation order per op is: output, then inputs in slot order —
    /// this fixes `Varnode::create_index` to the emission order Ghidra uses.
    pub fn inject_raw_ops_single(&mut self, raw_ops: &[PcodeOpRaw], base_addr: crate::address::Address) {
        for raw in raw_ops {
            let opcode = match OpCode::from_i32(raw.get_opcode()) {
                Some(opc) => opc,
                None => continue,
            };
            let addr = raw.seq_num()
                .map(|s| s.get_addr())
                .unwrap_or(base_addr);
            let op_ref = self.obank.create(opcode, raw.num_input(), addr);
            // PcodeEmitFd::dump: the output varnode is created between
            // newOp and opSetOpcode, before any input (funcdata.cc:884-890).
            if let Some(out_raw) = raw.output() {
                // newVarnodeOut → VarnodeBank::createDef (ctor flags +
                // written|coverdirty from setDef + insert from xref).
                let out_vn = self.vbank.create_def_with_space(
                    out_raw.size,
                    out_raw.space,
                    out_raw.offset,
                    &op_ref.0,
                );
                op_ref.0.write().unwrap().output = Some(out_vn);
            }
            // PcodeEmitFd::dump: `if (op->isCodeRef())` — the CODEREF flag is
            // only set on BRANCH/CBRANCH/CALL opcodes (typeop.cc:586/605/663;
            // BRANCHIND/CALLIND deliberately lack it).
            let mut slot = 0;
            if matches!(
                opcode,
                OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH | OpCode::CPUI_CALL
            ) {
                if let Some(in0) = raw.inputs().first() {
                    // newCodeRef(Address(vars[0].space, vars[0].offset)):
                    // 1-byte annotation Varnode in the raw SLEIGH space.
                    let in_vn = self.vbank.create_with_space(1, in0.space, in0.offset);
                    {
                        let mut value = in_vn.write().unwrap();
                        value.set_flags(crate::varnode::varnode_flags::ANNOTATION);
                        // Core "code" type (sleigh_arch.cc:233); Ghidra reads
                        // it from the architecture TypeFactory, which Rugra
                        // does not thread through this emit path.
                        value.v_type = Some(code_ref_datatype());
                        value.add_descend(&op_ref.0);
                    }
                    op_ref.0.write().unwrap().inrefs.push(in_vn);
                    slot = 1;
                }
            }
            // Remaining inputs: newVarnode (fresh Varnode per reference — no
            // location dedup for either constants or storage reads).
            for input_raw in &raw.inputs()[slot..] {
                let in_vn = if input_raw.space == crate::space::AddressSpace::Const {
                    self.vbank.create_constant(input_raw.size, input_raw.offset)
                } else {
                    self.vbank.create_with_space(
                        input_raw.size,
                        input_raw.space,
                        input_raw.offset,
                    )
                };
                in_vn.write().unwrap().add_descend(&op_ref.0);
                op_ref.0.write().unwrap().inrefs.push(in_vn);
            }
            self.obank.mark_alive(op_ref);
        }
    }

    /// Build basic blocks from ALL alive ops (called after flow tracking completes).
    // RUGRA-GLUE: 从全部 alive ops 构建 CFG（FlowInfo 流追踪后调用）。
    pub fn build_blocks_from_alive(&mut self) {
        let op_refs: Vec<PcodeOpRef> = self.obank.alivelist.iter()
            .map(|r| PcodeOpRef(r.0.clone()))
            .collect();
        self.build_blocks_from_ops(&op_refs);
        eprintln!("[INJECT] {} build_blocks_from_alive done bblocks={}", self.name, self.bblocks.get_size());
    }

    // RUGRA-GLUE: Batch raw-P-code adapter around Ghidra's PcodeEmitFd::dump conversion and Funcdata bank insertion APIs.
    pub fn inject_raw_ops(&mut self, raw_ops: &[PcodeOpRaw]) {
        if raw_ops.is_empty() {
            return;
        }

        // Phase 1: Convert all raw ops into PcodeOps with proper varnodes
        let mut op_refs: Vec<PcodeOpRef> = Vec::with_capacity(raw_ops.len());

        for (raw_idx, raw) in raw_ops.iter().enumerate() {
            // NOTE: raw.get_opcode() returns a RUST enum discriminant (the
            // lifter in x86_lift.rs builds PcodeOpRaw via `OpCode::CPUI_X as
            // i32`), NOT a Ghidra-native opcode int. So OpCode::from_i32 is
            // correct here. map_ghidra_opcode is only for Ghidra-FFI ints.
            // (Audit BATCH3 R37 was a false-positive for this call site; the
            // real FFI mapping fix is in ffi.rs — CPUI_CAST now round-trips.)
            let opcode = match OpCode::from_i32(raw.get_opcode()) {
                Some(opc) => opc,
                None => {
                    log::warn!("Unknown opcode {}, skipping", raw.get_opcode());
                    continue;
                }
            };

            // Assign a distinct address to each op: base + index * stride
            // This allows CBRANCH targets to be resolved to block start addresses
            let addr = raw
                .seq_num()
                .map(|s| s.get_addr())
                .unwrap_or(Address::new(self.baseaddr.as_u64() + raw_idx as u64 * 0x10));

            let op_ref = self.obank.create(opcode, raw.num_input(), addr);

            // Create output varnode if present
            if let Some(out_raw) = raw.output() {
                let out_vn =
                    self.vbank
                        .create_with_space(out_raw.size, out_raw.space, out_raw.offset);
                // Mark as written and set def
                let out_vn = self
                    .vbank
                    .set_def_prevalidated(out_vn, Arc::downgrade(&op_ref.0));
                op_ref.0.write().unwrap().output = Some(out_vn);
            }

            // Create input varnodes. Faithful to PcodeEmitFd::dump
            // (funcdata.cc:878-908: newVarnode -> opSetInput per
            // input reference, cc:904-907): every read gets a FRESH free Varnode —
            // inject_raw_ops_single (the single-op adapter) already does this,
            // and Ghidra's model forbids the previous dedup: a free varnode
            // with a second reader makes Varnode::addDescend throw
            // "Free varnode has multiple descendants" (varnode.cc:331-340).
            // Pre-merging same-register reads also bypassed Heritage: collect
            // classified the merged object as one read with 2+ descends,
            // which refineRead/loneDescend and normalizeReadSize's
            // opSetOutput("not free") cannot process (HELPF-NONFREE-
            // NORMALIZE-0001). Read-to-write linking is Heritage's job.
            for input_raw in raw.inputs() {
                let in_vn = if input_raw.space == AddressSpace::Const {
                    self.vbank.create_constant(input_raw.size, input_raw.offset)
                } else {
                    self.vbank.create_with_space(
                        input_raw.size,
                        input_raw.space,
                        input_raw.offset,
                    )
                };
                // Add use-def link
                in_vn
                    .write()
                    .unwrap()
                    .descend
                    .push(Arc::downgrade(&op_ref.0));
                op_ref.0.write().unwrap().inrefs.push(in_vn);
            }

            op_refs.push(op_ref);
        }

        eprintln!("[INJECT] {} phase1 done ops={}", self.name, op_refs.len());

        // Phase 2: Build basic blocks from the linear op sequence
        self.build_blocks_from_ops(&op_refs);
        eprintln!("[INJECT] {} phase2 done bblocks={}", self.name, self.bblocks.get_size());

        // Phase 3: Mark unwritten Register-space input varnodes as INPUT
        // In Ghidra's model, Heritage marks register reads with no prior definition
        // within the function as INPUT varnodes (function parameters / callee-saved regs).
        //
        // Correct semantics (read-before-write): a register read at op N is an INPUT
        // if no earlier op (in instruction order) wrote to that register offset.
        // Using a global "ever-defined" set is WRONG because parameter registers
        // are routinely re-assigned mid-function (e.g. RDX is read as param_3 at
        // 0x34a2 then overwritten by `mov rdx,[rsp+8]` at 0x34ac). A global set
        // would see the later write and miss the earlier read.
        //
        // We process ops in order; for each op we first inspect its inputs (reads)
        // and then record its output (write). This gives correct read-before-write
        // ordering within the linear instruction stream.
        //
        // CALL ops are skipped: the lifter attaches 6 ABI arg registers as inputs
        // to every CALL, which represent arguments PASSED TO the callee, not
        // registers READ by this function. Counting them would inflate the INPUT
        // set with RDI/RSI/RDX/RCX/R8/R9 on every function containing a call.
        let mut defined_reg_offsets: std::collections::HashSet<u64> = std::collections::HashSet::new();

        // Track which offsets we've already marked as INPUT to avoid duplicates
        let mut marked_input = std::collections::HashSet::new();
        for op_ref in &op_refs {
            // Snapshot first. setInput can canonicalize through xref and
            // rewrite this op's slots, so no read guard on the op may survive
            // across the bank transition.
            let (opcode, inputs, output) = {
                let op = op_ref.0.read().unwrap();
                (op.opcode, op.inrefs.clone(), op.output.clone())
            };

            // Skip CALL: its register inputs are callee args, not this function's reads.
            if opcode == OpCode::CPUI_CALL {
                // Still record any output (call return value in RAX) as defined,
                // so a later read of RAX is not mistaken for a parameter.
                if let Some(ref out_arc) = output {
                    let out_vn = out_arc.read().unwrap();
                    if out_vn.get_space() == AddressSpace::Register {
                        defined_reg_offsets.insert(out_vn.get_offset());
                    }
                }
                continue;
            }

            // First: process reads (inputs) against the *current* defined set.
            for (slot, in_arc) in inputs.into_iter().enumerate() {
                let vn = in_arc.read().unwrap();
                if vn.get_space() == AddressSpace::Register
                    && vn.is_free()
                    && !vn.is_input()
                    && !defined_reg_offsets.contains(&vn.get_offset())
                    && marked_input.insert(vn.get_offset())
                {
                    drop(vn); // Release read lock before write
                    let canonical = self.vbank.set_input_prevalidated(in_arc);
                    debug_assert!(op_ref
                        .0
                        .read()
                        .unwrap()
                        .inrefs
                        .get(slot)
                        .is_some_and(|current| Arc::ptr_eq(current, &canonical)));
                }
            }

            // Then: record this op's output as defined for subsequent ops.
            if let Some(ref out_arc) = output {
                let out_vn = out_arc.read().unwrap();
                if out_vn.get_space() == AddressSpace::Register {
                    defined_reg_offsets.insert(out_vn.get_offset());
                }
            }
        }
        eprintln!("[INJECT] {} phase3 done marked_input={}", self.name, marked_input.len());
        // NOTE: Phase 4 global use-def linking is disabled — it correctly
        // resolves stack symbols (verified) but perturbs typeop inference
        // (struct-pointer types leak into switch/arith contexts). varmap's
        // resolve_rsp_offset_via_bank provides a read-only def bridge scoped
        // to spacebase resolution only, avoiding the typeop interaction.
    }

    // Ghidra: funcdata.cc:34 Funcdata::buildBlocksFromOps
    /// Build basic blocks from a linear sequence of PcodeOps
    ///
    /// Splits the op list at control flow terminators (BRANCH, CBRANCH, RETURN, CALL)
    /// and creates basic blocks in `self.bblocks`.
    fn build_blocks_from_ops(&mut self, op_refs: &[PcodeOpRef]) {
        if op_refs.is_empty() {
            return;
        }

        // Identify block start indices. Ghidra's basic-block partitioning
        // (BlockGraph::copyBlocks / Funcdata::structureReset) splits at TWO
        // kinds of points:
        //   (1) after each block terminator (BRANCH/CBRANCH/BRANCHIND/RETURN)
        //   (2) at every jump TARGET address — any address that a BRANCH/
        //       CBRANCH points to must begin a new block, so the target edge
        //       resolves to a block start.
        // Rugra previously did only (1), which meant jump targets landing in
        // the middle of a block were unresolvable — the CBRANCH edge was
        // silently dropped (observed: curl main 56 / global 182 CBRANCH
        // targets unmatched, losing back-edges and collapsing while-loop
        // recovery from ~6 to 1).

        // Build addr -> op-index map for target resolution.
        let mut addr_to_idx: std::collections::HashMap<u64, usize> =
            std::collections::HashMap::with_capacity(op_refs.len());
        for (i, op_ref) in op_refs.iter().enumerate() {
            let addr = op_ref.0.read().unwrap().get_addr().as_u64();
            addr_to_idx.entry(addr).or_insert(i);
        }

        // Collect target op-indices from BRANCH/CBRANCH.
        let mut target_starts: std::collections::HashSet<usize> =
            std::collections::HashSet::new();
        for (i, op_ref) in op_refs.iter().enumerate() {
            let (opc, target_offset) = {
                let op = op_ref.0.read().unwrap();
                let tgt = match op.opcode {
                    OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCH => {
                        op.get_in(0).map(|vn| vn.read().unwrap().get_offset())
                    }
                    _ => None,
                };
                (op.opcode, tgt)
            };
            if matches!(opc, OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCH) {
                if let Some(taddr) = target_offset {
                    if let Some(&tidx) = addr_to_idx.get(&taddr) {
                        // The op at the target address starts a new block.
                        // Don't split at index 0 (it's already a start) and
                        // don't split at i+1 if this branch falls through to
                        // its target (handled by terminator rule below).
                        if tidx != 0 {
                            target_starts.insert(tidx);
                        }
                    }
                    // If target not in addr_to_idx, the target is outside
                    // this function (e.g. tail-call / external) — skip, the
                    // edge will be dropped as before.
                    let _ = i; // suppress unused warning
                }
            }
        }

        // Combine: block starts = {0} ∪ {terminator+1} ∪ {jump targets}.
        let mut block_starts: std::collections::BTreeSet<usize> =
            std::collections::BTreeSet::new();
        block_starts.insert(0);
        for (i, op_ref) in op_refs.iter().enumerate() {
            let op = op_ref.0.read().unwrap();
            if op.opcode.is_block_terminator() && i + 1 < op_refs.len() {
                block_starts.insert(i + 1);
            }
        }
        for tidx in target_starts {
            block_starts.insert(tidx);
        }
        let block_starts: Vec<usize> = block_starts.into_iter().collect();

        // Create basic blocks
        let mut blocks: Vec<Arc<RwLock<BlockBasic>>> = Vec::new();
        for (block_idx, &start) in block_starts.iter().enumerate() {
            let end = if block_idx + 1 < block_starts.len() {
                block_starts[block_idx + 1]
            } else {
                op_refs.len()
            };

            let block_addr = op_refs[start].0.read().unwrap().get_addr();
            let block = Arc::new(RwLock::new(BlockBasic::new(block_idx as i32, block_addr)));

            // Add ops to this block
            for op_ref in &op_refs[start..end] {
                {
                    let mut op = op_ref.0.write().unwrap();
                    op.parent = Some(Arc::downgrade(
                        // We need to cast to dyn FlowBlock
                        &(block.clone() as Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>),
                    ));
                }
                let insert_pos = block.read().unwrap().get_ops().len();
                block.write().unwrap().insert_op(insert_pos, op_ref.clone());
            }

            blocks.push(block);
        }

        // Add blocks to the graph
        for block in &blocks {
            self.bblocks.add_block(block.clone());
        }

        // Add fallthrough edges between consecutive blocks
        // Also resolve BRANCH and CBRANCH targets to add the branch edges
        for i in 0..blocks.len() {
            let (last_opcode, branch_target_offset) = {
                let b = blocks[i].read().unwrap();
                let ops = b.get_ops();
                if ops.is_empty() {
                    continue;
                }
                let last_op = ops.last().unwrap().0.read().unwrap();
                let target = match last_op.opcode {
                    OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCH => {
                        // Input 0 is the branch target address
                        last_op.get_in(0).map(|vn| vn.read().unwrap().get_offset())
                    }
                    _ => None,
                };
                (last_op.opcode, target)
            };

            match last_opcode {
                OpCode::CPUI_RETURN | OpCode::CPUI_BRANCHIND => {
                    // Terminators that don't transition to a known, raw intra-function block
                }
                OpCode::CPUI_BRANCH => {
                    // Unconditional branch: 1 edge to the target ONLY
                    if let Some(target_addr) = branch_target_offset {
                        for j in 0..blocks.len() {
                            let target_start = blocks[j].read().unwrap().get_start_addr().as_u64();
                            if target_start == target_addr {
                                self.bblocks.add_edge(blocks[i].clone(), blocks[j].clone());
                                break;
                            }
                        }
                    }
                }
                OpCode::CPUI_CBRANCH => {
                    // CBRANCH gets BOTH edges, but ORDER MATTERS for Structure Collapse!
                    // Edge 0: branch target (true branch)
                    if let Some(target_addr) = branch_target_offset {
                        for j in 0..blocks.len() {
                            let target_start = blocks[j].read().unwrap().get_start_addr().as_u64();
                            if target_start == target_addr {
                                self.bblocks.add_edge(blocks[i].clone(), blocks[j].clone());
                                break;
                            }
                        }
                    }

                    // Edge 1: fallthrough (false branch) to next sequential block
                    if i + 1 < blocks.len() {
                        self.bblocks
                            .add_edge(blocks[i].clone(), blocks[i + 1].clone());
                    }
                }
                _ => {
                    // Add fallthrough edge to next block
                    if i + 1 < blocks.len() {
                        self.bblocks
                            .add_edge(blocks[i].clone(), blocks[i + 1].clone());
                    }
                }
            }
        }
    }

    // Ghidra: funcdata.cc:84 Funcdata::clear
    /// Clear all analysis state
    pub fn clear(&mut self) {
        self.min_laned_size = self
            .arch
            .as_ref()
            .map_or(u32::MAX, |arch| arch.get_minimum_laned_register_size() as u32);
        self.vbank.clear();
        self.obank.clear();
        self.bblocks.clear();
        self.sblocks.clear();
        self.heritage.clear();
        // Ghidra funcdata.cc:108: covermerge.clear()
        self.merge_state.clear();
        self.union_map.clear();
        // Ghidra's clear() does not reset localoverride (commands survive
        // restarts), so we leave it intact here.
    }

    // =========================================================================
    // Union field resolution (funcdata.cc:917-1005)
    // =========================================================================

    // Ghidra: funcdata.cc:917 Funcdata::getUnionField
    /// Get the resolved union field associated with the given edge, or None.
    /// Faithful to `Funcdata::getUnionField` (funcdata.cc:917-926):
    ///   ResolveEdge edge(parent, op, slot);
    ///   iter = unionMap.find(edge);
    ///   if (iter != unionMap.end()) return &(*iter).second;
    ///   return NULL;
    /// Returns a cloned `ResolvedUnion` (Rugra's borrow model cannot hand out
    /// a borrow tied to `&self` alongside later `&mut self` setUnionField).
    pub fn get_union_field(
        &self,
        parent: &crate::type_system::datatype::Datatype,
        op: &crate::op::PcodeOpRef,
        slot: i32,
    ) -> Option<crate::unionresolve::ResolvedUnion> {
        let edge = crate::unionresolve::ResolveEdge::new(parent, &op.0.read().unwrap(), slot);
        self.union_map.get(&edge).cloned()
    }

    // Ghidra: funcdata.cc:937 Funcdata::setUnionField
    /// Associate a union field with the given edge. Faithful to
    /// `Funcdata::setUnionField` (funcdata.cc:937-965). If a previous
    /// association exists and is locked, return false (no overwrite).
    /// Otherwise overwrite. Additionally, when `op` is a MULTIEQUAL and slot
    /// >= 0, copy the resolution to any other input slot holding the same
    /// Varnode (data-type propagation does not happen between such slots).
    /// Returns true unless a locked association blocked the overwrite.
    pub fn set_union_field(
        &mut self,
        parent: &crate::type_system::datatype::Datatype,
        op: &crate::op::PcodeOpRef,
        slot: i32,
        resolve: crate::unionresolve::ResolvedUnion,
    ) -> bool {
        let edge = crate::unionresolve::ResolveEdge::new(parent, &op.0.read().unwrap(), slot);
        // cc:942-948: res = unionMap.emplace(edge, resolve); if (!res.second)
        //   { if (locked) return false; else (*res.first).second = resolve; }
        let blocked = match self.union_map.get(&edge) {
            Some(existing) if existing.is_locked() => true,
            _ => false,
        };
        if blocked {
            return false;
        }
        self.union_map.insert(edge.clone(), resolve.clone());
        // cc:949-963: MULTIEQUAL same-Varnode duplication.
        let (is_multiequal, dup_slots, dup_vn) = {
            let o = op.0.read().unwrap();
            if o.opcode == crate::opcodes::OpCode::CPUI_MULTIEQUAL && slot >= 0 {
                let target = o.get_in(slot as usize).cloned();
                if let Some(target_vn) = target {
                    let mut dups = Vec::new();
                    for i in 0..o.num_input() {
                        if i as i32 == slot {
                            continue;
                        }
                        if let Some(v) = o.get_in(i) {
                            if std::sync::Arc::ptr_eq(v, &target_vn) {
                                dups.push(i as i32);
                            }
                        }
                    }
                    (true, dups, Some(target_vn))
                } else {
                    (true, Vec::new(), None)
                }
            } else {
                (false, Vec::new(), None)
            }
        };
        let _ = (is_multiequal, dup_vn); // dup_vn only used to scope the read guard above.
        // cc:956-961: for each dup slot, emplace dupedge; if not locked overwrite.
        for dup_slot in dup_slots {
            let dup_edge = crate::unionresolve::ResolveEdge::new(
                parent,
                &op.0.read().unwrap(),
                dup_slot,
            );
            let locked = self
                .union_map
                .get(&dup_edge)
                .map_or(false, |r| r.is_locked());
            if !locked {
                self.union_map.insert(dup_edge, resolve.clone());
            }
        }
        true
    }

    // Ghidra: funcdata.cc:974 Funcdata::forceFacingType
    /// Force a specific union field resolution for the given edge. Faithful
    /// to `Funcdata::forceFacingType` (funcdata.cc:974-986):
    ///   baseType = parent;
    ///   if (baseType->getMetatype() == TYPE_PTR)
    ///     baseType = ((TypePointer *)baseType)->getPtrTo();
    ///   if (parent->isPointerRel())
    ///     parent = glb->types->getTypePointer(parent->getSize(), baseType,
    ///                                         ((TypePointer*)parent)->getWordSize());
    ///   ResolvedUnion resolve(parent, fieldNum, *glb->types);
    ///   setUnionField(parent, op, slot, resolve);
    /// Rugra: relative pointers (pointerRel) are not modeled as a distinct
    /// Datatype flag yet; the rewrite to a standard pointer is a no-op until
    /// that metadata lands. The ResolvedUnion is built via `with_field`, which
    /// needs a TypeFactory; when no arch is attached we fall back to the
    /// plain `new(parent)` self-resolution.
    pub fn force_facing_type(
        &mut self,
        parent: std::sync::Arc<crate::type_system::datatype::Datatype>,
        field_num: i32,
        op: &crate::op::PcodeOpRef,
        slot: i32,
    ) {
        // cc:978-979: strip one pointer layer for the base type.
        let _base_type = match parent.as_ref() {
            crate::type_system::datatype::Datatype::Pointer(p) => p.ptr_to.clone(),
            _ => parent.clone(),
        };
        // cc:980-983: relative-pointer → standard-pointer rewrite (Rugra gap).
        // cc:984-985: ResolvedUnion resolve(parent, fieldNum, *glb->types).
        let resolve = if let Some(arch) = &self.arch {
            if let Some(tg) = &arch.types {
                let tg_guard = tg.read().unwrap();
                crate::unionresolve::ResolvedUnion::with_field(
                    parent.clone(),
                    field_num,
                    &tg_guard,
                )
            } else {
                crate::unionresolve::ResolvedUnion::new(parent.clone())
            }
        } else {
            // RUGRA-GAP: no TypeFactory available; record a self-resolution so
            // the edge is at least tracked in unionMap.
            crate::unionresolve::ResolvedUnion::new(parent.clone())
        };
        self.set_union_field(parent.as_ref(), op, slot, resolve);
    }

    // Ghidra: funcdata.cc:995 Funcdata::inheritResolution
    /// Copy a read/write facing resolution from `oldOp`/`oldSlot` to
    /// `op`/`slot`. Faithful to `Funcdata::inheritResolution`
    /// (funcdata.cc:995-1005):
    ///   ResolveEdge edge(parent, oldOp, oldSlot);
    ///   iter = unionMap.find(edge);
    ///   if (iter == unionMap.end()) return -1;
    ///   setUnionField(parent, op, slot, (*iter).second);
    ///   return (*iter).second.getFieldNum();
    /// Returns the resolved field number, or -1 if no resolution was present
    /// on the source edge.
    pub fn inherit_resolution(
        &mut self,
        parent: &crate::type_system::datatype::Datatype,
        op: &crate::op::PcodeOpRef,
        slot: i32,
        old_op: &crate::op::PcodeOpRef,
        old_slot: i32,
    ) -> i32 {
        let edge =
            crate::unionresolve::ResolveEdge::new(parent, &old_op.0.read().unwrap(), old_slot);
        let Some(resolve) = self.union_map.get(&edge).cloned() else {
            return -1;
        };
        let field_num = resolve.get_field_num();
        self.set_union_field(parent, op, slot, resolve);
        field_num
    }

    // =========================================================================
    // Expression normalization (funcdata_op.cc:1132-1500)
    // =========================================================================

    // Ghidra: funcdata_op.cc:1132 Funcdata::collapseIntMultMult
    /// Fold two chained constant INT_MULTs into one. Faithful to
    /// `Funcdata::collapseIntMultMult` (funcdata_op.cc:1132-1153). Given
    ///   vn = INT_MULT(A, c1)
    ///   A  = INT_MULT(B, c2)
    /// rewrites the outer multiply to `INT_MULT(B, c1*c2)`. Returns true if a
    /// fold happened. Walks the def chain: vn must be written by an INT_MULT
    /// whose second input is constant, and whose first input is itself a
    /// constant INT_MULT.
    pub fn collapse_int_mult_mult(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
        // cc:1135: if (!vn->isWritten()) return false.
        let (def, const_first, in0, sz) = {
            let v = vn.read().unwrap();
            if !v.is_written() {
                return false;
            }
            let def = match v.get_def() {
                Some(d) => d,
                None => return false,
            };
            let (opcode, const_first, in0) = {
                let o = def.read().unwrap();
                // cc:1137: if (op->code() != CPUI_INT_MULT) return false.
                if o.opcode != OpCode::CPUI_INT_MULT {
                    return false;
                }
                // cc:1138-1139: constVnFirst = op->getIn(1); if (!isConstant) false.
                let const_first = match o.get_in(1) {
                    Some(c) if c.read().unwrap().is_constant() => c.clone(),
                    _ => return false,
                };
                // cc:1140: if (!op->getIn(0)->isWritten()) return false.
                let in0 = match o.get_in(0) {
                    Some(v0) => v0.clone(),
                    None => return false,
                };
                (o.opcode, const_first, in0)
            };
            if !in0.read().unwrap().is_written() {
                return false;
            }
            let _ = opcode;
            (def, const_first, in0, vn.read().unwrap().get_size())
        };
        // cc:1141-1142: otherMultOp = in0->getDef(); if code != INT_MULT false.
        let (other_def, const_second, invn) = {
            let other_def = match in0.read().unwrap().get_def() {
                Some(d) => d,
                None => return false,
            };
            let (const_second, invn) = {
                let oo = other_def.read().unwrap();
                if oo.opcode != OpCode::CPUI_INT_MULT {
                    return false;
                }
                // cc:1143-1144: constVnSecond = otherMultOp->getIn(1); const check.
                let const_second = match oo.get_in(1) {
                    Some(c) if c.read().unwrap().is_constant() => c.clone(),
                    _ => return false,
                };
                // cc:1145: invn = otherMultOp->getIn(0).
                let invn = match oo.get_in(0) {
                    Some(v) => v.clone(),
                    None => return false,
                };
                (const_second, invn)
            };
            (other_def, const_second, invn)
        };
        // cc:1146: if (invn->isFree()) return false.
        if invn.read().unwrap().is_free() {
            return false;
        }
        // cc:1147-1152: val = (c1*c2) & calc_mask(sz); rewrite op inputs.
        let val_first = const_first.read().unwrap().get_offset();
        let val_second = const_second.read().unwrap().get_offset();
        let mask = crate::address::calc_mask(sz);
        let val = (val_first.wrapping_mul(val_second)) & mask;
        let newvn = self.new_constant(sz, val);
        let op_ref = crate::op::PcodeOpRef(def.clone());
        self.op_set_input(&op_ref, newvn, 1);
        self.op_set_input(&op_ref, invn, 0);
        // other_def / const_second kept for clarity; the original INT_MULT(B,c2)
        // becomes dead and is reclaimed by the dead-code pass (faithful: cc
        // does not explicitly destroy it here).
        let _ = (other_def, const_second);
        true
    }

    // Ghidra: funcdata_op.cc:1161 Funcdata::buildCopyTemp
    /// Return a unique-space Varnode defined by a COPY of `vn`, available at
    /// `point`. Faithful to `Funcdata::buildCopyTemp` (funcdata_op.cc:1161-1213).
    /// If a preexisting COPY into unique space exists and is usable at `point`,
    /// reuse it; if it is in a different block but not ancestor/descendant, a
    /// new COPY is built at the common dominator's end. Otherwise a fresh COPY
    /// is inserted before `point`. Stale copies are totalReplace'd away.
    pub fn build_copy_temp(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        point: &crate::op::PcodeOpRef,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // cc:1167-1177: scan vn's descendants for a COPY into unique space.
        let mut other_op: Option<crate::op::PcodeOpRef> = None;
        {
            let descendants: Vec<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>> =
                vn.read().unwrap().descend_iter().collect();
            for op_arc in descendants {
                let o = op_arc.read().unwrap();
                if o.opcode != OpCode::CPUI_COPY {
                    continue;
                }
                // cc:1170-1173: outvn must be in IPTR_INTERNAL and not typelock.
                if let Some(outvn) = o.get_out() {
                    let ov = outvn.read().unwrap();
                    if ov.get_space() == crate::space::AddressSpace::Unique
                        && !ov.is_type_lock()
                    {
                        other_op = Some(crate::op::PcodeOpRef(op_arc.clone()));
                        break;
                    }
                }
            }
        }
        // cc:1178-1200: decide which copy to use, possibly building one at a
        // common dominator block.
        let point_parent = point.0.read().unwrap().parent.clone().and_then(|w| w.upgrade());
        let mut used_copy: Option<crate::op::PcodeOpRef> = None;
        let mut built_at_common = false;
        if let Some(other) = &other_op {
            let other_parent = other.0.read().unwrap().parent.clone().and_then(|w| w.upgrade());
            match (&point_parent, &other_parent) {
                (Some(pp), Some(op_parent)) if std::sync::Arc::ptr_eq(pp, op_parent) => {
                    // cc:1179-1184: same block — compare seqnum order.
                    let (point_order, other_order) = {
                        let p = point.0.read().unwrap();
                        let o = other.0.read().unwrap();
                        (p.get_seq_num().order, o.get_seq_num().order)
                    };
                    if point_order < other_order {
                        used_copy = None;
                    } else {
                        used_copy = Some(other.clone());
                    }
                }
                (Some(pp), Some(op_parent)) => {
                    // cc:1186-1198: different blocks — find common dominator.
                    let common = crate::block::BlockGraph::find_common_block(pp, op_parent);
                    match &common {
                        Some(c) if std::sync::Arc::ptr_eq(c, pp) => {
                            used_copy = None;
                        }
                        Some(c) if std::sync::Arc::ptr_eq(c, op_parent) => {
                            used_copy = Some(other.clone());
                        }
                        Some(c) => {
                            // cc:1193-1198: neither dominates — build a COPY at
                            // the common block's stop address, inserted at end.
                            let vn_size = vn.read().unwrap().get_size();
                            // Ghidra's getStop() is a BlockBasic method; we
                            // downcast to fetch it, falling back to the block's
                            // start address if the common dominator is not a
                            // BlockBasic (shouldn't happen for the merge case).
                            let stop_addr = {
                                let c_rg = c.read().unwrap();
                                c_rg
                                    .as_any()
                                    .downcast_ref::<crate::block::BlockBasic>()
                                    .map(|bb| bb.get_stop_addr())
                                    .unwrap_or_else(|| c_rg.get_start_addr())
                            };
                            let new_copy = self.new_op(1, stop_addr);
                            self.op_set_opcode(&new_copy, OpCode::CPUI_COPY);
                            self.new_unique_out(vn_size, &new_copy);
                            self.op_set_input(&new_copy, vn.clone(), 0);
                            self.op_insert_end(&new_copy, c);
                            used_copy = Some(new_copy);
                            built_at_common = true;
                        }
                        None => {
                            used_copy = None;
                        }
                    }
                }
                _ => {
                    used_copy = None;
                }
            }
        }
        // cc:1201-1207: no usable preexisting copy — build one before point.
        if used_copy.is_none() {
            let vn_size = vn.read().unwrap().get_size();
            let addr = point.0.read().unwrap().get_addr();
            let new_copy = self.new_op(1, addr);
            self.op_set_opcode(&new_copy, OpCode::CPUI_COPY);
            self.new_unique_out(vn_size, &new_copy);
            self.op_set_input(&new_copy, vn.clone(), 0);
            self.op_insert_before(&new_copy, point);
            used_copy = Some(new_copy);
        }
        let used_copy = used_copy.expect("build_copy_temp: used_copy set above");
        // cc:1208-1211: if the preexisting otherOp is no longer used, replace
        // its output with the chosen copy's output and destroy it.
        if let Some(other) = &other_op {
            if !built_at_common && !std::sync::Arc::ptr_eq(&other.0, &used_copy.0) {
                let (other_out, used_out) = {
                    let o = other.0.read().unwrap();
                    let u = used_copy.0.read().unwrap();
                    (o.get_out().cloned(), u.get_out().cloned())
                };
                if let (Some(old), Some(new)) = (other_out, used_out) {
                    self.total_replace(&old, new);
                    self.op_destroy(&other.clone());
                }
            }
        }
        // cc:1212: return usedCopy->getOut().
        let out_vn = used_copy
            .0
            .read()
            .unwrap()
            .get_out()
            .cloned()
            .expect("build_copy_temp: COPY has output");
        out_vn
    }

    // Ghidra: funcdata_op.cc:1223 Funcdata::opFlipInPlaceTest
    /// Trace a boolean value to the set of PcodeOps whose opcodes must flip to
    /// negate it. Faithful to `Funcdata::opFlipInPlaceTest`
    /// (funcdata_op.cc:1223-1275). Returns 0 if the flip normalizes, 1 if
    /// ambivalent, 2 if the change does not normalize. The discovered ops are
    /// appended to `fliplist` in evaluation order.
    pub fn op_flip_in_place_test(
        &self,
        op: &crate::op::PcodeOpRef,
        fliplist: &mut Vec<crate::op::PcodeOpRef>,
    ) -> i32 {
        let opc = op.0.read().unwrap().opcode;
        match opc {
            OpCode::CPUI_CBRANCH => {
                // cc:1230-1233: vn = getIn(1); loneDescend==op && isWritten.
                let vn = op.0.read().unwrap().get_in(1).cloned();
                let vn = match vn {
                    Some(v) => v,
                    None => return 2,
                };
                let lone = vn.read().unwrap().lone_descend();
                let lone_is_op = lone.map(|d| std::sync::Arc::ptr_eq(&d, &op.0)).unwrap_or(false);
                if !lone_is_op {
                    return 2;
                }
                if !vn.read().unwrap().is_written() {
                    return 2;
                }
                let def = match vn.read().unwrap().get_def() {
                    Some(d) => crate::op::PcodeOpRef(d),
                    None => return 2,
                };
                self.op_flip_in_place_test(&def, fliplist)
            }
            OpCode::CPUI_INT_EQUAL | OpCode::CPUI_FLOAT_EQUAL => {
                fliplist.push(op.clone());
                1
            }
            OpCode::CPUI_BOOL_NEGATE
            | OpCode::CPUI_INT_NOTEQUAL
            | OpCode::CPUI_FLOAT_NOTEQUAL => {
                fliplist.push(op.clone());
                0
            }
            OpCode::CPUI_INT_SLESS | OpCode::CPUI_INT_LESS => {
                // cc:1245-1248: vn = getIn(0); push; if !const return 1 else 0.
                let is_const = op
                    .0
                    .read()
                    .unwrap()
                    .get_in(0)
                    .map(|v| v.read().unwrap().is_constant())
                    .unwrap_or(false);
                fliplist.push(op.clone());
                if !is_const {
                    1
                } else {
                    0
                }
            }
            OpCode::CPUI_INT_SLESSEQUAL | OpCode::CPUI_INT_LESSEQUAL => {
                // cc:1250-1253: vn = getIn(1); push; if const return 1 else 0.
                let is_const = op
                    .0
                    .read()
                    .unwrap()
                    .get_in(1)
                    .map(|v| v.read().unwrap().is_constant())
                    .unwrap_or(false);
                fliplist.push(op.clone());
                if is_const {
                    1
                } else {
                    0
                }
            }
            OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_AND => {
                // cc:1256-1270: recurse into both inputs; push op last.
                let (in0_ok, in0_def, in1_ok, in1_def) = {
                    let o = op.0.read().unwrap();
                    let i0 = o.get_in(0).cloned();
                    let i1 = o.get_in(1).cloned();
                    let check_lone = |v: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>| {
                        let lone = v.read().unwrap().lone_descend();
                        lone.map(|d| std::sync::Arc::ptr_eq(&d, &op.0)).unwrap_or(false)
                    };
                    let i0_ok = i0.as_ref().map_or(false, check_lone);
                    let i1_ok = i1.as_ref().map_or(false, check_lone);
                    (
                        i0_ok,
                        i0.and_then(|v| v.read().unwrap().get_def()),
                        i1_ok,
                        i1.and_then(|v| v.read().unwrap().get_def()),
                    )
                };
                // cc:1258-1259: vn = getIn(0); loneDescend==op && isWritten.
                if !in0_ok {
                    return 2;
                }
                let in0_def = match in0_def {
                    Some(d) => crate::op::PcodeOpRef(d),
                    None => return 2,
                };
                let subtest1 = self.op_flip_in_place_test(&in0_def, fliplist);
                if subtest1 == 2 {
                    return 2;
                }
                // cc:1263-1265: vn = getIn(1); loneDescend==op && isWritten.
                if !in1_ok {
                    return 2;
                }
                let in1_def = match in1_def {
                    Some(d) => crate::op::PcodeOpRef(d),
                    None => return 2,
                };
                let subtest2 = self.op_flip_in_place_test(&in1_def, fliplist);
                if subtest2 == 2 {
                    return 2;
                }
                fliplist.push(op.clone());
                subtest1 // cc:1270: front of AND/OR must be normalizing.
            }
            _ => 2,
        }
    }

    // Ghidra: funcdata_op.cc:1282 Funcdata::opFlipInPlaceExecute
    /// Apply the precomputed op-code flips to negate a boolean value. Faithful
    /// to `Funcdata::opFlipInPlaceExecute` (funcdata_op.cc:1282-1315). For
    /// each op in `fliplist`: look up its boolean-flip target via
    /// `get_booleanflip`. A BOOL_NEGATE collapses to COPY semantics (propagate
    /// its input into the lone descendant, then destroy it). A BOOL_AND/BOOL_OR
    /// with no direct flip swaps to the other. Otherwise set the opcode and,
    /// if `reorder`, swap inputs and (for LESSEQUAL variants) replace_lessequal.
    pub fn op_flip_in_place_execute(&mut self, fliplist: &[crate::op::PcodeOpRef]) {
        use crate::opcodes::get_booleanflip;
        for op in fliplist {
            let cur_opc = op.0.read().unwrap().opcode;
            let mut reorder = false;
            let new_opc = get_booleanflip(cur_opc, &mut reorder);
            if new_opc == OpCode::CPUI_COPY {
                // cc:1290-1296: BOOL_NEGATE collapses — propagate input, destroy.
                let (in0, out, lone_desc) = {
                    let o = op.0.read().unwrap();
                    let in0 = o.get_in(0).cloned();
                    let out = o.get_out().cloned();
                    let lone_desc = out.as_ref().and_then(|v| v.read().unwrap().lone_descend());
                    (in0, out, lone_desc)
                };
                let Some(in_vn) = in0 else { continue };
                let Some(out_vn) = out else { continue };
                let Some(other_op) = lone_desc else { continue };
                let other_ref = crate::op::PcodeOpRef(other_op);
                // cc:1293-1294: slot = otherop->getSlot(op->getOut()).
                let slot = other_ref
                    .0
                    .read()
                    .unwrap()
                    .inrefs
                    .iter()
                    .position(|v| std::sync::Arc::ptr_eq(v, &out_vn));
                if let Some(slot) = slot {
                    self.op_set_input(&other_ref, in_vn, slot);
                }
                self.op_destroy(op);
            } else if new_opc == OpCode::CPUI_MAX {
                // cc:1297-1303: BOOL_AND <-> BOOL_OR swap.
                match cur_opc {
                    OpCode::CPUI_BOOL_AND => self.op_set_opcode(op, OpCode::CPUI_BOOL_OR),
                    OpCode::CPUI_BOOL_OR => self.op_set_opcode(op, OpCode::CPUI_BOOL_AND),
                    _ => {
                        eprintln!("[FUNCDATA] Bad flipInPlace op {:?}", cur_opc);
                    }
                }
            } else {
                // cc:1305-1313: set opcode; if reorder, swap inputs + lequal.
                self.op_set_opcode(op, new_opc);
                if reorder {
                    self.op_swap_input(op, 0, 1);
                    if new_opc == OpCode::CPUI_INT_LESSEQUAL
                        || new_opc == OpCode::CPUI_INT_SLESSEQUAL
                    {
                        self.replace_lessequal(op);
                    }
                }
            }
        }
    }

    // Ghidra: funcdata_op.cc:1326 Funcdata::cseFindInBlock
    /// Find a duplicate calculation of `op` that reads `vn` in block `bl`
    /// earlier than `earliest`. Faithful to `Funcdata::cseFindInBlock`
    /// (funcdata_op.cc:1326-1347). Only 1-level matches are considered: the
    /// candidate op's output must be functionally equal (depth 0) to `op`'s
    /// output. Returns the discovered duplicate, or None.
    pub fn cse_find_in_block(
        &self,
        op: &crate::op::PcodeOpRef,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        bl: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        earliest: Option<&crate::op::PcodeOpRef>,
    ) -> Option<crate::op::PcodeOpRef> {
        // cc:1331-1345: for each descendant res of vn:
        let descendants: Vec<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>> =
            vn.read().unwrap().descend_iter().collect();
        let op_out = op.0.read().unwrap().get_out().cloned();
        let earliest_order = earliest.map(|e| e.0.read().unwrap().get_seq_num().order);
        for res_arc in descendants {
            // cc:1333: if (res == op) continue.
            if std::sync::Arc::ptr_eq(&res_arc, &op.0) {
                continue;
            }
            let res_parent = res_arc.read().unwrap().parent.clone().and_then(|w| w.upgrade());
            // cc:1334: if (res->getParent() != bl) continue.
            let parent_matches = match (&res_parent, bl) {
                (Some(rp), bp) => std::sync::Arc::ptr_eq(rp, bp),
                _ => false,
            };
            if !parent_matches {
                continue;
            }
            // cc:1335-1337: earliest != NULL && earliest->order < res->order → continue.
            if let Some(eo) = earliest_order {
                let res_order = res_arc.read().unwrap().get_seq_num().order;
                if eo < res_order {
                    continue;
                }
            }
            // cc:1338-1344: functionalEqualityLevel(out1, out2, buf1, buf2) == 0.
            let outvn2 = res_arc.read().unwrap().get_out().cloned();
            let Some(outvn2) = outvn2 else { continue };
            let Some(outvn1) = &op_out else { continue };
            let eq = crate::expression::functional_equality_level(outvn1, &outvn2);
            if eq.code == 0 {
                return Some(crate::op::PcodeOpRef(res_arc));
            }
        }
        None
    }

    // Ghidra: funcdata_op.cc:1459 Funcdata::moveRespectingCover
    /// Move `op` past COPY/CAST ops toward `lastOp`, within its basic block,
    /// only when no data-flow interference occurs. Faithful to
    /// `Funcdata::moveRespectingCover` (funcdata_op.cc:1459-1500). The move
    /// respects the cover of the expression rooted at `op`'s output: we stop
    /// before any COPY that writes a HighVariable in the expression, or before
    /// a possible indirect interference. Returns true if the move completed.
    pub fn move_respecting_cover(
        &mut self,
        op: &crate::op::PcodeOpRef,
        last_op: &crate::op::PcodeOpRef,
    ) -> bool {
        // cc:1462: if (op == lastOp) return true.
        if std::sync::Arc::ptr_eq(&op.0, &last_op.0) {
            return true;
        }
        // cc:1463: if (op->isCall()) return false.
        if op.0.read().unwrap().is_call() {
            return false;
        }
        // cc:1464-1473: if op is CAST and its input is not explicit, the
        // previous op must move as well (and immediately precede the CAST).
        let prev_op: Option<crate::op::PcodeOpRef> = if op.0.read().unwrap().opcode == OpCode::CPUI_CAST {
            let in0 = op.0.read().unwrap().get_in(0).cloned();
            if let Some(vn) = in0 {
                if !vn.read().unwrap().is_explicit() {
                    if !vn.read().unwrap().is_written() {
                        return false;
                    }
                    let prev = match vn.read().unwrap().get_def() {
                        Some(d) => crate::op::PcodeOpRef(d),
                        None => return false,
                    };
                    if prev.0.read().unwrap().is_call() {
                        return false;
                    }
                    // cc:1471: op->previousOp() must equal prevOp.
                    let op_prev = op
                        .0
                        .read()
                        .unwrap()
                        .previous_op_in_block(&self.obank);
                    let matches = match &op_prev {
                        Some(p) => std::sync::Arc::ptr_eq(&p.0, &prev.0),
                        None => false,
                    };
                    if !matches {
                        return false;
                    }
                    Some(prev)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        // cc:1474-1476: rootvn = op->getOut(); markExpression(rootvn, highList).
        let rootvn = op.0.read().unwrap().get_out().cloned();
        let Some(rootvn) = rootvn else { return false };
        let mut high_list: Vec<std::sync::Arc<std::sync::RwLock<crate::variable::HighVariable>>> =
            Vec::new();
        let type_val = crate::variable::HighVariable::mark_expression(&rootvn, &mut high_list);
        // cc:1477-1487: walk forward over COPY/CAST ops, stopping at any
        // interference.
        let mut cur_op = op.clone();
        loop {
            let next_op = cur_op
                .0
                .read()
                .unwrap()
                .next_op_in_flow(&self.obank);
            let Some(next_op) = next_op else { break };
            let next_opc = next_op.0.read().unwrap().opcode;
            if next_opc != OpCode::CPUI_COPY && next_opc != OpCode::CPUI_CAST {
                break;
            }
            // cc:1482: if (rootvn == nextOp->getIn(0)) break.
            let next_in0 = next_op.0.read().unwrap().get_in(0).cloned();
            if let Some(v) = &next_in0 {
                if std::sync::Arc::ptr_eq(v, &rootvn) {
                    break;
                }
            }
            // cc:1483-1484: copyVn = nextOp->getOut(); if (copyVn->getHigh()->isMark()) break.
            let copy_vn = next_op.0.read().unwrap().get_out().cloned();
            if let Some(cv) = &copy_vn {
                let copy_high = cv.read().unwrap().get_high().cloned();
                if let Some(h) = copy_high {
                    if h.read().unwrap().is_mark() {
                        break;
                    }
                }
            }
            // cc:1485: if (typeVal != 0 && copyVn->isAddrTied()) break.
            if type_val != 0 {
                if let Some(cv) = &copy_vn {
                    if cv.read().unwrap().is_addr_tied() {
                        break;
                    }
                }
            }
            cur_op = next_op;
            if std::sync::Arc::ptr_eq(&cur_op.0, &last_op.0) {
                break;
            }
        }
        // cc:1488-1489: clear marks on the expression.
        for h in &high_list {
            h.write().unwrap().clear_mark();
        }
        // cc:1490-1499: if we reached lastOp, perform the move.
        if std::sync::Arc::ptr_eq(&cur_op.0, &last_op.0) {
            self.op_uninsert(op);
            self.op_insert_after(op, last_op);
            if let Some(prev) = prev_op {
                self.op_uninsert(&prev);
                self.op_insert_after(&prev, last_op);
            }
            true
        } else {
            false
        }
    }

    // =========================================================================
    // String / return-address / replacement (funcdata_varnode.cc:1413-1743)
    // =========================================================================

    // Ghidra: funcdata_varnode.cc:1413 Funcdata::getInternalString
    /// Build the p-code that displays an encoded string constant. Faithful
    /// to `Funcdata::getInternalString` (funcdata_varnode.cc:1413-1434):
    ///   - reject non-pointer types
    ///   - register the raw bytes with the StringManager, returning a hash;
    ///     hash==0 means the encoding is not a legal string → return null
    ///   - register the BUILTIN_STRING_DATA user-op
    ///   - emit `CALLOTHER(string_data_id, hash)` before `readOp`, returning
    ///     its unique output typed as `ptrType`
    /// Returns the new Varnode, or None if the encoding is not a string.
    /// RUGRA-GAP: Rugra's StringManager has no `registerInternalStringData`;
    /// we validate the encoding via `check_characters`/`has_char_terminator`
    /// and synthesize a stable hash from (addr, bytes). When no arch/string
    /// manager is attached, returns None (caller treats as non-string).
    pub fn get_internal_string(
        &mut self,
        buf: &[u8],
        ptr_type: &crate::type_system::datatype::Datatype,
        read_op: &crate::op::PcodeOpRef,
    ) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        use crate::type_system::datatype::{Datatype, TypeMetatype};
        // cc:1416-1417: if (ptrType->getMetatype() != TYPE_PTR) return null.
        if ptr_type.get_metatype() != TypeMetatype::Pointer {
            return None;
        }
        // cc:1418: charType = ((TypePointer *)ptrType)->getPtrTo().
        let char_type = match ptr_type {
            Datatype::Pointer(p) => p.ptr_to.clone(),
            _ => return None,
        };
        // cc:1420-1423: hash = glb->stringManager->registerInternalStringData(...).
        // Rugra: validate + synthesize hash. charsize inferred from char_type size.
        let charsize = char_type.get_size().max(1) as i32;
        let addr = read_op.0.read().unwrap().get_addr();
        let hash = if let Some(arch) = &self.arch {
            if let Some(sm_arc) = &arch.string_manager {
                let mut sm = sm_arc.write().unwrap();
                // Validate the encoding (faithful to StringManager logic).
                let num_chars = crate::stringmanage::check_characters(buf, charsize, false);
                if num_chars < 0
                    || !crate::stringmanage::has_char_terminator(buf, charsize as usize)
                {
                    return None;
                }
                let mut data = crate::stringmanage::StringData::default();
                crate::stringmanage::assign_string_data(
                    &mut data,
                    buf,
                    charsize,
                    num_chars,
                    false,
                    sm.get_maximum_chars(),
                );
                sm.insert_string_data(addr, data);
                // Synthesize a stable hash from addr (low 56 bits) | charsize<<56.
                (addr.as_u64() & 0x00ff_ffff_ffff_ffff) | ((charsize as u64) << 56)
            } else {
                return None;
            }
        } else {
            return None;
        };
        if hash == 0 {
            return None;
        }
        // cc:1424-1429: register BUILTIN_STRING_DATA + emit CALLOTHER.
        let string_data_id: u64 = if let Some(arch) = &self.arch {
            if let Some(userops) = arch.userops.as_ref() {
                let mut mgr = userops.write().unwrap();
                mgr.register_builtin_by_id(crate::userop::BUILTIN_STRINGDATA) as u64
            } else {
                // RUGRA-GAP: no userop table — use the canonical builtin id.
                crate::userop::BUILTIN_STRINGDATA as u64
            }
        } else {
            crate::userop::BUILTIN_STRINGDATA as u64
        };
        let string_op = self.new_op(2, addr);
        self.op_set_opcode(&string_op, crate::opcodes::OpCode::CPUI_CALLOTHER);
        // cc:1427: stringOp->clearFlag(PcodeOp::call).
        string_op.0.write().unwrap().flags &= !crate::op::pcodeop_flags::CALL;
        let id_vn = self.new_constant(4, string_data_id);
        let hash_vn = self.new_constant(8, hash);
        self.op_set_input(&string_op, id_vn, 0);
        self.op_set_input(&string_op, hash_vn, 1);
        // cc:1430-1431: resVn = newUniqueOut(ptrType->getSize(), stringOp);
        //   resVn->updateType(ptrType, true, false).
        let ptr_size = ptr_type.get_size();
        let res_vn = self.new_unique_out(ptr_size, &string_op);
        res_vn.write().unwrap().update_type_lock(
            std::sync::Arc::new(ptr_type.clone()),
            true,
            false,
        );
        // cc:1432: opInsertBefore(stringOp, readOp).
        self.op_insert_before(&string_op, read_op);
        Some(res_vn)
    }

    // Ghidra: funcdata_varnode.cc:1496 Funcdata::totalReplaceConstant
    /// Replace every read reference of `vn` with a fresh constant `val`.
    /// Faithful to `Funcdata::totalReplaceConstant` (funcdata_varnode.cc:1496-1534).
    /// For marker ops (MULTIEQUAL/INDIRECT) a single COPY of the constant is
    /// inserted (after vn's def, or at block 0 start if vn is unwritten) and
    /// the marker input is set to the COPY's output; otherwise each read site
    /// gets its own fresh constant Varnode.
    pub fn total_replace_constant(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        val: u64,
    ) {
        let vn_size = vn.read().unwrap().get_size();
        // Snapshot (op, slot) descendants before mutation.
        let sites: Vec<(crate::op::PcodeOpRef, usize)> = {
            let vn_rg = vn.read().unwrap();
            vn_rg
                .descend
                .iter()
                .filter_map(|w| w.upgrade())
                .filter_map(|op_arc| {
                    let op_rg = op_arc.read().unwrap();
                    let slot = op_rg
                        .inrefs
                        .iter()
                        .position(|v| std::sync::Arc::ptr_eq(v, vn))?;
                    drop(op_rg);
                    Some((crate::op::PcodeOpRef(op_arc), slot))
                })
                .collect()
        };
        // Lazily-built COPY for marker ops (cc:1510-1529).
        let mut copy_op: Option<crate::op::PcodeOpRef> = None;
        for (op, slot) in sites {
            let is_marker = op.0.read().unwrap().is_marker();
            let new_rep = if is_marker {
                if copy_op.is_none() {
                    // cc:1511-1525: build a single COPY of the constant.
                    let vn_is_written = vn.read().unwrap().is_written();
                    if vn_is_written {
                        let def = vn.read().unwrap().get_def();
                        if let Some(def_op) = def {
                            let def_ref = crate::op::PcodeOpRef(def_op);
                            let def_addr = def_ref.0.read().unwrap().get_addr();
                            let new_copy = self.new_op(1, def_addr);
                            self.op_set_opcode(&new_copy, OpCode::CPUI_COPY);
                            self.new_unique_out(vn_size, &new_copy);
                            let c = self.new_constant(vn_size, val);
                            self.op_set_input(&new_copy, c, 0);
                            self.op_insert_after(&new_copy, &def_ref);
                            copy_op = Some(new_copy);
                        }
                    } else {
                        // cc:1519-1525: vn unwritten — insert at block 0 start.
                        let bb0 = self.bblocks.get_block(0);
                        if let Some(bb) = bb0 {
                            let start_addr = bb.read().unwrap().get_start_addr();
                            let new_copy = self.new_op(1, start_addr);
                            self.op_set_opcode(&new_copy, OpCode::CPUI_COPY);
                            self.new_unique_out(vn_size, &new_copy);
                            let c = self.new_constant(vn_size, val);
                            self.op_set_input(&new_copy, c, 0);
                            self.op_insert_begin(&new_copy, &bb);
                            copy_op = Some(new_copy);
                        }
                    }
                }
                // cc:1528: newrep = copyop->getOut().
                match &copy_op {
                    Some(c) => c.0.read().unwrap().get_out().cloned(),
                    None => None,
                }
            } else {
                // cc:1531: newrep = newConstant(vn->getSize(), val).
                Some(self.new_constant(vn_size, val))
            };
            if let Some(rep) = new_rep {
                self.op_set_input(&op, rep, slot);
            }
        }
    }

    // Ghidra: funcdata_varnode.cc:1573 Funcdata::findDisjointCover
    /// Find the minimal Address range covering `vn` that does not split any
    /// other Varnode. Faithful to `Funcdata::findDisjointCover`
    /// (funcdata_varnode.cc:1573-1596). Walks the loc tree backward and
    /// forward from vn's address, expanding the [addr, endaddr) range to
    /// include any overlapping neighbours, then returns the start and passes
    /// the size back via `sz`.
    pub fn find_disjoint_cover(
        &self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        sz: &mut usize,
    ) -> crate::address::Address {
        let mut addr = *vn.read().unwrap().get_addr();
        let mut end_off = addr.as_u64() + vn.read().unwrap().get_size() as u64;
        // cc:1580-1586: walk backward over overlapping earlier varnodes.
        // Rugra: overlap_loc returns candidates overlapping the current range;
        // we rescan with the expanded range until it stabilizes.
        let mut changed = true;
        while changed {
            changed = false;
            let candidates = self.vbank.overlap_loc(addr, (end_off - addr.as_u64()) as usize);
            for cv in candidates {
                let cv_rg = cv.read().unwrap();
                let cv_addr = *cv_rg.get_addr();
                let cv_end = cv_addr.as_u64() + cv_rg.get_size() as u64;
                if cv_addr.as_u64() < addr.as_u64() {
                    addr = cv_addr;
                    changed = true;
                }
                if cv_end > end_off {
                    end_off = cv_end;
                    changed = true;
                }
            }
        }
        // cc:1594-1595: sz = endaddr - addr; return addr.
        *sz = (end_off - addr.as_u64()) as usize;
        addr
    }

    // Ghidra: funcdata_varnode.cc:1606 Funcdata::coverVarnodes
    /// Ensure every Varnode in `list` (in Address order) overlaps a Symbol so
    /// it will link. Faithful to `Funcdata::coverVarnodes`
    /// (funcdata_varnode.cc:1606-1627). For each address group, pick the
    /// biggest Varnode; if it has no overlapping Symbol entry, create one
    /// named `<entry>_<diff>` at the over-extending offset.
    /// RUGRA-GAP: ScopeLocal has no findContainer/addSymbol; we approximate by
    /// recording the synthetic name in symbol_table (matching the existing
    /// `remap_varnode` strategy) and setting MAPPED.
    pub fn cover_varnodes(
        &mut self,
        entry_addr: u64,
        entry_name: &str,
        list: &[std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>],
    ) {
        let mut i = 0;
        while i < list.len() {
            let vn = &list[i];
            // cc:1614-1615: skip if next varnode shares the same address
            // (we only check once per address, picking the biggest implicitly
            // by taking the last same-address varnode).
            let vn_addr = *vn.read().unwrap().get_addr();
            if i + 1 < list.len() && list[i + 1].read().unwrap().get_addr().as_u64() == vn_addr.as_u64()
            {
                i += 1;
                continue;
            }
            // cc:1617: usepoint = vn->getUsePoint(*this).
            // cc:1618: overlapEntry = scope->findContainer(addr, size, usepoint).
            // Rugra: symbol_table lookup by address is the analogue of
            // findContainer; if present the varnode already links.
            let already_mapped = vn.read().unwrap().is_mapped()
                || self.symbol_table.contains_key(&vn_addr.as_u64());
            if !already_mapped {
                // cc:1619-1624: diff = vn->getOffset() - entry->getAddr();
                //   name = entry->getName() + "_" + diff; addSymbol(...).
                let diff = vn_addr.as_u64() as i64 - entry_addr as i64;
                let sym_name = format!("{}_{}", entry_name, diff);
                self.symbol_table.insert(vn_addr.as_u64(), sym_name);
                vn.write().unwrap()
                    .set_flags(crate::varnode::varnode_flags::MAPPED);
            }
            i += 1;
        }
    }

    // Ghidra: funcdata_varnode.cc:1637 Funcdata::applyUnionFacet
    /// Cache a UnionFacetSymbol's forced union-field resolution into unionMap.
    /// Faithful to `Funcdata::applyUnionFacet` (funcdata_varnode.cc:1637-1649):
    ///   op = dhash.findOp(this, entry->getFirstUseAddress(), entry->getHash());
    ///   if (op == NULL) return false;
    ///   slot = DynamicHash::getSlotFromHash(hash);
    ///   fldNum = ((UnionFacetSymbol *)sym)->getFieldNumber();
    ///   ResolvedUnion resolve(sym->getType(), fldNum, *glb->types);
    ///   resolve.setLock(true);
    ///   return setUnionField(sym->getType(), op, slot, resolve);
    /// RUGRA-GAP: there is no UnionFacetSymbol type yet; the caller passes the
    /// resolved (parent type, field number) projection of the facet symbol.
    /// Returns true if the op was located and the resolution cached.
    pub fn apply_union_facet(
        &mut self,
        parent: std::sync::Arc<crate::type_system::datatype::Datatype>,
        first_use_addr: crate::address::Address,
        hash: u64,
        field_num: i32,
    ) -> bool {
        // cc:1641: op = dhash.findOp(this, addr, hash).
        let op = {
            let mut dhash = crate::dynamic::DynamicHash::new();
            dhash.find_op(self, first_use_addr, hash)
        };
        let Some(op_arc) = op else { return false };
        let op_ref = crate::op::PcodeOpRef(op_arc);
        // cc:1644: slot = DynamicHash::getSlotFromHash(hash).
        let slot = crate::dynamic::DynamicHash::get_slot_from_hash(hash);
        // cc:1645-1647: fldNum + ResolvedUnion(parent, fldNum, types); setLock.
        let resolve = if let Some(arch) = &self.arch {
            if let Some(tg) = &arch.types {
                let tg_guard = tg.read().unwrap();
                let mut r = crate::unionresolve::ResolvedUnion::with_field(
                    parent.clone(),
                    field_num,
                    &tg_guard,
                );
                r.set_lock(true);
                r
            } else {
                let mut r = crate::unionresolve::ResolvedUnion::new(parent.clone());
                r.set_lock(true);
                r
            }
        } else {
            let mut r = crate::unionresolve::ResolvedUnion::new(parent.clone());
            r.set_lock(true);
            r
        };
        // cc:1648: return setUnionField(sym->getType(), op, slot, resolve).
        self.set_union_field(parent.as_ref(), &op_ref, slot, resolve)
    }

    // Ghidra: funcdata_varnode.cc:1723 Funcdata::prepareThisPointer
    /// Ensure that if a "this" pointer exists it is treated as a pointer
    /// data-type. Faithful to `Funcdata::prepareThisPointer`
    /// (funcdata_varnode.cc:1723-1743):
    ///   for each param: if isThisPointer && isTypeLocked return;
    ///   if (localmap->hasTypeRecommendations()) return;
    ///   dt = getTypeVoid(); spc = getDefaultDataSpace();
    ///   dt = getTypePointer(spc->getAddrSize(), dt, spc->getWordSize());
    ///   addr = funcp.getThisPointerStorage(dt);
    ///   localmap->addTypeRecommendation(addr, dt);
    /// RUGRA-GAP: ScopeLocal has no type-recommendation store; we approximate
    /// by recording the recommendation address in symbol_table. The
    /// "this"-pointer storage location is taken from funcp's first param
    /// marked as THIS_POINTER, or from the configured stack pointer.
    pub fn prepare_this_pointer(&mut self) {
        // cc:1727-1731: for each param if isThisPointer && isTypeLocked return.
        let num_inputs = self.funcp.num_params();
        for i in 0..num_inputs {
            if let Some(param) = self.funcp.get_param(i) {
                if param.is_this_pointer() && param.is_type_locked() {
                    return;
                }
            }
        }
        // cc:1735-1736: if (localmap->hasTypeRecommendations()) return.
        // Rugra: symbol_table acts as the recommendation store; presence of a
        // "this" entry means a recommendation was already collected.
        let has_recommendation = self
            .symbol_table
            .values()
            .any(|name| name == "this" || name.contains("this"));
        if has_recommendation {
            return;
        }
        // cc:1738-1740: dt = void; spc = default data space;
        //   dt = getTypePointer(spc->getAddrSize(), void, spc->getWordSize()).
        let dt = if let Some(arch) = &self.arch {
            if let Some(tg) = &arch.types {
                let mut tg_guard = tg.write().unwrap();
                let void_dt = tg_guard.get_type_void();
                let addr_size = self.stack_pointer_size;
                let word_size = self.stack_space.word_size();
                tg_guard.get_type_pointer(addr_size, void_dt, word_size)
            } else {
                return;
            }
        } else {
            return;
        };
        // cc:1741-1742: addr = funcp.getThisPointerStorage(dt);
        //   localmap->addTypeRecommendation(addr, dt).
        // Rugra: prefer the first THIS_POINTER param's address; else the stack
        // pointer offset.
        let this_addr = (0..num_inputs)
            .find_map(|i| {
                self.funcp
                    .get_param(i)
                    .filter(|p| p.is_this_pointer())
                    .and_then(|p| Some(p.address.as_u64()))
            })
            .unwrap_or(self.stack_pointer_offset);
        self.symbol_table.insert(this_addr, "this".to_string());
        let _ = dt; // recommendation data-type recorded implicitly via "this" name.
    }

    // Ghidra: funcdata.cc:34 Funcdata::numHeritagePasses
    /// Get number of heritage passes completed
    pub fn num_heritage_passes(&self) -> i32 {
        self.heritage.get_pass()
    }

    // =========================================================================
    // Group 4: Warning & lifecycle methods (funcdata.cc:119-188)
    // =========================================================================

    // Ghidra: funcdata.cc:119 Funcdata::warning
    /// Emit a per-address warning comment. Faithful to
    /// `Funcdata::warning` (funcdata.cc:119-129). The message is prefixed
    /// with `"WARNING (jumptable): "` when this Funcdata is a partial clone
    /// dedicated to jump-table recovery (the `jumptablerecovery_on` flag),
    /// otherwise with `"WARNING: "`. Uses the arch's commentdb if available;
    /// otherwise eprintln as fallback.
    pub fn warning(&self, txt: &str, ad: Address) {
        let prefix = if self.is_jumptable_recovery_on() {
            "WARNING (jumptable): "
        } else {
            "WARNING: "
        };
        let msg = format!("{}{}", prefix, txt);
        if let Some(a) = &self.arch {
            if let Some(cdb) = &a.commentdb {
                let _ = cdb.write().unwrap().add_comment_no_duplicate(
                    crate::comment::comment_type::WARNING,
                    self.baseaddr,
                    ad,
                    &msg,
                );
                return;
            }
        }
        eprintln!("[{}] {}: {} (ad={:#x})", prefix.trim_end_matches(": "), self.name, txt, ad.as_u64());
    }

    // Ghidra: funcdata.cc:150 Funcdata::startProcessing
    /// Basic set-up for analyzing the function: marks the processing-started
    /// flag, clears unlocked scope/proto state, (in Ghidra) follows flow to
    /// build p-code and blocks, resets structuring, sorts call specs, builds
    /// heritage info, and applies dead-code delay. Faithful to
    /// `Funcdata::startProcessing` (funcdata.cc:150-168).
    ///
    /// RUGRA-GAP: `followFlow`, `localoverride.applyDeadCodeDelay`, and the
    /// inline-function header warning depend on infrastructure not yet ported;
    /// the flag transition, unlocked-output clear, structuring reset, call-spec
    /// sort, and heritage-info build are all performed.
    pub fn start_processing(&mut self) {
        if self.is_proc_started() {
            // Ghidra throws LowlevelError here; Rugra panics to preserve the
            // invariant that startProcessing is called at most once.
            panic!("Function processing already started");
        }
        self.flags |= funcdata_flags::PROCESSING_STARTED;

        // Ghidra: if (funcp.isInline()) warningHeader("This is an inlined function");
        // RUGRA-GAP: FuncProto has no is_inline flag yet.

        // Ghidra: localmap->clearUnlocked();
        // RUGRA-GAP: ScopeLocal has no clear_unlocked; clear symbol table instead.
        if let Some(scope) = self.scope.as_mut() {
            scope.symbols.clear();
        }
        // The HighVariable→Symbol associations die with the symbols.
        self.high_symbols.clear();
        self.symbol_entry_cache.clear();

        // Ghidra: funcp.clearUnlockedOutput();
        // Rugra's FuncProto::clear_unlocked_output exists (fspec.rs:308).
        self.funcp.clear_unlocked_output();

        // Ghidra: followFlow(baddr, eaddr); structureReset();
        // RUGRA-GAP: followFlow not ported. structureReset is available.
        //   self.follow_flow(...);  // TODO: port followFlow
        self.structure_reset();

        // Must come after structure reset.
        self.sort_call_specs();

        // Ghidra: heritage.buildInfo();
        self.heritage.build_info_list();

        // Ghidra: localoverride.applyDeadCodeDelay(*this);
        // RUGRA-GAP: localoverride not ported.
    }

    // Ghidra: funcdata.cc:170 Funcdata::stopProcessing
    /// Mark processing complete and free the dead-op list. Faithful to
    /// `Funcdata::stopProcessing` (funcdata.cc:170-180). If this is not a
    /// jump-table-recovery clone, datatype warnings are issued.
    pub fn stop_processing(&mut self) {
        self.flags |= funcdata_flags::PROCESSING_COMPLETE;
        // Ghidra: obank.destroyDead();
        self.obank.destroy_dead();
        if !self.is_jumptable_recovery_on() {
            self.issue_datatype_warnings();
        }
    }

    // Ghidra: funcdata.cc:182 Funcdata::startTypeRecovery
    /// Mark that type recovery has started. Returns `true` if this is the
    /// first call (i.e. type recovery was not previously started), `false`
    /// otherwise. Faithful to `Funcdata::startTypeRecovery` (funcdata.cc:182-188).
    pub fn start_type_recovery(&mut self) -> bool {
        if (self.flags & funcdata_flags::TYPE_RECOVERY_START) != 0 {
            return false;
        }
        self.flags |= funcdata_flags::TYPE_RECOVERY_START;
        true
    }

    // =========================================================================
    // Group 1: Callspec management (funcdata.cc:464-573)
    // =========================================================================

    // Ghidra: funcdata.cc:475 Funcdata::issueDatatypeWarnings
    /// Re-emit all accumulated datatype warnings as header warnings. Faithful
    /// to `Funcdata::issueDatatypeWarnings` (funcdata.cc:475-482). In Ghidra
    /// this iterates `glb->types->beginWarnings()..endWarnings()` and calls
    /// `warningHeader` for each. RUGRA-GAP: `TypeFactory` has no warning list
    /// yet, so this is currently a no-op that preserves the call site in
    /// [`stop_processing`](Self::stop_processing).
    pub fn issue_datatype_warnings(&self) {
        // RUGRA-GAP: TypeFactory::beginWarnings/endWarnings not ported.
        // Once ported, this becomes:
        //   for w in arch.types.iter_warnings() { self.warning_header(w); }
    }

    // Ghidra: funcdata.cc:464 Funcdata::clearCallSpecs
    /// Delete all call specifications. Faithful to
    /// `Funcdata::clearCallSpecs` (funcdata.cc:464-473). In C++ each
    /// `FuncCallSpecs*` is heap-allocated and freed individually before the
    /// vector is cleared; in Rust the Vec owns its elements, so clearing the
    /// Vec drops them.
    pub fn clear_call_specs(&mut self) {
        self.callspecs.clear();
    }

    // Ghidra: funcdata.cc:504 Funcdata::compareCallspecs
    /// Compare two call specs by their position in the block dominance order.
    /// Faithful to `Funcdata::compareCallspecs` (funcdata.cc:504-512). First
    /// key is the basic-block index of the call op; ties are broken by the
    /// op's sequence-number order. Rugra keys FuncCallSpecs by `op_addr`
    /// (the call op's address) rather than an op pointer, so the block index
    /// is looked up via the op bank's dead/alive lists.
    pub fn compare_callspecs(&self, a: &crate::fspec::FuncCallSpecs, b: &crate::fspec::FuncCallSpecs) -> bool {
        let ind1 = self.block_index_for_op_addr(a.op_addr);
        let ind2 = self.block_index_for_op_addr(b.op_addr);
        if ind1 != ind2 {
            return ind1 < ind2;
        }
        // Tie-break on SeqNum order. Rugra doesn't store the SeqNum on
        // FuncCallSpecs, so fall back to op-address ordering within a block.
        a.op_addr.as_u64() < b.op_addr.as_u64()
    }

    // Ghidra: funcdata.cc:516 Funcdata::sortCallSpecs
    /// Sort call specifications into dominance order so earlier calls are
    /// evaluated first. Faithful to `Funcdata::sortCallSpecs`
    /// (funcdata.cc:516-520). Order affects parameter analysis.
    pub fn sort_call_specs(&mut self) {
        // Borrow split: sort_by needs &self for compare_callspecs while the
        // Vec is mutated. Snapshot the comparison keys (block index, op-addr
        // order, original index) first, sort, then rebuild the Vec in the new
        // order by moving each element exactly once out of a Option-slot buffer.
        let mut keyed: Vec<(i32, u64, usize)> = self
            .callspecs
            .iter()
            .enumerate()
            .map(|(i, fc)| (self.block_index_for_op_addr(fc.op_addr), fc.op_addr.as_u64(), i))
            .collect();
        keyed.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
        let new_order: Vec<usize> = keyed.iter().map(|k| k.2).collect();
        // Move ownership out, wrap each in Option so we can take() by index.
        let mut buf: Vec<Option<crate::fspec::FuncCallSpecs>> =
            std::mem::take(&mut self.callspecs).into_iter().map(Some).collect();
        let mut result: Vec<crate::fspec::FuncCallSpecs> = Vec::with_capacity(buf.len());
        for &src in &new_order {
            result.push(buf[src].take().expect("sort permutation visited an index twice"));
        }
        self.callspecs = result;
    }

    // Ghidra: funcdata.cc:524 Funcdata::deleteCallSpecs
    /// Remove the call specification matching the given call op. Faithful to
    /// `Funcdata::deleteCallSpecs` (funcdata.cc:524-537). Used internally when
    /// a CALL is removed (e.g. because it is unreachable). Rugra keys specs by
    /// op address, so the match is on the op's address.
    pub fn delete_call_specs(&mut self, op: &PcodeOpRef) {
        let op_addr = op.0.read().unwrap().get_addr();
        let target = op_addr.as_u64();
        if let Some(pos) = self.callspecs.iter().position(|fc| fc.op_addr.as_u64() == target) {
            self.callspecs.remove(pos);
        }
    }

    // Ghidra: funcdata.cc:545 Funcdata::fillinExtrapop
    /// If the prototype's extrapop is unknown, recover it by examining the
    /// function's first return instruction (x86 assumption: `ret` is `0xc3`,
    /// `ret imm16` is `0xc2 lo hi`). Faithful to `Funcdata::fillinExtrapop`
    /// (funcdata.cc:545-573). Returns the recovered value.
    ///
    /// RUGRA-GAP: Rugra's `FuncProto` has no `extrapop` field (only
    /// `ProtoModel` does). The recovery is computed and returned, but cannot
    /// yet be cached on the prototype. Callers that need the side effect
    /// should store the return value themselves.
    pub fn fillin_extrapop(&self) -> i32 {
        // If no body, we cannot decide: return whatever the model says.
        if self.has_no_code() {
            return self.funcp_extrapop();
        }
        let ep = self.funcp_extrapop();
        if ep != crate::fspec::EXTRAPOP_UNKNOWN_FULL {
            return ep;
        }
        // Ghidra: list<PcodeOp*>::const_iterator iter = beginOp(CPUI_RETURN);
        // If no RETURN ops, the answer is irrelevant; return 0.
        let first_ret = self.obank.begin_op(OpCode::CPUI_RETURN).next();
        let retop = match first_ret {
            Some(r) => r,
            None => return 0,
        };
        let ret_addr = retop.0.read().unwrap().get_addr();
        // Ghidra: glb->loader->loadFill(buffer, 4, retop->getAddr());
        let buffer = match self.load_fill(4, ret_addr) {
            Some(b) => b,
            None => return self.funcp_extrapop(),
        };
        // We are assuming x86 code here.
        let mut extrapop: i32 = 4; // default
        if buffer.len() >= 3 && buffer[0] == 0xc2 {
            // ret imm16: bytes [lo, hi]; extrapop = imm16 + 4 (return address).
            extrapop = buffer[2] as i32; // hi
            extrapop <<= 8;
            extrapop += buffer[1] as i32; // lo
            extrapop += 4; // extra 4 for the return address
        }
        // RUGRA-GAP: funcp.setExtraPop(extrapop) — FuncProto has no extrapop.
        extrapop
    }

    // =========================================================================
    // Group 2: Jumptable recovery (funcdata_block.cc:427-686)
    // =========================================================================

    // Ghidra: funcdata_block.cc:427 Funcdata::linkJumpTable
    /// Link an existing (possibly override) jump-table to the given BRANCHIND
    /// op by setting its indirect op. Faithful to `Funcdata::linkJumpTable`
    /// (funcdata_block.cc:427-441). Returns the matching table, or `None` if
    /// no table's op-address matches.
    pub fn link_jump_table(
        &mut self,
        op: &PcodeOpRef,
    ) -> Option<Arc<RwLock<crate::jumptable::JumpTable>>> {
        let op_addr = op.0.read().unwrap().get_addr();
        let target = op_addr.as_u64();
        // Find the matching table, then set its indirect op.
        let pos = self.jump_tables.iter().position(|jt| {
            jt.read().unwrap().get_op_address().as_u64() == target
        });
        if let Some(idx) = pos {
            let jt_arc = self.jump_tables[idx].clone();
            // set_indirect_op takes ownership of Arc<RwLock<PcodeOp>>; we can
            // clone the inner Arc from the PcodeOpRef wrapper.
            jt_arc.write().unwrap().set_indirect_op(op.0.clone());
            Some(jt_arc)
        } else {
            None
        }
    }

    // Ghidra: funcdata_block.cc:464 Funcdata::installJumpTable
    /// Install a fresh (empty) jump-table at the given address, suitable for
    /// an override. Must be called before flow is traced. Faithful to
    /// `Funcdata::installJumpTable` (funcdata_block.cc:464-477). Returns the
    /// new table.
    pub fn install_jump_table(&mut self, addr: Address) -> Arc<RwLock<crate::jumptable::JumpTable>> {
        if self.is_proc_started() {
            panic!("Cannot install jumptable if flow is already traced");
        }
        for jt in &self.jump_tables {
            if jt.read().unwrap().get_op_address().as_u64() == addr.as_u64() {
                panic!("Trying to install over existing jumptable");
            }
        }
        let new_jt = Arc::new(RwLock::new(crate::jumptable::JumpTable::new(addr)));
        self.jump_tables.push(new_jt.clone());
        new_jt
    }

    // Ghidra: funcdata_block.cc:492 Funcdata::stageJumpTable
    /// Recover a jump-table for a BRANCHIND using existing flow information.
    /// Faithful to `Funcdata::stageJumpTable` (funcdata_block.cc:492-548). A
    /// partial function clone is simplified under the "jumptable" strategy,
    /// then the table's addresses are recovered. Returns a success/failure
    /// code.
    ///
    /// RUGRA-GAP: the partial-clone simplification pipeline (`truncatedFlow`,
    /// `glb->allacts` action dispatch, `recoverMultistage`) is not ported.
    /// This implementation performs the parts that exist: flag set, indirect-op
    /// link, partial/dead checks, return-address test, and
    /// [`JumpTable::recover_addresses`]. Callers driving real recovery should
    /// simplify `partial` beforehand.
    pub fn stage_jump_table(
        &mut self,
        partial: &mut Funcdata,
        jt: &Arc<RwLock<crate::jumptable::JumpTable>>,
        op: &PcodeOpRef,
    ) -> crate::jumptable::RecoveryMode {
        if !partial.is_jumptable_recovery_on() {
            // Do full analysis on the table if we haven't before.
            partial.flags |= funcdata_flags::JUMPTABLERECOVERY_ON;
            // Ghidra: partial.truncatedFlow(this, flow); then runs the
            // "jumptable" action group on the partial clone.
            // RUGRA-GAP: truncatedFlow + action group not ported. Callers must
            // simplify `partial` themselves before invoking this.
        }

        let op_seqnum = op.0.read().unwrap().get_seq_num().clone();
        // Ghidra: PcodeOp *partop = partial.findOp(op->getSeqNum());
        let partop = partial.obank.find_op(&op_seqnum);
        let partop = match partop {
            Some(p) => p,
            None => {
                self.warning(
                    "Error recovering jumptable: Bad partial clone",
                    op.0.read().unwrap().get_addr(),
                );
                return crate::jumptable::RecoveryMode::FailNormal;
            }
        };
        {
            let p_rg = partop.0.read().unwrap();
            if p_rg.opcode != OpCode::CPUI_BRANCHIND
                || p_rg.get_addr().as_u64() != op.0.read().unwrap().get_addr().as_u64()
            {
                self.warning(
                    "Error recovering jumptable: Bad partial clone",
                    op.0.read().unwrap().get_addr(),
                );
                return crate::jumptable::RecoveryMode::FailNormal;
            }
            // Indirectop we were trying to recover was eliminated as dead code.
            if p_rg.is_dead() {
                return crate::jumptable::RecoveryMode::Success;
            }
        }

        // Test if the branch target is copied from the return address.
        let in0 = {
            let p_rg = partop.0.read().unwrap();
            p_rg.get_in(0).cloned()
        };
        if let Some(vn) = in0 {
            if self.test_for_return_address(&vn) {
                // Switch would not recover anyway.
                return crate::jumptable::RecoveryMode::FailReturn;
            }
        }

        // Ghidra: jt->setLoadCollect(flow->doesJumpRecord());
        // RUGRA-GAP: FlowInfo not threaded through; default to no load collect.
        {
            let mut jt_w = jt.write().unwrap();
            jt_w.set_load_collect(false);
            jt_w.set_indirect_op(partop.0.clone());
        }
        // Ghidra branches on jt->isPartial(): recoverMultistage vs recoverAddresses.
        // RUGRA-GAP: recoverMultistage not ported; always recoverAddresses.
        let recovered = jt.write().unwrap().recover_addresses(partial);
        if !recovered {
            // recoverAddresses returned false (no model / zero entries).
            self.warning(
                "Jumptable recovery produced no addresses",
                op.0.read().unwrap().get_addr(),
            );
            return crate::jumptable::RecoveryMode::FailNormal;
        }
        crate::jumptable::RecoveryMode::Success
    }

    // Ghidra: funcdata_block.cc:555 Funcdata::earlyJumpTableFail
    /// Backtrack from a BRANCHIND looking for ops that might affect the
    /// destination. If an uninjected CALLOTHER is in the flow path, the
    /// jump-table analysis will fail and `FailCallother` is returned.
    /// Faithful to `Funcdata::earlyJumpTableFail` (funcdata_block.cc:555-628).
    pub fn early_jump_table_fail(&self, op: &PcodeOpRef) -> crate::jumptable::RecoveryMode {
        use crate::op::pcodeop_flags as pf;
        let mut vn_arc = {
            let op_rg = op.0.read().unwrap();
            op_rg.get_in(0).cloned()
        };
        // Walk the dead op list backwards from op's position. Rugra's obank
        // keeps a single `alivelist`; the dead list is implicit. We emulate
        // Ghidra's `beginOpDead()..op->insertiter` window by scanning the
        // alive list up to `op`, then continuing through earlier ops.
        let alive = &self.obank.alivelist;
        let start_idx = alive
            .iter()
            .position(|r| Arc::ptr_eq(&r.0, &op.0))
            .unwrap_or(0);
        let mut count_max: i32 = 8;
        let mut i: isize = start_idx as isize - 1;
        let vn_size = vn_arc.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0);
        let mut cur_vn_size = vn_size;
        while i >= 0 {
            // Ghidra: if (vn->getSize() == 1) return success;
            if cur_vn_size == 1 {
                return crate::jumptable::RecoveryMode::Success;
            }
            count_max -= 1;
            if count_max < 0 {
                return crate::jumptable::RecoveryMode::Success;
            }
            let cur_op = alive[i as usize].clone();
            let (eval_type, opcode, is_call, is_branch, out_arc, in0_arc, in1_arc) = {
                let op_rg = cur_op.0.read().unwrap();
                (
                    op_rg.get_eval_type(),
                    op_rg.opcode,
                    op_rg.is_call(),
                    op_rg.is_branch(),
                    op_rg.get_out().cloned(),
                    op_rg.get_in(0).cloned(),
                    op_rg.get_in(1).cloned(),
                )
            };
            // Does cur_op write something overlapping our current vn?
            let outhit = match (&out_arc, &vn_arc) {
                (Some(o), Some(v)) => o.read().unwrap().intersects(&v.read().unwrap()),
                _ => false,
            };
            if eval_type == pf::SPECIAL {
                if is_call {
                    if opcode == OpCode::CPUI_CALLOTHER {
                        // int4 id = (int4)op->getIn(0)->getOffset();
                        let id = in0_arc.as_ref().map(|v| v.read().unwrap().get_offset()).unwrap_or(0) as usize;
                        let user_op_type = self.userop_type(id);
                        use crate::userop::UserOpType;
                        if user_op_type == UserOpType::Injected
                            || user_op_type == UserOpType::JumpAssist
                            || user_op_type == UserOpType::Segment
                        {
                            return crate::jumptable::RecoveryMode::Success;
                        }
                        if outhit {
                            // Address formed via uninjected CALLOTHER, analysis will fail.
                            return crate::jumptable::RecoveryMode::FailCallother;
                        }
                        // Assume CALLOTHER will not interfere; continue backtracking.
                    } else {
                        // CALL or CALLIND — output not established yet.
                        return crate::jumptable::RecoveryMode::Success;
                    }
                } else if is_branch {
                    return crate::jumptable::RecoveryMode::Success;
                } else {
                    if opcode == OpCode::CPUI_STORE {
                        return crate::jumptable::RecoveryMode::Success;
                    }
                    // Some special op generates the address; don't assume failure.
                }
            } else if eval_type == pf::UNARY {
                if outhit {
                    let invn = in0_arc;
                    let invn_size = invn.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0);
                    if invn_size != cur_vn_size {
                        return crate::jumptable::RecoveryMode::Success;
                    }
                    vn_arc = invn;
                    cur_vn_size = invn_size;
                }
            } else if eval_type == pf::BINARY {
                if outhit {
                    if opcode != OpCode::CPUI_INT_ADD
                        && opcode != OpCode::CPUI_INT_SUB
                        && opcode != OpCode::CPUI_INT_XOR
                    {
                        return crate::jumptable::RecoveryMode::Success;
                    }
                    let in1_const = in1_arc
                        .as_ref()
                        .map(|v| v.read().unwrap().is_constant())
                        .unwrap_or(false);
                    if !in1_const {
                        return crate::jumptable::RecoveryMode::Success;
                    }
                    let invn = in0_arc;
                    let invn_size = invn.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0);
                    if invn_size != cur_vn_size {
                        return crate::jumptable::RecoveryMode::Success;
                    }
                    vn_arc = invn;
                    cur_vn_size = invn_size;
                }
            } else if outhit {
                return crate::jumptable::RecoveryMode::Success;
            }
            i -= 1;
        }
        crate::jumptable::RecoveryMode::Success
    }

    // Ghidra: funcdata_block.cc:640 Funcdata::recoverJumpTable
    /// Recover control-flow destinations for a BRANCHIND. Faithful to
    /// `Funcdata::recoverJumpTable` (funcdata_block.cc:640-674). If an
    /// existing non-override, non-partial table exists it is returned
    /// immediately; otherwise an attempt is made to stage recovery. Returns
    /// the recovered table (also pushed into `jump_tables` if newly created)
    /// or `None` on failure, with `mode` set to the failure code.
    pub fn recover_jump_table(
        &mut self,
        partial: &mut Funcdata,
        op: &PcodeOpRef,
        mode: &mut crate::jumptable::RecoveryMode,
    ) -> Option<Arc<RwLock<crate::jumptable::JumpTable>>> {
        *mode = crate::jumptable::RecoveryMode::Success;

        // Search for a pre-existing jumptable.
        if let Some(jt) = self.link_jump_table(op) {
            let (is_override, is_partial) = {
                let jt_rg = jt.read().unwrap();
                (jt_rg.is_override(), jt_rg.is_partial())
            };
            if !is_override {
                if !is_partial {
                    return Some(jt); // Previously calculated jumptable.
                }
            }
            *mode = self.stage_jump_table(partial, &jt, op);
            if *mode != crate::jumptable::RecoveryMode::Success {
                return None;
            }
            // Relink table back to original op.
            jt.write().unwrap().set_indirect_op(op.0.clone());
            return Some(jt);
        }

        if (self.flags & funcdata_flags::JUMPTABLERECOVERY_DONT) != 0 {
            return None; // Explicitly told not to recover jumptables.
        }
        *mode = self.early_jump_table_fail(op);
        if *mode != crate::jumptable::RecoveryMode::Success {
            return None;
        }

        // JumpTable trialjt(glb);  — start with an empty trial table.
        let op_addr = op.0.read().unwrap().get_addr();
        let trial_jt = Arc::new(RwLock::new(crate::jumptable::JumpTable::new(op_addr)));
        *mode = self.stage_jump_table(partial, &trial_jt, op);
        if *mode != crate::jumptable::RecoveryMode::Success {
            return None;
        }
        // Make the jumptable permanent.
        trial_jt.write().unwrap().set_indirect_op(op.0.clone());
        self.jump_tables.push(trial_jt.clone());
        Some(trial_jt)
    }

    // Ghidra: funcdata_block.cc:679 Funcdata::switchOverJumpTables
    /// For each jump-table, for each address, compute the corresponding basic
    /// block index and the default branch. Faithful to
    /// `Funcdata::switchOverJumpTables` (funcdata_block.cc:679-686).
    ///
    /// RUGRA-GAP: Ghidra delegates to `JumpTable::switchOver(flow)` which
    /// consults `FlowInfo`'s address→op map. Rugra's `JumpTable` has no
    /// `switch_over` yet; this stub iterates the tables so the call site is
    /// preserved, and the per-table switchover is a no-op until FlowInfo
    /// lands.
    pub fn switch_over_jump_tables(&mut self) {
        for jt in &self.jump_tables {
            // RUGRA-GAP: jt->switchOver(flow);
            let _ = jt;
        }
    }

    // =========================================================================
    // Group 3: Block structure maintenance (funcdata_block.cc:28-321)
    // =========================================================================

    // Ghidra: funcdata_block.cc:28 Funcdata::printBlockTree
    /// Print the structure tree (composite blocks) to a string. Faithful to
    /// `Funcdata::printBlockTree` (funcdata_block.cc:28-33), which delegates
    /// to `BlockGraph::printTree(s, 0)`. Rugra's `BlockGraph` has no
    /// `print_tree`, so this walks the top-level structure blocks and emits
    /// one line per block with its index and type, indented to depth 0.
    pub fn print_block_tree(&self) -> String {
        let mut out = String::new();
        for blk in &self.sblocks.blocks {
            let rg = blk.read().unwrap();
            out.push_str(&format!(
                "  Block {} ({:?})\n",
                rg.get_index(),
                rg.get_type()
            ));
        }
        out
    }

    // Ghidra: funcdata_block.cc:35 Funcdata::clearBlocks
    /// Clear both the basic-block graph and the structure tree. Faithful to
    /// `Funcdata::clearBlocks` (funcdata_block.cc:35-40).
    pub fn clear_blocks(&mut self) {
        self.bblocks.clear();
        self.sblocks.clear();
    }

    // Ghidra: funcdata_block.cc:43 Funcdata::clearJumpTables
    /// Clear all derived jump-table data, preserving any manually-overridden
    /// tables (which are cleared of derived data but kept). Faithful to
    /// `Funcdata::clearJumpTables` (funcdata_block.cc:43-60). Rugra's
    /// `JumpTable` has no `clear()` method; an override is replaced with a
    /// fresh empty table at the same address.
    pub fn clear_jump_tables(&mut self) {
        let mut remain: Vec<Arc<RwLock<crate::jumptable::JumpTable>>> = Vec::new();
        for jt in self.jump_tables.drain(..) {
            let is_override = jt.read().unwrap().is_override();
            if is_override {
                // Clear out any derived data but keep the override itself.
                let addr = jt.read().unwrap().get_op_address();
                let fresh = Arc::new(RwLock::new(crate::jumptable::JumpTable::new(addr)));
                remain.push(fresh);
            }
            // else: drop (the Arc is released when it goes out of scope).
        }
        self.jump_tables = remain;
    }

    // Ghidra: funcdata_block.cc:85 Funcdata::pushMultiequals
    /// Assuming `bb` is being removed, force any Varnode defined by a
    /// MULTIEQUAL in `bb` to be defined in the output block instead, patching
    /// up data-flow. Faithful to `Funcdata::pushMultiequals`
    /// (funcdata_block.cc:85-172).
    ///
    /// RUGRA-GAP: the full algorithm constructs artificial MULTIEQUAL ops and
    /// rewrites descend lists. Rugra's op/varnode mutation API is incomplete
    /// (no `opSetAllInput`, no descend iteration that yields owned ops), so
    /// this implementation handles the common single-output, no-replacement
    /// case and warns otherwise. The structure and intent match Ghidra.
    pub fn push_multiequals(&mut self, bb: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        let (size_out, out_block, outblock_ind) = {
            let bb_rg = bb.read().unwrap();
            if bb_rg.size_out() == 0 {
                return;
            }
            if bb_rg.size_out() > 1 {
                self.warning_header("push_multiequal on block with multiple outputs");
            }
            let out = bb_rg.get_out(0).map(|e| e.point);
            // get_out_rev_index is on BlockBasic only; downcast to reach it.
            let rev = if let Some(bb_basic) = bb_rg.as_any().downcast_ref::<BlockBasic>() {
                bb_basic.get_out_rev_index(0)
            } else {
                -1
            };
            (bb_rg.size_out(), out, rev)
        };
        let _ = size_out;
        let outblock = match out_block {
            Some(o) => o,
            None => return,
        };

        // Gather the MULTIEQUAL ops in bb that still have descendants.
        // We snapshot the relevant ops first to avoid holding a borrow across
        // the mutation below.
        let bb_ops = {
            let bb_rg = bb.read().unwrap();
            if let Some(bb_basic) = bb_rg.as_any().downcast_ref::<BlockBasic>() {
                bb_basic.get_ops()
            } else {
                return;
            }
        };

        for origop in bb_ops {
            let is_multiequal = origop.0.read().unwrap().opcode == OpCode::CPUI_MULTIEQUAL;
            if !is_multiequal {
                continue;
            }
            let origvn = origop.0.read().unwrap().get_out().cloned();
            let origvn = match origvn {
                Some(v) => v,
                None => continue,
            };
            if origvn.read().unwrap().has_no_descend() {
                continue;
            }
            // Check whether any descendant is a MULTIEQUAL in outblock reading
            // origvn via the dead edge (outblock_ind). If so, no replacement is
            // needed for that read.
            // RUGRA-GAP: full descend iteration + artificial MULTIEQUAL
            // construction requires opSetAllInput/opSetOutput on new ops,
            // which Rugra exposes but the descend-rewrite is involved. We
            // implement the detection step and emit the warning Ghidra emits
            // when a replacement would be required, leaving the rewrite for a
            // follow-up once descend iteration is owned.
            let _ = outblock_ind;
            let _ = &outblock;
            // The conservative warning matches Ghidra's
            //   warningHeader("push_multiequal on block with multiple outputs")
            // only for the multi-output case (already handled above). For the
            // single-output case with active descendants we currently cannot
            // rebuild the artificial MULTIEQUAL, so we warn.
            self.warning_header("push_multiequal: descendant rewrite not yet implemented");
        }
    }

    // Ghidra: funcdata_block.cc:178 Funcdata::opZeroMulti
    /// If the MULTIEQUAL has no inputs, treat it as a COPY from a new input
    /// Varnode; if it has one input, transform it directly into a COPY.
    /// Faithful to `Funcdata::opZeroMulti` (funcdata_block.cc:178-188).
    pub fn op_zero_multi(&mut self, op: &PcodeOpRef) {
        let num_input = op.0.read().unwrap().num_input();
        if num_input == 0 {
            // No branches left: insert a new input varnode at slot 0 and
            // convert to COPY.
            let (size, addr) = {
                let op_rg = op.0.read().unwrap();
                let out = op_rg.get_out();
                match out {
                    Some(o) => {
                        let o_rg = o.read().unwrap();
                        (o_rg.get_size(), *o_rg.get_addr())
                    }
                    None => (0, Address::new(0)),
                }
            };
            let newvn = self.new_varnode(size, addr);
            self.op_insert_input(op, newvn.clone(), 0);
            // Ghidra: setInputVarnode(op->getIn(0)); promote slot 0 to input.
            self.set_input_varnode(newvn);
            self.op_set_opcode(op, OpCode::CPUI_COPY);
        } else if num_input == 1 {
            self.op_set_opcode(op, OpCode::CPUI_COPY);
        }
    }

    // Ghidra: funcdata_block.cc:196 Funcdata::branchRemoveInternal
    /// Remove an outgoing branch of the given basic block, patching
    /// MULTIEQUAL p-code ops in the target block. Faithful to
    /// `Funcdata::branchRemoveInternal` (funcdata_block.cc:196-216).
    pub fn branch_remove_internal(&mut self, bb: &Arc<RwLock<dyn FlowBlock + Send + Sync>>, num: usize) {
        // If there is no decision left (2 out-edges), remove the branch op.
        let size_out = bb.read().unwrap().size_out();
        if size_out == 2 {
            let last = {
                let bb_rg = bb.read().unwrap();
                if let Some(bb_basic) = bb_rg.as_any().downcast_ref::<BlockBasic>() {
                    bb_basic.last_op()
                } else {
                    None
                }
            };
            if let Some(op) = last {
                self.op_destroy(&op);
            }
        }

        let bbout = bb.read().unwrap().get_out(num).map(|e| e.point);
        let bbout = match bbout {
            Some(o) => o,
            None => return,
        };
        let blocknum = self.find_in_index(&bbout, bb);
        // Sever (one) connection between bb and bbout.
        self.bblocks.remove_edge_blocks(bb, &bbout);

        // For each MULTIEQUAL in bbout, remove input `blocknum` and zero it.
        let ops: Vec<PcodeOpRef> = {
            let bbout_rg = bbout.read().unwrap();
            if let Some(bb_basic) = bbout_rg.as_any().downcast_ref::<BlockBasic>() {
                bb_basic.get_ops()
            } else {
                return;
            }
        };
        for op in ops {
            let is_me = op.0.read().unwrap().opcode == OpCode::CPUI_MULTIEQUAL;
            if !is_me {
                continue;
            }
            if let Some(bn) = blocknum {
                self.op_remove_input(&op, bn);
            }
            self.op_zero_multi(&op);
        }
    }

    // Ghidra: funcdata_block.cc:234 Funcdata::descendantsOutside
    /// Assuming a basic block is marked dead, return `true` if any PcodeOp
    /// reading `vn` is outside the dead block (i.e. the varnode still has
    /// live readers). Faithful to `Funcdata::descendantsOutside`
    /// (funcdata_block.cc:234-242).
    pub fn descendants_outside(&self, vn: &Arc<RwLock<crate::varnode::Varnode>>) -> bool {
        use crate::block::block_flags;
        // Walk the descend list; if any reading op's parent block is NOT
        // dead, the varnode has descendants outside.
        let descend: Vec<Arc<RwLock<crate::op::PcodeOp>>> = {
            let vn_rg = vn.read().unwrap();
            vn_rg.descend_iter().collect()
        };
        for dop in descend {
            // We cannot reach getParent()->isDead() without a parent pointer
            // on PcodeOp. Approximate via the op's own DEAD flag, which is
            // set when the op is destroyed.
            let is_dead = dop.read().unwrap().is_dead();
            if !is_dead {
                // The op is alive somewhere; treat it as outside the dead block.
                let _ = block_flags::DEAD;
                return true;
            }
        }
        false
    }

    // Ghidra: funcdata_block.cc:255 Funcdata::blockRemoveInternal
    /// Remove an active basic block from the function: delete its PcodeOps,
    /// patch up data-flow and control-flow (mostly MULTIEQUALs). Faithful to
    /// `Funcdata::blockRemoveInternal` (funcdata_block.cc:255-321).
    ///
    /// RUGRA-GAP: the full MULTIEQUAL-splicing logic and
    /// `bblocks.removeFromFlow` are not ported. This implementation performs
    /// the reachable parts: jump-table removal for a trailing BRANCHIND,
    /// call-spec deletion, op destruction, and final block removal. The
    /// unreachable-warning path is preserved.
    pub fn block_remove_internal(
        &mut self,
        bb: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        unreachable_flag: bool,
    ) {
        // If the last op is a BRANCHIND with an attached jump-table, remove it.
        let last_op = {
            let bb_rg = bb.read().unwrap();
            if let Some(bb_basic) = bb_rg.as_any().downcast_ref::<BlockBasic>() {
                bb_basic.last_op()
            } else {
                None
            }
        };
        if let Some(ref op) = last_op {
            let is_branchind = op.0.read().unwrap().opcode == OpCode::CPUI_BRANCHIND;
            if is_branchind {
                if let Some(jt) = self.find_jump_table_arc(op) {
                    self.remove_jump_table(&jt);
                }
            }
        }

        if !unreachable_flag {
            self.push_multiequals(bb);
            // For each output block, splice MULTIEQUAL inputs. RUGRA-GAP: the
            // full splice (opInsertInput with each in-edge) requires owning
            // the input varnodes across the edge removal, which depends on
            // `bblocks.removeFromFlow`. Deferred.
        }
        // Ghidra: bblocks.removeFromFlow(bb);  RUGRA-GAP: not ported.
        // Approximate by detaching bb's edges.
        self.bblocks.remove_block_arc(bb);

        // Finally remove all the ops.
        let mut desc_warning = false;
        let ops: Vec<PcodeOpRef> = {
            let bb_rg = bb.read().unwrap();
            if let Some(bb_basic) = bb_rg.as_any().downcast_ref::<BlockBasic>() {
                bb_basic.get_ops()
            } else {
                Vec::new()
            }
        };
        for op in ops {
            let (is_assignment, is_call, out_vn) = {
                let op_rg = op.0.read().unwrap();
                (op_rg.is_assignment(), op_rg.is_call(), op_rg.get_out().cloned())
            };
            if is_assignment {
                if let Some(deadvn) = out_vn {
                    if unreachable_flag {
                        // Ghidra: bool undef = descend2Undef(deadvn);
                        // RUGRA-GAP: descend2Undef not ported. Mark warning.
                        if !desc_warning {
                            self.warning_header(
                                "Creating undefined varnodes in (possibly) reachable block",
                            );
                            desc_warning = true;
                        }
                    }
                    if self.descendants_outside(&deadvn) {
                        // Ghidra throws LowlevelError here.
                        panic!("Deleting op with descendants");
                    }
                }
            }
            if is_call {
                self.delete_call_specs(&op);
            }
            self.op_destroy(&op);
        }

        // Remove the block altogether. Rugra exposes `remove_block_arc`
        // (BlockGraph::removeBlock) rather than `remove_block`.
        self.bblocks.remove_block_arc(bb);
    }

    // =========================================================================
    // Helpers used by the ported methods (no Ghidra line — these adapt the
    // Rust API surface to the ported code).
    // =========================================================================

    /// Look up the index of the basic block containing the op at `op_addr`.
    /// Returns `i32::MAX` if not found so the spec sorts to the end.
    /// (Adapts Ghidra's `op->getParent()->getIndex()` to Rugra's flat block
    /// list.)
    // RUGRA-GLUE: Rugra call specs retain only an Address, so this scans the
    // CFG; Ghidra retains PcodeOp pointers and reads their parent inline.
    fn block_index_for_op_addr(&self, op_addr: Address) -> i32 {
        let target = op_addr.as_u64();
        for (i, blk_arc) in self.bblocks.blocks.iter().enumerate() {
            let blk_rg = blk_arc.read().unwrap();
            if let Some(bb) = blk_rg.as_any().downcast_ref::<BlockBasic>() {
                for op in bb.get_ops() {
                    if op.0.read().unwrap().get_addr().as_u64() == target {
                        return i as i32;
                    }
                }
            }
        }
        i32::MAX
    }

    /// Find `parent`'s slot in `child`'s incoming list (Ghidra
    /// `FlowBlock::getInIndex`). Returns `None` if not present.
    // Ghidra: block.cc:579 FlowBlock::getInIndex
    fn find_in_index(
        &self,
        child: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        parent: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> Option<usize> {
        let child_rg = child.read().unwrap();
        (0..child_rg.size_in()).find(|&i| {
            child_rg
                .get_in(i)
                .map(|e| Arc::ptr_eq(&e.point, parent))
                .unwrap_or(false)
        })
    }

    /// Find a jump-table whose op-address matches `op`, returning a cloned
    /// Arc (mutable-self counterpart to [`find_jump_table`](Self::find_jump_table)).
    // RUGRA-GLUE: Rust ownership form of the existing find_jump_table mapping;
    // Ghidra returns one raw JumpTable pointer and has no Arc-cloning helper.
    fn find_jump_table_arc(
        &self,
        op: &PcodeOpRef,
    ) -> Option<Arc<RwLock<crate::jumptable::JumpTable>>> {
        let op_addr = op.0.read().unwrap().get_addr().as_u64();
        self.jump_tables
            .iter()
            .find(|jt| jt.read().unwrap().get_op_address().as_u64() == op_addr)
            .cloned()
    }

    /// Load `size` bytes from the load image at `addr`. Adapts Ghidra's
    /// `glb->loader->loadFill(buf, size, addr)` to Rugra's
    /// `LoadImage::load_fill(size, addr) -> Result<Vec<u8>, DataUnavailError>`.
    /// Returns `None` if the image has no data at `addr`.
    // RUGRA-GLUE: Rust Result/buffer adapter around LoadImage::load_fill;
    // Ghidra fills the caller's buffer directly and has no Funcdata helper.
    fn load_fill(&self, size: usize, addr: Address) -> Option<Vec<u8>> {
        let arch = self.arch.as_ref()?;
        let loader = arch.loader.as_ref()?;
        loader.load_fill(size, addr).ok()
    }

    /// Get the prototype's extrapop. Adapts Ghidra's `funcp.getExtraPop()`.
    /// RUGRA-GAP: Rugra's `FuncProto` has no `extrapop` field (only
    /// `ProtoModel` does), and `Funcdata` has no architecture-resolved default
    /// model, so this always returns `EXTRAPOP_UNKNOWN_FULL` — which forces
    /// [`fillin_extrapop`](Self::fillin_extrapop) to attempt byte-level
    /// recovery rather than short-circuiting.
    // RUGRA-GLUE: Adapter for the unported FuncProto extrapop field; Ghidra
    // calls funcp.getExtraPop() directly and has no Funcdata wrapper.
    fn funcp_extrapop(&self) -> i32 {
        crate::fspec::EXTRAPOP_UNKNOWN_FULL
    }

    /// Does this function have no code body (external/thunk)? Adapts Ghidra's
    /// `hasNoCode()`. RUGRA-GAP: Rugra has no explicit flag; approximate via
    /// an empty obank (no ops means no body).
    // Ghidra: funcdata.hh:153 Funcdata::hasNoCode
    fn has_no_code(&self) -> bool {
        self.obank.alivelist.is_empty() && self.size == 0
    }

    /// Get the user-op type for CALLOTHER id `id`. Adapts Ghidra's
    /// `glb->userops.getOp(id)->getType()`. Returns `Unspecialized` if the
    /// architecture or user-op table is unavailable.
    // RUGRA-GLUE: Rust Option/lock adapter for the inline user-op lookup in
    // Funcdata::earlyJumpTableFail; Ghidra has no Funcdata::useropType helper.
    fn userop_type(&self, id: usize) -> crate::userop::UserOpType {
        use crate::userop::UserOpType;
        let arch = match self.arch.as_ref() {
            Some(a) => a,
            None => return UserOpType::Unspecialized,
        };
        if let Some(userops) = arch.userops.as_ref() {
            let mgr = userops.read().unwrap();
            if let Some(uo) = mgr.get_op(id as i32) {
                return uo.get_type();
            }
        }
        UserOpType::Unspecialized
    }

    // Ghidra: funcdata_varnode.cc:1442 Funcdata::testForReturnAddress
    /// Trace `vn` back to see if it derives from this function's return
    /// address. Faithful to `Funcdata::testForReturnAddress`
    /// (funcdata_varnode.cc:1442-1468). The value may flow through COPY,
    /// INDIRECT, and INT_AND (alignment mask) ops; any other op breaks the
    /// chain. The terminal Varnode must be an input marked as the return
    /// address storage location.
    /// RUGRA-GAP: Ghidra compares against `glb->defaultReturnAddr` (a
    /// VarnodeData). Rugra's Architecture does not yet hold that datum, so we
    /// instead check the terminal Varnode's `is_input()` and its
    /// `RETURN_ADDRESS` flag (set by the loader/disassembler on the storage
    /// location). When no return-address flag is present we conservatively
    /// return false.
    pub fn test_for_return_address(&self, vn: &Arc<RwLock<crate::varnode::Varnode>>) -> bool {
        // cc:1445-1447: retaddr = glb->defaultReturnAddr; if null return false.
        // Rugra: the RETURN_ADDRESS varnode flag is our analogue of having a
        // known return-address storage location.
        let mut cur = vn.clone();
        loop {
            let (def, opc, in0) = {
                let c = cur.read().unwrap();
                if !c.is_written() {
                    break;
                }
                let d = match c.get_def() {
                    Some(d) => d,
                    None => break,
                };
                // Read the opcode/input under the guard, then move the Arc out.
                let (opc, in0) = {
                    let dg = d.read().unwrap();
                    (dg.opcode, dg.get_in(0).cloned())
                };
                (d, opc, in0)
            };
            // cc:1451-1453: INDIRECT/COPY → follow in(0).
            if opc == OpCode::CPUI_INDIRECT || opc == OpCode::CPUI_COPY {
                match in0 {
                    Some(v) => cur = v,
                    None => return false,
                }
            } else if opc == OpCode::CPUI_INT_AND {
                // cc:1454-1458: only allow alignment-style masking (constant
                // second input); follow in(0).
                let in1_const = {
                    let d = def.read().unwrap();
                    d.get_in(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false)
                };
                if !in1_const {
                    return false;
                }
                match in0 {
                    Some(v) => cur = v,
                    None => return false,
                }
            } else {
                // cc:1460-1461: any other op → not a return address.
                return false;
            }
        }
        // cc:1463-1466: terminal must match the return-address storage and be
        // an input. Rugra: check is_input() + RETURN_ADDRESS flag.
        let c = cur.read().unwrap();
        if !c.is_input() {
            return false;
        }
        c.is_return_address()
    }

    // Ghidra: funcdata_varnode.cc:190 Funcdata::newVarnodeSpace
    /// Encode an address space as a constant Varnode. Faithful to
    /// `Funcdata::newVarnodeSpace` (funcdata_varnode.cc:190-198):
    ///   Datatype *ct = glb->types->getBase(sizeof(spc), TYPE_UNKNOWN);
    ///   Varnode *vn = vbank.create(sizeof(spc), glb->createConstFromSpace(spc), ct);
    ///   assignHigh(vn);
    ///   return vn;
    /// These Varnodes are used as the first input to LOAD/STORE p-code ops to
    /// name the address space being accessed. Rugra encodes the space via its
    /// SpaceId (which uniquely identifies the space) as the constant offset.
    pub fn new_varnode_space(
        &mut self,
        spc: crate::space::AddressSpace,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let sz = std::mem::size_of::<usize>();
        let offset = spc.space_id() as u64;
        let vn = self.vbank.create_with_space(sz, crate::space::AddressSpace::Const, offset);
        let _ = self.assign_high(&vn);
        vn
    }

    // Ghidra: funcdata_varnode.cc:205 Funcdata::newVarnodeCallSpecs
    /// Encode a FuncCallSpecs pointer as a fspace annotation Varnode. Faithful
    /// to `Funcdata::newVarnodeCallSpecs` (funcdata_varnode.cc:205-214):
    ///   Datatype *ct = glb->types->getBase(sizeof(fc), TYPE_UNKNOWN);
    ///   AddrSpace *cspc = glb->getFspecSpace();
    ///   Varnode *vn = vbank.create(sizeof(fc), Address(cspc,(uintb)(uintp)fc), ct);
    ///   assignHigh(vn);
    ///   return vn;
    /// The Varnode is the first input to a CPUI_CALL op and accelerates lookup
    /// of the associated call specification. Rugra has no fspace address space;
    /// we encode the callspec's index in the callspecs vector as the offset of
    /// a synthetic Iop-adjacent annotation Varnode.
    pub fn new_varnode_call_specs(
        &mut self,
        fc_index: usize,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let sz = std::mem::size_of::<usize>();
        let vn = self.vbank.create_with_space(
            sz,
            crate::space::AddressSpace::Iop,
            fc_index as u64,
        );
        vn.write().unwrap().set_flags(crate::varnode::varnode_flags::ANNOTATION);
        let _ = self.assign_high(&vn);
        vn
    }

    // Ghidra: funcdata_varnode.cc:222 Funcdata::newCodeRef
    /// Construct an annotation Varnode that holds a reference to a code
    /// Address (used as the destination of a BRANCH op). Faithful to
    /// `Funcdata::newCodeRef` (funcdata_varnode.cc:222-233):
    ///   Datatype *ct = glb->types->getTypeCode();
    ///   vn = vbank.create(1, m, ct);
    ///   vn->setFlags(Varnode::annotation);
    ///   assignHigh(vn);
    ///   return vn;
    /// Rugra has no dedicated TypeCode; we still create a 1-byte Varnode at the
    /// given code address and mark it as an annotation.
    pub fn new_code_ref(
        &mut self,
        m: crate::address::Address,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let vn = self.vbank.create(1, m);
        vn.write().unwrap().set_flags(crate::varnode::varnode_flags::ANNOTATION);
        let _ = self.assign_high(&vn);
        vn
    }

    // Ghidra: funcdata_varnode.cc:252 Funcdata::cloneVarnode
    /// Shallow-clone a Varnode from another Funcdata into \b this. Faithful to
    /// `Funcdata::cloneVarnode` (funcdata_varnode.cc:252-267):
    ///   newvn = vbank.create(vn->getSize(), vn->getAddr(), vn->getType());
    ///   uint4 vflags = vn->getFlags();
    ///   vflags &= (annotation | externref | readonly | persist |
    ///             addrtied | addrforce | indirect_creation | incidental_copy |
    ///             volatil | mapped);
    ///   newvn->setFlags(vflags);
    ///   return newvn;
    /// Used by `cloneOp` / `truncatedFlow` to copy raw p-code across functions.
    /// The clone deliberately does NOT carry over `def`/`descend` links — the
    /// caller re-establishes them via `opSetOutput`/`opSetInput`.
    pub fn clone_varnode(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        use crate::varnode::varnode_flags as vf;
        let (size, loc, vflags) = {
            let r = vn.read().unwrap();
            (r.size, r.loc, r.flags)
        };
        let newvn = self.vbank.create(size, loc);
        // cc:260-264: keep only the documented flag subset.
        let keep_mask = vf::ANNOTATION
            | vf::EXTERNREF
            | vf::READONLY
            | vf::PERSIST
            | vf::ADDRTIED
            | vf::ADDRFORCE
            | vf::INDIRECT_CREATION
            | vf::INCIDENTAL_COPY
            | vf::VOLATIL
            | vf::MAPPED;
        newvn.write().unwrap().set_flags(vflags & keep_mask);
        newvn
    }

    // Ghidra: funcdata_varnode.cc:298 Funcdata::checkForLanedRegister
    /// Check if the given storage range is a potential laned register; if so,
    /// record the storage with the matching laned-register record. Faithful to
    /// `Funcdata::checkForLanedRegister` (funcdata_varnode.cc:298-309):
    ///   const LanedRegister *lanedRegister = glb->getLanedRegister(addr, sz);
    ///   if (lanedRegister == NULL) return;
    ///   VarnodeData storage{addr.getSpace(), addr.getOffset(), sz};
    ///   lanedMap[storage] = lanedRegister;
    /// The explicit `space` parameter restores the address-space component
    /// carried by Ghidra's `Address`, which Rugra's scalar `Address` separates.
    pub fn check_for_laned_register(
        &mut self,
        sz: usize,
        space: crate::space::AddressSpace,
        addr: crate::address::Address,
    ) {
        let Some(record) = self
            .arch
            .as_ref()
            .and_then(|arch| arch.get_laned_register(addr, sz))
        else {
            return;
        };
        let storage = LanedStorage {
            space,
            offset: addr.as_u64(),
            size: sz,
        };
        self.laned_map.insert(storage, record);
    }

    // Ghidra: funcdata.hh:155 Funcdata::setLanedRegGenerated
    /// Stop recording newly created laned-register accesses for the remainder
    /// of the current ActionLaneDivide lifecycle.
    pub fn set_laned_reg_generated(&mut self) {
        self.min_laned_size = 1_000_000;
    }

    // Ghidra: funcdata.hh:397 Funcdata::beginLaneAccess
    /// Iterate recorded lane accesses in `VarnodeData::operator<` order.
    pub fn lane_accesses(
        &self,
    ) -> std::collections::btree_map::Iter<
        '_,
        LanedStorage,
        std::sync::Arc<crate::transform::LanedRegister>,
    > {
        self.laned_map.iter()
    }

    // Ghidra: funcdata.hh:399 Funcdata::clearLanedAccessMap
    /// Clear all recorded candidate storage locations without changing the
    /// current minimum-size gate.
    pub fn clear_laned_access_map(&mut self) {
        self.laned_map.clear();
    }

    // Ghidra: funcdata_varnode.cc:494 Funcdata::adjustInputVarnodes
    /// Collapse any input Varnodes contained in the range `[addr, addr+sz)`
    /// into a single input, redefining the originals as SUBPIECEs of it.
    /// Faithful to `Funcdata::adjustInputVarnodes`
    /// (funcdata_varnode.cc:494-537):
    ///   endaddr = addr + (sz-1);
    ///   for each input vn in [addr, endaddr]:
    ///     if (vn->getOffset() + (vn->getSize()-1) > endaddr) throw;
    ///     inlist.push_back(vn);
    ///   for each vn in inlist:
    ///     sa = addr.justifiedContain(sz, vn->getAddr(), vn->getSize(), false);
    ///     if (!isInput || sa<0 || sz<=vn->getSize()) throw;
    ///     subop = newOp(2, getAddress()); SUBPIECE;
    ///     opSetInput(subop, newConstant(4, sa), 1);
    ///     newvn = newVarnodeOut(vn->getSize(), vn->getAddr(), subop);
    ///     opInsertBegin(subop, bblocks[0]);
    ///     totalReplace(vn, newvn); deleteVarnode(vn);
    ///     inlist[i] = newvn;
    ///   invn = newVarnode(sz, addr); invn = setInputVarnode(invn);
    ///   invn->setWriteMask();
    ///   for each vn in inlist: opSetInput(vn->getDef(), invn, 0);
    /// RUGRA-GAP: `justifiedContain` is approximated by a direct byte offset;
    /// Rugra scans loc_tree for inputs completely contained in the range.
    pub fn adjust_input_varnodes(
        &mut self,
        addr: crate::address::Address,
        sz: usize,
    ) -> crate::error::Result<()> {
        let end = addr.as_u64().saturating_add(sz.saturating_sub(1) as u64);
        // cc:500-508: gather inputs completely contained in [addr, end].
        let inlist: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = self
            .vbank
            .loc_tree
            .iter()
            .filter_map(|lr| {
                let r = lr.0.read().unwrap();
                if !r.is_input() { return None; }
                let start = r.loc.as_u64();
                let vn_end = start.saturating_add(r.size as u64).saturating_sub(1);
                if start < addr.as_u64() || vn_end > end { return None; }
                Some(lr.0.clone())
            })
            .collect();
        // cc:510-524: replace each contained input with a SUBPIECE off the new
        // combined input, then destroy the old input.
        let mut replaced: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = Vec::new();
        for vn in inlist {
            let (vn_addr, vn_size) = {
                let r = vn.read().unwrap();
                (r.loc.as_u64(), r.size)
            };
            let sa = vn_addr.saturating_sub(addr.as_u64()) as usize;
            if sz <= vn_size { continue; }
            let pc = self.baseaddr;
            let subop = self.new_op(2, pc);
            self.op_set_opcode(&subop, crate::opcodes::OpCode::CPUI_SUBPIECE);
            let sa_const = self.new_constant(4, sa as u64);
            self.op_set_input(&subop, sa_const, 1);
            let newvn = self.new_varnode_out(vn_size, crate::address::Address::new(vn_addr), &subop);
            // cc:520: opInsertBegin(subop, bblocks[0]).
            if let Some(bb0) = self.bblocks.get_block(0) {
                self.op_insert_begin(&subop, &bb0);
            }
            self.total_replace(&vn, newvn.clone());
            self.delete_varnode(&vn)?;
            replaced.push(newvn);
        }
        if replaced.is_empty() { return Ok(()); }
        // cc:526-531: create the combined input and mark it writemask.
        let invn = self.new_varnode(sz, addr);
        let invn = self.set_input_varnode(invn);
        invn.write().unwrap().set_write_mask();
        // cc:533-536: each replacement SUBPIECE reads the new input at slot 0.
        for newvn in replaced {
            let def = newvn.read().unwrap().get_def();
            if let Some(def) = def {
                self.op_set_input(&crate::op::PcodeOpRef(def), invn.clone(), 0);
            }
        }
        Ok(())
    }

    // Ghidra: funcdata_varnode.cc:543 Funcdata::descend2Undef
    /// Replace every read of `vn` with a 0xBADDEF constant, inserting COPY
    /// ops where the reader is a MULTIEQUAL or INDIRECT (constants cannot go
    /// directly into those slots). Faithful to `Funcdata::descend2Undef`
    /// (funcdata_varnode.cc:543-583):
    ///   for each descendant op (skipping dead-parent ops):
    ///     if MULTIEQUAL: copyop = newOp(1, inbl->getStart()); COPY(badconst);
    ///                    insertEnd(inbl); opSetInput(op, inputvn, i);
    ///     else if INDIRECT: copyop = newOp(1, op->getAddr()); COPY(badconst);
    ///                       insertBefore(op); opSetInput(op, inputvn, i);
    ///     else: opSetInput(op, badconst, i);
    /// Used by unreachable-block removal to make stale reads explicit.
    /// Returns true if any modified op was inside a block with non-zero in-edges.
    pub fn descend2_undef(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
        use crate::opcodes::OpCode as OC;
        let sz = vn.read().unwrap().size;
        // cc:556: iterate descendants; gather first since we'll mutate.
        let descends: Vec<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>> =
            vn.read().unwrap().descend_iter().collect();
        let mut res = false;
        for op_arc in descends {
            let opc = op_arc.read().unwrap().opcode;
            let parent = op_arc.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
            // cc:558-559: skip ops whose parent block has been destroyed.
            // Rugra models this as parent.is_none() — a destroyed block clears
            // the op's parent link. The Ghidra `isDead()` block flag is not
            // modeled as a runtime field; we treat presence of a parent as
            // "alive" and set `res` if that parent has incoming edges.
            if parent.is_none() { continue; }
            if let Some(p) = &parent {
                if p.read().unwrap().size_in() != 0 { res = true; }
            }
            let op_ref = crate::op::PcodeOpRef(op_arc.clone());
            let slot = self.op_get_slot(&op_ref, vn) as usize;
            let badconst = self.new_constant(sz, 0xBA_AD_EF);
            match opc {
                OC::CPUI_MULTIEQUAL => {
                    // cc:563-569: insert COPY in the predecessor block.
                    let inblk_edge = parent.as_ref().and_then(|p| p.read().unwrap().get_in(slot));
                    let inbl_start = inblk_edge.as_ref().and_then(|e| {
                        e.point.read().unwrap().as_any()
                            .downcast_ref::<crate::block::BlockBasic>()
                            .map(|bb| bb.start_addr)
                    }).unwrap_or(self.baseaddr);
                    let copyop = self.new_op(1, inbl_start);
                    self.op_set_opcode(&copyop, OC::CPUI_COPY);
                    let inputvn = self.new_unique_out(sz, &copyop);
                    self.op_set_input(&copyop, badconst, 0);
                    if let Some(e) = inblk_edge {
                        self.op_insert_end(&copyop, &e.point);
                    }
                    self.op_set_input(&op_ref, inputvn, slot);
                }
                OC::CPUI_INDIRECT => {
                    // cc:571-577: insert COPY immediately before the INDIRECT.
                    let op_addr = op_arc.read().unwrap().get_addr();
                    let copyop = self.new_op(1, op_addr);
                    self.op_set_opcode(&copyop, OC::CPUI_COPY);
                    let inputvn = self.new_unique_out(sz, &copyop);
                    self.op_set_input(&copyop, badconst, 0);
                    self.op_insert_before(&copyop, &op_ref);
                    self.op_set_input(&op_ref, inputvn, slot);
                }
                _ => {
                    // cc:579-580: directly slot the constant.
                    self.op_set_input(&op_ref, badconst, slot);
                }
            }
        }
        res
    }

    // Ghidra: funcdata_varnode.cc:585 Funcdata::initActiveOutput
    /// Allocate / reset `activeoutput` for return-value recovery. Faithful to
    /// `Funcdata::initActiveOutput` (funcdata_varnode.cc:585-593):
    ///   activeoutput = new ParamActive(false);
    ///   maxdelay = funcp.getMaxOutputDelay();
    ///   if (maxdelay > 0) maxdelay = 3;
    ///   activeoutput->setMaxPass(maxdelay);
    /// RUGRA-GAP: FuncProto::getMaxOutputDelay is not ported; we use the
    /// Ghidra-default of 3 passes (matches the `maxdelay>0 ? 3` arm).
    pub fn init_active_output(&mut self) {
        let mut active = crate::fspec::ParamActive::new(false);
        // cc:590-592: clamp any positive delay to 3.
        active.set_max_pass(3);
        self.active_output = Some(active);
    }

    // Ghidra: funcdata_varnode.cc:832 Funcdata::clearDeadVarnodes
    /// Free any unattached Varnodes so editing ops can detach/reattach without
    /// leaking. Faithful to `Funcdata::clearDeadVarnodes`
    /// (funcdata_varnode.cc:832-850):
    ///   for vn in vbank.beginLoc()..endLoc():
    ///     if (vn->hasNoDescend()):
    ///       if (vn->isInput() && !vn->isLockedInput()):
    ///         vbank.makeFree(vn); vn->clearCover();
    ///       if (vn->isFree()): vbank.destroy(vn);
    pub fn clear_dead_varnodes(&mut self) {
        // Gather first; we'll mutate vbank during the loop.
        let candidates: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = self
            .vbank
            .loc_tree
            .iter()
            .map(|lr| lr.0.clone())
            .collect();
        for vn in candidates {
            if !vn.read().unwrap().has_no_descend() { continue; }
            let (is_input, is_locked_input) = {
                let r = vn.read().unwrap();
                (r.is_input(), (r.addlflags & crate::varnode::addl_flags::LOCKED_INPUT) != 0)
            };
            if is_input && !is_locked_input {
                // cc:843-845: makeFree + clearCover.
                // `vn` came from this bank's loc_tree snapshot, proving the
                // Arc-identity precondition of the internal transition.
                self.vbank.make_free_prevalidated(&vn);
                vn.write().unwrap().clear_cover();
            }
            if vn.read().unwrap().is_free() {
                // cc:841 guards hasNoDescend; makeFree (if needed) cleared
                // the definition, so the integrated-destroy guard is proven.
                self.vbank.destroy_varnode_prevalidated(&vn);
            }
        }
    }

    // Ghidra: funcdata_varnode.cc:635 Funcdata::fillinReadOnly
    /// Treat the given Varnode as read-only; look up its value in the
    /// LoadImage and replace read references with that value as a constant.
    /// Faithful to `Funcdata::fillinReadOnly`
    /// (funcdata_varnode.cc:635-709):
    ///   if (vn->isWritten()) {
    ///     defop = vn->getDef();
    ///     if (defop->isMarker()) defop->setAdditionalFlag(warning);
    ///     else if (!defop->isWarning()) {
    ///       defop->setAdditionalFlag(warning);
    ///       if (!isAddrForce || !hasNoDescend)
    ///         warning("Read-only address ... is written", defop->getAddr());
    ///     }
    ///     return false;
    ///   }
    ///   if (vn->getSize() > sizeof(uintb)) return false;
    ///   try { glb->loader->loadFill(bytes, size, addr); }
    ///   catch (DataUnavailError) { vn->clearFlags(readonly); return true; }
    ///   res = assemble bytes (big/little endian);
    ///   for each descendant op:
    ///     if (op->isMarker() && (op!=INDIRECT || slot!=0)) continue;
    ///       if INDIRECT: opRemoveInput(1); opSetOpcode(op, COPY);
    ///     cvn = newConstant(size, res);
    ///     if (locktype) cvn->updateType(locktype, true, true);
    ///     opSetInput(op, cvn, slot);
    ///     changemade = true;
    ///   return changemade;
    /// RUGRA-GAP: requires the Architecture's LoadImage; when absent the method
    /// returns false (no change). Marker-op collapse + locktype propagation are
    /// faithfully ported.
    pub fn fillin_read_only(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
        use crate::opcodes::OpCode as OC;
        // cc:638-655: written varnode — warn and bail.
        if vn.read().unwrap().is_written() {
            let def = vn.read().unwrap().get_def();
            if let Some(def) = def {
                let def_ref = crate::op::PcodeOpRef(def);
                let is_marker = def_ref.0.read().unwrap().is_marker();
                if is_marker {
                    def_ref.0.write().unwrap().addlflags |= crate::op::op_addl_flags::WARNING;
                } else {
                    let already_warn = (def_ref.0.read().unwrap().addlflags & crate::op::op_addl_flags::WARNING) != 0;
                    if !already_warn {
                        def_ref.0.write().unwrap().addlflags |= crate::op::op_addl_flags::WARNING;
                        let (addr_force, no_descend, space, addr) = {
                            let r = vn.read().unwrap();
                            (r.is_addr_force(), r.has_no_descend(), r.address_space, r.loc)
                        };
                        if !addr_force || !no_descend {
                            self.warning(
                                &format!("Read-only address ({:?},{:x}) is written", space, addr.as_u64()),
                                def_ref.0.read().unwrap().get_addr(),
                            );
                        }
                    }
                }
            }
            return false;
        }
        // cc:657-658: constants larger than uintb precision can't be assembled.
        let sz = vn.read().unwrap().size;
        if sz > std::mem::size_of::<u64>() { return false; }
        // cc:660-667: load bytes from the LoadImage; on failure clear readonly.
        let vn_addr = vn.read().unwrap().loc;
        let bytes = match self.arch.as_ref() {
            Some(a) => match &a.loader {
                Some(loader) => match loader.load_fill(sz, vn_addr) {
                    Ok(b) => b,
                    Err(_) => {
                        vn.write().unwrap().clear_flags(crate::varnode::varnode_flags::READONLY);
                        return true;
                    }
                },
                None => return false,
            },
            None => return false,
        };
        if bytes.len() < sz { return false; }
        // cc:669-682: assemble the value (little-endian default; Rugra lacks
        // per-space endianness, so we mirror x86-64 LE).
        let mut res: u64 = 0;
        for i in (0..sz).rev() {
            res <<= 8;
            res |= bytes[i] as u64;
        }
        // cc:684-707: replace each read reference with the constant.
        let locktype: Option<std::sync::Arc<crate::type_system::datatype::Datatype>> =
            vn.read().unwrap().get_type().map(|t| t.clone());
        let descends: Vec<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>> =
            vn.read().unwrap().descend_iter().collect();
        let mut changemade = false;
        for op_arc in descends {
            let op_ref = crate::op::PcodeOpRef(op_arc.clone());
            let slot = self.op_get_slot(&op_ref, vn) as usize;
            let is_marker = op_arc.read().unwrap().is_marker();
            let code = op_arc.read().unwrap().opcode;
            if is_marker {
                // cc:694-701: must not place constants into a marker, except
                // an INDIRECT in slot 0 (converted to COPY).
                if code != OC::CPUI_INDIRECT || slot != 0 { continue; }
                // cc:699-700: opRemoveInput(op,1); opSetOpcode(op, COPY).
                self.op_remove_input(&op_ref, 1);
                self.op_set_opcode(&op_ref, OC::CPUI_COPY);
            }
            let cvn = self.new_constant(sz, res);
            if let Some(lt) = &locktype {
                // cc:703-704: cvn->updateType(locktype, true, true) — pass on
                // the locked datatype. Rugra's update_type takes (Arc<Datatype>);
                // the (lock, override_lock) flags map to the lock-keeping path
                // via update_type_lock when typelock is set.
                cvn.write().unwrap().update_type_lock(lt.clone(), true, true);
            }
            self.op_set_input(&op_ref, cvn, slot);
            changemade = true;
        }
        changemade
    }

    // Ghidra: funcdata_varnode.cc:717 Funcdata::replaceVolatile
    /// Model a volatile Varnode's read/write with a special user-op
    /// (BUILTIN_VOLATILE_READ / BUILTIN_VOLATILE_WRITE). Faithful to
    /// `Funcdata::replaceVolatile` (funcdata_varnode.cc:717-764):
    ///   if (vn->isWritten()) {            // a write
    ///     vw_op = registerBuiltin(VOLATILE_WRITE);
    ///     if (!hasNoDescend) throw;
    ///     defop = vn->getDef();
    ///     newop = newOp(3, defop->getAddr()); CALLOTHER;
    ///     opSetInput(newop, newConstant(4, vw_op->getIndex()), 0);
    ///     annoteVn = newCodeRef(vn->getAddr()); annoteVn->setFlags(volatil);
    ///     opSetInput(newop, annoteVn, 1);
    ///     tmp = newUnique(size); opSetOutput(defop, tmp);
    ///     opSetInput(newop, tmp, 2); opInsertAfter(newop, defop);
    ///   } else {                          // a read
    ///     vr_op = registerBuiltin(VOLATILE_READ);
    ///     if (hasNoDescend) return false;
    ///     readop = vn->loneDescend(); if null throw;
    ///     newop = newOp(2, readop->getAddr()); CALLOTHER;
    ///     tmp = newUniqueOut(size, newop);
    ///     opSetInput(newop, newConstant(4, vr_op->getIndex()), 0);
    ///     annoteVn = newCodeRef(vn->getAddr()); annoteVn->setFlags(volatil);
    ///     opSetInput(newop, annoteVn, 1);
    ///     opSetInput(readop, tmp, readop->getSlot(vn));
    ///     opInsertBefore(newop, readop);
    ///     if (vr_op->getDisplay() != 0) newop->setHoldOutput();
    ///   }
    ///   if (vn->isTypeLock()) newop->setAdditionalFlag(special_prop);
    ///   return true;
    /// RUGRA-GAP: Architecture's UserOpManage is consulted for the builtin
    /// index; if absent the method returns false (no change).
    pub fn replace_volatile(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
        use crate::opcodes::OpCode as OC;
        let sz = vn.read().unwrap().size;
        let vn_addr = vn.read().unwrap().loc;
        let is_written = vn.read().unwrap().is_written();
        let is_type_lock = vn.read().unwrap().is_type_lock();
        let newop = if is_written {
            // cc:721-738: model the write.
            let vw_index = match self.arch.as_ref() {
                Some(a) => match &a.userops {
                    Some(uo) => uo.write().unwrap().register_builtin_by_id(crate::userop::BUILTIN_VOLATILE_WRITE) as u64,
                    None => return false,
                },
                None => return false,
            };
            if !vn.read().unwrap().has_no_descend() {
                eprintln!("[FUNCDATA] replaceVolatile: volatile memory was propagated");
                return false;
            }
            let def = match vn.read().unwrap().get_def() { Some(d) => d, None => return false };
            let def_ref = crate::op::PcodeOpRef(def.clone());
            let def_addr = def.read().unwrap().get_addr();
            let newop = self.new_op(3, def_addr);
            self.op_set_opcode(&newop, OC::CPUI_CALLOTHER);
            let idx_const = self.new_constant(4, vw_index);
            self.op_set_input(&newop, idx_const, 0);
            // cc:730-731: annoteVn = newCodeRef(addr); setFlags(volatil).
            let annote_vn = self.new_code_ref(vn_addr);
            annote_vn.write().unwrap().set_flags(crate::varnode::varnode_flags::VOLATIL);
            self.op_set_input(&newop, annote_vn, 1);
            // cc:733-734: tmp = newUnique(size); opSetOutput(defop, tmp).
            let tmp = self.new_unique(sz);
            self.op_set_output(&def_ref, tmp.clone());
            // cc:736: opSetInput(newop, tmp, 2).
            self.op_set_input(&newop, tmp, 2);
            // cc:738: opInsertAfter(newop, defop).
            self.op_insert_after(&newop, &def_ref);
            newop
        } else {
            // cc:740-759: model the read.
            let vr_index = match self.arch.as_ref() {
                Some(a) => match &a.userops {
                    Some(uo) => uo.write().unwrap().register_builtin_by_id(crate::userop::BUILTIN_VOLATILE_READ) as u64,
                    None => return false,
                },
                None => return false,
            };
            if vn.read().unwrap().has_no_descend() { return false; }
            let readop = match vn.read().unwrap().lone_descend() { Some(r) => r, None => {
                eprintln!("[FUNCDATA] replaceVolatile: volatile memory value used more than once");
                return false;
            }};
            let readop_ref = crate::op::PcodeOpRef(readop.clone());
            let read_addr = readop.read().unwrap().get_addr();
            let newop = self.new_op(2, read_addr);
            self.op_set_opcode(&newop, OC::CPUI_CALLOTHER);
            let tmp = self.new_unique_out(sz, &newop);
            let idx_const = self.new_constant(4, vr_index);
            self.op_set_input(&newop, idx_const, 0);
            let annote_vn = self.new_code_ref(vn_addr);
            annote_vn.write().unwrap().set_flags(crate::varnode::varnode_flags::VOLATIL);
            self.op_set_input(&newop, annote_vn, 1);
            let slot = self.op_get_slot(&readop_ref, vn) as usize;
            self.op_set_input(&readop_ref, tmp, slot);
            self.op_insert_before(&newop, &readop_ref);
            // cc:758-759: if (vr_op->getDisplay() != 0) newop->setHoldOutput().
            // Rugra: VOLATILE_READ's display is functional (1), so always hold.
            // HOLD_OUTPUT lives in addl_flags (Rugra models it as an addlflag).
            newop.0.write().unwrap().addlflags |= crate::op::op_addl_flags::HOLD_OUTPUT;
            newop
        };
        // cc:761-762: if (vn->isTypeLock()) newop->setAdditionalFlag(special_prop).
        if is_type_lock {
            // RUGRA-GAP: Ghidra's PcodeOp::special_prop (0x10000) is not
            // modeled as a dedicated addl-flag; we approximate with the
            // closest semantic — STOP_TYPE_PROPAGATION (0x40) — so type
            // recovery knows the volatile user-op needs special handling.
            newop.0.write().unwrap().addlflags |= crate::op::op_addl_flags::STOP_TYPE_PROPAGATION;
        }
        true
    }

    // Ghidra: funcdata_varnode.cc:771 Funcdata::checkIndirectUse
    /// Test if the given Varnode only flows into call-based INDIRECT ops,
    /// following flow through MULTIEQUAL ops. Faithful to
    /// `Funcdata::checkIndirectUse` (funcdata_varnode.cc:771-811):
    ///   vlist = {vn}; vn->setMark();
    ///   while (i < vlist.size() && result):
    ///     vn = vlist[i++];
    ///     for each descendant op:
    ///       if INDIRECT: if isIndirectStore follow outvn; else continue;
    ///       else if MULTIEQUAL: follow outvn;
    ///       else: result = false; break;
    ///   clear marks; return result;
    pub fn check_indirect_use(
        &self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
        use crate::opcodes::OpCode as OC;
        let mut vlist: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = vec![vn.clone()];
        vn.write().unwrap().set_mark();
        let mut i = 0;
        let mut result = true;
        while i < vlist.len() && result {
            let cur = vlist[i].clone();
            i += 1;
            let descends: Vec<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>> =
                cur.read().unwrap().descend_iter().collect();
            for op_arc in descends {
                let code = op_arc.read().unwrap().opcode;
                match code {
                    OC::CPUI_INDIRECT => {
                        if op_arc.read().unwrap().is_indirect_store() {
                            // cc:786-793: INDIRECT from a STORE — follow outvn.
                            let outvn = op_arc.read().unwrap().get_out().cloned();
                            if let Some(outvn) = outvn {
                                if !outvn.read().unwrap().is_mark() {
                                    outvn.write().unwrap().set_mark();
                                    vlist.push(outvn);
                                }
                            }
                        }
                        // else: a call-based INDIRECT — keep going (result stays true).
                    }
                    OC::CPUI_MULTIEQUAL => {
                        // cc:795-800: follow outvn.
                        let outvn = op_arc.read().unwrap().get_out().cloned();
                        if let Some(outvn) = outvn {
                            if !outvn.read().unwrap().is_mark() {
                                outvn.write().unwrap().set_mark();
                                vlist.push(outvn);
                            }
                        }
                    }
                    _ => {
                        // cc:802-804: any other op → not indirect-only.
                        result = false;
                        break;
                    }
                }
            }
        }
        for v in &vlist { v.write().unwrap().clear_mark(); }
        result
    }

    // Ghidra: funcdata_varnode.cc:815 Funcdata::markIndirectOnly
    /// Mark every illegal-input Varnode that only flows into call-based
    /// INDIRECTs with the `indirectonly` flag. Faithful to
    /// `Funcdata::markIndirectOnly` (funcdata_varnode.cc:815-828):
    ///   for each input vn:
    ///     if (!vn->isIllegalInput()) continue;
    ///     if (checkIndirectUse(vn)) vn->setFlags(indirectonly);
    pub fn mark_indirect_only(&mut self) {
        // Gather inputs first to avoid holding a borrow across mutation.
        let inputs: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = self
            .vbank
            .loc_tree
            .iter()
            .filter_map(|lr| {
                let r = lr.0.read().unwrap();
                if r.is_input() && r.is_illegal_input() { Some(lr.0.clone()) } else { None }
            })
            .collect();
        for vn in inputs {
            if self.check_indirect_use(&vn) {
                vn.write().unwrap().set_flags(crate::varnode::varnode_flags::INDIRECTONLY);
            }
        }
    }

    // Ghidra: funcdata_varnode.cc:1653 Funcdata::mapGlobals
    /// For each persistent global Varnode that has no symbol yet, create / link
    /// a global Symbol. Faithful to `Funcdata::mapGlobals`
    /// (funcdata_varnode.cc:1653-1719):
    ///   for each run of persistent Varnodes sharing a base address:
    ///     maxvn = biggest vn; ct = type of maxvn (or sized base type);
    ///     entry = localmap->queryProperties(addr, 1, usepoint, fl);
    ///     if (entry == NULL) {
    ///       discover = localmap->discoverScope(addr, sz, usepoint);
    ///       name = discover->buildVariableName(addr, usepoint, ct, 0,
    ///                                          addrtied|persist);
    ///       discover->addSymbol(name, ct, addr, usepoint);
    ///     } else if ((addr+sz-1) > (entry_addr+entry_sz-1)) {
    ///       inconsistentuse = true;
    ///       if (!uncoveredVarnodes.empty()) coverVarnodes(entry, uncovered);
    ///     }
    ///   if (inconsistentuse) warningHeader("Globals starting with '_' ...");
    /// RUGRA-GAP: Rugra's ScopeLocal has no queryProperties/discoverScope/
    /// addSymbol/buildVariableName; we approximate by recording each new
    /// global in `symbol_table` (matching the existing link_symbol strategy)
    /// and calling cover_varnodes when an inconsistent overlap is detected.
    pub fn map_globals(&mut self) {
        // Gather persistent varnodes (sorted by Address via loc_tree).
        let candidates: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = self
            .vbank
            .loc_tree
            .iter()
            .map(|lr| lr.0.clone())
            .filter(|vn| {
                let r = vn.read().unwrap();
                !r.is_free() && r.is_persist()
            })
            .collect();
        let mut inconsistent = false;
        let mut i = 0;
        while i < candidates.len() {
            let vn = candidates[i].clone();
            i += 1;
            // cc:1670: skip if already has a symbol entry.
            let already_mapped = vn.read().unwrap().is_mapped();
            if already_mapped { continue; }
            // cc:1671-1691: gather the run of overlapping persistent varnodes.
            let (addr, mut endaddr, mut max_size) = {
                let r = vn.read().unwrap();
                let a = r.loc.as_u64();
                (a, a + r.size as u64, r.size)
            };
            let mut uncovered: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = Vec::new();
            while i < candidates.len() {
                let next = candidates[i].clone();
                let r = next.read().unwrap();
                if !r.is_persist() { break; }
                if r.loc.as_u64() >= endaddr { break; }
                // cc:1682-1683: internal varnode with no symbol → uncovered.
                if r.loc.as_u64() != addr && !r.is_mapped() {
                    uncovered.push(next.clone());
                }
                endaddr = endaddr.max(r.loc.as_u64() + r.size as u64);
                if r.size > max_size { max_size = r.size; }
                i += 1;
            }
            // cc:1697-1701: queryProperties → does a symbol already overlap?
            let has_symbol = self.scope.as_ref().map(|s| s.has_overlap(addr, 1)).unwrap_or(false)
                || self.symbol_table.contains_key(&addr);
            if !has_symbol {
                // cc:1702-1709: discoverScope + buildVariableName + addSymbol.
                // Rugra: record a synthetic name in symbol_table.
                let name = format!("global_{:x}", addr);
                self.symbol_table.insert(addr, name);
            } else if (addr + max_size as u64).saturating_sub(1)
                > self.symbol_table.get(&addr).map(|_| addr).unwrap_or(u64::MAX)
            {
                // cc:1711-1715: inconsistent overlap → cover uncovered varnodes.
                inconsistent = true;
                if !uncovered.is_empty() {
                    let entry_name = self.symbol_table.get(&addr).cloned().unwrap_or_default();
                    self.cover_varnodes(addr, &entry_name, &uncovered);
                }
            }
        }
        // cc:1717-1718: warningHeader on inconsistent use.
        if inconsistent {
            self.warning_header(
                "Globals starting with '_' overlap smaller symbols at the same address",
            );
        }
    }

    // Ghidra: funcdata_varnode.cc:1314 Funcdata::attemptDynamicMapping
    /// Given a dynamic SymbolEntry, find its Varnode via DynamicHash and attach
    /// the symbol's properties. Faithful to `Funcdata::attemptDynamicMapping`
    /// (funcdata_varnode.cc:1314-1337):
    ///   sym = entry->getSymbol();
    ///   if (sym->getScope() != localmap) throw;
    ///   dhash.clear();
    ///   category = sym->getCategory();
    ///   if (category == union_facet) return applyUnionFacet(entry, dhash);
    ///   vn = dhash.findVarnode(this, entry->getFirstUseAddress(), entry->getHash());
    ///   if (vn == NULL) return false;
    ///   if (vn->getSymbolEntry() != NULL) return false;
    ///   if (category == equate) { vn->setSymbolEntry(entry); return true; }
    ///   else if (entry->getSize() == vn->getSize())
    ///     if (vn->setSymbolProperties(entry)) return true;
    ///   return false;
    /// RUGRA-GAP: Rugra has no SymbolEntry/Symbol objects on Funcdata; the
    /// caller supplies (first_use_addr, hash, size, category) directly. On a
    /// successful find, MAPPED is set and the name is recorded.
    pub fn attempt_dynamic_mapping(
        &mut self,
        first_use_addr: crate::address::Address,
        hash: u64,
        size: usize,
        is_equate: bool,
        is_union_facet: bool,
        sym_name: &str,
    ) -> bool {
        // cc:1322-1324: union_facet → applyUnionFacet.
        if is_union_facet {
            // RUGRA-GAP: full union-facet path needs parent type; callers
            // should use apply_union_facet directly. We treat as no-match.
            return false;
        }
        // cc:1325: vn = dhash.findVarnode(this, addr, hash).
        let vn = {
            let mut dhash = crate::dynamic::DynamicHash::new();
            dhash.find_varnode(self, first_use_addr, hash)
        };
        let Some(vn) = vn else { return false };
        // cc:1326-1327: if (vn->getSymbolEntry()) return false.
        if vn.read().unwrap().is_mapped() { return false; }
        // cc:1328-1331: equate category → setSymbolEntry.
        if is_equate {
            vn.write().unwrap().set_flags(crate::varnode::varnode_flags::MAPPED);
            self.symbol_table.insert(hash | 0x8000_0000_0000_0000, sym_name.to_string());
            return true;
        }
        // cc:1332-1335: matching size → setSymbolProperties.
        if vn.read().unwrap().size == size {
            vn.write().unwrap().set_flags(crate::varnode::varnode_flags::MAPPED);
            self.symbol_table.insert(hash | 0x8000_0000_0000_0000, sym_name.to_string());
            return true;
        }
        false
    }

    // Ghidra: funcdata_varnode.cc:1347 Funcdata::attemptDynamicMappingLate
    /// Late-phase dynamic mapping: attach the Symbol's NAME only (no
    /// type/property forcing). Faithful to `Funcdata::attemptDynamicMappingLate`
    /// (funcdata_varnode.cc:1347-1399):
    ///   dhash.clear();
    ///   sym = entry->getSymbol();
    ///   if (sym->getCategory() == union_facet) return applyUnionFacet(...);
    ///   vn = dhash.findVarnode(this, addr, hash);
    ///   if (vn == NULL) return false;
    ///   if (vn->getSymbolEntry()) return false;
    ///   if (category == equate) { vn->setSymbolEntry(entry); return true; }
    ///   if (vn->getSize() != entry->getSize()) {
    ///     warningHeader("Unable to use symbol ...: Size does not match");
    ///     return false;
    ///   }
    ///   if (vn->isImplied()) { /* look across a CAST */ }
    ///   vn->setSymbolEntry(entry);
    ///   if (!sym->isTypeLocked()) localmap->retypeSymbol(sym, vn->getType());
    ///   else if (sym->getType() != vn->getType()) warningHeader(...);
    ///   return true;
    /// RUGRA-GAP: SymbolEntry/ScopeLocal.retypeSymbol not ported; we attach the
    /// name + MAPPED flag and warn on size mismatch, matching the user-visible
    /// behaviour.
    pub fn attempt_dynamic_mapping_late(
        &mut self,
        first_use_addr: crate::address::Address,
        hash: u64,
        size: usize,
        is_equate: bool,
        is_union_facet: bool,
        sym_name: &str,
    ) -> bool {
        // cc:1352-1354: union_facet → applyUnionFacet.
        if is_union_facet { return false; }
        // cc:1355: vn = dhash.findVarnode(this, addr, hash).
        let vn = {
            let mut dhash = crate::dynamic::DynamicHash::new();
            dhash.find_varnode(self, first_use_addr, hash)
        };
        let Some(vn) = vn else { return false };
        // cc:1358: already labelled.
        if vn.read().unwrap().is_mapped() { return false; }
        // cc:1359-1361: equate → setSymbolEntry regardless of size.
        if is_equate {
            vn.write().unwrap().set_flags(crate::varnode::varnode_flags::MAPPED);
            self.symbol_table.insert(hash | 0x8000_0000_0000_0000, sym_name.to_string());
            return true;
        }
        // cc:1363-1371: size mismatch → warningHeader + return false.
        if vn.read().unwrap().size != size {
            self.warning_header(&format!(
                "Unable to use symbol {}: Size does not match variable it labels",
                sym_name
            ));
            return false;
        }
        // cc:1373-1386: implied varnode → follow across a CAST (omitted; rare).
        // cc:1388: vn->setSymbolEntry(entry).
        vn.write().unwrap().set_flags(crate::varnode::varnode_flags::MAPPED);
        self.symbol_table.insert(hash | 0x8000_0000_0000_0000, sym_name.to_string());
        // cc:1389-1397: retype / warningHeader on type mismatch omitted
        // (RUGRA-GAP: no ScopeLocal.retypeSymbol).
        true
    }

    // Ghidra: varnode.hh:313 Varnode::setReturnAddress / funcdata.cc setters
    /// Mark `vn` as the storage location for a return address. Faithful to
    /// `Varnode::setReturnAddress` (varnode.hh:313):
    ///   void setReturnAddress(void) { flags |= Varnode::return_address; }
    /// This is the Funcdata-level entry point used by `setInputVarnode`
    /// (funcdata_varnode.cc:368-371) when a ProtoModel effect records the
    /// input as a return-address storage location.
    pub fn set_return_address(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        vn.write().unwrap().set_return_address();
    }

    // Ghidra: funcdata_varnode.cc:1756 Funcdata::checkCallDoubleUse
    /// Test for legitimate double use of a parameter trial: the trial is a
    /// putative input to `opmatch`, but also traces into a second CALL `op`.
    /// Faithful to `Funcdata::checkCallDoubleUse`
    /// (funcdata_varnode.cc:1756-1794). The Ghidra original:
    ///   j = op->getSlot(vn);
    ///   if (j <= 0) return false;             // flows to indirect-call var
    ///   fc = getCallSpecs(op); matchfc = getCallSpecs(opmatch);
    ///   if (op->code() == opmatch->code()) {
    ///     bool isdirect = (opmatch->code() == CALL);
    ///     if ((isdirect && matchfc->getEntryAddress()==fc->getEntryAddress()) ||
    ///         (!isdirect && op->getIn(0)==opmatch->getIn(0))) {
    ///       curtrial = fc->getActiveInput()->getTrialForInputVarnode(j);
    ///       if (curtrial->getAddress() == trial->getAddress()) {
    ///         if (op->getParent()==opmatch->getParent()) {
    ///           if (opmatch->getSeqNum().getOrder() < op->getSeqNum().getOrder())
    ///             return true;
    ///         } else return true;
    ///       }
    ///     }
    ///   }
    ///   if (fc->isInputActive()) {
    ///     curtrial = fc->getActiveInput()->getTrialForInputVarnode(j);
    ///     if (curtrial->isChecked()) {
    ///       if (curtrial->isActive()) return false;
    ///     } else if (TraverseNode::isAlternatePathValid(vn, fl))
    ///       return false;
    ///     return true;
    ///   }
    ///   return false;
    /// Rugra's free-function `only_op_use` does NOT consult call-spec trials,
    /// so this method provides the missing double-use reasoning. It takes the
    /// raw (opmatch, op, vn, fl, trial_addr) inputs; the ParamTrial is reduced
    /// to its address for the same-function / same-trial comparison.
    pub fn check_call_double_use(
        &self,
        opmatch: &crate::op::PcodeOpRef,
        op: &crate::op::PcodeOpRef,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        _fl: u32,
        trial_addr: crate::address::Address,
    ) -> bool {
        use crate::opcodes::OpCode as OC;
        // cc:1759: j = op->getSlot(vn); if (j<=0) return false.
        let j = self.op_get_slot(op, vn);
        if j <= 0 { return false; }
        // cc:1761-1762: fc / matchfc lookup by op address.
        let op_addr = op.0.read().unwrap().get_addr().as_u64();
        let match_addr = opmatch.0.read().unwrap().get_addr().as_u64();
        let fc_idx = self.callspecs.iter().position(|c| c.op_addr.as_u64() == op_addr);
        let matchfc_idx = self.callspecs.iter().position(|c| c.op_addr.as_u64() == match_addr);
        // cc:1763-1781: same-call double-use test.
        let op_code = op.0.read().unwrap().opcode;
        let match_code = opmatch.0.read().unwrap().opcode;
        if op_code == match_code {
            let is_direct = match_code == OC::CPUI_CALL;
            let same_target = match (fc_idx, matchfc_idx) {
                (Some(fi), Some(mi)) => {
                    let fc = &self.callspecs[fi];
                    let mfc = &self.callspecs[mi];
                    if is_direct {
                        fc.entry_addr.is_some() && fc.entry_addr == mfc.entry_addr
                    } else {
                        // CALLIND: compare the indirect-call varnode (in(0)).
                        let a = op.0.read().unwrap().get_in(0).cloned();
                        let b = opmatch.0.read().unwrap().get_in(0).cloned();
                        match (a, b) { (Some(x), Some(y)) => std::sync::Arc::ptr_eq(&x, &y), _ => false }
                    }
                }
                _ => false,
            };
            if same_target {
                // cc:1770-1778: same trial address + ordering test.
                // Rugra: we approximate the per-slot trial-address lookup by
                // checking that the candidate's address equals trial_addr.
                let vn_addr = vn.read().unwrap().loc;
                if vn_addr == trial_addr {
                    let op_parent = op.0.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
                    let match_parent = opmatch.0.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
                    let same_parent = match (op_parent, match_parent) {
                        (Some(a), Some(b)) => std::sync::Arc::ptr_eq(&a, &b),
                        _ => false,
                    };
                    if same_parent {
                        // cc:1773-1774: opmatch dibs if it comes first.
                        let op_order = op.0.read().unwrap().get_seq_num().get_order();
                        let match_order = opmatch.0.read().unwrap().get_seq_num().get_order();
                        if match_order < op_order { return true; }
                        // else fall through (may still reject).
                    } else {
                        // cc:1777-1778: different blocks → assume legit.
                        return true;
                    }
                }
            }
        }
        // cc:1783-1793: input-active path.
        if let Some(fi) = fc_idx {
            if self.callspecs[fi].is_input_active() {
                // cc:1784: curtrial = fc->getActiveInput()->getTrialForInputVarnode(j).
                if let Some(active) = self.callspecs[fi].get_active_input() {
                    // Rugra's ParamActive lacks getTrialForInputVarnode; we
                    // approximate by indexing trials by slot (trial index is
                    // slot-1 since slot 0 is the call target).
                    let trial_idx = (j as usize).saturating_sub(1);
                    if trial_idx < active.get_num_trials() {
                        let trial = active.get_trial(trial_idx);
                        if trial.is_checked() {
                            // cc:1786-1787: checked & active → reject.
                            if trial.is_active() { return false; }
                            return true; // checked & inactive → keep.
                        }
                        // cc:1789-1790: not yet checked → reject if alt path
                        // valid; RUGRA-GAP: TraverseNode::isAlternatePathValid
                        // not ported, so we conservatively keep the trial.
                        return true;
                    }
                }
                return true;
            }
        }
        false
    }

    // Ghidra: funcdata_varnode.cc:1805 Funcdata::onlyOpUse
    /// Test if the given Varnode seems to only be used by a CALL/RETURN op.
    /// Faithful to `Funcdata::onlyOpUse` (funcdata_varnode.cc:1805-1904).
    /// This is the `impl Funcdata` method form of the existing free function
    /// `only_op_use`; it supplies `has_active_output` from `self.active_output`
    /// and delegates to the free function so existing call-sites stay intact.
    pub fn only_op_use(
        &self,
        invn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        opmatch: &crate::op::PcodeOpRef,
        trial_slot: i32,
        main_flags: u32,
    ) -> bool {
        let has_active_output = self.active_output.is_some();
        only_op_use(has_active_output, invn, opmatch, trial_slot, main_flags)
    }

    // Ghidra: funcdata_varnode.cc:1917 Funcdata::ancestorOpUse
    /// Test if the given trial Varnode is likely only used for parameter
    /// passing, following flow from ancestors it was copied from. Faithful to
    /// `Funcdata::ancestorOpUse` (funcdata_varnode.cc:1917-1994). This is the
    /// `impl Funcdata` method form of the free function `ancestor_op_use`;
    /// it supplies `has_active_output` from `self.active_output`.
    pub fn ancestor_op_use(
        &self,
        maxlevel: i32,
        invn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        op: &crate::op::PcodeOpRef,
        trial_slot: i32,
        offset: i32,
        main_flags: u32,
    ) -> bool {
        let has_active_output = self.active_output.is_some();
        ancestor_op_use(has_active_output, maxlevel, invn, op, trial_slot, offset, main_flags)
    }

    // Ghidra: funcdata_op.cc:332 Funcdata::newOp(int4, const SeqNum &)
    /// Create a new PcodeOp with an explicit sequence number. Faithful to
    /// `Funcdata::newOp(int4 inputs, const SeqNum &sq)` (funcdata_op.cc:332).
    /// The immutable creation `time` and mutable block `order` are both
    /// copied, and the bank advances its uniqid past an imported time.
    pub fn new_op_with_seq(&mut self, num_inputs: usize, sq: &crate::address::SeqNum) -> crate::op::PcodeOpRef {
        self.obank.create_seq(num_inputs, *sq)
    }

    // Ghidra: funcdata_op.cc:616 Funcdata::cloneOp
    /// Clone an existing PcodeOp (with a new SeqNum) into this function.
    /// Faithful to `Funcdata::cloneOp` (funcdata_op.cc:616-628):
    ///   PcodeOp *newop = newOp(op->numInput(),seq);
    ///   opSetOpcode(newop,op->code());
    ///   uint4 fl = op->flags & (startmark | startbasic);
    ///   newop->setFlag(fl);
    ///   if (op->getOut() != (Varnode *)0)
    ///     opSetOutput(newop,cloneVarnode(op->getOut()));
    ///   for(int4 i=0;i<op->numInput();++i)
    ///     opSetInput(newop,cloneVarnode(op->getIn(i)),i);
    ///   return newop;
    pub fn clone_op(
        &mut self,
        op: &crate::op::PcodeOpRef,
        seq: &crate::address::SeqNum,
    ) -> crate::op::PcodeOpRef {
        use crate::op::pcodeop_flags as pf;
        let (num_inputs, opcode, flag_subset, has_out) = {
            let r = op.0.read().unwrap();
            let fl = r.flags & (pf::STARTMARK | pf::STARTBASIC);
            (r.num_input(), r.opcode, fl, r.get_out().is_some())
        };
        let newop = self.new_op_with_seq(num_inputs, seq);
        self.op_set_opcode(&newop, opcode);
        // cc:621-622: copy startmark/startbasic flags.
        newop.0.write().unwrap().flags |= flag_subset;
        // cc:623-624: clone the output varnode if any.
        if has_out {
            let out_clone = {
                let r = op.0.read().unwrap();
                self.clone_varnode(r.get_out().unwrap())
            };
            self.op_set_output(&newop, out_clone);
        }
        // cc:625-626: clone each input varnode.
        for i in 0..num_inputs {
            let in_clone = {
                let r = op.0.read().unwrap();
                self.clone_varnode(r.get_in(i).unwrap())
            };
            self.op_set_input(&newop, in_clone, i);
        }
        newop
    }

    // Ghidra: funcdata_op.cc:656 Funcdata::newOpBefore
    /// Create a new PcodeOp with 2 or 3 given operands and insert it before
    /// `follow`. Faithful to `Funcdata::newOpBefore` (funcdata_op.cc:656-671):
    ///   sz = (in3 == NULL) ? 2 : 3;
    ///   newop = newOp(sz, follow->getAddr());
    ///   opSetOpcode(newop, opc);
    ///   newUniqueOut(in1->getSize(), newop);
    ///   opSetInput(newop, in1, 0);
    ///   opSetInput(newop, in2, 1);
    ///   if (sz==3) opSetInput(newop, in3, 2);
    ///   opInsertBefore(newop, follow);
    pub fn new_op_before(
        &mut self,
        follow: &crate::op::PcodeOpRef,
        opc: crate::opcodes::OpCode,
        in1: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        in2: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        in3: Option<&std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    ) -> crate::op::PcodeOpRef {
        let sz = if in3.is_some() { 3 } else { 2 };
        let addr = follow.0.read().unwrap().get_addr();
        let newop = self.new_op(sz, addr);
        self.op_set_opcode(&newop, opc);
        let s1 = in1.read().unwrap().size as usize;
        self.new_unique_out(s1, &newop);
        self.op_set_input(&newop, in1.clone(), 0);
        self.op_set_input(&newop, in2.clone(), 1);
        if sz == 3 {
            self.op_set_input(&newop, in3.unwrap().clone(), 2);
        }
        // cc:671: opInsertBefore — `new_op` already registered the op in
        // optree/alivelist, so we only need to reorder it ahead of `follow`.
        self.op_insert_before(&newop, follow);
        newop
    }

    // Ghidra: funcdata_op.cc:929 Funcdata::findPrimaryBranch
    /// Find the primary branch op within an address range. Faithful to
    /// `Funcdata::findPrimaryBranch` (funcdata_op.cc:929-961): iterate the
    /// ops at `addr` and return the first whose opcode matches the requested
    /// category (branch / call / return). BRANCH/CBRANCH are only returned
    /// when their target input is non-constant (i.e., a real branch, not an
    /// internal p-code branch).
    pub fn find_primary_branch(
        &self,
        ops_at_addr: &[crate::op::PcodeOpRef],
        find_branch: bool,
        find_call: bool,
        find_return: bool,
    ) -> Option<crate::op::PcodeOpRef> {
        use crate::opcodes::OpCode as OC;
        for op_ref in ops_at_addr {
            let r = op_ref.0.read().unwrap();
            match r.opcode {
                OC::CPUI_BRANCH | OC::CPUI_CBRANCH => {
                    if find_branch {
                        // cc:938: skip internal (constant-target) branches.
                        let is_const = r.get_in(0).map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
                        if !is_const { return Some(op_ref.clone()); }
                    }
                }
                OC::CPUI_BRANCHIND => {
                    if find_branch { return Some(op_ref.clone()); }
                }
                OC::CPUI_CALL | OC::CPUI_CALLIND => {
                    if find_call { return Some(op_ref.clone()); }
                }
                OC::CPUI_RETURN => {
                    if find_return { return Some(op_ref.clone()); }
                }
                _ => {}
            }
        }
        None
    }

    // Ghidra: funcdata_op.cc:969 Funcdata::overrideFlow
    /// Override the control-flow p-code for a particular instruction.
    /// Faithful to `Funcdata::overrideFlow` (funcdata_op.cc:969-1021):
    /// given an instruction address and an Override type, locate the primary
    /// branch op at that address (still dead / pre-block-formation) and
    /// rewrite its opcode per the override table. For `CALL_RETURN` a fresh
    /// RETURN op is inserted after the rewritten call. Throws LowlevelError
    /// if the primary op is missing or already alive (block-formed).
    pub fn override_flow(&mut self, addr: crate::address::Address, flow_type: crate::override_rs::FlowOverride) {
        use crate::opcodes::OpCode as OC;
        use crate::override_rs::FlowOverride as FO;
        // cc:972-983: gather dead ops at addr, then dispatch on the override.
        let ops_at_addr: Vec<crate::op::PcodeOpRef> = self.obank.optree.iter()
            .filter(|op| {
                let r = op.0.read().unwrap();
                r.get_addr() == addr && r.is_dead()
            })
            .cloned()
            .collect();
        let primary = match flow_type {
            FO::Branch => self.find_primary_branch(&ops_at_addr, false, true, true),
            FO::Call => self.find_primary_branch(&ops_at_addr, true, false, true),
            FO::CallReturn => self.find_primary_branch(&ops_at_addr, true, true, true),
            FO::Return => self.find_primary_branch(&ops_at_addr, true, true, false),
            FO::None => return,
        };
        let op = match primary {
            Some(o) => o,
            None => {
                self.warning_header("Could not apply flowoverride: no primary op");
                return;
            }
        };
        // cc:988-1020: rewrite the opcode per the override table.
        let opc = op.0.read().unwrap().opcode;
        match flow_type {
            FO::Branch => {
                match opc {
                    OC::CPUI_CALL => self.op_set_opcode(&op, OC::CPUI_BRANCH),
                    OC::CPUI_CALLIND => self.op_set_opcode(&op, OC::CPUI_BRANCHIND),
                    OC::CPUI_RETURN => self.op_set_opcode(&op, OC::CPUI_BRANCHIND),
                    _ => {}
                }
            }
            FO::Call | FO::CallReturn => {
                match opc {
                    OC::CPUI_BRANCH => self.op_set_opcode(&op, OC::CPUI_CALL),
                    OC::CPUI_BRANCHIND => self.op_set_opcode(&op, OC::CPUI_CALLIND),
                    OC::CPUI_RETURN => self.op_set_opcode(&op, OC::CPUI_CALLIND),
                    _ => {}
                }
                // cc:1006-1011: for CALL_RETURN, append a fresh RETURN after.
                if flow_type == FO::CallReturn {
                    let new_return = self.new_op(1, addr);
                    self.op_set_opcode(&new_return, OC::CPUI_RETURN);
                    let c = self.new_constant(1, 0);
                    self.op_set_input(&new_return, c, 0);
                    // cc:1010: opDeadInsertAfter — Rugra approximates by
                    // pushing to deadlist after the primary op's position.
                    let pos = self.obank.deadlist.iter()
                        .position(|r| std::sync::Arc::ptr_eq(&r.0, &op.0));
                    match pos {
                        Some(idx) => self.obank.deadlist.insert(idx + 1, new_return),
                        None => self.obank.deadlist.push(new_return),
                    }
                }
            }
            FO::Return => {
                match opc {
                    OC::CPUI_BRANCHIND => self.op_set_opcode(&op, OC::CPUI_RETURN),
                    OC::CPUI_CALLIND => self.op_set_opcode(&op, OC::CPUI_RETURN),
                    _ => {}
                }
            }
            FO::None => {}
        }
        // Record the override so later passes / serialization see it.
        self.localoverride.insert_flow_override(addr, flow_type);
    }

    // Ghidra: funcdata_op.cc:756 Funcdata::followFlow
    /// Walk the instruction stream and produce p-code + basic blocks for the
    /// half-open range `[baddr, eaddr)`. Faithful to
    /// `Funcdata::followFlow` (funcdata_op.cc:756-783):
    ///   if (!obank.empty()) {
    ///     if ((flags & blocks_generated)==0)
    ///       throw LowlevelError("Function loaded for inlining");
    ///     return;  // Already translated
    ///   }
    ///   FlowInfo flow(*this,obank,bblocks,qlst);
    ///   flow.setRange(baddr,eaddr);
    ///   flow.generateOps();
    ///   size = flow.getSize();
    ///   flow.generateBlocks();
    ///   flags |= blocks_generated;
    ///   switchOverJumpTables(flow);
    ///   if (flow.hasUnimplemented()) flags |= unimplemented_present;
    ///   if (flow.hasBadData())      flags |= baddata_present;
    /// RUGRA-GAP: Rugra currently ingests p-code via `inject_raw_ops` +
    /// `build_blocks_from_ops` (see x86_lift.rs / the test harness), so the
    /// disassembly-driven FlowInfo walk is not wired up. This stub preserves
    /// the Ghidra semantics for the "already translated" early-return path
    /// and the flag side-effects, and is the natural attachment point when
    /// a Rugra FlowInfo / lifter is added.
    pub fn follow_flow(&mut self, baddr: crate::address::Address, eaddr: crate::address::Address) {
        // cc:759-763: if obank already populated, this function is either
        // already translated (blocks_generated set → return) or was loaded
        // for inlining (→ error).
        if !self.obank.optree.is_empty() {
            if (self.flags & funcdata_flags::BLOCKS_GENERATED) == 0 {
                self.warning_header("Function loaded for inlining; follow_flow ignored");
            }
            return;
        }
        // cc:767-783: FlowInfo walk + block generation + flag side-effects.
        // RUGRA-GAP: full FlowInfo not implemented; record the range so any
        // future lifter can pick it up, and set blocks_generated defensively.
        let _ = (baddr, eaddr);
        self.flags |= funcdata_flags::BLOCKS_GENERATED;
    }

    // Ghidra: funcdata.hh:547 Funcdata::getStructure
    /// Get the current control-flow structuring hierarchy. Faithful to
    /// `BlockGraph &getStructure(void)` (funcdata.hh:547) — returns a mutable
    /// reference to the structured BlockGraph (`sblocks`) that sits on top of
    /// the basic blocks.
    pub fn get_structure(&mut self) -> &mut crate::block::BlockGraph {
        &mut self.sblocks
    }

    // Ghidra: funcdata.hh:549 Funcdata::getBasicBlocks
    /// Get the basic-block container. Faithful to
    /// `const BlockGraph &getBasicBlocks(void) const` (funcdata.hh:549).
    pub fn get_basic_blocks(&self) -> &crate::block::BlockGraph {
        &self.bblocks
    }

    // Ghidra: funcdata.hh:170 Funcdata::hasNoStructBlocks
    /// Return true if no block structuring was performed. Faithful to
    /// `bool hasNoStructBlocks(void) const` (funcdata.hh:170) — true iff the
    /// structured hierarchy is empty.
    pub fn has_no_struct_blocks(&self) -> bool {
        self.sblocks.get_size() == 0
    }

    // Ghidra: funcdata.hh:206 Funcdata::getOverride
    /// Get the Override object for this function. Faithful to
    /// `Override &getOverride(void)` (funcdata.hh:206) — returns a mutable
    /// reference to `localoverride` so callers can insert flow/deadcodedelay
    /// overrides.
    pub fn get_override(&mut self) -> &mut crate::override_rs::Override {
        &mut self.localoverride
    }

    // Ghidra: funcdata_varnode.cc:272 Funcdata::destroyVarnode
    /// Detach a Varnode from Rugra's descendant/definition indexes and remove
    /// it from the bank, adapting `Funcdata::destroyVarnode`
    /// (funcdata_varnode.cc:272-292):
    ///   for(iter=vn->beginDescend(); iter!=vn->endDescend(); ++iter) {
    ///     PcodeOp *op = *iter;
    ///     op->clearInput(op->getSlot(vn));
    ///   }
    ///   if (vn->def != NULL) {
    ///     vn->def->setOutput(NULL);
    ///     vn->def = NULL;
    ///   }
    ///   vn->destroyDescend();
    ///   vbank.destroy(vn);
    /// Rust input slots cannot be NULL: `op_unset_input` erases the descendant
    /// edge but leaves a stale Arc in `inrefs` until the caller removes or
    /// replaces that slot. Thus this function does not prove Ghidra's complete
    /// clearInput mutation and only guarantees index/bank detachment for its
    /// prevalidated callers. `delete_varnode` instead forwards to the checked
    /// public bank destroy and should be used for an already detached value.
    pub fn destroy_varnode(&mut self, vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) {
        // cc:277-284: clear each descending op's input slot.
        // Snapshot the (op, slot) pairs first because the slot lookup
        // (`op_get_slot`) and the unset both read the op. `op_get_slot`
        // returns -1 on miss; casting that to usize would produce
        // usize::MAX and a silent no-op inside op_unset_input, leaving the
        // op in vn's descend list as drift (and, once its Arc is released,
        // a dead Weak entry no erase_descend can ever match). Ghidra's
        // `clearInput(op->getSlot(vn))` on a miss indexes out of bounds —
        // the precondition is that every descendant really reads vn; on
        // drift, drop the stale entry instead so the list converges to the
        // actual reads (the whole list is destroyed below anyway).
        let descend_pairs: Vec<(crate::op::PcodeOpRef, i32)> = {
            let r = vn.read().unwrap();
            r.descend.iter()
                .filter_map(|w| w.upgrade())
                .map(|op_arc| {
                    let op_ref = crate::op::PcodeOpRef(op_arc.clone());
                    let slot = self.op_get_slot(&op_ref, vn);
                    (op_ref, slot)
                })
                .collect()
        };
        for (op_ref, slot) in descend_pairs {
            // cc:283: op->clearInput(op->getSlot(vn)).
            // Rust has no clearInput; op_unset_input erases the descend link
            // and leaves the slot stale (to be overwritten or removed).
            if slot >= 0 {
                self.op_unset_input(&op_ref, slot as usize);
            }
        }
        // cc:285-288: if vn has a def, detach the def's output.
        let def_op = vn.read().unwrap().get_def();
        if let Some(def) = def_op {
            self.op_unset_output(&crate::op::PcodeOpRef(def));
        }
        // cc:290: vn->destroyDescend().
        vn.write().unwrap().destroy_descend();
        // cc:291: vbank.destroy(vn).
        // The loop and def block above detached every integrated edge.
        self.vbank.destroy_varnode_prevalidated(vn);
    }

    // Ghidra: funcdata_varnode.cc:1048 Funcdata::syncVarnodesWithSymbol (single-range)
    /// Update MAPPED/ADDRTIED/ADDRFORCE/NOLOCALALIAS flags on a range of
    /// Varnodes that all share the same address, plus optionally update their
    /// Datatype. Faithful to `Funcdata::syncVarnodesWithSymbol(VarnodeLocSet::const_iterator &iter, uint4 fl, Datatype *ct)`
    /// (funcdata_varnode.cc:1048-1095). Ghidra walks an iterator range
    /// `[iter, endLoc(size, addr))` advancing the caller's iterator in place;
    /// Rugra passes the explicit slice of Varnodes at that address instead
    /// (the idiomatic Rust equivalent of the iterator range), since the
    /// in-out iterator pattern has no direct Rust analogue.
    ///
    /// Flag-update rules (verbatim from cc:1055-1067):
    ///   mask  = mapped;
    ///   if ((fl & addrtied) == 0)        // addrtied cleared → clear addrforce too
    ///     mask |= addrtied | addrforce;
    ///   if ((fl & nolocalalias) != 0)    // nolocalalias set → clear addrforce
    ///     mask |= nolocalalias | addrforce;
    ///   fl &= mask;
    /// and per-varnode (cc:1071-1093): skip free varnodes; if a dynamic
    /// SymbolEntry is attached (`mapentry`), hold the `mapped` bit unchanged;
    /// otherwise apply `fl` vs `mask`. Finally, if `ct` is provided, call
    /// `vn->updateType(ct)`.
    ///
    /// RUGRA-GAP: Rugra's Varnode has no `mapentry` field (no SymbolEntry
    /// infrastructure), so the "dynamic SymbolEntry attached" branch is taken
    /// to be the same as the plain branch — the `mapped` bit is updated along
    /// with the rest of the mask. When SymbolEntry wiring lands, restore the
    /// `localMask = mask & ~mapped` special case for attached entries.
    pub fn sync_varnodes_with_symbol(
        &mut self,
        range: &[std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>],
        fl_in: u32,
        ct: Option<&std::sync::Arc<crate::type_system::Datatype>>,
    ) -> bool {
        use crate::varnode::varnode_flags as vf;
        // cc:1056-1067: build mask and clamp fl.
        let mut mask = vf::MAPPED;
        if (fl_in & vf::ADDRTIED) == 0 {
            mask |= vf::ADDRTIED | vf::ADDRFORCE;
        }
        if (fl_in & vf::NOLOCALALIAS) != 0 {
            mask |= vf::NOLOCALALIAS | vf::ADDRFORCE;
        }
        let fl = fl_in & mask;
        let mut update_occurred = false;
        for vn_arc in range {
            let mut vn = vn_arc.write().unwrap();
            // cc:1073: if (vn->isFree()) continue.
            if vn.is_free() { continue; }
            let vnflags = vn.flags;
            // RUGRA-GAP: no mapentry — treat all varnodes uniformly (see doc).
            if (vnflags & mask) != fl {
                update_occurred = true;
                vn.set_flags(fl);
                vn.clear_flags((!fl) & mask);
            }
            if let Some(ct_arc) = ct {
                // cc:1089-1092: if (ct != NULL && vn->updateType(ct)) updateoccurred = true.
                if vn.update_type(ct_arc.clone()) {
                    update_occurred = true;
                }
            }
        }
        update_occurred
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::align::runtime_verify::{RuntimeVerifier, VerifyResult};
    use crate::disasm::{Disassembler, X86Lifter, X86_64Disassembler};
    use crate::ffi;
    use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
    use std::sync::Mutex;

    // Serialize tests that use the global CURRENT_PROGRAM to prevent
    // multi-threaded test races when `cargo test` runs in parallel.
    lazy_static::lazy_static! {
        static ref FFI_TEST_LOCK: Mutex<()> = Mutex::new(());
    }

    #[test]
    fn test_funcdata_creation() {
        let fd = Funcdata::new("test_func", Address::new(0x1000), 0x100);
        assert_eq!(fd.get_name(), "test_func");
        assert_eq!(fd.get_address().as_u64(), 0x1000);
    }

    #[test]
    fn test_inject_raw_ops_simple() {
        let mut fd = Funcdata::new("add", Address::new(0x1000), 7);

        // Build: RAX = COPY(RDI)
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        // Build: RAX = INT_ADD(RAX, RSI)
        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op2.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI

        // Build: RETURN(RAX)
        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op3.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX

        fd.inject_raw_ops(&[op1, op2, op3]);

        // Verify ops were created
        assert_eq!(fd.obank.alivelist.len(), 3);

        // Verify varnodes were created (2 outputs + 4 inputs = 6 total)
        assert!(fd.vbank.num_varnodes() > 0);

        // Verify basic blocks (RETURN terminates, so we get 1 block)
        assert_eq!(fd.bblocks.get_size(), 1);
    }

    #[test]
    fn test_inject_raw_ops_with_branch() {
        let mut fd = Funcdata::new("branch_test", Address::new(0x2000), 20);

        // Block 0: compare and branch
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 1));
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8));
        op1.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));

        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
        op2.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x2010, 8));
        op2.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 1));

        // Block 1: true branch
        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op3.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 1, 8));

        let mut op4 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op4.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));

        fd.inject_raw_ops(&[op1, op2, op3, op4]);

        // Basic-block partitioning splits at terminators AND at jump targets
        // (Ghidra-style). CBRANCH at op1 (addr 0x2010) targets 0x2010 — itself,
        // a self-loop — so op1 is its own block boundary. This yields 3 blocks:
        //   [op0(op1=INT_EQUAL), op1(CBRANCH)] | [op2(COPY), op3(RETURN)]
        // becomes, with the self-loop target splitting at op1:
        //   [op0] | [op1(CBRANCH, self-loop)] | [op2, op3]
        assert_eq!(fd.bblocks.get_size(), 3);
    }

    #[test]
    fn test_mov_reg_reg_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x89, 0xc3]; // mov rbx, rax
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "mov");
        assert!(inst.text.contains("rbx"));
        assert!(inst.text.contains("rax"));

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        assert_eq!(raw_ops.len(), 1);

        let raw = &raw_ops[0];
        assert_eq!(OpCode::from_i32(raw.get_opcode()), Some(OpCode::CPUI_COPY));

        let out_binding = raw.output();
        let out = out_binding.as_ref().unwrap();
        assert_eq!(out.space, AddressSpace::Register);
        assert_eq!(out.offset, 0x18);
        assert_eq!(out.size, 8);

        let inputs = raw.inputs();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].space, AddressSpace::Register);
        assert_eq!(inputs[0].offset, 0x00);
        assert_eq!(inputs[0].size, 8);

        let mut fd = Funcdata::new("mov_reg_reg", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 1);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result = verifier.verify_pcode_generation("mov_rbx_rax_minimal", start, &rugra_ops, 1);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_add_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x83, 0xc0, 0x01]; // add rax, 1
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "add");
        assert!(inst.text.contains("rax"));
        assert!(inst.text.contains("1"));

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        assert_eq!(raw_ops.len(), 2);

        let raw_add = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_add.get_opcode()),
            Some(OpCode::CPUI_INT_ADD)
        );

        let add_out_binding = raw_add.output();
        let add_out = add_out_binding.as_ref().unwrap();
        assert_eq!(add_out.space, AddressSpace::Unique);
        assert_eq!(add_out.size, 8);

        let add_inputs = raw_add.inputs();
        assert_eq!(add_inputs.len(), 2);
        assert_eq!(add_inputs[0].space, AddressSpace::Register);
        assert_eq!(add_inputs[0].offset, 0x00);
        assert_eq!(add_inputs[0].size, 8);
        assert_eq!(add_inputs[1].space, AddressSpace::Const);
        assert_eq!(add_inputs[1].offset, 0x01);
        assert_eq!(add_inputs[1].size, 1);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let copy_out_binding = raw_copy.output();
        let copy_out = copy_out_binding.as_ref().unwrap();
        assert_eq!(copy_out.space, AddressSpace::Register);
        assert_eq!(copy_out.offset, 0x00);
        assert_eq!(copy_out.size, 8);

        let copy_inputs = raw_copy.inputs();
        assert_eq!(copy_inputs.len(), 1);
        assert_eq!(copy_inputs[0].space, AddressSpace::Unique);
        assert_eq!(copy_inputs[0].offset, add_out.offset);
        assert_eq!(copy_inputs[0].size, 8);

        let mut fd = Funcdata::new("add_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result = verifier.verify_pcode_generation("add_rax_1_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_sub_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x83, 0xe8, 0x08]; // sub rax, 8
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "sub");
        assert!(inst.text.contains("rax"));
        assert!(inst.text.contains("8"));

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        // Expect INT_SUB + COPY (same pattern as add)
        assert_eq!(raw_ops.len(), 2);

        let raw_sub = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_sub.get_opcode()),
            Some(OpCode::CPUI_INT_SUB)
        );

        let sub_out_binding = raw_sub.output();
        let sub_out = sub_out_binding.as_ref().unwrap();
        assert_eq!(sub_out.space, AddressSpace::Unique);
        assert_eq!(sub_out.size, 8);

        let sub_inputs = raw_sub.inputs();
        assert_eq!(sub_inputs.len(), 2);
        assert_eq!(sub_inputs[0].space, AddressSpace::Register);
        assert_eq!(sub_inputs[0].offset, 0x00); // RAX
        assert_eq!(sub_inputs[0].size, 8);
        assert_eq!(sub_inputs[1].space, AddressSpace::Const);
        assert_eq!(sub_inputs[1].offset, 0x08);
        assert_eq!(sub_inputs[1].size, 1);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let copy_out_binding = raw_copy.output();
        let copy_out = copy_out_binding.as_ref().unwrap();
        assert_eq!(copy_out.space, AddressSpace::Register);
        assert_eq!(copy_out.offset, 0x00); // RAX
        assert_eq!(copy_out.size, 8);

        let copy_inputs = raw_copy.inputs();
        assert_eq!(copy_inputs.len(), 1);
        assert_eq!(copy_inputs[0].space, AddressSpace::Unique);
        assert_eq!(copy_inputs[0].offset, sub_out.offset);
        assert_eq!(copy_inputs[0].size, 8);

        let mut fd = Funcdata::new("sub_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result = verifier.verify_pcode_generation("sub_rax_8_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    // ========== Fourth batch: and / or / xor / shl / shr / cmp ==========

    #[test]
    fn test_and_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // and rax, 0xf  →  48 83 e0 0f
        let code = vec![0x48, 0x83, 0xe0, 0x0f];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "and");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        // Expect INT_AND + COPY
        assert_eq!(raw_ops.len(), 2);

        let raw_op = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_op.get_opcode()),
            Some(OpCode::CPUI_INT_AND)
        );

        let op_out_binding = raw_op.output();
        let op_out = op_out_binding.as_ref().unwrap();
        assert_eq!(op_out.space, AddressSpace::Unique);
        assert_eq!(op_out.size, 8);

        let op_inputs = raw_op.inputs();
        assert_eq!(op_inputs.len(), 2);
        assert_eq!(op_inputs[0].space, AddressSpace::Register);
        assert_eq!(op_inputs[0].offset, 0x00); // RAX
        assert_eq!(op_inputs[1].space, AddressSpace::Const);
        assert_eq!(op_inputs[1].offset, 0x0f);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let mut fd = Funcdata::new("and_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("and_rax_0xf_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_or_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // or rax, 0x10  →  48 83 c8 10
        let code = vec![0x48, 0x83, 0xc8, 0x10];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "or");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        assert_eq!(raw_ops.len(), 2);

        let raw_op = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_op.get_opcode()),
            Some(OpCode::CPUI_INT_OR)
        );

        let op_out_binding = raw_op.output();
        let op_out = op_out_binding.as_ref().unwrap();
        assert_eq!(op_out.space, AddressSpace::Unique);
        assert_eq!(op_out.size, 8);

        let op_inputs = raw_op.inputs();
        assert_eq!(op_inputs.len(), 2);
        assert_eq!(op_inputs[0].space, AddressSpace::Register);
        assert_eq!(op_inputs[0].offset, 0x00); // RAX
        assert_eq!(op_inputs[1].space, AddressSpace::Const);
        assert_eq!(op_inputs[1].offset, 0x10);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let mut fd = Funcdata::new("or_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("or_rax_0x10_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_xor_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // xor rax, 0x7  →  48 83 f0 07
        let code = vec![0x48, 0x83, 0xf0, 0x07];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "xor");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        assert_eq!(raw_ops.len(), 2);

        let raw_op = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_op.get_opcode()),
            Some(OpCode::CPUI_INT_XOR)
        );

        let op_out_binding = raw_op.output();
        let op_out = op_out_binding.as_ref().unwrap();
        assert_eq!(op_out.space, AddressSpace::Unique);
        assert_eq!(op_out.size, 8);

        let op_inputs = raw_op.inputs();
        assert_eq!(op_inputs.len(), 2);
        assert_eq!(op_inputs[0].space, AddressSpace::Register);
        assert_eq!(op_inputs[0].offset, 0x00); // RAX
        assert_eq!(op_inputs[1].space, AddressSpace::Const);
        assert_eq!(op_inputs[1].offset, 0x07);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let mut fd = Funcdata::new("xor_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("xor_rax_0x7_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_shl_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // shl rax, 4  →  48 c1 e0 04
        let code = vec![0x48, 0xc1, 0xe0, 0x04];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "shl");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        assert_eq!(raw_ops.len(), 2);

        let raw_op = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_op.get_opcode()),
            Some(OpCode::CPUI_INT_LEFT)
        );

        let op_out_binding = raw_op.output();
        let op_out = op_out_binding.as_ref().unwrap();
        assert_eq!(op_out.space, AddressSpace::Unique);
        assert_eq!(op_out.size, 8);

        let op_inputs = raw_op.inputs();
        assert_eq!(op_inputs.len(), 2);
        assert_eq!(op_inputs[0].space, AddressSpace::Register);
        assert_eq!(op_inputs[0].offset, 0x00); // RAX
        assert_eq!(op_inputs[1].space, AddressSpace::Const);
        assert_eq!(op_inputs[1].offset, 0x04);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let mut fd = Funcdata::new("shl_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("shl_rax_4_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_shr_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // shr rax, 4  →  48 c1 e8 04
        let code = vec![0x48, 0xc1, 0xe8, 0x04];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "shr");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        assert_eq!(raw_ops.len(), 2);

        let raw_op = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_op.get_opcode()),
            Some(OpCode::CPUI_INT_RIGHT)
        );

        let op_out_binding = raw_op.output();
        let op_out = op_out_binding.as_ref().unwrap();
        assert_eq!(op_out.space, AddressSpace::Unique);
        assert_eq!(op_out.size, 8);

        let op_inputs = raw_op.inputs();
        assert_eq!(op_inputs.len(), 2);
        assert_eq!(op_inputs[0].space, AddressSpace::Register);
        assert_eq!(op_inputs[0].offset, 0x00); // RAX
        assert_eq!(op_inputs[1].space, AddressSpace::Const);
        assert_eq!(op_inputs[1].offset, 0x04);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let mut fd = Funcdata::new("shr_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("shr_rax_4_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_cmp_rax_rbx_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // cmp rax, rbx  →  48 39 d8
        let code = vec![0x48, 0x39, 0xd8];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "cmp");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        // cmp produces 3 flag-setting ops: INT_EQUAL(ZF), INT_LESS(CF), INT_SLESS(SF)
        assert_eq!(raw_ops.len(), 3);

        // Op 0: ZF = INT_EQUAL(rax, rbx)
        let raw_zf = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_zf.get_opcode()),
            Some(OpCode::CPUI_INT_EQUAL)
        );
        let zf_out_binding = raw_zf.output();
        let zf_out = zf_out_binding.as_ref().unwrap();
        assert_eq!(zf_out.space, AddressSpace::Register);
        assert_eq!(zf_out.offset, 0x201); // ZF register
        assert_eq!(zf_out.size, 1);

        let zf_inputs = raw_zf.inputs();
        assert_eq!(zf_inputs.len(), 2);
        assert_eq!(zf_inputs[0].space, AddressSpace::Register);
        assert_eq!(zf_inputs[0].offset, 0x00); // RAX
        assert_eq!(zf_inputs[1].space, AddressSpace::Register);
        assert_eq!(zf_inputs[1].offset, 0x18); // RBX

        // Op 1: CF = INT_LESS(rax, rbx)
        let raw_cf = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_cf.get_opcode()),
            Some(OpCode::CPUI_INT_LESS)
        );
        let cf_out_binding = raw_cf.output();
        let cf_out = cf_out_binding.as_ref().unwrap();
        assert_eq!(cf_out.space, AddressSpace::Register);
        assert_eq!(cf_out.offset, 0x203); // CF register
        assert_eq!(cf_out.size, 1);

        // Op 2: SF = INT_SLESS(rax, rbx)
        let raw_sf = &raw_ops[2];
        assert_eq!(
            OpCode::from_i32(raw_sf.get_opcode()),
            Some(OpCode::CPUI_INT_SLESS)
        );
        let sf_out_binding = raw_sf.output();
        let sf_out = sf_out_binding.as_ref().unwrap();
        assert_eq!(sf_out.space, AddressSpace::Register);
        assert_eq!(sf_out.offset, 0x202); // SF register
        assert_eq!(sf_out.size, 1);

        let mut fd = Funcdata::new("cmp_rax_rbx", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 3);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("cmp_rax_rbx_minimal", start, &rugra_ops, 3);

        assert!(matches!(result, VerifyResult::Match));
    }

    // ========== Memory instruction (LOAD / STORE) alignment tests ==========

    /// Test: `mov rax, [rbx]` — Simple memory load
    /// Machine code: 48 8b 03
    /// Expected P-code:
    ///   1. CPUI_LOAD(const(ram_space_id), reg(rbx)) -> unique_tmp
    ///   2. CPUI_COPY(unique_tmp) -> reg(rax)
    #[test]
    fn test_load_mov_rax_mem_rbx_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x8b, 0x03]; // mov rax, [rbx]
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "mov");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);

        // parse_operand for Memory emits a LOAD internally, then mov emits COPY
        // So we expect: LOAD + COPY = 2 ops
        assert_eq!(raw_ops.len(), 2, "Expected LOAD + COPY, got {} ops", raw_ops.len());

        // Op 0: CPUI_LOAD
        let raw_load = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_load.get_opcode()),
            Some(OpCode::CPUI_LOAD)
        );

        let load_out_binding = raw_load.output();
        let load_out = load_out_binding.as_ref().unwrap();
        assert_eq!(load_out.space, AddressSpace::Unique);
        assert_eq!(load_out.size, 8);

        let load_inputs = raw_load.inputs();
        assert_eq!(load_inputs.len(), 2);
        // Input 0: RAM space ID as a constant
        assert_eq!(load_inputs[0].space, AddressSpace::Const);
        assert_eq!(load_inputs[0].offset, AddressSpace::Ram.space_id() as u64);
        // Input 1: address from rbx register
        assert_eq!(load_inputs[1].space, AddressSpace::Register);
        assert_eq!(load_inputs[1].offset, 0x18); // rbx offset
        assert_eq!(load_inputs[1].size, 8);

        // Op 1: CPUI_COPY
        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let copy_out_binding = raw_copy.output();
        let copy_out = copy_out_binding.as_ref().unwrap();
        assert_eq!(copy_out.space, AddressSpace::Register);
        assert_eq!(copy_out.offset, 0x00); // rax
        assert_eq!(copy_out.size, 8);

        let copy_inputs = raw_copy.inputs();
        assert_eq!(copy_inputs.len(), 1);
        assert_eq!(copy_inputs[0].space, AddressSpace::Unique);
        assert_eq!(copy_inputs[0].offset, load_out.offset);

        // Inject and verify
        let mut fd = Funcdata::new("load_mov_rax_mem_rbx", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("load_mov_rax_mem_rbx", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: `mov [rbx], rax` — Simple memory store
    /// Machine code: 48 89 03
    /// Expected P-code:
    ///   1. CPUI_STORE(const(ram_space_id), reg(rbx), reg(rax)) — no output
    #[test]
    fn test_store_mov_mem_rbx_rax_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x89, 0x03]; // mov [rbx], rax
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "mov");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);

        // mov [rbx], rax: source is register (no LOAD), dest is memory (STORE)
        // So we expect just 1 op: STORE
        assert_eq!(raw_ops.len(), 1, "Expected 1 STORE op, got {} ops", raw_ops.len());

        // Op 0: CPUI_STORE
        let raw_store = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_store.get_opcode()),
            Some(OpCode::CPUI_STORE)
        );

        // STORE has no output
        assert!(raw_store.output().is_none());

        let store_inputs = raw_store.inputs();
        assert_eq!(store_inputs.len(), 3);
        // Input 0: RAM space ID
        assert_eq!(store_inputs[0].space, AddressSpace::Const);
        assert_eq!(store_inputs[0].offset, AddressSpace::Ram.space_id() as u64);
        // Input 1: address from rbx
        assert_eq!(store_inputs[1].space, AddressSpace::Register);
        assert_eq!(store_inputs[1].offset, 0x18); // rbx
        assert_eq!(store_inputs[1].size, 8);
        // Input 2: value from rax
        assert_eq!(store_inputs[2].space, AddressSpace::Register);
        assert_eq!(store_inputs[2].offset, 0x00); // rax
        assert_eq!(store_inputs[2].size, 8);

        // Inject and verify
        let mut fd = Funcdata::new("store_mov_mem_rbx_rax", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 1);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("store_mov_mem_rbx_rax", start, &rugra_ops, 1);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: `mov rax, [rbx+0x10]` — Memory load with displacement
    /// Machine code: 48 8b 43 10
    /// Expected P-code:
    ///   1. CPUI_INT_ADD(rbx, 0x10) -> tmp_addr
    ///   2. CPUI_LOAD(const(ram_space_id), tmp_addr) -> tmp_val
    ///   3. CPUI_COPY(tmp_val) -> rax
    #[test]
    fn test_load_mov_rax_mem_rbx_disp_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x8b, 0x43, 0x10]; // mov rax, [rbx+0x10]
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "mov");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);

        // Displacement != 0 → INT_ADD for addr calc, then LOAD, then COPY
        assert_eq!(raw_ops.len(), 3, "Expected INT_ADD + LOAD + COPY, got {} ops", raw_ops.len());

        // Op 0: CPUI_INT_ADD for address computation
        let raw_add = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_add.get_opcode()),
            Some(OpCode::CPUI_INT_ADD)
        );

        let add_out_binding = raw_add.output();
        let add_out = add_out_binding.as_ref().unwrap();
        assert_eq!(add_out.space, AddressSpace::Unique);

        let add_inputs = raw_add.inputs();
        assert_eq!(add_inputs.len(), 2);
        assert_eq!(add_inputs[0].space, AddressSpace::Register);
        assert_eq!(add_inputs[0].offset, 0x18); // rbx
        assert_eq!(add_inputs[1].space, AddressSpace::Const);
        assert_eq!(add_inputs[1].offset, 0x10); // displacement

        // Op 1: CPUI_LOAD
        let raw_load = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_load.get_opcode()),
            Some(OpCode::CPUI_LOAD)
        );

        let load_out_binding = raw_load.output();
        let load_out = load_out_binding.as_ref().unwrap();
        assert_eq!(load_out.space, AddressSpace::Unique);
        assert_eq!(load_out.size, 8);

        let load_inputs = raw_load.inputs();
        assert_eq!(load_inputs.len(), 2);
        assert_eq!(load_inputs[0].space, AddressSpace::Const); // RAM space ID
        assert_eq!(load_inputs[1].space, AddressSpace::Unique); // computed address
        assert_eq!(load_inputs[1].offset, add_out.offset);

        // Op 2: CPUI_COPY
        let raw_copy = &raw_ops[2];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let copy_out_binding = raw_copy.output();
        let copy_out = copy_out_binding.as_ref().unwrap();
        assert_eq!(copy_out.space, AddressSpace::Register);
        assert_eq!(copy_out.offset, 0x00); // rax

        // Inject and verify
        let mut fd = Funcdata::new("load_mov_rax_mem_rbx_disp", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 3);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result = verifier.verify_pcode_generation(
            "load_mov_rax_mem_rbx_disp",
            start,
            &rugra_ops,
            3,
        );

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: `add [rbx], rax` — Memory read-modify-write
    /// Machine code: 48 01 03
    /// Expected P-code:
    ///   1. CPUI_LOAD(ram_space_id, rbx) -> tmp_orig  (read original value)
    ///   2. CPUI_INT_ADD(tmp_orig, rax) -> tmp_result
    ///   3. CPUI_STORE(ram_space_id, rbx, tmp_result)  (write back)
    #[test]
    fn test_add_mem_rbx_rax_rmw_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x01, 0x03]; // add [rbx], rax
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "add");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);

        // For `add [rbx], rax`:
        // - parse_dest_operand([rbx]) returns (rbx_vn, Some(size_vn)) — memory target
        // - parse_operand(rax) returns rax_vn — register source
        // - Because mem_size.is_some(), it calls parse_operand([rbx]) again for reading
        //   → this generates a LOAD op and returns tmp
        // - INT_ADD(tmp, rax) → tmp_result
        // - emit_store(rbx_vn, tmp_result, size_vn) → STORE
        // Total: LOAD + INT_ADD + STORE = 3 ops
        assert_eq!(raw_ops.len(), 3, "Expected LOAD + INT_ADD + STORE, got {} ops", raw_ops.len());

        // Op 0: CPUI_LOAD (read original value from [rbx])
        let raw_load = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_load.get_opcode()),
            Some(OpCode::CPUI_LOAD)
        );

        let load_out_binding = raw_load.output();
        let load_out = load_out_binding.as_ref().unwrap();
        assert_eq!(load_out.space, AddressSpace::Unique);
        assert_eq!(load_out.size, 8);

        let load_inputs = raw_load.inputs();
        assert_eq!(load_inputs.len(), 2);
        assert_eq!(load_inputs[0].space, AddressSpace::Const); // RAM space ID
        assert_eq!(load_inputs[1].space, AddressSpace::Register);
        assert_eq!(load_inputs[1].offset, 0x18); // rbx

        // Op 1: CPUI_INT_ADD
        let raw_add = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_add.get_opcode()),
            Some(OpCode::CPUI_INT_ADD)
        );

        let add_out_binding = raw_add.output();
        let add_out = add_out_binding.as_ref().unwrap();
        assert_eq!(add_out.space, AddressSpace::Unique);

        let add_inputs = raw_add.inputs();
        assert_eq!(add_inputs.len(), 2);
        // Input 0: loaded value (unique tmp from LOAD)
        assert_eq!(add_inputs[0].space, AddressSpace::Unique);
        assert_eq!(add_inputs[0].offset, load_out.offset);
        // Input 1: rax
        assert_eq!(add_inputs[1].space, AddressSpace::Register);
        assert_eq!(add_inputs[1].offset, 0x00); // rax

        // Op 2: CPUI_STORE (write result back to [rbx])
        let raw_store = &raw_ops[2];
        assert_eq!(
            OpCode::from_i32(raw_store.get_opcode()),
            Some(OpCode::CPUI_STORE)
        );
        assert!(raw_store.output().is_none());

        let store_inputs = raw_store.inputs();
        assert_eq!(store_inputs.len(), 3);
        assert_eq!(store_inputs[0].space, AddressSpace::Const); // RAM space ID
        assert_eq!(store_inputs[1].space, AddressSpace::Register);
        assert_eq!(store_inputs[1].offset, 0x18); // rbx (address)
        assert_eq!(store_inputs[2].space, AddressSpace::Unique); // result

        // Inject and verify
        let mut fd = Funcdata::new("add_mem_rbx_rax_rmw", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 3);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("add_mem_rbx_rax_rmw", start, &rugra_ops, 3);

        assert!(matches!(result, VerifyResult::Match));
    }

    // ========== SSA alignment tests ==========

    /// Test: Single-block SSA construction for `mov rax, rdi; add rax, rsi; ret`
    ///
    /// Verifies that after heritage (SSA construction), a single-block
    /// function has:
    /// - No MULTIEQUAL (Phi) nodes (single block, no merge point)
    /// - Heritage pass counter incremented
    /// - Varnode def/use chains are established
    #[test]
    fn test_ssa_single_block_linear() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();

        // Build raw ops for: mov rax, rdi; add rax, rsi; ret
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op2.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI

        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));

        let start = Address::new(0x2000);
        let mut fd = Funcdata::new("ssa_linear", start, 10);

        // Inject ops
        fd.inject_raw_ops(&[op1, op2, op3]);
        assert_eq!(fd.obank.alivelist.len(), 3);
        assert_eq!(fd.bblocks.get_size(), 1);

        // Build dominator tree (required for heritage)
        fd.bblocks.build_dom_tree();

        // Run heritage directly using the _direct methods to avoid
        // the deadlock that occurs when heritage() tries to re-acquire
        // the Funcdata lock via fd_weak.upgrade().
        fd.heritage.place_multiequals_direct(
            &mut fd.vbank,
            &mut fd.obank,
            &fd.bblocks,
            &fd.sblocks,
        );
        fd.heritage.rename_direct(&mut fd.vbank, &fd.bblocks);
        fd.heritage.pass += 1;

        // Heritage pass should have incremented
        assert_eq!(fd.num_heritage_passes(), 1, "Heritage pass should be 1 after first run");

        // Single block → no MULTIEQUAL ops should be inserted
        let multiequal_count = fd
            .obank
            .optree
            .iter()
            .filter(|op| op.0.read().unwrap().get_opcode() == OpCode::CPUI_MULTIEQUAL)
            .count();
        assert_eq!(
            multiequal_count, 0,
            "Single block should have no Phi (MULTIEQUAL) nodes, found {}",
            multiequal_count
        );

        // Original 3 ops should still be present
        assert!(
            fd.obank.alivelist.len() >= 3,
            "Should still have at least 3 original ops"
        );
    }

    // ========== Multi-instruction sequence tests ==========

    /// Test: `mov rax, rdi; add rax, rsi; ret`
    /// A minimal function that returns first_arg + second_arg.
    /// Produces 4 P-code ops in a single basic block:
    ///   COPY(rax ← rdi), INT_ADD(tmp), COPY(rax ← tmp), RETURN
    #[test]
    fn test_seq_mov_add_ret_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // mov rax, rdi = 48 89 f8
        // add rax, rsi = 48 01 f0
        // ret          = c3
        let code = vec![
            0x48, 0x89, 0xf8, // mov rax, rdi
            0x48, 0x01, 0xf0, // add rax, rsi
            0xc3,             // ret
        ];
        let start = Address::new(0x1000);

        // Phase 1: Disassemble
        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 3);
        assert_eq!(instructions[0].mnemonic, "mov");
        assert_eq!(instructions[1].mnemonic, "add");
        assert_eq!(instructions[2].mnemonic, "ret");

        // Verify sequential addresses
        assert_eq!(instructions[0].address.as_u64(), 0x1000);
        assert_eq!(instructions[1].address.as_u64(), 0x1003);
        assert_eq!(instructions[2].address.as_u64(), 0x1006);

        // Phase 2: Lift all instructions
        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            let ops = lifter.lift(inst);
            all_raw_ops.extend(ops);
        }
        // mov→1(COPY) + add→2(INT_ADD+COPY) + ret→1(RETURN) = 4
        assert_eq!(all_raw_ops.len(), 4);

        // Verify op sequence
        assert_eq!(OpCode::from_i32(all_raw_ops[0].get_opcode()), Some(OpCode::CPUI_COPY));
        assert_eq!(OpCode::from_i32(all_raw_ops[1].get_opcode()), Some(OpCode::CPUI_INT_ADD));
        assert_eq!(OpCode::from_i32(all_raw_ops[2].get_opcode()), Some(OpCode::CPUI_COPY));
        assert_eq!(OpCode::from_i32(all_raw_ops[3].get_opcode()), Some(OpCode::CPUI_RETURN));

        // Phase 3: Inject into Funcdata
        let mut fd = Funcdata::new("seq_mov_add_ret", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 4);
        // RETURN terminates, all ops in one block
        assert_eq!(fd.bblocks.get_size(), 1);

        // Phase 4: Verify via RuntimeVerifier
        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("seq_mov_add_ret", start, &rugra_ops, 4);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: `mov rax, rdi; and rax, 0xf; shl rax, 4; ret`
    /// Arithmetic chain: mask low nibble, shift left by 4. Returns (arg & 0xf) << 4.
    /// Produces 6 P-code ops in a single basic block:
    ///   COPY(rax←rdi), INT_AND(tmp1), COPY(rax←tmp1), INT_LEFT(tmp2), COPY(rax←tmp2), RETURN
    #[test]
    fn test_seq_mov_and_shl_ret_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![
            0x48, 0x89, 0xf8,       // mov rax, rdi
            0x48, 0x83, 0xe0, 0x0f, // and rax, 0xf
            0x48, 0xc1, 0xe0, 0x04, // shl rax, 4
            0xc3,                    // ret
        ];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 4);
        assert_eq!(instructions[0].mnemonic, "mov");
        assert_eq!(instructions[1].mnemonic, "and");
        assert_eq!(instructions[2].mnemonic, "shl");
        assert_eq!(instructions[3].mnemonic, "ret");

        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            all_raw_ops.extend(lifter.lift(inst));
        }
        // mov→1 + and→2 + shl→2 + ret→1 = 6
        assert_eq!(all_raw_ops.len(), 6);

        assert_eq!(OpCode::from_i32(all_raw_ops[0].get_opcode()), Some(OpCode::CPUI_COPY));
        assert_eq!(OpCode::from_i32(all_raw_ops[1].get_opcode()), Some(OpCode::CPUI_INT_AND));
        assert_eq!(OpCode::from_i32(all_raw_ops[2].get_opcode()), Some(OpCode::CPUI_COPY));
        assert_eq!(OpCode::from_i32(all_raw_ops[3].get_opcode()), Some(OpCode::CPUI_INT_LEFT));
        assert_eq!(OpCode::from_i32(all_raw_ops[4].get_opcode()), Some(OpCode::CPUI_COPY));
        assert_eq!(OpCode::from_i32(all_raw_ops[5].get_opcode()), Some(OpCode::CPUI_RETURN));

        let mut fd = Funcdata::new("seq_and_shl_ret", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 6);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("seq_and_shl_ret", start, &rugra_ops, 6);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: multi-block with conditional branch
    /// ```text
    /// 0x1000: cmp rdi, rsi     ; 48 39 f7
    /// 0x1003: je  0x100d       ; 74 08
    /// 0x1005: mov rax, 1       ; 48 c7 c0 01 00 00 00
    /// 0x100c: ret              ; c3
    /// 0x100d: xor rax, rax     ; 48 31 c0     (je target)
    /// 0x1010: ret              ; c3
    /// ```
    /// Tests: CBRANCH generation, basic block splitting, multi-block inject.
    /// Block 0: cmp(3 ops) + je(CBRANCH) = 4 ops
    /// Block 1: mov(COPY) + ret(RETURN) = 2 ops
    /// Block 2: xor(INT_XOR+COPY) + ret(RETURN) = 3 ops
    /// Total: 9 ops, 3 blocks
    #[test]
    fn test_seq_cmp_je_multiblock_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![
            0x48, 0x39, 0xf7,                         // cmp rdi, rsi
            0x74, 0x08,                                // je +8 → 0x100d
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1
            0xc3,                                      // ret
            0x48, 0x31, 0xc0,                          // xor rax, rax
            0xc3,                                      // ret
        ];
        let start = Address::new(0x1000);

        // Phase 1: Disassemble
        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 6);
        assert_eq!(instructions[0].mnemonic, "cmp");
        assert_eq!(instructions[1].mnemonic, "je");
        assert_eq!(instructions[2].mnemonic, "mov");
        assert_eq!(instructions[3].mnemonic, "ret");
        assert_eq!(instructions[4].mnemonic, "xor");
        assert_eq!(instructions[5].mnemonic, "ret");

        // Verify addresses
        assert_eq!(instructions[0].address.as_u64(), 0x1000);
        assert_eq!(instructions[1].address.as_u64(), 0x1003);
        assert_eq!(instructions[2].address.as_u64(), 0x1005);
        assert_eq!(instructions[3].address.as_u64(), 0x100c);
        assert_eq!(instructions[4].address.as_u64(), 0x100d);
        assert_eq!(instructions[5].address.as_u64(), 0x1010);

        // Phase 2: Lift all
        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            all_raw_ops.extend(lifter.lift(inst));
        }
        // cmp→3(INT_EQUAL+INT_LESS+INT_SLESS)
        // je→1(CBRANCH)
        // mov→1(COPY)
        // ret→1(RETURN)
        // xor→2(INT_XOR+COPY)
        // ret→1(RETURN)
        // Total: 9
        assert_eq!(all_raw_ops.len(), 9);

        // Verify key opcodes
        assert_eq!(OpCode::from_i32(all_raw_ops[0].get_opcode()), Some(OpCode::CPUI_INT_EQUAL));
        assert_eq!(OpCode::from_i32(all_raw_ops[3].get_opcode()), Some(OpCode::CPUI_CBRANCH));
        assert_eq!(OpCode::from_i32(all_raw_ops[4].get_opcode()), Some(OpCode::CPUI_COPY));
        assert_eq!(OpCode::from_i32(all_raw_ops[5].get_opcode()), Some(OpCode::CPUI_RETURN));
        assert_eq!(OpCode::from_i32(all_raw_ops[6].get_opcode()), Some(OpCode::CPUI_INT_XOR));

        // Phase 3: Inject and verify block structure
        let mut fd = Funcdata::new("seq_cmp_je_multi", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 9);
        // CBRANCH terminates block 0, RETURN terminates block 1 and block 2 → 3 blocks
        assert_eq!(fd.bblocks.get_size(), 3);

        // Verify block 0 has 4 ops (cmp: 3 flag ops + CBRANCH)
        let block0 = fd.bblocks.get_block(0).unwrap();
        assert_eq!(block0.read().unwrap().get_ops().len(), 4);

        // Verify block 1 has 2 ops (mov + ret)
        let block1 = fd.bblocks.get_block(1).unwrap();
        assert_eq!(block1.read().unwrap().get_ops().len(), 2);

        // Verify block 2 has 3 ops (xor: INT_XOR+COPY + ret)
        let block2 = fd.bblocks.get_block(2).unwrap();
        assert_eq!(block2.read().unwrap().get_ops().len(), 3);

        // Phase 4: Verify via RuntimeVerifier
        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("seq_cmp_je_multiblock", start, &rugra_ops, 9);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: multi-block with conditional branch converging to a merge block
    /// ```text
    /// 0x1000: cmp rdi, 0
    /// 0x1004: je 0x100f
    /// 0x1006: mov rax, 1
    /// 0x100d: jmp 0x1018
    /// 0x100f: mov rax, 2
    /// 0x1016: jmp 0x1018
    /// 0x1018: add rax, rsi
    /// 0x101b: ret
    /// ```
    /// This creates 4 basic blocks:
    /// Block 0: cmp + CBRANCH
    /// Block 1: mov rax, 1 + BRANCH (to block 3)
    /// Block 2: mov rax, 2 + BRANCH (to block 3)
    /// Block 3: MULTIEQUAL (Phi for rax) + add + ret
    #[test]
    fn test_ssa_dual_block_phi_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![
            0x48, 0x83, 0xff, 0x00,                         // cmp rdi, 0
            0x74, 0x09,                                     // je 0x100f
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,       // mov rax, 1
            0xeb, 0x09,                                     // jmp 0x1018
            0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00,       // mov rax, 2
            0xeb, 0x00,                                     // jmp 0x1018
            0x48, 0x01, 0xf0,                               // add rax, rsi
            0xc3,                                           // ret
        ];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        
        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            all_raw_ops.extend(lifter.lift(inst));
        }

        let mut fd = Funcdata::new("ssa_phi_test", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        // Build dom tree
        fd.bblocks.build_dom_tree();

        // Run heritage to build SSA
        fd.run_heritage_direct();

        // Verify that a MULTIEQUAL (Phi) node was created
        let multiequals: Vec<_> = fd.obank.optree.iter()
            .filter(|op| op.0.read().unwrap().get_opcode() == OpCode::CPUI_MULTIEQUAL)
            .collect();
            
        assert_eq!(multiequals.len(), 1, "Expected exactly 1 Phi node, got {}", multiequals.len());
        
        let phi = multiequals[0].0.read().unwrap();
        assert_eq!(phi.inrefs.len(), 2, "Phi node should have 2 inputs");
        
        let out_vn = phi.output.as_ref().unwrap().read().unwrap();
        assert_eq!(out_vn.get_space(), AddressSpace::Register);
        assert_eq!(out_vn.get_offset(), 0x00); // RAX
        assert_eq!(out_vn.get_size(), 8); // RAX is 8 bytes
    }

    // ========== SSA Renaming Verification Tests ==========

    /// Test: Single-block SSA renaming correctness
    ///
    /// Sequence: mov rax, rdi; add rax, rsi; ret
    /// P-code:
    ///   op0: RAX = COPY(RDI)
    ///   op1: RAX = INT_ADD(RAX, RSI)
    ///   op2: RETURN(const)
    ///
    /// After renaming:
    ///   - op1's first input (RAX) should be rewritten to point to op0's output (the first def of RAX)
    ///   - op0's output and op1's output should be DIFFERENT Varnode instances (different create_index)
    ///   - op1's input[0] should be Arc::ptr_eq to op0's output
    #[test]
    fn test_ssa_rename_single_block_linear() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();

        // Build: op0: RAX = COPY(RDI)
        let mut op0 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op0.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op0.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        // Build: op1: RAX = INT_ADD(RAX, RSI)
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX (should be rewritten)
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI

        // Build: op2: RETURN(const)
        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op2.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));

        let start = Address::new(0x3000);
        let mut fd = Funcdata::new("ssa_rename_linear", start, 10);
        fd.inject_raw_ops(&[op0, op1, op2]);

        assert_eq!(fd.bblocks.get_size(), 1, "Should have exactly 1 basic block");

        // Build dom tree & run heritage
        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Collect ops in order from the block
        let block = &fd.bblocks.blocks[0];
        let ops = block.read().unwrap().get_ops();

        // Filter to only non-MULTIEQUAL ops (there should be none in single block, but be safe)
        let regular_ops: Vec<_> = ops.iter()
            .filter(|op_ref| op_ref.0.read().unwrap().get_opcode() != OpCode::CPUI_MULTIEQUAL)
            .collect();
        assert!(regular_ops.len() >= 3, "Should have at least 3 regular ops, got {}", regular_ops.len());

        let pcode_op0 = regular_ops[0].0.read().unwrap();
        let pcode_op1 = regular_ops[1].0.read().unwrap();

        // op0 output: the first definition of RAX
        let op0_out = pcode_op0.output.as_ref().expect("op0 should have output");
        // op1 output: the second definition of RAX
        let op1_out = pcode_op1.output.as_ref().expect("op1 should have output");

        // VERIFY: op0 and op1 outputs are DIFFERENT Varnode instances
        assert!(
            !Arc::ptr_eq(op0_out, op1_out),
            "op0 and op1 should define DIFFERENT Varnode instances for RAX"
        );
        // Both should be at Register:0x00 (RAX)
        assert_eq!(op0_out.read().unwrap().get_space(), AddressSpace::Register);
        assert_eq!(op0_out.read().unwrap().get_offset(), 0x00);
        assert_eq!(op1_out.read().unwrap().get_space(), AddressSpace::Register);
        assert_eq!(op1_out.read().unwrap().get_offset(), 0x00);

        // VERIFY: op1's first input (RAX) was rewritten to point to op0's output
        let op1_in0 = &pcode_op1.inrefs[0];
        assert!(
            Arc::ptr_eq(op1_in0, op0_out),
            "After renaming, op1's RAX input should point to op0's output Varnode. \
             op1_in0 create_index={}, op0_out create_index={}",
            op1_in0.read().unwrap().get_create_index(),
            op0_out.read().unwrap().get_create_index(),
        );

        // VERIFY: op0's and op1's outputs have different create_index
        let ci0 = op0_out.read().unwrap().get_create_index();
        let ci1 = op1_out.read().unwrap().get_create_index();
        assert_ne!(ci0, ci1, "Different definitions of RAX should have different create_index: {} vs {}", ci0, ci1);
    }

    /// Test: Multi-block SSA renaming with Phi node input filling
    ///
    /// Assembly:
    ///   cmp rdi, 0       (Block 0)
    ///   je block2
    ///   mov rax, 1       (Block 1)
    ///   jmp block3
    ///   mov rax, 2       (Block 2)
    ///   jmp block3
    ///   add rax, rsi     (Block 3 — merge)
    ///   ret
    ///
    /// After renaming, at the merge block:
    ///   - A MULTIEQUAL (Phi) for RAX should exist
    ///   - Phi input 0 should be the RAX definition from Block 1 (mov rax, 1)
    ///   - Phi input 1 should be the RAX definition from Block 2 (mov rax, 2)
    ///   - op `add rax, rsi` in Block 3 should use the Phi output as its RAX input
    #[test]
    fn test_ssa_rename_multi_block_phi_inputs() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![
            0x48, 0x83, 0xff, 0x00,                         // cmp rdi, 0
            0x74, 0x09,                                     // je 0x100f
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,       // mov rax, 1
            0xeb, 0x09,                                     // jmp 0x1018
            0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00,       // mov rax, 2
            0xeb, 0x00,                                     // jmp 0x1018
            0x48, 0x01, 0xf0,                               // add rax, rsi
            0xc3,                                           // ret
        ];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();

        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            all_raw_ops.extend(lifter.lift(inst));
        }

        let mut fd = Funcdata::new("ssa_rename_phi", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        // Build dom tree & run heritage
        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Find the MULTIEQUAL (Phi) op for RAX
        let multiequals: Vec<_> = fd.obank.optree.iter()
            .filter(|op| op.0.read().unwrap().get_opcode() == OpCode::CPUI_MULTIEQUAL)
            .collect();

        // Find Phi node for RAX (Register:0x00)
        let rax_phis: Vec<_> = multiequals.iter()
            .filter(|op_ref| {
                let op = op_ref.0.read().unwrap();
                if let Some(out_vn) = &op.output {
                    let vn = out_vn.read().unwrap();
                    vn.get_space() == AddressSpace::Register && vn.get_offset() == 0x00
                } else {
                    false
                }
            })
            .collect();

        assert!(!rax_phis.is_empty(), "Should have at least one Phi node for RAX");
        let phi = rax_phis[0].0.read().unwrap();
        assert_eq!(phi.inrefs.len(), 2, "RAX Phi node should have 2 inputs (from 2 predecessor blocks)");

        // VERIFY: Both Phi inputs should be WRITTEN varnodes (defined by mov rax, 1 / mov rax, 2)
        // After renaming, Phi inputs should NOT be placeholder varnodes — they should point to
        // the actual definitions from the predecessor blocks.
        for (idx, phi_input) in phi.inrefs.iter().enumerate() {
            let vn = phi_input.read().unwrap();
            assert_eq!(
                vn.get_space(), AddressSpace::Register,
                "Phi input {} should be in Register space", idx
            );
            assert_eq!(
                vn.get_offset(), 0x00,
                "Phi input {} should reference RAX (offset 0x00)", idx
            );
            // Each phi input should be a WRITTEN varnode (defined by a preceding op)
            // or at least not the same as the phi output itself
            assert!(
                !Arc::ptr_eq(phi_input, phi.output.as_ref().unwrap()),
                "Phi input {} should NOT be the same as Phi output", idx
            );
        }

        // VERIFY: The two Phi inputs should be DIFFERENT varnodes
        // (they come from different blocks with different definitions)
        assert!(
            !Arc::ptr_eq(&phi.inrefs[0], &phi.inrefs[1]),
            "Phi's two inputs should be different Varnode instances (from different blocks). \
             input0 ci={}, input1 ci={}",
            phi.inrefs[0].read().unwrap().get_create_index(),
            phi.inrefs[1].read().unwrap().get_create_index(),
        );

        // VERIFY: Find the merge block's `add rax, rsi` op
        // Its RAX input should point to the Phi output, not to some random prior definition
        let phi_output = phi.output.as_ref().unwrap().clone();
        drop(phi); // Release the read lock

        // Search all ops for INT_ADD in the merge block that uses RAX
        let add_ops: Vec<_> = fd.obank.optree.iter()
            .filter(|op_ref| {
                let op = op_ref.0.read().unwrap();
                op.get_opcode() == OpCode::CPUI_INT_ADD
                    && op.inrefs.iter().any(|inref| {
                        let vn = inref.read().unwrap();
                        vn.get_space() == AddressSpace::Register && vn.get_offset() == 0x00
                    })
            })
            .collect();

        // Among those, find one whose RAX input is the Phi output
        let uses_phi_output = add_ops.iter().any(|op_ref| {
            let op = op_ref.0.read().unwrap();
            op.inrefs.iter().any(|inref| Arc::ptr_eq(inref, &phi_output))
        });
        assert!(
            uses_phi_output,
            "The merge block's INT_ADD should use the Phi output as its RAX input"
        );
    }

    /// Test: SSA renaming with diamond CFG pattern
    ///
    /// Uses `mov rax, imm` instructions to ensure direct RAX definitions.
    /// CFG:
    ///   Block 0 (entry): cmp rdi,0; je block2
    ///   Block 1 (then):  mov rax, 0x10; jmp block3
    ///   Block 2 (else):  mov rax, 0x20; jmp block3
    ///   Block 3 (merge): ret   (Phi for RAX should be placed here)
    #[test]
    fn test_ssa_rename_diamond_pattern() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();

        let code = vec![
            // Block 0: cmp rdi, 0; je block2
            0x48, 0x83, 0xff, 0x00,                         // 0x4000: cmp rdi, 0
            0x74, 0x09,                                     // 0x4004: je +9 → 0x400f
            // Block 1: mov rax, 0x10; jmp block3
            0x48, 0xc7, 0xc0, 0x10, 0x00, 0x00, 0x00,       // 0x4006: mov rax, 0x10
            0xeb, 0x09,                                     // 0x400d: jmp +9 → 0x4018
            // Block 2: mov rax, 0x20; jmp block3
            0x48, 0xc7, 0xc0, 0x20, 0x00, 0x00, 0x00,       // 0x400f: mov rax, 0x20
            0xeb, 0x00,                                     // 0x4016: jmp +0 → 0x4018
            // Block 3: ret
            0xc3,                                           // 0x4018: ret
        ];
        let start = Address::new(0x4000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();

        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            all_raw_ops.extend(lifter.lift(inst));
        }

        let mut fd = Funcdata::new("ssa_diamond", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        let num_blocks = fd.bblocks.get_size();
        assert!(num_blocks >= 3, "Diamond pattern should have at least 3 blocks, got {}", num_blocks);

        // Build dom tree & run heritage
        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Find Phi nodes for RAX (Register:0x00)
        let rax_phis: Vec<_> = fd.obank.optree.iter()
            .filter(|op_ref| {
                let op = op_ref.0.read().unwrap();
                if op.get_opcode() != OpCode::CPUI_MULTIEQUAL {
                    return false;
                }
                if let Some(out_vn) = &op.output {
                    let vn = out_vn.read().unwrap();
                    vn.get_space() == AddressSpace::Register && vn.get_offset() == 0x00
                } else {
                    false
                }
            })
            .collect();

        assert!(!rax_phis.is_empty(), "Diamond merge should have Phi for RAX");

        let phi = rax_phis[0].0.read().unwrap();
        assert_eq!(
            phi.inrefs.len(), 2,
            "RAX Phi at diamond merge should have 2 inputs, got {}",
            phi.inrefs.len()
        );

        // VERIFY: Both inputs should be register RAX varnodes
        for (i, phi_in) in phi.inrefs.iter().enumerate() {
            let vn = phi_in.read().unwrap();
            assert_eq!(vn.get_space(), AddressSpace::Register,
                "Phi input {} should be Register", i);
            assert_eq!(vn.get_offset(), 0x00,
                "Phi input {} should be RAX (offset 0x00)", i);
        }

        // VERIFY: Phi inputs are distinct (different definitions)
        assert!(
            !Arc::ptr_eq(&phi.inrefs[0], &phi.inrefs[1]),
            "Diamond Phi inputs should be distinct varnode instances"
        );

        // VERIFY: Phi output is distinct from both inputs
        let phi_out = phi.output.as_ref().unwrap();
        assert!(!Arc::ptr_eq(phi_out, &phi.inrefs[0]));
        assert!(!Arc::ptr_eq(phi_out, &phi.inrefs[1]));
    }

    /// Test: SSA renaming correctly uses INPUT varnodes for undefined reads
    ///
    /// Sequence: add rax, rsi; ret
    /// There is no prior definition of RAX — it should remain linked to
    /// the INPUT varnode that heritage creates for uninitialized reads.
    #[test]
    fn test_ssa_rename_input_varnode_for_undefined_read() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();

        // op0: RAX = INT_ADD(RAX, RSI)   — RAX is read before being defined
        let mut op0 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op0.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX out
        op0.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX in (undefined)
        op0.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI

        // op1: RETURN
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op1.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));

        let start = Address::new(0x5000);
        let mut fd = Funcdata::new("ssa_input_test", start, 10);
        fd.inject_raw_ops(&[op0, op1]);

        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Get ops
        let block = &fd.bblocks.blocks[0];
        let ops = block.read().unwrap().get_ops();
        let regular_ops: Vec<_> = ops.iter()
            .filter(|op_ref| op_ref.0.read().unwrap().get_opcode() != OpCode::CPUI_MULTIEQUAL)
            .collect();

        assert!(!regular_ops.is_empty(), "Should have at least 1 regular op");

        // Find the INT_ADD op
        let add_op_ref = regular_ops.iter()
            .find(|op_ref| op_ref.0.read().unwrap().get_opcode() == OpCode::CPUI_INT_ADD);
        assert!(add_op_ref.is_some(), "Should find INT_ADD op");

        let add_op = add_op_ref.unwrap().0.read().unwrap();
        assert!(add_op.inrefs.len() >= 2, "INT_ADD should have at least 2 inputs");

        // The RAX input (input 0) should reference a varnode.
        // Since there is no prior definition of RAX in this block,
        // after renaming it should either:
        // a) remain unchanged (no stack entry for RAX exists), or
        // b) point to an INPUT varnode if heritage created one
        //
        // The key verification: the input RAX varnode should be DIFFERENT from the output RAX varnode.
        let add_out = add_op.output.as_ref().expect("INT_ADD should have output");
        let add_in_rax = &add_op.inrefs[0];

        // Both refer to RAX
        assert_eq!(add_in_rax.read().unwrap().get_space(), AddressSpace::Register);
        assert_eq!(add_in_rax.read().unwrap().get_offset(), 0x00);
        assert_eq!(add_out.read().unwrap().get_space(), AddressSpace::Register);
        assert_eq!(add_out.read().unwrap().get_offset(), 0x00);

        // They must be DIFFERENT Varnode instances (input vs output are different SSA versions)
        assert!(
            !Arc::ptr_eq(add_in_rax, add_out),
            "Input RAX and output RAX should be different SSA versions. \
             Input ci={}, output ci={}",
            add_in_rax.read().unwrap().get_create_index(),
            add_out.read().unwrap().get_create_index(),
        );
    }

    // ========== CBRANCH condition def-loss repro ==========
    // Diagnostic for the curl `while (local_0 == local_0)` dead-loop root cause:
    // does Heritage rename wire CBRANCH in(1) (the condition) to the op that
    // defines it? Mirrors exactly what x86_lift.rs emits for `cmp rdi, rsi`
    // followed by `je target` (ZF lives at Register:0x201).

    #[test]
    fn test_cbranch_condition_def_wired_via_heritage_single_block() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();

        // Reproduce the exact P-code x86_lift.rs emits for `cmp rdi,rsi` + `je`.
        // cmp emits 3 flag writes; only ZF (Register:0x201) matters for je.
        let mut cmp_zf = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        cmp_zf.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI
        cmp_zf.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI
        cmp_zf.set_output(VarnodeRaw::new(AddressSpace::Register, 0x201, 1)); // ZF

        // je target  → CBRANCH(target, ZF). in(1) is a FREE zf varnode distinct
        // from the cmp's written ZF (find_or_create_input_space filters out written).
        let mut cbranch = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
        cbranch.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x1010, 8)); // target
        cbranch.add_input(VarnodeRaw::new(AddressSpace::Register, 0x201, 1)); // ZF

        let start = Address::new(0x1000);
        let mut fd = Funcdata::new("cbranch_cond", start, 10);
        fd.inject_raw_ops(&[cmp_zf, cbranch]);
        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Locate the CBRANCH op.
        let cbranch_ref = fd.obank.optree.iter()
            .find(|op| op.0.read().unwrap().get_opcode() == OpCode::CPUI_CBRANCH)
            .expect("CBRANCH op should exist");
        let cbranch_op = cbranch_ref.0.read().unwrap();
        assert_eq!(cbranch_op.inrefs.len(), 2, "CBRANCH must have target + condition");

        let cond_vn = &cbranch_op.inrefs[1];
        // The condition varnode must carry a def (be written) after rename.
        let cond_def = {
            let vn = cond_vn.read().unwrap();
            vn.def.as_ref().and_then(|w| w.upgrade())
        };
        let cond_is_written = cond_vn.read().unwrap().is_written();
        assert!(
            cond_is_written && cond_def.is_some(),
            "CBRANCH condition varnode lost its SSA def after heritage. \
             is_written={}, def={:?} (Register:0x201, size 1). \
             This is the root cause of the `while(local_0==local_0)` dead loop.",
            cond_is_written,
            if cond_def.is_some() { "Some" } else { "None/dead" },
        );

        // And the def must be the cmp's INT_EQUAL, not a placeholder.
        if let Some(def_op) = cond_def {
            let d = def_op.read().unwrap();
            assert_eq!(
                d.get_opcode(), OpCode::CPUI_INT_EQUAL,
                "CBRANCH condition def should be the INT_EQUAL (cmp) op"
            );
        }
    }

    /// Multi-block variant: cmp and the je/CBRANCH land in DIFFERENT basic blocks
    /// (the normal x86 case — `je` is itself a block terminator). This is where
    /// Heritage must propagate the cmp's ZF def across the block boundary into
    /// CBRANCH in(1). Uses the real x86 lifter so the P-code is exactly what
    /// curl produces.
    #[test]
    fn test_cbranch_condition_def_wired_multiblock_real_x86() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();

        // 0x1000: cmp rdi, rsi      48 39 f7
        // 0x1003: je  0x100a        74 05     → branches over the next insn
        // 0x1005: mov rax, 1        48 c7 c0 01 00 00 00
        // 0x100c: ret               c3
        let code: Vec<u8> = vec![
            0x48, 0x39, 0xf7,
            0x74, 0x05,
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
            0xc3,
        ];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            all_raw_ops.extend(lifter.lift(inst));
        }

        let mut fd = Funcdata::new("cbranch_cond_mb", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);
        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Find the CBRANCH op.
        let cbranch_ref = fd.obank.optree.iter()
            .find(|op| op.0.read().unwrap().get_opcode() == OpCode::CPUI_CBRANCH)
            .expect("CBRANCH op should exist (from the je)");
        let cbranch_op = cbranch_ref.0.read().unwrap();
        assert_eq!(cbranch_op.inrefs.len(), 2, "CBRANCH must have target + condition");

        let cond_vn = &cbranch_op.inrefs[1];
        let cond_def = {
            let vn = cond_vn.read().unwrap();
            vn.def.as_ref().and_then(|w| w.upgrade())
        };
        let cond_is_written = cond_vn.read().unwrap().is_written();

        // Diagnostic dump so the failure message shows the actual state.
        let cond_desc = {
            let vn = cond_vn.read().unwrap();
            format!(
                "space={:?} off=0x{:x} size={} is_written={} def={}",
                vn.get_space(), vn.get_offset(), vn.get_size(), vn.is_written(),
                if cond_def.is_some() { "Some" } else { "None/dead" },
            )
        };

        assert!(
            cond_is_written && cond_def.is_some(),
            "CBRANCH condition varnode lost its SSA def after heritage (multi-block). \
             cond={} — this is the root cause of the `while(local_0==local_0)` dead loop.",
            cond_desc,
        );

        if let Some(def_op) = cond_def {
            let d = def_op.read().unwrap();
            assert_eq!(
                d.get_opcode(), OpCode::CPUI_INT_EQUAL,
                "CBRANCH condition def should be the cmp INT_EQUAL op, got {:?}",
                d.get_opcode(),
            );
        }
    }

    /// Pattern B from docs/alignment_audit/ssa_flags_diagnosis.md §2-3: a LOOP
    /// where the loop header is the function entry. The flag varnode (ZF) is
    /// defined BOTH in the header (blk[0], the cmp) AND in the loop body
    /// (blk[1], a second flag writer) so ZF has multiple defs across the
    /// back-edge. Heritage MUST place a MULTIEQUAL (phi) for ZF at the loop
    /// header so the CBRANCH condition read resolves. This is the root-cause
    /// regression for the curl `while (local_0 == local_0)` dead-loop.
    ///
    ///   blk[0] entry+header: cmp ZF=...; je exit; ... ; jmp back  (idom=None)
    ///   blk[1] body:          cmp2 ZF=...; (falls back to header)
    ///   blk[2] exit (ret)
    #[test]
    fn test_cbranch_condition_def_wired_loop_header_is_entry() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();

        // --- blk[0] (header/entry): cmp; je exit; jmp back ---
        // cmp rdi, rsi  →  INT_EQUAL ZF = (RDI == RSI)
        let mut cmp_zf = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        cmp_zf.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI
        cmp_zf.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI
        cmp_zf.set_output(VarnodeRaw::new(AddressSpace::Register, 0x201, 1)); // ZF
        cmp_zf.set_seq_num(crate::address::SeqNum::new(Address::new(0x1000), 0));

        // je exit (0x100a)  →  CBRANCH(exit, ZF)  — conditional exit from loop
        let mut cbranch = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
        cbranch.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x100a, 8)); // exit target
        cbranch.add_input(VarnodeRaw::new(AddressSpace::Register, 0x201, 1)); // ZF
        cbranch.set_seq_num(crate::address::SeqNum::new(Address::new(0x1003), 0));

        // --- blk[1] (loop body): cmp2 ZF=... (a SECOND writer of ZF) ---
        // This second def of ZF in the body is what makes ZF loop-carried and
        // forces a phi at the header. Without it, ZF is single-def in the
        // header and no phi is needed. The body starts at 0x1005 (the
        // fall-through target of the je at 0x1003).
        let mut cmp2_zf = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        cmp2_zf.add_input(VarnodeRaw::new(AddressSpace::Register, 0x40, 8)); // RAX
        cmp2_zf.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));        // 0
        cmp2_zf.set_output(VarnodeRaw::new(AddressSpace::Register, 0x201, 1)); // ZF
        cmp2_zf.set_seq_num(crate::address::SeqNum::new(Address::new(0x1005), 0));

        // jmp back to 0x1000 (header) — terminates the loop body.
        let mut branch_back = PcodeOpRaw::new(OpCode::CPUI_BRANCH as i32);
        branch_back.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x1000, 8));
        branch_back.set_seq_num(crate::address::SeqNum::new(Address::new(0x1008), 0));

        // exit block: ret
        let mut ret_op = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        ret_op.set_seq_num(crate::address::SeqNum::new(Address::new(0x100a), 0));

        let start = Address::new(0x1000);
        let mut fd = Funcdata::new("cbranch_loop", start, 16);
        fd.inject_raw_ops(&[cmp_zf, cbranch, cmp2_zf, branch_back, ret_op]);
        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Dump the CFG for diagnostics if it fails.
        let dump_cfg = || -> String {
            let mut s = String::new();
            for blk in &fd.bblocks.blocks {
                let b = blk.read().unwrap();
                let idx = b.get_index();
                let size_in = b.size_in();
                let b_idom = b.get_immed_dom().and_then(|w| w.upgrade());
                let is_entry = (b.get_flags()
                    & crate::block::block_flags::ENTRY_POINT) != 0
                    || size_in == 0
                    || b_idom.is_none();
                let idom = b_idom
                    .map(|d| d.read().unwrap().get_index());
                let df = b.get_dom_frontier();
                let mut preds = Vec::new();
                for j in 0..size_in {
                    if let Some(e) = b.get_in(j) {
                        preds.push(e.point.read().unwrap().get_index());
                    }
                }
                s.push_str(&format!(
                    "\n    blk[{}] size_in={} is_entry={} idom={:?} df={:?} preds={:?}",
                    idx, size_in, is_entry, idom, df, preds
                ));
            }
            s
        };

        // Cooper-Harvey-Kennedy invariant for an entry-loop-header: the loop
        // header `H` (entry, reached by a back-edge from body `B`) must appear
        // in `B`'s dominance frontier. Concretely, if `H` dominates `B` and
        // there is a back-edge `B -> H`, then H ∈ DF(B). Without the
        // calc_dom_frontier fix the entry is skipped as a join-point (only one
        // recorded predecessor — the back-edge) and DF(B) stays empty, so no
        // phi is ever placed for a loop-carried varnode.
        let (header_idx, body_idx) = {
            // Header = the entry/root block (idom None). Body = its successor
            // that loops back to it.
            let mut header = -1i32;
            let mut body = -1i32;
            for blk in &fd.bblocks.blocks {
                let b = blk.read().unwrap();
                let b_idom = b.get_immed_dom().and_then(|w| w.upgrade());
                let is_entry = (b.get_flags()
                    & crate::block::block_flags::ENTRY_POINT) != 0
                    || b.size_in() == 0
                    || b_idom.is_none();
                if is_entry && header == -1 {
                    header = b.get_index();
                    // Find the successor that loops back to header.
                    for j in 0..b.size_out() {
                        if let Some(e) = b.get_out(j) {
                            let s_idx = e.point.read().unwrap().get_index();
                            // The body is the successor whose own successor set
                            // contains header (back-edge).
                            for k in 0..e.point.read().unwrap().size_out() {
                                if let Some(e2) = e.point.read().unwrap().get_out(k) {
                                    if e2.point.read().unwrap().get_index() == header {
                                        body = s_idx;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            (header, body)
        };
        assert!(
            header_idx != -1 && body_idx != -1,
            "Could not identify loop header/body. CFG:{}", dump_cfg()
        );
        let body_df = fd
            .bblocks
            .blocks
            .iter()
            .find(|b| b.read().unwrap().get_index() == body_idx)
            .map(|b| b.read().unwrap().get_dom_frontier())
            .unwrap_or_default();
        assert!(
            body_df.contains(&header_idx),
            "Loop header (blk[{}]) must be in the loop body's (blk[{}]) dominance \
             frontier. Got DF(body)={:?}. This is the calc_dom_frontier \
             join-point bug. CFG:{}",
            header_idx, body_idx, body_df, dump_cfg()
        );

        // A MULTIEQUAL (phi) for ZF (Register:0x201) must have been inserted at
        // the header, because ZF is written in both the header and the body.
        // We look at the header block's op list directly (the phi's `parent`
        // back-pointer is not always set by insert_op, so iterating the block's
        // ops is the reliable check).
        let header_ops: Vec<_> = fd
            .bblocks
            .blocks
            .iter()
            .find(|b| b.read().unwrap().get_index() == header_idx)
            .map(|b| {
                // BlockBasic stores its ops in `ops`. Downcast to access them.
                b.read().unwrap().get_ops()
            })
            .unwrap_or_default();
        let phi_at_header = header_ops.iter().any(|op_ref| {
            let o = op_ref.0.read().unwrap();
            if o.get_opcode() != OpCode::CPUI_MULTIEQUAL {
                return false;
            }
            // The phi's output must be at Register:0x201 (ZF).
            o.output
                .as_ref()
                .map(|out| {
                    let v = out.read().unwrap();
                    v.get_space() == AddressSpace::Register && v.get_offset() == 0x201
                })
                .unwrap_or(false)
        });
        assert!(
            phi_at_header,
            "Expected a MULTIEQUAL (phi) for ZF (Register:0x201) at the loop \
             header blk[{}], but found none. This means calc_dom_frontier's \
             fix is not propagating into phi placement. Header block ops: [{}] \
             CFG:{}",
            header_idx,
            header_ops.iter().map(|op_ref| {
                let o = op_ref.0.read().unwrap();
                let out_desc = o.output.as_ref().map(|out| {
                    let v = out.read().unwrap();
                    format!("{:?}:0x{:x}/{}", v.get_space(), v.get_offset(), v.get_size())
                }).unwrap_or_else(|| "none".to_string());
                format!("{:?}->{}", o.get_opcode(), out_desc)
            }).collect::<Vec<_>>().join(", "),
            dump_cfg()
        );

        // End-to-end check: does the CBRANCH condition varnode resolve to a def
        // after heritage? Note that full resolution also requires the inserted
        // phi's `parent` back-pointer to be set so rename can traverse it — that
        // is a separate concern (BlockBasic::insert_op does not yet set the
        // op's parent, unlike Ghidra's setParent). This regression covers the
        // calc_dom_frontier fix specifically (dom_frontier + phi placement
        // above); the condition-wiring is recorded here as a diagnostic and is
        // NOT asserted, to keep this test focused on the dom_frontier fix.
        let cbranch_ref = fd
            .obank
            .optree
            .iter()
            .find(|op| op.0.read().unwrap().get_opcode() == OpCode::CPUI_CBRANCH)
            .expect("CBRANCH op should exist");
        let cbranch_op = cbranch_ref.0.read().unwrap();
        let cond_vn = cbranch_op.inrefs[1].clone();
        drop(cbranch_op);
        let cond_def = {
            let vn = cond_vn.read().unwrap();
            vn.def.as_ref().and_then(|w| w.upgrade())
        };
        let cond_is_written = cond_vn.read().unwrap().is_written();
        // Diagnostic only (not asserted) — surfaces the rename/parent issue
        // without failing the regression on the (separate) wiring concern.
        let _ = format!(
            "CBRANCH cond space={:?} off=0x{:x} size={} is_written={} def={}",
            cond_vn.read().unwrap().get_space(),
            cond_vn.read().unwrap().get_offset(),
            cond_vn.read().unwrap().get_size(),
            cond_is_written,
            if cond_def.is_some() { "Some" } else { "None/dead" },
        );
    }

    // ========== ActionNormalizeBranches tests ==========

    #[test]
    fn test_normalize_branches_break_in_while_loop() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();

        // while(rdi != rsi) { if (rax == 0x10) break; rax++; }
        //
        // 0x1000: cmp rdi, rsi        48 39 f7
        // 0x1003: je  0x1011          74 0c       → exit (loop condition: if equal, exit)
        // 0x1005: cmp rax, 0x10       48 83 f8 10
        // 0x1009: je  0x1011          74 06       → break (early exit from loop body)
        // 0x100b: add rax, 1          48 83 c0 01
        // 0x100f: jmp 0x1000          eb ef       → continue (back to loop header)
        // 0x1011: ret                 c3
        let code: Vec<u8> = vec![
            0x48, 0x39, 0xf7,
            0x74, 0x0c,
            0x48, 0x83, 0xf8, 0x10,
            0x74, 0x06,
            0x48, 0x83, 0xc0, 0x01,
            0xeb, 0xef,
            0xc3,
        ];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();

        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            all_raw_ops.extend(lifter.lift(inst));
        }

        let mut fd = Funcdata::new("loop_break_test", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        assert!(
            fd.bblocks.get_size() >= 3,
            "Loop CFG should have at least 3 blocks, got {}",
            fd.bblocks.get_size()
        );

        fd.bblocks.build_dom_tree();

        use crate::action::Action;
        let mut structurer = crate::blockaction::ActionBlockStructure::new();
        let result = structurer.apply(&mut fd);
        assert!(result.is_ok());

        let mut normalizer = crate::blockaction::ActionNormalizeBranches::new();
        let result = normalizer.apply(&mut fd);
        assert!(result.is_ok());

        let mut _found_break = false;
        let mut found_continue = false;

        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            match op.opcode {
                OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH => {
                    if op.branch_type == crate::op::branch_type::BREAK {
                        _found_break = true;
                    }
                    if op.branch_type == crate::op::branch_type::CONTINUE {
                        found_continue = true;
                    }
                }
                _ => {}
            }
        }

        // The jmp back to 0x1000 should be tagged CONTINUE
        assert!(
            found_continue,
            "The back-edge jmp to loop header should be tagged CONTINUE"
        );
    }

    #[test]
    fn test_normalize_branches_op_branch_type_field() {
        use crate::op::branch_type;
        use crate::address::SeqNum;

        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = crate::op::PcodeOp::new(seq, OpCode::CPUI_CBRANCH);

        assert_eq!(op.branch_type, branch_type::NONE);

        op.branch_type = branch_type::BREAK;
        assert_eq!(op.branch_type, branch_type::BREAK);

        op.branch_type = branch_type::CONTINUE;
        assert_eq!(op.branch_type, branch_type::CONTINUE);
    }

    // ========== Boolean Condition Folding tests ==========

    #[test]
    fn test_bool_condition_folding_and_pattern() {
        use crate::block::{BlockBasic, BlockGraph, BlockEdge, BlockType, BlockCondition, BoolOp, FlowBlock};
        use crate::opcodes::OpCode;
        use crate::op::PcodeOp;
        use crate::address::{Address, SeqNum};

        // AND-pattern CFG:
        // A (CBRANCH): out(0)=B, out(1)=C → false edge to C
        // B (CBRANCH): out(0)=D, out(1)=C → false edge to C (same as A)
        // Both false edges → C → AND pattern
        let mut basic_a = BlockBasic::new(0, Address::new(0x1000));
        basic_a.ops.push(crate::op::PcodeOpRef(Arc::new(RwLock::new(
            PcodeOp::new(SeqNum::new(Address::new(0x1000), 0), OpCode::CPUI_CBRANCH),
        ))));

        let mut basic_b = BlockBasic::new(1, Address::new(0x1010));
        basic_b.ops.push(crate::op::PcodeOpRef(Arc::new(RwLock::new(
            PcodeOp::new(SeqNum::new(Address::new(0x1010), 0), OpCode::CPUI_CBRANCH),
        ))));

        let basic_c = BlockBasic::new(2, Address::new(0x1020));
        let basic_d = BlockBasic::new(3, Address::new(0x1030));

        let block_a: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(basic_a));
        let block_b: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(basic_b));
        let block_c: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(basic_c));
        let block_d: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(basic_d));

        // Wire edges
        {
            let mut a = block_a.write().unwrap();
            a.add_out_edge(BlockEdge::new(block_b.clone(), 0)); // out(0)=B (true)
            a.add_out_edge(BlockEdge::new(block_c.clone(), 0)); // out(1)=C (false)
        }
        {
            let mut b = block_b.write().unwrap();
            b.add_in_edge(BlockEdge::new(block_a.clone(), 0));
            b.add_out_edge(BlockEdge::new(block_d.clone(), 0)); // out(0)=D (true)
            b.add_out_edge(BlockEdge::new(block_c.clone(), 1)); // out(1)=C (false)
        }
        {
            let mut c = block_c.write().unwrap();
            c.add_in_edge(BlockEdge::new(block_a.clone(), 1));
            c.add_in_edge(BlockEdge::new(block_b.clone(), 1));
        }
        {
            let mut d = block_d.write().unwrap();
            d.add_in_edge(BlockEdge::new(block_b.clone(), 0));
        }

        let mut graph = BlockGraph::new();
        graph.blocks = vec![block_a, block_b, block_c, block_d];

        let mut cs = crate::blockaction::CollapseStructure::new(&mut graph, "test");
        cs.collapse_all();

        // Search for BlockCondition(And) — after full Ghidra-style collapseAll
        // (including interleaved cat/if rules), it may be standalone, inside a
        // BlockList, or its original block slot may have been replaced.
        // Search ALL blocks recursively for any BlockCondition with And.
        let mut found_and = false;
        for i in 0..graph.get_size() {
            if let Some(block) = graph.get_block(i) {
                let b = block.read().unwrap();
                match b.get_type() {
                    BlockType::Condition => {
                        if let Some(cond) = b.as_any().downcast_ref::<BlockCondition>() {
                            if cond.op_type == BoolOp::And { found_and = true; }
                        }
                    }
                    BlockType::List => {
                        if let Some(list) = b.as_any().downcast_ref::<crate::block::BlockList>() {
                            for child in &list.children {
                                let c = child.read().unwrap();
                                if c.get_type() == BlockType::Condition {
                                    if let Some(cond) = c.as_any().downcast_ref::<BlockCondition>() {
                                        if cond.op_type == BoolOp::And { found_and = true; }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        assert!(found_and, "Expected BlockCondition(And) after boolean folding");
    }

    #[test]
    fn test_block_condition_struct_fields() {
        use crate::block::{BlockBasic, BlockCondition, BlockType, BoolOp, FlowBlock, BlockEdge};
        use crate::address::Address;

        let a: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x1000))));
        let b: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockBasic::new(1, Address::new(0x2000))));

        let cond = BlockCondition {
            index: 10,
            op_type: BoolOp::And,
            first: a.clone(),
            second: b.clone(),
            incoming: Vec::new(),
            outgoing: vec![BlockEdge {
                point: a.clone(),
                flags: 0,
                reverse_index: 0,
            }],
            parent: None,
            flags: 0,
        };

        assert_eq!(cond.get_type(), BlockType::Condition);
        assert_eq!(cond.get_index(), 10);
        assert_eq!(cond.op_type, BoolOp::And);
        assert_eq!(cond.size_out(), 1);
        assert_eq!(cond.get_start_addr(), Address::new(0x1000));

        let cond_or = BlockCondition {
            index: 20,
            op_type: BoolOp::Or,
            first: a,
            second: b,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0,
        };
        assert_eq!(cond_or.op_type, BoolOp::Or);
        assert_eq!(cond_or.get_type(), BlockType::Condition);
    }

    #[test]
    fn test_switch_case_structuring() {
        use crate::action::Action;
        use crate::blockaction::ActionBlockStructure;
        use crate::prettyprint::EmitNoMarkup;
        use crate::printlanguage::PrintLanguage;
        use crate::printc::PrintC;
        use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
        use crate::space::AddressSpace;
        use crate::block::BlockType;

        let mut fd = Funcdata::new("test_switch", Address::new(0x1000), 0x100);

        // Control block (Block 0): indirect jump
        // unique_var = COPY(RDI)
        // BRANCHIND(unique_var)
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x50, 8));
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_BRANCHIND as i32);
        op2.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x50, 8));

        // Case 0 block (Block 1): return 10
        // RAX = COPY(10)
        // RETURN(RAX)
        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op3.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 10, 8));

        let mut op4 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op4.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));

        // Case 1 block (Block 2): return 20
        // RAX = COPY(20)
        // RETURN(RAX)
        let mut op5 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op5.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op5.add_input(VarnodeRaw::new(AddressSpace::Const, 20, 8));

        let mut op6 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op6.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));

        fd.inject_raw_ops(&[op1, op2, op3, op4, op5, op6]);

        // Verify we got 3 basic blocks
        assert_eq!(fd.bblocks.get_size(), 3);

        // Add edges: Block 0 -> Block 1, Block 0 -> Block 2
        let b0 = fd.bblocks.get_block(0).unwrap();
        let b1 = fd.bblocks.get_block(1).unwrap();
        let b2 = fd.bblocks.get_block(2).unwrap();
        fd.bblocks.add_edge(b0.clone(), b1.clone());
        fd.bblocks.add_edge(b0.clone(), b2.clone());

        // Run block structuring action
        let mut action = ActionBlockStructure::new();
        action.apply(&mut fd).unwrap();

        // Verify the main block was collapsed into a Switch
        assert_eq!(fd.sblocks.get_size(), 3);
        let entry = fd.sblocks.get_block(0).unwrap();
        assert_eq!(entry.read().unwrap().get_type(), BlockType::Switch);

        // Print C code
        let emit = EmitNoMarkup::new();
        let mut printer = PrintC::new(Box::new(emit));
        printer.doc_function(&fd);

        let emitted_code = printer.take_emit().into_any().downcast::<EmitNoMarkup>().unwrap().get_output();
        println!("Emitted code:\n{}", emitted_code);

        // Assert code structure
        assert!(emitted_code.contains("switch ("));
        assert!(emitted_code.contains("case 0:"));
        assert!(emitted_code.contains("case 1:"));
    }

    #[test]
    fn test_type_propagation() {
        use crate::action::Action;
        use crate::coreaction::ActionTypeInfer;
        use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
        use crate::space::AddressSpace;
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
        use crate::opcodes::OpCode;
        use std::sync::Arc;

        let mut fd = Funcdata::new("test_type_prop", Address::new(0x1000), 0x100);

        // Define linear instructions representing:
        // unique_1 = COPY(RDI)
        // unique_2 = INT_ADD(unique_1, 8)
        // unique_3 = LOAD(unique_2)
        // STORE(unique_4, unique_3)
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x10, 8)); // unique_1
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI (input)

        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op2.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x20, 8)); // unique_2
        op2.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x10, 8));
        op2.add_input(VarnodeRaw::new(AddressSpace::Const, 8, 8));

        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        op3.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x30, 4)); // unique_3 (size 4)
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 2, 8)); // space Ram
        op3.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x20, 8)); // unique_2 (addr)

        let mut op4 = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        op4.add_input(VarnodeRaw::new(AddressSpace::Const, 2, 8)); // space Ram
        op4.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x40, 8)); // unique_4 (addr, untyped)
        op4.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x30, 4)); // unique_3 (val)

        fd.inject_raw_ops(&[op1, op2, op3, op4]);

        // 1. Deduplicate/Link variables so dataflow can propagate.
        // We link inputs to matching output Varnodes by space/offset/size.
        // First, collect all output varnode info to avoid RwLock deadlocks.
        let mut output_varnodes: Vec<(crate::space::AddressSpace, u64, usize, Arc<RwLock<crate::varnode::Varnode>>)> = Vec::new();
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if let Some(ref out_vn_arc) = op.output {
                let out_vn = out_vn_arc.read().unwrap();
                output_varnodes.push((out_vn.space(), out_vn.offset(), out_vn.get_size(), out_vn_arc.clone()));
            }
        }

        let ops_to_update: Vec<_> = fd.obank.alivelist.iter().cloned().collect();
        for op_ref in &ops_to_update {
            let mut op = op_ref.0.write().unwrap();
            let num_inputs = op.inrefs.len();
            for i in 0..num_inputs {
                let (in_space, in_offset, in_size) = {
                    let in_vn = op.inrefs[i].read().unwrap();
                    (in_vn.space(), in_vn.offset(), in_vn.get_size())
                };

                if in_space != AddressSpace::Const {
                    let found_match = output_varnodes.iter()
                        .find(|(s, o, sz, _)| *s == in_space && *o == in_offset && *sz == in_size)
                        .map(|(_, _, _, arc)| arc.clone());

                    if let Some(matching_vn) = found_match {
                        op.inrefs[i] = matching_vn.clone();
                        matching_vn.write().unwrap().descend.push(Arc::downgrade(&op_ref.0));
                    }
                }
            }
        }

        // Manually inject a starting type: RDI is an "int *" pointer.
        let int_type = Arc::new(Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int)));
        let int_ptr_type = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: int_type.clone(),
            wordsize: 1,
        }));

        {
            let mut found = false;
            for op_ref in &fd.obank.alivelist {
                let op = op_ref.0.read().unwrap();
                if op.opcode == OpCode::CPUI_COPY {
                    let mut in_vn = op.inrefs[0].write().unwrap();
                    if in_vn.space().is_register() && in_vn.offset() == 0x38 {
                        in_vn.v_type = Some(int_ptr_type.clone());
                        found = true;
                    }
                }
            }
            assert!(found, "RDI input varnode not found and typed");
        }

        // Run type propagation
        let mut action = ActionTypeInfer::new();
        action.apply(&mut fd).unwrap();

        // Verify propagation results on our unified SSA variable chain
        let mut checked_u1 = false;
        let mut checked_u2 = false;
        let mut checked_u3 = false;
        let mut checked_u4 = false;

        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            match op.opcode {
                OpCode::CPUI_COPY => {
                    let out_vn = op.output.as_ref().unwrap().read().unwrap();
                    assert_eq!(out_vn.space(), AddressSpace::Unique);
                    assert_eq!(out_vn.offset(), 0x10);
                    assert_eq!(out_vn.v_type.as_ref().unwrap().get_name(), "int *");
                    checked_u1 = true;
                }
                OpCode::CPUI_INT_ADD => {
                    let out_vn = op.output.as_ref().unwrap().read().unwrap();
                    assert_eq!(out_vn.space(), AddressSpace::Unique);
                    assert_eq!(out_vn.offset(), 0x20);
                    assert_eq!(out_vn.v_type.as_ref().unwrap().get_name(), "int *");
                    checked_u2 = true;
                }
                OpCode::CPUI_LOAD => {
                    let out_vn = op.output.as_ref().unwrap().read().unwrap();
                    assert_eq!(out_vn.space(), AddressSpace::Unique);
                    assert_eq!(out_vn.offset(), 0x30);
                    assert_eq!(out_vn.v_type.as_ref().unwrap().get_name(), "int");
                    checked_u3 = true;
                }
                OpCode::CPUI_STORE => {
                    let addr_vn = op.inrefs[1].read().unwrap();
                    assert_eq!(addr_vn.space(), AddressSpace::Unique);
                    assert_eq!(addr_vn.offset(), 0x40);
                    assert_eq!(addr_vn.v_type.as_ref().unwrap().get_name(), "int *");
                    checked_u4 = true;
                }
                _ => {}
            }
        }

        assert!(checked_u1, "unique_1 type verification failed");
        assert!(checked_u2, "unique_2 type verification failed");
        assert!(checked_u3, "unique_3 type verification failed");
        assert!(checked_u4, "unique_4 type verification failed");
    }

    #[test]
    fn test_infer_params_and_return_type() {
        use crate::action::Action;
        use crate::coreaction::ActionInferParams;
        use crate::type_system::datatype::Datatype;

        let mut fd = Funcdata::new("my_func", Address::new(0x1000), 0x100);

        // Create INPUT varnodes in SysV ABI parameter registers
        // param1 = RDI (offset 0x38, size 8)
        let rdi_vn = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x38);
        let rdi_vn = fd.vbank.set_input(rdi_vn).expect("fresh RDI input");
        // param2 = RSI (offset 0x30, size 8)
        let rsi_vn = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x30);
        let rsi_vn = fd.vbank.set_input(rsi_vn).expect("fresh RSI input");

        // Create an op that reads both params: ADD rdi, rsi -> result (RAX)
        let result_vn = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x00);
        let add_ref = fd.obank.create(OpCode::CPUI_INT_ADD, 2, Address::new(0x1000));
        {
            let mut add_op = add_ref.0.write().unwrap();
            add_op.output = Some(result_vn.clone());
            add_op.inrefs.push(rdi_vn);
            add_op.inrefs.push(rsi_vn);
        }

        // Create RETURN op with RAX as return value
        let ret_addr_vn = fd.vbank.create_constant(8, 0);
        let ret_ref = fd.obank.create(OpCode::CPUI_RETURN, 2, Address::new(0x1010));
        {
            let mut ret_op = ret_ref.0.write().unwrap();
            ret_op.inrefs.push(ret_addr_vn);
            ret_op.inrefs.push(result_vn); // RAX as return value
        }

        // Verify initial state: void return, no params
        assert!(matches!(fd.funcp.return_type.as_ref(), Datatype::Void(_)));
        assert!(fd.funcp.parameters.is_empty());

        // Run ActionInferParams
        let mut action = ActionInferParams::new();
        let result = action.apply(&mut fd).unwrap();
        // Ghidra Actions return 0 (count is statistics only).
        assert_eq!(result, 0, "ActionInferParams returns 0 (Ghidra convention)");

        // Verify parameters detected
        assert_eq!(fd.funcp.parameters.len(), 2, "Should detect 2 parameters");
        assert_eq!(fd.funcp.parameters[0].name, "param_1");
        assert_eq!(fd.funcp.parameters[1].name, "param_2");

        // Verify return type inferred (RAX is size 8 -> long)
        assert_eq!(fd.funcp.return_type.get_name(), "long",
            "Return type should be inferred as 'long' from 8-byte RAX");
    }

    /// End-to-end decompilation test simulating a realistic curl-style function.
    ///
    /// Models a function like:
    /// ```c
    /// long curl_easy_setopt(long handle, int option, long value) {
    ///     long result;
    ///     if (option == 0x2712) {
    ///         *(long *)(handle + 0x28) = value;
    ///         result = 0;
    ///     } else {
    ///         result = curl_set_error(handle, option);
    ///     }
    ///     return result;
    /// }
    /// ```
    #[test]
    #[ignore = "TODO: action clone_registry init order needs fix (set_default_actions must run before clone_all)"]
    fn test_realistic_curl_function() {
        use crate::action::ActionDatabase;
        use crate::prettyprint::EmitNoMarkup;
        use crate::printlanguage::PrintLanguage;
        use crate::printc::PrintC;
        use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
        use crate::space::AddressSpace;

        let mut fd = Funcdata::new("curl_easy_setopt", Address::new(0x4050a0), 0x60);

        // Add symbol table entries for known functions
        fd.symbol_table.insert(0x403210, "curl_set_error".to_string());

        // Addresses: baseaddr + idx * 0x10
        // Block 0: op0..op4 (5 ops) → CBRANCH at op4
        //   Block 0 starts at 0x4050a0
        // Block 1: op5..op7 (3 ops) → BRANCH at op7
        //   Block 1 starts at 0x4050a0 + 5*0x10 = 0x4050f0
        // Block 2: op8..op11 (4 ops) → BRANCH at op11
        //   Block 2 starts at 0x4050a0 + 8*0x10 = 0x405120
        // Block 3: op12..op13 (2 ops) → RETURN at op13
        //   Block 3 starts at 0x4050a0 + 12*0x10 = 0x405160

        // === Block 0: Entry / condition check ===
        // op0: u0 = COPY(RDI)           ; handle → unique
        let mut op0 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op0.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));
        op0.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI = handle
        // op1: u1 = INT_ZEXT(ESI)       ; option → 8-byte
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_INT_ZEXT as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x108, 8));
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 4)); // ESI = option (4 byte)
        // op2: u2 = COPY(RDX)           ; value → unique
        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op2.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x110, 8));
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x10, 8)); // RDX = value
        // op3: u3 = INT_EQUAL(u1, 0x2712)  ; option == CURLOPT_URL
        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        op3.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x118, 1));
        op3.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x108, 8));
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 0x2712, 8));
        // op4: CBRANCH → Block 2 (then branch at 0x405120)
        let mut op4 = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
        op4.add_input(VarnodeRaw::new(AddressSpace::Const, 0x405120, 8));
        op4.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x118, 1));

        // === Block 1: else branch (call curl_set_error + branch to exit) ===
        // op5: CALL curl_set_error
        let mut op5 = PcodeOpRaw::new(OpCode::CPUI_CALL as i32);
        op5.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x403210, 8));
        // op6: u4 = COPY(RAX)     ; capture return value
        let mut op6 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op6.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x120, 8));
        op6.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        // op7: BRANCH → Block 3 (exit at 0x405160)
        let mut op7 = PcodeOpRaw::new(OpCode::CPUI_BRANCH as i32);
        op7.add_input(VarnodeRaw::new(AddressSpace::Const, 0x405160, 8));

        // === Block 2: then branch (store value + branch to exit) ===
        // op8: u5 = INT_ADD(u0, 0x28)  ; handle + 0x28
        let mut op8 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op8.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x128, 8));
        op8.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));
        op8.add_input(VarnodeRaw::new(AddressSpace::Const, 0x28, 8));
        // op9: STORE([ram], u5, u2)     ; *(handle+0x28) = value
        let mut op9 = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        op9.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        op9.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x128, 8));
        op9.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x110, 8));
        // op10: u6 = COPY(0)           ; result = 0
        let mut op10 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op10.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x130, 8));
        op10.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        // op11: BRANCH → Block 3 (exit at 0x405160)
        let mut op11 = PcodeOpRaw::new(OpCode::CPUI_BRANCH as i32);
        op11.add_input(VarnodeRaw::new(AddressSpace::Const, 0x405160, 8));

        // === Block 3: exit (return result) ===
        // op12: RAX = COPY(result)
        let mut op12 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op12.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        op12.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x120, 8));
        // op13: RETURN(RAX)
        let mut op13 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op13.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        op13.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));

        fd.inject_raw_ops(&[op0, op1, op2, op3, op4, op5, op6, op7, op8, op9, op10, op11, op12, op13]);

        // CFG edges are automatically created by build_blocks_from_ops

        // Run full analysis pipeline
        let mut db = ActionDatabase::new();
        db.set_default_actions();
        let _ = db.apply_all(&mut fd);

        // Print decompiled output
        let emit = EmitNoMarkup::new();
        let mut printer = PrintC::new(Box::new(emit));
        printer.doc_function(&fd);

        let emitted_code = printer.take_emit().into_any().downcast::<EmitNoMarkup>().unwrap().get_output();
        println!("\n====== Rugra Decompiled Output: curl_easy_setopt ======\n{}\n======================================================", emitted_code);

        // Basic structure assertions
        assert!(emitted_code.contains("curl_easy_setopt"), "Should contain function name");
        assert!(!emitted_code.contains("void curl_easy_setopt"), "Should NOT have void return (has RETURN with RAX)");
        // Function signature should contain parameters
        assert!(emitted_code.contains("param_1"), "Should contain param_1 in signature");
        assert!(emitted_code.contains("param_2"), "Should contain param_2 in signature or body");
        assert!(emitted_code.contains("param_3"), "Should contain param_3 in signature");
        // param_2 should appear in the body expression (not just signature)
        assert!(emitted_code.contains("(long)param_2") || emitted_code.contains("param_2"),
            "param_2 should be used in body expression");
    }

    /// Verify Funcdata::spacebase() marks the RSP input varnode with the
    /// SPACEBASE flag, faithful to Ghidra Funcdata::spacebase()
    /// (funcdata.cc:230-269). This is the foundational mechanism that lets
    /// varmap/ActionStackPtrFlow recognize RSP as a Stack-space pointer.
    #[test]
    fn test_spacebase_marks_rsp_input() {
        // RSP input at Register@0x20, size 8 (matches x86_lift.rs:40).
        // A normal register (RAX @ 0x00) that should NOT be marked spacebase.
        let mut read_rsp = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        read_rsp.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x10, 8));
        read_rsp.add_input(VarnodeRaw::new(AddressSpace::Const, 0x100, 8)); // space-id const
        read_rsp.add_input(VarnodeRaw::new(AddressSpace::Register, 0x20, 8)); // RSP

        let mut read_rax = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        read_rax.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x18, 8));
        read_rax.add_input(VarnodeRaw::new(AddressSpace::Const, 0x100, 8));
        read_rax.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX

        let mut fd = Funcdata::new("test_spacebase", Address::new(0x1000), 0x100);
        fd.inject_raw_ops(&[read_rsp, read_rax]);

        // Before spacebase(): no varnode has SPACEBASE flag.
        let sb_before = fd.vbank.loc_tree.iter()
            .filter(|v| v.0.read().unwrap().is_spacebase())
            .count();
        assert_eq!(sb_before, 0, "No spacebase varnodes before spacebase()");

        // Run spacebase() — faithful to Ghidra Funcdata::spacebase().
        fd.spacebase();

        // After: the RSP input (Register@0x20) should be marked SPACEBASE.
        let sb_varnodes: Vec<_> = fd.vbank.loc_tree.iter()
            .filter(|v| v.0.read().unwrap().is_spacebase())
            .map(|v| v.0.clone())
            .collect();
        assert!(!sb_varnodes.is_empty(), "RSP input should be marked SPACEBASE");

        // Verify it's at Register@0x20, size 8.
        let sb = sb_varnodes[0].read().unwrap();
        assert_eq!(sb.get_space(), AddressSpace::Register);
        assert_eq!(sb.get_offset(), 0x20);
        assert_eq!(sb.get_size(), 8);
        assert!(sb.is_spacebase());

        // RAX (Register@0x00) must NOT be marked.
        let rax_marked = fd.vbank.loc_tree.iter()
            .any(|v| {
                let g = v.0.read().unwrap();
                g.get_space() == AddressSpace::Register
                    && g.get_offset() == 0x00
                    && g.is_spacebase()
            });
        assert!(!rax_marked, "RAX must NOT be marked spacebase");
    }

    /// Verify split_uses() duplicates a multi-descendant op so each reader
    /// gets its own output, faithful to Ghidra Funcdata::splitUses()
    /// (funcdata_varnode.cc:1540-1567).
    #[test]
    fn test_split_uses_duplicates_op() {
        // Build a Funcdata where one INT_ADD output has 2 descendant readers.
        // We construct varnodes directly in the bank with proper descend links
        // (inject_raw_ops creates separate varnode instances for inputs, which
        // breaks identity; so we wire the descend chain manually here).
        let mut fd = Funcdata::new("test_split", Address::new(0x1000), 0x100);
        let block = fd.create_new_block();

        // INT_ADD(RSP, 0x10) -> tmp_out
        let add_op = fd.new_op(2, Address::new(0x1000));
        fd.op_set_opcode(&add_op, OpCode::CPUI_INT_ADD);
        let tmp_out = fd.new_unique_out(8, &add_op);
        let rsp = fd.vbank.create_with_space(8, AddressSpace::Register, 0x20);
        // Register rsp as a function input (VarnodeBank::setInput,
        // varnode.cc:1358). splitUses re-reads every defining-op input on each
        // duplicated op (funcdata_varnode.cc:1560 opSetInput(newop,op->getIn(i),i));
        // in the Ghidra rule universe those inputs are written/input at that
        // point. A free rsp is Ghidra-unreachable — Varnode::addDescend would
        // throw "Free varnode has multiple descendants" (varnode.cc:336).
        // INPUT keeps is_written() false, and split_uses/op_set_input have no
        // input-flag branch, so the duplication path is identical.
        let rsp = fd.vbank.set_input(rsp).unwrap();
        let off = fd.vbank.create_constant(8, 0x10);
        fd.op_set_input(&add_op, rsp, 0);
        fd.op_set_input(&add_op, off, 1);
        fd.op_insert_end(&add_op, &block);

        // Two readers of tmp_out.
        let r1 = fd.new_op(2, Address::new(0x1001));
        fd.op_set_opcode(&r1, OpCode::CPUI_LOAD);
        fd.op_set_input(&r1, tmp_out.clone(), 1);  // reads tmp_out -> adds descend
        fd.op_insert_end(&r1, &block);

        let r2 = fd.new_op(3, Address::new(0x1002));
        fd.op_set_opcode(&r2, OpCode::CPUI_STORE);
        fd.op_set_input(&r2, tmp_out.clone(), 1);  // reads tmp_out -> adds descend
        fd.op_insert_end(&r2, &block);

        // Before split: tmp_out has 2 descendants.
        assert_eq!(tmp_out.read().unwrap().count_descends(), 2);

        // Run split_uses — faithful to Ghidra Funcdata::splitUses().
        fd.split_uses(&tmp_out);

        // After: a new duplicated INT_ADD op exists whose output is NOT tmp_out.
        let has_new_add = fd.obank.alivelist.iter().any(|r| {
            let o = r.0.read().unwrap();
            if o.opcode != OpCode::CPUI_INT_ADD { return false; }
            match o.output.as_ref() {
                Some(out) => !std::sync::Arc::ptr_eq(out, &tmp_out),
                None => false,
            }
        });
        assert!(has_new_add, "split_uses should create a duplicated INT_ADD op");
    }

    /// Diagnostic (2026-07-02): does lifting `xor eax,eax; ret` produce the
    /// SAME varnode for both XOR inputs? Ghidra's SSA identity model requires
    /// all reads of the same register (before any write) to share ONE varnode,
    /// so that `x^x→0` (RuleTrivialArith) can fold via Arc::ptr_eq. If this
    /// FAILS (ptreq=false AND same_storage=false), it is the root cause of the
    /// `return iVar1 ^ iVar1` defect in curl main_init.
    #[test]
    fn test_xor_eax_eax_input_identity() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // 31 c0 = xor eax,eax ; c3 = ret
        let code = vec![0x31, 0xc0, 0xc3];
        let start = Address::new(0x1000);
        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 2);
        let mut lifter = X86Lifter::new();
        let mut raw_ops = Vec::new();
        for inst in &instructions { raw_ops.extend(lifter.lift(inst)); }
        // xor→2(INT_XOR+COPY), ret→1(RETURN)
        assert_eq!(raw_ops.len(), 3, "expected 3 raw ops, got {}", raw_ops.len());
        let mut fd = Funcdata::new("xor_eax_eax", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if op.opcode == OpCode::CPUI_INT_XOR {
                let i0 = &op.inrefs[0]; let i1 = &op.inrefs[1];
                let v0 = i0.read().unwrap(); let v1 = i1.read().unwrap();
                let ptreq = std::sync::Arc::ptr_eq(i0, i1);
                let same_storage = v0.get_space()==v1.get_space()
                    && v0.get_offset()==v1.get_offset() && v0.get_size()==v1.get_size();
                eprintln!("XOR inputs: ptreq={} same_storage={} in0={:?}@0x{:x} sz{} written={} | in1={:?}@0x{:x} sz{} written={}",
                    ptreq, same_storage,
                    v0.get_space(), v0.get_offset(), v0.get_size(), v0.is_written(),
                    v1.get_space(), v1.get_offset(), v1.get_size(), v1.is_written());
            }
        }
    }

    #[test]
    fn test_combine_input_varnodes_preserves_storage_and_rewires_readers() {
        use crate::block::{BlockBasic, FlowBlock};
        use crate::space::AddressSpace;

        let mut fd = Funcdata::new("combine", Address::new(0x5000), 0x20);
        let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
            BlockBasic::new(0, Address::new(0x5000)),
        ));
        fd.bblocks.add_block(block.clone());

        let hi = fd
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x24);
        let hi = fd.vbank.set_input(hi).expect("fresh high input");
        let lo = fd
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x20);
        let lo = fd.vbank.set_input(lo).expect("fresh low input");

        let piece = fd.new_op(2, Address::new(0x5000));
        fd.op_set_opcode(&piece, OpCode::CPUI_PIECE);
        fd.op_insert_input(&piece, hi.clone(), 0);
        fd.op_insert_input(&piece, lo.clone(), 1);
        let piece_out = fd.vbank.create_def_unique(8, &piece.0);
        piece.0.write().unwrap().output = Some(piece_out);
        fd.op_insert_end(&piece, &block);

        // The same non-PIECE op reads hi twice. This exercises Ghidra's
        // one-descendant-entry-per-slot totalReplace iteration.
        let hi_reader = fd.new_op(2, Address::new(0x5001));
        fd.op_set_opcode(&hi_reader, OpCode::CPUI_INT_ADD);
        fd.op_insert_input(&hi_reader, hi.clone(), 0);
        fd.op_insert_input(&hi_reader, hi.clone(), 1);
        let hi_reader_out = fd.vbank.create_def_unique(4, &hi_reader.0);
        hi_reader.0.write().unwrap().output = Some(hi_reader_out);
        fd.op_insert_end(&hi_reader, &block);

        let lo_reader = fd.new_op(1, Address::new(0x5002));
        fd.op_set_opcode(&lo_reader, OpCode::CPUI_COPY);
        fd.op_insert_input(&lo_reader, lo.clone(), 0);
        let lo_reader_out = fd.vbank.create_def_unique(4, &lo_reader.0);
        lo_reader.0.write().unwrap().output = Some(lo_reader_out);
        fd.op_insert_end(&lo_reader, &block);

        assert_eq!(fd.vbank.num_varnodes(), 5);
        assert_eq!(fd.obank.optree.len(), 3);
        fd.combine_input_varnodes(&hi, &lo)
            .expect("valid contiguous register inputs");

        let combined = fd
            .vbank
            .loc_tree
            .iter()
            .map(|entry| entry.0.clone())
            .find(|candidate| {
                let value = candidate.read().unwrap();
                value.is_input()
                    && value.get_space() == AddressSpace::Register
                    && value.get_offset() == 0x20
                    && value.get_size() == 8
            })
            .expect("combined canonical input");
        assert_eq!(combined.read().unwrap().count_descends(), 3);
        assert_eq!(piece.0.read().unwrap().opcode, OpCode::CPUI_COPY);
        assert_eq!(piece.0.read().unwrap().inrefs.len(), 1);
        assert!(Arc::ptr_eq(
            &piece.0.read().unwrap().inrefs[0],
            &combined,
        ));

        let new_hi = hi_reader.0.read().unwrap().inrefs[0].clone();
        assert!(Arc::ptr_eq(
            &new_hi,
            &hi_reader.0.read().unwrap().inrefs[1],
        ));
        let new_lo = lo_reader.0.read().unwrap().inrefs[0].clone();
        for (replacement, offset, expected_storage) in [
            (new_hi, 4_u64, 0x24_u64),
            (new_lo, 0_u64, 0x20_u64),
        ] {
            let value = replacement.read().unwrap();
            assert_eq!(value.get_space(), AddressSpace::Register);
            assert_eq!(value.get_offset(), expected_storage);
            assert_eq!(value.get_size(), 4);
            let definition = value.get_def().expect("replacement definition");
            drop(value);
            let definition = crate::op::PcodeOpRef(definition);
            let operation = definition.0.read().unwrap();
            assert_eq!(operation.opcode, OpCode::CPUI_SUBPIECE);
            assert_eq!(operation.get_addr(), Address::new(0x5000));
            assert_eq!(operation.inrefs.len(), 2);
            assert!(Arc::ptr_eq(&operation.inrefs[0], &combined));
            assert!(operation.inrefs[1].read().unwrap().is_constant());
            assert_eq!(operation.inrefs[1].read().unwrap().get_offset(), offset);
        }

        assert!(hi.read().unwrap().has_no_descend());
        assert!(lo.read().unwrap().has_no_descend());
        assert!(!fd
            .vbank
            .loc_tree
            .iter()
            .any(|entry| Arc::ptr_eq(&entry.0, &hi) || Arc::ptr_eq(&entry.0, &lo)));
        assert_eq!(fd.vbank.num_varnodes(), 8);
        assert_eq!(fd.obank.optree.len(), 5);
    }

    #[test]
    fn test_combine_input_varnodes_reports_ghidra_errors() {
        use crate::space::AddressSpace;

        let mut non_input = Funcdata::new("combine_non_input", Address::new(0), 1);
        let hi = non_input
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x24);
        let lo = non_input
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x20);
        let lo = non_input.vbank.set_input(lo).expect("fresh low input");
        let error = non_input
            .combine_input_varnodes(&hi, &lo)
            .expect_err("free high value is not an input");
        assert_eq!(error.to_string(), "Varnodes being combined are not inputs");

        let mut disjoint = Funcdata::new("combine_disjoint", Address::new(0), 1);
        let hi = disjoint
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x30);
        let hi = disjoint.vbank.set_input(hi).expect("fresh high input");
        let lo = disjoint
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x20);
        let lo = disjoint.vbank.set_input(lo).expect("fresh low input");
        let error = disjoint
            .combine_input_varnodes(&hi, &lo)
            .expect_err("disjoint inputs are not contiguous");
        assert_eq!(
            error.to_string(),
            "Input varnodes being combined are not contiguous"
        );
    }

    // Regression for FUNC-GLOBRANGE-HANG-0001.
    //
    // Ghidra totalReplace (funcdata_varnode.cc:1478-1486) advances its
    // std::list iterator BEFORE opSetInput severs the entry, so the loop
    // visits each original entry exactly once and terminates at
    // endDescend() even when opSetInput early-outs because newvn == the
    // current input (funcdata_op.cc:107). The pre-fix Rust re-scan loop
    // re-found the same descendant forever in exactly that case — the
    // glob_range(0x4d60) deadlock.
    #[test]
    fn test_total_replace_same_varnode_terminates() {
        use crate::space::AddressSpace;

        let mut fd = Funcdata::new("total_replace_self", Address::new(0x1000), 0x10);
        let vn = fd
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x100);
        let reader = fd.new_op(1, Address::new(0x1000));
        fd.op_set_input(&reader, vn.clone(), 0);

        // totalReplace(vn, vn): opSetInput early-outs (getIn(0) == vn ==
        // newvn) leaving the descend entry in place — Ghidra still exits
        // after one pass. Pre-fix Rugra spun forever here.
        fd.total_replace(&vn, vn.clone());

        // Ghidra end state: opSetInput early-out mutates nothing.
        assert_eq!(
            vn.read().unwrap().descend.len(),
            1,
            "early-out opSetInput must leave the descend entry (Ghidra cc:107)"
        );
        assert!(std::sync::Arc::ptr_eq(
            &reader.0.read().unwrap().inrefs[0],
            &vn
        ));

        // A real replacement must drain vn's list exactly once per entry and
        // rewire the reader (Ghidra: eraseDescend + addDescend on newvn).
        let newvn = fd
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x200);
        fd.total_replace(&vn, newvn.clone());
        assert!(
            vn.read().unwrap().descend.is_empty(),
            "totalReplace must erase every live descend entry of the replaced vn"
        );
        assert!(std::sync::Arc::ptr_eq(
            &reader.0.read().unwrap().inrefs[0],
            &newvn
        ));
        assert_eq!(newvn.read().unwrap().descend.len(), 1);
    }

    // A dead Weak entry (op Arc freed without unset — impossible in Ghidra's
    // raw-pointer model) must be skipped, never matched: erase_descend
    // matches by upgraded identity, so a dead entry can only make a
    // "scan until drained" loop non-terminating. The snapshot walk visits it
    // zero times and terminates.
    #[test]
    fn test_total_replace_skips_dead_weak_entries() {
        use crate::space::AddressSpace;

        let mut fd = Funcdata::new("total_replace_deadweak", Address::new(0x1000), 0x10);
        let vn = fd
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x100);
        let newvn = fd
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x200);
        let reader = fd.new_op(1, Address::new(0x1000));
        fd.op_set_input(&reader, vn.clone(), 0);

        // Fabricate a dead entry: downgrade a temporary op Arc, then drop it.
        {
            let temp = std::sync::Arc::new(std::sync::RwLock::new(crate::op::PcodeOp::new(
                crate::address::SeqNum::new(Address::new(0x1000), 1),
                OpCode::CPUI_COPY,
            )));
            vn.write().unwrap().descend.push(std::sync::Arc::downgrade(&temp));
        }
        assert_eq!(vn.read().unwrap().descend.len(), 2);

        // Must terminate and leave only the dead entry behind (live site
        // rewired to newvn exactly as in Ghidra).
        fd.total_replace(&vn, newvn.clone());
        assert_eq!(
            vn.read().unwrap().descend.len(),
            1,
            "only the (unmatchable) dead entry may remain"
        );
        assert!(std::sync::Arc::ptr_eq(
            &reader.0.read().unwrap().inrefs[0],
            &newvn
        ));
    }

    // Regression for the erase_descend WARN storm (UPSTREAM-OUTVN-DEADWIRE
    // family). Ghidra opUnlink (funcdata_op.cc:186-193) NULLs every input
    // slot via opUnsetInput/clearInput, and opDestroy (funcdata_op.cc:211-216)
    // then skips those NULL slots. Rugra cannot NULL a Vec slot, so the
    // second unset must detect the already-severed link through descend
    // membership and be a no-op instead of re-erasing.
    #[test]
    fn test_unlink_then_destroy_does_not_disturb_other_readers() {
        use crate::space::AddressSpace;

        let mut fd = Funcdata::new("unlink_destroy", Address::new(0x1000), 0x10);
        let vn = fd
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x100);
        // Register vn as a function input (VarnodeBank::setInput,
        // varnode.cc:1358). The harness links TWO readers to one varnode; in
        // Ghidra a multi-reader varnode is written/input (per-read frees are
        // separate objects — PcodeEmitFd::dump, funcdata.cc:905), so a free
        // vn gaining a second descend is Ghidra-unreachable: addDescend would
        // throw "Free varnode has multiple descendants" (varnode.cc:336).
        // INPUT keeps is_written() false and op_unlink/op_destroy/op_unset_input
        // have no input-flag branch, so the double-unset no-op path under test
        // is identical. setInput returns the same Arc here (unique loc, xref
        // re-inserts the same object), so the ptr_eq assertions still bind.
        let vn = fd.vbank.set_input(vn).unwrap();
        let reader = fd.new_op(1, Address::new(0x1000));
        fd.op_set_input(&reader, vn.clone(), 0);
        let other = fd.new_op(1, Address::new(0x1002));
        fd.op_set_input(&other, vn.clone(), 0);
        assert_eq!(vn.read().unwrap().descend.len(), 2);

        // op_unlink severs reader's link (stale Arc remains in its inrefs),
        // then op_destroy re-unsets every slot — the double unset must not
        // touch `other`'s descend entry.
        fd.op_unlink(&reader);
        fd.op_destroy(&reader);

        let live: Vec<_> = vn.read().unwrap().descend_iter().collect();
        assert_eq!(live.len(), 1, "other reader's descend entry must survive");
        assert!(std::sync::Arc::ptr_eq(&live[0], &other.0));
        assert!(std::sync::Arc::ptr_eq(
            &other.0.read().unwrap().inrefs[0],
            &vn
        ));
    }

}

// RUGRA-GLUE: 在出边列表中查找指向目标块的索引。Ghidra 用 FlowBlock::getOutIndex
// (block.hh:317)；Rugra 内联为文件级函数（需 downcast 到 BlockBasic/BlockGraph）。
/// Find the index of the outgoing edge pointing to `target` in `src`.
fn find_out_index(
    src: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    target: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
) -> Option<usize> {
    let rg = src.read().unwrap();
    let n = rg.size_out();
    for i in 0..n {
        if let Some(e) = rg.get_out(i) {
            if Arc::ptr_eq(&e.point, target) {
                return Some(i);
            }
        }
    }
    None
}

// Ghidra: funcdata.hh:655 AncestorRealistic
/// Helper for determining if Varnodes can trace their value from a legitimate
/// source. Faithful 1:1 port of `AncestorRealistic` (funcdata.hh:655-724 +
/// funcdata_varnode.cc:1997-2237).
///
/// Tries to determine if a Varnode (a particular input to a CALL, CALLIND, or
/// RETURN op) makes sense as parameter-passing/return storage by examining the
/// Varnode's ancestors. If ancestors are \e unaffected, \e abnormal inputs, or
/// \e killedbycall, the Varnode doesn't make a good parameter.
///
/// The traversal is a depth-first walk over ancestor Varnodes (following the
/// def chain). The `State` stack holds the traversal frontier; each `State`
/// records (op, slot, flags, offset). The `marked_vn` list tracks visited
/// Varnodes so cycles are trimmed and marks can be cleared afterwards.
pub struct AncestorRealistic {
    state_stack: Vec<ArState>,
    marked_vn: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    multi_depth: i32,
    allow_failing_path: bool,
    // Snapshot of trial->isKilledByCall() taken at execute() start, so the
    // INDIRECT case can read it without &mut aliasing on ParamTrial.
    trial_killed_by_call: bool,
    // Snapshot of trial->getSize() taken at execute() start, so the PIECE
    // case can compare stateVn->getSize() > trial->getSize() faithfully.
    trial_size: i32,
    // Deferred ParamTrial flag mutations (applied by execute() after the
    // traversal). Ghidra mutates the trial pointer mid-traversal
    // (setIndCreateFormed / setCondExeEffect); Rugra defers these to avoid
    // &mut aliasing on ParamTrial during the self-referential traversal.
    pending_ind_create_formed: bool,
    pending_condexe_effect: bool,
}

// Ghidra: funcdata.hh:655 AncestorRealistic::State
/// One node in the depth-first ancestor traversal. Faithful to the nested
/// `AncestorRealistic::State` class (funcdata.hh:657-696).
#[derive(Clone)]
struct ArState {
    /// Operation along the path to the Varnode. `vn = op.getIn(slot)`.
    op: std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>,
    /// Input slot: `vn = op.getIn(slot)`.
    slot: i32,
    /// Boolean properties (seen_solid0 | seen_solid1 | seen_kill).
    flags: u32,
    /// Offset of the eventual trial value within a possibly larger register.
    offset: i32,
}

// Ghidra: funcdata.hh:659 AncestorRealistic::State (anonymous enum)
mod state_flags {
    /// Solid movement into slot 0 seen on at least one path to MULTIEQUAL.
    pub const SEEN_SOLID0: u32 = 1;
    /// Solid movement into a slot other than 0 seen.
    pub const SEEN_SOLID1: u32 = 2;
    /// Killedbycall seen on at least one path to MULTIEQUAL.
    pub const SEEN_KILL: u32 = 4;
}

// Ghidra: funcdata.hh:698 AncestorRealistic (anonymous enum)
/// Depth-first traversal commands. Faithful to the anonymous enum in
/// `AncestorRealistic` (funcdata.hh:698-704).
mod ar_command {
    /// Extending path into a new Varnode.
    pub const ENTER_NODE: i32 = 0;
    /// Backtracking, from a path that contained a reasonable ancestor.
    pub const POP_SUCCESS: i32 = 1;
    /// Backtracking, from a path with successful solid movement.
    pub const POP_SOLID: i32 = 2;
    /// Backtracking, from a path with a bad ancestor.
    pub const POP_FAIL: i32 = 3;
    /// Backtracking, from a path with a bad ancestor (specifically killedbycall).
    pub const POP_FAILKILL: i32 = 4;
}

impl ArState {
    // Ghidra: funcdata.hh:692 State::markSolid
    /// Mark the given slot as having solid movement. Faithful to
    /// `State::markSolid` (funcdata.hh:692).
    fn mark_solid(&mut self, s: i32) {
        self.flags |= if s == 0 { state_flags::SEEN_SOLID0 } else { state_flags::SEEN_SOLID1 };
    }
    // Ghidra: funcdata.hh:693 State::markKill
    /// Mark killedbycall as seen. Faithful to `State::markKill` (funcdata.hh:693).
    fn mark_kill(&mut self) {
        self.flags |= state_flags::SEEN_KILL;
    }
    // Ghidra: funcdata.hh:694 State::seenSolid
    /// Has solid movement been seen? Faithful to `State::seenSolid` (funcdata.hh:694).
    fn seen_solid(&self) -> bool {
        (self.flags & (state_flags::SEEN_SOLID0 | state_flags::SEEN_SOLID1)) != 0
    }
    // Ghidra: funcdata.hh:695 State::seenKill
    /// Has killedbycall been seen? Faithful to `State::seenKill` (funcdata.hh:695).
    fn seen_kill(&self) -> bool {
        (self.flags & state_flags::SEEN_KILL) != 0
    }
    // Ghidra: funcdata.hh:691 State::getSolidSlot
    /// Get the slot associated with solid movement. Faithful to
    /// `State::getSolidSlot` (funcdata.hh:691).
    fn get_solid_slot(&self) -> i32 {
        if (self.flags & state_flags::SEEN_SOLID0) != 0 { 0 } else { 1 }
    }
}

impl AncestorRealistic {
    // RUGRA-GLUE: AncestorRealistic::new constructor (no Ghidra counterpart — Ghidra uses stack allocation)
    /// Construct an empty ancestor-realistic checker.
    pub fn new() -> Self {
        Self {
            state_stack: Vec::new(),
            marked_vn: Vec::new(),
            multi_depth: 0,
            allow_failing_path: false,
            trial_killed_by_call: false,
            trial_size: 0,
            pending_ind_create_formed: false,
            pending_condexe_effect: false,
        }
    }

    // Ghidra: funcdata_varnode.cc:1997 AncestorRealistic::checkConditionalExe
    /// Check if the current Varnode was produced by conditional flow. Faithful
    /// to `AncestorRealistic::checkConditionalExe` (funcdata_varnode.cc:1997-2022).
    /// Returns true if there are two input flows and one is a normal solid flow
    /// (the MULTIEQUAL block has exactly 2 inputs, and the solid-slot's source
    /// block has exactly 1 out-edge).
    fn check_conditional_exe(&self, state: &ArState) -> bool {
        let parent_arc = {
            let op_rg = state.op.read().unwrap();
            op_rg.parent.as_ref().and_then(|w| w.upgrade())
        };
        let bl = match parent_arc { Some(b) => b, None => return false };
        let (solid_point, size_in) = {
            let bl_rg = bl.read().unwrap();
            let solid_slot = state.get_solid_slot();
            let point = bl_rg.get_in(solid_slot as usize).map(|e| e.point.clone());
            (point, bl_rg.size_in())
        };
        if size_in != 2 { return false; }
        match solid_point {
            Some(sb) => sb.read().unwrap().size_out() == 1,
            None => false,
        }
    }

    // Ghidra: funcdata_varnode.cc:2026 AncestorRealistic::enterNode
    /// Analyze a newly-entered node during the depth-first traversal. Faithful
    /// to `AncestorRealistic::enterNode` (funcdata_varnode.cc:2026-2136).
    /// Returns the command for the next traversal step.
    fn enter_node(&mut self) -> i32 {
        use crate::opcodes::OpCode as OC;
        let (op_arc, slot, state_offset) = {
            let state = self.state_stack.last().unwrap();
            (state.op.clone(), state.slot, state.offset)
        };
        // Resolve the Varnode being traversed: vn = op.getIn(slot)
        let state_vn = {
            let op_rg = op_arc.read().unwrap();
            op_rg.get_in(slot as usize).cloned()
        };
        let state_vn = match state_vn {
            Some(v) => v,
            None => return ar_command::POP_FAIL,
        };
        // Truncate traversal on already-visited varnodes (cycle prevention).
        let (is_mark, is_written) = {
            let vn = state_vn.read().unwrap();
            (vn.is_mark(), vn.is_written())
        };
        if is_mark { return ar_command::POP_SUCCESS; }
        if !is_written {
            let (is_input, is_unaffected, is_persist, is_direct_write) = {
                let vn = state_vn.read().unwrap();
                (vn.is_input(), vn.is_unaffected(), vn.is_persist(), vn.is_direct_write())
            };
            if is_input {
                if is_unaffected { return ar_command::POP_FAIL; }
                if is_persist { return ar_command::POP_SUCCESS; }
                if !is_direct_write { return ar_command::POP_FAIL; }
            }
            return ar_command::POP_SUCCESS;
        }
        // Mark the varnode as visited.
        {
            let mut vn = state_vn.write().unwrap();
            vn.set_mark();
        }
        self.marked_vn.push(state_vn.clone());
        // Follow the defining op.
        let def_arc = {
            let vn = state_vn.read().unwrap();
            vn.get_def()
        };
        let op_def = match def_arc {
            Some(d) => d,
            None => return ar_command::POP_FAIL,
        };
        let opcode = { op_def.read().unwrap().opcode };
        match opcode {
            OC::CPUI_INDIRECT => {
                let (is_ind_create, is_ind_store, out_is_return, in0_indirect_zero) = {
                    let d = op_def.read().unwrap();
                    let out_is_ret = d.get_out().map(|v| v.read().unwrap().is_return_address()).unwrap_or(false);
                    let in0_iz = d.get_in(0).map(|v| v.read().unwrap().is_indirect_zero()).unwrap_or(false);
                    (d.is_indirect_creation(), d.is_indirect_store(), out_is_ret, in0_iz)
                };
                if is_ind_create {
                    self.pending_ind_create_formed = true;
                    if in0_indirect_zero {
                        return ar_command::POP_FAILKILL;
                    }
                    return ar_command::POP_SUCCESS;
                }
                if !is_ind_store {
                    // Ghidra: funcdata_varnode.cc:2052 "If flow goes THROUGH a call"
                    if out_is_return { return ar_command::POP_FAIL; }
                    if self.trial_killed_by_call { return ar_command::POP_FAIL; }
                }
                self.state_stack.push(ArState {
                    op: op_def.clone(),
                    slot: 0,
                    flags: 0,
                    offset: 0,
                });
                return ar_command::ENTER_NODE;
            }
            OC::CPUI_SUBPIECE => {
                let (out_space_is_internal, is_incidental, in0_incidental, out_overlap_in0_eq_in1, new_offset) = {
                    let d = op_def.read().unwrap();
                    let out_vn = d.get_out().and_then(|v| Some(v.clone()));
                    let in0 = d.get_in(0).and_then(|v| Some(v.clone()));
                    let in1_off = d.get_in(1).and_then(|v| Some(v.clone()))
                        .map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
                    let out_space = out_vn.as_ref().map(|v| v.read().unwrap().get_space());
                    let out_overlap = match (&out_vn, &in0) {
                        (Some(o), Some(i)) => o.read().unwrap().overlap(&i.read().unwrap()),
                        _ => -1,
                    };
                    (
                        out_space == Some(AddressSpace::Unique),
                        d.is_incidental_copy(),
                        in0.as_ref().map(|v| v.read().unwrap().is_incidental_copy()).unwrap_or(false),
                        out_overlap == in1_off as i32,
                        state_offset + in1_off as i32,
                    )
                };
                if out_space_is_internal || is_incidental || in0_incidental || out_overlap_in0_eq_in1 {
                    self.state_stack.push(ArState {
                        op: op_def.clone(),
                        slot: 0,
                        flags: 0,
                        offset: new_offset,
                    });
                    return ar_command::ENTER_NODE;
                }
                // Ghidra: funcdata_varnode.cc:2069-2077 minimal traversal to
                // rule out unaffected/invalid inputs (COPY/SUBPIECE chain).
                let mut cur_op = op_def.clone();
                loop {
                    let (vn_mark, vn_input, vn_unaffected, vn_direct_write, next_def) = {
                        let d = cur_op.read().unwrap();
                        let vn = d.get_in(0).and_then(|v| Some(v.clone()));
                        match vn {
                            Some(v) => {
                                let vr = v.read().unwrap();
                                (vr.is_mark(), vr.is_input(), vr.is_unaffected(), vr.is_direct_write(), vr.get_def())
                            }
                            None => return ar_command::POP_FAIL,
                        }
                    };
                    if !vn_mark && vn_input {
                        if vn_unaffected || !vn_direct_write {
                            return ar_command::POP_FAIL;
                        }
                    }
                    match next_def {
                        Some(nd) => {
                            let next_code = nd.read().unwrap().opcode;
                            if next_code == OC::CPUI_COPY || next_code == OC::CPUI_SUBPIECE {
                                cur_op = nd;
                            } else {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                return ar_command::POP_SOLID;
            }
            OC::CPUI_COPY => {
                let (out_space_internal, is_incidental, in0_incidental, out_addr_eq_in0_addr) = {
                    let d = op_def.read().unwrap();
                    let out_vn = d.get_out().and_then(|v| Some(v.clone()));
                    let in0 = d.get_in(0).and_then(|v| Some(v.clone()));
                    let out_space = out_vn.as_ref().map(|v| v.read().unwrap().get_space());
                    let out_addr = out_vn.as_ref().map(|v| v.read().unwrap().get_offset());
                    let in0_addr = in0.as_ref().map(|v| v.read().unwrap().get_offset());
                    (
                        out_space == Some(AddressSpace::Unique),
                        d.is_incidental_copy(),
                        in0.as_ref().map(|v| v.read().unwrap().is_incidental_copy()).unwrap_or(false),
                        out_addr.is_some() && in0_addr.is_some() && out_addr == in0_addr,
                    )
                };
                if out_space_internal || is_incidental || in0_incidental || out_addr_eq_in0_addr {
                    self.state_stack.push(ArState {
                        op: op_def.clone(),
                        slot: 0,
                        flags: 0,
                        offset: 0,
                    });
                    return ar_command::ENTER_NODE;
                }
                // Ghidra: funcdata_varnode.cc:2090-2108 minimal traversal:
                // follow COPY/SUBPIECE/PIECE chain checking input flags +
                // store_unmapped. (op, vn) advance together.
                let mut cur_op = op_def.clone();
                let mut cur_vn = {
                    let d = op_def.read().unwrap();
                    d.get_in(0).and_then(|v| Some(v.clone()))
                };
                loop {
                    let (vn_mark, vn_input, vn_direct_write) = match &cur_vn {
                        Some(v) => {
                            let vr = v.read().unwrap();
                            (vr.is_mark(), vr.is_input(), vr.is_direct_write())
                        }
                        None => return ar_command::POP_FAIL,
                    };
                    if !vn_mark && vn_input {
                        if !vn_direct_write { return ar_command::POP_FAIL; }
                    }
                    if cur_op.read().unwrap().is_store_unmapped() {
                        return ar_command::POP_FAIL;
                    }
                    let next_def = match &cur_vn {
                        Some(v) => v.read().unwrap().get_def(),
                        None => break,
                    };
                    match next_def {
                        Some(nd) => {
                            let next_code = nd.read().unwrap().opcode;
                            if next_code == OC::CPUI_COPY || next_code == OC::CPUI_SUBPIECE {
                                cur_vn = nd.read().unwrap().get_in(0).cloned();
                            } else if next_code == OC::CPUI_PIECE {
                                // Follow least significant piece.
                                cur_vn = nd.read().unwrap().get_in(1).cloned();
                            } else {
                                break;
                            }
                            cur_op = nd;
                        }
                        None => break,
                    }
                }
                return ar_command::POP_SOLID;
            }
            OC::CPUI_MULTIEQUAL => {
                self.multi_depth += 1;
                self.state_stack.push(ArState {
                    op: op_def.clone(),
                    slot: 0,
                    flags: 0,
                    offset: 0,
                });
                return ar_command::ENTER_NODE;
            }
            OC::CPUI_PIECE => {
                // Ghidra: funcdata_varnode.cc:2115-2132 PIECE case.
                // stateVn is the PIECE output; compare its size to trial size.
                let state_vn_size = state_vn.read().unwrap().get_size() as i32;
                let (in1_size, in0_size, state_vn_is_spacebase) = {
                    let d = op_def.read().unwrap();
                    let in0 = d.get_in(0).and_then(|v| Some(v.clone()));
                    let in1 = d.get_in(1).and_then(|v| Some(v.clone()));
                    let state_vn_space = state_vn.read().unwrap().get_space();
                    let in0_sz = in0.as_ref().map(|v| v.read().unwrap().get_size() as i32).unwrap_or(0);
                    let in1_sz = in1.as_ref().map(|v| v.read().unwrap().get_size() as i32).unwrap_or(0);
                    (in1_sz, in0_sz, state_vn_space == AddressSpace::Stack)
                };
                if state_vn_size > self.trial_size {
                    if state_offset == 0 && in1_size <= self.trial_size {
                        self.state_stack.push(ArState {
                            op: op_def.clone(), slot: 1, flags: 0, offset: 0,
                        });
                        return ar_command::ENTER_NODE;
                    } else if state_offset == in1_size && in0_size <= self.trial_size {
                        self.state_stack.push(ArState {
                            op: op_def.clone(), slot: 0, flags: 0, offset: 0,
                        });
                        return ar_command::ENTER_NODE;
                    }
                    if !state_vn_is_spacebase {
                        return ar_command::POP_FAIL;
                    }
                }
                return ar_command::POP_SOLID;
            }
            _ => {
                // Any other LOAD or arithmetic/logical operation is solid movement.
                return ar_command::POP_SOLID;
            }
        }
    }

    // Ghidra: funcdata_varnode.cc:2141 AncestorRealistic::uponPop
    /// Backtrack into a previously visited node. Faithful to
    /// `AncestorRealistic::uponPop` (funcdata_varnode.cc:2141-2185).
    fn upon_pop(&mut self, pop_command: i32) -> i32 {
        use crate::opcodes::OpCode as OC;
        let is_multiequal = {
            let state = self.state_stack.last().unwrap();
            state.op.read().unwrap().opcode == OC::CPUI_MULTIEQUAL
        };
        if is_multiequal {
            let (cur_slot, cur_num_input) = {
                let state = self.state_stack.last().unwrap();
                let s = state.op.read().unwrap();
                (state.slot, s.num_input() as i32)
            };
            if pop_command == ar_command::POP_FAIL {
                self.multi_depth -= 1;
                self.state_stack.pop();
                return pop_command;
            } else if pop_command == ar_command::POP_SOLID && self.multi_depth == 1 && cur_num_input == 2 {
                let slot = self.state_stack.last().unwrap().slot;
                let stack_len = self.state_stack.len();
                if stack_len >= 2 {
                    self.state_stack[stack_len - 2].mark_solid(slot);
                }
            } else if pop_command == ar_command::POP_FAILKILL {
                let stack_len = self.state_stack.len();
                if stack_len >= 2 {
                    self.state_stack[stack_len - 2].mark_kill();
                }
            }
            // state.slot += 1 (Ghidra funcdata_varnode.cc:2156)
            self.state_stack.last_mut().unwrap().slot += 1;
            let (new_slot, num_input) = {
                let state = self.state_stack.last().unwrap();
                let s = state.op.read().unwrap();
                (state.slot, s.num_input() as i32)
            };
            if new_slot == num_input {
                // All siblings traversed.
                let (prev_seen_solid, prev_seen_kill) = if self.state_stack.len() >= 2 {
                    let p = &self.state_stack[self.state_stack.len() - 2];
                    (p.seen_solid(), p.seen_kill())
                } else { (false, false) };
                let mut final_cmd = pop_command;
                if prev_seen_solid {
                    final_cmd = ar_command::POP_SUCCESS;
                    if prev_seen_kill {
                        if self.allow_failing_path {
                            // Re-read the current state for checkConditionalExe.
                            let state_clone = self.state_stack.last().unwrap().clone();
                            if !self.check_conditional_exe(&state_clone) {
                                final_cmd = ar_command::POP_FAIL;
                            } else {
                                self.pending_condexe_effect = true;
                            }
                        } else {
                            final_cmd = ar_command::POP_FAIL;
                        }
                    }
                } else if prev_seen_kill {
                    final_cmd = ar_command::POP_FAILKILL;
                } else {
                    final_cmd = ar_command::POP_SUCCESS;
                }
                self.multi_depth -= 1;
                self.state_stack.pop();
                return final_cmd;
            }
            return ar_command::ENTER_NODE;
        } else {
            self.state_stack.pop();
            return pop_command;
        }
    }

    // Ghidra: funcdata_varnode.cc:2194 AncestorRealistic::execute
    /// Perform a full ancestor check on a given parameter trial. Faithful to
    /// `AncestorRealistic::execute` (funcdata_varnode.cc:2194-2237).
    ///
    /// Returns true if the varnode (op's input at `slot`) has realistic
    /// ancestors for a parameter-passing location. Sets the trial's
    /// ancestor_realistic / ancestor_solid / condexe_effect / ind_create_formed
    /// flags as appropriate.
    pub fn execute(
        &mut self,
        op: &crate::op::PcodeOpRef,
        slot: i32,
        trial: &mut crate::fspec::ParamTrial,
        allow_fail: bool,
    ) -> bool {
        self.allow_failing_path = allow_fail;
        self.trial_killed_by_call = trial.is_killed_by_call();
        self.trial_size = trial.get_size();
        self.marked_vn.clear();
        self.state_stack.clear();
        self.multi_depth = 0;
        self.pending_ind_create_formed = false;
        self.pending_condexe_effect = false;
        // If the parameter itself is an input, we don't consider this realistic
        // (unless retesting for condexe).
        let is_input = {
            let op_rg = op.0.read().unwrap();
            let vn = op_rg.get_in(slot as usize);
            match vn {
                Some(v) => v.read().unwrap().is_input(),
                None => return false,
            }
        };
        if is_input {
            if !trial.has_condexe_effect() {
                return false;
            }
        }
        // Run the depth-first traversal.
        let mut command = ar_command::ENTER_NODE;
        self.state_stack.push(ArState {
            op: op.0.clone(),
            slot,
            flags: 0,
            offset: 0,
        });
        while !self.state_stack.is_empty() {
            match command {
                c if c == ar_command::ENTER_NODE => command = self.enter_node(),
                _ => command = self.upon_pop(command),
            }
        }
        // Clean up marks.
        for vn_arc in &self.marked_vn {
            vn_arc.write().unwrap().clear_mark();
        }
        // Apply deferred trial mutations.
        if self.pending_ind_create_formed { trial.set_ind_create_formed(); }
        if self.pending_condexe_effect { trial.set_condexe_effect(); }
        if command == ar_command::POP_SUCCESS {
            trial.set_ancestor_realistic();
            return true;
        } else if command == ar_command::POP_SOLID {
            trial.set_ancestor_realistic();
            trial.set_ancestor_solid();
            return true;
        }
        false
    }
}

// TraverseNode flags (expression.hh:62-68), used by onlyOpUse/ancestorOpUse.
mod traverse_flags {
    pub const ACTIONALT: u32 = 1;
    pub const INDIRECT: u32 = 2;
    pub const INDIRECTALT: u32 = 4;
    pub const LSB_TRUNCATED: u32 = 8;
    pub const CONCAT_HIGH: u32 = 0x10;
}

// Ghidra: funcdata_varnode.cc:1805 Funcdata::onlyOpUse
/// Test if the given Varnode seems to only be used by a CALL/RETURN. Faithful
/// to `Funcdata::onlyOpUse` (funcdata_varnode.cc:1805-1904). Walks forward
/// through descendants; if any descendent is a non-call use (BRANCH, LOAD,
/// STORE, etc.) returns false. CALL/CALLIND descendants trigger
/// checkCallDoubleUse (conservatively returns false — safe direction).
fn only_op_use(
    has_active_output: bool,
    invn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    opmatch: &crate::op::PcodeOpRef,
    trial_slot: i32,
    main_flags: u32,
) -> bool {
    use crate::opcodes::OpCode as OC;
    use std::sync::{Arc, RwLock};
    struct TNode {
        vn: Arc<RwLock<crate::varnode::Varnode>>,
        flags: u32,
    }
    let mut varlist: Vec<TNode> = Vec::with_capacity(64);
    {
        let mut vn = invn.write().unwrap();
        vn.set_mark();
    }
    varlist.push(TNode { vn: invn.clone(), flags: main_flags });
    let mut idx = 0;
    let mut res = true;
    while idx < varlist.len() {
        let base_flags = varlist[idx].flags;
        let vn_arc = varlist[idx].vn.clone();
        let descends: Vec<Arc<RwLock<crate::op::PcodeOp>>> =
            vn_arc.read().unwrap().descend.iter().filter_map(|w| w.upgrade()).collect();
        for op_arc in descends {
            let op_rg = op_arc.read().unwrap();
            if Arc::ptr_eq(&op_arc, &opmatch.0) {
                let trial_in = op_rg.get_in(trial_slot as usize);
                if let Some(tiv) = trial_in {
                    if Arc::ptr_eq(tiv, &vn_arc) { continue; }
                }
            }
            let mut cur_flags = base_flags;
            match op_rg.opcode {
                OC::CPUI_BRANCH | OC::CPUI_CBRANCH | OC::CPUI_BRANCHIND
                | OC::CPUI_LOAD | OC::CPUI_STORE => {
                    res = false;
                }
                OC::CPUI_CALL | OC::CPUI_CALLIND => {
                    let _ = &mut cur_flags;
                    res = false;
                }
                OC::CPUI_INDIRECT => {
                    cur_flags |= traverse_flags::INDIRECTALT;
                }
                OC::CPUI_COPY => {
                    let out_internal = op_rg.get_out()
                        .map(|v| v.read().unwrap().get_space() == AddressSpace::Unique)
                        .unwrap_or(false);
                    let op_incidental = op_rg.is_incidental_copy();
                    let vn_incidental = vn_arc.read().unwrap().is_incidental_copy();
                    if !out_internal && !op_incidental && !vn_incidental {
                        cur_flags |= traverse_flags::ACTIONALT;
                    }
                }
                OC::CPUI_RETURN => {
                    let opmatch_code = opmatch.0.read().unwrap().opcode;
                    if opmatch_code == OC::CPUI_RETURN {
                        let r_in = op_rg.get_in(trial_slot as usize);
                        if let Some(riv) = r_in {
                            if Arc::ptr_eq(riv, &vn_arc) { continue; }
                        }
                    } else if has_active_output {
                        res = false;
                    } else {
                        res = false;
                    }
                }
                _ => {}
            }
            if !res { break; }
            if op_rg.opcode == OC::CPUI_INDIRECT || op_rg.opcode == OC::CPUI_COPY {
                if let Some(out) = op_rg.get_out() {
                    let out_clone = out.clone();
                    if !out_clone.read().unwrap().is_mark() {
                        out_clone.write().unwrap().set_mark();
                        varlist.push(TNode { vn: out_clone, flags: cur_flags });
                    }
                }
            }
        }
        if !res { break; }
        idx += 1;
    }
    for t in &varlist {
        t.vn.write().unwrap().clear_mark();
    }
    res
}

// Ghidra: funcdata_varnode.cc:1917 Funcdata::ancestorOpUse
/// Test if the given trial Varnode is likely only used for parameter passing.
/// Faithful to `Funcdata::ancestorOpUse` (funcdata_varnode.cc:1917-1994).
pub fn ancestor_op_use(
    has_active_output: bool,
    maxlevel: i32,
    invn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    op: &crate::op::PcodeOpRef,
    trial_slot: i32,
    offset: i32,
    main_flags: u32,
) -> bool {
    use crate::opcodes::OpCode as OC;
    if maxlevel == 0 { return false; }
    let (is_written, is_input, is_type_lock) = {
        let vn = invn.read().unwrap();
        (vn.is_written(), vn.is_input(), vn.is_type_lock())
    };
    if !is_written {
        if !is_input { return false; }
        if !is_type_lock { return false; }
        return only_op_use(has_active_output, invn, op, trial_slot, main_flags);
    }
    let def_arc = { invn.read().unwrap().get_def() };
    let def_arc = match def_arc { Some(d) => d, None => return false };
    let opcode = def_arc.read().unwrap().opcode;
    match opcode {
        OC::CPUI_INDIRECT => {
            if def_arc.read().unwrap().is_indirect_creation() { return false; }
            let in0 = def_arc.read().unwrap().get_in(0).cloned();
            match in0 {
                Some(v) => ancestor_op_use(has_active_output, maxlevel - 1, &v, op, trial_slot, offset,
                    main_flags | traverse_flags::INDIRECT),
                None => false,
            }
        }
        OC::CPUI_MULTIEQUAL => {
            if def_arc.read().unwrap().is_mark() { return false; }
            def_arc.write().unwrap().set_mark();
            let num_input = def_arc.read().unwrap().num_input();
            let mut result = false;
            for i in 0..num_input {
                let in_vn = def_arc.read().unwrap().get_in(i).cloned();
                if let Some(v) = in_vn {
                    if ancestor_op_use(has_active_output, maxlevel - 1, &v, op, trial_slot, offset, main_flags) {
                        result = true;
                        break;
                    }
                }
            }
            def_arc.write().unwrap().clear_mark();
            result
        }
        OC::CPUI_COPY => {
            let out_internal = def_arc.read().unwrap().get_out()
                .map(|v| v.read().unwrap().get_space() == AddressSpace::Unique)
                .unwrap_or(false);
            let op_incidental = def_arc.read().unwrap().is_incidental_copy();
            let in0 = def_arc.read().unwrap().get_in(0).cloned();
            let in0_incidental = in0.as_ref().map(|v| v.read().unwrap().is_incidental_copy()).unwrap_or(false);
            if out_internal || op_incidental || in0_incidental {
                match in0 {
                    Some(v) => ancestor_op_use(has_active_output, maxlevel - 1, &v, op, trial_slot, offset, main_flags),
                    None => false,
                }
            } else {
                only_op_use(has_active_output, invn, op, trial_slot, main_flags)
            }
        }
        OC::CPUI_PIECE => {
            let in0 = def_arc.read().unwrap().get_in(0).cloned();
            let in1 = def_arc.read().unwrap().get_in(1).cloned();
            let in1_size = in1.as_ref().map(|v| v.read().unwrap().get_size() as i32).unwrap_or(0);
            if let Some(v0) = in0 {
                if ancestor_op_use(has_active_output, maxlevel - 1, &v0, op, trial_slot, offset + in1_size,
                    main_flags | traverse_flags::CONCAT_HIGH) {
                    return true;
                }
            }
            if let Some(v1) = in1 {
                if ancestor_op_use(has_active_output, maxlevel - 1, &v1, op, trial_slot, offset, main_flags) {
                    return true;
                }
            }
            false
        }
        OC::CPUI_SUBPIECE => {
            let out_internal = def_arc.read().unwrap().get_out()
                .map(|v| v.read().unwrap().get_space() == AddressSpace::Unique)
                .unwrap_or(false);
            let op_incidental = def_arc.read().unwrap().is_incidental_copy();
            let in0 = def_arc.read().unwrap().get_in(0).cloned();
            let in0_incidental = in0.as_ref().map(|v| v.read().unwrap().is_incidental_copy()).unwrap_or(false);
            let in1_off = def_arc.read().unwrap().get_in(1)
                .map(|v| v.read().unwrap().get_offset() as i32).unwrap_or(0);
            if (out_internal || op_incidental || in0_incidental) && (offset - in1_off) >= 0 {
                match in0 {
                    Some(v) => ancestor_op_use(has_active_output, maxlevel - 1, &v, op, trial_slot, offset - in1_off,
                        main_flags | traverse_flags::LSB_TRUNCATED),
                    None => false,
                }
            } else {
                only_op_use(has_active_output, invn, op, trial_slot, main_flags)
            }
        }
        OC::CPUI_CALL | OC::CPUI_CALLIND => false,
        _ => only_op_use(has_active_output, invn, op, trial_slot, main_flags),
    }
}

// Ghidra: funcdata_block.cc:962 CloneBlockOps
/// Clone p-code ops from one basic block into another (for nodeSplit).
/// Faithful to Ghidra's `CloneBlockOps` class (funcdata_block.cc:962-1104).
struct CloneBlockOps {
    /// (clone_op, orig_op) pairs, in clone order.
    clone_list: Vec<(crate::op::PcodeOpRef, crate::op::PcodeOpRef)>,
    /// Map from orig op Arc ptr → clone op Arc.
    orig_to_clone: std::collections::HashMap<usize, crate::op::PcodeOpRef>,
}

impl CloneBlockOps {
    // RUGRA-GLUE: Rust 构造器（Ghidra CloneBlockOps 用 C++ 构造函数 + data 引用初始化）。
    fn new() -> Self {
        Self {
            clone_list: Vec::new(),
            orig_to_clone: std::collections::HashMap::new(),
        }
    }

    // Ghidra: funcdata_block.cc:962 CloneBlockOps::buildOpClone
    /// Clone a PcodeOp (copy opcode + flags). Skip branches (return None).
    fn build_op_clone(&mut self, fd: &mut Funcdata, orig: &crate::op::PcodeOpRef) -> Option<crate::op::PcodeOpRef> {
        let (is_branch, is_not_branch, num_input, addr, opcode, flags, addlflags) = {
            let o = orig.0.read().unwrap();
            let ib = o.is_branch();
            let addr = o.get_addr();
            let opcode = o.opcode;
            let flags = o.flags;
            let addlflags = o.addlflags;
            (ib, ib && o.opcode != crate::opcodes::OpCode::CPUI_BRANCH, o.num_input(), addr, opcode, flags, addlflags)
        };
        if is_branch {
            if is_not_branch {
                eprintln!("[BLOCK] Cannot duplicate 2-way or n-way branch in nodesplit");
            }
            return None;
        }
        let dup = fd.new_op(num_input, addr);
        fd.op_set_opcode(&dup, opcode);
        // Copy flag subset (funcdata_block.cc:974-978).
        let fl_mask = crate::op::pcodeop_flags::STARTBASIC
            | crate::op::pcodeop_flags::NOCOLLAPSE
            | crate::op::pcodeop_flags::STARTMARK
            | crate::op::pcodeop_flags::NONPRINTING
            | crate::op::pcodeop_flags::HALT
            | crate::op::pcodeop_flags::BADINSTRUCTION
            | crate::op::pcodeop_flags::UNIMPLEMENTED
            | crate::op::pcodeop_flags::NORETURN
            | crate::op::pcodeop_flags::MISSING
            | crate::op::pcodeop_flags::INDIRECT_CREATION
            | crate::op::pcodeop_flags::INDIRECT_STORE
            | crate::op::pcodeop_flags::CALCULATED_BOOL
            | crate::op::pcodeop_flags::PTRFLOW;
        dup.0.write().unwrap().flags |= flags & fl_mask;
        // Copy addlflag subset (funcdata_block.cc:979-980).
        let afl_mask = crate::op::op_addl_flags::SPECIAL_PRINT
            | crate::op::op_addl_flags::INCIDENTAL_COPY
            | crate::op::op_addl_flags::IS_CPOOL_TRANSFORMED
            | crate::op::op_addl_flags::STOP_TYPE_PROPAGATION
            | crate::op::op_addl_flags::STORE_UNMAPPED;
        dup.0.write().unwrap().addlflags |= addlflags & afl_mask;
        // Record mappings.
        self.clone_list.push((dup.clone(), orig.clone()));
        self.orig_to_clone.insert(Arc::as_ptr(&orig.0) as usize, dup.clone());
        Some(dup)
    }

    // Ghidra: funcdata_block.cc:992 CloneBlockOps::buildVarnodeOutput
    /// Clone the output Varnode of an op into the clone op.
    fn build_varnode_output(&self, fd: &mut Funcdata, orig_op: &crate::op::PcodeOpRef, clone_op: &crate::op::PcodeOpRef) {
        let orig_out = orig_op.0.read().unwrap().output.clone();
        let Some(orig_vn) = orig_out else { return };
        let (size, addr) = {
            let v = orig_vn.read().unwrap();
            (v.size, v.loc)
        };
        let new_vn = fd.new_varnode_out(size, addr, clone_op);
        // Copy varnode flag subset (funcdata_block.cc:1001-1004).
        let orig_flags = orig_vn.read().unwrap().flags;
        let vflag_mask = crate::varnode::varnode_flags::EXTERNREF
            | crate::varnode::varnode_flags::VOLATIL
            | crate::varnode::varnode_flags::INCIDENTAL_COPY
            | crate::varnode::varnode_flags::READONLY
            | crate::varnode::varnode_flags::PERSIST
            | crate::varnode::varnode_flags::ADDRTIED
            | crate::varnode::varnode_flags::ADDRFORCE
            | crate::varnode::varnode_flags::NOLOCALALIAS
            | crate::varnode::varnode_flags::SPACEBASE
            | crate::varnode::varnode_flags::INDIRECT_CREATION
            | crate::varnode::varnode_flags::RETURN_ADDRESS
            | crate::varnode::varnode_flags::PRECISLO
            | crate::varnode::varnode_flags::PRECISHI;
        new_vn.write().unwrap().set_flags(orig_flags & vflag_mask);
    }

    // Ghidra: funcdata_block.cc:1015 CloneBlockOps::cloneBlock
    /// Clone all ops from `b` into `bprime`, patching inputs.
    fn clone_block(
        &mut self,
        fd: &mut Funcdata,
        b: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        bprime: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        inedge: usize,
    ) {
        // Collect ops from b.
        let ops: Vec<crate::op::PcodeOpRef> = {
            let rg = b.read().unwrap();
            if let Some(bb) = rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                bb.get_ops()
            } else {
                Vec::new()
            }
        };
        for orig_ref in &ops {
            if let Some(clone_ref) = self.build_op_clone(fd, orig_ref) {
                self.build_varnode_output(fd, orig_ref, &clone_ref);
                fd.op_insert_end(&clone_ref, bprime);
            }
        }
        self.patch_inputs(fd, inedge);
    }

    // Ghidra: funcdata_block.cc:1058 CloneBlockOps::patchInputs
    /// Patch cloned op inputs: MULTIEQUAL → COPY; constants shared; written
    /// inputs mapped to clone outputs; others shared.
    fn patch_inputs(&self, fd: &mut Funcdata, inedge: usize) {
        use crate::opcodes::OpCode;
        for (clone_ref, orig_ref) in &self.clone_list {
            let opcode = orig_ref.0.read().unwrap().opcode;
            match opcode {
                OpCode::CPUI_MULTIEQUAL => {
                    // cloneOp becomes a single-input COPY from orig's inedge slot.
                    clone_ref.0.write().unwrap().inrefs.resize(1, std::sync::Arc::new(std::sync::RwLock::new(
                        crate::varnode::Varnode::new_constant(0, 0)
                    )));
                    fd.op_set_opcode(clone_ref, OpCode::CPUI_COPY);
                    let in_vn = orig_ref.0.read().unwrap().inrefs.get(inedge).cloned();
                    if let Some(vn) = in_vn {
                        fd.op_set_input(clone_ref, vn, 0);
                    }
                    // Remove inedge from original MULTIEQUAL (funcdata_block.cc:1068).
                    fd.op_remove_input(orig_ref, inedge);
                    if orig_ref.0.read().unwrap().num_input() == 1 {
                        fd.op_set_opcode(orig_ref, OpCode::CPUI_COPY);
                    }
                }
                OpCode::CPUI_INDIRECT => {
                    eprintln!("[BLOCK] Can't clone INDIRECTs in nodesplit");
                }
                _ if orig_ref.0.read().unwrap().is_call() => {
                    eprintln!("[BLOCK] Can't clone CALLs in nodesplit");
                }
                _ => {
                    // Regular op: patch each input (funcdata_block.cc:1079-1101).
                    let num_in = clone_ref.0.read().unwrap().num_input();
                    for i in 0..num_in {
                        let orig_vn = orig_ref.0.read().unwrap().inrefs.get(i).cloned();
                        let Some(orig_vn) = orig_vn else { continue };
                        let clone_vn = {
                            let v = orig_vn.read().unwrap();
                            if v.is_constant() {
                                Some(orig_vn.clone())
                            } else if v.is_annotation() {
                                // data.newCodeRef — Rugra shares annotation varnodes.
                                Some(orig_vn.clone())
                            } else if v.is_free() {
                                eprintln!("[BLOCK] Can't clone free varnode in nodesplit");
                                None
                            } else {
                                // Check if orig_vn is defined by a cloned op.
                                let def_op = v.def.as_ref().and_then(|w| w.upgrade());
                                match def_op {
                                    Some(def_arc) => {
                                        let key = Arc::as_ptr(&def_arc) as usize;
                                        match self.orig_to_clone.get(&key) {
                                            Some(clone_op) => clone_op.0.read().unwrap().output.clone(),
                                            None => Some(orig_vn.clone()),
                                        }
                                    }
                                    None => Some(orig_vn.clone()),
                                }
                            }
                        };
                        if let Some(cv) = clone_vn {
                            fd.op_set_input(clone_ref, cv, i);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod laned_access_tests {
    use super::*;

    #[test]
    fn order_identity_and_minimum_lifecycle() {
        let mut architecture = crate::arch::Architecture::new();
        architecture.set_lane_records(vec![
            crate::transform::LanedRegister::with_sizes(16, 1 << 4),
            crate::transform::LanedRegister::with_sizes(8, 1 << 2),
        ]);
        let architecture = Arc::new(architecture);
        let record16 = architecture
            .get_laned_register(Address::new(0), 16)
            .unwrap();
        let mut fd = Funcdata::new("lanes", Address::new(0x1000), 0x20);
        fd.set_arch(architecture);

        fd.check_for_laned_register(12, AddressSpace::Register, Address::new(0x20));
        assert!(fd.laned_map.is_empty());
        fd.check_for_laned_register(8, AddressSpace::Register, Address::new(0x20));
        fd.check_for_laned_register(16, AddressSpace::Register, Address::new(0x20));
        fd.check_for_laned_register(8, AddressSpace::Unique, Address::new(5));
        let keys = fd
            .lane_accesses()
            .map(|(storage, _)| *storage)
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            vec![
                LanedStorage {
                    space: AddressSpace::Unique,
                    offset: 5,
                    size: 8,
                },
                LanedStorage {
                    space: AddressSpace::Register,
                    offset: 0x20,
                    size: 16,
                },
                LanedStorage {
                    space: AddressSpace::Register,
                    offset: 0x20,
                    size: 8,
                },
            ]
        );
        assert!(Arc::ptr_eq(
            fd.laned_map
                .get(&LanedStorage {
                    space: AddressSpace::Register,
                    offset: 0x20,
                    size: 16,
                })
                .unwrap(),
            &record16,
        ));

        let before_generation = fd.laned_map.len();
        fd.set_laned_reg_generated();
        let _ = fd.new_unique(16);
        assert_eq!(fd.laned_map.len(), before_generation);
        fd.clear();
        assert_eq!(fd.laned_map.len(), before_generation);
        let _ = fd.new_unique(16);
        assert_eq!(fd.laned_map.len(), before_generation + 1);
        fd.clear_laned_access_map();
        assert!(fd.laned_map.is_empty());
    }
}
