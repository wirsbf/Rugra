//! Ghidra varmap.cc port: local variable mapping and stack frame restructuring.
//!
//! Corresponds to Ghidra's `varmap.hh` / `varmap.cc` (1620 lines).
//!
//! Key classes ported:
//! - `RangeHint`: a typed range on the stack, used for variable layout
//! - `AliasChecker`: analyzes pointer aliasing on the stack
//! - `MapState`: gathers RangeHints from varnodes, merges them into Symbols
//! - `ScopeLocal`: the local scope that restructures the stack frame
//!
//! The main entry point is `ScopeLocal::restructure_varnode()`, which:
//! 1. Gathers stack varnodes with their types
//! 2. Gathers open pointer references (potential aliases)
//! 3. Merges overlapping ranges into disjoint local variables
//! 4. Marks unaliased variables for merge eligibility

use std::collections::BTreeMap;
use crate::varnode::Varnode;
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::type_system::Datatype;
use crate::type_system::TypeMetatype;
use std::sync::Arc;

/// Range type for RangeHint (varmap.hh:RangeType)
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RangeType {
    /// A fixed-size range with known type
    Fixed,
    /// An open range (pointer reference, size unknown)
    Open,
    /// An endpoint marker for bounding
    Endpoint,
}

/// Flags for RangeHint
pub mod range_flags {
    pub const TYPE_LOCK: u32 = 1;
    pub const COPY_CONSTANT: u32 = 2;
    pub const UNALIASED: u32 = 4;
    pub const MAPPED: u32 = 8;
}

/// A typed range hint on the stack address space.
/// Corresponds to Ghidra's RangeHint (varmap.hh:90).
#[derive(Clone, Debug)]
pub struct RangeHint {
    /// Start offset (unsigned)
    pub start: u64,
    /// Size in bytes
    pub size: i32,
    /// Signed start offset (for comparison)
    pub sstart: i64,
    /// Data type at this range
    pub dtype: Option<Arc<Datatype>>,
    /// Flags (range_flags)
    pub flags: u32,
    /// Range type
    pub range_type: RangeType,
    /// Highest index for arrays (-1 if not array)
    pub high_ind: i32,
}

impl RangeHint {
    pub fn new(start: u64, size: i32, sstart: i64, dtype: Option<Arc<Datatype>>,
               flags: u32, range_type: RangeType, high_ind: i32) -> Self {
        Self { start, size, sstart, dtype, flags, range_type, high_ind }
    }

    pub fn is_type_lock(&self) -> bool {
        self.flags & range_flags::TYPE_LOCK != 0
    }

    /// Compare two RangeHints by signed start offset.
    /// Corresponds to RangeHint::compareRanges (varmap.cc:321).
    pub fn compare(a: &RangeHint, b: &RangeHint) -> std::cmp::Ordering {
        if a.sstart != b.sstart {
            a.sstart.cmp(&b.sstart)
        } else if a.size != b.size {
            b.size.cmp(&a.size) // Bigger size first
        } else {
            std::cmp::Ordering::Equal
        }
    }

    /// Check if two intersecting ranges can coexist.
    /// Corresponds to RangeHint::reconcile (varmap.cc:62).
    pub fn reconcile(&self, b: &RangeHint) -> bool {
        // Simplified: if types match or one is unknown, allow reconciliation
        match (&self.dtype, &b.dtype) {
            (None, _) | (_, None) => true,
            (Some(a), Some(bt)) => {
                let am = a.get_metatype();
                let bm = bt.get_metatype();
                if am == bm { return true; }
                if am == TypeMetatype::Unknown || bm == TypeMetatype::Unknown { return true; }
                // For structs/unions, allow partial overlap
                if am == TypeMetatype::Struct || am == TypeMetatype::Union {
                    if bm == TypeMetatype::Unknown || bm == TypeMetatype::Int || bm == TypeMetatype::Uint {
                        return true;
                    }
                }
                false
            }
        }
    }

    /// Merge two intersecting ranges into one.
    /// Corresponds to RangeHint::merge (varmap.cc:259).
    pub fn merge_with(&mut self, other: &RangeHint) -> bool {
        // Returns true if there were overlap problems
        let end_self = self.start.wrapping_add(self.size as u64);
        let end_other = other.start.wrapping_add(other.size as u64);
        let new_end = end_self.max(end_other);
        self.size = (new_end.wrapping_sub(self.start)) as i32;

        // Prefer the larger type or the locked type
        if other.is_type_lock() && !self.is_type_lock() {
            self.dtype = other.dtype.clone();
            self.flags |= range_flags::TYPE_LOCK;
        } else if self.dtype.is_none() && other.dtype.is_some() {
            self.dtype = other.dtype.clone();
        }

        // For open ranges, extend size
        if self.range_type == RangeType::Open && other.range_type == RangeType::Fixed {
            self.range_type = RangeType::Fixed;
        }
        true // overlap problem
    }

    /// Attempt to join adjacent ranges (gap of 0).
    /// Corresponds to RangeHint::attemptJoin (varmap.cc:170).
    pub fn attempt_join(&mut self, other: &RangeHint) -> bool {
        let end_self = self.start.wrapping_add(self.size as u64);
        if end_self != other.start {
            return false;
        }
        // Same type or one is unknown
        let types_compatible = match (&self.dtype, &other.dtype) {
            (None, _) | (_, None) => true,
            (Some(a), Some(b)) => a.get_metatype() == b.get_metatype(),
        };
        if !types_compatible {
            return false;
        }
        self.size += other.size;
        if self.dtype.is_none() {
            self.dtype = other.dtype.clone();
        }
        true
    }
}

/// AliasChecker: analyzes pointer aliasing on the stack.
/// Corresponds to Ghidra's AliasChecker (varmap.hh:137).
pub struct AliasChecker {
    /// Sorted list of alias starting offsets
    pub aliases: Vec<u64>,
    /// Additive base references
    pub add_base: Vec<(u64, Option<u64>)>, // (base_offset, index_offset)
    /// Boundary offset for local vs parameter region
    local_boundary: u64,
    /// Direction of stack growth (-1 = grows down)
    direction: i32,
}

impl AliasChecker {
    pub fn new(direction: i32) -> Self {
        Self {
            aliases: Vec::new(),
            add_base: Vec::new(),
            local_boundary: 0x1000000,
            direction,
        }
    }

    /// Gather alias information from a function's varnodes.
    /// Looks for stack pointer (RSP) additive uses.
    /// Corresponds to AliasChecker::gatherInternal (varmap.cc:660).
    pub fn gather(&mut self, fd: &crate::funcdata::Funcdata) {
        // Find the stack base input varnode (RSP in x86-64)
        // Then trace additive uses (INT_ADD, PTRADD, PTRSUB, etc.)
        // For each additive use, extract the constant offset → alias boundary
        self.aliases.clear();
        self.add_base.clear();

        // Simplified: scan for STORE/LOAD ops using stack-relative addresses
        // This captures the alias boundaries for the stack
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            match op.opcode {
                OpCode::CPUI_STORE => {
                    if op.inrefs.len() >= 2 {
                        let ptr_vn = &op.inrefs[1];
                        if ptr_vn.read().unwrap().get_space() == crate::space::AddressSpace::Register {
                            // Check if this is RSP-derived pointer
                            if let Some(def) = ptr_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                                let def_op = def.read().unwrap();
                                if def_op.opcode == OpCode::CPUI_INT_ADD || def_op.opcode == OpCode::CPUI_PTRSUB {
                                    if def_op.inrefs.len() >= 2 {
                                        let const_in = &def_op.inrefs[1];
                                        if const_in.read().unwrap().get_space() == crate::space::AddressSpace::Const {
                                            let offset = const_in.read().unwrap().get_offset();
                                            self.aliases.push(offset);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        self.sort_alias();
    }

    fn sort_alias(&mut self) {
        self.aliases.sort();
        self.aliases.dedup();
    }

    pub fn get_aliases(&self) -> &[u64] {
        &self.aliases
    }
}

/// MapState: gathers RangeHints and restructures them into Symbols.
/// Corresponds to Ghidra's MapState (varmap.hh:174).
pub struct MapState {
    /// List of collected RangeHints
    maplist: Vec<RangeHint>,
    /// Iterator position for restructuring
    iter_pos: usize,
    /// Default type for unknowns
    default_type: Option<Arc<Datatype>>,
    /// Whether local range is defined
    local_start: u64,
    local_end: u64,
}

impl MapState {
    pub fn new(local_start: u64, local_end: u64) -> Self {
        Self {
            maplist: Vec::new(),
            iter_pos: 0,
            default_type: None,
            local_start,
            local_end,
        }
    }

    /// Add a range hint.
    /// Corresponds to MapState::addRange (varmap.cc:896).
    pub fn add_range(&mut self, start: u64, dtype: Option<Arc<Datatype>>, flags: u32, rt: RangeType) {
        let size = dtype.as_ref().map_or(1, |d| d.get_size() as i32);
        if size <= 0 { return; }
        // Check if in local range
        if start < self.local_start || start >= self.local_end { return; }
        let sstart = start as i64;
        self.maplist.push(RangeHint::new(start, size, sstart, dtype, flags, rt, -1));
    }

    /// Add a fixed type reference from a varnode.
    /// Corresponds to MapState::addFixedType (varmap.cc:926).
    pub fn add_fixed_type(&mut self, start: u64, dtype: Option<Arc<Datatype>>, flags: u32) {
        self.add_range(start, dtype, flags, RangeType::Fixed);
    }

    /// Gather varnodes from the function's vbank.
    /// Corresponds to MapState::gatherVarnodes (varmap.cc:1124).
    pub fn gather_varnodes(&mut self, fd: &crate::funcdata::Funcdata) {
        for vn_arc in &fd.vbank.loc_tree {
            let vn = vn_arc.0.read().unwrap();
            if vn.is_free() { continue; }
            // Only gather stack-space varnodes
            if vn.get_space() != crate::space::AddressSpace::Stack { continue; }
            let offset = vn.get_offset();
            let dtype = vn.v_type.clone();
            // Determine flags based on definition op
            if let Some(def_weak) = vn.def.as_ref() {
                if let Some(def_arc) = def_weak.upgrade() {
                    let def_op = def_arc.read().unwrap();
                    match def_op.opcode {
                        OpCode::CPUI_COPY => {
                            let const_flag = if def_op.inrefs.first().map_or(false, |i| {
                                i.read().unwrap().get_space() == crate::space::AddressSpace::Const
                            }) { range_flags::COPY_CONSTANT } else { 0 };
                            self.add_fixed_type(offset, dtype, const_flag);
                        }
                        OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INDIRECT => {
                            // Only add if not just copying to same storage
                            self.add_fixed_type(offset, dtype, 0);
                        }
                        _ => {
                            self.add_fixed_type(offset, dtype, 0);
                        }
                    }
                    continue;
                }
            }
            // Unwritten varnode (input) with reads
            self.add_fixed_type(offset, dtype, 0);
        }
    }

    /// Initialize for restructuring: sort and add endpoint.
    /// Corresponds to MapState::initialize (varmap.cc:1063).
    pub fn initialize(&mut self) -> bool {
        if self.maplist.is_empty() { return false; }
        // Add endpoint range
        self.maplist.push(RangeHint::new(
            self.local_end, 1, self.local_end as i64,
            self.default_type.clone(), 0, RangeType::Endpoint, -2,
        ));
        // Sort by signed start
        self.maplist.sort_by(RangeHint::compare);
        self.iter_pos = 0;
        true
    }

    /// Get next range hint (for restructuring iteration).
    pub fn next_hint(&self) -> Option<&RangeHint> {
        self.maplist.get(self.iter_pos)
    }

    /// Advance iterator and return true if there's another hint.
    pub fn get_next(&mut self) -> bool {
        self.iter_pos += 1;
        self.iter_pos < self.maplist.len()
    }

    /// Reset iterator.
    pub fn reset_iter(&mut self) {
        self.iter_pos = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.maplist.is_empty()
    }

    pub fn len(&self) -> usize {
        self.maplist.len()
    }
}

/// A restructured local variable symbol.
/// Corresponds to Ghidra's SymbolEntry for local scope.
#[derive(Clone, Debug)]
pub struct LocalSymbol {
    /// Name (auto-generated: Stack_offset or local_XX)
    pub name: String,
    /// Start offset on stack
    pub start: u64,
    /// Size in bytes
    pub size: i32,
    /// Data type
    pub dtype: Option<Arc<Datatype>>,
    /// Whether this variable is unaliased (safe for merge)
    pub unaliased: bool,
    /// Whether this is a function parameter
    pub is_param: bool,
}

/// ScopeLocal: the local variable scope for a function.
/// Corresponds to Ghidra's ScopeLocal (varmap.hh:212).
pub struct ScopeLocal {
    /// The restructured local symbols
    pub symbols: Vec<LocalSymbol>,
    /// Whether restructuring had overlap problems
    pub overlap_problems: bool,
    /// Stack growth direction (-1 = grows down, typical x86-64)
    pub stack_direction: i32,
}

impl ScopeLocal {
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
            overlap_problems: false,
            stack_direction: -1,
        }
    }

    /// Restructure the stack frame from varnodes.
    /// Main entry point. Corresponds to ScopeLocal::restructureVarnode (varmap.cc:1256).
    pub fn restructure_varnode(&mut self, fd: &crate::funcdata::Funcdata) {
        // Clear existing symbols
        self.symbols.clear();
        self.overlap_problems = false;

        // Determine local range from function prototype
        let local_start = 0u64;
        let local_end = 0x100000u64; // Simplified: 1MB stack range

        // Gather RangeHints from stack varnodes
        let mut state = MapState::new(local_start, local_end);
        state.gather_varnodes(fd);

        // Gather alias info
        let mut checker = AliasChecker::new(self.stack_direction);
        checker.gather(fd);
        let aliases = checker.get_aliases().to_vec();

        // Restructure: merge overlapping ranges into disjoint symbols
        self.overlap_problems = self.restructure(&mut state);

        // Mark unaliased symbols
        self.mark_unaliased(&aliases);

        // Build fake input symbols for parameters
        self.fake_input_symbols(fd);
    }

    /// Merge RangeHints into a definitive set of Symbols.
    /// Corresponds to ScopeLocal::restructure (varmap.cc:1294).
    fn restructure(&mut self, state: &mut MapState) -> bool {
        if !state.initialize() { return false; }

        let mut overlap_problems = false;
        let mut current = match state.next_hint() {
            Some(h) => h.clone(),
            None => return false,
        };

        while state.get_next() {
            let next = match state.next_hint() {
                Some(h) => h.clone(),
                None => break,
            };

            // Check if ranges intersect
            let cur_end = current.start.wrapping_add(current.size as u64);
            if next.start < cur_end {
                // Ranges intersect — merge them
                if current.merge_with(&next) {
                    overlap_problems = true;
                }
            } else {
                // No intersection — finalize current range
                if !current.attempt_join(&next) {
                    // Adjust and create entry
                    if current.range_type == RangeType::Open {
                        current.size = (next.start.wrapping_sub(current.start)) as i32;
                    }
                    self.create_entry(&current);
                    current = next;
                }
            }
        }

        overlap_problems
    }

    /// Create a symbol entry from a RangeHint.
    /// Corresponds to ScopeLocal::createEntry (varmap.cc:617).
    fn create_entry(&mut self, hint: &RangeHint) {
        if hint.size <= 0 { return; }

        // Build variable name
        let name = self.build_variable_name(hint.start);

        self.symbols.push(LocalSymbol {
            name,
            start: hint.start,
            size: hint.size,
            dtype: hint.dtype.clone(),
            unaliased: false,
            is_param: false,
        });
    }

    /// Build a variable name from stack offset.
    /// Corresponds to ScopeLocal::buildVariableName (varmap.cc:548).
    fn build_variable_name(&self, offset: u64) -> String {
        // Ghidra convention: Stack_offset (signed hex)
        let signed = offset as i64;
        if self.stack_direction == -1 {
            // Stack grows down: negative offsets are locals
            let neg = -signed;
            format!("Stack_{:x}", neg)
        } else {
            format!("Stack_{:x}", signed)
        }
    }

    /// Mark symbols as unaliased based on alias boundaries.
    /// Corresponds to ScopeLocal::markUnaliased (varmap.cc:1332).
    fn mark_unaliased(&mut self, aliases: &[u64]) {
        if aliases.is_empty() {
            // No aliases → all unaliased
            for sym in &mut self.symbols {
                sym.unaliased = true;
            }
            return;
        }

        // Symbols before the first alias boundary are unaliased
        let first_alias = aliases[0];
        for sym in &mut self.symbols {
            let sym_end = sym.start.wrapping_add(sym.size as u64);
            if sym_end <= first_alias {
                sym.unaliased = true;
            }
        }
    }

    /// Create fake input symbols for function parameters.
    /// Corresponds to ScopeLocal::fakeInputSymbols (varmap.cc:1392).
    fn fake_input_symbols(&mut self, fd: &crate::funcdata::Funcdata) {
        // Add parameter symbols from function prototype
        for (i, param) in fd.funcp.parameters.iter().enumerate() {
            self.symbols.push(LocalSymbol {
                name: format!("param_{}", i),
                start: param.address.as_u64(),
                size: 8, // Default size for register-stored params
                dtype: None,
                unaliased: true,
                is_param: true,
            });
        }
    }

    /// Look up a symbol by stack offset.
    pub fn find_symbol(&self, offset: u64) -> Option<&LocalSymbol> {
        for sym in &self.symbols {
            let end = sym.start.wrapping_add(sym.size as u64);
            if offset >= sym.start && offset < end {
                return Some(sym);
            }
        }
        None
    }
}
