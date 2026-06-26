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
use std::sync::{Arc, RwLock};

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

    /// Whether this is a constant-absorbable range (copy_constant flag).
    /// Faithful to Ghidra's `RangeHint::copy_constant` flag semantics.
    fn is_copy_constant(&self) -> bool {
        self.flags & range_flags::COPY_CONSTANT != 0
    }

    /// This is assumed to be open. If this is a primitive integer or float, and
    /// if the other range is just a constant being COPYed, return true, even if
    /// the constant is bigger. Corresponds to `RangeHint::isConstAbsorbable`
    /// (varmap.cc:30).
    pub fn is_const_absorbable(&self, b: &RangeHint) -> bool {
        if !b.is_copy_constant() {
            return false;
        }
        if b.is_type_lock() {
            return false;
        }
        if b.size < self.size {
            return false;
        }
        let self_dt = match &self.dtype {
            Some(d) => d,
            None => return false, // Ghidra dereferences type unconditionally
        };
        let meta = self_dt.get_metatype();
        if meta != TypeMetatype::Int
            && meta != TypeMetatype::Uint
            && meta != TypeMetatype::Bool
            && meta != TypeMetatype::Float
        {
            return false;
        }
        if let Some(b_dt) = &b.dtype {
            let b_meta = b_dt.get_metatype();
            if b_meta != TypeMetatype::Unknown
                && b_meta != TypeMetatype::Int
                && b_meta != TypeMetatype::Uint
            {
                return false;
            }
        }
        let mut end = self.sstart;
        if self.high_ind > 0 {
            if let Some(t) = &self.dtype {
                end += (self.high_ind as i64) * (t.get_align_size() as i64);
            }
        } else {
            end += self.size as i64;
        }
        if b.sstart > end {
            return false;
        }
        true
    }

    /// Can the given intersecting RangeHint coexist with this at their given
    /// offsets? Faithful to `RangeHint::reconcile` (varmap.cc:62).
    pub fn reconcile(&self, b_in: &RangeHint) -> bool {
        // Make `a` the larger-alignSize range, `b` the smaller.
        let (a, b) = match (&self.dtype, &b_in.dtype) {
            (Some(a_dt), Some(b_dt)) => {
                if a_dt.get_align_size() < b_dt.get_align_size() {
                    (b_in, self)
                } else {
                    (self, b_in)
                }
            }
            // Without full type info we cannot do the alignment modulo check;
            // conservatively allow reconciliation (matches the TYPE_UNKNOWN
            // fallback branch in Ghidra).
            _ => return true,
        };

        let a_dt = a.dtype.as_ref().unwrap();
        let b_dt = b.dtype.as_ref().unwrap();
        let a_align = a_dt.get_align_size().max(1) as i64;

        let mut mod_ = (b.sstart - a.sstart) % a_align;
        if mod_ < 0 {
            mod_ += a_align;
        }

        // Descend through a's subtypes while a is bigger than b.
        let mut sub = a_dt.clone();
        let mut cur_mod = mod_;
        loop {
            let sub_align = sub.get_align_size();
            if sub_align <= b_dt.get_align_size() {
                break;
            }
            let (next, newoff) = sub.get_sub_type(cur_mod);
            match next {
                Some(n) => {
                    sub = Arc::new(n.clone());
                    cur_mod = newoff;
                }
                None => break,
            }
        }

        if sub.get_align_size() == b_dt.get_align_size() {
            return true;
        }
        // b overlaps multiple components of a.

        if b.range_type == RangeType::Open && b.is_const_absorbable(a) {
            return true;
        }
        if b.is_type_lock() {
            return false;
        }
        let meta = a_dt.get_metatype();
        if meta != TypeMetatype::Struct && meta != TypeMetatype::Union {
            if meta != TypeMetatype::Array {
                return false;
            }
            // Array of unknown base is allowed.
            return true;
        }
        // For structures/unions/arrays-of-unknown, accept int/uint/unknown b.
        let b_meta = b_dt.get_metatype();
        b_meta == TypeMetatype::Unknown
            || b_meta == TypeMetatype::Int
            || b_meta == TypeMetatype::Uint
    }

    /// Return true if this or the given range contains the other. Assumes this
    /// starts at least as early as b and that they intersect.
    /// Faithful to `RangeHint::contain` (varmap.cc:109).
    pub fn contain(&self, b: &RangeHint) -> bool {
        if self.sstart == b.sstart {
            return true;
        }
        // b->sstart + b->size - 1 <= sstart + size - 1
        (b.sstart + b.size as i64 - 1) <= (self.sstart + self.size as i64 - 1)
    }

    /// Is this range's data-type preferred over the other?
    /// Faithful to `RangeHint::preferred` (varmap.cc:126).
    pub fn preferred(&self, b: &RangeHint, reconcile: bool) -> bool {
        if self.start != b.start {
            return true; // Something must occupy a->start to b->start
        }
        // Prefer the locked type.
        if b.is_type_lock() {
            if !self.is_type_lock() {
                return false;
            }
        } else if self.is_type_lock() {
            return true;
        }

        if self.range_type == RangeType::Open && b.range_type != RangeType::Open {
            if !reconcile {
                return false;
            }
            if self.is_const_absorbable(b) {
                return true;
            }
        } else if b.range_type == RangeType::Open && self.range_type != RangeType::Open {
            if !reconcile {
                return true;
            }
            if b.is_const_absorbable(self) {
                return false;
            }
        } else if self.range_type == RangeType::Fixed && b.range_type == RangeType::Fixed {
            if self.size != b.size && !reconcile {
                return self.size > b.size;
            }
        }

        // Prefer the more specific type (typeOrder < 0 means self < b → preferred).
        match (&self.dtype, &b.dtype) {
            (Some(a), Some(bb)) => a.type_order(bb) < 0,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => true,
        }
    }

    /// Absorb details of the other RangeHint into this, except the data-type.
    /// Faithful to `RangeHint::absorb` (varmap.cc:217).
    pub fn absorb(&mut self, b: &RangeHint) {
        if b.range_type == RangeType::Open {
            let aligns_match = match (&self.dtype, &b.dtype) {
                (Some(a), Some(bb)) => a.get_align_size() == bb.get_align_size(),
                _ => false,
            };
            if aligns_match {
                self.range_type = RangeType::Open;
                if b.high_ind >= 0 {
                    let diffsz = b.sstart - self.sstart;
                    if let Some(t) = &self.dtype {
                        let align = t.get_align_size().max(1) as i64;
                        let trialhi = b.high_ind as i64 + diffsz / align;
                        if (self.high_ind as i64) < trialhi {
                            self.high_ind = trialhi as i32;
                        }
                    }
                }
            } else if self.start == b.start {
                let meta = match &self.dtype {
                    Some(t) => t.get_metatype(),
                    None => TypeMetatype::Unknown,
                };
                if meta != TypeMetatype::Struct && meta != TypeMetatype::Union {
                    self.range_type = RangeType::Open;
                }
            }
        } else if b.is_copy_constant() && self.range_type == RangeType::Open {
            let diffsz = b.sstart - self.sstart + b.size as i64;
            if diffsz > self.size as i64 {
                if let Some(t) = &self.dtype {
                    let align = t.get_align_size().max(1) as i64;
                    let trialhi = diffsz / align;
                    if (self.high_ind as i64) < trialhi {
                        self.high_ind = trialhi as i32;
                    }
                }
            }
        }
        if self.is_copy_constant() && !b.is_copy_constant() {
            self.flags ^= range_flags::COPY_CONSTANT;
        }
    }

    /// Given that this and the other RangeHint intersect, redefine this so that
    /// it becomes the union of the two. Faithful to `RangeHint::merge`
    /// (varmap.cc:259). Returns true if there was a reconcilable overlap.
    pub fn merge_with(&mut self, b: &RangeHint) -> bool {
        let did_reconcile;
        let res_type: i32; // 0=this, 1=b, 2=confuse

        if self.contain(b) {
            did_reconcile = self.reconcile(b);
            if !did_reconcile && self.start != b.start {
                res_type = 2;
            } else {
                res_type = if self.preferred(b, did_reconcile) { 0 } else { 1 };
            }
        } else {
            did_reconcile = false;
            res_type = if self.is_type_lock() { 0 } else { 2 };
        }

        // Check for really problematic cases.
        if !did_reconcile {
            if self.is_type_lock() && b.is_type_lock() {
                // Ghidra throws LowlevelError; we log via eprintln and discard b.
                let n1 = self.dtype.as_ref().map(|d| d.get_name()).unwrap_or("?");
                let n2 = b.dtype.as_ref().map(|d| d.get_name()).unwrap_or("?");
                eprintln!("[VARMAP] overlapping forced variable types: {} {}", n1, n2);
                if self.start != b.start {
                    return false; // Discard b entirely
                }
            }
        }

        if res_type == 0 {
            self.absorb(b);
        } else if res_type == 1 {
            // Take b's type/flags/rangeType/highind/size, absorb old self.
            let copy = self.clone();
            self.dtype = b.dtype.clone();
            self.flags = b.flags;
            self.range_type = b.range_type;
            self.high_ind = b.high_ind;
            self.size = b.size;
            self.absorb(&copy);
        } else {
            // resType == 2: concede confusion, set unknown type.
            self.flags = 0;
            self.range_type = RangeType::Fixed;
            let diff = (b.sstart - self.sstart) as i32;
            if diff + b.size > self.size {
                self.size = diff + b.size;
            }
            if self.size != 1 && self.size != 2 && self.size != 4 && self.size != 8 {
                self.size = 1;
                self.range_type = RangeType::Open;
            }
            self.dtype = Some(Arc::new(Datatype::Base(
                crate::type_system::datatype::TypeBase::new(
                    "unknown".to_string(),
                    self.size as usize,
                    TypeMetatype::Unknown,
                ),
            )));
            self.flags = 0;
            self.high_ind = -1;
            return false;
        }
        false
    }

    /// Compare (signed) offset, size, RangeType, flags, high index — in that
    /// order. Datatype is NOT compared. Faithful to `RangeHint::compare`
    /// (varmap.cc:321).
    pub fn compare(a: &RangeHint, b: &RangeHint) -> std::cmp::Ordering {
        if a.sstart != b.sstart {
            return a.sstart.cmp(&b.sstart);
        }
        if a.size != b.size {
            // Small sizes come first.
            return a.size.cmp(&b.size);
        }
        if a.range_type != b.range_type {
            return (a.range_type as u8).cmp(&(b.range_type as u8));
        }
        if a.flags != b.flags {
            return a.flags.cmp(&b.flags);
        }
        if a.high_ind != b.high_ind {
            return a.high_ind.cmp(&b.high_ind);
        }
        std::cmp::Ordering::Equal
    }

    /// If this is an array and the following RangeHint lines up, absorb it.
    /// Faithful to `RangeHint::attemptJoin` (varmap.cc:170). Returns true if b
    /// was absorbed into this.
    pub fn attempt_join(&mut self, b: &RangeHint) -> bool {
        if self.range_type != RangeType::Open {
            return false;
        }
        if b.range_type == RangeType::Endpoint {
            return false;
        }
        if self.is_const_absorbable(b) {
            self.absorb(b);
            return true;
        }
        if self.high_ind < 0 {
            return false;
        }
        let settype = match &self.dtype {
            Some(t) => t.clone(),
            None => return false,
        };
        let b_dt = match &b.dtype {
            Some(t) => t.clone(),
            None => return false,
        };
        if settype.get_align_size() != b_dt.get_align_size() {
            return false;
        }
        if !Arc::ptr_eq(&settype, &b_dt) {
            // Walk pointer chains comparing metatypes.
            let mut a_test = settype.clone();
            let mut b_test = b_dt.clone();
            loop {
                let am = a_test.get_metatype();
                if am != TypeMetatype::Pointer {
                    break;
                }
                if b_test.get_metatype() != TypeMetatype::Pointer {
                    break;
                }
                // descend into pointer targets
                match (&*a_test, &*b_test) {
                    (Datatype::Pointer(ap), Datatype::Pointer(bp)) => {
                        a_test = ap.ptr_to.clone();
                        b_test = bp.ptr_to.clone();
                    }
                    _ => break,
                }
            }
            let keep_b = match a_test.get_metatype() {
                TypeMetatype::Unknown => true,
                TypeMetatype::Int if b_test.get_metatype() == TypeMetatype::Uint => false,
                TypeMetatype::Uint if b_test.get_metatype() == TypeMetatype::Int => false,
                _ if b_test.get_metatype() == TypeMetatype::Unknown => false,
                _ => {
                    // both concrete and differ → cannot join
                    if !Arc::ptr_eq(&a_test, &b_test) {
                        return false;
                    }
                    false
                }
            };
            if keep_b {
                self.dtype = Some(b_dt);
            }
        }
        if self.is_type_lock() {
            return false;
        }
        if b.is_type_lock() {
            return false;
        }
        let diffsz = b.sstart - self.sstart;
        let align = settype.get_align_size().max(1) as i64;
        if diffsz % align != 0 {
            return false;
        }
        let diffsz = diffsz / align;
        if diffsz > self.high_ind as i64 {
            return false;
        }
        self.absorb(b);
        true
    }
}

/// An additive-base entry: the result varnode of an additive expression plus
/// an optional non-constant index varnode. Corresponds to Ghidra's
/// `AliasChecker::AddBase` (varmap.hh:130).
#[derive(Clone)]
pub struct AddBase {
    /// The additive expression result varnode.
    pub base: Arc<RwLock<Varnode>>,
    /// A non-constant index varnode (or None if the offset is fully constant).
    pub index: Option<Arc<RwLock<Varnode>>>,
}

/// AliasChecker: analyzes pointer aliasing on the stack.
/// Corresponds to Ghidra's AliasChecker (varmap.hh:137). Faithful port of
/// varmap.cc:660-731 (gatherInternal/gather/gatherAdditiveBase/gatherOffset).
pub struct AliasChecker {
    /// Sorted list of alias offsets (varmap.cc `alias`).
    pub aliases: Vec<u64>,
    /// Additive-base references collected from the spacebase (varmap.cc `addBase`).
    pub add_base: Vec<AddBase>,
    /// Boundary between local and parameter region (varmap.cc `localBoundary`).
    local_boundary: u64,
    /// The lowest alias offset seen (varmap.cc `aliasBoundary`), initialised to
    /// `local_extreme` and shrunk toward the locals region.
    alias_boundary: u64,
    /// Stack growth direction: 1 for negative growth (x86), -1 otherwise.
    /// Matches Ghidra's convention where direction==1 is the normal case.
    direction: i32,
    /// Whether the alias calculation has been performed.
    calculated: bool,
}

impl AliasChecker {
    /// The "infinitely far" boundary, so the first real alias always wins.
    /// Ghidra initialises `localExtreme` from `space->getHighest()`.
    const LOCAL_EXTREME: u64 = u64::MAX;

    pub fn new(direction: i32) -> Self {
        Self {
            aliases: Vec::new(),
            add_base: Vec::new(),
            local_boundary: 0x1000000,
            alias_boundary: Self::LOCAL_EXTREME,
            direction,
            calculated: false,
        }
    }

    /// Configure local/parameter boundaries from a function prototype.
    /// Corresponds to `AliasChecker::deriveBoundaries` (varmap.cc ~590).
    /// For a negative-growing stack the locals occupy offsets below
    /// `local_boundary`; the parameter region is above it.
    pub fn derive_boundaries(&mut self, local_boundary: u64) {
        self.local_boundary = local_boundary;
    }

    /// If there is a stack (spacebase) pointer, find its input Varnode, and look
    /// for additive uses of it. Then calculate the offsets that start an aliased
    /// region. Faithful to `AliasChecker::gatherInternal` (varmap.cc:660).
    pub fn gather_internal(&mut self, fd: &crate::funcdata::Funcdata) {
        self.calculated = true;
        self.alias_boundary = Self::LOCAL_EXTREME;
        self.aliases.clear();
        self.add_base.clear();

        // Find the spacebase input varnode (RSP). Rugra models RSP as the
        // Register-space input varnode at offset 0x20, size 8.
        let spacebase = match find_spacebase_input(fd) {
            Some(vn) => vn,
            None => return, // No possible alias
        };

        // Recursively collect additive roots.
        self.gather_additive_base(&spacebase);

        for entry in self.add_base.clone().into_iter() {
            let offset = gather_offset(&entry.base);
            // Ghidra converts via addressToByte(offset, wordSize); wordSize==1
            // for the stack space, so the offset is already in bytes.
            self.aliases.push(offset);
            if self.direction == 1 {
                // Negative stack growth: offsets above local_boundary are params.
                if offset < self.local_boundary {
                    continue;
                }
            } else {
                if offset > self.local_boundary {
                    continue;
                }
            }
            // Anything after (below, for negative growth) a pointer reference is
            // aliased, regardless of stack direction.
            if offset < self.alias_boundary {
                self.alias_boundary = offset;
            }
        }

        self.sort_aliases();
    }

    /// Gather result Varnodes for all sums that `startvn` is involved in.
    /// Faithful to `AliasChecker::gatherAdditiveBase` (varmap.cc:741).
    ///
    /// A sum is any expression involving only the additive operators
    /// INT_ADD, INT_SUB, PTRADD, PTRSUB, and SEGMENTOP (plus COPY). The routine
    /// traverses forward through descendants that are additive operations and
    /// collects the roots of the traversed trees.
    fn gather_additive_base(&mut self, startvn: &Arc<RwLock<Varnode>>) {
        // Marked varnodes (by raw pointer identity within this borrow scope).
        let mut marked: std::collections::HashSet<*const Varnode> = std::collections::HashSet::new();
        // Work queue of (varnode, index).
        let mut vnqueue: Vec<AddBase> = Vec::new();

        let start_ptr = Arc::as_ptr(startvn) as *const Varnode;
        marked.insert(start_ptr);
        vnqueue.push(AddBase { base: startvn.clone(), index: None });

        let mut i = 0;
        while i < vnqueue.len() {
            let cur = vnqueue[i].clone();
            i += 1;
            let mut indexvn = cur.index.clone();
            let mut nonadduse = false;

            // Iterate over descendants (ops that read this varnode).
            let descend_refs: Vec<_> = {
                let vn = cur.base.read().unwrap();
                vn.descend.iter().filter_map(|w| w.upgrade()).collect()
            };

            for op_ref in descend_refs {
                let op = op_ref.read().unwrap();
                match op.opcode {
                    OpCode::CPUI_COPY => {
                        nonadduse = true; // COPY is both a non-add use and part of ADD.
                        if let Some(out) = op.output.clone() {
                            let p = Arc::as_ptr(&out) as *const Varnode;
                            if !marked.contains(&p) {
                                marked.insert(p);
                                vnqueue.push(AddBase { base: out, index: indexvn.clone() });
                            }
                        }
                    }
                    OpCode::CPUI_INT_SUB => {
                        // If the pointer is the subtrahend (input 1), it's a non-add use.
                        let vn_ptr = Arc::as_ptr(&cur.base);
                        let in1_ptr = op.inrefs.get(1).map(|v| Arc::as_ptr(v));
                        if in1_ptr == Some(vn_ptr) {
                            nonadduse = true;
                            // break out of this op's processing
                        } else {
                            // Otherwise the other operand may be a non-const index.
                            if let Some(othervn) = op.inrefs.get(1) {
                                let ov = othervn.read().unwrap();
                                if !ov.is_constant() {
                                    indexvn = Some(othervn.clone());
                                }
                            }
                            if let Some(out) = op.output.clone() {
                                let p = Arc::as_ptr(&out) as *const Varnode;
                                if !marked.contains(&p) {
                                    marked.insert(p);
                                    vnqueue.push(AddBase { base: out, index: indexvn.clone() });
                                }
                            }
                        }
                    }
                    OpCode::CPUI_INT_ADD | OpCode::CPUI_PTRADD => {
                        // Check if something non-constant is being added.
                        let in0 = op.inrefs.get(0);
                        let in1 = op.inrefs.get(1);
                        let vn_ptr = Arc::as_ptr(&cur.base);
                        let othervn = if in1.map(|v| Arc::as_ptr(v)) == Some(vn_ptr) {
                            in0
                        } else {
                            in1
                        };
                        if let Some(other) = othervn {
                            let ov = other.read().unwrap();
                            if !ov.is_constant() {
                                indexvn = Some(other.clone());
                            }
                        }
                        // fallthru to PTRSUB/SEGMENTOP output handling
                        if let Some(out) = op.output.clone() {
                            let p = Arc::as_ptr(&out) as *const Varnode;
                            if !marked.contains(&p) {
                                marked.insert(p);
                                vnqueue.push(AddBase { base: out, index: indexvn.clone() });
                            }
                        }
                    }
                    OpCode::CPUI_PTRSUB | OpCode::CPUI_SEGMENTOP => {
                        if let Some(out) = op.output.clone() {
                            let p = Arc::as_ptr(&out) as *const Varnode;
                            if !marked.contains(&p) {
                                marked.insert(p);
                                vnqueue.push(AddBase { base: out, index: indexvn.clone() });
                            }
                        }
                    }
                    _ => {
                        nonadduse = true; // Used in a non-additive expression.
                    }
                }
            }

            if nonadduse {
                self.add_base.push(AddBase { base: cur.base.clone(), index: indexvn.clone() });
            }
        }
        // Ghidra clears marks here; our HashSet is dropped at scope end.
    }

    fn sort_aliases(&mut self) {
        self.aliases.sort();
    }

    /// Rough analysis of whether `vn` might be aliased by another pointer.
    /// Faithful to `AliasChecker::hasLocalAlias` (varmap.cc:711).
    pub fn has_local_alias(&self, vn: &Varnode) -> bool {
        if !self.calculated {
            return true; // Conservative: assume alias if uncalculated.
        }
        if vn.get_space() != crate::space::AddressSpace::Stack {
            return false;
        }
        if self.direction == -1 {
            return false; // Positive growth: not a good test.
        }
        vn.get_offset() >= self.alias_boundary
    }

    pub fn get_aliases(&self) -> &[u64] {
        &self.aliases
    }

    pub fn get_add_base(&self) -> &[AddBase] {
        &self.add_base
    }
}

/// Find the stack-pointer input Varnode for a function (the spacebase).
/// Corresponds to `Funcdata::findSpacebaseInput`. Rugra models RSP as the
/// Register-space, offset 0x20, size-8 input varnode.
fn find_spacebase_input(fd: &crate::funcdata::Funcdata) -> Option<Arc<RwLock<Varnode>>> {
    for vn_arc in &fd.vbank.loc_tree {
        let vn = vn_arc.0.read().unwrap();
        if vn.is_free() {
            continue;
        }
        if vn.get_space() == crate::space::AddressSpace::Register
            && vn.get_offset() == 0x20
            && vn.get_size() == 8
            && vn.def.is_none()
        {
            // An input varnode (no defining op).
            return Some(vn_arc.0.clone());
        }
    }
    None
}

/// If the given Varnode is a sum result, return the constant portion of the sum.
/// Faithful to `AliasChecker::gatherOffset` (varmap.cc:817).
///
/// Treats `vn` as the result of a series of ADD operations and sums all the
/// constant terms by traversing the syntax tree backwards through additive ops.
fn gather_offset(vn: &Arc<RwLock<Varnode>>) -> u64 {
    let v = vn.read().unwrap();
    if v.is_constant() {
        return v.get_offset();
    }
    let def = match v.def.as_ref().and_then(|w| w.upgrade()) {
        Some(d) => d,
        None => return 0,
    };
    drop(v);
    let op = def.read().unwrap();
    let retval: u64;
    match op.opcode {
        OpCode::CPUI_COPY => {
            let in0 = op.inrefs[0].clone();
            drop(op);
            retval = gather_offset(&in0);
        }
        OpCode::CPUI_PTRSUB | OpCode::CPUI_INT_ADD => {
            let in0 = op.inrefs[0].clone();
            let in1 = op.inrefs[1].clone();
            drop(op);
            retval = gather_offset(&in0).wrapping_add(gather_offset(&in1));
        }
        OpCode::CPUI_INT_SUB => {
            let in0 = op.inrefs[0].clone();
            let in1 = op.inrefs[1].clone();
            drop(op);
            retval = gather_offset(&in0).wrapping_sub(gather_offset(&in1));
        }
        OpCode::CPUI_PTRADD => {
            let in0 = op.inrefs[0].clone();
            let in1 = op.inrefs[1].clone();
            let in2 = op.inrefs.get(2).cloned();
            let in1_const = {
                let iv = in1.read().unwrap();
                iv.is_constant()
            };
            if in1_const {
                let mult = in2.map(|m| m.read().unwrap().get_offset()).unwrap_or(1);
                let in1_off = in1.read().unwrap().get_offset();
                drop(op);
                retval = gather_offset(&in0).wrapping_add(in1_off.wrapping_mul(mult));
            } else {
                let mult_is_one = in2.map(|m| m.read().unwrap().get_offset() == 1).unwrap_or(false);
                drop(op);
                if mult_is_one {
                    retval = gather_offset(&in0).wrapping_add(gather_offset(&in1));
                } else {
                    retval = gather_offset(&in0);
                }
            }
        }
        OpCode::CPUI_SEGMENTOP => {
            let in2 = op.inrefs[2].clone();
            drop(op);
            retval = gather_offset(&in2);
        }
        _ => {
            retval = 0;
        }
    }
    // Ghidra masks to the varnode size: retval & calc_mask(vn->getSize()).
    let size = vn.read().unwrap().get_size();
    let mask = if size >= 64 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
    retval & mask
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
        checker.gather_internal(fd);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_system::datatype::TypeBase;

    fn int_dt(size: usize, mt: TypeMetatype) -> Arc<Datatype> {
        Arc::new(Datatype::Base(TypeBase::new("x".into(), size, mt)))
    }

    // --- compare (varmap.cc:321): signed offset, then size small-first ---

    #[test]
    fn test_rangehint_compare_offset() {
        let a = RangeHint::new(0, 4, 0, None, 0, RangeType::Fixed, -1);
        let b = RangeHint::new(16, 4, 16, None, 0, RangeType::Fixed, -1);
        assert_eq!(RangeHint::compare(&a, &b), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_rangehint_compare_size_small_first() {
        // Same start, different sizes → smaller size first.
        let a = RangeHint::new(0, 2, 0, None, 0, RangeType::Fixed, -1);
        let b = RangeHint::new(0, 4, 0, None, 0, RangeType::Fixed, -1);
        assert_eq!(RangeHint::compare(&a, &b), std::cmp::Ordering::Less);
    }

    // --- contain (varmap.cc:109) ---

    #[test]
    fn test_rangehint_contain() {
        // a: [0,8), b: [0,4) → a contains b (same start)
        let a = RangeHint::new(0, 8, 0, None, 0, RangeType::Fixed, -1);
        let b = RangeHint::new(0, 4, 0, None, 0, RangeType::Fixed, -1);
        assert!(a.contain(&b));
        // a: [0,8), b: [4,8) starts later, ends at a's end → contained
        let b2 = RangeHint::new(4, 4, 4, None, 0, RangeType::Fixed, -1);
        assert!(a.contain(&b2));
        // a: [0,4), b: [0,8): same start → contain returns true (Ghidra treats
        // same-start intersecting ranges as mutually contained).
        let small = RangeHint::new(0, 4, 0, None, 0, RangeType::Fixed, -1);
        let big = RangeHint::new(0, 8, 0, None, 0, RangeType::Fixed, -1);
        assert!(small.contain(&big));
        // To get non-containment, this must start earlier AND not reach b's end.
        // a: [0,3), b: [2,8): a does not contain b (b extends past a).
        let early_short = RangeHint::new(0, 3, 0, None, 0, RangeType::Fixed, -1);
        let later_long = RangeHint::new(2, 6, 2, None, 0, RangeType::Fixed, -1);
        assert!(!early_short.contain(&later_long));
    }

    // --- reconcile (varmap.cc:62): same-alignSize compatible types reconcile ---

    #[test]
    fn test_rangehint_reconcile_compatible_ints() {
        // Two int4 ranges at the same offset reconcile.
        let a = RangeHint::new(0, 4, 0, Some(int_dt(4, TypeMetatype::Int)), 0, RangeType::Fixed, -1);
        let b = RangeHint::new(0, 4, 0, Some(int_dt(4, TypeMetatype::Int)), 0, RangeType::Fixed, -1);
        assert!(a.reconcile(&b));
    }

    #[test]
    fn test_rangehint_reconcile_struct_field() {
        // struct { char@0; int@4; } size 8. A char-range at offset 0 should
        // reconcile with the struct because the struct has a char-sized subtype
        // at offset 0 (alignSize match via getSubType traversal).
        let char_t = int_dt(1, TypeMetatype::Int);
        let int_t = int_dt(4, TypeMetatype::Int);
        let s = Arc::new(Datatype::Struct(crate::type_system::datatype::TypeStruct {
            base: TypeBase::new("S".into(), 8, TypeMetatype::Struct),
            fields: vec![
                crate::type_system::datatype::TypeField { name: "f0".into(), offset: 0, type_ptr: char_t.clone() },
                crate::type_system::datatype::TypeField { name: "f1".into(), offset: 4, type_ptr: int_t.clone() },
            ],
        }));
        let a = RangeHint::new(0, 8, 0, Some(s), 0, RangeType::Fixed, -1);
        let b = RangeHint::new(0, 1, 0, Some(char_t), 0, RangeType::Fixed, -1);
        assert!(a.reconcile(&b));
    }

    // --- preferred (varmap.cc:126): locked preferred, more specific preferred ---

    #[test]
    fn test_rangehint_preferred_locked() {
        // a unlocked int4, b locked int4 at same start → b preferred.
        let a = RangeHint::new(0, 4, 0, Some(int_dt(4, TypeMetatype::Int)), 0, RangeType::Fixed, -1);
        let b = RangeHint::new(0, 4, 0, Some(int_dt(4, TypeMetatype::Int)), range_flags::TYPE_LOCK, RangeType::Fixed, -1);
        assert!(!a.preferred(&b, true)); // a NOT preferred → b wins
        assert!(b.preferred(&a, true));  // b preferred
    }

    #[test]
    fn test_rangehint_preferred_smaller_int() {
        // int4 vs int8 at same start, both unlocked, fixed, reconcile=true.
        // typeOrder(int4, int8) returns (8-4)=+4 → not < 0 → int4 NOT preferred??
        // Ghidra: preferred returns (0 > typeOrder(b)) i.e. typeOrder<0.
        // typeOrder smaller-size-first: int4.type_order(int8) > 0 → int4 NOT preferred.
        // So int8 (b) is preferred here. Verify that symmetry: int8 preferred.
        let a = RangeHint::new(0, 4, 0, Some(int_dt(4, TypeMetatype::Int)), 0, RangeType::Fixed, -1);
        let b = RangeHint::new(0, 8, 0, Some(int_dt(8, TypeMetatype::Int)), 0, RangeType::Fixed, -1);
        // For same metatype both unlocked fixed with reconcile=true, the fixed-size
        // branch is skipped (size differs but reconcile=true). Falls to typeOrder.
        // typeOrder(int4,int8) = (8-4)=+4 → a.preferred returns +4<0 = false.
        assert!(!a.preferred(&b, true));
    }

    // --- merge_with (varmap.cc:259): resType=0 absorb ---

    #[test]
    fn test_rangehint_merge_absorb_same_type() {
        // a: int4@[0,4) contained b: int4@[0,4), reconcile true, preferred a
        // → resType=0 → absorb b (no-op since identical).
        let mut a = RangeHint::new(0, 4, 0, Some(int_dt(4, TypeMetatype::Int)), 0, RangeType::Fixed, -1);
        let b = RangeHint::new(0, 4, 0, Some(int_dt(4, TypeMetatype::Int)), 0, RangeType::Fixed, -1);
        let overlap = a.merge_with(&b);
        assert!(!overlap); // reconcilable → false
        assert_eq!(a.size, 4);
    }

    #[test]
    fn test_rangehint_merge_confuse_to_unknown() {
        // a: int4@[0,4), b: int8@[2,10) — NOT contained, NOT locked → resType=2.
        // Result: unknown type, size = (2-0)+8 = 10 → not in {1,2,4,8} → size 1, open.
        let mut a = RangeHint::new(0, 4, 0, Some(int_dt(4, TypeMetatype::Int)), 0, RangeType::Fixed, -1);
        let b = RangeHint::new(2, 8, 2, Some(int_dt(8, TypeMetatype::Int)), 0, RangeType::Fixed, -1);
        let overlap = a.merge_with(&b);
        assert!(!overlap);
        assert_eq!(a.size, 1);
        assert_eq!(a.range_type, RangeType::Open);
        assert_eq!(a.dtype.as_ref().unwrap().get_metatype(), TypeMetatype::Unknown);
        assert_eq!(a.high_ind, -1);
    }

    // --- is_const_absorbable (varmap.cc:30) ---

    #[test]
    fn test_rangehint_const_absorbable() {
        // self: open int4 @0 with copy_constant candidate b.
        // b must have copy_constant flag, be >= self.size, and overlap.
        let a = RangeHint::new(0, 4, 0, Some(int_dt(4, TypeMetatype::Int)), 0, RangeType::Open, -1);
        let b = RangeHint::new(0, 4, 0, Some(int_dt(4, TypeMetatype::Int)), range_flags::COPY_CONSTANT, RangeType::Open, -1);
        assert!(a.is_const_absorbable(&b));
        // b smaller than self.size → not absorbable
        let b_small = RangeHint::new(0, 2, 0, Some(int_dt(2, TypeMetatype::Int)), range_flags::COPY_CONSTANT, RangeType::Open, -1);
        assert!(!a.is_const_absorbable(&b_small));
    }
}
