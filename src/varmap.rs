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
    // Ghidra: varmap.hh:90 RangeHint::new
    pub fn new(start: u64, size: i32, sstart: i64, dtype: Option<Arc<Datatype>>,
               flags: u32, range_type: RangeType, high_ind: i32) -> Self {
        Self { start, size, sstart, dtype, flags, range_type, high_ind }
    }

    // Ghidra: varmap.hh:90 RangeHint::isTypeLock
    pub fn is_type_lock(&self) -> bool {
        self.flags & range_flags::TYPE_LOCK != 0
    }

    // Ghidra: varmap.hh:90 RangeHint::isCopyConstant
    /// Whether this is a constant-absorbable range (copy_constant flag).
    /// Faithful to Ghidra's `RangeHint::copy_constant` flag semantics.
    fn is_copy_constant(&self) -> bool {
        self.flags & range_flags::COPY_CONSTANT != 0
    }

    // Ghidra: varmap.cc:30 RangeHint::isConstAbsorbable
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

    // Ghidra: varmap.cc:62 RangeHint::reconcile
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

    // Ghidra: varmap.cc:109 RangeHint::contain
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

    // Ghidra: varmap.cc:126 RangeHint::preferred
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

    // Ghidra: varmap.cc:217 RangeHint::absorb
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

    // Ghidra: varmap.hh:90 RangeHint::mergeWith
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

    // Ghidra: varmap.cc:321 RangeHint::compare
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

    // Ghidra: varmap.cc:170 RangeHint::attemptJoin
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
    /// Stack growth direction following Ghidra's convention (varmap.cc:700):
    /// `direction = stackGrowsNegative() ? 1 : -1`. **`direction==1` is the
    /// normal negative-growth (x86) case.** This matches Ghidra exactly;
    /// `has_local_alias` (varmap.cc:721) returns false on `direction==-1`.
    direction: i32,
    /// Whether the alias calculation has been performed.
    calculated: bool,
}

impl AliasChecker {
    /// The "infinitely far" boundary, so the first real alias always wins.
    /// Ghidra initialises `localExtreme` from `space->getHighest()`.
    const LOCAL_EXTREME: u64 = u64::MAX;

    // Ghidra: varmap.hh:137 AliasChecker::new
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

    // Ghidra: varmap.cc:633 AliasChecker::deriveBoundaries
    /// Configure local/parameter boundaries from a function prototype.
    /// Corresponds to `AliasChecker::deriveBoundaries` (varmap.cc ~590).
    /// For a negative-growing stack the locals occupy offsets below
    /// `local_boundary`; the parameter region is above it.
    pub fn derive_boundaries(&mut self, local_boundary: u64) {
        self.local_boundary = local_boundary;
    }

    // Ghidra: varmap.cc:660 AliasChecker::gatherInternal
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

    // Ghidra: varmap.cc:741 AliasChecker::gatherAdditiveBase
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

    // Ghidra: varmap.hh:137 AliasChecker::sortAliases
    fn sort_aliases(&mut self) {
        self.aliases.sort();
    }

    // Ghidra: varmap.cc:711 AliasChecker::hasLocalAlias
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

    // Ghidra: varmap.hh:137 AliasChecker::getAliases
    pub fn get_aliases(&self) -> &[u64] {
        &self.aliases
    }

    // Ghidra: varmap.hh:137 AliasChecker::getAddBase
    pub fn get_add_base(&self) -> &[AddBase] {
        &self.add_base
    }
}

// Ghidra: varmap.hh:137 AliasChecker::findSpacebaseInput
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

/// RSP register identity: Register space, offset 0x20, size 8.
const RSP_SPACE: crate::space::AddressSpace = crate::space::AddressSpace::Register;
const RSP_OFFSET: u64 = 0x20;
const RSP_SIZE: usize = 8;

// Ghidra: varmap.hh:137 AliasChecker::resolveRspOffset
/// Resolve whether an address varnode is RSP-derived, returning the raw stack
/// offset (relative to RSP) and whether the pointer was writable.
///
/// Handles additive chains rooted at RSP, which is how Rugra's lift encodes
/// stack accesses — including the common frame-base pattern:
///   - `INT_ADD(frame_base, const)` where `frame_base = INT_SUB(RSP, frame_size)`
///     → offset = const - frame_size (relative to RSP)
///   - `INT_ADD(RSP, const)`  → +const
///   - `INT_SUB(RSP, const)`  → -const (two's complement as u64)
///   - `RSP` directly         → 0
///
/// This mirrors Ghidra's Stack-spacebase address resolution: the offset is
/// relative to the spacebase (RSP), which is what `get_stack_variable_name`
/// in printc also queries.
fn resolve_rsp_offset(addr: &Arc<RwLock<Varnode>>) -> Option<(u64, bool)> {
    resolve_rsp_offset_signed(addr).map(|(off, w)| (off as u64, w))
}

// Ghidra: varmap.hh:137 AliasChecker::resolveRspOffsetViaBank
/// Like `resolve_rsp_offset`, but when the addr varnode's def chain is broken
/// (def=None — inject creates fresh def-less input varnodes), fall back to a
/// spatial lookup: find a def-carrying varnode at the same (space, offset) and
/// resolve through that. This bridges the SSA-def gap for spacebase resolution
/// WITHOUT mutating any varnode (preserving SSA identity that global
/// def-linking perturbed). Scoped to varmap only — typeop/copyprop are
/// unaffected, avoiding the struct-pointer regressions global linking caused.
fn resolve_rsp_offset_via_bank(
    addr: &Arc<RwLock<Varnode>>,
    fd: &crate::funcdata::Funcdata,
) -> Option<(u64, bool)> {
    if let Some(r) = resolve_rsp_offset(addr) {
        return Some(r);
    }
    let (size, loc, space) = {
        let a = addr.read().unwrap();
        (a.get_size(), a.loc, a.get_space())
    };
    if !matches!(space, crate::space::AddressSpace::Unique | crate::space::AddressSpace::Register) {
        return None;
    }
    for entry in fd.vbank.loc_tree.iter() {
        let v = entry.0.read().unwrap();
        if v.get_size() == size && v.loc == loc && v.get_space() == space && v.is_written() {
            drop(v);
            if let Some(r) = resolve_rsp_offset(&entry.0) {
                return Some(r);
            }
        }
    }
    None
}

// Ghidra: varmap.hh:137 AliasChecker::resolveRspOffsetSigned
/// Signed-offset variant: returns the offset relative to RSP as i64, then the
/// caller masks to u64. This lets additive chains compose correctly.
fn resolve_rsp_offset_signed(addr: &Arc<RwLock<Varnode>>) -> Option<(i64, bool)> {
    let a = addr.read().unwrap();
    // Direct RSP reference.
    if a.get_space() == RSP_SPACE && a.get_offset() == RSP_OFFSET && a.get_size() == RSP_SIZE {
        return Some((0, true));
    }
    let def = match a.def.as_ref().and_then(|w| w.upgrade()) {
        Some(d) => d,
        None => return None,
    };
    drop(a);
    let op = def.read().unwrap();
    match op.opcode {
        OpCode::CPUI_INT_ADD => {
            let in0 = op.inrefs.first()?;
            let in1 = op.inrefs.get(1)?;
            // Try: this = base + term, where base is RSP-derived and term is const.
            let base_off = resolve_rsp_offset_signed(in0);
            let term_const = {
                let i1 = in1.read().unwrap();
                if i1.is_constant() {
                    Some(i1.get_offset() as i64)
                } else {
                    None
                }
            };
            drop(op);
            match (base_off, term_const) {
                (Some((bo, w)), Some(tc)) => Some((bo.wrapping_add(tc), w)),
                _ => None,
            }
        }
        OpCode::CPUI_INT_SUB => {
            let in0 = op.inrefs.first()?;
            let in1 = op.inrefs.get(1)?;
            let base_off = resolve_rsp_offset_signed(in0);
            let term_const = {
                let i1 = in1.read().unwrap();
                if i1.is_constant() {
                    Some(i1.get_offset() as i64)
                } else {
                    None
                }
            };
            drop(op);
            match (base_off, term_const) {
                (Some((bo, w)), Some(tc)) => Some((bo.wrapping_sub(tc), w)),
                _ => None,
            }
        }
        // COPY chains may carry an RSP-derived pointer.
        OpCode::CPUI_COPY => {
            let in0 = op.inrefs.first()?.clone();
            drop(op);
            resolve_rsp_offset_signed(&in0)
        }
        _ => None,
    }
}

// Ghidra: varmap.hh:137 AliasChecker::makeIntType
/// Build a small unsigned int Datatype of the given size for RangeHint typing.
/// Ghidra uses the TypeFactory to getBase(size, TYPE_UNKNOWN); we approximate
/// with an Unknown-metatype base type so the size is preserved and varmap can
/// reconcile it with real types later.
fn make_int_type(size: usize) -> Arc<Datatype> {
    Arc::new(Datatype::Base(crate::type_system::datatype::TypeBase::new(
        "unknown".to_string(),
        size,
        TypeMetatype::Unknown,
    )))
}

// Ghidra: varmap.cc:817 AliasChecker::gatherOffset
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
    // Ghidra: varmap.cc:864 MapState::new
    pub fn new(local_start: u64, local_end: u64) -> Self {
        Self {
            maplist: Vec::new(),
            iter_pos: 0,
            default_type: None,
            local_start,
            local_end,
        }
    }

    // Ghidra: varmap.cc:864 MapState::newWithDefault
    /// Construct with a default type used when a gathered varnode has no type.
    pub fn new_with_default(local_start: u64, local_end: u64,
                            default_type: Arc<Datatype>) -> Self {
        Self {
            maplist: Vec::new(),
            iter_pos: 0,
            default_type: Some(default_type),
            local_start,
            local_end,
        }
    }

    // Ghidra: varmap.cc:896 MapState::addRange
    /// Add a range hint. Faithful to `MapState::addRange` (varmap.cc:896).
    /// `high_ind` is the biggest guaranteed index for open-range hints
    /// (-1 if not an array reference).
    pub fn add_range(&mut self, start: u64, dtype: Option<Arc<Datatype>>, flags: u32,
                     rt: RangeType, high_ind: i32) {
        let dtype = dtype.or_else(|| self.default_type.clone());
        let size = dtype.as_ref().map_or(1, |d| d.get_size() as i32);
        if size <= 0 { return; }
        // Check if in local range.
        if start < self.local_start || start >= self.local_end { return; }
        let sstart = start as i64;
        self.maplist.push(RangeHint::new(start, size, sstart, dtype, flags, rt, high_ind));
    }

    // Ghidra: varmap.cc:926 MapState::addFixedType
    /// Add a fixed type reference from a varnode.
    /// Corresponds to MapState::addFixedType (varmap.cc:926).
    pub fn add_fixed_type(&mut self, start: u64, dtype: Option<Arc<Datatype>>, flags: u32) {
        self.add_range(start, dtype, flags, RangeType::Fixed, -1);
    }

    // Ghidra: varmap.cc:864 MapState::hintCount
    /// Number of RangeHints collected so far (diagnostic).
    pub fn hint_count(&self) -> usize {
        self.maplist.len()
    }

    // Ghidra: varmap.cc:1088 MapState::isReadActive
    /// Filter out INDIRECT/MULTIEQUAL/PIECE ops that just copy between the same
    /// storage location. If another op actively reads `vn`, return true.
    /// Faithful to `MapState::isReadActive` (varmap.cc:1088).
    fn is_read_active(vn: &Arc<RwLock<Varnode>>) -> bool {
        let descend_refs: Vec<_> = {
            let v = vn.read().unwrap();
            v.descend.iter().filter_map(|w| w.upgrade()).collect()
        };
        let vn_addr = {
            let v = vn.read().unwrap();
            (v.get_space(), v.get_offset())
        };
        for op_ref in descend_refs {
            let op = op_ref.read().unwrap();
            let is_marker = matches!(op.opcode, OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INDIRECT);
            if is_marker {
                if let Some(out) = op.output.as_ref() {
                    let o = out.read().unwrap();
                    let out_addr = (o.get_space(), o.get_offset());
                    if vn_addr != out_addr {
                        return true;
                    }
                }
            } else {
                // Non-marker op reading vn → active by definition.
                return true;
            }
        }
        false
    }

    // Ghidra: varmap.cc:1124 MapState::gatherVarnodes
    /// Gather varnodes from the function's vbank.
    /// Faithful to `MapState::gatherVarnodes` (varmap.cc:1124).
    pub fn gather_varnodes(&mut self, fd: &crate::funcdata::Funcdata) {
        for vn_arc in &fd.vbank.loc_tree {
            let vn = vn_arc.0.read().unwrap();
            if vn.is_free() {
                continue;
            }
            // Only gather stack-space varnodes.
            if vn.get_space() != crate::space::AddressSpace::Stack {
                continue;
            }
            let offset = vn.get_offset();
            let dtype = vn.v_type.clone();

            if vn.def.is_none() {
                // Unwritten (input) varnode.
                drop(vn);
                if Self::is_read_active(&vn_arc.0) {
                    self.add_fixed_type(offset, dtype, 0);
                }
                continue;
            }

            let def_arc = match vn.def.as_ref().and_then(|w| w.upgrade()) {
                Some(d) => d,
                None => continue,
            };
            drop(vn);
            let def_op = def_arc.read().unwrap();
            match def_op.opcode {
                OpCode::CPUI_INDIRECT => {
                    let invn = def_op.inrefs.first().cloned();
                    drop(def_op);
                    let same_addr = match invn {
                        Some(inv) => {
                            let iv = inv.read().unwrap();
                            iv.get_space() == crate::space::AddressSpace::Stack
                                && iv.get_offset() == offset
                        }
                        None => false,
                    };
                    if !same_addr || Self::is_read_active(&vn_arc.0) {
                        self.add_fixed_type(offset, dtype, 0);
                    }
                }
                OpCode::CPUI_MULTIEQUAL => {
                    // Only add if not just copying to the same storage.
                    let mut same_all = true;
                    for invn in &def_op.inrefs {
                        let iv = invn.read().unwrap();
                        if iv.get_space() != crate::space::AddressSpace::Stack
                            || iv.get_offset() != offset
                        {
                            same_all = false;
                            break;
                        }
                    }
                    drop(def_op);
                    if !same_all || Self::is_read_active(&vn_arc.0) {
                        self.add_fixed_type(offset, dtype, 0);
                    }
                }
                OpCode::CPUI_COPY => {
                    let is_const = def_op
                        .inrefs
                        .first()
                        .map(|i| i.read().unwrap().is_constant())
                        .unwrap_or(false);
                    drop(def_op);
                    let flags = if is_const { range_flags::COPY_CONSTANT } else { 0 };
                    self.add_fixed_type(offset, dtype, flags);
                }
                _ => {
                    drop(def_op);
                    self.add_fixed_type(offset, dtype, 0);
                }
            }
        }
    }

    // Ghidra: varmap.cc:864 MapState::gatherSpacebase
    /// Gather stack-space references by promoting the stack spacebase.
    ///
    /// Rugra's x86 lift does not produce Stack-space varnodes: RSP-relative
    /// memory accesses are emitted as `INT_ADD(RSP, off) → LOAD/STORE`. Ghidra,
    /// by contrast, resolves these through its Stack address space (whose
    /// spacebase is the stack pointer), so `MapState::gatherVarnodes` naturally
    /// sees Stack-space varnodes. This method is the faithful equivalent: it
    /// scans every LOAD/STORE whose address is RSP-derived and synthesizes a
    /// fixed RangeHint at the (raw) stack offset, sized to the access.
    ///
    /// Corresponds to the Stack-spacebase resolution Ghidra performs via
    /// `ActionSpacebase` + the spacebase input varnode.
    pub fn gather_spacebase(&mut self, fd: &crate::funcdata::Funcdata) {
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            match op.opcode {
                OpCode::CPUI_LOAD => {
                    // LOAD(space_id, addr) -> out. Resolve addr to a stack offset.
                    if op.inrefs.len() < 2 {
                        continue;
                    }
                    let out_size = op.output.as_ref().map(|o| o.read().unwrap().get_size());
                    let addr_vn = op.inrefs[1].clone();
                    if let Some((off, _writable)) = resolve_rsp_offset_via_bank(&addr_vn, fd) {
                        let size = out_size.unwrap_or(1);
                        let dtype = make_int_type(size);
                        self.add_fixed_type(off, Some(dtype), 0);
                    }
                }
                OpCode::CPUI_STORE => {
                    // STORE(space_id, addr, value). Resolve addr to a stack offset.
                    if op.inrefs.len() < 3 {
                        continue;
                    }
                    let val_size = op.inrefs[2].read().unwrap().get_size();
                    let addr_vn = op.inrefs[1].clone();
                    if let Some((off, _writable)) = resolve_rsp_offset_via_bank(&addr_vn, fd) {
                        let dtype = make_int_type(val_size);
                        let is_const = op.inrefs[2].read().unwrap().is_constant();
                        let flags = if is_const { range_flags::COPY_CONSTANT } else { 0 };
                        self.add_fixed_type(off, Some(dtype), flags);
                    }
                }
                _ => {}
            }
        }
    }

    // Ghidra: varmap.cc:1211 MapState::gatherOpen
    /// Gather open (pointer-referenced) ranges. Faithful to
    /// `MapState::gatherOpen` (varmap.cc:1211): for each additive base root,
    /// if its type is a pointer, create an open RangeHint sized to the
    /// pointee; use minItems=3 if an index varnode is present.
    pub fn gather_open(&mut self, fd: &crate::funcdata::Funcdata, checker: &AliasChecker) {
        let addbase = checker.get_add_base();
        let aliases = checker.get_aliases();
        for (i, entry) in addbase.iter().enumerate() {
            let offset = aliases.get(i).copied().unwrap_or(0);
            let ct: Option<Arc<Datatype>> = {
                let base_vn = entry.base.read().unwrap();
                base_vn.v_type.clone()
            };
            // If pointer, descend to pointee; if pointee is array, descend to base.
            let pointee = ct.and_then(|t| match t.as_ref() {
                Datatype::Pointer(p) => Some(p.ptr_to.clone()),
                _ => None,
            });
            let final_dt: Arc<Datatype> = match &pointee {
                Some(p) => match p.as_ref() {
                    Datatype::Array(a) => a.array_of.clone(),
                    _ => p.clone(),
                },
                None => Arc::new(Datatype::Base(
                    crate::type_system::datatype::TypeBase::new(
                        "unknown".into(), 1, TypeMetatype::Unknown,
                    ),
                )),
            };
            let min_items: i32 = if entry.index.is_some() { 3 } else { -1 };
            self.add_range(offset, Some(final_dt), 0, RangeType::Open, min_items);
        }
        // LoadGuard/StoreGuard handling (varmap.cc:1241-1248) is omitted until
        // Rugra wires LoadGuard into Funcdata for the stack space; the additive
        // base trace above already captures the dominant alias sources.
    }

    // Ghidra: varmap.cc:1063 MapState::initialize
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

    // Ghidra: varmap.cc:864 MapState::nextHint
    /// Get next range hint (for restructuring iteration).
    pub fn next_hint(&self) -> Option<&RangeHint> {
        self.maplist.get(self.iter_pos)
    }

    // Ghidra: varmap.cc:864 MapState::getNext
    /// Advance iterator and return true if there's another hint.
    pub fn get_next(&mut self) -> bool {
        self.iter_pos += 1;
        self.iter_pos < self.maplist.len()
    }

    // Ghidra: varmap.cc:864 MapState::resetIter
    /// Reset iterator.
    pub fn reset_iter(&mut self) {
        self.iter_pos = 0;
    }

    // Ghidra: varmap.cc:864 MapState::isEmpty
    pub fn is_empty(&self) -> bool {
        self.maplist.is_empty()
    }

    // Ghidra: varmap.cc:864 MapState::len
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
#[derive(Debug, Clone)]
pub struct ScopeLocal {
    /// The restructured local symbols
    pub symbols: Vec<LocalSymbol>,
    /// Whether restructuring had overlap problems
    pub overlap_problems: bool,
    /// Stack growth direction following Ghidra's convention (varmap.cc:700):
    /// `direction = stackGrowsNegative() ? 1 : -1`. So `1` = negative growth
    /// (typical x86-64), `-1` = positive growth. **This field's sign matches
    /// Ghidra's `AliasChecker::direction` exactly — do not flip it.**
    pub stack_direction: i32,
}

impl ScopeLocal {
    // Ghidra: varmap.cc:341 ScopeLocal::new
    // Per varmap.cc:700 (`direction = stackGrowsNegative() ? 1 : -1`), the
    // default for a typical x86-64 binary is negative growth → direction == 1.
    // Previously this was -1, which inverted Ghidra's convention and made
    // `has_local_alias` (varmap.cc:721) always return false on x86, silently
    // disabling alias analysis. See docs/alignment_audit/INDEX.md P0-1.
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
            overlap_problems: false,
            stack_direction: 1,
        }
    }

    // Ghidra: varmap.cc:510 ScopeLocal::markNotMapped
    /// Mark a specific stack address range as not mapped. Faithful to
    /// `ScopeLocal::markNotMapped` (varmap.cc:510-546). Removes any symbols
    /// overlapping the given range. Used by ActionRestrictLocal to prevent
    /// specific stack locations (e.g. saved registers, call params) from
    /// being treated as local variables.
    pub fn mark_not_mapped(&mut self, offset: u64, size: i32, _parameter: bool) {
        let last = offset + size as u64 - 1;
        // Remove any symbols whose range overlaps [offset, last].
        self.symbols.retain(|sym| {
            let sym_start = sym.start;
            let sym_end = sym.start + sym.size as u64 - 1;
            // No overlap if sym_end < offset or sym_start > last
            !(sym_end >= offset && sym_start <= last)
        });
    }

    // Ghidra: varmap.cc:341 ScopeLocal::hasOverlap
    /// Check if a stack address range overlaps any symbol. Used by
    /// ActionRestrictLocal to verify storage locations.
    pub fn has_overlap(&self, offset: u64, size: i32) -> bool {
        let last = offset + size as u64 - 1;
        self.symbols.iter().any(|sym| {
            let sym_end = sym.start + sym.size as u64 - 1;
            sym_end >= offset && sym.start <= last
        })
    }

    // Ghidra: varmap.cc:341 ScopeLocal::queryByAddr
    /// Find the LocalSymbol whose storage range contains `(offset, offset+size)`.
    /// Faithful to `ScopeLocal::queryByAddr` / `Scope::findContainer`.
    /// Returns the symbol and the offset within the symbol (for partial reads).
    pub fn query_by_addr(&self, offset: u64, size: i32) -> Option<(&LocalSymbol, i32)> {
        let last = offset + size as u64 - 1;
        for sym in &self.symbols {
            let sym_end = sym.start + sym.size as u64 - 1;
            if sym.start <= offset && sym_end >= last {
                return Some((sym, (offset - sym.start) as i32));
            }
        }
        None
    }

    // Ghidra: varmap.cc:1256 ScopeLocal::restructureVarnode
    /// Restructure the stack frame from varnodes.
    /// Main entry point. Faithful to `ScopeLocal::restructureVarnode`
    /// (varmap.cc:1256).
    pub fn restructure_varnode(&mut self, fd: &crate::funcdata::Funcdata) {
        // Clear existing symbols.
        self.symbols.clear();
        self.overlap_problems = false;

        // Determine local range. Ghidra derives this from the prototype's
        // getRangeTree/getParamRange; Rugra uses the full stack extent.
        let local_start = 0u64;
        let local_end = 0x100000u64;

        // Build the MapState with a default unknown base type (1 byte),
        // matching Ghidra's glb->types->getBase(1, TYPE_UNKNOWN).
        let default_type = Arc::new(Datatype::Base(
            crate::type_system::datatype::TypeBase::new("unknown".into(), 1, TypeMetatype::Unknown),
        ));
        let mut state = MapState::new_with_default(local_start, local_end, default_type);
        state.gather_varnodes(fd);
        state.gather_spacebase(fd);

        // Gather alias info.
        let mut checker = AliasChecker::new(self.stack_direction);
        checker.gather_internal(fd);
        let aliases = checker.get_aliases().to_vec();

        // Gather open (pointer-referenced) ranges.
        state.gather_open(fd, &checker);

        // Restructure: merge overlapping ranges into disjoint symbols.
        self.overlap_problems = self.restructure(&mut state);

        // Mark unaliased symbols.
        self.mark_unaliased(&aliases);

        // Build fake input symbols for parameters.
        self.fake_input_symbols(fd);
    }

    // Ghidra: varmap.cc:1294 ScopeLocal::restructure
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
                // No intersection — finalize current range.
                if !current.attempt_join(&next) {
                    // Adjust open ranges to span up to the next hint.
                    if current.range_type == RangeType::Open {
                        current.size = (next.start.wrapping_sub(current.start)) as i32;
                    }
                    // Faithful to ScopeLocal::restructure (varmap.cc:1316):
                    // only create an entry if the range fits.
                    if self.adjust_fit(&mut current) {
                        self.create_entry(&current);
                    }
                    current = next;
                }
            }
        }

        overlap_problems
    }

    // Ghidra: varmap.cc:587 ScopeLocal::adjustFit
    /// Shrink the RangeHint as necessary so it fits in the mapped region and
    /// does not overlap an existing Symbol. Faithful to
    /// `ScopeLocal::adjustFit` (varmap.cc:587). Returns true if a valid
    /// adjustment was made.
    fn adjust_fit(&self, a: &mut RangeHint) -> bool {
        if a.size == 0 {
            return false;
        }
        if a.is_type_lock() {
            return false; // Already entered.
        }
        // Check for overlap with an existing symbol. Rugra does not model
        // getRangeTree/longestFit, so we only guard against symbol overlaps.
        if let Some(existing) = self.find_symbol(a.start) {
            if existing.start <= a.start {
                return false;
            }
            let maxsize = existing.start - a.start;
            let type_size = a.dtype.as_ref().map(|d| d.get_size()).unwrap_or(1) as i64;
            if (maxsize as i64) < type_size {
                return false; // Can't shrink for this type.
            }
            a.size = maxsize as i32;
        }
        true
    }

    // Ghidra: varmap.cc:617 ScopeLocal::createEntry
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

    // Ghidra: varmap.cc:548 ScopeLocal::buildVariableName
    /// Build a variable name from stack offset. Faithful to
    /// `ScopeLocal::buildVariableName` (varmap.cc:548).
    ///
    /// Ghidra produces names of the form `<SpaceName>[X|Y]_<hex>` where:
    ///   - the space name is capitalised ("Stack")
    ///   - 'X' marks local stack space allocated by the caller (start <= 0
    ///     after sign-extension and negation for negative-growing stacks)
    ///   - otherwise a plain hex offset follows '_'
    fn build_variable_name(&self, offset: u64) -> String {
        // Sign-extend the offset to the address size, then for a negative-growing
        // stack negate it (varmap.cc:558).
        let mut start = offset as i64;
        // Treat as signed within 64 bits; for negative growth, locals live at
        // high (unsigned) offsets which become small negatives.
        // Per varmap.cc:700, `direction==1` is the negative-growth case.
        if self.stack_direction == 1 {
            // stackGrowsNegative → start = -start
            start = -start;
        }
        let mut name = String::from("Stack");
        if start <= 0 {
            name.push('X'); // Local stack space allocated by caller.
            start = -start;
        }
        name.push('_');
        name.push_str(&format!("{:x}", start as u64));
        name
    }

    // Ghidra: varmap.cc:1332 ScopeLocal::markUnaliased
    /// Mark symbols as unaliased based on alias starting offsets.
    /// Faithful to `ScopeLocal::markUnaliased` (varmap.cc:1332).
    ///
    /// For each symbol, walk the sorted alias offsets: once an alias offset
    /// reaches or passes the symbol's end, aliasing is "on" for that symbol.
    /// A symbol far enough (0xffff bytes) past the last alias boundary is
    /// considered unaliased (varmap.cc:1374). Locked struct/array types can
    /// block aliasing, but Rugra does not yet model `alias_block_level`, so
    /// only the distance heuristic is applied here.
    fn mark_unaliased(&mut self, aliases: &[u64]) {
        if aliases.is_empty() {
            // No aliases → all unaliased.
            for sym in &mut self.symbols {
                sym.unaliased = true;
            }
            return;
        }

        for sym in &mut self.symbols {
            let curoff = sym.start.wrapping_add(sym.size as u64).wrapping_sub(1);
            // Find the largest alias offset <= curoff.
            let mut aliason = false;
            let mut curalias = 0u64;
            for &a in aliases {
                if a <= curoff {
                    aliason = true;
                    curalias = a;
                }
            }
            // Distance heuristic: far enough past the last alias → unaliased.
            if aliason && curoff.saturating_sub(curalias) > 0xffff {
                aliason = false;
            }
            sym.unaliased = !aliason;
        }
    }

    // Ghidra: varmap.cc:1392 ScopeLocal::fakeInputSymbols
    /// Create fake input symbols for stack-space input Varnodes that are not
    /// part of the formal prototype. Faithful to
    /// `ScopeLocal::fakeInputSymbols` (varmap.cc:1392).
    ///
    /// Ghidra scans `fd->beginDef(input)` for stack-space inputs, coalesces
    /// adjacent ones, and creates a fake-input symbol of unknown type. Rugra
    /// approximates this by scanning stack-space input varnodes (no defining
    /// op) in the vbank.
    fn fake_input_symbols(&mut self, fd: &crate::funcdata::Funcdata) {
        // Collect (offset, size) of stack-space input varnodes, sorted by offset.
        let mut inputs: Vec<(u64, i32)> = Vec::new();
        for vn_arc in &fd.vbank.loc_tree {
            let vn = vn_arc.0.read().unwrap();
            if vn.is_free() {
                continue;
            }
            if vn.get_space() != crate::space::AddressSpace::Stack {
                continue;
            }
            if vn.def.is_some() {
                continue; // Only inputs (no defining op).
            }
            inputs.push((vn.get_offset(), vn.get_size() as i32));
        }
        inputs.sort();

        // Coalesce adjacent/overlapping inputs (varmap.cc:1408-1419).
        let mut i = 0;
        while i < inputs.len() {
            let (addr, sz) = inputs[i];
            let mut endpoint = addr + sz as u64 - 1;
            let mut j = i + 1;
            while j < inputs.len() {
                let (off2, sz2) = inputs[j];
                if endpoint < off2 {
                    break;
                }
                let new_endpoint = off2 + sz2 as u64 - 1;
                if endpoint < new_endpoint {
                    endpoint = new_endpoint;
                }
                j += 1;
            }
            let size = (endpoint - addr + 1) as i32;
            self.symbols.push(LocalSymbol {
                name: format!("param_{:x}", addr),
                start: addr,
                size,
                dtype: Some(Arc::new(Datatype::Base(
                    crate::type_system::datatype::TypeBase::new(
                        "unknown".into(), size as usize, TypeMetatype::Unknown,
                    ),
                ))),
                unaliased: true,
                is_param: true,
            });
            i = j;
        }
    }

    // Ghidra: varmap.cc:341 ScopeLocal::findSymbol
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

    // --- ScopeLocal.build_variable_name (varmap.cc:548) ---

    #[test]
    fn test_build_variable_name_negative_stack() {
        let scope = ScopeLocal::new(); // stack_direction == 1 (negative growth, x86)
        // For a negative-growing stack, a high unsigned offset (a local) maps
        // to a negative signed value, which is negated to positive magnitude.
        // offset = 0xfffffffffffffff0 → sign-extended -16 → negated +16 → "Stack_10".
        let name = scope.build_variable_name(0xfffffffffffffff0);
        assert_eq!(name, "Stack_10");
        // A small positive offset (parameter region) → negated to negative → 'X'.
        let name2 = scope.build_variable_name(0x10);
        assert!(name2.starts_with("StackX_"), "got {}", name2);
    }

    #[test]
    fn test_build_variable_name_positive() {
        let mut scope = ScopeLocal::new();
        scope.stack_direction = -1; // positive growth → no negation
        // offset 0x10 → start = 0x10 > 0 → plain "Stack_10".
        let name = scope.build_variable_name(0x10);
        assert_eq!(name, "Stack_10");
    }

    // --- ScopeLocal.mark_unaliased (varmap.cc:1332) distance heuristic ---

    #[test]
    fn test_mark_unaliased_no_aliases() {
        let mut scope = ScopeLocal::new();
        scope.symbols.push(LocalSymbol {
            name: "a".into(), start: 0, size: 4,
            dtype: None, unaliased: false, is_param: false,
        });
        scope.mark_unaliased(&[]);
        assert!(scope.symbols[0].unaliased);
    }

    #[test]
    fn test_mark_unaliased_near_boundary_aliased() {
        let mut scope = ScopeLocal::new();
        // Symbol [0,8), alias at offset 4 → curoff=7, alias<=7 → aliased,
        // and distance (7-4)=3 <= 0xffff → stays aliased.
        scope.symbols.push(LocalSymbol {
            name: "a".into(), start: 0, size: 8,
            dtype: None, unaliased: false, is_param: false,
        });
        scope.mark_unaliased(&[4]);
        assert!(!scope.symbols[0].unaliased);
    }

    #[test]
    fn test_mark_unaliased_far_past_boundary_unaliased() {
        let mut scope = ScopeLocal::new();
        // Symbol [0x20000, 4), alias at offset 4 → curoff=0x20003,
        // distance = 0x20003-4 > 0xffff → unaliased (distance heuristic).
        scope.symbols.push(LocalSymbol {
            name: "a".into(), start: 0x20000, size: 4,
            dtype: None, unaliased: false, is_param: false,
        });
        scope.mark_unaliased(&[4]);
        assert!(scope.symbols[0].unaliased);
    }

    // --- ScopeLocal.restructure via adjust_fit (varmap.cc:1294, 587) ---

    #[test]
    fn test_restructure_two_disjoint_ranges() {
        // Build a MapState manually with two non-overlapping fixed int4 ranges.
        let mut state = MapState::new(0, 0x100000);
        let int_t = int_dt(4, TypeMetatype::Int);
        state.add_range(0, Some(int_t.clone()), 0, RangeType::Fixed, -1);
        state.add_range(16, Some(int_t), 0, RangeType::Fixed, -1);

        let mut scope = ScopeLocal::new();
        let overlap = scope.restructure(&mut state);
        assert!(!overlap);
        // Two disjoint symbols created.
        assert_eq!(scope.symbols.len(), 2);
        assert_eq!(scope.symbols[0].start, 0);
        assert_eq!(scope.symbols[0].size, 4);
        assert_eq!(scope.symbols[1].start, 16);
        assert_eq!(scope.symbols[1].size, 4);
    }

    #[test]
    fn test_restructure_overlapping_same_type_merges() {
        // Two int4 ranges at the same offset → contained, reconcile true,
        // preferred → absorb (no new symbol, size stays 4).
        let mut state = MapState::new(0, 0x100000);
        let int_t = int_dt(4, TypeMetatype::Int);
        state.add_range(0, Some(int_t.clone()), 0, RangeType::Fixed, -1);
        state.add_range(0, Some(int_t), 0, RangeType::Fixed, -1);

        let mut scope = ScopeLocal::new();
        let _overlap = scope.restructure(&mut state);
        // The merged range is emitted once at the finalization step; with the
        // endpoint added by initialize(), the single merged int4 is emitted.
        assert_eq!(scope.symbols.len(), 1);
        assert_eq!(scope.symbols[0].start, 0);
        assert_eq!(scope.symbols[0].size, 4);
    }

    // --- resolve_rsp_offset (Stack-spacebase resolution) ---

    /// Build a minimal varnode/op graph for spacebase tests. Returns the
    /// address varnode plus the ops that must be kept alive (so the Weak def
    /// links resolve) for the duration of the test.
    fn build_rsp_chain() -> (
        Arc<RwLock<Varnode>>,
        Vec<std::sync::Arc<RwLock<PcodeOp>>>,
    ) {
        use crate::address::SeqNum;
        let mkseq = || SeqNum::new(crate::address::Address::new(0x1000), 0);
        // RSP input varnode: Register@0x20 size 8.
        let rsp = Arc::new(RwLock::new(
            Varnode::new_with_space(8, crate::space::AddressSpace::Register, 0x20),
        ));
        // frame_size const = 0x40
        let fs = Arc::new(RwLock::new(Varnode::new_constant(0x40, 8)));
        // INT_SUB(RSP, 0x40) → frame_base (Unique tmp)
        let frame_base = Arc::new(RwLock::new(
            Varnode::new_unique(0x1000, 8),
        ));
        let sub_op = Arc::new(RwLock::new(PcodeOp::new(mkseq(), OpCode::CPUI_INT_SUB)));
        {
            let mut so = sub_op.write().unwrap();
            so.inrefs.push(rsp.clone());
            so.inrefs.push(fs.clone());
            so.output = Some(frame_base.clone());
        }
        frame_base.write().unwrap().def = Some(Arc::downgrade(&sub_op));

        // INT_ADD(frame_base, 0x18) → addr
        let disp = Arc::new(RwLock::new(Varnode::new_constant(0x18, 8)));
        let addr = Arc::new(RwLock::new(Varnode::new_unique(0x2000, 8)));
        let add_op = Arc::new(RwLock::new(PcodeOp::new(mkseq(), OpCode::CPUI_INT_ADD)));
        {
            let mut ao = add_op.write().unwrap();
            ao.inrefs.push(frame_base.clone());
            ao.inrefs.push(disp.clone());
            ao.output = Some(addr.clone());
        }
        addr.write().unwrap().def = Some(Arc::downgrade(&add_op));
        (addr, vec![sub_op, add_op])
    }

    #[test]
    fn test_resolve_rsp_offset_frame_base_chain() {
        // addr = INT_ADD(INT_SUB(RSP, 0x40), 0x18) → offset = 0x18 - 0x40 = -0x28
        let (addr, _ops) = build_rsp_chain();
        let off = resolve_rsp_offset_signed(&addr);
        assert!(off.is_some(), "should resolve RSP-derived chain");
        let (signed_off, _writable) = off.unwrap();
        assert_eq!(signed_off, -0x28i64);
    }

    #[test]
    fn test_resolve_rsp_offset_direct_add() {
        use crate::address::SeqNum;
        // INT_ADD(RSP, 0x10) → +0x10
        let rsp = Arc::new(RwLock::new(
            Varnode::new_with_space(8, crate::space::AddressSpace::Register, 0x20),
        ));
        let disp = Arc::new(RwLock::new(Varnode::new_constant(0x10, 8)));
        let addr = Arc::new(RwLock::new(Varnode::new_unique(0x3000, 8)));
        let add_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(crate::address::Address::new(0x1000), 0),
            OpCode::CPUI_INT_ADD,
        )));
        {
            let mut ao = add_op.write().unwrap();
            ao.inrefs.push(rsp.clone());
            ao.inrefs.push(disp.clone());
            ao.output = Some(addr.clone());
        }
        addr.write().unwrap().def = Some(Arc::downgrade(&add_op));
        let (signed_off, _w) = resolve_rsp_offset_signed(&addr).unwrap();
        assert_eq!(signed_off, 0x10);
    }

    #[test]
    fn test_resolve_rsp_offset_non_rsp_returns_none() {
        use crate::address::SeqNum;
        // INT_ADD(RIP@0x200, 0x10) → NOT stack-relative → None
        let rip = Arc::new(RwLock::new(
            Varnode::new_with_space(8, crate::space::AddressSpace::Register, 0x200),
        ));
        let disp = Arc::new(RwLock::new(Varnode::new_constant(0x10, 8)));
        let addr = Arc::new(RwLock::new(Varnode::new_unique(0x4000, 8)));
        let add_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(crate::address::Address::new(0x1000), 0),
            OpCode::CPUI_INT_ADD,
        )));
        {
            let mut ao = add_op.write().unwrap();
            ao.inrefs.push(rip.clone());
            ao.inrefs.push(disp.clone());
            ao.output = Some(addr.clone());
        }
        addr.write().unwrap().def = Some(Arc::downgrade(&add_op));
        assert!(resolve_rsp_offset_signed(&addr).is_none());
    }
}
