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
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::rangemap::{RangeMap, RangeRecord, RangeSubsort};
use crate::type_system::Datatype;
use crate::type_system::TypeMetatype;
use crate::varnode::Varnode;
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

    // Ghidra: varmap.cc:259 RangeHint::merge
    /// Given that this and the other RangeHint intersect, redefine this so that
    /// it becomes the union of the two. Faithful to `RangeHint::merge`
    /// (varmap.cc:259). Returns `Ok(true)` if there was a reconcilable
    /// overlap, `Ok(false)` on the ordinary fall-through paths, and `Err`
    /// for the LowlevelError at varmap.cc:280 (both ranges type-locked and
    /// unreconcilable) — the exception unwinds `ScopeLocal::restructure`
    /// and `restructureVarnode` entirely, so the error text must reach the
    /// caller's abort channel, not a debug log (F3, SCOPE-FINDOVERLAP-KEY-0001).
    /// `types` mirrors the `TypeFactory *typeFactory` parameter of the Ghidra
    /// signature (varmap.hh:124) — consumed only by the resType==2 concede
    /// path (varmap.cc:309).
    pub fn merge_with(
        &mut self,
        b: &RangeHint,
        types: &Arc<RwLock<crate::type_system::typefactory::TypeFactory>>,
    ) -> anyhow::Result<bool> {
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

        // Check for really problematic cases (varmap.cc:277-284): the
        // discard-b guard hangs off `isTypeLock()` alone — a typelocked
        // self with an UNlocked b is discarded whenever the starts differ.
        if !did_reconcile {
            if self.is_type_lock() {
                if b.is_type_lock() {
                    // throw LowlevelError("Overlapping forced variable types : "
                    //   + type->getName() + "   " + b->type->getName());
                    // (varmap.cc:280) — text kept verbatim (colon-space,
                    // three spaces between the names).
                    let n1 = self.dtype.as_ref().map(|d| d.get_name()).unwrap_or("?");
                    let n2 = b.dtype.as_ref().map(|d| d.get_name()).unwrap_or("?");
                    return Err(anyhow::anyhow!(
                        "Overlapping forced variable types : {}   {}",
                        n1,
                        n2
                    ));
                }
                if self.start != b.start {
                    return Ok(false); // Discard b entirely (varmap.cc:281-282)
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
            // Ghidra: type = typeFactory->getBase(size,TYPE_UNKNOWN)
            // (varmap.cc:309) — the factory handle is threaded from
            // ScopeLocal::restructure's `glb->types` (varmap.cc:1309).
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
            self.dtype = Some(make_int_type(types, self.size as usize));
            self.flags = 0;
            self.high_ind = -1;
            return Ok(false);
        }
        Ok(false)
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

// Ghidra: varmap.cc:942 MapState::addFixedType / varmap.cc:1438 ScopeLocal::fakeInputSymbols
/// Resolve the unknown base type of `size` bytes for RangeHint typing.
/// Ghidra draws these from the Architecture TypeFactory
/// (`types->getBase(size,TYPE_UNKNOWN)`, varmap.cc:942/1031/1438); Rugra
/// threads the factory resolved by `ScopeLocal::restructure_varnode`
/// (`fd.arch.types`, else the process-canonical default) so the hint, symbol,
/// and varnode type objects share the factory identity domain.
fn make_int_type(
    types: &Arc<RwLock<crate::type_system::typefactory::TypeFactory>>,
    size: usize,
) -> Arc<Datatype> {
    types
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get_base(size, TypeMetatype::Unknown)
        .expect("factory always produces an unknown base type")
}

// Ghidra: fspec.hh:1540 FuncProto::getParamRange
/// Resolve the stack-parameter range of a Funcdata's prototype the way
/// `fd->getFuncProto().getParamRange()` (fspec.hh:1540) does: it reads the
/// ProtoModel attached to the prototype, and `FuncProto::setScope`
/// (fspec.cc:3879-3885) guarantees a model is attached by falling back to
/// `s->getArch()->defaultfp`. Rugra's `FuncProto` stores only the convention
/// name (`model` is not exposed), so resolve through the Architecture's
/// registry in the same precedence: the prototype's convention name, else
/// the Architecture default model. With no Architecture attached
/// (FUNCPROTO-MODEL-BIND-0001 chain), stand in with the model Ghidra's
/// default constructor would have built — `ProtoModel::defaultParamRange`
/// (fspec.cc:2292) for the process-canonical 8-byte negative-growth stack.
fn func_proto_param_range(
    fd: &crate::funcdata::Funcdata,
) -> crate::address::RangeList {
    if let Some(arch) = &fd.arch {
        let name = fd.get_func_proto().get_model_name();
        if let Some(model) = arch.proto_models.get(name) {
            return model.paramrange.clone();
        }
        if let Some(model) = &arch.defaultfp {
            return model.paramrange.clone();
        }
    }
    crate::fspec::ProtoModelFull::new(Some(crate::space::AddressSpace::Stack), 8).paramrange
}

// Ghidra: address.cc:468 RangeList::inRange
/// Is the single address `offset` contained in the parameter range?
/// Faithful to `RangeList::inRange(addr, 1)` (address.cc:468-487) as invoked
/// at varmap.cc:1407: an invalid address returns true ("we don't really
/// care" — unreachable here, every queried Varnode has a real address), an
/// empty container returns false, otherwise the last range with
/// `first <= offset` must reach `offset + size - 1` (= `offset` for size 1)
/// in the same space. (Rugra's fspec `RangeList` ranges carry no space —
/// they are all stack ranges built from stack pentries / `<range
/// space="stack">`, and every caller of this helper has already filtered
/// `addr.getSpace() == scope space`, so Ghidra's space test is subsumed.)
fn param_range_in_range(paramrange: &crate::address::RangeList, offset: u64) -> bool {
    let ranges = paramrange.ranges();
    if ranges.is_empty() {
        return false;
    }
    // iter = tree.upper_bound(Range(spc,offset,offset)); if (iter ==
    // tree.begin()) return false; --iter; — the last range with first <= offset.
    let mut candidate: Option<&crate::address::Range> = None;
    for range in ranges {
        if range.get_first().as_u64() <= offset {
            candidate = Some(range);
        } else {
            break; // sorted by first
        }
    }
    match candidate {
        Some(range) => range.get_last().as_u64() >= offset,
        None => false,
    }
}

// Ghidra: database.cc:2571 ScopeInternal::makeNameUnique (suffix parsing)
/// Parse the `_NN` (2-digit) or `_xNNNNN` (5-digit) uniquifier suffix that
/// `makeNameUnique` (database.cc:2571-2593) accepts on an existing name:
/// `bname` must be at least `nm.len()+3` chars, hold '_' at `nm.len()`, and
/// then either exactly 2 digits or 'x' plus exactly 5 digits. Returns the
/// parsed id, or None when the name is "not in our format"
/// (uniqid == 0xffffffff upstream).
fn parse_name_unique_suffix(bname: &str, nm: &str) -> Option<u32> {
    let nb = bname.as_bytes();
    let nlen = nm.len();
    if bname.len() < nlen + 3 || nb[nlen] != b'_' {
        return None;
    }
    let mut i = nlen + 1;
    let mut is_x_form = false;
    if nb[i] == b'x' {
        i += 1; // 5 digit form
        is_x_form = true;
    }
    let mut uniqid: u32 = 0;
    let mut dig_count = 0;
    while i < bname.len() {
        let dig = nb[i];
        if !dig.is_ascii_digit() {
            // Everything after '_' must be a digit, or not in our format.
            return None;
        }
        uniqid = uniqid.wrapping_mul(10).wrapping_add((dig - b'0') as u32);
        dig_count += 1;
        i += 1;
    }
    if is_x_form && dig_count != 5 {
        return None; // x form, but not right number of digits
    }
    if !is_x_form && dig_count != 2 {
        return None;
    }
    Some(uniqid)
}

// RUGRA-GLUE: space_name (AddrSpace::getName for Rugra's space enum)
/// Ghidra reads `addr.getSpace()->getName()` (database.cc:2463/2474/2486);
/// Rugra's `AddressSpace` is an enum with the canonical Ghidra space names.
pub fn space_name(space: crate::space::AddressSpace) -> &'static str {
    match space {
        crate::space::AddressSpace::Ram => "ram",
        crate::space::AddressSpace::Register => "register",
        crate::space::AddressSpace::Unique => "unique",
        crate::space::AddressSpace::Const => "const",
        crate::space::AddressSpace::Stack => "stack",
        crate::space::AddressSpace::Join => "join",
        crate::space::AddressSpace::Iop => "iop",
        crate::space::AddressSpace::Overlay => "overlay",
        crate::space::AddressSpace::Other(_) => "other",
    }
}

// RUGRA-GLUE: addr_space_size (AddrSpace::getAddrSize for Rugra's space enum)
/// Ghidra reads `addr.getSpace()->getAddrSize()` to width the hex offset
/// (database.cc:2466/2489: `setw(2*addrSize)`); every Rugra space models an
/// 8-byte address.
fn addr_space_size(_space: crate::space::AddressSpace) -> usize {
    8
}

// RUGRA-GLUE: capitalized_space_name (spacename[0] = toupper(spacename[0]))
/// Capitalize the space name the way database.cc:2464/2487 does
/// (`spacename[0] = toupper(spacename[0])`).
fn capitalized_space_name(space: crate::space::AddressSpace) -> String {
    let name = space_name(space);
    let mut out = String::with_capacity(name.len());
    let mut chars = name.chars();
    if let Some(c) = chars.next() {
        out.extend(c.to_uppercase());
        out.push_str(chars.as_str());
    }
    out
}

// Ghidra: varmap.cc:817 AliasChecker::gatherOffset
/// If the given Varnode is a sum result, return the constant portion of the sum.
/// Faithful to `AliasChecker::gatherOffset` (varmap.cc:817).
///
/// Treats `vn` as the result of a series of ADD operations and sums all the
/// constant terms by traversing the syntax tree backwards through additive ops.
pub fn gather_offset(vn: &Arc<RwLock<Varnode>>) -> u64 {
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
    let mask = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
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
                OpCode::CPUI_PIECE => {
                    // cc:1165-1179: treat PIECE as two COPYs.
                    // slot = addr.isBigEndian() ? 0 : 1  (Rugra x86 = little → slot 1)
                    let in_first = def_op.inrefs.get(1).cloned();
                    let in_second = def_op.inrefs.get(0).cloned();
                    drop(def_op);
                    if let Some(in_first) = &in_first {
                        let iv = in_first.read().unwrap();
                        let iv_space = iv.get_space();
                        let iv_off = iv.get_offset();
                        let iv_size = iv.get_size() as u64;
                        let iv_dtype = iv.v_type.clone();
                        // cc:1171: inFirst->getAddr() != addr
                        let same_addr1 = iv_space == crate::space::AddressSpace::Stack
                            && iv_off == offset;
                        drop(iv);
                        if !same_addr1 {
                            self.add_fixed_type(iv_off, iv_dtype, 0);
                        }
                        // cc:1173: addr = addr + inFirst->getSize()
                        let addr2 = offset.wrapping_add(iv_size);
                        if let Some(in_second) = &in_second {
                            let iv2 = in_second.read().unwrap();
                            let iv2_space = iv2.get_space();
                            let iv2_off = iv2.get_offset();
                            let iv2_dtype = iv2.v_type.clone();
                            // cc:1175: inSecond->getAddr() != addr
                            let same_addr2 = iv2_space == crate::space::AddressSpace::Stack
                                && iv2_off == addr2;
                            drop(iv2);
                            if !same_addr2 {
                                self.add_fixed_type(iv2_off, iv2_dtype, 0);
                            }
                        }
                    }
                    if Self::is_read_active(&vn_arc.0) {
                        self.add_fixed_type(offset, dtype, 0);
                    }
                }
                OpCode::CPUI_SUBPIECE => {
                    // cc:1181-1196: don't treat as active write if just copying
                    // to same storage. trunc depends on endianness.
                    // Little-endian (Rugra x86): trunc = (int4)op->getIn(1)->getOffset();
                    let in0 = def_op.inrefs.first().cloned();
                    let in1_const_off = def_op.inrefs.get(1)
                        .map(|i| i.read().unwrap().get_offset())
                        .unwrap_or(0);
                    drop(def_op);
                    if let Some(in0) = &in0 {
                        let iv = in0.read().unwrap();
                        let iv_space = iv.get_space();
                        let iv_off = iv.get_offset();
                        // little-endian: trunc = in1 offset; addr = iv_off + trunc
                        let trunc = in1_const_off;
                        let addr_off = iv_off.wrapping_add(trunc);
                        drop(iv);
                        // addr != vn->getAddr(): compare space + offset.
                        let same_addr = iv_space == crate::space::AddressSpace::Stack
                            && addr_off == offset;
                        if !same_addr || Self::is_read_active(&vn_arc.0) {
                            self.add_fixed_type(offset, dtype, 0);
                        }
                    }
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
    pub fn gather_spacebase(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        types: &Arc<RwLock<crate::type_system::typefactory::TypeFactory>>,
    ) {
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
                        let dtype = make_int_type(types, size);
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
                        let dtype = make_int_type(types, val_size);
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
    pub fn gather_open(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        checker: &AliasChecker,
    ) {
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
            // Ghidra passes ct = NULL for non-pointers ("Do unknown array",
            // varmap.cc:1230); MapState::addRange substitutes the default
            // type (the factory's getBase(1,TYPE_UNKNOWN), varmap.cc:896).
            let final_dt: Option<Arc<Datatype>> = match &pointee {
                Some(p) => match p.as_ref() {
                    Datatype::Array(a) => Some(a.array_of.clone()),
                    _ => Some(p.clone()),
                },
                None => None,
            };
            let min_items: i32 = if entry.index.is_some() { 3 } else { -1 };
            self.add_range(offset, final_dt, 0, RangeType::Open, min_items);
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

// Ghidra: database.hh:214 Symbol::category constants
/// Symbol category constants. Faithful to the `Symbol` category enum
/// (database.hh:214-218): `no_category = -1`, `function_parameter = 0`,
/// `equate = 1`, `union_facet = 2`, `fake_input = 3`.
pub mod symbol_category {
    pub const NO_CATEGORY: i32 = -1;
    pub const FUNCTION_PARAMETER: i32 = 0;
    pub const EQUATE: i32 = 1;
    pub const UNION_FACET: i32 = 2;
    pub const FAKE_INPUT: i32 = 3;
}

/// A restructured local variable symbol.
/// Corresponds to Ghidra's Symbol (database.hh:168) plus its first whole
/// SymbolEntry mapping (database.hh:130 SymbolEntry).
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
    /// Ghidra Symbol::displayName (database.hh:179): the name to display in
    /// output. `addSymbolInternal`/`renameSymbol` keep it equal to `name`.
    pub display_name: String,
    /// Ghidra Symbol::nameDedup (database.hh:181): distinguishes symbols with
    /// the same name in the SymbolNameTree (database.hh:358 SymbolCompareName).
    pub name_dedup: u32,
    /// Ghidra Symbol::category (database.hh:186): -1 = no_category,
    /// 0 = function_parameter, 3 = fake_input (see symbol_category).
    pub category: i32,
    /// Ghidra Symbol::catindex (database.hh:187): position within category.
    pub cat_index: u32,
    /// Ghidra Symbol::flags & Varnode::typelock (database.hh:183).
    pub typelock: bool,
    /// Ghidra Symbol::flags & Varnode::namelock (database.hh:183).
    pub namelock: bool,
    /// Ghidra Symbol::flags & Varnode::addrtied (database.hh:183): set by
    /// `Scope::addMap` exactly when a static mapping carries an EMPTY
    /// uselimit (database.cc:1149-1150) and never cleared afterwards, so a
    /// Symbol with several entries becomes address-tied as soon as ONE entry
    /// is unrestricted. `SymbolEntry::getSubsort` (database.cc:101) and
    /// `SymbolEntry::inUse` (database.cc:117) both read this SYMBOL-level
    /// flag, not the entry's own uselimit. Dynamic symbols never take it
    /// (addDynamicMapInternal is outside the database.cc:1149 branch).
    pub addrtied: bool,
    /// First use-point address of the symbol's first SymbolEntry
    /// (database.cc:122 SymbolEntry::getFirstUseAddress); `None` models an
    /// invalid `Address()` (no uselimit range), which `Scope::buildDefaultName`
    /// (database.cc:1776) translates into the `Varnode::addrtied` flag.
    pub usepoint: Option<u64>,
    /// Ghidra SymbolEntry storage space for `linkSymbol`-created symbols
    /// (funcdata_varnode.cc:1177 `addSymbol("",...,vn->getAddr(),...)` maps
    /// the varnode's address, whose space may be register/unique/ram — not
    /// just this scope's stack space). Stack-restructure symbols
    /// (varmap.cc createEntry) keep `AddressSpace::Stack`.
    pub space: crate::space::AddressSpace,
    /// Ghidra SymbolEntry::isDynamic (database.hh:142): storage identified by
    /// a dynamic hash instead of an address. `linkSymbol` conflict symbols
    /// (funcdata_varnode.cc:1303 addDynamicSymbol) set this.
    pub is_dynamic: bool,
    /// Ghidra SymbolEntry::hash (database.hh:136): the dynamic storage hash
    /// (0 for static entries).
    pub hash: u64,
}

impl LocalSymbol {
    // Ghidra: database.hh:965 Symbol::Symbol
    /// Construct a symbol the way Ghidra's `Symbol(Scope*, name, Datatype*)`
    /// constructor does: `nameDedup = 0` (database.hh:983), category unset,
    /// `displayName` mirrors `name` once integrated by `addSymbolInternal`
    /// (database.cc:1818-1821).
    pub fn new(nm: &str, start: u64, size: i32, dtype: Option<Arc<Datatype>>,
               category: i32) -> Self {
        Self {
            name: nm.to_string(),
            start,
            size,
            dtype,
            unaliased: false,
            is_param: category == symbol_category::FUNCTION_PARAMETER,
            display_name: nm.to_string(),
            name_dedup: 0,
            category,
            cat_index: 0,
            typelock: false,
            namelock: false,
            addrtied: false,
            usepoint: None,
            space: crate::space::AddressSpace::Stack,
            is_dynamic: false,
            hash: 0,
        }
    }

    // Ghidra: database.cc:246 Symbol::isNameUndefined
    /// Does this Symbol have an undefined name? Faithful to
    /// `Symbol::isNameUndefined` (database.cc:246-250): the name is exactly 15
    /// characters and starts with "$$undef".
    pub fn is_name_undefined(&self) -> bool {
        self.name.len() == 15 && self.name.starts_with("$$undef")
    }
}

// RUGRA-GLUE: canonical Ghidra space indices for the locked x86-64 oracle.
/// Index of an address space in the locked BfdArchitecture
/// (x86:LE:64:default:gcc). Ghidra assigns indices in space-creation order;
/// the live oracle prints const=0, unique=2, ram=3, stack=8
/// (tests/oracle/scopelocal_query_1204 setup record). These constants feed
/// `EntrySubsort` comparisons (database.hh:109) — only the uselimit
/// spaces (ram code space, and any cross-space uselimit range) participate,
/// so the unverified Register/Join/Iop/Overlay/Other values are inert (a
/// storage space never reaches a subsort). Migrating to the registry-backed
/// space model is the ADDRESS-0001 / SPACE-0001 residual.
pub fn ghidra_space_index(space: &crate::space::AddressSpace) -> i32 {
    match space {
        crate::space::AddressSpace::Const => 0,
        crate::space::AddressSpace::Unique => 2,
        crate::space::AddressSpace::Ram => 3,
        crate::space::AddressSpace::Stack => 8,
        crate::space::AddressSpace::Register => 4,
        crate::space::AddressSpace::Join => 9,
        crate::space::AddressSpace::Iop => 10,
        crate::space::AddressSpace::Overlay => 11,
        crate::space::AddressSpace::Other(_) => 12,
    }
}

/// Ghidra SymbolEntry::EntrySubsort (database.hh:107-134): the sub-sort key
/// ordering the SymbolEntry records that share one common-refinement
/// partition unit. Comparison is `useindex` first, then `useoffset`
/// (database.hh:129-133). `minimum()` is the default-constructed "earliest
/// possible sub-sort" (database.hh:114) held by address-tied entries;
/// `maximum()` is the `EntrySubsort(true)` "latest possible" bound
/// (database.hh:119-122, useindex 0xffff > any real space index).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntrySubsort {
    /// Index of the sub-sorting address space (database.hh:109).
    pub useindex: i32,
    /// Offset into the sub-sorting address space (database.hh:110).
    pub useoffset: u64,
}

impl RangeSubsort for EntrySubsort {
    // Ghidra: database.hh:114 EntrySubsort::EntrySubsort(void)
    /// The earliest possible sub-sort: useindex 0, useoffset 0.
    fn minimum() -> Self {
        EntrySubsort { useindex: 0, useoffset: 0 }
    }

    // Ghidra: database.hh:119 EntrySubsort::EntrySubsort(bool)
    /// The latest possible sub-sort: useindex 0xffff exceeds every real
    /// space index, so the never-written useoffset is never compared.
    fn maximum() -> Self {
        EntrySubsort { useindex: 0xffff, useoffset: 0 }
    }
}

/// One static SymbolEntry mapping of a local Symbol (database.hh:75-163):
/// `[start, start+size-1]` in `space`, covering `offset..offset+size` of the
/// Symbol (partial pieces carry `offset > 0`), with a uselimit of code-space
/// ranges (empty = unrestricted = address-tied symbol). This is the record
/// type of the scope's per-space rangemap (`EntryMap`,
/// database.hh:164) — one Symbol can own several entries
/// (Symbol::mapentry, database.hh:189), and queries observe ENTRIES, not
/// symbols.
#[derive(Clone, Debug)]
pub struct LocalMapEntry {
    /// Index into `ScopeLocal::symbols` of the mapped Symbol.
    pub sym: usize,
    /// Storage space of this mapping (`SymbolEntry::addr`'s space).
    pub space: crate::space::AddressSpace,
    /// `SymbolEntry::getFirst` (database.hh:146): first offset of the storage.
    pub start: u64,
    /// `SymbolEntry::getSize` (database.hh:152): bytes consumed by this piece.
    pub size: i32,
    /// `SymbolEntry::getOffset` (database.hh:145): offset of this piece
    /// within the whole Symbol (partial-offset pieces carry `offset > 0`).
    pub offset: i32,
    /// `SymbolEntry::extraflags` (database.hh:78): Varnode flags specific to
    /// this storage location (`Varnode::mapped` for whole maps,
    /// precislo/precishi for join pieces).
    pub extraflags: u32,
    /// `SymbolEntry::uselimit` (database.hh:83) as sorted inclusive ranges
    /// `(space index, first, last)`; empty = valid across all code.
    pub uselimit: Vec<(i32, u64, u64)>,
    /// Sub-sort frozen at insertion, exactly as `rangemap::insert` calls
    /// `getSubsort()` once per record (rangemap.hh:238).
    pub subsort: EntrySubsort,
}

impl RangeRecord for LocalMapEntry {
    type Subsort = EntrySubsort;

    // Ghidra: database.hh:146 SymbolEntry::getFirst
    fn first(&self) -> u64 {
        self.start
    }

    // Ghidra: database.hh:147 SymbolEntry::getLast
    fn last(&self) -> u64 {
        self.start.wrapping_add(self.size.max(0) as u64).wrapping_sub(1)
    }

    // Ghidra: rangemap.hh:36 recordtype::getSubsort
    fn subsort(&self) -> Self::Subsort {
        self.subsort.clone()
    }
}

/// Which scope ended the `stackContainer` walk (database.cc:953-961): the
/// scope whose `findContainer` answered, the scope that owns the range
/// ("discovery of new variable"), or neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryFinalScope {
    /// No scope answered and none owns the range (database.cc:961).
    None,
    /// This (querying) scope answered or owns the range.
    This,
    /// The parent scope answered or owns the range.
    Parent,
}

/// Observable outcome of `Scope::queryProperties` (database.cc:1263-1281):
/// the answering SymbolEntry (if any) plus the `uint4 &flags` side-output
/// computed along the oracle's three branches.
#[derive(Clone, Debug)]
pub struct QueryPropertiesOutcome {
    /// The smallest containing in-use SymbolEntry, or None.
    pub entry: Option<LocalMapEntry>,
    /// `res->getAllFlags()` / scope-derived / property-only flags
    /// (database.cc:1270, 1273-1276, 1279).
    pub flags: u32,
    /// Which scope terminated the stackContainer walk.
    pub final_scope: QueryFinalScope,
}

/// ScopeLocal: the local variable scope for a function.
/// Corresponds to Ghidra's ScopeLocal (varmap.hh:212) extending
/// ScopeInternal (database.hh:795).
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
    /// Ghidra ScopeInternal::nametree (database.hh:809): the set of Symbol
    /// indices ordered by `(name, nameDedup)` — SymbolCompareName
    /// (database.hh:358-372): `name.compare()` first, then `nameDedup`.
    /// Maps the SymbolNameTree key to the index into `symbols`.
    nametree: std::collections::BTreeMap<(String, u32), usize>,
    /// Ghidra ScopeInternal::category lists (database.hh:805): per-category
    /// ordered slots mirroring `vector<vector<Symbol *>> category`.
    /// `None` slots are the null entries popped by `setCategory`
    /// (database.cc:2828-2832).
    category_lists: Vec<Vec<Option<usize>>>,
    /// Ghidra ScopeLocal::space (varmap.hh:213): address space of the local
    /// stack. Rugra models the space as the `AddressSpace::Stack` enum.
    pub space: crate::space::AddressSpace,
    /// Ghidra ScopeLocal local window (varmap.cc:438-465, resetLocalWindow):
    /// inclusive `(first, last)` ranges obtained from
    /// `FuncProto::getLocalRange()` consulted by `buildVariableName`
    /// (varmap.cc:555).
    pub local_range: Vec<(u64, u64)>,
    /// Ghidra ScopeLocal::minParamOffset (varmap.cc:345): init `~0`.
    pub min_param_offset: u64,
    /// Ghidra ScopeLocal::maxParamOffset (varmap.cc:346): init 0.
    pub max_param_offset: u64,
    /// Ghidra ScopeLocal::stackGrowsNegative (varmap.cc:348): init true.
    /// Kept in lockstep with `stack_direction` (1 == grows negative).
    pub stack_grows_negative: bool,
    /// Register-name lookup table standing in for
    /// `glb->translate->getRegisterName(space, off, size)`
    /// (translate.hh:380). Rugra's ScopeLocal is a plain struct without an
    /// Architecture handle, so the caller installs the register table; the
    /// empty default returns "" exactly like a Translate with no matching
    /// register.
    pub register_names: std::collections::BTreeMap<(u64, i32), String>,
    /// Exact `Funcdata::warningHeader` texts emitted inside scope methods
    /// that Ghidra routes through the scope's `fd` member
    /// (varmap.cc:536 markNotMapped; varmap.cc:1439-1445 fakeInputSymbols
    /// takes its fd parameter directly). ScopeLocal holds no Funcdata handle
    /// (`Funcdata.scope` owns the ScopeLocal — a Rust ownership seam), so
    /// the texts wait here for the caller-side drain into
    /// `Funcdata::warning_header` (F3, SCOPE-FINDOVERLAP-KEY-0001).
    pub pending_warnings: Vec<String>,
    /// The LowlevelError message that unwound `restructureVarnode`
    /// (`RangeHint::merge`, varmap.cc:280). Ghidra's exception aborts the
    /// whole action pipeline for the function; the buffered text preserves
    /// the exact message for the caller's abort channel (F3).
    pub pending_lowlevel_error: Option<String>,
    /// Ghidra ScopeInternal::maptable (database.hh:807) as an
    /// insertion-ordered log of static SymbolEntry records across all
    /// spaces. The per-space `rangemap<SymbolEntry>` view is materialized
    /// per query (see `materialize_maptable`) because `ScopeLocal: Clone`
    /// (printc.rs copies the scope) cannot own the non-Clone `RangeMap`;
    /// re-inserting the log in order reproduces the oracle's multiset
    /// state (equal keys keep insertion order, and erase keeps the
    /// survivors' relative order), verified by
    /// tests/oracle/scopelocal_query_1204 removal cases.
    pub mapentry_log: Vec<LocalMapEntry>,
    /// Ghidra Scope::isGlobal (database.hh:34): a ScopeLocal is never
    /// global, but the parent-scope mirror threaded through
    /// `query_properties_ex` models the global scope (persist flag on its
    /// symbols, database.cc:1131-1132, and the persist bit of the
    /// no-symbol branch, database.cc:1274-1275). Production ScopeLocal
    /// instances keep this false.
    pub is_global_scope: bool,
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
            nametree: std::collections::BTreeMap::new(),
            category_lists: Vec::new(),
            space: crate::space::AddressSpace::Stack,
            local_range: Vec::new(),
            min_param_offset: u64::MAX,
            max_param_offset: 0,
            stack_grows_negative: true,
            register_names: std::collections::BTreeMap::new(),
            pending_warnings: Vec::new(),
            pending_lowlevel_error: None,
            mapentry_log: Vec::new(),
            is_global_scope: false,
        }
    }

    // Ghidra: varmap.cc:510 ScopeLocal::markNotMapped
    /// Mark a specific stack address range as not mapped. Faithful to
    /// `ScopeLocal::markNotMapped` (varmap.cc:510-546): `last` is clamped to
    /// the space highest on wrap/over-extension (varmap.cc:516-519), a
    /// parameter-flagged call extends the min/max parameter-offset window
    /// consumed by `buildVariableName`'s Y-region test (varmap.cc:519-524),
    /// then the removal loop re-issues the partition-owner `findOverlap`
    /// query after every removal (varmap.cc:528-544): a typelocked symbol
    /// aborts with `fd->warningHeader("Variable defined which should be
    /// unmapped: "+name)` — silenced for the shared-return special case
    /// (`parameter && category == function_parameter`, varmap.cc:531-537)
    /// (F3) — a fake_input symbol aborts silently (varmap.cc:539-541), and
    /// plain overlapping symbols are removed one at a time. The window then
    /// loses `[first,last]` from the symboltab range tree (varmap.cc:545).
    ///
    /// (Ghidra's `space != spc` early return (varmap.cc:513) has no Rugra
    /// counterpart: the signature models the scope-space calls of the only
    /// production caller (ActionRestrictLocal, coreaction.cc:1968-1983).
    /// ScopeLocal holds no Funcdata handle — a Rust ownership seam, since
    /// `Funcdata.scope` owns the ScopeLocal — so the exact warningHeader
    /// texts are buffered in `pending_warnings` for the caller-side drain;
    /// the drain into the comment database is a funcdata/coreaction lease.)
    pub fn mark_not_mapped(&mut self, offset: u64, size: i32, parameter: bool) {
        // uintb last = first + sz - 1; (varmap.cc:514) with the wrap and
        // over-extension clamp (varmap.cc:516-519) against the stack space
        // highest — u64::MAX for the 8-byte stack model.
        let mut last = offset.wrapping_add(size.max(0) as u64).wrapping_sub(1);
        if last < offset {
            last = u64::MAX;
        } else if last > u64::MAX {
            last = u64::MAX;
        }
        if parameter {
            // Everything above parameter (varmap.cc:520-524)
            if offset < self.min_param_offset {
                self.min_param_offset = offset;
            }
            if last > self.max_param_offset {
                self.max_param_offset = last;
            }
        }
        // SymbolEntry *overlap = findOverlap(addr,sz); while(overlap != 0)
        // {...} (varmap.cc:528-544) — sz is the ORIGINAL size, only the
        // range-tree removal uses the clamped last.
        while let Some(idx) = self.find_overlap(self.space, offset, size) {
            let (is_typelock, category, name) = {
                let sym = &self.symbols[idx];
                (sym.typelock, sym.category, sym.name.clone())
            };
            if is_typelock {
                // If the symbol and the use are both as parameters this is
                // likely the special case of a shared return call sharing
                // the parameter location of the original function, in which
                // case we don't print a warning (varmap.cc:531-537).
                if !parameter || category != symbol_category::FUNCTION_PARAMETER {
                    self.pending_warnings
                        .push(format!("Variable defined which should be unmapped: {}", name));
                }
                return;
            } else if category == symbol_category::FAKE_INPUT {
                return; // Inputs in the stack space should not be unmapped
            }
            self.remove_symbol(idx);
        }
        // glb->symboltab->removeRange(this,space,first,last) (varmap.cc:545)
        self.local_range_remove_range(offset, last);
    }

    // Ghidra: database.cc:2138 ScopeInternal::removeSymbol
    /// Remove the symbol: null its category slot (popping trailing nulls,
    /// database.cc:2141-2146), drop its mappings (removeSymbolMappings,
    /// database.cc:2117-2136 — every maptable entry of the symbol, dynamic
    /// entries excluded from the static log by construction), and erase it
    /// from the nametree (database.cc:2147-2149). The Vec-based storage
    /// re-keys every nametree/category/entry-log reference above the hole
    /// down by one; entry-log survivors keep their relative order — the
    /// multiset equivalent-element order `rangemap::erase` preserves.
    /// (Public: `Scope::removeSymbol` is a public oracle entry point —
    /// database.hh:601 — and the locked fixture drives it directly.)
    pub fn remove_symbol(&mut self, idx: usize) {
        let key = (self.symbols[idx].name.clone(), self.symbols[idx].name_dedup);
        if self.symbols[idx].category >= 0 {
            let cat = self.symbols[idx].category as usize;
            let ci = self.symbols[idx].cat_index as usize;
            if let Some(list) = self.category_lists.get_mut(cat) {
                if ci < list.len() {
                    list[ci] = None;
                }
                while matches!(list.last(), Some(None)) {
                    list.pop();
                }
            }
        }
        self.symbols.remove(idx);
        self.nametree.remove(&key);
        for value in self.nametree.values_mut() {
            if *value > idx {
                *value -= 1;
            }
        }
        for list in &mut self.category_lists {
            for slot in list.iter_mut().flatten() {
                if *slot > idx {
                    *slot -= 1;
                }
            }
        }
        self.mapentry_log.retain(|entry| entry.sym != idx);
        for entry in &mut self.mapentry_log {
            if entry.sym > idx {
                entry.sym -= 1;
            }
        }
    }

    // Ghidra: address.cc:417 RangeList::removeRange
    /// Remove `[first,last]` from the scope's local window: every
    /// intersecting range is dropped, keeping only its non-intersecting
    /// remainders (splitting a bridging range in two). Faithful to
    /// `RangeList::removeRange` (address.cc:417-448) over the sorted
    /// inclusive-range model.
    fn local_range_remove_range(&mut self, first: u64, last: u64) {
        let mut result: Vec<(u64, u64)> = Vec::with_capacity(self.local_range.len() + 1);
        for &(rfirst, rlast) in &self.local_range {
            // Ranges are disjoint and sorted; a range intersects iff
            // rfirst <= last && first <= rlast.
            if rfirst <= last && first <= rlast {
                if rfirst < first {
                    result.push((rfirst, first.wrapping_sub(1)));
                }
                if rlast > last {
                    result.push((last.wrapping_add(1), rlast));
                }
            } else {
                result.push((rfirst, rlast));
            }
        }
        self.local_range = result;
    }

    // Ghidra: database.cc:2392 ScopeInternal::findOverlap
    /// First SymbolEntry of the scope overlapping
    /// `[offset, offset+size-1]` in the given space — the canonical
    /// `ScopeInternal::findOverlap` (database.cc:2392-2403). The oracle
    /// consults the space's EntryMap (a `rangemap<SymbolEntry>`,
    /// database.hh:164), whose multiset is keyed by `(last, subsort)`
    /// (rangemap.hh:88-91): `find_overlap(point, end)`
    /// (rangemap.hh:411-423) lower-bounds on the first sub-range whose
    /// `last >= point` — the leftmost partition unit intersecting the query
    /// — and returns its record iff the unit's `first <= end`. Delegation to
    /// `RangeMap::find_overlap` (oracle-proven by
    /// RANGEMAP-COMMON-REFINEMENT-0001) reproduces the traversal order and
    /// the equal-(last,subsort) insertion-order tie-break exactly; the
    /// per-query materialization replays `mapentry_log` in insertion order.
    /// Dynamic entries never enter the static map table
    /// (`addDynamicMapInternal` database.cc:1874-1886 pushes to
    /// `dynamicentry`, not maptable), so they are invisible (F2,
    /// SCOPE-FINDOVERLAP-DYNAMIC-0001). Returns the symbol index, mirroring
    /// the non-null `SymbolEntry*` return.
    pub fn find_overlap(
        &self,
        space: crate::space::AddressSpace,
        offset: u64,
        size: i32,
    ) -> Option<usize> {
        self.find_overlap_entry(space, offset, size).map(|entry| entry.sym)
    }

    // Ghidra: database.cc:2392 ScopeInternal::findOverlap
    /// Entry-returning form of `find_overlap` (the oracle returns the
    /// `SymbolEntry*` itself; Rugra's symbol-index form is the production
    /// seam). Same traversal and tie-break as `find_overlap`.
    pub fn find_overlap_entry(
        &self,
        space: crate::space::AddressSpace,
        offset: u64,
        size: i32,
    ) -> Option<LocalMapEntry> {
        let end = offset.wrapping_add(size.max(0) as u64).wrapping_sub(1);
        self.materialize_maptable(space)
            .find_overlap(offset, end)
            .cloned()
    }

    // Ghidra: database.cc:97 SymbolEntry::getSubsort
    /// Sub-sort of a mapping frozen at insertion time, faithful to
    /// `SymbolEntry::getSubsort` (database.cc:97-107) +
    /// `EntrySubsort::operator<` (database.hh:129-133): the minimal subsort
    /// (0,0) when the SYMBOL is address-tied (the flag `Scope::addMap` sets
    /// for an empty uselimit, database.cc:1149-1150), else `(useindex,
    /// useoffset)` of the first uselimit range (RangeList order: space index
    /// first, then offset — address.hh:202-205). A non-addrtied entry with
    /// an empty uselimit would hit the oracle's
    /// `LowlevelError("Map entry with empty uselimit")` (database.cc:104);
    /// constructors in this module never produce one, and the minimal
    /// fallback mirrors the address-tied shape.
    fn entry_subsort(addrtied: bool, uselimit: &[(i32, u64, u64)]) -> EntrySubsort {
        if addrtied {
            return EntrySubsort::minimum();
        }
        match uselimit.first() {
            None => EntrySubsort::minimum(),
            Some(&(useindex, useoffset, _)) => EntrySubsort { useindex, useoffset },
        }
    }

    // RUGRA-GLUE: per-query materialization of the space's EntryMap.
    /// Build `maptable[space]` (database.hh:807) by replaying the static
    /// entry log in insertion order into the oracle-proven `RangeMap`.
    /// Equal-(last,subsort) keys keep insertion order (std::multiset
    /// equivalent-element order), and removal-driven rebuilds replay the
    /// survivors in original order — the state `rangemap::erase` leaves.
    fn materialize_maptable(&self, space: crate::space::AddressSpace) -> RangeMap<LocalMapEntry> {
        let mut rangemap = RangeMap::new();
        for entry in &self.mapentry_log {
            if entry.space == space {
                rangemap.insert(entry.clone());
            }
        }
        rangemap
    }

    // Ghidra: database.cc:114 SymbolEntry::inUse
    /// Is a mapping valid at `usepoint`? Faithful to `SymbolEntry::inUse`
    /// (database.cc:114-120): an address-tied SYMBOL is valid throughout the
    /// scope; an invalid usepoint (None) admits nothing else; otherwise some
    /// uselimit range in the usepoint's space must contain the offset
    /// (`RangeList::inRange`, address.cc:483, compares the containing
    /// range's space). `usepoint` is a code-space offset (the only space
    /// production queries pass).
    fn entry_in_use(&self, entry: &LocalMapEntry, usepoint: Option<u64>) -> bool {
        if self.symbols[entry.sym].addrtied {
            return true; // database.cc:117
        }
        let Some(up) = usepoint else {
            return false; // database.cc:118
        };
        let code_index = ghidra_space_index(&crate::space::AddressSpace::Ram);
        entry
            .uselimit
            .iter()
            .any(|&(idx, first, last)| idx == code_index && first <= up && up <= last)
    }

    // Ghidra: database.hh:271 SymbolEntry::getAllFlags
    /// Union of the entry's extraflags and the Symbol's flags, faithful to
    /// `getAllFlags` (database.hh:271-273): `extraflags | symbol->getFlags()`.
    /// The Symbol flags modeled here are addrtied (database.cc:1150),
    /// typelock/namelock, and persist for global-scope symbols
    /// (database.cc:1131-1132); readonly/volatile property bits folded into
    /// the symbol at addMap (database.cc:1153) are the Database flagbase
    /// residual (DB-LOCALSCOPE-MAP-0001).
    fn entry_all_flags(&self, entry: &LocalMapEntry) -> u32 {
        use crate::varnode::varnode_flags;
        let sym = &self.symbols[entry.sym];
        let mut flags = entry.extraflags;
        if sym.addrtied {
            flags |= varnode_flags::ADDRTIED;
        }
        if sym.typelock {
            flags |= varnode_flags::TYPELOCK;
        }
        if sym.namelock {
            flags |= varnode_flags::NAMELOCK;
        }
        if self.is_global_scope {
            flags |= varnode_flags::PERSIST;
        }
        flags
    }

    // Ghidra: database.hh:597 Scope::inScope
    /// Does this scope OWN `[offset, offset+size-1]`? Faithful to
    /// `Scope::inScope` (database.hh:597-598: `rangetree.inRange(addr,size)`,
    /// full containment — address.cc:484): the ownership tree is modeled by
    /// `local_range`, which holds this scope's primary-space ranges (the
    /// local window for a ScopeLocal, the global ranges for the parent
    /// mirror), so other spaces report false.
    pub fn in_scope(
        &self,
        space: crate::space::AddressSpace,
        offset: u64,
        size: i64,
    ) -> bool {
        if space != self.space {
            return false;
        }
        let end = offset.wrapping_add(size.max(1) as u64).wrapping_sub(1);
        self.local_range
            .iter()
            .any(|&(first, last)| first <= offset && end <= last)
    }

    // Ghidra: database.cc:1263 Scope::queryProperties (via findContainer,
    // database.cc:2250, with an INVALID usepoint — funcdata_varnode.cc:1699)
    /// Does a static address-tied SymbolEntry contain
    /// `[offset, offset+size-1]` in the given space? The boolean form of the
    /// `mapGlobals` queryProperties probe (funcdata_varnode.cc:1697-1701:
    /// `localmap->queryProperties(addr,1,Address(),fl)`): `findContainer`
    /// with an invalid usepoint admits only address-tied entries
    /// (`SymbolEntry::inUse`, database.cc:114-120), and dynamic entries are
    /// not in the address range map (F2, database.cc:1874-1886).
    pub fn has_overlap_in(&self, space: crate::space::AddressSpace, offset: u64, size: i32) -> bool {
        self.find_container_entry(space, offset, size as i64, None)
            .is_some()
    }

    // Ghidra: database.cc:1263 Scope::queryProperties (findContainer chain)
    /// Backward-compatible `mapGlobals` probe whose frozen signature
    /// (funcdata.rs, off-lease this round) carries no space: consult every
    /// space holding entries, preserving the legacy any-space contract.
    /// Threading the varnode's real space through the funcdata caller is
    /// the production-consumer residual (SCOPELOCAL-QUERY-0001 r2 /
    /// FUNCDATA-LOCALSCOPE-OWNERSHIP-0001 chain).
    pub fn has_overlap(&self, offset: u64, size: i32) -> bool {
        let spaces: Vec<crate::space::AddressSpace> = self
            .mapentry_log
            .iter()
            .map(|entry| entry.space)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        spaces
            .iter()
            .any(|&space| self.has_overlap_in(space, offset, size))
    }

    // Ghidra: database.cc:2224 ScopeInternal::findAddr
    /// Find the SymbolEntry whose mapping STARTS exactly at `offset` in the
    /// given space and is valid at `usepoint`. Faithful to
    /// `ScopeInternal::findAddr` (database.cc:2224-2248): the
    /// `find(offset, subsorttype(false), subsorttype(usepoint-or-true))`
    /// window (rangemap.hh:355-369) is walked with `--res.second` —
    /// DESCENDING multiset order over the partition unit containing
    /// `offset` — returning the first exact-start entry that passes
    /// `inUse`. Delegation to `RangeMap::find_with_subsort(...).rev()`
    /// reproduces both the subsort bound (an entry whose first uselimit
    /// range sorts after the usepoint never enters the window) and the
    /// equal-subsort tie-break (the LAST inserted wins, multiset reverse
    /// order). `usepoint` is a code-space offset; None models the invalid
    /// `Address()` for which only address-tied entries are in use.
    /// Dynamic entries are address-unsearchable (F2, database.cc:1874-1886).
    /// Returns the symbol index.
    pub fn find_addr(
        &self,
        space: crate::space::AddressSpace,
        offset: u64,
        usepoint: Option<u64>,
    ) -> Option<usize> {
        self.find_addr_entry(space, offset, usepoint).map(|entry| entry.sym)
    }

    // Ghidra: database.cc:2224 ScopeInternal::findAddr
    /// Entry-returning form of `find_addr` (the oracle returns the
    /// `SymbolEntry*`). Same window walk, subsort bound, and tie-break.
    pub fn find_addr_entry(
        &self,
        space: crate::space::AddressSpace,
        offset: u64,
        usepoint: Option<u64>,
    ) -> Option<LocalMapEntry> {
        let rangemap = self.materialize_maptable(space);
        let sub2 = match usepoint {
            None => EntrySubsort::maximum(), // database.cc:2232-2233
            Some(up) => EntrySubsort {
                useindex: ghidra_space_index(&crate::space::AddressSpace::Ram),
                useoffset: up,
            }, // database.cc:2237 EntrySubsort(usepoint)
        };
        let sub1 = EntrySubsort::minimum();
        for entry in rangemap.find_with_subsort(offset, &sub1, &sub2).rev() {
            if entry.start == offset && self.entry_in_use(entry, usepoint) {
                return Some(entry.clone()); // database.cc:2241-2244
            }
        }
        None
    }

    // Ghidra: database.cc:2250 ScopeInternal::findContainer
    /// Find the smallest SymbolEntry that fully contains
    /// `[offset, offset+size-1]` in the given space and is valid at
    /// `usepoint`. Faithful to `ScopeInternal::findContainer`
    /// (database.cc:2250-2282): the same subsort-bounded window as
    /// `findAddr` walked in DESCENDING multiset order; an entry replaces
    /// the best only on a STRICTLY smaller size (database.cc:2271), and an
    /// exact-size hit short-circuits the walk (database.cc:2274) — so among
    /// equally-sized containers the LARGEST subsort (first met in the
    /// backward walk) wins, and equal-(last,subsort) entries resolve to the
    /// LAST inserted. `oldsize` is updated only after an in-use accept.
    pub fn find_container_entry(
        &self,
        space: crate::space::AddressSpace,
        offset: u64,
        size: i64,
        usepoint: Option<u64>,
    ) -> Option<LocalMapEntry> {
        let rangemap = self.materialize_maptable(space);
        let sub2 = match usepoint {
            None => EntrySubsort::maximum(),
            Some(up) => EntrySubsort {
                useindex: ghidra_space_index(&crate::space::AddressSpace::Ram),
                useoffset: up,
            },
        };
        let sub1 = EntrySubsort::minimum();
        let end = offset.wrapping_add(size.max(0) as u64).wrapping_sub(1);
        let mut best: Option<LocalMapEntry> = None;
        let mut oldsize: i64 = -1;
        for entry in rangemap.find_with_subsort(offset, &sub1, &sub2).rev() {
            if entry.last() < end {
                continue; // database.cc:2270 — must contain the whole range
            }
            let entry_size = entry.size as i64;
            if entry_size < oldsize || oldsize == -1 {
                // database.cc:2271
                if self.entry_in_use(entry, usepoint) {
                    best = Some(entry.clone());
                    if entry_size == size {
                        break; // database.cc:2274
                    }
                    oldsize = entry_size;
                }
            }
        }
        best
    }

    // Ghidra: varmap.cc:1256 ScopeLocal::restructureVarnode
    /// Restructure the stack frame from varnodes.
    /// Main entry point. Faithful to `ScopeLocal::restructureVarnode`
    /// (varmap.cc:1256).
    pub fn restructure_varnode(&mut self, fd: &crate::funcdata::Funcdata) {
        // Ghidra varmap.cc:1273 `clearUnlockedCategory(-1)` — NOT a blanket
        // clear: symbols with category >= 0 (function parameters, equates)
        // survive unconditionally (database.cc:2086 `if
        // (sym->getCategory() >= 0) continue;`); category<0 symbols survive
        // while type-locked, with an unlocked name reset to the $$undef
        // placeholder (database.cc:2091-2094); everything else is
        // removeSymbol'd. Rugra previously cleared every symbol, wiping
        // platform-seeded parameter symbols between passes.
        let old_symbols = std::mem::take(&mut self.symbols);
        let old_mapentries = std::mem::take(&mut self.mapentry_log);
        let mut kept: Vec<LocalSymbol> = Vec::new();
        let mut kept_old_idx: Vec<usize> = Vec::new();
        for (old_idx, mut sym) in old_symbols.into_iter().enumerate() {
            let survive = if sym.category >= 0 {
                true
            } else if sym.typelock {
                if !sym.namelock && !sym.is_name_undefined() {
                    // renameSymbol(sym, buildUndefinedName()) (cc:2092-2093)
                    sym.name = self
                        .build_undefined_name()
                        .unwrap_or_else(|| "$$undef00000000".to_string());
                    sym.display_name = sym.name.clone();
                }
                true
            } else {
                false
            };
            if survive {
                kept.push(sym);
                kept_old_idx.push(old_idx);
            }
        }
        // Rebuild all derived containers from the survivors, preserving each
        // survivor's whole map entry (space/start/size/flags/uselimit) and
        // category slot.
        let mut new_symbols: Vec<LocalSymbol> = Vec::new();
        let mut new_entries: Vec<LocalMapEntry> = Vec::new();
        self.nametree.clear();
        self.category_lists.clear();
        for (new_idx, sym) in kept.into_iter().enumerate() {
            let old_idx = kept_old_idx[new_idx];
            let cat = sym.category;
            let cat_index = sym.cat_index as i32;
            let key = (sym.name.clone(), sym.name_dedup);
            self.nametree.insert(key, new_idx);
            while self.category_lists.len() <= cat as usize && cat >= 0 {
                self.category_lists.push(Vec::new());
            }
            if cat >= 0 {
                let list = &mut self.category_lists[cat as usize];
                while list.len() <= cat_index as usize {
                    list.push(None);
                }
                list[cat_index as usize] = Some(new_idx);
            }
            for entry in old_mapentries.iter().filter(|e| e.sym == old_idx) {
                let mut e = entry.clone();
                e.sym = new_idx;
                new_entries.push(e);
            }
            new_symbols.push(sym);
        }
        self.symbols = new_symbols;
        self.mapentry_log = new_entries;
        self.overlap_problems = false;
        self.pending_warnings.clear();
        self.pending_lowlevel_error = None;

        // Ghidra reads every factory type through `glb->types` (the
        // Architecture's single TypeFactory member, type.cc:3106). Rugra's
        // production Funcdata has no attached Architecture yet
        // (FUNCPROTO-MODEL-BIND-0001 chain), so resolve: the attached
        // Architecture's factory when present, else the process-canonical
        // factory modeling the headless oracle's single Architecture.
        let types: Arc<RwLock<crate::type_system::typefactory::TypeFactory>> = fd
            .arch
            .as_ref()
            .and_then(|a| a.types.clone())
            .unwrap_or_else(crate::type_system::typefactory::TypeFactory::shared_default);

        // Determine local range. Ghidra derives this from the prototype's
        // getRangeTree/getParamRange (varmap.cc:438-465, resetLocalWindow);
        // Rugra uses the full stack extent.
        let local_start = 0u64;
        let local_end = 0x100000u64;
        // Install the local window consulted by buildVariableName
        // (varmap.cc:555) the way resetLocalWindow copies the prototype's
        // localRange into the scope.
        self.local_range = vec![(local_start, local_end - 1)];

        // Build the MapState with a default unknown base type (1 byte),
        // matching Ghidra's glb->types->getBase(1, TYPE_UNKNOWN)
        // (varmap.cc:1261).
        let default_type = make_int_type(&types, 1);
        let mut state = MapState::new_with_default(local_start, local_end, default_type);
        state.gather_varnodes(fd);
        state.gather_spacebase(fd, &types);

        // Gather alias info.
        let mut checker = AliasChecker::new(self.stack_direction);
        checker.gather_internal(fd);
        let aliases = checker.get_aliases().to_vec();

        // Gather open (pointer-referenced) ranges.
        state.gather_open(fd, &checker);

        // Restructure: merge overlapping ranges into disjoint symbols
        // (varmap.cc:1270). A LowlevelError from `RangeHint::merge`
        // (varmap.cc:280) unwinds restructureVarnode entirely in the oracle
        // — markUnaliased and fakeInputSymbols never run — modeled by the
        // early return with the exact message buffered for the caller's
        // abort channel (F3, SCOPE-FINDOVERLAP-KEY-0001).
        self.overlap_problems = match self.restructure(&mut state, &types) {
            Ok(problems) => problems,
            Err(err) => {
                self.pending_lowlevel_error = Some(err.to_string());
                return;
            }
        };

        // Mark unaliased symbols.
        self.mark_unaliased(&aliases);

        // Build fake input symbols for parameters.
        self.fake_input_symbols(fd, &types);
    }

    // Ghidra: varmap.cc:1294 ScopeLocal::restructure
    /// Merge RangeHints into a definitive set of Symbols.
    /// Corresponds to ScopeLocal::restructure (varmap.cc:1294); `types`
    /// mirrors the `glb->types` handle threaded into `RangeHint::merge`
    /// (varmap.cc:1309) and `createEntry` (varmap.cc:622). Returns
    /// `Err` for the LowlevelError thrown by `RangeHint::merge`
    /// (varmap.cc:280), which in the oracle unwinds out of this walk.
    fn restructure(
        &mut self,
        state: &mut MapState,
        types: &Arc<RwLock<crate::type_system::typefactory::TypeFactory>>,
    ) -> anyhow::Result<bool> {
        if !state.initialize() { return Ok(false); }

        let mut overlap_problems = false;
        let mut current = match state.next_hint() {
            Some(h) => h.clone(),
            None => return Ok(false),
        };

        while state.get_next() {
            let next = match state.next_hint() {
                Some(h) => h.clone(),
                None => break,
            };

            // Check if ranges intersect — Ghidra cc:1308 uses SIGNED comparison
            // (sstart is intb/int8). For negative stack offsets (x86 locals at
            // high unsigned addresses = small negatives), unsigned comparison
            // treats them as huge positives → wrong intersection decision.
            let cur_end = current.sstart.wrapping_add(current.size as i64);
            if next.sstart < cur_end {
                // Ranges intersect — merge them (varmap.cc:1309). The
                // LowlevelError from RangeHint::merge (varmap.cc:280)
                // propagates out of this walk unchecked.
                if current.merge_with(&next, types)? {
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
                        self.create_entry(&current, types);
                    }
                    current = next;
                }
            }
        }

        Ok(overlap_problems)
    }

    // Ghidra: varmap.cc:587 ScopeLocal::adjustFit
    /// Shrink the RangeHint as necessary so it fits in the mapped region of
    /// the Scope and doesn't overlap any other Symbols. Faithful to
    /// `ScopeLocal::adjustFit` (varmap.cc:587-612): the mapped region is
    /// consulted through `RangeList::longestFit` over the scope's range
    /// window (`local_range`, standing in for the symboltab range tree),
    /// then `findOverlap` — the partition-owner overlap query (F1,
    /// SCOPE-FINDOVERLAP-KEY-0001) — answers "ANY symbol that might be
    /// within this range" (varmap.cc:599), whose start clamps the hint from
    /// above. Returns true if a valid adjustment was made.
    fn adjust_fit(&self, a: &mut RangeHint) -> bool {
        if a.size == 0 {
            return false; // Nothing to fit (varmap.cc:590)
        }
        if a.is_type_lock() {
            return false; // Already entered (varmap.cc:591)
        }
        // uintb maxsize = getRangeTree().longestFit(addr,a.size);
        // (varmap.cc:593) — the scope's range tree; Rugra's window is the
        // inclusive-range `local_range` model.
        let mut maxsize = self.longest_fit(a.start, a.size as u64);
        if maxsize == 0 {
            return false; // varmap.cc:594
        }
        // Ghidra reads a.type->getSize() (never null on this path); the
        // optional dtype keeps the 1-byte fallback of the previous port.
        let type_size = a.dtype.as_ref().map(|d| d.get_size()).unwrap_or(1) as u64;
        if maxsize < a.size as u64 {
            // Suggested range doesn't fit (varmap.cc:595-598)
            if maxsize < type_size {
                return false; // Can't shrink that much
            }
            a.size = maxsize as i32;
        }
        // SymbolEntry *entry = findOverlap(addr,a.size); (varmap.cc:600) —
        // partition-owner semantics, dynamic entries invisible (F2).
        let entry = self.find_overlap(self.space, a.start, a.size);
        let entry_start = match entry {
            None => return true, // varmap.cc:601-602
            Some(idx) => self.symbols[idx].start,
        };
        if entry_start <= a.start {
            // < generally shouldn't be possible (varmap.cc:603-607)
            return false;
        }
        maxsize = entry_start - a.start;
        if maxsize < type_size {
            return false; // Can't shrink for this type (varmap.cc:609)
        }
        a.size = maxsize as i32;
        true
    }

    // Ghidra: address.cc:512 RangeList::longestFit
    /// Size of the biggest contiguous sequence of addresses in the scope's
    /// local window containing `offset`, capped by `maxsize` (the caller's
    /// hint size). Faithful to `RangeList::longestFit`
    /// (address.cc:512-537): locate the last range whose `first <= offset`
    /// (the window is kept sorted ascending), require `last >= offset`,
    /// then chain consecutive ranges — the walk stops at the first gap,
    /// a different space, a range starting after the chain point, or once
    /// `sizeres >= maxsize` (address.cc:533).
    fn longest_fit(&self, offset: u64, maxsize: u64) -> u64 {
        if self.local_range.is_empty() {
            return 0; // address.cc:518
        }
        // iter = tree.upper_bound(Range(offset,offset)); if (iter ==
        // tree.begin()) return 0; --iter; — the last window range with
        // first <= offset (the Vec is sorted by construction).
        let pos = self
            .local_range
            .partition_point(|&(first, _)| first <= offset);
        if pos == 0 {
            return 0; // address.cc:523
        }
        let mut i = pos - 1;
        let mut sizeres: u64 = 0;
        if self.local_range[i].1 < offset {
            return sizeres; // address.cc:527
        }
        let mut chain = offset;
        loop {
            let (first, last) = self.local_range[i];
            if first > chain {
                break; // address.cc:530
            }
            sizeres = sizeres.wrapping_add(last.wrapping_sub(chain).wrapping_add(1));
            chain = last.wrapping_add(1); // address.cc:532
            if sizeres >= maxsize {
                break; // address.cc:533
            }
            i += 1; // address.cc:534 — next range in the chain
            if i >= self.local_range.len() {
                break; // iter == tree.end()
            }
        }
        sizeres
    }

    // Ghidra: varmap.cc:617 ScopeLocal::createEntry
    /// Create a symbol entry from a RangeHint. Faithful to
    /// `ScopeLocal::createEntry` (varmap.cc:617-631): the symbol is added with
    /// an EMPTY name (addSymbolInternal then assigns a `$$undef` placeholder,
    /// database.cc:1818-1821) and an invalid usepoint. Naming happens later
    /// in `assignDefaultNames` (database.cc:2850). The data-type is concretized
    /// and wrapped into an array when more than one aligned element fits
    /// (varmap.cc:622-625).
    fn create_entry(
        &mut self,
        hint: &RangeHint,
        types: &Arc<RwLock<crate::type_system::typefactory::TypeFactory>>,
    ) {
        if hint.size <= 0 { return; }

        // Datatype *ct = glb->types->concretize(a.type); (varmap.cc:622)
        let raw = hint.dtype.clone().unwrap_or_else(|| make_int_type(types, 1));
        let ct = types
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .concretize(raw);
        // int4 num = a.size/ct->getAlignSize(); if (num>1) ct = getTypeArray(num,ct);
        let align = ct.get_align_size().max(1) as i32;
        let num = hint.size / align;
        // NOTE: Ghidra wraps the array through glb->types->getTypeArray
        // (varmap.cc:625), whose factory deduplication is not yet ported
        // (no TypeFactory::getTypeArray in Rust); the array shell is built
        // locally around the factory-owned element type. Registered as a
        // TYPE-WIRING-0001 residual.
        let final_dt: Arc<Datatype> = if num > 1 {
            Arc::new(Datatype::Array(crate::type_system::datatype::TypeArray {
                base: crate::type_system::datatype::TypeBase::new(
                    format!("{}[{}]", ct.get_name(), num),
                    hint.size as usize,
                    TypeMetatype::Array,
                ),
                array_of: ct.clone(),
                num_elements: num as usize,
            }))
        } else {
            ct
        };

        // addSymbol("",ct,addr,usepoint) — usepoint is the default invalid Address.
        let start = hint.start;
        let size = hint.size;
        let idx = self.add_symbol(
            crate::space::AddressSpace::Stack, "", Some(final_dt), start, None,
        );
        // SymbolEntry extent: [start, start+size); kept on LocalSymbol for
        // Rugra's query_by_addr/find_symbol consumers.
        self.symbols[idx].size = size;
    }

    // Ghidra: varmap.cc:548 ScopeLocal::buildVariableName
    /// Build a variable name. Faithful override of
    /// `ScopeLocal::buildVariableName` (varmap.cc:548-581): for an
    /// address-tied (non-persist) symbol in this scope's stack space whose
    /// address lies within the local range, the name is
    /// `<printNameBase>Stack[X|Y]_<hex>` uniquified via `makeNameUnique`;
    /// otherwise the `ScopeInternal::buildVariableName` implementation runs.
    ///
    /// `offset` is the entry address offset, `usepoint` the pc (None =
    /// invalid Address), `index` the caller's counter — the function-parameter
    /// branch prints it, the local branch post-increments it
    /// (database.cc:2504) so the shared `int4 base` advances.
    pub fn build_variable_name(
        &self,
        space: crate::space::AddressSpace,
        offset: u64,
        usepoint: Option<u64>,
        ct: Option<&Arc<Datatype>>,
        index: &mut i32,
        flags: u32,
    ) -> Option<String> {
        use crate::varnode::varnode_flags;
        if flags & (varnode_flags::ADDRTIED | varnode_flags::PERSIST)
            == varnode_flags::ADDRTIED
            && space == self.space
            && self.local_range_in_range(offset)
        {
            // intb start = byteToAddress(offset, wordSize); wordSize == 1 for
            // the stack space, so the offset is already in bytes; the 64-bit
            // sign-extension of varmap.cc:557 is the identity for i64.
            let mut start = offset as i64;
            if self.stack_grows_negative {
                start = start.wrapping_neg();
            }
            let mut s = String::new();
            if let Some(t) = ct {
                t.print_name_base(&mut s);
            }
            s.push_str("Stack");
            if start <= 0 {
                s.push('X'); // Local stack space allocated by caller
                start = start.wrapping_neg();
            } else if self.min_param_offset < self.max_param_offset
                && (if self.stack_grows_negative {
                    offset < self.min_param_offset
                } else {
                    offset > self.max_param_offset
                })
            {
                s.push('Y'); // Unusual region of stack
            }
            s.push('_');
            s.push_str(&format!("{:x}", start as u64));
            return self.make_name_unique(&s);
        }
        self.build_variable_name_internal(space, offset, usepoint, ct, index, flags)
    }

    // Ghidra: database.cc:2434 ScopeInternal::buildVariableName
    /// Base implementation of `buildVariableName`. Faithful to
    /// `ScopeInternal::buildVariableName` (database.cc:2434-2518), branch for
    /// branch: unaffected / persist / irregular input / regular parameter /
    /// addrtied / indirect_creation / default local, each uniquified with
    /// `makeNameUnique` at database.cc:2517.
    fn build_variable_name_internal(
        &self,
        space: crate::space::AddressSpace,
        offset: u64,
        _usepoint: Option<u64>,
        ct: Option<&Arc<Datatype>>,
        index: &mut i32,
        flags: u32,
    ) -> Option<String> {
        use crate::varnode::varnode_flags;
        let sz = ct.map(|t| t.get_size() as i32).unwrap_or(1);
        let mut s = String::new();

        if flags & varnode_flags::UNAFFECTED != 0 {
            if flags & varnode_flags::RETURN_ADDRESS != 0 {
                s.push_str("unaff_retaddr");
            } else {
                let unaffname = self.get_register_name(space, offset, sz);
                if unaffname.is_empty() {
                    s.push_str("unaff_");
                    s.push_str(&format!("{:08x}", offset));
                } else {
                    s.push_str("unaff_");
                    s.push_str(&unaffname);
                }
            }
        } else if flags & varnode_flags::PERSIST != 0 {
            let spacename = self.get_register_name(space, offset, sz);
            if !spacename.is_empty() {
                s.push_str(&spacename);
            } else {
                if let Some(t) = ct {
                    t.print_name_base(&mut s);
                }
                s.push_str(&capitalized_space_name(space));
                s.push_str(&format!("{:0w$x}", offset, w = 2 * addr_space_size(space)));
            }
        } else if flags & varnode_flags::INPUT != 0 && *index < 0 {
            // Irregular input
            let regname = self.get_register_name(space, offset, sz);
            if regname.is_empty() {
                s.push_str(&format!("in_{}_{:08x}", space_name(space), offset));
            } else {
                s.push_str(&format!("in_{}", regname));
            }
        } else if flags & varnode_flags::INPUT != 0 {
            // Regular parameter
            s.push_str(&format!("param_{}", *index));
        } else if flags & varnode_flags::ADDRTIED != 0 {
            if let Some(t) = ct {
                t.print_name_base(&mut s);
            }
            s.push_str(&capitalized_space_name(space));
            s.push_str(&format!("{:0w$x}", offset, w = 2 * addr_space_size(space)));
        } else if flags & varnode_flags::INDIRECT_CREATION != 0 {
            s.push_str("extraout_");
            let regname = self.get_register_name(space, offset, sz);
            if !regname.is_empty() {
                s.push_str(&regname);
            } else {
                s.push_str("var");
            }
        } else {
            // Some sort of local variable
            if let Some(t) = ct {
                t.print_name_base(&mut s);
            }
            // s << "Var" << dec << index++;
            let n = *index;
            *index += 1;
            s.push_str("Var");
            s.push_str(&n.to_string());
            if self.find_first_by_name(&s).is_some() {
                // If the name already exists, try bumping up the index a few
                // times before calling makeNameUnique (database.cc:2506-2515).
                for _ in 0..10 {
                    let mut s2 = String::new();
                    if let Some(t) = ct {
                        t.print_name_base(&mut s2);
                    }
                    let n = *index;
                    *index += 1;
                    s2.push_str("Var");
                    s2.push_str(&n.to_string());
                    if self.find_first_by_name(&s2).is_none() {
                        return Some(s2);
                    }
                }
            }
        }
        self.make_name_unique(&s)
    }

    // Ghidra: database.cc:2553 ScopeInternal::makeNameUnique
    /// Make the given name unique in this scope. Faithful to
    /// `ScopeInternal::makeNameUnique` (database.cc:2553-2614): if the name is
    /// unused it is returned unchanged; otherwise the last symbol whose name
    /// starts with `nm` is scanned for a `_NN` (2-digit) or `_xNNNNN`
    /// (5-digit) suffix, the id is incremented, and the result re-formatted.
    /// Returns `None` for Ghidra's `LowlevelError` ("Unable to uniquify name")
    /// at database.cc:2611-2612.
    pub fn make_name_unique(&self, nm: &str) -> Option<String> {
        let first_key = match self.find_first_by_name(nm) {
            Some(idx) => (self.symbols[idx].name.clone(), self.symbols[idx].name_dedup),
            None => return Some(nm.to_string()), // nm is already unique
        };

        // Symbol boundsym((Scope*)0, nm+"_x99999", ...); nameDedup = 0xffffffff;
        // iter2 = nametree.lower_bound(&boundsym);
        let bound = (format!("{}_x99999", nm), u32::MAX);
        // All keys strictly below the bound, in SymbolNameTree order.
        let ordered: Vec<(&String, &u32)> =
            self.nametree.range(..bound).map(|(k, _)| (&k.0, &k.1)).collect();
        let first_pos = ordered
            .iter()
            .position(|(n, d)| (n.as_str(), **d) == (first_key.0.as_str(), first_key.1))?;

        // do { uniqid = 0xffffffff; --iter2; if (iter == iter2) break; ... }
        // while (uniqid == 0xffffffff)
        let mut pos = ordered.len();
        let mut uniqid: Option<u32> = None;
        loop {
            if pos == 0 {
                break;
            }
            pos -= 1; // --iter2
            if pos == first_pos {
                break; // iter == iter2
            }
            let (bname, _) = ordered[pos];
            if let Some(u) = parse_name_unique_suffix(bname, nm) {
                uniqid = Some(u);
                break;
            }
        }

        let res_string = match uniqid {
            None => format!("{}_00", nm), // no other names matching our convention
            Some(u) => {
                let uniqid = u + 1;
                if uniqid < 100 {
                    format!("{}_{:02}", nm, uniqid)
                } else {
                    format!("{}_x{:05}", nm, uniqid)
                }
            }
        };
        if self.find_first_by_name(&res_string).is_some() {
            return None; // throw LowlevelError("Unable to uniquify name: "+resString)
        }
        Some(res_string)
    }

    // Ghidra: database.cc:2733 ScopeInternal::findFirstByName
    /// Find the index of the first symbol in the SymbolNameTree ordering with
    /// the given name. Faithful to `ScopeInternal::findFirstByName`
    /// (database.cc:2733-2742): a `lower_bound` lookup on `(nm, 0)` that
    /// returns `None` (nametree.end()) unless the found symbol's name equals
    /// `nm` exactly. Indices invalidated by an external
    /// `symbols.clear()` (funcdata.rs startProcessing clears only the vec,
    /// modeling Ghidra's `localmap->clearUnlocked()` whose Rugra counterpart
    /// cannot touch the private nametree) are treated as absent.
    pub fn find_first_by_name(&self, nm: &str) -> Option<usize> {
        self.nametree
            .range((nm.to_string(), 0u32)..)
            .next()
            .and_then(|(k, &idx)| {
                if k.0 == nm && idx < self.symbols.len() {
                    Some(idx)
                } else {
                    None
                }
            })
    }

    // Ghidra: database.cc:2712 ScopeInternal::insertNameTree
    /// Insert the symbol into the nametree. Faithful to
    /// `ScopeInternal::insertNameTree` (database.cc:2712-2727): the dedup id
    /// starts at 0; if the `(name, 0)` slot is taken, the id becomes the last
    /// same-named symbol's id + 1.
    fn insert_name_tree(&mut self, idx: usize) {
        let name = self.symbols[idx].name.clone();
        self.symbols[idx].name_dedup = 0;
        if self.nametree.contains_key(&(name.clone(), 0)) {
            // iter = nametree.upper_bound(sym); --iter  (last symbol with this name)
            let mut next_name = name.clone();
            next_name.push('\0');
            let last_dedup = self
                .nametree
                .range((name.clone(), 0u32)..(next_name, 0u32))
                .next_back()
                .map(|(k, _)| k.1)
                .unwrap_or(u32::MAX);
            self.symbols[idx].name_dedup = last_dedup.wrapping_add(1);
        }
        let key = (self.symbols[idx].name.clone(), self.symbols[idx].name_dedup);
        // A duplicate key here mirrors Ghidra's
        // "Could not deduplicate symbol" LowlevelError; overwrite is
        // unreachable because the dedup bump above reserved a fresh slot.
        self.nametree.insert(key, idx);
    }

    // Ghidra: database.cc:2152 ScopeInternal::renameSymbol
    /// Rename a symbol. Faithful to `ScopeInternal::renameSymbol`
    /// (database.cc:2152-2164): erase from the nametree under the old name,
    /// set both `name` and `displayName`, and reinsert via
    /// `insertNameTree`. (Ghidra additionally removes/reinserts
    /// `multiEntrySet` when `wholeCount > 1`; Rugra's LocalSymbol models
    /// exactly one whole mapping, so that branch cannot trigger.)
    pub fn rename_symbol(&mut self, idx: usize, newname: &str) {
        let old_key = (self.symbols[idx].name.clone(), self.symbols[idx].name_dedup);
        self.nametree.remove(&old_key);
        self.symbols[idx].name = newname.to_string();
        self.symbols[idx].display_name = newname.to_string();
        self.insert_name_tree(idx);
    }

    // Ghidra: database.cc:2520 ScopeInternal::buildUndefinedName
    /// Generate an official undefined placeholder name `$$undefXXXXXXXX`.
    /// Faithful to `ScopeInternal::buildUndefinedName` (database.cc:2520-2551):
    /// look at the nametree position just before "$$undefz"; if that symbol
    /// carries an undefined name, parse its 8 hex digits, increment, and
    /// re-emit; otherwise start at 00000000. Returns `None` for Ghidra's
    /// LowlevelError("Error creating undefined name").
    pub fn build_undefined_name(&self) -> Option<String> {
        // Symbol testsym((Scope*)0, "$$undefz", ...); iter = lower_bound(&testsym);
        let keys: Vec<&(String, u32)> = self.nametree.keys().collect();
        let lower_pos = keys
            .binary_search_by(|k| k.0.as_str().cmp("$$undefz").then(k.1.cmp(&0)))
            .unwrap_or_else(|p| p);
        // if (iter != nametree.begin()) --iter;
        let probe = if lower_pos > 0 { lower_pos - 1 } else { 0 };
        if probe < keys.len() {
            let symname = &keys[probe].0;
            if symname.len() == 15 && symname.starts_with("$$undef") {
                let hexpart = &symname[7..15];
                let uniq = u32::from_str_radix(hexpart, 16).ok();
                if let Some(uniq) = uniq.filter(|u| *u != u32::MAX) {
                    return Some(format!("$$undef{:08x}", uniq.wrapping_add(1)));
                }
                // istringstream failure or ~0 → LowlevelError.
                return None;
            }
        }
        Some("$$undef00000000".to_string())
    }

    // Ghidra: translate.hh:380 Translate::getRegisterName
    /// Register-name lookup standing in for
    /// `glb->translate->getRegisterName(space, off, size)`. The fixture
    /// installs an exact `(offset, size) → name` table; an absent entry
    /// returns the empty string exactly like a Translate without a matching
    /// register.
    pub fn get_register_name(
        &self,
        _space: crate::space::AddressSpace,
        offset: u64,
        size: i32,
    ) -> String {
        self.register_names
            .get(&(offset, size))
            .cloned()
            .unwrap_or_default()
    }

    // RUGRA-GLUE: local_range_in_range (RangeList::inRange for the local window)
    /// `RangeList::inRange(addr, 1)` over `self.local_range`: does any range
    /// contain the single byte at `offset`? Ghidra consults
    /// `fd->getFuncProto().getLocalRange()` directly (varmap.cc:555); Rugra
    /// caches the inclusive `(first, last)` ranges on the scope.
    pub fn local_range_in_range(&self, offset: u64) -> bool {
        self.local_range
            .iter()
            .any(|&(first, last)| first <= offset && offset <= last)
    }

    // Ghidra: database.cc:2824 ScopeInternal::setCategory
    /// Set the symbol's category. Faithful to `ScopeInternal::setCategory`
    /// (database.cc:2824-2845): clear the old category slot (pop trailing
    /// nulls), then append to the new category list — the passed index is
    /// honored for category 0 and recomputed to `list.size()` for category > 0.
    pub fn set_category(&mut self, idx: usize, cat: i32, ind: i32) {
        if self.symbols[idx].category >= 0 {
            let old_cat = self.symbols[idx].category as usize;
            if old_cat < self.category_lists.len() {
                let list = &mut self.category_lists[old_cat];
                let ci = self.symbols[idx].cat_index as usize;
                if ci < list.len() {
                    list[ci] = None;
                    while let Some(None) = list.last() {
                        list.pop();
                    }
                }
            }
        }
        self.symbols[idx].category = cat;
        self.symbols[idx].cat_index = ind.max(0) as u32;
        if cat < 0 {
            return;
        }
        while self.category_lists.len() <= cat as usize {
            self.category_lists.push(Vec::new());
        }
        let list = &mut self.category_lists[cat as usize];
        if cat > 0 {
            self.symbols[idx].cat_index = list.len() as u32;
        }
        while list.len() <= self.symbols[idx].cat_index as usize {
            list.push(None);
        }
        list[self.symbols[idx].cat_index as usize] = Some(idx);
    }

    // Ghidra: database.cc:2814 ScopeInternal::getCategorySymbol
    /// Get the symbol in category `cat` at index `ind`. Faithful to
    /// `ScopeInternal::getCategorySymbol` (database.cc:2814-2822).
    pub fn get_category_symbol(&self, cat: i32, ind: i32) -> Option<usize> {
        if cat < 0 || cat as usize >= self.category_lists.len() {
            return None;
        }
        if ind < 0 || ind as usize >= self.category_lists[cat as usize].len() {
            return None;
        }
        self.category_lists[cat as usize][ind as usize]
    }

    // Ghidra: database.cc:1530 Scope::addSymbol
    /// Add a symbol with storage. Faithful to `Scope::addSymbol`
    /// (database.cc:1530-1541) + `addSymbolInternal` (database.cc:1810-1840) +
    /// `addMapPoint` (database.cc:1548-1561): an empty name is replaced by a
    /// `$$undef` placeholder with `displayName` mirroring it
    /// (database.cc:1818-1821), the symbol joins the nametree
    /// (insertNameTree), and the whole mapping at `start` records `usepoint`
    /// as its first use address. Returns the new symbol's index.
    ///
    /// (Ghidra's symbolId allocation (database.cc:1813-1816) and the
    /// null/zero-size type LowlevelError checks (database.cc:1822-1825) have
    /// no Rugra counterpart: LocalSymbol has no id field and models its
    /// Datatype as optional throughout.)
    pub fn add_symbol(
        &mut self,
        space: crate::space::AddressSpace,
        nm: &str,
        ct: Option<Arc<Datatype>>,
        start: u64,
        usepoint: Option<u64>,
    ) -> usize {
        let idx = self.symbols.len();
        let mut sym = LocalSymbol::new(nm, start, 1, ct, symbol_category::NO_CATEGORY);
        sym.space = space;
        if sym.name.is_empty() {
            sym.name = self.build_undefined_name().unwrap_or_else(|| "$$undef00000000".into());
            sym.display_name = sym.name.clone();
        }
        sym.usepoint = usepoint;
        let size = sym
            .dtype
            .as_ref()
            .map(|d| d.get_size() as i32)
            .unwrap_or(1);
        sym.size = size;
        self.symbols.push(sym);
        self.insert_name_tree(idx);
        // addMapPoint (database.cc:1548-1557): a valid usepoint restricts the
        // uselimit to that single address, then Scope::addMap (via
        // addMapInternal, database.cc:1155) installs the static entry with
        // extraflags = Varnode::mapped.
        let code_index = ghidra_space_index(&crate::space::AddressSpace::Ram);
        let uselimit = match usepoint {
            None => Vec::new(),
            Some(up) => vec![(code_index, up, up)],
        };
        self.add_map_entry(idx, space, start, size, 0, crate::varnode::varnode_flags::MAPPED, uselimit);
        idx
    }

    // Ghidra: database.cc:1843 ScopeInternal::addMapInternal
    /// Install one static SymbolEntry into the scope's maptable (the entry
    /// log this module materializes per query). Faithful to
    /// `addMapInternal` (database.cc:1843-1872) + the addMap flag logic
    /// (database.cc:1149-1155): an EMPTY uselimit sets the Symbol's
    /// `addrtied` flag before the sub-sort is frozen; the entry's subsort is
    /// computed once, at insertion (rangemap.hh:238 calls `getSubsort()` on
    /// the new record); the uselimit ranges are kept sorted by
    /// `(space index, first)` — the `set<Range>` order of the oracle's
    /// RangeList (address.hh:202-205) — with adjacent same-space ranges
    /// merged the way `RangeList::insertRange` merges them. The wrap check
    /// (database.cc:1855-1861) is the caller's duty
    /// (`add_fake_input_symbol` keeps the exact LowlevelError text).
    pub fn add_map_entry(
        &mut self,
        sym: usize,
        space: crate::space::AddressSpace,
        start: u64,
        size: i32,
        offset: i32,
        extraflags: u32,
        uselimit: Vec<(i32, u64, u64)>,
    ) {
        if uselimit.is_empty() {
            self.symbols[sym].addrtied = true; // database.cc:1149-1150
        }
        let mut ranges = uselimit;
        ranges.sort_unstable();
        let mut merged: Vec<(i32, u64, u64)> = Vec::with_capacity(ranges.len());
        for (idx, first, last) in ranges {
            // RangeList::insertRange merges only overlapping ranges in the
            // same space; an adjacent predecessor (last == first-1) is
            // excluded by `(*iter1).last < first` and stays separate
            // (address.cc:385-410; SCOPELOCAL-RANGE-STATE-0001 invariant).
            if let Some(&(prev_idx, _, prev_last)) = merged.last() {
                if idx == prev_idx && prev_last >= first {
                    if last > prev_last {
                        merged.last_mut().unwrap().2 = last;
                    }
                    continue;
                }
            }
            merged.push((idx, first, last));
        }
        let subsort = Self::entry_subsort(self.symbols[sym].addrtied, &merged);
        self.mapentry_log.push(LocalMapEntry {
            sym,
            space,
            start,
            size,
            offset,
            extraflags,
            uselimit: merged,
            subsort,
        });
    }

    // Ghidra: database.cc:1530 Scope::addSymbol
    /// Install a fully-formed LocalSymbol with its primary mapping — the
    /// fixture/test construction path mirroring `Scope::addSymbol` +
    /// `addMapPoint`: the symbol joins the nametree and its static entry is
    /// derived from the mirror fields (space/start/usepoint; a dynamic
    /// symbol takes NO static entry, database.cc:1874-1886). Production
    /// construction goes through `add_symbol`/`add_dynamic_symbol`.
    pub fn install_symbol(&mut self, sym: LocalSymbol) -> usize {
        let idx = self.symbols.len();
        let space = sym.space;
        let start = sym.start;
        let size = sym.size;
        let usepoint = sym.usepoint;
        let is_dynamic = sym.is_dynamic;
        let mut sym = sym;
        // Single-entry equivalence of the addMap flag rule
        // (database.cc:1149-1150).
        sym.addrtied = usepoint.is_none() && !is_dynamic;
        self.symbols.push(sym);
        self.insert_name_tree(idx);
        if !is_dynamic {
            let code_index = ghidra_space_index(&crate::space::AddressSpace::Ram);
            let uselimit = match usepoint {
                None => Vec::new(),
                Some(up) => vec![(code_index, up, up)],
            };
            self.add_map_entry(
                idx,
                space,
                start,
                size,
                0,
                crate::varnode::varnode_flags::MAPPED,
                uselimit,
            );
        }
        idx
    }

    // Ghidra: database.cc:1690 Scope::addDynamicSymbol
    /// Add a symbol whose storage is a dynamic hash rather than an address.
    /// Faithful to `Scope::addDynamicSymbol` (database.cc:1690-1701) +
    /// `addDynamicMapInternal` (database.cc:1666-1676): the Symbol is created
    /// with an empty name (`addSymbolInternal`'s `$$undef` placeholder), the
    /// dynamic map records `hash`, offset 0, `ct`'s size, extraflags
    /// `Varnode::mapped`, and a uselimit restricted to the single address
    /// `caddr` when it is valid. Returns the new symbol's index.
    pub fn add_dynamic_symbol(
        &mut self,
        nm: &str,
        ct: Option<Arc<Datatype>>,
        hash: u64,
        caddr: Option<u64>,
    ) -> usize {
        let idx = self.symbols.len();
        let size = ct.as_ref().map(|d| d.get_size() as i32).unwrap_or(1);
        let mut sym = LocalSymbol::new(nm, 0, size, ct, symbol_category::NO_CATEGORY);
        sym.is_dynamic = true;
        sym.hash = hash;
        // rnglist.insertRange(caddr) — a valid caddr restricts the uselimit to
        // that single address; the map's address field stays invalid
        // (database.cc:1668-1670), modeled by leaving `start` at 0 with
        // `is_dynamic` set (query_properties skips dynamic entries).
        sym.usepoint = caddr;
        if sym.name.is_empty() {
            sym.name = self.build_undefined_name().unwrap_or_else(|| "$$undef00000000".into());
            sym.display_name = sym.name.clone();
        }
        self.symbols.push(sym);
        self.insert_name_tree(idx);
        idx
    }

    // Ghidra: database.cc:1263 Scope::queryProperties
    /// Find the smallest static SymbolEntry whose storage contains
    /// `[offset, offset+size)` in the given space and whose use-limit admits
    /// `usepoint` — the `linkSymbol` projection of `Scope::queryProperties`
    /// (database.cc:1263-1281) restricted to this local scope: production
    /// has no parent-scope handle (the Database unification gap,
    /// DB-LOCALSCOPE-MAP-0001), and the flags side-output has no linkSymbol
    /// consumer (funcdata_varnode.cc:1169). See `query_properties_ex` for
    /// the full stackContainer walk. Returns the symbol index, mirroring
    /// the non-null `SymbolEntry*` return.
    pub fn query_properties(
        &self,
        space: crate::space::AddressSpace,
        offset: u64,
        size: i64,
        usepoint: Option<u64>,
    ) -> Option<usize> {
        self.query_properties_ex(space, offset, size, usepoint, None, &|_, _| 0)
            .entry
            .map(|entry| entry.sym)
    }

    // Ghidra: database.cc:1263 Scope::queryProperties (+ database.cc:943
    // Scope::stackContainer, database.cc:3185 Database::mapScope)
    /// Full `Scope::queryProperties` walk, faithful to
    /// database.cc:1263-1281: `mapScope` returns the querying scope when the
    /// Database resolvemap is empty (database.cc:3187-3188 — no namespace
    /// scopes in the fixture domain), then `stackContainer`
    /// (database.cc:943-962) walks this scope and the optional parent:
    /// `findContainer` at each level, then the scope-ownership
    /// (`inScope`, database.hh:597) "discovery of new variable" stop. The
    /// flags side-output follows the oracle's three branches — the answering
    /// entry's `getAllFlags()` (database.hh:271),
    /// `mapped|addrtied(|persist for the global scope)|property(addr)` for
    /// a scope-only answer (database.cc:1273-1276), and the bare Database
    /// property for no scope at all (database.cc:1279) — with a
    /// constant-space address short-circuiting to the last branch
    /// (database.cc:950). `property` models
    /// `glb->symboltab->getProperty(addr)` (Database::flagbase,
    /// database.hh:946); production passes the empty lookup.
    pub fn query_properties_ex(
        &self,
        space: crate::space::AddressSpace,
        offset: u64,
        size: i64,
        usepoint: Option<u64>,
        parent: Option<&ScopeLocal>,
        property: &dyn Fn(crate::space::AddressSpace, u64) -> u32,
    ) -> QueryPropertiesOutcome {
        use crate::varnode::varnode_flags;
        // stackContainer (database.cc:950): a constant address never enters
        // a scope.
        if space == crate::space::AddressSpace::Const {
            return QueryPropertiesOutcome {
                entry: None,
                flags: property(space, offset),
                final_scope: QueryFinalScope::None,
            };
        }
        // database.cc:1268-1270 — this scope's findContainer answers.
        if let Some(entry) = self.find_container_entry(space, offset, size, usepoint) {
            let flags = self.entry_all_flags(&entry);
            return QueryPropertiesOutcome {
                entry: Some(entry),
                flags,
                final_scope: QueryFinalScope::This,
            };
        }
        // database.cc:957-958 + 1271-1277 — scope ownership without a
        // symbol: mapped|addrtied, persist only for the global scope.
        if self.in_scope(space, offset, size) {
            let mut flags = varnode_flags::MAPPED | varnode_flags::ADDRTIED;
            if self.is_global_scope {
                flags |= varnode_flags::PERSIST;
            }
            flags |= property(space, offset);
            return QueryPropertiesOutcome {
                entry: None,
                flags,
                final_scope: QueryFinalScope::This,
            };
        }
        // database.cc:959 — walk to the parent scope.
        if let Some(parent) = parent {
            if let Some(entry) = parent.find_container_entry(space, offset, size, usepoint) {
                let flags = parent.entry_all_flags(&entry);
                return QueryPropertiesOutcome {
                    entry: Some(entry),
                    flags,
                    final_scope: QueryFinalScope::Parent,
                };
            }
            if parent.in_scope(space, offset, size) {
                let mut flags = varnode_flags::MAPPED | varnode_flags::ADDRTIED;
                if parent.is_global_scope {
                    flags |= varnode_flags::PERSIST; // database.cc:1274-1275
                }
                flags |= property(space, offset);
                return QueryPropertiesOutcome {
                    entry: None,
                    flags,
                    final_scope: QueryFinalScope::Parent,
                };
            }
        }
        // database.cc:1278-1279 — no scope claimed the address.
        QueryPropertiesOutcome {
            entry: None,
            flags: property(space, offset),
            final_scope: QueryFinalScope::None,
        }
    }

    // Ghidra: database.cc:1756 Scope::buildDefaultName
    /// Create the default name for a symbol. Faithful to
    /// `Scope::buildDefaultName` (database.cc:1756-1786). With a
    /// representative Varnode (ActionNameVars' namerec path, coreaction.cc:2992)
    /// the flags/index come from the varnode and its HighVariable; otherwise
    /// (the `assignDefaultNames` path, database.cc:2862) the first mapping's
    /// address and use-point provide them — an invalid use-point yields the
    /// `addrtied` flag (database.cc:1776), and a function-parameter category
    /// forces the `input` flag with `catindex+1` as the parameter index
    /// (database.cc:1777-1781). Returns `None` for a LowlevelError from
    /// `buildVariableName`/`makeNameUnique`.
    pub fn build_default_name(
        &mut self,
        idx: usize,
        base: &mut i32,
        vn: Option<&Varnode>,
        fd: Option<&crate::funcdata::Funcdata>,
    ) -> Option<String> {
        use crate::varnode::varnode_flags;
        if let Some(vn) = vn {
            if !vn.is_constant() {
                // Address usepoint; if (!vn->isAddrTied() && fd != 0) usepoint = vn->getUsePoint(*fd);
                let usepoint: Option<u64> = if !vn.is_addr_tied() {
                    fd.map(|f| vn.get_use_point(f).as_u64())
                } else {
                    None
                };
                let high_input = vn
                    .high
                    .as_ref()
                    .map(|h| {
                        // Ghidra's HighVariable::isInput lazily runs
                        // updateFlags (variable.hh:200); mirror that here so
                        // the input bit reflects the member varnodes.
                        h.write().unwrap().update_flags();
                        h.read().unwrap().is_input()
                    })
                    .unwrap_or(false);
                let dtype = self.symbols[idx].dtype.clone();
                if self.symbols[idx].category == symbol_category::FUNCTION_PARAMETER
                    || high_input
                {
                    let mut index: i32 = -1;
                    if self.symbols[idx].category == symbol_category::FUNCTION_PARAMETER {
                        index = self.symbols[idx].cat_index as i32 + 1;
                    }
                    return self.build_variable_name(
                        vn.get_space(), vn.get_offset(), usepoint,
                        dtype.as_ref(), &mut index,
                        vn.flags | varnode_flags::INPUT,
                    );
                }
                return self.build_variable_name(
                    vn.get_space(), vn.get_offset(), usepoint,
                    dtype.as_ref(), base, vn.flags,
                );
            }
        }
        // if (sym->numEntries() != 0) — Rugra LocalSymbol always models one entry.
        let sym = &self.symbols[idx];
        // entry->getAddr(): for a dynamic entry the map address is invalid
        // (database.cc:1668) and only the uselimit (usepoint = caddr) is
        // meaningful — buildVariableName's local branch (flags==0) never
        // consults the address there, matching Ghidra's flow.
        let space = sym.space;
        let addr = sym.start;
        let usepoint = sym.usepoint;
        let dtype = sym.dtype.clone();
        let mut flags: u32 = if usepoint.is_none() {
            varnode_flags::ADDRTIED
        } else {
            0
        };
        if sym.category == symbol_category::FUNCTION_PARAMETER {
            flags |= varnode_flags::INPUT;
            let mut index = sym.cat_index as i32 + 1;
            return self.build_variable_name(
                space, addr, usepoint, dtype.as_ref(), &mut index, flags,
            );
        }
        self.build_variable_name(space, addr, usepoint, dtype.as_ref(), base, flags)
    }

    // RUGRA-GLUE: symbols_in_nametree_order (locked naming-fixture observation accessor)
    /// Read-only view of the symbol indices in SymbolNameTree order
    /// (database.hh:373, sorted by name then nameDedup). Production C++
    /// iterates the `nametree` set directly; the locked naming fixture needs
    /// the same walk order through the public API to observe the
    /// `assignDefaultNames` traversal byte-comparably.
    pub fn symbols_in_nametree_order(&self) -> Vec<usize> {
        self.nametree
            .values()
            .copied()
            .filter(|&idx| idx < self.symbols.len())
            .collect()
    }

    // Ghidra: database.cc:2850 ScopeInternal::assignDefaultNames
    /// Assign a default name to any symbol whose name is undefined. Faithful
    /// to `ScopeInternal::assignDefaultNames` (database.cc:2850-2865): walk
    /// the nametree from `upper_bound("$$undef")`, and while symbols keep the
    /// `$$undef` placeholder, build a default name via `buildDefaultName`
    /// with the shared `base` counter and rename the symbol. The iterator is
    /// advanced BEFORE renaming (database.cc:2861) so the mutation cannot
    /// disturb the walk. Returns `None` on a LowlevelError.
    pub fn assign_default_names(&mut self, base: &mut i32) -> Option<()> {
        // iter = nametree.upper_bound(&testsym) — first key > ("$$undef", 0).
        let walk: Vec<(String, u32)> = self
            .nametree
            .range((
                std::ops::Bound::Excluded(("$$undef".to_string(), 0u32)),
                std::ops::Bound::Unbounded,
            ))
            .map(|(k, _)| k.clone())
            .collect();
        for key in walk {
            let idx = match self.nametree.get(&key) {
                Some(&i) if i < self.symbols.len() => i,
                // Slot vacated by an external symbols.clear() or by an
                // earlier rename in this walk; Ghidra's iterator cannot see
                // either, so treat as exhausted.
                _ => break,
            };
            if !self.symbols[idx].is_name_undefined() {
                break;
            }
            let nm = self.build_default_name(idx, base, None, None)?;
            self.rename_symbol(idx, &nm);
        }
        Some(())
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
    /// Assign a Symbol to any input Varnode stored in the scope's address
    /// space which could be a parameter but isn't in the formal prototype of
    /// the function (those are already in the scope marked category '0').
    /// Faithful 1:1 port of `ScopeLocal::fakeInputSymbols`
    /// (varmap.cc:1392-1448):
    ///
    /// 1. Only offsets whose FIRST address alone (size 1) passes
    ///    `fd->getFuncProto().getParamRange().inRange(addr,1)` (varmap.cc:1407)
    ///    become fake inputs — negative-growth locals at flipped (huge) stack
    ///    offsets are filtered out.
    /// 2. Each surviving varnode opens a group; subsequent varnodes in
    ///    `fd->beginDef(Varnode::input)` order (VarnodeCompareDefLoc:
    ///    space, offset, size) extend the group while they stay in the
    ///    scope's space AND overlap (`off2 <= endpoint` — adjacent-but-
    ///    non-overlapping varnodes do NOT merge, varmap.cc:1409-1419).
    /// 3. A group is skipped entirely when any member Varnode is typelocked
    ///    (varmap.cc:1416-1417, 1420).
    /// 4. With locked inputs present, the group is also skipped when the
    ///    last examined varnode of the inner loop (the breaking varnode, or
    ///    the outer one when the loop never entered) resolves through
    ///    `queryProperties` to an existing `function_parameter` Symbol
    ///    (varmap.cc:1428-1435).
    /// 5. `endpoint`/`size` arithmetic is uintb modulo 2^64 (wrapping)
    ///    (varmap.cc:1408/1413/1437).
    /// 6. `addSymbol("",getBase(size,TYPE_UNKNOWN),addr,invalid-usepoint)` +
    ///    `setCategory(sym, Symbol::fake_input, -1)`; a LowlevelError from
    ///    the addSymbol chain (no/zero-size type, or a mapping that wraps
    ///    past the end of the address space, database.cc:1822-1825/1855-1861)
    ///    is caught and routed to `fd->warningHeader` (varmap.cc:1439-1445)
    ///    without aborting the scan.
    pub fn fake_input_symbols(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        types: &Arc<RwLock<crate::type_system::typefactory::TypeFactory>>,
    ) {
        // int4 lockedinputs = getCategorySize(Symbol::function_parameter);
        // (varmap.cc:1395)
        let lockedinputs = self.get_category_size(symbol_category::FUNCTION_PARAMETER) as i32;

        // iter = fd->beginDef(Varnode::input); enditer = fd->endDef(...)
        // (varmap.cc:1398-1399). Inputs form a prefix of the def_tree
        // (VarnodeCompareDefLoc varnode.cc:60-79: input, then written, then
        // free), ordered by (space index, offset, size). Snapshot in that
        // order so index arithmetic reproduces the iterator walk.
        let mut inputs: Vec<(crate::space::AddressSpace, u64, i32, bool)> = Vec::new();
        for entry in &fd.vbank.def_tree {
            let vn = entry.0.read().unwrap();
            if !vn.is_input() {
                break; // reached endDef(Varnode::input)
            }
            inputs.push((vn.get_space(), vn.get_offset(), vn.get_size() as i32, vn.is_type_lock()));
        }

        // fd->getFuncProto().getParamRange() (varmap.cc:1407 via fspec.hh:1540).
        let paramrange = func_proto_param_range(fd);

        let mut iter = 0usize;
        while iter < inputs.len() {
            let (spc, addr_off, sz, mut locked) = inputs[iter];
            let group_start = iter;
            iter += 1; // Varnode *vn = *iter++;
            if spc != self.space {
                continue; // varmap.cc:1405
            }
            // Only allow offsets which can be parameters — the FIRST address
            // alone (size 1), not the whole varnode extent (varmap.cc:1407).
            if !param_range_in_range(&paramrange, addr_off) {
                continue;
            }
            // uintb endpoint = addr.getOffset() + vn->getSize() - 1;
            // (varmap.cc:1408) — uintb wraps modulo 2^64.
            let mut endpoint = addr_off.wrapping_add(sz as u64).wrapping_sub(1);
            // `vn` for the queryProperties probe below (varmap.cc:1430):
            // the inner loop assigns the breaker varnode to `vn` before
            // testing it, and leaves the outer varnode in place when the
            // loop body never runs.
            let mut last = inputs[group_start];
            while iter < inputs.len() {
                let cand = inputs[iter];
                last = cand; // vn = *iter; (varmap.cc:1410)
                if cand.0 != self.space {
                    break; // varmap.cc:1411
                }
                if endpoint < cand.1 {
                    break; // varmap.cc:1412 — gap: adjacent inputs do NOT merge
                }
                let newendpoint = cand.1.wrapping_add(cand.2 as u64).wrapping_sub(1); // cc:1413
                if endpoint < newendpoint {
                    endpoint = newendpoint; // cc:1414-1415
                }
                if cand.3 {
                    locked = true; // cc:1416-1417
                }
                iter += 1; // cc:1418
            }
            if !locked {
                // varmap.cc:1428-1435: with a locked input prototype, double
                // check that vn doesn't already have a representative
                // parameter Symbol (the input prototype may be locked with
                // TYPE_UNKNOWN members that never got typelocked).
                if lockedinputs != 0 {
                    if let Some(symidx) =
                        self.find_container_invalid_usepoint(last.0, last.1, last.2)
                    {
                        if self.symbols[symidx].category == symbol_category::FUNCTION_PARAMETER {
                            continue; // Found a matching symbol (varmap.cc:1433)
                        }
                    }
                }

                // int4 size = (endpoint - addr.getOffset()) + 1; (varmap.cc:1437)
                let size = endpoint.wrapping_sub(addr_off).wrapping_add(1) as i32;
                // try { addSymbol("",ct,addr,usepoint); setCategory(...) }
                // catch(LowlevelError) { fd->warningHeader(...) } (cc:1438-1445)
                if let Err(explain) = self.add_fake_input_symbol(types, addr_off, size) {
                    fd.warning_header(&explain);
                }
            }
        }
    }

    // Ghidra: database.cc:2806 ScopeInternal::getCategorySize
    /// Number of slots in a category list (null slots popped by setCategory
    /// still count while they are not trailing). Faithful to
    /// `ScopeInternal::getCategorySize` (database.cc:2806-2812): a negative
    /// or unallocated category reports 0.
    pub fn get_category_size(&self, cat: i32) -> usize {
        if cat < 0 {
            return 0;
        }
        self.category_lists
            .get(cat as usize)
            .map(|list| list.len())
            .unwrap_or(0)
    }

    // Ghidra: database.cc:2250 ScopeInternal::findContainer (invalid usepoint) +
    // database.cc:1263 Scope::queryProperties
    /// Find the smallest whole Symbol mapping that fully contains
    /// `[addr, addr+size-1]` and is valid at an INVALID use point — the
    /// container probe behind the `queryProperties` call at varmap.cc:1430.
    /// Thin delegate of `find_container_entry` with `usepoint = None`:
    /// only address-tied entries (no use limit) match an invalid use point
    /// (database.cc:114-120), and dynamic entries are not in the address
    /// range map.
    ///
    /// (Ghidra's `Scope::queryProperties` walks up through parent scopes
    /// after this scope; Rugra's varmap ScopeLocal has no parent linkage —
    /// the database-scope unification gap recorded for the scope stack — so
    /// only this scope's symbols can answer.)
    fn find_container_invalid_usepoint(
        &self,
        space: crate::space::AddressSpace,
        addr: u64,
        size: i32,
    ) -> Option<usize> {
        self.find_container_entry(space, addr, size as i64, None)
            .map(|entry| entry.sym)
    }

    // Ghidra: database.cc:1810 ScopeInternal::addSymbolInternal +
    // database.cc:1843 ScopeInternal::addMapInternal (via varmap.cc:1440 addSymbol)
    /// Create the fake-input Symbol the way `Scope::addSymbol` does, with the
    /// LowlevelError surfaces that `fakeInputSymbols` catches
    /// (varmap.cc:1439-1445): the no-type/zero-size-type checks of
    /// `addSymbolInternal` (database.cc:1822-1825) and the end-of-address-
    /// space wrap check of `addMapInternal` (database.cc:1855-1861).
    /// `addr`/`size` model the mapping `[addr, addr+size-1]` in the scope's
    /// 8-byte stack space, where Ghidra's `Address::operator+` wrapOffset is
    /// the uintb identity, so the wrap test is uintb modulo 2^64.
    fn add_fake_input_symbol(
        &mut self,
        types: &Arc<RwLock<crate::type_system::typefactory::TypeFactory>>,
        addr: u64,
        size: i32,
    ) -> Result<(), String> {
        // sym->name = buildUndefinedName() runs before the type checks
        // (database.cc:1818-1821), so the exception texts carry the
        // placeholder name the symbol would have taken.
        let placeholder = self
            .build_undefined_name()
            .unwrap_or_else(|| "$$undef00000000".to_string());
        if size < 1 {
            // getBase never yields a null type (type.cc:3631-3660: the
            // TYPE_UNKNOWN arm skips the cache and falls through to
            // TypeBase(s,m)+findAdd), so a size<1 request walks the
            // "zero size type" arm at database.cc:1824-1825, not the
            // null-type arm at 1822-1823. Unreachable from
            // fakeInputSymbols (endpoint >= addr forces size >= 1); text
            // kept for arm fidelity. Ghidra s<0 with a float metatype is a
            // typecache[9][8] OOB UB (type.hh:774) — no oracle exists.
            return Err(format!("{} symbol created with zero size type", placeholder));
        }
        // Address lastaddress = addr + (sz-1); (database.cc:1855) — the
        // mapping must not wrap past the end of the address space.
        let lastaddress = addr.wrapping_add(size as u64).wrapping_sub(1);
        if lastaddress < addr {
            return Err(format!(
                "Symbol {} extends beyond the end of the address space",
                placeholder
            ));
        }
        // Datatype *ct = fd->getArch()->types->getBase(size,TYPE_UNKNOWN);
        // (varmap.cc:1438)
        let ct = make_int_type(types, size as usize);
        // Symbol *sym = addSymbol("",ct,addr,usepoint)->getSymbol(); (cc:1440)
        let idx = self.add_symbol(self.space, "", Some(ct), addr, None);
        // setCategory(sym, Symbol::fake_input, -1); (cc:1441)
        self.set_category(idx, symbol_category::FAKE_INPUT, -1);
        Ok(())
    }

    // Ghidra: database.cc:2392 ScopeInternal::findOverlap (single-byte stack probe)
    /// Look up a stack symbol by offset — the partition-owner answer of
    /// `ScopeInternal::findOverlap` for the one-byte query at `offset`: the
    /// record covering the partition unit containing the byte with the
    /// smallest EntrySubsort, dynamic entries invisible (F1+F2,
    /// SCOPE-FINDOVERLAP-KEY-0001). Stack-restricted as before: symbols
    /// created by `Funcdata::linkSymbol` (funcdata_varnode.cc:1177) in other
    /// spaces (register/unique/ram) share this Vec but never answer a stack
    /// query.
    pub fn find_symbol(&self, offset: u64) -> Option<&LocalSymbol> {
        let idx = self.find_overlap(crate::space::AddressSpace::Stack, offset, 1)?;
        Some(&self.symbols[idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_system::datatype::TypeBase;

    fn int_dt(size: usize, mt: TypeMetatype) -> Arc<Datatype> {
        Arc::new(Datatype::Base(TypeBase::new("x".into(), size, mt)))
    }

    /// Named base type: printNameBase (type.hh:273) writes name[0], so a
    /// "int"/"char" type yields the i/c prefixes of Ghidra's variable names.
    fn named_dt(nm: &str, size: usize, mt: TypeMetatype) -> Arc<Datatype> {
        Arc::new(Datatype::Base(TypeBase::new(nm.into(), size, mt)))
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
        let types = crate::type_system::typefactory::TypeFactory::shared_default();
        let mut a = RangeHint::new(0, 4, 0, Some(int_dt(4, TypeMetatype::Int)), 0, RangeType::Fixed, -1);
        let b = RangeHint::new(0, 4, 0, Some(int_dt(4, TypeMetatype::Int)), 0, RangeType::Fixed, -1);
        let overlap = a.merge_with(&b, &types).unwrap();
        assert!(!overlap); // reconcilable → false
        assert_eq!(a.size, 4);
    }

    #[test]
    fn test_rangehint_merge_confuse_to_unknown() {
        // a: int4@[0,4), b: int8@[2,10) — NOT contained, NOT locked → resType=2.
        // Result: unknown type, size = (2-0)+8 = 10 → not in {1,2,4,8} → size 1, open.
        let types = crate::type_system::typefactory::TypeFactory::shared_default();
        let mut a = RangeHint::new(0, 4, 0, Some(int_dt(4, TypeMetatype::Int)), 0, RangeType::Fixed, -1);
        let b = RangeHint::new(2, 8, 2, Some(int_dt(8, TypeMetatype::Int)), 0, RangeType::Fixed, -1);
        let overlap = a.merge_with(&b, &types).unwrap();
        assert!(!overlap);
        assert_eq!(a.size, 1);
        assert_eq!(a.range_type, RangeType::Open);
        assert_eq!(a.dtype.as_ref().unwrap().get_metatype(), TypeMetatype::Unknown);
        // resType==2 draws the unknown from the threaded factory
        // (varmap.cc:309): canonical spelling + factory identity.
        let dt = a.dtype.as_ref().unwrap();
        assert_eq!(dt.get_name(), "undefined1");
        assert!(Arc::ptr_eq(dt, &make_int_type(&types, 1)));
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
        use crate::varnode::varnode_flags;
        let mut scope = ScopeLocal::new(); // stack_grows_negative (x86)
        scope.local_range = vec![(0, u64::MAX)];
        // For a negative-growing stack, a high unsigned offset (a local) maps
        // to a negative signed value, which is negated to positive magnitude.
        // offset = 0xfffffffffffffff0 → signed -16 → negated +16 → "Stack_10".
        let mut index = 1;
        let name = scope.build_variable_name(
            crate::space::AddressSpace::Stack, 0xfffffffffffffff0, None,
            Some(&named_dt("int", 4, TypeMetatype::Int)), &mut index,
            varnode_flags::ADDRTIED,
        ).unwrap();
        // printNameBase("int") = 'i', so the name is "iStack_10" — Ghidra's
        // auStack_/abStack_ style (varmap.cc:561-565).
        assert_eq!(name, "iStack_10");
        // A small positive offset (parameter region) → negated to negative → 'X'.
        let mut index = 1;
        let name2 = scope.build_variable_name(
            crate::space::AddressSpace::Stack, 0x10, None,
            Some(&named_dt("int", 4, TypeMetatype::Int)), &mut index,
            varnode_flags::ADDRTIED,
        ).unwrap();
        assert!(name2.starts_with("iStackX_"), "got {}", name2);
    }

    #[test]
    fn test_build_variable_name_positive() {
        use crate::varnode::varnode_flags;
        let mut scope = ScopeLocal::new();
        scope.stack_direction = -1; // positive growth → no negation
        scope.stack_grows_negative = false;
        scope.local_range = vec![(0, u64::MAX)];
        // offset 0x10 → start = 0x10 > 0 → plain "Stack_10".
        let mut index = 1;
        let name = scope.build_variable_name(
            crate::space::AddressSpace::Stack, 0x10, None,
            Some(&named_dt("int", 4, TypeMetatype::Int)), &mut index,
            varnode_flags::ADDRTIED,
        ).unwrap();
        assert_eq!(name, "iStack_10");
    }

    // --- assignDefaultNames shared base counter (database.cc:2850) ---

    #[test]
    fn test_assign_default_names_shared_base_counter() {
        // Three unnamed locals with DIFFERENT type prefixes must draw from the
        // ONE shared base counter (per-prefix counters would restart at 1).
        let mut scope = ScopeLocal::new();
        scope.add_symbol(
            crate::space::AddressSpace::Stack, "", Some(named_dt("int", 4, TypeMetatype::Int)), 0xfffffff0, Some(0x1000));
        scope.add_symbol(
            crate::space::AddressSpace::Stack, "", Some(named_dt("char", 1, TypeMetatype::Int)), 0xfffffff4, Some(0x1000));
        scope.add_symbol(
            crate::space::AddressSpace::Stack, "", Some(Arc::new(Datatype::Pointer(
            crate::type_system::datatype::TypePointer {
                base: TypeBase::new("char *".into(), 8, TypeMetatype::Pointer),
                ptr_to: named_dt("int", 4, TypeMetatype::Int),
                wordsize: 1,
            }))), 0xfffffff8, Some(0x1000));
        let mut base: i32 = 1;
        scope.assign_default_names(&mut base).unwrap();
        assert_eq!(base, 4); // 3 names consumed the shared counter
        let names: Vec<&str> = scope.symbols.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["iVar1", "cVar2", "piVar3"]);
        // Idempotence: a second run finds no $$undef symbols.
        scope.assign_default_names(&mut base).unwrap();
        assert_eq!(base, 4);
    }

    #[test]
    fn test_make_name_unique_suffix_forms() {
        let mut scope = ScopeLocal::new();
        scope.add_symbol(
            crate::space::AddressSpace::Stack, "iVar1", Some(int_dt(4, TypeMetatype::Int)), 0, None);
        // "iVar1" is taken → new sequence "_00".
        assert_eq!(scope.make_name_unique("iVar1").unwrap(), "iVar1_00");
        scope.add_symbol(
            crate::space::AddressSpace::Stack, "iVar1_00", Some(int_dt(4, TypeMetatype::Int)), 0, None);
        // Last existing id 0 → next is 01 (2-digit form).
        assert_eq!(scope.make_name_unique("iVar1").unwrap(), "iVar1_01");
        scope.add_symbol(
            crate::space::AddressSpace::Stack, "iVar1_01", Some(int_dt(4, TypeMetatype::Int)), 0, None);
        scope.add_symbol(
            crate::space::AddressSpace::Stack, "iVar1_02", Some(int_dt(4, TypeMetatype::Int)), 0, None);
        // Last existing id 2 → next is 03.
        assert_eq!(scope.make_name_unique("iVar1").unwrap(), "iVar1_03");
        // A free name returns unchanged.
        assert_eq!(scope.make_name_unique("freeVar").unwrap(), "freeVar");
    }

    #[test]
    fn test_param_category_uses_catindex_not_base() {
        // function_parameter category: name comes from catindex+1, and the
        // shared base counter is NOT consumed (database.cc:1777-1781).
        let mut scope = ScopeLocal::new();
        let p1 = scope.add_symbol(
            crate::space::AddressSpace::Stack, "", Some(int_dt(8, TypeMetatype::Int)), 0x20, Some(0x100));
        let p2 = scope.add_symbol(
            crate::space::AddressSpace::Stack, "", Some(int_dt(8, TypeMetatype::Int)), 0x30, Some(0x100));
        scope.set_category(p1, symbol_category::FUNCTION_PARAMETER, 0);
        scope.set_category(p2, symbol_category::FUNCTION_PARAMETER, 1);
        let mut base: i32 = 1;
        scope.assign_default_names(&mut base).unwrap();
        assert_eq!(base, 1); // untouched by the param branch
        let names: Vec<&str> = scope.symbols.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["param_1", "param_2"]);
    }

    // --- fakeInputSymbols helpers (VARMAP-FAKEINPUT-0001) ---

    #[test]
    fn test_get_category_size_database_cc_2806() {
        // Negative and unallocated categories report 0; allocated slots
        // count, including non-trailing nulls.
        let mut scope = ScopeLocal::new();
        assert_eq!(scope.get_category_size(symbol_category::FUNCTION_PARAMETER), 0);
        assert_eq!(scope.get_category_size(-1), 0);
        let p1 = scope.add_symbol(
            crate::space::AddressSpace::Stack, "", Some(int_dt(8, TypeMetatype::Int)), 0x20, None);
        scope.set_category(p1, symbol_category::FUNCTION_PARAMETER, 0);
        assert_eq!(scope.get_category_size(symbol_category::FUNCTION_PARAMETER), 1);
    }

    #[test]
    fn test_param_range_in_range_address_cc_468() {
        // upper_bound containment: last range with first <= offset must
        // reach the offset; empty list false; below-first false.
        let build = |pairs: &[(u64, u64)]| {
            let mut rl = crate::address::RangeList::new();
            for &(f, l) in pairs {
                if let Some(r) = crate::address::Range::new(
                    crate::address::Address::new(f),
                    crate::address::Address::new(l),
                ) {
                    rl.insert_range(r);
                }
            }
            rl
        };
        let rl = build(&[(8, 515)]);
        assert!(param_range_in_range(&rl, 8));
        assert!(param_range_in_range(&rl, 512)); // first byte only
        assert!(param_range_in_range(&rl, 515));
        assert!(!param_range_in_range(&rl, 7)); // below the range
        assert!(!param_range_in_range(&rl, 516)); // past the range
        assert!(!param_range_in_range(&rl, 0xfffffffffffffff0)); // flipped local
        assert!(!param_range_in_range(&build(&[]), 8)); // empty
    }

    #[test]
    fn test_find_container_invalid_usepoint() {
        // Smallest containing address-tied whole map wins (database.cc:2250);
        // usepoint-limited and dynamic entries never match an invalid
        // usepoint (database.cc:114-120); an exact-size hit short-circuits.
        let mut scope = ScopeLocal::new();
        let big = scope.add_symbol(
            crate::space::AddressSpace::Stack, "big", Some(int_dt(8, TypeMetatype::Int)), 0x10, None);
        let small = scope.add_symbol(
            crate::space::AddressSpace::Stack, "small", Some(int_dt(4, TypeMetatype::Int)), 0x14, None);
        let used = scope.add_symbol(
            crate::space::AddressSpace::Stack, "used", Some(int_dt(8, TypeMetatype::Int)), 0x40, Some(0x1000));
        let _ = (big, small, used);
        // Query [0x14,0x17]: big [0x10,0x17] contains it, small [0x14,0x17]
        // is the exact-size smallest → small wins.
        assert_eq!(scope.find_container_invalid_usepoint(crate::space::AddressSpace::Stack, 0x14, 4), Some(small));
        // Query [0x10,0x17] (8 bytes): only big contains it.
        assert_eq!(scope.find_container_invalid_usepoint(crate::space::AddressSpace::Stack, 0x10, 8), Some(big));
        // Query [0x40,0x47]: the only candidate has a use limit → no match.
        assert_eq!(scope.find_container_invalid_usepoint(crate::space::AddressSpace::Stack, 0x40, 8), None);
        // Dynamic entries are not in the address range map.
        let dyn_idx = scope.add_dynamic_symbol("dyn", Some(int_dt(8, TypeMetatype::Int)), 0x1234, None);
        assert_eq!(scope.find_container_invalid_usepoint(crate::space::AddressSpace::Stack, 0x60, 8), None);
        let _ = dyn_idx;
    }

    #[test]
    fn test_typelocked_name_survives_assign() {
        // A named (locked) symbol is never renamed by assignDefaultNames.
        let mut scope = ScopeLocal::new();
        let locked = scope.add_symbol(
            crate::space::AddressSpace::Stack, "cust_lock", Some(int_dt(4, TypeMetatype::Int)), 0x40, None);
        scope.symbols[locked].typelock = true;
        scope.symbols[locked].namelock = true;
        scope.add_symbol(
            crate::space::AddressSpace::Stack, "", Some(int_dt(4, TypeMetatype::Int)), 0x44, Some(0x100));
        let mut base: i32 = 1;
        scope.assign_default_names(&mut base).unwrap();
        assert_eq!(scope.symbols[locked].name, "cust_lock");
        assert_eq!(scope.symbols[locked].display_name, "cust_lock");
    }

    #[test]
    fn test_name_dedup_on_duplicate_names() {
        // Two symbols with the same name get nameDedup 0 and 1
        // (database.cc:2712-2727 insertNameTree).
        let mut scope = ScopeLocal::new();
        scope.add_symbol(
            crate::space::AddressSpace::Stack, "dup", Some(int_dt(4, TypeMetatype::Int)), 0, None);
        scope.add_symbol(
            crate::space::AddressSpace::Stack, "dup", Some(int_dt(4, TypeMetatype::Int)), 8, None);
        assert_eq!(scope.symbols[0].name_dedup, 0);
        assert_eq!(scope.symbols[1].name_dedup, 1);
        assert_eq!(scope.find_first_by_name("dup"), Some(0));
    }

    #[test]
    fn test_build_undefined_name_sequence() {
        let mut scope = ScopeLocal::new();
        assert_eq!(scope.build_undefined_name().unwrap(), "$$undef00000000");
        scope.add_symbol(
            crate::space::AddressSpace::Stack, "", Some(int_dt(4, TypeMetatype::Int)), 0, None);
        assert_eq!(scope.symbols[0].name, "$$undef00000000");
        assert_eq!(scope.build_undefined_name().unwrap(), "$$undef00000001");
        scope.add_symbol(
            crate::space::AddressSpace::Stack, "", Some(int_dt(4, TypeMetatype::Int)), 4, None);
        assert_eq!(scope.symbols[1].name, "$$undef00000001");
        assert!(scope.symbols[0].is_name_undefined());
    }

    // --- ScopeLocal.mark_unaliased (varmap.cc:1332) distance heuristic ---

    #[test]
    fn test_mark_unaliased_no_aliases() {
        let mut scope = ScopeLocal::new();
        scope.symbols.push(LocalSymbol::new("a", 0, 4, None, symbol_category::NO_CATEGORY));
        scope.mark_unaliased(&[]);
        assert!(scope.symbols[0].unaliased);
    }

    #[test]
    fn test_mark_unaliased_near_boundary_aliased() {
        let mut scope = ScopeLocal::new();
        // Symbol [0,8), alias at offset 4 → curoff=7, alias<=7 → aliased,
        // and distance (7-4)=3 <= 0xffff → stays aliased.
        scope.symbols.push(LocalSymbol::new("a", 0, 8, None, symbol_category::NO_CATEGORY));
        scope.mark_unaliased(&[4]);
        assert!(!scope.symbols[0].unaliased);
    }

    #[test]
    fn test_mark_unaliased_far_past_boundary_unaliased() {
        let mut scope = ScopeLocal::new();
        // Symbol [0x20000, 4), alias at offset 4 → curoff=0x20003,
        // distance = 0x20003-4 > 0xffff → unaliased (distance heuristic).
        scope.symbols.push(LocalSymbol::new("a", 0x20000, 4, None, symbol_category::NO_CATEGORY));
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
        // adjustFit consults longestFit over the scope's range window
        // (varmap.cc:593); an empty window admits nothing.
        scope.local_range = vec![(0, 0xfffff)];
        let types = crate::type_system::typefactory::TypeFactory::shared_default();
        let overlap = scope.restructure(&mut state, &types).unwrap();
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
        scope.local_range = vec![(0, 0xfffff)];
        let types = crate::type_system::typefactory::TypeFactory::shared_default();
        let _overlap = scope.restructure(&mut state, &types).unwrap();
        // The merged range is emitted once at the finalization step; with the
        // endpoint added by initialize(), the single merged int4 is emitted.
        assert_eq!(scope.symbols.len(), 1);
        assert_eq!(scope.symbols[0].start, 0);
        assert_eq!(scope.symbols[0].size, 4);
    }

    // --- SCOPE-FINDOVERLAP-KEY-0001 (F1/F2/F3) ---

    fn overlap_sym(name: &str, start: u64, size: i32, usepoint: Option<u64>) -> LocalSymbol {
        let mut sym = LocalSymbol::new(name, start, size, None, symbol_category::NO_CATEGORY);
        sym.usepoint = usepoint;
        sym
    }

    fn install(scope: &mut ScopeLocal, sym: LocalSymbol) -> usize {
        scope.install_symbol(sym)
    }

    #[test]
    fn test_find_overlap_partition_unit_and_subsort() {
        // F1: "wide" [0x300,0x30f] usepoint 0x1010 vs "narrow" [0x308,0x30b]
        // usepoint 0x1000. The query start 0x309 lands in partition unit
        // [0x308,0x30b]; both records cover the unit, EntrySubsort picks
        // "narrow" (smaller first use). Min-START overlap would pick "wide".
        let mut scope = ScopeLocal::new();
        install(&mut scope, overlap_sym("wide", 0x300, 16, Some(0x1010)));
        install(&mut scope, overlap_sym("narrow", 0x308, 4, Some(0x1000)));
        let hit = scope.find_overlap(crate::space::AddressSpace::Stack, 0x309, 2).unwrap();
        assert_eq!(scope.symbols[hit].name, "narrow");
        // Query start 0x300 is in the wide-only unit [0x300,0x307].
        let hit = scope.find_overlap(crate::space::AddressSpace::Stack, 0x300, 2).unwrap();
        assert_eq!(scope.symbols[hit].name, "wide");
        // Address-tied beats use-limited on a shared unit regardless of
        // insertion order (database.cc:97-107: addrtied subsort (0,0)).
        let mut scope = ScopeLocal::new();
        install(&mut scope, overlap_sym("used", 0x320, 8, Some(0x1000)));
        install(&mut scope, overlap_sym("tied", 0x320, 8, None));
        let hit = scope.find_overlap(crate::space::AddressSpace::Stack, 0x322, 4).unwrap();
        assert_eq!(scope.symbols[hit].name, "tied");
    }

    #[test]
    fn test_find_overlap_gap_query_leftmost_unit() {
        // F1: query start uncovered — the leftmost partition unit starting
        // after the query start answers iff it begins before the query end.
        let mut scope = ScopeLocal::new();
        install(&mut scope, overlap_sym("gapend", 0x340, 4, Some(0x1000)));
        install(&mut scope, overlap_sym("gapfar", 0x344, 4, Some(0x1001)));
        let hit = scope.find_overlap(crate::space::AddressSpace::Stack, 0x338, 0x10).unwrap();
        assert_eq!(scope.symbols[hit].name, "gapend");
        assert_eq!(scope.find_overlap(crate::space::AddressSpace::Stack, 0x338, 0x6), None);
    }

    #[test]
    fn test_find_overlap_dynamic_invisible() {
        // F2: dynamic entries never enter the static map table
        // (addDynamicMapInternal database.cc:1874-1886).
        let mut scope = ScopeLocal::new();
        let mut dyn_sym = overlap_sym("dyn", 0, 8, Some(0x1000));
        dyn_sym.is_dynamic = true;
        dyn_sym.hash = 0x1234;
        install(&mut scope, dyn_sym);
        assert_eq!(scope.find_overlap(crate::space::AddressSpace::Stack, 0, 8), None);
        // find_symbol delegates to the same probe.
        assert!(scope.find_symbol(0).is_none());
        // has_overlap models the queryProperties invalid-usepoint container
        // probe: dynamic + non-addrtied both filtered.
        assert!(!scope.has_overlap(0, 1));
        install(&mut scope, overlap_sym("staticfar", 0x360, 4, None));
        let hit = scope.find_overlap(crate::space::AddressSpace::Stack, 0x360, 4).unwrap();
        assert_eq!(scope.symbols[hit].name, "staticfar");
    }

    #[test]
    fn test_find_addr_descending_subsort_and_inuse() {
        // F1: exact-start match with the descending multiset walk — among
        // equally-subsorted entries the LAST inserted wins; use-limited
        // entries never answer an invalid usepoint.
        let mut scope = ScopeLocal::new();
        install(&mut scope, overlap_sym("used1", 0x320, 8, Some(0x1000)));
        install(&mut scope, overlap_sym("used2", 0x320, 8, Some(0x1010)));
        install(&mut scope, overlap_sym("tied", 0x320, 8, None));
        let hit = scope
            .find_addr(crate::space::AddressSpace::Stack, 0x320, Some(0x1000))
            .unwrap();
        assert_eq!(scope.symbols[hit].name, "used1");
        // Invalid usepoint: only the address-tied entry is in use.
        let hit = scope.find_addr(crate::space::AddressSpace::Stack, 0x320, None).unwrap();
        assert_eq!(scope.symbols[hit].name, "tied");
        // A usepoint no restricted uselimit admits and no addrtied entry at
        // a different start: null.
        assert_eq!(
            scope.find_addr(crate::space::AddressSpace::Stack, 0x328, Some(0x1000)),
            None
        );
        // Two equal-subsort (both addrtied) exact-start entries: the last
        // inserted wins (reverse multiset insertion order).
        let mut scope = ScopeLocal::new();
        install(&mut scope, overlap_sym("first", 0x400, 4, None));
        install(&mut scope, overlap_sym("second", 0x400, 4, None));
        let hit = scope.find_addr(crate::space::AddressSpace::Stack, 0x400, Some(0x999)).unwrap();
        assert_eq!(scope.symbols[hit].name, "second");
    }

    #[test]
    fn test_multi_entry_symbol_queries_and_removal() {
        // Symbol::mapentry holds several entries (database.hh:189); queries
        // observe ENTRIES, and removeSymbol drops every mapping
        // (database.cc:2117-2136).
        let mut scope = ScopeLocal::new();
        let idx = install(&mut scope, overlap_sym("multi", 0x500, 4, None));
        // A second mapping of the SAME symbol at a disjoint address.
        scope.add_map_entry(
            idx,
            crate::space::AddressSpace::Stack,
            0x600,
            8,
            0,
            crate::varnode::varnode_flags::MAPPED,
            Vec::new(),
        );
        assert_eq!(scope.mapentry_log.len(), 2);
        let hit = scope.find_overlap(crate::space::AddressSpace::Stack, 0x502, 2).unwrap();
        assert_eq!(hit, idx);
        let hit = scope.find_overlap(crate::space::AddressSpace::Stack, 0x605, 2).unwrap();
        assert_eq!(hit, idx);
        // Entry-level view distinguishes the two mappings.
        let entry = scope
            .find_container_entry(crate::space::AddressSpace::Stack, 0x605, 2, None)
            .unwrap();
        assert_eq!((entry.start, entry.size), (0x600, 8));
        // A second symbol installed after survives removal with re-keyed
        // entry references.
        install(&mut scope, overlap_sym("other", 0x700, 4, None));
        scope.remove_symbol(idx);
        assert_eq!(scope.find_overlap(crate::space::AddressSpace::Stack, 0x502, 2), None);
        assert_eq!(scope.find_overlap(crate::space::AddressSpace::Stack, 0x605, 2), None);
        // Both mappings of the removed symbol are gone; the survivor keeps
        // one entry, re-keyed to its new symbol index.
        assert_eq!(scope.mapentry_log.len(), 1);
        assert_eq!(scope.symbols[scope.mapentry_log[0].sym].name, "other");
        let hit = scope.find_overlap(crate::space::AddressSpace::Stack, 0x702, 2).unwrap();
        assert_eq!(scope.symbols[hit].name, "other");
    }

    #[test]
    fn test_find_addr_multi_uselimit_containment() {
        // inUse checks uselimit CONTAINMENT in any range (database.cc:119,
        // RangeList::inRange), not single-address equality; the subsort
        // comes from the FIRST range (database.cc:102-106).
        let mut scope = ScopeLocal::new();
        let idx = install(&mut scope, overlap_sym("spread", 0x320, 8, Some(0x1000)));
        let ram = ghidra_space_index(&crate::space::AddressSpace::Ram);
        // Replace the single-address uselimit with two disjoint ranges.
        scope.mapentry_log[0].uselimit = vec![(ram, 0x1000, 0x100f), (ram, 0x2000, 0x200f)];
        scope.mapentry_log[0].subsort = ScopeLocal::entry_subsort(false, &scope.mapentry_log[0].uselimit);
        let _ = idx;
        // Mid-range usepoint of the FIRST range: admitted.
        assert_eq!(scope.find_addr(crate::space::AddressSpace::Stack, 0x320, Some(0x1005)), Some(idx));
        // Inside the SECOND range: subsort (ram,0x1000) <= sub2 (ram,0x2005)
        // admits the window and inUse passes.
        assert_eq!(scope.find_addr(crate::space::AddressSpace::Stack, 0x320, Some(0x2005)), Some(idx));
        // Between the ranges: window admits, inUse rejects.
        assert_eq!(scope.find_addr(crate::space::AddressSpace::Stack, 0x320, Some(0x1500)), None);
        // Before the first range: the subsort bound itself excludes it.
        assert_eq!(scope.find_addr(crate::space::AddressSpace::Stack, 0x320, Some(0x0ff0)), None);
    }

    #[test]
    fn test_query_properties_flags_branches() {
        use crate::varnode::varnode_flags;
        // Branch 1 (database.cc:1269-1270): answering entry's getAllFlags.
        let mut scope = ScopeLocal::new();
        scope.local_range = vec![(0x0, 0xffff)];
        let locked = install(&mut scope, overlap_sym("locked", 0x100, 4, None));
        scope.symbols[locked].typelock = true;
        let out = scope.query_properties_ex(
            crate::space::AddressSpace::Stack, 0x100, 4, None, None, &|_, _| 0,
        );
        assert!(out.entry.is_some());
        assert_eq!(out.final_scope, QueryFinalScope::This);
        assert_eq!(out.flags, varnode_flags::MAPPED | varnode_flags::ADDRTIED | varnode_flags::TYPELOCK);
        // Branch 2 (database.cc:1271-1277): scope ownership without a
        // symbol — mapped|addrtied|property, no persist for a local scope.
        let out = scope.query_properties_ex(
            crate::space::AddressSpace::Stack, 0x200, 1, None, None,
            &|_, _| varnode_flags::READONLY,
        );
        assert!(out.entry.is_none());
        assert_eq!(out.final_scope, QueryFinalScope::This);
        assert_eq!(out.flags, varnode_flags::MAPPED | varnode_flags::ADDRTIED | varnode_flags::READONLY);
        // Branch 3 (database.cc:1278-1279): no scope — property only.
        let out = scope.query_properties_ex(
            crate::space::AddressSpace::Ram, 0x4000, 1, None, None,
            &|_, _| varnode_flags::READONLY,
        );
        assert_eq!(out.final_scope, QueryFinalScope::None);
        assert_eq!(out.flags, varnode_flags::READONLY);
        // Constant-space short-circuit (database.cc:950).
        let out = scope.query_properties_ex(
            crate::space::AddressSpace::Const, 5, 1, None, None, &|_, _| varnode_flags::READONLY,
        );
        assert_eq!(out.final_scope, QueryFinalScope::None);
        assert_eq!(out.flags, varnode_flags::READONLY);
    }

    #[test]
    fn test_query_properties_parent_branch() {
        use crate::varnode::varnode_flags;
        // stackContainer walks to the parent (database.cc:959): the global
        // scope's symbols carry persist (database.cc:1131-1132) and its
        // scope-only branch sets persist (database.cc:1274-1275).
        let mut local = ScopeLocal::new();
        let mut parent = ScopeLocal::new();
        parent.is_global_scope = true;
        parent.space = crate::space::AddressSpace::Ram;
        parent.local_range = vec![(0x8000, 0x8fff)];
        let mut sym = LocalSymbol::new(
            "gsym", 0x4000, 8, None, symbol_category::NO_CATEGORY);
        sym.space = crate::space::AddressSpace::Ram;
        parent.install_symbol(sym);
        // Parent symbol answers through the local scope's query.
        let out = local.query_properties_ex(
            crate::space::AddressSpace::Ram, 0x4002, 4, None, Some(&parent), &|_, _| 0,
        );
        assert_eq!(out.entry.as_ref().map(|e| e.start), Some(0x4000));
        assert_eq!(out.final_scope, QueryFinalScope::Parent);
        assert_eq!(
            out.flags,
            varnode_flags::MAPPED | varnode_flags::ADDRTIED | varnode_flags::PERSIST
        );
        // Parent scope ownership without a symbol: persist bit set.
        let out = local.query_properties_ex(
            crate::space::AddressSpace::Ram, 0x8100, 1, None, Some(&parent), &|_, _| 0,
        );
        assert!(out.entry.is_none());
        assert_eq!(out.final_scope, QueryFinalScope::Parent);
        assert_eq!(
            out.flags,
            varnode_flags::MAPPED | varnode_flags::ADDRTIED | varnode_flags::PERSIST
        );
    }

    #[test]
    fn test_has_overlap_space_dimension() {
        // maptable[addr.getSpace()->getIndex()] (database.cc:2254): a stack
        // entry never answers a ram probe; the legacy signatureless helper
        // keeps its any-space production contract.
        let mut scope = ScopeLocal::new();
        install(&mut scope, overlap_sym("stk", 0x100, 8, None));
        assert!(!scope.has_overlap_in(crate::space::AddressSpace::Ram, 0x100, 4));
        assert!(scope.has_overlap_in(crate::space::AddressSpace::Stack, 0x100, 4));
        assert!(scope.has_overlap(0x100, 4)); // legacy any-space
        // Partial containment fails (findContainer needs the WHOLE range).
        assert!(!scope.has_overlap_in(crate::space::AddressSpace::Stack, 0xfe, 4));
    }

    #[test]
    fn test_add_map_entry_partial_offset_piece() {
        // addMapInternal's `off` piece offset (database.cc:1843) is observable
        // on the entry returned by the container query.
        let mut scope = ScopeLocal::new();
        let idx = install(&mut scope, overlap_sym("whole", 0x100, 8, None));
        scope.add_map_entry(
            idx,
            crate::space::AddressSpace::Stack,
            0x700,
            4,
            4, // high half of the 8-byte symbol
            crate::varnode::varnode_flags::PRECISHI,
            Vec::new(),
        );
        let entry = scope
            .find_container_entry(crate::space::AddressSpace::Stack, 0x701, 2, None)
            .unwrap();
        assert_eq!((entry.offset, entry.size), (4, 4));
        assert_eq!(entry.extraflags, crate::varnode::varnode_flags::PRECISHI);
    }

    #[test]
    fn test_longest_fit_chains_and_stops() {
        // RangeList::longestFit (address.cc:512-537): chain consecutive
        // ranges containing the offset, stop at a gap or past maxsize.
        let mut scope = ScopeLocal::new();
        scope.local_range = vec![(0x100, 0x1ff), (0x300, 0x3ff), (0x500, 0x5ff)];
        assert_eq!(scope.longest_fit(0x180, 0x1000), 0x80); // to end of first range
        assert_eq!(scope.longest_fit(0x100, 0x1000), 0x100);
        assert_eq!(scope.longest_fit(0x2a0, 0x1000), 0); // in a gap
        assert_eq!(scope.longest_fit(0x500, 0x10), 0x100); // early break, return NOT capped (address.cc:533)
        assert_eq!(scope.longest_fit(0x600, 0x10), 0); // past every range
    }

    #[test]
    fn test_local_range_remove_range_splits() {
        // RangeList::removeRange (address.cc:417-448): a bridging range
        // splits around the removed span; disjoint neighbors are trimmed.
        let mut scope = ScopeLocal::new();
        scope.local_range = vec![(0x100, 0x2ff), (0x400, 0x4ff)];
        scope.local_range_remove_range(0x180, 0x401);
        assert_eq!(scope.local_range, vec![(0x100, 0x17f), (0x402, 0x4ff)]);
        // Removing past the end clamps (markNotMapped varmap.cc:516-519
        // wraps `last` to the space highest first).
        scope.local_range_remove_range(0x4f0, u64::MAX);
        assert_eq!(scope.local_range, vec![(0x100, 0x17f), (0x402, 0x4ef)]);
    }

    #[test]
    fn test_mark_not_mapped_guards_and_warning_channel() {
        // F1+F3 (varmap.cc:510-546): the removal loop re-issues findOverlap
        // after every removal; a typelocked symbol aborts with the exact
        // warningHeader text — silenced for the shared-return special case —
        // and a fake_input symbol aborts silently.
        let mut scope = ScopeLocal::new();
        let mut p = overlap_sym("p", 0x40, 8, None);
        p.typelock = true;
        p.category = symbol_category::FUNCTION_PARAMETER;
        let mut f = overlap_sym("f", 0x60, 8, None);
        f.category = symbol_category::FAKE_INPUT;
        install(&mut scope, p);
        install(&mut scope, f);
        install(&mut scope, overlap_sym("u", 0x70, 4, None));
        install(&mut scope, overlap_sym("v", 0x80, 4, None));
        scope.local_range = vec![(0, 0xfffff)];

        // parameter=true on a function_parameter typelocked symbol: the
        // shared-return special case keeps the warning silent, everything
        // survives (varmap.cc:531-537).
        scope.mark_not_mapped(0x38, 0x50, true);
        assert_eq!(scope.symbols.len(), 4);
        assert!(scope.pending_warnings.is_empty());

        // parameter=false: the exact warningHeader text fires (F3), the
        // walk aborts before removing anything.
        scope.mark_not_mapped(0x38, 0x50, false);
        assert_eq!(
            scope.pending_warnings,
            vec!["Variable defined which should be unmapped: p".to_string()]
        );
        assert_eq!(scope.symbols.len(), 4);

        // fake_input early return (varmap.cc:539-541): the later symbol u
        // survives even though the range covers it.
        scope.pending_warnings.clear();
        scope.mark_not_mapped(0x60, 0x14, true);
        assert!(scope.pending_warnings.is_empty());
        assert_eq!(scope.symbols.len(), 4);

        // Plain symbols only: the loop removes every overlapping entry and
        // the window loses the range (varmap.cc:542-545).
        scope.mark_not_mapped(0x70, 0x14, false);
        assert_eq!(scope.symbols.len(), 2); // p and f survive, u and v removed
        assert_eq!(scope.local_range, vec![(0, 0x6f), (0x84, 0xfffff)]);
        // The parameter=true call extended the min/max window
        // (varmap.cc:520-524); parameter=false calls leave it untouched.
        assert_eq!(scope.min_param_offset, 0x38);
        assert_eq!(scope.max_param_offset, 0x87);
    }

    #[test]
    fn test_merge_with_typelock_throw_text_and_discard_guard() {
        // F3 (varmap.cc:277-284): both typelocked and unreconcilable throws
        // LowlevelError with the verbatim text (colon-space, three spaces).
        let types = crate::type_system::typefactory::TypeFactory::shared_default();
        let mut a = RangeHint::new(
            0, 4, 0, Some(named_dt("int4", 4, TypeMetatype::Int)),
            range_flags::TYPE_LOCK, RangeType::Fixed, -1,
        );
        let b = RangeHint::new(
            2, 8, 2, Some(named_dt("uint8", 8, TypeMetatype::Uint)),
            range_flags::TYPE_LOCK, RangeType::Fixed, -1,
        );
        let err = a.merge_with(&b, &types).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Overlapping forced variable types : int4   uint8"
        );
        // The discard-b guard hangs off isTypeLock() alone (varmap.cc:278,
        // 281-282): a typelocked self with an UNLOCKED b and differing
        // starts discards b — Ok(false), no error.
        let mut a2 = RangeHint::new(
            0, 4, 0, Some(int_dt(4, TypeMetatype::Int)),
            range_flags::TYPE_LOCK, RangeType::Fixed, -1,
        );
        let b2 = RangeHint::new(
            2, 8, 2, Some(int_dt(8, TypeMetatype::Int)),
            0, RangeType::Fixed, -1,
        );
        assert!(!a2.merge_with(&b2, &types).unwrap());
        // Same starts: the guard falls through to the resType handling.
        let b3 = RangeHint::new(
            0, 8, 0, Some(int_dt(8, TypeMetatype::Int)),
            0, RangeType::Fixed, -1,
        );
        let mut a3 = RangeHint::new(
            0, 4, 0, Some(int_dt(4, TypeMetatype::Int)),
            range_flags::TYPE_LOCK, RangeType::Fixed, -1,
        );
        assert!(!a3.merge_with(&b3, &types).unwrap());
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
