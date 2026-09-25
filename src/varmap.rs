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
                    sub = n;
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
    /// The extreme offset of the locals region (varmap.cc `localExtreme`):
    /// `~0` for negative-growing stacks, `localBoundary` for positive growth.
    local_extreme: u64,
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
    // Ghidra: varmap.hh:137 AliasChecker::AliasChecker
    pub fn new(direction: i32) -> Self {
        Self {
            aliases: Vec::new(),
            add_base: Vec::new(),
            local_boundary: 0x1000000,
            local_extreme: u64::MAX,
            alias_boundary: u64::MAX,
            direction,
            calculated: false,
        }
    }

    // Ghidra: varmap.cc:633 AliasChecker::deriveBoundaries
    /// Set up basic offset boundaries for what constitutes a local variable
    /// or a parameter on the stack, informed by the ProtoModel when available.
    /// Faithful to `AliasChecker::deriveBoundaries` (varmap.cc:633-655):
    /// defaults `localExtreme = ~0; localBoundary = 0x1000000` (with
    /// `localExtreme = localBoundary` when the stack grows positively),
    /// then, **if the prototype has a model** (`proto.hasModel()`), reads the
    /// model's local/param windows and sets `localBoundary =
    /// paramrange.getLastRange()->getLast()` — for the default
    /// negative-growth model that is **511** (`defaultParamRange`
    /// `[0,511]`, fspec.cc:2298-2307) — and, for positive growth,
    /// `localBoundary = paramrange.getFirstRange()->getFirst()` with
    /// `localExtreme = localBoundary`. Ranges arrive as sorted inclusive
    /// `(first,last)` pairs; `getFirstRange`/`getLastRange` are the set's
    /// first/last elements (address.hh Range ordering by (space,first)).
    pub fn derive_boundaries(
        &mut self,
        localrange: &[(u64, u64)],
        paramrange: &[(u64, u64)],
        has_model: bool,
    ) {
        // localExtreme = ~((uintb)0); localBoundary = 0x1000000;
        // if (direction == -1) localExtreme = localBoundary; (varmap.cc:636-639)
        self.local_extreme = u64::MAX;
        self.local_boundary = 0x1000000;
        if self.direction == -1 {
            self.local_extreme = self.local_boundary;
        }
        // if (proto.hasModel()) { const Range *local = localrange.getFirstRange();
        // const Range *param = paramrange.getLastRange();
        // if ((local != 0)&&(param != 0)) { ... } } (varmap.cc:641-653)
        if has_model {
            let local = localrange.first();
            let param = paramrange.last();
            if let (Some(_local), Some(param)) = (local, param) {
                self.local_boundary = param.1; // param->getLast()
                if self.direction == -1 {
                    // localBoundary = paramrange.getFirstRange()->getFirst();
                    // localExtreme = localBoundary; (varmap.cc:650-651)
                    self.local_boundary = paramrange.first().map(|r| r.0).unwrap_or(0);
                    self.local_extreme = self.local_boundary;
                }
            }
        }
    }

    // Ghidra: varmap.cc:692 AliasChecker::gather
    /// Entry point for a function+space alias analysis. Faithful to
    /// `AliasChecker::gather` (varmap.cc:692-704): reset state, set
    /// `direction = space->stackGrowsNegative() ? 1 : -1`, run
    /// `deriveBoundaries(fd->getFuncProto())`, and — unless `defer` — run
    /// `gatherInternal` immediately (a deferred checker calculates on the
    /// first `hasLocalAlias`). Rugra's `AddressSpace` enum carries no
    /// per-space growth flag; the scope's prototype-derived
    /// `stack_grows_negative` is passed in its place (identical value for
    /// every reachable cspec: the stack space's growth bit and the model's
    /// `stackgrowsnegative` are configured together).
    pub fn gather(&mut self, fd: &crate::funcdata::Funcdata, stack_grows_negative: bool, defer: bool) {
        // fd = f; space = spc; calculated = false;
        // addBase.clear(); alias.clear(); (varmap.cc:695-699)
        self.calculated = false;
        self.add_base.clear();
        self.aliases.clear();
        // direction = space->stackGrowsNegative() ? 1 : -1; (varmap.cc:700)
        self.direction = if stack_grows_negative { 1 } else { -1 };
        // deriveBoundaries(fd->getFuncProto()); (varmap.cc:701) — the
        // prototype's own local/param windows (fspec.hh:1539/1540), with the
        // same model precedence as the `func_proto_*` bridges.
        let localrange = func_proto_local_range(fd)
            .ranges()
            .iter()
            .map(|r| (r.get_first().as_u64(), r.get_last().as_u64()))
            .collect::<Vec<_>>();
        let paramrange = func_proto_param_range(fd)
            .ranges()
            .iter()
            .map(|r| (r.get_first().as_u64(), r.get_last().as_u64()))
            .collect::<Vec<_>>();
        self.derive_boundaries(&localrange, &paramrange, func_proto_has_model(fd));
        if !defer {
            self.gather_internal(fd);
        }
    }

    // RUGRA-GLUE: boundary observation accessor for the locked oracle fixture
    /// `(localBoundary, localExtreme, aliasBoundary)` — the Ghidra fixture
    /// reads these members directly through `#define private public`; the
    /// Rust fixture gets the same read-only view here.
    pub fn boundaries(&self) -> (u64, u64, u64) {
        (self.local_boundary, self.local_extreme, self.alias_boundary)
    }

    // Ghidra: varmap.cc:660 AliasChecker::gatherInternal
    /// If there is a stack (spacebase) pointer, find its input Varnode, and look
    /// for additive uses of it. Then calculate the offsets that start an aliased
    /// region. Faithful to `AliasChecker::gatherInternal` (varmap.cc:660):
    /// `aliasBoundary = localExtreme` (NOT a constant — deriveBoundaries
    /// sets it to `localBoundary` for positive-growth stacks); the lists are
    /// cleared by `gather` (varmap.cc:698-699), not here.
    pub fn gather_internal(&mut self, fd: &crate::funcdata::Funcdata) {
        self.calculated = true;
        self.alias_boundary = self.local_extreme;

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
        // NOTE: no sort here — Ghidra's gatherInternal (varmap.cc:660-684)
        // leaves `alias` in gather order; `sortAlias` (varmap.cc:726) runs
        // separately from ScopeLocal::restructureVarnode (varmap.cc:1279).
    }

    // Ghidra: varmap.cc:726 AliasChecker::sortAlias
    /// Sort the alias offsets ascending. Faithful to
    /// `AliasChecker::sortAlias` (varmap.cc:726-729), called from
    /// `ScopeLocal::restructureVarnode` (varmap.cc:1279) before
    /// markUnaliased/checkUnaliasedReturn consume the list
    /// (checkUnaliasedReturn's lower_bound requires the sort).
    pub fn sort_aliases(&mut self) {
        self.aliases.sort();
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

// RUGRA-GLUE: no single Ghidra counterpart. Rugra's x86 lift keeps stack
// accesses as RSP-derived address expressions instead of Ghidra's stack-space
// varnodes (see gather_spacebase below), so this backward-walking resolver
// substitutes for that visibility. Its per-opcode semantics mirror the two
// oracle kin it must stay consistent with:
//   - AliasChecker::gatherAdditiveBase (varmap.cc:741) walks forward from the
//     spacebase through COPY/INT_ADD/INT_SUB/PTRADD/PTRSUB/SEGMENTOP
//     (PTRSUB arm cc:791, PTRADD arm cc:783-789);
//   - AliasChecker::gatherOffset (varmap.cc:817) computes constant offsets:
//     PTRSUB like INT_ADD (cc:830-834), PTRADD const-index*stride with the
//     non-constant index followed only when stride==1 (cc:839-849).
// Unlike gatherOffset's lenient partial sums, this resolver is strict (it
// returns None unless the whole chain resolves to a constant offset): its
// caller synthesizes *fixed* RangeHints, which in the oracle come from
// constant-address varnodes only (MapState::gatherVarnodes varmap.cc:1124);
// variable-index (open) references enter through gather_open instead.
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
        // Ghidra's AliasChecker::gatherOffset (varmap.cc:830-834) treats
        // PTRSUB exactly like INT_ADD: base offset + the constant byte
        // offset. Without this arm, every PTRSUB-addressed stack access
        // (the form Rugra's rules produce for `lea`-shaped loads/stores)
        // was invisible to the gather_spacebase hint synthesis.
        OpCode::CPUI_PTRSUB => {
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
                (Some((bo, w)), Some(tc)) => Some((bo.wrapping_add(tc), w)),
                _ => None,
            }
        }
        // gatherOffset's PTRADD arm (varmap.cc:839-849): a constant index
        // contributes `index * stride` bytes; a non-constant index is only
        // followed when the stride is 1 (a plain ADD in disguise — "we only
        // follow getIn(1) if the PTRADD multiply is by 1"). Any other shape
        // (variable index with stride != 1) cannot be resolved to a fixed
        // stack offset.
        OpCode::CPUI_PTRADD => {
            let in0 = op.inrefs.first()?;
            let in1 = op.inrefs.get(1)?;
            let stride = op
                .inrefs
                .get(2)
                .map(|v| v.read().unwrap().get_offset())
                .unwrap_or(1);
            let base_off = resolve_rsp_offset_signed(in0);
            let term: Option<i64> = {
                let i1 = in1.read().unwrap();
                if i1.is_constant() {
                    Some((i1.get_offset() as i64).wrapping_mul(stride as i64))
                } else if stride == 1 {
                    drop(i1);
                    resolve_rsp_offset_signed(in1).map(|(o, _)| o)
                } else {
                    None
                }
            };
            drop(op);
            match (base_off, term) {
                (Some((bo, w)), Some(tc)) => Some((bo.wrapping_add(tc), w)),
                _ => None,
            }
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

// Ghidra: fspec.hh:1539 FuncProto::getLocalRange
/// Resolve the local-variable stack window of a Funcdata's prototype the
/// way `fd->getFuncProto().getLocalRange()` (fspec.hh:1539) does — the same
/// precedence as `func_proto_param_range` above (the attached model, else
/// `s->getArch()->defaultfp` via `FuncProto::setScope`, fspec.cc:3879-3885,
/// else the model Ghidra's default constructor builds:
/// `ProtoModel::defaultLocalRange` (fspec.cc:2263-2290), which for a
/// negative-growing 8-byte stack is `[u64::MAX-999999, u64::MAX]` — the
/// sign-extended negative-offset half where heritage puts locals).
fn func_proto_local_range(
    fd: &crate::funcdata::Funcdata,
) -> crate::address::RangeList {
    if let Some(arch) = &fd.arch {
        let name = fd.get_func_proto().get_model_name();
        if let Some(model) = arch.proto_models.get(name) {
            return model.localrange.clone();
        }
        if let Some(model) = &arch.defaultfp {
            return model.localrange.clone();
        }
    }
    crate::fspec::ProtoModelFull::new(Some(crate::space::AddressSpace::Stack), 8).localrange
}

// Ghidra: fspec.hh:1541 FuncProto::isStackGrowsNegative
/// Whether the prototype's stack grows toward smaller addresses, read with
/// the same model precedence as `func_proto_param_range`/
/// `func_proto_local_range`. `ScopeLocal::resetLocalWindow`'s first statement
/// (varmap.cc:435) assigns this into the scope's `stackGrowsNegative`, which
/// `buildVariableName` (varmap.cc:558) consumes; the no-Architecture
/// fallback is the `ProtoModel` default constructor's `stackgrowsnegative =
/// true` (fspec.cc:2349).
fn func_proto_stack_grows_negative(fd: &crate::funcdata::Funcdata) -> bool {
    if let Some(arch) = &fd.arch {
        let name = fd.get_func_proto().get_model_name();
        if let Some(model) = arch.proto_models.get(name) {
            return model.stackgrowsnegative;
        }
        if let Some(model) = &arch.defaultfp {
            return model.stackgrowsnegative;
        }
    }
    true
}

// Ghidra: fspec.hh:1389 FuncProto::hasModel
/// Whether the prototype has a ProtoModel attached
/// (`FuncProto::hasModel`, fspec.hh:1389 `model != 0`), resolved with the
/// same precedence as `func_proto_param_range`/`func_proto_local_range`
/// (the registry model for the prototype's convention name, else the
/// Architecture default). With no Architecture attached there is no model —
/// `AliasChecker::deriveBoundaries` then keeps the `0x1000000` default
/// boundary (varmap.cc:637), exactly as Ghidra does for a model-less
/// prototype.
fn func_proto_has_model(fd: &crate::funcdata::Funcdata) -> bool {
    if let Some(arch) = &fd.arch {
        let name = fd.get_func_proto().get_model_name();
        if arch.proto_models.get(name).is_some() {
            return true;
        }
        if arch.defaultfp.is_some() {
            return true;
        }
    }
    false
}

// RUGRA-GLUE: window_in_range (RangeList::inRange over the Vec window model)
/// `RangeList::inRange(addr, size)` (address.cc:468-487) over a sorted,
/// inclusive `Vec<(first, last)>` window: empty → false; the last range with
/// `first <= offset` must be in the same space (the Vec carries no space —
/// every window range here is a stack range, subsuming Ghidra's space test,
/// cf. `param_range_in_range`) and must reach `offset + size - 1`
/// (uintb-wrapping, address.cc:486). Ghidra's `addr.isInvalid()` early
/// `return true` has no caller here: every queried hint has a real address.
fn window_in_range(ranges: &[(u64, u64)], offset: u64, size: u64) -> bool {
    if ranges.is_empty() {
        return false;
    }
    // iter = tree.upper_bound(Range(spc,offset,offset)); if (iter ==
    // tree.begin()) return false; --iter; — the last range with first <= offset.
    let pos = ranges.partition_point(|&(first, _)| first <= offset);
    if pos == 0 {
        return false;
    }
    let (_, last) = ranges[pos - 1];
    last >= offset.wrapping_add(size).wrapping_sub(1)
}

// RUGRA-GLUE: get_last_signed_range (RangeList::getLastSignedRange over the Vec model)
/// `RangeList::getLastSignedRange` (address.cc:562-583) over a sorted
/// inclusive `Vec<(first, last)>`: treating high-bit-set offsets as coming
/// *before* clear-high-bit offsets, return the last/latest contiguous range.
/// Ghidra probes `upper_bound(Range(spaceid, midway, midway))` with
/// `midway = getHighest()/2`; `Range::operator<` compares **only
/// (spaceIndex, first)** — `last` is never part of the key (address.hh:202-205)
/// — so upper_bound returns the first range with `first > midway` and `--iter`
/// lands on the LAST range with `first <= midway`, including one whose
/// `first == midway` with an arbitrary `last` (it is equivalent to the
/// (midway,midway) probe key under the first-only ordering). If no such
/// "positive" range exists, the second probe `upper_bound((highest,highest))`
/// lands on `end()` and `--iter` yields the final range in unsigned order —
/// the biggest negative range. (The Vec carries no space — every window range
/// is a stack range, cf. `param_range_in_range`; a future cspec declaring
/// non-stack `<localrange>` ranges must add a space tag or filter at the
/// bridge.)
fn get_last_signed_range(ranges: &[(u64, u64)]) -> Option<(u64, u64)> {
    if ranges.is_empty() {
        return None;
    }
    let midway = u64::MAX / 2; // spaceid->getHighest() / 2 for the stack space
    // First index with first > midway — the first-only ordering key of
    // address.hh:202-205 (same predicate shape as `window_in_range`).
    let pos = ranges.partition_point(|&(first, _)| first <= midway);
    if pos > 0 {
        return Some(ranges[pos - 1]);
    }
    // No positive ranges: return the biggest negative range.
    ranges.last().copied()
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
    /// Analysis window: Ghidra's `range` member (varmap.hh:179), the
    /// `RangeList rn` the constructor copies from the scope's range tree
    /// minus every param range (varmap.cc:864-875). Modeled as a sorted,
    /// inclusive `Vec<(first, last)>`; all ranges are stack ranges (the Vec
    /// carries no space, cf. `param_range_in_range`).
    range: Vec<(u64, u64)>,
    /// Alias analysis for the space (varmap.hh MapState member
    /// `AliasChecker checker`): `gatherOpen` (varmap.cc:1214) runs
    /// `checker.gather(&fd,spaceid,false)` on it and `restructureVarnode`
    /// (varmap.cc:1279-1284) consumes `sortAlias`/`getAlias` afterwards.
    pub(crate) checker: AliasChecker,
    /// Whether the stack grows toward smaller addresses — Ghidra derives
    /// gatherOpen's `checker.gather` direction from the space member
    /// (`spaceid->stackGrowsNegative()`, varmap.cc:700); Rugra's
    /// `AddressSpace` enum carries no per-space flag, so the scope's
    /// prototype-derived value is installed at construction.
    stack_grows_negative: bool,
}

impl MapState {
    // Ghidra: varmap.cc:864 MapState::MapState
    /// Construct with the analysis window `rn` (inclusive `(first,last)`
    /// ranges, sorted). Faithful to the constructor head (varmap.cc:864-867,
    /// `MapState(spc,rn,pm,dt) : range(rn)`); the param-range subtraction of
    /// varmap.cc:870-875 is performed by the caller (`ScopeLocal::
    /// restructure_varnode`) so the window can double as the scope's range
    /// tree before subtraction.
    pub fn new(range: Vec<(u64, u64)>) -> Self {
        Self {
            maplist: Vec::new(),
            iter_pos: 0,
            default_type: None,
            range,
            checker: AliasChecker::new(1),
            stack_grows_negative: true,
        }
    }

    // Ghidra: varmap.cc:864 MapState::MapState
    /// Construct with a default type used when a gathered varnode has no
    /// type (Ghidra threads `glb->types->getBase(1,TYPE_UNKNOWN)` here,
    /// varmap.cc:1261).
    pub fn new_with_default(range: Vec<(u64, u64)>,
                            default_type: Arc<Datatype>) -> Self {
        Self {
            maplist: Vec::new(),
            iter_pos: 0,
            default_type: Some(default_type),
            range,
            checker: AliasChecker::new(1),
            stack_grows_negative: true,
        }
    }

    // RUGRA-GLUE: direction install for the checker (Ghidra reads the space
    // member's growth flag; the Rust MapState stores the scope's value).
    /// Set the stack-growth direction the embedded checker uses when
    /// `gather_open` runs `checker.gather` (varmap.cc:1214/700).
    pub fn set_stack_grows_negative(&mut self, grows_negative: bool) {
        self.stack_grows_negative = grows_negative;
    }

    // RUGRA-GLUE: analysis window accessor (Ghidra reads the `range` member
    // directly at varmap.cc:902/1067; Rust keeps it private with a read-only
    // probe for the oracle fixture's observation surface).
    /// The analysis window (scope range tree minus param ranges), sorted
    /// inclusive `(first, last)` pairs.
    pub fn analysis_range(&self) -> &[(u64, u64)] {
        &self.range
    }

    // RUGRA-GLUE: hints accessor (Ghidra walks `maplist` directly through
    // the MapState iterators at varmap.cc:1080/1299; the Rust fixture needs
    // the same read-only view after initialize's sort).
    /// The collected RangeHints in current (post-initialize: sorted)
    /// order.
    pub fn hints(&self) -> &[RangeHint] {
        &self.maplist
    }

    // Ghidra: varmap.cc:896 MapState::addRange
    /// Add a range hint. Faithful to `MapState::addRange` (varmap.cc:896):
    /// a null/zero-size type is SUBSTITUTED with the default type and the
    /// flow continues (varmap.cc:899-900 — never dropped), then the
    /// FULL extent `[st, st+sz-1]` must fit inside one range of the
    /// analysis window (`range.inRange(Address(spaceid,st),sz)`,
    /// varmap.cc:902 — address.cc:468-487) or the hint is dropped;
    /// `sst` is `byteToAddress`+`sign_extend`+`addressToByte`
    /// (varmap.cc:904-906), the identity for the 1-word-size 8-byte stack,
    /// where a sign-extended negative offset (`0xfffffff...`) keeps its
    /// negative `i64` value for `RangeHint::compare`'s signed ordering.
    /// `high_ind` is the biggest guaranteed index for open-range hints
    /// (-1 if not an array reference).
    pub fn add_range(&mut self, start: u64, dtype: Option<Arc<Datatype>>, flags: u32,
                     rt: RangeType, high_ind: i32) {
        // varmap.cc:899-900: (ct == (Datatype *)0) || (ct->getSize() == 0)
        // → ct = defaultType — a zero-size Some is SUBSTITUTED with the
        // default type and the flow CONTINUES; it is never dropped. The
        // default-less `MapState::new` constructor (test-only; the oracle
        // always threads getBase(1,TYPE_UNKNOWN) here, varmap.cc:1261)
        // cannot substitute and keeps the historical anonymous size-1
        // fallback of the map_or below.
        let dtype = match dtype {
            Some(d) if d.get_size() != 0 => Some(d),
            _ => self.default_type.clone(),
        };
        // varmap.cc:901: int4 sz = ct->getSize();
        let size = dtype.as_ref().map_or(1, |d| d.get_size() as i32);
        // if (!range.inRange(Address(spaceid,st),sz)) return; (varmap.cc:902)
        if !window_in_range(&self.range, start, size as u64) { return; }
        // intb sst = byteToAddress(st, wordSize); sst = sign_extend(sst,
        // addrSize*8-1); sst = addressToByte(sst, wordSize); — identity for
        // wordSize == 1 and the 64-bit sign-extension of the u64 cast.
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
    /// `MapState::gatherOpen` (varmap.cc:1211-1249): run
    /// `checker.gather(&fd,spaceid,false)` (the alias analysis whose
    /// deriveBoundaries sets the local/param boundary), then for each
    /// additive base root, if its type is a pointer, descend through ALL
    /// array layers of the pointee (varmap.cc:1224-1227 — a single-level
    /// descend stops too early for `int (*)[4][8]`-shaped pointers) and
    /// create an open RangeHint; use minItems=3 if an index varnode is
    /// present, -1 otherwise. Finally every LoadGuard/StoreGuard of the
    /// function is converted through `add_guard` (varmap.cc:1241-1248).
    pub fn gather_open(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        types: &Arc<RwLock<crate::type_system::typefactory::TypeFactory>>,
    ) {
        // checker.gather(&fd,spaceid,false); (varmap.cc:1214)
        self.checker.gather(fd, self.stack_grows_negative, false);

        let addbase = self.checker.add_base.clone();
        let aliases = self.checker.aliases.clone();
        for (i, entry) in addbase.iter().enumerate() {
            let offset = aliases.get(i).copied().unwrap_or(0);
            let ct: Option<Arc<Datatype>> = {
                let base_vn = entry.base.read().unwrap();
                base_vn.v_type.clone()
            };
            // if (ct->getMetatype() == TYPE_PTR) { ct = ptr_to;
            // while (ct->getMetatype() == TYPE_ARRAY) ct = base; }
            // else ct = NULL; (varmap.cc:1224-1230)
            let mut pointee = ct.and_then(|t| match t.as_ref() {
                Datatype::Pointer(p) => Some(p.ptr_to.clone()),
                _ => None,
            });
            while let Some(p) = pointee.clone() {
                match p.as_ref() {
                    Datatype::Array(a) => pointee = Some(a.array_of.clone()),
                    _ => break,
                }
            }
            // Ghidra passes ct = NULL for non-pointers ("Do unknown array",
            // varmap.cc:1230); MapState::addRange substitutes the default
            // type (the factory's getBase(1,TYPE_UNKNOWN), varmap.cc:896).
            let min_items: i32 = if entry.index.is_some() { 3 } else { -1 };
            self.add_range(offset, pointee, 0, RangeType::Open, min_items);
        }

        // const list<LoadGuard> &loadGuard( fd.getLoadGuards() );
        // for(giter=loadGuard.begin();giter!=loadGuard.end();++giter)
        //   addGuard(*giter,CPUI_LOAD,typeFactory); (varmap.cc:1241-1244)
        for guard in &fd.heritage.load_guard {
            self.add_guard(guard, OpCode::CPUI_LOAD, types);
        }
        // const list<LoadGuard> &storeGuard( fd.getStoreGuards() );
        // ... addGuard(*siter,CPUI_STORE,typeFactory); (varmap.cc:1246-1248)
        for guard in &fd.heritage.store_guard {
            self.add_guard(guard, OpCode::CPUI_STORE, types);
        }
    }

    // Ghidra: varmap.cc:1003 MapState::addGuard
    /// Convert a LoadGuard (LOAD or STORE) into an open RangeHint, making
    /// use of any data-type or index information. Faithful to
    /// `MapState::addGuard` (varmap.cc:1003-1039): the guard must still
    /// describe a live op of the expected opcode (`isValid`,
    /// heritage.hh:169 `!op->isDead() && op->code() == opc`) with a nonzero
    /// step; the pointer type of the address input is descended through
    /// array layers; the access size must match the step or evenly divide it
    /// (pretending an array of the LOAD size); a mismatched alignment
    /// re-types to `getBase(step,TYPE_UNKNOWN)` unless step exceeds 8;
    /// a range-locked guard (`analysisState == 2`, heritage.hh:168) yields
    /// `minItems = (max-min+1)/step - 1`, otherwise the conservative 3.
    pub fn add_guard(
        &mut self,
        guard: &crate::heritage::LoadGuard,
        opc: OpCode,
        types: &Arc<RwLock<crate::type_system::typefactory::TypeFactory>>,
    ) {
        // if (!guard.isValid(opc)) return; (varmap.cc:1006)
        let Some(op_arc) = guard.get_op() else { return; };
        let op_alive_and_code = {
            let op = op_arc.read().unwrap();
            (!op.is_dead(), op.opcode)
        };
        if !op_alive_and_code.0 || op_alive_and_code.1 != opc {
            return;
        }
        // int4 step = guard.getStep(); if (step == 0) return;
        // (varmap.cc:1007-1008)
        if guard.step == 0 {
            return; // No definitive sign of array access
        }
        // Datatype *ct = guard.getOp()->getIn(1)->getTypeReadFacing(op)
        // (varmap.cc:1009) — the ADDRESS input (LOAD/STORE input slot 1).
        // getTypeReadFacing(op) resolves union pointers via
        // TypePointer::findResolve (type.cc:1192-1202), so the op form is
        // required; getIn(1) is read at slot 1 (op->getSlot(this) == 1).
        // Ghidra's Varnode ALWAYS carries a data-type — every construction
        // path installs the factory's getBase(s,TYPE_UNKNOWN)
        // (funcdata_varnode.cc:107 newVarnodeOut, :132 newUniqueOut,
        // :153-154 newVarnode) and getTypeReadFacing returns `type`
        // verbatim for non-unions (varnode.cc:639-645) — so the oracle's
        // addGuard never sees a null ct (varmap.cc:1009-1038 has no
        // null-ct early return). Rust models the untyped varnode as
        // v_type=None: stand in the factory's unknown base of the address
        // varnode's SIZE, the exact value getIn(1)->getTypeReadFacing
        // returns in the oracle, instead of dropping the guard hint.
        let mut ct: Option<Arc<Datatype>> = {
            let op = op_arc.read().unwrap();
            let Some(in1) = op.inrefs.get(1) else { return; };
            let vn = in1.read().unwrap();
            vn.get_type_read_facing_op(&op, 1)
                .or_else(|| Some(make_int_type(types, vn.get_size())))
        };
        // if (ct->getMetatype() == TYPE_PTR) { ct = ptrTo;
        // while (ct->getMetatype() == TYPE_ARRAY) ct = base; } (cc:1010-1014)
        if let Some(t) = ct.clone() {
            if let Datatype::Pointer(p) = t.as_ref() {
                let mut base = p.ptr_to.clone();
                while let Datatype::Array(a) = base.as_ref() {
                    base = a.array_of.clone();
                }
                ct = Some(base);
            }
        }
        let Some(ct) = ct else { return };
        // int4 outSize; if (opc == CPUI_STORE) outSize = getIn(2)->getSize();
        // else outSize = getOut()->getSize(); (varmap.cc:1015-1019)
        let out_size: usize = {
            let op = op_arc.read().unwrap();
            if opc == OpCode::CPUI_STORE {
                let Some(val) = op.inrefs.get(2) else { return; };
                val.read().unwrap().get_size()
            } else {
                let Some(out) = op.output.clone() else { return; };
                let out_size = out.read().unwrap().get_size();
                out_size
            }
        };
        // if (outSize != step) { if (outSize > step || (step % outSize)!=0)
        // return; step = outSize; } (varmap.cc:1020-1027)
        let mut step = guard.step as u64;
        if out_size as u64 != step {
            if out_size as u64 > step || (step % out_size as u64) != 0 {
                return; // field in array of structures or something unusual
            }
            // Since the LOAD size divides the step and we want to preserve
            // the arrayness we pretend we have an array of LOAD's size.
            step = out_size as u64;
        }
        // if (ct->getAlignSize() != step) { if (step > 8) return;
        // ct = typeFactory->getBase(step,TYPE_UNKNOWN); } (varmap.cc:1028-1032)
        let mut ct = ct;
        if ct.get_align_size() as u64 != step {
            if step > 8 {
                return; // Don't manufacture primitives bigger than 8-bytes
            }
            ct = make_int_type(types, step as usize);
        }
        // if (guard.isRangeLocked()) { int4 minItems = ((max - min)+1)/step;
        //   addRange(min,ct,0,open,minItems-1); }
        // else addRange(min,ct,0,open,3); (varmap.cc:1033-1038)
        let min_items: i32 = if guard.analysis_state == 2 {
            // isRangeLocked (heritage.hh:168): analysisState == 2
            let span = guard
                .get_maximum()
                .wrapping_sub(guard.get_minimum())
                .wrapping_add(1);
            (span / step) as i32 - 1
        } else {
            3
        };
        self.add_range(guard.get_minimum(), Some(ct), 0, RangeType::Open, min_items);
    }

    // Ghidra: varmap.cc:1044 MapState::gatherSymbols
    /// Run through all Symbols in the scope's maptable (the space's EntryMap)
    /// and create a corresponding fixed RangeHint for each Symbol entry.
    /// Faithful to `MapState::gatherSymbols` (varmap.cc:1044-1059): each
    /// entry's START offset (the SymbolEntry address, not the symbol), the
    /// symbol's type, and `RangeHint::typelock` when the symbol is
    /// type-locked feed `addRange(start,ct,flags,fixed,-1)` — this re-feeds
    /// locked symbols so restructure keeps their boundaries stable across
    /// passes (varmap.cc:1269).
    pub fn gather_symbols(&mut self, scope: &ScopeLocal) {
        // list<SymbolEntry> iterate over rangemap = maptable[space->getIndex()]
        // in list (insertion-refined) order (varmap.cc:1047-1050).
        let rangemap = scope.materialize_maptable(scope.space);
        for entry in rangemap.records() {
            // sym = (*riter).getSymbol(); if (sym == 0) continue;
            let Some(sym) = scope.symbols.get(entry.sym) else { continue };
            // uintb start = (*riter).getAddr().getOffset(); (varmap.cc:1054)
            let start = entry.start;
            let ct = sym.dtype.clone();
            // uint4 flags = sym->isTypeLocked() ? RangeHint::typelock : 0;
            let flags = if sym.typelock { range_flags::TYPE_LOCK } else { 0 };
            self.add_range(start, ct, flags, RangeType::Fixed, -1);
        }
    }

    // Ghidra: varmap.cc MapState::sortAlias (checker.sortAlias at
    // varmap.cc:1279) / MapState::getAlias (varmap.cc:1281-1284)
    /// Sort the embedded alias-checker's offsets (restructureVarnode,
    /// varmap.cc:1279) and expose the list the way `state.getAlias()` does.
    pub fn sort_alias(&mut self) {
        self.checker.sort_aliases();
    }

    // Ghidra: varmap.cc:1281 MapState::getAlias
    /// The (sorted, after `sort_alias`) alias offsets of the embedded checker.
    pub fn get_alias(&self) -> &[u64] {
        &self.checker.aliases
    }

    // Ghidra: varmap.cc:1063 MapState::initialize
    /// Sort the collection and add a special terminating RangeHint.
    /// Faithful to `MapState::initialize` (varmap.cc:1063-1082): the
    /// endpoint sits at `wrapOffset(lastrange->getLast()+1)` where
    /// `lastrange` is the analysis window's LAST SIGNED range
    /// (`RangeList::getLastSignedRange`, address.cc:562-583) — for the
    /// default negative-growth window `[u64::MAX-999999, u64::MAX]` that is
    /// offset 0, the top of the stack window just past the deepest locals
    /// (NOT the window's numeric end). The endpoint's signed start is the
    /// sign-extension of that offset (0 here). After appending the endpoint
    /// the list is stable-sorted by `RangeHint::compareRanges` and deduped/
    /// unified by `reconcileDatatypes` (varmap.cc:1078-1079).
    pub fn initialize(&mut self) -> bool {
        // Enforce boundaries of local variables: const Range *lastrange =
        // range.getLastSignedRange(spaceid); if (lastrange == 0) return
        // false; (varmap.cc:1067-1068)
        let Some((_first, last)) = get_last_signed_range(&self.range) else {
            return false;
        };
        if self.maplist.is_empty() { return false; }
        // uintb high = spaceid->wrapOffset(lastrange->getLast()+1);
        // (varmap.cc:1070) — the +1 is uintb arithmetic wrapping modulo
        // 2^64 before wrapOffset (space.hh:383), i.e. Rust wrapping_add.
        let high = last.wrapping_add(1);
        // intb sst = byteToAddress(high, wordSize); sst =
        // sign_extend(sst, addrSize*8-1); sst = addressToByte(sst,
        // wordSize); (varmap.cc:1071-1073) — identity for the stack space.
        let sst = high as i64;
        // Add extra range to bound any final open entry (varmap.cc:1075)
        self.maplist.push(RangeHint::new(
            high, 1, sst,
            self.default_type.clone(), 0, RangeType::Endpoint, -2,
        ));
        // stable_sort(maplist, RangeHint::compareRanges); — Rust sort_by is
        // stable, and RangeHint::compare is the compareRanges key
        // (varmap.cc:321).
        self.maplist.sort_by(RangeHint::compare);
        self.reconcile_datatypes();
        self.iter_pos = 0;
        true
    }

    // Ghidra: varmap.cc:960 MapState::reconcileDatatypes
    /// Assuming a sorted list, from among a sequence of RangeHints with the
    /// same start, size, and flags, select the most specific data-type
    /// (`typeOrder < 0`), set all elements of the sequence to use it, and
    /// eliminate duplicates (`compare == 0`). Faithful to
    /// `MapState::reconcileDatatypes` (varmap.cc:960-996); Ghidra's heap
    /// `delete` of dropped hints is Rust's drop of the un-pushed clone.
    /// Ghidra's types are never null here (addRange substitutes the default
    /// type, varmap.cc:899-900); the None arm of the typeOrder test can only
    /// be reached through `MapState::new` without a default (test-only) and
    /// keeps None rather than dereferencing.
    fn reconcile_datatypes(&mut self) {
        if self.maplist.is_empty() { return; }
        let maplist = std::mem::take(&mut self.maplist);
        let mut new_list: Vec<RangeHint> = Vec::with_capacity(maplist.len());
        let mut start_pos = 0usize;
        let mut start_hint = maplist[0].clone();
        let mut start_datatype = start_hint.dtype.clone();
        new_list.push(maplist[0].clone());
        let mut cur_pos = 1usize;
        while cur_pos < maplist.len() {
            let cur_hint = &maplist[cur_pos];
            cur_pos += 1;
            if cur_hint.start == start_hint.start
                && cur_hint.size == start_hint.size
                && cur_hint.flags == start_hint.flags
            {
                // Take the most specific variant of the data-type
                // (varmap.cc:974-975)
                if let (Some(cur_dt), Some(start_dt)) = (&cur_hint.dtype, &start_datatype) {
                    if cur_dt.type_order(start_dt) < 0 {
                        start_datatype = cur_hint.dtype.clone();
                    }
                }
                // Keep the current hint if it is otherwise different
                // (varmap.cc:976-979)
                let is_duplicate = new_list
                    .last()
                    .map(|back| RangeHint::compare(cur_hint, back) == std::cmp::Ordering::Equal)
                    .unwrap_or(false);
                if !is_duplicate {
                    new_list.push(cur_hint.clone());
                }
            } else {
                while start_pos < new_list.len() {
                    new_list[start_pos].dtype = start_datatype.clone();
                    start_pos += 1;
                }
                start_hint = cur_hint.clone();
                start_datatype = cur_hint.dtype.clone();
                new_list.push(cur_hint.clone());
            }
        }
        while start_pos < new_list.len() {
            new_list[start_pos].dtype = start_datatype.clone();
            start_pos += 1;
        }
        self.maplist = new_list;
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
    /// Ghidra Symbol::flags & Varnode::persist: set by `Scope::addMap`
    /// when the mapping scope is global (database.cc:1131-1132) OR when a
    /// non-global symbol maps inside the global scope's discovery range
    /// (database.cc:1133-1142). Projected through
    /// `SymbolEntry::getAllFlags` (database.hh:271).
    pub persist: bool,
    /// Ghidra Symbol::flags property bits folded in by `Scope::addMap`
    /// (database.cc:1153): when a STATIC mapping with an EMPTY uselimit is
    /// installed, `glb->symboltab->getProperty(entry.addr)` (the Database
    /// flagbase — readonly/volatile ranges) is OR-ed into the SYMBOL's
    /// flags, exactly once, at map-install time. A property range installed
    /// later never contaminates an already-mapped symbol (the
    /// qp_scope_symbol_victim construction-order case). Accumulates across
    /// the symbol's mappings (`|=` per addMap, like the C++ flags word).
    pub property_flags: u32,
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
            persist: false,
            property_flags: 0,
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
    /// Ghidra ScopeLocal's symboltab range tree (varmap.cc:441-459,
    /// resetLocalWindow): the UNION of the prototype's localRange and
    /// paramRange, installed by `glb->symboltab->setRange`. Consumed by
    /// `adjust_fit`/`longest_fit` (varmap.cc:593), `mark_not_mapped`'s
    /// removeRange (varmap.cc:545) and `Scope::inScope` (database.hh:597).
    /// Modeled as inclusive `(first, last)` ranges sorted by `first`.
    pub local_range: Vec<(u64, u64)>,
    /// Ghidra `fd->getFuncProto().getLocalRange()` (fspec.hh:1539) — the
    /// prototype's OWN local window, cached on the scope because
    /// `buildVariableName` consults it directly (varmap.cc:555), DISTINCT
    /// from the union tree in `local_range` (a stack parameter at a positive
    /// offset is in the union but NOT in this window, so it must fall
    /// through to `ScopeInternal::buildVariableName`). Inclusive
    /// `(first, last)` ranges sorted by `first`.
    pub proto_local_range: Vec<(u64, u64)>,
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
    /// The Architecture whose `register_xref` answers register-name
    /// lookups when attached — Ghidra's `glb->translate` of the
    /// `buildVariableName` register queries (database.cc:2447 etc.). When
    /// `Some`, [`Self::get_register_name`] delegates to
    /// `Architecture::get_register_name` (the faithful
    /// sleighbase.cc:144-168 port) and `register_names` above is only the
    /// fixture fallback.
    pub arch_lookup: Option<std::sync::Arc<crate::arch::Architecture>>,
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
            proto_local_range: Vec::new(),
            min_param_offset: u64::MAX,
            max_param_offset: 0,
            stack_grows_negative: true,
            register_names: std::collections::BTreeMap::new(),
            arch_lookup: None,
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
        // database.cc:1131-1132/1138-1139 — persist lands on the SYMBOL at
        // addMap (global scope or global-discovery hit), projected through
        // getAllFlags (database.hh:271) exactly as the oracle bit does.
        if sym.persist {
            flags |= varnode_flags::PERSIST;
        }
        // database.cc:1153 — the addMap property fold lands on the SYMBOL's
        // flags (database.hh:271 getAllFlags = extraflags | symbol->flags).
        flags |= sym.property_flags;
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

    // Ghidra: varmap.cc:432 ScopeLocal::resetLocalWindow
    /// Reset the discovery window for local variables mapped to the scope's
    /// address space. Faithful to `ScopeLocal::resetLocalWindow`
    /// (varmap.cc:432-460): the stack growth direction comes from the
    /// prototype (varmap.cc:435 — Rugra threads `fd` because the scope owns
    /// no Funcdata handle, an ownership seam), the parameter-offset window
    /// resets (varmap.cc:436-437 — equivalent to Ghidra's call sites ONLY on
    /// the FIRST pass / after `Funcdata::clear` (funcdata.cc:70/96/836);
    /// Ghidra does NOT re-run resetLocalWindow across RULE_REPEATAPPLY
    /// restarts (action.cc:539-570), so from the 2nd pass on it keeps the
    /// markNotMapped-narrowed window and the cross-pass accumulated
    /// min/maxParamOffset — Rugra's fresh-per-pass scope (coreaction.rs)
    /// re-installs the full window each pass; registered as
    /// VARMAP-CROSSPASS-PERSISTENCE-0001), and the symboltab range tree
    /// becomes the UNION of the prototype's localRange and paramRange
    /// (varmap.cc:441-458) — for the default negative-growth 8-byte stack
    /// `[u64::MAX-999999, u64::MAX] ∪ [0, 511]`, the sign-extended
    /// negative-offset half where heritage puts locals. Rugra previously
    /// hardcoded a positive `[0, 0x100000)` window here — the PARAMETER
    /// side — which dropped every negative-offset local/open hint at the
    /// add_range gate (varmap.cc:902). Ghidra's `if (rangeLocked) return`
    /// (varmap.cc:439) has no Rugra counterpart: the `<localdb lock>`
    /// decode path that can lock the window is not ported, so the
    /// unconditional install is the only reachable behavior.
    pub fn reset_local_window(&mut self, fd: &crate::funcdata::Funcdata) {
        // stackGrowsNegative = fd->getFuncProto().isStackGrowsNegative();
        // (varmap.cc:435)
        self.stack_grows_negative = func_proto_stack_grows_negative(fd);
        // The AliasChecker direction (varmap.cc:700) reads the SPACE's
        // growth flag; Rugra derives it from the same proto flag (the two
        // are configured together in every reachable cspec).
        self.stack_direction = if self.stack_grows_negative { 1 } else { -1 };
        // minParamOffset = ~(uintb)0; maxParamOffset = 0;
        self.min_param_offset = u64::MAX;
        self.max_param_offset = 0;
        let localrange = func_proto_local_range(fd);
        let paramrange = func_proto_param_range(fd);
        // RangeList newrange; localRange ranges first, then paramrange
        // ranges (varmap.cc:444-458).
        let mut newrange = crate::address::RangeList::new();
        for r in localrange.ranges() {
            newrange.insert_range(*r);
        }
        for r in paramrange.ranges() {
            newrange.insert_range(*r);
        }
        // glb->symboltab->setRange(this,newrange); (varmap.cc:459)
        self.local_range = newrange
            .ranges()
            .iter()
            .map(|r| (r.get_first().as_u64(), r.get_last().as_u64()))
            .collect();
        // buildVariableName (varmap.cc:555) consults the prototype's own
        // localRange — NOT the union tree — so cache it separately.
        self.proto_local_range = localrange
            .ranges()
            .iter()
            .map(|r| (r.get_first().as_u64(), r.get_last().as_u64()))
            .collect();
    }

    // Ghidra: varmap.cc:1260 ScopeLocal::restructureVarnode (MapState construction)
    /// Build the MapState exactly as `ScopeLocal::restructureVarnode`
    /// (varmap.cc:1260-1261) does: the analysis range is the scope's range
    /// tree (the union installed by `reset_local_window`) with every param
    /// range removed — "Clear possible input symbols" (varmap.cc:874, the
    /// constructor loop varmap.cc:870-875) — and the default type is the
    /// factory's 1-byte TYPE_UNKNOWN (varmap.cc:1261). Public for the
    /// locked oracle fixture's observation surface (the C++ fixture reaches
    /// the same construction through `#define private public`).
    pub fn build_map_state(
        &self,
        fd: &crate::funcdata::Funcdata,
        types: &Arc<RwLock<crate::type_system::typefactory::TypeFactory>>,
    ) -> MapState {
        // MapState state(space,getRangeTree(),fd->getFuncProto().getParamRange(),
        //                 glb->types->getBase(1,TYPE_UNKNOWN));
        let mut analysis = crate::address::RangeList::new();
        for &(first, last) in &self.local_range {
            if let Some(r) = crate::address::Range::new(
                crate::address::Address::new(first),
                crate::address::Address::new(last),
            ) {
                analysis.insert_range(r);
            }
        }
        for r in func_proto_param_range(fd).ranges() {
            analysis.remove_range(*r);
        }
        let analysis_window: Vec<(u64, u64)> = analysis
            .ranges()
            .iter()
            .map(|r| (r.get_first().as_u64(), r.get_last().as_u64()))
            .collect();
        MapState::new_with_default(analysis_window, make_int_type(types, 1))
    }

    // Ghidra: varmap.cc:1256 ScopeLocal::restructureVarnode
    /// Restructure the stack frame from varnodes.
    /// Main entry point. Faithful to `ScopeLocal::restructureVarnode`
    /// (varmap.cc:1256-1286), including the gatherSymbols re-feed (:1269),
    /// the function_parameter/fake_input category clears before
    /// fakeInputSymbols (:1275-1276), sortAlias + markUnaliased +
    /// checkUnaliasedReturn (:1279-1282) and the alias[0]==0
    /// annotateRawStackPtr placeholder (:1284-1285). `fd` is mutable
    /// because annotateRawStackPtr inserts PTRSUB ops (newOpBefore/
    /// opSetInput, varmap.cc:405-406).
    pub fn restructure_varnode(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        aliasyes: bool,
    ) {
        // Ghidra varmap.cc:1259 `clearUnlockedCategory(-1)`（1275 为 function_parameter 另一调用） — NOT a blanket
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

        // resetLocalWindow (varmap.cc:432-460) is a Funcdata-lifecycle call:
        // Ghidra runs it exactly once right after scope construction
        // (funcdata.cc:70; again from Funcdata::clear, funcdata.cc:106) and
        // NEVER from restructureVarnode. The scope persists across
        // restructure passes, so the window narrowing done by
        // markNotMapped (outgoing call-parameter slots via
        // FuncCallSpecs::buildInputFromTrials fspec.cc:5737 and saved-register
        // spills via ActionRestrictLocal coreaction.cc:1979/1997) survives
        // into the next pass's MapState, where addRange's
        // `range.inRange(Address(spaceid,st),sz)` gate (varmap.cc:902) drops
        // hints for those slots. Rugra re-installed the full window here per
        // pass, resurrecting entries for unmapped slots and (through
        // markUnaliased) their varnodes' nolocalalias flag
        // (SB-MATCHURL-ORD70-0001); reset_local_window now runs only at
        // scope creation (coreaction.rs ActionRestructureVarnode).

        // Build the MapState with a default unknown base type (1 byte),
        // matching Ghidra's MapState construction (varmap.cc:1260-1261),
        // including the param-range subtraction of varmap.cc:870-875. The
        // stack-growth direction the MapState's embedded AliasChecker uses
        // (varmap.cc:700 `spaceid->stackGrowsNegative()`) comes from the
        // scope's proto-derived flag.
        let mut state = self.build_map_state(fd, &types);
        state.set_stack_grows_negative(self.stack_grows_negative);
        // state.gatherVarnodes(*fd); (varmap.cc:1267)
        state.gather_varnodes(fd);
        state.gather_spacebase(fd, &types);
        // state.gatherOpen(*fd); (varmap.cc:1268) — runs checker.gather
        // (varmap.cc:1214, deriveBoundaries included) and the
        // LoadGuard/StoreGuard addGuard loops (varmap.cc:1241-1248).
        state.gather_open(fd, &types);
        // state.gatherSymbols(maptable[space->getIndex()]); (varmap.cc:1269)
        // — re-feeds every mapped Symbol (typelocked ones with the typelock
        // hint flag) as a fixed hint.
        state.gather_symbols(&self);

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

        // At some point, processing mapped input symbols may be folded into
        // the above gather/restructure process, but for now we just define
        // fake symbols so that mark_unaliased will work (varmap.cc:1272-1277):
        // clearUnlockedCategory(Symbol::function_parameter) — unlocked
        // parameter Symbols do NOT survive the pass (only type-locked ones
        // stay, with an unlocked name reset) — then clearCategory(fake_input)
        // drops every previous pass's fake input symbols before rebuilding.
        self.clear_unlocked_category(symbol_category::FUNCTION_PARAMETER);
        self.clear_category(symbol_category::FAKE_INPUT);
        self.fake_input_symbols(fd, &types);

        // state.sortAlias(); (varmap.cc:1279)
        state.sort_alias();
        let aliases = state.get_alias().to_vec();
        // if (aliasyes) { markUnaliased(state.getAlias());
        // checkUnaliasedReturn(state.getAlias()); } (varmap.cc:1280-1282) —
        // aliasyes = (numpass != 0) from ActionRestructureVarnode
        // (coreaction.cc:2279): alias calculations are not reliable on the
        // first pass, so pass 0 skips both the unaliased marking and the
        // return-storage check entirely.
        if aliasyes {
            self.mark_unaliased(&aliases);
            self.check_unaliased_return(fd, &aliases);
        }
        // if (!state.getAlias().empty() && state.getAlias()[0] == 0)
        //   annotateRawStackPtr(); (varmap.cc:1284-1285) — a zero offset use
        // of the stack pointer gets the placeholder PTRSUB.
        if !aliases.is_empty() && aliases[0] == 0 {
            self.annotate_raw_stack_ptr(fd);
        }
    }

    // Ghidra: database.cc:2071 ScopeInternal::clearUnlockedCategory (cat >= 0)
    /// Clear unlocked symbols of the given category, mirroring
    /// `ScopeInternal::clearUnlockedCategory` (database.cc:2071-2090) for the
    /// `cat >= 0` branch `restructureVarnode` uses with
    /// `Symbol::function_parameter` (varmap.cc:1275): a type-locked symbol
    /// survives but its unlocked name resets to the `$$undef` placeholder
    /// (`renameSymbol(sym,buildUndefinedName())`, database.cc:2080-2082);
    /// everything else is `removeSymbol`'d. Ghidra's trailing
    /// `resetSizeLockType` (database.cc:2085-2086) has no Rugra counterpart:
    /// no Rugra path creates a size-locked (as opposed to type-locked)
    /// Symbol in ScopeLocal, so the branch is unreachable today.
    pub fn clear_unlocked_category(&mut self, cat: i32) {
        if cat < 0 {
            return; // category doesn't exist (database.cc:2073)
        }
        // Rename pass: type-locked symbols with an unlocked, defined name
        // take the undefined placeholder (order-independent of removals).
        loop {
            let idx = self
                .symbols
                .iter()
                .position(|s| {
                    s.category == cat
                        && s.typelock
                        && !s.namelock
                        && !s.is_name_undefined()
                });
            let Some(idx) = idx else { break };
            let undef = self
                .build_undefined_name()
                .unwrap_or_else(|| "$$undef00000000".to_string());
            self.rename_symbol(idx, &undef);
        }
        // Removal pass: every non-type-locked symbol of the category
        // (database.cc:2088-2089). Removing by position repeatedly keeps the
        // Vec re-keying consistent.
        loop {
            let idx = self
                .symbols
                .iter()
                .position(|s| s.category == cat && !s.typelock);
            match idx {
                Some(idx) => {
                    self.remove_symbol(idx);
                }
                None => break,
            }
        }
    }

    // Ghidra: database.cc:2022 ScopeInternal::clearCategory (cat >= 0)
    /// Remove every symbol of the given category, mirroring
    /// `ScopeInternal::clearCategory` (database.cc:2022-2029) for the
    /// `cat >= 0` branch `restructureVarnode` uses with
    /// `Symbol::fake_input` (varmap.cc:1276).
    pub fn clear_category(&mut self, cat: i32) {
        if cat < 0 {
            return;
        }
        loop {
            let idx = self.symbols.iter().position(|s| s.category == cat);
            match idx {
                Some(idx) => {
                    self.remove_symbol(idx);
                }
                None => break,
            }
        }
    }

    // Ghidra: varmap.cc:414 ScopeLocal::checkUnaliasedReturn
    /// If the return value is passed back in a location whose address space
    /// holds \b this scope's variables, assume the return value is unmapped,
    /// unless there is a specific alias into the location. Faithful to
    /// `ScopeLocal::checkUnaliasedReturn` (varmap.cc:414-428): the first
    /// RETURN op's value input, when it lives in the stack space and no
    /// alias offset (lower_bound over the SORTED alias list) reaches into
    /// `[offset, offset+size-1]`, is marked unmapped via
    /// `markNotMapped(space, offset, size, false)` — which removes any
    /// overlapping symbol and narrows the range tree.
    fn check_unaliased_return(&mut self, fd: &crate::funcdata::Funcdata, alias: &[u64]) {
        // PcodeOp *retOp = fd->getFirstReturnOp(); if (retOp == 0 ||
        // retOp->numInput() < 2) return; (varmap.cc:417-418)
        let Some(ret_op) = fd.get_first_return_op() else { return; };
        let (space, offset, size) = {
            let op = ret_op.0.read().unwrap();
            if op.inrefs.len() < 2 {
                return;
            }
            let vn = op.inrefs[1].read().unwrap();
            (vn.get_space(), vn.get_offset(), vn.get_size())
        };
        // if (vn->getSpace() != space) return; (varmap.cc:420)
        if space != self.space {
            return;
        }
        // Assume vn is mapped. Cannot check vn->isMapped() as we are in the
        // middle of restructuring. (varmap.cc:421)
        // vector<uintb>::const_iterator iter = lower_bound(alias.begin(),
        // alias.end(), vn->getOffset()); if (iter != alias.end()) {
        //   if (*iter <= (vn->getOffset() + vn->getSize() - 1)) return; }
        // (varmap.cc:422-426) — alias must be sorted (sortAlias, cc:1279).
        let end = offset.wrapping_add(size as u64).wrapping_sub(1);
        let pos = alias.partition_point(|&a| a < offset);
        if pos < alias.len() && alias[pos] <= end {
            return; // Alias into return storage, don't continue
        }
        // markNotMapped(space, vn->getOffset(), vn->getSize(), false);
        // (varmap.cc:427)
        self.mark_not_mapped(offset, size as i32, false);
    }

    // Ghidra: varmap.cc:386 ScopeLocal::annotateRawStackPtr
    /// For any read of the input stack pointer by a non-additive p-code op,
    /// assume this constitutes a zero offset reference into the stack frame
    /// and replace the raw Varnode with the standard spacebase placeholder
    /// `PTRSUB(sp,#0)` so the data-type system can treat it as a reference.
    /// Faithful to `ScopeLocal::annotateRawStackPtr` (varmap.cc:386-408):
    /// requires type recovery to have started; consumers whose eval type is
    /// `special` (unless a call) and the additive INT_ADD/PTRSUB/PTRADD
    /// producers are skipped; every remaining consumer gets a new PTRSUB
    /// before it, feeding slot `op->getSlot(spVn)`.
    fn annotate_raw_stack_ptr(&mut self, fd: &mut crate::funcdata::Funcdata) {
        // if (!fd->hasTypeRecoveryStarted()) return; (varmap.cc:389)
        if !fd.has_type_recovery_started() {
            return;
        }
        // Varnode *spVn = fd->findSpacebaseInput(space);
        // if (spVn == 0) return; (varmap.cc:390-391)
        let Some(sp_vn) = find_spacebase_input(fd) else { return; };
        // Collect the raw readers: skip eval-special non-calls and the
        // additive opcodes (varmap.cc:394-401).
        let descend_refs: Vec<_> = {
            let sp = sp_vn.read().unwrap();
            sp.descend.iter().filter_map(|w| w.upgrade()).collect()
        };
        let mut ref_ops: Vec<std::sync::Arc<RwLock<crate::op::PcodeOp>>> = Vec::new();
        for op_ref in descend_refs {
            let op = op_ref.read().unwrap();
            // if (op->getEvalType() == PcodeOp::special && !op->isCall())
            // continue; (varmap.cc:396)
            if op.get_eval_type() == crate::op::pcodeop_flags::SPECIAL && !op.is_call() {
                continue;
            }
            // if (opc == CPUI_INT_ADD || opc == CPUI_PTRSUB ||
            //     opc == CPUI_PTRADD) continue; (varmap.cc:397-399)
            if matches!(
                op.opcode,
                OpCode::CPUI_INT_ADD | OpCode::CPUI_PTRSUB | OpCode::CPUI_PTRADD
            ) {
                continue;
            }
            ref_ops.push(op_ref.clone());
        }
        // for each refOp: slot = op->getSlot(spVn); ptrsub =
        // fd->newOpBefore(op,CPUI_PTRSUB,spVn,fd->newConstant(size,0));
        // fd->opSetInput(op, ptrsub->getOut(), slot); (varmap.cc:402-407)
        for op_arc in ref_ops {
            let slot = {
                let op = op_arc.read().unwrap();
                let mut slot = op.inrefs.len();
                for (i, vn) in op.inrefs.iter().enumerate() {
                    if Arc::ptr_eq(vn, &sp_vn) {
                        slot = i;
                        break;
                    }
                }
                slot
            };
            let op_ref = crate::op::PcodeOpRef(op_arc);
            let cnst = fd.new_constant(sp_vn.read().unwrap().get_size(), 0);
            let ptrsub = fd.new_op_before(&op_ref, OpCode::CPUI_PTRSUB, &sp_vn, &cnst, None);
            let ptrsub_out = ptrsub.0.read().unwrap().output.clone();
            if let Some(out) = ptrsub_out {
                fd.op_set_input(&op_ref, out, slot);
            }
        }
    }

    // Ghidra: varmap.cc:1294 ScopeLocal::restructure
    /// Merge RangeHints into a definitive set of Symbols.
    /// Corresponds to ScopeLocal::restructure (varmap.cc:1294); `types`
    /// mirrors the `glb->types` handle threaded into `RangeHint::merge`
    /// (varmap.cc:1309) and `createEntry` (varmap.cc:622). Returns
    /// `Err` for the LowlevelError thrown by `RangeHint::merge`
    /// (varmap.cc:280), which in the oracle unwinds out of this walk.
    /// Public for the locked oracle fixture (Ghidra's declaration is
    /// reachable the same way through the fixture's access defines).
    pub fn restructure(
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
        // (varmap.cc:625); the factory deduplication is not yet ported
        // (no TypeFactory::getTypeArray in Rust), so the array shell is
        // built locally around the factory-owned element type. Registered
        // as a TYPE-WIRING-0001 residual.
        // type.hh:937 TypeArray(int4 n,Datatype *ao)
        //   : Datatype(n*ao->getAlignSize(), ao->getAlignment(), TYPE_ARRAY)
        // — the array shell's size is num × ELEMENT ALIGN-SIZE, never the
        // raw hint extent: the non-integral tail of an over-extended open
        // hint (varmap.cc:1315) stays unmapped (余数留洞).
        // (VARMAP-SPALIAS-ARRAYSHELL-SIZE-0001)
        let final_dt: Arc<Datatype> = if num > 1 {
            let array_size = num as usize * ct.get_align_size();
            Arc::new(Datatype::Array(crate::type_system::datatype::TypeArray {
                base: crate::type_system::datatype::TypeBase::new(
                    format!("{}[{}]", ct.get_name(), num),
                    array_size,
                    TypeMetatype::Array,
                ),
                array_of: ct.clone(),
                num_elements: num as usize,
            }))
        } else {
            ct
        };

        // addSymbol("",ct,addr,usepoint) — usepoint is the default invalid Address.
        // The symbol's byte size is the (possibly array-wrapped) TYPE size,
        // exactly as Ghidra's addSymbol sizes the Symbol from ct
        // (database.cc: Symbol/SymbolEntry take the mapping extent from the
        // data-type): varmap.cc:627 passes only the type, never a.size. An
        // open hint extended past the next symbol's start (varmap.cc:1315
        // `cur.size = next->sstart-cur.sstart`) routinely carries a
        // non-integral size — e.g. 12 bytes over undefined8 elements — and
        // createEntry rounds DOWN to whole elements (num = a.size/align,
        // varmap.cc:623), leaving the tail bytes unmapped (oracle httpd
        // main: -0xa8 hint extends to 12, symbol is 8 bytes, [-0xa0,-0x9c)
        // stays symbol-less). Stamping the raw hint size here (the old
        // `symbols[idx].size = hint.size`) extended the mapping over the
        // hole — VARMAP-SPALIAS-RETYPE-0001 drill evidence. add_symbol
        // already sizes the symbol from final_dt; no post-write.
        let start = hint.start;
        let _ = self.add_symbol(
            crate::space::AddressSpace::Stack, "", Some(final_dt), start, None,
        );
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
    /// register. When an `arch` handle is attached
    /// ([`ScopeLocal::set_arch_lookup`]), the lookup delegates to
    /// `Architecture::get_register_name` — the faithful
    /// `SleighBase::getRegisterName` port (sleighbase.cc:144-168) — and the
    /// flat table stays as the fallback for fixture ScopeLocals without an
    /// Architecture.
    pub fn get_register_name(
        &self,
        space: crate::space::AddressSpace,
        offset: u64,
        size: i32,
    ) -> String {
        if let Some(arch) = &self.arch_lookup {
            return arch.get_register_name(space, offset, size);
        }
        self.register_names
            .get(&(offset, size))
            .cloned()
            .unwrap_or_default()
    }

    // RUGRA-GLUE: set_arch_lookup (no Ghidra counterpart; Ghidra's
    //   ScopeInternal holds the `glb` Architecture pointer from its
    //   constructor (database.hh:688) and the getRegisterName calls in
    //   ScopeInternal::buildVariableName (database.cc:2447/2454/2462/2472/
    /// 2485) read glb->translate directly; Rugra's ScopeLocal is a plain
    /// struct, so the Architecture handle is attached by the caller that
    /// owns both).
    /// Attach the Architecture whose `register_xref` answers register-name
    /// lookups. Callers install this once at scope construction, before
    /// any `build_variable_name` consumer runs.
    pub fn set_arch_lookup(&mut self, arch: Option<std::sync::Arc<crate::arch::Architecture>>) {
        self.arch_lookup = arch;
    }

    // RUGRA-GLUE: local_range_in_range (RangeList::inRange for the local window)
    /// `RangeList::inRange(addr, 1)` over the prototype's own local window
    /// (`proto_local_range`): does any range contain the single byte at
    /// `offset`? Ghidra consults `fd->getFuncProto().getLocalRange()`
    /// directly (varmap.cc:555) — NOT the scope's union range tree — so a
    /// positive-offset stack parameter fails this gate and falls through to
    /// `ScopeInternal::buildVariableName`.
    pub fn local_range_in_range(&self, offset: u64) -> bool {
        self.proto_local_range
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
        self.add_symbol_with_property(space, nm, ct, start, usepoint, &|_, _| 0)
    }

    // Ghidra: database.cc:1530 Scope::addSymbol (+ database.cc:1126 addMap)
    /// `Scope::addSymbol` with the full `Scope::addMap` flag rules — the
    /// static whole-map entry installs with `addrtied` and the Database
    /// property bits at `start` folded into the symbol's flags when the
    /// uselimit is empty (database.cc:1149-1153; `property` models
    /// `glb->symboltab->getProperty`).
    pub fn add_symbol_with_property(
        &mut self,
        space: crate::space::AddressSpace,
        nm: &str,
        ct: Option<Arc<Datatype>>,
        start: u64,
        usepoint: Option<u64>,
        property: &dyn Fn(crate::space::AddressSpace, u64) -> u32,
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
        self.add_map_entry_with_property(
            idx, space, start, size, 0, crate::varnode::varnode_flags::MAPPED, uselimit, property,
        );
        idx
    }

    // Ghidra: database.cc:1843 ScopeInternal::addMapInternal
    /// Install one static SymbolEntry into the scope's maptable (the entry
    /// log this module materializes per query) without a Database property
    /// lookup — the production form: the flagbase fold answers 0 (the
    /// Database-unification gap DB-LOCALSCOPE-MAP-0001). See
    /// [`ScopeLocal::add_map_entry_with_property`] for the full addMap
    /// rule set.
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
        self.add_map_entry_with_property(
            sym, space, start, size, offset, extraflags, uselimit, &|_, _| 0,
        );
    }

    // Ghidra: database.cc:1843 ScopeInternal::addMapInternal (+ database.cc:1126
    // Scope::addMap flag rules)
    /// Install one static SymbolEntry with the FULL `Scope::addMap` flag
    /// rules. Faithful to `addMapInternal` (database.cc:1843-1872) + the
    /// addMap flag logic (database.cc:1149-1155): an EMPTY uselimit sets the
    /// Symbol's `addrtied` flag AND folds the Database property bits at the
    /// mapping address (`glb->symboltab->getProperty(entry.addr)`,
    /// database.cc:1153 — modeled by `property`, the flagbase lookup)
    /// into the SYMBOL's flags — BEFORE the sub-sort is frozen and the entry
    /// is installed. The entry's subsort is computed once, at insertion
    /// (rangemap.hh:238 calls `getSubsort()` on the new record; property
    /// bits never feed `getSubsort`, database.cc:98-106 reads only
    /// `addrtied`); the uselimit ranges are kept sorted by
    /// `(space index, first)` — the `set<Range>` order of the oracle's
    /// RangeList (address.hh:202-205) — with adjacent same-space ranges
    /// merged the way `RangeList::insertRange` merges them. The wrap check
    /// (database.cc:1855-1861) is the caller's duty
    /// (`add_fake_input_symbol` keeps the exact LowlevelError text).
    pub fn add_map_entry_with_property(
        &mut self,
        sym: usize,
        space: crate::space::AddressSpace,
        start: u64,
        size: i32,
        offset: i32,
        extraflags: u32,
        uselimit: Vec<(i32, u64, u64)>,
        property: &dyn Fn(crate::space::AddressSpace, u64) -> u32,
    ) {
        if uselimit.is_empty() {
            self.symbols[sym].addrtied = true; // database.cc:1149-1150
            // database.cc:1153 — the flagbase property fold onto the symbol.
            self.symbols[sym].property_flags |= property(space, start);
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
    /// Installs WITHOUT a flagbase property lookup (the addMap fold answers
    /// 0 — see [`ScopeLocal::install_symbol_with_property`]).
    pub fn install_symbol(&mut self, sym: LocalSymbol) -> usize {
        self.install_symbol_with_property(sym, &|_, _| 0)
    }

    // Ghidra: database.cc:1530 Scope::addSymbol (+ database.cc:1126 addMap)
    /// Install a fully-formed LocalSymbol with the full `Scope::addMap`
    /// flag rules: a static symbol with no usepoint gets `addrtied` set AND
    /// the Database property bits at its mapping address folded into its
    /// flags (database.cc:1149-1153 — `property` models
    /// `glb->symboltab->getProperty`). A global SCOPE also sets persist
    /// (database.cc:1131-1132). A dynamic symbol takes no static
    /// entry and never folds (database.cc:1146-1147). See
    /// [`ScopeLocal::install_symbol_addmap`] for the global-discovery
    /// branch (database.cc:1133-1142).
    pub fn install_symbol_with_property(
        &mut self,
        sym: LocalSymbol,
        property: &dyn Fn(crate::space::AddressSpace, u64) -> u32,
    ) -> usize {
        self.install_symbol_addmap(sym, property, None)
    }

    // Ghidra: database.cc:1530 Scope::addSymbol (+ database.cc:1126
    // Scope::addMap flag rules in full)
    /// Install a fully-formed LocalSymbol with the COMPLETE `Scope::addMap`
    /// rule set (database.cc:1126-1155):
    /// - global scope: `symbol->flags |= persist` (database.cc:1131-1132);
    /// - non-global scope whose mapping address is inside the GLOBAL
    ///   scope's discovery range (`in_global_discovery`, modeling
    ///   `glbScope->inScope(entry.addr,1,...)`, database.cc:1138): persist
    ///   AND `entry.uselimit.clear()` (database.cc:1140) — the cleared
    ///   uselimit then feeds the addrtied + fold branch;
    /// - static map with EMPTY uselimit: `addrtied` + the flagbase property
    ///   fold at the mapping address (database.cc:1149-1153).
    pub fn install_symbol_addmap(
        &mut self,
        mut sym: LocalSymbol,
        property: &dyn Fn(crate::space::AddressSpace, u64) -> u32,
        in_global_discovery: Option<&dyn Fn(crate::space::AddressSpace, u64) -> bool>,
    ) -> usize {
        let idx = self.symbols.len();
        let space = sym.space;
        let start = sym.start;
        let size = sym.size;
        let mut usepoint = sym.usepoint;
        let is_dynamic = sym.is_dynamic;
        // database.cc:1131-1132 — global scope: persist.
        if self.is_global_scope {
            sym.persist = true;
        } else if let Some(disc) = in_global_discovery {
            // database.cc:1133-1142 — global-discovery hit: persist AND the
            // uselimit clear (the entry stops being use-limited).
            if disc(space, start) {
                sym.persist = true;
                usepoint = None;
            }
        }
        // Single-entry equivalence of the addMap flag rule
        // (database.cc:1149-1150) on the (possibly cleared) usepoint.
        sym.addrtied = usepoint.is_none() && !is_dynamic;
        sym.usepoint = usepoint;
        self.symbols.push(sym);
        self.insert_name_tree(idx);
        if !is_dynamic {
            let code_index = ghidra_space_index(&crate::space::AddressSpace::Ram);
            let uselimit = match usepoint {
                None => Vec::new(),
                Some(up) => vec![(code_index, up, up)],
            };
            self.add_map_entry_with_property(
                idx,
                space,
                start,
                size,
                0,
                crate::varnode::varnode_flags::MAPPED,
                uselimit,
                property,
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
    fn mark_unaliased(&mut self, aliases: &[u64]) {
        // int4 alias_block_level = glb->alias_block_level; (varmap.cc:1347) —
        // default 2 = "block structs and arrays" (architecture.cc:1430). The
        // fixture fallback 0 ("block none") only applies to scope probes
        // without an attached Architecture.
        let alias_block_level = self
            .arch_lookup
            .as_ref()
            .map(|a| a.alias_block_level)
            .unwrap_or(0);

        // EntryMap *rangemap = maptable[space->getIndex()]; — the per-space
        // symbol-entry rangemap, iterated in (first, size, subsort) order
        // (varmap.cc:1333-1334). Materializing from the insertion log
        // reproduces the oracle's multiset order.
        let entries: Vec<(u64, i32, usize)> = self
            .materialize_maptable(self.space)
            .iter()
            .map(|e| (e.start, e.size, e.sym))
            .collect();

        // set<Range>::const_iterator rangeIter = getRangeTree().begin();
        // (varmap.cc:1339) — the scope's symboltab range tree (union of the
        // prototype's localRange/paramRange, narrowed by markNotMapped),
        // already (first, last) inclusive and sorted by first. The iterator
        // is STATEFUL across entries — it never resets inside the walk.
        let ranges = self.local_range.clone();

        let mut aliason = false;
        let mut curalias = 0u64;
        let mut i = 0usize;
        let mut range_iter = 0usize;

        for &(start, size, symi) in &entries {
            let curoff = start.wrapping_add(size as u64).wrapping_sub(1);
            // while ((i<alias.size()) && (alias[i] <= curoff)) { aliason =
            // true; curalias = alias[i++]; } (varmap.cc:1358-1361) — the
            // cursor i is shared across entries; aliason is sticky.
            while i < aliases.len() && aliases[i] <= curoff {
                aliason = true;
                curalias = aliases[i];
                i += 1;
            }
            // Aliases shouldn't go thru unmapped regions of the local
            // variables (varmap.cc:1363-1375): walking the (stateful) range
            // iterator, an alias is turned off when the symbol sits in a
            // mapped region that starts past the last alias, or when a
            // passed-over region ends beyond the last alias. `break` leaves
            // range_iter AT the containing range (no advance).
            while range_iter < ranges.len() {
                let (first, last) = ranges[range_iter];
                if first > curalias && curoff >= first {
                    aliason = false;
                }
                if last >= curoff {
                    break; // Check if symbol past end of mapped range
                }
                if last > curalias {
                    // If past end of range AND past last alias offset,
                    // turn aliases off
                    aliason = false;
                }
                range_iter += 1;
            }
            // Distance heuristic (varmap.cc:1378): a symbol far enough
            // (0xffff) past the last alias turns aliasing off — and the
            // mutation is sticky for subsequent entries.
            if aliason && curoff.wrapping_sub(curalias) > 0xffff {
                aliason = false;
            }
            // if (!aliason) symbol->getScope()->setAttribute(symbol,
            // Varnode::nolocalalias); (varmap.cc:1379) — setAttribute ORs
            // the flag in (database.cc:2200-2207): it is never cleared, so
            // a later pass that judges the symbol aliased keeps the mark.
            if !aliason {
                self.symbols[symi].unaliased = true;
            }
            // Locked data-types can block aliasing for subsequent entries
            // (varmap.cc:1381-1390): level 3 blocks everything, level >= 1
            // blocks structs, level > 1 (the default 2) also blocks arrays.
            let sym = &self.symbols[symi];
            if sym.typelock && alias_block_level != 0 {
                if alias_block_level == 3 {
                    aliason = false;
                } else {
                    let meta = sym.dtype.as_ref().map(|t| t.get_metatype());
                    if meta == Some(crate::type_system::datatype::TypeMetatype::Struct) {
                        aliason = false;
                    } else if meta
                        == Some(crate::type_system::datatype::TypeMetatype::Array)
                        && alias_block_level > 1
                    {
                        aliason = false;
                    }
                }
            }
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
        // The buildVariableName gate reads the prototype's own localRange
        // (varmap.cc:555), cached as proto_local_range — NOT the union tree.
        scope.proto_local_range = vec![(0, u64::MAX)];
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
        scope.proto_local_range = vec![(0, u64::MAX)];
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
        let s = scope.add_symbol(crate::space::AddressSpace::Stack, "a",
            Some(int_dt(4, TypeMetatype::Int)), 0, None);
        scope.mark_unaliased(&[]);
        assert!(scope.symbols[s].unaliased);
    }

    #[test]
    fn test_mark_unaliased_near_boundary_aliased() {
        let mut scope = ScopeLocal::new();
        // Symbol [0,8), alias at offset 4 → curoff=7, alias<=7 → aliased,
        // and distance (7-4)=3 <= 0xffff → stays aliased.
        let s = scope.add_symbol(crate::space::AddressSpace::Stack, "a",
            Some(int_dt(8, TypeMetatype::Int)), 0, None);
        scope.mark_unaliased(&[4]);
        assert!(!scope.symbols[s].unaliased);
    }

    #[test]
    fn test_mark_unaliased_far_past_boundary_unaliased() {
        let mut scope = ScopeLocal::new();
        // Symbol [0x20000, 4), alias at offset 4 → curoff=0x20003,
        // distance = 0x20003-4 > 0xffff → unaliased (distance heuristic).
        let s = scope.add_symbol(crate::space::AddressSpace::Stack, "a",
            Some(int_dt(4, TypeMetatype::Int)), 0x20000, None);
        scope.mark_unaliased(&[4]);
        assert!(scope.symbols[s].unaliased);
    }

    #[test]
    // Ghidra: varmap.cc:1363-1375 markUnaliased range-tree walk
    /// Aliases do not pass through unmapped regions: with an alias at 0x20
    /// inside mapped range [0x10,0x2f], a symbol in a separate mapped range
    /// [0x100,0x107] is UNALIASED — the stateful range walk turns aliasing
    /// off when it passes the end of a range beyond the last alias
    /// (`rng.getLast() > curalias`, varmap.cc:1371-1374). The helpf
    /// projection lane (PM-HF) pinned this on the locked oracle: entry
    /// -0xf8 unaliased despite aliases at -0x230..-0x220 within 0xffff.
    fn test_mark_unaliased_range_gap_clears_alias() {
        let mut scope = ScopeLocal::new();
        // Two mapped regions: [0x10,0x2f] (alias zone) and [0x100,0x107].
        scope.local_range = vec![(0x10, 0x2f), (0x100, 0x107)];
        let in_zone = scope.add_symbol(crate::space::AddressSpace::Stack, "in_zone",
            Some(int_dt(8, TypeMetatype::Int)), 0x20, None);
        let beyond_gap = scope.add_symbol(crate::space::AddressSpace::Stack, "beyond",
            Some(int_dt(8, TypeMetatype::Int)), 0x100, None);
        scope.mark_unaliased(&[0x20]);
        // In-zone symbol: alias 0x20 consumed, distance 7 <= 0xffff → aliased.
        assert!(!scope.symbols[in_zone].unaliased);
        // Beyond-gap symbol: sticky aliason from the zone, but the walk
        // passes range [0x10,0x2f] whose last (0x2f) > curalias (0x20) →
        // aliases off; the next range starts past curalias too.
        assert!(scope.symbols[beyond_gap].unaliased);
    }

    // --- ScopeLocal.restructure via adjust_fit (varmap.cc:1294, 587) ---

    #[test]
    // Ghidra: varmap.cc:633 AliasChecker::deriveBoundaries (model gates)
    /// The default-window model sets localBoundary = paramrange last = 511;
    /// a model-less prototype keeps the 0x1000000 default; the positive-
    /// growth branch takes paramrange first-range first for BOTH
    /// localBoundary and localExtreme (varmap.cc:648-652).
    fn test_derive_boundaries_model_gates() {
        let local = vec![(0xfffffffffff0bdc0u64, u64::MAX)];
        let param = vec![(0u64, 0x1ffu64)];
        let mut checker = AliasChecker::new(1);
        checker.derive_boundaries(&local, &param, true);
        assert_eq!(checker.boundaries(), (0x1ff, u64::MAX, u64::MAX));
        checker.derive_boundaries(&local, &param, false);
        assert_eq!(checker.boundaries(), (0x1000000, u64::MAX, u64::MAX));
        let mut pos = AliasChecker::new(-1);
        pos.derive_boundaries(&local, &param, true);
        assert_eq!(pos.boundaries(), (0, 0, u64::MAX));
    }

    fn test_get_last_signed_range_midway_corner() {
        // R8 cross-review corner: `Range::operator<` compares only
        // (spaceIndex, first) — never `last` (address.hh:202-205) — so
        // getLastSignedRange's upper_bound((midway,midway)) probe treats a
        // range with first == midway and last > midway as EQUIVALENT to the
        // probe key: upper_bound steps past it and --iter selects it. A
        // predicate that excluded it (ordering by (first,last)) would pick
        // the previous positive range and misplace initialize()'s endpoint.
        let midway = u64::MAX / 2;
        let ranges = [
            (0x100u64, 0x200u64),
            (midway, 0x8000000000000100),
            (0xfffffffffff0bdc0, u64::MAX),
        ];
        assert_eq!(
            get_last_signed_range(&ranges),
            Some((midway, 0x8000000000000100))
        );
        // Default-domain invariants: pure positive windows take the last
        // positive range; pure negative windows (the default local window)
        // take the last range in unsigned order; empty returns None.
        assert_eq!(
            get_last_signed_range(&[(0, 0x1ff), (0xfffffffffff0bdc0, u64::MAX)]),
            Some((0, 0x1ff))
        );
        assert_eq!(
            get_last_signed_range(&[(0xfffffffffff0bdc0, u64::MAX)]),
            Some((0xfffffffffff0bdc0, u64::MAX))
        );
        assert_eq!(get_last_signed_range(&[]), None);
    }

    #[test]
    fn test_restructure_two_disjoint_ranges() {
        // Build a MapState manually with two non-overlapping fixed int4 ranges.
        let mut state = MapState::new(vec![(0, 0xfffff)]);
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
        let mut state = MapState::new(vec![(0, 0xfffff)]);
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

    // --- RANGEHINT-CR-F2: a zero-size Some is substituted, never dropped ---

    #[test]
    fn test_mapstate_add_range_zero_size_substitutes_default() {
        // varmap.cc:899-900: a ct with getSize()==0 → ct = defaultType, and
        // the flow CONTINUES — the hint is collected with the default type
        // and its size. Pre-fix behavior: the Some(zero-size) input was
        // silently dropped (the `size <= 0` early return).
        let mut state =
            MapState::new_with_default(vec![(0, 0xfffff)], int_dt(4, TypeMetatype::Int));
        state.add_range(
            0x20,
            Some(int_dt(0, TypeMetatype::Int)),
            0,
            RangeType::Fixed,
            -1,
        );
        assert_eq!(state.hint_count(), 1, "zero-size Some must not be dropped");
        assert_eq!(state.hints()[0].start, 0x20);
        assert_eq!(state.hints()[0].size, 4, "size comes from the substituted default");
        assert_eq!(
            state.hints()[0].dtype.as_ref().map(|d| d.get_size()),
            Some(4),
            "dtype is the substituted default"
        );
    }

    #[test]
    fn test_mapstate_add_range_zero_size_bare_constructor_keeps_flow() {
        // The default-less `MapState::new` (test-only; the oracle always has
        // defaultType, varmap.cc:1261) cannot substitute: the flow still
        // continues with the historical anonymous size-1 shape instead of
        // dropping the hint (pre-fix: dropped).
        let mut bare = MapState::new(vec![(0, 0xfffff)]);
        bare.add_range(
            0x40,
            Some(int_dt(0, TypeMetatype::Int)),
            0,
            RangeType::Fixed,
            -1,
        );
        assert_eq!(bare.hint_count(), 1, "flow continues even without a default");
        assert_eq!(bare.hints()[0].size, 1);
        assert!(bare.hints()[0].dtype.is_none());
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
    fn test_add_map_property_fold_construction_order() {
        use crate::varnode::varnode_flags;
        // database.cc:1149-1153 — a static map with an EMPTY uselimit folds
        // the Database property bits at the mapping address into the SYMBOL
        // (visible through getAllFlags, database.hh:271); the fold runs at
        // map-install time, so construction order decides.
        let mut scope = ScopeLocal::new();
        scope.space = crate::space::AddressSpace::Stack;
        // Property-first: the readonly+volatile range covers 0x900-0x9ff.
        let property = |space: crate::space::AddressSpace, off: u64| -> u32 {
            if space == crate::space::AddressSpace::Stack && (0x900..=0x9ff).contains(&off) {
                varnode_flags::READONLY | varnode_flags::VOLATIL
            } else {
                0
            }
        };
        let folded = scope.install_symbol_with_property(
            overlap_sym("folded", 0x900, 4, None),
            &property,
        );
        let out = scope.query_properties_ex(
            crate::space::AddressSpace::Stack, 0x900, 4, None, None, &property,
        );
        assert!(out.entry.is_some());
        assert_eq!(
            out.flags,
            varnode_flags::MAPPED
                | varnode_flags::ADDRTIED
                | varnode_flags::READONLY
                | varnode_flags::VOLATIL
        );
        // Victim order: property range installed AFTER the map — the symbol
        // never folds, but the query-time property still answers for
        // scope-only/property-only branches.
        let victim = scope.install_symbol(overlap_sym("victim", 0x910, 4, None));
        let out = scope.query_properties_ex(
            crate::space::AddressSpace::Stack, 0x910, 4, None, None, &property,
        );
        assert!(out.entry.is_some());
        assert_eq!(
            out.flags,
            varnode_flags::MAPPED | varnode_flags::ADDRTIED
        );
        assert_eq!(scope.symbols[victim].property_flags, 0);
        assert_eq!(
            scope.symbols[folded].property_flags,
            varnode_flags::READONLY | varnode_flags::VOLATIL
        );
        // A usepoint-restricted map (non-empty uselimit) takes NEITHER
        // addrtied NOR the fold (database.cc:1149-1154 guard).
        scope.install_symbol_with_property(overlap_sym("limited", 0x920, 4, Some(0x5000)), &property);
        let out = scope.query_properties_ex(
            crate::space::AddressSpace::Stack, 0x920, 4, None, None, &property,
        );
        assert!(out.entry.is_none());
        // The fold is per-mapping-START (entry.addr), not per-extent: a
        // symbol starting OUTSIDE the range but overlapping into it folds
        // nothing even though part of its storage is readonly.
        scope.install_symbol_with_property(overlap_sym("tail", 0x8f8, 16, None), &property);
        assert_eq!(scope.symbols.last().unwrap().property_flags, 0);
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
