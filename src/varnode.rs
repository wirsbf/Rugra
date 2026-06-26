//! Varnode definitions for P-code IR
//!
//! Corresponds to Ghidra's `varnode.hh`

use crate::address::Address;
use crate::space::AddressSpace;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Weak, RwLock};

// Forward declarations/Stubs
// These placeholders allow the code to compile while other modules are being aligned.
pub mod stubs {
// use super::*;
    #[derive(Debug)] pub struct SymbolEntry;
    #[derive(Debug)] pub struct ValueSet;
}

use stubs::*;
use crate::variable::HighVariable;
use crate::cover::Cover;
use crate::op::PcodeOp;
use crate::type_system::Datatype;
use crate::type_system::TypeMetatype;

/// Flags for Varnode properties (varnode_flags in Ghidra)
pub mod varnode_flags {
    pub const MARK: u32 = 1 << 0;
    pub const CONSTANT: u32 = 1 << 1;
    pub const ANNOTATION: u32 = 1 << 2;
    pub const INPUT: u32 = 1 << 3;
    pub const WRITTEN: u32 = 1 << 4;
    pub const INSERT: u32 = 1 << 5;
    pub const IMPLIED: u32 = 1 << 6;
    pub const EXPLICIT: u32 = 1 << 7;
    pub const TYPELOCK: u32 = 1 << 8;
    pub const NAMELOCK: u32 = 1 << 9;
    pub const NOLOCALALIAS: u32 = 1 << 10;
    pub const VOLATIL: u32 = 1 << 11;
    pub const EXTERNREF: u32 = 1 << 12;
    pub const READONLY: u32 = 1 << 13;
    pub const PERSIST: u32 = 1 << 14;
    pub const ADDRTIED: u32 = 1 << 15;
    pub const UNAFFECTED: u32 = 1 << 16;
    pub const SPACEBASE: u32 = 1 << 17;
    pub const INDIRECTONLY: u32 = 1 << 18;
    pub const DIRECTWRITE: u32 = 1 << 19;
    pub const ADDRFORCE: u32 = 1 << 20;
    pub const MAPPED: u32 = 1 << 21;
    pub const INDIRECT_CREATION: u32 = 1 << 22;
    pub const RETURN_ADDRESS: u32 = 1 << 23;
    pub const COVERDIRTY: u32 = 1 << 24;
    pub const PRECISLO: u32 = 1 << 25;
    pub const PRECISHI: u32 = 1 << 26;
    pub const INDIRECTSTORAGE: u32 = 1 << 27;
    pub const HIDDENRETPARM: u32 = 1 << 28;
    pub const INCIDENTAL_COPY: u32 = 1 << 29;
    pub const AUTOLIVE_HOLD: u32 = 1 << 30;
    pub const PROTO_PARTIAL: u32 = 1 << 31;
}

/// A Varnode represents a storage location and size in P-code IR
///
/// Corresponds to Ghidra's `Varnode` class in `varnode.hh`
#[derive(Debug)]
pub struct Varnode {
    /// Flags describing properties (input, written, etc.)
    pub flags: u32,
    /// Size in bytes
    pub size: usize,
    /// Unique index assigned at creation
    pub create_index: u32,
    /// Merge group identifier
    pub mergegroup: i16,
    /// Additional flags (addl_flags in Ghidra)
    pub addlflags: u16,
    /// Address space this varnode belongs to
    pub address_space: AddressSpace,
    /// Location (offset within the address space)
    pub loc: Address,
    /// PcodeOp that defines this varnode (if written)
    pub def: Option<Weak<RwLock<PcodeOp>>>,
    /// High-level variable associated with this varnode
    pub high: Option<Arc<RwLock<HighVariable>>>,
    /// Symbol table entry
    pub mapentry: Option<Arc<RwLock<SymbolEntry>>>,
    /// Data type
    pub v_type: Option<Arc<Datatype>>,
    /// Ops that read this varnode
    pub descend: Vec<Weak<RwLock<PcodeOp>>>,
    /// Range of P-code ops where this varnode is "alive"
    pub cover: Option<Box<Cover>>,

    // Union fields from Ghidra (represented as separate fields in Rust)
    pub consumed: u64,
    pub nzm: u64,
}

impl Varnode {
    /// Create a new varnode (defaults to Ram space for backward compatibility)
    pub fn new(size: usize, loc: Address) -> Self {
        Self {
            flags: 0,
            size,
            create_index: 0,
            mergegroup: 0,
            addlflags: 0,
            address_space: AddressSpace::Ram,
            loc,
            def: None,
            high: None,
            mapentry: None,
            v_type: None,
            descend: Vec::new(),
            cover: None,
            consumed: 0,
            nzm: !0, // All bits possible initially
        }
    }

    /// Create a new varnode with explicit address space
    pub fn new_with_space(size: usize, space: AddressSpace, offset: u64) -> Self {
        let mut vn = Self::new(size, Address::new(offset));
        vn.address_space = space;
        vn
    }

    pub fn get_addr(&self) -> &Address {
        &self.loc
    }

    /// Get the address space this varnode belongs to
    pub fn get_space(&self) -> AddressSpace {
        self.address_space
    }

    pub fn get_offset(&self) -> u64 {
        self.loc.into()
    }

    pub fn get_val(&self) -> u64 {
        self.loc.as_u64()
    }

    
    pub fn is_unique(&self) -> bool {
        self.get_space() == AddressSpace::Unique
    }

    pub fn is_register(&self) -> bool {
        self.get_space() == AddressSpace::Register
    }

    pub fn constant_value(&self) -> Option<u64> {
        if self.is_constant() {
            Some(self.get_offset())
        } else {
            None
        }
    }

    pub fn size(&self) -> usize {
        self.get_size()
    }

    pub fn offset(&self) -> u64 {
        self.get_offset()
    }

    pub fn space(&self) -> AddressSpace {
        self.get_space()
    }

    pub fn version(&self) -> usize {
        0 // Add version support back if needed or mock it
    }

    pub fn with_version(self, _version: usize) -> Self {
        self // Mock
    }

    pub fn new_constant(val: u64, size: usize) -> Self {
        let mut v = Self::new_with_space(size, AddressSpace::Const, val);
        v.set_flags(varnode_flags::CONSTANT);
        v
    }

    pub fn new_register(offset: u64, size: usize) -> Self {
        Self::new_with_space(size, AddressSpace::Register, offset)
    }

    pub fn new_ram(offset: u64, size: usize) -> Self {
        Self::new_with_space(size, AddressSpace::Ram, offset)
    }

    pub fn new_stack(offset: u64, size: usize) -> Self {
        Self::new_with_space(size, AddressSpace::Stack, offset)
    }

    pub fn new_unique(offset: u64, size: usize) -> Self {
        Self::new_with_space(size, AddressSpace::Unique, offset)
    }


    pub fn get_size(&self) -> usize {
        self.size
    }

    pub fn get_create_index(&self) -> u32 {
        self.create_index
    }

    pub fn is_constant(&self) -> bool {
        (self.flags & varnode_flags::CONSTANT) != 0
    }

    pub fn is_input(&self) -> bool {
        (self.flags & varnode_flags::INPUT) != 0
    }

    pub fn is_written(&self) -> bool {
        (self.flags & varnode_flags::WRITTEN) != 0
    }

    pub fn is_free(&self) -> bool {
        (self.flags & (varnode_flags::INPUT | varnode_flags::WRITTEN)) == 0
    }

    pub fn set_flags(&mut self, f: u32) {
        self.flags |= f;
    }

    pub fn clear_flags(&mut self, f: u32) {
        self.flags &= !f;
    }

    // --- Ghidra-faithful varnode flag accessors (varnode.hh:235-330) ---
    // These mirror the C++ inline methods used by the core Actions
    // (ActionMarkExplicit, ActionMarkImplied, ActionRestrictLocal, etc.).

    /// Has this been visited by the current algorithm? (varnode.hh:263)
    pub fn is_mark(&self) -> bool {
        (self.flags & varnode_flags::MARK) != 0
    }
    /// Mark this Varnode for breadcrumb algorithms. (varnode.hh:303)
    pub fn set_mark(&mut self) {
        self.flags |= varnode_flags::MARK;
    }
    /// Clear the mark on this Varnode. (varnode.hh:304)
    pub fn clear_mark(&mut self) {
        self.flags &= !varnode_flags::MARK;
    }

    /// Is this an implied variable? (varnode.hh:235)
    pub fn is_implied(&self) -> bool {
        (self.flags & varnode_flags::IMPLIED) != 0
    }
    /// Mark this as an implied variable in the final C source. (varnode.hh:309)
    pub fn set_implied(&mut self) {
        self.flags |= varnode_flags::IMPLIED;
    }
    /// Clear the implied mark. (varnode.hh:310)
    pub fn clear_implied(&mut self) {
        self.flags &= !varnode_flags::IMPLIED;
    }

    /// Is this an explicitly printed variable? (varnode.hh:236)
    pub fn is_explicit(&self) -> bool {
        (self.flags & varnode_flags::EXPLICIT) != 0
    }
    /// Mark this as an explicit variable in the final C source. (varnode.hh:311)
    pub fn set_explicit(&mut self) {
        self.flags |= varnode_flags::EXPLICIT;
    }
    /// Clear the explicit mark. (varnode.hh:312)
    pub fn clear_explicit(&mut self) {
        self.flags &= !varnode_flags::EXPLICIT;
    }

    /// Is this value affected by a legitimate function input? (varnode.hh:247)
    pub fn is_direct_write(&self) -> bool {
        (self.flags & varnode_flags::DIRECTWRITE) != 0
    }
    /// Mark this as directly affected by a legal input. (varnode.hh:305)
    pub fn set_direct_write(&mut self) {
        self.flags |= varnode_flags::DIRECTWRITE;
    }
    /// Mark this as not directly affected. (varnode.hh:306)
    pub fn clear_direct_write(&mut self) {
        self.flags &= !varnode_flags::DIRECTWRITE;
    }

    /// Is the high-level variable tied to an address? (varnode.hh:250)
    /// Ghidra: (flags & (addrtied|insert)) == (addrtied|insert).
    pub fn is_addr_tied(&self) -> bool {
        (self.flags & (varnode_flags::ADDRTIED | varnode_flags::INSERT))
            == (varnode_flags::ADDRTIED | varnode_flags::INSERT)
    }

    /// Does this storage location persist beyond the function? (varnode.hh:246)
    pub fn is_persist(&self) -> bool {
        (self.flags & varnode_flags::PERSIST) != 0
    }

    /// Is this a value preserved across the function? (varnode.hh:255)
    pub fn is_unaffected(&self) -> bool {
        (self.flags & varnode_flags::UNAFFECTED) != 0
    }
    /// Mark Varnode as unaffected. (varnode.hh:167)
    pub fn set_unaffected(&mut self) {
        self.flags |= varnode_flags::UNAFFECTED;
    }

    /// Is this an abnormal input to the function? (varnode.hh:240)
    /// Ghidra: (flags & (input|directwrite)) == input.
    pub fn is_illegal_input(&self) -> bool {
        (self.flags & (varnode_flags::INPUT | varnode_flags::DIRECTWRITE))
            == varnode_flags::INPUT
    }

    /// Get the mask of bits known to be zero (non-zero mask).
    /// Faithful to Ghidra's `Varnode::getNZMask` (varnode.hh:231). In Ghidra
    /// this field (`nzm`) is maintained by Heritage/Cover. Until Rugra wires
    /// that, we return a conservative approximation:
    ///   - constants: the constant value (bits that are zero)
    ///   - others:    calc_mask(size) (assume all bits could be non-zero)
    pub fn get_nz_mask(&self) -> u64 {
        if self.is_constant() {
            self.get_offset()
        } else {
            let size = self.get_size();
            if size >= 8 {
                u64::MAX
            } else {
                (1u64 << (size * 8)) - 1
            }
        }
    }

    /// Return true if no live op reads this varnode. Faithful to
    /// `Varnode::hasNoDescend`. Used by several Rules (RuleXorCollapse,
    /// RuleSubZext) to check exclusive use.
    pub fn has_no_descend(&self) -> bool {
        self.descend.iter().all(|w| w.upgrade().is_none())
    }

    /// Return the single descendant op of this varnode, or None if there are
    /// zero or more than one. Faithful to `Varnode::loneDescend`.
    pub fn lone_descend(&self) -> Option<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>> {
        let live: Vec<_> = self.descend.iter().filter_map(|w| w.upgrade()).collect();
        if live.len() == 1 {
            Some(live.into_iter().next().unwrap())
        } else {
            None
        }
    }

    /// Get the mask of consumed bits. Faithful to `Varnode::getConsume`
    /// (varnode.hh:205). Maintained by the dead-code algorithm.
    pub fn get_consume(&self) -> u64 {
        self.consumed
    }

    /// Set the mask of consumed bits. Faithful to `Varnode::setConsume`
    /// (varnode.hh:206).
    pub fn set_consume(&mut self, val: u64) {
        self.consumed = val;
    }

    /// Get the stored non-zero mask (the Heritage-maintained field).
    /// Faithful to accessing the `nzm` field directly. This is the raw stored
    /// value; prefer get_nz_mask for the conservative approximation.
    pub fn get_nzm(&self) -> u64 {
        self.nzm
    }

    /// Set the stored non-zero mask.
    pub fn set_nzm(&mut self, val: u64) {
        self.nzm = val;
    }

    /// Is this varnode known to hold a boolean (0 or 1) value? Faithful to
    /// `Varnode::isBooleanValue` (varnode.cc:942-953). If written, checks the
    /// defining op's isCalculatedBool flag. If an input, checks type annotation
    /// (only when use_annotation is true).
    pub fn is_boolean_value(&self, use_annotation: bool) -> bool {
        if self.is_written() {
            if let Some(def) = self.def.as_ref().and_then(|w| w.upgrade()) {
                return def.read().unwrap().is_calculated_bool();
            }
        }
        if !use_annotation {
            return false;
        }
        // Check typelocked input of TYPE_BOOL.
        if self.is_input() && (self.flags & varnode_flags::TYPELOCK) != 0 {
            if self.size == 1 {
                if let Some(t) = &self.v_type {
                    return t.get_metatype() == TypeMetatype::Bool;
                }
            }
        }
        false
    }

    // --- Ghidra-faithful def / descend / flag accessors (varnode.hh:213-330) ---

    /// Get the PcodeOp that defines this Varnode, or None if not written.
    /// Faithful to `Varnode::getDef` (varnode.hh:213). Upgrades the internal
    /// Weak to an Arc; returns None if the def has been dropped or was never
    /// set.
    pub fn get_def(&self) -> Option<Arc<RwLock<PcodeOp>>> {
        self.def.as_ref().and_then(|w| w.upgrade())
    }

    /// Is this Varnode's value read-only (from a read-only memory space)?
    /// Faithful to `Varnode::isReadOnly` (varnode.hh:243).
    pub fn is_read_only(&self) -> bool {
        (self.flags & varnode_flags::READONLY) != 0
    }

    /// Is this an annotation varnode (inserted by the decompiler, not real
    /// code)? Faithful to `Varnode::isAnnotation` (varnode.hh:237).
    pub fn is_annotation(&self) -> bool {
        (self.flags & varnode_flags::ANNOTATION) != 0
    }

    /// Is this a spacebase pointer varnode? Faithful to
    /// `Varnode::isSpacebase` (varnode.hh, referenced by varmap/heritage).
    pub fn is_spacebase(&self) -> bool {
        (self.flags & varnode_flags::SPACEBASE) != 0
    }

    /// Is this a persistent (global) varnode? Faithful to `isPersist`.
    pub fn is_persist_global(&self) -> bool {
        (self.flags & varnode_flags::PERSIST) != 0
    }

    /// Return an iterator over the live descendant ops (ops that read this
    /// Varnode). Faithful to `Varnode::beginDescend`/`endDescend`
    /// (varnode.hh:219-220). Filters out Weak refs whose target has been
    /// dropped.
    pub fn descend_iter(&self) -> impl Iterator<Item = Arc<RwLock<PcodeOp>>> + '_ {
        self.descend.iter().filter_map(|w| w.upgrade())
    }

    /// Count the live descendant ops. Useful for Rules that need the descend
    /// count without collecting into a Vec.
    pub fn count_descends(&self) -> usize {
        self.descend.iter().filter(|w| w.strong_count() > 0).count()
    }

    /// Add a descendant op reference. Faithful to `Varnode::addDescend`
    /// (varnode.hh:295).
    pub fn add_descend(&mut self, op: &Arc<RwLock<PcodeOp>>) {
        self.descend.push(std::sync::Arc::downgrade(op));
    }

    /// Does the defining op of this Varnode have a boolean output? Faithful to
    /// checking `getDef()->isBoolOutput()` (used by JumpBasic::calcRange,
    /// jumptable.cc:1144). Returns false if not written or the def can't be
    /// resolved.
    pub fn is_bool_output_def(&self) -> bool {
        if !self.is_written() {
            return false;
        }
        if let Some(def) = self.get_def() {
            return (def.read().unwrap().flags & crate::op::pcodeop_flags::BOOLOUTPUT) != 0;
        }
        false
    }
}

impl PartialEq for Varnode {
    fn eq(&self, other: &Self) -> bool {
        self.loc == other.loc && self.size == other.size && self.create_index == other.create_index
    }
}

impl Eq for Varnode {}

impl PartialOrd for Varnode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for Varnode {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Mimic VarnodeCompareLocDef logic from Ghidra
        match self.loc.cmp(&other.loc) {
            std::cmp::Ordering::Equal => {
                match self.size.cmp(&other.size) {
                    std::cmp::Ordering::Equal => {
                        self.create_index.cmp(&other.create_index)
                    }
                    ord => ord,
                }
            }
            ord => ord,
        }
    }
}

/// A wrapper for Rc<RefCell<Varnode>> for location-based sorting
#[derive(Debug, Clone)]
pub struct VarnodeLocRef(pub Arc<RwLock<Varnode>>);

impl PartialEq for VarnodeLocRef {
    fn eq(&self, other: &Self) -> bool {
        if Arc::ptr_eq(&self.0, &other.0) { return true; }
        self.0.read().unwrap().eq(&other.0.read().unwrap())
    }
}

impl Eq for VarnodeLocRef {}

impl PartialOrd for VarnodeLocRef {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VarnodeLocRef {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if Arc::ptr_eq(&self.0, &other.0) { return std::cmp::Ordering::Equal; }
        let a = self.0.read().unwrap();
        let b = other.0.read().unwrap();
        match a.loc.cmp(&b.loc) {
            std::cmp::Ordering::Equal => {
                match a.size.cmp(&b.size) {
                    std::cmp::Ordering::Equal => {
                        a.create_index.cmp(&b.create_index)
                    }
                    ord => ord,
                }
            }
            ord => ord,
        }
    }
}

/// A wrapper for Rc<RefCell<Varnode>> for definition-based sorting
#[derive(Debug, Clone)]
pub struct VarnodeDefRef(pub Arc<RwLock<Varnode>>);

impl PartialEq for VarnodeDefRef {
    fn eq(&self, other: &Self) -> bool {
        if Arc::ptr_eq(&self.0, &other.0) { return true; }
        self.0.read().unwrap().eq(&other.0.read().unwrap())
    }
}

impl Eq for VarnodeDefRef {}

impl PartialOrd for VarnodeDefRef {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VarnodeDefRef {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if Arc::ptr_eq(&self.0, &other.0) { return std::cmp::Ordering::Equal; }
        let a = self.0.read().unwrap();
        let b = other.0.read().unwrap();

        let a_cat = if a.is_input() { 0 } else if a.is_written() { 1 } else { 2 };
        let b_cat = if b.is_input() { 0 } else if b.is_written() { 1 } else { 2 };

        match a_cat.cmp(&b_cat) {
            std::cmp::Ordering::Equal => {
                match a.loc.cmp(&b.loc) {
                    std::cmp::Ordering::Equal => a.create_index.cmp(&b.create_index),
                    ord => ord,
                }
            }
            ord => ord,
        }
    }
}

/// Simplified varnode data (for serialization/deserialization)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VarnodeData {
    pub space: AddressSpace,
    pub offset: u64,
    pub size: usize,
}

impl VarnodeData {
    pub fn new(space: AddressSpace, offset: u64, size: usize) -> Self {
        Self {
            space,
            offset,
            size,
        }
    }
}

impl From<&Varnode> for VarnodeData {
    fn from(vn: &Varnode) -> Self {
        VarnodeData {
            space: vn.get_space(),
            offset: vn.get_offset(),
            size: vn.get_size(),
        }
    }
}

/// Container for managing Varnodes
///
/// Corresponds to Ghidra's `VarnodeBank` class in `varnode.hh`
#[derive(Debug)]
pub struct VarnodeBank {
    /// Sorted by location (VarnodeLocSet in Ghidra)
    pub loc_tree: BTreeSet<VarnodeLocRef>,
    /// Sorted by definition (VarnodeDefSet in Ghidra)
    pub def_tree: BTreeSet<VarnodeDefRef>,

    /// Counter for assigning create_index
    create_index: u32,

    /// Unique space manager
    uniq_space: AddressSpace,
    uniqid: u64,
}

impl VarnodeBank {
    pub fn new() -> Self {
        Self {
            loc_tree: BTreeSet::new(),
            def_tree: BTreeSet::new(),
            create_index: 0,
            uniq_space: AddressSpace::Unique,
            uniqid: 0,
        }
    }

    /// Create a new free varnode
    pub fn create(&mut self, size: usize, loc: Address) -> Arc<RwLock<Varnode>> {
        let mut vn = Varnode::new(size, loc);
        vn.create_index = self.create_index;
        self.create_index += 1;

        let rc = Arc::new(RwLock::new(vn));
        self.loc_tree.insert(VarnodeLocRef(rc.clone()));
        self.def_tree.insert(VarnodeDefRef(rc.clone()));
        rc
    }

    /// Create a new varnode with explicit address space
    pub fn create_with_space(&mut self, size: usize, space: AddressSpace, offset: u64) -> Arc<RwLock<Varnode>> {
        let vn_arc = self.create(size, Address::new(offset));
        vn_arc.write().unwrap().address_space = space;
        vn_arc
    }

    /// Create a new unique varnode
    pub fn create_unique(&mut self, size: usize) -> Arc<RwLock<Varnode>> {
        let addr = Address::new(self.uniqid);
        self.uniqid += size as u64;
        let vn_arc = self.create(size, addr);
        vn_arc.write().unwrap().address_space = AddressSpace::Unique;
        vn_arc
    }

    /// Create a new constant varnode
    pub fn create_constant(&mut self, size: usize, val: u64) -> Arc<RwLock<Varnode>> {
        let addr = Address::new(val);
        let vn = self.create(size, addr);
        {
            let mut vn_w = vn.write().unwrap();
            vn_w.set_flags(varnode_flags::CONSTANT);
            vn_w.address_space = AddressSpace::Const;
        }
        vn
    }

    /// Mark a varnode as an input
    pub fn set_input(&mut self, vn: Arc<RwLock<Varnode>>) {
        self.loc_tree.remove(&VarnodeLocRef(vn.clone()));
        self.def_tree.remove(&VarnodeDefRef(vn.clone()));

        vn.write().unwrap().set_flags(varnode_flags::INPUT);

        self.loc_tree.insert(VarnodeLocRef(vn.clone()));
        self.def_tree.insert(VarnodeDefRef(vn.clone()));
    }

    /// Mark a varnode as defined by an operation
    pub fn set_def(&mut self, vn: Arc<RwLock<Varnode>>, op: Weak<RwLock<PcodeOp>>) {
        self.loc_tree.remove(&VarnodeLocRef(vn.clone()));
        self.def_tree.remove(&VarnodeDefRef(vn.clone()));

        let mut v = vn.write().unwrap();
        v.set_flags(varnode_flags::WRITTEN);
        v.def = Some(op);

        drop(v);
        self.loc_tree.insert(VarnodeLocRef(vn.clone()));
        self.def_tree.insert(VarnodeDefRef(vn.clone()));
    }

    pub fn clear(&mut self) {
        self.loc_tree.clear();
        self.def_tree.clear();
        self.create_index = 0;
        self.uniqid = 0;
    }

    
    pub fn make_free(&mut self, vn: &mut Varnode) {
        vn.flags &= !varnode_flags::INPUT;
        vn.flags &= !varnode_flags::WRITTEN;
        vn.def = None;
    }

    pub fn replace(&mut self, vn1: &mut Varnode, vn2: &mut Varnode) {
        vn2.size = vn1.size;
        vn2.loc = vn1.loc;
    }

    pub fn begin_def(&self) -> std::collections::btree_set::Iter<'_, VarnodeDefRef> {
        self.def_tree.iter()
    }

    pub fn begin_loc(&self) -> std::collections::btree_set::Iter<'_, VarnodeLocRef> {
        self.loc_tree.iter()
    }

    pub fn has_input_intersection(&self) -> bool {
        false // Placeholder for structure alignment
    }

    pub fn num_varnodes(&self) -> usize {
        self.loc_tree.len()
    }

    pub fn get_create_index(&self) -> u32 {
        self.create_index
    }

    /// Find a free varnode at a specific location and size
    pub fn find_free(&self, size: usize, loc: Address) -> Option<Arc<RwLock<Varnode>>> {
        let search_vn = Arc::new(RwLock::new(Varnode::new(size, loc)));
        self.loc_tree.get(&VarnodeLocRef(search_vn)).map(|v| v.0.clone())
    }
}

impl fmt::Display for Varnode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.loc, self.size)
    }
}

impl Default for VarnodeBank {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varnode_bank_creation() {
        let mut bank = VarnodeBank::new();
        let loc = Address::new(0);
        let vn = bank.create(4, loc);

        assert_eq!(bank.num_varnodes(), 1);
        assert_eq!(vn.read().unwrap().get_size(), 4);
    }

    // --- Ghidra-faithful flag accessors (varnode.hh:235-330) ---

    #[test]
    fn test_varnode_mark_flag() {
        let mut v = Varnode::new(4, Address::new(0));
        assert!(!v.is_mark());
        v.set_mark();
        assert!(v.is_mark());
        v.clear_mark();
        assert!(!v.is_mark());
    }

    #[test]
    fn test_varnode_explicit_implied_flags() {
        let mut v = Varnode::new(4, Address::new(0));
        assert!(!v.is_explicit());
        assert!(!v.is_implied());
        v.set_explicit();
        assert!(v.is_explicit());
        v.set_implied();
        assert!(v.is_implied());
        v.clear_explicit();
        assert!(!v.is_explicit());
        v.clear_implied();
        assert!(!v.is_implied());
    }

    #[test]
    fn test_varnode_addr_tied_requires_both_flags() {
        // is_addr_tied is true only when BOTH addrtied AND insert are set
        // (varnode.hh:250).
        let mut v = Varnode::new(4, Address::new(0));
        v.set_flags(varnode_flags::ADDRTIED);
        assert!(!v.is_addr_tied()); // only addrtied → false
        v.set_flags(varnode_flags::INSERT);
        assert!(v.is_addr_tied()); // both → true
    }

    #[test]
    fn test_varnode_illegal_input() {
        // is_illegal_input: input set but directwrite clear (varnode.hh:240).
        let mut v = Varnode::new(4, Address::new(0));
        v.set_flags(varnode_flags::INPUT);
        assert!(v.is_illegal_input());
        v.set_direct_write();
        assert!(!v.is_illegal_input()); // input|directwrite → not illegal
    }
}
