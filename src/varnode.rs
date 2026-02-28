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
    use super::*;
    #[derive(Debug)] pub struct SymbolEntry;
    #[derive(Debug)] pub struct ValueSet;
}

use stubs::*;
use crate::variable::HighVariable;
use crate::cover::Cover;
use crate::op::PcodeOp;
use crate::type_system::Datatype;

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
    /// Location (space + offset)
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
    pub fn new(size: usize, loc: Address) -> Self {
        Self {
            flags: 0,
            size,
            create_index: 0,
            mergegroup: 0,
            addlflags: 0,
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

    pub fn get_addr(&self) -> &Address {
        &self.loc
    }

    pub fn get_space(&self) -> AddressSpace {
        // Address in current address.rs is just u64 wrapper, returning Ram as placeholder
        AddressSpace::Ram
    }

    pub fn get_offset(&self) -> u64 {
        self.loc.into()
    }

    pub fn get_val(&self) -> u64 {
        self.loc.as_u64()
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
        let a = self.0.read().unwrap();
        let b = other.0.read().unwrap();
        // Corresponds to VarnodeCompareLocDef
        match a.loc.cmp(&b.loc) {
            std::cmp::Ordering::Equal => {
                match a.size.cmp(&b.size) {
                    std::cmp::Ordering::Equal => {
                        // Compare def (seqnum) if written
                        // For now, fall back to create_index as a unique tie-breaker
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
        let a = self.0.read().unwrap();
        let b = other.0.read().unwrap();
        // Corresponds to VarnodeCompareDefLoc

        // Input < Written < Free
        let a_cat = if a.is_input() { 0 } else if a.is_written() { 1 } else { 2 };
        let b_cat = if b.is_input() { 0 } else if b.is_written() { 1 } else { 2 };

        match a_cat.cmp(&b_cat) {
            std::cmp::Ordering::Equal => {
                // If categories are same, sort by location then index
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

    /// Create a new unique varnode
    pub fn create_unique(&mut self, size: usize) -> Arc<RwLock<Varnode>> {
        let addr = Address::new(self.uniqid);
        self.uniqid += size as u64;
        self.create(size, addr)
    }

    /// Create a new constant varnode
    pub fn create_constant(&mut self, size: usize, val: u64) -> Arc<RwLock<Varnode>> {
        let addr = Address::new(val);
        let vn = self.create(size, addr);
        vn.write().unwrap().set_flags(varnode_flags::CONSTANT);
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
}
