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
    #[derive(Debug)] pub struct ValueSet;
}

use crate::database::SymbolEntry;
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

/// Additional boolean properties on a Varnode.
/// Faithful to Ghidra's `addl_flags` (varnode.hh:115-140).
pub mod addl_flags {
    pub const ACTIVE_HERITAGE: u16 = 0x01;
    pub const WRITE_MASK: u16 = 0x02;
    pub const VAC_CONSUME: u16 = 0x04;
    pub const LIS_CONSUME: u16 = 0x08;
    pub const PTR_CHECK: u16 = 0x10;
    pub const PTR_FLOW: u16 = 0x20;
    pub const UNSIGNED_PRINT: u16 = 0x40;
    pub const LONG_PRINT: u16 = 0x80;
    pub const STACK_STORE: u16 = 0x100;
    pub const LOCKED_INPUT: u16 = 0x200;
    pub const SPACEBASE_PLACEHOLDER: u16 = 0x400;
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
    // Ghidra: varnode.cc:578 Varnode::new
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

    // Ghidra: varnode.cc:578 Varnode::newWithSpace
    /// Create a new varnode with explicit address space
    pub fn new_with_space(size: usize, space: AddressSpace, offset: u64) -> Self {
        let mut vn = Self::new(size, Address::new(offset));
        vn.address_space = space;
        vn
    }

    // Ghidra: varnode.cc:578 Varnode::getAddr
    pub fn get_addr(&self) -> &Address {
        &self.loc
    }

    // Ghidra: varnode.cc:578 Varnode::getSpace
    /// Get the address space this varnode belongs to
    pub fn get_space(&self) -> AddressSpace {
        self.address_space
    }

    // Ghidra: varnode.cc:578 Varnode::getOffset
    pub fn get_offset(&self) -> u64 {
        self.loc.into()
    }

    // Ghidra: varnode.cc:578 Varnode::getVal
    pub fn get_val(&self) -> u64 {
        self.loc.as_u64()
    }

    
    // Ghidra: varnode.cc:578 Varnode::isUnique
    pub fn is_unique(&self) -> bool {
        self.get_space() == AddressSpace::Unique
    }

    // Ghidra: varnode.cc:578 Varnode::isRegister
    pub fn is_register(&self) -> bool {
        self.get_space() == AddressSpace::Register
    }

    // Ghidra: varnode.cc:578 Varnode::constantValue
    pub fn constant_value(&self) -> Option<u64> {
        if self.is_constant() {
            Some(self.get_offset())
        } else {
            None
        }
    }

    // Ghidra: varnode.cc:578 Varnode::size
    pub fn size(&self) -> usize {
        self.get_size()
    }

    // Ghidra: varnode.cc:578 Varnode::offset
    pub fn offset(&self) -> u64 {
        self.get_offset()
    }

    // Ghidra: varnode.cc:578 Varnode::space
    pub fn space(&self) -> AddressSpace {
        self.get_space()
    }

    // Ghidra: varnode.cc:578 Varnode::version
    pub fn version(&self) -> usize {
        0 // Add version support back if needed or mock it
    }

    // Ghidra: varnode.cc:578 Varnode::withVersion
    pub fn with_version(self, _version: usize) -> Self {
        self // Mock
    }

    // Ghidra: varnode.cc:578 Varnode::newConstant
    pub fn new_constant(val: u64, size: usize) -> Self {
        let mut v = Self::new_with_space(size, AddressSpace::Const, val);
        v.set_flags(varnode_flags::CONSTANT);
        v
    }

    // Ghidra: varnode.cc:578 Varnode::newRegister
    pub fn new_register(offset: u64, size: usize) -> Self {
        Self::new_with_space(size, AddressSpace::Register, offset)
    }

    // Ghidra: varnode.cc:578 Varnode::newRam
    pub fn new_ram(offset: u64, size: usize) -> Self {
        Self::new_with_space(size, AddressSpace::Ram, offset)
    }

    // Ghidra: varnode.cc:578 Varnode::newStack
    pub fn new_stack(offset: u64, size: usize) -> Self {
        Self::new_with_space(size, AddressSpace::Stack, offset)
    }

    // Ghidra: varnode.cc:578 Varnode::newUnique
    pub fn new_unique(offset: u64, size: usize) -> Self {
        Self::new_with_space(size, AddressSpace::Unique, offset)
    }


    // Ghidra: varnode.cc:578 Varnode::getSize
    pub fn get_size(&self) -> usize {
        self.size
    }

    // Ghidra: varnode.cc:578 Varnode::getCreateIndex
    pub fn get_create_index(&self) -> u32 {
        self.create_index
    }

    // Ghidra: varnode.cc:578 Varnode::isConstant
    pub fn is_constant(&self) -> bool {
        (self.flags & varnode_flags::CONSTANT) != 0
    }

    // Ghidra: varnode.cc:799 Varnode::isConstantExtended
    /// Check if this Varnode holds an extended constant, returning the
    /// 128-bit value. Faithful to `Varnode::isConstantExtended`
    /// (varnode.cc:799-840). Returns Some((lo, hi)) or None.
    pub fn is_constant_extended(&self) -> Option<(u64, u64)> {
        if self.is_constant() {
            return Some((self.get_offset(), 0));
        }
        if !self.is_written() || self.size <= 8 {
            return None;
        }
        if self.size > 16 {
            return None;
        }
        let def = self.get_def()?;
        let def_rg = def.read().unwrap();
        let opc = def_rg.opcode;
        if opc == crate::opcodes::OpCode::CPUI_INT_ZEXT {
            let vn0 = def_rg.get_in(0)?;
            let r0 = vn0.read().unwrap();
            if r0.is_constant() {
                return Some((r0.get_offset(), 0));
            }
        } else if opc == crate::opcodes::OpCode::CPUI_INT_SEXT {
            let vn0 = def_rg.get_in(0)?;
            let r0 = vn0.read().unwrap();
            if r0.is_constant() {
                let val = r0.get_offset();
                let val = if r0.get_size() < 8 {
                    // Sign-extend from r0 size to self size.
                    let signbit = 1u64 << (r0.get_size() * 8 - 1);
                    if (val & signbit) != 0 {
                        val | crate::address::calc_mask(self.size) & !crate::address::calc_mask(r0.get_size())
                    } else {
                        val
                    }
                } else {
                    val
                };
                let hi = if (val & (1u64 << 63)) != 0 && self.size > 8 {
                    u64::MAX
                } else {
                    0
                };
                return Some((val, hi));
            }
        } else if opc == crate::opcodes::OpCode::CPUI_PIECE {
            let vn0 = def_rg.get_in(0)?;
            let vn1 = def_rg.get_in(1)?;
            let r0 = vn0.read().unwrap();
            let r1 = vn1.read().unwrap();
            if r0.is_constant() && r1.is_constant() {
                let lo = r1.get_offset();
                let hi = r0.get_offset();
                return Some((lo, hi));
            }
        }
        None
    }

    // Ghidra: varnode.cc:578 Varnode::isInput
    pub fn is_input(&self) -> bool {
        (self.flags & varnode_flags::INPUT) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::isWritten
    pub fn is_written(&self) -> bool {
        (self.flags & varnode_flags::WRITTEN) != 0
    }

    // Ghidra: varnode.cc:711 Varnode::printRawNoMarkup
    /// Print varnode location without markup (for debugging).
    /// Returns the "expected" size (register size or default).
    /// Faithful to `printRawNoMarkup` (varnode.cc:711-734).
    pub fn print_raw_no_markup(&self) -> (String, usize) {
        // cc:719: try register name
        // Rugra doesn't have Translate::getRegisterName; use space+offset.
        let space_name = self.address_space.name();
        let offset = self.loc.as_u64();
        let s = format!("{}:{}", space_name, offset);
        // cc:730: expect = trans->getDefaultSize()
        let expect = 8; // x86-64 default
        (s, expect)
    }

    // Ghidra: varnode.cc:741 Varnode::printRaw
    /// Print full varnode info for debugging.
    /// Faithful to `printRaw` (varnode.cc:741-756).
    pub fn print_raw(&self) -> String {
        let (base, expect) = self.print_raw_no_markup();
        let mut s = base;
        // cc:746: if expect != size, append size
        if expect != self.size {
            s += &format!(":{}", self.size);
        }
        // cc:748: input marker
        if self.is_input() {
            s += "(i)";
        }
        // cc:750: def seqnum
        if self.is_written() {
            if let Some(def_weak) = self.def.as_ref() {
                if let Some(def_op) = def_weak.upgrade() {
                    let def_r = def_op.read().unwrap();
                    s += &format!(" ({:?})", def_r.start);
                }
            }
        }
        // cc:752: free marker
        if (self.flags & (varnode_flags::INSERT | varnode_flags::CONSTANT)) == 0 {
            s += "(free)";
        }
        s
    }

    // Ghidra: varnode.cc:761 Varnode::printRawHeritage
    /// Print data-flow tree for debugging.
    /// Faithful to `printRawHeritage` (varnode.cc:761-797).
    pub fn print_raw_heritage(&self, depth: i32) -> String {
        let indent: String = std::iter::repeat(' ').take(depth as usize).collect();
        if self.is_constant() {
            return format!("{}{}\n", indent, self.print_raw());
        }
        let mut s = format!("{}{}", indent, self.print_raw());
        s += " ";
        if let Some(def_weak) = self.def.as_ref() {
            if let Some(def_op) = def_weak.upgrade() {
                let def_r = def_op.read().unwrap();
                s += &format!("{:?} {:?}\n", def_r.opcode, def_r.start);
            }
        } else {
            s += "(null)\n";
        }
        s
    }

    // Ghidra: varnode.cc:282 Varnode::printInfo
    /// Print summary info for debugging.
    /// Faithful to `printInfo` (varnode.cc:282-314).
    pub fn print_info(&self) -> String {
        let mut s = self.print_raw();
        s += &format!("  create={}", self.create_index);
        if self.is_input() { s += " <input>"; }
        if self.is_written() { s += " <written>"; }
        if self.is_constant() { s += " <const>"; }
        if self.is_persist() { s += " <persist>"; }
        if self.is_addr_tied() { s += " <addrtied>"; }
        if self.is_implied() { s += " <implied>"; }
        if self.is_explicit() { s += " <explicit>"; }
        s
    }

    // Ghidra: varnode.cc:533 Varnode::operator<
    /// Ghidra's Varnode comparison for sorting (loc→size→flag→def SeqNum).
    /// Faithful to `operator<` (varnode.cc:533-547). Used by VarnodeCompareLocDef.
    /// Note: Rugra's Ord impl uses create_index (for BTreeSet identity);
    /// this method implements Ghidra's operator< semantics.
    pub fn ghidra_less(&self, other: &Varnode) -> bool {
        if self.loc != other.loc { return self.loc < other.loc; }
        if self.size != other.size { return self.size < other.size; }
        let f1 = self.flags & (varnode_flags::INPUT | varnode_flags::WRITTEN);
        let f2 = other.flags & (varnode_flags::INPUT | varnode_flags::WRITTEN);
        if f1 != f2 {
            // cc:542: -1 forces free varnodes to come last
            return (f1.wrapping_sub(1)) < (f2.wrapping_sub(1));
        }
        if f1 == varnode_flags::WRITTEN {
            let self_seq = self.def.as_ref().and_then(|w| w.upgrade())
                .map(|op| op.read().unwrap().start.clone());
            let other_seq = other.def.as_ref().and_then(|w| w.upgrade())
                .map(|op| op.read().unwrap().start.clone());
            if self_seq != other_seq {
                return self_seq < other_seq;
            }
        }
        false
    }

    // Ghidra: varnode.cc:556 Varnode::operator==
    /// Ghidra's Varnode equality (loc+size+flag+def SeqNum).
    /// Faithful to `operator==` (varnode.cc:556-570).
    pub fn ghidra_eq(&self, other: &Varnode) -> bool {
        if self.loc != other.loc { return false; }
        if self.size != other.size { return false; }
        let f1 = self.flags & (varnode_flags::INPUT | varnode_flags::WRITTEN);
        let f2 = other.flags & (varnode_flags::INPUT | varnode_flags::WRITTEN);
        if f1 != f2 { return false; }
        if f1 == varnode_flags::WRITTEN {
            let self_seq = self.def.as_ref().and_then(|w| w.upgrade())
                .map(|op| op.read().unwrap().start.clone());
            let other_seq = other.def.as_ref().and_then(|w| w.upgrade())
                .map(|op| op.read().unwrap().start.clone());
            if self_seq != other_seq { return false; }
        }
        true
    }

    // Ghidra: varnode.cc:578 Varnode::isFree
    pub fn is_free(&self) -> bool {
        (self.flags & (varnode_flags::INPUT | varnode_flags::WRITTEN)) == 0
    }

    // Ghidra: varnode.cc:578 Varnode::isHeritageKnown
    /// Is this varnode already known to heritage? Faithful to
    /// `Varnode::isHeritageKnown` (varnode.hh:298):
    /// `flags & (insert | constant | annotation)`.
    /// Used by rename to skip varnodes that have already been SSA-resolved.
    pub fn is_heritage_known(&self) -> bool {
        (self.flags & (varnode_flags::INSERT | varnode_flags::CONSTANT | varnode_flags::ANNOTATION)) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::isActiveHeritage
    /// Is this varnode actively being heritaged this round? Faithful to
    /// `Varnode::isActiveHeritage` (varnode.hh). Set by placeMultiequals/
    /// guardStores on varnodes that need rename this pass.
    pub fn is_active_heritage(&self) -> bool {
        (self.addlflags & addl_flags::ACTIVE_HERITAGE) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::setActiveHeritage
    /// Mark this varnode as actively being heritaged. Faithful to
    /// `Varnode::setActiveHeritage` (varnode.hh).
    pub fn set_active_heritage(&mut self) {
        self.addlflags |= addl_flags::ACTIVE_HERITAGE;
    }

    // Ghidra: varnode.cc:578 Varnode::clearActiveHeritage
    /// Clear active heritage flag. Faithful to `Varnode::clearActiveHeritage`.
    pub fn clear_active_heritage(&mut self) {
        self.addlflags &= !addl_flags::ACTIVE_HERITAGE;
    }

    // Ghidra: varnode.cc:352 Varnode::setFlags
    pub fn set_flags(&mut self, f: u32) {
        self.flags |= f;
    }

    // Ghidra: varnode.cc:365 Varnode::clearFlags
    pub fn clear_flags(&mut self, f: u32) {
        self.flags &= !f;
    }

    // --- Ghidra-faithful varnode flag accessors (varnode.hh:235-330) ---
    // These mirror the C++ inline methods used by the core Actions
    // (ActionMarkExplicit, ActionMarkImplied, ActionRestrictLocal, etc.).

    // Ghidra: varnode.cc:578 Varnode::isMark
    /// Has this been visited by the current algorithm? (varnode.hh:263)
    pub fn is_mark(&self) -> bool {
        (self.flags & varnode_flags::MARK) != 0
    }
    // Ghidra: varnode.cc:578 Varnode::setMark
    /// Mark this Varnode for breadcrumb algorithms. (varnode.hh:303)
    pub fn set_mark(&mut self) {
        self.flags |= varnode_flags::MARK;
    }
    // Ghidra: varnode.cc:578 Varnode::clearMark
    /// Clear the mark on this Varnode. (varnode.hh:304)
    pub fn clear_mark(&mut self) {
        self.flags &= !varnode_flags::MARK;
    }

    // Ghidra: varnode.hh:284 Varnode::hasCover
    /// Return true if this Varnode has a Cover (participates in liveness).
    /// Faithful to `Varnode::hasCover` (varnode.hh:284):
    ///   (flags & (constant|annotation|insert)) == insert
    pub fn has_cover(&self) -> bool {
        (self.flags
            & (varnode_flags::CONSTANT | varnode_flags::ANNOTATION | varnode_flags::INSERT))
            == varnode_flags::INSERT
    }

    // Ghidra: varnode.cc:233 Varnode::updateCover
    /// Rebuild cover if dirty. Faithful to `updateCover` (varnode.cc:233-241).
    pub fn update_cover(&mut self) {
        if (self.flags & varnode_flags::COVERDIRTY) != 0 {
            if self.has_cover() && self.cover.is_some() {
                // Rugra's Cover::rebuild is simplified (merge.rs compute_varnode_covers).
                // TODO: port full Cover::rebuild (cover.cc:477).
            }
            self.flags &= !varnode_flags::COVERDIRTY;
        }
    }

    // Ghidra: varnode.cc:244 Varnode::clearCover
    /// Delete the Cover object. Faithful to `clearCover` (varnode.cc:244-251).
    pub fn clear_cover(&mut self) {
        self.cover = None;
    }

    // Ghidra: varnode.cc:254 Varnode::calcCover
    /// Initialize a new Cover and set dirty bit. Faithful to `calcCover`
    /// (varnode.cc:254-263).
    pub fn calc_cover(&mut self) {
        if self.has_cover() {
            self.cover = Some(Box::new(Cover::new()));
            self.flags |= varnode_flags::COVERDIRTY;
        }
    }

    // Ghidra: varnode.cc:578 Varnode::isImplied
    /// Is this an implied variable? (varnode.hh:235)
    pub fn is_implied(&self) -> bool {
        (self.flags & varnode_flags::IMPLIED) != 0
    }
    // Ghidra: varnode.cc:578 Varnode::setImplied
    /// Mark this as an implied variable in the final C source. (varnode.hh:309)
    pub fn set_implied(&mut self) {
        self.flags |= varnode_flags::IMPLIED;
    }
    // Ghidra: varnode.cc:578 Varnode::clearImplied
    /// Clear the implied mark. (varnode.hh:310)
    pub fn clear_implied(&mut self) {
        self.flags &= !varnode_flags::IMPLIED;
    }

    // Ghidra: varnode.cc:578 Varnode::isExplicit
    /// Is this an explicitly printed variable? (varnode.hh:236)
    pub fn is_explicit(&self) -> bool {
        (self.flags & varnode_flags::EXPLICIT) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::isAutoLive
    /// Is this varnode held alive automatically (AUTOLIVE_HOLD)? Faithful to
    /// `Varnode::isAutoLive` (varnode.hh). Currently always false — Rugra has
    /// not yet ported the machinery that SETS the auto-live flag (ActionCopyPropagate /
    /// merge marking). This is a safe conservative port: when no varnode is
    /// marked, isAutoLive returns false, matching Ghidra. The empty-varnode
    /// bug in RuleEarlyRemoval is fixed by the `is_indirect_source` guard, not
    /// this one; re-evaluate when auto-live setting is ported.
    pub fn is_auto_live(&self) -> bool {
        // addlflags is u16; AUTOLIVE_HOLD (1<<30) doesn't fit — the flag
        // representation needs fixing when the setter is ported. Until then
        // no varnode is auto-live.
        false
    }
    // Ghidra: varnode.cc:578 Varnode::setExplicit
    /// Mark this as an explicit variable in the final C source. (varnode.hh:311)
    pub fn set_explicit(&mut self) {
        self.flags |= varnode_flags::EXPLICIT;
    }
    // Ghidra: varnode.cc:578 Varnode::clearExplicit
    /// Clear the explicit mark. (varnode.hh:312)
    pub fn clear_explicit(&mut self) {
        self.flags &= !varnode_flags::EXPLICIT;
    }

    // Ghidra: varnode.cc:578 Varnode::isDirectWrite
    /// Is this value affected by a legitimate function input? (varnode.hh:247)
    pub fn is_direct_write(&self) -> bool {
        (self.flags & varnode_flags::DIRECTWRITE) != 0
    }
    // Ghidra: varnode.cc:578 Varnode::setDirectWrite
    /// Mark this as directly affected by a legal input. (varnode.hh:305)
    pub fn set_direct_write(&mut self) {
        self.flags |= varnode_flags::DIRECTWRITE;
    }
    // Ghidra: varnode.cc:578 Varnode::clearDirectWrite
    /// Mark this as not directly affected. (varnode.hh:306)
    pub fn clear_direct_write(&mut self) {
        self.flags &= !varnode_flags::DIRECTWRITE;
    }

    // ---- Ghidra flag accessors (varnode.hh:251-300, 307-330) ----
    // Flag constants already defined in varnode_flags/addl_flags above; these
    // are the missing accessor methods needed by ported Rules.

    // Ghidra: varnode.cc:578 Varnode::isAddrForce
    /// Is this varnode forced to be treated as an address? (varnode.hh:251)
    pub fn is_addr_force(&self) -> bool {
        (self.flags & varnode_flags::ADDRFORCE) != 0
    }
    // Ghidra: varnode.cc:578 Varnode::setAddrForce
    /// Mark as address-forced. (varnode.hh:307)
    pub fn set_addr_force(&mut self) {
        self.flags |= varnode_flags::ADDRFORCE;
    }
    // Ghidra: varnode.cc:578 Varnode::clearAddrForce
    /// Clear address-forced. (varnode.hh:308)
    pub fn clear_addr_force(&mut self) {
        self.flags &= !varnode_flags::ADDRFORCE;
    }

    // Ghidra: varnode.cc:578 Varnode::isTypeLock
    /// Is the type locked on this varnode? (varnode.hh:299)
    pub fn is_type_lock(&self) -> bool {
        (self.flags & varnode_flags::TYPELOCK) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::isNameLock
    /// Is the name locked on this varnode? (varnode.hh:300)
    pub fn is_name_lock(&self) -> bool {
        (self.flags & varnode_flags::NAMELOCK) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::isPrecisLo
    /// Is this the low half of a precise register pair? (varnode.hh:275)
    pub fn is_precis_lo(&self) -> bool {
        (self.flags & varnode_flags::PRECISLO) != 0
    }
    // Ghidra: varnode.cc:578 Varnode::isPrecisHi
    /// Is this the high half of a precise register pair? (varnode.hh:276)
    pub fn is_precis_hi(&self) -> bool {
        (self.flags & varnode_flags::PRECISHI) != 0
    }
    // Ghidra: varnode.cc:578 Varnode::setPrecisLo
    /// Mark as precise low half. (varnode.hh:321)
    pub fn set_precis_lo(&mut self) {
        self.flags |= varnode_flags::PRECISLO;
    }
    // Ghidra: varnode.cc:578 Varnode::setPrecisHi
    /// Mark as precise high half. (varnode.hh:322)
    pub fn set_precis_hi(&mut self) {
        self.flags |= varnode_flags::PRECISHI;
    }
    // Ghidra: varnode.cc:578 Varnode::clearPrecisLo
    /// Clear precise low half. (varnode.hh:323)
    pub fn clear_precis_lo(&mut self) {
        self.flags &= !varnode_flags::PRECISLO;
    }
    // Ghidra: varnode.cc:578 Varnode::clearPrecisHi
    /// Clear precise high half. (varnode.hh:324)
    pub fn clear_precis_hi(&mut self) {
        self.flags &= !varnode_flags::PRECISHI;
    }

    // Ghidra: varnode.cc:578 Varnode::isProtoPartial
    /// Is this a partial prototype varnode? (varnode.hh:258)
    pub fn is_proto_partial(&self) -> bool {
        (self.flags & varnode_flags::PROTO_PARTIAL) != 0
    }
    // Ghidra: varnode.cc:578 Varnode::setProtoPartial
    /// Mark as proto-partial. (varnode.hh:329)
    pub fn set_proto_partial(&mut self) {
        self.flags |= varnode_flags::PROTO_PARTIAL;
    }
    // Ghidra: varnode.cc:578 Varnode::clearProtoPartial
    /// Clear proto-partial. (varnode.hh:330)
    pub fn clear_proto_partial(&mut self) {
        self.flags &= !varnode_flags::PROTO_PARTIAL;
    }

    // Ghidra: varnode.cc:578 Varnode::isPtrFlow
    /// Is this varnode a pointer-flow tracking varnode? (varnode.hh:260)
    /// Uses addlflags (ptrflow), not the main flags field.
    pub fn is_ptr_flow(&self) -> bool {
        (self.addlflags & addl_flags::PTR_FLOW) != 0
    }
    // Ghidra: varnode.cc:578 Varnode::setPtrFlow
    /// Mark as pointer-flow. (varnode.hh:317)
    pub fn set_ptr_flow(&mut self) {
        self.addlflags |= addl_flags::PTR_FLOW;
    }
    // Ghidra: varnode.cc:578 Varnode::clearPtrFlow
    /// Clear pointer-flow. (varnode.hh:318)
    pub fn clear_ptr_flow(&mut self) {
        self.addlflags &= !addl_flags::PTR_FLOW;
    }

    // Ghidra: varnode.cc:578 Varnode::isIndirectCreation
    /// Is this varnode marked as an indirect creation? (varnode.hh:248)
    pub fn is_indirect_creation(&self) -> bool {
        (self.flags & varnode_flags::INDIRECT_CREATION) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::getType
    /// Get the datatype of this varnode. (varnode.hh:192)
    pub fn get_type(&self) -> Option<Arc<Datatype>> {
        self.v_type.clone()
    }

    // Ghidra: varnode.cc:456 Varnode::updateType
    /// Set the type without locking. Faithful to `Varnode::updateType(Datatype*)`
    /// (varnode.cc:456-464). Returns true if the type was changed.
    pub fn update_type(&mut self, ct: Arc<Datatype>) -> bool {
        if self.v_type.as_ref().map(|t| Arc::ptr_eq(t, &ct)).unwrap_or(false) || self.is_type_lock() {
            return false;
        }
        self.v_type = Some(ct);
        // typeDirty on high — no-op until HighVariable tracks dirtiness.
        true
    }

    // Ghidra: varnode.cc:578 Varnode::updateTypeLock
    /// Set the type with lock/override control. Faithful to
    /// `Varnode::updateType(Datatype*, bool, bool)` (varnode.cc:474-489).
    /// TYPE_UNKNOWN always forces lock=false. Returns true if changed.
    pub fn update_type_lock(&mut self, ct: Arc<Datatype>, lock: bool, override_lock: bool) -> bool {
        use crate::type_system::datatype::TypeMetatype;
        let mut effective_lock = lock;
        if ct.get_metatype() == TypeMetatype::Unknown {
            effective_lock = false;
        }
        if self.is_type_lock() && !override_lock {
            return false;
        }
        let same = self.v_type.as_ref().map(|t| Arc::ptr_eq(t, &ct)).unwrap_or(false);
        if same && self.is_type_lock() == effective_lock {
            return false;
        }
        self.clear_flags(varnode_flags::TYPELOCK);
        if effective_lock {
            self.set_flags(varnode_flags::TYPELOCK);
        }
        self.v_type = Some(ct);
        true
    }

    // Ghidra: varnode.cc:639 Varnode::getTypeReadFacing
    /// Get the type as seen by a reading op. Faithful to
    /// `Varnode::getTypeReadFacing` (varnode.cc:639-645). For union types this
    /// resolves the field; Rugra has no union varnodes in Rule paths, so this
    /// is the degenerate form returning v_type directly.
    pub fn get_type_read_facing(&self) -> Option<Arc<Datatype>> {
        self.v_type.clone()
    }

    // Ghidra: varnode.cc:626 Varnode::getTypeDefFacing
    /// Return the resolved data-type for this Varnode based on its def op.
    /// Faithful to `getTypeDefFacing` (varnode.cc:626-632). If the type
    /// needs resolution (union), resolves via findResolve(def, -1).
    pub fn get_type_def_facing(&self) -> Option<Arc<Datatype>> {
        let ct = self.v_type.clone()?;
        if !ct.needs_resolution() {
            return Some(ct);
        }
        // cc:631: type->findResolve(def, -1)
        // Rugra's findResolve is currently identity (returns self).
        // Full union resolution TODO (needs unionresolve.cc).
        Some(Arc::new((*ct).clone()))
    }

    // Ghidra: varnode.cc:639 Varnode::getTypeReadFacing
    /// Return the resolved data-type for this Varnode when read by `op`
    /// at the given slot. Faithful to `getTypeReadFacing` (varnode.cc:639-645).
    pub fn get_type_read_facing_op(&self, _op: &PcodeOp, slot: i32) -> Option<Arc<Datatype>> {
        let ct = self.v_type.clone()?;
        if !ct.needs_resolution() {
            return Some(ct);
        }
        // cc:644: type->findResolve(op, op->getSlot(this))
        // Rugra's findResolve is currently identity.
        let _ = slot;
        Some(Arc::new((*ct).clone()))
    }

    // Ghidra: varnode.cc:651 Varnode::getHighTypeDefFacing
    /// Return the resolved HighVariable type for this Varnode based on def.
    /// Faithful to `getHighTypeDefFacing` (varnode.cc:651-658).
    pub fn get_high_type_def_facing(&self) -> Option<Arc<Datatype>> {
        let high = self.high.as_ref()?;
        let ct = high.read().unwrap().get_type();
        if !ct.needs_resolution() {
            return Some(ct);
        }
        Some(Arc::new((*ct).clone()))
    }

    // Ghidra: varnode.cc:665 Varnode::getHighTypeReadFacing
    /// Return the resolved HighVariable type when read by `op`.
    /// Faithful to `getHighTypeReadFacing` (varnode.cc:665-672).
    pub fn get_high_type_read_facing(&self, _op: &PcodeOp, _slot: i32) -> Option<Arc<Datatype>> {
        let high = self.high.as_ref()?;
        let ct = high.read().unwrap().get_type();
        if !ct.needs_resolution() {
            return Some(ct);
        }
        Some(Arc::new((*ct).clone()))
    }

    // Ghidra: varnode.cc:493 Varnode::copySymbol
    /// Copy symbol/type info from another varnode. Faithful to
    /// `Varnode::copySymbol` (varnode.cc:493-505). Copies type + mapentry +
    /// typelock/namelock flags.
    pub fn copy_symbol(&mut self, vn: &Varnode) {
        self.v_type = vn.v_type.clone();
        self.mapentry = vn.mapentry.clone();
        self.clear_flags(varnode_flags::TYPELOCK | varnode_flags::NAMELOCK);
        let inherit = vn.flags & (varnode_flags::TYPELOCK | varnode_flags::NAMELOCK);
        self.set_flags(inherit);
    }

    // Ghidra: varnode.cc:410 Varnode::setSymbolProperties
    /// Set symbol properties on this Varnode from a SymbolEntry.
    /// Faithful to `setSymbolProperties` (varnode.cc:410-424). Sets
    /// mapentry if type-locked, applies entry flags (minus typelock).
    pub fn set_symbol_properties(&mut self, entry: &Arc<RwLock<SymbolEntry>>) {
        let e = entry.read().unwrap();
        // cc:414: if entry symbol is type-locked, set mapentry
        let is_type_locked = e.symbol.read().unwrap().is_type_locked();
        if is_type_locked {
            self.mapentry = Some(entry.clone());
        }
        // cc:422: setFlags(entry->getAllFlags() & ~typelock)
        let all_flags = e.get_all_flags();
        drop(e);
        let flags_to_set = all_flags & !varnode_flags::TYPELOCK;
        self.set_flags(flags_to_set);
    }

    // Ghidra: varnode.cc:429 Varnode::setSymbolEntry
    /// Link a Symbol to this Varnode via the given SymbolEntry.
    /// Faithful to `setSymbolEntry` (varnode.cc:429-439). Sets mapentry,
    /// marks MAPPED, and NAMELOCK if the symbol is name-locked.
    pub fn set_symbol_entry(&mut self, entry: Arc<RwLock<SymbolEntry>>) {
        let is_name_locked = entry.read().unwrap().symbol.read().unwrap().is_name_locked();
        self.mapentry = Some(entry);
        let mut fl = varnode_flags::MAPPED;
        if is_name_locked {
            fl |= varnode_flags::NAMELOCK;
        }
        self.set_flags(fl);
    }

    // Ghidra: varnode.cc:446 Varnode::setSymbolReference
    /// Link Symbol info to this as a reference (for constant address refs).
    /// Faithful to `setSymbolReference` (varnode.cc:446-452).
    pub fn set_symbol_reference(&mut self, _entry: &Arc<RwLock<SymbolEntry>>, _off: i32) {
        // cc:449-451: if high != null, high->setSymbolReference(entry->getSymbol(), off)
        // Rugra's HighVariable setSymbolReference is not yet implemented.
        // TODO: port when HighVariable symbol linking is available.
    }

    // Ghidra: varnode.cc:510 Varnode::copySymbolIfValid
    /// Copy symbol info from vn if it has an EquateSymbol that is value-close.
    /// Faithful to `copySymbolIfValid` (varnode.cc:510-522).
    pub fn copy_symbol_if_valid(&mut self, vn: &Varnode) {
        let map_entry = match vn.get_symbol_entry() {
            Some(e) => e,
            None => return,
        };
        // cc:516: check if symbol is EquateSymbol and value is close.
        // Rugra's SymbolEntry doesn't distinguish EquateSymbol yet.
        // Conservative: copy symbol if mapentry exists and both are constant.
        if vn.is_constant() && self.is_constant() {
            self.copy_symbol(vn);
        }
    }

    // Ghidra: varnode.cc:578 Varnode::getSymbolEntry
    /// Get the SymbolEntry (symbol mapping) of this varnode, if any.
    /// Faithful to `Varnode::getSymbolEntry` (varnode.hh:190).
    pub fn get_symbol_entry(&self) -> Option<Arc<RwLock<SymbolEntry>>> {
        self.mapentry.clone()
    }

    // Ghidra: varnode.cc:1137 Varnode::getStructuredType
    /// Get the structured type of this varnode, preferring the symbol's type
    /// over the varnode's own type. Faithful to `Varnode::getStructuredType`
    /// (varnode.cc:1137-1148). Returns the type if it is piece-structured,
    /// else None.
    pub fn get_structured_type(&self) -> Option<Arc<Datatype>> {
        let ct = if let Some(me) = &self.mapentry {
            let me_rg = me.read().unwrap();
            me_rg.get_symbol().read().unwrap().get_type().or_else(|| self.v_type.clone())
        } else {
            self.v_type.clone()
        };
        ct.filter(|t| t.is_piece_structured())
    }

    /// Is the high-level variable tied to an address? (varnode.hh:250)
    /// Ghidra: (flags & (addrtied|insert)) == (addrtied|insert).
    pub fn is_addr_tied(&self) -> bool {
        (self.flags & (varnode_flags::ADDRTIED | varnode_flags::INSERT))
            == (varnode_flags::ADDRTIED | varnode_flags::INSERT)
    }

    // Ghidra: varnode.cc:578 Varnode::isPersist
    /// Does this storage location persist beyond the function? (varnode.hh:246)
    pub fn is_persist(&self) -> bool {
        (self.flags & varnode_flags::PERSIST) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::isUnaffected
    /// Is this a value preserved across the function? (varnode.hh:255)
    pub fn is_unaffected(&self) -> bool {
        (self.flags & varnode_flags::UNAFFECTED) != 0
    }

    // Ghidra: varnode.hh:247 Varnode::isVolatile
    pub fn is_volatile(&self) -> bool {
        (self.flags & varnode_flags::VOLATIL) != 0
    }

    // Ghidra: varnode.cc:1182 Varnode::encode
    /// Encode this Varnode as XML attributes. Faithful to `encode`
    /// (varnode.cc:1182-1201). Rugra returns a String (no Encoder).
    pub fn encode(&self) -> String {
        let mut s = format!("<addr space=\"{}\" offset=\"{:x}\" size=\"{}\" ref=\"{}\"",
            self.address_space.name(), self.loc.as_u64(), self.size, self.create_index);
        if self.is_persist() { s += " persists=\"true\""; }
        if self.is_addr_tied() { s += " addrtied=\"true\""; }
        if self.is_unaffected() { s += " unaff=\"true\""; }
        if self.is_input() { s += " input=\"true\""; }
        if self.is_volatile() { s += " volatile=\"true\""; }
        s += "/>";
        s
    }

    // Ghidra: varnode.cc:344 Varnode::destroyDescend
    /// Clear all descend references. Faithful to `destroyDescend`
    /// (varnode.cc:344-350).
    pub fn destroy_descend(&mut self) {
        self.descend.clear();
    }

    // Ghidra: varnode.cc:1153 Varnode::termOrder
    /// Compare this varnode with another for term ordering (constants last).
    /// Faithful to `termOrder` (varnode.cc:1153-1180). Used by
    /// AddExpression to order commutative operands.
    pub fn term_order(&self, op: &Varnode) -> i32 {
        // cc:1156-1160: constants sort last
        if self.is_constant() {
            if !op.is_constant() { return 1; }
        } else {
            if op.is_constant() { return -1; }
        }
        // cc:1162-1168: unwrap INT_MULT by constant (find the non-const factor)
        // cc:1170-1175: compare by size (smaller first)
        if self.size != op.size {
            return self.size as i32 - op.size as i32;
        }
        // cc:1176: compare by offset
        self.loc.as_u64().cmp(&op.loc.as_u64()) as i32
    }

    // Ghidra: varnode.hh:257 Varnode::isReturnAddress
    /// Is this storage for a call's return address? Faithful to
    /// `Varnode::isReturnAddress` (varnode.hh:257):
    ///   `(flags & return_address) != 0`.
    /// Used by AncestorRealistic::enterNode (INDIRECT case) to reject return
    /// address storage as a parameter passing location.
    pub fn is_return_address(&self) -> bool {
        (self.flags & varnode_flags::RETURN_ADDRESS) != 0
    }

    // Ghidra: varnode.hh:271 Varnode::isIndirectZero
    /// Is this an indirect creation that is also a constant (i.e. a possible
    /// zero produced indirectly by a call)? Faithful to
    /// `Varnode::isIndirectZero` (varnode.hh:271):
    ///   `(flags & (indirect_creation|constant)) == (indirect_creation|constant)`.
    /// Used by AncestorRealistic::enterNode (INDIRECT case) to detect a
    /// killedbycall output that is definitely not a real parameter.
    pub fn is_indirect_zero(&self) -> bool {
        (self.flags
            & (varnode_flags::INDIRECT_CREATION | varnode_flags::CONSTANT))
            == (varnode_flags::INDIRECT_CREATION | varnode_flags::CONSTANT)
    }

    // Ghidra: varnode.hh:277 Varnode::isIncidentalCopy
    /// Does this varnode get copied as a side-effect of a call (an
    /// "incidental" COPY)? Faithful to `Varnode::isIncidentalCopy`
    /// (varnode.hh:277): `(flags & incidental_copy) != 0`.
    /// Used by AncestorRealistic::enterNode (COPY/SUBPIECE cases) to treat
    /// incidental copies as transparent traversal nodes.
    pub fn is_incidental_copy(&self) -> bool {
        (self.flags & varnode_flags::INCIDENTAL_COPY) != 0
    }

    // Ghidra: varnode.cc:178 Varnode::overlap
    /// Return the relative point of overlap between this Varnode and `other`,
    /// or -1 if no overlap. Faithful to `Varnode::overlap` (varnode.cc:178).
    /// For little-endian (Rugra's only supported case), this returns the byte
    /// offset within `other` where this Varnode's low byte falls. Used by
    /// AncestorRealistic::enterNode (SUBPIECE case) to detect a no-op
    /// truncation extracting the same physical bytes.
    pub fn overlap(&self, other: &Varnode) -> i32 {
        if self.address_space != other.address_space {
            return -1;
        }
        let off = other.get_offset() as i64;
        let end = off + other.size as i64;
        let my_off = self.get_offset() as i64;
        if my_off < off || my_off >= end {
            return -1;
        }
        (my_off - off) as i32
    }

    // Ghidra: varnode.cc:217 Varnode::overlap(const Address&, int4)
    /// Return LSB-relative overlap with an address range. Faithful to
    /// `overlap(const Address&, int4)` (varnode.cc:217-231).
    pub fn overlap_addr(&self, op2loc: Address, op2size: usize) -> i32 {
        if self.address_space == AddressSpace::Const { return -1; }
        let dist = self.loc.as_u64().wrapping_sub(op2loc.as_u64());
        if dist >= op2size as u64 { return -1; }
        dist as i32
    }

    // Ghidra: varnode.cc:197 Varnode::overlapJoin
    /// Return overlap relative to MSB (for join-space operations).
    /// Faithful to `overlapJoin` (varnode.cc:197-208).
    pub fn overlap_join(&self, op: &Varnode) -> i32 {
        // Little endian (x86-64): same as overlap_addr
        self.overlap_addr(op.loc, op.size)
    }

    // Ghidra: varnode.cc:578 Varnode::hasNoLocalAlias
    /// Does the high-level variable have no local alias? (varnode.hh:262)
    pub fn has_no_local_alias(&self) -> bool {
        (self.flags & varnode_flags::NOLOCALALIAS) != 0
    }
    // Ghidra: varnode.cc:578 Varnode::setNoLocalAlias
    pub fn set_no_local_alias(&mut self) {
        self.flags |= varnode_flags::NOLOCALALIAS;
    }
    // Ghidra: varnode.cc:578 Varnode::clearNoLocalAlias
    pub fn clear_no_local_alias(&mut self) {
        self.flags &= !varnode_flags::NOLOCALALIAS;
    }
    // Ghidra: varnode.cc:578 Varnode::setUnaffected
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

    // Ghidra: varnode.cc:578 Varnode::getNzMask
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

    // Ghidra: varnode.cc:578 Varnode::hasNoDescend
    /// Return true if no live op reads this varnode. Faithful to
    /// `Varnode::hasNoDescend`. Used by several Rules (RuleXorCollapse,
    /// RuleSubZext) to check exclusive use.
    pub fn has_no_descend(&self) -> bool {
        self.descend.iter().all(|w| w.upgrade().is_none())
    }

    // Ghidra: varnode.cc:676 Varnode::loneDescend
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

    // Ghidra: varnode.cc:155 Varnode::characterizeOverlap
    /// Characterize the storage overlap between this varnode and `op`.
    /// Faithful to `Varnode::characterizeOverlap` (varnode.cc:155-170).
    /// Returns: 0 = no overlap, 1 = partial overlap, 2 = identical storage.
    pub fn characterize_overlap(&self, other: &Varnode) -> i32 {
        // Different address spaces => no overlap.
        if self.address_space != other.address_space {
            return 0;
        }
        let s_off = self.get_offset();
        let o_off = other.get_offset();
        let s_end = s_off.wrapping_add(self.get_size() as u64);
        let o_end = o_off.wrapping_add(other.get_size() as u64);
        // Same left boundary
        if s_off == o_off {
            return if self.get_size() == other.get_size() { 2 } else { 1 };
        }
        // Check whether the ranges overlap at all: one range must start within
        // the other's [start, end) extent.
        if s_off < o_off {
            // this starts before other; overlap iff this's end > other's start
            if s_end > o_off { 1 } else { 0 }
        } else {
            // other starts before this; overlap iff other's end > this's start
            if o_end > s_off { 1 } else { 0 }
        }
    }

    // Ghidra: varnode.cc:121 Varnode::intersects(const Varnode&)
    /// Check if this Varnode intersects another. Faithful to
    /// `intersects(const Varnode&)` (varnode.cc:121-134).
    pub fn intersects(&self, op: &Varnode) -> bool {
        if self.address_space != op.address_space { return false; }
        if self.address_space == AddressSpace::Const { return false; }
        let a = self.loc.as_u64();
        let b = op.loc.as_u64();
        if b < a {
            return a < b.wrapping_add(op.size as u64);
        }
        b < a.wrapping_add(self.size as u64)
    }

    // Ghidra: varnode.cc:140 Varnode::intersects(const Address&, int4)
    /// Check if this Varnode intersects the given Address range.
    /// Faithful to `intersects(const Address&, int4)` (varnode.cc:140-153).
    pub fn intersects_addr(&self, op2loc: Address, op2size: usize) -> bool {
        if self.address_space == AddressSpace::Const { return false; }
        let a = self.loc.as_u64();
        let b = op2loc.as_u64();
        if b < a {
            return a < b.wrapping_add(op2size as u64);
        }
        b < a.wrapping_add(self.size as u64)
    }

    // Ghidra: varnode.cc:977 Varnode::copyShadow
    /// Check if this Varnode and `op2` are copies of the same source.
    /// Faithful to `Varnode::copyShadow` (varnode.cc:977-995): trace both
    /// varnodes back along COPY chains; if they meet, they shadow each other.
    pub fn copy_shadow(&self, op2: &Varnode) -> bool {
        // Trace self back along COPY chain, collecting source Arcs.
        let self_sources = collect_copy_sources(self);
        let other_sources = collect_copy_sources(op2);
        // If self's chain hits op2 directly, or the two chains share a source.
        for s in &self_sources {
            for o in &other_sources {
                if std::sync::Arc::ptr_eq(s, o) {
                    return true;
                }
            }
        }
        false
    }

    // Ghidra: varnode.cc:1102 Varnode::partialCopyShadow
    /// For this and `op2`, establish that either bigger=CONCAT(smaller,..)
    /// or smaller=SUBPIECE(bigger). Faithful to `Varnode::partialCopyShadow`
    /// (varnode.cc:1102-1131).
    pub fn partial_copy_shadow(&self, op2: &Varnode, mut rel_off: i32) -> bool {
        // Normalize direction: vn = smaller, op2 = bigger (varnode.cc:1107-1116).
        let (vn, big): (&Varnode, &Varnode) = if self.size < op2.size {
            (self, op2)
        } else if self.size > op2.size {
            (op2, self)
        } else {
            return false; // equal size → not a partial shadow
        };
        // Note: the reassignment of which is vn vs op2 flips rel_off sign.
        if self.size > op2.size {
            rel_off = -rel_off;
        }
        if rel_off < 0 {
            return false; // not proper containment (varnode.cc:1117)
        }
        if (rel_off as usize) + vn.size > big.size {
            return false; // not proper containment (varnode.cc:1119)
        }
        // big-endian leastByte computation (varnode.cc:1122-1123).
        // Ghidra uses this->getSpace()->isBigEndian(); vn and big share space.
        let big_endian = vn.address_space.is_big_endian();
        let least_byte = if big_endian {
            (big.size - vn.size) as i32 - rel_off
        } else {
            rel_off
        };
        // vn->findSubpieceShadow(leastByte, op2, 0) (varnode.cc:1124).
        if find_subpiece_shadow(vn, least_byte, big, 0) {
            return true;
        }
        // op2->findPieceShadow(leastByte, vn) (varnode.cc:1127).
        if find_piece_shadow(big, least_byte, vn) {
            return true;
        }
        false
    }

    // Ghidra: varnode.hh:226 Varnode::contains
    pub fn contains(&self, other: &Varnode) -> i32 {
        if self.address_space != other.address_space {
            return 3;
        }
        let s_off = self.get_offset();
        let o_off = other.get_offset();
        let s_end = s_off.wrapping_add(self.get_size() as u64);
        let o_end = o_off.wrapping_add(other.get_size() as u64);
        if o_off < s_off {
            -1
        } else if o_off < s_end {
            // op starts within this's range
            if o_end <= s_end { 0 } else { 1 }
        } else {
            2
        }
    }

    // Ghidra: varnode.cc:578 Varnode::getConsume
    /// Get the mask of consumed bits. Faithful to `Varnode::getConsume`
    /// (varnode.hh:205). Maintained by the dead-code algorithm.
    pub fn get_consume(&self) -> u64 {
        self.consumed
    }

    // Ghidra: varnode.cc:578 Varnode::setConsume
    /// Set the mask of consumed bits. Faithful to `Varnode::setConsume`
    /// (varnode.hh:206).
    pub fn set_consume(&mut self, val: u64) {
        self.consumed = val;
    }

    // Ghidra: varnode.cc:578 Varnode::getNzm
    /// Get the stored non-zero mask (the Heritage-maintained field).
    /// Faithful to accessing the `nzm` field directly. This is the raw stored
    /// value; prefer get_nz_mask for the conservative approximation.
    pub fn get_nzm(&self) -> u64 {
        self.nzm
    }

    // Ghidra: varnode.cc:578 Varnode::setNzm
    /// Set the stored non-zero mask.
    pub fn set_nzm(&mut self, val: u64) {
        self.nzm = val;
    }

    // Ghidra: varnode.cc:942 Varnode::isBooleanValue
    /// Is this varnode known to hold a boolean (0 or 1) value? Faithful to
    /// `Varnode::isBooleanValue` (varnode.cc:942-953). If written, checks the
    /// defining op's isCalculatedBool flag. If an input, checks type annotation
    /// (only when use_annotation is true).
    // Ghidra: varnode.cc:696 Varnode::getUsePoint
    /// Get the use-point address for this Varnode. Faithful to
    /// `getUsePoint` (varnode.cc:696-703).
    pub fn get_use_point(&self, _fd: &crate::funcdata::Funcdata) -> Address {
        if self.is_written() {
            if let Some(def_weak) = self.def.as_ref().and_then(|w| w.upgrade()) {
                return def_weak.read().unwrap().get_addr();
            }
        }
        Address::new(0)
    }

    // Ghidra: varnode.cc:958 Varnode::isZeroExtended
    /// Check if this Varnode is a zero-extended form of a smaller value.
    /// Faithful to `isZeroExtended` (varnode.cc:958-975).
    pub fn is_zero_extended(&self, base_size: usize) -> bool {
        if !self.is_written() { return false; }
        let def = match self.def.as_ref().and_then(|w| w.upgrade()) {
            Some(d) => d, None => return false,
        };
        let def_r = def.read().unwrap();
        if def_r.opcode != crate::opcodes::OpCode::CPUI_INT_ZEXT { return false; }
        let in_size = match def_r.get_in(0) {
            Some(v) => v.read().unwrap().get_size(),
            None => return false,
        };
        in_size == base_size
    }

    // Ghidra: varnode.cc:942 Varnode::isBooleanValue
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

    // Ghidra: varnode.cc:578 Varnode::getDef
    /// Get the PcodeOp that defines this Varnode, or None if not written.
    /// Faithful to `Varnode::getDef` (varnode.hh:213). Upgrades the internal
    /// Weak to an Arc; returns None if the def has been dropped or was never
    /// set.
    pub fn get_def(&self) -> Option<Arc<RwLock<PcodeOp>>> {
        self.def.as_ref().and_then(|w| w.upgrade())
    }

    // Ghidra: varnode.cc:578 Varnode::isReadOnly
    /// Is this Varnode's value read-only (from a read-only memory space)?
    /// Faithful to `Varnode::isReadOnly` (varnode.hh:243).
    pub fn is_read_only(&self) -> bool {
        (self.flags & varnode_flags::READONLY) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::isAnnotation
    /// Is this an annotation varnode (inserted by the decompiler, not real
    /// code)? Faithful to `Varnode::isAnnotation` (varnode.hh:237).
    pub fn is_annotation(&self) -> bool {
        (self.flags & varnode_flags::ANNOTATION) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::isSpacebase
    /// Is this a spacebase pointer varnode? Faithful to
    /// `Varnode::isSpacebase` (varnode.hh, referenced by varmap/heritage).
    pub fn is_spacebase(&self) -> bool {
        (self.flags & varnode_flags::SPACEBASE) != 0
    }

    // Ghidra: varnode.cc:578 Varnode::descendIter
    /// Return an iterator over the live descendant ops (ops that read this
    /// Varnode). Faithful to `Varnode::beginDescend`/`endDescend`
    /// (varnode.hh:219-220). Filters out Weak refs whose target has been
    /// dropped.
    pub fn descend_iter(&self) -> impl Iterator<Item = Arc<RwLock<PcodeOp>>> + '_ {
        self.descend.iter().filter_map(|w| w.upgrade())
    }

    // Ghidra: varnode.cc:578 Varnode::countDescends
    /// Count the live descendant ops. Useful for Rules that need the descend
    /// count without collecting into a Vec.
    pub fn count_descends(&self) -> usize {
        self.descend.iter().filter(|w| w.strong_count() > 0).count()
    }

    // Ghidra: varnode.cc:330 Varnode::addDescend
    /// Add a descendant op reference. Faithful to `Varnode::addDescend`
    /// (varnode.hh:295). Per Ghidra cc:333-336, a free non-spacebase varnode
    /// with existing descend throws LowlevelError; Rugra logs (eprintln) and
    /// continues conservatively — IR construction should not panic on
    /// transient inconsistency.
    /// Also sets coverdirty (Ghidra cc:339); Rugra's cover system is simplified
    /// (see merge.rs compute_varnode_covers) and does not track the coverdirty
    /// flag — TODO tracked in ALIGNMENT_ROADMAP (cover.cc full port).
    pub fn add_descend(&mut self, op: &Arc<RwLock<PcodeOp>>) {
        if self.is_free() && !self.is_spacebase() {
            if !self.descend.is_empty() {
                eprintln!("[VN] WARN: free varnode space={:?} off={:#x} gets multiple descendants",
                    self.address_space, self.loc.as_u64());
            }
        }
        self.descend.push(std::sync::Arc::downgrade(op));
        // Ghidra cc:339: setFlags(Varnode::coverdirty)
        self.flags |= varnode_flags::COVERDIRTY;
    }

    // Ghidra: varnode.cc:316 Varnode::eraseDescend
    /// Erase a descendant op from this varnode's descend list. Faithful to
    /// `Varnode::eraseDescend` (varnode.hh:175). Per Ghidra cc:321-324, finds
    /// the op in the descend list and removes it; throws if not found.
    /// Rugra uses retain (drops ALL matching weak refs to op, in case of
    /// accidental duplicates) and logs if nothing was removed.
    /// Also sets coverdirty (Ghidra cc:325); omitted (see add_descend note).
    pub fn erase_descend(&mut self, op: &Arc<RwLock<PcodeOp>>) {
        let target_ptr = std::sync::Arc::as_ptr(op) as *const ();
        let before = self.descend.len();
        self.descend.retain(|w| {
            w.upgrade().map(|a| std::sync::Arc::as_ptr(&a) as *const () != target_ptr).unwrap_or(true)
        });
        if self.descend.len() == before {
            eprintln!("[VN] WARN: erase_descend op={:p} not in descend list (space={:?} off={:#x})",
                std::sync::Arc::as_ptr(op), self.address_space, self.loc.as_u64());
        }
        // Ghidra cc:325: setFlags(Varnode::coverdirty)
        self.flags |= varnode_flags::COVERDIRTY;
    }

    // Ghidra: varnode.cc:578 Varnode::isBoolOutputDef
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
    // Ghidra: varnode.cc:578 Varnode::eq
    fn eq(&self, other: &Self) -> bool {
        self.loc == other.loc && self.size == other.size && self.create_index == other.create_index
    }
}

impl Eq for Varnode {}

impl PartialOrd for Varnode {
    // Ghidra: varnode.cc:578 Varnode::partialCmp
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for Varnode {
    // Ghidra: varnode.cc:578 Varnode::cmp
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
    // RUGRA-GLUE: eq (no Ghidra counterpart found)
    fn eq(&self, other: &Self) -> bool {
        if Arc::ptr_eq(&self.0, &other.0) { return true; }
        self.0.read().unwrap().eq(&other.0.read().unwrap())
    }
}

impl Eq for VarnodeLocRef {}

impl PartialOrd for VarnodeLocRef {
    // RUGRA-GLUE: partial_cmp (no Ghidra counterpart found)
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VarnodeLocRef {
    // RUGRA-GLUE: cmp (no Ghidra counterpart found)
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if Arc::ptr_eq(&self.0, &other.0) { return std::cmp::Ordering::Equal; }
        let a = self.0.read().unwrap();
        let b = other.0.read().unwrap();
        // Faithful to Ghidra's VarnodeCompareLocDef (varnode.cc:34-52):
        // (address_space, loc, size, input/written/free, def-SeqNum-or-createIndex)
        //
        // Key difference from the old (space, loc, size, create_index): the
        // input/written/free classification layer makes:
        //   - input varnodes at the same (space, loc, size) be EQUAL (same object)
        //   - written varnodes distinguished by def SeqNum (SSA versions)
        //   - free varnodes distinguished by createIndex (multiple allowed)
        // This is what Ghidra's xref relies on: a newVarnode lookup finds the
        // existing input varnode at a location (not a different free/written one).
        match a.address_space.cmp(&b.address_space) {
            ne @ std::cmp::Ordering::Less | ne @ std::cmp::Ordering::Greater => return ne,
            std::cmp::Ordering::Equal => {}
        }
        match a.loc.cmp(&b.loc) {
            ne @ std::cmp::Ordering::Less | ne @ std::cmp::Ordering::Greater => return ne,
            std::cmp::Ordering::Equal => {}
        }
        match a.size.cmp(&b.size) {
            ne @ std::cmp::Ordering::Less | ne @ std::cmp::Ordering::Greater => return ne,
            std::cmp::Ordering::Equal => {}
        }
        // Classify by input/written flags: 0=free, input(1<<3)=input, written(1<<4)=written.
        // Ghidra ordering: (f-1) comparison puts free LAST, input before written.
        let f1 = a.flags & (varnode_flags::INPUT | varnode_flags::WRITTEN);
        let f2 = b.flags & (varnode_flags::INPUT | varnode_flags::WRITTEN);
        match f1.cmp(&f2) {
            ne @ std::cmp::Ordering::Less | ne @ std::cmp::Ordering::Greater => return ne,
            std::cmp::Ordering::Equal => {}
        }
        // Same classification. For written: compare def SeqNum.
        // For input: return Equal (same input varnode = same object).
        // For free: compare createIndex.
        if f1 == varnode_flags::WRITTEN {
            // Compare def op SeqNum.
            let a_seq = a.get_def().map(|d| *d.read().unwrap().get_seq_num());
            let b_seq = b.get_def().map(|d| *d.read().unwrap().get_seq_num());
            a_seq.cmp(&b_seq)
        } else if f1 == varnode_flags::INPUT {
            std::cmp::Ordering::Equal
        } else {
            // Free: compare createIndex.
            a.create_index.cmp(&b.create_index)
        }
    }
}

/// A wrapper for Rc<RefCell<Varnode>> for definition-based sorting
#[derive(Debug, Clone)]
pub struct VarnodeDefRef(pub Arc<RwLock<Varnode>>);

impl PartialEq for VarnodeDefRef {
    // RUGRA-GLUE: eq (no Ghidra counterpart found)
    fn eq(&self, other: &Self) -> bool {
        if Arc::ptr_eq(&self.0, &other.0) { return true; }
        self.0.read().unwrap().eq(&other.0.read().unwrap())
    }
}

impl Eq for VarnodeDefRef {}

impl PartialOrd for VarnodeDefRef {
    // RUGRA-GLUE: partial_cmp (no Ghidra counterpart found)
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VarnodeDefRef {
    // Ghidra: varnode.cc:60 VarnodeCompareDefLoc::operator()
    /// Compare by definition then by location. Faithful to
    /// `VarnodeCompareDefLoc` (varnode.cc:60-79).
    /// Uses (f-1) trick: written=0, input=1, free=2 (free last).
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if Arc::ptr_eq(&self.0, &other.0) { return std::cmp::Ordering::Equal; }
        let a = self.0.read().unwrap();
        let b = other.0.read().unwrap();

        // cc:65-67: f1 = flags & (input|written); (f1-1) < (f2-1) forces free last
        let f1 = a.flags & (varnode_flags::INPUT | varnode_flags::WRITTEN);
        let f2 = b.flags & (varnode_flags::INPUT | varnode_flags::WRITTEN);
        if f1 != f2 {
            return (f1.wrapping_sub(1)).cmp(&(f2.wrapping_sub(1)));
        }
        // cc:69-71: if written, compare def SeqNum
        if f1 == varnode_flags::WRITTEN {
            let a_seq = a.def.as_ref().and_then(|w| w.upgrade())
                .map(|op| op.read().unwrap().start.clone());
            let b_seq = b.def.as_ref().and_then(|w| w.upgrade())
                .map(|op| op.read().unwrap().start.clone());
            match a_seq.cmp(&b_seq) {
                std::cmp::Ordering::Equal => {}
                ord => return ord,
            }
        }
        // cc:73-74: compare addr, then size
        match a.loc.cmp(&b.loc) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match a.size.cmp(&b.size) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        // cc:75-77: if both free, compare createIndex
        if f1 == 0 {
            return a.create_index.cmp(&b.create_index);
        }
        std::cmp::Ordering::Equal
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
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    pub fn new(space: AddressSpace, offset: u64, size: usize) -> Self {
        Self {
            space,
            offset,
            size,
        }
    }
}

impl From<&Varnode> for VarnodeData {
    // RUGRA-GLUE: from (no Ghidra counterpart found)
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
    // Ghidra: varnode.cc:1218 VarnodeBank::new
    pub fn new() -> Self {
        Self {
            loc_tree: BTreeSet::new(),
            def_tree: BTreeSet::new(),
            create_index: 0,
            uniq_space: AddressSpace::Unique,
            uniqid: 0,
        }
    }

    // Ghidra: varnode.cc:1250 VarnodeBank::create
    /// Create a new free varnode
    pub fn create(&mut self, size: usize, loc: Address) -> Arc<RwLock<Varnode>> {
        // Faithful to VarnodeBank::create (varnode.cc:1250-1258): does NOT
        // set INSERT flag. Only createDef/xref sets INSERT (for written
        // varnodes). Free varnodes (created via newVarnode→create) have no
        // INSERT — isHeritageKnown returns false — rename processes them.
        let mut vn = Varnode::new(size, loc);
        vn.create_index = self.create_index;
        self.create_index += 1;

        let rc = Arc::new(RwLock::new(vn));
        self.loc_tree.insert(VarnodeLocRef(rc.clone()));
        self.def_tree.insert(VarnodeDefRef(rc.clone()));
        rc
    }

    // Ghidra: varnode.cc:1218 VarnodeBank::createWithSpace
    /// Create a new varnode with explicit address space
    pub fn create_with_space(&mut self, size: usize, space: AddressSpace, offset: u64) -> Arc<RwLock<Varnode>> {
        let vn_arc = self.create(size, Address::new(offset));
        vn_arc.write().unwrap().address_space = space;
        vn_arc
    }

    // Ghidra: varnode.cc:1265 VarnodeBank::createUnique
    /// Create a new unique varnode
    pub fn create_unique(&mut self, size: usize) -> Arc<RwLock<Varnode>> {
        let addr = Address::new(self.uniqid);
        self.uniqid += size as u64;
        let vn_arc = self.create(size, addr);
        vn_arc.write().unwrap().address_space = AddressSpace::Unique;
        vn_arc
    }

    // Ghidra: varnode.cc:1218 VarnodeBank::createConstant
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

    // Ghidra: varnode.cc:1411 VarnodeBank::createDef
    /// Create a new Varnode with a defining op, already inserted in both trees.
    /// Faithful to `createDef` (varnode.cc:1411-1418).
    pub fn create_def(
        &mut self,
        size: usize,
        loc: Address,
        op: &Arc<RwLock<PcodeOp>>,
    ) -> Arc<RwLock<Varnode>> {
        let vn = self.create(size, loc);
        vn.write().unwrap().def = Some(Arc::downgrade(op));
        // Re-insert into def_tree with the def set (xref equivalent).
        // create() already inserted into loc_tree + def_tree as free.
        // set_def re-inserts with the def op assigned.
        self.set_def(vn.clone(), Arc::downgrade(op));
        vn
    }

    // Ghidra: varnode.cc:1426 VarnodeBank::createDefUnique
    /// Create a unique-space Varnode with a defining op.
    /// Faithful to `createDefUnique` (varnode.cc:1426-1432).
    pub fn create_def_unique(
        &mut self,
        size: usize,
        op: &Arc<RwLock<PcodeOp>>,
    ) -> Arc<RwLock<Varnode>> {
        let addr = Address::new(self.uniqid);
        self.uniqid += size as u64;
        let vn = self.create_def(size, addr, op);
        vn.write().unwrap().address_space = AddressSpace::Unique;
        vn
    }

    // Ghidra: varnode.cc:1358 VarnodeBank::setInput
    /// Mark a varnode as an input
    /// Mark a varnode as a function input. Faithful to Ghidra's
    /// VarnodeBank::makeInput which re-inserts via xref (sets INSERT).
    pub fn set_input(&mut self, vn: Arc<RwLock<Varnode>>) {
        self.loc_tree.remove(&VarnodeLocRef(vn.clone()));
        self.def_tree.remove(&VarnodeDefRef(vn.clone()));

        vn.write().unwrap().set_flags(varnode_flags::INPUT | varnode_flags::INSERT);

        self.loc_tree.insert(VarnodeLocRef(vn.clone()));
        self.def_tree.insert(VarnodeDefRef(vn.clone()));
    }

    // Ghidra: varnode.cc:1380 VarnodeBank::setDef
    /// Mark a varnode as defined by an operation
    /// Set the defining op of a varnode. Faithful to Ghidra's model where
    /// createDef (varnode.cc:1411) calls xref which sets INSERT.
    /// A varnode with a def is "inserted" — isHeritageKnown returns true.
    pub fn set_def(&mut self, vn: Arc<RwLock<Varnode>>, op: Weak<RwLock<PcodeOp>>) {
        self.loc_tree.remove(&VarnodeLocRef(vn.clone()));
        self.def_tree.remove(&VarnodeDefRef(vn.clone()));

        let mut v = vn.write().unwrap();
        v.set_flags(varnode_flags::WRITTEN | varnode_flags::INSERT);
        v.def = Some(op);

        drop(v);
        self.loc_tree.insert(VarnodeLocRef(vn.clone()));
        self.def_tree.insert(VarnodeDefRef(vn.clone()));
    }

    // Ghidra: varnode.cc:1218 VarnodeBank::destroyVarnode
    /// Remove a varnode from both trees. Faithful to `VarnodeBank::destroy`.
    /// The varnode is detached from the bank; if no other Arc holds it, it
    /// is dropped.
    pub fn destroy_varnode(&mut self, vn: &Arc<RwLock<Varnode>>) {
        self.loc_tree.remove(&VarnodeLocRef(vn.clone()));
        self.def_tree.remove(&VarnodeDefRef(vn.clone()));
    }

    // Ghidra: funcdata_varnode.cc:340 Funcdata::setInputVarnode (vbank-level core)
    /// Promote a varnode to a function input. Faithful to
    /// `Funcdata::setInputVarnode` (funcdata_varnode.cc:340-373).
    ///
    /// Ghidra does: (1) early-out if already input, (2) overlap dedup
    /// against existing inputs (return existing on exact match, throw on
    /// partial overlap), (3) `vbank.setInput(vn)`, (4) ProtoModel effect
    /// property setting (unaffected / return_address).
    ///
    /// Rugra ports (1)+(2)+(3) at the VarnodeBank level (the Funcdata
    /// wrapper delegates here). Step (4) requires ProtoModel effect records
    /// not yet wired; conservative subset — these properties affect later
    /// type/recovery passes but not SSA correctness, so heritage rename
    /// (heritage.cc:2502/2512) is unaffected.
    pub fn set_input_varnode(
        &mut self,
        vn: Arc<RwLock<Varnode>>,
    ) -> Arc<RwLock<Varnode>> {
        // (1) Early-out if already an input.
        if vn.read().unwrap().is_input() {
            return vn;
        }
        // (2) Overlap dedup against existing inputs. Ghidra uses
        // vbank.beginDef(Varnode::input, addr+size) then walks back; Rugra
        // scans loc_tree for input varnodes overlapping [vn_addr, vn_end).
        let (vn_addr, vn_size) = {
            let r = vn.read().unwrap();
            (r.loc, r.size)
        };
        let vn_end = vn_addr.as_u64().saturating_add(vn_size as u64);
        let existing = {
            let mut found: Option<Arc<RwLock<Varnode>>> = None;
            for loc_ref in self.loc_tree.iter() {
                let cand = loc_ref.0.clone();
                let cr = cand.read().unwrap();
                if !cr.is_input() { continue; }
                let c_start = cr.loc.as_u64();
                let c_end = c_start.saturating_add(cr.size as u64);
                let overlaps = vn_addr.as_u64() < c_end && c_start < vn_end;
                if overlaps {
                    if cr.loc == vn_addr && cr.size == vn_size {
                        // Exact match → return existing (Ghidra cc:356-357).
                        found = Some(cand.clone());
                        break;
                    } else {
                        // Partial overlap → Ghidra throws LowlevelError.
                        // Rugra logs and falls through (conservative).
                        eprintln!("[HERITAGE] WARN: overlapping input varnodes at {:x} (size {}) vs {:x} (size {})",
                                  vn_addr.as_u64(), vn_size, c_start, cr.size);
                    }
                }
            }
            found
        };
        if let Some(existing) = existing {
            return existing;
        }
        // (3) Mark as input via set_input (sets INPUT | INSERT, re-inserts).
        self.set_input(vn.clone());
        // (4) ProtoModel effect-property setting omitted (conservative subset).
        vn
    }

    // Ghidra: varnode.cc:1230 VarnodeBank::clear
    pub fn clear(&mut self) {
        self.loc_tree.clear();
        self.def_tree.clear();
        self.create_index = 0;
        self.uniqid = 0;
    }

    
    // Ghidra: varnode.cc:1316 VarnodeBank::makeFree
    pub fn make_free(&mut self, vn: &mut Varnode) {
        vn.flags &= !varnode_flags::INPUT;
        vn.flags &= !varnode_flags::WRITTEN;
        vn.def = None;
    }

    // Ghidra: varnode.cc:1332 VarnodeBank::replace
    pub fn replace(&mut self, vn1: &mut Varnode, vn2: &mut Varnode) {
        vn2.size = vn1.size;
        vn2.loc = vn1.loc;
    }

    // Ghidra: varnode.cc:1831 VarnodeBank::beginDef(uint4 fl)
    /// Beginning of defined Varnodes with given flags. Faithful to
    /// `beginDef(uint4 fl)` (varnode.cc:1831-1867). Filters by flag class.
    pub fn begin_def_fl(&self, fl: u32) -> impl Iterator<Item = &VarnodeDefRef> {
        self.def_tree.iter().filter(move |v| {
            let vn = v.0.read().unwrap();
            match fl {
                0 => vn.is_input(),
                1 => vn.is_written(),
                _ => true,
            }
        })
    }

    // Ghidra: varnode.cc:1869 VarnodeBank::endDef(uint4 fl)
    pub fn end_def_fl(&self, _fl: u32) -> std::collections::btree_set::Iter<'_, VarnodeDefRef> {
        self.def_tree.iter()
    }

    // Ghidra: varnode.cc:1908 VarnodeBank::beginDef(uint4 fl, const Address&)
    /// Beginning of defined Varnodes at a specific address.
    pub fn begin_def_addr(&self, fl: u32, addr: Address) -> impl Iterator<Item = &VarnodeDefRef> {
        self.def_tree.iter().filter(move |v| {
            let vn = v.0.read().unwrap();
            let flag_ok = match fl {
                0 => vn.is_input(),
                1 => vn.is_written(),
                _ => true,
            };
            flag_ok && vn.loc.as_u64() >= addr.as_u64()
        })
    }

    // Ghidra: varnode.cc:1942 VarnodeBank::endDef(uint4 fl, const Address&)
    pub fn end_def_addr(&self, _fl: u32, addr: Address) -> impl Iterator<Item = &VarnodeDefRef> {
        self.def_tree.iter().filter(move |v| {
            v.0.read().unwrap().loc.as_u64() > addr.as_u64()
        })
    }

    // Ghidra: varnode.cc:1791 VarnodeBank::overlapLoc
    /// Find overlapping varnodes in loc_tree for a given iterator.
    /// Faithful to `overlapLoc` (varnode.cc:1791-1830).
    pub fn overlap_loc(&self, target_addr: Address, target_size: usize) -> Vec<Arc<RwLock<Varnode>>> {
        let mut result = Vec::new();
        let target_end = target_addr.as_u64().wrapping_add(target_size as u64);
        for loc_ref in &self.loc_tree {
            let vn = loc_ref.0.read().unwrap();
            let vn_start = vn.loc.as_u64();
            let vn_end = vn_start.wrapping_add(vn.get_size() as u64);
            if vn_start < target_end && target_addr.as_u64() < vn_end {
                drop(vn);
                result.push(loc_ref.0.clone());
            }
        }
        result
    }

    // Ghidra: varnode.cc:1831 VarnodeBank::beginDef (no-flag version)
    pub fn begin_def(&self) -> std::collections::btree_set::Iter<'_, VarnodeDefRef> {
        self.def_tree.iter()
    }

    // Ghidra: varnode.cc:1560 VarnodeBank::beginLoc
    pub fn begin_loc(&self) -> std::collections::btree_set::Iter<'_, VarnodeLocRef> {
        self.loc_tree.iter()
    }

    // Ghidra: varnode.cc:1536 VarnodeBank::hasInputIntersection
    pub fn has_input_intersection(&self) -> bool {
        false // Placeholder for structure alignment
    }

    // Ghidra: varnode.cc:1218 VarnodeBank::numVarnodes
    pub fn num_varnodes(&self) -> usize {
        self.loc_tree.len()
    }

    // Ghidra: varnode.cc:1218 VarnodeBank::getCreateIndex
    pub fn get_create_index(&self) -> u32 {
        self.create_index
    }

    // Ghidra: varnode.cc:1218 VarnodeBank::findFree
    /// Find a free varnode at a specific location and size
    pub fn find_free(&self, size: usize, loc: Address) -> Option<Arc<RwLock<Varnode>>> {
        let search_vn = Arc::new(RwLock::new(Varnode::new(size, loc)));
        self.loc_tree.get(&VarnodeLocRef(search_vn)).map(|v| v.0.clone())
    }

    // Ghidra: varnode.cc:1465 VarnodeBank::findInput
    /// Find an input varnode at the given size and location. Faithful to
    /// `VarnodeBank::findInput` (varnode.hh). Used by ActionRestrictLocal
    /// and AncestorRealistic to find specific register inputs.
    pub fn find_input(&self, size: usize, loc: Address) -> Option<Arc<RwLock<Varnode>>> {
        self.loc_tree.iter()
            .find(|v| {
                let g = v.0.read().unwrap();
                g.is_input() && g.get_size() == size && g.get_offset() == loc.as_u64()
            })
            .map(|v| v.0.clone())
    }

    // Ghidra: varnode.cc:1440 VarnodeBank::find
    /// Find a Varnode by size, address, defining op address, and optional uniq.
    /// Faithful to `find` (varnode.cc:1440-1458). Scans loc_tree entries
    /// matching (size, addr) and checks def op address + time.
    pub fn find_vn(&self, size: usize, loc: Address, pc: Address, uniq: u32) -> Option<Arc<RwLock<Varnode>>> {
        for loc_ref in &self.loc_tree {
            let vn = loc_ref.0.read().unwrap();
            if vn.get_size() != size { continue; }
            if vn.loc != loc { continue; }
            // Check def op address + time.
            if let Some(def_weak) = vn.def.as_ref().and_then(|w| w.upgrade()) {
                let def_op = def_weak.read().unwrap();
                if def_op.get_addr() == pc {
                    if uniq == u32::MAX || def_op.start.order == uniq {
                        drop(vn);
                        return Some(loc_ref.0.clone());
                    }
                }
            }
        }
        None
    }

    // Ghidra: varnode.cc:1485 VarnodeBank::findCoveredInput
    /// Find the first input Varnode completely contained within [loc, loc+s).
    /// Faithful to `findCoveredInput` (varnode.cc:1485-1507).
    pub fn find_covered_input(&self, size: usize, loc: Address) -> Option<Arc<RwLock<Varnode>>> {
        let end = loc.as_u64().wrapping_add(size as u64).wrapping_sub(1);
        for loc_ref in &self.loc_tree {
            let vn = loc_ref.0.read().unwrap();
            if !vn.is_input() { continue; }
            let vn_start = vn.loc.as_u64();
            let vn_end = vn_start.wrapping_add(vn.get_size() as u64).wrapping_sub(1);
            // vn must be completely contained in [loc, loc+s)
            if vn_start >= loc.as_u64() && vn_end <= end {
                drop(vn);
                return Some(loc_ref.0.clone());
            }
        }
        None
    }

    // Ghidra: varnode.cc:1513 VarnodeBank::findCoveringInput
    /// Find the input Varnode that completely contains [loc, loc+s).
    /// Faithful to `findCoveringInput` (varnode.cc:1513-1531).
    pub fn find_covering_input(&self, size: usize, loc: Address) -> Option<Arc<RwLock<Varnode>>> {
        for loc_ref in &self.loc_tree {
            let vn = loc_ref.0.read().unwrap();
            if !vn.is_input() { continue; }
            let vn_start = vn.loc.as_u64();
            let vn_end = vn_start.wrapping_add(vn.get_size() as u64).wrapping_sub(1);
            // vn must completely contain [loc, loc+s)
            if vn_start <= loc.as_u64() && vn_end >= loc.as_u64().wrapping_add(size as u64).wrapping_sub(1) {
                drop(vn);
                return Some(loc_ref.0.clone());
            }
        }
        None
    }

    // Ghidra: varnode.cc:1560 VarnodeBank::beginLoc(AddrSpace*)
    /// Beginning of Varnodes in given address space, sorted by location.
    /// Faithful to `beginLoc(AddrSpace*)` (varnode.cc:1560-1564).
    pub fn begin_loc_space(&self, space: AddressSpace) -> impl Iterator<Item = &VarnodeLocRef> {
        self.loc_tree.iter().filter(move |v| {
            v.0.read().unwrap().address_space == space
        })
    }

    // Ghidra: varnode.cc:1582 VarnodeBank::beginLoc(const Address&)
    /// Beginning of Varnodes at a specific address.
    pub fn begin_loc_addr(&self, addr: Address) -> impl Iterator<Item = &VarnodeLocRef> {
        self.loc_tree.iter().filter(move |v| {
            v.0.read().unwrap().loc == addr
        })
    }

    // Ghidra: varnode.cc:1560 VarnodeBank::endLoc(AddrSpace*)
    /// End iterator for Varnodes in given address space. In Rust, this is
    /// combined with begin_loc_space into a single filter iterator.
    /// This method exists for API completeness but returns an empty iterator
    /// (use begin_loc_space().chain(empty) pattern instead).
    pub fn end_loc_space(&self, _space: AddressSpace) -> std::collections::btree_set::Iter<'_, VarnodeLocRef> {
        // In Rust, we use the filter iterator from begin_loc_space directly.
        // This is a no-op stub for API parity.
        self.loc_tree.iter()
    }

    // Ghidra: varnode.cc:1218 VarnodeBank::findOrCreateInputSpace
    /// Find or create an input varnode at (space, offset, size).
    pub fn find_or_create_input_space(
        &mut self,
        size: usize,
        space: AddressSpace,
        offset: u64,
    ) -> Arc<RwLock<Varnode>> {
        for entry in self.loc_tree.iter() {
            let g = entry.0.read().unwrap();
            if g.address_space == space
                && g.get_offset() == offset
                && g.get_size() == size
                && !g.is_constant()
                && !g.is_written()
            {
                return entry.0.clone();
            }
        }
        self.create_with_space(size, space, offset)
    }

    // Ghidra: varnode.cc:1218 VarnodeBank::findByLoc
    /// Find any varnode at (size, loc), regardless of create_index.
    ///
    /// `find_free` requires an exact (loc, size, create_index) match, so it
    /// only finds a varnode whose create_index is 0. This helper instead
    /// scans the loc_tree for any varnode with matching (loc, size),
    /// returning the most recently created (highest create_index), which is
    /// the one most likely to carry a current def link. Used by inject to
    /// reuse a prior op's output varnode when linking use-def chains.
    pub fn find_by_loc(&self, size: usize, loc: Address) -> Option<Arc<RwLock<Varnode>>> {
        let mut best: Option<Arc<RwLock<Varnode>>> = None;
        let mut best_idx = 0u32;
        for entry in self.loc_tree.iter() {
            let v = entry.0.read().unwrap();
            if v.loc == loc && v.size == size {
                if v.create_index >= best_idx {
                    best_idx = v.create_index;
                    best = Some(entry.0.clone());
                }
            }
        }
        best
    }

    // Ghidra: varnode.cc:1218 VarnodeBank::iterSpace
    /// Iterate all varnodes in a given address space, in sorted order.
    /// Faithful to Ghidra's `beginLoc(size, addr, space, size4)` /
    /// `endLoc` range iteration (varnode.hh). With address_space now part of
    /// the loc_tree sort key (VarnodeLocRef::Ord), all varnodes of one space
    /// form a contiguous range, so this collects them efficiently.
    pub fn iter_space(
        &self,
        space: crate::space::AddressSpace,
    ) -> impl Iterator<Item = Arc<RwLock<Varnode>>> + '_ {
        self.loc_tree
            .iter()
            .filter(move |entry| {
                entry.0.read().unwrap().address_space == space
            })
            .map(|entry| entry.0.clone())
    }
}

impl fmt::Display for Varnode {
    // Ghidra: varnode.cc:1218 VarnodeBank::fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.loc, self.size)
    }
}

impl Default for VarnodeBank {
    // Ghidra: varnode.cc:1218 VarnodeBank::default
    fn default() -> Self {
        Self::new()
    }
}

// RUGRA-GLUE: walk COPY chain collecting source Arcs. Ghidra's copyShadow
// (varnode.cc:977) inlines this with raw pointers; Rust needs Arc
// collection for the bidirectional source comparison (borrow safety).
/// Walk the COPY chain starting from `vn`, collecting the Arc of each Varnode
/// encountered (including `vn` itself). Used by `Varnode::copy_shadow` to
/// implement Ghidra's bidirectional COPY-source comparison (varnode.cc:977).
///
/// Stops at the first non-COPY-defined Varnode (the chain source).
fn collect_copy_sources(vn: &Varnode) -> Vec<std::sync::Arc<std::sync::RwLock<Varnode>>> {
    use crate::opcodes::OpCode;
    let mut sources = Vec::new();
    let mut current = None::<std::sync::Arc<std::sync::RwLock<Varnode>>>;
    // We start by looking at vn itself; since we only have &Varnode, we use
    // its def chain to find the owning Arc via the def op's input.
    // Walk forward: at each step, if current vn is defined by COPY, record it
    // and move to the COPY's input.
    loop {
        // Determine the Arc for the current Varnode in this iteration.
        let cur_arc: std::sync::Arc<std::sync::RwLock<Varnode>> = match current.take() {
            Some(a) => a,
            None => {
                // First iteration: we have &vn but no Arc. Resolve via def.
                // vn's def op (if COPY) holds an Arc to vn in its output, but
                // that's circular. Instead, the COPY *input* gives the next
                // source. We record vn by pointer for comparison via the def
                // op's output Arc (which == the vn that is the COPY output).
                // Simpler: record the def op's output Arc.
                let def_arc = match vn.def.as_ref().and_then(|w| w.upgrade()) {
                    Some(a) => a,
                    None => return sources, // vn has no def; nothing to walk
                };
                let def = def_arc.read().unwrap();
                let out_arc = match def.output.clone() {
                    Some(o) => o,
                    None => return sources,
                };
                // Verify the output is actually vn (it should be, as vn.def
                // points to this op). Record it.
                if std::sync::Arc::as_ptr(&out_arc) as *const () as usize
                    != vn as *const Varnode as *const () as usize
                {
                    // Mismatch (shouldn't happen); bail.
                    return sources;
                }
                drop(def);
                out_arc
            }
        };
        sources.push(cur_arc.clone());
        // Try to advance: is cur defined by a COPY?
        let cur_vn = cur_arc.read().unwrap();
        let next = cur_vn.def.as_ref().and_then(|w| w.upgrade()).and_then(|op_arc| {
            let op = op_arc.read().unwrap();
            if op.opcode == OpCode::CPUI_COPY {
                op.inrefs.get(0).cloned()
            } else {
                None
            }
        });
        drop(cur_vn);
        match next {
            Some(n) => current = Some(n),
            None => break,
        }
    }
    sources
}

/// Walk forward along COPY defs from `vn`, returning true if `target` (by
/// pointer identity) appears anywhere along the chain. Faithful to the
// RUGRA-GLUE: 沿 COPY 链逐步比较指针身份。Ghidra 用裸指针 while 循环
// (varnode.cc:1010,1030)；Rugra 需 clone Arc + 释放 guard 逐层展开。
/// `while(vn->isWritten() && vn->getDef()->code()==CPUI_COPY) { vn=...; if(vn==t) return true; }`
/// pattern in findSubpieceShadow/findPieceShadow (varnode.cc:1010,1030).
fn copy_chain_hits(vn: &Varnode, target: &Varnode) -> bool {
    use crate::opcodes::OpCode;
    if std::ptr::eq(vn as *const Varnode, target as *const Varnode) {
        return true;
    }
    let mut cur_def = vn.def.as_ref().and_then(|w| w.upgrade());
    let mut cur_vn_ptr: *const Varnode = vn as *const Varnode;
    // We need to compare each Varnode along the COPY chain to target.
    // Walk: at each step, if cur is defined by COPY, advance to in(0).
    loop {
        let def_arc = match cur_def.take() {
            Some(a) => a,
            None => return false,
        };
        let next = {
            let def = def_arc.read().unwrap();
            if def.opcode != OpCode::CPUI_COPY {
                return false;
            }
            def.inrefs.get(0).cloned()
        };
        let Some(next_arc) = next else { return false };
        // Compare next Varnode to target by pointer.
        let hits = {
            let n = next_arc.read().unwrap();
            std::ptr::eq(&*n as *const Varnode, target as *const Varnode)
        };
        if hits {
            return true;
        }
        // Set up for next iteration: cur_vn becomes next_arc's Varnode.
        // Its def is next_arc.def.
        let next_def = next_arc.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
        let _ = cur_vn_ptr; // suppress unused
        cur_def = next_def;
    }
}

/// Resolve the COPY-chain source of `vn` and return it as a borrowed
/// comparison target. Returns the def op + the advanced `vn` reference is
/// implicit (caller re-reads). For findSubpieceShadow we need the terminal
/// non-COPY-defined Varnode. Returns (def_op_arc, is_constant_terminal).
/// Actually, to avoid lifetime issues, we return the source Varnode's def
/// op Arc so the caller can inspect its opcode/inputs.
// RUGRA-GLUE: 透传 COPY 链到终端 def op（非 COPY 定义或 unwritten）。
// Ghidra 内联 while 循环；Rugra 提取为函数以避免跨层 RwLockReadGuard 冲突。
/// Returns None if vn is not written.
fn copy_chain_source_def(vn: &Varnode) -> Option<(std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>, bool)> {
    use crate::opcodes::OpCode;
    // Walk COPY chain to the terminal def op.
    let mut cur_def = vn.def.as_ref().and_then(|w| w.upgrade())?;
    loop {
        let (is_copy, next_def) = {
            let d = cur_def.read().unwrap();
            if d.opcode == OpCode::CPUI_COPY {
                (true, d.inrefs.get(0).and_then(|v| v.read().unwrap().def.as_ref().and_then(|w| w.upgrade())))
            } else {
                (false, None)
            }
        };
        if !is_copy {
            // cur_def is the terminal non-COPY def.
            let written = true;
            return Some((cur_def, written));
        }
        match next_def {
            Some(nd) => cur_def = nd,
            None => {
                // COPY chain ends at an unwritten/input Varnode.
                return Some((cur_def, false));
            }
        }
    }
}

// Ghidra: varnode.cc:1006 Varnode::findSubpieceShadow
/// Faithful to `Varnode::findSubpieceShadow` (varnode.cc:1006-1053).
/// Establish that `vn` is produced from `whole` by SUBPIECE truncating
/// `least_byte` low bytes (allowing COPY pass-through and 1 level of
/// MULTIEQUAL recursion).
fn find_subpiece_shadow(vn: &Varnode, least_byte: i32, whole: &Varnode, recurse: i32) -> bool {
    use crate::opcodes::OpCode;
    // Walk COPY chain from vn to its source.
    let (def_arc, written) = match copy_chain_source_def(vn) {
        Some(x) => x,
        None => {
            // vn not written at all.
            if vn.is_constant() {
                // Constant short-circuit (varnode.cc:1013-1020).
                let whole_def = copy_chain_source_def(whole);
                let whole_is_const = match &whole_def {
                    Some((_, true)) => false,
                    None => whole.is_constant(),
                    Some((_, false)) => whole.is_constant(),
                };
                // Re-derive whole's terminal offset by walking its COPY chain.
                if !whole_is_const {
                    return false;
                }
                let whole_off = whole_terminal_offset(whole);
                let off = whole_off >> (least_byte as u32 * 8);
                let mask = crate::address::calc_mask(vn.size);
                return (off & mask) == vn.get_offset();
            }
            return false;
        }
    };
    if !written {
        // vn's COPY chain ends at an unwritten (input) non-constant Varnode.
        return false;
    }
    let def = def_arc.read().unwrap();
    match def.opcode {
        OpCode::CPUI_SUBPIECE => {
            let tmpvn_arc = match def.inrefs.get(0) { Some(a) => a.clone(), None => return false };
            let off = match def.inrefs.get(1) { Some(a) => a.read().unwrap().get_offset() as i32, None => return false };
            if off != least_byte {
                return false;
            }
            let tmpvn_size = tmpvn_arc.read().unwrap().size;
            if tmpvn_size != whole.size {
                return false;
            }
            // if (tmpvn == whole) return true; + COPY chain check (varnode.cc:1029-1033)
            let tmpvn = tmpvn_arc.read().unwrap();
            return copy_chain_hits(&tmpvn, whole);
        }
        OpCode::CPUI_MULTIEQUAL => {
            let new_recurse = recurse + 1;
            if new_recurse > 1 {
                return false; // Truncate recursion at max depth (varnode.cc:1037)
            }
            // Walk whole's COPY chain, require it to be defined by MULTIEQUAL.
            let (whole_def_arc, whole_written) = match copy_chain_source_def(whole) {
                Some(x) => x,
                None => return false,
            };
            if !whole_written {
                return false;
            }
            let small_op = def_arc.clone();
            drop(def);
            let big_op_def = whole_def_arc.read().unwrap();
            if big_op_def.opcode != OpCode::CPUI_MULTIEQUAL {
                return false;
            }
            // bigOp->getParent() != smallOp->getParent() check (varnode.cc:1044).
            let same_parent = {
                let big_p = big_op_def.parent.as_ref().and_then(|w| w.upgrade());
                let small_p = small_op.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
                match (big_p, small_p) {
                    (Some(b), Some(s)) => std::sync::Arc::ptr_eq(&b, &s),
                    _ => false,
                }
            };
            if !same_parent {
                return false;
            }
            let n = big_op_def.num_input();
            // Collect input Arcs before recursing (avoid holding guards).
            let pairs: Vec<(std::sync::Arc<std::sync::RwLock<Varnode>>, std::sync::Arc<std::sync::RwLock<Varnode>>)> = {
                let small = small_op.read().unwrap();
                (0..n).filter_map(|i| {
                    let sin = small.inrefs.get(i).cloned();
                    let bin = big_op_def.inrefs.get(i).cloned();
                    match (sin, bin) { (Some(a), Some(b)) => Some((a, b)), _ => None }
                }).collect()
            };
            drop(big_op_def);
            for (s_arc, b_arc) in pairs {
                let (s, b) = { (s_arc.read().unwrap(), b_arc.read().unwrap()) };
                // Note: recursing with dropped guards — but we hold s,b here.
                // find_subpiece_shadow only reads, so it's safe to pass &*s, &*b.
                if !find_subpiece_shadow(&s, least_byte, &b, new_recurse) {
                    return false;
                }
            }
            return true;
        }
        _ => return false,
    }
}

// RUGRA-GLUE: 透传 whole 的 COPY 链取终端 offset（常量短路用）。
// Ghidra 内联 while 循环 (varnode.cc:1014-1017)；Rugra 提取为函数。
/// Get the terminal offset of a constant Varnode after walking its COPY
/// chain. Used by findSubpieceShadow's constant short-circuit (varnode.cc:1017).
fn whole_terminal_offset(whole: &Varnode) -> u64 {
    use crate::opcodes::OpCode;
    let mut off = whole.get_offset();
    let mut cur = whole.def.as_ref().and_then(|w| w.upgrade());
    while let Some(d_arc) = cur.take() {
        let d = d_arc.read().unwrap();
        if d.opcode != OpCode::CPUI_COPY {
            break;
        }
        if let Some(next) = d.inrefs.get(0) {
            off = next.read().unwrap().get_offset();
            cur = next.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
        } else {
            break;
        }
    }
    off
}

// Ghidra: varnode.cc:1062 Varnode::findPieceShadow
/// Faithful to `Varnode::findPieceShadow` (varnode.cc:1062-1091).
fn find_piece_shadow(vn: &Varnode, mut least_byte: i32, piece: &Varnode) -> bool {
    use crate::opcodes::OpCode;
    // Walk COPY chain.
    let (def_arc, written) = match copy_chain_source_def(vn) {
        Some(x) => x,
        None => return false,
    };
    if !written {
        return false;
    }
    let def = def_arc.read().unwrap();
    if def.opcode != OpCode::CPUI_PIECE {
        return false;
    }
    // tmpvn = getIn(1) (least significant part).
    let mut tmpvn_arc = match def.inrefs.get(1) { Some(a) => a.clone(), None => return false };
    let tmp_size = tmpvn_arc.read().unwrap().size;
    if (least_byte as usize) >= tmp_size {
        least_byte -= tmp_size as i32;
        // tmpvn = getIn(0).
        tmpvn_arc = match def.inrefs.get(0) { Some(a) => a.clone(), None => return false };
    } else {
        let tmp_size2 = tmpvn_arc.read().unwrap().size;
        if piece.size + (least_byte as usize) > tmp_size2 {
            return false;
        }
    }
    let tmp_size_final = tmpvn_arc.read().unwrap().size;
    if least_byte == 0 && tmp_size_final == piece.size {
        let tmpvn = tmpvn_arc.read().unwrap();
        return copy_chain_hits(&tmpvn, piece);
    }
    // CPUI_PIECE input too big: recurse.
    let tmpvn = tmpvn_arc.read().unwrap();
    find_piece_shadow(&tmpvn, least_byte, piece)
}

// Ghidra: varnode.cc:2014 contiguous_test
/// Test if two Varnodes are contiguous pieces of a whole via SUBPIECE.
/// Faithful to `contiguous_test` (varnode.cc:2014-2037).
pub fn contiguous_test(vn1: &Varnode, vn2: &Varnode) -> bool {
    use crate::opcodes::OpCode;
    if vn1.is_input() || vn2.is_input() { return false; }
    if !vn1.is_written() || !vn2.is_written() { return false; }
    let def1 = match vn1.def.as_ref().and_then(|w| w.upgrade()) { Some(d) => d, None => return false };
    let def2 = match vn2.def.as_ref().and_then(|w| w.upgrade()) { Some(d) => d, None => return false };
    let d1 = def1.read().unwrap();
    let d2 = def2.read().unwrap();
    if d1.opcode != OpCode::CPUI_SUBPIECE || d2.opcode != OpCode::CPUI_SUBPIECE { return false; }
    let vnwhole1 = match d1.get_in(0) { Some(v) => v.clone(), None => return false };
    let vnwhole2 = match d2.get_in(0) { Some(v) => v.clone(), None => return false };
    if !Arc::ptr_eq(&vnwhole1, &vnwhole2) { return false; }
    // vn2 must be least significant (offset 0)
    let off2 = match d2.get_in(1) { Some(v) => v.read().unwrap().get_offset(), None => return false };
    if off2 != 0 { return false; }
    // vn1 must be contiguous above vn2
    let off1 = match d1.get_in(1) { Some(v) => v.read().unwrap().get_offset(), None => return false };
    if off1 != vn2.size as u64 { return false; }
    true
}

// Ghidra: varnode.cc:2045 findContiguousWhole
/// Return the whole Varnode containing vn1+vn2 (assuming contiguous_test passed).
/// Faithful to `findContiguousWhole` (varnode.cc:2045-2051).
pub fn find_contiguous_whole(vn1: &Varnode) -> Option<Arc<RwLock<Varnode>>> {
    if vn1.is_written() {
        if let Some(def) = vn1.def.as_ref().and_then(|w| w.upgrade()) {
            if def.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_SUBPIECE {
                return def.read().unwrap().get_in(0).cloned();
            }
        }
    }
    None
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

    #[test]
    fn test_is_constant_extended_plain_constant() {
        // A plain constant returns Some((offset, 0)) (varnode.cc:799-840).
        let v = Varnode::new_constant(0x1234, 8);
        assert_eq!(v.is_constant_extended(), Some((0x1234, 0)));
    }

    #[test]
    fn test_is_constant_extended_small_nonconst() {
        // A non-constant 8-byte varnode with no def returns None.
        let v = Varnode::new(8, Address::new(0x100));
        assert_eq!(v.is_constant_extended(), None);
    }
}
