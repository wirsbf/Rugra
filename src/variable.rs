//! High-level variable management
//!
//! Corresponds to Ghidra's `variable.hh`

use crate::varnode::Varnode;
use crate::type_system::Datatype;
use crate::cover::Cover;
use std::sync::{Arc, RwLock};

/// Represents a high-level variable in the decompiler
///
/// Corresponds to Ghidra's `HighVariable` class. A HighVariable is a
/// collection of SSA Varnodes that represent the same logical variable.
#[derive(Debug)]
pub struct HighVariable {
    /// Name of the variable (if known)
    pub name: String,
    /// Data type of the variable
    pub v_type: Arc<Datatype>,
    /// All varnodes that belong to this high-level variable
    pub instances: Vec<Arc<RwLock<Varnode>>>,
    /// Flags (corresponds to high_flags in Ghidra)
    pub flags: u32,
    /// Unique ID assigned to this high variable
    pub id: u64,
    /// Extended cover: union of all member Varnode covers.
    /// Faithful to HighVariable::internalCover (variable.hh:143).
    /// Used by ActionMarkImplied's checkImpliedCover / inflateTest.
    pub cover: Cover,
}

impl HighVariable {
    // Ghidra: variable.cc:220 HighVariable::new
    /// Create a new high-level variable
    pub fn new(v_type: Arc<Datatype>) -> Self {
        Self {
            name: String::new(),
            v_type,
            instances: Vec::new(),
            flags: 0,
            id: 0,
            cover: Cover::new(),
        }
    }

    // Ghidra: variable.cc:220 HighVariable::getName
    /// Get the name of the high variable
    pub fn get_name(&self) -> &str {
        &self.name
    }

    // Ghidra: variable.cc:220 HighVariable::setName
    /// Set the name of the high variable
    pub fn set_name(&mut self, name: String) {
        self.name = name;
        self.flags |= high_flags::NAMELOCK;
    }

    // Ghidra: variable.cc:220 HighVariable::getType
    /// Get the data type of the high variable
    pub fn get_type(&self) -> Arc<Datatype> {
        self.v_type.clone()
    }

    // Ghidra: variable.cc:220 HighVariable::setType
    /// Set the data type of the high variable
    pub fn set_type(&mut self, v_type: Arc<Datatype>) {
        self.v_type = v_type;
    }

    // Ghidra: variable.cc:220 HighVariable::addInstance
    /// Add a varnode instance to this high variable
    pub fn add_instance(&mut self, vn: Arc<RwLock<Varnode>>) {
        self.instances.push(vn);
    }

    // Ghidra: variable.cc:220 HighVariable::numInstances
    /// Get the number of instances
    pub fn num_instances(&self) -> usize {
        self.instances.len()
    }

    // Ghidra: variable.cc:220 HighVariable::getInstance
    /// Get a specific instance
    pub fn get_instance(&self, i: usize) -> Option<Arc<RwLock<Varnode>>> {
        self.instances.get(i).cloned()
    }

    // Ghidra: variable.cc:220 HighVariable::isNameLocked
    /// Check if this variable has a locked name.
    /// Faithful to HighVariable::isNameLocked (variable.hh).
    pub fn is_name_locked(&self) -> bool {
        self.flags & high_flags::NAMELOCK != 0
    }

    // Ghidra: variable.cc:220 HighVariable::isTypeLocked
    /// Check if this variable has a locked type.
    /// Faithful to HighVariable::isTypeLocked (variable.hh).
    pub fn is_type_locked(&self) -> bool {
        self.flags & high_flags::TYPELOCK != 0
    }

    // Ghidra: variable.cc:220 HighVariable::isPersist
    /// Check if this variable is persistent (global/external).
    /// Faithful to HighVariable::isPersist (variable.hh:198).
    /// Checks high_flags bit OR any instance Varnode carrying persist.
    pub fn is_persist(&self) -> bool {
        if self.flags & high_flags::PERSIST != 0 {
            return true;
        }
        self.instances.iter().any(|vn| {
            vn.read().unwrap().flags & crate::varnode::varnode_flags::PERSIST != 0
        })
    }

    // Ghidra: variable.cc:220 HighVariable::isAddrTied
    /// Check if this variable is address-tied (lives at a specific address).
    /// Faithful to HighVariable::isAddrTied (variable.hh:199).
    ///
    /// Ghidra's HighVariable::isAddrTied calls updateFlags() then checks
    /// `flags & Varnode::addrtied`. updateFlags() recomputes the aggregated
    /// flags from all instance Varnodes. Rugra has no updateFlags cache, so
    /// we check the high_flags bit (set at HighVariable creation) OR any
    /// instance Varnode carrying the addrtied flag.
    pub fn is_addr_tied(&self) -> bool {
        if self.flags & high_flags::ADDRTIED != 0 {
            return true;
        }
        self.instances.iter().any(|vn| {
            vn.read().unwrap().flags & crate::varnode::varnode_flags::ADDRTIED != 0
        })
    }

    // Ghidra: variable.hh:200 HighVariable::isInput
    /// Check if this variable is an input variable.
    /// Faithful to HighVariable::isInput (variable.hh:200).
    /// Checks aggregated instance Varnode flags (Ghidra updateFlags model).
    pub fn is_input(&self) -> bool {
        self.instances.iter().any(|vn| {
            vn.read().unwrap().is_input()
        })
    }

    // Ghidra: variable.hh:205 HighVariable::isExtraOut
    /// Check if this variable is an extra output (indirect_creation but not addrtied).
    /// Faithful to HighVariable::isExtraOut (variable.hh:205):
    ///   `(flags & (indirect_creation|addrtied)) == indirect_creation`
    pub fn is_extra_out(&self) -> bool {
        self.instances.iter().any(|vn| {
            let f = vn.read().unwrap().flags;
            let ic = crate::varnode::varnode_flags::INDIRECT_CREATION;
            let at = crate::varnode::varnode_flags::ADDRTIED;
            (f & (ic | at)) == ic
        })
    }

    // Ghidra: variable.hh:206 HighVariable::isProtoPartial
    /// Check if this variable is a proto-partial (CONCAT piece).
    /// Faithful to HighVariable::isProtoPartial (variable.hh:206).
    pub fn is_proto_partial(&self) -> bool {
        self.instances.iter().any(|vn| {
            vn.read().unwrap().is_proto_partial()
        })
    }

    // Ghidra: variable.cc:220 HighVariable::isConstant
    /// Check if this variable is a constant.
    /// Faithful to HighVariable::isConstant (variable.hh).
    pub fn is_constant(&self) -> bool {
        self.flags & high_flags::CONSTANT != 0
    }

    // Ghidra: variable.cc:718 HighVariable::hasName
    /// Check if this variable has a name assigned.
    /// Faithful to HighVariable::hasName (variable.cc:718).
    pub fn has_name(&self) -> bool {
        !self.name.is_empty() || self.is_name_locked()
    }

    // Ghidra: variable.cc:220 HighVariable::removeInstance
    /// Remove a varnode instance by index.
    /// Faithful to HighVariable::remove (variable.cc:515).
    pub fn remove_instance(&mut self, index: usize) {
        if index < self.instances.len() {
            self.instances.remove(index);
        }
    }

    // Ghidra: variable.cc:808 HighVariable::instanceIndex
    /// Find the index of a specific varnode instance.
    /// Faithful to HighVariable::instanceIndex (variable.cc:808).
    pub fn instance_index(&self, vn: &Arc<RwLock<Varnode>>) -> Option<usize> {
        self.instances.iter().position(|v| Arc::ptr_eq(v, vn))
    }

    // Ghidra: variable.cc:626 HighVariable::mergeInternal
    /// Merge another HighVariable's instances into this one.
    /// Faithful to HighVariable::mergeInternal (variable.cc:626).
    pub fn merge_internal(&mut self, other: &mut HighVariable) {
        self.instances.append(&mut other.instances);
        // Update flags: if either has TYPELOCK, keep it.
        self.flags |= other.flags & high_flags::TYPELOCK;
        // Take the name if we don't have one and the other does.
        if self.name.is_empty() && !other.name.is_empty() {
            self.name = other.name.clone();
            self.flags |= other.flags & high_flags::NAMELOCK;
        }
    }

    // Ghidra: variable.cc:377 HighVariable::getTypeRepresentative
    /// Get the representative varnode for type queries.
    /// Faithful to HighVariable::getTypeRepresentative (variable.cc:377).
    pub fn get_type_representative(&self) -> Option<Arc<RwLock<Varnode>>> {
        // Prefer a non-constant, written varnode.
        for vn in &self.instances {
            let vn_guard = vn.read().unwrap();
            if !vn_guard.is_constant() && vn_guard.is_written() {
                return Some(vn.clone());
            }
        }
        self.instances.first().cloned()
    }

    // Ghidra: variable.cc:492 HighVariable::getNameRepresentative
    /// Get the representative varnode for name queries.
    /// Faithful to HighVariable::getNameRepresentative (variable.cc:492).
    pub fn get_name_representative(&self) -> Option<Arc<RwLock<Varnode>>> {
        // Prefer a varnode with a symbol entry or input.
        for vn in &self.instances {
            let vn_guard = vn.read().unwrap();
            if vn_guard.is_input() {
                return Some(vn.clone());
            }
        }
        self.instances.first().cloned()
    }

    // Ghidra: variable.cc:302 HighVariable::stripType
    /// Strip the type (set to unknown). Used when type propagation fails.
    /// Faithful to HighVariable::stripType (variable.cc:302).
    pub fn strip_type(&mut self, unknown_type: Arc<Datatype>) {
        if !self.is_type_locked() {
            self.v_type = unknown_type;
        }
    }

    // Ghidra: variable.cc:324 HighVariable::updateInternalCover
    /// Re-derive the internal cover from the member Varnodes.
    /// Faithful to HighVariable::updateInternalCover (variable.cc:324).
    /// Clears the cover then merges every instance's cover. Skips
    /// instances that have no cover (constants/annotations/free).
    pub fn update_internal_cover(&mut self) {
        self.cover.clear();
        for inst_arc in &self.instances {
            let inst = inst_arc.read().unwrap();
            if let Some(ic) = inst.cover.as_ref() {
                self.cover.merge(ic);
            }
        }
    }
}

/// Flags for HighVariable properties
pub mod high_flags {
    pub const NAMELOCK: u32 = 1 << 0;
    pub const TYPELOCK: u32 = 1 << 1;
    pub const PERSIST: u32 = 1 << 2;
    pub const ADDRTIED: u32 = 1 << 3;
    pub const UNUSED1: u32 = 1 << 4;
    pub const CONSTANT: u32 = 1 << 5;
    pub const EXTRA_FLAGS: u32 = 1 << 6;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_system::datatype::{TypeBase, TypeMetatype};

    fn make_type() -> Arc<Datatype> {
        Arc::new(Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int)))
    }

    #[test]
    fn test_high_variable_basic() {
        let hv = HighVariable::new(make_type());
        assert_eq!(hv.num_instances(), 0);
        assert!(!hv.has_name());
    }

    #[test]
    fn test_name_lock() {
        let mut hv = HighVariable::new(make_type());
        hv.set_name("myVar".into());
        assert!(hv.is_name_locked());
        assert!(hv.has_name());
        assert_eq!(hv.get_name(), "myVar");
    }

    #[test]
    fn test_merge_internal() {
        let mut hv1 = HighVariable::new(make_type());
        let mut hv2 = HighVariable::new(make_type());
        hv2.set_name("named".into());
        hv1.merge_internal(&mut hv2);
        assert_eq!(hv1.get_name(), "named");
    }

    #[test]
    fn test_flags() {
        let mut hv = HighVariable::new(make_type());
        hv.flags |= high_flags::TYPELOCK | high_flags::PERSIST;
        assert!(hv.is_type_locked());
        assert!(hv.is_persist());
        assert!(!hv.is_addr_tied());
        assert!(!hv.is_constant());
    }
}
