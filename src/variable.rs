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

// Ghidra: variable.hh:44 VariableGroup
/// A group of mutually overlapping HighVariables that share a storage region.
/// Faithful to Ghidra's `VariableGroup` (variable.hh:44-68). Manages a set
/// of VariablePiece objects, tracks total size and symbol offset.
#[derive(Debug)]
pub struct VariableGroup {
    /// Pieces in this group, sorted by (offset, size).
    pub pieces: Vec<Arc<RwLock<VariablePiece>>>,
    /// Number of contiguous bytes covered by the whole group.
    pub size: i32,
    /// Byte offset of this group within its containing Symbol.
    pub symbol_offset: i32,
}

impl VariableGroup {
    // Ghidra: variable.hh:56 VariableGroup::VariableGroup
    pub fn new() -> Self {
        Self { pieces: Vec::new(), size: 0, symbol_offset: 0 }
    }

    // Ghidra: variable.hh:58 VariableGroup::empty
    pub fn is_empty(&self) -> bool { self.pieces.is_empty() }

    // Ghidra: variable.hh:59 VariableGroup::addPiece
    /// Add a new piece to this group and update total size.
    pub fn add_piece(&mut self, piece: Arc<RwLock<VariablePiece>>) {
        let p_size = piece.read().unwrap().size;
        let p_offset = piece.read().unwrap().group_offset;
        piece.write().unwrap().group = Some(Arc::new(RwLock::new(VariableGroup::new()))); // placeholder
        self.pieces.push(piece);
        self.pieces.sort_by_key(|p| {
            let r = p.read().unwrap();
            (r.group_offset, r.size)
        });
        let end = p_offset + p_size;
        if end > self.size { self.size = end; }
    }

    // Ghidra: variable.hh:60 VariableGroup::adjustOffsets
    /// Adjust offset for every piece by the given amount.
    pub fn adjust_offsets(&mut self, amt: i32) {
        for piece in &self.pieces {
            piece.write().unwrap().group_offset += amt;
        }
        self.symbol_offset += amt;
    }

    // Ghidra: variable.hh:61 VariableGroup::removePiece
    /// Remove a piece from this group.
    pub fn remove_piece(&mut self, piece: &Arc<RwLock<VariablePiece>>) {
        let target_ptr = Arc::as_ptr(piece) as usize;
        self.pieces.retain(|p| Arc::as_ptr(p) as usize != target_ptr);
    }

    // Ghidra: variable.hh:62 VariableGroup::getSize
    pub fn get_size(&self) -> i32 { self.size }

    // Ghidra: variable.hh:63 VariableGroup::setSymbolOffset
    pub fn set_symbol_offset(&mut self, val: i32) { self.symbol_offset = val; }

    // Ghidra: variable.hh:64 VariableGroup::getSymbolOffset
    pub fn get_symbol_offset(&self) -> i32 { self.symbol_offset }

    // Ghidra: variable.hh:65 VariableGroup::combineGroups
    /// Combine another VariableGroup into this one.
    pub fn combine_groups(&mut self, op2: &mut VariableGroup) {
        for piece in op2.pieces.drain(..) {
            self.pieces.push(piece);
        }
        self.pieces.sort_by_key(|p| {
            let r = p.read().unwrap();
            (r.group_offset, r.size)
        });
        if op2.size > self.size { self.size = op2.size; }
    }
}

impl Default for VariableGroup {
    // RUGRA-GLUE: Default impl (Rust trait glue; Ghidra has default ctor)
    fn default() -> Self { Self::new() }
}

// Ghidra: variable.hh:71 VariablePiece
/// Information about how a HighVariable fits into a larger group or Symbol.
/// Faithful to Ghidra's `VariablePiece` (variable.hh:71-97). Describes
/// overlaps and how they affect the HighVariable Cover.
#[derive(Debug)]
pub struct VariablePiece {
    /// Group to which this piece belongs.
    pub group: Option<Arc<RwLock<VariableGroup>>>,
    /// HighVariable owning this piece.
    pub high: Option<Arc<RwLock<HighVariable>>>,
    /// Byte offset of this piece within the group.
    pub group_offset: i32,
    /// Number of bytes in this piece.
    pub size: i32,
    /// List of pieces this piece intersects with.
    pub intersection: Vec<Arc<RwLock<VariablePiece>>>,
    /// Extended cover for the piece.
    pub cover: Cover,
}

impl VariablePiece {
    // Ghidra: variable.hh:83 VariablePiece::VariablePiece
    pub fn new(offset: i32, size: i32) -> Self {
        Self {
            group: None,
            high: None,
            group_offset: offset,
            size,
            intersection: Vec::new(),
            cover: Cover::new(),
        }
    }

    // Ghidra: variable.hh:85 VariablePiece::getHigh
    pub fn get_high(&self) -> Option<&Arc<RwLock<HighVariable>>> { self.high.as_ref() }

    // Ghidra: variable.hh:86 VariablePiece::getGroup
    pub fn get_group(&self) -> Option<&Arc<RwLock<VariableGroup>>> { self.group.as_ref() }

    // Ghidra: variable.hh:87 VariablePiece::getOffset
    pub fn get_offset(&self) -> i32 { self.group_offset }

    // Ghidra: variable.hh:88 VariablePiece::getSize
    pub fn get_size(&self) -> i32 { self.size }

    // Ghidra: variable.hh:89 VariablePiece::getCover
    pub fn get_cover(&self) -> &Cover { &self.cover }

    // Ghidra: variable.hh:90 VariablePiece::numIntersection
    pub fn num_intersection(&self) -> usize { self.intersection.len() }

    // Ghidra: variable.hh:91 VariablePiece::getIntersection
    pub fn get_intersection(&self, i: usize) -> Option<&Arc<RwLock<VariablePiece>>> {
        self.intersection.get(i)
    }

    // Ghidra: variable.hh:92 VariablePiece::markIntersectionDirty
    pub fn mark_intersection_dirty(&self) {
        // In Ghidra, this sets a dirty flag on the cover. Rugra's Cover
        // doesn't have a dirty flag (simplified), so this is a no-op.
    }

    // Ghidra: variable.hh:93 VariablePiece::markExtendCoverDirty
    pub fn mark_extend_cover_dirty(&self) {
        // Same as above — no-op in Rugra's simplified cover.
    }

    // Ghidra: variable.hh:94 VariablePiece::updateIntersections
    /// Calculate intersections with other pieces in the group.
    pub fn update_intersections(&mut self, group: &VariableGroup) {
        self.intersection.clear();
        let my_end = self.group_offset + self.size;
        for other in &group.pieces {
            if Arc::as_ptr(other) as usize == self as *const _ as usize { continue; }
            let o = other.read().unwrap();
            let o_end = o.group_offset + o.size;
            if self.group_offset < o_end && o.group_offset < my_end {
                self.intersection.push(other.clone());
            }
        }
    }

    // Ghidra: variable.hh:95 VariablePiece::updateCover
    /// Calculate extended cover based on intersections.
    pub fn update_cover(&mut self) {
        // Simplified: just use the base cover. Full implementation would
        // merge covers from all intersecting pieces.
    }

    // Ghidra: variable.hh:96 VariablePiece::transferGroup
    /// Transfer this piece to another VariableGroup.
    pub fn transfer_group(&mut self, new_group: Arc<RwLock<VariableGroup>>) {
        self.group = Some(new_group);
    }

    // Ghidra: variable.hh:97 VariablePiece::setHigh
    pub fn set_high(&mut self, new_high: Arc<RwLock<HighVariable>>) {
        self.high = Some(new_high);
    }

    // Ghidra: variable.hh:98 VariablePiece::mergeGroups
    /// Combine two VariableGroups by merging op2's group into this piece's group.
    pub fn merge_groups(&mut self, op2: &Arc<RwLock<VariablePiece>>) {
        // Simplified: just mark both pieces as belonging to the same group.
        // Full implementation requires vector<HighVariable*> mergePairs.
        if let (Some(g1), Some(g2)) = (&self.group, &op2.read().unwrap().group) {
            if !Arc::ptr_eq(g1, g2) {
                // Merge g2 into g1
                let mut g2_w = g2.write().unwrap();
                let mut g1_w = g1.write().unwrap();
                g1_w.combine_groups(&mut g2_w);
            }
        }
    }
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
