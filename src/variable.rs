//! High-level variable management
//!
//! Corresponds to Ghidra's `variable.hh`

use crate::varnode::Varnode;
use crate::type_system::Datatype;
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
}

impl HighVariable {
    /// Create a new high-level variable
    pub fn new(v_type: Arc<Datatype>) -> Self {
        Self {
            name: String::new(),
            v_type,
            instances: Vec::new(),
            flags: 0,
            id: 0,
        }
    }

    /// Get the name of the high variable
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Set the name of the high variable
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Get the data type of the high variable
    pub fn get_type(&self) -> Arc<Datatype> {
        self.v_type.clone()
    }

    /// Set the data type of the high variable
    pub fn set_type(&mut self, v_type: Arc<Datatype>) {
        self.v_type = v_type;
    }

    /// Add a varnode instance to this high variable
    pub fn add_instance(&mut self, vn: Arc<RwLock<Varnode>>) {
        self.instances.push(vn);
    }

    /// Get the number of instances
    pub fn num_instances(&self) -> usize {
        self.instances.len()
    }

    /// Get a specific instance
    pub fn get_instance(&self, i: usize) -> Option<Arc<RwLock<Varnode>>> {
        self.instances.get(i).cloned()
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
