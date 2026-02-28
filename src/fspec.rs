//! Function prototypes and call specifications
//!
//! Corresponds to Ghidra's `fspec.hh`. This module manages how functions
//! are defined (prototypes) and how call sites are handled (call specs).

use std::sync::Arc;
use crate::address::Address;
use crate::type_system::datatype::Datatype;

/// Flags for ProtoParameter (corresponds to flags in fspec.hh)
pub mod protoparam_flags {
    pub const HIDDEN_RETURN: u32 = 1 << 0;
    pub const INDIRECT_STORAGE: u32 = 1 << 1;
    pub const THIS_POINTER: u32 = 1 << 2;
    pub const NAME_LOCKED: u32 = 1 << 3;
    pub const TYPE_LOCKED: u32 = 1 << 4;
}

/// A single parameter in a function signature
///
/// Corresponds to Ghidra's `ProtoParameter` class.
#[derive(Debug, Clone)]
pub struct ProtoParameter {
    /// Name of the parameter
    pub name: String,
    /// Data type of the parameter
    pub data_type: Arc<Datatype>,
    /// Storage location (register, stack offset, etc.)
    pub address: Address,
    /// Property flags
    pub flags: u32,
}

impl ProtoParameter {
    /// Create a new function parameter
    pub fn new(name: String, data_type: Arc<Datatype>, address: Address) -> Self {
        Self {
            name,
            data_type,
            address,
            flags: 0,
        }
    }

    /// Returns true if this parameter is a "this" pointer
    pub fn is_this_pointer(&self) -> bool {
        (self.flags & protoparam_flags::THIS_POINTER) != 0
    }

    /// Returns true if the type is locked (user-defined)
    pub fn is_type_locked(&self) -> bool {
        (self.flags & protoparam_flags::TYPE_LOCKED) != 0
    }
}

/// A formal function prototype
///
/// Corresponds to Ghidra's `FuncProto` class. It defines the return type,
/// parameters, and calling convention of a function.
#[derive(Debug, Clone)]
pub struct FuncProto {
    /// Name of the function (optional, can be empty for anonymous signatures)
    pub name: String,
    /// Return type of the function
    pub return_type: Arc<Datatype>,
    /// List of formal parameters
    pub parameters: Vec<ProtoParameter>,
    /// Calling convention name (e.g., "__stdcall", "__cdecl")
    pub calling_convention: String,
    /// True if the function accepts variable arguments (...)
    pub is_dotdotdot: bool,
}

impl FuncProto {
    /// Create a new function prototype
    pub fn new(name: String, return_type: Arc<Datatype>) -> Self {
        Self {
            name,
            return_type,
            parameters: Vec::new(),
            calling_convention: "unknown".to_string(),
            is_dotdotdot: false,
        }
    }

    /// Add a parameter to the prototype
    pub fn add_parameter(&mut self, param: ProtoParameter) {
        self.parameters.push(param);
    }

    /// Get the number of parameters
    pub fn num_params(&self) -> usize {
        self.parameters.len()
    }

    /// Get a parameter by index
    pub fn get_param(&self, index: usize) -> Option<&ProtoParameter> {
        self.parameters.get(index)
    }
}

/// Specification for a specific function call site
///
/// Corresponds to Ghidra's `FuncCallSpecs` class.
#[derive(Debug, Clone)]
pub struct FuncCallSpecs {
    /// The address of the call instruction
    pub op_addr: Address,
    /// The destination address of the call (if known)
    pub entry_addr: Option<Address>,
    /// The prototype used at this call site
    pub prototype: FuncProto,
    /// Flags and other metadata
    pub flags: u32,
}

impl FuncCallSpecs {
    /// Create a new call specification
    pub fn new(op_addr: Address, prototype: FuncProto) -> Self {
        Self {
            op_addr,
            entry_addr: None,
            prototype,
            flags: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_system::datatype::{TypeBase, TypeMetatype};

    #[test]
    fn test_proto_creation() {
        let void_type = Arc::new(Datatype::Void(TypeBase::new("void".to_string(), 0, TypeMetatype::Void)));
        let int_type = Arc::new(Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int)));

        let mut proto = FuncProto::new("test_func".to_string(), void_type);
        proto.add_parameter(ProtoParameter::new("a".to_string(), int_type, Address::new(0)));

        assert_eq!(proto.num_params(), 1);
        assert_eq!(proto.get_param(0).unwrap().name, "a");
    }
}
