//! Datatype definitions for Rugra's type system
//!
//! Corresponds to Ghidra's `type.hh`

use std::sync::{Arc, Weak};
use crate::address::Address;
use crate::fspec::FuncProto;

/// Stubs for related modules
pub mod stubs {
    #[derive(Debug)] pub struct Funcdata;
}

/// Categories of types (type_metatype in Ghidra)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TypeMetatype {
    Unknown = 0,
    Void = 1,
    Bool = 2,
    Int = 3,
    Uint = 4,
    Float = 5,
    Pointer = 6,
    Array = 7,
    Struct = 8,
    Union = 9,
    Enum = 10,
    Code = 11,
    Spacebase = 12,
}

/// Flags for Datatype properties (corresponds to flags in type.hh)
pub mod type_flags {
    pub const CORETYPE: u32 = 1 << 0;
    pub const CHARTYPE: u32 = 1 << 1;
    pub const ENUMTYPE: u32 = 1 << 2;
    pub const TYPEDEF: u32 = 1 << 3;
    pub const VARLENGTH: u32 = 1 << 4;
    pub const UTF16: u32 = 1 << 5;
    pub const UTF32: u32 = 1 << 6;
    pub const OPAQUE_STRUCT: u32 = 1 << 7;
}

/// A single field within a structure or union
///
/// Corresponds to Ghidra's `TypeField` class in `type.hh`
#[derive(Debug, Clone)]
pub struct TypeField {
    pub name: String,
    pub offset: usize,
    pub type_ptr: Arc<Datatype>,
}

/// Base structure for all data types containing common fields
#[derive(Debug, Clone)]
pub struct TypeBase {
    pub name: String,
    pub size: usize,
    pub metatype: TypeMetatype,
    pub id: u64,
    pub flags: u32,
}

impl TypeBase {
    pub fn new(name: String, size: usize, metatype: TypeMetatype) -> Self {
        Self {
            name,
            size,
            metatype,
            id: 0,
            flags: 0,
        }
    }
}

/// Represents a data type in the decompiler
///
/// Corresponds to Ghidra's `Datatype` class hierarchy in `type.hh`
#[derive(Debug, Clone)]
pub enum Datatype {
    Void(TypeBase),
    Base(TypeBase), // Used for Int, Uint, Float, Bool, Char, Unicode
    Pointer(TypePointer),
    Array(TypeArray),
    Struct(TypeStruct),
    Enum(TypeEnum),
    Union(TypeUnion),
    Code(TypeCode),
    Spacebase(TypeSpacebase),
}

impl Datatype {
    /// Get the name of the data type
    pub fn get_name(&self) -> &str {
        match self {
            Datatype::Void(b) => &b.name,
            Datatype::Base(b) => &b.name,
            Datatype::Pointer(p) => &p.base.name,
            Datatype::Array(a) => &a.base.name,
            Datatype::Struct(s) => &s.base.name,
            Datatype::Enum(e) => &e.base.name,
            Datatype::Union(u) => &u.base.name,
            Datatype::Code(c) => &c.base.name,
            Datatype::Spacebase(s) => &s.base.name,
        }
    }

    /// Get the size of the data type in bytes
    pub fn get_size(&self) -> usize {
        match self {
            Datatype::Void(b) => b.size,
            Datatype::Base(b) => b.size,
            Datatype::Pointer(p) => p.base.size,
            Datatype::Array(a) => a.base.size,
            Datatype::Struct(s) => s.base.size,
            Datatype::Enum(e) => e.base.size,
            Datatype::Union(u) => u.base.size,
            Datatype::Code(c) => c.base.size,
            Datatype::Spacebase(s) => s.base.size,
        }
    }

    /// Get the metatype of the data type
    pub fn get_metatype(&self) -> TypeMetatype {
        match self {
            Datatype::Void(b) => b.metatype,
            Datatype::Base(b) => b.metatype,
            Datatype::Pointer(p) => p.base.metatype,
            Datatype::Array(a) => a.base.metatype,
            Datatype::Struct(s) => s.base.metatype,
            Datatype::Enum(e) => e.base.metatype,
            Datatype::Union(u) => u.base.metatype,
            Datatype::Code(c) => c.base.metatype,
            Datatype::Spacebase(s) => s.base.metatype,
        }
    }

    /// Get the unique ID of the data type
    pub fn get_id(&self) -> u64 {
        match self {
            Datatype::Void(b) => b.id,
            Datatype::Base(b) => b.id,
            Datatype::Pointer(p) => p.base.id,
            Datatype::Array(a) => a.base.id,
            Datatype::Struct(s) => s.base.id,
            Datatype::Enum(e) => e.base.id,
            Datatype::Union(u) => u.base.id,
            Datatype::Code(c) => c.base.id,
            Datatype::Spacebase(s) => s.base.id,
        }
    }

    /// Returns true if this is a core type
    pub fn is_coretype(&self) -> bool {
        (self.get_flags() & type_flags::CORETYPE) != 0
    }

    /// Returns true if this type has a variable length
    pub fn is_variable_length(&self) -> bool {
        (self.get_flags() & type_flags::VARLENGTH) != 0
    }

    /// Get the internal flags of the data type
    pub fn get_flags(&self) -> u32 {
        match self {
            Datatype::Void(b) => b.flags,
            Datatype::Base(b) => b.flags,
            Datatype::Pointer(p) => p.base.flags,
            Datatype::Array(a) => a.base.flags,
            Datatype::Struct(s) => s.base.flags,
            Datatype::Enum(e) => e.base.flags,
            Datatype::Union(u) => u.base.flags,
            Datatype::Code(c) => c.base.flags,
            Datatype::Spacebase(s) => s.base.flags,
        }
    }
}

/// Pointer data type
///
/// Corresponds to Ghidra's `TypePointer` class in `type.hh`
#[derive(Debug, Clone)]
pub struct TypePointer {
    pub base: TypeBase,
    pub ptr_to: Arc<Datatype>,
    pub wordsize: usize,
}

/// Array data type
///
/// Corresponds to Ghidra's `TypeArray` class in `type.hh`
#[derive(Debug, Clone)]
pub struct TypeArray {
    pub base: TypeBase,
    pub array_of: Arc<Datatype>,
    pub num_elements: usize,
}

/// Structure data type
///
/// Corresponds to Ghidra's `TypeStruct` class in `type.hh`
#[derive(Debug, Clone)]
pub struct TypeStruct {
    pub base: TypeBase,
    pub fields: Vec<TypeField>,
}

/// Enumeration data type
///
/// Corresponds to Ghidra's `TypeEnum` class in `type.hh`
#[derive(Debug, Clone)]
pub struct TypeEnum {
    pub base: TypeBase,
    pub values: std::collections::BTreeMap<u64, String>,
}

/// Union data type
///
/// Corresponds to Ghidra's `TypeUnion` class in `type.hh`
#[derive(Debug, Clone)]
pub struct TypeUnion {
    pub base: TypeBase,
    pub fields: Vec<TypeField>,
}

/// Code/Function data type
///
/// Corresponds to Ghidra's `TypeCode` class in `type.hh`
#[derive(Debug, Clone)]
pub struct TypeCode {
    pub base: TypeBase,
    /// Function prototype associated with this code type
    pub proto: Option<Arc<FuncProto>>,
}

/// Type representing a spacebase (e.g. stack frame, register bank)
///
/// Corresponds to Ghidra's `TypeSpacebase` class in `type.hh`
#[derive(Debug, Clone)]
pub struct TypeSpacebase {
    pub base: TypeBase,
    pub address: Address,
    /// Associated function data (if this spacebase is a stack frame)
    pub fd: Option<Weak<stubs::Funcdata>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_types() {
        let base = TypeBase::new("int".to_string(), 4, TypeMetatype::Int);
        let dt = Datatype::Base(base);
        assert_eq!(dt.get_name(), "int");
        assert_eq!(dt.get_size(), 4);
        assert_eq!(dt.get_metatype(), TypeMetatype::Int);
    }

    #[test]
    fn test_pointer_type() {
        let int_base = TypeBase::new("int".to_string(), 4, TypeMetatype::Int);
        let int_dt = Arc::new(Datatype::Base(int_base));

        let ptr_base = TypeBase::new("int *".to_string(), 8, TypeMetatype::Pointer);
        let ptr_dt = Datatype::Pointer(TypePointer {
            base: ptr_base,
            ptr_to: int_dt,
            wordsize: 1,
        });

        assert_eq!(ptr_dt.get_name(), "int *");
        assert_eq!(ptr_dt.get_size(), 8);
        assert_eq!(ptr_dt.get_metatype(), TypeMetatype::Pointer);
    }
}
