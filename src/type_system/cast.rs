//! Type casting and promotion strategies
//!
//! Corresponds to Ghidra's `cast.hh`. This module defines the rules
//! for when explicit casts are required in the output C code and how
//! types are promoted during arithmetic operations.

use std::sync::Arc;
use crate::type_system::datatype::{Datatype, TypeMetatype};

/// Interface for determining when a cast is necessary
///
/// Corresponds to Ghidra's `CastStrategy` class.
pub trait CastStrategy {
    /// Decide if an explicit cast is required between two types
    fn is_cast_implied(&self, out_type: &Datatype, in_type: &Datatype) -> bool;

    /// Get the type of a constant, given a specific size and output requirement
    fn cast_standard(&self, out_type: &Datatype, in_type: &Datatype) -> Option<Arc<Datatype>>;

    /// Determine if an integer promotion is required for an extension
    fn check_int_promotion_for_extension(&self, op_type: &Datatype) -> bool;

    /// Determine if an integer promotion is required for a comparison
    fn check_int_promotion_for_compare(&self, op_type: &Datatype) -> bool;
}

/// Standard C-language casting strategy
///
/// Corresponds to Ghidra's `CastStrategyC` class.
pub struct CastStrategyC {
    /// The size of an 'int' in the target architecture
    promote_size: usize,
}

impl CastStrategyC {
    pub fn new(promote_size: usize) -> Self {
        Self { promote_size }
    }

    /// Check if the type is a character type
    fn is_char_type(&self, dt: &Datatype) -> bool {
        // In Rugra, this would check the CHARTYPE flag in TypeBase
        (dt.get_flags() & crate::type_system::datatype::type_flags::CHARTYPE) != 0
    }

    /// Check if the type is an enumeration type
    fn is_enum_type(&self, dt: &Datatype) -> bool {
        matches!(dt.get_metatype(), TypeMetatype::Enum)
    }
}

impl CastStrategy for CastStrategyC {
    fn is_cast_implied(&self, out_type: &Datatype, in_type: &Datatype) -> bool {
        if Arc::ptr_eq(&Arc::new(out_type.clone()), &Arc::new(in_type.clone())) {
            return true;
        }

        let out_meta = out_type.get_metatype();
        let in_meta = in_type.get_metatype();

        if out_meta == in_meta {
            match out_meta {
                TypeMetatype::Int | TypeMetatype::Uint | TypeMetatype::Bool => {
                    // Implied if output is at least as large as input
                    return out_type.get_size() >= in_type.get_size();
                }
                TypeMetatype::Pointer => {
                    // Pointers usually need explicit casts unless they are the same
                    // or one is void* (not fully implemented here)
                    return false;
                }
                _ => return false,
            }
        }

        // C allows implicit conversion from array to pointer
        if out_meta == TypeMetatype::Pointer && in_meta == TypeMetatype::Array {
            return true;
        }

        // Pointer to boolean (e.g. if (ptr))
        if out_meta == TypeMetatype::Bool && in_meta == TypeMetatype::Pointer {
            return true;
        }

        false
    }

    fn cast_standard(&self, out_type: &Datatype, in_type: &Datatype) -> Option<Arc<Datatype>> {
        if self.is_cast_implied(out_type, in_type) {
            return None;
        }
        Some(Arc::new(out_type.clone()))
    }

    fn check_int_promotion_for_extension(&self, op_type: &Datatype) -> bool {
        let size = op_type.get_size();
        if size >= self.promote_size {
            return false;
        }
        let meta = op_type.get_metatype();
        // Small integers, booleans, and enums are promoted in C
        matches!(meta, TypeMetatype::Int | TypeMetatype::Uint | TypeMetatype::Bool | TypeMetatype::Enum)
    }

    fn check_int_promotion_for_compare(&self, op_type: &Datatype) -> bool {
        let size = op_type.get_size();
        if size >= self.promote_size {
            return false;
        }
        let meta = op_type.get_metatype();
        // Comparison also triggers promotion for small types
        matches!(meta, TypeMetatype::Int | TypeMetatype::Uint | TypeMetatype::Bool | TypeMetatype::Enum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_system::datatype::{TypeBase, TypeMetatype, Datatype};

    #[test]
    fn test_c_implied_cast() {
        let strategy = CastStrategyC::new(4);

        let int4 = Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int));
        let int2 = Datatype::Base(TypeBase::new("short".to_string(), 2, TypeMetatype::Int));

        // short to int is implied
        assert!(strategy.is_cast_implied(&int4, &int2));
        // int to short requires cast
        assert!(!strategy.is_cast_implied(&int2, &int4));
    }

    #[test]
    fn test_c_promotion() {
        let strategy = CastStrategyC::new(4);

        let int1 = Datatype::Base(TypeBase::new("char".to_string(), 1, TypeMetatype::Int));
        let int4 = Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int));

        // char is promoted
        assert!(strategy.check_int_promotion_for_extension(&int1));
        // int is not promoted (already at promote size)
        assert!(!strategy.check_int_promotion_for_extension(&int4));
    }
}
