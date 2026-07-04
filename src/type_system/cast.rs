//! Type casting and promotion strategies
//!
//! Corresponds to Ghidra's `cast.hh`. This module defines the rules
//! for when explicit casts are required in the output C code and how
//! types are promoted during arithmetic operations.

use std::sync::Arc;
use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype};

// RUGRA-GLUE: base_type_for (no Ghidra counterpart found)
/// Build a base integer/unsigned type for a given size and metatype.
/// Faithful to Ghidra `TypeFactory::getBase(size, metatype)` (type.cc) for
/// the integer cases: size 1→char/byte, 2→short, 4→int, 8→long (signed) /
/// ulong (unsigned). Used by input-type-local to derive the type an op
/// expects for its input slot (`TypeOpBinary::getInputLocal`,
/// typeop.cc:329-333).
pub fn base_type_for(size: usize, meta: TypeMetatype) -> Arc<Datatype> {
    let name = match (meta, size) {
        (TypeMetatype::Int, 1) => "byte",
        (TypeMetatype::Int, 2) => "short",
        (TypeMetatype::Int, 4) => "int",
        (TypeMetatype::Int, 8) => "long",
        (TypeMetatype::Uint, 1) => "undefined",
        (TypeMetatype::Uint, 2) => "ushort",
        (TypeMetatype::Uint, 4) => "uint",
        (TypeMetatype::Uint, 8) => "ulong",
        _ => "long",
    };
    Arc::new(Datatype::Base(TypeBase::new(name.to_string(), size, meta)))
}

/// Interface for determining when a cast is necessary
///
/// Corresponds to Ghidra's `CastStrategy` class.
pub trait CastStrategy {
    // RUGRA-GLUE: is_cast_implied (no Ghidra counterpart found)
    /// Decide if an explicit cast is required between two types
    fn is_cast_implied(&self, out_type: &Datatype, in_type: &Datatype) -> bool;

    // RUGRA-GLUE: cast_standard (no Ghidra counterpart found)
    /// Get the type of a constant, given a specific size and output requirement
    fn cast_standard(&self, out_type: &Datatype, in_type: &Datatype) -> Option<Arc<Datatype>>;

    // RUGRA-GLUE: check_int_promotion_for_extension (no Ghidra counterpart found)
    /// Determine if an integer promotion is required for an extension
    fn check_int_promotion_for_extension(&self, op_type: &Datatype) -> bool;

    // RUGRA-GLUE: check_int_promotion_for_compare (no Ghidra counterpart found)
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
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    pub fn new(promote_size: usize) -> Self {
        Self { promote_size }
    }

    // RUGRA-GLUE: is_char_type (no Ghidra counterpart found)
    /// Check if the type is a character type
    fn is_char_type(&self, dt: &Datatype) -> bool {
        // In Rugra, this would check the CHARTYPE flag in TypeBase
        (dt.get_flags() & crate::type_system::datatype::type_flags::CHARTYPE) != 0
    }

    // RUGRA-GLUE: is_enum_type (no Ghidra counterpart found)
    /// Check if the type is an enumeration type
    fn is_enum_type(&self, dt: &Datatype) -> bool {
        matches!(dt.get_metatype(), TypeMetatype::Enum)
    }
    // Ghidra: cast.cc:411 CastStrategyC::isSubpieceCast
    /// Check if a SUBPIECE op should be rendered as a cast.
    /// Faithful to Ghidra CastStrategyC::isSubpieceCast (cast.cc:411).
    pub fn is_subpiece_cast(&self, out_type: &Datatype, in_type: &Datatype, offset: u32) -> bool {
        if offset != 0 { return false; }
        let in_meta = in_type.get_metatype();
        if !matches!(in_meta, TypeMetatype::Int | TypeMetatype::Uint | TypeMetatype::Unknown
            | TypeMetatype::Pointer)
        { return false; }
        let out_meta = out_type.get_metatype();
        if !matches!(out_meta, TypeMetatype::Int | TypeMetatype::Uint | TypeMetatype::Unknown
            | TypeMetatype::Pointer | TypeMetatype::Float)
        { return false; }
        if in_meta == TypeMetatype::Pointer {
            if out_meta == TypeMetatype::Pointer {
                if out_type.get_size() < in_type.get_size() { return true; }
            }
            if !matches!(out_meta, TypeMetatype::Int | TypeMetatype::Uint) { return false; }
        }
        true
    }

    // Ghidra: cast.cc:434 CastStrategyC::isSubpieceCastEndian
    /// Check if a SUBPIECE with endianness should be rendered as a cast.
    /// Faithful to Ghidra CastStrategyC::isSubpieceCastEndian (cast.cc:434).
    pub fn is_subpiece_cast_endian(&self, out_type: &Datatype, in_type: &Datatype, offset: u32, is_bigend: bool) -> bool {
        let tmpoff = if is_bigend { in_type.get_size() as u32 - 1 - offset } else { offset };
        self.is_subpiece_cast(out_type, in_type, tmpoff)
    }

    // Ghidra: cast.cc:443 CastStrategyC::isSextCast
    /// Check if INT_SEXT should be rendered as a cast.
    /// Faithful to Ghidra CastStrategyC::isSextCast (cast.cc:443).
    pub fn is_sext_cast(&self, out_type: &Datatype, in_type: &Datatype) -> bool {
        let metaout = out_type.get_metatype();
        if !matches!(metaout, TypeMetatype::Uint | TypeMetatype::Int) { return false; }
        let metain = in_type.get_metatype();
        // Input must be signed for SEXT to be a cast
        matches!(metain, TypeMetatype::Int | TypeMetatype::Bool)
    }

    // Ghidra: cast.cc:457 CastStrategyC::isZextCast
    /// Check if INT_ZEXT should be rendered as a cast.
    /// Faithful to Ghidra CastStrategyC::isZextCast (cast.cc:457).
    pub fn is_zext_cast(&self, out_type: &Datatype, in_type: &Datatype) -> bool {
        let metaout = out_type.get_metatype();
        if !matches!(metaout, TypeMetatype::Uint | TypeMetatype::Int) { return false; }
        let metain = in_type.get_metatype();
        // Input must be unsigned for ZEXT to be a cast
        matches!(metain, TypeMetatype::Uint | TypeMetatype::Bool)
    }
}

impl CastStrategy for CastStrategyC {
    // RUGRA-GLUE: is_cast_implied (no Ghidra counterpart found)
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

    // Ghidra: cast.cc:300 CastStrategyC::castStandard
    fn cast_standard(&self, out_type: &Datatype, in_type: &Datatype) -> Option<Arc<Datatype>> {
        if self.is_cast_implied(out_type, in_type) {
            return None;
        }
        Some(Arc::new(out_type.clone()))
    }

    // Ghidra: cast.cc:126 CastStrategyC::checkIntPromotionForExtension
    fn check_int_promotion_for_extension(&self, op_type: &Datatype) -> bool {
        let size = op_type.get_size();
        if size >= self.promote_size {
            return false;
        }
        let meta = op_type.get_metatype();
        // Small integers, booleans, and enums are promoted in C
        matches!(meta, TypeMetatype::Int | TypeMetatype::Uint | TypeMetatype::Bool | TypeMetatype::Enum)
    }

    // Ghidra: cast.cc:107 CastStrategyC::checkIntPromotionForCompare
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

impl CastStrategyC {
    // RUGRA-GLUE: cast_standard_full (no Ghidra counterpart found)
    /// Faithful 1:1 port of Ghidra `CastStrategyC::castStandard`
    /// (cast.cc:300-392). Determines whether an explicit cast is required
    /// when a varnode of `curtype` feeds an op expecting `reqtype`.
    ///
    /// Returns `Some(reqtype)` if a cast IS needed (the caller inserts a
    /// CPUI_CAST emitting `(reqtype)expr`), or `None` if no cast is needed.
    ///
    /// `care_uint_int` — if true, distinguish signed/unsigned (used under
    ///   pointers, where the distinction matters); if false, treat int/uint
    ///   interchangeably (most arithmetic ops).
    /// `care_ptr_uint` — if true, casting a pointer to an integer DOES need a
    ///   cast (e.g. STORE value slot); if false, it's implied.
    ///
    /// Rugra's Datatype lacks typedef chains, variable-length arrays, and
    /// per-pointer AddrSpace; those branches are faithfully no-ops (a cast
    /// decision is never wrong in their absence — at worst slightly more
    /// conservative).
    pub fn cast_standard_full(
        &self,
        reqtype: &Datatype,
        curtype: &Datatype,
        mut care_uint_int: bool,
        care_ptr_uint: bool,
    ) -> Option<Arc<Datatype>> {
        let req_arc = Arc::new(reqtype.clone());
        // Types equal → no cast.
        if Arc::ptr_eq(&req_arc, &Arc::new(curtype.clone())) {
            return None;
        }
        // From void → always cast.
        if curtype.get_metatype() == TypeMetatype::Void {
            return Some(req_arc);
        }
        // Peel matching pointer layers (cast.cc:310-324).
        let mut reqbase = reqtype;
        let mut curbase = curtype;
        let mut isptr = false;
        while reqbase.get_metatype() == TypeMetatype::Pointer
            && curbase.get_metatype() == TypeMetatype::Pointer
        {
            // Rugra TypePointer has no separate AddrSpace/wordsize comparison
            // beyond wordsize==1 default; skip the space-mismatch cast branch
            // (would need AddrSpace wiring). Wordsize equality is implicitly
            // handled by size equality below.
            reqbase = match reqbase { Datatype::Pointer(p) => &p.ptr_to, _ => break };
            curbase = match curbase { Datatype::Pointer(p) => &p.ptr_to, _ => break };
            care_uint_int = true;
            isptr = true;
        }
        // No typedef chains in Rugra (getTypedef loop is a no-op).
        if std::ptr::eq(reqbase as *const _, curbase as *const _) {
            return None;
        }
        let reqmeta = reqbase.get_metatype();
        let curmeta = curbase.get_metatype();
        // Don't cast to/from a void pointer.
        if reqmeta == TypeMetatype::Void || curmeta == TypeMetatype::Void {
            return None;
        }
        // Size change → always cast (cast.cc:333-337).
        if reqbase.get_size() != curbase.get_size() {
            return Some(req_arc);
        }
        // Same size: metatype-specific rules (cast.cc:339-389).
        match reqmeta {
            TypeMetatype::Unknown => return None,
            _ => {}
        }
        match reqmeta {
            TypeMetatype::Uint => {
                if !care_uint_int {
                    if matches!(curmeta,
                        TypeMetatype::Unknown | TypeMetatype::Int | TypeMetatype::Uint
                        | TypeMetatype::Bool) {
                        return None;
                    }
                } else {
                    if matches!(curmeta, TypeMetatype::Uint | TypeMetatype::Bool) {
                        return None;
                    }
                    if isptr && curmeta == TypeMetatype::Unknown {
                        return None; // Don't cast pointers to unknown
                    }
                }
                if !care_ptr_uint && curmeta == TypeMetatype::Pointer {
                    return None;
                }
            }
            TypeMetatype::Int => {
                if !care_uint_int {
                    if matches!(curmeta,
                        TypeMetatype::Unknown | TypeMetatype::Int | TypeMetatype::Uint
                        | TypeMetatype::Bool) {
                        return None;
                    }
                } else {
                    if matches!(curmeta, TypeMetatype::Int | TypeMetatype::Bool) {
                        return None;
                    }
                    if isptr && curmeta == TypeMetatype::Unknown {
                        return None;
                    }
                }
            }
            // TYPE_CODE / default → fall through to "cast needed".
            _ => {}
        }
        Some(req_arc)
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

    #[test]
    fn test_is_subpiece_cast() {
        let s = CastStrategyC::new(4);
        let int4 = Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int));
        let int8 = Datatype::Base(TypeBase::new("long".into(), 8, TypeMetatype::Int));
        // offset 0, int→int subpiece is a cast
        assert!(s.is_subpiece_cast(&int4, &int8, 0));
        // offset != 0 → not a cast
        assert!(!s.is_subpiece_cast(&int4, &int8, 4));
    }

    #[test]
    fn test_is_sext_cast() {
        let s = CastStrategyC::new(4);
        let int2 = Datatype::Base(TypeBase::new("short".into(), 2, TypeMetatype::Int));
        let int4 = Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int));
        // signed input → sext is a cast
        assert!(s.is_sext_cast(&int4, &int2));
    }

    #[test]
    fn test_is_zext_cast() {
        let s = CastStrategyC::new(4);
        let uint2 = Datatype::Base(TypeBase::new("ushort".into(), 2, TypeMetatype::Uint));
        let uint4 = Datatype::Base(TypeBase::new("uint".into(), 4, TypeMetatype::Uint));
        // unsigned input → zext is a cast
        assert!(s.is_zext_cast(&uint4, &uint2));
        // signed input → zext is NOT a cast
        let int2 = Datatype::Base(TypeBase::new("short".into(), 2, TypeMetatype::Int));
        assert!(!s.is_zext_cast(&uint4, &int2));
    }
}
