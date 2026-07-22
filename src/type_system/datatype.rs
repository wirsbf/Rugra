//! Datatype definitions for Rugra's type system
//!
//! Corresponds to Ghidra's `type.hh`

use std::sync::{Arc, Weak};
use crate::address::Address;
use crate::fspec::FuncProto;
use crate::AddressSpace;

/// Stubs for related modules
pub mod stubs {
    #[derive(Debug)] pub struct Funcdata;
}

/// Categories of types (type_metatype in Ghidra)
///
/// Mirrors Ghidra's `type_metatype` (type.hh:79-98) discriminant set, including
/// the three `Partial*` specializations introduced by this alignment pass:
/// `TypePartialEnum`, `TypePartialStruct`, `TypePartialUnion`. Numeric values
/// are Rugra-private and do not match Ghidra 1:1 (Ghidra orders them so the
/// lowest number is the most specific); `type_order`/`compare` reproduce
/// Ghidra's precedence via explicit comparison, not via the discriminant value.
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
    /// Part of a structure/array, stored separately from the whole.
    /// Ghidra `TYPE_PARTIALSTRUCT` (type.hh:97).
    PartialStruct = 13,
    /// Part of an enumeration (specialization of TYPE_UINT).
    /// Ghidra `TYPE_PARTIALENUM` (type.hh:96).
    PartialEnum = 14,
    /// Part of a union. Ghidra `TYPE_PARTIALUNION` (type.hh:98).
    PartialUnion = 15,
}

/// Flags for Datatype properties (corresponds to the `Datatype` enum in
/// type.hh:169-186). Values mirror Ghidra exactly.
pub mod type_flags {
    pub const CORETYPE: u32 = 1 << 0;          // coretype
    pub const CHARTYPE: u32 = 1 << 1;          // chartype
    pub const ENUMTYPE: u32 = 1 << 2;          // enumtype
    pub const POWEROF2: u32 = 1 << 3;          // poweroftwo
    pub const UTF16: u32 = 1 << 4;             // utf16
    pub const UTF32: u32 = 1 << 5;             // utf32
    pub const OPAQUE_STRUCT: u32 = 1 << 6;     // opaque_string (mapped to OPAQUE_STRUCT)
    pub const VARLENGTH: u32 = 1 << 7;         // variable_length
    pub const HAS_STRIPPED: u32 = 1 << 8;      // has_stripped
    pub const IS_PTRREL: u32 = 1 << 9;         // is_ptrrel
    pub const TYPE_INCOMPLETE: u32 = 1 << 10;  // type_incomplete
    pub const NEEDS_RESOLUTION: u32 = 1 << 11; // needs_resolution
    // Bits 0x7000..0x8000 are `force_format` in Ghidra (3 display-format bits).
    // Bit 0x8000 is `truncate_bigendian`, 0x10000 is `pointer_to_array`,
    // 0x20000 is `warning_issued`. Ghidra has NO equate flag on Datatype —
    // equates are `EquateSymbol`s (database.hh:302). Rugra reserves a high
    // private bit (not conflicting with any Ghidra flag) to track an
    // equated-mark on the type for the print path.
    pub const EQUATED: u32 = 1 << 20; // Rugra-private (no Ghidra counterpart)

    // Kept for backward compatibility with earlier code (TYPEDEF alias).
    pub const TYPEDEF: u32 = VARLENGTH;
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
    // Ghidra: type.hh:332 TypeBase::new
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
    /// Part of a structure or array. Ghidra `TypePartialStruct`
    /// (type.hh:590). Holds a contiguous byte range `[offset, offset+size)`
    /// taken out of a containing struct/array, plus an optional "stripped"
    /// fallback used when a formal data-type is required.
    PartialStruct(TypePartialStruct),
    /// Part of an enumeration. Ghidra `TypePartialEnum` (type.hh:569).
    /// Specialises TypeEnum: holds a byte range of a parent enum and
    /// delegates `hasNamedValue`/`getMatches` (with the appropriate bit
    /// shift) to the parent.
    PartialEnum(TypePartialEnum),
    /// Part of a union. Ghidra `TypePartialUnion` (type.hh:616). Records
    /// that a Varnode lies inside a union Symbol at a byte offset that
    /// cannot yet be resolved to a single field; carries the union's
    /// resolve-truncation/findResolve machinery so a later flow-sensitive
    /// resolution can pin down the field.
    PartialUnion(TypePartialUnion),
}

impl Datatype {
    // Ghidra: type.hh:165 Datatype::getName
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
            Datatype::PartialStruct(ps) => &ps.base.name,
            Datatype::PartialEnum(pe) => &pe.base.name,
            Datatype::PartialUnion(pu) => &pu.base.name,
        }
    }

    // Ghidra: type.hh:165 Datatype::getSize
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
            Datatype::PartialStruct(ps) => ps.base.size,
            Datatype::PartialEnum(pe) => pe.base.size,
            Datatype::PartialUnion(pu) => pu.base.size,
        }
    }

    // Ghidra: type.hh:165 Datatype::getMetatype
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
            Datatype::PartialStruct(ps) => ps.base.metatype,
            Datatype::PartialEnum(pe) => pe.base.metatype,
            Datatype::PartialUnion(pu) => pu.base.metatype,
        }
    }

    // Ghidra: type.hh:165 Datatype::getId
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
            Datatype::PartialStruct(ps) => ps.base.id,
            Datatype::PartialEnum(pe) => pe.base.id,
            Datatype::PartialUnion(pu) => pu.base.id,
        }
    }

    // Ghidra: type.hh:165 Datatype::isCoretype
    /// Returns true if this is a core type
    pub fn is_coretype(&self) -> bool {
        (self.get_flags() & type_flags::CORETYPE) != 0
    }

    // Ghidra: type.hh:165 Datatype::isVariableLength
    /// Returns true if this type has a variable length
    pub fn is_variable_length(&self) -> bool {
        (self.get_flags() & type_flags::VARLENGTH) != 0
    }

    // Ghidra: type.hh:165 Datatype::isCharPrint
    /// Should this type be printed as a character/string type?
    /// Faithful to `Datatype::isCharPrint` (type.hh:218). Ghidra checks
    /// flags (chartype|utf16|utf32|opaque_string). Rugra maps opaque_string
    /// to OPAQUE_STRUCT.
    pub fn is_char_print(&self) -> bool {
        let f = self.get_flags();
        (f & (type_flags::CHARTYPE | type_flags::UTF16 | type_flags::UTF32 | type_flags::OPAQUE_STRUCT))
            != 0
    }

    // Ghidra: type.hh:929 Datatype::isPieceStructured
    /// Is this a structured type composed of pieces (struct/union/array)?
    /// Faithful to `Datatype::isPieceStructured` (type.hh:929-935). Ghidra
    /// checks `metatype <= TYPE_ARRAY`; Rugra's enum values differ so we use
    /// a semantic match.
    pub fn is_piece_structured(&self) -> bool {
        matches!(
            self.get_metatype(),
            TypeMetatype::Struct | TypeMetatype::Union | TypeMetatype::Array
        )
    }

    // Ghidra: type.hh:165 Datatype::getFlags
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
            Datatype::PartialStruct(ps) => ps.base.flags,
            Datatype::PartialEnum(pe) => pe.base.flags,
            Datatype::PartialUnion(pu) => pu.base.flags,
        }
    }

    // Ghidra: type.hh:165 Datatype::getAlignment
    /// Get the expected byte alignment of this data-type.
    /// Corresponds to Ghidra's `Datatype::getAlignment` (type.hh:241).
    ///
    /// For base types, alignment is derived from the size via Ghidra's
    /// default `size_alignment_map` (type.cc:4649):
    ///   size→align: {0:1, 1:1, 2:2, 3:2, 4:4, 5:4, 6:4, 7:4, 8+:8}
    /// For arrays, alignment = element alignment (type.cc:1340).
    /// For structs/unions, alignment is the max of field alignments
    /// (type.cc setFields), but since Rugra does not store alignment on
    /// the type, we derive it from size for those as a faithful fallback.
    pub fn get_alignment(&self) -> usize {
        primitive_alignment(self.get_size())
    }

    // Ghidra: type.hh:165 Datatype::getAlignSize
    /// Get the size rounded up to a multiple of the alignment.
    /// Corresponds to Ghidra's `Datatype::getAlignSize` (type.hh:240) and
    /// `TypeFactory::getPrimitiveAlignSize` (type.cc:3312).
    ///
    /// For composite types this equals `calcAlignSize(size, alignment)`
    /// (type.cc:536); for base types it equals `getPrimitiveAlignSize(size)`.
    /// We compute it uniformly as `size` rounded up to `get_alignment()`.
    pub fn get_align_size(&self) -> usize {
        let sz = self.get_size();
        let align = self.get_alignment();
        calc_align_size(sz, align)
    }

    // Ghidra: type.cc:174 Datatype::getSubType
    /// Recover the component data-type one level down at the given offset.
    /// Corresponds to Ghidra's `Datatype::getSubType` (type.hh:247).
    ///
    /// On entry `off` is an offset into this data-type. If this type has an
    /// interior structure (struct/union/array/pointer), the field/element
    /// containing `off` is returned and `newoff` is set to the offset within
    /// that component. Otherwise `None` is returned and `newoff` is set to
    /// `off` unchanged (type.cc:174 base behaviour).
    ///
    /// Returns `(Some(component), newoff)` or `(None, off)`.
    pub fn get_sub_type(&self, off: i64) -> (Option<&Datatype>, i64) {
        match self {
            Datatype::Struct(s) => struct_get_sub_type(s, off),
            Datatype::Union(u) => {
                // Union fields all start at offset 0 (type.cc TypeUnion).
                // Find a field whose type contains off; pass offset through.
                if off < 0 {
                    return (None, off);
                }
                for f in &u.fields {
                    if (off as usize) < f.type_ptr.get_size() {
                        return (Some(f.type_ptr.as_ref()), off);
                    }
                }
                (None, off)
            }
            Datatype::Array(a) => {
                // type.cc:1234 — one level down to element type.
                let sz = a.base.size as i64;
                if off >= sz {
                    return (None, off);
                }
                let elem_align = a.array_of.get_align_size().max(1) as i64;
                let newoff = off % elem_align;
                (Some(a.array_of.as_ref()), newoff)
            }
            // Pointer: Ghidra has a `truncate` field we do not model, so it
            // falls through to the base behaviour (type.cc:920).
            // PartialEnum/PartialUnion fall through to base (no sub-type walk);
            // PartialStruct has its own override on the variant struct.
            Datatype::Pointer(_) | Datatype::Void(_) | Datatype::Base(_)
            | Datatype::Enum(_) | Datatype::Code(_) | Datatype::Spacebase(_)
            | Datatype::PartialEnum(_) | Datatype::PartialUnion(_) => (None, off),
            // TypePartialStruct override (type.cc:2363): walk down the container
            // until the component no longer overruns the partial's size.
            Datatype::PartialStruct(ps) => partial_struct_get_sub_type(ps, off),
        }
    }

    // Ghidra: type.hh:165 Datatype::getHoleSize
    /// For the given offset, return the number of bytes at that offset that are
    /// padding / a "hole". Corresponds to Ghidra's `Datatype::getHoleSize`.
    ///
    /// For structs: distance to the following field or end (type.cc:1652).
    /// For arrays: delegates to element (type.cc:1243).
    /// Base: returns the remaining size from off.
    pub fn get_hole_size(&self, off: i64) -> i64 {
        match self {
            Datatype::Struct(s) => struct_get_hole_size(s, off),
            Datatype::Array(a) => {
                let elem_align = a.array_of.get_align_size().max(1) as i64;
                let new_off = off % elem_align;
                a.array_of.get_hole_size(new_off)
            }
            // TypePartialStruct override (type.cc:2379): delegate to container
            // then clamp to the remaining size of the partial.
            Datatype::PartialStruct(ps) => partial_struct_get_hole_size(ps, off),
            _ => {
                let sz = self.get_size() as i64;
                if off < 0 || off >= sz {
                    0
                } else {
                    sz - off
                }
            }
        }
    }

    // Ghidra: type.hh:165 Datatype::typeOrder
    /// Order this data-type with `other`. Negative if `self < other`,
    /// zero if equal, positive if `self > other`.
    /// Corresponds to Ghidra's `Datatype::typeOrder` (type.hh:283), which is a
    /// thin wrapper over `Datatype::compare` (type.cc:212):
    ///   - compare submeta (metatype), then size.
    /// Used by varmap `RangeHint::preferred` to prefer more specific types.
    pub fn type_order(&self, other: &Datatype) -> i32 {
        // Identity shortcut (type.hh:283).
        if std::ptr::eq(self, other) {
            return 0;
        }
        // metatype (submeta) ordering first.
        let mt_a = self.get_metatype() as u8;
        let mt_b = other.get_metatype() as u8;
        if mt_a != mt_b {
            return if mt_a < mt_b { -1 } else { 1 };
        }
        // Then size: Ghidra returns (op.size - size), i.e. smaller size first.
        let sa = self.get_size();
        let sb = other.get_size();
        (sb as i32) - (sa as i32)
    }

    // Ghidra: type.hh:916 Datatype::typeOrderBool
    /// Like `type_order` but treat Bool specially (never prefer bool).
    /// Corresponds to Ghidra's `Datatype::typeOrderBool` (type.hh:916).
    pub fn type_order_bool(&self, other: &Datatype) -> i32 {
        if std::ptr::eq(self, other) {
            return 0;
        }
        if self.get_metatype() == TypeMetatype::Bool {
            return 1;
        }
        if other.get_metatype() == TypeMetatype::Bool {
            return -1;
        }
        self.type_order(other)
    }

    // Ghidra: type.cc:212 Datatype::compare
    /// Compare two datatypes for structural equality.
    /// Faithful to Datatype::compare (type.cc:212).
    pub fn compare(&self, other: &Datatype) -> i32 {
        let self_meta = self.get_metatype() as i32;
        let other_meta = other.get_metatype() as i32;
        if self_meta != other_meta { return self_meta - other_meta; }
        let self_size = self.get_size() as i32;
        let other_size = other.get_size() as i32;
        if self_size != other_size { return self_size - other_size; }
        match self.get_name().cmp(other.get_name()) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Greater => 1,
            std::cmp::Ordering::Equal => 0,
        }
    }

    // Ghidra: type.hh:273 Datatype::printNameBase
    // Ghidra: type.hh:424 TypePointer::printNameBase
    // Ghidra: type.hh:457 TypeArray::printNameBase
    /// Write the type-indicator character(s) used to build variable name
    /// prefixes (e.g. "i" for int → "iVar", "pi" for int* → "piVar").
    /// Faithful to Ghidra's virtual dispatch:
    ///   - Base class (type.hh:273): `if (!name.empty()) s << name[0];`
    ///   - TypePointer (type.hh:424): `s << 'p'; ptrto->printNameBase(s);`
    ///   - TypeArray (type.hh:457): `s << 'a'; arrayof->printNameBase(s);`
    /// Rugra's enum dispatch mirrors the C++ virtual method resolution.
    pub fn print_name_base(&self, out: &mut String) {
        match self {
            Datatype::Pointer(p) => {
                out.push('p');
                p.ptr_to.print_name_base(out);
            }
            Datatype::Array(a) => {
                out.push('a');
                a.array_of.print_name_base(out);
            }
            _ => {
                let name = self.get_name();
                if let Some(c) = name.chars().next() {
                    out.push(c);
                }
            }
        }
    }

    // Ghidra: type.cc:227 Datatype::compareDependency
    /// Compare datatypes by dependency order.
    /// Faithful to Datatype::compareDependency (type.cc:227).
    pub fn compare_dependency(&self, other: &Datatype) -> i32 {
        self.compare(other)
    }

    // Ghidra: type.cc:561 Datatype::getStripped
    /// Get the "stripped" version (removes typedef wrappers).
    /// Faithful to Datatype::getStripped (type.cc:561-565). The base class
    /// returns null (here: `self`, matching the "no stripped form" intent);
    /// the partial-type overrides (TypePartialEnum::getStripped type.hh:586,
    /// TypePartialStruct::getStripped type.hh:607, TypePartialUnion::getStripped
    /// type.hh:635) return their `stripped` field. Rugra stores the optional
    /// stripped form on each partial variant.
    pub fn get_stripped(&self) -> &Datatype {
        match self {
            Datatype::PartialStruct(ps) => ps.stripped.as_deref().unwrap_or(self),
            Datatype::PartialEnum(pe) => pe.stripped.as_deref().unwrap_or(self),
            Datatype::PartialUnion(pu) => pu.stripped.as_deref().unwrap_or(self),
            _ => self,
        }
    }

    // Ghidra: type.hh:165 Datatype::needsResolution
    /// Return `true` if this data-type is a union or a pointer to a union
    /// (or otherwise needs resolution before propagation).
    /// Faithful to `Datatype::needsResolution` (type.hh:231).
    pub fn needs_resolution(&self) -> bool {
        (self.get_flags() & type_flags::NEEDS_RESOLUTION) != 0
    }

    // Ghidra: type.hh:165 Datatype::isEnumType
    /// Is this an enumerated type?
    /// Faithful to `Datatype::isEnumType` (type.hh:219): checks the
    /// `enumtype` flag. Note this is flag-based, not metatype-based, because
    /// in Ghidra an enum is internally a TypeBase with the enumtype flag set
    /// (type.hh:490-494), and partial-enum types share the flag.
    pub fn is_enum_type(&self) -> bool {
        (self.get_flags() & type_flags::ENUMTYPE) != 0
    }

    // Ghidra: type.hh:165 Datatype::hasStripped
    /// Has a stripped form for formal declarations?
    /// Faithful to `Datatype::hasStripped` (type.hh:229).
    pub fn has_stripped(&self) -> bool {
        (self.get_flags() & type_flags::HAS_STRIPPED) != 0
    }

    // Ghidra: type.cc:586 Datatype::findResolve
    /// The constant version of `resolve_in_flow`. If a resulting sub-type has
    /// already been calculated for the particular read (`slot >= 0`) or write
    /// (`slot == -1`), then return it; otherwise return the original
    /// data-type.
    ///
    /// Faithful to `Datatype::findResolve` (type.cc:586-590): the base class
    /// simply returns `self`. Subclass overrides (TypePointer, TypeArray,
    /// TypeStruct, TypeUnion) walk down to a resolved component; those are
    /// added on their respective variants. Here `op`/`slot` are taken as
    /// opaque `&PcodeOp`-style references — Rugra threads them as
    /// `Option<&op::PcodeOp>` so callers that do not have a concrete op can
    /// pass `None` and still get the base "return self" behaviour.
    pub fn find_resolve(&self, _op: Option<&crate::op::PcodeOp>, _slot: i32) -> &Datatype {
        // TypePartialUnion override (type.cc:2517) would walk the container
        // looking for a previously-resolved union field. Rugra does not yet
        // cache union resolutions on the Funcdata, so we fall back to the
        // base "return self" behaviour for partial unions as well.
        self
    }

    // Ghidra: type.hh:165 Datatype::markEquate
    /// Mark/unmark this data-type as equated. Ghidra has no
    /// `Datatype::markEquate`; equates are represented as `EquateSymbol`
    /// objects in a `Scope` (database.hh:302). Rugra mirrors the intent with
    /// a dedicated flag bit on the data-type so that print/format code can
    /// detect equated types without pulling in the full symbol machinery.
    /// Faithful in spirit to the equate handling in `printc.cc`/`varnode.cc`.
    pub fn mark_equate(&mut self) {
        self.set_flags_mut(type_flags::EQUATED);
    }

    // Ghidra: type.hh:165 Datatype::markUnEquate
    /// Clear the equate marker. See `mark_equate`.
    pub fn mark_un_equate(&mut self) {
        self.clear_flags_mut(type_flags::EQUATED);
    }

    // Ghidra: type.hh:165 Datatype::isEquated
    /// Has this data-type been marked equated? (Rugra-private, no Ghidra
    /// counterpart — see `mark_equate`.)
    pub fn is_equated(&self) -> bool {
        (self.get_flags() & type_flags::EQUATED) != 0
    }

    // Ghidra: type.hh:165 Datatype::setFlagsMut
    /// Internal: OR flags into the variant's `TypeBase.flags`.
    fn set_flags_mut(&mut self, bits: u32) {
        let f = self.base_mut();
        *f |= bits;
    }

    // Ghidra: type.hh:165 Datatype::clearFlagsMut
    /// Internal: AND-NOT flags out of the variant's `TypeBase.flags`.
    fn clear_flags_mut(&mut self, bits: u32) {
        let f = self.base_mut();
        *f &= !bits;
    }

    // Ghidra: type.hh:165 Datatype::baseMut
    /// Internal: mutable access to the underlying `TypeBase.flags` regardless
    /// of which variant `self` is.
    fn base_mut(&mut self) -> &mut u32 {
        match self {
            Datatype::Void(b) => &mut b.flags,
            Datatype::Base(b) => &mut b.flags,
            Datatype::Pointer(p) => &mut p.base.flags,
            Datatype::Array(a) => &mut a.base.flags,
            Datatype::Struct(s) => &mut s.base.flags,
            Datatype::Enum(e) => &mut e.base.flags,
            Datatype::Union(u) => &mut u.base.flags,
            Datatype::Code(c) => &mut c.base.flags,
            Datatype::Spacebase(s) => &mut s.base.flags,
            Datatype::PartialStruct(ps) => &mut ps.base.flags,
            Datatype::PartialEnum(pe) => &mut pe.base.flags,
            Datatype::PartialUnion(pu) => &mut pu.base.flags,
        }
    }

    // Ghidra: type.cc:501 Datatype::isPrimitiveWhole
    /// Check if this type occupies a whole primitive value.
    /// Faithful to Datatype::isPrimitiveWhole (type.cc:501).
    pub fn is_primitive_whole(&self) -> bool {
        matches!(self.get_metatype(),
            TypeMetatype::Int | TypeMetatype::Uint | TypeMetatype::Bool
            | TypeMetatype::Float)
    }

    // Ghidra: type.cc:139 Datatype::printRaw
    /// Print a raw representation for debugging.
    /// Faithful to Datatype::printRaw (type.cc:139) + the Partial* overrides
    /// (TypePartialEnum::printRaw type.cc:2264, TypePartialStruct::printRaw
    /// type.cc:2356, TypePartialUnion::printRaw type.cc:2433), which all
    /// render as `<parent.printRaw>[off=<offset>,sz=<size>]`.
    pub fn print_raw(&self) -> String {
        match self {
            Datatype::Void(_) => "void".into(),
            Datatype::Base(b) => b.name.clone(),
            Datatype::Pointer(p) => format!("{} *", p.ptr_to.print_raw()),
            Datatype::Array(a) => format!("{}[{}]", a.array_of.print_raw(), a.num_elements),
            Datatype::Struct(s) => {
                let fields: Vec<String> = s.fields.iter()
                    .map(|f| format!("{}+{}:{}", f.name, f.offset, f.type_ptr.print_raw()))
                    .collect();
                format!("struct{{{}}}", fields.join(","))
            }
            Datatype::Enum(e) => format!("enum {}", e.base.name),
            Datatype::Union(u) => format!("union {}", u.base.name),
            Datatype::Code(c) => format!("code {}", c.base.name),
            Datatype::Spacebase(s) => format!("spacebase {}", s.base.name),
            // Ghidra: type.cc:2264/2356/2433 — "<container>[off=<o>,sz=<s>]"
            Datatype::PartialStruct(ps) => format!(
                "{}[off={},sz={}]",
                ps.container.print_raw(),
                ps.offset,
                ps.base.size
            ),
            Datatype::PartialEnum(pe) => format!(
                "{}[off={},sz={}]",
                pe.parent.print_raw(),
                pe.offset,
                pe.base.size
            ),
            Datatype::PartialUnion(pu) => format!(
                "{}[off={},sz={}]",
                pu.container.print_raw(),
                pu.offset,
                pu.base.size
            ),
        }
    }
}

// Ghidra: type.cc:536 Datatype::calcAlignSize
/// Round `sz` up to a multiple of `align`. Corresponds to Ghidra's
/// `Datatype::calcAlignSize` (type.cc:536).
pub fn calc_align_size(sz: usize, align: usize) -> usize {
    if align == 0 {
        return sz;
    }
    let mod_ = sz % align;
    if mod_ != 0 {
        sz + (align - mod_)
    } else {
        sz
    }
}

// Ghidra: type.hh:165 Datatype::primitiveAlignment
/// Default primitive alignment for a given size, from Ghidra's
/// `setDefaultAlignmentMap` (type.cc:4649).
pub fn primitive_alignment(size: usize) -> usize {
    match size {
        0 => 1,
        1 => 1,
        2 => 2,
        3 => 2,
        4..=7 => 4,
        _ => 8,
    }
}

// Ghidra: type.hh:165 Datatype::structGetFieldIter
/// Find the field index in a struct containing `off`, or None if `off` is not
/// inside any field. Corresponds to Ghidra's `TypeStruct::getFieldIter`
/// (type.cc:1580). Fields are assumed sorted by offset.
fn struct_get_field_iter(s: &TypeStruct, off: i64) -> Option<usize> {
    if off < 0 {
        return None;
    }
    let off = off as usize;
    // Linear scan (structs are small); returns the highest-offset field that
    // starts at or before `off` and contains it within its size.
    let mut best: Option<usize> = None;
    for (i, f) in s.fields.iter().enumerate() {
        if f.offset <= off && off < f.offset + f.type_ptr.get_size() {
            best = Some(i);
        }
    }
    best
}

// Ghidra: type.hh:165 Datatype::structGetSubType
/// Struct subtype lookup. Corresponds to `TypeStruct::getSubType`
/// (type.cc:1640).
fn struct_get_sub_type(s: &TypeStruct, off: i64) -> (Option<&Datatype>, i64) {
    match struct_get_field_iter(s, off) {
        Some(i) => {
            let f = &s.fields[i];
            (Some(f.type_ptr.as_ref()), off - f.offset as i64)
        }
        None => (None, off),
    }
}

// Ghidra: type.hh:165 Datatype::structGetHoleSize
/// Struct hole size. Corresponds to `TypeStruct::getHoleSize` (type.cc:1652).
fn struct_get_hole_size(s: &TypeStruct, off: i64) -> i64 {
    if off < 0 {
        return 0;
    }
    let off_u = off as usize;
    // If inside a field, delegate to that field's hole size.
    if let Some(i) = struct_get_field_iter(s, off) {
        let f = &s.fields[i];
        let new_off = off_u - f.offset;
        if new_off < f.type_ptr.get_size() {
            return f.type_ptr.get_hole_size(new_off as i64);
        }
    }
    // Distance to the next field, or to the end of the struct.
    let mut next_field_offset: Option<usize> = None;
    for f in &s.fields {
        if f.offset > off_u {
            next_field_offset = Some(f.offset);
            break;
        }
    }
    match next_field_offset {
        Some(nfo) => (nfo - off_u) as i64,
        None => (s.base.size - off_u) as i64,
    }
}

// Ghidra: type.cc:2363 TypePartialStruct::getSubType
/// Walk the container's sub-types, advancing the offset by `offset`, until the
/// returned component no longer overruns this partial's size. Faithful to
/// `TypePartialStruct::getSubType` (type.cc:2363-2377).
fn partial_struct_get_sub_type(ps: &TypePartialStruct, off: i64) -> (Option<&Datatype>, i64) {
    let size_left = ps.base.size as i64 - off;
    let mut cur_off = off + ps.offset;
    let mut ct: &Datatype = ps.container.as_ref();
    // Ghidra's `do { ct = ct->getSubType(off,newoff); if null break; ... }
    // while(...)` reassigns ct at the top of the loop, so a null first lookup
    // yields a null result (NOT the container). We track `found` to mirror
    // that and to return the last successful sub-type + its newoff.
    let mut newoff = cur_off;
    let mut found = false;
    loop {
        let (sub, no) = ct.get_sub_type(cur_off);
        match sub {
            None => {
                // Datatype::getSubType base sets *newoff = off on null
                // (type.cc:177); honour that for the returned offset.
                newoff = no;
                break;
            }
            Some(s) => {
                ct = s;
                cur_off = no;
                newoff = no;
                found = true;
                // Component can extend beyond range of this partial, in which
                // case we go down another level (type.cc:2375).
                if ct.get_size() as i64 - cur_off <= size_left {
                    break;
                }
            }
        }
    }
    if found {
        (Some(ct), newoff)
    } else {
        (None, newoff)
    }
}

// Ghidra: type.cc:2379 TypePartialStruct::getHoleSize
/// Delegate to the container's hole size (at `offset + off`), clamped to the
/// remaining size of this partial. Faithful to `TypePartialStruct::getHoleSize`
/// (type.cc:2379-2388).
fn partial_struct_get_hole_size(ps: &TypePartialStruct, off: i64) -> i64 {
    let size_left = ps.base.size as i64 - off;
    let res = ps.container.get_hole_size(off + ps.offset);
    if res > size_left {
        size_left
    } else {
        res
    }
}

// Ghidra: type.cc:1354 TypeEnum::hasNamedValue
/// True if `parent` is an enum with a name for `val`. Delegates to the enum's
/// value map. Faithful to `TypeEnum::hasNamedValue` (type.cc:1354-1358):
/// `namemap.find(val) != namemap.end()`. For non-enum parents (which Ghidra
/// never constructs for a partial-enum), returns false.
fn enum_has_named_value(parent: &Datatype, val: u64) -> bool {
    if let Datatype::Enum(e) = parent {
        e.values.contains_key(&val)
    } else {
        false
    }
}

// Ghidra: type.cc:1365 TypeEnum::getMatches
/// Build the named representation of `val` by ORing enum names (with a
/// complement fallback). Faithful to `TypeEnum::getMatches`
/// (type.cc:1365-1414). This is the Representation-recovery algorithm used by
/// the decompiler's print path: it greedily matches the largest named enum
/// values covering the most-significant bits, falling back to the bitwise
/// complement of `val` for the second pass.
fn enum_get_matches(parent: &Datatype, val: u64, rep: &mut EnumRepresentation) {
    let e = match parent {
        Datatype::Enum(e) => e,
        // Non-enum parent (Ghidra never constructs this for a partial): leave
        // the representation empty, matching "no representation possible".
        _ => return,
    };
    let size = e.base.size;
    // calc_mask(size): low-order (size*8) bits all set.
    let mask: u64 = if size == 0 { 0 } else { if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 } };
    let mut cur_val = val;
    for count in 0..2 {
        let mut all_match = true;
        if cur_val == 0 {
            if let Some(nm) = e.values.get(&0u64) {
                rep.match_name.push(nm.clone());
            } else {
                all_match = false;
            }
        } else {
            let mut bits_left = cur_val;
            let mut target = cur_val;
            loop {
                if target == 0 {
                    break;
                }
                // Find the biggest named value <= target.
                // BTreeMap::range().next_back() returns Option<(&u64, &String)>.
                let (curval_ref, name) = match e.values.range(..=target).next_back() {
                    Some(pair) => pair,
                    None => { all_match = false; break; }
                };
                let curval = *curval_ref;
                // coveringmask(bitsleft ^ curval): mask of low bits where they
                // agree up to the highest set bit of the xor.
                let diff = covering_mask(bits_left ^ curval);
                if diff >= bits_left {
                    all_match = false;
                    break;
                }
                if (curval & diff) == 0 {
                    rep.match_name.push(name.clone());
                    bits_left ^= curval;
                    target = bits_left;
                } else {
                    // Restrict search to bits at or below `curval & ~diff`.
                    let new_target = curval & !diff;
                    if new_target == target {
                        all_match = false;
                        break;
                    }
                    target = new_target;
                }
            }
            all_match = all_match && bits_left == 0;
        }
        if all_match {
            rep.complement = count == 1;
            return;
        }
        cur_val ^= mask; // switch to the complement for the second pass
        rep.match_name.clear();
    }
    // No representation possible — match_name remains empty.
}

/// `coveringmask(xor)`: the smallest mask covering the low bits of `xor` up to
/// and including its most-significant set bit, i.e. `(1 << (msb+1)) - 1`.
/// Mirrors Ghidra's `coveringmask` utility (used by `TypeEnum::getMatches`).
fn covering_mask(xor: u64) -> u64 {
    if xor == 0 {
        return 0;
    }
    let msb = 63 - xor.leading_zeros();
    (1u64 << (msb + 1)) - 1
}

// Ghidra: type.hh:526/555 TypeStruct/TypeUnion::numDepend
/// Number of dependent component types of a union: `field.size()`.
/// Faithful to `TypeUnion::numDepend` (type.hh:555).
fn union_num_depend(container: &Datatype) -> usize {
    if let Datatype::Union(u) = container {
        u.fields.len()
    } else {
        0
    }
}

// Ghidra: type.hh:556 TypeUnion::getDepend
/// The `index`-th field type of a union: `field[index].type`. Faithful to
/// `TypeUnion::getDepend` (type.hh:556).
fn union_get_depend(container: &Datatype, index: usize) -> Option<Arc<Datatype>> {
    if let Datatype::Union(u) = container {
        u.fields.get(index).map(|f| f.type_ptr.clone())
    } else {
        None
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
/// Corresponds to Ghidra's `TypeSpacebase` class in `type.hh:721-746`.
/// A spacebase treats an `AddrSpace` as a "structure" indexed into by pointer
/// offsets, facilitating type propagation from local symbols into the stack
/// space and from global symbols into RAM.
#[derive(Debug, Clone)]
pub struct TypeSpacebase {
    pub base: TypeBase,
    pub address: Address,
    /// Associated function data (if this spacebase is a stack frame)
    pub fd: Option<Weak<stubs::Funcdata>>,
    /// The address space we are treating as a structure. Ghidra field
    /// `spaceid` (type.hh:723). Rugra stores an `Option` because the decode
    /// path (type.cc:3090) may leave it unset when no `Architecture` is wired
    /// up; `get_address`/`get_sub_type` honour Ghidra's "no spaceid ⇒ no
    /// resolution" contract by returning the identity/unknown result.
    pub spaceid: Option<AddressSpace>,
    /// Address of the function whose symbol table is indexed, or the
    /// "invalid" sentinel (all-zeros in Rugra's single-space model) for the
    /// global scope. Ghidra field `localframe` (type.hh:724). `is_invalid()`
    /// matches Ghidra's `Address::isInvalid()`.
    pub localframe: Address,
    /// Symbol table indexed by this spacebase, when available. Ghidra obtains
    /// this on demand via `glb->symboltab->getGlobalScope()` /
    /// `fd->getScopeLocal()` (type.cc:2935-2945 `getMap`); Rugra does not yet
    /// thread an `Architecture` object through every type, so the Scope is
    /// stored by reference and consulted lazily by `get_sub_type`. `None`
    /// mirrors Ghidra's "no map ⇒ TYPE_UNKNOWN" fallback (type.cc:2963-2965).
    pub scope: Option<Arc<crate::database::Scope>>,
}

impl TypeSpacebase {
    // RUGRA-GLUE: default fields for callers that build a spacebase without
    // the full Architecture wiring (matches Ghidra's decode-only constructor
    /// `TypeSpacebase(Architecture *g)` which leaves spaceid null). Produces
    /// a global spacebase at address 0 with no scope attached.
    pub fn new_global(address: Address) -> Self {
        let base = TypeBase::new(String::new(), 0, TypeMetatype::Spacebase);
        Self {
            base,
            address,
            fd: None,
            spaceid: None,
            localframe: Address::new(0),
            scope: None,
        }
    }

    /// Sentinel for "no localframe" / global spacebase. Matches Ghidra's
    /// `Address::isInvalid()` (address.hh) as used by `getMap`/`getAddress`.
    pub fn is_invalid(&self) -> bool {
        self.localframe.as_u64() == 0
    }

    // Ghidra: type.cc:2935 TypeSpacebase::getMap
    /// Get the symbol table indexed by this spacebase. Faithful to
    /// `TypeSpacebase::getMap` (type.cc:2935-2945): Ghidra returns the global
    /// scope, or — if `localframe` is valid — the function-local scope of the
    /// function at `localframe`. Rugra does not yet wire a global symbol table
    /// into every spacebase, so the stored `scope` reference is returned
    /// directly. `None` mirrors the "no architecture / no global scope" case.
    pub fn get_map(&self) -> Option<&Arc<crate::database::Scope>> {
        self.scope.as_ref()
    }

    // Ghidra: type.cc:3063 TypeSpacebase::getAddress
    /// Construct the `Address` referred to by a specific offset relative to a
    /// pointer of this type. Faithful to `TypeSpacebase::getAddress`
    /// (type.cc:3063-3071): for a global spacebase (`localframe` invalid)
    /// Ghidra forces `sz = -1` to skip full-encoding recovery; Rugra, lacking
    /// an `Architecture::resolveConstant`, returns the byte→address converted
    /// offset directly. `spaceid`, when present, converts `off` via
    /// `AddrSpace::byteToAddressInt(off, wordsize)` (= off * wordsize).
    pub fn get_address(&self, off: u64, _sz: i32, _point: Address) -> Address {
        let wordsize = self.spaceid.map(|s| s.word_size()).unwrap_or(1).max(1) as u64;
        Address::new(off.wrapping_mul(wordsize))
    }

    // Ghidra: type.cc:2947 TypeSpacebase::getSubType
    /// Recover the component data-type one level down at offset `off` by
    /// querying the indexed symbol table. Faithful to
    /// `TypeSpacebase::getSubType` (type.cc:2947-2969): converts `off` to an
    /// address unit, looks up the smallest containing `SymbolEntry`, and
    /// returns its symbol's type with the renormalized offset. With no scope
    /// attached (the common Rugra case today), returns `(None, off)` matching
    /// Ghidra's "no container ⇒ base behaviour".
    pub fn get_sub_type(&self, off: i64) -> (Option<Arc<Datatype>>, i64) {
        let scope = match self.get_map() {
            Some(s) => s.clone(),
            None => return (None, off),
        };
        let wordsize = self.spaceid.map(|s| s.word_size()).unwrap_or(1).max(1) as i64;
        // AddrSpace::byteToAddress(off, wordsize) (space.hh).
        let addr_off = off.wrapping_mul(wordsize) as u64;
        let addr = Address::new(addr_off);
        match scope.find_container(addr, 1) {
            Some(entry) => {
                // newoff = (addr - entry.addr) + entry.offset (type.cc:2967).
                let newoff = (addr.as_u64().wrapping_sub(entry.addr.as_u64()) as i64)
                    + entry.offset as i64;
                (entry.symbol.read().unwrap().get_type(), newoff)
            }
            None => (None, 0),
        }
    }

    // Ghidra: type.cc:3039 TypeSpacebase::compare
    /// Compare two spacebases. Faithful to `TypeSpacebase::compare`
    /// (type.cc:3039-3043): delegates to `compareDependency`.
    pub fn compare(&self, other: &TypeSpacebase) -> i32 {
        self.compare_dependency(other)
    }

    // Ghidra: type.cc:3045 TypeSpacebase::compareDependency
    /// Compare two spacebases for tree-structure ordering. Faithful to
    /// `TypeSpacebase::compareDependency` (type.cc:3045-3055): base comparison
    /// first, then `spaceid`, then `localframe` (only if not a global
    /// spacebase).
    pub fn compare_dependency(&self, other: &TypeSpacebase) -> i32 {
        // Base comparison: submeta(metatype), then size (Datatype::compareDependency).
        let self_meta = self.base.metatype as i32;
        let other_meta = other.base.metatype as i32;
        if self_meta != other_meta {
            return self_meta - other_meta;
        }
        let res = other.base.size as i32 - self.base.size as i32;
        if res != 0 {
            return res;
        }
        // spaceid comparison (type.cc:3051). Rugra has no pointer identity for
        // enums; use word_size as a proxy that distinguishes distinct spaces
        // in the common single-space model.
        let s_ws = self.spaceid.map(|s| s.word_size()).unwrap_or(0);
        let o_ws = other.spaceid.map(|s| s.word_size()).unwrap_or(0);
        if s_ws != o_ws {
            return if s_ws < o_ws { -1 } else { 1 };
        }
        // Global spacebase: localframe comparison skipped (type.cc:3052).
        if self.is_invalid() {
            return 0;
        }
        match self.localframe.as_u64().cmp(&other.localframe.as_u64()) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Greater => 1,
            std::cmp::Ordering::Equal => 0,
        }
    }
}

/// A data-type that holds part of a `TypeStruct` or `TypeArray`.
///
/// Ghidra `TypePartialStruct` (type.hh:590-608). Stores a contiguous byte
/// range `[offset, offset+size)` cut out of `container` (a struct or array),
/// plus an optional `stripped` fallback data-type used when a formal type is
/// required. Constructed by `TypeFactory::getTypePartialStruct` (type.cc:3929)
/// and consumed by `varmap.cc`/`printc.cc`/`ruleaction.cc` to represent
/// proto-partial Varnodes.
#[derive(Debug, Clone)]
pub struct TypePartialStruct {
    pub base: TypeBase,
    /// Parent structure or array of which `this` is a part. Ghidra field
    /// `container` (type.hh:593).
    pub container: Arc<Datatype>,
    /// Byte offset within `container` where this piece starts. Ghidra field
    /// `offset` (type.hh:594).
    pub offset: i64,
    /// The undefined data-type to use if a formal data-type is required.
    /// Ghidra field `stripped` (type.hh:592). `None` mirrors a null stripped
    /// pointer.
    pub stripped: Option<Arc<Datatype>>,
}

impl TypePartialStruct {
    // Ghidra: type.cc:2330 TypePartialStruct::TypePartialStruct
    /// Construct a partial-struct given the container, byte offset, size, and
    /// stripped fallback. Faithful to the C++ constructor
    /// (type.cc:2330-2341): sets `metatype = TYPE_PARTIALSTRUCT`, asserts the
    /// container is a struct or array (debug-only in C++; Rugra uses
    /// `debug_assert!`), and sets the `has_stripped` flag.
    pub fn new(
        container: Arc<Datatype>,
        offset: i64,
        size: usize,
        stripped: Option<Arc<Datatype>>,
    ) -> Self {
        debug_assert!(
            matches!(
                container.get_metatype(),
                TypeMetatype::Struct | TypeMetatype::Array
            ),
            "Parent of partial struct is not a structure or array"
        );
        let mut base = TypeBase::new(String::new(), size, TypeMetatype::PartialStruct);
        base.flags |= type_flags::HAS_STRIPPED;
        Self { base, container, offset, stripped }
    }

    // Ghidra: type.hh:598 TypePartialStruct::getOffset
    /// Byte offset into the containing data-type. (Inline in C++.)
    pub fn get_offset(&self) -> i64 { self.offset }

    // Ghidra: type.hh:599 TypePartialStruct::getParent
    /// Data-type containing this piece. (Inline in C++.)
    pub fn get_parent(&self) -> &Arc<Datatype> { &self.container }

    // Ghidra: type.hh:607 TypePartialStruct::getStripped
    /// The undefined data-type to use if a formal data-type is required.
    pub fn get_stripped(&self) -> Option<&Arc<Datatype>> { self.stripped.as_ref() }

    // Ghidra: type.cc:2345 TypePartialStruct::getComponentForPtr
    /// If the parent is an array, return the element data-type when the offset
    /// is element-aligned and the element is concrete; otherwise return the
    /// `stripped` data-type. Faithful to `getComponentForPtr`
    /// (type.cc:2345-2354).
    pub fn get_component_for_ptr(&self) -> Option<Arc<Datatype>> {
        if self.container.get_metatype() == TypeMetatype::Array {
            if let Datatype::Array(a) = self.container.as_ref() {
                let eltype = a.array_of.clone();
                if eltype.get_metatype() != TypeMetatype::Unknown
                    && (self.offset % eltype.get_align_size().max(1) as i64) == 0
                {
                    return Some(eltype);
                }
            }
        }
        self.stripped.clone()
    }

    // Ghidra: type.cc:2390 TypePartialStruct::compare
    /// Compare two partial-structs. Faithful to `TypePartialStruct::compare`
    /// (type.cc:2390-2404): base `Datatype::compare` first, then offset, then
    /// (if `level > 0`) the container.
    pub fn compare(&self, other: &TypePartialStruct, level: i32) -> i32 {
        // Base comparison (Datatype::compare): submeta, then size.
        let self_meta = self.base.metatype as i32;
        let other_meta = other.base.metatype as i32;
        if self_meta != other_meta {
            return self_meta - other_meta;
        }
        let res = other.base.size as i32 - self.base.size as i32;
        if res != 0 {
            return res;
        }
        if self.offset != other.offset {
            return if self.offset < other.offset { -1 } else { 1 };
        }
        let mut lvl = level - 1;
        if lvl < 0 {
            return if self.base.id == other.base.id {
                0
            } else if self.base.id < other.base.id {
                -1
            } else {
                1
            };
        }
        if lvl < 0 {
            lvl = 0;
        }
        self.container.compare(&other.container)
    }

    // Ghidra: type.cc:2406 TypePartialStruct::compareDependency
    /// Compare for the type-factory tree sort. Faithful to
    /// `TypePartialStruct::compareDependency` (type.cc:2406-2414): submeta,
    /// then container by identity (Rugra uses `Arc::as_ptr`), then offset,
    /// then `(op.size - size)`.
    pub fn compare_dependency(&self, other: &TypePartialStruct) -> i32 {
        let self_meta = self.base.metatype as i32;
        let other_meta = other.base.metatype as i32;
        if self_meta != other_meta {
            return self_meta - other_meta;
        }
        // Compare container by pointer identity (type.cc:2411).
        let sp = Arc::as_ptr(&self.container) as usize;
        let op = Arc::as_ptr(&other.container) as usize;
        if sp != op {
            return if sp < op { -1 } else { 1 };
        }
        if self.offset != other.offset {
            return if self.offset < other.offset { -1 } else { 1 };
        }
        other.base.size as i32 - self.base.size as i32
    }
}

/// A data-type that holds part of a `TypeEnum`.
///
/// Ghidra `TypePartialEnum` (type.hh:569-587). Inherits TypeEnum behaviour
/// but, for value lookups, shifts the value left by `8*offset` bits before
/// delegating to the parent enum, recording the shift in the `Representation`
/// so callers can render the value correctly.
#[derive(Debug, Clone)]
pub struct TypePartialEnum {
    pub base: TypeBase,
    /// The enumeration data-type this is based on. Ghidra field `parent`
    /// (type.hh:572).
    pub parent: Arc<Datatype>,
    /// Byte offset within `parent` where this piece starts. Ghidra field
    /// `offset` (type.hh:573).
    pub offset: i64,
    /// Undefined fallback for formal-type requests. Ghidra field `stripped`
    /// (type.hh:571).
    pub stripped: Option<Arc<Datatype>>,
}

impl TypePartialEnum {
    // Ghidra: type.cc:2255 TypePartialEnum::TypePartialEnum
    /// Construct a partial-enum given the parent enum, byte offset, size, and
    /// stripped fallback. Faithful to the C++ constructor
    /// (type.cc:2255-2262): sets `metatype = TYPE_PARTIALENUM` and the
    /// `has_stripped` + `enumtype` flags.
    pub fn new(
        parent: Arc<Datatype>,
        offset: i64,
        size: usize,
        stripped: Option<Arc<Datatype>>,
    ) -> Self {
        let mut base = TypeBase::new(String::new(), size, TypeMetatype::PartialEnum);
        base.flags |= type_flags::HAS_STRIPPED | type_flags::ENUMTYPE;
        Self { base, parent, offset, stripped }
    }

    // Ghidra: type.hh:577 TypePartialEnum::getOffset
    pub fn get_offset(&self) -> i64 { self.offset }

    // Ghidra: type.hh:578 TypePartialEnum::getParent
    pub fn get_parent(&self) -> &Arc<Datatype> { &self.parent }

    // Ghidra: type.hh:586 TypePartialEnum::getStripped
    pub fn get_stripped(&self) -> Option<&Arc<Datatype>> { self.stripped.as_ref() }

    // Ghidra: type.cc:2271 TypePartialEnum::hasNamedValue
    /// Shift `val` left by `8*offset` bits and delegate to the parent enum.
    /// Faithful to `TypePartialEnum::hasNamedValue` (type.cc:2271-2276).
    pub fn has_named_value(&self, val: u64) -> bool {
        let shifted = val.wrapping_shl((8 * self.offset) as u32);
        enum_has_named_value(&self.parent, shifted)
    }

    // Ghidra: type.cc:2278 TypePartialEnum::getMatches
    /// Build the named representation of `val` by shifting it left by
    /// `8*offset` bits, recording that shift on the `Representation`, and
    /// delegating to the parent enum. Faithful to `getMatches`
    /// (type.cc:2278-2284).
    pub fn get_matches(&self, val: u64, rep: &mut EnumRepresentation) {
        let shifted = val.wrapping_shl((8 * self.offset) as u32);
        rep.shift_amount = self.offset * 8;
        enum_get_matches(&self.parent, shifted, rep);
    }

    // Ghidra: type.cc:2286 TypePartialEnum::compare
    /// Compare two partial-enums. Faithful to `TypePartialEnum::compare`
    /// (type.cc:2286-2300): base `Datatype::compare` first, then offset, then
    /// (if `level > 0`) the parent.
    pub fn compare(&self, other: &TypePartialEnum, level: i32) -> i32 {
        let self_meta = self.base.metatype as i32;
        let other_meta = other.base.metatype as i32;
        if self_meta != other_meta {
            return self_meta - other_meta;
        }
        let res = other.base.size as i32 - self.base.size as i32;
        if res != 0 {
            return res;
        }
        if self.offset != other.offset {
            return if self.offset < other.offset { -1 } else { 1 };
        }
        let mut lvl = level - 1;
        if lvl < 0 {
            return if self.base.id == other.base.id {
                0
            } else if self.base.id < other.base.id {
                -1
            } else {
                1
            };
        }
        if lvl < 0 {
            lvl = 0;
        }
        self.parent.compare(&other.parent)
    }

    // Ghidra: type.cc:2302 TypePartialEnum::compareDependency
    /// Compare for the type-factory tree sort. Faithful to
    /// `TypePartialEnum::compareDependency` (type.cc:2302-2310): submeta, then
    /// parent by identity, then offset, then `(op.size - size)`.
    pub fn compare_dependency(&self, other: &TypePartialEnum) -> i32 {
        let self_meta = self.base.metatype as i32;
        let other_meta = other.base.metatype as i32;
        if self_meta != other_meta {
            return self_meta - other_meta;
        }
        let sp = Arc::as_ptr(&self.parent) as usize;
        let op = Arc::as_ptr(&other.parent) as usize;
        if sp != op {
            return if sp < op { -1 } else { 1 };
        }
        if self.offset != other.offset {
            return if self.offset < other.offset { -1 } else { 1 };
        }
        other.base.size as i32 - self.base.size as i32
    }
}

/// A data-type holding part of a `TypeUnion`.
///
/// Ghidra `TypePartialUnion` (type.hh:616-640). Used when a Varnode is known
/// to be contained within a union Symbol but the specific field cannot yet be
/// determined. Carries the union's `resolveTruncation`/`findResolve`/
/// `findCompatibleResolve` machinery so a later flow-sensitive resolution can
/// pin down the field.
#[derive(Debug, Clone)]
pub struct TypePartialUnion {
    pub base: TypeBase,
    /// Union data-type containing this partial. Ghidra field `container`
    /// (type.hh:620).
    pub container: Arc<Datatype>,
    /// Byte offset into `container`. Ghidra field `offset` (type.hh:621).
    pub offset: i64,
    /// Undefined fallback for formal-type requests. Ghidra field `stripped`
    /// (type.hh:619).
    pub stripped: Option<Arc<Datatype>>,
}

impl TypePartialUnion {
    // Ghidra: type.cc:2424 TypePartialUnion::TypePartialUnion
    /// Construct a partial-union given the container union, byte offset, size,
    /// and stripped fallback. Faithful to the C++ constructor
    /// (type.cc:2424-2431): sets `metatype = TYPE_PARTIALUNION` and the
    /// `needs_resolution | has_stripped` flags (type.hh:616 marks partial
    /// unions as resolution-deferred).
    pub fn new(
        container: Arc<Datatype>,
        offset: i64,
        size: usize,
        stripped: Option<Arc<Datatype>>,
    ) -> Self {
        let mut base = TypeBase::new(String::new(), size, TypeMetatype::PartialUnion);
        base.flags |= type_flags::NEEDS_RESOLUTION | type_flags::HAS_STRIPPED;
        Self { base, container, offset, stripped }
    }

    // Ghidra: type.hh:625 TypePartialUnion::getOffset
    pub fn get_offset(&self) -> i64 { self.offset }

    // Ghidra: type.hh:626 TypePartialUnion::getParentUnion
    pub fn get_parent_union(&self) -> &Arc<Datatype> { &self.container }

    // Ghidra: type.hh:635 TypePartialUnion::getStripped
    pub fn get_stripped(&self) -> Option<&Arc<Datatype>> { self.stripped.as_ref() }

    // Ghidra: type.cc:2446 TypePartialUnion::numDepend
    /// Number of dependent component types — delegated to the underlying
    /// union. Faithful to `TypePartialUnion::numDepend` (type.cc:2446-2450).
    pub fn num_depend(&self) -> usize {
        union_num_depend(&self.container)
    }

    // Ghidra: type.cc:2452 TypePartialUnion::getDepend
    /// Return the `index`-th dependent type of the underlying union, or the
    /// `stripped` data-type if its size does not match this partial's size.
    /// Faithful to `TypePartialUnion::getDepend` (type.cc:2452-2460).
    pub fn get_depend(&self, index: usize) -> Option<Arc<Datatype>> {
        match union_get_depend(&self.container, index) {
            Some(res) => {
                if res.get_size() != self.base.size {
                    self.stripped.clone()
                } else {
                    Some(res)
                }
            }
            None => None,
        }
    }

    // Ghidra: type.cc:2462 TypePartialUnion::compare
    /// Compare two partial-unions. Faithful to `TypePartialUnion::compare`
    /// (type.cc:2462-2476): base `Datatype::compare` first, then offset, then
    /// (if `level > 0`) the container.
    pub fn compare(&self, other: &TypePartialUnion, level: i32) -> i32 {
        let self_meta = self.base.metatype as i32;
        let other_meta = other.base.metatype as i32;
        if self_meta != other_meta {
            return self_meta - other_meta;
        }
        let res = other.base.size as i32 - self.base.size as i32;
        if res != 0 {
            return res;
        }
        if self.offset != other.offset {
            return if self.offset < other.offset { -1 } else { 1 };
        }
        let mut lvl = level - 1;
        if lvl < 0 {
            return if self.base.id == other.base.id {
                0
            } else if self.base.id < other.base.id {
                -1
            } else {
                1
            };
        }
        if lvl < 0 {
            lvl = 0;
        }
        self.container.compare(&other.container)
    }

    // Ghidra: type.cc:2478 TypePartialUnion::compareDependency
    /// Compare for the type-factory tree sort. Faithful to
    /// `TypePartialUnion::compareDependency` (type.cc:2478-2486): submeta,
    /// then container by identity, then offset, then `(op.size - size)`.
    pub fn compare_dependency(&self, other: &TypePartialUnion) -> i32 {
        let self_meta = self.base.metatype as i32;
        let other_meta = other.base.metatype as i32;
        if self_meta != other_meta {
            return self_meta - other_meta;
        }
        let sp = Arc::as_ptr(&self.container) as usize;
        let op = Arc::as_ptr(&other.container) as usize;
        if sp != op {
            return if sp < op { -1 } else { 1 };
        }
        if self.offset != other.offset {
            return if self.offset < other.offset { -1 } else { 1 };
        }
        other.base.size as i32 - self.base.size as i32
    }

    // Ghidra: type.cc:2498 TypePartialUnion::resolveInFlow
    /// Walk down the container union (and any nested composites) until a
    /// data-type of this partial's size is reached, then return it; otherwise
    /// return the stripped data-type. Faithful to `resolveInFlow`
    /// (type.cc:2498-2515).
    ///
    /// NOTE: Ghidra's full implementation consults the Funcdata's
    /// `unionField` cache (via `resolveTruncation`) to pick a specific union
    /// field based on the reading PcodeOp. Rugra does not yet thread that
    /// cache through, so this port walks the structural sub-types only and
    /// returns the first matching-size component, falling back to `stripped`
    /// when no match is found. `op`/`slot` are accepted for API alignment.
    pub fn resolve_in_flow(
        &self,
        _op: Option<&crate::op::PcodeOp>,
        _slot: i32,
    ) -> Option<Arc<Datatype>> {
        let mut cur_type: &Datatype = self.container.as_ref();
        let mut cur_off = self.offset;
        let target_size = self.base.size;
        while cur_type.get_size() > target_size {
            if cur_type.get_metatype() == TypeMetatype::Union {
                // Ghidra calls resolveTruncation here; without the Funcdata
                // union-field cache we cannot pick a field, so stop walking.
                break;
            } else {
                let (sub, no) = cur_type.get_sub_type(cur_off);
                match sub {
                    None => break,
                    Some(s) => {
                        cur_type = s;
                        cur_off = no;
                    }
                }
            }
        }
        if cur_type.get_size() == target_size {
            Some(Arc::new(cur_type.clone()))
        } else {
            self.stripped.clone()
        }
    }

    // Ghidra: type.cc:2517 TypePartialUnion::findResolve
    /// The constant version of `resolve_in_flow`. Faithful to `findResolve`
    /// (type.cc:2517-2534): walks the container like `resolve_in_flow`, but
    /// for unions consults the cached `findResolve` result instead of
    /// `resolveTruncation`. As with `resolve_in_flow`, Rugra lacks the
    /// Funcdata union cache, so the union branch stops walking and we fall
    /// back to `stripped`.
    pub fn find_resolve(&self, _op: Option<&crate::op::PcodeOp>, _slot: i32) -> Option<Arc<Datatype>> {
        let mut cur_type: &Datatype = self.container.as_ref();
        let mut cur_off = self.offset;
        let target_size = self.base.size;
        while cur_type.get_size() > target_size {
            if cur_type.get_metatype() == TypeMetatype::Union {
                break;
            } else {
                let (sub, no) = cur_type.get_sub_type(cur_off);
                match sub {
                    None => break,
                    Some(s) => {
                        cur_type = s;
                        cur_off = no;
                    }
                }
            }
        }
        if cur_type.get_size() == target_size {
            Some(Arc::new(cur_type.clone()))
        } else {
            self.stripped.clone()
        }
    }

    // Ghidra: type.cc:2536 TypePartialUnion::findCompatibleResolve
    /// Delegate to the container union's `findCompatibleResolve`. Faithful to
    /// `TypePartialUnion::findCompatibleResolve` (type.cc:2536-2540). Returns
    /// -1 (no compatible form) until Rugra wires the union-resolution cache.
    pub fn find_compatible_resolve(&self, _ct: &Datatype) -> i32 {
        -1
    }

    // Ghidra: type.cc:2542 TypePartialUnion::resolveTruncation
    /// Resolve which union field is being used for a truncation. Delegates to
    /// the container union's `resolveTruncation` at `off + offset`. Faithful
    /// to `TypePartialUnion::resolveTruncation` (type.cc:2542-2546). Without
    /// the Funcdata union-field cache, returns `None` (no field resolved).
    pub fn resolve_truncation(
        &self,
        _off: i64,
        _op: Option<&crate::op::PcodeOp>,
        _slot: i32,
    ) -> Option<(TypeField, i64)> {
        None
    }

    // Ghidra: type.cc:2440 TypePartialUnion::findTruncation
    /// Find the field for a truncation without re-scoring. Delegates to the
    /// container union's `findTruncation` at `off + offset`. Faithful to
    /// `TypePartialUnion::findTruncation` (type.cc:2440-2444). Without the
    /// Funcdata union-field cache, returns `None`.
    pub fn find_truncation(
        &self,
        _off: i64,
        _sz: i32,
        _op: Option<&crate::op::PcodeOp>,
        _slot: i32,
    ) -> Option<(TypeField, i64)> {
        None
    }
}

// Ghidra: type.hh:474 TypeEnum::Representation
/// Mirrors Ghidra's `TypeEnum::Representation` (type.hh:474-480): the list of
/// name tokens ORed together, whether the final value must be bitwise
/// complemented, and how many bits to left-shift the final value. Used by
/// `TypePartialEnum::get_matches` and (eventually) `TypeEnum::get_matches`.
#[derive(Debug, Default, Clone)]
pub struct EnumRepresentation {
    /// Name tokens that are ORed together.
    pub match_name: Vec<String>,
    /// If true, bitwise-complement the value after ORing.
    pub complement: bool,
    /// Number of bits to left-shift the final value.
    pub shift_amount: i64,
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

    // --- alignment / align-size (Ghidra setDefaultAlignmentMap type.cc:4649) ---

    #[test]
    fn test_primitive_alignment() {
        assert_eq!(primitive_alignment(0), 1);
        assert_eq!(primitive_alignment(1), 1);
        assert_eq!(primitive_alignment(2), 2);
        assert_eq!(primitive_alignment(3), 2);
        assert_eq!(primitive_alignment(4), 4);
        assert_eq!(primitive_alignment(5), 4);
        assert_eq!(primitive_alignment(6), 4);
        assert_eq!(primitive_alignment(7), 4);
        assert_eq!(primitive_alignment(8), 8);
        assert_eq!(primitive_alignment(16), 8); // capped at 8
    }

    #[test]
    fn test_calc_align_size() {
        assert_eq!(calc_align_size(5, 4), 8);
        assert_eq!(calc_align_size(4, 4), 4);
        assert_eq!(calc_align_size(3, 2), 4);
        assert_eq!(calc_align_size(0, 8), 0);
    }

    #[test]
    fn test_datatype_get_align_size_base() {
        // int (size 4) → align 4 → alignSize 4
        let int_dt = Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int));
        assert_eq!(int_dt.get_alignment(), 4);
        assert_eq!(int_dt.get_align_size(), 4);
        // a 3-byte value → align 2 → alignSize 4
        let odd_dt = Datatype::Base(TypeBase::new("odd".into(), 3, TypeMetatype::Int));
        assert_eq!(odd_dt.get_alignment(), 2);
        assert_eq!(odd_dt.get_align_size(), 4);
    }

    // --- get_sub_type ---

    #[test]
    fn test_struct_get_sub_type() {
        // struct { char f0 @0; int f1 @4; } size 8
        let char_t = Arc::new(Datatype::Base(TypeBase::new("char".into(), 1, TypeMetatype::Int)));
        let int_t = Arc::new(Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int)));
        let s = Datatype::Struct(TypeStruct {
            base: TypeBase::new("S".into(), 8, TypeMetatype::Struct),
            fields: vec![
                TypeField { name: "f0".into(), offset: 0, type_ptr: char_t },
                TypeField { name: "f1".into(), offset: 4, type_ptr: int_t.clone() },
            ],
        });
        // offset 0 → field f0, newoff 0
        let (sub, newoff) = s.get_sub_type(0);
        assert_eq!(newoff, 0);
        assert_eq!(sub.unwrap().get_name(), "char");
        // offset 6 → inside f1 (starts at 4), newoff 2
        let (sub, newoff) = s.get_sub_type(6);
        assert_eq!(newoff, 2);
        assert_eq!(sub.unwrap().get_name(), "int");
        // offset 10 → outside the struct (size 8) → None, unchanged
        let (sub, newoff) = s.get_sub_type(10);
        assert!(sub.is_none());
        assert_eq!(newoff, 10);
    }

    #[test]
    fn test_array_get_sub_type() {
        // int[3] → element int (size 4)
        let int_t = Arc::new(Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int)));
        let arr = Datatype::Array(TypeArray {
            base: TypeBase::new("int[3]".into(), 12, TypeMetatype::Array),
            array_of: int_t.clone(),
            num_elements: 3,
        });
        // offset 5 → element (5 % 4 = 1), newoff 1
        let (sub, newoff) = arr.get_sub_type(5);
        assert_eq!(newoff, 1);
        assert_eq!(sub.unwrap().get_name(), "int");
        // offset 12 (== size) → None
        let (sub, _newoff) = arr.get_sub_type(12);
        assert!(sub.is_none());
    }

    // --- type_order (Ghidra compare: submeta, then size smaller-first) ---

    #[test]
    fn test_type_order_basic() {
        let int4 = Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int));
        let int8 = Datatype::Base(TypeBase::new("long".into(), 8, TypeMetatype::Int));
        // same metatype, size 4 < size 8 → int4 orders before int8
        // type_order returns (op.size - size): (8-4)=+4 means self<int? No:
        // Ghidra: returns (op.size - size); positive → self < other in sort.
        // We mirror that: smaller size → positive → "preferred".
        assert!(int4.type_order(&int8) > 0);   // int4 preferred over int8
        assert!(int8.type_order(&int4) < 0);
        assert_eq!(int4.type_order(&int4), 0);
    }

    #[test]
    fn test_type_order_metatype() {
        // Unknown < Int per the enum ordering (Unknown=0, Int=3).
        let unk = Datatype::Base(TypeBase::new("unk".into(), 4, TypeMetatype::Unknown));
        let int4 = Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int));
        // Same size; Unknown (metatype 0) orders before Int (metatype 3).
        // type_order(unk, int4): metatype 0 < 3 → return -1.
        assert_eq!(unk.type_order(&int4), -1);
        assert_eq!(int4.type_order(&unk), 1);
    }

    // --- new Datatype methods aligned with type.hh / type.cc ---

    #[test]
    fn test_needs_resolution_union() {
        // type.hh:231 / TypeUnion constructor type.hh:551 — union sets
        // needs_resolution; a plain int does not.
        let mut u_base = TypeBase::new("U".into(), 0, TypeMetatype::Union);
        u_base.flags |= type_flags::NEEDS_RESOLUTION;
        let u = Datatype::Union(TypeUnion { base: u_base, fields: vec![] });
        assert!(u.needs_resolution());

        let int_t = Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int));
        assert!(!int_t.needs_resolution());
    }

    #[test]
    fn test_is_enum_type_flag() {
        // type.hh:219 — isEnumType checks the enumtype flag, not metatype.
        let mut e_base = TypeBase::new("Color".into(), 4, TypeMetatype::Int);
        e_base.flags |= type_flags::ENUMTYPE;
        let e = Datatype::Enum(TypeEnum { base: e_base, values: Default::default() });
        assert!(e.is_enum_type());

        let int_t = Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int));
        assert!(!int_t.is_enum_type());
    }

    #[test]
    fn test_find_resolve_base_returns_self() {
        // type.cc:586-590 — base Datatype::findResolve returns self.
        let int_t = Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int));
        let resolved = int_t.find_resolve(None, -1);
        assert!(std::ptr::eq(resolved as *const _, &int_t as *const _));
    }

    #[test]
    fn test_get_stripped_base_is_identity() {
        // type.cc:561-565 — base getStripped returns null/self for non-stripped.
        let int_t = Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int));
        let stripped = int_t.get_stripped();
        assert!(std::ptr::eq(stripped as *const _, &int_t as *const _));
    }

    #[test]
    fn test_mark_unmark_equate() {
        // Rugra-private (no Ghidra counterpart): toggle EQUATED flag.
        let mut int_t = Datatype::Base(TypeBase::new("x".into(), 4, TypeMetatype::Int));
        assert!(!int_t.is_equated());
        int_t.mark_equate();
        assert!(int_t.is_equated());
        int_t.mark_un_equate();
        assert!(!int_t.is_equated());
    }

    #[test]
    fn test_has_stripped_flag() {
        // type.hh:229 — hasStripped checks HAS_STRIPPED.
        let mut td_base = TypeBase::new("Word".into(), 4, TypeMetatype::Int);
        td_base.flags |= type_flags::HAS_STRIPPED;
        let td = Datatype::Base(td_base);
        assert!(td.has_stripped());

        let plain = Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int));
        assert!(!plain.has_stripped());
    }

    // --- P0 partial-type alignment (type.cc:2247-2546) ---

    fn build_struct_for_partial() -> Arc<Datatype> {
        // struct S { char c @0; int i @4; short s @8; } size 10
        let char_t = Arc::new(Datatype::Base(TypeBase::new("char".into(), 1, TypeMetatype::Int)));
        let int_t = Arc::new(Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int)));
        let short_t = Arc::new(Datatype::Base(TypeBase::new("short".into(), 2, TypeMetatype::Int)));
        Arc::new(Datatype::Struct(TypeStruct {
            base: TypeBase::new("S".into(), 10, TypeMetatype::Struct),
            fields: vec![
                TypeField { name: "c".into(), offset: 0, type_ptr: char_t },
                TypeField { name: "i".into(), offset: 4, type_ptr: int_t },
                TypeField { name: "s".into(), offset: 8, type_ptr: short_t },
            ],
        }))
    }

    #[test]
    fn test_partial_struct_construction_and_flags() {
        // type.cc:2330 — TypePartialStruct ctor sets metatype + has_stripped.
        let s = build_struct_for_partial();
        let stripped = Arc::new(Datatype::Base(TypeBase::new("unk4".into(), 4, TypeMetatype::Unknown)));
        let ps = TypePartialStruct::new(s.clone(), 4, 4, Some(stripped.clone()));
        assert_eq!(ps.base.size, 4);
        assert_eq!(ps.offset, 4);
        assert_eq!(ps.base.metatype, TypeMetatype::PartialStruct);
        assert!(ps.base.flags & type_flags::HAS_STRIPPED != 0);
        assert!(Arc::ptr_eq(ps.get_parent(), &s));
        assert!(Arc::ptr_eq(ps.get_stripped().unwrap(), &stripped));
        assert_eq!(ps.get_offset(), 4);
    }

    #[test]
    fn test_partial_struct_get_sub_type() {
        // type.cc:2363 — partial over [4,8) of struct S resolves to the int field.
        let s = build_struct_for_partial();
        let stripped = Arc::new(Datatype::Base(TypeBase::new("unk4".into(), 4, TypeMetatype::Unknown)));
        let ps = TypePartialStruct::new(s, 4, 4, Some(stripped));
        // Within the partial at relative off 0 ⇒ absolute off 4 ⇒ int field.
        let (sub, newoff) = partial_struct_get_sub_type(&ps, 0);
        assert_eq!(sub.unwrap().get_name(), "int");
        assert_eq!(newoff, 0);
        // Relative off 2 ⇒ absolute 6 ⇒ inside int (offset 4), newoff 2.
        let (sub, newoff) = partial_struct_get_sub_type(&ps, 2);
        assert_eq!(sub.unwrap().get_name(), "int");
        assert_eq!(newoff, 2);
    }

    #[test]
    fn test_partial_struct_get_hole_size() {
        // type.cc:2379 — clamped to remaining partial size.
        let s = build_struct_for_partial();
        let stripped = Arc::new(Datatype::Base(TypeBase::new("unk4".into(), 4, TypeMetatype::Unknown)));
        let ps = TypePartialStruct::new(s, 4, 4, Some(stripped));
        // At relative off 0, the int field has 4 bytes; partial has 4-0=4 left.
        assert_eq!(partial_struct_get_hole_size(&ps, 0), 4);
        // At relative off 2, partial has 4-2=2 bytes left (clamped below the
        // int field's remaining 2 — equal, so 2 either way).
        assert_eq!(partial_struct_get_hole_size(&ps, 2), 2);
    }

    #[test]
    fn test_partial_struct_print_raw() {
        // type.cc:2356 — "<container>[off=<o>,sz=<s>]".
        let s = build_struct_for_partial();
        let dt = Datatype::PartialStruct(TypePartialStruct::new(s.clone(), 4, 4, None));
        let raw = dt.print_raw();
        assert!(raw.starts_with("struct{"));
        assert!(raw.contains("[off=4,sz=4]"));
    }

    #[test]
    fn test_partial_struct_get_stripped_via_datatype() {
        // type.cc:561 — Datatype::getStripped override returns the stripped.
        let s = build_struct_for_partial();
        let stripped = Arc::new(Datatype::Base(TypeBase::new("unk4".into(), 4, TypeMetatype::Unknown)));
        let dt = Datatype::PartialStruct(TypePartialStruct::new(s, 4, 4, Some(stripped.clone())));
        // get_stripped returns &Datatype pointing into the Arc.
        let resolved = dt.get_stripped();
        assert!(Arc::ptr_eq(stripped.as_ref(), resolved));
    }

    #[test]
    fn test_partial_enum_has_named_value_shifts() {
        // type.cc:2271 — val <<= 8*offset before delegating to parent.
        let mut e_base = TypeBase::new("Color".into(), 4, TypeMetatype::Int);
        e_base.flags |= type_flags::ENUMTYPE;
        // Parent enum names value 0x100 (which is 1 << 8).
        let mut values = std::collections::BTreeMap::new();
        values.insert(0x100u64, "RED".to_string());
        let parent = Arc::new(Datatype::Enum(TypeEnum { base: e_base, values }));
        // Partial at byte offset 1: val 1 shifted by 8 bits → 0x100 → matches.
        let pe = TypePartialEnum::new(parent, 1, 1, None);
        assert!(pe.has_named_value(1));   // 1 << 8 = 0x100 → named
        assert!(!pe.has_named_value(2));  // 2 << 8 = 0x200 → not named
    }

    #[test]
    fn test_partial_union_flags_and_accessors() {
        // type.cc:2424 — ctor sets needs_resolution + has_stripped.
        let u_base = TypeBase::new("U".into(), 8, TypeMetatype::Union);
        let union = Arc::new(Datatype::Union(TypeUnion { base: u_base, fields: vec![] }));
        let stripped = Arc::new(Datatype::Base(TypeBase::new("unk4".into(), 4, TypeMetatype::Unknown)));
        let pu = TypePartialUnion::new(union.clone(), 0, 4, Some(stripped));
        assert_eq!(pu.base.metatype, TypeMetatype::PartialUnion);
        assert!(pu.base.flags & type_flags::NEEDS_RESOLUTION != 0);
        assert!(pu.base.flags & type_flags::HAS_STRIPPED != 0);
        assert!(Arc::ptr_eq(pu.get_parent_union(), &union));
        assert_eq!(pu.get_offset(), 0);
        // numDepend delegates to the (empty) union.
        assert_eq!(pu.num_depend(), 0);
    }

    #[test]
    fn test_spacebase_get_address_wordsize() {
        // type.cc:3063 — byteToAddressInt(off, wordsize) = off * wordsize.
        use crate::AddressSpace;
        let mut sb = TypeSpacebase::new_global(Address::new(0));
        // No spaceid ⇒ wordsize 1 ⇒ identity.
        assert_eq!(sb.get_address(5, 8, Address::new(0)).as_u64(), 5);
        // Attach a spaceid; Rugra's AddressSpace enum has word_size 1 for all
        // variants, so the product is still identity. The contract is honoured.
        sb.spaceid = Some(AddressSpace::Ram);
        assert_eq!(sb.get_address(5, 8, Address::new(0)).as_u64(), 5);
    }

    #[test]
    fn test_spacebase_get_sub_type_no_scope_returns_identity() {
        // type.cc:2947 — with no scope (Rugra default), returns (None, off).
        let sb = TypeSpacebase::new_global(Address::new(0));
        let (sub, newoff) = sb.get_sub_type(42);
        assert!(sub.is_none());
        assert_eq!(newoff, 42);
    }

    #[test]
    fn test_spacebase_is_invalid_for_global() {
        // type.cc:2935 — global spacebase has invalid localframe.
        let global = TypeSpacebase::new_global(Address::new(0));
        assert!(global.is_invalid());
    }
}
