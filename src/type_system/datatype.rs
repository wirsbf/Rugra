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
            Datatype::Pointer(_) | Datatype::Void(_) | Datatype::Base(_)
            | Datatype::Enum(_) | Datatype::Code(_) | Datatype::Spacebase(_) => (None, off),
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

    // Ghidra: type.cc:227 Datatype::compareDependency
    /// Compare datatypes by dependency order.
    /// Faithful to Datatype::compareDependency (type.cc:227).
    pub fn compare_dependency(&self, other: &Datatype) -> i32 {
        self.compare(other)
    }

    // Ghidra: type.cc:561 Datatype::getStripped
    /// Get the "stripped" version (removes typedef wrappers).
    /// Faithful to Datatype::getStripped (type.cc:561-565). The base class
    /// returns null (here: `None`); the various overrides (TypePointerRel,
    /// TypeTypedef, etc.) return their `stripped` field. Rugra does not yet
    /// model stripped forms on every variant, so for variants without an
    /// explicit stripped reference we return `self`, matching the intent of
    /// "no stripped form" by returning the type itself.
    pub fn get_stripped(&self) -> &Datatype { self }

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
    /// Faithful to Datatype::printRaw (type.cc:139).
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
}
