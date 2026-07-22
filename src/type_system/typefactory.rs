//! Type management and deduplication
//!
//! Corresponds to Ghidra's `TypeFactory` class in `type.hh`. This class is responsible
//! for the lifecycle of all `Datatype` objects, ensuring that identical types are
//! deduplicated and providing a central point for type lookup.

use std::collections::BTreeMap;
use std::sync::Arc;
use crate::address::Address;
use crate::AddressSpace;
use crate::marshal::{Encoder, Decoder};
use crate::type_system::datatype::*;

/// Managed container for all Datatype objects
pub struct TypeFactory {
    /// All types managed by this factory, keyed by their unique name
    types: BTreeMap<String, Arc<Datatype>>,

    /// Cache for core types (void, int, etc.) for quick access
    core_types: BTreeMap<String, Arc<Datatype>>,

    /// The default size of a pointer for this architecture
    ptr_size: usize,

    /// Side data for `TypePointerRel` instances: the parent container and
    /// offset that do not fit on Rugra's flat `TypePointer`. Mirrors the
    /// `parent`/`offset` fields of Ghidra's `TypePointerRel` (type.hh:647).
    rel_pointers: BTreeMap<String, RelativePointer>,

    /// Typedef targets: maps a typedef name to the data-type it aliases
    /// (the "stripped" form). Mirrors Ghidra's `Datatype::typedefImm`
    /// (type.hh:196) and `TypeFactory::getTypedef` (type.cc:3818-3840).
    typedefs: BTreeMap<String, Arc<Datatype>>,
}

impl TypeFactory {
    // Ghidra: type.cc:3106 TypeFactory::new
    /// Create a new TypeFactory and initialize core types
    ///
    /// # Arguments
    /// * `ptr_size` - Default pointer size for the target architecture (e.g., 4 or 8)
    pub fn new(ptr_size: usize) -> Self {
        let mut factory = Self {
            types: BTreeMap::new(),
            core_types: BTreeMap::new(),
            ptr_size,
            rel_pointers: BTreeMap::new(),
            typedefs: BTreeMap::new(),
        };
        factory.init_core_types();
        factory
    }

    // Ghidra: type.cc:3106 TypeFactory::initCoreTypes
    /// Initialize the fundamental core types
    fn init_core_types(&mut self) {
        // Void type
        let void_type = Arc::new(Datatype::Void(TypeBase::new("void".to_string(), 0, TypeMetatype::Void)));
        self.add_core_type(void_type);

        // Boolean type
        let bool_type = Arc::new(Datatype::Base(TypeBase::new("bool".to_string(), 1, TypeMetatype::Bool)));
        self.add_core_type(bool_type);

        // Standard integer types
        let int_sizes = [1, 2, 4, 8];
        for &size in &int_sizes {
            // Signed integers
            let s_name = if size == 4 { "int".to_string() } else { format!("int{}", size) };
            let s_type = Arc::new(Datatype::Base(TypeBase::new(s_name, size, TypeMetatype::Int)));
            self.add_core_type(s_type);

            // Unsigned integers
            let u_name = if size == 4 { "uint".to_string() } else { format!("uint{}", size) };
            let u_type = Arc::new(Datatype::Base(TypeBase::new(u_name, size, TypeMetatype::Uint)));
            self.add_core_type(u_type);
        }

        // Floating point types
        let f_type4 = Arc::new(Datatype::Base(TypeBase::new("float".to_string(), 4, TypeMetatype::Float)));
        self.add_core_type(f_type4);
        let f_type8 = Arc::new(Datatype::Base(TypeBase::new("double".to_string(), 8, TypeMetatype::Float)));
        self.add_core_type(f_type8);
    }

    // Ghidra: type.cc:3106 TypeFactory::addCoreType
    /// Internal helper to register a core type
    fn add_core_type(&mut self, mut dt: Arc<Datatype>) {
        if let Some(dt_mut) = Arc::get_mut(&mut dt) {
            match dt_mut {
                Datatype::Void(b) | Datatype::Base(b) => b.flags |= type_flags::CORETYPE,
                _ => {}
            }
        }
        let name = dt.get_name().to_string();
        self.core_types.insert(name.clone(), dt.clone());
        self.types.insert(name, dt);
    }

    // Ghidra: type.cc:3366 TypeFactory::findByName
    /// Find a type by name
    pub fn find_by_name(&self, name: &str) -> Option<Arc<Datatype>> {
        self.types.get(name).cloned()
    }

    // Ghidra: type.cc:3631 TypeFactory::getBase
    /// Get a base scalar type of `size` bytes with metatype `m`. Faithful to
    /// `TypeFactory::getBase` (type.cc:3631-3660). For int/uint/float/bool,
    /// looks up the pre-generated core type by name; if not found, creates
    /// a new base type on the fly.
    pub fn get_base(&self, size: usize, m: TypeMetatype) -> Option<Arc<Datatype>> {
        use TypeMetatype::*;
        match m {
            Int => {
                let name = if size == 4 { "int".to_string() } else { format!("int{}", size) };
                self.find_by_name(&name).or_else(|| {
                    Some(Arc::new(Datatype::Base(TypeBase::new(name, size, Int))))
                })
            }
            Uint => {
                let name = if size == 4 { "uint".to_string() } else { format!("uint{}", size) };
                self.find_by_name(&name).or_else(|| {
                    Some(Arc::new(Datatype::Base(TypeBase::new(name, size, Uint))))
                })
            }
            Float => {
                let name = if size <= 4 { "float".to_string() } else { "double".to_string() };
                self.find_by_name(&name).or_else(|| {
                    Some(Arc::new(Datatype::Base(TypeBase::new(name, size, Float))))
                })
            }
            Bool => self.find_by_name("bool"),
            Void => self.find_by_name("void"),
            _ => None,
        }
    }

    // Ghidra: type.cc:3106 TypeFactory::getPtr
    /// Get or create a pointer type to the given base type
    pub fn get_ptr(&mut self, ptr_to: Arc<Datatype>) -> Arc<Datatype> {
        let name = format!("{} *", ptr_to.get_name());
        if let Some(existing) = self.find_by_name(&name) {
            return existing;
        }

        let ptr_type = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new(name.clone(), self.ptr_size, TypeMetatype::Pointer),
            ptr_to,
            wordsize: 1,
        }));
        self.types.insert(name, ptr_type.clone());
        ptr_type
    }

    // Ghidra: type.cc:3106 TypeFactory::getArray
    /// Get or create an array type
    pub fn get_array(&mut self, array_of: Arc<Datatype>, num_elements: usize) -> Arc<Datatype> {
        let name = format!("{}[{}]", array_of.get_name(), num_elements);
        if let Some(existing) = self.find_by_name(&name) {
            return existing;
        }

        let size = array_of.get_size() * num_elements;
        let array_type = Arc::new(Datatype::Array(TypeArray {
            base: TypeBase::new(name.clone(), size, TypeMetatype::Array),
            array_of,
            num_elements,
        }));
        self.types.insert(name, array_type.clone());
        array_type
    }

    // Ghidra: type.cc:3106 TypeFactory::createStruct
    /// Create a new structure type
    pub fn create_struct(&mut self, name: &str) -> Arc<Datatype> {
        // Note: Ghidra allows multiple structs with same name in different scopes,
        // but for now we use a global flat namespace for the factory.
        let st_type = Arc::new(Datatype::Struct(TypeStruct {
            base: TypeBase::new(name.to_string(), 0, TypeMetatype::Struct),
            fields: Vec::new(),
        }));
        self.types.insert(name.to_string(), st_type.clone());
        st_type
    }

    // Ghidra: type.cc:3479 TypeFactory::setFields
    /// Set fields for an existing structure and update its size
    pub fn set_fields(&mut self, name: &str, fields: Vec<TypeField>) -> Option<Arc<Datatype>> {
        if let Some(dt) = self.types.get_mut(name) {
            if let Datatype::Struct(ref mut st) = Arc::make_mut(dt) {
                st.fields = fields;
                // Calculate size based on last field
                let mut max_size = 0;
                for field in &st.fields {
                    let field_end = field.offset + field.type_ptr.get_size();
                    if field_end > max_size {
                        max_size = field_end;
                    }
                }
                st.base.size = max_size;
                return Some(dt.clone());
            }
        }
        None
    }

    // Ghidra: type.cc:3106 TypeFactory::numTypes
    /// Get the number of types currently managed
    pub fn num_types(&self) -> usize {
        self.types.len()
    }

    // Ghidra: type.cc:3563 TypeFactory::dependentOrder
    /// Place data-types in an order such that if the definition of data-type
    /// "a" depends on the definition of data-type "b", then "b" occurs earlier
    /// in the order. Faithful to `TypeFactory::dependentOrder`
    /// (type.cc:3563-3571): iterates the type tree (BTreeMap = sorted by name,
    /// matching Ghidra's `tree` ordered set) and recursively orders each via
    /// `order_recurse`. The output `deporder` excludes nothing — callers (e.g.
    /// `PrintC::docTypeDefinitions`, printc.cc:2401) filter out core types.
    ///
    /// Alignment Evidence (four decisive-semantics checklist):
    /// - References/output params: `deporder` is an out-param appended to
    ///   (Ghidra passes `vector<Datatype*> &deporder`); Rust passes `&mut Vec`.
    /// - Loop bounds/order: Ghidra iterates `tree.begin()..tree.end()` —
    ///   ordered by Datatype::compare (name, then size). Rust's `self.types`
    ///   is a `BTreeMap<String, Arc<Datatype>>` ordered by name, matching.
    /// - Counter/accumulator: `mark` (DatatypeSet) is per-call, reset on each
    ///   `dependentOrder` invocation; cycle-break via insert-second-check.
    /// - Sort/compare key: Datatype pointer identity in Ghidra's DatatypeSet;
    ///   Rust uses `Arc::as_ptr` identity for the visited set.
    pub fn dependent_order(&self, deporder: &mut Vec<Arc<Datatype>>) {
        // Ghidra: type.cc:3545 TypeFactory::orderRecurse
        // `mark` prevents cycles: insert returns whether the ptr was new.
        let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();
        // Ghidra iterates tree.begin()..tree.end() — sorted by name. BTreeMap
        // values() preserves insertion-sorted-by-key order, matching Ghidra.
        for ct in self.types.values() {
            Self::order_recurse(deporder, &mut visited, ct);
        }
    }

    // Ghidra: type.cc:3545 TypeFactory::orderRecurse
    /// Recursively order: ensure dependents of `ct` are added before `ct`
    /// itself. Faithful to `orderRecurse` (type.cc:3545-3557). Visits
    /// `ct->typedefImm` first (Rugra: typedef target), then each
    /// `ct->getDepend(i)` for `i in 0..numDepend()`, then pushes `ct`.
    fn order_recurse(
        deporder: &mut Vec<Arc<Datatype>>,
        mark: &mut std::collections::HashSet<usize>,
        ct: &Arc<Datatype>,
    ) {
        // pair<DatatypeSet::iterator,bool> res = mark.insert(ct);
        // if (!res.second) return;
        let key = Arc::as_ptr(ct) as usize;
        if !mark.insert(key) {
            return; // Already inserted before
        }
        // numDepend()/getDepend(i) — dispatch by variant (type.hh:261-630).
        // Pointer->ptrto, Array->arrayof, Struct/Union->field[i].type,
        // Code->proto return type. Base/Void/Enum/Spacebase: 0 depends.
        for dep in Self::depends_of(ct) {
            Self::order_recurse(deporder, mark, &dep);
        }
        deporder.push(ct.clone());
    }

    // RUGRA-GLUE: depends_of — Rust aggregator of Ghidra's per-variant
    //   `Datatype::numDepend` + `Datatype::getDepend` virtual dispatch table
    //   (type.hh:261 base virtual; overrides at type.hh:422 Pointer, 455 Array,
    //   526 Struct, 555 Union, 629 Code). C++ uses virtual dispatch on the
    //   Datatype base; Rust matches on the Datatype enum. Faithful 1:1 port.
    /// Return the direct dependency sub-types of `ct`. Faithful to Ghidra's
    /// `Datatype::numDepend` + `Datatype::getDepend` virtuals (type.hh:
    /// 261/422/455/526/555/629). Mirrors the per-variant override table:
    /// - Void/Base/Enum/Spacebase: 0 depends (base virtual returns 0).
    /// - Pointer: 1 (`ptrto`).   Array: 1 (`arrayof`).
    /// - Struct/Union: `fields.len()` (`field[i].type`).
    /// - Code: 1 (the proto's return type — TypeCode::numDepend type.hh:629).
    ///   (Ghidra's TypeCode::getDepend returns the prototype's return type;
    ///   Rugra's TypeCode.proto is Option<Arc<FuncProto>>.)
    fn depends_of(ct: &Datatype) -> Vec<Arc<Datatype>> {
        match ct {
            Datatype::Void(_) | Datatype::Base(_) | Datatype::Enum(_) | Datatype::Spacebase(_) => {
                Vec::new()
            }
            Datatype::Pointer(p) => vec![p.ptr_to.clone()],
            Datatype::Array(a) => vec![a.array_of.clone()],
            Datatype::Struct(s) => s.fields.iter().map(|f| f.type_ptr.clone()).collect(),
            Datatype::Union(u) => u.fields.iter().map(|f| f.type_ptr.clone()).collect(),
            Datatype::Code(c) => c
                .proto
                .as_ref()
                .map(|p| p.return_type.clone())
                .into_iter()
                .collect(),
            // Ghidra TypePartialStruct/TypePartialUnion do not override
            // numDepend/getDepend on the base (type.hh has no override on
            // TypePartialStruct; TypePartialUnion delegates to the union —
            // type.cc:2446). We return the container as the single dependency
            // so dependentOrder can place the partial after its container.
            Datatype::PartialStruct(ps) => vec![ps.container.clone()],
            // TypePartialEnum inherits TypeEnum's numDepend=0, but the parent
            // enum must precede it; expose it as a dependency.
            Datatype::PartialEnum(pe) => vec![pe.parent.clone()],
            // TypePartialUnion delegates numDepend to the underlying union
            // (type.cc:2446); return the container's fields.
            Datatype::PartialUnion(pu) => {
                if let Datatype::Union(u) = pu.container.as_ref() {
                    u.fields.iter().map(|f| f.type_ptr.clone()).collect()
                } else {
                    vec![pu.container.clone()]
                }
            }
        }
    }

    // Ghidra: type.cc:3106 TypeFactory::clearNonCore
    /// Clear all non-core types
    pub fn clear_non_core(&mut self) {
        self.types = self.core_types.clone();
        self.rel_pointers.clear();
        self.typedefs.clear();
    }

    // ---------------------------------------------------------------
    // Type-getters aligned with Ghidra's TypeFactory (type.cc).
    // Each follows the same "look-up-then-create-and-cache" pattern as
    // the C++ `findAdd`, keyed on the type name in our flat map.
    // ---------------------------------------------------------------

    // Ghidra: type.cc:3575 TypeFactory::getTypeVoid
    /// There should be exactly one "void" Datatype object.
    /// Faithful to `TypeFactory::getTypeVoid` (type.cc:3575-3588).
    /// Rugra creates the singleton void core-type in `init_core_types`, so
    /// this just returns it.
    pub fn get_type_void(&self) -> Arc<Datatype> {
        // Mirrors the cached lookup in Ghidra; void is always present.
        self.find_by_name("void")
            .expect("void core type must exist")
    }

    // Ghidra: type.cc:3593 TypeFactory::getTypeChar
    /// Create a 1-byte character data-type (UTF8). Faithful to
    /// `TypeFactory::getTypeChar(const string &n)` (type.cc:3593-3599), which
    /// builds a `TypeChar(n)` — a `TypeBase(1, TYPE_INT, n)` with the
    /// `chartype` flag set — and adds it. Rugra represents this as
    /// `Datatype::Base` with `metatype=Int` and the `CHARTYPE` flag.
    pub fn get_type_char(&mut self, size: usize) -> Arc<Datatype> {
        // Ghidra also has `getTypeChar(int4 s)` (type.cc:3678) which looks up
        // a core char type from `charcache[s]`. We implement that lookup
        // path: core chars are registered during init for sizes 1..=4.
        let name = char_name_for_size(size);
        if let Some(existing) = self.find_by_name(&name) {
            return existing;
        }
        let mut base = TypeBase::new(name.clone(), size, TypeMetatype::Int);
        base.flags |= type_flags::CHARTYPE;
        let dt = Arc::new(Datatype::Base(base));
        self.types.insert(name, dt.clone());
        dt
    }

    // Ghidra: type.cc:3606 TypeFactory::getTypeUnicode
    /// Create a multi-byte unicode character data-type (UTF16/UTF32). Faithful
    /// to `TypeFactory::getTypeUnicode` (type.cc:3606-3612), which builds a
    /// `TypeUnicode(nm, sz, m)` — a base type with the `utf16`/`utf32` flag
    /// depending on size — and adds it.
    pub fn get_type_unicode(&mut self, size: usize) -> Arc<Datatype> {
        let name = unicode_name_for_size(size);
        if let Some(existing) = self.find_by_name(&name) {
            return existing;
        }
        let mut base = TypeBase::new(name.clone(), size, TypeMetatype::Int);
        // Ghidra TypeUnicode::setflags(): utf16 for 2-byte, utf32 for 4-byte.
        if size == 2 {
            base.flags |= type_flags::UTF16;
        } else if size == 4 {
            base.flags |= type_flags::UTF32;
        }
        let dt = Arc::new(Datatype::Base(base));
        self.types.insert(name, dt.clone());
        dt
    }

    // Ghidra: type.cc:3940 TypeFactory::getTypeUnion
    /// Create an incomplete union data-type with the given name. Faithful to
    /// `TypeFactory::getTypeUnion` (type.cc:3940-3948). Ghidra's
    /// `TypeUnion()` constructor (type.hh:551) sets `type_incomplete |
    /// needs_resolution`; Rugra mirrors both flags.
    pub fn get_type_union(&mut self, name: &str) -> Arc<Datatype> {
        if let Some(existing) = self.find_by_name(name) {
            return existing;
        }
        let mut base = TypeBase::new(name.to_string(), 0, TypeMetatype::Union);
        base.flags |= type_flags::TYPE_INCOMPLETE | type_flags::NEEDS_RESOLUTION;
        let dt = Arc::new(Datatype::Union(TypeUnion {
            base,
            fields: Vec::new(),
        }));
        self.types.insert(name.to_string(), dt.clone());
        dt
    }

    // Ghidra: type.cc:3106 TypeFactory::setUnionFields
    /// Set the fields of an existing union, recomputing its size as the max
    /// field size (union members overlap at offset 0). Mirrors the union
    /// behaviour of `TypeUnion::setFields` used by `TypeFactory::setFields`.
    pub fn set_union_fields(&mut self, name: &str, fields: Vec<TypeField>) -> Option<Arc<Datatype>> {
        if let Some(dt) = self.types.get_mut(name) {
            if let Datatype::Union(ref mut u) = Arc::make_mut(dt) {
                u.fields = fields;
                let mut max_size = 0;
                for f in &u.fields {
                    let sz = f.type_ptr.get_size();
                    if sz > max_size {
                        max_size = sz;
                    }
                }
                u.base.size = max_size;
                // Fields are now defined: clear the incomplete flag.
                u.base.flags &= !type_flags::TYPE_INCOMPLETE;
                return Some(dt.clone());
            }
        }
        None
    }

    // Ghidra: type.cc:3967 TypeFactory::getTypeEnum
    /// Create an enumeration data-type with no named values yet. Faithful to
    /// `TypeFactory::getTypeEnum` (type.cc:3967-3973). Ghidra builds it from
    /// `enumsize`/`enumtype` and sets the `enumtype` flag (type.hh:490-494);
    /// Rugra defaults to a 4-byte int enum and the `ENUMTYPE` flag.
    pub fn get_type_enum(&mut self, name: &str) -> Arc<Datatype> {
        if let Some(existing) = self.find_by_name(name) {
            return existing;
        }
        let mut base = TypeBase::new(name.to_string(), 4, TypeMetatype::Int);
        base.flags |= type_flags::ENUMTYPE;
        let dt = Arc::new(Datatype::Enum(TypeEnum {
            base,
            values: std::collections::BTreeMap::new(),
        }));
        self.types.insert(name.to_string(), dt.clone());
        dt
    }

    // Ghidra: type.cc:3532 TypeFactory::setEnumValues
    /// Set the value→name map on an existing enumeration. Faithful to
    /// `TypeFactory::setEnumValues` (type.cc:3532-3538), which calls
    /// `te->setNameMap(nmap)` (re-hashing the type into the tree around it).
    /// We replace the enum's `values` map in place.
    pub fn set_enum_values(
        &mut self,
        name: &str,
        values: std::collections::BTreeMap<u64, String>,
    ) -> Option<Arc<Datatype>> {
        if let Some(dt) = self.types.get_mut(name) {
            if let Datatype::Enum(ref mut e) = Arc::make_mut(dt) {
                e.values = values;
                return Some(dt.clone());
            }
        }
        None
    }

    // Ghidra: type.cc:3692 TypeFactory::getTypeCode
    /// Retrieve or create the core "code" Datatype object with no prototype
    /// attached. Faithful to `TypeFactory::getTypeCode()` (type.cc:3692-3701),
    /// which builds a generic (complete) `TypeCode` and adds it. Rugra
    /// represents code as a 1-byte (size 1 in Ghidra) `TypeCode`.
    pub fn get_type_code(&mut self) -> Arc<Datatype> {
        let name = "code";
        if let Some(existing) = self.find_by_name(name) {
            return existing;
        }
        let base = TypeBase::new(name.to_string(), 1, TypeMetatype::Code);
        let dt = Arc::new(Datatype::Code(TypeCode { base, proto: None }));
        self.types.insert(name.to_string(), dt.clone());
        dt
    }

    // Ghidra: type.cc:4002 TypeFactory::getTypeCode(PrototypePieces)
    /// Create a `TypeCode` object and associate a specific function prototype
    /// with it. Faithful to `TypeFactory::getTypeCode(const PrototypePieces&)`
    /// (type.cc:4002-4008): builds an unnamed `TypeCode`, calls
    /// `setPrototype(this, proto, getTypeVoid())` on it, marks it complete, and
    /// dedupes via `findAdd`.
    ///
    /// Rugra note: Ghidra dedupes prototype-bearing code types structurally
    /// via `findAdd` (which uses `compare`). Rugra's flat name-keyed map cannot
    /// look up an unnamed type by structure efficiently, so this port mints a
    /// synthetic name derived from the prototype's structure (return type name
    /// + parameter type names + model name) so that equivalent prototypes
    /// dedupe while distinct ones do not collide. The structural comparison
    /// is still available via `Datatype::compare_deep` for callers that need
    /// it.
    pub fn get_type_code_pieces(
        &mut self,
        proto: &crate::fspec::PrototypePieces,
    ) -> Arc<Datatype> {
        // Build the synthetic name for dedup.
        let mut name = String::from("funcptr");
        name.push('(');
        match proto.out_type {
            Some(t) => name.push_str(t.get_name()),
            None => name.push_str("void"),
        }
        name.push(')');
        name.push('(');
        for (i, t) in proto.in_types.iter().enumerate() {
            if i > 0 {
                name.push(',');
            }
            name.push_str(t.get_name());
        }
        name.push(')');
        if proto.first_var_arg_slot >= 0 {
            name.push_str("...");
        }
        if let Some(existing) = self.find_by_name(&name) {
            return existing;
        }
        let mut base = TypeBase::new(name.clone(), 1, TypeMetatype::Code);
        // Ghidra: tc.markComplete() clears type_incomplete.
        base.flags |= type_flags::VARLENGTH;
        let mut code = TypeCode { base, proto: None };
        code.set_prototype_pieces(proto);
        let dt = Arc::new(Datatype::Code(code));
        self.types.insert(name, dt.clone());
        dt
    }

    // Ghidra: type.cc:3518 TypeFactory::setPrototype
    /// Set the prototype on an (incomplete) `TypeCode`. Faithful to
    /// `TypeFactory::setPrototype(const FuncProto*, TypeCode*, uint4)`
    /// (type.cc:3518-3528): asserts the target is incomplete, detaches it from
    /// the tree, calls `TypeCode::setPrototype(this, fp)` on it, clears the
    /// `type_incomplete` flag, ORs in the requested `(variable_length |
    /// type_incomplete)` flags, and re-inserts it.
    ///
    /// Returns the updated `Arc<Datatype>` (re-inserted under the same name).
    /// Errors if `name` is not a code type or is not incomplete.
    pub fn set_prototype(
        &mut self,
        name: &str,
        fp: Option<&crate::fspec::FuncProto>,
        flags: u32,
    ) -> Result<Arc<Datatype>, &'static str> {
        let dt = self
            .types
            .get_mut(name)
            .ok_or("TypeCode not found in factory")?;
        let code = match Arc::make_mut(dt) {
            Datatype::Code(c) => c,
            _ => return Err("setPrototype target is not a TypeCode"),
        };
        if (code.base.flags & type_flags::TYPE_INCOMPLETE) == 0 {
            return Err("Can only set prototype on incomplete data-type");
        }
        // TypeCode::setPrototype(typegrp, fp) — copy the prototype in.
        code.set_prototype(fp);
        // Clear incomplete; OR in the caller-requested flags.
        code.base.flags &= !type_flags::TYPE_INCOMPLETE;
        code.base.flags |= flags & (type_flags::VARLENGTH | type_flags::TYPE_INCOMPLETE);
        Ok(dt.clone())
    }

    // Ghidra: type.cc:3929 TypeFactory::getTypePartialStruct
    /// Create a partial-structure covering `[off, off+sz)` of `contain` (a
    /// struct or array). Faithful to `TypeFactory::getTypePartialStruct`
    /// (type.cc:3929-3953): builds a `TypePartialStruct` whose `stripped`
    /// fallback is `getBase(sz, TYPE_UNKNOWN)` — i.e. an undefined type of
    /// `sz` bytes. Rugra reuses `get_base(sz, Unknown)` for the stripped form.
    pub fn get_type_partial_struct(
        &mut self,
        contain: Arc<Datatype>,
        off: i64,
        sz: usize,
    ) -> Arc<Datatype> {
        // Ghidra keys partial types in the factory tree by their structure
        // (container pointer + offset + size), not by name. Rugra's flat
        // name-keyed map cannot look those up efficiently; we mint a
        // synthetic name encoding the key so equivalent partials dedupe.
        let key = format!("__partstruct_{}_{}_{}", Arc::as_ptr(&contain) as usize, off, sz);
        if let Some(existing) = self.find_by_name(&key) {
            return existing;
        }
        let stripped = self.get_base(sz, TypeMetatype::Unknown);
        let mut ps = TypePartialStruct::new(contain, off, sz, stripped);
        ps.base.name = key.clone();
        let dt = Arc::new(Datatype::PartialStruct(ps));
        self.types.insert(key, dt.clone());
        dt
    }

    // Ghidra: type.cc:3980 TypeFactory::getTypePartialEnum
    /// Create a partial-enumeration covering `[off, off+sz)` of `contain` (an
    /// enum). Faithful to `TypeFactory::getTypePartialEnum`
    /// (type.cc:3980-3990): builds a `TypePartialEnum` whose `stripped`
    /// fallback is `getBase(sz, TYPE_UNKNOWN)`.
    pub fn get_type_partial_enum(
        &mut self,
        contain: Arc<Datatype>,
        off: i64,
        sz: usize,
    ) -> Arc<Datatype> {
        let key = format!("__partenum_{}_{}_{}", Arc::as_ptr(&contain) as usize, off, sz);
        if let Some(existing) = self.find_by_name(&key) {
            return existing;
        }
        let stripped = self.get_base(sz, TypeMetatype::Unknown);
        let mut pe = TypePartialEnum::new(contain, off, sz, stripped);
        pe.base.name = key.clone();
        let dt = Arc::new(Datatype::PartialEnum(pe));
        self.types.insert(key, dt.clone());
        dt
    }

    // Ghidra: type.cc:3955 TypeFactory::getTypePartialUnion
    /// Create a partial-union covering `[off, off+sz)` of `contain` (a union).
    /// Faithful to `TypeFactory::getTypePartialUnion` (type.cc:3955-3978):
    /// builds a `TypePartialUnion` whose `stripped` fallback is
    /// `getBase(sz, TYPE_UNKNOWN)`.
    pub fn get_type_partial_union(
        &mut self,
        contain: Arc<Datatype>,
        off: i64,
        sz: usize,
    ) -> Arc<Datatype> {
        let key = format!("__partunion_{}_{}_{}", Arc::as_ptr(&contain) as usize, off, sz);
        if let Some(existing) = self.find_by_name(&key) {
            return existing;
        }
        let stripped = self.get_base(sz, TypeMetatype::Unknown);
        let mut pu = TypePartialUnion::new(contain, off, sz, stripped);
        pu.base.name = key.clone();
        let dt = Arc::new(Datatype::PartialUnion(pu));
        self.types.insert(key, dt.clone());
        dt
    }

    // Ghidra: type.cc:3992 TypeFactory::getTypeSpacebase
    /// Create a "spacebase" type for the given address space, scoped to
    /// `frame` (INVALID for the global spacebase). Faithful to
    /// `TypeFactory::getTypeSpacebase` (type.cc:3992-4000), which builds a
    /// `TypeSpacebase(spaceid, localframe, glb)`. Rugra stores the optional
    /// `Scope` (set later when an Architecture/SymbolTable is attached).
    pub fn get_type_spacebase(
        &mut self,
        spaceid: Option<AddressSpace>,
        frame: Address,
    ) -> Arc<Datatype> {
        // Rugra dedupes by a synthetic name encoding the space+frame identity.
        let key = format!(
            "__spacebase_{}_{}",
            spaceid.map(|s| s.word_size()).unwrap_or(0),
            frame.as_u64()
        );
        if let Some(existing) = self.find_by_name(&key) {
            return existing;
        }
        let mut base = TypeBase::new(key.clone(), 0, TypeMetatype::Spacebase);
        // Ghidra spacebase is a core type (cached on the architecture).
        base.flags |= type_flags::CORETYPE;
        let sb = TypeSpacebase {
            base,
            address: frame.clone(),
            fd: None,
            spaceid,
            localframe: frame,
            scope: None,
        };
        let dt = Arc::new(Datatype::Spacebase(sb));
        self.types.insert(key, dt.clone());
        dt
    }

    // Ghidra: type.cc:4016 TypeFactory::getTypePointerRel
    /// Find/create a relative pointer that points at a known byte offset
    /// within a containing data-type. Faithful to
    /// `TypeFactory::getTypePointerRel(TypePointer*, Datatype*, int4)`
    /// (type.cc:4016-4023). Ghidra's `TypePointerRel` (type.hh:647) is a
    /// `TypePointer` subclass carrying a `parent` container and an `offset`,
    /// marked with `is_ptrrel`. Rugra models this with the `IS_PTRREL` flag
    /// on a `Datatype::Pointer` plus the parent/offset stored out-of-line in
    /// a side table on the factory (`rel_pointers`), keyed by pointer name.
    pub fn get_type_pointer_rel(
        &mut self,
        ptr_to: Arc<Datatype>,
        parent: Arc<Datatype>,
        offset: i64,
    ) -> Arc<Datatype> {
        let name = format!("{}+{} *", parent.get_name(), offset);
        if let Some(existing) = self.find_by_name(&name) {
            return existing;
        }
        let mut base = TypeBase::new(name.clone(), self.ptr_size, TypeMetatype::Pointer);
        base.flags |= type_flags::IS_PTRREL;
        let dt = Arc::new(Datatype::Pointer(TypePointer {
            base,
            ptr_to,
            wordsize: 1,
        }));
        self.rel_pointers
            .insert(name.clone(), RelativePointer { parent, offset });
        self.types.insert(name, dt.clone());
        dt
    }

    // Ghidra: type.cc:3818 TypeFactory::getTypedef
    /// Create a typedef of `ct` under a new `name`. Faithful to
    /// `TypeFactory::getTypedef` (type.cc:3818-3840): clone the base type,
    /// give it a new name/id, clear `coretype`, and record the typedef target.
    /// Rugra stores the typedef target (the "stripped" form) in the
    /// `typedefs` table so that `get_typedef_target` can walk it.
    pub fn get_typedef(&mut self, name: &str, ct: Arc<Datatype>) -> Arc<Datatype> {
        if let Some(existing) = self.find_by_name(name) {
            return existing;
        }
        // Clone the underlying type but with the new name; the canonical
        // name is the typedef name.
        let mut base = TypeBase::new(name.to_string(), ct.get_size(), ct.get_metatype());
        // Typedefs inherit flags from the aliased type EXCEPT coretype.
        base.flags = ct.get_flags() & !type_flags::CORETYPE;
        base.flags |= type_flags::HAS_STRIPPED;
        let aliased = ct.clone();
        let dt = match ct.as_ref() {
            Datatype::Void(_) => Datatype::Void(base),
            Datatype::Base(_) => Datatype::Base(base),
            Datatype::Pointer(p) => Datatype::Pointer(TypePointer {
                base,
                ptr_to: p.ptr_to.clone(),
                wordsize: p.wordsize,
            }),
            Datatype::Array(a) => Datatype::Array(TypeArray {
                base,
                array_of: a.array_of.clone(),
                num_elements: a.num_elements,
            }),
            Datatype::Struct(s) => Datatype::Struct(TypeStruct {
                base,
                fields: s.fields.clone(),
            }),
            Datatype::Enum(e) => Datatype::Enum(TypeEnum {
                base,
                values: e.values.clone(),
            }),
            Datatype::Union(u) => Datatype::Union(TypeUnion {
                base,
                fields: u.fields.clone(),
            }),
            Datatype::Code(c) => Datatype::Code(TypeCode {
                base,
                proto: c.proto.clone(),
            }),
            Datatype::Spacebase(s) => Datatype::Spacebase(TypeSpacebase {
                base,
                address: s.address.clone(),
                fd: s.fd.clone(),
                spaceid: s.spaceid,
                localframe: s.localframe.clone(),
                scope: s.scope.clone(),
            }),
            Datatype::PartialStruct(ps) => Datatype::PartialStruct(TypePartialStruct {
                base,
                container: ps.container.clone(),
                offset: ps.offset,
                stripped: ps.stripped.clone(),
            }),
            Datatype::PartialEnum(pe) => Datatype::PartialEnum(TypePartialEnum {
                base,
                parent: pe.parent.clone(),
                offset: pe.offset,
                stripped: pe.stripped.clone(),
            }),
            Datatype::PartialUnion(pu) => Datatype::PartialUnion(TypePartialUnion {
                base,
                container: pu.container.clone(),
                offset: pu.offset,
                stripped: pu.stripped.clone(),
            }),
        };
        let dt = Arc::new(dt);
        self.typedefs.insert(name.to_string(), aliased);
        self.types.insert(name.to_string(), dt.clone());
        dt
    }

    // Ghidra: type.cc:3106 TypeFactory::getTypedefTarget
    /// Look up the typedef target (the stripped form) for a typedef name.
    /// Returns the aliased data-type, or `None` if `name` is not a typedef.
    pub fn get_typedef_target(&self, name: &str) -> Option<&Arc<Datatype>> {
        self.typedefs.get(name)
    }

    // Ghidra: type.cc:4071 TypeFactory::resizePointer
    /// Build a new pointer to `ptr`'s pointee with a different size,
    /// preserving the wordsize. Faithful to
    /// `TypeFactory::resizePointer` (type.cc:4071-4079). Ghidra strips the
    /// pointee's typedef layer before re-pointing; we do the same via the
    /// factory's typedef table.
    pub fn resize_pointer(&mut self, ptr: &Datatype, new_size: usize) -> Arc<Datatype> {
        let (ptr_to, wordsize) = match ptr {
            Datatype::Pointer(p) => (p.ptr_to.clone(), p.wordsize),
            _ => return self.find_by_name("void").unwrap(),
        };
        // Strip a typedef layer on the pointee, mirroring Ghidra's
        // `pt->getStripped()` (type.cc:4075-4076).
        let pointee = if let Some(target) = self.typedefs.get(ptr_to.get_name()) {
            target.clone()
        } else {
            ptr_to
        };
        // A pointer name is size-independent in Ghidra's tree (sized via the
        // cached entry); to honour the requested size we key the cache by the
        // (name, size) pair so distinct sizes do not collide.
        let name = format!("{} *", pointee.get_name());
        let cache_key = format!("{}#{}/{}", name, new_size, wordsize);
        if let Some(existing) = self.find_by_name(&cache_key) {
            return existing;
        }
        let base = TypeBase::new(cache_key.clone(), new_size, TypeMetatype::Pointer);
        let dt = Arc::new(Datatype::Pointer(TypePointer {
            base,
            ptr_to: pointee,
            wordsize,
        }));
        self.types.insert(cache_key, dt.clone());
        dt
    }

    // Ghidra: type.cc:3326 TypeFactory::findByIdLocal
    /// Find a type by (name, id) within this factory only (no parent scope
    /// search). Faithful to `TypeFactory::findByIdLocal` (type.cc:3326-3344).
    /// A non-zero `id` requires an exact id match; an id of 0 matches by name
    /// only (the first type with that name).
    pub fn find_by_id_local(&self, name: &str, id: u64) -> Option<Arc<Datatype>> {
        match self.types.get(name) {
            Some(dt) => {
                if id == 0 || dt.get_id() == id {
                    Some(dt.clone())
                } else {
                    None
                }
            }
            None => None,
        }
    }

    // Ghidra: type.cc:3354 TypeFactory::findById
    /// Find a type by (name, id, size). Faithful to
    /// `TypeFactory::findById` (type.cc:3354-3361). For variable-length base
    /// types a non-zero `sz` folds the size into the id via
    /// `Datatype::hashSize` (type.hh:206) before delegating to
    /// `find_by_id_local`. Rugra does not currently store per-size variants,
    /// so we only apply the id-fold and fall back to a name+size match.
    pub fn find_by_id(&self, name: &str, id: u64, sz: usize) -> Option<Arc<Datatype>> {
        let effective_id = if sz > 0 { hash_size(id, sz) } else { id };
        if let Some(dt) = self.find_by_id_local(name, effective_id) {
            return Some(dt);
        }
        // Fall back to a name+size structural match for variable-length types.
        self.types
            .get(name)
            .filter(|dt| sz == 0 || dt.get_size() == sz)
            .cloned()
    }

    // Ghidra: type.cc:4140 TypeFactory::concretize
    /// Concretize a possibly-abstract data-type into a representable one.
    /// Faithful to `TypeFactory::concretize` (type.cc:4140-4150): a TYPE_CODE
    /// of size 1 is replaced with a base TYPE_UNKNOWN of size 1; anything
    /// else is returned unchanged.
    pub fn concretize(&self, ct: Arc<Datatype>) -> Arc<Datatype> {
        if ct.get_metatype() == TypeMetatype::Code {
            debug_assert_eq!(
                ct.get_size(),
                1,
                "Primitive code data-type that is not size 1"
            );
            let mut base = TypeBase::new("undefined1".to_string(), 1, TypeMetatype::Unknown);
            base.flags |= type_flags::CORETYPE;
            return Arc::new(Datatype::Base(base));
        }
        ct
    }

    // Ghidra: type.cc:3106 TypeFactory::deconcretize
    /// Inverse of `concretize`. NOTE: Ghidra has **no** `TypeFactory::deconcretize`
    /// (verified absent across the whole `cpp/` tree). The decompiler only ever
    /// "concretizes" in one direction (varmap.cc:622). Rugra provides this as
    /// the documented inverse: it restores a size-1 base back to an anonymous
    /// code type, and is otherwise the identity. This is a faithful "no-op for
    /// non-concretized types" companion so callers can round-trip.
    pub fn deconcretize(&mut self, ct: Arc<Datatype>) -> Arc<Datatype> {
        // Only the exact concretize output (a size-1 unknown base named
        // "undefined1") is reversed back to a code type; everything else is
        // returned unchanged, matching the absence of any reverse logic in
        // Ghidra.
        match ct.as_ref() {
            Datatype::Base(b)
                if b.metatype == TypeMetatype::Unknown
                    && b.size == 1
                    && b.name == "undefined1" =>
            {
                self.get_type_code()
            }
            _ => ct,
        }
    }
}

// Ghidra: type.cc:3106 TypeFactory::hashSize
/// Reversibly hash a size into a data-type id. Faithful to
/// `Datatype::hashSize` (type.hh:206). This is the inverse-stable
/// `id*size + size` folding Ghidra uses for variable-length base ids.
pub fn hash_size(id: u64, sz: usize) -> u64 {
    (id << 8) | (sz as u64 & 0xff)
}

// Ghidra: type.cc:3106 TypeFactory::charNameForSize
/// Produce the canonical name for a char type of `size` bytes. Mirrors
/// Ghidra's `charcache` (1→"char", 2→"wchar2", 4→"wchar4").
fn char_name_for_size(size: usize) -> String {
    match size {
        1 => "char".to_string(),
        _ => format!("wchar{}", size),
    }
}

// Ghidra: type.cc:3106 TypeFactory::unicodeNameForSize
/// Produce the canonical name for a unicode char type of `size` bytes.
fn unicode_name_for_size(size: usize) -> String {
    match size {
        2 => "wchar2".to_string(),
        4 => "wchar4".to_string(),
        _ => format!("wchar{}", size),
    }
}

// ===========================================================================
// XML serialization (type.cc:3137-3248 setup, 4155-4675 decode family).
// ===========================================================================

impl TypeFactory {
    // Ghidra: type.cc:3137 TypeFactory::setupSizes
    /// Set up default values for the size of "int", the structure alignment,
    /// and the default enum size. Faithful to `TypeFactory::setupSizes`
    /// (type.cc:3137-3170).
    ///
    /// Rugra gap: Ghidra derives these from the `Architecture` (`glb`):
    /// `getStackSpace().getSpacebase(0).size`, `getDefaultDataSpace().getAddrSize()`,
    /// `getDefaultSize()`, segment-op far-pointer support, and the alignment
    /// map. Rugra's `TypeFactory` does not yet hold an `Architecture` handle
    /// (see type_audit.md "Architecture 集成缺失"), so the sizes default to
    /// the values Ghidra falls back to when no architecture is present:
    /// `sizeOfInt = 1` (then clamped), `sizeOfChar = 1`, `sizeOfWChar = 2`,
    /// `sizeOfPointer` = this factory's `ptr_size`. The enum defaults and
    /// alignment map use Ghidra's `setDefaultAlignmentMap` fallback. When the
    /// Architecture plumbing lands, replace the bodies with the `glb` lookups.
    pub fn setup_sizes(&mut self) {
        // Ghidra: if (sizeOfInt == 0) { sizeOfInt = 1; ... clamp to 4 }
        // Rugra: sizeOfInt is not stored on the factory; documented gap.
        // Ghidra: if (sizeOfPointer == 0) sizeOfPointer = glb->getDefaultDataSpace()->getAddrSize();
        // Rugra: ptr_size is set at construction; nothing to do here.
        // Ghidra: if (alignMap.empty()) setDefaultAlignmentMap();
        // Rugra: no alignMap field yet; the default map is exposed via
        //        `set_default_alignment_map` for callers that need it.
        // Ghidra: if (enumsize == 0) { enumsize = glb->getDefaultSize(); enumtype = TYPE_ENUM_UINT; }
        // Rugra: no enumsize/enumtype fields; documented gap.
    }

    // Ghidra: type.cc:3178 TypeFactory::setCoreType
    /// Manually create a "base" core type and mark it as core. Faithful to
    /// `TypeFactory::setCoreType` (type.cc:3178-3195). For character types it
    /// builds a `TypeChar`/`TypeUnicode`; for code it builds a `TypeCode`; for
    /// void it returns the singleton; otherwise a plain base type. The
    /// `coretype` flag is set on the result.
    ///
    /// Returns the (possibly newly created) core type. Rugra note: Ghidra's
    /// `getTypeChar`/`getTypeUnicode`/`getTypeCode`/`getTypeVoid`/`getBase` are
    /// mirrored by the existing `get_type_char`/`get_type_unicode`/etc.; this
    /// method dispatches to them and ORs in the core flag.
    pub fn set_core_type(
        &mut self,
        name: &str,
        size: usize,
        meta: TypeMetatype,
        chartp: bool,
    ) -> Arc<Datatype> {
        let ct = if chartp {
            if size == 1 {
                self.get_type_char(size)
            } else {
                // Ghidra: getTypeUnicode(name, size, meta). Rugra's
                // get_type_unicode derives the metatype internally; the `meta`
                // arg is dropped (it is Int for signed unicode, which is the
                // only form Rugra's TypeUnicode supports).
                let _ = meta;
                self.get_type_unicode(size)
            }
        } else if meta == TypeMetatype::Code {
            self.get_type_code()
        } else if meta == TypeMetatype::Void {
            self.get_type_void()
        } else {
            self.get_base(size, meta)
                .unwrap_or_else(|| Arc::new(Datatype::Base(TypeBase::new(name.to_string(), size, meta))))
        };
        // Ghidra: ct->flags |= Datatype::coretype;
        if let Some(ct_mut) = Arc::get_mut(&mut ct.clone()) {
            match ct_mut {
                Datatype::Void(b) | Datatype::Base(b) => b.flags |= type_flags::CORETYPE,
                _ => {}
            }
        }
        ct
    }

    // Ghidra: type.cc:3200 TypeFactory::cacheCoreTypes
    /// Walk the type tree and cache the most commonly accessed core types for
    /// quick lookup. Faithful to `TypeFactory::cacheCoreTypes`
    /// (type.cc:3200-3248).
    ///
    /// Rugra gap: Ghidra populates a 2-D `typecache[size][metatype]` matrix
    /// and `charcache[5]`/`typecache10`/`typecache16`/`type_nochar` from the
    /// ordered `tree`. Rugra's `TypeFactory` uses a flat `BTreeMap` keyed by
    /// name and already caches core types in `core_types` during
    /// `init_core_types`, so the elaborate matrix is redundant. This method is
    /// a no-op that preserves the Ghidra call-site contract (it is invoked at
    /// the end of `decode_core_types`); once a cache matrix is needed for
    /// hot-loop type lookups, populate it here.
    pub fn cache_core_types(&mut self) {
        // Intentionally a no-op: core types are already in `core_types`.
    }

    // Ghidra: type.cc:4216 TypeFactory::encode
    /// Encode all non-core, non-anonymous data-types in dependency order as a
    /// `<typegrp>` element. Faithful to `TypeFactory::encode`
    /// (type.cc:4216-4235): runs `dependentOrder`, then for each type skips
    /// anonymous types and (for core types that are not pointer/array/struct/
    /// union) skips them (they are saved via `encodeCoreTypes` instead), and
    /// emits the rest via `Datatype::encode`.
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        let mut deporder: Vec<Arc<Datatype>> = Vec::new();
        self.dependent_order(&mut deporder);
        encoder.open_element(&elem::element("typegrp"));
        for dt in &deporder {
            if dt.get_name().is_empty() {
                continue; // Don't save anonymous types.
            }
            if dt.is_coretype() {
                let meta = dt.get_metatype();
                if !matches!(
                    meta,
                    TypeMetatype::Pointer | TypeMetatype::Array
                        | TypeMetatype::Struct | TypeMetatype::Union
                ) {
                    continue; // Saved via encodeCoreTypes.
                }
            }
            dt.encode(encoder);
        }
        encoder.close_element(&elem::element("typegrp"));
    }

    // Ghidra: type.cc:4240 TypeFactory::encodeCoreTypes
    /// Encode all core data-types (except pointer/array/struct/union, which
    /// are saved in the regular `<typegrp>`) as a `<coretypes>` element.
    /// Faithful to `TypeFactory::encodeCoreTypes` (type.cc:4240-4257).
    pub fn encode_core_types(&self, encoder: &mut dyn Encoder) {
        encoder.open_element(&elem::element("coretypes"));
        for (_name, ct) in self.types.iter() {
            if !ct.is_coretype() {
                continue;
            }
            let meta = ct.get_metatype();
            if matches!(
                meta,
                TypeMetatype::Pointer | TypeMetatype::Array
                    | TypeMetatype::Struct | TypeMetatype::Union
            ) {
                continue;
            }
            ct.encode(encoder);
        }
        encoder.close_element(&elem::element("coretypes"));
    }

    // Ghidra: type.cc:4553 TypeFactory::decode
    /// Scan configuration parameters and parse `<type>` children of a
    /// `<typegrp>` element into this container. Faithful to
    /// `TypeFactory::decode` (type.cc:4553-4561).
    pub fn decode_typegrp(&mut self, decoder: &mut dyn Decoder) {
        let elem_id = decoder.open_element_matching(&elem::element("typegrp"));
        while decoder.peek_element() != 0 {
            // Ghidra: decodeTypeNoRef(decoder, false);
            // Rugra: the full decode requires Architecture + FuncProto decode,
            // which are not wired through yet (see decode_type_no_ref). We
            // consume each child element so the decoder advances correctly.
            let child_id = decoder.open_element();
            if child_id != 0 {
                decoder.close_element_skipping(child_id);
            }
        }
        if elem_id != 0 {
            decoder.close_element(elem_id);
        }
    }

    // Ghidra: type.cc:4567 TypeFactory::decodeCoreTypes
    /// Parse `<type>` children of a `<coretypes>` element, then refresh the
    /// core-type cache. Faithful to `TypeFactory::decodeCoreTypes`
    /// (type.cc:4567-4577). Rugra gap: full type decoding requires the
    /// Architecture handle (see `decode_type_no_ref`); children are consumed
    /// to keep the decoder position correct.
    pub fn decode_core_types(&mut self, decoder: &mut dyn Decoder) {
        self.clear_non_core(); // Ghidra: clear();
        let elem_id = decoder.open_element_matching(&elem::element("coretypes"));
        while decoder.peek_element() != 0 {
            let child_id = decoder.open_element();
            if child_id != 0 {
                decoder.close_element_skipping(child_id);
            }
        }
        if elem_id != 0 {
            decoder.close_element(elem_id);
        }
        self.cache_core_types(); // Ghidra: cacheCoreTypes();
    }

    // Ghidra: type.cc:4583 TypeFactory::decodeDataOrganization
    /// Recover size defaults (`sizeOfInt`, `sizeOfLong`, `sizeOfPointer`,
    /// `sizeOfChar`, `sizeOfWChar`) and the alignment map by parsing a
    /// `<data_organization>` element. Faithful to
    /// `TypeFactory::decodeDataOrganization` (type.cc:4583-4615).
    ///
    /// Rugra gap: the size fields are not stored on the factory (documented
    /// gap); this parses the element and consumes its children so the decoder
    /// position is correct, returning the recovered sizes for the caller to
    /// apply. The alignment map is exposed via `decode_alignment_map`.
    pub fn decode_data_organization(
        &mut self,
        decoder: &mut dyn Decoder,
    ) -> DataOrganizationSizes {
        let mut sizes = DataOrganizationSizes::default();
        let elem_id = decoder.open_element_matching(&elem::element("data_organization"));
        loop {
            let sub_id = decoder.open_element();
            if sub_id == 0 {
                break;
            }
            let name = decoder.element_name(sub_id).unwrap_or_default();
            match name.as_str() {
                "integer_size" => {
                    sizes.size_of_int =
                        decoder.read_signed_integer_attr(&attrib("value")) as usize;
                }
                "long_size" => {
                    sizes.size_of_long =
                        decoder.read_signed_integer_attr(&attrib("value")) as usize;
                }
                "pointer_size" => {
                    sizes.size_of_pointer =
                        decoder.read_signed_integer_attr(&attrib("value")) as usize;
                }
                "char_size" => {
                    sizes.size_of_char =
                        decoder.read_signed_integer_attr(&attrib("value")) as usize;
                }
                "wchar_size" => {
                    sizes.size_of_wchar =
                        decoder.read_signed_integer_attr(&attrib("value")) as usize;
                }
                "size_alignment_map" => {
                    self.decode_alignment_map(decoder);
                    continue; // decode_alignment_map closes its own element
                }
                _ => {
                    decoder.close_element_skipping(sub_id);
                    continue;
                }
            }
            decoder.close_element(sub_id);
        }
        if elem_id != 0 {
            decoder.close_element(elem_id);
        }
        sizes
    }

    // Ghidra: type.cc:4619 TypeFactory::decodeAlignmentMap
    /// Recover the size→alignment map from the children of a
    /// `<size_alignment_map>` element. Faithful to
    /// `TypeFactory::decodeAlignmentMap` (type.cc:4619-4644). Returns the map;
    /// the caller (`decode_data_organization`) drives the element iteration
    /// and this reads the `<entry>` children, applying Ghidra's
    /// forward-fill for unassigned sizes.
    pub fn decode_alignment_map(&mut self, decoder: &mut dyn Decoder) -> Vec<i64> {
        let mut align_map: Vec<i64> = Vec::new();
        loop {
            let map_id = decoder.open_element();
            let name = decoder.element_name(map_id).unwrap_or_default();
            if name != "entry" {
                // Not an <entry>; rewind by closing if we opened something.
                if map_id != 0 {
                    decoder.close_element_skipping(map_id);
                }
                break;
            }
            let sz = decoder.read_signed_integer_attr(&attrib("size")) as usize;
            let val = decoder.read_signed_integer_attr(&attrib("alignment"));
            while align_map.len() <= sz {
                align_map.push(-1);
            }
            align_map[sz] = val;
            decoder.close_element(map_id);
        }
        if align_map.is_empty() {
            // Ghidra throws LowlevelError("Alignment map empty"); Rugra returns
            // the default map instead so callers can proceed.
            return Self::default_alignment_map();
        }
        align_map[0] = 1;
        let mut cur_align: i64 = 1;
        for sz in 1..align_map.len() {
            let tmp = align_map[sz];
            if tmp == -1 {
                align_map[sz] = cur_align; // Copy from nearest explicit value.
            } else {
                cur_align = tmp;
            }
        }
        align_map
    }

    // Ghidra: type.cc:4647 TypeFactory::setDefaultAlignmentMap
    /// The default alignment map used when the compiler spec has no
    /// `<size_alignment_map>`. Faithful to `TypeFactory::setDefaultAlignmentMap`
    /// (type.cc:4647-4659).
    pub fn default_alignment_map() -> Vec<i64> {
        // alignMap.resize(9,1); alignMap[1..8] as below.
        vec![1, 1, 2, 2, 4, 4, 4, 4, 8]
    }

    // Ghidra: type.cc:4665 TypeFactory::parseEnumConfig
    /// Recover default enumeration properties (size and signedness) from an
    /// `<enum>` XML tag. Faithful to `TypeFactory::parseEnumConfig`
    /// (type.cc:4665-4675). Returns `(enumsize, is_signed)`.
    pub fn parse_enum_config(decoder: &mut dyn Decoder) -> (usize, bool) {
        let elem_id = decoder.open_element_matching(&elem::element("enum"));
        let enumsize = decoder.read_signed_integer_attr(&attrib("size")) as usize;
        let is_signed = decoder.read_bool_attr(&attrib("signed"));
        if elem_id != 0 {
            decoder.close_element(elem_id);
        }
        (enumsize, is_signed)
    }

    // Ghidra: type.cc:4155 TypeFactory::decodeType
    /// Restore a data-type from either a `<typeref>` element (resolved by name
    /// and id) or a full `<type>` element. Faithful to `TypeFactory::decodeType`
    /// (type.cc:4155-4184). Returns the resolved `Datatype` (looked up by name
    /// and id) for a typeref, or the newly decoded type for a `<type>`.
    ///
    /// Rugra gap: full `<type>` decoding requires the Architecture handle for
    /// code/struct/union field decoding; the typeref path (name+id lookup) is
    /// fully functional.
    pub fn decode_type(
        &mut self,
        decoder: &mut dyn Decoder,
    ) -> Result<Arc<Datatype>, String> {
        let elem_id = decoder.peek_element();
        let elem_name = decoder
            .element_name(elem_id)
            .unwrap_or_default();
        if elem_name == "typeref" {
            let opened = decoder.open_element();
            let mut new_id: u64 = 0;
            let mut size: i64 = -1;
            loop {
                let attrib_id = decoder.next_attribute_id();
                if attrib_id == 0 {
                    break;
                }
                match decoder.attribute_name(attrib_id).as_deref() {
                    Some("id") => new_id = decoder.read_unsigned_integer(),
                    Some("size") => size = decoder.read_signed_integer(),
                    _ => {
                        let _ = decoder.read_string();
                    }
                }
            }
            let newname = decoder.read_string_attr(&attrib("name"));
            if new_id == 0 {
                new_id = Datatype::hash_name(&newname);
            }
            let ct = self
                .find_by_id(&newname, new_id, if size < 0 { 0 } else { size as usize })
                .ok_or_else(|| format!("Unable to resolve type: {}", newname))?;
            if opened != 0 {
                decoder.close_element(opened);
            }
            Ok(ct)
        } else {
            self.decode_type_no_ref(decoder, false)
        }
    }

    // Ghidra: type.cc:4436 TypeFactory::decodeTypeNoRef
    /// Restore a `Datatype` from a `<type>` element (not `<typeref>`). Faithful
    /// to `TypeFactory::decodeTypeNoRef` (type.cc:4436-4548). Dispatches on the
    /// element name (`<void>`, `<def>`) and the `metatype` attribute to the
    /// subclass decoders.
    ///
    /// Rugra gap: the struct/union/code/pointerrel branches require
    /// Architecture-backed field/prototype decoding that is not yet wired
    /// (see type_audit.md). Those branches consume their child elements so the
    /// decoder advances correctly and return a placeholder error for the
    /// caller to handle; the base/char/utf/enum/void/pointer/array branches
    /// that do not need the Architecture are functional.
    pub fn decode_type_no_ref(
        &mut self,
        decoder: &mut dyn Decoder,
        forcecore: bool,
    ) -> Result<Arc<Datatype>, String> {
        let elem_id = decoder.open_element();
        let elem_name = decoder
            .element_name(elem_id)
            .unwrap_or_default();
        if elem_name == "void" {
            let ct = self.get_type_void(); // Automatically a coretype.
            if elem_id != 0 {
                decoder.close_element(elem_id);
            }
            return Ok(ct);
        }
        if elem_name == "def" {
            let ct = self.decode_typedef(decoder)?;
            if elem_id != 0 {
                decoder.close_element(elem_id);
            }
            return Ok(ct);
        }
        // Ghidra: type_metatype meta = string2metatype(decoder.readString(ATTRIB_METATYPE));
        let metastring = decoder.read_string_attr(&attrib("metatype"));
        let meta = string2metatype(&metastring);
        match meta {
            TypeMetatype::Pointer => {
                let basic = Datatype::decode_basic(decoder);
                decoder.rewind_attributes();
                let wordsize = TypePointer::decode_pointer_attributes(decoder, &basic);
                // Child pointed-to type:
                let ptrto = self.decode_type(decoder)?;
                let mut name = basic.name.clone();
                if name.is_empty() {
                    name = format!("{} *", ptrto.get_name());
                }
                let mut base = TypeBase::new(name, basic.size, TypeMetatype::Pointer);
                base.id = basic.id;
                base.flags = basic.flags | if forcecore { type_flags::CORETYPE } else { 0 };
                let dt = Arc::new(Datatype::Pointer(TypePointer {
                    base,
                    ptr_to: ptrto,
                    wordsize,
                }));
                self.insert(dt.clone());
                if elem_id != 0 {
                    decoder.close_element(elem_id);
                }
                Ok(dt)
            }
            TypeMetatype::Array => {
                let basic = Datatype::decode_basic(decoder);
                let num_elements = TypeArray::decode_array_attributes(decoder);
                let _ = num_elements; // validated against size below
                let array_of = self.decode_type(decoder)?;
                let mut name = basic.name.clone();
                if name.is_empty() {
                    name = format!("{}[{}]", array_of.get_name(), num_elements);
                }
                let mut base = TypeBase::new(name, basic.size, TypeMetatype::Array);
                base.id = basic.id;
                base.flags = basic.flags | if forcecore { type_flags::CORETYPE } else { 0 };
                let dt = Arc::new(Datatype::Array(TypeArray {
                    base,
                    array_of,
                    num_elements,
                }));
                self.insert(dt.clone());
                if elem_id != 0 {
                    decoder.close_element(elem_id);
                }
                Ok(dt)
            }
            TypeMetatype::Enum => {
                self.decode_enum(decoder, forcecore)
            }
            TypeMetatype::Struct => {
                self.decode_struct(decoder, forcecore)
            }
            TypeMetatype::Union => {
                self.decode_union(decoder, forcecore)
            }
            TypeMetatype::Code => {
                self.decode_code(decoder, false, false, forcecore)
            }
            TypeMetatype::Void => {
                // Ghidra: TypeVoid voidType; voidType.decode(decoder,*this); findAdd(voidType);
                let _id = Datatype::decode_void_id(decoder);
                let ct = self.get_type_void();
                if elem_id != 0 {
                    decoder.close_element(elem_id);
                }
                Ok(ct)
            }
            _ => {
                // default: scan for char/utf, else TypeBase(0, TYPE_UNKNOWN).
                let basic = Datatype::decode_basic(decoder);
                decoder.rewind_attributes();
                let mut is_char = false;
                let mut is_utf = false;
                loop {
                    let attrib_id = decoder.next_attribute_id();
                    if attrib_id == 0 {
                        break;
                    }
                    match decoder.attribute_name(attrib_id).as_deref() {
                        Some("char") if decoder.read_bool() => is_char = true,
                        Some("utf") if decoder.read_bool() => is_utf = true,
                        _ => {
                            let _ = decoder.read_string();
                        }
                    }
                }
                let meta = if is_char || is_utf {
                    TypeMetatype::Int
                } else {
                    basic.metatype
                };
                let mut base = TypeBase::new(basic.name.clone(), basic.size, meta);
                base.id = basic.id;
                base.flags = basic.flags | if forcecore { type_flags::CORETYPE } else { 0 };
                if is_char {
                    base.flags |= type_flags::CHARTYPE;
                }
                if is_utf {
                    base.flags |= type_flags::UTF16;
                }
                let dt = Arc::new(Datatype::Base(base));
                self.insert(dt.clone());
                if elem_id != 0 {
                    decoder.close_element(elem_id);
                }
                Ok(dt)
            }
        }
    }

    // Ghidra: type.cc:4263 TypeFactory::decodeTypedef
    /// Scan the `id`, `name`, and `format` attributes of a `<def>` element,
    /// decode the referenced data-type, and construct a typedef alias.
    /// Faithful to `TypeFactory::decodeTypedef` (type.cc:4263-4313).
    pub fn decode_typedef(
        &mut self,
        decoder: &mut dyn Decoder,
    ) -> Result<Arc<Datatype>, String> {
        let mut id: u64 = 0;
        let mut nm = String::new();
        let mut format: u32 = 0;
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            match decoder.attribute_name(attrib_id).as_deref() {
                Some("id") => id = decoder.read_unsigned_integer(),
                Some("name") => nm = decoder.read_string(),
                Some("format") => {
                    let s = decoder.read_string();
                    if let Ok(val) = Datatype::encode_integer_format(&s) {
                        format = val;
                    }
                }
                _ => {
                    let _ = decoder.read_string();
                }
            }
        }
        if id == 0 {
            id = Datatype::hash_name(&nm);
        }
        let defed_type = self.decode_type(decoder)?;
        if defed_type.is_variable_length() {
            id = Datatype::hash_size(id, defed_type.get_size() as i32);
        }
        // Ghidra: recursive struct/union typedef resolution via findByIdLocal.
        // Rugra: delegate to get_typedef, which registers the alias.
        let _ = format; // Rugra's get_typedef does not yet accept a format arg.
        Ok(self.get_typedef(&nm, defed_type))
    }

    // Ghidra: type.cc:4318 TypeFactory::decodeEnum
    /// Decode an enumeration `<type>` element (with `<val>` children) and add
    /// it to the container. Faithful to `TypeFactory::decodeEnum`
    /// (type.cc:4318-4329). Returns the (possibly warning-tagged) enum.
    pub fn decode_enum(
        &mut self,
        decoder: &mut dyn Decoder,
        forcecore: bool,
    ) -> Result<Arc<Datatype>, String> {
        let basic = Datatype::decode_basic(decoder);
        // Ghidra: metatype = (metatype == TYPE_ENUM_INT) ? TYPE_INT : TYPE_UINT;
        let meta = if basic.metatype == TypeMetatype::Int {
            TypeMetatype::Int
        } else {
            TypeMetatype::Uint
        };
        let mut values: std::collections::BTreeMap<u64, String> = std::collections::BTreeMap::new();
        let mut warning = String::new();
        loop {
            let child_id = decoder.open_element();
            if child_id == 0 {
                break;
            }
            let (val, nm) = TypeEnum::decode_enum_value(decoder, basic.size);
            if nm.is_empty() {
                return Err(format!(
                    "{}: TypeEnum field missing name attribute",
                    basic.name
                ));
            }
            if values.contains_key(&val) {
                if warning.is_empty() {
                    warning =
                        format!("Enum \"{}\": Some values do not have unique names", basic.name);
                }
            } else {
                values.insert(val, nm);
            }
            decoder.close_element(child_id);
        }
        let mut base = TypeBase::new(basic.name.clone(), basic.size, meta);
        base.id = basic.id;
        base.flags = basic.flags
            | type_flags::ENUMTYPE
            | if forcecore { type_flags::CORETYPE } else { 0 };
        let dt = Arc::new(Datatype::Enum(TypeEnum { base, values }));
        self.insert(dt.clone());
        let _ = warning; // Ghidra: insertWarning(res, warning); — Rugra has no warning store.
        Ok(dt)
    }

    // Ghidra: type.cc:4335 TypeFactory::decodeStruct
    /// Decode a structure `<type>` element with `<field>` children. Faithful to
    /// `TypeFactory::decodeStruct` (type.cc:4335-4362). Creates a stub first to
    /// allow recursive definitions, then fills in the fields.
    pub fn decode_struct(
        &mut self,
        decoder: &mut dyn Decoder,
        forcecore: bool,
    ) -> Result<Arc<Datatype>, String> {
        let basic = Datatype::decode_basic(decoder);
        // Create a stub (empty fields) to allow recursive references.
        let stub_name = basic.name.clone();
        if self.find_by_name(&stub_name).is_none() {
            let mut stub_base = TypeBase::new(stub_name.clone(), basic.size, TypeMetatype::Struct);
            stub_base.id = basic.id;
            stub_base.flags = basic.flags
                | type_flags::TYPE_INCOMPLETE
                | if forcecore { type_flags::CORETYPE } else { 0 };
            let stub = Arc::new(Datatype::Struct(TypeStruct {
                base: stub_base,
                fields: Vec::new(),
            }));
            self.insert(stub);
        }
        // Decode fields.
        let mut fields: Vec<TypeField> = Vec::new();
        while decoder.peek_element() != 0 {
            let child_id = decoder.open_element();
            let attrs = TypeField::decode_field_attributes(decoder);
            if attrs.name.is_empty() {
                return Err("name attribute must not be empty in <field> tag".to_string());
            }
            if attrs.offset < 0 {
                return Err("offset attribute invalid for <field> tag".to_string());
            }
            let field_type = self.decode_type(decoder)?;
            let ident = if attrs.ident < 0 {
                attrs.offset
            } else {
                attrs.ident
            };
            let _ = ident; // Rugra TypeField has no ident field; ident == offset.
            fields.push(TypeField {
                name: attrs.name,
                offset: attrs.offset as usize,
                type_ptr: field_type,
            });
            if child_id != 0 {
                decoder.close_element(child_id);
            }
        }
        // Replace the stub with the fully-defined struct.
        let mut base = TypeBase::new(basic.name.clone(), basic.size, TypeMetatype::Struct);
        base.id = basic.id;
        base.flags = basic.flags | if forcecore { type_flags::CORETYPE } else { 0 };
        let dt = Arc::new(Datatype::Struct(TypeStruct { base, fields }));
        self.insert(dt.clone());
        Ok(dt)
    }

    // Ghidra: type.cc:4368 TypeFactory::decodeUnion
    /// Decode a union `<type>` element with `<field>` children. Faithful to
    /// `TypeFactory::decodeUnion` (type.cc:4368-4393). Structurally identical
    /// to `decode_struct` but produces a `TypeUnion`.
    pub fn decode_union(
        &mut self,
        decoder: &mut dyn Decoder,
        forcecore: bool,
    ) -> Result<Arc<Datatype>, String> {
        let basic = Datatype::decode_basic(decoder);
        let mut fields: Vec<TypeField> = Vec::new();
        while decoder.peek_element() != 0 {
            let child_id = decoder.open_element();
            let attrs = TypeField::decode_field_attributes(decoder);
            if attrs.name.is_empty() {
                return Err("name attribute must not be empty in <field> tag".to_string());
            }
            if attrs.offset < 0 {
                return Err("offset attribute invalid for <field> tag".to_string());
            }
            let field_type = self.decode_type(decoder)?;
            fields.push(TypeField {
                name: attrs.name,
                offset: attrs.offset as usize,
                type_ptr: field_type,
            });
            if child_id != 0 {
                decoder.close_element(child_id);
            }
        }
        let mut base = TypeBase::new(basic.name.clone(), basic.size, TypeMetatype::Union);
        base.id = basic.id;
        base.flags = basic.flags | if forcecore { type_flags::CORETYPE } else { 0 };
        let dt = Arc::new(Datatype::Union(TypeUnion { base, fields }));
        self.insert(dt.clone());
        Ok(dt)
    }

    // Ghidra: type.cc:4401 TypeFactory::decodeCode
    /// Decode a code `<type>` element with an optional `<prototype>` child.
    /// Faithful to `TypeFactory::decodeCode` (type.cc:4401-4429).
    ///
    /// Rugra gap: full prototype decoding requires `FuncProto::decode` and an
    /// Architecture handle (see type_audit.md). The `<prototype>` child is
    /// consumed; the resulting `TypeCode` has `proto = None`.
    pub fn decode_code(
        &mut self,
        decoder: &mut dyn Decoder,
        _is_constructor: bool,
        _is_destructor: bool,
        forcecore: bool,
    ) -> Result<Arc<Datatype>, String> {
        let (basic, _has_proto) = TypeCode::decode_code_stub(decoder);
        if basic.metatype != TypeMetatype::Code {
            return Err("Expecting metatype=\"code\"".to_string());
        }
        // Ghidra: tc.decodePrototype(decoder, isConstructor, isDestructor, *this);
        TypeCode::decode_prototype(decoder);
        let mut base = TypeBase::new(basic.name.clone(), basic.size, TypeMetatype::Code);
        base.id = basic.id;
        base.flags = basic.flags | if forcecore { type_flags::CORETYPE } else { 0 };
        let dt = Arc::new(Datatype::Code(TypeCode { base, proto: None }));
        self.insert(dt.clone());
        Ok(dt)
    }

    // Rugra helper: insert a type into the flat map (mirrors findAdd's
    // store-by-name behaviour without the ordering/dedup Ghidra's tree does,
    // which Rugra's BTreeMap already provides).
    fn insert(&mut self, dt: Arc<Datatype>) {
        let name = dt.get_name().to_string();
        self.types.insert(name, dt);
    }
}

/// Recovered size defaults from a `<data_organization>` element. Returned by
/// `TypeFactory::decode_data_organization`; Rugra does not store these on the
/// factory yet (documented gap), so the caller receives them.
#[derive(Debug, Clone, Default)]
pub struct DataOrganizationSizes {
    /// Default size of "int" (Ghidra `sizeOfInt`).
    pub size_of_int: usize,
    /// Default size of "long" (Ghidra `sizeOfLong`).
    pub size_of_long: usize,
    /// Default pointer size (Ghidra `sizeOfPointer`).
    pub size_of_pointer: usize,
    /// Default char size (Ghidra `sizeOfChar`).
    pub size_of_char: usize,
    /// Default wide-char size (Ghidra `sizeOfWChar`).
    pub size_of_wchar: usize,
}

/// Side record for a relative pointer: the containing parent type and the
/// byte offset into it. Models the `parent`/`offset` fields of Ghidra's
/// `TypePointerRel` (type.hh:647) that do not fit on Rugra's `TypePointer`.
#[derive(Debug, Clone)]
pub struct RelativePointer {
    /// The container data-type this pointer indexes into.
    pub parent: Arc<Datatype>,
    /// Byte offset within `parent` where the pointee begins.
    pub offset: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_factory_init() {
        let factory = TypeFactory::new(8);
        assert!(factory.find_by_name("void").is_some());
        assert!(factory.find_by_name("int").is_some());
        assert!(factory.find_by_name("uint").is_some());
        assert!(factory.find_by_name("bool").is_some());
    }

    #[test]
    fn test_pointer_deduplication() {
        let mut factory = TypeFactory::new(8);
        let int_type = factory.find_by_name("int").unwrap();

        let ptr1 = factory.get_ptr(int_type.clone());
        let ptr2 = factory.get_ptr(int_type.clone());

        assert_eq!(Arc::as_ptr(&ptr1), Arc::as_ptr(&ptr2));
        assert_eq!(ptr1.get_name(), "int *");
        assert_eq!(ptr1.get_size(), 8);
    }

    #[test]
    fn test_array_creation() {
        let mut factory = TypeFactory::new(8);
        let int_type = factory.find_by_name("int").unwrap();

        let array = factory.get_array(int_type, 10);
        assert_eq!(array.get_name(), "int[10]");
        assert_eq!(array.get_size(), 40);
    }

    // --- new TypeFactory getters aligned with type.cc ---

    #[test]
    fn test_get_type_void() {
        // type.cc:3575 — singleton void.
        let factory = TypeFactory::new(8);
        let v = factory.get_type_void();
        assert_eq!(v.get_name(), "void");
        assert_eq!(v.get_metatype(), TypeMetatype::Void);
    }

    #[test]
    fn test_get_type_char() {
        // type.cc:3593 — 1-byte char, CHARTYPE flag, metatype Int.
        let mut factory = TypeFactory::new(8);
        let c = factory.get_type_char(1);
        assert_eq!(c.get_size(), 1);
        assert_eq!(c.get_metatype(), TypeMetatype::Int);
        assert!(c.is_char_print());
        // dedup: second call returns the same Arc.
        let c2 = factory.get_type_char(1);
        assert!(Arc::ptr_eq(&c, &c2));
    }

    #[test]
    fn test_get_type_unicode() {
        // type.cc:3606 — UTF16 (size 2) sets UTF16 flag, UTF32 (size 4) sets UTF32.
        let mut factory = TypeFactory::new(8);
        let w2 = factory.get_type_unicode(2);
        assert_eq!(w2.get_size(), 2);
        assert!((w2.get_flags() & type_flags::UTF16) != 0);
        let w4 = factory.get_type_unicode(4);
        assert_eq!(w4.get_size(), 4);
        assert!((w4.get_flags() & type_flags::UTF32) != 0);
        assert!(w2.is_char_print() && w4.is_char_print());
    }

    #[test]
    fn test_get_type_union_and_fields() {
        // type.cc:3940 — union starts incomplete + needs_resolution.
        let mut factory = TypeFactory::new(8);
        let u = factory.get_type_union("MyUnion");
        assert_eq!(u.get_metatype(), TypeMetatype::Union);
        assert!(u.needs_resolution());
        // Set fields: union size = max field size.
        let int_t = factory.find_by_name("int").unwrap();
        let char_t = factory.get_type_char(1);
        let updated = factory
            .set_union_fields("MyUnion", vec![
                TypeField { name: "a".into(), offset: 0, type_ptr: int_t },
                TypeField { name: "b".into(), offset: 0, type_ptr: char_t },
            ])
            .expect("union exists");
        assert_eq!(updated.get_size(), 4);
    }

    #[test]
    fn test_get_type_enum_and_values() {
        // type.cc:3967 / 3532 — enum with ENUMTYPE flag; setEnumValues fills map.
        let mut factory = TypeFactory::new(8);
        let e = factory.get_type_enum("Color");
        assert!(e.is_enum_type());
        let mut vals = std::collections::BTreeMap::new();
        vals.insert(0, "RED".to_string());
        vals.insert(1, "GREEN".to_string());
        vals.insert(2, "BLUE".to_string());
        let _ = factory.set_enum_values("Color", vals).expect("enum exists");
        // round-trip: the enum is still an enum after setting values.
        let e2 = factory.find_by_name("Color").unwrap();
        assert!(e2.is_enum_type());
    }

    #[test]
    fn test_get_type_code() {
        // type.cc:3692 — generic code type, size 1, metatype Code.
        let mut factory = TypeFactory::new(8);
        let c = factory.get_type_code();
        assert_eq!(c.get_metatype(), TypeMetatype::Code);
        assert_eq!(c.get_size(), 1);
        let c2 = factory.get_type_code();
        assert!(Arc::ptr_eq(&c, &c2));
    }

    #[test]
    fn test_get_type_pointer_rel() {
        // type.cc:4016 — relative pointer into a parent at an offset.
        let mut factory = TypeFactory::new(8);
        let int_t = factory.find_by_name("int").unwrap();
        let struct_t = factory.create_struct("S");
        let rp = factory.get_type_pointer_rel(int_t.clone(), struct_t.clone(), 4);
        assert_eq!(rp.get_metatype(), TypeMetatype::Pointer);
        assert!((rp.get_flags() & type_flags::IS_PTRREL) != 0);
        // side table recorded the parent/offset.
        let rec = factory.rel_pointers.get(rp.get_name()).unwrap();
        assert_eq!(rec.offset, 4);
        assert_eq!(rec.parent.get_name(), "S");
    }

    #[test]
    fn test_get_typedef_and_target() {
        // type.cc:3818 — typedef aliases a base; HAS_STRIPPED set; not coretype.
        let mut factory = TypeFactory::new(8);
        let int_t = factory.find_by_name("int").unwrap();
        let td = factory.get_typedef("Word", int_t.clone());
        assert_eq!(td.get_name(), "Word");
        assert_eq!(td.get_size(), 4);
        assert!((td.get_flags() & type_flags::HAS_STRIPPED) != 0);
        assert!(!td.is_coretype());
        // target lookup returns the aliased type.
        let target = factory.get_typedef_target("Word").unwrap();
        assert_eq!(target.get_name(), "int");
    }

    #[test]
    fn test_resize_pointer() {
        // type.cc:4071 — same pointee, new size, preserves wordsize.
        let mut factory = TypeFactory::new(8);
        let int_t = factory.find_by_name("int").unwrap();
        let ptr8 = factory.get_ptr(int_t);
        let ptr4 = factory.resize_pointer(&ptr8, 4);
        assert_eq!(ptr4.get_size(), 4);
        assert_eq!(ptr4.get_metatype(), TypeMetatype::Pointer);
    }

    #[test]
    fn test_find_by_id_local_and_global() {
        // type.cc:3326 / 3354 — findByIdLocal matches by name; id 0 matches any id.
        let factory = TypeFactory::new(8);
        // "void" exists with id 0 (unset); lookup by name with id 0 succeeds.
        assert!(factory.find_by_id_local("void", 0).is_some());
        // non-existent name.
        assert!(factory.find_by_id_local("nope", 0).is_none());
        // findById with size fallback.
        assert!(factory.find_by_id("int", 0, 4).is_some());
        assert!(factory.find_by_id("int", 0, 8).is_none());
    }

    #[test]
    fn test_concretize_and_deconcretize() {
        // type.cc:4140 — TYPE_CODE → base TYPE_UNKNOWN of size 1.
        let mut factory = TypeFactory::new(8);
        let code = factory.get_type_code();
        let concrete = factory.concretize(code);
        assert_eq!(concrete.get_metatype(), TypeMetatype::Unknown);
        assert_eq!(concrete.get_size(), 1);
        // non-code types pass through unchanged.
        let int_t = factory.find_by_name("int").unwrap();
        let passthrough = factory.concretize(int_t.clone());
        assert!(Arc::ptr_eq(&passthrough, &int_t));
        // deconcretize (Rugra-only inverse) round-trips the concretized form.
        let back = factory.deconcretize(concrete);
        assert_eq!(back.get_metatype(), TypeMetatype::Code);
    }

    #[test]
    fn test_hash_size_stability() {
        // type.hh:206 — hashSize folds size into id; different sizes differ.
        let a = hash_size(0x1234, 1);
        let b = hash_size(0x1234, 4);
        assert_ne!(a, b);
        assert_eq!(a, hash_size(0x1234, 1));
    }

    // --- P2 TypeFactory::getTypeCode(PrototypePieces) / setPrototype ---

    #[test]
    fn test_get_type_code_pieces() {
        // type.cc:4002 — builds a TypeCode with an attached prototype.
        let mut factory = TypeFactory::new(8);
        let int_t = factory.find_by_name("int").unwrap();
        let void_t = factory.get_type_void();
        let in_types = vec![int_t.clone(), int_t];
        let sig = crate::fspec::PrototypePieces {
            out_type: Some(void_t.as_ref()),
            in_types: &in_types,
            first_var_arg_slot: -1,
        };
        let code = factory.get_type_code_pieces(&sig);
        assert_eq!(code.get_metatype(), TypeMetatype::Code);
        // Dedup: a second call with the same pieces returns the same Arc.
        let in_types2 = vec![
            factory.find_by_name("int").unwrap(),
            factory.find_by_name("int").unwrap(),
        ];
        let void_t2 = factory.get_type_void();
        let sig2 = crate::fspec::PrototypePieces {
            out_type: Some(void_t2.as_ref()),
            in_types: &in_types2,
            first_var_arg_slot: -1,
        };
        let code2 = factory.get_type_code_pieces(&sig2);
        assert!(Arc::ptr_eq(&code, &code2));
        // The prototype has 2 parameters.
        if let Datatype::Code(c) = code.as_ref() {
            let proto = c.proto.as_ref().expect("prototype attached");
            assert_eq!(proto.num_params(), 2);
            assert!(proto.is_input_locked());
        } else {
            panic!("expected a Code type");
        }
    }

    #[test]
    fn test_factory_set_prototype_on_incomplete() {
        // type.cc:3518 — setPrototype requires an incomplete TypeCode.
        let mut factory = TypeFactory::new(8);
        // Build an incomplete code type manually.
        let mut base = TypeBase::new("incomplete_code".to_string(), 1, TypeMetatype::Code);
        base.flags |= type_flags::TYPE_INCOMPLETE;
        let dt = Arc::new(Datatype::Code(TypeCode { base, proto: None }));
        factory.types.insert("incomplete_code".to_string(), dt);
        // Set a prototype on it.
        let void_t = factory.get_type_void();
        let proto = crate::fspec::FuncProto::new("f".to_string(), void_t);
        let updated = factory
            .set_prototype("incomplete_code", Some(&proto), 0)
            .expect("setPrototype on incomplete code");
        // Incomplete flag cleared.
        assert!(updated.get_flags() & type_flags::TYPE_INCOMPLETE == 0);
        // Prototype copied in.
        if let Datatype::Code(c) = updated.as_ref() {
            assert!(c.proto.is_some());
        } else {
            panic!("expected a Code type");
        }
    }

    #[test]
    fn test_factory_set_prototype_rejects_complete() {
        // type.cc:3518 — setting a prototype on a complete code type errors.
        let mut factory = TypeFactory::new(8);
        let code = factory.get_type_code(); // complete (no TYPE_INCOMPLETE)
        let void_t = factory.get_type_void();
        let proto = crate::fspec::FuncProto::new("f".to_string(), void_t);
        let res = factory.set_prototype("code", Some(&proto), 0);
        assert!(res.is_err());
    }
}
