//! Type management and deduplication
//!
//! Corresponds to Ghidra's `TypeFactory` class in `type.hh`. This class is responsible
//! for the lifecycle of all `Datatype` objects, ensuring that identical types are
//! deduplicated and providing a central point for type lookup.

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
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

    /// Structural registry for atomic types. Ghidra's `DatatypeSet tree`
    /// orders `TypeBase` by sub-metatype, descending size, then id.  Keeping
    /// this separate from the name cross-reference lets unnamed id-zero types
    /// participate in factory enumeration and `clearNoncore`.
    base_type_tree: RwLock<BTreeMap<(u8, Reverse<usize>, u64), Arc<Datatype>>>,

    /// Fast preferred-core lookup corresponding to Ghidra's `typecache`.
    base_cache: RwLock<BTreeMap<(usize, TypeMetatype), Arc<Datatype>>>,

    /// The non-character signed byte selected by `cacheCoreTypes`, matching
    /// Ghidra's `type_nochar` side cache (type.hh:777).
    type_nochar: RwLock<Option<Arc<Datatype>>>,

    /// Preferred printable character types by byte size, matching Ghidra's
    /// `charcache[5]` (type.hh:778). Only sizes 0..=4 can be populated.
    char_cache: RwLock<BTreeMap<usize, Arc<Datatype>>>,

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

    /// Size of the core "int" data-type (Ghidra `sizeOfInt`, type.hh:763).
    /// Persisted state of `decodeDataOrganization`/`setupSizes`.
    size_of_int: i32,
    /// Size of the core "long" data-type (Ghidra `sizeOfLong`, type.hh:764).
    size_of_long: i32,
    /// Size of the core "char" data-type (Ghidra `sizeOfChar`, type.hh:765).
    size_of_char: i32,
    /// Size of the core "wchar_t" data-type (Ghidra `sizeOfWChar`, type.hh:766).
    size_of_wchar: i32,
    /// Size of pointers into the default data space (Ghidra `sizeOfPointer`,
    /// type.hh:767).
    size_of_pointer: i32,
    /// Size of alternate pointers, 0 when unused (Ghidra `sizeOfAltPointer`,
    /// type.hh:768). Only `setupSizes`'s far-pointer branch writes this.
    size_of_alt_pointer: i32,
    /// Size of an enumerated type (Ghidra `enumsize`, type.hh:769).
    enum_size: i32,
    /// Default enumeration meta-type (Ghidra `enumtype`, type.hh:770).
    enum_type: TypeMetatype,
    /// Alignment of primitive data-types keyed by size (Ghidra `alignMap`,
    /// type.hh:771). Element value -1 marks "not set" during decode; index 0
    /// stays -1 unless an explicit `<entry size="0">` exists.
    align_map: Vec<i32>,

    /// Maximum size of a scalar "base" type before `getBase` converts the
    /// request into an array of 1-byte unknowns (Ghidra
    /// `Architecture::max_basetype_size`, architecture.hh:173, set to 10 at
    /// architecture.cc:1422). Rugra stores it on the factory because the
    /// factory has no Architecture handle yet.
    max_base_type_size: usize,
}

/// Which core-unknown registration path the architecture uses. Ghidra
/// has two: the data-organization path installs `undefined1/2/4/8`
/// (ghidra_arch.cc:349-355, what the canonical headless oracle emits),
/// while the SLEIGH standalone fallback installs `xunknown1/2/4/8`
/// (sleigh_arch.cc:229-232, what a standalone-driven oracle observes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CoreTypeFlavor {
    DataOrg,
    Standalone,
}

impl TypeFactory {
    // RUGRA-GLUE: Combines TypeFactory construction (type.cc:3106) with the
    // standalone SLEIGH fallback bootstrap (sleigh_arch.cc:204).
    /// Create a new TypeFactory and initialize core types
    ///
    /// # Arguments
    /// * `ptr_size` - Default pointer size for the target architecture (e.g., 4 or 8)
    pub fn new(ptr_size: usize) -> Self {
        Self::new_flavor(ptr_size, CoreTypeFlavor::DataOrg)
    }

    /// Construct with an explicit core-unknown registration flavor; the
    /// standalone flavor mirrors SleighArchitecture::buildCoreTypes
    /// (sleigh_arch.cc:229-232) for oracle-driven fixtures.
    // RUGRA-GLUE: Rust construction split of the two Ghidra registration
    // sites (ghidra_arch.cc:349 dataorg / sleigh_arch.cc:204 standalone);
    // Ghidra picks the site by architecture subclass instead of a param.
    pub fn new_flavor(ptr_size: usize, flavor: CoreTypeFlavor) -> Self {
        let mut factory = Self {
            types: BTreeMap::new(),
            core_types: BTreeMap::new(),
            base_type_tree: RwLock::new(BTreeMap::new()),
            base_cache: RwLock::new(BTreeMap::new()),
            type_nochar: RwLock::new(None),
            char_cache: RwLock::new(BTreeMap::new()),
            ptr_size,
            rel_pointers: BTreeMap::new(),
            typedefs: BTreeMap::new(),
            // Ghidra: type.cc:3106 TypeFactory::TypeFactory zeroes every
            // size field (int/long/char/wchar/pointer/altpointer/enumsize)
            // and leaves alignMap default-constructed (empty).
            size_of_int: 0,
            size_of_long: 0,
            size_of_char: 0,
            size_of_wchar: 0,
            size_of_pointer: 0,
            size_of_alt_pointer: 0,
            enum_size: 0,
            // Ghidra leaves `enumtype` uninitialized in the constructor
            // (type.cc:3108-3118); it is only read after parseEnumConfig or
            // setupSizes assigns it. Rust must initialize: Unknown is a
            // non-production placeholder never observable through the
            // mapped call graph.
            enum_type: TypeMetatype::Unknown,
            align_map: Vec::new(),
            // Ghidra: architecture.cc:1422 `max_basetype_size = 10;` —
            // installed by Architecture::resetDefaults, mirrored as the
            // factory default because TypeFactory reads it from `glb` at
            // type.cc:3652.
            max_base_type_size: 10,
        };
        factory.init_core_types_flavor(flavor);
        factory
    }

    // Ghidra: type.cc:3106 TypeFactory::TypeFactory(Architecture *g)
    /// The raw Ghidra constructor projection: an EMPTY container with zeroed
    /// size fields, no alignment map, no core types, and freshly cleared
    /// caches. `TypeFactory::new` is the Rust architecture-bootstrap twin
    /// (Ghidra builds core types from `SleighArchitecture::buildCoreTypes`
    /// AFTER constructing the raw factory); `raw` exposes the pre-bootstrap
    /// state itself so the constructor's observable behaviour — `findAdd`
    /// failing with the uninitialized-alignment-map LowlevelError and
    /// `getTypeVoid`/`getTypeCode` still working — can be differentially
    /// tested against the oracle.
    pub fn raw() -> Self {
        let mut factory = Self {
            types: BTreeMap::new(),
            core_types: BTreeMap::new(),
            base_type_tree: RwLock::new(BTreeMap::new()),
            base_cache: RwLock::new(BTreeMap::new()),
            type_nochar: RwLock::new(None),
            char_cache: RwLock::new(BTreeMap::new()),
            // Rugra's pointer-size field has no Ghidra member counterpart
            // (Ghidra reads glb->sizeof_pointer at use sites); 0 marks the
            // uninitialized raw-constructor state.
            ptr_size: 0,
            rel_pointers: BTreeMap::new(),
            typedefs: BTreeMap::new(),
            size_of_int: 0,
            size_of_long: 0,
            size_of_char: 0,
            size_of_wchar: 0,
            size_of_pointer: 0,
            size_of_alt_pointer: 0,
            enum_size: 0,
            enum_type: TypeMetatype::Unknown,
            align_map: Vec::new(),
            max_base_type_size: 10,
        };
        // Ghidra: type.cc:3118 `clearCache();` is the constructor's only call.
        factory.clear_cache();
        factory
    }

    // Ghidra: sleigh_arch.cc:204 SleighArchitecture::buildCoreTypes
    /// Initialize the fundamental core types
    fn init_core_types(&mut self) {
        self.init_core_types_flavor(CoreTypeFlavor::DataOrg);
    }

    // Ghidra: sleigh_arch.cc:204 SleighArchitecture::buildCoreTypes
    /// Core-unknown loop parameterized by registration flavor.
    fn init_core_types_flavor(&mut self, flavor: CoreTypeFlavor) {
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

        // Ghidra: ghidra_arch.cc:349 ArchitectureGhidra::buildCoreTypes
        // The Ghidra data organization installs these four named core
        // unknowns before TypeFactory::cacheCoreTypes (`setCoreType
        // ("undefined",1,TYPE_UNKNOWN,false)` etc. via getBase -> id =
        // hashName(name)). The canonical headless oracle output names the
        // 1-byte form `undefined1` (production compiler-spec <coretypes>
        // data organization, cf. tests/golden/ghidra_curl.c
        // `undefined1 auVar21 [24];`), so the uniform size-suffixed spelling
        // is used; the SLEIGH standalone else-branch spellings are
        // `xunknown1/2/4/8` (sleigh_arch.cc:229) and are NOT what the E2E
        // diff gate targets. Other sizes are created as unnamed, non-core
        // TypeBase objects by TypeFactory::getBase.
        for &size in &[1, 2, 4, 8] {
            let name = match flavor {
                CoreTypeFlavor::DataOrg => format!("undefined{size}"),
                CoreTypeFlavor::Standalone => format!("xunknown{size}"),
            };
            let mut base = TypeBase::new(name.clone(), size, TypeMetatype::Unknown);
            base.id = Datatype::hash_name(&name);
            self.add_core_type(Arc::new(Datatype::Base(base)));
        }

        // Both locked architecture registration paths call cacheCoreTypes
        // after every core type has entered the ordered tree
        // (sleigh_arch.cc:237, ghidra_arch.cc:355).
        self.cache_core_types();
    }

    // RUGRA-GLUE: Rust-owned Arc insertion used by the architecture bootstrap;
    // Ghidra performs the same flag mutation in setCoreType (type.cc:3178)
    // and ordered-tree insertion in findAdd (type.cc:3412).
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
        self.types.insert(name, dt.clone());
        let tree_key = (
            Self::submeta_of(&dt),
            Reverse(dt.get_size()),
            dt.get_id(),
        );
        let tree = self
            .base_type_tree
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tree.entry(tree_key).or_insert_with(|| dt.clone());
    }

    // Ghidra: type.cc:23 Datatype::base2sub
    /// Return the locked-oracle propagation sub-metatype used by the factory's
    /// structural ordering. Atomic types use these exact `base2sub` values.
    fn base_submeta(metatype: TypeMetatype) -> u8 {
        match metatype {
            TypeMetatype::PartialUnion => 0,
            TypeMetatype::Union => 1,
            TypeMetatype::Struct => 2,
            TypeMetatype::Array => 3,
            TypeMetatype::Pointer => 6,
            TypeMetatype::Float => 8,
            TypeMetatype::Code => 9,
            TypeMetatype::Bool => 10,
            TypeMetatype::Enum => 13,
            TypeMetatype::PartialEnum => 14,
            TypeMetatype::Uint => 16,
            TypeMetatype::Int => 17,
            TypeMetatype::PartialStruct => 20,
            TypeMetatype::Unknown => 21,
            TypeMetatype::Spacebase => 22,
            TypeMetatype::Void => 23,
        }
    }

    // Ghidra: type.hh:236 Datatype::getSubMeta (via DatatypeCompare, type.hh:306)
    /// The propagation sub-metatype used by the factory's structural ordering
    /// (`DatatypeSet` with `DatatypeCompare`: submeta ascending, size
    /// descending, id ascending — type.cc:227 `compareDependency`). Rugra
    /// derives it from the `Datatype` variant exactly as Ghidra's
    /// constructors assign it (TypeChar type.hh:356, TypeUnicode type.cc:862,
    /// TypeEnum type.hh:489), including the `submeta_override` those
    /// constructor ports record.
    fn submeta_of(datatype: &Datatype) -> u8 {
        datatype.get_submeta() as i32 as u8
    }

    // Ghidra: type.cc:3366 TypeFactory::findByName
    /// Find a type by name
    pub fn find_by_name(&self, name: &str) -> Option<Arc<Datatype>> {
        self.types.get(name).cloned()
    }

    // Ghidra: type.cc:3631 TypeFactory::getBase
    /// Get a base scalar type of `size` bytes with metatype `m`.
    ///
    /// Compat projection of Ghidra `TypeFactory::getBase`
    /// (`type.cc:3631-3651,3658-3660`): a preferred core entry wins regardless
    /// of name; otherwise one unnamed `TypeBase` is canonicalized by the
    /// ordered tree. The byte-faithful port — including the
    /// `size > max_basetype_size` array conversion and the
    /// uninitialized-alignment-map LowlevelError — is [`Self::get_base_result`];
    /// this lenient twin preserves the historical Rugra contract for existing
    /// callers on factories whose architecture wiring has not installed an
    /// alignment map yet (registered residual
    /// TYPEFACTORY-ARCH-ALIGNMAP-WIRING-0001).
    pub fn get_base(&self, size: usize, m: TypeMetatype) -> Option<Arc<Datatype>> {
        let cache_key = (size, m);
        let cache = self
            .base_cache
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = cache.get(&cache_key) {
            return Some(existing.clone());
        }
        drop(cache);

        // Ghidra constructs an unnamed TypeBase and canonicalizes it through
        // findAdd when no preferred core entry exists. Its structural key is
        // the plain base sub-metatype, descending size, then id zero.
        let tree_key = (Self::base_submeta(m), Reverse(size), 0);
        let tree = self
            .base_type_tree
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = tree.get(&tree_key) {
            return Some(existing.clone());
        }
        drop(tree);

        let mut tree = self
            .base_type_tree
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Some(
            tree.entry(tree_key)
                .or_insert_with(|| Arc::new(Datatype::Base(TypeBase::new(String::new(), size, m))))
                .clone(),
        )
    }

    // Ghidra: type.cc:3631 TypeFactory::getBase
    /// The faithful `TypeFactory::getBase(int4,type_metatype)` port
    /// (type.cc:3631-3660), returning Ghidra's LowlevelError messages as
    /// `Err`:
    /// - `size < 9` and a printable-scalar metatype: the preferred
    ///   `typecache[size][m]` entry returns immediately.
    /// - `size >= 9` and TYPE_FLOAT: `typecache10`/`typecache16` (Rugra's
    ///   `base_cache[(10|16, Float)]`) return when populated.
    /// - `size > max_base_type_size` (10, architecture.cc:1422): the request
    ///   converts to an array of `size` cached 1-byte unknowns, exactly as
    ///   type.cc:3652-3657 does (including the `getStripped` element strip
    ///   and the findAdd canonicalization of the unnamed array).
    /// - otherwise an unnamed `TypeBase` is canonicalized through
    ///   [`Self::find_add`], whose miss path raises the
    ///   "TypeFactory alignment map not initialized" LowlevelError when no
    ///   alignment map has been installed (the raw-constructor state).
    pub fn get_base_result(&mut self, size: usize, m: TypeMetatype) -> Result<Arc<Datatype>, String> {
        // Ghidra guards `m >= TYPE_FLOAT` (numeric 10..17: Float, Code, Bool,
        // Uint, Int, Unknown, Spacebase, Void) for the 9x8 typecache matrix.
        let printable_scalar = matches!(
            m,
            TypeMetatype::Float
                | TypeMetatype::Code
                | TypeMetatype::Bool
                | TypeMetatype::Uint
                | TypeMetatype::Int
                | TypeMetatype::Unknown
                | TypeMetatype::Spacebase
                | TypeMetatype::Void
        );
        if size < 9 && printable_scalar {
            let cache_key = (size, m);
            let cache = self
                .base_cache
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(existing) = cache.get(&cache_key) {
                return Ok(existing.clone());
            }
        } else if size >= 9 && m == TypeMetatype::Float {
            // type.cc:3642-3651: only sizes 10 and 16 have dedicated slots.
            if size == 10 || size == 16 {
                let cache = self
                    .base_cache
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(existing) = cache.get(&(size, m)) {
                    return Ok(existing.clone());
                }
            }
        }
        if size > self.max_base_type_size {
            // type.cc:3652-3657: build an array of unknown bytes to match the
            // size. Ghidra dereferences typecache[1][TYPE_UNKNOWN] without a
            // null check — a factory that never cached a 1-byte unknown
            // crashes; Rugra panics with the same precondition documented.
            let cache_key = (1_usize, TypeMetatype::Unknown);
            let element = {
                let cache = self
                    .base_cache
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                cache.get(&cache_key).cloned()
            };
            let element = element.expect(
                "getBase array conversion requires a cached 1-byte unknown (type.cc:3654)",
            );
            // getTypeArray strips a typedef layer off the element first
            // (type.cc:3902-3905).
            let element = if element.get_flags() & type_flags::HAS_STRIPPED != 0 {
                match self.typedefs.get(element.get_name()) {
                    Some(target) => target.clone(),
                    None => element,
                }
            } else {
                element
            };
            // TypeArray ctor (type.hh:937-944): size = n * arrayof->getAlignSize(),
            // alignment inherited, NO inheritable flags, needs_resolution for n==1.
            let total = size * element.get_align_size();
            let mut base = TypeBase::new(String::new(), total, TypeMetatype::Array);
            if size == 1 {
                base.flags |= type_flags::NEEDS_RESOLUTION;
            }
            return self.find_add(
                Datatype::Array(TypeArray {
                    base,
                    array_of: element,
                    num_elements: size,
                }),
                true,
            );
        }
        self.find_add(Datatype::Base(TypeBase::new(String::new(), size, m)), true)
    }

    // Ghidra: type.cc:3619 TypeFactory::getBaseNoChar
    /// The faithful `TypeFactory::getBaseNoChar` port (type.cc:3619-3625): a
    /// one-byte TYPE_INT request returns `type_nochar` when the side cache
    /// holds a selection; everything else delegates to the faithful
    /// [`Self::get_base_result`], including its LowlevelError propagation.
    pub fn get_base_no_char_result(
        &mut self,
        size: usize,
        metatype: TypeMetatype,
    ) -> Result<Arc<Datatype>, String> {
        if size == 1 && metatype == TypeMetatype::Int {
            let nochar = self
                .type_nochar
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(datatype) = nochar.as_ref() {
                return Ok(datatype.clone());
            }
        }
        self.get_base_result(size, metatype)
    }

    // Ghidra: type.cc:3619 TypeFactory::getBaseNoChar
    /// Get a canonical base type, excluding the printable ASCII character
    /// specialization for a one-byte signed integer when a non-character core
    /// type was selected by `cache_core_types`.
    pub fn get_base_no_char(&self, size: usize, metatype: TypeMetatype) -> Option<Arc<Datatype>> {
        if size == 1 && metatype == TypeMetatype::Int {
            let nochar = self
                .type_nochar
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(datatype) = nochar.as_ref() {
                return Some(datatype.clone());
            }
        }
        self.get_base(size, metatype)
    }

    // Ghidra: type.cc:3667 TypeFactory::getBase(int4,type_metatype,const string &)
    /// Get or create a "base" type with a specified name and properties.
    /// Faithful to `TypeFactory::getBase(int4 s,type_metatype m,const string &n)`
    /// (type.cc:3667-3673): `TypeBase tmp(s,m,n); tmp.id = hashName(n);
    /// return findAdd(tmp);`
    pub fn get_base_named(
        &mut self,
        size: usize,
        m: TypeMetatype,
        name: &str,
    ) -> Result<Arc<Datatype>, String> {
        let mut base = TypeBase::new(name.to_string(), size, m);
        base.id = Datatype::hash_name(name);
        self.find_add(Datatype::Base(base), false)
    }

    // Ghidra: type.cc:3412 TypeFactory::findAdd
    /// Use the quickest method (name or id when possible) to locate the
    /// matching data-type; if not currently in this container, insert the
    /// candidate. Faithful to `TypeFactory::findAdd` (type.cc:3412-3439):
    ///
    /// - Named candidate with id 0 raises
    ///   `"Datatype must have a valid id: {name}"` (type.cc:3419).
    /// - A name+id hit whose `compareDependency` differs (sub-metatype or
    ///   size; type.cc:227-234) raises
    ///   `"Trying to alter definition of type: {name}"` (type.cc:3423); an
    ///   equal definition returns the EXISTING factory object (this is the
    ///   aliasing point `setCoreType` relies on when promoting).
    /// - An unnamed (or id-missed) candidate is probed structurally in the
    ///   ordered tree keyed by (sub-metatype, descending size, id) —
    ///   `DatatypeCompare`, type.hh:306-310 — and returns the canonical entry
    ///   on equivalence.
    /// - On a miss the candidate is inserted; the alignment computation
    /// (type.cc:3433-3436) raises
    /// `"TypeFactory alignment map not initialized"` when no map was
    /// installed (the raw-constructor state) — gated behind
    /// `enforce_alignment`, which is set on the faithful `getBase` port
    /// [`Self::get_base_result`] only: production Rugra factories do not yet
    /// thread the decoded alignment map through their architecture wiring
    /// (registered residual TYPEFACTORY-ARCH-ALIGNMAP-WIRING-0001), and a
    /// tree slot already holding the same key raises
    /// `"Shared type id: {id:x}"` (type.cc:3393-3403).
    ///
    /// Rugra note: `Datatype::compareDependency` on containers walks
    /// components/element pointers (type.cc:1225 TypeArray uses the element
    /// POINTER); the tree key here can only carry (submeta, size, id), so
    /// container candidates are probed/inserted under an additional element
    /// Arc-identity check, and deep structural container ordering remains the
    /// registered TYPE-0001 residual. Atomic candidates match the oracle
    /// exactly.
    fn find_add(
        &mut self,
        candidate: Datatype,
        enforce_alignment: bool,
    ) -> Result<Arc<Datatype>, String> {
        let name = candidate.get_name().to_string();
        let candidate_id = candidate.get_id();
        let candidate_submeta = Self::submeta_of(&candidate);
        let candidate_size = candidate.get_size();
        if !name.is_empty() {
            // type.cc:3417-3425
            if candidate_id == 0 {
                return Err(format!("Datatype must have a valid id: {name}"));
            }
            if let Some(existing) = self.types.get(&name) {
                if existing.get_id() == candidate_id {
                    // compareDependency: submeta, then size (type.cc:227).
                    if existing.get_submeta() as i32 != candidate_submeta as i32
                        || existing.get_size() != candidate_size
                    {
                        return Err(format!("Trying to alter definition of type: {name}"));
                    }
                    return Ok(existing.clone());
                }
                // Ghidra's nametree keeps multiple (name,id) entries; Rugra's
                // flat map holds one, so an id mismatch falls through to the
                // structural insert and overwrites the name slot (registered
                // TYPE-0001 name-map residual).
            }
        } else {
            // type.cc:3427-3430 findNoName: structural probe including id.
            let tree_key = (candidate_submeta, Reverse(candidate_size), candidate_id);
            let tree = self
                .base_type_tree
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(existing) = tree.get(&tree_key) {
                if !matches!(candidate, Datatype::Array(_))
                    || Self::array_element_matches(&candidate, existing)
                {
                    return Ok(existing.clone());
                }
            }
        }
        // type.cc:3432-3438: alignment computation on the clone. Rugra's
        // TypeBase has no alignment field (datatype.rs registered gap); the
        // observable LowlevelError on an uninitialized map is preserved for
        // the enforcing entry points.
        if enforce_alignment && self.align_map.is_empty() {
            return Err("TypeFactory alignment map not initialized".to_string());
        }
        let tree_key = (candidate_submeta, Reverse(candidate_size), candidate_id);
        let mut tree = self
            .base_type_tree
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = tree.get(&tree_key) {
            if matches!(candidate, Datatype::Array(_)) {
                if Self::array_element_matches(&candidate, existing) {
                    // Unnamed arrays of the same element canonicalize to one
                    // entry.
                    return Ok(existing.clone());
                }
                // Ghidra orders same-size arrays of distinct elements by
                // element pointer (type.cc:1228); Rugra's flat key cannot
                // hold both, so the second distinct element raises the
                // shared-id LowlevelError (registered TYPE-0001 residual).
            }
            let mut message = format!("Shared type id: {:x}\n  ", candidate_id);
            message.push_str(&Self::print_raw(&candidate));
            message.push_str(" : ");
            message.push_str(&Self::print_raw(existing));
            return Err(message);
        }
        let arc = Arc::new(candidate);
        tree.insert(tree_key, arc.clone());
        drop(tree);
        // type.cc:3404-3405: nametree gets named (id != 0) entries.
        if !name.is_empty() {
            self.types.insert(name, arc.clone());
        }
        Ok(arc)
    }

    // RUGRA-GLUE: element comparison for array findAdd probes. Ghidra's
    // TypeArray::compareDependency (type.cc:1225-1232) orders arrays by the
    // element POINTER; Arc identity is the Rust observation of that pointer.
    fn array_element_matches(candidate: &Datatype, existing: &Arc<Datatype>) -> bool {
        match (candidate, existing.as_ref()) {
            (Datatype::Array(c), Datatype::Array(e)) => Arc::ptr_eq(&c.array_of, &e.array_of),
            _ => false,
        }
    }

    // Ghidra: type.cc:139 Datatype::printRaw (base), type.cc:910
    // TypePointer::printRaw, type.cc:1204 TypeArray::printRaw — the fragments
    /// used by insert's "Shared type id" message (type.cc:3396-3400): the
    /// name (or `unkbyte<size>`), `element *` for pointers, and
    /// `element [n]` for arrays.
    fn print_raw(dt: &Datatype) -> String {
        match dt {
            Datatype::Pointer(p) => format!("{} *", Self::print_raw(&p.ptr_to)),
            Datatype::Array(a) => {
                format!("{} [{}]", Self::print_raw(&a.array_of), a.num_elements)
            }
            _ => {
                let name = dt.get_name();
                if name.is_empty() {
                    format!("unkbyte{}", dt.get_size())
                } else {
                    name.to_string()
                }
            }
        }
    }

    // Ghidra: type.cc:1035 TypePointer::calcSubmeta (needs_resolution arm)
    /// The `needs_resolution` inheritance arm of `TypePointer::calcSubmeta`
    /// (type.cc:1051-1052): `if (ptrto->needsResolution() && ptrtoMeta !=
    /// TYPE_PTR) flags |= needs_resolution;` — a pointer to a
    /// resolution-needing type (union, single-field struct, size-1 array)
    /// inherits the flag, but never through a second pointer level. In Ghidra
    /// this runs in every `TypePointer` constructor (type.hh:413/416) and in
    /// `TypePointer::decode` (type.cc:1027); Rugra applies it at each pointer
    /// construction site in this factory (get_ptr, get_type_pointer,
    /// get_type_pointer_rel, resize_pointer, and the decode `<type>` pointer
    /// branch), which are the paths that flow through the ctor in Ghidra.
    ///
    /// Consumers treat a pointer's flag as identity-resolution only
    /// (`Datatype::findResolve` base returns `this`; every needsResolution
    /// rejection in printc/cast waives `TYPE_PTR`), so the flag on pointers
    /// changes no resolved type — it makes the printc.cc:1962 TYPE_PTR waiver
    /// load-bearing, exactly as in Ghidra.
    ///
    /// NOTE (scope): calcSubmeta's submeta reclassification
    /// (SUB_PTR/SUB_PTR_STRUCT) and the `pointer_to_array` flag are not yet
    /// modelled on Rugra's `TypePointer` (no sub_metatype field); only the
    /// needs_resolution arm — the setting this factory's matrix owns — is
    /// mirrored here. The constructors' `flags = ptrto->getInheritable()`
    /// (type.hh:413, coretype inheritance) is likewise not yet mirrored.
    fn pointer_inherit_needs_resolution(ptr_to: &Datatype) -> u32 {
        if ptr_to.needs_resolution() && ptr_to.get_metatype() != TypeMetatype::Pointer {
            type_flags::NEEDS_RESOLUTION
        } else {
            0
        }
    }

    // Ghidra: type.cc:3850 TypeFactory::getPtr
    /// Get or create a pointer type to the given base type
    pub fn get_ptr(&mut self, ptr_to: Arc<Datatype>) -> Arc<Datatype> {
        let name = format!("{} *", ptr_to.get_name());
        if let Some(existing) = self.find_by_name(&name) {
            return existing;
        }

        let mut base = TypeBase::new(name.clone(), self.ptr_size, TypeMetatype::Pointer);
        // type.cc:1051-1052 calcSubmeta needs_resolution inheritance.
        base.flags |= Self::pointer_inherit_needs_resolution(&ptr_to);
        let ptr_type = Arc::new(Datatype::Pointer(TypePointer {
            base,
            ptr_to,
            wordsize: 1,
        }));
        self.types.insert(name, ptr_type.clone());
        ptr_type
    }

    // Ghidra: type.cc:3850 TypeFactory::getArray
    /// Get or create an array type
    pub fn get_array(&mut self, array_of: Arc<Datatype>, num_elements: usize) -> Arc<Datatype> {
        let name = format!("{}[{}]", array_of.get_name(), num_elements);
        if let Some(existing) = self.find_by_name(&name) {
            return existing;
        }

        let size = array_of.get_size() * num_elements;
        let mut base = TypeBase::new(name.clone(), size, TypeMetatype::Array);
        // Ghidra: type.hh:937-944 inline TypeArray ctor (the path
        // TypeFactory::getTypeArray takes, type.cc:3902-3908):
        //   // A varnode which is an array of size 1, should generally
        //   // always be treated as the element data-type
        //   if (n == 1) flags |= needs_resolution;
        // TypeArray::decode (type.cc:1341-1342) sets the same flag on the
        // arraysize==1 decode arm, so both creation paths agree.
        if num_elements == 1 {
            base.flags |= type_flags::NEEDS_RESOLUTION;
        }
        let array_type = Arc::new(Datatype::Array(TypeArray {
            base,
            array_of,
            num_elements,
        }));
        self.types.insert(name, array_type.clone());
        array_type
    }

    // Ghidra: type.cc:3850 TypeFactory::createStruct
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
    /// Set fields for an existing structure and update its size.
    ///
    /// Includes the `TypeStruct::setFields` single-field arm (type.cc:1569-1571):
    /// a structure with exactly one field whose type's full size
    /// (`getSize`, NOT `getAlignSize`) equals the structure size passed by
    /// the caller is marked `needs_resolution` — the write-side producer that
    /// feeds `TypeStruct::findResolve`/`resolveInFlow` (type.cc:1944-1960)
    /// and the printc pushPartialSymbol needsResolution early-break
    /// (printc.cc:1967). Ghidra ORs the flag in (never clears) and checks
    /// `field[0].type`'s full size only — the field's offset is not examined
    /// by `setFields` itself.
    ///
    /// NOTE on the comparison operand: Ghidra's `TypeStruct::setFields`
    /// receives `newSize` explicitly (type.cc:1567). The grammar caller
    /// passes `assignFieldOffsets`' output (type.cc:2798-2799), which for a
    /// single unassigned field is
    /// `calcAlignSize(field.getAlignSize(), max(1, field.getAlignment()))`
    /// (type.cc:1971-1993: running offset starts at 0 and advances by
    /// ALIGN sizes; the struct size is the align-rounded end). Rugra's
    /// `set_fields` takes no size parameter, so the arm recomputes that
    /// grammar-form `newSize` instead of comparing against the derived
    /// `st.base.size` (`max(offset + get_size())`): comparing against the
    /// derived size OVER-FIRES for a field type whose `alignSize > size`
    /// (e.g. an XML-decoded unrounded struct type — Ghidra's grammar
    /// `newSize` is 8 for a size-5/align-4 field type so the flag stays
    /// clear, while the derived size 5 would match the field's full size).
    /// Relies on `get_align_size`/`get_alignment` (Rugra derives alignment
    /// from size via the default map — the registered datatype.rs gap).
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
                // Ghidra: type.cc:1569-1571 TypeStruct::setFields:
                //   if (field.size() == 1) {
                //     if (field[0].type->getSize() == size)
                //       flags |= needs_resolution;
                //   }
                // `size` is the caller-supplied newSize; for the grammar path
                // (this function's only production caller, grammar.rs
                // new_struct) it equals calcAlignSize(field.getAlignSize(),
                // newAlign) with newAlign = max(1, field.getAlignment()).
                if st.fields.len() == 1 {
                    let field = &st.fields[0];
                    let new_align = field.type_ptr.get_alignment().max(1);
                    let ghidra_new_size = crate::type_system::datatype::calc_align_size(
                        field.type_ptr.get_align_size(),
                        new_align,
                    );
                    if field.type_ptr.get_size() == ghidra_new_size {
                        st.base.flags |= type_flags::NEEDS_RESOLUTION;
                    }
                }
                return Some(dt.clone());
            }
        }
        None
    }

    // Ghidra: type.cc:3479 TypeFactory::setFields (explicit newSize/newAlign arm)
    /// Set fields on an existing structure with an EXPLICIT final size and
    /// alignment, mirroring the full `TypeFactory::setFields(const
    /// vector<TypeField> &fd, TypeStruct *ot, int4 newSize, int4 newAlign,
    /// uint4 flags)` signature (type.cc:3479-3490) whose core is
    /// `TypeStruct::setFields(fd, newSize, newAlign)` (type.cc:1563-1574):
    /// `size = newSize` unconditionally, then the single-field
    /// needs_resolution arm compares `field[0].type->getSize()` against that
    /// EXPLICIT size — not against anything derived from the fields.
    ///
    /// This is the form Ghidra's non-grammar callers use (`decodeStruct`'s
    /// stub fill at type.cc:4355 passes the decoded size attribute;
    /// `setStructDecl` passes the stored declaration size), and the only form
    /// under which the "single field does NOT fill the struct" cell
    /// (field size < newSize) and the "offset not examined" cell (single field
    /// at offset > 0 whose type size still equals newSize) are reachable.
    /// The size-derived `set_fields` above is the grammar-path twin
    /// (grammar.cc:2798-2799 derives newSize via `assignFieldOffsets`, so
    /// there the derived and explicit conditions coincide for offset-0
    /// fields with `alignSize == size`).
    ///
    /// Divergences kept out of scope (Rugra registry has no structural tree):
    /// the `isIncomplete` guard, `tree.erase/insert`, and the
    /// `flags & (opaque_string | variable_length | type_incomplete)` merge.
    /// `new_align` is accepted for signature parity; Rugra's `TypeBase` does
    /// not yet store an alignment field (Ghidra's `alignment = newAlign;
    /// alignSize = calcAlignSize(size, alignment)` tail).
    pub fn set_fields_sized(
        &mut self,
        name: &str,
        fields: Vec<TypeField>,
        new_size: usize,
        new_align: usize,
    ) -> Option<Arc<Datatype>> {
        let _ = new_align; // no alignment field on TypeBase yet
        if let Some(dt) = self.types.get_mut(name) {
            if let Datatype::Struct(ref mut st) = Arc::make_mut(dt) {
                st.fields = fields;
                st.base.size = new_size;
                // Ghidra: type.cc:1569-1571 TypeStruct::setFields:
                //   if (field.size() == 1) {
                //     if (field[0].type->getSize() == size)
                //       flags |= needs_resolution;
                //   }
                // `size` is the explicitly provided newSize; the field's
                // offset is not part of the condition.
                if st.fields.len() == 1 && st.fields[0].type_ptr.get_size() == st.base.size {
                    st.base.flags |= type_flags::NEEDS_RESOLUTION;
                }
                return Some(dt.clone());
            }
        }
        None
    }

    // RUGRA-GLUE: Ghidra exposes no numTypes method; this counts the union of
    // its structural `tree` (type.hh:772) and Rust's named cross-reference.
    /// Get the number of types currently managed
    pub fn num_types(&self) -> usize {
        let anonymous_base_count = self
            .base_type_tree
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .filter(|datatype| datatype.get_name().is_empty())
            .count();
        self.types.len() + anonymous_base_count
    }

    // Ghidra: type.cc:3563 TypeFactory::dependentOrder
    /// Place data-types in dependency order. The atomic registry, including
    /// unnamed `getBase` results, follows Ghidra's `DatatypeCompare` key for
    /// atomic types: sub-metatype, descending size, then id. The remaining
    /// pointer/aggregate registry is still name-keyed, so full non-atomic
    /// `dependentOrder` equivalence remains `TYPE-0001`/L2.
    ///
    /// Alignment Evidence (four decisive-semantics checklist):
    /// - References/output params: `deporder` is an out-param appended to
    ///   (Ghidra passes `vector<Datatype*> &deporder`); Rust passes `&mut Vec`.
    /// - Loop bounds/order: Ghidra iterates every `tree` entry from begin to
    ///   end. Rust first walks every atomic structural entry in the same key
    ///   order, then the remaining named roots; the latter is a known gap.
    /// - Counter/accumulator: `mark` (DatatypeSet) is per-call, reset on each
    ///   `dependentOrder` invocation; cycle-break via insert-second-check.
    /// - Sort/compare key: Ghidra's roots and mark use `compareDependency`
    ///   then id. Rust's atomic roots match this; the visited set uses canonical
    ///   `Arc` identity, equivalent for the factory-owned atomic slice only.
    pub fn dependent_order(&self, deporder: &mut Vec<Arc<Datatype>>) {
        // Ghidra: type.cc:3545 TypeFactory::orderRecurse
        // `mark` prevents cycles: insert returns whether the ptr was new.
        let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();
        // Atomic roots are held in the same (submeta, descending size, id)
        // order as Ghidra's DatatypeSet. This includes unnamed getBase results.
        let tree = self
            .base_type_tree
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for ct in tree.values() {
            Self::order_recurse(deporder, &mut visited, ct);
        }
        drop(tree);
        // Add non-atomic named roots. Pointer/aggregate global structural
        // ordering remains part of the module-level TypeFactory L2 gap.
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

    // Ghidra: type.cc:3122 TypeFactory::clearCache
    /// Clear every preferred-type side cache without changing the ordered
    /// factory tree. Ghidra invokes this from the constructor and `clear`.
    fn clear_cache(&mut self) {
        self.base_cache
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        *self
            .type_nochar
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        self.char_cache
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    // Ghidra: type.cc:3251 TypeFactory::clear
    /// Remove every factory-owned type and reset all preferred-type caches.
    /// Size/alignment configuration is deliberately retained, as in Ghidra.
    pub fn clear(&mut self) {
        self.types.clear();
        self.core_types.clear();
        self.base_type_tree
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        self.clear_cache();
        self.rel_pointers.clear();
        self.typedefs.clear();
    }

    // Ghidra: type.cc:3266 TypeFactory::clearNoncore
    /// Delete anything that isn't a core type. Faithful to
    /// `TypeFactory::clearNoncore` (type.cc:3266-3285): the ordered tree (and
    /// its name cross-reference) is walked retaining exactly the entries
    /// whose object carries the core flag — INCLUDING entries that were
    /// promoted in place by `setCoreType` — while the preferred-type caches
    /// are left untouched (every cached entry is core by construction).
    /// `warnings`/`incompleteTypedef` have no Rugra counterpart; the relative
    /// pointer/typedef side registries are glue and follow their objects.
    pub fn clear_non_core(&mut self) {
        // Ghidra scans the core flag on the tree entries; the promoted objects
        // carry it after promote_core replaced every channel.
        self.types.retain(|_, datatype| datatype.is_coretype());
        self.core_types.retain(|_, datatype| datatype.is_coretype());
        self.base_type_tree
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|_, datatype| datatype.is_coretype());
        self.base_cache
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|_, datatype| datatype.is_coretype());
        self.rel_pointers.clear();
        self.typedefs.clear();
    }

    // ---------------------------------------------------------------
    // Type-getters aligned with Ghidra's TypeFactory (type.cc).
    // Each follows the same "look-up-then-create-and-cache" pattern as
    // the C++ `findAdd`, keyed on the type name in our flat map.
    // ---------------------------------------------------------------

    // Ghidra: type.cc:3575 TypeFactory::getTypeVoid
    /// The faithful `TypeFactory::getTypeVoid` port (type.cc:3575-3588): the
    /// typecache slot `typecache[0][TYPE_VOID-TYPE_FLOAT]` returns
    /// immediately when filled; otherwise a `TypeVoid` (whose constructor
    /// sets `coretype` and the name "void", type.hh:389) is given
    /// `id = hashName("void")`, inserted directly into the tree/name
    /// cross-reference WITHOUT a findAdd conflict check, and cached in the
    /// typecache slot itself.
    pub fn get_type_void_result(&mut self) -> Arc<Datatype> {
        {
            let cache = self
                .base_cache
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(existing) = cache.get(&(0, TypeMetatype::Void)) {
                return existing.clone();
            }
        }
        // TypeVoid ctor (type.hh:389): name "void", size 0, coretype flag.
        let mut base = TypeBase::new("void".to_string(), 0, TypeMetatype::Void);
        base.id = Datatype::hash_name("void");
        base.flags |= type_flags::CORETYPE;
        let dt = Arc::new(Datatype::Void(base));
        let tree_key = (Self::submeta_of(&dt), Reverse(dt.get_size()), dt.get_id());
        let mut tree = self
            .base_type_tree
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tree.insert(tree_key, dt.clone());
        drop(tree);
        self.types.insert("void".to_string(), dt.clone());
        self.base_cache
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert((0, TypeMetatype::Void), dt.clone());
        dt
    }

    // RUGRA-GLUE: shared-reference twin of [`Self::get_type_void_result`]
    /// for callers holding `&TypeFactory` (userop/funcdata). Every production
    /// factory bootstraps the void core type, so the cache/name lookup always
    /// resolves; the raw-constructor creation path is the `_result` variant.
    pub fn get_type_void(&self) -> Arc<Datatype> {
        {
            let cache = self
                .base_cache
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(existing) = cache.get(&(0, TypeMetatype::Void)) {
                return existing.clone();
            }
        }
        self.find_by_name("void")
            .expect("void core type must exist")
    }

    // Ghidra: type.cc:3678 TypeFactory::getTypeChar(int4 s)
    /// If a core character data-type of the given size exists, return it.
    /// Otherwise raise Ghidra's LowlevelError. Faithful to
    /// `TypeFactory::getTypeChar(int4 s)` (type.cc:3678-3687): the lookup
    /// consults `charcache[s]` only for `s < 5`; every other size — and every
    /// cache miss — raises
    /// `"Request for unsupported character data-type"` as `Err`.
    pub fn get_type_char(&self, size: usize) -> Result<Arc<Datatype>, String> {
        if size < 5 {
            let cache = self
                .char_cache
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(existing) = cache.get(&size) {
                return Ok(existing.clone());
            }
        }
        Err("Request for unsupported character data-type".to_string())
    }

    // Ghidra: type.cc:3593 TypeFactory::getTypeChar(const string &n)
    /// Create a 1-byte character data-type (assumed UTF8). Faithful to
    /// `TypeFactory::getTypeChar(const string &n)` (type.cc:3593-3599): build
    /// a `TypeChar(n)` — `TypeBase(1,TYPE_INT,n)` with the `chartype` flag
    /// and `SUB_INT_CHAR` (type.hh:356) — give it `id = hashName(n)`, and run
    /// it through `findAdd` (same-definition hit returns the existing object,
    /// conflicting definitions raise the alter-definition LowlevelError).
    pub fn get_type_char_named(&mut self, n: &str) -> Result<Arc<Datatype>, String> {
        let mut base = TypeBase::new_char(n.to_string(), TypeMetatype::Int);
        base.id = Datatype::hash_name(n);
        self.find_add(Datatype::Base(base), false)
    }

    // Ghidra: type.cc:3606 TypeFactory::getTypeUnicode
    /// Create a multi-byte character data-type (UTF16/UTF32). Faithful to
    /// `TypeFactory::getTypeUnicode` (type.cc:3606-3612): build a
    /// `TypeUnicode(nm,sz,m)` — `setflags()` selects `utf16`/`utf32`/
    /// `chartype` by size (type.cc:837-846) and the sub-metatype is
    /// `SUB_INT_UNICODE`/`SUB_UINT_UNICODE` regardless of size
    /// (type.cc:862-867) — give it `id = hashName(nm)`, and run it through
    /// `findAdd`.
    pub fn get_type_unicode_named(
        &mut self,
        nm: &str,
        sz: usize,
        m: TypeMetatype,
    ) -> Result<Arc<Datatype>, String> {
        let mut base = TypeBase::new_unicode(nm.to_string(), sz, m);
        base.id = Datatype::hash_name(nm);
        self.find_add(Datatype::Base(base), false)
    }

    // RUGRA-GLUE: size-keyed convenience wrapper over
    /// [`Self::get_type_unicode_named`] with the historical canonical name
    /// (wchar2/wchar4). Ghidra has no size-only getTypeUnicode; the
    /// name-carrying port above is the faithful entry.
    pub fn get_type_unicode(&mut self, size: usize) -> Arc<Datatype> {
        let name = unicode_name_for_size(size);
        match self.get_type_unicode_named(&name, size, TypeMetatype::Int) {
            Ok(dt) => dt,
            // The legacy API cannot fail on the default factory state it was
            // designed for (an installed alignment map); surface the faithful
            // error as a panic rather than silently diverging.
            Err(message) => panic!("LowlevelError: {message}"),
        }
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

    // Ghidra: type.cc:3850 TypeFactory::setUnionFields
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
    /// The faithful `TypeFactory::getTypeEnum` port (type.cc:3967-3973): a
    /// `TypeEnum tmp(enumsize, enumtype, n)` — the factory's configured
    /// `enumsize`/`enumtype` state (type.hh:489-494 sets the `enumtype` flag,
    /// normalizes the metatype to TYPE_INT/TYPE_UINT, and leaves the
    /// sub-metatype at base2sub[TYPE_ENUM_INT/UINT] = 15/13) — with
    /// `id = hashName(n)`, canonicalized through `findAdd` (name cross-
    /// reference AND the ordered tree, so the enum participates in
    /// cacheCoreTypes like any other core entry).
    ///
    /// `enum_size`/`enum_type` are populated by `parse_enum_config` /
    /// `setup_sizes`; a factory that never ran either keeps the raw-
    /// constructor zero state, and the faithful error propagation surfaces
    /// findAdd's LowlevelErrors as `Err`.
    pub fn get_type_enum_result(&mut self, name: &str) -> Result<Arc<Datatype>, String> {
        let meta = if self.enum_type == TypeMetatype::Int {
            TypeMetatype::Int
        } else {
            TypeMetatype::Uint
        };
        let mut base = TypeBase::new(name.to_string(), self.enum_size.max(0) as usize, meta);
        base.id = Datatype::hash_name(name);
        base.flags |= type_flags::ENUMTYPE;
        self.find_add(
            Datatype::Enum(TypeEnum {
                base,
                values: std::collections::BTreeMap::new(),
            }),
            false,
        )
    }

    // RUGRA-GLUE: legacy flat-map twin of [`Self::get_type_enum_result`]
    /// kept for grammar.rs (its file is under another lease): dedupes by
    /// name and creates a 4-byte signed stub, which matches the oracle only
    /// for factories whose `enumsize`/`enumtype` were configured as 4/signed.
    /// The byte-faithful port reading the configured enum state is
    /// `get_type_enum_result`.
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

    // Ghidra: type.cc:3692 TypeFactory::getTypeCode()
    /// Retrieve or create the core "code" Datatype object with no prototype
    /// attached. Faithful to `TypeFactory::getTypeCode()` (type.cc:3692-3701):
    /// the typecache slot `typecache[1][TYPE_CODE-TYPE_FLOAT]` returns when
    /// filled; otherwise a generic complete `TypeCode` — UNNAMED, id 0
    /// (type.cc:3698-3700) — is canonicalized through `findAdd` (the ordered
    /// tree dedupes it on (SUB_CODE, size, id)).
    pub fn get_type_code(&mut self) -> Arc<Datatype> {
        {
            let cache = self
                .base_cache
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(existing) = cache.get(&(1, TypeMetatype::Code)) {
                return existing.clone();
            }
        }
        let base = TypeBase::new(String::new(), 1, TypeMetatype::Code);
        // tmp.markComplete() (type.cc:3699): considered complete.
        let candidate = Datatype::Code(TypeCode { base, proto: None });
        let tree_key = (Self::submeta_of(&candidate), Reverse(1), 0);
        let mut tree = self
            .base_type_tree
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dt = tree
            .entry(tree_key)
            .or_insert_with(|| Arc::new(candidate))
            .clone();
        dt
    }

    // Ghidra: type.cc:3707 TypeFactory::getTypeCode(const string &nm)
    /// Create a "function"/"executable" data-type with a name. Faithful to
    /// `TypeFactory::getTypeCode(const string &nm)` (type.cc:3707-3717): an
    /// empty name delegates to the unnamed getter; otherwise a generic
    /// complete `TypeCode` carrying `name`/`displayName` and
    /// `id = hashName(nm)` is canonicalized through `findAdd`.
    pub fn get_type_code_named(&mut self, nm: &str) -> Result<Arc<Datatype>, String> {
        if nm.is_empty() {
            return Ok(self.get_type_code());
        }
        let mut base = TypeBase::new(nm.to_string(), 1, TypeMetatype::Code);
        base.id = Datatype::hash_name(nm);
        // tmp.markComplete() (type.cc:3715).
        self.find_add(Datatype::Code(TypeCode { base, proto: None }), false)
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
        // type.cc:1051-1052 calcSubmeta needs_resolution inheritance
        // (TypePointerRel ctor delegates to the TypePointer ctor, type.hh:662).
        base.flags |= Self::pointer_inherit_needs_resolution(&ptr_to);
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

    // Ghidra: type.cc:3867 TypeFactory::getTypePointer(s,pt,ws)
    /// Find/create a pointer of the given `size` to `ptr_to` with `wordsize`,
    /// mirroring Ghidra's `TypeFactory::getTypePointer(int4 sz, Datatype *pt,
    /// uint4 ws)` (type.cc:3867-3883). The simpler `get_ptr` (which derives
    /// size from `ptr_size` and assumes `wordsize = 1`) is the hot path; this
    /// overload exists for callers (notably `TypePointerRel::downChain`,
    /// type.cc:2667) that must match an explicit pointer width and word size.
    pub fn get_type_pointer(
        &mut self,
        size: usize,
        ptr_to: Arc<Datatype>,
        wordsize: usize,
    ) -> Arc<Datatype> {
        // If the requested size matches the default and wordsize is 1, the
        // cheap `get_ptr` lookup covers us (and dedups by name).
        if size == self.ptr_size && wordsize == 1 {
            return self.get_ptr(ptr_to);
        }
        let name = format!("{} *", ptr_to.get_name());
        if let Some(existing) = self.find_by_name(&name) {
            // An existing entry under the default name may have a different
            // size/wordsize; trust the caller's explicit request by building
            // a fresh entry only when the cached one does not match.
            if existing.get_size() == size {
                return existing;
            }
        }
        let mut base = TypeBase::new(name.clone(), size, TypeMetatype::Pointer);
        base.flags |= type_flags::IS_PTRREL; // mark as non-core
        // type.cc:1051-1052 calcSubmeta needs_resolution inheritance
        // (TypeFactory::getTypePointer builds via the TypePointer ctor).
        base.flags |= Self::pointer_inherit_needs_resolution(&ptr_to);
        let dt = Arc::new(Datatype::Pointer(TypePointer {
            base,
            ptr_to,
            wordsize,
        }));
        self.types.insert(name, dt.clone());
        dt
    }

    // Ghidra: type.cc:2656 TypePointerRel::downChain
    /// Find a sub-type pointer given an offset into this relative pointer.
    /// Faithful to `TypePointerRel::downChain` (type.cc:2656-2672).
    ///
    /// If the offset lands inside `ptrto` and `ptrto` is a struct/array,
    /// defer to the plain `TypePointer::downChain` (reproduced inline below).
    /// Otherwise convert the offset to be relative to the parent container:
    /// `relOff = (off + offset) & calc_mask(size)`. If `relOff` is out of the
    /// parent's range, return `None`. Otherwise build a pointer to the parent
    /// and recurse via the plain-pointer downChain.
    ///
    /// `ptr` is the relative pointer; `parent`/`offset` come from the side
    /// table; `allow_array_wrap` matches Ghidra's `allowArrayWrap`. `off` is
    /// the in/out offset (updated in place). On success returns `(component,
    /// new_par, new_par_off)` where `component` is the pointer to drill into,
    /// `new_par` is the container pointer, and `new_par_off` is the offset
    /// into the container.
    pub fn down_chain(
        &mut self,
        ptr: &TypePointer,
        parent: &Arc<Datatype>,
        offset: i64,
        off: &mut i64,
        par: &mut Option<Arc<Datatype>>,
        par_off: &mut i64,
        allow_array_wrap: bool,
    ) -> Option<Arc<Datatype>> {
        let ptrto_meta = ptr.ptr_to.get_metatype();
        let ptrto_size = ptr.ptr_to.get_size() as i64;
        // If the offset is inside ptrto and ptrto is a container, defer to the
        // plain TypePointer::downChain (type.cc:2660-2662).
        if *off >= 0 && *off < ptrto_size
            && (ptrto_meta == TypeMetatype::Struct || ptrto_meta == TypeMetatype::Array)
        {
            return self.down_chain_pointer(ptr, off, par, par_off, allow_array_wrap);
        }
        // Convert off to be relative to the parent container.
        let mask = crate::address::calc_mask(ptr.base.size) as i64;
        let rel_off = (*off + offset) & mask;
        if rel_off < 0 || rel_off >= parent.get_size() as i64 {
            return None; // Don't let pointer shift beyond original container.
        }
        // Build a pointer to the parent (Ghidra: origPointer =
        // typegrp.getTypePointer(size, parent, wordsize)).
        let orig_pointer = self.get_type_pointer(ptr.base.size, parent.clone(), ptr.wordsize);
        *off = rel_off;
        // Recovering the start of the parent is still downchaining, even
        // though the parent may be the container (type.cc:2669-2670): return
        // the pointer to the parent and do not drill down to a field at 0.
        if rel_off == 0 && offset != 0 {
            *par = Some(orig_pointer.clone());
            *par_off = rel_off;
            return Some(orig_pointer);
        }
        // Recurse via the plain-pointer downChain on the freshly built parent
        // pointer (type.cc:2671). This walks into the parent's sub-type at
        // rel_off.
        let orig_as_ptr = match orig_pointer.as_ref() {
            Datatype::Pointer(p) => p.clone(),
            // Should not happen: get_type_pointer always builds a Pointer.
            _ => return Some(orig_pointer),
        };
        let result =
            self.down_chain_pointer(&orig_as_ptr, off, par, par_off, allow_array_wrap);
        result.or(Some(orig_pointer))
    }

    // Ghidra: type.cc:1084 TypePointer::downChain
    /// Plain `TypePointer::downChain` (type.cc:1084-1121), factored out so the
    /// relative-pointer override above can recurse into it. Faithful to the
    /// wrapping / enum / array / struct dispatch.
    ///
    /// Returns `Some(pointer_to_component)` with `off` updated to the
    /// component-relative offset, `par` set to the container pointer (when
    /// ptrto is an array or struct), and `par_off` set to the offset into the
    /// container.
    fn down_chain_pointer(
        &mut self,
        ptr: &TypePointer,
        off: &mut i64,
        par: &mut Option<Arc<Datatype>>,
        par_off: &mut i64,
        allow_array_wrap: bool,
    ) -> Option<Arc<Datatype>> {
        let ptrto = &ptr.ptr_to;
        let ptrto_size = ptrto.get_align_size() as i64;
        // Check if we are wrapping (type.cc:1088-1100).
        if *off < 0 || *off >= ptrto_size {
            if ptrto_size != 0 && !ptrto.is_variable_length() {
                if !allow_array_wrap {
                    return None;
                }
                // sign_extend(off, size*8-1) then modulo ptrto_size.
                let bits = ptr.base.size * 8;
                let mut sign_off = sign_extend(*off, bits.saturating_sub(1));
                sign_off = sign_off % ptrto_size;
                if sign_off < 0 {
                    sign_off += ptrto_size;
                }
                *off = sign_off;
                if *off == 0 {
                    // Wrapped back to zero: consider this going down one level.
                    // Return a pointer to `this` (the original ptrto).
                    return Some(
                        self.get_type_pointer(ptr.base.size, ptrto.clone(), ptr.wordsize),
                    );
                }
            }
        }
        if ptrto.is_enum_type() {
            // Go "into" the enumeration: build a pointer to a 1-byte uint.
            let tmp = self.get_base(1, TypeMetatype::Uint)?;
            *off = 0;
            return Some(self.get_type_pointer(ptr.base.size, tmp, ptr.wordsize));
        }
        let meta = ptrto.get_metatype();
        let is_array = meta == TypeMetatype::Array;
        // Build the pointer-to-`this` for the container bookkeeping (Ghidra
        // sets `par = this`).
        let this_pointer = self.get_type_pointer(ptr.base.size, ptrto.clone(), ptr.wordsize);
        if is_array || meta == TypeMetatype::Struct {
            *par = Some(this_pointer.clone());
            *par_off = *off;
        }
        // pt = ptrto->getSubType(off, &off).
        let (pt, new_off) = ptrto.get_sub_type(*off);
        let pt = match pt {
            Some(t) => Arc::new(t.clone()),
            None => return None,
        };
        *off = new_off;
        if !is_array {
            // getTypePointerStripArray: strip the array layer off `pt` if any
            // (type.cc:3849). Rugra has no dedicated factory method yet; the
            // strip is done inline by recursing into the element type.
            let stripped = strip_array(pt.clone());
            Some(self.get_type_pointer(ptr.base.size, stripped, ptr.wordsize))
        } else {
            Some(self.get_type_pointer(ptr.base.size, pt, ptr.wordsize))
        }
    }

    // Ghidra: type.cc:2693 TypePointerRel::getPtrToFromParent (static)
    /// Given a containing data-type and offset, find the "pointed to"
    /// data-type suitable for a `TypePointerRel`. Faithful to
    /// `TypePointerRel::getPtrToFromParent` (type.cc:2693-2707).
    ///
    /// The biggest contained data-type that starts at the exact offset is
    /// returned. If the offset is negative or there is no data-type starting
    /// exactly there, a 1-byte `undefined1` data-type is returned.
    pub fn get_ptr_to_from_parent(
        &mut self,
        base: &Arc<Datatype>,
        off: i64,
    ) -> Arc<Datatype> {
        if off > 0 {
            let mut cur = base.clone();
            let mut cur_off = off;
            loop {
                let (sub, new_off) = cur.get_sub_type(cur_off);
                match sub {
                    Some(s) => {
                        cur = Arc::new(s.clone());
                        cur_off = new_off;
                        if cur_off == 0 {
                            break;
                        }
                    }
                    None => {
                        // Ghidra: base = typegrp.getBase(1, TYPE_UNKNOWN).
                        return self.get_base(1, TypeMetatype::Unknown)
                            .unwrap_or_else(|| {
                                Arc::new(Datatype::Base(TypeBase::new(
                                    "undefined1".to_string(),
                                    1,
                                    TypeMetatype::Unknown,
                                )))
                            });
                    }
                }
            }
            cur
        } else {
            // off <= 0: unknown.
            self.get_base(1, TypeMetatype::Unknown).unwrap_or_else(|| {
                Arc::new(Datatype::Base(TypeBase::new(
                    "undefined1".to_string(),
                    1,
                    TypeMetatype::Unknown,
                )))
            })
        }
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

    // Ghidra: type.cc:3850 TypeFactory::getTypedefTarget
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
        let mut base = TypeBase::new(cache_key.clone(), new_size, TypeMetatype::Pointer);
        // type.cc:1051-1052 calcSubmeta needs_resolution inheritance
        // (TypeFactory::resizePointer builds `TypePointer tmp(newSize,pt,
        // wordsize)` via the ctor, type.cc:4077).
        base.flags |= Self::pointer_inherit_needs_resolution(&pointee);
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

    // Ghidra: type.cc:3850 TypeFactory::TypeFactory(Architecture *g)
    /// The single TypeFactory instance for the locked-oracle process model.
    ///
    /// Ghidra constructs exactly one `TypeFactory` per `Architecture`
    /// (`TypeFactory::TypeFactory(Architecture *g)`, type.cc:3850-3119 — the
    /// factory holds `glb` and every `getBase`/`findAdd` call deduplicates
    /// against that one factory), and the canonical headless oracle runs one
    /// Architecture per process. Rugra's production `Funcdata` does not yet
    /// carry an attached `Architecture` (FUNCPROTO-MODEL-BIND-0001 chain), so
    /// callers with no injectable handle (`VarnodeBank` default typing,
    /// `ScopeLocal` symbol typing) resolve this process-wide DataOrg-flavor
    /// factory instead — preserving the oracle's observable identity domain
    /// (one canonical `undefined{size}` object per size for the whole
    /// process) until per-Architecture wiring lands. Callers that DO have an
    /// Architecture must prefer its own `types` handle.
    pub fn shared_default() -> Arc<RwLock<TypeFactory>> {
        static SHARED: std::sync::OnceLock<Arc<RwLock<TypeFactory>>> = std::sync::OnceLock::new();
        SHARED
            .get_or_init(|| Arc::new(RwLock::new(TypeFactory::new(8))))
            .clone()
    }

    // Ghidra: type.cc:4140 TypeFactory::concretize
    /// Concretize a possibly-abstract data-type into a representable one.
    /// Faithful to `TypeFactory::concretize` (type.cc:4140-4150): a TYPE_CODE
    /// of size 1 is replaced with the factory's `getBase(1, TYPE_UNKNOWN)`
    /// output (same object identity on repeated calls); anything else is
    /// returned unchanged.
    pub fn concretize(&self, ct: Arc<Datatype>) -> Arc<Datatype> {
        if ct.get_metatype() == TypeMetatype::Code {
            debug_assert_eq!(
                ct.get_size(),
                1,
                "Primitive code data-type that is not size 1"
            );
            // type.cc:4147: ct = getBase(1, TYPE_UNKNOWN);
            return self
                .get_base(1, TypeMetatype::Unknown)
                .expect("factory always produces a base unknown");
        }
        ct
    }

    // Ghidra: type.cc:3850 TypeFactory::deconcretize
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

// Ghidra: type.cc:709 Datatype::hashSize
/// Reversibly hash a size into a data-type id. Faithful to
/// `Datatype::hashSize` (type.cc:709-716): `sizeHash = size *
/// 0x98251033aecbabaf; id ^= sizeHash;` — feeding the output back with the
/// same size recovers the original id. Delegates to the canonical
/// `Datatype::hash_size` port.
pub fn hash_size(id: u64, sz: usize) -> u64 {
    Datatype::hash_size(id, sz as i32)
}

// Ghidra: type.cc:3850 TypeFactory::charNameForSize
/// Produce the canonical name for a char type of `size` bytes. Mirrors
/// Ghidra's `charcache` (1→"char", 2→"wchar2", 4→"wchar4").
fn char_name_for_size(size: usize) -> String {
    match size {
        1 => "char".to_string(),
        _ => format!("wchar{}", size),
    }
}

// Ghidra: type.cc:3850 TypeFactory::unicodeNameForSize
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
    /// (type.cc:3137-3170): every zeroed size field gets its default, an
    /// empty alignment map installs `setDefaultAlignmentMap`, and a zero
    /// `enumsize` takes the architecture default size with unsigned
    /// meta-type.
    ///
    /// Rugra glue: Ghidra pulls the stack spacebase size, default data space
    /// address size, default size, and far-pointer segment op from the
    /// `Architecture` handle (`glb`). Rugra's `TypeFactory` does not hold an
    /// Architecture yet, so those lookups are passed in as `SizeArchInputs`
    /// by the caller; the derivation arithmetic below is 1:1 with the
    /// oracle.
    pub fn setup_sizes(&mut self, arch: &SizeArchInputs) {
        // Ghidra: if (sizeOfInt == 0) { sizeOfInt = 1; spc = glb->getStackSpace();
        //        if (spc) { sizeOfInt = spdata.size; if (sizeOfInt > 4) sizeOfInt = 4; } }
        if self.size_of_int == 0 {
            self.size_of_int = 1; // Default if we can't find a better value
            if let Some(spacebase_size) = arch.stack_spacebase_size {
                // Use stack pointer as likely indicator of "int" size.
                self.size_of_int = spacebase_size;
                if self.size_of_int > 4 {
                    // "int" is rarely bigger than 4 bytes
                    self.size_of_int = 4;
                }
            }
        }
        // Ghidra: if (sizeOfLong == 0) sizeOfLong = (sizeOfInt == 4) ? 8 : sizeOfInt;
        if self.size_of_long == 0 {
            self.size_of_long = if self.size_of_int == 4 {
                8
            } else {
                self.size_of_int
            };
        }
        // Ghidra: if (sizeOfChar == 0) sizeOfChar = 1;
        if self.size_of_char == 0 {
            self.size_of_char = 1;
        }
        // Ghidra: if (sizeOfWChar == 0) sizeOfWChar = 2;
        if self.size_of_wchar == 0 {
            self.size_of_wchar = 2;
        }
        // Ghidra: if (sizeOfPointer == 0) sizeOfPointer =
        //        glb->getDefaultDataSpace()->getAddrSize();
        if self.size_of_pointer == 0 {
            self.size_of_pointer = arch.default_data_space_addr_size;
        }
        // Ghidra: segOp = glb->getSegmentOp(glb->getDefaultDataSpace());
        //        if (segOp && segOp->hasFarPointerSupport()) {
        //          sizeOfPointer = segOp->getInnerSize();
        //          sizeOfAltPointer = sizeOfPointer + segOp->getBaseSize(); }
        if let Some((inner_size, base_size)) = arch.far_pointer {
            self.size_of_pointer = inner_size;
            self.size_of_alt_pointer = inner_size + base_size;
        }
        // Ghidra: if (alignMap.empty()) setDefaultAlignmentMap();
        if self.align_map.is_empty() {
            self.set_default_alignment_map();
        }
        // Ghidra: if (enumsize == 0) { enumsize = glb->getDefaultSize();
        //        enumtype = TYPE_ENUM_UINT; }
        if self.enum_size == 0 {
            self.enum_size = arch.default_size;
            self.enum_type = TypeMetatype::Uint;
        }
    }

    // Ghidra: type.cc:3178 TypeFactory::setCoreType
    /// Manually create a "base" core type and mark it as core. Faithful to
    /// `TypeFactory::setCoreType` (type.cc:3178-3195):
    ///
    /// ```text
    /// if (chartp) { if (size == 1) ct = getTypeChar(name);
    ///               else ct = getTypeUnicode(name,size,meta); }
    /// else if (meta == TYPE_CODE) ct = getTypeCode(name);
    /// else if (meta == TYPE_VOID) ct = getTypeVoid();
    /// else ct = getBase(size,meta,name);
    /// ct->flags |= Datatype::coretype;
    /// ```
    ///
    /// Returns the (possibly newly created) core type. Conflicting
    /// registrations surface Ghidra's `findAdd` LowlevelError messages as
    /// `Err` ("Trying to alter definition of type: …", "Shared type id: …",
    /// "Datatype must have a valid id: …", "TypeFactory alignment map not
    /// initialized") with NO partial state — exactly like the oracle, which
    /// throws before inserting anything.
    ///
    /// Promotion aliasing: Ghidra ORs `coretype` onto the canonical object
    /// IN PLACE when the name already resolves to an equal definition, so
    /// every external alias observes the flag immediately. Rust's immutable
    /// `Arc<Datatype>` cannot mutate through shared handles
    /// (src/type_system/datatype.rs holds the flag model, a separate lease),
    /// so [`Self::promote_core`] conservatively replaces the promoted object
    /// in EVERY factory-owned channel — `types`, `core_types`,
    /// `base_type_tree`, `base_cache`, `char_cache`, `type_nochar`, and
    /// identical `typedefs`/`rel_pointers` values — making all
    /// factory-mediated observations identical. Flag visibility through an
    /// external stale Arc handle remains the registered residual
    /// TYPEFACTORY-CORE-PROMOTION-IDENTITY-0001.
    pub fn set_core_type_result(
        &mut self,
        name: &str,
        size: usize,
        meta: TypeMetatype,
        chartp: bool,
    ) -> Result<Arc<Datatype>, String> {
        let ct = if chartp {
            if size == 1 {
                self.get_type_char_named(name)?
            } else {
                self.get_type_unicode_named(name, size, meta)?
            }
        } else if meta == TypeMetatype::Code {
            self.get_type_code_named(name)?
        } else if meta == TypeMetatype::Void {
            // getTypeVoid returns the singleton, whose constructor already
            // sets coretype (type.hh:389).
            return Ok(self.get_type_void_result());
        } else {
            self.get_base_named(size, meta, name)?
        };
        // type.cc:3194 `ct->flags |= Datatype::coretype;`
        Ok(self.promote_core(&ct))
    }

    // RUGRA-GLUE: Arc-returning compatibility wrapper around
    /// [`Self::set_core_type_result`] for callers written before the Result
    /// port (cpool.rs/merge.rs test fixtures; their files are under other
    /// leases). The faithful LowlevelError-equivalent path is
    /// `set_core_type_result`; migrate callers when their leases free up
    /// (TYPEFACTORY-LEGACY-CALLER-MIGRATION-0001).
    pub fn set_core_type(
        &mut self,
        name: &str,
        size: usize,
        meta: TypeMetatype,
        chartp: bool,
    ) -> Arc<Datatype> {
        match self.set_core_type_result(name, size, meta, chartp) {
            Ok(dt) => dt,
            Err(message) => panic!("LowlevelError: {message}"),
        }
    }

    // Ghidra: type.cc:3194 `ct->flags |= Datatype::coretype;` (in-place OR)
    /// OR the `coretype` flag onto the canonical factory object, replacing
    /// the immutable Arc in every factory-owned channel so that all
    /// factory-mediated lookups observe the promotion atomically. A type that
    /// is already core is returned unchanged (the OR is idempotent, exactly
    /// like the oracle's in-place mutation).
    ///
    /// External stale-handle flag visibility cannot be mirrored without an
    /// interior-mutability rework of `Datatype` (datatype.rs, separate
    /// lease); that divergence stays registered under
    /// TYPEFACTORY-CORE-PROMOTION-IDENTITY-0001.
    fn promote_core(&mut self, ct: &Arc<Datatype>) -> Arc<Datatype> {
        if ct.is_coretype() {
            return ct.clone();
        }
        let mut promoted = ct.as_ref().clone();
        match &mut promoted {
            Datatype::Void(base) | Datatype::Base(base) => base.flags |= type_flags::CORETYPE,
            Datatype::Enum(e) => e.base.flags |= type_flags::CORETYPE,
            Datatype::Spacebase(s) => s.base.flags |= type_flags::CORETYPE,
            Datatype::Pointer(p) => p.base.flags |= type_flags::CORETYPE,
            Datatype::Array(a) => a.base.flags |= type_flags::CORETYPE,
            Datatype::Struct(s) => s.base.flags |= type_flags::CORETYPE,
            Datatype::Union(u) => u.base.flags |= type_flags::CORETYPE,
            Datatype::Code(c) => c.base.flags |= type_flags::CORETYPE,
            Datatype::PartialStruct(ps) => ps.base.flags |= type_flags::CORETYPE,
            Datatype::PartialEnum(pe) => pe.base.flags |= type_flags::CORETYPE,
            Datatype::PartialUnion(pu) => pu.base.flags |= type_flags::CORETYPE,
        }
        let promoted = Arc::new(promoted);
        let name = promoted.get_name().to_string();
        if !name.is_empty() {
            // The factory's core retention set must contain the promoted
            // object so clearNoncore keeps it (Ghidra scans the core flag in
            // the tree instead).
            self.core_types.insert(name.clone(), promoted.clone());
            if self
                .types
                .get(&name)
                .is_some_and(|old| Arc::ptr_eq(old, ct))
            {
                self.types.insert(name, promoted.clone());
            }
        }
        {
            let tree_key = (
                Self::submeta_of(&promoted),
                Reverse(promoted.get_size()),
                promoted.get_id(),
            );
            let mut tree = self
                .base_type_tree
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match tree.get(&tree_key) {
                Some(old) if Arc::ptr_eq(old, ct) => {
                    tree.insert(tree_key, promoted.clone());
                }
                None => {
                    tree.insert(tree_key, promoted.clone());
                }
                _ => {}
            }
        }
        {
            // Ghidra's in-place OR never touches the caches; the preferred
            // slots only ever hold core types (cacheCoreTypes skips
            // non-core), so a promoted type cannot already occupy a slot.
            // Replace-by-identity only, for defensive atomicity.
            let mut cache = self
                .base_cache
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(slot) = cache.get_mut(&(promoted.get_size(), promoted.get_metatype())) {
                if Arc::ptr_eq(slot, ct) {
                    *slot = promoted.clone();
                }
            }
        }
        {
            let mut char_cache = self
                .char_cache
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for slot in char_cache.values_mut() {
                if Arc::ptr_eq(slot, ct) {
                    *slot = promoted.clone();
                }
            }
        }
        {
            let mut nochar = self
                .type_nochar
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if nochar.as_ref().is_some_and(|old| Arc::ptr_eq(old, ct)) {
                *nochar = Some(promoted.clone());
            }
        }
        for target in self.typedefs.values_mut() {
            if Arc::ptr_eq(target, ct) {
                *target = promoted.clone();
            }
        }
        for rel in self.rel_pointers.values_mut() {
            if Arc::ptr_eq(&rel.parent, ct) {
                rel.parent = promoted.clone();
            }
        }
        promoted
    }

    // Ghidra: type.cc:3200 TypeFactory::cacheCoreTypes
    /// Walk the type tree and cache the most commonly accessed core types for
    /// quick lookup. Faithful to `TypeFactory::cacheCoreTypes`
    /// (type.cc:3200-3248).
    ///
    pub fn cache_core_types(&mut self) {
        let ordered: Vec<Arc<Datatype>> = self
            .base_type_tree
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect();
        let cache = self
            .base_cache
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let nochar = self
            .type_nochar
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let char_cache = self
            .char_cache
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        for datatype in ordered {
            if !datatype.is_coretype() {
                continue;
            }
            let size = datatype.get_size();
            let metatype = datatype.get_metatype();
            if size > 8 {
                if metatype == TypeMetatype::Float && (size == 10 || size == 16) {
                    cache.insert((size, metatype), datatype);
                }
                continue;
            }

            match metatype {
                TypeMetatype::Int => {
                    let is_ascii = datatype.get_flags() & type_flags::CHARTYPE != 0;
                    if size == 1 && !is_ascii {
                        *nochar = Some(datatype.clone());
                    }
                    if datatype.is_enum_type() {
                        continue;
                    }
                    if datatype.is_char_print() {
                        if size < 5 {
                            char_cache.insert(size, datatype.clone());
                        }
                        if is_ascii {
                            cache.insert((size, metatype), datatype);
                        }
                        continue;
                    }
                    cache.entry((size, metatype)).or_insert(datatype);
                }
                TypeMetatype::Uint => {
                    if datatype.is_enum_type() {
                        continue;
                    }
                    let is_ascii = datatype.get_flags() & type_flags::CHARTYPE != 0;
                    if datatype.is_char_print() {
                        if size < 5 {
                            char_cache.insert(size, datatype.clone());
                        }
                        if is_ascii {
                            cache.insert((size, metatype), datatype);
                        }
                        continue;
                    }
                    cache.entry((size, metatype)).or_insert(datatype);
                }
                TypeMetatype::Void
                | TypeMetatype::Unknown
                | TypeMetatype::Bool
                | TypeMetatype::Code
                | TypeMetatype::Float => {
                    cache.entry((size, metatype)).or_insert(datatype);
                }
                _ => {}
            }
        }
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
    /// Parse data-type elements into this container. This stream is presumed
    /// to contain "core" data-types and the cached matrix will be populated
    /// from this set. Faithful to `TypeFactory::decodeCoreTypes`
    /// (type.cc:4567-4577):
    /// - `clear()` FIRST — a FULL wipe of tree/name cross-reference and
    /// every preferred-type cache (NOT clearNoncore; core entries from a
    /// previous stream do not survive),
    /// - each child element is decoded through `decodeTypeNoRef(decoder,
    ///   true)` (the forcecore flag ORs `coretype` onto the freshly built
    ///   candidate, type.cc:4459-4460 etc.),
    /// - `cacheCoreTypes()` runs at the end — but NOT when a child raised a
    ///   LowlevelError: the error propagates and the decoded-so-far partial
    ///   state remains observable.
    pub fn decode_core_types(&mut self, decoder: &mut dyn Decoder) -> Result<(), String> {
        self.clear(); // Make sure this routine flushes
        let elem_id = decoder.open_element_matching(&elem::element("coretypes"));
        while decoder.peek_element() != 0 {
            self.decode_type_no_ref(decoder, true)?;
        }
        if elem_id != 0 {
            decoder.close_element(elem_id);
        }
        self.cache_core_types();
        Ok(())
    }

    // Ghidra: type.cc:4583 TypeFactory::decodeDataOrganization
    /// Recover size defaults (`sizeOfInt`, `sizeOfLong`, `sizeOfPointer`,
    /// `sizeOfChar`, `sizeOfWChar`) and the alignment map by parsing a
    /// `<data_organization>` element. Faithful to
    /// `TypeFactory::decodeDataOrganization` (type.cc:4583-4615): only the
    /// five size children and `<size_alignment_map>` are consumed, every
    /// other child is closed-and-skipped, and the parsed sizes overwrite the
    /// factory fields (no defaulting happens here — that is `setupSizes`).
    /// Returns a snapshot of the five sizes for callers; the same values are
    /// persisted on the factory.
    pub fn decode_data_organization(
        &mut self,
        decoder: &mut dyn Decoder,
    ) -> DataOrganizationSizes {
        let elem_id = decoder.open_element_matching(&elem::element("data_organization"));
        loop {
            let sub_id = decoder.open_element();
            if sub_id == 0 {
                break;
            }
            let name = decoder.element_name(sub_id).unwrap_or_default();
            match name.as_str() {
                "integer_size" => {
                    // Ghidra: sizeOfInt = decoder.readSignedInteger(ATTRIB_VALUE);
                    self.size_of_int = decoder.read_signed_integer_attr(&attrib("value")) as i32;
                }
                "long_size" => {
                    self.size_of_long = decoder.read_signed_integer_attr(&attrib("value")) as i32;
                }
                "pointer_size" => {
                    self.size_of_pointer =
                        decoder.read_signed_integer_attr(&attrib("value")) as i32;
                }
                "char_size" => {
                    self.size_of_char = decoder.read_signed_integer_attr(&attrib("value")) as i32;
                }
                "wchar_size" => {
                    self.size_of_wchar = decoder.read_signed_integer_attr(&attrib("value")) as i32;
                }
                "size_alignment_map" => {
                    // Ghidra: decodeAlignmentMap(decoder); — no continue:
                    // falls through to the unified closeElement(subId)
                    // below, which closes <size_alignment_map> itself
                    // (type.cc:4604-4606 -> 4612).
                    self.decode_alignment_map(decoder);
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
        DataOrganizationSizes {
            size_of_int: self.size_of_int,
            size_of_long: self.size_of_long,
            size_of_pointer: self.size_of_pointer,
            size_of_char: self.size_of_char,
            size_of_wchar: self.size_of_wchar,
        }
    }

    // Ghidra: type.cc:4619 TypeFactory::decodeAlignmentMap
    /// Recover the size→alignment map from the children of a
    /// `<size_alignment_map>` element. Faithful to
    /// `TypeFactory::decodeAlignmentMap` (type.cc:4619-4641): the map is
    /// cleared, each `<entry size alignment>` grows the vector with -1 fill
    /// and assigns its size slot (a later duplicate entry wins), and a final
    /// forward pass copies the nearest earlier explicit alignment into every
    /// remaining -1 slot starting from `curAlign = 1` at index 1. Index 0 is
    /// never touched by the fill pass: it stays -1 unless an explicit
    /// `<entry size="0">` set it. An empty `<size_alignment_map>` leaves the
    /// map empty — no default is installed here (that is `setupSizes` via
    /// `setDefaultAlignmentMap`) and no exception is raised. Returns a
    /// snapshot of the persisted map.
    ///
    /// Rugra divergence (ill-formed input only): when a non-`<entry>` child
    /// appears mid-map, Ghidra breaks with the element left open (its parent
    /// `closeElement` then throws `DecoderError`); Rugra's TreeDecoder must
    /// close the opened child to keep its position coherent, so the child is
    /// skipped instead. Well-formed compiler specs (only `<entry>` children)
    /// never reach this branch.
    pub fn decode_alignment_map(&mut self, decoder: &mut dyn Decoder) -> Vec<i32> {
        // Ghidra: alignMap.clear();
        self.align_map.clear();
        loop {
            let map_id = decoder.open_element();
            let name = decoder.element_name(map_id).unwrap_or_default();
            if name != "entry" {
                // Ghidra: if (mapId != ELEM_ENTRY) break; — openElement
                // returning 0 (end of children) also lands here.
                if map_id != 0 {
                    decoder.close_element_skipping(map_id);
                }
                break;
            }
            // Ghidra: int4 sz = readSignedInteger(ATTRIB_SIZE);
            //        int4 val = readSignedInteger(ATTRIB_ALIGNMENT);
            let sz = decoder.read_signed_integer_attr(&attrib("size")) as usize;
            let val = decoder.read_signed_integer_attr(&attrib("alignment")) as i32;
            // Ghidra: while (alignMap.size() <= sz) alignMap.push_back(-1);
            while self.align_map.len() <= sz {
                self.align_map.push(-1);
            }
            self.align_map[sz] = val;
            decoder.close_element(map_id);
        }
        // Ghidra: int4 curAlign = 1;
        //        for (sz = 1; sz < alignMap.size(); ++sz) { ... }
        let mut cur_align: i32 = 1;
        for sz in 1..self.align_map.len() {
            let tmp = self.align_map[sz];
            if tmp == -1 {
                self.align_map[sz] = cur_align; // Copy from nearest explicit value.
            } else {
                cur_align = tmp;
            }
        }
        self.align_map.clone()
    }

    // Ghidra: type.cc:4644 TypeFactory::setDefaultAlignmentMap
    /// The default alignment map used when the compiler spec has no
    /// `<size_alignment_map>`. Faithful to
    /// `TypeFactory::setDefaultAlignmentMap` (type.cc:4644-4656): the vector
    /// is resized to 9 with 0 fill (so a fresh install yields
    /// `[0,1,2,2,4,4,4,4,8]` — index 0 is 0, not 1) and slots 1..=8 are
    /// assigned the x86-style powers-of-two ladder.
    pub fn set_default_alignment_map(&mut self) {
        // Ghidra: alignMap.resize(9,0);
        self.align_map.resize(9, 0);
        self.align_map[1] = 1;
        self.align_map[2] = 2;
        self.align_map[3] = 2;
        self.align_map[4] = 4;
        self.align_map[5] = 4;
        self.align_map[6] = 4;
        self.align_map[7] = 4;
        self.align_map[8] = 8;
    }

    // Ghidra: type.hh:813 TypeFactory::getSizeOfInt
    /// Snapshot getter mirroring Ghidra's inline `getSizeOfInt`
    /// (type.hh:813).
    pub fn get_size_of_int(&self) -> i32 {
        self.size_of_int
    }

    // Ghidra: type.hh:814 TypeFactory::getSizeOfLong
    /// Snapshot getter mirroring Ghidra's inline `getSizeOfLong`
    /// (type.hh:814).
    pub fn get_size_of_long(&self) -> i32 {
        self.size_of_long
    }

    // Ghidra: type.hh:815 TypeFactory::getSizeOfChar
    /// Snapshot getter mirroring Ghidra's inline `getSizeOfChar`
    /// (type.hh:815).
    pub fn get_size_of_char(&self) -> i32 {
        self.size_of_char
    }

    // Ghidra: type.hh:816 TypeFactory::getSizeOfWChar
    /// Snapshot getter mirroring Ghidra's inline `getSizeOfWChar`
    /// (type.hh:816).
    pub fn get_size_of_wchar(&self) -> i32 {
        self.size_of_wchar
    }

    // Ghidra: type.hh:817 TypeFactory::getSizeOfPointer
    /// Snapshot getter mirroring Ghidra's inline `getSizeOfPointer`
    /// (type.hh:817).
    pub fn get_size_of_pointer(&self) -> i32 {
        self.size_of_pointer
    }

    // Ghidra: type.hh:818 TypeFactory::getSizeOfAltPointer
    /// Snapshot getter mirroring Ghidra's inline `getSizeOfAltPointer`
    /// (type.hh:818).
    pub fn get_size_of_alt_pointer(&self) -> i32 {
        self.size_of_alt_pointer
    }

    // Ghidra: type.cc:3296 TypeFactory::getAlignment
    /// Return the alignment associated with a primitive data-type of the
    /// given size. Faithful to `TypeFactory::getAlignment`
    /// (type.cc:3296-3305): a size at or beyond the map end returns the last
    /// entry, an empty map raises `LowlevelError("TypeFactory alignment map
    /// not initialized")` (returned as `Err` with the same message), and any
    /// other size returns its slot (which may be -1 for index 0 when no
    /// explicit size-0 entry exists).
    pub fn get_alignment(&self, size: u32) -> Result<i32, String> {
        if size as usize >= self.align_map.len() {
            if self.align_map.is_empty() {
                return Err("TypeFactory alignment map not initialized".to_string());
            }
            return Ok(self.align_map[self.align_map.len() - 1]);
        }
        Ok(self.align_map[size as usize])
    }

    // Ghidra: type.cc:3312 TypeFactory::getPrimitiveAlignSize
    /// Return the amount of room a data-type takes up in memory (the
    /// `\b sizeof` size). Faithful to `TypeFactory::getPrimitiveAlignSize`
    /// (type.cc:3312-3320): `uint4 mod = size % align` converts the signed
    /// alignment to unsigned 32-bit first, so a -1 alignment behaves as
    /// 0xFFFFFFFF; the remainder is then padded up. A zero alignment (the
    /// default map's index 0) is a division by zero in Ghidra and panics
    /// here — never query size 0 against a default-installed map.
    pub fn get_primitive_align_size(&self, size: u32) -> Result<i32, String> {
        let align = self.get_alignment(size)?;
        let align_u = align as u32;
        let rem = size % align_u;
        let result = if rem != 0 {
            size.wrapping_add(align_u.wrapping_sub(rem))
        } else {
            size
        };
        Ok(result as i32)
    }

    // Ghidra: type.cc:4662 TypeFactory::parseEnumConfig
    /// Recover default enumeration properties (size and signedness) from an
    /// `<enum>` XML tag and store them (`enumsize`/`enumtype`). Faithful to
    /// `TypeFactory::parseEnumConfig` (type.cc:4662-4672).
    pub fn parse_enum_config(&mut self, decoder: &mut dyn Decoder) {
        let elem_id = decoder.open_element_matching(&elem::element("enum"));
        // Ghidra: enumsize = decoder.readSignedInteger(ATTRIB_SIZE);
        self.enum_size = decoder.read_signed_integer_attr(&attrib("size")) as i32;
        // Ghidra: if (decoder.readBool(ATTRIB_SIGNED)) enumtype = TYPE_ENUM_INT;
        //        else enumtype = TYPE_ENUM_UINT;
        self.enum_type = if decoder.read_bool_attr(&attrib("signed")) {
            TypeMetatype::Int
        } else {
            TypeMetatype::Uint
        };
        if elem_id != 0 {
            decoder.close_element(elem_id);
        }
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
                // type.cc:1027 TypePointer::decode calls calcSubmeta() —
                // mirror its needs_resolution inheritance arm
                // (type.cc:1051-1052) on the freshly decoded pointer.
                base.flags |= Self::pointer_inherit_needs_resolution(&ptrto);
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
                // Ghidra: type.cc:1329 TypeArray::decode rewinds attributes
                // after decodeBasic before re-reading ATTRIB_ARRAYSIZE —
                // decodeBasic's attribute loop has otherwise consumed the
                // element's attributes, and arraysize would stay -1.
                decoder.rewind_attributes();
                let num_elements = TypeArray::decode_array_attributes(decoder);
                let array_of = self.decode_type(decoder)?;
                // Ghidra: type.cc:1338-1339 TypeArray::decode:
                //   if ((arraysize<=0)||(arraysize*arrayof->getAlignSize()!=size))
                //     throw LowlevelError("Bad size for array of type "+arrayof->getName());
                // `decode_array_attributes` folds an absent or negative
                // `arraysize` attribute to 0, matching Ghidra's `<= 0` arm.
                // Ghidra multiplies in int4; Rust's usize cannot wrap, so an
                // overflowing product is rejected directly (such inputs would
                // only pass Ghidra's compare by int4 wraparound coincidence;
                // unreachable from well-formed specs).
                let product = num_elements.checked_mul(array_of.get_align_size());
                if product != Some(basic.size) {
                    return Err(format!(
                        "Bad size for array of type {}",
                        array_of.get_name()
                    ));
                }
                let mut name = basic.name.clone();
                if name.is_empty() {
                    name = format!("{}[{}]", array_of.get_name(), num_elements);
                }
                let mut base = TypeBase::new(name, basic.size, TypeMetatype::Array);
                base.id = basic.id;
                base.flags = basic.flags | if forcecore { type_flags::CORETYPE } else { 0 };
                // Ghidra: type.cc:1341-1342 TypeArray::decode:
                //   if (arraysize == 1)
                //     flags |= needs_resolution;	// Array of size 1 needs special treatment
                // Same condition as the inline TypeArray ctor arm applied by
                // get_array (type.hh:937-944), so decode and factory
                // creation agree.
                if num_elements == 1 {
                    base.flags |= type_flags::NEEDS_RESOLUTION;
                }
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
                // Ghidra's switch distinguishes TYPE_ENUM_INT/TYPE_ENUM_UINT
                // (type.cc:4482-4485); Rust's TypeMetatype collapses both
                // variants, so the original attribute string selects the
                // signedness that TypeEnum::decode derives from the decoded
                // metatype (type.cc:4323).
                let ct = self.decode_enum(decoder, forcecore, metastring == "enum_int")?;
                if elem_id != 0 {
                    decoder.close_element(elem_id);
                }
                Ok(ct)
            }
            TypeMetatype::Struct => {
                let ct = self.decode_struct(decoder, forcecore)?;
                if elem_id != 0 {
                    decoder.close_element(elem_id);
                }
                Ok(ct)
            }
            TypeMetatype::Union => {
                let ct = self.decode_union(decoder, forcecore)?;
                if elem_id != 0 {
                    decoder.close_element(elem_id);
                }
                Ok(ct)
            }
            TypeMetatype::Code => {
                let ct = self.decode_code(decoder, false, false, forcecore)?;
                if elem_id != 0 {
                    decoder.close_element(elem_id);
                }
                Ok(ct)
            }
            TypeMetatype::Void => {
                // Ghidra: type.cc:4504-4509 — TypeVoid voidType;
                // voidType.decode(decoder,*this); ct = findAdd(voidType);
                // The TypeVoid ctor sets name "void" and the coretype flag
                // (type.hh:389); decode only overwrites the id
                // (type.cc:887-897), and findAdd runs the full named path —
                // an absent id raises "Datatype must have a valid id: void".
                let id = Datatype::decode_void_id(decoder);
                let mut base = TypeBase::new("void".to_string(), 0, TypeMetatype::Void);
                base.id = id;
                base.flags |= type_flags::CORETYPE;
                let ct = self.find_add(Datatype::Void(base), false)?;
                if elem_id != 0 {
                    decoder.close_element(elem_id);
                }
                Ok(ct)
            }
            _ => {
                // Ghidra default arm (type.cc:4511-4544): scan attributes for
                // char/utf; a `char="true"` builds a TypeChar, `utf="true"`
                // builds a TypeUnicode, anything else a plain TypeBase — each
                // merged with decodeBasic's fields and canonicalized through
                // findAdd.
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
                let core_bit = if forcecore { type_flags::CORETYPE } else { 0 };
                let candidate = if is_char {
                    // type.cc:4515-4523: TypeChar ctor (type.hh:356) sets
                    // size 1/TYPE_INT/chartype/SUB_INT_CHAR; the ctor's
                    // decode then overwrites name/size/metatype/id and
                    // re-specializes submeta by the decoded metatype
                    // (type.cc:818).
                    let mut base = TypeBase::new_char(basic.name.clone(), basic.metatype);
                    base.size = basic.size;
                    base.id = basic.id;
                    base.flags |= basic.flags | core_bit;
                    Datatype::Base(base)
                } else if is_utf {
                    // type.cc:4525-4533: TypeUnicode + decode — setflags()
                    // picks utf16/utf32/chartype by size (type.cc:837-846)
                    // and submeta is SUB_INT_UNICODE/SUB_UINT_UNICODE
                    // regardless of size (type.cc:858).
                    let mut base =
                        TypeBase::new_unicode(basic.name.clone(), basic.size, basic.metatype);
                    base.id = basic.id;
                    base.flags |= basic.flags | core_bit;
                    Datatype::Base(base)
                } else {
                    let mut base = TypeBase::new(basic.name.clone(), basic.size, basic.metatype);
                    base.id = basic.id;
                    base.flags = basic.flags | core_bit;
                    Datatype::Base(base)
                };
                let dt = self.find_add(candidate, false)?;
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
    /// (type.cc:4318-4329): a `TypeEnum` scratch is decoded
    /// (`TypeEnum::decode` normalizes the metatype to TYPE_INT/TYPE_UINT,
    /// type.cc:4323), ORs `coretype` when `forcecore`, and is canonicalized
    /// through `findAdd` — so the enum enters the ordered tree and
    /// participates in cacheCoreTypes exactly like the oracle.
    ///
    /// `signed` carries the TYPE_ENUM_INT/TYPE_ENUM_UINT distinction of
    /// Ghidra's switch (type.cc:4482-4485), which Rust's collapsed
    /// `TypeMetatype::Enum` cannot express from `decode_basic` alone.
    pub fn decode_enum(
        &mut self,
        decoder: &mut dyn Decoder,
        forcecore: bool,
        signed: bool,
    ) -> Result<Arc<Datatype>, String> {
        let basic = Datatype::decode_basic(decoder);
        // Ghidra: metatype = (metatype == TYPE_ENUM_INT) ? TYPE_INT : TYPE_UINT;
        let meta = if signed {
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
        let dt = self.find_add(Datatype::Enum(TypeEnum { base, values }), false)?;
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
        // Decode fields. Per-field this mirrors, in order:
        //  - `TypeField::TypeField(Decoder&,TypeFactory&)` (type.cc:768-794):
        //    decode attributes, then `decodeType`, then the name-empty and
        //    offset-negative throws, then closeElement;
        //  - the `TypeStruct::decodeFields` acceptance loop
        //    (type.cc:1839-1870): void-metatype throw, out-of-order throw,
        //    overlap throw-out, does-not-fit throw.
        let mut fields: Vec<TypeField> = Vec::new();
        // decodeFields loop state (type.cc:1835-1837).
        let mut last_off: i64 = -1;
        let mut calc_size: i64 = 0;
        while decoder.peek_element() != 0 {
            let child_id = decoder.open_element();
            let attrs = TypeField::decode_field_attributes(decoder);
            // type.cc:786: type = typegrp.decodeType(decoder);
            let field_type = self.decode_type(decoder)?;
            // type.cc:787-790 (TypeField ctor, in this order).
            if attrs.name.is_empty() {
                return Err("name attribute must not be empty in <field> tag".to_string());
            }
            if attrs.offset < 0 {
                return Err("offset attribute invalid for <field> tag".to_string());
            }
            if child_id != 0 {
                decoder.close_element(child_id);
            }
            // type.cc:1842-1843: null type is impossible in Rust (decode_type
            // returns Result); the TYPE_VOID arm remains.
            if field_type.get_metatype() == TypeMetatype::Void {
                return Err(format!(
                    "Bad field data-type for structure: {}",
                    basic.name
                ));
            }
            // type.cc:1846-1848: strictly-lower-than-previous offset is out of
            // order; equal offsets fall through to the overlap check below.
            if (attrs.offset as i64) < last_off {
                return Err("Fields are out of order".to_string());
            }
            last_off = attrs.offset as i64;
            // type.cc:1849-1860: a field starting inside the previous field's
            // extent is thrown out with a warning (warning storage — the
            // `warning_issued` flag and the factory warnings list — is not
            // modelled on Rugra; the FIELD DROP is observable and mirrored).
            if (attrs.offset as i64) < calc_size {
                continue;
            }
            // type.cc:1861-1866: field must fit within the declared size.
            calc_size = attrs.offset as i64 + field_type.get_size() as i64;
            if calc_size > basic.size as i64 {
                return Err(format!(
                    "Field {} does not fit in structure {}",
                    attrs.name, basic.name
                ));
            }
            // type.cc:1867-1869 (calcAlign accumulation) feeds only the
            // `alignment`/`alignSize` tail, which Rugra's TypeBase does not
            // store (registered datatype.rs gap).
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
        }
        // Replace the stub with the fully-defined struct.
        let mut base = TypeBase::new(basic.name.clone(), basic.size, TypeMetatype::Struct);
        base.id = basic.id;
        base.flags = basic.flags | if forcecore { type_flags::CORETYPE } else { 0 };
        // decodeFields tail (type.cc:1871-1874) on the scratch:
        //   if (size == 0) flags |= type_incomplete;
        //   if (field.size() > 0) markComplete();   // clears type_incomplete
        // then decodeStruct transfers via TypeFactory::setFields
        // (type.cc:3487-3488: clear, then masked-OR the scratch's
        // opaque_string|variable_length|type_incomplete). The scratch always
        // starts incomplete (TypeStruct() default ctor, type.hh:518), so the
        // observable residue is: the factory type stays incomplete iff it
        // ended with zero fields (a size-0 struct cannot accept any field —
        // the fit check above rejects `calcSize > 0 == size`), and an XML
        // `incomplete="true"` attribute is overridden by non-empty fields,
        // exactly as Ghidra's markComplete-then-transfer sequence does.
        if fields.is_empty() {
            base.flags |= type_flags::TYPE_INCOMPLETE;
        } else {
            base.flags &= !type_flags::TYPE_INCOMPLETE;
        }
        // Ghidra: type.cc:1875-1877 TypeStruct::decodeFields tail:
        //   if (field.size() == 1) {
        //     if (field[0].type->getSize() == size)
        //       flags |= needs_resolution;		// needs special resolution
        //   }
        // `size` is the struct size decoded from the <type> element's
        // attributes (decodeBasic), exactly the member `TypeStruct::decodeFields`
        // reads (and the `newSize` decodeStruct passes through
        // `TypeFactory::setFields` at type.cc:4355, whose
        // `TypeStruct::setFields` arm re-derives the same flag, type.cc:1569-1571);
        // the comparison uses the field type's full `getSize` against the
        // post-throw-out field list. The flag is ORed in, never cleared.
        if fields.len() == 1 && fields[0].type_ptr.get_size() == basic.size {
            base.flags |= type_flags::NEEDS_RESOLUTION;
        }
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

    // Ghidra: type.cc:3390 TypeFactory::insert
    /// Internal method for finally inserting a new Datatype pointer.
    /// Faithful to the oracle's dual registration (type.cc:3390-3406) for the
    /// ATOMIC variants this factory's ordered tree models: the tree slot is
    /// keyed by (sub-metatype, descending size, id) — exactly `DatatypeCompare`
    /// (type.hh:306-310) — and the name cross-reference only receives NAMED
    /// (id != 0) entries. Container variants stay name-map-only because the
    /// flat key cannot express their component ordering (registered TYPE-0001
    /// residual); the byte-faithful path with the "Shared type id" conflict
    /// LowlevelError is [`Self::find_add`].
    fn insert(&mut self, dt: Arc<Datatype>) {
        let name = dt.get_name().to_string();
        let atomic = matches!(
            dt.as_ref(),
            Datatype::Void(_) | Datatype::Base(_) | Datatype::Enum(_) | Datatype::Code(_)
        );
        if atomic {
            let tree_key = (Self::submeta_of(&dt), Reverse(dt.get_size()), dt.get_id());
            self.base_type_tree
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .entry(tree_key)
                .or_insert_with(|| dt.clone());
        }
        // type.cc:3404-3405: `if (newtype->id!=0) nametree.insert(newtype);`
        // — unnamed entries live in the tree only. decodeBasic's hashName
        // fallback keeps named decode candidates id-non-zero in practice;
        // the flat map keeps any named entry for the legacy lookup paths.
        if !name.is_empty() {
            self.types.insert(name, dt);
        }
    }
}

/// Recovered size defaults from a `<data_organization>` element. Returned by
/// `TypeFactory::decode_data_organization` as a snapshot of the persisted
/// factory state (the factory also stores these in its own fields, mirroring
/// Ghidra's `sizeOf*` members).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataOrganizationSizes {
    /// Default size of "int" (Ghidra `sizeOfInt`).
    pub size_of_int: i32,
    /// Default size of "long" (Ghidra `sizeOfLong`).
    pub size_of_long: i32,
    /// Default pointer size (Ghidra `sizeOfPointer`).
    pub size_of_pointer: i32,
    /// Default char size (Ghidra `sizeOfChar`).
    pub size_of_char: i32,
    /// Default wide-char size (Ghidra `sizeOfWChar`).
    pub size_of_wchar: i32,
}

// RUGRA-GLUE: Architecture-handle lookups of TypeFactory::setupSizes
/// The architecture-derived inputs `TypeFactory::setup_sizes` reads from
/// `glb` in Ghidra (type.cc:3142-3167). Rugra's `TypeFactory` has no
/// Architecture handle yet, so callers provide the same observations:
/// `getStackSpace()->getSpacebase(0).size` (`None` when there is no stack
/// space), `getDefaultDataSpace()->getAddrSize()`, `getDefaultSize()`, and
/// the far-pointer segment op `(innerSize, baseSize)` when one with
/// far-pointer support resolves.
pub struct SizeArchInputs {
    /// `glb->getStackSpace()->getSpacebase(0).size`, or `None` when the
    /// architecture has no stack space (`getStackSpace() == 0`).
    pub stack_spacebase_size: Option<i32>,
    /// `glb->getDefaultDataSpace()->getAddrSize()`.
    pub default_data_space_addr_size: i32,
    /// `glb->getDefaultSize()`.
    pub default_size: i32,
    /// `(innerSize, baseSize)` of a far-pointer segment op on the default
    /// data space, `None` when there is none.
    pub far_pointer: Option<(i32, i32)>,
}

/// Side record for a relative pointer: the containing parent type and the
/// byte offset into it. Models the `parent`/`offset` fields of Ghidra's
/// `TypePointerRel` (type.hh:647) that do not fit on Rugra's flat `TypePointer`.
#[derive(Debug, Clone)]
pub struct RelativePointer {
    /// The container data-type this pointer indexes into.
    pub parent: Arc<Datatype>,
    /// Byte offset within `parent` where the pointee begins.
    pub offset: i64,
}

// Ghidra: type.cc:1092 sign_extend (address.hh:499 local helper)
/// Sign-extend the low `bits+1` bits of `val` to a full `i64`. Mirrors
/// Ghidra's `sign_extend(off, size*8-1)` invocation at type.cc:1092 (the
/// helper is defined in address.hh:499 as `sign_extend(intb val, int4 bits)`).
/// Used by `TypeFactory::down_chain_pointer` when wrapping an out-of-range
/// array offset back into `[0, ptrtoSize)`.
fn sign_extend(val: i64, bits: usize) -> i64 {
    // Guard against bits >= 64 (size >= 8 bytes), in which case no extension
    // is needed (Ghidra's shift by >= width is UB but effectively a no-op).
    if bits >= 63 {
        return val;
    }
    let shift = 63 - bits;
    ((val as i64) << shift) >> shift
}

// Ghidra: type.cc:3849 TypeFactory::getTypePointerStripArray (inline effect)
/// Strip a single array layer from `dt`, mirroring the behaviour of
/// `TypeFactory::getTypePointerStripArray` (type.cc:3849-3859) as invoked by
/// the plain `TypePointer::downChain` (type.cc:1119): if the component is an
/// array, return its element type; otherwise return the type unchanged.
fn strip_array(dt: Arc<Datatype>) -> Arc<Datatype> {
    match dt.as_ref() {
        Datatype::Array(a) => a.array_of.clone(),
        _ => dt,
    }
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
        // type.cc:3593/3678 — the size-only lookup returns the charcache
        // selection, which only exists after an ASCII core registration and
        // cacheCoreTypes (Ghidra's buildCoreTypes registers "char" first,
        // sleigh_arch.cc:235); an uncached request raises the oracle's
        // LowlevelError.
        let mut factory = TypeFactory::new(8);
        assert_eq!(
            factory.get_type_char(1).unwrap_err(),
            "Request for unsupported character data-type"
        );
        factory.set_core_type("char", 1, TypeMetatype::Int, true);
        factory.cache_core_types();
        let c = factory.get_type_char(1).expect("cached char");
        assert_eq!(c.get_size(), 1);
        assert_eq!(c.get_metatype(), TypeMetatype::Int);
        assert!(c.is_char_print());
        // dedup: second call returns the same Arc.
        let c2 = factory.get_type_char(1).expect("cached char");
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
        factory.set_core_type("char", 1, TypeMetatype::Int, true);
        factory.cache_core_types();
        let char_t = factory.get_type_char(1).expect("cached char");
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
    fn test_get_ptr_to_from_parent() {
        // type.cc:2693 — drill into a struct to find the field type at `off`.
        let mut factory = TypeFactory::new(8);
        let int_t = factory.find_by_name("int").unwrap();
        let _ = factory.create_struct("S");
        // S { int a @ 0; int b @ 4; }
        let fields = vec![
            TypeField { name: "a".into(), offset: 0, type_ptr: int_t.clone() },
            TypeField { name: "b".into(), offset: 4, type_ptr: int_t.clone() },
        ];
        let struct_t = factory.set_fields("S", fields).expect("struct S exists");
        // off=4 lands on field `b` (an int); the loop exits at newoff==0.
        let pt = factory.get_ptr_to_from_parent(&struct_t, 4);
        assert_eq!(pt.get_size(), 4);
        // off=0 should return the unknown fallback (Ghidra: getBase(1, UNKNOWN)).
        let pt0 = factory.get_ptr_to_from_parent(&struct_t, 0);
        assert_eq!(pt0.get_size(), 1);
        // Negative offset returns the 1-byte unknown fallback.
        let ptn = factory.get_ptr_to_from_parent(&struct_t, -1);
        assert_eq!(ptn.get_size(), 1);
    }

    #[test]
    fn test_down_chain_struct_field() {
        // type.cc:2656 — downchain a relative pointer whose offset (4) points
        // past the end of a 4-byte struct into the parent at offset 4.
        let mut factory = TypeFactory::new(8);
        let int_t = factory.find_by_name("int").unwrap();
        let _ = factory.create_struct("Inner");
        let inner_fields = vec![
            TypeField { name: "a".into(), offset: 0, type_ptr: int_t.clone() },
        ];
        let inner = factory.set_fields("Inner", inner_fields).expect("Inner exists");
        // Parent is a 2-field struct; the relative pointer points to `inner`
        // at offset 0 but its parent-relative offset is 4.
        let _ = factory.create_struct("Outer");
        let outer_fields = vec![
            TypeField { name: "x".into(), offset: 0, type_ptr: int_t.clone() },
            TypeField { name: "y".into(), offset: 4, type_ptr: inner.clone() },
        ];
        let outer = factory.set_fields("Outer", outer_fields).expect("Outer exists");
        let rp = factory.get_type_pointer_rel(int_t.clone(), outer.clone(), 4);
        let rp_ptr = match rp.as_ref() {
            Datatype::Pointer(p) => p.clone(),
            _ => panic!("expected a Pointer"),
        };
        // off=0 lands inside ptrto (int, size 4) but ptrto is neither struct
        // nor array, so we fall through to the parent-relative path.
        let mut off: i64 = 0;
        let mut par: Option<Arc<Datatype>> = None;
        let mut par_off: i64 = 0;
        let result = factory.down_chain(
            &rp_ptr, &outer, 4, &mut off, &mut par, &mut par_off, false,
        );
        // We expect a non-None result (drilled into the parent at rel_off=4).
        assert!(result.is_some(), "down_chain should produce a component pointer");
        // `par` should be populated (the pointer to Outer).
        assert!(par.is_some());
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
    fn test_raw_constructor_alignment_gate_and_void() {
        // type.cc:3106/3122 — the raw factory has no alignment map and no
        // core types; a findAdd miss raises the oracle LowlevelError text.
        let mut raw = TypeFactory::raw();
        assert_eq!(
            raw.get_base_result(1, TypeMetatype::Int).unwrap_err(),
            "TypeFactory alignment map not initialized"
        );
        // getTypeVoid works on the raw factory (type.cc:3575-3588).
        let void_t = raw.get_type_void_result();
        assert_eq!(void_t.get_name(), "void");
        assert_eq!(void_t.get_id(), Datatype::hash_name("void"));
        assert!(void_t.is_coretype());
    }

    #[test]
    fn test_set_core_type_promotes_existing_noncore_factory_view() {
        // type.cc:3178-3195 — setCoreType on an existing equal definition
        // ORs the core flag onto the canonical object. Every factory-mediated
        // lookup observes the promotion.
        let mut factory = TypeFactory::new(8);
        factory.clear();
        let pre = factory.get_base_named(1, TypeMetatype::Int, "promo_plain").unwrap();
        assert!(!pre.is_coretype());
        let post = factory.set_core_type_result("promo_plain", 1, TypeMetatype::Int, false).unwrap();
        assert!(post.is_coretype());
        assert_eq!(post.get_id(), pre.get_id());
        // The factory view is promoted.
        let queried = factory.find_by_name("promo_plain").unwrap();
        assert!(queried.is_coretype());
        assert!(Arc::ptr_eq(&queried, &post));
        // The promoted entry survives clearNoncore (Ghidra scans the flag).
        factory.clear_non_core();
        assert!(factory.find_by_name("promo_plain").is_some());
    }

    #[test]
    fn test_set_core_type_conflict_returns_oracle_error() {
        // type.cc:3423 — compareDependency mismatch raises the alter-
        // definition LowlevelError with no partial state.
        let mut factory = TypeFactory::new(8);
        factory.clear();
        factory.set_core_type("plain_x", 1, TypeMetatype::Int, false);
        let err = factory
            .set_core_type_result("plain_x", 2, TypeMetatype::Int, false)
            .unwrap_err();
        assert_eq!(err, "Trying to alter definition of type: plain_x");
        // Partial state: the original registration is untouched.
        let survivor = factory.find_by_name("plain_x").unwrap();
        assert_eq!(survivor.get_size(), 1);
        // A char/plain submeta mismatch also raises.
        let err2 = factory
            .set_core_type_result("plain_x", 1, TypeMetatype::Int, true)
            .unwrap_err();
        assert_eq!(err2, "Trying to alter definition of type: plain_x");
    }

    #[test]
    fn test_large_base_converts_to_unknown_array() {
        // type.cc:3652-3657 — sizes over max_basetype_size (10) become an
        // unnamed array of the cached 1-byte unknown.
        let mut factory = TypeFactory::new(8);
        factory.clear();
        factory.setup_sizes(&SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        factory.set_core_type("u1", 1, TypeMetatype::Unknown, false);
        factory.cache_core_types();
        let big = factory.get_base_result(20, TypeMetatype::Int).unwrap();
        assert_eq!(big.get_metatype(), TypeMetatype::Array);
        assert_eq!(big.get_size(), 20);
        assert!(big.get_name().is_empty());
        let repeat = factory.get_base_result(20, TypeMetatype::Int).unwrap();
        assert!(Arc::ptr_eq(&big, &repeat));
        match big.as_ref() {
            crate::type_system::datatype::Datatype::Array(a) => {
                assert_eq!(a.num_elements, 20);
                assert_eq!(a.array_of.get_name(), "u1");
            }
            _ => panic!("expected an array"),
        }
    }

    #[test]
    fn test_wide_char_and_float_cache_slots() {
        // type.cc:3182-3186 chartp size!=1 → TypeUnicode; type.cc:3210-3215
        // float10/16 dedicated slots; unicode fills charcache but never the
        // preferred ASCII slot.
        let mut factory = TypeFactory::new(8);
        factory.clear();
        let wide2 = factory.set_core_type_result("wide2", 2, TypeMetatype::Int, true).unwrap();
        assert!(wide2.get_flags() & type_flags::UTF16 != 0);
        let plain2 = factory.set_core_type_result("plain2", 2, TypeMetatype::Int, false).unwrap();
        let f10 = factory.set_core_type_result("f10", 10, TypeMetatype::Float, false).unwrap();
        let f16 = factory.set_core_type_result("f16", 16, TypeMetatype::Float, false).unwrap();
        factory.cache_core_types();
        // UTF16 is char-printable: charcache[2] holds it.
        assert!(Arc::ptr_eq(&factory.get_type_char(2).unwrap(), &wide2));
        // But not ASCII: the preferred (2, INT) slot goes to the plain int.
        assert!(Arc::ptr_eq(&factory.get_base(2, TypeMetatype::Int).unwrap(), &plain2));
        // Float10/16 dedicated slots.
        assert!(Arc::ptr_eq(&factory.get_base_result(10, TypeMetatype::Float).unwrap(), &f10));
        assert!(Arc::ptr_eq(&factory.get_base_result(16, TypeMetatype::Float).unwrap(), &f16));
    }

    #[test]
    fn test_decode_core_types_rebuilds_and_enums_enter_tree() {
        use crate::marshal::{Element, IdRegistry, TreeDecoder};
        fn el(name: &str, attrs: &[(&str, &str)]) -> std::sync::Arc<std::sync::RwLock<Element>> {
            let mut e = Element::new();
            e.set_name(name);
            for (k, v) in attrs {
                e.add_attribute(k, v);
            }
            std::sync::Arc::new(std::sync::RwLock::new(e))
        }
        let mut factory = TypeFactory::new(8);
        factory.clear();
        let root = el("coretypes", &[]);
        {
            let mut rg = root.write().unwrap();
            rg.add_child(el(
                "type",
                &[("name", "dk_enum"), ("size", "1"), ("metatype", "enum_int"), ("id", "0x5500000000000011")],
            ));
            rg.add_child(el(
                "type",
                &[("name", "dk_char"), ("size", "1"), ("metatype", "int"), ("char", "true"), ("id", "0x5500000000000012")],
            ));
        }
        let mut decoder = TreeDecoder::new(root, std::sync::Arc::new(std::sync::RwLock::new(IdRegistry)));
        factory.decode_core_types(&mut decoder).unwrap();
        // Full clear wiped the bootstrap entries.
        assert!(factory.find_by_name("undefined1").is_none());
        // The decoded enum is core and entered the ordered tree: with no
        // plain size-1 INT registered, type_nochar selects it (type.cc:3220-
        // 3222 runs BEFORE the isEnumType break).
        let dk_enum = factory.find_by_name("dk_enum").unwrap();
        assert!(dk_enum.is_coretype());
        assert!(dk_enum.is_enum_type());
        let nochar = factory.get_base_no_char(1, TypeMetatype::Int).unwrap();
        assert!(Arc::ptr_eq(&nochar, &dk_enum));
        // The enum break leaves typecache[1][INT] to the ASCII char.
        let dk_char = factory.find_by_name("dk_char").unwrap();
        let preferred = factory.get_base(1, TypeMetatype::Int).unwrap();
        assert!(Arc::ptr_eq(&preferred, &dk_char));
    }

    #[test]
    fn test_hash_size_stability() {
        // type.cc:709-716 — hashSize XORs the scaled size into the id; the
        // transform is an involution: feeding the output back with the same
        // size recovers the original id.
        let a = hash_size(0x1234, 1);
        let b = hash_size(0x1234, 4);
        assert_ne!(a, b);
        assert_eq!(a, hash_size(0x1234, 1));
        assert_eq!(hash_size(a, 1), 0x1234);
        assert_eq!(hash_size(b, 4), 0x1234);
        assert_eq!(a, Datatype::hash_size(0x1234, 1));
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

    #[test]
    fn test_unknown_base_is_canonical_by_size() {
        let mut factory = TypeFactory::new(8);
        let core = factory.get_base(8, TypeMetatype::Unknown).unwrap();
        let core_again = factory.get_base(8, TypeMetatype::Unknown).unwrap();
        assert!(Arc::ptr_eq(&core, &core_again));
        assert_eq!(core.get_name(), "undefined8");
        assert!(core.is_coretype());

        let anonymous = factory.get_base(3, TypeMetatype::Unknown).unwrap();
        let anonymous_again = factory.get_base(3, TypeMetatype::Unknown).unwrap();
        assert!(Arc::ptr_eq(&anonymous, &anonymous_again));
        assert!(!Arc::ptr_eq(&core, &anonymous));
        assert_eq!(anonymous.get_name(), "");
        assert_eq!(anonymous.get_id(), 0);
        assert!(!anonymous.is_coretype());

        let mut ordered = Vec::new();
        factory.dependent_order(&mut ordered);
        assert!(ordered.iter().any(|datatype| Arc::ptr_eq(datatype, &anonymous)));

        factory.clear_non_core();
        let recreated = factory.get_base(3, TypeMetatype::Unknown).unwrap();
        let recreated_again = factory.get_base(3, TypeMetatype::Unknown).unwrap();
        assert!(!Arc::ptr_eq(&anonymous, &recreated));
        assert!(Arc::ptr_eq(&recreated, &recreated_again));
    }

    #[test]
    fn test_named_unknown_rejects_conflicting_definition() {
        let mut factory = TypeFactory::new(8);
        let first = factory
            .get_base_named(3, TypeMetatype::Unknown, "fixture_unknown3")
            .unwrap();
        let repeated = factory
            .get_base_named(3, TypeMetatype::Unknown, "fixture_unknown3")
            .unwrap();
        assert!(Arc::ptr_eq(&first, &repeated));
        assert_eq!(first.get_id(), Datatype::hash_name("fixture_unknown3"));
        assert_eq!(
            factory
                .get_base_named(4, TypeMetatype::Unknown, "fixture_unknown3")
                .unwrap_err(),
            "Trying to alter definition of type: fixture_unknown3"
        );
    }

    #[test]
    fn test_core_cache_uses_ordered_identity_not_names() {
        let mut factory = TypeFactory::new(8);
        factory.clear();

        let plain_a = factory.set_core_type("plain_high", 1, TypeMetatype::Int, false);
        let plain_b = factory.set_core_type("aaaaaaaa", 1, TypeMetatype::Int, false);
        let uint_a = factory.set_core_type("unsigned_custom_a", 1, TypeMetatype::Uint, false);
        let uint_b = factory.set_core_type("unsigned_custom_b", 1, TypeMetatype::Uint, false);
        let ascii = factory.set_core_type("custom_ascii_glyph", 1, TypeMetatype::Int, true);
        factory.cache_core_types();

        let preferred = factory
            .get_base(1, TypeMetatype::Int)
            .expect("preferred signed byte");
        assert!(Arc::ptr_eq(&preferred, &ascii));
        let preferred_char = factory.get_type_char(1).expect("cached char");
        assert!(Arc::ptr_eq(&preferred_char, &ascii));

        let expected_nochar = if plain_a.get_id() > plain_b.get_id() {
            &plain_a
        } else {
            &plain_b
        };
        let nochar = factory
            .get_base_no_char(1, TypeMetatype::Int)
            .expect("non-character signed byte");
        assert!(Arc::ptr_eq(&nochar, expected_nochar));

        let expected_uint = if uint_a.get_id() < uint_b.get_id() {
            &uint_a
        } else {
            &uint_b
        };
        let preferred_uint = factory
            .get_base(1, TypeMetatype::Uint)
            .expect("preferred unsigned byte");
        assert!(Arc::ptr_eq(&preferred_uint, expected_uint));
        assert_eq!(preferred.get_name(), "custom_ascii_glyph");
    }

    #[test]
    fn test_core_cache_repeat_late_plain_and_clear() {
        let mut factory = TypeFactory::new(8);
        factory.clear();

        let first_plain = factory.set_core_type("aaaaaaaa", 1, TypeMetatype::Int, false);
        let ascii = factory.set_core_type("custom_ascii_glyph", 1, TypeMetatype::Int, true);
        factory.cache_core_types();
        let first_preferred = factory.get_base(1, TypeMetatype::Int).unwrap();
        let first_nochar = factory.get_base_no_char(1, TypeMetatype::Int).unwrap();
        assert!(Arc::ptr_eq(&first_preferred, &ascii));
        assert!(Arc::ptr_eq(&first_nochar, &first_plain));

        factory.cache_core_types();
        assert!(Arc::ptr_eq(
            &first_preferred,
            &factory.get_base(1, TypeMetatype::Int).unwrap()
        ));
        assert!(Arc::ptr_eq(
            &first_nochar,
            &factory.get_base_no_char(1, TypeMetatype::Int).unwrap()
        ));

        let late_plain = factory.set_core_type("zzzzzzzz", 1, TypeMetatype::Int, false);
        assert!(late_plain.get_id() > first_plain.get_id());
        factory.cache_core_types();
        assert!(Arc::ptr_eq(
            &ascii,
            &factory.get_base(1, TypeMetatype::Int).unwrap()
        ));
        assert!(Arc::ptr_eq(
            &late_plain,
            &factory.get_base_no_char(1, TypeMetatype::Int).unwrap()
        ));

        factory.clear();
        factory.clear();
        assert!(factory.find_by_name("custom_ascii_glyph").is_none());
        let post_clear = factory.set_core_type("post_clear_plain", 1, TypeMetatype::Int, false);
        factory.cache_core_types();
        assert!(Arc::ptr_eq(
            &post_clear,
            &factory.get_base(1, TypeMetatype::Int).unwrap()
        ));
        assert!(Arc::ptr_eq(
            &post_clear,
            &factory.get_base_no_char(1, TypeMetatype::Int).unwrap()
        ));
    }

    // ---- data_organization / alignment-map state (oracle-verified numbers
    // ---- come from tests/oracle/cspec_typeorg_state_1204; these are the
    // ---- Rust regression mirrors).

    use crate::marshal::{Element, IdRegistry, TreeDecoder};

    fn elem_node(name: &str, attrs: &[(&str, &str)]) -> Arc<RwLock<Element>> {
        let mut el = Element::new();
        el.set_name(name);
        for (k, v) in attrs {
            el.add_attribute(k, v);
        }
        Arc::new(RwLock::new(el))
    }

    fn decoder_over(root: Arc<RwLock<Element>>) -> TreeDecoder {
        TreeDecoder::new(root, Arc::new(RwLock::new(IdRegistry::new())))
    }

    fn data_org_node(children: Vec<Arc<RwLock<Element>>>) -> Arc<RwLock<Element>> {
        let root = elem_node("data_organization", &[]);
        {
            let mut rg = root.write().unwrap();
            for child in children {
                rg.add_child(child);
            }
        }
        root
    }

    fn size_node(name: &str, value: &str) -> Arc<RwLock<Element>> {
        elem_node(name, &[("value", value)])
    }

    fn entry_node(size: &str, alignment: &str) -> Arc<RwLock<Element>> {
        elem_node("entry", &[("size", size), ("alignment", alignment)])
    }

    fn align_probe(factory: &TypeFactory, sizes: &[u32]) -> Vec<i32> {
        sizes
            .iter()
            .map(|&sz| factory.get_alignment(sz).unwrap())
            .collect()
    }

    #[test]
    fn test_data_organization_persists_sizes_and_skips_unknown_children() {
        let mut factory = TypeFactory::new(8);
        let root = data_org_node(vec![
            size_node("machine_alignment", "2"), // not consumed: skipped
            size_node("pointer_size", "8"),
            size_node("wchar_size", "4"),
            size_node("short_size", "2"), // not consumed: skipped
            size_node("integer_size", "4"),
            size_node("long_size", "8"),
            size_node("float_size", "4"), // not consumed: skipped
        ]);
        let snapshot = factory.decode_data_organization(&mut decoder_over(root));
        // Production x86-64-gcc.cspec values (no char_size element: stays 0).
        assert_eq!(snapshot.size_of_int, 4);
        assert_eq!(snapshot.size_of_long, 8);
        assert_eq!(snapshot.size_of_pointer, 8);
        assert_eq!(snapshot.size_of_char, 0);
        assert_eq!(snapshot.size_of_wchar, 4);
        assert_eq!(factory.get_size_of_int(), 4);
        assert_eq!(factory.get_size_of_long(), 8);
        assert_eq!(factory.get_size_of_char(), 0);
        assert_eq!(factory.get_size_of_wchar(), 4);
        assert_eq!(factory.get_size_of_pointer(), 8);
        assert_eq!(factory.get_size_of_alt_pointer(), 0);
    }

    #[test]
    fn test_alignment_map_sparse_fill_leaves_index0_minus1() {
        let mut factory = TypeFactory::new(8);
        let map = elem_node("size_alignment_map", &[]);
        {
            let mut rg = map.write().unwrap();
            rg.add_child(entry_node("1", "1"));
            rg.add_child(entry_node("2", "2"));
            rg.add_child(entry_node("4", "4"));
            rg.add_child(entry_node("8", "8"));
            rg.add_child(entry_node("16", "16"));
        }
        let root = data_org_node(vec![map]);
        let observed = factory.decode_data_organization(&mut decoder_over(root));
        assert_eq!(observed.size_of_int, 0); // sizes untouched by map-only doc
        // Forward-fill semantics: index 0 keeps -1, 3<-2, 5..7<-4, 9..15<-8.
        assert_eq!(
            align_probe(&factory, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17]),
            vec![-1, 1, 2, 2, 4, 4, 4, 4, 8, 8, 8, 16, 16]
        );
    }

    #[test]
    fn test_alignment_map_empty_stays_empty_until_setup_sizes() {
        let mut factory = TypeFactory::new(8);
        let root = data_org_node(vec![elem_node("size_alignment_map", &[])]);
        factory.decode_data_organization(&mut decoder_over(root));
        // decodeAlignmentMap installs nothing; getAlignment raises the oracle
        // LowlevelError text.
        assert_eq!(
            factory.get_alignment(1).unwrap_err(),
            "TypeFactory alignment map not initialized"
        );
        factory.setup_sizes(&SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        // setDefaultAlignmentMap: resize(9,0) then slots 1..=8 — index 0 is 0.
        assert_eq!(
            align_probe(&factory, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            vec![0, 1, 2, 2, 4, 4, 4, 4, 8, 8]
        );
    }

    #[test]
    fn test_alignment_map_explicit_zero_entry_and_duplicate_wins() {
        let mut factory = TypeFactory::new(8);
        let map = elem_node("size_alignment_map", &[]);
        {
            let mut rg = map.write().unwrap();
            rg.add_child(entry_node("0", "1"));
            rg.add_child(entry_node("2", "2"));
            rg.add_child(entry_node("8", "8"));
            rg.add_child(entry_node("8", "4")); // duplicate size: later wins
            rg.add_child(entry_node("5", "0")); // explicit zero alignment
        }
        let root = data_org_node(vec![map]);
        factory.decode_data_organization(&mut decoder_over(root));
        // Fill: 1<-1, 3..4<-2, 6..7<-0, 8 stays 4 (duplicate winner).
        assert_eq!(
            align_probe(&factory, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            vec![1, 1, 2, 2, 2, 0, 0, 0, 4, 4]
        );
    }

    #[test]
    fn test_setup_sizes_derives_defaults_from_arch_inputs() {
        let mut factory = TypeFactory::new(8);
        // Only char_size present: everything else derives (type.cc:3137-3170).
        let root = data_org_node(vec![size_node("char_size", "3")]);
        factory.decode_data_organization(&mut decoder_over(root));
        factory.setup_sizes(&SizeArchInputs {
            stack_spacebase_size: Some(8), // stack pointer is 8 -> clamp to 4
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        assert_eq!(factory.get_size_of_int(), 4);
        assert_eq!(factory.get_size_of_long(), 8); // (int==4) ? 8 : int
        assert_eq!(factory.get_size_of_char(), 3); // already set: untouched
        assert_eq!(factory.get_size_of_wchar(), 2);
        assert_eq!(factory.get_size_of_pointer(), 8);
        assert_eq!(factory.get_size_of_alt_pointer(), 0);

        // int != 4 branch: sizeOfLong copies sizeOfInt instead of becoming 8.
        let mut factory2 = TypeFactory::new(8);
        let root2 = data_org_node(vec![size_node("integer_size", "2")]);
        factory2.decode_data_organization(&mut decoder_over(root2));
        factory2.setup_sizes(&SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        assert_eq!(factory2.get_size_of_int(), 2);
        assert_eq!(factory2.get_size_of_long(), 2);

        // No stack space: sizeOfInt keeps the literal fallback 1.
        let mut factory3 = TypeFactory::new(8);
        factory3.setup_sizes(&SizeArchInputs {
            stack_spacebase_size: None,
            default_data_space_addr_size: 4,
            default_size: 4,
            far_pointer: Some((2, 2)),
        });
        assert_eq!(factory3.get_size_of_int(), 1);
        assert_eq!(factory3.get_size_of_long(), 1);
        assert_eq!(factory3.get_size_of_pointer(), 2); // far-pointer override
        assert_eq!(factory3.get_size_of_alt_pointer(), 4); // inner + base
    }

    #[test]
    fn test_data_organization_consumes_children_after_alignment_map() {
        // Reviewer probe (CSPEC-TYPEORG-STATE-0001 rework): Ghidra's sam
        // branch falls through to closeElement(subId) (type.cc:4604-4612),
        // so children AFTER <size_alignment_map> are still consumed. A
        // missing close would leave the TreeDecoder stack on the sam
        // element, break the loop early, and silently drop them.
        let mut factory = TypeFactory::new(8);
        let map = elem_node("size_alignment_map", &[]);
        {
            let mut rg = map.write().unwrap();
            rg.add_child(entry_node("1", "1"));
        }
        let root = data_org_node(vec![map, size_node("char_size", "3")]);
        let snapshot = factory.decode_data_organization(&mut decoder_over(root));
        assert_eq!(snapshot.size_of_char, 3);
        assert_eq!(factory.get_size_of_char(), 3);
        assert_eq!(factory.get_alignment(1).unwrap(), 1);
    }

    #[test]
    fn test_primitive_align_size_pads_like_sizeof() {
        let mut factory = TypeFactory::new(8);
        let map = elem_node("size_alignment_map", &[]);
        {
            let mut rg = map.write().unwrap();
            rg.add_child(entry_node("1", "1"));
            rg.add_child(entry_node("2", "2"));
            rg.add_child(entry_node("4", "4"));
        }
        let root = data_org_node(vec![map]);
        factory.decode_data_organization(&mut decoder_over(root));
        assert_eq!(factory.get_primitive_align_size(1).unwrap(), 1);
        assert_eq!(factory.get_primitive_align_size(2).unwrap(), 2);
        assert_eq!(factory.get_primitive_align_size(3).unwrap(), 4);
        assert_eq!(factory.get_primitive_align_size(4).unwrap(), 4);
        assert_eq!(factory.get_primitive_align_size(5).unwrap(), 8); // 5%4=1 -> +3
        assert_eq!(factory.get_primitive_align_size(7).unwrap(), 8);
        assert_eq!(factory.get_primitive_align_size(8).unwrap(), 8); // align 4
    }
}
