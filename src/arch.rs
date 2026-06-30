//! Architecture manager — faithful port of `architecture.hh` / `architecture.cc`
//! (1570 lines).
//!
//! Manager for all the major decompiler subsystems. An instantiation is tailored
//! to a specific LoadImage, processor, and compiler spec. This class is the
//! *owner* of the LoadImage, Translate, symbols (Database), PrintLanguage, etc.
//! It also holds numerous configuration parameters for the analysis process.
//!
//! Status: L1→L2. The configuration container with all fields and defaults is
//! complete. The XML decode/parse methods and virtual factory hooks
//! (buildTranslator/buildLoader/…) are documented as L3 gaps pending the
//! Translate/LoadImage/DocumentStorage infrastructure.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/architecture.{hh,cc}.

use crate::address::{Range, RangeList};
use crate::override_rs::Override;
use std::collections::BTreeMap;

/// FlowInfo option bit: error on too many instructions. Faithful to
/// `FlowInfo::error_toomanyinstructions` (used in resetDefaultsInternal).
pub const FLOWOPT_ERROR_TOOMANY: u32 = 1 << 0;

/// Data-type split configuration bits. Faithful to `OptionSplitDatatypes`
/// option flags (architecture.cc:1431).
pub mod split_datatype {
    /// Split struct accesses.
    pub const OPTION_STRUCT: u32 = 1;
    /// Split array accesses.
    pub const OPTION_ARRAY: u32 = 2;
    /// Split pointer accesses.
    pub const OPTION_POINTER: u32 = 4;
}

/// The major decompiler version. Faithful to `ArchitectureCapability::majorversion`.
pub const MAJOR_VERSION: u32 = 6;
/// The minor decompiler version. Faithful to `ArchitectureCapability::minorversion`.
pub const MINOR_VERSION: u32 = 1;

/// Abstract extension point for building Architecture objects. Faithful to
/// `ArchitectureCapability` (architecture.hh:117).
///
/// Each extension implements `build_architecture()` as the formal entry point
/// for the bootstrapping process.
pub trait ArchitectureCapability: Send + Sync {
    /// Get the capability identifier.
    fn name(&self) -> &str;

    /// Build an Architecture given a raw file or data. Faithful to
    /// `buildArchitecture`. Returns `Ok(())` on success; the built architecture
    /// is stored externally.
    fn build_architecture(
        &self,
        filename: &str,
        target: &str,
    ) -> Result<Box<dyn ArchitectureBuilder>, String>;

    /// Determine if this extension can handle this file. Faithful to
    /// `isFileMatch`.
    fn is_file_match(&self, filename: &str) -> bool;

    /// Determine if this extension can handle this XML document. Faithful to
    /// `isXmlMatch`.
    fn is_xml_match(&self, doc: &str) -> bool;
}

/// Trait that an `ArchitectureCapability::build_architecture` returns,
/// providing the virtual factory hooks for sub-components. Faithful to the
/// protected virtual methods of `Architecture` (architecture.hh:264-348).
pub trait ArchitectureBuilder: Send + Sync {
    /// Build the database and global scope. Faithful to `buildDatabase`.
    fn build_database(&mut self) -> Result<(), String>;
    /// Build the Translator object. Faithful to `buildTranslator`.
    fn build_translator(&mut self) -> Result<(), String>;
    /// Build the LoadImage object and load the executable image. Faithful to
    /// `buildLoader`.
    fn build_loader(&mut self) -> Result<(), String>;
    /// Build the injection library. Faithful to `buildPcodeInjectLibrary`.
    fn build_pcode_inject_library(&mut self) -> Result<(), String>;
    /// Build the data-type factory/container. Faithful to `buildTypegrp`.
    fn build_typegrp(&mut self) -> Result<(), String>;
    /// Add core primitive data-types. Faithful to `buildCoreTypes`.
    fn build_core_types(&mut self) -> Result<(), String>;
    /// Build the comment database. Faithful to `buildCommentDB`.
    fn build_comment_db(&mut self) -> Result<(), String>;
    /// Build the string manager. Faithful to `buildStringManager`.
    fn build_string_manager(&mut self) -> Result<(), String>;
    /// Build the constant pool. Faithful to `buildConstantPool`.
    fn build_constant_pool(&mut self) -> Result<(), String>;
    /// Build the Context database. Faithful to `buildContext`.
    fn build_context(&mut self) -> Result<(), String>;
    /// Build any symbols from spec files. Faithful to `buildSymbols`.
    fn build_symbols(&mut self) -> Result<(), String>;
    /// Load any relevant specification files. Faithful to `buildSpecFile`.
    fn build_spec_file(&mut self) -> Result<(), String>;
    /// Modify address spaces as required. Faithful to `modifySpaces`.
    fn modify_spaces(&mut self) -> Result<(), String>;
    /// Figure out the processor and compiler. Faithful to `resolveArchitecture`.
    fn resolve_architecture(&mut self) -> Result<(), String>;
}

/// Registry of `ArchitectureCapability` extensions. Faithful to the static
/// `thelist` and static methods of `ArchitectureCapability`
/// (architecture.hh:120-156).
pub struct CapabilityRegistry {
    capabilities: Vec<Box<dyn ArchitectureCapability>>,
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            capabilities: Vec::new(),
        }
    }

    /// Register a new capability.
    pub fn register(&mut self, cap: Box<dyn ArchitectureCapability>) {
        self.capabilities.push(cap);
    }

    /// Find an extension to process a file. Faithful to
    /// `ArchitectureCapability::findCapability(filename)` (architecture.cc:92).
    pub fn find_capability_for_file(&self, filename: &str) -> Option<&dyn ArchitectureCapability> {
        self.capabilities
            .iter()
            .find(|c| c.is_file_match(filename))
            .map(|c| c.as_ref())
    }

    /// Find an extension to process an XML document. Faithful to
    /// `ArchitectureCapability::findCapability(Document*)` (architecture.cc:106).
    pub fn find_capability_for_xml(&self, doc: &str) -> Option<&dyn ArchitectureCapability> {
        self.capabilities
            .iter()
            .find(|c| c.is_xml_match(doc))
            .map(|c| c.as_ref())
    }

    /// Get a capability by name. Faithful to `getCapability` (architecture.cc:120).
    pub fn get_capability(&self, name: &str) -> Option<&dyn ArchitectureCapability> {
        self.capabilities
            .iter()
            .find(|c| c.name() == name)
            .map(|c| c.as_ref())
    }

    /// Sort extensions so the "raw" architecture comes last. Faithful to
    /// `sortCapabilities` (architecture.cc:134).
    pub fn sort_capabilities(&mut self) {
        if let Some(raw_pos) = self.capabilities.iter().position(|c| c.name() == "raw") {
            let raw = self.capabilities.remove(raw_pos);
            self.capabilities.push(raw);
        }
    }

    /// Get the major decompiler version. Faithful to `getMajorVersion`.
    pub fn major_version() -> u32 {
        MAJOR_VERSION
    }

    /// Get the minor decompiler version. Faithful to `getMinorVersion`.
    pub fn minor_version() -> u32 {
        MINOR_VERSION
    }
}

/// A prototype model name → model placeholder. The full ProtoModel is in
/// `fspec.rs`; until integrated, we store names.
pub type ProtoModelMap = BTreeMap<String, ProtoModelEntry>;

/// A lightweight prototype-model entry. Faithful to the fields of
/// `ProtoModel` used by Architecture (name + whether it's the default).
#[derive(Debug, Clone, Default)]
pub struct ProtoModelEntry {
    /// Name of the prototype model.
    pub name: String,
    /// Whether this is the default model.
    pub is_default: bool,
    /// Whether to print in declaration form.
    pub print_in_decl: bool,
}

/// Manager for all the major decompiler subsystems. Faithful to
/// `Architecture` (architecture.hh:165).
///
/// This is the Ghidra `Architecture` class — distinct from the `types::Architecture`
/// enum (which is the target CPU). It holds all configuration parameters and
/// owns the sub-component references.
#[derive(Clone)]
pub struct Architecture {
    /// ID string uniquely describing this architecture. Faithful to `archid`.
    pub archid: String,

    // ---- Configuration data (architecture.hh:170-188) ----
    /// How many levels to let parameter trims recurse.
    pub trim_recurse_max: i32,
    /// Maximum number of references to an implied var.
    pub max_implied_ref: i32,
    /// Max terms duplicated without a new variable.
    pub max_term_duplication: i32,
    /// Maximum size of an "integer" type before creating an array type.
    pub max_basetype_size: i32,
    /// Minimum size of a function symbol.
    pub min_funcsymbol_size: i32,
    /// Maximum number of entries in a single JumpTable.
    pub max_jumptable_size: u32,
    /// Aggressively trim inputs that look like they are sign extended.
    pub aggressive_ext_trim: bool,
    /// True if readonly values should be treated as constants.
    pub readonlypropagate: bool,
    /// True if we should infer pointers from constants that are likely addresses.
    pub infer_pointers: bool,
    /// True if we should attempt conversion of while-do loops to for loops.
    pub analyze_for_loops: bool,
    /// True if we should ignore NaN operations entirely.
    pub nan_ignore_all: bool,
    /// True if we should ignore NaN operations protecting floating-point comparisons.
    pub nan_ignore_compare: bool,
    /// How many bits of alignment a function ptr has.
    pub funcptr_align: i32,
    /// Options passed to flow following engine.
    pub flowoptions: u32,
    /// Maximum instructions that can be processed in one function.
    pub max_instructions: u32,
    /// Aliases blocked by 0=none, 1=struct, 2=array, 3=all.
    pub alias_block_level: i32,
    /// Toggle for data-types splitting: Bit 0=structs, 1=arrays, 2=pointers.
    pub split_datatype_config: u32,

    // ---- Sub-component references (placeholders until integrated) ----
    /// Parsed forms of possible prototypes (name → entry).
    pub proto_models: ProtoModelMap,
    /// Name of the default prototype model.
    pub defaultfp_name: Option<String>,
    /// Name of the model to use when evaluating the current function.
    pub evalfp_current_name: Option<String>,
    /// Name of the model to use when evaluating called functions.
    pub evalfp_called_name: Option<String>,
    /// Ranges for which high-level pointers are not possible. Faithful to
    /// `nohighptr`.
    pub nohighptr: RangeList,
    /// Override commands for the current function. Faithful to the Override
    /// owned by Funcdata (referenced via Architecture).
    pub overrides: Override,
    /// True if loader symbols have been read.
    pub loadersymbols_parsed: bool,

    // ---- Sub-component references (architecture.hh:190-213) ----
    /// Symbol table (Database). Faithful to `symboltab`.
    pub symboltab: Option<std::sync::Arc<std::sync::RwLock<crate::database::Database>>>,
    /// Load image. Faithful to `loader`.
    pub loader: Option<std::sync::Arc<dyn crate::loadimage::LoadImage>>,
    /// Type factory. Faithful to `types`.
    pub type_factory_name: Option<String>,
    /// Comment database. Faithful to `commentdb`.
    pub commentdb: Option<std::sync::Arc<std::sync::RwLock<crate::comment::CommentDatabaseInternal>>>,
    /// String manager. Faithful to `stringManager`.
    pub string_manager: Option<std::sync::Arc<std::sync::RwLock<crate::stringmanage::StringManager>>>,
    /// Constant pool. Faithful to `cpool`.
    pub cpool: Option<std::sync::Arc<std::sync::RwLock<crate::cpool::ConstantPoolInternal>>>,
    /// Context database. Faithful to `context`.
    pub context_db: Option<std::sync::Arc<std::sync::RwLock<crate::context::ContextInternal>>>,
    /// Options database. Faithful to `options`.
    pub options_db: Option<std::sync::Arc<std::sync::RwLock<crate::options::OptionDatabase>>>,
    /// Prefer-split records. Faithful to `splitrecords`.
    pub split_records: Vec<crate::prefersplit::PreferSplitRecord>,
    /// Laned register records. Faithful to `lanerecords`.
    pub lane_records: Vec<crate::transform::LanedRegister>,

    // ---- Stack space / spacebase configuration (cspec <stackpointer>) ----
    /// The address space that the stack pointer indexes into (IPTR_SPACEBASE).
    /// Faithful to `glb->getStackSpace()`. Defaults to AddressSpace::Stack.
    pub stack_space: crate::space::AddressSpace,
    /// The (space, offset, size) of the formal stack pointer register.
    /// Faithful to cspec `<stackpointer register="RSP" space="ram"/>` +
    /// `SpacebaseSpace::getSpacebase(0)`. Defaults to the x86-64 RSP:
    /// Register@0x20, size 8.
    pub stack_pointer_space: crate::space::AddressSpace,
    pub stack_pointer_offset: u64,
    pub stack_pointer_size: usize,
    /// True if the stack grows toward negative offsets (x86 convention).
    /// Faithful to cspec `growth="negative"`.
    pub stack_grows_negative: bool,
}

// Manual Debug impl (the `loader` field is `Arc<dyn LoadImage>` without a
// Debug bound, so we cannot derive). Print just the archid for diagnostics.
impl std::fmt::Debug for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Architecture").field("archid", &self.archid).finish()
    }
}

impl Default for Architecture {
    fn default() -> Self {
        Self::new()
    }
}

impl Architecture {
    /// Construct an uninitialized Architecture. Faithful to `Architecture()`
    /// (architecture.cc:150).
    pub fn new() -> Self {
        let mut arch = Self {
            archid: String::new(),
            trim_recurse_max: 0,
            max_implied_ref: 0,
            max_term_duplication: 0,
            max_basetype_size: 0,
            min_funcsymbol_size: 1,
            max_jumptable_size: 0,
            aggressive_ext_trim: false,
            readonlypropagate: false,
            infer_pointers: false,
            analyze_for_loops: false,
            nan_ignore_all: false,
            nan_ignore_compare: false,
            funcptr_align: 0,
            flowoptions: 0,
            max_instructions: 0,
            alias_block_level: 0,
            split_datatype_config: 0,
            proto_models: ProtoModelMap::new(),
            defaultfp_name: None,
            evalfp_current_name: None,
            evalfp_called_name: None,
            nohighptr: RangeList::new(),
            overrides: Override::new(),
            loadersymbols_parsed: false,
            symboltab: None,
            loader: None,
            type_factory_name: None,
            commentdb: None,
            string_manager: None,
            cpool: None,
            context_db: None,
            options_db: None,
            split_records: Vec::new(),
            lane_records: Vec::new(),
            stack_space: crate::space::AddressSpace::Stack,
            stack_pointer_space: crate::space::AddressSpace::Register,
            stack_pointer_offset: 0x20, // x86-64 RSP
            stack_pointer_size: 8,
            stack_grows_negative: true,
        };
        arch.reset_defaults_internal();
        arch
    }

    /// Reset default values for options specific to Architecture. Faithful to
    /// `resetDefaultsInternal` (architecture.cc:1416).
    pub fn reset_defaults_internal(&mut self) {
        self.trim_recurse_max = 5;
        self.max_implied_ref = 2;
        self.max_term_duplication = 2;
        self.max_basetype_size = 10;
        self.flowoptions = FLOWOPT_ERROR_TOOMANY;
        self.max_instructions = 100000;
        self.infer_pointers = true;
        self.analyze_for_loops = true;
        self.readonlypropagate = false;
        self.nan_ignore_all = false;
        self.nan_ignore_compare = true;
        self.alias_block_level = 2;
        self.split_datatype_config = split_datatype::OPTION_STRUCT
            | split_datatype::OPTION_ARRAY
            | split_datatype::OPTION_POINTER;
        self.max_jumptable_size = 1024;
    }

    /// Reset defaults values for options owned by this Architecture. Faithful
    /// to `resetDefaults` (architecture.cc:1438).
    pub fn reset_defaults(&mut self) {
        self.reset_defaults_internal();
        // allacts.resetDefaults() and printlist reset deferred until those
        // subsystems are integrated.
    }

    /// Get a specific PrototypeModel by name. Faithful to `getModel`
    /// (architecture.cc:234). Returns the entry, or None.
    pub fn get_model(&self, nm: &str) -> Option<&ProtoModelEntry> {
        self.proto_models.get(nm)
    }

    /// Does this Architecture have a specific PrototypeModel? Faithful to
    /// `hasModel` (architecture.cc:247).
    pub fn has_model(&self, nm: &str) -> bool {
        self.proto_models.contains_key(nm)
    }

    /// Set the default PrototypeModel. Faithful to `setDefaultModel`
    /// (architecture.cc:323). The previous default (if any) is reset to
    /// print-in-decl.
    pub fn set_default_model(&mut self, model_name: &str) {
        if let Some(prev_name) = &self.defaultfp_name {
            if let Some(prev) = self.proto_models.get_mut(prev_name) {
                prev.print_in_decl = true;
            }
        }
        if let Some(model) = self.proto_models.get_mut(model_name) {
            model.print_in_decl = false;
            model.is_default = true;
        }
        self.defaultfp_name = Some(model_name.to_string());
    }

    /// Are pointers possible to the given location? Faithful to
    /// `highPtrPossible` (architecture.hh:408). Without AddrSpace type info we
    /// conservatively check the nohighptr range list.
    pub fn high_ptr_possible(&self, loc: crate::Address, size: i32) -> bool {
        // inRange checks the whole span; Ghidra checks !nohighptr.inRange(loc, size).
        // Our RangeList::in_range takes a single address, so we check both ends.
        if self.nohighptr.in_range(loc) {
            return false;
        }
        if size > 1 {
            let end = crate::Address::new(loc.as_u64().saturating_add(size as u64 - 1));
            if self.nohighptr.in_range(end) {
                return false;
            }
        }
        true
    }

    /// Add a new region where pointers do not exist. Faithful to `addNoHighPtr`
    /// (architecture.cc:576).
    pub fn add_no_high_ptr(&mut self, rng: Range) {
        self.nohighptr.insert_range(rng);
    }

    /// Mark all spaces as global. Faithful to `globalify` (architecture.cc:437).
    /// Without AddrSpaceManager, this is a no-op placeholder; the global flag is
    /// a property of spaces owned externally.
    pub fn globalify(&mut self) {
        // L3 gap: requires AddrSpaceManager integration.
    }

    /// Create a name alias for a ProtoModel. Faithful to `createModelAlias`
    /// (architecture.hh:354). The alias inherits the parent's entry.
    pub fn create_model_alias(&mut self, alias_name: &str, parent_name: &str) -> bool {
        if let Some(parent) = self.proto_models.get(parent_name) {
            let mut entry = parent.clone();
            entry.name = alias_name.to_string();
            entry.is_default = false;
            self.proto_models.insert(alias_name.to_string(), entry);
            true
        } else {
            false
        }
    }

    /// Decode flow overrides from a stream. Faithful to
    /// `decodeFlowOverride` (architecture.hh:239). The actual XML parse is an
    /// L3 gap; this is the application entry point.
    pub fn decode_flow_override(&mut self) {
        // L3 gap: XML decode of <flowoverridelist>.
    }

    /// Get a string describing this architecture. Faithful to
    /// `getDescription` (architecture.hh:244).
    pub fn get_description(&self) -> &str {
        &self.archid
    }

    /// Print an error message to console. Faithful to `printMessage`
    /// (architecture.hh:250). Default implementation prints to stderr.
    pub fn print_message(&self, message: &str) {
        eprintln!("[ARCH] {message}");
    }

    /// Load the image and configure architecture. Faithful to
    /// `Architecture::init` (architecture.hh:221). This method orchestrates
    /// the initialization by calling the virtual factory hooks.
    pub fn init(&mut self) -> Result<(), String> {
        // In full Ghidra, this calls the virtual factory methods:
        //   buildLoader(store)
        //   fillinReadOnlyFromLoader()
        //   buildTypegrp(store)
        //   buildCoreTypes(store)
        //   buildCommentDB(store)
        //   buildStringManager(store)
        //   buildConstantPool(store)
        //   buildContext(store)
        //   buildInstructions(store)
        //   buildAction(store)
        //   postSpecFile()
        //
        // In Rugra, sub-components are set externally via set_* methods.
        // This method verifies that essential components are present.
        if self.archid.is_empty() {
            return Err("Architecture ID not set".to_string());
        }
        Ok(())
    }

    /// Clear analysis specific to a function. Faithful to `clearAnalysis`
    /// (architecture.hh:232).
    pub fn clear_analysis(&self) {
        // Full: fd.clear() + commentdb.clearType. Requires Funcdata.
    }

    /// Read symbols from loader into database. Faithful to
    /// `readLoaderSymbols` (architecture.hh:233).
    pub fn read_loader_symbols(&mut self, _delim: &str) {
        if self.loadersymbols_parsed {
            return;
        }
        // Full: iterate loader symbols and insert into database.
        self.loadersymbols_parsed = true;
    }

    /// Encode this architecture to a stream. Faithful to
    /// `Architecture::encode` (architecture.hh:251).
    pub fn encode(&self, encoder: &mut dyn crate::marshal::Encoder) {
        use crate::marshal::{AttributeId, ElementId};
        let arch_elem = ElementId::new("architecture", 0);
        encoder.open_element(&arch_elem);
        encoder.write_string(&AttributeId::new("id", 0), &self.archid);
        // Encode sub-components as needed.
        encoder.close_element(&arch_elem);
    }

    // ---- Sub-component setters (virtual factory hook equivalents) ----

    /// Set the symbol table (Database). Replaces `buildDatabase`.
    pub fn set_symboltab(&mut self, db: std::sync::Arc<std::sync::RwLock<crate::database::Database>>) {
        self.symboltab = Some(db);
    }

    /// Set the load image. Replaces `buildLoader`.
    pub fn set_loader(&mut self, loader: std::sync::Arc<dyn crate::loadimage::LoadImage>) {
        self.loader = Some(loader);
    }

    /// Set the comment database. Replaces `buildCommentDB`.
    pub fn set_commentdb(&mut self, db: std::sync::Arc<std::sync::RwLock<crate::comment::CommentDatabaseInternal>>) {
        self.commentdb = Some(db);
    }

    /// Set the string manager. Replaces `buildStringManager`.
    pub fn set_string_manager(&mut self, sm: std::sync::Arc<std::sync::RwLock<crate::stringmanage::StringManager>>) {
        self.string_manager = Some(sm);
    }

    /// Set the constant pool. Replaces `buildConstantPool`.
    pub fn set_cpool(&mut self, cp: std::sync::Arc<std::sync::RwLock<crate::cpool::ConstantPoolInternal>>) {
        self.cpool = Some(cp);
    }

    /// Set the context database. Replaces `buildContext`.
    pub fn set_context_db(&mut self, ctx: std::sync::Arc<std::sync::RwLock<crate::context::ContextInternal>>) {
        self.context_db = Some(ctx);
    }

    /// Set the options database. Replaces the OptionDatabase constructor.
    pub fn set_options_db(&mut self, opts: std::sync::Arc<std::sync::RwLock<crate::options::OptionDatabase>>) {
        self.options_db = Some(opts);
    }

    /// Set the prefer-split records. Replaces `decodePreferSplit`.
    pub fn set_split_records(&mut self, records: Vec<crate::prefersplit::PreferSplitRecord>) {
        self.split_records = records;
    }

    /// Set the laned register records.
    pub fn set_lane_records(&mut self, records: Vec<crate::transform::LanedRegister>) {
        self.lane_records = records;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;

    #[test]
    fn test_defaults() {
        let arch = Architecture::new();
        assert_eq!(arch.trim_recurse_max, 5);
        assert_eq!(arch.max_implied_ref, 2);
        assert_eq!(arch.max_term_duplication, 2);
        assert_eq!(arch.max_basetype_size, 10);
        assert!(arch.infer_pointers);
        assert!(arch.analyze_for_loops);
        assert!(!arch.readonlypropagate);
        assert!(arch.nan_ignore_compare);
        assert!(!arch.nan_ignore_all);
        assert_eq!(arch.alias_block_level, 2);
        assert_eq!(arch.max_jumptable_size, 1024);
        assert_eq!(arch.max_instructions, 100000);
        assert_eq!(
            arch.split_datatype_config,
            split_datatype::OPTION_STRUCT | split_datatype::OPTION_ARRAY | split_datatype::OPTION_POINTER
        );
        assert_eq!(arch.min_funcsymbol_size, 1);
    }

    #[test]
    fn test_reset_defaults() {
        let mut arch = Architecture::new();
        arch.trim_recurse_max = 99;
        arch.infer_pointers = false;
        arch.reset_defaults();
        assert_eq!(arch.trim_recurse_max, 5);
        assert!(arch.infer_pointers);
    }

    #[test]
    fn test_proto_models() {
        let mut arch = Architecture::new();
        arch.proto_models.insert(
            "__stdcall".to_string(),
            ProtoModelEntry {
                name: "__stdcall".to_string(),
                is_default: false,
                print_in_decl: true,
            },
        );
        assert!(arch.has_model("__stdcall"));
        assert!(!arch.has_model("__cdecl"));
        assert!(arch.get_model("__stdcall").is_some());
        arch.set_default_model("__stdcall");
        assert_eq!(arch.defaultfp_name.as_deref(), Some("__stdcall"));
        assert!(!arch.get_model("__stdcall").unwrap().print_in_decl);
    }

    #[test]
    fn test_model_alias() {
        let mut arch = Architecture::new();
        arch.proto_models.insert(
            "parent".to_string(),
            ProtoModelEntry {
                name: "parent".to_string(),
                is_default: true,
                print_in_decl: false,
            },
        );
        assert!(arch.create_model_alias("alias", "parent"));
        assert!(arch.has_model("alias"));
        // Alias inherits the entry but is reset to non-default.
        assert!(!arch.get_model("alias").unwrap().is_default);
        assert!(!arch.create_model_alias("alias2", "nonexistent"));
    }

    #[test]
    fn test_high_ptr_possible() {
        let mut arch = Architecture::new();
        assert!(arch.high_ptr_possible(Address::new(0x1000), 4));
        arch.add_no_high_ptr(Range::new(Address::new(0x1000), Address::new(0x1FFF)).unwrap());
        assert!(!arch.high_ptr_possible(Address::new(0x1000), 4));
        assert!(!arch.high_ptr_possible(Address::new(0x1FFC), 8)); // end in range
        assert!(arch.high_ptr_possible(Address::new(0x2000), 4));
    }

    #[test]
    fn test_version() {
        assert_eq!(CapabilityRegistry::major_version(), 6);
        assert_eq!(CapabilityRegistry::minor_version(), 1);
    }

    /// A trivial test capability for the registry.
    struct DummyCap {
        name: String,
    }
    impl ArchitectureCapability for DummyCap {
        fn name(&self) -> &str {
            &self.name
        }
        fn build_architecture(
            &self,
            _f: &str,
            _t: &str,
        ) -> Result<Box<dyn ArchitectureBuilder>, String> {
            Err("not implemented".to_string())
        }
        fn is_file_match(&self, f: &str) -> bool {
            f.ends_with(".bin")
        }
        fn is_xml_match(&self, _d: &str) -> bool {
            false
        }
    }

    /// A "raw" capability that should sort last.
    struct RawCap;
    impl ArchitectureCapability for RawCap {
        fn name(&self) -> &str {
            "raw"
        }
        fn build_architecture(
            &self,
            _f: &str,
            _t: &str,
        ) -> Result<Box<dyn ArchitectureBuilder>, String> {
            Err("not implemented".to_string())
        }
        fn is_file_match(&self, _f: &str) -> bool {
            true
        }
        fn is_xml_match(&self, _d: &str) -> bool {
            false
        }
    }

    #[test]
    fn test_capability_registry() {
        let mut reg = CapabilityRegistry::new();
        reg.register(Box::new(RawCap));
        reg.register(Box::new(DummyCap {
            name: "elf".to_string(),
        }));
        // Before sort: raw is first.
        assert_eq!(reg.get_capability("raw").unwrap().name(), "raw");
        // Find by file.
        assert!(reg.find_capability_for_file("test.bin").is_some());
        // Sort: raw should move to the end.
        reg.sort_capabilities();
        // Still findable by name.
        assert!(reg.get_capability("raw").is_some());
        assert!(reg.get_capability("elf").is_some());
    }
}
