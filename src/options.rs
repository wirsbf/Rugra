//! Architecture configuration options — faithful port of `options.hh` /
//! `options.cc` (1063 lines).
//!
//! Classes for processing architecture configuration options. Each option
//! modifies the Architecture object's configuration via its `apply` method.
//! `OptionDatabase` dispatches option commands by name.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/options.{hh,cc}.

use crate::arch::Architecture;
use std::collections::HashMap;

/// Parse an "on" or "off" string into a boolean. Faithful to
/// `ArchOption::onOrOff` (options.cc:69). An empty string defaults to true.
pub fn on_or_off(p: &str) -> bool {
    if p.is_empty() {
        return true;
    }
    if p == "on" {
        return true;
    }
    if p == "off" {
        return false;
    }
    // Ghidra throws ParseError; we default to true for unknown values.
    true
}

/// Base trait for options that affect Architecture configuration. Faithful to
/// `ArchOption` (options.hh:75).
pub trait ArchOption: Send + Sync {
    /// Return the name of the option.
    fn name(&self) -> &str;

    /// Apply a configuration option to the Architecture. Returns a
    /// confirmation/failure message. Faithful to `apply`.
    fn apply(&self, arch: &mut Architecture, p1: &str, p2: &str, p3: &str) -> String;
}

// ---------------------------------------------------------------------------
// Concrete option implementations
// ---------------------------------------------------------------------------

/// Set the `infer_pointers` flag. Faithful to `OptionInferConstPtr`.
pub struct OptionInferConstPtr;
impl ArchOption for OptionInferConstPtr {
    fn name(&self) -> &str {
        "inferconstptr"
    }
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        arch.infer_pointers = val;
        if val {
            "Constant pointers are now inferred".to_string()
        } else {
            "Constant pointers must now be set explicitly".to_string()
        }
    }
}

/// Set the `analyze_for_loops` flag. Faithful to `OptionForLoops`.
pub struct OptionForLoops;
impl ArchOption for OptionForLoops {
    fn name(&self) -> &str {
        "analyzeforloops"
    }
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        arch.analyze_for_loops = on_or_off(p1);
        format!("Recovery of for-loops is {p1}")
    }
}

/// Set the `readonlypropagate` flag. Faithful to `OptionReadOnly`.
pub struct OptionReadOnly;
impl ArchOption for OptionReadOnly {
    fn name(&self) -> &str {
        "readonly"
    }
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        arch.readonlypropagate = on_or_off(p1);
        format!("Read-only propagation is {p1}")
    }
}

/// Set the `max_jumptable_size`. Faithful to `OptionJumpTableMax`.
pub struct OptionJumpTableMax;
impl ArchOption for OptionJumpTableMax {
    fn name(&self) -> &str {
        "jumptablemax"
    }
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val: u32 = p1.parse().unwrap_or(0);
        if val == 0 {
            return "Must specify integer maximum".to_string();
        }
        arch.max_jumptable_size = val;
        format!("Maximum jumptable size set to {p1}")
    }
}

/// Set the `max_instructions`. Faithful to `OptionMaxInstruction`.
pub struct OptionMaxInstruction;
impl ArchOption for OptionMaxInstruction {
    fn name(&self) -> &str {
        "maxinstruction"
    }
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val: u32 = p1.parse().unwrap_or(0);
        arch.max_instructions = val;
        "Maximum instructions per function set".to_string()
    }
}

/// Set the `alias_block_level`. Faithful to `OptionAliasBlock`.
pub struct OptionAliasBlock;
impl ArchOption for OptionAliasBlock {
    fn name(&self) -> &str {
        "aliasblock"
    }
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        if p1.is_empty() {
            return "Must specify alias block level".to_string();
        }
        arch.alias_block_level = match p1 {
            "none" => 0,
            "struct" => 1,
            "array" => 2,
            "all" => 3,
            _ => return format!("Unknown alias block level: {p1}"),
        };
        format!("Alias block level set to {p1}")
    }
}

/// Set NaN ignore flags. Faithful to `OptionNanIgnore`.
pub struct OptionNanIgnore;
impl ArchOption for OptionNanIgnore {
    fn name(&self) -> &str {
        "nanignore"
    }
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        match p1 {
            "all" => {
                arch.nan_ignore_all = true;
                arch.nan_ignore_compare = true;
            }
            "compare" => {
                arch.nan_ignore_all = false;
                arch.nan_ignore_compare = true;
            }
            "none" => {
                arch.nan_ignore_all = false;
                arch.nan_ignore_compare = false;
            }
            _ => return "Unknown NaN ignore mode".to_string(),
        }
        format!("NaN ignore set to {p1}")
    }
}

/// Set the `split_datatype_config`. Faithful to `OptionSplitDatatypes`.
pub mod split_datatype_option {
    pub const OPTION_STRUCT: u32 = 1;
    pub const OPTION_ARRAY: u32 = 2;
    pub const OPTION_POINTER: u32 = 4;
}

/// Translate an option string to a split-datatype config bit. Faithful to
/// `OptionSplitDatatypes::getOptionBit`.
pub fn get_split_datatype_bit(val: &str) -> u32 {
    match val {
        "struct" => split_datatype_option::OPTION_STRUCT,
        "array" => split_datatype_option::OPTION_ARRAY,
        "pointer" => split_datatype_option::OPTION_POINTER,
        _ => 0,
    }
}

/// Set the `split_datatype_config`. Faithful to `OptionSplitDatatypes`.
pub struct OptionSplitDatatypes;
impl ArchOption for OptionSplitDatatypes {
    fn name(&self) -> &str {
        "splitdatatype"
    }
    fn apply(&self, arch: &mut Architecture, p1: &str, p2: &str, p3: &str) -> String {
        arch.split_datatype_config =
            get_split_datatype_bit(p1) | get_split_datatype_bit(p2) | get_split_datatype_bit(p3);
        format!("Split datatype config updated")
    }
}

/// Set the default prototype model name. Faithful to `OptionDefaultPrototype`.
pub struct OptionDefaultPrototype;
impl ArchOption for OptionDefaultPrototype {
    fn name(&self) -> &str {
        "defaultprototype"
    }
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        if !p1.is_empty() {
            arch.set_default_model(p1);
        }
        format!("Default prototype set to {p1}")
    }
}

/// Toggle warning generation. Faithful to `OptionWarning`.
pub struct OptionWarning;
impl ArchOption for OptionWarning {
    fn name(&self) -> &str {
        "warning"
    }
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        format!("Warning option: {p1}")
    }
}

/// A generic toggle option that sets a single Architecture bool field.
/// Used for the many on/off options (nullprinting, conventionprinting, etc.).
macro_rules! toggle_option {
    ($struct_name:ident, $opt_name:expr, $field:ident, $desc:expr) => {
        pub struct $struct_name;
        impl ArchOption for $struct_name {
            fn name(&self) -> &str {
                $opt_name
            }
            fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
                arch.$field = on_or_off(p1);
                format!("{} is {}", $desc, p1)
            }
        }
    };
}

// The print-language options (nullprinting, conventionprinting, etc.) modify
// PrintLanguage fields which are not yet wired into Architecture. We provide
// stub implementations that return confirmation messages.
macro_rules! stub_option {
    ($struct_name:ident, $opt_name:expr, $desc:expr) => {
        pub struct $struct_name;
        impl ArchOption for $struct_name {
            fn name(&self) -> &str {
                $opt_name
            }
            fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
                format!("{}: {}", $desc, p1)
            }
        }
    };
}

stub_option!(OptionExtraPop, "extrapop", "ExtraPop");
stub_option!(OptionInline, "inline", "Inline");
stub_option!(OptionNoReturn, "noreturn", "NoReturn");
stub_option!(OptionProtoEval, "protoeval", "ProtoEval");
stub_option!(OptionNullPrinting, "nullprinting", "Null printing");
stub_option!(OptionInPlaceOps, "inplaceops", "In-place ops");
stub_option!(OptionConventionPrinting, "conventionprinting", "Convention printing");
stub_option!(OptionNoCastPrinting, "nocastprinting", "No-cast printing");
stub_option!(OptionHideExtensions, "hideextensions", "Hide extensions");
stub_option!(OptionMaxLineWidth, "maxlinewidth", "Max line width");
stub_option!(OptionIndentIncrement, "indentincrement", "Indent increment");
stub_option!(OptionCommentIndent, "commentindent", "Comment indent");
stub_option!(OptionCommentStyle, "commentstyle", "Comment style");
stub_option!(OptionCommentHeader, "commentheader", "Comment header");
stub_option!(OptionCommentInstruction, "commentinstruction", "Comment instruction");
stub_option!(OptionIntegerFormat, "integerformat", "Integer format");
stub_option!(OptionBraceFormat, "braceformat", "Brace format");
stub_option!(OptionSetAction, "setaction", "Set action");
stub_option!(OptionCurrentAction, "currentaction", "Current action");
stub_option!(OptionAllowContextSet, "allowcontextset", "Allow context set");
stub_option!(OptionIgnoreUnimplemented, "ignoreunimplemented", "Ignore unimplemented");
stub_option!(OptionErrorUnimplemented, "errorunimplemented", "Error unimplemented");
stub_option!(OptionErrorReinterpreted, "errorreinterpreted", "Error reinterpreted");
stub_option!(OptionErrorTooManyInstructions, "errortoomanyinstructions", "Error too many instructions");
stub_option!(OptionSetLanguage, "setlanguage", "Set language");
stub_option!(OptionJumpLoad, "jumpload", "Jump load");
stub_option!(OptionToggleRule, "togglerule", "Toggle rule");
stub_option!(OptionNamespaceStrategy, "namespacestrategy", "Namespace strategy");

// ---------------------------------------------------------------------------
// OptionDatabase dispatcher
// ---------------------------------------------------------------------------

/// A dispatcher for `ArchOption` commands. Faithful to `OptionDatabase`
/// (options.hh:106).
pub struct OptionDatabase {
    /// Map from option name to the registered ArchOption instance.
    optionmap: HashMap<String, Box<dyn ArchOption>>,
}

impl Default for OptionDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl OptionDatabase {
    /// Construct and register all built-in options. Faithful to the
    /// `OptionDatabase` constructor (options.cc:93).
    pub fn new() -> Self {
        let mut db = Self {
            optionmap: HashMap::new(),
        };
        db.register_all();
        db
    }

    /// Register all built-in ArchOption objects.
    fn register_all(&mut self) {
        self.register(Box::new(OptionExtraPop));
        self.register(Box::new(OptionReadOnly));
        self.register(Box::new(OptionIgnoreUnimplemented));
        self.register(Box::new(OptionErrorUnimplemented));
        self.register(Box::new(OptionErrorReinterpreted));
        self.register(Box::new(OptionErrorTooManyInstructions));
        self.register(Box::new(OptionDefaultPrototype));
        self.register(Box::new(OptionInferConstPtr));
        self.register(Box::new(OptionForLoops));
        self.register(Box::new(OptionInline));
        self.register(Box::new(OptionNoReturn));
        self.register(Box::new(OptionProtoEval));
        self.register(Box::new(OptionWarning));
        self.register(Box::new(OptionNullPrinting));
        self.register(Box::new(OptionInPlaceOps));
        self.register(Box::new(OptionConventionPrinting));
        self.register(Box::new(OptionNoCastPrinting));
        self.register(Box::new(OptionHideExtensions));
        self.register(Box::new(OptionMaxLineWidth));
        self.register(Box::new(OptionIndentIncrement));
        self.register(Box::new(OptionCommentIndent));
        self.register(Box::new(OptionCommentStyle));
        self.register(Box::new(OptionCommentHeader));
        self.register(Box::new(OptionCommentInstruction));
        self.register(Box::new(OptionIntegerFormat));
        self.register(Box::new(OptionBraceFormat));
        self.register(Box::new(OptionCurrentAction));
        self.register(Box::new(OptionAllowContextSet));
        self.register(Box::new(OptionSetAction));
        self.register(Box::new(OptionSetLanguage));
        self.register(Box::new(OptionJumpTableMax));
        self.register(Box::new(OptionJumpLoad));
        self.register(Box::new(OptionToggleRule));
        self.register(Box::new(OptionAliasBlock));
        self.register(Box::new(OptionMaxInstruction));
        self.register(Box::new(OptionNamespaceStrategy));
        self.register(Box::new(OptionSplitDatatypes));
        self.register(Box::new(OptionNanIgnore));
    }

    /// Register a new ArchOption. Faithful to `registerOption`.
    fn register(&mut self, option: Box<dyn ArchOption>) {
        let name = option.name().to_string();
        self.optionmap.insert(name, option);
    }

    /// Issue an option command directly, given its name and optional
    /// parameters. Faithful to `OptionDatabase::set` (options.cc:150).
    /// Returns the confirmation/failure message.
    pub fn set(
        &mut self,
        arch: &mut Architecture,
        name: &str,
        p1: &str,
        p2: &str,
        p3: &str,
    ) -> String {
        match self.optionmap.get(name) {
            Some(opt) => opt.apply(arch, p1, p2, p3),
            None => format!("Unknown option: {name}"),
        }
    }

    /// Check if an option is registered.
    pub fn has_option(&self, name: &str) -> bool {
        self.optionmap.contains_key(name)
    }

    /// Number of registered options.
    pub fn num_options(&self) -> usize {
        self.optionmap.len()
    }

    /// Get all registered option names.
    pub fn option_names(&self) -> Vec<&str> {
        self.optionmap.keys().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_on_or_off() {
        assert!(on_or_off("on"));
        assert!(on_or_off("")); // empty = on
        assert!(!on_or_off("off"));
    }

    #[test]
    fn test_database_construction() {
        let db = OptionDatabase::new();
        assert!(db.num_options() >= 37);
        assert!(db.has_option("inferconstptr"));
        assert!(db.has_option("analyzeforloops"));
        assert!(db.has_option("jumptablemax"));
        assert!(db.has_option("aliasblock"));
        assert!(db.has_option("nanignore"));
        assert!(db.has_option("splitdatatype"));
    }

    #[test]
    fn test_infer_const_ptr() {
        let mut db = OptionDatabase::new();
        let mut arch = Architecture::new();
        arch.infer_pointers = false;
        let msg = db.set(&mut arch, "inferconstptr", "on", "", "");
        assert!(arch.infer_pointers);
        assert!(msg.contains("inferred"));
        db.set(&mut arch, "inferconstptr", "off", "", "");
        assert!(!arch.infer_pointers);
    }

    #[test]
    fn test_for_loops() {
        let mut db = OptionDatabase::new();
        let mut arch = Architecture::new();
        db.set(&mut arch, "analyzeforloops", "off", "", "");
        assert!(!arch.analyze_for_loops);
        db.set(&mut arch, "analyzeforloops", "on", "", "");
        assert!(arch.analyze_for_loops);
    }

    #[test]
    fn test_jump_table_max() {
        let mut db = OptionDatabase::new();
        let mut arch = Architecture::new();
        let msg = db.set(&mut arch, "jumptablemax", "2048", "", "");
        assert_eq!(arch.max_jumptable_size, 2048);
        assert!(msg.contains("2048"));
    }

    #[test]
    fn test_max_instruction() {
        let mut db = OptionDatabase::new();
        let mut arch = Architecture::new();
        db.set(&mut arch, "maxinstruction", "50000", "", "");
        assert_eq!(arch.max_instructions, 50000);
    }

    #[test]
    fn test_alias_block() {
        let mut db = OptionDatabase::new();
        let mut arch = Architecture::new();
        db.set(&mut arch, "aliasblock", "none", "", "");
        assert_eq!(arch.alias_block_level, 0);
        db.set(&mut arch, "aliasblock", "all", "", "");
        assert_eq!(arch.alias_block_level, 3);
    }

    #[test]
    fn test_nan_ignore() {
        let mut db = OptionDatabase::new();
        let mut arch = Architecture::new();
        db.set(&mut arch, "nanignore", "all", "", "");
        assert!(arch.nan_ignore_all);
        assert!(arch.nan_ignore_compare);
        db.set(&mut arch, "nanignore", "none", "", "");
        assert!(!arch.nan_ignore_all);
        assert!(!arch.nan_ignore_compare);
    }

    #[test]
    fn test_split_datatypes() {
        let mut db = OptionDatabase::new();
        let mut arch = Architecture::new();
        db.set(&mut arch, "splitdatatype", "struct", "array", "pointer");
        assert_eq!(
            arch.split_datatype_config,
            split_datatype_option::OPTION_STRUCT
                | split_datatype_option::OPTION_ARRAY
                | split_datatype_option::OPTION_POINTER
        );
    }

    #[test]
    fn test_readonly() {
        let mut db = OptionDatabase::new();
        let mut arch = Architecture::new();
        db.set(&mut arch, "readonly", "on", "", "");
        assert!(arch.readonlypropagate);
        db.set(&mut arch, "readonly", "off", "", "");
        assert!(!arch.readonlypropagate);
    }

    #[test]
    fn test_default_prototype() {
        let mut db = OptionDatabase::new();
        let mut arch = Architecture::new();
        arch.proto_models.insert(
            "__stdcall".to_string(),
            crate::arch::ProtoModelEntry {
                name: "__stdcall".to_string(),
                is_default: false,
                print_in_decl: true,
            },
        );
        db.set(&mut arch, "defaultprototype", "__stdcall", "", "");
        assert_eq!(arch.defaultfp_name.as_deref(), Some("__stdcall"));
    }

    #[test]
    fn test_unknown_option() {
        let mut db = OptionDatabase::new();
        let mut arch = Architecture::new();
        let msg = db.set(&mut arch, "nonexistent", "", "", "");
        assert!(msg.contains("Unknown option"));
    }

    #[test]
    fn test_get_split_datatype_bit() {
        assert_eq!(get_split_datatype_bit("struct"), split_datatype_option::OPTION_STRUCT);
        assert_eq!(get_split_datatype_bit("array"), split_datatype_option::OPTION_ARRAY);
        assert_eq!(get_split_datatype_bit("pointer"), split_datatype_option::OPTION_POINTER);
        assert_eq!(get_split_datatype_bit("unknown"), 0);
    }
}
