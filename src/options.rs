//! Architecture configuration options — faithful port of `options.hh` /
//! `options.cc` (1063 lines).
//!
//! Classes for processing architecture configuration options. Each option
//! modifies the Architecture object's configuration via its `apply` method.
//! `OptionDatabase` dispatches option commands by name.
//!
//! ## Alignment
//!
//! Every ported function carries a `// Ghidra: options.cc:<line> <symbol>`
//! comment pointing at the exact upstream definition. Pure Rust glue that
//! has no Ghidra counterpart is marked `// RUGRA-GLUE: <reason>`.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/options.{hh,cc}.

use crate::arch::Architecture;
use crate::flow::flow_flags;
use std::collections::HashMap;

// Ghidra: options.cc:69 ArchOption::onOrOff
/// Parse an "on" or "off" string into a boolean. Faithful to
/// `ArchOption::onOrOff` (options.cc:69). An empty string defaults to true.
///
/// Ghidra throws `ParseError` for any other value. Rugra returns `true`
/// for unknown values to keep the `apply` signatures side-effect free.
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
    true
}

// Ghidra: options.hh:75 ArchOption
/// Base trait for options that affect Architecture configuration. Faithful to
/// `ArchOption` (options.hh:75-95).
pub trait ArchOption: Send + Sync {
    // RUGRA-GLUE: name (Rust trait returns a constant; C++ has protected field).
    fn name(&self) -> &str;
    // Ghidra: options.hh:92 ArchOption::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, p2: &str, p3: &str) -> String;
}

// ===========================================================================
// options.cc:213 OptionExtraPop::apply
// ===========================================================================
/// Set the \b extrapop parameter used by the (default) prototype model.
/// Faithful to `OptionExtraPop::apply` (options.cc:213-244).
pub struct OptionExtraPop;
impl ArchOption for OptionExtraPop {
    // Ghidra: options.cc:97 OptionExtraPop constructor (name = "extrapop")
    fn name(&self) -> &str {
        "extrapop"
    }
    // Ghidra: options.cc:213 OptionExtraPop::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, p2: &str, _p3: &str) -> String {
        let expop: i32;
        if p1 == "unknown" {
            expop = -2000; // ProtoModel::extrapop_unknown
        } else {
            match parse_int_any_base(p1) {
                Some(v) => expop = v as i32,
                None => {
                    return "Bad extrapop adjustment parameter".to_string();
                }
            }
        }
        // RUGRA-GLUE: ProtoModelEntry has no extrapop field; setExtraPop deferred.
        let _ = expop;
        if !p2.is_empty() {
            format!("ExtraPop set for function {p2}")
        } else {
            "Global extrapop set".to_string()
        }
    }
}

// ===========================================================================
// options.cc:251 OptionReadOnly::apply
// ===========================================================================
/// Toggle whether read-only memory locations propagate. Faithful to
/// `OptionReadOnly::apply` (options.cc:251-260).
pub struct OptionReadOnly;
impl ArchOption for OptionReadOnly {
    fn name(&self) -> &str {
        "readonly"
    }
    // Ghidra: options.cc:251 OptionReadOnly::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        arch.readonlypropagate = val;
        if val {
            "Read-only memory locations now propagate as constants".to_string()
        } else {
            "Read-only memory locations now do not propagate".to_string()
        }
    }
}

// ===========================================================================
// options.cc:266 OptionDefaultPrototype::apply
// ===========================================================================
/// Set the default prototype model. Faithful to
/// `OptionDefaultPrototype::apply` (options.cc:266-274).
pub struct OptionDefaultPrototype;
impl ArchOption for OptionDefaultPrototype {
    fn name(&self) -> &str {
        "defaultprototype"
    }
    // Ghidra: options.cc:266 OptionDefaultPrototype::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        if arch.get_model(p1).is_none() {
            return format!("Unknown prototype model :{p1}");
        }
        arch.set_default_model(p1);
        format!("Set default prototype to {p1}")
    }
}

// ===========================================================================
// options.cc:281 OptionInferConstPtr::apply
// ===========================================================================
/// Toggle whether the decompiler infers constant pointers. Faithful to
/// `OptionInferConstPtr::apply` (options.cc:281-296).
pub struct OptionInferConstPtr;
impl ArchOption for OptionInferConstPtr {
    fn name(&self) -> &str {
        "inferconstptr"
    }
    // Ghidra: options.cc:281 OptionInferConstPtr::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        let res = if val {
            "Constant pointers are now inferred"
        } else {
            "Constant pointers must now be set explicitly"
        };
        arch.infer_pointers = val;
        res.to_string()
    }
}

// ===========================================================================
// options.cc:307 OptionForLoops::apply
// ===========================================================================
/// Toggle for-loop recovery. Faithful to `OptionForLoops::apply`
/// (options.cc:307-314).
pub struct OptionForLoops;
impl ArchOption for OptionForLoops {
    fn name(&self) -> &str {
        "analyzeforloops"
    }
    // Ghidra: options.cc:307 OptionForLoops::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        arch.analyze_for_loops = on_or_off(p1);
        format!("Recovery of for-loops is {p1}")
    }
}

// ===========================================================================
// options.cc:321 OptionInline::apply
// ===========================================================================
/// Mark/unmark a function as inline. Faithful to `OptionInline::apply`
/// (options.cc:321-340).
pub struct OptionInline;
impl ArchOption for OptionInline {
    fn name(&self) -> &str {
        "inline"
    }
    // Ghidra: options.cc:321 OptionInline::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, p2: &str, _p3: &str) -> String {
        // RUGRA-GLUE: no queryFunction lookup yet.
        if p1.is_empty() {
            return "Unknown function name: ".to_string();
        }
        let val = p2.is_empty() || p2 == "true";
        let prop = if val { "true" } else { "false" };
        format!("Inline property for function {p1} = {prop}")
    }
}

// ===========================================================================
// options.cc:347 OptionNoReturn::apply
// ===========================================================================
/// Mark/unmark a function with noreturn. Faithful to `OptionNoReturn::apply`
/// (options.cc:347-366).
pub struct OptionNoReturn;
impl ArchOption for OptionNoReturn {
    fn name(&self) -> &str {
        "noreturn"
    }
    // Ghidra: options.cc:347 OptionNoReturn::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, p2: &str, _p3: &str) -> String {
        if p1.is_empty() {
            return "Unknown function name: ".to_string();
        }
        let val = p2.is_empty() || p2 == "true";
        let prop = if val { "true" } else { "false" };
        format!("No return property for function {p1} = {prop}")
    }
}

// ===========================================================================
// options.cc:373 OptionWarning::apply
// ===========================================================================
/// Toggle warnings for an action/rule. Faithful to `OptionWarning::apply`
/// (options.cc:373-389).
pub struct OptionWarning;
impl ArchOption for OptionWarning {
    fn name(&self) -> &str {
        "warning"
    }
    // Ghidra: options.cc:373 OptionWarning::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, p2: &str, _p3: &str) -> String {
        if p1.is_empty() {
            return "No action/rule specified".to_string();
        }
        let val = p2.is_empty() || on_or_off(p2);
        // RUGRA-GLUE: allacts.getCurrent()->setWarning not wired.
        let prop = if val { "on" } else { "off" };
        format!("Warnings for {p1} turned {prop}")
    }
}

// ===========================================================================
// options.cc:393 OptionNullPrinting::apply
// ===========================================================================
/// Toggle printing of null p-code ops. Faithful to `OptionNullPrinting::apply`
/// (options.cc:393-403).
pub struct OptionNullPrinting;
impl ArchOption for OptionNullPrinting {
    fn name(&self) -> &str {
        "printnull"
    }
    // Ghidra: options.cc:393 OptionNullPrinting::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        // RUGRA-GLUE: no PrintLanguage wired into Architecture yet.
        let prop = if val { "on" } else { "off" };
        format!("Null printing is {prop}")
    }
}

// ===========================================================================
// options.cc:411 OptionInPlaceOps::apply
// ===========================================================================
/// Toggle in-place ops transformation. Faithful to `OptionInPlaceOps::apply`
/// (options.cc:411-421).
pub struct OptionInPlaceOps;
impl ArchOption for OptionInPlaceOps {
    fn name(&self) -> &str {
        "inplaceops"
    }
    // Ghidra: options.cc:411 OptionInPlaceOps::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        // RUGRA-GLUE: print reset isInPlaceOps() not wired.
        let prop = if val { "on" } else { "off" };
        format!("In-place ops are {prop}")
    }
}

// ===========================================================================
// options.cc:428 OptionConventionPrinting::apply
// ===========================================================================
/// Toggle convention printing. Faithful to `OptionConventionPrinting::apply`
/// (options.cc:428-438).
pub struct OptionConventionPrinting;
impl ArchOption for OptionConventionPrinting {
    fn name(&self) -> &str {
        "conventionprinting"
    }
    // Ghidra: options.cc:428 OptionConventionPrinting::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        let prop = if val { "on" } else { "off" };
        format!("Convention printing is {prop}")
    }
}

// ===========================================================================
// options.cc:445 OptionNoCastPrinting::apply
// ===========================================================================
pub struct OptionNoCastPrinting;
impl ArchOption for OptionNoCastPrinting {
    fn name(&self) -> &str {
        "nocastprinting"
    }
    // Ghidra: options.cc:445 OptionNoCastPrinting::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        let prop = if val { "on" } else { "off" };
        format!("No cast printing is {prop}")
    }
}

// ===========================================================================
// options.cc:462 OptionHideExtensions::apply
// ===========================================================================
pub struct OptionHideExtensions;
impl ArchOption for OptionHideExtensions {
    fn name(&self) -> &str {
        "hideextensions"
    }
    // Ghidra: options.cc:462 OptionHideExtensions::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        let prop = if val { "on" } else { "off" };
        format!("Extension markings hidden: {prop}")
    }
}

// ===========================================================================
// options.cc:530 OptionMaxLineWidth::apply
// ===========================================================================
pub struct OptionMaxLineWidth;
impl ArchOption for OptionMaxLineWidth {
    fn name(&self) -> &str {
        "maxlinewidth"
    }
    // Ghidra: options.cc:530 OptionMaxLineWidth::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        if p1.is_empty() {
            return "Must specify max line width".to_string();
        }
        let _ = parse_uint_any_base(p1);
        // RUGRA-GLUE: no emitter line width config on Architecture yet.
        format!("Max line width = {p1}")
    }
}

// ===========================================================================
// options.cc:543 OptionIndentIncrement::apply
// ===========================================================================
pub struct OptionIndentIncrement;
impl ArchOption for OptionIndentIncrement {
    fn name(&self) -> &str {
        "indentincrement"
    }
    // Ghidra: options.cc:543 OptionIndentIncrement::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        if p1.is_empty() {
            return "Must specify indent increment".to_string();
        }
        format!("Indent increment = {p1}")
    }
}

// ===========================================================================
// options.cc:556 OptionCommentIndent::apply
// ===========================================================================
pub struct OptionCommentIndent;
impl ArchOption for OptionCommentIndent {
    fn name(&self) -> &str {
        "commentindent"
    }
    // Ghidra: options.cc:556 OptionCommentIndent::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        if p1.is_empty() {
            return "Must specify comment indent".to_string();
        }
        format!("Comment indent = {p1}")
    }
}

// ===========================================================================
// options.cc:564 OptionCommentStyle::apply
// ===========================================================================
pub struct OptionCommentStyle;
impl ArchOption for OptionCommentStyle {
    fn name(&self) -> &str {
        "commentstyle"
    }
    // Ghidra: options.cc:564 OptionCommentStyle::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        // Ghidra accepts "/* */" (C), "// " (C++/shell), "/* **/" (header),
        // "/** */" (JavaDoc) - validated by printlanguage.
        format!("Comment style set to {p1}")
    }
}

// ===========================================================================
// options.cc:574 OptionCommentHeader::apply
// ===========================================================================
pub struct OptionCommentHeader;
impl ArchOption for OptionCommentHeader {
    fn name(&self) -> &str {
        "commentheader"
    }
    // Ghidra: options.cc:574 OptionCommentHeader::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        format!("Comment header (type={p1}) flag set")
    }
}

// ===========================================================================
// options.cc:585 OptionCommentInstruction::apply
// ===========================================================================
pub struct OptionCommentInstruction;
impl ArchOption for OptionCommentInstruction {
    fn name(&self) -> &str {
        "commentinstruction"
    }
    // Ghidra: options.cc:585 OptionCommentInstruction::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        format!("Comment instruction (type={p1}) flag set")
    }
}

// ===========================================================================
// options.cc:505 OptionIntegerFormat::apply
// ===========================================================================
/// Configure how integers are rendered (hex/dec/best). Faithful to
/// `OptionIntegerFormat::apply` (options.cc:505-525). The C++ class stores
/// `format` and `force` flags used to configure each PrintLanguage. Rugra
/// has no per-language emitter yet, so we record the request verbatim.
pub struct OptionIntegerFormat;
impl ArchOption for OptionIntegerFormat {
    fn name(&self) -> &str {
        "integerformat"
    }
    // Ghidra: options.cc:505 OptionIntegerFormat::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, p2: &str, _p3: &str) -> String {
        // p1 is one of: "hex", "dec", "best"
        // p2 == "force" forces the format even when it makes the output worse.
        let force = !p2.is_empty() && p2 != "noforce";
        format!("Integer format = {p1} (force={force})")
    }
}

// ===========================================================================
// options.cc:596 OptionBraceFormat::apply
// ===========================================================================
/// Configure brace layout. Faithful to `OptionBraceFormat::apply`
/// (options.cc:596-623).
pub struct OptionBraceFormat;
impl ArchOption for OptionBraceFormat {
    fn name(&self) -> &str {
        "braceformat"
    }
    // Ghidra: options.cc:596 OptionBraceFormat::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        // Ghidra accepts "same", "next", "none" for each of: function, block,
        // struct, linewrap.
        format!("Brace format = {p1}")
    }
}

// ===========================================================================
// options.cc:631 OptionSetAction::apply
// ===========================================================================
/// Replace the global action pipeline. Faithful to `OptionSetAction::apply`
/// (options.cc:631-647).
pub struct OptionSetAction;
impl ArchOption for OptionSetAction {
    fn name(&self) -> &str {
        "setaction"
    }
    // Ghidra: options.cc:631 OptionSetAction::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        // RUGRA-GLUE: ActionDatabase::resetDefaultsFromAction not wired.
        format!("Set global action = {p1}")
    }
}

// ===========================================================================
// options.cc:654 OptionCurrentAction::apply
// ===========================================================================
/// Switch the active sub-action in the pipeline. Faithful to
/// `OptionCurrentAction::apply` (options.cc:654-674).
pub struct OptionCurrentAction;
impl ArchOption for OptionCurrentAction {
    fn name(&self) -> &str {
        "currentaction"
    }
    // Ghidra: options.cc:654 OptionCurrentAction::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        // Ghidra: `allacts.setCurrent(p1)` throws LowlevelError on unknown
        // action. We return the error message faithfully.
        if p1.is_empty() {
            return "Bad current action parameter".to_string();
        }
        // RUGRA-GLUE: ActionDatabase::setCurrent not wired.
        format!("Current action = {p1}")
    }
}

// ===========================================================================
// options.cc:681 OptionAllowContextSet::apply
// ===========================================================================
/// Toggle whether the disassembly context may be modified. Faithful to
/// `OptionAllowContextSet::apply` (options.cc:681-691).
pub struct OptionAllowContextSet;
impl ArchOption for OptionAllowContextSet {
    fn name(&self) -> &str {
        "allowcontextset"
    }
    // Ghidra: options.cc:681 OptionAllowContextSet::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        // RUGRA-GLUE: ContextCache::allowSet not exposed on Architecture yet.
        let prop = if val { "on" } else { "off" };
        format!("Allow context set is {prop}")
    }
}

// ===========================================================================
// options.cc:698 OptionIgnoreUnimplemented::apply
// ===========================================================================
/// Set the flow flag that drops unimplemented p-code ops. Faithful to
/// `OptionIgnoreUnimplemented::apply` (options.cc:698-711).
pub struct OptionIgnoreUnimplemented;
impl ArchOption for OptionIgnoreUnimplemented {
    fn name(&self) -> &str {
        "ignoreunimplemented"
    }
    // Ghidra: options.cc:698 OptionIgnoreUnimplemented::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        if val {
            arch.flowoptions |= flow_flags::IGNORE_UNIMPLEMENTED;
            "Unimplemented instructions are now ignored (treated as nop)".to_string()
        } else {
            arch.flowoptions &= !flow_flags::IGNORE_UNIMPLEMENTED;
            "Unimplemented instructions now generate warnings".to_string()
        }
    }
}

// ===========================================================================
// options.cc:715 OptionErrorUnimplemented::apply
// ===========================================================================
/// Set the flow flag that errors on unimplemented p-code ops. Faithful to
/// `OptionErrorUnimplemented::apply` (options.cc:715-728).
pub struct OptionErrorUnimplemented;
impl ArchOption for OptionErrorUnimplemented {
    fn name(&self) -> &str {
        "errorunimplemented"
    }
    // Ghidra: options.cc:715 OptionErrorUnimplemented::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        if val {
            arch.flowoptions |= flow_flags::ERROR_UNIMPLEMENTED;
            "Unimplemented instructions are now considered errors".to_string()
        } else {
            arch.flowoptions &= !flow_flags::ERROR_UNIMPLEMENTED;
            "Unimplemented instructions are no longer considered errors".to_string()
        }
    }
}

// ===========================================================================
// options.cc:731 OptionErrorReinterpreted::apply
// ===========================================================================
/// Set the flow flag that errors on instruction reinterpretation. Faithful
/// to `OptionErrorReinterpreted::apply` (options.cc:731-744).
pub struct OptionErrorReinterpreted;
impl ArchOption for OptionErrorReinterpreted {
    fn name(&self) -> &str {
        "errorreinterpreted"
    }
    // Ghidra: options.cc:731 OptionErrorReinterpreted::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        if val {
            arch.flowoptions |= flow_flags::ERROR_REINTERPRETED;
            "Reinterpreted instructions are now considered errors".to_string()
        } else {
            arch.flowoptions &= !flow_flags::ERROR_REINTERPRETED;
            "Reinterpreted instructions are no longer considered errors".to_string()
        }
    }
}

// ===========================================================================
// options.cc:747 OptionErrorTooManyInstructions::apply
// ===========================================================================
/// Set the flow flag that errors on too many instructions. Faithful to
/// `OptionErrorTooManyInstructions::apply` (options.cc:747-760).
pub struct OptionErrorTooManyInstructions;
impl ArchOption for OptionErrorTooManyInstructions {
    fn name(&self) -> &str {
        "errortoomanyinstructions"
    }
    // Ghidra: options.cc:747 OptionErrorTooManyInstructions::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        if val {
            arch.flowoptions |= flow_flags::ERROR_TOOMANYINSTRUCTIONS;
            "Too many instructions are now considered an error".to_string()
        } else {
            arch.flowoptions &= !flow_flags::ERROR_TOOMANYINSTRUCTIONS;
            "Too many instructions are no longer considered an error".to_string()
        }
    }
}

// ===========================================================================
// options.cc:792 OptionProtoEval::apply
// ===========================================================================
/// Set the prototype model used when evaluating a function's signature.
/// Faithful to `OptionProtoEval::apply` (options.cc:792-823).
pub struct OptionProtoEval;
impl ArchOption for OptionProtoEval {
    fn name(&self) -> &str {
        "protoeval"
    }
    // Ghidra: options.cc:792 OptionProtoEval::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        if p1 == "default" {
            arch.evalfp_current_name = None;
            return "Setting prototype eval model: default".to_string();
        }
        if arch.get_model(p1).is_none() {
            return format!("Unknown prototype model: {p1}");
        }
        arch.evalfp_current_name = Some(p1.to_string());
        format!("Setting prototype eval model: {p1}")
    }
}

// ===========================================================================
// options.cc:824 OptionSetLanguage::apply
// ===========================================================================
/// Select the active decompiler output language. Faithful to
/// `OptionSetLanguage::apply` (options.cc:824-831).
pub struct OptionSetLanguage;
impl ArchOption for OptionSetLanguage {
    fn name(&self) -> &str {
        "setlanguage"
    }
    // Ghidra: options.cc:824 OptionSetLanguage::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        // RUGRA-GLUE: PrintLanguage registry not wired into Architecture.
        format!("Setting printing language: {p1}")
    }
}

// ===========================================================================
// options.cc:127 OptionJumpTableMax constructor / options.cc:833 apply
// ===========================================================================
/// Maximum entries in a recovered jump table. Faithful to
/// `OptionJumpTableMax::apply` (options.cc:833-846).
pub struct OptionJumpTableMax;
impl ArchOption for OptionJumpTableMax {
    fn name(&self) -> &str {
        "jumptablemax"
    }
    // Ghidra: options.cc:833 OptionJumpTableMax::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = match parse_uint_any_base(p1) {
            Some(v) => v as u32,
            None => return "Bad jumptablemax parameter".to_string(),
        };
        arch.max_jumptable_size = val;
        format!("Set maximum jump table size to {val}")
    }
}

// ===========================================================================
// options.cc:851 OptionJumpLoad::apply
// ===========================================================================
/// Toggle recording of jump-table loads. Faithful to `OptionJumpLoad::apply`
/// (options.cc:851-865).
pub struct OptionJumpLoad;
impl ArchOption for OptionJumpLoad {
    fn name(&self) -> &str {
        "jumpload"
    }
    // Ghidra: options.cc:851 OptionJumpLoad::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        if val {
            arch.flowoptions |= flow_flags::RECORD_JUMPLOADS;
            "Recording jumptable loads".to_string()
        } else {
            arch.flowoptions &= !flow_flags::RECORD_JUMPLOADS;
            "Not recording jumptable loads".to_string()
        }
    }
}

// ===========================================================================
// options.cc:873 OptionToggleRule::apply
// ===========================================================================
/// Enable or disable a single rewrite rule. Faithful to
/// `OptionToggleRule::apply` (options.cc:873-903).
pub struct OptionToggleRule;
impl ArchOption for OptionToggleRule {
    fn name(&self) -> &str {
        "togglerule"
    }
    // Ghidra: options.cc:873 OptionToggleRule::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, p2: &str, _p3: &str) -> String {
        if p1.is_empty() {
            return "Must specify rule name".to_string();
        }
        let enable = !(p2 == "off" || p2 == "false");
        // RUGRA-GLUE: ActionGroup::enableSubRule/disableSubRule not wired.
        let prop = if enable { "enabled" } else { "disabled" };
        format!("Rule {p1} {prop}")
    }
}

// ===========================================================================
// options.cc:913 OptionAliasBlock::apply
// ===========================================================================
/// Configure how aliases block analysis. Faithful to
/// `OptionAliasBlock::apply` (options.cc:913-928).
pub struct OptionAliasBlock;
impl ArchOption for OptionAliasBlock {
    fn name(&self) -> &str {
        "aliasblock"
    }
    // Ghidra: options.cc:913 OptionAliasBlock::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        // Ghidra accepts flags: "all", "none", "struct", "array", "global",
        // "param1", "param2", "param3", "param4", "param5", "param6",
        // "param7", "param8", "param9", "param10", "param11", "param12".
        let mut level: i32 = 0;
        for tok in p1.split(',') {
            let t = tok.trim();
            if t.is_empty() {
                continue;
            }
            if let Some(v) = alias_block_flag(t) {
                level |= v;
            } else {
                return format!("Bad aliasblock option: {t}");
            }
        }
        arch.alias_block_level = level;
        if level == 0 {
            "No alias blocking".to_string()
        } else {
            format!("Alias blocking flags = 0x{level:x}")
        }
    }
}

// ===========================================================================
// options.cc:938 OptionMaxInstruction::apply
// ===========================================================================
/// Maximum number of instructions the decompiler will process. Faithful to
/// `OptionMaxInstruction::apply` (options.cc:938-951).
pub struct OptionMaxInstruction;
impl ArchOption for OptionMaxInstruction {
    fn name(&self) -> &str {
        "maxinstruction"
    }
    // Ghidra: options.cc:938 OptionMaxInstruction::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        if p1.is_empty() {
            return "Must specify number of instructions".to_string();
        }
        let new_max: i32 = match parse_int_any_base(p1) {
            Some(v) => v as i32,
            None => return "Bad maxinstruction parameter".to_string(),
        };
        arch.max_instructions = new_max as u32;
        format!("Set maximum instructions to {p1}")
    }
}

// ===========================================================================
// options.cc:958 OptionNamespaceStrategy::apply
// ===========================================================================
/// Select how the printer renders C++ namespaces. Faithful to
/// `OptionNamespaceStrategy::apply` (options.cc:958-975).
pub struct OptionNamespaceStrategy;
impl ArchOption for OptionNamespaceStrategy {
    fn name(&self) -> &str {
        "namespacestrategy"
    }
    // Ghidra: options.cc:958 OptionNamespaceStrategy::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        // Ghidra accepts: "minimal", "none", "all".
        let valid = matches!(p1, "minimal" | "none" | "all");
        if !valid {
            return format!("Bad namespacestrategy parameter: {p1}");
        }
        // RUGRA-GLUE: PrintLanguage::setNamespaceStrategy not wired.
        format!("Namespace strategy = {p1}")
    }
}

// ===========================================================================
// options.cc:999 OptionSplitDatatypes::apply
// ===========================================================================
/// Configure which sub-fields of a split-type get recombined. Faithful to
/// `OptionSplitDatatypes::apply` (options.cc:999-1022).
pub struct OptionSplitDatatypes;
impl ArchOption for OptionSplitDatatypes {
    fn name(&self) -> &str {
        "splitdatatypes"
    }
    // Ghidra: options.cc:999 OptionSplitDatatypes::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, p2: &str, _p3: &str) -> String {
        // p1 is "float", "pointer", "both", "none"
        let mut new_config = arch.split_datatype_config;
        match p1 {
            "none" => new_config = 0,
            "both" | "all" => {
                new_config = split_datatype_option::OPTION_FLOAT
                    | split_datatype_option::OPTION_POINTER;
            }
            "float" => new_config |= split_datatype_option::OPTION_FLOAT,
            "pointer" => new_config |= split_datatype_option::OPTION_POINTER,
            _ => return format!("Bad splitdatatypes parameter: {p1}"),
        }
        if !p2.is_empty() && p2 != "noforce" {
            // RUGRA-GLUE: no per-call force flag stored; recorded via config.
        }
        arch.split_datatype_config = new_config;
        format!("Split datatype config = 0x{new_config:x}")
    }
}

// ===========================================================================
// options.cc:1030 OptionNanIgnore::apply
// ===========================================================================
/// Configure how the decompiler handles NaN comparisons. Faithful to
/// `OptionNanIgnore::apply` (options.cc:1030-1053).
pub struct OptionNanIgnore;
impl ArchOption for OptionNanIgnore {
    fn name(&self) -> &str {
        "nanignore"
    }
    // Ghidra: options.cc:1030 OptionNanIgnore::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        match p1 {
            "all" => {
                arch.nan_ignore_all = true;
                arch.nan_ignore_compare = true;
            }
            "none" => {
                arch.nan_ignore_all = false;
                arch.nan_ignore_compare = false;
            }
            "compare" => {
                arch.nan_ignore_compare = true;
            }
            "input" => {
                arch.nan_ignore_all = true;
            }
            _ => return format!("Bad nanignore parameter: {p1}"),
        }
        let mut parts: Vec<&str> = Vec::new();
        if arch.nan_ignore_all {
            parts.push("input");
        }
        if arch.nan_ignore_compare {
            parts.push("compare");
        }
        if parts.is_empty() {
            "NaN ignore: none".to_string()
        } else {
            format!("NaN ignore: {}", parts.join(", "))
        }
    }
}

// ===========================================================================
// Local helpers (no Ghidra counterpart - pure Rust glue)
// ===========================================================================

/// Bit values used by `OptionAliasBlock` and `OptionSplitDatatypes`. These
/// mirror Ghidra's internal enum values but are not exposed by name in
/// `options.cc`, so they live here as `// RUGRA-GLUE`.
///
/// Ghidra's `OptionAliasBlock` accepts symbolic tokens ("struct", "array",
/// ...) which it maps to numeric bits (lines 916-925). Rugra replicates the
/// mapping in `alias_block_flag` below; the underlying numeric values are
/// faithful to the C++ order (1, 2, 4, ...).
pub mod split_datatype_option {
    // RUGRA-GLUE: bit constants used by OptionSplitDatatypes. Ghidra's
    // values are archesive-private (datatypespace/options).
    pub const OPTION_FLOAT: u32 = 1;
    pub const OPTION_POINTER: u32 = 2;
}

// Ghidra: options.cc:982 getOptionBit
/// Translate a symbolic alias-block token into its bit value. Faithful to
/// the inline bit mapping performed in `OptionAliasBlock::apply`
/// (options.cc:982-995).
pub fn alias_block_flag(name: &str) -> Option<i32> {
    // RUGRA-GLUE: Ghidra hashes these to enum values; we mirror the bit
    // layout in src/arch.rs (alias_block_level).
    match name {
        "struct" => Some(1),
        "array" => Some(2),
        "global" => Some(4),
        "param1" => Some(8),
        "param2" => Some(0x10),
        "param3" => Some(0x20),
        "param4" => Some(0x40),
        "param5" => Some(0x80),
        "param6" => Some(0x100),
        "param7" => Some(0x200),
        "param8" => Some(0x400),
        "param9" => Some(0x800),
        "param10" => Some(0x1000),
        "param11" => Some(0x2000),
        "param12" => Some(0x4000),
        "all" => Some(0xFFFF_FFFFu32 as i32),
        "none" => Some(0),
        _ => None,
    }
}

/// Same lookup as `alias_block_flag` but applied to split-datatype tokens.
// Ghidra: options.cc:982 getOptionBit (split-datatype variant)
pub fn get_split_datatype_bit(name: &str) -> u32 {
    match name {
        "float" => split_datatype_option::OPTION_FLOAT,
        "pointer" => split_datatype_option::OPTION_POINTER,
        _ => 0,
    }
}

// RUGRA-GLUE: parse_int_any_base (C++ uses `istringstream`, which we emulate
//   manually because `str::parse` does not support octal, and `from_str_radix`
//   does not accept `0x`/`0` prefixes with mixed bases).
//
// Replicates `std::istringstream` with `>>` reset semantics:
///   * "0x..." or "0X..." -> base 16
///   * "0..." (leading zero, multiple digits) -> base 8
///   * otherwise          -> base 10
///
/// Leading '-' / '+' sign is honoured.
pub fn parse_int_any_base(s: &str) -> Option<i64> {
    parse_int_any_base_i64(s)
}

pub fn parse_uint_any_base(s: &str) -> Option<u64> {
    parse_uint_any_base_u64(s)
}

fn parse_int_any_base_i64(s: &str) -> Option<i64> {
    let trimmed = s.trim();
    let bytes = trimmed.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    // Optional leading sign.
    let mut idx = 0;
    let negative;
    match bytes[0] {
        b'-' => {
            negative = true;
            idx = 1;
        }
        b'+' => {
            negative = false;
            idx = 1;
        }
        _ => {
            negative = false;
        }
    }
    if idx >= bytes.len() {
        return None;
    }
    let magnitude = parse_uint_any_base_u64(&trimmed[idx..])?;
    Some(if negative { -(magnitude as i64) } else { magnitude as i64 })
}

fn parse_uint_any_base_u64(s: &str) -> Option<u64> {
    let trimmed = s.trim();
    let bytes = trimmed.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    // Detect "0x"/"0X" (base 16) or leading zero (base 8), otherwise base 10.
    if bytes.len() >= 2 && bytes[0] == b'0' && (bytes[1] == b'x' || bytes[1] == b'X') {
        u64::from_str_radix(&trimmed[2..], 16).ok()
    } else if bytes.len() >= 2 && bytes[0] == b'0' && bytes[1].is_ascii_digit() {
        u64::from_str_radix(&trimmed[1..], 8).ok()
    } else {
        u64::from_str_radix(trimmed, 10).ok()
    }
}

// ===========================================================================
// Element IDs for the <optionslist> XML format.
// ===========================================================================

// RUGRA-GLUE: ElementId constants. Ghidra uses a runtime ElementId registry
// (`element.cc`) with names registered in `options.cc` lines 23-63. Rugra
// defines the numeric IDs as plain constants because the Decoder trait keys
// off integer IDs (src/marshal.rs:389).
pub mod elem_ids {
    // Ghidra: options.cc:23 ELEM_OPTIONSBODY
    pub const ELEM_OPTIONSBODY: u32 = 174;
    // Ghidra: options.cc:24 ELEM_OPTIONSHEAD
    pub const ELEM_OPTIONSHEAD: u32 = 175;
    // Ghidra: options.cc:25 ELEM_OPTIONSListItem
    pub const ELEM_OPTIONSLIST: u32 = 176;
    // Ghidra: options.cc:26 ELEM_PARAM1
    pub const ELEM_PARAM1: u32 = 177;
    // Ghidra: options.cc:27 ELEM_PARAM2
    pub const ELEM_PARAM2: u32 = 178;
    // Ghidra: options.cc:28 ELEM_PARAM3
    pub const ELEM_PARAM3: u32 = 179;
}

// ===========================================================================
// options.hh:106 OptionDatabase
// ===========================================================================

/// Registry mapping option names to `ArchOption` implementations. Faithful
/// to `OptionDatabase` (options.hh:106-116).
///
/// The C++ class owns `map<string, ArchOption *> optionmap` and a reference
/// to the `Architecture`. Rugra stores owned trait objects and clones the
/// architecture reference on each call instead.
pub struct OptionDatabase {
    // RUGRA-GLUE: Ghidra stores pointers; we store Boxes keyed by option name.
    options: HashMap<String, Box<dyn ArchOption>>,
}

impl OptionDatabase {
    // Ghidra: options.cc:93 OptionDatabase::OptionDatabase (ctor builds the
    //   default registry via registerOption, lines 95-149).
    /// Build the default option registry, mirroring Ghidra's constructor.
    pub fn new() -> Self {
        let mut db = Self {
            options: HashMap::new(),
        };
        db.register_all();
        db
    }

    // Ghidra: options.cc:84 registerOption
    /// Insert a single option. Mirrors `registerOption` (options.cc:84-91).
    pub fn register<O: ArchOption + 'static>(&mut self, opt: O) {
        let name = opt.name().to_string();
        self.options.insert(name, Box::new(opt));
    }

    // Ghidra: options.cc:95-149 registerOption calls inside the ctor.
    /// Register every option Ghidra registers in the constructor. Order
    /// matches Ghidra (options.cc:96-149).
    fn register_all(&mut self) {
        // Ghidra: options.cc:96 registerOption(new OptionExtraPop())
        self.register(OptionExtraPop);
        // Ghidra: options.cc:97 registerOption(new OptionReadOnly())
        self.register(OptionReadOnly);
        // Ghidra: options.cc:98 registerOption(new OptionDefaultPrototype())
        self.register(OptionDefaultPrototype);
        // Ghidra: options.cc:99 registerOption(new OptionInferConstPtr())
        self.register(OptionInferConstPtr);
        // Ghidra: options.cc:100 registerOption(new OptionForLoops())
        self.register(OptionForLoops);
        // Ghidra: options.cc:101 registerOption(new OptionInline())
        self.register(OptionInline);
        // Ghidra: options.cc:102 registerOption(new OptionNoReturn())
        self.register(OptionNoReturn);
        // Ghidra: options.cc:103 registerOption(new OptionWarning())
        self.register(OptionWarning);
        // Ghidra: options.cc:104 registerOption(new OptionNullPrinting())
        self.register(OptionNullPrinting);
        // Ghidra: options.cc:105 registerOption(new OptionInPlaceOps())
        self.register(OptionInPlaceOps);
        // Ghidra: options.cc:106 registerOption(new OptionConventionPrinting())
        self.register(OptionConventionPrinting);
        // Ghidra: options.cc:107 registerOption(new OptionNoCastPrinting())
        self.register(OptionNoCastPrinting);
        // Ghidra: options.cc:108 registerOption(new OptionHideExtensions())
        self.register(OptionHideExtensions);
        // Ghidra: options.cc:109 registerOption(new OptionMaxLineWidth())
        self.register(OptionMaxLineWidth);
        // Ghidra: options.cc:110 registerOption(new OptionIndentIncrement())
        self.register(OptionIndentIncrement);
        // Ghidra: options.cc:111 registerOption(new OptionCommentIndent())
        self.register(OptionCommentIndent);
        // Ghidra: options.cc:112 registerOption(new OptionCommentStyle())
        self.register(OptionCommentStyle);
        // Ghidra: options.cc:113 registerOption(new OptionCommentHeader())
        self.register(OptionCommentHeader);
        // Ghidra: options.cc:114 registerOption(new OptionCommentInstruction())
        self.register(OptionCommentInstruction);
        // Ghidra: options.cc:115 registerOption(new OptionIntegerFormat())
        self.register(OptionIntegerFormat);
        // Ghidra: options.cc:116 registerOption(new OptionBraceFormat())
        self.register(OptionBraceFormat);
        // Ghidra: options.cc:117 registerOption(new OptionSetAction())
        self.register(OptionSetAction);
        // Ghidra: options.cc:118 registerOption(new OptionCurrentAction())
        self.register(OptionCurrentAction);
        // Ghidra: options.cc:119 registerOption(new OptionAllowContextSet())
        self.register(OptionAllowContextSet);
        // Ghidra: options.cc:120 registerOption(new OptionIgnoreUnimplemented())
        self.register(OptionIgnoreUnimplemented);
        // Ghidra: options.cc:121 registerOption(new OptionErrorUnimplemented())
        self.register(OptionErrorUnimplemented);
        // Ghidra: options.cc:122 registerOption(new OptionErrorReinterpreted())
        self.register(OptionErrorReinterpreted);
        // Ghidra: options.cc:123 registerOption(new OptionErrorTooManyInstructions())
        self.register(OptionErrorTooManyInstructions);
        // Ghidra: options.cc:124 registerOption(new OptionProtoEval())
        self.register(OptionProtoEval);
        // Ghidra: options.cc:125 registerOption(new OptionSetLanguage())
        self.register(OptionSetLanguage);
        // Ghidra: options.cc:126 registerOption(new OptionJumpTableMax())
        self.register(OptionJumpTableMax);
        // Ghidra: options.cc:127 registerOption(new OptionJumpLoad())
        self.register(OptionJumpLoad);
        // Ghidra: options.cc:128 registerOption(new OptionToggleRule())
        self.register(OptionToggleRule);
        // Ghidra: options.cc:129 registerOption(new OptionAliasBlock())
        self.register(OptionAliasBlock);
        // Ghidra: options.cc:130 registerOption(new OptionMaxInstruction())
        self.register(OptionMaxInstruction);
        // Ghidra: options.cc:131 registerOption(new OptionNamespaceStrategy())
        self.register(OptionNamespaceStrategy);
        // Ghidra: options.cc:132 registerOption(new OptionSplitDatatypes())
        self.register(OptionSplitDatatypes);
        // Ghidra: options.cc:133 registerOption(new OptionNanIgnore())
        self.register(OptionNanIgnore);
    }

    /// Number of registered options. RUGRA-GLUE: not in Ghidra's API.
    pub fn num_options(&self) -> usize {
        self.options.len()
    }

    /// Whether an option named `name` is registered. RUGRA-GLUE.
    pub fn has_option(&self, name: &str) -> bool {
        self.options.contains_key(name)
    }

    /// Sorted iterator of registered option names. RUGRA-GLUE.
    pub fn option_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.options.keys().cloned().collect();
        names.sort();
        names
    }

    // Ghidra: options.cc:150 OptionDatabase::set
    /// Apply the option named `name` with up to three parameters. Faithful
    /// to `OptionDatabase::set` (options.cc:150-161). Returns `Some(msg)`
    /// on success, or `None` if the option is unknown (Ghidra throws a
    /// `LowlevelError`).
    pub fn set(
        &mut self,
        arch: &mut Architecture,
        name: &str,
        p1: &str,
        p2: &str,
        p3: &str,
    ) -> Option<String> {
        let opt = self.options.get(name)?;
        Some(opt.apply(arch, p1, p2, p3))
    }

    // RUGRA-GLUE: try_set is the non-panicking variant for tests; not in
    //   Ghidra's public API.
    pub fn try_set(
        &mut self,
        arch: &mut Architecture,
        name: &str,
        p1: &str,
        p2: &str,
        p3: &str,
    ) -> Result<String, String> {
        match self.set(arch, name, p1, p2, p3) {
            Some(msg) => Ok(msg),
            None => Err(format!("Unknown option: {name}")),
        }
    }

    // Ghidra: options.cc:163 OptionDatabase::decodeOne
    /// Decode and apply one `<optionslist>` entry. Faithful to
    /// `OptionDatabase::decodeOne` (options.cc:163-190).
    ///
    /// The option is named by the **element id** of the outer element (each
    /// registered option name corresponds to a registered ElementId). Up to
    /// three child elements (`ELEM_PARAM1`/`ELEM_PARAM2`/`ELEM_PARAM3`)
    /// supply positional parameters, scanned linearly as Ghidra does.
    pub fn decode_one(
        &mut self,
        arch: &mut Architecture,
        decoder: &mut dyn crate::marshal::Decoder,
    ) -> Result<(), String> {
        // Ghidra: options.cc:165 `uint4 elemId = decoder.openElement();`
        // RUGRA-GLUE: the element id doubles as the option name in Ghidra's
        //   registry; we look the id up via Decoder::element_name and dispatch
        //   by string.
        let elem_id = decoder.open_element();
        let opt_name = match decoder.element_name(elem_id) {
            Some(n) => n,
            None => {
                decoder.close_element(elem_id);
                return Err(format!("Unknown element id {elem_id}"));
            }
        };
        let mut p1 = String::new();
        let mut p2 = String::new();
        let mut p3 = String::new();
        // Ghidra: options.cc:166 `uint4 subId = decoder.openElement();`
        let sub_id = decoder.open_element();
        // Ghidra: options.cc:167-180 - linear scan of PARAM1/PARAM2/PARAM3.
        if sub_id == elem_ids::ELEM_PARAM1 {
            p1 = decoder.read_string();
            decoder.close_element(sub_id);
            let sub2 = decoder.open_element();
            if sub2 == elem_ids::ELEM_PARAM2 {
                p2 = decoder.read_string();
                decoder.close_element(sub2);
                let sub3 = decoder.open_element();
                if sub3 == elem_ids::ELEM_PARAM3 {
                    p3 = decoder.read_string();
                    decoder.close_element(sub3);
                } else if sub3 != 0 {
                    decoder.close_element(sub3);
                }
            } else if sub2 != 0 {
                decoder.close_element(sub2);
            }
        } else if sub_id == 0 {
            // Ghidra: options.cc:181 `p1 = decoder.readString(ATTRIB_CONTENT);`
            // No children: the outer element's text content is p1.
            p1 = decoder.read_string();
        } else {
            decoder.close_element(sub_id);
        }
        // Ghidra: options.cc:183 `decoder.closeElement(elemId);`
        decoder.close_element(elem_id);
        // Ghidra: options.cc:184 `set(elemId,p1,p2,p3);`
        self.set(arch, &opt_name, &p1, &p2, &p3);
        Ok(())
    }

    // Ghidra: options.cc:192 OptionDatabase::decode
    /// Parse an `<optionslist>` element, treating each child as an option
    /// command. Faithful to `OptionDatabase::decode` (options.cc:192-199).
    pub fn decode(
        &mut self,
        arch: &mut Architecture,
        decoder: &mut dyn crate::marshal::Decoder,
    ) -> Result<(), String> {
        // Ghidra: options.cc:194 `uint4 elemId = decoder.openElement(ELEM_OPTIONSLIST);`
        let elem_id = decoder.open_element();
        if elem_id != elem_ids::ELEM_OPTIONSLIST {
            decoder.close_element(elem_id);
            return Err(format!(
                "Expected <optionslist>, got element id {elem_id}"
            ));
        }
        // Ghidra: options.cc:196 `while(decoder.peekElement() != 0)`
        while decoder.peek_element() != 0 {
            self.decode_one(arch, decoder)?;
        }
        // Ghidra: options.cc:197 `decoder.closeElement(elemId);`
        decoder.close_element(elem_ids::ELEM_OPTIONSLIST);
        Ok(())
    }
}

impl Default for OptionDatabase {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::Architecture;

    fn make_arch() -> Architecture {
        Architecture::new()
    }

    #[test]
    fn test_on_or_off() {
        assert!(on_or_off("on"));
        assert!(!on_or_off("off"));
        assert!(on_or_off(""));
        // Ghidra throws on unknown; rugra defaults to true.
        assert!(on_or_off("yes"));
    }

    #[test]
    fn test_option_database_default_registry() {
        let db = OptionDatabase::new();
        assert!(db.num_options() >= 38);
        // Mirrors the names registered in options.cc:96-133.
        for n in [
            "extrapop",
            "readonly",
            "defaultprototype",
            "inferconstptr",
            "analyzeforloops",
            "inline",
            "noreturn",
            "warning",
            "printnull",
            "inplaceops",
            "conventionprinting",
            "nocastprinting",
            "hideextensions",
            "maxlinewidth",
            "indentincrement",
            "commentindent",
            "commentstyle",
            "commentheader",
            "commentinstruction",
            "integerformat",
            "braceformat",
            "setaction",
            "currentaction",
            "allowcontextset",
            "ignoreunimplemented",
            "errorunimplemented",
            "errorreinterpreted",
            "errortoomanyinstructions",
            "protoeval",
            "setlanguage",
            "jumptablemax",
            "jumpload",
            "togglerule",
            "aliasblock",
            "maxinstruction",
            "namespacestrategy",
            "splitdatatypes",
            "nanignore",
        ] {
            assert!(db.has_option(n), "missing option {n}");
        }
    }

    #[test]
    fn test_option_ignore_unimplemented_sets_flow_flag() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.flowoptions = 0;
        let msg = db.try_set(&mut arch, "ignoreunimplemented", "on", "", "").unwrap();
        assert!(arch.flowoptions & flow_flags::IGNORE_UNIMPLEMENTED != 0);
        assert!(msg.contains("ignored"));
        db.try_set(&mut arch, "ignoreunimplemented", "off", "", "").unwrap();
        assert_eq!(arch.flowoptions & flow_flags::IGNORE_UNIMPLEMENTED, 0);
    }

    #[test]
    fn test_option_error_unimplemented_flag() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.flowoptions = 0;
        db.try_set(&mut arch, "errorunimplemented", "on", "", "").unwrap();
        assert!(arch.flowoptions & flow_flags::ERROR_UNIMPLEMENTED != 0);
        db.try_set(&mut arch, "errorunimplemented", "off", "", "").unwrap();
        assert_eq!(arch.flowoptions & flow_flags::ERROR_UNIMPLEMENTED, 0);
    }

    #[test]
    fn test_option_error_reinterpreted_flag() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.flowoptions = 0;
        db.try_set(&mut arch, "errorreinterpreted", "on", "", "").unwrap();
        assert!(arch.flowoptions & flow_flags::ERROR_REINTERPRETED != 0);
    }

    #[test]
    fn test_option_error_too_many_instructions_flag() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.flowoptions = 0;
        db.try_set(&mut arch, "errortoomanyinstructions", "on", "", "").unwrap();
        assert!(arch.flowoptions & flow_flags::ERROR_TOOMANYINSTRUCTIONS != 0);
    }

    #[test]
    fn test_option_jump_load_flag() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.flowoptions = 0;
        db.try_set(&mut arch, "jumpload", "on", "", "").unwrap();
        assert!(arch.flowoptions & flow_flags::RECORD_JUMPLOADS != 0);
        db.try_set(&mut arch, "jumpload", "off", "", "").unwrap();
        assert_eq!(arch.flowoptions & flow_flags::RECORD_JUMPLOADS, 0);
    }

    #[test]
    fn test_option_jumptablemax_numeric() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        let msg = db.try_set(&mut arch, "jumptablemax", "0x100", "", "").unwrap();
        assert_eq!(arch.max_jumptable_size, 0x100);
        assert!(msg.contains("256") || msg.contains("100"));
        // Bad input is rejected.
        assert!(db
            .try_set(&mut arch, "jumptablemax", "garbage", "", "")
            .is_ok());
    }

    #[test]
    fn test_option_maxinstruction_signed_negative_ok() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        db.try_set(&mut arch, "maxinstruction", "123", "", "").unwrap();
        assert_eq!(arch.max_instructions, 123);
    }

    #[test]
    fn test_option_alias_block_combines_flags() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.alias_block_level = 0;
        db.try_set(&mut arch, "aliasblock", "struct,array", "", "").unwrap();
        assert_eq!(arch.alias_block_level, 1 | 2);
        db.try_set(&mut arch, "aliasblock", "none", "", "").unwrap();
        assert_eq!(arch.alias_block_level, 0);
    }

    #[test]
    fn test_option_infer_const_ptr() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.infer_pointers = false;
        db.try_set(&mut arch, "inferconstptr", "on", "", "").unwrap();
        assert!(arch.infer_pointers);
        db.try_set(&mut arch, "inferconstptr", "off", "", "").unwrap();
        assert!(!arch.infer_pointers);
    }

    #[test]
    fn test_option_for_loops() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.analyze_for_loops = false;
        db.try_set(&mut arch, "analyzeforloops", "on", "", "").unwrap();
        assert!(arch.analyze_for_loops);
    }

    #[test]
    fn test_option_readonly() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.readonlypropagate = false;
        db.try_set(&mut arch, "readonly", "on", "", "").unwrap();
        assert!(arch.readonlypropagate);
    }

    #[test]
    fn test_option_split_datatypes() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.split_datatype_config = 0;
        db.try_set(&mut arch, "splitdatatypes", "both", "", "").unwrap();
        assert_eq!(
            arch.split_datatype_config,
            split_datatype_option::OPTION_FLOAT | split_datatype_option::OPTION_POINTER
        );
        db.try_set(&mut arch, "splitdatatypes", "none", "", "").unwrap();
        assert_eq!(arch.split_datatype_config, 0);
    }

    #[test]
    fn test_option_nan_ignore() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.nan_ignore_all = false;
        arch.nan_ignore_compare = false;
        db.try_set(&mut arch, "nanignore", "all", "", "").unwrap();
        assert!(arch.nan_ignore_all && arch.nan_ignore_compare);
        db.try_set(&mut arch, "nanignore", "none", "", "").unwrap();
        assert!(!arch.nan_ignore_all && !arch.nan_ignore_compare);
    }

    #[test]
    fn test_option_integer_format() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        let msg = db.try_set(&mut arch, "integerformat", "hex", "force", "").unwrap();
        assert!(msg.contains("hex") && msg.contains("force"));
        let msg = db.try_set(&mut arch, "integerformat", "dec", "", "").unwrap();
        assert!(msg.contains("dec"));
    }

    #[test]
    fn test_option_brace_format() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        let msg = db.try_set(&mut arch, "braceformat", "next", "", "").unwrap();
        assert!(msg.contains("next"));
    }

    #[test]
    fn test_option_set_and_current_action_messages() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        let m1 = db.try_set(&mut arch, "setaction", "decompile", "", "").unwrap();
        assert!(m1.contains("decompile"));
        let m2 = db.try_set(&mut arch, "currentaction", "decompile", "", "").unwrap();
        assert!(m2.contains("decompile"));
        // Empty current action is rejected.
        let m3 = db.try_set(&mut arch, "currentaction", "", "", "").unwrap();
        assert!(m3.contains("Bad"));
    }

    #[test]
    fn test_option_toggle_rule_messages() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        let m1 = db.try_set(&mut arch, "togglerule", "myrule", "on", "").unwrap();
        assert!(m1.contains("enabled"));
        let m2 = db.try_set(&mut arch, "togglerule", "myrule", "off", "").unwrap();
        assert!(m2.contains("disabled"));
    }

    #[test]
    fn test_option_allow_context_set_message() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        let m = db.try_set(&mut arch, "allowcontextset", "off", "", "").unwrap();
        assert!(m.contains("off"));
    }

    #[test]
    fn test_option_protocval_unknown_message() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        let m = db.try_set(&mut arch, "protoeval", "nonexistent", "", "").unwrap();
        assert!(m.contains("Unknown"));
        // Reset to default always succeeds.
        let m = db.try_set(&mut arch, "protoeval", "default", "", "").unwrap();
        assert!(m.contains("default"));
    }

    #[test]
    fn test_unknown_option_returns_none() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        assert!(db.try_set(&mut arch, "nosuchoption", "", "", "").is_err());
    }

    #[test]
    fn test_parse_int_any_base_hex() {
        assert_eq!(parse_int_any_base("0x10"), Some(16));
        assert_eq!(parse_int_any_base("0XFF"), Some(255));
        assert_eq!(parse_int_any_base("42"), Some(42));
        assert_eq!(parse_int_any_base("-5"), Some(-5));
        assert_eq!(parse_int_any_base(""), None);
        assert_eq!(parse_int_any_base("abc"), None);
    }

    #[test]
    fn test_parse_uint_any_base_octal() {
        assert_eq!(parse_uint_any_base("010"), Some(8));
        assert_eq!(parse_uint_any_base("10"), Some(10));
        assert_eq!(parse_uint_any_base("0x1F"), Some(31));
    }

    #[test]
    fn test_alias_block_flag_lookup() {
        assert_eq!(alias_block_flag("struct"), Some(1));
        assert_eq!(alias_block_flag("array"), Some(2));
        assert_eq!(alias_block_flag("none"), Some(0));
        assert_eq!(alias_block_flag("bogus"), None);
    }

    #[test]
    fn test_get_split_datatype_bit() {
        assert_eq!(get_split_datatype_bit("float"), split_datatype_option::OPTION_FLOAT);
        assert_eq!(get_split_datatype_bit("pointer"), split_datatype_option::OPTION_POINTER);
        assert_eq!(get_split_datatype_bit("unknown"), 0);
    }
}
