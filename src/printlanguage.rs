//! Base language printing interface
//!
//! Corresponds to Ghidra's `printlanguage.hh`

use crate::prettyprint::Emit;
use crate::op::PcodeOp;
use crate::varnode::Varnode;
use crate::type_system::Datatype;
use crate::fspec::FuncProto;
// use crate::block::BlockGraph;
// use std::sync::{Arc, RwLock};

/// Trait for emitting decompiled code in a specific source language
///
/// Corresponds to Ghidra's `PrintLanguage` class. This trait provides
/// the interface for converting P-code and other IR structures into
/// human-readable source code.
pub trait PrintLanguage {
    // RUGRA-GLUE: get_emit (no Ghidra counterpart found)
    /// Get the underlying token emitter
    fn get_emit(&mut self) -> &mut dyn Emit;

    // RUGRA-GLUE: set_emit (no Ghidra counterpart found)
    /// Set the underlying token emitter
    fn set_emit(&mut self, emit: Box<dyn Emit>);

    // RUGRA-GLUE: doc_function (no Ghidra counterpart found)
    /// Emit a full function
    fn doc_function(&mut self, fd: &crate::funcdata::Funcdata);

    // RUGRA-GLUE: doc_all_proto (no Ghidra counterpart found)
    /// Emit a function prototype
    fn doc_all_proto(&mut self, proto: &FuncProto);

    // RUGRA-GLUE: doc_variable_decl (no Ghidra counterpart found)
    /// Emit a variable declaration
    fn doc_variable_decl(&mut self, vn: &Varnode);

    // RUGRA-GLUE: doc_statement (no Ghidra counterpart found)
    /// Emit a statement
    fn doc_statement(&mut self, op: &PcodeOp);

    // --- P-code Op-code specific emission ---
    // These are called by TypeOp::push()

    // RUGRA-GLUE: op_copy (no Ghidra counterpart found)
    /// Emit a COPY operation
    fn op_copy(&mut self, op: &PcodeOp);
    // RUGRA-GLUE: op_load (no Ghidra counterpart found)
    /// Emit a LOAD operation
    fn op_load(&mut self, op: &PcodeOp);
    // RUGRA-GLUE: op_store (no Ghidra counterpart found)
    /// Emit a STORE operation
    fn op_store(&mut self, op: &PcodeOp);
    // RUGRA-GLUE: op_binary (no Ghidra counterpart found)
    /// Emit a binary operation
    fn op_binary(&mut self, op: &PcodeOp);
    // RUGRA-GLUE: op_unary (no Ghidra counterpart found)
    /// Emit a unary operation
    fn op_unary(&mut self, op: &PcodeOp);

    // RUGRA-GLUE: op_multiequal (no Ghidra counterpart found)
    /// Emit a MULTIEQUAL (Phi) operation
    fn op_multiequal(&mut self, op: &PcodeOp);
    // RUGRA-GLUE: op_indirect (no Ghidra counterpart found)
    /// Emit an INDIRECT operation
    fn op_indirect(&mut self, op: &PcodeOp);

    // RUGRA-GLUE: op_call (no Ghidra counterpart found)
    /// Emit a CALL operation
    fn op_call(&mut self, op: &PcodeOp);
    // RUGRA-GLUE: op_return (no Ghidra counterpart found)
    /// Emit a RETURN operation
    fn op_return(&mut self, op: &PcodeOp);
    // RUGRA-GLUE: op_cbranch (no Ghidra counterpart found)
    /// Emit a CBRANCH (conditional branch) operation
    fn op_cbranch(&mut self, op: &PcodeOp);
    // RUGRA-GLUE: op_branch (no Ghidra counterpart found)
    /// Emit a BRANCH (unconditional branch / goto) operation
    fn op_branch(&mut self, op: &PcodeOp);

    // --- Type emission ---

    // RUGRA-GLUE: push_type (no Ghidra counterpart found)
    /// Emit a type name
    fn push_type(&mut self, dt: &Datatype);

    // RUGRA-GLUE: push_varnode (no Ghidra counterpart found)
    /// Emit a variable name
    fn push_varnode(&mut self, vn: &Varnode, _op: Option<&PcodeOp>);

    // --- Scope / formatting management (printlanguage.cc:84-698) ---

    // RUGRA-GLUE: reset_defaults (no Ghidra counterpart found)
    /// Reset the printer to default state.
    /// Faithful to PrintLanguage::resetDefaults (cc:671).
    fn reset_defaults(&mut self) {}

    // RUGRA-GLUE: clear (no Ghidra counterpart found)
    /// Clear internal state for a new function.
    /// Faithful to PrintLanguage::clear (cc:678).
    fn clear(&mut self) {}

    // RUGRA-GLUE: set_packed_output (no Ghidra counterpart found)
    /// Set whether to use packed (single-line) output.
    /// Faithful to PrintLanguage::setPackedOutput (cc:653).
    fn set_packed_output(&mut self, _val: bool) {}

    // RUGRA-GLUE: set_flat (no Ghidra counterpart found)
    /// Set whether to flatten nested scopes.
    /// Faithful to PrintLanguage::setFlat (cc:662).
    fn set_flat(&mut self, _val: bool) {}

    // RUGRA-GLUE: pop_scope (no Ghidra counterpart found)
    /// Pop the current scope level.
    /// Faithful to PrintLanguage::popScope (cc:113).
    fn pop_scope(&mut self) {}

    // RUGRA-GLUE: emit_line_comment (no Ghidra counterpart found)
    /// Emit a line comment.
    /// Faithful to PrintLanguage::emitLineComment (cc:589).
    fn emit_line_comment(&mut self, _indent: i32, _text: &str) {}
}

// RUGRA-GLUE: escape_character_data (no Ghidra counterpart found)
/// Escape special characters in string data for C output.
/// Faithful to PrintLanguage::escapeCharacterData (printlanguage.cc:498).
pub fn escape_character_data(buf: &[u8], charsize: usize) -> String {
    let mut result = String::new();
    for &b in buf {
        match b {
            b'"' => result.push_str("\\\""),
            b'\\' => result.push_str("\\\\"),
            b'\n' => result.push_str("\\n"),
            b'\r' => result.push_str("\\r"),
            b'\t' => result.push_str("\\t"),
            0x20..=0x7e => result.push(b as char),
            _ => result.push_str(&format!("\\x{:02x}", b)),
        }
        let _ = charsize; // multi-byte chars not fully supported
    }
    result
}

/// Capability object for registering language printers
pub struct PrintLanguageCapability {
    pub name: String,
}

impl PrintLanguageCapability {
    // Ghidra: printlanguage.hh:42 PrintLanguageCapability::new
    pub fn new(name: &str) -> Self {
        Self { name: name.to_string() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_character_data() {
        assert_eq!(escape_character_data(b"hello", 1), "hello");
        assert_eq!(escape_character_data(b"a\"b", 1), "a\\\"b");
        assert_eq!(escape_character_data(b"a\nb", 1), "a\\nb");
        assert_eq!(escape_character_data(&[0x00, 0x41], 1), "\\x00A");
    }

    #[test]
    fn test_capability() {
        let cap = PrintLanguageCapability::new("c");
        assert_eq!(cap.name, "c");
    }
}
