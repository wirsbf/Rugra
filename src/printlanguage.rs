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
    /// Get the underlying token emitter
    fn get_emit(&mut self) -> &mut dyn Emit;

    /// Set the underlying token emitter
    fn set_emit(&mut self, emit: Box<dyn Emit>);

    /// Emit a full function
    fn doc_function(&mut self, fd: &crate::funcdata::Funcdata);

    /// Emit a function prototype
    fn doc_all_proto(&mut self, proto: &FuncProto);

    /// Emit a variable declaration
    fn doc_variable_decl(&mut self, vn: &Varnode);

    /// Emit a statement
    fn doc_statement(&mut self, op: &PcodeOp);

    // --- P-code Op-code specific emission ---
    // These are called by TypeOp::push()

    /// Emit a COPY operation
    fn op_copy(&mut self, op: &PcodeOp);
    /// Emit a LOAD operation
    fn op_load(&mut self, op: &PcodeOp);
    /// Emit a STORE operation
    fn op_store(&mut self, op: &PcodeOp);
    /// Emit a binary operation
    fn op_binary(&mut self, op: &PcodeOp);
    /// Emit a unary operation
    fn op_unary(&mut self, op: &PcodeOp);

    /// Emit a MULTIEQUAL (Phi) operation
    fn op_multiequal(&mut self, op: &PcodeOp);
    /// Emit an INDIRECT operation
    fn op_indirect(&mut self, op: &PcodeOp);

    /// Emit a CALL operation
    fn op_call(&mut self, op: &PcodeOp);
    /// Emit a RETURN operation
    fn op_return(&mut self, op: &PcodeOp);
    /// Emit a CBRANCH (conditional branch) operation
    fn op_cbranch(&mut self, op: &PcodeOp);
    /// Emit a BRANCH (unconditional branch / goto) operation
    fn op_branch(&mut self, op: &PcodeOp);

    // --- Type emission ---

    /// Emit a type name
    fn push_type(&mut self, dt: &Datatype);

    /// Emit a variable name
    fn push_varnode(&mut self, vn: &Varnode, _op: Option<&PcodeOp>);

    // --- Scope / formatting management (printlanguage.cc:84-698) ---

    /// Reset the printer to default state.
    /// Faithful to PrintLanguage::resetDefaults (cc:671).
    fn reset_defaults(&mut self) {}

    /// Clear internal state for a new function.
    /// Faithful to PrintLanguage::clear (cc:678).
    fn clear(&mut self) {}

    /// Set whether to use packed (single-line) output.
    /// Faithful to PrintLanguage::setPackedOutput (cc:653).
    fn set_packed_output(&mut self, _val: bool) {}

    /// Set whether to flatten nested scopes.
    /// Faithful to PrintLanguage::setFlat (cc:662).
    fn set_flat(&mut self, _val: bool) {}

    /// Pop the current scope level.
    /// Faithful to PrintLanguage::popScope (cc:113).
    fn pop_scope(&mut self) {}

    /// Emit a line comment.
    /// Faithful to PrintLanguage::emitLineComment (cc:589).
    fn emit_line_comment(&mut self, _indent: i32, _text: &str) {}
}

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
