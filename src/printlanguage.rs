//! Base language printing interface
//!
//! Corresponds to Ghidra's `printlanguage.hh`

use crate::prettyprint::Emit;
use crate::op::PcodeOp;
use crate::varnode::Varnode;
use crate::type_system::Datatype;
use crate::fspec::FuncProto;
use crate::block::BlockGraph;
use std::sync::{Arc, RwLock};

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

    // --- Type emission ---

    /// Emit a type name
    fn push_type(&mut self, dt: &Datatype);

    /// Emit a variable name
    fn push_varnode(&mut self, vn: &Varnode, _op: Option<&PcodeOp>);
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
