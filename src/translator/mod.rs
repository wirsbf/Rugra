//! Instruction to P-code translation module
//!
//! This module handles the translation of architecture-specific instructions
//! into P-code intermediate representation. It bridges the gap between
//! disassembled machine code and our architecture-independent IR.
//!
//! # Architecture
//!
//! ```text
//! Disassembled Instruction → Translator → P-code Operations
//!                               ↓
//!                         Register Map
//!                         Flag Handling
//!                         Operand Conversion
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use rugra::translator::{Translator, X86_64Translator};
//! use rugra::disasm::Instruction;
//! use rugra::Address;
//!
//! # fn example() -> rugra::Result<()> {
//! let translator = X86_64Translator::new();
//! // instruction: mov rax, rbx
//! // let inst = ...;
//! // let pcode_ops = translator.translate(&inst)?;
//! # Ok(())
//! # }
//! ```

mod x86_64;
mod registers;

pub use x86_64::X86_64Translator;
pub use registers::{RegisterMap, X86_64RegisterMap};

use crate::{Architecture, Result, Error};
use crate::disasm::Instruction;
use crate::pcode::{PcodeOperation, PcodeOp, Varnode, SeqNum};

/// Trait for instruction translators
///
/// Implementers of this trait convert architecture-specific instructions
/// into sequences of P-code operations.
pub trait Translator {
    /// Translate a single instruction into P-code operations
    ///
    /// # Arguments
    ///
    /// * `instruction` - The disassembled instruction to translate
    ///
    /// # Returns
    ///
    /// A vector of P-code operations representing this instruction
    fn translate(&self, instruction: &Instruction) -> Result<Vec<PcodeOperation>>;

    /// Get the architecture this translator supports
    fn architecture(&self) -> Architecture;

    /// Get the register map for this architecture
    fn register_map(&self) -> &dyn RegisterMap;
}

/// Create a translator for the given architecture
///
/// # Arguments
///
/// * `arch` - Target architecture
///
/// # Returns
///
/// A boxed translator instance
pub fn create_translator(arch: Architecture) -> Result<Box<dyn Translator>> {
    match arch {
        Architecture::X86_64 => Ok(Box::new(X86_64Translator::new())),
        Architecture::X86 => {
            Err(Error::UnsupportedArchitecture(
                "x86 32-bit translator not yet implemented".into(),
            ))
        }
        _ => Err(Error::UnsupportedArchitecture(format!(
            "{} translator not yet implemented",
            arch
        ))),
    }
}

/// Helper struct for building P-code operations during translation
pub struct PcodeBuilder {
    /// Current operation ID counter
    next_id: u64,
    /// Current unique varnode ID counter
    next_unique: u64,
    /// Accumulated operations
    operations: Vec<PcodeOperation>,
}

impl PcodeBuilder {
    /// Create a new P-code builder
    pub fn new() -> Self {
        PcodeBuilder {
            next_id: 0,
            next_unique: 0,
            operations: Vec::new(),
        }
    }

    /// Create a new unique varnode
    pub fn new_unique(&mut self, size: usize) -> Varnode {
        let id = self.next_unique;
        self.next_unique += 1;
        Varnode::new_unique(id, size)
    }

    /// Add a P-code operation
    pub fn add_op(
        &mut self,
        seqnum: SeqNum,
        opcode: PcodeOp,
        output: Option<Varnode>,
        inputs: Vec<Varnode>,
    ) {
        let id = crate::pcode::PcodeId::new(self.next_id);
        self.next_id += 1;

        let op = PcodeOperation::new(id, seqnum, opcode, output, inputs);
        self.operations.push(op);
    }

    /// Build and return all operations
    pub fn build(self) -> Vec<PcodeOperation> {
        self.operations
    }

    /// Get the current operation count
    pub fn op_count(&self) -> usize {
        self.operations.len()
    }
}

impl Default for PcodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcode_builder() {
        let mut builder = PcodeBuilder::new();

        let temp = builder.new_unique(4);
        assert_eq!(builder.op_count(), 0);

        let seqnum = SeqNum::new(crate::Address::new(0x1000), 0);
        builder.add_op(
            seqnum,
            PcodeOp::Copy,
            Some(temp.clone()),
            vec![Varnode::new_register(0, 4)],
        );

        assert_eq!(builder.op_count(), 1);

        let ops = builder.build();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].opcode(), PcodeOp::Copy);
    }

    #[test]
    fn test_create_translator_x64() {
        let translator = create_translator(Architecture::X86_64);
        assert!(translator.is_ok());
        assert_eq!(translator.unwrap().architecture(), Architecture::X86_64);
    }

    #[test]
    fn test_create_translator_unsupported() {
        let translator = create_translator(Architecture::ARM);
        assert!(translator.is_err());
    }

    #[test]
    fn test_unique_varnode_generation() {
        let mut builder = PcodeBuilder::new();
        let vn1 = builder.new_unique(4);
        let vn2 = builder.new_unique(8);

        assert_ne!(vn1, vn2);
        assert_eq!(vn1.size(), 4);
        assert_eq!(vn2.size(), 8);
    }
}
