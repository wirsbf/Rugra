//! Disassembly module for Rugra
//!
//! This module provides architecture-specific disassemblers for converting
//! machine code into instructions that can be translated to P-code.
//!
//! Currently supported architectures:
//! - x86-64 (via iced-x86)
//!
//! # Example
//!
//! ```rust,no_run
//! use rugra::disasm::{Disassembler, X86_64Disassembler};
//! use rugra::Address;
//!
//! # fn example() -> rugra::Result<()> {
//! let code = vec![0x48, 0x89, 0xc3]; // mov rbx, rax
//! let mut disasm = X86_64Disassembler::new();
//! let instructions = disasm.disassemble(&code, Address::new(0x1000))?;
//! # Ok(())
//! # }
//! ```

mod x86_64;
pub mod x86_lift;
pub mod sleigh_lift;

pub use x86_64::X86_64Disassembler;
pub use x86_lift::X86Lifter;

use std::fmt;
use crate::{Address, Architecture, Result};

/// A disassembled instruction
#[derive(Debug, Clone)]
pub struct Instruction {
    /// Address of the instruction
    pub address: Address,

    /// Raw bytes of the instruction
    pub bytes: Vec<u8>,

    /// Instruction length in bytes
    pub length: usize,

    /// Mnemonic (e.g., "mov", "add", "jmp")
    pub mnemonic: String,

    /// Full instruction string (e.g., "mov rax, rbx")
    pub text: String,

    /// Operands
    pub operands: Vec<Operand>,

    /// Instruction metadata
    pub metadata: InstructionMetadata,
}

impl Instruction {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    /// Create a new instruction
    pub fn new(address: Address) -> Self {
        Instruction {
            address,
            bytes: Vec::new(),
            length: 0,
            mnemonic: String::new(),
            text: String::new(),
            operands: Vec::new(),
            metadata: InstructionMetadata::default(),
        }
    }

    // RUGRA-GLUE: is_branch (no Ghidra counterpart found)
    /// Check if this is a branch instruction
    pub fn is_branch(&self) -> bool {
        self.metadata.is_branch
    }

    // RUGRA-GLUE: is_call (no Ghidra counterpart found)
    /// Check if this is a call instruction
    pub fn is_call(&self) -> bool {
        self.metadata.is_call
    }

    // RUGRA-GLUE: is_return (no Ghidra counterpart found)
    /// Check if this is a return instruction
    pub fn is_return(&self) -> bool {
        self.metadata.is_return
    }

    // RUGRA-GLUE: next_address (no Ghidra counterpart found)
    /// Get the next instruction address (if not a branch)
    pub fn next_address(&self) -> Address {
        self.address.offset(self.length as i64)
    }

    // RUGRA-GLUE: branch_target (no Ghidra counterpart found)
    /// Get the branch target (if this is a branch/call)
    pub fn branch_target(&self) -> Option<Address> {
        self.metadata.branch_target
    }
}

impl fmt::Display for Instruction {
    // RUGRA-GLUE: fmt (no Ghidra counterpart found)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text)
    }
}

/// Instruction operand
#[derive(Debug, Clone)]
pub enum Operand {
    /// Register operand
    Register {
        name: String,
        size: usize,
    },
    /// Immediate value
    Immediate {
        value: i64,
        size: usize,
    },
    /// Memory reference
    Memory {
        base: Option<String>,
        index: Option<String>,
        scale: i32,
        displacement: i64,
        size: usize,
    },
}

impl fmt::Display for Operand {
    // RUGRA-GLUE: fmt (no Ghidra counterpart found)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::Register { name, .. } => write!(f, "{}", name),
            Operand::Immediate { value, .. } => write!(f, "0x{:x}", value),
            Operand::Memory {
                base,
                index,
                scale,
                displacement,
                ..
            } => {
                write!(f, "[")?;
                let mut first = true;
                if let Some(b) = base {
                    write!(f, "{}", b)?;
                    first = false;
                }
                if let Some(idx) = index {
                    if !first {
                        write!(f, " + ")?;
                    }
                    write!(f, "{}*{}", idx, scale)?;
                    first = false;
                }
                if *displacement != 0 {
                    if !first {
                        if *displacement > 0 {
                            write!(f, " + ")?;
                        } else {
                            write!(f, " - ")?;
                        }
                    }
                    write!(f, "0x{:x}", displacement.abs())?;
                }
                write!(f, "]")
            }
        }
    }
}

/// Metadata about an instruction
#[derive(Debug, Clone, Default)]
pub struct InstructionMetadata {
    /// Is this a branch instruction?
    pub is_branch: bool,

    /// Is this a conditional branch?
    pub is_conditional: bool,

    /// Is this a call instruction?
    pub is_call: bool,

    /// Is this a return instruction?
    pub is_return: bool,

    /// Branch/call target address (if known)
    pub branch_target: Option<Address>,

    /// Does this instruction read memory?
    pub reads_memory: bool,

    /// Does this instruction write memory?
    pub writes_memory: bool,

    /// Registers read by this instruction
    pub reads_registers: Vec<String>,

    /// Registers written by this instruction
    pub writes_registers: Vec<String>,
}

/// Trait for architecture-specific disassemblers
pub trait Disassembler {
    // RUGRA-GLUE: disassemble (no Ghidra counterpart found)
    /// Disassemble a block of code
    ///
    /// # Arguments
    ///
    /// * `code` - Raw machine code bytes
    /// * `start_address` - Virtual address of the first byte
    ///
    /// # Returns
    ///
    /// Vector of disassembled instructions
    fn disassemble(&mut self, code: &[u8], start_address: Address) -> Result<Vec<Instruction>>;

    // RUGRA-GLUE: disassemble_one (no Ghidra counterpart found)
    /// Disassemble a single instruction
    ///
    /// # Arguments
    ///
    /// * `code` - Raw machine code bytes (should contain at least one instruction)
    /// * `address` - Virtual address of the instruction
    ///
    /// # Returns
    ///
    /// Disassembled instruction and number of bytes consumed
    fn disassemble_one(&mut self, code: &[u8], address: Address) -> Result<(Instruction, usize)>;

    // RUGRA-GLUE: architecture (no Ghidra counterpart found)
    /// Get the architecture this disassembler supports
    fn architecture(&self) -> Architecture;
}

// RUGRA-GLUE: create_disassembler (no Ghidra counterpart found)
/// Create a disassembler for the given architecture
pub fn create_disassembler(arch: Architecture) -> Result<Box<dyn Disassembler>> {
    match arch {
        Architecture::X86_64 => Ok(Box::new(X86_64Disassembler::new())),
        Architecture::X86 => {
            // TODO: Implement x86 32-bit support
            Err(crate::Error::UnsupportedArchitecture(
                "x86 32-bit not yet implemented".into(),
            ))
        }
        _ => Err(crate::Error::UnsupportedArchitecture(format!(
            "{} not yet implemented",
            arch
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_creation() {
        let inst = Instruction::new(Address::new(0x1000));
        assert_eq!(inst.address.as_u64(), 0x1000);
        assert!(!inst.is_branch());
        assert!(!inst.is_call());
        assert!(!inst.is_return());
    }

    #[test]
    fn test_next_address() {
        let mut inst = Instruction::new(Address::new(0x1000));
        inst.length = 5;
        assert_eq!(inst.next_address().as_u64(), 0x1005);
    }

    #[test]
    fn test_create_disassembler_x64() {
        let disasm = create_disassembler(Architecture::X86_64);
        assert!(disasm.is_ok());
    }

    #[test]
    fn test_create_disassembler_unsupported() {
        let disasm = create_disassembler(Architecture::ARM);
        assert!(disasm.is_err());
    }
}
