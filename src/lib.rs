//! # Rugra - Rust Ghidra-inspired Decompiler
//!
//! A high-performance, memory-safe decompiler for C/C++ binaries written in Rust.
//! Rugra aims to provide production-quality decompilation with a focus on correctness,
//! performance, and extensibility.
//!
//! ## Architecture
//!
//! ```text
//! Binary → Loader → Disassembler → P-code IR → Analysis → AST → C Code
//!    ↓                   ↓             ↓          ↓        ↓       ↓
//!   ELF              x86/ARM        SSA Form    CFG      Types   Output
//!   PE               MIPS           Optimizer   DFA
//!   Mach-O
//! ```
//!
//! ## Modules
//!
//! - [`binary`] - Binary parsing and loading (ELF, PE, Mach-O)
//! - [`pcode`] - P-code intermediate representation
//! - [`analysis`] - Control flow, data flow, and type analysis
//! - [`codegen`] - C code generation
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use rugra::{Decompiler, Architecture};
//!
//! # fn main() -> anyhow::Result<()> {
//! // Load a binary
//! let binary_data = std::fs::read("program.exe")?;
//!
//! // Create decompiler
//! let mut decompiler = Decompiler::new(Architecture::X86_64)?;
//! decompiler.load_binary(&binary_data)?;
//!
//! // Decompile a function
//! let c_code = decompiler.decompile_function(0x401000)?;
//! println!("{}", c_code);
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]
#![allow(dead_code)] // During development

// Core Ghidra-aligned modules
pub mod address;       // ← address.hh
pub mod space;         // ← space.hh
pub mod varnode;       // ← varnode.hh
pub mod op;            // ← op.hh
pub mod opcodes;       // ← opcodes.hh
pub mod typeop;        // ← typeop.hh
pub mod heritage;      // ← heritage.hh
pub mod fspec;         // ← fspec.hh
pub mod block;         // ← block.hh
pub mod funcdata;      // ← funcdata.hh
pub mod pcoderaw;      // ← pcoderaw.hh
pub mod type_system;   // ← type.hh
pub mod prettyprint;    // ← prettyprint.hh
pub mod printlanguage; // ← printlanguage.hh
pub mod printc;        // ← printc.hh
pub mod action;        // ← action.hh
pub mod coreaction;    // ← coreaction.hh
pub mod ruleaction;    // ← ruleaction.hh
pub mod cover;         // ← cover.hh
pub mod variable;      // ← variable.hh
pub mod merge;         // ← merge.hh
pub mod blockaction;   // ← blockaction.hh

// Temporarily disabled - legacy modules using old Program API
// TODO: Update these to use new Arc<RwLock<>> architecture
// pub mod binary;
// pub mod pcode;
// pub mod analysis;
// pub mod codegen;
// pub mod disasm;
// pub mod translator;
// pub mod ffi;
// pub mod align;

mod error;
mod types;
mod utils;

// Re-exports
pub use error::{Error, Result};
pub use address::{Address, SeqNum, Range, RangeList, RangeProperties};
pub use block::{BlockBasic, BlockRef, BlockEdge};
pub use funcdata::Funcdata;
pub use fspec::{FuncProto, ProtoParameter};
pub use space::AddressSpace;
pub use opcodes::OpCode;
pub use types::Architecture;
pub use type_system::{Datatype, TypeMetatype};

// use std::collections::HashMap;

// Temporarily disabled - Decompiler uses old Program API
// TODO: Reimplement using new VarnodeBank/PcodeOpBank architecture
/*
/// Main decompiler interface
///
/// This is the primary entry point for using Rugra. It orchestrates the entire
/// decompilation pipeline from binary loading to C code generation.
///
/// # Example
///
/// ```rust,no_run
/// use rugra::{Decompiler, Architecture};
///
/// # fn main() -> anyhow::Result<()> {
/// let mut dec = Decompiler::new(Architecture::X86_64)?;
/// dec.load_binary(&std::fs::read("binary")?)?;
/// let code = dec.decompile_function(0x1000)?;
/// # Ok(())
/// # }
/// ```
pub struct Decompiler {
    /// Target architecture
    arch: Architecture,

    /// Loaded binary
    binary: Option<binary::Binary>,

    /// P-code programs for each function
    pcode_cache: HashMap<Address, pcode::Program>,

    /// Analysis results cache
    analysis_cache: HashMap<Address, analysis::FunctionAnalysis>,
}

impl Decompiler {
    /// Create a new decompiler for the specified architecture
    ///
    /// # Arguments
    ///
    /// * `arch` - Target architecture (X86_64, ARM64, etc.)
    ///
    /// # Returns
    ///
    /// A new decompiler instance
    pub fn new(arch: Architecture) -> Result<Self> {
        Ok(Self {
            arch,
            binary: None,
            pcode_cache: HashMap::new(),
            analysis_cache: HashMap::new(),
        })
    }

    /// Load a binary file for analysis
    ///
    /// # Arguments
    ///
    /// * `data` - Raw binary data
    ///
    /// # Returns
    ///
    /// Result indicating success or failure
    pub fn load_binary(&mut self, data: &[u8]) -> Result<()> {
        let binary = binary::Binary::parse(data)?;
        self.binary = Some(binary);
        Ok(())
    }

    /// Decompile a function at the given address
    ///
    /// # Arguments
    ///
    /// * `address` - Virtual address of the function entry point
    ///
    /// # Returns
    ///
    /// Decompiled C code as a string
    pub fn decompile_function(&mut self, address: u64) -> Result<String> {
        let addr = Address::new(address);

        // Ensure binary is loaded
        let binary = self.binary.as_ref()
            .ok_or(Error::NoBinaryLoaded)?;

        // Get or generate P-code
        if !self.pcode_cache.contains_key(&addr) {
            let pcode = self.generate_pcode(binary, addr)?;
            self.pcode_cache.insert(addr, pcode);
        }

        // Get or perform analysis
        if !self.analysis_cache.contains_key(&addr) {
            let pcode = self.pcode_cache.get_mut(&addr).expect("P-code not found");
            let analysis = analysis::analyze_function(pcode, Some(binary))?;
            self.analysis_cache.insert(addr, analysis);
        }

        // Generate C code
        let analysis = &self.analysis_cache[&addr];
        let pcode = self.pcode_cache.get(&addr).expect("P-code not found");
        let c_code = codegen::generate_c_code(analysis, pcode, self.binary.as_ref())?;

        Ok(c_code)
    }

    /// Get list of all functions in the binary
    ///
    /// # Returns
    ///
    /// Vector of function entry point addresses
    pub fn get_functions(&self) -> Result<Vec<Address>> {
        let binary = self.binary.as_ref()
            .ok_or(Error::NoBinaryLoaded)?;
        Ok(binary.get_functions())
    }

    /// Get the name of a function at the given address
    pub fn get_function_name(&self, addr: Address) -> Option<String> {
        self.binary.as_ref()?.get_function_name(addr).cloned()
    }

    /// Get the target architecture
    pub fn architecture(&self) -> Architecture {
        self.arch
    }

    /// Clear all caches
    pub fn clear_cache(&mut self) {
        self.pcode_cache.clear();
        self.analysis_cache.clear();
    }

    // Private helper methods

    fn generate_pcode(&self, binary: &binary::Binary, addr: Address) -> Result<pcode::Program> {
        use crate::translator::Translator;

        let instructions = binary.disassemble_function(addr, self.arch)?;

        // Create translator for architecture
        // Currently we primary support X86_64
        let translator = crate::translator::X86_64Translator::new();

        let mut program = pcode::Program::with_entry_point(addr);

        for instr in instructions {
            match translator.translate(&instr) {
                Ok(ops) => {
                    for op in ops {
                        program.add_operation(op);
                    }
                }
                Err(e) => {
                    log::warn!("Failed to translate instruction at {}: {}", instr.address, e);
                }
            }
        }

        Ok(program)
    }
}
*/

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Get the version string
pub fn version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    // Temporarily disabled - Decompiler is commented out
    // #[test]
    // fn test_decompiler_creation() {
    //     let dec = Decompiler::new(Architecture::X86_64);
    //     assert!(dec.is_ok());
    // }

    #[test]
    fn test_version() {
        assert!(!version().is_empty());
    }
}
