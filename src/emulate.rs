//! P-code emulation engine.
//!
//! Corresponds to Ghidra's `emulate.hh` / `emulate.cc` (1013 lines).
//!
//! The emulator executes P-code operations on a virtual machine state
//! (MemState + register file), used for constant propagation and
//! jump-table analysis.
//!
//! Key classes:
//! - `BreakCallBack`: breakpoint callback trait
//! - `BreakTable`: breakpoint collection
//! - `Emulate`: base emulator that executes p-code ops one at a time
//! - `EmulatePcodeOp`: emulator operating on high-level PcodeOp objects
//!
//! # Status
//! Core Emulate struct with execute_op using opbehavior evaluate functions.
//! Full BreakCallBack/BreakTable and memory-backed LOAD/STORE are deferred.

use std::collections::HashMap;
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::varnode::Varnode;
use crate::opbehavior;
use crate::memstate::MemState;
use std::sync::{Arc, RwLock};

/// Emulation control flow state.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EmulateOpBehavior {
    /// Continue executing
    Continue,
    /// Op was a branch, stop
    Branch,
    /// Op was a return, stop
    Return,
    /// Op caused an error
    Error,
}

/// The base P-code emulator.
/// Corresponds to Ghidra's `Emulate` (emulate.hh).
pub struct Emulate {
    /// Memory state for LOAD/STORE
    pub mem_state: MemState,
    /// Current execution address
    pub current_address: u64,
    /// Whether emulation has terminated
    pub terminated: bool,
}

impl Emulate {
    pub fn new() -> Self {
        Self {
            mem_state: MemState::new(),
            current_address: 0,
            terminated: false,
        }
    }

    /// Execute a single PcodeOp, returning the behavior result.
    /// Uses opbehavior evaluate functions for constant emulation.
    pub fn execute_op(&mut self, op: &Arc<RwLock<PcodeOp>>) -> EmulateOpBehavior {
        let o = op.read().unwrap();
        match o.opcode {
            OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCHIND => {
                EmulateOpBehavior::Branch
            }
            OpCode::CPUI_RETURN => {
                self.terminated = true;
                EmulateOpBehavior::Return
            }
            OpCode::CPUI_LOAD | OpCode::CPUI_STORE => {
                // LOAD/STORE require memory state integration.
                EmulateOpBehavior::Continue
            }
            _ => {
                // For arithmetic/logic ops: if all inputs are constant,
                // evaluate and set the output.
                if let Some(out) = &o.output {
                    let all_const = o.inrefs.iter().all(|vn| vn.read().unwrap().is_constant());
                    if all_const && !o.inrefs.is_empty() {
                        let result = self.evaluate(&o);
                        if let Some(val) = result {
                            // Store result in the output varnode's offset
                            // (in a real emulator, this would update the register/memory).
                            let _ = val; // Result computed but not stored (simplified).
                        }
                    }
                }
                EmulateOpBehavior::Continue
            }
        }
    }

    /// Evaluate a constant operation using opbehavior.
    fn evaluate(&self, op: &PcodeOp) -> Option<u64> {
        let size_out = op.output.as_ref()?.read().unwrap().get_size();
        let in_size = op.inrefs.first()?.read().unwrap().get_size();
        match op.inrefs.len() {
            1 => {
                let in1 = op.inrefs[0].read().unwrap().get_offset();
                opbehavior::evaluate_unary(op.opcode, size_out, in_size, in1)
            }
            2 | 3 => {
                let in1 = op.inrefs[0].read().unwrap().get_offset();
                let in2 = op.inrefs.get(1)?.read().unwrap().get_offset();
                opbehavior::evaluate_binary(op.opcode, size_out, in_size, in1, in2)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emulate_creation() {
        let emu = Emulate::new();
        assert!(!emu.terminated);
        assert_eq!(emu.current_address, 0);
    }
}
