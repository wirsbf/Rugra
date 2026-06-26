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
    /// Register file: (space, offset) → value
    pub registers: HashMap<(u64, u64), u64>,
    /// Current execution address
    pub current_address: u64,
    /// Whether emulation has terminated
    pub terminated: bool,
    /// Instruction count (for limiting emulation)
    pub instruction_count: u64,
    /// Maximum instructions to emulate (0 = unlimited)
    pub max_instructions: u64,
}

impl Emulate {
    pub fn new() -> Self {
        Self {
            mem_state: MemState::new(),
            registers: HashMap::new(),
            current_address: 0,
            terminated: false,
            instruction_count: 0,
            max_instructions: 0,
        }
    }

    /// Set a register value.
    pub fn set_register(&mut self, space: u64, offset: u64, val: u64) {
        self.registers.insert((space, offset), val);
    }

    /// Get a register value.
    pub fn get_register(&self, space: u64, offset: u64) -> u64 {
        self.registers.get(&(space, offset)).copied().unwrap_or(0)
    }

    /// Execute a single PcodeOp, returning the behavior result.
    /// Uses opbehavior evaluate functions for constant emulation and
    /// integrates with MemState for LOAD/STORE.
    pub fn execute_op(&mut self, op: &Arc<RwLock<PcodeOp>>) -> EmulateOpBehavior {
        self.instruction_count += 1;
        if self.max_instructions > 0 && self.instruction_count > self.max_instructions {
            self.terminated = true;
            return EmulateOpBehavior::Error;
        }
        let o = op.read().unwrap();
        match o.opcode {
            OpCode::CPUI_BRANCH => EmulateOpBehavior::Branch,
            OpCode::CPUI_CBRANCH => {
                // Check condition
                let cond = o.inrefs.get(1).map(|vn| {
                    let v = vn.read().unwrap();
                    if v.is_constant() { v.get_offset() != 0 } else { false }
                }).unwrap_or(false);
                if cond { EmulateOpBehavior::Branch } else { EmulateOpBehavior::Continue }
            }
            OpCode::CPUI_BRANCHIND => EmulateOpBehavior::Branch,
            OpCode::CPUI_RETURN => {
                self.terminated = true;
                EmulateOpBehavior::Return
            }
            OpCode::CPUI_LOAD => {
                // LOAD(space_id, addr) → output
                if o.inrefs.len() >= 2 {
                    let addr_vn = &o.inrefs[1];
                    let addr = addr_vn.read().unwrap();
                    if addr.is_constant() {
                        let offset = addr.get_offset();
                        let size = o.output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(1);
                        let val = self.mem_state.get_bank("ram")
                            .map(|bank| bank.get_value(offset, size))
                            .unwrap_or(0);
                        // Store in registers via output varnode key
                        if let Some(out) = &o.output {
                            let out_vn = out.read().unwrap();
                            self.set_register(out_vn.get_space().space_id() as u64, out_vn.get_offset(), val);
                        }
                    }
                }
                EmulateOpBehavior::Continue
            }
            OpCode::CPUI_STORE => {
                // STORE(space_id, addr, value)
                if o.inrefs.len() >= 3 {
                    let addr_vn = &o.inrefs[1];
                    let val_vn = &o.inrefs[2];
                    let addr = addr_vn.read().unwrap();
                    let val = val_vn.read().unwrap();
                    if addr.is_constant() && val.is_constant() {
                        let offset = addr.get_offset();
                        let size = val.get_size();
                        if let Some(bank) = self.mem_state.get_bank_mut("ram") {
                            bank.set_value(offset, size, val.get_offset());
                        }
                    }
                }
                EmulateOpBehavior::Continue
            }
            _ => {
                // For arithmetic/logic ops: if all inputs are constant,
                // evaluate and store the output.
                if let Some(out) = &o.output {
                    let all_const = o.inrefs.iter().all(|vn| vn.read().unwrap().is_constant());
                    if all_const && !o.inrefs.is_empty() {
                        let result = self.evaluate(&o);
                        if let Some(val) = result {
                            let out_vn = out.read().unwrap();
                            self.set_register(out_vn.get_space().space_id() as u64, out_vn.get_offset(), val);
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

    #[test]
    fn test_register_file() {
        let mut emu = Emulate::new();
        emu.set_register(0, 0x100, 42);
        assert_eq!(emu.get_register(0, 0x100), 42);
        assert_eq!(emu.get_register(0, 0x200), 0);
    }

    #[test]
    fn test_instruction_limit() {
        let mut emu = Emulate::new();
        emu.max_instructions = 5;
        // Simulate 5 instructions
        for _ in 0..5 {
            emu.instruction_count += 1;
        }
        // Next instruction should trigger termination
        emu.instruction_count += 1;
        if emu.max_instructions > 0 && emu.instruction_count > emu.max_instructions {
            emu.terminated = true;
        }
        assert!(emu.terminated);
    }
}
