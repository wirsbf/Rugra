//! x86-64 disassembler implementation using iced-x86
//!
//! This module provides x86-64 disassembly using the iced-x86 library,
//! which is a fast and accurate x86/x64 disassembler written in Rust.

use super::{Disassembler, Instruction, InstructionMetadata, Operand};
use crate::{Address, Architecture, Error, Result};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction as IcedInstruction, NasmFormatter};
use iced_x86::{FlowControl, OpKind, Register};

/// x86-64 disassembler using iced-x86
pub struct X86_64Disassembler {
    /// Decoder options
    options: u32,
}

impl X86_64Disassembler {
    // RUGRA-GLUE: src/disasm/x86_64.rs helper (no direct Ghidra counterpart)
    /// Create a new x86-64 disassembler
    pub fn new() -> Self {
        X86_64Disassembler {
            options: DecoderOptions::NONE,
        }
    }

    // RUGRA-GLUE: src/disasm/x86_64.rs helper (no direct Ghidra counterpart)
    /// Create with custom decoder options
    pub fn with_options(options: u32) -> Self {
        X86_64Disassembler { options }
    }

    // RUGRA-GLUE: src/disasm/x86_64.rs helper (no direct Ghidra counterpart)
    /// Convert iced-x86 instruction to our Instruction type
    fn convert_instruction(
        &self,
        iced_inst: &IcedInstruction,
        address: Address,
    ) -> Result<Instruction> {
        let mut inst = Instruction::new(address);

        // Basic info
        inst.length = iced_inst.len();
        inst.mnemonic = format!("{:?}", iced_inst.mnemonic()).to_lowercase();

        // Format the full instruction
        let mut formatter = NasmFormatter::new();
        let mut output = String::new();
        formatter.format(iced_inst, &mut output);
        inst.text = output;

        // Instruction bytes are not directly available from IcedInstruction without original buffer
        inst.bytes = Vec::new();

        // Extract operands
        inst.operands = self.extract_operands(iced_inst);

        // Build metadata
        inst.metadata = self.build_metadata(iced_inst, address);

        Ok(inst)
    }

    // RUGRA-GLUE: src/disasm/x86_64.rs helper (no direct Ghidra counterpart)
    /// Extract operands from iced instruction
    fn extract_operands(&self, inst: &IcedInstruction) -> Vec<Operand> {
        let mut operands = Vec::new();

        for i in 0..inst.op_count() {
            let op = match inst.op_kind(i) {
                OpKind::Register => {
                    let reg = inst.op_register(i);
                    Some(Operand::Register {
                        name: format!("{:?}", reg).to_lowercase(),
                        size: reg.size(),
                    })
                }
                OpKind::Immediate8
                | OpKind::Immediate16
                | OpKind::Immediate32
                | OpKind::Immediate64
                | OpKind::Immediate8to16
                | OpKind::Immediate8to32
                | OpKind::Immediate8to64
                | OpKind::Immediate32to64 => {
                    let value = inst.immediate(i) as i64;
                    let size = self.get_immediate_size(inst.op_kind(i));
                    Some(Operand::Immediate { value, size })
                }
                OpKind::Memory => {
                    let base = if inst.memory_base() != Register::None {
                        Some(format!("{:?}", inst.memory_base()).to_lowercase())
                    } else if inst.segment_prefix() == Register::FS {
                        // Segment-absolute addressing (mov rax,fs:[0x28]): iced
                        // reports base=None + explicit FS prefix (segment_prefix;
                        // memory_segment defaults to DS/SS when unprefixed, so
                        // the explicit prefix is the discriminator). Route
                        // through the x86-64.sla FS spacebase register
                        // (FS_OFFSET = register:0x110:8, dumped via
                        // examples/rip_probe.rs) so the lifted address is
                        // INT_ADD(in_FS_OFFSET, disp) — the form both golden
                        // baselines print as `*(undefined8 *)(in_FS_OFFSET +
                        // 0x28)`. Without this the segment was dropped and the
                        // load folded to a bare absolute Ram@0x28 (CONCATRAM
                        // lane: canary-load uRam family root).
                        Some("fs_offset".to_string())
                    } else if inst.segment_prefix() == Register::GS {
                        // GS spacebase: register:0x118:8 (GS_OFFSET).
                        Some("gs_offset".to_string())
                    } else {
                        None
                    };

                    let index = if inst.memory_index() != Register::None {
                        Some(format!("{:?}", inst.memory_index()).to_lowercase())
                    } else {
                        None
                    };

                    Some(Operand::Memory {
                        base,
                        index,
                        scale: inst.memory_index_scale() as i32,
                        displacement: inst.memory_displacement64() as i64,
                        size: inst.memory_size().size(),
                    })
                }
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    let target = inst.near_branch64() as i64;
                    Some(Operand::Immediate { value: target, size: 8 })
                }
                _ => None,
            };

            if let Some(operand) = op {
                operands.push(operand);
            }
        }

        operands
    }

    // RUGRA-GLUE: src/disasm/x86_64.rs helper (no direct Ghidra counterpart)
    /// Get the size of an immediate operand
    fn get_immediate_size(&self, op_kind: OpKind) -> usize {
        match op_kind {
            OpKind::Immediate8 | OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64 => 1,
            OpKind::Immediate16 => 2,
            OpKind::Immediate32 | OpKind::Immediate32to64 => 4,
            OpKind::Immediate64 => 8,
            _ => 0,
        }
    }

    // RUGRA-GLUE: src/disasm/x86_64.rs helper (no direct Ghidra counterpart)
    /// Build instruction metadata
    fn build_metadata(&self, inst: &IcedInstruction, address: Address) -> InstructionMetadata {
        let mut metadata = InstructionMetadata::default();

        // Determine control flow type
        match inst.flow_control() {
            FlowControl::Next => {
                // Normal instruction, falls through to next
            }
            FlowControl::UnconditionalBranch => {
                metadata.is_branch = true;
                metadata.is_conditional = false;
                if let Some(target) = self.get_branch_target(inst, address) {
                    metadata.branch_target = Some(target);
                }
            }
            FlowControl::ConditionalBranch => {
                metadata.is_branch = true;
                metadata.is_conditional = true;
                if let Some(target) = self.get_branch_target(inst, address) {
                    metadata.branch_target = Some(target);
                }
            }
            FlowControl::Call => {
                metadata.is_call = true;
                if let Some(target) = self.get_branch_target(inst, address) {
                    metadata.branch_target = Some(target);
                }
            }
            FlowControl::Return => {
                metadata.is_return = true;
            }
            FlowControl::IndirectBranch | FlowControl::IndirectCall => {
                metadata.is_branch = true;
                metadata.is_call = inst.flow_control() == FlowControl::IndirectCall;
            }
            _ => {}
        }

        // Check memory access
        for i in 0..inst.op_count() {
            if inst.op_kind(i) == OpKind::Memory {
                // Determine if read or write based on op index
                // Typically, op0 is destination (write), others are source (read)
                if i == 0 {
                    metadata.writes_memory = true;
                } else {
                    metadata.reads_memory = true;
                }
            }
        }

        // Extract register usage
        for i in 0..inst.op_count() {
            if let OpKind::Register = inst.op_kind(i) {
                let reg_name = format!("{:?}", inst.op_register(i)).to_lowercase();
                if i == 0 {
                    // First operand is typically destination
                    metadata.writes_registers.push(reg_name);
                } else {
                    // Other operands are typically source
                    metadata.reads_registers.push(reg_name);
                }
            }
        }

        metadata
    }

    // RUGRA-GLUE: src/disasm/x86_64.rs helper (no direct Ghidra counterpart)
    /// Get branch/call target address
    fn get_branch_target(&self, inst: &IcedInstruction, _current_addr: Address) -> Option<Address> {
        // Check if it's a near branch with immediate
        if inst.op_count() > 0 {
            match inst.op_kind(0) {
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    let target = inst.near_branch64();
                    return Some(Address::new(target));
                }
                _ => {}
            }
        }

        None
    }
}

impl Default for X86_64Disassembler {
    // RUGRA-GLUE: src/disasm/x86_64.rs helper (no direct Ghidra counterpart)
    fn default() -> Self {
        Self::new()
    }
}

impl Disassembler for X86_64Disassembler {
    // RUGRA-GLUE: src/disasm/x86_64.rs helper (no direct Ghidra counterpart)
    fn disassemble(&mut self, code: &[u8], start_address: Address) -> Result<Vec<Instruction>> {
        let mut decoder = Decoder::with_ip(64, code, start_address.as_u64(), self.options);
        let mut instructions = Vec::new();

        while decoder.can_decode() {
            let iced_inst = decoder.decode();
            let address = Address::new(iced_inst.ip());

            match self.convert_instruction(&iced_inst, address) {
                Ok(inst) => instructions.push(inst),
                Err(e) => {
                    // Log error but continue disassembly
                    eprintln!("Warning: Failed to convert instruction at {}: {}", address, e);
                }
            }
        }

        Ok(instructions)
    }

    // RUGRA-GLUE: src/disasm/x86_64.rs helper (no direct Ghidra counterpart)
    fn disassemble_one(&mut self, code: &[u8], address: Address) -> Result<(Instruction, usize)> {
        if code.is_empty() {
            return Err(Error::DisassemblyError("Empty code buffer".into()));
        }

        let mut decoder = Decoder::with_ip(64, code, address.as_u64(), self.options);

        if !decoder.can_decode() {
            return Err(Error::DisassemblyError("Cannot decode instruction".into()));
        }

        let iced_inst = decoder.decode();
        let inst = self.convert_instruction(&iced_inst, address)?;
        let length = inst.length;

        Ok((inst, length))
    }

    // RUGRA-GLUE: src/disasm/x86_64.rs helper (no direct Ghidra counterpart)
    fn architecture(&self) -> Architecture {
        Architecture::X86_64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassemble_mov() {
        // mov rax, rbx (48 89 d8)
        let code = vec![0x48, 0x89, 0xd8];
        let mut disasm = X86_64Disassembler::new();

        let result = disasm.disassemble(&code, Address::new(0x1000));
        assert!(result.is_ok());

        let instructions = result.unwrap();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].length, 3);
        assert!(instructions[0].text.contains("rax"));
        assert!(instructions[0].text.contains("rbx"));
    }

    #[test]
    fn test_disassemble_add() {
        // add rax, rbx (48 01 d8)
        let code = vec![0x48, 0x01, 0xd8];
        let mut disasm = X86_64Disassembler::new();

        let result = disasm.disassemble(&code, Address::new(0x1000));
        assert!(result.is_ok());

        let instructions = result.unwrap();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].mnemonic, "add");
    }

    #[test]
    fn test_disassemble_ret() {
        // ret (c3)
        let code = vec![0xc3];
        let mut disasm = X86_64Disassembler::new();

        let result = disasm.disassemble(&code, Address::new(0x1000));
        assert!(result.is_ok());

        let instructions = result.unwrap();
        assert_eq!(instructions.len(), 1);
        assert!(instructions[0].is_return());
    }

    #[test]
    fn test_disassemble_call() {
        // call rel32 (e8 00 00 00 00)
        let code = vec![0xe8, 0x00, 0x00, 0x00, 0x00];
        let mut disasm = X86_64Disassembler::new();

        let result = disasm.disassemble(&code, Address::new(0x1000));
        assert!(result.is_ok());

        let instructions = result.unwrap();
        assert_eq!(instructions.len(), 1);
        assert!(instructions[0].is_call());
    }

    #[test]
    fn test_disassemble_jmp() {
        // jmp rel8 (eb 00)
        let code = vec![0xeb, 0x00];
        let mut disasm = X86_64Disassembler::new();

        let result = disasm.disassemble(&code, Address::new(0x1000));
        assert!(result.is_ok());

        let instructions = result.unwrap();
        assert_eq!(instructions.len(), 1);
        assert!(instructions[0].is_branch());
        assert!(!instructions[0].metadata.is_conditional);
    }

    #[test]
    fn test_disassemble_multiple() {
        // mov rax, rbx; add rax, rcx; ret
        let code = vec![
            0x48, 0x89, 0xd8, // mov rax, rbx
            0x48, 0x01, 0xc8, // add rax, rcx
            0xc3,             // ret
        ];
        let mut disasm = X86_64Disassembler::new();

        let result = disasm.disassemble(&code, Address::new(0x1000));
        assert!(result.is_ok());

        let instructions = result.unwrap();
        assert_eq!(instructions.len(), 3);
        assert_eq!(instructions[0].address.as_u64(), 0x1000);
        assert_eq!(instructions[1].address.as_u64(), 0x1003);
        assert_eq!(instructions[2].address.as_u64(), 0x1006);
    }

    #[test]
    fn test_disassemble_one() {
        // mov rax, rbx
        let code = vec![0x48, 0x89, 0xd8, 0x90, 0x90]; // extra nops
        let mut disasm = X86_64Disassembler::new();

        let result = disasm.disassemble_one(&code, Address::new(0x1000));
        assert!(result.is_ok());

        let (inst, length) = result.unwrap();
        assert_eq!(length, 3);
        assert_eq!(inst.address.as_u64(), 0x1000);
    }

    #[test]
    fn test_empty_buffer() {
        let code = vec![];
        let mut disasm = X86_64Disassembler::new();

        let result = disasm.disassemble_one(&code, Address::new(0x1000));
        assert!(result.is_err());
    }

    #[test]
    fn test_architecture() {
        let disasm = X86_64Disassembler::new();
        assert_eq!(disasm.architecture(), Architecture::X86_64);
    }
}
