//! x86-64 to P-code lifter
//!
//! Translates disassembled x86-64 instructions into raw P-code operations.

use crate::disasm::Instruction;
use crate::opcodes::OpCode;
use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
use crate::space::AddressSpace;

/// Lifter for translating x86-64 instructions to P-code
pub struct X86Lifter {
    uniq_base: u64,
}

impl Default for X86Lifter {
    // RUGRA-GLUE: src/disasm/x86_lift.rs helper (no direct Ghidra counterpart)
    fn default() -> Self {
        Self::new()
    }
}

impl X86Lifter {
    // RUGRA-GLUE: src/disasm/x86_lift.rs helper (no direct Ghidra counterpart)
    pub fn new() -> Self {
        Self { uniq_base: 0x1000 }
    }

    // RUGRA-GLUE: src/disasm/x86_lift.rs helper (no direct Ghidra counterpart)
    /// Allocate a new unique temporary varnode
    fn alloc_tmp(&mut self, size: usize) -> VarnodeRaw {
        let offset = self.uniq_base;
        self.uniq_base += size as u64;
        VarnodeRaw::new(AddressSpace::Unique, offset, size)
    }

    // RUGRA-GLUE: src/disasm/x86_lift.rs helper (no direct Ghidra counterpart)
    /// Map a register name to a VarnodeRaw
    fn get_register(name: &str, size: usize) -> Option<VarnodeRaw> {
        let offset = match name {
            "rax" | "eax" | "ax" | "al" => 0x00,
            "rcx" | "ecx" | "cx" | "cl" => 0x08,
            "rdx" | "edx" | "dx" | "dl" => 0x10,
            "rbx" | "ebx" | "bx" | "bl" => 0x18,
            "rsp" | "esp" | "sp" | "spl" => 0x20,
            "rbp" | "ebp" | "bp" | "bpl" => 0x28,
            "rsi" | "esi" | "si" | "sil" => 0x30,
            "rdi" | "edi" | "di" | "dil" => 0x38,
            "r8" | "r8d" | "r8w" | "r8b" => 0x80,
            "r9" | "r9d" | "r9w" | "r9b" => 0x88,
            "r10" | "r10d" | "r10w" | "r10b" => 0x90,
            "r11" | "r11d" | "r11w" | "r11b" => 0x98,
            "r12" | "r12d" | "r12w" | "r12b" => 0xA0,
            "r13" | "r13d" | "r13w" | "r13b" => 0xA8,
            "r14" | "r14d" | "r14w" | "r14b" => 0xB0,
            "r15" | "r15d" | "r15w" | "r15b" => 0xB8,
            "rip" | "eip" => 0x200, // Instruction pointer
            _ => return None,
        };
        Some(VarnodeRaw::new(AddressSpace::Register, offset, size))
    }

    // RUGRA-GLUE: 寄存器名→偏移量映射（复用 get_register 的 match 表）。
    /// Map register name to offset (shared with get_register).
    fn reg_offset(name: &str) -> u64 {
        Self::get_register(name, 8).map(|v| v.offset).unwrap_or(0)
    }

    // RUGRA-GLUE: src/disasm/x86_lift.rs helper (no direct Ghidra counterpart)
    /// Parse an operand into a VarnodeRaw (emitting load from memory if necessary)
    fn parse_operand(
        &mut self,
        operand: &crate::disasm::Operand,
        ops: &mut Vec<PcodeOpRaw>,
    ) -> Option<VarnodeRaw> {
        match operand {
            crate::disasm::Operand::Register { name, size } => Self::get_register(name, *size),
            crate::disasm::Operand::Immediate { value, size } => {
                Some(VarnodeRaw::new(AddressSpace::Const, *value as u64, *size))
            }
            crate::disasm::Operand::Memory {
                base,
                index,
                scale,
                displacement,
                size,
            } => {
                // Address computation: base + index * scale + displacement
                let mut addr_vn: Option<VarnodeRaw> = None;

                if let Some(b) = base {
                    if let Some(reg) = Self::get_register(b, 8) {
                        // Assuming 64-bit bounds
                        addr_vn = Some(reg);
                    }
                }

                if let Some(idx) = index {
                    if let Some(reg_idx) = Self::get_register(idx, 8) {
                        let scaled = if *scale > 1 {
                            let tmp = self.alloc_tmp(8);
                            let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_MULT as i32);
                            op.add_input(reg_idx);
                            op.add_input(VarnodeRaw::new(AddressSpace::Const, *scale as u64, 8));
                            op.set_output(tmp.clone());
                            ops.push(op);
                            tmp
                        } else {
                            reg_idx
                        };

                        if let Some(a) = addr_vn {
                            let tmp = self.alloc_tmp(8);
                            let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
                            op.add_input(a);
                            op.add_input(scaled);
                            op.set_output(tmp.clone());
                            ops.push(op);
                            addr_vn = Some(tmp);
                        } else {
                            addr_vn = Some(scaled);
                        }
                    }
                }

                if *displacement != 0 {
                    let disp_vn = VarnodeRaw::new(AddressSpace::Const, *displacement as u64, 8);
                    if let Some(a) = addr_vn {
                        let tmp = self.alloc_tmp(8);
                        let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
                        op.add_input(a);
                        op.add_input(disp_vn);
                        op.set_output(tmp.clone());
                        ops.push(op);
                        addr_vn = Some(tmp);
                    } else {
                        addr_vn = Some(disp_vn);
                    }
                }

                if let Some(a) = addr_vn {
                    let tmp = self.alloc_tmp(*size);
                    let mut op = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
                    op.add_input(VarnodeRaw::new(
                        AddressSpace::Const,
                        AddressSpace::Ram.space_id() as u64,
                        8,
                    )); // address space ID
                    op.add_input(a);
                    op.set_output(tmp.clone());
                    ops.push(op);
                    Some(tmp)
                } else {
                    None
                }
            }
        }
    }

    // RUGRA-GLUE: src/disasm/x86_lift.rs helper (no direct Ghidra counterpart)
    /// Retrieve the destination operand (for writing)
    fn parse_dest_operand(
        &mut self,
        operand: &crate::disasm::Operand,
        ops: &mut Vec<PcodeOpRaw>,
    ) -> Option<(VarnodeRaw, Option<VarnodeRaw>)> {
        match operand {
            crate::disasm::Operand::Register { name, size } => {
                Self::get_register(name, *size).map(|v| (v, None))
            }
            crate::disasm::Operand::Memory {
                base,
                index,
                scale,
                displacement,
                size,
            } => {
                // Very similar to parse_operand but returns the address var
                let mut addr_vn: Option<VarnodeRaw> = None;

                if let Some(b) = base {
                    if let Some(reg) = Self::get_register(b, 8) {
                        addr_vn = Some(reg);
                    }
                }

                if let Some(idx) = index {
                    if let Some(reg_idx) = Self::get_register(idx, 8) {
                        let scaled = if *scale > 1 {
                            let tmp = self.alloc_tmp(8);
                            let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_MULT as i32);
                            op.add_input(reg_idx);
                            op.add_input(VarnodeRaw::new(AddressSpace::Const, *scale as u64, 8));
                            op.set_output(tmp.clone());
                            ops.push(op);
                            tmp
                        } else {
                            reg_idx
                        };

                        if let Some(a) = addr_vn {
                            let tmp = self.alloc_tmp(8);
                            let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
                            op.add_input(a);
                            op.add_input(scaled);
                            op.set_output(tmp.clone());
                            ops.push(op);
                            addr_vn = Some(tmp);
                        } else {
                            addr_vn = Some(scaled);
                        }
                    }
                }

                if *displacement != 0 {
                    let disp_vn = VarnodeRaw::new(AddressSpace::Const, *displacement as u64, 8);
                    if let Some(a) = addr_vn {
                        let tmp = self.alloc_tmp(8);
                        let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
                        op.add_input(a);
                        op.add_input(disp_vn);
                        op.set_output(tmp.clone());
                        ops.push(op);
                        addr_vn = Some(tmp);
                    } else {
                        addr_vn = Some(disp_vn);
                    }
                }

                if let Some(a) = addr_vn {
                    let size_vn = VarnodeRaw::new(AddressSpace::Const, *size as u64, 4);
                    Some((a, Some(size_vn))) // Address and size marker for memory store
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    // RUGRA-GLUE: src/disasm/x86_lift.rs helper (no direct Ghidra counterpart)
    /// Create a store operation
    fn emit_store(
        &mut self,
        addr_vn: VarnodeRaw,
        value_vn: VarnodeRaw,
        _size_vn: VarnodeRaw,
        ops: &mut Vec<PcodeOpRaw>,
    ) {
        let mut op = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        op.add_input(VarnodeRaw::new(
            AddressSpace::Const,
            AddressSpace::Ram.space_id() as u64,
            8,
        )); // Space ID
        op.add_input(addr_vn);
        op.add_input(value_vn);
        ops.push(op);
    }

    // RUGRA-GLUE: src/disasm/x86_lift.rs helper (no direct Ghidra counterpart)
    /// Lift a single instruction to P-code
    pub fn lift(&mut self, inst: &Instruction) -> Vec<PcodeOpRaw> {
        let mut ops = Vec::new();
        let mnemonic = inst.mnemonic.as_str();

        match mnemonic {
            "mov" | "movabs" => {
                if inst.operands.len() == 2 {
                    if let Some(src) = self.parse_operand(&inst.operands[1], &mut ops) {
                        if let Some((dst, mem_size)) =
                            self.parse_dest_operand(&inst.operands[0], &mut ops)
                        {
                            if let Some(size) = mem_size {
                                self.emit_store(dst, src, size, &mut ops);
                            } else {
                                let mut op = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
                                op.add_input(src);
                                op.set_output(dst);
                                ops.push(op);
                            }
                        }
                    }
                }
            }
            "add" | "sub" | "shl" | "shr" | "sal" | "sar" | "and" | "or" | "xor" => {
                if inst.operands.len() == 2 {
                    if let Some(src) = self.parse_operand(&inst.operands[1], &mut ops) {
                        if let Some((dst, mem_size)) =
                            self.parse_dest_operand(&inst.operands[0], &mut ops)
                        {
                            let dst_read = if mem_size.is_some() {
                                self.parse_operand(&inst.operands[0], &mut ops).unwrap()
                            } else {
                                dst.clone()
                            };

                            let opcode = match mnemonic {
                                "add" => OpCode::CPUI_INT_ADD,
                                "sub" => OpCode::CPUI_INT_SUB,
                                "shl" | "sal" => OpCode::CPUI_INT_LEFT,
                                "shr" => OpCode::CPUI_INT_RIGHT,
                                "sar" => OpCode::CPUI_INT_SRIGHT,
                                "and" => OpCode::CPUI_INT_AND,
                                "or" => OpCode::CPUI_INT_OR,
                                "xor" => OpCode::CPUI_INT_XOR,
                                _ => unreachable!(),
                            };

                            let tmp = self.alloc_tmp(dst_read.size);
                            let mut op = PcodeOpRaw::new(opcode as i32);
                            op.add_input(dst_read);
                            op.add_input(src);
                            op.set_output(tmp.clone());
                            ops.push(op);

                            if let Some(size) = mem_size {
                                self.emit_store(dst, tmp, size, &mut ops);
                            } else {
                                let mut cp = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
                                cp.add_input(tmp);
                                cp.set_output(dst);
                                ops.push(cp);
                            }
                        }
                    }
                }
            }
            "lea" => {
                if inst.operands.len() == 2 {
                    if let Some((dst, _)) = self.parse_dest_operand(&inst.operands[0], &mut ops) {
                        // Check for RIP-relative addressing: lea reg, [rip+disp]
                        // In PIE binaries, this is how global variables are addressed.
                        // Resolve to absolute address = inst_addr + inst_len + disp
                        // so that seed_global_struct_pointers can match known globals.
                        let resolved_addr_vn = match &inst.operands[1] {
                            crate::disasm::Operand::Memory { base, displacement, .. } => {
                                if base.as_deref() == Some("rip") && *displacement != 0 {
                                    let next_rip = inst.address.as_u64() + inst.length as u64;
                                    let abs_addr = next_rip.wrapping_add(*displacement as u64);
                                    Some(VarnodeRaw::new(AddressSpace::Ram, abs_addr, 8))
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        };
                        if let Some(addr_vn) = resolved_addr_vn.or_else(||
                            self.parse_dest_operand(&inst.operands[1], &mut ops).map(|(v,_)| v))
                        {
                            let mut op = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
                            op.add_input(addr_vn);
                            op.set_output(dst);
                            ops.push(op);
                        }
                    }
                }
            }
            "cmp" => {
                if inst.operands.len() == 2 {
                    if let Some(src) = self.parse_operand(&inst.operands[1], &mut ops) {
                        if let Some((dst_addr, mem_size)) =
                            self.parse_dest_operand(&inst.operands[0], &mut ops)
                        {
                            let dst = if mem_size.is_some() {
                                self.parse_operand(&inst.operands[0], &mut ops).unwrap()
                            } else {
                                dst_addr
                            };

                            // ZF = (dst == src)
                            let mut op_zf = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
                            op_zf.add_input(dst.clone());
                            op_zf.add_input(src.clone());
                            op_zf.set_output(VarnodeRaw::new(AddressSpace::Register, 0x201, 1));
                            ops.push(op_zf);

                            // CF = (dst < src) unsigned
                            let mut op_cf = PcodeOpRaw::new(OpCode::CPUI_INT_LESS as i32);
                            op_cf.add_input(dst.clone());
                            op_cf.add_input(src.clone());
                            op_cf.set_output(VarnodeRaw::new(AddressSpace::Register, 0x203, 1));
                            ops.push(op_cf);

                            // SF = (dst < src) signed
                            let mut op_sf = PcodeOpRaw::new(OpCode::CPUI_INT_SLESS as i32);
                            op_sf.add_input(dst);
                            op_sf.add_input(src);
                            op_sf.set_output(VarnodeRaw::new(AddressSpace::Register, 0x202, 1));
                            ops.push(op_sf);
                        }
                    }
                }
            }
            "test" => {
                if inst.operands.len() == 2 {
                    if let Some(src) = self.parse_operand(&inst.operands[1], &mut ops) {
                        if let Some((dst_addr, mem_size)) =
                            self.parse_dest_operand(&inst.operands[0], &mut ops)
                        {
                            let dst = if mem_size.is_some() {
                                self.parse_operand(&inst.operands[0], &mut ops).unwrap()
                            } else {
                                dst_addr
                            };

                            let tmp = self.alloc_tmp(dst.size);
                            let mut op_and = PcodeOpRaw::new(OpCode::CPUI_INT_AND as i32);
                            op_and.add_input(dst);
                            op_and.add_input(src);
                            op_and.set_output(tmp.clone());
                            ops.push(op_and);

                            // ZF = (tmp == 0)
                            let mut op_zf = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
                            op_zf.add_input(tmp.clone());
                            op_zf.add_input(VarnodeRaw::new(AddressSpace::Const, 0, tmp.size));
                            op_zf.set_output(VarnodeRaw::new(AddressSpace::Register, 0x201, 1));
                            ops.push(op_zf);

                            // SF = (tmp < 0) signed
                            let mut op_sf = PcodeOpRaw::new(OpCode::CPUI_INT_SLESS as i32);
                            op_sf.add_input(tmp.clone());
                            op_sf.add_input(VarnodeRaw::new(AddressSpace::Const, 0, tmp.size));
                            op_sf.set_output(VarnodeRaw::new(AddressSpace::Register, 0x202, 1));
                            ops.push(op_sf);
                        }
                    }
                }
            }
            "jmp" => {
                if inst.operands.len() == 1 {
                    match &inst.operands[0] {
                        crate::disasm::Operand::Immediate { value, .. } => {
                            let mut op = PcodeOpRaw::new(OpCode::CPUI_BRANCH as i32);
                            op.add_input(VarnodeRaw::new(AddressSpace::Ram, *value as u64, 8));
                            ops.push(op);
                        }
                        // Indirect jump through register or memory → CPUI_BRANCHIND.
                        // This enables switch/jump-table flow tracking.
                        _ => {
                            // For register operand, emit a LOAD from the register's
                            // value. For memory operand, emit LOAD.
                            // Simplified: just emit the raw register/memory varnode
                            // as the BRANCHIND target. The jump-table recovery in
                            // flow.rs will resolve it.
                            let target_vn = match &inst.operands[0] {
                                crate::disasm::Operand::Register { name, size } => {
                                    let offset = Self::reg_offset(name);
                                    VarnodeRaw::new(AddressSpace::Register, offset, *size)
                                }
                                crate::disasm::Operand::Memory { base, index, scale, displacement, size } => {
                                    // For memory operands like jmp [rip+disp], emit a LOAD
                                    // from the computed address. Simplified: just use the
                                    // displacement as the address for now.
                                    let addr_vn = if let Some(base_name) = base {
                                        let base_off = Self::reg_offset(base_name);
                                        let mut load_op = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
                                        load_op.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8)); // space const
                                        load_op.add_input(VarnodeRaw::new(AddressSpace::Register, base_off, 8));
                                        let tmp = self.alloc_tmp(*size);
                                        load_op.set_output(tmp.clone());
                                        ops.push(load_op);
                                        tmp
                                    } else {
                                        VarnodeRaw::new(AddressSpace::Ram, *displacement as u64, *size)
                                    };
                                    addr_vn
                                }
                                _ => {
                                    VarnodeRaw::new(AddressSpace::Unique, 0, 8)
                                }
                            };
                            let mut op = PcodeOpRaw::new(OpCode::CPUI_BRANCHIND as i32);
                            op.add_input(target_vn);
                            ops.push(op);
                        }
                    }
                }
            }
            "je" | "jz" | "jne" | "jnz" | "jl" | "jle" | "jg" | "jge" | "jb" | "ja" | "jbe"
            | "jae" => {
                if inst.operands.len() == 1 {
                    if let crate::disasm::Operand::Immediate { value, .. } = inst.operands[0] {
                        let target = VarnodeRaw::new(AddressSpace::Ram, value as u64, 8);
                        let zf = VarnodeRaw::new(AddressSpace::Register, 0x201, 1);
                        let sf = VarnodeRaw::new(AddressSpace::Register, 0x202, 1);
                        let cf = VarnodeRaw::new(AddressSpace::Register, 0x203, 1);

                        let cond_vn = match mnemonic {
                            "je" | "jz" => zf,
                            "jne" | "jnz" => {
                                let tmp = self.alloc_tmp(1);
                                let mut op_not = PcodeOpRaw::new(OpCode::CPUI_BOOL_NEGATE as i32); // Or we can use INT_EQUAL zf, 0
                                op_not.add_input(zf);
                                op_not.set_output(tmp.clone());
                                ops.push(op_not);
                                tmp
                            }
                            "jl" => {
                                // SF != OF, simplified to SF for now
                                sf
                            }
                            "jle" => {
                                // ZF || SF
                                let tmp = self.alloc_tmp(1);
                                let mut op_or = PcodeOpRaw::new(OpCode::CPUI_BOOL_OR as i32);
                                op_or.add_input(zf);
                                op_or.add_input(sf); // Simplified
                                op_or.set_output(tmp.clone());
                                ops.push(op_or);
                                tmp
                            }
                            "jg" => {
                                // !ZF && SF == OF. Simplified to !ZF && !SF
                                let tmp1 = self.alloc_tmp(1);
                                let mut op_not_z = PcodeOpRaw::new(OpCode::CPUI_BOOL_NEGATE as i32);
                                op_not_z.add_input(zf);
                                op_not_z.set_output(tmp1.clone());
                                ops.push(op_not_z);

                                let tmp2 = self.alloc_tmp(1);
                                let mut op_not_s = PcodeOpRaw::new(OpCode::CPUI_BOOL_NEGATE as i32);
                                op_not_s.add_input(sf);
                                op_not_s.set_output(tmp2.clone());
                                ops.push(op_not_s);

                                let tmp3 = self.alloc_tmp(1);
                                let mut op_and = PcodeOpRaw::new(OpCode::CPUI_BOOL_AND as i32);
                                op_and.add_input(tmp1);
                                op_and.add_input(tmp2);
                                op_and.set_output(tmp3.clone());
                                ops.push(op_and);
                                tmp3
                            }
                            "jge" => {
                                // SF == OF. Simplified to !SF
                                let tmp = self.alloc_tmp(1);
                                let mut op_not_s = PcodeOpRaw::new(OpCode::CPUI_BOOL_NEGATE as i32);
                                op_not_s.add_input(sf);
                                op_not_s.set_output(tmp.clone());
                                ops.push(op_not_s);
                                tmp
                            }
                            "jb" => cf,
                            "ja" => {
                                // !CF && !ZF
                                let tmp1 = self.alloc_tmp(1);
                                let mut op_not_c = PcodeOpRaw::new(OpCode::CPUI_BOOL_NEGATE as i32);
                                op_not_c.add_input(cf);
                                op_not_c.set_output(tmp1.clone());
                                ops.push(op_not_c);

                                let tmp2 = self.alloc_tmp(1);
                                let mut op_not_z = PcodeOpRaw::new(OpCode::CPUI_BOOL_NEGATE as i32);
                                op_not_z.add_input(zf);
                                op_not_z.set_output(tmp2.clone());
                                ops.push(op_not_z);

                                let tmp3 = self.alloc_tmp(1);
                                let mut op_and = PcodeOpRaw::new(OpCode::CPUI_BOOL_AND as i32);
                                op_and.add_input(tmp1);
                                op_and.add_input(tmp2);
                                op_and.set_output(tmp3.clone());
                                ops.push(op_and);
                                tmp3
                            }
                            "jbe" => {
                                // CF || ZF
                                let tmp = self.alloc_tmp(1);
                                let mut op_or = PcodeOpRaw::new(OpCode::CPUI_BOOL_OR as i32);
                                op_or.add_input(cf);
                                op_or.add_input(zf);
                                op_or.set_output(tmp.clone());
                                ops.push(op_or);
                                tmp
                            }
                            "jae" => {
                                // !CF
                                let tmp = self.alloc_tmp(1);
                                let mut op_not = PcodeOpRaw::new(OpCode::CPUI_BOOL_NEGATE as i32);
                                op_not.add_input(cf);
                                op_not.set_output(tmp.clone());
                                ops.push(op_not);
                                tmp
                            }
                            _ => zf, // Fallback
                        };

                        let mut op = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
                        op.add_input(target);
                        op.add_input(cond_vn);
                        ops.push(op);
                    }
                }
            }
            "push" | "pop" | "call" | "ret" => {
                if mnemonic == "call" {
                    // Emit CPUI_CALL with target address
                    let target_addr = if let Some(ref bt) = inst.metadata.branch_target {
                        bt.as_u64()
                    } else if let Some(op) = inst.operands.first() {
                        match op {
                            crate::disasm::Operand::Immediate { value, .. } => *value as u64,
                            _ => 0,
                        }
                    } else {
                        0
                    };
                    let mut op = PcodeOpRaw::new(OpCode::CPUI_CALL as i32);
                    // Faithful to Ghidra's x86 lifter (ia.sinc): CALL emits only
                    // the target address as input(0). Parameter varnodes and the
                    // return-value output are established by ActionFuncLink's
                    // funcLinkInput/funcLinkOutput at analysis time (after Heritage),
                    // not by the lifter. This matches Ghidra flow.cc:680 setupCallSpecs
                    // + coreaction.cc:1474 funcLinkInput + 1521 funcLinkOutput.
                    op.add_input(VarnodeRaw::new(AddressSpace::Ram, target_addr, 8));
                    ops.push(op);
                } else if mnemonic == "ret" {
                    let mut op = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
                    op.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
                    ops.push(op);
                }
            }
            _ => {
                // Unimplemented
            }
        }

        for (order, op) in ops.iter_mut().enumerate() {
            op.set_seq_num(crate::address::SeqNum::new(inst.address, order as u32));
        }

        ops
    }
}
