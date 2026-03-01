//! x86-64 P-code translator
//!
//! This module implements the translation from x86-64 machine instructions
//! to P-code operations. It uses iced-x86 for decoding and maps each
//! instruction to its equivalent P-code semantic.

use super::{RegisterMap, Translator, X86_64RegisterMap};
use crate::disasm::{Instruction, Operand};
use crate::opcodes::OpCode;
use crate::pcode::{ PcodeOperation, SeqNum, Varnode, PcodeBuilder};
use crate::{Architecture, Result};

pub struct X86_64Translator {
    register_map: X86_64RegisterMap,
}

impl X86_64Translator {
    pub fn new() -> Self {
        X86_64Translator {
            register_map: X86_64RegisterMap::new(),
        }
    }

    fn translate_by_mnemonic(
        &self,
        inst: &Instruction,
        builder: &mut PcodeBuilder,
        seqnum: SeqNum,
    ) -> Result<()> {
        let mnemonic = inst.mnemonic.to_lowercase();

        match mnemonic.as_str() {
            // Data movement
            "mov" | "movaps" | "movups" | "movdqu" => self.translate_mov(inst, builder, seqnum)?,
            "movzx" => self.translate_movzx(inst, builder, seqnum)?,
            "movsx" | "movsxd" => self.translate_movsx(inst, builder, seqnum)?,
            "lea" => self.translate_lea(inst, builder, seqnum)?,
            "stosb" => self.translate_stosb(inst, builder, seqnum)?,
            "stosd" => self.translate_stosd(inst, builder, seqnum)?,
            "stosq" => self.translate_stosq(inst, builder, seqnum)?,
            "movsq" => self.translate_movsq(inst, builder, seqnum)?,
            "cdqe" => self.translate_cdqe(inst, builder, seqnum)?,
            "cmove" | "cmovne" | "cmovg" | "cmovge" | "cmovl" | "cmovle" | "cmova" | "cmovae" | "cmovb" | "cmovbe" | "cmovs" | "cmovns" => self.translate_cmov(inst, builder, seqnum)?,

            // Arithmetic
            "add" => self.translate_add(inst, builder, seqnum)?,
            "adc" => self.translate_adc(inst, builder, seqnum)?,
            "sub" => self.translate_sub(inst, builder, seqnum)?,
            "sbb" => self.translate_sbb(inst, builder, seqnum)?,
            "imul" => self.translate_imul(inst, builder, seqnum)?,
            "inc" => self.translate_inc(inst, builder, seqnum)?,
            "dec" => self.translate_dec(inst, builder, seqnum)?,
            "neg" => self.translate_neg(inst, builder, seqnum)?,
            "xchg" => self.translate_xchg(inst, builder, seqnum)?,

            // Logical
            "and" => self.translate_and(inst, builder, seqnum)?,
            "or" => self.translate_or(inst, builder, seqnum)?,
            "xor" | "pxor" => self.translate_xor(inst, builder, seqnum)?,
            "not" => self.translate_not(inst, builder, seqnum)?,

            // Comparison
            "cmp" => self.translate_cmp(inst, builder, seqnum)?,
            "test" => self.translate_test(inst, builder, seqnum)?,

            // Control flow
            "jmp" => self.translate_jmp(inst, builder, seqnum)?,
            "je" | "jz" => self.translate_je(inst, builder, seqnum)?,
            "jne" | "jnz" => self.translate_jne(inst, builder, seqnum)?,
            "jl" | "jnge" => self.translate_jl(inst, builder, seqnum)?,
            "jle" | "jng" => self.translate_jle(inst, builder, seqnum)?,
            "jg" | "jnle" => self.translate_jg(inst, builder, seqnum)?,
            "jge" | "jnl" => self.translate_jge(inst, builder, seqnum)?,
            "ja" | "jnbe" => self.translate_ja(inst, builder, seqnum)?,
            "jae" | "jnb" | "jnc" => self.translate_jae(inst, builder, seqnum)?,
            "jbe" | "jna" => self.translate_jbe(inst, builder, seqnum)?,
            "jb" | "jnae" | "jc" => self.translate_jb(inst, builder, seqnum)?,
            "jo" => self.translate_jo(inst, builder, seqnum)?,
            "call" => self.translate_call(inst, builder, seqnum)?,
            "ret" => self.translate_ret(inst, builder, seqnum)?,

            // Stack operations
            "push" => self.translate_push(inst, builder, seqnum)?,
            "pop" => self.translate_pop(inst, builder, seqnum)?,

            // Shifts
            "shl" | "sal" => self.translate_shl(inst, builder, seqnum)?,
            "shr" => self.translate_shr(inst, builder, seqnum)?,
            "sar" => self.translate_sar(inst, builder, seqnum)?,

            // Flags and IO
            "sahf" => self.translate_sahf(inst, builder, seqnum)?,
            "insb" | "insw" | "insd" => self.translate_in(inst, builder, seqnum)?,
            "outsb" | "outsw" | "outsd" => self.translate_out(inst, builder, seqnum)?,

            // No-op
            "nop" | "endbr64" | "prefetcht0" | "prefetcht1" | "prefetcht2" | "prefetchnta" | "hlt" => { }

            _ => {
                eprintln!("Warning: Unsupported instruction: {}", mnemonic);
            }
        }

        Ok(())
    }

    fn operand_to_varnode(&self, inst: &Instruction, op_idx: usize) -> Result<Varnode> {
        let op = &inst.operands[op_idx];
        match op {
            Operand::Register { name, size } => {
                let offset = self.register_map.get_register(name).map(|v| v.offset()).unwrap_or(0);
                Ok(Varnode::new_register(offset, *size))
            }
            Operand::Immediate { value, size } => Ok(Varnode::new_constant(*value as u64, *size)),
            Operand::Memory { size, .. } => self.translate_address(None, None, 0, 0, *size),
        }
    }

    fn translate_address(
        &self,
        _base: Option<&str>,
        _index: Option<&str>,
        _scale: i32,
        _displacement: i64,
        size: usize,
    ) -> Result<Varnode> {
        let addr = 0;
        Ok(Varnode::new_ram(addr, size))
    }

    fn store_operand(
        &self,
        inst: &Instruction,
        op_idx: usize,
        src: Varnode,
        builder: &mut PcodeBuilder,
    ) -> Result<()> {
        let dst = &inst.operands[op_idx];
        match dst {
            Operand::Register { name, size } => {
                let offset = self.register_map.get_register(name).map(|v| v.offset()).unwrap_or(0);
                let reg = Varnode::new_register(offset, *size);
                if *size == 4 {
                    let full_reg = Varnode::new_register(offset, 8);
                    builder.add_op(OpCode::CPUI_INT_ZEXT, Some(full_reg), vec![src]);
                } else {
                    builder.add_op(OpCode::CPUI_COPY, Some(reg), vec![src]);
                }
            }
            Operand::Memory { .. } => {
                let addr_vn = self.operand_to_varnode(inst, op_idx)?;
                builder.add_op(OpCode::CPUI_STORE, None, vec![Varnode::new_constant(0, 4), addr_vn, src]);
            }
            _ => {}
        }
        Ok(())
    }

    fn translate_mov(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let src = self.operand_to_varnode(inst, 1)?;
        self.store_operand(inst, 0, src, builder)?;
        Ok(())
    }

    fn translate_movzx(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        let src = self.operand_to_varnode(inst, 1)?;
        builder.add_op(OpCode::CPUI_INT_ZEXT, Some(dst), vec![src]);
        Ok(())
    }

    fn translate_movsx(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        let src = self.operand_to_varnode(inst, 1)?;
        builder.add_op(OpCode::CPUI_INT_SEXT, Some(dst), vec![src]);
        Ok(())
    }

    fn translate_lea(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        if let Operand::Memory { .. } = &inst.operands[1] {
            let addr = builder.new_unique(8);
            builder.add_op(OpCode::CPUI_COPY, Some(addr.clone()), vec![Varnode::new_constant(0xdeadbeef, 8)]);
            builder.add_op(OpCode::CPUI_COPY, Some(dst), vec![addr]);
        }
        Ok(())
    }

    fn translate_add(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        let src = self.operand_to_varnode(inst, 1)?;
        let res = builder.new_unique(dst.size());
        builder.add_op(OpCode::CPUI_INT_ADD, Some(res.clone()), vec![dst.clone(), src]);
        self.store_operand(inst, 0, res.clone(), builder)?;
        self.update_flags_arithmetic(inst, &res, builder)?;
        Ok(())
    }

    fn translate_sub(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        let src = self.operand_to_varnode(inst, 1)?;
        let res = builder.new_unique(dst.size());
        builder.add_op(OpCode::CPUI_INT_SUB, Some(res.clone()), vec![dst.clone(), src]);
        self.store_operand(inst, 0, res.clone(), builder)?;
        self.update_flags_arithmetic(inst, &res, builder)?;
        Ok(())
    }

    fn translate_inc(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        let one = Varnode::new_constant(1, dst.size());
        let res = builder.new_unique(dst.size());
        builder.add_op(OpCode::CPUI_INT_ADD, Some(res.clone()), vec![dst.clone(), one]);
        self.store_operand(inst, 0, res, builder)?;
        Ok(())
    }

    fn translate_dec(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        let one = Varnode::new_constant(1, dst.size());
        let res = builder.new_unique(dst.size());
        builder.add_op(OpCode::CPUI_INT_SUB, Some(res.clone()), vec![dst.clone(), one]);
        self.store_operand(inst, 0, res, builder)?;
        Ok(())
    }

    fn translate_neg(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        let res = builder.new_unique(dst.size());
        builder.add_op(OpCode::CPUI_INT_NEG, Some(res.clone()), vec![dst.clone()]);
        self.store_operand(inst, 0, res, builder)?;
        Ok(())
    }

    fn translate_and(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        let src = self.operand_to_varnode(inst, 1)?;
        let res = builder.new_unique(dst.size());
        builder.add_op(OpCode::CPUI_INT_AND, Some(res.clone()), vec![dst.clone(), src]);
        self.store_operand(inst, 0, res.clone(), builder)?;
        self.update_flags_logical(inst, &res, builder)?;
        Ok(())
    }

    fn translate_or(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        let src = self.operand_to_varnode(inst, 1)?;
        let res = builder.new_unique(dst.size());
        builder.add_op(OpCode::CPUI_INT_OR, Some(res.clone()), vec![dst.clone(), src]);
        self.store_operand(inst, 0, res.clone(), builder)?;
        self.update_flags_logical(inst, &res, builder)?;
        Ok(())
    }

    fn translate_xor(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        let src = self.operand_to_varnode(inst, 1)?;
        let res = builder.new_unique(dst.size());
        builder.add_op(OpCode::CPUI_INT_XOR, Some(res.clone()), vec![dst.clone(), src]);
        self.store_operand(inst, 0, res.clone(), builder)?;
        self.update_flags_logical(inst, &res, builder)?;
        Ok(())
    }

    fn translate_not(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        let res = builder.new_unique(dst.size());
        builder.add_op(OpCode::CPUI_INT_NOT, Some(res.clone()), vec![dst.clone()]);
        self.store_operand(inst, 0, res, builder)?;
        Ok(())
    }

    fn translate_cmp(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let op0 = self.operand_to_varnode(inst, 0)?;
        let op1 = self.operand_to_varnode(inst, 1)?;
        let res = builder.new_unique(op0.size());
        builder.add_op(OpCode::CPUI_INT_SUB, Some(res.clone()), vec![op0, op1]);
        self.update_flags_arithmetic(inst, &res, builder)?;
        Ok(())
    }

    fn translate_test(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let op0 = self.operand_to_varnode(inst, 0)?;
        let op1 = self.operand_to_varnode(inst, 1)?;
        let res = builder.new_unique(op0.size());
        builder.add_op(OpCode::CPUI_INT_AND, Some(res.clone()), vec![op0, op1]);
        self.update_flags_logical(inst, &res, builder)?;
        Ok(())
    }

    fn translate_jmp(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        if let Some(target) = inst.metadata.branch_target {
            let target_vn = Varnode::new_constant(target.as_u64(), 8);
            builder.add_op(OpCode::CPUI_BRANCH, None, vec![target_vn]);
        } else {
            let target = self.operand_to_varnode(inst, 0)?;
            builder.add_op(OpCode::CPUI_BRANCHInd, None, vec![target]);
        }
        Ok(())
    }

    fn translate_je(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        if let Some(target) = inst.metadata.branch_target {
            let target_vn = Varnode::new_constant(target.as_u64(), 8);
            let zf = Varnode::new_register(200, 1);
            builder.add_op(OpCode::CPUI_CBRANCH, None, vec![target_vn, zf]);
        }
        Ok(())
    }

    fn translate_jne(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        if let Some(target) = inst.metadata.branch_target {
            let target_vn = Varnode::new_constant(target.as_u64(), 8);
            let zf = Varnode::new_register(200, 1);
            let cond = builder.new_unique(1);
            builder.add_op(OpCode::CPUI_BOOL_NOT, Some(cond.clone()), vec![zf]);
            builder.add_op(OpCode::CPUI_CBRANCH, None, vec![target_vn, cond]);
        }
        Ok(())
    }

    fn translate_jl(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        if let Some(target) = inst.metadata.branch_target {
            let target_vn = Varnode::new_constant(target.as_u64(), 8);
            let sf = Varnode::new_register(201, 1);
            let of = Varnode::new_register(203, 1);
            let cond = builder.new_unique(1);
            builder.add_op(OpCode::CPUI_BOOL_XOR, Some(cond.clone()), vec![sf, of]);
            builder.add_op(OpCode::CPUI_CBRANCH, None, vec![target_vn, cond]);
        }
        Ok(())
    }

    fn translate_jle(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        if let Some(target) = inst.metadata.branch_target {
            let target_vn = Varnode::new_constant(target.as_u64(), 8);
            let sf = Varnode::new_register(201, 1);
            let of = Varnode::new_register(203, 1);
            let zf = Varnode::new_register(200, 1);
            let cond1 = builder.new_unique(1);
            let cond2 = builder.new_unique(1);
            builder.add_op(OpCode::CPUI_BOOL_XOR, Some(cond1.clone()), vec![sf, of]);
            builder.add_op(OpCode::CPUI_BOOL_OR, Some(cond2.clone()), vec![cond1, zf]);
            builder.add_op(OpCode::CPUI_CBRANCH, None, vec![target_vn, cond2]);
        }
        Ok(())
    }

    fn translate_jg(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        if let Some(target) = inst.metadata.branch_target {
            let target_vn = Varnode::new_constant(target.as_u64(), 8);
            let sf = Varnode::new_register(201, 1);
            let of = Varnode::new_register(203, 1);
            let zf = Varnode::new_register(200, 1);
            let cond1 = builder.new_unique(1);
            let cond2 = builder.new_unique(1);
            let cond3 = builder.new_unique(1);
            builder.add_op(OpCode::CPUI_BOOL_XOR, Some(cond1.clone()), vec![sf, of]);
            builder.add_op(OpCode::CPUI_BOOL_NOT, Some(cond2.clone()), vec![cond1]);
            builder.add_op(OpCode::CPUI_BOOL_NOT, Some(cond3.clone()), vec![zf]);
            let final_cond = builder.new_unique(1);
            builder.add_op(OpCode::CPUI_BOOL_AND, Some(final_cond.clone()), vec![cond2, cond3]);
            builder.add_op(OpCode::CPUI_CBRANCH, None, vec![target_vn, final_cond]);
        }
        Ok(())
    }

    fn translate_jge(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        if let Some(target) = inst.metadata.branch_target {
            let target_vn = Varnode::new_constant(target.as_u64(), 8);
            let sf = Varnode::new_register(201, 1);
            let of = Varnode::new_register(203, 1);
            let cond = builder.new_unique(1);
            builder.add_op(OpCode::CPUI_BOOL_XOR, Some(cond.clone()), vec![sf, of]);
            let final_cond = builder.new_unique(1);
            builder.add_op(OpCode::CPUI_BOOL_NOT, Some(final_cond.clone()), vec![cond]);
            builder.add_op(OpCode::CPUI_CBRANCH, None, vec![target_vn, final_cond]);
        }
        Ok(())
    }

    fn translate_call(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        if let Some(target) = inst.metadata.branch_target {
            let target_vn = Varnode::new_constant(target.as_u64(), 8);
            builder.add_op(OpCode::CPUI_CALL, None, vec![target_vn]);
        } else {
            let target = self.operand_to_varnode(inst, 0)?;
            builder.add_op(OpCode::CPUI_CALLInd, None, vec![target]);
        }
        Ok(())
    }

    fn translate_ret(&self, _inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        builder.add_op(OpCode::CPUI_RETURN, None, Vec::new());
        Ok(())
    }

    fn translate_push(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let src = self.operand_to_varnode(inst, 0)?;
        let rsp = Varnode::new_register(32, 8);
        let eight = Varnode::new_constant(8, 8);
        builder.add_op(OpCode::CPUI_INT_SUB, Some(rsp.clone()), vec![rsp.clone(), eight]);
        builder.add_op(OpCode::CPUI_STORE, None, vec![Varnode::new_constant(0, 4), rsp, src]);
        Ok(())
    }

    fn translate_pop(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        let rsp = Varnode::new_register(32, 8);
        let eight = Varnode::new_constant(8, 8);
        let val = builder.new_unique(dst.size());
        builder.add_op(OpCode::CPUI_LOAD, Some(val.clone()), vec![Varnode::new_constant(0, 4), rsp.clone()]);
        self.store_operand(inst, 0, val, builder)?;
        builder.add_op(OpCode::CPUI_INT_ADD, Some(rsp.clone()), vec![rsp, eight]);
        Ok(())
    }

    fn translate_shl(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        let count = self.operand_to_varnode(inst, 1)?;
        let res = builder.new_unique(dst.size());
        builder.add_op(OpCode::CPUI_INT_LEFT, Some(res.clone()), vec![dst.clone(), count]);
        self.store_operand(inst, 0, res, builder)?;
        Ok(())
    }

    fn translate_shr(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        let count = self.operand_to_varnode(inst, 1)?;
        let res = builder.new_unique(dst.size());
        builder.add_op(OpCode::CPUI_INT_RIGHT, Some(res.clone()), vec![dst.clone(), count]);
        self.store_operand(inst, 0, res, builder)?;
        Ok(())
    }

    fn translate_sar(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        let count = self.operand_to_varnode(inst, 1)?;
        let res = builder.new_unique(dst.size());
        builder.add_op(OpCode::CPUI_INT_SRIGHT, Some(res.clone()), vec![dst.clone(), count]);
        self.store_operand(inst, 0, res, builder)?;
        Ok(())
    }

    fn update_flags_arithmetic(&self, _inst: &Instruction, _res: &Varnode, _builder: &mut PcodeBuilder) -> Result<()> {
        Ok(())
    }

    fn update_flags_logical(&self, _inst: &Instruction, _res: &Varnode, _builder: &mut PcodeBuilder) -> Result<()> {
        Ok(())
    }

    fn translate_ja(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        if let Some(target) = inst.metadata.branch_target {
            let target_vn = Varnode::new_constant(target.as_u64(), 8);
            let cf = Varnode::new_register(202, 1);
            let zf = Varnode::new_register(200, 1);
            let cond1 = builder.new_unique(1);
            let cond2 = builder.new_unique(1);
            builder.add_op(OpCode::CPUI_BOOL_OR, Some(cond1.clone()), vec![cf, zf]);
            builder.add_op(OpCode::CPUI_BOOL_NOT, Some(cond2.clone()), vec![cond1]);
            builder.add_op(OpCode::CPUI_CBRANCH, None, vec![target_vn, cond2]);
        }
        Ok(())
    }

    fn translate_stosq(&self, _inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let rax = Varnode::new_register(0, 8);
        let rdi = Varnode::new_register(56, 8);
        builder.add_op(OpCode::CPUI_STORE, None, vec![Varnode::new_constant(0, 4), rdi.clone(), rax]);
        let eight = Varnode::new_constant(8, 8);
        builder.add_op(OpCode::CPUI_INT_ADD, Some(rdi.clone()), vec![rdi, eight]);
        Ok(())
    }

    fn translate_movsq(&self, _inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let rsi = Varnode::new_register(48, 8);
        let rdi = Varnode::new_register(56, 8);
        let temp = builder.new_unique(8);
        builder.add_op(OpCode::CPUI_LOAD, Some(temp.clone()), vec![Varnode::new_constant(0, 4), rsi.clone()]);
        builder.add_op(OpCode::CPUI_STORE, None, vec![Varnode::new_constant(0, 4), rdi.clone(), temp]);
        let eight = Varnode::new_constant(8, 8);
        builder.add_op(OpCode::CPUI_INT_ADD, Some(rsi.clone()), vec![rsi, eight.clone()]);
        builder.add_op(OpCode::CPUI_INT_ADD, Some(rdi.clone()), vec![rdi, eight]);
        Ok(())
    }

    fn translate_imul(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        let src = self.operand_to_varnode(inst, 1)?;
        let res = builder.new_unique(dst.size());
        builder.add_op(OpCode::CPUI_INT_MULT, Some(res.clone()), vec![dst.clone(), src]);
        self.store_operand(inst, 0, res, builder)?;
        Ok(())
    }

    fn translate_cdqe(&self, _inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let eax = Varnode::new_register(0, 4);
        let rax = Varnode::new_register(0, 8);
        builder.add_op(OpCode::CPUI_INT_SEXT, Some(rax), vec![eax]);
        Ok(())
    }

    fn translate_cmov(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        let src = self.operand_to_varnode(inst, 1)?;
        builder.add_op(OpCode::CPUI_COPY, Some(dst), vec![src]);
        Ok(())
    }

    fn translate_sbb(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        let src = self.operand_to_varnode(inst, 1)?;
        let cf = Varnode::new_register(202, 1);
        let temp = builder.new_unique(dst.size());
        builder.add_op(OpCode::CPUI_INT_SUB, Some(temp.clone()), vec![dst.clone(), src]);
        let cf_ext = builder.new_unique(dst.size());
        builder.add_op(OpCode::CPUI_INT_ZEXT, Some(cf_ext.clone()), vec![cf]);
        builder.add_op(OpCode::CPUI_INT_SUB, Some(dst), vec![temp, cf_ext]);
        Ok(())
    }

    fn translate_jb(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        if let Some(target) = inst.metadata.branch_target {
            let target_vn = Varnode::new_constant(target.as_u64(), 8);
            let cf = Varnode::new_register(202, 1);
            builder.add_op(OpCode::CPUI_CBRANCH, None, vec![target_vn, cf]);
        }
        Ok(())
    }

    fn translate_adc(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let dst = self.operand_to_varnode(inst, 0)?;
        let src = self.operand_to_varnode(inst, 1)?;
        let cf = Varnode::new_register(202, 1);
        let temp1 = builder.new_unique(dst.size());
        builder.add_op(OpCode::CPUI_INT_ADD, Some(temp1.clone()), vec![dst.clone(), src]);
        let cf_ext = builder.new_unique(dst.size());
        builder.add_op(OpCode::CPUI_INT_ZEXT, Some(cf_ext.clone()), vec![cf]);
        builder.add_op(OpCode::CPUI_INT_ADD, Some(dst.clone()), vec![temp1, cf_ext]);
        self.update_flags_arithmetic(inst, &dst, builder)?;
        Ok(())
    }

    fn translate_xchg(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let op0 = self.operand_to_varnode(inst, 0)?;
        let op1 = self.operand_to_varnode(inst, 1)?;
        let temp = builder.new_unique(op0.size());
        builder.add_op(OpCode::CPUI_COPY, Some(temp.clone()), vec![op0.clone()]);
        self.store_operand(inst, 0, op1, builder)?;
        self.store_operand(inst, 1, temp, builder)?;
        Ok(())
    }

    fn translate_stosb(&self, _inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let al = Varnode::new_register(0, 1);
        let rdi = Varnode::new_register(56, 8);
        builder.add_op(OpCode::CPUI_STORE, None, vec![Varnode::new_constant(0, 4), rdi.clone(), al]);
        let one = Varnode::new_constant(1, 8);
        builder.add_op(OpCode::CPUI_INT_ADD, Some(rdi.clone()), vec![rdi, one]);
        Ok(())
    }

    fn translate_stosd(&self, _inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let eax = Varnode::new_register(0, 4);
        let rdi = Varnode::new_register(56, 8);
        builder.add_op(OpCode::CPUI_STORE, None, vec![Varnode::new_constant(0, 4), rdi.clone(), eax]);
        let four = Varnode::new_constant(4, 8);
        builder.add_op(OpCode::CPUI_INT_ADD, Some(rdi.clone()), vec![rdi, four]);
        Ok(())
    }

    fn translate_jae(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        if let Some(target) = inst.metadata.branch_target {
            let target_vn = Varnode::new_constant(target.as_u64(), 8);
            let cf = Varnode::new_register(202, 1);
            let cond = builder.new_unique(1);
            builder.add_op(OpCode::CPUI_BOOL_NOT, Some(cond.clone()), vec![cf]);
            builder.add_op(OpCode::CPUI_CBRANCH, None, vec![target_vn, cond]);
        }
        Ok(())
    }

    fn translate_jbe(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        if let Some(target) = inst.metadata.branch_target {
            let target_vn = Varnode::new_constant(target.as_u64(), 8);
            let cf = Varnode::new_register(202, 1);
            let zf = Varnode::new_register(200, 1);
            let cond = builder.new_unique(1);
            builder.add_op(OpCode::CPUI_BOOL_OR, Some(cond.clone()), vec![cf, zf]);
            builder.add_op(OpCode::CPUI_CBRANCH, None, vec![target_vn, cond]);
        }
        Ok(())
    }

    fn translate_jo(&self, inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        if let Some(target) = inst.metadata.branch_target {
            let target_vn = Varnode::new_constant(target.as_u64(), 8);
            let of = Varnode::new_register(203, 1);
            builder.add_op(OpCode::CPUI_CBRANCH, None, vec![target_vn, of]);
        }
        Ok(())
    }

    fn translate_sahf(&self, _inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        let ah = Varnode::new_register(1, 1);
        let flags = [
            (202, 0), // CF
            (204, 2), // PF
            (205, 4), // AF
            (200, 6), // ZF
            (201, 7), // SF
        ];
        for (offset, bit) in flags {
            let flag = Varnode::new_register(offset, 1);
            let bit_val = builder.new_unique(1);
            let mask = Varnode::new_constant(1 << bit, 1);
            let temp = builder.new_unique(1);
            builder.add_op(OpCode::CPUI_INT_AND, Some(temp.clone()), vec![ah.clone(), mask]);
            builder.add_op(OpCode::CPUI_INT_NOTEQUAL, Some(bit_val.clone()), vec![temp, Varnode::new_constant(0, 1)]);
            builder.add_op(OpCode::CPUI_COPY, Some(flag), vec![bit_val]);
        }
        Ok(())
    }

    fn translate_in(&self, _inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        builder.add_op(OpCode::CPUI_CALLOTHER /* UserOp */(1001), None, Vec::new());
        Ok(())
    }

    fn translate_out(&self, _inst: &Instruction, builder: &mut PcodeBuilder, _seqnum: SeqNum) -> Result<()> {
        builder.add_op(OpCode::CPUI_CALLOTHER /* UserOp */(1002), None, Vec::new());
        Ok(())
    }
}

impl Default for X86_64Translator {
    fn default() -> Self {
        Self::new()
    }
}

impl Translator for X86_64Translator {
    fn translate(&self, instruction: &Instruction) -> Result<Vec<PcodeOperation>> {
        let mut builder = PcodeBuilder::new(instruction.address);
        let seqnum = SeqNum::new(instruction.address, 0);
        self.translate_by_mnemonic(instruction, &mut builder, seqnum)?;
        Ok(builder.build().operations().to_vec())
    }

    fn architecture(&self) -> Architecture {
        Architecture::X86_64
    }

    fn register_map(&self) -> &dyn crate::translator::RegisterMap {
        &self.register_map
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::{Instruction, Operand};

    fn make_test_instruction(mnemonic: &str, operands: Vec<Operand>) -> Instruction {
        let mut inst = Instruction::new(crate::Address::new(0x1000));
        inst.mnemonic = mnemonic.to_string();
        inst.operands = operands;
        inst.length = 3;
        inst
    }

    #[test]
    fn test_translate_mov() {
        let translator = X86_64Translator::new();
        let inst = make_test_instruction(
            "mov",
            vec![
                Operand::Register {
                    name: "rax".to_string(),
                    size: 8,
                },
                Operand::Register {
                    name: "rbx".to_string(),
                    size: 8,
                },
            ],
        );
        let result = translator.translate(&inst);
        assert!(result.is_ok());
        let ops = result.unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].opcode(), OpCode::CPUI_COPY);
    }

    #[test]
    fn test_translate_add() {
        let translator = X86_64Translator::new();
        let inst = make_test_instruction(
            "add",
            vec![
                Operand::Register {
                    name: "rax".to_string(),
                    size: 8,
                },
                Operand::Register {
                    name: "rbx".to_string(),
                    size: 8,
                },
            ],
        );
        let result = translator.translate(&inst);
        assert!(result.is_ok());
        let ops = result.unwrap();
        assert!(ops.len() > 0);
        assert!(ops.iter().any(|op| op.opcode == OpCode::CPUI_INT_ADD));
    }

    #[test]
    fn test_translate_ret() {
        let translator = X86_64Translator::new();
        let inst = make_test_instruction("ret", vec![]);
        let result = translator.translate(&inst);
        assert!(result.is_ok());
        let ops = result.unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].opcode(), OpCode::CPUI_RETURN);
    }

    #[test]
    fn test_architecture() {
        let translator = X86_64Translator::new();
        assert_eq!(translator.architecture(), Architecture::X86_64);
    }
}
