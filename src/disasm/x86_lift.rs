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

// RUGRA-GLUE: destination access for the flag-pcode ALU constructors
// (ia.sinc ADD/SUB/AND/OR/XOR/ADC/SBB/NEG/NOT register and memory forms).
// Register destination: the value op writes the register varnode directly
// and a 32-bit destination additionally zero-extends into its 64-bit parent
// (check_Reg32_dest/check_Rmr32_dest). Memory destination: one shared
// address varnode; the oracle re-evaluates the rm operand expression at
// EVERY use — add/sub/and/or/xor mem forms re-LOAD for each flag pair, the
// value op and each post-store resultflags group (evidence: `add dword
// [rbx+28h],1` = 7 LOADs, /tmp/w-iced-flagprobe3.out).
enum AluDst {
    Reg {
        vn: VarnodeRaw,
        parent64: Option<VarnodeRaw>,
    },
    Mem {
        addr: VarnodeRaw,
    },
}

// RUGRA-GLUE: first-operand reference for the ALU flag macros — Direct for
// registers, MemLoad for memory operands (materialize() emits a fresh LOAD
// per use, mirroring SLEIGH rm-operand re-evaluation).
enum Op1Ref {
    Direct(VarnodeRaw),
    MemLoad { addr: VarnodeRaw, size: usize },
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
            // High-byte sub-registers: AH/CH/DH/BH sit one byte above their
            // GPR base in the locked sla layout (dumped via
            // examples/x86flag_probe.rs, `and dh,1` oracle pcode reads
            // register:0x11:1). They appear in the httpd corpus.
            "ah" => 0x01,
            "ch" => 0x09,
            "dh" => 0x11,
            "bh" => 0x19,
            // RIP/EIP live at register offset 0x288 in the locked oracle
            // layout (sleigh_specs/x86-64.sla getAllRegisters: RIP=0x288:8,
            // EIP=0x288:4, rflags=0x280, CF=0x200..ID=0x214 — dumped by
            // examples/x86carry_probe.rs). The former 0x200 encoding aliased
            // the 1-bit flags region (CF..F5), so every rip-relative memory
            // operand built its address off a varnode overlapping the flags.
            "rip" | "eip" => 0x288, // Instruction pointer
            _ => return None,
        };
        Some(VarnodeRaw::new(AddressSpace::Register, offset, size))
    }

    // RUGRA-GLUE: 寄存器名→偏移量映射（复用 get_register 的 match 表）。
    /// Map register name to offset (shared with get_register).
    fn reg_offset(name: &str) -> u64 {
        Self::get_register(name, 8).map(|v| v.offset).unwrap_or(0)
    }

    // RUGRA-GLUE: x86 flag pcode for the iced path (X86LIFT-FLAG-PCODE-0001).
    // The locked cpp-oracle tree (ghidra/.../decompile/cpp) contains no x86
    // instruction semantics; the authoritative source is the locked
    // Ghidra 12.0.4 x86-64 language: sleigh_specs/x86-64.sla (compiled from
    // that oracle) executed through sleigh_shim, with ia.sinc macro names as
    // documentation. Flag register varnodes (1 byte each, register space):
    // CF=0x200 PF=0x202 AF=0x204 ZF=0x206 SF=0x207 OF=0x20b (full dumped
    // layout: F1=0x201 F3=0x203 F5=0x205 TF..OF=0x208..0x20b, RIP=0x288 —
    // evidence /tmp/w-iced-flagprobe.out, examples/x86flag_probe.rs).
    /// CF flag varnode (register:0x200:1)
    fn flag_cf() -> VarnodeRaw {
        VarnodeRaw::new(AddressSpace::Register, 0x200, 1)
    }

    // RUGRA-GLUE: see flag_cf (X86LIFT-FLAG-PCODE-0001 sla layout)
    /// PF flag varnode (register:0x202:1)
    fn flag_pf() -> VarnodeRaw {
        VarnodeRaw::new(AddressSpace::Register, 0x202, 1)
    }

    // RUGRA-GLUE: see flag_cf (X86LIFT-FLAG-PCODE-0001 sla layout)
    /// ZF flag varnode (register:0x206:1)
    fn flag_zf() -> VarnodeRaw {
        VarnodeRaw::new(AddressSpace::Register, 0x206, 1)
    }

    // RUGRA-GLUE: see flag_cf (X86LIFT-FLAG-PCODE-0001 sla layout)
    /// SF flag varnode (register:0x207:1)
    fn flag_sf() -> VarnodeRaw {
        VarnodeRaw::new(AddressSpace::Register, 0x207, 1)
    }

    // RUGRA-GLUE: see flag_cf (X86LIFT-FLAG-PCODE-0001 sla layout)
    /// OF flag varnode (register:0x20b:1)
    fn flag_of() -> VarnodeRaw {
        VarnodeRaw::new(AddressSpace::Register, 0x20b, 1)
    }

    // RUGRA-GLUE: const-space varnode helper for the iced path (oracle pcode
    // uses const-space inputs at the *operation* size, e.g. `sub rsp,0x98`
    // feeds 0x98:8 although encoded as imm8 — mask to `size` bytes).
    /// Constant varnode with the value masked to `size` bytes.
    fn const_vn(value: u64, size: usize) -> VarnodeRaw {
        let masked = if size >= 8 {
            value
        } else {
            value & ((1u64 << (size as u32 * 8)) - 1)
        };
        VarnodeRaw::new(AddressSpace::Const, masked, size)
    }

    // RUGRA-GLUE: ram-space id constant used by LOAD/STORE pcode (oracle
    // LOAD in=(const:spaceid:8, addr) — matches existing parse_operand shape)
    /// Constant varnode holding the ram space id.
    fn ram_space_const() -> VarnodeRaw {
        VarnodeRaw::new(AddressSpace::Const, AddressSpace::Ram.space_id() as u64, 8)
    }

    // RUGRA-GLUE: ia.sinc check_Reg32_dest/check_Rmr32_dest sub-register
    // mapping (x86-64 language): writing a 32-bit GPR zero-extends into the
    // 64-bit parent at the same register offset. 8/16-bit and memory
    // destinations have no such zext (check_rm32_dest is mod=3 only).
    /// Parent 64-bit register name for a 32-bit register name, if any.
    fn parent64_name(name: &str) -> Option<&'static str> {
        Some(match name {
            "eax" => "rax",
            "ecx" => "rcx",
            "edx" => "rdx",
            "ebx" => "rbx",
            "esp" => "rsp",
            "ebp" => "rbp",
            "esi" => "rsi",
            "edi" => "rdi",
            "r8d" => "r8",
            "r9d" => "r9",
            "r10d" => "r10",
            "r11d" => "r11",
            "r12d" => "r12",
            "r13d" => "r13",
            "r14d" => "r14",
            "r15d" => "r15",
            _ => return None,
        })
    }

    // RUGRA-GLUE: memory address computation shared by the flag-pcode ALU
    // paths (oracle emits ONE address varnode reused by the read LOAD, the
    // result STORE and every post-store flag re-LOAD — see `or qword
    // [rsp],0` in /tmp/w-iced-flagprobe.out). Mirrors parse_operand's
    // base + index*scale + displacement arithmetic.
    /// Compute a memory operand's address once, emitting address ops.
    fn compute_mem_addr(
        &mut self,
        base: &Option<String>,
        index: &Option<String>,
        scale: &i32,
        displacement: &i64,
        ops: &mut Vec<PcodeOpRaw>,
    ) -> Option<VarnodeRaw> {
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
                    op.add_input(Self::const_vn(*scale as u64, 8));
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
            let disp_vn = Self::const_vn(*displacement as u64, 8);
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

        addr_vn
    }

    // RUGRA-GLUE: LOAD helper for the flag-pcode ALU paths (oracle LOAD
    // in=(ram-space-const, addr) — same shape as parse_operand's memory arm)
    /// Emit LOAD from `addr_vn`, returning the loaded temp varnode.
    fn emit_load(&mut self, size: usize, addr_vn: &VarnodeRaw, ops: &mut Vec<PcodeOpRaw>) -> VarnodeRaw {
        let tmp = self.alloc_tmp(size);
        let mut op = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        op.add_input(Self::ram_space_const());
        op.add_input(addr_vn.clone());
        op.set_output(tmp.clone());
        ops.push(op);
        tmp
    }

    // RUGRA-GLUE: STORE helper for the flag-pcode ALU paths
    /// Emit STORE of `value_vn` to `addr_vn`.
    fn emit_store_v(
        &mut self,
        addr_vn: &VarnodeRaw,
        value_vn: VarnodeRaw,
        ops: &mut Vec<PcodeOpRaw>,
    ) {
        let mut op = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        op.add_input(Self::ram_space_const());
        op.add_input(addr_vn.clone());
        op.add_input(value_vn);
        ops.push(op);
    }

    // RUGRA-GLUE: port of ia.sinc macro resultflags(result) (x86-64 language
    // of the locked oracle; sla evidence: SF=INT_SLESS(result,0), ZF=
    // INT_EQUAL(result,0), PF = popcount chain). The oracle computes SF/ZF
    // from the post-write destination varnode for register destinations, and
    // from a fresh re-LOAD of the stored destination for memory destinations
    // (handled by the caller via the per-flag emitters below).
    /// Emit SF/ZF/PF computation (ia.sinc resultflags) from `result`.
    fn emit_resultflags(
        &mut self,
        result: VarnodeRaw,
        ops: &mut Vec<PcodeOpRaw>,
    ) {
        self.emit_sf_flag(&result, ops);
        self.emit_zf_flag(&result, ops);
        self.emit_pf_flag(&result, ops);
    }

    // RUGRA-GLUE: ia.sinc resultflags SF part — SF = result s< 0
    /// Emit the SF computation from `result`.
    fn emit_sf_flag(&mut self, result: &VarnodeRaw, ops: &mut Vec<PcodeOpRaw>) {
        let mut op_sf = PcodeOpRaw::new(OpCode::CPUI_INT_SLESS as i32);
        op_sf.add_input(result.clone());
        op_sf.add_input(Self::const_vn(0, result.size));
        op_sf.set_output(Self::flag_sf());
        ops.push(op_sf);
    }

    // RUGRA-GLUE: ia.sinc resultflags ZF part — ZF = result == 0
    /// Emit the ZF computation from `result`.
    fn emit_zf_flag(&mut self, result: &VarnodeRaw, ops: &mut Vec<PcodeOpRaw>) {
        let mut op_zf = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        op_zf.add_input(result.clone());
        op_zf.add_input(Self::const_vn(0, result.size));
        op_zf.set_output(Self::flag_zf());
        ops.push(op_zf);
    }

    // RUGRA-GLUE: ia.sinc resultflags PF part —
    /// Emit the PF popcount chain from `result`.
    fn emit_pf_flag(&mut self, result: &VarnodeRaw, ops: &mut Vec<PcodeOpRaw>) {
        let size = result.size;
        // PF = ((popcount(result & 0xff) & 1) == 0)
        let t_and = self.alloc_tmp(size);
        let mut op_and = PcodeOpRaw::new(OpCode::CPUI_INT_AND as i32);
        op_and.add_input(result.clone());
        op_and.add_input(Self::const_vn(0xff, size));
        op_and.set_output(t_and.clone());
        ops.push(op_and);
        let t_pop = self.alloc_tmp(1);
        let mut op_pop = PcodeOpRaw::new(OpCode::CPUI_POPCOUNT as i32);
        op_pop.add_input(t_and);
        op_pop.set_output(t_pop.clone());
        ops.push(op_pop);
        let t_bit = self.alloc_tmp(1);
        let mut op_bit = PcodeOpRaw::new(OpCode::CPUI_INT_AND as i32);
        op_bit.add_input(t_pop);
        op_bit.add_input(Self::const_vn(1, 1));
        op_bit.set_output(t_bit.clone());
        ops.push(op_bit);
        let mut op_pf = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        op_pf.add_input(t_bit);
        op_pf.add_input(Self::const_vn(0, 1));
        op_pf.set_output(Self::flag_pf());
        ops.push(op_pf);
    }

    // RUGRA-GLUE: port of ia.sinc macro addflags(op1,op2) — CF = carry(op1,
    // op2) = INT_CARRY, OF = scarry(op1,op2) = INT_SCARRY; emitted BEFORE the
    // value op (oracle op order: flags, ADD, [zext], resultflags); each use
    /// Emit CF/OF for add (ia.sinc addflags; op1 re-materialized per use).
    fn emit_addflags(&mut self, op1: &Op1Ref, op2: &VarnodeRaw, ops: &mut Vec<PcodeOpRaw>) {
        let a1 = self.materialize(op1, ops);
        let mut op_cf = PcodeOpRaw::new(OpCode::CPUI_INT_CARRY as i32);
        op_cf.add_input(a1);
        op_cf.add_input(op2.clone());
        op_cf.set_output(Self::flag_cf());
        ops.push(op_cf);
        let a2 = self.materialize(op1, ops);
        let mut op_of = PcodeOpRaw::new(OpCode::CPUI_INT_SCARRY as i32);
        op_of.add_input(a2);
        op_of.add_input(op2.clone());
        op_of.set_output(Self::flag_of());
        ops.push(op_of);
    }

    // RUGRA-GLUE: port of ia.sinc macro subflags(op1,op2) — CF = op1 < op2 =
    // INT_LESS, OF = sborrow(op1,op2) = INT_SBORROW; op1 re-materialized per
    /// Emit CF/OF for sub/cmp (ia.sinc subflags; op1 re-materialized per use).
    fn emit_subflags(&mut self, op1: &Op1Ref, op2: &VarnodeRaw, ops: &mut Vec<PcodeOpRaw>) {
        let a1 = self.materialize(op1, ops);
        let mut op_cf = PcodeOpRaw::new(OpCode::CPUI_INT_LESS as i32);
        op_cf.add_input(a1);
        op_cf.add_input(op2.clone());
        op_cf.set_output(Self::flag_cf());
        ops.push(op_cf);
        let a2 = self.materialize(op1, ops);
        let mut op_of = PcodeOpRaw::new(OpCode::CPUI_INT_SBORROW as i32);
        op_of.add_input(a2);
        op_of.add_input(op2.clone());
        op_of.set_output(Self::flag_of());
        ops.push(op_of);
    }

    // RUGRA-GLUE: port of ia.sinc macro negflags(op1) — CF = (op1 != 0) =
    // INT_NOTEQUAL(op1,0), OF = sborrow(0,op1) = INT_SBORROW(0,op1) with the
    // constant as FIRST input (oracle `neg eax`: INT_SBORROW in=(0:4, eax));
    /// Emit CF/OF for neg (ia.sinc negflags; op1 re-materialized per use).
    fn emit_negflags(&mut self, op1: &Op1Ref, ops: &mut Vec<PcodeOpRaw>) {
        let size = match op1 {
            Op1Ref::Direct(vn) => vn.size,
            Op1Ref::MemLoad { size, .. } => *size,
        };
        let a1 = self.materialize(op1, ops);
        let mut op_cf = PcodeOpRaw::new(OpCode::CPUI_INT_NOTEQUAL as i32);
        op_cf.add_input(a1);
        op_cf.add_input(Self::const_vn(0, size));
        op_cf.set_output(Self::flag_cf());
        ops.push(op_cf);
        let a2 = self.materialize(op1, ops);
        let mut op_of = PcodeOpRaw::new(OpCode::CPUI_INT_SBORROW as i32);
        op_of.add_input(Self::const_vn(0, size));
        op_of.add_input(a2);
        op_of.set_output(Self::flag_of());
        ops.push(op_of);
    }

    // RUGRA-GLUE: port of ia.sinc macro logicalflags() — CF = 0, OF = 0
    /// Emit CF=0/OF=0 for and/or/xor/test (ia.sinc logicalflags).
    fn emit_logicalflags(&mut self, ops: &mut Vec<PcodeOpRaw>) {
        let mut op_cf = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op_cf.add_input(Self::const_vn(0, 1));
        op_cf.set_output(Self::flag_cf());
        ops.push(op_cf);
        let mut op_of = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op_of.add_input(Self::const_vn(0, 1));
        op_of.set_output(Self::flag_of());
        ops.push(op_of);
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

    // RUGRA-GLUE: resolve ALU dst + op1 reference + src value (oracle order:
    // src value ops first, then dst access; immediate canonicalized to dst
    /// Resolve operands for a 2-operand ALU instruction; returns
    /// (dst access, op1 reference, src value varnode).
    fn resolve_alu(
        &mut self,
        inst: &Instruction,
        ops: &mut Vec<PcodeOpRaw>,
    ) -> Option<(AluDst, Op1Ref, VarnodeRaw)> {
        if inst.operands.len() != 2 {
            return None;
        }
        let dst_size = match &inst.operands[0] {
            crate::disasm::Operand::Register { size, .. } => *size,
            crate::disasm::Operand::Memory { size, .. } => *size,
            _ => return None,
        };

        // Source value at the destination size (immediates canonicalized).
        let src = match &inst.operands[1] {
            crate::disasm::Operand::Register { name, size } => {
                Self::get_register(name, *size)?
            }
            crate::disasm::Operand::Immediate { value, .. } => {
                Self::const_vn(*value as u64, dst_size)
            }
            crate::disasm::Operand::Memory {
                base,
                index,
                scale,
                displacement,
                size,
            } => {
                let addr = self.compute_mem_addr(base, index, scale, displacement, ops)?;
                self.emit_load(*size, &addr, ops)
            }
        };

        match &inst.operands[0] {
            crate::disasm::Operand::Register { name, size } => {
                let vn = Self::get_register(name, *size)?;
                let parent64 = if *size == 4 {
                    Self::parent64_name(name)
                        .and_then(|p| Self::get_register(p, 8))
                } else {
                    None
                };
                Some((
                    AluDst::Reg { vn, parent64 },
                    Op1Ref::Direct(vn),
                    src,
                ))
            }
            crate::disasm::Operand::Memory {
                base,
                index,
                scale,
                displacement,
                size,
            } => {
                let addr =
                    self.compute_mem_addr(base, index, scale, displacement, ops)?;
                Some((
                    AluDst::Mem { addr },
                    Op1Ref::MemLoad {
                        addr,
                        size: *size,
                    },
                    src,
                ))
            }
            _ => None,
        }
    }

    // RUGRA-GLUE: per-use materialization of the first ALU operand — SLEIGH
    // re-evaluates the rm expression at every macro use, so a memory operand
    /// Materialize `op1` (fresh LOAD for memory operands), for one use.
    fn materialize(&mut self, op1: &Op1Ref, ops: &mut Vec<PcodeOpRaw>) -> VarnodeRaw {
        match op1 {
            Op1Ref::Direct(vn) => vn.clone(),
            Op1Ref::MemLoad { addr, size } => self.emit_load(*size, addr, ops),
        }
    }

    // RUGRA-GLUE: post-value-op writeback + resultflags for the ALU
    // constructors: mem → STORE then per-flag-group re-LOADs (oracle re-reads
    // the stored destination for SF, ZF and the PF chain); reg → optional
    // parent64 zext (ia.sinc `build check_*32_dest`) plus resultflags reading
    // the destination varnode. ADD/SUB/AND/OR/XOR/ADC/SBB build the zext
    // BEFORE resultflags; NEG is the exception (`resultflags(Rmr32); build
    // check_Rmr32_dest;`), selected by `zext_after_resultflags`.
    /// Emit writeback + resultflags after an ALU value op.
    fn emit_alu_tail(
        &mut self,
        dst: AluDst,
        value_out: VarnodeRaw,
        zext_after_resultflags: bool,
        ops: &mut Vec<PcodeOpRaw>,
    ) {
        let emit_zext = |vn: &VarnodeRaw,
                         parent: &Option<VarnodeRaw>,
                         ops: &mut Vec<PcodeOpRaw>| {
            if let Some(parent) = parent {
                let mut op_zext = PcodeOpRaw::new(OpCode::CPUI_INT_ZEXT as i32);
                op_zext.add_input(vn.clone());
                op_zext.set_output(parent.clone());
                ops.push(op_zext);
            }
        };
        match dst {
            AluDst::Mem { addr } => {
                self.emit_store_v(&addr, value_out.clone(), ops);
                let size = value_out.size;
                // SF from re-LOAD
                let r1 = self.emit_load(size, &addr, ops);
                self.emit_sf_flag(&r1, ops);
                // ZF from re-LOAD
                let r2 = self.emit_load(size, &addr, ops);
                self.emit_zf_flag(&r2, ops);
                // PF chain from re-LOAD
                let r3 = self.emit_load(size, &addr, ops);
                self.emit_pf_flag(&r3, ops);
            }
            AluDst::Reg { vn, parent64 } => {
                if !zext_after_resultflags {
                    emit_zext(&vn, &parent64, ops);
                }
                self.emit_resultflags(vn.clone(), ops);
                if zext_after_resultflags {
                    emit_zext(&vn, &parent64, ops);
                }
            }
        }
    }

    // RUGRA-GLUE: ia.sinc :ADD constructors — `addflags(op1,op2); op1 = op1 +
    // op2; [check_*32_dest]; resultflags(op1)`; the value op writes the
    // destination varnode directly (no temp/COPY chain); memory forms
    /// Lift `add` (flags + value + zext + resultflags).
    fn lift_add(&mut self, inst: &Instruction, ops: &mut Vec<PcodeOpRaw>) {
        let Some((dst, op1, src)) = self.resolve_alu(inst, ops) else {
            return;
        };
        self.emit_addflags(&op1, &src, ops);
        let a = self.materialize(&op1, ops);
        let out = match &dst {
            AluDst::Reg { vn, .. } => vn.clone(),
            AluDst::Mem { .. } => a.clone(),
        };
        let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op.add_input(a);
        op.add_input(src);
        op.set_output(out.clone());
        ops.push(op);
        self.emit_alu_tail(dst, out, false, ops);
    }

    // RUGRA-GLUE: ia.sinc :SUB constructors — `subflags(op1,op2); op1 = op1 -
    // op2; [check_*32_dest]; resultflags(op1)`
    /// Lift `sub` (flags + value + zext + resultflags).
    fn lift_sub(&mut self, inst: &Instruction, ops: &mut Vec<PcodeOpRaw>) {
        let Some((dst, op1, src)) = self.resolve_alu(inst, ops) else {
            return;
        };
        self.emit_subflags(&op1, &src, ops);
        let a = self.materialize(&op1, ops);
        let out = match &dst {
            AluDst::Reg { vn, .. } => vn.clone(),
            AluDst::Mem { .. } => a.clone(),
        };
        let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_SUB as i32);
        op.add_input(a);
        op.add_input(src);
        op.set_output(out.clone());
        ops.push(op);
        self.emit_alu_tail(dst, out, false, ops);
    }

    // RUGRA-GLUE: ia.sinc :NEG constructors — `negflags(op1); op1 = -op1;
    // [check_*32_dest]; resultflags(op1)` (zext AFTER resultflags)
    /// Lift `neg` (negflags + INT_2COMP + resultflags + zext).
    fn lift_neg(&mut self, inst: &Instruction, ops: &mut Vec<PcodeOpRaw>) {
        if inst.operands.len() != 1 {
            return;
        }
        let (dst, op1) = match &inst.operands[0] {
            crate::disasm::Operand::Register { name, size } => {
                let vn = match Self::get_register(name, *size) {
                    Some(v) => v,
                    None => return,
                };
                let parent64 = if *size == 4 {
                    Self::parent64_name(name).and_then(|p| Self::get_register(p, 8))
                } else {
                    None
                };
                (AluDst::Reg { vn, parent64 }, Op1Ref::Direct(vn))
            }
            crate::disasm::Operand::Memory {
                base,
                index,
                scale,
                displacement,
                size,
            } => {
                let Some(addr) =
                    self.compute_mem_addr(base, index, scale, displacement, ops)
                else {
                    return;
                };
                (
                    AluDst::Mem { addr },
                    Op1Ref::MemLoad {
                        addr,
                        size: *size,
                    },
                )
            }
            _ => return,
        };
        // negflags reads op1 once per flag (re-LOAD per use for memory)
        self.emit_negflags(&op1, ops);
        let a = self.materialize(&op1, ops);
        let out = match &dst {
            AluDst::Reg { vn, .. } => vn.clone(),
            AluDst::Mem { .. } => a.clone(),
        };
        let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_2COMP as i32);
        op.add_input(a);
        op.set_output(out.clone());
        ops.push(op);
        // NEG builds check_Rmr32_dest AFTER resultflags (ia.sinc:4134)
        self.emit_alu_tail(dst, out, true, ops);
    }

    // RUGRA-GLUE: ia.sinc :NOT constructors — `Rmr = ~Rmr;` (no flags; 32-bit
    // register destinations still build check_Rmr32_dest → zext)
    /// Lift `not` (INT_NEGATE, no flags).
    fn lift_not(&mut self, inst: &Instruction, ops: &mut Vec<PcodeOpRaw>) {
        if inst.operands.len() != 1 {
            return;
        }
        let (dst, op1) = match &inst.operands[0] {
            crate::disasm::Operand::Register { name, size } => {
                let vn = match Self::get_register(name, *size) {
                    Some(v) => v,
                    None => return,
                };
                let parent64 = if *size == 4 {
                    Self::parent64_name(name).and_then(|p| Self::get_register(p, 8))
                } else {
                    None
                };
                (AluDst::Reg { vn, parent64 }, Op1Ref::Direct(vn))
            }
            crate::disasm::Operand::Memory {
                base,
                index,
                scale,
                displacement,
                size,
            } => {
                let Some(addr) =
                    self.compute_mem_addr(base, index, scale, displacement, ops)
                else {
                    return;
                };
                (
                    AluDst::Mem { addr },
                    Op1Ref::MemLoad {
                        addr,
                        size: *size,
                    },
                )
            }
            _ => return,
        };
        let a = self.materialize(&op1, ops);
        let out = match &dst {
            AluDst::Reg { vn, .. } => vn.clone(),
            AluDst::Mem { .. } => a.clone(),
        };
        let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_NEGATE as i32);
        op.add_input(a);
        op.set_output(out.clone());
        ops.push(op);
        // writeback only (no flags)
        match dst {
            AluDst::Mem { addr } => self.emit_store_v(&addr, out, ops),
            AluDst::Reg { vn, parent64 } => {
                if let Some(parent) = parent64 {
                    let mut op_zext = PcodeOpRaw::new(OpCode::CPUI_INT_ZEXT as i32);
                    op_zext.add_input(vn.clone());
                    op_zext.set_output(parent);
                    ops.push(op_zext);
                }
            }
        }
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
            "add" => {
                self.lift_add(inst, &mut ops);
            }
            "sub" => {
                self.lift_sub(inst, &mut ops);
            }
            "neg" => {
                self.lift_neg(inst, &mut ops);
            }
            "not" => {
                self.lift_not(inst, &mut ops);
            }
            "shl" | "shr" | "sal" | "sar" | "and" | "or" | "xor" => {
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
