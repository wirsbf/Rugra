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

// RUGRA-GLUE: SLEIGH binds operand expressions (memory address computation)
// BEFORE the constructor body runs, but the value read LOADs happen at each
// use inside the body — e.g. `test byte [rcx+rdx*2+1],8` lifts addr-ops,
// COPY CF, COPY OF, LOAD, INT_AND. BoundOperand is the bound form;
// read_bound() materializes one use.
enum BoundOperand {
    Reg(VarnodeRaw),
    Const(VarnodeRaw),
    MemAddr { addr: VarnodeRaw, size: usize },
}

// RUGRA-GLUE: shift direction for the ia.sinc SHL/SHR/SAR group-2
// constructors (locked sla value op: INT_LEFT / INT_RIGHT / INT_SRIGHT).
#[derive(Clone, Copy)]
enum ShiftDir {
    Left,
    Right,
    Arith,
}

// RUGRA-GLUE: rotate direction for the ia.sinc ROL/ROR group-2 rotate
// constructors (locked sla: value = OR of two opposite shifts of the same
// rm; evidence /tmp/w-ext-rol.out + /tmp/w-ext-ror.out).
#[derive(Clone, Copy)]
enum RotDir {
    Left,
    Right,
}

// RUGRA-GLUE: bit-test modify kind for the ia.sinc :BT/:BTS/:BTR/:BTC
// constructors (locked sla: CF = tested bit; modify op = OR / AND~ / XOR of
// the 1<<count mask; evidence /tmp/w-ext-bt.out + bts/btr/btc dumps).
#[derive(Clone, Copy, PartialEq, Eq)]
enum BtKind {
    Test,
    Set,
    Reset,
    Complement,
}

// RUGRA-GLUE: count source for the group-2 shift encodings. x86 encodes
// three DISTINCT count forms with different oracle pcode: C0/C1 imm8
// (count:4 = imm & mask, gated flag muxes), D0/D1 by-one (dedicated short
// form with no count temp), D2/D3 CL (count:1 = CL & mask). iced normalizes
// all three to the same mnemonic/operand shape, so the encoding opcode byte
// — after legacy prefixes and REX — is the only discriminator (evidence
// /tmp/w-shifts-dump-sleigh.out: `shl eax,1` C1-encoded lifts the 38-op
// general form while D1-encoded lifts the 11-op by-one form).
enum ShiftCount {
    /// C0/C1 — imm8 count (4-byte count temp in the oracle).
    Imm,
    /// D0/D1 — shift by one (dedicated constructor, no count temp).
    ByOne,
    /// D2/D3 — count in CL (1-byte count temp in the oracle).
    Cl,
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
            "r8" | "r8d" | "r8w" | "r8b" | "r8l" => 0x80,
            "r9" | "r9d" | "r9w" | "r9b" | "r9l" => 0x88,
            "r10" | "r10d" | "r10w" | "r10b" | "r10l" => 0x90,
            "r11" | "r11d" | "r11w" | "r11b" | "r11l" => 0x98,
            "r12" | "r12d" | "r12w" | "r12b" | "r12l" => 0xA0,
            "r13" | "r13d" | "r13w" | "r13b" | "r13l" => 0xA8,
            "r14" | "r14d" | "r14w" | "r14b" | "r14l" => 0xB0,
            "r15" | "r15d" | "r15w" | "r15b" | "r15l" => 0xB8,
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
            // Segment selectors live above the GPR/flag region in the locked
            // sla layout (dumped via examples/x86push_probe.rs: PUSH FS lifts
            // INT_ZEXT(register:0x108:2), PUSH GS 0x10a:2 — x86-64.sla
            // register space, 2-byte selector size).
            "fs" => 0x108,
            "gs" => 0x10a,
            // XMM vector registers: 0x1200 + 0x40*N in the locked sla
            // register space (dump /tmp/w-ext-comis.out: comiss xmm0 reads
            // register:0x1200:4, xmm1 0x1240:4, xmm8 0x1400:4; the varnode
            // size is the OPERATION size — 4 for *ss, 8 for *sd — not
            // iced's 16-byte vector width).
            "xmm0" => 0x1200,
            "xmm1" => 0x1240,
            "xmm2" => 0x1280,
            "xmm3" => 0x12c0,
            "xmm4" => 0x1300,
            "xmm5" => 0x1340,
            "xmm6" => 0x1380,
            "xmm7" => 0x13c0,
            "xmm8" => 0x1400,
            "xmm9" => 0x1440,
            "xmm10" => 0x1480,
            "xmm11" => 0x14c0,
            "xmm12" => 0x1500,
            "xmm13" => 0x1540,
            "xmm14" => 0x1580,
            "xmm15" => 0x15c0,
            _ => return None,
        };
        Some(VarnodeRaw::new(AddressSpace::Register, offset, size))
    }

    // RUGRA-GLUE: 寄存器名→偏移量映射（复用 get_register 的 match 表）。
    /// Map register name to offset (shared with get_register).
    fn reg_offset(name: &str) -> u64 {
        Self::get_register(name, 8).map(|v| v.offset).unwrap_or(0)
    }

    // RUGRA-GLUE: 64-bit view of a named GPR (address-table inputs are
    // full-width in the oracle push88 dump — base/index always 8 bytes).
    /// Full 64-bit register varnode by name.
    fn get_register_64(name: &str) -> Option<VarnodeRaw> {
        Self::get_register(name, 8)
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
    /// AF flag varnode (register:0x204:1; comiss writes it to 0)
    fn flag_af() -> VarnodeRaw {
        VarnodeRaw::new(AddressSpace::Register, 0x204, 1)
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
    // of each operand re-materializes (memory operands re-LOAD).
    /// Emit CF/OF for add (ia.sinc addflags; operands re-materialized per use).
    fn emit_addflags(&mut self, op1: &Op1Ref, op2: &Op1Ref, ops: &mut Vec<PcodeOpRaw>) {
        let a1 = self.materialize(op1, ops);
        let b1 = self.materialize(op2, ops);
        let mut op_cf = PcodeOpRaw::new(OpCode::CPUI_INT_CARRY as i32);
        op_cf.add_input(a1);
        op_cf.add_input(b1);
        op_cf.set_output(Self::flag_cf());
        ops.push(op_cf);
        let a2 = self.materialize(op1, ops);
        let b2 = self.materialize(op2, ops);
        let mut op_of = PcodeOpRaw::new(OpCode::CPUI_INT_SCARRY as i32);
        op_of.add_input(a2);
        op_of.add_input(b2);
        op_of.set_output(Self::flag_of());
        ops.push(op_of);
    }

    // RUGRA-GLUE: port of ia.sinc macro subflags(op1,op2) — CF = op1 < op2 =
    // INT_LESS, OF = sborrow(op1,op2) = INT_SBORROW; operands re-materialized
    /// Emit CF/OF for sub/cmp (ia.sinc subflags; operands re-materialized per use).
    fn emit_subflags(&mut self, op1: &Op1Ref, op2: &Op1Ref, ops: &mut Vec<PcodeOpRaw>) {
        let a1 = self.materialize(op1, ops);
        let b1 = self.materialize(op2, ops);
        let mut op_cf = PcodeOpRaw::new(OpCode::CPUI_INT_LESS as i32);
        op_cf.add_input(a1);
        op_cf.add_input(b1);
        op_cf.set_output(Self::flag_cf());
        ops.push(op_cf);
        let a2 = self.materialize(op1, ops);
        let b2 = self.materialize(op2, ops);
        let mut op_of = PcodeOpRaw::new(OpCode::CPUI_INT_SBORROW as i32);
        op_of.add_input(a2);
        op_of.add_input(b2);
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

    // RUGRA-GLUE: resolve ALU dst + operand references (both memory operands
    // re-LOAD per macro use — oracle `add rdi,[rax+8]` re-LOADs the source
    // for CARRY, SCARRY and the value op; immediates canonicalized to dst
    /// Resolve operands for a 2-operand ALU instruction; returns
    /// (dst access, op1 reference, src reference).
    fn resolve_alu(
        &mut self,
        inst: &Instruction,
        ops: &mut Vec<PcodeOpRaw>,
    ) -> Option<(AluDst, Op1Ref, Op1Ref)> {
        if inst.operands.len() != 2 {
            return None;
        }
        let dst_size = match &inst.operands[0] {
            crate::disasm::Operand::Register { size, .. } => *size,
            crate::disasm::Operand::Memory { size, .. } => *size,
            _ => return None,
        };

        // Operand binding: register/immediate direct, memory as per-use LOAD
        // (address computation emitted once here, at bind time).
        let mut bind_ref = |lifter: &mut Self, op: &crate::disasm::Operand| -> Option<Op1Ref> {
            match op {
                crate::disasm::Operand::Register { name, size } => {
                    Some(Op1Ref::Direct(Self::get_register(name, *size)?))
                }
                crate::disasm::Operand::Immediate { value, .. } => {
                    Some(Op1Ref::Direct(Self::const_vn(*value as u64, dst_size)))
                }
                crate::disasm::Operand::Memory {
                    base,
                    index,
                    scale,
                    displacement,
                    size,
                } => {
                    let addr = lifter.compute_mem_addr(base, index, scale, displacement, ops)?;
                    Some(Op1Ref::MemLoad {
                        addr,
                        size: *size,
                    })
                }
            }
        };

        let Some(src) = bind_ref(self, &inst.operands[1]) else {
            return None;
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
        let b = self.materialize(&src, ops);
        let out = match &dst {
            AluDst::Reg { vn, .. } => vn.clone(),
            AluDst::Mem { .. } => a.clone(),
        };
        let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op.add_input(a);
        op.add_input(b);
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
        let b = self.materialize(&src, ops);
        let out = match &dst {
            AluDst::Reg { vn, .. } => vn.clone(),
            AluDst::Mem { .. } => a.clone(),
        };
        let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_SUB as i32);
        op.add_input(a);
        op.add_input(b);
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

    // RUGRA-GLUE: bind an operand (emits address computation for memory;
    // immediates canonicalized to `canonical_size` — iced reports the
    /// Bind `op` without reading its value.
    fn bind_operand(
        &mut self,
        op: &crate::disasm::Operand,
        canonical_size: usize,
        ops: &mut Vec<PcodeOpRaw>,
    ) -> Option<BoundOperand> {
        match op {
            crate::disasm::Operand::Register { name, size } => {
                Some(BoundOperand::Reg(Self::get_register(name, *size)?))
            }
            crate::disasm::Operand::Immediate { value, .. } => {
                Some(BoundOperand::Const(Self::const_vn(
                    *value as u64,
                    canonical_size,
                )))
            }
            crate::disasm::Operand::Memory {
                base,
                index,
                scale,
                displacement,
                size,
            } => {
                let addr = self.compute_mem_addr(base, index, scale, displacement, ops)?;
                Some(BoundOperand::MemAddr {
                    addr,
                    size: *size,
                })
            }
        }
    }

    // RUGRA-GLUE: read a bound operand at one use (LOAD for memory).
    /// Materialize one use of a bound operand.
    fn read_bound(
        &mut self,
        bound: &BoundOperand,
        ops: &mut Vec<PcodeOpRaw>,
    ) -> VarnodeRaw {
        match bound {
            BoundOperand::Reg(vn) => vn.clone(),
            BoundOperand::Const(vn) => vn.clone(),
            BoundOperand::MemAddr { addr, size } => self.emit_load(*size, addr, ops),
        }
    }

    // RUGRA-GLUE: ia.sinc macro addCarryFlags(op1,op2) — `local CFcopy =
    // zext(CF); CF = carry(op1,op2); OF = scarry(op1,op2); local result =
    // op1 + op2; CF = CF || carry(result,CFcopy); OF = OF ^^ scarry(result,
    // CFcopy); op1 = result + CFcopy;` — the full-adder carry chain. CFcopy
    /// Lift `adc` (addCarryFlags + zext + resultflags).
    fn lift_adc(&mut self, inst: &Instruction, ops: &mut Vec<PcodeOpRaw>) {
        let Some((dst, op1, op2)) = self.resolve_alu(inst, ops) else {
            return;
        };
        let size = match &dst {
            AluDst::Reg { vn, .. } => vn.size,
            AluDst::Mem { addr: _, } => match &op1 {
                Op1Ref::Direct(vn) => vn.size,
                Op1Ref::MemLoad { size, .. } => *size,
            },
        };
        // local CFcopy = zext(CF)  (COPY when sizes match)
        let cfcopy = if size == 1 {
            let tmp = self.alloc_tmp(1);
            let mut op = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
            op.add_input(Self::flag_cf());
            op.set_output(tmp.clone());
            ops.push(op);
            tmp
        } else {
            let tmp = self.alloc_tmp(size);
            let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_ZEXT as i32);
            op.add_input(Self::flag_cf());
            op.set_output(tmp.clone());
            ops.push(op);
            tmp
        };
        // CF = carry(op1,op2); OF = scarry(op1,op2) — operands re-materialized
        let a1 = self.materialize(&op1, ops);
        let b1 = self.materialize(&op2, ops);
        let mut op_cf = PcodeOpRaw::new(OpCode::CPUI_INT_CARRY as i32);
        op_cf.add_input(a1);
        op_cf.add_input(b1);
        op_cf.set_output(Self::flag_cf());
        ops.push(op_cf);
        let a2 = self.materialize(&op1, ops);
        let b2 = self.materialize(&op2, ops);
        let mut op_of = PcodeOpRaw::new(OpCode::CPUI_INT_SCARRY as i32);
        op_of.add_input(a2);
        op_of.add_input(b2);
        op_of.set_output(Self::flag_of());
        ops.push(op_of);
        // local result = op1 + op2
        let a3 = self.materialize(&op1, ops);
        let b3 = self.materialize(&op2, ops);
        let result = self.alloc_tmp(size);
        let mut op_add = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op_add.add_input(a3);
        op_add.add_input(b3);
        op_add.set_output(result.clone());
        ops.push(op_add);
        // CF = CF || carry(result, CFcopy)
        let c2 = self.alloc_tmp(1);
        let mut op_c2 = PcodeOpRaw::new(OpCode::CPUI_INT_CARRY as i32);
        op_c2.add_input(result.clone());
        op_c2.add_input(cfcopy.clone());
        op_c2.set_output(c2.clone());
        ops.push(op_c2);
        let mut op_or = PcodeOpRaw::new(OpCode::CPUI_BOOL_OR as i32);
        op_or.add_input(Self::flag_cf());
        op_or.add_input(c2);
        op_or.set_output(Self::flag_cf());
        ops.push(op_or);
        // OF = OF ^^ scarry(result, CFcopy)
        let s2 = self.alloc_tmp(1);
        let mut op_s2 = PcodeOpRaw::new(OpCode::CPUI_INT_SCARRY as i32);
        op_s2.add_input(result.clone());
        op_s2.add_input(cfcopy.clone());
        op_s2.set_output(s2.clone());
        ops.push(op_s2);
        let mut op_xor = PcodeOpRaw::new(OpCode::CPUI_BOOL_XOR as i32);
        op_xor.add_input(Self::flag_of());
        op_xor.add_input(s2);
        op_xor.set_output(Self::flag_of());
        ops.push(op_xor);
        // op1 = result + CFcopy
        let out = match &dst {
            AluDst::Reg { vn, .. } => vn.clone(),
            AluDst::Mem { .. } => result.clone(),
        };
        let mut op_fin = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op_fin.add_input(result);
        op_fin.add_input(cfcopy);
        op_fin.set_output(out.clone());
        ops.push(op_fin);
        self.emit_alu_tail(dst, out, false, ops);
    }

    // RUGRA-GLUE: ia.sinc macro subCarryFlags(op1,op2) — `local CFcopy =
    // zext(CF); CF = op1 < op2; OF = sborrow(op1,op2); local result = op1 -
    // op2; CF = CF || (result < CFcopy); OF = OF ^^ sborrow(result,CFcopy);
    /// Lift `sbb` (subCarryFlags + zext + resultflags).
    fn lift_sbb(&mut self, inst: &Instruction, ops: &mut Vec<PcodeOpRaw>) {
        let Some((dst, op1, op2)) = self.resolve_alu(inst, ops) else {
            return;
        };
        let size = match &dst {
            AluDst::Reg { vn, .. } => vn.size,
            AluDst::Mem { addr: _ } => match &op1 {
                Op1Ref::Direct(vn) => vn.size,
                Op1Ref::MemLoad { size, .. } => *size,
            },
        };
        // local CFcopy = zext(CF)  (COPY when sizes match)
        let cfcopy = if size == 1 {
            let tmp = self.alloc_tmp(1);
            let mut op = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
            op.add_input(Self::flag_cf());
            op.set_output(tmp.clone());
            ops.push(op);
            tmp
        } else {
            let tmp = self.alloc_tmp(size);
            let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_ZEXT as i32);
            op.add_input(Self::flag_cf());
            op.set_output(tmp.clone());
            ops.push(op);
            tmp
        };
        // CF = op1 < op2; OF = sborrow(op1,op2)
        let a1 = self.materialize(&op1, ops);
        let b1 = self.materialize(&op2, ops);
        let mut op_cf = PcodeOpRaw::new(OpCode::CPUI_INT_LESS as i32);
        op_cf.add_input(a1);
        op_cf.add_input(b1);
        op_cf.set_output(Self::flag_cf());
        ops.push(op_cf);
        let a2 = self.materialize(&op1, ops);
        let b2 = self.materialize(&op2, ops);
        let mut op_of = PcodeOpRaw::new(OpCode::CPUI_INT_SBORROW as i32);
        op_of.add_input(a2);
        op_of.add_input(b2);
        op_of.set_output(Self::flag_of());
        ops.push(op_of);
        // local result = op1 - op2
        let a3 = self.materialize(&op1, ops);
        let b3 = self.materialize(&op2, ops);
        let result = self.alloc_tmp(size);
        let mut op_sub = PcodeOpRaw::new(OpCode::CPUI_INT_SUB as i32);
        op_sub.add_input(a3);
        op_sub.add_input(b3);
        op_sub.set_output(result.clone());
        ops.push(op_sub);
        // CF = CF || (result < CFcopy)
        let c2 = self.alloc_tmp(1);
        let mut op_c2 = PcodeOpRaw::new(OpCode::CPUI_INT_LESS as i32);
        op_c2.add_input(result.clone());
        op_c2.add_input(cfcopy.clone());
        op_c2.set_output(c2.clone());
        ops.push(op_c2);
        let mut op_or = PcodeOpRaw::new(OpCode::CPUI_BOOL_OR as i32);
        op_or.add_input(Self::flag_cf());
        op_or.add_input(c2);
        op_or.set_output(Self::flag_cf());
        ops.push(op_or);
        // OF = OF ^^ sborrow(result, CFcopy)
        let s2 = self.alloc_tmp(1);
        let mut op_s2 = PcodeOpRaw::new(OpCode::CPUI_INT_SBORROW as i32);
        op_s2.add_input(result.clone());
        op_s2.add_input(cfcopy.clone());
        op_s2.set_output(s2.clone());
        ops.push(op_s2);
        let mut op_xor = PcodeOpRaw::new(OpCode::CPUI_BOOL_XOR as i32);
        op_xor.add_input(Self::flag_of());
        op_xor.add_input(s2);
        op_xor.set_output(Self::flag_of());
        ops.push(op_xor);
        // op1 = result - CFcopy
        let out = match &dst {
            AluDst::Reg { vn, .. } => vn.clone(),
            AluDst::Mem { .. } => result.clone(),
        };
        let mut op_fin = PcodeOpRaw::new(OpCode::CPUI_INT_SUB as i32);
        op_fin.add_input(result);
        op_fin.add_input(cfcopy);
        op_fin.set_output(out.clone());
        ops.push(op_fin);
        self.emit_alu_tail(dst, out, false, ops);
    }

    // RUGRA-GLUE: ia.sinc :MOVZX/:MOVSX/:MOVSXD constructors (ia.sinc:4092-
    // 4115) — `Reg = zext/sext(rm)` (+ check_Reg32_dest for 32-bit
    // destinations); the same-size forms (MOVZX Reg16,rm16 / MOVSXD
    /// Lift movzx/movsx/movsxd (INT_ZEXT / INT_SEXT; COPY for same-size).
    fn lift_movx(
        &mut self,
        inst: &Instruction,
        extend_opcode: OpCode,
        ops: &mut Vec<PcodeOpRaw>,
    ) {
        if inst.operands.len() != 2 {
            return;
        }
        let (dst_vn, parent64) = match &inst.operands[0] {
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
                (vn, parent64)
            }
            _ => return,
        };
        // source (register direct / memory LOAD; address ops bind first)
        let src_b = match self.bind_operand(&inst.operands[1], dst_vn.size, ops) {
            Some(b) => b,
            None => return,
        };
        let src = self.read_bound(&src_b, ops);
        if src.size == dst_vn.size {
            // MOVZX Reg16,rm16 / MOVSXD Reg32,rm32 → plain COPY
            let mut op = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
            op.add_input(src);
            op.set_output(dst_vn.clone());
            ops.push(op);
        } else {
            let mut op = PcodeOpRaw::new(extend_opcode as i32);
            op.add_input(src);
            op.set_output(dst_vn.clone());
            ops.push(op);
        }
        if let Some(parent) = parent64 {
            let mut op_zext = PcodeOpRaw::new(OpCode::CPUI_INT_ZEXT as i32);
            op_zext.add_input(dst_vn.clone());
            op_zext.set_output(parent);
            ops.push(op_zext);
        }
    }

    // RUGRA-GLUE: ia.sinc :POP Rmr constructors (ia.sinc:4205-4215) —
    // `local val = 0; popNN(val); Rmr = val;` with pop88 `{ x = *:8 RSP;
    /// Lift pop (val init COPY, stack LOAD, RSP += size, COPY to register or
    /// STORE to memory).
    fn lift_pop(&mut self, inst: &Instruction, ops: &mut Vec<PcodeOpRaw>) {
        let Some(op0) = inst.operands.first() else {
            return;
        };
        let size = match op0 {
            crate::disasm::Operand::Register { size, .. } => *size,
            crate::disasm::Operand::Memory { size, .. } => *size,
            _ => return,
        };
        // bind memory destination address first (operand binding)
        let dst_bound = match self.bind_operand(op0, size, ops) {
            Some(b) => b,
            None => return,
        };
        // local val:size = 0  (constructor's dead local init — kept for
        // op-sequence parity with the sla lift)
        let val = self.alloc_tmp(size);
        let mut op_init = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op_init.add_input(Self::const_vn(0, size));
        op_init.set_output(val.clone());
        ops.push(op_init);
        // val = *:size RSP
        let rsp = match Self::get_register("rsp", 8) {
            Some(v) => v,
            None => return,
        };
        let mut op_load = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        op_load.add_input(Self::ram_space_const());
        op_load.add_input(rsp.clone());
        op_load.set_output(val.clone());
        ops.push(op_load);
        // RSP = RSP + size
        let mut op_add = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op_add.add_input(rsp);
        op_add.add_input(Self::const_vn(size as u64, 8));
        op_add.set_output(match Self::get_register("rsp", 8) {
            Some(v) => v,
            None => return,
        });
        ops.push(op_add);
        // Rmr = val
        match &dst_bound {
            BoundOperand::Reg(vn) => {
                let mut op = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
                op.add_input(val);
                op.set_output(vn.clone());
                ops.push(op);
            }
            BoundOperand::MemAddr { addr, .. } => {
                self.emit_store_v(addr, val, ops);
            }
            BoundOperand::Const(_) => {}
        }
    }

    // RUGRA-GLUE: ia.sinc :PUSH constructor family + push88 macro (x86-64
    // language of the locked oracle; semantics dumped op-for-op from
    // sleigh_specs/x86-64.sla via examples/x86push_probe.rs,
    // /tmp/w-push88-pushprobe.out). Every PUSH form first materializes the
    // source into a local val, then runs the push88 tail:
    //   RSP = RSP - sizeof(val);  *:sizeof(val) RSP = val
    // i.e. INT_SUB out=RSP:8 in=(RSP:8, const sizeof:8) THEN
    // STORE in=(ram-space-const, RSP:8, val). Per-form value ops (oracle):
    //   imm8/imm32 (6a/68) : COPY val:8 <- const sext(imm):8
    //   imm16 (66 68)      : COPY val:2 <- const imm:2   (no extension)
    //   reg (50+rd/FF /6)  : COPY val:s <- reg:s   (rsp reads PRE-decrement)
    //   fs/gs (0f a0/a8)   : INT_ZEXT val:8 <- seg:2 (FS=0x108, GS=0x10a)
    //   rm mem (FF /6)     : address ops + LOAD tl:s + COPY val:s <- tl:s
    //   rip-rel / absolute : COPY val:s <- ram:abs:s (no LOAD, no addr ops —
    //                         the sla folds a constant address into a direct
    //                         ram-space varnode input)
    /// Lift push (source materialization, RSP decrement, stack STORE).
    fn lift_push(&mut self, inst: &Instruction, ops: &mut Vec<PcodeOpRaw>) {
        let Some(op0) = inst.operands.first() else {
            return;
        };
        let rsp = match Self::get_register("rsp", 8) {
            Some(v) => v,
            None => return,
        };
        // val = <source operand>  (constructor local init; size = operand
        // size — 8 for 64-bit forms, 2 for 66-prefixed 16-bit forms)
        let Some(val) = self.push_source_val(op0, ops) else {
            return;
        };

        // push88 tail — RSP = RSP - sizeof(val)
        let mut op_sub = PcodeOpRaw::new(OpCode::CPUI_INT_SUB as i32);
        op_sub.add_input(rsp.clone());
        op_sub.add_input(Self::const_vn(val.size as u64, 8));
        op_sub.set_output(rsp.clone());
        ops.push(op_sub);
        // *:sizeof(val) RSP = val   (STORE address input IS the RSP varnode,
        // i.e. the post-decrement value)
        let mut op_store = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        op_store.add_input(Self::ram_space_const());
        op_store.add_input(rsp);
        op_store.add_input(val);
        ops.push(op_store);
    }

    // RUGRA-GLUE: ia.sinc :PUSH constructor local-init `val = <source>` —
    // the per-form value materialization listed in the lift_push evidence
    // table above (reg COPY / seg INT_ZEXT / imm COPY with per-width
    // extension / rm addr+LOAD+COPY / constant-address direct-ram COPY).
    /// Materialize the push source operand into a local val varnode.
    fn push_source_val(
        &mut self,
        op0: &crate::disasm::Operand,
        ops: &mut Vec<PcodeOpRaw>,
    ) -> Option<VarnodeRaw> {
        match op0 {
            crate::disasm::Operand::Register { name, size } => {
                // PUSH FS/GS (0f a0/a8): val:8 = zext(seg:2) — 2-byte
                // selector varnodes (sla dump), all other regs COPY at the
                // operand's own size.
                if name == "fs" || name == "gs" {
                    let seg = Self::get_register(name, 2)?;
                    let tmp = self.alloc_tmp(8);
                    let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_ZEXT as i32);
                    op.add_input(seg);
                    op.set_output(tmp.clone());
                    ops.push(op);
                    Some(tmp)
                } else {
                    let reg = Self::get_register(name, *size)?;
                    let tmp = self.alloc_tmp(*size);
                    let mut op = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
                    op.add_input(reg);
                    op.set_output(tmp.clone());
                    ops.push(op);
                    Some(tmp)
                }
            }
            crate::disasm::Operand::Immediate { value, size } => match *size {
                // imm8 (6a) / imm32 (68): sign-extended to a 64-bit constant
                // (oracle: 0x9c -> 0xffffffffffffff9c). The truncating cast
                // normalizes both raw and pre-extended immediate encodings
                // to the sign-extended value.
                1 | 4 => {
                    let shift = 64 - 8 * *size as u64;
                    let ext = (*value << shift) >> shift;
                    let tmp = self.alloc_tmp(8);
                    let mut op = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
                    op.add_input(Self::const_vn(ext as u64, 8));
                    op.set_output(tmp.clone());
                    ops.push(op);
                    Some(tmp)
                }
                // imm16 (66 68): raw 16-bit constant, val:2 (no extension)
                2 => {
                    let tmp = self.alloc_tmp(2);
                    let mut op = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
                    op.add_input(Self::const_vn(*value as u64, 2));
                    op.set_output(tmp.clone());
                    ops.push(op);
                    Some(tmp)
                }
                _ => None,
            },
            crate::disasm::Operand::Memory {
                base,
                index,
                scale,
                displacement,
                size,
            } => {
                // Constant address (rip-relative, or absolute disp-only):
                // oracle folds to a direct ram-space varnode input of COPY —
                // no LOAD, no address ops.
                if base.as_deref() == Some("rip")
                    || (base.is_none() && index.is_none() && *displacement != 0)
                {
                    // Rugra's X86_64Disassembler resolves a rip-relative
                    // operand's displacement to the ABSOLUTE target already
                    // (probe: `ff 35 34 12 00 00` @0x1036 reports
                    // displacement=0x2270=addr+len+0x1234, text
                    // `[rel 2270h]`; oracle lifts ram:0x2270) — so both the
                    // rip form and the absolute-disp form take the
                    // displacement as the ram offset directly.
                    let abs = *displacement as u64;
                    let tmp = self.alloc_tmp(*size);
                    let mut op = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
                    op.add_input(VarnodeRaw::new(AddressSpace::Ram, abs, *size));
                    op.set_output(tmp.clone());
                    ops.push(op);
                    Some(tmp)
                } else {
                    // Register-indirect: address ops per the oracle's
                    // modrm/SIB table shapes, then LOAD + COPY.
                    let addr = self.compute_push_src_addr(base, index, scale, displacement, ops)?;
                    let tl = self.emit_load(*size, &addr, ops);
                    let tmp = self.alloc_tmp(*size);
                    let mut op = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
                    op.add_input(tl);
                    op.set_output(tmp.clone());
                    ops.push(op);
                    Some(tmp)
                }
            }
        }
    }

    // RUGRA-GLUE: ia.sinc RM64/ModRM+SIB address tables as instantiated by
    // the :PUSH rm constructor (oracle op-for-op from x86-64.sla,
    // examples/x86push_probe.rs). SIB-ness is recoverable from the operand
    // shape alone: an index register, or a base that has no modrm-direct
    // encoding (rsp/r12 mirror as SIB base=100), means the SIB tables. The
    // two tables differ in op ORDER and operand order:
    //   modrm-direct [base+d] : INT_ADD(base, d)         — base first
    //   SIB [base+d]          : INT_ADD(d, base)         — disp first
    //   SIB [base+idx*s]      : INT_MULT(idx, s) [s=1 still emitted],
    //                          then INT_ADD(base, product)
    //   SIB [base+idx*s+d]    : INT_ADD(d, base), INT_MULT(idx, s),
    //                          INT_ADD(t1, product)
    //   SIB [idx*s+d] (no base): INT_MULT(idx, s), INT_ADD(d, product)
    //   d == 0                : folded — address is the bare base/product
    /// Compute a push memory source address, emitting oracle-ordered ops.
    fn compute_push_src_addr(
        &mut self,
        base: &Option<String>,
        index: &Option<String>,
        scale: &i32,
        displacement: &i64,
        ops: &mut Vec<PcodeOpRaw>,
    ) -> Option<VarnodeRaw> {
        let base_vn = base.as_deref().and_then(Self::get_register_64);
        let index_vn = index.as_deref().and_then(Self::get_register_64);
        // rsp/r12 have no modrm-direct encoding (rm=100 = SIB follow);
        // an index register likewise forces the SIB tables.
        let sib = index_vn.is_some() || matches!(base.as_deref(), Some("rsp") | Some("r12"));
        let emit_add = |this: &mut Self, a: VarnodeRaw, b: VarnodeRaw, ops: &mut Vec<PcodeOpRaw>| {
            let tmp = this.alloc_tmp(8);
            let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
            op.add_input(a);
            op.add_input(b);
            op.set_output(tmp.clone());
            ops.push(op);
            tmp
        };
        // SIB always multiplies the index by the scale byte, scale=1 included
        let emit_mult = |this: &mut Self, ops: &mut Vec<PcodeOpRaw>| -> Option<VarnodeRaw> {
            let idx = index_vn?;
            let tmp = this.alloc_tmp(8);
            let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_MULT as i32);
            op.add_input(idx);
            op.add_input(Self::const_vn(*scale as u64, 8));
            op.set_output(tmp.clone());
            ops.push(op);
            Some(tmp)
        };
        if sib {
            match (base_vn, index_vn.is_some(), *displacement != 0) {
                // [rsp+0x10] / [r12+0x160]: INT_ADD(disp, base)
                (Some(b), false, true) => {
                    let d = Self::const_vn(*displacement as u64, 8);
                    Some(emit_add(self, d, b, ops))
                }
                // [rax+rbx*4]: INT_MULT first, then INT_ADD(base, product)
                (Some(b), true, false) => {
                    let p = emit_mult(self, ops)?;
                    Some(emit_add(self, b, p, ops))
                }
                // [r8+rbx*4-0xC]: INT_ADD(disp, base) FIRST, then
                // INT_MULT(idx, scale), then INT_ADD(t1, product)
                (Some(b), true, true) => {
                    let d = Self::const_vn(*displacement as u64, 8);
                    let t1 = emit_add(self, d, b, ops);
                    let p = emit_mult(self, ops)?;
                    Some(emit_add(self, t1, p, ops))
                }
                // [rbx*4+0x12345678]: INT_MULT first, then INT_ADD(disp, product)
                (None, true, true) => {
                    let p = emit_mult(self, ops)?;
                    let d = Self::const_vn(*displacement as u64, 8);
                    Some(emit_add(self, d, p, ops))
                }
                // [rbx*4]: product alone
                (None, true, false) => emit_mult(self, ops),
                // [rsp] / [r12]: bare base
                (Some(b), false, false) => Some(b),
                // no base, no index, no disp: nothing to address — caller
                // (rip/abs routing) never reaches here
                (None, false, _) => None,
            }
        } else {
            match (base_vn, *displacement != 0) {
                // [rbp-8] / [r15+0x10]: INT_ADD(base, disp)
                (Some(b), true) => {
                    let d = Self::const_vn(*displacement as u64, 8);
                    Some(emit_add(self, b, d, ops))
                }
                // [rax] / [rdx]: bare base
                (Some(b), false) => Some(b),
                (None, _) => None,
            }
        }
    }

    // RUGRA-GLUE: ia.sinc :CWDE/:CDQE (ia.sinc:3004-3006) — `EAX = sext(AX)`
    /// Lift cwde/cdqe (INT_SEXT into the wider accumulator; 32-bit cwde adds
    /// the check_EAX_dest zext).
    fn lift_widen_acc(&mut self, inst: &Instruction, ops: &mut Vec<PcodeOpRaw>) {
        let size = match inst.mnemonic.as_str() {
            "cbw" => (2, 1),   // AX = sext(AL)
            "cwde" => (4, 2),  // EAX = sext(AX)
            "cdqe" => (8, 4),  // RAX = sext(EAX)
            _ => return,
        };
        let (dst_size, src_size) = size;
        let Some(acc) = Self::get_register("rax", dst_size) else {
            return;
        };
        let Some(src) = Self::get_register("rax", src_size) else {
            return;
        };
        let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_SEXT as i32);
        op.add_input(src);
        op.set_output(acc.clone());
        ops.push(op);
        if inst.mnemonic == "cwde" {
            // check_EAX_dest: RAX = zext(EAX)
            if let (Some(eax), Some(rax)) = (
                Self::get_register("eax", 4),
                Self::get_register("rax", 8),
            ) {
                let mut op_z = PcodeOpRaw::new(OpCode::CPUI_INT_ZEXT as i32);
                op_z.add_input(eax);
                op_z.set_output(rax);
                ops.push(op_z);
            }
        }
    }

    // RUGRA-GLUE: ia.sinc :CDQ/:CQO (ia.sinc:3010-3012) — `tmp:16 =
    /// Lift cdq/cqo (INT_SEXT into a double-width temp, SUBPIECE the low
    /// half into EDX/RDX).
    fn lift_sign_dividend(&mut self, inst: &Instruction, ops: &mut Vec<PcodeOpRaw>) {
        let (dst_size, src_size, dst_name, src_name) = match inst.mnemonic.as_str() {
            "cdq" => (4usize, 4usize, "edx", "eax"),
            "cqo" => (8, 8, "rdx", "rax"),
            _ => return,
        };
        let Some(src) = Self::get_register(src_name, src_size) else {
            return;
        };
        // tmp = sext(src)
        let tmp = self.alloc_tmp(src_size * 2);
        let mut op_sext = PcodeOpRaw::new(OpCode::CPUI_INT_SEXT as i32);
        op_sext.add_input(src);
        op_sext.set_output(tmp.clone());
        ops.push(op_sext);
        // RDX = tmp(0)  → SUBPIECE low half
        let Some(dst) = Self::get_register(dst_name, dst_size) else {
            return;
        };
        let mut op_piece = PcodeOpRaw::new(OpCode::CPUI_SUBPIECE as i32);
        op_piece.add_input(tmp);
        op_piece.add_input(Self::const_vn(0, 4));
        op_piece.set_output(dst.clone());
        ops.push(op_piece);
        // 32-bit cdq: check_EDX_dest → RDX = zext(EDX)
        if inst.mnemonic == "cdq" {
            if let (Some(edx), Some(rdx)) =
                (Self::get_register("edx", 4), Self::get_register("rdx", 8))
            {
                let mut op_z = PcodeOpRaw::new(OpCode::CPUI_INT_ZEXT as i32);
                op_z.add_input(edx);
                op_z.set_output(rdx);
                ops.push(op_z);
            }
        }
    }

    // RUGRA-GLUE: ia.sinc :CMOV^cc constructors (ia.sinc:3043-3046) —
    // `{ local tmp = rm; if (!cc) goto inst_next; Reg = tmp; }` — lifted
    /// Lift cmovcc (cond ops, tmp copy, old-dst zext for 32-bit, negate,
    /// CBRANCH over the move, final COPY).
    fn lift_cmov(&mut self, inst: &Instruction, cc: &str, ops: &mut Vec<PcodeOpRaw>) {
        if inst.operands.len() != 2 {
            return;
        }
        // destination must be a register
        let (dst_vn, parent64) = match &inst.operands[0] {
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
                (vn, parent64)
            }
            _ => return,
        };
        // bind source address (memory) before the body
        let src_bound = match self.bind_operand(&inst.operands[1], dst_vn.size, ops) {
            Some(b) => b,
            None => return,
        };
        // condition computation (cc table) — flag reads hoisted by SLEIGH
        // before `local tmp = rm`
        let Some(cond) = self.emit_cc_cond(cc, ops) else {
            return;
        };
        // local tmp = rm (register source → COPY; memory source → LOAD)
        let tmp = match &src_bound {
            BoundOperand::MemAddr { addr, size } => self.emit_load(*size, addr, ops),
            BoundOperand::Reg(vn) | BoundOperand::Const(vn) => {
                let t = self.alloc_tmp(vn.size);
                let mut op = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
                op.add_input(vn.clone());
                op.set_output(t.clone());
                ops.push(op);
                t
            }
        };
        // 32-bit destinations zext the OLD value before the branch
        if let Some(parent) = parent64 {
            let mut op_zext = PcodeOpRaw::new(OpCode::CPUI_INT_ZEXT as i32);
            op_zext.add_input(dst_vn.clone());
            op_zext.set_output(parent);
            ops.push(op_zext);
        }
        // if (!cc) goto inst_next
        let not_cond = self.emit_bool_not(cond, ops);
        let next = inst.address.as_u64() + inst.length as u64;
        let mut op_cbr = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
        op_cbr.add_input(VarnodeRaw::new(AddressSpace::Ram, next, 8));
        op_cbr.add_input(not_cond);
        ops.push(op_cbr);
        // Reg = tmp
        let mut op_copy = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op_copy.add_input(tmp);
        op_copy.set_output(dst_vn);
        ops.push(op_copy);
    }

    // RUGRA-GLUE: ia.sinc :SET^cc rm8 (ia.sinc:4595) — `{ rm8 = cc; }` —
    /// Lift setcc (cond ops, then COPY to the 1-byte register or STORE for
    /// memory destinations).
    fn lift_setcc(&mut self, inst: &Instruction, cc: &str, ops: &mut Vec<PcodeOpRaw>) {
        if inst.operands.len() != 1 {
            return;
        }
        // bind destination (register direct / memory address) first
        let Some(dst_op) = inst.operands.first() else {
            return;
        };
        let dst_bound = match self.bind_operand(dst_op, 1, ops) {
            Some(b) => b,
            None => return,
        };
        let Some(cond) = self.emit_cc_cond(cc, ops) else {
            return;
        };
        match &dst_bound {
            BoundOperand::Reg(vn) => {
                let mut op = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
                op.add_input(cond);
                op.set_output(vn.clone());
                ops.push(op);
            }
            BoundOperand::MemAddr { addr, .. } => {
                self.emit_store_v(addr, cond, ops);
            }
            BoundOperand::Const(_) => {}
        }
    }

    // RUGRA-GLUE: ia.sinc :AND/:OR/:XOR constructors — `logicalflags(); Rmr =
    // Rmr OP imm; [check_*32_dest]; resultflags(Rmr)`; CF/OF cleared before
    // any operand LOAD; memory forms re-LOAD per use like add.
    /// Lift and/or/xor (logicalflags + value + zext + resultflags).
    fn lift_logic(
        &mut self,
        inst: &Instruction,
        value_opcode: OpCode,
        ops: &mut Vec<PcodeOpRaw>,
    ) {
        if inst.operands.len() != 2 {
            return;
        }
        let dst_size = match &inst.operands[0] {
            crate::disasm::Operand::Register { size, .. } => *size,
            crate::disasm::Operand::Memory { size, .. } => *size,
            _ => return,
        };
        // operand binding (address computation) precedes the body
        let src_b = match self.bind_operand(&inst.operands[1], dst_size, ops) {
            Some(b) => b,
            None => return,
        };
        let (dst, op1_bound) = match &inst.operands[0] {
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
                (
                    AluDst::Reg { vn, parent64 },
                    BoundOperand::Reg(vn),
                )
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
                    BoundOperand::MemAddr {
                        addr,
                        size: *size,
                    },
                )
            }
            _ => return,
        };
        // logicalflags() is the body's first statement: CF = 0, OF = 0
        self.emit_logicalflags(ops);
        let src = self.read_bound(&src_b, ops);
        let a = self.read_bound(&op1_bound, ops);
        let out = match &dst {
            AluDst::Reg { vn, .. } => vn.clone(),
            AluDst::Mem { .. } => a.clone(),
        };
        let mut op = PcodeOpRaw::new(value_opcode as i32);
        op.add_input(a);
        op.add_input(src);
        op.set_output(out.clone());
        ops.push(op);
        self.emit_alu_tail(dst, out, false, ops);
    }

    // RUGRA-GLUE: ia.sinc :CMP constructors — `local temp = rm; subflags
    // (temp,src); local diff = temp - src; resultflags(diff)`; BOTH operands
    // take the local-cached form: register direct (SLEIGH elides the local),
    // memory is a single LOAD + COPY reused by every use (oracle `cmp
    // esi,[rcx+r12*4]`: addr, LOAD, COPY, INT_LESS, INT_SBORROW, INT_SUB...).
    /// Lift `cmp` (subflags + INT_SUB to temp + resultflags; no store/zext).
    fn lift_cmp(&mut self, inst: &Instruction, ops: &mut Vec<PcodeOpRaw>) {
        if inst.operands.len() != 2 {
            return;
        }
        let dst_size = match &inst.operands[0] {
            crate::disasm::Operand::Register { size, .. } => *size,
            crate::disasm::Operand::Memory { size, .. } => *size,
            _ => return,
        };
        // local cache: register/immediate direct, memory LOAD + COPY
        let cache_operand =
            |lifter: &mut Self, op: &crate::disasm::Operand, ops: &mut Vec<PcodeOpRaw>| -> Option<VarnodeRaw> {
                match op {
                    crate::disasm::Operand::Register { name, size } => {
                        Self::get_register(name, *size)
                    }
                    crate::disasm::Operand::Immediate { value, .. } => {
                        Some(Self::const_vn(*value as u64, dst_size))
                    }
                    crate::disasm::Operand::Memory {
                        base,
                        index,
                        scale,
                        displacement,
                        size,
                    } => {
                        let addr = lifter.compute_mem_addr(base, index, scale, displacement, ops)?;
                        let loaded = lifter.emit_load(*size, &addr, ops);
                        let temp = lifter.alloc_tmp(*size);
                        let mut op = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
                        op.add_input(loaded);
                        op.set_output(temp.clone());
                        ops.push(op);
                        Some(temp)
                    }
                }
            };
        let Some(src) = cache_operand(self, &inst.operands[1], ops) else {
            return;
        };
        let Some(temp) = cache_operand(self, &inst.operands[0], ops) else {
            return;
        };
        let op1 = Op1Ref::Direct(temp.clone());
        let op2 = Op1Ref::Direct(src.clone());
        self.emit_subflags(&op1, &op2, ops);
        let diff = self.alloc_tmp(dst_size);
        let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_SUB as i32);
        op.add_input(temp);
        op.add_input(src);
        op.set_output(diff.clone());
        ops.push(op);
        self.emit_resultflags(diff, ops);
    }

    // RUGRA-GLUE: ia.sinc :TEST constructors — `logicalflags(); local
    // tmpflag = rm & imm; resultflags(tmpflag)`; single operand read.
    /// Lift `test` (logicalflags + INT_AND to temp + resultflags; no store).
    fn lift_test(&mut self, inst: &Instruction, ops: &mut Vec<PcodeOpRaw>) {
        if inst.operands.len() != 2 {
            return;
        }
        let dst_size = match &inst.operands[0] {
            crate::disasm::Operand::Register { size, .. } => *size,
            crate::disasm::Operand::Memory { size, .. } => *size,
            _ => return,
        };
        // operand binding (address computation) precedes the body
        let src_b = match self.bind_operand(&inst.operands[1], dst_size, ops) {
            Some(b) => b,
            None => return,
        };
        let op0_b = match self.bind_operand(&inst.operands[0], dst_size, ops) {
            Some(b) => b,
            None => return,
        };
        // logicalflags(): CF = 0, OF = 0 (body's first statement)
        self.emit_logicalflags(ops);
        let src = self.read_bound(&src_b, ops);
        let a = self.read_bound(&op0_b, ops);
        let tmp = self.alloc_tmp(dst_size);
        let mut op = PcodeOpRaw::new(OpCode::CPUI_INT_AND as i32);
        op.add_input(a);
        op.add_input(src);
        op.set_output(tmp.clone());
        ops.push(op);
        self.emit_resultflags(tmp, ops);
    }

    // RUGRA-GLUE: raw pcode emit helper for the shift constructors — keeps
    // every emit site in the exact op order of the locked sla dump.
    /// Push one pcode op with the given inputs and optional output.
    fn push_raw(
        ops: &mut Vec<PcodeOpRaw>,
        opcode: OpCode,
        ins: &[VarnodeRaw],
        out: Option<&VarnodeRaw>,
    ) {
        let mut op = PcodeOpRaw::new(opcode as i32);
        for v in ins {
            op.add_input(v.clone());
        }
        if let Some(o) = out {
            op.set_output(o.clone());
        }
        ops.push(op);
    }

    // RUGRA-GLUE: group-2 shift encoding discriminator. The locked sla has
    // THREE distinct constructors per direction with different pcode:
    // C0/C1 imm-count (38-op gated form), D0/D1 by-one (short direct-flag
    // form), D2/D3 CL-count. iced normalizes all three to the same
    // mnemonic/operand shape AND the disassembler never populates
    // Instruction.bytes (src/disasm/x86_64.rs:51), so the form is
    // reconstructed from the operands: a CL register operand is definitive
    // (D2/D3); an imm8 count != 1 is definitive (C0/C1); an imm8 count == 1
    // is disambiguated by exact instruction-length arithmetic — the by-one
    // encoding is always exactly one byte shorter than the imm8 encoding of
    // the same instruction (same prefixes/modrm/SIB/disp, minus imm8), so
    // computing the canonical by-one length from the operands separates
    // D1-encoded `shl eax,1` (len 2) from C1-encoded (len 3). Exact for
    // canonical (assembler-minimal disp8) encodings, i.e. all
    // compiler-emitted code and every fixture form; a hypothetical
    // non-canonical by-one encoding with redundant disp32 falls back to the
    // imm form (disclosed X86LIFT-SHIFTS-FLAGS-0001 limitation — root fix
    // is populating Instruction.bytes in x86_64.rs, outside this task's
    // write-set).
    /// Classify the count form (C0/C1 imm, D0/D1 by-one, D2/D3 CL).
    fn shift_count_form(inst: &Instruction) -> Option<ShiftCount> {
        match inst.operands.get(1)? {
            crate::disasm::Operand::Register { name, size } => {
                if name == "cl" && *size == 1 {
                    Some(ShiftCount::Cl)
                } else {
                    None
                }
            }
            crate::disasm::Operand::Immediate { value, .. } => {
                if *value != 1 {
                    return Some(ShiftCount::Imm);
                }
                match Self::shift_byone_len(inst) {
                    Some(byone) if inst.length == byone => Some(ShiftCount::ByOne),
                    _ => Some(ShiftCount::Imm),
                }
            }
            _ => None,
        }
    }

    // RUGRA-GLUE: canonical encoding length of the by-one form (D0/D1) for
    // the same operands — prefixes (0x66 for 16-bit, REX) + opcode + modrm
    // + SIB + displacement; reg forms are mod=3 (no SIB/disp). Used only to
    /// Compute the by-one encoding length for form disambiguation.
    fn shift_byone_len(inst: &Instruction) -> Option<usize> {
        let size = match &inst.operands[0] {
            crate::disasm::Operand::Register { size, .. } => *size,
            crate::disasm::Operand::Memory { size, .. } => *size,
            _ => return None,
        };
        let mut len = 0usize;
        if size == 2 {
            len += 1; // 0x66 operand-size prefix
        }
        match &inst.operands[0] {
            crate::disasm::Operand::Register { name, .. } => {
                let id = Self::gpr_id(name)?;
                let rex = size == 8
                    || id >= 8
                    || (size == 1 && matches!(name.as_str(), "spl" | "bpl" | "sil" | "dil"));
                if rex {
                    len += 1;
                }
                len += 2; // opcode + modrm (mod=3)
            }
            crate::disasm::Operand::Memory { base, index, displacement, .. } => {
                let base_id = base.as_deref().and_then(Self::gpr_id);
                let index_id = index.as_deref().and_then(Self::gpr_id);
                let rex = size == 8
                    || base_id.is_some_and(|i| i >= 8)
                    || index_id.is_some_and(|i| i >= 8);
                if rex {
                    len += 1;
                }
                len += 2; // opcode + modrm
                // SIB when an index register is present or the base
                // encodes rm=100 (rsp/r12 families)
                if index.is_some() || base_id == Some(4) || base_id == Some(12) {
                    len += 1;
                }
                // displacement size (canonical minimal)
                if let Some(bname) = base {
                    if bname == "rip" || bname == "eip" {
                        len += 4;
                    } else {
                        let bid = base_id?;
                        if *displacement == 0 && bid != 5 && bid != 13 {
                            // mod=00, no disp (rbp/r13 base needs disp8=0)
                        } else if *displacement >= -128 && *displacement <= 127 {
                            len += 1;
                        } else {
                            len += 4;
                        }
                    }
                } else {
                    len += 4; // no base: SIB base=101 / direct disp32
                }
            }
            _ => return None,
        }
        Some(len)
    }

    // RUGRA-GLUE: GPR number (0-15) from a register name via the sla offset
    // table (ah/ch/dh/bh sit one byte above their GPR base).
    /// Map a GPR name to its 0-15 register number.
    fn gpr_id(name: &str) -> Option<u8> {
        let off = Self::get_register(name, 1)?.offset;
        if off >= 0xC0 {
            return None; // flags/segment/RIP region — not a GPR
        }
        Some(if matches!(off, 0x01 | 0x09 | 0x11 | 0x19) {
            ((off - 1) / 8) as u8
        } else {
            (off / 8) as u8
        })
    }

    // RUGRA-GLUE: LOAD into a caller-provided slot varnode — the sla reuses
    // ONE unique local slot for every re-LOAD of the rm operand in the
    /// Emit LOAD from `addr` into `slot`.
    fn emit_load_slot(
        &mut self,
        addr: &VarnodeRaw,
        slot: &VarnodeRaw,
        ops: &mut Vec<PcodeOpRaw>,
    ) {
        let mut op = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        op.add_input(Self::ram_space_const());
        op.add_input(addr.clone());
        op.set_output(slot.clone());
        ops.push(op);
    }

    // RUGRA-GLUE: port of the ia.sinc :SHL/:SHR/:SAR group-2 constructors of
    // the locked x86-64 sla (sleigh_specs/x86-64.sla, sleigh_shim op-for-op
    // dump /tmp/w-shifts-dump-sleigh.out, 56 forms). Structure per dump:
    //   imm/cl form — `local count = imm&mask / CL&mask`; `local tmpflags =
    //   rm << 0` (COPY save); `rm = rm <shift> count`; [+zext for 32-bit GPR
    //   dst]; shlflags(): CF = count==0 ? CF : bit-shifted-out,
    //   OF = count==1 ? dir-specific : OF; then shiftresultflags(): SF/ZF/PF
    //   each gated by count!=0 (preserved when count==0). Memory
    //   destinations re-LOAD the rm slot at every flag use.
    //   by-one form (D0/D1) — dedicated short constructors: shl CF from the
    //   pre-shift top bit, OF = CF ^ result-top after the value op; shr/sar
    //   CF = (rm&1)!=0 (8-bit writes CF directly), OF = 0, no gating.
    /// Lift `shl`/`sal`/`shr`/`sar` (all count forms; flags + value + zext).
    fn lift_shift(&mut self, inst: &Instruction, dir: ShiftDir, ops: &mut Vec<PcodeOpRaw>) {
        use OpCode as C;
        if inst.operands.len() != 2 {
            return;
        }
        let Some(form) = Self::shift_count_form(inst) else {
            return;
        };

        // Destination binding — memory address ops precede the constructor
        // body (dump `shl dword [rbx+8],3`: ADD, AND(count), LOAD, ...).
        let (dst, size) = match &inst.operands[0] {
            crate::disasm::Operand::Register { name, size } => {
                let Some(vn) = Self::get_register(name, *size) else {
                    return;
                };
                let parent64 = if *size == 4 {
                    Self::parent64_name(name).and_then(|p| Self::get_register(p, 8))
                } else {
                    None
                };
                (AluDst::Reg { vn, parent64 }, *size)
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
                (AluDst::Mem { addr }, *size)
            }
            _ => return,
        };

        let shift_op = match dir {
            ShiftDir::Left => C::CPUI_INT_LEFT,
            ShiftDir::Right => C::CPUI_INT_RIGHT,
            ShiftDir::Arith => C::CPUI_INT_SRIGHT,
        };
        // count==0 / count==1 gating constants use the count width; result
        // comparisons use the operand width.
        let mask: u64 = if size == 8 { 0x3f } else { 0x1f };

        // read_result: post-value rm for reg dst (register varnode) or a
        // re-LOAD into the ONE shared mem slot (the oracle reuses a single
        // unique local for every rm re-read — dump `shl byte [rbx],3` loads
        // unique#1 six times).
        let mem_slot = match &dst {
            AluDst::Mem { .. } => Some(self.alloc_tmp(size)),
            AluDst::Reg { .. } => None,
        };
        let read_result = |this: &mut Self, ops: &mut Vec<PcodeOpRaw>| -> VarnodeRaw {
            match (&dst, &mem_slot) {
                (AluDst::Reg { vn, .. }, _) => vn.clone(),
                (AluDst::Mem { addr }, Some(slot)) => {
                    this.emit_load_slot(addr, slot, ops);
                    slot.clone()
                }
                _ => unreachable!("mem dst must have a slot"),
            }
        };

        if let ShiftCount::ByOne = form {
            // ---- D0/D1 dedicated by-one constructors ----
            let one = Self::const_vn(1, 4);
            match dir {
                ShiftDir::Left => {
                    // CF = rm s< 0 (pre-shift top bit), BEFORE the value op
                    let r0 = read_result(self, ops);
                    Self::push_raw(
                        ops,
                        C::CPUI_INT_SLESS,
                        &[r0, Self::const_vn(0, size)],
                        Some(&Self::flag_cf()),
                    );
                    // rm = rm << 1
                    match &dst {
                        AluDst::Reg { vn, .. } => Self::push_raw(
                            ops,
                            shift_op,
                            &[vn.clone(), one],
                            Some(vn),
                        ),
                        AluDst::Mem { addr } => {
                            let slot = mem_slot.clone().expect("mem dst must have a slot");
                            self.emit_load_slot(addr, &slot, ops);
                            Self::push_raw(ops, shift_op, &[slot.clone(), one], Some(&slot));
                            self.emit_store_v(addr, slot, ops);
                        }
                    }
                    // OF = CF ^ (rm s< 0)  (direct flag output)
                    let r1 = read_result(self, ops);
                    let t_sign = self.alloc_tmp(1);
                    Self::push_raw(
                        ops,
                        C::CPUI_INT_SLESS,
                        &[r1, Self::const_vn(0, size)],
                        Some(&t_sign),
                    );
                    Self::push_raw(
                        ops,
                        C::CPUI_INT_XOR,
                        &[Self::flag_cf(), t_sign],
                        Some(&Self::flag_of()),
                    );
                    // zext for 32-bit GPR dst comes AFTER the OF op
                    if let AluDst::Reg { vn, parent64 } = &dst {
                        if let Some(parent) = parent64 {
                            Self::push_raw(ops, C::CPUI_INT_ZEXT, &[vn.clone()], Some(parent));
                        }
                    }
                }
                ShiftDir::Right | ShiftDir::Arith => {
                    // CF = rm & 1 (8-bit writes the AND directly into CF);
                    // OF = 0; both precede the value op
                    let r0 = read_result(self, ops);
                    if size == 1 {
                        Self::push_raw(
                            ops,
                            C::CPUI_INT_AND,
                            &[r0, Self::const_vn(1, 1)],
                            Some(&Self::flag_cf()),
                        );
                    } else {
                        let t0 = self.alloc_tmp(size);
                        Self::push_raw(
                            ops,
                            C::CPUI_INT_AND,
                            &[r0, Self::const_vn(1, size)],
                            Some(&t0),
                        );
                        Self::push_raw(
                            ops,
                            C::CPUI_INT_NOTEQUAL,
                            &[t0, Self::const_vn(0, size)],
                            Some(&Self::flag_cf()),
                        );
                    }
                    Self::push_raw(
                        ops,
                        C::CPUI_COPY,
                        &[Self::const_vn(0, 1)],
                        Some(&Self::flag_of()),
                    );
                    // rm = rm >> 1 (logical or arithmetic)
                    match &dst {
                        AluDst::Reg { vn, .. } => Self::push_raw(
                            ops,
                            shift_op,
                            &[vn.clone(), one],
                            Some(vn),
                        ),
                        AluDst::Mem { addr } => {
                            let slot = mem_slot.clone().expect("mem dst must have a slot");
                            self.emit_load_slot(addr, &slot, ops);
                            Self::push_raw(ops, shift_op, &[slot.clone(), one], Some(&slot));
                            self.emit_store_v(addr, slot, ops);
                        }
                    }
                    // zext for 32-bit GPR dst (after the value op)
                    if let AluDst::Reg { vn, parent64 } = &dst {
                        if let Some(parent) = parent64 {
                            Self::push_raw(ops, C::CPUI_INT_ZEXT, &[vn.clone()], Some(parent));
                        }
                    }
                }
            }
            // ungated SF/ZF/PF (direct flag outputs; mem re-LOADs per flag)
            let r_sf = read_result(self, ops);
            Self::push_raw(
                ops,
                C::CPUI_INT_SLESS,
                &[r_sf, Self::const_vn(0, size)],
                Some(&Self::flag_sf()),
            );
            let r_zf = read_result(self, ops);
            Self::push_raw(
                ops,
                C::CPUI_INT_EQUAL,
                &[r_zf, Self::const_vn(0, size)],
                Some(&Self::flag_zf()),
            );
            let r_pf = read_result(self, ops);
            let t_and = self.alloc_tmp(size);
            Self::push_raw(
                ops,
                C::CPUI_INT_AND,
                &[r_pf, Self::const_vn(0xff, size)],
                Some(&t_and),
            );
            let t_pop = self.alloc_tmp(1);
            Self::push_raw(ops, C::CPUI_POPCOUNT, &[t_and], Some(&t_pop));
            let t_bit = self.alloc_tmp(1);
            Self::push_raw(
                ops,
                C::CPUI_INT_AND,
                &[t_pop, Self::const_vn(1, 1)],
                Some(&t_bit),
            );
            Self::push_raw(
                ops,
                C::CPUI_INT_EQUAL,
                &[t_bit, Self::const_vn(0, 1)],
                Some(&Self::flag_pf()),
            );
            return;
        }

        // ---- imm (C0/C1) / cl (D2/D3) general form ----
        // local count = imm & mask (:4) / CL & mask (:1) — one AND op
        let (t_count, cs) = match form {
            ShiftCount::Cl => {
                let cl = match &inst.operands[1] {
                    crate::disasm::Operand::Register { name, size } => {
                        match Self::get_register(name, *size) {
                            Some(vn) => vn,
                            None => return,
                        }
                    }
                    _ => return,
                };
                let t = self.alloc_tmp(1);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_AND,
                    &[cl, Self::const_vn(mask, 1)],
                    Some(&t),
                );
                (t, 1)
            }
            ShiftCount::Imm => {
                let value = match &inst.operands[1] {
                    crate::disasm::Operand::Immediate { value, .. } => *value,
                    _ => return,
                };
                let t = self.alloc_tmp(4);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_AND,
                    &[Self::const_vn((value & 0xff) as u64, 4), Self::const_vn(mask, 4)],
                    Some(&t),
                );
                (t, 4)
            }
            ShiftCount::ByOne => unreachable!("handled above"),
        };

        // local tmpflags = rm << 0 (COPY save); rm = rm <shift> count;
        // [+zext]; memory form re-LOADs the rm slot for the value op.
        let save = match &dst {
            AluDst::Reg { vn, .. } => {
                let save = self.alloc_tmp(size);
                Self::push_raw(ops, C::CPUI_COPY, &[vn.clone()], Some(&save));
                save
            }
            AluDst::Mem { addr } => {
                let slot = mem_slot.clone().expect("mem dst must have a slot");
                self.emit_load_slot(addr, &slot, ops);
                let save = self.alloc_tmp(size);
                Self::push_raw(ops, C::CPUI_COPY, &[slot.clone()], Some(&save));
                self.emit_load_slot(addr, &slot, ops);
                Self::push_raw(ops, shift_op, &[slot.clone(), t_count.clone()], Some(&slot));
                self.emit_store_v(addr, slot, ops);
                save
            }
        };
        if let AluDst::Reg { vn, parent64 } = &dst {
            Self::push_raw(ops, shift_op, &[vn.clone(), t_count.clone()], Some(vn));
            if let Some(parent) = parent64 {
                Self::push_raw(ops, C::CPUI_INT_ZEXT, &[vn.clone()], Some(parent));
            }
        }

        // ---- shlflags(): CF ----
        let t_ne = self.alloc_tmp(1);
        Self::push_raw(
            ops,
            C::CPUI_INT_NOTEQUAL,
            &[t_count.clone(), Self::const_vn(0, cs)],
            Some(&t_ne),
        );
        let t_m1 = self.alloc_tmp(cs);
        Self::push_raw(
            ops,
            C::CPUI_INT_SUB,
            &[t_count.clone(), Self::const_vn(1, cs)],
            Some(&t_m1),
        );
        let t_sh = self.alloc_tmp(size);
        Self::push_raw(ops, shift_op, &[save.clone(), t_m1], Some(&t_sh));
        let t_bit = match dir {
            ShiftDir::Left => {
                let t = self.alloc_tmp(1);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_SLESS,
                    &[t_sh, Self::const_vn(0, size)],
                    Some(&t),
                );
                t
            }
            ShiftDir::Right | ShiftDir::Arith => {
                let t_and = self.alloc_tmp(size);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_AND,
                    &[t_sh, Self::const_vn(1, size)],
                    Some(&t_and),
                );
                let t = self.alloc_tmp(1);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_NOTEQUAL,
                    &[t_and, Self::const_vn(0, size)],
                    Some(&t),
                );
                t
            }
        };
        let t_neg = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_BOOL_NEGATE, &[t_ne.clone()], Some(&t_neg));
        let t_a = self.alloc_tmp(1);
        Self::push_raw(
            ops,
            C::CPUI_INT_AND,
            &[t_neg, Self::flag_cf()],
            Some(&t_a),
        );
        let t_b = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_INT_AND, &[t_ne.clone(), t_bit], Some(&t_b));
        Self::push_raw(ops, C::CPUI_INT_OR, &[t_a, t_b], Some(&Self::flag_cf()));

        // ---- shlflags(): OF (direction-specific) ----
        let t_eq1 = self.alloc_tmp(1);
        Self::push_raw(
            ops,
            C::CPUI_INT_EQUAL,
            &[t_count.clone(), Self::const_vn(1, cs)],
            Some(&t_eq1),
        );
        match dir {
            ShiftDir::Left => {
                // OF = count==1 ? (CF ^ result-top) : OF — result re-read
                let r = read_result(self, ops);
                let t_sign = self.alloc_tmp(1);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_SLESS,
                    &[r, Self::const_vn(0, size)],
                    Some(&t_sign),
                );
                let t_xor = self.alloc_tmp(1);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_XOR,
                    &[Self::flag_cf(), t_sign],
                    Some(&t_xor),
                );
                let t_neg = self.alloc_tmp(1);
                Self::push_raw(ops, C::CPUI_BOOL_NEGATE, &[t_eq1.clone()], Some(&t_neg));
                let t_a = self.alloc_tmp(1);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_AND,
                    &[t_neg, Self::flag_of()],
                    Some(&t_a),
                );
                let t_b = self.alloc_tmp(1);
                Self::push_raw(ops, C::CPUI_INT_AND, &[t_eq1.clone(), t_xor], Some(&t_b));
                Self::push_raw(ops, C::CPUI_INT_OR, &[t_a, t_b], Some(&Self::flag_of()));
            }
            ShiftDir::Right => {
                // OF = count==1 ? original-top : OF (from the saved COPY)
                let t_sign = self.alloc_tmp(1);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_SLESS,
                    &[save.clone(), Self::const_vn(0, size)],
                    Some(&t_sign),
                );
                let t_neg = self.alloc_tmp(1);
                Self::push_raw(ops, C::CPUI_BOOL_NEGATE, &[t_eq1.clone()], Some(&t_neg));
                let t_a = self.alloc_tmp(1);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_AND,
                    &[t_neg, Self::flag_of()],
                    Some(&t_a),
                );
                let t_b = self.alloc_tmp(1);
                Self::push_raw(ops, C::CPUI_INT_AND, &[t_eq1.clone(), t_sign], Some(&t_b));
                Self::push_raw(ops, C::CPUI_INT_OR, &[t_a, t_b], Some(&Self::flag_of()));
            }
            ShiftDir::Arith => {
                // OF &= (count != 1) — direct flag output, no temp
                let t_neg = self.alloc_tmp(1);
                Self::push_raw(ops, C::CPUI_BOOL_NEGATE, &[t_eq1.clone()], Some(&t_neg));
                Self::push_raw(
                    ops,
                    C::CPUI_INT_AND,
                    &[t_neg, Self::flag_of()],
                    Some(&Self::flag_of()),
                );
            }
        }

        // ---- shiftresultflags(): gated SF / ZF / PF ----
        let t_gate = self.alloc_tmp(1);
        Self::push_raw(
            ops,
            C::CPUI_INT_NOTEQUAL,
            &[t_count.clone(), Self::const_vn(0, cs)],
            Some(&t_gate),
        );
        // SF
        let r_sf = read_result(self, ops);
        let t_sf = self.alloc_tmp(1);
        Self::push_raw(
            ops,
            C::CPUI_INT_SLESS,
            &[r_sf, Self::const_vn(0, size)],
            Some(&t_sf),
        );
        let t_neg = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_BOOL_NEGATE, &[t_gate.clone()], Some(&t_neg));
        let t_a = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_INT_AND, &[t_neg, Self::flag_sf()], Some(&t_a));
        let t_b = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_INT_AND, &[t_gate.clone(), t_sf], Some(&t_b));
        Self::push_raw(ops, C::CPUI_INT_OR, &[t_a, t_b], Some(&Self::flag_sf()));
        // ZF
        let r_zf = read_result(self, ops);
        let t_zf = self.alloc_tmp(1);
        Self::push_raw(
            ops,
            C::CPUI_INT_EQUAL,
            &[r_zf, Self::const_vn(0, size)],
            Some(&t_zf),
        );
        let t_neg = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_BOOL_NEGATE, &[t_gate.clone()], Some(&t_neg));
        let t_a = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_INT_AND, &[t_neg, Self::flag_zf()], Some(&t_a));
        let t_b = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_INT_AND, &[t_gate.clone(), t_zf], Some(&t_b));
        Self::push_raw(ops, C::CPUI_INT_OR, &[t_a, t_b], Some(&Self::flag_zf()));
        // PF
        let r_pf = read_result(self, ops);
        let t_and = self.alloc_tmp(size);
        Self::push_raw(
            ops,
            C::CPUI_INT_AND,
            &[r_pf, Self::const_vn(0xff, size)],
            Some(&t_and),
        );
        let t_pop = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_POPCOUNT, &[t_and], Some(&t_pop));
        let t_bit = self.alloc_tmp(1);
        Self::push_raw(
            ops,
            C::CPUI_INT_AND,
            &[t_pop, Self::const_vn(1, 1)],
            Some(&t_bit),
        );
        let t_eq = self.alloc_tmp(1);
        Self::push_raw(
            ops,
            C::CPUI_INT_EQUAL,
            &[t_bit, Self::const_vn(0, 1)],
            Some(&t_eq),
        );
        let t_neg = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_BOOL_NEGATE, &[t_gate.clone()], Some(&t_neg));
        let t_a = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_INT_AND, &[t_neg, Self::flag_pf()], Some(&t_a));
        let t_b = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_INT_AND, &[t_gate.clone(), t_eq], Some(&t_b));
        Self::push_raw(ops, C::CPUI_INT_OR, &[t_a, t_b], Some(&Self::flag_pf()));
    }

    // RUGRA-GLUE: port of the ia.sinc :ROL/:ROR group-2 rotate constructors of
    // the locked x86-64 sla (sleigh_shim op-for-op dumps /tmp/w-ext-rol.out +
    // /tmp/w-ext-ror.out, 26 forms, examples/x86ext_probe.rs). Structure per
    // dump:
    //   imm/cl form — `local count = imm&(bits-1):4 / CL&(bits-1):1` (8/16-bit
    //   cl forms additionally compute `CL&0x1f:1` UP FRONT as the flag count);
    //   value rm = (rm <dir> count) | (rm <other> (bits-count)); 8/16-bit imm
    //   forms compute `imm&0x1f:1` AFTER the value section as the flag count;
    //   flags: CF = count!=0 ? (rol: result bit0 / ror: result msb) : CF,
    //   OF = count==1 ? (rol: CF^result-msb / ror: (rm s<0)^((rm<<1) s<0))
    //   : OF — the standard AND/OR flag mux. Memory destinations share ONE
    //   unique slot re-LOADed at every rm read (same as the shift group).
    //   by-one form (D0/D1) — dedicated short constructors: rol sets CF to the
    //   pre-shift result-msb then rm = (rm<<1) | CF (8-bit: CF direct, wider:
    //   zext(CF)); ror sets CF = rm&1 (8-bit: AND writes CF directly, wider:
    //   AND:W + INT_NOTEQUAL) then rm = (rm>>1) | zext(CF)<<(bits-1); OF =
    //   (result & second-top-bit) != 0) ^ (result s< 0). Shift-amount consts
    //   are always :4; bit-test masks at operand width.
    /// Lift `rol`/`ror` (all count forms; flags + value + zext).
    fn lift_rotate(&mut self, inst: &Instruction, dir: RotDir, ops: &mut Vec<PcodeOpRaw>) {
        use OpCode as C;
        if inst.operands.len() != 2 {
            return;
        }
        let Some(form) = Self::shift_count_form(inst) else {
            return;
        };

        // Destination binding — memory address ops precede the constructor
        // body (same operand-binding order as the shift group).
        let (dst, size) = match &inst.operands[0] {
            crate::disasm::Operand::Register { name, size } => {
                let Some(vn) = Self::get_register(name, *size) else {
                    return;
                };
                let parent64 = if *size == 4 {
                    Self::parent64_name(name).and_then(|p| Self::get_register(p, 8))
                } else {
                    None
                };
                (AluDst::Reg { vn, parent64 }, *size)
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
                (AluDst::Mem { addr }, *size)
            }
            _ => return,
        };

        let bits = (size * 8) as u64;
        let vmask: u64 = bits - 1;
        let dir_op = match dir {
            RotDir::Left => C::CPUI_INT_LEFT,
            RotDir::Right => C::CPUI_INT_RIGHT,
        };
        let oth_op = match dir {
            RotDir::Left => C::CPUI_INT_RIGHT,
            RotDir::Right => C::CPUI_INT_LEFT,
        };

        // read_rm: the rm operand for reg dst (register varnode) or a re-LOAD
        // into the ONE shared mem slot (the oracle reuses a single unique
        // local for every rm re-read — same as the shift group).
        let mem_slot = match &dst {
            AluDst::Mem { .. } => Some(self.alloc_tmp(size)),
            AluDst::Reg { .. } => None,
        };
        let read_rm = |this: &mut Self, ops: &mut Vec<PcodeOpRaw>| -> VarnodeRaw {
            match (&dst, &mem_slot) {
                (AluDst::Reg { vn, .. }, _) => vn.clone(),
                (AluDst::Mem { addr }, Some(slot)) => {
                    this.emit_load_slot(addr, slot, ops);
                    slot.clone()
                }
                _ => unreachable!("mem dst must have a slot"),
            }
        };
        let zext_parent = |ops: &mut Vec<PcodeOpRaw>| {
            if let AluDst::Reg { vn, parent64 } = &dst {
                if let Some(parent) = parent64 {
                    Self::push_raw(ops, C::CPUI_INT_ZEXT, &[vn.clone()], Some(parent));
                }
            }
        };

        if let ShiftCount::ByOne = form {
            // ---- D0/D1 dedicated by-one constructors ----
            match dir {
                RotDir::Left => {
                    // CF = rm s< 0 (pre-shift top bit), BEFORE the value op
                    let r0 = read_rm(self, ops);
                    Self::push_raw(
                        ops,
                        C::CPUI_INT_SLESS,
                        &[r0, Self::const_vn(0, size)],
                        Some(&Self::flag_cf()),
                    );
                    // rm = (rm << 1) | CF   (8-bit: CF direct; wider: zext(CF))
                    let r1 = read_rm(self, ops);
                    let t0 = self.alloc_tmp(size);
                    Self::push_raw(
                        ops,
                        C::CPUI_INT_LEFT,
                        &[r1, Self::const_vn(1, 4)],
                        Some(&t0),
                    );
                    let rhs = if size == 1 {
                        Self::flag_cf()
                    } else {
                        let z = self.alloc_tmp(size);
                        Self::push_raw(
                            ops,
                            C::CPUI_INT_ZEXT,
                            &[Self::flag_cf()],
                            Some(&z),
                        );
                        z
                    };
                    match &dst {
                        AluDst::Reg { vn, .. } => {
                            Self::push_raw(ops, C::CPUI_INT_OR, &[t0, rhs], Some(vn))
                        }
                        AluDst::Mem { addr } => {
                            let slot =
                                mem_slot.clone().expect("mem dst must have a slot");
                            Self::push_raw(ops, C::CPUI_INT_OR, &[t0, rhs], Some(&slot));
                            self.emit_store_v(addr, slot, ops);
                        }
                    }
                    // OF = CF ^ (rm s< 0)  (result top bit)
                    let r2 = read_rm(self, ops);
                    let m = self.alloc_tmp(1);
                    Self::push_raw(
                        ops,
                        C::CPUI_INT_SLESS,
                        &[r2, Self::const_vn(0, size)],
                        Some(&m),
                    );
                    Self::push_raw(
                        ops,
                        C::CPUI_INT_XOR,
                        &[Self::flag_cf(), m],
                        Some(&Self::flag_of()),
                    );
                    zext_parent(ops);
                }
                RotDir::Right => {
                    // CF = rm & 1  (8-bit writes the AND directly into CF;
                    // wider: AND:W temp + INT_NOTEQUAL)
                    let r0 = read_rm(self, ops);
                    if size == 1 {
                        Self::push_raw(
                            ops,
                            C::CPUI_INT_AND,
                            &[r0, Self::const_vn(1, 1)],
                            Some(&Self::flag_cf()),
                        );
                    } else {
                        let t0 = self.alloc_tmp(size);
                        Self::push_raw(
                            ops,
                            C::CPUI_INT_AND,
                            &[r0, Self::const_vn(1, size)],
                            Some(&t0),
                        );
                        Self::push_raw(
                            ops,
                            C::CPUI_INT_NOTEQUAL,
                            &[t0, Self::const_vn(0, size)],
                            Some(&Self::flag_cf()),
                        );
                    }
                    // rm = (rm >> 1) | (CF << (bits-1))   (8-bit: CF direct;
                    // wider: zext(CF) first)
                    let r1 = read_rm(self, ops);
                    let t1 = self.alloc_tmp(size);
                    Self::push_raw(
                        ops,
                        C::CPUI_INT_RIGHT,
                        &[r1, Self::const_vn(1, 4)],
                        Some(&t1),
                    );
                    let rhs = if size == 1 {
                        Self::flag_cf()
                    } else {
                        let z = self.alloc_tmp(size);
                        Self::push_raw(ops, C::CPUI_INT_ZEXT, &[Self::flag_cf()], Some(&z));
                        z
                    };
                    let t2 = self.alloc_tmp(size);
                    Self::push_raw(
                        ops,
                        C::CPUI_INT_LEFT,
                        &[rhs, Self::const_vn(vmask, 4)],
                        Some(&t2),
                    );
                    match &dst {
                        AluDst::Reg { vn, .. } => {
                            Self::push_raw(ops, C::CPUI_INT_OR, &[t1, t2], Some(vn))
                        }
                        AluDst::Mem { addr } => {
                            let slot =
                                mem_slot.clone().expect("mem dst must have a slot");
                            Self::push_raw(ops, C::CPUI_INT_OR, &[t1, t2], Some(&slot));
                            self.emit_store_v(addr, slot, ops);
                        }
                    }
                    // OF = ((rm & second-top) != 0) ^ (rm s< 0)
                    let second_top: u64 = 1u64 << (bits - 2);
                    let r2 = read_rm(self, ops);
                    let a_w = self.alloc_tmp(size);
                    Self::push_raw(
                        ops,
                        C::CPUI_INT_AND,
                        &[r2, Self::const_vn(second_top, size)],
                        Some(&a_w),
                    );
                    let b = self.alloc_tmp(1);
                    Self::push_raw(
                        ops,
                        C::CPUI_INT_NOTEQUAL,
                        &[a_w, Self::const_vn(0, size)],
                        Some(&b),
                    );
                    let r3 = read_rm(self, ops);
                    let m = self.alloc_tmp(1);
                    Self::push_raw(
                        ops,
                        C::CPUI_INT_SLESS,
                        &[r3, Self::const_vn(0, size)],
                        Some(&m),
                    );
                    Self::push_raw(
                        ops,
                        C::CPUI_INT_XOR,
                        &[b, m],
                        Some(&Self::flag_of()),
                    );
                    zext_parent(ops);
                }
            }
            return;
        }

        // ---- imm (C0/C1) / cl (D2/D3) general form ----
        // local count = imm & (bits-1) :4 / CL & (bits-1) :1; 8/16-bit cl
        // forms ALSO compute the flag count CL & 0x1f :1 up front.
        let imm_val: u64 = match form {
            ShiftCount::Imm => match &inst.operands[1] {
                crate::disasm::Operand::Immediate { value, .. } => (*value as u64) & 0xff,
                _ => return,
            },
            _ => 0,
        };
        let (t_count, cs, cf1_early) = match form {
            ShiftCount::Cl => {
                let cl = match &inst.operands[1] {
                    crate::disasm::Operand::Register { name, size } => {
                        match Self::get_register(name, *size) {
                            Some(vn) => vn,
                            None => return,
                        }
                    }
                    _ => return,
                };
                let t = self.alloc_tmp(1);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_AND,
                    &[cl.clone(), Self::const_vn(vmask, 1)],
                    Some(&t),
                );
                let early = if size <= 2 {
                    let c = self.alloc_tmp(1);
                    Self::push_raw(
                        ops,
                        C::CPUI_INT_AND,
                        &[cl, Self::const_vn(0x1f, 1)],
                        Some(&c),
                    );
                    Some(c)
                } else {
                    None
                };
                (t, 1, early)
            }
            ShiftCount::Imm => {
                let t = self.alloc_tmp(4);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_AND,
                    &[Self::const_vn(imm_val, 4), Self::const_vn(vmask, 4)],
                    Some(&t),
                );
                (t, 4, None)
            }
            ShiftCount::ByOne => unreachable!("handled above"),
        };

        // value rm = (rm <dir> count) | (rm <other> (bits - count));
        // mem form re-LOADs the rm slot for each shift input.
        match &dst {
            AluDst::Reg { vn, .. } => {
                let ta = self.alloc_tmp(size);
                Self::push_raw(ops, dir_op, &[vn.clone(), t_count.clone()], Some(&ta));
                let tsub = self.alloc_tmp(cs);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_SUB,
                    &[Self::const_vn(bits, cs), t_count.clone()],
                    Some(&tsub),
                );
                let tb = self.alloc_tmp(size);
                Self::push_raw(ops, oth_op, &[vn.clone(), tsub], Some(&tb));
                Self::push_raw(ops, C::CPUI_INT_OR, &[ta, tb], Some(vn));
            }
            AluDst::Mem { addr } => {
                let slot = mem_slot.clone().expect("mem dst must have a slot");
                self.emit_load_slot(addr, &slot, ops);
                let ta = self.alloc_tmp(size);
                Self::push_raw(ops, dir_op, &[slot.clone(), t_count.clone()], Some(&ta));
                let tsub = self.alloc_tmp(cs);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_SUB,
                    &[Self::const_vn(bits, cs), t_count.clone()],
                    Some(&tsub),
                );
                self.emit_load_slot(addr, &slot, ops);
                let tb = self.alloc_tmp(size);
                Self::push_raw(ops, oth_op, &[slot.clone(), tsub], Some(&tb));
                Self::push_raw(ops, C::CPUI_INT_OR, &[ta, tb], Some(&slot));
                self.emit_store_v(addr, slot, ops);
            }
        }

        // flag count: 8/16-bit imm forms re-AND the raw imm at :1 AFTER the
        // value section; other forms use the count temp / early flag count.
        let cf1 = match form {
            ShiftCount::Imm if size <= 2 => {
                let c = self.alloc_tmp(1);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_AND,
                    &[Self::const_vn(imm_val, 1), Self::const_vn(0x1f, 1)],
                    Some(&c),
                );
                c
            }
            _ => cf1_early.unwrap_or_else(|| t_count.clone()),
        };

        // CF = count!=0 ? (rol: result bit0 / ror: result msb) : CF
        let g = self.alloc_tmp(1);
        Self::push_raw(
            ops,
            C::CPUI_INT_NOTEQUAL,
            &[cf1.clone(), Self::const_vn(0, cf1.size)],
            Some(&g),
        );
        let b = match dir {
            RotDir::Left => {
                let r = read_rm(self, ops);
                let bit = self.alloc_tmp(size);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_AND,
                    &[r, Self::const_vn(1, size)],
                    Some(&bit),
                );
                let nb = self.alloc_tmp(1);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_NOTEQUAL,
                    &[bit, Self::const_vn(0, size)],
                    Some(&nb),
                );
                nb
            }
            RotDir::Right => {
                let r = read_rm(self, ops);
                let nb = self.alloc_tmp(1);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_SLESS,
                    &[r, Self::const_vn(0, size)],
                    Some(&nb),
                );
                nb
            }
        };
        let neg = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_BOOL_NEGATE, &[g.clone()], Some(&neg));
        let t_a = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_INT_AND, &[neg, Self::flag_cf()], Some(&t_a));
        let t_b = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_INT_AND, &[g, b], Some(&t_b));
        Self::push_raw(ops, C::CPUI_INT_OR, &[t_a, t_b], Some(&Self::flag_cf()));

        // OF = count==1 ? (rol: CF^result-msb / ror: (rm s<0)^((rm<<1) s<0))
        // : OF
        let eq1 = self.alloc_tmp(1);
        Self::push_raw(
            ops,
            C::CPUI_INT_EQUAL,
            &[cf1.clone(), Self::const_vn(1, cf1.size)],
            Some(&eq1),
        );
        let x = match dir {
            RotDir::Left => {
                let r = read_rm(self, ops);
                let m = self.alloc_tmp(1);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_SLESS,
                    &[r, Self::const_vn(0, size)],
                    Some(&m),
                );
                let xx = self.alloc_tmp(1);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_XOR,
                    &[Self::flag_cf(), m],
                    Some(&xx),
                );
                xx
            }
            RotDir::Right => {
                let r0 = read_rm(self, ops);
                let m0 = self.alloc_tmp(1);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_SLESS,
                    &[r0, Self::const_vn(0, size)],
                    Some(&m0),
                );
                let r1 = read_rm(self, ops);
                let sh = self.alloc_tmp(size);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_LEFT,
                    &[r1, Self::const_vn(1, 4)],
                    Some(&sh),
                );
                let m1 = self.alloc_tmp(1);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_SLESS,
                    &[sh, Self::const_vn(0, size)],
                    Some(&m1),
                );
                let xx = self.alloc_tmp(1);
                Self::push_raw(ops, C::CPUI_INT_XOR, &[m0, m1], Some(&xx));
                xx
            }
        };
        let neg2 = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_BOOL_NEGATE, &[eq1.clone()], Some(&neg2));
        let t_a2 = self.alloc_tmp(1);
        Self::push_raw(
            ops,
            C::CPUI_INT_AND,
            &[neg2, Self::flag_of()],
            Some(&t_a2),
        );
        let t_b2 = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_INT_AND, &[eq1, x], Some(&t_b2));
        Self::push_raw(ops, C::CPUI_INT_OR, &[t_a2, t_b2], Some(&Self::flag_of()));

        // 32-bit GPR destination zext comes LAST (after all flag ops)
        zext_parent(ops);
    }

    // RUGRA-GLUE: port of the ia.sinc :IMUL constructors of the locked x86-64
    // sla (sleigh_shim op-for-op dump /tmp/w-ext-imul.out, 19 forms,
    // examples/x86ext_probe.rs). All forms compute the double-width flag
    // product `p:D = sext(op1)*sext(op2)` (D = 2*W), then set CF =
    // sext(result) != p and OF = COPY(CF); SF/ZF/PF are left untouched.
    // Per-form structure (dump is truth):
    //   2-op (0F AF) — s0=sext(dst); rm read (mem: LOAD); s1=sext(rm); p;
    //     value: W==8 → INT_MULT(dst, rm re-read) into dst, W<8 →
    //     SUBPIECE(p,0) into dst; dead SUBPIECE(p,W):W; chk=sext(dst);
    //     CF/OF; W==4 → parent zext last.
    //   3-op (69/6B) — iced collapses dst==src to 2 operands (dst, imm);
    //     src read FIRST (mem: LOAD); s0=sext(src); s1=sext(imm const) —
    //     6B encodings (iced imm size 1) hold the sign-extended imm at
    //     operand width W, 69 encodings at the encoded imm width (:4/:2);
    //     value: W==8 → INT_MULT(src, ext) into dst where ext = 6B ? const:8
    //     : sext(const:4):8 (mem src re-LOADs first), W<8 → SUBPIECE(p,0);
    //     dead SUBPIECE(p,W); chk=sext(dst); CF/OF; W==4 → parent zext.
    //   1-op (F6/F7 /5) — AX-family accumulator: p=sext(acc)*sext(rm);
    //     W==1 → INT_MULT(s0,s1) writes AX:2 directly, CF = sext(AL) != AX;
    //     W==8 → acc = INT_MULT(acc, rm), RDX = SUBPIECE(p,8);
    //     W==4 → EDX=SUBPIECE(p,4), RDX=zext(EDX), EAX=SUBPIECE(p,0),
    //     RAX=zext(EAX) (high half first); W==2 → DX=SUBPIECE(p,2),
    //     AX=SUBPIECE(p,0); chk=sext(acc); CF/OF.
    /// Lift `imul` (1/2/3-operand forms; CF/OF via double-width product).
    fn lift_imul(&mut self, inst: &Instruction, ops: &mut Vec<PcodeOpRaw>) {
        match inst.operands.len() {
            1 => self.lift_imul_one_op(inst, ops),
            2 if matches!(inst.operands[1], crate::disasm::Operand::Immediate { .. }) => {
                // iced collapses the 3-operand dst==src form to (dst, imm)
                self.lift_imul_three_op(inst, 0, ops)
            }
            2 => self.lift_imul_two_op(inst, ops),
            3 => self.lift_imul_three_op(inst, 1, ops),
            _ => {}
        }
    }

    // RUGRA-GLUE: :IMUL rm operand binding — the constructors re-LOAD the rm
    // operand into ONE shared unique slot at every use (oracle `imul
    // rbx,[rax]`: LOAD unique#1 for the flag sext AND again for the value
    // INT_MULT — /tmp/w-ext-imul.out).
    /// Bind an imul rm operand; memory operands get one shared load slot.
    fn imul_bind_rm(
        &mut self,
        op: &crate::disasm::Operand,
        w: usize,
        ops: &mut Vec<PcodeOpRaw>,
    ) -> Option<(BoundOperand, Option<VarnodeRaw>)> {
        let b = self.bind_operand(op, w, ops)?;
        let slot = match &b {
            BoundOperand::MemAddr { size, .. } => Some(self.alloc_tmp(*size)),
            _ => None,
        };
        Some((b, slot))
    }

    // RUGRA-GLUE: :IMUL rm re-read — reg/const direct, memory re-LOADs into
    /// One use of the bound imul rm operand (shared mem slot).
    fn imul_read_rm(
        &mut self,
        bound: &BoundOperand,
        slot: &Option<VarnodeRaw>,
        ops: &mut Vec<PcodeOpRaw>,
    ) -> VarnodeRaw {
        match (bound, slot) {
            (BoundOperand::Reg(vn), _) => vn.clone(),
            (BoundOperand::Const(vn), _) => vn.clone(),
            (BoundOperand::MemAddr { addr, .. }, Some(s)) => {
                self.emit_load_slot(addr, s, ops);
                s.clone()
            }
            (BoundOperand::MemAddr { .. }, None) => {
                unreachable!("imul mem operand must have a slot")
            }
        }
    }

    // RUGRA-GLUE: :IMUL two-operand constructor (0F AF) — see lift_imul
    // evidence block; /tmp/w-ext-imul.out forms `imul eax,ecx` /
    /// Lift 2-operand `imul dst, rm`.
    fn lift_imul_two_op(&mut self, inst: &Instruction, ops: &mut Vec<PcodeOpRaw>) {
        use OpCode as C;
        let (dst_vn, parent64) = match &inst.operands[0] {
            crate::disasm::Operand::Register { name, size } => {
                let Some(vn) = Self::get_register(name, *size) else {
                    return;
                };
                let parent64 = if *size == 4 {
                    Self::parent64_name(name).and_then(|p| Self::get_register(p, 8))
                } else {
                    None
                };
                (vn, parent64)
            }
            _ => return,
        };
        let w = dst_vn.size;
        let d = w * 2;
        // s0 = sext(dst)
        let s0 = self.alloc_tmp(d);
        Self::push_raw(ops, C::CPUI_INT_SEXT, &[dst_vn.clone()], Some(&s0));
        // rm read (mem: address ops + LOAD into the shared slot)
        let Some((rm_bound, rm_slot)) = self.imul_bind_rm(&inst.operands[1], w, ops) else {
            return;
        };
        let rm = self.imul_read_rm(&rm_bound, &rm_slot, ops);
        // s1 = sext(rm); p = s0 * s1
        let s1 = self.alloc_tmp(d);
        Self::push_raw(ops, C::CPUI_INT_SEXT, &[rm], Some(&s1));
        let p = self.alloc_tmp(d);
        Self::push_raw(ops, C::CPUI_INT_MULT, &[s0, s1], Some(&p));
        // value op
        if w == 8 {
            let rm2 = self.imul_read_rm(&rm_bound, &rm_slot, ops);
            Self::push_raw(
                ops,
                C::CPUI_INT_MULT,
                &[dst_vn.clone(), rm2],
                Some(&dst_vn),
            );
        } else {
            Self::push_raw(
                ops,
                C::CPUI_SUBPIECE,
                &[p.clone(), Self::const_vn(0, 4)],
                Some(&dst_vn),
            );
        }
        // dead high-half SUBPIECE (present in every dump)
        let hi = self.alloc_tmp(w);
        Self::push_raw(
            ops,
            C::CPUI_SUBPIECE,
            &[p.clone(), Self::const_vn(w as u64, 4)],
            Some(&hi),
        );
        // chk = sext(result); CF = chk != p; OF = CF
        let chk = self.alloc_tmp(d);
        Self::push_raw(ops, C::CPUI_INT_SEXT, &[dst_vn.clone()], Some(&chk));
        Self::push_raw(
            ops,
            C::CPUI_INT_NOTEQUAL,
            &[chk, p],
            Some(&Self::flag_cf()),
        );
        let mut of = PcodeOpRaw::new(C::CPUI_COPY as i32);
        of.add_input(Self::flag_cf());
        of.set_output(Self::flag_of());
        ops.push(of);
        if let Some(parent) = parent64 {
            Self::push_raw(ops, C::CPUI_INT_ZEXT, &[dst_vn], Some(&parent));
        }
    }

    // RUGRA-GLUE: :IMUL three-operand constructors (69/6B) — see lift_imul
    // evidence block; /tmp/w-ext-imul.out forms `imul rbx,rbx,3E8h` /
    /// Lift 3-operand `imul dst, src, imm` (`src_idx` 0 = collapsed dst==src
    /// 2-operand display, 1 = real 3-operand form).
    fn lift_imul_three_op(
        &mut self,
        inst: &Instruction,
        src_idx: usize,
        ops: &mut Vec<PcodeOpRaw>,
    ) {
        use OpCode as C;
        let (dst_vn, parent64) = match &inst.operands[0] {
            crate::disasm::Operand::Register { name, size } => {
                let Some(vn) = Self::get_register(name, *size) else {
                    return;
                };
                let parent64 = if *size == 4 {
                    Self::parent64_name(name).and_then(|p| Self::get_register(p, 8))
                } else {
                    None
                };
                (vn, parent64)
            }
            _ => return,
        };
        let w = dst_vn.size;
        let d = w * 2;
        let (imm_val, imm_enc_size) = match inst.operands.last() {
            Some(crate::disasm::Operand::Immediate { value, size }) => {
                (*value as u64, *size)
            }
            _ => return,
        };
        // 6B encodings (iced imm size 1) carry the sign-extended imm at
        // operand width; 69 encodings at the encoded imm width.
        let imm_w = if imm_enc_size == 1 { w } else { imm_enc_size };
        // src read FIRST (mem: address ops + LOAD into the shared slot)
        let Some((src_bound, src_slot)) = self.imul_bind_rm(&inst.operands[src_idx], w, ops)
        else {
            return;
        };
        let src1 = self.imul_read_rm(&src_bound, &src_slot, ops);
        // p = sext(src) * sext(imm)
        let s0 = self.alloc_tmp(d);
        Self::push_raw(ops, C::CPUI_INT_SEXT, &[src1], Some(&s0));
        let s1 = self.alloc_tmp(d);
        Self::push_raw(
            ops,
            C::CPUI_INT_SEXT,
            &[Self::const_vn(imm_val, imm_w)],
            Some(&s1),
        );
        let p = self.alloc_tmp(d);
        Self::push_raw(ops, C::CPUI_INT_MULT, &[s0, s1], Some(&p));
        // value op
        if w == 8 {
            let ext = if imm_enc_size == 1 {
                // 6B: the imm is already sign-extended to operand width
                Self::const_vn(imm_val, 8)
            } else {
                let t = self.alloc_tmp(8);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_SEXT,
                    &[Self::const_vn(imm_val, imm_w)],
                    Some(&t),
                );
                t
            };
            let src2 = self.imul_read_rm(&src_bound, &src_slot, ops);
            Self::push_raw(ops, C::CPUI_INT_MULT, &[src2, ext], Some(&dst_vn));
        } else {
            Self::push_raw(
                ops,
                C::CPUI_SUBPIECE,
                &[p.clone(), Self::const_vn(0, 4)],
                Some(&dst_vn),
            );
        }
        // dead high-half SUBPIECE
        let hi = self.alloc_tmp(w);
        Self::push_raw(
            ops,
            C::CPUI_SUBPIECE,
            &[p.clone(), Self::const_vn(w as u64, 4)],
            Some(&hi),
        );
        // chk = sext(result); CF = chk != p; OF = CF
        let chk = self.alloc_tmp(d);
        Self::push_raw(ops, C::CPUI_INT_SEXT, &[dst_vn.clone()], Some(&chk));
        Self::push_raw(
            ops,
            C::CPUI_INT_NOTEQUAL,
            &[chk, p],
            Some(&Self::flag_cf()),
        );
        let mut of = PcodeOpRaw::new(C::CPUI_COPY as i32);
        of.add_input(Self::flag_cf());
        of.set_output(Self::flag_of());
        ops.push(of);
        if let Some(parent) = parent64 {
            Self::push_raw(ops, C::CPUI_INT_ZEXT, &[dst_vn], Some(&parent));
        }
    }

    // RUGRA-GLUE: :IMUL one-operand constructor (F6/F7 /5, AX-family
    // accumulator) — see lift_imul evidence block; /tmp/w-ext-imul.out forms
    /// Lift 1-operand `imul rm` (AX = AX * rm).
    fn lift_imul_one_op(&mut self, inst: &Instruction, ops: &mut Vec<PcodeOpRaw>) {
        use OpCode as C;
        let Some(op0) = inst.operands.first() else {
            return;
        };
        let w = match op0 {
            crate::disasm::Operand::Register { size, .. } => *size,
            crate::disasm::Operand::Memory { size, .. } => *size,
            _ => return,
        };
        let acc_name = match w {
            1 => "al",
            2 => "ax",
            4 => "eax",
            8 => "rax",
            _ => return,
        };
        let Some(acc_vn) = Self::get_register(acc_name, w) else {
            return;
        };
        let d = w * 2;
        // s0 = sext(acc); rm read (shared slot); s1 = sext(rm)
        let s0 = self.alloc_tmp(d);
        Self::push_raw(ops, C::CPUI_INT_SEXT, &[acc_vn.clone()], Some(&s0));
        let Some((rm_bound, rm_slot)) = self.imul_bind_rm(op0, w, ops) else {
            return;
        };
        let rm1 = self.imul_read_rm(&rm_bound, &rm_slot, ops);
        let s1 = self.alloc_tmp(d);
        Self::push_raw(ops, C::CPUI_INT_SEXT, &[rm1], Some(&s1));
        if w == 1 {
            // 8-bit: the product writes AX:2 directly; CF = sext(AL) != AX
            let Some(ax) = Self::get_register("ax", 2) else {
                return;
            };
            Self::push_raw(ops, C::CPUI_INT_MULT, &[s0, s1], Some(&ax));
            let chk = self.alloc_tmp(2);
            Self::push_raw(ops, C::CPUI_INT_SEXT, &[acc_vn], Some(&chk));
            Self::push_raw(
                ops,
                C::CPUI_INT_NOTEQUAL,
                &[chk, ax],
                Some(&Self::flag_cf()),
            );
            let mut of = PcodeOpRaw::new(C::CPUI_COPY as i32);
            of.add_input(Self::flag_cf());
            of.set_output(Self::flag_of());
            ops.push(of);
            return;
        }
        // p = s0 * s1
        let p = self.alloc_tmp(d);
        Self::push_raw(ops, C::CPUI_INT_MULT, &[s0, s1], Some(&p));
        // result writeback — high half FIRST for W<8
        match w {
            8 => {
                let rm2 = self.imul_read_rm(&rm_bound, &rm_slot, ops);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_MULT,
                    &[acc_vn.clone(), rm2],
                    Some(&acc_vn),
                );
                let Some(rdx) = Self::get_register("rdx", 8) else {
                    return;
                };
                Self::push_raw(
                    ops,
                    C::CPUI_SUBPIECE,
                    &[p.clone(), Self::const_vn(8, 4)],
                    Some(&rdx),
                );
            }
            4 => {
                let (Some(edx), Some(rdx), Some(eax), Some(rax)) = (
                    Self::get_register("edx", 4),
                    Self::get_register("rdx", 8),
                    Self::get_register("eax", 4),
                    Self::get_register("rax", 8),
                ) else {
                    return;
                };
                Self::push_raw(
                    ops,
                    C::CPUI_SUBPIECE,
                    &[p.clone(), Self::const_vn(4, 4)],
                    Some(&edx),
                );
                Self::push_raw(ops, C::CPUI_INT_ZEXT, &[edx], Some(&rdx));
                Self::push_raw(
                    ops,
                    C::CPUI_SUBPIECE,
                    &[p.clone(), Self::const_vn(0, 4)],
                    Some(&eax),
                );
                Self::push_raw(ops, C::CPUI_INT_ZEXT, &[eax], Some(&rax));
            }
            2 => {
                let (Some(dx), Some(ax)) =
                    (Self::get_register("dx", 2), Self::get_register("ax", 2))
                else {
                    return;
                };
                Self::push_raw(
                    ops,
                    C::CPUI_SUBPIECE,
                    &[p.clone(), Self::const_vn(2, 4)],
                    Some(&dx),
                );
                Self::push_raw(
                    ops,
                    C::CPUI_SUBPIECE,
                    &[p.clone(), Self::const_vn(0, 4)],
                    Some(&ax),
                );
            }
            _ => return,
        }
        // chk = sext(acc); CF = chk != p; OF = CF
        let chk = self.alloc_tmp(d);
        Self::push_raw(ops, C::CPUI_INT_SEXT, &[acc_vn], Some(&chk));
        Self::push_raw(
            ops,
            C::CPUI_INT_NOTEQUAL,
            &[chk, p],
            Some(&Self::flag_cf()),
        );
        let mut of = PcodeOpRaw::new(C::CPUI_COPY as i32);
        of.add_input(Self::flag_cf());
        of.set_output(Self::flag_of());
        ops.push(of);
    }

    // RUGRA-GLUE: port of the ia.sinc :BT/:BTS/:BTR/:BTC constructors of the
    // locked x86-64 sla (sleigh_shim op-for-op dumps /tmp/w-ext-bt.out +
    // /tmp/w-ext-bts.out + /tmp/w-ext-btr.out + /tmp/w-ext-btc.out, 19
    // forms, examples/x86ext_probe.rs). CF = tested bit; the modify kind
    // selects the value op (bts: OR / btr: AND ~ / btc: XOR of the 1<<count
    // mask); plain bt never modifies. Per-constructor op ORDER (dump is
    // truth — CF placement differs by width and index kind):
    //   reg dst, reg/imm idx — count c = idx & (bits-1) at operand width
    //   (imm forms hold BOTH consts at :4, mask bits-1); sh = rm >> c;
    //   b = sh & 1; W==8: modify THEN CF = b!=0; W<8: CF THEN modify;
    //   modify = t = INT_LEFT(1:W, c); rm = rm OR/AND~NOT(t)/XOR t; 32-bit
    //   GPR modify forms end with the parent zext (plain bt: CF only).
    //   mem dst, imm idx — c:4 = imm & (bits-1); ONE shared slot LOADed at
    //   W; b from slot; W<8: CF THEN modify (t = 1:W << c, slot re-LOAD,
    //   slot = slot OP t, STORE); W==8: modify THEN CF.
    //   mem dst, reg idx — byte-granular bit string addressing: s:8 =
    //   sext(idx); sar = s >> 3 (const :4); addr = base + sar; c = idx & 7
    //   (idx width); byte = LOAD:1; b = (byte >> c) & 1; modify re-LOADs a
    //   fresh byte temp, OR/AND~/XOR with (1:1 << c) and STOREs; CF comes
    //   AFTER the STORE.
    /// Lift `bt`/`bts`/`btr`/`btc` (CF = tested bit; modify per kind).
    fn lift_bt(&mut self, inst: &Instruction, kind: BtKind, ops: &mut Vec<PcodeOpRaw>) {
        use OpCode as C;
        if inst.operands.len() != 2 {
            return;
        }
        let emit_cf = |this: &mut Self, b: &VarnodeRaw, ops: &mut Vec<PcodeOpRaw>| {
            let mut op = PcodeOpRaw::new(C::CPUI_INT_NOTEQUAL as i32);
            op.add_input(b.clone());
            op.add_input(Self::const_vn(0, b.size));
            op.set_output(Self::flag_cf());
            ops.push(op);
            let _ = this;
        };
        // modify op over (dst, mask) — btr negates the mask first
        let emit_modify = |this: &mut Self,
                           kind: BtKind,
                           dst_in: VarnodeRaw,
                           out: VarnodeRaw,
                           t: VarnodeRaw,
                           ops: &mut Vec<PcodeOpRaw>| {
            match kind {
                BtKind::Test => {}
                BtKind::Set => {
                    let mut op = PcodeOpRaw::new(C::CPUI_INT_OR as i32);
                    op.add_input(dst_in);
                    op.add_input(t);
                    op.set_output(out);
                    ops.push(op);
                }
                BtKind::Reset => {
                    let nt = this.alloc_tmp(t.size);
                    let mut neg = PcodeOpRaw::new(C::CPUI_INT_NEGATE as i32);
                    neg.add_input(t);
                    neg.set_output(nt.clone());
                    ops.push(neg);
                    let mut op = PcodeOpRaw::new(C::CPUI_INT_AND as i32);
                    op.add_input(dst_in);
                    op.add_input(nt);
                    op.set_output(out);
                    ops.push(op);
                }
                BtKind::Complement => {
                    let mut op = PcodeOpRaw::new(C::CPUI_INT_XOR as i32);
                    op.add_input(dst_in);
                    op.add_input(t);
                    op.set_output(out);
                    ops.push(op);
                }
            }
        };
        match &inst.operands[0] {
            crate::disasm::Operand::Register { name, size } => {
                // ---- reg dst, reg/imm idx ----
                let Some(rm) = Self::get_register(name, *size) else {
                    return;
                };
                let parent64 = if *size == 4 {
                    Self::parent64_name(name).and_then(|p| Self::get_register(p, 8))
                } else {
                    None
                };
                let w = *size;
                let mask: u64 = (w as u64 * 8) - 1;
                let c = match &inst.operands[1] {
                    crate::disasm::Operand::Register { name, size } => {
                        let Some(idx) = Self::get_register(name, *size) else {
                            return;
                        };
                        let t = self.alloc_tmp(w);
                        Self::push_raw(
                            ops,
                            C::CPUI_INT_AND,
                            &[idx, Self::const_vn(mask, w)],
                            Some(&t),
                        );
                        t
                    }
                    crate::disasm::Operand::Immediate { value, .. } => {
                        let t = self.alloc_tmp(4);
                        Self::push_raw(
                            ops,
                            C::CPUI_INT_AND,
                            &[
                                Self::const_vn((*value as u64) & 0xff, 4),
                                Self::const_vn(mask, 4),
                            ],
                            Some(&t),
                        );
                        t
                    }
                    _ => return,
                };
                let sh = self.alloc_tmp(w);
                Self::push_raw(ops, C::CPUI_INT_RIGHT, &[rm.clone(), c.clone()], Some(&sh));
                let b = self.alloc_tmp(w);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_AND,
                    &[sh, Self::const_vn(1, w)],
                    Some(&b),
                );
                if kind == BtKind::Test {
                    emit_cf(self, &b, ops);
                    return;
                }
                if w < 8 {
                    emit_cf(self, &b, ops);
                }
                let t = self.alloc_tmp(w);
                Self::push_raw(
                    ops,
                    C::CPUI_INT_LEFT,
                    &[Self::const_vn(1, w), c],
                    Some(&t),
                );
                emit_modify(self, kind, rm.clone(), rm.clone(), t, ops);
                if w == 8 {
                    emit_cf(self, &b, ops);
                } else if let Some(parent) = parent64 {
                    Self::push_raw(ops, C::CPUI_INT_ZEXT, &[rm], Some(&parent));
                }
            }
            crate::disasm::Operand::Memory {
                base,
                index,
                scale,
                displacement,
                size,
            } => {
                let w = *size;
                let mask: u64 = (w as u64 * 8) - 1;
                match &inst.operands[1] {
                    crate::disasm::Operand::Immediate { value, .. } => {
                        // ---- mem dst, imm idx ----
                        let Some(addr) =
                            self.compute_mem_addr(base, index, scale, displacement, ops)
                        else {
                            return;
                        };
                        let c = self.alloc_tmp(4);
                        Self::push_raw(
                            ops,
                            C::CPUI_INT_AND,
                            &[
                                Self::const_vn((*value as u64) & 0xff, 4),
                                Self::const_vn(mask, 4),
                            ],
                            Some(&c),
                        );
                        let slot = self.alloc_tmp(w);
                        self.emit_load_slot(&addr, &slot, ops);
                        let sh = self.alloc_tmp(w);
                        Self::push_raw(
                            ops,
                            C::CPUI_INT_RIGHT,
                            &[slot.clone(), c.clone()],
                            Some(&sh),
                        );
                        let b = self.alloc_tmp(w);
                        Self::push_raw(
                            ops,
                            C::CPUI_INT_AND,
                            &[sh, Self::const_vn(1, w)],
                            Some(&b),
                        );
                        if kind == BtKind::Test {
                            emit_cf(self, &b, ops);
                            return;
                        }
                        if w < 8 {
                            emit_cf(self, &b, ops);
                        }
                        // mask first (btr negates), THEN the re-LOAD, then
                        // the combine (dump `btr dword [rbx],5` [5][6][7])
                        let t = self.alloc_tmp(w);
                        Self::push_raw(
                            ops,
                            C::CPUI_INT_LEFT,
                            &[Self::const_vn(1, w), c],
                            Some(&t),
                        );
                        let mask_vn = if kind == BtKind::Reset {
                            let nt = self.alloc_tmp(w);
                            Self::push_raw(ops, C::CPUI_INT_NEGATE, &[t.clone()], Some(&nt));
                            nt
                        } else {
                            t
                        };
                        self.emit_load_slot(&addr, &slot, ops);
                        match kind {
                            BtKind::Set => Self::push_raw(
                                ops,
                                C::CPUI_INT_OR,
                                &[slot.clone(), mask_vn],
                                Some(&slot),
                            ),
                            BtKind::Reset => Self::push_raw(
                                ops,
                                C::CPUI_INT_AND,
                                &[slot.clone(), mask_vn],
                                Some(&slot),
                            ),
                            BtKind::Complement => Self::push_raw(
                                ops,
                                C::CPUI_INT_XOR,
                                &[slot.clone(), mask_vn],
                                Some(&slot),
                            ),
                            BtKind::Test => unreachable!("handled above"),
                        }
                        self.emit_store_v(&addr, slot, ops);
                        if w == 8 {
                            emit_cf(self, &b, ops);
                        }
                    }
                    crate::disasm::Operand::Register { name, size } => {
                        // ---- mem dst, reg idx (byte-granular bit string) ----
                        let Some(idx) = Self::get_register(name, *size) else {
                            return;
                        };
                        let Some(base_addr) =
                            self.compute_mem_addr(base, index, scale, displacement, ops)
                        else {
                            return;
                        };
                        // s:8 = sext(idx); sar = s >> 3; addr = base + sar
                        let s = self.alloc_tmp(8);
                        Self::push_raw(ops, C::CPUI_INT_SEXT, &[idx.clone()], Some(&s));
                        let sar = self.alloc_tmp(8);
                        Self::push_raw(
                            ops,
                            C::CPUI_INT_SRIGHT,
                            &[s, Self::const_vn(3, 4)],
                            Some(&sar),
                        );
                        let addr = self.alloc_tmp(8);
                        Self::push_raw(
                            ops,
                            C::CPUI_INT_ADD,
                            &[base_addr, sar],
                            Some(&addr),
                        );
                        // c = idx & 7 (idx width); plain BT LOADs the byte
                        // BEFORE this AND, the modify kinds AND first (dump
                        // `bt [rax],edx` [3][4] vs `bts [rax],edx` [3][4])
                        let c = self.alloc_tmp(idx.size);
                        if kind == BtKind::Test {
                            let byte = self.emit_load(1, &addr, ops);
                            Self::push_raw(
                                ops,
                                C::CPUI_INT_AND,
                                &[idx, Self::const_vn(7, idx.size)],
                                Some(&c),
                            );
                            let sh = self.alloc_tmp(1);
                            Self::push_raw(
                                ops,
                                C::CPUI_INT_RIGHT,
                                &[byte, c],
                                Some(&sh),
                            );
                            let b = self.alloc_tmp(1);
                            Self::push_raw(
                                ops,
                                C::CPUI_INT_AND,
                                &[sh, Self::const_vn(1, 1)],
                                Some(&b),
                            );
                            emit_cf(self, &b, ops);
                            return;
                        }
                        Self::push_raw(
                            ops,
                            C::CPUI_INT_AND,
                            &[idx, Self::const_vn(7, idx.size)],
                            Some(&c),
                        );
                        let byte = self.emit_load(1, &addr, ops);
                        let sh = self.alloc_tmp(1);
                        Self::push_raw(
                            ops,
                            C::CPUI_INT_RIGHT,
                            &[byte, c.clone()],
                            Some(&sh),
                        );
                        let b = self.alloc_tmp(1);
                        Self::push_raw(
                            ops,
                            C::CPUI_INT_AND,
                            &[sh, Self::const_vn(1, 1)],
                            Some(&b),
                        );
                        if kind == BtKind::Test {
                            emit_cf(self, &b, ops);
                            return;
                        }
                        // modify: fresh byte LOAD, OR/AND~/XOR (1 << c), STORE
                        let load2 = self.emit_load(1, &addr, ops);
                        let t = self.alloc_tmp(1);
                        Self::push_raw(
                            ops,
                            C::CPUI_INT_LEFT,
                            &[Self::const_vn(1, 1), c],
                            Some(&t),
                        );
                        let res = self.alloc_tmp(1);
                        emit_modify(self, kind, load2, res.clone(), t, ops);
                        self.emit_store_v(&addr, res, ops);
                        emit_cf(self, &b, ops);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    // RUGRA-GLUE: port of the ia.sinc :COMIS/:UCOMIS constructors of the
    // locked x86-64 sla (sleigh_shim op-for-op dump /tmp/w-ext-comis.out, 8
    // forms, examples/x86ext_probe.rs). COMISS and UCOMIS lift IDENTICAL
    // pcode (both flag NaN via FLOAT_NAN on both operands): PF = BOOL_OR(
    // NAN(lhs), NAN(rhs)); ZF = INT_OR(PF, FLOAT_EQUAL(lhs,rhs)); CF =
    // INT_OR(PF, FLOAT_LESS(lhs,rhs)); OF/AF/SF = COPY(0). Operand size
    // from the mnemonic suffix (*ss=4, *sd=8) — iced reports the 16-byte
    // vector width, the oracle reads the XMM register at the operation
    // size (register:0x1200+0x40*N). Memory rhs: address ops bind first
    // (displaced forms), then ONE shared slot re-LOADed before each float
    // op; constant addresses (rip-relative / absolute displacement) fold
    // to a direct ram-space varnode input with NO LOAD and NO address ops
    // (dump `comiss xmm0,[rip+0]`: FLOAT_NAN in=(ram:0x1c:4)).
    /// Lift `comiss`/`ucomiss`/`comisd`/`ucomisd` (PF/ZF/CF from float
    /// compare; OF/AF/SF cleared).
    fn lift_comis(&mut self, inst: &Instruction, ops: &mut Vec<PcodeOpRaw>) {
        use OpCode as C;
        if inst.operands.len() != 2 {
            return;
        }
        let size = if inst.mnemonic.ends_with("sd") { 8 } else { 4 };
        let lhs = match &inst.operands[0] {
            crate::disasm::Operand::Register { name, .. } => Self::get_register(name, size),
            _ => None,
        };
        let Some(lhs) = lhs else {
            return;
        };
        // rhs access: register direct / displaced-mem shared slot /
        // constant-address direct ram varnode
        enum Rhs {
            Direct(VarnodeRaw),
            Slot { addr: VarnodeRaw, slot: VarnodeRaw, size: usize },
            ConstAddr(VarnodeRaw),
        }
        let rhs = match &inst.operands[1] {
            crate::disasm::Operand::Register { name, .. } => {
                match Self::get_register(name, size) {
                    Some(vn) => Rhs::Direct(vn),
                    None => return,
                }
            }
            crate::disasm::Operand::Memory {
                base,
                index,
                scale,
                displacement,
                size: msize,
            } => {
                // rip-relative / absolute-displacement: constant address —
                // the oracle folds it into a direct ram varnode (the Rugra
                // disassembler resolves rip displacement to the absolute
                // target already)
                if base.as_deref() == Some("rip") && index.is_none() {
                    Rhs::ConstAddr(VarnodeRaw::new(
                        AddressSpace::Ram,
                        *displacement as u64,
                        *msize,
                    ))
                } else if base.is_none() && index.is_none() {
                    Rhs::ConstAddr(VarnodeRaw::new(
                        AddressSpace::Ram,
                        *displacement as u64,
                        *msize,
                    ))
                } else {
                    let Some(addr) =
                        self.compute_mem_addr(base, index, scale, displacement, ops)
                    else {
                        return;
                    };
                    let slot = self.alloc_tmp(*msize);
                    Rhs::Slot {
                        addr,
                        slot,
                        size: *msize,
                    }
                }
            }
            _ => return,
        };
        let use_rhs = |this: &mut Self, rhs: &Rhs, ops: &mut Vec<PcodeOpRaw>| -> VarnodeRaw {
            match rhs {
                Rhs::Direct(vn) | Rhs::ConstAddr(vn) => vn.clone(),
                Rhs::Slot { addr, slot, .. } => {
                    this.emit_load_slot(addr, slot, ops);
                    slot.clone()
                }
            }
        };
        // PF = BOOL_OR(NAN(lhs), NAN(rhs))
        let n0 = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_FLOAT_NAN, &[lhs.clone()], Some(&n0));
        let r1 = use_rhs(self, &rhs, ops);
        let n1 = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_FLOAT_NAN, &[r1], Some(&n1));
        Self::push_raw(
            ops,
            C::CPUI_BOOL_OR,
            &[n0, n1],
            Some(&Self::flag_pf()),
        );
        // ZF = INT_OR(PF, FLOAT_EQUAL(lhs, rhs))
        let r2 = use_rhs(self, &rhs, ops);
        let eq = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_FLOAT_EQUAL, &[lhs.clone(), r2], Some(&eq));
        Self::push_raw(
            ops,
            C::CPUI_INT_OR,
            &[Self::flag_pf(), eq],
            Some(&Self::flag_zf()),
        );
        // CF = INT_OR(PF, FLOAT_LESS(lhs, rhs))
        let r3 = use_rhs(self, &rhs, ops);
        let lt = self.alloc_tmp(1);
        Self::push_raw(ops, C::CPUI_FLOAT_LESS, &[lhs, r3], Some(&lt));
        Self::push_raw(
            ops,
            C::CPUI_INT_OR,
            &[Self::flag_pf(), lt],
            Some(&Self::flag_cf()),
        );
        // OF = AF = SF = 0
        for flag in [Self::flag_of(), Self::flag_af(), Self::flag_sf()] {
            Self::push_raw(ops, C::CPUI_COPY, &[Self::const_vn(0, 1)], Some(&flag));
        }
    }

    // RUGRA-GLUE: port of the ia.sinc cc condition table (ia.sinc:1523-1539,
    // `cc: "O" is cond=0 { export OF; }` ... `cc: "G" is cond=15 { local tmp
    // = !ZF && (OF == SF); export tmp; }`); executed semantics verified
    /// Emit the condition computation for a cc suffix; returns the 1-byte
    /// condition varnode. Suffix set: o no c(b) nc(ae) e(z) ne(nz) be(na)
    /// a(nbe) s ns p(pe) np(po) l(nge) ge(nl) le(ng) g(nle).
    fn emit_cc_cond(&mut self, cc: &str, ops: &mut Vec<PcodeOpRaw>) -> Option<VarnodeRaw> {
        match cc {
            "o" => Some(Self::flag_of()),
            "no" => Some(self.emit_bool_not(Self::flag_of(), ops)),
            "c" | "b" | "nae" => Some(Self::flag_cf()),
            "nc" | "ae" | "nb" => Some(self.emit_bool_not(Self::flag_cf(), ops)),
            "e" | "z" => Some(Self::flag_zf()),
            "ne" | "nz" => Some(self.emit_bool_not(Self::flag_zf(), ops)),
            "be" | "na" => Some(self.emit_bool_binary(
                Self::flag_cf(),
                Self::flag_zf(),
                OpCode::CPUI_BOOL_OR,
                ops,
            )),
            "a" | "nbe" => {
                let or = self.emit_bool_binary(
                    Self::flag_cf(),
                    Self::flag_zf(),
                    OpCode::CPUI_BOOL_OR,
                    ops,
                );
                Some(self.emit_bool_not(or, ops))
            }
            "s" => Some(Self::flag_sf()),
            "ns" => Some(self.emit_bool_not(Self::flag_sf(), ops)),
            "p" | "pe" => Some(Self::flag_pf()),
            "np" | "po" => Some(self.emit_bool_not(Self::flag_pf(), ops)),
            "l" | "nge" => Some(self.emit_flag_pair(
                Self::flag_of(),
                Self::flag_sf(),
                OpCode::CPUI_INT_NOTEQUAL,
                ops,
            )),
            "ge" | "nl" => Some(self.emit_flag_pair(
                Self::flag_of(),
                Self::flag_sf(),
                OpCode::CPUI_INT_EQUAL,
                ops,
            )),
            "le" | "ng" => {
                let ne = self.emit_flag_pair(
                    Self::flag_of(),
                    Self::flag_sf(),
                    OpCode::CPUI_INT_NOTEQUAL,
                    ops,
                );
                Some(self.emit_bool_binary(
                    Self::flag_zf(),
                    ne,
                    OpCode::CPUI_BOOL_OR,
                    ops,
                ))
            }
            "g" | "nle" => {
                let not_zf = self.emit_bool_not(Self::flag_zf(), ops);
                let eq = self.emit_flag_pair(
                    Self::flag_of(),
                    Self::flag_sf(),
                    OpCode::CPUI_INT_EQUAL,
                    ops,
                );
                Some(self.emit_bool_binary(
                    not_zf,
                    eq,
                    OpCode::CPUI_BOOL_AND,
                    ops,
                ))
            }
            _ => None,
        }
    }

    // RUGRA-GLUE: cc-table helper — BOOL_NEGATE into a fresh 1-byte temp
    /// Emit boolean negation of `v`.
    fn emit_bool_not(&mut self, v: VarnodeRaw, ops: &mut Vec<PcodeOpRaw>) -> VarnodeRaw {
        let tmp = self.alloc_tmp(1);
        let mut op = PcodeOpRaw::new(OpCode::CPUI_BOOL_NEGATE as i32);
        op.add_input(v);
        op.set_output(tmp.clone());
        ops.push(op);
        tmp
    }

    // RUGRA-GLUE: cc-table helper — BOOL_AND / BOOL_OR over two 1-byte
    /// Emit a boolean binary op over two condition varnodes.
    fn emit_bool_binary(
        &mut self,
        a: VarnodeRaw,
        b: VarnodeRaw,
        opcode: OpCode,
        ops: &mut Vec<PcodeOpRaw>,
    ) -> VarnodeRaw {
        let tmp = self.alloc_tmp(1);
        let mut op = PcodeOpRaw::new(opcode as i32);
        op.add_input(a);
        op.add_input(b);
        op.set_output(tmp.clone());
        ops.push(op);
        tmp
    }

    // RUGRA-GLUE: cc-table helper — INT_EQUAL / INT_NOTEQUAL over two flags
    /// Emit a flag-pair comparison (OF vs SF family).
    fn emit_flag_pair(
        &mut self,
        a: VarnodeRaw,
        b: VarnodeRaw,
        opcode: OpCode,
        ops: &mut Vec<PcodeOpRaw>,
    ) -> VarnodeRaw {
        let tmp = self.alloc_tmp(1);
        let mut op = PcodeOpRaw::new(opcode as i32);
        op.add_input(a);
        op.add_input(b);
        op.set_output(tmp.clone());
        ops.push(op);
        tmp
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
            "and" => {
                self.lift_logic(inst, OpCode::CPUI_INT_AND, &mut ops);
            }
            "or" => {
                self.lift_logic(inst, OpCode::CPUI_INT_OR, &mut ops);
            }
            "xor" => {
                self.lift_logic(inst, OpCode::CPUI_INT_XOR, &mut ops);
            }
            "shl" | "sal" => {
                self.lift_shift(inst, ShiftDir::Left, &mut ops);
            }
            "shr" => {
                self.lift_shift(inst, ShiftDir::Right, &mut ops);
            }
            "sar" => {
                self.lift_shift(inst, ShiftDir::Arith, &mut ops);
            }
            "rol" => {
                self.lift_rotate(inst, RotDir::Left, &mut ops);
            }
            "ror" => {
                self.lift_rotate(inst, RotDir::Right, &mut ops);
            }
            "imul" => {
                self.lift_imul(inst, &mut ops);
            }
            "bt" => {
                self.lift_bt(inst, BtKind::Test, &mut ops);
            }
            "bts" => {
                self.lift_bt(inst, BtKind::Set, &mut ops);
            }
            "btr" => {
                self.lift_bt(inst, BtKind::Reset, &mut ops);
            }
            "btc" => {
                self.lift_bt(inst, BtKind::Complement, &mut ops);
            }
            "comiss" | "ucomiss" | "comisd" | "ucomisd" => {
                self.lift_comis(inst, &mut ops);
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
            "adc" => {
                self.lift_adc(inst, &mut ops);
            }
            "sbb" => {
                self.lift_sbb(inst, &mut ops);
            }
            other if other.starts_with("cmov") => {
                self.lift_cmov(inst, &other[4..], &mut ops);
            }
            "movzx" => {
                self.lift_movx(inst, OpCode::CPUI_INT_ZEXT, &mut ops);
            }
            "movsx" | "movsxd" => {
                self.lift_movx(inst, OpCode::CPUI_INT_SEXT, &mut ops);
            }
            "pop" => {
                self.lift_pop(inst, &mut ops);
            }
            "cbw" | "cwde" | "cdqe" => {
                self.lift_widen_acc(inst, &mut ops);
            }
            "cdq" | "cqo" => {
                self.lift_sign_dividend(inst, &mut ops);
            }
            other if other.starts_with("set") => {
                self.lift_setcc(inst, &other[3..], &mut ops);
            }
            "cmp" => {
                self.lift_cmp(inst, &mut ops);
            }
            "test" => {
                self.lift_test(inst, &mut ops);
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
            "je" | "jz" | "jne" | "jnz" | "jl" | "jle" | "jg" | "jge" | "jb" | "jc" | "jna"
            | "ja" | "jnb" | "jbe" | "jae" | "jnc" | "js" | "jns" | "jo" | "jno" | "jp" | "jpe"
            | "jnp" | "jpo" | "jnge" | "jnl" | "jng" | "jnle" | "jnae" | "jnbe" => {
                // X86LIFT-FLAG-PCODE-0001: conditions per the ia.sinc cc
                // table (jCC reads CF=0x200/PF=0x202/ZF=0x206/SF=0x207/
                // OF=0x20b; e.g. je = CBRANCH(target, ZF), jne =
                // BOOL_NEGATE(ZF), jl = INT_NOTEQUAL(OF,SF), ja =
                // BOOL_NEGATE(BOOL_OR(CF,ZF))). The old arm used wrong flag
                // offsets (0x201/0x202/0x203) and SF-only signed conditions.
                if inst.operands.len() == 1 {
                    if let crate::disasm::Operand::Immediate { value, .. } = inst.operands[0] {
                        let target = VarnodeRaw::new(AddressSpace::Ram, value as u64, 8);
                        if let Some(cond_vn) = self.emit_cc_cond(&mnemonic[1..], &mut ops) {
                            let mut op = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
                            op.add_input(target);
                            op.add_input(cond_vn);
                            ops.push(op);
                        }
                    }
                }
            }
            "push" => {
                self.lift_push(inst, &mut ops);
            }
            "call" | "ret" => {
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
