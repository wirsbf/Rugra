use crate::address::{Address, SeqNum};
use crate::opcodes::OpCode;
use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
use crate::space::AddressSpace;
use crate::sleigh_ffi::{SleighCtx, PcodeOpC, VarnodeC};
use std::sync::OnceLock;

static SLA_PATH: OnceLock<String> = OnceLock::new();

// RUGRA-GLUE: set_sla_path
pub fn set_sla_path(path: &str) {
    let _ = SLA_PATH.set(path.to_string());
}

// RUGRA-GLUE: get_sla_path
fn get_sla_path() -> &'static str {
    SLA_PATH.get().map(|s| s.as_str()).unwrap_or("sleigh_specs/x86-64.sla")
}

// RUGRA-GLUE: map_space
fn map_space(space_idx: i32) -> AddressSpace {
    AddressSpace::from_id(space_idx as u8)
}

// RUGRA-GLUE: map_vn
fn map_vn(vn: &VarnodeC) -> VarnodeRaw {
    VarnodeRaw::new(map_space(vn.space), vn.offset, vn.size as usize)
}

pub struct SleighLifter;

impl SleighLifter {
    // RUGRA-GLUE: new
    pub fn new() -> Self { Self }

    // RUGRA-GLUE: lift_function
    pub fn lift_function(func_code: &[u8], func_base: u64, inst_offsets: &[(u64, usize)]) -> Vec<(u64, Vec<PcodeOpRaw>)> {
        let mut ctx = match SleighCtx::new() {
            Some(c) => c,
            None => return Vec::new(),
        };
        let pspec = std::path::Path::new("sleigh_specs/x86-64.pspec");
        if pspec.exists() {
            ctx.load_pspec(pspec.to_str().unwrap());
        }
        ctx.set_image(func_code, func_base);

        let mut result = Vec::new();
        for &(rel_offset, len) in inst_offsets {
            let off = rel_offset as usize;
            if off + 4 <= func_code.len() && func_code[off..off+4] == [0xf3, 0x0f, 0x1e, 0xfa] {
                continue;
            }
            let abs_addr = func_base + rel_offset;
            let ops_c = ctx.decode(abs_addr);
            if ops_c.is_empty() { continue; }
            let real_addr = abs_addr;
            let seq = SeqNum::new(Address::new(real_addr), 0);
            // next_rip for RIP-relative resolution: instruction address + length
            let next_rip = abs_addr.wrapping_add(len as u64);
            let mut ops = Vec::new();
            for opc in &ops_c {
                ops.push(Self::convert_with_rip(opc, seq, next_rip));
            }
            result.push((real_addr, ops));
        }
        result
    }

    // RUGRA-GLUE: convert (legacy, no RIP resolution)
    pub fn convert(opc: &PcodeOpC, seq: SeqNum) -> PcodeOpRaw {
        Self::convert_with_rip(opc, seq, 0)
    }

    // RUGRA-GLUE: convert_with_rip — convert SLEIGH PcodeOpC to PcodeOpRaw,
    // resolving RIP-relative INT_ADD(RIP, Const@disp) → COPY(Ram@abs_addr).
    // This mirrors x86_lift.rs:331-356's RIP-relative resolver. In PIE binaries,
    // `mov [rip+disp], reg` lifts to STORE(Ram, INT_ADD(RIP, Const@disp), reg).
    // Without resolution, the absolute address never appears as a constant,
    // so seed_global_struct_pointers and printc's mapentry pipeline cannot
    // match known global addresses (e.g. ::config @ 0x17520). Resolving to
    // COPY(Ram@abs_addr) makes the address available for struct field rendering.
    pub fn convert_with_rip(opc: &PcodeOpC, seq: SeqNum, next_rip: u64) -> PcodeOpRaw {
        let opcode = OpCode::from_i32(opc.opcode).unwrap_or(OpCode::CPUI_COPY);

        // Detect INT_ADD(RIP, Const@disp) pattern and resolve to absolute address.
        // RIP is Register@0x200, size 8 (per src/printc.rs:3917 get_rip_relative_operand).
        if opcode == OpCode::CPUI_INT_ADD && opc.has_output != 0 && opc.num_inputs >= 2 && next_rip != 0 {
            let i0 = &opc.inputs[0];
            let i1 = &opc.inputs[1];
            // Check: one input is Register@0x200 (RIP), other is Const@disp
            // SLEIGH space indices: 0=const, 1=other, 2=unique, 3=ram, 4=register, 5=stack
            let rip_is_i0 = i0.space == 4 /* SPACEID_REGISTER */ && i0.offset == 0x200;
            let rip_is_i1 = i1.space == 4 && i1.offset == 0x200;
            if rip_is_i0 || rip_is_i1 {
                let disp_vn = if rip_is_i0 { i1 } else { i0 };
                // Const space is SPACEID_CONST = 0
                if disp_vn.space == 0 {
                    let abs_addr = next_rip.wrapping_add(disp_vn.offset);
                    // Emit COPY(Ram@abs_addr) instead of INT_ADD(RIP, disp)
                    let mut raw = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
                    raw.set_seq_num(seq);
                    raw.set_output(map_vn(&opc.output));
                    raw.add_input(VarnodeRaw::new(AddressSpace::Ram, abs_addr, opc.output.size as usize));
                    return raw;
                }
            }
        }

        // Default conversion (unchanged)
        let mut raw = PcodeOpRaw::new(opcode as i32);
        raw.set_seq_num(seq);

        if opc.has_output != 0 {
            raw.set_output(map_vn(&opc.output));
        }
        for i in 0..opc.num_inputs.min(16) as usize {
            let vn = &opc.inputs[i];
            let space = if vn.space == 0 && matches!(opcode,
                OpCode::CPUI_CALL | OpCode::CPUI_CALLIND |
                OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH) {
                AddressSpace::Ram
            } else {
                map_space(vn.space)
            };
            raw.add_input(VarnodeRaw::new(space, vn.offset, vn.size as usize));
        }
        raw
    }

    // RUGRA-GLUE: lift_from_func
    pub fn lift_from_func(func_code: &[u8], func_base: u64, addr: u64) -> Vec<PcodeOpRaw> {
        let mut ctx = match SleighCtx::new() {
            Some(c) => c,
            None => return Vec::new(),
        };
        ctx.set_image(func_code, func_base);
        let ops_c = ctx.decode(addr);
        let seq = SeqNum::new(Address::new(addr), 0);
        ops_c.iter().map(|opc| Self::convert(opc, seq)).collect()
    }
}
