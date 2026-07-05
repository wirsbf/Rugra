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
        ctx.set_image(func_code, func_base);

        let mut result = Vec::new();
        for &(rel_offset, _len) in inst_offsets {
            let abs_addr = func_base + rel_offset;
            let ops_c = ctx.decode(abs_addr);
            if ops_c.is_empty() { continue; }
            let real_addr = abs_addr;
            let seq = SeqNum::new(Address::new(real_addr), 0);
            let mut ops = Vec::new();
            for opc in &ops_c {
                ops.push(Self::convert(opc, seq));
            }
            result.push((real_addr, ops));
        }
        result
    }

    // RUGRA-GLUE: convert
    pub fn convert(opc: &PcodeOpC, seq: SeqNum) -> PcodeOpRaw {
        let opcode = OpCode::from_i32(opc.opcode).unwrap_or(OpCode::CPUI_COPY);
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
