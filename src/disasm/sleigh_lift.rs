use crate::address::{Address, SeqNum};
use crate::opcodes::OpCode;
use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
use crate::space::AddressSpace;
use crate::sleigh_ffi::{
    PcodeOpC, SleighCtx, SleighDecodeError, SleighErrorKind, VarnodeC,
};

// RUGRA-GLUE: set_sla_path
pub fn set_sla_path(path: &str) {
    crate::sleigh_ffi::set_sla_path(path);
}

// RUGRA-GLUE: map_space
fn map_space(space_idx: i32) -> AddressSpace {
    AddressSpace::from_id(space_idx as u8)
}

// RUGRA-GLUE: map_vn
fn map_vn(vn: &VarnodeC) -> VarnodeRaw {
    VarnodeRaw::new(map_space(vn.space), vn.offset, vn.size as usize)
}

pub struct SleighLifter {
    ctx: Option<SleighCtx>,
}

impl SleighLifter {
    // RUGRA-GLUE: new
    pub fn new() -> Self {
        Self {
            ctx: SleighCtx::new(),
        }
    }

    // RUGRA-GLUE: configure one owned SLEIGH translator before following a function
    pub fn configure_x86_64(
        &mut self,
        image: &[u8],
        image_base: u64,
    ) -> Result<(), SleighDecodeError> {
        let ctx = self.ctx.as_mut().ok_or_else(Self::unavailable_error)?;
        let pspec = std::path::Path::new("sleigh_specs/x86-64.pspec");
        if pspec.exists() {
            ctx.load_pspec(pspec.to_str().unwrap_or_default());
        }
        ctx.try_set_image(image, image_base)
    }

    // RUGRA-GLUE: atomically consume Sleigh::oneInstruction step and emitted ops
    pub fn lift_instruction(
        &mut self,
        address: u64,
    ) -> Result<(usize, Vec<PcodeOpRaw>), SleighDecodeError> {
        let ctx = self.ctx.as_mut().ok_or_else(Self::unavailable_error)?;
        let decoded = ctx.one_instruction(address)?;
        let step = usize::try_from(decoded.step)
            .ok()
            .filter(|step| *step != 0)
            .ok_or_else(|| SleighDecodeError {
                kind: SleighErrorKind::Bridge,
                message: format!("SLEIGH returned invalid step {}", decoded.step).into_bytes(),
                instruction_length: None,
            })?;
        let seq = SeqNum::new(Address::new(address), 0);
        let ops = decoded
            .ops
            .iter()
            .map(|op| Self::convert(op, seq))
            .collect();
        Ok((step, ops))
    }

    // RUGRA-GLUE: construct the typed failure used when the C++ engine could not be created
    fn unavailable_error() -> SleighDecodeError {
        SleighDecodeError {
            kind: SleighErrorKind::Bridge,
            message: b"unable to create the SLEIGH translator".to_vec(),
            instruction_length: None,
        }
    }

    // RUGRA-GLUE: lift_function
    pub fn lift_function(func_code: &[u8], func_base: u64, inst_offsets: &[(u64, usize)]) -> Vec<(u64, Vec<PcodeOpRaw>)> {
        let mut lifter = Self::new();
        if lifter.configure_x86_64(func_code, func_base).is_err() {
            return Vec::new();
        }

        let mut result = Vec::new();
        for &(rel_offset, _len) in inst_offsets {
            let off = rel_offset as usize;
            if off + 4 <= func_code.len() && func_code[off..off+4] == [0xf3, 0x0f, 0x1e, 0xfa] {
                continue;
            }
            let abs_addr = func_base + rel_offset;
            let Ok((_step, ops)) = lifter.lift_instruction(abs_addr) else {
                continue;
            };
            if !ops.is_empty() {
                result.push((abs_addr, ops));
            }
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
        for vn in &opc.inputs {
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
        let mut lifter = Self::new();
        if lifter.configure_x86_64(func_code, func_base).is_err() {
            return Vec::new();
        }
        lifter
            .lift_instruction(addr)
            .map(|(_, ops)| ops)
            .unwrap_or_default()
    }
}
