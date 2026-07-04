use crate::address::{Address, SeqNum};
use crate::opcodes::OpCode;
use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
use crate::space::AddressSpace;
use jingle_sleigh::SpaceType;
use jingle_sleigh::context::SleighContextBuilder;
use jingle_sleigh::{PcodeOperation, VarNode, OpCode as JOpCode};

// RUGRA-GLUE: SleighLifter — integrates jingle_sleigh SLEIGH runtime with Rugra's PcodeOpRaw
pub struct SleighLifter {
    uniq_base: u64,
}

impl SleighLifter {
    // RUGRA-GLUE: constructor (no Ghidra counterpart — Rust initialization)
    pub fn new() -> Self {
        Self { uniq_base: 0x1000 }
    }

    // RUGRA-GLUE: maps jingle_sleigh SpaceType to Rugra AddressSpace
    fn map_space(vn: &VarNode, arch: &jingle_sleigh::SleighArchInfo) -> AddressSpace {
        let si = arch.get_space(vn.space_index());
        let stype = si.map(|s| s._type);
        match stype {
            Some(SpaceType::IPTR_CONSTANT) => AddressSpace::Const,
            Some(SpaceType::IPTR_PROCESSOR) => AddressSpace::Ram,
            Some(SpaceType::IPTR_INTERNAL) => AddressSpace::Unique,
            Some(SpaceType::IPTR_IOP) => AddressSpace::Iop,
            Some(SpaceType::IPTR_JOIN) => AddressSpace::Join,
            Some(SpaceType::IPTR_FSPEC) => AddressSpace::Iop,
            Some(SpaceType::IPTR_SPACEBASE) => {
                let name = si.and_then(|s| Some(s.name.as_str())).unwrap_or("");
                if name.eq_ignore_ascii_case("stack") { AddressSpace::Stack }
                else { AddressSpace::Register }
            }
            None => AddressSpace::Ram,
            _ => AddressSpace::Ram,
        }
    }

    // RUGRA-GLUE: maps jingle_sleigh VarNode to Rugra VarnodeRaw
    fn map_vn(vn: &VarNode, arch: &jingle_sleigh::SleighArchInfo) -> VarnodeRaw {
        VarnodeRaw::new(Self::map_space(vn, arch), vn.offset(), vn.size())
    }

    // RUGRA-GLUE: maps jingle_sleigh OpCode to Rugra OpCode by variant name
    fn opc_from(jopc: JOpCode) -> OpCode {
        use jingle_sleigh::OpCode as J;
        match jopc {
            J::CPUI_COPY => OpCode::CPUI_COPY,
            J::CPUI_LOAD => OpCode::CPUI_LOAD,
            J::CPUI_STORE => OpCode::CPUI_STORE,
            J::CPUI_BRANCH => OpCode::CPUI_BRANCH,
            J::CPUI_CBRANCH => OpCode::CPUI_CBRANCH,
            J::CPUI_BRANCHIND => OpCode::CPUI_BRANCHIND,
            J::CPUI_CALL => OpCode::CPUI_CALL,
            J::CPUI_CALLIND => OpCode::CPUI_CALLIND,
            J::CPUI_CALLOTHER => OpCode::CPUI_CALLOTHER,
            J::CPUI_RETURN => OpCode::CPUI_RETURN,
            J::CPUI_INT_EQUAL => OpCode::CPUI_INT_EQUAL,
            J::CPUI_INT_NOTEQUAL => OpCode::CPUI_INT_NOTEQUAL,
            J::CPUI_INT_SLESS => OpCode::CPUI_INT_SLESS,
            J::CPUI_INT_SLESSEQUAL => OpCode::CPUI_INT_SLESSEQUAL,
            J::CPUI_INT_LESS => OpCode::CPUI_INT_LESS,
            J::CPUI_INT_LESSEQUAL => OpCode::CPUI_INT_LESSEQUAL,
            J::CPUI_INT_ZEXT => OpCode::CPUI_INT_ZEXT,
            J::CPUI_INT_SEXT => OpCode::CPUI_INT_SEXT,
            J::CPUI_INT_ADD => OpCode::CPUI_INT_ADD,
            J::CPUI_INT_SUB => OpCode::CPUI_INT_SUB,
            J::CPUI_INT_CARRY => OpCode::CPUI_INT_CARRY,
            J::CPUI_INT_SCARRY => OpCode::CPUI_INT_SCARRY,
            J::CPUI_INT_SBORROW => OpCode::CPUI_INT_SBORROW,
            J::CPUI_INT_2COMP => OpCode::CPUI_INT_2COMP,
            J::CPUI_INT_NEGATE => OpCode::CPUI_INT_NEGATE,
            J::CPUI_INT_XOR => OpCode::CPUI_INT_XOR,
            J::CPUI_INT_AND => OpCode::CPUI_INT_AND,
            J::CPUI_INT_OR => OpCode::CPUI_INT_OR,
            J::CPUI_INT_LEFT => OpCode::CPUI_INT_LEFT,
            J::CPUI_INT_RIGHT => OpCode::CPUI_INT_RIGHT,
            J::CPUI_INT_SRIGHT => OpCode::CPUI_INT_SRIGHT,
            J::CPUI_INT_MULT => OpCode::CPUI_INT_MULT,
            J::CPUI_INT_DIV => OpCode::CPUI_INT_DIV,
            J::CPUI_INT_SDIV => OpCode::CPUI_INT_SDIV,
            J::CPUI_INT_REM => OpCode::CPUI_INT_REM,
            J::CPUI_INT_SREM => OpCode::CPUI_INT_SREM,
            J::CPUI_BOOL_NEGATE => OpCode::CPUI_BOOL_NEGATE,
            J::CPUI_BOOL_XOR => OpCode::CPUI_BOOL_XOR,
            J::CPUI_BOOL_AND => OpCode::CPUI_BOOL_AND,
            J::CPUI_BOOL_OR => OpCode::CPUI_BOOL_OR,
            J::CPUI_FLOAT_EQUAL => OpCode::CPUI_FLOAT_EQUAL,
            J::CPUI_FLOAT_NOTEQUAL => OpCode::CPUI_FLOAT_NOTEQUAL,
            J::CPUI_FLOAT_LESS => OpCode::CPUI_FLOAT_LESS,
            J::CPUI_FLOAT_LESSEQUAL => OpCode::CPUI_FLOAT_LESSEQUAL,
            J::CPUI_FLOAT_NAN => OpCode::CPUI_FLOAT_NAN,
            J::CPUI_FLOAT_ADD => OpCode::CPUI_FLOAT_ADD,
            J::CPUI_FLOAT_DIV => OpCode::CPUI_FLOAT_DIV,
            J::CPUI_FLOAT_MULT => OpCode::CPUI_FLOAT_MULT,
            J::CPUI_FLOAT_SUB => OpCode::CPUI_FLOAT_SUB,
            J::CPUI_FLOAT_NEG => OpCode::CPUI_FLOAT_NEG,
            J::CPUI_FLOAT_ABS => OpCode::CPUI_FLOAT_ABS,
            J::CPUI_FLOAT_SQRT => OpCode::CPUI_FLOAT_SQRT,
            J::CPUI_FLOAT_INT2FLOAT => OpCode::CPUI_FLOAT_INT2FLOAT,
            J::CPUI_FLOAT_FLOAT2FLOAT => OpCode::CPUI_FLOAT_FLOAT2FLOAT,
            J::CPUI_FLOAT_TRUNC => OpCode::CPUI_FLOAT_TRUNC,
            J::CPUI_FLOAT_CEIL => OpCode::CPUI_FLOAT_CEIL,
            J::CPUI_FLOAT_FLOOR => OpCode::CPUI_FLOAT_FLOOR,
            J::CPUI_FLOAT_ROUND => OpCode::CPUI_FLOAT_ROUND,
            J::CPUI_MULTIEQUAL => OpCode::CPUI_MULTIEQUAL,
            J::CPUI_INDIRECT => OpCode::CPUI_INDIRECT,
            J::CPUI_PIECE => OpCode::CPUI_PIECE,
            J::CPUI_SUBPIECE => OpCode::CPUI_SUBPIECE,
            J::CPUI_CAST => OpCode::CPUI_CAST,
            J::CPUI_PTRADD => OpCode::CPUI_PTRADD,
            J::CPUI_PTRSUB => OpCode::CPUI_PTRSUB,
            J::CPUI_SEGMENTOP => OpCode::CPUI_SEGMENTOP,
            J::CPUI_CPOOLREF => OpCode::CPUI_CPOOLREF,
            J::CPUI_NEW => OpCode::CPUI_NEW,
            J::CPUI_INSERT => OpCode::CPUI_INSERT,
            J::CPUI_EXTRACT => OpCode::CPUI_EXTRACT,
            J::CPUI_POPCOUNT => OpCode::CPUI_POPCOUNT,
            J::CPUI_LZCOUNT => OpCode::CPUI_LZCOUNT,
            _ => OpCode::CPUI_COPY,
        }
    }

    // RUGRA-GLUE: SLEIGH-based lift — replaces manual x86_lift instruction-by-instruction
    pub fn lift(addr: u64, code: &[u8]) -> Vec<PcodeOpRaw> {
        let specs_dir = std::path::Path::new("sleigh_specs");
        let builder = SleighContextBuilder::load_folder(specs_dir)
            .expect("SLEIGH specs not found");
        let ctx = builder.build("x86:LE:64:default")
            .expect("build context");
        let arch = ctx.arch_info().clone();
        let loaded = ctx.initialize_with_image(code)
            .expect("init image");

        let inst = match loaded.instruction_at(addr) {
            Some(i) => i,
            None => return Vec::new(),
        };

        let mut result = Vec::new();
        let seq = SeqNum::new(Address::new(addr), 0);

        for op in &inst.ops {
            let opcode = Self::opc_from(op.opcode());
            let mut raw = PcodeOpRaw::new(opcode as i32);
            raw.set_seq_num(seq);

            match op {
                PcodeOperation::Copy { input, output } => {
                    raw.set_output(Self::map_vn(output, &arch));
                    raw.add_input(Self::map_vn(input, &arch));
                }
                PcodeOperation::IntAdd { output, input0, input1 }
                | PcodeOperation::IntSub { output, input0, input1 }
                | PcodeOperation::IntMult { output, input0, input1 }
                | PcodeOperation::IntDiv { output, input0, input1 }
                | PcodeOperation::IntAnd { output, input0, input1 }
                | PcodeOperation::IntOr { output, input0, input1 }
                | PcodeOperation::IntXor { output, input0, input1 }
                | PcodeOperation::IntEqual { output, input0, input1 }
                | PcodeOperation::IntLess { output, input0, input1 }
                | PcodeOperation::IntLeftShift { output, input0, input1 } => {
                    raw.set_output(Self::map_vn(output, &arch));
                    raw.add_input(Self::map_vn(input0, &arch));
                    raw.add_input(Self::map_vn(input1, &arch));
                }
                PcodeOperation::Store { output, input } => {
                    raw.add_input(Self::map_vn(&output.pointer_location(), &arch));
                    raw.add_input(Self::map_vn(input, &arch));
                }
                PcodeOperation::Load { output, input } => {
                    raw.set_output(Self::map_vn(output, &arch));
                    raw.add_input(Self::map_vn(&input.pointer_location(), &arch));
                }
                PcodeOperation::Branch { input }
                | PcodeOperation::Fallthrough { input } => {
                    raw.add_input(Self::map_vn(input, &arch));
                }
                PcodeOperation::Call { dest, .. } => {
                    raw.add_input(Self::map_vn(dest, &arch));
                }
                PcodeOperation::Return { input } => {
                    raw.add_input(Self::map_vn(&input.pointer_location(), &arch));
                }
                _ => {
                    // Fallback for ops not yet explicitly handled
                }
            }
            result.push(raw);
        }
        result
    }
}
