//! LANEDIVIDE-INFRA-0001 Rugra comparand.

use rugra::address::Address;
use rugra::arch::Architecture;
use rugra::block::FlowBlock;
use rugra::funcdata::Funcdata;
use rugra::op::PcodeOpRef;
use rugra::opcodes::OpCode;
use rugra::space::AddressSpace;
use rugra::subflow::LaneDivide;
use rugra::transform::{LaneDescription, LanedRegister};
use rugra::varnode::Varnode;
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::{Arc, RwLock};

type Block = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

struct GraphProjection {
    ops: Vec<PcodeOpRef>,
    op_index: HashMap<usize, usize>,
    vars: Vec<Arc<RwLock<Varnode>>>,
    var_index: HashMap<usize, usize>,
}

impl GraphProjection {
    fn new(block: &Block) -> Self {
        let ops = block.read().unwrap().get_ops();
        let op_index = ops
            .iter()
            .enumerate()
            .map(|(index, op)| (Arc::as_ptr(&op.0) as usize, index))
            .collect();
        let mut result = Self {
            ops,
            op_index,
            vars: Vec::new(),
            var_index: HashMap::new(),
        };
        for op_index in 0..result.ops.len() {
            let (output, inputs) = {
                let op = result.ops[op_index].0.read().unwrap();
                (op.get_out().cloned(), op.inrefs.clone())
            };
            result.touch(output);
            for input in inputs {
                result.touch(Some(input));
            }
        }
        result
    }

    fn touch(&mut self, varnode: Option<Arc<RwLock<Varnode>>>) {
        let Some(varnode) = varnode else { return };
        let pointer = Arc::as_ptr(&varnode) as usize;
        if self.var_index.contains_key(&pointer) {
            return;
        }
        self.var_index.insert(pointer, self.vars.len());
        self.vars.push(varnode);
    }

    fn var_name(&self, varnode: Option<&Arc<RwLock<Varnode>>>) -> String {
        let Some(varnode) = varnode else {
            return "_".to_string();
        };
        self.var_index
            .get(&(Arc::as_ptr(varnode) as usize))
            .map_or_else(|| "x".to_string(), |index| format!("v{index}"))
    }

    fn op_name(&self, op: Option<&Arc<RwLock<rugra::op::PcodeOp>>>) -> String {
        let Some(op) = op else {
            return "_".to_string();
        };
        self.op_index
            .get(&(Arc::as_ptr(op) as usize))
            .map_or_else(|| "x".to_string(), |index| format!("o{index}"))
    }

    fn render(&self, fd: &Funcdata, block: &Block) -> String {
        let mut output = String::new();
        output.push_str("ops[");
        for (index, op) in self.ops.iter().enumerate() {
            if index != 0 {
                output.push(';');
            }
            let op = op.0.read().unwrap();
            let parent = op
                .parent
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .filter(|parent| Arc::ptr_eq(parent, block))
                .map_or(-1, |parent| parent.read().unwrap().get_index());
            write!(
                output,
                "o{index}:{}@{}/t{}/r{}/d{}/p{parent}/o{}/i",
                op.opcode as i32,
                op.get_addr().as_u64(),
                op.start.get_time(),
                op.start.get_order(),
                u8::from(op.is_dead()),
                self.var_name(op.get_out()),
            )
            .unwrap();
            for (slot, input) in op.inrefs.iter().enumerate() {
                if slot != 0 {
                    output.push(',');
                }
                output.push_str(&self.var_name(Some(input)));
            }
        }
        output.push_str("]vars[");
        for (index, varnode) in self.vars.iter().enumerate() {
            if index != 0 {
                output.push(';');
            }
            let varnode = varnode.read().unwrap();
            write!(
                output,
                "v{index}:c{}/s{}/sp{}/k{}",
                varnode.create_index,
                varnode.get_size(),
                varnode.get_space().space_id(),
                u8::from(varnode.is_constant()),
            )
            .unwrap();
            if varnode.is_constant() {
                write!(output, ":{}", varnode.get_offset()).unwrap();
            }
            write!(
                output,
                "/f{}/n{}/w{}/d{}/u",
                u8::from(varnode.is_free()),
                u8::from(varnode.is_input()),
                u8::from(varnode.is_written()),
                self.op_name(varnode.get_def().as_ref()),
            )
            .unwrap();
            for (use_index, descendant) in varnode.descend_iter().enumerate() {
                if use_index != 0 {
                    output.push(',');
                }
                output.push_str(&self.op_name(Some(&descendant)));
            }
        }
        write!(
            output,
            "]count={},{},{},{},{},{}",
            self.ops.len(),
            self.vars.len(),
            fd.obank.alivelist.len(),
            fd.obank.deadlist.len(),
            fd.obank.optree.len(),
            fd.vbank.num_varnodes(),
        )
        .unwrap();
        output
    }
}

fn snapshot(fd: &Funcdata, block: &Block) -> String {
    GraphProjection::new(block).render(fd, block)
}

fn new_output_op(
    fd: &mut Funcdata,
    block: &Block,
    opcode: OpCode,
    pc: u64,
    inputs: usize,
    output_size: usize,
    at_begin: bool,
) -> (PcodeOpRef, Arc<RwLock<Varnode>>) {
    let op = fd.new_op(inputs, Address::new(pc));
    fd.op_set_opcode(&op, opcode);
    let output = fd.new_unique_out(output_size, &op);
    if at_begin {
        fd.op_insert_begin(&op, block);
    } else {
        fd.op_insert_end(&op, block);
    }
    (op, output)
}

fn lane_map(fd: &Funcdata, architecture: &Architecture) -> String {
    fd.lane_accesses()
        .map(|(storage, record)| {
            let identity = architecture
                .lane_records
                .iter()
                .position(|candidate| Arc::ptr_eq(candidate, record))
                .map_or(-1, |index| index as i32);
            format!(
                "{}:{}:{}=r{}:{}:{}",
                storage.space.space_id(),
                storage.offset,
                storage.size,
                identity,
                record.get_whole_size(),
                record.get_size_bit_mask(),
            )
        })
        .collect::<Vec<_>>()
        .join(";")
}

fn run_lane_map(architecture: &Arc<Architecture>) {
    let lookup_a = architecture
        .get_laned_register(Address::new(0x10), 16)
        .unwrap();
    let lookup_b = architecture
        .get_laned_register(Address::new(0xdead), 16)
        .unwrap();
    println!(
        "arch|min={}|sizes={},{}|lookup16={}:{}|same={}|missing12={}",
        architecture.get_minimum_laned_register_size(),
        architecture.lane_records[0].get_whole_size(),
        architecture.lane_records[1].get_whole_size(),
        lookup_a.get_whole_size(),
        lookup_a.get_size_bit_mask(),
        u8::from(Arc::ptr_eq(&lookup_a, &lookup_b)),
        u8::from(
            architecture
                .get_laned_register(Address::new(0), 12)
                .is_none()
        ),
    );

    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 74);
    fd.set_arch(architecture.clone());
    let initial = fd.laned_map.len();
    fd.check_for_laned_register(12, AddressSpace::Register, Address::new(0x20));
    let after_miss = fd.laned_map.len();
    fd.check_for_laned_register(8, AddressSpace::Register, Address::new(0x20));
    fd.check_for_laned_register(16, AddressSpace::Register, Address::new(0x20));
    fd.check_for_laned_register(8, AddressSpace::Unique, Address::new(5));
    let before = lane_map(&fd, architecture);
    let before_generated = fd.laned_map.len();
    fd.set_laned_reg_generated();
    let suppressed = fd.new_op(0, Address::new(0x4100));
    let _ = fd.new_varnode_out(16, Address::new(0x40), &suppressed);
    let after_generated = fd.laned_map.len();
    fd.clear();
    let after_clear = fd.laned_map.len();
    let recorded = fd.new_op(0, Address::new(0x4101));
    let _ = fd.new_varnode_out(16, Address::new(0x40), &recorded);
    let after_reset = lane_map(&fd, architecture);
    fd.clear_laned_access_map();
    println!(
        "map|miss_delta={}|before={before}|generated_delta={}|clear_preserved={after_clear}|reset={after_reset}|explicit_clear={}",
        after_miss - initial,
        after_generated - before_generated,
        fd.laned_map.len(),
    );
}

fn new_function(name: &str, address: u64, architecture: &Arc<Architecture>) -> (Funcdata, Block) {
    let mut fd = Funcdata::new(name, Address::new(address), 0);
    fd.set_arch(architecture.clone());
    let block = fd.create_new_block();
    (fd, block)
}

fn run_piece(architecture: &Arc<Architecture>) {
    let (mut fd, block) = new_function("main_free", 0x4970, architecture);
    let (piece, root) = new_output_op(&mut fd, &block, OpCode::CPUI_PIECE, 0x5000, 2, 4, false);
    let high_input = fd.new_constant(2, 0x1122);
    let low_input = fd.new_constant(2, 0x3344);
    fd.op_set_input(&piece, high_input, 0);
    fd.op_set_input(&piece, low_input, 1);
    let (low, _) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x5001, 2, 2, false);
    fd.op_set_input(&low, root.clone(), 0);
    let zero = fd.new_constant(4, 0);
    fd.op_set_input(&low, zero, 1);
    let (high, _) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x5002, 2, 2, false);
    fd.op_set_input(&high, root.clone(), 0);
    let two = fd.new_constant(4, 2);
    fd.op_set_input(&high, two, 1);
    let before = snapshot(&fd, &block);
    let mut divide = LaneDivide::new(&mut fd, root.clone(), LaneDescription::uniform(4, 2), false);
    let traced = divide.do_trace();
    let mark = root.read().unwrap().is_mark();
    if traced {
        divide.apply(&mut fd);
    }
    let after = snapshot(&fd, &block);
    println!(
        "piece|trace={}|mark={}|before={before}|after={after}|old={},{},{},{},{},{}",
        u8::from(traced),
        u8::from(mark),
        u8::from(piece.0.read().unwrap().is_dead()),
        u8::from(piece.0.read().unwrap().get_out().is_none()),
        low.0.read().unwrap().opcode as i32,
        low.0.read().unwrap().num_input(),
        high.0.read().unwrap().opcode as i32,
        high.0.read().unwrap().num_input(),
    );
}

fn run_multiequal(architecture: &Arc<Architecture>) {
    let (mut fd, block) = new_function("hugehelp", 0x4a00, architecture);
    let (phi, root) = new_output_op(
        &mut fd,
        &block,
        OpCode::CPUI_MULTIEQUAL,
        0x6000,
        2,
        4,
        true,
    );
    let left = fd.new_constant(4, 0x11223344);
    let right = fd.new_constant(4, 0x55667788);
    fd.op_set_input(&phi, left, 0);
    fd.op_set_input(&phi, right, 1);
    let (low, _) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x6001, 2, 2, false);
    fd.op_set_input(&low, root.clone(), 0);
    let zero = fd.new_constant(4, 0);
    fd.op_set_input(&low, zero, 1);
    let (high, _) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x6002, 2, 2, false);
    fd.op_set_input(&high, root.clone(), 0);
    let two = fd.new_constant(4, 2);
    fd.op_set_input(&high, two, 1);
    let before = snapshot(&fd, &block);
    let mut divide = LaneDivide::new(&mut fd, root.clone(), LaneDescription::uniform(4, 2), false);
    let traced = divide.do_trace();
    let mark = root.read().unwrap().is_mark();
    if traced {
        divide.apply(&mut fd);
    }
    let after = snapshot(&fd, &block);
    println!(
        "multiequal|trace={}|mark={}|before={before}|after={after}|old={},{},{},{},{},{}",
        u8::from(traced),
        u8::from(mark),
        u8::from(phi.0.read().unwrap().is_dead()),
        u8::from(phi.0.read().unwrap().get_out().is_none()),
        low.0.read().unwrap().opcode as i32,
        low.0.read().unwrap().num_input(),
        high.0.read().unwrap().opcode as i32,
        high.0.read().unwrap().num_input(),
    );
}

fn run_failure(architecture: &Arc<Architecture>) {
    let (mut fd, block) = new_function("main_init", 0x4960, architecture);
    let (multiply, root) = new_output_op(
        &mut fd,
        &block,
        OpCode::CPUI_INT_MULT,
        0x7000,
        2,
        4,
        false,
    );
    let left = fd.new_constant(4, 3);
    let right = fd.new_constant(4, 7);
    fd.op_set_input(&multiply, left, 0);
    fd.op_set_input(&multiply, right, 1);
    let (low, _) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x7001, 2, 2, false);
    fd.op_set_input(&low, root.clone(), 0);
    let zero = fd.new_constant(4, 0);
    fd.op_set_input(&low, zero, 1);
    let before = snapshot(&fd, &block);
    let mut divide = LaneDivide::new(&mut fd, root.clone(), LaneDescription::uniform(4, 2), false);
    let traced = divide.do_trace();
    let after = snapshot(&fd, &block);
    println!(
        "failure|trace={}|same={}|mark={}|before={before}|after={after}",
        u8::from(traced),
        u8::from(before == after),
        u8::from(root.read().unwrap().is_mark()),
    );
}

fn main() {
    let mut architecture = Architecture::new();
    architecture.set_lane_records(vec![
        LanedRegister::with_sizes(8, 1 << 2),
        LanedRegister::with_sizes(16, (1 << 4) | (1 << 8)),
    ]);
    let architecture = Arc::new(architecture);
    run_lane_map(&architecture);
    run_piece(&architecture);
    run_multiequal(&architecture);
    run_failure(&architecture);
}
