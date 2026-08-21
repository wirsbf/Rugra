//! TRANSFORM-MULTIEQUAL-INSERT-0001 Rugra comparand.

use rugra::address::Address;
use rugra::block::FlowBlock;
use rugra::funcdata::Funcdata;
use rugra::op::PcodeOpRef;
use rugra::opcodes::OpCode;
use rugra::transform::TransformManager;
use rugra::varnode::Varnode;
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::{Arc, RwLock};

type Block = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

fn snapshot(fd: &Funcdata, block: &Block) -> String {
    let ops = block.read().unwrap().get_ops();
    let op_index: HashMap<usize, usize> = ops
        .iter()
        .enumerate()
        .map(|(index, op)| (Arc::as_ptr(&op.0) as usize, index))
        .collect();
    let mut vars: Vec<Arc<RwLock<Varnode>>> = Vec::new();
    let mut var_index: HashMap<usize, usize> = HashMap::new();
    for op in &ops {
        let (output, inputs) = {
            let op = op.0.read().unwrap();
            (op.get_out().cloned(), op.inrefs.clone())
        };
        for varnode in output.into_iter().chain(inputs) {
            let pointer = Arc::as_ptr(&varnode) as usize;
            if let std::collections::hash_map::Entry::Vacant(entry) = var_index.entry(pointer) {
                entry.insert(vars.len());
                vars.push(varnode);
            }
        }
    }
    let var_name = |varnode: Option<&Arc<RwLock<Varnode>>>| {
        varnode.map_or_else(
            || "_".to_string(),
            |varnode| format!("v{}", var_index[&(Arc::as_ptr(varnode) as usize)]),
        )
    };
    let mut output = String::new();
    output.push_str("ops[");
    for (index, op) in ops.iter().enumerate() {
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
            "o{index}:{}/t{}/r{}/p{parent}/o{}/i",
            op.opcode as i32,
            op.start.get_time(),
            op.start.get_order(),
            var_name(op.get_out()),
        )
        .unwrap();
        for (slot, input) in op.inrefs.iter().enumerate() {
            if slot != 0 {
                output.push(',');
            }
            output.push_str(&var_name(Some(input)));
        }
    }
    output.push_str("]vars[");
    for (index, varnode) in vars.iter().enumerate() {
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
        output.push_str("/d");
        let definition = varnode.get_def();
        match definition
            .as_ref()
            .and_then(|op| op_index.get(&(Arc::as_ptr(op) as usize)))
        {
            Some(index) => write!(output, "o{index}").unwrap(),
            None => output.push('_'),
        }
        output.push_str("/u");
        for (use_index, descendant) in varnode.descend_iter().enumerate() {
            if use_index != 0 {
                output.push(',');
            }
            match op_index.get(&(Arc::as_ptr(&descendant) as usize)) {
                Some(index) => write!(output, "o{index}").unwrap(),
                None => output.push('x'),
            }
        }
    }
    write!(
        output,
        "]count={},{},{},{},{},{}",
        ops.len(),
        vars.len(),
        fd.obank.alivelist.len(),
        fd.obank.deadlist.len(),
        fd.obank.optree.len(),
        fd.vbank.num_varnodes(),
    )
    .unwrap();
    output
}

fn new_function(name: &str, address: u64) -> (Funcdata, Block) {
    let mut fd = Funcdata::new(name, Address::new(address), 0);
    let block = fd.create_new_block();
    (fd, block)
}

fn new_anchor(fd: &mut Funcdata, block: &Block, address: u64) -> PcodeOpRef {
    let op = fd.new_op(0, Address::new(address));
    fd.op_set_opcode(&op, OpCode::CPUI_COPY);
    fd.op_insert_end(&op, block);
    op
}

fn wire(
    manager: &mut TransformManager,
    op: usize,
    inputs: usize,
    output_size: i32,
    value_base: u64,
) {
    let output = manager.new_unique(output_size);
    manager.op_set_output(op, output);
    for slot in 0..inputs {
        let input = manager.new_constant(output_size, 0, value_base + slot as u64);
        manager.op_set_input(op, input, slot);
    }
}

fn run_replace(name: &str, address: u64, label: &str, opcode: OpCode, inputs: usize) {
    let (mut fd, block) = new_function(name, address);
    let anchor = new_anchor(&mut fd, &block, 0x8000);
    let mut manager = TransformManager::new();
    manager.init(&mut fd);
    let first = manager.new_op_replace(inputs, opcode, anchor.clone());
    wire(&mut manager, first, inputs, 2, 0x10);
    let second = manager.new_op_replace(inputs, opcode, anchor.clone());
    wire(&mut manager, second, inputs, 2, 0x20);
    manager.apply(&mut fd);
    let anchor_guard = anchor.0.read().unwrap();
    println!(
        "{label}|after={}|anchor={},{}",
        snapshot(&fd, &block),
        u8::from(anchor_guard.is_dead()),
        u8::from(
            anchor_guard
                .parent
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .is_none()
        ),
    );
}

fn run_follow(name: &str, address: u64, label: &str, opcode: OpCode, inputs: usize) {
    let (mut fd, block) = new_function(name, address);
    let anchor = new_anchor(&mut fd, &block, 0x9000);
    let mut manager = TransformManager::new();
    manager.init(&mut fd);
    let follow = manager.new_op_replace(1, OpCode::CPUI_COPY, anchor.clone());
    wire(&mut manager, follow, 1, 2, 0x30);
    let first = manager.new_op(inputs, opcode, follow);
    wire(&mut manager, first, inputs, 2, 0x40);
    let second = manager.new_op(inputs, opcode, follow);
    wire(&mut manager, second, inputs, 2, 0x50);
    manager.apply(&mut fd);
    let anchor_guard = anchor.0.read().unwrap();
    println!(
        "{label}|after={}|anchor={},{}",
        snapshot(&fd, &block),
        u8::from(anchor_guard.is_dead()),
        u8::from(
            anchor_guard
                .parent
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .is_none()
        ),
    );
}

fn main() {
    run_replace("GetStr", 0x36d0, "replace_phi", OpCode::CPUI_MULTIEQUAL, 2);
    run_follow(
        "main_free",
        0x4970,
        "follow_phi",
        OpCode::CPUI_MULTIEQUAL,
        2,
    );
    run_replace("hugehelp", 0x4a00, "replace_copy", OpCode::CPUI_COPY, 1);
    run_follow("main_init", 0x4960, "follow_copy", OpCode::CPUI_COPY, 1);
}
