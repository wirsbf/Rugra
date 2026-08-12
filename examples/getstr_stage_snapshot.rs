//! Emit layered Rugra pipeline snapshots for `GetStr` in `examples/curl`.
//!
//! The locked Ghidra fixture emits the same JSON schema.  This is diagnostic
//! evidence, not a parity claim: the Heritage stage is explicitly a direct
//! Rugra Action replay because Rugra's Action tree has no observation hook yet.

use goblin::Object;
use rugra::action::{Action, ActionDatabase};
use rugra::address::Address;
use rugra::block::{
    edge_flags, type_to_name, BlockCondition, BlockCopy, BlockDoWhile, BlockGraph, BlockIf,
    BlockInfLoop, BlockList, BlockSwitch, BlockWhileDo, FlowBlock,
};
use rugra::coreaction::ActionHeritage;
use rugra::disasm::{Disassembler, X86_64Disassembler};
use rugra::funcdata::Funcdata;
use rugra::op::PcodeOpRef;
use rugra::pcoderaw::PcodeOpRaw;
use rugra::prettyprint::EmitNoMarkup;
use rugra::printc::PrintC;
use rugra::printlanguage::PrintLanguage;
use rugra::type_system::datatype::metatype2string;
use rugra::varnode::Varnode;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

const FUNCTION_NAME: &str = "GetStr";

#[derive(Clone)]
struct FunctionInput {
    name: String,
    address: u64,
    size: usize,
    raw_ops: Vec<PcodeOpRaw>,
    symbols: HashMap<u64, String>,
}

struct SnapshotIds {
    ops: Vec<PcodeOpRef>,
    op_ids: HashMap<usize, u64>,
    varnodes: Vec<Arc<RwLock<Varnode>>>,
    varnode_ids: HashMap<usize, u64>,
}

impl SnapshotIds {
    fn from_funcdata(fd: &Funcdata) -> Self {
        let ops = fd.obank.optree.iter().cloned().collect::<Vec<_>>();
        let op_ids = ops
            .iter()
            .enumerate()
            .map(|(index, op)| (Arc::as_ptr(&op.0) as usize, index as u64))
            .collect::<HashMap<_, _>>();
        let mut ids = Self {
            ops,
            op_ids,
            varnodes: Vec::new(),
            varnode_ids: HashMap::new(),
        };
        let ordered_ops = ids.ops.clone();
        for op in ordered_ops {
            let (output, inputs) = {
                let op_read = op.0.read().expect("PcodeOp read lock");
                (op_read.output.clone(), op_read.inrefs.clone())
            };
            if let Some(output) = output {
                ids.add_varnode(output);
            }
            for input in inputs {
                ids.add_varnode(input);
            }
        }
        for entry in &fd.vbank.loc_tree {
            ids.add_varnode(entry.0.clone());
        }
        ids
    }

    fn add_varnode(&mut self, varnode: Arc<RwLock<Varnode>>) {
        let key = Arc::as_ptr(&varnode) as usize;
        if self.varnode_ids.contains_key(&key) {
            return;
        }
        let id = self.varnodes.len() as u64;
        self.varnode_ids.insert(key, id);
        self.varnodes.push(varnode);
    }

    fn op_id(&self, op: &Arc<RwLock<rugra::op::PcodeOp>>) -> i64 {
        self.op_ids
            .get(&(Arc::as_ptr(op) as usize))
            .copied()
            .map_or(-1, |id| id as i64)
    }

    fn varnode_id(&self, varnode: &Arc<RwLock<Varnode>>) -> i64 {
        self.varnode_ids
            .get(&(Arc::as_ptr(varnode) as usize))
            .copied()
            .map_or(-1, |id| id as i64)
    }
}

fn address_value(space: rugra::space::AddressSpace, offset: u64) -> Value {
    json!({
        "space": space.space_id(),
        "space_name": space.name(),
        "offset": offset,
    })
}

fn op_values(ids: &SnapshotIds) -> Vec<Value> {
    ids.ops
        .iter()
        .enumerate()
        .map(|(index, op)| {
            let op = op.0.read().expect("PcodeOp read lock");
            let parent_block = op
                .parent
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .map(|parent| parent.read().expect("parent block read lock").get_index());
            json!({
                "id": index,
                "address": address_value(rugra::space::AddressSpace::Ram, op.start.addr.as_u64()),
                // Rugra currently collapses Ghidra SeqNum::uniq/time and mutable order.
                // Recording the same field twice exposes this structural mismatch.
                "time": op.start.order,
                "order": op.start.order,
                "opcode": op.opcode as i32,
                "opcode_name": op.opcode.name(),
                "parent_block": parent_block,
                "output": op.output.as_ref().map(|varnode| ids.varnode_id(varnode)),
                "inputs": op.inrefs.iter().map(|varnode| ids.varnode_id(varnode)).collect::<Vec<_>>(),
                "properties": {
                    "dead": op.is_dead(),
                    "call": op.is_call(),
                    "marker": op.is_marker(),
                    "branch": op.is_branch(),
                    "bool_output": op.is_bool_output(),
                    "boolean_flip": op.is_boolean_flip(),
                    "instruction_start": op.is_instruction_start(),
                    "indirect_source": op.is_indirect_source(),
                    "ptr_flow": op.is_ptr_flow(),
                },
            })
        })
        .collect()
}

fn varnode_values(ids: &SnapshotIds) -> Vec<Value> {
    ids.varnodes
        .iter()
        .enumerate()
        .map(|(index, varnode_ref)| {
            let varnode = varnode_ref.read().expect("Varnode read lock");
            let defining_op = varnode
                .def
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .map(|op| ids.op_id(&op));
            let uses = varnode
                .descend
                .iter()
                .filter_map(std::sync::Weak::upgrade)
                .map(|op| ids.op_id(&op))
                .collect::<Vec<_>>();
            let is_space_reference = varnode.is_constant()
                && varnode
                    .descend
                    .iter()
                    .filter_map(std::sync::Weak::upgrade)
                    .any(|op| {
                        let op = op.read().expect("PcodeOp space-input read lock");
                        matches!(
                            op.opcode,
                            rugra::opcodes::OpCode::CPUI_LOAD | rugra::opcodes::OpCode::CPUI_STORE
                        ) && op
                            .inrefs
                            .first()
                            .is_some_and(|input| Arc::ptr_eq(input, varnode_ref))
                    });
            let space_reference = is_space_reference.then_some(varnode.loc.as_u64());
            let iop_reference =
                (varnode.address_space == rugra::space::AddressSpace::Iop).then(|| {
                    ids.op_ids
                        .get(&(varnode.loc.as_u64() as usize))
                        .copied()
                        .expect("Iop varnode does not reference a live PcodeOp")
                });
            let normalized_offset = space_reference
                .or(iop_reference)
                .unwrap_or_else(|| varnode.loc.as_u64());
            let pointer_ref_kind = if space_reference.is_some() {
                Some("space")
            } else if iop_reference.is_some() {
                Some("iop")
            } else {
                None
            };
            let data_type = varnode.v_type.as_ref().map(|data_type| {
                json!({
                    "name": data_type.get_name(),
                    "size": data_type.get_size(),
                    "metatype": metatype2string(data_type.get_metatype()),
                })
            });
            json!({
                "id": index,
                "space": varnode.address_space.space_id(),
                "space_name": varnode.address_space.name(),
                "offset": normalized_offset,
                "space_ref_index": space_reference,
                "pointer_ref_kind": pointer_ref_kind,
                "size": varnode.size,
                "flags": varnode.flags,
                "create_index": varnode.create_index,
                "def": defining_op,
                "uses": uses,
                "type": data_type,
            })
        })
        .collect()
}

fn out_edge_values(block: &dyn FlowBlock) -> Vec<Value> {
    (0..block.size_out())
        .filter_map(|slot| {
            block.get_out(slot).map(|edge| {
                let flags = edge.flags;
                json!({
                    "slot": slot,
                    "target": edge.point.read().expect("edge target read lock").get_index(),
                    "reverse": edge.reverse_index,
                    "loop": flags & edge_flags::F_LOOP_EDGE != 0,
                    "default": flags & edge_flags::F_DEFAULTSWITCH_EDGE != 0,
                    "back": flags & edge_flags::F_BACK_EDGE != 0,
                    "irreducible": flags & edge_flags::F_IRREDUCIBLE_EDGE != 0,
                    "goto": flags & edge_flags::F_GOTO_EDGE != 0,
                })
            })
        })
        .collect()
}

fn in_edge_values(block: &dyn FlowBlock) -> Vec<Value> {
    (0..block.size_in())
        .filter_map(|slot| {
            block.get_in(slot).map(|edge| {
                let flags = edge.flags;
                json!({
                    "slot": slot,
                    "source": edge.point.read().expect("edge source read lock").get_index(),
                    "reverse": edge.reverse_index,
                    "loop": flags & edge_flags::F_LOOP_EDGE != 0,
                    "tree": flags & edge_flags::F_TREE_EDGE != 0,
                    "back": flags & edge_flags::F_BACK_EDGE != 0,
                    "irreducible": flags & edge_flags::F_IRREDUCIBLE_EDGE != 0,
                    "goto": flags & edge_flags::F_GOTO_EDGE != 0,
                })
            })
        })
        .collect()
}

fn block_values(fd: &Funcdata, ids: &SnapshotIds) -> Vec<Value> {
    fd.bblocks
        .blocks
        .iter()
        .map(|block| {
            let block = block.read().expect("basic block read lock");
            let (start, stop) = block
                .as_any()
                .downcast_ref::<rugra::block::BlockBasic>()
                .map_or((Value::Null, Value::Null), |basic| {
                    (
                        address_value(rugra::space::AddressSpace::Ram, basic.start_addr.as_u64()),
                        address_value(
                            rugra::space::AddressSpace::Ram,
                            basic.get_stop_addr().as_u64(),
                        ),
                    )
                });
            json!({
                "index": block.get_index(),
                "type": type_to_name(block.get_type()),
                "flags": block.get_flags(),
                "start": start,
                "stop": stop,
                "ops": block.get_ops().iter().map(|op| ids.op_id(&op.0)).collect::<Vec<_>>(),
                "out_edges": out_edge_values(&*block),
                "in_edges": in_edge_values(&*block),
            })
        })
        .collect()
}

fn structure_node_arc(block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> Value {
    let block = block.read().expect("structure block read lock");
    structure_node(&*block)
}

fn structure_node(block: &dyn FlowBlock) -> Value {
    let mut children = Vec::new();
    if let Some(copy) = block.as_any().downcast_ref::<BlockCopy>() {
        let original = copy.original.read().expect("BlockCopy original read lock");
        children.push(structure_node(&*original));
    } else if let Some(if_block) = block.as_any().downcast_ref::<BlockIf>() {
        children.push(structure_node_arc(&if_block.condition));
        children.push(structure_node_arc(&if_block.if_body));
        if let Some(else_body) = &if_block.else_body {
            children.push(structure_node_arc(else_body));
        }
    } else if let Some(while_block) = block.as_any().downcast_ref::<BlockWhileDo>() {
        children.push(structure_node_arc(&while_block.condition));
        children.push(structure_node_arc(&while_block.body));
    } else if let Some(do_while) = block.as_any().downcast_ref::<BlockDoWhile>() {
        children.push(structure_node_arc(&do_while.condition));
    } else if let Some(infinite) = block.as_any().downcast_ref::<BlockInfLoop>() {
        children.push(structure_node_arc(&infinite.body));
    } else if let Some(list) = block.as_any().downcast_ref::<BlockList>() {
        children.extend(list.children.iter().map(structure_node_arc));
    } else if let Some(condition) = block.as_any().downcast_ref::<BlockCondition>() {
        children.push(structure_node_arc(&condition.first));
        children.push(structure_node_arc(&condition.second));
    } else if let Some(switch) = block.as_any().downcast_ref::<BlockSwitch>() {
        children.push(structure_node_arc(&switch.control));
        children.extend(switch.cases.iter().map(structure_node_arc));
        if let Some(default_case) = &switch.default_case {
            children.push(structure_node_arc(default_case));
        }
    }
    json!({
        "index": block.get_index(),
        "type": type_to_name(block.get_type()),
        "flags": block.get_flags(),
        "children": children,
    })
}

fn structure_graph(graph: &BlockGraph) -> Value {
    json!({
        "index": graph.index,
        "type": "graph",
        "flags": graph.flags,
        "children": graph.blocks.iter().map(structure_node_arc).collect::<Vec<_>>(),
    })
}

#[allow(clippy::too_many_arguments)]
fn snapshot(
    stage: &str,
    fd: &Funcdata,
    include_ops: bool,
    include_varnodes: bool,
    include_blocks: bool,
    include_structure: bool,
    text: Option<&str>,
) -> Value {
    let ids = SnapshotIds::from_funcdata(fd);
    json!({
        "schema": 1,
        "state": "OK",
        "stage": stage,
        "function": {
            "name": fd.name,
            "entry": address_value(rugra::space::AddressSpace::Ram, fd.baseaddr.as_u64()),
            "size": fd.size,
        },
        "ops": if include_ops { op_values(&ids) } else { Vec::new() },
        "varnodes": if include_varnodes { varnode_values(&ids) } else { Vec::new() },
        "blocks": if include_blocks { block_values(fd, &ids) } else { Vec::new() },
        "structure": if include_structure { structure_graph(&fd.sblocks) } else { Value::Null },
        "text": text,
    })
}

fn write_snapshot(
    output_directory: &Path,
    name: &str,
    value: &Value,
) -> Result<(), Box<dyn Error>> {
    let path = output_directory.join(name);
    let bytes = serde_json::to_vec(value)?;
    fs::write(path, [bytes.as_slice(), b"\n"].concat())?;
    Ok(())
}

fn build_funcdata(input: &FunctionInput) -> Funcdata {
    let mut fd = Funcdata::new(&input.name, Address::new(input.address), input.size as i32);
    for (&address, name) in &input.symbols {
        fd.add_symbol(address, name.clone());
    }
    fd.inject_raw_ops(&input.raw_ops);
    fd
}

fn load_input(binary: &Path) -> Result<FunctionInput, Box<dyn Error>> {
    let bytes = fs::read(binary)?;
    let object = Object::parse(&bytes)?;
    let Object::Elf(elf) = object else {
        return Err("GetStr snapshot currently requires an ELF input".into());
    };
    let mut symbols = HashMap::new();
    for symbol in &elf.syms {
        if symbol.st_value == 0 {
            continue;
        }
        if let Some(name) = elf.strtab.get_at(symbol.st_name) {
            if !name.is_empty() {
                symbols.insert(symbol.st_value, name.to_string());
            }
        }
    }
    for symbol in &elf.dynsyms {
        if symbol.st_value == 0 {
            continue;
        }
        if let Some(name) = elf.dynstrtab.get_at(symbol.st_name) {
            if !name.is_empty() {
                symbols.insert(symbol.st_value, name.to_string());
            }
        }
    }
    let symbol = elf
        .syms
        .iter()
        .find(|symbol| {
            symbol.is_function()
                && symbol.st_size > 0
                && elf.strtab.get_at(symbol.st_name) == Some(FUNCTION_NAME)
        })
        .ok_or("GetStr was not found in the ELF symbol table")?;
    let section = elf
        .section_headers
        .iter()
        .find(|section| {
            symbol.st_value >= section.sh_addr
                && symbol.st_value < section.sh_addr.saturating_add(section.sh_size)
        })
        .ok_or("GetStr does not belong to a file-backed ELF section")?;
    let file_offset = section.sh_offset + (symbol.st_value - section.sh_addr);
    let end = file_offset
        .checked_add(symbol.st_size)
        .ok_or("GetStr file range overflow")? as usize;
    let start = file_offset as usize;
    let code = bytes
        .get(start..end)
        .ok_or("GetStr file range lies outside the ELF bytes")?;

    let mut disassembler = X86_64Disassembler::new();
    let instructions = disassembler.disassemble(code, Address::new(symbol.st_value))?;
    let instruction_offsets = instructions
        .iter()
        .map(|instruction| {
            (
                instruction.address.as_u64() - symbol.st_value,
                instruction.length,
            )
        })
        .collect::<Vec<_>>();
    let lifted = rugra::disasm::sleigh_lift::SleighLifter::lift_function(
        code,
        symbol.st_value,
        &instruction_offsets,
    );
    let raw_ops = lifted
        .into_iter()
        .flat_map(|(_, ops)| ops)
        .collect::<Vec<_>>();

    Ok(FunctionInput {
        name: FUNCTION_NAME.to_string(),
        address: symbol.st_value,
        size: symbol.st_size as usize,
        raw_ops,
        symbols,
    })
}

fn run(binary: &Path, output_directory: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(output_directory)?;
    let input = load_input(binary)?;

    let raw_fd = build_funcdata(&input);
    write_snapshot(
        output_directory,
        "00_raw_pcode.json",
        &snapshot("00_raw_pcode", &raw_fd, true, true, false, false, None),
    )?;
    write_snapshot(
        output_directory,
        "01_cfg.json",
        &snapshot("01_cfg", &raw_fd, false, false, true, false, None),
    )?;

    let mut heritage_fd = build_funcdata(&input);
    let mut heritage = ActionHeritage::new();
    heritage.apply(&mut heritage_fd)?;
    write_snapshot(
        output_directory,
        "02_heritage_ssa.json",
        &snapshot(
            "02_heritage_ssa",
            &heritage_fd,
            true,
            true,
            true,
            false,
            None,
        ),
    )?;

    let action_fd = Arc::new(RwLock::new(build_funcdata(&input)));
    action_fd
        .write()
        .expect("Funcdata write lock")
        .set_self_ref(Arc::downgrade(&action_fd));
    let mut actions = ActionDatabase::new();
    actions.set_default_actions();
    if let Some(action) = actions.get_action_mut("decompile") {
        action.apply(&mut action_fd.write().expect("Funcdata action write lock"))?;
    } else {
        return Err("Rugra did not configure the decompile action".into());
    }
    let action_read = action_fd.read().expect("Funcdata snapshot read lock");
    write_snapshot(
        output_directory,
        "03_action_ir.json",
        &snapshot("03_action_ir", &action_read, true, true, true, false, None),
    )?;
    write_snapshot(
        output_directory,
        "04_structure.json",
        &snapshot(
            "04_structure",
            &action_read,
            false,
            false,
            false,
            true,
            None,
        ),
    )?;

    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    printer.set_rpn_enabled(true);
    printer.doc_function(&action_read);
    let output = printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .map_err(|_| "PrintC returned an unexpected emitter type")?;
    let c_text = output.get_output();
    write_snapshot(
        output_directory,
        "05_c.json",
        &snapshot(
            "05_c",
            &action_read,
            false,
            false,
            false,
            false,
            Some(&c_text),
        ),
    )?;
    eprintln!(
        "getstr_stage_snapshot: raw_ops={} action_ops={} output={}",
        input.raw_ops.len(),
        action_read.obank.optree.len(),
        output_directory.display()
    );
    Ok(())
}

fn main() {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    let binary = arguments
        .get(1)
        .map_or_else(|| PathBuf::from("examples/curl"), PathBuf::from);
    let output_directory = arguments.get(2).map_or_else(
        || PathBuf::from("result/pipeline_snapshots/getstr/rugra"),
        PathBuf::from,
    );
    if let Err(error) = run(&binary, &output_directory) {
        eprintln!("getstr_stage_snapshot: {error}");
        std::process::exit(1);
    }
}
