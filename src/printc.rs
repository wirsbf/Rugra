//! C language printing implementation
//!
//! Corresponds to Ghidra's `printc.hh` and `printc.cc`

use crate::fspec::FuncProto;
use crate::funcdata::Funcdata;
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::prettyprint::{Emit, NullEmit};
use crate::printlanguage::PrintLanguage;
use crate::type_system::Datatype;
use crate::type_system::cast::CastStrategyC;
use crate::varnode::Varnode;
use crate::address::SeqNum;
use crate::space::AddressSpace;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

fn sanitize_c_ident(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect()
}

/// Escape a raw string from the binary into a C string literal.
/// Converts control characters to their escape sequences:
/// newline → \n, carriage return → \r, tab → \t, null → \0, etc.
fn escape_c_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"'  => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if c.is_ascii_control() => {
                // Other control chars as hex escape
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            _ => out.push(c),
        }
    }
    out
}

/// Represents a detected struct on the stack frame.
/// When a stack address is passed to a function call (via lea reg, [rsp+X]),
/// it indicates a struct/buffer at that offset.
#[derive(Debug, Clone)]
struct StackStruct {
    /// Name assigned to this struct variable (e.g., "config", "buf")
    name: String,
    /// RSP offset where this struct starts
    base_offset: u64,
    /// Detected or estimated size of the struct  
    size: u64,
    /// Offsets of known fields (relative to base_offset)
    fields: Vec<u64>,
}

/// Printer for the C programming language
///
/// Corresponds to Ghidra's `PrintC` class. This handles the conversion
/// of high-level IR (P-code and Control Flow) into valid C source code.
pub struct PrintC {
    emit: Box<dyn Emit>,
    /// Address → symbol name lookup (borrowed from Funcdata during doc_function)
    symbol_table: HashMap<u64, String>,
    /// Address → string literal lookup (borrowed from Funcdata during doc_function)
    string_table: HashMap<u64, String>,
    /// Function address range for local label detection
    func_start: u64,
    func_end: u64,
    /// Copy propagation map: varnode Arc ptr → root source varnode Arc
    copy_map: HashMap<usize, Arc<RwLock<Varnode>>>,
    /// Defining-op map: output varnode Arc ptr → defining PcodeOp Arc
    def_map: HashMap<usize, Arc<RwLock<PcodeOp>>>,
    /// Value-based defining-op map: (space, offset) → defining PcodeOp Arc
    /// Reliable cross-block: same SSA value has same (space, offset) key.
    value_def_map: HashMap<(crate::space::AddressSpace, u64), Arc<RwLock<PcodeOp>>>,
    /// Track post-return state across blocks
    seen_return: bool,
    /// Block indices that are switch case bodies. BlockIf emit checks this to
    /// avoid extracting case bodies (which would pull `case` labels out of switch).
    case_body_indices: HashSet<i32>,
    /// Track ops that have been inlined into consumers (and should not be emitted as standalone lines)
    inlined_ops: HashSet<SeqNum>,
    /// Track variable names actually used in the emitted code (for declaration pruning)
    used_varnode_names: HashSet<String>,
    /// Track actual types, space and offset of used variables for robust declaration mapping
    used_varnode_types: HashMap<String, (String, crate::space::AddressSpace, u64)>,
    /// If true, we are in the discovery pass (only collecting names, not printing)
    discovery_pass: bool,
    /// Addresses of CALL targets (should not be declared as local variables)
    call_targets: HashSet<u64>,
    /// Varnode Arc pointers that are used as pointers (LOAD/STORE address
    /// or INT_ADD input feeding LOAD/STORE). Precomputed in doc_function
    /// for usage-based type inference in Hungarian naming.
    pointer_varnodes: HashSet<(crate::space::AddressSpace, u64)>,
    /// Inline candidates: Unique-space (space, offset) → defining PcodeOp Arc
    /// Only populated for single-use Unique outputs of non-COPY, non-STORE ops.
    inline_candidates: HashMap<(crate::space::AddressSpace, u64), Arc<RwLock<PcodeOp>>>,
    /// Recursion guard to prevent infinite inlining loops
    inline_depth: u32,
    /// Cast strategy for determining when explicit casts are required
    cast_strategy: CastStrategyC,
    /// Parameter register offset → parameter name mapping
    /// Populated from fd.funcp.parameters in doc_function
    param_names: HashMap<u64, String>,
    /// True when currently emitting an output (LHS) varnode — skip def chain resolution
    is_lhs: bool,
    /// Global set of varnode Arc pointers used as input across ALL blocks
    /// Used for cross-block dead code elimination
    global_used_outputs: HashSet<usize>,
    /// Comparison/boolean ops def map: (space, offset) → comparison/boolean PcodeOp Arc
    /// Unlike value_def_map, this ONLY stores comparison and boolean ops,
    /// so non-comparison writes don't overwrite these entries.
    comparison_def_map: HashMap<(crate::space::AddressSpace, u64), Arc<RwLock<PcodeOp>>>,
    /// Stack frame size detected from `sub rsp, N` pattern.
    /// 0 means no stack frame detected.
    stack_frame_size: u64,
    /// (space, offset) key of the varnode that holds RSP - frame_size.
    /// Used to resolve uVar107 + offset patterns.
    stack_frame_base_key: Option<(crate::space::AddressSpace, u64)>,
    /// Detected structs on the stack (base_offset sorted)
    stack_structs: Vec<StackStruct>,
    /// Block-local register def map: (Register space, offset) → defining PcodeOp.
    /// Tracks the most recent op that writes to each register within the current block.
    /// Preferred over value_def_map for CALL argument resolution to avoid cross-block contamination.
    block_local_reg_defs: HashMap<(crate::space::AddressSpace, u64), Arc<RwLock<PcodeOp>>>,
    /// Current loop nesting depth. >0 means we are inside a while/do-while body.
    /// Used to suppress `continue` statements in non-loop contexts.
    loop_depth: u32,
    /// Set of block addresses that are targets of BRANCH/CBRANCH goto statements.
    /// Used to emit LAB_XXXX: labels at the start of target blocks.
    goto_targets: HashSet<u64>,
}

impl PrintC {
    /// Create a new PrintC instance
    pub fn new(emit: Box<dyn Emit>) -> Self {
        Self {
            emit,
            symbol_table: HashMap::new(),
            string_table: HashMap::new(),
            func_start: 0,
            func_end: 0,
            copy_map: HashMap::new(),
            def_map: HashMap::new(),
            value_def_map: HashMap::new(),
            seen_return: false,
            case_body_indices: HashSet::new(),
            inlined_ops: HashSet::new(),
            used_varnode_names: HashSet::new(),
            used_varnode_types: HashMap::new(),
            discovery_pass: false,
            call_targets: HashSet::new(),
        pointer_varnodes: HashSet::new(),
            inline_candidates: HashMap::new(),
            inline_depth: 0,
            cast_strategy: CastStrategyC::new(4), // promote_size = 4 (x86/x64 int)
            param_names: HashMap::new(),
            is_lhs: false,
            global_used_outputs: HashSet::new(),
            comparison_def_map: HashMap::new(),
            stack_frame_size: 0,
            stack_frame_base_key: None,
            stack_structs: Vec::new(),
            block_local_reg_defs: HashMap::new(),
            loop_depth: 0,
            goto_targets: HashSet::new(),

        }
    }

    /// Take ownership of the internal emitter, consuming the printer.
    /// This allows callers to retrieve the buffered output from emitters
    /// like `EmitNoMarkup`.
    pub fn take_emit(self) -> Box<dyn Emit> {
        self.emit
    }

    /// Emit a single block's operations, with dead code elimination.
    ///
    /// Skips: COPY ops (folded via copy_map), terminal branches (when skip_terminal),
    /// dead flag outputs (not referenced by any other op), and post-return dead code.
    fn emit_block_ops(&mut self, block_arc: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>, skip_terminal: bool) {
        use crate::opcodes::OpCode;
        use std::collections::HashSet;

        let block = block_arc.read().unwrap();
        let ops = block.get_ops();

        // Clear block-local register defs — each block starts fresh
        self.block_local_reg_defs.clear();

        // Build set of "used" varnode pointers: every input of every op is "used"
        // Combine block-local with global cross-block tracking
        let mut used_outputs: HashSet<usize> = self.global_used_outputs.clone();
        for op_ref in &ops {
            let op = op_ref.0.read().unwrap();
            for in_arc in &op.inrefs {
                used_outputs.insert(Arc::as_ptr(in_arc) as usize);
                // Also mark the copy-resolved source as used
                if let Some(resolved) = self.copy_map.get(&(Arc::as_ptr(in_arc) as usize)) {
                    used_outputs.insert(Arc::as_ptr(resolved) as usize);
                }
            }
        }

        for op_ref in &ops {
            let op = op_ref.0.read().unwrap();

            // Update block-local register def map: track last op writing to each register
            if let Some(ref out_arc) = op.output {
                let out_vn = out_arc.read().unwrap();
                if out_vn.get_space() == crate::space::AddressSpace::Register {
                    let key = (out_vn.get_space(), out_vn.get_offset());
                    drop(out_vn);
                    self.block_local_reg_defs.insert(key, op_ref.0.clone());
                }
            }

            // Feature 3: Skip ops after RETURN (global across blocks)
            if self.seen_return {
                continue;
            }
            if op.opcode == OpCode::CPUI_RETURN {
                self.doc_statement(&op);
                self.seen_return = true;
                continue;
            }

            if skip_terminal {
                match op.opcode {
                    OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCH | OpCode::CPUI_BRANCHIND => {
                        // In structured emission (BlockIf/BlockWhile), branches are always
                        // consumed by the structure — skip regardless of branch_type
                        continue;
                    }
                    _ => {}
                }
            }

            // Skip COPY ops (folded via copy_map)
            if op.opcode == OpCode::CPUI_COPY {
                continue;
            }

            // Round 7 Feature 1: Skip ops that have already been inlined into consumers
            if self.inlined_ops.contains(&op.get_seq_num()) {
                continue;
            }

            // Skip RIP-relative INT_ADD ops — they create symbol aliases resolved via Priority 1.5
            if self.get_rip_relative_operand(&op).is_some() {
                continue;
            }

            // Skip INT_SUB(RSP, const) — stack frame setup (e.g., sub rsp, 0x228)
            if self.stack_frame_size > 0 && self.is_stack_frame_setup(&op) {
                continue;
            }

            // Feature 1: Skip dead outputs (flag comparisons not used by anyone)
            // Only skip pure-computation ops (comparisons, boolean ops), not side-effectful ones
            if let Some(ref out_arc) = op.output {
                let out_ptr = Arc::as_ptr(out_arc) as usize;
                if !used_outputs.contains(&out_ptr) {
                    // Skip pure-computation ops whose output is not used by anyone
                    match op.opcode {
                        // Comparisons and boolean ops
                        OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
                        | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS
                        | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL
                        | OpCode::CPUI_BOOL_NOT | OpCode::CPUI_BOOL_AND
                        | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR
                        // Arithmetic ops
                        | OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB
                        | OpCode::CPUI_INT_MULT | OpCode::CPUI_INT_DIV
                        | OpCode::CPUI_INT_SDIV | OpCode::CPUI_INT_REM
                        | OpCode::CPUI_INT_SREM
                        // Bitwise ops
                        | OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR
                        | OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_NOT
                        | OpCode::CPUI_INT_NEG
                        // Shift ops
                        | OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT
                        | OpCode::CPUI_INT_SRIGHT
                        // Extensions and casts
                        | OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT
                        | OpCode::CPUI_SUBPIECE | OpCode::CPUI_PIECE
                        // Loads (no side effects, just reads memory)
                        | OpCode::CPUI_LOAD
                        // COPY already handled above, but just in case
                        | OpCode::CPUI_COPY
                        => continue,
                        _ => {}
                    }
                }
            }

            self.doc_statement(&op);
        }
    }

    /// Check if a block body has no emittable ops (all ops are dead, skipped, or branch-only).
    /// Used to suppress empty `if () {} else {}` blocks.
    fn is_block_body_empty(&self, block_arc: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>) -> bool {
        use crate::opcodes::OpCode;
        let block = block_arc.read().unwrap();
        let ops = block.get_ops();

        // A block ending in CBRANCH/BRANCH/RETURN/CALL is NOT empty — it has
        // control flow that must be emitted. Without this, the block's
        // branch logic (and everything after it) gets silently dropped.
        if let Some(last_op_ref) = ops.last() {
            let last_op = last_op_ref.0.read().unwrap();
            if matches!(last_op.opcode,
                OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCH | OpCode::CPUI_BRANCHIND
                | OpCode::CPUI_RETURN | OpCode::CPUI_CALL | OpCode::CPUI_CALLIND)
            {
                return false;
            }
        }

        for op_ref in &ops {
            let op = op_ref.0.read().unwrap();
            // Skip branches, COPY, phi-nodes, and dead ops — same logic as emit_block_ops
            match op.opcode {
                OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCH | OpCode::CPUI_BRANCHIND
                | OpCode::CPUI_COPY | OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INDIRECT => continue,
                _ => {}
            }
            // Skip RIP-relative
            if self.get_rip_relative_operand(&op).is_some() { continue; }
            // Skip stack frame setup
            if self.stack_frame_size > 0 && self.is_stack_frame_setup(&op) { continue; }
            // Skip inlined ops
            if self.inlined_ops.contains(&op.get_seq_num()) { continue; }
            // Check if output is dead (pure computation with unused output)
            if let Some(ref out_arc) = op.output {
                let out_ptr = Arc::as_ptr(out_arc) as usize;
                if !self.global_used_outputs.contains(&out_ptr) {
                    match op.opcode {
                        OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
                        | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS
                        | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL
                        | OpCode::CPUI_BOOL_NOT | OpCode::CPUI_BOOL_AND
                        | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR
                        | OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB
                        | OpCode::CPUI_INT_MULT | OpCode::CPUI_INT_DIV
                        | OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR
                        | OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_NOT
                        | OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT
                        | OpCode::CPUI_INT_SRIGHT
                        | OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT
                        | OpCode::CPUI_SUBPIECE | OpCode::CPUI_PIECE
                        | OpCode::CPUI_LOAD
                        => continue,
                        _ => {}
                    }
                }
            }
            // If we reach here, this op is emittable
            return false;
        }
        true
    }

    /// Emit a block with structured control flow detection.
    ///
    /// Recursively walks structured block types (`BlockIf`, `BlockWhileDo`,
    /// `BlockList`) produced by `CollapseStructure`. Falls back to flat
    /// statement emission for `BlockBasic` nodes.
    fn emit_block_structured(
        &mut self,
        block_arc: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        graph: &crate::block::BlockGraph,
        emitted: &mut std::collections::HashSet<i32>,
    ) {
        use crate::block::{BlockType, BlockIf, BlockWhileDo, BlockDoWhile, BlockList, BlockCondition, BlockSwitch};

        let block_idx = block_arc.read().unwrap().get_index();
        if emitted.contains(&block_idx) {
            return;
        }
        emitted.insert(block_idx);

        // Skip all emission after RETURN — prevents dead-code blocks from appearing
        if self.seen_return {
            return;
        }

        // Emit label if this block is a goto target
        {
            let block = block_arc.read().unwrap();
            let ops = block.get_ops();
            if let Some(first_op) = ops.first() {
                let addr = first_op.0.read().unwrap().start.addr.as_u64();
                if self.goto_targets.contains(&addr) {
                    self.emit.tag_line(0);
                    self.emit.print(&format!("LAB_{:x}:", addr));
                }
            }
        }

        let block_type = block_arc.read().unwrap().get_type();

        match block_type {
            BlockType::If => {
                // Structured if-then or if-then-else
                let block = block_arc.read().unwrap();
                let if_block = block.as_any().downcast_ref::<BlockIf>();
                if let Some(if_data) = if_block {
                    // Check if bodies have any emittable ops — skip empty if/else blocks
                    let if_body_empty = self.is_block_body_empty(&if_data.if_body);
                    let else_body_empty = if_data.else_body.as_ref()
                        .map_or(true, |eb| self.is_block_body_empty(eb));
                    
                    if if_body_empty && else_body_empty {
                        // Both bodies empty — skip entire if/else, just emit condition block's ops
                        emitted.insert(if_data.if_body.read().unwrap().get_index());
                        if let Some(ref eb) = if_data.else_body {
                            emitted.insert(eb.read().unwrap().get_index());
                        }
                        self.emit_block_ops(&if_data.condition, true);
                    } else if if_body_empty && !else_body_empty && if_data.else_body.is_some() {
                        // if_body is empty, else_body has code.
                        self.emit_block_ops(&if_data.condition, true);
                        emitted.insert(if_data.if_body.read().unwrap().get_index());
                        let else_body = if_data.else_body.as_ref().unwrap();
                        self.emit.tag_line(0);
                        if if_data.negated {
                            // Triangle-reverse + empty false branch: else_body is the true edge.
                            // Emit with the original (un-negated) condition.
                            self.emit.print("if (");
                            self.emit_block_condition(&if_data.condition);
                            self.emit.print(")");
                        } else {
                            // Standard: negate condition → if (!cond) { else_code }
                            let orig_emit = std::mem::replace(&mut self.emit,
                                Box::new(crate::prettyprint::EmitNoMarkup::new()));
                            self.emit_block_condition(&if_data.condition);
                            let cond_text = {
                                let buf = std::mem::replace(&mut self.emit, orig_emit);
                                buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
                                    .map(|b| b.get_output()).unwrap_or_default()
                            };
                            let trimmed = cond_text.trim();
                            let negated_cond = Self::negate_condition_text(trimmed)
                                .unwrap_or_else(|| format!("!({})", trimmed));
                            self.emit.print(&format!("if ({})", negated_cond));
                        }
                        self.emit.begin_block();
                        let else_body_type = else_body.read().unwrap().get_type();
                        if matches!(else_body_type, BlockType::Basic) {
                            emitted.insert(else_body.read().unwrap().get_index());
                            self.emit_block_ops(else_body, true);
                        } else {
                            self.emit_block_structured(else_body, graph, emitted);
                        }
                        self.emit.end_block();
                    } else {
                        // Emit the condition block's non-branch ops
                        self.emit_block_ops(&if_data.condition, true);

                        // Emit: if (condition) — handles both simple and compound conditions
                        // When negated=true (Triangle-reverse), negate the condition textually
                        self.emit.tag_line(0);
                        if if_data.negated {
                            // Capture condition text and negate it
                            let orig_emit = std::mem::replace(&mut self.emit,
                                Box::new(crate::prettyprint::EmitNoMarkup::new()));
                            self.emit_block_condition(&if_data.condition);
                            let cond_text = {
                                let buf = std::mem::replace(&mut self.emit, orig_emit);
                                buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
                                    .map(|b| b.get_output()).unwrap_or_default()
                            };
                            let trimmed = cond_text.trim();
                            let negated_cond = Self::negate_condition_text(trimmed)
                                .unwrap_or_else(|| format!("!({})", trimmed));
                            self.emit.print(&format!("if ({})", negated_cond));
                        } else {
                            self.emit.print("if (");
                            self.emit_block_condition(&if_data.condition);
                            self.emit.print(")");
                        }

                        // Emit true body
                        self.emit.begin_block();
                        let if_body_type = if_data.if_body.read().unwrap().get_type();
                        if matches!(if_body_type, BlockType::Basic) {
                            emitted.insert(if_data.if_body.read().unwrap().get_index());
                            self.emit_block_ops(&if_data.if_body, true);
                        } else {
                            self.emit_block_structured(&if_data.if_body, graph, emitted);
                        }
                        self.emit.end_block();

                        // Emit else body if present and non-empty.
                        // seen_return from the then-branch must NOT suppress the else.
                        if let Some(ref else_body) = if_data.else_body {
                            if !else_body_empty {
                                self.emit.print(" else");
                                self.emit.begin_block();
                                let else_body_type = else_body.read().unwrap().get_type();
                                if matches!(else_body_type, BlockType::Basic) {
                                    emitted.insert(else_body.read().unwrap().get_index());
                                    let saved = self.seen_return;
                                    self.seen_return = false;
                                    self.emit_block_ops(else_body, true);
                                    self.seen_return = saved;
                                } else {
                                    let saved = self.seen_return;
                                    self.seen_return = false;
                                    self.emit_block_structured(else_body, graph, emitted);
                                    self.seen_return = saved;
                                }
                                self.emit.end_block();
                            } else {
                                emitted.insert(else_body.read().unwrap().get_index());
                            }
                        }
                    }
                } else {
                    // Fallback: emit flat
                    self.emit_block_ops(block_arc, false);
                }
            }
            BlockType::WhileDo => {
                // Structured while loop
                let block = block_arc.read().unwrap();
                let while_block = block.as_any().downcast_ref::<BlockWhileDo>();
                if let Some(while_data) = while_block {
                    self.emit.tag_line(0);
                    self.emit.print("while (");
                    self.emit_block_condition(&while_data.condition);
                    self.emit.print(")");

                    self.emit.begin_block();
                    self.loop_depth += 1;
                    self.emit_block_structured(&while_data.body, graph, emitted);
                    self.loop_depth -= 1;
                    self.emit.end_block();
                } else {
                    self.emit_block_ops(block_arc, false);
                }
            }
            BlockType::DoWhile => {
                // Structured do-while loop
                let block = block_arc.read().unwrap();
                let dowhile_block = block.as_any().downcast_ref::<BlockDoWhile>();
                if let Some(_dowhile_data) = dowhile_block {
                    self.emit.tag_line(0);
                    self.emit.print("do ");
                    self.emit.begin_block();
                    // In a do-while loop, the 'condition' block IS the body, but wait:
                    // we merged true_target into cond_idx. Actually, we should just emit the condition block inside the body
                    // because the ops are currently interleaved!
                    // Wait, Ghidra's BlockDoWhile usually has a separate condition block. But for now, we just emit its ops.
                    self.loop_depth += 1;
                    self.emit_block_ops(block_arc, true);
                    self.loop_depth -= 1;
                    self.emit.end_block();
                    
                    self.emit.print(" while (");
                    let ops = block.get_ops();
                    if let Some(last_op_ref) = ops.last() {
                        let last_op = last_op_ref.0.read().unwrap();
                        if let Some(cond_vn) = last_op.get_in(1) {
                            self.emit_condition(&cond_vn);
                        }
                    }
                    self.emit.print(");");
                } else {
                    self.emit_block_ops(block_arc, false);
                }
            }
            BlockType::List => {
                // Sequence of blocks — emit children in order
                let block = block_arc.read().unwrap();
                let list_block = block.as_any().downcast_ref::<BlockList>();
                if let Some(list_data) = list_block {
                    for child in &list_data.children {
                        self.emit_block_structured(child, graph, emitted);
                    }
                } else {
                    self.emit_block_ops(block_arc, false);
                }
            }
            BlockType::Condition => {
                // BlockCondition at top level (not inside a BlockIf/BlockWhile) —
                // Just emit the sub-block ops flat. The individual CBRANCH ops will
                // produce proper `if (cond) goto` statements.
                // Previously this incorrectly emitted `if (compound_cond)` without a body.
                let block = block_arc.read().unwrap();
                if let Some(cond_data) = block.as_any().downcast_ref::<BlockCondition>() {
                    let first = cond_data.first.clone();
                    let second = cond_data.second.clone();
                    drop(block);
                    self.emit_block_structured(&first, graph, emitted);
                    self.emit_block_structured(&second, graph, emitted);
                } else {
                    drop(block);
                    self.emit_block_ops(block_arc, false);
                }
            }
            BlockType::Switch => {
                let block = block_arc.read().unwrap();
                let switch_block = block.as_any().downcast_ref::<BlockSwitch>();
                if let Some(switch_data) = switch_block {
                    // Emit the control block's non-branch ops (e.g. index computation)
                    self.emit_block_ops(&switch_data.control, true);

                    // Print switch header
                    self.emit.tag_line(0);
                    self.emit.print("switch (");
                    if let Some(ref idx_vn_arc) = switch_data.index_varnode {
                        let idx_vn = idx_vn_arc.read().unwrap();
                        let key = (idx_vn.get_space(), idx_vn.get_offset());
                        drop(idx_vn);
                        // If this varnode is in inline_candidates, emit its defining expression
                        // instead of the inlined-away name (which would be empty)
                        if let Some(def_op_arc) = self.inline_candidates.get(&key).cloned()
                            .or_else(|| self.value_def_map.get(&key).cloned())
                        {
                            // Chase through COPY to the real expression
                            let def_op = def_op_arc.read().unwrap();
                            if def_op.opcode == OpCode::CPUI_COPY && !def_op.inrefs.is_empty() {
                                // COPY from something — push the source
                                let src = def_op.inrefs[0].clone();
                                drop(def_op);
                                self.push_varnode(&src.read().unwrap(), None);
                            } else {
                                // Non-trivial expression — inline it
                                let seq = *def_op.get_seq_num();
                                drop(def_op);
                                self.inlined_ops.insert(seq);
                                let def_op2 = def_op_arc.read().unwrap();
                                self.emit_inline_expr(&def_op2);
                            }
                        } else {
                            // Not in inline_candidates — emit normally
                            let idx_vn = idx_vn_arc.read().unwrap();
                            self.push_varnode(&idx_vn, None);
                        }
                    } else {
                        // Fallback 1: search for BRANCHIND's input
                        let mut found_var = false;
                        {
                            let ctrl = switch_data.control.read().unwrap();
                            let ops = ctrl.get_ops();
                            if let Some(last_op_ref) = ops.last() {
                                let last_op = last_op_ref.0.read().unwrap();
                                if last_op.opcode == OpCode::CPUI_BRANCHIND && !last_op.inrefs.is_empty() {
                                    self.push_varnode(&last_op.inrefs[0].read().unwrap(), Some(&last_op));
                                    found_var = true;
                                }
                            }
                            // Fallback 2: for CBRANCH cascade, find the compared non-const operand
                            if !found_var {
                                for op_ref in ops.iter().rev() {
                                    let op = op_ref.0.read().unwrap();
                                    if matches!(op.opcode,
                                        OpCode::CPUI_INT_EQUAL
                                        | OpCode::CPUI_INT_NOTEQUAL
                                        | OpCode::CPUI_INT_LESS
                                        | OpCode::CPUI_INT_SLESS
                                        | OpCode::CPUI_INT_LESSEQUAL
                                        | OpCode::CPUI_INT_SLESSEQUAL)
                                        && op.inrefs.len() >= 2
                                    {
                                        let in0 = op.inrefs[0].read().unwrap();
                                        let in1 = op.inrefs[1].read().unwrap();
                                        if in1.get_space() == crate::space::AddressSpace::Const && in0.get_space() != crate::space::AddressSpace::Const {
                                            drop(in0); drop(in1);
                                            self.push_varnode(&op.inrefs[0].read().unwrap(), Some(&op));
                                            break;
                                        } else if in0.get_space() == crate::space::AddressSpace::Const && in1.get_space() != crate::space::AddressSpace::Const {
                                            drop(in0); drop(in1);
                                            self.push_varnode(&op.inrefs[1].read().unwrap(), Some(&op));
                                            break;
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    self.emit.print(")");

                    // Switch body block
                    self.emit.begin_block();

                    // Print each case block
                    for (idx, case_block) in switch_data.cases.iter().enumerate() {
                        let values = &switch_data.case_values[idx];
                        for val in values {
                            self.emit.tag_line(0);
                            // Format case value: char literal for printable ASCII, else numeric
                            let case_label = if *val >= 0x20 && *val <= 0x7e {
                                let ch = *val as u8 as char;
                                // Escape brace/paren chars to avoid confusing post-process brace counters
                                if matches!(ch, '}' | '{' | ')' | '(' | '\'' | '\\' | '"') || ch == '\0' {
                                    format!("case '\\x{:x}':", *val as u8)
                                } else {
                                    format!("case '{}':", ch)
                                }
                            } else if *val >= 256 {
                                format!("case 0x{:x}:", val)
                            } else {
                                format!("case {}:", val)
                            };
                            self.emit.print(&case_label);
                        }

                        self.emit.begin_block();
                        self.emit_block_structured(case_block, graph, emitted);

                        // If it doesn't end with a return, print break;
                        let is_terminal = {
                            let cb = case_block.read().unwrap();
                            (cb.get_flags() & crate::block::block_flags::RETURN_TERMINAL) != 0
                        };
                        if !is_terminal {
                            self.emit.tag_line(0);
                            self.emit.print("break;");
                        }
                        self.emit.end_block();
                    }

                    // Print default case
                    if let Some(ref def_block) = switch_data.default_case {
                        self.emit.tag_line(0);
                        self.emit.print("default:");
                        self.emit.begin_block();
                        self.emit_block_structured(def_block, graph, emitted);
                        let is_terminal = {
                            let cb = def_block.read().unwrap();
                            (cb.get_flags() & crate::block::block_flags::RETURN_TERMINAL) != 0
                        };
                        if !is_terminal {
                            self.emit.tag_line(0);
                            self.emit.print("break;");
                        }
                        self.emit.end_block();
                    }

                    self.emit.end_block();
                } else {
                    self.emit_block_ops(block_arc, false);
                }
            }
            _ => {
                // BlockBasic or other — flat statement emission
                // Still check for inline CBRANCH pattern as fallback
                let has_cond = {
                    let block = block_arc.read().unwrap();
                    let ops = block.get_ops();
                    ops.last().map_or(false, |op_ref| {
                        let op = op_ref.0.read().unwrap();
                        op.opcode == OpCode::CPUI_CBRANCH
                    })
                };
                let size_out = block_arc.read().unwrap().size_out();

                if has_cond && size_out == 2 {
                    // Check if both branches are empty before emitting
                    // Ghidra convention: out(0) = true edge (taken), out(1) = false edge (fall-through)
                    let true_edge = block_arc.read().unwrap().get_out(0);
                    let false_edge = block_arc.read().unwrap().get_out(1);
                    
                    let true_empty = true_edge.as_ref()
                        .map_or(true, |e| self.is_block_body_empty(&e.point));
                    let false_empty = false_edge.as_ref()
                        .map_or(true, |e| self.is_block_body_empty(&e.point));
                    
                    if true_empty && false_empty {
                        // Both branches empty — emit the condition block ops but skip the if/else
                        self.emit_block_ops(block_arc, true);
                        if let Some(ref te) = true_edge {
                            emitted.insert(te.point.read().unwrap().get_index());
                        }
                        if let Some(ref fe) = false_edge {
                            emitted.insert(fe.point.read().unwrap().get_index());
                        }
                    } else if true_empty && !false_empty {
                        // True branch empty, false has code → negate: if (!cond) { false_code }
                        self.emit_block_ops(block_arc, true);
                        if let Some(ref te) = true_edge {
                            emitted.insert(te.point.read().unwrap().get_index());
                        }

                        self.emit.tag_line(0);
                        // Emit condition to temp buffer for text-based negation
                        let orig_emit = std::mem::replace(&mut self.emit,
                            Box::new(crate::prettyprint::EmitNoMarkup::new()));
                        self.emit_block_condition(block_arc);
                        let cond_text = {
                            let buf = std::mem::replace(&mut self.emit, orig_emit);
                            buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
                                .map(|b| b.get_output()).unwrap_or_default()
                        };
                        let trimmed = cond_text.trim();
                        let negated_cond2 = Self::negate_condition_text(trimmed)
                            .unwrap_or_else(|| format!("!({})", trimmed));
                        self.emit.print(&format!("if ({})", negated_cond2));
                        if let Some(false_block_edge) = false_edge {
                            let false_idx = false_block_edge.point.read().unwrap().get_index();
                            self.emit.begin_block();
                            emitted.insert(false_idx);
                            self.emit_block_ops(&false_block_edge.point, false);
                            self.emit.end_block();
                        }
                    } else {
                        // Legacy inline if/else for blocks not captured by CollapseStructure
                        self.emit_block_ops(block_arc, true);

                        self.emit.tag_line(0);
                        self.emit.print("if (");
                        // Use emit_block_condition for consistent block-local comparison resolution
                        self.emit_block_condition(block_arc);
                        self.emit.print(")");

                        if let Some(true_block_edge) = true_edge {
                            let true_idx = true_block_edge.point.read().unwrap().get_index();
                            self.emit.begin_block();
                            emitted.insert(true_idx);
                            self.emit_block_ops(&true_block_edge.point, false);
                            self.emit.end_block();
                        }

                        if let Some(false_block_edge) = false_edge {
                            let false_idx = false_block_edge.point.read().unwrap().get_index();
                            // The else block is part of the conditional, not sequential code.
                            // seen_return from the then-branch should NOT suppress it.
                            if !emitted.contains(&false_idx) && !false_empty {
                                self.emit.print(" else");
                                self.emit.begin_block();
                                emitted.insert(false_idx);
                                // Temporarily clear seen_return so the else block emits.
                                let saved_seen_return = self.seen_return;
                                self.seen_return = false;
                                self.emit_block_ops(&false_block_edge.point, false);
                                self.seen_return = saved_seen_return;
                                self.emit.end_block();
                            } else {
                                emitted.insert(false_idx);
                            }
                        }
                    }
                } else {
                    self.emit_block_ops(block_arc, false);
                }
            }
        }
    }
    /// Emit a goto label name. Uses `LAB_xxxx` for intra-function addresses,
    /// falls back to symbol lookup then `DAT_xxxx` for external addresses.
    fn push_goto_target(&mut self, vn: &Varnode) {
        let addr = vn.get_offset();
        if let Some(sym_name) = self.symbol_table.get(&addr) {
            self.emit.tag_variable(sym_name, 0);
            return;
        }
        let label = format!("LAB_{:08x}", addr);
        self.emit.tag_variable(&label, 0);
    }

    /// Emit variable declarations at the top of the function body.
    fn doc_variable_decls_from_funcdata(&mut self, _fd: &Funcdata) {
        use std::collections::BTreeMap;
        use crate::space::AddressSpace;

        let mut declared: BTreeMap<String, String> = BTreeMap::new();

        let is_declarable = |name: &str, space: AddressSpace, offset: u64, call_targets: &HashSet<u64>| -> bool {
            if name.is_empty() { return false; }
            if !name.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_') {
                return false;
            }
            if name.starts_with("DAT_") || name.starts_with("LAB_")
                || name.starts_with('"') || name.contains('(')
                || name.starts_with("0x") || name == "argc" || name == "argv"
            {
                return false;
            }
            // Don't declare parameters (they're already in the function signature)
            if name.starts_with("param_") && !name.starts_with("param_stack_") {
                return false;
            }
            // Don't declare function call targets as local variables
            if matches!(space, AddressSpace::Ram | AddressSpace::Const)
                && call_targets.contains(&offset)
            {
                return false;
            }
            // Don't declare RIP/RSP/RBP — they're pseudo/frame registers, not local variables
            // Also don't declare any raw register names — they're architectural temporaries.
            // Don't declare RIP — it's a pseudo register, not a real variable.
            // RSP/RBP and callee-saved (R12-R15, RBX) may appear in expressions
            // when stack-frame analysis is incomplete; declaring them as `long`
            // keeps the output compilable (they are real 8-byte registers).
            if space == AddressSpace::Register {
                // RIP (0x200) is a pseudo register — never declare
                if offset == 0x200 { return false; }
                const DECL_PREFIXES: &[&str] = &[
                    "lVar", "uVar", "iVar", "bVar", "sVar",
                    "piVar", "pcVar", "psVar", "ppVar", "pvVar",
                    "fVar", "dVar",
                ];
                let is_auto_local = DECL_PREFIXES.iter().any(|p| {
                    if let Some(rest) = name.strip_prefix(p) {
                        rest.starts_with(|c: char| c.is_ascii_digit() || c == '_')
                    } else {
                        false
                    }
                });
                if is_auto_local {
                    // Allow declaring variables renamed from registers
                } else {
                    // Callee-saved + frame registers: allow declaration as long
                    // (RSP=0x20, RBP=0x28, RBX=0x18, R12=0xa0..R15=0xb8)
                    const DECL_REG_OFFSETS: &[u64] = &[
                        0x20, 0x28, 0x18, 0xa0, 0xa8, 0xb0, 0xb8,
                    ];
                    if !DECL_REG_OFFSETS.contains(&offset) {
                        // All other raw register names (RAX/RCX/flags) — not declared
                        return false;
                    }
                    // For these, only declare if the name is the raw register name
                    // (RBP, RSP, RBX, R12-R15) — not some other identifier at this offset
                    const RAW_REG_NAMES: &[&str] = &[
                        "RSP", "ESP", "RBP", "EBP", "RBX", "EBX",
                        "R12", "R13", "R14", "R15",
                    ];
                    if !RAW_REG_NAMES.contains(&name) {
                        return false;
                    }
                }
            }
            // Don't declare names that come from the global symbol or string table
            if matches!(space, AddressSpace::Ram | AddressSpace::Const) {
                if call_targets.contains(&offset) {
                    return false;
                }
                // These are global symbols, not local variables
                return false;
            }
            true
        };

        for (name, (type_name, space, offset)) in &self.used_varnode_types {
            if is_declarable(name, *space, *offset, &self.call_targets) {
                let entry = declared.entry(name.clone()).or_insert_with(|| type_name.clone());
                if type_name.contains('*') && !entry.contains('*') {
                    *entry = type_name.clone();
                }
            }
        }

        if !declared.is_empty() {
            for (name, type_name) in &declared {
                self.emit.tag_line(0);
                self.emit.print(&format!("{} {};", type_name, name));
            }
            self.emit.tag_line(0);
            self.emit.print("");
        }
    }

    /// Mark a variable name as used, recording its space, offset, and type
    fn mark_variable_used(&mut self, name: String, space: crate::space::AddressSpace, offset: u64, type_name: String) {
        if name.is_empty() { return; }
        // Filter out expressions (like struct->field or arrays) so we don't emit illegal declarations
        if name.contains("->") || name.contains('.') || name.contains('[') || name.contains('*') || name.contains('&') {
            return;
        }
        self.used_varnode_names.insert(name.clone());
        self.used_varnode_types.insert(name, (type_name, space, offset));
    }

    /// Mark a varnode's display name as used, recording its space, offset, and type
    fn mark_varnode_used(&mut self, name: String, vn: &Varnode) {
        if name.is_empty() { return; }
        let type_name = vn.v_type.as_ref()
            .map(|dt| dt.get_name().to_string())
            .unwrap_or_else(|| "int".to_string());
        self.mark_variable_used(name, vn.get_space(), vn.get_offset(), type_name);
    }

    /// Get the display name for a varnode without emitting it
    fn get_varnode_display_name(&self, vn: &Varnode) -> String {
        use crate::space::AddressSpace;

        let addr = vn.get_offset();
        let space = vn.get_space();
        if matches!(space, AddressSpace::Ram | AddressSpace::Const) {
            if let Some(sym_name) = self.symbol_table.get(&addr) {
                return sym_name.clone();
            }
            if self.string_table.contains_key(&addr) {
                return String::new(); // Don't declare strings
            }
        }

        // Priority 0.5: Parameter names take precedence over HighVariable for Register varnodes
        if vn.get_space() == AddressSpace::Register {
            if let Some(pname) = self.param_names.get(&vn.get_offset()) {
                return pname.clone();
            }
        }

        if let Some(ref high_arc) = vn.high {
            let high = high_arc.read().unwrap();
            let name = high.get_name();
            if !name.is_empty() {
                // Convert raw register names to local variable names
                if Self::is_raw_register_name(name)
                    && name != "RSP" && name != "ESP" && name != "RBP" && name != "EBP"
                {
                    if let Some(pname) = self.param_names.get(&vn.get_offset()) {
                        return pname.clone();
                    }
                    let effective_type = Self::find_typed_instance(&high)
                        .or_else(|| Self::vn_type_if_meaningful(vn))
                        .or_else(|| self.pointer_type_for(vn));
                    let prefix = Self::var_prefix(&effective_type, vn.get_size());
                    return format!("{}_{:x}", prefix, vn.get_offset());
                }
                let effective_type = Self::find_typed_instance(&high)
                    .or_else(|| Self::vn_type_if_meaningful(vn))
                    .or_else(|| self.pointer_type_for(vn));
                return Self::maybe_apply_type_prefix(name, &effective_type, vn.get_size());
            }
        }

        match vn.get_space() {
            AddressSpace::Register => {
                // Check if this register corresponds to a function parameter
                if let Some(pname) = self.param_names.get(&vn.get_offset()) {
                    return pname.clone();
                }
                format!("uVar{:x}", vn.get_offset())
            }
            AddressSpace::Stack => {
                let off = vn.get_offset();
                if off >= 0x8000_0000_0000_0000 {
                    format!("local_{:x}", (!off).wrapping_add(1))
                } else {
                    format!("param_stack_{:x}", off)
                }
            }
            AddressSpace::Unique => {
                let key = (AddressSpace::Unique, vn.get_offset());
                if self.inline_candidates.contains_key(&key) {
                    return String::new();
                }
                format!("uVar_{:x}", vn.get_offset())
            }
            _ => String::new(),
        }
    }

    /// Check if a name is a raw x86-64 register name
    /// Scan all instances of a HighVariable for one with a meaningful
    /// (non-Unknown, non-undefined) type. ActionTypeInfer assigns types to
    /// individual SSA instances, not to the HighVariable as a whole. This
    /// finds the best type across all instances.
    fn find_typed_instance(high: &crate::variable::HighVariable) -> Option<std::sync::Arc<crate::type_system::Datatype>> {
        use crate::type_system::TypeMetatype;
        for inst_arc in &high.instances {
            let inst = inst_arc.read().unwrap();
            if let Some(ref dt) = inst.v_type {
                if dt.get_metatype() != TypeMetatype::Unknown && dt.get_name() != "undefined" {
                    return Some(dt.clone());
                }
            }
        }
        None
    }

    fn vn_type_if_meaningful(vn: &crate::varnode::Varnode) -> Option<std::sync::Arc<crate::type_system::Datatype>> {
        use crate::type_system::TypeMetatype;
        vn.v_type.as_ref()
            .filter(|t| t.get_metatype() != TypeMetatype::Unknown && t.get_name() != "undefined")
            .cloned()
    }

    fn pointer_type_for(&self, vn: &crate::varnode::Varnode) -> Option<std::sync::Arc<crate::type_system::Datatype>> {
        if self.pointer_varnodes.contains(&(vn.get_space(), vn.get_offset())) {
            return self.make_int_ptr();
        }
        if let Some(ref high_arc) = vn.high {
            let high = high_arc.read().unwrap();
            for inst_arc in &high.instances {
                let inst = inst_arc.read().unwrap();
                if self.pointer_varnodes.contains(&(inst.get_space(), inst.get_offset())) {
                    return self.make_int_ptr();
                }
            }
        }
        None
    }

    fn make_int_ptr(&self) -> Option<std::sync::Arc<crate::type_system::Datatype>> {
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
        let int_type = std::sync::Arc::new(Datatype::Base(
            TypeBase::new("int".to_string(), 4, TypeMetatype::Int),
        ));
        Some(std::sync::Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: int_type,
            wordsize: 1,
        })))
    }

    /// Ghidra-style Hungarian notation prefix based on inferred datatype.
    /// Falls back to size-based when no type info is available.
    fn var_prefix(v_type: &Option<std::sync::Arc<crate::type_system::Datatype>>, size: usize) -> &'static str {
        use crate::type_system::{Datatype, TypeMetatype};
        const CHARTYPE: u32 = 1 << 1;
        match v_type {
            Some(dt) => match &**dt {
                Datatype::Pointer(ptr) => {
                    let is_char = matches!(&*ptr.ptr_to, Datatype::Base(b) if (b.flags & CHARTYPE) != 0);
                    if is_char { "pcVar" }
                    else { match &*ptr.ptr_to {
                        Datatype::Base(b) if b.metatype == TypeMetatype::Int || b.metatype == TypeMetatype::Uint => "piVar",
                        Datatype::Struct(_) => "psVar",
                        Datatype::Pointer(_) => "ppVar",
                        _ => "pvVar",
                    }}
                }
                Datatype::Base(b) => {
                    let is_char = (b.flags & CHARTYPE) != 0;
                    if is_char { "cVar" }
                    else { match b.metatype {
                        TypeMetatype::Float if size >= 8 => "dVar",
                        TypeMetatype::Float => "fVar",
                        TypeMetatype::Bool => "bVar",
                        _ => Self::size_prefix(size),
                    }}
                }
                _ => Self::size_prefix(size),
            },
            None => Self::size_prefix(size),
        }
    }

    fn size_prefix(size: usize) -> &'static str {
        match size {
            8 => "lVar",
            4 => "iVar",
            2 => "sVar",
            1 => "bVar",
            _ => "uVar",
        }
    }

    fn maybe_apply_type_prefix(name: &str, v_type: &Option<std::sync::Arc<crate::type_system::Datatype>>, size: usize) -> String {
        use crate::type_system::TypeMetatype;
        let suffix = ["uVar", "lVar", "iVar", "sVar", "bVar"]
            .iter()
            .find_map(|p| name.strip_prefix(p));
        if let Some(suffix) = suffix {
            let has_type = v_type.as_ref().map_or(false, |t| {
                t.get_metatype() != TypeMetatype::Unknown && t.get_name() != "undefined"
            });
            if has_type {
                let new_prefix = Self::var_prefix(v_type, size);
                let old_prefix_len = name.len() - suffix.len();
                if &name[..old_prefix_len] != new_prefix {
                    return format!("{}{}", new_prefix, suffix);
                }
            }
        }
        name.to_string()
    }

    fn is_raw_register_name(name: &str) -> bool {
        matches!(name,
            "RAX" | "EAX" | "AX" | "AL" | "AH"
            | "RCX" | "ECX" | "CX" | "CL"
            | "RDX" | "EDX" | "DX" | "DL"
            | "RBX" | "EBX" | "BX" | "BL"
            | "RSP" | "ESP" | "SP"
            | "RBP" | "EBP" | "BP"
            | "RSI" | "ESI" | "SI" | "SIL"
            | "RDI" | "EDI" | "DI" | "DIL"
            | "R8" | "R8D" | "R8W" | "R8B"
            | "R9" | "R9D" | "R9W" | "R9B"
            | "R10" | "R10D" | "R10W" | "R10B"
            | "R11" | "R11D" | "R11W" | "R11B"
            | "R12" | "R12D" | "R12W" | "R12B"
            | "R13" | "R13D" | "R13W" | "R13B"
            | "R14" | "R14D" | "R14W" | "R14B"
            | "R15" | "R15D" | "R15W" | "R15B"
            | "RIP"
        )
    }

    /// Resolve a varnode through the copy propagation map.
    /// If this varnode is the output of a COPY op, return the root source.
    fn resolve_varnode(&self, vn_arc: &Arc<RwLock<Varnode>>) -> Option<Arc<RwLock<Varnode>>> {
        let ptr = Arc::as_ptr(vn_arc) as usize;
        self.copy_map.get(&ptr).cloned()
    }

    /// Get the meaningful defining op for a varnode using the SSA def chain.
    /// Chases through COPY ops to find the non-trivial definition.
    /// This is the SSA-based replacement for ad-hoc map lookups.
    fn get_defining_op(vn_arc: &Arc<RwLock<Varnode>>) -> Option<Arc<RwLock<PcodeOp>>> {
        let mut current = vn_arc.clone();
        for _ in 0..20 {
            let def_op = {
                let vn = current.read().unwrap();
                vn.def.as_ref().and_then(|w| w.upgrade())
            };
            match def_op {
                Some(op_arc) => {
                    let op = op_arc.read().unwrap();
                    if op.opcode == OpCode::CPUI_COPY && !op.inrefs.is_empty() {
                        // Chase through COPY to the source
                        let src = op.inrefs[0].clone();
                        drop(op);
                        current = src;
                        continue;
                    }
                    drop(op);
                    return Some(op_arc);
                }
                None => return None,
            }
        }
        None
    }

    /// Check if an op is INT_SUB(RSP, const) — the stack frame setup instruction.
    fn is_stack_frame_setup(&self, op: &PcodeOp) -> bool {
        if op.opcode != OpCode::CPUI_INT_SUB || op.inrefs.len() < 2 {
            return false;
        }
        let in0 = op.inrefs[0].read().unwrap();
        let in1 = op.inrefs[1].read().unwrap();
        in0.get_space() == crate::space::AddressSpace::Register
            && in0.get_offset() == 0x20 && in0.get_size() == 8
            && in1.get_space() == crate::space::AddressSpace::Const
            && in1.get_offset() == self.stack_frame_size
    }

    /// Check if an INT_ADD op is RSP + const, and if so, return the stack variable name.
    /// Also handles uVar107 + offset where uVar107 = RSP - frame_size.
    fn get_stack_variable_name(&self, op: &PcodeOp) -> Option<String> {
        if op.opcode != OpCode::CPUI_INT_ADD || op.inrefs.len() < 2 {
            return None;
        }
        if self.stack_frame_size == 0 {
            return None;
        }
        let in0 = op.inrefs[0].read().unwrap();
        let in1 = op.inrefs[1].read().unwrap();
        
        // Case 1: INT_ADD(RSP, const) — direct stack access
        if in0.get_space() == crate::space::AddressSpace::Register
            && in0.get_offset() == 0x20 && in0.get_size() == 8
            && in1.get_space() == crate::space::AddressSpace::Const
        {
            let offset = in1.get_offset();
            
            // Check if this offset falls within a detected struct (IDA-style)
            for ss in &self.stack_structs {
                if offset >= ss.base_offset && offset < ss.base_offset + ss.size {
                    if offset == ss.base_offset {
                        // Exact base: reference to the struct itself
                        return Some(ss.name.clone());
                    } else {
                        // Field access: struct1->field_XX (IDA arrow notation)
                        let field_offset = offset - ss.base_offset;
                        return Some(format!("{}->field_{:x}", ss.name, field_offset));
                    }
                }
            }
            
            // Ghidra convention: local_XX where XX = frame_size - offset
            if offset < self.stack_frame_size {
                return Some(format!("local_{:x}", self.stack_frame_size - offset));
            } else if offset == self.stack_frame_size {
                return Some("local_0".to_string());
            } else {
                // Positive offset beyond frame = parameter area or return address
                return Some(format!("stack_{:x}", offset));
            }
        }
        
        // Case 2: INT_ADD(frame_base, const) where frame_base = RSP - frame_size
        // e.g., uVar107 + 0x218 where uVar107 = RSP - 0x228
        // → equivalent to RSP + (0x218 - 0x228) = RSP - 0x10 → local_10
        if let Some(ref base_key) = self.stack_frame_base_key {
            let in0_key = (in0.get_space(), in0.get_offset());
            if in0_key == *base_key && in1.get_space() == crate::space::AddressSpace::Const {
                let offset = in1.get_offset();
                if offset < self.stack_frame_size {
                    // frame_base + offset = (RSP - frame_size) + offset = RSP + (offset - frame_size)
                    // This is a negative RSP offset = local variable
                    return Some(format!("local_{:x}", self.stack_frame_size - offset));
                } else if offset == self.stack_frame_size {
                    return Some("local_0".to_string());
                } else {
                    // offset > frame_size: (RSP - frame_size) + offset = RSP + (offset - frame_size)
                    let rsp_off = offset - self.stack_frame_size;
                    if rsp_off < self.stack_frame_size {
                        return Some(format!("local_{:x}", self.stack_frame_size - rsp_off));
                    } else {
                        return Some(format!("stack_{:x}", rsp_off));
                    }
                }
            }
        }
        
        None
    }

    /// Check if two condition strings form a tautology when OR'd.
    /// Covers:
    /// - Complementary pairs: "X == Y" / "X != Y", "X < Y" / "X >= Y"
    /// - Subsumption: "X != Y" / "X >= Y" (always true), "X != Y" / "X <= Y"
    /// - Duplicates: "X != Y" / "X != Y" → not a tautology but redundant
    fn is_complementary_condition(left: &str, right: &str) -> bool {
        // Direct complement pairs (guaranteed tautology when OR'd)
        let complementary_pairs: &[(&str, &str)] = &[
            (" == ", " != "),
            (" != ", " == "),
            (" < ",  " >= "),
            (" >= ", " < "),
            (" <= ", " > "),
            (" > ",  " <= "),
            // Subsumption tautologies: != covers everything except ==,
            // >= covers == and >, so != || >= is always true
            (" != ", " >= "),
            (" >= ", " != "),
            (" != ", " <= "),
            (" <= ", " != "),
        ];

        for &(op1, op2) in complementary_pairs {
            if let Some(pos1) = left.find(op1) {
                if let Some(pos2) = right.find(op2) {
                    let left_lhs = &left[..pos1];
                    let left_rhs = &left[pos1 + op1.len()..];
                    let right_lhs = &right[..pos2];
                    let right_rhs = &right[pos2 + op2.len()..];
                    if left_lhs == right_lhs && left_rhs == right_rhs {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Try to negate a comparison expression textually.
    /// E.g., "X == 0" → "X != 0", "X < Y" → "X >= Y"
    /// Returns None if the text doesn't contain a recognized comparison operator.
    fn negate_condition_text(text: &str) -> Option<String> {
        if let Some(pos) = text.find(" == ") {
            Some(format!("{} != {}", &text[..pos], &text[pos + 4..]))
        } else if let Some(pos) = text.find(" != ") {
            Some(format!("{} == {}", &text[..pos], &text[pos + 4..]))
        } else if let Some(pos) = text.find(" < ") {
            Some(format!("{} >= {}", &text[..pos], &text[pos + 3..]))
        } else if let Some(pos) = text.find(" >= ") {
            Some(format!("{} < {}", &text[..pos], &text[pos + 4..]))
        } else if let Some(pos) = text.find(" <= ") {
            Some(format!("{} > {}", &text[..pos], &text[pos + 4..]))
        } else if let Some(pos) = text.find(" > ") {
            Some(format!("{} <= {}", &text[..pos], &text[pos + 3..]))
        } else {
            None
        }
    }

    /// Try to fold a BOOL_OR/BOOL_AND of two comparisons into a single comparison.
    /// E.g., `BOOL_OR(INT_EQUAL(A,B), INT_LESS(A,B))` → emits `A <= B`
    /// Returns true if folding succeeded and the expression was emitted.
    fn try_fold_bool_comparison(&mut self, def_op: &PcodeOp) -> bool {
        if def_op.inrefs.len() < 2 || def_op.opcode != OpCode::CPUI_BOOL_OR {
            return false;
        }

        // Get the defining ops of both BOOL_OR inputs using pointer-based def_map
        // This is more precise than value_def_map which can have collisions
        let in0_ptr = Arc::as_ptr(&def_op.inrefs[0]) as usize;
        let in1_ptr = Arc::as_ptr(&def_op.inrefs[1]) as usize;
        // Also try the copy-resolved source
        let in0_resolved = self.copy_map.get(&in0_ptr)
            .map(|r| Arc::as_ptr(r) as usize).unwrap_or(in0_ptr);
        let in1_resolved = self.copy_map.get(&in1_ptr)
            .map(|r| Arc::as_ptr(r) as usize).unwrap_or(in1_ptr);

        let op0_arc = self.def_map.get(&in0_ptr).cloned()
            .or_else(|| self.def_map.get(&in0_resolved).cloned())
            .or_else(|| {
                let vn = def_op.inrefs[0].read().unwrap();
                let key = (vn.get_space(), vn.get_offset());
                self.value_def_map.get(&key).cloned()
                    .or_else(|| self.inline_candidates.get(&key).cloned())
            })
            // SSA def chain fallback
            .or_else(|| Self::get_defining_op(&def_op.inrefs[0]));
        let op1_arc = self.def_map.get(&in1_ptr).cloned()
            .or_else(|| self.def_map.get(&in1_resolved).cloned())
            .or_else(|| {
                let vn = def_op.inrefs[1].read().unwrap();
                let key = (vn.get_space(), vn.get_offset());
                self.value_def_map.get(&key).cloned()
                    .or_else(|| self.inline_candidates.get(&key).cloned())
            })
            // SSA def chain fallback
            .or_else(|| Self::get_defining_op(&def_op.inrefs[1]));

        let (op0_arc, op1_arc) = match (op0_arc, op1_arc) {
            (Some(a), Some(b)) => (a, b),
            _ => return false,
        };

        let op0 = op0_arc.read().unwrap();
        let op1 = op1_arc.read().unwrap();

        // Both must be binary comparison ops with 2 inputs
        if op0.inrefs.len() < 2 || op1.inrefs.len() < 2 {
            return false;
        }

        // Check that both compare the same operands
        // Strategy 1: exact (space+offset) match
        let op0_a = { let v = op0.inrefs[0].read().unwrap(); (v.get_space(), v.get_offset()) };
        let op0_b = { let v = op0.inrefs[1].read().unwrap(); (v.get_space(), v.get_offset()) };
        let op1_a = { let v = op1.inrefs[0].read().unwrap(); (v.get_space(), v.get_offset()) };
        let op1_b = { let v = op1.inrefs[1].read().unwrap(); (v.get_space(), v.get_offset()) };

        let operands_match = if op0_a == op1_a && op0_b == op1_b {
            true
        } else {
            // Strategy 2: compare by HighVariable display name (cross-SSA-version matching)
            // Two different SSA versions of the same register share the same HighVariable name
            let name_a0 = op0.inrefs[0].read().unwrap().high.as_ref()
                .map(|h| h.read().unwrap().get_name().to_string()).unwrap_or_default();
            let name_a1 = op1.inrefs[0].read().unwrap().high.as_ref()
                .map(|h| h.read().unwrap().get_name().to_string()).unwrap_or_default();
            let name_b0 = op0.inrefs[1].read().unwrap().high.as_ref()
                .map(|h| h.read().unwrap().get_name().to_string()).unwrap_or_default();
            let name_b1 = op1.inrefs[1].read().unwrap().high.as_ref()
                .map(|h| h.read().unwrap().get_name().to_string()).unwrap_or_default();
            !name_a0.is_empty() && !name_b0.is_empty()
                && name_a0 == name_a1 && name_b0 == name_b1
        };
        // Also check swapped operand order: (a,b) vs (b,a)
        let operands_swapped = !operands_match && {
            if op0_a == op1_b && op0_b == op1_a {
                true
            } else {
                let name_a0 = op0.inrefs[0].read().unwrap().high.as_ref()
                    .map(|h| h.read().unwrap().get_name().to_string()).unwrap_or_default();
                let name_b1 = op1.inrefs[1].read().unwrap().high.as_ref()
                    .map(|h| h.read().unwrap().get_name().to_string()).unwrap_or_default();
                let name_b0 = op0.inrefs[1].read().unwrap().high.as_ref()
                    .map(|h| h.read().unwrap().get_name().to_string()).unwrap_or_default();
                let name_a1 = op1.inrefs[0].read().unwrap().high.as_ref()
                    .map(|h| h.read().unwrap().get_name().to_string()).unwrap_or_default();
                !name_a0.is_empty() && !name_b0.is_empty()
                    && name_a0 == name_b1 && name_b0 == name_a1
            }
        };

        if !operands_match && !operands_swapped {
            return false;
        }

        // Determine the folded operator from the combination of comparison opcodes
        // Fix 2: Detect tautological conditions first
        let folded_sym = match (op0.opcode, op1.opcode) {
            // EQ(a,b) || NEQ(a,b) → always true (tautology)
            (OpCode::CPUI_INT_EQUAL, OpCode::CPUI_INT_NOTEQUAL)
            | (OpCode::CPUI_INT_NOTEQUAL, OpCode::CPUI_INT_EQUAL) => {
                let seq0 = *op0.get_seq_num();
                let seq1 = *op1.get_seq_num();
                drop(op0);
                drop(op1);
                self.inlined_ops.insert(seq0);
                self.inlined_ops.insert(seq1);
                self.emit.print("1");
                return true;
            }
            // Swapped-operand tautologies:
            // NEQ(a,b) || LESSEQUAL(b,a) = a!=b || a>=b → always true
            // LESSEQUAL(a,b) || NEQ(b,a) = same
            _ if operands_swapped && matches!(
                (op0.opcode, op1.opcode),
                (OpCode::CPUI_INT_NOTEQUAL, OpCode::CPUI_INT_LESSEQUAL)
                | (OpCode::CPUI_INT_NOTEQUAL, OpCode::CPUI_INT_SLESSEQUAL)
                | (OpCode::CPUI_INT_LESSEQUAL, OpCode::CPUI_INT_NOTEQUAL)
                | (OpCode::CPUI_INT_SLESSEQUAL, OpCode::CPUI_INT_NOTEQUAL)
                // LESS(a,b) || LESSEQUAL(b,a) = a<b || a>=b → always true
                | (OpCode::CPUI_INT_LESS, OpCode::CPUI_INT_LESSEQUAL)
                | (OpCode::CPUI_INT_SLESS, OpCode::CPUI_INT_SLESSEQUAL)
                | (OpCode::CPUI_INT_LESSEQUAL, OpCode::CPUI_INT_LESS)
                | (OpCode::CPUI_INT_SLESSEQUAL, OpCode::CPUI_INT_SLESS)
            ) => {
                let seq0 = *op0.get_seq_num();
                let seq1 = *op1.get_seq_num();
                drop(op0);
                drop(op1);
                self.inlined_ops.insert(seq0);
                self.inlined_ops.insert(seq1);
                self.emit.print("1");
                return true;
            }
            // Duplicate: X(a,b) || X(a,b) → single X(a,b)
            (a, b) if a == b && matches!(a,
                OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
                | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS
                | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL
            ) => {
                let sym = match a {
                    OpCode::CPUI_INT_EQUAL => " == ",
                    OpCode::CPUI_INT_NOTEQUAL => " != ",
                    OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS => " < ",
                    OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL => " <= ",
                    _ => unreachable!(),
                };
                sym
            }
            // EQ || LT → <=
            (OpCode::CPUI_INT_EQUAL, OpCode::CPUI_INT_LESS)
            | (OpCode::CPUI_INT_LESS, OpCode::CPUI_INT_EQUAL) => " <= ",
            (OpCode::CPUI_INT_EQUAL, OpCode::CPUI_INT_SLESS)
            | (OpCode::CPUI_INT_SLESS, OpCode::CPUI_INT_EQUAL) => " <= ",
            _ => return false,
        };

        // Clone the operand arcs from one of the sub-comparisons before dropping the lock
        let operand_a = op0.inrefs[0].clone();
        let operand_b = op0.inrefs[1].clone();
        let seq0 = *op0.get_seq_num();
        let seq1 = *op1.get_seq_num();
        drop(op0);
        drop(op1);

        // Mark the sub-comparisons as inlined (they won't emit as separate lines)
        self.inlined_ops.insert(seq0);
        self.inlined_ops.insert(seq1);

        // Emit: A <= B
        self.push_varnode(&operand_a.read().unwrap(), None);
        self.emit.print(folded_sym);
        self.push_varnode(&operand_b.read().unwrap(), None);
        true
    }

    /// Check if an op is `INT_ADD(RIP, x)` or `INT_ADD(x, RIP)` — a RIP-relative address.
    /// Returns the index of the non-RIP operand if matched.
    /// x86-64 PIC code uses `lea reg, [rip + offset]` which lifts to `INT_ADD(RIP, const)`.
    /// The result is a global address that should be displayed as just the symbol name.
    fn get_rip_relative_operand(&self, op: &PcodeOp) -> Option<usize> {
        use crate::space::AddressSpace;
        if op.opcode != OpCode::CPUI_INT_ADD || op.inrefs.len() < 2 {
            return None;
        }
        // RIP is Register offset 0x200, size 8
        let in0 = op.inrefs[0].read().unwrap();
        if in0.get_space() == AddressSpace::Register && in0.get_offset() == 0x200 && in0.get_size() == 8 {
            return Some(1);
        }
        drop(in0);
        let in1 = op.inrefs[1].read().unwrap();
        if in1.get_space() == AddressSpace::Register && in1.get_offset() == 0x200 && in1.get_size() == 8 {
            return Some(0);
        }
        None
    }

    /// Push an op's input varnode, resolving through the copy chain.
    fn push_input(&mut self, op: &PcodeOp, index: usize) {
        if let Some(in_arc) = op.get_in(index) {
            let resolved = self.resolve_varnode(&in_arc).unwrap_or_else(|| in_arc.clone());
            self.push_varnode(&resolved.read().unwrap(), Some(op));
        }
    }

    /// Push an op's output varnode (no resolution needed for outputs).
    fn push_output(&mut self, op: &PcodeOp) {
        if let Some(out_arc) = op.get_out() {
            self.is_lhs = true;
            self.push_varnode(&out_arc.read().unwrap(), Some(op));
            self.is_lhs = false;
        }
    }

    /// Emit just the RHS expression of a defining op (for expression inlining).
    /// Emits the operation without the `output = ` prefix.
    fn emit_inline_expr(&mut self, def_op: &PcodeOp) {
        match def_op.opcode {
            OpCode::CPUI_INT_ADD | OpCode::CPUI_FLOAT_ADD
            | OpCode::CPUI_INT_SUB | OpCode::CPUI_FLOAT_SUB
            | OpCode::CPUI_INT_MULT | OpCode::CPUI_FLOAT_MULT
            | OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_SDIV | OpCode::CPUI_FLOAT_DIV
            | OpCode::CPUI_INT_REM | OpCode::CPUI_INT_SREM
            | OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR | OpCode::CPUI_INT_XOR
            | OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT
            | OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
            | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS
            | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL
            | OpCode::CPUI_FLOAT_EQUAL | OpCode::CPUI_FLOAT_NOTEQUAL
            | OpCode::CPUI_FLOAT_LESS | OpCode::CPUI_FLOAT_LESSEQUAL
            | OpCode::CPUI_BOOL_AND | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR => {
                // RIP-relative folding: INT_ADD(RIP, x) → just emit x
                if let Some(non_rip_idx) = self.get_rip_relative_operand(def_op) {
                    self.push_input(def_op, non_rip_idx);
                    return;
                }
                // Stack variable folding: INT_ADD(RSP, const) → &local_XX
                if let Some(stack_name) = self.get_stack_variable_name(def_op) {
                    self.mark_variable_used(stack_name.clone(), AddressSpace::Stack, 0, "int".to_string());
                    if !self.discovery_pass {
                        self.emit.print("&");
                        self.emit.tag_variable(&stack_name, 0);
                    }
                    return;
                }

                // Boolean comparison folding: BOOL_OR(EQ(A,B), LT(A,B)) → A <= B
                if self.try_fold_bool_comparison(def_op) {
                    return;
                }

                self.push_input(def_op, 0);
                let op_sym = match def_op.opcode {
                    OpCode::CPUI_INT_EQUAL | OpCode::CPUI_FLOAT_EQUAL => " == ",
                    OpCode::CPUI_INT_NOTEQUAL | OpCode::CPUI_FLOAT_NOTEQUAL => " != ",
                    OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS | OpCode::CPUI_FLOAT_LESS => " < ",
                    OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL | OpCode::CPUI_FLOAT_LESSEQUAL => " <= ",
                    OpCode::CPUI_INT_ADD | OpCode::CPUI_FLOAT_ADD => " + ",
                    OpCode::CPUI_INT_SUB | OpCode::CPUI_FLOAT_SUB => " - ",
                    OpCode::CPUI_INT_MULT | OpCode::CPUI_FLOAT_MULT => " * ",
                    OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_SDIV | OpCode::CPUI_FLOAT_DIV => " / ",
                    OpCode::CPUI_INT_REM | OpCode::CPUI_INT_SREM => " % ",
                    OpCode::CPUI_INT_AND => " & ",
                    OpCode::CPUI_INT_OR => " | ",
                    OpCode::CPUI_INT_XOR | OpCode::CPUI_BOOL_XOR => " ^ ",
                    OpCode::CPUI_INT_LEFT => " << ",
                    OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT => " >> ",
                    OpCode::CPUI_BOOL_AND => " && ",
                    OpCode::CPUI_BOOL_OR => " || ",
                    _ => " op ",
                };
                self.emit.print(op_sym);
                self.push_input(def_op, 1);
            }
            OpCode::CPUI_INT_NOT => { self.emit.print("~"); self.push_input(def_op, 0); }
            OpCode::CPUI_INT_NEG => { self.emit.print("-"); self.push_input(def_op, 0); }
            OpCode::CPUI_BOOL_NOT => {
                // Try to negate textually: emit inner to temp buffer
                let orig_emit = std::mem::replace(&mut self.emit,
                    Box::new(crate::prettyprint::EmitNoMarkup::new()));
                self.push_input(def_op, 0);
                let inner_text = {
                    let buf = std::mem::replace(&mut self.emit, orig_emit);
                    buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
                        .map(|b| b.get_output()).unwrap_or_default()
                };
                let trimmed = inner_text.trim();
                let negated = if let Some(pos) = trimmed.find(" == ") {
                    Some(format!("{} != {}", &trimmed[..pos], &trimmed[pos + 4..]))
                } else if let Some(pos) = trimmed.find(" != ") {
                    Some(format!("{} == {}", &trimmed[..pos], &trimmed[pos + 4..]))
                } else if let Some(pos) = trimmed.find(" < ") {
                    Some(format!("{} >= {}", &trimmed[..pos], &trimmed[pos + 3..]))
                } else if let Some(pos) = trimmed.find(" >= ") {
                    Some(format!("{} < {}", &trimmed[..pos], &trimmed[pos + 4..]))
                } else if let Some(pos) = trimmed.find(" <= ") {
                    Some(format!("{} > {}", &trimmed[..pos], &trimmed[pos + 4..]))
                } else if let Some(pos) = trimmed.find(" > ") {
                    Some(format!("{} <= {}", &trimmed[..pos], &trimmed[pos + 3..]))
                } else {
                    None
                };
                if let Some(neg) = negated {
                    self.emit.print(&neg);
                } else {
                    self.emit.print("!(");
                    self.emit.print(trimmed);
                    self.emit.print(")");
                }
            }
            OpCode::CPUI_INT_ZEXT => {
                let cast_name = def_op.output.as_ref()
                    .and_then(|out| out.read().unwrap().v_type.as_ref().map(|t| t.get_name().to_string()))
                    .unwrap_or_else(|| "uint".to_string());
                self.emit.print(&format!("({})", cast_name));
                self.push_input(def_op, 0);
            }
            OpCode::CPUI_INT_SEXT => {
                let cast_name = def_op.output.as_ref()
                    .and_then(|out| out.read().unwrap().v_type.as_ref().map(|t| t.get_name().to_string()))
                    .unwrap_or_else(|| "int".to_string());
                self.emit.print(&format!("({})", cast_name));
                self.push_input(def_op, 0);
            }
            OpCode::CPUI_LOAD => {
                // Struct field access: LOAD(RAM, INT_ADD(ptr, const_offset)) → ptr->field_XX
                if def_op.inrefs.len() >= 2 {
                    let addr_arc = &def_op.inrefs[1];
                    let addr_vn = addr_arc.read().unwrap();
                    let addr_key = (addr_vn.get_space(), addr_vn.get_offset());
                    drop(addr_vn);

                    let addr_def_opt = self.value_def_map.get(&addr_key).cloned()
                        .or_else(|| {
                            let ptr = Arc::as_ptr(addr_arc) as usize;
                            self.def_map.get(&ptr).cloned()
                        })
                        .or_else(|| {
                            self.inline_candidates.get(&addr_key).cloned()
                        })
                        .or_else(|| {
                            let resolved = self.resolve_varnode(addr_arc).unwrap_or_else(|| addr_arc.clone());
                            let rkey = { let rv = resolved.read().unwrap(); (rv.get_space(), rv.get_offset()) };
                            self.value_def_map.get(&rkey).cloned()
                                .or_else(|| self.inline_candidates.get(&rkey).cloned())
                        })
                        .or_else(|| Self::get_defining_op(addr_arc));

                    let mut emitted_as_field = false;
                    if let Some(addr_def_arc) = addr_def_opt {
                        let addr_def = addr_def_arc.read().unwrap();
                        if addr_def.opcode == OpCode::CPUI_INT_ADD && addr_def.inrefs.len() >= 2 {
                            let in0 = addr_def.inrefs[0].read().unwrap();
                            let in1 = addr_def.inrefs[1].read().unwrap();
                            // Pattern: INT_ADD(ptr, const_offset) — ptr can be any space
                            if in1.get_space() == AddressSpace::Const
                                && in0.get_space() != AddressSpace::Const
                                // But not RSP/RBP (stack frame) — those are already handled by get_stack_variable_name
                                && !(in0.get_space() == AddressSpace::Register
                                     && (in0.get_offset() == 0x20 || in0.get_offset() == 0x28))
                            {
                                let offset = in1.get_offset();
                                let ptr_arc = addr_def.inrefs[0].clone();
                                drop(in0); drop(in1); drop(addr_def);
                                // Emit: *ptr->field_XX  (dereference struct pointer field)
                                self.push_varnode(&ptr_arc.read().unwrap(), None);
                                if !self.discovery_pass {
                                    self.emit.print(&format!("->field_{:x}", offset));
                                }
                                emitted_as_field = true;
                            }
                        }
                    }

                    if !emitted_as_field {
                        // Standard typed dereference
                        let addr_type_name = def_op.inrefs[1].read().unwrap().v_type.as_ref()
                            .and_then(|t| if matches!(t.as_ref(), Datatype::Pointer(_)) { Some(t.get_name().to_string()) } else { None });
                        if let Some(ref ptr_name) = addr_type_name {
                            self.emit.print(&format!("*(({} *)", ptr_name.trim_end_matches(" *")));
                            self.push_input(def_op, 1);
                            self.emit.print(")");
                        } else {
                            // *(long *)addr — default cast so *addr is legal C even
                            // when addr was inferred as a non-pointer scalar.
                            self.emit.print("*(long *)");
                            self.push_input(def_op, 1);
                        }
                    }
                } else {
                    // *(long *)addr — default cast form for bare LOAD address.
                    self.emit.print("*(long *)");
                    self.push_input(def_op, 1);
                }
            }
            OpCode::CPUI_CALL => {
                if let Some(in0) = def_op.get_in(0) {
                    let target_vn = in0.read().unwrap();
                    let target_addr = target_vn.get_offset();
                    let target_space = target_vn.get_space();
                    drop(target_vn);
                    if let Some(sym_name) = self.symbol_table.get(&target_addr) {
                        if !self.discovery_pass {
                            self.emit.tag_variable(sym_name, 0);
                        }
                    } else {
                        let fun_name = format!("FUN_{:08x}", target_addr);
                        self.mark_variable_used(fun_name.clone(), target_space, target_addr, "long".to_string());
                        if !self.discovery_pass {
                            self.emit.tag_variable(&fun_name, 0);
                        }
                    }
                }
                self.emit.open_paren();
                for i in 1..def_op.num_input() {
                    if i > 1 { self.emit.print(", "); }
                    if let Some(vn) = def_op.get_in(i) {
                        self.push_varnode(&vn.read().unwrap(), Some(def_op));
                    }
                }
                self.emit.close_paren();
            }
            _ => {
                // Fallback: emit as variable name (don't inline unknown ops)
                if let Some(ref out_arc) = def_op.output {
                    let out_vn = out_arc.read().unwrap();
                    let name = format!("uVar_{:x}", out_vn.get_offset());
                    self.mark_varnode_used(name.clone(), &out_vn);
                    if !self.discovery_pass {
                        self.emit.tag_variable(&name, 0);
                    }
                }
            }
        }
    }

    /// Emit a condition expression from a block that may be a `BlockCondition`.
    ///
    /// If the block is a `BlockCondition`, recursively emits `(a) && (b)` or `(a) || (b)`.
    /// Otherwise, reads the last CBRANCH's condition input and emits it via `emit_condition`.
    fn emit_block_condition(
        &mut self,
        block_arc: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) {
        use crate::block::{BlockType, BlockCondition, BoolOp};

        let block_type = block_arc.read().unwrap().get_type();

        if block_type == BlockType::Condition {
            let block = block_arc.read().unwrap();
            if let Some(cond_data) = block.as_any().downcast_ref::<BlockCondition>() {
                let op_str = match cond_data.op_type {
                    BoolOp::And => " && ",
                    BoolOp::Or => " || ",
                };
                let first = cond_data.first.clone();
                let second = cond_data.second.clone();
                let is_or = matches!(cond_data.op_type, BoolOp::Or);
                drop(block);

                // For OR patterns, check for tautologies first
                if is_or {
                    // Emit each side to temp buffers
                    let orig_emit = std::mem::replace(&mut self.emit,
                        Box::new(crate::prettyprint::EmitNoMarkup::new()));
                    self.emit_block_condition(&first);
                    let left_text = {
                        let buf = std::mem::replace(&mut self.emit,
                            Box::new(crate::prettyprint::EmitNoMarkup::new()));
                        buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
                            .map(|b| b.get_output()).unwrap_or_default()
                    };
                    self.emit_block_condition(&second);
                    let right_text = {
                        let buf = std::mem::replace(&mut self.emit, orig_emit);
                        buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
                            .map(|b| b.get_output()).unwrap_or_default()
                    };

                    // Strip outer parens for comparison: "(X == 1)" → "X == 1"
                    let left_bare = left_text.trim().trim_start_matches('(').trim_end_matches(')').trim();
                    let right_bare = right_text.trim().trim_start_matches('(').trim_end_matches(')').trim();

                    if Self::is_complementary_condition(left_bare, right_bare) {
                        self.emit.print("1");
                        return;
                    }

                    // Not a tautology — emit normally with the captured text
                    self.emit.print("(");
                    self.emit.print(&left_text);
                    self.emit.print(")");
                    self.emit.print(op_str);
                    self.emit.print("(");
                    self.emit.print(&right_text);
                    self.emit.print(")");
                    return;
                }

                self.emit.print("(");
                self.emit_block_condition(&first);
                self.emit.print(")");
                self.emit.print(op_str);
                self.emit.print("(");
                self.emit_block_condition(&second);
                self.emit.print(")");
                return;
            }
        }

        // Simple block: read last CBRANCH's condition varnode and look for its defining comparison
        let block = block_arc.read().unwrap();
        let ops = block.get_ops();
        if let Some(last_op_ref) = ops.last() {
            // Extract condition varnode and drop the CBRANCH lock before mutating self
            let cond_vn_opt = {
                let last_op = last_op_ref.0.read().unwrap();
                last_op.get_in(1).map(|arc| arc.clone())
            };
            if let Some(cond_vn) = cond_vn_opt {
                // Strategy: scan the block's ops (excluding CBRANCH) for a comparison/boolean
                // whose output has the same (space, offset) as the condition varnode.
                let cond_key = {
                    let cv = cond_vn.read().unwrap();
                    (cv.get_space(), cv.get_offset())
                };
                for op_ref in &ops[..ops.len().saturating_sub(1)] {
                    let op = op_ref.0.read().unwrap();
                    if let Some(ref out_arc) = op.output {
                        let out_vn = out_arc.read().unwrap();
                        let out_key = (out_vn.get_space(), out_vn.get_offset());
                        if out_key == cond_key {
                            match op.opcode {
                                OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
                                | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS
                                | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL
                                | OpCode::CPUI_BOOL_NOT | OpCode::CPUI_BOOL_AND
                                | OpCode::CPUI_BOOL_OR => {
                                    let cond_ptr = Arc::as_ptr(&cond_vn) as usize;
                                    drop(out_vn);
                                    drop(op);
                                    self.def_map.insert(cond_ptr, op_ref.0.clone());
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                drop(block);
                self.emit_condition(&cond_vn);
            }
        }
    }

    /// Emit a condition expression, inlining comparisons.
    ///
    /// Uses `def_map` to trace the defining op for any varnode (cross-block).
    /// Resolves through copy chains, then inlines:
    /// - `BOOL_NOT(a == b)` → `a != b`
    /// - `a == b` → `a == b` (direct comparison)
    /// - `a || b` / `a && b` → inlined boolean expr
    fn emit_condition(&mut self, cond_arc: &Arc<RwLock<Varnode>>) {
        // Resolve through copy chain first
        let resolved = self.resolve_varnode(cond_arc).unwrap_or_else(|| cond_arc.clone());
        let resolved_ptr = Arc::as_ptr(&resolved) as usize;
        let vn_key = {
            let resolved_vn = resolved.read().unwrap();
            (resolved_vn.get_space(), resolved_vn.get_offset())
        };

        // Strategy 0: SSA def chain (ground truth from Heritage)
        // Use Varnode.def to chase through COPY chain to the meaningful defining op.
        // This is the most reliable strategy since it uses the actual SSA graph.
        let mut def_op_arc = Self::get_defining_op(cond_arc);
        
        // If SSA def didn't find anything, or found a non-comparison op,
        // check if it's a comparison/boolean op (which is what we need for conditions).
        if let Some(ref arc) = def_op_arc {
            let op = arc.read().unwrap();
            match op.opcode {
                OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
                | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS
                | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL
                | OpCode::CPUI_BOOL_NOT | OpCode::CPUI_BOOL_AND
                | OpCode::CPUI_BOOL_OR | OpCode::CPUI_MULTIEQUAL => {
                    // Good — it's a comparison/boolean/phi, keep it
                }
                _ => {
                    // Not a comparison — clear so we fall through to ad-hoc maps
                    drop(op);
                    def_op_arc = None;
                }
            }
        }

        // Fallback strategies using ad-hoc maps (for cases where SSA def is incomplete):
        // 1. Original varnode Arc pointer → def_map (most precise)
        // 2. Copy-resolved Arc pointer → def_map  
        // 3. Value-based (space, offset) → value_def_map (may have collisions)
        // 4. inline_candidates
        let original_ptr = Arc::as_ptr(cond_arc) as usize;
        let mut lookup_key = vn_key;
        
        if def_op_arc.is_none() {
            // Try pointer-based lookup first (more precise than value-based)
            if let Some(arc) = self.def_map.get(&original_ptr).cloned()
                .or_else(|| self.def_map.get(&resolved_ptr).cloned())
            {
                let op = arc.read().unwrap();
                if op.opcode == OpCode::CPUI_COPY && !op.inrefs.is_empty() {
                    // Chase through COPY chain
                    let (s, o) = {
                        let in_vn = op.inrefs[0].read().unwrap();
                        (in_vn.get_space(), in_vn.get_offset())
                    };
                    lookup_key = (s, o);
                    drop(op);
                    // Continue to value-based chase below
                } else {
                    drop(op);
                    def_op_arc = Some(arc);
                }
            }
        }
        
        // If pointer-based didn't find a non-COPY def, chase via value_def_map
        if def_op_arc.is_none() {
            for _ in 0..20 {
                let found = self.value_def_map.get(&lookup_key).cloned()
                    .or_else(|| self.inline_candidates.get(&lookup_key).cloned());
                match found {
                    Some(arc) => {
                        let op = arc.read().unwrap();
                        if op.opcode == OpCode::CPUI_COPY && !op.inrefs.is_empty() {
                            let in_vn = op.inrefs[0].read().unwrap();
                            lookup_key = (in_vn.get_space(), in_vn.get_offset());
                            continue;
                        }
                        drop(op);
                        def_op_arc = Some(arc);
                        break;
                    }
                    None => break,
                }
            }
        }
        
        // Final fallback: try comparison_def_map which only stores comparison/boolean ops
        // This handles cases where value_def_map was overwritten by a later non-comparison op
        if def_op_arc.is_none() {
            // Try resolved key first, then original (unresolved) key
            let original_key = {
                let orig_vn = cond_arc.read().unwrap();
                (orig_vn.get_space(), orig_vn.get_offset())
            };
            if let Some(arc) = self.comparison_def_map.get(&vn_key).cloned()
                .or_else(|| self.comparison_def_map.get(&original_key).cloned())
                .or_else(|| self.comparison_def_map.get(&lookup_key).cloned())
            {
                def_op_arc = Some(arc);
            }
        }

        if let Some(def_op_arc) = def_op_arc {
            let def_op = def_op_arc.read().unwrap();

            // Round 7 Feature 2: Trace through MULTIEQUAL (phi-nodes)
            if def_op.opcode == OpCode::CPUI_MULTIEQUAL && !def_op.inrefs.is_empty() {
                // For a phi-merge of boolean conditions, try tracing through the first input
                // that has a defining comparison.
                let first_in = def_op.inrefs[0].clone();
                drop(def_op);
                self.emit_condition(&first_in);
                return;
            }

            // Case 1: BOOL_NOT(x) — negate the inner comparison
            if def_op.opcode == OpCode::CPUI_BOOL_NOT && def_op.inrefs.len() == 1 {
                let inner_arc = def_op.inrefs[0].clone();
                let inner_resolved = self.resolve_varnode(&inner_arc).unwrap_or_else(|| inner_arc.clone());
                let inner_key = {
                    let inner_vn = inner_resolved.read().unwrap();
                    (inner_vn.get_space(), inner_vn.get_offset())
                };
                let inner_ptr = Arc::as_ptr(&inner_resolved) as usize;

                let inner_def = self.value_def_map.get(&inner_key).cloned()
                    .or_else(|| self.def_map.get(&inner_ptr).cloned());

                if let Some(inner_def_arc) = inner_def {
                    let inner_def_op = inner_def_arc.read().unwrap();
                    let negated_sym = match inner_def_op.opcode {
                        OpCode::CPUI_INT_EQUAL => Some(" != "),
                        OpCode::CPUI_INT_NOTEQUAL => Some(" == "),
                        OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS => Some(" >= "),
                        OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL => Some(" > "),
                        _ => None,
                    };
                    if let Some(sym) = negated_sym {
                        if inner_def_op.inrefs.len() >= 2 {
                            // Mark both NOT and inner Comparison as inlined
                            self.inlined_ops.insert(*def_op.get_seq_num());
                            self.inlined_ops.insert(*inner_def_op.get_seq_num());

                            let a = self.resolve_varnode(&inner_def_op.inrefs[0]).unwrap_or_else(|| inner_def_op.inrefs[0].clone());
                            let b = self.resolve_varnode(&inner_def_op.inrefs[1]).unwrap_or_else(|| inner_def_op.inrefs[1].clone());
                            self.push_varnode(&a.read().unwrap(), None);
                            self.emit.print(sym);
                            self.push_varnode(&b.read().unwrap(), None);
                            return;
                        }
                    }
                }
                // Fallback: emit the inner condition and try to negate textually
                self.inlined_ops.insert(*def_op.get_seq_num());
                drop(def_op);

                // Emit inner to temp buffer
                let orig_emit = std::mem::replace(&mut self.emit,
                    Box::new(crate::prettyprint::EmitNoMarkup::new()));
                self.emit_condition(&inner_arc);
                let inner_text = {
                    let buf = std::mem::replace(&mut self.emit, orig_emit);
                    buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
                        .map(|b| b.get_output()).unwrap_or_default()
                };

                // Try to negate the comparison textually
                let trimmed = inner_text.trim();
                let negated = if let Some(pos) = trimmed.find(" == ") {
                    Some(format!("{} != {}", &trimmed[..pos], &trimmed[pos + 4..]))
                } else if let Some(pos) = trimmed.find(" != ") {
                    Some(format!("{} == {}", &trimmed[..pos], &trimmed[pos + 4..]))
                } else if let Some(pos) = trimmed.find(" < ") {
                    Some(format!("{} >= {}", &trimmed[..pos], &trimmed[pos + 3..]))
                } else if let Some(pos) = trimmed.find(" >= ") {
                    Some(format!("{} < {}", &trimmed[..pos], &trimmed[pos + 4..]))
                } else if let Some(pos) = trimmed.find(" <= ") {
                    Some(format!("{} > {}", &trimmed[..pos], &trimmed[pos + 4..]))
                } else if let Some(pos) = trimmed.find(" > ") {
                    Some(format!("{} <= {}", &trimmed[..pos], &trimmed[pos + 3..]))
                } else {
                    None
                };

                if let Some(neg) = negated {
                    self.emit.print(&neg);
                } else {
                    self.emit.print("!(");
                    self.emit.print(trimmed);
                    self.emit.print(")");
                }
                return;
            }

            // Case 2: Direct comparison or boolean combinator
            if def_op.inrefs.len() >= 2 {
                let cmp_sym = match def_op.opcode {
                    OpCode::CPUI_INT_EQUAL => Some(" == "),
                    OpCode::CPUI_INT_NOTEQUAL => Some(" != "),
                    OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS => Some(" < "),
                    OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL => Some(" <= "),
                    OpCode::CPUI_BOOL_OR => Some(" || "),
                    OpCode::CPUI_BOOL_AND => Some(" && "),
                    _ => None,
                };
                if let Some(sym) = cmp_sym {
                    // Mark comparison/combinator as inlined
                    self.inlined_ops.insert(*def_op.get_seq_num());

                    // For BOOL_OR/BOOL_AND: try fold first (e.g., BOOL_OR(EQ, LT) → <=),
                    // then recursively resolve operands as conditions
                    if def_op.opcode == OpCode::CPUI_BOOL_OR || def_op.opcode == OpCode::CPUI_BOOL_AND {
                        let a_arc = def_op.inrefs[0].clone();
                        let b_arc = def_op.inrefs[1].clone();
                        let bool_opcode = def_op.opcode;
                        // Try folding first (e.g., EQ || LT → <=)
                        if self.try_fold_bool_comparison(&def_op) {
                            return;
                        }
                        drop(def_op);

                        // Fallback tautology detection: emit each side to temp buffer,
                        // then check if they form a complementary pair
                        if bool_opcode == OpCode::CPUI_BOOL_OR {
                            // Save current emit state and emit to temp buffers
                            let orig_emit = std::mem::replace(&mut self.emit,
                                Box::new(crate::prettyprint::EmitNoMarkup::new()));
                            self.emit_condition(&a_arc);
                            let left_text = {
                                let buf = std::mem::replace(&mut self.emit,
                                    Box::new(crate::prettyprint::EmitNoMarkup::new()));
                                buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
                                    .map(|b| b.get_output()).unwrap_or_default()
                            };
                            self.emit_condition(&b_arc);
                            let right_text = {
                                let buf = std::mem::replace(&mut self.emit, orig_emit);
                                buf.into_any().downcast::<crate::prettyprint::EmitNoMarkup>()
                                    .map(|b| b.get_output()).unwrap_or_default()
                            };

                            // Check complementary patterns:
                            // "X == Y" || "X != Y" → always true
                            // "X < Y"  || "X >= Y" → always true
                            // "X <= Y" || "X > Y"  → always true
                            let is_tautology = Self::is_complementary_condition(
                                left_text.trim(), right_text.trim());

                            if is_tautology {
                                self.emit.print("1");
                                return;
                            }

                            // Not a tautology — emit normally
                            self.emit.print(&left_text);
                            self.emit.print(sym);
                            self.emit.print(&right_text);
                            return;
                        }

                        // Can't fold — emit each side as a condition recursively
                        self.emit_condition(&a_arc);
                        self.emit.print(sym);
                        self.emit_condition(&b_arc);
                        return;
                    }

                    let a = self.resolve_varnode(&def_op.inrefs[0]).unwrap_or_else(|| def_op.inrefs[0].clone());
                    let b = self.resolve_varnode(&def_op.inrefs[1]).unwrap_or_else(|| def_op.inrefs[1].clone());
                    self.push_varnode(&a.read().unwrap(), None);
                    self.emit.print(sym);
                    self.push_varnode(&b.read().unwrap(), None);
                    return;
                }
            }
        }

        // Fallback: emit the varnode name
        let cond_vn = resolved.read().unwrap();
        self.push_varnode(&cond_vn, None);
    }
}

impl PrintLanguage for PrintC {
    fn get_emit(&mut self) -> &mut dyn Emit {
        self.emit.as_mut()
    }

    fn set_emit(&mut self, emit: Box<dyn Emit>) {
        self.emit = emit;
    }

    fn doc_function(&mut self, fd: &Funcdata) {
        use std::collections::HashSet;

        // Load symbol and string tables from Funcdata, sanitizing C identifiers
        self.symbol_table = fd.symbol_table.iter()
            .map(|(k, v)| (*k, sanitize_c_ident(v)))
            .collect();
        self.string_table = fd.string_table.clone();

        // Populate parameter name mapping from function prototype
        self.param_names.clear();
        for param in &fd.funcp.parameters {
            self.param_names.insert(param.address.as_u64(), param.name.clone());
        }

        // Collect function call target addresses so we don't declare them as variables
        let mut call_targets: HashSet<u64> = HashSet::new();
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if op.opcode == OpCode::CPUI_CALL {
                if let Some(in0) = op.get_in(0) {
                    let vn = in0.read().unwrap();
                    call_targets.insert(vn.get_offset());
                }
            }
        }
        self.call_targets = call_targets;

        // Precompute pointer varnodes for usage-based type inference.
        self.pointer_varnodes.clear();
        use crate::space::AddressSpace;
        let mut addr_feeding_load: HashSet<(AddressSpace, u64)> = HashSet::new();
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            match op.opcode {
                OpCode::CPUI_LOAD | OpCode::CPUI_STORE if op.inrefs.len() > 1 => {
                    let vn = op.inrefs[1].read().unwrap();
                    self.pointer_varnodes.insert((vn.get_space(), vn.get_offset()));
                }
                OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB => {
                    if let Some(ref out) = op.output {
                        let vn = out.read().unwrap();
                        addr_feeding_load.insert((vn.get_space(), vn.get_offset()));
                    }
                }
                _ => {}
            }
        }
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if matches!(op.opcode, OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB) {
                if let Some(ref out) = op.output {
                    let out_vn = out.read().unwrap();
                    if addr_feeding_load.contains(&(out_vn.get_space(), out_vn.get_offset())) {
                        for in_arc in &op.inrefs {
                            let in_vn = in_arc.read().unwrap();
                            if in_vn.get_space() != AddressSpace::Const {
                                self.pointer_varnodes.insert((in_vn.get_space(), in_vn.get_offset()));
                            }
                        }
                    }
                }
            }
        }

        // Directly stamp Pointer type on all varnodes identified as pointers.
        // This runs AFTER the full pipeline (heritage, type inference, copy
        // propagation, dead code) so the varnodes in loc_tree are the final
        // surviving ones that PrintC will encounter. This is the approach
        // Ghidra uses: type information is applied to display-level varnodes
        // just before printing, not deferred to a separate propagation pass.
        if !self.pointer_varnodes.is_empty() {
            use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
            let int_type = std::sync::Arc::new(Datatype::Base(
                TypeBase::new("int".to_string(), 4, TypeMetatype::Int),
            ));
            let int_ptr = std::sync::Arc::new(Datatype::Pointer(TypePointer {
                base: TypeBase::new("int *".to_string(), 8, TypeMetatype::Pointer),
                ptr_to: int_type,
                wordsize: 1,
            }));
            for vn_ref in &fd.vbank.loc_tree {
                let vn = vn_ref.0.read().unwrap();
                if self.pointer_varnodes.contains(&(vn.get_space(), vn.get_offset())) {
                    let needs_update = vn.v_type.as_ref().map_or(true, |t| {
                        t.get_metatype() != TypeMetatype::Pointer
                    });
                    if needs_update {
                        drop(vn);
                        vn_ref.0.write().unwrap().v_type = Some(int_ptr.clone());
                    }
                }
            }
        }

        self.func_start = fd.baseaddr.as_u64();
        self.func_end = self.func_start + (fd.obank.alivelist.len() as u64 * 16).max(0x2000);

        // Build copy propagation map from ALL blocks' ops.
        // COPY ops are block-local, not in fd.obank.alivelist.
        self.copy_map.clear();
        for i in 0..fd.bblocks.get_size() {
            if let Some(block_arc) = fd.bblocks.get_block(i) {
                let block = block_arc.read().unwrap();
                for op_ref in &block.get_ops() {
                    let op = op_ref.0.read().unwrap();
                    if op.opcode == OpCode::CPUI_COPY && !op.inrefs.is_empty() {
                        if let Some(ref out_arc) = op.output {
                            let out_ptr = Arc::as_ptr(out_arc) as usize;
                            let src = op.inrefs[0].clone();
                            self.copy_map.insert(out_ptr, src);
                        }
                    }
                }
            }
        }
        // Chase chains: if A->B and B->C, resolve A->C
        let keys: Vec<usize> = self.copy_map.keys().cloned().collect();
        for key in &keys {
            let mut current = self.copy_map[key].clone();
            let mut depth = 0;
            while depth < 20 {
                let ptr = Arc::as_ptr(&current) as usize;
                if let Some(next) = self.copy_map.get(&ptr) {
                    current = next.clone();
                    depth += 1;
                } else {
                    break;
                }
            }
            self.copy_map.insert(*key, current);
        }

        // Build defining-op map: for each op, map output varnode ptr -> op Arc
        // Include BOTH alivelist ops AND block-level ops (comparisons, booleans, etc.)
        self.def_map.clear();
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if let Some(ref out_arc) = op.output {
                let out_ptr = Arc::as_ptr(out_arc) as usize;
                self.def_map.insert(out_ptr, op_ref.0.clone());
            }
        }
        // Also add block-level ops (many comparisons/booleans live only in blocks)
        for i in 0..fd.bblocks.get_size() {
            if let Some(block_arc) = fd.bblocks.get_block(i) {
                let block = block_arc.read().unwrap();
                for op_ref in &block.get_ops() {
                    let op = op_ref.0.read().unwrap();
                    if let Some(ref out_arc) = op.output {
                        let out_ptr = Arc::as_ptr(out_arc) as usize;
                        // Don't overwrite alivelist entries
                        self.def_map.entry(out_ptr).or_insert_with(|| op_ref.0.clone());
                    }

                }
            }
        }
        // For COPY chain intermediates: if copy_map says X->Y and Y is defined by op,
        // then X should also resolve to that same op. But more importantly,
        // we need the copy destination to also be in def_map pointing to its COPY's source's def.
        // Actually, the def_map should map ANY varnode ptr to the op that "meaningfully" defines it.
        // For a COPY dest, the meaningful def is the source's def.
        let copy_keys: Vec<(usize, usize)> = self.copy_map.iter()
            .map(|(k, v)| (*k, Arc::as_ptr(v) as usize))
            .collect();
        for (copy_dest, copy_src) in &copy_keys {
            if let Some(src_def) = self.def_map.get(copy_src).cloned() {
                self.def_map.insert(*copy_dest, src_def);
            }
        }

        // Build value-based defining-op map from ALL blocks' ops.
        // We scan fd.bblocks (basic blocks) because many ops (comparisons, boolean)
        // are NOT in fd.obank.alivelist but DO exist in block-level op lists.
        self.value_def_map.clear();
        for i in 0..fd.bblocks.get_size() {
            if let Some(block_arc) = fd.bblocks.get_block(i) {
                let block = block_arc.read().unwrap();
                for op_ref in &block.get_ops() {
                    let op = op_ref.0.read().unwrap();
                    // Skip Unique-space COPY ops — their outputs are handled by copy_map.
                    // But keep Register-space COPY ops so CALL argument resolution works.
                    if op.opcode == OpCode::CPUI_COPY {
                        if let Some(ref out_arc) = op.output {
                            let out_vn = out_arc.read().unwrap();
                            if out_vn.get_space() != crate::space::AddressSpace::Register {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    }
                    if let Some(ref out_arc) = op.output {
                        let out_vn = out_arc.read().unwrap();
                        let key = (out_vn.get_space(), out_vn.get_offset());
                        self.value_def_map.insert(key, op_ref.0.clone());
                    }
                }
            }
        }
        // Build comparison_def_map: only comparison and boolean ops, keyed by (space, offset).
        // Unlike value_def_map, later non-comparison ops won't overwrite these entries.
        self.comparison_def_map.clear();
        self.stack_frame_size = 0;
        for i in 0..fd.bblocks.get_size() {
            if let Some(block_arc) = fd.bblocks.get_block(i) {
                let block = block_arc.read().unwrap();
                for op_ref in &block.get_ops() {
                    let op = op_ref.0.read().unwrap();
                    // Collect comparison/boolean ops
                    match op.opcode {
                        OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
                        | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS
                        | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL
                        | OpCode::CPUI_BOOL_NOT | OpCode::CPUI_BOOL_AND
                        | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR => {
                            if let Some(ref out_arc) = op.output {
                                let out_vn = out_arc.read().unwrap();
                                let key = (out_vn.get_space(), out_vn.get_offset());
                                // First one wins (don't overwrite)
                                self.comparison_def_map.entry(key)
                                    .or_insert_with(|| op_ref.0.clone());
                            }
                        }
                        _ => {}
                    }
                    // Detect stack frame: INT_SUB(RSP, const) or INT_ADD(RSP, negative_const)
                    if self.stack_frame_size == 0 {
                        if op.opcode == OpCode::CPUI_INT_SUB && op.inrefs.len() >= 2 {
                            let in0 = op.inrefs[0].read().unwrap();
                            let in1 = op.inrefs[1].read().unwrap();
                            // RSP is Register offset 0x20, size 8
                            if in0.get_space() == crate::space::AddressSpace::Register
                                && in0.get_offset() == 0x20 && in0.get_size() == 8
                                && in1.get_space() == crate::space::AddressSpace::Const
                            {
                                self.stack_frame_size = in1.get_offset();
                                // Record the output varnode key for frame base resolution
                                if let Some(ref out_arc) = op.output {
                                    let out_vn = out_arc.read().unwrap();
                                    self.stack_frame_base_key = Some((out_vn.get_space(), out_vn.get_offset()));
                                }
                            }
                        }
                        // Also handle INT_ADD(RSP, large_negative_const) — two's complement
                        if op.opcode == OpCode::CPUI_INT_ADD && op.inrefs.len() >= 2 {
                            let in0 = op.inrefs[0].read().unwrap();
                            let in1 = op.inrefs[1].read().unwrap();
                            if in0.get_space() == crate::space::AddressSpace::Register
                                && in0.get_offset() == 0x20 && in0.get_size() == 8
                                && in1.get_space() == crate::space::AddressSpace::Const
                            {
                                // Large const (> 0x8000_0000_0000_0000) means negative = subtraction
                                let val = in1.get_offset();
                                if val > 0x8000_0000_0000_0000u64 {
                                    let frame_size = (!val).wrapping_add(1); // two's complement negate
                                    if frame_size > 0 && frame_size < 0x10000 {
                                        self.stack_frame_size = frame_size;
                                        if let Some(ref out_arc) = op.output {
                                            let out_vn = out_arc.read().unwrap();
                                            self.stack_frame_base_key = Some((out_vn.get_space(), out_vn.get_offset()));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // Fallback: scan alivelist if bblocks didn't find stack frame
        if self.stack_frame_size == 0 {
            for op_ref in &fd.obank.alivelist {
                let op = op_ref.0.read().unwrap();
                if op.opcode == OpCode::CPUI_INT_SUB && op.inrefs.len() >= 2 {
                    let in0 = op.inrefs[0].read().unwrap();
                    let in1 = op.inrefs[1].read().unwrap();
                    if in0.get_space() == crate::space::AddressSpace::Register
                        && in0.get_offset() == 0x20 && in0.get_size() == 8
                        && in1.get_space() == crate::space::AddressSpace::Const
                        && in1.get_offset() > 0 && in1.get_offset() < 0x10000
                    {
                        self.stack_frame_size = in1.get_offset();
                        if let Some(ref out_arc) = op.output {
                            let out_vn = out_arc.read().unwrap();
                            self.stack_frame_base_key = Some((out_vn.get_space(), out_vn.get_offset()));
                        }
                        break;
                    }
                }
            }
        }
        // Detect structs on the stack by finding INT_ADD(RSP, const) outputs
        // that are passed as CALL arguments (indicating struct/buffer base addresses).
        self.stack_structs.clear();
        if self.stack_frame_size > 0 {
            let mut call_arg_offsets: Vec<u64> = Vec::new();
            let mut all_stack_offsets: Vec<u64> = Vec::new();
            
            for i in 0..fd.bblocks.get_size() {
                if let Some(block_arc) = fd.bblocks.get_block(i) {
                    let block = block_arc.read().unwrap();
                    let ops = block.get_ops();
                    for (op_idx, op_ref) in ops.iter().enumerate() {
                        let op = op_ref.0.read().unwrap();
                        
                        // Track all INT_ADD(RSP, const) offsets
                        if op.opcode == OpCode::CPUI_INT_ADD && op.inrefs.len() >= 2 {
                            let in0 = op.inrefs[0].read().unwrap();
                            let in1 = op.inrefs[1].read().unwrap();
                            if in0.get_space() == crate::space::AddressSpace::Register
                                && in0.get_offset() == 0x20 && in0.get_size() == 8
                                && in1.get_space() == crate::space::AddressSpace::Const
                            {
                                let offset = in1.get_offset();
                                if offset < self.stack_frame_size {
                                    all_stack_offsets.push(offset);
                                    
                                    // Check if the output is COPY-propagated to a register
                                    // (function argument pattern: lea rdi,[rsp+X] → COPY → register)
                                    if let Some(ref out_arc) = op.output {
                                        let out_key = {
                                            let out_vn = out_arc.read().unwrap();
                                            (out_vn.get_space(), out_vn.get_offset())
                                        };
                                        // Check if any COPY op in this block uses this output
                                        // and copies it to a register (argument passing)
                                        for next_op_ref in ops.iter().skip(op_idx + 1).take(5) {
                                            let next_op = next_op_ref.0.read().unwrap();
                                            if next_op.opcode == OpCode::CPUI_COPY && !next_op.inrefs.is_empty() {
                                                let copy_in = next_op.inrefs[0].read().unwrap();
                                                if copy_in.get_space() == out_key.0 && copy_in.get_offset() == out_key.1 {
                                                    // This INT_ADD output is COPYed somewhere — likely a function arg
                                                    if let Some(ref copy_out) = next_op.output {
                                                        let copy_out_vn = copy_out.read().unwrap();
                                                        if copy_out_vn.get_space() == crate::space::AddressSpace::Register {
                                                            call_arg_offsets.push(offset);
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                            // Also directly check if a CALL uses this output
                                            if (next_op.opcode == OpCode::CPUI_CALL || next_op.opcode == OpCode::CPUI_CALLIND)
                                                && next_op.inrefs.len() > 1
                                            {
                                                for in_arc in &next_op.inrefs[1..] {
                                                    let in_vn = in_arc.read().unwrap();
                                                    if in_vn.get_space() == out_key.0 && in_vn.get_offset() == out_key.1 {
                                                        call_arg_offsets.push(offset);
                                                        break;
                                                    }
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // Sort and deduplicate
            call_arg_offsets.sort();
            call_arg_offsets.dedup();
            all_stack_offsets.sort();
            all_stack_offsets.dedup();
            
            // For each call-argument offset, create a struct that spans to the next call-argument offset
            // or to the frame boundary
            let mut struct_counter = 0;
            for &base in &call_arg_offsets {
                // Find size: distance to next struct base, or remaining frame
                let next_base = call_arg_offsets.iter()
                    .find(|&&o| o > base)
                    .copied()
                    .unwrap_or(self.stack_frame_size);
                let size = next_base - base;
                
                // Create a struct for each call-argument base
                // Skip very small ranges (< 8 bytes) as they're likely scalar variables
                let fields_in_range: Vec<u64> = all_stack_offsets.iter()
                    .filter(|&&o| o >= base && o < next_base)
                    .map(|&o| o - base)
                    .collect();
                
                if size >= 8 {
                    let name = format!("struct{}", struct_counter + 1);
                    self.stack_structs.push(StackStruct {
                        name,
                        base_offset: base,
                        size,
                        fields: fields_in_range,
                    });
                    struct_counter += 1;
                }
            }
        }
        // Build inline candidates for Unique-space and Register-space single-use outputs.
        // Count how many times each (space, offset) pair is used as input.
        self.inline_candidates.clear();
        {
            use crate::space::AddressSpace;
            let mut use_count: HashMap<(AddressSpace, u64), u32> = HashMap::new();
            let track_spaces = |vn_space: AddressSpace| -> bool {
                matches!(vn_space, AddressSpace::Unique | AddressSpace::Register)
            };
            for i in 0..fd.bblocks.get_size() {
                if let Some(block_arc) = fd.bblocks.get_block(i) {
                    let block = block_arc.read().unwrap();
                    for op_ref in &block.get_ops() {
                        let op = op_ref.0.read().unwrap();
                        for in_arc in &op.inrefs {
                            let in_vn = in_arc.read().unwrap();
                            if track_spaces(in_vn.get_space()) {
                                let key = (in_vn.get_space(), in_vn.get_offset());
                                *use_count.entry(key).or_insert(0) += 1;
                            }
                            // Also check the resolved copy source
                            let ptr = Arc::as_ptr(in_arc) as usize;
                            if let Some(resolved) = self.copy_map.get(&ptr) {
                                let res_vn = resolved.read().unwrap();
                                if track_spaces(res_vn.get_space()) {
                                    let key = (res_vn.get_space(), res_vn.get_offset());
                                    *use_count.entry(key).or_insert(0) += 1;
                                }
                            }
                        }
                    }
                }
            }
            // Also count uses from alivelist
            for op_ref in &fd.obank.alivelist {
                let op = op_ref.0.read().unwrap();
                for in_arc in &op.inrefs {
                    let in_vn = in_arc.read().unwrap();
                    if track_spaces(in_vn.get_space()) {
                        let key = (in_vn.get_space(), in_vn.get_offset());
                        *use_count.entry(key).or_insert(0) += 1;
                    }
                    let ptr = Arc::as_ptr(in_arc) as usize;
                    if let Some(resolved) = self.copy_map.get(&ptr) {
                        let res_vn = resolved.read().unwrap();
                        if track_spaces(res_vn.get_space()) {
                            let key = (res_vn.get_space(), res_vn.get_offset());
                            *use_count.entry(key).or_insert(0) += 1;
                        }
                    }
                }
            }

            // Populate inline_candidates: single-use outputs (Unique or Register space)
            // that are produced by inlineable ops (not COPY/STORE/branch/return/CALL)
            for (key, def_op_arc) in &self.value_def_map {
                if !track_spaces(key.0) {
                    continue;
                }
                // For Register space, only inline if the varnode would get a uVar name
                // (don't inline named parameters, RSP/RBP, etc.)
                if key.0 == AddressSpace::Register {
                    // Skip frame registers
                    if key.1 == 0x20 || key.1 == 0x28 { continue; }
                    // Skip parameter registers  
                    if self.param_names.contains_key(&key.1) { continue; }
                }
                let count = use_count.get(key).copied().unwrap_or(0);
                if count > 1 {
                    continue;
                }
                let def_op = def_op_arc.read().unwrap();
                match def_op.opcode {
                    OpCode::CPUI_STORE
                    | OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCHIND
                    | OpCode::CPUI_RETURN | OpCode::CPUI_INDIRECT
                    | OpCode::CPUI_MULTIEQUAL
                    | OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => continue,
                    // CPUI_COPY is intentionally NOT excluded: single-use
                    // COPY outputs can be inlined at their use site, with
                    // printc emitting the COPY's input (handled at the
                    // inline-emit path). This is what eliminates redundant
                    // `t = COPY(reg); use(t)` patterns in favor of `use(reg)`.
                    OpCode::CPUI_COPY => {}
                    _ => {}
                }
                drop(def_op);
                self.inline_candidates.insert(*key, def_op_arc.clone());
                self.inlined_ops.insert(*def_op_arc.read().unwrap().get_seq_num());
            }
        }
        // Build global used_outputs for cross-block dead code elimination.
        // Scan ALL blocks and alivelist to find every varnode Arc used as input.
        self.global_used_outputs.clear();
        for i in 0..fd.bblocks.get_size() {
            if let Some(block_arc) = fd.bblocks.get_block(i) {
                let block = block_arc.read().unwrap();
                for op_ref in &block.get_ops() {
                    let op = op_ref.0.read().unwrap();
                    for in_arc in &op.inrefs {
                        self.global_used_outputs.insert(Arc::as_ptr(in_arc) as usize);
                        if let Some(resolved) = self.copy_map.get(&(Arc::as_ptr(in_arc) as usize)) {
                            self.global_used_outputs.insert(Arc::as_ptr(resolved) as usize);
                        }
                    }
                }
            }
        }
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            for in_arc in &op.inrefs {
                self.global_used_outputs.insert(Arc::as_ptr(in_arc) as usize);
                if let Some(resolved) = self.copy_map.get(&(Arc::as_ptr(in_arc) as usize)) {
                    self.global_used_outputs.insert(Arc::as_ptr(resolved) as usize);
                }
            }
        }

         // Reset tracking state
        self.seen_return = false;
        self.inlined_ops.clear();
        self.used_varnode_names.clear();
        self.used_varnode_types.clear();

        // Pass 1: Discovery (only collect used names silently)
        self.discovery_pass = true;
        let old_emit = std::mem::replace(&mut self.emit, Box::new(NullEmit::new()));

        let graph = if fd.sblocks.get_size() > 0 {
            &fd.sblocks
        } else {
            &fd.bblocks
        };

        // Collect all switch case body block indices. BlockIf emit checks this
        // to avoid extracting case bodies (which pulls `case` labels out of switch).
        self.case_body_indices.clear();
        for i in 0..graph.get_size() {
            if let Some(block_arc) = graph.get_block(i) {
                let b = block_arc.read().unwrap();
                if b.get_type() == crate::block::BlockType::Switch {
                    if let Some(bs) = b.as_any().downcast_ref::<crate::block::BlockSwitch>() {
                        for case in &bs.cases {
                            self.case_body_indices.insert(case.read().unwrap().get_index());
                        }
                        if let Some(ref dc) = bs.default_case {
                            self.case_body_indices.insert(dc.read().unwrap().get_index());
                        }
                    }
                }
                // Also collect CASE_BODY flagged blocks (cascade switch cases)
                if b.get_flags() & crate::block::block_flags::CASE_BODY != 0 {
                    self.case_body_indices.insert(b.get_index());
                }
            }
        }


        let mut discovery_emitted: HashSet<i32> = HashSet::new();
        for i in 0..graph.get_size() {
            if let Some(block_arc) = graph.get_block(i) {
                let block_idx = block_arc.read().unwrap().get_index();
                let size_in = block_arc.read().unwrap().size_in();
                if size_in == 0 && !discovery_emitted.contains(&block_idx) {
                    self.emit_block_structured(&block_arc, graph, &mut discovery_emitted);
                }
            }
        }
        
        self.emit = old_emit;
        self.discovery_pass = false;

        // Pass 2: Final Emission
        self.seen_return = false;

        // Emit Ghidra-style typedefs at the top of each function. These mirror
        // the declarations Ghidra prepends to every decompiled function so its
        // output is self-contained C. byte/bool come from size-based inference
        // in ActionInferParams/ActionTypeInfer; without these typedefs the
        // emitted `byte bVarN;` declarations fail C compilation.
        // `_struct` is a generic backing type for pointer variables that get
        // dereferenced via `->field_N` (see fix_deref_declarations): declaring
        // such a variable as `_struct *` keeps `X->field_N` legal C.
        self.emit.tag_line(0);
        self.emit.print("typedef unsigned char byte;");
        self.emit.tag_line(0);
        self.emit.print("typedef unsigned long undefined;");
        self.emit.tag_line(0);
        self.emit.print("typedef unsigned long undefined4;");
        self.emit.tag_line(0);
        self.emit.print("typedef unsigned long long undefined8;");
        self.emit.tag_line(0);
        self.emit.print("typedef struct { char _anon[256]; } _struct;");
        self.emit.tag_line(0);
        self.emit.print("");

        // Emit extern declarations for referenced global variables that are not
        // function call targets. Ghidra's output is self-contained: every global
        // referenced in a function body has a visible declaration. We approximate
        // this by declaring any Ram/Const-space name (from symbol/string tables)
        // as `extern long NAME;` so the body compiles even when the global's real
        // type/layout is unknown.
        let mut emitted_globals: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for (name, (_type, space, offset)) in &self.used_varnode_types {
            if matches!(space, AddressSpace::Ram | AddressSpace::Const)
                && !self.call_targets.contains(offset)
                && !name.starts_with('"')
                && !name.is_empty()
                && name.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_')
            {
                emitted_globals.insert(name.clone());
            }
        }
        // Also scan used_varnode_names for symbol-table globals not captured above
        for name in &self.used_varnode_names {
            // Only add names that look like symbols (not local var prefixes, not keywords)
            if name.contains('.') || name.contains('-') || name.contains('>') { continue; }
            if name.starts_with("param_") || name.starts_with("local_") { continue; }
            let is_local_prefix = ["lVar","uVar","iVar","bVar","sVar","piVar","pcVar","psVar","ppVar","pvVar","fVar","dVar","DAT_","LAB_"].iter().any(|p| name.starts_with(p));
            if is_local_prefix { continue; }
            if ["argc","argv","RBP","RSP","RBX","R12","R13","R14","R15"].contains(&name.as_str()) { continue; }
            // Check it's a known symbol from the binary
            if self.symbol_table.values().any(|s| s == name) {
                emitted_globals.insert(name.clone());
            }
        }
        for name in &emitted_globals {
            self.emit.tag_line(0);
            self.emit.print(&format!("extern long {};", name));
        }
        if !emitted_globals.is_empty() {
            self.emit.tag_line(0);
            self.emit.print("");
        }

        // 1. Emit signature from function prototype
        let is_main = fd.get_name() == "main";
        if is_main {
            // Special case: main always gets canonical signature
            self.emit.print("int ");
            self.emit.tag_func_name(fd.get_name(), 0);
            self.emit.open_paren();
            self.emit.print("int argc, char **argv");
            self.emit.close_paren();
            // Override param_names for main: EDI/RDI=argc, RSI=argv
            self.param_names.insert(0x38, "argc".to_string());
            self.param_names.insert(0x30, "argv".to_string());
            self.param_names.retain(|&k, _| k == 0x38 || k == 0x30);
        } else {
            // Infer return type: check if RAX/EAX (register offset 0x00) is written
            // by any op in the function. If written, function likely returns a value.
            let inferred_ret_type = {
                use crate::space::AddressSpace;
                let mut rax_written = false;
                let mut rax_size: usize = 4;
                let mut has_return = false;
                let mut total_ops = 0u32;
                for op_ref in &fd.obank.alivelist {
                    let op = op_ref.0.read().unwrap();
                    total_ops += 1;
                    if op.opcode == OpCode::CPUI_RETURN { has_return = true; }
                    if let Some(ref out_arc) = op.output {
                        let out_vn = out_arc.read().unwrap();
                        if out_vn.get_space() == AddressSpace::Register && out_vn.get_offset() == 0x00 {
                            rax_written = true;
                            rax_size = out_vn.get_size();
                        }
                    }
                }
                // Also check block-level ops
                for i in 0..fd.bblocks.get_size() {
                    if let Some(block_arc) = fd.bblocks.get_block(i) {
                        let block = block_arc.read().unwrap();
                        for op_ref in &block.get_ops() {
                            let op = op_ref.0.read().unwrap();
                            if op.opcode == OpCode::CPUI_RETURN { has_return = true; }
                            if let Some(ref out_arc) = op.output {
                                let out_vn = out_arc.read().unwrap();
                                if out_vn.get_space() == AddressSpace::Register && out_vn.get_offset() == 0x00 {
                                    rax_written = true;
                                    rax_size = out_vn.get_size();
                                }
                            }
                        }
                    }
                }
                // Heuristic: if the function writes RAX and has meaningful body, infer non-void
                if rax_written && has_return && total_ops > 2 {
                    match rax_size {
                        8 => "long",
                        4 => "int",
                        2 => "short",
                        1 => "char",
                        _ => "int",
                    }
                } else if total_ops <= 2 {
                    "void" // trivial functions like main_init/main_free
                } else {
                    "void"
                }
            };
            self.emit.print(inferred_ret_type);
            self.emit.print(" ");
            // Sanitize function name: GCC generates names like "parseconfig.constprop.0"
            // with dots that aren't valid C identifiers. Replace non-identifier chars with '_'.
            let sanitized_name = sanitize_c_ident(fd.get_name());
            self.emit.tag_func_name(&sanitized_name, 0);
            self.emit.open_paren();
            
            if fd.funcp.parameters.is_empty() {
                // Fix 4: Fallback parameter detection
                // Scan all ops for Register reads of SysV ABI arg registers
                // that are NOT written by any op in the function (= function params)
                use crate::space::AddressSpace;
                // SysV ABI: RDI(0x38), RSI(0x30), RDX(0x10), RCX(0x08), R8(0x80), R9(0x88)
                let abi_regs: [(u64, &str, &str); 6] = [
                    (0x38, "long", "param_1"), (0x30, "long", "param_2"),
                    (0x10, "long", "param_3"), (0x08, "long", "param_4"),
                    (0x80, "long", "param_5"), (0x88, "long", "param_6"),
                ];
                
                // Collect all register offsets that are WRITTEN (output) by some op
                let mut written_regs = std::collections::HashSet::new();
                for op_ref in &fd.obank.alivelist {
                    let op = op_ref.0.read().unwrap();
                    if let Some(ref out_arc) = op.output {
                        let out_vn = out_arc.read().unwrap();
                        if out_vn.get_space() == AddressSpace::Register {
                            written_regs.insert(out_vn.get_offset());
                        }
                    }
                }
                
                // Collect register offsets that are READ (input) by some op
                let mut read_regs = std::collections::HashSet::new();
                for op_ref in &fd.obank.alivelist {
                    let op = op_ref.0.read().unwrap();
                    for in_arc in &op.inrefs {
                        let vn = in_arc.read().unwrap();
                        if vn.get_space() == AddressSpace::Register {
                            read_regs.insert(vn.get_offset());
                        }
                    }
                }
                
                // A register is likely a parameter if it's read but never written
                // (meaning the value comes from the caller)
                let mut detected_params: Vec<(u64, &str, &str)> = Vec::new();
                for &(reg_off, type_name, param_name) in &abi_regs {
                    if read_regs.contains(&reg_off) {
                        detected_params.push((reg_off, type_name, param_name));
                    } else {
                        // Stop at first gap (SysV ABI requires contiguous registers)
                        break;
                    }
                }
                
                for (i, (reg_off, type_name, param_name)) in detected_params.iter().enumerate() {
                    if i > 0 { self.emit.print(", "); }
                    self.emit.print(type_name);
                    self.emit.print(" ");
                    self.emit.print(param_name);
                    self.param_names.insert(*reg_off, param_name.to_string());
                }
            } else {
                // Emit parameters from prototype
                for (i, param) in fd.funcp.parameters.iter().enumerate() {
                    if i > 0 {
                        self.emit.print(", ");
                    }
                    self.emit.print(param.data_type.get_name());
                    self.emit.print(" ");
                    self.emit.print(&param.name);
                }
            }
            self.emit.close_paren();
        }

        // 2. Emit body with structured control flow
        self.emit.begin_block();

        // 2a. Emit variable declarations (now pruned by used_varnode_names)
        self.doc_variable_decls_from_funcdata(fd);

        // 2a.5: Collect goto targets for label emission
        self.goto_targets.clear();
        for i in 0..graph.get_size() {
            if let Some(block_arc) = graph.get_block(i) {
                let block = block_arc.read().unwrap();
                let ops = block.get_ops();
                for op_ref in &ops {
                    let op = op_ref.0.read().unwrap();
                    if op.opcode == crate::opcodes::OpCode::CPUI_BRANCH
                        || op.opcode == crate::opcodes::OpCode::CPUI_CBRANCH
                    {
                        // First input is the target address
                        if !op.inrefs.is_empty() {
                            let target = op.inrefs[0].read().unwrap();
                            if target.get_space() == crate::space::AddressSpace::Const
                                || target.get_space() == crate::space::AddressSpace::Ram
                            {
                                self.goto_targets.insert(target.get_offset());
                            }
                        }
                    }
                }
            }
        }

        let mut emitted: HashSet<i32> = HashSet::new();
        // 2b. Emit body starting from root/entry blocks
        for i in 0..graph.get_size() {
            if let Some(block_arc) = graph.get_block(i) {
                let block_idx = block_arc.read().unwrap().get_index();
                let size_in = block_arc.read().unwrap().size_in();
                if size_in == 0 && !emitted.contains(&block_idx) {
                    self.emit_block_structured(&block_arc, graph, &mut emitted);
                }
            }
        }

        // 2c. Emit any disconnected or unreachable subgraphs
        for i in 0..graph.get_size() {
            if let Some(block_arc) = graph.get_block(i) {
                let block_idx = block_arc.read().unwrap().get_index();
                if !emitted.contains(&block_idx) {
                    self.emit_block_structured(&block_arc, graph, &mut emitted);
                }
            }
        }

        self.emit.end_block();

        // Post-process: eliminate redundant gotos and orphan labels (P3)
        if let Some(eno) = self.emit.as_any_mut()
            .and_then(|a| a.downcast_mut::<crate::prettyprint::EmitNoMarkup>())
        {
            eno.post_process();
        }

        self.emit.end_function();
    }


    fn doc_all_proto(&mut self, _proto: &FuncProto) {
        // TODO: Implement prototype emission
    }

    fn doc_variable_decl(&mut self, vn: &Varnode) {
        if let Some(dt) = &vn.v_type {
            self.push_type(dt);
            self.emit.print(" ");
        } else {
            self.emit.print("int "); // Fallback
        }
        self.push_varnode(vn, None);
        self.emit.print(";");
    }


    fn doc_statement(&mut self, op: &PcodeOp) {
        self.emit.tag_line(0);
        op.push(self); // This will call the appropriate op_xxx method
        self.emit.print(";");
    }

    // --- P-code Op-code specific emission ---

    fn op_copy(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.is_lhs = true;
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.is_lhs = false;
            self.emit.tag_op(" = ");
            if let Some(in0) = op.get_in(0) {
                self.push_varnode(&in0.read().unwrap(), Some(op));
            }
        }
    }

    fn op_load(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.is_lhs = true;
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.is_lhs = false;
            self.emit.tag_op(" = ");
            // Typed dereference: if address input has pointer type, emit *(type *)addr
            if op.inrefs.len() >= 2 {
                let addr_type_name = op.inrefs[1].read().unwrap().v_type.as_ref()
                    .and_then(|t| if matches!(t.as_ref(), Datatype::Pointer(_)) {
                        Some(t.get_name().to_string())
                    } else {
                        None
                    });
                if let Some(ref ptr_name) = addr_type_name {
                    self.emit.print(&format!("*({} )", ptr_name));
                    self.push_input(op, 1);
                } else {
                    self.emit.print("*(long *)");
                    self.push_input(op, 1);
                }
            } else {
                self.emit.print("*(long *)");
                self.push_input(op, 1);
            }
        }
    }

    fn op_store(&mut self, op: &PcodeOp) {
        // Try to inline address computation: *(base + off) = val
        let mut inlined_addr = false;
        if let Some(addr_arc) = op.get_in(1) {
            let resolved = self.resolve_varnode(&addr_arc).unwrap_or_else(|| addr_arc.clone());
            let resolved_ptr = Arc::as_ptr(&resolved) as usize;
            let addr_key = {
                let resolved_vn = resolved.read().unwrap();
                (resolved_vn.get_space(), resolved_vn.get_offset())
            };

            // Value-based lookup first, then pointer-based
            let def_op_opt = self.value_def_map.get(&addr_key).cloned()
                .or_else(|| self.def_map.get(&resolved_ptr).cloned());

            if let Some(def_op_arc) = def_op_opt {
                let def_op = def_op_arc.read().unwrap();
                if def_op.opcode == OpCode::CPUI_INT_ADD && def_op.inrefs.len() >= 2 {
                    // Mark addition as inlined
                    self.inlined_ops.insert(*def_op.get_seq_num());

                    // RIP-relative: *(RIP + sym) → *(long *)sym (cast for legality)
                    if let Some(non_rip_idx) = self.get_rip_relative_operand(&def_op) {
                        let operand = self.resolve_varnode(&def_op.inrefs[non_rip_idx])
                            .unwrap_or_else(|| def_op.inrefs[non_rip_idx].clone());
                        self.emit.print("*(long *)");
                        self.push_varnode(&operand.read().unwrap(), None);
                    } else if let Some(stack_name) = self.get_stack_variable_name(&def_op) {
                        // Stack variable: *(RSP + offset) → local_XX
                        self.mark_variable_used(stack_name.clone(), AddressSpace::Stack, 0, "int".to_string());
                        self.emit.tag_variable(&stack_name, 0);
                    } else {
                        // Check for struct field access: *(base + const_offset)
                        // If one operand is Const, emit as base->field_XX
                        let in0 = self.resolve_varnode(&def_op.inrefs[0]).unwrap_or_else(|| def_op.inrefs[0].clone());
                        let in1 = self.resolve_varnode(&def_op.inrefs[1]).unwrap_or_else(|| def_op.inrefs[1].clone());
                        let in0_vn = in0.read().unwrap();
                        let in1_vn = in1.read().unwrap();

                        let (base_vn, offset_val) = if in1_vn.get_space() == crate::space::AddressSpace::Const
                            && in0_vn.get_space() != crate::space::AddressSpace::Const
                            && in1_vn.get_offset() > 0 && in1_vn.get_offset() < 0x10000
                        {
                            // *(base + const_offset)
                            (Some(in0.clone()), Some(in1_vn.get_offset()))
                        } else if in0_vn.get_space() == crate::space::AddressSpace::Const
                            && in1_vn.get_space() != crate::space::AddressSpace::Const
                            && in0_vn.get_offset() > 0 && in0_vn.get_offset() < 0x10000
                        {
                            // *(const_offset + base)
                            (Some(in1.clone()), Some(in0_vn.get_offset()))
                        } else {
                            (None, None)
                        };
                        drop(in0_vn);
                        drop(in1_vn);

                        if let (Some(base), Some(off)) = (base_vn, offset_val) {
                            // Emit as: *(base + 0xNN) or base->field_XX for small offsets
                            self.push_varnode(&base.read().unwrap(), None);
                            if off <= 0xffff {
                                self.emit.print(&format!("->field_{:x}", off));
                            } else {
                                self.emit.print(&format!("->field_0x{:x}", off));
                            }
                        } else {
                            // Emit as *(long *)(a + b) — the cast makes it legal C
                            // regardless of whether a/b are pointers or scalars,
                            // since integer-to-pointer cast is allowed.
                            self.emit.print("*(long *)(");
                            let a = self.resolve_varnode(&def_op.inrefs[0]).unwrap_or_else(|| def_op.inrefs[0].clone());
                            let b = self.resolve_varnode(&def_op.inrefs[1]).unwrap_or_else(|| def_op.inrefs[1].clone());
                            self.push_varnode(&a.read().unwrap(), None);
                            self.emit.print(" + ");
                            self.push_varnode(&b.read().unwrap(), None);
                            self.emit.print(")");
                        }
                    }
                    inlined_addr = true;
                }
            }
        }
        if !inlined_addr {
            if let Some(addr_arc) = op.get_in(1) {
                let addr_vn = addr_arc.read().unwrap();
                let addr_space = addr_vn.get_space();
                let addr_offset = addr_vn.get_offset();
                
                // Fix 6: STORE directly to RSP → stack top variable
                if addr_space == crate::space::AddressSpace::Register && self.stack_frame_size > 0 {
                    // RSP offset = 0x20 on x86-64. This is `mov [rsp], val` (stack top)
                    if addr_offset == 0x20 {
                        let var_name = format!("local_{:x}", self.stack_frame_size);
                        self.mark_variable_used(var_name.clone(), AddressSpace::Stack, self.stack_frame_size, "int".to_string());
                        drop(addr_vn);
                        self.emit.tag_variable(&var_name, 0);
                        self.emit.tag_op(" = ");
                        self.push_input(op, 2);
                        return;
                    }
                }
                
                // Fix 7: Resolve global address to symbol name
                // Check if the address constant matches a known symbol
                if matches!(addr_space, crate::space::AddressSpace::Const | crate::space::AddressSpace::Ram) {
                    if let Some(sym_name) = self.symbol_table.get(&addr_offset) {
                        drop(addr_vn);
                        // *(long *)sym — cast makes dereference legal regardless of sym's type
                        self.emit.print("*(long *)");
                        self.emit.tag_variable(sym_name, 0);
                        self.emit.tag_op(" = ");
                        self.push_input(op, 2);
                        return;
                    }
                    // Synthetic BSS/data variable name for unmapped addresses
                    // Typical ELF data sections are in the range 0x10000..0x1000000
                    if addr_offset >= 0x10000 && addr_offset < 0x1000000 {
                        let syn_name = format!("DAT_{:05x}", addr_offset);
                        // Mark as used so an extern declaration is emitted (self-contained output)
                        self.mark_variable_used(syn_name.clone(), addr_space, addr_offset, "long".to_string());
                        drop(addr_vn);
                        self.emit.print("*(long *)");
                        self.emit.tag_variable(&syn_name, 0);
                        self.emit.tag_op(" = ");
                        self.push_input(op, 2);
                        return;
                    }
                }
                drop(addr_vn);

                // Typed dereference for STORE address
                let addr_type_name = addr_arc.read().unwrap().v_type.as_ref()
                    .and_then(|t| if matches!(t.as_ref(), Datatype::Pointer(_)) {
                        Some(t.get_name().to_string())
                    } else {
                        None
                    });
                if let Some(ref ptr_name) = addr_type_name {
                    self.emit.print(&format!("*({} )", ptr_name));
                    self.push_input(op, 1);
                } else {
                    // *(long *)addr — default cast form so *addr is legal C even
                    // when addr was inferred as a non-pointer scalar.
                    self.emit.print("*(long *)");
                    self.push_input(op, 1);
                }
            } else {
                self.emit.print("*(long *)");
                self.push_input(op, 1);
            }
        }
        self.emit.tag_op(" = ");
        self.push_input(op, 2);
    }

    fn op_binary(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            // RIP-relative folding: INT_ADD(RIP, const) → the output is just a symbol alias.
            // Skip entirely because every read resolves back to the symbol via Priority 1.5.
            if let Some(_non_rip_idx) = self.get_rip_relative_operand(op) {
                return;
            }

            // Stack frame setup: INT_SUB(RSP, frame_size) → skip entirely
            if self.is_stack_frame_setup(op) {
                return;
            }

            // Stack variable: INT_ADD(RSP, const) → output = &local_XX
            if let Some(stack_name) = self.get_stack_variable_name(op) {
                self.is_lhs = true;
                self.push_varnode(&out.read().unwrap(), Some(op));
                self.is_lhs = false;
                self.emit.tag_op(" = ");
                self.mark_variable_used(stack_name.clone(), AddressSpace::Stack, 0, "int".to_string());
                self.emit.print("&");
                self.emit.tag_variable(&stack_name, 0);
                return;
            }

            self.is_lhs = true;
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.is_lhs = false;
            self.emit.tag_op(" = ");

            // Boolean comparison folding: BOOL_OR(EQ(A,B), LT(A,B)) → A <= B
            if self.try_fold_bool_comparison(op) {
                return;
            }

            self.push_input(op, 0);

            let op_sym = match op.opcode {
                OpCode::CPUI_INT_EQUAL | OpCode::CPUI_FLOAT_EQUAL => " == ",
                OpCode::CPUI_INT_NOTEQUAL | OpCode::CPUI_FLOAT_NOTEQUAL => " != ",
                OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS | OpCode::CPUI_FLOAT_LESS => " < ",
                OpCode::CPUI_INT_LESSEQUAL
                | OpCode::CPUI_INT_SLESSEQUAL
                | OpCode::CPUI_FLOAT_LESSEQUAL => " <= ",
                OpCode::CPUI_INT_ADD | OpCode::CPUI_FLOAT_ADD => " + ",
                OpCode::CPUI_INT_SUB | OpCode::CPUI_FLOAT_SUB => " - ",
                OpCode::CPUI_INT_MULT | OpCode::CPUI_FLOAT_MULT => " * ",
                OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_SDIV | OpCode::CPUI_FLOAT_DIV => " / ",
                OpCode::CPUI_INT_REM | OpCode::CPUI_INT_SREM => " % ",
                OpCode::CPUI_INT_AND => " & ",
                OpCode::CPUI_INT_OR => " | ",
                OpCode::CPUI_INT_XOR => " ^ ",
                OpCode::CPUI_INT_LEFT => " << ",
                OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT => " >> ",
                OpCode::CPUI_BOOL_AND => " && ",
                OpCode::CPUI_BOOL_OR => " || ",
                OpCode::CPUI_BOOL_XOR => " ^ ",
                _ => " op ",
            };

            self.emit.print(op_sym);
            self.push_input(op, 1);
        }
    }

    fn op_unary(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.is_lhs = true;
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.is_lhs = false;
            self.emit.tag_op(" = ");

            let op_sym = match op.opcode {
                OpCode::CPUI_INT_NOT => "~",
                OpCode::CPUI_INT_NEG => "-",
                OpCode::CPUI_BOOL_NOT => "!",
                OpCode::CPUI_FLOAT_NEG => "-",
                OpCode::CPUI_INT_ZEXT => {
                    // Use output type if available for more precise cast
                    let cast_name = op.output.as_ref()
                        .and_then(|out| out.read().unwrap().v_type.as_ref().map(|t| t.get_name().to_string()));
                    if let Some(ref name) = cast_name {
                        self.emit.print(&format!("({})", name));
                        self.push_input(op, 0);
                        return;
                    }
                    "(uint)"
                }
                OpCode::CPUI_INT_SEXT => {
                    let cast_name = op.output.as_ref()
                        .and_then(|out| out.read().unwrap().v_type.as_ref().map(|t| t.get_name().to_string()));
                    if let Some(ref name) = cast_name {
                        self.emit.print(&format!("({})", name));
                        self.push_input(op, 0);
                        return;
                    }
                    "(int)"
                }
                OpCode::CPUI_FLOAT_ABS => "fabs",
                OpCode::CPUI_FLOAT_SQRT => "sqrt",
                _ => "op",
            };
            self.emit.print(op_sym);
            self.push_input(op, 0);
        }
    }

    fn op_multiequal(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.is_lhs = true;
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.is_lhs = false;
            self.emit.tag_op(" = ");
            self.emit.print("phi");
            self.emit.open_paren();
            for i in 0..op.num_input() {
                if i > 0 {
                    self.emit.print(", ");
                }
                if let Some(vn) = op.get_in(i) {
                    self.push_varnode(&vn.read().unwrap(), Some(op));
                }
            }
            self.emit.close_paren();
        }
    }

    fn op_indirect(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.is_lhs = true;
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.is_lhs = false;
            self.emit.tag_op(" = ");
            self.push_input(op, 0);
            self.emit.print(" (indirect)");
        }
    }

    fn op_call(&mut self, op: &PcodeOp) {
        if let Some(out) = op.get_out() {
            self.is_lhs = true;
            self.push_varnode(&out.read().unwrap(), Some(op));
            self.is_lhs = false;
            self.emit.tag_op(" = ");
        }
        if let Some(in0) = op.get_in(0) {
            let target_vn = in0.read().unwrap();
            let target_addr = target_vn.get_offset();
            drop(target_vn);
            if target_addr == 0 {
                if !self.discovery_pass {
                    // Indirect call via unresolved pointer (address 0). Emit a
                    // function-pointer cast so the call is legal C regardless
                    // of how the target was represented.
                    self.emit.tag_variable("(*(void(*)())0)", 0);
                }
            } else if let Some(sym_name) = self.symbol_table.get(&target_addr) {
                self.emit.tag_variable(sym_name, 0);
            } else {
                let fun_name = format!("FUN_{:08x}", target_addr);
                if !self.discovery_pass {
                    self.emit.tag_variable(&fun_name, 0);
                }
            }
        }
        self.emit.open_paren();
        // For CALL arguments (in[1..]), try to resolve the defining expression
        // instead of printing raw register names like "RDI"
        for i in 1..op.num_input() {
            if i > 1 {
                self.emit.print(", ");
            }
            if let Some(vn_arc) = op.get_in(i) {
                let vn = vn_arc.read().unwrap();
                let space = vn.get_space();
                let offset = vn.get_offset();
                drop(vn);

                // For register args, try to find what value was written to this register
                // Prefer block-local def (avoids cross-block contamination) over global value_def_map
                if space == crate::space::AddressSpace::Register {
                    let key = (space, offset);
                    let def_op_opt = self.block_local_reg_defs.get(&key).cloned()
                        .or_else(|| self.value_def_map.get(&key).cloned());
                    if let Some(def_op_arc) = def_op_opt {
                        let def_op = def_op_arc.read().unwrap();
                        if def_op.opcode == OpCode::CPUI_COPY && !def_op.inrefs.is_empty() {
                            // Resolve COPY source — check what defined the source
                            let src_arc = def_op.inrefs[0].clone();
                            let src_vn = src_arc.read().unwrap();
                            let src_space = src_vn.get_space();
                            let src_offset = src_vn.get_offset();
                            drop(src_vn);
                            drop(def_op);

                            // Try to find the source's defining op for deeper resolution
                            let src_key = (src_space, src_offset);
                            let src_def = self.value_def_map.get(&src_key).cloned()
                                .or_else(|| self.inline_candidates.get(&src_key).cloned());
                            
                            if let Some(src_def_arc) = src_def {
                                let src_def_op = src_def_arc.read().unwrap();
                                // RIP-relative? Just emit the symbol
                                if let Some(non_rip_idx) = self.get_rip_relative_operand(&src_def_op) {
                                    if non_rip_idx < src_def_op.inrefs.len() {
                                        let sym_arc = src_def_op.inrefs[non_rip_idx].clone();
                                        drop(src_def_op);
                                        self.push_varnode(&sym_arc.read().unwrap(), None);
                                        continue;
                                    }
                                }
                                // Other inlineable expression
                                self.inlined_ops.insert(*src_def_op.get_seq_num());
                                self.emit_inline_expr(&src_def_op);
                                continue;
                            }
                            // Fallback: push the COPY source directly
                            self.push_varnode(&src_arc.read().unwrap(), None);
                            continue;
                        }
                        // For other ops (not COPY), try inline the expression
                        if !def_op.inrefs.is_empty() {
                            // RIP-relative? Just emit the symbol
                            if let Some(non_rip_idx) = self.get_rip_relative_operand(&def_op) {
                                if non_rip_idx < def_op.inrefs.len() {
                                    let sym_arc = def_op.inrefs[non_rip_idx].clone();
                                    drop(def_op);
                                    self.push_varnode(&sym_arc.read().unwrap(), None);
                                    continue;
                                }
                            }
                            self.inlined_ops.insert(*def_op.get_seq_num());
                            self.emit_inline_expr(&def_op);
                            continue;
                        }
                    }
                }
                // Fallback: print the varnode as-is
                self.push_varnode(&vn_arc.read().unwrap(), Some(op));
            }
        }
        self.emit.close_paren();
    }

    fn op_return(&mut self, op: &PcodeOp) {
        self.emit.print("return");
        if op.num_input() > 1 {
            self.emit.print(" ");
            if let Some(in1) = op.get_in(1) {
                self.push_varnode(&in1.read().unwrap(), Some(op));
            }
        } else {
            // No explicit return value on the RETURN op. Check if RAX/EAX (offset 0x0)
            // was written by an op just before this RETURN in the same block. If so,
            // emit that value as the return — mirrors how Ghidra reconstructs
            // 'xor eax,eax; ret' into 'return 0'.
            use crate::space::AddressSpace;
            if let Some(ref parent_arc) = op.parent {
                if let Some(ref parent_dyn) = parent_arc.upgrade() {
                    let block = parent_dyn.read().unwrap();
                    let ops = block.get_ops();
                    for op_ref in ops.iter().rev() {
                        let o = op_ref.0.read().unwrap();
                        if o.start == op.start { continue; }
                        if let Some(ref out_arc) = o.output {
                            let out_vn = out_arc.read().unwrap();
                            if out_vn.get_space() == AddressSpace::Register
                                && out_vn.get_offset() == 0x0
                                && out_vn.get_size() >= 4
                            {
                                drop(out_vn);
                                drop(o);
                                self.emit.print(" ");
                                let o2 = op_ref.0.read().unwrap();
                                self.emit_inline_expr(&o2);
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    fn op_cbranch(&mut self, op: &PcodeOp) {
        use crate::op::branch_type;
        match op.branch_type {
            branch_type::BREAK => {
                self.emit.print("if (");
                if let Some(in1) = op.get_in(1) {
                    self.emit_condition(&in1);
                }
                self.emit.print(") break");
            }
            branch_type::CONTINUE => {
                if self.loop_depth > 0 {
                    self.emit.print("if (");
                    if let Some(in1) = op.get_in(1) {
                        self.emit_condition(&in1);
                    }
                    self.emit.print(") continue");
                } else {
                    // Not in a loop — emit as goto instead
                    self.emit.print("if (");
                    if let Some(in1) = op.get_in(1) {
                        self.emit_condition(&in1);
                    }
                    self.emit.print(") goto ");
                    if let Some(in0) = op.get_in(0) {
                        self.push_goto_target(&in0.read().unwrap());
                    }
                }
            }
            _ => {
                self.emit.print("if (");
                if let Some(in1) = op.get_in(1) {
                    self.emit_condition(&in1);
                }
                self.emit.print(") goto ");
                if let Some(in0) = op.get_in(0) {
                    self.push_goto_target(&in0.read().unwrap());
                }
            }
        }
    }

    fn op_branch(&mut self, op: &PcodeOp) {
        use crate::op::branch_type;
        match op.branch_type {
            branch_type::BREAK => {
                self.emit.print("break");
            }
            branch_type::CONTINUE => {
                if self.loop_depth > 0 {
                    self.emit.print("continue");
                } else {
                    self.emit.print("goto ");
                    if let Some(in0) = op.get_in(0) {
                        self.push_goto_target(&in0.read().unwrap());
                    }
                }
            }
            _ => {
                self.emit.print("goto ");
                if let Some(in0) = op.get_in(0) {
                    self.push_goto_target(&in0.read().unwrap());
                }
            }
        }
    }

    fn push_type(&mut self, dt: &Datatype) {
        self.emit.tag_type(dt.get_name(), dt.get_id());
    }

    fn push_varnode(&mut self, vn: &Varnode, _op: Option<&PcodeOp>) {
        use crate::space::AddressSpace;

        // Priority 0: Resolve known symbols/strings by address (overrides any auto-generated name)
        let addr = vn.get_offset();
        let space = vn.get_space();

        // Check if this constant is used in a bitwise operation — if so, skip string resolution.
        // Constants in XOR/AND/OR/shift are bitmasks, not string addresses, even if they
        // happen to fall within .rodata address range.
        let is_bitwise_context = _op.map_or(false, |op| matches!(op.opcode,
            OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR
            | OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT
        ));

        if matches!(space, AddressSpace::Ram | AddressSpace::Const) {
            if let Some(sym_name) = self.symbol_table.get(&addr) {
                self.used_varnode_names.insert(sym_name.clone());
                if !self.discovery_pass {
                    self.emit.tag_variable(sym_name, 0);
                }
                return;
            }
            if !is_bitwise_context {
                if let Some(str_val) = self.string_table.get(&addr) {
                    if !self.discovery_pass {
                        let display = if str_val.len() > 80 {
                            format!("{} (continues)", &str_val[..60])
                        } else {
                            str_val.clone()
                        };
                        self.emit.print(&format!("\"{}\"", escape_c_string(&display)));
                    }
                    return;
                }
                // Substring lookup: check if addr falls within a known string
                // (e.g., pointer to middle of a .rodata string)
                if addr >= 256 {
                    for (&str_addr, str_val) in &self.string_table {
                        if addr > str_addr && addr < str_addr + str_val.len() as u64 {
                            let offset = (addr - str_addr) as usize;
                            let substr = &str_val[offset..];
                            if !self.discovery_pass {
                                let display = if substr.len() > 80 {
                                    format!("{} (continues)", &substr[..60])
                                } else {
                                    substr.to_string()
                                };
                                self.emit.print(&format!("\"{}\"", escape_c_string(&display)));
                            }
                            return;
                        }
                    }
                }
            }
        }

        // Priority 0.5: Parameter names always take precedence for Register varnodes
        if vn.get_space() == AddressSpace::Register {
            if let Some(pname) = self.param_names.get(&vn.get_offset()) {
                self.used_varnode_names.insert(pname.clone());
                if !self.discovery_pass {
                    self.emit.tag_variable(pname, 0);
                }
                return;
            }
        }

        // Priority 1: Use HighVariable name if available (from Merge pass)
        // But NOT for Const-space varnodes — those should always display as literal values
        if vn.get_space() != AddressSpace::Const {
        if let Some(ref high_arc) = vn.high {
            let high = high_arc.read().unwrap();
            let name = high.get_name();
            if !name.is_empty() {
                // Convert raw register names to local variable names
                // (except RSP/RBP which are kept as stack/frame pointers)
                let display_name = if Self::is_raw_register_name(name)
                    && name != "RSP" && name != "ESP" && name != "RBP" && name != "EBP"
                {
                    if let Some(pname) = self.param_names.get(&vn.get_offset()) {
                        pname.clone()
                    } else {
                        let prefix = Self::var_prefix(&vn.v_type, vn.get_size());
                        format!("{}_{:x}", prefix, vn.get_offset())
                    }
                } else {
                    Self::maybe_apply_type_prefix(name, &vn.v_type, vn.get_size())
                };
                let name = &display_name;

                // Priority 1.5: For generic uVarN names on Register/Unique varnodes,
                // try to resolve through the def chain to emit more meaningful output
                // (constants, symbol names, RIP-relative addresses).
                if name.starts_with("uVar") && self.inline_depth < 8 && !self.is_lhs {
                    let key = (vn.get_space(), vn.get_offset());
                    if let Some(def_op_arc) = self.value_def_map.get(&key).cloned() {
                        let def_op = def_op_arc.read().unwrap();

                        // Case A: COPY from a Const → emit the constant value directly
                        if def_op.opcode == OpCode::CPUI_COPY && !def_op.inrefs.is_empty() {
                            let src_space = def_op.inrefs[0].read().unwrap().get_space();
                            let src_offset = def_op.inrefs[0].read().unwrap().get_offset();
                            let _src_size = def_op.inrefs[0].read().unwrap().get_size();

                            if src_space == AddressSpace::Const {
                                // Check if const is a known symbol
                                if let Some(sym_name) = self.symbol_table.get(&src_offset) {
                                    self.used_varnode_names.insert(sym_name.clone());
                                    if !self.discovery_pass {
                                        self.emit.tag_variable(sym_name, 0);
                                    }
                                    return;
                                }
                                if let Some(str_val) = self.string_table.get(&src_offset) {
                                    if !self.discovery_pass {
                                        self.emit.print(&format!("\"{}\"", escape_c_string(str_val)));
                                    }
                                    return;
                                }
                                // Substring lookup in Case A
                                if src_offset >= 256 {
                                    let mut found_substr = false;
                                    for (&sa, sv) in &self.string_table {
                                        if src_offset > sa && src_offset < sa + sv.len() as u64 {
                                            let off = (src_offset - sa) as usize;
                                            if !self.discovery_pass {
                                                self.emit.print(&format!("\"{}\"", escape_c_string(&sv[off..])));
                                            }
                                            found_substr = true;
                                            break;
                                        }
                                    }
                                    if found_substr { return; }
                                }
                                // Plain constant
                                if !self.discovery_pass {
                                    if src_offset <= 9 {
                                        self.emit.print(&format!("{}", src_offset));
                                    } else if src_offset >= 0x8000_0000_0000_0000 {
                                        // Likely negative: show as signed
                                        let signed = src_offset as i64;
                                        self.emit.print(&format!("{}", signed));
                                    } else if src_offset == 0xffffffff {
                                        self.emit.print("-1"); // (uint32_t)-1
                                    } else if src_offset >= 256 {
                                        self.emit.print(&format!("0x{:x} /* {} */", src_offset, src_offset));
                                    } else {
                                        self.emit.print(&format!("0x{:x}", src_offset));
                                    }
                                }
                                return;
                            }
                            // Case B: COPY from Unique → try to inline the Unique's def
                            if src_space == AddressSpace::Unique {
                                let unique_key = (AddressSpace::Unique, src_offset);
                                drop(def_op);
                                if let Some(unique_def_arc) = self.value_def_map.get(&unique_key).cloned()
                                    .or_else(|| self.inline_candidates.get(&unique_key).cloned())
                                {
                                    let unique_def = unique_def_arc.read().unwrap();
                                    // RIP-relative? Just emit the non-RIP operand
                                    if let Some(non_rip_idx) = self.get_rip_relative_operand(&unique_def) {
                                        self.inline_depth += 1;
                                        self.push_input(&unique_def, non_rip_idx);
                                        self.inline_depth -= 1;
                                        return;
                                    }
                                    // Other inlineable expression
                                    self.inline_depth += 1;
                                    self.inlined_ops.insert(*unique_def.get_seq_num());
                                    self.emit_inline_expr(&unique_def);
                                    self.inline_depth -= 1;
                                    return;
                                }
                                // Fall through — def_op was dropped, can't use Case C
                            } else {
                                // Case C: Direct RIP-relative INT_ADD on this Register varnode
                                if let Some(non_rip_idx) = self.get_rip_relative_operand(&def_op) {
                                    if non_rip_idx < def_op.inrefs.len() {
                                        let input_arc = def_op.inrefs[non_rip_idx].clone();
                                        drop(def_op);
                                        self.inline_depth += 1;
                                        self.push_varnode(&input_arc.read().unwrap(), None);
                                        self.inline_depth -= 1;
                                        return;
                                    }
                                }
                            }
                        } else {
                            // Not a COPY — check for direct RIP-relative
                            if let Some(non_rip_idx) = self.get_rip_relative_operand(&def_op) {
                                if non_rip_idx < def_op.inrefs.len() {
                                    let input_arc = def_op.inrefs[non_rip_idx].clone();
                                    drop(def_op);
                                    self.inline_depth += 1;
                                    self.push_varnode(&input_arc.read().unwrap(), None);
                                    self.inline_depth -= 1;
                                    return;
                                }
                            }
                        }
                    }
                }

                // Priority 1.7: Check inline candidates for single-use Register vars
                // (def chain failed, but var is single-use and inlineable)
                if !self.is_lhs && self.inline_depth < 8 {
                    let key = (vn.get_space(), vn.get_offset());
                    if let Some(def_op_arc) = self.inline_candidates.get(&key).cloned() {
                        self.inline_depth += 1;
                        let def_op = def_op_arc.read().unwrap();
                        self.emit_inline_expr(&def_op);
                        self.inline_depth -= 1;
                        return;
                    }
                }

                self.mark_varnode_used(name.to_string(), vn);
                if !self.discovery_pass {
                    self.emit.tag_variable(name, 0);
                }
                return;
            }
        }
        } // end if not Const space

        // Priority 2: Fall back to raw address-based naming
        let name = match vn.get_space() {
            AddressSpace::Register => {
                // Priority: parameter name > local variable name
                if let Some(pname) = self.param_names.get(&vn.get_offset()) {
                    pname.clone()
                } else {
                    // Check inline candidates for single-use Register-space vars
                    if !self.is_lhs && self.inline_depth < 8 {
                        let key = (AddressSpace::Register, vn.get_offset());
                        if let Some(def_op_arc) = self.inline_candidates.get(&key).cloned() {
                            self.inline_depth += 1;
                            let def_op = def_op_arc.read().unwrap();
                            self.emit_inline_expr(&def_op);
                            self.inline_depth -= 1;
                            return;
                        }
                    }
                    // Keep RSP/ESP and RBP/EBP as-is (stack/frame pointers)
                    // Convert all other registers to local variable names
                    match (vn.get_offset(), vn.get_size()) {
                        (0x20, 8) => "RSP".to_string(),
                        (0x20, 4) => "ESP".to_string(),
                        (0x28, 8) => "RBP".to_string(),
                        (0x28, 4) => "EBP".to_string(),
                        (off, sz) => {
                            // Generate Ghidra-style local variable name based on size
                            let prefix = match sz {
                                8 => "lVar",   // long
                                4 => "iVar",   // int
                                2 => "sVar",   // short
                                1 => "bVar",   // byte
                                _ => "uVar",   // unknown
                            };
                            format!("{}_{:x}", prefix, off)
                        }
                    }
                }
            }
            AddressSpace::Const => {
                let val = vn.get_offset();
                // Symbol/string lookups are handled at Priority 0 above.
                if val <= 9 {
                    format!("{}", val)
                } else if val >= 0x8000_0000_0000_0000 {
                    // Likely negative signed value
                    format!("{}", val as i64)
                } else if val == 0xffffffff {
                    "-1".to_string() // (uint32_t)-1
                } else if val >= 0x20 && val <= 0x7e {
                    // Printable ASCII — show as char literal only for clearly char-like values
                    // that are NEVER used as sizes/counts/flags (letters, some punctuation)
                    let ch = val as u8 as char;
                    // Brace/paren/bracket chars in single quotes ('}', '{', ')') confuse
                    // text-level brace counting in post-process passes. Emit them as hex
                    // escape instead so the literal braces aren't mistaken for code braces.
                    let needs_escape = matches!(ch, '}' | '{' | ')' | '(' | '\'' | '\\' | '"')
                        || ch == '\0';
                    if needs_escape {
                        format!("'\\x{:x}'", val as u8)
                    } else if ch.is_ascii_alphabetic() || "/=.@[]".contains(ch) {
                        format!("'{}'", ch)
                    } else {
                        // Numbers 0-9, and punctuation like - & * ( ) + etc.
                        // Often used as numeric values (sizes, flags), keep as numeric
                        if val >= 10 {
                            format!("0x{:x}", val)
                        } else {
                            format!("{}", val)
                        }
                    }
                } else if val >= 256 {
                    format!("0x{:x} /* {} */", val, val)
                } else {
                    format!("0x{:x}", val)
                }
            }
            AddressSpace::Stack => {
                let off = vn.get_offset();
                if off >= 0x8000_0000_0000_0000 {
                    // Negative offset (local variable)
                    format!("local_{:x}", (!off).wrapping_add(1))
                } else {
                    format!("param_stack_{:x}", off)
                }
            }
            AddressSpace::Unique => {
                let key = (AddressSpace::Unique, vn.get_offset());
                if self.inline_depth < 8 {
                    if let Some(def_op_arc) = self.inline_candidates.get(&key).cloned() {
                        self.inline_depth += 1;
                        if !self.discovery_pass {
                            self.emit.print("(");
                        }
                        let def_op = def_op_arc.read().unwrap();
                        self.emit_inline_expr(&def_op);
                        if !self.discovery_pass {
                            self.emit.print(")");
                        }
                        self.inline_depth -= 1;
                        return;
                    }
                }
                format!("uVar_{:x}", vn.get_offset())
            }
            AddressSpace::Ram => {
                // Symbol/string lookups are handled at Priority 0 above.
                // If we reach here, it's an unresolved RAM address.
                format!("DAT_{:08x}", vn.get_offset())
            }
            _ => {
                format!("v_{}_{:x}", vn.get_size(), vn.get_offset())
            }
        };

        self.mark_varnode_used(name.clone(), vn);
        if !self.discovery_pass {
            self.emit.tag_variable(&name, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use crate::opcodes::OpCode;
    use crate::prettyprint::EmitNoMarkup;

    #[test]
    fn test_print_c_copy() {
        let emit = Box::new(EmitNoMarkup::new());
        let mut printer = PrintC::new(emit);

        let mut vbank = crate::varnode::VarnodeBank::new();
        let out_vn = vbank.create(4, Address::new(0x1000));
        let in_vn = vbank.create(4, Address::new(0x2000));

        let mut op = PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x100), 0),
            OpCode::CPUI_COPY,
        );
        op.output = Some(out_vn);
        op.inrefs.push(in_vn);

        printer.op_copy(&op);
        // Verify emission doesn't panic
    }

    #[test]
    fn test_doc_function_stub() {
        let emit = Box::new(EmitNoMarkup::new());
        let mut printer = PrintC::new(emit);
        let fd = Funcdata::new("test_func", Address::new(0x1000), 0x100);

        printer.doc_function(&fd);
    }

    #[test]
    fn test_type_cast_load_typed_dereference() {
        // Test that op_load emits *(int * ) addr when address has pointer type
        use crate::type_system::datatype::{TypeBase, TypeMetatype, TypePointer};

        let emit = Box::new(EmitNoMarkup::new());
        let mut printer = PrintC::new(emit);

        let mut vbank = crate::varnode::VarnodeBank::new();
        let out_vn = vbank.create_with_space(4, crate::space::AddressSpace::Unique, 0x30);
        let space_vn = vbank.create_constant(4, 0); // space id for LOAD
        let addr_vn = vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x38); // RDI

        // Set pointer type on addr_vn
        let int_type = std::sync::Arc::new(crate::type_system::Datatype::Base(
            TypeBase::new("int".to_string(), 4, TypeMetatype::Int),
        ));
        let int_ptr_type = std::sync::Arc::new(crate::type_system::Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: int_type.clone(),
            wordsize: 1,
        }));
        addr_vn.write().unwrap().v_type = Some(int_ptr_type);

        let mut op = PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x100), 0),
            OpCode::CPUI_LOAD,
        );
        op.output = Some(out_vn);
        op.inrefs.push(space_vn);
        op.inrefs.push(addr_vn);

        printer.op_load(&op);

        let output = printer.take_emit();
        let text = output.into_any().downcast::<EmitNoMarkup>().unwrap().get_output();
        // Should contain typed dereference
        assert!(text.contains("int *"), "Expected typed dereference with 'int *', got: {}", text);
    }

    #[test]
    fn test_type_cast_zext_uses_output_type() {
        // Test that op_unary for ZEXT uses output type name instead of hardcoded (uint)
        use crate::type_system::datatype::{TypeBase, TypeMetatype};

        let emit = Box::new(EmitNoMarkup::new());
        let mut printer = PrintC::new(emit);

        let mut vbank = crate::varnode::VarnodeBank::new();
        let out_vn = vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x00); // RAX
        let in_vn = vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);  // EAX-like

        // Set output type to "long"
        let long_type = std::sync::Arc::new(crate::type_system::Datatype::Base(
            TypeBase::new("long".to_string(), 8, TypeMetatype::Int),
        ));
        out_vn.write().unwrap().v_type = Some(long_type);

        let mut op = PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x200), 0),
            OpCode::CPUI_INT_ZEXT,
        );
        op.output = Some(out_vn);
        op.inrefs.push(in_vn);

        printer.op_unary(&op);

        let output = printer.take_emit();
        let text = output.into_any().downcast::<EmitNoMarkup>().unwrap().get_output();
        // Should use "long" instead of hardcoded "uint"
        assert!(text.contains("(long)"), "Expected (long) cast, got: {}", text);
        assert!(!text.contains("(uint)"), "Should NOT contain hardcoded (uint), got: {}", text);
    }

    #[test]
    fn test_param_name_resolution() {
        // Test that push_varnode uses param names instead of register names
        let emit = Box::new(EmitNoMarkup::new());
        let mut printer = PrintC::new(emit);

        // Simulate parameter detected at RDI (offset 0x38)
        printer.param_names.insert(0x38, "param_1".to_string());

        let mut vbank = crate::varnode::VarnodeBank::new();
        let rdi_vn = vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x38);
        let const_vn = vbank.create_constant(8, 42);

        // Create ADD op: param_1 + 42
        let out_vn = vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x00);
        let mut op = PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x300), 0),
            OpCode::CPUI_INT_ADD,
        );
        op.output = Some(out_vn);
        op.inrefs.push(rdi_vn);
        op.inrefs.push(const_vn);

        printer.op_binary(&op);

        let output = printer.take_emit();
        let text = output.into_any().downcast::<EmitNoMarkup>().unwrap().get_output();
        // Should use "param_1" instead of "RDI"
        assert!(text.contains("param_1"), "Expected 'param_1', got: {}", text);
        assert!(!text.contains("RDI"), "Should NOT contain 'RDI', got: {}", text);
    }
}
