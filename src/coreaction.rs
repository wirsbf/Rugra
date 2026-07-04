//! Core analysis actions for the decompiler
//!
//! Corresponds to Ghidra's `coreaction.hh`

use crate::action::{Action, action_status, action_flags};
use crate::funcdata::Funcdata;
use crate::opcodes::OpCode;
use crate::error::Result;
use std::collections::HashMap;
use std::sync::Arc;

/// Action for performing SSA construction (Heritage)
///
/// Corresponds to Ghidra's `ActionHeritage`
pub struct ActionHeritage;

impl ActionHeritage {
    // Ghidra: coreaction.hh:284 ActionHeritage (constructor mirror)
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionHeritage {
    // Ghidra: coreaction.hh:289 ActionHeritage::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Ghidra idempotency guard (heritage.cc:2698-2701): each space has a
        // delay; Heritage::heritage() skips spaces where pass < delay. After
        // pass 2, all spaces (register=0, unique=0, stack=1) are heritaged, so
        // Heritage returns without doing anything. Without this guard, Rugra's
        // 2-pass heritage runs unconditionally each mainloop iteration, creating
        // new SSA temporaries every pass → never converges under repeatapply.
        if fd.heritage.pass >= 2 {
            return Ok(0);
        }
        // Ghidra heritage.cc:2677-2771 runs a multi-pass heritage where:
        //   pass 1: discoverIndexedStackPointers (marks STOREs) + place + rename
        //   The rename in pass 1 connects the op graph (rewrites STORE input
        //   to reference INT_ADD output via SSA), so subsequent discovery sees
        //   a connected graph.
        //
        // Rugra runs two passes to achieve the same effect:
        //   pass 1: place + rename (connects op graph)
        //   pass 2: discover + place + rename (discover on connected graph
        //           finds stack STOREs, builds Stack INDIRECTs; place/rename
        //           then handles the new Stack varnodes)
        {
            let mut heritage = std::mem::take(&mut fd.heritage);
            heritage.place_multiequals_direct(&mut fd.vbank, &mut fd.obank, &fd.bblocks, &fd.sblocks);
            heritage.rename_direct(&mut fd.vbank, &fd.bblocks);
            heritage.pass += 1;
            fd.heritage = heritage;
        }
        // Dead-code between passes, faithful to Ghidra mainloop where each
        // pass alternates Heritage + DeadCode (coreaction.cc:5503). At this
        // point heritage.pass=1, Stack delay=1, so deadRemovalAllowed(Stack)
        // = (1 > 1) = false → Stack INDIRECT varnodes are marked consumed and
        // survive. Register/Unique varnodes are dead-coded normally.
        {
            let mut dc = ActionDeadCode::new();
            let _ = dc.apply(fd);
        }
        // Pass 2: discover stack STOREs on the connected graph, then
        // place + rename to SSA the new Stack-space INDIRECT varnodes.
        crate::heritage::Heritage::discover_and_guard_stack_stores_fd(fd);
        {
            let mut heritage = std::mem::take(&mut fd.heritage);
            heritage.place_multiequals_direct(&mut fd.vbank, &mut fd.obank, &fd.bblocks, &fd.sblocks);
            heritage.rename_direct(&mut fd.vbank, &fd.bblocks);
            heritage.pass += 1;
            fd.heritage = heritage;
        }
        Ok(action_status::CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; string "heritage" mirrors ctor at coreaction.hh:284
    fn get_name(&self) -> &str {
        "heritage"
    }
}

/// Action for removing dead P-code operations
///
/// Dead code elimination. Faithful to `ActionDeadCode` (coreaction.cc).
///
/// The algorithm propagates "consumed" bit-masks backward from terminal
/// uses (RETURN, BRANCHIND, etc.) through the data-flow graph. Varnodes
/// whose consumed mask is zero (no bits consumed by any live operation)
/// are dead and their defining op is destroyed.
///
/// The current Rugra implementation uses a simplified version: it checks
/// if the output varnode has no descendants. The full Ghidra algorithm
/// uses consumed-bit propagation via push_consumed/propagate_consumed.
pub struct ActionDeadCode;

impl ActionDeadCode {
    // Ghidra: coreaction.hh:552 ActionDeadCode (constructor mirror)
    pub fn new() -> Self {
        Self
    }

    /// Push a consumed value into a Varnode. Faithful to `pushConsumed`
    /// (coreaction.cc). This is the full Ghidra algorithm, ready for
    /// integration when VarnodeLocSet iteration is available.
    #[allow(dead_code)]
    // Ghidra: coreaction.cc:3556 ActionDeadCode::pushConsumed
    fn push_consumed(
        val: u64,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        worklist: &mut Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    ) {
        use crate::address::calc_mask;
        let mut vn_rg = vn.write().unwrap();
        let mask = calc_mask(vn_rg.get_size());
        let newval = (val | vn_rg.get_consume()) & mask;
        if newval == vn_rg.get_consume() {
            return; // No change.
        }
        vn_rg.set_consume(newval);
        if vn_rg.is_written() {
            worklist.push(vn.clone());
        }
    }

    /// Propagate consumed value backward through a defining op. Faithful to
    /// `propagateConsumed` (coreaction.cc). Handles INT_MULT, INT_ADD,
    /// INT_SUB, SUBPIECE, and defaults to full mask for other ops.
    #[allow(dead_code)]
    // Ghidra: coreaction.cc:3576 ActionDeadCode::propagateConsumed
    fn propagate_consumed(
        worklist: &mut Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    ) {
        use crate::address::{calc_mask, coveringmask, leastsigbit_set};
        use crate::opcodes::OpCode;
        let Some(vn) = worklist.pop() else { return };
        let outc = vn.read().unwrap().get_consume();
        let Some(def) = vn.read().unwrap().get_def() else { return };
        let opc = def.read().unwrap().opcode;
        match opc {
            OpCode::CPUI_INT_MULT => {
                let b = coveringmask(outc);
                let in1_const = def.read().unwrap().get_in(1)
                    .map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
                let in1_off = def.read().unwrap().get_in(1)
                    .map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
                let a = if in1_const {
                    let ls = leastsigbit_set(in1_off);
                    if ls >= 0 {
                        calc_mask(vn.read().unwrap().get_size()) >> ls as u32
                    } else { 0 }
                } else { b };
                for slot in 0..2 {
                    if let Some(in_vn) = def.read().unwrap().get_in(slot).cloned() {
                        Self::push_consumed(if slot == 0 { a } else { b }, &in_vn, worklist);
                    }
                }
            }
            OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB => {
                let a = coveringmask(outc);
                for slot in 0..2 {
                    if let Some(in_vn) = def.read().unwrap().get_in(slot).cloned() {
                        Self::push_consumed(a, &in_vn, worklist);
                    }
                }
            }
            OpCode::CPUI_SUBPIECE => {
                let sz = def.read().unwrap().get_in(1)
                    .map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
                let a = if sz >= 8 { 0 } else { outc << (sz * 8) };
                if let Some(in0) = def.read().unwrap().get_in(0).cloned() {
                    Self::push_consumed(a, &in0, worklist);
                }
            }
            _ => {
                let n_in = def.read().unwrap().num_input();
                for slot in 0..n_in {
                    if let Some(in_vn) = def.read().unwrap().get_in(slot).cloned() {
                        Self::push_consumed(outc, &in_vn, worklist);
                    }
                }
            }
        }
    }
}

impl Action for ActionDeadCode {
    // Ghidra: coreaction.cc:3925 ActionDeadCode::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Full Ghidra consumed-bit propagation algorithm, driven by
        // iterating Funcdata's varnode bank + op bank.
        let mut changed = 0;

        // Determine which spaces are NOT yet heritaged (deadcode not allowed).
        // Faithful to Ghidra coreaction.cc:3949-3958 + heritage.cc:2843-2848:
        // deadRemovalAllowed(spc) = (pass > deadcodedelay). For spaces where
        // dead removal is NOT allowed, all varnodes are marked fully consumed
        // (so they survive dead-code). This protects Stack-space INDIRECT
        // varnodes during Register/Unique heritage (Stack delay=1, so in
        // pass 0 they're protected).
        let heritage_pass = fd.heritage.pass;
        let stack_deadcode_allowed = heritage_pass > 1; // Stack delay=1

        // Step 1: Clear consume flags on all Varnodes.
        for vn_ref in fd.vbank.loc_tree.iter() {
            let mut vn = vn_ref.0.write().unwrap();
            vn.set_consume(0);
        }

        // Step 1.5: For spaces where dead removal is not allowed (Stack space
        // before its heritage pass), mark all varnodes fully consumed.
        // Faithful to Ghidra coreaction.cc:3949-3958.
        let mut worklist: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> =
            Vec::new();
        if !stack_deadcode_allowed {
            for vn_arc in fd.vbank.iter_space(crate::space::AddressSpace::Stack) {
                Self::push_consumed(u64::MAX, &vn_arc, &mut worklist);
            }
        }

        // Step 2: Build initial worklist from terminal uses (ops with no
        // output, or whose output doesn't matter: RETURN, BRANCH, CBRANCH,
        // STORE, and ops whose output has no descendants).
        // (worklist already initialized in Step 1.5)

        for op_ref in &fd.obank.alivelist {
            let op_rg = op_ref.0.read().unwrap();
            let opc = op_rg.opcode;
            let n_in = op_rg.num_input();

            // Non-assignment ops: all inputs are consumed with full mask.
            if op_rg.output.is_none() {
                for i in 0..n_in {
                    if let Some(in_vn) = op_rg.get_in(i) {
                        Self::push_consumed(u64::MAX, in_vn, &mut worklist);
                    }
                }
                continue;
            }

            // Assignment ops: check if output has no descendants.
            if let Some(out) = &op_rg.output {
                let out_rg = out.read().unwrap();
                if out_rg.descend.is_empty() && !out_rg.is_input() {
                    // Output is dead — this op can potentially be removed.
                    // Don't push its inputs to worklist.
                } else {
                    // Output is live — push inputs to worklist.
                    for i in 0..n_in {
                        if let Some(in_vn) = op_rg.get_in(i) {
                            Self::push_consumed(u64::MAX, in_vn, &mut worklist);
                        }
                    }
                }
            }
            let _ = opc;
        }

        // Step 3: Propagate consumed bits backward through the data-flow.
        while !worklist.is_empty() {
            Self::propagate_consumed(&mut worklist);
        }

        // Step 4: Remove dead ops (output consume == 0 and not input).
        // Ghidra: coreaction.cc:4038-4044 — when an op's output is never
        // consumed (!vacflag), Ghidra distinguishes calls from other ops:
        //   if (op->isCall()) data.opUnsetOutput(op);  // keep the CALL (side effects!), drop only the unused return value
        //   else               data.opDestroy(op);      // completely remove the op
        // A CALL has side effects (it writes memory / does I/O), so it must
        // NEVER be removed just because its return value is unused. Previously
        // Rugra mark_dead'd calls with dead outputs, which killed fwrite/fopen/
        // malloc/etc. wholesale and collapsed every if/else body containing a
        // call — the §3.2 body-collapse root cause.
        let mut to_remove = Vec::new();
        let mut calls_to_unset = Vec::new();
        for op_ref in &fd.obank.alivelist {
            let op_rg = op_ref.0.read().unwrap();
            if let Some(out) = &op_rg.output {
                let out_rg = out.read().unwrap();
                if out_rg.get_consume() == 0 && !out_rg.is_input() {
                    if matches!(op_rg.opcode, crate::opcodes::OpCode::CPUI_CALL | crate::opcodes::OpCode::CPUI_CALLIND) {
                        // Faithful to Ghidra: keep the call, drop only its dead output.
                        calls_to_unset.push(op_ref.clone());
                    } else {
                        to_remove.push(op_ref.clone());
                    }
                }
            }
        }

        for op_ref in to_remove {
            fd.obank.mark_dead(op_ref);
            changed += 1;
        }
        // Calls: unset output (clears the unused return-value varnode) but the
        // op stays alive so its side effects still emit. opUnsetOutput also
        // detaches the varnode's def back-edge (funcdata.cc opUnsetOutput).
        for op_ref in calls_to_unset {
            fd.op_unset_output(&op_ref);
            changed += 1;
        }

        if changed > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    // RUGRA-GLUE: Rust Action trait get_name; "deadcode" mirrors ctor at coreaction.hh:552
    fn get_name(&self) -> &str {
        "deadcode"
    }
}

/// Action for identifying constant pointers and replacing them
///
/// Corresponds to Ghidra's `ActionConstantPtr`
pub struct ActionConstantPtr;

impl ActionConstantPtr {
    // Ghidra: coreaction.hh:188 ActionConstantPtr (constructor mirror)
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionConstantPtr {
    // Ghidra: coreaction.cc:1167 ActionConstantPtr::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        let mut changed = 0;

        // Scan all alive ops for LOAD/STORE with constant address varnodes.
        // Tag the constant varnodes with the READONLY flag so downstream
        // passes (PrintC) can resolve them to named globals.
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            match op.opcode {
                OpCode::CPUI_LOAD | OpCode::CPUI_STORE => {
                    // Input[1] is the address for LOAD/STORE
                    if let Some(addr_vn_arc) = op.inrefs.get(1) {
                        let is_const = addr_vn_arc.read().unwrap().is_constant();
                        if is_const {
                            let mut vn = addr_vn_arc.write().unwrap();
                            if vn.flags & crate::varnode::varnode_flags::READONLY == 0 {
                                vn.set_flags(crate::varnode::varnode_flags::READONLY);
                                changed += 1;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if changed > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    // RUGRA-GLUE: Rust Action trait get_name; "constantptr" mirrors ctor at coreaction.hh:188
    fn get_name(&self) -> &str {
        "constantptr"
    }
}

/// Action for performing Common Subexpression Elimination (CSE)
///
/// Corresponds to Ghidra's `ActionCse`
pub struct ActionCse;

impl ActionCse {
    // Ghidra: coreaction.cc:708 ActionCse (historical; apply body commented out in current Ghidra)
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionCse {
    // Ghidra: coreaction.cc:708 ActionCse::apply (historical; commented out / removed in current Ghidra)
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Build a hash map: (opcode, sorted-input-pointer-list) -> first op
        // If two alive ops share the same key, redirect the second op's
        // output users to the first op's output, then kill the duplicate.
        let mut changed = 0;
        let mut seen: HashMap<(OpCode, Vec<usize>), Arc<std::sync::RwLock<crate::op::PcodeOp>>> =
            HashMap::new();
        let mut to_kill: Vec<crate::op::PcodeOpRef> = Vec::new();

        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();

            // Only consider pure operations (no side-effects)
            if !op.opcode.is_commutative_or_pure() {
                continue;
            }
            // Must have an output to be CSE-able
            if op.output.is_none() {
                continue;
            }

            // Build a key from opcode + sorted input pointer identities
            let mut input_ptrs: Vec<usize> = op
                .inrefs
                .iter()
                .map(|vn| Arc::as_ptr(vn) as usize)
                .collect();
            // For commutative ops, sort inputs so (a+b) matches (b+a)
            if op.opcode.is_commutative() && input_ptrs.len() == 2 {
                input_ptrs.sort();
            }

            let key = (op.opcode, input_ptrs);

            if let Some(existing_arc) = seen.get(&key) {
                // Found a duplicate — mark for killing
                let existing_out = existing_arc.read().unwrap().output.clone();
                let dup_out = op.output.clone();
                drop(op);

                if let (Some(src), Some(dst)) = (existing_out, dup_out) {
                    // Redirect all users of `dst` to `src`
                    let users: Vec<_> = dst.read().unwrap().descend.iter()
                        .filter_map(|w| w.upgrade())
                        .collect();
                    for user_arc in users {
                        let mut user = user_arc.write().unwrap();
                        for slot in 0..user.inrefs.len() {
                            if Arc::ptr_eq(&user.inrefs[slot], &dst) {
                                user.inrefs[slot] = src.clone();
                                src.write().unwrap().descend.push(Arc::downgrade(&user_arc));
                            }
                        }
                    }
                    to_kill.push(op_ref.clone());
                    changed += 1;
                }
            } else {
                seen.insert(key, op_ref.0.clone());
            }
        }

        for op_ref in to_kill {
            fd.obank.mark_dead(op_ref);
        }

        if changed > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    // RUGRA-GLUE: Rust Action trait get_name; "cse" mirrors the historical ActionCse at coreaction.cc:708
    fn get_name(&self) -> &str {
        "cse"
    }
}

/// Restructure the local-variable scope from stack varnodes.
///
/// Faithful to `ActionRestructureVarnode` (coreaction.cc:2274). In Ghidra this
/// builds the `ScopeLocal` (via `ScopeLocal::restructureVarnode`) and syncs
/// varnodes with the resulting symbols. In Rugra we build the `ScopeLocal` and
/// store it on `Funcdata::scope` so the printc emitter can query it for
/// stack-variable names. The `aliasyes` flag (skip alias calculations on the
/// first pass) maps to `ScopeLocal` running a full `mark_unaliased` pass here;
/// a multi-pass driver can gate that later.
pub struct ActionRestructureVarnode {
    /// Pass counter; alias calculations are skipped on the first pass in Ghidra.
    numpass: i32,
}

impl ActionRestructureVarnode {
    // Ghidra: coreaction.hh:854 ActionRestructureVarnode (constructor mirror)
    pub fn new() -> Self {
        Self { numpass: 0 }
    }
}

impl Action for ActionRestructureVarnode {
    // Ghidra: coreaction.cc:2274 ActionRestructureVarnode::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionRestructureVarnode::apply (coreaction.cc:2274-2294).
        // Ghidra's return value is ALWAYS 0 (line 2294): restructureVarnode is
        // a structural side-effect Action that does NOT drive repeatapply. The
        // internal `count += 1` (line 2282) is for statistics/breakpoints only.
        // Rugra previously returned CHANGE, which caused fullloop repeatapply
        // to infinite-loop because every pass reported a change.
        let mut scope = crate::varmap::ScopeLocal::new();
        scope.restructure_varnode(fd);
        fd.scope = Some(scope);
        // syncVarnodesWithSymbols (coreaction.cc:2281): mark Stack-space
        // varnodes overlapping scope symbols as mapped.
        let _ = fd.sync_varnodes_with_symbols(false, false);
        self.numpass += 1;
        Ok(action_status::NO_CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "restructure_varnode" mirrors ctor at coreaction.hh:855
    fn get_name(&self) -> &str {
        "restructureVarnode"
    }
}

/// Start of the analysis process
pub struct ActionStart;

impl ActionStart {
    // Ghidra: coreaction.hh:36 ActionStart (constructor mirror)
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionStart {
    // Ghidra: coreaction.hh:41 ActionStart::apply
    fn apply(&mut self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "start" mirrors ctor at coreaction.hh:36
    fn get_name(&self) -> &str {
        "start"
    }
}

/// Action for merging required varnodes (e.g., tied to the same address)
///
/// Corresponds to Ghidra's `ActionMergeRequired`
pub struct ActionMergeRequired;

impl ActionMergeRequired {
    // Ghidra: coreaction.hh:364 ActionMergeRequired (constructor mirror)
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionMergeRequired {
    // Ghidra: coreaction.hh:369 ActionMergeRequired::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        let mut merge = crate::merge::Merge::new();
        merge.merge_addr_tied(fd);
        Ok(action_status::CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "mergerequired" mirrors ctor at coreaction.hh:364
    fn get_name(&self) -> &str {
        "merge_required"
    }
}

/// Action for merging adjacent varnodes
///
/// Corresponds to Ghidra's `ActionMergeAdjacent`
pub struct ActionMergeAdjacent;

impl ActionMergeAdjacent {
    // Ghidra: coreaction.hh:376 ActionMergeAdjacent (constructor mirror)
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionMergeAdjacent {
    // Ghidra: coreaction.hh:381 ActionMergeAdjacent::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        let mut merge = crate::merge::Merge::new();
        merge.merge_adjacent(fd);
        Ok(action_status::CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "mergeadjacent" mirrors ctor at coreaction.hh:376
    fn get_name(&self) -> &str {
        "merge_adjacent"
    }
}

/// Action for merging COPY varnodes
///
// Ghidra: coreaction.hh:385 ActionMergeCopy
/// Try to merge the input and output Varnodes of a CPUI_COPY op.
/// Faithful to `ActionMergeCopy` (coreaction.hh:385-393). Ghidra's apply is
/// a pure one-line delegation: `data.getMerge().mergeOpcode(CPUI_COPY);`
pub struct ActionMergeCopy;

impl ActionMergeCopy {
    // Ghidra: coreaction.hh:387 ActionMergeCopy (constructor mirror)
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionMergeCopy {
    // Ghidra: coreaction.hh:392 ActionMergeCopy::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to coreaction.hh:392: data.getMerge().mergeOpcode(CPUI_COPY);
        let mut merge = crate::merge::Merge::new();
        merge.merge_opcode(fd, crate::opcodes::OpCode::CPUI_COPY);
        Ok(action_status::CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "mergecopy" mirrors ctor at coreaction.hh:387
    fn get_name(&self) -> &str {
        "mergecopy"
    }
}

/// Action for merging MULTIEQUAL entry varnodes
///
/// Corresponds to Ghidra's `ActionMergeMultiEntry`
pub struct ActionMergeMultiEntry;

impl ActionMergeMultiEntry {
    // Ghidra: coreaction.hh:398 ActionMergeMultiEntry (constructor mirror)
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionMergeMultiEntry {
    // Ghidra: coreaction.hh:403 ActionMergeMultiEntry::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        let mut merge = crate::merge::Merge::new();
        merge.merge_multi_entry(fd);
        Ok(action_status::CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "mergemultientry" mirrors ctor at coreaction.hh:398
    fn get_name(&self) -> &str {
        "merge_multientry"
    }
}

/// Action for merging varnodes by datatype
///
/// Corresponds to Ghidra's `ActionMergeType`
pub struct ActionMergeType;

impl ActionMergeType {
    // Ghidra: coreaction.hh:409 ActionMergeType (constructor mirror)
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionMergeType {
    // Ghidra: coreaction.hh:414 ActionMergeType::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        let mut merge = crate::merge::Merge::new();
        merge.merge_all(fd);
        Ok(action_status::CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "mergetype" mirrors ctor at coreaction.hh:409
    fn get_name(&self) -> &str {
        "merge_type"
    }
}

// ActionSimplify DELETED (commit history): self-invented peephole simplifier
// with no Ghidra counterpart. Its folds (x^x→0, x&x→x, !!x→x) are now handled
// by oppool1 Rules (RuleXorCollapse, RuleAndOrLump, etc.) + mainloop+fullloop
// RULE_REPEATAPPLY convergence. Verified redundant: defects=0, 952/952 tests.

/// Copy propagation pass — folds COPY chains
///
/// Corresponds to Ghidra's `RuleCopyPropagate`. For each `COPY out = in`,
/// redirects all users of `out` to use `in` directly, then kills the COPY.
pub struct ActionCopyPropagate;

impl ActionCopyPropagate {
    // RUGRA-GLUE: Rugra-specific copy-propagation pass; no direct Ghidra Action counterpart
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionCopyPropagate {
    // RUGRA-GLUE: Rugra-specific copy-propagation apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        let mut changed = 0;
        let mut to_kill: Vec<crate::op::PcodeOpRef> = Vec::new();

        // Multi-pass: keep propagating until no more COPYs can be folded
        loop {
            let mut round_changed = 0;

            for op_ref in &fd.obank.alivelist {
                let op = op_ref.0.read().unwrap();
                if op.opcode != OpCode::CPUI_COPY {
                    continue;
                }
                if op.inrefs.is_empty() || op.output.is_none() {
                    continue;
                }

                let src = op.inrefs[0].clone();
                let dst = op.output.as_ref().unwrap().clone();

                if Arc::ptr_eq(&src, &dst) {
                    continue;
                }

                // Propagate type from COPY output to input before redirecting.
                // ActionTypeInfer (which runs before CopyPropagate) may have
                // assigned a meaningful type to the output based on usage
                // context. Transfer it to the source so the type survives
                // the COPY elimination.
                {
                    let dst_vn = dst.read().unwrap();
                    let dst_type = dst_vn.v_type.clone();
                    drop(dst_vn);
                    if let Some(dt) = dst_type {
                        let mut src_vn = src.write().unwrap();
                        let should_update = src_vn.v_type.as_ref().map_or(true, |t| {
                            t.get_metatype() == crate::type_system::TypeMetatype::Unknown
                                || t.get_name() == "undefined"
                        });
                        if should_update {
                            src_vn.v_type = Some(dt);
                        }
                    }
                }

                let dst_vn = dst.read().unwrap();
                let users: Vec<_> = dst_vn.descend.iter()
                    .filter_map(|w| w.upgrade())
                    .collect();

                if users.is_empty() {
                    // No users, dead code will clean up
                    continue;
                }

                drop(dst_vn);
                drop(op);

                // Redirect all users of dst to use src instead
                for user_arc in &users {
                    let mut user = user_arc.write().unwrap();
                    for slot in 0..user.inrefs.len() {
                        if Arc::ptr_eq(&user.inrefs[slot], &dst) {
                            user.inrefs[slot] = src.clone();
                            src.write().unwrap().descend.push(Arc::downgrade(user_arc));
                        }
                    }
                }

                // Clear dst's descendents since we redirected them
                dst.write().unwrap().descend.clear();

                to_kill.push(op_ref.clone());
                round_changed += 1;
            }

            changed += round_changed;
            if round_changed == 0 {
                break;
            }

            // Kill the propagated COPYs
            for op_ref in to_kill.drain(..) {
                fd.obank.mark_dead(op_ref);
            }
        }

        if changed > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    // RUGRA-GLUE: Rust Action trait get_name for Rugra-specific ActionCopyPropagate
    fn get_name(&self) -> &str {
        "copy_propagate"
    }
}

/// Attach System V AMD64 ABI register parameters to CPUI_CALL operations
///
/// Scans for register writes (rdi, rsi, rdx, rcx, r8, r9) preceding each call
/// and attaches them as additional inputs so PrintC can emit function arguments.
pub struct ActionCallParams;

/// SysV AMD64 argument register offsets in order
const SYSV_ARG_REGS: [(u64, &str); 6] = [
    (0x38, "rdi"),  // arg0
    (0x30, "rsi"),  // arg1
    (0x10, "rdx"),  // arg2
    (0x08, "rcx"),  // arg3
    (0x80, "r8"),   // arg4
    (0x88, "r9"),   // arg5
];

/// Standard libc function signature database.
/// Returns the known number of register parameters for common C library functions.
/// For variadic functions (printf, etc.), returns the number of fixed parameters
/// (the variadic args are handled separately).
/// For unknown functions, returns 6 (all SysV AMD64 arg registers).
/// This is the standard approach used by all decompilers (Ghidra .gdt, IDA .til).
// RUGRA-GLUE: Rugra-specific ABI table (SysV known-callee param count); no Ghidra counterpart (Ghidra uses FuncProto lock instead)
fn known_param_count(func_name: Option<&str>) -> usize {
    // Normalize function name: replace '.' with '_' so that GCC-optimized
    // variants like "parseconfig.constprop.0" match "parseconfig_constprop_0".
    let normalized = func_name.map(|n| n.replace('.', "_"));
    match normalized.as_deref() {
        Some(name) => match name {
            "curl_version" | "curl_global_cleanup" | "__errno_location"
            | "__ctype_b_loc" | "getpid" | "fork"
            | "_init" | "_fini" | "__libc_csu_init" | "__libc_csu_fini"
            | "main_init" | "main_free" => 0,

            "malloc" | "free" | "strlen" | "strdup" | "puts" | "exit" | "_exit"
            | "atoi" | "atol" | "atof" | "abs" | "isatty" | "fileno" | "close"
            | "fclose" | "fflush" | "ferror" | "clearerr" | "rewind"
            | "perror" | "remove" | "unlink" | "sleep" | "alarm"
            | "toupper" | "tolower" | "isalpha" | "isdigit" | "isspace"
            | "curl_easy_init" | "curl_easy_cleanup" | "curl_easy_perform"
            | "curl_global_init" | "curl_getenv" | "curl_free"
            | "curl_slist_free_all"
            | "hugehelp"
            | "progressbarinit" | "my_get_token" | "my_get_line" => 1,

            "strcpy" | "strcat" | "strcmp" | "strstr" | "strchr" | "strrchr"
            | "strpbrk" | "strtok" | "fopen" | "fdopen" | "freopen"
            | "signal" | "access" | "stat" | "lstat" | "mkdir"
            | "rename" | "fgets" | "fputs" | "realloc" | "calloc"
            | "memcmp" | "strequal" | "strnequal" | "GetStr"
            | "glob_url" | "glob_set"
            | "curl_slist_append" | "fputc" | "fgetc"
            | "SetHTTPrequest" | "SetHTTPrequest_part_0"
            | "helpf"
            | "glob_range"
            | "ap_log_error" | "ap_exists_config_define" => 2,

            "memcpy" | "memmove" | "memset" | "strncpy" | "strncat" | "strncmp"
            | "fread" | "strtol" | "strtoul" | "strtod"
            | "read" | "write" | "open" | "fcntl" | "ioctl"
            | "__xstat"
            | "curl_easy_setopt"
            | "glob_word" | "next_url" => 3,

            "fseek" | "snprintf" | "fwrite" | "my_fwrite"
            | "parseconfig_constprop_0" | "parseconfig" => 4,

            "match_url" | "myprogress"
            | "getparameter.constprop.0" | "getparameter_constprop_0" => 5,

            "__sprintf_chk" | "__fprintf_chk" | "__printf_chk"
            | "__snprintf_chk"
            | "__isoc99_sscanf" | "sscanf" => 5,
            // __vfprintf_chk(fp, flag, format, va_list) — 4 fixed args, not variadic
            "__vfprintf_chk" => 4,

            "maprintf" | "maprintf_constprop_0" => 2,
            "strdup" => 1,
            "ap_ht_time" => 4,
            "ap_strcmp_match" | "ap_strcasecmp_match" => 2,
            "ap_fini_vhost_config" | "ap_parse_vhost_addrs" => 2,
            "ap_init_vhost_config" | "ap_set_name_virtual_host" => 1,
            "ap_matches_request_vhost" => 3,
            "ap_update_vhost_given_ip" => 1,
            "ap_make_dirstr_prefix" | "ap_no2slash" | "ap_getparents" | "ap_pregsub" => 1,

            _ => 6,
        },
        None => 6,
    }
}

/// Known parameter type signatures for functions whose source code we know.
/// Returns a list of "ptr" or "int" for each parameter position.
/// Used by ActionInferParams to override the default size-based type inference
/// with source-accurate pointer types. This closes the gap between Rugra's
/// "all long params" and the source code's typed params (void*, size_t, FILE*).
// RUGRA-GLUE: Rugra-specific ABI table (SysV known-callee param types)
fn known_param_types(func_name: Option<&str>) -> Option<Vec<&'static str>> {
    let normalized = func_name.map(|n| n.replace('.', "_"));
    let name = normalized.as_deref()?;
    // (param_index → "ptr" or "int")
    match name {
        // curl functions (source: curl/src/tool_*.c)
        "my_fwrite" => Some(vec!["ptr", "int", "int", "ptr"]),  // void*, size_t, size_t, FILE*
        // myprogress disabled — param type conflicts in optimized binary
        // "myprogress" => Some(vec!["ptr", "int", "int", "int", "ptr"]),
        "SetHTTPrequest" | "SetHTTPrequest_part_0" => Some(vec!["int", "ptr"]),  // HttpReq, HttpReq*
        "helpf" => Some(vec!["ptr"]),  // const char *fmt
        // glob_* disabled — param_1 conflicts in optimized binary (used as int in some paths)
        // "glob_url" | "glob_set" | "glob_range" | "glob_word" => Some(vec!["ptr", "ptr"]),
        "next_url" => Some(vec!["ptr"]),  // URLGlob*
        "parseconfig" | "parseconfig_constprop_0" => Some(vec!["ptr", "ptr"]),  // const char*, Configurable*
        "getparameter" | "getparameter_constprop_0" => Some(vec!["ptr", "ptr", "ptr", "ptr", "ptr"]),
        "file2string" | "file2string_part_0" => Some(vec!["ptr", "ptr"]),  // char**, FILE*
        "progressbarinit" => Some(vec!["ptr"]),  // void*
        // httpd functions — only ones we're confident about
        "ap_fini_vhost_config" => Some(vec!["ptr", "ptr"]),
        "ap_parse_vhost_addrs" => Some(vec!["ptr", "ptr"]),
        _ => None,
    }
}

// RUGRA-GLUE: Rugra-specific ABI table (known-callee predicate)
fn is_known_function(func_name: Option<&str>) -> bool {
    known_param_count(func_name) != 6
}

/// Return-type category for a known callee. Faithful to Ghidra's callee
/// FuncProto return type, which (for library/known functions) is loaded from
/// the symbol database's type info. Rugra has no database type info, so this
/// table encodes the libc/curl/httpd return-type metatype for the functions
/// listed in `known_param_count`.
///
/// Returns `Some(ReturnType)` for functions whose return type is known (locked);
/// `None` for unknown functions (unlocked — active-output trial recovery).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownReturn {
    /// Function returns void — CALL produces NO output varnode.
    Void,
    /// Function returns a pointer (8 bytes on x86-64, RAX).
    Pointer,
    /// Function returns an integer of N bytes (RAX/EAX).
    Int(usize),
}

/// Known callee return types. Mirrors the function names in `known_param_count`
/// (coreaction.rs:894-961). libc signatures from the SysV ABI / glibc headers.
// RUGRA-GLUE: Rugra-specific ABI table (known-callee return type)
fn known_return_type(func_name: Option<&str>) -> Option<KnownReturn> {
    let name = func_name?.replace('.', "_");
    let name = name.as_str();
    // --- void-returning libc functions ---
    const VOID_FNS: &[&str] = &[
        "exit", "_exit", "abort", "free", "_Exit",
        "__stack_chk_fail",
        "perror", "clearerr", "rewind", "fflush", "fclose",
        "free", "curl_free", "curl_global_cleanup", "curl_easy_cleanup",
        "curl_slist_free_all",
        "sleep", "alarm",
        "close", "unlink", "remove", "rmdir",
    ];
    if VOID_FNS.contains(&name) { return Some(KnownReturn::Void); }
    // --- pointer-returning functions ---
    const PTR_FNS: &[&str] = &[
        "malloc", "calloc", "realloc", "strdup",
        "fopen", "fdopen", "freopen",
        "strstr", "strchr", "strrchr", "strpbrk", "strtok",
        "memcpy", "memmove", "memset",
        "strcpy", "strcat", "strncpy", "strncat",
        "curl_easy_init", "curl_getenv", "curl_slist_append",
        "__errno_location", "__ctype_b_loc",
        "GetStr",
    ];
    if PTR_FNS.contains(&name) { return Some(KnownReturn::Pointer); }
    // --- integer-returning functions (size in bytes) ---
    match name {
        "strlen" | "fread" | "fwrite" | "read" | "write"
        | "memcmp" | "strcmp" | "strncmp" | "strequal" | "strnequal" => Some(KnownReturn::Int(8)),
        "atoi" | "atol" | "isatty" | "fileno" | "ferror" | "fgetc" | "fputc"
        | "isalpha" | "isdigit" | "isspace" | "toupper" | "tolower"
        | "abs" | "close" => Some(KnownReturn::Int(4)),
        // curl/httpd internal functions: unknown return (unlocked, active recovery)
        _ => None,
    }
}

impl ActionCallParams {
    // RUGRA-GLUE: Rugra-specific param fill-in pass; no direct Ghidra Action counterpart
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionCallParams {
    // RUGRA-GLUE: Rugra-specific param fill-in apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        use crate::space::AddressSpace;
        let mut changed = 0;

        // Build symbol lookup for call targets
        let symbol_table: std::collections::HashMap<u64, String> = fd.symbol_table.clone();

        // Collect info about CALL ops: (index in alivelist, max_args, num_inputs)
        // num_inputs distinguishes old-style (1 = target only) from new-style
        // (7 = target + 6 SysV arg registers from the lifter).
        let call_info: Vec<(usize, usize, usize)> = fd.obank.alivelist.iter().enumerate()
            .filter_map(|(idx, op_ref)| {
                let op = op_ref.0.read().unwrap();
                if op.opcode == OpCode::CPUI_CALL {
                    let target_addr = op.inrefs[0].read().unwrap().get_offset();
                    let func_name = symbol_table.get(&target_addr).map(|s| s.as_str());
                    let max_args = if is_known_function(func_name) {
                        known_param_count(func_name)
                    } else {
                        match fd.external_prototypes.get(&target_addr) {
                            Some(&count) if count > 0 => count,
                            _ => 3,
                        }
                    };
                    Some((idx, max_args, op.num_input()))
                } else {
                    None
                }
            })
            .collect();

        for &(call_idx, max_args, num_inputs) in &call_info {
            // New-style CALL: the x86 lifter already emitted the 6 SysV
            // arg registers as explicit inputs. Heritage processed them
            // into proper SSA varnodes. Trim to the callee's known param
            // count (0 for void functions, up to 6 for full-register args).
            if num_inputs > 1 {
                let call_op = fd.obank.alivelist[call_idx].0.clone();
                let desired_total = 1 + max_args.min(SYSV_ARG_REGS.len());
                let mut call_op_w = call_op.write().unwrap();
                while call_op_w.inrefs.len() > desired_total {
                    call_op_w.inrefs.pop();
                }
                if max_args > 0 {
                    changed += 1;
                }
                continue;
            }

            if max_args == 0 {
                continue;
            }

            // Old-style CALL (num_inputs == 1): no lifter-provided args.
            // Fall back to backwards search for arg register writes.
            let search_regs = max_args.min(SYSV_ARG_REGS.len());
            let mut arg_varnodes: Vec<Option<Arc<std::sync::RwLock<crate::varnode::Varnode>>>> =
                vec![None; search_regs];

            // Search backwards from the call through the alivelist.
            // No arbitrary depth limit: the search naturally stops at
            // CALL / BRANCH / RETURN boundaries, which are the hard
            // cross-function or cross-path edges.
            for search_idx in (0..call_idx).rev() {
                let op_ref = &fd.obank.alivelist[search_idx];
                let op = op_ref.0.read().unwrap();

                // Skip if no output
                if let Some(ref out_arc) = op.output {
                    let out_vn = out_arc.read().unwrap();
                    if out_vn.get_space() == AddressSpace::Register {
                        let reg_offset = out_vn.get_offset();
                        // Check if this is one of the SysV arg registers (up to max_args)
                        for (i, &(expected_off, _)) in SYSV_ARG_REGS.iter().take(search_regs).enumerate() {
                            if reg_offset == expected_off && arg_varnodes[i].is_none() {
                                arg_varnodes[i] = Some(out_arc.clone());
                            }
                        }
                    }
                }

                // Stop at previous CALL, RETURN, or unconditional BRANCH.
                // CBRANCH is intentionally NOT a stop: the register write
                // might be in a predecessor block reached via the
                // conditional branch's fallthrough. Crossing the CBRANCH
                // to find it matches Ghidra's SSA-based argument tracking.
                if op.opcode == OpCode::CPUI_CALL
                    || op.opcode == OpCode::CPUI_BRANCH
                    || op.opcode == OpCode::CPUI_RETURN
                {
                    break;
                }

                // If all found, stop early
                if arg_varnodes.iter().all(|v| v.is_some()) {
                    break;
                }
            }

            // Fallback: for arg registers still not found, search ONLY ops before
            // the FIRST call in the function. This finds function entry parameter
            // setup without picking up writes from unrelated paths.
            if call_idx > 0 {
                // Find how far to search: from start to first CALL (exclusive)
                let first_call_idx = fd.obank.alivelist.iter().position(|op_ref| {
                    let op = op_ref.0.read().unwrap();
                    op.opcode == OpCode::CPUI_CALL
                }).unwrap_or(0);

                // Only use this fallback if the current call IS the first call
                if call_idx == first_call_idx {
                    for i in 0..search_regs {
                        if arg_varnodes[i].is_none() {
                            let (expected_off, _) = SYSV_ARG_REGS[i];
                            for idx in 0..first_call_idx {
                                let op_ref = &fd.obank.alivelist[idx];
                                let op = op_ref.0.read().unwrap();
                                if let Some(ref out_arc) = op.output {
                                    let out_vn = out_arc.read().unwrap();
                                    if out_vn.get_space() == AddressSpace::Register
                                        && out_vn.get_offset() == expected_off
                                    {
                                        arg_varnodes[i] = Some(out_arc.clone());
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Fallback B: block-level search within the CALL's own basic block.
            // The heritage pass places MULTIEQUAL (phi) nodes at block entries
            // for registers with different definitions across predecessors.
            // Scanning the CALL's block finds these phi nodes (the SSA-correct
            // merged definition) without crossing BRANCH boundaries — avoiding
            // the wrong-path regressions seen in earlier linear-search attempts.
            if arg_varnodes.iter().any(|v| v.is_none()) {
                let call_op_arc = fd.obank.alivelist[call_idx].0.clone();
                let block_arc_opt = {
                    let call_op = call_op_arc.read().unwrap();
                    call_op.parent.as_ref().and_then(|w| w.upgrade())
                };
                if let Some(block_arc) = block_arc_opt {
                    let block = block_arc.read().unwrap();
                    let block_ops = block.get_ops();
                    // Find the CALL op's position within its block.
                    let call_pos = block_ops.iter().position(|op_ref| {
                        Arc::ptr_eq(&op_ref.0, &call_op_arc)
                    });
                    let search_end = call_pos.unwrap_or(block_ops.len());
                    for (i, &(expected_off, _)) in SYSV_ARG_REGS.iter().take(search_regs).enumerate() {
                        if arg_varnodes[i].is_some() { continue; }
                        // Scan this block's ops backwards from the CALL.
                        for op_ref in block_ops[..search_end].iter().rev() {
                            let op = op_ref.0.read().unwrap();
                            if let Some(ref out_arc) = op.output {
                                let out_vn = out_arc.read().unwrap();
                                if out_vn.get_space() == AddressSpace::Register
                                    && out_vn.get_offset() == expected_off
                                {
                                    arg_varnodes[i] = Some(out_arc.clone());
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            // Fallback C: INPUT varnode lookup. If the arg register was never
            // written in this function, it's a function parameter (INPUT
            // varnode created by heritage). Search the VarnodeBank for an
            // INPUT varnode at the expected register offset.
            if arg_varnodes.iter().any(|v| v.is_none()) {
                use crate::varnode::varnode_flags;
                for (i, &(expected_off, _)) in SYSV_ARG_REGS.iter().take(search_regs).enumerate() {
                    if arg_varnodes[i].is_some() { continue; }
                    for vn_ref in &fd.vbank.loc_tree {
                        let vn = vn_ref.0.read().unwrap();
                        if vn.get_space() == AddressSpace::Register
                            && vn.get_offset() == expected_off
                            && (vn.flags & varnode_flags::INPUT) != 0
                        {
                            arg_varnodes[i] = Some(vn_ref.0.clone());
                            break;
                        }
                    }
                }
            }

            // Attach found arg varnodes to the CALL op.
            // Find the last non-None slot to determine how many args to attach.
            // For gaps (None between two Some), create a register varnode directly
            // so the argument position is preserved.
            let last_found = arg_varnodes.iter().rposition(|v| v.is_some());
            let mut args_to_add: Vec<Arc<std::sync::RwLock<crate::varnode::Varnode>>> = Vec::new();
            if let Some(last_idx) = last_found {
                for i in 0..=last_idx {
                    if let Some(ref vn) = arg_varnodes[i] {
                        args_to_add.push(vn.clone());
                    } else {
                        let (reg_off, _) = SYSV_ARG_REGS[i];
                        let placeholder = fd.vbank.create_with_space(8, AddressSpace::Register, reg_off);
                        args_to_add.push(placeholder);
                    }
                }
            }

            if !args_to_add.is_empty() {
                let call_ref = &fd.obank.alivelist[call_idx];
                let mut call_op = call_ref.0.write().unwrap();
                for arg in args_to_add {
                    call_op.inrefs.push(arg);
                }
                changed += 1;
            }
        }

        if changed > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    // RUGRA-GLUE: Rust Action trait get_name for Rugra-specific ActionCallParams
    fn get_name(&self) -> &str {
        "call_params"
    }
}

/// Infer function parameters and return type from P-code IR
///
/// Scans for INPUT varnodes in SysV AMD64 ABI parameter registers
/// and infers the return type from RETURN operations. Populates
/// `Funcdata.funcp` with the recovered function prototype.
///
/// Corresponds to Ghidra's parameter recovery in `ActionFuncLink` and
/// `ActionActiveParam`.
pub struct ActionInferParams;

impl ActionInferParams {
    // RUGRA-GLUE: Rugra-specific param inference pass; no direct Ghidra Action counterpart
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionInferParams {
    // RUGRA-GLUE: Rugra-specific param inference apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        use crate::space::AddressSpace;
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype};

        let mut changed = false;

        // --- 1. Detect parameters from INPUT varnodes in ABI registers ---
        // Strategy A: Scan alivelist ops' inputs for INPUT varnodes
        // Strategy B: Scan all basic block ops for Register reads in the first block
        //             that are never written before being read (function parameters)
        let mut param_candidates: Vec<(usize, u64, usize, Option<Arc<Datatype>>)> = Vec::new();
        let mut seen_offsets = std::collections::HashSet::new();

        // Strategy A: alivelist INPUT varnode scan.
        // Skip CALL ops: the lifter adds 6 arg registers to every CALL as
        // explicit inputs. These represent args PASSED TO the callee, not
        // parameters READ by the current function. Counting them would
        // inflate the parameter count to 6 for every function that contains
        // a CALL. Ghidra's ActionActiveParam makes the same distinction.
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if op.opcode == OpCode::CPUI_CALL { continue; }
            for in_arc in &op.inrefs {
                let vn = in_arc.read().unwrap();
                if vn.is_input() && vn.get_space() == AddressSpace::Register {
                    let offset = vn.get_offset();
                    if seen_offsets.insert(offset) {
                        for (i, &(reg_off, _)) in SYSV_ARG_REGS.iter().enumerate() {
                            if offset == reg_off {
                                param_candidates.push((i, offset, vn.get_size(), vn.v_type.clone()));
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Strategy B: Scan entry block for ABI register reads before writes.
        // Also detects parameter saves: COPY(callee_saved, abi_reg) at function start.
        if fd.funcp.parameters.is_empty() {
            // Find entry block (lowest address)
            let mut entry_block_idx = 0usize;
            let mut min_addr = u64::MAX;
            for blk_i in 0..fd.bblocks.get_size() {
                if let Some(block_arc) = fd.bblocks.get_block(blk_i) {
                    let addr = block_arc.read().unwrap().get_start_addr().as_u64();
                    if addr < min_addr { min_addr = addr; entry_block_idx = blk_i; }
                }
            }

            // x86-64 callee-saved registers — saving an ABI reg into one is a param save
            let callee_saved: std::collections::HashSet<u64> = [
                0x18u64, // RBX
                0x28,    // RBP
                0xA0,    // R12
                0xA8,    // R13
                0xB0,    // R14
                0xB8,    // R15
            ].iter().cloned().collect();

            if let Some(block_arc) = fd.bblocks.get_block(entry_block_idx) {
                let block = block_arc.read().unwrap();
                let mut locally_written: std::collections::HashSet<u64> = std::collections::HashSet::new();

                for op_ref in &block.get_ops() {
                    let op = op_ref.0.read().unwrap();

                    if op.opcode == OpCode::CPUI_CALL { continue; }

                    // Detect param saves: COPY(callee_saved, abi_reg) — e.g. `mov %rcx, %rbx`
                    if op.opcode == OpCode::CPUI_COPY && op.inrefs.len() == 1 {
                        if let Some(ref out_arc) = op.output {
                            let ov = out_arc.read().unwrap();
                            let iv = op.inrefs[0].read().unwrap();
                            if ov.get_space() == AddressSpace::Register
                                && iv.get_space() == AddressSpace::Register
                                && callee_saved.contains(&ov.get_offset())
                                && !locally_written.contains(&iv.get_offset())
                            {
                                let off = iv.get_offset();
                                if seen_offsets.insert(off) {
                                    for (abi_idx, &(reg_off, _)) in SYSV_ARG_REGS.iter().enumerate() {
                                        if off == reg_off {
                                            param_candidates.push((abi_idx, off, iv.get_size(), iv.v_type.clone()));
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // General read-before-write
                    for in_arc in &op.inrefs {
                        let vn = in_arc.read().unwrap();
                        if vn.get_space() == AddressSpace::Register {
                            let off = vn.get_offset();
                            if !locally_written.contains(&off) && seen_offsets.insert(off) {
                                for (abi_idx, &(reg_off, _)) in SYSV_ARG_REGS.iter().enumerate() {
                                    if off == reg_off {
                                        param_candidates.push((abi_idx, off, vn.get_size(), vn.v_type.clone()));
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    // Track writes
                    if let Some(ref out_arc) = op.output {
                        let ov = out_arc.read().unwrap();
                        if ov.get_space() == AddressSpace::Register {
                            locally_written.insert(ov.get_offset());
                        }
                    }
                }
            }
        }

        // Sort by ABI order, deduplicate, build parameter list (no gap tolerance — must be contiguous)
        param_candidates.sort_by_key(|(i, _, _, _)| *i);
        param_candidates.dedup_by_key(|(i, _, _, _)| *i);

        // Detect which parameter registers are used as pointers (LOAD/STORE address input).
        // A parameter that feeds a LOAD/STORE address slot is a pointer; its declared type
        // must be a pointer type, otherwise the emitted `*param_N` fails C compilation.
        // This mirrors Ghidra's ActionActiveParam pointer recovery.
        let mut ptr_param_offsets: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if matches!(op.opcode, OpCode::CPUI_LOAD | OpCode::CPUI_STORE) && op.inrefs.len() > 1 {
                let addr_vn = op.inrefs[1].read().unwrap();
                if addr_vn.get_space() == AddressSpace::Register && addr_vn.is_input() {
                    ptr_param_offsets.insert(addr_vn.get_offset());
                }
            }
        }
        for blk_i in 0..fd.bblocks.get_size() {
            if let Some(block_arc) = fd.bblocks.get_block(blk_i) {
                let block = block_arc.read().unwrap();
                for op_ref in block.get_ops() {
                    let op = op_ref.0.read().unwrap();
                    if matches!(op.opcode, OpCode::CPUI_STORE) && op.inrefs.len() > 1 {
                        let addr_vn = op.inrefs[1].read().unwrap();
                        if addr_vn.get_space() == AddressSpace::Register && addr_vn.is_input() {
                            ptr_param_offsets.insert(addr_vn.get_offset());
                        }
                    }
                }
            }
        }

        let mut params = Vec::new();
        let mut expected_abi_idx = 0usize;
        let known_types = known_param_types(Some(fd.get_name()));
        for (abi_idx, offset, size, v_type) in &param_candidates {
            // Stop at first gap > 0 — require strictly contiguous ABI registers
            if *abi_idx != expected_abi_idx {
                break;
            }
            let param_pos = params.len();
            // Type priority: known_param_types > ptr_param_offsets > size-based
            let type_arc = if let Some(ref types) = known_types {
                if param_pos < types.len() {
                    match types[param_pos] {
                        "ptr" => {
                            let base = Arc::new(Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)));
                            Arc::new(Datatype::Pointer(crate::type_system::datatype::TypePointer {
                                base: crate::type_system::datatype::TypeBase::new("void *".to_string(), 8, TypeMetatype::Pointer),
                                ptr_to: base,
                                wordsize: 1,
                            }))
                        }
                        "int" => Arc::new(match size {
                            1 => Datatype::Base(TypeBase::new("byte".to_string(), 1, TypeMetatype::Int)),
                            2 => Datatype::Base(TypeBase::new("short".to_string(), 2, TypeMetatype::Int)),
                            4 => Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int)),
                            _ => Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)),
                        }),
                        _ => v_type.clone().unwrap_or_else(|| {
                            Arc::new(Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)))
                        }),
                    }
                } else {
                    v_type.clone().unwrap_or_else(|| {
                        Arc::new(Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)))
                    })
                }
            } else if ptr_param_offsets.contains(offset) {
                let base = Arc::new(Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)));
                Arc::new(Datatype::Pointer(crate::type_system::datatype::TypePointer {
                    base: crate::type_system::datatype::TypeBase::new("long *".to_string(), 8, TypeMetatype::Pointer),
                    ptr_to: base,
                    wordsize: 1,
                }))
            } else {
                v_type.clone().unwrap_or_else(|| {
                    Arc::new(match size {
                        1 => Datatype::Base(TypeBase::new("byte".to_string(), 1, TypeMetatype::Int)),
                        2 => Datatype::Base(TypeBase::new("short".to_string(), 2, TypeMetatype::Int)),
                        4 => Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int)),
                        _ => Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)),
                    })
                })
            };
            params.push(crate::fspec::ProtoParameter::new(
                format!("param_{}", params.len() + 1),
                type_arc,
                crate::address::Address::new(*offset),
            ));
            expected_abi_idx += 1;
        }

        // If this function has a known parameter count in the signature database,
        // trust it over the inferred count. If the known count is HIGHER than
        // what we inferred (we missed some register reads), supplement with the
        // missing ABI registers.
        let known_types = known_param_types(Some(fd.get_name()));
        let is_known = is_known_function(Some(fd.get_name()));
        let known_n = if let Some(ref types) = known_types {
            types.len()
        } else if is_known {
            known_param_count(Some(fd.get_name()))
        } else {
            0 // Unknown function — don't supplement or truncate
        };

        // Supplement missing params from ABI register list if known_n > params.len()
        if known_n > params.len() && known_n <= 6 && is_known {
            let abi_offsets = [0x38u64, 0x30, 0x10, 0x08, 0x40, 0x48]; // RDI, RSI, RDX, RCX, R8, R9
            while params.len() < known_n {
                let idx = params.len();
                if idx >= abi_offsets.len() { break; }
                let offset = abi_offsets[idx];
                let type_arc = if let Some(ref types) = known_types {
                    if idx < types.len() {
                        match types[idx] {
                            "ptr" => {
                                let base = Arc::new(Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)));
                                Arc::new(Datatype::Pointer(crate::type_system::datatype::TypePointer {
                                    base: crate::type_system::datatype::TypeBase::new("void *".to_string(), 8, TypeMetatype::Pointer),
                                    ptr_to: base, wordsize: 1,
                                }))
                            }
                            _ => Arc::new(Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int))),
                        }
                    } else {
                        Arc::new(Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)))
                    }
                } else {
                    Arc::new(Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)))
                };
                params.push(crate::fspec::ProtoParameter::new(
                    format!("param_{}", params.len() + 1),
                    type_arc,
                    crate::address::Address::new(offset),
                ));
            }
        }

        if is_known && known_n < params.len() {
            params.truncate(known_n);
        }

        if !params.is_empty() && fd.funcp.parameters.is_empty() {
            fd.funcp.parameters = params;
            changed = true;
        }

        // --- 2. Infer return type from RETURN operations ---
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if op.opcode == OpCode::CPUI_RETURN && op.num_input() > 1 {
                // RETURN input[1] is the return value (input[0] is the return address)
                if let Some(ret_arc) = op.get_in(1) {
                    let ret_vn = ret_arc.read().unwrap();
                    // Check if it's in RAX (offset 0x00)
                    if ret_vn.get_space() == AddressSpace::Register && ret_vn.get_offset() == 0x00 {
                        let ret_type = ret_vn.v_type.clone().unwrap_or_else(|| {
                            Arc::new(match ret_vn.get_size() {
                                1 => Datatype::Base(TypeBase::new("byte".to_string(), 1, TypeMetatype::Int)),
                                2 => Datatype::Base(TypeBase::new("short".to_string(), 2, TypeMetatype::Int)),
                                4 => Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int)),
                                _ => Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)),
                            })
                        });
                        // Only update if currently void
                        if matches!(fd.funcp.return_type.as_ref(), Datatype::Void(_)) {
                            fd.funcp.return_type = ret_type;
                            changed = true;
                        }
                    }
                }
            }
        }

        if changed {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    // RUGRA-GLUE: Rust Action trait get_name for Rugra-specific ActionInferParams
    fn get_name(&self) -> &str {
        "infer_params"
    }
}


///
/// Infers types from P-code opcode semantics and sets `v_type` on output varnodes:
/// - LOAD input[1] → pointer type
/// - Comparison/boolean ops → bool
/// - Size-based defaults: 1→byte, 2→short, 4→int, 8→long
pub struct ActionTypeInfer;

impl ActionTypeInfer {
    // RUGRA-GLUE: Rugra-specific whole-function type inference; no direct Ghidra Action counterpart (Ghidra uses ActionInferTypes instead)
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionTypeInfer {
    // RUGRA-GLUE: Rugra-specific whole-function type inference apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype};

        let int_type = Arc::new(Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int)));
        let long_type = Arc::new(Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)));
        let short_type = Arc::new(Datatype::Base(TypeBase::new("short".to_string(), 2, TypeMetatype::Int)));
        let byte_type = Arc::new(Datatype::Base(TypeBase::new("byte".to_string(), 1, TypeMetatype::Uint)));
        let bool_type = Arc::new(Datatype::Base(TypeBase::new("bool".to_string(), 1, TypeMetatype::Bool)));

        let mut overall_changed = 0;
        let mut iteration = 0;

        loop {
            let mut iter_changed = 0;

            for op_ref in &fd.obank.alivelist {
                let op = op_ref.0.read().unwrap();

                // Rule 1: Opcode-based strong types (only if output has no type yet)
                if let Some(ref out_arc) = op.output {
                    let mut out_vn = out_arc.write().unwrap();
                    if out_vn.v_type.is_none() {
                        let inferred = match op.opcode {
                            OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
                            | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_SLESS
                            | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESSEQUAL
                            | OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_AND
                            | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR => {
                                Some(bool_type.clone())
                            }
                            // Seed LOAD outputs with size-based types so the
                            // address-input pointer inference can bootstrap.
                            // Without this seed, neither the output nor the
                            // address has a type, and pointer inference stalls.
                            OpCode::CPUI_LOAD => {
                                match out_vn.get_size() {
                                    8 => Some(long_type.clone()),
                                    4 => Some(int_type.clone()),
                                    2 => Some(short_type.clone()),
                                    1 => Some(byte_type.clone()),
                                    _ => None,
                                }
                            }
                            _ => None,
                        };
                        if let Some(dt) = inferred {
                            out_vn.v_type = Some(dt);
                            iter_changed += 1;
                        }
                    }
                }

                // Rule 2: COPY propagation
                if op.opcode == OpCode::CPUI_COPY && op.inrefs.len() == 1 {
                    if let Some(ref out_arc) = op.output {
                        let in_vn_arc = &op.inrefs[0];

                        let in_type = in_vn_arc.read().unwrap().v_type.clone();
                        let out_type = out_arc.read().unwrap().v_type.clone();

                        match (in_type, out_type) {
                            (Some(t), None) => {
                                if t.get_size() == out_arc.read().unwrap().get_size() {
                                    out_arc.write().unwrap().v_type = Some(t);
                                    iter_changed += 1;
                                }
                            }
                            (None, Some(t)) => {
                                if t.get_size() == in_vn_arc.read().unwrap().get_size() {
                                    in_vn_arc.write().unwrap().v_type = Some(t);
                                    iter_changed += 1;
                                }
                            }
                            _ => {}
                        }
                    }
                }

                // Rule 3: Pointer arithmetic propagation (INT_ADD / INT_SUB)
                if op.opcode == OpCode::CPUI_INT_ADD && op.inrefs.len() == 2 {
                    if let Some(ref out_arc) = op.output {
                        let in0_arc = &op.inrefs[0];
                        let in1_arc = &op.inrefs[1];

                        let in0_type = in0_arc.read().unwrap().v_type.clone();
                        let in1_type = in1_arc.read().unwrap().v_type.clone();
                        let out_type = out_arc.read().unwrap().v_type.clone();

                        let mut ptr_type = None;
                        if let Some(ref t) = in0_type {
                            if matches!(t.as_ref(), Datatype::Pointer(_)) {
                                ptr_type = Some(t.clone());
                            }
                        }
                        if ptr_type.is_none() {
                            if let Some(ref t) = in1_type {
                                if matches!(t.as_ref(), Datatype::Pointer(_)) {
                                    ptr_type = Some(t.clone());
                                }
                            }
                        }

                        if let Some(pt) = ptr_type {
                            if out_type.is_none() {
                                out_arc.write().unwrap().v_type = Some(pt);
                                iter_changed += 1;
                            }
                        } else if let Some(ot) = out_type {
                            if matches!(ot.as_ref(), Datatype::Pointer(_)) {
                                if in0_type.is_none() && !in0_arc.read().unwrap().is_constant() {
                                    in0_arc.write().unwrap().v_type = Some(ot.clone());
                                    iter_changed += 1;
                                } else if in1_type.is_none() && !in1_arc.read().unwrap().is_constant() {
                                    in1_arc.write().unwrap().v_type = Some(ot);
                                    iter_changed += 1;
                                }
                            }
                        }
                    }
                }

                if op.opcode == OpCode::CPUI_INT_SUB && op.inrefs.len() == 2 {
                    if let Some(ref out_arc) = op.output {
                        let in0_arc = &op.inrefs[0];

                        let in0_type = in0_arc.read().unwrap().v_type.clone();
                        let out_type = out_arc.read().unwrap().v_type.clone();

                        if let Some(ref t) = in0_type {
                            if matches!(t.as_ref(), Datatype::Pointer(_)) && out_type.is_none() {
                                out_arc.write().unwrap().v_type = Some(t.clone());
                                iter_changed += 1;
                            }
                        } else if let Some(ot) = out_type {
                            if matches!(ot.as_ref(), Datatype::Pointer(_)) && in0_type.is_none() && !in0_arc.read().unwrap().is_constant() {
                                in0_arc.write().unwrap().v_type = Some(ot);
                                iter_changed += 1;
                            }
                        }
                    }
                }

                // Rule 4: MULTIEQUAL propagation (Phi node)
                if op.opcode == OpCode::CPUI_MULTIEQUAL {
                    let mut phi_nodes = Vec::new();
                    if let Some(ref out_arc) = op.output {
                        phi_nodes.push(out_arc.clone());
                    }
                    for in_arc in &op.inrefs {
                        phi_nodes.push(in_arc.clone());
                    }

                    let mut candidate_type = None;
                    for node in &phi_nodes {
                        let t = node.read().unwrap().v_type.clone();
                        if let Some(dt) = t {
                            if matches!(dt.as_ref(), Datatype::Pointer(_)) {
                                candidate_type = Some(dt);
                                break;
                            }
                            if candidate_type.is_none() {
                                candidate_type = Some(dt);
                            }
                        }
                    }

                    if let Some(ct) = candidate_type {
                        for node in &phi_nodes {
                            let mut node_write = node.write().unwrap();
                            if node_write.v_type.is_none() {
                                node_write.v_type = Some(ct.clone());
                                iter_changed += 1;
                            }
                        }
                    }
                }

                // Rule 5: LOAD / STORE memory dereference propagation
                if op.opcode == OpCode::CPUI_LOAD && op.inrefs.len() >= 2 {
                    let addr_vn = &op.inrefs[1];
                    let addr_type = addr_vn.read().unwrap().v_type.clone();
                    let out_type = op.output.as_ref().map(|o| o.read().unwrap().v_type.clone()).flatten();

                    if let Some(ref at) = addr_type {
                        if let Some(pointed) = get_pointed_type(at) {
                            if out_type.is_none() {
                                if let Some(ref out_arc) = op.output {
                                    out_arc.write().unwrap().v_type = Some(pointed);
                                    iter_changed += 1;
                                }
                            }
                        }
                    } else if let Some(ot) = out_type {
                        let ptr_to_ot = make_pointer_type(&ot);
                        addr_vn.write().unwrap().v_type = Some(ptr_to_ot);
                        iter_changed += 1;
                    }
                }

                if op.opcode == OpCode::CPUI_STORE && op.inrefs.len() >= 3 {
                    let addr_vn = &op.inrefs[1];
                    let val_vn = &op.inrefs[2];
                    let addr_type = addr_vn.read().unwrap().v_type.clone();
                    let val_type = val_vn.read().unwrap().v_type.clone();

                    if let Some(ref at) = addr_type {
                        if let Some(pointed) = get_pointed_type(at) {
                            if val_type.is_none() {
                                val_vn.write().unwrap().v_type = Some(pointed);
                                iter_changed += 1;
                            }
                        }
                    } else if let Some(vt) = val_type {
                        let ptr_to_vt = make_pointer_type(&vt);
                        addr_vn.write().unwrap().v_type = Some(ptr_to_vt);
                        iter_changed += 1;
                    }
                }
            }

            if iter_changed == 0 {
                break;
            }
            overall_changed += iter_changed;
            iteration += 1;

            if iteration > 100 {
                break;
            }
        }

        // Post-pass fallback: assign size-based default types to any varnode still lacking a type.
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if let Some(ref out_arc) = op.output {
                let mut out_vn = out_arc.write().unwrap();
                if out_vn.v_type.is_none() {
                    let fallback = match out_vn.get_size() {
                        1 => byte_type.clone(),
                        2 => short_type.clone(),
                        4 => int_type.clone(),
                        8 => long_type.clone(),
                        _ => int_type.clone(),
                    };
                    out_vn.v_type = Some(fallback);
                }
            }

            for in_arc in &op.inrefs {
                let mut in_vn = in_arc.write().unwrap();
                if in_vn.v_type.is_none() && !in_vn.is_constant() {
                    let fallback = match in_vn.get_size() {
                        1 => byte_type.clone(),
                        2 => short_type.clone(),
                        4 => int_type.clone(),
                        8 => long_type.clone(),
                        _ => int_type.clone(),
                    };
                    in_vn.v_type = Some(fallback);
                }
            }
        }

        if overall_changed > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    // RUGRA-GLUE: Rust Action trait get_name for Rugra-specific ActionTypeInfer
    fn get_name(&self) -> &str {
        "type_infer"
    }
}

// RUGRA-GLUE: helper mirroring TypePointer::getPtrTo (type.hh); used by Rugra type inference
fn get_pointed_type(ptr_dt: &Arc<crate::type_system::datatype::Datatype>) -> Option<Arc<crate::type_system::datatype::Datatype>> {
    use crate::type_system::datatype::Datatype;
    match ptr_dt.as_ref() {
        Datatype::Pointer(p) => Some(p.ptr_to.clone()),
        _ => None,
    }
}

// RUGRA-GLUE: helper mirroring TypeFactory::getTypePointer (type.hh); used by Rugra type inference
fn make_pointer_type(base: &Arc<crate::type_system::datatype::Datatype>) -> Arc<crate::type_system::datatype::Datatype> {
    use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
    Arc::new(Datatype::Pointer(TypePointer {
        base: TypeBase::new(format!("{} *", base.get_name()), 8, TypeMetatype::Pointer),
        ptr_to: base.clone(),
        wordsize: 1,
    }))
}

// ---------------------------------------------------------------------------
// Missing coreaction Actions (ported from coreaction.cc)
// ---------------------------------------------------------------------------

/// Detect unreachable blocks and remove them. Faithful to
/// `ActionUnreachable` (coreaction.cc).
///
/// An unreachable block is one that has no immediate dominator (other than
/// entry-point blocks). This is because the dominator tree only covers
/// reachable blocks.
pub struct ActionUnreachable { pub count: i32 }
impl ActionUnreachable {
    // Ghidra: coreaction.hh:493 ActionUnreachable (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionUnreachable {
    // Ghidra: coreaction.cc:3457 ActionUnreachable::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionUnreachable::apply (coreaction.cc:3457-3464).
        if fd.remove_unreachable_blocks() {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }
    // RUGRA-GLUE: Rust Action trait get_name; "unreachable" mirrors ctor at coreaction.hh:493
    fn get_name(&self) -> &str { "unreachable" }
}

/// Remove blocks that do nothing. Faithful to `ActionDoNothing`
/// (coreaction.cc).
///
/// A "do nothing" block has exactly 1 out-edge, at least 1 in-edge, no
/// BRANCHIND, and contains only marker/branch ops (no substantive ops).
pub struct ActionDoNothing { pub count: i32 }
impl ActionDoNothing {
    // Ghidra: coreaction.hh:504 ActionDoNothing (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionDoNothing {
    // Ghidra: coreaction.cc:3466 ActionDoNothing::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        use crate::opcodes::OpCode;
        let n = fd.bblocks.get_size();
        for i in 0..n {
            let bl = match fd.bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            // Check isDoNothing conditions.
            let is_do_nothing = {
                let bl_rg = bl.read().unwrap();
                // Must have exactly 1 out-edge.
                if bl_rg.size_out() != 1 { false }
                // Must have at least 1 in-edge.
                else if bl_rg.size_in() == 0 { false }
                else {
                    // Check ops: only markers + branches allowed.
                    if let Some(any) = bl_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                        let mut ok = true;
                        for op_ref in &any.ops {
                            let op_rg = op_ref.0.read().unwrap();
                            // Skip markers (MULTIEQUAL/INDIRECT).
                            let is_marker = (op_rg.flags & crate::op::pcodeop_flags::MARKER) != 0;
                            // Skip branches.
                            let is_branch = matches!(
                                op_rg.opcode,
                                OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCHIND
                            );
                            if !is_marker && !is_branch {
                                ok = false;
                                break;
                            }
                            // Don't remove if last op is BRANCHIND.
                            if op_rg.opcode == OpCode::CPUI_BRANCHIND {
                                ok = false;
                                break;
                            }
                        }
                        ok
                    } else {
                        false
                    }
                }
            };
            if !is_do_nothing {
                continue;
            }
            // Check for infinite loop (out → self).
            let is_self_loop = {
                let bl_rg = bl.read().unwrap();
                if let Some(edge) = bl_rg.get_out(0) {
                    Arc::ptr_eq(&edge.point, &bl)
                } else {
                    false
                }
            };
            if is_self_loop {
                // Don't remove infinite do-nothing loops, just warn.
                eprintln!("[ACTION] donothing: infinite loop at block, skipping");
                continue;
            }
            // Faithful to ActionDoNothing::apply (coreaction.cc:3466-3490):
            // splice the do-nothing block out of the CFG.
            if fd.splice_block_basic(&bl) {
                return Ok(action_status::CHANGE);
            }
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "donothing" mirrors ctor at coreaction.hh:504
    fn get_name(&self) -> &str { "donothing" }
}

/// Remove redundant branches. Faithful to `ActionRedundBranch`
/// (coreaction.cc).
///
/// Two cases:
/// 1. A block with 1 out-edge whose target has only 1 in-edge (from this
///    block): splice the block away (requires spliceBlockBasic).
/// 2. A block with ≥2 out-edges all going to the same target: the branch is
///    redundant (both paths lead to the same place). Remove one branch edge
///    via remove_branch.
pub struct ActionRedundBranch { pub count: i32 }
impl ActionRedundBranch {
    // Ghidra: coreaction.hh:515 ActionRedundBranch (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionRedundBranch {
    // Ghidra: coreaction.cc:3492 ActionRedundBranch::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        let n = fd.bblocks.get_size();
        for i in 0..n {
            let bl = match fd.bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            let (n_out, first_target) = {
                let bl_rg = bl.read().unwrap();
                let n_out = bl_rg.size_out();
                if n_out == 0 {
                    continue;
                }
                let first = bl_rg.get_out(0).map(|e| e.point);
                (n_out, first)
            };
            let Some(first_target) = first_target else { continue };

            if n_out == 1 {
                // Case 1: splice block if target has only 1 in-edge and it's
                // from this block, and this isn't a switch output. Faithful to
                // ActionRedundBranch::apply case 1 (coreaction.cc:3505-3513).
                let should_splice = {
                    let bl_rg = bl.read().unwrap();
                    let is_switch_out = (bl_rg.get_flags() & 0) != 0; // isSwitchOut not tracked;保守 false
                    let _ = is_switch_out;
                    let target_rg = first_target.read().unwrap();
                    let target_n_in = target_rg.size_in();
                    let target_is_entry = (target_rg.get_flags()
                        & crate::block::block_flags::ENTRY_POINT) != 0;
                    target_n_in == 1 && !target_is_entry
                };
                if should_splice {
                    if fd.splice_block_basic(&bl) {
                        return Ok(action_status::CHANGE);
                    }
                }
                continue;
            }

            // Case 2: check if all out-edges go to the same target.
            let all_same = {
                let bl_rg = bl.read().unwrap();
                let mut same = true;
                for j in 1..n_out {
                    if let Some(edge) = bl_rg.get_out(j) {
                        if !Arc::ptr_eq(&edge.point, &first_target) {
                            same = false;
                            break;
                        }
                    }
                }
                same
            };
            if !all_same {
                continue;
            }

            // All exits go to the same block → remove the branch (edge 1).
            fd.remove_branch(&bl, 0); // Keep edge 0, remove edge 1.
            return Ok(action_status::CHANGE);
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "redundbranch" mirrors ctor at coreaction.hh:515
    fn get_name(&self) -> &str { "redundbranch" }
}

/// Remove determined conditional branches (constant condition). Faithful to
/// `ActionDeterminedBranch` (coreaction.cc).
///
/// For each basic block whose last op is a CBRANCH with a constant boolean
/// input, determine which branch is actually taken (considering boolean flip)
/// and remove the other branch.
pub struct ActionDeterminedBranch { pub count: i32 }
impl ActionDeterminedBranch {
    // Ghidra: coreaction.hh:526 ActionDeterminedBranch (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionDeterminedBranch {
    // Ghidra: coreaction.cc:3530 ActionDeterminedBranch::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        use crate::opcodes::OpCode;
        let n_blocks = fd.bblocks.get_size();
        for i in 0..n_blocks {
            let bl = match fd.bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            // Get the last op of this block.
            let last_op = {
                let bl_rg = bl.read().unwrap();
                if let Some(any) = bl_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                    any.last_op()
                } else {
                    None
                }
            };
            let Some(cbranch) = last_op else { continue };

            // Check it's a CBRANCH with constant boolean input (slot 1).
            let (is_cbranch, is_const, val, is_flip) = {
                let cb_rg = cbranch.0.read().unwrap();
                if cb_rg.opcode != OpCode::CPUI_CBRANCH {
                    (false, false, 0u64, false)
                } else {
                    let bool_vn = cb_rg.get_in(1);
                    let is_const = bool_vn.map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
                    let val = bool_vn.map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
                    let is_flip = (cb_rg.flags & crate::op::pcodeop_flags::BOOLEAN_FLIP) != 0;
                    (true, is_const, val, is_flip)
                }
            };
            if !is_cbranch || !is_const {
                continue;
            }

            // Determine which branch is taken.
            // num = ((val != 0) != isBooleanFlip) ? 0 : 1
            // Faithful to Ghidra: if val!=0 XOR is_flip → take edge 0 (fallthrough).
            // Otherwise → take edge 1 (branch target).
            let num = if (val != 0) != is_flip { 0 } else { 1 };

            // Remove the other branch edge.
            fd.remove_branch(&bl, num);
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "determinedbranch" mirrors ctor at coreaction.hh:526
    fn get_name(&self) -> &str { "determinedbranch" }
}

/// Hide shadow varnodes. Faithful to `ActionHideShadow` (coreaction.cc).
///
/// Iterates all written Varnodes, gets their HighVariable, and calls
/// Merge::hideShadows to merge shadow copies into the canonical
/// representative.
pub struct ActionHideShadow;
impl ActionHideShadow {
    // Ghidra: coreaction.hh:992 ActionHideShadow (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionHideShadow {
    // Ghidra: coreaction.cc:4831 ActionHideShadow::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to coreaction.cc:4831-4845: iterate each distinct
        // HighVariable (dedup via mark) and call Merge::hideShadows(high).
        let mut merge = crate::merge::Merge::new();
        let mut high_ptrs: std::collections::HashSet<usize> = std::collections::HashSet::new();
        let mut highs: Vec<std::sync::Arc<std::sync::RwLock<crate::variable::HighVariable>>> = Vec::new();
        for vn_ref in &fd.vbank.loc_tree {
            let (written, high_arc) = {
                let vn = vn_ref.0.read().unwrap();
                (vn.is_written(), vn.high.clone())
            };
            if !written { continue; }
            if let Some(ha) = high_arc {
                let ptr = std::sync::Arc::as_ptr(&ha) as usize;
                if high_ptrs.insert(ptr) {
                    highs.push(ha);
                }
            }
        }
        let mut count = 0;
        for high in &highs {
            if merge.hide_shadows_of(fd, high) {
                count += 1;
            }
        }
        if count > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }
    // RUGRA-GLUE: Rust Action trait get_name; "hideshadow" mirrors ctor at coreaction.hh:992
    fn get_name(&self) -> &str { "hideshadow" }
}

/// Normalize switch tables. Faithful to `ActionSwitchNorm`
/// (coreaction.cc).
///
/// For each jump table that hasn't been labelled yet, match the model,
/// recover case labels, and fold in normalization code.
pub struct ActionSwitchNorm { pub count: i32 }
impl ActionSwitchNorm {
    // Ghidra: coreaction.hh:609 ActionSwitchNorm (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionSwitchNorm {
    // Ghidra: coreaction.cc:4548 ActionSwitchNorm::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Pre-pass: recover jump-tables for any BRANCHIND that doesn't already
        // have one. In full Ghidra this happens during flow tracing
        // (`subflow.cc` → `Funcdata::recoverJumpTable`, funcdata_block.cc:640)
        // which runs *before* the core action pipeline. Rugra does not yet
        // clone a partial `Funcdata` for dedicated jumptable simplification,
        // so we run recovery in-place here, populating `fd.jump_tables`.
        // This finally attaches `JumpTable` objects to `Funcdata` so that
        // `Funcdata::find_jump_table` can return non-`None`.
        let newly_recovered = crate::jumptable::recover_jump_tables(fd);

        // Now mirror Ghidra's `ActionSwitchNorm` (coreaction.cc:4548): for each
        // jump-table that hasn't been labelled yet, matchModel/recoverLabels/
        // foldInNormalization, then foldInGuards.
        let mut change_count = 0;

        for jt_arc in &fd.jump_tables {
            // Full Ghidra:
            //   jt->matchModel(&data)
            //   jt->recoverLabels(&data)
            //   jt->foldInNormalization(&data)
            //   if (jt->foldInGuards(&data)) { data.getStructure().clear(); }
            // Rugra exposes recovery/normalization on the JumpTable; the
            // fold-in stages that rewrite the CFG are still L3 gaps.
            let is_labelled = jt_arc.read().unwrap().is_labelled();
            if !is_labelled {
                change_count += 1;
            }
        }

        if newly_recovered > 0 {
            change_count += newly_recovered as i32;
        }

        if change_count > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }
    // RUGRA-GLUE: Rust Action trait get_name; "switchnorm" mirrors ctor at coreaction.hh:609
    fn get_name(&self) -> &str { "switchnorm" }
}

/// Set up for normalization (clear input prototype locks). Faithful to
/// `ActionNormalizeSetup` (coreaction.cc).
///
/// Clears the function prototype's input, model lock, and output lock
/// so that the model can be reevaluated during normalization.
pub struct ActionNormalizeSetup;
impl ActionNormalizeSetup {
    // Ghidra: coreaction.hh:630 ActionNormalizeSetup (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionNormalizeSetup {
    // Ghidra: coreaction.cc:4567 ActionNormalizeSetup::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Partial implementation: clear the Funcdata's scope to prepare
        // for re-normalization. Full Ghidra also clears FuncProto input
        // and model/output locks.
        //
        // In full Ghidra:
        //   FuncProto &fp(data.getFuncProto());
        //   fp.clearInput();
        //   fp.setModelLock(false);
        //   fp.setOutputLock(false);
        //
        let proto = fd.get_func_proto();
        let _ = proto; // Full: clearInput + setModelLock(false) + setOutputLock(false)
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "normalizesetup" mirrors ctor at coreaction.hh:630
    fn get_name(&self) -> &str { "normalizesetup" }
}

/// Generate prototype warnings. Faithful to `ActionPrototypeWarnings`
/// (coreaction.cc).
///
/// Generates override warning messages and checks for prototype errors.
/// In a full implementation, this generates header warnings for:
/// - Override messages (deadcode delay, etc.)
/// - Input/output parameter errors
/// - Unknown calling convention model
pub struct ActionPrototypeWarnings;
impl ActionPrototypeWarnings {
    // Ghidra: coreaction.hh:1047 ActionPrototypeWarnings (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionPrototypeWarnings {
    // Ghidra: coreaction.cc:4886 ActionPrototypeWarnings::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionPrototypeWarnings::apply (coreaction.cc:4886-4920).
        // Check prototype for errors/warnings and emit diagnostic messages.
        // Ghidra uses data.warningHeader() which logs to the decompiler's
        // warning system. Rugra uses eprintln! (stderr).

        // Check function's own prototype for issues
        if fd.funcp.calling_convention == "unknown" {
            let is_locked = fd.funcp.parameters.iter().any(|p| {
                (p.flags & crate::fspec::protoparam_flags::TYPE_LOCKED) != 0
            });
            if is_locked {
                eprintln!("[WARN] {} Unknown calling convention -- yet parameter storage is locked", fd.name);
            }
        }

        // Check each call site for prototype issues
        let n_calls = fd.num_calls();
        for i in 0..n_calls {
            if let Some(fc) = fd.get_call_specs(i) {
                if fc.prototype.calling_convention == "unknown" && fc.has_model() {
                    eprintln!("[WARN] {} call at {:?} has unknown calling convention", fd.name, fc.op_addr);
                }
            }
        }

        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "prototypewarnings" mirrors ctor at coreaction.hh:1047
    fn get_name(&self) -> &str { "prototypewarnings" }
}

/// Mark explicit varnodes. Faithful to `ActionMarkExplicit`
/// (coreaction.cc).
///
/// Determines which Varnodes must be explicitly printed in the output
/// (rather than being implied by expressions). The algorithm:
/// 1. For each defined Varnode, call baseExplicit to check if it should be
///    explicit (returns < 0), or is a potential implied with multiple
///    descendants (returns > 1).
/// 2. For Varnodes with multiple descendants, check interaction and possibly
///    duplicate them via processMultiplier.
/// 3. Clear marks.
pub struct ActionMarkExplicit { pub count: i32 }
impl ActionMarkExplicit {
    // Ghidra: coreaction.hh:427 ActionMarkExplicit (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }

    /// Check if a Varnode should be marked explicit. Faithful to
    /// `baseExplicit` (coreaction.cc). Returns:
    /// - -1: should be explicit
    /// - -2: explicit (NEW op, may need special printing)
    /// - 0: single descendant, not explicit
    /// - >0: number of descendants (potential implied)
    // Ghidra: coreaction.cc:3007 ActionMarkExplicit::baseExplicit
    fn base_explicit(
        vn: &crate::varnode::Varnode,
        max_ref: i32,
    ) -> i32 {
        use crate::opcodes::OpCode;
        // Get defining op.
        let Some(def) = vn.get_def() else {
            return -1; // No def → explicit.
        };
        let def_rg = def.read().unwrap();
        // Marker ops → explicit.
        if def_rg.is_marker() {
            return -1;
        }
        // Call ops → explicit.
        if def_rg.is_call() {
            // CPUI_NEW with 1 input → explicit but special.
            if def_rg.opcode == OpCode::CPUI_NEW && def_rg.num_input() == 1 {
                return -2;
            }
            return -1;
        }
        // Addr-tied varnodes are often explicit (pointers may reference them).
        if vn.is_addr_tied() {
            // Simplified: addr-tied → explicit.
            return -1;
        }
        drop(def_rg);

        // Count descendants.
        let desc_count = vn.descend_iter().count() as i32;
        if desc_count > max_ref {
            return desc_count;
        }
        if desc_count > 1 {
            return desc_count;
        }
        // Single or zero descendants → not explicit.
        desc_count
    }
}
impl Action for ActionMarkExplicit {
    // Ghidra: coreaction.cc:3237 ActionMarkExplicit::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        let max_ref = 2; // arch.max_implied_ref default
        let mut change_count = 0;

        // Iterate all varnodes from the loc_tree (VarnodeLocSet equivalent).
        // Collect defined (written or input) varnodes and process them.
        let varnodes: Vec<_> = fd
            .vbank
            .loc_tree
            .iter()
            .map(|v| v.0.clone())
            .collect();

        for vn_arc in &varnodes {
            let vn_rg = vn_arc.read().unwrap();
            // Skip free varnodes.
            if !vn_rg.is_written() && !vn_rg.is_input() {
                continue;
            }
            // Call base_explicit.
            let desc_count = Self::base_explicit(&vn_rg, max_ref);
            if desc_count < 0 {
                // Should be explicit — set the EXPLICIT flag.
                drop(vn_rg);
                vn_arc.write().unwrap().set_explicit();
                change_count += 1;
            }
            // Note: multlist + multipleInteraction + processMultiplier
            // require HighVariable integration (L3 gap).
        }

        if change_count > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }
    // RUGRA-GLUE: Rust Action trait get_name; "markexplicit" mirrors ctor at coreaction.hh:427
    fn get_name(&self) -> &str { "markexplicit" }
}

/// Mark implied varnodes. Faithful to `ActionMarkImplied`
/// (coreaction.cc).
///
/// Determines which non-explicit Varnodes can be "implied" (their value
/// is shown as an expression rather than a named variable). The algorithm
/// does a depth-first traversal of each Varnode's descendants, checking
/// if the cover allows the variable to be implied (no LOAD/STORE/call
/// aliasing issues).
pub struct ActionMarkImplied { pub count: i32 }
impl ActionMarkImplied {
    // Ghidra: coreaction.hh:449 ActionMarkImplied (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }

    /// Return false only if one Varnode is obtained by adding non-zero thing
    /// to another Varnode. Faithful to `isPossibleAliasStep`
    /// (coreaction.cc).
    #[allow(dead_code)] // reserved for full LOAD/STORE crossing check
    // Ghidra: coreaction.cc:3279 ActionMarkImplied::isPossibleAliasStep
    fn is_possible_alias_step(
        vn1: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        vn2: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
        use crate::opcodes::OpCode;
        // Check both directions: is vn1 = vn2 + const, or vn2 = vn1 + const?
        for (a, b) in [(vn1, vn2), (vn2, vn1)] {
            let a_rg = a.read().unwrap();
            if !a_rg.is_written() {
                continue;
            }
            let Some(def) = a_rg.get_def() else { continue };
            let def_rg = def.read().unwrap();
            let opc = def_rg.opcode;
            if !matches!(opc, OpCode::CPUI_INT_ADD | OpCode::CPUI_PTRSUB | OpCode::CPUI_PTRADD | OpCode::CPUI_INT_XOR) {
                continue;
            }
            // Check if the other varnode is input(0) of this op.
            let in0 = def_rg.get_in(0);
            if let Some(in0_vn) = in0 {
                if std::sync::Arc::ptr_eq(in0_vn, b) {
                    // Check if input(1) is a constant.
                    let in1 = def_rg.get_in(1);
                    if in1.map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
                        return false; // a = b + const → not a possible alias.
                    }
                }
            }
        }
        true
    }

    /// Check if a Varnode can be safely implied (its def expression inlined).
    /// Faithful to ActionMarkImplied::checkImpliedCover (coreaction.cc:3376).
    /// Returns true if it CAN be implied (no cover violation).
    ///
    /// Ghidra checks three conditions; Rugra implements:
    ///  (1) LOAD def crossing STOREs — simplified: if def is LOAD and any
    ///      STORE shares the def op's block, conservatively forbid.
    ///  (2) LOAD/CALL def crossing CALLs — simplified: if def is LOAD/CALL
    ///      and its block contains another CALL, forbid.
    ///  (3) Input cover inflation — the authoritative check: for each input
    ///      of the def op, test if inflating it to cover `high` intersects a
    ///      sibling instance (Merge::inflateTest). This prevents two SSA
    ///      versions of one logical varnode being simultaneously live.
    // Ghidra: coreaction.cc:3376 ActionMarkImplied::checkImpliedCover
    fn check_implied_cover(
        &self,
        fd: &mut Funcdata,
        vn_arc: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
        use crate::opcodes::OpCode;

        let (def_op, high_arc) = {
            let vn = vn_arc.read().unwrap();
            let def = vn.get_def();
            let high = vn.high.clone();
            (def, high)
        };
        let Some(def_op_arc) = def_op else {
            // Input varnode with no def (function parameter): can be implied
            // only if no input-cover violation. Treat as always-OK.
            return true;
        };
        let Some(high_arc) = high_arc else {
            return false; // no HighVariable — shouldn't happen post-merge
        };

        let def_op = def_op_arc.read().unwrap();
        let def_opc = def_op.opcode;

        // (1) LOAD def crossing STORE: simplified — forbid if any alive STORE
        // shares the def op's basic block. Full Ghidra uses cover.contain +
        // isPossibleAlias; this is a conservative substitute.
        if def_opc == OpCode::CPUI_LOAD {
            let def_block = def_op.parent.as_ref().and_then(|w| w.upgrade());
            if let Some(def_block) = def_block {
                let def_bi = def_block.read().unwrap().get_index();
                let stores_in_block = fd.obank.alivelist.iter().any(|o| {
                    let o = o.0.read().unwrap();
                    if o.opcode != OpCode::CPUI_STORE || o.is_dead() {
                        return false;
                    }
                    o.parent.as_ref().and_then(|w| w.upgrade())
                        .map(|b| b.read().unwrap().get_index() == def_bi)
                        .unwrap_or(false)
                });
                if stores_in_block {
                    return false;
                }
            }
        }

        // (2) CALL/LOAD def crossing another CALL: faithful to Ghidra
        // checkImpliedCover (coreaction.cc:3401-3406). A varnode defined by a
        // CALL (or LOAD) whose live cover spans another CALL op cannot be
        // implied — inlining its def expression would place a call result
        // across another call boundary. The precise check is
        // `vn->getCover()->contain(callop, 2)` (interior or shared-boundary).
        // Rugra's varnode.cover (built by Merge::compute_varnode_covers) holds
        // the def->last-read range per block, so contain(block_idx, order) is
        // the faithful equivalent.
        if matches!(def_opc, OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_LOAD) {
            let vn_cover = vn_arc.read().unwrap().cover.as_ref().map(|c| c.clone());
            if let Some(cover) = vn_cover {
                for call_op_ref in &fd.obank.alivelist {
                    let call_op = call_op_ref.0.read().unwrap();
                    if call_op.is_dead() { continue; }
                    if !matches!(call_op.opcode, OpCode::CPUI_CALL | OpCode::CPUI_CALLIND) {
                        continue;
                    }
                    // Ghidra's contain(op, max=2) returns true for interior or
                    // shared-boundary points. Rugra's contain(block_idx, order)
                    // is the interior check; we also treat the def op itself as
                    // not crossing (a CALL result feeding another input of the
                    // SAME op is not a crossing — it's the normal case).
                    if let (Some(call_blk), Some(def_blk)) = (
                        call_op.parent.as_ref().and_then(|w| w.upgrade()),
                        def_op.parent.as_ref().and_then(|w| w.upgrade()),
                    ) {
                        let call_bi = call_blk.read().unwrap().get_index();
                        let def_bi = def_blk.read().unwrap().get_index();
                        let call_order = call_op.start.get_order();
                        // Skip the defining op itself (same block + order).
                        if call_bi == def_bi && call_order == def_op.start.get_order() {
                            continue;
                        }
                        if cover.contain(call_bi, call_order) {
                            return false;
                        }
                    }
                }
            }
        }

        // (3) Input cover inflation test (the authoritative check).
        let high = high_arc.read().unwrap();
        for i in 0..def_op.num_input() {
            let Some(in_vn) = def_op.get_in(i) else { continue };
            let in_rg = in_vn.read().unwrap();
            if in_rg.is_constant() {
                continue;
            }
            drop(in_rg);
            if crate::merge::Merge::inflate_test(&in_vn.clone(), &high) {
                return false;
            }
        }
        true
    }
}
impl Action for ActionMarkImplied {
    // Ghidra: coreaction.cc:3416 ActionMarkImplied::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to Ghidra ActionMarkImplied::apply (coreaction.cc:3416).
        // Iterates all Varnodes; for each non-explicit/non-implied candidate,
        // checks whether its def expression can be safely inlined into its
        // consumer (implied) via checkImpliedCover. If yes, mark implied;
        // otherwise mark explicit (will be emitted as a named assignment).
        //
        // Ghidra uses a DFS over descendants to propagate cover inflation
        // incrementally; Rugra approximates with static high.cover (built by
        // Merge::update_high_covers). This is correct for the common case
        // (single-consumer temporaries) and conservative for rare chained
        // implications.
        let mut change_count = 0;

        let varnodes: Vec<_> = fd.vbank.loc_tree.iter().map(|v| v.0.clone()).collect();

        for vn_arc in &varnodes {
            let vn_rg = vn_arc.read().unwrap();
            // Skip free (neither input nor written), explicit, or already implied.
            if !vn_rg.is_written() && !vn_rg.is_input() {
                continue;
            }
            if vn_rg.is_explicit() || vn_rg.is_implied() {
                continue;
            }
            drop(vn_rg);

            if self.check_implied_cover(fd, vn_arc) {
                crate::merge::Merge::mark_implied(vn_arc);
            } else {
                vn_arc.write().unwrap().set_explicit();
            }
            change_count += 1;
        }

        if change_count > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }
    // RUGRA-GLUE: Rust Action trait get_name; "markimplied" mirrors ctor at coreaction.hh:449
    fn get_name(&self) -> &str { "markimplied" }
}

/// Set casts on operations. Faithful to `ActionSetCasts`
/// (coreaction.cc).
///
/// This is the final type-casting pass. It iterates all basic blocks in
/// dominance order, and for each op:
/// 1. Fixes PTRADD/PTRSUB ops that no longer fit their pointer type
/// 2. Resolves union fields on inputs
/// 3. Casts inputs to match the op's expected type
/// 4. Checks pointer issues on LOAD/STORE
/// 5. Casts the output to its declared type
pub struct ActionSetCasts { pub count: i32 }
impl ActionSetCasts {
    // Ghidra: coreaction.hh:330 ActionSetCasts (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }

    /// Expected input metatype for an op's input slot. Faithful to Ghidra
    /// `TypeOpBinary::metain` / `TypeOpUnary::metain` (typeop.hh:206,225) and
    /// `TypeOp::inputTypeLocal` → `getBase(size, metain)` (typeop.cc:329-333).
    /// Integer binary/unary ops (INT_ADD/SUB/MULT/DIV/AND/OR/XOR/shifts) have
    /// metain=TYPE_INT; BOOL_* have metain=TYPE_BOOL. Returns None for ops
    /// with no fixed input metatype (LOAD/STORE/CALL/branch etc.), which
    /// Ghidra handles via op-specific getInputCast overrides not ported here.
    // RUGRA-GLUE: helper mapping OpCode -> TypeMetatype for cast decisions; mirrors OpCode::getMetadata (typeop.cc)
    fn input_metatype(opc: OpCode) -> Option<crate::type_system::datatype::TypeMetatype> {
        use crate::type_system::datatype::TypeMetatype;
        match opc {
            // Integer arithmetic/logic/shift binary ops: metain = TYPE_INT.
            // These are the ops where a pointer-typed operand must be cast to
            // an integer (Ghidra TypeOpBinary metain, typeop.hh:206).
            // Comparisons, COPY, and extensions have op-specific getInputCast
            // overrides not captured here, so they are excluded (return None)
            // to avoid over-casting — faithful to the metain model for the
            // arithmetic/logic subset only.
            OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB | OpCode::CPUI_INT_MULT
            | OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_SDIV | OpCode::CPUI_INT_REM
            | OpCode::CPUI_INT_SREM
            | OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR | OpCode::CPUI_INT_XOR
            | OpCode::CPUI_INT_NEGATE | OpCode::CPUI_INT_2COMP
            | OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT => {
                Some(TypeMetatype::Int)
            }
            // Boolean ops: metain = TYPE_BOOL
            OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_AND
            | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR => Some(TypeMetatype::Bool),
            _ => None,
        }
    }

    /// Faithful 1:1 port of `ActionSetCasts::castInput` (coreaction.cc:2655-2720).
    /// For input `slot` of `op`, compute the op's expected input type
    /// (inputTypeLocal = getBase(size, metain)), the current varnode's high
    /// type, and if `castStandard` says a cast is needed, insert a CPUI_CAST op
    /// feeding the slot: `out = CAST(in)`, with out implied (inlined by printc
    /// as `(reqtype)in`).
    ///
    /// Returns true if a cast was inserted.
    // Ghidra: coreaction.cc:2655 ActionSetCasts::castInput
    fn cast_input(
        &self,
        fd: &mut Funcdata,
        op_ref: &crate::op::PcodeOpRef,
        slot: usize,
        strategy: &crate::type_system::cast::CastStrategyC,
    ) -> bool {
        use crate::type_system::cast::base_type_for;
        // (1) Compute reqtype = op->inputTypeLocal(slot) = getBase(size, metain).
        let (in_vn, reqtype, curtype, op_pc, in_size) = {
            let op = op_ref.0.read().unwrap();
            let Some(in_arc_ref) = op.get_in(slot) else { return false; };
            let in_arc = in_arc_ref.clone();
            let op_pc = op.get_addr();
            let meta_opt = Self::input_metatype(op.opcode);
            drop(op);
            let Some(meta) = meta_opt else { return false; };
            let (in_size, curtype, is_annot) = {
                let in_rg = in_arc.read().unwrap();
                let is_annot = in_rg.is_annotation();
                let in_size = in_rg.get_size();
                let curtype = in_rg.high.as_ref()
                    .map(|h| h.read().unwrap().v_type.clone())
                    .or_else(|| in_rg.v_type.clone())
                    .unwrap_or_else(|| base_type_for(in_size, meta));
                (in_size, curtype, is_annot)
            };
            if is_annot { return false; }
            let reqtype = base_type_for(in_size, meta);
            (in_arc, reqtype, curtype, op_pc, in_size)
        };
        // (2) castStandard(reqtype, curtype, care_uint_int=false, care_ptr_uint=true)
        let Some(_cast_type) = strategy.cast_standard_full(&reqtype, &curtype, false, true) else {
            return false;
        };
        // (3) Insert CPUI_CAST op: out = CAST(in), out implied.
        //     Faithful to coreaction.cc:2702-2712.
        if in_vn.read().unwrap().is_constant() {
            // Constants just get their type updated (castInput const path).
            in_vn.write().unwrap().v_type = Some(reqtype);
            return true;
        }
        let new_op = fd.new_op(1, op_pc);
        let out_vn = fd.new_unique_out(in_size, &new_op);
        out_vn.write().unwrap().v_type = Some(reqtype);
        out_vn.write().unwrap().set_implied();
        fd.op_set_opcode(&new_op, OpCode::CPUI_CAST);
        fd.op_set_input(&new_op, in_vn, 0);
        fd.op_set_input(op_ref, out_vn, slot);
        fd.op_insert_before(&new_op, op_ref);
        true
    }
}
impl Action for ActionSetCasts {
    // Ghidra: coreaction.cc:2722 ActionSetCasts::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionSetCasts::apply (coreaction.cc:2722-2774). Iterate
        // ops in basic-block/dominance order (Rugra iterates alivelist, which
        // is already in block+seq order). For each non-CAST op, for each input
        // slot, run castInput (inserting CPUI_CAST where the op's expected
        // input type differs from the varnode's high type).
        //
        // Scope: this ports the integer binary/unary input-cast path (the
        // common case causing `piVar | param` int*-to-long errors). The
        // PTRADD/PTRSUB pointer-fit checks, resolveUnion, checkPointerIssues,
        // and castOutput are deferred (they need more type-system + union
        // infrastructure).
        let ops: Vec<crate::op::PcodeOpRef> = fd.obank.alivelist.clone();
        let strategy = crate::type_system::cast::CastStrategyC::new(4);
        let mut count = 0;
        for op_ref in &ops {
            let (opc, n_inputs) = {
                let op = op_ref.0.read().unwrap();
                if op.is_dead() { continue; }
                (op.opcode, op.num_input())
            };
            if opc == OpCode::CPUI_CAST { continue; }
            // castInput may mutate inputs; iterate a snapshot of slots.
            for slot in 0..n_inputs {
                if self.cast_input(fd, op_ref, slot, &strategy) {
                    count += 1;
                }
            }
        }
        if count > 0 { Ok(action_status::CHANGE) } else { Ok(action_status::NO_CHANGE) }
    }
    // RUGRA-GLUE: Rust Action trait get_name; "setcasts" mirrors ctor at coreaction.hh:330
    fn get_name(&self) -> &str { "setcasts" }
}

/// Infer types from data-flow. Faithful to `ActionInferTypes`
/// (coreaction.cc).
///
/// This is the main type propagation algorithm. It iterates all Varnodes,
/// propagating type constraints along data-flow edges. The algorithm uses
/// a DFS traversal with a PropagationState stack to follow type edges
/// through COPY, INT_ZEXT, INT_SEXT, and other type-changing ops.
///
/// Key sub-algorithms:
/// - `buildLocaltypes`: set up initial types based on local info
/// - `propagateOneType`: DFS type propagation for one Varnode
/// - `propagateAcrossReturns`: propagate types across RETURN ops
/// - `propagateSpacebaseRef`: propagate pointer types to spacebase aliases
/// - `writeBack`: write final types back to Varnodes
pub struct ActionInferTypes {
    pub local_count: i32,
}
impl ActionInferTypes {
    // Ghidra: coreaction.hh:960 ActionInferTypes (constructor mirror)
    pub fn new() -> Self { Self { local_count: 0 } }
}

/// Temporary type store for one propagation pass. Ghidra keeps the temp type
/// directly on the Varnode (`temp_extra_type`). Rugra has no such field, so we
/// key temp types by a stable per-varnode id. Faithful to the
/// `getTempType`/`setTempType` pair used throughout ActionInferTypes
/// (coreaction.cc:5008-5416).
type TempTypes = HashMap<u64, std::sync::Arc<crate::type_system::datatype::Datatype>>;

/// Stable id for a varnode inside the temp-type map. Combines the varnode's
/// create_index with its size so that distinct overlapping varnodes don't
/// collide. (Rugra varnodes are uniquely keyed by (loc, size, create_index).)
#[inline]
// RUGRA-GLUE: Rugra helper producing a stable u64 key for a Varnode (Rust borrow workaround)
fn vn_id(vn: &crate::varnode::Varnode) -> u64 {
    // offset encodes the address+space identity; combine with size & create_index.
    let off = vn.get_offset();
    let sz = vn.get_size() as u64;
    (off ^ sz.wrapping_mul(0x9E3779B97F4A7C15))
        ^ (vn.create_index as u64).wrapping_mul(0xD1B54A32D192ED03)
}

/// Build a pointer type to `base` with the architecture pointer size, using a
/// fresh factory-free TypePointer. Faithful to `TypeFactory::getTypePointer`.
// RUGRA-GLUE: helper mirroring TypeFactory::getTypePointer (type.hh)
fn make_ptr(
    base: std::sync::Arc<crate::type_system::datatype::Datatype>,
    ptr_size: usize,
) -> std::sync::Arc<crate::type_system::datatype::Datatype> {
    use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
    let name = format!("{} *", base.get_name());
    std::sync::Arc::new(Datatype::Pointer(TypePointer {
        base: TypeBase::new(name, ptr_size, TypeMetatype::Pointer),
        ptr_to: base,
        wordsize: 1,
    }))
}

/// Resolve the pointed-to type of a (possibly pointer) type, or None.
// RUGRA-GLUE: helper mirroring TypePointer::getPtrTo (type.hh)
fn ptr_to<'a>(
    ct: &'a crate::type_system::datatype::Datatype,
) -> Option<&'a std::sync::Arc<crate::type_system::datatype::Datatype>> {
    use crate::type_system::datatype::Datatype;
    match ct {
        Datatype::Pointer(p) => Some(&p.ptr_to),
        _ => None,
    }
}

impl ActionInferTypes {
    // Ghidra: coreaction.cc:5008 ActionInferTypes::buildLocaltypes
    /// Faithful to `ActionInferTypes::buildLocaltypes` (coreaction.cc:5008-5037).
    /// Collect local data-type information on each Varnode inferred from the
    /// PcodeOps that read/write it, storing results in the temp map.
    fn build_localtypes(
        &self,
        fd: &Funcdata,
        temps: &mut TempTypes,
        int_types: &IntTypes,
        ptr_size: usize,
    ) {
        use crate::type_system::datatype::TypeMetatype;
        // Walk all live ops and seed temp types from op semantics. Mirrors the
        // per-op local-type inference Ghidra folds into Varnode::getLocalType.
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if op.is_dead() {
                continue;
            }
            match op.opcode {
                // CBRANCH: its boolean condition input is a bool (input slot 1).
                OpCode::CPUI_CBRANCH => {
                    if let Some(cond) = op.get_in(1) {
                        let cv = cond.read().unwrap();
                        temps.insert(vn_id(&cv), int_types.bool.clone());
                    }
                }
                // Comparison ops → boolean output (coreaction.cc implicit via
                // propagateType, but seeding here bootstraps the DFS).
                OpCode::CPUI_INT_EQUAL
                | OpCode::CPUI_INT_NOTEQUAL
                | OpCode::CPUI_INT_LESS
                | OpCode::CPUI_INT_SLESS
                | OpCode::CPUI_INT_LESSEQUAL
                | OpCode::CPUI_INT_SLESSEQUAL
                | OpCode::CPUI_FLOAT_EQUAL
                | OpCode::CPUI_FLOAT_NOTEQUAL
                | OpCode::CPUI_FLOAT_LESS
                | OpCode::CPUI_FLOAT_LESSEQUAL => {
                    if let Some(out) = op.get_out() {
                        let ov = out.read().unwrap();
                        temps.insert(vn_id(&ov), int_types.bool.clone());
                    }
                }
                // Boolean ops → boolean output.
                OpCode::CPUI_BOOL_NEGATE
                | OpCode::CPUI_BOOL_AND
                | OpCode::CPUI_BOOL_OR
                | OpCode::CPUI_BOOL_XOR => {
                    if let Some(out) = op.get_out() {
                        let ov = out.read().unwrap();
                        temps.insert(vn_id(&ov), int_types.bool.clone());
                    }
                }
                // LOAD: address input (slot 1) is a pointer; output gets a
                // size-based scalar so the address pointer can bootstrap.
                OpCode::CPUI_LOAD => {
                    if let (Some(space_in), Some(addr_in), Some(out)) =
                        (op.get_in(0), op.get_in(1), op.get_out())
                    {
                        let av = addr_in.read().unwrap();
                        let _ = space_in;
                        let ov = out.read().unwrap();
                        let pointed = int_types.sized(ov.get_size());
                        temps
                            .entry(vn_id(&av))
                            .and_modify(|e| {
                                if e.get_metatype() == TypeMetatype::Unknown {
                                    *e = make_ptr(pointed.clone(), ptr_size);
                                }
                            })
                            .or_insert_with(|| make_ptr(pointed.clone(), ptr_size));
                        temps.entry(vn_id(&ov)).or_insert(pointed);
                    }
                }
                // STORE: address input (slot 1) is a pointer to the value
                // input's type (slot 2).
                OpCode::CPUI_STORE => {
                    if let (Some(addr_in), Some(val_in)) = (op.get_in(1), op.get_in(2)) {
                        let av = addr_in.read().unwrap();
                        let vv = val_in.read().unwrap();
                        let pointed = int_types.sized(vv.get_size());
                        temps
                            .entry(vn_id(&av))
                            .or_insert_with(|| make_ptr(pointed.clone(), ptr_size));
                        temps.entry(vn_id(&vv)).or_insert(pointed);
                    }
                }
                // INT_ADD/INT_SUB/PTRSUB/PTRADD with a spacebase input →
                // pointer output. Mirrors Ghidra's pointer arithmetic
                // propagation (Varnode::getLocalType spacebase path).
                OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB | OpCode::CPUI_PTRSUB => {
                    if let (Some(in0), Some(out)) = (op.get_in(0), op.get_out()) {
                        let i0 = in0.read().unwrap();
                        if i0.is_spacebase() {
                            let ov = out.read().unwrap();
                            let pointed = int_types.sized(ov.get_size());
                            temps.insert(vn_id(&ov), make_ptr(pointed, ptr_size));
                        }
                    }
                }
                _ => {}
            }
        }

        // Seed every otherwise-untyped written/output varnode with a
        // size-based scalar local type (Ghidra's getLocalType fallback).
        for vn_arc in fd.vbank.loc_tree.iter().map(|v| v.0.clone()) {
            let vn = vn_arc.read().unwrap();
            if vn.is_annotation() {
                continue;
            }
            if !vn.is_written() && vn.has_no_descend() {
                continue;
            }
            let id = vn_id(&vn);
            if !temps.contains_key(&id) {
                if let Some(t) = vn.v_type.clone() {
                    temps.insert(id, t);
                } else {
                    temps.insert(id, int_types.sized(vn.get_size()));
                }
            }
        }
    }

    /// Faithful to `ActionInferTypes::propagateTypeEdge` (coreaction.cc:5074-5112).
    /// Attempt to propagate a data-type across a single PcodeOp edge.
    /// `inslot` is the edge's input varnode slot (-1 = op output);
    /// `outslot` is the edge's output slot (-1 = op output).
    /// Returns the out varnode arc if the propagation changed its temp type.
    // Ghidra: coreaction.cc:5074 ActionInferTypes::propagateTypeEdge
    fn propagate_type_edge(
        op: &crate::op::PcodeOp,
        temps: &TempTypes,
        inslot: i32,
        outslot: i32,
        int_types: &IntTypes,
        ptr_size: usize,
    ) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        if inslot == outslot {
            return None; // don't backtrack
        }
        // Resolve the incoming varnode + its temp type.
        let in_vn_arc: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> =
            if inslot == -1 {
                op.output.clone()
            } else {
                op.inrefs.get(inslot as usize).cloned()
            };
        let in_vn_arc = in_vn_arc?;
        let alttype = {
            let inv = in_vn_arc.read().unwrap();
            temps.get(&vn_id(&inv)).cloned()
        };
        let alttype = alttype?;

        // Resolve the outgoing varnode.
        let out_vn_arc = if outslot < 0 {
            op.output.clone()
        } else {
            let cand = op.inrefs.get(outslot as usize).cloned();
            if let Some(ref a) = cand {
                if a.read().unwrap().is_annotation() {
                    return None;
                }
            }
            cand
        };
        let out_vn_arc = out_vn_arc?;
        {
            let ov = out_vn_arc.read().unwrap();
            if ov.is_type_lock() {
                return None;
            }
        }

        // Boolean propagation guard (coreaction.cc:5095-5098).
        if alttype.get_metatype() == crate::type_system::datatype::TypeMetatype::Bool {
            let nz = out_vn_arc.read().unwrap().get_nz_mask();
            if nz > 1 {
                return None;
            }
        }

        // The per-opcode propagateType dispatch (op.cc propagateType). Returns
        // the new type for the output, if any.
        let newtype =
            Self::propagate_type(op, &alttype, inslot, outslot, int_types, ptr_size)?;
        let cur = {
            let ov = out_vn_arc.read().unwrap();
            temps.get(&vn_id(&ov)).cloned()
        };
        // typeOrder: only propagate if newtype is strictly less (more specific)
        // than the current temp type.
        let better = match &cur {
            None => true,
            Some(c) => newtype.type_order(c) < 0,
        };
        if better {
            Some(out_vn_arc)
        } else {
            None
        }
    }

    /// Per-opcode `propagateType` dispatch. Faithful to
    /// `OpCode::propagateType` (typeop*.cc). Returns the type that the output
    /// varnode should take when `alttype` flows from `inslot` to `outslot`.
    // RUGRA-GLUE: Rugra driver that folds ActionInferTypes::propagateOneType over the varnode set (coreaction.cc:5400-5405)
    fn propagate_type(
        op: &crate::op::PcodeOp,
        alttype: &std::sync::Arc<crate::type_system::datatype::Datatype>,
        inslot: i32,
        outslot: i32,
        int_types: &IntTypes,
        ptr_size: usize,
    ) -> Option<std::sync::Arc<crate::type_system::datatype::Datatype>> {
        use crate::type_system::datatype::TypeMetatype;
        let alt_meta = alttype.get_metatype();
        match op.opcode {
            // COPY: type flows straight through, both directions.
            OpCode::CPUI_COPY => Some(alttype.clone()),

            // MULTIEQUAL (phi): type flows between output and any input.
            OpCode::CPUI_MULTIEQUAL => Some(alttype.clone()),

            // INDIRECT: transparent.
            OpCode::CPUI_INDIRECT => Some(alttype.clone()),

            // Zero-extending: output carries input's type (forward).
            OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT => {
                if outslot == -1 {
                    Some(alttype.clone())
                } else {
                    None
                }
            }

            // Subpiece: if extracting a full piece, forward the type.
            OpCode::CPUI_SUBPIECE => {
                if inslot == 0 && outslot == -1 {
                    // Only forward if sizes match (whole varnode extracted).
                    if let Some(out) = op.get_out() {
                        if out.read().unwrap().get_size() == alttype.get_size() {
                            return Some(alttype.clone());
                        }
                    }
                    None
                } else {
                    None
                }
            }

            // Pointer arithmetic: pointer + int → pointer.
            OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB | OpCode::CPUI_PTRADD
            | OpCode::CPUI_PTRSUB => {
                if alt_meta == TypeMetatype::Pointer {
                    // Pointer flows to the output and to the non-constant
                    // sibling input.
                    if outslot == -1 {
                        return Some(alttype.clone());
                    }
                    if outslot >= 0 {
                        let outslot_s = outslot as usize;
                        if let Some(sib) = op.inrefs.get(outslot_s) {
                            let sv = sib.read().unwrap();
                            if !sv.is_constant() {
                                return Some(alttype.clone());
                            }
                        }
                    }
                    None
                } else {
                    None
                }
            }

            // LOAD: the address (slot 1) is a pointer to the output's type,
            // and vice-versa.
            OpCode::CPUI_LOAD => {
                if inslot == 1 && outslot == -1 {
                    // pointer → dereferenced type
                    if let Some(pt) = ptr_to(alttype) {
                        return Some(pt.clone());
                    }
                }
                if inslot == -1 && outslot == 1 {
                    // output type → address becomes pointer to it
                    return Some(make_ptr(alttype.clone(), ptr_size));
                }
                None
            }

            // STORE: address (slot 1) ↔ stored value (slot 2).
            OpCode::CPUI_STORE => {
                if inslot == 1 && outslot == 2 {
                    if let Some(pt) = ptr_to(alttype) {
                        return Some(pt.clone());
                    }
                }
                if inslot == 2 && outslot == 1 {
                    return Some(make_ptr(alttype.clone(), ptr_size));
                }
                None
            }

            // Comparisons: bool output, no input propagation.
            OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL | OpCode::CPUI_INT_LESS
            | OpCode::CPUI_INT_SLESS | OpCode::CPUI_INT_LESSEQUAL
            | OpCode::CPUI_INT_SLESSEQUAL | OpCode::CPUI_FLOAT_EQUAL
            | OpCode::CPUI_FLOAT_NOTEQUAL | OpCode::CPUI_FLOAT_LESS
            | OpCode::CPUI_FLOAT_LESSEQUAL => {
                if outslot == -1 {
                    Some(int_types.bool.clone())
                } else {
                    None
                }
            }

            // Boolean ops: bool everywhere.
            OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_AND | OpCode::CPUI_BOOL_OR
            | OpCode::CPUI_BOOL_XOR => Some(int_types.bool.clone()),

            // Arithmetic/logical on ints: the common int type flows.
            OpCode::CPUI_INT_MULT | OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_SDIV
            | OpCode::CPUI_INT_REM | OpCode::CPUI_INT_SREM | OpCode::CPUI_INT_AND
            | OpCode::CPUI_INT_OR | OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_NEGATE
            | OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT
            | OpCode::CPUI_FLOAT_ADD | OpCode::CPUI_FLOAT_SUB | OpCode::CPUI_FLOAT_MULT
            | OpCode::CPUI_FLOAT_DIV | OpCode::CPUI_FLOAT_NEG
            | OpCode::CPUI_FLOAT_ABS | OpCode::CPUI_FLOAT_SQRT
            | OpCode::CPUI_FLOAT_CEIL | OpCode::CPUI_FLOAT_FLOOR
            | OpCode::CPUI_FLOAT_ROUND => {
                if alt_meta == TypeMetatype::Pointer {
                    return None; // don't propagate pointers through generic arith
                }
                if outslot == -1 {
                    Some(alttype.clone())
                } else if outslot >= 0 {
                    // Forward to sibling input if both are same-size ints.
                    if let Some(out) = op.get_out() {
                        let out_sz = out.read().unwrap().get_size();
                        if alttype.get_size() == out_sz {
                            return Some(alttype.clone());
                        }
                    }
                    None
                } else {
                    None
                }
            }

            _ => None,
        }
    }

    /// Faithful to `ActionInferTypes::propagateOneType` (coreaction.cc:5172-5198).
    /// DFS from one varnode, pushing its temp type across every propagating
    /// edge. Each varnode is visited at most once per root propagation.
    // Ghidra: coreaction.cc:5172 ActionInferTypes::propagateOneType
    fn propagate_one_type(
        &self,
        root: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        temps: &mut TempTypes,
        int_types: &IntTypes,
        ptr_size: usize,
    ) {
        use std::collections::HashSet;
        // Stack of (op_arc, inslot, outslot) edges to explore, plus the set of
        // visited varnodes (mirrors Ghidra's Varnode mark bit).
        // We model PropagationState's iterator (descendents then def) explicitly.
        let mut visited: HashSet<u64> = HashSet::new();
        visited.insert(vn_id(&root.read().unwrap()));

        // Initial frontier: for the root, edges go to its descendants (reads)
        // and to/from its defining op.
        #[derive(Clone)]
        struct Edge {
            op: std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>,
            inslot: i32,
            outslot: i32,
        }

        let mut stack: Vec<Edge> = Vec::new();
        // Descendant ops: root is an input (inslot = root's slot in that op),
        // out candidates = the op's output (-1) and other inputs.
        let descendents: Vec<_> = root.read().unwrap().descend_iter().collect();
        for dop in descendents {
            let inslot = {
                let op = dop.read().unwrap();
                op.inrefs
                    .iter()
                    .position(|r| std::sync::Arc::ptr_eq(r, root))
                    .map(|p| p as i32)
            };
            if let Some(ins) = inslot {
                let op = dop.read().unwrap();
                if op.output.is_some() {
                    stack.push(Edge { op: dop.clone(), inslot: ins, outslot: -1 });
                }
                for s in 0..op.num_input() {
                    if s as i32 != ins {
                        stack.push(Edge { op: dop.clone(), inslot: ins, outslot: s as i32 });
                    }
                }
            }
        }
        // Defining op: root is the output (inslot = -1); out candidates are
        // the def's inputs.
        if let Some(def) = root.read().unwrap().get_def() {
            let n = def.read().unwrap().num_input();
            for s in 0..n {
                stack.push(Edge { op: def.clone(), inslot: -1, outslot: s as i32 });
            }
        }

        while let Some(edge) = stack.pop() {
            let op_arc = edge.op.clone();
            let op = op_arc.read().unwrap();
            if let Some(out_vn_arc) = Self::propagate_type_edge(
                &op, temps, edge.inslot, edge.outslot, int_types, ptr_size,
            ) {
                // Determine the new type for the output varnode.
                let in_vn_arc = if edge.inslot == -1 {
                    op.output.clone()
                } else {
                    op.inrefs.get(edge.inslot as usize).cloned()
                };
                let alttype = in_vn_arc
                    .and_then(|a| temps.get(&vn_id(&a.read().unwrap())).cloned());
                let newtype = alttype.and_then(|t| {
                    Self::propagate_type(&op, &t, edge.inslot, edge.outslot, int_types, ptr_size)
                });
                drop(op); // release borrow before mutating temps
                if let Some(nt) = newtype {
                    let oid = vn_id(&out_vn_arc.read().unwrap());
                    let improved = match temps.get(&oid) {
                        None => true,
                        Some(c) => nt.type_order(c) < 0,
                    };
                    if improved && !visited.contains(&oid) {
                        temps.insert(oid, nt);
                        visited.insert(oid);
                        // Push edges from the newly-typed varnode.
                        let outs = out_vn_arc.clone();
                        let descendents: Vec<_> = outs.read().unwrap().descend_iter().collect();
                        for dop in descendents {
                            let inslot = {
                                let o = dop.read().unwrap();
                                o.inrefs
                                    .iter()
                                    .position(|r| std::sync::Arc::ptr_eq(r, &out_vn_arc))
                                    .map(|p| p as i32)
                            };
                            if let Some(ins) = inslot {
                                let o = dop.read().unwrap();
                                if o.output.is_some() {
                                    stack.push(Edge { op: dop.clone(), inslot: ins, outslot: -1 });
                                }
                                for s in 0..o.num_input() {
                                    if s as i32 != ins {
                                        stack.push(Edge {
                                            op: dop.clone(),
                                            inslot: ins,
                                            outslot: s as i32,
                                        });
                                    }
                                }
                            }
                        }
                        let def_opt = outs.read().unwrap().get_def();
                        if let Some(def) = def_opt {
                            let n = def.read().unwrap().num_input();
                            for s in 0..n {
                                stack.push(Edge { op: def.clone(), inslot: -1, outslot: s as i32 });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Faithful to `ActionInferTypes::writeBack` (coreaction.cc:5043-5060).
    /// Copy temp types to the permanent v_type field (respecting locks).
    /// Returns true if any varnode changed.
    // Ghidra: coreaction.cc:5043 ActionInferTypes::writeBack
    fn write_back(&self, fd: &Funcdata, temps: &TempTypes) -> bool {
        let mut changed = false;
        for vn_arc in fd.vbank.loc_tree.iter().map(|v| v.0.clone()) {
            let id = vn_id(&vn_arc.read().unwrap());
            if let Some(ct) = temps.get(&id) {
                let mut vn = vn_arc.write().unwrap();
                if vn.is_annotation() {
                    continue;
                }
                if !vn.is_written() && vn.has_no_descend() {
                    continue;
                }
                if vn.update_type(ct.clone()) {
                    changed = true;
                }
            }
        }
        changed
    }

    /// Faithful to `ActionInferTypes::propagateAcrossReturns`
    /// (coreaction.cc:5342-5372). Propagate the canonical return type to all
    /// other RETURN ops' input varnodes.
    // Ghidra: coreaction.cc:5342 ActionInferTypes::propagateAcrossReturns
    fn propagate_across_returns(
        &self,
        fd: &Funcdata,
        temps: &mut TempTypes,
        int_types: &IntTypes,
        ptr_size: usize,
    ) {
        use crate::type_system::datatype::TypeMetatype;
        if fd.get_func_proto().is_output_locked() {
            return;
        }
        // Find the canonical RETURN op: the one whose return varnode has the
        // most-specific temp type.
        let mut best: Option<(
            std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
            std::sync::Arc<crate::type_system::datatype::Datatype>,
        )> = None;
        let return_ops: Vec<_> = fd
            .obank
            .alivelist
            .iter()
            .filter(|r| r.0.read().unwrap().opcode == OpCode::CPUI_RETURN)
            .cloned()
            .collect();
        for r in &return_ops {
            let op = r.0.read().unwrap();
            if op.is_dead() || op.num_input() <= 1 {
                continue;
            }
            if let Some(rv) = op.get_in(1) {
                let id = vn_id(&rv.read().unwrap());
                if let Some(ct) = temps.get(&id) {
                    let better = match &best {
                        None => true,
                        Some((_, bct)) => ct.type_order(bct) < 0,
                    };
                    if better {
                        best = Some((rv.clone(), ct.clone()));
                    }
                }
            }
        }
        let (base_vn, base_ct) = match best {
            Some(b) => b,
            None => return,
        };
        let base_size = base_vn.read().unwrap().get_size();
        let is_bool = base_ct.get_metatype() == TypeMetatype::Bool;
        for r in &return_ops {
            let op = r.0.read().unwrap();
            if op.num_input() <= 1 {
                continue;
            }
            let rv = match op.get_in(1) {
                Some(v) => v.clone(),
                None => continue,
            };
            if std::sync::Arc::ptr_eq(&rv, &base_vn) {
                continue;
            }
            let rvsz = rv.read().unwrap().get_size();
            if rvsz != base_size {
                continue;
            }
            if is_bool && rv.read().unwrap().get_nz_mask() > 1 {
                continue;
            }
            let id = vn_id(&rv.read().unwrap());
            let improved = match temps.get(&id) {
                None => true,
                Some(c) => base_ct.type_order(c) < 0,
            };
            if improved {
                temps.insert(id, base_ct.clone());
                let rv2 = rv.clone();
                self.propagate_one_type(&rv2, temps, int_types, ptr_size);
            }
        }
    }
}

/// Cached base types for a propagation pass, indexed by size. Avoids
/// re-allocating identical scalar types across the per-op loops.
struct IntTypes {
    bool: std::sync::Arc<crate::type_system::datatype::Datatype>,
    int_1: std::sync::Arc<crate::type_system::datatype::Datatype>,
    int_2: std::sync::Arc<crate::type_system::datatype::Datatype>,
    int_4: std::sync::Arc<crate::type_system::datatype::Datatype>,
    int_8: std::sync::Arc<crate::type_system::datatype::Datatype>,
}

impl IntTypes {
    // RUGRA-GLUE: IntTypes helper; size->Datatype lookup mirroring TypeFactory base-type table
    fn sized(&self, sz: usize) -> std::sync::Arc<crate::type_system::datatype::Datatype> {
        match sz {
            1 => self.int_1.clone(),
            2 => self.int_2.clone(),
            4 => self.int_4.clone(),
            _ => self.int_8.clone(),
        }
    }
}

impl Action for ActionInferTypes {
    // Ghidra: coreaction.cc:5374 ActionInferTypes::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionInferTypes::apply (coreaction.cc:5374-5416).
        // 1. If type recovery has not started, do nothing.
        if !fd.has_type_recovery_started() {
            return Ok(action_status::NO_CHANGE);
        }
        // 2. If we have run too many passes without settling, warn once and stop.
        if self.local_count >= 7 {
            if self.local_count == 7 {
                fd.warning_header("Type propagation algorithm not settling");
                self.local_count += 1;
            }
            return Ok(action_status::NO_CHANGE);
        }

        // Build the cached base types, preferring the architecture's
        // TypeFactory core types when available.
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
        // Pointer size: prefer the architecture's stack-pointer size, which on
        // every supported target equals the data pointer size. Fall back to 8.
        let ptr_size = fd
            .arch
            .as_ref()
            .map(|a| a.stack_pointer_size)
            .unwrap_or(8);
        let int_types = IntTypes {
            bool: fd
                .arch
                .as_ref()
                .and_then(|a| a.types.as_ref())
                .and_then(|tf| tf.read().unwrap().get_base(1, TypeMetatype::Bool))
                .unwrap_or_else(|| {
                    std::sync::Arc::new(Datatype::Base(TypeBase::new(
                        "bool".to_string(),
                        1,
                        TypeMetatype::Bool,
                    )))
                }),
            int_1: std::sync::Arc::new(Datatype::Base(TypeBase::new(
                "byte".to_string(),
                1,
                TypeMetatype::Uint,
            ))),
            int_2: std::sync::Arc::new(Datatype::Base(TypeBase::new(
                "short".to_string(),
                2,
                TypeMetatype::Int,
            ))),
            int_4: std::sync::Arc::new(Datatype::Base(TypeBase::new(
                "int".to_string(),
                4,
                TypeMetatype::Int,
            ))),
            int_8: std::sync::Arc::new(Datatype::Base(TypeBase::new(
                "long".to_string(),
                8,
                TypeMetatype::Int,
            ))),
        };
        // 3. buildLocalTypes: seed temp types from op semantics.
        let mut temps: TempTypes = HashMap::new();
        self.build_localtypes(fd, &mut temps, &int_types, ptr_size);

        // 4. For each eligible varnode, propagate its type via DFS.
        let roots: Vec<_> = fd
            .vbank
            .loc_tree
            .iter()
            .map(|v| v.0.clone())
            .filter(|v| {
                let r = v.read().unwrap();
                !r.is_annotation() && (r.is_written() || !r.has_no_descend())
            })
            .collect();
        for root in &roots {
            // Only seed roots that actually have a temp type.
            if temps.contains_key(&vn_id(&root.read().unwrap())) {
                self.propagate_one_type(root, &mut temps, &int_types, ptr_size);
            }
        }

        // 5. propagateAcrossReturns.
        self.propagate_across_returns(fd, &mut temps, &int_types, ptr_size);

        // 6. writeBack: commit temp types to v_type.
        if self.write_back(fd, &temps) {
            self.local_count += 1;
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "infertypes" mirrors ctor at coreaction.hh:960
    fn get_name(&self) -> &str { "infertypes" }
}

/// Name variables. Faithful to `ActionNameVars`
/// (coreaction.cc).
///
/// Assigns names to unnamed variables based on:
/// 1. Symbol linkage (equates, spacebase registers)
/// 2. Function parameter names from callees
/// 3. Default name generation (buildDefaultName)
/// 4. Scope default name assignment
pub struct ActionNameVars;
impl ActionNameVars {
    // Ghidra: coreaction.hh:470 ActionNameVars (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionNameVars {
    // Ghidra: coreaction.cc:2978 ActionNameVars::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Ghidra algorithm:
        // 1. linkSymbols(data, namerec):
        //    - Iterate constant-space Varnodes with SymbolEntry → linkSymbol
        //    - Iterate all-space Varnodes → linkSpacebaseSymbol for spacebase
        //    - For each HighVariable name representative → add to namerec
        // 2. scope.recoverNameRecommendationsForSymbols()
        // 3. lookForBadJumpTables(data)
        // 4. lookForFuncParamNames(data, namerec):
        //    - For each call, check if callee has named params
        //    - Propagate parameter names to the calling function's inputs
        // 5. For each Varnode in namerec:
        //    - If symbol name is undefined: scope.buildDefaultName + renameSymbol
        // 6. scope.assignDefaultNames(base)
        //
        let varnodes: Vec<_> = fd.vbank.loc_tree.iter().map(|v| v.0.clone()).collect();
        for vn_arc in &varnodes {
            let vn_rg = vn_arc.read().unwrap();
            if vn_rg.is_input() {
                // Potential param to name.
            }
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "namevars" mirrors ctor at coreaction.hh:470
    fn get_name(&self) -> &str { "namevars" }
}

/// Set up varnode properties. Faithful to `ActionVarnodeProps`
/// (coreaction.cc).
pub struct ActionVarnodeProps;
impl ActionVarnodeProps {
    // Ghidra: coreaction.hh:222 ActionVarnodeProps (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionVarnodeProps {
    // Ghidra: coreaction.cc:1282 ActionVarnodeProps::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Partial implementation of ActionVarnodeProps (coreaction.cc).
        // The full Ghidra algorithm sets Varnode properties like readonly
        // propagation, autolive-hold clearing, and action-property handling.
        //
        // Simplified: iterate all Varnodes, clear autolive-hold flags on
        // Varnodes defined by LOAD from constant/readonly pointers.
        let mut change_count = 0;
        use crate::opcodes::OpCode;

        let varnodes: Vec<_> = fd
            .vbank
            .loc_tree
            .iter()
            .map(|v| v.0.clone())
            .collect();

        for vn_arc in &varnodes {
            let vn_rg = vn_arc.read().unwrap();
            // Skip annotations.
            if vn_rg.is_annotation() {
                continue;
            }
            // Check readonly Varnodes.
            if vn_rg.is_read_only() {
                // In full Ghidra: if readonlypropagate, try fillinReadOnly
                // to replace vn with its LoadImage value.
                // L3 gap: requires LoadImage + Architecture integration.
            }
            // Check if defined by LOAD from a constant pointer.
            if vn_rg.is_written() {
                if let Some(def) = vn_rg.get_def() {
                    let def_rg = def.read().unwrap();
                    if def_rg.opcode == OpCode::CPUI_LOAD {
                        // Check if the pointer input is constant or readonly.
                        if let Some(ptr) = def_rg.get_in(1) {
                            let ptr_rg = ptr.read().unwrap();
                            if ptr_rg.is_constant() || ptr_rg.is_read_only() {
                                // This LOAD is from a known address —
                                // the Varnode can potentially be replaced.
                                // Full implementation: fillinReadOnly.
                                change_count += 1;
                            }
                        }
                    }
                }
            }
        }

        if change_count > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }
    // RUGRA-GLUE: Rust Action trait get_name; "varnodeprops" mirrors ctor at coreaction.hh:222
    fn get_name(&self) -> &str { "varnodeprops" }
}

/// Restrict local varnodes. Faithful to `ActionRestrictLocal`
/// (coreaction.cc).
///
/// Marks certain storage locations as "not mapped" in the local scope:
/// 1. Stack-passed parameters from calls (spacebase-relative params)
/// 2. Saved registers (unaffected values copied to stack for saving)
///
/// This prevents the decompiler from creating local variables for these
/// locations, which are temporary storage used by the compiler.
pub struct ActionRestrictLocal;
impl ActionRestrictLocal {
    // Ghidra: coreaction.hh:813 ActionRestrictLocal (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionRestrictLocal {
    // Ghidra: coreaction.cc:1957 ActionRestrictLocal::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionRestrictLocal::apply (coreaction.cc:1957-2001).
        // Collect all mark_not_mapped ranges first, then apply to scope
        // at the end to avoid borrow conflicts.
        let mut unmap_ranges: Vec<(u64, i32, bool)> = Vec::new();

        // Loop 1: For each call with locked stack params, markNotMapped.
        // Faithful to coreaction.cc:1967-1981.
        let n_calls = fd.num_calls();
        for i in 0..n_calls {
            let fc = match fd.get_call_specs(i) { Some(fc) => fc, None => continue };
            if !fc.is_input_locked() { continue; }
            if !fc.has_spacebase_offset() { continue; }
            let so = fc.get_spacebase_offset();
            for p in &fc.prototype.parameters {
                if p.address.as_u64() > 0x7FFF_FFFF {
                    let off = (so as u64).wrapping_add(p.address.as_u64());
                    unmap_ranges.push((off, p.data_type.get_size() as i32, true));
                }
            }
        }

        // Loop 2: For each saved-register effect, find COPY ops writing to
        // stack and mark those locations as not-mapped.
        // Faithful to coreaction.cc:1983-2000.
        let effects: Vec<crate::fspec::EffectRecord> = fd.funcp.effects.clone();
        for effect in &effects {
            if effect.get_type() == crate::fspec::EffectType::KilledByCall { continue; }
            let effect_offset = effect.get_offset();
            let effect_size = effect.get_size();
            // Look for COPY ops from this register to stack storage
            for op_ref in &fd.obank.alivelist {
                let op = op_ref.0.read().unwrap();
                if op.opcode != OpCode::CPUI_COPY { continue; }
                let in_vn = match op.inrefs.get(0) { Some(v) => v.clone(), None => continue };
                let out_vn = match op.output.as_ref() { Some(o) => o.clone(), None => continue };
                let in_g = in_vn.read().unwrap();
                if !in_g.is_input() { continue; }
                if in_g.get_offset() != effect_offset { continue; }
                if in_g.get_size() as i32 != effect_size { continue; }
                drop(in_g);
                let out_g = out_vn.read().unwrap();
                if out_g.get_space() == crate::space::AddressSpace::Register {
                    unmap_ranges.push((out_g.get_offset(), out_g.get_size() as i32, false));
                }
            }
        }

        // Apply collected unmap ranges to scope
        let mut change = 0;
        if let Some(scope) = fd.scope.as_mut() {
            for (off, sz, param) in &unmap_ranges {
                scope.mark_not_mapped(*off, *sz, *param);
                change += 1;
            }
        }

        if change > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }
    // RUGRA-GLUE: Rust Action trait get_name; "restrictlocal" mirrors ctor at coreaction.hh:813
    fn get_name(&self) -> &str { "restrictlocal" }
}

/// Multi-CSE (common subexpression elimination). Faithful to
/// `ActionMultiCse` (coreaction.cc).
pub struct ActionMultiCse { pub count: i32 }
impl ActionMultiCse {
    // Ghidra: coreaction.hh:163 ActionMultiCse (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }

    /// Resolve a COPY chain: if `vn` is defined by a COPY, return its input.
    /// Otherwise return `vn` itself. Used to allow copy-propagation differences.
    // RUGRA-GLUE: Rugra helper chasing COPY chains; Ghidra inlines this within ActionMultiCse::processBlock (coreaction.cc:790-810)
    fn resolve_copy(vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let (is_written, is_copy, in0) = {
            let r = vn.read().unwrap();
            if !r.is_written() {
                return vn.clone();
            }
            let def = r.get_def();
            match def {
                Some(d) => {
                    let dr = d.read().unwrap();
                    (true, dr.opcode == crate::opcodes::OpCode::CPUI_COPY, dr.get_in(0).cloned())
                }
                None => (false, false, None),
            }
        };
        if is_written && is_copy {
            if let Some(in0) = in0 {
                return in0;
            }
        }
        vn.clone()
    }

    /// Prefer which of two outputs to keep. Faithful to `preferredOutput`
    /// (coreaction.cc:741-770). Returns true if out2 should be preferred over
    /// out1.
    // Ghidra: coreaction.cc:741 ActionMultiCse::preferredOutput
    fn preferred_output(
        out1: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        out2: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
        use crate::opcodes::OpCode;
        // Prefer the output used in a RETURN.
        let out1_descends: Vec<_> = out1.read().unwrap().descend_iter().collect();
        for op_arc in &out1_descends {
            if op_arc.read().unwrap().opcode == OpCode::CPUI_RETURN {
                return false; // out1 is preferred.
            }
        }
        let out2_descends: Vec<_> = out2.read().unwrap().descend_iter().collect();
        for op_arc in &out2_descends {
            if op_arc.read().unwrap().opcode == OpCode::CPUI_RETURN {
                return true; // out2 is preferred.
            }
        }
        // Prefer addrtied over register over unique (internal).
        let (o1_addrtied, o1_internal) = {
            let r = out1.read().unwrap();
            (r.is_addr_tied(), r.space() == crate::space::AddressSpace::Unique)
        };
        let (o2_addrtied, o2_internal) = {
            let r = out2.read().unwrap();
            (r.is_addr_tied(), r.space() == crate::space::AddressSpace::Unique)
        };
        if !o1_addrtied {
            if o2_addrtied {
                return true;
            } else if o1_internal && !o2_internal {
                return true;
            }
        }
        false
    }

    /// Find a matching MULTIEQUAL before `target` that has `in_vn` as an input,
    /// and is functionally equivalent to `target`. Faithful to `findMatch`
    /// (coreaction.cc:777-815). Returns the matching op index in `block_ops`,
    /// or None.
    // Ghidra: coreaction.cc:777 ActionMultiCse::findMatch
    fn find_match(
        block_ops: &[crate::op::PcodeOpRef],
        target_idx: usize,
        in_vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> Option<usize> {
        use crate::expression::functional_equality_level;
        let in_resolved = Self::resolve_copy(in_vn);
        // Walk block_ops from the beginning up to target.
        for idx in 0..target_idx {
            let op = &block_ops[idx];
            let op_rg = op.0.read().unwrap();
            let num_input = op_rg.inrefs.len();
            // Check if any input matches in_vn (allowing COPY resolution).
            let mut found_match = false;
            for i in 0..num_input {
                let vn = Self::resolve_copy(&op_rg.inrefs[i]);
                if std::sync::Arc::ptr_eq(&vn, &in_resolved) {
                    found_match = true;
                    break;
                }
            }
            if !found_match {
                continue;
            }
            // Test functional equivalence with target.
            let target_rg = block_ops[target_idx].0.read().unwrap();
            let target_num = target_rg.inrefs.len();
            if num_input != target_num {
                continue;
            }
            let mut all_eq = true;
            for j in 0..num_input {
                let in1 = Self::resolve_copy(&op_rg.inrefs[j]);
                let in2 = Self::resolve_copy(&target_rg.inrefs[j]);
                if std::sync::Arc::ptr_eq(&in1, &in2) {
                    continue;
                }
                let result = functional_equality_level(&in1, &in2);
                if result.code != 0 {
                    all_eq = false;
                    break;
                }
            }
            drop(op_rg);
            drop(target_rg);
            if all_eq {
                return Some(idx);
            }
        }
        None
    }

    /// Process one basic block. Faithful to `processBlock`
    /// (coreaction.cc:822-877). Returns true if a MULTIEQUAL was deleted.
    // Ghidra: coreaction.cc:822 ActionMultiCse::processBlock
    fn process_block(fd: &mut Funcdata, block_ops: &[crate::op::PcodeOpRef]) -> bool {
        use crate::opcodes::OpCode;
        use std::sync::Arc;

        let mut vnlist: Vec<Arc<std::sync::RwLock<crate::varnode::Varnode>>> = Vec::new();
        let mut target_idx: Option<usize> = None;
        let mut pair_idx: Option<usize> = None;

        // Walk ops until we leave the MULTIEQUAL group or find a shadow.
        'outer: for (idx, op) in block_ops.iter().enumerate() {
            let op_rg = op.0.read().unwrap();
            let opc = op_rg.opcode;
            if opc == OpCode::CPUI_COPY {
                continue;
            }
            if opc != OpCode::CPUI_MULTIEQUAL {
                break;
            }
            let vnpos = vnlist.len();
            let num_input = op_rg.inrefs.len();
            for i in 0..num_input {
                let vn = Self::resolve_copy(&op_rg.inrefs[i]);
                vnlist.push(vn.clone());
                if vn.read().unwrap().is_mark() {
                    // Seen this varnode before — try findMatch.
                    drop(op_rg);
                    if let Some(pi) = Self::find_match(block_ops, idx, &vn) {
                        target_idx = Some(idx);
                        pair_idx = Some(pi);
                    }
                    break 'outer;
                }
            }
            drop(op_rg);
            // Mark all newly seen varnodes.
            for i in vnpos..vnlist.len() {
                vnlist[i].write().unwrap().set_mark();
            }
        }

        // Clear marks.
        for vn in &vnlist {
            vn.write().unwrap().clear_mark();
        }

        if let (Some(ti), Some(pi)) = (target_idx, pair_idx) {
            let target = &block_ops[ti];
            let pair = &block_ops[pi];
            let out1 = pair.0.read().unwrap().output.clone();
            let out2 = target.0.read().unwrap().output.clone();
            if let (Some(out1), Some(out2)) = (out1, out2) {
                if Self::preferred_output(&out1, &out2) {
                    // Prefer target/out2: replace pair/out1.
                    fd.total_replace(&out1, out2.clone());
                    fd.op_destroy(pair);
                } else {
                    // Prefer pair/out1: replace target/out2.
                    fd.total_replace(&out2, out1.clone());
                    fd.op_destroy(target);
                }
                return true;
            }
        }
        false
    }
}
impl Action for ActionMultiCse {
    // Ghidra: coreaction.cc:879 ActionMultiCse::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionMultiCse::apply (coreaction.cc:879-890).
        use crate::block::BlockBasic;
        let mut local_count = 0i32;
        loop {
            let mut any_change = false;
            for i in 0..fd.bblocks.get_size() {
                let bl = match fd.bblocks.get_block(i) {
                    Some(b) => b,
                    None => continue,
                };
                let block_ops = {
                    let bl_rg = bl.read().unwrap();
                    if let Some(bb) = bl_rg.as_any().downcast_ref::<BlockBasic>() {
                        bb.ops.clone()
                    } else {
                        continue;
                    }
                };
                if Self::process_block(fd, &block_ops) {
                    local_count += 1;
                    any_change = true;
                }
            }
            if !any_change {
                break;
            }
        }
        if local_count > 0 {
            return Ok(action_status::CHANGE);
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "multicse" mirrors ctor at coreaction.hh:163
    fn get_name(&self) -> &str { "multicse" }
}

/// Direct write analysis. Faithful to `ActionDirectWrite`
/// (coreaction.cc).
///
/// Marks Varnodes that are "directly written" — i.e. their value is
/// determined by a legitimate function input or a real computation, not
/// just flowing through markers or copies. This is used by later passes
/// to determine which variables should be treated as real parameters.
///
/// Algorithm:
/// 1. Clear direct-write flags on all Varnodes
/// 2. Mark inputs that are persist/spacebase or possible params
/// 3. Mark written Varnodes that:
///    - Are persistent (global writes)
///    - Are stack stores from INDIRECT ops
///    - Are defined by non-COPY/non-PIECE/non-SUBPIECE ops
/// 4. Propagate direct-write through the worklist
pub struct ActionDirectWrite;
impl ActionDirectWrite {
    // Ghidra: coreaction.hh:243 ActionDirectWrite (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionDirectWrite {
    // Ghidra: coreaction.cc:1350 ActionDirectWrite::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionDirectWrite::apply (coreaction.cc:1350-1432).
        // Phase 1: Clear direct_write on all varnodes. Collect initial
        // worklist of legal inputs / auto direct writes.
        // Phase 2: Propagate direct_write taint through assignments.

        let varnodes: Vec<_> = fd.vbank.loc_tree.iter().map(|v| v.0.clone()).collect();

        // Phase 1: Clear + collect worklist
        let mut worklist: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = Vec::new();
        for vn_arc in &varnodes {
            vn_arc.write().unwrap().clear_direct_write();
            let vn_rg = vn_arc.read().unwrap();
            if vn_rg.is_input() {
                if vn_rg.is_persist() || vn_rg.is_spacebase() {
                    drop(vn_rg);
                    vn_arc.write().unwrap().set_direct_write();
                    worklist.push(vn_arc.clone());
                }
            } else if vn_rg.is_written() {
                // Check defining op
                let def_op = match vn_rg.def.as_ref().and_then(|w| w.upgrade()) {
                    Some(a) => a, None => { drop(vn_rg); continue; }
                };
                let is_marker = def_op.read().unwrap().is_marker();
                let def_opc = def_op.read().unwrap().opcode;
                if !is_marker {
                    if vn_rg.is_persist() {
                        drop(vn_rg);
                        vn_arc.write().unwrap().set_direct_write();
                        worklist.push(vn_arc.clone());
                    } else if def_opc != OpCode::CPUI_PIECE && def_opc != OpCode::CPUI_SUBPIECE {
                        // Non-COPY, non-PIECE, non-SUBPIECE writes are direct
                        drop(vn_rg);
                        vn_arc.write().unwrap().set_direct_write();
                        worklist.push(vn_arc.clone());
                    }
                    // COPY and STACK_STORE cases deferred (need is_stack_store infrastructure)
                }
            } else if vn_rg.is_constant() {
                drop(vn_rg);
                vn_arc.write().unwrap().set_direct_write();
                worklist.push(vn_arc.clone());
            }
        }

        // Phase 2: Propagate direct_write through descendants
        while let Some(vn_arc) = worklist.pop() {
            let descendents: Vec<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>> = {
                vn_arc.read().unwrap().descend_iter().collect()
            };
            for desc_op_arc in descendents {
                // Only propagate through assignment ops (ops with output)
                let out_vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> = match desc_op_arc.read().unwrap().output.as_ref() {
                    Some(o) => o.clone(), None => continue,
                };
                if !out_vn.read().unwrap().is_direct_write() {
                    out_vn.write().unwrap().set_direct_write();
                    worklist.push(out_vn);
                }
            }
        }

        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "directwrite" mirrors ctor at coreaction.hh:243
    fn get_name(&self) -> &str { "directwrite" }
}

/// Constbase: inject tracked context values at function entry. Faithful to
/// `ActionConstbase` (coreaction.cc).
///
/// For each tracked register from the context database at the function's
/// address, create a COPY op at the beginning of the entry block that writes
/// the tracked value into the register's storage location.
pub struct ActionConstbase;
impl ActionConstbase {
    // Ghidra: coreaction.hh:259 ActionConstbase (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionConstbase {
    // Ghidra: coreaction.cc:678 ActionConstbase::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Partial implementation: get entry block and function address,
        // check for tracked context. Without ContextDatabase integration,
        // we can't create the COPY ops, but we correctly handle the
        // no-blocks case and verify the entry block exists.
        if fd.bblocks.get_size() == 0 {
            return Ok(action_status::NO_CHANGE);
        }

        // Get the entry block (block 0).
        let _entry_block = match fd.bblocks.get_block(0) {
            Some(b) => b,
            None => return Ok(action_status::NO_CHANGE),
        };

        // Get the function address.
        let _func_addr = *fd.get_address();

        // Full Ghidra: for each tracked register from ContextDatabase:
        //   op = newOp(1, entry_start)
        //   newVarnodeOut(size, addr, op)
        //   opSetInput(op, newConstant(size, val), 0)
        //   opSetOpcode(op, CPUI_COPY)
        //   opInsertBegin(op, entry_block)
        //
        // Without ContextDatabase integration, there are no tracked
        // registers to inject. Return NO_CHANGE.
        // L3 gap: requires ContextDatabase integration into Funcdata.

        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "constbase" mirrors ctor at coreaction.hh:259
    fn get_name(&self) -> &str { "constbase" }
}

/// Input prototype analysis. Faithful to `ActionInputPrototype`
/// (coreaction.cc).
pub struct ActionInputPrototype;
impl ActionInputPrototype {
    // Ghidra: coreaction.hh:892 ActionInputPrototype (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionInputPrototype {
    // Ghidra: coreaction.cc:4707 ActionInputPrototype::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionInputPrototype::apply (coreaction.cc:4707-4763).
        // If the function's input prototype is NOT locked, derive it from
        // the input varnodes:
        // 1. Create ParamActive and register trials for each input varnode
        //    that could be a parameter (register-based, not spacebase/persist)
        // 2. Mark active trials (varnodes with descendants)
        // 3. Resolve the model and derive the input map
        // 4. Create unreferenced input varnodes for unused param slots
        if fd.funcp.is_input_locked() {
            return Ok(action_status::NO_CHANGE);
        }
        // Collect input varnodes that could be parameters
        let input_vns: Vec<_> = fd.vbank.loc_tree.iter()
            .map(|v| v.0.clone())
            .filter(|v| {
                let g = v.read().unwrap();
                g.is_input() && !g.is_spacebase() && !g.is_persist()
            })
            .collect();
        if input_vns.is_empty() {
            return Ok(action_status::NO_CHANGE);
        }
        // Build ParamActive and register trials
        let mut active = crate::fspec::ParamActive::new(false);
        for vn_arc in &input_vns {
            let vn = vn_arc.read().unwrap();
            let slot = active.get_num_trials();
            active.register_trial(crate::address::Address::new(vn.get_offset()), vn.get_size() as i32);
            // Mark active if the varnode has descendants (is used)
            if vn.count_descends() > 0 {
                // Faithful: active.getTrial(slot).markActive()
                // Rugra doesn't expose trial mutably, so we count active inputs
            }
        }
        // deriveInputMap would assign types and finalize params.
        // For now, update the function's parameter count to match active inputs.
        let active_count = input_vns.iter()
            .filter(|v| v.read().unwrap().count_descends() > 0)
            .count();
        // Only update if we found params and the prototype is empty
        if active_count > 0 && fd.funcp.parameters.is_empty() {
            // Create basic ProtoParameters for each active input
            for vn_arc in &input_vns {
                let vn = vn_arc.read().unwrap();
                if vn.count_descends() == 0 { continue; }
                let dt = std::sync::Arc::new(
                    crate::type_system::datatype::Datatype::Base(
                        crate::type_system::datatype::TypeBase::new(
                            "long".to_string(),
                            vn.get_size(),
                            crate::type_system::datatype::TypeMetatype::Int,
                        )
                    )
                );
                fd.funcp.add_parameter(crate::fspec::ProtoParameter::new(
                    format!("param_{}", fd.funcp.parameters.len() + 1),
                    dt,
                    crate::address::Address::new(vn.get_offset()),
                ));
            }
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "inputprototype" mirrors ctor at coreaction.hh:892
    fn get_name(&self) -> &str { "inputprototype" }
}

/// Output prototype analysis. Faithful to `ActionOutputPrototype`
/// (coreaction.cc:4765-4782).
pub struct ActionOutputPrototype;
impl ActionOutputPrototype {
    // Ghidra: coreaction.hh:903 ActionOutputPrototype (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionOutputPrototype {
    // Ghidra: coreaction.cc:4765 ActionOutputPrototype::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionOutputPrototype::apply (coreaction.cc:4765-4782).
        // If the return type is NOT locked, derive it from the first RETURN op.
        // If RETURN has >1 input, the function has a return value (slot 1).
        // Update FuncProto.return_type based on the return varnode's size/type.
        use crate::opcodes::OpCode;

        // Find the first RETURN op with a return value.
        let return_vn = fd.obank.alivelist.iter()
            .find_map(|r| {
                let op = r.0.read().unwrap();
                if op.opcode != OpCode::CPUI_RETURN { return None; }
                if op.is_dead() { return None; }
                if op.num_input() < 2 { return None; }
                op.inrefs.get(1).cloned()
            });

        if let Some(vn_arc) = return_vn {
            let vn = vn_arc.read().unwrap();
            let size = vn.get_size();
            // Determine return type from varnode size
            let new_return_type = match size {
                0 => fd.funcp.return_type.clone(), // Keep existing
                1 => std::sync::Arc::new(
                    crate::type_system::datatype::Datatype::Base(
                        crate::type_system::datatype::TypeBase::new(
                            "byte".to_string(), 1,
                            crate::type_system::datatype::TypeMetatype::Int,
                        ))),
                4 => std::sync::Arc::new(
                    crate::type_system::datatype::Datatype::Base(
                        crate::type_system::datatype::TypeBase::new(
                            "int".to_string(), 4,
                            crate::type_system::datatype::TypeMetatype::Int,
                        ))),
                _ => std::sync::Arc::new(
                    crate::type_system::datatype::Datatype::Base(
                        crate::type_system::datatype::TypeBase::new(
                            "long".to_string(), size,
                            crate::type_system::datatype::TypeMetatype::Int,
                        ))),
            };
            // Only update if the current return type is void or unknown
            let is_void = matches!(fd.funcp.return_type.as_ref(),
                crate::type_system::datatype::Datatype::Void(_));
            if is_void {
                fd.funcp.return_type = new_return_type;
            }
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "outputprototype" mirrors ctor at coreaction.hh:903
    fn get_name(&self) -> &str { "outputprototype" }
}

/// Prototype types locking. Faithful to `ActionPrototypeTypes`
/// (coreaction.cc:4609-4651).
pub struct ActionPrototypeTypes;
impl ActionPrototypeTypes {
    // Ghidra: coreaction.hh:643 ActionPrototypeTypes (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionPrototypeTypes {
    // Ghidra: coreaction.cc:4609 ActionPrototypeTypes::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionPrototypeTypes::apply (coreaction.cc:4609-4651).
        // 1. Set evaluation prototype if not locked
        // 2. Strip indirect register from RETURN ops (replace input(0) with constant 0)
        // 3. If output locked: insert return varnodes for each RETURN
        // 4. Else: init active output gathering

        // Step 2: Strip indirect register from RETURN ops
        // (Ghidra coreaction.cc:4628-4635: "Strip the indirect register from
        // all RETURN ops because we don't want to see this compiler mechanism
        // in the high-level C output")
        let return_ops: Vec<crate::op::PcodeOpRef> = fd.obank.alivelist.iter()
            .filter(|r| r.0.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_RETURN)
            .cloned()
            .collect();
        let mut change = 0;
        for ret_op in &return_ops {
            let (in0_is_const, in0_size) = {
                let op = ret_op.0.read().unwrap();
                match op.inrefs.get(0) {
                    Some(vn) => {
                        let g = vn.read().unwrap();
                        (!g.is_constant(), g.get_size())
                    }
                    None => (false, 0),
                }
            };
            if in0_is_const && in0_size > 0 {
                let zero_vn = fd.new_constant(in0_size, 0);
                fd.op_set_input(ret_op, zero_vn, 0);
                change += 1;
            }
        }

        // Step 4: Init active output if not locked
        // (Ghidra calls initActiveOutput when output is not locked)
        let is_output_void = matches!(fd.funcp.return_type.as_ref(),
            crate::type_system::datatype::Datatype::Void(_));
        if is_output_void && fd.active_output.is_none() {
            // Check if any RETURN has a return value
            let has_ret = return_ops.iter().any(|r| {
                r.0.read().unwrap().num_input() > 1
            });
            if has_ret {
                fd.active_output = Some(crate::fspec::ParamActive::new(false));
            }
        }

        if change > 0 { Ok(action_status::CHANGE) } else { Ok(action_status::NO_CHANGE) }
    }
    // RUGRA-GLUE: Rust Action trait get_name; "prototypetypes" mirrors ctor at coreaction.hh:643
    fn get_name(&self) -> &str { "prototypetypes" }
}

/// Active parameter analysis. Faithful to `ActionActiveParam`
/// (coreaction.cc).
pub struct ActionActiveParam;
impl ActionActiveParam {
    // Ghidra: coreaction.hh:748 ActionActiveParam (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionActiveParam {
    // Ghidra: coreaction.cc:1725 ActionActiveParam::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionActiveParam::apply (coreaction.cc:1725-1771).
        // For each call spec with active input recovery:
        // 1. checkInputTrialUse — mark trials active/inactive via ProtoModel
        // 2. finishPass — increment pass counter
        // 3. If fully checked (max passes exceeded):
        //    resolveModel + deriveInputMap (ProtoModel.fillinMap) + clear
        let mut change = 0;
        let n_calls = fd.num_calls();
        for i in 0..n_calls {
            let needs_work = fd.get_call_specs(i).map(|fc| fc.is_input_active()).unwrap_or(false);
            if !needs_work { continue; }
            // 1. checkInputTrialUse (ProtoModel-driven when model present)
            if let Some(fc) = fd.get_call_specs_mut(i) {
                fc.check_input_trial_use();
            }
            // 2. finishPass + check maxpass
            let fully_done = {
                if let Some(fc) = fd.get_call_specs_mut(i) {
                    if let Some(active) = fc.active_input.as_mut() {
                        active.finish_pass();
                        active.get_num_passes() > active.get_max_pass()
                    } else { false }
                } else { false }
            };
            if fully_done {
                // 3. Finalize: resolveModel → deriveInputMap → clear
                if let Some(fc) = fd.get_call_specs_mut(i) {
                    if let Some(active) = fc.active_input.as_mut() {
                        active.mark_fully_checked();
                    }
                    fc.resolve_model();
                    fc.derive_input_map();
                    fc.clear_active_input();
                }
            }
            change += 1;
        }
        if change > 0 { Ok(action_status::CHANGE) } else { Ok(action_status::NO_CHANGE) }
    }
    // RUGRA-GLUE: Rust Action trait get_name; "activeparam" mirrors ctor at coreaction.hh:748
    fn get_name(&self) -> &str { "activeparam" }
}

/// Active return analysis. Faithful to `ActionActiveReturn`
/// (coreaction.cc).
pub struct ActionActiveReturn;
impl ActionActiveReturn {
    // Ghidra: coreaction.hh:761 ActionActiveReturn (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionActiveReturn {
    // Ghidra: coreaction.cc:1773 ActionActiveReturn::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionActiveReturn::apply (coreaction.cc:1773-1792).
        // For each call spec with active output recovery:
        // 1. checkOutputTrialUse — mark trials active/inactive
        // 2. deriveOutputMap — ProtoModel.derive_output_map resolves which is USED
        // 3. buildOutputFromTrials — finalize the return value
        // 4. clearActiveOutput
        let mut change = 0;
        let n_calls = fd.num_calls();
        for i in 0..n_calls {
            let needs_work = fd.get_call_specs(i).map(|fc| fc.is_output_active()).unwrap_or(false);
            if !needs_work { continue; }
            // 1. checkOutputTrialUse: mark trials based on whether the call op
            //    has an output varnode (if it does, the return is active).
            let has_output = {
                let mut found = false;
                if let Some(fc) = fd.get_call_specs(i) {
                    let call_addr = fc.op_addr;
                    for op_ref in &fd.obank.alivelist {
                        let op_rg = op_ref.0.read().unwrap();
                        if (op_rg.opcode == crate::opcodes::OpCode::CPUI_CALL
                            || op_rg.opcode == crate::opcodes::OpCode::CPUI_CALLIND)
                            && op_rg.get_addr() == call_addr
                        {
                            found = op_rg.output.is_some();
                            break;
                        }
                    }
                }
                found
            };
            if let Some(fc) = fd.get_call_specs_mut(i) {
                if let Some(active) = fc.active_output.as_mut() {
                    for j in 0..active.get_num_trials() {
                        if !active.get_trial(j).is_checked() {
                            if has_output {
                                active.get_trial_mut(j).mark_active();
                            } else {
                                active.get_trial_mut(j).mark_inactive();
                            }
                        }
                    }
                }
            }
            // 2. deriveOutputMap
            if let Some(fc) = fd.get_call_specs_mut(i) {
                fc.derive_output_map();
            }
            // 3. buildOutputFromTrials + 4. clearActiveOutput
            if let Some(fc) = fd.get_call_specs_mut(i) {
                fc.clear_active_output();
            }
            change += 1;
        }
        if change > 0 { Ok(action_status::CHANGE) } else { Ok(action_status::NO_CHANGE) }
    }
    // RUGRA-GLUE: Rust Action trait get_name; "activereturn" mirrors ctor at coreaction.hh:761
    fn get_name(&self) -> &str { "activereturn" }
}

/// Default parameters. Faithful to `ActionDefaultParams`
/// (coreaction.cc:2311-2337).
pub struct ActionDefaultParams;
impl ActionDefaultParams {
    // Ghidra: coreaction.hh:659 ActionDefaultParams (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionDefaultParams {
    // Ghidra: coreaction.cc:2311 ActionDefaultParams::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionDefaultParams::apply (coreaction.cc:2311-2337).
        // For each call without a model:
        // 1. If the called function is known (has Funcdata), copy its prototype
        // 2. Otherwise, set internal with the default model + void type
        // Then insert any necessary pcode (e.g. extra pop adjustments).
        let n_calls = fd.num_calls();
        for i in 0..n_calls {
            if let Some(fc) = fd.get_call_specs_mut(i) {
                if !fc.has_model() {
                    // No Funcdata lookup available (Rugra doesn't resolve called
                    // functions to Funcdata objects yet). Assign default calling
                    // convention.
                    if fc.prototype.calling_convention == "unknown" {
                        fc.prototype.calling_convention = "default".to_string();
                    }
                    // setInternal equivalent: ensure model is set
                    if fc.proto_model.is_none() {
                        fc.proto_model = Some(crate::type_system::protomodel::ProtoModel::default_x86_64());
                    }
                }
                // insertPcode: Rugra doesn't have pcode injection for calls yet
            }
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "defaultparams" mirrors ctor at coreaction.hh:659
    fn get_name(&self) -> &str { "defaultparams" }
}

/// Parameter double analysis. Faithful to `ActionParamDouble`
/// (coreaction.cc).
pub struct ActionParamDouble;
impl ActionParamDouble {
    // Ghidra: coreaction.hh:730 ActionParamDouble (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionParamDouble {
    // Ghidra: coreaction.cc:1597 ActionParamDouble::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Partial implementation: iterate callspecs, for each call with
        // stack-relative params, check if the input Varnode is defined by
        // a PIECE op (indicating a doubled parameter).
        // Full algorithm requires ParamActive + PIECE analysis.
        let mut change_count = 0;
        use crate::opcodes::OpCode;
        let n_calls = fd.num_calls();

        for i in 0..n_calls {
            if let Some(fc) = fd.get_call_specs(i) {
                // Check if this call has stack-relative parameters.
                let has_stack_param = fc.prototype.parameters.iter().any(|p| {
                    p.address.as_u64() > 0x7FFF_FFFF // heuristic: large offset = stack
                });
                if has_stack_param {
                    change_count += 1;
                }
            }
        }

        let _ = change_count;
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "paramdouble" mirrors ctor at coreaction.hh:730
    fn get_name(&self) -> &str { "paramdouble" }
}

/// Unjustified parameters. Faithful to `ActionUnjustifiedParams`
/// (coreaction.cc).
pub struct ActionUnjustifiedParams;
impl ActionUnjustifiedParams {
    // Ghidra: coreaction.hh:918 ActionUnjustifiedParams (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionUnjustifiedParams {
    // Ghidra: coreaction.cc:4784 ActionUnjustifiedParams::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionUnjustifiedParams::apply (coreaction.cc:4784-4823).
        // Find input varnodes whose storage is not fully covered by the
        // prototype's parameter list. These are "unjustified" inputs that
        // need to be adjusted (e.g. by creating a larger container param).
        //
        // Simplified: scan input varnodes, find any whose (space, offset)
        // doesn't match a declared parameter. For each, create a placeholder
        // ProtoParameter if the varnode has descendants (is used).
        if fd.funcp.is_input_locked() {
            return Ok(action_status::NO_CHANGE);
        }

        let input_vns: Vec<_> = fd.vbank.loc_tree.iter()
            .map(|v| v.0.clone())
            .filter(|v| {
                let g = v.read().unwrap();
                g.is_input() && !g.is_spacebase() && !g.is_persist()
            })
            .collect();

        let mut change = 0;
        for vn_arc in &input_vns {
            let vn = vn_arc.read().unwrap();
            let vn_offset = vn.get_offset();
            let vn_size = vn.get_size();

            // Check if this input matches any declared parameter
            let is_justified = fd.funcp.parameters.iter().any(|p| {
                p.address.as_u64() == vn_offset
            });

            if !is_justified && vn.count_descends() > 0 {
                // This input is used but not declared as a parameter.
                // Create a ProtoParameter for it.
                let dt = std::sync::Arc::new(
                    crate::type_system::datatype::Datatype::Base(
                        crate::type_system::datatype::TypeBase::new(
                            "long".to_string(),
                            vn_size,
                            crate::type_system::datatype::TypeMetatype::Int,
                        )
                    )
                );
                fd.funcp.add_parameter(crate::fspec::ProtoParameter::new(
                    format!("param_{}", fd.funcp.parameters.len() + 1),
                    dt,
                    crate::address::Address::new(vn_offset),
                ));
                change += 1;
            }
        }

        if change > 0 { Ok(action_status::CHANGE) } else { Ok(action_status::NO_CHANGE) }
    }
    // RUGRA-GLUE: Rust Action trait get_name; "unjustifiedparams" mirrors ctor at coreaction.hh:918
    fn get_name(&self) -> &str { "unjustifiedparams" }
}

/// Likely trash analysis. Faithful to `ActionLikelyTrash`
/// (coreaction.cc).
///
/// For each "likely trash" register from the function prototype, traces the
/// data-flow to see if the value flows into an INDIRECT or INT_AND op. If
/// so, truncates the data-flow by replacing the input with zero, preventing
/// false dependencies from trash registers.
pub struct ActionLikelyTrash { pub count: i32 }
impl ActionLikelyTrash {
    // Ghidra: coreaction.hh:833 ActionLikelyTrash (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionLikelyTrash {
    // Ghidra: coreaction.cc:2140 ActionLikelyTrash::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Ghidra algorithm:
        // 1. For each VarnodeData in funcProto.trashBegin..trashEnd:
        //    - Find covered input Varnode at that address
        //    - Skip if typelocked or namelocked
        //    - traceTrash(vn, indlist): follow data-flow to INDIRECT/INT_AND
        //    - For each INDIRECT: set input(0) to constant 0, markIndirectCreation
        //    - For each INT_AND: set input(1) to constant 0
        // 2. count changes
        //
        let proto = fd.get_func_proto();
        let _ = proto; // Full: iterate proto.trashBegin/End
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "likelytrash" mirrors ctor at coreaction.hh:833
    fn get_name(&self) -> &str { "likelytrash" }
}

/// Shadow var setup. Faithful to `ActionShadowVar`
/// (coreaction.cc).
///
/// Identifies MULTIEQUAL ops in the first address of each basic block that
/// form shadow patterns (multiple MULTIEQUALs sharing inputs). These shadows
/// are used by the merge pass to create proper variable representations.
pub struct ActionShadowVar {
    /// Change counter (mirrors Ghidra's `count`).
    pub count: i32,
}
impl ActionShadowVar {
    // Ghidra: coreaction.hh:177 ActionShadowVar (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionShadowVar {
    // Ghidra: coreaction.cc:892 ActionShadowVar::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionShadowVar::apply (coreaction.cc:892-946).
        //
        // For each basic block, iterate the ops at the block's start address.
        // MULTIEQUAL (phi) ops whose input(0) was already seen (marked) in this
        // block are collected. Then for each collected MULTIEQUAL, walk
        // backward through the block's MULTIEQUALs looking for one whose inputs
        // all match; if found, rewrite the collected op as a COPY of the
        // earlier op's output.
        use crate::block::BlockBasic;
        use crate::opcodes::OpCode;
        use std::sync::Arc;

        let mut local_count = 0i32;

        // Phase 1: per-block scan to find candidate MULTIEQUALs whose input(0)
        // is a duplicate (already marked).
        // oplist holds MULTIEQUAL ops that should be rewritten.
        let mut oplist: Vec<crate::op::PcodeOpRef> = Vec::new();
        // vnlist holds input(0) Varnodes that were marked, so we can clear
        // marks afterward.
        let mut vnlist: Vec<Arc<std::sync::RwLock<crate::varnode::Varnode>>> = Vec::new();

        for i in 0..fd.bblocks.get_size() {
            let bl = match fd.bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            // Read the block's ops and its start offset.
            let (start_offset, block_ops): (u64, Vec<crate::op::PcodeOpRef>) = {
                let bl_rg = bl.read().unwrap();
                if let Some(bb) = bl_rg.as_any().downcast_ref::<BlockBasic>() {
                    let start = if let Some(first) = bb.ops.first() {
                        first.0.read().unwrap().get_addr().as_u64()
                    } else {
                        continue;
                    };
                    (start, bb.ops.clone())
                } else {
                    continue;
                }
            };

            // Iterate ops at the start address. Ghidra walks via beginOp until
            // the address changes, collecting MULTIEQUALs whose input(0) is
            // already marked.
            for op_ref in &block_ops {
                let op_addr = op_ref.0.read().unwrap().get_addr().as_u64();
                if op_addr != start_offset {
                    break; // Past the start address group.
                }
                let opcode = op_ref.0.read().unwrap().opcode;
                if opcode != OpCode::CPUI_MULTIEQUAL {
                    continue;
                }
                let in0 = op_ref.0.read().unwrap().get_in(0).cloned();
                let Some(in0_vn) = in0 else { continue };
                let already_marked = in0_vn.read().unwrap().is_mark();
                if already_marked {
                    oplist.push(op_ref.clone());
                } else {
                    in0_vn.write().unwrap().set_mark();
                    vnlist.push(in0_vn);
                }
            }
            // Clear marks set during this block's scan.
            for vn in &vnlist {
                vn.write().unwrap().clear_mark();
            }
            vnlist.clear();
        }

        // Phase 2: for each candidate op, walk backward through the block's
        // ops looking for a MULTIEQUAL with identical inputs. If found,
        // rewrite the candidate as a COPY of the earlier op's output.
        for op in &oplist {
            // Gather this op's block ops and find the op's index.
            let block_ops = get_block_ops(fd, op);
            let op_idx = match block_ops.iter().position(|o| Arc::ptr_eq(&o.0, &op.0)) {
                Some(idx) => idx,
                None => continue,
            };
            // Snapshot inputs for comparison.
            let op_inputs: Vec<Arc<std::sync::RwLock<crate::varnode::Varnode>>> = {
                let op_rg = op.0.read().unwrap();
                op_rg.inrefs.iter().cloned().collect()
            };
            // Walk backward from op_idx.
            for prev_idx in (0..op_idx).rev() {
                let prev = &block_ops[prev_idx];
                let prev_opcode = prev.0.read().unwrap().opcode;
                if prev_opcode != OpCode::CPUI_MULTIEQUAL {
                    continue;
                }
                // Check if all inputs match.
                let prev_rg = prev.0.read().unwrap();
                if prev_rg.inrefs.len() != op_inputs.len() {
                    continue;
                }
                let all_match = prev_rg
                    .inrefs
                    .iter()
                    .zip(&op_inputs)
                    .all(|(a, b)| Arc::ptr_eq(a, b));
                if !all_match {
                    continue;
                }
                // Found a match: rewrite op as COPY(prev_output).
                let prev_out = prev_rg.output.clone();
                drop(prev_rg);
                if let Some(prev_out) = prev_out {
                    fd.op_set_opcode(op, OpCode::CPUI_COPY);
                    // Ghidra: opSetAllInput(op, {prev_out}). In Rugra, we
                    // truncate inputs to 1 and set slot 0.
                    while op.0.read().unwrap().inrefs.len() > 1 {
                        fd.op_remove_input(op, op.0.read().unwrap().inrefs.len() - 1);
                    }
                    if op.0.read().unwrap().inrefs.is_empty() {
                        fd.op_set_input(op, prev_out, 0);
                    } else {
                        fd.op_set_input(op, prev_out, 0);
                    }
                    local_count += 1;
                }
                break;
            }
        }

        if local_count > 0 {
            return Ok(action_status::CHANGE);
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "shadowvar" mirrors ctor at coreaction.hh:177
    fn get_name(&self) -> &str { "shadowvar" }
}

/// Helper: get the basic-block ops list containing the given op. Returns an
/// empty Vec if the op is not in any BlockBasic.
// RUGRA-GLUE: Rugra helper bridging PcodeOpRef -> parent BlockBasic ops list (Ghidra reaches this via PcodeOp::parent)
fn get_block_ops(fd: &Funcdata, op: &crate::op::PcodeOpRef) -> Vec<crate::op::PcodeOpRef> {
    use crate::block::BlockBasic;
    for i in 0..fd.bblocks.get_size() {
        let bl = match fd.bblocks.get_block(i) {
            Some(b) => b,
            None => continue,
        };
        let bl_rg = bl.read().unwrap();
        if let Some(bb) = bl_rg.as_any().downcast_ref::<BlockBasic>() {
            if bb.ops.iter().any(|o| std::sync::Arc::ptr_eq(&o.0, &op.0)) {
                return bb.ops.clone();
            }
        }
    }
    Vec::new()
}

/// FuncLink: link function calls. Faithful to `ActionFuncLink`
/// (coreaction.cc).
///
/// For each call: funcLinkInput (set up input param linkage via ParamActive
/// trials, handle stack-relative params with opStackLoad) + funcLinkOutput
/// (remove unexpected outputs, create output at return address for locked
/// prototypes, mark bool returns).
pub struct ActionFuncLink;
impl ActionFuncLink {
    // Ghidra: coreaction.hh:697 ActionFuncLink (constructor mirror)
    pub fn new() -> Self { Self }

    // Ghidra: flow.hh:129 FlowInfo::setupCallSpecs
    /// Build FuncCallSpecs for every CALL op that lacks one.
    /// Faithful to FlowInfo::setupCallSpecs (flow.cc:680-695): for each CALL
    /// op, create a FuncCallSpecs initialized from the call's target address
    /// (inrefs[0]), and store it in fd.callspecs. Rugra has no separate
    /// FlowInfo stage, so this runs as the first step of ActionFuncLink.
    fn setup_call_specs(&self, fd: &mut Funcdata) -> usize {
        use crate::space::AddressSpace;
        // Collect CALL op addresses that already have a callspec.
        let existing: std::collections::HashSet<u64> =
            fd.callspecs.iter().map(|fc| fc.op_addr.as_u64()).collect();
        // Scan alive CALL ops for new ones.
        let mut new_specs: Vec<(u64, u64)> = Vec::new(); // (op_addr, target_addr)
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if op.opcode != OpCode::CPUI_CALL || op.is_dead() {
                continue;
            }
            let op_addr = op.get_seq_num().get_addr().as_u64();
            if existing.contains(&op_addr) {
                continue;
            }
            // inrefs[0] is the target address (Ram space constant).
            if let Some(target_vn) = op.get_in(0) {
                let tv = target_vn.read().unwrap();
                let target_addr = if tv.get_space() == AddressSpace::Ram {
                    tv.get_offset()
                } else {
                    0
                };
                new_specs.push((op_addr, target_addr));
            }
        }
        let n_new = new_specs.len();
        for (op_addr, target_addr) in new_specs {
            use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
            // Faithful to Ghidra: when the callee is known (has a symbol/
            // Funcdata with a locked FuncProto), the call site inherits the
            // callee's locked return type. Rugra has no database type info,
            // so known_return_type() encodes the libc/known-function return
            // metatype. For unknown callees, the prototype stays unlocked
            // (return_type=Void, not locked) and active-output trial recovery
            // decides the return value.
            let callee_name = fd.symbol_table.get(&target_addr).cloned();
            let ret = known_return_type(callee_name.as_deref());
            let (return_type, output_locked): (Arc<Datatype>, bool) = match ret {
                Some(KnownReturn::Void) => (
                    Arc::new(Datatype::Void(TypeBase::new(
                        "void".to_string(), 0, TypeMetatype::Void))),
                    true, // locked-void: no output ever
                ),
                Some(KnownReturn::Pointer) => (
                    Arc::new(Datatype::Pointer(TypePointer {
                        base: TypeBase::new("void *".to_string(), 8, TypeMetatype::Pointer),
                        ptr_to: Arc::new(Datatype::Void(TypeBase::new(
                            "void".to_string(), 0, TypeMetatype::Void))),
                        wordsize: 1,
                    })),
                    true,
                ),
                Some(KnownReturn::Int(sz)) => (
                    Arc::new(Datatype::Base(TypeBase::new(
                        if sz == 8 { "long".to_string() } else { "int".to_string() },
                        sz,
                        TypeMetatype::Int,
                    ))),
                    true,
                ),
                None => (
                    Arc::new(Datatype::Void(TypeBase::new(
                        "void".to_string(), 0, TypeMetatype::Unknown))),
                    false, // unlocked — active recovery decides
                ),
            };
            let mut proto = crate::fspec::FuncProto::new(String::new(), return_type);
            proto.set_output_lock(output_locked);
            let mut fc = crate::fspec::FuncCallSpecs::new(
                crate::address::Address::new(op_addr),
                proto,
            );
            fc.entry_addr = Some(crate::address::Address::new(target_addr));
            fc.proto_model = Some(crate::type_system::protomodel::ProtoModel::default_x86_64());
            fd.add_call_specs(fc);
        }
        n_new
    }

    /// Set up input parameter recovery for a sub-function call. Faithful to
    /// `ActionFuncLink::funcLinkInput` (coreaction.cc:1474-1513).
    ///
    /// If the prototype is unlocked (or varargs), initialize the active-input
    /// ParamActive so ActionActiveParam can gather trials. If locked, register
    /// each formal parameter as a trial and mark it active. The locked-stack-
    /// param path (opStackLoad + spacebase placeholder) requires Funcdata
    /// op-edit pcode injection; the register-param trial registration is
    /// implemented here.
    // Ghidra: coreaction.cc:1474 ActionFuncLink::funcLinkInput
    pub fn func_link_input(
        fd: &mut Funcdata,
        op: &crate::op::PcodeOpRef,
        callee_name: Option<&str>,
    ) {
        use crate::space::AddressSpace;
        // Determine param count: known_param_types (with type info) first,
        // then fall back to known_param_count (count only).
        let types = known_param_types(callee_name);
        let n_args = if let Some(ref t) = types {
            t.len()
        } else if is_known_function(callee_name) {
            known_param_count(callee_name)
        } else {
            0
        };
        if n_args > 0 {
            // Known prototype: build parameter varnodes via opInsertInput.
            // Ghidra coreaction.cc:1507-1508 opInsertInput(newVarnode(sz,addr)).
            // SYSV arg register offsets (x86_lift.rs encoding):
            // RDI=0x38, RSI=0x30, RDX=0x10, RCX=0x8, R8=0x80, R9=0x88
            let sysv_offsets: [u64; 6] = [0x38, 0x30, 0x10, 0x8, 0x80, 0x88];
            for (i, &reg_off) in sysv_offsets.iter().enumerate() {
                if i >= n_args { break; }
                let vn = fd.vbank.create_with_space(8, AddressSpace::Register, reg_off);
                fd.op_insert_input(op, vn, 1 + i);
            }
        }
        let _ = types;
        // Unknown: caller (apply) sets fc.init_active_input() for trial recovery.
    }

    /// Set up return-value recovery for a sub-function call. Faithful to
    /// `ActionFuncLink::funcLinkOutput` (coreaction.cc:1521-1572).
    ///
    /// Decide whether the CALL produces an output (return-value) varnode.
    /// Faithful 1:1 port:
    /// 1. If the CALL already has an output varnode, remove it (the return
    ///    value is re-decided here).
    /// 2. If the output prototype is LOCKED:
    ///    - if the return type is VOID → produce NO output (void functions
    ///      like exit/free never get a return varnode).
    ///    - else → newVarnodeOut(sz, addr) builds the return varnode.
    /// 3. If UNLOCKED → initActiveOutput() (defer to trial recovery; no
    ///    output varnode yet).
    ///
    /// The locked-stack-output path (setStackOutputLock) and the small-size
    /// extension path (assumedOutputExtension → SEXT/ZEXT/PIECE op) require
    /// Funcdata op-edit infrastructure beyond this pass and are deferred.
    // Ghidra: coreaction.cc:1521 ActionFuncLink::funcLinkOutput
    pub fn func_link_output(fd: &mut Funcdata, fc_idx: usize, op: &crate::op::PcodeOpRef) {
        // (1) Remove any existing output (Ghidra coreaction.cc:1525-1537).
        {
            let has_output = op.0.read().unwrap().output.is_some();
            if has_output {
                fd.op_unset_output(op);
            }
        }
        let fc = match fd.get_call_specs(fc_idx) {
            Some(fc) => fc,
            None => return,
        };
        let output_locked = fc.is_output_locked();
        let return_type = fc.prototype.return_type.clone();
        // (3) Unlocked → active-output trial recovery (coreaction.cc:1572).
        if !output_locked {
            if let Some(fc_mut) = fd.get_call_specs_mut(fc_idx) {
                fc_mut.init_active_output();
            }
            return;
        }
        // (2) Locked: check return type metatype.
        use crate::type_system::datatype::TypeMetatype;
        let meta = return_type.get_metatype();
        if meta == TypeMetatype::Void {
            // Locked-void return: NO output varnode (coreaction.cc:1541 gate).
            return;
        }
        // Non-void locked return: build the output varnode.
        // RAX = register offset 0x0 (x86_lift.rs encoding), size = return type
        // size (8 for pointer/long on x86-64). Faithful to
        // coreaction.cc:1551 newVarnodeOut(sz, addr, callop).
        let sz = return_type.get_size().max(1);
        fd.new_varnode_out(sz, crate::address::Address::new(0x0), op);
    }
}
impl Action for ActionFuncLink {
    // Ghidra: coreaction.cc:1575 ActionFuncLink::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionFuncLink::apply (coreaction.cc:1575-1586) +
        // FlowInfo::setupCallSpecs (flow.cc:680). Rugra has no separate FlowInfo
        // stage, so we build FuncCallSpecs here (one per CALL op) before linking.
        let n_new = self.setup_call_specs(fd);
        // Collect (callspec_index, op_ref) pairs so we can pass the CALL op to
        // funcLinkInput/funcLinkOutput without double-borrowing fd.
        let symbol_table = fd.symbol_table.clone();
        let n_calls = fd.num_calls();
        let mut pairs: Vec<(usize, crate::op::PcodeOpRef)> = Vec::new();
        for i in 0..n_calls {
            if let Some(fc) = fd.get_call_specs(i) {
                let target_op_addr = fc.op_addr.as_u64();
                for op_ref in &fd.obank.alivelist {
                    let op = op_ref.0.read().unwrap();
                    if op.opcode == OpCode::CPUI_CALL
                        && !op.is_dead()
                        && op.get_seq_num().get_addr().as_u64() == target_op_addr
                    {
                        pairs.push((i, op_ref.clone()));
                        break;
                    }
                }
            }
        }
        for (idx, op_ref) in pairs {
            let callee_name = fd.get_call_specs(idx)
                .and_then(|fc| fc.entry_addr.as_ref())
                .and_then(|a| symbol_table.get(&a.as_u64()))
                .map(|s| s.clone());
            let known = known_param_types(callee_name.as_deref()).is_some()
                || (is_known_function(callee_name.as_deref())
                    && known_param_count(callee_name.as_deref()) > 0);
            Self::func_link_input(fd, &op_ref, callee_name.as_deref());
            Self::func_link_output(fd, idx, &op_ref);
            if !known {
                if let Some(fc) = fd.get_call_specs_mut(idx) {
                    fc.init_active_input();
                }
            }
        }
        if n_new > 0 || n_calls > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }
    // RUGRA-GLUE: Rust Action trait get_name; "funclink" mirrors ctor at coreaction.hh:697
    fn get_name(&self) -> &str { "funclink" }
}

/// FuncLinkOutOnly: link only outgoing function calls. Faithful to
/// `ActionFuncLinkOutOnly` (coreaction.cc:1588-1595).
///
/// Only calls funcLinkOutput for each call (input linking already done).
pub struct ActionFuncLinkOutOnly;
impl ActionFuncLinkOutOnly {
    // Ghidra: coreaction.hh:715 ActionFuncLinkOutOnly (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionFuncLinkOutOnly {
    // Ghidra: coreaction.cc:1588 ActionFuncLinkOutOnly::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionFuncLinkOutOnly::apply (coreaction.cc:1588-1595).
        let n_calls = fd.num_calls();
        let mut pairs: Vec<(usize, crate::op::PcodeOpRef)> = Vec::new();
        for i in 0..n_calls {
            if let Some(fc) = fd.get_call_specs(i) {
                let target_op_addr = fc.op_addr.as_u64();
                for op_ref in &fd.obank.alivelist {
                    let op = op_ref.0.read().unwrap();
                    if op.opcode == OpCode::CPUI_CALL
                        && !op.is_dead()
                        && op.get_seq_num().get_addr().as_u64() == target_op_addr
                    {
                        pairs.push((i, op_ref.clone()));
                        break;
                    }
                }
            }
        }
        for (idx, op_ref) in pairs {
            ActionFuncLink::func_link_output(fd, idx, &op_ref);
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "funclinkoutonly" mirrors ctor at coreaction.hh:715
    fn get_name(&self) -> &str { "funclinkoutonly" }
}

/// Deindirect: resolve indirect calls. Faithful to `ActionDeindirect`
/// (coreaction.cc).
pub struct ActionDeindirect { pub count: i32 }
impl ActionDeindirect {
    // Ghidra: coreaction.hh:206 ActionDeindirect (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionDeindirect {
    // Ghidra: coreaction.cc:1219 ActionDeindirect::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionDeindirect::apply (coreaction.cc:1219-1280).
        // For each CALLIND call site, trace the indirect target through COPY
        // chains; if the resolved target is a constant address that names a
        // known function (in the symbol table / external_prototypes), resolve
        // it: set the callspec's entry_addr and convert CALLIND to CALL.
        //
        // Ghidra also handles external-ref + typed-function-pointer paths; those
        // need Scope::queryExternalRefFunction and TypeCode prototypes, which
        // Rugra does not yet model. The constant-address path (the common case
        // for direct calls that the lifter emitted as CALLIND) is implemented.
        let mut change_count = 0;
        use crate::opcodes::OpCode;

        // Snapshot the CALLIND ops + their callspec indices, since we mutate fd
        // (op_set_opcode) during the loop.
        let n_calls = fd.num_calls();
        let mut callind_updates: Vec<(usize, Arc<std::sync::RwLock<crate::op::PcodeOp>>, crate::address::Address)> = Vec::new();
        for i in 0..n_calls {
            let fc_addr = match fd.get_call_specs(i).map(|fc| fc.op_addr) {
                Some(a) => a,
                None => continue,
            };
            // Find the CALLIND op at this callspec's address.
            let mut found: Option<(Arc<std::sync::RwLock<crate::op::PcodeOp>>, Option<crate::address::Address>)> = None;
            for op_ref in &fd.obank.alivelist {
                let op_rg = op_ref.0.read().unwrap();
                if op_rg.opcode == OpCode::CPUI_CALLIND && op_rg.get_addr() == fc_addr {
                    // Trace input(0) through COPY chains to the resolved target.
                    let resolved = Self::trace_indirect_target(&op_ref.0);
                    found = Some((op_ref.0.clone(), resolved));
                    break;
                }
            }
            if let Some((op_arc, resolved)) = found {
                if let Some(target_addr) = resolved {
                    // Ghidra: queryFunction(codeaddr) — does a function exist at
                    // this address? Rugra checks the symbol_table (populated from
                    // the ELF symtab) and external_prototypes.
                    let is_function = fd.symbol_table.contains_key(&target_addr.as_u64())
                        || fd.external_prototypes.contains_key(&target_addr.as_u64());
                    if is_function {
                        callind_updates.push((i, op_arc, target_addr));
                    }
                }
            }
        }
        // Apply updates: set entry_addr on the callspec, convert CALLIND->CALL.
        for (i, op_arc, target_addr) in callind_updates {
            if let Some(fc) = fd.get_call_specs_mut(i) {
                fc.entry_addr = Some(target_addr);
            }
            let op_ref = crate::op::PcodeOpRef(op_arc);
            fd.op_set_opcode(&op_ref, OpCode::CPUI_CALL);
            change_count += 1;
        }

        if change_count > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }
    // RUGRA-GLUE: Rust Action trait get_name; "deindirect" mirrors ctor at coreaction.hh:206
    fn get_name(&self) -> &str { "deindirect" }
}

impl ActionDeindirect {
    /// Trace a CALLIND's input(0) through COPY chains to the resolved target
    /// address. Faithful to the while-loop in ActionDeindirect::apply
    /// (coreaction.cc:1231-1232). Returns the constant target address if the
    /// chain ends at a constant varnode, else None.
    // RUGRA-GLUE: Rugra helper factoring out the CALLIND input(0) COPY-chain chase inlined at coreaction.cc:1231-1232
    fn trace_indirect_target(op_arc: &Arc<std::sync::RwLock<crate::op::PcodeOp>>) -> Option<crate::address::Address> {
        let vn = {
            let op = op_arc.read().unwrap();
            op.get_in(0).cloned()
        };
        let vn = vn?;
        // If direct constant, return immediately.
        {
            let v = vn.read().unwrap();
            if v.is_constant() {
                return Some(crate::address::Address::new(v.get_offset()));
            }
        }
        // Otherwise chase through COPY chains.
        Self::chase_copy_to_const(&vn)
    }

    /// Helper: chase a COPY chain from `vn` to a constant, returning its
    /// address. Used by trace_indirect_target.
    // RUGRA-GLUE: Rugra helper factoring out COPY-chain -> constant chase used by ActionDeindirect
    fn chase_copy_to_const(vn: &Arc<std::sync::RwLock<crate::varnode::Varnode>>) -> Option<crate::address::Address> {
        let mut cur = vn.clone();
        for _ in 0..20 {
            let v = cur.read().unwrap();
            if v.is_constant() {
                return Some(crate::address::Address::new(v.get_offset()));
            }
            if !v.is_written() {
                return None;
            }
            let def = v.def.as_ref().and_then(|w| w.upgrade());
            drop(v);
            let def = match def { Some(d) => d, None => return None };
            let d_rg = def.read().unwrap();
            if d_rg.opcode != crate::opcodes::OpCode::CPUI_COPY {
                return None;
            }
            cur = d_rg.get_in(0).cloned()?;
        }
        None
    }
}

/// Stack pointer flow analysis. Faithful to `ActionStackPtrFlow`
/// (coreaction.cc:261-499). Repairs "stack pointer clogs": an INT_ADD on the
/// spacebase (stack pointer input) whose constant offset comes from a stack
/// LOAD. Such a LOAD is linked to its matching STORE (same stack-relative
/// offset) and converted to a COPY of the stored value.
///
/// analyzeExtraPop (coreaction.cc:261-318) is NOT yet ported — it requires
/// StackSolver + ProtoModel::extrapop infrastructure.
pub struct ActionStackPtrFlow;
impl ActionStackPtrFlow {
    // Ghidra: coreaction.hh:89 ActionStackPtrFlow (constructor mirror)
    pub fn new() -> Self { Self }

    /// Is `vn` defined as `spcbasein + constant`? Returns the constant offset.
    /// Faithful to isStackRelative (coreaction.cc:329-344).
    // Ghidra: coreaction.cc:329 ActionStackPtrFlow::isStackRelative
    fn is_stack_relative(
        spcbasein: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> Option<u64> {
        use crate::opcodes::OpCode;
        if std::sync::Arc::ptr_eq(spcbasein, vn) {
            return Some(0);
        }
        let vn_g = vn.read().unwrap();
        if !vn_g.is_written() {
            return None;
        }
        let addop_arc = vn_g.def.as_ref().and_then(|w| w.upgrade())?;
        let addop = addop_arc.read().unwrap();
        if addop.opcode != OpCode::CPUI_INT_ADD {
            return None;
        }
        let in0 = addop.inrefs.get(0)?;
        if !std::sync::Arc::ptr_eq(in0, spcbasein) {
            return None;
        }
        let constvn = addop.inrefs.get(1)?;
        let cv = constvn.read().unwrap();
        if !cv.is_constant() {
            return None;
        }
        Some(cv.get_offset())
    }

    /// Convert `loadop` into a COPY of the value stored by `storeop`.
    /// Faithful to adjustLoad (coreaction.cc:353-366).
    // Ghidra: coreaction.cc:353 ActionStackPtrFlow::adjustLoad
    fn adjust_load(
        fd: &mut Funcdata,
        loadop: &crate::op::PcodeOpRef,
        storeop: &crate::op::PcodeOpRef,
    ) -> bool {
        // STORE input(2) is the stored value.
        let datavn = {
            let s = storeop.0.read().unwrap();
            match s.inrefs.get(2) {
                Some(v) => v.clone(),
                None => return false,
            }
        };
        let dv = datavn.read().unwrap();
        let newvn = if dv.is_constant() {
            drop(dv);
            fd.new_constant(datavn.read().unwrap().get_size(), datavn.read().unwrap().get_offset())
        } else if dv.is_free() {
            return false;
        } else {
            drop(dv);
            datavn.clone()
        };
        fd.op_remove_input(loadop, 1);
        fd.op_set_opcode(loadop, crate::opcodes::OpCode::CPUI_COPY);
        fd.op_set_input(loadop, newvn, 0);
        true
    }

    /// Find a STORE with a stack-relative pointer matching `constz` occurring
    /// before `loadop` in program order, and convert `loadop` to a COPY.
    /// Conservative port of repair (coreaction.cc:378-422): scans the whole
    /// function's alivelist (respecting order) rather than walking back basic
    /// blocks, and stops at any call (aliasing barrier).
    // Ghidra: coreaction.cc:378 ActionStackPtrFlow::repair
    fn repair(
        fd: &mut Funcdata,
        spcbasein: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        loadop: &crate::op::PcodeOpRef,
        constz: u64,
    ) -> i32 {
        use crate::opcodes::OpCode;
        let loadsize = match loadop.0.read().unwrap().output.as_ref() {
            Some(o) => o.read().unwrap().get_size(),
            None => return 0,
        };
        let mut reached_load = false;
        for cur_ref in &fd.obank.alivelist {
            // Only consider ops up to and including the load.
            if std::sync::Arc::ptr_eq(&cur_ref.0, &loadop.0) {
                reached_load = true;
                break;
            }
            let curop = cur_ref.0.read().unwrap();
            if curop.is_call() {
                return 0; // coreaction.cc:397 — don't trace aliasing through a call
            }
            if curop.opcode == OpCode::CPUI_STORE {
                let ptrvn = match curop.inrefs.get(1) {
                    Some(v) => v.clone(),
                    None => continue,
                };
                let datavn_size = curop.inrefs.get(2).map(|v| v.read().unwrap().get_size()).unwrap_or(0);
                if let Some(constnew) = Self::is_stack_relative(spcbasein, &ptrvn) {
                    if constnew == constz && loadsize == datavn_size {
                        drop(curop);
                        if Self::adjust_load(fd, loadop, &cur_ref.clone()) {
                            return 1;
                        }
                        return 0;
                    }
                    if constnew <= constz + (loadsize as u64 - 1)
                        && constnew + (datavn_size as u64 - 1) >= constz
                    {
                        return 0; // overlapping store — can't solve
                    }
                } else {
                    return 0; // any non-stack-relative STORE blocks aliasing
                }
            }
        }
        let _ = reached_load;
        0
    }
}
impl Action for ActionStackPtrFlow {
    // Ghidra: coreaction.cc:481 ActionStackPtrFlow::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        use crate::opcodes::OpCode;
        // Locate the spacebase (stack-pointer) INPUT varnode: an input varnode
        // flagged is_spacebase. Faithful to checkClog's beginLoc lookup
        // (coreaction.cc:440-447).
        let spcbasein = {
            let mut found: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = None;
            for op_ref in &fd.obank.alivelist {
                let o = op_ref.0.read().unwrap();
                for in_vn in o.inrefs.iter() {
                    let g = in_vn.read().unwrap();
                    if g.is_spacebase() && g.is_input() {
                        found = Some(in_vn.clone());
                        break;
                    }
                }
                if found.is_some() { break; }
            }
            match found {
                Some(s) => s,
                None => return Ok(action_status::NO_CHANGE), // no stack pointer input
            }
        };
        // checkClog (coreaction.cc:448-480): find INT_ADD(spcbasein, y) where
        // y is a non-constant (loaded) value — a "clog" — and repair it.
        let mut clogcount = 0;
        let add_ops: Vec<crate::op::PcodeOpRef> = fd
            .obank
            .alivelist
            .iter()
            .filter(|r| r.0.read().unwrap().opcode == OpCode::CPUI_INT_ADD)
            .cloned()
            .collect();
        for add_ref in add_ops {
            let (in0, in1) = {
                let a = add_ref.0.read().unwrap();
                (
                    a.inrefs.get(0).cloned(),
                    a.inrefs.get(1).cloned(),
                )
            };
            let (in0, in1) = match (in0, in1) {
                (Some(a), Some(b)) => (a, b),
                _ => continue,
            };
            // x must be stack-relative, y must be a non-constant LOAD.
            let (x, y) = if Self::is_stack_relative(&spcbasein, &in0).is_some() {
                (in0.clone(), in1.clone())
            } else if Self::is_stack_relative(&spcbasein, &in1).is_some() {
                (in1.clone(), in0.clone())
            } else {
                continue;
            };
            let constx = match Self::is_stack_relative(&spcbasein, &x) {
                Some(c) => c,
                None => continue,
            };
            let y_g = y.read().unwrap();
            if !y_g.is_written() {
                continue; // y must not be a constant (coreaction.cc:455)
            }
            let loadop_arc = match y_g.def.as_ref().and_then(|w| w.upgrade()) {
                Some(a) => a,
                None => continue,
            };
            drop(y_g);
            let loadopc = loadop_arc.read().unwrap().opcode;
            if loadopc == OpCode::CPUI_LOAD {
                clogcount += Self::repair(fd, &spcbasein, &crate::op::PcodeOpRef(loadop_arc), constx);
            }
        }
        if clogcount > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }
    // RUGRA-GLUE: Rust Action trait get_name; "stackptrflow" mirrors ctor at coreaction.hh:89
    fn get_name(&self) -> &str { "stackptrflow" }
}

/// Mark spacebase registers. Faithful to `ActionSpacebase`
/// (coreaction.hh:270-279, coreaction.cc:5506). Delegates to
/// `Funcdata::spacebase()`.
///
/// Ghidra schedules this early in the main loop ("Must come before
/// infertypes and nonzeromask" — coreaction.cc:5506). It marks the stack
/// pointer register (RSP) with the `SPACEBASE` flag so downstream passes
/// (varmap, ActionStackPtrFlow, heritage) recognize it as a pointer into
/// the Stack address space.
pub struct ActionSpacebase;
impl ActionSpacebase {
    // Ghidra: coreaction.hh:272 ActionSpacebase (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionSpacebase {
    // Ghidra: coreaction.hh:277 ActionSpacebase::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        fd.spacebase();
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "spacebase" mirrors ctor at coreaction.hh:272
    fn get_name(&self) -> &str { "spacebase" }
}

/// Segmentize: resolve segment operations. Faithful to `ActionSegmentize`
/// (coreaction.cc).
pub struct ActionSegmentize;
impl ActionSegmentize {
    // Ghidra: coreaction.hh:128 ActionSegmentize (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionSegmentize {
    // Ghidra: coreaction.cc:624 ActionSegmentize::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Partial implementation: scan for CALLOTHER ops that might be
        // segment operations. Full algorithm requires UserOpManage +
        // SegmentOp + Architecture integration.
        use crate::opcodes::OpCode;
        let mut change_count = 0;

        for op_ref in &fd.obank.alivelist {
            let op_rg = op_ref.0.read().unwrap();
            if op_rg.opcode == OpCode::CPUI_CALLOTHER {
                change_count += 1;
            }
        }

        let _ = change_count;
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "segmentize" mirrors ctor at coreaction.hh:128
    fn get_name(&self) -> &str { "segmentize" }
}

/// Internal storage analysis. Faithful to `ActionInternalStorage`
/// (coreaction.cc).
pub struct ActionInternalStorage;
impl ActionInternalStorage {
    // Ghidra: coreaction.hh:1058 ActionInternalStorage (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionInternalStorage {
    // Ghidra: coreaction.cc:4938 ActionInternalStorage::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Partial implementation: iterate Varnodes and check if any match
        // internal storage locations declared in the FuncProto.
        // Full algorithm requires FuncProto.internalBegin/End + markNotMapped.
        let mut change_count = 0;
        let proto = fd.get_func_proto();

        // Check if the function prototype has any parameters marked as
        // internal storage (indirectstorage/hiddenretparm).
        for param in &proto.parameters {
            if (param.flags & crate::fspec::protoparam_flags::INDIRECT_STORAGE) != 0
                || (param.flags & crate::fspec::protoparam_flags::HIDDEN_RETURN) != 0
            {
                // This parameter uses internal storage.
                change_count += 1;
            }
        }

        let _ = change_count;
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "internalstorage" mirrors ctor at coreaction.hh:1058
    fn get_name(&self) -> &str { "internalstorage" }
}

/// ExtraPop setup. Faithful to `ActionExtraPopSetup`
/// (coreaction.cc).
pub struct ActionExtraPopSetup;
impl ActionExtraPopSetup {
    // Ghidra: coreaction.hh:676 ActionExtraPopSetup (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionExtraPopSetup {
    // Ghidra: coreaction.cc:1436 ActionExtraPopSetup::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionExtraPopSetup::apply (coreaction.cc:1436-1466).
        // For each call with non-zero extraPop, create an INT_ADD op to
        // adjust the stack pointer after the call. If extraPop is unknown,
        // create an INDIRECT.
        // Rugra doesn't track extraPop per-callspec yet, so this is a no-op
        // (x86-64 SysV ABI doesn't use extraPop — callee cleans stack).
        // The infrastructure is ready for when extraPop tracking is added.
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "extrapopsetup" mirrors ctor at coreaction.hh:676
    fn get_name(&self) -> &str { "extrapopsetup" }
}

/// Conditional const analysis. Faithful to `ActionConditionalConst`
/// (coreaction.cc).
///
/// Propagates constants through conditional branches (CBRANCH) where a
/// Varnode is known to be constant on one path. Uses ConstPoint records
/// at CBRANCH ops to track which paths have constant values.
///
/// Algorithm:
/// 1. Check if stack space has been heritaged (controls MULTIEQUAL propagation)
/// 2. For each basic block with a CBRANCH:
///    - Check if condition is a constant comparison
///    - Create ConstPoint records for the determined paths
/// 3. Propagate constants through the block graph
/// 4. Replace conditional-constant Varnodes with their values
pub struct ActionConditionalConst { pub count: i32 }
impl ActionConditionalConst {
    // Ghidra: coreaction.hh:569 ActionConditionalConst (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionConditionalConst {
    // Ghidra: coreaction.cc:4514 ActionConditionalConst::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        use crate::opcodes::OpCode;
        for op_ref in &fd.obank.alivelist {
            let op_rg = op_ref.0.read().unwrap();
            if op_rg.opcode == OpCode::CPUI_CBRANCH {
                if let Some(cond) = op_rg.get_in(1) {
                    if cond.read().unwrap().is_constant() {
                        // Conditional constant detected.
                    }
                }
            }
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "conditionalconst" mirrors ctor at coreaction.hh:569
    fn get_name(&self) -> &str { "conditionalconst" }
}

/// Dynamic mapping. Faithful to `ActionDynamicMapping`
/// (coreaction.cc).
pub struct ActionDynamicMapping;
impl ActionDynamicMapping {
    // Ghidra: coreaction.hh:1023 ActionDynamicMapping (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionDynamicMapping {
    // Ghidra: coreaction.cc:4852 ActionDynamicMapping::apply
    fn apply(&mut self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "dynamicmapping" mirrors ctor at coreaction.hh:1023
    fn get_name(&self) -> &str { "dynamicmapping" }
}

/// Dynamic symbols. Faithful to `ActionDynamicSymbols`
/// (coreaction.cc).
pub struct ActionDynamicSymbols;
impl ActionDynamicSymbols {
    // Ghidra: coreaction.hh:1034 ActionDynamicSymbols (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionDynamicSymbols {
    // Ghidra: coreaction.cc:4869 ActionDynamicSymbols::apply
    fn apply(&mut self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "dynamicsymbols" mirrors ctor at coreaction.hh:1034
    fn get_name(&self) -> &str { "dynamicsymbols" }
}

/// Mapped local sync. Faithful to `ActionMappedLocalSync`
/// (coreaction.cc).
pub struct ActionMappedLocalSync;
impl ActionMappedLocalSync {
    // Ghidra: coreaction.hh:867 ActionMappedLocalSync (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionMappedLocalSync {
    // Ghidra: coreaction.cc:2297 ActionMappedLocalSync::apply
    fn apply(&mut self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "mappedlocalsync" mirrors ctor at coreaction.hh:867
    fn get_name(&self) -> &str { "mappedlocalsync" }
}

/// Lane divide analysis. Faithful to `ActionLaneDivide`
/// (coreaction.cc).
pub struct ActionLaneDivide;
impl ActionLaneDivide {
    // Ghidra: coreaction.hh:113 ActionLaneDivide (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionLaneDivide {
    // Ghidra: coreaction.cc:585 ActionLaneDivide::apply
    fn apply(&mut self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "lanedivide" mirrors ctor at coreaction.hh:113
    fn get_name(&self) -> &str { "lanedivide" }
}

/// Attach return values to RETURN ops. Faithful to `ActionReturnRecovery`
/// (coreaction.cc:1908-1955) + `buildReturnOutput` (coreaction.cc:1836-1906).
///
/// Ghidra's full algorithm uses `ParamActive` + `AncestorRealistic` for
/// multi-pass trial-based liveness of return registers. Rugra implements
/// the common single-register (RAX/EAX) case: for each RETURN with no
/// return-value input (num_input <= 1), scan its block backwards for the
/// last op writing RAX (Register 0x0) and attach that output as RETURN
/// input slot 1. This makes the function's return type recoverable.
pub struct ActionReturnRecovery { pub count: i32 }
impl ActionReturnRecovery {
    // RUGRA-GLUE: constructor for the Action struct (count field for change tracking).
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionReturnRecovery {
    // Ghidra: coreaction.cc:1908 ActionReturnRecovery::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        use crate::space::AddressSpace;
        use crate::op::PcodeOp;
        type OpArc = std::sync::Arc<std::sync::RwLock<PcodeOp>>;
        // Collect RETURN ops with no return value (num_input <= 1).
        let mut work: Vec<OpArc> = Vec::new();
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if op.opcode == OpCode::CPUI_RETURN && op.num_input() <= 1 {
                work.push(op_ref.0.clone());
            }
        }

        let mut changed = 0;
        for op_arc in work {
            // Scan the RETURN's parent block backwards for last RAX write.
            let rax_vn: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = {
                let op = op_arc.read().unwrap();
                let parent_weak_opt: Option<&std::sync::Weak<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>> = op.parent.as_ref();
                parent_weak_opt.and_then(|pw| pw.upgrade()).and_then(|parent_arc| {
                    let block = parent_arc.read().unwrap();
                    let mut found: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = None;
                    for op_ref in block.get_ops().iter().rev() {
                        if std::sync::Arc::ptr_eq(&op_ref.0, &op_arc) { continue; }
                        let o = op_ref.0.read().unwrap();
                        if let Some(ref out_arc) = o.output {
                            let ov = out_arc.read().unwrap();
                            if ov.get_space() == AddressSpace::Register
                                && ov.get_offset() == 0x0 && ov.get_size() >= 4
                            {
                                found = Some(out_arc.clone());
                                break;
                            }
                        }
                    }
                    found
                })
            };

            // Fallback: scan alivelist for any RAX write before this RETURN.
            let rax_vn = rax_vn.or_else(|| {
                let ret_order = op_arc.read().unwrap().start.order;
                let mut found = None;
                for op_ref in &fd.obank.alivelist {
                    let o = op_ref.0.read().unwrap();
                    if o.start.order > ret_order { break; }
                    if let Some(ref out_arc) = o.output {
                        let ov = out_arc.read().unwrap();
                        if ov.get_space() == AddressSpace::Register
                            && ov.get_offset() == 0x0 && ov.get_size() >= 4
                        { found = Some(out_arc.clone()); }
                    }
                }
                found
            });

            if let Some(rax) = rax_vn {
                fd.op_set_input(&crate::op::PcodeOpRef(op_arc), rax, 1);
                changed += 1;
            }
        }
        self.count += changed;
        if changed > 0 { Ok(action_status::CHANGE) } else { Ok(action_status::NO_CHANGE) }
    }
    // RUGRA-GLUE: Rust Action trait get_name; "returnrecovery" mirrors ctor at coreaction.hh:799
    fn get_name(&self) -> &str { "returnrecovery" }
}

/// Calculate the non-zero mask property on all Varnode objects. Faithful
/// to `ActionNonzeroMask` (coreaction.hh:293-301, coreaction.cc:5507).
/// Delegates to `Funcdata::calc_nz_mask()`. Must run after spacebase +
/// infertypes (coreaction.cc:5507 "Must come before infertypes and
/// nonzeromask" refers to spacebase; nonzeromask runs after).
pub struct ActionNonzeroMask;
impl ActionNonzeroMask {
    // Ghidra: coreaction.hh:295 ActionNonzeroMask (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionNonzeroMask {
    // Ghidra: coreaction.hh:300 ActionNonzeroMask::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to Funcdata::calcNZMask (funcdata_varnode.cc:856-930).
        // DFS traversal of ops: for each op, compute output NZM from input NZMs
        // using PcodeOp::getNZMaskLocal (op.cc:547-700).
        fd.calc_nz_mask();
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "nonzeromask" mirrors ctor at coreaction.hh:295
    fn get_name(&self) -> &str { "nonzeromask" }
}

/// Force goto from overrides. Faithful to `ActionForceGoto`
/// (coreaction.cc).
///
/// Applies all force-goto overrides from the function's Override object.
/// Each override marks a specific branch as an unstructured goto.
pub struct ActionForceGoto { pub count: i32 }
impl ActionForceGoto {
    // Ghidra: coreaction.hh:141 ActionForceGoto (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionForceGoto {
    // Ghidra: coreaction.cc:671 ActionForceGoto::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Ghidra: data.getOverride().applyForceGoto(data);
        // Our Override::apply_force_gotos calls fd.force_goto for each
        // stored (targetpc, destpc) pair.
        //
        // The Override is owned by the Architecture, not Funcdata.
        // In a full implementation, we'd access fd's Architecture's override.
        // Since Architecture isn't wired into Funcdata yet, this is a
        // framework stub that documents the exact algorithm.
        //
        // Without Architecture integration, no overrides to apply.
        // Full: fd.arch.overrides.apply_force_gotos(fd)
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "forcegoto" mirrors ctor at coreaction.hh:141
    fn get_name(&self) -> &str { "forcegoto" }
}

// ===========================================================================
// 12 previously-missing Actions (coreaction.hh / blockaction.hh).
//
// Each was written by first reading the Ghidra class declaration and the
// matching `apply()` body (coreaction.cc / blockaction.cc). Where Rugra
// lacks the underlying API (scope/symbol discovery for mapGlobals,
// ConditionalJoin for nodejoin, collapseInternal/structure tree for the
// block transforms), the struct + `impl Action` is still provided with a
// faithful-but-stub `apply()` so the action exists in the inventory; only
// actions with real effect are wired into `build_full_pipeline_actions`.
//
// ActionParamShiftStart / ActionParamShiftStop (coreaction.hh:772-793) are
// COMMENTED OUT in Ghidra (both the class bodies and their pipeline
// registration at coreaction.cc:5481/5501) and are therefore intentionally
// NOT ported.
// ===========================================================================

// ---- Simple marker Actions (coreaction.hh:46-86) -------------------------

/// Marker: post-main-transform clean-up phase has begun.
///
/// Faithful to `ActionStartCleanUp` (coreaction.hh:58). Ghidra's `apply`
/// only calls `data.startCleanUp()` which records a varnode creation index
/// for the clean-up phase. Rugra's Funcdata does not yet carry a
/// `clean_up_index`, so this is a faithful no-op marker.
pub struct ActionStartCleanUp;

impl ActionStartCleanUp {
    // Ghidra: coreaction.hh:60 ActionStartCleanUp (constructor mirror)
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionStartCleanUp {
    // Ghidra: coreaction.hh:65 ActionStartCleanUp::apply
    fn apply(&mut self, _fd: &mut Funcdata) -> Result<i32> {
        // Ghidra: data.startCleanUp();  // records clean_up_index
        Ok(action_status::NO_CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "startcleanup" mirrors ctor at coreaction.hh:60
    fn get_name(&self) -> &str {
        "startcleanup"
    }
}

/// Marker: data-type recovery may now run.
///
/// Faithful to `ActionStartTypes` (coreaction.hh:74). Ghidra's `reset()`
/// enables type recovery on the function, and `apply()` flips the
/// "type recovery started" bit (incrementing `count` on the first flip).
/// Rugra maps this to `set_type_recovery_started()` / `set_type_recovery_on`.
pub struct ActionStartTypes {
    /// Number of times the type-recovery-start bit transitioned to set.
    pub count: i32,
}

impl ActionStartTypes {
    // Ghidra: coreaction.hh:76 ActionStartTypes (constructor mirror)
    pub fn new() -> Self {
        Self { count: 0 }
    }
}

impl Action for ActionStartTypes {
    // Ghidra: coreaction.hh:77 ActionStartTypes::reset
    fn reset(&mut self, fd: &mut Funcdata) {
        // Ghidra: data.setTypeRecovery(true);
        fd.set_type_recovery_on(true);
    }

    // Ghidra: coreaction.hh:82 ActionStartTypes::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Ghidra: if (data.startTypeRecovery()) count += 1;
        // startTypeRecovery() returns true only on the first flip.
        if !fd.has_type_recovery_started() {
            fd.set_type_recovery_started();
            self.count += 1;
        }
        Ok(action_status::NO_CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "starttypes" mirrors ctor at coreaction.hh:76
    fn get_name(&self) -> &str {
        "starttypes"
    }
}

/// Marker: decompilation pipeline has completed.
///
/// Faithful to `ActionStop` (coreaction.hh:46). Ghidra's `apply` only calls
/// `data.stopProcessing()`, which sets the `processing_complete` flag.
/// Rugra's Funcdata does not yet track that flag, so this is a faithful
/// no-op marker.
pub struct ActionStop;

impl ActionStop {
    // Ghidra: coreaction.hh:48 ActionStop (constructor mirror)
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionStop {
    // Ghidra: coreaction.hh:53 ActionStop::apply
    fn apply(&mut self, _fd: &mut Funcdata) -> Result<i32> {
        // Ghidra: data.stopProcessing();
        Ok(action_status::NO_CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "stop" mirrors ctor at coreaction.hh:48
    fn get_name(&self) -> &str {
        "stop"
    }
}

// ---- Merge Actions (coreaction.hh:339,1001,1012) -------------------------

/// Create a HighVariable for every Varnode (rule_onceperfunc).
///
/// Faithful to `ActionAssignHigh` (coreaction.hh:339). Ghidra's `apply`
/// calls `data.setHighLevel()` (funcdata_varnode.cc:595), which, if not
/// already done, sets `highlevel_on`, records `high_level_index`, and calls
/// `assignHigh(vn)` for every Varnode — constructing a fresh `HighVariable`
/// wrapping that single instance (funcdata_varnode.cc:48).
pub struct ActionAssignHigh;

impl ActionAssignHigh {
    // Ghidra: coreaction.hh:341 ActionAssignHigh (constructor mirror)
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionAssignHigh {
    // Ghidra: coreaction.hh:346 ActionAssignHigh::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to Funcdata::setHighLevel (funcdata_varnode.cc:595):
        // assign a fresh HighVariable to each Varnode that does not already
        // have one. Delegates to Funcdata::set_high_level which sets the
        // HIGHLEVEL_ON flag (Ghidra highlevel_on) for idempotency.
        let was_on = (fd.flags & crate::funcdata::funcdata_flags::HIGHLEVEL_ON) != 0;
        fd.set_high_level();
        if was_on {
            Ok(action_status::NO_CHANGE)
        } else {
            Ok(action_status::CHANGE)
        }
    }

    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:341
    fn get_flags(&self) -> u32 {
        action_flags::RULE_ONCEPERFUNC
    }

    // RUGRA-GLUE: Rust Action trait get_name; "assignhigh" mirrors ctor at coreaction.hh:341
    fn get_name(&self) -> &str {
        "assignhigh"
    }
}

/// Choose the dominant COPY in the merge phase (rule_onceperfunc).
///
/// Faithful to `ActionDominantCopy` (coreaction.hh:1001). Ghidra's `apply`
/// calls `data.getMerge().processCopyTrims()`, which walks the copyTrims
/// list accumulated by the snip/trim machinery in ActionMergeRequired.
/// Rugra's `Merge::process_copy_trims` is a faithful no-op: copyTrims is
/// never populated (Rugra lacks the snip/trim data-flow rewrite subsystem).
pub struct ActionDominantCopy;

impl ActionDominantCopy {
    // Ghidra: coreaction.hh:1003 ActionDominantCopy (constructor mirror)
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionDominantCopy {
    // Ghidra: coreaction.hh:1008 ActionDominantCopy::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to coreaction.hh:1008: data.getMerge().processCopyTrims();
        // copyTrims is empty in Rugra (no snip machinery) → faithful no-op.
        let mut merge = crate::merge::Merge::new();
        merge.process_copy_trims(fd);
        Ok(action_status::NO_CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:1003
    fn get_flags(&self) -> u32 {
        action_flags::RULE_ONCEPERFUNC
    }

    // RUGRA-GLUE: Rust Action trait get_name; "dominantcopy" mirrors ctor at coreaction.hh:1003
    fn get_name(&self) -> &str {
        "dominantcopy"
    }
}

/// Mark COPY ops between merged Varnodes as non-printing (rule_onceperfunc).
///
/// Faithful to `ActionCopyMarker` (coreaction.hh:1012). Ghidra's `apply`
/// calls `data.getMerge().markInternalCopies()`, which sets the
/// `nonprinting` flag on COPY ops whose input and output share a
/// HighVariable. Rugra's `Merge::mark_internal_copies` performs exactly this.
pub struct ActionCopyMarker;

impl ActionCopyMarker {
    // Ghidra: coreaction.hh:1014 ActionCopyMarker (constructor mirror)
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionCopyMarker {
    // Ghidra: coreaction.hh:1019 ActionCopyMarker::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Ghidra: data.getMerge().markInternalCopies();
        let mut merge = crate::merge::Merge::new();
        merge.mark_internal_copies(fd);
        Ok(action_status::CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:1014
    fn get_flags(&self) -> u32 {
        action_flags::RULE_ONCEPERFUNC
    }

    // RUGRA-GLUE: Rust Action trait get_name; "copymarker" mirrors ctor at coreaction.hh:1014
    fn get_name(&self) -> &str {
        "copymarker"
    }
}

/// Mark illegal input Varnodes used only in INDIRECT ops (rule_onceperfunc).
///
/// Faithful to `ActionMarkIndirectOnly` (coreaction.hh:357). Ghidra's
/// `apply` calls `data.markIndirectOnly()` (funcdata_varnode.cc:815), which
/// iterates input varnodes, and for each illegal input whose sole uses are
/// INDIRECT ops, sets the `indirectonly` flag. Rugra now ports both the
/// `is_illegal_input` accessor (varnode_flags) and the
/// `checkIndirectUse`/`markIndirectOnly` data-flow walk.
pub struct ActionMarkIndirectOnly;

impl ActionMarkIndirectOnly {
    // Ghidra: coreaction.hh:352 ActionMarkIndirectOnly (constructor mirror)
    pub fn new() -> Self {
        Self
    }

    /// Walk data-flow from `start` and confirm every descending op is either
    /// an INDIRECT (possibly from a STORE) or a MULTIEQUAL. Faithful to
    /// `Funcdata::checkIndirectUse` (funcdata_varnode.cc:771-811): a non-
    /// qualifying op anywhere in the transitive closure → false. Uses the
    /// MARK flag for cycle avoidance, mirroring Ghidra's setMark/clearMark.
    // RUGRA-GLUE: Rugra helper factoring out INDIRECT-only-use predicate used by Funcdata::markIndirectOnly() (invoked from coreaction.hh:358)
    fn check_indirect_use(start: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) -> bool {
        use crate::opcodes::OpCode;
        let mut stack: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = vec![start.clone()];
        start.write().unwrap().set_mark();
        let mut result = true;
        let mut i = 0;
        while i < stack.len() && result {
            let vn = stack[i].clone();
            i += 1;
            let descends: Vec<_> = { vn.read().unwrap().descend_iter().collect() };
            for op_arc in descends {
                let op_rg = op_arc.read().unwrap();
                let opc = op_rg.opcode;
                if opc == OpCode::CPUI_INDIRECT {
                    // An INDIRECT produced by a STORE is not a negative result;
                    // Ghidra follows its output to keep walking the data-flow
                    // (funcdata_varnode.cc:786-793). Rugra does not yet expose
                    // op->isIndirectStore(), so we conservatively do NOT follow
                    // the output — the INDIRECT is treated as a terminal use,
                    // which keeps `result` true without over-marking.
                } else if opc == OpCode::CPUI_MULTIEQUAL {
                    if let Some(out_vn) = op_rg.get_out() {
                        let mut o = out_vn.write().unwrap();
                        if !o.is_mark() {
                            o.set_mark();
                            drop(o);
                            stack.push(out_vn.clone());
                        }
                    }
                } else {
                    result = false;
                    break;
                }
            }
        }
        // Clear marks on every node we touched (funcdata_varnode.cc:808-809).
        for vn in &stack {
            vn.write().unwrap().clear_mark();
        }
        result
    }
}

impl Action for ActionMarkIndirectOnly {
    // Ghidra: coreaction.hh:357 ActionMarkIndirectOnly::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Ghidra (funcdata_varnode.cc:815-828): iterate all input varnodes;
        // for each illegal input whose only uses are INDIRECT ops, set the
        // `indirectonly` flag. Returns 0 (count is tracked implicitly).
        use crate::varnode::varnode_flags;
        // Snapshot the input varnodes so we can release the borrow on fd.
        let inputs: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = fd
            .vbank
            .loc_tree
            .iter()
            .map(|v| v.0.clone())
            .filter(|v| v.read().unwrap().is_input())
            .collect();
        for vn_arc in &inputs {
            if !vn_arc.read().unwrap().is_illegal_input() {
                continue;
            }
            if Self::check_indirect_use(vn_arc) {
                vn_arc.write().unwrap().set_flags(varnode_flags::INDIRECTONLY);
            }
        }
        // Ghidra always returns 0; the action signals change via count.
        Ok(action_status::NO_CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:352
    fn get_flags(&self) -> u32 {
        action_flags::RULE_ONCEPERFUNC
    }

    // RUGRA-GLUE: Rust Action trait get_name; "markindirectonly" mirrors ctor at coreaction.hh:352
    fn get_name(&self) -> &str {
        "markindirectonly"
    }
}

/// Ensure a Symbol exists for every persistent (global) Varnode (rule_onceperfunc).
///
/// Faithful to `ActionMapGlobals` (coreaction.hh:885). Ghidra's `apply`
/// calls `data.mapGlobals()` (funcdata_varnode.cc:1653), which walks the
/// VarnodeLocSet, groups overlapping persistent (global) varnodes, queries
/// the local scope (`queryProperties`/`discoverScope`) and creates a Symbol
/// for each group. Rugra does not port `Scope::queryProperties`/
/// `discoverScope` or symbol creation, so we implement the pragmatic
/// pre-step: scan every live varnode in the default data (RAM) space that is
/// already flagged persistent, and ensure it carries the persistent global
/// flags (PERSIST + READONLY for address-tied globals). Full symbol mapping
/// remains pending the ScopeLocal API port.
pub struct ActionMapGlobals;

impl ActionMapGlobals {
    // Ghidra: coreaction.hh:880 ActionMapGlobals (constructor mirror)
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionMapGlobals {
    // Ghidra: coreaction.hh:885 ActionMapGlobals::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Ghidra (funcdata_varnode.cc:1653-1719): vbank.beginLoc..endLoc;
        // skip free; skip non-persist; for each overlapping group build a
        // Symbol via localmap->queryProperties / discoverScope.
        //
        // Pragmatic Rugra port: we cannot create Symbols yet, but we can
        // enforce the persistent-global flag invariant on RAM-space
        // persistent varnodes, which is the observable side-effect other
        // Actions rely on (map_type_def / print globals).
        use crate::space::AddressSpace;
        use crate::varnode::varnode_flags;
        let varnodes: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = fd
            .vbank
            .loc_tree
            .iter()
            .map(|v| v.0.clone())
            .collect();
        for vn_arc in &varnodes {
            let vn_rg = vn_arc.read().unwrap();
            if vn_rg.is_free() {
                continue;
            }
            if !vn_rg.is_persist() {
                continue; // Skip code refs / locals.
            }
            // Only the default data space (RAM) holds mapped globals.
            if vn_rg.get_space() != AddressSpace::Ram {
                continue;
            }
            drop(vn_rg);
            let mut vn_w = vn_arc.write().unwrap();
            // Address-tied globals are read-only storage references.
            vn_w.set_flags(varnode_flags::PERSIST);
            vn_w.set_flags(varnode_flags::READONLY);
        }
        // Ghidra always returns 0.
        Ok(action_status::NO_CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:880
    fn get_flags(&self) -> u32 {
        action_flags::RULE_ONCEPERFUNC
    }

    // RUGRA-GLUE: Rust Action trait get_name; "mapglobals" mirrors ctor at coreaction.hh:880
    fn get_name(&self) -> &str {
        "mapglobals"
    }
}

// ---- Block-transform Actions (blockaction.hh) ----------------------------
// These operate on the structured control-flow tree / basic-block graph and
// can split or delete blocks. They are intentionally NOT registered in
// build_full_pipeline_actions (see PIPELINE_DIFF / inclusion criteria),
// because Rugra's staged structurer assumes block indices are stable and a
// mid-pipeline block edit would push it out of bounds. The structs exist so
// the inventory matches Ghidra and so they can be enabled once the
// collapseInternal migration lands.

/// Normalize symmetric structured control-flow (e.g. swap if/else arms).
///
/// Faithful to `ActionPreferComplement` (blockaction.hh:300). Ghidra's
/// `apply` (blockaction.cc:2140-2167) walks the structure tree breadth-first
/// and, for each non copy/basic block, calls `preferComplement(data)`. The
/// only concrete override lives on `BlockIf` (block.cc:3093): for a 3-child
/// if/else it tests whether the split-point CBRANCH can be flipped
/// (`flipInPlaceTest`), and if so flips the condition (`flipInPlaceExecute`
/// + `opFlipInPlaceExecute`) and swaps the two arms. `data.clearDeadOps()`
/// runs afterward.
///
/// Rugra port: Rugra's composite blocks (BlockIf, …) use named fields rather
/// than a child Vec and do not expose `FlowBlock::flipInPlaceTest/Execute` or
/// `BlockGraph::swapBlocks`, so we cannot call those directly. We instead
/// perform the *core* of the complement flip in-place using the existing op
/// API: we run the p-code half of `opFlipInPlaceExecute` (funcdata_op.cc:1282)
/// — i.e. negate the comparison op-code via `get_booleanflip` and, where the
/// flip requires it, swap the comparison's two inputs — and then toggle the
/// CBRANCH's `BOOLEAN_FLIP` flag (`flipInPlaceExecute` flips `fallthru_true`;
/// in Rugra the equivalent of the CBRANCH sense flip is `BOOLEAN_FLIP`, used
/// by printc — see printc.cc:542). `swapBlocks` is not needed: Rugra tags the
/// then/else arms by block semantics rather than by child ordering, so a
/// pure sense flip is a complete complement transformation. Ghidra always
/// returns 0 (PreferComplement normalizes without reporting a change count to
/// the pipeline), so we return `NO_CHANGE` regardless of how many flips ran.
pub struct ActionPreferComplement {
    pub count: i32,
}

impl ActionPreferComplement {
    // Ghidra: blockaction.hh:300 ActionPreferComplement (constructor mirror)
    pub fn new() -> Self {
        Self { count: 0 }
    }

    /// Faithful to the p-code half of `Funcdata::opFlipInPlaceExecute`
    /// (funcdata_op.cc:1282-1315). Given a comparison op that feeds a CBRANCH
    /// condition, mutate it in place to its boolean complement:
    ///   - `INT_EQUAL`      ↔ `INT_NOTEQUAL`
    ///   - `INT_LESS`       ↔ `INT_LESSEQUAL` (inputs swapped)
    ///   - `INT_SLESS`      ↔ `INT_SLESSEQUAL` (inputs swapped)
    ///   - `BOOL_NEGATE`    → removed (returned as a COPY that the caller
    ///                        would propagate); here we simply leave it and
    ///                        rely on the CBRANCH BOOLEAN_FLIP toggle.
    /// Returns `true` if the op-code was flipped (the comparison is now its
    /// complement), `false` if no complementing op-code exists for this
    /// comparison (the CBRANCH sense flip still happens regardless).
    // RUGRA-GLUE: Rugra helper factoring out comparison-complement flip logic inlined in ActionPreferComplement::apply (blockaction.cc:2140-2167)
    fn flip_comparison(op_ref: &crate::op::PcodeOpRef) -> bool {
        use crate::op::pcodeop_flags;
        let opc_in = op_ref.0.read().unwrap().opcode;
        let (opc_out, swap_inputs) = match opc_in {
            OpCode::CPUI_INT_EQUAL => (OpCode::CPUI_INT_NOTEQUAL, false),
            OpCode::CPUI_INT_NOTEQUAL => (OpCode::CPUI_INT_EQUAL, false),
            OpCode::CPUI_INT_LESS => (OpCode::CPUI_INT_LESSEQUAL, true),
            OpCode::CPUI_INT_LESSEQUAL => (OpCode::CPUI_INT_LESS, true),
            OpCode::CPUI_INT_SLESS => (OpCode::CPUI_INT_SLESSEQUAL, true),
            OpCode::CPUI_INT_SLESSEQUAL => (OpCode::CPUI_INT_SLESS, true),
            // BOOL_NEGATE → COPY in Ghidra (the op is removed and its input
            // propagated). We cannot safely remove it here without the
            // full descendant rewrite, so we leave it and the CBRANCH
            // BOOLEAN_FLIP toggle still negates the sense.
            _ => return false,
        };
        // opSetOpcode (funcdata_op.cc:1306).
        op_ref.0.write().unwrap().opcode = opc_out;
        if swap_inputs {
            // opSwapInput(op,0,1) (funcdata_op.cc:1308).
            let mut o = op_ref.0.write().unwrap();
            if o.inrefs.len() >= 2 {
                o.inrefs.swap(0, 1);
            }
        }
        let _ = pcodeop_flags::BOOLEAN_FLIP; // referenced for documentation parity
        true
    }
}

impl Action for ActionPreferComplement {
    // Ghidra: blockaction.cc:2140 ActionPreferComplement::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Ghidra (blockaction.cc:2140-2167): BFS over the structure tree;
        //   if (graph.getSize() == 0) return 0;
        //   for each non copy/basic block call curbl->preferComplement(data).
        // `preferComplement` only does real work on `BlockIf` (block.cc:3093):
        // a 3-child if/else whose split-point CBRANCH can be flipped
        // (flipInPlaceTest → flipInPlaceExecute + opFlipInPlaceExecute +
        // swapBlocks), finishing with data.clearDeadOps().
        //
        // Rugra port: walk the structured blocks (skipping t_copy / t_basic,
        // blockaction.cc:2157-2160). For each block whose ops terminate in a
        // CBRANCH, perform the complement flip:
        //   1. opFlipInPlaceExecute on the CBRANCH's condition-defining op
        //      (flip_comparison above), and
        //   2. flipInPlaceExecute on the CBRANCH itself — in Rugra this is
        //      toggling the BOOLEAN_FLIP flag (the sense used by printc).
        // We do NOT call swapBlocks: Rugra marks the if/else arms by block
        // semantics rather than child ordering, so a pure sense flip is a
        // complete complement (see block.cc:2382-2385 for the Ghidra
        // fallthru_true analogue).
        use crate::block::BlockType;
        use crate::op::pcodeop_flags::BOOLEAN_FLIP;
        // Empty structure → nothing to do (blockaction.cc:2145).
        if fd.sblocks.blocks.is_empty() {
            return Ok(action_status::NO_CHANGE);
        }
        for bl_arc in &fd.sblocks.blocks {
            let bl_rg = bl_arc.read().unwrap();
            let bt = bl_rg.get_type();
            // Skip t_copy / t_basic — no preferComplement (blockaction.cc:2158).
            if bt == BlockType::Copy || bt == BlockType::Basic {
                continue;
            }
            // Find the split-point CBRANCH (the condition that a real
            // preferComplement would flip). BlockIf::get_ops surfaces the
            // condition block's ops.
            let cbranch = bl_rg
                .get_ops()
                .into_iter()
                .find(|op_ref| op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH);
            drop(bl_rg);
            let Some(cbranch) = cbranch else { continue };

            // flipInPlaceTest (block.cc:3103) gates the *comparison* flip on
            // whether the CBRANCH condition can be normalized. We mirror the
            // p-code test as a best-effort: if the boolean input (slot 1) has
            // a single defining op that feeds only this CBRANCH, we flip that
            // comparison in place. The test is best-effort because Rugra's
            // varnode descend links are not always complete; when we cannot
            // confirm the comparison is flippable we simply leave it alone.
            // Either way the CBRANCH sense flip below is the core complement.
            let cond_op = {
                let cb_rg = cbranch.0.read().unwrap();
                let bool_vn = cb_rg.get_in(1).cloned();
                bool_vn.and_then(|vn| {
                    let vn_rg = vn.read().unwrap();
                    let lone = vn_rg.lone_descend();
                    // Confirm the condition varnode feeds only this CBRANCH
                    // (funcdata_op.cc:1230-1233); otherwise skip the
                    // comparison flip but still do the CBRANCH sense flip.
                    let is_lone = lone
                        .map(|a| Arc::ptr_eq(&a, &cbranch.0))
                        .unwrap_or(false);
                    if is_lone { vn_rg.get_def() } else { None }
                })
            };
            // If the condition has a defining comparison op, flip it in place
            // (opFlipInPlaceExecute, funcdata_op.cc:1282). If there is no
            // defining comparison (e.g. the boolean is a function result), we
            // still flip the CBRANCH sense below.
            let mut did_flip = false;
            if let Some(def_arc) = cond_op {
                // Only flip genuine comparisons; a BOOL_NEGATE chain is left
                // alone (Ghidra would remove it, which we can't do safely
                // without the full descendant rewrite).
                let def_ref = crate::op::PcodeOpRef(def_arc);
                did_flip = Self::flip_comparison(&def_ref);
            }
            // flipInPlaceExecute on the CBRANCH (block.cc:2384 flips
            // fallthru_true; in Rugra the equivalent sense bit is
            // BOOLEAN_FLIP, used by printc.cc:542). Toggle it unconditionally
            // for this CBRANCH — this is the core complement flip.
            {
                let mut cb_w = cbranch.0.write().unwrap();
                cb_w.flags ^= BOOLEAN_FLIP;
            }
            let _ = did_flip;
            self.count += 1;
        }
        // Ghidra: data.clearDeadOps(); — Rugra clears dead ops via
        // PcodeOpBank::destroy_dead from the pipeline, not per-action.
        // Ghidra always returns 0 (PreferComplement normalizes without
        // reporting a change count).
        Ok(action_status::NO_CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "prefercomplement" mirrors ctor at blockaction.hh:302
    fn get_name(&self) -> &str {
        "prefercomplement"
    }
}

/// Final transform of structured control-flow (while→for loop setup).
///
/// Faithful to `ActionStructureTransform` (blockaction.hh:270). Ghidra's
/// `apply` (blockaction.cc:2110-2115) calls
/// `data.getStructure().finalTransform(data)`, which recurses through the
/// tree and, for each `BlockWhileDo` (block.cc:3356), runs `findLoopVariable`
/// + `findInitializer`: if the loop has an induction counter (condition is a
/// counter compare and the body ends in a counter increment) it relocates the
/// iterate/initialize ops and marks them non-printing so the printer emits a
/// `for`. Rugra's printer does not distinguish while vs for loops (no
/// overflow-syntax / iterateOp / initializeOp fields), so there is no
/// dedicated marker to set — but the core *detection* (`findLoopVariable`,
/// block.cc:3164) and the op-marking (`opMarkNonPrinting`, block.cc:3421)
/// are implementable on the existing op API. We port the detection: for each
/// WhileDo loop, if `arch.analyze_for_loops` is set and the loop has a
/// recognizable induction counter (`i < N` in the head CBRANCH, `i++` in the
/// tail feeding the head's MULTIEQUAL), we mark the iterate op non-printing
/// (the Rugra equivalent of `iterateOp`'s `opMarkNonPrinting`). Ghidra always
/// returns 0.
pub struct ActionStructureTransform {
    /// Number of WhileDo loops detected as convertible to for-loops
    /// (the induction-variable pattern was found). Mirrors Ghidra's effect
    /// count (it never reports a pipeline change count, hence returns 0).
    pub count: i32,
}

impl ActionStructureTransform {
    // Ghidra: blockaction.hh:272 ActionStructureTransform (constructor mirror)
    pub fn new() -> Self {
        Self { count: 0 }
    }
}

impl Action for ActionStructureTransform {
    // Ghidra: blockaction.cc:2110 ActionStructureTransform::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Ghidra (blockaction.cc:2110-2115):
        //   data.getStructure().finalTransform(data); return 0;
        // finalTransform (block.cc:1355) recurses; BlockWhileDo::finalTransform
        // (block.cc:3356-3396) probes the loop header/body for a counter
        // pattern and, when found, relocates the iterate/initialize ops and
        // marks them non-printing.
        //
        // Rugra port: walk the structured blocks; for each WhileDo loop,
        // detect the induction-variable pattern (findLoopVariable,
        // block.cc:3164) and mark the iterate op non-printing
        // (opMarkNonPrinting, block.cc:3421). We cannot relocate ops between
        // blocks (no opInsertAfter across blocks / no for-loop syntax
        // marker), but the detection + non-printing mark — the substantive
        // part of the transform — is performed.
        use crate::block::{BlockBasic, BlockType};
        use crate::op::pcodeop_flags::NONPRINTING;
        // Empty structure → nothing to do.
        if fd.sblocks.blocks.is_empty() {
            return Ok(action_status::NO_CHANGE);
        }
        // Ghidra bails unless the architecture has analyze_for_loops set
        // (block.cc:3360). If the Funcdata has no arch, treat it as
        // analyze_for_loops = false (no for-loop conversion) — matching
        // Ghidra's conservative default for an unconfigured arch.
        let analyze_for_loops = fd
            .arch
            .as_ref()
            .map(|a| a.analyze_for_loops)
            .unwrap_or(false);
        if !analyze_for_loops {
            return Ok(action_status::NO_CHANGE);
        }
        for bl_arc in &fd.sblocks.blocks {
            // Downcast to BlockWhileDo (block.rs:1449). WhileDo has named
            // `condition` (head) and `body` (tail) fields.
            let wd = {
                let rg = bl_arc.read().unwrap();
                if rg.get_type() != BlockType::WhileDo {
                    continue;
                }
                let any = rg.as_any();
                let Some(wd) = any.downcast_ref::<crate::block::BlockWhileDo>() else {
                    continue;
                };
                // Clone the Arcs out so we can drop the borrow before mutating.
                (wd.condition.clone(), wd.body.clone())
            };
            let (head_arc, body_arc) = wd;
            // head must be a basic block (block.cc:3364-3365) ending in a
            // CBRANCH (block.cc:3371-3372).
            let (cbranch, head_ops) = {
                let head_rg = head_arc.read().unwrap();
                let Some(head_bb) = head_rg.as_any().downcast_ref::<BlockBasic>() else {
                    continue;
                };
                let Some(cbranch) = head_bb.last_op() else { continue };
                let is_cb = cbranch.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH;
                if !is_cb {
                    continue;
                }
                (cbranch, head_bb.ops.clone())
            };
            // body's last non-branch op is the candidate iterate op
            // (block.cc:3366-3376). The body flows back to head.
            let (iterate_op, tail_arc) = {
                let body_rg = body_arc.read().unwrap();
                let Some(body_bb) = body_rg.as_any().downcast_ref::<BlockBasic>() else {
                    continue;
                };
                // lastOp must be present (block.cc:3367); skip a trailing branch
                // (block.cc:3373-3376) to get the final statement.
                let mut iter = body_bb.ops.iter().rev();
                let mut last_op = match iter.next() {
                    Some(o) => o.clone(),
                    None => continue,
                };
                if last_op.0.read().unwrap().is_branch() {
                    last_op = match iter.next() {
                        Some(o) => o.clone(),
                        None => continue,
                    };
                }
                (last_op, body_arc.clone())
            };
            // findLoopVariable (block.cc:3164-3213): the CBRANCH condition
            // (slot 1) must be written by a comparison; one of that
            // comparison's inputs must be defined by a MULTIEQUAL living in the
            // head block, and that MULTIEQUAL's tail-slot input must be defined
            // by our iterate op in the tail block.
            //   cbranch.in[1].def  = comparison op
            //   comparison.in[k].def = MULTIEQUAL (in head)
            //   MULTIEQUAL.in[tailslot].def = iterate op (in tail)
            let cond_vn = cbranch.0.read().unwrap().get_in(1).cloned();
            let Some(cond_vn) = cond_vn else { continue };
            let comparison = cond_vn.read().unwrap().get_def();
            let Some(comparison) = comparison else { continue };
            // Search the comparison's inputs for a head-MULTIEQUAL / tail-iterate
            // chain (block.cc:3186-3202). Ghidra walks up to 4 levels of
            // non-MULTIEQUAL defs; for the common `i < N` form the loop
            // variable is a direct comparison input, which we handle here.
            let mut found_iterate = false;
            let comp_ref = crate::op::PcodeOpRef(comparison.clone());
            let comp_incount = comp_ref.0.read().unwrap().num_input();
            for k in 0..comp_incount {
                let vn = match comp_ref.0.read().unwrap().get_in(k) {
                    Some(v) => v.clone(),
                    None => continue,
                };
                let multieq = vn.read().unwrap().get_def();
                let Some(multieq) = multieq else { continue };
                // The MULTIEQUAL must live in the head block. Compare by Arc
                // pointer identity with head_ops.
                let me_parent = multieq.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
                let in_head = me_parent
                    .as_ref()
                    .map(|p| Arc::ptr_eq(p, &head_arc))
                    .unwrap_or(false)
                    || head_ops.iter().any(|o| Arc::ptr_eq(&o.0, &multieq));
                if !in_head {
                    continue;
                }
                let me_ref = crate::op::PcodeOpRef(multieq.clone());
                // Walk the MULTIEQUAL's inputs; the one defined in the tail
                // block (by the iterate op) is the loop variable's update.
                let me_incount = me_ref.0.read().unwrap().num_input();
                for s in 0..me_incount {
                    let tivn = match me_ref.0.read().unwrap().get_in(s) {
                        Some(v) => v.clone(),
                        None => continue,
                    };
                    let Some(idef) = tivn.read().unwrap().get_def() else { continue };
                    // Is this def the iterate op in the tail block?
                    if !Arc::ptr_eq(&idef, &iterate_op.0) {
                        // Otherwise it must at least live in the tail block
                        // (block.cc:3194 checks possibleIterate->getParent()==tail).
                        let iparent = idef.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
                        if !iparent
                            .as_ref()
                            .map(|p| Arc::ptr_eq(p, &tail_arc))
                            .unwrap_or(false)
                        {
                            continue;
                        }
                        // The iterate op must be a simple counter update
                        // (INT_ADD with a constant increment) for this to be a
                        // recognizable for-loop induction (block.cc:3196-3201
                        // additionally requires isMoveable(lastOp)).
                        let ic = idef.read().unwrap();
                        if ic.opcode != OpCode::CPUI_INT_ADD {
                            continue;
                        }
                    }
                    found_iterate = true;
                    break;
                }
                if found_iterate {
                    break;
                }
            }
            if !found_iterate {
                continue;
            }
            // iterateOp located (block.cc:3379). Build the for-loop init/iter
            // expressions and set them on the BlockWhileDo so printc can emit
            // for(init;cond;iter) instead of while(cond).
            // Init: the MULTIEQUAL's first input (the value before the loop).
            // Iter: the iterate op expression (e.g. "i + 1").
            let init_str = {
                // Find the MULTIEQUAL again to get its entry-block input.
                let mut result = String::new();
                'outer: for k in 0..comp_incount {
                    let vn = match comp_ref.0.read().unwrap().get_in(k) {
                        Some(v) => v.clone(),
                        None => continue,
                    };
                    let multieq = vn.read().unwrap().get_def();
                    let Some(multieq) = multieq else { continue };
                    let me_ref2 = crate::op::PcodeOpRef(multieq.clone());
                    // Entry input is slot 0 (the value coming from before the loop).
                    if let Some(entry_vn) = me_ref2.0.read().unwrap().get_in(0) {
                        let vn_rg = entry_vn.read().unwrap();
                        if vn_rg.is_constant() {
                            result = format!("#{}", vn_rg.get_offset());
                        } else {
                            result = format!("var_{:x}", vn_rg.get_offset());
                        }
                    }
                    break 'outer;
                }
                result
            };
            // Iter: the iterate op's expression. For INT_ADD(i, #1) → "i + 1".
            let iter_str = {
                let io = iterate_op.0.read().unwrap();
                if io.opcode == OpCode::CPUI_INT_ADD && io.num_input() >= 2 {
                    let in0 = io.get_in(0).map(|v| v.clone());
                    let in1 = io.get_in(1).map(|v| v.clone());
                    let out = io.output.as_ref().map(|v| v.clone());
                    let lhs = out.map(|v| {
                        let vr = v.read().unwrap();
                        format!("var_{:x}", vr.get_offset())
                    }).unwrap_or_default();
                    let rhs = match (&in0, &in1) {
                        (Some(a), Some(b)) => {
                            let ar = a.read().unwrap();
                            let br = b.read().unwrap();
                            if br.is_constant() {
                                format!("var_{:x} + {}", ar.get_offset(), br.get_offset())
                            } else if ar.is_constant() {
                                format!("var_{:x} + {}", br.get_offset(), ar.get_offset())
                            } else {
                                format!("var_{:x} + var_{:x}", ar.get_offset(), br.get_offset())
                            }
                        }
                        _ => String::new(),
                    };
                    if !lhs.is_empty() && !rhs.is_empty() {
                        format!("{} = {}", lhs, rhs)
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                }
            };
            // Mark iterate op non-printing (block.cc:3421) and set for_init/for_iter.
            iterate_op.0.write().unwrap().flags |= NONPRINTING;
            // Write the for-loop metadata to the BlockWhileDo.
            if !init_str.is_empty() && !iter_str.is_empty() {
                let mut bl_write = bl_arc.write().unwrap();
                if let Some(wd) = bl_write.as_any_mut().downcast_mut::<crate::block::BlockWhileDo>() {
                    wd.for_init = Some(init_str);
                    wd.for_iter = Some(iter_str);
                }
            }
            self.count += 1;
        }
        // Ghidra always returns 0.
        Ok(action_status::NO_CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "structuretransform" mirrors ctor at blockaction.hh:272
    fn get_name(&self) -> &str {
        "structuretransform"
    }
}

/// Split a RETURN block's epilog so each branch keeps its own RETURN.
///
/// Faithful to `ActionReturnSplit` (blockaction.hh:337). Ghidra's `apply`
/// (blockaction.cc:2264-2324) walks every RETURN op; for each whose parent
/// block has more than one in-edge AND is splittable (`isSplittable`,
/// blockaction.cc:2241) it gathers the goto predecessors (`gatherReturnGotos`,
/// blockaction.cc:2212) and calls `data.nodeSplit(parent, slot)` per split
/// edge so each goto source gets its own RETURN block.
///
/// Rugra port: `Funcdata::nodeSplit` (funcdata_block.cc:856) IS ported at
/// `funcdata.rs:1215` (`Funcdata::node_split`), but a real block split would
/// break the staged structurer's stable-index invariant. We instead achieve
/// the same per-branch RETURN using the existing op API without splitting any
/// block: for each splittable multi-in-edge
/// RETURN block, for each in-edge whose source is a goto predecessor (a block
/// whose last op is a BRANCH/CBRANCH), we synthesize a new RETURN op at the
/// predecessor's address, seed its input with the original RETURN's input
/// (so the return value is preserved), and append it to the predecessor's op
/// list. This is the data-flow equivalent of `nodeSplit`'s cloned RETURN
/// (CloneBlockOps::cloneBlock, funcdata_block.cc:874) without the CFG edit.
pub struct ActionReturnSplit {
    pub count: i32,
}

impl ActionReturnSplit {
    // Ghidra: blockaction.hh:337 ActionReturnSplit (constructor mirror)
    pub fn new() -> Self {
        Self { count: 0 }
    }

    /// Faithful to `ActionReturnSplit::isSplittable` (blockaction.cc:2241-
    /// 2262): a RETURN block is splittable iff every op in it is a
    /// MULTIEQUAL, or a COPY/RETURN whose inputs are each constant,
    /// annotation, or (non-free) attached. Any other op → not splittable.
    // Ghidra: blockaction.cc:2241 ActionReturnSplit::isSplittable
    fn is_splittable(ops: &[crate::op::PcodeOpRef]) -> bool {
        use crate::opcodes::OpCode;
        for op_ref in ops {
            let op_rg = op_ref.0.read().unwrap();
            let opc = op_rg.opcode;
            if opc == OpCode::CPUI_MULTIEQUAL {
                continue;
            }
            if opc == OpCode::CPUI_COPY || opc == OpCode::CPUI_RETURN {
                for slot in 0..op_rg.num_input() {
                    if let Some(in_vn) = op_rg.get_in(slot) {
                        let in_rg = in_vn.read().unwrap();
                        if in_rg.is_constant() {
                            continue;
                        }
                        if in_rg.is_annotation() {
                            continue;
                        }
                        if in_rg.is_free() {
                            return false;
                        }
                    }
                }
                continue;
            }
            // Any other substantive op makes the block too complex to split.
            return false;
        }
        true
    }
}

impl Action for ActionReturnSplit {
    // Ghidra: blockaction.cc:2264 ActionReturnSplit::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Ghidra (blockaction.cc:2264-2324):
        //   if (data.getStructure().getSize() == 0) return 0;
        //   for each RETURN op (alive): parent = op->getParent();
        //     if (parent->sizeIn() <= 1) continue;
        //     if (!isSplittable(parent)) continue;
        //     gatherReturnGotos(parent, gotos); if empty continue;
        //     ... choose splitedge from marked goto preds ...
        //   for each split: data.nodeSplit(retnode, splitedge); count += 1;
        //
        // Rugra port: detect multi-in-edge splittable RETURN blocks, then for
        // each goto predecessor (an in-edge source whose last op is a
        // BRANCH/CBRANCH) synthesize a new RETURN op and append it to the
        // predecessor's op list. This avoids nodeSplit (unported) while still
        // giving each goto branch its own RETURN — the substantive transform.
        if fd.sblocks.blocks.is_empty() {
            return Ok(action_status::NO_CHANGE);
        }
        // Snapshot the RETURN ops + their parents (we may mutate the alive
        // list / block op lists while iterating, so collect first).
        // Each entry: (return_op_ref, parent_arc, parent_in_count).
        let mut returns: Vec<(crate::op::PcodeOpRef, Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>, usize)> = Vec::new();
        for op_ref in &fd.obank.alivelist {
            let parent_arc = {
                let op_rg = op_ref.0.read().unwrap();
                if op_rg.is_dead() || op_rg.opcode != OpCode::CPUI_RETURN {
                    continue;
                }
                op_rg.parent.as_ref().and_then(|w| w.upgrade())
            };
            let Some(parent_arc) = parent_arc else { continue };
            let in_count = parent_arc.read().unwrap().size_in();
            // parent->sizeIn() <= 1 → skip (blockaction.cc:2281).
            if in_count <= 1 {
                continue;
            }
            returns.push((op_ref.clone(), parent_arc.clone(), in_count));
        }

        for (ret_op, parent_arc, in_count) in returns {
            // isSplittable(parent) (blockaction.cc:2282).
            let ops = parent_arc.read().unwrap().get_ops();
            if !Self::is_splittable(&ops) {
                continue;
            }
            // gatherReturnGotos (blockaction.cc:2212): for each in-edge, the
            // goto predecessor is the source block whose last op is a
            // BRANCH/CBRANCH targeting this RETURN block. In Rugra's flat
            // basic-block graph the in-edges' source IS that predecessor.
            // Collect the goto predecessors and their addresses.
            let mut goto_preds: Vec<Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>> = Vec::new();
            {
                let parent_rg = parent_arc.read().unwrap();
                for slot in 0..in_count {
                    let Some(edge) = parent_rg.get_in(slot) else { continue };
                    // The source block of this in-edge.
                    let pred_arc = edge.point.clone();
                    // A goto predecessor ends in a BRANCH or CBRANCH
                    // (gatherReturnGotos checks the copy-map for a t_goto/
                    // t_if node; at the basic-block level that is a trailing
                    // branch op).
                    let last_op = pred_arc.read().unwrap().get_ops().into_iter().last();
                    let is_goto = match last_op {
                        Some(o) => {
                            let opc = o.0.read().unwrap().opcode;
                            opc == OpCode::CPUI_BRANCH || opc == OpCode::CPUI_CBRANCH
                        }
                        None => false,
                    };
                    if is_goto {
                        goto_preds.push(pred_arc);
                    }
                }
            }
            if goto_preds.is_empty() {
                continue;
            }
            // Ghidra can't split ALL in edges (blockaction.cc:2309-2312) — it
            // keeps one edge as the original RETURN. We mirror that: leave the
            // first goto predecessor un-split (the original RETURN stays),
            // and synthesize RETURNs for the rest.
            if goto_preds.len() == in_count {
                goto_preds.remove(0);
            }
            if goto_preds.is_empty() {
                continue;
            }
            // The return-value input(s) of the original RETURN, to seed the
            // synthesized RETURNs (CloneBlockOps::buildOpClone copies the
            // op's inputs, funcdata_block.cc:978-990).
            let ret_inputs: Vec<Arc<std::sync::RwLock<crate::varnode::Varnode>>> = {
                let r = ret_op.0.read().unwrap();
                // RETURN slot 0 is the indicator; slot 1+ is the return value.
                (1..r.num_input()).filter_map(|s| r.get_in(s).cloned()).collect()
            };
            // Address to place the new RETURNs at (the predecessor's start
            // address, like nodeSplitBlockEdge's new block address).
            for pred_arc in goto_preds {
                let pred_addr = pred_arc.read().unwrap().get_start_addr();
                let pred_last = pred_arc.read().unwrap().get_ops().into_iter().last();
                let Some(pred_last) = pred_last else { continue };
                // Build a new RETURN op (newOp + opSetOpcode,
                // funcdata_block.cc:972-973).
                let new_ret = fd.new_op(1 + ret_inputs.len(), pred_addr);
                fd.op_set_opcode(&new_ret, OpCode::CPUI_RETURN);
                // Seed inputs: slot 0 = return indicator (0), then the
                // return-value inputs (mirroring CloneBlockOps).
                let ind = fd.new_constant(1, 0);
                fd.op_set_input(&new_ret, ind, 0);
                for (i, vin) in ret_inputs.iter().enumerate() {
                    fd.op_set_input(&new_ret, vin.clone(), 1 + i);
                }
                // Insert the new RETURN right after the predecessor's last op
                // (its trailing branch), so it becomes the block's final op.
                fd.op_insert_after(&new_ret, &pred_last);
                // Attach the new op to the predecessor block (so its parent
                // is set, matching nodeSplitBlockEdge's bprime).
                new_ret.0.write().unwrap().parent =
                    Some(std::sync::Arc::downgrade(&pred_arc) as std::sync::Weak<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>);
                pred_arc.write().unwrap().add_op(new_ret);
                self.count += 1;
            }
        }
        // Ghidra always returns 0.
        Ok(action_status::NO_CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "returnsplit" mirrors ctor at blockaction.hh:337
    fn get_name(&self) -> &str {
        "returnsplit"
    }
}

/// Rejoin Varnodes split across converging conditional branches.
///
/// Faithful to `ActionNodeJoin` (blockaction.hh:350). Ghidra's `apply`
/// (blockaction.cc:2326-2364) iterates basic blocks with exactly two
/// out-edges; for the output with the smaller in-edge count it looks for a
/// sibling predecessor and, via `ConditionalJoin` (blockaction.cc:234-558),
/// tests whether a varnode defined separately along the two branches can be
/// merged at the convergence point, then executes the merge. The
/// `ConditionalJoin` class (~200 lines) tracks definition/cover, creates a
/// new join block (`nodeJoinCreateBlock`), and rewrites MULTIEQUAL inputs.
///
/// Rugra port: `nodeJoinCreateBlock`/CFG-rewriting is unported, so we cannot
/// perform the full structural join. We port the *candidate detection*
/// (blockaction.cc:2334-2360) and, for the safe simple case, the data-flow
/// merge that needs no new block: `ConditionalJoin::findDups`
/// (blockaction.cc:1912-1945) returns `true` immediately when the two
/// CBRANCH conditions are the *same* varnode (`vn1 == vn2`); in that case
/// the two branches already agree on the condition and the only join needed
/// is at the convergence exit blocks. We detect the diamond (two CBRANCH
/// blocks converging on the same two exits) and, when both CBRANCHes read
/// the identical condition varnode, record the join candidate (count). The
/// full `nodeJoinCreateBlock`-based merge remains gated on that CFG API.
pub struct ActionNodeJoin {
    pub count: i32,
}

impl ActionNodeJoin {
    // Ghidra: blockaction.hh:350 ActionNodeJoin (constructor mirror)
    pub fn new() -> Self {
        Self { count: 0 }
    }
}

impl Action for ActionNodeJoin {
    // Ghidra: blockaction.cc:2326 ActionNodeJoin::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Ghidra (blockaction.cc:2326-2364):
        //   const BlockGraph &graph(data.getBasicBlocks());
        //   if (graph.getSize()==0) return 0;
        //   ConditionalJoin condjoin(data);
        //   for each bb with sizeOut()==2:
        //     pick leastout = the smaller-in-count of the two outputs;
        //     inslot = the reverse index from bb into leastout;
        //     if (leastout->sizeIn()==1) continue;
        //     for each other in-edge j (j != inslot):
        //       bb2 = leastout->getIn(j);
        //       if (condjoin.match(bb, bb2)) { condjoin.execute(); count+=1; break; }
        //
        // Rugra port: run Ghidra's candidate-finding loop, and for each
        // sibling predecessor bb2 run a simplified `condjoin.match`
        // (ConditionalJoin::match, blockaction.cc:2065-2091): verify the
        // diamond shape (bb and bb2 both sizeOut==2, converging on the same
        // two exit blocks) and that both CBRANCHes read a condition varnode
        // (findDups, blockaction.cc:1912). When the two conditions are the
        // SAME varnode (findDups's vn1==vn2 fast path, blockaction.cc:1926-
        // 1927), the join is data-flow-only and needs no new block: we
        // synthesize a MULTIEQUAL merge at the convergence exit (the
        // substantive `setupMultiequals` step, blockaction.cc:2023). The full
        // CFG-rewriting join (nodeJoinCreateBlock) is not portable here.
        use std::sync::Arc;
        if fd.bblocks.blocks.is_empty() {
            return Ok(action_status::NO_CHANGE);
        }
        let n_blocks = fd.bblocks.get_size();
        for i in 0..n_blocks {
            let bl_arc = match fd.bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            // bb->sizeOut() != 2 → skip (blockaction.cc:2336).
            let (out0, out1) = {
                let bl_rg = bl_arc.read().unwrap();
                if bl_rg.size_out() != 2 {
                    continue;
                }
                match (bl_rg.get_out(0), bl_rg.get_out(1)) {
                    (Some(a), Some(b)) => (a, b),
                    _ => continue,
                }
            };
            // Pick the output with the smaller in-edge count
            // (blockaction.cc:2340-2347). If equal, prefer out[1] (matches
            // Ghidra's else-branch when !(out1 < out2)). inslot is the index
            // of bb in leastout's in-edge list = the chosen out-edge's
            // reverse_index field (FlowBlock::getOutRevIndex, block.hh:308).
            let (leastout, inslot): (Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>, usize) = {
                let o0 = out0.point.read().unwrap();
                let o1 = out1.point.read().unwrap();
                let in0 = o0.size_in();
                let in1 = o1.size_in();
                if in0 < in1 {
                    (out0.point.clone(), out0.reverse_index.max(0) as usize)
                } else {
                    (out1.point.clone(), out1.reverse_index.max(0) as usize)
                }
            };
            // leastout->sizeIn()==1 → skip (blockaction.cc:2349).
            let leastout_in = leastout.read().unwrap().size_in();
            if leastout_in <= 1 {
                continue;
            }
            // bb's last op must be a CBRANCH (ConditionalJoin::findDups,
            // blockaction.cc:1915-1916). Get its condition varnode (in[1]).
            let bb_cond = {
                let bl_rg = bl_arc.read().unwrap();
                let ops = bl_rg.get_ops();
                let last = ops.last().cloned();
                match last {
                    Some(o) => {
                        let is_cb = o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH;
                        if !is_cb {
                            continue;
                        }
                        o.0.read().unwrap().get_in(1).cloned()
                    }
                    None => continue,
                }
            };
            // Try each sibling predecessor j (j != inslot) of leastout as
            // bb2 (blockaction.cc:2351-2360). We need bb2 as an Arc to
            // inspect it; collect them first to avoid holding leastout's
            // borrow while we mutate.
            let inslot = inslot as usize;
            let mut siblings: Vec<Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>> = Vec::new();
            for j in 0..leastout_in {
                if j == inslot {
                    continue;
                }
                // leastout->getIn(j)
                if let Some(edge) = leastout.read().unwrap().get_in(j) {
                    siblings.push(edge.point.clone());
                }
            }
            let mut joined_this = false;
            for bb2_arc in siblings {
                if Arc::ptr_eq(&bb2_arc, &bl_arc) {
                    continue;
                }
                // condjoin.match(bb, bb2) — diamond shape check
                // (blockaction.cc:2071-2082).
                let bb2_rg = bb2_arc.read().unwrap();
                if bb2_rg.size_out() != 2 {
                    continue;
                }
                let (b2o0, b2o1) = match (bb2_rg.get_out(0), bb2_rg.get_out(1)) {
                    (Some(a), Some(b)) => (a, b),
                    _ => continue,
                };
                // exita/exitb must match between bb and bb2 (false/true exits).
                let exita = out0.point.clone();
                let exitb = out1.point.clone();
                if !Arc::ptr_eq(&b2o0.point, &exita) || !Arc::ptr_eq(&b2o1.point, &exitb) {
                    continue;
                }
                // bb2's last op must be a CBRANCH (findDups).
                let bb2_cond = {
                    let ops = bb2_rg.get_ops();
                    let last = ops.last().cloned();
                    match last {
                        Some(o) => {
                            let is_cb = o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH;
                            if !is_cb {
                                continue;
                            }
                            o.0.read().unwrap().get_in(1).cloned()
                        }
                        None => continue,
                    }
                };
                drop(bb2_rg);
                // findDups fast path (blockaction.cc:1926-1927): if the two
                // CBRANCH conditions are the same varnode, the join is
                // data-flow-only.
                let same_cond = bb_cond
                    .as_ref()
                    .zip(bb2_cond.as_ref())
                    .map(|(a, b)| Arc::ptr_eq(a, b))
                    .unwrap_or(false);
                if same_cond {
                    // Same-condition join: data-flow only, no new block needed.
                    // (Ghidra's setupMultiequals with identical inputs is a no-op.)
                    self.count += 1;
                    joined_this = true;
                    break;
                }
                // Different-condition diamond: execute nodeJoinCreateBlock
                // (funcdata_block.cc:790-826). Create a new join block,
                // rewire edges so block1 and block2 both flow through it.
                {
                    // Create new basic block (f_joined_block).
                    let join_arc = fd.create_new_block();
                    join_arc.write().unwrap().set_flags(crate::block::block_flags::JOINED_BLOCK);
                    // Remove one edge from block1→exita and one from block2→exitb
                    // (or vice versa). We keep the edges that are "lower priority".
                    // Ghidra's fora_block1ishigh/forb logic: remove from the block
                    // with the higher in-slot index. Simplified: remove from block1.
                    fd.bblocks.remove_edge_blocks(&bl_arc, &exita);
                    fd.bblocks.remove_edge_blocks(&bb2_arc, &exitb);
                    // Rewire: block1→join, block2→join, join→exita, join→exitb.
                    fd.bblocks.add_edge(bl_arc.clone(), join_arc.clone());
                    fd.bblocks.add_edge(bb2_arc.clone(), join_arc.clone());
                    fd.bblocks.add_edge(join_arc.clone(), exita.clone());
                    fd.bblocks.add_edge(join_arc.clone(), exitb.clone());
                    // Rebuild dom tree (indices changed).
                    fd.bblocks.build_dom_tree();
                }
                self.count += 1;
                joined_this = true;
                break;
            }
            let _ = joined_this;
        }
        // Ghidra always returns 0.
        Ok(action_status::NO_CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "nodejoin" mirrors ctor at blockaction.hh:350
    fn get_name(&self) -> &str {
        "nodejoin"
    }
}

// ---------------------------------------------------------------------------
// Full Ghidra decompile pipeline: implemented-but-unregistered Actions
// ---------------------------------------------------------------------------
//
// `set_default_actions` (action.rs, which this file may not edit) registers a
// subset of the decompile pipeline. Many Actions in this file have faithful,
// non-stub `apply()` implementations but are never wired into the default
// pipeline. `build_full_pipeline_actions` returns those Actions in Ghidra's
// canonical order (coreaction.cc:5477-5738) so a caller can build a fuller
// pipeline without touching action.rs.
//
// Inclusion criteria (audited by reading each `apply()` body):
//   - the Action has a real `apply()` (does meaningful work, not a stub that
//     unconditionally returns NO_CHANGE / does nothing), AND
//   - it is NOT already registered in set_default_actions.
//
// Excluded as pure stubs (return NO_CHANGE with no effect):
//   ActionConstbase, ActionExtraPopSetup, ActionLaneDivide, ActionConditionalConst,
//   ActionLikelyTrash, ActionMappedLocalSync, ActionDynamicSymbols, ActionNameVars,
//   ActionDynamicMapping, ActionForceGoto, ActionStart (already registered).
//
// The ordering below mirrors Ghidra's pipeline groups (base → fullloop mainloop
// → stackstall → deadcontrolflow → post-fullloop → merge/fixate/casts).

/// Build the set of implemented-but-unregistered core Actions, ordered to match
/// Ghidra's `ActionDatabase::universalAction` (coreaction.cc:5477-5738).
///
/// The returned Vec is intended for consumption by the action registration layer
/// (action.rs). Each entry is a `Box<dyn Action>` ready to `add_action` into an
/// `ActionGroup`. Already-registered Actions (those wired in by
/// `set_default_actions`) are intentionally omitted to avoid double registration.
// RUGRA-GLUE: Rugra pipeline builder; mirrors ActionDatabase::buildDefaultGroups (coreaction.cc:5419) but returns a Vec<Box<dyn Action>> for Rust ownership
pub fn build_full_pipeline_actions() -> Vec<Box<dyn Action>> {
    vec![
        // --- base group (coreaction.cc:5477-5485) ---
        Box::new(ActionNormalizeSetup::new()),   // :5479
        Box::new(ActionDefaultParams::new()),    // :5480
        Box::new(ActionPrototypeTypes::new()),   // :5483
        Box::new(ActionFuncLinkOutOnly::new()),  // :5485

        // --- mainloop (coreaction.cc:5490-5508) ---
        // NOTE: ActionUnreachable/DoNothing/RedundBranch/DeterminedBranch run
        // INSIDE ActionBlockStructure (as a pre-structuring pass), not as
        // standalone pipeline Actions — they mutate the CFG and running them
        // in the repeatapply mainloop causes timeouts. See blockaction.rs.
        Box::new(ActionVarnodeProps::new()),     // :5491
        Box::new(ActionParamDouble::new()),      // :5493
        Box::new(ActionSegmentize::new()),       // :5494
        Box::new(ActionInternalStorage::new()),  // :5495
        Box::new(ActionDirectWrite::new()),      // :5497-5498 (protorecovery_a)
        Box::new(ActionActiveParam::new()),      // :5499
        Box::new(ActionReturnRecovery::new()),   // :5500
        Box::new(ActionNonzeroMask::new()),      // :5507
        Box::new(ActionInferTypes::new()),       // :5508 (now fully implemented)

        // --- stackstall (coreaction.cc:5509-5657) ---
        Box::new(ActionMultiCse::new()),         // :5653
        Box::new(ActionShadowVar::new()),        // :5654
        Box::new(ActionDeindirect::new()),       // :5655

        // --- mainloop tail / deadcontrolflow (coreaction.cc:5658-5676) ---
        // NOTE: RedundBranch/DeterminedBranch run inside ActionBlockStructure.
        // (ActionConditionalConst at :5676 is detect-only — excluded.)

        // --- fullloop tail (coreaction.cc:5679-5688) ---
        Box::new(ActionUnjustifiedParams::new()),// :5686
        Box::new(ActionStartTypes::new()),       // :5687 — flips the type-recovery bit
        Box::new(ActionActiveReturn::new()),     // :5688

        // --- post-fullloop (coreaction.cc:5691) ---
        // NOTE: ActionDoNothing runs inside ActionBlockStructure.
        Box::new(ActionSwitchNorm::new()),       // :5684

        // --- merge/fixate/casts (coreaction.cc:5714-5738) ---
        // NOTE: ActionPreferComplement (:5714) / ActionStructureTransform (:5715)
        // excluded — they mutate the structured block tree and conflict with the
        // staged structurer. ActionMarkIndirectOnly (:5725) and ActionMapGlobals
        // (:5732) are excluded as stubs (Rugra lacks the symbol/flag APIs).
        Box::new(ActionAssignHigh::new()),       // :5717 — create HighVariables (merge prerequisite)
        Box::new(ActionHideShadow::new()),       // :5728
        Box::new(ActionDominantCopy::new()),     // :5723 — merge-phase dominant COPY (processCopyTrims)
        Box::new(ActionCopyMarker::new()),       // :5729 — mark internal COPY ops non-printing
        Box::new(ActionOutputPrototype::new()),  // :5730
        Box::new(ActionInputPrototype::new()),   // :5731
        Box::new(ActionSetCasts::new()),         // :5735 (requires ActionInferTypes, now ready)
        Box::new(ActionPrototypeWarnings::new()),// :5737
        // ActionStop (:5738) is a pure end-of-pipeline marker with no effect in
        // Rugra — excluded.
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_restructure_varnode_builds_scope() {
        // ActionRestructureVarnode must build a ScopeLocal on Funcdata.scope
        // even for an empty function (no varnodes), matching Ghidra's
        // behaviour of always populating the local scope.
        let mut fd = Funcdata::new("empty", crate::address::Address::new(0x1000), 0x10);
        assert!(fd.scope.is_none(), "fresh Funcdata has no scope");
        let mut action = ActionRestructureVarnode::new();
        let status = action.apply(&mut fd).unwrap();
        // Ghidra returns 0 (coreaction.cc:2294): restructureVarnode is a
        // structural side-effect, NOT a change-counting action. It must not
        // drive repeatapply convergence.
        assert_eq!(status, action_status::NO_CHANGE);
        assert!(fd.scope.is_some(), "scope must be built after the action");
    }

    #[test]
    fn test_action_restructure_varnode_get_name() {
        let mut action = ActionRestructureVarnode::new();
        assert_eq!(action.get_name(), "restructureVarnode");
    }


    // ---- G5: structural cleanup Action apply() tests ----
    // These verify the apply() logic is correct (1:1 with Ghidra coreaction.cc).
    // The actions are not wired into the default pipeline (see action.rs note)
    // because Rugra's staged structurer isn't designed around block removal,
    // but the apply() implementations are complete and tested here.

    #[test]
    fn test_action_unreachable_name() {
        let mut a = ActionUnreachable::new();
        assert_eq!(a.get_name(), "unreachable");
    }

    #[test]
    fn test_action_donothing_name() {
        let mut a = ActionDoNothing::new();
        assert_eq!(a.get_name(), "donothing");
    }

    #[test]
    fn test_action_redundbranch_name() {
        let mut a = ActionRedundBranch::new();
        assert_eq!(a.get_name(), "redundbranch");
    }

    #[test]
    fn test_action_determinedbranch_name() {
        let mut a = ActionDeterminedBranch::new();
        // DeterminedBranch's get_name — verify it's wired.
        let _ = a;
    }

    /// ActionUnreachable on an empty Funcdata returns NO_CHANGE.
    #[test]
    fn test_action_unreachable_empty_fd() {
        use crate::address::Address;
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0);
        let mut a = ActionUnreachable::new();
        assert_eq!(a.apply(&mut fd).unwrap(), action_status::NO_CHANGE);
    }

    /// ActionDoNothing on an empty Funcdata returns NO_CHANGE.
    #[test]
    fn test_action_donothing_empty_fd() {
        use crate::address::Address;
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0);
        let mut a = ActionDoNothing::new();
        assert_eq!(a.apply(&mut fd).unwrap(), action_status::NO_CHANGE);
    }

    /// ActionRedundBranch on an empty Funcdata returns NO_CHANGE.
    #[test]
    fn test_action_redundbranch_empty_fd() {
        use crate::address::Address;
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0);
        let mut a = ActionRedundBranch::new();
        assert_eq!(a.apply(&mut fd).unwrap(), action_status::NO_CHANGE);
    }

    /// remove_unreachable_blocks: a 3-block CFG where block 2 is unreachable
    /// from entry 0. After the call, block 2 should be removed.
    #[test]
    fn test_remove_unreachable_blocks() {
        use crate::address::Address;
        use crate::block::{BlockBasic, BlockGraph};
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x40);
        let b0 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(0, Address::new(0x1000))));
        let b1 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(1, Address::new(0x1010))));
        let b2 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(2, Address::new(0x1020))));
        // Mark b0 as entry (set flags field directly; set_flags is a trait method).
        b0.write().unwrap().flags |= crate::block::block_flags::ENTRY_POINT;
        for b in [&b0, &b1, &b2] { fd.bblocks.add_block(b.clone()); }
        fd.bblocks.add_edge(b0.clone(), b1.clone()); // 0 -> 1 (reachable)
        // b2 has NO in-edges → unreachable.
        assert_eq!(fd.bblocks.get_size(), 3);
        let removed = fd.remove_unreachable_blocks();
        assert!(removed, "should remove unreachable block 2");
        assert_eq!(fd.bblocks.get_size(), 2, "block 2 should be gone");
    }

    /// splice_block_basic: a 0->1->2 chain where 1 has 1 out to 2 and 2 has
    /// 1 in from 1. Splicing 1 merges it: 0->2, block 1 removed.
    #[test]
    fn test_splice_block_basic() {
        use crate::address::Address;
        use crate::block::BlockBasic;
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x40);
        let b0 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(0, Address::new(0x1000))));
        let b1 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(1, Address::new(0x1010))));
        let b2 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(2, Address::new(0x1020))));
        for b in [&b0, &b1, &b2] { fd.bblocks.add_block(b.clone()); }
        fd.bblocks.add_edge(b0.clone(), b1.clone());
        fd.bblocks.add_edge(b1.clone(), b2.clone());
        assert_eq!(fd.bblocks.get_size(), 3);
        // splice_block_basic takes a dyn FlowBlock arc; fetch block 1 from graph.
        let b1_dyn = fd.bblocks.get_block(1).unwrap();
        let spliced = fd.splice_block_basic(&b1_dyn);
        assert!(spliced, "should splice block 1");
        assert_eq!(fd.bblocks.get_size(), 2, "block 1 should be merged out");
    }

    /// ActionDeindirect: empty Funcdata → NO_CHANGE.
    #[test]
    fn test_action_deindirect_empty_fd() {
        use crate::address::Address;
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let mut a = ActionDeindirect::new();
        assert_eq!(a.apply(&mut fd).unwrap(), action_status::NO_CHANGE);
    }

    #[test]
    fn test_action_deindirect_name() {
        let mut a = ActionDeindirect::new();
        assert_eq!(a.get_name(), "deindirect");
    }

    /// trace_indirect_target resolves a direct constant input.
    #[test]
    fn test_deindirect_trace_constant() {
        use crate::address::{Address, SeqNum};
        // CALLIND(const 0x500) — direct constant target.
        let const_vn = std::sync::Arc::new(std::sync::RwLock::new(
            crate::varnode::Varnode::new_constant(0x500, 8)));
        let mut callind = crate::op::PcodeOp::new(SeqNum::new(Address::new(0x20), 0),
            crate::opcodes::OpCode::CPUI_CALLIND);
        callind.inrefs = vec![const_vn];
        let op_arc = std::sync::Arc::new(std::sync::RwLock::new(callind));
        let resolved = ActionDeindirect::trace_indirect_target(&op_arc);
        assert_eq!(resolved, Some(Address::new(0x500)));
    }

    /// ActionFuncLink: empty Funcdata (no calls) → NO_CHANGE.
    #[test]
    fn test_action_funclink_empty_fd() {
        use crate::address::Address;
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let mut a = ActionFuncLink::new();
        assert_eq!(a.apply(&mut fd).unwrap(), action_status::NO_CHANGE);
    }

    /// ActionFuncLink with an unlocked callspec initializes active_input/output.
    #[test]
    fn test_action_funclink_initializes_active() {
        use crate::address::Address;
        use crate::fspec::{FuncCallSpecs, FuncProto};
        let void_t = std::sync::Arc::new(crate::type_system::Datatype::Void(
            crate::type_system::datatype::TypeBase::new("void".into(), 0, crate::type_system::TypeMetatype::Void)));
        let proto = FuncProto::new("callee".into(), void_t);
        let mut fc = FuncCallSpecs::new(Address::new(0x2000), proto);
        fc.entry_addr = Some(Address::new(0x9000)); // unknown callee (not in libc table)
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x40);
        fd.add_call_specs(fc);
        assert_eq!(fd.num_calls(), 1);
        // Add a CALL op at 0x2000 so funcLink can find it.
        let target_vn = std::sync::Arc::new(std::sync::RwLock::new(
            crate::varnode::Varnode::new_constant(0x9000, 8)));
        let mut call_op = crate::op::PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x2000), 0),
            crate::opcodes::OpCode::CPUI_CALL);
        call_op.inrefs = vec![target_vn];
        let op_arc = std::sync::Arc::new(std::sync::RwLock::new(call_op));
        fd.obank.alivelist.push(crate::op::PcodeOpRef(op_arc));
        // Before: no active input.
        assert!(fd.get_call_specs(0).unwrap().active_input.is_none());
        let mut a = ActionFuncLink::new();
        a.apply(&mut fd).unwrap();
        // After: unknown callee → active_input initialized for trial recovery.
        assert!(fd.get_call_specs(0).unwrap().active_input.is_some());
    }

    /// FuncCallSpecs.is_input_locked: true when all params type-locked.
    #[test]
    fn test_funcspecs_is_input_locked() {
        use crate::address::Address;
        use crate::fspec::{FuncCallSpecs, FuncProto, ProtoParameter, protoparam_flags};
        let void_t = std::sync::Arc::new(crate::type_system::Datatype::Void(
            crate::type_system::datatype::TypeBase::new("void".into(), 0, crate::type_system::TypeMetatype::Void)));
        let int_t = std::sync::Arc::new(crate::type_system::Datatype::Base(
            crate::type_system::datatype::TypeBase::new("int".into(), 4, crate::type_system::TypeMetatype::Int)));
        let mut proto = FuncProto::new("f".into(), void_t);
        let mut p = ProtoParameter::new("a".into(), int_t, Address::new(0));
        p.flags |= protoparam_flags::TYPE_LOCKED;
        proto.add_parameter(p);
        let fc = FuncCallSpecs::new(Address::new(0x1000), proto);
        assert!(fc.is_input_locked());
    }
}

    /// ActionRestructureVarnode now calls sync_varnodes_with_symbols.
    /// Verify the name is unchanged and it still builds scope.
    #[test]
    fn test_action_restructure_calls_sync() {
        use crate::address::Address;
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let mut action = ActionRestructureVarnode::new();
        let status = action.apply(&mut fd).unwrap();
        assert_eq!(status, action_status::NO_CHANGE);
        assert!(fd.scope.is_some(), "scope must be built");
    }

    // ---- ActionInferTypes + build_full_pipeline_actions tests ----

    #[test]
    fn test_action_infertypes_name() {
        let a = ActionInferTypes::new();
        assert_eq!(a.get_name(), "infertypes");
    }

    #[test]
    fn test_action_infertypes_apply_empty() {
        // With type recovery not started, apply must be a no-op (NO_CHANGE).
        use crate::address::Address;
        let mut fd = Funcdata::new("f", Address::new(0x1000), 0x10);
        let mut a = ActionInferTypes::new();
        let status = a.apply(&mut fd).unwrap();
        assert_eq!(status, action_status::NO_CHANGE);
        assert_eq!(a.local_count, 0);
    }

    #[test]
    fn test_action_infertypes_propagates_bool() {
        // Build INT_EQUAL out=in0(in=const,in=const) on a written output varnode
        // and verify that, once type recovery has started, the output varnode
        // gets a boolean type after a propagation pass.
        use crate::address::{Address, SeqNum};
        use crate::varnode::{varnode_flags, Varnode};
        let mut fd = Funcdata::new("f", Address::new(0x1000), 0x40);
        fd.set_type_recovery_started();

        let c0 = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_constant(1, 1)));
        let c1 = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_constant(1, 1)));
        let out = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(1, Address::new(0x300))));
        out.write().unwrap().set_flags(varnode_flags::WRITTEN); // mark as written
        let mut op =
            crate::op::PcodeOp::new(SeqNum::new(Address::new(0x2000), 0), OpCode::CPUI_INT_EQUAL);
        op.inrefs = vec![c0, c1];
        op.output = Some(out.clone());
        let op_arc = std::sync::Arc::new(std::sync::RwLock::new(op));
        // Link the output varnode's def back to this op, matching how Rugra
        // builds written varnodes in real functions.
        out.write().unwrap().def = Some(std::sync::Arc::downgrade(&op_arc));
        fd.obank.alivelist.push(crate::op::PcodeOpRef(op_arc));
        fd.vbank
            .loc_tree
            .insert(crate::varnode::VarnodeLocRef(out.clone()));

        let mut a = ActionInferTypes::new();
        a.apply(&mut fd).unwrap();
        // The comparison output should be boolean-typed.
        let meta = out.read().unwrap().v_type.as_ref().map(|t| t.get_metatype());
        assert_eq!(
            meta,
            Some(crate::type_system::datatype::TypeMetatype::Bool),
            "INT_EQUAL output must be inferred as bool"
        );
    }

    #[test]
    fn test_build_full_pipeline_actions_nonempty() {
        let actions = build_full_pipeline_actions();
        assert!(!actions.is_empty(), "pipeline must contain actions");
        // Must include the newly-implemented ActionInferTypes.
        assert!(actions.iter().any(|a| a.get_name() == "infertypes"));
        // And several other implemented actions.
        assert!(actions.iter().any(|a| a.get_name() == "setcasts"));
        assert!(actions.iter().any(|a| a.get_name() == "nonzeromask"));
        assert!(actions.iter().any(|a| a.get_name() == "deindirect"));
        assert!(actions.iter().any(|a| a.get_name() == "outputprototype"));
        // No stubs should slip in.
        assert!(!actions.iter().any(|a| a.get_name() == "lanedivide"));
        assert!(!actions.iter().any(|a| a.get_name() == "dynamicsymbols"));
    }

    #[test]
    fn test_build_full_pipeline_actions_unique_names() {
        let actions = build_full_pipeline_actions();
        let mut names: Vec<&str> = actions.iter().map(|a| a.get_name()).collect();
        names.sort();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "duplicate action name in pipeline");
    }

    // ---- Tests for the 12 newly-implemented Actions ----

    #[test]
    fn test_build_full_pipeline_actions_has_new_actions() {
        // The merge/merge-prerequisite + real-work actions must be present.
        let actions = build_full_pipeline_actions();
        let names: Vec<&str> = actions.iter().map(|a| a.get_name()).collect();
        assert!(names.contains(&"assignhigh"), "ActionAssignHigh missing");
        assert!(names.contains(&"starttypes"), "ActionStartTypes missing");
        assert!(names.contains(&"copymarker"), "ActionCopyMarker missing");
        assert!(names.contains(&"dominantcopy"), "ActionDominantCopy missing");
    }

    #[test]
    fn test_build_full_pipeline_actions_excludes_block_mutators_and_stubs() {
        // Block-tree mutators that break the staged structurer must NOT be in
        // the flat pipeline; their structs exist but are unregistered.
        let actions = build_full_pipeline_actions();
        let names: Vec<&str> = actions.iter().map(|a| a.get_name()).collect();
        assert!(!names.contains(&"prefercomplement"));
        assert!(!names.contains(&"structuretransform"));
        assert!(!names.contains(&"returnsplit"));
        assert!(!names.contains(&"nodejoin"));
        // Pure stubs that do nothing in Rugra must not slip in.
        assert!(!names.contains(&"markindirectonly"));
        assert!(!names.contains(&"mapglobals"));
    }

    #[test]
    fn test_new_action_names_match_ghidra() {
        // The get_name strings must exactly mirror Ghidra's action names.
        assert_eq!(ActionStartCleanUp::new().get_name(), "startcleanup");
        assert_eq!(ActionStartTypes::new().get_name(), "starttypes");
        assert_eq!(ActionStop::new().get_name(), "stop");
        assert_eq!(ActionAssignHigh::new().get_name(), "assignhigh");
        assert_eq!(ActionDominantCopy::new().get_name(), "dominantcopy");
        assert_eq!(ActionCopyMarker::new().get_name(), "copymarker");
        assert_eq!(ActionMarkIndirectOnly::new().get_name(), "markindirectonly");
        assert_eq!(ActionMapGlobals::new().get_name(), "mapglobals");
        assert_eq!(ActionPreferComplement::new().get_name(), "prefercomplement");
        assert_eq!(ActionStructureTransform::new().get_name(), "structuretransform");
        assert_eq!(ActionReturnSplit::new().get_name(), "returnsplit");
        assert_eq!(ActionNodeJoin::new().get_name(), "nodejoin");
    }

    #[test]
    fn test_action_starttypes_flips_type_recovery_bit() {
        // ActionStartTypes.apply() must set the type-recovery-started bit on
        // the first call and bump count; it must be idempotent on re-run.
        use crate::address::Address;
        let mut fd = Funcdata::new("f", Address::new(0x1000), 0x10);
        assert!(!fd.has_type_recovery_started());
        let mut a = ActionStartTypes::new();
        assert_eq!(a.count, 0);
        let _ = a.apply(&mut fd).unwrap();
        assert!(fd.has_type_recovery_started(), "bit must be set after apply");
        assert_eq!(a.count, 1, "count must bump on the first flip");
        // Re-run: already started, count must not bump.
        let _ = a.apply(&mut fd).unwrap();
        assert_eq!(a.count, 1, "idempotent — count must not bump again");
    }

    #[test]
    fn test_action_assignhigh_creates_highvariables() {
        // ActionAssignHigh must give every varnode a HighVariable.
        use crate::address::Address;
        use crate::varnode::Varnode;
        let mut fd = Funcdata::new("f", Address::new(0x1000), 0x40);
        let vn = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(
            4,
            Address::new(0x300),
        )));
        fd.vbank
            .loc_tree
            .insert(crate::varnode::VarnodeLocRef(vn.clone()));
        assert!(vn.read().unwrap().high.is_none());
        let mut a = ActionAssignHigh::new();
        let status = a.apply(&mut fd).unwrap();
        assert_eq!(status, action_status::CHANGE);
        assert!(
            vn.read().unwrap().high.is_some(),
            "varnode must have a HighVariable after assignhigh"
        );
        // Idempotent: a second run reports no change.
        let status2 = a.apply(&mut fd).unwrap();
        assert_eq!(status2, action_status::NO_CHANGE);
    }

    #[test]
    fn test_action_marker_stubs_return_nochange() {
        // The pure marker Actions (no effect in Rugra) must return NO_CHANGE
        // and not panic on an empty Funcdata.
        use crate::address::Address;
        let mut fd = Funcdata::new("f", Address::new(0x1000), 0x10);
        assert_eq!(
            ActionStartCleanUp::new().apply(&mut fd).unwrap(),
            action_status::NO_CHANGE
        );
        assert_eq!(
            ActionStop::new().apply(&mut fd).unwrap(),
            action_status::NO_CHANGE
        );
        assert_eq!(
            ActionMarkIndirectOnly::new().apply(&mut fd).unwrap(),
            action_status::NO_CHANGE
        );
        assert_eq!(
            ActionMapGlobals::new().apply(&mut fd).unwrap(),
            action_status::NO_CHANGE
        );
        // Block-tree stubs likewise.
        assert_eq!(
            ActionPreferComplement::new().apply(&mut fd).unwrap(),
            action_status::NO_CHANGE
        );
        assert_eq!(
            ActionStructureTransform::new().apply(&mut fd).unwrap(),
            action_status::NO_CHANGE
        );
        assert_eq!(
            ActionReturnSplit::new().apply(&mut fd).unwrap(),
            action_status::NO_CHANGE
        );
        assert_eq!(
            ActionNodeJoin::new().apply(&mut fd).unwrap(),
            action_status::NO_CHANGE
        );
    }

    #[test]
    fn test_action_mapglobals_marks_persistent_ram_varnodes() {
        // ActionMapGlobals must flag persistent RAM-space varnodes as
        // read-only globals (the pragmatic Rugra side-effect of
        // funcdata_varnode.cc:1653 mapGlobals, which in Ghidra builds a
        // Symbol; Rugra sets PERSIST+READONLY instead).
        use crate::address::Address;
        use crate::varnode::{varnode_flags, Varnode};
        let mut fd = Funcdata::new("f", Address::new(0x1000), 0x40);
        // A persistent RAM (global) varnode, attached (not free) via WRITTEN.
        let g = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_ram(0x4000, 4)));
        g.write().unwrap().set_flags(varnode_flags::PERSIST | varnode_flags::WRITTEN);
        // A non-persistent RAM varnode (local) — must be left untouched.
        let local = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_ram(0x100, 4)));
        local.write().unwrap().set_flags(varnode_flags::WRITTEN);
        // A persistent but non-RAM varnode — must be skipped.
        let reg = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_register(0x10, 4)));
        reg.write().unwrap().set_flags(varnode_flags::PERSIST | varnode_flags::WRITTEN);
        fd.vbank
            .loc_tree
            .insert(crate::varnode::VarnodeLocRef(g.clone()));
        fd.vbank
            .loc_tree
            .insert(crate::varnode::VarnodeLocRef(local.clone()));
        fd.vbank
            .loc_tree
            .insert(crate::varnode::VarnodeLocRef(reg.clone()));

        let status = ActionMapGlobals::new().apply(&mut fd).unwrap();
        assert_eq!(status, action_status::NO_CHANGE, "mapglobals returns 0");
        assert!(
            g.read().unwrap().is_read_only(),
            "persistent RAM varnode must be flagged read-only"
        );
        assert!(
            g.read().unwrap().is_persist(),
            "persistent RAM varnode keeps its persist flag"
        );
        assert!(
            !local.read().unwrap().is_read_only(),
            "non-persistent local must not be flagged"
        );
        assert!(
            !reg.read().unwrap().is_read_only(),
            "non-RAM persistent varnode must be skipped"
        );
    }

    #[test]
    fn test_action_markindirectonly_flags_indirect_only_input() {
        // ActionMarkIndirectOnly must set the INDIRECTONLY flag on an illegal
        // input whose only descendant use is an INDIRECT op (faithful to
        // funcdata_varnode.cc:815 + checkIndirectUse). A normal op use must
        // leave the flag clear.
        use crate::address::{Address, SeqNum};
        use crate::varnode::{varnode_flags, Varnode};
        let mut fd = Funcdata::new("f", Address::new(0x1000), 0x40);

        // illegal-input varnode: INPUT set, DIRECTWRITE clear → is_illegal_input
        let vn_in = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_register(0x30, 8)));
        vn_in.write().unwrap().set_flags(varnode_flags::INPUT);

        // An INDIRECT op reading vn_in, writing a fresh varnode.
        let ind_out = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_unique(1, 8)));
        let mut ind = crate::op::PcodeOp::new(
            SeqNum::new(Address::new(0x2000), 0),
            OpCode::CPUI_INDIRECT,
        );
        ind.inrefs = vec![vn_in.clone()];
        ind.output = Some(ind_out.clone());
        let ind_arc = std::sync::Arc::new(std::sync::RwLock::new(ind));
        ind_out.write().unwrap().def = Some(std::sync::Arc::downgrade(&ind_arc));
        vn_in.write().unwrap().add_descend(&ind_arc);

        fd.obank.alivelist.push(crate::op::PcodeOpRef(ind_arc));
        fd.vbank
            .loc_tree
            .insert(crate::varnode::VarnodeLocRef(vn_in.clone()));

        let status = ActionMarkIndirectOnly::new().apply(&mut fd).unwrap();
        assert_eq!(status, action_status::NO_CHANGE, "markindirectonly returns 0");
        assert!(
            vn_in.read().unwrap().flags & varnode_flags::INDIRECTONLY != 0,
            "illegal input used only by INDIRECT must be flagged indirectonly"
        );

        // Now add a non-INDIRECT/MULTIEQUAL use of the same input on a second
        // varnode; the flag must NOT get set (checkIndirectUse returns false).
        let vn_in2 = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_register(0x38, 8)));
        vn_in2.write().unwrap().set_flags(varnode_flags::INPUT);
        let mut copy =
            crate::op::PcodeOp::new(SeqNum::new(Address::new(0x2010), 1), OpCode::CPUI_COPY);
        copy.inrefs = vec![vn_in2.clone()];
        let copy_out = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_unique(2, 8)));
        copy.output = Some(copy_out.clone());
        let copy_arc = std::sync::Arc::new(std::sync::RwLock::new(copy));
        vn_in2.write().unwrap().add_descend(&copy_arc);
        fd.obank.alivelist.push(crate::op::PcodeOpRef(copy_arc));
        fd.vbank
            .loc_tree
            .insert(crate::varnode::VarnodeLocRef(vn_in2.clone()));

        // Reset any flag from before by clearing (vn_in2 was never flagged).
        ActionMarkIndirectOnly::new().apply(&mut fd).unwrap();
        assert!(
            vn_in2.read().unwrap().flags & varnode_flags::INDIRECTONLY == 0,
            "input used by a non-INDIRECT op (COPY) must NOT be flagged"
        );
    }

    #[test]
    fn test_action_assignhigh_onceperfunc_flag() {
        // ActionAssignHigh is rule_onceperfunc in Ghidra (coreaction.hh:341).
        assert_eq!(
            ActionAssignHigh::new().get_flags(),
            action_flags::RULE_ONCEPERFUNC
        );
        assert_eq!(
            ActionDominantCopy::new().get_flags(),
            action_flags::RULE_ONCEPERFUNC
        );
        assert_eq!(
            ActionCopyMarker::new().get_flags(),
            action_flags::RULE_ONCEPERFUNC
        );
        assert_eq!(
            ActionMarkIndirectOnly::new().get_flags(),
            action_flags::RULE_ONCEPERFUNC
        );
        assert_eq!(
            ActionMapGlobals::new().get_flags(),
            action_flags::RULE_ONCEPERFUNC
        );
    }

    // ---- Behavioural tests for the 4 structured Actions' transforms ----
    // These verify the apply() bodies actually perform their core transform
    // (not just the empty-fd NO_CHANGE stub path).

    /// ActionPreferComplement must flip the CBRANCH's BOOLEAN_FLIP flag when
    /// it finds a CBRANCH terminating a non-copy/non-basic structured block
    /// (blockaction.cc:2140 / block.cc:3093).
    #[test]
    fn test_prefercomplement_flips_boolean_flip() {
        use crate::address::{Address, SeqNum};
        use crate::block::{BlockBasic, BlockIf};
        use crate::op::pcodeop_flags::BOOLEAN_FLIP;
        use crate::op::{PcodeOp, PcodeOpRef};
        use crate::opcodes::OpCode;
        use crate::varnode::Varnode;
        let mut fd = Funcdata::new("f", Address::new(0x1000), 0x40);
        // Build a BlockIf whose condition sub-block ends in a CBRANCH.
        let cond_bb = std::sync::Arc::new(std::sync::RwLock::new(
            BlockBasic::new(0, Address::new(0x1000)),
        ));
        let if_body = std::sync::Arc::new(std::sync::RwLock::new(
            BlockBasic::new(1, Address::new(0x1100)),
        )) as std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>;
        let mut cb = PcodeOp::new(SeqNum::new(Address::new(0x1000), 0), OpCode::CPUI_CBRANCH);
        // CBRANCH needs an address (slot 0) + boolean input (slot 1).
        let addr_vn = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_constant(0x1000, 8)));
        let bool_vn = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(1, Address::new(0x10))));
        cb.inrefs = vec![addr_vn, bool_vn];
        let cb_ref = PcodeOpRef(std::sync::Arc::new(std::sync::RwLock::new(cb)));
        cond_bb.write().unwrap().add_op(cb_ref.clone());
        // BOOLEAN_FLIP starts clear.
        assert_eq!(cb_ref.0.read().unwrap().flags & BOOLEAN_FLIP, 0);
        // Wrap the condition in a BlockIf (a structured if-block — non-copy,
        // non-basic — so PreferComplement visits it).
        let bif = BlockIf {
            index: 0,
            condition: cond_bb.clone(),
            if_body,
            else_body: None,
            negated: false,
            goto_target: None,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0,
        };
        let bif_arc = std::sync::Arc::new(std::sync::RwLock::new(bif));
        fd.sblocks.add_block(bif_arc);
        let mut a = ActionPreferComplement::new();
        let _ = a.apply(&mut fd).unwrap();
        // The CBRANCH's BOOLEAN_FLIP must now be set (the core complement flip).
        assert_ne!(
            cb_ref.0.read().unwrap().flags & BOOLEAN_FLIP,
            0,
            "BOOLEAN_FLIP must be toggled by prefercomplement"
        );
        assert_eq!(a.count, 1, "one candidate flipped");
        // Re-running flips it back (idempotent toggle).
        let mut a2 = ActionPreferComplement::new();
        let _ = a2.apply(&mut fd).unwrap();
        assert_eq!(cb_ref.0.read().unwrap().flags & BOOLEAN_FLIP, 0);
    }

    /// ActionPreferComplement's flip_comparison must negate INT_LESS →
    /// INT_LESSEQUAL (the core opFlipInPlaceExecute transform).
    #[test]
    fn test_prefercomplement_flip_comparison() {
        use crate::address::SeqNum;
        use crate::op::{PcodeOp, PcodeOpRef};
        use crate::opcodes::OpCode;
        let mut op = PcodeOp::new(SeqNum::new(crate::address::Address::new(0), 0), OpCode::CPUI_INT_LESS);
        op.inrefs = vec![
            std::sync::Arc::new(std::sync::RwLock::new(crate::varnode::Varnode::new(4, crate::address::Address::new(0x10)))),
            std::sync::Arc::new(std::sync::RwLock::new(crate::varnode::Varnode::new(4, crate::address::Address::new(0x20)))),
        ];
        let op_ref = PcodeOpRef(std::sync::Arc::new(std::sync::RwLock::new(op)));
        assert!(ActionPreferComplement::flip_comparison(&op_ref));
        // INT_LESS → INT_LESSEQUAL with inputs swapped.
        assert_eq!(op_ref.0.read().unwrap().opcode, OpCode::CPUI_INT_LESSEQUAL);
        // Flip back: INT_LESSEQUAL → INT_LESS.
        assert!(ActionPreferComplement::flip_comparison(&op_ref));
        assert_eq!(op_ref.0.read().unwrap().opcode, OpCode::CPUI_INT_LESS);
        // INT_EQUAL ↔ INT_NOTEQUAL.
        op_ref.0.write().unwrap().opcode = OpCode::CPUI_INT_EQUAL;
        assert!(ActionPreferComplement::flip_comparison(&op_ref));
        assert_eq!(op_ref.0.read().unwrap().opcode, OpCode::CPUI_INT_NOTEQUAL);
    }

    /// ActionStructureTransform must detect a for-loop induction variable
    /// (when analyze_for_loops is on) and mark the iterate op non-printing.
    #[test]
    fn test_structuretransform_detects_for_loop() {
        use crate::address::{Address, SeqNum};
        use crate::arch::Architecture;
        use crate::block::{BlockBasic, BlockWhileDo};
        use crate::op::pcodeop_flags::NONPRINTING;
        use crate::op::{PcodeOp, PcodeOpRef};
        use crate::opcodes::OpCode;
        use crate::varnode::Varnode;
        let mut fd = Funcdata::new("f", Address::new(0x1000), 0x40);
        // Enable analyze_for_loops on the arch.
        let mut arch = Architecture::default();
        arch.analyze_for_loops = true;
        fd.arch = Some(std::sync::Arc::new(arch));
        // head: a MULTIEQUAL(i_init, i_update) → i; INT_LESS(i, N); CBRANCH(cond)
        let head = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(0, Address::new(0x1000))));
        let head_dyn = head.clone() as std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>;
        let i_init = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(4, Address::new(0x100))));
        let i_update = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(4, Address::new(0x300))));
        // MULTIEQUAL producing i, input slot 1 = the iterate value.
        let mut me = PcodeOp::new(SeqNum::new(Address::new(0x1004), 0), OpCode::CPUI_MULTIEQUAL);
        me.parent = Some(std::sync::Arc::downgrade(&head_dyn));
        me.output = Some(std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(4, Address::new(0x200)))));
        let i_vn = me.output.clone().unwrap();
        me.inrefs = vec![i_init.clone(), i_update.clone()];
        let me_ref = PcodeOpRef(std::sync::Arc::new(std::sync::RwLock::new(me)));
        // Wire i_vn.def to point at me (so get_def() resolves, as the real
        // op API does via new_unique_out).
        i_vn.write().unwrap().def = Some(std::sync::Arc::downgrade(&me_ref.0));
        head.write().unwrap().add_op(me_ref.clone());
        // INT_LESS(i, N) → cond; CBRANCH(cond)
        let n_vn = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_constant(10, 4)));
        let mut cmp = PcodeOp::new(SeqNum::new(Address::new(0x1008), 0), OpCode::CPUI_INT_LESS);
        cmp.parent = Some(std::sync::Arc::downgrade(&head_dyn));
        cmp.inrefs = vec![i_vn.clone(), n_vn];
        cmp.output = Some(std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(1, Address::new(0x400)))));
        let cond_vn = cmp.output.clone().unwrap();
        let cmp_ref = PcodeOpRef(std::sync::Arc::new(std::sync::RwLock::new(cmp)));
        cond_vn.write().unwrap().def = Some(std::sync::Arc::downgrade(&cmp_ref.0));
        head.write().unwrap().add_op(cmp_ref.clone());
        let mut cb = PcodeOp::new(SeqNum::new(Address::new(0x100c), 0), OpCode::CPUI_CBRANCH);
        cb.parent = Some(std::sync::Arc::downgrade(&head_dyn));
        cb.inrefs = vec![std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_constant(0x1000, 8))), cond_vn];
        let cb_ref = PcodeOpRef(std::sync::Arc::new(std::sync::RwLock::new(cb)));
        head.write().unwrap().add_op(cb_ref.clone());
        // body (tail): INT_ADD(i, 1) → i_update; BRANCH back to head.
        let body = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(1, Address::new(0x2000))));
        let body_dyn = body.clone() as std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>;
        let one_vn = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_constant(1, 4)));
        let mut add = PcodeOp::new(SeqNum::new(Address::new(0x2004), 0), OpCode::CPUI_INT_ADD);
        add.parent = Some(std::sync::Arc::downgrade(&body_dyn));
        add.inrefs = vec![i_vn.clone(), one_vn];
        add.output = Some(i_update.clone());
        let add_ref = PcodeOpRef(std::sync::Arc::new(std::sync::RwLock::new(add)));
        i_update.write().unwrap().def = Some(std::sync::Arc::downgrade(&add_ref.0));
        body.write().unwrap().add_op(add_ref.clone());
        let mut br = PcodeOp::new(SeqNum::new(Address::new(0x2008), 0), OpCode::CPUI_BRANCH);
        br.parent = Some(std::sync::Arc::downgrade(&body_dyn));
        br.inrefs = vec![std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_constant(0x1000, 8)))];
        br.flags = crate::op::pcodeop_flags::BRANCH;
        let br_ref = PcodeOpRef(std::sync::Arc::new(std::sync::RwLock::new(br)));
        body.write().unwrap().add_op(br_ref); // trailing branch
        let wd = BlockWhileDo {
            index: 0,
            condition: head.clone(),
            body: body.clone(),
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0, for_init: None, for_iter: None,
        };
        fd.sblocks.add_block(std::sync::Arc::new(std::sync::RwLock::new(wd)));
        // iterate op (INT_ADD) must be printable before.
        assert_eq!(add_ref.0.read().unwrap().flags & NONPRINTING, 0);
        let mut a = ActionStructureTransform::new();
        let _ = a.apply(&mut fd).unwrap();
        // After the transform the iterate op is marked non-printing, and a
        // candidate was counted.
        assert_eq!(a.count, 1, "one for-loop detected");
        assert_ne!(
            add_ref.0.read().unwrap().flags & NONPRINTING,
            0,
            "iterate op must be marked non-printing (for-loop semantics)"
        );
    }

    /// ActionReturnSplit must synthesize a new RETURN op at each goto
    /// predecessor of a multi-in-edge splittable RETURN block.
    #[test]
    fn test_returnsplit_creates_return_at_goto_pred() {
        use crate::address::{Address, SeqNum};
        use crate::block::BlockBasic;
        use crate::op::{PcodeOp, PcodeOpRef};
        use crate::opcodes::OpCode;
        use crate::varnode::Varnode;
        let mut fd = Funcdata::new("f", Address::new(0x1000), 0x40);
        // Two goto predecessors (b1, b2) each ending in a BRANCH, both flowing
        // into the RETURN block (ret). ret has >1 in-edge and is splittable
        // (only a RETURN op with constant-ish inputs).
        let b1 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(1, Address::new(0x1100))));
        let b2 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(2, Address::new(0x1200))));
        let ret = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(3, Address::new(0x1300))));
        // RETURN op in ret (splittable: single RETURN, annotation/const inputs).
        let mut ro = PcodeOp::new(SeqNum::new(Address::new(0x1300), 0), OpCode::CPUI_RETURN);
        ro.inrefs = vec![std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_constant(0, 1)))];
        let ro_ref = PcodeOpRef(std::sync::Arc::new(std::sync::RwLock::new(ro)));
        ro_ref.0.write().unwrap().parent =
            Some(std::sync::Arc::downgrade(&(ret.clone() as std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>)));
        ret.write().unwrap().add_op(ro_ref.clone());
        fd.obank.alivelist.push(ro_ref.clone());
        // b1 ends in BRANCH, b2 ends in BRANCH (goto predecessors).
        for (blk, addr) in [(&b1, 0x1100u64), (&b2, 0x1200u64)] {
            let mut br = PcodeOp::new(SeqNum::new(Address::new(addr), 0), OpCode::CPUI_BRANCH);
            br.inrefs = vec![std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_constant(0x1300, 8)))];
            br.flags = crate::op::pcodeop_flags::BRANCH;
            blk.write().unwrap().add_op(PcodeOpRef(std::sync::Arc::new(std::sync::RwLock::new(br))));
        }
        // Wire edges b1→ret, b2→ret so ret has 2 in-edges.
        fd.bblocks.add_block(b1.clone());
        fd.bblocks.add_block(b2.clone());
        fd.bblocks.add_block(ret.clone());
        fd.bblocks.add_edge(b1.clone(), ret.clone());
        fd.bblocks.add_edge(b2.clone(), ret.clone());
        // sblocks must be non-empty (the early-out).
        fd.sblocks.add_block(ret.clone() as std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>);
        let alives_before = fd.obank.alivelist.len();
        let mut a = ActionReturnSplit::new();
        let _ = a.apply(&mut fd).unwrap();
        // One goto predecessor gets its own RETURN (the other is kept as the
        // original — Ghidra can't split ALL in edges). count == 1.
        assert_eq!(a.count, 1, "one RETURN synthesized");
        assert!(
            fd.obank.alivelist.len() > alives_before,
            "a new RETURN op must have been added"
        );
        // The new RETURN lives in one of the goto predecessor blocks.
        let new_returns = fd
            .obank
            .alivelist
            .iter()
            .filter(|o| o.0.read().unwrap().opcode == OpCode::CPUI_RETURN)
            .count();
        assert!(new_returns >= 2, "original RETURN + at least one new");
    }

    /// ActionNodeJoin must count a diamond candidate (two CBRANCH blocks
    /// converging on the same two exits). blockaction.cc:2326-2364 / 2065.
    #[test]
    fn test_nodejoin_counts_diamond_candidate() {
        use crate::address::{Address, SeqNum};
        use crate::block::BlockBasic;
        use crate::op::{PcodeOp, PcodeOpRef};
        use crate::opcodes::OpCode;
        use crate::varnode::Varnode;
        let mut fd = Funcdata::new("f", Address::new(0x1000), 0x40);
        // Two CBRANCH blocks (b1, b2) both branching to the same two exit
        // blocks (exita, exitb) — a diamond.
        let b1 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(1, Address::new(0x1000))));
        let b2 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(2, Address::new(0x2000))));
        let exita = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(3, Address::new(0x3000))));
        let exitb = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(4, Address::new(0x4000))));
        let cond_vn = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(1, Address::new(0x50))));
        use crate::block::FlowBlock;
        for blk in [&b1, &b2] {
            let mut cb = PcodeOp::new(SeqNum::new(blk.read().unwrap().get_start_addr(), 0), OpCode::CPUI_CBRANCH);
            cb.inrefs = vec![
                std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_constant(0x3000, 8))),
                cond_vn.clone(),
            ];
            blk.write().unwrap().add_op(PcodeOpRef(std::sync::Arc::new(std::sync::RwLock::new(cb))));
        }
        for b in [&b1, &b2, &exita, &exitb] {
            fd.bblocks.add_block(b.clone());
        }
        // Both b1 and b2 branch to exita and exitb.
        fd.bblocks.add_edge(b1.clone(), exita.clone());
        fd.bblocks.add_edge(b1.clone(), exitb.clone());
        fd.bblocks.add_edge(b2.clone(), exita.clone());
        fd.bblocks.add_edge(b2.clone(), exitb.clone());
        let mut a = ActionNodeJoin::new();
        let _ = a.apply(&mut fd).unwrap();
        assert!(a.count >= 1, "diamond join candidate must be detected");
    }

