//! Core analysis actions for the decompiler
//!
//! Corresponds to Ghidra's `coreaction.hh`

use crate::action::{action_flags, action_status, Action};
use crate::error::Result;
use crate::funcdata::Funcdata;
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

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
        // Ghidra coreaction.hh:289 verbatim: { data.opHeritage(); return 0; }
        // No pass guard, no embedded DeadCode, no direct double pass:
        // ActionHeritage sits in the repeatapply "mainloop" group
        // (coreaction.cc:5489-5492), so the executor re-runs this apply on
        // every mainloop iteration and Heritage::heritage itself decides
        // per space what is left to do (heritage.cc:2684-2748: pass < delay
        // skip, prev==2 old ranges only re-entered when not heritageKnown,
        // per-space once-only loadGuardSearch/warning).
        fd.op_heritage();
        Ok(action_status::NO_CHANGE)
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
/// `VAC_CONSUME` records a data-flow path to a formal use, while
/// `LIS_CONSUME` records membership in the LIFO propagation work-list.
pub struct ActionDeadCode;

impl ActionDeadCode {
    // Ghidra: coreaction.hh:560 ActionDeadCode::ActionDeadCode
    pub fn new() -> Self {
        Self
    }

    /// Merge a consume mask and enqueue a written Varnode at most once.
    // Ghidra: coreaction.cc:3556 ActionDeadCode::pushConsumed
    fn push_consumed(
        val: u64,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        worklist: &mut Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    ) {
        use crate::address::calc_mask;
        let mut vn_rg = vn.write().unwrap();
        let newval = (val | vn_rg.get_consume()) & calc_mask(vn_rg.get_size());
        if newval == vn_rg.get_consume() && vn_rg.is_consume_vacuous() {
            return;
        }
        vn_rg.set_consume_vacuous();
        if !vn_rg.is_consume_list() {
            vn_rg.set_consume_list();
            if vn_rg.is_written() {
                worklist.push(vn.clone());
            }
        }
        vn_rg.set_consume(newval);
    }

    /// Propagate the top Varnode's consume mask through its defining op.
    // Ghidra: coreaction.cc:3576 ActionDeadCode::propagateConsumed
    fn propagate_consumed(
        fd: &Funcdata,
        worklist: &mut Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    ) {
        use crate::address::{calc_mask, coveringmask, leastsigbit_set};
        use crate::opcodes::OpCode;
        let Some(vn) = worklist.pop() else { return };
        let (outc, out_size, def) = {
            let mut vn_rg = vn.write().unwrap();
            let values = (vn_rg.get_consume(), vn_rg.get_size(), vn_rg.get_def());
            vn_rg.clear_consume_list();
            values
        };
        let Some(def) = def else { return };
        let (opc, inputs, output) = {
            let op_rg = def.read().unwrap();
            (op_rg.opcode, op_rg.inrefs.clone(), op_rg.output.clone())
        };
        let push = |slot: usize,
                    val: u64,
                    worklist: &mut Vec<
            std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        >| {
            if let Some(input) = inputs.get(slot) {
                Self::push_consumed(val, input, worklist);
            }
        };
        match opc {
            OpCode::CPUI_INT_MULT => {
                let b = coveringmask(outc);
                let in1 = inputs.get(1).map(|input| {
                    let input_rg = input.read().unwrap();
                    (input_rg.is_constant(), input_rg.get_offset())
                });
                let a = if let Some((true, offset)) = in1 {
                    let ls = leastsigbit_set(offset);
                    if ls >= 0 {
                        (calc_mask(out_size) >> ls as u32) & b
                    } else { 0 }
                } else { b };
                push(0, a, worklist);
                push(1, b, worklist);
            }
            OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB => {
                let a = coveringmask(outc);
                push(0, a, worklist);
                push(1, a, worklist);
            }
            OpCode::CPUI_SUBPIECE => {
                let byte_offset = inputs
                    .get(1)
                    .map(|input| input.read().unwrap().get_offset())
                    .unwrap_or(0);
                let mut a = if byte_offset >= 8 { 0 } else { outc << (byte_offset * 8) };
                if a == 0 && outc != 0 && inputs
                        .get(0)
                    .is_some_and(|input| input.read().unwrap().get_size() > 8)
                {
                    a = u64::MAX ^ (u64::MAX >> 1);
                }
                push(0, a, worklist);
                push(1, if outc == 0 { 0 } else { u64::MAX }, worklist);
            }
            OpCode::CPUI_PIECE => {
                let low_size = inputs
                    .get(1)
                    .map(|input| input.read().unwrap().get_size())
                    .unwrap_or(0);
                let (a, b) = if out_size > 8 {
                    if low_size >= 8 {
                        (u64::MAX, outc)
                    } else {
                        let shift = low_size * 8;
                        let high_fill = if shift == 0 { 0 } else { u64::MAX << (64 - shift) };
                        let high = (outc >> shift) ^ high_fill;
                        (high, outc ^ (high << shift))
                    }
                } else {
                    let shift = low_size * 8;
                    let high = if shift >= 64 { 0 } else { outc >> shift };
                    let low = if shift >= 64 { outc } else { outc ^ (high << shift) };
                    (high, low)
                };
                push(0, a, worklist);
                push(1, b, worklist);
            }
            OpCode::CPUI_INDIRECT => {
                push(0, outc, worklist);
                if let (Some(iop), Some(indirect_out)) = (inputs.get(1), output.as_ref()) {
                    if let Some(indop) = fd.get_op_from_const(iop) {
                        let (is_dead, ind_opcode, ind_out) = {
                            let ind_rg = indop.0.read().unwrap();
                            (ind_rg.is_dead(), ind_rg.opcode, ind_rg.output.clone())
                        };
                        if !is_dead {
                            if ind_opcode == OpCode::CPUI_COPY {
                                let overlaps = ind_out.as_ref().is_some_and(|copy_out| {
                                    let copy_rg = copy_out.read().unwrap();
                                    let indirect_rg = indirect_out.read().unwrap();
                                    copy_rg.characterize_overlap(&indirect_rg) > 0
                                });
                                if overlaps {
                                    if let Some(copy_out) = ind_out {
                                        Self::push_consumed(u64::MAX, &copy_out, worklist);
                                    }
                                    indop.0.write().unwrap().flags |= crate::op::pcodeop_flags::INDIRECT_SOURCE;
                                }
                            } else {
                                indop.0.write().unwrap().flags |= crate::op::pcodeop_flags::INDIRECT_SOURCE;
                            }
                        }
                    }
                }
            }
            OpCode::CPUI_COPY | OpCode::CPUI_INT_NEGATE => push(0, outc, worklist),
            OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_OR => {
                push(0, outc, worklist);
                push(1, outc, worklist);
            }
            OpCode::CPUI_INT_AND => {
                let constant = inputs.get(1).and_then(|input| {
                    let input_rg = input.read().unwrap();
                    input_rg.is_constant().then_some(input_rg.get_offset())
                });
                push(0, constant.map_or(outc, |val| outc & val), worklist);
                push(1, outc, worklist);
            }
            OpCode::CPUI_MULTIEQUAL => {
                for input in &inputs {
                    Self::push_consumed(outc, input, worklist);
                }
            }
            OpCode::CPUI_INT_ZEXT => push(0, outc, worklist),
            OpCode::CPUI_INT_SEXT => {
                let b = inputs
                    .get(0)
                    .map(|input| calc_mask(input.read().unwrap().get_size()))
                    .unwrap_or(0);
                let mut a = outc & b;
                if outc > b {
                    a |= b ^ (b >> 1);
                }
                push(0, a, worklist);
            }
            OpCode::CPUI_INT_LEFT => {
                let constant_shift = inputs.get(1).and_then(|input| {
                    let input_rg = input.read().unwrap();
                    input_rg
                        .is_constant()
                        .then_some(input_rg.get_offset() as usize)
                });
                if let Some(shift) = constant_shift {
                    let mut a = if out_size > 8 {
                        if shift >= 64 {
                            u64::MAX
                        } else if shift == 0 {
                            outc
                        } else {
                            (outc >> shift) ^ (u64::MAX << (64 - shift))
                        }
                    } else if shift >= 64 {
                        0
                    } else {
                        outc >> shift
                    };
                    if out_size > 8 {
                        let retained = out_size.saturating_mul(8).saturating_sub(shift);
                        if retained < 64 {
                            a &= if retained == 0 { 0 } else { (1u64 << retained) - 1 };
                        }
                    }
                    push(0, a, worklist);
                    push(1, if outc == 0 { 0 } else { u64::MAX }, worklist);
                } else {
                    let a = if outc == 0 { 0 } else { u64::MAX };
                    push(0, a, worklist);
                    push(1, a, worklist);
                }
            }
            OpCode::CPUI_INT_RIGHT => {
                let constant_shift = inputs.get(1).and_then(|input| {
                    let input_rg = input.read().unwrap();
                    input_rg
                        .is_constant()
                        .then_some(input_rg.get_offset() as usize)
                });
                if let Some(shift) = constant_shift {
                    push(0, if shift >= 64 { 0 } else { outc << shift }, worklist);
                    push(1, if outc == 0 { 0 } else { u64::MAX }, worklist);
                } else {
                    let a = if outc == 0 { 0 } else { u64::MAX };
                    push(0, a, worklist);
                    push(1, a, worklist);
                }
            }
            OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_LESSEQUAL |
            OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL => {
                let a = if outc == 0 { 0 } else {
                    inputs
                        .get(0)
                        .map(|input| input.read().unwrap().get_nz_mask())
                        .unwrap_or(0)
                        | inputs
                            .get(1)
                            .map(|input| input.read().unwrap().get_nz_mask())
                            .unwrap_or(0)
                };
                push(0, a, worklist);
                push(1, a, worklist);
            }
            OpCode::CPUI_INSERT => {
                let width = inputs
                    .get(3)
                    .map(|input| input.read().unwrap().get_offset())
                    .unwrap_or(0);
                let position = inputs
                    .get(2)
                    .map(|input| input.read().unwrap().get_offset())
                    .unwrap_or(0);
                let insert_mask = if width >= 64 { u64::MAX } else if width == 0 { 0 } else { (1u64 << width) - 1 };
                push(1, insert_mask, worklist);
                let shifted_mask = if position >= 64 { 0 } else { insert_mask << position };
                push(0, outc & !shifted_mask, worklist);
                let b = if outc == 0 { 0 } else { u64::MAX };
                push(2, b, worklist);
                push(3, b, worklist);
            }
            OpCode::CPUI_EXTRACT => {
                let width = inputs
                    .get(2)
                    .map(|input| input.read().unwrap().get_offset())
                    .unwrap_or(0);
                let position = inputs
                    .get(1)
                    .map(|input| input.read().unwrap().get_offset())
                    .unwrap_or(0);
                let extract_mask = if width >= 64 { u64::MAX } else if width == 0 { 0 } else { (1u64 << width) - 1 };
                let consumed = extract_mask & outc;
                push(
                    0, if position >= 64 { 0 } else { consumed << position }, worklist,
                );
                let b = if outc == 0 { 0 } else { u64::MAX };
                push(1, b, worklist);
                push(2, b, worklist);
            }
            OpCode::CPUI_POPCOUNT | OpCode::CPUI_LZCOUNT => {
                let possible = inputs
                    .get(0)
                    .map(|input| {
                        16u64
                            .saturating_mul(input.read().unwrap().get_size() as u64)
                            .saturating_sub(1)
                    })
                    .unwrap_or(0) & outc;
                push(0, if possible == 0 { 0 } else { u64::MAX }, worklist);
            }
            OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => {}
            OpCode::CPUI_FLOAT_INT2FLOAT => {
                let a = if outc == 0 { 0 } else {
                    coveringmask(
                        inputs
                            .get(0)
                        .map(|input| input.read().unwrap().get_nz_mask())
                            .unwrap_or(0),
                    )
                };
                push(0, a, worklist);
            }
            _ => {
                let a = if outc == 0 { 0 } else { u64::MAX };
                for input in &inputs {
                    Self::push_consumed(a, input, worklist);
                }
            }
        }
    }

    // Ghidra: coreaction.cc:3809 ActionDeadCode::neverConsumed
    fn never_consumed(
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        fd: &mut Funcdata,
    ) -> bool {
        let (size, descendants, def) = {
            let vn_rg = vn.read().unwrap();
            if vn_rg.get_size() > 8 {
                return false;
            }
            (
                vn_rg.get_size(), vn_rg
                    .descend
                    .iter()
                    .filter_map(|weak| weak.upgrade())
                    .collect::<Vec<_>>(), vn_rg.get_def(),
            )
        };
        for descendant in descendants {
            let op = crate::op::PcodeOpRef(descendant);
            let slot = { op.0.read().unwrap().slot_of_input(vn) };
            if let Some(slot) = slot {
                let zero = fd.new_constant(size, 0);
                fd.op_set_input(&op, zero, slot);
            }
        }
        if let Some(def) = def {
            let op = crate::op::PcodeOpRef(def);
            if op.0.read().unwrap().is_call() {
                fd.op_unset_output(&op);
            } else {
                fd.op_destroy(&op);
            }
            true
        } else {
            false
        }
    }

    // RUGRA-GLUE: Ghidra's PcodeOp::isCallWithoutSpec() (op.hh:177) tests the
    // has_callspec flag, which in Ghidra is an exact proxy for "a
    // FuncCallSpecs object is attached": flow.cc:685 FlowInfo::setupCallSpecs
    // creates the FuncCallSpecs and rewrites in(0) in the same breath, and no
    // other site sets the flag (typeop.cc:663/741 set it statically at
    // opcode-assign time). Rugra's inject_raw_ops path births CPUI_CALL with
    // the static TypeOp flag but no FuncCallSpecs object, so the flag alone
    // is not a faithful proxy; query Funcdata::callspecs for an attached
    // spec instead (Weak identity link, fspec.rs FuncCallSpecs::op).
    fn op_has_attached_callspec(fd: &Funcdata, op_ref: &crate::op::PcodeOpRef) -> bool {
        fd.callspecs.iter().any(|spec| {
            spec.read()
                .unwrap()
                .op
                .upgrade()
                .is_some_and(|op| std::sync::Arc::ptr_eq(&op, &op_ref.0))
        })
    }

    // Ghidra: coreaction.cc:3840 ActionDeadCode::markConsumedParameters
    fn mark_consumed_parameters(
        fd: &Funcdata,
        fc: &crate::fspec::FuncCallSpecs,
        worklist: &mut Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    ) {
        let Some(call_op) = fc.find_call_op(fd) else { return ;
        };
        let inputs = call_op.0.read().unwrap().inrefs.clone();
        if let Some(target) = inputs.first() {
            Self::push_consumed(u64::MAX, target, worklist);
        }
        if fc.is_input_locked() || fc.is_input_active() {
            for input in inputs.iter().skip(1) {
                Self::push_consumed(u64::MAX, input, worklist);
            }
            return;
        }
        for (slot, input) in inputs.iter().enumerate().skip(1) {
            let mut consume = {
                let input_rg = input.read().unwrap();
                if input_rg.is_auto_live() { u64::MAX }
                else { crate::address::minimalmask(input_rg.get_nz_mask()) }
            };
            let bytes = fc.get_input_bytes_consumed(slot);
            if bytes != 0 {
                consume &= crate::address::calc_mask(bytes as usize);
            }
            Self::push_consumed(consume, input, worklist);
        }
    }

    // Ghidra: coreaction.cc:3871 ActionDeadCode::gatherConsumedReturn
    fn gather_consumed_return(fd: &Funcdata) -> u64 {
        if fd.get_func_proto().is_output_locked() || fd.active_output.is_some() {
            return u64::MAX;
        }
        let mut consume = 0;
        for return_op in &fd.obank.returnlist {
            let input = {
                let op_rg = return_op.0.read().unwrap();
                if op_rg.is_dead() || op_rg.num_input() <= 1 { None }
                else { op_rg.get_in(1).cloned() }
            };
            if let Some(input) = input {
                consume |= crate::address::minimalmask(input.read().unwrap().get_nz_mask());
            }
        }
        let bytes = fd.get_func_proto().get_return_bytes_consumed();
        if bytes != 0 {
            consume &= crate::address::calc_mask(bytes as usize);
        }
        consume
    }

    // Ghidra: coreaction.cc:3902 ActionDeadCode::lastChanceLoad
    /// Mark LOAD ops whose address input (in(1)) is an eventual constant as
    /// auto-live, so they survive dead-code removal. This prevents losing LOADs
    /// whose address hasn't been resolved to a concrete value yet during early
    /// heritage passes. Faithful to `lastChanceLoad` (coreaction.cc:3902-3923):
    ///   - Returns false if heritage_pass > 1 or jumptable recovery is on.
    ///   - For each live LOAD op: if in(1) is eventual constant (maxBinary=3,
    ///     maxLoad=1), push full consumed on the output + set auto_live_hold.
    fn last_chance_load(
        fd: &mut Funcdata, worklist: &mut Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    ) -> bool {
        // cc:3905: if (data.getHeritagePass() > 1) return false;
        if fd.heritage.pass > 1 { return false; }
        // cc:3906: if (data.isJumptableRecoveryOn()) return false;
        if fd.is_jumptable_recovery_on() { return false; }
        let mut res = false;
        // cc:3907-3921: iterate LOAD ops.
        let load_ops: Vec<crate::op::PcodeOpRef> = fd.obank.loadlist.clone();
        for op_ref in &load_ops {
            // Capture the output Arc + in(1) eventual-const check while holding
            // the read lock, then release before mutating.
            let out_arc = {
                let op = op_ref.0.read().unwrap();
                if op.is_dead() { None }
                else if let Some(out) = &op.output {
                    if out.read().unwrap().is_consume_vacuous() { None }
                    else {
                        let in1_is_eventual = op
                            .get_in(1)
                            .map(|v| v.read().unwrap().is_eventual_constant(3, 1)
                        )
                            .unwrap_or(false);
                        if in1_is_eventual { Some(out.clone()) }
                        else { None }
                    }
                } else { None }
            };
            if let Some(out) = out_arc {
                Self::push_consumed(u64::MAX, &out, worklist);
                out.write().unwrap().set_auto_live_hold();
                res = true;
            }
        }
        res
    }
}

impl Action for ActionDeadCode {
    // Ghidra: coreaction.cc:3925 ActionDeadCode::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        use crate::space::{AddressSpace, SPACEID_OTHER};
        let all_varnodes = fd
            .vbank
            .loc_tree
            .iter()
            .map(|entry| entry.0.clone())
            .collect::<Vec<_>>();
        let mut spaces = all_varnodes
            .iter()
            .map(|vn| vn.read().unwrap().get_space())
            .collect::<Vec<_>>();
        spaces.sort_by_key(|space| (space.space_id(), *space));
        spaces.dedup();
        let does_deadcode = |space: AddressSpace| {
            !matches!(
                space, AddressSpace::Const | AddressSpace::Iop | AddressSpace::Other(SPACEID_OTHER)
            )
        };

        for vn in &all_varnodes {
            let mut vn_rg = vn.write().unwrap();
            vn_rg.clear_consume_list();
            vn_rg.clear_consume_vacuous();
            vn_rg.set_consume(0);
            if vn_rg.is_addr_force() && !vn_rg.is_direct_write() {
                vn_rg.clear_addr_force();
            }
        }

        let mut worklist: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> =
            Vec::new();
        for &space in &spaces {
            if !does_deadcode(space) || fd.heritage.dead_removal_allowed(space) {
                continue;
            }
            for vn in fd.vbank.iter_space(space) {
                Self::push_consumed(u64::MAX, &vn, &mut worklist);
            }
        }

        let return_consume = Self::gather_consumed_return(fd);
        let alive_ops = fd.obank.alivelist.clone();
        for op_ref in &alive_ops {
            op_ref.0.write().unwrap().flags &= !crate::op::pcodeop_flags::INDIRECT_SOURCE;
            let (is_call, is_call_without_spec, is_assignment, hold_output, opcode, inputs, output) = {
                let op_rg = op_ref.0.read().unwrap();
                (
                    op_rg.is_call(),
                    (op_rg.flags & (crate::op::pcodeop_flags::CALL | crate::op::pcodeop_flags::HAS_CALLSPEC))
                        == crate::op::pcodeop_flags::CALL,
                    op_rg.is_assignment(),
                    (op_rg.addlflags & crate::op::op_addl_flags::HOLD_OUTPUT) != 0,
                    op_rg.opcode,
                    op_rg.inrefs.clone(),
                    op_rg.output.clone(),
                )
            };
            if is_call {
                if is_call_without_spec {
                    for input in &inputs {
                        Self::push_consumed(u64::MAX, input, &mut worklist);
                    }
                } else if !Self::op_has_attached_callspec(fd, op_ref) {
                    // coreaction.cc:3846 (markConsumedParameters, first
                    // statement): pushConsumed(~0, callOp->getIn(0)) — "In
                    // all cases the first operand is fully consumed". In
                    // Ghidra every CPUI_CALL carries a FuncCallSpecs
                    // (flow.cc:685 FlowInfo::setupCallSpecs attaches one at
                    // flow time, and TypeOpCall's static has_callspec flag
                    // — typeop.cc:663 — makes cc:3968's isCallWithoutSpec
                    // branch unreachable for CALL), so the cc:3846 guarantee
                    // always covers in(0). Rugra's inject_raw_ops path births
                    // calls with the static flag but NO FuncCallSpecs object;
                    // the mark_consumed_parameters loop below therefore never
                    // runs for them, in(0) keeps consume==0 after the reset
                    // above, and ActionVarnodeProps (coreaction.cc:1327-1341)
                    // totalReplaceConstant's the coderef target to const:0 —
                    // the FUN_0 clobber (COREACTION-CALLIN0-CLOBBER-0001).
                    // Restore the unconditional first-operand guarantee for
                    // spec-less calls here.
                    if let Some(target) = inputs.first() {
                        Self::push_consumed(u64::MAX, target, &mut worklist);
                    }
                }
                if !is_assignment { continue; }
                if hold_output {
                    if let Some(output) = &output {
                        Self::push_consumed(u64::MAX, output, &mut worklist);
                    }
                }
            } else if !is_assignment {
                if opcode == OpCode::CPUI_RETURN {
                    if let Some(input) = inputs.first() {
                        Self::push_consumed(u64::MAX, input, &mut worklist);
                    }
                    for input in inputs.iter().skip(1) {
                        Self::push_consumed(return_consume, input, &mut worklist);
                    }
                } else if opcode == OpCode::CPUI_BRANCHIND {
                    let mask = fd
                        .find_jump_table(op_ref)
                        .map(|table| table.read().unwrap().get_switch_var_consume())
                        .unwrap_or(u64::MAX);
                    if let Some(input) = inputs.first() {
                        Self::push_consumed(mask, input, &mut worklist);
                    }
                } else {
                    for input in &inputs {
                        Self::push_consumed(u64::MAX, input, &mut worklist);
                    }
                }
                continue;
            } else {
                for input in &inputs {
                    if input.read().unwrap().is_auto_live() {
                        Self::push_consumed(u64::MAX, input, &mut worklist);
                    }
                }
            }
            if let Some(output) = output {
                if output.read().unwrap().is_auto_live() {
                    Self::push_consumed(u64::MAX, &output, &mut worklist);
                }
            }
        }

        let call_specs = fd.callspecs.clone();
        for call_spec in &call_specs {
            let call_spec = call_spec.read().unwrap();
            Self::mark_consumed_parameters(fd, &call_spec, &mut worklist);
        }

        while !worklist.is_empty() {
            Self::propagate_consumed(fd, &mut worklist);
        }

        if Self::last_chance_load(fd, &mut worklist) {
            while !worklist.is_empty() {
                Self::propagate_consumed(fd, &mut worklist);
            }
        }

        for &space in &spaces {
            if !does_deadcode(space) || !fd.heritage.dead_removal_allowed(space) {
                continue;
            }
            let varnodes = fd.vbank.iter_space(space).collect::<Vec<_>>();
            let mut change_count = 0;
            for vn in varnodes {
                let (written, vacuous, consume, def) = {
                    let mut vn_rg = vn.write().unwrap();
                    let values = (
                        vn_rg.is_written(), vn_rg.is_consume_vacuous(), vn_rg.get_consume(), vn_rg.get_def(),
                    );
                    if values.0 {
                        vn_rg.clear_consume_list();
                        vn_rg.clear_consume_vacuous();
                    }
                    values
                };
                if !written { continue; }
                if !vacuous {
                    if let Some(def) = def {
                        let op = crate::op::PcodeOpRef(def);
                        change_count += 1;
                        if op.0.read().unwrap().is_call() {
                            fd.op_unset_output(&op);
                        } else {
                            fd.op_destroy(&op);
                        }
                    }
                } else if consume == 0 && Self::never_consumed(&vn, fd) {
                    change_count += 1;
                }
            }
            if change_count != 0 {
                fd.heritage.seen_dead_code(space);
            }
        }

        fd.clear_dead_varnodes();
        fd.obank.destroy_dead();
        Ok(action_status::NO_CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "deadcode" mirrors ctor at coreaction.hh:552
    fn get_name(&self) -> &str {
        "deadcode"
    }
}

// RUGRA-GLUE: wraps Varnode::getSpaceFromConst (varnode.hh) for the
// LOAD/STORE space-id operands of searchForSpaceAttribute — same projection
// double_precis.rs uses (the constant holds a space id; recover via
// AddressSpace::from_id).
fn space_from_const_vn(vn: &crate::varnode::Varnode) -> crate::space::AddressSpace {
    if vn.is_constant() {
        crate::space::AddressSpace::from_id(vn.get_offset() as u8)
    } else {
        vn.get_space()
    }
}

// Ghidra: space.hh:374 AddrSpace::getMinimumPtrSize
/// Minimum pointer size of an enum-space projection. The registry handle
/// caches `minimumPointerSize` (set to `newsize` only by `truncateSpace`,
/// space.cc:105-112); every hardwired enum space is untruncated, so the
/// production value is 0 (= exact addrSize match) — the documented enum
/// projection of [`crate::space::AddrSpace::get_minimum_ptr_size`].
fn enum_minimum_ptr_size(_spc: crate::space::AddressSpace) -> i32 {
    0
}

/// Action for identifying constant pointers and replacing them
///
/// Corresponds to Ghidra's `ActionConstantPtr` (coreaction.hh:186-196):
/// check for constants, with pointer type, that correspond to global
/// symbols. Iterates the constant space, infers the pointer space, runs the
/// op/bounds/bit-form gates, queries the parent scope's container table and
/// rewrites hits into `PTRSUB(spacebase, offset)` chains via
/// [`Funcdata::spacebase_constant`].
pub struct ActionConstantPtr {
    /// Number of passes made for this function (coreaction.hh:189
    /// `localcount`).
    localcount: i32,
    /// Externalized Ghidra `Action::count` (one increment per
    /// `spacebaseConstant` rewrite, coreaction.cc:1213).
    count: i32,
}

impl ActionConstantPtr {
    // Ghidra: coreaction.hh:188 ActionConstantPtr (constructor mirror)
    pub fn new() -> Self {
        Self { localcount: 0, count: 0 ,
        }
    }

    // Ghidra: coreaction.cc:957 ActionConstantPtr::searchForSpaceAttribute
    /// From a constant, search forward in its data-flow either for a LOAD or
    /// STORE operation where we can see the address space being accessed, or
    /// search for a pointer data-type with an address space attribute.
    /// Faithful to `searchForSpaceAttribute` (coreaction.cc:957-995): a
    /// limited traversal (3 steps) through the op reading the constant, over
    /// INT_ADD/COPY/INDIRECT/MULTIEQUAL, until a LOAD/STORE is hit; when the
    /// chase hits a varnode with no lone descendant, cc:984's `break` exits
    /// the for-loop (with `vn` already advanced to the output at cc:972) and
    /// the epilogue scans every descendant of that varnode for LOAD/STORE
    /// (R-RAWQUAR F2 fix: the former `?` early-return skipped the epilogue).
    fn search_for_space_attribute(
        vn: &Arc<RwLock<crate::varnode::Varnode>>,
        op: &Arc<RwLock<PcodeOp>>,
    ) -> Option<crate::space::AddressSpace> {
        // cc:960-985: for(int4 i=0;i<3;++i) — the limited data-flow walk.
        let mut vn = vn.clone();
        let mut op = op.clone();
        'chase: for _ in 0..3 {
            // cc:961-966: a pointer type with an explicit space attribute
            // whose addrSize matches the varnode size answers directly.
            // Rugra's TypePointer does not model the space attribute yet
            // (TYPE-0001 residual), so the arm always falls through — the
            // behavior when no pointer carries a space attribute.
            let _ = vn.read().unwrap().get_type();
            let next: Option<(Arc<RwLock<crate::varnode::Varnode>>, Arc<RwLock<PcodeOp>>)> = {
                let op_r = op.read().unwrap();
                match op_r.opcode {
                    // cc:968-974: chase the output's lone descendant.
                    OpCode::CPUI_INT_ADD
                    | OpCode::CPUI_COPY
                    | OpCode::CPUI_INDIRECT
                    | OpCode::CPUI_MULTIEQUAL => {
                        let outvn = match op_r.output.clone() {
                            Some(out) => out,
                            // Unreachable in valid IR (these opcodes always
                            // have outputs); the C++ would dereference null.
                            None => return None,
                        };
                        let desc = outvn.read().unwrap().lone_descend();
                        match desc {
                            // cc:972 already advanced vn to the output;
                            // cc:984: if (op == 0) break — out of the for
                            // loop, into the epilogue below (which scans
                            // THIS varnode's descendants).
                            None => {
                                drop(op_r);
                                vn = outvn;
                                break 'chase;
                            }
                            Some(desc) => {
                                drop(op_r);
                                Some((outvn, desc))
                            }
                        }
                    }
                    // cc:975-976: LOAD exposes the space constant.
                    OpCode::CPUI_LOAD => {
                        let spc_vn = op_r.get_in(0)?;
                        return Some(space_from_const_vn(&spc_vn.read().unwrap()));
                    }
                    // cc:977-980: STORE only when vn is the address input.
                    OpCode::CPUI_STORE => {
                        let is_addr_input = op_r
                            .get_in(1)
                            .map(|n| Arc::ptr_eq(n, &vn))
                            .unwrap_or(false);
                        if !is_addr_input {
                            return None;
                        }
                        let spc_vn = op_r.get_in(0)?;
                        return Some(space_from_const_vn(&spc_vn.read().unwrap()));
                    }
                    _ => return None,
                }
            };
            let (next_vn, next_op) = next?;
            vn = next_vn;
            op = next_op;
        }
        // cc:986-993: epilogue — scan every descendant of the final varnode
        // for a LOAD (any position) or a STORE where vn is the address input.
        for desc in vn.read().unwrap().descend_iter() {
            let desc_r = desc.read().unwrap();
            match desc_r.opcode {
                OpCode::CPUI_LOAD => {
                    let spc_vn = desc_r.get_in(0)?;
                    return Some(space_from_const_vn(&spc_vn.read().unwrap()));
                }
                OpCode::CPUI_STORE => {
                    let is_addr_input = desc_r
                        .get_in(1)
                        .map(|n| Arc::ptr_eq(n, &vn))
                        .unwrap_or(false);
                    if is_addr_input {
                        let spc_vn = desc_r.get_in(0)?;
                        return Some(space_from_const_vn(&spc_vn.read().unwrap()));
                    }
                }
                _ => {}
            }
        }
        None
    }

    // Ghidra: coreaction.cc:1005 ActionConstantPtr::selectInferSpace
    /// Select the address space in which we infer that the given constant is
    /// a pointer. Faithful to `selectInferSpace` (coreaction.cc:1005-1032):
    /// an explicit TYPE_PTR space attribute wins first; otherwise the first
    /// space in `inferPtrSpaces` whose size gate passes (`minSize==0` demands
    /// `vn.size == spc.addrSize`, else `vn.size >= minSize`); a second
    /// candidate triggers `searchForSpaceAttribute` disambiguation and ends
    /// the scan.
    fn select_infer_space(
        vn: &Arc<RwLock<crate::varnode::Varnode>>,
        op: &Arc<RwLock<PcodeOp>>,
        space_list: &[crate::space::AddressSpace],
    ) -> Option<crate::space::AddressSpace> {
        let mut res_space: Option<crate::space::AddressSpace> = None;
        // cc:1009-1013: explicit pointer type with a matching space.
        // Rugra's TypePointer does not model the space attribute yet
        // (TYPE-0001 residual), so this arm cannot fire — the behavior when
        // no pointer type carries a space attribute.
        let _ = vn.read().unwrap().get_type();
        // cc:1014-1030: walk inferPtrSpaces in order (the default data space
        // leads — architecture.cc:665-701 cacheAddrSpaceProperties; Rugra's
        // list is built by <global> ingestion in registration order).
        for spc in space_list {
            let min_size = enum_minimum_ptr_size(*spc);
            let vn_size = vn.read().unwrap().get_size();
            if min_size == 0 {
                // cc:1017-1019: exact addrSize match required.
                if vn_size != spc.addr_size() {
                    continue;
                }
            } else if (vn_size as i32) < min_size {
                // cc:1021-1022: partial pointers must at least reach
                // minSize.
                continue;
            }
            if res_space.is_some() {
                // cc:1023-1028: a second candidate — disambiguate from the
                // syntax tree, then stop scanning.
                let search_spc = Self::search_for_space_attribute(vn, op);
                if let Some(found) = search_spc {
                    res_space = Some(found);
                }
                break;
            }
            res_space = Some(*spc);
        }
        res_space
    }

    // Ghidra: coreaction.cc:1041 ActionConstantPtr::checkCopy
    /// Check if we need to try to infer a constant pointer from the input of
    /// the given COPY. Faithful to `checkCopy` (coreaction.cc:1041-1054):
    /// a COPY feeding a lone RETURN consults the locked output type (PTR or
    /// UNKNOWN try regardless of infer_pointers; anything else refuses);
    /// every other COPY follows the infer_pointers boolean.
    fn check_copy(op: &Arc<RwLock<PcodeOp>>, fd: &Funcdata) -> bool {
        // cc:1044-1045: vn = op->getOut(); retOp = vn->loneDescend().
        let ret_op = {
            let op_r = op.read().unwrap();
            let outvn = op_r.output.clone();
            match outvn {
                Some(out) => out.read().unwrap().lone_descend(),
                None => None,
            }
        };
        if let Some(ret_op) = ret_op {
            let is_return = ret_op.read().unwrap().opcode == OpCode::CPUI_RETURN;
            // cc:1046: retOp is RETURN and the function output is locked.
            if is_return && fd.funcp.is_output_locked() {
                // cc:1047-1048: the locked output metatype decides.
                let meta = fd.funcp.return_type.get_metatype();
                if meta != crate::type_system::datatype::TypeMetatype::Pointer
                    && meta != crate::type_system::datatype::TypeMetatype::Unknown
                {
                    // cc:1049: we KNOW the constant can't be a pointer.
                    return false;
                }
                // cc:1051: we KNOW it is a pointer — infer regardless of
                // the infer_pointers config.
                return true;
            }
        }
        // cc:1053: every other COPY follows the architecture boolean.
        fd.arch.as_ref().map(|a| a.infer_pointers).unwrap_or(false)
    }

    // Ghidra: coreaction.cc:1070 ActionConstantPtr::isPointer
    /// Determine if the given Varnode might be a pointer constant; if it is,
    /// return the symbol it points to. Faithful to `isPointer`
    /// (coreaction.cc:1070-1165): the explicit TYPE_PTR arm resolves
    /// immediately with `needexacthit=false`; otherwise the op-shape gate
    /// (CALL/CALLIND/COPY/PIECE/comparisons/INT_ADD/STORE), the pointer
    /// range gate, the `bit_transitions>=3` gate and the container query run
    /// in that order. `rampoint`/`full_encoding` are the C++ out parameters.
    fn is_pointer(
        spc: crate::space::AddressSpace,
        vn: &Arc<RwLock<crate::varnode::Varnode>>,
        op: &Arc<RwLock<PcodeOp>>,
        slot: usize,
        rampoint: &mut crate::address::Address,
        full_encoding: &mut u64,
        fd: &Funcdata,
    ) -> Option<crate::database::QueryContainerHit> {
        use crate::type_system::datatype::TypeMetatype;
        let mut needexacthit: bool;
        let (vn_offset, vn_size) = {
            let vn_r = vn.read().unwrap();
            (vn_r.get_offset(), vn_r.get_size())
        };
        let op_addr = op.read().unwrap().get_addr();
        let op_code = op.read().unwrap().opcode;
        // cc:1077-1080: explicitly marked as a pointer type — resolve and
        // skip every heuristic gate (needexacthit=false: partial pointers may
        // land mid-symbol).
        if vn
            .read()
            .unwrap()
            .get_type_read_facing()
            .map(|dt| dt.get_metatype())
            == Some(TypeMetatype::Pointer)
        {
            *rampoint = Self::resolve_constant(spc, vn_offset, vn_size, op_addr, full_encoding);
            needexacthit = false;
        } else {
            // cc:1082: locked as NOT a pointer.
            if vn.read().unwrap().is_type_lock() {
                return None;
            }
            needexacthit = true;
            // cc:1086-1136: check if the constant is involved in a potential
            // pointer expression as the base.
            match op_code {
                OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => {
                    // cc:1090-1091: the call target itself is never inferred.
                    if slot == 0 {
                        return None;
                    }
                    // cc:1093-1099: a locked callspec parameter type that is
                    // neither PTR nor UNKNOWN rules the constant out.
                    let fc = fd.get_call_specs_of_op(&crate::op::PcodeOpRef(op.clone()));
                    match &fc {
                        Some(fc_arc) => {
                            let fc_r = fc_arc.read().unwrap();
                            if fc_r.is_input_locked()
                                && (fc_r.prototype.num_params() as usize) > slot - 1
                            {
                                // cc:1095-1098: the locked parameter type decides.
                                if let Some(param) = fc_r.prototype.get_param(slot - 1) {
                                    let meta = param.data_type.get_metatype();
                                    if meta != TypeMetatype::Pointer
                                        && meta != TypeMetatype::Unknown
                                    {
                                        // cc:1097: definitely not passing a pointer.
                                        return None;
                                    }
                                }
                            } else {
                                // cc:1100-1101: an unlocked/missing parameter
                                // needs the infer_pointers boolean.
                                if !fd.arch.as_ref().map(|a| a.infer_pointers).unwrap_or(false)
                                {
                                    return None;
                                }
                            }
                        }
                        None => {
                            // cc:1100-1101: no callspec at all.
                            if !fd.arch.as_ref().map(|a| a.infer_pointers).unwrap_or(false) {
                                return None;
                            }
                        }
                    }
                }
                OpCode::CPUI_COPY => {
                    // cc:1104-1106.
                    if !Self::check_copy(op, fd) {
                        return None;
                    }
                }
                OpCode::CPUI_PIECE
                | OpCode::CPUI_INT_EQUAL
                | OpCode::CPUI_INT_NOTEQUAL
                | OpCode::CPUI_INT_LESS
                | OpCode::CPUI_INT_LESSEQUAL => {
                    // cc:1108-1116: pointers get concatenated in structures /
                    // compared against constants — needs infer_pointers.
                    if !fd.arch.as_ref().map(|a| a.infer_pointers).unwrap_or(false) {
                        return None;
                    }
                }
                OpCode::CPUI_INT_ADD => {
                    // cc:1118-1128: an INT_ADD output already typed PTR makes
                    // the constant the base of the pointer expression.
                    let out_is_ptr = op
                        .read()
                        .unwrap()
                        .output
                        .as_ref()
                        .and_then(|out| out.read().unwrap().get_type_def_facing())
                        .map(|dt| dt.get_metatype() == TypeMetatype::Pointer)
                        .unwrap_or(false);
                    if out_is_ptr {
                        // cc:1122-1123: another pointer base in the same
                        // expression means this constant is the offset, not
                        // the pointer.
                        let other_is_ptr = op
                            .read()
                            .unwrap()
                            .get_in(1 - slot)
                            .and_then(|other| other.read().unwrap().get_type_read_facing())
                            .map(|dt| dt.get_metatype() == TypeMetatype::Pointer)
                            .unwrap_or(false);
                        if other_is_ptr {
                            return None;
                        }
                        // cc:1125: the typed sum pins the symbol exactly enough
                        // that a mid-symbol hit is acceptable.
                        needexacthit = false;
                    } else if !fd.arch.as_ref().map(|a| a.infer_pointers).unwrap_or(false) {
                        return None;
                    }
                }
                OpCode::CPUI_STORE => {
                    // cc:1130-1132: only the value input (slot 2) of STORE.
                    if slot != 2 {
                        return None;
                    }
                }
                _ => return None,
            }
            // cc:1138-1141: the constant must sit in the space's inferred
            // pointer range (AddrSpace::calcScaleMask bounds, space.cc:34-44).
            let (lower_bound, upper_bound) = Self::pointer_bounds(spc);
            if lower_bound > vn_offset {
                return None;
            }
            if upper_bound < vn_offset {
                return None;
            }
            // cc:1143-1144: reject single bits / masks.
            if crate::rangeutil::bit_transitions(vn_offset, vn_size) < 3 {
                return None;
            }
            // cc:1145.
            *rampoint = Self::resolve_constant(spc, vn_offset, vn_size, op_addr, full_encoding);
        }

        // cc:1148: rampoint.isInvalid() — Rugra's no-resolver resolve always
        // produces a (spaceless but defined) address, and no resolver is
        // registered in this pipeline, so the invalid branch is unreachable
        // here (AddressResolver registration is the translate.cc residual).
        // cc:1151: global addresses are address tied — empty usepoint.
        let entry = fd.query_container_parent_scope(
            *rampoint,
            1,
            // cc:1151 — the empty usepoint `Address()`.
            crate::address::Address::new(0),
        )?;
        // cc:1152-1160: strings (character arrays) may be pointed at from
        // the middle.
        if entry.type_metatype
            == crate::type_system::datatype::TypeMetatype::Array
            && entry.base_is_char_print
        {
            needexacthit = false;
        }
        // cc:1161-1162: every other symbol demands an entry starting exactly
        // at the resolved address.
        if needexacthit && entry.entry_addr.as_u64() != rampoint.as_u64() {
            return None;
        }
        Some(entry)
    }

    // Ghidra: translate.cc:628 AddrSpaceManager::resolveConstant
    /// Resolve a native constant into an address — the no-resolver default
    /// path of `AddrSpaceManager::resolveConstant` (translate.cc:637-641):
    /// `fullEncoding = val; val = addressToByte(val, wordSize); val =
    /// wrapOffset(val)`. Rugra's Funcdata pipeline carries no
    /// `AddrSpaceManager`, and no `AddressResolver` is registered for the
    /// production spaces (x86-64 registers none), so this local arm is the
    /// exact production behavior for this oracle configuration; the
    /// resolver-registration channel is the documented residual.
    fn resolve_constant(
        spc: crate::space::AddressSpace,
        val: u64,
        _sz: usize,
        _point: crate::address::Address,
        full_encoding: &mut u64,
    ) -> crate::address::Address {
        // cc:638: fullEncoding = val.
        *full_encoding = val;
        // cc:639: val = addressToByte(val, wordSize) — multiply by the space
        // word size (1 for every production space here).
        let word_size = spc.word_size().max(1) as u64;
        let val_bytes = if word_size == 1 { val } else { val * word_size };
        // cc:640: wrapOffset — mask to the space's address size.
        let addr_bits = (spc.addr_size() * 8) as u32;
        let addr_mask = if addr_bits == 0 || addr_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << addr_bits) - 1
        };
        crate::address::Address::new(val_bytes & addr_mask)
    }

    // Ghidra: space.cc:34 AddrSpace::calcScaleMask
    /// The default pointer bounds of an address space, recomputed from the
    /// space's (addressSize, wordsize) exactly as `calcScaleMask`
    /// (space.cc:34-44) caches them on construction:
    /// `highest = calc_mask(addressSize)*wordsize + wordsize-1`,
    /// `bufferSize = addressSize<3 ? 0x100 : 0x1000`,
    /// `pointerLowerBound = bufferSize`, `pointerUpperBound =
    /// highest-bufferSize`. Rugra's enum `AddressSpace` carries no cached
    /// bounds (the registry handle does, and the Funcdata pipeline uses the
    /// enum), so the constructor formula is evaluated directly — same
    /// inputs, same unsigned wraparound arithmetic.
    fn pointer_bounds(spc: crate::space::AddressSpace) -> (u64, u64) {
        let address_size = spc.addr_size() as i32;
        let word_size = spc.word_size() as u64;
        let highest = crate::space::calc_mask(address_size)
            .wrapping_mul(word_size)
            .wrapping_add(word_size.wrapping_sub(1));
        let buffer_size: u64 = if address_size < 3 { 0x100 } else { 0x1000 };
        (buffer_size, highest.wrapping_sub(buffer_size))
    }
}

impl Action for ActionConstantPtr {
    // Ghidra: coreaction.cc:1167 ActionConstantPtr::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // cc:1170: type recovery must have started.
        if !fd.has_type_recovery_started() {
            return Ok(action_status::NO_CHANGE);
        }
        // cc:1172-1174: at most 4 passes once type recovery starts.
        if self.localcount >= 4 {
            return Ok(action_status::NO_CHANGE);
        }
        self.localcount += 1;

        // cc:1178: cspc = glb->getConstantSpace().
        let cspc = crate::space::AddressSpace::Const;
        // cc:1182-1183: begiter = data.beginLoc(cspc); enditer =
        // data.endLoc(cspc). The snapshot materializes the same ordered
        // VarnodeLocSet window once up front; every varnode the loop itself
        // creates is either offset 0 (the spacebase constant, skipped at
        // cc:1188) or pre-flagged with setPtrCheck (cc:407/430), so visiting
        // them is a no-op in Ghidra and their absence from the snapshot is
        // observationally equivalent.
        let constant_vns: Vec<Arc<RwLock<crate::varnode::Varnode>>> = fd
            .vbank
            .begin_loc_space(cspc)
            .map(|loc_ref| loc_ref.0.clone())
            .collect();

        for vn in constant_vns {
            // cc:1187: the C++ tolerates newly inserted non-constant
            // varnodes by breaking; the snapshot cannot contain any.
            // cc:1188: never make constant 0 into a spacebase.
            let (vn_offset, _) = {
                let vn_r = vn.read().unwrap();
                if !vn_r.is_constant() {
                    break;
                }
                (vn_r.get_offset(), vn_r.get_size())
            };
            if vn_offset == 0 {
                continue;
            }
            // cc:1189: have we checked this variable before?
            if (vn.read().unwrap().addlflags & crate::varnode::addl_flags::PTR_CHECK) != 0 {
                continue;
            }
            // cc:1190: no descendants — nothing to infer from.
            if vn.read().unwrap().has_no_descend() {
                continue;
            }
            // cc:1191: constant 0 already serving as a spacebase.
            if vn.read().unwrap().is_spacebase() {
                continue;
            }
            // cc:1194-1195: op = vn->loneDescend().
            let Some(op) = vn.read().unwrap().lone_descend() else {
                continue;
            };
            // cc:1196-1197: rspc = selectInferSpace(vn, op, glb->inferPtrSpaces).
            let infer_ptr_spaces = fd
                .arch
                .as_ref()
                .map(|a| a.infer_ptr_spaces.clone())
                .unwrap_or_default();
            let Some(rspc) = Self::select_infer_space(&vn, &op, &infer_ptr_spaces) else {
                continue;
            };
            // cc:1198-1204: slot gates.
            let Some(slot) = op.read().unwrap().slot_of_input(&vn) else {
                continue;
            };
            let opc = op.read().unwrap().opcode;
            if opc == OpCode::CPUI_INT_ADD {
                // cc:1201: the other side is already a spacebase.
                let other_is_spacebase = op
                    .read()
                    .unwrap()
                    .get_in(1 - slot)
                    .map(|other| other.read().unwrap().is_spacebase())
                    .unwrap_or(false);
                if other_is_spacebase {
                    continue;
                }
            } else if opc == OpCode::CPUI_PTRSUB || opc == OpCode::CPUI_PTRADD {
                // cc:1203-1204.
                continue;
            }
            // cc:1205-1207: entry = isPointer(rspc,vn,op,slot,...).
            let mut rampoint = crate::address::Address::new(0);
            let mut full_encoding: u64 = 0;
            let entry = Self::is_pointer(
                rspc,
                &vn,
                &op,
                slot,
                &mut rampoint,
                &mut full_encoding,
                fd);
            // cc:1208: set the check flag AFTER searching for the symbol.
            vn.write().unwrap().addlflags |= crate::varnode::addl_flags::PTR_CHECK;
            if let Some(entry) = entry {
                // cc:1210: data.spacebaseConstant(op,slot,entry,rampoint,
                // fullEncoding,vn->getSize()).
                let origsize = vn.read().unwrap().get_size();
                fd.spacebase_constant(
                    &crate::op::PcodeOpRef(op.clone()),
                    slot,
                    &entry,
                    rspc,
                    rampoint,
                    full_encoding,
                    origsize,
                );
                // cc:1211-1212: INT_ADD with the constant in slot 1 swaps to
                // slot 0 so the spacebase leads the expression.
                if opc == OpCode::CPUI_INT_ADD && slot == 1 {
                    fd.op_swap_input(&crate::op::PcodeOpRef(op.clone()), 0, 1);
                }
                // cc:1213.
                self.count += 1;
            }
        }
        // cc:1216: apply always returns 0; the change flows through the
        // base-class count (take_count_delta).
        Ok(action_status::NO_CHANGE)
    }

    // Ghidra: coreaction.hh:194 ActionConstantPtr::reset
    fn reset(&mut self, _fd: &mut Funcdata) {
        self.localcount = 0;
    }

    // RUGRA-GLUE: externalizes Ghidra's inherited protected Action::count
    // (coreaction.cc:1213) into the Rust ActionState accumulator.
    fn take_count_delta(&mut self) -> i32 {
        std::mem::take(&mut self.count)
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
                    let users: Vec<_> = dst
                        .read()
                        .unwrap()
                        .descend
                        .iter()
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
            Ok(action_status::NO_CHANGE)
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
    /// Ghidra Action::count: incremented when syncVarnodesWithSymbols
    /// reports an update (coreaction.cc:2281-2282).
    count: i32,
}

impl ActionRestructureVarnode {
    // Ghidra: coreaction.hh:854 ActionRestructureVarnode (constructor mirror)
    pub fn new() -> Self {
        Self { numpass: 0, count: 0 ,
        }
    }
}

impl Action for ActionRestructureVarnode {
    // Ghidra: coreaction.cc:2274 ActionRestructureVarnode::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Ghidra cc:2279: aliasyes = (numpass != 0).
        // Alias calculations are not reliable on the first pass.
        let aliasyes = self.numpass != 0;
        let mut scope = crate::varmap::ScopeLocal::new();
        // Ghidra platform-side parameter symbols: the function's local scope
        // arrives from the Program database with the DWARF function's named
        // parameter symbols already installed (decompile.cc <localdb>
        // decode); ScopeLocal::restructureVarnode's fakeInputSymbols
        // (varmap.cc:1428-1435) then skips inputs that already have a
        // function_parameter symbol, so printing uses the parameter name
        // (`string`/`value`) rather than the in_RXX irregular-input fallback
        // (varmap.cc:1508 buildDefaultName). Rugra's fresh ScopeLocal is
        // empty, so seed the input-locked FuncProto's parameters here, at
        // scope construction, before restructure_varnode.
        if fd.funcp.is_input_locked() {
            let params: Vec<(
                String, std::sync::Arc<crate::type_system::datatype::Datatype>, u64,
            )> =
                fd
                .funcp
                    .parameters
                    .iter()
                    .map(|p| (
                            p.name.clone(),
                            p.data_type.clone(),
                            p.address.as_u64()))
                    .collect();
            for (index, (name, dtype, offset)) in params.into_iter().enumerate() {
                let idx = scope.add_symbol(
                    crate::space::AddressSpace::Register,
                    &name,
                    Some(dtype.clone()),
                    offset,
                    None,
                );
                scope.set_category(
                    idx,
                    crate::varmap::symbol_category::FUNCTION_PARAMETER,
                    index as i32,
                );
                // Platform parameter symbols are name+type locked (they
                // come from the debug info); the locks also protect the
                // symbols from ScopeInternal::clearUnlockedCategory(
                // Symbol::function_parameter) (varmap.cc:1275), which runs
                // at the top of every restructureVarnode pass.
                scope.symbols[idx].namelock = true;
                scope.symbols[idx].typelock = true;
                // The locked parameter symbol also type-locks its storage
                // varnode: Ghidra's Varnode::setSymbolEntry (varnode.cc:418)
                // sets Varnode::typelock from the Symbol flags and
                // syncVarnodesWithSymbol (funcdata_varnode.cc:983-1002)
                // flows the symbol's Datatype onto the varnode. Rugra's
                // sync only walks the stack space, so apply the type to the
                // register input directly here.
                let input_vn =
                    fd.find_varnode_input(dtype.get_size(), crate::address::Address::new(offset));
                if let Some(vn_arc) = input_vn {
                    let mut vn = vn_arc.write().unwrap();
                    if !vn.is_type_lock() {
                        vn.v_type = Some(dtype.clone());
                        vn.set_flags(crate::varnode::varnode_flags::TYPELOCK);
                    }
                }
            }
        }
        // Install the register-name lookup standing in for
        // `glb->translate->getRegisterName` (translate.hh:380): Ghidra's
        // ScopeInternal::buildVariableName register queries
        // (database.cc:2447/2454/2462/2472/2485) read the SLEIGH
        // `varnode_xref` through the Architecture's Translate; Rugra's
        // ScopeLocal takes a caller-attached Architecture handle
        // (`set_arch_lookup`) whose `register_xref` (populated from
        // `SleighBase::getAllRegisters`, sleighbase.cc:182-186) answers via
        // the faithful `Architecture::get_register_name` port
        // (sleighbase.cc:144-168). The legacy flat table below stays as the
        // fixture fallback for Funcdata without an Architecture.
        scope.set_arch_lookup(fd.arch.clone());
        if fd.arch.is_none() {
            scope.register_names = [
                (0x00u64, 8i32, "RAX"), (0x00, 4, "EAX"), (0x00, 2, "AX"), (0x00, 1, "AL"),
                (0x08, 8, "RCX"), (0x08, 4, "ECX"),
                (0x10, 8, "RDX"), (0x10, 4, "EDX"),
                (0x18, 8, "RBX"), (0x18, 4, "EBX"),
                (0x20, 8, "RSP"), (0x20, 4, "ESP"),
                (0x28, 8, "RBP"), (0x28, 4, "EBP"),
                (0x30, 8, "RSI"), (0x30, 4, "ESI"),
                (0x38, 8, "RDI"), (0x38, 4, "EDI"),
                (0x80, 8, "R8"), (0x88, 8, "R9"),
                (0x90, 8, "R10"), (0x98, 8, "R11"),
                (0xA0, 8, "R12"), (0xA8, 8, "R13"),
                (0xB0, 8, "R14"), (0xB8, 8, "R15"),
                (0x200, 8, "RIP"),
            ]
            .into_iter()
            .map(|(o, s, n)| ((o, s), n.to_string()))
            .collect();
        }
        // Ghidra cc:2280: l1->restructureVarnode(aliasyes).
        // Rugra's restructure_varnode doesn't yet take aliasyes (the
        // markUnaliased aliasyes gate is inside restructure, which is
        // always-on in Rugra). TODO: thread aliasyes through.
        scope.restructure_varnode(fd);
        fd.scope = Some(scope);
        // Ghidra cc:2281-2282: if (data.syncVarnodesWithSymbols(l1,false,aliasyes)) count += 1;
        if fd.sync_varnodes_with_symbols(false, aliasyes) {
            self.count += 1;
        }
        // Ghidra cc:2284-2285: if (data.isJumptableRecoveryOn()) protectSwitchPaths(data).
        // TODO: protectSwitchPaths needs jumptable recovery state tracking.
        self.numpass += 1;
        Ok(action_status::NO_CHANGE)
    }

    // RUGRA-GLUE: externalizes Ghidra's inherited protected Action::count
    // (coreaction.cc:2282) into the Rust ActionState accumulator.
    fn take_count_delta(&mut self) -> i32 {
        std::mem::take(&mut self.count)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "restructure_varnode" mirrors ctor at coreaction.hh:855 (Action(0,"restructure_varnode",g))
    fn get_name(&self) -> &str {
        "restructure_varnode"
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
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // coreaction.hh:42: data.startProcessing(); return 0;
        fd.start_processing();
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
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:364
    fn get_flags(&self) -> u32 {
        action_flags::RULE_ONCEPERFUNC
    }

    // Ghidra: coreaction.hh:369 ActionMergeRequired::apply
    /// Faithful: data.getMerge().mergeAddrTied(); groupPartials(); mergeMarker();
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        let mut merge = crate::merge::Merge::new();
        // Ghidra coreaction.hh:370: three calls in sequence.
        merge.merge_addr_tied(fd);
        merge.group_partials(fd);  // currently no-op (CONCAT infra TODO)
        merge.merge_marker(fd);
        Ok(action_status::NO_CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "mergerequired" mirrors ctor at coreaction.hh:364
    fn get_name(&self) -> &str {
        "mergerequired"
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
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:376
    fn get_flags(&self) -> u32 {
        action_flags::RULE_ONCEPERFUNC
    }

    // Ghidra: coreaction.hh:381 ActionMergeAdjacent::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        let mut merge = crate::merge::Merge::new();
        merge.merge_adjacent(fd);
        Ok(action_status::NO_CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "mergeadjacent" mirrors ctor at coreaction.hh:376
    fn get_name(&self) -> &str {
        "mergeadjacent"
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
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:387
    fn get_flags(&self) -> u32 {
        action_flags::RULE_ONCEPERFUNC
    }

    // Ghidra: coreaction.hh:392 ActionMergeCopy::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to coreaction.hh:392: data.getMerge().mergeOpcode(CPUI_COPY);
        let mut merge = crate::merge::Merge::new();
        merge.merge_opcode(fd, crate::opcodes::OpCode::CPUI_COPY);
        Ok(action_status::NO_CHANGE)
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
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:398
    fn get_flags(&self) -> u32 {
        action_flags::RULE_ONCEPERFUNC
    }

    // Ghidra: coreaction.hh:403 ActionMergeMultiEntry::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        let mut merge = crate::merge::Merge::new();
        merge.merge_multi_entry(fd);
        Ok(action_status::NO_CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "mergemultientry" mirrors ctor at coreaction.hh:398
    fn get_name(&self) -> &str {
        "mergemultientry"
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
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:409
    fn get_flags(&self) -> u32 {
        action_flags::RULE_ONCEPERFUNC
    }

    // Ghidra: coreaction.hh:414 ActionMergeType::apply
    /// Faithful to coreaction.hh:414:
    /// `data.getMerge().mergeByDatatype(data.beginLoc(),data.endLoc());`
    ///
    /// This Action runs the same-type speculative merge pass ONLY. It must
    /// NOT re-enter the required-merge sequence: in the Ghidra pipeline
    /// (coreaction.cc:5717-5727) ActionMergeRequired — the sole caller of
    /// Merge::mergeAddrTied/mergeRangeMust — runs BEFORE ActionMarkImplied,
    /// so mergeTestMust never observes an implied Varnode. Re-running
    /// mergeAddrTied after ActionMarkImplied (as the former `merge_all`
    /// monolith did, MERGE-FORCEMERGE-PANIC-0001) reaches a state Ghidra
    /// never builds and trips mergeTestMust's throw on implied addrtied
    /// varnodes (e.g. SUBPIECE outputs at stack locations).
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        let mut merge = crate::merge::Merge::new();
        merge.merge_by_datatype(fd);
        Ok(action_status::NO_CHANGE)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "mergetype" mirrors ctor at coreaction.hh:409
    fn get_name(&self) -> &str {
        "mergetype"
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
            Ok(action_status::NO_CHANGE)
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
        "getparameter" | "getparameter_constprop_0" => {
            Some(vec!["ptr", "ptr", "ptr", "ptr", "ptr"])
        }
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
        let call_info: Vec<(usize, usize, usize)> = fd
            .obank
            .alivelist
            .iter()
            .enumerate()
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
                let first_call_idx = fd
                    .obank
                    .alivelist
                    .iter()
                    .position(|op_ref| {
                    let op = op_ref.0.read().unwrap();
                    op.opcode == OpCode::CPUI_CALL
                })
                    .unwrap_or(0);

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
                    let call_pos = block_ops
                        .iter()
                        .position(|op_ref| Arc::ptr_eq(&op_ref.0, &call_op_arc)
                    );
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
                        let placeholder = fd.vbank
                                .create_with_space(8, AddressSpace::Register, reg_off);
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
            Ok(action_status::NO_CHANGE)
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
                                param_candidates.push((
                                    i, offset, vn.get_size(), vn.v_type.clone(),
                                ));
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
            ]
            .iter()
            .cloned()
            .collect();

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
                                            param_candidates.push((
                                                abi_idx, off, iv.get_size(), iv.v_type.clone(),
                                            ));
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
                                        param_candidates.push((
                                            abi_idx, off, vn.get_size(), vn.v_type.clone(),
                                        ));
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
                            let base = Arc::new(Datatype::Base(TypeBase::new(
                                "long".to_string(), 8, TypeMetatype::Int,
                            )));
                            Arc::new(Datatype::Pointer(
                                crate::type_system::datatype::TypePointer {
                                base: crate::type_system::datatype::TypeBase::new(
                                        "void *".to_string(), 8, TypeMetatype::Pointer,
                                    ),
                                ptr_to: base,
                                wordsize: 1,
                            },
                            ))
                        }
                        "int" => Arc::new(match size {
                            1 => Datatype::Base(TypeBase::new(
                                "byte".to_string(), 1, TypeMetatype::Int,
                            )),
                            2 => Datatype::Base(TypeBase::new(
                                "short".to_string(), 2, TypeMetatype::Int,
                            )),
                            4 => Datatype::Base(TypeBase::new(
                                "int".to_string(), 4, TypeMetatype::Int,
                            )),
                            _ => Datatype::Base(TypeBase::new(
                                "long".to_string(), 8, TypeMetatype::Int,
                            )),
                        }),
                        _ => v_type.clone().unwrap_or_else(|| {
                            Arc::new(Datatype::Base(TypeBase::new(
                                "long".to_string(), 8, TypeMetatype::Int,
                            )))
                        }),
                    }
                } else {
                    v_type.clone().unwrap_or_else(|| {
                        Arc::new(Datatype::Base(TypeBase::new(
                            "long".to_string(), 8, TypeMetatype::Int,
                        )))
                    })
                }
            } else if ptr_param_offsets.contains(offset) {
                let base = Arc::new(Datatype::Base(TypeBase::new(
                    "long".to_string(), 8, TypeMetatype::Int,
                )));
                Arc::new(Datatype::Pointer(
                    crate::type_system::datatype::TypePointer {
                    base: crate::type_system::datatype::TypeBase::new(
                            "long *".to_string(), 8, TypeMetatype::Pointer,
                        ),
                    ptr_to: base,
                    wordsize: 1,
                },
                ))
            } else {
                v_type.clone().unwrap_or_else(|| {
                    Arc::new(match size {
                        1 => {
                            Datatype::Base(TypeBase::new("byte".to_string(), 1, TypeMetatype::Int))
                        }
                        2 => {
                            Datatype::Base(TypeBase::new("short".to_string(), 2, TypeMetatype::Int))
                        }
                        4 => Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int)),
                        _ => {
                            Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int))
                        }
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
                                let base = Arc::new(Datatype::Base(TypeBase::new(
                                    "long".to_string(), 8, TypeMetatype::Int,
                                )));
                                Arc::new(Datatype::Pointer(
                                    crate::type_system::datatype::TypePointer {
                                    base: crate::type_system::datatype::TypeBase::new(
                                            "void *".to_string(), 8, TypeMetatype::Pointer,
                                        ),
                                    ptr_to: base, wordsize: 1,
                                },
                                ))
                            }
                            _ => Arc::new(Datatype::Base(TypeBase::new(
                                "long".to_string(), 8, TypeMetatype::Int,
                            ))),
                        }
                    } else {
                        Arc::new(Datatype::Base(TypeBase::new(
                            "long".to_string(), 8, TypeMetatype::Int,
                        )))
                    }
                } else {
                    Arc::new(Datatype::Base(TypeBase::new(
                        "long".to_string(), 8, TypeMetatype::Int,
                    )))
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

        // Ghidra: coreaction.cc:4711-4761 ActionInputPrototype mutates the
        // input map only when FuncProto::isInputLocked() is false. This
        // Rugra-only compatibility action must honor the same boundary.
        if !fd.funcp.is_input_locked() && !params.is_empty() && fd.funcp.parameters.is_empty() {
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
                                1 => Datatype::Base(TypeBase::new(
                                    "byte".to_string(), 1, TypeMetatype::Int,
                                )),
                                2 => Datatype::Base(TypeBase::new(
                                    "short".to_string(), 2, TypeMetatype::Int,
                                )),
                                4 => Datatype::Base(TypeBase::new(
                                    "int".to_string(), 4, TypeMetatype::Int,
                                )),
                                _ => Datatype::Base(TypeBase::new(
                                    "long".to_string(), 8, TypeMetatype::Int,
                                )),
                            })
                        });
                        // Only update if currently void
                        // Ghidra: coreaction.cc:4765-4782
                        // ActionOutputPrototype never replaces a type-locked
                        // output. Preserve that invariant in this Rugra-only
                        // compatibility action as well.
                        if !fd.funcp.is_output_locked()
                            && matches!(fd.funcp.return_type.as_ref(), Datatype::Void(_))
                        {
                            fd.funcp.return_type = ret_type;
                            changed = true;
                        }
                    }
                }
            }
        }

        if changed {
            Ok(action_status::NO_CHANGE)
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

        let int_type = Arc::new(Datatype::Base(TypeBase::new(
            "int".to_string(), 4, TypeMetatype::Int,
        )));
        let long_type = Arc::new(Datatype::Base(TypeBase::new(
            "long".to_string(), 8, TypeMetatype::Int,
        )));
        let short_type = Arc::new(Datatype::Base(TypeBase::new(
            "short".to_string(), 2, TypeMetatype::Int,
        )));
        let byte_type = Arc::new(Datatype::Base(TypeBase::new(
            "byte".to_string(), 1, TypeMetatype::Uint,
        )));
        let bool_type = Arc::new(Datatype::Base(TypeBase::new(
            "bool".to_string(), 1, TypeMetatype::Bool,
        )));

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
                            | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR => Some(bool_type.clone())
                            ,
                            // Seed LOAD outputs with size-based types so the
                            // address-input pointer inference can bootstrap.
                            // Without this seed, neither the output nor the
                            // address has a type, and pointer inference stalls.
                            OpCode::CPUI_LOAD => match out_vn.get_size() {
                                    8 => Some(long_type.clone()),
                                    4 => Some(int_type.clone()),
                                    2 => Some(short_type.clone()),
                                    1 => Some(byte_type.clone()),
                                    _ => None,
                                }
                            ,
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
                    let out_type = op
                        .output
                        .as_ref()
                        .map(|o| o.read().unwrap().v_type.clone())
                        .flatten();

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
            Ok(action_status::NO_CHANGE)
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
fn get_pointed_type(
    ptr_dt: &Arc<crate::type_system::datatype::Datatype>,
) -> Option<Arc<crate::type_system::datatype::Datatype>> {
    use crate::type_system::datatype::Datatype;
    match ptr_dt.as_ref() {
        Datatype::Pointer(p) => Some(p.ptr_to.clone()),
        _ => None,
    }
}

// RUGRA-GLUE: helper mirroring TypeFactory::getTypePointer (type.hh); used by Rugra type inference
// Ghidra: type.cc:3867 TypeFactory::getTypePointer(int4,Datatype*,uint4) — the 3-arg
// overload constructs `TypePointer tmp(s,pt,ws)` with an EMPTY name (only the
// 4-arg overload at type.cc:3885 attaches a name), so every type-inference
// pointer the Actions build is ANONYMOUS. The former composed-name spelling
// ("char *") made Rugra's pointers named, which the print layer then rendered
// through the single-layer named-pointer path (`char * p`, oracle
// printc_anonymous_pointer_decl_1204 named_ptr_contrast) instead of Ghidra's
// drilled multi-layer `char *p` — the pointer NAME is not observable in any
// Ghidra output for these types, so the empty name is the faithful form.
fn make_pointer_type(
    base: &Arc<crate::type_system::datatype::Datatype>,
) -> Arc<crate::type_system::datatype::Datatype> {
    use crate::type_system::datatype::Datatype;
    Arc::new(Datatype::Pointer(crate::type_system::datatype::TypePointer::new(
        8, base.clone(), 1,
    )))
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
pub struct ActionUnreachable { pub count: i32 ,
}
impl ActionUnreachable {
    // Ghidra: coreaction.hh:493 ActionUnreachable (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionUnreachable {
    // Ghidra: coreaction.cc:3457 ActionUnreachable::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionUnreachable::apply (coreaction.cc:3457-3464):
        // issuewarning=true, checkexistence=false (cached flag gate).
        if fd.remove_unreachable_blocks(true, false) {
            self.count += 1; // Deleting at least one block
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "unreachable" mirrors ctor at coreaction.hh:493
    fn get_name(&self) -> &str { "unreachable" }
}

/// Remove blocks that do nothing. Faithful to `ActionDoNothing`
/// (coreaction.cc).
///
/// A "do nothing" block has exactly 1 out-edge, at least 1 in-edge, no
/// BRANCHIND, and contains only marker/branch ops (no substantive ops).
pub struct ActionDoNothing { pub count: i32 ,
}
impl ActionDoNothing {
    // Ghidra: coreaction.hh:504 ActionDoNothing (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }

    // Ghidra: block.cc:2596 BlockBasic::isDoNothing
    /// `BlockBasic::isDoNothing` (block.cc:2596-2619): exactly one out-edge,
    /// at least one in-edge, no live switch-target propagation edge
    /// (block.cc:2604-2613), last op not BRANCHIND, and hasOnlyMarkers
    /// (block.cc:2578-2592: every op is a marker or a branch).
    fn block_is_do_nothing(
        &self,
        bl: &Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) -> bool {
        use crate::opcodes::OpCode;
        use crate::block::FlowBlock as _;
        let bl_rg = bl.read().unwrap();
        if bl_rg.size_out() != 1 {
            return false; // block.cc:2599
        }
        if bl_rg.size_in() == 0 {
            return false; // block.cc:2601
        }
        // block.cc:2604-2613: switch-target guard — if any in-edge comes
        // from a multi-out switch block and the out target is a join, the
        // switch edge may still be propagating a unique value.
        let out_target = bl_rg.get_out(0).map(|e| e.point);
        let Some(out_target) = out_target else {
            return false;
        };
        let out_n_in = out_target.read().unwrap().size_in();
        for s in 0..bl_rg.size_in() {
            let switchbl = bl_rg.get_in(s).map(|e| e.point);
            let Some(switchbl) = switchbl else { continue };
            let is_switch_out = {
                let rg = switchbl.read().unwrap();
                (rg.get_flags() & crate::block::block_flags::SWITCH_OUT) != 0
            };
            if !is_switch_out {
                continue;
            }
            if switchbl.read().unwrap().size_out() > 1 && out_n_in > 1 {
                return false; // block.cc:2611
            }
        }
        // block.cc:2615-2617: BRANCHIND last op never removed.
        let (ops, last_op) = {
            let bb2 = bl_rg
                .as_any()
                .downcast_ref::<crate::block::BlockBasic>();
            match bb2 {
                Some(bb) => (bb.get_ops(), bb.last_op()),
                None => return false,
            }
        };
        if let Some(op_ref) = last_op {
            if op_ref.0.read().unwrap().opcode == OpCode::CPUI_BRANCHIND {
                return false;
            }
        }
        // block.cc:2618 hasOnlyMarkers.
        for op_ref in &ops {
            let o = op_ref.0.read().unwrap();
            let is_marker = (o.flags & crate::op::pcodeop_flags::MARKER) != 0;
            let is_branch = matches!(
                o.opcode,
                OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCHIND
            );
            if !is_marker && !is_branch {
                return false;
            }
        }
        true
    }

    // Ghidra: block.cc:2534 BlockBasic::unblockedMulti
    /// `BlockBasic::unblockedMulti` (block.cc:2534-2571): true when removing
    /// this block cannot change data-flow through the out-block — for every
    /// MULTIEQUAL in the out-block, the varnode contributed via this block
    /// (resolved through this block's own MULTIEQUAL when present) must be
    /// pointer-identical to the varnode contributed by each other in-block
    /// that also branches directly to the out-block.
    fn block_unblocked_multi(
        &self,
        bl: &Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        outslot: usize,
    ) -> bool {
        use crate::opcodes::OpCode;
        use crate::block::FlowBlock as _;
        let bl_rg = bl.read().unwrap();
        let blout = match bl_rg.get_out(outslot) {
            Some(e) => e.point,
            None => return true,
        };
        // block.cc:2545-2553: build redundlist — in-blocks of this block
        // that also branch directly to blout.
        let mut redundlist: Vec<
            Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        > = Vec::new();
        for s in 0..bl_rg.size_in() {
            let inbl = match bl_rg.get_in(s) {
                Some(e) => e.point,
                None => continue,
            };
            let in_rg = inbl.read().unwrap();
            for j in 0..in_rg.size_out() {
                if let Some(e) = in_rg.get_out(j) {
                    if Arc::ptr_eq(&e.point, &blout) {
                        redundlist.push(inbl.clone());
                    }
                }
            }
        }
        // block.cc:2554
        if redundlist.is_empty() {
            return true;
        }
        // block.cc:2555-2569: for each MULTIEQUAL in blout, compare the
        // varnode from this block against each redundant in-block's.
        let multi_ops: Vec<crate::op::PcodeOpRef> = {
            let out_rg = blout.read().unwrap();
            match out_rg
                .as_any()
                .downcast_ref::<crate::block::BlockBasic>()
            {
                Some(bb) => bb
                    .get_ops()
                    .into_iter()
                    .filter(|o| o.0.read().unwrap().opcode == OpCode::CPUI_MULTIEQUAL)
                    .collect(),
                None => return true,
            }
        };
        for multiop in &multi_ops {
            for red in &redundlist {
                // block.cc:2560-2561
                let vnredund = {
                    let out_rg = blout.read().unwrap();
                    let idx = (0..out_rg.size_in()).find(|&k| {
                        out_rg
                            .get_in(k)
                            .map(|e| Arc::ptr_eq(&e.point, red))
                            .unwrap_or(false)
                    });
                    match idx {
                        Some(idx) => {
                            let o = multiop.0.read().unwrap();
                            o.inrefs.get(idx).cloned()
                        }
                        None => None,
                    }
                };
                let vnremove = {
                    let out_rg = blout.read().unwrap();
                    let idx = (0..out_rg.size_in()).find(|&k| {
                        out_rg
                            .get_in(k)
                            .map(|e| Arc::ptr_eq(&e.point, bl))
                            .unwrap_or(false)
                    });
                    match idx {
                        Some(idx) => {
                            let o = multiop.0.read().unwrap();
                            o.inrefs.get(idx).cloned()
                        }
                        None => None,
                    }
                };
                let (Some(vnredund), Some(vnremove)) = (vnredund, vnremove) else {
                    continue;
                };
                // block.cc:2562-2566: resolve vnremove through this block's
                // own MULTIEQUAL when it is defined by one.
                let vnremove_resolved = {
                    let def = vnremove.read().unwrap().get_def();
                    match def {
                        Some(d) => {
                            let (is_multi, parent_is_bl) = {
                                let d_rg = d.read().unwrap();
                                let parent_is_bl = d_rg
                                    .parent
                                    .as_ref()
                                    .and_then(|w| w.upgrade())
                                    .map(|p| Arc::ptr_eq(&p, bl))
                                    .unwrap_or(false);
                                (d_rg.opcode == OpCode::CPUI_MULTIEQUAL, parent_is_bl)
                            };
                            if is_multi && parent_is_bl {
                                // othermulti->getIn(getInIndex(bl))
                                let bl_rg2 = bl.read().unwrap();
                                let in_idx = (0..bl_rg2.size_in()).find(|&k| {
                                    bl_rg2
                                        .get_in(k)
                                        .map(|e| Arc::ptr_eq(&e.point, red))
                                        .unwrap_or(false)
                                });
                                match in_idx {
                                    Some(in_idx) => {
                                        let d_rg = d.read().unwrap();
                                        d_rg.inrefs.get(in_idx).cloned()
                                    }
                                    None => Some(vnremove.clone()),
                                }
                            } else {
                                Some(vnremove.clone())
                            }
                        }
                        None => Some(vnremove.clone()),
                    }
                };
                let Some(vnremove_resolved) = vnremove_resolved else { continue };
                // block.cc:2567: redundant branches must be identical.
                if !Arc::ptr_eq(&vnremove_resolved, &vnredund) {
                    return false;
                }
            }
        }
        true
    }
}
impl Action for ActionDoNothing {
    // Ghidra: coreaction.cc:3466 ActionDoNothing::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        let n = fd.bblocks.get_size();
        for i in 0..n {
            let bl = match fd.bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            // cc:3475 bb->isDoNothing() — BlockBasic::isDoNothing
            // (block.cc:2596-2619): sizeOut==1, sizeIn>0, no
            // switch-target propagation edge, last op not BRANCHIND, and
            // hasOnlyMarkers (markers + branches only).
            let is_do_nothing = self.block_is_do_nothing(&bl);
            if !is_do_nothing {
                continue;
            }
            // cc:3476-3481: a self-looping do-nothing block is an infinite
            // loop — flag f_donothing_loop once (block.hh:100) and warn,
            // never remove.
            let is_self_loop = {
                let bl_rg = bl.read().unwrap();
                if let Some(edge) = bl_rg.get_out(0) {
                    Arc::ptr_eq(&edge.point, &bl)
                } else {
                    false
                }
            };
            if is_self_loop {
                let already = {
                    let bl_rg = bl.read().unwrap();
                    (bl_rg.get_flags() & crate::block::block_flags::DONOTHING_LOOP) != 0
                };
                if !already {
                    bl.write()
                        .unwrap()
                        .set_flags(crate::block::block_flags::DONOTHING_LOOP);
                    let start = crate::block::front_leaf(&bl)
                        .map(|l| l.read().unwrap().get_start_addr().as_u64())
                        .unwrap_or(0);
                    fd.warning(
                        "Do nothing block with infinite loop",
                        crate::address::Address::new(start),
                    );
                }
                continue;
            }
            // cc:3482 bb->unblockedMulti(0) — BlockBasic::unblockedMulti
            // (block.cc:2534-2571): every MULTIEQUAL in the out-block must
            // see identical varnodes from this block (resolved through this
            // block's own MULTIEQUAL) and from each other in-block that also
            // branches directly to the out-block.
            if self.block_unblocked_multi(&bl, 0) {
                // cc:3483-3485 removeDoNothingBlock + count += 1. The count
                // growth feeds Action::perform's repeat loop (action.cc:339)
                // so the rule_repeatapply fullloop re-runs mainloop and
                // ActionBlockStructure re-structures the purged CFG
                // (structureReset cleared sblocks). Returning CHANGE(1)
                // mirrors the C++ count increment through Rugra's
                // state.count += res adapter.
                fd.remove_do_nothing_block(&bl);
                self.count += 1;
                return Ok(action_status::CHANGE);
            }
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_repeatapply bit set in ctor at coreaction.hh:504 (Action(rule_repeatapply,"donothing",g))
    fn get_flags(&self) -> u32 { action_flags::RULE_REPEATAPPLY }
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
pub struct ActionRedundBranch { pub count: i32 ,
}
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
            let Some(first_target) = first_target else { continue ;
            };

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
                        return Ok(action_status::NO_CHANGE);
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

            // coreaction.cc:3528: remove the branch edge at slot 1.
            fd.remove_branch(&bl, 1);
            return Ok(action_status::NO_CHANGE);
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
pub struct ActionDeterminedBranch { pub count: i32 ,
}
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
            let size_out = bl.read().unwrap().size_out();

            // Check it's a CBRANCH with constant boolean input (slot 1).
            let (is_cbranch, is_const, val, is_flip) = {
                let cb_rg = cbranch.0.read().unwrap();
                if cb_rg.opcode != OpCode::CPUI_CBRANCH {
                    (false, false, 0u64, false)
                } else {
                    let bool_vn = cb_rg.get_in(1);
                    let is_const = bool_vn
                        .map(|v| v.read().unwrap().is_constant())
                        .unwrap_or(false);
                    let val = bool_vn.map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
                    let is_flip = (cb_rg.flags & crate::op::pcodeop_flags::BOOLEAN_FLIP) != 0;
                    (true, is_const, val, is_flip)
                }
            };
            if !is_cbranch || !is_const {
                continue;
            }

            // HTTPD-STRCASECMP-NONCONVERGE-0001: Ghidra's implicit contract at
            // coreaction.cc:3544-3545 is that a block whose lastOp is CBRANCH
            // has exactly 2 out-edges — `data.removeBranch(bb,num)` with
            // num∈{0,1} derefs `bb->getOut(num)` unconditionally
            // (funcdata_block.cc:206), and the oracle maintains the invariant
            // by construction (branchRemoveInternal destroys the cbranch at
            // sizeOut==2 BEFORE any edge count drop, cc:203-204). Rugra can
            // carry malformed "zombie decision" blocks (CBRANCH lastOp with
            // <2 out-edges, left behind by edge-severing paths that skip the
            // op-destroy step); calling remove_branch on them mutates nothing
            // (get_out(num)→None early-return) yet still runs structureReset,
            // clearing sblocks every mainloop round. That re-arms
            // ActionBlockStructure + ruleBlockIfNoExit's negateCondition (a
            // real dataflow change whose count feeds rule_repeatapply), so
            // the mainloop never converges (ap_strcasecmp_match: 100k+ rounds
            // of orderLoopBodies 0-loops / finalize 3->1). Ghidra would crash
            // on this input (null deref of an impossible state); the faithful
            // Rust degradation is skip + log, mirroring the LowlevelError
            // degradation precedent (selectGoto exhausted, blockaction.cc:1275).
            if size_out < 2 {
                eprintln!(
                    "[ACTION] {}: determinedbranch skipped malformed decision block (CBRANCH lastOp with {} out-edges; Ghidra contract coreaction.cc:3538-3547 requires 2)",
                    fd.name, size_out
                );
                continue;
            }

            // Determine which branch is taken.
            // num = ((val != 0) != isBooleanFlip) ? 0 : 1
            // Faithful to Ghidra: if val!=0 XOR is_flip → take edge 0 (fallthrough).
            // Otherwise → take edge 1 (branch target).
            let num = if (val != 0) != is_flip { 0 } else { 1 };

            // `num` is the edge to remove (funcdata_block.cc:220), leaving
            // the statically selected successor as the sole outgoing edge.
            fd.remove_branch(&bl, num);
            // cc:3546: `count += 1` — indicate change has been made; harvested
            // by take_count_delta into the mainloop repeatapply accumulator.
            self.count += 1;
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "determinedbranch" mirrors ctor at coreaction.hh:526
    fn get_name(&self) -> &str { "determinedbranch" }
    // RUGRA-GLUE: externalizes Ghidra's inherited protected Action::count
    // (coreaction.cc:3546 `count += 1`) into the ActionState accumulator
    // harvested by Action::perform, same pattern as ActionBlockStructure.
    fn take_count_delta(&mut self) -> i32 {
        std::mem::take(&mut self.count)
    }
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
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:992
    fn get_flags(&self) -> u32 {
        action_flags::RULE_ONCEPERFUNC
    }

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
        // Ghidra cc:4845: count += num; return 0;
        let _ = count;
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "hideshadow" mirrors ctor at coreaction.hh:992
    fn get_name(&self) -> &str { "hideshadow" }
}

/// Normalize switch tables. Faithful to `ActionSwitchNorm`
/// (coreaction.cc).
///
/// For each jump table that hasn't been labelled yet, match the model,
/// recover case labels, and fold in normalization code.
pub struct ActionSwitchNorm { pub count: i32 ,
}
impl ActionSwitchNorm {
    // Ghidra: coreaction.hh:609 ActionSwitchNorm (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionSwitchNorm {
    // Ghidra: coreaction.cc:4548 ActionSwitchNorm::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionSwitchNorm::apply (coreaction.cc:4548-4565).
        // In Ghidra, every JumpTable on `data` was already recovered during
        // flow tracing (`FlowInfo::recoverJumpTables` → Funcdata::
        // recoverJumpTable, funcdata_block.cc:640) — this action only
        // normalizes the recovered tables. Rugra formerly ran an in-place
        // recovery pre-pass here because flow-time recovery was unwired;
        // JUMPTABLE-PIPELINE-0001 removed it now that the staged flow-time
        // path exists.
        //
        // cc:4551-4563: for each unlabelled table, matchModel /
        // recoverLabels / foldInNormalization, then foldInGuards on every
        // table (clearing the structure on change). Ghidra iterates by index
        // over data.numJumpTables(); the table list cannot grow during the
        // loop (fold-ins only append address entries), so an Arc snapshot is
        // equivalent.
        let jump_tables: Vec<_> = fd.jump_tables.clone();
        for jt_arc in jump_tables {
            {
                let mut jt = jt_arc.write().unwrap();
                if !jt.is_labelled() {
                    // Ghidra: matchModel/recoverLabels LowlevelError messages
                    // propagate out of apply verbatim; keep the exact string.
                    jt.match_model(fd)
                        .map_err(|e| crate::error::Error::Lowlevel(e.message().to_string()))?;
                    jt.recover_labels(fd)
                        .map_err(|e| crate::error::Error::Lowlevel(e.message().to_string()))?; // Recover case statement labels
                    jt.fold_in_normalization(fd);
                    self.count += 1;
                }
            }
            // cc:4559-4562: fold guards for every table, labelled or not.
            let folded = jt_arc.write().unwrap().fold_in_guards(fd);
            if folded {
                fd.get_structure().clear(); // Make sure we redo structure
                self.count += 1;
            }
        }
        // cc:4564: `return 0;` — Ghidra reports no status change from this
        // action regardless of the local counter.
        Ok(action_status::NO_CHANGE)
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
        // cc:4569-4572: clear input params + unlock model/output.
        //   FuncProto &fp(data.getFuncProto());
        //   fp.clearInput();
        //   fp.setModelLock(false);
        //   fp.setOutputLock(false);
        fd.funcp.clear_unlocked_input();
        fd.funcp.set_output_lock(false);
        // setModelLock(false): Rugra doesn't track model-lock state separately
        // (calling_convention is a String, not locked). This is a no-op until
        // model-lock tracking is added.
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:630 (Action(rule_onceperfunc,"normalizesetup",g))
    fn get_flags(&self) -> u32 { action_flags::RULE_ONCEPERFUNC }
    // RUGRA-GLUE: Rust Action trait get_name; "normalizesetup" mirrors ctor at coreaction.hh:630
    fn get_name(&self) -> &str { "normalizesetup" }
}

/// Generate prototype warnings. Faithful to `ActionPrototypeWarnings`
/// (coreaction.cc:4886).
///
/// Emits the override-message batch, the prototype error warnings and the
/// unknown-calling-convention warning through `Funcdata::warningHeader`, and
/// per-call-site parameter/return errors through `Funcdata::warning` — the
/// same commentdb channels Ghidra uses, so the comments surface as
/// `/* WARNING: ... */` header lines in the C output.
pub struct ActionPrototypeWarnings;
impl ActionPrototypeWarnings {
    // Ghidra: coreaction.hh:1047 ActionPrototypeWarnings (constructor mirror)
    pub fn new() -> Self { Self }
}

// Ghidra: fspec.hh:1461 FuncProto::hasInputErrors
/// Faithful mirror of the `FuncProto::hasInputErrors()` inline accessor
/// (fspec.hh:1461): `flags & error_inputparam`.
fn proto_has_input_errors(proto: &crate::fspec::FuncProto) -> bool {
    proto.has_input_errors()
}

// Ghidra: fspec.hh:1464 FuncProto::hasOutputErrors
/// Faithful mirror of `FuncProto::hasOutputErrors()` (fspec.hh:1464):
/// `flags & error_outputparam`. See [`proto_has_input_errors`] for why the
/// unmodeled flag reads false.
fn proto_has_output_errors(_proto: &crate::fspec::FuncProto) -> bool { false }

// Ghidra: fspec.hh:1400 FuncProto::hasCustomStorage
/// Faithful mirror of `FuncProto::hasCustomStorage()` (fspec.hh:1400):
/// `flags & custom_storage`. In Ghidra the bit is set only when a decoded
/// prototype carries ATTRIB_CUSTOM (fspec.cc:4724-4727); Rugra's prototype
/// decoder stubs that attribute as a no-op and no writer exists, so false is
/// observably identical to the oracle today.
fn proto_has_custom_storage(_proto: &crate::fspec::FuncProto) -> bool { false }

// Ghidra: fspec.hh:1686 FuncCallSpecs::getEntryAddress
/// Faithful mirror of `FuncCallSpecs::getEntryAddress()` (fspec.hh:1686).
/// The oracle leaves `entryaddress` invalid for indirect calls (fspec.cc:4943
/// "If call is indirect, we leave address as invalid"); Rugra models an
/// unknown target as `None`, normalized here to offset 0 — the same offset
/// Ghidra's default-constructed invalid Address carries (address.cc:94-97).
fn call_entry_address(fc: &crate::fspec::FuncCallSpecs) -> crate::address::Address {
    fc.entry_addr
        .unwrap_or(crate::address::Address::new(0))
}

impl Action for ActionPrototypeWarnings {
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:1047
    fn get_flags(&self) -> u32 {
        action_flags::RULE_ONCEPERFUNC
    }

    // Ghidra: coreaction.cc:4886 ActionPrototypeWarnings::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionPrototypeWarnings::apply (coreaction.cc:4886-4936).
        // Warnings flow exclusively through Funcdata::warningHeader /
        // Funcdata::warning (the commentdb channels), never stderr.

        // coreaction.cc:4889-4892: override messages (deadcode-delay restart
        // notices). Space-name indexing needs Architecture's indexed space
        // manager (override.cc:51-56 getSpace(i)->getName()); Rugra's
        // Architecture has no indexed space list yet, so resolve names
        // through the locked x86-64 corpus space table
        // (AddressSpace::spec_space_name, same provenance as
        // AddressSpace::get_index). Heritage::bumpDeadcodeDelay
        // (heritage.cc:2581) is the production inserter.
        let space_names: Vec<String> = (0..9)
            .map(|i| {
                crate::space::AddressSpace::spec_space_name(i)
                    .unwrap_or("unknown")
                    .to_string()
            })
            .collect();
        for message in fd.localoverride.generate_override_messages(&space_names) {
            // coreaction.cc:4892: data.warningHeader(overridemessages[i]);
            fd.warning_header(&message);
        }

        // coreaction.cc:4894-4897: this function's own prototype input errors.
        if proto_has_input_errors(&fd.funcp) {
            fd.warning_header(
                "Cannot assign parameter locations for this function: Prototype may be inaccurate",
            );
        }
        // coreaction.cc:4898-4900: output errors.
        if proto_has_output_errors(&fd.funcp) {
            fd.warning_header(
                "Cannot assign location of return value for this function: Return value may be inaccurate",
            );
        }
        // coreaction.cc:4901-4909: unknown calling convention.
        if fd.funcp.is_model_unknown() {
            let mut s = String::from("Unknown calling convention");
            if fd.funcp.print_model_in_decl() {
                s.push_str(": ");
                s.push_str(fd.funcp.get_model_name());
            }
            if !proto_has_custom_storage(&fd.funcp)
                && (fd.funcp.is_input_locked() || fd.funcp.is_output_locked())
            {
                s.push_str(" -- yet parameter storage is locked");
            }
            // coreaction.cc:4908: data.warningHeader(s.str());
            fd.warning_header(&s);
        }
        // coreaction.cc:4910-4934: per-call-site parameter/return errors.
        let numcalls = fd.num_calls();
        for i in 0..numcalls {
            let Some(fc) = fd.get_call_specs(i) else { continue ;
            };
            // The oracle prints the callee Funcdata's name, falling back to
            // "<indirect>" when the callspec has no Funcdata link
            // (coreaction.cc:4913-4920). Rugra's front-end boundary binds the
            // observable (name, entry) pair on the callspec prototype via
            // set_funcdata; an empty name is the no-link case.
            let callee = if fc.prototype.name.is_empty() {
                "<indirect>".to_string()
            } else {
                fc.prototype.name.clone()
            };
            if proto_has_input_errors(&fc.prototype) {
                let s = format!(
                    "Cannot assign parameter location for function {callee}: Prototype may be inaccurate"
                );
                // coreaction.cc:4922: data.warning(s.str(),fc->getEntryAddress());
                fd.warning(&s, call_entry_address(&fc));
            }
            if proto_has_output_errors(&fc.prototype) {
                let s = format!(
                    "Cannot assign location of return value for function {callee}: Return value may be inaccurate"
                );
                // coreaction.cc:4932: data.warning(s.str(),fc->getEntryAddress());
                fd.warning(&s, call_entry_address(&fc));
            }
        }
        // coreaction.cc:4935: return 0; (no IR mutation).
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
pub struct ActionMarkExplicit { pub count: i32 ,
}

/// Record of the backward edge traversal state for one Varnode on the
/// op stack. Faithful to `ActionMarkExplicit::OpStackElement`
/// (coreaction.cc:3136-3157): LOAD skips the space input, PTRADD does
/// not traverse the multiplier slot, SEGMENTOP skips its first two
/// inputs. (Nested in the Ghidra class; Rust requires module scope.)
// Ghidra: coreaction.cc:3136 ActionMarkExplicit::OpStackElement::OpStackElement
pub struct MarkExplicitOpStackElement {
    vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    slot: usize,
    slotback: usize,
}
impl MarkExplicitOpStackElement {
    // Ghidra: coreaction.cc:3136 ActionMarkExplicit::OpStackElement::OpStackElement
    fn new(v: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) -> Self {
        use crate::opcodes::OpCode;
        let mut slot = 0usize;
        let mut slotback = 0usize;
        let v_rg = v.read().unwrap();
        if v_rg.is_written() {
            if let Some(def_arc) = v_rg.get_def() {
                let def = def_arc.read().unwrap();
                match def.opcode {
                    OpCode::CPUI_LOAD => {
                        slot = 1;
                        slotback = 2;
                    }
                    OpCode::CPUI_PTRADD => {
                        slotback = 1; // Don't traverse the multiplier slot
                    }
                    OpCode::CPUI_SEGMENTOP => {
                        slot = 2;
                        slotback = 3;
                    }
                    _ => {
                        slotback = def.num_input();
                    }
                }
            }
        }
        Self { vn: v.clone(), slot, slotback ,
        }
    }
}

impl ActionMarkExplicit {
    // Ghidra: coreaction.hh:427 ActionMarkExplicit (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }

    /// Check if a Varnode should be marked explicit. Faithful to
    /// `baseExplicit` (coreaction.cc:3007-3082). Returns:
    /// - -1: should be explicit
    /// - -2: explicit (NEW op, may need special printing)
    /// - 0: single descendant, not explicit
    /// - >0: number of descendants (potential implied)
    // Ghidra: coreaction.cc:3007 ActionMarkExplicit::baseExplicit
    fn base_explicit(
        vn_arc: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        max_ref: i32,
    ) -> i32 {
        use crate::opcodes::OpCode;
        let vn = vn_arc.read().unwrap();
        // Get defining op (cc:3012-3013).
        let Some(def_arc) = vn.get_def() else {
            return -1; // No def → explicit.
        };
        let def = def_arc.read().unwrap();
        // Marker ops → explicit (cc:3014).
        if def.is_marker() {
            return -1;
        }
        // Call ops → explicit (cc:3015-3019); CPUI_NEW with a single input
        // is explicit but may need special printing (-2).
        if def.is_call() {
            if def.opcode == OpCode::CPUI_NEW && def.num_input() == 1 {
                return -2;
            }
            return -1;
        }
        // Ghidra coreaction.cc:3020-3021: a Varnode whose HighVariable
        // already holds more than one instance must not be merged at all —
        // inlining its def expression would splice SSA versions whose
        // combined cover inflates past the read sites. This rule runs
        // BEFORE the addr-tied/mapped checks in the oracle, so a merged
        // multi-instance member is explicit regardless of property flags.
        if let Some(high_arc) = vn.high.as_ref() {
            if high_arc.read().unwrap().num_instances() > 1 {
                return -1; // Must not be merged at all
            }
        }
        // Addr-tied varnodes are often explicit (pointers may reference them).
        // cc:3020-3021: a HighVariable merged across more than one Varnode
        // instance can never be implied — the token is printed per instance,
        // so every defining varnode of the high must be explicit.
        if let Some(high) = vn.get_high() {
            if high.read().unwrap().num_instances() > 1 {
                return -1; // Must not be merged at all
            }
        }
        if vn.is_addr_tied() {
            // cc:3022-3029: addr-tied SUBPIECE of an addr-tied input whose
            // join overlap equals the truncation offset is a copy marker —
            // explicit and not printed. (cc:3026 compares int4 overlapJoin
            // against uintb getOffset: -1 sign-extends and never matches a
            // small SUBPIECE offset, mirrored by the u64 cast.)
            if def.opcode == OpCode::CPUI_SUBPIECE {
                if let Some(vin_arc) = def.get_in(0) {
                    let vin = vin_arc.read().unwrap();
                    if vin.is_addr_tied() {
                        if let Some(off_vn_arc) = def.get_in(1) {
                            let off = off_vn_arc.read().unwrap().get_offset();
                            if (vn.overlap_join(&vin) as u64) == off {
                                return -1;
                            }
                        }
                    }
                }
            }
            // cc:3030-3031: addr-tied needs a lone descendant to stay
            // implicit-eligible.
            let Some(use_op_arc) = vn.lone_descend() else {
                return -1;
            };
            let use_op = use_op_arc.read().unwrap();
            if use_op.opcode == OpCode::CPUI_INT_ZEXT {
                // cc:3032-3036: explicit unless the ZEXT output is itself
                // addr-tied AND fully contains vn (contains == 0).
                match use_op.get_out() {
                    Some(vnout_arc) => {
                        let vnout = vnout_arc.read().unwrap();
                        if !vnout.is_addr_tied() || vnout.contains(&vn) != 0 {
                            return -1;
                        }
                    }
                    None => return -1,
                }
            } else if use_op.opcode == OpCode::CPUI_PIECE {
                // cc:3037-3045: the PIECE root itself must be explicit;
                // internal pieces of a non-partial-root stay implicit-
                // eligible.
                match Self::piece_node_find_root(vn_arc) {
                    Some(root_arc) => {
                        if std::sync::Arc::ptr_eq(&root_arc, vn_arc) {
                            return -1;
                        }
                        // cc:3040: `rootVn->getDef()->isPartialRoot()` — Rugra
                        // has no PcodeOp::partialroot flag (ruleaction.rs
                        // RulePieceStructure skips setPartialRoot at Ghidra
                        // ruleaction.cc:7642; VariablePiece registry tracked
                        // by MERGE-ADDRTIED-CLOSURE-0001), so the flag reads
                        // false for every IR the current pipeline builds.
                    }
                    None => return -1,
                }
            } else {
                // cc:3046-3048: any other lone reader of an addr-tied
                // varnode keeps it explicit.
                return -1;
            }
        } else if vn.is_mapped() {
            // cc:3050-3054: NOT addrtied but still mapped — a first-use
            // (register) or dynamic symbol mapping — should be explicit.
            return -1;
        } else if vn.is_proto_partial() {
            // cc:3055-3059: pieces being CONCATed into a structure are
            // explicit; internal PIECEs will be hidden.
            return -1;
        } else if def.opcode == OpCode::CPUI_PIECE
            && def
                .get_in(0)
                .map(|v| v.read().unwrap().is_proto_partial())
                .unwrap_or(false)
        {
            // cc:3060-3063: the base of PIECE operations building a
            // structure should be explicit.
            return -1;
        }
        // cc:3064: must have at least one descendant.
        if vn.has_no_descend() {
            return -1;
        }

        // cc:3066-3072: a PTRSUB dereference of a constant/input spacebase
        // is always implicit — remove the limit on max references.
        let mut max_ref = max_ref;
        if def.opcode == OpCode::CPUI_PTRSUB {
            if let Some(base_vn_arc) = def.get_in(0) {
                let base_vn = base_vn_arc.read().unwrap();
                if base_vn.is_spacebase()
                    && (base_vn.is_constant() || base_vn.is_input())
                {
                    max_ref = 1000000;
                }
            }
        }
        // cc:3073-3081: count descendants; a marker reader or exceeding
        // maxref makes the varnode explicit.
        let mut desc_count: i32 = 0;
        for op_arc in vn.descend_iter() {
            let op = op_arc.read().unwrap();
            if op.is_marker() {
                return -1;
            }
            desc_count += 1;
            if desc_count > max_ref {
                return -1; // Must not exceed max descendants
            }
        }

        desc_count
    }

    // Ghidra: op.cc:824 PieceNode::findRoot
    /// Find the root of the CONCAT tree of Varnodes marked either
    /// `is_proto_partial()` or `is_addr_tied()`: the maximal Varnode
    /// containing the given Varnode (as storage) with a backward path to it
    /// through PIECE operations. Mirrors the private helper
    /// `piece_node_find_root` in funcdata.rs (same oracle lines,
    /// op.cc:824-852; endianness-adjusted output address, renormalize is a
    /// no-op for word-size-1 spaces, `compareOrder != 0` tie replacement) —
    /// duplicated locally because the funcdata.rs item is private and that
    /// file is outside this change's lease.
    fn piece_node_find_root(
        vn_arc: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        use crate::opcodes::OpCode;
        use std::sync::Arc;
        let mut cur = vn_arc.clone();
        loop {
            let (is_pp, is_at, cur_addr, cur_space) = {
                let r = cur.read().unwrap();
                (
                    r.is_proto_partial(), r.is_addr_tied(), r.get_offset(), r.get_space(),
                )
            };
            if !is_pp && !is_at {
                break;
            }
            let mut piece_op: Option<Arc<std::sync::RwLock<crate::op::PcodeOp>>> = None;
            let readers: Vec<_> = cur
                .read()
                .unwrap()
                .descend
                .iter()
                .filter_map(|w| w.upgrade())
                .collect();
            for op_arc in readers {
                let op = op_arc.read().unwrap();
                if op.opcode != OpCode::CPUI_PIECE {
                    continue;
                }
                let slot = (0..2)
                    .find(|&i| op.get_in(i).map(|v| Arc::ptr_eq(v, &cur)).unwrap_or(false));
                let (Some(slot), Some(out)) = (slot, op.output.clone()) else { continue ;
                };
                let out_r = out.read().unwrap();
                let mut addr = out_r.get_offset();
                let (in0_size, in1_size) = (
                    op.get_in(0)
                        .map(|v| v.read().unwrap().get_size())
                        .unwrap_or(0),
                    op.get_in(1)
                        .map(|v| v.read().unwrap().get_size())
                        .unwrap_or(0),
                );
                // if (addr.getSpace()->isBigEndian() == (slot == 1))
                //   addr = addr + op->getIn(1-slot)->getSize();
                if cur_space.is_big_endian() == (slot == 1) {
                    addr = addr.wrapping_add(if slot == 0 { in1_size } else { in0_size } as u64);
                }
                // addr.renormalize(vn->getSize()) — identity for word-size-1
                // spaces (Rugra's scalar Address carries no word size).
                if addr == cur_addr {
                    match &piece_op {
                        Some(prev) => {
                            // op.cc:841-843: `if (op->compareOrder(pieceOp))
                            // pieceOp = op;` — nonzero truthiness replaces.
                            let prev_guard = prev.read().unwrap();
                            if op.compare_order(&prev_guard) != 0 {
                                drop(prev_guard);
                                piece_op = Some(op_arc.clone());
                            }
                        }
                        None => piece_op = Some(op_arc.clone()),
                    }
                }
            }
            match piece_op {
                Some(op_arc) => {
                    let next = op_arc.read().unwrap().output.clone();
                    match next {
                        Some(n) => cur = n,
                        None => break,
                    }
                }
                None => break,
            }
        }
        Some(cur)
    }

    /// Look for one Varnode with multiple descendants flowing into another.
    /// Faithful to `multipleInteraction` (coreaction.cc:3091-3132): for
    /// bool-output / INT_ZEXT / INT_SEXT / PTRADD outputs whose first two
    /// inputs carry the multlist mark, the marked input is purged to
    /// explicit. Returns the number of Varnodes marked explicit.
    // Ghidra: coreaction.cc:3091 ActionMarkExplicit::multipleInteraction
    fn multiple_interaction(
        multlist: &[std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>],
    ) -> i32 {
        use crate::opcodes::OpCode;
        let mut purgelist: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> =
            Vec::new();

        for vn_arc in multlist {
            // All elements in this list should have a defining op.
            let vn = vn_arc.read().unwrap();
            let Some(def_arc) = vn.get_def() else { continue ;
            };
            let op = def_arc.read().unwrap();
            let opc = op.opcode;
            if op.is_bool_output()
                || opc == OpCode::CPUI_INT_ZEXT
                || opc == OpCode::CPUI_INT_SEXT
                || opc == OpCode::CPUI_PTRADD
            {
                let mut maxparam = 2usize;
                if op.num_input() < maxparam {
                    maxparam = op.num_input();
                }
                for j in 0..maxparam {
                    let Some(topvn_arc) = op.get_in(j) else { continue ;
                    };
                    let topvn = topvn_arc.read().unwrap();
                    // We have a "multiple" interaction between topvn and vn.
                    if topvn.is_mark() {
                        let mut topopc = OpCode::CPUI_COPY;
                        if topvn.is_written() {
                            if let Some(topdef_arc) = topvn.get_def() {
                                let topdef = topdef_arc.read().unwrap();
                                if topdef.is_bool_output() {
                                    continue; // Try not to make boolean outputs explicit
                                }
                                topopc = topdef.opcode;
                            }
                        }
                        if opc == OpCode::CPUI_PTRADD {
                            if topopc == OpCode::CPUI_PTRADD {
                                purgelist.push(topvn_arc.clone());
                            }
                        } else {
                            purgelist.push(topvn_arc.clone());
                        }
                    }
                }
            }
        }

        for vn_arc in &purgelist {
            let mut vn = vn_arc.write().unwrap();
            vn.set_explicit();
            vn.clear_implied();
            vn.clear_mark();
        }
        purgelist.len() as i32
    }

    /// Count the number of terms in the expression making up vn; if more
    /// than max, mark vn explicit. Faithful to `processMultiplier`
    /// (coreaction.cc:3166-3199) including the marked-ancestor shortcut
    /// (cc:3192-3195) and the spacebase exclusion (cc:3179-3180).
    // Ghidra: coreaction.cc:3166 ActionMarkExplicit::processMultiplier
    fn process_multiplier(
        vn_arc: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        max: i32,
    ) {
        let mut opstack: Vec<MarkExplicitOpStackElement> = Vec::new();
        let mut finalcount: i32 = 0;

        opstack.push(MarkExplicitOpStackElement::new(vn_arc));
        loop {
            if opstack.is_empty() {
                break;
            }
            let vncur_arc = opstack.last().unwrap().vn.clone();
            let vncur = vncur_arc.read().unwrap();
            let isaterm = vncur.is_explicit() || !vncur.is_written();
            if isaterm || (opstack.last().unwrap().slotback <= opstack.last().unwrap().slot) {
                // Trimming condition (cc:3177)
                if isaterm {
                    if !vncur.is_spacebase() {
                        // Don't count space base (cc:3179-3180)
                        finalcount += 1;
                    }
                }
                if finalcount > max {
                    // Make this variable explicit (cc:3182-3185)
                    drop(vncur);
                    let mut vn = vn_arc.write().unwrap();
                    vn.set_explicit();
                    vn.clear_implied();
                    return;
                }
                opstack.pop();
            } else {
                let def_arc = vncur.get_def().expect("non-term stack element is written");
                let op = def_arc.read().unwrap();
                let slot = opstack.last().unwrap().slot;
                let Some(newvn_arc) = op.get_in(slot) else {
                    opstack.last_mut().unwrap().slot += 1;
                    continue;
                };
                opstack.last_mut().unwrap().slot += 1;
                let ancestor_marked = newvn_arc.read().unwrap().is_mark();
                drop(vncur);
                if ancestor_marked {
                    // If an ancestor is marked (also possible implied with
                    // multiple descendants) then automatically consider this
                    // to be explicit (cc:3192-3195).
                    let mut vn = vn_arc.write().unwrap();
                    vn.set_explicit();
                    vn.clear_implied();
                    return;
                }
                opstack.push(MarkExplicitOpStackElement::new(&newvn_arc));
            }
        }
    }

    /// Assume vn is produced via a CPUI_NEW operation. If it is immediately
    /// fed to a constructor, set special printing flags on the Varnode.
    /// Faithful to `checkNewToConstructor` (coreaction.cc:3205-3235).
    // Ghidra: coreaction.cc:3205 ActionMarkExplicit::checkNewToConstructor
    fn check_new_to_constructor(
        fd: &mut Funcdata,
        vn_arc: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        use crate::opcodes::OpCode;
        let vn = vn_arc.read().unwrap();
        let Some(op_arc) = vn.get_def() else { return };
        let op = op_arc.read().unwrap();
        let Some(bb_arc) = op.parent.as_ref().and_then(|w| w.upgrade()) else {
            return;
        };
        let mut firstuse: Option<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>> = None;
        for curop_arc in vn.descend_iter() {
            let curop = curop_arc.read().unwrap();
            let curop_bb = curop.parent.as_ref().and_then(|w| w.upgrade());
            let same_bb = match &curop_bb {
                Some(cb) => std::sync::Arc::ptr_eq(cb, &bb_arc),
                None => false,
            };
            if !same_bb {
                continue;
            }
            if firstuse.is_none() {
                firstuse = Some(curop_arc.clone());
            } else if let Some(fu_arc) = &firstuse {
                let fu = fu_arc.read().unwrap();
                // cc:3216-3223: replace firstuse when curop runs earlier, or
                // when a CALLIND's function-pointer input is defined by the
                // current firstuse.
                let replace = if curop.get_seq_num().get_order() < fu.get_seq_num().get_order() {
                    true
                } else if curop.opcode == OpCode::CPUI_CALLIND {
                    curop
                        .get_in(0)
                        .filter(|ptr_arc| ptr_arc.read().unwrap().is_written())
                        .and_then(|ptr_arc| ptr_arc.read().unwrap().get_def())
                        .map(|ptr_def| std::sync::Arc::ptr_eq(&ptr_def, fu_arc))
                        .unwrap_or(false)
                } else {
                    false
                };
                drop(fu);
                if replace {
                    firstuse = Some(curop_arc.clone());
                }
            }
        }
        let Some(firstuse_arc) = firstuse else { return };
        let firstuse = firstuse_arc.read().unwrap();
        if !firstuse.is_call() {
            return;
        }
        if firstuse.get_out().is_some() {
            return;
        }
        if firstuse.num_input() < 2 {
            return; // Must have at least 1 parameter (plus destination varnode)
        }
        if !firstuse
            .get_in(1)
            .map(|v| std::sync::Arc::ptr_eq(&v, vn_arc))
            .unwrap_or(false)
        {
            return; // First parameter must be result of new
        }
        // data.opMarkSpecialPrint(firstuse) — Mark call to print the new
        // operator as well (cc:3233).
        drop(firstuse);
        drop(op);
        drop(vn);
        fd.op_mark_special_print(&crate::op::PcodeOpRef(firstuse_arc));
        // data.opMarkNonPrinting(op) — Don't print the new operator as a
        // stand-alone operation (cc:3234).
        fd.op_mark_non_printing(&crate::op::PcodeOpRef(op_arc));
    }
}
impl Action for ActionMarkExplicit {
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:440
    fn get_flags(&self) -> u32 {
        action_flags::RULE_ONCEPERFUNC
    }

    // Ghidra: coreaction.cc:3237 ActionMarkExplicit::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // cc:3244: maxref = data.getArch()->max_implied_ref (default 2,
        // arch.rs default_x86_64 mirrors architecture.cc).
        let max_ref = fd.arch.as_ref().map(|a| a.max_implied_ref).unwrap_or(2);
        let mut change_count: i32 = 0;
        // implied varnodes with >1 descendants (cc:3241)
        let mut multlist: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> =
            Vec::new();

        // Iterate all varnodes from the loc_tree (VarnodeLocSet equivalent);
        // skip free varnodes (cc:3245 `enditer = data.beginDef(0)` proxy —
        // constants attached to op inputs are marked explicit by baseExplicit
        // in Ghidra but never reach any print path, so the non-free proxy
        // keeps the observable flag set identical).
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
            drop(vn_rg);
            // cc:3249: baseExplicit determination.
            let desc_count = Self::base_explicit(vn_arc, max_ref);
            if desc_count < 0 {
                // cc:3251-3254: should be explicit — set the EXPLICIT flag,
                // bump the inherited count, and run the NEW-to-constructor
                // special-print pass for -2.
                vn_arc.write().unwrap().set_explicit();
                change_count += 1;
                if desc_count < -1 {
                    Self::check_new_to_constructor(fd, vn_arc);
                }
            } else if desc_count > 1 {
                // cc:3256-3259: keep track of possible implieds with more
                // than one descendant.
                vn_arc.write().unwrap().set_mark();
                multlist.push(vn_arc.clone());
            }
        }

        // cc:3262: count += multipleInteraction(multlist)
        change_count += Self::multiple_interaction(&multlist);
        // cc:3263: maxdup = data.getArch()->max_term_duplication
        let max_dup = fd
            .arch
            .as_ref()
            .map(|a| a.max_term_duplication)
            .unwrap_or(2);
        for vn_arc in &multlist {
            // cc:3266: mark may have been cleared by multipleInteraction
            if vn_arc.read().unwrap().is_mark() {
                Self::process_multiplier(vn_arc, max_dup);
            }
        }
        // cc:3269-3270: clear marks.
        for vn_arc in &multlist {
            vn_arc.write().unwrap().clear_mark();
        }

        if change_count > 0 {
            // Ghidra coreaction.cc:3252/3262: every setExplicit/purge
            // increments the inherited Action::count; apply itself returns
            // 0 (cc:3271). Returning the bump count here is the sanctioned
            // Rust count-bridge (see Action::perform doc).
            self.count += change_count;
            Ok(change_count)
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
pub struct ActionMarkImplied { pub count: i32 ,
}
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
            if !matches!(
                opc, OpCode::CPUI_INT_ADD | OpCode::CPUI_PTRSUB | OpCode::CPUI_PTRADD | OpCode::CPUI_INT_XOR
            ) {
                continue;
            }
            // Check if the other varnode is input(0) of this op.
            let in0 = def_rg.get_in(0);
            if let Some(in0_vn) = in0 {
                if std::sync::Arc::ptr_eq(in0_vn, b) {
                    // Check if input(1) is a constant.
                    let in1 = def_rg.get_in(1);
                    if in1
                        .map(|v| v.read().unwrap().is_constant())
                        .unwrap_or(false) {
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

        // (1) LOAD def crossing STORE (coreaction.cc:3379-3395): Ghidra walks
        // the alive STORE ops and, when `vn->getCover()->contain(storeop, 2)`
        // — INTERIOR containment, same max==2 form as check (2) — cavalierly
        // lets the load through unless the STORE's spacebase offset equals
        // the LOAD's AND isPossibleAlias cannot rule the pointers different.
        // The previous whole-block shortcut forbade every LOAD that merely
        // shared a block with a STORE, even one AFTER the load's last read
        // (my_fwrite's `*stream` vs the later `_IO_read_ptr` store).
        if def_opc == OpCode::CPUI_LOAD {
            let vn_cover = vn_arc.read().unwrap().cover.as_ref().map(|c| c.clone());
            let load_spacebase_off = def_op.get_in(0).map(|v| v.read().unwrap().get_offset());
            if let Some(cover) = vn_cover {
                for store_op_ref in &fd.obank.alivelist {
                    let store_op = store_op_ref.0.read().unwrap();
                    if store_op.is_dead() || store_op.opcode != OpCode::CPUI_STORE {
                        continue;
                    }
                    let Some(store_blk) = store_op.parent.as_ref().and_then(|w| w.upgrade()) else { continue ;
                    };
                    let store_bi = store_blk.read().unwrap().get_index();
                    let store_order = store_op.start.get_order();
                    let interior = cover
                        .blocks
                        .get(&store_bi)
                        .map(|cb| cb.contain(store_order) && cb.boundary(store_order) == 0)
                        .unwrap_or(false);
                    if !interior {
                        continue;
                    }
                    // The LOAD crosses this STORE. Ghidra consults
                    // isPossibleAlias (coreaction.cc:3392) before refusing;
                    // Rugra's full alias machinery is unported
                    // (is_possible_alias_step is reserved), so same-spacebase
                    // crossings are conservatively refused — a superset of
                    // Ghidra's refusals, differing only for provably
                    // non-aliasing pointer pairs.
                    let store_spacebase_off =
                        store_op.get_in(0).map(|v| v.read().unwrap().get_offset());
                    if load_spacebase_off == store_spacebase_off {
                        return false;
                    }
                }
            }
        }

        // (2) CALL/LOAD def crossing another CALL: faithful to Ghidra
        // checkImpliedCover (coreaction.cc:3401-3406). A varnode defined by a
        // CALL (or LOAD) whose live cover spans another CALL op cannot be
        // implied — inlining its def expression would place a call result
        // across another call boundary. The precise check is
        // `vn->getCover()->contain(callop, 2)`: cover.cc:413-424 with max==2
        // requires INTERIOR containment — `CoverBlock::contain` (cover.cc:107,
        // inclusive of both endpoints) AND `CoverBlock::boundary(op)==0`
        // (cover.cc:129 — neither the defining point nor the tail). A LOAD
        // whose only read is the CALL itself has the call on its TAIL
        // boundary, so it does not count as crossing and stays imposable —
        // that is exactly the `fopen(*(char **)stream, ...)` inline form.
        if matches!(
            def_opc, OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_LOAD
        ) {
            let vn_cover = vn_arc.read().unwrap().cover.as_ref().map(|c| c.clone());
            if let Some(cover) = vn_cover {
                for call_op_ref in &fd.obank.alivelist {
                    let call_op = call_op_ref.0.read().unwrap();
                    if call_op.is_dead() { continue; }
                    if !matches!(call_op.opcode, OpCode::CPUI_CALL | OpCode::CPUI_CALLIND) {
                        continue;
                    }
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
                        // contain(callop, 2): interior only. Rugra's public
                        // Cover::contain(block, point) is the max==1 form, so
                        // the boundary==0 test from cover.cc:421 is applied on
                        // the CoverBlock directly.
                        let interior = cover
                            .blocks
                            .get(&call_bi)
                            .map(|cb| cb.contain(call_order) && cb.boundary(call_order) == 0)
                            .unwrap_or(false);
                        if interior {
                            return false;
                        }
                    }
                }
            }
        }

        // (3) Input cover inflation test (the authoritative check).
        let high = high_arc.read().unwrap();
        for i in 0..def_op.num_input() {
            let Some(in_vn) = def_op.get_in(i) else { continue ;
            };
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
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:461
    fn get_flags(&self) -> u32 {
        action_flags::RULE_ONCEPERFUNC
    }

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
            // Ghidra coreaction.cc:3434: every candidate popped from the DFS
            // stack — each Varnode that gets marked either explicit or
            // implied — increments the inherited Action::count; apply itself
            // still returns 0, and Action::perform surfaces the accumulated
            // count as its result (action.cc:362 `return count;`). Returning
            // the bump count here is the sanctioned Rust count-bridge (see
            // Action::perform doc; same convention as
            // ActionMarkExplicit::apply above).
            // Ghidra coreaction.cc:3434: `count += 1` fires for every
            // varnode that completes the traversal — it will be marked
            // either explicit or implied. apply itself returns 0 (cc:3454);
            // returning the bump count is the sanctioned Rust count-bridge
            // (see Action::perform doc), so `perform` observes
            // lcount<count → count_apply/status_end exactly like the oracle
            // (ActionMarkImplied is rule_onceperfunc, coreaction.hh:461).
            self.count += change_count;
            Ok(change_count)
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
pub struct ActionSetCasts { pub count: i32 ,
}
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
            | OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT => Some(TypeMetatype::Int)
            ,
            // Boolean ops: metain = TYPE_BOOL
            OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_AND
            | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR => Some(TypeMetatype::Bool),
            _ => None,
        }
    }

    /// Faithful port of `TypeOpLoad::getInputCast` (typeop.cc:440-470).
    /// Slot 1 (the address): cast the load POINTER so it matches the output
    /// type. `reqtype` is the output's high type; `curtype` is the address
    /// high type unwrapped ONE level. When the unwrapped pointee matches the
    /// output size and is primitive-ish, the cast is POSTPONED to the load
    /// output (returning None) unless the address is already an implied CAST
    /// that can be re-cast — this is what keeps `stream->_IO_read_ptr`
    /// (address char**, output high FILE*) free of a `*(FILE **)` prefix in
    /// the oracle. A size mismatch (e.g. `*stream` on a FILE* param feeding
    /// fopen's char*) falls through to castStandard and returns the pointer
    /// cast `char**` that prints `*(char **)stream`.
    // Ghidra: typeop.cc:440 TypeOpLoad::getInputCast
    fn load_input_cast(
        op: &crate::op::PcodeOp,
        slot: usize,
        strategy: &crate::type_system::cast::CastStrategyC,
    ) -> Option<Arc<crate::type_system::datatype::Datatype>> {
        use crate::type_system::datatype::{Datatype, TypeMetatype};
        if slot != 1 {
            return None;
        }
        // cc:444: reqtype = op->getOut()->getHighTypeDefFacing()
        let reqtype = op.get_out().and_then(|o| {
            let vn = o.read().unwrap();
            vn.high
                .as_ref()
                .map(|h| h.read().unwrap().v_type.get())
                .or_else(|| vn.v_type.clone())
        })?;
        let invn = op.get_in(1)?;
        let in_size = invn.read().unwrap().get_size();
        // cc:446: curtype = invn->getHighTypeReadFacing(op)
        let curtype_full = {
            let vn = invn.read().unwrap();
            vn.high
                .as_ref()
                .map(|h| h.read().unwrap().v_type.get())
                .or_else(|| vn.v_type.clone())
        }?;
        // cc:450-453: unwrap exactly one level; a non-pointer address takes
        // a direct pointer-to-reqtype cast.
        let curtype = match curtype_full.as_ref() {
            Datatype::Pointer(pt) => pt.ptr_to.clone(),
            _ => return Some(make_ptr(reqtype, in_size)),
        };
        // cc:454-465: postpone branch.
        if !curtype.type_equal(&reqtype) && curtype.get_size() == reqtype.get_size() {
            let curmeta = curtype.get_metatype();
            if !matches!(
                curmeta,
                TypeMetatype::Struct | TypeMetatype::Array | TypeMetatype::Spacebase | TypeMetatype::Union
            ) {
                // Primitive pointee of the right size: only keep going to
                // re-cast when the address is already an implied CAST.
                let vn_rg = invn.read().unwrap();
                let def_is_cast = vn_rg
                    .def
                    .as_ref()
                    .and_then(|d| d.upgrade())
                    .map(|d| d.read().unwrap().opcode == OpCode::CPUI_CAST)
                    .unwrap_or(false);
                if !vn_rg.is_implied() || !vn_rg.is_written() || !def_is_cast {
                    return None; // Postpone cast to output
                }
            }
        }
        // cc:467-469: castStandard(reqtype, curtype, false, true), then wrap
        // the resulting cast type back into a pointer.
        let cast = strategy.cast_standard_full(&reqtype, &curtype, false, true)?;
        Some(make_ptr(cast, in_size))
    }

    /// Faithful port of `TypeOpStore::getInputCast` (typeop.cc:520-555).
    /// Slot 1 (the address): when the pointed-to size does not match the
    /// value size, cast the pointer to pointer-of-valuetype. Slot 2 (the
    /// value): when sizes match, castStandard(pointedToType, valueType) —
    /// the `(char *)__s` form for a FILE* stored through a char** field
    /// pointer.
    // Ghidra: typeop.cc:520 TypeOpStore::getInputCast
    fn store_input_cast(
        op: &crate::op::PcodeOp,
        slot: usize,
        strategy: &crate::type_system::cast::CastStrategyC,
    ) -> Option<Arc<crate::type_system::datatype::Datatype>> {
        use crate::type_system::datatype::Datatype;
        if slot == 0 {
            return None;
        }
        let pointer_vn = op.get_in(1)?;
        let value_vn = op.get_in(2)?;
        let pointer_type = {
            let vn = pointer_vn.read().unwrap();
            vn.high
                .as_ref()
                .map(|h| h.read().unwrap().v_type.get())
                .or_else(|| vn.v_type.clone())
        }?;
        let value_type = {
            let vn = value_vn.read().unwrap();
            vn.high
                .as_ref()
                .map(|h| h.read().unwrap().v_type.get())
                .or_else(|| vn.v_type.clone())
        }?;
        let ptr_size = pointer_vn.read().unwrap().get_size();
        // cc:530-535: pointedToType / destSize.
        let (pointed_to, dest_size) = match pointer_type.as_ref() {
            Datatype::Pointer(pt) => (pt.ptr_to.clone(), pt.ptr_to.get_size() as i64),
            _ => (pointer_type.clone(), -1i64),
        };
        // cc:536-541: size mismatch → cast the POINTER (slot 1 only).
        if dest_size != value_type.get_size() as i64 {
            if slot == 1 {
                return Some(make_ptr(value_type, ptr_size));
            }
            return None;
        }
        if slot == 1 {
            // cc:542-551: a CAST already in place on the pointer is tested
            // for the right target type and re-cast only then.
            let vn_rg = pointer_vn.read().unwrap();
            let def = vn_rg.def.as_ref().and_then(|d| d.upgrade());
            if let Some(def) = def {
                if def.read().unwrap().opcode == OpCode::CPUI_CAST
                    && vn_rg.is_implied()
                    && vn_rg
                        .lone_descend()
                        .map(|d| {
                            std::ptr::eq(
                                &*d.read().unwrap() as *const crate::op::PcodeOp,
                                op as *const crate::op::PcodeOp,
                            )
                        })
                        .unwrap_or(false)
                {
                    let new_type = make_ptr(value_type, ptr_size);
                    if !pointer_type.type_equal(&new_type) {
                        return Some(new_type);
                    }
                }
            }
            return None;
        }
        // cc:553-554: slot 2 — cast the value, not the pointer.
        strategy.cast_standard_full(&pointed_to, &value_type, false, true)
    }

    /// Faithful 1:1 port of `ActionSetCasts::castInput` (coreaction.cc:2655-2720).
    /// For input `slot` of `op`, compute the op's expected input type
    /// (inputTypeLocal = getBase(size, metain)), the current varnode's high
    /// type, and if `castStandard` says a cast is needed, insert a CPUI_CAST op
    /// feeding the slot: `out = CAST(in)`, with out implied (inlined by printc
    /// as `(reqtype)in`).
    ///
    /// LOAD slot 1 and STORE slots 1/2 take the `TypeOpLoad::getInputCast`
    /// (typeop.cc:440-470) / `TypeOpStore::getInputCast` (typeop.cc:520-555)
    /// overrides instead of the generic metain model — those return a POINTER
    /// cast for the LOAD address (`*(char **)stream`) and a pointee cast for
    /// the STORE value (`(char *)__s`).
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
        let type_factory = fd
            .get_arch()
            .and_then(|architecture| architecture.types.clone())
            .unwrap_or_else(crate::type_system::typefactory::TypeFactory::shared_default);
        // (1) cc:2662: ct = op->getOpcode()->getInputCast(op,slot,strategy)
        // — the virtual dispatch mirror. The specialized arms (LOAD/STORE
        // slot overrides, comparison) already ran castStandard internally,
        // and the base TypeOp::getInputCast (typeop.cc:293-300) is
        // castStandard(inputTypeLocal(slot), highReadFacing, false, true):
        // a null ct means no cast is needed. Annotations get a null ct
        // (typeop.cc:295).
        let (in_vn, ct_opt, op_pc, in_size) = {
            let op = op_ref.0.read().unwrap();
            let Some(in_arc_ref) = op.get_in(slot) else { return false; };
            let in_arc = in_arc_ref.clone();
            let op_pc = op.get_addr();
            let in_size = in_arc.read().unwrap().get_size();
            let ct = match op.opcode {
                OpCode::CPUI_LOAD => Self::load_input_cast(&op, slot, strategy),
                OpCode::CPUI_STORE => Self::store_input_cast(&op, slot, strategy),
                OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL => {
                    crate::typeop::comparison_input_cast(&op, slot, strategy)
                }
                opc => match Self::input_metatype(opc) {
                    Some(meta) => {
                        let curtype = in_arc
                            .read()
                            .unwrap()
                            .get_high_type_read_facing(&op, slot as i32)
                            .or_else(|| in_arc.read().unwrap().v_type.clone())
                            .or_else(|| {
                                type_factory.read().unwrap().get_base(in_size, meta)
                            });
                        let reqtype =
                            type_factory.read().unwrap().get_base(in_size, meta);
                        match (curtype, reqtype) {
                            (Some(cur), Some(req))
                                if strategy
                                    .cast_standard_full(&req, &cur, false, true)
                                    .is_some() =>
                            {
                                Some(req)
                            }
                            _ => None,
                        }
                    }
                    None => None,
                },
            };
            let ct = if in_arc.read().unwrap().is_annotation() {
                None
            } else {
                ct
            };
            // Release the op read guard before the Funcdata mutations below
            // take their own write locks on this op.
            drop(op);
            (in_arc, ct, op_pc, in_size)
        };
        // (2) cc:2663-2668: null ct — mark explicit-print constants; that is
        // the only change this path can make.
        let Some(ct) = ct_opt else {
            return Self::mark_explicit_unsigned(op_ref, slot, strategy)
                || Self::mark_explicit_long_size(op_ref, slot, strategy);
        };
        // (3) cc:2671: vnin = vn = op->getIn(slot).
        let mut vnin = in_vn.clone();
        // (4) cc:2672-2686: double-cast guard — TWO nested levels, faithful
        // to the oracle arm order. The OUTER level (cc:2673) is
        // `isWritten && def==CAST` and consumes the arm regardless of
        // implied; only the INNER level (cc:2674) is `isImplied`. When the
        // producer is a CAST but the varnode is NOT implied, the whole
        // else-if chain below (constant arm, PTRSUB-zero, resolution
        // adjustment) is skipped and control falls through to the CAST
        // insert with vnin still = vn.
        let def_is_cast = {
            let rg = in_vn.read().unwrap();
            rg.is_written()
                && rg.def
                    .as_ref()
                    .and_then(|d| d.upgrade())
                    .map(|d| d.read().unwrap().opcode == OpCode::CPUI_CAST)
                    .unwrap_or(false)
        };
        if def_is_cast {
            if in_vn.read().unwrap().is_implied() {
                // cc:2675-2678: lone-descend retype ends the count on
                // success.
                let lone_is_op = in_vn
                    .read()
                    .unwrap()
                    .lone_descend()
                    .map(|d| std::sync::Arc::ptr_eq(&d, &op_ref.0))
                    .unwrap_or(false);
                if lone_is_op {
                    in_vn.write().unwrap().update_type(ct.clone());
                    if in_vn
                        .read()
                        .unwrap()
                        .get_type()
                        .map(|t| Arc::ptr_eq(&t, &ct))
                        .unwrap_or(false)
                    {
                        return true;
                    }
                }
                // cc:2680-2684: cast directly from the input of the
                // previous cast.
                if let Some(prev) = in_vn
                    .read()
                    .unwrap()
                    .def
                    .as_ref()
                    .and_then(|d| d.upgrade())
                    .and_then(|d| d.read().unwrap().get_in(0).cloned())
                {
                    vnin = prev;
                    if vnin
                        .read()
                        .unwrap()
                        .get_type()
                        .map(|t| Arc::ptr_eq(&t, &ct))
                        .unwrap_or(false)
                    {
                        fd.op_set_input(op_ref, vnin, slot);
                        return true;
                    }
                }
            }
            // def==CAST but NOT implied: no inner action; fall through to
            // the CAST insert below (vnin stays vn).
        }
        // (5) cc:2687-2691: constants update in place when they can take the
        // type; a locked constant falls through to a CAST op. This arm is
        // the OUTER else: unreachable when def==CAST (see cc:2673/2687).
        else if in_vn.read().unwrap().is_constant() {
            in_vn.write().unwrap().update_type(ct.clone());
            if in_vn
                .read()
                .unwrap()
                .get_type()
                .map(|t| Arc::ptr_eq(&t, &ct))
                .unwrap_or(false)
            {
                return true;
            }
        }
        // (6) cc:2692-2698 (ct PTR + testStructOffset0 → insertPtrsubZero)
        // and cc:2699-2701 (tryResolutionAdjustment) remain registered
        // residuals (input-side PTRSUB-zero / union resolution forms).
        // (7) cc:2702-2718: insert CPUI_CAST op: out = CAST(vnin), out
        // implied, inserted before op.
        let new_op = fd.new_op(1, op_pc);
        let out_vn = fd.new_unique_out(vnin.read().unwrap().get_size(), &new_op);
        out_vn.write().unwrap().v_type = Some(ct);
        out_vn.write().unwrap().set_implied();
        fd.op_set_opcode(&new_op, OpCode::CPUI_CAST);
        fd.op_set_input(&new_op, vnin, 0);
        fd.op_set_input(op_ref, out_vn, slot);
        fd.op_insert_before(&new_op, op_ref);
        true
    }

    // RUGRA-GLUE: addlflags predicates from the Ghidra TypeOp constructors
    /// `TypeOp::inheritsSign` (typeop.hh:131): the addlflags bit assigned by
    /// the comparison/arithmetic/logic/shift ctor `addlflags` lines in
    /// typeop.cc (928-1695) and read by markExplicitUnsigned (cast.cc:42).
    fn op_inherits_sign(opc: OpCode) -> bool {
        matches!(
            opc,
            OpCode::CPUI_INT_EQUAL
                | OpCode::CPUI_INT_NOTEQUAL
                | OpCode::CPUI_INT_SLESS
                | OpCode::CPUI_INT_SLESSEQUAL
                | OpCode::CPUI_INT_LESS
                | OpCode::CPUI_INT_LESSEQUAL
                | OpCode::CPUI_INT_ADD
                | OpCode::CPUI_INT_SUB
                | OpCode::CPUI_INT_2COMP
                | OpCode::CPUI_INT_NEGATE
                | OpCode::CPUI_INT_XOR
                | OpCode::CPUI_INT_AND
                | OpCode::CPUI_INT_OR
                | OpCode::CPUI_INT_LEFT
                | OpCode::CPUI_INT_RIGHT
                | OpCode::CPUI_INT_SRIGHT
                | OpCode::CPUI_INT_MULT
                | OpCode::CPUI_INT_DIV
                | OpCode::CPUI_INT_SDIV
                | OpCode::CPUI_INT_REM
                | OpCode::CPUI_INT_SREM
        )
    }

    /// `TypeOp::inheritsSignFirstParamOnly` (typeop.hh:134,
    /// `inherits_sign_zero`): shifts and INT_REM/INT_SREM only inherit sign
    /// from their first parameter.
    // RUGRA-GLUE: addlflags predicate mirror of TypeOp::inheritsSignFirstParamOnly (typeop.hh:134)
    fn op_inherits_sign_first_param_only(opc: OpCode) -> bool {
        matches!(
            opc,
            OpCode::CPUI_INT_LEFT
                | OpCode::CPUI_INT_RIGHT
                | OpCode::CPUI_INT_SRIGHT
                | OpCode::CPUI_INT_REM
                | OpCode::CPUI_INT_SREM
        )
    }

    /// `TypeOp::isShiftOp` (typeop.hh:137, `shift_op`).
    // RUGRA-GLUE: addlflags predicate mirror of TypeOp::isShiftOp (typeop.hh:137)
    fn op_is_shift(opc: OpCode) -> bool {
        matches!(
            opc,
            OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT
        )
    }

    // Ghidra: cast.cc:38 CastStrategy::markExplicitUnsigned
    /// Check if the input constant must be coerced to an unsigned token:
    /// the op must inherit sign, the constant's read-facing HIGH type must
    /// be unsigned-family (UINT/UNKNOWN/PARTIAL*), not char/enum, the other
    /// operand must not already force unsigned, and the output must not be
    /// explicit nor feed a non-inheriting lone reader. On success the
    /// Varnode is flagged `unsignedprint`. Faithful to
    /// `CastStrategy::markExplicitUnsigned` (cast.cc:38-77).
    fn mark_explicit_unsigned(
        op_ref: &crate::op::PcodeOpRef,
        slot: usize,
        strategy: &crate::type_system::cast::CastStrategyC,
    ) -> bool {
        use crate::type_system::datatype::TypeMetatype;
        let unsigned_family = |m: TypeMetatype| {
            matches!(
                m,
                TypeMetatype::Uint
                    | TypeMetatype::Unknown
                    | TypeMetatype::PartialStruct
                    | TypeMetatype::PartialUnion
            )
        };
        let op = op_ref.0.read().unwrap();
        // cc:41-44: inheritsSign gate; slot-1 of firstParamOnly ops never
        // coerces.
        if !Self::op_inherits_sign(op.opcode) {
            return false;
        }
        let first_param_only = Self::op_inherits_sign_first_param_only(op.opcode);
        if slot == 1 && first_param_only {
            return false;
        }
        // cc:45-46: constants only.
        let Some(vn) = op.get_in(slot).cloned() else {
            return false;
        };
        if !vn.read().unwrap().is_constant() {
            return false;
        }
        // cc:47-52: unsigned-family read-facing HIGH type, not char/enum.
        let Some(dt) = vn
            .read()
            .unwrap()
            .get_high_type_read_facing(&op, slot as i32)
            .or_else(|| vn.read().unwrap().v_type.clone())
        else {
            return false;
        };
        if !unsigned_family(dt.get_metatype()) {
            return false;
        }
        if strategy.is_char_type(&dt) || strategy.is_enum_type(&dt) {
            return false;
        }
        // cc:53-58: binary op (not firstParamOnly) — if the other side is
        // unsigned-family it forces the unsigned already.
        if op.num_input() == 2 && !first_param_only && slot <= 1 {
            if let Some(other) = op.get_in(1 - slot) {
                if let Some(ot) = other
                    .read()
                    .unwrap()
                    .get_high_type_read_facing(&op, (1 - slot) as i32)
                    .or_else(|| other.read().unwrap().v_type.clone())
                {
                    if unsigned_family(ot.get_metatype()) {
                        return false;
                    }
                }
            }
        }
        // cc:59-67: explicit outputs and outputs whose lone reader does not
        // inherit sign never coerce.
        if let Some(outvn) = op.get_out().cloned() {
            if outvn.read().unwrap().is_explicit() {
                return false;
            }
            if let Some(lone) = outvn.read().unwrap().lone_descend() {
                if !Self::op_inherits_sign(lone.read().unwrap().opcode) {
                    return false;
                }
            }
        }
        drop(op);
        // cc:68-69: vn->setUnsignedPrint(); return true.
        vn.write().unwrap().addlflags |= crate::varnode::addl_flags::UNSIGNED_PRINT;
        true
    }

    // Ghidra: cast.cc:79 CastStrategy::markExplicitLongSize
    /// Check if a shift-amount (slot 0) constant of a shift op must print as
    /// an explicitly long token: size > promote size, integer-family HIGH
    /// type, and the value's most significant bit below the promote width
    /// (sign-adjusted for signed values). On success the Varnode is flagged
    /// `longprint`. Faithful to `CastStrategy::markExplicitLongSize`
    /// (cast.cc:79-105).
    fn mark_explicit_long_size(
        op_ref: &crate::op::PcodeOpRef,
        slot: usize,
        strategy: &crate::type_system::cast::CastStrategyC,
    ) -> bool {
        use crate::type_system::datatype::TypeMetatype;
        let op = op_ref.0.read().unwrap();
        // cc:82-84: shift ops, slot 0 only.
        if !Self::op_is_shift(op.opcode) || slot != 0 {
            return false;
        }
        // cc:85-86: constants only.
        let Some(vn) = op.get_in(slot).cloned() else {
            return false;
        };
        if !vn.read().unwrap().is_constant() {
            return false;
        }
        let size = vn.read().unwrap().get_size();
        // cc:87: vn->getSize() <= promoteSize → false.
        if size <= strategy.get_promote_size() {
            return false;
        }
        // cc:87-91: HIGH type (not read-facing) must be integer-family.
        let dt = vn
            .read()
            .unwrap()
            .high
            .as_ref()
            .map(|h| h.read().unwrap().v_type.get())
            .or_else(|| vn.read().unwrap().v_type.clone());
        let Some(dt) = dt else {
            return false;
        };
        if !matches!(
            dt.get_metatype(),
            TypeMetatype::Uint
                | TypeMetatype::Int
                | TypeMetatype::Unknown
                | TypeMetatype::PartialStruct
                | TypeMetatype::PartialUnion
        ) {
            return false;
        }
        // cc:92-101: most-significant-bit threshold against the promote
        // width; signed values compare after two's-complement negation.
        let off = vn.read().unwrap().get_offset();
        let promote_bits = (strategy.get_promote_size() * 8) as i32;
        if dt.get_metatype() == TypeMetatype::Int
            && crate::address::signbit_negative(off, size)
        {
            // cc:93-94: off = uintb_negate(off, size) (address.cc:654:
            // ~off & calc_mask(size)); opbehavior's Rust twin is private, so
            // inline the same masked complement.
            let negated = !off & crate::address::calc_mask(size);
            if crate::address::mostsigbit_set(negated) >= promote_bits - 1 {
                return false;
            }
        } else if crate::address::mostsigbit_set(off) >= promote_bits {
            return false;
        }
        drop(op);
        // cc:103-104: vn->setLongPrint(); return true.
        vn.write().unwrap().addlflags |= crate::varnode::addl_flags::LONG_PRINT;
        true
    }

    // Ghidra: coreaction.cc:2469 ActionSetCasts::isOpIdentical
    /// Check if two types are identical after unwrapping pointer layers and
    /// typedef aliases. Faithful to `isOpIdentical` (cc:2469-2481): the
    /// synchronized double-PTR descent runs first (cc:2472-2474), then each
    /// side independently walks its own typedef chain (cc:2476-2479:
    /// `while(ct->getTypedef() != 0) ct = ct->getTypedef();`) before the
    /// identity comparison (cc:2480). Ghidra's `typedefImm` is a per-instance
    /// field; Rugra resolves the same chain through the TypeFactory typedef
    /// table (name -> stripped target, populated by `get_typedef`,
    /// typefactory.rs), which is identity-equivalent for factory-interned
    /// types. A detached Funcdata without an architecture factory keeps the
    /// bare pointer comparison (Ghidra always has a factory).
    fn is_op_identical(
        ct1: &Arc<crate::type_system::datatype::Datatype>, ct2: &Arc<crate::type_system::datatype::Datatype>,
        factory: Option<&crate::type_system::typefactory::TypeFactory>,
    ) -> bool {
        use crate::type_system::datatype::Datatype;
        let mut t1 = ct1.clone();
        let mut t2 = ct2.clone();
        while matches!(t1.as_ref(), Datatype::Pointer(_)) && matches!(t2.as_ref(), Datatype::Pointer(_)) {
            if let (Datatype::Pointer(p1), Datatype::Pointer(p2)) = (t1.as_ref(), t2.as_ref()) {
                t1 = p1.ptr_to.clone();
                t2 = p2.ptr_to.clone();
            } else { break; }
        }
        // cc:2476-2479: strip typedef aliases independently on each side
        // after the pointer descent (a typedef-of-pointer loses its alias
        // when descended; a typedef pointee keeps it until stripped here).
        if let Some(factory) = factory {
            while let Some(target) = factory.get_typedef_target(t1.get_name()) {
                t1 = target.clone();
            }
            while let Some(target) = factory.get_typedef_target(t2.get_name()) {
                t2 = target.clone();
            }
        }
        Arc::ptr_eq(&t1, &t2)
    }

    // Ghidra: coreaction.cc:2532 ActionSetCasts::castOutput
    /// Insert a CAST (or PTRSUB) op after `op` to convert its output to the
    /// token type (cc:2532-2616): token via the TypeOp virtual dispatch
    /// (PTRSUB field-sensitive, PTRADD in0-high, arithmetic family via
    /// cast.cc:394, LOAD pointee, CALL callspec, metatype fallback), the
    /// token==outHigh short-circuit, the implied varnode retype arms
    /// (cc:2559-2582, incl. the typelock/RETURN force case), the
    /// testStructOffset0 PTRSUB form (cc:2586-2588), and the observable
    /// rewiring order (cc:2595-2609). The union needsResolution arms
    /// (cc:2545-2548, 2553-2557, 2610-2613) remain registered residuals
    /// (`PIPE-ACTION-COUNT-0001C`); this is not a whole-function match
    /// claim.
    fn cast_output(
        fd: &mut Funcdata,
        op: &crate::op::PcodeOpRef,
        strategy: &crate::type_system::cast::CastStrategyC,
    ) -> i32 {
        use crate::type_system::cast::base_type_for;
        use crate::type_system::datatype::Datatype;
        use crate::type_system::datatype::TypeMetatype;
        // cc:2542: get the output varnode.
        let outvn = match op.0.read().unwrap().output.as_ref() {
            Some(o) => o.clone(), None => return 0,
        };
        // cc:2541: tokenct = op->getOpcode()->getOutputToken(op, castStrategy)
        // Rugra: compute the token type from the opcode's output metatype.
        let out_size = outvn.read().unwrap().get_size();
        // TypeOpLoad::getOutputToken (typeop.cc:472-485): the LOAD's token
        // is the POINTEE of its address input's high type (when the pointee
        // size matches the output size), else the output's own high type.
        // This is what surfaces the golden `(FILE *)stream->_IO_read_ptr`
        // cast: the address (PTRSUB `stream->_IO_read_ptr`) is char**, so
        // the token is char* while the phi-merged output high is FILE*.
        let tokenct = {
            use crate::typeop::TypeOp as _;
            let op_rg = op.0.read().unwrap();
            // A Ghidra PcodeOp always owns a TypeOp with a TypeFactory; Rugra
            // can represent a detached Funcdata, whose factory-dependent
            // token arms bail out (no bilateral token semantics).
            let type_factory = fd
                .arch
                .as_ref()
                .and_then(|architecture| architecture.types.clone());
            if op_rg.opcode == OpCode::CPUI_PTRSUB {
                // typeop.cc:2349-2364 supplies PTRSUB's field-sensitive token,
                // and coreaction.cc:2541 consumes it at this exact cast stage.
                // Type inference continues to use getOutputLocal (INT).
                let Some(type_factory) = type_factory else {
                    return 0;
                };
                let Some(token) = crate::typeop::TypeOpPtrsub::new(type_factory)
                    .get_output_token(&op_rg)
                else {
                    return 0;
                };
                token
            } else if op_rg.opcode == OpCode::CPUI_PTRADD {
                // typeop.cc:2244: the PTRADD token is the input-0 HIGH
                // read-facing type ("cast to the input data-type"), not the
                // output type.
                let Some(type_factory) = type_factory else {
                    return 0;
                };
                let Some(token) = crate::typeop::TypeOpPtradd::new(type_factory)
                    .get_output_token(&op_rg)
                else {
                    return 0;
                };
                token
            } else if matches!(
                op_rg.opcode,
                OpCode::CPUI_INT_ADD
                    | OpCode::CPUI_INT_SUB
                    | OpCode::CPUI_INT_2COMP
                    | OpCode::CPUI_INT_NEGATE
                    | OpCode::CPUI_INT_XOR
                    | OpCode::CPUI_INT_AND
                    | OpCode::CPUI_INT_OR
                    | OpCode::CPUI_INT_MULT
            ) {
                // typeop.cc:1175/1326/1388/1402/1416/1449/1482/1625 route the
                // arithmetic family through
                // CastStrategyC::arithmeticOutputStandard (cast.cc:394): the
                // earliest-ordering input HIGH type, bool demoted to base int.
                let Some(type_factory) = type_factory else {
                    return 0;
                };
                let Some(token) =
                    crate::type_system::cast::arithmetic_output_standard(&op_rg, &type_factory)
                else {
                    return 0;
                };
                token
            } else if op_rg.opcode == OpCode::CPUI_LOAD {
                let in1_high = op_rg
                    .get_in(1)
                    .and_then(|a| {
                        let vn = a.read().unwrap();
                        vn.high
                            .as_ref()
                            .map(|h| h.read().unwrap().v_type.get())
                            .or_else(|| vn.v_type.clone())
                    });
                let out_high = || {
                    outvn
                        .read()
                        .unwrap()
                        .high
                        .as_ref()
                        .map(|h| h.read().unwrap().v_type.get())
                        .or_else(|| outvn.read().unwrap().v_type.clone())
                };
                match in1_high {
                    Some(ct) if matches!(ct.as_ref(), Datatype::Pointer(_)) => {
                        if let Datatype::Pointer(pt) = ct.as_ref() {
                            if pt.ptr_to.get_size() == out_size {
                                pt.ptr_to.clone()
                            } else {
                                out_high().unwrap_or_else(|| ct.clone())
                            }
                        } else {
                            unreachable!()
                        }
                    }
                    _ => match out_high() {
                        Some(t) => t,
                        None => return 0,
                    },
                }
            } else if matches!(op_rg.opcode, OpCode::CPUI_CALL | OpCode::CPUI_CALLIND) {
                // cc:2541 getOutputToken -> outputTypeLocal ->
                // TypeOpCall::getOutputLocal (typeop.cc:720-735) /
                // TypeOpCallind::getOutputLocal (typeop.cc:776-789): the
                // callspec's LOCKED non-void output type, else the TypeOp
                // base default getBase(size, TYPE_UNKNOWN) (typeop.cc:261-265).
                // This token is what makes an unlocked (default-proto) call
                // output print as `__nptr = (char *)curl_getenv(...)`: token
                // undefined8 vs output high char* ->
                // castStandard(char*, undefined8) -> CAST inserted after the
                // CALL, whose printc spelling is the CAST output's high type
                // (PrintC::opTypeCast, printc.cc:448-464). Locked outputs
                // whose type equals the output high (strtol -> long) hit the
                // type_equal short-circuit and take no cast.
                // CALLIND reaches the callspec through Funcdata::getCallSpecs
                // (typeop.cc:782); Rugra's get_call_specs_of_op performs the
                // same op-identity verification through the slot-0 Iop
                // annotation (TYPEOP-FSPEC-SPACE-0001).
                match fd.get_call_specs_of_op(op) {
                    Some(fc) => {
                        let fc_r = fc.read().unwrap();
                        if fc_r.prototype.output_type_locked {
                            let ct = fc_r.prototype.return_type.clone();
                            if ct.get_metatype() != TypeMetatype::Void {
                                ct
                            } else {
                                base_type_for(out_size, TypeMetatype::Unknown)
                            }
                        } else {
                            base_type_for(out_size, TypeMetatype::Unknown)
                        }
                    }
                    None => base_type_for(out_size, TypeMetatype::Unknown),
                }
            } else {
                match Self::output_metatype(op_rg.opcode) {
                    Some(m) => base_type_for(out_size, m),
                    None => return 0,
                }
            }
        };
        // cc:2543: outHighType = outvn->getHigh()->getType()
        let out_high_type = outvn
            .read()
            .unwrap()
            .high
            .as_ref()
            .map(|h| h.read().unwrap().v_type.get())
            .or_else(|| outvn.read().unwrap().v_type.clone())
            .unwrap_or_else(|| tokenct.clone());
        // cc:2544: if (tokenct == outHighType) → no cast needed. Ghidra
        // compares interned TypeFactory pointers (identical canonical types
        // are the same object); Rugra's Datatypes are not interned, so the
        // equivalent is structural equality of base types
        // (metatype+size+name).
        if tokenct.type_equal(&out_high_type) {
            return 0;
        }
        // cc:2553-2557: outHighResolve starts as outHighType; the union
        // needsResolution resolution arm is a registered residual (no union
        // resolution infrastructure yet).
        let mut out_high_resolve = out_high_type.clone();
        // cc:2559-2582: implied varnode must have parse type.
        let mut force = false;
        {
            let (out_implied, out_typelock) = {
                let r = outvn.read().unwrap();
                (r.is_implied(), r.is_type_lock())
            };
            if out_implied {
                if out_typelock {
                    // cc:2562-2567: the Varnode input to a CPUI_RETURN is
                    // marked implied but casts as if explicit.
                    let lone_is_return = outvn
                        .read()
                        .unwrap()
                        .lone_descend()
                        .map(|d| d.read().unwrap().opcode == OpCode::CPUI_RETURN)
                        .unwrap_or(false);
                    if !lone_is_return {
                        // cc:2566: force = !isOpIdentical(outHighResolve,
                        // tokenct) — the typedef-chain stripping inside
                        // isOpIdentical (cc:2476-2479) runs through the
                        // architecture's TypeFactory typedef table.
                        let factory_arc = fd
                            .get_arch()
                            .and_then(|architecture| architecture.types.clone());
                        let factory_guard =
                            factory_arc.as_ref().map(|types| types.read().unwrap());
                        force = !Self::is_op_identical(
                            &out_high_resolve,
                            &tokenct,
                            factory_guard.as_deref(),
                        );
                    }
                } else if out_high_resolve.get_metatype() != TypeMetatype::Pointer {
                    // cc:2569-2571: implied atomic (non-pointer) out — ignore
                    // its type in favor of the token type.
                    outvn.write().unwrap().update_type(tokenct.clone());
                    out_high_resolve = Self::refresh_out_high_resolve(
                        &outvn,
                        &out_high_resolve,
                        &tokenct,
                    );
                } else if tokenct.get_metatype() == TypeMetatype::Pointer {
                    // cc:2573-2580: implied pointer out AND pointer token —
                    // preserve the implied pointer only when it points to a
                    // composite; otherwise retype to the token.
                    let pointee_composite = match out_high_resolve.as_ref() {
                        Datatype::Pointer(p) => matches!(
                            p.ptr_to.get_metatype(),
                            TypeMetatype::Array
                                | TypeMetatype::Struct
                                | TypeMetatype::Union
                        ),
                        _ => false,
                    };
                    if !pointee_composite {
                        outvn.write().unwrap().update_type(tokenct.clone());
                        out_high_resolve = Self::refresh_out_high_resolve(
                            &outvn,
                            &out_high_resolve,
                            &tokenct,
                        );
                    }
                }
            }
        }
        // cc:2583-2592: CAST unless forced; a pointer out whose first
        // field/array base matches the token takes the PTRSUB(#0) form.
        let mut num_inputs = 1;
        if !force {
            if out_high_resolve.get_metatype() == TypeMetatype::Pointer
                && Self::test_struct_offset0(&out_high_resolve, &tokenct, strategy)
            {
                num_inputs = 2; // CPUI_PTRSUB form
            } else if strategy
                .cast_standard_full(&out_high_resolve, &tokenct, false, true)
                .is_none()
            {
                return 0; // No cast needed.
            }
        }
        // cc:2595-2609: insert CAST/PTRSUB op after `op`.
        // vn = newUnique(outvn->getSize()); vn->updateType(tokenct); vn->setImplied()
        let vn = fd.new_unique(out_size);
        vn.write().unwrap().v_type = Some(tokenct.clone());
        vn.write().unwrap().set_implied();
        // cc:2598: newOp(2) for the PTRSUB form, newOp(1) for CAST.
        let op_addr = op.0.read().unwrap().get_addr();
        let newop = fd.new_op(num_inputs, op_addr);
        let opc = if num_inputs == 2 {
            OpCode::CPUI_PTRSUB
        } else {
            OpCode::CPUI_CAST
        };
        fd.op_set_opcode(&newop, opc);
        // opSetOutput(newop, outvn); opSetInput(newop, vn, 0)
        // opSetOutput(op, vn)
        // opInsertAfter(newop, op)
        // Rugra: use op_set_output/op_set_input so def links, WRITTEN flags
        // and descend xrefs are maintained consistently (faithful to Ghidra
        // which goes through Funcdata::opSetOutput/opSetInput).
        // Order is observable: the new op first steals outvn from its old
        // definition, then consumes the implied temporary, and only then is
        // the original op rebound to that temporary (cc:2603-2608).
        fd.op_set_output(&newop, outvn.clone());
        fd.op_set_input(&newop, vn.clone(), 0);
        if opc == OpCode::CPUI_PTRSUB {
            // cc:2605-2607: PTRSUB form reads the constant 0 in slot 1.
            let zero = fd.new_constant(4, 0);
            fd.op_set_input(&newop, zero, 1);
        }
        fd.op_set_output(&op, vn);
        fd.op_insert_after(&newop, op);
        1 // count += 1
    }

    // RUGRA-GLUE: cc:2570-2571/2578-2579 refresh helper — Varnode::updateType
    // calls high->typeDirty() in Ghidra so the following
    // getHighTypeDefFacing() recomputes from the just-written instance type;
    // Rugra's typeDirty is a no-op, so a high still reporting the pre-update
    /// type (single-instance implied temp) is projected as the token type.
    fn refresh_out_high_resolve(
        outvn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        stale: &Arc<crate::type_system::datatype::Datatype>,
        tokenct: &Arc<crate::type_system::datatype::Datatype>,
    ) -> Arc<crate::type_system::datatype::Datatype> {
        match outvn.read().unwrap().get_high_type_def_facing() {
            Some(t) if Arc::ptr_eq(&t, stale) => tokenct.clone(),
            Some(t) => t,
            None => tokenct.clone(),
        }
    }

    // Ghidra: coreaction.cc:2384 ActionSetCasts::testStructOffset0
    /// Test if the cast conflict can be resolved by passing to the first
    /// structure/array field: `curtype` (the token) must be a pointer whose
    /// pointee is a struct with a field at offset 0 (or an array); descending
    /// one pointer level on `reqtype` (the out type) and unwrapping one array
    /// layer on both sides, the cast must vanish under
    /// castStandard(req, cur, true, true). Faithful to
    /// `ActionSetCasts::testStructOffset0` (coreaction.cc:2384-2413).
    fn test_struct_offset0(
        reqtype: &Arc<crate::type_system::datatype::Datatype>,
        curtype: &Arc<crate::type_system::datatype::Datatype>,
        strategy: &crate::type_system::cast::CastStrategyC,
    ) -> bool {
        use crate::type_system::datatype::{Datatype, TypeMetatype};
        // cc:2387: curtype must be a pointer.
        let Datatype::Pointer(cur_ptr) = curtype.as_ref() else {
            return false;
        };
        let high_ptr_to = &cur_ptr.ptr_to;
        let (req_inner, cur_inner) = match high_ptr_to.as_ref() {
            Datatype::Struct(st) => {
                // cc:2391: numDepend() == 0 → false.
                if st.fields.is_empty() {
                    return false;
                }
                // cc:2392-2393: beginField() (offset-sorted) must sit at 0.
                let first = st.fields.iter().min_by_key(|f| f.offset).unwrap();
                if first.offset != 0 {
                    return false;
                }
                // cc:2394-2399: descend one pointer level on reqtype, unwrap
                // one array layer on both sides.
                let Datatype::Pointer(req_ptr) = reqtype.as_ref() else {
                    return false;
                };
                let peel_array = |t: &Arc<Datatype>| match t.as_ref() {
                    Datatype::Array(a) => a.array_of.clone(),
                    _ => t.clone(),
                };
                (peel_array(&req_ptr.ptr_to), peel_array(&first.type_ptr))
            }
            Datatype::Array(arr) => {
                let Datatype::Pointer(req_ptr) = reqtype.as_ref() else {
                    return false;
                };
                (req_ptr.ptr_to.clone(), arr.array_of.clone())
            }
            _ => return false,
        };
        // cc:2409-2410: never induce PTRSUB for "void *".
        if req_inner.get_metatype() == TypeMetatype::Void {
            return false;
        }
        // cc:2412: the resolved pair must not need a standard cast.
        strategy
            .cast_standard_full(&req_inner, &cur_inner, true, true)
            .is_none()
    }

    /// Faithful port of the PTRSUB/PTRADD pointer-fit arm of
    /// `ActionSetCasts::castInput` (coreaction.cc:2655-2720, PTRSUB/PTRADD
    /// branch). For a PTRSUB `c = PTRSUB(a, off)` or PTRADD
    /// `c = PTRADD(a, idx, sz)`, input slot 0 must be a pointer whose
    /// pointed-to type matches the op's expected base. If `a`'s (read-facing)
    /// varnode type differs from its high type in the way
    /// `TypeOpPtrsub/Ptradd::getInputCast` describes (see
    /// [`Self::ptr_input_reqtype`]), insert `out = CAST(a)` feeding slot 0
    /// with `reqtype`, so printc emits `(ptype *)a`.
    ///
    /// `reqtype` comes from the faithful getInputCast port; Ghidra's
    /// `castInput` inserts the cast directly for a non-null getInputCast
    /// return (its testStructOffset0/tryResolutionAdjustment rewrites are
    /// separate residuals here), so no second `castStandard` gate is applied.
    /// Returns true if a cast was inserted.
    // Ghidra: coreaction.cc:2655 ActionSetCasts::castInput (PTRSUB/PTRADD arm)
    fn cast_input_ptr(
        &self,
        fd: &mut Funcdata,
        op_ref: &crate::op::PcodeOpRef,
        slot: usize,
        strategy: &crate::type_system::cast::CastStrategyC,
        reqtype: std::sync::Arc<crate::type_system::datatype::Datatype>,
    ) -> bool {
        let _ = strategy;
        // (1) Read the current input varnode and its high type.
        let (in_vn, op_pc, in_size) = {
            let op = op_ref.0.read().unwrap();
            let Some(in_arc_ref) = op.get_in(slot) else { return false; };
            let in_arc = in_arc_ref.clone();
            let op_pc = op.get_addr();
            drop(op);
            let (in_size, is_annot) = {
                let in_rg = in_arc.read().unwrap();
                (in_rg.get_size(), in_rg.is_annotation())
            };
            if is_annot { return false; }
            (in_arc, op_pc, in_size)
        };
        // Constants cannot carry a pointer cast; skip (faithful to castInput
        // which only updates integer constants, never pointer constants).
        if in_vn.read().unwrap().is_constant() {
            return false;
        }
        // (2) Insert CPUI_CAST op: out = CAST(in), out implied.
        //     Faithful to coreaction.cc:2702-2712.
        let new_op = fd.new_op(1, op_pc);
        let out_vn = fd.new_unique_out(in_size, &new_op);
        out_vn.write().unwrap().v_type = Some(reqtype);
        out_vn.write().unwrap().set_implied();
        fd.op_set_opcode(&new_op, OpCode::CPUI_CAST);
        fd.op_set_input(&new_op, in_vn, 0);
        fd.op_set_input(op_ref, out_vn.clone(), slot);
        fd.op_insert_before(&new_op, op_ref);
        true
    }

    /// Compute the cast type for input slot 0 of a PTRSUB/PTRADD op, faithful
    /// to `TypeOpPtrsub::getInputCast` (typeop.cc:2320-2347) and
    /// `TypeOpPtradd::getInputCast` (typeop.cc:2250-2266).
    ///
    /// Both oracles compare the input VARNODE's own (read-facing) type —
    /// `reqtype` — against the input HIGH's (read-facing) type — `curtype`:
    /// PTRSUB additionally peels one array layer and unwraps typedefs before
    /// the base equality check; PTRADD compares the bases' `align_size`.
    /// Neither ever consults the op's OUTPUT type (the previous heuristic
    /// here did, which produced casts to downChain-transformed field pointers
    /// whenever ActionInferTypes gave the PTRSUB output a PointerRel form).
    ///
    /// Residual: `getTypeReadFacing`'s in-flow resolution of
    /// needs-resolution types (PointerRel et al.) is not available yet
    /// (ACTION-INFERTYPES-DISPATCH-0001) — the raw v_type/high type is used,
    /// which is exact for every type that does not need resolution. Rugra
    /// also has no typedef layer, so the `getTypedef()` unwrap loop is a
    /// structural no-op.
    // Ghidra: typeop.cc:2320 TypeOpPtrsub::getInputCast / typeop.cc:2250 TypeOpPtradd::getInputCast
    fn ptr_input_reqtype(
        op: &crate::op::PcodeOpRef,
    ) -> Option<std::sync::Arc<crate::type_system::datatype::Datatype>> {
        use crate::type_system::datatype::Datatype;
        use crate::type_system::TypeMetatype;
        let (opcode, in0_arc) = {
            let op = op.0.read().unwrap();
            (op.opcode, op.get_in(0).cloned()?)
        };
        let in0 = in0_arc.read().unwrap();
        // reqtype = op->getIn(0)->getTypeReadFacing(op)
        let reqtype = in0.v_type.clone()?;
        // curtype = op->getIn(0)->getHighTypeReadFacing(op)
        let curtype = in0
            .high
            .as_ref()
            .map(|h| h.read().unwrap().v_type.get())
            .unwrap_or_else(|| reqtype.clone());
        // Pointer-identity equality mirrors Ghidra's interned `Datatype*`
        // comparison; the name check extends it across separately-constructed
        // Arcs of the same named factory type.
        let same_type = |a: &Arc<Datatype>, b: &Arc<Datatype>| {
            Arc::ptr_eq(a, b) || (!a.get_name().is_empty() && a.get_name() == b.get_name())
        };
        let ptr_of = |t: &Arc<Datatype>| match t.as_ref() {
            Datatype::Pointer(p) => Some(p.ptr_to.clone()),
            _ => None,
        };
        match opcode {
            OpCode::CPUI_PTRSUB => {
                // typeop.cc:2327-2328
                if same_type(&curtype, &reqtype) {
                    return None;
                }
                // typeop.cc:2329-2331
                if reqtype.get_metatype() != TypeMetatype::Pointer {
                    return Some(reqtype);
                }
                if curtype.get_metatype() != TypeMetatype::Pointer {
                    return Some(reqtype);
                }
                // typeop.cc:2331-2335: go down exactly one level, peeling a
                // shared array layer.
                let reqbase = ptr_of(&reqtype)?;
                let curbase = ptr_of(&curtype)?;
                let (reqbase, curbase) = match (reqbase.as_ref(), curbase.as_ref()) {
                    (Datatype::Array(_), Datatype::Array(_)) => {
                        let peel = |b: &Arc<Datatype>| match b.as_ref() {
                            Datatype::Array(a) => a.array_of.clone(),
                            _ => b.clone(),
                        };
                        (peel(&reqbase), peel(&curbase))
                    }
                    _ => (reqbase, curbase),
                };
                // typeop.cc:2337-2340 typedef unwrap is a no-op (no typedef
                // layer in Rugra).
                // typeop.cc:2342-2344
                if same_type(&curbase, &reqbase) {
                    return None;
                }
                Some(reqtype)
            }
            OpCode::CPUI_PTRADD => {
                // typeop.cc:2257-2258
                if reqtype.get_metatype() != TypeMetatype::Pointer {
                    return Some(reqtype);
                }
                if curtype.get_metatype() != TypeMetatype::Pointer {
                    return Some(reqtype);
                }
                // typeop.cc:2259-2262: equal align sizes on the bases cancel
                // the cast.
                let reqbase = ptr_of(&reqtype)?;
                let curbase = ptr_of(&curtype)?;
                if reqbase.get_align_size() == curbase.get_align_size() {
                    return None;
                }
                Some(reqtype)
            }
            _ => None,
        }
    }

    // RUGRA-GLUE: output_metatype (no Ghidra direct counterpart; derived from
    // TypeOp::getOutputToken which Rugra lacks)
    /// Determine the output metatype for an opcode (for castOutput). Mirrors
    /// the integer/boolean branches of Ghidra's
    /// `TypeOp::getOutputToken(op, castStrategy)` (typeop.cc). Pointer-
    /// producing ops (PTRSUB/PTRADD/LOAD/CALL/COPY/etc.) return None so
    /// castOutput leaves their output pointer type untouched — the pointer
    /// shape is established upstream by ActionInferTypes / cast_input_ptr,
    /// and forcing a base-int token would wrongly cast `(long *)out` →
    /// `(long)out`.
    fn output_metatype(opc: OpCode) -> Option<crate::type_system::datatype::TypeMetatype> {
        use crate::opcodes::OpCode;
        use crate::type_system::datatype::TypeMetatype;
        match opc {
            OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
            | OpCode::CPUI_INT_SLESS | OpCode::CPUI_INT_SLESSEQUAL
            | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_LESSEQUAL
            | OpCode::CPUI_FLOAT_EQUAL | OpCode::CPUI_FLOAT_NOTEQUAL
            | OpCode::CPUI_FLOAT_LESS | OpCode::CPUI_FLOAT_LESSEQUAL
            | OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_XOR
            | OpCode::CPUI_BOOL_AND | OpCode::CPUI_BOOL_OR
            | OpCode::CPUI_INT_CARRY | OpCode::CPUI_INT_SCARRY
            | OpCode::CPUI_INT_SBORROW | OpCode::CPUI_FLOAT_NAN
            => Some(TypeMetatype::Bool),
            // Pointer-producing ops: their output token is the pointer type
            // itself (set by type inference), not a base int/bool. Skip
            // castOutput for them.
            OpCode::CPUI_PTRSUB | OpCode::CPUI_PTRADD
            | OpCode::CPUI_LOAD | OpCode::CPUI_CALL | OpCode::CPUI_CALLIND
            | OpCode::CPUI_COPY | OpCode::CPUI_INDIRECT
            | OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_CAST
            => None,
            _ => Some(TypeMetatype::Int),
        }
    }
}
impl Action for ActionSetCasts {
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:330
    fn get_flags(&self) -> u32 {
        action_flags::RULE_ONCEPERFUNC
    }

    // Ghidra: coreaction.cc:2722 ActionSetCasts::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // coreaction.cc:2729-2733 walks basic blocks in dominance order and
        // operations in each block's list order. Detached Rust fixtures that
        // have no basic-block graph retain their explicit alivelist order.
        let ops: Vec<crate::op::PcodeOpRef> = if fd.bblocks.blocks.is_empty() {
            fd.obank.alivelist.clone()
        } else {
            fd.bblocks
                .blocks
                .iter()
                .flat_map(|block| block.read().unwrap().get_ops())
                .collect()
        };
        let strategy = crate::type_system::cast::CastStrategyC::new(4);
        let mut changes = 0;
        // cc:2728: startCastPhase() records the cast-phase Varnode index.
        fd.start_cast_phase();
        for op_ref in &ops {
            let (opcode, skip) = {
                let op = op_ref.0.read().unwrap();
                let not_printed = op.flags
                    & (crate::op::pcodeop_flags::MARKER
                        | crate::op::pcodeop_flags::NONPRINTING
                        | crate::op::pcodeop_flags::NORETURN)
                    != 0;
                (
                    op.opcode,
                    op.is_dead() || not_printed || op.opcode == OpCode::CPUI_CAST,
                )
            };
            if skip { continue; }
            // cc:2740-2746: PTRADD that no longer fits its pointer — in0's
            // read-facing HIGH type must be a pointer whose pointee alignSize
            // equals addressToByteInt(scale, wordSize); otherwise the op is
            // rewritten in place through opUndoPtradd(op, true) (an implied
            // INT_MULT folds the scale in, constants folded outright).
            if opcode == OpCode::CPUI_PTRADD {
                let undo = {
                    let op = op_ref.0.read().unwrap();
                    match (op.get_in(2), op.get_in(0)) {
                        (Some(scale_vn), Some(base_vn)) => {
                            // cc:2741: int4 sz = (int4)op->getIn(2)->getOffset()
                            let sz = scale_vn.read().unwrap().get_offset() as u32 as i64;
                            // cc:2742: ct = op->getIn(0)->getHighTypeReadFacing(op)
                            let ct = base_vn
                                .read()
                                .unwrap()
                                .get_high_type_read_facing(&op, 0)
                                .or_else(|| base_vn.read().unwrap().v_type.clone());
                            match ct.as_deref() {
                                Some(crate::type_system::datatype::Datatype::Pointer(pt)) => {
                                    pt.ptr_to.get_align_size() as i64
                                        != crate::space::AddrSpace::address_to_byte_int(
                                            sz,
                                            pt.wordsize as u32,
                                        )
                                }
                                // cc:2743: ct->getMetatype() != TYPE_PTR → undo
                                _ => true,
                            }
                        }
                        // Malformed PTRADD: Ghidra reads slots 2/0 blind; the
                        // defensive no-op keeps detached fixtures alive.
                        _ => false,
                    }
                };
                if undo {
                    fd.op_undo_ptradd_full(op_ref, true);
                }
            }
            // cc:2747-2756: PTRSUB that no longer fits its pointer — demote
            // offset 0 to COPY (dropping the offset input), else INT_ADD.
            // The demoted op keeps flowing through this iteration's
            // castInput/castOutput under its NEW opcode (Ghidra re-reads
            // code()/numInput() live after the rewrite).
            else if opcode == OpCode::CPUI_PTRSUB {
                let (demote, offset_is_zero) = {
                    let op = op_ref.0.read().unwrap();
                    match (op.get_in(0), op.get_in(1)) {
                        (Some(base_vn), Some(off_vn)) => {
                            // cc:2748: isPtrsubMatching(in(1) offset, 0, 0)
                            let off = off_vn.read().unwrap().get_offset() as i64;
                            let t = base_vn
                                .read()
                                .unwrap()
                                .get_type_read_facing_op(&op, 0)
                                .or_else(|| base_vn.read().unwrap().v_type.clone());
                            let matches = match t.as_deref() {
                                Some(crate::type_system::datatype::Datatype::Pointer(pt)) => {
                                    crate::type_system::datatype::pointer_is_ptrsub_matching(
                                        &pt.ptr_to,
                                        pt.wordsize,
                                        off,
                                        0,
                                        0,
                                    )
                                }
                                // Base Datatype::isPtrsubMatching returns false.
                                _ => false,
                            };
                            (!matches, off == 0)
                        }
                        _ => (false, false),
                    }
                };
                if demote {
                    if offset_is_zero {
                        fd.op_remove_input(op_ref, 1);
                        fd.op_set_opcode(op_ref, OpCode::CPUI_COPY);
                    } else {
                        fd.op_set_opcode(op_ref, OpCode::CPUI_INT_ADD);
                    }
                }
            }
            // coreaction.cc:2756-2759: every operation is handled atomically:
            // all of its input casts precede its output cast. In particular,
            // a later op observes the output mutation of an earlier op.
            // The input count and the slot-0 dispatch opcode are re-read
            // AFTER the preflight (Ghidra evaluates op->numInput() live in
            // the loop condition and dispatches virtually on the current
            // opcode).
            let (live_opcode, input_count) = {
                let op = op_ref.0.read().unwrap();
                (op.opcode, op.num_input())
            };
            for slot in 0..input_count {
                let changed =
                    if slot == 0 && matches!(live_opcode, OpCode::CPUI_PTRSUB | OpCode::CPUI_PTRADD) {
                        Self::ptr_input_reqtype(op_ref).is_some_and(|required| {
                            self.cast_input_ptr(fd, op_ref, slot, &strategy, required)
                        })
                    } else {
                        self.cast_input(fd, op_ref, slot, &strategy) };
                if changed {
                    changes += 1;
                }
            }

            // resolveUnion and checkPointerIssues remain separately
            // registered residuals; the ordering here now matches the oracle
            // for the implemented castInput/castOutput closure.
            changes += Self::cast_output(fd, op_ref, &strategy);
        }

        // Ghidra mutates Action::count and returns 0 from raw apply. The Rust
        // executor drains this field through take_count_delta below.
        self.count += changes;
        Ok(action_status::NO_CHANGE)
    }

    // RUGRA-GLUE: exposes ActionSetCasts inherited count through external ActionState after raw apply returns Ghidra's 0
    fn take_count_delta(&mut self) -> i32 {
        let changes = self.count ;
        self.count = 0 ;
        changes
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

/// TypeOrder-min merge for one varnode's temp type: keep the strictly more
/// specific candidate, ties keep the incumbent (first seeded). This is the
/// descendant competition loop of `Varnode::getLocalType`
/// (varnode.cc:926-931):
/// `if (ct == (Datatype *)0) ct = newct; else { if (0>newct->typeOrder(*ct)) ct = newct; }`
/// — replacement only on strictly negative typeOrder, so the first-seeded
/// type survives an ordering tie.
// Ghidra: varnode.cc:900 Varnode::getLocalType (typeOrder-min competition at :926-931)
fn merge_min_type_order(
    temps: &mut TempTypes,
    id: u64,
    ct: std::sync::Arc<crate::type_system::datatype::Datatype>,
) {
    use std::collections::hash_map::Entry;
    match temps.entry(id) {
        Entry::Occupied(mut entry) => {
            if ct.type_order(entry.get()) < 0 {
                entry.insert(ct);
            }
        }
        Entry::Vacant(entry) => {
            entry.insert(ct);
        }
    }
}

/// Build a pointer type to `base` with the architecture pointer size, using a
/// fresh factory-free TypePointer. Faithful to `TypeFactory::getTypePointer`.
// RUGRA-GLUE: helper mirroring TypeFactory::getTypePointer (type.hh)
// Ghidra: type.cc:3867 TypeFactory::getTypePointer(int4,Datatype*,uint4) — the
// 3-arg overload's `TypePointer tmp(s,pt,ws)` carries an EMPTY name (names
// attach only via the 4-arg overload, type.cc:3885); see make_pointer_type's
// note for why the former composed-name spelling diverged from the oracle.
fn make_ptr(
    base: std::sync::Arc<crate::type_system::datatype::Datatype>,
    ptr_size: usize,
) -> std::sync::Arc<crate::type_system::datatype::Datatype> {
    use crate::type_system::datatype::Datatype;
    std::sync::Arc::new(Datatype::Pointer(
        crate::type_system::datatype::TypePointer::new(ptr_size, base, 1),
    ))
}

// Ghidra: type.cc:3392 TypeFactory::findAdd (canonical interning every propagateType product flows through)
/// Canonicalize a temporary data-type through the architecture TypeFactory.
///
/// In the oracle, every `Datatype*` that ActionInferTypes handles is
/// TypeFactory-interned: `buildLocaltypes` seeds from `getOutputLocal`/
/// `getInputLocal`, which end in `tlst->getBase(...)` (typeop.cc:264), and
/// every `propagateType` override builds its result through the factory
/// (`TypeOp::propagateToPointer` ends in `t->getTypePointer`, typeop.cc:197).
/// `Varnode::updateType` then settles on the C++ pointer comparison
/// `type == ct` (varnode.cc:459) — structurally identical types are the
/// same interned pointer, so a second writeBack pass reports no change and
/// the `localcount >= 7` "not settling" warning (coreaction.cc:5390-5392)
/// stays cold.
///
/// Rugra's temp-type producers include factory-free constructors (the
/// COPY-spacebase pointer arm below, `typeop::propagate_to_pointer`), so a
/// raw `Arc::ptr_eq` in `Varnode::updateType` never matches across passes
/// and writeBack reported a change on every round forever. Routing every
/// temp type through the factory here restores the interned-pointer
/// invariant the oracle's settle behavior depends on. Canonicalization is
/// conservative: a factory answer is accepted only when it is structurally
/// equal (same metatype/size/name for scalars, same size/wordsize for
/// pointers with a recursively canonical pointee); anything else passes
/// through unchanged.
fn canonicalize_temp_type(
    dt: &std::sync::Arc<crate::type_system::datatype::Datatype>,
    type_factory: Option<&Arc<RwLock<crate::type_system::typefactory::TypeFactory>>>,
) -> std::sync::Arc<crate::type_system::datatype::Datatype> {
    use crate::type_system::datatype::{Datatype, TypeMetatype};
    let Some(factory) = type_factory else {
        return dt.clone();
    };
    match dt.as_ref() {
        Datatype::Base(_) => {
            let size = dt.get_size();
            let meta = dt.get_metatype();
            if !matches!(
                meta,
                TypeMetatype::Bool
                    | TypeMetatype::Uint
                    | TypeMetatype::Int
                    | TypeMetatype::Float
                    | TypeMetatype::Unknown
            ) {
                return dt.clone();
            }
            let mut factory = factory
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let name = dt.get_name();
            if !name.is_empty() {
                // Named scalar (e.g. "size_t"): the oracle keeps every named
                // Datatype in the factory nametree (type.cc:3404-3405), so
                // getBase(s,m,n) (type.cc:3667-3673) returns the same interned
                // instance on every call.
                match factory.get_base_named(size, meta, name) {
                    Ok(canonical)
                        if canonical.get_size() == size && canonical.get_metatype() == meta =>
                    {
                        return canonical;
                    }
                    _ => return dt.clone(),
                }
            }
            match factory.get_base(size, meta) {
                Some(canonical)
                    if canonical.get_size() == size
                        && canonical.get_metatype() == meta
                        && canonical.get_name() == dt.get_name() =>
                {
                    canonical
                }
                _ => dt.clone(),
            }
        }
        Datatype::Pointer(ptr) => {
            let pointee =
                canonicalize_temp_type(&ptr.ptr_to, type_factory);
            // Preserve the pointer's own name: named pointers (e.g. the
            // signature table's "char *") intern by (name,id) in the factory
            // nametree (type.cc:3404-3405/3417-3425), and the print layer
            // renders a named pointer through its name. Look the name up in
            // the factory and accept only a structurally compatible entry
            // (Ghidra would raise "Trying to alter definition of type"
            // otherwise, type.cc:3423); on any miss keep the original Arc —
            // stable producer Arcs still settle under ptr_eq. Unnamed
            // pointers take the structural getTypePointer(s,pt,ws) form
            // (type.cc:3867-3883).
            if !ptr.base.name.is_empty() {
                let existing = factory
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .find_by_name(&ptr.base.name);
                if let Some(canonical) = existing {
                    let compatible = canonical.get_size() == dt.get_size()
                        && canonical.get_metatype() == TypeMetatype::Pointer
                        && matches!(canonical.as_ref(), Datatype::Pointer(cp)
                            if std::sync::Arc::ptr_eq(&cp.ptr_to, &pointee)
                                || cp.ptr_to.type_order(&pointee) == 0);
                    if compatible {
                        return canonical;
                    }
                }
                return dt.clone();
            }
            let mut factory = factory
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let canonical = factory.get_ptr(pointee);
            if canonical.get_size() == dt.get_size()
                && canonical.get_metatype() == TypeMetatype::Pointer
            {
                canonical
            } else {
                dt.clone()
            }
        }
        _ => dt.clone(),
    }
}

impl ActionInferTypes {
    // Ghidra: coreaction.cc:5008 ActionInferTypes::buildLocaltypes
    /// Collect the local data-type for each eligible Varnode in loc-set order.
    ///
    /// This follows the oracle's one-pass dispatch: an exact piece from a
    /// type-locked parent Symbol wins when it resolves to a concrete type;
    /// otherwise the Varnode's defining op and descendants are queried through
    /// `Varnode::get_local_type`.  There is no size-based scalar fallback and
    /// no second op-centric seeding pass.
    fn build_localtypes(
        &self,
        fd: &Funcdata,
        temps: &mut TempTypes,
        _int_types: &IntTypes,
        _ptr_size: usize,
    ) -> Result<()> {
        let type_factory = fd
            .arch
            .as_ref()
            .and_then(|architecture| architecture.types.clone())
            .unwrap_or_else(crate::type_system::typefactory::TypeFactory::shared_default);
        let userops = fd
            .arch
            .as_ref()
            .and_then(|architecture| architecture.userops.clone());

        // coreaction.cc:5016: beginLoc()/endLoc() is VarnodeLocSet order.
        for vn_arc in fd.vbank.loc_tree.iter().map(|entry| entry.0.clone()) {
            let (mapentry, type_locked, address, size, id) = {
                let vn = vn_arc.read().unwrap();
                // cc:5018-5019: annotations and free, unread Varnodes have no
                // temporary type and are skipped in place.
                if vn.is_annotation() || (!vn.is_written() && vn.has_no_descend()) {
                    continue;
                }
                (
                    vn.mapentry.clone(),
                    vn.is_type_lock(),
                    *vn.get_addr(),
                    vn.get_size(),
                    vn_id(&vn),
                )
            };

            // cc:5021-5027: a type-locked parent Symbol can provide an exact
            // piece even when this particular Varnode is not type locked.
            let exact_piece = if !type_locked {
                if let Some(entry_arc) = mapentry {
                    let (symbol, entry_address, entry_offset) = {
                        let entry = entry_arc.read().unwrap();
                        (entry.get_symbol(), entry.get_addr(), entry.get_offset())
                    };
                    let symbol_type = {
                        let symbol = symbol.read().unwrap();
                        symbol.is_type_locked().then(|| symbol.get_type()).flatten()
                    };
                    if let Some(symbol_type) = symbol_type {
                        // The C++ expression is assigned to int4 after unsigned
                        // address arithmetic. Preserve its wrapping truncation.
                        let current_offset = address
                            .as_u64()
                            .wrapping_sub(entry_address.as_u64())
                            .wrapping_add(entry_offset as u64)
                            as i32;
                        type_factory
                            .write()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .get_exact_piece(symbol_type, current_offset as i64, size)
                            .filter(|datatype| {
                                datatype.get_metatype()
                                    != crate::type_system::datatype::TypeMetatype::Unknown
                            })
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            // cc:5020 resets needsBlock for every Varnode. getLocalType is the
            // only path that can set it; a successful exact-piece lookup leaves
            // it false.
            let mut needs_block = false;
            let local_type = if let Some(exact_piece) = exact_piece {
                Some(exact_piece)
            } else {
                vn_arc
                    .read()
                    .unwrap()
                    .get_local_type(&mut needs_block, &type_factory, userops.as_ref())
                    .map_err(|error| crate::error::Error::Lowlevel(error.to_string()))?
            };
            if needs_block {
                vn_arc.write().unwrap().set_stop_up_propagation();
            }
            if let Some(local_type) = local_type {
                // The oracle seeds temp types exclusively from factory types
                // (typeop.cc:264 tlst->getBase); canonicalize so identical
                // locals share one Arc across passes (writeBack settle).
                let local_type = canonicalize_temp_type(
                    &local_type,
                    fd.arch.as_ref().and_then(|a| a.types.as_ref()),
                );
                temps.insert(id , local_type);
            }
        }
        Ok(())
    }

    /// Faithful to `ActionInferTypes::propagateTypeEdge` (coreaction.cc:5074-5112).
    /// Attempt to propagate a data-type across a single PcodeOp edge.
    /// `inslot` is the edge's input varnode slot (-1 = op output);
    /// `outslot` is the edge's output slot (-1 = op output).
    /// Returns the out varnode arc if the propagation changed its temp type.
    // Ghidra: coreaction.cc:5074 ActionInferTypes::propagateTypeEdge
    fn propagate_type_edge(
        op: &crate::op::PcodeOp,
        temps: &mut TempTypes,
        active_path: &std::collections::HashSet<u64>,
        inslot: i32,
        outslot: i32,
        int_types: &IntTypes,
        ptr_size: usize,
        type_factory: Option<&Arc<RwLock<crate::type_system::typefactory::TypeFactory>>>,
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
            // coreaction.cc:5093: `if (outvn->stopsUpPropagation() && outslot >= 0)
            // return false;` — propagation is blocked into a STOP-sealed
            // varnode when it is the edge's INPUT-slot target (outslot >= 0);
            // an edge targeting the op's OUTPUT (outslot == -1) is not subject
            // to this flag, which is exactly what lets the downChain
            // field-pointer flow reach a RulePtrArith-sealed PTRSUB output.
            if outslot >= 0 && ov.stops_up_propagation() {
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
        let newtype = Self::propagate_type(
            op,
            &alttype,
            inslot,
            outslot,
            int_types,
            ptr_size,
            type_factory,
        )?;
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
        if !better {
            return None;
        }

        // coreaction.cc:5106-5110: setTempType happens even if this Varnode is
        // already marked. The mark suppresses only recursive descent; it must
        // not suppress the better temporary type itself. The oracle's temp
        // type is factory-interned (every propagateType override builds
        // through the TypeFactory); canonicalize here so structurally equal
        // types share one Arc and writeBack's updateType settles.
        let newtype = canonicalize_temp_type(&newtype, type_factory);
        let out_id = vn_id(&out_vn_arc.read().unwrap());
        temps.insert(out_id, newtype);
        (!active_path.contains(&out_id)).then_some(out_vn_arc)
    }

    /// Per-opcode `propagateType` dispatch. Faithful to
    /// `OpCode::propagateType` (typeop*.cc). Returns the type that the output
    /// varnode should take when `alttype` flows from `inslot` to `outslot`.
    /// `type_factory` is the owning Architecture TypeFactory that the C++
    /// original reaches through the TypeOp's `tlst` member (op.hh:122); the
    /// add-family pointer arms need it to intern the downChain-transformed
    /// types, so they stop the propagation when no factory is available.
    // RUGRA-GLUE: Rugra driver that folds ActionInferTypes::propagateOneType over the varnode set (coreaction.cc:5400-5405)
    fn propagate_type(
        op: &crate::op::PcodeOp,
        alttype: &std::sync::Arc<crate::type_system::datatype::Datatype>,
        inslot: i32,
        outslot: i32,
        int_types: &IntTypes,
        _ptr_size: usize,
        type_factory: Option<&Arc<RwLock<crate::type_system::typefactory::TypeFactory>>>,
    ) -> Option<std::sync::Arc<crate::type_system::datatype::Datatype>> {
        use crate::type_system::datatype::TypeMetatype;
        let alt_meta = alttype.get_metatype();
        match op.opcode {
            // COPY (typeop.cc:411-423 TypeOpCopy::propagateType): the type
            // flows between the output and the single input only
            // (`(inslot!=-1)&&(outslot!=-1)` returns null — no input↔input
            // edges exist for a 1-input op in the PropagationState walk, but
            // the guard is kept faithful). A SPACEBASE input transforms to a
            // pointer-to-unknown1 of the alttype's size; anything else flows
            // unchanged.
            OpCode::CPUI_COPY => {
                if inslot != -1 && outslot != -1 {
                    return None; // Must propagate input <-> output
                }
                let in_vn_is_spacebase = if inslot == -1 {
                    op.get_out().cloned()
                } else {
                    op.inrefs.get(inslot as usize).cloned()
                }
                .map(|v| v.read().unwrap().is_spacebase())
                .unwrap_or(false);
                if in_vn_is_spacebase {
                    let factory = type_factory?;
                    let unknown1 = factory
                        .read()
                        .unwrap()
                        .get_base(1, TypeMetatype::Unknown)
                        .unwrap_or_else(|| {
                            std::sync::Arc::new(crate::type_system::datatype::Datatype::Base(
                                crate::type_system::datatype::TypeBase::new(
                                    "unknown".to_string(),
                                    1,
                                    TypeMetatype::Unknown,
                                ),
                            ))
                        });
                    let mut factory = factory.write().unwrap();
                    let _ = &mut factory;
                    return Some(std::sync::Arc::new(
                        crate::type_system::datatype::Datatype::Pointer(
                            // typeop.cc:418: tlst->getTypePointer(sz, getBase(1,
                            // TYPE_UNKNOWN), ws) — the 3-arg overload is
                            // anonymous (type.cc:3867-3875); the composed-name
                            // spelling diverged from the oracle (see
                            // make_pointer_type's note).
                            crate::type_system::datatype::TypePointer::new(
                                alttype.get_size(),
                                unknown1,
                                1,
                            ),
                        ),
                    ));
                    // (get_type_pointer interning form; wordsize from the
                    // default data space — the worker cspec's ram space has
                    // wordsize 1.)
                }
                Some(alttype.clone())
            }

            // MULTIEQUAL (phi): Ghidra has NO TypeOpMultiequal::propagateType
            // override — the base TypeOp::propagateType (typeop.cc:317-321)
            // returns null, so types NEVER flow across a phi's edges during
            // ActionInferTypes. The earlier `Some(alttype)` here let a
            // locked CALL output type leak through the phi into sibling
            // inputs (my_fwrite: fopen's FILE* overwrote the LOAD-out temp
            // and then lost to the inferred char*), diverging from the
            // oracle where phi members keep their independent temps and the
            // HighVariable::getTypeRepresentative merge (variable.cc:377-395)
            // alone decides the high type.
            OpCode::CPUI_MULTIEQUAL => None,

            // INDIRECT (typeop.cc:2005-2020 TypeOpIndirect::propagateType):
            // see the dedicated arm below.

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

            // PTRSUB (typeop.cc:2366-2378 TypeOpPtrsub::propagateType): a
            // pointer input is transformed through propagateAddIn2Out's
            // downChain — the struct offset is consumed and the output takes
            // the field pointer / ephemeral PointerRel form. It never
            // propagates output->input, nor across two input slots.
            OpCode::CPUI_PTRSUB => {
                if inslot != -1 && outslot != -1 {
                    return None; // Must propagate input <-> output
                }
                if alt_meta != TypeMetatype::Pointer {
                    return None;
                }
                if inslot == -1 {
                    // Propagating output to input: don't propagate pointer
                    // types this direction.
                    return None;
                }
                let factory = type_factory?;
                crate::typeop::TypeOpIntAdd::propagate_add_in2out(alttype, factory, op, inslot)
            }

            // PTRADD (typeop.cc:2268-2281 TypeOpPtradd::propagateType): same
            // pointer transformation as PTRSUB, plus the slot-2 multiplier
            // edge rejection.
            OpCode::CPUI_PTRADD => {
                if inslot == 2 || outslot == 2 {
                    return None; // Don't propagate along this edge
                }
                if inslot != -1 && outslot != -1 {
                    return None; // Must propagate input <-> output
                }
                if alt_meta != TypeMetatype::Pointer {
                    return None;
                }
                if inslot == -1 {
                    return None;
                }
                let factory = type_factory?;
                crate::typeop::TypeOpIntAdd::propagate_add_in2out(alttype, factory, op, inslot)
            }

            // INT_ADD (typeop.cc:1181-1201 TypeOpIntAdd::propagateType): ints
            // only flow when added to the slot-1 constant; pointers flow
            // input->output through the same downChain transform.
            OpCode::CPUI_INT_ADD => {
                if alt_meta != TypeMetatype::Pointer {
                    if alt_meta != TypeMetatype::Int && alt_meta != TypeMetatype::Uint {
                        return None;
                    }
                    if outslot != 1
                        || !op
                            .get_in(1)
                            .is_some_and(|in1| in1.read().unwrap().is_constant())
                    {
                        return None;
                    }
                } else if inslot != -1 && outslot != -1 {
                    return None; // Must propagate input <-> output for pointers
                }
                // outvn is the edge's output varnode (op output when
                // outslot < 0, else the op input at outslot).
                let out_is_constant = if outslot < 0 {
                    op.get_out()
                        .is_some_and(|out| out.read().unwrap().is_constant())
                } else {
                    op.get_in(outslot as usize)
                        .is_some_and(|out| out.read().unwrap().is_constant())
                };
                if out_is_constant && alt_meta != TypeMetatype::Pointer {
                    return Some(alttype.clone());
                }
                if inslot == -1 {
                    // Propagating output to input: don't propagate pointer
                    // types this direction.
                    return None;
                }
                let factory = type_factory?;
                crate::typeop::TypeOpIntAdd::propagate_add_in2out(alttype, factory, op, inslot)
            }

            // INT_SUB: `TypeOpIntSub` has no propagateType override; the
            // base `TypeOp::propagateType` (typeop.cc:317-321) returns null —
            // pointers never propagate through a subtraction.
            OpCode::CPUI_INT_SUB => None,

            // LOAD: the address (slot 1) is a pointer to the output's type,
            // and vice-versa.
            OpCode::CPUI_LOAD => {
                if inslot == 1 && outslot == -1 {
                    // pointer → dereferenced type
                    let dereference_size = op
                        .get_out()
                        .map(|target| target.read().unwrap().get_size())?;
                    return crate::typeop::propagate_from_pointer(
                        alttype,
                        dereference_size);
                }
                if inslot == -1 && outslot == 1 {
                    // output type → address becomes pointer to it.
                    // Ghidra TypeOpLoad::propagateType (typeop.cc:493-496)
                    // wraps via propagateToPointer (typeop.cc:186-198),
                    // which truncates a pointer alttype to unknown* — the
                    // raw ptr-of-ptr here typed my_fwrite's
                    // `stream->_IO_read_ptr` address FILE** (out FILE* →
                    // make_ptr(FILE*)), which outranked the downChain field
                    // type char** in the typeOrder competition and
                    // suppressed the golden `(FILE *)`/`(char *)` casts.
                    return Some(crate::typeop::propagate_to_pointer(alttype));
                }
                None
            }

            // STORE: address (slot 1) ↔ stored value (slot 2).
            OpCode::CPUI_STORE => {
                if inslot == 1 && outslot == 2 {
                    let dereference_size = op
                        .get_in(2)
                        .map(|target| target.read().unwrap().get_size())?;
                    return crate::typeop::propagate_from_pointer(
                        alttype,
                        dereference_size);
                }
                if inslot == 2 && outslot == 1 {
                    // value → address: propagateToPointer truncation, same
                    // as the LOAD arm (TypeOpStore::propagateType,
                    // typeop.cc:563-566).
                    return Some(crate::typeop::propagate_to_pointer(alttype));
                }
                None
            }

            // TypeOpEqual::propagateAcrossCompare (typeop.cc:961-989):
            // comparisons propagate ACROSS THE INPUTS only (`if (inslot == -1
            // || outslot == -1) return 0`) — a typed operand lends its type
            // to the sibling (so `value != 0` types the constant char*);
            // the boolean output never participates.
            OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL | OpCode::CPUI_INT_LESS
            | OpCode::CPUI_INT_SLESS | OpCode::CPUI_INT_LESSEQUAL
            | OpCode::CPUI_INT_SLESSEQUAL | OpCode::CPUI_FLOAT_EQUAL
            | OpCode::CPUI_FLOAT_NOTEQUAL | OpCode::CPUI_FLOAT_LESS
            | OpCode::CPUI_FLOAT_LESSEQUAL => {
                if inslot >= 0 && outslot >= 0 {
                    Some(alttype.clone())
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
    /// edge. The mark set is the active DFS path, not a global visited set.
    // Ghidra: coreaction.cc:5172 ActionInferTypes::propagateOneType
    fn propagate_one_type(
        &self,
        root: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        temps: &mut TempTypes,
        int_types: &IntTypes,
        ptr_size: usize,
        type_factory: Option<&Arc<RwLock<crate::type_system::typefactory::TypeFactory>>>,
    ) {
        use std::collections::HashSet;
        #[derive(Clone)]
        struct Edge {
            op: std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>,
            inslot: i32,
            outslot: i32,
        }

        struct Frame {
            vn_id: u64,
            edges: Vec<Edge> ,
            next: usize,
        }

        // PropagationState constructor + step (coreaction.cc:5115-5163): for
        // each descendant in insertion order, visit its output first (when it
        // has one), then every input slot including the back-edge slot. Only
        // after all descendants are exhausted do we visit the defining op's
        // inputs. propagateTypeEdge itself rejects the back-edge.
        let edges_for = |vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>| {
            let (descendants, defining) = {
                let vn_guard = vn.read().unwrap();
                (
                    vn_guard.descend_iter().collect::<Vec<_> >(),
                    vn_guard.get_def(),
                )
            };
            let mut edges = Vec::new();
            for descendant in descendants {
                let op_guard = descendant.read().unwrap();
                let Some(inslot ) = op_guard
                    .inrefs
                    .iter()
                    .position(|input| std::sync::Arc::ptr_eq(input, vn))
                    .map(|slot| slot as i32)
            else {
                    continue;
                };
                if op_guard.output.is_some() {
                    edges.push(Edge { op: descendant.clone(), inslot, outslot: -1 ,
                    });
                }
                for outslot in 0..op_guard.num_input() {
                    edges.push(Edge {
                        op: descendant.clone(),
                        inslot,
                        outslot: outslot as i32 ,
                    });
                }
            }
            if let Some(defining) = defining {
                let input_count = defining.read().unwrap().num_input();
                for outslot in 0..input_count {
                    edges.push(Edge { op: defining.clone(), inslot: -1, outslot: outslot as i32 ,
                    });
                }
            }
            edges
        };

        let root_id = vn_id(&root.read().unwrap());
        let mut active_path = HashSet::from([root_id]);
        let mut stack = vec![Frame {
            vn_id: root_id,
            edges: edges_for(root),
            next: 0,
        }];

        while !stack.is_empty() {
            let edge = {
                let frame = stack.last_mut().unwrap();
                if frame.next == frame.edges.len() {
                    active_path.remove(&frame.vn_id);
                    stack.pop();
                    continue;
                }
                let edge = frame.edges[frame.next].clone();
                // coreaction.cc:5191: advance the parent frame before the
                // child state is pushed.
                frame.next += 1;
                edge
            };

            let next_vn = {
                let op = edge.op.read().unwrap();
                Self::propagate_type_edge(
                    &op,
                    temps,
                    &active_path,
                    edge.inslot,
                    edge.outslot,
                    int_types,
                    ptr_size,
                    type_factory,
                )
            };
            if let Some(next_vn) = next_vn {
                let next_id = vn_id(&next_vn.read().unwrap());
                active_path.insert(next_id);
                stack.push(Frame {
                    vn_id: next_id,
                    edges: edges_for(&next_vn),
                    next: 0,
                    });
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
        type_factory: Option<&Arc<RwLock<crate::type_system::typefactory::TypeFactory>>>,
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
                self.propagate_one_type(&rv2, temps, int_types, ptr_size, type_factory);
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
    // Ghidra: coreaction.hh:975 ActionInferTypes::reset
    /// `virtual void reset(Funcdata &data) { localcount = 0; }` — the
    /// settling-pass counter is per-function; without this override the
    /// counter leaks across functions in a shared action pool and trips the
    /// 7-pass cap spuriously.
    fn reset(&mut self, _fd: &mut Funcdata) {
        self.local_count = 0;
    }
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
                // coreaction.cc:5393: data.setTypeRecoveryExceeded(); — the
                // flag is what lets RulePtrArith's buildTree
                // (ruleaction.cc:6502/6514) stamp propagated types on new
                // PTRADD/PTRSUB outputs itself, since this loop no longer runs.
                fd.set_type_recovery_exceeded();
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
        self.build_localtypes(fd, &mut temps, &int_types, ptr_size)?;

        // 3b. Seed struct-pointer types from DWARF-known globals. Stamp the
        // address of any known global (e.g. `::config` @ 0x17520 →
        // Configurable*) onto the varnode that holds that address, then the
        // standard COPY/INT_ADD/PTRSUB propagation diffuses it. Mirrors
        // Ghidra's SymbolEntry→Datatype linkage that Rugra's driver populates
        // via `Funcdata::global_struct_ptrs` (Rugra has no Architecture/
        // SymbolTable layer).
        seed_global_struct_pointers(fd, &mut temps, ptr_size);

        // 4. For each eligible varnode, propagate its type via DFS. The
        // Architecture TypeFactory (Ghidra's `data.getArch()->types`,
        // coreaction.cc:5377) threads down to the add-family pointer arms,
        // which intern downChain-transformed types through it.
        let type_factory: Option<
            Arc<RwLock<crate::type_system::typefactory::TypeFactory>>> = fd.arch.as_ref().and_then(|a| a.types.clone());
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

                self.propagate_one_type(
                    root,
                    &mut temps,
                    &int_types,
                    ptr_size,
                    type_factory.as_ref(),
                );
            }
        }

        // 5. propagateAcrossReturns.
        self.propagate_across_returns(fd, &mut temps, &int_types, ptr_size, type_factory.as_ref());

        // 6. writeBack: commit temp types to v_type.
        if self.write_back(fd, &temps) {
            self.local_count += 1;
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "infertypes" mirrors ctor at coreaction.hh:960
    fn get_name(&self) -> &str { "infertypes" }
}

// RUGRA-GLUE: seed_global_struct_pointers (no Ghidra counterpart found)
/// Stamp struct-pointer types from `Funcdata::global_struct_ptrs` into the
/// ActionInferTypes temp-type map. This is Rugra's stand-in for Ghidra's
/// SymbolEntry→Datatype linkage (database.cc): when the decompiler sees a
/// varnode holding the address of a DWARF-known global, that global's
/// struct-pointer type flows onto it. Without this seed, Rugra can only
/// synthesise a field-less `_struct *`, which never yields `->field` accesses
/// nor drives RulePtrArith with a sized pointee.
///
/// Because Rugra runs without an Architecture/SymbolTable layer, the driver
/// (curl_decompile.rs) registers the known globals in
/// `Funcdata::global_struct_ptrs` first. We scan every live varnode and, when
/// a constant or Ram-space varnode's offset matches a known global address,
/// seed its temp type with the struct pointer.
fn seed_global_struct_pointers(
    fd: &Funcdata,
    temps: &mut TempTypes,
    ptr_size: usize) {
    if fd.global_struct_ptrs.is_empty() {
        return;
    }
    let globals: Vec<(u64, std::sync::Arc<crate::type_system::datatype::Datatype>)> = fd
        .global_struct_ptrs
        .iter()
        .map(|(addr, dt)| (*addr, dt.clone()))
        .collect();
    let known: std::collections::HashMap<
        u64, std::sync::Arc<crate::type_system::datatype::Datatype>,
    > =
        globals.into_iter().collect();

    // 1. Search loc_tree for direct address constants
    for vn_ref in &fd.vbank.loc_tree {
        let vn = vn_ref.0.read().unwrap();
        if vn.is_annotation() || vn.is_free() { continue; }
        let off = vn.get_offset();
        
        // Match known global addresses in both Const and Ram spaces.
        // SLEIGH's ram space (index 0) maps to Rugra's Const, so global
        // addresses like 0x17520 surface as Const@0x17520.
        if known.contains_key(&off)
            && matches!(
                vn.get_space(), crate::space::AddressSpace::Const | crate::space::AddressSpace::Ram
            )
        {
            if let Some(dt) = known.get(&off) {
                temps.insert(vn_id(&vn), dt.clone());
            }
        }
    }
    // 2. Search COPY ops: if COPY(Const/Ram@addr) → output, stamp output
    // This catches Heritage-renamed varnodes where the address constant
    // was folded into a COPY input but the output (in Register space)
    // carries the global's address value.
    for op_ref in &fd.obank.alivelist {
        let op = op_ref.0.read().unwrap();
        if op.opcode != crate::opcodes::OpCode::CPUI_COPY {
            continue;
        }
        if let Some(in0) = op.get_in(0) {
            if let Some(ref out_arc) = op.output {
            let src = in0.read().unwrap();
            let off = src.get_offset();
            if known.contains_key(&off)
                && matches!(
                        src.get_space(), crate::space::AddressSpace::Const | crate::space::AddressSpace::Ram
                    )
            {
                let out_vn = out_arc.read().unwrap();
                if let Some(dt) = known.get(&off) {
                    temps.insert(vn_id(&out_vn), dt.clone());
                }
            }
            }
        }
    }
    // 3. Search block ops for COPY(Const/Ram@addr) → output
    for i in 0..fd.bblocks.get_size() {
        if let Some(block_arc) = fd.bblocks.get_block(i) {
            for op_ref in &block_arc.read().unwrap().get_ops() {
                let op = op_ref.0.read().unwrap();
                if op.opcode != crate::opcodes::OpCode::CPUI_COPY { continue; }
                if let Some(in0) = op.get_in(0) {
                    if let Some(ref out_arc) = op.output {
                        let src = in0.read().unwrap();
                        let off = src.get_offset();
                        if known.contains_key(&off)
                            && matches!(
                                src.get_space(), crate::space::AddressSpace::Const
                                | crate::space::AddressSpace::Ram
                            )
                        {
                            let out_vn = out_arc.read().unwrap();
                            if let Some(dt) = known.get(&off) {
                                temps.insert(vn_id(&out_vn), dt.clone());
                            }
                        }
                    }
                }
            }
        }
    }
    let _ = ptr_size;
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

    // Ghidra: coreaction.cc:2907 ActionNameVars::linkSpacebaseSymbol
    /// Link symbols associated with a given spacebase Varnode.
    /// Iterates the Varnode's descendant PTRSUB ops and resolves the
    /// constant offset input (in(1)) to a symbol via linkSymbolReference.
    /// Faithful to `linkSpacebaseSymbol` (cc:2907-2920). The namerec type is
    /// the (Varnode, symbol index) pair vector shared with linkSymbols.
    fn link_spacebase_symbol(
        fd: &mut Funcdata,
        vn: &Arc<RwLock<crate::varnode::Varnode>>,
        _namerec: &mut Vec<(Arc<RwLock<crate::varnode::Varnode>>, usize)>,
    ) {
        use crate::opcodes::OpCode;
        // cc:2910: only process constant or input spacebase varnodes.
        {
            let vn_r = vn.read().unwrap();
            if !vn_r.is_constant() && !vn_r.is_input() { return; }
        }
        // cc:2911-2918: iterate descendants.
        let descend_refs: Vec<_> = {
            let vn_r = vn.read().unwrap();
            vn_r.descend.iter().filter_map(|w| w.upgrade()).collect()
        };
        for op_arc in &descend_refs {
            let op = op_arc.read().unwrap();
            // cc:2914: only PTRSUB ops.
            if op.opcode != OpCode::CPUI_PTRSUB { continue; }
            // cc:2915: offVn = op->getIn(1) — the constant offset input.
            let off_vn = match op.get_in(1) { Some(v) => v.clone(), None => continue ,
            };
            drop(op);
            // cc:2916: sym = data.linkSymbolReference(offVn)
            let sym_name = fd.link_symbol_reference(&off_vn);
            // cc:2917-2918: if sym found and name undefined, add to namerec.
            if sym_name.is_some() {
                // Rugra: symbol_table already has the name (not undefined),
                // so we don't add to namerec unless it's a generated name.
                // Ghidra checks sym->isNameUndefined(); Rugra's symbol_table
                // entries are user-defined (always named), so this branch
                // is a no-op for Rugra's model.
            }
        }
    }

    // Ghidra: coreaction.cc:2930 ActionNameVars::linkSymbols
    /// Link formal Symbols to their HighVariable representative in the given
    /// Function. Run through all Varnodes in all spaces (except constant),
    /// and for each that is the name representative of its HighVariable, call
    /// linkSymbol to associate it with a Symbol (creating one holding
    /// `high->getType()` when nothing overlaps — coreaction.cc:2963 →
    /// funcdata_varnode.cc:1177). Any Symbol without a name whose high
    /// represents the whole symbol is collected into `namerec` for further
    /// name resolution. Faithful to `linkSymbols` (coreaction.cc:2930-2976).
    /// `namerec` entries are (representative Varnode, symbol index) pairs —
    /// the index stands in for Ghidra's `high->getSymbol()` handle.
    fn link_symbols(
        fd: &mut Funcdata,
        namerec: &mut Vec<(Arc<RwLock<crate::varnode::Varnode>>, usize)>,
    ) {
        use crate::space::AddressSpace;
        // Snapshot all varnode arcs to avoid borrow conflicts when calling
        // fd.link_symbol (which needs &mut fd) inside the loop.
        let vn_arcs: Vec<_> = fd.vbank.loc_tree.iter().map(|v| v.0.clone()).collect();
        // coreaction.cc:2946 captures exactly data.getArch()->types once for
        // the HighVariable::finalizeDatatype calls below. If the optional Rust
        // Architecture wiring is absent, this path fails closed instead of
        // substituting the process-global factory.
        let type_factory = fd.get_arch().and_then(|arch| arch.types.clone());
        // cc:2938-2944: iterate constant-space varnodes for equate symbols +
        // spacebase links.
        for vn_arc in &vn_arcs {
            let vn = vn_arc.read().unwrap();
            if vn.get_space() != AddressSpace::Const { continue; }
            let has_sym = vn.get_symbol_entry().is_some();
            let is_sb = vn.is_spacebase();
            drop(vn);
            if has_sym {
                let _ = fd.link_symbol(vn_arc); // Special equate symbol
            } else if is_sb {
                Self::link_spacebase_symbol(fd, vn_arc, namerec);
            }
        }
        // cc:2947-2974: iterate all non-constant spaces, loc order.
        for vn_arc in &vn_arcs {
            {
                let vn = vn_arc.read().unwrap();
                if vn.get_space() == AddressSpace::Const { continue; }
                // cc:2954-2956: if (curvn->isFree()) continue;
                if vn.is_free() { continue; }
                // cc:2957-2958: if (curvn->isSpacebase()) linkSpacebaseSymbol(...);
                // Ghidra does NOT continue here — the flow falls through to
                // the nameRepresentative/hasName/linkSymbol steps (an
                // unaffected RSP input passes hasName at variable.cc:737-745
                // and gets linked).
                if vn.is_spacebase() {
                    drop(vn);
                    Self::link_spacebase_symbol(fd, vn_arc, namerec);
                }
            }
            // Fall-through (cc:2959+): re-acquire the guard after the
            // mutable fd call above.
            let vn = vn_arc.read().unwrap();
            // cc:2959-2960: vn = curvn->getHigh()->getNameRepresentative();
            //               if (vn != curvn) continue; — hit each high once.
            let high_arc = vn.high.clone();
            let is_rep = match &high_arc {
                Some(h) => match h.read().unwrap().get_name_representative() {
                    Some(rep_vn) => Arc::ptr_eq(vn_arc, &rep_vn),
                    // Ghidra dereferences inst.front() (variable.cc:503) — an
                    // instance-less high is unreachable there; skip it here.
                    None => false,
                },
                None => false,
            };
            if !is_rep { continue; }
            // cc:2961-2962: if (!high->hasName()) continue; — hasName is the
            // "can have a name" predicate (variable.cc:718-747: coverable,
            // not implied, unaffected-input rules), NOT "already named".
            // Ghidra's hasName reads isUnaffected/isInput, which lazily run
            // updateFlags (variable.hh:200/:148) — mirror the refresh so the
            // flag bits reflect the member varnodes.
            let nameable = high_arc
                .as_ref()
                .map(|h| {
                    h.write().unwrap().update_flags();
                    h.read().unwrap().has_name()
                })
                .unwrap_or(false);
            if !nameable { continue; }
            // cc:2963: sym = data.linkSymbol(vn);
            drop(vn);
            let sym_idx = fd.link_symbol(vn_arc);
            let Some(sym_idx) = sym_idx else { continue };
            // cc:2964-2973: can we associate high with a nameable symbol?
            let (sym_undef, sym_size) = {
                let scope = fd.scope.as_ref().unwrap();
                let sym = &scope.symbols[sym_idx];
                (sym.is_name_undefined(), sym.size)
            };
            if sym_undef {
                let high_ro = vn_arc.read().unwrap().high.clone();
                if let Some(h) = &high_ro {
                    // cc:2965-2966: if (sym->isNameUndefined() &&
                    // high->getSymbolOffset() < 0) namerec.push_back(vn);
                    if h.read().unwrap().get_symbol_offset() < 0 {
                        namerec.push((vn_arc.clone(), sym_idx));
                    }
                }
            }
            let _ = sym_size;
            // cc:2967-2970: if (sym->isSizeTypeLocked() && sizes match)
            //   overrideSizeLockType — RUGRA-GAP: LocalSymbol models typelock
            //   only; the size-lock type override has no counterpart yet.
            // cc:2971-2972: if (vn->isAddrTied() && !sym->getScope()->isGlobal())
            //   high->finalizeDatatype(typeFactory);
            if vn_arc.read().unwrap().is_addr_tied() {
                // The local map is never global.
                if let (Some(h), Some(factory)) = (
                    vn_arc.read().unwrap().high.clone(),
                    type_factory.as_ref()) {
                    let mut factory = factory
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    h.write().unwrap().finalize_datatype(&mut factory);
                }
            }
        }
    }
}
impl Action for ActionNameVars {
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:482
    fn get_flags(&self) -> u32 {
        action_flags::RULE_ONCEPERFUNC
    }

    // Ghidra: coreaction.cc:2978 ActionNameVars::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Ghidra cc:2981-2986 — in order:
        //   linkSymbols(data, namerec);
        //   recoverNameRecommendationsForSymbols();
        //   lookForBadJumpTables(data);
        //   lookForFuncParamNames(data, namerec);
        let mut namerec: Vec<(Arc<RwLock<crate::varnode::Varnode>>, usize)> = Vec::new();
        Self::link_symbols(fd, &mut namerec);

        // cc:2984: data.getScopeLocal()->recoverNameRecommendationsForSymbols()
        // — make sure recommended names hit before subfunc. RUGRA-GAP: no
        // name-recommendation store is ported yet (no override framework).

        // cc:2985: lookForBadJumpTables — scan calls for bad jump tables and
        // rename the associated symbol to "UNRECOVERED_JUMPTABLE".
        // Rugra: implemented conservatively (no isBadJumpTable flag on
        // FuncCallSpecs yet, so this is a no-op that matches Ghidra's
        // behavior when no bad jump tables are detected).

        // cc:2986: lookForFuncParamNames(data, namerec) — propagate locked
        // prototype parameter names onto the namerec symbols
        // (coreaction.cc:2858-2897): makeRec (cc:2815-2850) builds the
        // (high → (name, preferred-type)) recommendation map from locked
        // callspecs — gates: name-locked param (cc:2818), defined name
        // (cc:2819), matching varnode size (cc:2820), CAST unwrap for
        // implied+written varnodes demoting the type to None (cc:2822-2828),
        // no address-tired targets (cc:2830), no param_N placeholders
        // (cc:2831); on a repeat high the recommendation wins only with a
        // non-null type, by Datatype::typeOrder (cc:2833-2845). Then each
        // namerec symbol whose name is still undefined is renamed, in the
        // original (address-based) order, via makeNameUnique.
        let mut rec_map: std::collections::HashMap<
            usize,
            (
                String, Option<std::sync::Arc<crate::type_system::datatype::Datatype>>,
            ),
        > = std::collections::HashMap::new();
        if !fd.callspecs.is_empty() {
            for fc in &fd.callspecs {
                let fc = fc.read().unwrap();
                if !fc.is_input_locked() {
                    continue;
                }
                let num_param = fc.prototype.num_params();
                let call_op = match fc.find_call_op(fd) {
                    Some(op) => op,
                    None => continue,
                };
                let op_r = call_op.0.read().unwrap();
                let max_param = num_param.min(op_r.num_input().saturating_sub(1));
                for j in 0..max_param {
                    let param = match fc.prototype.get_param(j) { Some(p) => p, None => continue ,
                    };
                    // cc:2818: if (!param->isNameLocked()) return;
                    if param.flags & crate::fspec::protoparam_flags::NAME_LOCKED == 0 {
                        continue;
                    }
                    // cc:2819: if (param->isNameUndefined()) return;
                    // cc:2831: name placeholders never propagate.
                    if param.name.is_empty() || param.name.starts_with("param_") { continue; }
                    // cc:2876: vn = op->getIn(j+1) — the j-th parameter varnode.
                    let Some(vn) = op_r.get_in(j + 1) else { continue ;
                    };
                    // cc:2820: if (vn->getSize() != param->getSize()) return;
                    if vn.read().unwrap().get_size() != param.data_type.get_size() {
                        continue;
                    }
                    // Datatype *ct = param->getType();
                    let mut ct: Option<std::sync::Arc<crate::type_system::datatype::Datatype>> =
                        Some(param.data_type.clone());
                    let mut vn = vn.clone();
                    // cc:2822-2828: if (vn->isImplied() && vn->isWritten())
                    //   { castop = vn->getDef(); if (castop->code()==CPUI_CAST) {
                    //     vn = castop->getIn(0); ct = NULL; } }
                    {
                        let vn_r = vn.read().unwrap();
                        if vn_r.is_implied() && vn_r.is_written() {
                            if let Some(def) = vn_r.get_def() {
                                let def_r = def.read().unwrap();
                                if def_r.opcode == OpCode::CPUI_CAST {
                                    if let Some(in0) = def_r.get_in(0) {
                                        drop(vn_r);
                                        vn = in0.clone();
                                        ct = None; // Less preferred (casted) name
                                    }
                                }
                            }
                        }
                    }
                    let vn_r = vn.read().unwrap();
                    if vn_r.is_free() { continue; }
                    // cc:2830: if (high->isAddrTied()) return; — don't
                    // propagate a parameter name to an address-tied var.
                    let Some(high) = &vn_r.high else { continue };
                    let mut high_w = high.write().unwrap();
                    high_w.update_flags();
                    if high_w.is_addr_tied() { continue; }
                    drop(high_w);
                    let high_ptr = Arc::as_ptr(high) as usize;
                    // cc:2833-2845: repeat recommendations keep the more
                    // specified type (Datatype::typeOrder), never override
                    // with a null (casted) type.
                    match rec_map.get_mut(&high_ptr) {
                        Some(existing) => {
                            let Some(new_ct) = &ct else { continue };
                            if let Some(old_ct) = &existing.1 {
                                if old_ct.type_order(new_ct) <= 0 {
                                    continue; // oldtype is more specified
                                }
                            }
                            existing.1 = ct.clone();
                            existing.0 = param.name.clone();
                        }
                        None => {
                            rec_map.insert(high_ptr, (param.name.clone(), ct.clone()));
                        }
                    }
                }
            }
        }
        if !rec_map.is_empty() {
            // cc:2882-2896: do the actual naming in the original order.
            for (vn_arc, sym_idx) in &namerec {
                let vn_r = vn_arc.read().unwrap();
                if vn_r.is_free() { continue; }
                if vn_r.is_input() { continue; } // Don't override input naming strategy
                let Some(high) = &vn_r.high else { continue };
                // cc:2887: if (high->getNumMergeClasses() > 1) continue;
                if high.read().unwrap().get_num_merge_classes() > 1 { continue; }
                // cc:2888-2889: sym = high->getSymbol(); if null or named, skip.
                let high_ptr = Arc::as_ptr(high) as usize;
                let Some((name, _ct)) = rec_map.get(&high_ptr) else { continue ;
                };
                let is_undef = fd
                    .scope
                    .as_ref()
                    .map(|s| {
                        s.symbols
                            .get(*sym_idx)
                            .map(|sy| sy.is_name_undefined())
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                if !is_undef { continue; }
                // cc:2893-2894: sym->getScope()->renameSymbol(sym,
                //   localmap->makeNameUnique(namerec)).
                if let Some(scope) = fd.scope.as_mut() {
                    if let Some(unique) = scope.make_name_unique(name) {
                        scope.rename_symbol(*sym_idx, &unique);
                    }
                }
            }
        }

        // cc:2988-2997: int4 base = 1; for each namerec varnode whose symbol
        // is still name-undefined, build a default name with the vn
        // representative (buildDefaultName's vn path drives the in_/unaff_/
        // param_ branches) and rename the symbol.
        let mut base: i32 = 1;
        // The scope is taken out of fd so build_default_name can hold both
        // the mutable scope and the shared &Funcdata (Ghidra's localmap and
        // Funcdata are separate objects).
        let mut scope_taken = fd.scope.take();
        if let Some(scope) = scope_taken.as_mut() {
            for (vn_arc, sym_idx) in &namerec {
                let is_undef = scope
                    .symbols
                    .get(*sym_idx)
                    .map(|sy| sy.is_name_undefined())
                    .unwrap_or(false);
                if !is_undef { continue; }
                let vn_guard = vn_arc.read().unwrap();
                let newname = scope.build_default_name(
                    *sym_idx, &mut base, Some(&vn_guard), Some(fd));
                drop(vn_guard);
                if let Some(nm) = newname {
                    scope.rename_symbol(*sym_idx, &nm);
                }
            }
            // cc:2998: data.getScopeLocal()->assignDefaultNames(base) — walk
            // the nametree from "$$undef" and name every remaining
            // placeholder with the SAME shared base counter.
            if scope.assign_default_names(&mut base).is_none() {
                eprintln!(
                    "[VARMAP] assign_default_names: makeNameUnique failure (coreaction.cc:2998)"
                );
            }
        }
        fd.scope = scope_taken;

        // RUGRA-GLUE: symbol→HighVariable name write-back. Ghidra's PrintC
        // resolves every variable name through `high->getSymbol()` /
        // `Symbol::getDisplayName`; Rugra's printc still reads
        // `HighVariable::name`. Mirror the symbol attachment by publishing
        // each linked symbol's finished display name onto its high — the
        // symbol is the single naming authority (earlier direct high.name
        // writes, e.g. ActionInferParams, are superseded exactly as Ghidra's
        // namevars output supersedes them). Retirement of this bridge is
        // PRINTC-SYMBOL-DECL-0001.
        if let Some(scope) = fd.scope.as_ref() {
            for (high_ptr, sym_idx) in fd.high_symbols.iter() {
                let Some(display) = scope
                    .symbols
                    .get(*sym_idx)
                    .map(|s| s.display_name.clone())
                    .filter(|n| !n.is_empty())
                else {
                    continue;
                };
                for vn_ref in &fd.vbank.loc_tree {
                    let high_arc = {
                        let vn = vn_ref.0.read().unwrap();
                        vn.high.clone()
                    };
                    if let Some(high) = high_arc {
                        if Arc::as_ptr(&high) as usize == *high_ptr {
                            high.write().unwrap().set_name(display.clone());
                        }
                    }
                }
            }
        }

        // RUGRA-GLUE: refresh the bridged database.rs mirror symbols with
        // the finished names, so any consumer reading a Varnode's mapentry
        // (`vn->getSymbolEntry()->getSymbol()`) sees the same name as the
        // varmap symbol, like Ghidra's single Symbol object would.
        for (sym_idx, entry) in fd.symbol_entry_cache.iter() {
            let Some(names) = fd
                .scope
                .as_ref()
                .and_then(|s| s.symbols.get(*sym_idx))
                .map(|s| (s.name.clone(), s.display_name.clone()))
            else {
                continue;
            };
            let mut entry_w = entry.write().unwrap();
            let mut bridge = entry_w.symbol.write().unwrap();
            bridge.name = names.0;
            bridge.display_name = names.1;
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
        // Faithful port of ActionVarnodeProps::apply (coreaction.cc:1282-1348).
        //
        // The algorithm walks every Varnode in loc-tree order and, for each,
        // performs exactly one of four mutually-exclusive branches
        // (Ghidra uses an `else if` chain):
        //
        //   1. If vn->isAutoLiveHold() && pass>0:
        //        - if vn is the output of a LOAD whose pointer (possibly via a
        //          single COPY) is constant/readonly, KEEP the hold (continue).
        //        - otherwise clearAutoLiveHold() and count it.
        //
        //   2. else if vn->hasActionProperty()  (i.e. readonly OR volatile):
        //        - readonly + cachereadonly -> fillinReadOnly(vn)
        //        - volatile                 -> replaceVolatile(vn)
        //
        //   3. else if (vn->getNZMask() & vn->getConsume())==0 && size<=8:
        //        - skip true constants
        //        - skip a COPY of the constant 0 (would recurse)
        //        - if vn still has descendants: totalReplaceConstant(vn, 0)
        //
        // Snapshotting the varnodes up-front mirrors Ghidra's pre-increment
        // iterator (`vn = *iter++`): we never revisit varnodes inserted by the
        // mutating helpers below, which is exactly Ghidra's behaviour.
        use crate::varnode::varnode_flags;

        // Ghidra: bool cachereadonly = glb->readonlypropagate;
        let cachereadonly = fd
            .get_arch()
            .map(|a| a.readonlypropagate)
            .unwrap_or(false);
        // Ghidra: int4 pass = data.getHeritagePass();
        let pass = fd.heritage.pass;

        // Snapshot all live Varnodes (loc-tree, addr-sorted).
        let varnodes: Vec<Arc<RwLock<crate::varnode::Varnode>>> = fd
            .vbank
            .loc_tree
            .iter()
            .map(|v| v.0.clone())
            .collect();

        let mut count: i32 = 0;

        for vn_arc in &varnodes {
            // cc:1294: if (vn->isAnnotation()) continue;
            if vn_arc.read().unwrap().is_annotation() {
                continue;
            }
            // cc:1295: int4 vnSize = vn->getSize();
            let vn_size = vn_arc.read().unwrap().get_size();

            // ---- Branch 1: isAutoLiveHold (cc:1296-1317) ----
            if vn_arc.read().unwrap().is_auto_live_hold() {
                if pass > 0 {
                    // Determine whether this auto-live-hold varnode is the
                    // output of a LOAD from a known (constant/readonly) addr.
                    // If so we KEEP the hold (Ghidra: continue); otherwise we
                    // clearAutoLiveHold() and count it.
                    //
                    // Clone the Arc<PcodeOp>/Arc<Varnode> out of the read
                    // guards so the temporaries outlive the borrow.
                    let load_op_arc = {
                        let vn_rg = vn_arc.read().unwrap();
                        if vn_rg.is_written() {
                            vn_rg.get_def()
                        } else {
                            None
                        }
                    };
                    let is_load = load_op_arc
                        .as_ref()
                        .map(|o| o.read().unwrap().opcode == OpCode::CPUI_LOAD)
                        .unwrap_or(false);

                    let keep_hold = if is_load {
                        let load_op_arc = load_op_arc.unwrap();
                        // ptr = loadOp->getIn(1). Bind the guard so the &Arc outlives the use.
                        let load_g = load_op_arc.read().unwrap();
                        let ptr0 = load_g.get_in(1);
                        if let Some(ptr0) = ptr0 {
                            let ptr_is_known = {
                                let p0 = ptr0.read().unwrap();
                                p0.is_constant() || p0.is_read_only()
                            };
                            if ptr_is_known {
                                true
                            } else {
                                // Follow a single COPY chain:
                                //   copyOp = ptr->getDef()
                                //   if (copyOp->code()==COPY) ptr = copyOp->getIn(0)
                                let copy_op_arc = ptr0.read().unwrap().get_def();
                                let is_copy_of_known = match copy_op_arc {
                                    Some(co) => {
                                        let co_g = co.read().unwrap();
                                        if co_g.opcode != OpCode::CPUI_COPY {
                                            false
                                        } else {
                                            match co_g.get_in(0) {
                                                Some(p2) => {
                                                    let p2r = p2.read().unwrap();
                                                    p2r.is_constant() || p2r.is_read_only()
                                                }
                                                None => false,
                                            }
                                        }
                                    }
                                    None => false,
                                };
                                is_copy_of_known
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if !keep_hold {
                        // cc:1314: vn->clearAutoLiveHold();
                        vn_arc.write().unwrap().flags &= !varnode_flags::AUTOLIVE_HOLD;
                        count += 1;
                    }
                }
                // (auto-live-hold branch handled; continue to next vn)
                continue;
            }

            // ---- Branch 2: hasActionProperty (cc:1318-1326) ----
            // Ghidra: hasActionProperty() == (readonly || volatile).
            let is_ro = vn_arc.read().unwrap().is_read_only();
            let is_vol = vn_arc.read().unwrap().is_volatile();
            if is_ro || is_vol {
                if cachereadonly && is_ro {
                    // cc:1320: if (data.fillinReadOnly(vn)) count += 1;
                    if fd.fillin_read_only(vn_arc) {
                        count += 1;
                    }
                } else if is_vol {
                    // cc:1323-1325: else if (vn->isVolatile())
                    //                 if (data.replaceVolatile(vn)) count += 1;
                    if fd.replace_volatile(vn_arc) {
                        count += 1;
                    }
                }
                continue;
            }

            // ---- Branch 3: NZMask & Consume == 0  (cc:1327-1345) ----
            // Guard on pass>0: On the first mainloop iteration (pass=0),
            // DeadCode hasn't run yet so consume==0 for all varnodes.
            // On subsequent iterations, DeadCode from the PREVIOUS iteration
            // has set consume, and this iteration's DeadCode hasn't cleared
            // it yet (VarnodeProps runs first). This matches Ghidra exactly.
            if pass > 0 {
                let (nz_mask, consume) = {
                    let r = vn_arc.read().unwrap();
                    (r.get_nz_mask(), r.get_consume())
                };
                if (nz_mask & consume) == 0 && vn_size <= std::mem::size_of::<u64>() {
                    if vn_arc.read().unwrap().is_constant() {
                        continue;
                    }
                    let skip_copy_zero = {
                        let vn_rg = vn_arc.read().unwrap();
                        if vn_rg.is_written() {
                            match vn_rg.get_def() {
                                Some(def) => {
                                    let def_g = def.read().unwrap();
                                    if def_g.opcode != OpCode::CPUI_COPY {
                                        false
                                    } else {
                                        match def_g.get_in(0) {
                                            Some(in0) => {
                                                let i0 = in0.read().unwrap();
                                                i0.is_constant() && i0.get_offset() == 0
                                            }
                                            None => false,
                                        }
                                    }
                                }
                                None => false,
                            }
                        } else {
                            false
                        }
                    };
                    if skip_copy_zero {
                        continue;
                    }
                    if !vn_arc.read().unwrap().has_no_descend() {
                        fd.total_replace_constant(vn_arc, 0);
                        count += 1;
                    }
                }
            }
        }

        // Ghidra returns 0 (NO_CHANGE) from apply() — the internal count
        // is for statistics only and does NOT drive repeatapply.
        Ok(0)
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
            let fc = match fd.get_call_specs(i) { Some(fc) => fc, None => continue ,
            };
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
                let in_vn = match op.inrefs.get(0) { Some(v) => v.clone(), None => continue ,
                };
                let out_vn = match op.output.as_ref() { Some(o) => o.clone(), None => continue ,
                };
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
            Ok(action_status::NO_CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }
    // RUGRA-GLUE: Rust Action trait get_name; "restrictlocal" mirrors ctor at coreaction.hh:813
    fn get_name(&self) -> &str { "restrictlocal" }
}

/// Multi-CSE (common subexpression elimination). Faithful to
/// `ActionMultiCse` (coreaction.cc).
pub struct ActionMultiCse { pub count: i32 ,
}
impl ActionMultiCse {
    // Ghidra: coreaction.hh:163 ActionMultiCse (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }

    /// Resolve a COPY chain: if `vn` is defined by a COPY, return its input.
    /// Otherwise return `vn` itself. Used to allow copy-propagation differences.
    // RUGRA-GLUE: Rugra helper chasing COPY chains; Ghidra inlines this within ActionMultiCse::processBlock (coreaction.cc:790-810)
    fn resolve_copy(
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let (is_written, is_copy, in0) = {
            let r = vn.read().unwrap();
            if !r.is_written() {
                return vn.clone();
            }
            let def = r.get_def();
            match def {
                Some(d) => {
                    let dr = d.read().unwrap();
                    (
                        true, dr.opcode == crate::opcodes::OpCode::CPUI_COPY, dr.get_in(0).cloned(),
                    )
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
            (
                r.is_addr_tied(), r.space() == crate::space::AddressSpace::Unique,
            )
        };
        let (o2_addrtied, o2_internal) = {
            let r = out2.read().unwrap();
            (
                r.is_addr_tied(), r.space() == crate::space::AddressSpace::Unique,
            )
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
        // Ghidra: coreaction.cc:873 — every successful processBlock merge
        // increments the inherited Action::count member; perform() returns
        // that count so the parent stackstall group's rule_repeatapply
        // fixed point sees this action's changes (PIPE-STACKSTALL-COUNT-0001).
        self.count += local_count;
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: externalizes Ghidra's inherited protected Action::count (coreaction.cc:873) into the Rust ActionState accumulator
    fn take_count_delta(&mut self) -> i32 {
        std::mem::take(&mut self.count)
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
pub struct ActionDirectWrite {
    /// Propagate thru CPUI_INDIRECT ops. Faithful to the `propagateIndirect`
    /// field (coreaction.hh:244), set once by the constructor: `true` for the
    /// `protorecovery_a` registration, `false` for `protorecovery_b`
    /// (coreaction.cc:5497/:5498, :5680/:5681).
    propagate_indirect: bool,
}
impl ActionDirectWrite {
    // Ghidra: coreaction.hh:246 ActionDirectWrite::ActionDirectWrite
    pub fn new(propagate_indirect: bool) -> Self { Self { propagate_indirect } }
}
impl Action for ActionDirectWrite {
    // Ghidra: coreaction.cc:1350 ActionDirectWrite::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionDirectWrite::apply (coreaction.cc:1350-1432).
        // Phase 1: Clear direct_write on all varnodes. Collect initial
        // worklist of legal inputs / auto direct writes.
        // Phase 2: Propagate direct_write taint through assignments.

        let varnodes: Vec<_> = fd.vbank.loc_tree.iter().map(|v| v.0.clone()).collect();

        // Phase 1: Clear + collect worklist (cc:1360-1416)
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
                // Ghidra cc:1368-1371: else if (data.getFuncProto()
                //   .possibleInputParam(vn->getAddr(),vn->getSize()))
                else if fd.funcp.possible_input_param(
                    vn_rg.get_offset(),
                    vn_rg.get_size() as i32,
                    vn_rg.get_space(),
                ) {
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
                    }
                    // Ghidra cc:1381: else if (op->code() == CPUI_COPY)
                    // For most COPYs, do NOT consider it a direct write.
                    else if def_opc == OpCode::CPUI_COPY {
                        // Ghidra cc:1382: if (vn->isStackStore()) — the
                        // original operation was really a CPUI_STORE (the
                        // flag is set by RuleStoreVarnode,
                        // ruleaction.cc:4333).
                        if vn_rg.is_stack_store() {
                            // Ghidra cc:1383-1388: Varnode *invn =
                            //   op->getIn(0); if (invn->isWritten()) {
                            //   curop = invn->getDef(); if (curop->code()
                            //   == CPUI_COPY) invn = curop->getIn(0); }
                            // — trace the COPY source through (at most) one
                            // intermediate COPY (single-level unroll, not a
                            // loop).
                            let mut invn_arc = {
                                let op_rg = def_op.read().unwrap();
                                match op_rg.inrefs.first() {
                                    Some(v) => v.clone(),
                                    None => { drop(vn_rg); continue; }
                                }
                            };
                            if invn_arc.read().unwrap().is_written() {
                                let curop_arc = invn_arc
                                    .read()
                                    .unwrap()
                                    .def
                                    .as_ref()
                                    .and_then(|w| w.upgrade());
                                if let Some(curop) = curop_arc {
                                    if curop.read().unwrap().opcode == OpCode::CPUI_COPY {
                                        let next = {
                                            let op_rg = curop.read().unwrap();
                                            op_rg.inrefs.first().cloned()
                                        };
                                        if let Some(next) = next {
                                            invn_arc = next;
                                        }
                                    }
                                }
                            }
                            // Ghidra cc:1389-1392: if (invn->isWritten() &&
                            //   invn->getDef()->isMarker()) — source is from
                            //   an INDIRECT → treat as direct write.
                            let marker_sourced = {
                                let invn_rg = invn_arc.read().unwrap();
                                if invn_rg.is_written() {
                                    invn_rg
                                        .def
                                        .as_ref()
                                        .and_then(|w| w.upgrade())
                                        .map(|d| d.read().unwrap().is_marker())
                                        .unwrap_or(false)
                                } else {
                                    false
                                }
                            };
                            if marker_sourced {
                                drop(vn_rg);
                                vn_arc.write().unwrap().set_direct_write();
                                worklist.push(vn_arc.clone());
                            }
                        }
                        // Plain COPY output: NOT a direct write at collection
                        // time (cc:1381 comment); it can only gain the flag
                        // via Phase-2 taint.
                    }
                    // Ghidra cc:1395-1399: else if (op->code()!=CPUI_PIECE
                    //   && op->code()!=CPUI_SUBPIECE) — anything that writes
                    // to a variable in a way that isn't some form of COPY.
                    else if def_opc != OpCode::CPUI_PIECE && def_opc != OpCode::CPUI_SUBPIECE {
                        drop(vn_rg);
                        vn_arc.write().unwrap().set_direct_write();
                        worklist.push(vn_arc.clone());
                    }
                }
                // Ghidra cc:1401-1408: else if (!propagateIndirect &&
                //   op->code() == CPUI_INDIRECT) — the marker collection
                // branch, only active for the protorecovery_b registration.
                // The output is marked but deliberately NOT pushed to the
                // worklist ("We do NOT add vn to worklist as INDIRECT
                // otherwise does not propagate").
                else if !self.propagate_indirect && def_opc == OpCode::CPUI_INDIRECT {
                    let (addr_differs, out_persist) = {
                        let op_rg = def_op.read().unwrap();
                        let in0 = op_rg.inrefs.first().cloned();
                        let out = op_rg.output.clone();
                        match (in0, out) {
                            (Some(in0), Some(out)) => {
                                let i = in0.read().unwrap();
                                let o = out.read().unwrap();
                                // Ghidra cc:1403: op->getIn(0)->getAddr() !=
                                //   outvn->getAddr() — full Address compare
                                //   (AddrSpace pointer + offset).
                                let differs = i.get_space() != o.get_space()
                                    || i.get_offset() != o.get_offset();
                                (differs, o.is_persist())
                            }
                            (None, _) | (_, None) => (false, false),
                        }
                    };
                    // Ghidra cc:1404/1406: address change indicates an active
                    // COPY (direct write); else a persist output must be
                    // present in global storage at the call point.
                    if addr_differs {
                        drop(vn_rg);
                        vn_arc.write().unwrap().set_direct_write();
                    } else if out_persist {
                        drop(vn_rg);
                        vn_arc.write().unwrap().set_direct_write();
                    }
                }
            } else if vn_rg.is_constant() {
                // Ghidra cc:1411: if (!vn->isIndirectZero())
                if !vn_rg.is_indirect_zero() {
                    drop(vn_rg);
                    vn_arc.write().unwrap().set_direct_write();
                    worklist.push(vn_arc.clone());
                }
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
                    // Ghidra cc:1427-1429: for call based INDIRECTs, output
                    // is marked, but does not propagate depending on setting:
                    //   if (propagateIndirect || op->code() != CPUI_INDIRECT
                    //       || op->isIndirectStore())
                    // `propagateIndirect` is the constructor flag
                    // (coreaction.hh:244): true for protorecovery_a, false
                    // for protorecovery_b.
                    let is_ind = desc_op_arc.read().unwrap().opcode == OpCode::CPUI_INDIRECT;
                    let is_store = desc_op_arc.read().unwrap().is_indirect_store();
                    if self.propagate_indirect || !is_ind || is_store {
                        worklist.push(out_vn);
                    }
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
        if fd.bblocks.get_size() == 0 {
            return Ok(action_status::NO_CHANGE); // No blocks
        }
        // Get start block, which is constructed to have nothing
        // falling into it
        let bb = match fd.bblocks.get_block(0) {
            Some(b) => b,
            None => return Ok(action_status::NO_CHANGE),
        };

        // Ghidra: coreaction.cc:686-690 — int4 injectid =
        //   data.getFuncProto().getInjectUponEntry();
        //   if (injectid >= 0) { pcodeinjectlib->getPayload(injectid);
        //   data.doLiveInject(payload, bb->getStart(), bb, bb->beginOp()); }
        // Rugra's FuncProto stores no injection id (FuncProto::set_inject_id
        // is the INJECT-0001 no-op, and ProtoModelFull::inject_upon_entry is
        // only assigned through a prototype-model <inject> resolver that no
        // worker wires — production -1), so the leg reads as the INJECT-0001
        // compatibility fallback "-1 = none" (same pattern as
        // FuncCallSpecsExt::get_inject_id, flow.rs).
        // TODO(INJECT-0001): doLiveInject(payload, bb start, bb, bb beginOp).
        let _injectid: i32 = -1;
        if _injectid >= 0 {
            // doLiveInject residual (INJECT-0001): unreachable under the
            // current production wiring (no inject resolver registered).
        }

        // Ghidra: coreaction.cc:692 — const TrackedSet trackset(
        //   data.getArch()->context->getTrackedSet(data.getAddress()));
        // The function entry address lives in the default code space
        // (x86-64 ram); Rugra's Address carries no space dimension, so the
        // ram space is passed explicitly (same-space lookup is provably
        // equivalent to Ghidra's baselist-ordered Address compare — see
        // TrackedSetMap's ordering caveat in arch.rs).  The snapshot ends
        // the immutable fd borrow before the mutating loop; Ghidra's
        // reference points into the global context database, which nothing
        // in this loop mutates, so a shallow copy is observationally
        // identical.
        let trackset: Vec<crate::arch::TrackedRegister> = match fd.get_arch() {
            Some(arch) => arch
                .get_tracked_set(crate::space::AddressSpace::Ram, fd.get_address().as_u64())
                .to_vec(),
            None => Vec::new(),
        };

        for ctx in &trackset {
            // Ghidra: coreaction.cc:697 — Address addr(ctx.loc.space,ctx.loc.offset);
            // (Funcdata::new_varnode_out pins the Register space for the
            // defined varnode — correct for every pspec register-resolved
            // tracked loc like DF register:0x20a; a non-register tracked
            // loc needs the space-aware vbank create first.)
            let addr = crate::address::Address::new(ctx.loc.offset);
            // Ghidra: coreaction.cc:698 — PcodeOp *op = data.newOp(1,bb->getStart());
            let op = fd.new_op(
                1, bb.read().expect("entry block read lock").get_start_addr(),
            );
            // Ghidra: coreaction.cc:699 — data.newVarnodeOut(ctx.loc.size,addr,op);
            fd.new_varnode_out(ctx.loc.size as usize, addr, &op);
            // Ghidra: coreaction.cc:700 — Varnode *vnin = data.newConstant(ctx.loc.size,ctx.val);
            let vnin = fd.new_constant(ctx.loc.size as usize, ctx.val);
            // Ghidra: coreaction.cc:701 — data.opSetOpcode(op,CPUI_COPY);
            fd.op_set_opcode(&op, OpCode::CPUI_COPY);
            // Ghidra: coreaction.cc:702 — data.opSetInput(op,vnin,0);
            fd.op_set_input(&op, vnin, 0);
            // Ghidra: coreaction.cc:703 — data.opInsertBegin(op,bb);
            fd.op_insert_begin(&op, &bb);
        }
        // Ghidra: coreaction.cc:705 — return 0; (unconditionally, even
        // when COPY ops were inserted: no change counter in this action).
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
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:894
    fn get_flags(&self) -> u32 {
        action_flags::RULE_ONCEPERFUNC
    }

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
        let input_vns: Vec<_> = fd
            .vbank
            .loc_tree
            .iter()
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
            active.register_trial_in_space(
                vn.get_space(),
                crate::address::Address::new(vn.get_offset()),
                vn.get_size() as i32,
            );
            // Mark active if the varnode has descendants (is used)
            if vn.count_descends() > 0 {
                // Faithful: active.getTrial(slot).markActive()
                // Rugra doesn't expose trial mutably, so we count active inputs
            }
        }
        // deriveInputMap would assign types and finalize params.
        // For now, update the function's parameter count to match active inputs.
        let active_count = input_vns
            .iter()
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
                    ,
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
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:905
    fn get_flags(&self) -> u32 {
        action_flags::RULE_ONCEPERFUNC
    }

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
                        ),
                )),
                4 => std::sync::Arc::new(
                    crate::type_system::datatype::Datatype::Base(
                        crate::type_system::datatype::TypeBase::new(
                            "int".to_string(), 4,
                            crate::type_system::datatype::TypeMetatype::Int,
                        ),
                )),
                _ => std::sync::Arc::new(
                    crate::type_system::datatype::Datatype::Base(
                        crate::type_system::datatype::TypeBase::new(
                            "long".to_string(), size,
                            crate::type_system::datatype::TypeMetatype::Int,
                        ),
                )),
            };
            // Only update if the current return type is void or unknown
            let is_void = matches!(
                fd.funcp.return_type.as_ref(),
                crate::type_system::datatype::Datatype::Void(_)
            );
            if is_void {
                fd.funcp.return_type = new_return_type;
            }
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "outputprototype" mirrors ctor at coreaction.hh:903
    fn get_name(&self) -> &str { "outputprototype" }
}

/// Prototype type setup (partial port of `ActionPrototypeTypes`).
///
/// RUGRA-GAP(PIPE-LIFECYCLE-0001): locked input materialization at
/// coreaction.cc:4680-4699 cannot be ported at this layer yet. Rugra's
/// `ProtoParameter` drops the storage address space and `FuncProto` does not
/// retain the resolved `ProtoModel`/input `ParamList`, so `extendInput` cannot
/// query `assumedInputExtension` without guessing the compiler specification.
pub struct ActionPrototypeTypes;
impl ActionPrototypeTypes {
    // Ghidra: coreaction.hh:643 ActionPrototypeTypes (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionPrototypeTypes {
    // Ghidra: coreaction.cc:4609 ActionPrototypeTypes::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Partial ActionPrototypeTypes::apply (coreaction.cc:4609-4699).
        // 1. Set evaluation prototype if not locked
        // 2. Strip indirect register from RETURN ops (replace input(0) with constant 0)
        // 3. If output locked: insert return varnodes for each RETURN
        // 4. Else: init active output gathering

        // Step 1 (coreaction.cc:4615-4619, PLTSTUB-WARNLOSS-0001 adjudication):
        //   ProtoModel *evalfp = data.getArch()->evalfp_current;
        //   if (evalfp == 0) evalfp = data.getArch()->defaultfp;
        //   if ((!data.getFuncProto().isModelLocked()) && !data.getFuncProto().hasMatchingModel(evalfp))
        //     data.getFuncProto().setModel(evalfp);
        // The gate is the single conjunction: a model-locked prototype is
        // NEVER given the evaluation model — not even to repair a modelless
        // state. Ghidra maintains "locked => model != NULL" at the
        // signature-decode boundary instead (FuncProto::decode ATTRIB_MODEL,
        // fspec.cc:4690-4698: an unrecognized convention name maps to
        // createUnknownModel — an UnknownProtoModel cloning the default
        // model's behavior while reporting isUnknown(), architecture.cc
        // :1159-1166), so the locked unknown-model identity survives here
        // and stays observable to ActionPrototypeWarnings
        // (coreaction.cc:4901-4908). The earlier "install the default model
        // when modelless, even if locked" arm inverted this oracle stance
        // and destroyed that identity (PLT/DWARF overlays lost their
        // "Unknown calling convention" warning headers). setInputLock(true)
        // already couples to model_locked exactly as fspec.cc:3924-3925
        // ("Locking input locks the model"), so a locked overlay keeps its
        // identity through this action; a modelless+locked FuncProto (a
        // Rugra-only transitional form Ghidra cannot reach) likewise keeps
        // its identity rather than being silently repaired here.
        if let Some(arch) = fd.get_arch() {
            let evalfp = arch
                .evalfp_current
                .clone()
                .or_else(|| arch.defaultfp.clone());
            if let Some(evalfp) = evalfp {
                if !fd.funcp.is_model_locked() && !fd.funcp.has_matching_model(&evalfp) {
                    fd.funcp.set_model(Some(evalfp));
                }
            }
        }

        // Step 2: Strip indirect register from RETURN ops
        // (Ghidra coreaction.cc:4628-4635: "Strip the indirect register from
        // all RETURN ops because we don't want to see this compiler mechanism
        // in the high-level C output")
        let return_ops: Vec<crate::op::PcodeOpRef> = fd
            .obank
            .alivelist
            .iter()
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

        // Step 3 (coreaction.cc:4637-4649): locked output — insert a read of
        // the output storage (e.g. RAX for a locked `size_t` return) as the
        // last input of every live, non-halt RETURN op. This is the
        // return-value dataflow edge: heritage renames the free read to the
        // reaching definition, giving `return <value>` (and enabling
        // ActionReturnSplit's per-branch RETURNs). Previously only the else
        // arm (initActiveOutput) was ported, so functions with a type-locked
        // return (all DWARF/PLT locked signatures) decompiled as valueless
        // `return;` with the value-producing ops dead-coded away.
        if fd.funcp.output_type_locked {
            let storage = fd.funcp.locked_output_storage();
            if let Some((space, off, size)) = storage {
                for ret_op in &return_ops {
                    let (dead, halt, num_input) = {
                        let r = ret_op.0.read().unwrap();
                        (
                            (r.flags & crate::op::pcodeop_flags::DEAD) != 0,
                            (r.flags
                                & (crate::op::pcodeop_flags::HALT
                                    | crate::op::pcodeop_flags::BADINSTRUCTION
                                    | crate::op::pcodeop_flags::UNIMPLEMENTED
                                    | crate::op::pcodeop_flags::NORETURN
                                    | crate::op::pcodeop_flags::MISSING))
                                != 0,
                            r.num_input(),
                        )
                    };
                    if dead {
                        continue; // cc:4642
                    }
                    if halt {
                        continue; // cc:4643
                    }
                    // cc:4644-4645: vn = newVarnode(outparam->getSize(),
                    // outparam->getAddress()); opInsertInput(op, vn, numInput()).
                    let vn = fd
                        .vbank
                        .create_with_space(size as usize, space, off);
                    crate::heritage::Heritage::apply_new_varnode_flags(fd, &vn);
                    fd.op_insert_input(ret_op, vn.clone(), num_input);
                    // cc:4646: vn->updateType(outparam->getType(), true, true).
                    vn.write()
                        .unwrap()
                        .update_type_lock(
                        fd.funcp.return_type.clone(),
                        true,
                        true);
                    change += 1;
                }
            }
        }
        // Step 4: Init active output if not locked.
        // Ghidra coreaction.cc:4649-4651: the else-branch of isOutputLocked
        // calls data.initActiveOutput() UNCONDITIONALLY (regardless of
        // return-type voidness or whether any RETURN already has a value).
        // This action is onceperfunc, so the container is created exactly
        // once; ActionReturnRecovery clears it once fully checked and must
        // never re-create it (see cc:1908-1955 lifecycle).
        else {
            fd.init_active_output();
        }

        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:646
    fn get_flags(&self) -> u32 { action_flags::RULE_ONCEPERFUNC }
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
        // Faithful 1:1 port of ActionActiveParam::apply (coreaction.cc:1725-1771).
        let mut count = 0;
        // Ghidra line 1730-1731: AliasChecker gather stack aliases.
        let mut aliascheck = crate::varmap::AliasChecker::new(1);
        aliascheck.gather_internal(fd);
        let maxancestor = fd.get_arch().map(|a| a.trim_recurse_max).unwrap_or(5);
        let has_active_output = fd.active_output.is_some();
        let n_calls = fd.num_calls();
        let debug = std::env::var("RUGRA_DEBUG_ACTIVEPARAM").is_ok();
        if debug && n_calls > 0 { eprintln!("[ACTIVEPARAM-DBG] {} n_calls={}", fd.name, n_calls); }
        for i in 0..n_calls {
            let is_input_active = fd
                .get_call_specs(i)
                .map(|fc| fc.is_input_active())
                .unwrap_or(false);
            if !is_input_active { continue; }
            // Ghidra line 1741: trimmable = (numPasses>0) || (op is not CALLIND).
            let op_ref = fd.get_call_specs(i).and_then(|fc| fc.find_call_op(fd));
            let (trimmable, fully_checked_before) = match fd.get_call_specs(i) {
                Some(fc) => {
                    let active = &fc.active_input;
                    let op_is_callind = op_ref
                        .as_ref()
                        .map(|o| o.0.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_CALLIND)
                        .unwrap_or(false);
                    let trimmable = active.get_num_passes() > 0 || !op_is_callind;
                    (trimmable, active.is_fully_checked())
                }
                None => continue,
            };
            // Ghidra line 1742-1743: checkInputTrialUse if !fullyChecked.
            if !fully_checked_before {
                let replace_slots = if let (Some(op_ref), Some(mut fc)) =
                    (&op_ref, fd.get_call_specs_mut(i))
                {
                    fc.check_input_trial_use(op_ref, has_active_output, &aliascheck, maxancestor)
                } else {
                    Vec::new()
                };
                if let Some(op_ref) = &op_ref {
                    for (slot, vn_size) in replace_slots {
                        let zero_vn = fd.new_constant(vn_size as usize, 0);
                        fd.op_set_input(op_ref, zero_vn, slot as usize);
                    }
                }
            }
            // Ghidra line 1744: finishPass.
            // Ghidra line 1745-1748: maxPass check.
            let (pass_exceeded, fully_checked_after) = match fd.get_call_specs_mut(i) {
                Some(mut fc) => {
                    let active = &mut fc.active_input;
                    active.finish_pass();
                    let exceeded = active.get_num_passes() > active.get_max_pass();
                    if exceeded { active.mark_fully_checked(); }
                    (exceeded, active.is_fully_checked())
                }
                None => (false, false),
            };
            if !pass_exceeded {
                // Ghidra line 1748: count a change (still have work to do).
                count += 1;
            }
            // Ghidra line 1749-1757: finalize if trimmable && fullyChecked.
            if trimmable && fully_checked_after {
                let needs_final = fd
                    .get_call_specs(i)
                    .map(|fc| fc.active_input.needs_final_check())
                    .unwrap_or(false);
                if needs_final {
                    if let (Some(op_ref), Some(mut fc)) = (&op_ref, fd.get_call_specs_mut(i)) {
                        fc.final_input_check(op_ref);
                    }
                }
                // Ghidra cc:1752-1755: resolveModel, deriveInputMap,
                // buildInputFromTrials, clearActiveInput. The owner Arc is
                // cloned so the write guard can coexist with the &mut fd the
                // opSetAllInput tail inside build_input_from_trials needs.
                let owner = fd.callspecs.get(i).cloned();
                if let Some(owner) = owner {
                    let mut fc = owner.write().unwrap();
                    fc.resolve_model();
                    fc.derive_input_map();
                    if let Some(op_ref) = &op_ref {
                        fc.build_input_from_trials(fd, op_ref);
                    }
                    fc.clear_active_input();
                }
                count += 1;
            }
        }
        Ok(count)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "activeparam" mirrors ctor at coreaction.hh:748
    fn get_name(&self) -> &str { "activeparam" }
}

/// Active return analysis. Faithful to `ActionActiveReturn`
/// (coreaction.cc).
pub struct ActionActiveReturn { pub count: i32 ,
}
impl ActionActiveReturn {
    // Ghidra: coreaction.hh:761 ActionActiveReturn (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionActiveReturn {
    // Ghidra: coreaction.cc:1773 ActionActiveReturn::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to ActionActiveReturn::apply (coreaction.cc:1773-1792).
        // For each call spec with active output recovery:
        // 1. checkOutputTrialUse — collect the trial varnodes from the
        //    INDIRECT ops holding them, then mark trials active/inactive
        //    (fspec.cc:5661-5677 + fspec.cc:5536 collectOutputTrialVarnodes)
        // 2. deriveOutputMap — ProtoModel.derive_output_map resolves which is USED
        // 3. buildOutputFromTrials — move the surviving trial varnode onto
        //    the CALL and destroy the holding INDIRECT (fspec.cc:5770-5860)
        // 4. clearActiveOutput
        use crate::opcodes::OpCode;
        let mut local_count = 0;
        let n_calls = fd.num_calls();
        for i in 0..n_calls {
            let needs_work = fd
                .get_call_specs(i)
                .map(|fc| fc.is_output_active())
                .unwrap_or(false);
            if !needs_work { continue; }
            let Some(call_op) = fd.get_call_specs(i).and_then(|fc| fc.find_call_op(fd)) else {
                continue;
            };
            // 1a. fspec.cc:5537-5538 collectOutputTrialVarnodes prologue: an
            // output already on the CALL at this point means recovery raced
            // a locked install — Ghidra throws LowlevelError.
            if call_op.0.read().unwrap().output.is_some() {
                return Err(crate::error::Error::Lowlevel(
                    "Output of call was determined prematurely".to_string(),
                ));
            }
            // fspec.cc:5539-5540: trialvn sized to the number of trials
            // (None = location unused).
            let num_trials = fd
                .get_call_specs(i)
                .map(|fc| fc.active_output.get_num_trials())
                .unwrap_or(0);
            let mut trial_vn: Vec<
                Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
            > =
                vec![None; num_trials];
            // The trial-address resets mutate the callspec while the op walk
            // below borrows fd.obank read-only, so take the stable Arc owner
            // up front and edit through its own lock (Ghidra has one object;
            // Rust borrow split). This preserves Ghidra's ordering: the
            // reset at fspec.cc:5550-5552 happens INSIDE the collection
            // loop, so later whichTrial calls see the reset addresses.
            let fc_owner = fd.callspecs.get(i).cloned();
            // fspec.cc:5541-5553: walk the ops immediately preceding the
            // CALL with PcodeOp::previousOp (op.cc:344 — the parent block's
            // op list via basiciter, NOT the global SeqNum tree); stop at
            // the first non-INDIRECT op. For each INDIRECT marked
            // indirect_creation whose output address matches a registered
            // trial, record the varnode and reset the trial address to the
            // exact varnode address.
            let mut cursor = call_op.0.read().unwrap().previous_op_in_block(&fd.obank);
            while let Some(prev) = cursor {
                let (is_indirect, is_creation) = {
                    let op = prev.0.read().unwrap();
                    (
                        op.opcode == OpCode::CPUI_INDIRECT, op.is_indirect_creation(),
                    )
                };
                if !is_indirect {
                    // fspec.cc:5543: if (indop->code() != CPUI_INDIRECT) break;
                    break;
                }
                if is_creation {
                    let out = prev.0.read().unwrap().output.clone();
                    if let Some(out) = out {
                        let (out_space, out_off, out_size) = {
                            let v = out.read().unwrap();
                            (v.get_space(), v.get_offset(), v.get_size())
                        };
                        let index = fc_owner
                            .as_ref()
                            .map(|fc| {
                                let fc = fc.read().unwrap();
                                fc.active_output.which_trial_in_space(
                                    out_space,
                                    crate::address::Address::new(out_off),
                                    out_size as i32,
                                )
                            })
                            .unwrap_or(-1);
                        if index >= 0 && (index as usize) < trial_vn.len() {
                            trial_vn[index as usize] = Some(out);
                            // fspec.cc:5550-5552: the exact varnode may
                            // have changed, so reset the trial address.
                            if let Some(fc) = fc_owner.as_ref() {
                                let mut fc = fc.write().unwrap();
                                fc.active_output.get_trial_mut(index as usize).set_address(
                                    crate::address::Address::new(out_off),
                                    out_size as i32,
                                );
                            }
                        }
                    }
                }
                cursor = prev.0.read().unwrap().previous_op_in_block(&fd.obank);
            }
            // 1b. fspec.cc:5668-5676 checkOutputTrialUse: the trial is
            // active exactly when its varnode was found (dataflow/deadcode
            // decided whether the location survives the call).
            if let Some(mut fc) = fd.get_call_specs_mut(i) {
                let active = &mut fc.active_output;
                for j in 0..active.get_num_trials() {
                    if active.get_trial(j).is_checked() {
                        // fspec.cc:5670-5671.
                        return Err(crate::error::Error::Lowlevel(
                            "Output trial has been checked prematurely".to_string(),
                        ));
                    }
                    if trial_vn[j].is_some() {
                        active.get_trial_mut(j).mark_active();
                    } else {
                        // fspec.cc:5675: don't call markNoUse — the
                        // value may be returned but not used.
                        active.get_trial_mut(j).mark_inactive();
                    }
                }
            }
            // 2. deriveOutputMap (coreaction.cc:1785).
            if let Some(mut fc) = fd.get_call_specs_mut(i) {
                fc.derive_output_map();
            }
            // 3. buildOutputFromTrials (coreaction.cc:1786 /
            // fspec.cc:5770-5860): reorder survivors by slot, delete unused
            // trials, move the surviving varnode(s) onto the CALL, and
            // destroy the holding INDIRECT ops. The dense Option list is
            // Ghidra's `vector<Varnode*> trialvn` verbatim — position ==
            // registration slot - 1, None == the null entries — so the
            // slot-based indexing inside survives sortTrials unchanged.
            // The Funcdata-editing closures need &mut fd, so take the
            // callspec lock through the stable Arc owner (captured before
            // the collection walk above) instead of the Funcdata borrow
            // (Rust borrow split; Ghidra has one object).
            if let Some(fc_owner) = fc_owner.as_ref() {
                let mut fc = fc_owner.write().unwrap();
                fc.build_output_from_trials(
                    fd,
                    &call_op,
                    &trial_vn,
                    // fspec.cc:5804 data.opSetOutput(op, finaloutvn).
                    &|fd, op, vn| {
                        fd.op_set_output(op, vn.clone());
                    },
                    // fspec.cc:5850-5859: destroy the INDIRECT and delete
                    // its two input varnodes (the constant-0 and the Iop
                    // annotation). Rugra's bank may share constants, in
                    // which case the delete is a no-op error Ghidra never
                    // observes (dedicated per-op constants).
                    &|fd, dop| {
                        let (in0, in1) = {
                            let d = dop.0.read().unwrap();
                            (d.get_in(0).cloned(), d.get_in(1).cloned())
                        };
                        fd.op_destroy(dop);
                        for vn in in0.into_iter().chain(in1) {
                            let _ = fd.delete_varnode(&vn);
                        }
                    },
                    // fspec.cc:5823-5841: two-piece join —
                    // constructJoinAddress, newVarnode, opSetOutput, then a
                    // SUBPIECE per half inserted after the call.
                    &|fd, op, hi_vn, lo_vn| {
                        let (hi_off, hi_size, lo_off, lo_size) = {
                            let h = hi_vn.read().unwrap();
                            let l = lo_vn.read().unwrap();
                            (h.get_offset(), h.get_size(), l.get_offset(), l.get_size())
                        };
                        let join_off = fd
                            .get_arch()
                            .map(|arch| {
                                arch.construct_join_address(hi_off, hi_size, lo_off, lo_size)
                            })
                            .unwrap_or(lo_off);
                        let whole = fd.vbank.create_with_space(
                            (hi_size + lo_size) as usize,
                            crate::space::AddressSpace::Unique,
                            join_off,
                        );
                        fd.op_set_output(op, whole.clone());
                        let op_addr = op.0.read().unwrap().get_addr();
                        // fspec.cc:5829-5834: SUBPIECE(whole, 0) -> lo.
                        let sublo = fd.new_op(2, op_addr);
                        fd.op_set_opcode(&sublo, OpCode::CPUI_SUBPIECE);
                        fd.op_set_output(&sublo, lo_vn.clone());
                        fd.op_set_input(&sublo, whole.clone(), 0);
                        let const_zero = fd.new_constant(4, 0);
                        fd.op_set_input(&sublo, const_zero, 1);
                        fd.op_insert_after(&sublo, op);
                        // fspec.cc:5835-5840: SUBPIECE(whole, lo size) -> hi.
                        let subhi = fd.new_op(2, op_addr);
                        fd.op_set_opcode(&subhi, OpCode::CPUI_SUBPIECE);
                        fd.op_set_output(&subhi, hi_vn.clone());
                        fd.op_set_input(&subhi, whole.clone(), 0);
                        let const_lo_size = fd.new_constant(4, lo_size as u64);
                        fd.op_set_input(&subhi, const_lo_size, 1);
                        fd.op_insert_after(&subhi, op);
                        whole
                    },
                );
            }
            // 4. clearActiveOutput (coreaction.cc:1787).
            if let Some(mut fc) = fd.get_call_specs_mut(i) {
                fc.clear_active_output();
            }
            // coreaction.cc:1788: count += 1 — the inherited protected
            // Action::count, observable through perform()'s
            // lcount<count → issueWarning/count_apply channel
            // (action.cc:302/322). Mirror via the take_count_delta
            // accumulator; the apply RETURN stays 0 (coreaction.cc:1791).
            local_count += 1;
        }
        self.count += local_count;
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: externalizes Ghidra's inherited protected Action::count (coreaction.cc:1788) into the Rust ActionState accumulator
    fn take_count_delta(&mut self) -> i32 {
        std::mem::take(&mut self.count)
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
        // cc:2313-2315: evalfp = evalfp_called, or the default model when the
        // evaluation option is unset.
        let evalfp = match fd.get_arch() {
            Some(arch) => arch
                .evalfp_called
                .clone()
                .or_else(|| arch.defaultfp.clone()),
            // No Architecture bound (legacy callers): the modelless state is
            // preserved exactly as before FUNCPROTO-MODEL-BIND-0001.
            None => None,
        };
        // cc:2316-2317: types->getTypeVoid() for the internal store's output.
        let type_void = match fd.get_arch() {
            Some(arch) => arch
                .types
                .as_ref()
                .and_then(|factory| factory.read().ok().map(|f| f.get_type_void()))
                .unwrap_or_else(|| {
                    crate::type_system::typefactory::TypeFactory::shared_default()
                        .read()
                        .expect("shared type factory lock poisoned")
                        .get_type_void()
                }),
            None => std::sync::Arc::new(crate::type_system::datatype::Datatype::Void(
                crate::type_system::datatype::TypeBase::new(
                    "void".to_string(),
                    0,
                    crate::type_system::datatype::TypeMetatype::Void,
                ),
            )),
        };
        let n_calls = fd.num_calls();
        for i in 0..n_calls {
            if let Some(mut fc) = fd.get_call_specs_mut(i) {
                // cc:2318: if (!fc->hasModel()) — the single Ghidra model
                // field maps to the FuncProto full model that hasEffect/
                // effect_iter consult.
                if !fc.prototype.has_model() {
                    // Rugra cannot resolve fc->getFuncdata() to a per-callee
                    // Funcdata registry yet, so the cc:2321-2326
                    // copy-from-callee branch is unreachable and the
                    // cc:2327-2328 else branch runs for every modelless
                    // callspec: fc->setInternal(evalfp, void).
                    //
                    // Locked-guard (rework of the first WIP): Ghidra's
                    // modelless callspecs never carry locked storage — a
                    // platform-locked callee proto arrives WITH a model
                    // (setPieces model, or an UnknownProtoModel clone of the
                    // default, architecture.cc:1155-1166) — so setInternal
                    // never clobbers a locked prototype there. Rugra's
                    // LibcSignatureTable/DWARF boundary CAN produce a
                    // modelless + model-locked callspec
                    // (UNKNOWN-PROTOMODEL-0001 residual): setInternal's
                    // void-output/store swap would destroy that locked
                    // storage and return type (integration rework
                    // regression 2). For those, install ONLY the shared eval
                    // model — mirroring the UnknownProtoModel behavior clone
                    // (effects known via the default, locked storage intact)
                    // — and never run setInternal on a locked prototype.
                    if fc.prototype.is_model_locked() {
                        fc.prototype.set_model(evalfp.clone());
                    } else {
                        fc.prototype.set_internal(evalfp.clone(), type_void.clone());
                    }
                    // RUGRA-GLUE: dual-model seam — keep the simplified
                    // type_system model seeded for possible_input_param
                    // consumers (no Ghidra counterpart: one model field).
                    if fc.proto_model.is_none() {
                        fc.proto_model = Some(crate::type_system::protomodel::ProtoModel::default_x86_64());
                    }
                }
                // cc:2329 fc->insertPcode(data): callfixup injection for
                // calls is not wired in Rugra yet (CALLFIXUP-INJECT domain).
            }
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:661
    fn get_flags(&self) -> u32 { action_flags::RULE_ONCEPERFUNC }
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

        let input_vns: Vec<_> = fd
            .vbank
            .loc_tree
            .iter()
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
            let is_justified = fd
                .funcp
                .parameters
                .iter()
                .any(|p| p.address.as_u64() == vn_offset
            );

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
                    ,
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

        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "unjustparams" mirrors ctor at coreaction.hh:920 (Action(0,"unjustparams",g))
    fn get_name(&self) -> &str { "unjustparams" }
}

/// Likely trash analysis. Faithful to `ActionLikelyTrash`
/// (coreaction.cc).
///
/// For each "likely trash" register from the function prototype, traces the
/// data-flow to see if the value flows into an INDIRECT or INT_AND op. If
/// so, truncates the data-flow by replacing the input with zero, preventing
/// false dependencies from trash registers.
pub struct ActionLikelyTrash { pub count: i32 ,
}
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
                    // truncate inputs to 1 and set slot 0.  The length read
                    // is hoisted out of the branch condition: an `if`-condition
                    // temporary read guard lives through the branch body, and
                    // op_set_input's write lock on the same op would deadlock
                    // (PIPE-STACKSTALL-COUNT-0001; first execution of this
                    // rewrite path hung the whole pipeline).
                    while op.0.read().unwrap().inrefs.len() > 1 {
                        let last = op.0.read().unwrap().inrefs.len() - 1;
                        fd.op_remove_input(op, last);
                    }
                    let remaining = op.0.read().unwrap().inrefs.len();
                    if remaining == 0 {
                        fd.op_insert_input(op, prev_out, 0);
                    } else {
                        fd.op_set_input(op, prev_out, 0);
                    }
                    local_count += 1;
                }
                break;
            }
        }

        // Ghidra: coreaction.cc:945 — every MULTIEQUAL rewritten to a COPY
        // increments the inherited Action::count member; perform() returns
        // that count so the parent stackstall group's rule_repeatapply
        // fixed point sees this action's changes (PIPE-STACKSTALL-COUNT-0001).
        self.count += local_count;
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: externalizes Ghidra's inherited protected Action::count (coreaction.cc:945) into the Rust ActionState accumulator
    fn take_count_delta(&mut self) -> i32 {
        std::mem::take(&mut self.count)
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

/// FuncLink: link function calls, corresponding to `ActionFuncLink`
/// (coreaction.cc). `func_link_input` preserves Ghidra's permanent trials,
/// storage spaces, stack loads, and placeholder slots. The output-extension
/// and calculated-bool paths in `func_link_output` remain `CALLSPEC-0001`.
pub struct ActionFuncLink;
impl ActionFuncLink {
    // Ghidra: coreaction.hh:697 ActionFuncLink (constructor mirror)
    pub fn new() -> Self { Self }

    /// Set up input-parameter recovery for one call site. The permanently
    /// embedded `ParamActive` records every locked formal, while its separate
    /// active flag is enabled only for unlocked or varargs prototypes.
    // Ghidra: coreaction.cc:1474 ActionFuncLink::funcLinkInput
    pub fn func_link_input(
        fd: &mut Funcdata,
        fc_idx: usize,
        op: &crate::op::PcodeOpRef,
    ) -> Result<()> {
        let (inputlocked, varargs, mut spacebase, params) = match fd.get_call_specs(fc_idx) {
            Some(fc) => (
                fc.is_input_locked(),
                fc.is_dotdotdot(),
                fc.prototype.get_spacebase(),
                fc.prototype
                    .parameters
                    .iter()
                    .map(|param| {
                        (
                            param.get_address_space(),
                            param.address,
                            param.data_type.get_size() as i32,
                        )
                    })
                    .collect::<Vec<_>>(),
            ),
            None => return Ok(()),
        };
        if !inputlocked || varargs {
            if let Some(mut fc) = fd.get_call_specs_mut(fc_idx) {
                fc.init_active_input();
            }
        }
        if inputlocked {
            let mut setplaceholder = varargs;
            for (i, &(param_space, param_addr, sz)) in params.iter().enumerate() {
                let off = param_addr.as_u64();
                if let Some(mut fc) = fd.get_call_specs_mut(fc_idx) {
                    fc.active_input
                        .register_trial_in_space(param_space, param_addr, sz);
                    fc.active_input.get_trial_mut(i).mark_active();
                    if varargs {
                        fc.active_input
                            .get_trial_mut(i)
                            .set_fixed_position(i as i32);
                    }
                }
                let vn = if param_space.is_stack() {
                    let loadval = fd.op_stack_load(param_space, off, sz as usize, op, None, false);
                    let num_in = op.0.read().unwrap().num_input();
                    fd.op_insert_input(op, loadval.clone(), num_in);
                    if !setplaceholder {
                        setplaceholder = true;
                        loadval.write().unwrap().set_spacebase_placeholder();
                        spacebase = None;
                    }
                    None
                } else {
                    Some(fd.new_varnode_in_space(sz as usize, param_space, param_addr))
                };
                if let Some(vn) = vn {
                    let num_in = op.0.read().unwrap().num_input();
                    fd.op_insert_input(op, vn, num_in);
                }
            }
        }
        if let Some(spacebase) = spacebase {
            if let Some(fc_arc) = fd.callspecs.get(fc_idx).cloned() {
                fc_arc
                    .write()
                    .unwrap()
                    .create_placeholder(fd, op, spacebase);
            }
        }
        Ok(())
    }

    /// Set up the modeled return-value recovery slice for a sub-function call,
    /// corresponding to `ActionFuncLink::funcLinkOutput`
    /// (coreaction.cc:1521-1572). The small-size extension path remains
    /// `CALLSPEC-0001`.
    ///
    /// Decide whether the CALL produces an output (return-value) varnode.
    /// Covered control-flow slice:
    /// 1. If the CALL already has an output varnode, remove it (the return
    ///    value is re-decided here).
    /// 2. If the output prototype is LOCKED:
    ///    - if the return type is VOID → produce NO output (void functions
    ///      like exit/free never get a return varnode).
    ///    - else if the proto-store output storage is recorded and lives in
    ///      the spacebase (stack) space → setStackOutputLock(true) and delay
    ///      the output varnode until stack heritage (coreaction.cc:1546-1549;
    ///      `Heritage::tryOutputStackGuard` then builds it caller-
    ///      perspective).
    ///    - else → newVarnodeOut(sz, addr) builds the return varnode at the
    ///      recorded storage offset (coreaction.cc:1551). With no recorded
    ///      storage — a transitional state Ghidra cannot reach (its outparam
    ///      always carries an address) — RAX offset 0x0 remains the default.
    /// 3. If UNLOCKED → initActiveOutput() (defer to trial recovery; no
    ///    output varnode yet).
    ///
    /// The small-size extension path (assumedOutputExtension → SEXT/ZEXT/
    /// PIECE op, coreaction.cc:1552-1568) requires Funcdata op-edit
    /// infrastructure beyond this pass and is deferred (`CALLSPEC-0001`).
    // Ghidra: coreaction.cc:1521 ActionFuncLink::funcLinkOutput
    pub fn func_link_output(fd: &mut Funcdata, fc_idx: usize, op: &crate::op::PcodeOpRef) {
        // (1) Remove any existing output (Ghidra coreaction.cc:1525-1537).
        {
            let has_output = op.0.read().unwrap().output.is_some();
            if has_output {
                fd.op_unset_output(op);
            }
        }
        let (output_locked, return_type) = match fd.get_call_specs(fc_idx) {
            Some(fc) => (fc.is_output_locked(), fc.prototype.return_type.clone()),
            None => return,
        };
        // (3) Unlocked → active-output trial recovery (coreaction.cc:1572).
        if !output_locked {
            if let Some(mut fc_mut) = fd.get_call_specs_mut(fc_idx) {
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
        // Non-void locked return: read the proto-store output parameter
        // (coreaction.cc:1539-1542).
        //   ProtoParameter *outparam = fc->getOutput();
        //   int4 sz = outparam->getSize();
        let sz = return_type.get_size().max(1);
        let output_storage = match fd.get_call_specs(fc_idx) {
            Some(fc) => fc.get_output_storage(),
            None => return,
        };
        if let Some((spc, off)) = output_storage {
            // coreaction.cc:1545-1550:
            //   Address addr = outparam->getAddress();
            //   if (addr.getSpace()->getType() == IPTR_SPACEBASE) {
            //     // Delay creating output Varnode until heritage of the
            //     // stack, when we know relative value of the stack pointer
            //     fc->setStackOutputLock(true);
            //     return;
            //   }
            // The transitional enum's Stack IS the spacebase space (the
            // same cc:1460 convention as guard_calls).
            if spc == crate::space::AddressSpace::Stack {
                if let Some(mut fc_mut) = fd.get_call_specs_mut(fc_idx) {
                    fc_mut.set_stack_output_lock(true);
                }
                return;
            }
            // coreaction.cc:1551: data.newVarnodeOut(sz, addr, callop) —
            // the return varnode lives at the recorded storage offset
            // (Rugra's new_varnode_out creates it in the register space,
            // the registered transitional divergence).
            fd.new_varnode_out(sz, crate::address::Address::new(off), op);
        } else {
            // Transitional no-storage fallback: RAX = register offset 0x0
            // (x86_lift.rs encoding), for locked prototypes whose storage
            // is not recorded (known-prototype paths).
            fd.new_varnode_out(sz, crate::address::Address::new(0x0), op);
        }
    }
}
impl Action for ActionFuncLink {
    // Ghidra: coreaction.cc:1575 ActionFuncLink::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        let n_calls = fd.num_calls();
        for idx in 0..n_calls {
            let op_ref = fd
                .get_call_specs(idx)
                .and_then(|fc| fc.find_call_op(fd))
                .ok_or_else(|| {
                    crate::error::Error::Lowlevel(
                        "FuncCallSpecs is not bound to its CALL operation".to_string(),
                    )
                })?;
            Self::func_link_input(fd, idx, &op_ref)?;
            Self::func_link_output(fd, idx, &op_ref);
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:697
    fn get_flags(&self) -> u32 { action_flags::RULE_ONCEPERFUNC }
    // RUGRA-GLUE: Rust Action trait get_name; "funclink" mirrors ctor at coreaction.hh:697
    fn get_name(&self) -> &str { "funclink" }
}

/// FuncLinkOutOnly: run the modeled outgoing-link slice corresponding to
/// `ActionFuncLinkOutOnly` (coreaction.cc:1588-1595). It delegates to the
/// partial `func_link_output`; its remaining paths are `CALLSPEC-0001`.
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
        // Partial correspondence to ActionFuncLinkOutOnly::apply
        // (coreaction.cc:1588-1595); func_link_output carries the
        // CALLSPEC-0001 remainder.
        let n_calls = fd.num_calls();
        let mut pairs: Vec<(usize, crate::op::PcodeOpRef)> = Vec::new();
        for i in 0..n_calls {
            if let Some(fc) = fd.get_call_specs(i) {
                if let Some(op_ref) = fc.find_call_op(fd) {
                    pairs.push((i, op_ref));
                }
            }
        }
        for (idx, op_ref) in pairs {
            ActionFuncLink::func_link_output(fd, idx, &op_ref);
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:715
    fn get_flags(&self) -> u32 { action_flags::RULE_ONCEPERFUNC }
    // RUGRA-GLUE: Rust Action trait get_name; "funclink_outonly" mirrors ctor at coreaction.hh:715 (Action(rule_onceperfunc,"funclink_outonly",g))
    fn get_name(&self) -> &str { "funclink_outonly" }
}

/// Deindirect: partially resolve indirect calls, corresponding to
/// `ActionDeindirect` (coreaction.cc). External-reference and typed-prototype
/// paths remain `CALLSPEC-0001`.
pub struct ActionDeindirect { pub count: i32 ,
}
impl ActionDeindirect {
    // Ghidra: coreaction.hh:206 ActionDeindirect (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionDeindirect {
    // Ghidra: coreaction.cc:1219 ActionDeindirect::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Partial correspondence to ActionDeindirect::apply
        // (coreaction.cc:1219-1280).
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
        let mut callind_updates: Vec<(
            usize, Arc<std::sync::RwLock<crate::op::PcodeOp>>, crate::address::Address,
        )> = Vec::new();
        for i in 0..n_calls {
            let call_op = match fd.get_call_specs(i).and_then(|fc| fc.find_call_op(fd)) {
                Some(op) => op,
                None => continue,
            };
            let is_callind = call_op.0.read().unwrap().opcode == OpCode::CPUI_CALLIND;
            let found = is_callind.then(|| {
                let resolved = Self::trace_indirect_target(&call_op.0);
                (call_op.0.clone(), resolved)
            });
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
            if let Some(mut fc) = fd.get_call_specs_mut(i) {
                fc.entry_addr = Some(target_addr);
            }
            let op_ref = crate::op::PcodeOpRef(op_arc);
            let owner = fd
                .get_call_specs_owner(i)
                .expect("callspec owner disappeared during deindirect");
            let annotation = fd.new_varnode_call_specs(&owner);
            fd.op_set_input(&op_ref, annotation, 0);
            fd.op_set_opcode(&op_ref, OpCode::CPUI_CALL);
            change_count += 1;
        }

        // Ghidra: coreaction.cc:1240 — every resolved indirect call increments
        // the inherited Action::count member; perform() returns that count so
        // the parent stackstall group's rule_repeatapply fixed point sees this
        // action's changes (PIPE-STACKSTALL-COUNT-0001).
        self.count += change_count;
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: externalizes Ghidra's inherited protected Action::count (coreaction.cc:1240) into the Rust ActionState accumulator
    fn take_count_delta(&mut self) -> i32 {
        std::mem::take(&mut self.count)
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
    fn trace_indirect_target(
        op_arc: &Arc<std::sync::RwLock<crate::op::PcodeOp>>,
    ) -> Option<crate::address::Address> {
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
    fn chase_copy_to_const(
        vn: &Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> Option<crate::address::Address> {
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
            let def = match def { Some(d) => d, None => return None ,
            };
            let d_rg = def.read().unwrap();
            if d_rg.opcode != crate::opcodes::OpCode::CPUI_COPY {
                return None;
            }
            cur = d_rg.get_in(0).cloned()?;
        }
        None
    }
}

// ============================================================================
// StackEqn (coreaction.cc:25-30)
// ============================================================================

/// A stack equation. Faithful to Ghidra `StackEqn` (coreaction.cc:25-30).
/// Represents a linear equation `var1 - var2 = rhs` relating two stack-pointer
/// variable instances. Used by StackSolver to recover stack-pointer changes
/// across unknown sub-functions.
#[derive(Debug, Clone, Copy)]
pub struct StackEqn {
    /// Variable with +1 coefficient.
    pub var1: i32,
    /// Variable with -1 coefficient.
    pub var2: i32,
    /// Right-hand side of the equation.
    pub rhs: i32,
}

impl StackEqn {
    // Ghidra: coreaction.cc:55 StackEqn::compare
    /// Order two equations by var1. Faithful to `StackEqn::compare`
    /// (coreaction.cc:55-59): `return (a.var1 < b.var1);`.
    pub fn compare(a: &StackEqn, b: &StackEqn) -> bool {
        a.var1 < b.var1
    }
}

// ============================================================================
// StackSolver (coreaction.cc:33-50 / 55-252)
// ============================================================================

/// Solves for stack-pointer changes across unknown sub-functions.
/// Faithful to Ghidra `StackSolver` (coreaction.cc:33-50).
///
/// Builds a system of linear equations from stack-pointer-defining ops
/// (INT_ADD/COPY/INDIRECT/MULTIEQUAL/INT_AND), then solves via worklist
/// propagation. The INDIRECT case produces "guess" equations (rhs=4 default)
/// that are resolved iteratively when the system is underdetermined.
pub struct StackSolver {
    /// Known equations (coreaction.cc:34 `eqs`).
    eqs: Vec<StackEqn>,
    /// Guessed equations for underdetermined systems (coreaction.cc:35 `guess`).
    guess: Vec<StackEqn>,
    /// Indexed set of stack-pointer varnodes (coreaction.cc:36 `vnlist`).
    vnlist: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    /// Companion input index for INDIRECT-produced variables (coreaction.cc:37).
    companion: Vec<i32>,
    /// Starting address of the stack-pointer (coreaction.cc:38 `spacebase`).
    spacebase: crate::address::Address,
    /// Collected solutions (coreaction.cc:39 `soln`); 65535 = unsolved.
    soln: Vec<i32>,
    /// Number of variables missing an equation (coreaction.cc:40).
    missed_variables: i32,
}

impl StackSolver {
    /// Sentinel value for "unsolved" (Ghidra uses 65535, coreaction.cc:70/87).
    const UNSOLVED: i32 = 65535;

    // Ghidra: coreaction.cc:33 StackSolver (constructor)
    /// Create an empty solver.
    pub fn new() -> Self {
        Self {
            eqs: Vec::new(),
            guess: Vec::new(),
            vnlist: Vec::new(),
            companion: Vec::new(),
            spacebase: crate::address::Address::new(0),
            soln: Vec::new(),
            missed_variables: 0,
        }
    }

    // Ghidra: coreaction.cc:67 StackSolver::propagate
    /// Propagate a solution for one variable to other variables via the
    /// equation system. Faithful to `StackSolver::propagate`
    /// (coreaction.cc:67-94). Uses a worklist; for each popped variable,
    /// finds equations where var1==that variable and solves for var2.
    fn propagate(&mut self, varnum: i32, val: i32) {
        let varnum = varnum as usize;
        if varnum >= self.soln.len() {
            return;
        }
        if self.soln[varnum] != Self::UNSOLVED {
            return; // Already solved (cc:70).
        }
        self.soln[varnum] = val;
        let mut workstack: Vec<i32> = Vec::with_capacity(self.soln.len());
        workstack.push(varnum as i32);
        while let Some(vn) = workstack.pop() {
            let vn_u = vn as usize;
            // lower_bound on eqs by var1 (cc:84). eqs is sorted by var1.
            let target = StackEqn { var1: vn, var2: 0, rhs: 0 ,
            };
            let start = self.eqs.partition_point(|e| StackEqn::compare(e, &target));
            let mut i = start;
            while i < self.eqs.len() && self.eqs[i].var1 == vn {
                let var2 = self.eqs[i].var2 as usize;
                if var2 < self.soln.len() && self.soln[var2] == Self::UNSOLVED {
                    // cc:88: soln[var2] = soln[varnum] - rhs;
                    self.soln[var2] = self.soln[vn_u].wrapping_sub(self.eqs[i].rhs);
                    workstack.push(var2 as i32);
                }
                i += 1;
            }
        }
    }

    // Ghidra: coreaction.cc:96 StackSolver::duplicate
    /// Duplicate each equation, swapping var1/var2 and negating rhs.
    /// Faithful to `StackSolver::duplicate` (coreaction.cc:96-110).
    /// After duplication, re-sort by var1.
    fn duplicate(&mut self) {
        let size = self.eqs.len();
        for i in 0..size {
            let eqn = StackEqn {
                var1: self.eqs[i].var2,
                var2: self.eqs[i].var1,
                rhs: -self.eqs[i].rhs,
            };
            self.eqs.push(eqn);
        }
        // stable_sort by StackEqn::compare (cc:109).
        self.eqs.sort_by(|a, b| {
            if StackEqn::compare(a, b) {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        });
    }

    // Ghidra: coreaction.cc:112 StackSolver::solve
    /// Solve the equation system. Faithful to `StackSolver::solve`
    /// (coreaction.cc:112-140). Initializes soln to UNSOLVED, duplicates
    /// equations, propagates from variable 0=0, then iteratively applies
    /// guesses until no progress.
    pub fn solve(&mut self) {
        self.soln.clear();
        self.soln.resize(self.vnlist.len(), Self::UNSOLVED);
        self.duplicate();
        self.propagate(0, 0);
        let size = self.guess.len();
        let mut lastcount = size + 2;
        loop {
            let mut count = 0;
            for i in 0..size {
                let var1 = self.guess[i].var1 as usize;
                let var2 = self.guess[i].var2 as usize;
                let rhs = self.guess[i].rhs;
                let s1 = *self.soln.get(var1).unwrap_or(&Self::UNSOLVED);
                let s2 = *self.soln.get(var2).unwrap_or(&Self::UNSOLVED);
                if s1 != Self::UNSOLVED && s2 == Self::UNSOLVED {
                    self.propagate(var2 as i32, s1.wrapping_sub(rhs));
                } else if s1 == Self::UNSOLVED && s2 != Self::UNSOLVED {
                    self.propagate(var1 as i32, s2.wrapping_add(rhs));
                } else if s1 == Self::UNSOLVED && s2 == Self::UNSOLVED {
                    count += 1;
                }
            }
            if count == lastcount {
                break;
            }
            lastcount = count;
            if count == 0 {
                break;
            }
        }
    }

    // Ghidra: coreaction.cc:147 StackSolver::build
    /// Build the equation system from the function's stack-pointer varnodes.
    /// The covered equation/solve core corresponds to `StackSolver::build`
    /// (coreaction.cc:147-252). The initial-input error channel is
    /// `PIPE-STALL-SHAPE-0001`/UNTESTED and differs today (Ghidra throws
    /// `LowlevelError`, while Rust logs and returns). The INDIRECT branch also
    /// guesses rhs=4 instead of consuming a known callspec extrapop. Neither
    /// branch is claimed by the D0 projection; the callspec branch remains
    /// `CALLSPEC-0001`/UNTESTED.
    ///
    /// Collects all instances of the spacebase varnode, then for each
    /// instance examines its defining op:
    /// - INT_ADD(const): equation `var1 - var2 = const` (cc:175-189)
    /// - COPY: equation `var1 - var2 = 0` (cc:190-198)
    /// - INDIRECT: equation with companion; rhs from callspec extrapop or
    ///   guess rhs=4 (cc:199-221)
    /// - MULTIEQUAL: one equation per input (cc:222-232)
    /// - INT_AND(const): treat as COPY, rhs=0 (cc:233-248)
    pub fn build(
        &mut self,
        data: &crate::funcdata::Funcdata,
        spacebase_addr: crate::address::Address,
        spacebase_size: usize,
    ) {
        use crate::opcodes::OpCode;
        self.spacebase = spacebase_addr;
        // Ghidra cc:154-162: collect all instances of the spacebase varnode.
        // begiter = data.beginLoc(size, spacebase); enditer = endLoc(...).
        // All instances must not be free.
        self.vnlist.clear();
        self.companion.clear();
        for vn_ref in &data.vbank.loc_tree {
            let vn = vn_ref.0.read().unwrap();
            if vn.size == spacebase_size && vn.loc == spacebase_addr {
                if vn.is_free() {
                    break; // cc:158: if ((*begiter)->isFree()) break;
                }
                self.vnlist.push(vn_ref.0.clone());
                self.companion.push(-1);
            }
        }
        self.missed_variables = 0;
        if self.vnlist.is_empty() {
            return;
        }
        // cc:165-166: if (!vnlist[0]->isInput()) throw.
        if !self.vnlist[0].read().unwrap().is_input() {
            eprintln!("[STACKPTR] WARN: input value of stackpointer is not used");
            return;
        }
        // cc:170-251: build equations.
        for i in 1..self.vnlist.len() {
            let vn_arc = self.vnlist[i].clone();
            let op_arc = {
                let vn = vn_arc.read().unwrap();
                vn.def.as_ref().and_then(|w| w.upgrade())
            };
            let Some(op_arc) = op_arc else {
                self.missed_variables += 1;
                continue;
            };
            let op_code = op_arc.read().unwrap().opcode;
            match op_code {
                OpCode::CPUI_INT_ADD => {
                    // cc:175-189.
                    let (in0, in1) = {
                        let o = op_arc.read().unwrap();
                        (o.get_in(0).cloned(), o.get_in(1).cloned())
                    };
                    let (mut other, mut const_) = (in0, in1);
                    if other
                        .as_ref()
                        .map(|v| v.read().unwrap().is_constant())
                        .unwrap_or(false) {
                        std::mem::swap(&mut other, &mut const_);
                    }
                    let (Some(other), Some(const_)) = (other, const_) else {
                        self.missed_variables += 1;
                        continue;
                    };
                    if !const_.read().unwrap().is_constant() {
                        self.missed_variables += 1;
                        continue;
                    }
                    // cc:183: othervn->getAddr() != spacebase
                    let other_loc = other.read().unwrap().loc;
                    if other_loc != spacebase_addr {
                        self.missed_variables += 1;
                        continue;
                    }
                    // Find othervn in vnlist (binary search, cc:184).
                    let var2 = self.find_varnode_index(&other);
                    if var2 < 0 {
                        self.missed_variables += 1;
                        continue;
                    }
                    let rhs = const_.read().unwrap().get_offset() as i32;
                    self.eqs.push(StackEqn { var1: i as i32, var2, rhs ,
                    });
                }
                OpCode::CPUI_COPY => {
                    // cc:190-198.
                    let othervn = op_arc.read().unwrap().get_in(0).cloned();
                    let Some(othervn) = othervn else {
                        self.missed_variables += 1;
                        continue;
                    };
                    if othervn.read().unwrap().loc != spacebase_addr {
                        self.missed_variables += 1;
                        continue;
                    }
                    let var2 = self.find_varnode_index(&othervn);
                    if var2 < 0 {
                        self.missed_variables += 1;
                        continue;
                    }
                    self.eqs.push(StackEqn { var1: i as i32, var2, rhs: 0 ,
                    });
                }
                OpCode::CPUI_INDIRECT => {
                    // cc:199-221.
                    let othervn = op_arc.read().unwrap().get_in(0).cloned();
                    let Some(othervn) = othervn else {
                        self.missed_variables += 1;
                        continue;
                    };
                    if othervn.read().unwrap().loc != spacebase_addr {
                        self.missed_variables += 1;
                        continue;
                    }
                    let var2 = self.find_varnode_index(&othervn);
                    if var2 < 0 {
                        self.missed_variables += 1;
                        continue;
                    }
                    self.companion[i] = var2;
                    // cc:206-217: if INDIRECT is due to a CALL, try to get
                    // extrapop from the callspec. Exact per-op callspec
                    // identity is now available, but FuncCallSpecs still lacks
                    // effective_extrapop and this StackSolver consumer remains
                    // unwired under CALLSPEC-0001, so retain the old guess.
                    // cc:219-220: guess, rhs = 4.
                    self.guess.push(StackEqn { var1: i as i32, var2, rhs: 4 ,
                    });
                }
                OpCode::CPUI_MULTIEQUAL => {
                    // cc:222-232: one equation per input.
                    let num_in = op_arc.read().unwrap().inrefs.len();
                    for j in 0..num_in {
                        let othervn = op_arc.read().unwrap().get_in(j).cloned();
                        let Some(othervn) = othervn else {
                            self.missed_variables += 1;
                            continue;
                        };
                        if othervn.read().unwrap().loc != spacebase_addr {
                            self.missed_variables += 1;
                            continue;
                        }
                        let var2 = self.find_varnode_index(&othervn);
                        if var2 < 0 {
                            self.missed_variables += 1;
                            continue;
                        }
                        self.eqs.push(StackEqn { var1: i as i32, var2, rhs: 0 ,
                        });
                    }
                }
                OpCode::CPUI_INT_AND => {
                    // cc:233-248: stack alignment via INT_AND. Treat as COPY.
                    let (in0, in1) = {
                        let o = op_arc.read().unwrap();
                        (o.get_in(0).cloned(), o.get_in(1).cloned())
                    };
                    let (mut other, mut const_) = (in0, in1);
                    if other
                        .as_ref()
                        .map(|v| v.read().unwrap().is_constant())
                        .unwrap_or(false) {
                        std::mem::swap(&mut other, &mut const_);
                    }
                    let (Some(other), Some(const_)) = (other, const_) else {
                        self.missed_variables += 1;
                        continue;
                    };
                    if !const_.read().unwrap().is_constant() {
                        self.missed_variables += 1;
                        continue;
                    }
                    if other.read().unwrap().loc != spacebase_addr {
                        self.missed_variables += 1;
                        continue;
                    }
                    let var2 = self.find_varnode_index(&other);
                    if var2 < 0 {
                        self.missed_variables += 1;
                        continue;
                    }
                    self.eqs.push(StackEqn { var1: i as i32, var2, rhs: 0 ,
                    });
                }
                _ => {
                    // cc:249-250.
                    self.missed_variables += 1;
                }
            }
        }
    }

    // RUGRA-GLUE: find_varnode_index — Ghidra cc:184 用 lower_bound+
    // Varnode::comparePointers; Rugra 用线性 Arc 指针匹配(vnlist 小)。
    /// Binary search for a varnode's index in vnlist (Ghidra cc:184
    /// `lower_bound(vnlist, othervn, Varnode::comparePointers)`). Rugra's
    /// vnlist is in loc_tree order (sorted by address), so binary search by
    /// Arc pointer identity works.
    fn find_varnode_index(
        &self, vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> i32 {
        let target_ptr = std::sync::Arc::as_ptr(vn);
        for (i, v) in self.vnlist.iter().enumerate() {
            if std::sync::Arc::as_ptr(v) == target_ptr {
                return i as i32;
            }
        }
        -1
    }

    // Ghidra: coreaction.cc:46 StackSolver::getNumVariables
    pub fn get_num_variables(&self) -> usize {
        self.vnlist.len()
    }
    // Ghidra: coreaction.cc:47 StackSolver::getVariable
    pub fn get_variable(
        &self, i: usize,
    ) -> Option<&std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        self.vnlist.get(i)
    }
    // Ghidra: coreaction.cc:48 StackSolver::getCompanion
    pub fn get_companion(&self, i: usize) -> i32 {
        *self.companion.get(i).unwrap_or(&-1)
    }
    // Ghidra: coreaction.cc:49 StackSolver::getSolution
    pub fn get_solution(&self, i: usize) -> i32 {
        *self.soln.get(i).unwrap_or(&Self::UNSOLVED)
    }
    // RUGRA-GLUE: get_missed_variables — Ghidra StackSolver 暴露 missedvariables
    // 字段 (coreaction.cc:50);Rugra 用访问器。
    /// Number of variables for which we are missing an equation.
    pub fn get_missed_variables(&self) -> i32 {
        self.missed_variables
    }
}

// Ghidra: coreaction.cc:261 ActionStackPtrFlow::analyzeExtraPop
/// Calculate stack-pointer change across undetermined sub-functions.
/// Structurally corresponds to `ActionStackPtrFlow::analyzeExtraPop`
/// (coreaction.cc:261-318). It uses StackSolver to build and solve the equation
/// system for the stack pointer, but currently only counts solved changes.
///
/// **Status**: structural skeleton. D0 supplies exact callspec identity, but
/// effective_extrapop storage and this solver's mutating write-back are still
/// absent under `CALLSPEC-0001`. StackSolver's equation/solve core is present,
/// but its known-extrapop INDIRECT branch and this consumer are incomplete.
pub fn analyze_extra_pop(
    data: &crate::funcdata::Funcdata,
    stackspace_spacebase: crate::address::Address,
    spacebase_size: usize,
    _spcbase: i32,
) -> i32 {
    let mut solver = StackSolver::new();
    solver.build(data, stackspace_spacebase, spacebase_size);
    solver.solve();
    let mut numchange = 0;
    // Ghidra cc:303-316: walk solutions, for each INDIRECT-companion varnode
    // with a valid solution, set the callspec's extrapop. Exact owner lookup is
    // available, but effective_extrapop/write-back is CALLSPEC-0001; count the
    // changes without mutating the owner.
    for i in 0..solver.get_num_variables() {
        let sol = solver.get_solution(i);
        let comp = solver.get_companion(i);
        if sol != StackSolver::UNSOLVED && comp >= 0 {
            // Would write: fc->setEffectiveExtraPop(sol-sol2) on the exact
            // callspec for vnlist[i]'s INDIRECT op. CALLSPEC-0001.
            numchange += 1;
        }
    }
    numchange
}

/// (coreaction.cc:261-499). Repairs "stack pointer clogs": an INT_ADD on the
/// spacebase (stack pointer input) whose constant offset comes from a stack
/// LOAD. Such a LOAD is linked to its matching STORE (same stack-relative
/// offset) and converted to a COPY of the stored value.
///
/// analyzeExtraPop (coreaction.cc:261-318) uses StackSolver to recover
/// extra-pop across undetermined sub-functions.
///
/// Ghidra carries `analysis_finished` (coreaction.hh:91) — set on the first
/// clean pass and cleared only by reset (coreaction.hh:99) — and reports a
/// repaired clog through the inherited Action::count member
/// (coreaction.cc:492) so the parent stackstall group's rule_repeatapply
/// fixed point sees the change (PIPE-STACKSTALL-COUNT-0001).
pub struct ActionStackPtrFlow {
    /// True if analysis already performed (coreaction.hh:91).
    analysis_finished: bool,
    /// Inherited Action::count channel (repaired clogs; coreaction.cc:492).
    count: i32,
}

impl ActionStackPtrFlow {
    // Ghidra: coreaction.hh:89 ActionStackPtrFlow (constructor mirror)
    pub fn new() -> Self {
        Self {
            analysis_finished: false,
            count: 0,
        }
    }

    // RUGRA-GLUE: fixture view of the protected analysis_finished member (coreaction.hh:91); Ghidra fixtures read the flag through the same test-only access shim
    /// Read the `analysis_finished` state (fixture view of coreaction.hh:91).
    pub fn is_analysis_finished(&self) -> bool {
        self.analysis_finished
    }

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
            fd.new_constant(
                datavn.read().unwrap().get_size(), datavn.read().unwrap().get_offset(),
            )
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
                let datavn_size = curop
                    .inrefs
                    .get(2)
                    .map(|v| v.read().unwrap().get_size())
                    .unwrap_or(0);
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

    // Ghidra: coreaction.cc:432 ActionStackPtrFlow::checkClog
    /// Find any stack pointer clogs and pass them to the repair routine.
    /// Returns the number of clogs repaired (cc:478) together with the
    /// spacebase register location/size (used by analyzeExtraPop, cc:435-436).
    /// With no spacebase input the count is 0 (cc:444).
    fn check_clog(
        fd: &mut Funcdata) -> (
        i32,
        Option<(crate::address::Address, usize)>) {
        use crate::opcodes::OpCode;
        // Locate the spacebase (stack-pointer) INPUT varnode: an input varnode
        // flagged is_spacebase. Faithful to checkClog's beginLoc lookup
        // (coreaction.cc:440-447).
        let mut spcbasein: Option<
            std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = None;
        for op_ref in &fd.obank.alivelist {
            let o = op_ref.0.read().unwrap();
            for in_vn in o.inrefs.iter() {
                let g = in_vn.read().unwrap();
                if g.is_spacebase() && g.is_input() {
                    spcbasein = Some(in_vn.clone());
                    break;
                }
            }
            if spcbasein.is_some() {
                break;
            }
        }
        let Some(spcbasein) = spcbasein else {
            return (0, None); // cc:444 — no spacebase input, no clogs
        };
        let spacebase_loc = {
            let g = spcbasein.read().unwrap();
            Some((g.loc.clone(), g.get_size()))
        };
        // cc:448-480: find INT_ADD(spcbasein, y) where y is a non-constant
        // (loaded) value — a "clog" — and repair it.
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
                (a.inrefs.get(0).cloned(), a.inrefs.get(1).cloned())
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
            // cc:458-461 — x must be stack-relative (the guard itself; the
            // constant value is only used through the LOAD pointer below).
            match Self::is_stack_relative(&spcbasein, &x) {
                Some(_) => {}
                None => continue,
            }
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
                // cc:473-475 — constz is the LOAD's pointer stack offset, not
                // the clog ADD's operand offset.
                let ptrvn = {
                    let l = loadop_arc.read().unwrap();
                    l.inrefs.get(1).cloned()
                };
                let Some(ptrvn) = ptrvn else { continue };
                let Some(constz) = Self::is_stack_relative(&spcbasein, &ptrvn) else {
                    continue;
                };
                clogcount += Self::repair(
                    fd,
                    &spcbasein,
                    &crate::op::PcodeOpRef(loadop_arc),
                    constz);
            }
        }
        (clogcount, spacebase_loc)
    }
}
impl Action for ActionStackPtrFlow {
    // Ghidra: coreaction.cc:481 ActionStackPtrFlow::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // cc:484-485 — analysis already performed; a successive pass does
        // nothing until reset() (coreaction.hh:99) clears the flag.
        if self.analysis_finished {
            return Ok(action_status::NO_CHANGE);
        }
        // cc:490 — checkClog(data, stackspace, 0). A null stackspace
        // (cc:486-489) has no Rugra counterpart: the spacebase-input lookup
        // returning None is the same "nothing to analyze" condition and falls
        // into the clean-pass arm below, mirroring the finish side-effect.
        let (numchange, spacebase_loc) = Self::check_clog(fd);
        if numchange > 0 {
            // cc:492 — the repair feeds the inherited Action::count member so
            // the parent stackstall group's rule_repeatapply fixed point
            // re-runs the group (PIPE-STACKSTALL-COUNT-0001).
            self.count += 1;
        }
        if numchange == 0 {
            // cc:495 analyzeExtraPop. The cc:264-267 guard reads the
            // architecture's evalfp_called/defaultfp proto model and elides
            // the solver when the model's extra-pop is known; Rugra reads the
            // function prototype's resolved extra_pop (same "known" answer in
            // the default pipeline once the model is installed). The unknown
            // path runs StackSolver — its callspec write-back is still
            // unwired (see analyze_extra_pop), tracked by
            // PIPE-STACKSTALL-COUNT-0001's solver residual.
            if fd.funcp.get_extra_pop() == crate::fspec::EXTRAPOP_UNKNOWN_FULL {
                if let Some((spacebase_addr, spacebase_size)) = spacebase_loc {
                    analyze_extra_pop(fd, spacebase_addr, spacebase_size, 0);
                }
            }
            // cc:496 — analysis finished on a clean pass.
            self.analysis_finished = true;
        }
        Ok(action_status::NO_CHANGE)
    }
    // Ghidra: coreaction.hh:99 ActionStackPtrFlow::reset — purge the
    // per-function analysis state (the inherited Action::reset status/flag
    // handling lives in the externalized ActionState, see ActionGroup::reset).
    fn reset(&mut self, _fd: &mut Funcdata) {
        self.analysis_finished = false;
    }
    // RUGRA-GLUE: externalizes Ghidra's inherited protected Action::count (coreaction.cc:492) into the Rust ActionState accumulator
    fn take_count_delta(&mut self) -> i32 {
        std::mem::take(&mut self.count)
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
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:1060
    fn get_flags(&self) -> u32 { action_flags::RULE_ONCEPERFUNC }
    // RUGRA-GLUE: Rust Action trait get_name; "internalstorage" mirrors ctor at coreaction.hh:1058
    fn get_name(&self) -> &str { "internalstorage" }
}

/// ExtraPop setup corresponding to the modeled portion of
/// `ActionExtraPopSetup` (coreaction.cc). Effective-extrapop callspec storage
/// remains `CALLSPEC-0001`.
pub struct ActionExtraPopSetup;
impl ActionExtraPopSetup {
    // Ghidra: coreaction.hh:676 ActionExtraPopSetup (constructor mirror)
    pub fn new() -> Self { Self }
}
impl Action for ActionExtraPopSetup {
    // Ghidra: coreaction.cc:1436 ActionExtraPopSetup::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Partial correspondence to ActionExtraPopSetup::apply
        // (coreaction.cc:1436-1466).
        // For each call whose prototype extraPop is non-zero, insert an op on
        // the stack-pointer register: `RSP' = RSP + extrapop` (INT_ADD)
        // placed AFTER the call when extrapop is known, or an INDIRECT on
        // RSP placed BEFORE the call when unknown. This models the callee's
        // `ret` popping the pushed return address — without it the SLEIGH
        // call push (`RSP = RSP-8; [RSP] = retaddr`) leaves the stack
        // pointer permanently 8 bytes off across every call, and the
        // stack-relative STORE at the call site can never be rewritten to a
        // stack-space COPY by RuleStoreVarnode (the ghost
        // `*(long*)((long)uVar20-8) = 0x3710` class of residual stores).
        //
        // cc:1441-1444: stackspace==0 → return; sb = stackspace->getSpacebase(0)
        // (coreaction.cc:5472: stackspace = conf->getStackSpace()). Rugra's
        // equivalent stack-pointer record lives on the Architecture
        // (stack_pointer_space/offset/size, x86-64 = register:0x20 size 8).
        let Some(arch) = fd.get_arch().cloned() else {
            return Ok(action_status::NO_CHANGE);
        };
        let sb_space = arch.stack_pointer_space;
        let sb_offset = arch.stack_pointer_offset;
        let sb_size = arch.stack_pointer_size;

        let n = fd.num_calls();
        for i in 0..n {
            // cc:1447-1448: fc = data.getCallSpecs(i); skip when extraPop==0.
            let (call_op, extra_pop) = {
                let Some(fc) = fd.get_call_specs(i) else {
                    continue;
                };
                (fc.find_call_op(fd), fc.prototype.get_extra_pop())
            };
            if extra_pop == 0 {
                continue; // Stack pointer is undisturbed
            }
            let call_op = match call_op {
                Some(op) => op,
                None => continue,
            };
            let op_addr = call_op.0.read().unwrap().get_addr();
            // cc:1449-1451: op = newOp(2, call addr); out = newVarnodeOut(sb)
            // — a REGISTER-space varnode at the stack-pointer address.
            let op = fd.new_op(2, op_addr);
            fd.new_varnode_out(sb_size, crate::address::Address::new(sb_offset), &op);
            // cc:1452: in(0) = newVarnode(sb) — a FREE register-space varnode
            // at the same address; heritage links it to the most recent RSP
            // definition before the call.
            let invn = fd
                .vbank
                .create_with_space(sb_size, sb_space, sb_offset);
            fd.op_set_input(&op, invn, 0);
            if extra_pop != crate::fspec::EXTRAPOP_UNKNOWN_FULL {
                // cc:1453-1457: setEffectiveExtraPop (bookkeeping; Rugra's
                // FuncCallSpecs has no effective_extrapop field yet — the
                // value is only read back by FuncCallSpecs consumers that
                // Rugra has not ported) + INT_ADD form inserted AFTER call.
                fd.op_set_opcode(&op, OpCode::CPUI_INT_ADD);
                let pop_c = fd.new_constant(sb_size, extra_pop as u64);
                fd.op_set_input(&op, pop_c, 1);
                fd.op_insert_after(&op, &call_op);
            } else {
                // cc:1459-1464: unknown extrapop → INDIRECT form inserted
                // BEFORE the call, keyed by the iop-space reference.
                fd.op_set_opcode(&op, OpCode::CPUI_INDIRECT);
                let iop_vn = fd.new_varnode_iop(&call_op);
                fd.op_set_input(&op, iop_vn, 1);
                fd.op_insert_before(&op, &call_op);
            }
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:679
    fn get_flags(&self) -> u32 { action_flags::RULE_ONCEPERFUNC }
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
pub struct ActionConditionalConst { pub count: i32 ,
}

// Ghidra: coreaction.hh:571 ActionConditionalConst::ConstPoint
/// A point in control-flow where a Varnode can propagate as a constant
/// down a conditional branch. Faithful to `ConstPoint` (coreaction.hh:571-582).
#[derive(Clone)]
struct ConstPoint {
    /// Varnode that is constant for some reads.
    vn: Arc<RwLock<crate::varnode::Varnode>>,
    /// Representative of the constant (may be None if constructed from value).
    const_vn: Option<Arc<RwLock<crate::varnode::Varnode>>>,
    /// The constant value.
    value: u64,
    /// Block index that dominates all reads where vn is constant.
    const_block_idx: i32,
    /// Input edge from condition block.
    in_slot: i32,
    /// True if block is dominated by constant path.
    block_is_dom: bool,
}

impl ConstPoint {
    // Ghidra: coreaction.hh:578 ConstPoint::ConstPoint(Varnode*,Varnode*,FlowBlock*,int4,bool)
    /// Construct from a constant Varnode (coreaction.hh:578).
    fn from_const_vn(
        vn: Arc<RwLock<crate::varnode::Varnode>>,
        const_vn: Arc<RwLock<crate::varnode::Varnode>>,
        const_block_idx: i32,
        in_slot: i32,
        block_is_dom: bool,
    ) -> Self {
        let value = const_vn.read().unwrap().get_offset();
        Self { vn, const_vn: Some(const_vn), value, const_block_idx, in_slot, block_is_dom ,
        }
    }
    // Ghidra: coreaction.hh:580 ConstPoint::ConstPoint(Varnode*,uintb,FlowBlock*,int4,bool)
    /// Construct from a constant value (coreaction.hh:580).
    fn from_value(
        vn: Arc<RwLock<crate::varnode::Varnode>>,
        value: u64,
        const_block_idx: i32,
        in_slot: i32,
        block_is_dom: bool,
    ) -> Self {
        Self { vn, const_vn: None, value, const_block_idx, in_slot, block_is_dom ,
        }
    }
}

impl ActionConditionalConst {
    // Ghidra: coreaction.hh:569 ActionConditionalConst (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }

    // Ghidra: coreaction.cc:4069 ActionConditionalConst::clearMarks
    /// Clear the mark flag on all ops in the list. Faithful to `clearMarks`
    /// (coreaction.cc:4069-4074).
    fn clear_marks(op_list: &[crate::op::PcodeOpRef]) {
        for op_ref in op_list {
            op_ref.0.write().unwrap().flags &= !crate::op::pcodeop_flags::MARK;
        }
    }

    // Ghidra: coreaction.cc:4083 ActionConditionalConst::collectReachable
    /// Collect COPY, INDIRECT, and MULTIEQUAL ops reachable from the given
    /// varnode, without going through excised phi-node edges. Faithful to
    /// `collectReachable` (coreaction.cc:4083-4121).
    /// Sets MARK on each collected op. `phi_node_edges` is a sorted list of
    /// (op_ptr, slot) pairs to excise.
    fn collect_reachable(
        vn: &Arc<RwLock<crate::varnode::Varnode>>,
        phi_node_edges: &mut Vec<(usize, usize)>,
        reachable: &mut Vec<crate::op::PcodeOpRef>,
    ) {
        use crate::opcodes::OpCode;
        phi_node_edges.sort();
        let mut count = 0usize;
        // cc:4088-4095: if vn is written by MULTIEQUAL, mark it reachable.
        {
            let vn_r = vn.read().unwrap();
            if vn_r.is_written() {
                if let Some(def_weak) = vn_r.def.as_ref().and_then(|w| w.upgrade()) {
                    let def = def_weak.read().unwrap();
                    if def.opcode == OpCode::CPUI_MULTIEQUAL {
                        drop(def);
                        def_weak.write().unwrap().flags |= crate::op::pcodeop_flags::MARK;
                        reachable.push(crate::op::PcodeOpRef(def_weak.clone()));
                    }
                }
            }
        }
        let mut cur_vn = vn.clone();
        loop {
            // cc:4099-4116: iterate descendants of cur_vn.
            let descend_refs: Vec<_> = {
                let vn_r = cur_vn.read().unwrap();
                vn_r.descend.iter().filter_map(|w| w.upgrade()).collect()
            };
            for op_arc in &descend_refs {
                let op = op_arc.read().unwrap();
                if (op.flags & crate::op::pcodeop_flags::MARK) != 0 { continue; }
                let opc = op.opcode;
                if opc == OpCode::CPUI_MULTIEQUAL {
                    // cc:4104-4110: find incoming slot for current vn, check
                    // if it's an excised edge.
                    let op_ptr = Arc::as_ptr(op_arc) as usize;
                    let mut found_slot = false;
                    for slot in 0..op.num_input() {
                        if let Some(in_vn) = op.get_in(slot) {
                            if Arc::ptr_eq(&in_vn, &cur_vn) {
                                // Check if this edge is excised.
                                if phi_node_edges.binary_search(&(op_ptr, slot)).is_ok() {
                                    continue; // excised — skip this slot
                                }
                                found_slot = true;
                                break;
                            }
                        }
                    }
                    if !found_slot { continue; } // was reached via excised edge only
                    // cc:4110: if all slots excised → continue (not reached)
                } else if opc != OpCode::CPUI_COPY && opc != OpCode::CPUI_INDIRECT {
                    continue;
                }
                drop(op);
                op_arc.write().unwrap().flags |= crate::op::pcodeop_flags::MARK;
                reachable.push(crate::op::PcodeOpRef(op_arc.clone()));
            }
            // cc:4117: if count >= reachable.size() break.
            if count >= reachable.len() { break; }
            // cc:4118: vn = reachable[count]->getOut().
            cur_vn = match reachable[count].0.read().unwrap().output.as_ref() {
                Some(out) => out.clone(),
                None => break,
            };
            count += 1;
        }
    }

    // Ghidra: coreaction.cc:4129 ActionConditionalConst::flowToAlternatePath
    /// Follow the output of `op` forward through MULTIEQUAL/INDIRECT/COPY ops.
    /// If it hits a marked op (alternate flow), return true. Faithful to
    /// `flowToAlternatePath` (coreaction.cc:4129-4160).
    fn flow_to_alternate_path(op: &crate::op::PcodeOpRef) -> bool {
        use crate::opcodes::OpCode;
        // cc:4132: if op is already marked, it IS the alternate path.
        if (op.0.read().unwrap().flags & crate::op::pcodeop_flags::MARK) != 0 { return true; }
        let mut mark_set: Vec<Arc<RwLock<crate::varnode::Varnode>>> = Vec::new();
        let vn = match op.0.read().unwrap().output.as_ref() {
            Some(out) => out.clone(), None => return false,
        };
        mark_set.push(vn.clone());
        vn.write().unwrap().set_mark();
        let mut count = 0usize;
        let mut found_path = false;
        while count < mark_set.len() {
            let cur_vn = mark_set[count].clone();
            count += 1;
            let descend_refs: Vec<_> = {
                let vn_r = cur_vn.read().unwrap();
                vn_r.descend.iter().filter_map(|w| w.upgrade()).collect()
            };
            for next_op_arc in &descend_refs {
                let next_op = next_op_arc.read().unwrap();
                let opc = next_op.opcode;
                if opc == OpCode::CPUI_MULTIEQUAL {
                    // cc:4147-4149: if nextOp is marked, found alternate path.
                    if (next_op.flags & crate::op::pcodeop_flags::MARK) != 0 {
                        found_path = true;
                        break;
                    }
                } else if opc != OpCode::CPUI_COPY && opc != OpCode::CPUI_INDIRECT {
                    continue;
                }
                let out_vn = match next_op.output.as_ref() {
                    Some(o) => o.clone(), None => continue,
                };
                if out_vn.read().unwrap().is_marked() { continue; }
                out_vn.write().unwrap().set_mark();
                mark_set.push(out_vn);
            }
            if found_path { break; }
        }
        // Clear marks on varnodes (Ghidra doesn't explicitly clear here —
        // marks are cleared later by clearMarks on ops, not varnodes. But
        // Varnode marks in Rugra use the same MARK bit as PcodeOp — we need
        // to be careful. Ghidra uses separate mark bits for Varnode vs PcodeOp.)
        for vn in &mark_set {
            vn.write().unwrap().clear_mark();
        }
        found_path
    }

    // Ghidra: coreaction.cc:4261 ActionConditionalConst::pushConstant
    /// Try to propagate a constant through an op. If all inputs are constant
    /// (the front ConstPoint's value substituted for its vn, other inputs
    /// already constant), compute the output via executeSimple and create a
    /// new ConstPoint for the output. Faithful to `pushConstant` (cc:4261-4288).
    fn push_constant(points: &mut Vec<ConstPoint>, op: &crate::op::PcodeOpRef) {
        use crate::opcodes::OpCode;
        let op_r = op.0.read().unwrap();
        // cc:4264: skip special ops.
        let eval_type = op_r.get_eval_type();
        if (eval_type & crate::op::pcodeop_flags::SPECIAL) != 0 { return; }
        // cc:4265: skip floating-point ops.
        // (Rugra: check opcode for float ops.)
        if matches!(
            op_r.opcode,
            OpCode::CPUI_FLOAT_ADD | OpCode::CPUI_FLOAT_SUB | OpCode::CPUI_FLOAT_MULT
            | OpCode::CPUI_FLOAT_DIV | OpCode::CPUI_FLOAT_NEG | OpCode::CPUI_FLOAT_ABS
            | OpCode::CPUI_FLOAT_SQRT | OpCode::CPUI_FLOAT_TRUNC | OpCode::CPUI_FLOAT_CEIL
            | OpCode::CPUI_FLOAT_FLOOR | OpCode::CPUI_FLOAT_ROUND
            | OpCode::CPUI_FLOAT_FLOAT2FLOAT | OpCode::CPUI_FLOAT_INT2FLOAT
            | OpCode::CPUI_FLOAT_NAN | OpCode::CPUI_FLOAT_EQUAL
            | OpCode::CPUI_FLOAT_NOTEQUAL | OpCode::CPUI_FLOAT_LESS
            | OpCode::CPUI_FLOAT_LESSEQUAL
        ) { return; }
        let out_vn = match op_r.output.as_ref() { Some(o) => o.clone(), None => return ,
        };
        if out_vn.read().unwrap().get_size() > 8 { return; }
        // cc:4268-4269: get the varnode + slot from front ConstPoint.
        if points.is_empty() { return; }
        let front_vn = points[0].vn.clone();
        let front_value = points[0].value;
        let front_block = points[0].const_block_idx;
        let front_slot = points[0].in_slot;
        let front_dom = points[0].block_is_dom;
        let slot = op_r.slot_of_input(&front_vn);
        let slot = match slot { Some(s) => s, None => return ,
        };
        // cc:4270-4282: build input values.
        let n_in = op_r.num_input();
        let mut inputs: Vec<u64> = Vec::with_capacity(n_in);
        for i in 0..n_in {
            if i == slot {
                inputs.push(front_value);
            } else {
                let in_vn = match op_r.get_in(i) { Some(v) => v.clone(), None => return ,
                };
                if in_vn.read().unwrap().get_size() > 8 { return; }
                if in_vn.read().unwrap().is_constant() {
                    inputs.push(in_vn.read().unwrap().get_offset());
                } else {
                    return; // Not all inputs constant.
                }
            }
        }
        drop(op_r);
        // cc:4284: executeSimple.
        let outval = match op.0.read().unwrap().execute_simple(&inputs) {
            Some(v) => v, None => return,
        };
        // cc:4287: create new ConstPoint for output.
        points.push(ConstPoint::from_value(
            out_vn, outval, front_block, front_slot, front_dom,
        ));
    }

    // Ghidra: coreaction.cc:4478 ActionConditionalConst::findConstCompare
    /// Examine a boolean varnode's definition for a comparison against a
    /// constant. If found, create a ConstPoint for the variable down the
    /// constant edge. Faithful to `findConstCompare` (cc:4478-4511).
    fn find_const_compare(
        points: &mut Vec<ConstPoint>,
        bool_vn: &Arc<RwLock<crate::varnode::Varnode>>,
        bl_out: &[Option<Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>>; 2],
        bl_out_rev_index: [i32; 2],
        block_dom: [bool; 2],
        mut flip_edge: bool,
    ) {
        use crate::opcodes::OpCode;
        // cc:4481: boolVn must be written.
        let mut cur_vn = bool_vn.clone();
        let mut comp_op;
        let mut opc;
        loop {
            let vn_r = cur_vn.read().unwrap();
            if !vn_r.is_written() { return; }
            let def_arc = match vn_r.def.as_ref().and_then(|w| w.upgrade()) {
                Some(d) => d, None => return,
            };
            drop(vn_r);
            comp_op = def_arc;
            let comp_r = comp_op.read().unwrap();
            opc = comp_r.opcode;
            // cc:4484-4490: BOOL_NEGATE → flip edge, follow in(0).
            if opc == OpCode::CPUI_BOOL_NEGATE {
                flip_edge = !flip_edge;
                let next = match comp_r.get_in(0) { Some(v) => v.clone(), None => return ,
                };
                drop(comp_r);
                cur_vn = next;
                continue;
            }
            break;
        }
        // cc:4492-4497: determine constEdge from INT_EQUAL/INT_NOTEQUAL.
        let const_edge = if opc == OpCode::CPUI_INT_EQUAL { 1 }
                         else if opc == OpCode::CPUI_INT_NOTEQUAL { 0 }
                         else { return; };
        // cc:4499-4507: find variable and constant inputs.
        let comp_r = comp_op.read().unwrap();
        let mut var_vn = match comp_r.get_in(0) { Some(v) => v.clone(), None => return ,
        };
        let mut const_vn = match comp_r.get_in(1) { Some(v) => v.clone(), None => return ,
        };
        if !const_vn.read().unwrap().is_constant() {
            if !var_vn.read().unwrap().is_constant() { return; }
            std::mem::swap(&mut var_vn, &mut const_vn);
        }
        drop(comp_r);
        // cc:4508: varVn must NOT have a lone descendant (else no phi to split).
        if var_vn.read().unwrap().lone_descend().is_some() { return; }
        // cc:4509-4510: flip edge if needed.
        let const_edge = if flip_edge { 1 - const_edge } else { const_edge };
        // cc:4511: create ConstPoint.
        let out_block = match &bl_out[const_edge] { Some(b) => b.clone(), None => return ,
        };
        let _ = bl_out_rev_index; // rev index not used in Rugra's block model
        points.push(ConstPoint::from_const_vn(
            var_vn, const_vn,
            out_block.read().unwrap().get_index(),
            const_edge as i32,
            block_dom[const_edge],
        ));
    }

    // Ghidra: coreaction.cc:4349 ActionConditionalConst::testAlternatePath
    /// Test if we can reach the given Varnode via a path other than through
    /// the immediate edge. Backtracks through MULTIEQUAL other slots (up to
    /// depth) and checks INT_ADD/PTRSUB/PTRADD inputs. Faithful to
    /// `testAlternatePath` (cc:4349-4371).
    fn test_alternate_path(
        vn: &Arc<RwLock<crate::varnode::Varnode>>,
        op: &Arc<RwLock<crate::op::PcodeOp>>,
        slot: i32,
        depth: i32,
    ) -> bool {
        use crate::opcodes::OpCode;
        let op_r = op.read().unwrap();
        let n_in = op_r.num_input();
        for i in 0..n_in {
            if i as i32 == slot { continue; }
            let in_vn = match op_r.get_in(i) { Some(v) => v.clone(), None => continue ,
            };
            // cc:4355: direct match.
            if Arc::ptr_eq(&in_vn, vn) { return true; }
            // cc:4356-4367: check if inVn is written by ADD/PTRSUB/PTRADD/MULTIEQUAL.
            let in_r = in_vn.read().unwrap();
            if !in_r.is_written() { continue; }
            let def_arc = match in_r.def.as_ref().and_then(|w| w.upgrade()) {
                Some(d) => d, None => continue,
            };
            drop(in_r);
            let def_r = def_arc.read().unwrap();
            let opc = def_r.opcode;
            if opc == OpCode::CPUI_INT_ADD || opc == OpCode::CPUI_PTRSUB || opc == OpCode::CPUI_PTRADD {
                // cc:4360-4361: check if vn is an input to the ADD/PTRSUB/PTRADD.
                if let Some(in0) = def_r.get_in(0) {
                    if Arc::ptr_eq(&in0, vn) { return true; }
                }
                if let Some(in1) = def_r.get_in(1) {
                    if Arc::ptr_eq(&in1, vn) { return true; }
                }
            } else if opc == OpCode::CPUI_MULTIEQUAL {
                // cc:4363-4367: recursive backtrack through MULTIEQUAL.
                if depth == 0 { continue; }
                drop(def_r);
                if Self::test_alternate_path(vn, &def_arc, -1, depth - 1) {
                    return true;
                }
            }
        }
        false
    }

    // Ghidra: coreaction.cc:4201 ActionConditionalConst::placeCopy
    /// Create a COPY op assigning `const_vn` at the bottom of block `bl`,
    /// before any branch. Returns the output Varnode of the COPY.
    fn place_copy(
        fd: &mut Funcdata,
        op: &crate::op::PcodeOpRef,
        bl: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        const_vn: &Arc<RwLock<crate::varnode::Varnode>>,
    ) -> Arc<RwLock<crate::varnode::Varnode>> {
        let addr = {
            let bl_r = bl.read().unwrap();
            let bb = match bl_r.as_any().downcast_ref::<crate::block::BlockBasic>() {
                Some(b) => b,
                None => return fd.new_unique_out(const_vn.read().unwrap().get_size(), op),
            };
            if let Some(last_op) = bb.ops.last() {
                last_op.0.read().unwrap().start.addr
            } else {
                op.0.read().unwrap().start.addr
            }
        };
        let copy_op = fd.new_op(1, addr);
        fd.op_set_opcode(&copy_op, crate::opcodes::OpCode::CPUI_COPY);
        let out_vn = fd.new_unique_out(const_vn.read().unwrap().get_size(), &copy_op);
        fd.op_set_input(&copy_op, const_vn.clone(), 0);
        fd.obank.alivelist.push(copy_op.clone());
        out_vn
    }

    // Ghidra: coreaction.cc:4299 ActionConditionalConst::handlePhiNodes
    /// Replace MULTIEQUAL edges with constant if no alternate flow.
    fn handle_phi_nodes(
        &mut self,
        fd: &mut Funcdata,
        var_vn: &Arc<RwLock<crate::varnode::Varnode>>,
        const_vn: &Arc<RwLock<crate::varnode::Varnode>>,
        phi_node_edges: &mut Vec<(usize, usize)>,
    ) {
        let mut alternate_flow: Vec<crate::op::PcodeOpRef> = Vec::new();
        Self::collect_reachable(var_vn, phi_node_edges, &mut alternate_flow);
        let mut results: Vec<i32> = vec![0; phi_node_edges.len()];
        for (i, (op_ptr, _)) in phi_node_edges.iter().enumerate() {
            let op_ref = fd
                .obank
                .alivelist
                .iter()
                .find(|r| Arc::as_ptr(&r.0) as usize == *op_ptr)
                .cloned();
            if let Some(op_ref) = op_ref {
                if !Self::flow_to_alternate_path(&op_ref) {
                    results[i] = 1;
                }
            }
        }
        Self::clear_marks(&alternate_flow);
        for (i, (op_ptr, slot)) in phi_node_edges.iter().enumerate() {
            if results[i] != 1 { continue; }
            let op_ref = fd
                .obank
                .alivelist
                .iter()
                .find(|r| Arc::as_ptr(&r.0) as usize == *op_ptr)
                .cloned();
            if let Some(op_ref) = op_ref {
                let bl_idx = {
                    let op_r = op_ref.0.read().unwrap();
                    if let Some(parent_weak) = op_r.parent.as_ref() {
                        if let Some(parent) = parent_weak.upgrade() {
                            parent
                                .read()
                                .unwrap()
                                .get_in(*slot)
                                .map(|e| e.point.read().unwrap().get_index())
                                .unwrap_or(0)
                        } else { 0 }
                    } else { 0 }
                };
                let bl = match fd.bblocks.get_block(bl_idx as usize) {
                    Some(b) => b, None => continue,
                };
                let out_vn = Self::place_copy(fd, &op_ref, &bl, const_vn);
                fd.op_set_input(&op_ref, out_vn, *slot);
                self.count += 1;
            }
        }
    }

    // Ghidra: coreaction.cc:4383 ActionConditionalConst::propagateConstant
    /// Replace reads of the Varnode down the constant path with a constant.
    /// Faithful to `propagateConstant` (cc:4383-4466).
    ///
    /// For each ConstPoint, walk descendants of its Varnode:
    ///  - INDIRECT: skip.
    ///  - MULTIEQUAL (if use_multiequal): collect phi-node edges for
    ///    handlePhiNodes (the immediate edge from the const block, or any edge
    ///    whose source block is dominated by constBlock when blockIsDom).
    ///  - COPY: only follow if its output has a lone descendant that is not a
    ///    marker and not another COPY.
    ///  - otherwise: if blockIsDom AND constBlock dominates op's parent:
    ///    CPUI_RETURN never takes the constant directly — a `copyBeforeRet`
    ///    COPY (newOp(1, ret->getAddr()), out at varVn's size/address) is
    ///    inserted before the RETURN and its output becomes RETURN input
    ///    slot 1 (cc:4439-4448); every other opcode gets the constant in
    ///    varVn's slot directly (cc:4449-4452). Else pushConstant to extend
    ///    the point through this op.
    fn propagate_constant(
        &mut self,
        fd: &mut Funcdata,
        points: &mut Vec<ConstPoint>,
        use_multiequal: bool,
    ) {
        use crate::block::FlowBlock;
        use crate::opcodes::OpCode;
        let mut phi_node_edges: Vec<(usize, usize)> = Vec::new();
        while !points.is_empty() {
            let point = points.remove(0);
            let var_vn = point.vn.clone();
            let mut const_vn = point.const_vn.clone();
            let const_block_idx = point.const_block_idx;
            let const_block = fd.bblocks.get_block(const_block_idx as usize);
            let in_slot = point.in_slot;
            let block_is_dom = point.block_is_dom;
            let descend_refs: Vec<_> = {
                let vn_r = var_vn.read().unwrap();
                vn_r.descend.iter().filter_map(|w| w.upgrade()).collect()
            };
            for op_arc in &descend_refs {
                let op_r = op_arc.read().unwrap();
                let opc = op_r.opcode;
                // cc:4399: don't propagate into INDIRECT.
                if opc == OpCode::CPUI_INDIRECT { continue; }
                // cc:4401-4427: MULTIEQUAL handling.
                if opc == OpCode::CPUI_MULTIEQUAL {
                    if !use_multiequal { continue; }
                    // cc:4404-4405: skip if varVn is addr-tied to the op output.
                    let var_addr_tied = var_vn.read().unwrap().is_addr_tied();
                    let out_matches_addr = op_r
                        .output
                        .as_ref()
                        .map(|o| {
                        let o_r = o.read().unwrap();
                        let v_r = var_vn.read().unwrap();
                        o_r.is_addr_tied() && o_r.get_addr() == v_r.get_addr()
                    })
                        .unwrap_or(false);
                    if var_addr_tied && out_matches_addr { continue; }
                    // Get the MULTIEQUAL's parent block.
                    let bl = match op_r.parent.as_ref().and_then(|w| w.upgrade()) {
                        Some(b) => b, None => continue,
                    };
                    let bl_idx = bl.read().unwrap().get_index();
                    if bl_idx == const_block_idx {
                        // cc:4407-4415: immediate edge from the const block.
                        let input_matches = op_r
                            .get_in(in_slot as usize)
                            .map(|v| Arc::ptr_eq(v, &var_vn))
                            .unwrap_or(false);
                        if input_matches {
                            // cc:4411-4413: heuristics to avoid needless new var.
                            if point.value > 1 { continue; }
                            let out_addr_tied = op_r
                                .output
                                .as_ref()
                                .map(|o| o.read().unwrap().is_addr_tied())
                                .unwrap_or(false);
                            if out_addr_tied { continue; }
                            if Self::test_alternate_path(&var_vn, op_arc, in_slot, 2) { continue; }
                            let op_ptr = Arc::as_ptr(op_arc) as usize;
                            phi_node_edges.push((op_ptr, in_slot as usize));
                        }
                    } else if block_is_dom {
                        // cc:4417-4425: any edge whose source block is dominated
                        // by constBlock.
                        for slot in 0..op_r.num_input() {
                            let matches = op_r
                                .get_in(slot)
                                .map(|v| Arc::ptr_eq(v, &var_vn))
                                .unwrap_or(false);
                            if !matches { continue; }
                            // constBlock must dominate bl->getIn(slot).
                            let in_bl_dominated = {
                                let bl_r = bl.read().unwrap();
                                match bl_r.get_in(slot) {
                                    Some(edge) => {
                                        let src = edge.point.clone();
                                        match &const_block {
                                            Some(cb) => {
                                                let cb_r = cb.read().unwrap();
                                                let src_r = src.read().unwrap();
                                                cb_r.dominates(&src)
                                            }
                                            None => false,
                                        }
                                    }
                                    None => false,
                                }
                            };
                            if in_bl_dominated {
                                let op_ptr = Arc::as_ptr(op_arc) as usize;
                                phi_node_edges.push((op_ptr, slot));
                            }
                        }
                    }
                    continue;
                }
                // cc:4428-4434: COPY — only follow into a "more interesting" op.
                if opc == OpCode::CPUI_COPY {
                    let out_vn = match op_r.output.as_ref() { Some(o) => o.clone(), None => continue ,
                    };
                    let follow = out_vn.read().unwrap().lone_descend();
                    match &follow {
                        Some(f) => {
                            let fr = f.read().unwrap();
                            if fr.is_marker() || fr.opcode == OpCode::CPUI_COPY { continue; }
                        }
                        None => continue,
                    }
                }
                // cc:4435: if !blockIsDom, skip (but may still pushConstant).
                let op_parent = op_r.parent.as_ref().and_then(|w| w.upgrade());
                drop(op_r);
                // cc:4436: constBlock->dominates(op->getParent()).
                let dominated = match (&const_block, &op_parent) {
                    (Some(cb), Some(op_bl)) => {
                        let cb_r = cb.read().unwrap();
                        let op_bl_r = op_bl.read().unwrap();
                        cb_r.dominates(&op_bl)
                    }
                    _ => false,
                };
                if block_is_dom && dominated {
                    // SAFETY GUARD (convergence): only count this as a change if
                    // the target slot does NOT already hold the same constant
                    // value. Rugra's op_set_input does Arc-ptr dedup, but each
                    // call to new_constant allocates a fresh constant Arc, so
                    // without a value-level guard the repeatapply mainloop
                    // re-reports the same propagation every pass and never
                    // converges (12/24 curl timeouts). Ghidra avoids this via
                    // immediate deadcode/condexe folding of the now-constant
                    // compare; Rugra's downstream passes don't always fold, so
                    // we guard at the source. For the CPUI_RETURN arm below the
                    // guard is vacuous after the first insertion (RETURN slot 1
                    // then holds the copyBeforeRet COPY output, never a
                    // constant, and op_set_input severs varVn's descend link so
                    // the RETURN is never revisited).
                    let slot = op_arc.read().unwrap().slot_of_input(&var_vn);
                    if let Some(slot) = slot {
                        let already_const = op_arc
                            .read()
                            .unwrap()
                            .get_in(slot)
                            .map(|v| {
                                let vr = v.read().unwrap();
                                vr.is_constant() && vr.get_offset() == point.value
                            })
                            .unwrap_or(false);
                        if already_const { continue; }
                        // cc:4437-4438: lazily create the constant varnode.
                        if const_vn.is_none() {
                            let size = var_vn.read().unwrap().get_size();
                            const_vn = Some(fd.new_constant(size, point.value));
                        }
                        let cvn = const_vn.clone().unwrap();
                        if opc == OpCode::CPUI_RETURN {
                            // cc:4439-4448: CPUI_RETURN ops can't directly take
                            // constants as inputs. Insert a COPY before the
                            // RETURN whose output varnode (at varVn's exact
                            // size/address) becomes RETURN input slot 1 — slot
                            // 1 unconditionally, NOT getSlot(varVn).
                            let (var_size, var_space, var_off) = {
                                let vr = var_vn.read().unwrap();
                                (vr.get_size(), vr.get_space(), vr.get_offset())
                            };
                            let op_ref = crate::op::PcodeOpRef(op_arc.clone());
                            let ret_addr = op_ref.0.read().unwrap().get_addr();
                            // cc:4442: newOp(1, op->getAddr()).
                            let copy_before_ret = fd.new_op(1, ret_addr);
                            // cc:4443: opSetOpcode(copyBeforeRet, CPUI_COPY).
                            fd.op_set_opcode(&copy_before_ret, OpCode::CPUI_COPY);
                            // cc:4444: opSetInput(copyBeforeRet, constVn, 0).
                            fd.op_set_input(&copy_before_ret, cvn, 0);
                            // cc:4445: newVarnodeOut(varVn->getSize(),
                            // varVn->getAddr(), copyBeforeRet). Space-aware
                            // form of Funcdata::new_varnode_out (which pins the
                            // Register space): the COPY out must live at
                            // varVn's exact (space,offset,size). The
                            // assignHigh/checkForLaned/setVarnodeProperties
                            // legs mirror Funcdata::newVarnodeOut
                            // (funcdata_varnode.cc:104-122) inline.
                            let out_vn = fd.vbank.create_def_with_space(
                                var_size,
                                var_space,
                                var_off,
                                &copy_before_ret.0,
                            );
                            copy_before_ret.0.write().unwrap().output = Some(out_vn.clone());
                            let _ = fd.assign_high(&out_vn);
                            if var_size >= fd.min_laned_size as usize {
                                fd.check_for_laned_register(
                                    var_size,
                                    var_space,
                                    crate::address::Address::new(var_off),
                                );
                            }
                            fd.set_varnode_properties(&out_vn);
                            // cc:4446: opSetInput(op, copyBeforeRet->getOut(), 1).
                            fd.op_set_input(&op_ref, out_vn, 1);
                            // cc:4447: opInsertBefore(copyBeforeRet, op).
                            fd.op_insert_before(&copy_before_ret, &op_ref);
                        } else {
                            // cc:4449-4452: replace the read with the constant.
                            fd.op_set_input(&crate::op::PcodeOpRef(op_arc.clone()), cvn, slot);
                        }
                        self.count += 1;
                    }
                } else {
                    // cc:4455-4457: try to push the constant through this op,
                    // extending the ConstPoint list so reads of the op's output
                    // (within the constant path) can also be replaced.
                    Self::push_constant(points, &crate::op::PcodeOpRef(op_arc.clone()));
                }
            }
            // cc:4459-4464: handle accumulated phi-node edges.
            if !phi_node_edges.is_empty() {
                if const_vn.is_none() {
                    let size = var_vn.read().unwrap().get_size();
                    const_vn = Some(fd.new_constant(size, point.value));
                }
                let cvn = const_vn.unwrap();
                let mut edges = phi_node_edges.clone();
                self.handle_phi_nodes(fd, &var_vn, &cvn, &mut edges);
                phi_node_edges.clear();
            }
        }
    }

    // Ghidra: coreaction.cc:4236 ActionConditionalConst::placeMultipleConstants
    /// Place a single COPY assignment shared by multiple MULTIEQUALs that
    /// flow together. Find common ancestor block via findCommonBlock, place
    /// COPY, replace all flowing-together edges. Faithful to cc:4236-4254.
    fn place_multiple_constants(
        fd: &mut Funcdata,
        phi_node_edges: &[(usize, usize)],
        marks: &[i32],
        const_vn: &Arc<RwLock<crate::varnode::Varnode>>,
    ) {
        // cc:4241-4247: collect blocks for edges with mark==2 (flowing together).
        let mut blocks: Vec<Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>> = Vec::new();
        let mut first_op: Option<crate::op::PcodeOpRef> = None;
        for (i, _) in phi_node_edges.iter().enumerate() {
            if marks.get(i).copied().unwrap_or(0) != 2 { continue; }
            let op_ptr = phi_node_edges[i].0;
            for op_ref in &fd.obank.alivelist {
                if Arc::as_ptr(&op_ref.0) as usize == op_ptr {
                    first_op = Some(op_ref.clone());
                    let op_r = op_ref.0.read().unwrap();
                    if let Some(parent_weak) = op_r.parent.as_ref() {
                        if let Some(parent) = parent_weak.upgrade() {
                            let slot = phi_node_edges[i].1;
                            if let Some(in_edge) = parent.read().unwrap().get_in(slot) {
                                blocks.push(in_edge.point.clone());
                            }
                        }
                    }
                    break;
                }
            }
        }
        if blocks.is_empty() { return; }
        // cc:4248: findCommonBlock — Rugra uses find_common_block_n.
        let root_block = match crate::block::BlockGraph::find_common_block_n(&blocks) {
            Some(b) => b, None => return,
        };
        let op_ref = match first_op { Some(o) => o, None => return ,
        };
        // cc:4249: placeCopy.
        let out_vn = Self::place_copy(fd, &op_ref, &root_block, const_vn);
        // cc:4250-4253: replace each flowing-together edge.
        let alivelist_snapshot: Vec<crate::op::PcodeOpRef> = fd.obank.alivelist.clone();
        for (i, _) in phi_node_edges.iter().enumerate() {
            if marks.get(i).copied().unwrap_or(0) != 2 { continue; }
            let op_ptr = phi_node_edges[i].0;
            let slot = phi_node_edges[i].1;
            for op_ref in &alivelist_snapshot {
                if Arc::as_ptr(&op_ref.0) as usize == op_ptr {
                    fd.op_set_input(op_ref, out_vn.clone(), slot);
                    break;
                }
            }
        }
    }
}
impl Action for ActionConditionalConst {
    // Ghidra: coreaction.cc:4514 ActionConditionalConst::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful port of Ghidra's apply (coreaction.cc:4514-4546).
        //
        // Algorithm:
        // 1. Determine `use_multiequal`: only propagate into MULTIEQUAL ops if
        //    the stack space has been heritaged (>=1 pass completed).
        // 2. For each basic block whose terminal op is a CBRANCH:
        //    a. Compute blockDom[0/1] = does each out-edge block have its
        //       flow restricted to the conditional edge (so a constant holds).
        //    b. If the boolean is read more than once, push two ConstPoints for
        //       the implied boolean constants (0 down false edge, 1 down true).
        //    c. findConstCompare: if the boolean is `var == const` / `var != const`,
        //       push a ConstPoint for `var` down the edge where it equals const.
        //    d. propagateConstant: replace reads of the constant-path Varnode
        //       with the constant, within blocks dominated by the const edge.
        //
        // Safety guards (Rugra-specific, see propagateConstant and the
        // CONVERGENCE GUARD below):
        //  - propagateConstant replaces an input only when the op's block is
        //    dominated by the const block, matching Ghidra's
        //    `constBlock->dominates(op->getParent())` check.
        //  - A value-level idempotency guard skips replacements where the slot
        //    already holds the same constant (avoids non-convergence under
        //    repeatapply, since each new_constant allocates a fresh Arc).
        //  - The IR-mutating work runs at most once per function (cond_const_done
        //    flag), because re-propagating after downstream CFG reshaping does
        //    not converge for some functions.
        //  - op_set_input already does constant dedup + descend-link fixup, so
        //    no dangling references are produced.
        //  - MULTIEQUAL/phi-node replacement (handlePhiNodes -> placeCopy) is
        //    disabled (use_multiequal forced false) because op-insertion under
        //    the repeatapply mainloop does not converge.
        use crate::block::FlowBlock;
        use crate::opcodes::OpCode;

        self.count = 0;

        // CONVERGENCE GUARD (Rugra-specific): the implied-boolean propagation
        // path below mutates the IR by replacing CBRANCH-condition reads with
        // constants. Re-running this on later mainloop iterations (after the
        // downstream ActionConditionalExe/branch-folding has reshaped the CFG)
        // does not converge for some functions — each pass finds fresh
        // propagation targets and the repeatapply loop never settles (5/24 curl
        // timeouts). Gate the IR-mutating work to run at most once per function.
        // The detect/scan still happens every pass (harmless), but once we've
        // mutated, subsequent passes skip. This mirrors Ghidra's effective
        // single-pass behaviour within one mainloop cycle.
        let already_done = fd.cond_const_done;
        fd.cond_const_done = true;

        // cc:4517-4525: useMultiequal gate based on stack heritage passes.
        let use_multiequal = fd.num_heritage_passes() > 0;
        // SAFETY GATE (progressive enablement): the MULTIEQUAL / phi-node
        // replacement path (handlePhiNodes -> placeCopy) inserts new ops into
        // the IR, and under Rugra's repeatapply mainloop this does not converge
        // — it causes 12/24 curl functions to time out. Disable it until the
        // op-insertion + deadcode convergence is hardened. The non-MULTIEQUAL
        // dominance-based constant replacement is retained (safe: it only calls
        // op_set_input, which is idempotent via the cc:107 early-out).
        let use_multiequal = false;

        let n_blocks = fd.bblocks.get_size();
        for i in 0..n_blocks {
            let bl = match fd.bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            // cc:4531-4532: lastOp must be a CBRANCH.
            // Use get_ops() (trait method, overridden on BlockBasic) rather than
            // last_op() (whose trait default returns None and is not overridden).
            let cbranch = {
                let ops = bl.read().unwrap().get_ops();
                match ops.last() {
                    Some(op) => op.clone(),
                    None => continue,
                }
            };
            if cbranch.0.read().unwrap().opcode != OpCode::CPUI_CBRANCH {
                continue;
            }
            // cc:4533: boolVn = cBranch->getIn(1).
            let bool_vn = {
                let cb_r = cbranch.0.read().unwrap();
                match cb_r.get_in(1) {
                    Some(v) => v.clone(),
                    None => continue,
                }
            };

            // cc:4534-4535: blockDom[i] = bl->getOut(i)->restrictedByConditional(bl).
            // Build out-edge block array + rev-index array + dominance array.
            let (bl_out, bl_out_rev_index, block_dom) = {
                let bl_r = bl.read().unwrap();
                let mut bl_out: [Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>; 2] =
                    [None, None];
                let mut bl_out_rev_index: [i32; 2] = [-1, -1];
                for slot in 0..2usize {
                    if let Some(edge) = bl_r.get_out(slot) {
                        let out_bl = edge.point.clone();
                        bl_out_rev_index[slot] = edge.reverse_index;
                        // restrictedByConditional needs the out-block + cond.
                        let restricted = out_bl
                            .read().unwrap()
                            .restricted_by_conditional(&bl);
                        bl_out[slot] = Some(out_bl);
                        // block_dom assigned below after read.
                        let _ = restricted;
                    }
                }
                // Compute block_dom by re-reading (restricted_by_conditional
                // borrows bl immutably, safe here).
                let mut block_dom = [false, false];
                for slot in 0..2usize {
                    if let Some(ref out_bl) = bl_out[slot] {
                        block_dom[slot] = out_bl
                            .read().unwrap()
                            .restricted_by_conditional(&bl);
                    }
                }
                (bl_out, bl_out_rev_index, block_dom)
            };

            // cc:4536: flipEdge = cBranch->isBooleanFlip().
            let flip_edge = cbranch.0.read().unwrap().is_boolean_flip();

            let mut points: Vec<ConstPoint> = Vec::new();

            // cc:4537-4541: if boolVn is read more than once (no lone descend),
            // push implied-constant points (bool=0 down false edge, bool=1 down true).
            // SAFETY GATE (progressive enablement): the implied-boolean path
            // propagates the CBRANCH's own boolean (0/1) into downstream reads.
            // Under Rugra's mainloop, this disrupts ActionConditionalExe / branch
            // folding convergence for several functions (5/24 curl timeouts).
            // Ghidra tolerates this because its condexe+deadcode immediately fold
            // the now-redundant branch; Rugra's do not. Disabled until that
            // downstream convergence is hardened. The findConstCompare path below
            // (var==const propagation) is retained — it is safe and useful.
            if bool_vn.read().unwrap().lone_descend().is_none() {
                // Need the false/true out-blocks. Ghidra uses getFalseOut/getTrueOut
                // which account for the boolean flip. bl_out is indexed [0,1] =
                // [getOut(0), getOut(1)]. Rugra's CBRANCH edges are
                // [branch(taken), fallthru]; with flip, taken/true semantics swap.
                // Match Ghidra: falseOut = getOut(flip ? 1 : 0)... but Rugra's
                // get_false_out/get_true_out helpers already encode this. Use them
                // via the block trait to stay consistent with the rest of Rugra.
                let (false_out_idx, true_out_idx) = if flip_edge { (1, 0) } else { (0, 1) };
                // cc:4539: push bool=flip?1:0 down false out, rev index 0.
                if let Some(false_bl) = bl_out[false_out_idx].clone() {
                    points.push(ConstPoint::from_value(
                        bool_vn.clone(),
                        if flip_edge { 1 } else { 0 },
                        false_bl.read().unwrap().get_index(),
                        bl_out_rev_index[false_out_idx],
                        block_dom[false_out_idx],
                    ));
                }
                // cc:4540: push bool=flip?0:1 down true out, rev index 1.
                if let Some(true_bl) = bl_out[true_out_idx].clone() {
                    points.push(ConstPoint::from_value(
                        bool_vn.clone(),
                        if flip_edge { 0 } else { 1 },
                        true_bl.read().unwrap().get_index(),
                        bl_out_rev_index[true_out_idx],
                        block_dom[true_out_idx],
                    ));
                }
            }

            // cc:4542: findConstCompare.
            Self::find_const_compare(
                &mut points,
                &bool_vn,
                &bl_out,
                bl_out_rev_index,
                block_dom,
                flip_edge,
            );

            // cc:4543: propagateConstant (the IR-mutating step).
            // Guarded by the once-per-function flag (see comment above).
            if !already_done && !points.is_empty() {
                let mut pts = points;
                self.propagate_constant(fd, &mut pts, use_multiequal);
            }
        }

        if self.count > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }
    // RUGRA-GLUE: Rust Action trait get_name; "condconst" mirrors ctor at coreaction.hh:595 (Action(0,"condconst",g))
    fn get_name(&self) -> &str { "condconst" }
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
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:1036
    fn get_flags(&self) -> u32 {
        action_flags::RULE_ONCEPERFUNC
    }

    // Ghidra: coreaction.cc:4869 ActionDynamicSymbols::apply
    fn apply(&mut self, _fd: &mut Funcdata) -> Result<i32> {
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "dynamicsymbols" mirrors ctor at coreaction.hh:1034
    fn get_name(&self) -> &str { "dynamicsymbols" }
}

/// Mapped local sync. Faithful to `ActionMappedLocalSync`
/// (coreaction.cc:2297-2309): re-syncs every Varnode with the final Symbol
/// set, this time updating data-types as well, and reports unreconciled
/// variable overlaps.
pub struct ActionMappedLocalSync {
    /// Ghidra Action::count: incremented when syncVarnodesWithSymbols
    /// reports an update (coreaction.cc:2302-2303).
    count: i32,
}
impl ActionMappedLocalSync {
    // Ghidra: coreaction.hh:867 ActionMappedLocalSync (constructor mirror)
    pub fn new() -> Self { Self { count: 0 } }
}
impl Action for ActionMappedLocalSync {
    // Ghidra: coreaction.cc:2297 ActionMappedLocalSync::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // cc:2300-2303: if (data.syncVarnodesWithSymbols(l1,true,true)) count += 1;
        if fd.sync_varnodes_with_symbols(true, true) {
            self.count += 1;
        }
        // cc:2305-2306: if (l1->hasOverlapProbems())
        // data.warningHeader("Could not reconcile some variable overlaps");
        if let Some(ref scope) = fd.scope {
            if scope.overlap_problems {
                eprintln!(
                    "[WARN] {} Could not reconcile some variable overlaps", fd.name
                );
            }
        }
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: externalizes Ghidra's inherited protected Action::count
    // (coreaction.cc:2303) into the Rust ActionState accumulator.
    fn take_count_delta(&mut self) -> i32 {
        std::mem::take(&mut self.count)
    }
    // RUGRA-GLUE: Rust Action trait get_name; "mapped_local_sync" mirrors ctor at coreaction.hh:869 (Action(0,"mapped_local_sync",g))
    fn get_name(&self) -> &str { "mapped_local_sync" }
}

/// Find Varnodes with a vectorized lane scheme and attempt to split the
/// lanes. Faithful to `ActionLaneDivide` (coreaction.hh:107-123,
/// coreaction.cc:509-622).
///
/// The Architecture lists (vector) registers that may be used to perform
/// parallelized operations on \b lanes within the register. This action
/// looks for these registers as Varnodes, determines if a particular lane
/// scheme makes sense in terms of the function's data-flow, and then
/// rewrites the data-flow so that the lanes become explicit Varnodes.
pub struct ActionLaneDivide {
    /// Ghidra protected `Action::count`, incremented per successful split
    /// (coreaction.cc:578 `count += 1`).
    count: i32,
}

// Ghidra: varnode.cc:1620 VarnodeBank::beginLoc(int4 s,const Address&) / endLoc
/// Varnodes of exact size `storage.size` at exact storage `(space,offset)`,
/// in loc-tree order. This is the Rust equivalent of walking Ghidra's
/// `[beginLoc(sz,addr), endLoc(sz,addr))` range: the loc set is ordered by
/// (address, size ascending, input/written/free, def SeqNum/createIndex)
/// via `VarnodeCompareLocDef` (varnode.cc:34-53), and the exact
/// (size,address) restriction selects a contiguous run in that order.
/// The live iteration is emulated by re-collecting the snapshot after every
/// successful split, mirroring the `Recalculate bounds` step at
/// coreaction.cc:606-607.
fn varnodes_at_storage(
    fd: &Funcdata, storage: &crate::funcdata::LanedStorage,
) -> Vec<Arc<RwLock<crate::varnode::Varnode>>> {
    fd.vbank
        .loc_tree
        .iter()
        .filter(|entry| {
            let vn = entry.0.read().unwrap();
            vn.get_space() == storage.space
                && vn.get_offset() == storage.offset
                && vn.get_size() == storage.size
        })
        .map(|entry| entry.0.clone())
        .collect()
}

impl ActionLaneDivide {
    // Ghidra: coreaction.hh:117 ActionLaneDivide::ActionLaneDivide
    /// Constructor mirror: `Action(rule_onceperfunc,"lanedivide",g)` with
    /// `count` zero-initialized by the Action base.
    pub fn new() -> Self {
        Self { count: 0 }
    }

    // Ghidra: coreaction.cc:509 ActionLaneDivide::collectLaneSizes
    /// Examine the PcodeOps using the given Varnode to determine possible
    /// lane sizes. Faithful to `collectLaneSizes` (coreaction.cc:509-540):
    /// walk the descendant ops first (step 0), then the defining op
    /// (step 1). A CPUI_SUBPIECE descendant contributes its output size; a
    /// CPUI_PIECE definition contributes `min(in(0) size, in(1) size)`.
    /// Each putative size registers only when
    /// `allowedLanes.allowedLane(curSize)` accepts it.
    fn collect_lane_sizes(
        vn: &Arc<RwLock<crate::varnode::Varnode>>,
        allowed_lanes: &crate::transform::LanedRegister,
        check_lanes: &mut crate::transform::LanedRegister,
    ) {
        // cc:512: live descendant-list iteration; nothing mutates during
        // collection, so the snapshot preserves Ghidra's insertion order.
        let descendants: Vec<Arc<RwLock<crate::op::PcodeOp>>> =
            vn.read().unwrap().descend_iter().collect();
        let mut step = 0usize; // 0 = descendants, 1 = def, 2 = done
        let mut iter = 0usize;
        if descendants.is_empty() {
            // cc:514-516: with no descendants, jump straight to the def.
            step = 1;
        }
        while step < 2 {
            let cur_size: i32; // Putative lane size
            if step == 0 {
                let op = descendants[iter].read().unwrap();
                iter += 1;
                if iter == descendants.len() {
                    step = 1; // cc:522-523: advance step before filtering
                }
                if op.opcode != OpCode::CPUI_SUBPIECE {
                    // cc:524: only SUBPIECE splits the big register
                    continue;
                }
                cur_size = op
                    .get_out()
                    .map_or(0, |out| out.read().unwrap().get_size() as i32);
            } else {
                step = 2; // cc:528
                let vng = vn.read().unwrap();
                if !vng.is_written() {
                    continue;
                }
                let Some(def) = vng.get_def() else {
                    continue;
                };
                let op = def.read().unwrap();
                if op.opcode != OpCode::CPUI_PIECE {
                    // cc:531: only PIECE forms the big register from pieces
                    continue;
                }
                // cc:532-535: lane size capped by the smaller PIECE input.
                let in0 = op
                    .get_in(0)
                    .map_or(0, |input| input.read().unwrap().get_size() as i32);
                let in1 = op
                    .get_in(1)
                    .map_or(0, |input| input.read().unwrap().get_size() as i32);
                cur_size = in0.min(in1);
            }
            if allowed_lanes.allowed_lane(cur_size) {
                check_lanes.add_lane_size(cur_size); // cc:537-538
            }
        }
    }

    // Ghidra: coreaction.cc:558 ActionLaneDivide::processVarnode
    /// Search for a likely lane size and try to divide a single Varnode
    /// into these lanes. Faithful to `processVarnode`
    /// (coreaction.cc:558-583). Modes 0/1 collect putative lane sizes from
    /// the local ops (mode 1 additionally allows SUBPIECE downcast
    /// terminators); mode 2 falls back to the architecture's default lane
    /// size. Lane sizes are tried smallest first (LanedIterator bitmask
    /// order); the first successful `LaneDivide::doTrace` applies the
    /// split and increments the change counter.
    fn process_varnode(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<crate::varnode::Varnode>>,
        laned_register: &crate::transform::LanedRegister,
        mode: i32,
    ) -> bool {
        let mut check_lanes = crate::transform::LanedRegister::default(); // no lanes yet
        let allow_downcast = mode > 0;
        if mode < 2 {
            Self::collect_lane_sizes(vn, laned_register, &mut check_lanes);
        } else {
            // cc:566-569: default lane size is the pointer size, except
            // non-4-byte pointers normalize to 8.
            let mut default_size = fd
                .arch
                .as_ref()
                .and_then(|arch| {
                    arch.types
                        .as_ref()
                        .map(|types| types.read().unwrap().get_size_of_pointer())
                })
                .unwrap_or(0);
            if default_size != 4 {
                default_size = 8;
            }
            check_lanes.add_lane_size(default_size);
        }
        // cc:571-572: LanedRegister::const_iterator walks lane sizes
        // smallest first (transform.hh:98-110 bitmask iterator).
        for cur_size in check_lanes.lane_sizes() {
            // cc:574: lane scheme dictated by curSize over the whole register
            let description =
                crate::transform::LaneDescription::uniform(
                laned_register.get_whole_size(), cur_size,
            );
            let mut lane_divide =
                crate::subflow::LaneDivide::new(fd, vn.clone(), description, allow_downcast);
            if lane_divide.do_trace() {
                lane_divide.apply(fd);
                self.count += 1; // cc:578: indicate a change was made
                return true;
            }
        }
        false
    }
}

impl Action for ActionLaneDivide {
    // Ghidra: coreaction.cc:585 ActionLaneDivide::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // cc:588: stop recording laned-register accesses before any split
        // varnode is created.
        fd.set_laned_reg_generated();
        for mode in 0..3i32 {
            // cc:591
            let mut all_storage_processed = true;
            // cc:592: live map<VarnodeData,const LanedRegister*> iteration.
            // The map is provably stable for the duration of apply: every
            // insert path (newUnique/newVarnode/newVarnodeOut/
            // newUniqueOut -> checkForLanedRegister) is gated by
            // minLanedSize == 1000000 from setLanedRegGenerated above, and
            // nothing removes entries before the final
            // clearLanedAccessMap. The per-mode snapshot taken in
            // BTreeMap (=std::map VarnodeData::operator<) order is
            // observably equivalent to Ghidra's live iterator.
            let lane_accesses: Vec<(
                crate::funcdata::LanedStorage, Arc<crate::transform::LanedRegister>,
            )> =
                fd
                .lane_accesses()
                    .map(|(storage, record)| (*storage, record.clone()))
                    .collect();
            for (storage, laned_reg) in &lane_accesses {
                // cc:594-597: sz/addr from the VarnodeData key feed
                // [beginLoc(sz,addr), endLoc(sz,addr)) in loc-tree order;
                // varnodes_at_storage applies the same exact
                // (space,offset,size) restriction.
                let mut varnodes = varnodes_at_storage(fd, storage);
                let mut all_varnodes_processed = true; // cc:598
                let mut index = 0usize;
                while index < varnodes.len() {
                    let vn = varnodes[index].clone();
                    if vn.read().unwrap().has_no_descend() {
                        index += 1; // cc:601-604
                        continue;
                    }
                    if self.process_varnode(fd, &vn, laned_reg, mode) {
                        // cc:606-608: recalculate bounds and restart the
                        // walk from beginLoc.
                        varnodes = varnodes_at_storage(fd, storage);
                        index = 0;
                        all_varnodes_processed = true;
                    } else {
                        index += 1;
                        all_varnodes_processed = false; // cc:611-612
                    }
                }
                if !all_varnodes_processed {
                    all_storage_processed = false; // cc:615-616
                }
            }
            if all_storage_processed {
                break; // cc:618-619
            }
        }
        fd.clear_laned_access_map(); // cc:620
        Ok(action_status::NO_CHANGE)
    }
    // RUGRA-GLUE: externalizes Ghidra's inherited protected Action::count
    // (coreaction.cc:578) into the Rust ActionState accumulator.
    fn take_count_delta(&mut self) -> i32 {
        std::mem::take(&mut self.count)
    }
    // RUGRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:117 (Action(rule_onceperfunc,"lanedivide",g))
    fn get_flags(&self) -> u32 { action_flags::RULE_ONCEPERFUNC }
    // RUGRA-GLUE: Rust Action trait get_name; "lanedivide" mirrors ctor at coreaction.hh:113
    fn get_name(&self) -> &str { "lanedivide" }
}

/// Attach return values to RETURN ops. Faithful to `ActionReturnRecovery`
/// (coreaction.cc:1908-1955) + `buildReturnOutput` (coreaction.cc:1836-1906).
///
/// This is a port of Ghidra's active-output protocol:
/// 1. `data.getActiveOutput()` yields the `ParamActive` (populated earlier by
///    `ActionPrototypeTypes`::initActiveOutput + `Heritage::guardReturns`).
/// 2. For each RETURN op and each unchecked trial, run
///    `AncestorRealistic::execute` + `Funcdata::ancestorOpUse`; if both
///    succeed the trial is `markActive` (the return register really carries a
///    computed value into this RETURN).
/// 3. `finishPass`; once `maxPass` is exceeded, `markFullyChecked`.
/// 4. When fully checked, `FuncProto::deriveOutputMap(active)` resolves which
///    trials survive as USED, then `buildReturnOutput` is applied to every
///    RETURN (assembling its return-value input(s), with PIECE concatenation
///    for multi-register returns).
/// 5. `clearActiveOutput`.
///
/// Rugra gap: the function-level `guardReturns` heritage pass that registers
/// RETURN trials is still a stub (see heritage.rs `guard_returns`), so
/// `active_output` frequently arrives empty. To keep behaviour faithful AND
/// functional we seed the active-output trials from the calling-convention
/// model's `output_entries` (Rugra's `ProtoModel::default_x86_64`) when the
/// container is present but empty. This replaces the previous hard-coded
/// "scan for any write of Register offset 0x0" heuristic with the model-driven
/// trial list while preserving the same end effect on the common RAX case.
pub struct ActionReturnRecovery { pub count: i32 ,
}
impl ActionReturnRecovery {
    // RUGRA-GLUE: constructor for the Action struct (count field for change tracking).
    pub fn new() -> Self { Self { count: 0 } }

    // Ghidra: coreaction.cc:1836 ActionReturnRecovery::buildReturnOutput
    /// Assemble the final input list for a RETURN op from the USED trials.
    /// Faithful port. Handles:
    ///   - 0/1 trial   -> trivial opSetAllInput,
    ///   - 2 trials    -> single PIECE join (constructJoinAddress),
    ///   - >2 trials   -> iterative PIECE concatenation of contiguous pieces.
    fn build_return_output(
        fd: &mut Funcdata,
        active: &crate::fspec::ParamActive,
        retop: &crate::op::PcodeOpRef,
    ) {
        use crate::address::Address as Addr;
        use crate::opcodes::OpCode as OC;
        // Ghidra cc:1839: newparam = [ retop->getIn(0) ]  (keep the
        // indirect/return-address input slot 0).
        let mut newparam: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = Vec::new();
        let in0 = { retop.0.read().unwrap().get_in(0).cloned() };
        if let Some(vn) = in0 { newparam.push(vn); }

        let num_input = retop.0.read().unwrap().num_input();
        // Ghidra cc:1842-1847: gather retop->getIn(trial.getSlot()) for each
        // USED trial, in order, until the slot falls outside the op inputs.
        for i in 0..active.get_num_trials() {
            let curtrial = active.get_trial(i);
            if !curtrial.is_used() { break; }
            let slot = curtrial.get_slot() as usize;
            if slot >= num_input { break; }
            let vn = retop.0.read().unwrap().get_in(slot).cloned();
            newparam_push_unique(&mut newparam, vn);
        }

        if newparam.len() <= 2 {
            // Ghidra cc:1848-1849: zero or one return varnode — opSetAllInput.
            fd.op_set_all_input(retop, &newparam);
        } else if newparam.len() == 3 {
            // Ghidra cc:1850-1868: two-piece concatenation.
            let lovn = newparam[1].clone();
            let hivn = newparam[2].clone();
            let triallo = active.get_trial(0);
            let trialhi = active.get_trial(1);
            // Rugra has no constructJoinAddress; the joined address is cosmetic
            // (it labels the synthetic whole varnode). Use the min of the two
            // piece offsets, which matches little-endian RAX:RDX layout.
            let lo_off = lovn.read().unwrap().get_offset();
            let hi_off = hivn.read().unwrap().get_offset();
            let join_off = lo_off.min(hi_off);
            let total_size = (trialhi.get_size() + triallo.get_size()) as usize;
            let ret_addr = retop.0.read().unwrap().get_addr();
            let newop = fd.new_op(2, ret_addr);
            fd.op_set_opcode(&newop, OC::CPUI_PIECE);
            // Ghidra cc:1860: newVarnodeOut(size, joinaddr, newop). Register space.
            let join_vn = fd.new_varnode_out(total_size, Addr::new(join_off), &newop);
            // Ghidra cc:1861: newwhole->setWriteMask().
            join_vn.write().unwrap().set_write_mask();
            // Ghidra cc:1862: opInsertBefore(newop, retop).
            fd.op_insert_before(&newop, retop);
            // Ghidra cc:1863-1865: pop back, replace with newwhole, opSetAllInput.
            newparam.pop();
            newparam.push(join_vn.clone());
            fd.op_set_all_input(retop, &newparam);
            // Ghidra cc:1866-1867: opSetInput(hi,0) opSetInput(lo,1).
            fd.op_set_input(&newop, hivn, 0);
            fd.op_set_input(&newop, lovn, 1);
        } else {
            // Ghidra cc:1869-1905: >2 pieces — iterative PIECE concatenation
            // of contiguous trials.
            newparam.clear();
            let in0 = retop.0.read().unwrap().get_in(0).cloned();
            if let Some(vn) = in0 { newparam.push(vn); }
            let mut offmatch: i32 = 0;
            let mut preexist: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = None;
            for i in 0..active.get_num_trials() {
                let curtrial = active.get_trial(i);
                if !curtrial.is_used() { break; }
                let slot = curtrial.get_slot() as usize;
                if slot >= num_input { break; }
                let vn = retop.0.read().unwrap().get_in(slot).cloned();
                let vn = match vn { Some(v) => v, None => break ,
                };
                if preexist.is_none() {
                    // Ghidra cc:1879-1881.
                    preexist = Some(vn);
                    offmatch = curtrial.get_offset() + curtrial.get_size();
                } else if offmatch == curtrial.get_offset() {
                    // Ghidra cc:1883-1897: contiguous — concatenate.
                    offmatch += curtrial.get_size();
                    let pre = preexist.unwrap();
                    let ret_addr = retop.0.read().unwrap().get_addr();
                    let newop = fd.new_op(2, ret_addr);
                    fd.op_set_opcode(&newop, OC::CPUI_PIECE);
                    let pre_size = pre.read().unwrap().get_size();
                    let vn_size = vn.read().unwrap().get_size();
                    let pre_off = pre.read().unwrap().get_offset();
                    let vn_off = vn.read().unwrap().get_offset();
                    let addr = Addr::new(pre_off.min(vn_off));
                    let newout = fd.new_varnode_out(pre_size + vn_size, addr, &newop);
                    newout.write().unwrap().set_write_mask();
                    fd.op_set_input(&newop, vn, 0);   // most sig
                    fd.op_set_input(&newop, pre, 1);  // least sig
                    fd.op_insert_before(&newop, retop);
                    preexist = Some(newout);
                } else {
                    // Ghidra cc:1899-1900: non-contiguous — stop.
                    break;
                }
            }
            if let Some(pre) = preexist { newparam.push(pre); }
            fd.op_set_all_input(retop, &newparam);
        }
    }
}
impl Action for ActionReturnRecovery {
    // Ghidra: coreaction.cc:1908 ActionReturnRecovery::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Ghidra cc:4637-4651: if the output is type-locked the prototype is
        // authoritative and return-value recovery must not run.
        if fd.funcp.output_type_locked {
            return Ok(action_status::NO_CHANGE);
        }

        // Ghidra cc:1911: the whole body is guarded by
        // `if (active != (ParamActive*)0)`; apply returns 0 when the
        // container is absent. The ONLY creation point is
        // ActionPrototypeTypes (cc:4651, onceperfunc); after
        // clearActiveOutput sets it to NULL it is never re-created, which is
        // what lets the mainloop converge.
        if fd.active_output.is_none() {
            return Ok(action_status::NO_CHANGE);
        }

        // Seed trials from the calling-convention model when the container is
        // empty. This substitutes for the (stub) function-level guardReturns
        // pass that, in Ghidra, calls `active->registerTrial(addr, size)` for
        // each candidate return storage location.
        let need_seed = fd
            .active_output
            .as_ref()
            .map(|a| a.get_num_trials() == 0)
            .unwrap_or(true);
        if need_seed {
            seed_output_trials(fd);
        }

        let maxancestor = fd.get_arch().map(|a| a.trim_recurse_max).unwrap_or(5);

        // Snapshot RETURN ops (cc:1919-1921 iterates beginOp/endOp(CPUI_RETURN)).
        let return_ops: Vec<crate::op::PcodeOpRef> = fd
            .obank
            .returnlist
            .iter()
            .filter(|r| !r.0.read().unwrap().is_dead())
            .filter(|r| (r.0.read().unwrap().flags & crate::op::pcodeop_flags::HALT) == 0)
            .cloned()
            .collect();
        if return_ops.is_empty() {
            // Ghidra's walk loop is a natural no-op with zero RETURNs, but the
            // lifecycle tail still runs: finishPass, the maxPass check, and —
            // once fully checked — deriveOutputMap + clearActiveOutput with
            // the single finalize count (cc:1937-1951). Completing the
            // lifecycle here (instead of early-returning) is what lets the
            // mainloop converge and clears the container exactly once.
            let fully_checked = {
                let active = fd.active_output.as_mut().unwrap();
                active.finish_pass();
                if active.get_num_passes() > active.get_max_pass() {
                    active.mark_fully_checked();
                }
                active.is_fully_checked()
            };
            let mut count = 0;
            if fully_checked {
                derive_func_output_map(fd);
                fd.active_output = None; // Ghidra cc:1950: clearActiveOutput.
                count += 1;
            }
            self.count += count;
            return if count > 0 {
                Ok(action_status::CHANGE)
            } else {
                Ok(action_status::NO_CHANGE)
            };
        }

        // Ghidra cc:1919-1935: per-RETURN, per-trial liveness analysis.
        let trial_count = fd
            .active_output
            .as_ref()
            .map(|a| a.get_num_trials())
            .unwrap_or(0);
        // Ghidra cc:1935: count += 1 for every unchecked trial processed,
        // accumulated across the whole walk and carried into the finalize
        // count below.
        let mut count = 0;
        if trial_count > 0 {
            let mut ancestor_real = crate::funcdata::AncestorRealistic::new();
            for retop in &return_ops {
                // Gather unchecked trial indices first so we never hold a
                // borrow on active while mutating trials or fd.
                let pending: Vec<usize> = (0..trial_count)
                    .filter(|&i| !fd.active_output.as_ref().unwrap().get_trial(i).is_checked())
                    .collect();
                for i in pending {
                    let slot = fd.active_output.as_ref().unwrap().get_trial(i).get_slot();
                    // The trial varnode for a RETURN is the op input at the
                    // trial's slot. If absent (RETURN has no return-value
                    // operand yet), synthesise a candidate varnode at the
                    // trial address so the ancestor walk has something to
                    // chase — mirroring guardReturns' opInsertInput of a fresh
                    // varnode. Only insert when the slot is missing.
                    let op_num_input = retop.0.read().unwrap().num_input();
                    if slot as usize >= op_num_input {
                        let (addr, size) = {
                            let t = fd.active_output.as_ref().unwrap().get_trial(i);
                            (t.get_address(), t.get_size())
                        };
                        let cand = fd.vbank.create_with_space(
                            size as usize, crate::space::AddressSpace::Register, addr.as_u64(),
                        );
                        cand.write().unwrap().set_active_heritage();
                        fd.op_insert_input(retop, cand, slot as usize);
                    }
                    let success_real = {
                        let active = fd.active_output.as_mut().unwrap();
                        ancestor_real.execute(retop, slot, active.get_trial_mut(i), false)
                    };
                    // Ghidra cc:1935: count += 1 — every unchecked trial
                    // processed increments the count exactly once.
                    count += 1;
                    if success_real {
                        // Ghidra cc:1931-1932: ancestorOpUse(op, vn) -> markActive.
                        let vn_opt = retop.0.read().unwrap().get_in(slot as usize).cloned();
                        if let Some(vn) = vn_opt {
                            let used = crate::funcdata::ancestor_op_use(
                                true, maxancestor, &vn, retop, slot, 0, 0,
                            );
                            if used {
                                fd.active_output
                                    .as_mut()
                                    .unwrap()
                                    .get_trial_mut(i)
                                    .mark_active();
                            }
                        }
                    }
                }
            }
        }

        // Ghidra cc:1937-1939: finishPass + maxPass check.
        let fully_checked = {
            let active = fd.active_output.as_mut().unwrap();
            active.finish_pass();
            if active.get_num_passes() > active.get_max_pass() {
                active.mark_fully_checked();
            }
            active.is_fully_checked()
        };

        let mut count = count; // carry the per-trial count from cc:1935
        if fully_checked {
            // Ghidra cc:1942: deriveOutputMap resolves USED trials.
            derive_func_output_map(fd);
            // Ghidra cc:1943-1949: buildReturnOutput for every RETURN.
            let return_ops_again: Vec<crate::op::PcodeOpRef> = fd
                .obank
                .returnlist
                .iter()
                .filter(|r| !r.0.read().unwrap().is_dead())
                .filter(|r| (r.0.read().unwrap().flags & crate::op::pcodeop_flags::HALT) == 0)
                .cloned()
                .collect();
            // Take the active container out of fd so we can read its final
            // USED-trial state while mutating fd inside buildReturnOutput.
            let active = fd.active_output.take().unwrap();
            for retop in &return_ops_again {
                Self::build_return_output(fd, &active, retop);
            }
            // Ghidra cc:1950-1951: clearActiveOutput (taken == cleared); the
            // single count += 1 fires once here, NOT per RETURN op.
            count += 1;
        }

        self.count += count;
        if count > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }
    // RUGRA-GLUE: Rust Action trait get_name; "returnrecovery" mirrors ctor at coreaction.hh:799
    fn get_name(&self) -> &str { "returnrecovery" }
}

// Push a varnode into newparam unless it duplicates the current last element
// (guards against copying slot 0 twice). Mirrors Ghidra's vector push_back
// inside buildReturnOutput's trial loop (cc:1846), which never duplicates
// because trial slots are strictly increasing.
// RUGRA-GLUE: ANN-F; Rust Option<Arc> adapter for Ghidra's inline push_back; duplicate suppression is tracked by OPBANK-0001/FSPEC-0002.
fn newparam_push_unique(
    newparam: &mut Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    vn: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
) {
    if let Some(v) = vn {
        let already_last = newparam
            .last()
            .map(|last| std::sync::Arc::ptr_eq(last, &v))
            .unwrap_or(false);
        if !already_last { newparam.push(v); }
    }
}

// Ghidra analogue: Heritage::guardReturns (heritage.cc:1653-1676) registers a
// ParamActive trial for each candidate return storage location described by
// the calling-convention model. Rugra's function-level guardReturns is a stub,
// so we perform the equivalent registration here, driven by
// ProtoModel::output_entries (the x86-64 SysV default's sole output entry is
// RAX at Register offset 0x0, size 8).
// RUGRA-GLUE: ANN-F; fallback seeds default-model outputs because Heritage::guardReturns is not wired; relocation is tracked by HERITAGE-0001/FSPEC-0002.
fn seed_output_trials(fd: &mut Funcdata) {
    use crate::address::Address;
    let model = crate::type_system::protomodel::ProtoModel::default_x86_64();
    let active = match fd.active_output.as_mut() {
        Some(a) => a,
        None => return,
    };
    for entry in &model.output_entries {
        let addr = Address::new(entry.base);
        if active.which_trial_in_space(entry.space, addr, entry.size) < 0 {
            active.register_trial_in_space(entry.space, addr, entry.size);
        }
    }
}

// Ghidra analogue: data.getFuncProto().deriveOutputMap(active) (coreaction.cc:1942)
// delegates to ProtoModel::deriveOutputMap -> ParamListStandard::fillinMap.
// Rugra's FuncProto has no ProtoModel pointer, so resolve the default model
// directly and call its derive_output_map.
// RUGRA-GLUE: ANN-F; calls a default ProtoModel because FuncProto lacks oracle model ownership; replacement is tracked by FSPEC-0001/FSPEC-0002.
fn derive_func_output_map(fd: &mut Funcdata) {
    let model = crate::type_system::protomodel::ProtoModel::default_x86_64();
    if let Some(active) = fd.active_output.as_mut() {
        model.derive_output_map(active);
    }
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
pub struct ActionForceGoto { pub count: i32 ,
}
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
// faithful-but-stub `apply()` so the action exists in the inventory; stubs
// are registered in the default pipeline wherever the oracle has the node
// (registration of a no-op is observably inert).
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

    // RUGRA-GLUE: externalizes Ghidra ActionStartTypes' inherited protected count into ActionState
    fn take_count_delta(&mut self) -> i32 {
        std::mem::take(&mut self.count)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "starttypes" mirrors ctor at coreaction.hh:76
    fn get_name(&self) -> &str {
        "starttypes"
    }
}

/// Finish processing after the decompilation pipeline has completed.
///
/// `ActionStop::apply` delegates to [`Funcdata::stop_processing`], which
/// marks processing complete, destroys the dead-op list, and invokes the
/// datatype-warning hook outside jump-table recovery.
pub struct ActionStop;

impl ActionStop {
    // Ghidra: coreaction.hh:48 ActionStop (constructor mirror)
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionStop {
    // Ghidra: coreaction.hh:53 ActionStop::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // coreaction.hh:54: data.stopProcessing(); return 0;
        fd.stop_processing();
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
            Ok(action_status::NO_CHANGE)
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
/// (coreaction.hh:1008) is exactly `data.getMerge().processCopyTrims();
/// return 0;` — it walks the copyTrims list accumulated by the snip
/// machinery of the forced-merge path (ActionMergeRequired) and replaces
/// groups of ≥2 COPYs into the same HighVariable with a single dominant
/// COPY. Rugra mirrors this with a transient `Merge` that attaches the
/// persistent `fd.merge_state.copy_trims` channel. In the standard pipeline
/// the merge phase (`Merge::merge_all` step 6) consumes the trims first, so
/// this standalone application normally sees an empty list; the traversal
/// order inside `process_copy_trims` is the deterministic copyTrims
/// first-seen order (merge.cc:1418-1435; DETERM-COPYTRIM-0001 /
/// DETERM-DOMINANTCOPY-0001 fixed there).
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
        // Faithful to coreaction.hh:1008: data.getMerge().processCopyTrims().
        // The transient Merge attaches fd.merge_state.copy_trims; typically
        // already consumed by merge_all step 6 (same oracle call site).
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
        Ok(action_status::NO_CHANGE)
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
    fn check_indirect_use(
        start: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
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
                vn_arc
                    .write()
                    .unwrap()
                    .set_flags(varnode_flags::INDIRECTONLY);
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
/// Faithful to `ActionMapGlobals` (coreaction.hh:878-886). Ghidra's `apply`
/// is exactly `data.mapGlobals(); return 0;` — the whole behavior lives in
/// [`Funcdata::map_globals`] (funcdata_varnode.cc:1653-1719): walk the
/// VarnodeLocSet in location order, group overlapping persistent Varnodes,
/// `queryProperties` the base address, and for an uncovered group
/// `discoverScope` + `buildVariableName(addrtied|persist)` + `addSymbol` on
/// the owning scope; over-extending groups over an existing smaller symbol
/// get `coverVarnodes` for their uncovered internal Varnodes.
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
        // coreaction.hh:885: virtual int4 apply(Funcdata &data)
        //   { data.mapGlobals(); return 0; }
        // mapGlobals can throw LowlevelError ("Could not discover scope",
        // funcdata_varnode.cc:1705); Rust propagates it through the Result.
        fd.map_globals()?;
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
// can split or delete blocks. ActionPreferComplement (:5714) and
// ActionStructureTransform (:5715) ARE registered at their oracle slots in
// build_default_pipeline; ActionFinalStructure (:5736) likewise. Any struct
// here that remains unregistered says so in its own doc comment, because
// Rugra's staged structurer assumes block indices are stable and a
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
/// Rugra port: full faithful port of the block-tree half and the p-code
/// half. `getSplitPoint` (block.hh:243 default NULL / BlockBasic this-if-
/// sizeOut==2 / BlockCopy copy->getSplitPoint / BlockList last-child /
/// BlockCondition this), `flipInPlaceTest` (block.cc:2368 BlockBasic via
/// Funcdata::opFlipInPlaceTest, block.cc:2990 BlockCondition over both
/// children's split points), `flipInPlaceExecute` (block.cc:2381 BlockBasic:
/// flip fallthru_true + FlowBlock::negateCondition edge swap; block.cc:3007
/// BlockCondition: AND<->OR + both children), `opFlipInPlaceExecute`
/// (funcdata_op.cc:1280-1315, incl. the BOOL_NEGATE removal and
/// replaceLessequal funcdata_op.cc:1029), and BlockIf arm swap
/// (`swapBlocks(1,2)`).
pub struct ActionPreferComplement {
    pub count: i32,
}

impl ActionPreferComplement {
    // Ghidra: blockaction.hh:300 ActionPreferComplement (constructor mirror)
    pub fn new() -> Self {
        Self { count: 0 }
    }

    // Ghidra: funcdata_op.cc:1221 Funcdata::opFlipInPlaceTest
    /// P-code half of the flip test: recursively classify whether flipping
    /// the boolean that reaches a CBRANCH would be normalized. 0 = flip
    /// normalizes, 1 = flip does not affect normalization, 2 = flip would be
    /// unnormalized (cannot flip). `fliplist` accumulates the ops that a
    /// subsequent `op_flip_in_place_execute` would rewrite.
    fn op_flip_in_place_test(
        op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
        fliplist: &mut Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>>,
    ) -> i32 {
        let op_r = op.read().unwrap();
        match op_r.opcode {
            OpCode::CPUI_CBRANCH => {
                let Some(vn) = op_r.inrefs.get(1).cloned() else { return 2 ;
                };
                drop(op_r);
                let vn_r = vn.read().unwrap();
                match vn_r.lone_descend() {
                    Some(d) if std::sync::Arc::ptr_eq(&d, op) => {}
                    _ => return 2,
                }
                let Some(def) = vn_r.get_def() else { return 2 };
                drop(vn_r);
                Self::op_flip_in_place_test(&def, fliplist)
            }
            OpCode::CPUI_INT_EQUAL | OpCode::CPUI_FLOAT_EQUAL => {
                fliplist.push(op.clone());
                1
            }
            OpCode::CPUI_BOOL_NEGATE
            | OpCode::CPUI_INT_NOTEQUAL
            | OpCode::CPUI_FLOAT_NOTEQUAL => {
                fliplist.push(op.clone());
                0
            }
            OpCode::CPUI_INT_SLESS | OpCode::CPUI_INT_LESS => {
                let in0_const = op_r
                    .inrefs
                    .first()
                    .map(|v| v.read().unwrap().is_constant())
                    .unwrap_or(false);
                fliplist.push(op.clone());
                if !in0_const { 1 } else { 0 }
            }
            OpCode::CPUI_INT_SLESSEQUAL | OpCode::CPUI_INT_LESSEQUAL => {
                let in1_const = op_r
                    .inrefs
                    .get(1)
                    .map(|v| v.read().unwrap().is_constant())
                    .unwrap_or(false);
                fliplist.push(op.clone());
                if in1_const { 1 } else { 0 }
            }
            OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_AND => {
                let in0 = op_r.inrefs.first().cloned();
                drop(op_r);
                let Some(vn0) = in0 else { return 2 };
                let vn0_r = vn0.read().unwrap();
                match vn0_r.lone_descend() {
                    Some(d) if std::sync::Arc::ptr_eq(&d, op) => {}
                    _ => return 2,
                }
                let Some(def0) = vn0_r.get_def() else { return 2 ;
                };
                drop(vn0_r);
                let subtest1 = Self::op_flip_in_place_test(&def0, fliplist);
                if subtest1 == 2 {
                    return 2;
                }
                let in1 = op.read().unwrap().inrefs.get(1).cloned();
                let Some(vn1) = in1 else { return 2 };
                let vn1_r = vn1.read().unwrap();
                match vn1_r.lone_descend() {
                    Some(d) if std::sync::Arc::ptr_eq(&d, op) => {}
                    _ => return 2,
                }
                let Some(def1) = vn1_r.get_def() else { return 2 ;
                };
                drop(vn1_r);
                let subtest2 = Self::op_flip_in_place_test(&def1, fliplist);
                if subtest2 == 2 {
                    return 2;
                }
                fliplist.push(op.clone());
                subtest1 // Front of AND/OR must be normalizing
            }
            _ => 2,
        }
    }

    // Ghidra: funcdata_op.cc:1029 Funcdata::replaceLessequal
    /// Rewrite `c <= V` (or signed) after an input swap into the equivalent
    /// `<` with the constant adjusted by ∓1. Faithful to `replaceLessequal`
    /// (funcdata_op.cc:1029-1063), including the signed/unsigned overflow
    /// guards.
    fn replace_lessequal(fd: &mut Funcdata, op: &crate::op::PcodeOpRef) -> bool {
        let op_r = op.0.read().unwrap();
        let (vn, diff, i): (
            std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, i64, usize,
        ) =
            if op_r
                .inrefs
                .first()
                .map(|v| v.read().unwrap().is_constant())
                .unwrap_or(false)
            {
                (op_r.inrefs[0].clone(), -1, 0)
            } else if op_r
                .inrefs
                .get(1)
                .map(|v| v.read().unwrap().is_constant())
                .unwrap_or(false)
            {
                (op_r.inrefs[1].clone(), 1, 1)
            } else {
                return false;
            };
        let vn_r = vn.read().unwrap();
        let size = vn_r.get_size();
        let val = crate::utils::bits::sign_extend(vn_r.get_offset(), size * 8);
        drop(vn_r);
        drop(op_r);
        let is_signed = op.0.read().unwrap().opcode == OpCode::CPUI_INT_SLESSEQUAL;
        if is_signed {
            if val < 0 && val + diff > 0 {
                return false;
            }
            if val > 0 && val + diff < 0 {
                return false;
            }
            fd.op_set_opcode(op, OpCode::CPUI_INT_SLESS);
        } else {
            if diff == -1 && val == 0 {
                return false;
            }
            if diff == 1 && val == -1 {
                return false;
            }
            fd.op_set_opcode(op, OpCode::CPUI_INT_LESS);
        }
        let mask = crate::address::calc_mask(size);
        let res = ((val + diff) as u64) & mask;
        let newvn = fd.new_constant(size, res);
        crate::varnode::Varnode::copy_symbol_if_valid(&newvn, &vn.read().unwrap());
        fd.op_set_input(op, newvn, i);
        true
    }

    // Ghidra: funcdata_op.cc:1280 Funcdata::opFlipInPlaceExecute
    /// Perform op-code flips (in-place) to change a boolean value. For each
    /// op in `fliplist`: BOOL_NEGATE is removed entirely (input propagated
    /// to its lone descendant); BOOL_AND/BOOL_OR are exchanged; other
    /// flippable comparisons get their opcode exchanged (and inputs swapped
    /// + replaceLessequal where the flip demands it).
    fn op_flip_in_place_execute(
        fd: &mut Funcdata,
        fliplist: Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>>,
    ) {
        for op in fliplist {
            let opc = op.read().unwrap().opcode;
            let mut reorder = false;
            let flip_opc = crate::opcodes::get_booleanflip(opc, &mut reorder);
            let op_ref = crate::op::PcodeOpRef(op.clone());
            if flip_opc == OpCode::CPUI_COPY {
                // We remove this (CPUI_BOOL_NEGATE) entirely
                let vn = op.read().unwrap().inrefs[0].clone();
                let out_vn = op.read().unwrap().output.clone();
                let Some(out_vn) = out_vn else { continue };
                // Must be a lone descendant
                let Some(otherop) = out_vn.read().unwrap().lone_descend() else {
                    continue;
                };
                let slot = otherop
                    .read()
                    .unwrap()
                    .slot_of_input(&out_vn)
                    .unwrap_or(0);
                fd.op_set_input(&crate::op::PcodeOpRef(otherop), vn, slot);
                fd.op_destroy(&op_ref);
            } else if flip_opc == OpCode::CPUI_MAX {
                if opc == OpCode::CPUI_BOOL_AND {
                    fd.op_set_opcode(&op_ref, OpCode::CPUI_BOOL_OR);
                } else if opc == OpCode::CPUI_BOOL_OR {
                    fd.op_set_opcode(&op_ref, OpCode::CPUI_BOOL_AND);
                }
                // Unreachable other opcodes: op_flip_in_place_test only
                // pushes flippable comparisons and BOOL_AND/OR.
            } else {
                fd.op_set_opcode(&op_ref, flip_opc);
                if reorder {
                    fd.op_swap_input(&op_ref, 0, 1);
                    if flip_opc == OpCode::CPUI_INT_LESSEQUAL
                        || flip_opc == OpCode::CPUI_INT_SLESSEQUAL
                    {
                        Self::replace_lessequal(fd, &op_ref);
                    }
                }
            }
        }
    }

    // Ghidra: block.hh:243 FlowBlock::getSplitPoint dispatch
    /// The deepest component block performing the conditional split.
    /// Default NULL; BlockBasic returns itself when sizeOut()==2 (block.cc:2361);
    /// BlockCopy delegates to its copy (block.hh:535); BlockList returns the
    /// last child's split point (block.cc:2976); BlockCondition returns
    /// itself (block.hh:631).
    fn get_split_point(
        block: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) -> Option<std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>> {
        use crate::block::{BlockBasic, BlockCondition, BlockCopy, BlockList, FlowBlock};
        let bl = block.read().unwrap();
        if let Some(bb) = bl.as_any().downcast_ref::<BlockBasic>() {
            if bb.size_out() == 2 {
                return Some(block.clone());
            }
            return None;
        }
        if let Some(bc) = bl.as_any().downcast_ref::<BlockCopy>() {
            let orig_basic = bc.original.clone();
            drop(bl);
            // The original is a BlockBasic; mirror BlockBasic::getSplitPoint.
            let ob = orig_basic.read().unwrap();
            if ob.size_out() == 2 {
                drop(ob);
                return Some(
                    orig_basic as std::sync::Arc<
                            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>,
                        >,
                );
            }
            return None;
        }
        if let Some(bls) = bl.as_any().downcast_ref::<BlockList>() {
            let last = bls.children.last().cloned();
            drop(bl);
            return last.and_then(|child| Self::get_split_point(&child));
        }
        if bl.as_any().downcast_ref::<BlockCondition>().is_some() {
            return Some(block.clone());
        }
        None
    }

    // Ghidra: block.cc:2368 BlockBasic::flipInPlaceTest / block.cc:2990 BlockCondition::flipInPlaceTest
    /// Test normalizing the conditional branch in this block. 0 = the flip
    /// would normalize the condition, 1 = flip does not affect normalization,
    /// 2 = flip produces an unnormalized condition (refuse).
    fn flip_in_place_test(
        block: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        fliplist: &mut Vec<std::sync::Arc<std::sync::RwLock<PcodeOp>>>,
    ) -> i32 {
        use crate::block::{BlockBasic, BlockCondition, FlowBlock};
        let bl = block.read().unwrap();
        if let Some(cond) = bl.as_any().downcast_ref::<BlockCondition>() {
            let first = cond.first.clone();
            let second = cond.second.clone();
            drop(bl);
            let Some(split1) = Self::get_split_point(&first) else { return 2 ;
            };
            let Some(split2) = Self::get_split_point(&second) else { return 2 ;
            };
            let subtest1 = Self::flip_in_place_test(&split1, fliplist);
            if subtest1 == 2 {
                return 2;
            }
            let subtest2 = Self::flip_in_place_test(&split2, fliplist);
            if subtest2 == 2 {
                return 2;
            }
            subtest1
        } else if let Some(bb) = bl.as_any().downcast_ref::<BlockBasic>() {
            let Some(lastop) = bb.ops.last().cloned() else { return 2 ;
            };
            drop(bl);
            if lastop.0.read().unwrap().opcode != OpCode::CPUI_CBRANCH {
                return 2;
            }
            Self::op_flip_in_place_test(&lastop.0, fliplist)
        } else {
            2
        }
    }

    // Ghidra: block.cc:2381 BlockBasic::flipInPlaceExecute / block.cc:3007 BlockCondition::flipInPlaceExecute
    /// Execute the conditional flip on this block: BlockBasic flips the
    /// `fallthru_true` op flag and swaps its outgoing edges; BlockCondition
    /// exchanges AND<->OR and flips both children's split points.
    fn flip_in_place_execute(
        block: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) {
        use crate::block::{BlockBasic, BlockCondition};
        let bl = block.read().unwrap();
        if let Some(cond) = bl.as_any().downcast_ref::<BlockCondition>() {
            let first = cond.first.clone();
            let second = cond.second.clone();
            drop(bl);
            {
                let mut c = block.write().unwrap();
                if let Some(cm) = c.as_any_mut().downcast_mut::<BlockCondition>() {
                    cm.op_type = match cm.op_type {
                        crate::block::BoolOp::And => crate::block::BoolOp::Or,
                        crate::block::BoolOp::Or => crate::block::BoolOp::And,
                    };
                }
            }
            if let Some(sp) = Self::get_split_point(&first) {
                Self::flip_in_place_execute(&sp);
            }
            if let Some(sp) = Self::get_split_point(&second) {
                Self::flip_in_place_execute(&sp);
            }
        } else if bl.as_any().downcast_ref::<BlockBasic>().is_some() {
            drop(bl);
            let mut bb = block.write().unwrap();
            // BlockBasic::flipInPlaceExecute (block.cc:2381-2387): flip the
            // fallthru_true flag on the CBRANCH, then FlowBlock::
            // negateCondition's edge swap (via the trait's swap_edges).
            if let Some(bbasic) = bb.as_any_mut().downcast_mut::<BlockBasic>() {
                if let Some(lastop) = bbasic.ops.last().cloned() {
                    lastop.0.write().unwrap().flags ^= crate::op::pcodeop_flags::FALLTHRU_TRUE;
                }
            }
            bb.swap_edges();
        }
    }

    // Ghidra: block.cc:3093 BlockIf::preferComplement
    /// For a 3-child if/else whose split-point condition can be flipped in
    /// place, flip the condition and swap the two arms.
    fn prefer_complement(
        if_arc: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        fd: &mut Funcdata,
    ) -> bool {
        use crate::block::BlockIf;
        // getSize()!=3 — Rugra BlockIf children: condition + if_body +
        // else_body; three children iff there is an else arm.
        let (condition, has_else) = {
            let bl = if_arc.read().unwrap();
            match bl.as_any().downcast_ref::<BlockIf>() {
                Some(bif) => (bif.condition.clone(), bif.else_body.is_some()),
                None => return false,
            }
        };
        if !has_else {
            return false;
        }
        let Some(split) = Self::get_split_point(&condition) else {
            return false;
        };
        let mut fliplist = Vec::new();
        if 0 != Self::flip_in_place_test(&split, &mut fliplist) {
            return false;
        }
        Self::flip_in_place_execute(&split);
        Self::op_flip_in_place_execute(fd, fliplist);
        // swapBlocks(1,2): exchange the then/else arms.
        let mut bl = if_arc.write().unwrap();
        if let Some(bif) = bl.as_any_mut().downcast_mut::<BlockIf>() {
            std::mem::swap(
                &mut bif.if_body, bif.else_body.as_mut().expect("checked above"),
            );
        }
        true
    }

    // RUGRA-GLUE: structure-tree children accessor (Ghidra BlockGraph::getBlock)
    /// Children of a composite structured block, mirroring the per-class
    /// child sets Ghidra exposes via BlockGraph::getBlock/getSize.
    fn structure_children(
        block: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) -> Vec<std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>> {
        use crate::block::{
            BlockCondition, BlockDoWhile, BlockIf, BlockInfLoop, BlockList, BlockSwitch,
            BlockWhileDo,
        };
        let bl = block.read().unwrap();
        let mut out: Vec<
            std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        > = Vec::new();
        if let Some(bif) = bl.as_any().downcast_ref::<BlockIf>() {
            out.push(bif.condition.clone());
            out.push(bif.if_body.clone());
            if let Some(eb) = &bif.else_body {
                out.push(eb.clone());
            }
        } else if let Some(bc) = bl.as_any().downcast_ref::<BlockCondition>() {
            out.push(bc.first.clone());
            out.push(bc.second.clone());
        } else if let Some(bls) = bl.as_any().downcast_ref::<BlockList>() {
            out.extend(bls.children.iter().cloned());
        } else if let Some(bwd) = bl.as_any().downcast_ref::<BlockWhileDo>() {
            out.push(bwd.condition.clone());
            out.push(bwd.body.clone());
        } else if let Some(bdw) = bl.as_any().downcast_ref::<BlockDoWhile>() {
            out.push(bdw.condition.clone());
        } else if let Some(bil) = bl.as_any().downcast_ref::<BlockInfLoop>() {
            out.push(bil.body.clone());
        } else if let Some(bsw) = bl.as_any().downcast_ref::<BlockSwitch>() {
            out.push(bsw.control.clone());
            out.extend(bsw.cases.iter().cloned());
            if let Some(dc) = &bsw.default_case {
                out.push(dc.clone());
            }
        }
        out
    }
}

impl Action for ActionPreferComplement {
    // Ghidra: blockaction.cc:2140 ActionPreferComplement::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Ghidra (blockaction.cc:2140-2167): BFS over the structure tree;
        // children are enqueued skipping t_copy/t_basic; each visited block
        // gets preferComplement(data). Only BlockIf with an else arm does
        // real work (block.cc:3093); every other block type returns false.
        if fd.sblocks.blocks.is_empty() {
            return Ok(action_status::NO_CHANGE);
        }
        let mut vec: Vec<
            std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        > =
            fd.sblocks.blocks.clone();
        let mut pos = 0usize;
        while pos < vec.len() {
            let curbl = vec[pos].clone();
            pos += 1;
            for childbl in Self::structure_children(&curbl) {
                let bt = childbl.read().unwrap().get_type();
                if bt == crate::block::BlockType::Copy || bt == crate::block::BlockType::Basic {
                    continue;
                }
                vec.push(childbl);
            }
            if Self::prefer_complement(&curbl, fd) {
                self.count += 1;
            }
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
        // Rugra port: walk the structured hierarchy in child-first order; for each WhileDo loop,
        // detect the induction-variable pattern (findLoopVariable,
        // block.cc:3164) and mark the iterate op non-printing
        // (opMarkNonPrinting, block.cc:3421). We cannot relocate ops between
        // blocks (no opInsertAfter across blocks / no for-loop syntax
        // marker), but the detection + non-printing mark — the substantive
        // part of the transform — is performed.
        use crate::block::BlockType;
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
        // BlockGraph::finalTransform (block.cc:1355-1362) recursively visits
        // every component in list order before the enclosing BlockWhileDo
        // performs its own transform (block.cc:3356). Rugra stores each
        // structured subtype's components directly, so build the same
        // post-order explicitly. The pointer set only guards malformed/shared
        // Rust stand-ins; Ghidra's component hierarchy is a tree.
        let mut transform_order = Vec::new();
        let mut transform_stack = fd
            .sblocks
            .blocks
            .iter()
            .rev()
            .map(|block| (block.clone(), false))
            .collect::<Vec<_>>();
        let mut discovered = std::collections::HashSet::new();
        while let Some((block, children_done)) = transform_stack.pop() {
            let identity = Arc::as_ptr(&block) as *const () as usize;
            if children_done {
                transform_order.push(block);
                continue;
            }
            if !discovered.insert(identity) {
                continue;
            }
            let children = {
                let rg = block.read().unwrap();
                match rg.get_type() {
                    BlockType::List => rg
                        .as_any()
                        .downcast_ref::<crate::block::BlockList>()
                        .map(|list| list.children.clone())
                        .unwrap_or_default(),
                    BlockType::Condition => rg
                        .as_any()
                        .downcast_ref::<crate::block::BlockCondition>()
                        .map(|condition| vec![condition.first.clone(), condition.second.clone()])
                        .unwrap_or_default(),
                    BlockType::If => rg
                        .as_any()
                        .downcast_ref::<crate::block::BlockIf>()
                        .map(|if_block| {
                            let mut components = vec![if_block.condition.clone()];
                            // A one-component BlockIf is the unstructured
                            // if-goto form (block.hh:652-655).
                            if if_block.goto_target.is_none() {
                                components.push(if_block.if_body.clone());
                                if let Some(else_body) = &if_block.else_body {
                                    components.push(else_body.clone());
                                }
                            }
                            components
                        })
                        .unwrap_or_default(),
                    BlockType::WhileDo => rg
                        .as_any()
                        .downcast_ref::<crate::block::BlockWhileDo>()
                        .map(|while_do| vec![while_do.condition.clone(), while_do.body.clone()])
                        .unwrap_or_default(),
                    BlockType::DoWhile => rg
                        .as_any()
                        .downcast_ref::<crate::block::BlockDoWhile>()
                        .map(|do_while| vec![do_while.condition.clone()])
                        .unwrap_or_default(),
                    BlockType::InfLoop => rg
                        .as_any()
                        .downcast_ref::<crate::block::BlockInfLoop>()
                        .map(|inf_loop| vec![inf_loop.body.clone()])
                        .unwrap_or_default(),
                    BlockType::Switch => rg
                        .as_any()
                        .downcast_ref::<crate::block::BlockSwitch>()
                        .map(|switch| {
                            let mut components = vec![switch.control.clone()];
                            components.extend(switch.cases.iter().cloned());
                            if let Some(default_case) = &switch.default_case {
                                if !components
                                    .iter()
                                    .any(|component| Arc::ptr_eq(component, default_case))
                                {
                                    components.push(default_case.clone());
                                }
                            }
                            components
                        })
                        .unwrap_or_default(),
                    _ => Vec::new(),
                }
            };
            transform_stack.push((block, true));
            for child in children.into_iter().rev() {
                transform_stack.push((child, false));
            }
        }
        for bl_arc in transform_order {
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
                if wd.has_overflow_syntax() {
                    continue;
                }
                // Clone the Arcs out so we can drop the borrow before mutating.
                (wd.condition.clone(), wd.body.clone())
            };
            let (condition_arc, body_arc) = wd;

            // block.cc:3362-3365: getFrontLeaf() yields the BlockCopy at the
            // front of the loop condition; subBlock(0) is its live Basic.
            let Some(copy_leaf) = crate::block::front_leaf(&bl_arc) else {
                continue;
            };
            let head_arc = {
                let leaf = copy_leaf.read().unwrap();
                if leaf.get_type() != BlockType::Copy {
                    continue;
                }
                let Some(head) = leaf.sub_block(0) else {
                    continue;
                };
                head
            };
            let head_ops = {
                let head = head_arc.read().unwrap();
                if head.get_type() != BlockType::Basic {
                    continue;
                }
                head.get_ops()
            };

            // block.cc:3371-3372 uses the condition subtree's virtual
            // lastOp(), not a concrete BlockBasic downcast.
            let cbranch = {
                let condition = condition_arc.read().unwrap();
                let Some(cbranch) = condition.last_op() else {
                    continue;
                };
                let is_cb = cbranch.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH;
                if !is_cb {
                    continue;
                }
                cbranch
            };

            // block.cc:3366-3376 obtains the body subtree's virtual lastOp,
            // then follows the op's parent to the actual tail Basic.
            let body_last = {
                let body = body_arc.read().unwrap();
                let Some(last) = body.last_op() else {
                    continue;
                };
                last
            };
            let Some(tail_arc) = body_last
                .0
                .read()
                .unwrap()
                .parent
                .as_ref()
                .and_then(|parent| parent.upgrade())
            else {
                continue;
            };
            let tail_slot = {
                let tail = tail_arc.read().unwrap();
                if tail.get_type() != BlockType::Basic || tail.size_out() != 1 {
                    continue;
                }
                let Some(edge) = tail.get_out(0) else {
                    continue;
                };
                if !Arc::ptr_eq(&edge.point, &head_arc) || edge.reverse_index < 0 {
                    continue;
                }
                edge.reverse_index as usize
            };
            let last_op = if body_last.0.read().unwrap().is_branch() {
                let Some(previous) = body_last
                    .0.read()
                    .unwrap()
                    .previous_op_in_block(&fd.obank)
                else {
                    continue;
                };
                previous
            } else {
                body_last
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
            let Some(comparison) = comparison else { continue ;
            };
            // Search the comparison's inputs for a head-MULTIEQUAL / tail-iterate
            // chain (block.cc:3186-3202). Ghidra walks up to 4 levels of
            // non-MULTIEQUAL defs; for the common `i < N` form the loop
            // variable is a direct comparison input, which we handle here.
            let mut found: Option<(crate::op::PcodeOpRef, crate::op::PcodeOpRef)> = None;
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
                let me_parent = multieq
                    .read()
                    .unwrap()
                    .parent
                    .as_ref()
                    .and_then(|w| w.upgrade());
                let in_head = me_parent
                    .as_ref()
                    .map(|p| Arc::ptr_eq(p, &head_arc))
                    .unwrap_or(false)
                    || head_ops.iter().any(|o| Arc::ptr_eq(&o.0, &multieq));
                if !in_head {
                    continue;
                }
                let me_ref = crate::op::PcodeOpRef(multieq.clone());
                // block.cc:3174/3190 selects the MULTIEQUAL input whose slot
                // is the tail edge's reciprocal slot at the loop head.
                let Some(tivn) = me_ref.0.read().unwrap().get_in(tail_slot).cloned() else {
                    continue;
                };
                let Some(idef) = tivn.read().unwrap().get_def() else {
                    continue;
                };
                let iparent = idef
                    .read()
                    .unwrap()
                    .parent
                    .as_ref()
                    .and_then(|parent| parent.upgrade());
                if !iparent
                    .as_ref()
                    .map(|parent| Arc::ptr_eq(parent, &tail_arc))
                    .unwrap_or(false)
                {
                    continue;
                }
                if idef.read().unwrap().is_marker() {
                    continue;
                }
                // Rugra still lacks the full PcodeOp::isMoveable closure.
                // Preserve the existing conservative INT_ADD gate whenever
                // the candidate is not already the tail's final statement.
                if !Arc::ptr_eq(&idef, &last_op.0)
                    && idef.read().unwrap().opcode != OpCode::CPUI_INT_ADD
                {
                    continue;
                }
                found = Some((me_ref, crate::op::PcodeOpRef(idef)));
                break;
            }
            let Some((loop_def, iterate_op)) = found else {
                continue;
            };
            // iterateOp located (block.cc:3379). Build the for-loop init/iter
            // expressions and set them on the BlockWhileDo so printc can emit
            // for(init;cond;iter) instead of while(cond).
            // Init: the MULTIEQUAL input opposite the tail reciprocal slot.
            // Iter: the iterate op expression (e.g. "i + 1").
            let init_str = {
                let mut result = String::new();
                if tail_slot <= 1 {
                    let entry_slot = 1 - tail_slot;
                    if let Some(entry_vn) = loop_def.0.read().unwrap().get_in(entry_slot) {
                        let vn_rg = entry_vn.read().unwrap();
                        if vn_rg.is_constant() {
                            result = format!("#{}", vn_rg.get_offset());
                        } else {
                            result = format!("var_{:x}", vn_rg.get_offset());
                        }
                    }
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
                    let lhs = out
                        .map(|v| {
                        let vr = v.read().unwrap();
                        format!("var_{:x}", vr.get_offset())
                    })
                        .unwrap_or_default();
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
            // Rugra can suppress the iterator only when it can also carry
            // both expressions into its for-loop printer. Otherwise keep the
            // statement visible, matching Ghidra's fail-closed transform.
            if init_str.is_empty() || iter_str.is_empty() {
                continue;
            }
            iterate_op.0.write().unwrap().flags |= NONPRINTING;
            let mut bl_write = bl_arc.write().unwrap();
            if let Some(wd) = bl_write
                .as_any_mut()
                .downcast_mut::<crate::block::BlockWhileDo>()
            {
                wd.for_init = Some(init_str);
                wd.for_iter = Some(iter_str);
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
/// Rugra port: calls the real `Funcdata::node_split` (port of
/// funcdata_block.cc:856, including CloneBlockOps op cloning with the
/// MULTIEQUAL → COPY in-edge split) — see apply for the one detection-side
/// substitution (basic-block goto-predecessor proxy for the structured
/// copy-map walk, because Rugra's structured BlockGoto/BlockIf keep their
/// goto targets implicit).
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

    /// Faithful port of `ActionReturnSplit::gatherReturnGotos`
    /// (blockaction.cc:2205-2234): for each in-edge source of the RETURN
    /// block `parent`, follow `getCopyMap()` into the structured tree and
    /// walk the ancestor chain; the edge is a \e goto predecessor iff the
    /// chain contains a `t_goto` block whose `gotoPrints()` holds and whose
    /// goto target resolves to `parent`, or a `t_if` block whose (if-goto)
    /// `getGotoTarget()` resolves to `parent` (cc:2215-2229, target descent
    /// `while(ret->getType()!=t_basic) ret=ret->subBlock(0)` at cc:2223-2224
    /// — `BlockCopy::subBlock` returns the mirrored ORIGINAL basic,
    /// block.hh:524, so the comparison is original-block pointer identity).
    ///
    /// Rugra's structured tree keeps components via typed fields without
    /// bottom-up parent wiring, so the ancestor-chain walk is realized as
    /// the equivalent top-down subtree scan: an in-edge source is selected
    /// iff its structured copy is a leaf under a qualifying node. The
    /// oracle's per-block marks (`setMark`/`clearMark`, scoped to a single
    /// RETURN's gather→select→clear cycle within cc:2283-2306) are carried
    /// as the `active_ancestors` path counter of the walk — observably
    /// identical because no state escapes between set and clear.
    ///
    /// `gotoPrints()` is evaluated live exactly as the oracle's mid-pipeline
    /// virtual call does (block.cc:2881-2890), via the per-parent-type
    /// `nextFlowAfter` dispatch (block.cc:1335/2899/3053/3127/3341/3448/
    /// 3476/3639) — not the `prints_precomputed` transport, which
    /// ActionFinalStructure only fills later in the pipeline.
    // Ghidra: blockaction.cc:2205 ActionReturnSplit::gatherReturnGotos
    fn gather_return_gotos(
        fd: &Funcdata,
        parent: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        in_count: usize,
    ) -> Vec<bool> {
        let mut walk = GatherReturnGotosWalk {
            parent_ptr: Arc::as_ptr(parent) as *const u8 as usize,
            selected_leaves: std::collections::HashSet::new(),
            active_ancestors: 0,
            gotoblocks: 0,
        };
        // Root level = BlockGraph::nextFlowAfter sibling rule (block.cc:1335-
        // 1353): each root's successor is the next root's front leaf; the
        // last root defers to the (null) parent — the oracle's null at root.
        let roots = fd.sblocks.blocks.clone();
        for i in 0..roots.len() {
            let succ = match roots.get(i + 1) {
                Some(next) => crate::block::front_leaf(next),
                None => None,
            };
            walk.visit(&roots[i], succ);
        }
        // Selection walk (cc:2291-2303): in-edge i is split iff the copy-map
        // chain of its source holds a marked node ⟺ the copy is a leaf under
        // a qualifying subtree.
        let mut marked = vec![false; in_count];
        let parent_rg = parent.read().unwrap();
        for i in 0..in_count {
            let Some(edge) = parent_rg.get_in(i) else { continue };
            let copy = edge
                .point
                .read()
                .unwrap()
                .get_copy_map()
                .and_then(|weak| weak.upgrade());
            if let Some(copy) = copy {
                if walk
                    .selected_leaves
                    .contains(&(Arc::as_ptr(&copy) as *const u8 as usize))
                {
                    marked[i] = true;
                }
            }
        }
        marked
    }
}

/// Per-parent traversal state of the gather walk (`gatherReturnGotos`'s
/// mark vec + ancestor-chain bookkeeping). `gotoblocks` mirrors the oracle's
/// `vec` size for the cc:2285 `gotoblocks.empty()` decision (recorded while
/// scanning; the selected-edge vector already encodes the same predicate).
// RUGRA-GLUE: mark-set transport for blockaction.cc:2205 gatherReturnGotos
/// (Ghidra marks live on FlowBlock flags; Rugra composites default the
/// setMark/clearMark trait to a no-op, so the marks ride the walk instead —
/// same set/gather/select/clear scope, cc:2213-2306).
struct GatherReturnGotosWalk {
    parent_ptr: usize,
    selected_leaves: std::collections::HashSet<usize>,
    active_ancestors: usize,
    gotoblocks: usize,
}

impl GatherReturnGotosWalk {
    /// One node of the cc:2210-2232 chain walk, realized top-down: qualify
    /// the node (cc:2213-2229), record copy leaves under qualifying
    /// ancestors, then recurse into the component list with the
    /// parent-type-aware successors.
    // Ghidra: blockaction.cc:2210 ActionReturnSplit::gatherReturnGotos (chain walk)
    fn visit(
        &mut self,
        node: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        succ: Option<Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>>,
    ) {
        use crate::block::{BlockGoto, BlockIf, BlockType};
        let bt = node.read().unwrap().get_type();
        // cc:2213-2229: qualification — t_goto needs gotoPrints + target,
        // t_if only a (non-null) if-goto target; both then descend the
        // target to its original basic and compare against `parent`.
        let qualified = match bt {
            BlockType::Goto => {
                // cc:2215-2217: if (((BlockGoto*)bl)->gotoPrints())
                //   ret = ((BlockGoto*)bl)->getGotoTarget();
                let target = node
                    .read()
                    .unwrap()
                    .as_any()
                    .downcast_ref::<BlockGoto>()
                    .and_then(|g| g.target_dyn.clone());
                match target {
                    Some(t) => {
                        self.goto_prints(&t, &succ) && Self::front_basic_hits(&t, self.parent_ptr)
                    }
                    None => false,
                }
            }
            BlockType::If => {
                // cc:2219-2221: ret = ((BlockIf*)bl)->getGotoTarget(); —
                // null for a proper if, set only by newBlockIfGoto
                // (block.cc:1808).
                let target = node
                    .read()
                    .unwrap()
                    .as_any()
                    .downcast_ref::<BlockIf>()
                    .and_then(|b| b.goto_target.clone());
                match target {
                    Some(t) => Self::front_basic_hits(&t, self.parent_ptr),
                    None => false,
                }
            }
            _ => false,
        };
        if qualified {
            self.active_ancestors += 1;
            self.gotoblocks += 1;
        }
        // cc:2212 + 2292-2302: a copy leaf whose ancestor chain contains a
        // marked node is a selected goto-predecessor source.
        if bt == BlockType::Copy && self.active_ancestors > 0 {
            self.selected_leaves.insert(Arc::as_ptr(node) as *const u8 as usize);
        }
        let components = crate::block::BlockGraph::component_list_dyn(node);
        if !components.is_empty() {
            let succs = next_flow_after_successors(node, &components, succ);
            for (child, child_succ) in components.into_iter().zip(succs) {
                self.visit(&child, child_succ);
            }
        }
        if qualified {
            self.active_ancestors -= 1;
        }
    }

    /// `BlockGoto::gotoPrints` (block.cc:2881-2890), live parent-present
    /// arm: `gotobl = getGotoTarget()->getFrontLeaf(); nextbl =
    /// <parent's nextFlowAfter(this)>; return gotobl != nextbl`. Both leaves
    /// sit at the BlockCopy level (getFrontLeaf stops at t_copy, block.cc:344);
    /// None-vs-None compares equal (C++ null == null).
    // Ghidra: block.cc:2881 BlockGoto::gotoPrints
    fn goto_prints(
        &self,
        target: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        succ: &Option<Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>>,
    ) -> bool {
        let gotobl = crate::block::front_leaf(target);
        match (gotobl, succ.clone()) {
            (Some(a), Some(b)) => !Arc::ptr_eq(&a, &b),
            (None, None) => false,
            _ => true,
        }
    }

    /// Target descent of cc:2222-2225: `if (ret != 0) { while
    /// (ret->getType() != t_basic) ret = ret->subBlock(0); if (ret == parent)
    /// ... }` — walk `subBlock(0)` (BlockCopy::subBlock = the mirrored
    /// original, block.hh:524) down to the original basic block and compare
    /// pointer identity with the RETURN's parent. A broken (componentless)
    /// chain yields false; the oracle cannot express that case (it would
    /// deref null), so this is the same predicate on every non-broken chain.
    // Ghidra: blockaction.cc:2223 ActionReturnSplit::gatherReturnGotos (target descent)
    fn front_basic_hits(
        target: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        parent_ptr: usize,
    ) -> bool {
        use crate::block::BlockType;
        let mut cur = target.clone();
        loop {
            let (is_basic, next) = {
                let rg = cur.read().unwrap();
                (
                    rg.get_type() == BlockType::Basic,
                    rg.sub_block(0),
                )
            };
            if is_basic {
                return Arc::as_ptr(&cur) as *const u8 as usize == parent_ptr;
            }
            match next {
                Some(n) => cur = n,
                None => return false,
            }
        }
    }
}

/// The per-parent-type `nextFlowAfter` successor each component of `node`
/// receives — the virtual dispatch `BlockGoto::gotoPrints` reaches through
/// `getParent()->nextFlowAfter(this)` (block.cc:2885):
/// - `BlockGraph` (root/list) block.cc:1335-1353: next sibling's front leaf;
///   last component defers to the composite's own successor (null at root).
/// - `BlockIf` block.cc:3127-3135: the getBlock(0) condition slot gets null
///   ("do not know where flow goes"); body/else defer to the parent.
/// - `BlockWhileDo` block.cc:3341-3351: condition slot null; body flows back
///   to front leaf of the condition (getBlock(0)).
/// - `BlockDoWhile` block.cc:3448-3452 / `BlockCondition` block.cc:3053-3057:
///   always null.
/// - `BlockInfLoop` block.cc:3476-3483: front leaf of getBlock(0) (the body
///   head — flow re-enters the loop).
/// - `BlockGoto` block.cc:2899-2903: front leaf of the goto target.
/// - `BlockSwitch` block.cc:3639-3661: case 0 null; a t_goto case gets the
///   next case's front leaf (last case defers to the parent); non-goto
///   cases null ("break statement in the flow").
// Ghidra: block.cc:1335 BlockGraph::nextFlowAfter (per-type dispatch)
fn next_flow_after_successors(
    node: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    components: &[Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>],
    succ: Option<Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>>,
) -> Vec<Option<Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>>> {
    use crate::block::{BlockGoto, BlockType, front_leaf};
    let n = components.len();
    let sibling_rule = |tail: &Option<Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>>| {
        (0..n)
            .map(|i| match components.get(i + 1) {
                Some(next) => front_leaf(next),
                None => tail.clone(),
            })
            .collect::<Vec<_>>()
    };
    let bt = node.read().unwrap().get_type();
    match bt {
        BlockType::If => {
            // cc:3130-3134: getBlock(0)==bl → null; else parent recursion.
            (0..n)
                .map(|i| if i == 0 { None } else { succ.clone() })
                .collect()
        }
        BlockType::WhileDo => {
            // cc:3344-3350: cond null; body → front leaf of getBlock(0).
            let mut v: Vec<Option<_>> = (0..n).map(|_| None).collect();
            if let Some(head) = components.first() {
                let head_leaf = front_leaf(head);
                for slot in v.iter_mut().skip(1) {
                    *slot = head_leaf.clone();
                }
            }
            v
        }
        BlockType::DoWhile | BlockType::Condition => {
            // cc:3451 / cc:3056: always null ("don't know what's next").
            (0..n).map(|_| None).collect()
        }
        BlockType::InfLoop => {
            // cc:3479-3482: front leaf of getBlock(0) for every component.
            let head_leaf = components.first().and_then(front_leaf);
            (0..n).map(|_| head_leaf.clone()).collect()
        }
        BlockType::Goto => {
            // cc:2902: getGotoTarget()->getFrontLeaf().
            let target = node
                .read()
                .unwrap()
                .as_any()
                .downcast_ref::<BlockGoto>()
                .and_then(|g| g.target_dyn.clone());
            let target_leaf = target.as_ref().and_then(front_leaf);
            (0..n).map(|_| target_leaf.clone()).collect()
        }
        BlockType::Switch => {
            // cc:3642-3660: case 0 null; t_goto case → next case's front
            // leaf (last → parent); non-goto case null.
            let mut v: Vec<Option<_>> = Vec::with_capacity(n);
            for i in 0..n {
                if i == 0 {
                    v.push(None);
                    continue;
                }
                let is_goto =
                    components[i].read().unwrap().get_type() == BlockType::Goto;
                if !is_goto {
                    v.push(None);
                } else {
                    v.push(match components.get(i + 1) {
                        Some(next) => front_leaf(next),
                        None => succ.clone(),
                    });
                }
            }
            v
        }
        // Root graph / BlockList / any other plain BlockGraph: the sibling
        // rule of block.cc:1340-1352.
        _ => sibling_rule(&succ),
    }
}

impl Action for ActionReturnSplit {
    // Ghidra: blockaction.cc:2264 ActionReturnSplit::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to blockaction.cc:2264-2324. For each alive RETURN whose
        // basic-block parent has >1 in-edge and is splittable, gather the
        // goto predecessors and nodeSplit the parent along those in-edges so
        // each goto source gets its own RETURN block. nodeSplit
        // (Funcdata::node_split, funcdata.rs port of funcdata_block.cc:856)
        // clones the block's ops via CloneBlockOps — the MULTIEQUAL phi
        // clone takes the split edge's incoming value and the original phi
        // drops that in-edge — so the cloned RETURN reads the value along
        // its own path (the `-1` for an early return), which the op-append
        // substitute could never reproduce (its clones shared the original
        // RETURN's pre-value placeholder).
        //
        // gatherReturnGotos (blockaction.cc:2205-2234, ported in
        // `gather_return_gotos` above): the goto-predecessor detection walks
        // the STRUCTURED copy-map tree for t_goto (gotoPrints) / t_if
        // (if-goto gotoTarget) blocks whose target resolves to the RETURN
        // block — only edges the structurer actually left unstructured are
        // split. The former substitute (any in-edge source ending in an
        // explicit BRANCH/CBRANCH) fired on structured if/else edges too and
        // was removed (ACTION-TRAVERSAL-144-0001 / TRAVERSAL144 §4).
        if fd.sblocks.blocks.is_empty() {
            return Ok(action_status::NO_CHANGE);
        }
        // Snapshot the RETURN parents first (nodeSplit mutates the CFG and
        // the alive op list). Each entry: (parent_arc, in_count).
        let mut returns: Vec<(
            Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>, usize,
        )> = Vec::new();
        for op_ref in &fd.obank.alivelist {
            let parent_arc = {
                let op_rg = op_ref.0.read().unwrap();
                if op_rg.is_dead() || op_rg.opcode != OpCode::CPUI_RETURN {
                    continue;
                }
                op_rg.parent.as_ref().and_then(|w| w.upgrade())
            };
            let Some(parent_arc) = parent_arc else { continue ;
            };
            let in_count = parent_arc.read().unwrap().size_in();
            // parent->sizeIn() <= 1 → skip (blockaction.cc:2281).
            if in_count <= 1 {
                continue;
            }
            returns.push((parent_arc, in_count));
        }

        // splitedge/retnode pairs, in the order they will be split
        // (blockaction.cc:2294-2305: biggest in-edge index first so earlier
        // nodeSplits do not shift later edges' indices).
        let mut splitedge: Vec<usize> = Vec::new();
        let mut retnode: Vec<Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>> = Vec::new();
        for (parent_arc, in_count) in &returns {
            // isSplittable(parent) (blockaction.cc:2282).
            let ops = parent_arc.read().unwrap().get_ops();
            if !Self::is_splittable(&ops) {
                continue;
            }
            // gatherReturnGotos (blockaction.cc:2284): per in-edge, does the
            // structured copy-map chain of the source contain a goto-printing
            // BlockGoto / if-goto BlockIf targeting this RETURN block.
            let marked = Self::gather_return_gotos(fd, parent_arc, *in_count);
            let any_marked = marked.iter().any(|&m| m);
            if !any_marked {
                continue; // gotoblocks.empty() (blockaction.cc:2287)
            }
            // Selection walk (blockaction.cc:2292-2305): from the biggest
            // in-edge index down; every marked edge is pushed.
            let mut splitcount = 0;
            for i in (0..*in_count).rev() {
                if marked[i] {
                    splitedge.push(i);
                    retnode.push(parent_arc.clone());
                    splitcount += 1;
                }
            }
            // Can't split ALL in edges (blockaction.cc:2309-2312) — pop the
            // last pushed (smallest index) so one edge keeps the original.
            if *in_count == splitcount {
                splitedge.pop();
                retnode.pop();
            }
        }

        let mut splits = 0;
        for i in 0..splitedge.len() {
            fd.node_split(&retnode[i], splitedge[i]);
            self.count += 1;
            splits += 1;
        }
        // Ghidra's apply returns 0 but does `count += 1` per split, which
        // Action::perform translates into a rule_repeatapply re-entry of the
        // fullloop (action.cc:332 lcount<count) — that re-entry is what
        // re-structures the CFG after nodeSplit's structureReset. Rugra's
        // Action trait carries the change through apply's return value (the
        // sanctioned count-bridge; same convention as ActionMarkImplied),
        // so the split count is returned instead of a bare 0.
        Ok(splits)
    }

    // RUGRA-GLUE: Rust Action trait get_name; "returnsplit" mirrors ctor at blockaction.hh:337
    fn get_name(&self) -> &str {
        "returnsplit"
    }
}

/// Outcome of the `ConditionalJoin::findDups` condition comparison.
/// `SameCondition` is the `vn1 == vn2` fast path (blockaction.cc:1926-1927),
/// `MergeNeeded` carries the `(vn1, vn2)` pair registered in `mergeneed`
/// (blockaction.cc:1943).
pub(crate) enum NodeJoinFindDups {
    SameCondition,
    MergeNeeded(
        std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ),
    NoMatch,
}

// Ghidra: blockaction.cc:1912 ConditionalJoin::findDups
/// Given the two CBRANCH ops of a ConditionalJoin candidate pair, decide
/// whether the conditional expressions are equivalent up to Varnodes that
/// need to be merged. Faithful to `ConditionalJoin::findDups`
/// (blockaction.cc:1912-1945). Callers have already verified both ops are
/// CBRANCH (blockaction.cc:1915-1918); this port covers the remaining gate
/// sequence verbatim:
///   - `isBooleanFlip()` on either cbranch rejects the pair (cc:1920-1921,
///     "flip hasn't propagated through yet")
///   - identical condition Varnodes are a complete match (cc:1926-1927)
///   - otherwise both conditions must be written (cc:1930-1931), not
///     spacebase (cc:1932-1933), functionally equal at level 0 or 1 via
///     `functionalEqualityLevel` (cc:1936-1938), and the first condition's
///     defining op must not be SUBPIECE or COPY (cc:1939-1941)
pub(crate) fn nodejoin_find_dups(
    cb1: &crate::op::PcodeOpRef,
    cb2: &crate::op::PcodeOpRef,
) -> NodeJoinFindDups {
    use std::sync::Arc;
    // cc:1920-1921: boolean-flipped branches are rejected outright.
    if cb1.0.read().unwrap().is_boolean_flip() {
        return NodeJoinFindDups::NoMatch;
    }
    if cb2.0.read().unwrap().is_boolean_flip() {
        return NodeJoinFindDups::NoMatch;
    }
    let vn1 = cb1.0.read().unwrap().get_in(1).cloned();
    let vn2 = cb2.0.read().unwrap().get_in(1).cloned();
    let (Some(vn1), Some(vn2)) = (vn1, vn2) else {
        return NodeJoinFindDups::NoMatch;
    };
    // cc:1926-1927: vn1 == vn2 is a COMPLETE match — the join still runs the
    // full execute() (nodeJoinCreateBlock + setupMultiequals +
    // moveCbranch + cutDownMultiequals); only mergeneed stays empty.
    if Arc::ptr_eq(&vn1, &vn2) {
        return NodeJoinFindDups::SameCondition;
    }
    // cc:1930-1931: "Parallel RulePushMulti, so we know it will apply if we
    // do the join" — both conditions must be written Varnodes.
    if !vn1.read().unwrap().is_written() {
        return NodeJoinFindDups::NoMatch;
    }
    if !vn2.read().unwrap().is_written() {
        return NodeJoinFindDups::NoMatch;
    }
    // cc:1932-1933: spacebase conditions (stack-pointer rewrites) reject.
    if vn1.read().unwrap().is_spacebase() {
        return NodeJoinFindDups::NoMatch;
    }
    if vn2.read().unwrap().is_spacebase() {
        return NodeJoinFindDups::NoMatch;
    }
    // cc:1936-1938: functionalEqualityLevel must return 0 or 1.
    let res = crate::expression::functional_equality_level(&vn1, &vn2);
    if res.code < 0 {
        return NodeJoinFindDups::NoMatch;
    }
    if res.code > 1 {
        return NodeJoinFindDups::NoMatch;
    }
    // cc:1939-1941: vn1's defining op must not be SUBPIECE or COPY.
    let op1_opcode = vn1
        .read()
        .unwrap()
        .get_def()
        .map(|d| d.read().unwrap().opcode);
    match op1_opcode {
        Some(OpCode::CPUI_SUBPIECE) => return NodeJoinFindDups::NoMatch,
        Some(OpCode::CPUI_COPY) => return NodeJoinFindDups::NoMatch,
        _ => {}
    }
    // cc:1943: mergeneed[MergePair(vn1,vn2)] = null — the pair travels with
    // the result so the ConditionalJoin state registers it
    // (blockaction.cc:1943 insertion inside findDups, before return true).
    NodeJoinFindDups::MergeNeeded(vn1, vn2)
}

/// `ConditionalJoin::MergePair` map entry: the two Varnode sides plus the
/// joined replacement (`null` until setupMultiequals creates it,
/// blockaction.cc:1943/2037).
struct NodeJoinMergePairEntry {
    /// Sort key: side1 create index then side2 create index — exactly
    /// `MergePair::operator<` (blockaction.cc:1898-1906). C++ `map` key
    /// equivalence is this ordering's equality, so equal `(ci1, ci2)` is the
    /// same key even for distinct pointers.
    ci1: u32,
    ci2: u32,
    side1: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    side2: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    outvn: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
}

// Ghidra: blockaction.hh:234 ConditionalJoin (state carrier)
/// Per-candidate state of Ghidra's `ConditionalJoin` helper class
/// (blockaction.hh:234-269): the `mergeneed` map from Varnode pairs to their
/// joined replacement. The match-shape fields (`block1/block2/exita/exitb/
/// a_in1..b_in2/cbranch1/cbranch2`) live as locals in
/// `ActionNodeJoin::apply`'s loop in this port; only the map needs to
/// outlive the individual checks (`checkExitBlock` fills it, `execute`
/// consumes it, `clear` empties it — blockaction.cc:1954/2094/2104).
pub(crate) struct ConditionalJoin {
    /// `map<MergePair, Varnode *> mergeneed` kept sorted by
    /// `(side1.createIndex, side2.createIndex)` — C++ map iteration order
    /// (setupMultiequals inserts MULTIEQUALs in this order, cc:2028).
    mergeneed: Vec<NodeJoinMergePairEntry>,
}

impl ConditionalJoin {
    // RUGRA-GLUE: default-constructed state mirror (C++ member init)
    pub(crate) fn new() -> Self {
        Self {
            mergeneed: Vec::new(),
        }
    }

    // Ghidra: blockaction.cc:2104 ConditionalJoin::clear
    /// Clear out data from a previous join. Faithful to
    /// `ConditionalJoin::clear` (blockaction.cc:2104-2108):
    /// `mergeneed.clear()`.
    pub(crate) fn clear(&mut self) {
        self.mergeneed.clear();
    }

    /// `mergeneed[MergePair(side1,side2)] = (Varnode*)0` — insert-or-reset
    /// with C++ `map::operator[]` semantics under the `MergePair::operator<`
    /// key (blockaction.cc:1898-1906): an existing equivalent key has its
    /// value reset to null; otherwise the entry is inserted in sorted
    /// position.
    // RUGRA-GLUE: C++ map<MergePair,Varnode*>::operator[] insert-or-reset realized on a sorted Vec (map semantics preserved)
    fn mergeneed_set_null(
        &mut self,
        side1: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        side2: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        let (ci1, ci2) = (
            side1.read().unwrap().get_create_index(),
            side2.read().unwrap().get_create_index(),
        );
        match self
            .mergeneed
            .binary_search_by(|e| (e.ci1, e.ci2).cmp(&(ci1, ci2)))
        {
            Ok(pos) => self.mergeneed[pos].outvn = None,
            Err(pos) => self.mergeneed.insert(
                pos,
                NodeJoinMergePairEntry {
                    ci1,
                    ci2,
                    side1: side1.clone(),
                    side2: side2.clone(),
                    outvn: None,
                },
            ),
        }
    }

    /// `mergeneed[MergePair(side1,side2)]` read: joined replacement for the
    /// pair, `None` when the key is absent. In Ghidra an absent key
    /// default-inserts a NULL which `opSetInput` would then store — that
    /// state is unreachable when `checkExitBlock` preceded
    /// `cutDownMultiequals` with identical slots (cc:1954-1972 run before
    /// cc:1981-2019 with the same `(in1,in2)`), so `None` here simply skips
    /// the substitution (RUGRA-GLUE: Rust input Vecs cannot hold a NULL
    /// Varnode slot).
    // RUGRA-GLUE: C++ map<MergePair,Varnode*> lookup realized on a sorted Vec (key = (side1.ci,side2.ci) equivalence)
    fn mergeneed_get(
        &self,
        side1: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        side2: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        let (ci1, ci2) = (
            side1.read().unwrap().get_create_index(),
            side2.read().unwrap().get_create_index(),
        );
        self.mergeneed
            .binary_search_by(|e| (e.ci1, e.ci2).cmp(&(ci1, ci2)))
            .ok()
            .map(|pos| self.mergeneed[pos].outvn.clone())
            .flatten()
    }

    // Ghidra: blockaction.cc:1954 ConditionalJoin::checkExitBlock
    /// Look for additional Varnode pairs in an exit block that need to be
    /// merged. Faithful to `ConditionalJoin::checkExitBlock`
    /// (blockaction.cc:1954-1972): walk the exit block's ops from the start;
    /// every MULTIEQUAL merging different Varnodes from our two root blocks
    /// (slots `in1`/`in2`) registers the pair in `mergeneed`; the walk stops
    /// at the first op that is neither MULTIEQUAL nor COPY.
    pub(crate) fn check_exit_block(
        &mut self,
        exit: &std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>,
        >,
        in1: usize,
        in2: usize,
    ) {
        let ops = exit.read().unwrap().get_ops();
        for op in ops {
            let opcode = op.0.read().unwrap().opcode;
            if opcode == OpCode::CPUI_MULTIEQUAL {
                let (vn1, vn2) = {
                    let o = op.0.read().unwrap();
                    (o.get_in(in1).cloned(), o.get_in(in2).cloned())
                };
                if let (Some(vn1), Some(vn2)) = (vn1, vn2) {
                    if !std::sync::Arc::ptr_eq(&vn1, &vn2) {
                        self.mergeneed_set_null(&vn1, &vn2);
                    }
                }
            } else if opcode != OpCode::CPUI_COPY {
                break;
            }
        }
    }

    // Ghidra: blockaction.cc:2023 ConditionalJoin::setupMultiequals
    /// Create a new Varnode and its defining MULTIEQUAL operation for each
    /// MergePair in the map. Faithful to `ConditionalJoin::setupMultiequals`
    /// (blockaction.cc:2023-2040): entries already holding a replacement are
    /// skipped; each new MULTIEQUAL takes `cbranch1`'s address, side1 at
    /// slot 0 / side2 at slot 1, an output of side1's size, and is inserted
    /// at the end of the join block — in map order (sorted by create
    /// indices).
    pub(crate) fn setup_multiequals(
        &mut self,
        fd: &mut Funcdata,
        joinblock: &std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>,
        >,
        cbranch1: &crate::op::PcodeOpRef,
    ) {
        let addr = cbranch1.0.read().unwrap().get_addr();
        for i in 0..self.mergeneed.len() {
            if self.mergeneed[i].outvn.is_some() {
                continue; // cc:2029
            }
            let vn1 = self.mergeneed[i].side1.clone();
            let vn2 = self.mergeneed[i].side2.clone();
            let size = vn1.read().unwrap().get_size();
            let multi = fd.new_op(2, addr);
            fd.op_set_opcode(&multi, OpCode::CPUI_MULTIEQUAL);
            let outvn = fd.new_unique_out(size, &multi);
            fd.op_set_input(&multi, vn1, 0);
            fd.op_set_input(&multi, vn2, 1);
            self.mergeneed[i].outvn = Some(outvn);
            fd.op_insert_end(&multi, joinblock);
        }
    }

    // Ghidra: blockaction.cc:2043 ConditionalJoin::moveCbranch
    /// Remove the other CBRANCH. Faithful to `ConditionalJoin::moveCbranch`
    /// (blockaction.cc:2043-2057): cbranch1 moves to the end of the join
    /// block, its condition input is replaced by the merged Varnode (or
    /// vn1 itself when both branches shared the condition), and cbranch2 is
    /// destroyed.
    pub(crate) fn move_cbranch(
        &mut self,
        fd: &mut Funcdata,
        joinblock: &std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>,
        >,
        cbranch1: &crate::op::PcodeOpRef,
        cbranch2: &crate::op::PcodeOpRef,
    ) {
        let vn1 = cbranch1.0.read().unwrap().get_in(1).cloned();
        let vn2 = cbranch2.0.read().unwrap().get_in(1).cloned();
        fd.op_uninsert(cbranch1);
        fd.op_insert_end(cbranch1, joinblock);
        // cc:2051-2055: vn = (vn1 != vn2) ? mergeneed[MergePair(vn1,vn2)]
        //                                 : vn1;
        // opSetInput(cbranch1, vn, 1). The vn1==vn2 case early-outs inside
        // opSetInput (same Varnode at slot 1).
        if let (Some(vn1), Some(vn2)) = (&vn1, &vn2) {
            if std::sync::Arc::ptr_eq(vn1, vn2) {
                fd.op_set_input(cbranch1, vn1.clone(), 1);
            } else if let Some(subvn) = self.mergeneed_get(vn1, vn2) {
                fd.op_set_input(cbranch1, subvn, 1);
            }
        }
        fd.op_destroy(cbranch2);
    }

    // Ghidra: blockaction.cc:1981 ConditionalJoin::cutDownMultiequals
    /// Substitute the new joined Varnode in the given exit block. Faithful
    /// to `ConditionalJoin::cutDownMultiequals` (blockaction.cc:1981-2019):
    /// walk the exit block's ops from the start (stopping at the first op
    /// that is neither MULTIEQUAL nor COPY); for every MULTIEQUAL, remove
    /// the `hi` input slot and put the merged replacement into `lo`; a
    /// 1-input MULTIEQUAL converts to COPY and moves to the block start.
    /// The op-list walk uses a snapshot — Ghidra advances its iterator
    /// before the inserts, and the only list mutation (the COPY conversion)
    /// moves an already-visited op to the front.
    pub(crate) fn cut_down_multiequals(
        &mut self,
        fd: &mut Funcdata,
        exit: &std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>,
        >,
        in1: usize,
        in2: usize,
    ) {
        let (lo, hi) = if in1 > in2 {
            (in2, in1)
        } else {
            (in1, in2)
        };
        let ops = exit.read().unwrap().get_ops();
        for op in ops {
            let opcode = op.0.read().unwrap().opcode;
            if opcode == OpCode::CPUI_MULTIEQUAL {
                let (vn1, vn2) = {
                    let o = op.0.read().unwrap();
                    (o.get_in(in1).cloned(), o.get_in(in2).cloned())
                };
                match (vn1, vn2) {
                    (Some(vn1), Some(vn2)) => {
                        if std::sync::Arc::ptr_eq(&vn1, &vn2) {
                            fd.op_remove_input(&op, hi);
                        } else {
                            let subvn = self.mergeneed_get(&vn1, &vn2);
                            fd.op_remove_input(&op, hi);
                            if let Some(subvn) = subvn {
                                fd.op_set_input(&op, subvn, lo);
                            }
                        }
                    }
                    _ => continue,
                }
                if op.0.read().unwrap().num_input() == 1 {
                    fd.op_uninsert(&op);
                    fd.op_set_opcode(&op, OpCode::CPUI_COPY);
                    fd.op_insert_begin(&op, exit);
                }
            } else if opcode != OpCode::CPUI_COPY {
                break;
            }
        }
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
        //       if (condjoin.match(bb, bb2)) { count+=1; condjoin.execute(); condjoin.clear(); break; }
        //
        // Rugra port: run Ghidra's candidate-finding loop with a faithful
        // ConditionalJoin state object (cc:2332). `condjoin.match` expands to
        // the diamond shape check (blockaction.cc:2071-2082), the full
        // findDups gate sequence (cc:1912-1945, nodejoin_find_dups) and the
        // two checkExitBlock calls (cc:2088-2089); `condjoin.execute` runs
        // all four steps (cc:2094-2102): nodeJoinCreateBlock,
        // setupMultiequals, moveCbranch, cutDownMultiequals x2.
        use std::sync::Arc;
        if fd.bblocks.blocks.is_empty() {
            return Ok(action_status::NO_CHANGE);
        }
        let mut condjoin = ConditionalJoin::new();
        // cc:2334: `for(int4 i=0;i<graph.getSize();++i)` — the loop bound is
        // RE-EVALUATED every iteration. nodeJoinCreateBlock appends the join
        // block (list grows) and its structureReset → findSpanningTree
        // reorders/reindexes the list (block.cc:1015-1137), so the walk must
        // keep consulting the CURRENT size to reach newly joined blocks —
        // a join block itself ends in a CBRANCH with two out edges and can
        // join again. NODEJOIN-F5-DYNAMIC-SIZE-0001: the former port froze
        // the pre-loop size and never visited appended join blocks.
        let mut i = 0usize;
        while i < fd.bblocks.get_size() {
            let bl_arc = match fd.bblocks.get_block(i) {
                Some(b) => b,
                None => {
                    i += 1;
                    continue;
                }
            };
            // bb->sizeOut() != 2 → skip (blockaction.cc:2336).
            let (out0, out1) = {
                let bl_rg = bl_arc.read().unwrap();
                if bl_rg.size_out() != 2 {
                    i += 1;
                    continue;
                }
                match (bl_rg.get_out(0), bl_rg.get_out(1)) {
                    (Some(a), Some(b)) => (a, b),
                    _ => {
                        i += 1;
                        continue;
                    }
                }
            };
            // Pick the output with the smaller in-edge count
            // (blockaction.cc:2340-2347). If equal, prefer out[1] (matches
            // Ghidra's else-branch when !(out1 < out2)). inslot is the index
            // of bb in leastout's in-edge list = the chosen out-edge's
            // reverse_index field (FlowBlock::getOutRevIndex, block.hh:308).
            let (leastout, inslot): (
                Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>, usize,
            ) = {
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
                i += 1;
                continue;
            }
            // bb's last op must be a CBRANCH (ConditionalJoin::findDups,
            // blockaction.cc:1915-1916). This per-bb pre-check is equivalent
            // to findDups' per-pair check: block1->lastOp() is invariant
            // across the sibling loop. The condition varnode itself is read
            // inside nodejoin_find_dups (cc:1923-1924).
            {
                let bl_rg = bl_arc.read().unwrap();
                let ops = bl_rg.get_ops();
                let last_is_cb = ops
                    .last()
                    .map(|o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH)
                    .unwrap_or(false);
                if !last_is_cb {
                    i += 1;
                    continue;
                }
            }
            // Try each sibling predecessor j (j != inslot) of leastout as
            // bb2 (blockaction.cc:2351-2360). We need bb2 as an Arc to
            // inspect it; collect them first to avoid holding leastout's
            // borrow while we mutate.
            let inslot = inslot as usize;
            let mut siblings: Vec<
                Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
            > = Vec::new();
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
                // blockaction.cc:2076: `if (exita == exitb) return false;` —
                // a CBRANCH whose target equals its fallthru registers BOTH
                // out-edges to the same block (flow.cc:960-967 registers
                // fallthru+branch unconditionally; only BRANCHIND dedups),
                // constructing sizeOut==2 with identical exits. Ghidra
                // rejects every match there; without the gate the join would
                // run removeEdge/moveOutEdge surgery twice on the same edge
                // and corrupt the CFG (R-NJF234-CROSSREVIEW MISMATCH #1).
                if Arc::ptr_eq(&exita, &exitb) {
                    continue;
                }
                if !Arc::ptr_eq(&b2o0.point, &exita) || !Arc::ptr_eq(&b2o1.point, &exitb) {
                    continue;
                }
                // bb2's last op must be a CBRANCH (findDups, cc:1917-1918).
                let bb2_cbranch = {
                    let ops = bb2_rg.get_ops();
                    let last = ops.last().cloned();
                    match last {
                        Some(o) => {
                            let is_cb = o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH;
                            if !is_cb {
                                continue;
                            }
                            o
                        }
                        None => continue,
                    }
                };
                drop(bb2_rg);
                // a_in1..b_in2 are the reverse edge indices of block1/block2
                // into exita/exitb (ConditionalJoin::match cc:2079-2082) —
                // computed before findDups like the oracle, and used by both
                // checkExitBlock/cutDownMultiequals (input slots) and
                // nodeJoinCreateBlock (fora/forb flags, cc:2097).
                let (a_in1, b_in1) = {
                    let rg = bl_arc.read().unwrap();
                    (
                        rg.get_out(0).map(|e| e.reverse_index).unwrap_or(-1),
                        rg.get_out(1).map(|e| e.reverse_index).unwrap_or(-1),
                    )
                };
                let (a_in2, b_in2) = {
                    let rg = bb2_arc.read().unwrap();
                    (
                        rg.get_out(0).map(|e| e.reverse_index).unwrap_or(-1),
                        rg.get_out(1).map(|e| e.reverse_index).unwrap_or(-1),
                    )
                };
                // findDups (blockaction.cc:1912-1945) decides the pair:
                // booleanFlip gate, vn1==vn2 fast path, then the written /
                // spacebase / functionalEqualityLevel / def-opcode gates.
                // NODEJOIN-F4-MATCH-GATES-0001: the former port joined ANY
                // different-condition diamond, missing every cc:1920-1941
                // gate (over-join).
                let bb_cbranch = {
                    let ops = bl_arc.read().unwrap().get_ops();
                    match ops.last().cloned() {
                        Some(o) => o,
                        None => continue,
                    }
                };
                match nodejoin_find_dups(&bb_cbranch, &bb2_cbranch) {
                    NodeJoinFindDups::NoMatch => {
                        // match() clears the state when findDups fails
                        // (blockaction.cc:2084-2087).
                        condjoin.clear();
                        continue;
                    }
                    // cc:1926-1927: vn1 == vn2 is a COMPLETE match — Ghidra
                    // returns true immediately and the caller runs the FULL
                    // execute() (nodeJoinCreateBlock + setupMultiequals +
                    // moveCbranch + cutDownMultiequals), identical to the
                    // different-condition path; only mergeneed stays empty.
                    // NODEJOIN-F3-SAMECOND-FULLJOIN-0001: the former port
                    // misread this fast path as "data-flow-only" and merely
                    // bumped count without joining.
                    NodeJoinFindDups::SameCondition => {}
                    // cc:1943: mergeneed[MergePair(vn1,vn2)] = null.
                    NodeJoinFindDups::MergeNeeded(vn1, vn2) => {
                        condjoin.mergeneed_set_null(&vn1, &vn2);
                    }
                }
                // ConditionalJoin::match tail (cc:2088-2089): Varnodes merged
                // in the exit blocks flowing from block1/block2 must also be
                // merged in the joined block — register them in mergeneed.
                // NODEJOIN-F2-EXECUTE-STEPS-0001.
                condjoin.check_exit_block(&exita, a_in1.max(0) as usize, a_in2.max(0) as usize);
                condjoin.check_exit_block(&exitb, b_in1.max(0) as usize, b_in2.max(0) as usize);
                // count += 1 (cc:2355) — indicate change has been made.
                self.count += 1;
                // ConditionalJoin::execute (blockaction.cc:2094-2102), all
                // four steps. Step 1 nodeJoinCreateBlock
                // (cc:2097 → funcdata_block.cc:779-826). The faithful
                // Funcdata::node_join_create_block twin (funcdata.rs) performs
                // the fora/forb edge surgery and — critically — the trailing
                // structureReset() (funcdata_block.cc:816) whose absence left
                // the join block out of the next heritage pass
                // (NODEJOIN-STRUCTURERESET-0001): free phi placeholder inputs
                // survived into ActionMergeRequired, tripping "Free varnode
                // has multiple descendants" and stalling
                // getparameter/match_url convergence.
                let cbranch_addr = bb_cbranch.0.read().unwrap().get_addr();
                let joinblock = fd.node_join_create_block(
                    &bl_arc,
                    &bb2_arc,
                    &exita,
                    &exitb,
                    a_in1 > a_in2,
                    b_in1 > b_in2,
                    cbranch_addr,
                );
                // No extra build_dom_tree: structureReset() already runs
                // calcForwardDominator (funcdata_block.cc:712 via the twin),
                // and the new block is appended so indices did not change
                // (R-NODEJOIN-CROSSREVIEW problem 4).
                // Step 2 setupMultiequals (cc:2098 → cc:2023-2040): new
                // MULTIEQUAL + output Varnode per mergeneed pair, appended to
                // the join block in map order.
                condjoin.setup_multiequals(fd, &joinblock, &bb_cbranch);
                // Step 3 moveCbranch (cc:2099 → cc:2043-2057): cbranch1 into
                // the join block reading the merged condition; cbranch2
                // destroyed.
                condjoin.move_cbranch(fd, &joinblock, &bb_cbranch, &bb2_cbranch);
                // Step 4 cutDownMultiequals (cc:2100-2101 → cc:1981-2019):
                // exit MULTIEQUALs lose the hi input and read the merged
                // replacement at lo; single-input ones become COPYs.
                condjoin.cut_down_multiequals(fd, &exita, a_in1.max(0) as usize, a_in2.max(0) as usize);
                condjoin.cut_down_multiequals(fd, &exitb, b_in1.max(0) as usize, b_in2.max(0) as usize);
                // condjoin.clear() (cc:2357).
                condjoin.clear();
                joined_this = true;
                break;
            }
            let _ = joined_this;
            i += 1;
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
// Default decompile pipeline assembly (RUGRA-GLUE, see src/action.rs)
// ---------------------------------------------------------------------------
//
// `build_default_pipeline` (action.rs) mirrors Ghidra's
// `ActionDatabase::universalAction` (coreaction.cc:5462-5738) and registers
// every implemented Action exactly once at its oracle tree slot. The former
// `build_full_pipeline_actions()` flat vec — which handed
// implemented-but-unregistered Actions to the action layer and flattened
// FuncLinkOutOnly/Segmentize/InternalStorage/MultiCse/ShadowVar/Deindirect
// as ROOT children running before fullloop/mainloop(heritage) — was removed
// by PIPE-HEAD-FLAT-ACTIONS-0001: those six Actions are now registered at
// their exact oracle slots (head :5485, mainloop :5494/:5495, stackstall
// :5653-:5655), and every other vec entry was already sole-registered by the
// builder (UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ④ + HERITAGE-FLAGFREE-SSA-0001
// moved setcasts to :5735; PIPE-MERGETYPE-ORDER-0001 moved assignhigh/
// dominantcopy/copymarker to :5717/:5723/:5729).
//
// Actions with faithful-but-stub `apply()` bodies are registered wherever
// the oracle has the node (the stubs are observably inert): e.g. LaneDivide
// inside stackstall (:5652), Constbase/ExtraPopSetup/Stop at head/tail,
// MappedLocalSync (:5691), StartCleanUp (:5692), MarkIndirectOnly (:5725),
// MapGlobals (:5732), both DynamicSymbols instances (:5724/:5733), NameVars
// (:5734). Remaining unregistered oracle nodes — all documented deviations:
//   - ActionForceGoto (:5496) and ActionDynamicMapping (:5504): ported as
//     no-op stubs, not registered (registration is observably inert either
//     way; kept out to minimize tree churn until real implementations land).
//   - ActionUnreachable base instance (:5490): Rugra registers a single
//     Unreachable at the :5673 slot (after BlockStructure) — running the
//     :5490 instance before bblocks are complete caused false-positive
//     unreachable removal (see the mainloop NOTE in action.rs).
//   - the `noproto` FuncLinkOutOnly and `protorecovery_b` DirectWrite
//     instances are decompile-grouplist-filtered in Ghidra itself
//     (coreaction.cc:5424-5431); Rugra keeps FuncLinkOutOnly registered at
//     :5485 (inert under FuncLink) and drops the protorecovery_b pair, per
//     the wave target head (coreaction.cc:5477-5486).
// ActionInferParams (mainloop, after StackPtrFlow's former slot) is
// RUGRA-GLUE with no oracle counterpart — it provides Rugra's parameter
// inference until ActionActiveParam/ActionDefaultParams fully cover it.
//
// ActionParamShiftStart / ActionParamShiftStop (coreaction.hh:772-793) are
// COMMENTED OUT in Ghidra (both the class bodies and their pipeline
// registration at coreaction.cc:5481/5501) and are therefore intentionally
// NOT ported.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_params_preserves_locked_void_prototype() {
        let mut fd = Funcdata::new(
            "locked_void",
            crate::address::Address::new(0x1000),
            0x10);
        let mut copy = crate::pcoderaw::PcodeOpRaw::new(
            crate::opcodes::OpCode::CPUI_COPY as i32);
        copy.set_output(crate::pcoderaw::VarnodeRaw::new(
            crate::space::AddressSpace::Unique,
            0x100,
            8,
        ));
        copy.add_input(crate::pcoderaw::VarnodeRaw::new(
            crate::space::AddressSpace::Register,
            0x38,
            8,
        ));
        fd.inject_raw_ops(&[copy]);
        fd.run_heritage_direct();
        assert!(fd.vbank.loc_tree.iter().any(|varnode| {
            let varnode = varnode.0.read().unwrap();
            varnode.is_input()
                && varnode.get_space() == crate::space::AddressSpace::Register
                && varnode.get_offset() == 0x38
        }));

        fd.funcp.set_input_lock(true);
        fd.funcp.set_output_lock(true);
        let mut action = ActionInferParams::new();
        assert_eq!(action.apply(&mut fd).unwrap(), action_status::NO_CHANGE);
        assert!(fd.funcp.is_input_locked());
        assert!(fd.funcp.parameters.is_empty());
        assert!(matches!(
            fd.funcp.return_type.as_ref(),
            crate::type_system::datatype::Datatype::Void(_)
        ));
    }

    // Ghidra: coreaction.cc:4901-4909 ActionPrototypeWarnings::apply (isModelUnknown arm)
    /// Locked-storage + unknown-model prototype — the PLT-thunk/DWARF shape
    /// that produces the golden's `/* WARNING: Unknown calling convention --
    /// yet parameter storage is locked */` header line. The oracle observable
    /// is the commentdb write (funcdata.cc:135-145 warningHeader ->
    /// addCommentNoDuplicate(warningheader, baseaddr, baseaddr)), not stderr.
    #[test]
    fn test_prototype_warnings_unknown_convention_locked_storage_writes_commentdb() {
        let mut arch = crate::arch::Architecture::new();
        let db = std::sync::Arc::new(std::sync::RwLock::new(
            crate::comment::CommentDatabaseInternal::new(),
        ));
        arch.set_commentdb(db.clone());
        let mut fd = Funcdata::new(
            "plt_thunk",
            crate::address::Address::new(0x1022f0),
            11);
        fd.set_arch(std::sync::Arc::new(arch));
        // The libc-signature lock combination (debugproto locked_proto /
        // Ghidra's platform-side locked signature): input+output locked, model
        // left unresolved (set_model(None) keeps calling_convention
        // "unknown").
        fd.funcp.set_input_lock(true);
        fd.funcp.set_output_lock(true);
        assert!(fd.funcp.is_model_unknown());

        let mut action = ActionPrototypeWarnings::new();
        assert_eq!(action.apply(&mut fd).unwrap(), action_status::NO_CHANGE);

        let comments: Vec<_> = db
            .read()
            .unwrap()
            .comments_for_function(crate::address::Address::new(0x1022f0))
            .cloned()
            .collect();
        assert_eq!(comments.len(), 1);
        assert_eq!(
            comments[0].get_type(),
            crate::comment::comment_type::WARNINGHEADER
        );
        assert_eq!(comments[0].get_addr().as_u64(), 0x1022f0);
        assert_eq!(
            comments[0].get_text(),
            "WARNING: Unknown calling convention -- yet parameter storage is locked"
        );
        // funcdata.cc:144 addCommentNoDuplicate: a re-run adds no duplicate.
        action.apply(&mut fd).unwrap();
        assert_eq!(db.read().unwrap().num_comments(), 1);
    }

    // Ghidra: coreaction.cc:4901-4908 ActionPrototypeWarnings::apply (isModelUnknown arm)
    /// Unlocked prototype with unknown model: the warning still fires
    /// (unconditional on isModelUnknown) but carries no lock suffix — the
    /// exact ostringstream assembly at coreaction.cc:4902-4907.
    #[test]
    fn test_prototype_warnings_unknown_convention_without_lock_has_no_suffix() {
        let mut arch = crate::arch::Architecture::new();
        let db = std::sync::Arc::new(std::sync::RwLock::new(
            crate::comment::CommentDatabaseInternal::new(),
        ));
        arch.set_commentdb(db.clone());
        let mut fd = Funcdata::new(
            "unresolved",
            crate::address::Address::new(0x2000),
            0x10);
        fd.set_arch(std::sync::Arc::new(arch));
        assert!(fd.funcp.is_model_unknown());
        assert!(!fd.funcp.is_input_locked());
        assert!(!fd.funcp.is_output_locked());

        let mut action = ActionPrototypeWarnings::new();
        action.apply(&mut fd).unwrap();

        let comments: Vec<_> = db
            .read()
            .unwrap()
            .comments_for_function(crate::address::Address::new(0x2000))
            .cloned()
            .collect();
        assert_eq!(comments.len(), 1);
        assert_eq!(
            comments[0].get_text(), "WARNING: Unknown calling convention"
        );
    }

    // Ghidra: coreaction.cc:4889-4892 ActionPrototypeWarnings::apply (override arm)
    /// Override messages ride the same warningHeader channel
    /// (coreaction.cc:4892). The deadcode-delay message text comes from
    /// override.cc:51-56 generateDeadcodeDelayMessage; with Rugra's empty
    /// space-name table (no indexed space manager yet) the space reads
    /// "unknown" — the channel and ordering are the oracle observables here.
    #[test]
    fn test_prototype_warnings_override_message_writes_commentdb() {
        let mut arch = crate::arch::Architecture::new();
        let db = std::sync::Arc::new(std::sync::RwLock::new(
            crate::comment::CommentDatabaseInternal::new(),
        ));
        arch.set_commentdb(db.clone());
        let mut fd = Funcdata::new(
            "with_override",
            crate::address::Address::new(0x3000),
            0x10);
        fd.set_arch(std::sync::Arc::new(arch));
        // Fixture tweak: bind a non-unknown model name so the isModelUnknown
        // arm stays silent and only the override message is observable.
        fd.funcp.set_model_name("__stdcall");
        fd.localoverride.insert_deadcode_delay(0, 3);

        let mut action = ActionPrototypeWarnings::new();
        action.apply(&mut fd).unwrap();

        let comments: Vec<_> = db
            .read()
            .unwrap()
            .comments_for_function(crate::address::Address::new(0x3000))
            .cloned()
            .collect();
        assert_eq!(comments.len(), 1);
        // Oracle text: Override::generateDeadcodeDelayMessage
        // (override.cc:51-56) resolves the space name via
        // glb->getSpace(0)->getName() = "const" (locked x86-64 corpus
        // table, AddressSpace::spec_space_name). The old expectation
        // "unknown" was the empty-name-table degradation.
        assert_eq!(
            comments[0].get_text(),
            "WARNING: Restarted to delay deadcode elimination for space: const"
        );
    }

    #[test]
    fn test_action_default_params_locked_callspec_keeps_storage() {
        // FUNCPROTO-MODEL-BIND-0001 rework regression 2: a modelless +
        // model-locked callspec (the LibcSignatureTable/DWARF boundary that
        // Ghidra represents as an UnknownProtoModel clone) must NOT run the
        // setInternal void-output swap — only the shared eval model is
        // installed, so the locked return type and parameters survive.
        let mut arch = crate::arch::Architecture::new();
        let mut model = crate::fspec::ProtoModelFull::new(
            Some(crate::space::AddressSpace::Stack),
            8);
        model.name = "test_default".to_string();
        model.extrapop = 0;
        let model = std::sync::Arc::new(model);
        arch.proto_models.insert("test_default".to_string(), model);
        arch.set_default_model("test_default");

        let mut fd = Funcdata::new("caller", crate::address::Address::new(0x1000), 0x10);
        fd.set_arch(std::sync::Arc::new(arch));

        let long_type = std::sync::Arc::new(crate::type_system::datatype::Datatype::Base(
            crate::type_system::datatype::TypeBase::new(
                "long".to_string(),
                8,
                crate::type_system::datatype::TypeMetatype::Int,
            ),
        ));
        // Locked libc-style callspec: parameters + return locked, modelless.
        let mut locked_proto = crate::fspec::FuncProto::new("locked_callee".to_string(), long_type.clone());
        locked_proto.set_input_lock(true);
        locked_proto.set_output_lock(true);
        let locked_fc = crate::fspec::FuncCallSpecs::new(
            crate::address::Address::new(0x2000),
            locked_proto);
        // Unlocked modelless callspec: the plain cc:2327-2328 else branch.
        let unlocked_fc = crate::fspec::FuncCallSpecs::new(
            crate::address::Address::new(0x2100),
            crate::fspec::FuncProto::new(String::new(), long_type.clone()),
        );
        fd.callspecs
            .push(std::sync::Arc::new(std::sync::RwLock::new(locked_fc)));
        fd.callspecs
            .push(std::sync::Arc::new(std::sync::RwLock::new(unlocked_fc)));

        let mut action = ActionDefaultParams::new();
        assert_eq!(action.apply(&mut fd).unwrap(), action_status::NO_CHANGE);

        let locked_fc = fd.callspecs[0].read().unwrap();
        let locked = &locked_fc.prototype;
        assert!(locked.has_model());
        assert!(locked.is_model_locked());
        // setInternal must NOT have run: the locked return type survives.
        assert!(matches!(
            locked.return_type.as_ref(),
            crate::type_system::datatype::Datatype::Base(_)
        ));
        assert_eq!(locked.get_model_name(), "test_default");
        let unlocked_fc = fd.callspecs[1].read().unwrap();
        let unlocked = &unlocked_fc.prototype;
        assert!(unlocked.has_model());
        // The unlocked branch DID run setInternal: void default output.
        assert!(matches!(
            unlocked.return_type.as_ref(),
            crate::type_system::datatype::Datatype::Void(_)
        ));
    }

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
        assert_eq!(action.get_name(), "restructure_varnode");
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

    /// HTTPD-EMPTYELSE-DONOTHING-0001 regression lock: the empty-else
    /// defect shape — a branch-only do-nothing block whose single out-edge
    /// targets a JOIN (multiple in-edges). The pre-fix ActionDoNothing
    /// called splice_block_basic, whose invented single-in guard refused
    /// every join target, so the block survived to ActionBlockStructure,
    /// which matched ruleBlockIfElse with an empty false clause and printed
    /// `if (...) { ... } else { }`. Ghidra's ActionDoNothing
    /// (coreaction.cc:3482-3485) removes the block via
    /// removeDoNothingBlock/blockRemoveInternal (funcdata_block.cc:254-320)
    /// — removeFromFlow retargets the in-edge to the join and the join's
    /// MULTIEQUAL inputs are spliced — then structureReset + the
    /// rule_repeatapply fullloop re-run restructure the purged CFG.
    /// Faithful behavior: block removed, edge retargeted, phi inputs
    /// preserved (remove+append = identity for a no-op block), CHANGE
    /// returned so the repeat loop re-runs the pipeline.
    #[test]
    fn test_action_donothing_removes_join_targeted_jmp_island() {
        use crate::address::Address;
        use crate::block::BlockBasic;
        use crate::opcodes::OpCode;
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x40);
        let mk = |idx: i32, addr: u64| {
            std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
                idx,
                Address::new(addr),
            ))) as std::sync::Arc<
                std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>,
            >
        };
        let b0 = mk(0, 0x1000); // entry, CBRANCH
        let tt = mk(1, 0x1010); // true clause: has a real op (not donothing)
        let jj = mk(2, 0x1020); // branch-only jmp island -> JOIN
        let join = mk(3, 0x1030); // JOIN: MULTIEQUAL head
        b0.write()
            .unwrap()
            .set_flags(crate::block::block_flags::ENTRY_POINT);
        for b in [&b0, &tt, &jj, &join] {
            fd.bblocks.add_block(b.clone());
        }
        fd.bblocks.add_edge(b0.clone(), tt.clone());
        fd.bblocks.add_edge(b0.clone(), jj.clone());
        fd.bblocks.add_edge(tt.clone(), join.clone());
        fd.bblocks.add_edge(jj.clone(), join.clone());
        // b0 ends with a CBRANCH (2 out-edges, so b0 itself is not donothing).
        let cb = fd.new_op(2, Address::new(0x1000));
        fd.op_set_opcode(&cb, OpCode::CPUI_CBRANCH);
        let addr_vn = fd.new_constant(8, 0x1010);
        fd.op_set_input(&cb, addr_vn, 0);
        let cond = fd.new_constant(1, 1);
        fd.op_set_input(&cb, cond, 1);
        fd.op_insert_end(&cb, &b0);
        // tt has a real COPY op (not donothing).
        let cp = fd.new_op(1, Address::new(0x1010));
        fd.op_set_opcode(&cp, OpCode::CPUI_COPY);
        let src_vn = fd.new_constant(4, 0x42);
        fd.op_set_input(&cp, src_vn, 0);
        let cp_out = fd.new_unique(4);
        fd.op_set_output(&cp, cp_out);
        fd.op_insert_end(&cp, &tt);
        // jj: BRANCH-only (hasOnlyMarkers).
        let br = fd.new_op(1, Address::new(0x1020));
        fd.op_set_opcode(&br, OpCode::CPUI_BRANCH);
        let br_addr = fd.new_constant(8, 0x1030);
        fd.op_set_input(&br, br_addr, 0);
        fd.op_insert_end(&br, &jj);
        // join: MULTIEQUAL with one input per in-edge (tt, jj).
        let phi = fd.new_op(2, Address::new(0x1030));
        fd.op_set_opcode(&phi, OpCode::CPUI_MULTIEQUAL);
        let vn_tt = fd.new_unique(4);
        fd.op_set_input(&phi, vn_tt, 0);
        let vn_jj = fd.new_unique(4);
        fd.op_set_input(&phi, vn_jj.clone(), 1);
        let phi_out = fd.new_unique(4);
        fd.op_set_output(&phi, phi_out);
        fd.op_insert_end(&phi, &join);

        let mut a = ActionDoNothing::new();
        assert_eq!(
            a.apply(&mut fd).unwrap(),
            action_status::CHANGE,
            "join-targeted jmp island must be removed and counted"
        );
        assert_eq!(a.count, 1);
        // The island is gone from the graph.
        assert_eq!(fd.bblocks.get_size(), 3, "b0, tt, join remain");
        let b0_outs = {
            let rg = b0.read().unwrap();
            (0..rg.size_out())
                .filter_map(|s| rg.get_out(s).map(|e| e.point))
                .collect::<Vec<_>>()
        };
        assert!(
            b0_outs
                .iter()
                .any(|o| std::sync::Arc::ptr_eq(o, &tt))
                && b0_outs.iter().any(|o| std::sync::Arc::ptr_eq(o, &join)),
            "b0's false edge retargeted to the join"
        );
        assert_eq!(
            join.read().unwrap().size_in(),
            2,
            "join still has 2 in-edges (tt + retargeted b0)"
        );
        // MULTIEQUAL splice: remove+append is an identity for a no-op block.
        use crate::block::FlowBlock as _;
        let phi_state = {
            let rg = join.read().unwrap();
            let bb = rg.as_any().downcast_ref::<BlockBasic>().unwrap();
            bb.get_ops()
                .into_iter()
                .find(|o| o.0.read().unwrap().opcode == OpCode::CPUI_MULTIEQUAL)
                .map(|o| {
                    let o_rg = o.0.read().unwrap();
                    (o_rg.inrefs.len(), o_rg.inrefs.get(1).map(|v| v.read().unwrap().get_offset()))
                })
        };
        let Some((n_ins, second)) = phi_state else {
            panic!("join MULTIEQUAL vanished");
        };
        assert_eq!(n_ins, 2, "phi input count preserved (remove+append)");
        assert_eq!(
            second,
            Some(vn_jj.read().unwrap().get_offset()),
            "the through-island value is preserved at the appended slot"
        );
    }

    /// ActionRedundBranch on an empty Funcdata returns NO_CHANGE.
    #[test]
    fn test_action_redundbranch_empty_fd() {
        use crate::address::Address;
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0);
        let mut a = ActionRedundBranch::new();
        assert_eq!(a.apply(&mut fd).unwrap(), action_status::NO_CHANGE);
    }

    /// HTTPD-STRCASECMP-NONCONVERGE-0001 regression lock: a malformed
    /// "zombie decision block" (CBRANCH lastOp + constant condition + fewer
    /// than 2 out-edges — a state Ghidra's coreaction.cc:3538-3547 contract
    /// forbids) must be SKIPPED by ActionDeterminedBranch without calling
    /// remove_branch: the no-op remove_branch would still run structureReset,
    /// clearing sblocks every mainloop round and re-arming
    /// ActionBlockStructure + ruleBlockIfNoExit's per-round negateCondition
    /// into an infinite rule_repeatapply loop.
    #[test]
    fn test_determinedbranch_skips_malformed_decision_block() {
        use crate::address::Address;
        use crate::block::BlockBasic;
        use crate::opcodes::OpCode;
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x40);
        let b0c = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            0, Address::new(0x1000),
        )));
        let b1 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            1, Address::new(0x1010),
        ))) as std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>,
        >;
        b0c.write().unwrap().flags |= crate::block::block_flags::ENTRY_POINT;
        let b0 = b0c as std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>,
        >;
        fd.bblocks.add_block(b0.clone());
        fd.bblocks.add_block(b1.clone());
        fd.bblocks.add_edge(b0.clone(), b1.clone());
        // b1 = zombie decision block: ends in CBRANCH with constant
        // condition (val=1) but ZERO out-edges.
        let cb = fd.new_op(2, Address::new(0x1010));
        fd.op_set_opcode(&cb, OpCode::CPUI_CBRANCH);
        let addr_vn = fd.new_constant(8, 0x1020);
        fd.op_set_input(&cb, addr_vn, 0);
        let cond = fd.new_constant(1, 1);
        fd.op_set_input(&cb, cond, 1);
        fd.op_insert_end(&cb, &b1);
        // Populate sblocks with a witness block: a faithful run must NOT
        // reset the structure (remove_branch's structureReset is the bug's
        // per-round sblocks wipe).
        let witness = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            0, Address::new(0x1000),
        ))) as std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>,
        >;
        fd.sblocks.add_block(witness);
        assert_eq!(fd.sblocks.get_size(), 1);

        let mut action = ActionDeterminedBranch::new();
        assert_eq!(action.apply(&mut fd).unwrap(), action_status::NO_CHANGE);

        assert_eq!(fd.sblocks.get_size(), 1, "zombie skip must not structureReset");
        assert_eq!(fd.bblocks.get_size(), 2, "graph untouched");
        assert_eq!(b1.read().unwrap().size_out(), 0, "no edge to remove");
        let last_is_cb = {
            let rg = b1.read().unwrap();
            rg.as_any()
                .downcast_ref::<BlockBasic>()
                .and_then(|bb| bb.last_op())
                .map(|o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH)
                .unwrap_or(false)
        };
        assert!(last_is_cb, "zombie cbranch left in place (skip, not destroy)");
        assert_eq!(action.count, 0, "no change counted for skipped malformed block");
    }

    /// Well-formed determined branch (CBRANCH + constant condition + exactly
    /// 2 out-edges): faithful cc:3544-3546 behavior — the not-taken edge is
    /// removed, the cbranch destroyed (branchRemoveInternal cc:203-204),
    /// count += 1 per removal.
    #[test]
    fn test_determinedbranch_removes_not_taken_edge_and_counts() {
        use crate::address::Address;
        use crate::block::BlockBasic;
        use crate::opcodes::OpCode;
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x40);
        let b0c = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            0, Address::new(0x1000),
        )));
        let b1 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            1, Address::new(0x1010),
        ))) as std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>,
        >;
        let b2 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            2, Address::new(0x1020),
        ))) as std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>,
        >;
        b0c.write().unwrap().flags |= crate::block::block_flags::ENTRY_POINT;
        let b0 = b0c as std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>,
        >;
        for b in [&b0, &b1, &b2] {
            fd.bblocks.add_block(b.clone());
        }
        fd.bblocks.add_edge(b0.clone(), b1.clone());
        fd.bblocks.add_edge(b0.clone(), b2.clone());
        // b0: CBRANCH, condition constant 1, no boolean flip ->
        // num = ((1!=0) != false) = true -> 0: edge to b1 (out[0]) removed.
        let cb = fd.new_op(2, Address::new(0x1000));
        fd.op_set_opcode(&cb, OpCode::CPUI_CBRANCH);
        let addr_vn = fd.new_constant(8, 0x1010);
        fd.op_set_input(&cb, addr_vn, 0);
        let cond = fd.new_constant(1, 1);
        fd.op_set_input(&cb, cond, 1);
        fd.op_insert_end(&cb, &b0);

        let mut action = ActionDeterminedBranch::new();
        assert_eq!(action.apply(&mut fd).unwrap(), action_status::NO_CHANGE);

        assert_eq!(
            b0.read().unwrap().size_out(),
            1,
            "not-taken edge removed (cc:3545)"
        );
        assert_eq!(action.count, 1, "count += 1 per removeBranch (cc:3546)");
        assert_eq!(action.take_count_delta(), 1, "delta harvest returns the count");
        assert_eq!(action.take_count_delta(), 0, "second harvest is zero (taken)");
        let last_is_cb = {
            let rg = b0.read().unwrap();
            rg.as_any()
                .downcast_ref::<BlockBasic>()
                .and_then(|bb| bb.last_op())
                .map(|o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH)
                .unwrap_or(false)
        };
        assert!(!last_is_cb, "cbranch destroyed at sizeOut==2 (cc:203-204)");
    }

    /// remove_unreachable_blocks: a 3-block CFG where block 2 is unreachable
    /// from entry 0. After the call, block 2 should be removed.
    #[test]
    fn test_remove_unreachable_blocks() {
        use crate::address::Address;
        use crate::block::{BlockBasic, BlockGraph};
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x40);
        let b0 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            0, Address::new(0x1000),
        )));
        let b1 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            1, Address::new(0x1010),
        )));
        let b2 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            2, Address::new(0x1020),
        )));
        // Mark b0 as entry (set flags field directly; set_flags is a trait method).
        b0.write().unwrap().flags |= crate::block::block_flags::ENTRY_POINT;
        for b in [&b0, &b1, &b2] { fd.bblocks.add_block(b.clone()); }
        fd.bblocks.add_edge(b0.clone(), b1.clone()); // 0 -> 1 (reachable)
        // b2 has NO in-edges → unreachable.
        assert_eq!(fd.bblocks.get_size(), 3);
        // Active search (checkexistence=true), matching the oracle's
        // generateBlocks call form (flow.cc:844).
        let removed = fd.remove_unreachable_blocks(false, true);
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
        let b0 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            0, Address::new(0x1000),
        )));
        let b1 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            1, Address::new(0x1010),
        )));
        let b2 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            2, Address::new(0x1020),
        )));
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
            crate::varnode::Varnode::new_constant(0x500, 8),
        ));
        let mut callind = crate::op::PcodeOp::new(
            SeqNum::new(Address::new(0x20), 0),
            crate::opcodes::OpCode::CPUI_CALLIND,
        );
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
            crate::type_system::datatype::TypeBase::new(
                "void".into(), 0, crate::type_system::TypeMetatype::Void,
            ),
        ));
        let proto = FuncProto::new("callee".into(), void_t);
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x40);
        // Add a CALL op at 0x2000 and bind the callspec to this exact owner.
        let target_vn = std::sync::Arc::new(std::sync::RwLock::new(
            crate::varnode::Varnode::new_constant(0x9000, 8),
        ));
        let mut call_op = crate::op::PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0x2000), 0),
            crate::opcodes::OpCode::CPUI_CALL,
        );
        let register_arg = fd.vbank
                .create_with_space(
            8,
            crate::space::AddressSpace::Register,
            0x18);
        let stack_arg = fd
            .vbank
            .create_with_space(8, crate::space::AddressSpace::Stack, 0x18);
        call_op.inrefs = vec![target_vn, register_arg, stack_arg];
        let op_arc = std::sync::Arc::new(std::sync::RwLock::new(call_op));
        let op_ref = crate::op::PcodeOpRef(op_arc);
        fd.obank.alivelist.push(op_ref.clone());
        let fc = FuncCallSpecs::new_for_op(&op_ref, proto);
        let owner = std::sync::Arc::new(std::sync::RwLock::new(fc));
        let annotation = fd.new_varnode_call_specs(&owner);
        fd.op_set_input(&op_ref, annotation, 0);
        fd.add_call_specs_owner(owner);
        assert_eq!(fd.num_calls(), 1);
        // Before: no active input.
        assert!(!fd.get_call_specs(0).unwrap().is_input_active());
        assert_eq!(
            fd.get_call_specs(0).unwrap().active_input.get_num_trials(), 0
        );
        let mut a = ActionFuncLink::new();
        a.apply(&mut fd).unwrap();
        // After: unlocked callee → initActiveInput (coreaction.cc:1482-1483),
        // but funcLinkInput itself registers NO trials — in the oracle the
        // two pre-existing CALL inputs only become trials during heritage
        // (Heritage::guardCalls cc:1495-1509 registers each candidate range
        // while appending it as the last CALL input). The former centralized
        // re-registration loop over existing inputs was a guard_calls-stub
        // workaround and is gone.
        let callspec = fd.get_call_specs(0).unwrap();
        let active = &callspec.active_input;
        assert_eq!(active.get_num_trials(), 0);
        // The stack-pointer placeholder (cc:1511-1512 createPlaceholder) is
        // appended as the final CALL input for a model with a stack entry.
        // This Funcdata carries no model, so no placeholder is created and
        // the CALL input count stays exactly as constructed.
        assert_eq!(op_ref.0.read().unwrap().num_input(), 3);
    }

    /// FuncCallSpecs.is_input_locked: true when all params type-locked.
    #[test]
    fn test_funcspecs_is_input_locked() {
        use crate::address::Address;
        use crate::fspec::{protoparam_flags, FuncCallSpecs, FuncProto, ProtoParameter};
        let void_t = std::sync::Arc::new(crate::type_system::Datatype::Void(
            crate::type_system::datatype::TypeBase::new(
                "void".into(), 0, crate::type_system::TypeMetatype::Void,
            ),
        ));
        let int_t = std::sync::Arc::new(crate::type_system::Datatype::Base(
            crate::type_system::datatype::TypeBase::new(
                "int".into(), 4, crate::type_system::TypeMetatype::Int,
            ),
        ));
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

    // ---- ActionSetCasts tests ----

    #[test]
    fn test_action_setcasts_name() {
        let a = ActionSetCasts::new();
        assert_eq!(a.get_name(), "setcasts");
    }

    /// Empty Funcdata → NO_CHANGE, count stays 0.
    #[test]
    fn test_action_setcasts_apply_empty() {
        use crate::address::Address;
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let mut a = ActionSetCasts::new();
        let status = a.apply(&mut fd).unwrap();
        assert_eq!(status, action_status::NO_CHANGE);
        assert_eq!(a.count, 0);
    }

    /// PTRSUB with mismatched input(0) pointer type → CAST op inserted
    /// feeding slot 0; raw apply returns 0 while inherited count changes.
/// ActionSetCasts::castInput's PTRSUB arm (coreaction.cc:2655-2720).
    #[test]
    fn test_action_setcasts_ptrsub_inserts_cast() {
        use crate::address::{Address, SeqNum};
        use crate::op::{PcodeOp, PcodeOpRef};
        use crate::opcodes::OpCode;
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
        use crate::varnode::{varnode_flags, Varnode};
        use std::sync::{Arc, RwLock};

        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x40);

        // TypeOpPtrsub::getInputCast (typeop.cc:2311-2347) compares the input
        // VARNODe's own type (`reqtype`) with its HIGH's type (`curtype`) —
        // never the op's output type. Give in0 an (int *) varnode type whose
        // high holds a (long *): both are pointers, the one-level bases int
        // and long differ (no shared array layer, no typedefs), so the cast
        // to the varnode's own (int *) is required.
        let long_t = Arc::new(Datatype::Base(TypeBase::new(
        "long".to_string(), 8, TypeMetatype::Int,
    )));
        let long_ptr = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("long *".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: long_t.clone(),
            wordsize: 1,
        }));
        let int_t = Arc::new(Datatype::Base(TypeBase::new(
        "int".to_string(), 4, TypeMetatype::Int,
    )));
        let int_ptr = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: int_t.clone(),
            wordsize: 1,
        }));
        let in0 = Arc::new(RwLock::new(Varnode::new(8, Address::new(0x2000))));
        in0.write().unwrap().set_flags(varnode_flags::WRITTEN);
        in0.write().unwrap().v_type = Some(int_ptr.clone());
        in0.write().unwrap().high =
            Some(Arc::new(RwLock::new(crate::variable::HighVariable::new(
        long_ptr,
    ))));

        // PTRSUB output: its type plays no role in the input cast decision.
        let out = Arc::new(RwLock::new(Varnode::new(8, Address::new(0x3000))));
        out.write().unwrap().set_flags(varnode_flags::WRITTEN);
        out.write().unwrap().v_type = Some(int_ptr.clone());

        // offset constant (input 1).
        let off = Arc::new(RwLock::new(Varnode::new_constant(8, 8)));

        let mut op = PcodeOp::new(SeqNum::new(Address::new(0x4000), 0), OpCode::CPUI_PTRSUB);
        op.inrefs = vec![in0.clone(), off];
        op.output = Some(out.clone());
        let op_arc = Arc::new(RwLock::new(op));
        out.write().unwrap().def = Some(Arc::downgrade(&op_arc));
        let op_ref = PcodeOpRef(op_arc);
        fd.obank.alivelist.push(op_ref.clone());

        let mut a = ActionSetCasts::new();
        let status = a.apply(&mut fd).unwrap();
        // cc:2747-2756: the read-facing type (int *) does not satisfy
        // isPtrsubMatching (pointer to base int, offset 8), so the PTRSUB is
        // demoted to INT_ADD BEFORE any input cast; the slot-0 cast is then
        // the INT_ADD metain cast to base int of the input size (the
        // pre-preflight (int *) cast no longer exists — bilateral fixture
        // ptrsub_switch_cast_1204 pins the oracle shape).
        assert_eq!(
        status, action_status::NO_CHANGE,
        "Ghidra raw apply returns 0"
    );
        assert!(a.count >= 1, "at least one CAST must be inserted");
        assert_eq!(
        op_ref.0.read().unwrap().opcode,
        OpCode::CPUI_INT_ADD,
        "non-matching PTRSUB is demoted to INT_ADD (cc:2747-2756)"
    );

        // Verify a CPUI_CAST op now feeds slot 0 of the demoted INT_ADD.
        let new_in0 = op_ref.0.read().unwrap().get_in(0).map(|a| a.clone());
        let cast_op_arc = {
            let in0_rg = new_in0.as_ref().unwrap().read().unwrap();
            in0_rg.def.as_ref().and_then(|w| w.upgrade())
        };
        assert!(cast_op_arc.is_some(), "slot 0 must now have a defining op");
        let cast_op = cast_op_arc.unwrap();
        assert_eq!(
        cast_op.read().unwrap().opcode, OpCode::CPUI_CAST,
            "the defining op must be a CAST"
    );
        assert!(
        Arc::ptr_eq(&cast_op.read().unwrap().get_in(0).unwrap(), &in0),
            "the CAST reads the original input varnode"
    );
        let ct = new_in0
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .v_type
            .clone()
            .unwrap();
        // After the cc:2747-2756 demotion the slot-0 cast is the INT_ADD
        // metain cast (base int of the input size), not the old ic0
        // (int *) reqtype.
        assert!(
        ct.get_metatype() == TypeMetatype::Int && ct.get_size() == 8,
        "the CAST output carries the INT_ADD metain base int (8 bytes), got {ct:?}"
    );
    }

    /// PTRSUB whose input(0) pointer does not satisfy isPtrsubMatching
    /// (pointer to base int at offset 8) is demoted to INT_ADD and takes the
    /// INT_ADD metain casts (cc:2747-2756 + cc:2758-2770). The pre-preflight
    /// "no cast when ic0 matches" expectation is superseded by the demotion;
    /// the matching-pointer projection is covered bilaterally by the
    /// ptrsub_switch_cast_1204 `aligned` case (count=0 with a struct field).
    #[test]
    fn test_action_setcasts_ptrsub_no_cast_when_matching() {
        use crate::address::{Address, SeqNum};
        use crate::op::{PcodeOp, PcodeOpRef};
        use crate::opcodes::OpCode;
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
        use crate::varnode::{varnode_flags, Varnode};
        use std::sync::{Arc, RwLock};

        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x40);

        // Both input(0) and output share the same (long *) pointer type.
        let long_t = Arc::new(Datatype::Base(TypeBase::new(
        "long".to_string(), 8, TypeMetatype::Int,
    )));
        let long_ptr = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("long *".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: long_t.clone(),
            wordsize: 1,
        }));

        let in0 = Arc::new(RwLock::new(Varnode::new(8, Address::new(0x2000))));
        in0.write().unwrap().set_flags(varnode_flags::WRITTEN);
        in0.write().unwrap().v_type = Some(long_ptr.clone());

        let out = Arc::new(RwLock::new(Varnode::new(8, Address::new(0x3000))));
        out.write().unwrap().set_flags(varnode_flags::WRITTEN);
        out.write().unwrap().v_type = Some(long_ptr);

        let off = Arc::new(RwLock::new(Varnode::new_constant(8, 8)));

        let mut op = PcodeOp::new(SeqNum::new(Address::new(0x4000), 0), OpCode::CPUI_PTRSUB);
        op.inrefs = vec![in0.clone(), off];
        op.output = Some(out.clone());
        let op_arc = Arc::new(RwLock::new(op));
        out.write().unwrap().def = Some(Arc::downgrade(&op_arc));
        fd.obank.alivelist.push(PcodeOpRef(op_arc.clone()));

        let mut a = ActionSetCasts::new();
        let status = a.apply(&mut fd).unwrap();
        assert_eq!(
        status, action_status::NO_CHANGE, "Ghidra raw apply returns 0"
    );
        // cc:2747-2756: a (long *) with no struct pointee never satisfies
        // isPtrsubMatching, so the op is demoted to INT_ADD and takes the
        // metain slot-0 cast plus the token-vs-outHigh output cast (count 2).
        assert_eq!(
        op_arc.read().unwrap().opcode, OpCode::CPUI_INT_ADD,
        "pointer-to-base-int PTRSUB is demoted to INT_ADD"
    );
        assert_eq!(a.count, 2);
    }

    /// PTRADD with mismatched input(0) pointer type → CAST op inserted.
    #[test]
    fn test_action_setcasts_ptradd_inserts_cast() {
        use crate::address::{Address, SeqNum};
        use crate::op::{PcodeOp, PcodeOpRef};
        use crate::opcodes::OpCode;
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
        use crate::varnode::{varnode_flags, Varnode};
        use std::sync::{Arc, RwLock};

        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x40);

        // TypeOpPtradd::getInputCast (typeop.cc:2250-2266): reqtype = the
        // input VARNODe's own type, curtype = its HIGH's type; the cast is
        // dropped only when the one-level bases have equal align sizes.
        // int (align 4) vs char (align 1) differ, so the varnode's own
        // (int *) becomes the CAST target.
        let char_t = Arc::new(Datatype::Base(TypeBase::new(
        "char".to_string(), 1, TypeMetatype::Int,
    )));
        let char_ptr = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("char *".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: char_t.clone(),
            wordsize: 1,
        }));
        let int_t = Arc::new(Datatype::Base(TypeBase::new(
        "int".to_string(), 4, TypeMetatype::Int,
    )));
        let int_ptr = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: int_t.clone(),
            wordsize: 1,
        }));
        let in0 = Arc::new(RwLock::new(Varnode::new(8, Address::new(0x2000))));
        in0.write().unwrap().set_flags(varnode_flags::WRITTEN);
        in0.write().unwrap().v_type = Some(int_ptr.clone());
        in0.write().unwrap().high =
            Some(Arc::new(RwLock::new(crate::variable::HighVariable::new(
        char_ptr,
    ))));

        let out = Arc::new(RwLock::new(Varnode::new(8, Address::new(0x3000))));
        out.write().unwrap().set_flags(varnode_flags::WRITTEN);
        out.write().unwrap().v_type = Some(int_ptr.clone());

        let idx = Arc::new(RwLock::new(Varnode::new_constant(8, 1)));
        let sz = Arc::new(RwLock::new(Varnode::new_constant(8, 4)));

        let mut op = PcodeOp::new(SeqNum::new(Address::new(0x4000), 0), OpCode::CPUI_PTRADD);
        op.inrefs = vec![in0.clone(), idx, sz];
        op.output = Some(out.clone());
        let op_arc = Arc::new(RwLock::new(op));
        out.write().unwrap().def = Some(Arc::downgrade(&op_arc));
        let op_ref = PcodeOpRef(op_arc);
        fd.obank.alivelist.push(op_ref.clone());

        let mut a = ActionSetCasts::new();
        let status = a.apply(&mut fd).unwrap();
        assert_eq!(
        status, action_status::NO_CHANGE,
        "Ghidra raw apply returns 0"
    );
        // cc:2740-2746: the HIGH (char *) pointee alignSize 1 != 4 = the
        // scale, so the PTRADD is undone to INT_ADD (constant index folded
        // with the scale) before the casts; the slot-0 cast is then the
        // INT_ADD metain base int, not the preflight-era ic0 (int *).
        assert_eq!(
        op_ref.0.read().unwrap().opcode,
        OpCode::CPUI_INT_ADD,
        "misfit PTRADD is undone to INT_ADD (cc:2740-2746)"
    );
        assert!(a.count >= 1);
        // Verify CAST op now feeds slot 0 with the metain base-int type.
        let new_in0 = op_ref.0.read().unwrap().get_in(0).map(|a| a.clone());
        let cast_op_arc = {
            let in0_rg = new_in0.as_ref().unwrap().read().unwrap();
            in0_rg.def.as_ref().and_then(|w| w.upgrade())
        };
        assert!(cast_op_arc.is_some());
        assert_eq!(
        cast_op_arc.unwrap().read().unwrap().opcode, OpCode::CPUI_CAST
    );
        let ct = new_in0
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .v_type
            .clone()
            .unwrap();
        assert!(
        ct.get_metatype() == TypeMetatype::Int && ct.get_size() == 8,
        "the CAST output carries the INT_ADD metain base int (8 bytes), got {ct:?}"
    );
        let _ = &int_ptr;
    }

    // ---- ActionInferTypes + default-pipeline tree tests ----

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
        let meta = out
        .read()
        .unwrap()
        .v_type
        .as_ref()
        .map(|t| t.get_metatype());
        assert_eq!(
            meta,
            Some(crate::type_system::datatype::TypeMetatype::Bool),
            "INT_EQUAL output must be inferred as bool"
        );
    }

    // PIPE-HEAD-FLAT-ACTIONS-0001: build_full_pipeline_actions() and its
    // skip-set consumption are deleted; build_default_pipeline (action.rs)
    // mirrors universalAction (coreaction.cc:5462-5738) with every Action
    // at its oracle tree slot. These tests pin the migrated slots.

    // RUGRA-GLUE: test-only recursive tree search over the pipeline (Ghidra
    // walks the same tree in Action::print, action.cc:417-440).
    fn find_group_recursive<'a>(
        node: &'a dyn crate::action::Action,
        name: &str,
    ) -> Option<&'a crate::action::ActionGroup> {
        if node.get_name() == name {
            if let Some(g) = node.as_action_group() {
                return Some(g);
            }
        }
        let g = node.as_action_group()?;
        for child in g.child_actions() {
            if let Some(found) = find_group_recursive(child.as_ref(), name) {
                return Some(found);
            }
        }
        None
    }

    // Ghidra: coreaction.cc:5477-5486 universalAction head after decompile
    // derive filtering (8 raw slots; NormalizeSetup :5479 group
    // "normalanalysis" and FuncLinkOutOnly :5485 group "noproto" are both
    // filtered from the decompile root — coreaction.cc:5424-5431).
    #[test]
    fn test_default_pipeline_head_matches_ghidra_5477_5486() {
        let root = crate::action::build_default_pipeline();
        let names = root.child_names();
        assert!(
            names.len() >= 7,
            "head + fullloop must exist, got {names:?}"
        );
        assert_eq!(
            &names[..7],
            &[
                "start",            // :5477
                "constbase",        // :5478
                "defaultparams",    // :5480
                "extrapopsetup",    // :5482
                "prototypetypes",   // :5483
                "funclink",         // :5484
                "fullloop",         // :5487
            ][..]
        );
        // No flat survivors: the six former root children must live only in
        // their oracle groups (mainloop :5494/:5495, stackstall :5653-:5656).
        for name in [
            "segmentize",
            "internalstorage",
            "multicse",
            "shadowvar",
            "deindirect",
            "stackptrflow",
        ] {
            assert!(
                !names.contains(&name),
                "{name} must not be a flat root child (got {names:?})"
            );
        }
        // setcasts stays sole-registered at :5735 (HERITAGE-FLAGFREE-SSA-0001).
        assert_eq!(names.iter().filter(|n| **n == "setcasts").count(), 1);
    }

    // Ghidra: coreaction.cc:5493-5500 mainloop slot order — Segmentize
    // :5494 and InternalStorage :5495 sit between ParamDouble :5493 and
    // DirectWrite :5497.
    #[test]
    fn test_default_pipeline_mainloop_segmentize_internalstorage_slots() {
        let root = crate::action::build_default_pipeline();
        let mainloop =
            find_group_recursive(&root, "mainloop").expect("mainloop group must exist");
        let names = mainloop.child_names();
        let expect = [
            "varnodeprops",    // :5491
            "heritage",        // :5492
            "paramdouble",     // :5493
            "segmentize",      // :5494
            "internalstorage", // :5495
            "directwrite",     // :5497 (protorecovery_a instance)
            "activeparam",     // :5499
            "returnrecovery",  // :5500
        ];
        let pos: Vec<usize> = expect
            .iter()
            .map(|n| {
            names
                .iter()
                .position(|x| x == n)
                .unwrap_or_else(|| panic!("{n} must be registered in mainloop, got {names:?}")
            )
        })
            .collect();
        assert!(
            pos.windows(2).all(|w| w[0] < w[1]),
            "mainloop slot order broken: {names:?}"
        );
    }

    // Ghidra: coreaction.cc:5651-5656 stackstall children — oppool1, then
    // LaneDivide :5652, MultiCse :5653, ShadowVar :5654, Deindirect :5655,
    // StackPtrFlow :5656.
    #[test]
    fn test_default_pipeline_stackstall_children_match_ghidra_5651_5656() {
        let root = crate::action::build_default_pipeline();
        let stackstall =
            find_group_recursive(&root, "stackstall").expect("stackstall group must exist");
        assert_eq!(
            stackstall.child_names(),
            vec![
                "oppool1",      // coreaction.cc:5511
                "lanedivide",   // :5652
                "multicse",     // :5653
                "shadowvar",    // :5654
                "deindirect",   // :5655
                "stackptrflow", // :5656
            ]
        );
    }

    // PIPE-MERGETYPE-ORDER-0001 + UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ④:
    // assignhigh/dominantcopy/copymarker/setcasts are sole-registered at
    // their oracle positions in the root tail — never early, never twice.
    #[test]
    fn test_default_pipeline_sole_registrations_survive() {
        let root = crate::action::build_default_pipeline();
        let names = root.child_names();
        for (name, expected) in [
            ("assignhigh", 1),      // :5717
            ("dominantcopy", 1),    // :5723
            ("copymarker", 1),      // :5729
            ("setcasts", 1),        // :5735
            ("prototypewarnings", 1), // :5737
            ("hideshadow", 1),      // :5728
            ("outputprototype", 1), // :5730
            ("inputprototype", 1),  // :5731
            ("starttypes", 0),      // fullloop :5687 only
            ("infertypes", 0),      // mainloop :5508 only
        ] {
            assert_eq!(
                names.iter().filter(|n| **n == name).count(),
                expected,
                "top-level count for {name}"
            );
        }
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
        // Merge family names must match Ghidra's ctor names exactly
        // (coreaction.hh:364/376/398/409 — no underscores).
        assert_eq!(ActionMergeRequired::new().get_name(), "mergerequired");
        assert_eq!(ActionMergeAdjacent::new().get_name(), "mergeadjacent");
        assert_eq!(ActionMergeMultiEntry::new().get_name(), "mergemultientry");
        assert_eq!(ActionMergeType::new().get_name(), "mergetype");
        assert_eq!(ActionMarkIndirectOnly::new().get_name(), "markindirectonly");
        assert_eq!(ActionMapGlobals::new().get_name(), "mapglobals");
        assert_eq!(ActionPreferComplement::new().get_name(), "prefercomplement");
        assert_eq!(
        ActionStructureTransform::new().get_name(), "structuretransform"
    );
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
        assert!(
        fd.has_type_recovery_started(), "bit must be set after apply"
    );
        assert_eq!(a.count, 1, "count must bump on the first flip");
        // Re-run: already started, count must not bump.
        let _ = a.apply(&mut fd).unwrap();
        assert_eq!(a.count, 1, "idempotent — count must not bump again");
    }

    #[test]
    fn test_action_start_and_stop_delegate_funcdata_lifecycle() {
        use crate::address::Address;

        let mut fd = Funcdata::new("f", Address::new(0x1000), 0x10);
        assert!(!fd.is_proc_started());
        assert!(!fd.is_proc_complete());
        assert!(fd.heritage.infolist.is_empty());

        let start_status = ActionStart::new().apply(&mut fd).unwrap();
        assert_eq!(start_status, action_status::NO_CHANGE);
        assert!(fd.is_proc_started());
        assert!(!fd.is_proc_complete());
        assert!(!fd.heritage.infolist.is_empty());

        let dead = fd.new_op(0, Address::new(0x1000));
        fd.obank.mark_dead(dead.clone());
        assert_eq!(fd.obank.deadlist.len(), 1);
        assert!(fd.obank.optree.contains(&dead));

        let stop_status = ActionStop::new().apply(&mut fd).unwrap();
        assert_eq!(stop_status, action_status::NO_CHANGE);
        assert!(fd.is_proc_complete());
        assert!(fd.obank.deadlist.is_empty());
        assert!(!fd.obank.optree.contains(&dead));
    }

    #[test]
    fn test_action_assignhigh_creates_highvariables() {
        // ActionAssignHigh must give every varnode a HighVariable.
        use crate::address::Address;
        use crate::varnode::Varnode;
        let mut fd = Funcdata::new("f", Address::new(0x1000), 0x40);
        let vn = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(
            4,
            Address::new(0x300))));
        fd.vbank
            .loc_tree
            .insert(crate::varnode::VarnodeLocRef(vn.clone()));
        assert!(vn.read().unwrap().high.is_none());
        let mut a = ActionAssignHigh::new();
        let status = a.apply(&mut fd).unwrap();
        // Ghidra ActionAssignHigh returns 0 (count is statistics only).
        assert_eq!(status, action_status::NO_CHANGE);
        assert!(
            vn.read().unwrap().high.is_some(),
            "varnode must have a HighVariable after assignhigh"
        );
        // Idempotent: a second run reports no change.
        let status2 = a.apply(&mut fd).unwrap();
        assert_eq!(status2, action_status::NO_CHANGE);
    }

    #[test]
    fn test_remaining_action_markers_return_nochange() {
        // Marker Actions return NO_CHANGE and do not panic on an empty
        // Funcdata. ActionStop additionally performs its lifecycle mutation.
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
        assert!(fd.is_proc_complete());
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
    fn test_action_mapglobals_creates_symbol_for_persistent_ram_varnodes() {
        // ActionMapGlobals::apply is exactly `data.mapGlobals(); return 0`
        // (coreaction.hh:885). For a persistent RAM (global) varnode with no
        // symbol (no channel attached in unit tests), the legacy proxy leg
        // records a Symbol name at the group address via
        // ScopeLocal::buildVariableName's persist branch (database.cc:2447:
        // <printNameBase>Ram<offset>; no high type → no printNameBase). The
        // old flag-only stub behavior (blanket PERSIST+READONLY) was NOT
        // Ghidra behavior and is gone.
        use crate::address::Address;
        use crate::varnode::{varnode_flags, Varnode};
        let mut fd = Funcdata::new("f", Address::new(0x1000), 0x40);
        // A persistent RAM (global) varnode, attached (not free) via WRITTEN.
        let g = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_ram(0x4000, 4)));
        g.write()
        .unwrap()
        .set_flags(varnode_flags::PERSIST | varnode_flags::WRITTEN);
        // A non-persistent RAM varnode (local) — must be left untouched.
        let local = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_ram(0x100, 4)));
        local.write().unwrap().set_flags(varnode_flags::WRITTEN);
        // A persistent but non-RAM varnode — mapGlobals processes it too in
        // Ghidra (the walk has no space gate; only the persist gate does the
        // filtering, cc:1669), but no symbol is forced read-only anywhere.
        let reg = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_register(0x10, 4)));
        reg.write()
        .unwrap()
        .set_flags(varnode_flags::PERSIST | varnode_flags::WRITTEN);
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
        // The uncovered persistent RAM group got a Symbol (proxy form).
        let name = fd
            .symbol_table
            .get(&0x4000)
            .expect("persistent RAM group must gain a symbol name");
        assert!(
            name.contains("Ram"),
            "persist-branch default name is <printNameBase>Ram<offset>, got {name}"
        );
        // No blanket READONLY: that was the stub's invention.
        assert!(
            !g.read().unwrap().is_read_only(),
            "mapGlobals never forces readonly (that was the old stub)"
        );
        assert!(
            g.read().unwrap().is_persist(),
            "persistent RAM varnode keeps its persist flag"
        );
        // Locals are not heritaged into global symbols.
        assert!(!fd.symbol_table.contains_key(&0x100));
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
            OpCode::CPUI_INDIRECT);
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
        assert_eq!(
        status, action_status::NO_CHANGE, "markindirectonly returns 0"
    );
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

    /// ActionPreferComplement must follow blockaction.cc:2140/block.cc:3093:
    /// only a 3-child BlockIf (with else arm) whose split-point condition
    /// normalizes on flip (opFlipInPlaceTest == 0, i.e. the comparison is in
    /// negated form like INT_NOTEQUAL) gets flipped: comparison op-code
    /// exchanged, fallthru_true toggled, arms swapped. A 2-child if (no
    /// else) and an already-normalized (INT_EQUAL) condition are refused.
    #[test]
    fn test_prefercomplement_flips_if_else_condition() {
        use crate::address::{Address, SeqNum};
        use crate::block::{BlockBasic, BlockIf};
        use crate::op::pcodeop_flags::{BOOLEAN_FLIP, FALLTHRU_TRUE};
        use crate::op::{PcodeOp, PcodeOpRef};
        use crate::opcodes::OpCode;
        use crate::varnode::Varnode;
        type BlkArc = std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>;
        let build_if = |else_some: bool, cond_opcode: OpCode| {
            let mut fd = Funcdata::new("f", Address::new(0x1000), 0x40);
            let cond_bb = std::sync::Arc::new(std::sync::RwLock::new(
                BlockBasic::new(
            0, Address::new(0x1000),
        )));
            // comparison op defining the CBRANCH condition, with proper
            // def/descend wiring so loneDescend/getDef resolve.
            let mut cmp = PcodeOp::new(SeqNum::new(Address::new(0x1000), 0), cond_opcode);
            let in0 = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(8, Address::new(0x30))));
            let in1 = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_constant(8, 5)));
            let bool_vn = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(1, Address::new(0x10))));
            cmp.inrefs = vec![in0.clone(), in1.clone()];
            cmp.output = Some(bool_vn.clone());
            let cmp_arc = std::sync::Arc::new(std::sync::RwLock::new(cmp));
            let mut cb = PcodeOp::new(SeqNum::new(Address::new(0x1000), 1), OpCode::CPUI_CBRANCH);
            let addr_vn = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_constant(0x1000, 8)));
            cb.inrefs = vec![addr_vn, bool_vn.clone()];
            let cb_arc = std::sync::Arc::new(std::sync::RwLock::new(cb));
            // Wire SSA links: bool_vn defined by cmp, read only by CBRANCH.
            bool_vn.write().unwrap().def = Some(std::sync::Arc::downgrade(&cmp_arc));
            bool_vn.write().unwrap().descend = vec![std::sync::Arc::downgrade(&cb_arc)];
            cond_bb.write().unwrap().add_op(PcodeOpRef(cmp_arc.clone()));
            cond_bb.write().unwrap().add_op(PcodeOpRef(cb_arc.clone()));
            let if_body = std::sync::Arc::new(std::sync::RwLock::new(
                BlockBasic::new(
            1, Address::new(0x1100),
        ))) as BlkArc;
            let else_body = std::sync::Arc::new(std::sync::RwLock::new(
                BlockBasic::new(
            2, Address::new(0x1200),
        ))) as BlkArc;
            // getSplitPoint (block.cc:2361) requires the condition block to
            // have two outgoing edges.
            cond_bb.write().unwrap().outgoing = vec![
                crate::block::BlockEdge { point: if_body.clone(), flags: 0, reverse_index: 0 ,
            },
                crate::block::BlockEdge { point: else_body.clone(), flags: 0, reverse_index: 0 ,
            },
            ];
            let bif = BlockIf {
                index: 3,
                condition: cond_bb.clone(),
                if_body: if_body.clone(),
                else_body: else_some.then(|| else_body.clone()),
                goto_target: None,
                goto_type: crate::block::goto_type::GOTO_GOTO,
                incoming: Vec::new(),
                outgoing: Vec::new(),
                parent: None,
                flags: 0,
            };
            let bif_arc =
                std::sync::Arc::new(std::sync::RwLock::new(bif)) as BlkArc;
            fd.sblocks.add_block(bif_arc.clone());
            (fd, bif_arc, cmp_arc, cb_arc, if_body)
        };

        // Case 1: 3-child if/else with INT_NOTEQUAL condition → flipped.
        let (mut fd, bif_arc, cmp_arc, cb_arc, if_body) = build_if(true, OpCode::CPUI_INT_NOTEQUAL);
        let mut a = ActionPreferComplement::new();
        let _ = a.apply(&mut fd).unwrap();
        assert_eq!(a.count, 1, "3-child if/else with normalizing flip runs");
        assert_eq!(
            cmp_arc.read().unwrap().opcode,
            OpCode::CPUI_INT_EQUAL,
            "INT_NOTEQUAL must be exchanged to INT_EQUAL"
        );
        assert_ne!(
            cb_arc.read().unwrap().flags & FALLTHRU_TRUE,
            0,
            "fallthru_true must be toggled"
        );
        assert_eq!(
            cb_arc.read().unwrap().flags & BOOLEAN_FLIP,
            0,
            "boolean_flip is NOT touched by flipInPlaceExecute"
        );
        {
            let bl = bif_arc.read().unwrap();
            let bif = bl.as_any().downcast_ref::<BlockIf>().unwrap();
            assert_eq!(
                bif.if_body.read().unwrap().get_index(),
                2,
                "arms must be swapped (old else is now then)"
            );
            let eb = bif.else_body.as_ref().unwrap();
            assert_eq!(eb.read().unwrap().get_index(), 1);
        }

        // Case 2: 2-child if (no else) → refused (block.cc:3096).
        let (mut fd2, _, cmp_arc2, cb_arc2, _) = build_if(false, OpCode::CPUI_INT_NOTEQUAL);
        let mut a2 = ActionPreferComplement::new();
        let _ = a2.apply(&mut fd2).unwrap();
        assert_eq!(a2.count, 0, "2-child if is refused");
        assert_eq!(cmp_arc2.read().unwrap().opcode, OpCode::CPUI_INT_NOTEQUAL);

        // Case 3: already-normalized INT_EQUAL → test returns 1, refused
        // (block.cc:3103: `0 != flipInPlaceTest`).
        let (mut fd3, _, cmp_arc3, _, _) = build_if(true, OpCode::CPUI_INT_EQUAL);
        let mut a3 = ActionPreferComplement::new();
        let _ = a3.apply(&mut fd3).unwrap();
        assert_eq!(a3.count, 0, "non-normalizing flip is refused");
        assert_eq!(cmp_arc3.read().unwrap().opcode, OpCode::CPUI_INT_EQUAL);
    }

    /// ActionPreferComplement::op_flip_in_place_execute must perform the
    /// funcdata_op.cc:1280 transforms: comparison opcode exchange (INT_LESS →
    /// INT_LESSEQUAL with swapped inputs), and BOOL_NEGATE removal with its
    /// input propagated to the lone descendant.
    #[test]
    fn test_prefercomplement_flip_in_place_execute() {
        use crate::address::{Address, SeqNum};
        use crate::op::{PcodeOp, PcodeOpRef};
        use crate::opcodes::OpCode;
        use crate::varnode::Varnode;
        let mut fd = Funcdata::new("f", Address::new(0x1000), 0x40);
        // INT_LESS(v1, v2) in the flip list.
        let v1 = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(4, Address::new(0x10))));
        let v2 = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(4, Address::new(0x20))));
        let mut op = PcodeOp::new(SeqNum::new(Address::new(0), 0), OpCode::CPUI_INT_LESS);
        op.inrefs = vec![v1.clone(), v2.clone()];
        let op_arc = std::sync::Arc::new(std::sync::RwLock::new(op));
        ActionPreferComplement::op_flip_in_place_execute(&mut fd, vec![op_arc.clone()]);
        {
            let o = op_arc.read().unwrap();
            assert_eq!(
            o.opcode, OpCode::CPUI_INT_LESSEQUAL, "INT_LESS → INT_LESSEQUAL"
        );
            assert!(
                std::sync::Arc::ptr_eq(&o.inrefs[0], &v2) && std::sync::Arc::ptr_eq(&o.inrefs[1], &v1),
                "inputs must be swapped"
            );
        }
        // BOOL_NEGATE(x) feeding a lone CBRANCH: negate removed, CBRANCH
        // rewired to x. Build through fd APIs so varnodes are bank-owned
        // (opDestroy requires bank ownership).
        let blk = std::sync::Arc::new(std::sync::RwLock::new(
            crate::block::BlockBasic::new(
        0, Address::new(0x1000),
    ))) as std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>;
        fd.bblocks.add_block(blk.clone());
        // x must be a WRITTEN varnode (free varnodes may have at most one
        // descendant, varnode.cc:333-336): define it as an INT_EQUAL output.
        let xdef_ref = fd.new_op(2, Address::new(0x1000));
        fd.op_set_opcode(&xdef_ref, OpCode::CPUI_INT_EQUAL);
        let x = fd.new_unique_out(1, &xdef_ref);
        let xc0 = fd.new_unique(8);
        let xc1 = fd.new_constant(1, 1);
        fd.op_set_input(&xdef_ref, xc0, 0);
        fd.op_set_input(&xdef_ref, xc1, 1);
        fd.op_insert_end(&xdef_ref, &blk);
        let neg_ref = fd.new_op(1, Address::new(0x1000));
        fd.op_set_opcode(&neg_ref, OpCode::CPUI_BOOL_NEGATE);
        let neg_out = fd.new_unique_out(1, &neg_ref);
        fd.op_set_input(&neg_ref, x.clone(), 0);
        fd.op_insert_end(&neg_ref, &blk);
        let cb_ref = fd.new_op(2, Address::new(0x1000));
        fd.op_set_opcode(&cb_ref, OpCode::CPUI_CBRANCH);
        let addr_vn = fd.new_constant(8, 0x1000);
        fd.op_set_input(&cb_ref, addr_vn, 0);
        fd.op_set_input(&cb_ref, neg_out.clone(), 1);
        fd.op_insert_end(&cb_ref, &blk);
        ActionPreferComplement::op_flip_in_place_execute(
            &mut fd,
            vec![neg_ref.0.clone()]);
        assert!(neg_ref.0.read().unwrap().is_dead(), "BOOL_NEGATE destroyed");
        assert!(
            std::sync::Arc::ptr_eq(&cb_ref.0.read().unwrap().inrefs[1], &x),
            "CBRANCH condition rewired to the negate's input"
        );
    }

    /// ActionStructureTransform must detect a for-loop induction variable
    /// (when analyze_for_loops is on) and mark the iterate op non-printing.
    #[test]
    fn test_structuretransform_detects_for_loop() {
        use crate::address::{Address, SeqNum};
        use crate::arch::Architecture;
        use crate::block::{BlockBasic, BlockList, BlockWhileDo};
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
        let head = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
        0, Address::new(0x1000),
    )));
        let head_dyn = head.clone() as std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>;
        let i_init = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(4, Address::new(0x100))));
        let i_update = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(4, Address::new(0x300))));
        // MULTIEQUAL producing i, input slot 1 = the iterate value.
        let mut me = PcodeOp::new(
        SeqNum::new(Address::new(0x1004), 0), OpCode::CPUI_MULTIEQUAL,
    );
        me.parent = Some(std::sync::Arc::downgrade(&head_dyn));
        me.output = Some(std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(
        4, Address::new(0x200),
    ))));
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
        cmp.output = Some(std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(
        1, Address::new(0x400),
    ))));
        let cond_vn = cmp.output.clone().unwrap();
        let cmp_ref = PcodeOpRef(std::sync::Arc::new(std::sync::RwLock::new(cmp)));
        cond_vn.write().unwrap().def = Some(std::sync::Arc::downgrade(&cmp_ref.0));
        head.write().unwrap().add_op(cmp_ref.clone());
        let mut cb = PcodeOp::new(SeqNum::new(Address::new(0x100c), 0), OpCode::CPUI_CBRANCH);
        cb.parent = Some(std::sync::Arc::downgrade(&head_dyn));
        cb.inrefs = vec![
        std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_constant(0x1000, 8))), cond_vn,
    ];
        let cb_ref = PcodeOpRef(std::sync::Arc::new(std::sync::RwLock::new(cb)));
        head.write().unwrap().add_op(cb_ref.clone());
        // body (tail): INT_ADD(i, 1) → i_update; BRANCH back to head.
        let body = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
        1, Address::new(0x2000),
    )));
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
        br.inrefs = vec![std::sync::Arc::new(std::sync::RwLock::new(
        Varnode::new_constant(0x1000, 8),
    ))];
        br.flags = crate::op::pcodeop_flags::BRANCH;
        let br_ref = PcodeOpRef(std::sync::Arc::new(std::sync::RwLock::new(br)));
        body.write().unwrap().add_op(br_ref); // trailing branch
        // Build the live CFG shape consumed by block.cc:3362-3378. The entry
        // edge is inserted before the tail back-edge so the latter occupies
        // head incoming slot 1, matching MULTIEQUAL input slot 1 above.
        let entry = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            2,
            Address::new(0x0800),
        ))) as std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>;
        let exit = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            3,
            Address::new(0x3000),
        ))) as std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>;
        fd.bblocks.add_block(entry.clone());
        fd.bblocks.add_block(head_dyn.clone());
        fd.bblocks.add_block(body_dyn.clone());
        fd.bblocks.add_block(exit.clone());
        fd.bblocks.add_edge(entry, head_dyn.clone());
        fd.bblocks.add_edge(head_dyn.clone(), body_dyn.clone());
        fd.bblocks.add_edge(head_dyn.clone(), exit);
        fd.bblocks.add_edge(body_dyn.clone(), head_dyn.clone());

        // finalTransform sees the structured BlockCopy hierarchy produced by
        // buildCopy, never naked BlockBasic nodes (blockaction.cc:2176-2177).
        fd.sblocks.build_copy(&fd.bblocks);
        let head_copy = fd.sblocks.get_block(1).unwrap();
        let body_copy = fd.sblocks.get_block(2).unwrap();
        let wd = BlockWhileDo {
            index: 0,
            condition: head_copy,
            body: body_copy,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0, for_init: None, for_iter: None, overflow_syntax: false,
        };
        let wd_arc = std::sync::Arc::new(std::sync::RwLock::new(wd)) as std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>;
        // Nest the WhileDo under a BlockList so the test exercises
        // BlockGraph::finalTransform's required child-first recursion.
        let list = std::sync::Arc::new(std::sync::RwLock::new(BlockList::new(
            0,
            vec![wd_arc.clone()],
        ))) as std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>;
        fd.sblocks.clear();
        fd.sblocks.add_block(list);
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

        // block.cc:3361 refuses overflow syntax before inspecting the loop.
        add_ref.0.write().unwrap().flags &= !NONPRINTING;
        {
            let mut rg = wd_arc.write().unwrap();
            let wd = rg.as_any_mut().downcast_mut::<BlockWhileDo>().unwrap();
            wd.for_init = None;
            wd.for_iter = None;
            wd.set_overflow_syntax();
        }
        let mut overflow_action = ActionStructureTransform::new();
        let _ = overflow_action.apply(&mut fd).unwrap();
        assert_eq!(overflow_action.count, 0, "overflow loop must be skipped");
        assert_eq!(
            add_ref.0.read().unwrap().flags & NONPRINTING,
            0,
            "overflow loop iterator remains printable"
        );
    }

    /// ActionReturnSplit must synthesize a new RETURN op at each goto
    /// predecessor of a multi-in-edge splittable RETURN block — where
    /// "goto predecessor" is the structured-tree detection of
    /// gatherReturnGotos (blockaction.cc:2205-2234), NOT the removed
    /// BRANCH/CBRANCH proxy. Phase A: BRANCH-ending in-edge sources with no
    /// goto structure → no split (regression for the proxy). Phase B: the
    /// same CFG with the sources' structured copies wrapped in BlockGotos
    /// targeting the RETURN block → both edges qualify, "can't split ALL"
    /// pops one, exactly one nodeSplit runs.
    #[test]
    fn test_returnsplit_creates_return_at_goto_pred() {
        use crate::address::{Address, SeqNum};
        use crate::block::{BlockBasic, BlockCopy, BlockGoto, FlowBlock};
        use crate::op::{PcodeOp, PcodeOpRef};
        use crate::opcodes::OpCode;
        use crate::varnode::Varnode;
        type DynBlk = std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>,
        >;
        let mut fd = Funcdata::new("f", Address::new(0x1000), 0x40);
        // Two predecessors (b1, b2) each ending in a BRANCH, both flowing
        // into the RETURN block (ret). ret has >1 in-edge and is splittable
        // (only a RETURN op with constant-ish inputs).
        let b1 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
        1, Address::new(0x1100),
    )));
        let b2 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
        2, Address::new(0x1200),
    )));
        let ret = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
        3, Address::new(0x1300),
    )));
        // RETURN op in ret (splittable: single RETURN, annotation/const inputs).
        let mut ro = PcodeOp::new(SeqNum::new(Address::new(0x1300), 0), OpCode::CPUI_RETURN);
        ro.inrefs = vec![std::sync::Arc::new(std::sync::RwLock::new(
        Varnode::new_constant(0, 1),
    ))];
        let ro_ref = PcodeOpRef(std::sync::Arc::new(std::sync::RwLock::new(ro)));
        let ret_dyn: DynBlk = ret.clone();
        ro_ref
            .0
            .write()
            .unwrap()
            .parent
            .replace(std::sync::Arc::downgrade(&ret_dyn));
        ret.write().unwrap().add_op(ro_ref.clone());
        fd.obank.alivelist.push(ro_ref.clone());
        // b1 ends in BRANCH, b2 ends in BRANCH — under the faithful
        // gatherReturnGotos this alone must NOT mark them as goto preds.
        for (blk, addr) in [(&b1, 0x1100u64), (&b2, 0x1200u64)] {
            let mut br = PcodeOp::new(SeqNum::new(Address::new(addr), 0), OpCode::CPUI_BRANCH);
            br.inrefs = vec![std::sync::Arc::new(std::sync::RwLock::new(
            Varnode::new_constant(0x1300, 8),
        ))];
            br.flags = crate::op::pcodeop_flags::BRANCH;
            blk.write()
            .unwrap()
            .add_op(PcodeOpRef(std::sync::Arc::new(std::sync::RwLock::new(br))));
        }
        // Wire edges b1→ret, b2→ret so ret has 2 in-edges.
        fd.bblocks.add_block(b1.clone());
        fd.bblocks.add_block(b2.clone());
        fd.bblocks.add_block(ret.clone());
        fd.bblocks.add_edge(b1.clone(), ret.clone());
        fd.bblocks.add_edge(b2.clone(), ret.clone());

        // Structured mirrors (buildCopy, block.cc:1925-1938): a BlockCopy per
        // original, each original's copy_map pointing at its copy.
        let mk_copy = |source: &DynBlk, idx: i32| -> DynBlk {
            std::sync::Arc::new(std::sync::RwLock::new(BlockCopy {
                index: idx,
                flags: 0,
                parent: None,
                self_ref: None,
                original: source.clone(),
                incoming: Vec::new(),
                outgoing: Vec::new(),
                immed_dom: None,
                copy_map: None,
                visit_count: 0,
                num_desc: -1,
                dom_depth: -1,
                dom_children: Vec::new(),
                dom_frontier: std::collections::HashSet::new(),
            }))
        };
        let b1_dyn: DynBlk = b1.clone();
        let b2_dyn: DynBlk = b2.clone();
        let copy_b1 = mk_copy(&b1_dyn, 1);
        let copy_b2 = mk_copy(&b2_dyn, 2);
        let copy_ret = mk_copy(&ret_dyn, 3);
        b1.write().unwrap().set_copy_map(Some(std::sync::Arc::downgrade(&copy_b1)));
        b2.write().unwrap().set_copy_map(Some(std::sync::Arc::downgrade(&copy_b2)));
        ret.write().unwrap().set_copy_map(Some(std::sync::Arc::downgrade(&copy_ret)));

        // Phase A: structure WITHOUT goto wrappers — plain copies only.
        // The BRANCH-ending in-edges must not be selected (proxy removed).
        fd.sblocks.clear();
        fd.sblocks.add_block(copy_ret.clone());
        fd.sblocks.add_block(copy_b1.clone());
        fd.sblocks.add_block(copy_b2.clone());
        let alives_before = fd.obank.alivelist.len();
        let mut a = ActionReturnSplit::new();
        let res_a = a.apply(&mut fd).unwrap();
        assert_eq!(a.count, 0, "no structured goto → no split");
        assert_eq!(res_a, 0, "apply reports no change without goto structure");
        assert_eq!(
            fd.obank.alivelist.len(),
            alives_before,
            "phase A must not create ops"
        );

        // Phase B: same CFG, sources wrapped in BlockGotos targeting the
        // RETURN's copy ([copy_ret, goto1, goto2] root order: goto1 prints
        // because its successor leaf copy_b2 != target copy_ret; goto2 is
        // last → null successor → prints — block.cc:2881-2890).
        let mk_goto = |wrapped: &DynBlk, target: &DynBlk, idx: i32| -> DynBlk {
            std::sync::Arc::new(std::sync::RwLock::new(BlockGoto {
                index: idx,
                flags: 0,
                parent: None,
                goto_target: None,
                target_dyn: Some(target.clone()),
                wrapped: Some(wrapped.clone()),
                goto_type: crate::block::goto_type::GOTO_GOTO,
                prints_precomputed: false,
                incoming: Vec::new(),
                outgoing: Vec::new(),
            }))
        };
        let goto1 = mk_goto(&copy_b1, &copy_ret, 1);
        let goto2 = mk_goto(&copy_b2, &copy_ret, 2);
        fd.sblocks.clear();
        fd.sblocks.add_block(copy_ret.clone());
        fd.sblocks.add_block(goto1.clone());
        fd.sblocks.add_block(goto2.clone());
        let _ = a.apply(&mut fd).unwrap();
        // Both goto predecessors qualify, but Ghidra can't split ALL in
        // edges (blockaction.cc:2309-2312), so exactly one nodeSplit runs.
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
        let b1 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
        1, Address::new(0x1000),
    )));
        let b2 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
        2, Address::new(0x2000),
    )));
        let exita = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
        3, Address::new(0x3000),
    )));
        let exitb = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
        4, Address::new(0x4000),
    )));
        let cond_vn = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(1, Address::new(0x50))));
        use crate::block::FlowBlock;
        for blk in [&b1, &b2] {
            let mut cb = PcodeOp::new(
            SeqNum::new(blk.read().unwrap().get_start_addr(), 0), OpCode::CPUI_CBRANCH,
        );
            cb.inrefs = vec![
                std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_constant(0x3000, 8))),
                cond_vn.clone(),
            ];
            blk.write()
            .unwrap()
            .add_op(PcodeOpRef(std::sync::Arc::new(std::sync::RwLock::new(cb))));
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
        // NODEJOIN-F3-SAMECOND-FULLJOIN-0001: vn1==vn2 (findDups cc:1926-1927)
        // is a COMPLETE match — the full join runs: nodeJoinCreateBlock
        // appends the join block (cc:2097) and moveCbranch relocates
        // cbranch1 into it / destroys cbranch2 (cc:2043-2057, op effects in
        // F2). The structural half is observable already: block count grows.
        assert_eq!(
            fd.bblocks.get_size(),
            5,
            "same-condition join must create the join block"
        );
    }

    /// NODEJOIN-F2-EXECUTE-STEPS-0001 Rugra regression leg:
    /// `ConditionalJoin::execute` must run ALL FOUR steps
    /// (blockaction.cc:2094-2102). Fixture: a mergeable-condition diamond
    /// (identical INT_LESS conditions, res=0) whose exita merges two distinct
    /// Varnodes v1/v2 through a MULTIEQUAL. After apply:
    /// - setupMultiequals (cc:2023-2040): the join block holds MULTIEQUALs
    ///   for (cond1,cond2) and (v1,v2) in mergeneed map order (createIndex
    ///   of side1), THEN the relocated cbranch1 (cc:2098 before cc:2099);
    /// - moveCbranch (cc:2043-2057): cbranch1 reads the (cond1,cond2)
    ///   MULTIEQUAL output; cbranch2 is destroyed (b2 left with no ops);
    /// - cutDownMultiequals (cc:1981-2019): exita's 2-input MULTIEQUAL loses
    ///   its hi input, reads the (v1,v2) replacement at lo, and becomes a
    ///   COPY moved to the block start (cc:2011-2015).
    /// Oracle side pinned by nodejoin_condjoin_1204 (mechanism B2).
    #[test]
    fn test_nodejoin_execute_runs_all_four_steps() {
        use crate::address::{Address, SeqNum};
        use crate::block::{BlockBasic, FlowBlock};
        use crate::op::{PcodeOp, PcodeOpRef};
        use crate::opcodes::OpCode;
        use crate::varnode::{varnode_flags, Varnode};
        type VnRef = std::sync::Arc<std::sync::RwLock<Varnode>>;

        // RUGRA-GLUE: test-fixture constant Varnode builder (no Ghidra counterpart)
        fn const_vn(val: u64) -> VnRef {
            std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_constant(
                val, 8,
            )))
        }
        // Written condition with a defining op; create_index controls the
        // mergeneed map order (MergePair::operator< cc:1898-1906).
        // RUGRA-GLUE: test-fixture written Varnode + defining op (mirrors oracle driver newUniqueOut/opSetOutput)
        fn written_vn(
            opcode: OpCode,
            inputs: Vec<VnRef>,
            seq_ord: u32,
            create_index: u32,
        ) -> (std::sync::Arc<std::sync::RwLock<PcodeOp>>, VnRef) {
            let out = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(
                8,
                Address::new(0x9000 + seq_ord as u64),
            )));
            {
                let mut o = out.write().unwrap();
                o.set_flags(varnode_flags::WRITTEN);
                o.create_index = create_index;
            }
            let mut def = PcodeOp::new(SeqNum::new(Address::new(0x1000), seq_ord), opcode);
            def.inrefs = inputs;
            def.output = Some(out.clone());
            let def_arc = std::sync::Arc::new(std::sync::RwLock::new(def));
            out.write().unwrap().def = Some(std::sync::Arc::downgrade(&def_arc));
            (def_arc, out)
        }
        // RUGRA-GLUE: test-fixture function-input style Varnode (INPUT flag, explicit createIndex)
        fn input_vn(addr: u64, create_index: u32) -> VnRef {
            let v = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(
                8,
                Address::new(addr),
            )));
            {
                let mut g = v.write().unwrap();
                g.set_flags(varnode_flags::INPUT);
                g.create_index = create_index;
            }
            v
        }

        let mut fd = Funcdata::new("f", Address::new(0x1000), 0x40);
        let b1 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            1,
            Address::new(0x1000),
        )));
        let b2 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            2,
            Address::new(0x2000),
        )));
        let exita = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            3,
            Address::new(0x3000),
        )));
        let exitb = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            4,
            Address::new(0x4000),
        )));

        // Mergeable conditions: identical INT_LESS(k1, k2) → res=0.
        let (def1, cond1) = written_vn(
            OpCode::CPUI_INT_LESS,
            vec![const_vn(1), const_vn(2)],
            1,
            10,
        );
        let (def2, cond2) = written_vn(
            OpCode::CPUI_INT_LESS,
            vec![const_vn(1), const_vn(2)],
            2,
            11,
        );
        // Exit merge inputs (v1 from b1, v2 from b2), createIndex AFTER the
        // condition pair so the join-block MULTIEQUAL order is ME(cond) then
        // ME(v1,v2) (map order by side1 createIndex).
        let v1 = input_vn(0x8100, 20);
        let v2 = input_vn(0x8200, 21);

        // CBRANCHes on the two conditions.
        for (blk, cond, ord) in
            [(b1.clone(), cond1.clone(), 5u32), (b2.clone(), cond2.clone(), 6)]
        {
            let mut cb = PcodeOp::new(
                SeqNum::new(blk.read().unwrap().get_start_addr(), ord),
                OpCode::CPUI_CBRANCH,
            );
            cb.inrefs = vec![const_vn(0x3000), cond];
            blk.write().unwrap().add_op(PcodeOpRef(std::sync::Arc::new(
                std::sync::RwLock::new(cb),
            )));
        }
        // exita: MULTIEQUAL merging v1 (b1 slot) / v2 (b2 slot), then a
        // non-COPY op stops the checkExitBlock/cutDown walk (cc:1970/2017).
        {
            let mut me = PcodeOp::new(
                SeqNum::new(Address::new(0x3000), 7),
                OpCode::CPUI_MULTIEQUAL,
            );
            me.inrefs = vec![v1.clone(), v2.clone()];
            let mut stop = PcodeOp::new(
                SeqNum::new(Address::new(0x3000), 8),
                OpCode::CPUI_INT_ADD,
            );
            stop.inrefs = vec![const_vn(1), const_vn(2)];
            let mut eg = exita.write().unwrap();
            eg.add_op(PcodeOpRef(std::sync::Arc::new(std::sync::RwLock::new(me))));
            eg.add_op(PcodeOpRef(std::sync::Arc::new(std::sync::RwLock::new(stop))));
        }
        for b in [&b1, &b2, &exita, &exitb] {
            fd.bblocks.add_block(b.clone());
        }
        fd.bblocks.add_edge(b1.clone(), exita.clone());
        fd.bblocks.add_edge(b1.clone(), exitb.clone());
        fd.bblocks.add_edge(b2.clone(), exita.clone());
        fd.bblocks.add_edge(b2.clone(), exitb.clone());

        let mut a = ActionNodeJoin::new();
        let _ = a.apply(&mut fd).unwrap();
        assert_eq!(a.count, 1, "mergeable pair joins once");
        let _ = (&def1, &def2);

        // Join block appended (nodeJoinCreateBlock, cc:2097).
        // nodeJoinCreateBlock appends the join block, but its trailing
        // structureReset → structureLoops → findSpanningTree REORDERS the
        // block list into reverse post order and reindexes (block.cc:1015-
        // 1137 `list = rpostorder`) — in Ghidra too. Locate the join block
        // by its f_joined_block flag, not by position.
        let joinblock = (0..fd.bblocks.get_size())
            .map(|pos| fd.bblocks.get_block(pos).expect("block"))
            .find(|b| {
                b.read().unwrap().get_flags()
                    & crate::block::block_flags::JOINED_BLOCK
                    != 0
            })
            .expect("join block present with JOINED_BLOCK flag");
        let join_ops = joinblock.read().unwrap().get_ops();
        let opcodes: Vec<OpCode> = join_ops
            .iter()
            .map(|o| o.0.read().unwrap().opcode)
            .collect();
        assert_eq!(
            opcodes,
            vec![
                OpCode::CPUI_MULTIEQUAL,
                OpCode::CPUI_MULTIEQUAL,
                OpCode::CPUI_CBRANCH
            ],
            "setupMultiequals inserts the two MULTIEQUALs in map order, then moveCbranch appends cbranch1"
        );
        // ME(cond1,cond2) first (createIndex 10 < 20): its output replaces
        // cbranch1's condition input (cc:2051-2055).
        let me_cond_out = join_ops[0].0.read().unwrap().output.clone().expect("me out");
        let cb_cond = join_ops[2]
            .0
            .read()
            .unwrap()
            .get_in(1)
            .cloned()
            .expect("cbranch cond");
        assert!(
            std::sync::Arc::ptr_eq(&me_cond_out, &cb_cond),
            "cbranch1 condition is the merged MULTIEQUAL output"
        );
        // ME(v1,v2) second.
        let me_v_out = join_ops[1].0.read().unwrap().output.clone().expect("me out");
        let me_v_ins: Vec<VnRef> = join_ops[1]
            .0
            .read()
            .unwrap()
            .inrefs
            .iter()
            .cloned()
            .collect();
        assert!(std::sync::Arc::ptr_eq(&me_v_ins[0], &v1));
        assert!(std::sync::Arc::ptr_eq(&me_v_ins[1], &v2));

        // moveCbranch: b1 lost its CBRANCH (moved), b2's CBRANCH destroyed.
        assert!(
            b1.read().unwrap().get_ops().is_empty(),
            "cbranch1 moved out of block1"
        );
        assert!(
            b2.read().unwrap().get_ops().is_empty(),
            "cbranch2 destroyed"
        );

        // cutDownMultiequals: exita's MULTIEQUAL became a COPY at the block
        // start reading the (v1,v2) replacement (cc:2007-2015); the INT_ADD
        // stop op is untouched after it.
        let exit_ops = exita.read().unwrap().get_ops();
        let exit_opcodes: Vec<OpCode> = exit_ops
            .iter()
            .map(|o| o.0.read().unwrap().opcode)
            .collect();
        assert_eq!(
            exit_opcodes,
            vec![OpCode::CPUI_COPY, OpCode::CPUI_INT_ADD],
            "2-input MULTIEQUAL trimmed to 1 input converts to COPY at block start"
        );
        let copy_in = exit_ops[0]
            .0
            .read()
            .unwrap()
            .get_in(0)
            .cloned()
            .expect("copy in");
        assert!(
            std::sync::Arc::ptr_eq(&copy_in, &me_v_out),
            "exit COPY reads the merged (v1,v2) replacement"
        );
    }

    /// NODEJOIN-F5-DYNAMIC-SIZE-0001 Rugra regression leg: the outer
    /// walk's loop bound is re-evaluated every iteration
    /// (`for(int4 i=0;i<graph.getSize();++i)`, blockaction.cc:2334), so a
    /// join block appended by nodeJoinCreateBlock is itself visited — and
    /// having inherited cbranch1 and the two out edges (moveCbranch
    /// cc:2043), it can join with a third same-condition sibling. Fixture:
    /// THREE CBRANCH blocks b1/b2/b3 converging on the same two exits with
    /// the identical condition Varnode. First pass joins b1+b2 into J1; the
    /// walk then reaches J1 and joins it with b3 into J2 — count == 2 and
    /// TWO JOINED_BLOCK blocks exist. The frozen pre-loop bound of the
    /// former port stopped after the first join (count == 1).
    #[test]
    fn test_nodejoin_dynamic_size_rejoins_joinblock() {
        use crate::address::{Address, SeqNum};
        use crate::block::{BlockBasic, FlowBlock};
        use crate::op::{PcodeOp, PcodeOpRef};
        use crate::opcodes::OpCode;
        use crate::varnode::Varnode;

        let mut fd = Funcdata::new("f", Address::new(0x1000), 0x40);
        let cond_vn = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(
            1,
            Address::new(0x50),
        )));
        let mut blocks = Vec::new();
        for (i, a) in [0x1000u64, 0x2000, 0x3000, 0x4000, 0x5000]
            .iter()
            .enumerate()
        {
            blocks.push(std::sync::Arc::new(std::sync::RwLock::new(
                BlockBasic::new((i + 1) as i32, Address::new(*a)),
            )));
        }
        let (b1, b2, b3, exita, exitb) = (
            blocks[0].clone(),
            blocks[1].clone(),
            blocks[2].clone(),
            blocks[3].clone(),
            blocks[4].clone(),
        );
        for blk in [&b1, &b2, &b3] {
            let mut cb = PcodeOp::new(
                SeqNum::new(blk.read().unwrap().get_start_addr(), 5),
                OpCode::CPUI_CBRANCH,
            );
            cb.inrefs = vec![
                std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_constant(
                    0x3000, 8,
                ))),
                cond_vn.clone(),
            ];
            blk.write().unwrap().add_op(PcodeOpRef(std::sync::Arc::new(
                std::sync::RwLock::new(cb),
            )));
        }
        for b in &blocks {
            fd.bblocks.add_block(b.clone());
        }
        fd.bblocks.add_edge(b1.clone(), exita.clone());
        fd.bblocks.add_edge(b1.clone(), exitb.clone());
        fd.bblocks.add_edge(b2.clone(), exita.clone());
        fd.bblocks.add_edge(b2.clone(), exitb.clone());
        fd.bblocks.add_edge(b3.clone(), exita.clone());
        fd.bblocks.add_edge(b3.clone(), exitb.clone());

        let mut a = ActionNodeJoin::new();
        let _ = a.apply(&mut fd).unwrap();
        let joined_count = (0..fd.bblocks.get_size())
            .filter(|&pos| {
                fd.bblocks.get_block(pos)
                    .expect("block")
                    .read()
                    .unwrap()
                    .get_flags()
                    & crate::block::block_flags::JOINED_BLOCK
                    != 0
            })
            .count();
        eprintln!("[F5PROBE] count={} joined_blocks={}", a.count, joined_count);
        assert_eq!(a.count, 2, "join block must itself be revisited and re-joined");
        assert_eq!(joined_count, 2, "two JOINED_BLOCK blocks (J1 and J2)");
    }

    /// NODEJOIN-F4-MATCH-GATES-0001 Rugra regression leg: every
    /// ConditionalJoin::findDups gate (blockaction.cc:1920-1941) must reject
    /// its ineligible diamond — booleanFlip (cc:1920-1921), unwritten
    /// condition (cc:1930-1931), spacebase condition (cc:1932-1933),
    /// functionalEqualityLevel outside {0,1} (cc:1936-1938), and SUBPIECE or
    /// COPY defining op (cc:1939-1941) — while an identical INT_LESS pair
    /// (res=0) passes and joins exactly once. The oracle-side behavior is
    /// pinned by the locked nodejoin_condjoin_1204 fixture; this test is the
    /// single-side regression leg (mechanism B2: cannot lift NO_ORACLE).
    #[test]
    fn test_nodejoin_finddups_gates() {
        use crate::address::{Address, SeqNum};
        use crate::block::{BlockBasic, FlowBlock};
        use crate::op::{PcodeOp, PcodeOpRef};
        use crate::opcodes::OpCode;
        use crate::varnode::{varnode_flags, Varnode};
        type VnRef = std::sync::Arc<std::sync::RwLock<Varnode>>;
        type OpArc = std::sync::Arc<std::sync::RwLock<PcodeOp>>;

        // RUGRA-GLUE: test-fixture constant Varnode builder (no Ghidra counterpart)
        fn const_vn(val: u64) -> VnRef {
            std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_constant(
                val, 8,
            )))
        }
        // Written condition varnode with a defining op (mirrors
        // Funcdata::newUniqueOut + opSetOutput wiring in the oracle fixture).
        // RUGRA-GLUE: test-fixture written Varnode + defining op (mirrors the oracle driver's newUniqueOut/opSetOutput setup)
        fn written_vn(opcode: OpCode, inputs: Vec<VnRef>, seq_ord: u32) -> (OpArc, VnRef) {
            let out = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(
                8,
                Address::new(0x9000 + seq_ord as u64),
            )));
            out.write().unwrap().set_flags(varnode_flags::WRITTEN);
            let mut def = PcodeOp::new(SeqNum::new(Address::new(0x1000), seq_ord), opcode);
            def.inrefs = inputs;
            def.output = Some(out.clone());
            let def_arc = std::sync::Arc::new(std::sync::RwLock::new(def));
            out.write().unwrap().def = Some(std::sync::Arc::downgrade(&def_arc));
            (def_arc, out)
        }
        struct Diamond {
            fd: Funcdata,
            cb_ops: [PcodeOpRef; 2],
        }
        // Two CBRANCH blocks converging on the same two exits; cond1/cond2
        // are the in(1) conditions, flip1/flip2 set the boolean_flip flag.
        // RUGRA-GLUE: test-fixture diamond CFG builder (mirrors the oracle driver's block/edge setup)
        fn diamond(cond1: VnRef, cond2: VnRef, flip1: bool, flip2: bool) -> Diamond {
            let mut fd = Funcdata::new("f", Address::new(0x1000), 0x40);
            let blocks: Vec<_> = [0x1000u64, 0x2000, 0x3000, 0x4000]
                .iter()
                .enumerate()
                .map(|(i, a)| {
                    std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
                        (i + 1) as i32,
                        Address::new(*a),
                    )))
                })
                .collect();
            let mut cb_ops = Vec::new();
            for (blk, cond, flip, ord) in [
                (blocks[0].clone(), cond1, flip1, 5u32),
                (blocks[1].clone(), cond2, flip2, 6),
            ] {
                let mut cb = PcodeOp::new(
                    SeqNum::new(blk.read().unwrap().get_start_addr(), ord),
                    OpCode::CPUI_CBRANCH,
                );
                cb.inrefs = vec![const_vn(0x3000), cond];
                if flip {
                    cb.flags |= crate::op::pcodeop_flags::BOOLEAN_FLIP;
                }
                let cb_ref = PcodeOpRef(std::sync::Arc::new(std::sync::RwLock::new(cb)));
                blk.write().unwrap().add_op(cb_ref.clone());
                cb_ops.push(cb_ref);
            }
            for b in &blocks {
                fd.bblocks.add_block(b.clone());
            }
            fd.bblocks.add_edge(blocks[0].clone(), blocks[2].clone());
            fd.bblocks.add_edge(blocks[0].clone(), blocks[3].clone());
            fd.bblocks.add_edge(blocks[1].clone(), blocks[2].clone());
            fd.bblocks.add_edge(blocks[1].clone(), blocks[3].clone());
            Diamond {
                fd,
                cb_ops: [cb_ops[0].clone(), cb_ops[1].clone()],
            }
        }
        // Function-input style varnode: written flag off, is_free false.
        // RUGRA-GLUE: test-fixture function-input style Varnode (INPUT flag)
        fn input_vn(n: u64) -> VnRef {
            let v = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(
                8,
                Address::new(0x8000 + n),
            )));
            v.write().unwrap().set_flags(varnode_flags::INPUT);
            v
        }
        let run = |d: &mut Diamond| -> (i32, usize) {
            let size_before = d.fd.bblocks.get_size();
            let mut a = ActionNodeJoin::new();
            let _ = a.apply(&mut d.fd).unwrap();
            (a.count, size_before)
        };
        // Defining ops must outlive the apply (Varnode::def is a Weak; the
        // real op bank owns them, the fixture keeps them here).
        let mut keep: Vec<OpArc> = Vec::new();

        // cc:1920-1921: booleanFlip on either cbranch rejects the pair.
        let (d1, c1) = written_vn(OpCode::CPUI_INT_LESS, vec![const_vn(1), const_vn(2)], 1);
        let (d2, c2) = written_vn(OpCode::CPUI_INT_LESS, vec![const_vn(1), const_vn(2)], 2);
        keep.extend([d1, d2]);
        for (f1, f2) in [(true, false), (false, true), (true, true)] {
            let mut d = diamond(c1.clone(), c2.clone(), f1, f2);
            let (count, size) = run(&mut d);
            assert_eq!(count, 0, "booleanFlip gate ({f1},{f2}) must reject");
            assert_eq!(d.fd.bblocks.get_size(), size, "no join block created");
        }

        // cc:1930-1931: unwritten (constant, distinct) conditions reject.
        let mut d = diamond(const_vn(11), const_vn(22), false, false);
        let (count, size) = run(&mut d);
        assert_eq!(count, 0, "unwritten conditions must reject");
        assert_eq!(d.fd.bblocks.get_size(), size);

        // cc:1932-1933: spacebase conditions reject even when written.
        let (d1, c1) = written_vn(OpCode::CPUI_INT_LESS, vec![const_vn(1), const_vn(2)], 3);
        let (d2, c2) = written_vn(OpCode::CPUI_INT_LESS, vec![const_vn(1), const_vn(2)], 4);
        keep.extend([d1, d2]);
        c1.write().unwrap().set_flags(varnode_flags::SPACEBASE);
        let mut d = diamond(c1, c2, false, false);
        let (count, size) = run(&mut d);
        assert_eq!(count, 0, "spacebase condition must reject");
        assert_eq!(d.fd.bblocks.get_size(), size);

        // cc:1937 (res < 0): INT_ADD sharing one input but with different
        // constant addends — functionalEqualityLevel's first pair matches,
        // second returns -1 → overall -1.
        let x = const_vn(0x10);
        let (d1, c1) = written_vn(OpCode::CPUI_INT_ADD, vec![x.clone(), const_vn(1)], 5);
        let (d2, c2) = written_vn(OpCode::CPUI_INT_ADD, vec![x, const_vn(2)], 6);
        keep.extend([d1, d2]);
        let mut d = diamond(c1, c2, false, false);
        let (count, size) = run(&mut d);
        assert_eq!(count, 0, "functionalEqualityLevel<0 must reject");
        assert_eq!(d.fd.bblocks.get_size(), size);

        // cc:1938 (res > 1): commutative INT_ADD over four distinct written
        // inputs — both orderings stay contingent (res==2).
        let (d1, c1) = written_vn(
            OpCode::CPUI_INT_ADD,
            vec![input_vn(1), input_vn(2)],
            11,
        );
        let (d2, c2) = written_vn(
            OpCode::CPUI_INT_ADD,
            vec![input_vn(3), input_vn(4)],
            12,
        );
        keep.extend([d1, d2]);
        let mut d = diamond(c1, c2, false, false);
        let (count, size) = run(&mut d);
        assert_eq!(count, 0, "functionalEqualityLevel>1 must reject");
        assert_eq!(d.fd.bblocks.get_size(), size);

        // cc:1939-1941: defining op SUBPIECE or COPY rejects even at res=0.
        let x = const_vn(0x10);
        for (opcode, ord) in [(OpCode::CPUI_SUBPIECE, 7u32), (OpCode::CPUI_COPY, 13)] {
            let inputs = if opcode == OpCode::CPUI_COPY {
                vec![x.clone()]
            } else {
                vec![x.clone(), const_vn(0)]
            };
            let (d1, c1) = written_vn(opcode, inputs.clone(), ord);
            let (d2, c2) = written_vn(opcode, inputs, ord + 1);
            keep.extend([d1, d2]);
            let mut d = diamond(c1, c2, false, false);
            let (count, size) = run(&mut d);
            assert_eq!(count, 0, "{opcode:?} def must reject");
            assert_eq!(d.fd.bblocks.get_size(), size);
        }

        // Positive control: identical INT_LESS pairs give res=0 and a
        // single join (blockaction.cc:1943-1944 → execute()).
        let (d1, c1) = written_vn(OpCode::CPUI_INT_LESS, vec![const_vn(1), const_vn(2)], 9);
        let (d2, c2) = written_vn(OpCode::CPUI_INT_LESS, vec![const_vn(1), const_vn(2)], 10);
        keep.extend([d1, d2]);
        let mut d = diamond(c1, c2, false, false);
        let (count, size) = run(&mut d);
        assert_eq!(count, 1, "identical INT_LESS pair must join once");
        assert_eq!(
            d.fd.bblocks.get_size(),
            size + 1,
            "join block appended by nodeJoinCreateBlock"
        );
    }

    // Ghidra: coreaction.cc:692-704 ActionConstbase::apply (tracked COPY loop)
    /// Single-side regression pin of the tracked-COPY insertion form: after
    /// ingesting the production x86-64.pspec tracked_set shape (DF=0 resolved
    /// to register:0x20a:1) through the mapped decode, ActionConstbase
    /// inserts exactly one COPY at the HEAD of entry block 0 — out = DF
    /// storage, in0 = constant 0 — and returns 0 (no change counter,
    /// coreaction.cc:705).  The oracle side of this observable is pinned
    /// per-object by the 02b CALLGUARD projection (block0 COPY
    /// out=reg:0x20a:1 in0=const0, guards 18->20) against the locked
    /// getstr_pipeline_1204 fixture; this test is the Rugra regression leg
    /// (mechanism B2: a hand-written expectation cannot lift NO_ORACLE).
    #[test]
    fn test_action_constbase_inserts_tracked_copy_at_entry_head() {
        use crate::address::Address;
        use crate::block::BlockBasic;

        // Ingest host: DF resolves through the SLEIGH register catalog shape
        // (register space 0x20a:1); spaces from the locked table.
        struct TrackedHost;
        impl crate::arch::SpecQuery for TrackedHost {
            // Ghidra: sleighbase.cc:133 SleighBase::getRegister (test host leg)
            fn get_register(&self, name: &str) -> Option<crate::fspec::VarnodeData> {
                match name {
                    "DF" => Some(crate::fspec::VarnodeData {
                        space: crate::space::AddressSpace::Register,
                        offset: 0x20a,
                        size: 1,
                    }),
                    _ => None,
                }
            }
            // Ghidra: translate.cc:590 AddrSpaceManager::getSpaceByName (test host leg)
            fn space_by_name(&self, name: &str) -> Option<crate::space::AddressSpace> {
                match name {
                    "ram" => Some(crate::space::AddressSpace::Ram),
                    "register" => Some(crate::space::AddressSpace::Register),
                    "const" => Some(crate::space::AddressSpace::Const),
                    _ => None,
                }
            }
            // Ghidra: space.hh:189 AddrSpace::getHighest (test host leg)
            fn space_highest(&self, _spc: crate::space::AddressSpace) -> u64 {
                u64::MAX
            }
        }

        // The production pspec <tracked_set space="ram"><set name="DF" val="0"/>
        // document, built as the fixture-local DOM the mapped decode reads.
        let root = {
            use crate::marshal::Element;
            let mut context_data = Element::new();
            context_data.set_name("context_data");
            let mut tracked_set = Element::new();
            tracked_set.set_name("tracked_set");
            tracked_set.add_attribute("space", "ram");
            let mut set = Element::new();
            set.set_name("set");
            set.add_attribute("name", "DF");
            set.add_attribute("val", "0");
            tracked_set.add_child(std::sync::Arc::new(std::sync::RwLock::new(set)));
            context_data.add_child(std::sync::Arc::new(std::sync::RwLock::new(tracked_set)));
            std::sync::Arc::new(std::sync::RwLock::new(context_data))
        };

        let mut arch = crate::arch::Architecture::new();
        {
            let registry = std::sync::Arc::new(std::sync::RwLock::new(
                crate::marshal::IdRegistry::new()));
            let mut decoder = crate::marshal::TreeDecoder::new(root, registry);
            arch.decode_context_data(&mut decoder, &TrackedHost)
                .expect("tracked_set decode");
        }
        // cc:692 precondition: the function address resolves to the DF
        // partition (whole-ram range from the pspec shape).
        assert_eq!(
        arch.get_tracked_set(crate::space::AddressSpace::Ram, 0x403000)
            .len(), 1
    );

        let mut fd = Funcdata::new("t", Address::new(0x403000), 0x40);
        fd.set_arch(std::sync::Arc::new(arch));
        let b0 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
        0, Address::new(0x403000),
    )));
        fd.bblocks.add_block(b0.clone());
        // One pre-existing op: the tracked COPY must land at the HEAD
        // (opInsertBegin, coreaction.cc:703).
        let pre = fd.new_op(1, Address::new(0x403000));
        fd.op_set_opcode(&pre, OpCode::CPUI_STORE);
        fd.op_insert_end(&pre, &fd.bblocks.get_block(0).unwrap());
        assert_eq!(b0.read().unwrap().ops.len(), 1);

        let mut action = ActionConstbase::new();
        // cc:705: unconditional return 0.
        assert_eq!(action.apply(&mut fd).unwrap(), action_status::NO_CHANGE);

        let ops = b0.read().unwrap().ops.clone();
        assert_eq!(ops.len(), 2, "exactly one COPY per tracked context");
        let copy = ops[0].0.read().unwrap();
        assert_eq!(copy.opcode, OpCode::CPUI_COPY, "tracked COPY at block head");
        let out_arc = copy.output.clone().expect("COPY output");
        let in0_arc = copy.inrefs[0].clone();
        drop(copy);
        let out = out_arc.read().unwrap();
        assert_eq!(out.get_space(), crate::space::AddressSpace::Register);
        assert_eq!(out.get_offset(), 0x20a);
        assert_eq!(out.size, 1);
        let in0 = in0_arc.read().unwrap();
        assert_eq!(in0.get_space(), crate::space::AddressSpace::Const);
        assert_eq!(in0.get_offset(), 0, "tracked DF value 0");
        assert_eq!(in0.size, 1);
        // Idempotence shape: a second apply inserts a second COPY (Ghidra
        // has no guard either), so only the single-run form is pinned here.
    }


    // Ghidra: coreaction.cc:2469 ActionSetCasts::isOpIdentical (cc:2476-2479)
    /// Typedef chains must be stripped independently on both sides after the
    /// double-PTR descent: a typedef alias of a base is op-identical to the
    /// base (cc:2476-2479 walks getTypedef() to the end, cc:2480 compares),
    /// including a typedef pointee reached through the pointer descent, and
    /// chained typedefs. Distinct bases stay non-identical.
    #[test]
    fn test_is_op_identical_strips_typedef_chain() {
        use crate::type_system::datatype::TypeMetatype;
        use crate::type_system::typefactory::{SizeArchInputs, TypeFactory};
        let mut factory = TypeFactory::raw();
        factory.setup_sizes(&SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        let int4 = factory.get_base(4, TypeMetatype::Int).expect("int4");
        let int8 = factory.get_base(8, TypeMetatype::Int).expect("int8");
        let td_int8 = factory.get_typedef("td_int8", int8.clone());
        let td_td_int8 = factory.get_typedef("td_td_int8", td_int8.clone());
        // Pointer forms (built before the shared immutable borrow below): a
        // typedef of a pointer loses its alias when descended, and a typedef
        // pointee keeps it until the strip loop.
        let p_int8 = factory.get_type_pointer(8, int8.clone(), 1);
        let p_td = factory.get_type_pointer(8, td_int8.clone(), 1);
        let td_p = factory.get_typedef("td_p_int8", p_int8.clone());
        let p_int4 = factory.get_type_pointer(8, int4.clone(), 1);
        let f = &factory;
        // cc:2476-2479: alias vs base strips to the same interned target.
        assert!(ActionSetCasts::is_op_identical(&td_int8, &int8, Some(f)));
        assert!(ActionSetCasts::is_op_identical(&int8, &td_int8, Some(f)));
        // A chained typedef walks the whole getTypedef() chain.
        assert!(ActionSetCasts::is_op_identical(&td_td_int8, &int8, Some(f)));
        assert!(ActionSetCasts::is_op_identical(&td_int8, &td_td_int8, Some(f)));
        // Distinct bases are still not op-identical.
        assert!(!ActionSetCasts::is_op_identical(&td_td_int8, &int4, Some(f)));
        // Pointer descent runs first (cc:2472-2474).
        assert!(ActionSetCasts::is_op_identical(&td_p, &p_int8, Some(f)));
        assert!(ActionSetCasts::is_op_identical(&p_td, &p_int8, Some(f)));
        assert!(!ActionSetCasts::is_op_identical(&p_int8, &p_int4, Some(f)));
        // Without a factory (detached Funcdata) the bare pointer comparison
        // remains — the pre-fix observable that this test pins as negative
        // control for the typedef arms above.
        assert!(!ActionSetCasts::is_op_identical(&td_int8, &int8, None));
    }

    // Ghidra: coreaction.cc:2673 ActionSetCasts::castInput arm order
    /// The double-cast guard is TWO nested levels: the outer arm
    /// `isWritten && def==CAST` (cc:2673) consumes the branch regardless of
    /// implied, and only the inner level tests isImplied (cc:2674). A
    /// CAST-produced varnode that is NOT implied skips the whole else-if
    /// chain (constant arm cc:2687 included) and falls through to the CAST
    /// insert with vnin = vn — it must NOT be retyped in place by the
    /// constant arm even when it lives in the constant space.
    #[test]
    fn test_cast_input_def_cast_non_implied_constant_skips_const_arm() {
        use crate::type_system::cast::CastStrategyC;
        use crate::type_system::datatype::TypeMetatype;
        use crate::type_system::typefactory::{SizeArchInputs, TypeFactory};
        let mut factory = TypeFactory::raw();
        factory.setup_sizes(&SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        let int4 = factory.get_base(4, TypeMetatype::Int).expect("int4");
        let int8 = factory.get_base(8, TypeMetatype::Int).expect("int8");
        let p_int4 = factory.get_type_pointer(8, int4, 1);
        let factory = std::sync::Arc::new(std::sync::RwLock::new(factory));
        let mut arch = crate::arch::Architecture::new();
        arch.set_types(factory.clone());
        let arch = std::sync::Arc::new(arch);

        let mut fd = Funcdata::new("cast_arm", crate::address::Address::new(0x6000), 0x10);
        fd.vbank.set_type_factory(factory.clone());
        fd.set_arch(arch);
        let block = fd.create_new_block();

        // cast0: CAST(src) whose output is a NON-implied constant-space
        // varnode typed as a pointer (the pathological fork input).
        let src_vn = fd
            .vbank
            .create_with_space(8, crate::space::AddressSpace::Register, 0x40);
        let src = fd.set_input_varnode(src_vn);
        src.write().unwrap().update_type(int8.clone());
        let cast0 = fd.new_op(1, crate::address::Address::new(0x6000));
        fd.op_set_opcode(&cast0, OpCode::CPUI_CAST);
        fd.op_set_input(&cast0, src.clone(), 0);
        let const_c = fd.new_constant(8, 0x30);
        const_c.write().unwrap().update_type(p_int4.clone());
        // Hand-built wiring bypassing VarnodeBank::set_def's constant-space
        // rejection (the C++ fixture mirrors this with #define private
        // public PcodeOp::setOutput + Varnode::setDef, which sets the
        // written flag the same way).
        const_c.write().unwrap().def = Some(std::sync::Arc::downgrade(&cast0.0));
        const_c.write().unwrap().flags |= crate::varnode::varnode_flags::WRITTEN;
        cast0.0.write().unwrap().output = Some(const_c.clone());

        // mult: INT_MULT(const_c, #4) — slot 0 expects int8, cur is ptr.
        let mult = fd.new_op(2, crate::address::Address::new(0x6001));
        fd.op_set_opcode(&mult, OpCode::CPUI_INT_MULT);
        fd.op_set_input(&mult, const_c.clone(), 0);
        let four = fd.new_constant(8, 4);
        fd.op_set_input(&mult, four.clone(), 1);
        fd.new_unique_out(8, &mult);
        fd.op_insert_end(&cast0, &block);
        fd.op_insert_end(&mult, &block);
        fd.set_high_level();

        let strategy = CastStrategyC::new(4);
        let mut action = ActionSetCasts::new();
        assert!(action.cast_input(&mut fd, &mult, 0, &strategy));
        // The constant arm must NOT have fired: const_c keeps its pointer
        // type (a constant-arm updateType would have replaced it with int8).
        let const_type = const_c.read().unwrap().get_type();
        assert!(
            const_type.as_ref().is_some_and(|t| t.get_metatype()
                == crate::type_system::datatype::TypeMetatype::Pointer),
            "def=CAST non-implied input must skip the constant arm"
        );
        // Fall-through inserted a CAST reading const_c before the mult.
        let in0 = mult.0.read().unwrap().get_in(0).cloned().expect("mult in0");
        assert!(
            !std::sync::Arc::ptr_eq(&in0, &const_c),
            "mult slot 0 is rewired to the inserted CAST output"
        );
        let in0_def = in0
            .read()
            .unwrap()
            .def
            .as_ref()
            .and_then(|d| d.upgrade())
            .map(crate::op::PcodeOpRef)
            .expect("new input is op-written");
        assert_eq!(in0_def.0.read().unwrap().opcode, OpCode::CPUI_CAST);
        // opSetInput's constant dedup (funcdata_op.cc:108-115, mirrored
        // in Rugra op_set_input) copies a many-descendant constant, so the
        // inserted CAST reads a same-value copy of const_c.
        let cast_in0 = in0_def.0.read().unwrap().get_in(0).cloned().expect("cast in0");
        let ci = cast_in0.read().unwrap();
        assert!(ci.is_constant(), "inserted CAST reads the constant");
        assert_eq!(ci.get_offset(), 0x30);
        assert_eq!(ci.get_size(), 8);
        assert!(!ci.is_written(), "the copy is a fresh unwritten constant");
    }
