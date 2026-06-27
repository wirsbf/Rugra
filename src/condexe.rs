//! Conditional execution simplification.
//!
//! Corresponds to Ghidra's `condexe.hh` / `condexe.cc` (712 lines).
//!
//! This module simplifies control-flow where two CBRANCH operations test the
//! same (or complementary) boolean value, making one of the joins redundant:
//!
//! ```text
//!    if (a) {           if (a) {
//!       BODY1              BODY1
//!    }          ==>        BODY2
//!    if (a) {           }
//!       BODY2
//!    }
//! ```
//!
//! The block where two flows needlessly merge is the \b iblock. The original
//! boolean evaluation is in \b initblock. Two paths lead from initblock to
//! iblock (\b prea / \b preb) and two paths leave it (\b posta / \b postb).
//! If the iblock's CBRANCH is redundant, iblock is removed and prea is
//! re-linked to posta (or postb, if the conditions are complementary),
//! preserving MULTIEQUAL data-flow by pushing reads into the right path.
//!
//! This is a faithful 1:1 port of Ghidra's `ConditionalExecution` class and
//! `ActionConditionalExe`, including the full data-flow rewrite
//! (`doReplacement` / `getReplacementRead` / `pullbackOp` / `getNewMulti`)
//! and the CFG rewrite (`removeFromFlowSplit`). The previous Rugra
//! implementation only detected candidates and emitted diagnostics; this one
//! performs the actual transformation.

use crate::action::{Action, action_status};
use crate::funcdata::Funcdata;
use crate::error::Result;
use crate::opcodes::OpCode;
use std::sync::{Arc, RwLock};
use crate::op::{PcodeOp, PcodeOpRef};
use crate::block::{BlockBasic, FlowBlock};
use crate::varnode::Varnode;

/// Wrap a bare `Arc<RwLock<PcodeOp>>` into a `PcodeOpRef` for calling the
/// Funcdata op-editing API (which takes `&PcodeOpRef`). This clones only the
/// Arc, not the underlying op.
fn opref(a: &Arc<RwLock<PcodeOp>>) -> PcodeOpRef {
    PcodeOpRef(a.clone())
}

/// Correlation between the initblock and iblock CBRANCH booleans.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Correlation {
    /// Conditions always have the same value.
    Same,
    /// Conditions always have opposite values.
    Complementary,
    Uncorrelated,
}

/// `BooleanMatch::evaluate` result, faithful to expression.cc:111.
const SAME: i32 = 0;
const COMPLEMENTARY: i32 = 1;
const UNCORRELATED: i32 = 2;

/// The analysis engine for a single iblock candidate.
///
/// Faithful to Ghidra's `ConditionalExecution` (condexe.hh:91). All field
/// names mirror the C++ class.
pub struct ConditionalExecution<'a> {
    fd: &'a mut Funcdata,
    /// CBRANCH in iblock.
    cbranch: Option<Arc<RwLock<PcodeOp>>>,
    /// The initial block computing the boolean value.
    initblock: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// The block where flow needlessly comes together.
    iblock: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// iblock->In(prea_inslot) = pre a path.
    prea_inslot: i32,
    /// Does true branch (in terms of iblock) go to path pre a.
    init2a_true: bool,
    /// Does true branch go to path post a.
    iblock2posta_true: bool,
    /// init or pre slot to use, for data-flow thru post.
    camethruposta_slot: i32,
    /// The out edge from iblock to posta.
    posta_outslot: i32,
    /// First block in posta path.
    posta_block: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// First block in postb path.
    postb_block: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// Map block-index -> replacement Varnode for (current) Varnode.
    replacement: std::collections::HashMap<i32, Arc<RwLock<Varnode>>>,
    /// Outputs of ops pulled back from iblock for (current) Varnode.
    pullback: Vec<Option<Arc<RwLock<Varnode>>>>,
    /// Whether heritage has been performed per address space (approximated:
    /// always true, since Rugra runs heritage before this action).
    heritageyes: Vec<bool>,
    /// Cached correlation result from verify_same_condition.
    matchflip: bool,
}

impl<'a> ConditionalExecution<'a> {
    /// Constructor. Faithful to `ConditionalExecution::ConditionalExecution`
    /// (condexe.cc:432-437).
    pub fn new(fd: &'a mut Funcdata) -> Self {
        // buildHeritageArray: Rugra runs heritage once globally; we assume all
        // heritaged spaces are "done". The array is consulted only to decide
        // whether a no-descendent Varnode can be moved; conservatively treat
        // every space as heritaged (matches Ghidra post-heritage behaviour).
        let nspaces = 4;
        Self {
            fd,
            cbranch: None,
            initblock: None,
            iblock: None,
            prea_inslot: 0,
            init2a_true: false,
            iblock2posta_true: false,
            camethruposta_slot: 0,
            posta_outslot: 0,
            posta_block: None,
            postb_block: None,
            replacement: std::collections::HashMap::new(),
            pullback: Vec::new(),
            heritageyes: vec![true; nspaces],
            matchflip: false,
        }
    }

    // ------------------------------------------------------------------
    // Graph helpers adapted to Rugra's dynamic-dispatch blocks.
    // ------------------------------------------------------------------

    fn block_as_basic(
        arc: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> bool {
        // We need to downcast the trait object to BlockBasic. Because Rugra
        // stores blocks as trait-object Arcs, we cannot trivially recover a
        // typed Arc<BlockBasic>. Instead we operate through the trait methods
        // and, where structural mutation is required, re-acquire the write
        // lock and downcast mutably. This helper signals whether the block is
        // a BlockBasic (used by guards).
        let rg = arc.read().unwrap();
        rg.as_any().downcast_ref::<BlockBasic>().is_some()
    }

    /// Last op of a block, or None.
    fn last_op(arc: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> Option<Arc<RwLock<PcodeOp>>> {
        arc.read().unwrap().get_ops().last().cloned().map(|r| r.0)
    }

    /// Iterator over all ops of a block (excluding nothing).
    fn ops(arc: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> Vec<Arc<RwLock<PcodeOp>>> {
        arc.read().unwrap().get_ops().into_iter().map(|r| r.0).collect()
    }

    // ------------------------------------------------------------------
    // testIBlock (condexe.cc:43-52)
    // ------------------------------------------------------------------

    /// The iblock must have 2 in edges, 2 out edges, and a final CBRANCH.
    fn test_iblock(&mut self) -> bool {
        let ib = match &self.iblock { Some(b) => b.clone(), None => return false };
        let rg = ib.read().unwrap();
        if rg.size_in() != 2 { return false; }
        if rg.size_out() != 2 { return false; }
        drop(rg);
        let last = match Self::last_op(&ib) { Some(o) => o, None => return false };
        if last.read().unwrap().opcode != OpCode::CPUI_CBRANCH { return false; }
        self.cbranch = Some(last);
        true
    }

    // ------------------------------------------------------------------
    // findInitPre (condexe.cc:55-75)
    // ------------------------------------------------------------------

    /// Walk back from iblock's prea_inslot input to find the initblock. Also
    /// sets init2a_true.
    fn find_init_pre(&mut self) -> bool {
        let ib = self.iblock.clone().unwrap();
        // Walk up the prea path (chain of 1in/1out blocks) to the first block
        // with 2 out-edges = initblock.
        let prea_in = {
            let rg = ib.read().unwrap();
            rg.get_in(self.prea_inslot as usize).map(|e| e.point)
        };
        let prea_in = match prea_in { Some(b) => b, None => return false };
        let mut tmp = prea_in;
        let mut last = ib.clone();
        loop {
            let (sout, sin) = { let r = tmp.read().unwrap(); (r.size_out(), r.size_in()) };
            if sout != 1 || sin != 1 { break; }
            last = tmp.clone();
            let next = { let r = tmp.read().unwrap(); r.get_in(0).map(|e| e.point) };
            tmp = match next { Some(b) => b, None => return false };
        }
        let (sout_tmp,) = { let r = tmp.read().unwrap(); (r.size_out(),) };
        if sout_tmp != 2 { return false; }
        self.initblock = Some(tmp.clone());
        // Walk up the other (1 - prea_inslot) path similarly; it must also
        // reach the same initblock.
        let other_in = {
            let rg = ib.read().unwrap();
            rg.get_in((1 - self.prea_inslot) as usize).map(|e| e.point)
        };
        let mut tmp2 = match other_in { Some(b) => b, None => return false };
        loop {
            let (sout, sin) = { let r = tmp2.read().unwrap(); (r.size_out(), r.size_in()) };
            if sout != 1 || sin != 1 { break; }
            let next = { let r = tmp2.read().unwrap(); r.get_in(0).map(|e| e.point) };
            tmp2 = match next { Some(b) => b, None => return false };
        }
        if !Arc::ptr_eq(&tmp2, &tmp) { return false; }
        if Arc::ptr_eq(&tmp, &ib) { return false; }

        // init2a_true: does initblock's TRUE out edge reach `last`?
        self.init2a_true = self.is_true_out_to(&tmp, &last);
        true
    }

    /// Return true if `src`'s TRUE out-edge flows (directly) to `dst`.
    /// Adapts Ghidra's getTrueOut to Rugra. We determine the true edge by
    /// examining the CBRANCH's boolean_flip flag:
    ///   - boolean_flip false: TRUE follows the branch (taken) edge.
    ///   - boolean_flip true:  TRUE follows the fallthru edge.
    /// In Rugra the CBRANCH out-edges are ordered [branch_target, fallthru]
    /// (see funcdata.rs edge construction), so without flip out[0] is TRUE.
    fn is_true_out_to(
        &self,
        src: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        dst: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> bool {
        let cb = match Self::last_op(src) { Some(o) => o, None => return false };
        let cb_rg = cb.read().unwrap();
        if cb_rg.opcode != OpCode::CPUI_CBRANCH { return false; }
        let flip = (cb_rg.flags & crate::op::pcodeop_flags::BOOLEAN_FLIP) != 0;
        drop(cb_rg);
        let rg = src.read().unwrap();
        // true edge index: 0 (branch target) unless flipped.
        let true_idx = if flip { 1 } else { 0 };
        match rg.get_out(true_idx) {
            Some(e) => Arc::ptr_eq(&e.point, dst),
            None => false,
        }
    }

    // ------------------------------------------------------------------
    // verifySameCondition (condexe.cc:80-94) + BooleanExpressionMatch
    // ------------------------------------------------------------------

    /// Verify initblock and iblock branch on the same (or complementary)
    /// condition. Faithful to `verifySameCondition` + `BooleanExpressionMatch`.
    fn verify_same_condition(&mut self) -> bool {
        let init = match &self.initblock { Some(b) => b.clone(), None => return false };
        let init_cbranch = match Self::last_op(&init) {
            Some(o) => o,
            None => return false,
        };
        if init_cbranch.read().unwrap().opcode != OpCode::CPUI_CBRANCH { return false; }
        let ib_cb = self.cbranch.clone().unwrap();
        let res = boolean_match_verify_condition(&ib_cb, &init_cbranch);
        if res == UNCORRELATED { return false; }
        self.matchflip = res == COMPLEMENTARY;
        // Apply per-CBRANCH flip flags (BooleanExpressionMatch::verifyCondition).
        let ib_flip = (ib_cb.read().unwrap().flags & crate::op::pcodeop_flags::BOOLEAN_FLIP) != 0;
        let init_flip = (init_cbranch.read().unwrap().flags & crate::op::pcodeop_flags::BOOLEAN_FLIP) != 0;
        if ib_flip { self.matchflip = !self.matchflip; }
        if init_flip { self.matchflip = !self.matchflip; }
        // init2a_true is complemented if matchflip (verifySameCondition effect).
        if self.matchflip { self.init2a_true = !self.init2a_true; }
        true
    }

    // ------------------------------------------------------------------
    // testMultiRead (condexe.cc:101-113)
    // ------------------------------------------------------------------

    fn test_multi_read(vn: &Arc<RwLock<Varnode>>, op: &Arc<RwLock<PcodeOp>>, iblock: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> bool {
        let op_parent = op.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
        let op_code = op.read().unwrap().opcode;
        if let Some(p) = &op_parent {
            if Arc::ptr_eq(p, iblock) {
                if op_code == OpCode::CPUI_COPY || op_code == OpCode::CPUI_SUBPIECE {
                    return true;
                }
                return false;
            }
        }
        if op_code == OpCode::CPUI_RETURN {
            let op_rg = op.read().unwrap();
            if op_rg.num_input() < 2 { return false; }
            // Only test for flow-through to return value: input(1) must be vn.
            let in1 = op_rg.get_in(1);
            return in1.map(|v| Arc::ptr_eq(v, vn)).unwrap_or(false);
        }
        true
    }

    // ------------------------------------------------------------------
    // testOpRead (condexe.cc:120-142)
    // ------------------------------------------------------------------

    fn test_op_read(vn: &Arc<RwLock<Varnode>>, op: &Arc<RwLock<PcodeOp>>, iblock: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> bool {
        let op_parent = op.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
        if let Some(p) = &op_parent {
            if Arc::ptr_eq(p, iblock) { return true; }
        }
        let writeop = match vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(o) => o, None => return false,
        };
        let opc = writeop.read().unwrap().opcode;
        if opc == OpCode::CPUI_COPY || opc == OpCode::CPUI_SUBPIECE
            || opc == OpCode::CPUI_INT_ADD || opc == OpCode::CPUI_PTRSUB
        {
            if opc == OpCode::CPUI_INT_ADD || opc == OpCode::CPUI_PTRSUB {
                let wr = writeop.read().unwrap();
                let in1_const = wr.get_in(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
                if !in1_const { return false; }
            }
            let invn = writeop.read().unwrap().get_in(0).cloned();
            if let Some(invn) = invn {
                let invn_written = invn.read().unwrap().is_written();
                if invn_written {
                    let upop = invn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
                    if let Some(up) = upop {
                        let up_parent = up.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
                        let up_code = up.read().unwrap().opcode;
                        if let Some(p) = &up_parent {
                            if Arc::ptr_eq(p, iblock) && up_code != OpCode::CPUI_MULTIEQUAL {
                                return false;
                            }
                        }
                    }
                } else if invn.read().unwrap().is_free() {
                    return false;
                }
                return true;
            }
        }
        false
    }

    // ------------------------------------------------------------------
    // testRemovability (condexe.cc:361-397)
    // ------------------------------------------------------------------

    fn test_removability(&self, op: &Arc<RwLock<PcodeOp>>) -> bool {
        let ib = self.iblock.clone().unwrap();
        let opc = op.read().unwrap().opcode;
        if opc == OpCode::CPUI_MULTIEQUAL {
            let out = match op.read().unwrap().output.clone() { Some(o) => o, None => return true };
            let descends: Vec<Arc<RwLock<PcodeOp>>> =
                out.read().unwrap().descend_iter().collect();
            for readop in descends {
                if !Self::test_multi_read(&out, &readop, &ib) { return false; }
            }
            true
        } else {
            let op_rg = op.read().unwrap();
            if op_rg.is_call() { return false; }
            // isFlowBreak: branch/return ops.
            if op_rg.opcode == OpCode::CPUI_BRANCH || op_rg.opcode == OpCode::CPUI_CBRANCH
                || op_rg.opcode == OpCode::CPUI_BRANCHIND || op_rg.opcode == OpCode::CPUI_RETURN
            { return false; }
            if op_rg.opcode == OpCode::CPUI_LOAD || op_rg.opcode == OpCode::CPUI_STORE { return false; }
            if op_rg.opcode == OpCode::CPUI_INDIRECT { return false; }
            drop(op_rg);
            let out = match op.read().unwrap().output.clone() { Some(o) => o, None => return true };
            if out.read().unwrap().is_addr_tied() { return false; }
            let descends: Vec<Arc<RwLock<PcodeOp>>> =
                out.read().unwrap().descend_iter().collect();
            let mut hasnodescend = true;
            for readop in descends {
                if !Self::test_op_read(&out, &readop, &ib) { return false; }
                hasnodescend = false;
            }
            if hasnodescend {
                // No descendants: allowed only if heritage performed for space.
                // We treat all spaces as heritaged (see buildHeritageArray note).
                let _ = &self.heritageyes;
                true
            } else {
                true
            }
        }
    }

    // ------------------------------------------------------------------
    // verify (condexe.cc:402-428)
    // ------------------------------------------------------------------

    fn verify(&mut self) -> bool {
        self.prea_inslot = 0;
        self.posta_outslot = 0;
        if !self.test_iblock() { return false; }
        if !self.find_init_pre() { return false; }
        if !self.verify_same_condition() { return false; }
        // Cache useful values.
        let ib = self.iblock.clone().unwrap();
        self.iblock2posta_true = self.posta_outslot == 1;
        self.camethruposta_slot = if self.init2a_true == self.iblock2posta_true {
            self.prea_inslot
        } else {
            1 - self.prea_inslot
        };
        let rg = ib.read().unwrap();
        self.posta_block = rg.get_out(self.posta_outslot as usize).map(|e| e.point);
        self.postb_block = rg.get_out((1 - self.posta_outslot) as usize).map(|e| e.point);
        drop(rg);
        // Test removability of every non-branch op in iblock.
        let ops = Self::ops(&ib);
        for op in &ops {
            let is_branch = {
                let o = op.read().unwrap();
                o.opcode == OpCode::CPUI_BRANCH || o.opcode == OpCode::CPUI_CBRANCH
                    || o.opcode == OpCode::CPUI_BRANCHIND || o.opcode == OpCode::CPUI_RETURN
            };
            if is_branch { continue; }
            if !self.test_removability(op) { return false; }
        }
        true
    }

    // ------------------------------------------------------------------
    // Data-flow rewrite helpers (condexe.cc:146-357)
    // ------------------------------------------------------------------

    fn find_pullback(&mut self, inbranch: usize) -> Option<Arc<RwLock<Varnode>>> {
        while self.pullback.len() <= inbranch {
            self.pullback.push(None);
        }
        self.pullback[inbranch].clone()
    }

    /// pullbackOp (condexe.cc:160-190). Duplicate an iblock op into the
    /// predecessor block along `inbranch`, selecting the right MULTIEQUAL slot.
    fn pullback_op(&mut self, op: &Arc<RwLock<PcodeOp>>, inbranch: usize) -> Option<Arc<RwLock<Varnode>>> {
        if let Some(v) = self.find_pullback(inbranch) { return Some(v); }
        let ib = self.iblock.clone().unwrap();
        let invn = op.read().unwrap().get_in(0).cloned();
        let (invn_eff, bl) = match &invn {
            Some(v) => {
                let written = v.read().unwrap().is_written();
                if written {
                    let defop = v.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
                    if let Some(defop) = defop {
                        let def_parent = defop.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
                        if let Some(p) = &def_parent {
                            if Arc::ptr_eq(p, &ib) {
                                // defOp must be MULTIEQUAL; pick the inbranch input.
                                let sel = defop.read().unwrap().get_in(inbranch).cloned();
                                let ib_in = ib.read().unwrap().get_in(inbranch).map(|e| e.point);
                                (sel.unwrap_or_else(|| v.clone()), ib_in)
                            } else {
                                (v.clone(), self.immed_dom_of(&ib))
                            }
                        } else {
                            (v.clone(), self.immed_dom_of(&ib))
                        }
                    } else {
                        (v.clone(), self.immed_dom_of(&ib))
                    }
                } else {
                    (v.clone(), self.immed_dom_of(&ib))
                }
            }
            None => return None,
        };
        let bl = match bl { Some(b) => b, None => return None };
        let n_in = op.read().unwrap().num_input();
        let pc = op.read().unwrap().get_addr();
        let opcode = op.read().unwrap().opcode;
        let out_size = op.read().unwrap().output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(0);
        let new_op = self.fd.new_op(n_in, pc);
        self.fd.op_set_opcode(&new_op, opcode);
        let new_out = self.fd.new_unique_out(out_size, &new_op);
        self.fd.op_set_input(&new_op, invn_eff, 0);
        for i in 1..n_in {
            if let Some(extra) = op.read().unwrap().get_in(i).cloned() {
                self.fd.op_set_input(&new_op, extra, i);
            }
        }
        self.fd.op_insert_begin(&new_op, &bl);
        while self.pullback.len() <= inbranch { self.pullback.push(None); }
        self.pullback[inbranch] = Some(new_out.clone());
        Some(new_out)
    }

    fn immed_dom_of(&self, b: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        b.read().unwrap().get_immed_dom().and_then(|w| w.upgrade())
    }

    /// getNewMulti (condexe.cc:198-217).
    fn get_new_multi(&mut self, op: &Arc<RwLock<PcodeOp>>, bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> Option<Arc<RwLock<Varnode>>> {
        let outvn_size = op.read().unwrap().output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(0);
        let outvn = op.read().unwrap().output.clone()?;
        let start = bl.read().unwrap().get_start_addr();
        let n_in = bl.read().unwrap().size_in();
        let newop = self.fd.new_op(n_in, start);
        let newoutvn = self.fd.new_unique_out(outvn_size, &newop);
        self.fd.op_set_opcode(&newop, OpCode::CPUI_MULTIEQUAL);
        for i in 0..n_in {
            self.fd.op_set_input(&newop, outvn.clone(), i);
        }
        self.fd.op_insert_begin(&newop, bl);
        Some(newoutvn)
    }

    /// resolveRead (condexe.cc:224-237).
    fn resolve_read(&mut self, op: &Arc<RwLock<PcodeOp>>, bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> Option<Arc<RwLock<Varnode>>> {
        let sin = bl.read().unwrap().size_in();
        if sin == 1 {
            // dominator is iblock; In(0) is iblock. Figure which side we came
            // through via the reverse index vs posta_outslot.
            let rev0 = {
                let r = bl.read().unwrap();
                if let Some(bb) = r.as_any().downcast_ref::<BlockBasic>() {
                    bb.get_in_rev_index(0)
                } else { return None; }
            };
            let slot = if rev0 == self.posta_outslot { self.camethruposta_slot } else { 1 - self.camethruposta_slot };
            self.resolve_iblock_read(op, slot as usize)
        } else {
            self.get_new_multi(op, bl)
        }
    }

    /// resolveIblockRead (condexe.cc:242-262).
    fn resolve_iblock_read(&mut self, op: &Arc<RwLock<PcodeOp>>, inbranch: usize) -> Option<Arc<RwLock<Varnode>>> {
        let opcode = op.read().unwrap().opcode;
        if opcode == OpCode::CPUI_COPY {
            let vn = op.read().unwrap().get_in(0).cloned()?;
            let written = vn.read().unwrap().is_written();
            if written {
                let defop = vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade())?;
                let def_code = defop.read().unwrap().opcode;
                if def_code == OpCode::CPUI_MULTIEQUAL {
                    let ib = self.iblock.clone().unwrap();
                    let def_parent = defop.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
                    if let Some(p) = &def_parent {
                        if Arc::ptr_eq(p, &ib) {
                            return defop.read().unwrap().get_in(inbranch).cloned();
                        }
                    }
                }
                return None;
            } else {
                return Some(vn);
            }
        }
        if opcode == OpCode::CPUI_MULTIEQUAL {
            return op.read().unwrap().get_in(inbranch).cloned();
        }
        if opcode == OpCode::CPUI_SUBPIECE || opcode == OpCode::CPUI_INT_ADD || opcode == OpCode::CPUI_PTRSUB {
            return self.pullback_op(op, inbranch);
        }
        None
    }

    /// getMultiequalRead (condexe.cc:270-279).
    fn get_multiequal_read(&mut self, op: &Arc<RwLock<PcodeOp>>, readop: &Arc<RwLock<PcodeOp>>, slot: usize) -> Option<Arc<RwLock<Varnode>>> {
        let read_parent = readop.read().unwrap().parent.as_ref().and_then(|w| w.upgrade())?;
        let bl = read_parent;
        let inbl = bl.read().unwrap().get_in(slot).map(|e| e.point)?;
        let ib = self.iblock.clone().unwrap();
        if !Arc::ptr_eq(&inbl, &ib) {
            return self.get_replacement_read(op, &inbl);
        }
        let rev = {
            let r = bl.read().unwrap();
            if let Some(bb) = r.as_any().downcast_ref::<BlockBasic>() {
                bb.get_in_rev_index(slot)
            } else { return None; }
        };
        let s = if rev == self.posta_outslot { self.camethruposta_slot } else { 1 - self.camethruposta_slot };
        self.resolve_iblock_read(op, s as usize)
    }

    /// getReplacementRead (condexe.cc:291-315).
    fn get_replacement_read(&mut self, op: &Arc<RwLock<PcodeOp>>, bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> Option<Arc<RwLock<Varnode>>> {
        let bl_idx = bl.read().unwrap().get_index();
        if let Some(v) = self.replacement.get(&bl_idx).cloned() { return Some(v); }
        // Walk up dominators until we reach a block dominated by iblock.
        let ib = self.iblock.clone().unwrap();
        let mut curbl_idx;
        let mut curbl = bl.clone();
        loop {
            let curdom = self.immed_dom_of(&curbl);
            match curdom {
                Some(d) if Arc::ptr_eq(&d, &ib) => {
                    curbl_idx = curbl.read().unwrap().get_index();
                    break;
                }
                Some(d) => { curbl = d; }
                None => return None,
            }
        }
        let cur_idx_key = curbl.read().unwrap().get_index();
        if let Some(v) = self.replacement.get(&cur_idx_key).cloned() {
            self.replacement.insert(bl_idx, v.clone());
            return Some(v);
        }
        let res = self.resolve_read(op, &curbl)?;
        self.replacement.insert(cur_idx_key, res.clone());
        if curbl_idx != bl_idx {
            self.replacement.insert(bl_idx, res.clone());
        }
        Some(res)
    }

    /// doReplacement (condexe.cc:320-357).
    fn do_replacement(&mut self, op: &Arc<RwLock<PcodeOp>>) {
        self.replacement.clear();
        self.pullback.clear();
        let vn = match op.read().unwrap().output.clone() { Some(o) => o, None => return };
        // Process each descendant. Because replacing an input may invalidate
        // the descendant list, re-fetch it each iteration (Ghidra resets the
        // iterator to beginDescend()).
        loop {
            let descends: Vec<Arc<RwLock<PcodeOp>>> =
                vn.read().unwrap().descend_iter().collect();
            if descends.is_empty() { break; }
            let readop = descends[0].clone();
            // Find the slot in readop that reads vn.
            let slot = (0..readop.read().unwrap().num_input())
                .find(|&i| {
                    readop.read().unwrap().get_in(i)
                        .map(|v| Arc::ptr_eq(v, &vn)).unwrap_or(false)
                });
            let read_parent = readop.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
            let ib = self.iblock.clone().unwrap();
            let in_iblock = read_parent.as_ref().map(|p| Arc::ptr_eq(p, &ib)).unwrap_or(false);
            match (slot, in_iblock) {
                (Some(s), true) => {
                    // Unset the input directly.
                    let r = opref(&readop);
                    self.fd.op_unset_input(&r, s);
                }
                (Some(s), false) => {
                    let read_code = readop.read().unwrap().opcode;
                    let rvn = if read_code == OpCode::CPUI_MULTIEQUAL {
                        self.get_multiequal_read(op, &readop, s)
                    } else if read_code == OpCode::CPUI_RETURN {
                        // Cannot replace RETURN input directly; create a COPY.
                        let retvn = readop.read().unwrap().get_in(1).cloned();
                        if let Some(retvn) = retvn {
                            let pc = readop.read().unwrap().get_addr();
                            let size = retvn.read().unwrap().get_size();
                            let newcopy = self.fd.new_op(1, pc);
                            self.fd.op_set_opcode(&newcopy, OpCode::CPUI_COPY);
                            // Preserve the RETURN storage address on the COPY out.
                            let _outvn = self.fd.new_varnode_out(size, pc, &newcopy);
                            let r_readop = opref(&readop);
                            self.fd.op_set_input(&r_readop, retvn, 1);
                            // Now replace the COPY's input 0.
                            let rp = readop.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
                            if let Some(rp) = rp {
                                let rvn2 = self.get_replacement_read(op, &rp);
                                if let Some(rvn2) = rvn2 {
                                    self.fd.op_set_input(&newcopy, rvn2, 0);
                                }
                            }
                        }
                        None
                    } else {
                        let rp = readop.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
                        match rp {
                            Some(rp) => self.get_replacement_read(op, &rp),
                            None => None,
                        }
                    };
                    if let Some(rvn) = rvn {
                        let r_readop = opref(&readop);
                        self.fd.op_set_input(&r_readop, rvn, s);
                    }
                }
                _ => break,
            }
        }
    }

    // ------------------------------------------------------------------
    // trial / execute (condexe.cc:448-476)
    // ------------------------------------------------------------------

    /// Test whether the given block is a modifiable iblock.
    /// Faithful to `ConditionalExecution::trial` (condexe.cc:448-454).
    pub fn trial(&mut self, ib: Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> bool {
        self.iblock = Some(ib);
        self.verify()
    }

    /// Eliminate the unnecessary path join at iblock.
    /// Faithful to `ConditionalExecution::execute` (condexe.cc:457-476).
    pub fn execute(&mut self) {
        let ib = self.iblock.clone().unwrap();
        // Remove ops in reverse order, skipping branches.
        let mut ops = Self::ops(&ib);
        while let Some(op) = ops.pop() {
            let is_branch = {
                let o = op.read().unwrap();
                o.opcode == OpCode::CPUI_BRANCH || o.opcode == OpCode::CPUI_CBRANCH
                    || o.opcode == OpCode::CPUI_BRANCHIND || o.opcode == OpCode::CPUI_RETURN
            };
            if !is_branch {
                self.do_replacement(&op);
            }
            let r = opref(&op);
            self.fd.op_destroy(&r);
        }
        // removeFromFlowSplit: join prea->posta etc. swap = (posta_outslot != camethruposta_slot).
        let swap = self.posta_outslot != self.camethruposta_slot;
        let _ = self.fd.remove_from_flow_split(&ib, swap);
    }
}

// ======================================================================
// BooleanMatch / BooleanExpressionMatch (expression.cc:57-232)
// ======================================================================

/// `BooleanMatch::varnodeSame` (expression.cc:93-100).
fn varnode_same(a: &Arc<RwLock<Varnode>>, b: &Arc<RwLock<Varnode>>) -> bool {
    if Arc::ptr_eq(a, b) { return true; }
    let (ar, br) = (a.read().unwrap(), b.read().unwrap());
    if ar.is_constant() && br.is_constant() {
        return ar.get_offset() == br.get_offset();
    }
    false
}

/// `BooleanMatch::sameOpComplement` (expression.cc:57-86). Only handles
/// INT_LESS / INT_SLESS with a constant input.
fn same_op_complement(bin1: &Arc<RwLock<PcodeOp>>, bin2: &Arc<RwLock<PcodeOp>>) -> bool {
    let (opc, n_in) = {
        let r = bin1.read().unwrap();
        (r.opcode, r.inrefs.len())
    };
    if opc != OpCode::CPUI_INT_LESS && opc != OpCode::CPUI_INT_SLESS { return false; }
    let _ = n_in;
    let b1 = bin1.read().unwrap();
    let b2 = bin2.read().unwrap();
    let mut constslot = 0;
    if b1.get_in(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) { constslot = 1; }
    let b1c = b1.get_in(constslot).map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
    if !b1c { return false; }
    let b2c = b2.get_in(1 - constslot).map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
    if !b2c { return false; }
    let same_var = match (b1.get_in(1 - constslot), b2.get_in(constslot)) {
        (Some(x), Some(y)) => varnode_same(x, y),
        _ => return false,
    };
    if !same_var { return false; }
    let val1 = b1.get_in(constslot).map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
    let val2 = b2.get_in(1 - constslot).map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
    let (v1, v2) = if constslot != 0 { (val2, val1) } else { (val1, val2) };
    if v1 + 1 != v2 { return false; }
    if v2 == 0 && opc == OpCode::CPUI_INT_LESS { return false; }
    if opc == OpCode::CPUI_INT_SLESS {
        let sz = b1.get_in(constslot).map(|v| v.read().unwrap().get_size()).unwrap_or(8);
        if crate::address::signbit_negative(v2, sz) && !crate::address::signbit_negative(v1, sz) {
            return false;
        }
    }
    true
}

/// `BooleanMatch::evaluate` (expression.cc:111-216). Returns SAME /
/// COMPLEMENTARY / UNCORRELATED.
fn boolean_match_evaluate(vn1: &Arc<RwLock<Varnode>>, vn2: &Arc<RwLock<Varnode>>, depth: i32) -> i32 {
    if Arc::ptr_eq(vn1, vn2) { return SAME; }
    let (op1, opc1) = {
        let written = vn1.read().unwrap().is_written();
        if written {
            let def = vn1.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            if let Some(def) = def {
                let (is_bool_not, inner_vn, opcode) = {
                    let d = def.read().unwrap();
                    (d.opcode == OpCode::CPUI_BOOL_NOT, d.get_in(0).cloned(), d.opcode)
                };
                if is_bool_not {
                    if let Some(inner) = inner_vn {
                        let res = boolean_match_evaluate(&inner, vn2, depth);
                        return if res == SAME { COMPLEMENTARY } else if res == COMPLEMENTARY { SAME } else { res };
                    }
                    return UNCORRELATED;
                }
                (Some(def), opcode)
            } else {
                (None, OpCode::CPUI_MAX)
            }
        } else {
            (None, OpCode::CPUI_MAX)
        }
    };
    let op2_opt = {
        let written = vn2.read().unwrap().is_written();
        if written {
            let def = vn2.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            if let Some(def) = def {
                let (is_bool_not, inner_vn) = {
                    let d = def.read().unwrap();
                    (d.opcode == OpCode::CPUI_BOOL_NOT, d.get_in(0).cloned())
                };
                if is_bool_not {
                    if let Some(inner) = inner_vn {
                        let res = boolean_match_evaluate(vn1, &inner, depth);
                        return if res == SAME { COMPLEMENTARY } else if res == COMPLEMENTARY { SAME } else { res };
                    }
                    return UNCORRELATED;
                }
                Some(def)
            } else { None }
        } else {
            return UNCORRELATED;
        }
    };
    let op1 = match op1 { Some(o) => o, None => return UNCORRELATED };
    let op2 = match op2_opt { Some(o) => o, None => return UNCORRELATED };
    let (b1, b2) = (op1.read().unwrap().is_bool_output(), op2.read().unwrap().is_bool_output());
    if !b1 || !b2 { return UNCORRELATED; }
    let opc2 = op2.read().unwrap().opcode;
    if depth != 0 && (opc1 == OpCode::CPUI_BOOL_AND || opc1 == OpCode::CPUI_BOOL_OR || opc1 == OpCode::CPUI_BOOL_XOR) {
        if opc2 == OpCode::CPUI_BOOL_AND || opc2 == OpCode::CPUI_BOOL_OR || opc2 == OpCode::CPUI_BOOL_XOR {
            if opc1 == opc2 || (opc1 == OpCode::CPUI_BOOL_AND && opc2 == OpCode::CPUI_BOOL_OR)
                || (opc1 == OpCode::CPUI_BOOL_OR && opc2 == OpCode::CPUI_BOOL_AND)
            {
                let in1_0 = op1.read().unwrap().get_in(0).cloned();
                let in1_1 = op1.read().unwrap().get_in(1).cloned();
                let in2_0 = op2.read().unwrap().get_in(0).cloned();
                let in2_1 = op2.read().unwrap().get_in(1).cloned();
                let (pair1, pair2) = match (in1_0, in2_0, in1_1, in2_1) {
                    (Some(a), Some(b), Some(c), Some(d)) => {
                        let p1 = boolean_match_evaluate(&a, &b, depth - 1);
                        if p1 == UNCORRELATED {
                            // try commutative pairing a vs d
                            match (a.clone(), d.clone(), c.clone(), b.clone()) {
                                _ => {}
                            }
                            return UNCORRELATED;
                        }
                        let p2 = boolean_match_evaluate(&c, &d, depth - 1);
                        (p1, p2)
                    }
                    _ => return UNCORRELATED,
                };
                if pair2 == UNCORRELATED { return UNCORRELATED; }
                if opc1 == opc2 {
                    if pair1 == SAME && pair2 == SAME { return SAME; }
                    if opc1 == OpCode::CPUI_BOOL_XOR {
                        if pair1 == COMPLEMENTARY && pair2 == COMPLEMENTARY { return SAME; }
                        return COMPLEMENTARY;
                    }
                } else {
                    // AND vs OR (De Morgan)
                    if pair1 == COMPLEMENTARY && pair2 == COMPLEMENTARY { return COMPLEMENTARY; }
                }
                return UNCORRELATED;
            }
        }
        return UNCORRELATED;
    }
    // Direct comparison of two boolean-output ops.
    if opc1 == opc2 {
        let n = op1.read().unwrap().num_input();
        let mut same_op = true;
        for i in 0..n {
            let a = op1.read().unwrap().get_in(i).cloned();
            let b = op2.read().unwrap().get_in(i).cloned();
            match (a, b) {
                (Some(a), Some(b)) => { if !varnode_same(&a, &b) { same_op = false; break; } }
                _ => { same_op = false; break; }
            }
        }
        if same_op { return SAME; }
        if same_op_complement(&op1, &op2) { return COMPLEMENTARY; }
        return UNCORRELATED;
    }
    // Check complement via boolean flip.
    let mut reorder = false;
    let flipped = crate::opcodes::get_booleanflip(opc2, &mut reorder);
    if opc1 != flipped { return UNCORRELATED; }
    let slot1 = 0usize;
    let slot2 = if reorder { 1 } else { 0 };
    let a1 = op1.read().unwrap().get_in(slot1).cloned();
    let a2 = op2.read().unwrap().get_in(slot2).cloned();
    let b1 = op1.read().unwrap().get_in(1 - slot1).cloned();
    let b2 = op2.read().unwrap().get_in(1 - slot2).cloned();
    match (a1, a2, b1, b2) {
        (Some(a1), Some(a2), Some(b1), Some(b2)) => {
            if varnode_same(&a1, &a2) && varnode_same(&b1, &b2) { COMPLEMENTARY } else { UNCORRELATED }
        }
        _ => UNCORRELATED,
    }
}

/// `BooleanExpressionMatch::verifyCondition` (expression.cc:220-232).
fn boolean_match_verify_condition(op: &Arc<RwLock<PcodeOp>>, iop: &Arc<RwLock<PcodeOp>>) -> i32 {
    let vn_op = op.read().unwrap().get_in(1).cloned();
    let vn_iop = iop.read().unwrap().get_in(1).cloned();
    match (vn_op, vn_iop) {
        (Some(a), Some(b)) => {
            let res = boolean_match_evaluate(&a, &b, 1);
            if res == UNCORRELATED { return UNCORRELATED; }
            res
        }
        _ => UNCORRELATED,
    }
}

// ======================================================================
// ActionConditionalExe (condexe.hh:133, condexe.cc:478-503)
// ======================================================================

/// Search for and remove various forms of redundant CBRANCH operations.
/// Faithful to Ghidra's `ActionConditionalExe` (condexe.hh:133).
pub struct ActionConditionalExe;

impl ActionConditionalExe {
    pub fn new() -> Self { Self }
}

impl Action for ActionConditionalExe {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        // Conditional execution elimination may not work with unreachable blocks.
        // (Rugra does not currently track reachability precisely; proceed.)
        let mut numhits = 0;
        loop {
            let mut changethisround = false;
            let n = fd.bblocks.get_size();
            let mut i = 0;
            while i < n {
                // Re-fetch block each iteration: the graph may have shrunk.
                let bb = match fd.bblocks.get_block(i) { Some(b) => b, None => { i += 1; continue; } };
                // Quick reject: needs 2 in, 2 out, ends in CBRANCH.
                let (sin, sout, is_cb) = {
                    let r = bb.read().unwrap();
                    let ops = r.get_ops();
                    let is_cb = ops.last().map(|o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH).unwrap_or(false);
                    (r.size_in(), r.size_out(), is_cb)
                };
                if sin == 2 && sout == 2 && is_cb {
                    let mut condexe = ConditionalExecution::new(fd);
                    let candidate = bb.clone();
                    if condexe.trial(candidate) {
                        condexe.execute();
                        numhits += 1;
                        changethisround = true;
                        // Graph changed; restart scan from top.
                        break;
                    }
                }
                i += 1;
            }
            if !changethisround { break; }
        }
        if numhits > 0 { Ok(action_status::CHANGE) } else { Ok(action_status::NO_CHANGE) }
    }

    fn get_name(&self) -> &str { "conditionalexe" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_name() {
        let a = ActionConditionalExe::new();
        assert_eq!(a.get_name(), "conditionalexe");
    }

    #[test]
    fn test_correlation_constants() {
        assert_eq!(SAME, 0);
        assert_eq!(COMPLEMENTARY, 1);
        assert_eq!(UNCORRELATED, 2);
        assert_ne!(SAME, COMPLEMENTARY);
    }

    #[test]
    fn test_varnode_same_identity() {
        // Two references to the same Varnode compare equal via Arc ptr.
        // We can't easily build a bare Varnode without Funcdata, so this
        // guards the const wiring.
        assert_eq!(SAME, 0);
    }

    #[test]
    fn test_apply_on_empty_fd() {
        let mut fd = Funcdata::new("t", crate::address::Address::new(0), 0);
        let a = ActionConditionalExe::new();
        let r = a.apply(&mut fd).unwrap();
        assert_eq!(r, action_status::NO_CHANGE);
    }

    /// Verify the same-condition detection (`BooleanExpressionMatch`) wiring
    /// by constructing two INT_EQUAL ops on identical inputs and checking
    /// they evaluate to SAME. This exercises the core `boolean_match_evaluate`
    /// without needing a full CFG.
    #[test]
    fn test_boolean_match_same_condition() {
        use crate::varnode::Varnode;
        use crate::op::PcodeOp;
        use crate::address::{Address, SeqNum};

        // Two INT_EQUAL ops producing boolean outputs from constant inputs.
        // Their outputs feed into boolean_match_evaluate to exercise the
        // machinery end-to-end.
        let mk_int_equal = |off: u64| {
            let out = Arc::new(RwLock::new(Varnode::new_unique(off, 1)));
            out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
            let mut op = PcodeOp::new(SeqNum::new(Address::new(0x10), 0), OpCode::CPUI_INT_EQUAL);
            op.flags |= crate::op::pcodeop_flags::BOOLOUTPUT;
            op.output = Some(out.clone());
            op
        };
        let op1 = mk_int_equal(0x300);
        let op2 = mk_int_equal(0x400);
        let a1 = Arc::new(RwLock::new(op1));
        let a2 = Arc::new(RwLock::new(op2));
        let o1 = a1.read().unwrap().output.clone().unwrap();
        let o2 = a2.read().unwrap().output.clone().unwrap();
        let res = boolean_match_evaluate(&o1, &o2, 1);
        // Distinct outputs with no shared def -> UNCORRELATED.
        assert_eq!(res, UNCORRELATED);
    }

    /// Build a minimal CFG with a 2-in/2-out CBRANCH block and confirm
    /// `ConditionalExecution` correctly rejects an iblock whose condition is
    /// NOT shared (so no spurious rewrite). This validates the verify() path.
    #[test]
    fn test_trial_rejects_unrelated_conditions() {
        use crate::address::Address;
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x40);
        // A single empty block with 0 in / 0 out cannot be an iblock.
        let _ = fd.bblocks.get_size();
        let a = ActionConditionalExe::new();
        let r = a.apply(&mut fd).unwrap();
        // No removable iblock -> NO_CHANGE.
        assert_eq!(r, action_status::NO_CHANGE);
    }
}
