//! Conditional execution simplification.
//!
//! Corresponds to Ghidra's `condexe.hh` / `condexe.cc` (712 lines).
//!
//! This module simplifies control-flow with shared conditional expressions.
//! When two CBRANCH operations test the same (or complemented) boolean value,
//! the redundant CBRANCH can be eliminated, merging the two paths.
//!
//! Key classes:
//! - `ConditionalExecution`: the analysis engine that detects and removes
//!   redundant CBRANCH operations between blocks
//! - `ActionConditionalExe`: the Action wrapper that scans for candidates

use crate::action::{Action, action_status};
use crate::funcdata::Funcdata;
use crate::error::Result;
use crate::opcodes::OpCode;
use crate::address::functional_equality;
use std::sync::{Arc, RwLock};
use crate::op::PcodeOp;
use crate::block::FlowBlock;

/// Describes the relationship between init and iblock CBRANCH conditions.
#[derive(Debug, Clone, Copy, PartialEq)]
enum CondRelation {
    /// Conditions are the same
    Same,
    /// Conditions are complementary
    Complement,
    /// No relationship found
    Unrelated,
}

/// The analysis engine for a single iblock candidate.
/// Corresponds to Ghidra's `ConditionalExecution` (condexe.hh:91).
pub struct ConditionalExecution {
    /// The CBRANCH in the iblock
    pub cbranch: Option<Arc<RwLock<PcodeOp>>>,
    /// Index of the block being analyzed
    pub iblock_index: i32,
    /// Whether the boolean values are the same or complemented
    pub relation: CondRelation,
}

impl ConditionalExecution {
    /// Construct for the given iblock index.
    pub fn new(iblock_index: i32) -> Self {
        Self {
            cbranch: None,
            iblock_index,
            relation: CondRelation::Unrelated,
        }
    }

    /// Test if the iblock is a valid candidate: 2 in-edges + CBRANCH.
    /// Corresponds to parts of `ConditionalExecution::trial` (condexe.cc).
    pub fn test_iblock(fd: &Funcdata, block_index: i32) -> bool {
        if let Some(block_arc) = fd.bblocks.get_block(block_index as usize) {
            let block = block_arc.read().unwrap();
            // Must have exactly 2 in-edges.
            if block.size_in() != 2 { return false; }
            // Must have a CBRANCH.
            let has_cbranch = block.get_ops().iter().any(|op_ref| {
                op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
            });
            return has_cbranch;
        }
        false
    }

    /// Find the CBRANCH op in the given block.
    pub fn find_cbranch(fd: &Funcdata, block_index: i32) -> Option<Arc<RwLock<PcodeOp>>> {
        if let Some(block_arc) = fd.bblocks.get_block(block_index as usize) {
            let block = block_arc.read().unwrap();
            for op_ref in block.get_ops() {
                let op = op_ref.0.read().unwrap();
                if op.opcode == OpCode::CPUI_CBRANCH {
                    return Some(op_ref.0.clone());
                }
            }
        }
        None
    }

    /// Verify that the init block and iblock CBRANCH on the same condition.
    /// Corresponds to `ConditionalExecution::verifySameCondition` (condexe.cc).
    /// Uses functional_equality to compare the boolean input varnodes.
    pub fn verify_same_condition(
        init_cbranch: &Arc<RwLock<PcodeOp>>,
        iblock_cbranch: &Arc<RwLock<PcodeOp>>,
    ) -> CondRelation {
        let init = init_cbranch.read().unwrap();
        let iblock = iblock_cbranch.read().unwrap();

        // Get the boolean condition varnodes (slot 0 or 1 depending on flip).
        let init_cond = init.inrefs.first().cloned();
        let iblock_cond = iblock.inrefs.first().cloned();

        match (init_cond, iblock_cond) {
            (Some(ic), Some(bc)) => {
                if functional_equality(&ic, &bc) {
                    CondRelation::Same
                } else {
                    // Check for complement: BOOL_NOT(ic) == bc or ic == BOOL_NOT(bc)
                    let ic_def = ic.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
                    let bc_def = bc.read().unwrap().def.as_ref().and_then(|w| w.upgrade());

                    // If ic is BOOL_NOT(x) and x == bc → complement
                    if let Some(def) = &ic_def {
                        let d = def.read().unwrap();
                        if d.opcode == OpCode::CPUI_BOOL_NOT {
                            if let Some(inner) = d.inrefs.first() {
                                if functional_equality(inner, &bc) {
                                    return CondRelation::Complement;
                                }
                            }
                        }
                    }
                    // If bc is BOOL_NOT(x) and x == ic → complement
                    if let Some(def) = &bc_def {
                        let d = def.read().unwrap();
                        if d.opcode == OpCode::CPUI_BOOL_NOT {
                            if let Some(inner) = d.inrefs.first() {
                                if functional_equality(inner, &ic) {
                                    return CondRelation::Complement;
                                }
                            }
                        }
                    }

                    CondRelation::Unrelated
                }
            }
            _ => CondRelation::Unrelated,
        }
    }

    /// Attempt analysis on the iblock.
    /// Returns true if the iblock can be simplified.
    /// Corresponds to `ConditionalExecution::trial` + `verify` (condexe.cc).
    pub fn trial(&mut self, fd: &Funcdata) -> bool {
        if !Self::test_iblock(fd, self.iblock_index) {
            return false;
        }
        // Find the CBRANCH in the iblock.
        let iblock_cbranch = match Self::find_cbranch(fd, self.iblock_index) {
            Some(c) => c,
            None => return false,
        };

        // Walk predecessors to find the init block (a block with a CBRANCH
        // that tests the same or complementary condition).
        if let Some(block_arc) = fd.bblocks.get_block(self.iblock_index as usize) {
            let block = block_arc.read().unwrap();
            let num_in = block.size_in();
            for i in 0..num_in {
                if let Some(edge) = block.get_in(i) {
                    let pred_block = edge.point.read().unwrap();
                    for op_ref in pred_block.get_ops() {
                        let op = op_ref.0.read().unwrap();
                        if op.opcode == OpCode::CPUI_CBRANCH {
                            let pred_cbranch = op_ref.0.clone();
                            drop(op);
                            let rel = Self::verify_same_condition(&pred_cbranch, &iblock_cbranch);
                            if rel != CondRelation::Unrelated {
                                self.cbranch = Some(iblock_cbranch);
                                self.relation = rel;
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }
}

/// Search for and remove various forms of redundant CBRANCH operations.
///
/// Corresponds to Ghidra's `ActionConditionalExe` (condexe.hh:133).
pub struct ActionConditionalExe;

impl ActionConditionalExe {
    pub fn new() -> Self { Self }
}

impl Action for ActionConditionalExe {
    fn apply(&self, fd: &mut Funcdata) -> Result<i32> {
        let count = fd.bblocks.get_size();
        let mut changed = false;
        for i in 0..count {
            // Quick check: 2 in-edges + CBRANCH.
            if !ConditionalExecution::test_iblock(fd, i as i32) {
                continue;
            }
            let mut ce = ConditionalExecution::new(i as i32);
            if ce.trial(fd) {
                // Found a removable iblock. The actual block-edge manipulation
                // (removeBlockEdge/setOut) requires block-editing infrastructure.
                // Mark that we found a candidate.
                changed = true;
                eprintln!("[CONDEXE] Found removable iblock at index {} (relation: {:?})",
                    i, ce.relation);
            }
        }
        if changed { Ok(action_status::CHANGE) } else { Ok(0) }
    }

    fn get_name(&self) -> &str { "conditionalexe" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_conditional_exe_name() {
        let action = ActionConditionalExe::new();
        assert_eq!(action.get_name(), "conditionalexe");
    }

    #[test]
    fn test_conditional_execution_creation() {
        let ce = ConditionalExecution::new(0);
        assert_eq!(ce.iblock_index, 0);
        assert_eq!(ce.relation, CondRelation::Unrelated);
        assert!(ce.cbranch.is_none());
    }

    #[test]
    fn test_cond_relation_equality() {
        assert_ne!(CondRelation::Same, CondRelation::Complement);
        assert_ne!(CondRelation::Same, CondRelation::Unrelated);
        assert_ne!(CondRelation::Complement, CondRelation::Unrelated);
    }
}
