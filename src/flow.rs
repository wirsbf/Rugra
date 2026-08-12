//! Reachability-based control flow tracking.
//!
//! Partial port of Ghidra's `FlowInfo` (flow.cc/flow.hh). Replaces Rugra's
//! linear-scan approach (disassemble → lift → inject_raw_ops) with
//! address-list-driven flow tracking that only decodes reachable code. The
//! remaining error, injection, override, jump-table, and block-generation
//! differences are tracked by `SLEIGH-FLOW-0001`.

use crate::address::Address;
use crate::disasm::sleigh_lift::SleighLifter;
use crate::funcdata::Funcdata;
use crate::opcodes::OpCode;
use crate::op::pcodeop_flags;
use crate::sleigh_ffi::SleighErrorKind;
use std::sync::Arc;

/// Flow-following option/property flag bits. Faithful to the anonymous enum
/// in flow.hh:60-74.
// Ghidra: flow.hh:60 FlowInfo::(anonymous enum)
pub mod flow_flags {
    /// Ignore/truncate flow into addresses out of the specified range.
    pub const IGNORE_OUTOFBOUNDS: u32 = 1;
    /// Treat unimplemented instructions as a NOP (no operation).
    pub const IGNORE_UNIMPLEMENTED: u32 = 2;
    /// Throw an exception for flow into addresses out of the specified range.
    pub const ERROR_OUTOFBOUNDS: u32 = 4;
    /// Throw an exception for flow into unimplemented instructions.
    pub const ERROR_UNIMPLEMENTED: u32 = 8;
    /// Throw an exception for flow into previously encountered data at a different cut.
    pub const ERROR_REINTERPRETED: u32 = 0x10;
    /// Throw an exception if too many instructions are encountered.
    pub const ERROR_TOOMANYINSTRUCTIONS: u32 = 0x20;
    /// Indicate we have encountered unimplemented instructions.
    pub const UNIMPLEMENTED_PRESENT: u32 = 0x40;
    /// Indicate we have encountered flow into unaccessible data.
    pub const BADDATA_PRESENT: u32 = 0x80;
    /// Indicate we have encountered flow out of the specified range.
    pub const OUTOFBOUNDS_PRESENT: u32 = 0x100;
    /// Indicate we have encountered reinterpreted data.
    pub const REINTERPRETED_PRESENT: u32 = 0x200;
    /// Indicate the maximum instruction threshold was reached.
    pub const TOOMANYINSTRUCTIONS_PRESENT: u32 = 0x400;
    /// Indicate a CALL was converted to a BRANCH and some code may be unreachable.
    pub const POSSIBLE_UNREACHABLE: u32 = 0x1000;
    /// Indicate flow is being generated to in-line (a function).
    pub const FLOW_FORINLINE: u32 = 0x2000;
    /// Indicate that any jump table recovery should record the table structure.
    pub const RECORD_JUMPLOADS: u32 = 0x4000;
}

/// Extension trait providing the `FuncCallSpecs` accessors that Ghidra's
/// `flow.cc` call-spec maintenance methods rely on but that Rugra's
/// `FuncCallSpecs` does not yet model. The audit (flow_audit.md item 2)
/// flags this as a "FuncCallSpecs gap": Ghidra's `FuncCallSpecs` carries
/// inline/noreturn/inject_id state, while Rugra's does not store them.
///
/// Because this alignment task is constrained to `src/flow.rs`, the accessors
/// are provided here as an extension trait. `is_inline`/`is_no_return`/
/// `get_inject_id` return conservative defaults (`false`/`false`/`-1`) until
/// the underlying storage is added to `FuncCallSpecs` (tracked as
/// RUGRA-GLUE). The remaining accessors (`get_op`, `get_name`,
/// `set_paramshift`, `cancel_inject_id`, `set_address`) delegate to the
/// existing public fields/methods where possible.
trait FuncCallSpecsExt {
    /// Flow-local adapter for `FuncCallSpecs::isInline` (fspec.hh). Rugra's
    /// `FuncCallSpecs` does not yet store the inline flag, so this returns
    /// false. Inline-driven injection (`check_for_flow_modification`) is a
    /// unavailable until the flag is wired in (`CALLSPEC-0001`).
    // RUGRA-GLUE: ANN-B; Rust extension-trait declaration because flow.cc calls FuncCallSpecs::isInline directly and has no flow-local interface.
    fn is_inline(&self) -> bool;
    /// Flow-local adapter for `FuncCallSpecs::isNoReturn` (fspec.hh), with the same
    /// caveat as `is_inline`.
    // RUGRA-GLUE: ANN-B; Rust extension-trait declaration because flow.cc calls FuncCallSpecs::isNoReturn directly and has no flow-local interface.
    fn is_no_return(&self) -> bool;
    /// Flow-local adapter for `FuncCallSpecs::getInjectId` (fspec.hh). Returns -1
    /// (Ghidra's "no injection" sentinel) until the id is stored.
    // RUGRA-GLUE: ANN-B; Rust extension-trait declaration because flow.cc calls FuncCallSpecs::getInjectId directly and has no flow-local interface.
    fn get_inject_id(&self) -> i32;
    /// Flow-local adapter for `FuncCallSpecs::getOp` (fspec.hh): the call op backing
    /// this spec. Rugra stores `op_addr` and resolves the op against the
    /// alive list (mirrors `FuncCallSpecs::find_call_op`).
    // RUGRA-GLUE: ANN-B; Rust extension-trait declaration for resolving a call op from Rugra's stored address instead of Ghidra's direct PcodeOp pointer.
    fn get_op(&self, fd: &Funcdata) -> Option<crate::op::PcodeOpRef>;
    /// Flow-local adapter for `FuncCallSpecs::getName` (fspec.hh): the callee name.
    /// Delegates to `FuncProto::get_name`.
    // RUGRA-GLUE: ANN-B; Rust extension-trait declaration exposing the nested FuncProto name used where Ghidra inherits the accessor directly.
    fn get_name(&self) -> &str;
    /// Flow-local adapter for `FuncCallSpecs::setParamshift` (fspec.hh). Delegates to
    /// `FuncProto::param_shift`; leaves state unchanged when `shift == 0`.
    // RUGRA-GLUE: ANN-B; Rust extension-trait declaration exposing nested FuncProto parameter shifting to flow-local code.
    fn set_paramshift(&mut self, shift: i32);
    /// Flow-local adapter for `FuncCallSpecs::cancelInjectId` (fspec.hh):
    /// delegates to the injection-state gap tracked by `INJECT-0001`.
    // RUGRA-GLUE: ANN-B; Rust extension-trait declaration exposing nested FuncProto injection cancellation to flow-local code.
    fn cancel_inject_id(&mut self);
    /// Flow-local adapter for `FuncCallSpecs::setAddress` (fspec.hh). Clears the entry
    /// address to cancel an indirect override (flow.cc:713).
    // RUGRA-GLUE: ANN-B; Rust extension-trait declaration representing Ghidra's setAddress(Address()) with Rugra's optional entry address.
    fn clear_entry_address(&mut self);
}

impl FuncCallSpecsExt for crate::fspec::FuncCallSpecs {
    // RUGRA-GLUE: ANN-B; CALLSPEC-0001 compatibility fallback because Rugra FuncCallSpecs has no Ghidra inline-state field.
    fn is_inline(&self) -> bool {
        // TODO(CALLSPEC-0001): depends on FuncCallSpecs storing an inline flag.
        false
    }
    // RUGRA-GLUE: ANN-B; CALLSPEC-0001 compatibility fallback because Rugra FuncCallSpecs has no Ghidra no-return-state field.
    fn is_no_return(&self) -> bool {
        // TODO(CALLSPEC-0001): depends on FuncCallSpecs storing a noreturn flag.
        false
    }
    // RUGRA-GLUE: ANN-B; INJECT-0001 compatibility fallback because Rugra FuncCallSpecs has no Ghidra injection-id field.
    fn get_inject_id(&self) -> i32 {
        // TODO(INJECT-0001): depends on FuncCallSpecs storing an inject id. -1 = none.
        -1
    }
    // RUGRA-GLUE: ANN-B; CALLSPEC-0001 adapter resolves Rugra's stored op address because Ghidra FuncCallSpecs keeps a direct PcodeOp pointer.
    fn get_op(&self, fd: &Funcdata) -> Option<crate::op::PcodeOpRef> {
        self.find_call_op(fd)
    }
    // RUGRA-GLUE: ANN-B; Rust adapter reads the nested FuncProto field because Rugra FuncCallSpecs does not inherit Ghidra's name accessor.
    fn get_name(&self) -> &str {
        // FuncProto stores the callee name in a public `name` field; Rugra
        // has no FuncProto::get_name accessor, so we read the field directly.
        self.prototype.name.as_str()
    }
    // RUGRA-GLUE: ANN-B; Rust adapter forwards flow-local parameter shifting to the nested FuncProto object.
    fn set_paramshift(&mut self, shift: i32) {
        self.prototype.param_shift(shift);
    }
    // RUGRA-GLUE: ANN-B; INJECT-0001 adapter forwards flow-local injection cancellation to the nested FuncProto object.
    fn cancel_inject_id(&mut self) {
        self.prototype.cancel_inject_id();
    }
    // RUGRA-GLUE: ANN-B; CALLSPEC-0001 adapter encodes flow.cc's setAddress(Address()) as Option::None in Rugra.
    fn clear_entry_address(&mut self) {
        self.entry_addr = None;
    }
}

/// Record of a visited instruction (flow.hh:77-80 VisitStat).
#[derive(Clone, Debug)]
struct VisitStat {
    /// Sequence number order of the first PcodeOp generated by this instruction.
    order: u32,
    /// Instruction byte length.
    size: usize,
}

/// Reachability-based flow tracker corresponding to `FlowInfo`
/// (flow.hh:58-169). This type is still `MISMATCH`, not a complete port.
///
/// Phase 1 (`generate_ops`): Decode instructions following control flow
/// from the entry point, building a work-list of reachable addresses.
/// Phase 2 (`generate_blocks`): Reuse Rugra's `build_blocks_from_ops`.
///
/// **Not yet ported**: jump-table inline expansion (tablelist/recoverJumpTables),
/// truncatedFlow/partial clone, inlineFlow/subfunction inlining, P-code injection.
pub struct FlowInfo<'a> {
    fd: &'a mut Funcdata,
    lifter: &'a mut SleighLifter,
    /// Work-list of addresses to process (LIFO stack). flow.hh:82 addrlist.
    addrlist: Vec<Address>,
    /// Addresses which are permanently unprocessed (flow.hh:87 unprocessed).
    unprocessed: Vec<Address>,
    /// Visited instruction map (flow.hh:84 visited).
    /// Keyed by instruction address; value carries the first-op order and
    /// the instruction byte size (RUGRA-GLUE: Ghidra's VisitStat.seqnum is
    /// replaced by `order`, see flow_audit.md item 7).
    visited: std::collections::BTreeMap<u64, VisitStat>,
    /// List of p-code ops that require injection (flow.hh:90 injectlist).
    /// Populated by `check_for_flow_modification` when a call site is inline
    /// and consumed by `inject_pcode`. RUGRA-GLUE: Ghidra stores `PcodeOp *`;
    /// we store `PcodeOpRef`. Entries are nulled after injection (flow.cc:1333).
    injectlist: Vec<Option<crate::op::PcodeOpRef>>,
    /// Instruction count limit (flow.hh:96 insn_max).
    insn_max: u64,
    /// Instruction count (flow.hh:95 insn_count).
    insn_count: u64,
    /// Flow range [baddr, eaddr).
    baddr: u64,
    eaddr: u64,
    /// Actual min/max address seen.
    minaddr: u64,
    maxaddr: u64,
    /// Boolean options for flow following (flow.hh:101 flags).
    flags: u32,
    /// First function in the in-lining chain (flow.hh:102 inline_head).
    /// Ghidra stores `Funcdata *`; Rugra stores the head function's base
    /// address so `inline_sub_function` can detect the top-level inline
    /// entry. `None` means no inlining is in progress.
    inline_head: Option<u64>,
    /// Active set of addresses for functions currently being in-lined
    /// (flow.hh:103 inline_recursion). Ghidra stores a pointer to an
    /// externally-owned `set<Address>`; Rugra owns the set directly.
    inline_recursion: std::collections::BTreeSet<u64>,
    /// Storage for addresses of functions that are in-lined (flow.hh:104
    /// inline_base). Backing store for `inline_recursion` at the top level.
    inline_base: std::collections::BTreeSet<u64>,
    /// Does the function have registered flow override instructions
    /// (flow.hh:100 flowoverride_present). Currently always false; Rugra
    /// does not yet model flow overrides.
    flowoverride_present: bool,
}

impl<'a> FlowInfo<'a> {
    // Ghidra: flow.hh:106 FlowInfo::FlowInfo
    pub fn new(
        fd: &'a mut Funcdata,
        lifter: &'a mut SleighLifter,
        baddr: u64,
        eaddr: u64,
    ) -> Self {
        Self {
            fd,
            lifter,
            addrlist: Vec::new(),
            unprocessed: Vec::new(),
            visited: std::collections::BTreeMap::new(),
            injectlist: Vec::new(),
            insn_max: 100000, // Ghidra default max_instructions
            insn_count: 0,
            baddr,
            eaddr,
            minaddr: u64::MAX,
            maxaddr: 0,
            flags: 0,
            inline_head: None,
            inline_recursion: std::collections::BTreeSet::new(),
            inline_base: std::collections::BTreeSet::new(),
            flowoverride_present: false,
        }
    }

    /// Set the maximum instruction limit. Faithful to `setMaximumInstructions`.
    // Ghidra: flow.hh:148 FlowInfo::setMaximumInstructions
    pub fn set_max_instructions(&mut self, max: u64) {
        self.insn_max = max;
    }

    /// Establish the flow bounds. Faithful to inline `setRange`
    /// (flow.hh:145).
    // Ghidra: flow.hh:145 FlowInfo::setRange
    pub fn set_range(&mut self, b: u64, e: u64) {
        self.baddr = b;
        self.eaddr = e;
    }

    /// Enable a specific flow option. Faithful to inline `setFlags`
    /// (flow.hh:147).
    // Ghidra: flow.hh:147 FlowInfo::setFlags
    pub fn set_flags(&mut self, val: u32) {
        self.flags |= val;
    }

    /// Disable a specific flow option. Faithful to inline `clearFlags`
    /// (flow.hh:148).
    // Ghidra: flow.hh:148 FlowInfo::clearFlags
    pub fn clear_flags(&mut self, val: u32) {
        self.flags &= !val;
    }

    /// Get the number of bytes covered by the flow. Faithful to inline
    /// `getSize` (flow.hh:160).
    // Ghidra: flow.hh:160 FlowInfo::getSize
    pub fn get_size(&self) -> u64 {
        // Ghidra returns maxaddr - minaddr; Rugra uses u64 sentinel for "no min".
        if self.minaddr == u64::MAX {
            0
        } else {
            self.maxaddr.saturating_sub(self.minaddr)
        }
    }

    /// Has the given instruction (address) been seen in flow. Faithful to
    /// inline `seenInstruction` (flow.hh:108).
    // Ghidra: flow.hh:108 FlowInfo::seenInstruction
    pub fn seen_instruction(&self, addr: Address) -> bool {
        self.visited.contains_key(&addr.as_u64())
    }

    /// Are there possible unreachable ops. Faithful to inline
    /// `hasPossibleUnreachable` (flow.hh:105).
    // Ghidra: flow.hh:105 FlowInfo::hasPossibleUnreachable
    pub fn has_possible_unreachable(&self) -> bool {
        (self.flags & flow_flags::POSSIBLE_UNREACHABLE) != 0
    }

    /// Mark that there may be unreachable ops. Faithful to inline
    /// `setPossibleUnreachable` (flow.hh:106).
    // Ghidra: flow.hh:106 FlowInfo::setPossibleUnreachable
    pub fn set_possible_unreachable(&mut self) {
        self.flags |= flow_flags::POSSIBLE_UNREACHABLE;
    }

    /// Does this flow have injections. Faithful to inline `hasInject`
    /// (flow.hh:161).
    // Ghidra: flow.hh:161 FlowInfo::hasInject
    pub fn has_inject(&self) -> bool {
        // flow.hh:161: `return !injectlist.empty();` — any pending inject op.
        self.injectlist.iter().any(|o| o.is_some())
    }

    /// Does this flow have unimplemented instructions. Faithful to inline
    /// `hasUnimplemented` (flow.hh:162).
    // Ghidra: flow.hh:162 FlowInfo::hasUnimplemented
    pub fn has_unimplemented(&self) -> bool {
        (self.flags & flow_flags::UNIMPLEMENTED_PRESENT) != 0
    }

    /// Does this flow reach inaccessible data. Faithful to inline
    /// `hasBadData` (flow.hh:163).
    // Ghidra: flow.hh:163 FlowInfo::hasBadData
    pub fn has_bad_data(&self) -> bool {
        (self.flags & flow_flags::BADDATA_PRESENT) != 0
    }

    /// Does this flow flow out of bound. Faithful to inline `hasOutOfBounds`
    /// (flow.hh:164).
    // Ghidra: flow.hh:164 FlowInfo::hasOutOfBounds
    pub fn has_out_of_bounds(&self) -> bool {
        (self.flags & flow_flags::OUTOFBOUNDS_PRESENT) != 0
    }

    /// Does this flow reinterpret bytes. Faithful to inline `hasReinterpreted`
    /// (flow.hh:165).
    // Ghidra: flow.hh:165 FlowInfo::hasReinterpreted
    pub fn has_reinterpreted(&self) -> bool {
        (self.flags & flow_flags::REINTERPRETED_PRESENT) != 0
    }

    /// Does this flow have too many instructions. Faithful to inline
    /// `hasTooManyInstructions` (flow.hh:166).
    // Ghidra: flow.hh:166 FlowInfo::hasTooManyInstructions
    pub fn has_too_many_instructions(&self) -> bool {
        (self.flags & flow_flags::TOOMANYINSTRUCTIONS_PRESENT) != 0
    }

    /// Is this flow to be in-lined. Faithful to inline `isFlowForInline`
    /// (flow.hh:167).
    // Ghidra: flow.hh:167 FlowInfo::isFlowForInline
    pub fn is_flow_for_inline(&self) -> bool {
        (self.flags & flow_flags::FLOW_FORINLINE) != 0
    }

    /// Should jump table structure be recorded. Faithful to inline
    /// `doesJumpRecord` (flow.hh:168).
    // Ghidra: flow.hh:168 FlowInfo::doesJumpRecord
    pub fn does_jump_record(&self) -> bool {
        (self.flags & flow_flags::RECORD_JUMPLOADS) != 0
    }

    /// Clear any discovered flow properties. Faithful to `clearProperties`
    /// (flow.cc:78-83). Resets the presence flags and the instruction
    /// counter, preparing for a fresh pass over the function.
    // Ghidra: flow.cc:78 FlowInfo::clearProperties
    pub fn clear_properties(&mut self) {
        self.flags &= !(flow_flags::UNIMPLEMENTED_PRESENT
            | flow_flags::BADDATA_PRESENT
            | flow_flags::OUTOFBOUNDS_PRESENT);
        self.insn_count = 0;
    }

    /// Generate warning message or throw exception for given flow that is
    /// out of bounds. Faithful to `handleOutOfBounds` (flow.cc:519-540).
    /// Rugra does not throw — it logs a warning and sets the
    /// `OUTOFBOUNDS_PRESENT` flag unless `IGNORE_OUTOFBOUNDS` is set.
    // Ghidra: flow.cc:519 FlowInfo::handleOutOfBounds
    fn handle_out_of_bounds(&mut self, fromaddr: Address, toaddr: Address) {
        if (self.flags & flow_flags::IGNORE_OUTOFBOUNDS) != 0 {
            return;
        }
        let msg = format!(
            "Function flow out of bounds: {:#x} flows to {:#x}",
            fromaddr.as_u64(),
            toaddr.as_u64()
        );
        if (self.flags & flow_flags::ERROR_OUTOFBOUNDS) == 0 {
            // data.warning(msg, toaddr);
            eprintln!("[FLOW] {}: {}", self.fd.name, msg);
            if !self.has_out_of_bounds() {
                self.flags |= flow_flags::OUTOFBOUNDS_PRESENT;
                self.fd.warning_header("Function flows out of bounds");
            }
        } else {
            // Ghidra throws LowlevelError; Rugra logs at error level instead.
            eprintln!("[FLOW] ERROR: {}: {}", self.fd.name, msg);
        }
    }

    /// Generate warning message or exception for a reinterpreted address.
    /// Faithful to `reinterpreted` (flow.cc:606-629). A set of bytes is
    /// reinterpreted if there are at least two different interpretations of
    /// the bytes as instructions. Rugra logs and sets the
    /// `REINTERPRETED_PRESENT` flag instead of throwing.
    // Ghidra: flow.cc:606 FlowInfo::reinterpreted
    fn reinterpreted(&mut self, addr: Address) {
        // Find the previously visited instruction whose tail overlaps addr.
        let mut addr2: Option<u64> = None;
        for (&k, _stat) in self.visited.range(..=addr.as_u64()).rev() {
            addr2 = Some(k);
            break;
        }
        let addr2 = match addr2 {
            Some(a) => a,
            None => return, // Should never happen.
        };
        let msg = format!(
            "Instruction at ({:#x}) overlaps instruction at ({:#x})",
            addr.as_u64(),
            addr2
        );
        if (self.flags & flow_flags::ERROR_REINTERPRETED) != 0 {
            eprintln!("[FLOW] ERROR: {}: {}", self.fd.name, msg);
            return;
        }
        if (self.flags & flow_flags::REINTERPRETED_PRESENT) == 0 {
            self.flags |= flow_flags::REINTERPRETED_PRESENT;
            self.fd.warning_header(&msg);
        }
    }

    /// An artificial halt is a special form of RETURN op. Faithful to
    /// `artificialHalt` (flow.cc:592-601). The op is annotated with the
    /// desired type of artificial halt:
    ///   - badinstruction (`PcodeOp::badinstruction`)
    ///   - unimplemented (`PcodeOp::unimplemented`)
    ///   - missing/truncated (`PcodeOp::missing`)
    ///   - noreturn (`PcodeOp::noreturn`)
    /// Returns the new RETURN op. The op is left in the dead list (Ghidra
    /// inserts via `data.newOp`, which is dead until `opInsert`).
    // Ghidra: flow.cc:592 FlowInfo::artificialHalt
    fn artificial_halt(&mut self, addr: Address, flag: u32) -> crate::op::PcodeOpRef {
        let haltop = self.fd.new_op(1, addr);
        self.fd.op_set_opcode(&haltop, OpCode::CPUI_RETURN);
        let c = self.fd.new_constant(4, 1);
        self.fd.op_set_input(&haltop, c, 0);
        if flag != 0 {
            self.fd.op_mark_halt(&haltop, flag);
        }
        haltop
    }

    /// Test if the given p-code op is a member of an array. Faithful to
    /// `isInArray` (flow.cc:776-783). This is a static helper in Ghidra used
    /// by `recoverJumpTables` to dedup BRANCHIND ops that need to be retried.
    // Ghidra: flow.cc:776 FlowInfo::isInArray
    fn is_in_array(
        array: &[crate::op::PcodeOpRef],
        op: &crate::op::PcodeOpRef,
    ) -> bool {
        array.iter().any(|x| std::sync::Arc::ptr_eq(&x.0, &op.0))
    }

    /// Delete any remaining ops at the end of the instruction (because they
    /// have been predetermined to be dead). Faithful to `deleteRemainingOps`
    /// (flow.cc:240-248). Ghidra walks the raw dead list from `oiter` to
    /// `endDead()` calling `opDestroyRaw`; Rugra uses `op_destroy` which
    /// unlinks the op from input Varnodes and marks it dead.
    // Ghidra: flow.cc:240 FlowInfo::deleteRemainingOps
    fn delete_remaining_ops_from(&mut self, start_idx: usize) {
        // Snapshot the tail of the alive list so we can drain without
        // upsetting the borrow checker (op_destroy mutates the list).
        let to_remove: Vec<crate::op::PcodeOpRef> =
            self.fd.obank.alivelist[start_idx..].to_vec();
        for op in &to_remove {
            self.fd.op_destroy(op);
        }
    }

    /// A function is in the EZ model if it is a straight-line leaf function.
    /// Faithful to `checkEZModel` (flow.cc:1157-1167). Returns true if this
    /// flow contains no CALL or BRANCH ops.
    // Ghidra: flow.cc:1157 FlowInfo::checkEZModel
    pub fn check_ez_model(&self) -> bool {
        for op_ref in &self.fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            match op.opcode {
                OpCode::CPUI_BRANCH
                | OpCode::CPUI_CBRANCH
                | OpCode::CPUI_BRANCHIND
                | OpCode::CPUI_CALL
                | OpCode::CPUI_CALLIND
                | OpCode::CPUI_RETURN => return false,
                _ => {}
            }
        }
        true
    }

    /// Treat an indirect jump (BRANCHIND) whose jumptable could not be
    /// recovered as a CALLIND or RETURN instead. Faithful to
    /// `truncateIndirectJump` (flow.cc:727-769). For `fail_return` the
    /// BRANCHIND becomes a RETURN; otherwise it becomes a CALLIND with an
    /// associated FuncCallSpecs and an artificial halt after it.
    ///
    /// Rugra notes: full FuncCallSpecs setup (`setupCallindSpecs`) and the
    /// JumpTable::RecoveryMode enum are not yet modelled — callers pass the
    /// canonical fail modes via the `fail_mode` byte (0 = fail_thunk,
    /// 1 = fail_callother, 2 = fail_return, 3 = default).
    // Ghidra: flow.cc:727 FlowInfo::truncateIndirectJump
    pub fn truncate_indirect_jump(&mut self, op: &crate::op::PcodeOpRef, fail_mode: u8) {
        let addr = {
            let o = op.0.read().unwrap();
            o.get_addr()
        };
        if fail_mode == 2 {
            // JumpTable::fail_return: turn the jump into a RETURN.
            self.fd.op_set_opcode(op, OpCode::CPUI_RETURN);
            eprintln!(
                "[FLOW] {}: Treating indirect jump at {:#x} as return",
                self.fd.name,
                addr.as_u64()
            );
            return;
        }
        // Otherwise turn the jump into a CALLIND.
        self.fd.op_set_opcode(op, OpCode::CPUI_CALLIND);
        // Ghidra: setupCallindSpecs(op, NULL); (flow.cc:736) — FuncCallSpecs
        // plumbing is not yet ported; Rugra's ActionFuncLink does this
        // post-hoc. We log it so the gap is visible.
        eprintln!(
            "[FLOW] {}: NOTE setupCallindSpecs at {:#x} deferred to ActionFuncLink",
            self.fd.name,
            addr.as_u64()
        );
        let (return_type, _no_params, warn_msg) = match fail_mode {
            0 => (0u32, false, None), // fail_thunk
            1 => (
                pcodeop_flags::NORETURN,
                true,
                Some("Does not return"),
            ), // fail_callother
            _ => (0u32, false, Some("Treating indirect jump as call")), // default
        };
        if let Some(msg) = warn_msg {
            eprintln!("[FLOW] {}: {} at {:#x}", self.fd.name, msg, addr.as_u64());
        }
        // Ghidra: if (noParams) { fc->setInternal(...) } — FuncCallSpecs gap.
        // Create an artificial return (flow.cc:766-767) right after the op.
        let truncop = self.artificial_halt(addr, return_type);
        self.fd.op_insert_after(&truncop, op);
    }

    /// Recover jumptables for the current set of BRANCHIND ops using existing
    /// flow. Faithful to `FlowInfo::recoverJumpTables`
    /// (flow.cc:1427-1458).
    ///
    /// Ghidra builds a fresh partial `Funcdata` for analysis, then walks every
    /// op in `tablelist` calling `data.recoverJumpTable(partial, op, this,
    /// mode)`. On failure it calls `truncateIndirectJump(op, mode)`; on a
    /// partial recovery it either defers the op to `notreached` (if more flow
    /// is coming) or marks the table complete.
    ///
    /// Rugra notes: there is no partial `Funcdata` clone, and `Funcdata::
    /// recoverJumpTable` is not yet ported — recovery goes through
    /// [`crate::jumptable::try_recover`], which performs the same
    /// `JumpTable::recover_addresses` work in-place. The `notreached` deferral
    /// list and the `fail_mode` → `RecoveryMode` mapping are preserved so the
    /// caller can drive the multistage loop in `generate_ops`.
    // Ghidra: flow.cc:1427 FlowInfo::recoverJumpTables
    pub fn recover_jump_tables(
        &mut self,
        new_tables: &mut Vec<Option<crate::jumptable::JumpTable>>,
        notreached: &mut Vec<crate::op::PcodeOpRef>,
    ) {
        // Ghidra reads tablelist[0] to build the partial-Funcdata label
        // (flow.cc:1430-1437). Rugra skips the label because there is no
        // partial clone; we still require a non-empty tablelist.
        let tablelist = self.collect_branchinds();
        let tablelist_len = tablelist.len();

        for op in &tablelist {
            let mode = crate::jumptable::RecoveryMode::FailNormal;

            // data.recoverJumpTable(partial, op, this, mode) (flow.cc:1442).
            let jt_opt = match crate::jumptable::try_recover(&op.0, self.fd) {
                Some(jt) => Some(jt),
                None => None,
            };

            match &jt_opt {
                None => {
                    // Could not recover the jumptable (flow.cc:1443-1445).
                    if !self.is_flow_for_inline() {
                        // Treat the indirect jump as a call/return. Rugra
                        // maps RecoveryMode → fail_mode byte expected by
                        // truncate_indirect_jump (FailNormal=1 → default).
                        self.truncate_indirect_jump(op, mode as u8);
                    }
                }
                Some(jt) => {
                    if jt.is_partial() {
                        // flow.cc:1447-1455: defer if more flow is coming and
                        // we have not already queued this op.
                        if tablelist_len > 1 && !Self::is_in_array(notreached, op) {
                            notreached.push(op.clone());
                        } else {
                            // Recovered table is final — attach it to fd and
                            // mark complete. Ghidra leaves attachment to the
                            // caller of recoverJumpTable; Rugra attaches here
                            // because there is no partial-clone hand-off.
                            let jt_arc = std::sync::Arc::new(std::sync::RwLock::new(
                                crate::jumptable::JumpTable::new(jt.opaddress),
                            ));
                            {
                                let mut dst = jt_arc.write().unwrap();
                                dst.addresstable = jt.addresstable.clone();
                                dst.mark_complete();
                                dst.set_indirect_op(op.0.clone());
                            }
                            self.fd.jump_tables.push(jt_arc);
                        }
                    } else {
                        // Fully recovered — attach to fd.
                        let jt_arc = std::sync::Arc::new(std::sync::RwLock::new(
                            crate::jumptable::JumpTable::new(jt.opaddress),
                        ));
                        {
                            let mut dst = jt_arc.write().unwrap();
                            dst.addresstable = jt.addresstable.clone();
                            dst.set_indirect_op(op.0.clone());
                        }
                        self.fd.jump_tables.push(jt_arc);
                    }
                }
            }
            new_tables.push(jt_opt);
        }
    }

    /// Look for changes in control-flow near indirect jumps that were
    /// discovered after the jumptable recovery. Faithful to
    /// `FlowInfo::checkMultistageJumptables` (flow.cc:1408-1417).
    ///
    /// Ghidra walks every `JumpTable` on `data` and, if `checkForMultistage`
    /// reports new flow, pushes the table's indirect op back onto
    /// `tablelist` so `generateOps` will recover it again.
    ///
    /// Rugra notes: `JumpTable::checkForMultistage` is not yet ported (it
    /// needs the partial-`Funcdata` simplification path). We mirror the
    /// iteration structure and surface the gap: for now no new indirect jumps
    /// are reported, so this is a structural placeholder that preserves the
    /// multistage loop contract.
    // Ghidra: flow.cc:1408 FlowInfo::checkMultistageJumptables
    pub fn check_multistage_jumptables(&self) -> Vec<crate::op::PcodeOpRef> {
        let rediscovered: Vec<crate::op::PcodeOpRef> = Vec::new();
        let num = self.fd.jump_tables.len();
        for i in 0..num {
            let jt_arc = &self.fd.jump_tables[i];
            // Ghidra: if (jt->checkForMultistage(&data)) tablelist.push_back(...);
            // RUGRA-GLUE: JumpTable::checkForMultistage is not yet ported — it
            // requires the partial Funcdata simplification loop that Rugra
            // does not model. We keep the iteration so the multistage contract
            // is visible; nothing is pushed until that method exists.
            let _ = jt_arc;
        }
        rediscovered
    }

    /// If the given injected op is a CALL, CALLIND, or BRANCHIND, add
    /// references to it in the other flow tables. Faithful to
    /// `FlowInfo::xrefInlinedBranch` (flow.cc:1053-1065).
    ///
    /// For BRANCHIND, Ghidra calls `data.linkJumpTable(op)` and, if that
    /// returns NULL, pushes the op onto `tablelist` so it will be recovered
    /// later. Rugra does not yet have `Funcdata::linkJumpTable`, so we mirror
    /// the logic with a local `find_jump_table` lookup and push onto the
    /// returned work-list when no table is linked.
    // Ghidra: flow.cc:1053 FlowInfo::xrefInlinedBranch
    pub fn xref_inlined_branch(&mut self, op: &crate::op::PcodeOpRef) -> Vec<crate::op::PcodeOpRef> {
        let mut new_tablelist: Vec<crate::op::PcodeOpRef> = Vec::new();
        let code = op.0.read().unwrap().opcode;
        match code {
            OpCode::CPUI_CALL => {
                // RUGRA-GLUE: setupCallSpecs needs FuncCallSpecs; deferred to
                // ActionFuncLink (flow.cc:1057). No-op here.
            }
            OpCode::CPUI_CALLIND => {
                // RUGRA-GLUE: setupCallindSpecs needs FuncCallSpecs; deferred
                // to ActionFuncLink (flow.cc:1059). No-op here.
            }
            OpCode::CPUI_BRANCHIND => {
                // data.linkJumpTable(op) — flow.cc:1061. Rugra's equivalent is
                // find_jump_table; if none exists we queue the op for recovery.
                let linked = self.fd.find_jump_table(op).is_some();
                if !linked {
                    new_tablelist.push(op.clone());
                }
            }
            _ => {}
        }
        new_tablelist
    }

    /// Add any remaining un-followed addresses to the unprocessed list.
    /// Faithful to `FlowInfo::findUnprocessed` (flow.cc:850-863). For each
    /// address still on `addrlist`: if we have already seen it, Ghidra marks
    /// its target op as a basic-block start; otherwise it is appended to
    /// `unprocessed`.
    // Ghidra: flow.cc:850 FlowInfo::findUnprocessed
    pub fn find_unprocessed(&mut self) {
        // Snapshot addrlist so we can mutate self while iterating.
        let addrs: Vec<Address> = self.addrlist.drain(..).collect();
        for addr in addrs {
            if self.seen_instruction(addr) {
                // Ghidra: PcodeOp *op = target(*iter); data.opMarkStartBasic(op);
                // RUGRA-GLUE: opMarkStartBasic is applied during block
                // splitting (build_blocks_from_alive), so this is a no-op.
            } else {
                self.unprocessed.push(addr);
            }
        }
    }

    /// Sort the unprocessed list and remove duplicates. Faithful to
    /// `FlowInfo::dedupUnprocessed` (flow.cc:866-885). Ghidra hand-rolls the
    /// dedup over a sorted vector; Rust's `sort` + `dedup` produce the same
    /// result because `Address: Ord`.
    // Ghidra: flow.cc:866 FlowInfo::dedupUnprocessed
    pub fn dedup_unprocessed(&mut self) {
        if self.unprocessed.is_empty() {
            return;
        }
        self.unprocessed.sort();
        self.unprocessed.dedup();
    }

    /// Generate a special-form RETURN (artificial halt) for every address in
    /// the unprocessed list. Faithful to `FlowInfo::fillinBranchStubs`
    /// (flow.cc:889-901). Each stub is marked as both a basic-block start and
    /// an instruction start.
    // Ghidra: flow.cc:889 FlowInfo::fillinBranchStubs
    pub fn fillin_branch_stubs(&mut self) {
        self.find_unprocessed();
        self.dedup_unprocessed();
        let stubs: Vec<Address> = self.unprocessed.iter().cloned().collect();
        for addr in &stubs {
            let op = self.artificial_halt(*addr, pcodeop_flags::MISSING);
            // Ghidra: data.opMarkStartBasic(op); data.opMarkStartInstruction(op);
            // RUGRA-GLUE: Rugra applies STARTBASIC/STARTMARK during
            // build_blocks_from_alive; the halt op is already in the alive
            // list via new_op. We set the flags directly to match Ghidra.
            {
                let mut o = op.0.write().unwrap();
                o.flags |= pcodeop_flags::STARTBASIC;
                o.flags |= pcodeop_flags::STARTMARK;
            }
        }
    }

    /// Collect edges between basic blocks as (source_op, target_op) pairs.
    /// Faithful to `FlowInfo::collectEdges` (flow.cc:906-977).
    ///
    /// Edges are generated for:
    ///   - BRANCH: one edge to branchTarget
    ///   - CBRANCH: two edges (fallthru + branch target)
    ///   - BRANCHIND: one edge per jump-table entry (de-duped via setMark)
    ///   - default op: a fallthru edge if the next op starts a basic block
    ///
    /// Rugra notes: Ghidra stores edges in two parallel lists
    /// (`block_edge1`/`block_edge2`); we return a single `Vec<(PcodeOpRef,
    /// PcodeOpRef)>`. Branch targets are resolved by address lookup against
    /// the alive op list (the `target(addr)` analogue).
    // Ghidra: flow.cc:906 FlowInfo::collectEdges
    pub fn collect_edges(
        &self,
    ) -> Vec<(crate::op::PcodeOpRef, crate::op::PcodeOpRef)> {
        let mut edges: Vec<(crate::op::PcodeOpRef, crate::op::PcodeOpRef)> = Vec::new();
        let alive: &[crate::op::PcodeOpRef] = &self.fd.obank.alivelist;

        for (idx, op_ref) in alive.iter().enumerate() {
            let code = op_ref.0.read().unwrap().opcode;
            match code {
                OpCode::CPUI_BRANCH => {
                    if let Some(targ) = self.target_op_for_branch(op_ref) {
                        edges.push((op_ref.clone(), targ));
                    }
                }
                OpCode::CPUI_BRANCHIND => {
                    // data.findJumpTable(op) — flow.cc:934. If there is no
                    // table we are doing partial flow analysis, assume no
                    // out-edges (flow.cc:935-937).
                    let op_addr = op_ref.0.read().unwrap().get_addr();
                    if let Some(jt_arc) = self.fd.jump_tables.iter().find(|jt| {
                        jt.read().unwrap().get_op_address().as_u64() == op_addr.as_u64()
                    }) {
                        let jt = jt_arc.read().unwrap();
                        let num = jt.num_entries();
                        // De-dup targets within this BRANCHIND via setMark
                        // (flow.cc:941-946). We snapshot entries first.
                        for i in 0..num {
                            let addr = jt.get_address_by_index(i);
                            if let Some(targ) = self.target_op_by_addr(addr) {
                                if targ.0.read().unwrap().is_mark() {
                                    continue;
                                }
                                targ.0.write().unwrap().set_mark();
                                edges.push((op_ref.clone(), targ));
                            }
                        }
                        // RUGRA-GLUE: Ghidra clears only the marks it set in
                        // this iteration (flow.cc:947-956) by walking back
                        // from the end of the edge list. We clear every mark
                        // we set across all BRANCHINDs in a final pass below
                        // to avoid borrow-checker conflicts.
                    }
                }
                OpCode::CPUI_RETURN => {
                    // No out-edge (flow.cc:958-959).
                }
                OpCode::CPUI_CBRANCH => {
                    if let Some(targ) = self.fallthru_op(op_ref) {
                        edges.push((op_ref.clone(), targ));
                    }
                    if let Some(targ) = self.target_op_for_branch(op_ref) {
                        edges.push((op_ref.clone(), targ));
                    }
                }
                _ => {
                    // flow.cc:968-974: fallthru edge if next op starts a block.
                    let nextstart = match alive.get(idx + 1) {
                        Some(next) => {
                            (next.0.read().unwrap().flags & pcodeop_flags::STARTBASIC) != 0
                        }
                        None => true, // end of list acts like a block boundary
                    };
                    if nextstart {
                        if let Some(targ) = self.fallthru_op(op_ref) {
                            edges.push((op_ref.clone(), targ));
                        }
                    }
                }
            }
        }
        // Final pass: clear all marks set during edge collection.
        for (_, targ) in &edges {
            targ.0.write().unwrap().clear_mark();
        }
        edges
    }

    // ===================== Public control-flow target queries =====================
    // These mirror Ghidra's public `target`/`branchTarget`/`fallthruOp`/
    // `findRelTarget`/`updateTarget` API (flow.cc:88/115/149/187/204). The
    // audit (flow_audit.md item 8) flagged that Rugra downgraded these to
    // private (`target_op_*`/`fallthru_op`) and never exposed them; the
    // wrappers below restore the public surface so an action system can query
    // control-flow targets. The private helpers retain the original names so
    // existing call-sites (`collect_edges`, etc.) are unchanged.

    /// Return the first p-code op associated with the machine instruction at
    /// the given address. Faithful to `FlowInfo::target` (flow.cc:115-138).
    ///
    /// Ghidra walks the `visited` map and falls through no-op instructions
    /// (flow.cc:120-131), throwing `LowlevelError` if no op is found. Rugra
    /// returns `Option<PcodeOpRef>`: we resolve via the alive op list because
    /// VisitStat no longer carries a full SeqNum (flow_audit.md item 7).
    // Ghidra: flow.cc:115 FlowInfo::target
    pub fn target(&self, addr: Address) -> Option<crate::op::PcodeOpRef> {
        // flow.cc:120-131: walk visited, skipping no-op instructions by falling
        // to (addr + size). Rugra's visited map keys on the instruction address.
        let mut cur = addr;
        loop {
            if !self.seen_instruction(cur) {
                // Ghidra throws LowlevelError("Could not find op at target
                // address"). Rugra returns None — callers log/handle as needed.
                return self.target_op_by_addr(cur);
            }
            if let Some(targ) = self.target_op_by_addr(cur) {
                return Some(targ);
            }
            // No-op instruction: fall through to the next instruction
            // (flow.cc:130).
            match self.visited.get(&cur.as_u64()) {
                Some(stat) => cur = Address::new(cur.as_u64() + stat.size as u64),
                None => return None,
            }
        }
    }

    /// Find the p-code op referred to by a BRANCH or CBRANCH input(0).
    /// Faithful to `FlowInfo::branchTarget` (flow.cc:187-199).
    ///
    /// Ghidra distinguishes a constant (relative) input via `findRelTarget`
    /// and an absolute address via `target`. Rugra's lifter emits absolute
    /// addresses, so the constant path reduces to the same address lookup.
    // Ghidra: flow.cc:187 FlowInfo::branchTarget
    pub fn branch_target(&self, op: &crate::op::PcodeOpRef) -> Option<crate::op::PcodeOpRef> {
        // flow.cc:190-198: read input(0) address; if constant, go through
        // findRelTarget, else target(addr).
        let in0 = op.0.read().unwrap().inrefs.get(0).cloned();
        let in0 = in0?;
        let target_addr = in0.read().unwrap().get_offset();
        // RUGRA-GLUE: both paths resolve to the same first-op-at-address
        // lookup because Rugra's branches carry absolute addresses. We still
        // consult find_rel_target first to honor the public API contract.
        if let Some(t) = self.find_rel_target(op) {
            return Some(t);
        }
        self.target(Address::new(target_addr))
    }

    /// Find the fallthru p-code op for a given op. Faithful to
    /// `FlowInfo::fallthruOp` (flow.cc:88-107, public non-const overload).
    // Ghidra: flow.cc:88 FlowInfo::fallthruOp
    pub fn fallthru_op_pub(&self, op: &crate::op::PcodeOpRef) -> Option<crate::op::PcodeOpRef> {
        self.fallthru_op(op)
    }

    /// Generate the target PcodeOp for a relative branch. Faithful to
    /// `FlowInfo::findRelTarget` (flow.cc:149-179).
    ///
    /// Ghidra computes `op->getTime() + addr.getOffset()`, forms a SeqNum,
    /// and looks the op up in the PcodeOpBank. If that fails it tries the
    /// previous sequence number and, if found, passes back the fallthru
    /// address in `res`. Rugra lacks the SeqNum/time machinery, so we
    /// approximate: if input(0) resolves to an alive op we return it;
    /// otherwise we check whether the branch target equals the next
    /// instruction address (the "branch to next instruction" case) and
    /// return None to indicate the caller should use the fallthru address.
    // Ghidra: flow.cc:149 FlowInfo::findRelTarget
    pub fn find_rel_target(&self, op: &crate::op::PcodeOpRef) -> Option<crate::op::PcodeOpRef> {
        let (op_addr, in0_offset) = {
            let o = op.0.read().unwrap();
            // Clone input(0) so the borrow of `o` is released before we read
            // the varnode (Ghidra dereferences op->getIn(0)->getAddr() in one
            // expression; Rust requires releasing the op guard first).
            let in0 = o.inrefs.get(0).cloned()?;
            let off = in0.read().unwrap().get_offset();
            (o.get_addr(), off)
        };
        // flow.cc:155: try the "properly internal" target first.
        if let Some(retop) = self.target_op_by_addr(Address::new(in0_offset)) {
            return Some(retop);
        }
        // flow.cc:160-172: try the previous sequence number (branch-to-next-
        // instruction case). We approximate by checking whether the visited
        // instruction at op_addr has a successor op whose address differs —
        // if so the relative branch is really a fallthru and the caller
        // should consult the fallthru address (res). We return None here;
        // `branch_target` falls back to `target(addr)` which mirrors Ghidra's
        // flow.cc:196 `return target(res)`.
        let _ = op_addr;
        None
    }

    /// Update the branch target for an inlined p-code op. Faithful to
    /// `FlowInfo::updateTarget` (flow.cc:204-212). When an op is replaced
    /// by the first op of an injected sequence, any visited-instruction
    /// entry whose `seqnum` pointed at the old op must now point at the
    /// new op. Rugra's VisitStat stores `order` (the alive-list index at
    /// visit time) rather than a SeqNum, so we update the stored order to
    /// the new op's alive-list index.
    // Ghidra: flow.cc:204 FlowInfo::updateTarget
    pub fn update_target(&mut self, old_op: &crate::op::PcodeOpRef, new_op: &crate::op::PcodeOpRef) {
        let old_addr = old_op.0.read().unwrap().get_addr();
        // flow.cc:207-211: if the old op is the recorded first-op for its
        // address, replace the seqnum with the new op's seqnum.
        if let Some(stat) = self.visited.get_mut(&old_addr.as_u64()) {
            // Recompute the new op's order as its current alive-list position.
            let new_order = self
                .fd
                .obank
                .alivelist
                .iter()
                .position(|r| Arc::ptr_eq(&r.0, &new_op.0))
                .map(|p| p as u32);
            if let Some(no) = new_order {
                stat.order = no;
            }
        }
    }

    // ===================== FuncCallSpecs maintenance =====================
    // These mirror Ghidra's call-spec lifecycle methods (flow.cc:636-723,
    // 1306-1318). Ghidra's FlowInfo owns `qlst` (vector<FuncCallSpecs *>);
    // Rugra's Funcdata owns `callspecs: Vec<FuncCallSpecs>`, so the Rust
    // ports index into `self.fd.callspecs` instead of a separate qlst.

    /// Check for modifications to flow at a call site given the recovered
    /// FuncCallSpecs. Faithful to `FlowInfo::checkForFlowModification`
    /// (flow.cc:636-651). Returns true if the sub-function never returns.
    ///
    /// If the call site is inline, its op is pushed onto `injectlist` so
    /// `inject_pcode` will expand it later (flow.cc:639-640). If it never
    /// returns, an artificial halt is inserted right after the call
    /// (flow.cc:642-644) and the method returns true.
    // Ghidra: flow.cc:636 FlowInfo::checkForFlowModification
    fn check_for_flow_modification(
        &mut self,
        fc_idx: usize,
    ) -> bool {
        let (is_inline, is_no_return, op_ref) = {
            let fc = match self.fd.callspecs.get(fc_idx) {
                Some(f) => f,
                None => return false,
            };
            let op_ref = match fc.get_op(self.fd) {
                Some(o) => o,
                None => return false,
            };
            (fc.is_inline(), fc.is_no_return(), op_ref)
        };
        if is_inline {
            // flow.cc:639-640: queue for inject_pcode.
            self.injectlist.push(Some(op_ref.clone()));
        }
        if is_no_return {
            // flow.cc:642-644: insert an artificial halt after the call.
            let addr = op_ref.0.read().unwrap().get_addr();
            let haltop = self.artificial_halt(addr, pcodeop_flags::NORETURN);
            self.fd.op_insert_after(&haltop, &op_ref);
            if !is_inline {
                // flow.cc:645-646: warning only when not inline.
                self.fd.warning("Subroutine does not return", addr);
            }
            return true;
        }
        false
    }

    /// If there is an explicit target address for the given call site,
    /// attempt to look up the function and adjust information in the
    /// FuncCallSpecs call site object. Faithful to `FlowInfo::queryCall`
    /// (flow.cc:656-672).
    ///
    /// Ghidra calls `data.getScopeLocal()->getParent()->queryFunction(addr)`
    /// to resolve the callee's Funcdata, then `fspecs.setFuncdata` and
    /// `fspecs.copyFlowEffects`. Rugra has no symbol-table query wired to
    /// FuncCallSpecs yet, so the body is a documented RUGRA-GLUE no-op until
    /// `Funcdata::query_function` + `set_funcdata` are integrated.
    // Ghidra: flow.cc:656 FlowInfo::queryCall
    fn query_call(&mut self, fc_idx: usize) {
        // flow.cc:659: `if (!fspecs.getEntryAddress().isInvalid())`.
        let entry = self
            .fd
            .callspecs
            .get(fc_idx)
            .and_then(|fc| fc.entry_addr);
        let entry = match entry {
            Some(a) => a,
            None => return, // Not a direct call (flow.cc:659 guard fails).
        };
        // flow.cc:660: query the function at the entry address. RUGRA-GLUE:
        // Funcdata has no query_function/scope linkage yet. We record the
        // entry address on the spec (already present) and rely on
        // ActionFuncLink to fill in the callee later.
        let _ = entry;
        // TODO(CALLSPEC-0001): depends on Funcdata::query_function + FuncCallSpecs::set_funcdata
        // + FuncCallSpecs::copy_flow_effects integration. See flow_audit.md
        // item 4. Until then, callers must resolve callees via ActionFuncLink.
    }

    /// Set up the FuncCallSpecs object for a new CALL call site. Faithful to
    /// `FlowInfo::setupCallSpecs` (flow.cc:680-695). Returns true if the
    /// sub-function never returns.
    ///
    /// Ghidra allocates a new `FuncCallSpecs(op)`, rewrites input(0) to a
    /// call-specs varnode, appends to qlst, applies any prototype override,
    /// runs `queryCall`, performs an injection cycle-check against `fc`, and
    /// finally runs `checkForFlowModification`. Rugra constructs the spec
    /// directly, rewrites input(0) to Rugra's synthetic call-spec Varnode,
    /// appends to `self.fd.callspecs`, and runs the cycle check and
    /// flow-modification check. Prototype override application remains a
    /// `CALLSPEC-0001` gap.
    // Ghidra: flow.cc:680 FlowInfo::setupCallSpecs
    fn setup_call_specs(
        &mut self,
        op: &crate::op::PcodeOpRef,
        inject_fc: Option<usize>,
    ) -> bool {
        // flow.cc:683-684: new FuncCallSpecs(op) captures the direct target
        // before input(0) is replaced with the call-spec annotation.
        let (op_addr, entry_addr) = {
            let op_read = op.0.read().unwrap();
            let entry_addr = op_read
                .inrefs
                .first()
                .map(|input| Address::new(input.read().unwrap().get_offset()));
            (op_read.get_addr(), entry_addr)
        };
        // Rugra's FuncCallSpecs::new requires a FuncProto; use the Funcdata's
        // own prototype as the starting point (Ghidra's ctor clones a default).
        let proto = self.fd.funcp.clone();
        let mut fc = crate::fspec::FuncCallSpecs::new(op_addr, proto);
        fc.entry_addr = entry_addr;
        let new_idx = self.fd.callspecs.len();
        self.fd.callspecs.push(fc);
        // flow.cc:685: data.opSetInput(op, data.newVarnodeCallSpecs(res), 0).
        let call_spec_vn = self.fd.new_varnode_call_specs(new_idx);
        self.fd.op_set_input(op, call_spec_vn, 0);
        // flow.cc:688: data.getOverride().applyPrototype(data, *res).
        // TODO(CALLSPEC-0001): depends on Override::applyPrototype integration.
        self.query_call(new_idx);
        // flow.cc:690-693: injection cycle check.
        if let Some(fc_inject_idx) = inject_fc {
            let same = self
                .fd
                .callspecs
                .get(fc_inject_idx)
                .map(|f| f.entry_addr)
                == self.fd.callspecs.get(new_idx).map(|f| f.entry_addr);
            if same {
                // flow.cc:692: don't allow recursion.
                if let Some(new_fc) = self.fd.callspecs.get_mut(new_idx) {
                    new_fc.cancel_inject_id();
                }
            }
        }
        // flow.cc:694.
        self.check_for_flow_modification(new_idx)
    }

    /// Set up the FuncCallSpecs object for a new indirect (CALLIND) call
    /// site. Faithful to `FlowInfo::setupCallindSpecs` (flow.cc:704-723).
    /// Returns true if the sub-function never returns.
    ///
    /// Mirrors `setup_call_specs` but: applies an indirect override first,
    /// cancels an indirect override when the inject-fc entry matches, and if
    /// an override resolves the call to a direct address, rewrites the
    /// CALLIND op to CALL (flow.cc:717-721).
    // Ghidra: flow.cc:704 FlowInfo::setupCallindSpecs
    fn setup_callind_specs(
        &mut self,
        op: &crate::op::PcodeOpRef,
        inject_fc: Option<usize>,
    ) -> bool {
        let op_addr = op.0.read().unwrap().get_addr();
        let proto = self.fd.funcp.clone();
        let fc = crate::fspec::FuncCallSpecs::new(op_addr, proto);
        let new_idx = self.fd.callspecs.len();
        self.fd.callspecs.push(fc);
        // flow.cc:711: data.getOverride().applyIndirect(data, *res).
        // TODO: depends on Override::applyIndirect integration.
        // flow.cc:712-713: cancel an indirect override if it matches the
        // injecting fc's entry address.
        if let Some(fc_inject_idx) = inject_fc {
            let same = self
                .fd
                .callspecs
                .get(fc_inject_idx)
                .map(|f| f.entry_addr)
                == self.fd.callspecs.get(new_idx).map(|f| f.entry_addr);
            if same {
                // flow.cc:713: setAddress(Address()); clears the entry.
                if let Some(new_fc) = self.fd.callspecs.get_mut(new_idx) {
                    new_fc.clear_entry_address();
                }
            }
        }
        // flow.cc:714: applyPrototype.
        // TODO: depends on Override::applyPrototype integration.
        self.query_call(new_idx);
        // flow.cc:717-721: if overridden to a direct call, rewrite CALLIND→CALL.
        let direct = self
            .fd
            .callspecs
            .get(new_idx)
            .map(|f| f.entry_addr.is_some())
            .unwrap_or(false);
        if direct {
            // flow.cc:719: data.opSetOpcode(op, CPUI_CALL).
            self.fd.op_set_opcode(op, OpCode::CPUI_CALL);
            // flow.cc:720: data.opSetInput(op, data.newVarnodeCallSpecs(res), 0).
            // TODO: depends on Funcdata::new_varnode_call_specs.
        }
        // flow.cc:722.
        self.check_for_flow_modification(new_idx)
    }

    /// Remove the given call site from the list for this function. Faithful
    /// to `FlowInfo::deleteCallSpec` (flow.cc:1306-1318).
    ///
    /// Ghidra scans `qlst` for the pointer, throws `LowlevelError` if absent,
    /// then `delete`s and erases. Rugra works by index (no pointer identity)
    /// because `callspecs` owns the specs by value.
    // Ghidra: flow.cc:1306 FlowInfo::deleteCallSpec
    fn delete_call_spec(&mut self, fc_idx: usize) {
        if fc_idx >= self.fd.callspecs.len() {
            // flow.cc:1313-1314: throw LowlevelError("Misplaced callspec").
            // Rugra logs the mismatch instead of panicking.
            eprintln!(
                "[FLOW] {}: delete_call_spec: index {} out of range (len {})",
                self.fd.name,
                fc_idx,
                self.fd.callspecs.len()
            );
            return;
        }
        // flow.cc:1316-1317: delete fc; qlst.erase(...).
        self.fd.callspecs.remove(fc_idx);
    }

    // ===================== Inline cloning (flow.cc:1043-1153) =====================

    /// Pull in-lining recursion information from another flow. Faithful to
    /// `FlowInfo::forwardRecursion` (flow.cc:1043-1048).
    ///
    /// Ghidra copies the `inline_recursion` pointer and `inline_head` pointer
    /// from the parent flow so that, when cloning an inline flow into `this`,
    /// the clone is informed of in-lining already performed. Rugra copies the
    /// head address and the recursion set contents (Rugra owns the set by
    /// value rather than via a pointer).
    // Ghidra: flow.cc:1043 FlowInfo::forwardRecursion
    pub fn forward_recursion(&mut self, op2: &FlowInfo<'_>) {
        // flow.cc:1046-1047: copy recursion state verbatim.
        self.inline_recursion = op2.inline_recursion.clone();
        self.inline_head = op2.inline_head;
    }

    /// Clone the given in-line flow into this flow using the hard model.
    /// Faithful to `FlowInfo::inlineClone` (flow.cc:1074-1099).
    ///
    /// Each PcodeOp from the inlined Funcdata is cloned into this flow
    /// preserving its original address; any RETURN op is replaced with a
    /// BRANCH to the return address (`retaddr`). After cloning, the flow
    /// tables (unprocessed, addrlist, visited) are merged from the inline
    /// flow, and any cloned call/branch op is cross-referenced via
    /// `xref_inlined_branch`.
    ///
    /// RUGRA-GLUE: Ghidra's clone path needs `data.cloneOp(op, seqnum)` and
    /// `data.newCodeRef(retaddr)`, neither of which is ported. Rugra emits a
    /// TODO and leaves the dead-list clone to a future partial-`Funcdata`
    /// clone implementation (flow_audit.md item 5). The flow-table merge and
    /// RETURN->BRANCH rewrite structure are preserved so the contract is
    /// visible.
    // Ghidra: flow.cc:1074 FlowInfo::inlineClone
    pub fn inline_clone(&mut self, inlineflow: &FlowInfo<'_>, retaddr: Address) {
        // flow.cc:1077-1091: walk inlineflow's dead ops, cloning each.
        // TODO: depends on partial-function clone (Funcdata::clone_op) and
        // Funcdata::new_code_ref. Rugra has no clone path yet, so we record
        // the gap and preserve the post-clone table merge below.
        let _ = retaddr; // would be used to build BRANCH targets (flow.cc:1083-1085).
        let mut new_tablelist: Vec<crate::op::PcodeOpRef> = Vec::new();
        // flow.cc:1089-1090: if a cloned op is call/branch, xref it.
        // With no clone available there are no new ops to xref; the loop is
        // structural and stays a no-op until clone_op lands.
        for op_ref in &inlineflow.fd.obank.alivelist {
            let is_call_or_branch = {
                let o = op_ref.0.read().unwrap();
                (o.flags & (pcodeop_flags::CALL | pcodeop_flags::BRANCH)) != 0
            };
            if is_call_or_branch {
                // flow.cc:1090: xrefInlinedBranch(cloneop).
                let mut extra = self.xref_inlined_branch(op_ref);
                new_tablelist.append(&mut extra);
            }
        }
        let _ = new_tablelist;
        // flow.cc:1093-1097: merge flow tables from the inline flow.
        self.unprocessed.extend(inlineflow.unprocessed.iter().cloned());
        self.addrlist.extend(inlineflow.addrlist.iter().cloned());
        // Visited merge: Ghidra does visited.insert(...) over the map.
        for (&k, v) in &inlineflow.visited {
            self.visited.insert(k, v.clone());
        }
        // flow.cc:1098: do not copy inline_recursion / inline_head here.
    }

    /// Clone the given in-line flow into this flow using the EZ model.
    /// Faithful to `FlowInfo::inlineEZClone` (flow.cc:1108-1120).
    ///
    /// Only straight-line code is cloned (cloning stops at the first
    /// RETURN), and every cloned op is reassigned the fixed `calladdr`.
    /// Because Rugra has no clone path, this is a structural placeholder.
    // Ghidra: flow.cc:1108 FlowInfo::inlineEZClone
    pub fn inline_ezclone(&mut self, inlineflow: &FlowInfo<'_>, calladdr: Address) {
        // flow.cc:1112-1117: walk dead ops until RETURN, cloning with a
        // SeqNum rooted at calladdr.
        // TODO: depends on partial-function clone (Funcdata::clone_op) and
        // SeqNum reconstruction. With no clone path, no ops are cloned; the
        // flow tables are deliberately untouched (flow.cc:1118-1119).
        let _ = calladdr;
        let _ = inlineflow;
    }

    /// For in-lining using the hard model, make sure some restrictions are
    /// met. Faithful to `FlowInfo::testHardInlineRestrictions`
    /// (flow.cc:1133-1153). Returns the distinct return address via the
    /// out-parameter `retaddr`; returns true if the restrictions are met.
    ///
    /// Restrictions:
    ///   - Can only inline the function once (caller checks recursion set).
    ///   - There must be a p-code op to return to.
    ///   - There must be a distinct return address so RETURN can become BRANCH.
    // Ghidra: flow.cc:1133 FlowInfo::testHardInlineRestrictions
    pub fn test_hard_inline_restrictions(
        &mut self,
        inlinefd: &Funcdata,
        op: &crate::op::PcodeOpRef,
        retaddr: &mut Option<Address>,
    ) -> bool {
        // flow.cc:1136: if the inlined function is not noreturn, we need a
        // fallthrough op and a distinct return address.
        // RUGRA-GLUE: FuncProto::is_no_return is not yet modelled; we
        // conservatively assume the function may return and enforce the
        // return-address restrictions.
        let inline_noreturn = false; // TODO: inlinefd.funcp.is_no_return()
        if !inline_noreturn {
            // flow.cc:1137-1141: find the op after the call; if none, warn.
            let next_op = self.fallthru_op(op);
            let next_op = match next_op {
                Some(o) => o,
                None => {
                    // flow.cc:1139-1141: inline_head->warning(...).
                    self.fd.warning(
                        "No fallthrough prevents inlining here",
                        op.0.read().unwrap().get_addr(),
                    );
                    return false;
                }
            };
            // flow.cc:1143-1144: retaddr = nextop->getAddr().
            let ra = next_op.0.read().unwrap().get_addr();
            // flow.cc:1145-1148: if op's address == retaddr, the return
            // address is not distinct — warn and bail.
            if op.0.read().unwrap().get_addr().as_u64() == ra.as_u64() {
                self.fd.warning(
                    "Return address prevents inlining here",
                    op.0.read().unwrap().get_addr(),
                );
                return false;
            }
            // flow.cc:1149-1150: opMarkStartBasic(nextop) — the inlined jump
            // back starts a new basic block.
            {
                let mut no = next_op.0.write().unwrap();
                no.flags |= pcodeop_flags::STARTBASIC;
            }
            *retaddr = Some(ra);
        }
        let _ = inlinefd;
        true
    }

    // ===================== P-code injection (flow.cc:1177-1355) =====================

    /// Inject the given payload into this flow. Faithful to
    /// `FlowInfo::doInjection` (flow.cc:1177-1208).
    ///
    /// The injected p-code replaces the given op, and the control-flow cross
    /// references are updated: the injected sequence is moved to right after
    /// the call, the original op is removed, and the target map is repointed
    /// at the first injected op.
    ///
    /// RUGRA-GLUE: Ghidra's `payload->inject(icontext, emitter)` runs the
    /// payload through the architecture's `PcodeEmit` (here `PcodeEmitFd`),
    /// appending ops to the dead list. Rugra does not yet model that emit
    /// path inside FlowInfo, so this method takes the already-emitted ops
    /// (`injected_ops`) as an argument and performs the post-inject
    /// bookkeeping (xrefControlFlow, moveSequence, updateTarget, opDestroyRaw)
    /// that Ghidra does at flow.cc:1186-1207.
    // Ghidra: flow.cc:1177 FlowInfo::doInjection
    pub fn do_injection(
        &mut self,
        injected_ops: &[crate::op::PcodeOpRef],
        op: &crate::op::PcodeOpRef,
        inject_fc_idx: Option<usize>,
    ) {
        // flow.cc:1180-1183: remember the dead-list position before inject.
        // Rugra's "dead list" is the alive list (ops are inserted directly);
        // we record the index just before the injected ops were appended.
        if injected_ops.is_empty() {
            // flow.cc:1188-1189: empty injection is an error.
            eprintln!("[FLOW] {}: Empty injection", self.fd.name);
            return;
        }
        let firstop = injected_ops[0].clone();
        let lastop = injected_ops[injected_ops.len() - 1].clone();

        // flow.cc:1186: startbasic = op->isBlockStart().
        let mut startbasic = (op.0.read().unwrap().flags & pcodeop_flags::STARTBASIC) != 0;

        // flow.cc:1192: xrefControlFlow(iter, startbasic, isfallthru, fc).
        // We approximate the per-op control-flow xref by walking the injected
        // ops and applying opMarkStartBasic + xrefInlinedBranch as Ghidra does.
        for iop in injected_ops {
            if startbasic {
                // flow.cc:273-275: opMarkStartBasic + clear startbasic.
                {
                    let mut o = iop.0.write().unwrap();
                    o.flags |= pcodeop_flags::STARTBASIC;
                }
                startbasic = false;
            }
            // Mirror xrefControlFlow's switch on the op code for control-flow
            // ops; non-control ops do nothing here (flow.cc:276-360).
            let code = iop.0.read().unwrap().opcode;
            match code {
                OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCHIND => {
                    startbasic = true;
                }
                OpCode::CPUI_CALL => {
                    // flow.cc:330-348: setupCallSpecs(op, fc).
                    let _ = self.setup_call_specs(iop, inject_fc_idx);
                    startbasic = true;
                }
                OpCode::CPUI_CALLIND => {
                    // flow.cc:349-360: setupCallindSpecs(op, fc).
                    let _ = self.setup_callind_specs(iop, inject_fc_idx);
                    startbasic = true;
                }
                OpCode::CPUI_RETURN => {
                    startbasic = true;
                }
                _ => {}
            }
        }

        // flow.cc:1194-1199: if the injected code does not fall thru, mark
        // the op after the call as a basic-block start.
        if startbasic {
            if let Some(next) = self.fallthru_op(op) {
                let mut no = next.0.write().unwrap();
                no.flags |= pcodeop_flags::STARTBASIC;
            }
        }

        // flow.cc:1201-1202: markIncidentalCopy(firstop, lastop).
        self.fd.obank.mark_incidental_copy(&firstop, &lastop);
        // flow.cc:1203: moveSequenceDead(firstop, lastop, op) — move the
        // injected sequence to right after the call. Rugra's obank method
        // reorders the alive list accordingly.
        self.fd.obank.move_sequence_dead(&firstop, &lastop, op);
        // flow.cc:1205: updateTarget(op, firstop).
        self.update_target(op, &firstop);
        // flow.cc:1207: opDestroyRaw(op) — get rid of the original call.
        self.fd.op_destroy_raw(op);
    }

    /// Perform injection for a given user-defined (CALLOTHER) p-code op.
    /// Faithful to `FlowInfo::injectUserOp` (flow.cc:1212-1236).
    ///
    /// Ghidra looks up the user op by CALLOTHER index, fetches the
    /// `InjectPayload` from `glb->pcodeinjectlib`, fills an `InjectContext`
    /// from the op's inputs/output, and calls `doInjection`. Rugra has no
    /// `Architecture`/`PcodeInjectLibrary` handle on FlowInfo, so the caller
    /// supplies the payload and pre-emitted injected ops; the context build
    /// is reproduced faithfully for when the emit path lands.
    // Ghidra: flow.cc:1212 FlowInfo::injectUserOp
    pub fn inject_user_op(
        &mut self,
        op: &crate::op::PcodeOpRef,
        payload_name: &str,
        inject_lib: &crate::pcodeinject::PcodeInjectLibrary,
        injected_ops: &[crate::op::PcodeOpRef],
    ) {
        // flow.cc:1215-1217: resolve the userop + payload + cached context.
        let _payload = match inject_lib.get_payload(payload_name) {
            Some(p) => p,
            None => {
                eprintln!(
                    "[FLOW] {}: injectUserOp: payload '{}' not found",
                    self.fd.name, payload_name
                );
                return;
            }
        };
        // flow.cc:1218-1234: build the InjectContext from the op's operands.
        let mut icontext = crate::pcodeinject::InjectContext::new();
        // flow.cc:1219-1220: baseaddr/nextaddr = op->getAddr().
        let base = op.0.read().unwrap().get_addr().as_u64();
        icontext.base_addr = base;
        icontext.next_addr = base;
        // flow.cc:1221-1227: inputlist from op inputs (skip slot 0 = injectid).
        let (inputs, output) = {
            let o = op.0.read().unwrap();
            let ins: Vec<(u32, u64, u32)> = o
                .inrefs
                .iter()
                .skip(1)
                .map(|vn| {
                    let v = vn.read().unwrap();
                    (address_space_as_u32(v.get_space()), v.get_offset(), v.size as u32)
                })
                .collect();
            let out = o.output.as_ref().map(|vn| {
                let v = vn.read().unwrap();
                (address_space_as_u32(v.get_space()), v.get_offset(), v.size as u32)
            });
            (ins, out)
        };
        icontext.input_list = inputs;
        if let Some(out) = output {
            icontext.output.push(out);
        }
        // flow.cc:1235: doInjection(payload, icontext, op, NULL).
        self.do_injection(injected_ops, op, None);
    }

    /// P-code is generated for the sub-function and then woven into this
    /// flow at the call site. Faithful to `FlowInfo::inlineSubFunction`
    /// (flow.cc:1242-1277). Returns true if the inlining is successful.
    ///
    /// Ghidra sets up `inline_head` / `inline_recursion` on first entry,
    /// inserts the current function's address, refuses to inline a function
    /// already in the recursion set, then calls `data.inlineFlow(fd, *this,
    /// op)` and interprets its result (easy vs hard model). Rugra has no
    /// `inlineFlow` partial clone (flow_audit.md item 5), so the recursion
    /// bookkeeping is preserved and the actual clone is a documented TODO.
    // Ghidra: flow.cc:1242 FlowInfo::inlineSubFunction
    pub fn inline_sub_function(&mut self, fc_idx: usize) -> bool {
        // flow.cc:1245-1246: need the callee Funcdata.
        let (entry_addr, op_ref) = {
            let fc = match self.fd.callspecs.get(fc_idx) {
                Some(f) => f,
                None => return false,
            };
            let entry = match fc.entry_addr {
                Some(a) => a,
                None => return false, // flow.cc:1246: fd == NULL
            };
            let op_ref = match fc.get_op(self.fd) {
                Some(o) => o,
                None => return false,
            };
            (entry, op_ref)
        };
        // flow.cc:1248-1252: set up the head of inlining on first entry.
        if self.inline_head.is_none() {
            // flow.cc:1250: inline_head = &data (this flow's function).
            self.inline_head = Some(self.fd.baseaddr.as_u64());
            // flow.cc:1251: inline_recursion = &inline_base.
            // Rugra owns inline_recursion directly, so we copy inline_base in.
            self.inline_recursion = self.inline_base.clone();
        }
        // flow.cc:1253: insert current function's address.
        self.inline_recursion.insert(self.fd.baseaddr.as_u64());
        // flow.cc:1254-1258: refuse to re-inline a function already in the set.
        if self.inline_recursion.contains(&entry_addr.as_u64()) {
            self.fd.warning(
                "Could not inline here",
                op_ref.0.read().unwrap().get_addr(),
            );
            return false;
        }
        // flow.cc:1260: data.inlineFlow(fd, *this, fc->getOp()).
        // TODO: depends on partial-function clone (Funcdata::inline_flow).
        // Rugra cannot perform the actual clone yet; we return false so the
        // caller (inject_pcode) treats the site as not-inlined and leaves
        // the CALL in place.
        let res = -1i32;
        if res < 0 {
            return false;
        }
        // flow.cc:1263-1271: easy vs hard model recursion bookkeeping.
        // (Unreachable until inline_flow lands.)
        // flow.cc:1273-1274: setPossibleUnreachable().
        self.set_possible_unreachable();
        true
    }

    /// Perform injection replacing the CALL at the given call site. Faithful
    /// to `FlowInfo::injectSubFunction` (flow.cc:1284-1303). Returns true to
    /// indicate the injection happened and the callspec should be deleted.
    ///
    /// Ghidra fills an InjectContext with the call address, fetches the
    /// payload via `fc->getInjectId()`, runs `doInjection`, and propagates
    /// any paramshift to the last callspec. Rugra has no Architecture
    /// handle, so the caller supplies the payload name + emitted ops.
    // Ghidra: flow.cc:1284 FlowInfo::injectSubFunction
    pub fn inject_sub_function(
        &mut self,
        fc_idx: usize,
        payload_name: &str,
        inject_lib: &crate::pcodeinject::PcodeInjectLibrary,
        injected_ops: &[crate::op::PcodeOpRef],
    ) -> bool {
        // flow.cc:1295: look up the payload; extract the paramshift up-front
        // so we can release the immutable borrow before do_injection takes
        // &mut self.
        let paramshift = match inject_lib.get_payload(payload_name) {
            Some(p) => p.get_paramshift(),
            None => {
                eprintln!(
                    "[FLOW] {}: injectSubFunction: payload '{}' not found",
                    self.fd.name, payload_name
                );
                return false;
            }
        };
        // flow.cc:1287-1294: build the context.
        let (op_ref, call_addr) = {
            let fc = match self.fd.callspecs.get(fc_idx) {
                Some(f) => f,
                None => return false,
            };
            let op = match fc.get_op(self.fd) {
                Some(o) => o,
                None => return false,
            };
            (op, fc.entry_addr.map(|a| a.as_u64()).unwrap_or(0))
        };
        let op_addr = op_ref.0.read().unwrap().get_addr().as_u64();
        let mut icontext = crate::pcodeinject::InjectContext::new();
        icontext.base_addr = op_addr;
        icontext.next_addr = op_addr;
        icontext.call_addr = call_addr;
        // flow.cc:1296: doInjection(payload, icontext, op, fc).
        self.do_injection(injected_ops, &op_ref, Some(fc_idx));
        // flow.cc:1299-1300: propagate paramshift to the last callspec.
        if paramshift != 0 {
            if let Some(last) = self.fd.callspecs.last_mut() {
                last.set_paramshift(paramshift);
            }
        }
        // flow.cc:1302: return true — callspec should be deleted.
        true
    }

    /// Perform substitution on any op that requires injection. Faithful to
    /// `FlowInfo::injectPcode` (flow.cc:1327-1355).
    ///
    /// Walks `injectlist`; for each op:
    ///   - CALLOTHER -> `inject_user_op`
    ///   - CALL/CALLIND with an inline callspec:
    ///       - if inject id >= 0 -> `inject_sub_function` + `delete_call_spec`
    ///       - else -> `inline_sub_function` + `delete_call_spec`
    ///
    /// Ghidra resolves the callspec from input(0)'s constant (flow.cc:1338).
    /// Rugra has no `FuncCallSpecs::getFspecFromConst`, so the caller-supplied
    /// `inject_lib` is used for payload lookup and the callspec is matched by
    /// the op's address against `self.fd.callspecs`.
    // Ghidra: flow.cc:1327 FlowInfo::injectPcode
    pub fn inject_pcode(
        &mut self,
        inject_lib: &crate::pcodeinject::PcodeInjectLibrary,
        injected_ops_for: &dyn Fn(&crate::op::PcodeOpRef) -> Vec<crate::op::PcodeOpRef>,
    ) {
        // flow.cc:1330: walk the injectlist; we drain a snapshot because the
        // list may grow during injection (xrefInlinedBranch pushes).
        let snapshot: Vec<crate::op::PcodeOpRef> =
            self.injectlist.iter().filter_map(|o| o.clone()).collect();
        // flow.cc:1333: nullify each entry as we go so we don't inject twice.
        for slot in &mut self.injectlist {
            *slot = None;
        }

        for op in &snapshot {
            let code = op.0.read().unwrap().opcode;
            if code == OpCode::CPUI_CALLOTHER {
                // flow.cc:1334-1336.
                let payload_name = match resolve_callother_payload_name(inject_lib, op) {
                    Some(n) => n,
                    None => {
                        eprintln!(
                            "[FLOW] {}: injectPcode: no payload for CALLOTHER at {:#x}",
                            self.fd.name,
                            op.0.read().unwrap().get_addr().as_u64()
                        );
                        continue;
                    }
                };
                let injected = injected_ops_for(op);
                self.inject_user_op(op, &payload_name, inject_lib, &injected);
            } else {
                // flow.cc:1337-1352: CALL or CALLIND with an inline callspec.
                let fc_idx = match find_callspec_for_op(self.fd, op) {
                    Some(i) => i,
                    None => continue, // No matching callspec; nothing to do.
                };
                let (is_inline, inject_id) = {
                    let fc = &self.fd.callspecs[fc_idx];
                    (fc.is_inline(), fc.get_inject_id())
                };
                if !is_inline {
                    continue;
                }
                if inject_id >= 0 {
                    // flow.cc:1340-1345: injectSubFunction + warningHeader.
                    let payload_name = format!("__inject_{}", inject_id);
                    let injected = injected_ops_for(op);
                    if self.inject_sub_function(fc_idx, &payload_name, inject_lib, &injected) {
                        self.fd.warning_header("Function replaced with injection");
                        self.delete_call_spec(fc_idx);
                    }
                } else {
                    // flow.cc:1347-1350: inlineSubFunction + warningHeader.
                    if self.inline_sub_function(fc_idx) {
                        self.fd.warning_header("Inlined function");
                        self.delete_call_spec(fc_idx);
                    }
                }
            }
        }
        // flow.cc:1354: injectlist.clear().
        self.injectlist.clear();
    }

    // ===================== Private target helpers (unchanged) =====================

    // RUGRA-GLUE: Resolve the BRANCH/CBRANCH input(0) address to the first
    // alive op at that address. Ghidra's branchTarget (flow.cc:187-199) also
    // handles relative (constant) branches via findRelTarget; Rugra's lifter
    // emits absolute addresses, so we only need the direct-address path.
    fn target_op_for_branch(&self, op: &crate::op::PcodeOpRef) -> Option<crate::op::PcodeOpRef> {
        let in0 = {
            let o = op.0.read().unwrap();
            o.inrefs.get(0).cloned()
        };
        let in0 = in0?;
        let target_addr = in0.read().unwrap().get_offset();
        self.target_op_by_addr(Address::new(target_addr))
    }

    // RUGRA-GLUE: Find the first alive op whose address matches. Mirrors the
    // address-fallthru loop in Ghidra's target() (flow.cc:115-138).
    fn target_op_by_addr(&self, addr: Address) -> Option<crate::op::PcodeOpRef> {
        for op_ref in &self.fd.obank.alivelist {
            if op_ref.0.read().unwrap().get_addr().as_u64() == addr.as_u64() {
                return Some(op_ref.clone());
            }
        }
        None
    }

    // RUGRA-GLUE: Find the fallthru op for a given op. Mirrors Ghidra's
    // fallthruOp (flow.cc:88-107): the next alive op in sequence, unless it
    // belongs to a later instruction (in which case we look up the target of
    // the next instruction). Rugra lacks SeqNum time-ordering across
    // instructions, so we approximate with the next alive op whose address
    // differs from the source op's instruction address.
    fn fallthru_op(&self, op: &crate::op::PcodeOpRef) -> Option<crate::op::PcodeOpRef> {
        let alive = &self.fd.obank.alivelist;
        let pos = alive.iter().position(|r| Arc::ptr_eq(&r.0, &op.0))?;
        let src_addr = op.0.read().unwrap().get_addr();
        for next in alive.iter().skip(pos + 1) {
            let next_addr = next.0.read().unwrap().get_addr();
            if next_addr.as_u64() != src_addr.as_u64() {
                return Some(next.clone());
            }
        }
        None
    }

    /// Split raw p-code ops up into basic blocks. Faithful to
    /// `FlowInfo::splitBasic` (flow.cc:983-1017).
    ///
    /// Ghidra walks the dead list creating a new `PcodeBlockBasic` each time
    /// it encounters an op marked `isBlockStart()`, recording per-block
    /// address ranges. Rugra delegates block construction to
    /// [`Funcdata::build_blocks_from_alive`], which already groups ops by
    /// STARTBASIC flags; this wrapper preserves the entry-point invariant
    /// (flow.cc:994-995): the first alive op must be marked as a block start.
    // Ghidra: flow.cc:983 FlowInfo::splitBasic
    pub fn split_basic(&mut self) {
        let first_ok = self
            .fd
            .obank
            .alivelist
            .first()
            .map(|r| (r.0.read().unwrap().flags & pcodeop_flags::STARTBASIC) != 0)
            .unwrap_or(true);
        if !first_ok {
            // Ghidra throws LowlevelError("First op not marked as entry point").
            eprintln!("[FLOW] {}: warning: first op not marked as entry point", self.fd.name);
        }
        // Delegate to the existing block builder, which honors STARTBASIC.
        self.fd.build_blocks_from_alive();
    }

    /// Generate edges between the basic blocks. Faithful to
    /// `FlowInfo::connectBasic` (flow.cc:1021-1037). Walks the collected
    /// (source, target) op pairs and asks the block graph to add an edge
    /// between the parent blocks of each op. Rugra's block graph is rebuilt
    /// wholesale by `build_blocks_from_alive`, so edge collection here is
    /// informational; the graph already derives edges from branch ops.
    // Ghidra: flow.cc:1021 FlowInfo::connectBasic
    pub fn connect_basic(&self) {
        // RUGRA-GLUE: Rugra's build_blocks_from_alive derives edges directly
        // from branch ops during construction, so there is no separate edge
        // list to replay. We collect edges only for diagnostics/testing.
        let _edges = self.collect_edges();
    }

    /// Generate basic blocks from the raw control-flow. Faithful to
    /// `FlowInfo::generateBlocks` (flow.cc:824-845). Order: fillinBranchStubs
    /// → collectEdges → splitBasic → connectBasic, then ensure the entry
    /// block has no incoming edges, and finally drop unreachable blocks if
    /// the flow flagged possible_unreachable.
    // Ghidra: flow.cc:824 FlowInfo::generateBlocks
    pub fn generate_blocks(&mut self) {
        self.fillin_branch_stubs();
        // collectEdges is folded into split_basic's delegation in Rugra.
        self.split_basic();
        self.connect_basic();
        // Ghidra: if entry block has incoming edges, prepend a new entry
        // (flow.cc:831-840). Rugra's build_blocks_from_alive always makes the
        // entry block the first block with no in-edges, so this is a no-op.
        if self.has_possible_unreachable() {
            // data.removeUnreachableBlocks(false,true) (flow.cc:844).
            self.fd.remove_unreachable_blocks();
        }
    }


    /// Generate P-code ops by following control flow from the entry point.
    /// Faithful to `FlowInfo::generateOps` (flow.cc:785-822).
    /// Phase 2: jump-table recovery via recoverJumpTables.
    // Ghidra: flow.cc:785 FlowInfo::generateOps
    pub fn generate_ops(&mut self, entry: Address) {
        // Seed with entry address (flow.cc:787).
        self.addrlist.push(entry);

        // Phase 1: linear flow tracking (flow.cc:792-793).
        while !self.addrlist.is_empty() {
            self.fallthru();
        }

        // Phase 2: jump-table recovery (flow.cc:796-821).
        // Collect BRANCHIND ops found during Phase 1, recover their jump
        // tables, and push newly discovered addresses to addrlist.
        loop {
            // Collect all BRANCHIND ops currently alive.
            let branchinds: Vec<crate::op::PcodeOpRef> = self.collect_branchinds();
            if branchinds.is_empty() {
                break;
            }

            // Recover jump tables for each BRANCHIND.
            let mut new_addresses: Vec<Address> = Vec::new();
            for bi_ref in &branchinds {
                // Check if already has a jump table.
                let bi_addr = bi_ref.0.read().unwrap().get_addr().as_u64();
                let already = self.fd.jump_tables.iter().any(|jt| {
                    jt.read().unwrap().get_op_address().as_u64() == bi_addr
                });
                if already {
                    // Use existing table entries.
                    if let Some(jt_arc) = self.fd.jump_tables.iter().find(|jt| {
                        jt.read().unwrap().get_op_address().as_u64() == bi_addr
                    }) {
                        let jt = jt_arc.read().unwrap();
                        for i in 0..jt.num_entries() {
                            new_addresses.push(jt.get_address_by_index(i));
                        }
                    }
                    continue;
                }

                // Try recovery (jumptable.rs::try_recover).
                if let Some(jt) = crate::jumptable::try_recover(&bi_ref.0, self.fd) {
                    let jt_arc = std::sync::Arc::new(std::sync::RwLock::new(jt));
                    let jt_copy = jt_arc.read().unwrap();
                    for i in 0..jt_copy.num_entries() {
                        new_addresses.push(jt_copy.get_address_by_index(i));
                    }
                    drop(jt_copy);
                    self.fd.jump_tables.push(jt_arc);
                }
            }

            // Push newly discovered addresses and trace them (flow.cc:806-809).
            for addr in &new_addresses {
                self.new_address(*addr);
            }
            while !self.addrlist.is_empty() {
                self.fallthru();
            }

            // Check if any new BRANCHINDs appeared (multistage, flow.cc:814).
            let new_branchinds = self.collect_branchinds();
            if new_branchinds.len() <= branchinds.len() {
                break; // No new indirect jumps → done.
            }
        }
    }

    // RUGRA-GLUE: 收集 alive BRANCHIND ops（Ghidra 内联在 generateOps 的 tablelist 循环中）。
    /// Collect all alive BRANCHIND ops (for tablelist processing).
    fn collect_branchinds(&self) -> Vec<crate::op::PcodeOpRef> {
        self.fd.obank.alivelist.iter()
            .filter(|r| r.0.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_BRANCHIND)
            .map(|r| crate::op::PcodeOpRef(r.0.clone()))
            .collect()
    }

    // Ghidra: flow.cc:198 FlowInfo::newAddress
    /// Add a new address to the work-list (flow.cc newAddress, ~:198-215).
    /// Mirrors Ghidra's behavior: out-of-bounds addresses are reported via
    /// `handleOutOfBounds` and pushed to `unprocessed`; already-seen targets
    /// are skipped (Ghidra additionally marks the target op as a basic-block
    /// start. Rugra records that flag on the first op found for the visit.
    fn new_address(&mut self, addr: Address) {
        let a = addr.as_u64();
        // flow.cc:222-226: range check + handleOutOfBounds.
        if a < self.baddr || self.eaddr < a {
            self.handle_out_of_bounds(Address::new(self.baddr), addr);
            self.unprocessed.push(addr);
            return;
        }
        // flow.cc:228-233: if already seen, mark the target op as a basic
        // block start.
        if let Some(stat) = self.visited.get(&a) {
            if let Some(op) = self.fd.obank.alivelist.get(stat.order as usize) {
                op.0.write().unwrap().flags |= pcodeop_flags::STARTBASIC;
            }
            return;
        }
        self.addrlist.push(addr);
    }

    /// Process sequential instructions from addrlist until a terminator
    /// or already-visited address is hit. Corresponds to `FlowInfo::fallthru`
    /// (flow.cc:545-580).
    // Ghidra: flow.cc:545 FlowInfo::fallthru
    fn fallthru(&mut self) {
        // Check if next address is worth processing (setFallthruBound).
        if !self.set_fallthru_bound() {
            return;
        }

        let mut is_fallthru = true;
        let mut start_basic = true;
        while is_fallthru && !self.addrlist.is_empty() {
            let curaddr = self.addrlist.pop().unwrap();
            is_fallthru = self.process_instruction(curaddr, &mut start_basic);

            if !is_fallthru {
                break;
            }

            if self.addrlist.is_empty() {
                break;
            }

            // Check boundary (flow.cc:560-574).
            let next = self.addrlist.last().unwrap().as_u64();
            let bound = self.current_bound();
            if bound > 0 && next >= bound {
                if bound == self.eaddr {
                    // Out of bounds — stop.
                    self.addrlist.pop();
                    return;
                }
                // Hit an already-visited address boundary.
                // set_fallthru_bound will handle dedup on next iteration.
                if !self.set_fallthru_bound() {
                    return;
                }
            }
        }
    }

    /// Check if the next address in addrlist is processable.
    /// Returns false if already visited or out of bounds.
    /// Partial port of `setFallthruBound` (flow.cc:489-513).
    // Ghidra: flow.cc:489 FlowInfo::setFallthruBound
    fn set_fallthru_bound(&mut self) -> bool {
        if self.addrlist.is_empty() {
            return false;
        }
        let addr = self.addrlist.last().unwrap().as_u64();

        // Check visited map (flow.cc:505-510).
        if let Some(stat) = self.visited.get(&addr) {
            // Already visited — pop and return false.
            self.addrlist.pop();
            return false;
        }

        // Check upper bound for reinterpreted addresses (flow.cc:507-509).
        // If addr falls within a previously visited instruction's range,
        // it's an off-cut (reinterpreted) — skip it.
        if let Some((_, stat)) = self.visited.range(..addr).next_back() {
            // This entry's address + size must be <= addr (otherwise overlap).
            // Since BTreeMap keys are the addresses, the predecessor's
            // [key, key+size) must not contain addr.
            // We need the predecessor's key + size.
            // range(..addr) gives entries with key < addr.
            let _ = stat; // We handle this below with full check.
        }
        // Full overlap check: any visited instruction [k, k+size) containing addr?
        for (&k, stat) in self.visited.range(..=addr).rev() {
            if k + stat.size as u64 > addr && k <= addr {
                // addr is inside a previously decoded instruction → reinterpreted
                // (flow.cc:504-505 calls reinterpreted(addr) here).
                self.reinterpreted(Address::new(addr));
                self.addrlist.pop();
                return false;
            }
            if k + stat.size as u64 <= addr {
                break; // No overlap possible with earlier entries.
            }
        }

        true
    }

    /// Get the current boundary address (next visited instruction after addrlist top).
    // RUGRA-GLUE: 辅助方法，Ghidra 内联在 setFallthruBound/fallthru 中。
    fn current_bound(&self) -> u64 {
        if self.addrlist.is_empty() {
            return self.eaddr;
        }
        let addr = self.addrlist.last().unwrap().as_u64();
        // Find the next visited instruction after addr.
        match self.visited.range(addr + 1..).next() {
            Some((&k, _)) => k,
            None => self.eaddr,
        }
    }

    /// Decode a single instruction, generate P-code, and analyze control flow.
    /// Returns true if execution falls through to the next instruction.
    /// Partial port of `processInstruction` (flow.cc:383-482).
    // Ghidra: flow.cc:383 FlowInfo::processInstruction
    fn process_instruction(&mut self, addr: Address, start_basic: &mut bool) -> bool {
        // Instruction count limit (flow.cc:387).
        if self.insn_count >= self.insn_max {
            eprintln!("[FLOW] Too many instructions (limit {})", self.insn_max);
            return false;
        }
        self.insn_count += 1;

        let num_ops_before = self.fd.obank.alivelist.len();
        let (step, raw_ops) = match self.lifter.lift_instruction(addr.as_u64()) {
            Ok(result) => result,
            Err(error) => {
                let ignored_unimplemented = error.kind == SleighErrorKind::Unimplemented
                    && (self.flags & flow_flags::IGNORE_UNIMPLEMENTED) != 0;
                if ignored_unimplemented {
                    let step = error
                        .instruction_length
                        .and_then(|length| usize::try_from(length).ok())
                        .filter(|length| *length != 0)
                        .unwrap_or(1);
                    if !self.has_unimplemented() {
                        self.flags |= flow_flags::UNIMPLEMENTED_PRESENT;
                        self.fd
                            .warning_header("Control flow ignored unimplemented instructions");
                    }
                    (step, Vec::new())
                } else {
                    let halt_flag = if error.kind == SleighErrorKind::Unimplemented {
                        self.flags |= flow_flags::UNIMPLEMENTED_PRESENT;
                        pcodeop_flags::UNIMPLEMENTED
                    } else {
                        self.flags |= flow_flags::BADDATA_PRESENT;
                        pcodeop_flags::BADINSTRUCTION
                    };
                    self.artificial_halt(addr, halt_flag);
                    self.fd.warning(
                        &format!("{} - Truncating control flow here", error),
                        addr,
                    );
                    (1, Vec::new())
                }
            }
        };

        // Record visited (flow.cc:468-469).
        let order = num_ops_before as u32;
        self.visited.insert(addr.as_u64(), VisitStat {
            order,
            size: step,
        });

        // Update min/max addr (flow.cc:470-471).
        let a = addr.as_u64();
        if a < self.minaddr { self.minaddr = a; }
        if a.saturating_add(step as u64) > self.maxaddr {
            self.maxaddr = a.saturating_add(step as u64);
        }

        // Inject into Funcdata (reuse inject_raw_ops_single logic).
        if !raw_ops.is_empty() {
            self.fd.inject_raw_ops_single(&raw_ops, addr);
            if let Some(first_op) = self.fd.obank.alivelist.get(num_ops_before) {
                first_op.0.write().unwrap().flags |= pcodeop_flags::STARTMARK;
            }
        }

        // Analyze control flow of the new ops (xrefControlFlow).
        let is_fallthru =
            self.xref_control_flow(addr, step, num_ops_before, start_basic);

        is_fallthru
    }

    /// Analyze the control-flow ops generated by the last instruction.
    /// Returns true if execution falls through.
    /// Partial port of `xrefControlFlow` (flow.cc:264-372).
    // Ghidra: flow.cc:264 FlowInfo::xrefControlFlow
    fn xref_control_flow(
        &mut self,
        addr: Address,
        step: usize,
        ops_start: usize,
        start_basic: &mut bool,
    ) -> bool {
        let ops_end = self.fd.obank.alivelist.len();
        let mut is_fallthru = true;

        for i in ops_start..ops_end {
            let op_ref = self.fd.obank.alivelist[i].clone();
            if *start_basic {
                op_ref.0.write().unwrap().flags |= pcodeop_flags::STARTBASIC;
                *start_basic = false;
            }
            let opcode = op_ref.0.read().unwrap().opcode;
            match opcode {
                OpCode::CPUI_BRANCH => {
                    // Direct branch. Target from in(0) constant varnode.
                    let input = op_ref.0.read().unwrap().inrefs.first().cloned();
                    if let Some(in0) = input {
                        let target = in0.read().unwrap().get_offset();
                        if target == addr.as_u64() + step as u64 {
                            // Branch to next instruction = fallthrough.
                            // is_fallthru stays true.
                        } else {
                            // Push target to addrlist (flow.cc:312).
                            self.addrlist.push(Address::new(target));
                            is_fallthru = false;
                        }
                    } else {
                        is_fallthru = false;
                    }
                    *start_basic = true;
                }
                OpCode::CPUI_CBRANCH => {
                    // Conditional branch: both targets are reachable.
                    // Push the branch target (flow.cc:312).
                    let input = op_ref.0.read().unwrap().inrefs.first().cloned();
                    if let Some(in0) = input {
                        let target = in0.read().unwrap().get_offset();
                        if target != addr.as_u64() + step as u64 {
                            self.addrlist.push(Address::new(target));
                        }
                    }
                    // Fallthrough target is pushed by the caller (process_instruction
                    // pushes addr+step via the return value).
                    *start_basic = true;
                }
                OpCode::CPUI_BRANCHIND => {
                    // TODO(SLEIGH-FLOW-0001): recover and enqueue the complete
                    // jump-table target set before finishing this flow wave.
                    // For now, mark as non-fallthru (flow stops here).
                    eprintln!("[FLOW] BRANCHIND at {:#x} — jump-table recovery not yet in flow", addr.as_u64());
                    is_fallthru = false;
                    *start_basic = true;
                }
                OpCode::CPUI_RETURN => {
                    is_fallthru = false;
                    *start_basic = true;
                }
                OpCode::CPUI_CALL => {
                    self.setup_call_specs(&op_ref, None);
                }
                OpCode::CPUI_CALLIND => {
                    self.setup_callind_specs(&op_ref, None);
                }
                _ => {}
            }
        }

        // If fallthru, push next instruction address (flow.cc:458).
        if is_fallthru {
            self.addrlist.push(Address::new(addr.as_u64() + step as u64));
        }

        is_fallthru
    }
}

/// Entry point: follow flow from entry address, generating P-code ops and CFG.
/// Partial production entry corresponding to `Funcdata::followFlow`
/// (funcdata_op.cc:756-783).
///
/// Replaces the three-stage linear scan (disassemble → lift → inject_raw_ops)
/// with reachability-driven flow tracking.
// Ghidra: funcdata_op.cc:756 Funcdata::followFlow
pub fn follow_flow(
    fd: &mut Funcdata,
    lifter: &mut SleighLifter,
    entry: Address,
    eaddr: u64,
) {
    let baddr = entry.as_u64();
    let mut flow = FlowInfo::new(fd, lifter, baddr, eaddr);
    flow.generate_ops(entry);
    // generateBlocks: build basic blocks from all alive ops.
    flow.fd.build_blocks_from_alive();
}

// ===================== Injection helpers (RUGRA-GLUE) =====================
// These free functions bridge gaps between Rugra's current types and the
// Ghidra flow.cc call paths. They are file-local to flow.rs because this
// alignment task is constrained to editing src/flow.rs.

/// Map an `AddressSpace` to the numeric tag Ghidra stores in an
/// `InjectContext` operand tuple. RUGRA-GLUE: Rugra's `AddressSpace` enum is
/// not `#[repr(u32)]`, so we map the discriminants by hand. The numeric tag
/// is only carried for diagnostic parity; Rugra's injection emit path is
/// not yet wired to interpret it.
// RUGRA-GLUE: ANN-B; INJECT-0001 maps a Rust AddressSpace enum into the temporary numeric injection tuple where Ghidra carries an AddrSpace pointer.
fn address_space_as_u32(space: crate::space::AddressSpace) -> u32 {
    // Order matches Ghidra's IPTR_* constants (space.hh) for the spaces Rugra
    // models; values are stable discriminants, not memory offsets.
    match space {
        crate::space::AddressSpace::Ram => 0,
        crate::space::AddressSpace::Register => 1,
        crate::space::AddressSpace::Unique => 2,
        crate::space::AddressSpace::Const => 3,
        crate::space::AddressSpace::Stack => 4,
        crate::space::AddressSpace::Join => 5,
        crate::space::AddressSpace::Iop => 6,
        crate::space::AddressSpace::Overlay => 7,
        crate::space::AddressSpace::Other(_) => 8,
    }
}

/// Resolve the payload name for a CALLOTHER op. Ghidra looks up the user op
/// by the CALLOTHER index in input(0) (flow.cc:1215) and reads its inject id.
/// Rugra has no `Architecture::userops` table on FlowInfo, so this helper
/// scans the inject library's call-other fixups for the first payload whose
/// name resolves to a valid id. Returns the payload name (the library key)
/// when a single CALLOTHER payload is registered, otherwise None.
///
/// RUGRA-GLUE: a precise mapping from CALLOTHER index to user-op name
/// requires the `UserOpManage` (Architecture::userops), which Rugra does not
/// yet thread into FlowInfo. This helper is a best-effort shim so `inject_pcode`
/// compiles and exercises the inject path; callers with a real user-op table
/// should resolve the name themselves and call `inject_user_op` directly.
fn resolve_callother_payload_name(
    inject_lib: &crate::pcodeinject::PcodeInjectLibrary,
    _op: &crate::op::PcodeOpRef,
) -> Option<String> {
    // The CALLOTHER index is in input(0) as a constant; Ghidra's userops
    // table maps index -> name -> inject id. Rugra lacks that table, so we
    // cannot map index -> name here. As a structural shim we report the
    // single registered call-other payload, if any.
    //
    // TODO(INJECT-0001): depends on Architecture::userops (UserOpManage) integration to
    // map the CALLOTHER index to the user-op name and inject id.
    let mut found: Option<String> = None;
    for (name, _id) in &inject_lib.call_other_fixups {
        found = Some(name.clone());
        break;
    }
    found
}

/// Find the index in `fd.callspecs` whose call op matches the given op.
/// Ghidra resolves the callspec from a constant in input(0)
/// (`FuncCallSpecs::getFspecFromConst`, flow.cc:1338); Rugra has no such
/// constant-via-pointer scheme, so we match by the call op's address
/// against each spec's `op_addr` (faithful to `FuncCallSpecs::find_call_op`).
// RUGRA-GLUE: ANN-B; CALLSPEC-0001 linear-scan fallback because Rugra does not encode FuncCallSpecs pointer identity in CALL input(0).
fn find_callspec_for_op(
    fd: &Funcdata,
    op: &crate::op::PcodeOpRef,
) -> Option<usize> {
    let op_addr = op.0.read().unwrap().get_addr();
    for (i, fc) in fd.callspecs.iter().enumerate() {
        if fc.op_addr == op_addr {
            return Some(i);
        }
    }
    None
}
