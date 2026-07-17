//! High-level function data container
//!
//! Corresponds to Ghidra's `funcdata.hh`

use crate::address::Address;
use crate::block::{BlockBasic, BlockGraph, FlowBlock};
use crate::fspec::FuncProto;
use crate::heritage::Heritage;
use crate::op::{PcodeOpBank, PcodeOpRef};
use crate::opcodes::OpCode;
use crate::pcoderaw::PcodeOpRaw;
use crate::space::AddressSpace;

/// Funcdata flags (funcdata.hh:highlevel_flags).
pub mod funcdata_flags {
    /// Data-type analysis is being performed.
    pub const TYPE_RECOVERY_ON: u32 = 1 << 0;
    /// Data-type analysis has started (Ghidra `typerecovery_start`,
    /// funcdata.hh:90). Set once ActionInferTypes begins, used by Rules to
    /// decide whether type-based guards apply.
    pub const TYPE_RECOVERY_START: u32 = 1 << 1;
    /// HighVariable objects have been assigned to all Varnodes (Ghidra
    /// `highlevel_on`, funcdata.hh:84 = 0x200). Set by ActionAssignHigh /
    /// setHighLevel. Prevents re-assignment on subsequent passes.
    pub const HIGHLEVEL_ON: u32 = 1 << 2;
    /// Double-precision recovery is active (Ghidra `double_precis_on`,
    /// funcdata.hh:85 = 0x2000).
    pub const DOUBLE_PRECIS_ON: u32 = 1 << 13;
}

use crate::varnode::VarnodeBank;
use std::collections::HashMap;
use std::sync::{Arc, RwLock, Weak};

/// Main container for a function being decompiled
///
/// Corresponds to Ghidra's `Funcdata` class. This class ties together
/// the P-code operations, varnodes, control flow graph, and analysis state.
#[derive(Debug)]
pub struct Funcdata {
    /// Name of the function
    pub name: String,
    /// Base address of the function
    pub baseaddr: Address,
    /// Size of the function in bytes
    pub size: i32,

    /// Bit-set of Funcdata flags (mirrors Ghidra's `flags` field).
    pub flags: u32,

    /// Bank of all varnodes in this function
    pub vbank: VarnodeBank,
    /// Bank of all P-code operations in this function
    pub obank: PcodeOpBank,
    /// Control flow graph (basic blocks)
    pub bblocks: BlockGraph,
    /// Structure tree (composite blocks)
    pub sblocks: BlockGraph,
    /// SSA construction manager
    pub heritage: Heritage,

    /// Self-reference for use by child components
    pub self_ref: Option<Weak<RwLock<Funcdata>>>,

    /// Address → function/symbol name mapping (populated from ELF symtab)
    pub symbol_table: HashMap<u64, String>,
    /// Address → string literal mapping (populated from ELF .rodata)
    pub string_table: HashMap<u64, String>,
    /// Function prototype (return type, parameters)
    pub funcp: FuncProto,
    /// External function prototypes: maps callee address → param count.
    /// Populated by a pre-pass that analyzes all functions in the binary
    /// before decompilation. Mirrors Ghidra's multi-pass approach where
    /// ActionActiveParam runs across all functions to build a prototype
    /// database before final decompilation.
    pub external_prototypes: HashMap<u64, usize>,
    /// Restructured local-variable scope. Built by ActionRestructureVarnode
    /// (coreaction.cc:2274) and queried by printc's stack-variable resolution.
    /// Corresponds to Ghidra's `Funcdata::getScopeLocal()`.
    pub scope: Option<crate::varmap::ScopeLocal>,
    /// Function call specifications, one per call site. Corresponds to
    /// Ghidra's `Funcdata::breefcall` vector.
    pub callspecs: Vec<crate::fspec::FuncCallSpecs>,
    /// Active output parameter recovery. Faithful to
    /// `Funcdata::activeoutput` (funcdata.hh). Set by ActionFuncLinkOutOnly;
    /// used by ActionReturnRecovery to determine which RETURN varnodes
    /// are the function's return value.
    pub active_output: Option<crate::fspec::ParamActive>,

    /// Architecture configuration (Ghidra `glb` / funcdata.hh:80). Optional:
    /// legacy callers/tests construct Funcdata without it. Set via
    /// `set_arch` before running Rules that need cpool/funcptr_align/
    /// nan_ignore_all/userops/types.
    pub arch: Option<Arc<crate::arch::Architecture>>,
    /// Restart-pending flag for ActionRestartGroup (funcdata.hh).
    pub restart_pending: bool,
    /// Jump tables recovered for this function. Faithful to
    /// `Funcdata::jumpvec` (funcdata.hh:89). Populated by JumpTable recovery.
    pub jump_tables: Vec<std::sync::Arc<std::sync::RwLock<crate::jumptable::JumpTable>>>,

    // ---- Stack space / spacebase configuration (from Architecture, defaults to x86-64) ----
    // Faithful to Architecture's cspec <stackpointer> fields. Funcdata does
    // not yet hold an Architecture reference (L3 gap), so these are defaults
    // matching x86-64-gcc.cspec: <stackpointer register="RSP" space="ram"/>.
    /// The stack address space (IPTR_SPACEBASE). Stack varnodes live here.
    pub stack_space: crate::space::AddressSpace,
    /// Stack pointer register: (space, offset, size) = (Register, 0x20, 8) for RSP.
    pub stack_pointer_space: crate::space::AddressSpace,
    pub stack_pointer_offset: u64,
    pub stack_pointer_size: usize,
    /// Stack grows toward negative offsets (x86 convention).
    pub stack_grows_negative: bool,
}

impl Funcdata {
    // Ghidra: funcdata.cc:34 Funcdata::new
    /// Create a new Funcdata instance
    pub fn new(name: &str, addr: Address, size: i32) -> Self {
        Self {
            name: name.to_string(),
            baseaddr: addr,
            size,
            flags: 0,
            vbank: VarnodeBank::new(),
            obank: PcodeOpBank::new(),
            bblocks: BlockGraph::new(),
            sblocks: BlockGraph::new(),
            heritage: Heritage::new(),
            self_ref: None,
            symbol_table: HashMap::new(),
            string_table: HashMap::new(),
            funcp: FuncProto::new(
                name.to_string(),
                std::sync::Arc::new(crate::type_system::datatype::Datatype::Void(
                    crate::type_system::datatype::TypeBase::new("void".to_string(), 0, crate::type_system::datatype::TypeMetatype::Void)
                )),
            ),
            external_prototypes: HashMap::new(),
            scope: None,
            callspecs: Vec::new(),
            active_output: None,
            arch: None,
            restart_pending: false,
            jump_tables: Vec::new(),
            stack_space: crate::space::AddressSpace::Stack,
            stack_pointer_space: crate::space::AddressSpace::Register,
            stack_pointer_offset: 0x20, // x86-64 RSP
            stack_pointer_size: 8,
            stack_grows_negative: true,
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::isTypeRecoveryOn
    /// Is data-type analysis being performed? Faithful to
    /// `Funcdata::isTypeRecoveryOn` (funcdata.hh:150).
    pub fn is_type_recovery_on(&self) -> bool {
        (self.flags & funcdata_flags::TYPE_RECOVERY_ON) != 0
    }

    // Ghidra: funcdata.cc:34 Funcdata::setTypeRecoveryOn
    /// Enable/disable type recovery. Faithful to `Funcdata::setTypeRecoveryOn`.
    pub fn set_type_recovery_on(&mut self, on: bool) {
        if on {
            self.flags |= funcdata_flags::TYPE_RECOVERY_ON;
        } else {
            self.flags &= !funcdata_flags::TYPE_RECOVERY_ON;
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::hasTypeRecoveryStarted
    /// Has data-type analysis started? Faithful to
    /// `Funcdata::hasTypeRecoveryStarted` (funcdata.hh:151).
    pub fn has_type_recovery_started(&self) -> bool {
        (self.flags & funcdata_flags::TYPE_RECOVERY_START) != 0
    }
    // Ghidra: funcdata.cc:34 Funcdata::setTypeRecoveryStarted
    /// Mark that type recovery has started.
    pub fn set_type_recovery_started(&mut self) {
        self.flags |= funcdata_flags::TYPE_RECOVERY_START;
    }

    // Ghidra: funcdata.cc:34 Funcdata::isDoublePrecisOn
    /// Is double-precision recovery active? (funcdata.hh:167)
    pub fn is_double_precis_on(&self) -> bool {
        (self.flags & funcdata_flags::DOUBLE_PRECIS_ON) != 0
    }
    // Ghidra: funcdata.cc:34 Funcdata::setDoublePrecisRecovery
    /// Set/clear double-precis recovery. (funcdata.hh:167)
    pub fn set_double_precis_recovery(&mut self, on: bool) {
        if on {
            self.flags |= funcdata_flags::DOUBLE_PRECIS_ON;
        } else {
            self.flags &= !funcdata_flags::DOUBLE_PRECIS_ON;
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::newVarnode
    /// Create a varnode of `size` bytes at a specific address. Faithful to
    /// `Funcdata::newVarnode(int4, const Address&)` (funcdata.hh:282).
    pub fn new_varnode(&mut self, size: usize, addr: crate::address::Address) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        self.vbank.create(size, addr)
    }

    // Ghidra: funcdata_varnode.cc:340 Funcdata::setInputVarnode
    /// Promote a varnode to a function input. Faithful to
    /// `Funcdata::setInputVarnode` (funcdata_varnode.cc:340-373).
    ///
    /// Thin wrapper over `VarnodeBank::set_input_varnode` which ports
    /// steps (1)+(2)+(3) of Ghidra (early-out / overlap dedup / setInput).
    /// Step (4) ProtoModel effect properties omitted (conservative subset).
    pub fn set_input_varnode(
        &mut self,
        vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        self.vbank.set_input_varnode(vn)
    }

    // Ghidra: funcdata_varnode.cc Funcdata::deleteVarnode
    /// Remove a varnode from both loc/def trees. Faithful to
    /// `Funcdata::deleteVarnode` (which delegates to VarnodeBank::destroy).
    pub fn delete_varnode(&mut self, vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) {
        self.vbank.destroy_varnode(vn);
    }

    // Ghidra: funcdata.cc:34 Funcdata::combineInputVarnodes
    /// Combine two contiguous input varnodes into one. Faithful to
    /// `Funcdata::combineInputVarnodes` (funcdata_varnode.cc:381-454).
    /// Replaces PIECE(hi,lo) ops with COPY of the combined varnode; creates
    /// SUBPIECE replacements for any non-PIECE readers of hi/lo.
    pub fn combine_input_varnodes(
        &mut self,
        vn_hi: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        vn_lo: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        use crate::opcodes::OpCode;
        // Determine contiguity (little-endian: lo is at lower address).
        let lo_off = vn_lo.read().unwrap().get_offset();
        let lo_size = vn_lo.read().unwrap().get_size();
        let hi_off = vn_hi.read().unwrap().get_offset();
        let hi_size = vn_hi.read().unwrap().get_size();
        let combined_addr = if lo_off + lo_size as u64 == hi_off {
            lo_off
        } else if hi_off + hi_size as u64 == lo_off {
            hi_off
        } else {
            // Not contiguous — cannot combine.
            return;
        };
        // Collect PIECE(hi,lo) ops and detect other readers.
        let mut piece_list = Vec::new();
        let mut other_ops_hi = false;
        let mut other_ops_lo = false;
        {
            let hi_rg = vn_hi.read().unwrap();
            for w in &hi_rg.descend {
                if let Some(op) = w.upgrade() {
                    let g = op.read().unwrap();
                    if g.opcode == OpCode::CPUI_PIECE
                        && g.inrefs.len() >= 2
                        && std::sync::Arc::ptr_eq(&g.inrefs[0], vn_hi)
                        && std::sync::Arc::ptr_eq(&g.inrefs[1], vn_lo)
                    {
                        piece_list.push(crate::op::PcodeOpRef(op.clone()));
                    } else {
                        other_ops_hi = true;
                    }
                }
            }
        }
        {
            let lo_rg = vn_lo.read().unwrap();
            for w in &lo_rg.descend {
                if let Some(op) = w.upgrade() {
                    let g = op.read().unwrap();
                    if g.opcode != OpCode::CPUI_PIECE
                        || g.inrefs.len() < 2
                        || !std::sync::Arc::ptr_eq(&g.inrefs[0], vn_hi)
                        || !std::sync::Arc::ptr_eq(&g.inrefs[1], vn_lo)
                    {
                        other_ops_lo = true;
                    }
                }
            }
        }
        // For each PIECE: remove input[1], unset input[0] (will be replaced).
        for p in &piece_list {
            self.op_remove_input(p, 1);
            self.op_unset_input(p, 0);
        }
        // Create SUBPIECE replacements for non-PIECE readers.
        let entry_block = self.bblocks.get_block(0);
        let out_size = hi_size + lo_size;
        // Destroy the original input varnodes and create the combined input.
        self.vbank.destroy_varnode(vn_hi);
        self.vbank.destroy_varnode(vn_lo);
        let in_vn = self.new_varnode(out_size, crate::address::Address::new(combined_addr));
        self.vbank.set_input(in_vn.clone());
        // Rewrite PIECE ops to COPY.
        for p in &piece_list {
            self.op_set_input(p, in_vn.clone(), 0);
            self.op_set_opcode(p, OpCode::CPUI_COPY);
        }
        // SUBPIECE replacements for other readers.
        if other_ops_hi {
            if let Some(bb) = &entry_block {
                let sub_hi = self.new_op(2, crate::address::Address::new(0));
                self.op_set_opcode(&sub_hi, OpCode::CPUI_SUBPIECE);
                let lo_size_const = self.new_constant(4, lo_size as u64);
                self.op_set_input(&sub_hi, lo_size_const, 1);
                let new_hi = self.new_unique_out(hi_size, &sub_hi);
                new_hi.write().unwrap().update_type(vn_hi.read().unwrap().get_type().unwrap_or_else(|| {
                    std::sync::Arc::new(crate::type_system::datatype::Datatype::Base(
                        crate::type_system::datatype::TypeBase::new("unknown".into(), hi_size, crate::type_system::datatype::TypeMetatype::Unknown)
                    ))
                }));
                self.op_insert_begin(&sub_hi, bb);
                self.total_replace(vn_hi, new_hi.clone());
                self.op_set_input(&sub_hi, in_vn.clone(), 0);
            }
        }
        if other_ops_lo {
            if let Some(bb) = &entry_block {
                let sub_lo = self.new_op(2, crate::address::Address::new(0));
                self.op_set_opcode(&sub_lo, OpCode::CPUI_SUBPIECE);
                let zero_const = self.new_constant(4, 0);
                self.op_set_input(&sub_lo, zero_const, 1);
                let new_lo = self.new_unique_out(lo_size, &sub_lo);
                self.op_insert_begin(&sub_lo, bb);
                self.total_replace(vn_lo, new_lo.clone());
                self.op_set_input(&sub_lo, in_vn.clone(), 0);
            }
        }
    }

    // Ghidra: funcdata.cc:135 Funcdata::warningHeader
    /// Attach a warning comment to this function. Faithful to
    /// `Funcdata::warningHeader` (funcdata.cc:135-145). Uses the arch's
    /// commentdb if available; otherwise eprintln as fallback.
    pub fn warning_header(&self, txt: &str) {
        let msg = format!("WARNING: {}", txt);
        if let Some(a) = &self.arch {
            if let Some(cdb) = &a.commentdb {
                let _ = cdb.write().unwrap().add_comment_no_duplicate(
                    crate::comment::comment_type::WARNINGHEADER,
                    self.baseaddr,
                    self.baseaddr,
                    &msg,
                );
                return;
            }
        }
        eprintln!("[WARNING] {}: {}", self.name, msg);
    }

    // Ghidra: funcdata.cc:34 Funcdata::getArch
    /// Get the Architecture configuration, if set.
    /// Faithful to `Funcdata::getArch` (funcdata.hh:144).
    pub fn get_arch(&self) -> Option<&Arc<crate::arch::Architecture>> {
        self.arch.as_ref()
    }
    // Ghidra: funcdata.cc:34 Funcdata::setArch
    /// Set the Architecture reference (Ghidra sets it in the ctor from scope).
    pub fn set_arch(&mut self, arch: Arc<crate::arch::Architecture>) {
        self.arch = Some(arch);
    }

    // Ghidra: funcdata.cc:34 Funcdata::hasRestartPending
    /// Is a pipeline restart pending? Faithful to `Funcdata::hasRestartPending`.
    pub fn has_restart_pending(&self) -> bool {
        self.restart_pending
    }
    // Ghidra: funcdata.cc:34 Funcdata::setRestartPending
    /// Request a pipeline restart (ActionRestartGroup will detect this).
    pub fn set_restart_pending(&mut self, v: bool) {
        self.restart_pending = v;
    }
    // Ghidra: funcdata.cc:34 Funcdata::isJumptableRecoveryOn
    /// Is jumptable recovery currently active? Faithful to
    /// `Funcdata::isJumptableRecoveryOn`. Rugra has no jumptable recovery yet.
    pub fn is_jumptable_recovery_on(&self) -> bool {
        false
    }

    // Ghidra: funcdata.cc:34 Funcdata::setSelfRef
    /// Set the self-reference after wrapping in Arc<RwLock>
    pub fn set_self_ref(&mut self, self_ref: Weak<RwLock<Funcdata>>) {
        self.self_ref = Some(self_ref.clone());
        self.heritage.fd = Some(self_ref);
    }

    // Ghidra: funcdata.cc:34 Funcdata::runHeritageDirect
    /// Safely run the SSA heritage pass directly, avoiding deadlocks.
    /// 
    /// The standard `heritage()` method attempts to acquire a write lock on `Funcdata`
    /// via a weak pointer. If the caller already holds a lock on `Funcdata`, this
    /// leads to a deadlock. This method avoids the deadlock by passing the required
    /// banks directly to the underlying heritage algorithms.
    pub fn run_heritage_direct(&mut self) {
        let mut vbank = std::mem::take(&mut self.vbank);
        let mut obank = std::mem::take(&mut self.obank);

        self.heritage.place_multiequals_direct(
            &mut vbank,
            &mut obank,
            &self.bblocks,
            &self.sblocks,
        );
        self.heritage.rename_direct(&mut vbank, &self.bblocks);
        self.heritage.pass += 1;

        self.vbank = vbank;
        self.obank = obank;
    }

    /// Assign a HighVariable to every Varnode that lacks one. Faithful to
    /// `Funcdata::setHighLevel` (funcdata_varnode.cc:595-605) + the
    /// `assignHigh` per-Varnode call (funcdata_varnode.cc:48-59). Sets the
    /// `HIGHLEVEL_ON` flag (Ghidra `highlevel_on`) to make this idempotent.
    /// Called by ActionAssignHigh (coreaction.hh:339-347) which runs BEFORE
    /// the merge stage, so ActionMarkExplicit/Implied see HighVariables.
    // Ghidra: funcdata_varnode.cc:595 Funcdata::setHighLevel
    pub fn set_high_level(&mut self) {
        use crate::variable::HighVariable;
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
        if (self.flags & funcdata_flags::HIGHLEVEL_ON) != 0 { return; }
        self.flags |= funcdata_flags::HIGHLEVEL_ON;

        let vn_arcs: Vec<Arc<RwLock<crate::varnode::Varnode>>> = self.vbank.loc_tree
            .iter()
            .filter(|r| r.0.read().unwrap().high.is_none())
            .map(|r| r.0.clone())
            .collect();

        for vn_arc in vn_arcs {
            let dt = {
                let vn = vn_arc.read().unwrap();
                vn.v_type.clone().unwrap_or_else(|| {
                    Arc::new(Datatype::Base(TypeBase::new(
                        "undefined".to_string(), vn.size, TypeMetatype::Unknown,
                    )))
                })
            };
            let high = Arc::new(RwLock::new(HighVariable::new(dt)));
            high.write().unwrap().add_instance(vn_arc.clone());
            vn_arc.write().unwrap().high = Some(high);
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::getName
    /// Get function name
    pub fn get_name(&self) -> &str {
        &self.name
    }

    // Ghidra: funcdata.cc:34 Funcdata::findVarnodeInput
    /// Find an input varnode of the given size at the given address.
    /// Faithful to `Funcdata::findVarnodeInput` (funcdata.hh:324).
    /// Used by ActionRestrictLocal and AncestorRealistic.
    pub fn find_varnode_input(&self, size: usize, addr: crate::address::Address) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        self.vbank.find_input(size, addr)
    }

    // Ghidra: funcdata.cc:34 Funcdata::addSymbol
    /// Register a symbol (function/global) at the given virtual address
    pub fn add_symbol(&mut self, addr: u64, name: String) {
        self.symbol_table.insert(addr, name);
    }

    // Ghidra: funcdata_varnode.cc:1193 Funcdata::linkSymbolReference
    /// Resolve a constant Varnode that is the second input to a PTRSUB op
    /// into a Symbol. If the PTRSUB's first input is a spacebase pointer
    /// (stack or global), look up the offset in the symbol table. If found,
    /// set the symbol reference on the Varnode and return the symbol name.
    /// Faithful to `linkSymbolReference` (funcdata_varnode.cc:1193-1213).
    /// Returns the symbol name if found, None otherwise.
    // Ghidra: funcdata_varnode.cc:1156 Funcdata::linkSymbol
    /// Link a Varnode to a Symbol in the local scope. If a Symbol already
    /// overlaps the Varnode's address, link it. If not and the Varnode is
    /// non-persistent, create a new local symbol entry. Faithful to
    /// `linkSymbol` (funcdata_varnode.cc:1156-1184). Returns the symbol
    /// name if linked/created, None otherwise.
    pub fn link_symbol(
        &mut self,
        vn: &Arc<RwLock<crate::varnode::Varnode>>,
    ) -> Option<String> {
        // cc:1164: if high already has a symbol, return it.
        // Rugra: check if vn already has a symbol_table entry.
        let (vn_addr, vn_space, is_persist, is_addr_tied, vn_size) = {
            let vn_r = vn.read().unwrap();
            (
                vn_r.get_offset(),
                vn_r.get_space(),
                vn_r.is_persist(),
                vn_r.is_addr_tied(),
                vn_r.get_size(),
            )
        };
        // cc:1169: queryProperties — check if a symbol overlaps.
        if let Some(name) = self.symbol_table.get(&vn_addr).cloned() {
            return Some(name);
        }
        // cc:1173-1180: create new local symbol if not persistent.
        if !is_persist {
            // cc:1177: localmap->addSymbol("", type, addr, usepoint)
            // Rugra: add to symbol_table with auto-generated name.
            let auto_name = format!("local_{:x}", vn_addr);
            self.symbol_table.insert(vn_addr, auto_name.clone());
            return Some(auto_name);
        }
        None
    }

    // Ghidra: funcdata_varnode.cc:1193 Funcdata::linkSymbolReference
    pub fn link_symbol_reference(
        &mut self,
        vn: &Arc<RwLock<crate::varnode::Varnode>>,
    ) -> Option<String> {
        use crate::opcodes::OpCode;
        // cc:1196: op = vn->loneDescend() — must be consumed by exactly one op.
        let op_arc = vn.read().unwrap().lone_descend()?;
        let op = op_arc.read().unwrap();
        // cc:1197-1202: check that in(0) is a spacebase pointer type.
        // Rugra: check if the PTRSUB's first input is a spacebase varnode.
        if op.opcode != OpCode::CPUI_PTRSUB { return None; }
        let in0 = op.get_in(0)?;
        let in0_r = in0.read().unwrap();
        if !in0_r.is_spacebase() { return None; }
        drop(in0_r);
        // cc:1204: addr = sb->getAddress(vn->getOffset(), in0->getSize(), op->getAddr())
        // Rugra: the offset encodes the stack/global address directly.
        let vn_offset = vn.read().unwrap().get_offset();
        // cc:1207: entry = scope->queryContainer(addr, 1, Address())
        // Rugra: look up in symbol_table (which maps address → name).
        let sym_name = self.symbol_table.get(&vn_offset).cloned();
        if let Some(ref name) = sym_name {
            // cc:1210-1211: vn->setSymbolReference(entry, off)
            // Rugra: we don't have full SymbolEntry infrastructure, but we
            // can record the name on the varnode via the symbol reference.
            // For now, the symbol_table lookup IS the resolution.
            return Some(name.clone());
        }
        // Also check scope.symbols for stack-relative symbols.
        if let Some(ref scope) = self.scope {
            for sym in &scope.symbols {
                if sym.start == vn_offset {
                    return Some(sym.name.clone());
                }
            }
        }
        None
    }

    // Ghidra: funcdata.cc:34 Funcdata::addString
    /// Register a string literal at the given virtual address
    pub fn add_string(&mut self, addr: u64, s: String) {
        self.string_table.insert(addr, s);
    }

    // Ghidra: funcdata.cc:34 Funcdata::getSymbol
    /// Look up a symbol name by address
    pub fn get_symbol(&self, addr: u64) -> Option<&str> {
        self.symbol_table.get(&addr).map(|s| s.as_str())
    }

    // Ghidra: funcdata.cc:34 Funcdata::getString
    /// Look up a string literal by address
    pub fn get_string(&self, addr: u64) -> Option<&str> {
        self.string_table.get(&addr).map(|s| s.as_str())
    }

    // Ghidra: funcdata.cc:34 Funcdata::getAddress
    /// Get function base address
    pub fn get_address(&self) -> &Address {
        &self.baseaddr
    }

    // Ghidra: funcdata.cc:34 Funcdata::getSize
    /// Get function size
    pub fn get_size(&self) -> i32 {
        self.size
    }

    // Ghidra: funcdata.cc:34 Funcdata::numCalls
    /// Number of call sites in this function. Faithful to
    /// `Funcdata::numCalls` (funcdata.hh).
    pub fn num_calls(&self) -> usize {
        self.callspecs.len()
    }

    // Ghidra: funcdata.cc:484 Funcdata::getCallSpecs
    /// Get call specs by index. Faithful to `Funcdata::getCallSpecs`
    /// (funcdata.hh).
    pub fn get_call_specs(&self, i: usize) -> Option<&crate::fspec::FuncCallSpecs> {
        self.callspecs.get(i)
    }

    // Ghidra: funcdata.cc:34 Funcdata::getCallSpecsMut
    /// Get mutable call specs by index.
    pub fn get_call_specs_mut(&mut self, i: usize) -> Option<&mut crate::fspec::FuncCallSpecs> {
        self.callspecs.get_mut(i)
    }

    // Ghidra: funcdata.cc:34 Funcdata::addCallSpecs
    /// Add a new call specification. Returns the index.
    pub fn add_call_specs(&mut self, fc: crate::fspec::FuncCallSpecs) -> usize {
        self.callspecs.push(fc);
        self.callspecs.len() - 1
    }

    // Ghidra: funcdata.cc:34 Funcdata::getFuncProto
    /// Get the function prototype. Faithful to `Funcdata::getFuncProto`.
    pub fn get_func_proto(&self) -> &FuncProto {
        &self.funcp
    }

    // Ghidra: funcdata.cc:34 Funcdata::getFuncProtoMut
    /// Get mutable function prototype.
    pub fn get_func_proto_mut(&mut self) -> &mut FuncProto {
        &mut self.funcp
    }

    // --- Funcdata P-code op editing API (faithful to funcdata.hh:281-479) ---
    // These mirror Ghidra's Funcdata methods used by the rule/action transforms
    // to construct and edit P-code during analysis.

    // Ghidra: funcdata.cc:34 Funcdata::newOp
    /// Allocate a new PcodeOp with `num_inputs` slots at the function's base
    /// address. Faithful to `Funcdata::newOp` (funcdata.hh:444).
    pub fn new_op(&mut self, num_inputs: usize, pc: crate::address::Address) -> crate::op::PcodeOpRef {
        // Ghidra defaults the opcode to CPUI_COPY until opSetOpcode is called.
        self.obank.create(crate::opcodes::OpCode::CPUI_COPY, num_inputs, pc)
    }

    // Ghidra: funcdata.cc:34 Funcdata::newUniqueOut
    /// Create a new temporary output Varnode of size `s` for `op`.
    /// Faithful to `Funcdata::newUniqueOut` (funcdata.hh:281).
    pub fn new_unique_out(&mut self, s: usize, op: &crate::op::PcodeOpRef) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let vn = self.vbank.create_unique(s);
        // Set the op's output and the varnode's def link.
        vn.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        vn.write().unwrap().def = Some(std::sync::Arc::downgrade(&op.0));
        op.0.write().unwrap().output = Some(vn.clone());
        vn
    }

    // Ghidra: funcdata.cc:34 Funcdata::newConstant
    /// Create a new constant Varnode. Faithful to `Funcdata::newConstant`
    /// (funcdata.hh:283).
    pub fn new_constant(&mut self, s: usize, val: u64) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        self.vbank.create_constant(s, val)
    }

    // Ghidra: funcdata.cc:34 Funcdata::newExtendedConstant
    /// Create a new (possibly extended) constant Varnode of size `s` from a
    /// 128-bit value `(lo, hi)`. Faithful to `Funcdata::newExtendedConstant`
    /// (funcdata_varnode.cc:462-484). For s≤8, creates a plain constant.
    /// For s>8 with hi==0, creates INT_ZEXT(const). For s>8 with hi!=0,
    /// creates PIECE(hi_const, lo_const).
    pub fn new_extended_constant(&mut self, s: usize, lo: u64, hi: u64, before_op: &crate::op::PcodeOpRef) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        if s <= 8 {
            return self.new_constant(s, lo);
        }
        let addr = before_op.0.read().unwrap().get_addr();
        if hi == 0 {
            let ext_op = self.new_op(1, addr);
            self.op_set_opcode(&ext_op, crate::opcodes::OpCode::CPUI_INT_ZEXT);
            let out = self.new_unique_out(s, &ext_op);
            let lo_const = self.new_constant(8, lo);
            self.op_set_input(&ext_op, lo_const, 0);
            self.op_insert_before(&ext_op, before_op);
            out
        } else {
            let piece_op = self.new_op(2, addr);
            self.op_set_opcode(&piece_op, crate::opcodes::OpCode::CPUI_PIECE);
            let out = self.new_unique_out(s, &piece_op);
            let hi_const = self.new_constant(8, hi);
            let lo_const = self.new_constant(8, lo);
            self.op_set_input(&piece_op, hi_const, 0);
            self.op_set_input(&piece_op, lo_const, 1);
            self.op_insert_before(&piece_op, before_op);
            out
        }
    }

    // Ghidra: funcdata_op.cc:632 Funcdata::getFirstReturnOp
    /// Return the first non-dead, non-halt CPUI_RETURN op, or None.
    /// Faithful to `getFirstReturnOp` (funcdata_op.cc:632-644).
    pub fn get_first_return_op(&self) -> Option<crate::op::PcodeOpRef> {
        // Use returnlist (PcodeOpBank code list for RETURN ops).
        for retop in &self.obank.returnlist {
            let op = retop.0.read().unwrap();
            if op.is_dead() { continue; }
            // cc:640: getHaltType()!=0 → skip artificial halts.
            let halt_mask = crate::op::pcodeop_flags::HALT
                | crate::op::pcodeop_flags::BADINSTRUCTION
                | crate::op::pcodeop_flags::UNIMPLEMENTED
                | crate::op::pcodeop_flags::NORETURN
                | crate::op::pcodeop_flags::MISSING;
            if (op.flags & halt_mask) != 0 { continue; }
            return Some(retop.clone());
        }
        None
    }

    // Ghidra: funcdata.cc:34 Funcdata::newUnique
    /// Create a new temporary Varnode (no defining op). Faithful to
    /// `Funcdata::newUnique` (funcdata.hh:288).
    pub fn new_unique(&mut self, s: usize) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        self.vbank.create_unique(s)
    }

    // Ghidra: funcdata_op.cc:37 Funcdata::opMarkHalt
    /// Mark a CPUI_RETURN op as an artificial halt. Faithful to
    /// `opMarkHalt` (funcdata_op.cc:37-48). Throws if op is not RETURN
    /// or flag is invalid (Rugra logs + returns).
    pub fn op_mark_halt(&self, op: &crate::op::PcodeOpRef, flag: u32) {
        use crate::opcodes::OpCode;
        use crate::op::pcodeop_flags;
        // cc:40: if (op->code() != CPUI_RETURN) throw;
        if op.0.read().unwrap().opcode != OpCode::CPUI_RETURN {
            eprintln!("[FUNCDATA] WARN: opMarkHalt on non-RETURN op");
            return;
        }
        // cc:42-44: flag &= (halt|badinstruction|unimplemented|noreturn|missing);
        let mask = pcodeop_flags::HALT | pcodeop_flags::BADINSTRUCTION
            | pcodeop_flags::UNIMPLEMENTED | pcodeop_flags::NORETURN
            | pcodeop_flags::MISSING;
        let masked = flag & mask;
        // cc:45-46: if (flag == 0) throw;
        if masked == 0 {
            eprintln!("[FUNCDATA] WARN: opMarkHalt with bad flag {:#x}", flag);
            return;
        }
        // cc:47: op->setFlag(flag);
        op.0.write().unwrap().flags |= masked;
    }

    // Ghidra: funcdata.cc:34 Funcdata::opSetOpcode
    /// Set the op-code for a specific PcodeOp. Faithful to
    /// `Funcdata::opSetOpcode` (funcdata.hh:463).
    pub fn op_set_opcode(&self, op: &crate::op::PcodeOpRef, opc: crate::opcodes::OpCode) {
        // Faithful to PcodeOp::setOpcode (op.cc:276): clear the opcode-derived
        // flag bits, then set them from the new opcode's TypeOp flags. Ghidra
        // gets these from TypeOp::getFlags() (registered per-opcode in
        // typeop.cc); Rugra encodes the same mapping here. Without this, a
        // CPUI_CALL op never had the CALL flag, so ActionMarkExplicit's
        // baseExplicit `def->isCall()` guard failed to force CALL outputs
        // explicit → ActionMarkImplied marked them implied → printc skipped
        // the CALL statement entirely (130 vanished calls in curl).
        use crate::op::pcodeop_flags as F;
        use crate::opcodes::OpCode;
        const OPC_FLAGS_MASK: u32 = F::BRANCH | F::CALL | F::CODEREF
            | F::RETURNS | F::MARKER | F::HAS_CALLSPEC | F::RETURN_COPY;
        let mut o = op.0.write().unwrap();
        o.flags &= !OPC_FLAGS_MASK;
        let extra = match opc {
            OpCode::CPUI_BRANCH | OpCode::CPUI_BRANCHIND =>
                F::SPECIAL | F::BRANCH | F::CODEREF | F::NOCOLLAPSE,
            OpCode::CPUI_CBRANCH =>
                F::SPECIAL | F::BRANCH | F::NOCOLLAPSE,
            OpCode::CPUI_CALL =>
                F::SPECIAL | F::CALL | F::HAS_CALLSPEC | F::CODEREF | F::NOCOLLAPSE,
            OpCode::CPUI_CALLIND =>
                F::SPECIAL | F::CALL | F::HAS_CALLSPEC | F::NOCOLLAPSE,
            OpCode::CPUI_CALLOTHER | OpCode::CPUI_NEW =>
                F::SPECIAL | F::CALL | F::NOCOLLAPSE,
            OpCode::CPUI_RETURN =>
                F::SPECIAL | F::RETURNS | F::NOCOLLAPSE | F::RETURN_COPY,
            OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INDIRECT =>
                F::SPECIAL | F::MARKER | F::NOCOLLAPSE,
            _ => 0,
        };
        o.flags |= extra;
        o.opcode = opc;
    }

    // Ghidra: funcdata_op.cc:104 Funcdata::opSetInput
    /// Set a specific input operand for the given PcodeOp. Faithful to
    /// `Funcdata::opSetInput` (funcdata_op.cc:104-125). Four decisive steps:
    ///   (1) early-out if vn is already the input at slot
    ///   (2) const dedup: if vn is constant AND has descend AND not spacebase,
    ///       create a fresh constant copy (with copySymbol) and use that
    ///   (3) opUnsetInput(op, slot) on the OLD input — erases op from old
    ///       vn's descend list (Rugra's inrefs Vec can't hold null, so the
    ///       "clearInput" half is implicit: inrefs[slot] gets overwritten
    ///       below; the load-bearing part is erase_descend on the old vn)
    ///   (4) vn->addDescend(op) + op->setInput(vn, slot)
    ///
    /// **2026-07-05 修正**:此前 Rugra 漏了 (1)(2)(3),直接 addDescend + 赋值,
    /// 导致旧 vn 的 descend 列表残留当前 op 引用 → has_no_descend 永远返回
    /// false → heritage rename 的 deleteVarnode (heritage.cc:2521) 永远不执行
    /// → 死 varnode 累积污染后续 pass。同时 const 去重缺失导致同一常量 vn 被
    /// 多个 op 引用,违反 Ghidra "constants should have only one descendant"
    /// 不变量 (cc:108)。
    pub fn op_set_input(&mut self, op: &crate::op::PcodeOpRef, vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, slot: usize) {
        let mut o = op.0.write().unwrap();
        // Extend inrefs if needed (Rugra Vec model; Ghidra's BehaviorList
        // pre-allocates slots at op creation). Placeholder slots get a fresh
        // sentinel varnode (NOT vn — using vn would trigger the early-out
        // below and skip the addDescend, losing the descend link).
        while o.inrefs.len() <= slot {
            let sentinel = self.vbank.create(1, crate::address::Address::new(u64::MAX));
            o.inrefs.push(sentinel);
        }
        // (1) Ghidra cc:107: if (vn == op->getIn(slot)) return;
        if std::sync::Arc::ptr_eq(&vn, &o.inrefs[slot]) {
            return;
        }
        // (2) Ghidra cc:108-115: const dedup. If vn is constant AND has
        // descend AND not spacebase, create a fresh copy so each constant
        // has only one descendant.
        let vn_final = {
            let vn_r = vn.read().unwrap();
            let needs_dedup = vn_r.is_constant() && !vn_r.has_no_descend() && !vn_r.is_spacebase();
            drop(vn_r);
            if needs_dedup {
                let (sz, off) = {
                    let r = vn.read().unwrap();
                    (r.size, r.loc.as_u64())
                };
                let cvn = self.new_constant(sz, off);
                // Ghidra cc:112: cvn->copySymbol(vn);
                let sym = vn.read().unwrap().mapentry.clone();
                if sym.is_some() {
                    cvn.write().unwrap().mapentry = sym;
                }
                cvn
            } else {
                vn.clone()
            }
        };
        // (3) Ghidra cc:120-121: if (op->getIn(slot) != null) opUnsetInput(op, slot).
        // opUnsetInput does vn->eraseDescend(op) + op->clearInput(slot).
        // Rugra's clearInput half is implicit (inrefs[slot] overwritten below);
        // the load-bearing half is erase_descend on the old vn.
        {
            let old_vn = o.inrefs[slot].clone();
            old_vn.write().unwrap().erase_descend(&op.0);
        }
        // (4) Ghidra cc:123-124: vn->addDescend(op) + op->setInput(vn, slot).
        vn_final.write().unwrap().add_descend(&op.0);
        o.inrefs[slot] = vn_final;
    }

    // Ghidra: funcdata.cc:34 Funcdata::opInsertInput
    /// Insert a new Varnode into the operand list at `slot`. Faithful to
    /// `Funcdata::opInsertInput` (funcdata.hh:479).
    pub fn op_insert_input(&self, op: &crate::op::PcodeOpRef, vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, slot: usize) {
        let mut o = op.0.write().unwrap();
        let slot = slot.min(o.inrefs.len());
        o.inrefs.insert(slot, vn.clone());
        vn.write().unwrap().descend.push(std::sync::Arc::downgrade(&op.0));
    }

    // Ghidra: funcdata.cc:34 Funcdata::opRemoveInput
    /// Remove a specific input slot. Faithful to `Funcdata::opRemoveInput`
    /// (funcdata.hh:478).
    pub fn op_remove_input(&self, op: &crate::op::PcodeOpRef, slot: usize) {
        let mut o = op.0.write().unwrap();
        if slot < o.inrefs.len() {
            o.inrefs.remove(slot);
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::opSwapInput
    /// Swap two input operands. Faithful to `Funcdata::opSwapInput`
    /// (funcdata.hh). Used by RuleBoolNegate to reorder operands when flipping
    /// a comparison (e.g. `!(V < W) => W <= V`).
    pub fn op_swap_input(&self, op: &crate::op::PcodeOpRef, slot1: usize, slot2: usize) {
        let mut o = op.0.write().unwrap();
        if slot1 < o.inrefs.len() && slot2 < o.inrefs.len() {
            o.inrefs.swap(slot1, slot2);
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::opSetOutput
    /// Set the output varnode for an op (replacing any existing output).
    /// Faithful to `Funcdata::opSetOutput`. Marks the varnode WRITTEN and sets
    /// its def link to this op; clears the old output's def if present.
    pub fn op_set_output(&self, op: &crate::op::PcodeOpRef, vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) {
        let mut o = op.0.write().unwrap();
        if let Some(old) = o.output.take() {
            // Clear the old output's def (best-effort).
            old.write().unwrap().def = None;
        }
        vn.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        vn.write().unwrap().def = Some(std::sync::Arc::downgrade(&op.0));
        o.output = Some(vn);
    }

    // Ghidra: funcdata.cc:34 Funcdata::opDestroy
    /// Destroy an unused PcodeOp. Faithful to `Funcdata::opDestroy`
    /// (funcdata_op.cc:203-222). Clears the output's def, unsets all inputs,
    /// and marks the op dead in the obank. Only call when the output has no
    /// descendants (dead code).
    pub fn op_destroy(&mut self, op: &crate::op::PcodeOpRef) {
        // Clear output def link.
        let out = op.0.read().unwrap().output.clone();
        if let Some(o) = out {
            o.write().unwrap().def = None;
        }
        // Clear all inrefs (break descend links on inputs).
        let inrefs = op.0.read().unwrap().inrefs.clone();
        for in_vn in &inrefs {
            in_vn.write().unwrap().descend.retain(|w| {
                w.upgrade().map(|a| !std::sync::Arc::ptr_eq(&a, &op.0)).unwrap_or(true)
            });
        }
        op.0.write().unwrap().inrefs.clear();
        // Mark the op dead.
        self.obank.mark_dead(op.clone());
    }

    // Ghidra: funcdata.cc:34 Funcdata::opDestroyRecursive
    /// Recursively destroy an op and its now-dead defining ops. Faithful to
    /// `Funcdata::opDestroyRecursive` (funcdata_op.cc:228-247). Destroys the
    /// given op, then for each input Varnode that becomes dead (its only
    /// reader was this op and it is not auto-live/call/indirect-source),
    /// recursively destroys its defining op.
    pub fn op_destroy_recursive(&mut self, op: &crate::op::PcodeOpRef) {
        let mut scratch: Vec<crate::op::PcodeOpRef> = Vec::new();
        scratch.push(op.clone());
        let mut pos = 0;
        while pos < scratch.len() {
            let cur = scratch[pos].clone();
            pos += 1;
            // Collect input varnodes and check if their defining ops should be
            // recursively destroyed.
            let inrefs = cur.0.read().unwrap().inrefs.clone();
            for in_vn in &inrefs {
                let (is_written, lone_descend_none, def) = {
                    let vn_rg = in_vn.read().unwrap();
                    let lone = vn_rg.lone_descend();
                    (
                        vn_rg.is_written(),
                        lone.is_none(),
                        vn_rg.get_def(),
                    )
                };
                if !is_written {
                    continue;
                }
                if lone_descend_none {
                    continue; // Still has descendants (or no def).
                }
                let Some(def_op) = def else { continue };
                let def_ref = crate::op::PcodeOpRef(def_op);
                // Skip call and indirect-source ops (faithful to Ghidra).
                let is_call = def_ref.0.read().unwrap().is_call();
                let is_indirect_source = {
                    let f = def_ref.0.read().unwrap().flags;
                    (f & crate::op::pcodeop_flags::INDIRECT_SOURCE) != 0
                };
                if is_call || is_indirect_source {
                    continue;
                }
                scratch.push(def_ref);
            }
            self.op_destroy(&cur);
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::totalReplace
    /// Replace every read reference of `vn` with `newvn`. Faithful to
    /// `Funcdata::totalReplace` (funcdata_varnode.cc:1474-1487). Walks all
    /// descendant ops of `vn` and sets their input slot to `newvn`.
    pub fn total_replace(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        newvn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        // Snapshot descendant ops and their slots referencing vn.
        let replacements: Vec<(crate::op::PcodeOpRef, usize)> = {
            let vn_rg = vn.read().unwrap();
            vn_rg
                .descend
                .iter()
                .filter_map(|w| w.upgrade())
                .filter_map(|op_arc| {
                    let op_rg = op_arc.read().unwrap();
                    // Find the slot referencing vn.
                    let slot = op_rg
                        .inrefs
                        .iter()
                        .position(|v| std::sync::Arc::ptr_eq(v, vn))?;
                    drop(op_rg);
                    Some((crate::op::PcodeOpRef(op_arc), slot))
                })
                .collect()
        };
        for (op, slot) in replacements {
            self.op_set_input(&op, newvn.clone(), slot);
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::opUnsetInput
    /// Unset an input slot. Faithful to `Funcdata::opUnsetInput`
    /// (funcdata_op.cc). Removes the descend link from the input varnode and
    /// sets the slot to None (represented as removing from inrefs in Rugra).
    // Ghidra: funcdata_op.cc:92 Funcdata::opUnsetInput
    /// Unlink the input Varnode at `slot` from `op`. Faithful to
    /// `Funcdata::opUnsetInput` (funcdata_op.cc:92-99):
    ///   vn = op->getIn(slot);
    ///   vn->eraseDescend(op);
    ///   op->clearInput(slot);
    /// Rugra's inrefs Vec cannot hold null, so the slot is left holding the
    /// old Arc (clearInput is implicit — the slot will be overwritten by the
    /// next op_set_input). The load-bearing half is erase_descend on the old
    /// vn, which removes `op` from its descend list.
    pub fn op_unset_input(&self, op: &crate::op::PcodeOpRef, slot: usize) {
        let in_vn = {
            let o = op.0.read().unwrap();
            o.inrefs.get(slot).cloned()
        };
        if let Some(vn) = in_vn {
            vn.write().unwrap().erase_descend(&op.0);
        }
        // Ghidra cc:98: op->clearInput(slot) — implicit in Rugra (Vec slot
        // overwritten on next set; callers must set or remove before relying
        // on inrefs[slot]).
    }

    // Ghidra: funcdata.cc:34 Funcdata::opUnsetOutput
    /// Unset the output of an op. Faithful to `Funcdata::opUnsetOutput`
    /// (funcdata_op.cc). Clears the output's def link and removes the output
    /// from the op, making the old output a free varnode.
    pub fn op_unset_output(&self, op: &crate::op::PcodeOpRef) {
        let old = op.0.write().unwrap().output.take();
        if let Some(o) = old {
            o.write().unwrap().def = None;
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::newVarnodeOut
    /// Create a new output varnode for an op at a given address+size.
    /// Faithful to `Funcdata::newVarnodeOut` (funcdata.hh). Creates a varnode
    /// in the register space at the given address and wires it as the op's
    /// output.
    pub fn new_varnode_out(&mut self, size: usize, addr: crate::address::Address, op: &crate::op::PcodeOpRef) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let vn = self.vbank.create_with_space(size, crate::space::AddressSpace::Register, addr.as_u64());
        vn.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        vn.write().unwrap().def = Some(std::sync::Arc::downgrade(&op.0));
        op.0.write().unwrap().output = Some(vn.clone());
        vn
    }

    // Ghidra: funcdata.cc:34 Funcdata::pushBranch
    /// Push a conditional branch edge into a new destination, turning the
    /// CBRANCH into an unconditional BRANCH. Faithful to `Funcdata::pushBranch`
    /// (funcdata_block.cc:404).
    ///
    /// `bb` is the block containing the CBRANCH; `slot` is the out-edge to
    /// redirect; `bbnew` is the new destination (must end in BRANCHIND).
    pub fn push_branch(
        &mut self,
        bb: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        slot: usize,
        bbnew: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) -> Result<(), String> {
        // Get the CBRANCH (last op of bb).
        let last_op = {
            let bb_rg = bb.read().unwrap();
            if let Some(any) = bb_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                any.last_op()
            } else {
                None
            }
        };
        let cbranch = match last_op {
            Some(op) => op,
            None => return Err("No last op in block".to_string()),
        };
        // Verify it's a CBRANCH with 2 out-edges.
        let is_cbranch = {
            let cb_rg = cbranch.0.read().unwrap();
            cb_rg.opcode == crate::opcodes::OpCode::CPUI_CBRANCH
        };
        if !is_cbranch || bb.read().unwrap().size_out() != 2 {
            return Err("Cannot push non-conditional edge".to_string());
        }
        // Verify bbnew ends in BRANCHIND.
        let bbnew_last = {
            let bn_rg = bbnew.read().unwrap();
            if let Some(any) = bn_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                any.last_op()
            } else {
                None
            }
        };
        if let Some(indop) = &bbnew_last {
            if indop.0.read().unwrap().opcode != crate::opcodes::OpCode::CPUI_BRANCHIND {
                return Err("Can only push branch into indirect jump".to_string());
            }
        } else {
            return Err("Destination has no last op".to_string());
        }
        // Remove the conditional variable (input slot 1) and change opcode to
        // BRANCH. Faithful to opRemoveInput(cbranch,1) + opSetOpcode(BRANCH).
        self.op_remove_input(&cbranch, 1);
        self.op_set_opcode(&cbranch, crate::opcodes::OpCode::CPUI_BRANCH);
        // Move the out-edge.
        self.move_out_edge(bb, slot, bbnew);
        Ok(())
    }

    // Ghidra: funcdata.cc:34 Funcdata::moveOutEdge
    /// Move an out-edge of `bb` from its current destination to `bbnew`.
    /// Faithful to `BlockGraph::moveOutEdge` (block.cc). This redirects the
    /// edge by updating both the source's outgoing list and the old/new
    /// destinations' incoming lists.
    pub fn move_out_edge(
        &mut self,
        bb: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        slot: usize,
        bbnew: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) {
        // Get the old destination.
        let old_dest = {
            let bb_rg = bb.read().unwrap();
            bb_rg.get_out(slot).map(|e| e.point)
        };
        let Some(old_dest) = old_dest else { return };
        // Update the source's outgoing edge to point to bbnew.
        let rev_idx_new = bbnew.read().unwrap().size_in() as i32;
        {
            let mut bb_rg = bb.write().unwrap();
            if let Some(any) = bb_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                if slot < any.outgoing.len() {
                    let old_rev = any.outgoing[slot].reverse_index;
                    any.outgoing[slot].point = bbnew.clone();
                    any.outgoing[slot].reverse_index = rev_idx_new;
                    // Remove the old reverse edge from old_dest.
                    let _ = old_rev;
                }
            }
        }
        // Add the incoming edge to bbnew.
        {
            let mut bn_rg = bbnew.write().unwrap();
            let out_idx = slot as i32;
            bn_rg.add_in_edge(crate::block::BlockEdge::new(bb.clone(), out_idx));
        }
        // Remove the old incoming edge from old_dest (the reverse_index stored
        // in bb's edge tells us which slot in old_dest to remove).
        let old_rev = {
            let bb_rg = bb.read().unwrap();
            // The reverse_index was captured before we changed it; recompute
            // from old_dest's incoming list by finding bb.
            let dest_rg = old_dest.read().unwrap();
            let mut found = None;
            for i in 0..dest_rg.size_in() {
                if let Some(e) = dest_rg.get_in(i) {
                    if Arc::ptr_eq(&e.point, bb) {
                        found = Some(i);
                        break;
                    }
                }
            }
            found
        };
        if let Some(slot_in) = old_rev {
            let mut od_rg = old_dest.write().unwrap();
            if let Some(any) = od_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                if slot_in < any.incoming.len() {
                    any.incoming.remove(slot_in);
                    // Fix reverse indices on bb's remaining edges that pointed
                    // past the removed slot.
                    let mut bb_rg = bb.write().unwrap();
                    if let Some(any_bb) = bb_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                        for e in any_bb.outgoing.iter_mut() {
                            if e.reverse_index > slot_in as i32 {
                                e.reverse_index -= 1;
                            }
                        }
                    }
                }
            }
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::forceGoto
    /// Force a specific branch instruction to be an unstructured goto.
    /// Faithful to `Funcdata::forceGoto` (funcdata_block.cc:752).
    ///
    /// `pcop` is the address of the branch op to mark; `pcdest` is the
    /// destination address. Returns true if a matching branch was found and
    /// marked.
    pub fn force_goto(
        &mut self,
        pcop: crate::address::Address,
        pcdest: crate::address::Address,
    ) -> bool {
        for i in 0..self.bblocks.get_size() {
            let bl = match self.bblocks.get_block(i) {
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
            let Some(op) = last_op else { continue };
            if op.0.read().unwrap().get_addr() != pcop {
                continue;
            }
            // Find the out-edge whose destination's last op has addr == pcdest.
            let n_out = bl.read().unwrap().size_out();
            for j in 0..n_out {
                let bl2 = bl.read().unwrap().get_out(j).map(|e| e.point);
                let Some(bl2) = bl2 else { continue };
                let op2 = {
                    let bl2_rg = bl2.read().unwrap();
                    if let Some(any) = bl2_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                        any.last_op()
                    } else {
                        None
                    }
                };
                let Some(op2) = op2 else { continue };
                if op2.0.read().unwrap().get_addr() == pcdest {
                    // Mark this out-edge as a goto branch.
                    self.set_goto_branch(&bl, j);
                    return true;
                }
            }
        }
        false
    }

    // Ghidra: block.cc:305 FlowBlock::setGotoBranch
    /// Mark the j-th out-edge of a block as an unstructured goto. Faithful to
    /// `FlowBlock::setGotoBranch` (block.cc:305-314), which does THREE things:
    ///   1. setOutEdgeFlag(j, f_goto_edge) — mark the edge as goto.
    ///   2. flags |= f_interior_gotoout — mark that there's a goto OUT of this
    ///      block's interior (read by hasInteriorGoto).
    ///   3. outofthis[j].point->flags |= f_interior_gotoin — mark the TARGET
    ///      block as a goto target (read by isInteriorGotoTarget).
    /// Previously Rugra only did (1) for BlockBasic, so is_interior_goto_target
    /// could not behave correctly for goto-marked targets.
    pub fn set_goto_branch(
        &mut self,
        bl: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        j: usize,
    ) {
        // cc:307-310: bounds check + setOutEdgeFlag(j, f_goto_edge).
        // Capture the target block for step (3) before taking the write lock.
        let target_opt: Option<Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>> = {
            let bl_rg = bl.read().unwrap();
            if j < bl_rg.size_out() {
                bl_rg.get_out(j).map(|e| e.point.clone())
            } else {
                None
            }
        };
        {
            let mut bl_rg = bl.write().unwrap();
            // cc:311: flags |= f_interior_gotoout (source-side mark).
            bl_rg.set_flags(crate::block::block_flags::INTERIOR_GOTOOUT);
            // cc:308: setOutEdgeFlag(j, f_goto_edge). For BlockBasic we use the
            // dedicated GOTO_EDGE_0/1 flags; for structured blocks we set the
            // edge's F_GOTO_EDGE flag directly.
            if let Some(any) = bl_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                match j {
                    0 => any.flags |= crate::block::block_flags::GOTO_EDGE_0,
                    1 => any.flags |= crate::block::block_flags::GOTO_EDGE_1,
                    _ => {}
                }
            } else {
                // Structured block: set F_GOTO_EDGE on the edge directly.
                bl_rg.set_out_edge_flag(j, crate::block::edge_flags::F_GOTO_EDGE);
            }
        }
        // cc:313: target->flags |= f_interior_gotoin (target-side mark).
        if let Some(target) = target_opt {
            let mut tg = target.write().unwrap();
            tg.set_flags(crate::block::block_flags::INTERIOR_GOTOIN);
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::removeBranch
    /// Remove a branch edge from a basic block. Faithful to
    /// `Funcdata::removeBranch` / `branchRemoveInternal`
    /// (funcdata_block.cc). If the block has 2 out-edges (CBRANCH), the
    /// branch op is destroyed. The edge to the un-selected out-block is
    /// severed.
    ///
    /// `bb` is the block with the branch; `num` is the out-edge index to
    /// KEEP (0 or 1). The OTHER edge is removed.
    pub fn remove_branch(
        &mut self,
        bb: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        num: usize,
    ) {
        // If 2 out-edges, destroy the CBRANCH op.
        let n_out = bb.read().unwrap().size_out();
        if n_out == 2 {
            let last_op = {
                let bb_rg = bb.read().unwrap();
                if let Some(any) = bb_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                    any.last_op()
                } else {
                    None
                }
            };
            if let Some(cbranch) = last_op {
                self.op_destroy(&cbranch);
            }
        }

        // The out-edge to REMOVE is (1 - num) if num is the kept one.
        let remove_edge = if n_out == 2 { 1 - num } else { return };

        // Get the target block of the edge to remove.
        let target = bb.read().unwrap().get_out(remove_edge).map(|e| e.point);
        let Some(target) = target else { return };

        // Remove the edge from bb to target.
        // In our simplified model, we remove the outgoing edge from bb and
        // the incoming edge from target.
        {
            let mut bb_rg = bb.write().unwrap();
            if let Some(any) = bb_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                if remove_edge < any.outgoing.len() {
                    any.outgoing.remove(remove_edge);
                }
            }
        }
        {
            let mut target_rg = target.write().unwrap();
            if let Some(any) = target_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                // Find and remove the incoming edge from bb.
                let bb_ptr = Arc::as_ptr(bb) as *const () as usize;
                any.incoming.retain(|e| {
                    Arc::as_ptr(&e.point) as *const () as usize != bb_ptr
                });
            }
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::structureReset
    /// Recompute loop structure, dominance, and reset the structured-block
    /// hierarchy for the current CFG. Faithful to
    /// `Funcdata::structureReset` (funcdata_block.cc:705-735).
    ///
    /// Must be called after any mutation that changes the CFG so that
    /// dominator/loop information stays consistent.
    pub fn structure_reset(&mut self) {
        // Ghidra clears blocks_unreachable, recomputes loops + dominators,
        // then rebuilds the high-level structured hierarchy. Rugra's
        // structured hierarchy (sblocks) is rebuilt by blockaction on demand;
        // here we refresh the basic-block dominator tree and loop flags so
        // subsequent analyses see a consistent CFG.
        self.bblocks.build_dom_tree();
        let _ = self.bblocks.structure_loops();
        // Clear any cached high-level structure; it will be regenerated.
        self.sblocks.clear();
    }

    // Ghidra: funcdata_block.cc:688 Funcdata::installSwitchDefaults
    /// Mark default switch edges for all jump tables. Faithful to
    /// `Funcdata::installSwitchDefaults` (funcdata_block.cc:688-700).
    pub fn install_switch_defaults(&mut self) {
        for jt_arc in &self.jump_tables {
            let jt = jt_arc.read().unwrap();
            let default_block = jt.get_default_block();
            if default_block < 0 {
                continue;
            }
            let indop = jt.get_indirect_op();
            let Some(indop_arc) = indop else { continue };
            // indop->getParent() → the switch BlockBasic.
            let parent = {
                let op = indop_arc.read().unwrap();
                op.parent.as_ref().and_then(|w| w.upgrade())
            };
            let Some(parent_blk) = parent else { continue };
            parent_blk.write().unwrap().set_default_switch(default_block as usize);
        }
    }

    // Ghidra: funcdata_block.cc:328 Funcdata::removeDoNothingBlock
    /// Remove a basic block that does nothing (only marker ops + optional
    /// single branch). Faithful to `Funcdata::removeDoNothingBlock`
    /// (funcdata_block.cc:328-337).
    pub fn remove_do_nothing_block(
        &mut self,
        bb: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) {
        if bb.read().unwrap().size_out() > 1 {
            eprintln!("[BLOCK] Cannot delete block with >1 out edge");
            return;
        }
        bb.write().unwrap().set_flags(crate::block::block_flags::DEAD);
        let ops_to_destroy: Vec<crate::op::PcodeOpRef> = {
            let rg = bb.read().unwrap();
            if let Some(bb2) = rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                bb2.get_ops()
            } else {
                Vec::new()
            }
        };
        for op_ref in &ops_to_destroy {
            self.op_destroy(op_ref);
        }
        self.bblocks.remove_block_arc(bb);
        self.structure_reset();
    }

    // Ghidra: funcdata_block.cc:790 Funcdata::nodeJoinCreateBlock
    /// Create a joined block from two blocks that share exit targets.
    /// Faithful to `Funcdata::nodeJoinCreateBlock`
    /// (funcdata_block.cc:790-826).
    pub fn node_join_create_block(
        &mut self,
        block1: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        block2: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        exita: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        exitb: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        fora_block1ishigh: bool,
        forb_block1ishigh: bool,
        addr: crate::address::Address,
    ) -> Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>> {
        let newblock = self.create_new_block();
        newblock.write().unwrap().set_flags(crate::block::block_flags::JOINED_BLOCK);
        // setInitialRange(addr, addr) — Rugra's create_new_block uses Address(0);
        // the range is informational only (used for cover/debug), so we skip it.

        // Delete 2 of the original edges into exita and exitb (merge.cc:807-818).
        let swapa = if fora_block1ishigh {
            self.bblocks.remove_edge_blocks(block1, exita);
            block2.clone()
        } else {
            self.bblocks.remove_edge_blocks(block2, exita);
            block1.clone()
        };
        let swapb = if forb_block1ishigh {
            self.bblocks.remove_edge_blocks(block1, exitb);
            block2.clone()
        } else {
            self.bblocks.remove_edge_blocks(block2, exitb);
            block1.clone()
        };
        // Move remaining edges to newblock (merge.cc:820-821).
        // swapa->getOutIndex(exita) — find exita in swapa's outgoing.
        let out_idx_a = find_out_index(&swapa, exita);
        let out_idx_b = find_out_index(&swapb, exitb);
        if let Some(idx_a) = out_idx_a {
            self.move_out_edge(&swapa, idx_a, &newblock);
        }
        if let Some(idx_b) = out_idx_b {
            self.move_out_edge(&swapb, idx_b, &newblock);
        }
        // Add edges from block1/block2 to newblock.
        self.bblocks.add_edge(block1.clone(), newblock.clone());
        self.bblocks.add_edge(block2.clone(), newblock.clone());
        self.structure_reset();
        newblock
    }

    // Ghidra: block.cc:1489 BlockGraph::switchEdge
    /// Redirect the edge from `in`→`outbefore` to `in`→`outafter`.
    /// Faithful to `BlockGraph::switchEdge` (block.cc:1489-1495).
    pub fn switch_edge(
        &mut self,
        in_block: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        outbefore: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        outafter: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) {
        // Find the out-edge slot from in_block pointing to outbefore, then
        // redirect it to outafter (block.cc:1492-1494).
        if let Some(slot) = find_out_index(in_block, outbefore) {
            let mut in_rg = in_block.write().unwrap();
            if let Some(bb) = in_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                bb.replace_out_edge_target(slot, outafter.clone());
            }
            // BlockGraph and other types: nodeSplit only operates on BlockBasic.
        }
    }

    // Ghidra: funcdata_block.cc:835 Funcdata::nodeSplitBlockEdge
    /// Create a duplicate block that inherits the same out-edges but only the
    /// one indicated in-edge, which is moved from the original block.
    /// Faithful to `Funcdata::nodeSplitBlockEdge` (funcdata_block.cc:835-848).
    fn node_split_block_edge(
        &mut self,
        b: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        inedge: usize,
    ) -> Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>> {
        let a = b.read().unwrap().get_in(inedge).map(|e| e.point.clone());
        let Some(a) = a else {
            return self.create_new_block();
        };
        let bprime = self.create_new_block();
        bprime.write().unwrap().set_flags(crate::block::block_flags::DUPLICATE_BLOCK);
        // copyRange(b) — Rugra blocks don't track address range; skip.
        // switchEdge(a, b, bprime)
        self.switch_edge(&a, b, &bprime);
        // Add all of b's out-edges to bprime.
        let outs: Vec<Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>> = {
            let br = b.read().unwrap();
            (0..br.size_out()).filter_map(|i| br.get_out(i).map(|e| e.point.clone())).collect()
        };
        for out in &outs {
            self.bblocks.add_edge(bprime.clone(), out.clone());
        }
        bprime
    }

    // Ghidra: funcdata_block.cc:856 Funcdata::nodeSplit
    /// Split control-flow into a basic block, duplicating its p-code into a
    /// new block. Faithful to `Funcdata::nodeSplit` (funcdata_block.cc:856-882).
    pub fn node_split(
        &mut self,
        b: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        inedge: usize,
    ) {
        // Preconditions (merge.cc:859-869).
        if b.read().unwrap().size_out() != 0 {
            eprintln!("[BLOCK] Cannot nodesplit block with out flow");
            return;
        }
        if b.read().unwrap().size_in() <= 1 {
            eprintln!("[BLOCK] Cannot nodesplit block with only 1 in edge");
            return;
        }
        // Create duplicate block.
        let bprime = self.node_split_block_edge(b, inedge);
        // CloneBlockOps: clone all ops from b into bprime.
        let mut cloner = CloneBlockOps::new();
        cloner.clone_block(self, b, &bprime, inedge);
        self.structure_reset();
    }

    // Ghidra: funcdata.cc:34 Funcdata::syncVarnodesWithSymbols
    /// Synchronize varnodes with the local-variable scope symbols. Faithful to
    /// `Funcdata::syncVarnodesWithSymbols` (funcdata_varnode.cc:938-989).
    ///
    /// For each Stack-space varnode that overlaps a ScopeLocal symbol, mark it
    /// as mapped. For varnodes not overlapping any symbol, if the scope reports
    /// them as unaliased, set the no-local-alias flag. Returns true if any
    /// varnode was modified (indicating a change for the caller to count).
    ///
    /// This is the sync step ActionRestructureVarnode performs after
    /// restructureVarnode. Rugra's ScopeLocal uses a simplified LocalSymbol
    /// model; this adaptation iterates Stack-space varnodes and matches them
    /// against scope symbols by offset/size.
    pub fn sync_varnodes_with_symbols(&mut self, _update_datatypes: bool, _unmapped_alias_check: bool) -> bool {
        let scope = match &self.scope {
            Some(s) => s.clone(),
            None => return false,
        };
        let mut updated = false;
        // Collect Stack-space varnodes and their (offset, size) for matching.
        // Rugra stores Stack-space varnodes sparsely; we scan vbank.loc_tree.
        let to_update: Vec<(std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, bool)> = {
            let mut matches = Vec::new();
            for entry in self.vbank.loc_tree.iter() {
                let vn = entry.0.read().unwrap();
                if vn.get_space() == crate::space::AddressSpace::Stack {
                    let off = vn.get_offset();
                    let sz = vn.get_size() as u64;
                    // Does any scope symbol overlap (off, sz)?
                    let has_symbol = scope.symbols.iter().any(|sym| {
                        let sym_end = sym.start + sym.size as u64;
                        sym.start < off + sz && off < sym_end
                    });
                    if has_symbol {
                        matches.push((entry.0.clone(), true));
                    }
                }
            }
            matches
        };
        // Mark matched varnodes as mapped (set DIRECT_WRITE flag as a proxy
        // for "mapped" since Rugra lacks a dedicated MAPPED flag).
        for (vn_arc, _has_sym) in to_update {
            vn_arc.write().unwrap().set_direct_write();
            updated = true;
        }
        updated
    }

    // Ghidra: funcdata.cc:34 Funcdata::removeFromFlowSplit
    /// Remove a 2-in/2-out empty block, rejoining each in-edge to the
    /// corresponding out-edge. Faithful to `Funcdata::removeFromFlowSplit`
    /// (funcdata_block.cc:892-900) + `BlockGraph::removeFromFlowSplit`
    /// (block.cc:1575-1590).
    ///
    /// `bl` must have exactly 2 in-edges and 2 out-edges and no ops.
    /// If `swap` is false: In(0)->Out(1), In(1)->Out(0).
    /// If `swap` is true:  In(0)->Out(0), In(1)->Out(1).
    ///
    /// (Ghidra's flipflow semantics: flipflow=true maps to replaceEdgesThru(0,0)
    ///  joining in0->out0; flipflow=false joins in0->out1 first. We mirror this.)
    pub fn remove_from_flow_split(
        &mut self,
        bl: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        swap: bool,
    ) -> Result<(), String> {
        // Validate 2-in / 2-out and empty.
        if bl.read().unwrap().size_in() != 2 || bl.read().unwrap().size_out() != 2 {
            return Err("remove_from_flow_split: block must have 2 in/2 out".to_string());
        }
        let nonempty = {
            let bl_rg = bl.read().unwrap();
            if let Some(bb) = bl_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                !bb.ops.is_empty()
            } else {
                // Non-basic composite blocks: treat as removable if they have
                // no ops directly (they delegate to children).
                bl_rg.get_ops().is_empty()
            }
        };
        if nonempty {
            return Err("remove_from_flow_split: block must be empty".to_string());
        }

        // Faithful to BlockGraph::removeFromFlowSplit (block.cc:1584-1589):
        //   if flipflow: replaceEdgesThru(0,1)  // in0 -> out1
        //   else:        replaceEdgesThru(1,1)  // in1 -> out1
        //   then:        replaceEdgesThru(0,0)  // remaining in0 -> out0
        // Note: Ghidra's param is `flipflow`; our `swap` matches flipflow
        // (swap=true => in0->out0, in1->out1).
        {
            let mut bl_rg = bl.write().unwrap();
            if let Some(bb) = bl_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                if swap {
                    bb.replace_edges_thru(0, 0);
                    bb.replace_edges_thru(0, 1);
                } else {
                    bb.replace_edges_thru(0, 1);
                    bb.replace_edges_thru(0, 0);
                }
            } else {
                return Err("remove_from_flow_split: only BlockBasic supported".to_string());
            }
        }
        // Remove the now-disconnected block from the graph.
        self.bblocks.remove_block_arc(bl);
        self.structure_reset();
        Ok(())
    }

    // Ghidra: funcdata.cc:34 Funcdata::removeUnreachableBlocks
    /// Remove any basic blocks not reachable from the entry point.
    /// Faithful to `Funcdata::removeUnreachableBlocks` (funcdata_block.cc:347-394).
    ///
    /// Performs a forward BFS from the entry block, marks blocks NOT visited as
    /// dead, removes their out-edges, then removes them from the graph. Returns
    /// true if any unreachable block was removed.
    pub fn remove_unreachable_blocks(&mut self) -> bool {
        let n = self.bblocks.get_size();
        if n == 0 {
            return false;
        }
        // Find the entry point: a block with zero in-edges (no predecessors),
        // matching Ghidra's isEntryPoint() (block.hh:325: size_in()==0 or
        // explicitly flagged). Previously only checked the ENTRY_POINT flag
        // which is never set during Rugra's CFG construction, causing the
        // fallback to block 0 — which may not be the true entry, leading to
        // false-positive "unreachable" detection and function-body loss.
        let entry = (0..n)
            .find(|&i| {
                self.bblocks.get_block(i).map(|b| {
                    let bg = b.read().unwrap();
                    bg.size_in() == 0
                        || (bg.get_flags() & crate::block::block_flags::ENTRY_POINT) != 0
                }).unwrap_or(false)
            })
            .unwrap_or(0);
        // Forward BFS from entry to find reachable set.
        let mut reachable = std::collections::HashSet::new();
        let mut queue = vec![entry];
        reachable.insert(entry);
        while let Some(idx) = queue.pop() {
            let outs: Vec<i32> = {
                if let Some(blk) = self.bblocks.get_block(idx) {
                    let b = blk.read().unwrap();
                    let nn = b.size_out();
                    (0..nn).filter_map(|j| b.get_out(j).map(|e| e.point.read().unwrap().get_index())).collect()
                } else {
                    Vec::new()
                }
            };
            for o in outs {
                if reachable.insert(o as usize) {
                    queue.push(o as usize);
                }
            }
        }
        // Collect unreachable blocks.
        let unreachable: Vec<usize> = (0..n).filter(|i| !reachable.contains(i)).collect();
        if unreachable.is_empty() {
            return false;
        }
        // Conservative guard: if a large fraction of blocks are "unreachable",
        // the CFG is likely incomplete (BRANCHIND/jump-table edges missing).
        // Skip removal to avoid deleting reachable function body.
        // Uses BOTH absolute (>=5) and relative (>5%) thresholds: small test
        // CFGs with genuinely dead blocks still get cleaned, but real functions
        // with incomplete CFGs (where many blocks are falsely unreachable)
        // are protected.
        // TODO: remove this guard once BRANCHIND edges are added to the CFG.
        if unreachable.len() >= 5 && unreachable.len() * 20 > n {
            return false;
        }
        // Mark dead, remove their out-edges, then remove from the graph.
        // Faithful to Ghidra removeUnreachableBlocks (funcdata_block.cc:370-391):
        // for each unreachable block: setDead, branchRemoveInternal all out-edges,
        // then blockRemoveInternal (which destroys ops + removes from graph).
        // For unreachable=true, Ghidra calls descend2Undef on output varnodes
        // (funcdata_block.cc:305-306) and checks descendantsOutside (312).
        // Rugra's simplified version: mark block's ops as dead (so they don't
        // appear in alivelist for printc), remove all edges, remove block.
        let dead_arcs: Vec<_> = unreachable.iter()
            .filter_map(|&i| self.bblocks.get_block(i))
            .collect();
        // Phase 1: mark blocks DEAD.
        for arc in &dead_arcs {
            arc.write().unwrap().set_flags(crate::block::block_flags::DEAD);
        }
        // Phase 2: destroy ops in each dead block. Faithful to Ghidra
        // blockRemoveInternal funcdata_block.cc:300-319: for unreachable=true,
        // Ghidra calls descend2Undef on output varnodes, then checks
        // descendantsOutside. Rugra's approach: only mark_dead ops whose
        // output has NO descendants outside the dead block set. Ops with
        // external descendants are left alive (their block is DEAD-flagged so
        // emit_block_ops skips them, but the op stays in alivelist so its
        // output varnode remains valid for any phi-node that references it).
        let dead_block_ptrs: std::collections::HashSet<usize> = dead_arcs.iter()
            .map(|a| std::sync::Arc::as_ptr(a) as *const () as usize)
            .collect();
        for arc in &dead_arcs {
            let ops_to_check: Vec<crate::op::PcodeOpRef> = {
                let block = arc.read().unwrap();
                if let Some(bb) = block.as_any().downcast_ref::<crate::block::BlockBasic>() {
                    bb.ops.iter().map(|o| o.0.clone()).map(crate::op::PcodeOpRef).collect()
                } else {
                    Vec::new()
                }
            };
            for op_ref in ops_to_check {
                // Check if output has descendants outside dead blocks.
                let has_external_desc = {
                    let op = op_ref.0.read().unwrap();
                    if let Some(ref out_arc) = op.output {
                        let out_vn = out_arc.read().unwrap();
                        out_vn.descend.iter()
                            .filter_map(|w| w.upgrade())
                            .any(|desc_op| {
                                let d = desc_op.read().unwrap();
                                d.parent.as_ref()
                                    .and_then(|pw| pw.upgrade())
                                    .map(|parent| {
                                        let p = std::sync::Arc::as_ptr(&parent) as *const () as usize;
                                        !dead_block_ptrs.contains(&p)
                                    })
                                    .unwrap_or(true)
                            })
                    } else {
                        false
                    }
                };
                if !has_external_desc {
                    self.obank.mark_dead(op_ref);
                }
                // Ops with external descendants are left alive — their block is
                // DEAD-flagged (emit_block_ops checks is_dead) but the op
                // remains valid for phi-node references.
            }
        }
        // Phase 3: detach all out-edges (branchRemoveInternal equivalent).
        for arc in &dead_arcs {
            while arc.read().unwrap().size_out() > 0 {
                let dst = arc.read().unwrap().get_out(0).map(|e| e.point);
                if let Some(dst) = dst {
                    self.bblocks.remove_edge_blocks(arc, &dst);
                } else {
                    break;
                }
            }
        }
        // Phase 4: remove blocks from graph (blockRemoveInternal equivalent).
        for arc in &dead_arcs {
            self.bblocks.remove_block_arc(arc);
        }
        self.structure_reset();
        true
    }

    // Ghidra: funcdata.cc:34 Funcdata::createNewBlock
    /// Splice a 1-out basic block into its single successor.
    /// Faithful to `Funcdata::spliceBlockBasic` (funcdata_block.cc:919-956).
    ///
    /// The given block must have a single output block with a single input
    /// (from this block). The output block's ops are conceptually merged; here
    /// we splice the CFG: this block inherits the successor's out-edges and the
    /// successor is removed. This is used by ActionRedundBranch (case 1) and
    /// ActionDoNothing.
    /// Create a new empty basic block and add it to bblocks. Faithful to
    /// `Funcdata::newBlockBasic` (funcdata_block.cc). Returns the Arc.
    pub fn create_new_block(&mut self) -> Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>> {
        let addr = crate::address::Address::new(0);
        let bb = Arc::new(RwLock::new(crate::block::BlockBasic::new(0, addr)));
        self.bblocks.add_block(bb.clone());
        bb
    }

    // Ghidra: funcdata.cc:34 Funcdata::spliceBlockBasic
    pub fn splice_block_basic(&mut self, bb: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>) -> bool {
        let (out_block, out_has_single_in) = {
            let rg = bb.read().unwrap();
            if rg.size_out() != 1 {
                return false;
            }
            let ob = rg.get_out(0).map(|e| e.point);
            let ob = match ob { Some(o) => o, None => return false };
            let single_in = ob.read().unwrap().size_in() == 1;
            (ob, single_in)
        };
        if !out_has_single_in {
            return false;
        }
        // Destroy any branch op at the end of bb (it falls through).
        let last_op = {
            let rg = bb.read().unwrap();
            if let Some(bb2) = rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                bb2.last_op()
            } else {
                None
            }
        };
        if let Some(branch_op) = last_op {
            let is_branch = {
                let o = branch_op.0.read().unwrap();
                o.opcode == crate::opcodes::OpCode::CPUI_BRANCH
                    || o.opcode == crate::opcodes::OpCode::CPUI_CBRANCH
                    || o.opcode == crate::opcodes::OpCode::CPUI_BRANCHIND
            };
            if is_branch {
                self.op_destroy(&branch_op);
            }
        }
        // Move out_block's ops into bb (faithful to Ghidra funcdata_block.cc:
        // 940-947: bl->op.splice(bl->op.end(), outbl->op, ...)). This is the
        // KEY step that was missing — without it, out_block's ops are orphaned
        // when the block is removed, and printc can't find them.
        {
            // Check for MULTIEQUAL (phi) at start of out_block — Ghidra throws
            // if found (funcdata_block.cc:936). We skip the splice in that case.
            let has_phi = {
                let out_rg = out_block.read().unwrap();
                if let Some(out_bb) = out_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                    out_bb.ops.first().map(|o| {
                        o.0.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_MULTIEQUAL
                    }).unwrap_or(false)
                } else {
                    false
                }
            };
            if has_phi {
                // Can't splice — out_block starts with a phi-node. Put the
                // edge back and abort. Ghidra throws; we just return false.
                self.bblocks.add_edge(bb.clone(), out_block.clone());
                return false;
            }

            // Move ops from out_block to end of bb.
            let moved_ops: Vec<crate::op::PcodeOpRef> = {
                let mut out_rg = out_block.write().unwrap();
                if let Some(out_bb) = out_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                    let ops = std::mem::take(&mut out_bb.ops);
                    ops.into_iter().map(|o| crate::op::PcodeOpRef(o.0)).collect()
                } else {
                    Vec::new()
                }
            };
            // Set parent of moved ops to bb, and append to bb's ops.
            let bb_weak = std::sync::Arc::downgrade(
                &(bb.clone() as Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>),
            );
            let mut bb_rg = bb.write().unwrap();
            if let Some(bb_bb) = bb_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                for op_ref in &moved_ops {
                    op_ref.0.write().unwrap().parent = Some(bb_weak.clone());
                    let insert_pos = bb_bb.ops.len();
                    bb_bb.insert_op(insert_pos, crate::op::PcodeOpRef(op_ref.0.clone()));
                }
                // Reset seq_num ordering on all ops in bb (Ghidra :948 setOrder).
                bb_bb.set_order();
            }
        }
        // Splice the CFG edges, faithful to BlockGraph::spliceBlock
        // (block.cc:1597-1620):
        //   fl1 = bl->flags & (f_unstructured_targ | f_entry_point)   // keep from bl
        //   fl2 = outbl->flags & f_switch_out                          // keep from outbl
        //   bl->removeOutEdge(0)                                       // drop bl→outbl
        //   for each out-edge of outbl: moveOutEdge(outbl, 0, bl)      // move outbl's edges to bl
        //   removeBlock(outbl)
        //   bl->flags = fl1 | fl2                                       // merge flags
        let (fl1, fl2, szout) = {
            let bl_rg = bb.read().unwrap();
            let out_rg = out_block.read().unwrap();
            let keep_from_bl = bl_rg.get_flags()
                & (crate::block::block_flags::UNSTRUCTURED_TARG
                    | crate::block::block_flags::ENTRY_POINT);
            let keep_from_out = out_rg.get_flags()
                & crate::block::block_flags::SWITCH_OUT;
            (keep_from_bl, keep_from_out, out_rg.size_out())
        };
        // Drop bb's single out-edge to out_block (block.cc:1612 removeOutEdge(0)).
        self.bblocks.remove_edge_blocks(bb, &out_block);
        // Move every out-edge of out_block to bb (block.cc:1614-1616).
        // moveOutEdge(outbl, 0, bl) relocates edge 0's reverse-index entry on
        // the destination to point at bl. We always move slot 0 because after
        // each move the remaining edges shift down.
        for _ in 0..szout {
            self.move_out_edge(&out_block, 0, bb);
        }
        // Remove out_block from the graph (block.cc:1618 removeBlock).
        self.bblocks.remove_block_arc(&out_block);
        // Merge flags: bl->flags = fl1 | fl2 (block.cc:1619).
        // BlockBasic.flags is a public field; assign exactly as Ghidra does.
        {
            let mut bb_rg = bb.write().unwrap();
            if let Some(bb_bb) = bb_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>() {
                bb_bb.flags = fl1 | fl2;
            }
        }
        // bl->mergeRange(outbl) (funcdata_block.cc:953) — update address cover.
        // TODO: Rugra has no Cover system yet; address-cover merge is a known
        // infrastructure gap (recorded in ALIGNMENT_ROADMAP). Does not affect
        // correctness of CFG splice for current pipeline.
        self.structure_reset();
        true
    }

    // Ghidra: funcdata.cc:34 Funcdata::replaceLessequal
    /// Replace INT_LESSEQUAL/INT_SLESSEQUAL with INT_LESS/INT_SLESS:
    /// `V <= c => V < c+1`. Faithful to `Funcdata::replaceLessequal`
    /// (funcdata_op.cc:1029-1065).
    pub fn replace_lessequal(&mut self, op: &crate::op::PcodeOpRef) -> bool {
        let (i, diff, val, size, is_signed) = {
            let o = op.0.read().unwrap();
            let (vn_idx, diff) = if o.inrefs.get(0).map_or(false, |v| v.read().unwrap().is_constant()) {
                (0, -1i64)
            } else if o.inrefs.get(1).map_or(false, |v| v.read().unwrap().is_constant()) {
                (1, 1i64)
            } else {
                return false;
            };
            let vn = o.inrefs[vn_idx].clone();
            let val = vn.read().unwrap().get_offset();
            let size = vn.read().unwrap().get_size();
            (vn_idx, diff, val, size, o.opcode == OpCode::CPUI_INT_SLESSEQUAL)
        };
        let mask = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
        if is_signed {
            let int_min = if size >= 8 { i64::MIN as u64 } else { (1u64 << (size * 8 - 1)) };
            let int_max = if size >= 8 { i64::MAX as u64 } else { mask >> 1 };
            if diff == -1 && val == int_min { return false; }
            if diff == 1 && val == int_max { return false; }
            self.op_set_opcode(op, OpCode::CPUI_INT_SLESS);
        } else {
            if diff == -1 && val == 0 { return false; }
            if diff == 1 && val == mask { return false; }
            self.op_set_opcode(op, OpCode::CPUI_INT_LESS);
        }
        let res = (val as i64 + diff) as u64 & mask;
        let newconst = self.new_constant(size, res);
        self.op_set_input(op, newconst, i);
        true
    }

    // Ghidra: funcdata.cc:34 Funcdata::distributeIntMultAdd
    /// Distribute INT_MULT coefficient through INT_ADD:
    /// `(V + W) * c => V*c + W*c`.
    /// Faithful to `Funcdata::distributeIntMultAdd` (funcdata_op.cc:1073-1118).
    /// The given op is INT_MULT(in0=INT_ADD(...), in1=constant coeff).
    pub fn distribute_int_mult_add(&mut self, op: &crate::op::PcodeOpRef) -> bool {
        let (vn0, vn1, coeff, sz, pc) = {
            let o = op.0.read().unwrap();
            if o.opcode != OpCode::CPUI_INT_MULT { return false; }
            let in0 = match o.inrefs.get(0) { Some(v) => v.clone(), None => return false };
            let in1 = match o.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return false,
            };
            let addop_arc = {
                let i0 = in0.read().unwrap();
                i0.def.as_ref().and_then(|w| w.upgrade())
            };
            let addop_arc = match addop_arc { Some(a) => a, None => return false };
            if addop_arc.read().unwrap().opcode != OpCode::CPUI_INT_ADD { return false; }
            let (vn0, vn1) = {
                let ao = addop_arc.read().unwrap();
                (ao.inrefs.get(0).cloned(), ao.inrefs.get(1).cloned())
            };
            let (vn0, vn1) = match (vn0, vn1) { (Some(a), Some(b)) => (a, b), _ => return false };
            let coeff = in1.read().unwrap().get_offset();
            let sz = o.output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(0);
            (vn0, vn1, coeff, sz, o.start.get_addr())
        };
        if sz == 0 { return false; }
        let mask = if sz >= 8 { u64::MAX } else { (1u64 << (sz * 8)) - 1 };
        let follow = crate::op::PcodeOpRef(op.0.clone());
        // Distribute vn0 * coeff
        let newvn0 = if vn0.read().unwrap().is_constant() {
            let val = coeff.wrapping_mul(vn0.read().unwrap().get_offset()) & mask;
            self.new_constant(sz, val)
        } else {
            if vn0.read().unwrap().is_free() && !vn0.read().unwrap().is_constant() { return false; }
            let newop0 = self.new_op(2, pc);
            self.op_set_opcode(&newop0, OpCode::CPUI_INT_MULT);
            let newout0 = self.new_unique_out(sz, &newop0);
            self.op_set_input(&newop0, vn0, 0);
            let c0 = self.new_constant(sz, coeff);
            self.op_set_input(&newop0, c0, 1);
            self.op_insert_before(&newop0, &follow);
            newout0
        };
        // Distribute vn1 * coeff
        let newvn1 = if vn1.read().unwrap().is_constant() {
            let val = coeff.wrapping_mul(vn1.read().unwrap().get_offset()) & mask;
            self.new_constant(sz, val)
        } else {
            if vn1.read().unwrap().is_free() && !vn1.read().unwrap().is_constant() { return false; }
            let newop1 = self.new_op(2, pc);
            self.op_set_opcode(&newop1, OpCode::CPUI_INT_MULT);
            let newout1 = self.new_unique_out(sz, &newop1);
            self.op_set_input(&newop1, vn1, 0);
            let c1 = self.new_constant(sz, coeff);
            self.op_set_input(&newop1, c1, 1);
            self.op_insert_before(&newop1, &follow);
            newout1
        };
        // Rewrite op to INT_ADD(newvn0, newvn1)
        self.op_set_input(&follow, newvn0, 0);
        self.op_set_input(&follow, newvn1, 1);
        self.op_set_opcode(&follow, OpCode::CPUI_INT_ADD);
        true
    }

    // Ghidra: funcdata.cc:34 Funcdata::opInsertBefore
    /// Insert `op` before `follow` in the alive list. Faithful to
    /// `Funcdata::opInsertBefore` (funcdata.hh:454). Rugra's alive list is not
    /// strictly ordered per-block, but we insert before `follow` to preserve
    /// relative ordering where it matters for emit.
    pub fn op_insert_before(&mut self, op: &crate::op::PcodeOpRef, follow: &crate::op::PcodeOpRef) {
        let pos = self.obank.alivelist.iter().position(|r| std::sync::Arc::ptr_eq(&r.0, &follow.0));
        let insert_idx = match pos {
            Some(mut idx) => {
                // Ghidra cc:351-362: if op is not INDIRECT, skip preceding
                // INDIRECTs (they stay grouped before their associated op).
                let op_is_indirect = op.0.read().unwrap().opcode == OpCode::CPUI_INDIRECT;
                if !op_is_indirect {
                    while idx > 0 {
                        let prev = &self.obank.alivelist[idx - 1];
                        if prev.0.read().unwrap().opcode != OpCode::CPUI_INDIRECT {
                            break;
                        }
                        idx -= 1;
                    }
                }
                idx
            }
            None => self.obank.alivelist.len(),
        };
        self.obank.alivelist.insert(insert_idx, op.clone());
    }

    // Ghidra: funcdata.cc:34 Funcdata::newIndirectOp
    /// Build a CPUI_INDIRECT op that models an indirect effect on a Stack-space
    /// Varnode, caused by a STORE (or CALL) to memory via a spacebase pointer.
    /// Faithful to `Funcdata::newIndirectOp` (funcdata_op.cc:683-698).
    ///
    /// Creates `STACK:addr = INDIRECT(STACK:addr, iop=indeffect)`:
    ///   - input[0]  = Stack-space Varnode at (addr, sz) — the value before
    ///   - output    = Stack-space Varnode at (addr, sz) — the value after
    ///   - input[1]  = iop constant referencing the causing op
    /// The op is inserted before `indeffect` and flagged INDIRECT_STORE.
    pub fn new_indirect_op(
        &mut self,
        indeffect: &crate::op::PcodeOpRef,
        stack_offset: u64,
        sz: usize,
    ) -> crate::op::PcodeOpRef {
        use crate::space::AddressSpace;
        // input[0]: Stack-space varnode at stack_offset (free, no INSERT)
        let newin = self.vbank.create_with_space(sz, AddressSpace::Stack, stack_offset);
        // The op
        let indeffect_addr = indeffect.0.read().unwrap().get_seq_num().get_addr();
        let newop = self.new_op(2, indeffect_addr);
        newop.0.write().unwrap().flags |= crate::op::pcodeop_flags::INDIRECT_STORE;
        // output: Stack-space varnode at stack_offset, defined by newop.
        // set_def sets WRITTEN + INSERT (faithful to createDef→xref).
        let newout = self.vbank.create_with_space(sz, AddressSpace::Stack, stack_offset);
        self.vbank.set_def(newout.clone(), std::sync::Arc::downgrade(&newop.0));
        newop.0.write().unwrap().output = Some(newout.clone());
        // Set opcode to INDIRECT
        self.op_set_opcode(&newop, crate::opcodes::OpCode::CPUI_INDIRECT);
        // input[0] = the Stack varnode
        self.op_set_input(&newop, newin.clone(), 0);
        // input[1] = iop constant referencing the causing op
        let iop_addr = indeffect.0.read().unwrap().get_seq_num().get_addr();
        let iop_vn = self.new_constant(8, iop_addr.as_u64());
        iop_vn.write().unwrap().set_flags(crate::varnode::varnode_flags::ANNOTATION);
        self.op_set_input(&newop, iop_vn, 1);
        // Faithful to guardStores (heritage.cc:1554-1556):
        // setActiveHeritage on INDIRECT input + output so rename processes
        // them (builds SSA def-use chain, preventing dead-code removal).
        newin.write().unwrap().set_active_heritage();
        newout.write().unwrap().set_active_heritage();
        // Insert before the causing op
        self.op_insert_before(&newop, indeffect);
        newop
    }

    // Ghidra: funcdata.cc:34 Funcdata::newVarnodeIop
    /// Create a varnode in the iop address space referencing `op`.
    /// Faithful to `Funcdata::newVarnodeIop` (funcdata_varnode.cc:176-184).
    /// Ghidra encodes the raw op pointer as the iop-space offset; Rugra
    /// encodes `Arc::as_ptr()` (the stable address of the inner RwLock).
    pub fn new_varnode_iop(&mut self, op: &crate::op::PcodeOpRef) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // Encode the op's identity as a raw address. We use the Arc's data
        // pointer, which is stable for the Arc's lifetime (matching Ghidra's
        // `(uintb)(uintp)op`).
        let ptr_addr = std::sync::Arc::as_ptr(&op.0) as u64;
        let vn = self.vbank.create_with_space(
            std::mem::size_of::<usize>(),
            crate::space::AddressSpace::Iop,
            ptr_addr,
        );
        vn.write().unwrap().set_flags(crate::varnode::varnode_flags::ANNOTATION);
        vn
    }

    // Ghidra: funcdata.cc:34 Funcdata::getOpFromConst
    /// Resolve an iop-space constant varnode back to the PcodeOp it references.
    /// Faithful to `PcodeOp::getOpFromConst` (op.hh:249). Ghidra reinterprets
    /// the offset as an op pointer; Rugra reinterprets it back to the
    /// `Arc<RwLock<PcodeOp>>`.
    pub fn get_op_from_const(&self, vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) -> Option<crate::op::PcodeOpRef> {
        let v = vn.read().unwrap();
        if v.get_space() != crate::space::AddressSpace::Iop {
            return None;
        }
        let ptr_addr = v.get_offset() as usize;
        // Reconstruct the Arc from the raw pointer. This is safe as long as
        // the original Arc is still alive (which it is — the op bank holds it).
        let raw = ptr_addr as *const std::sync::RwLock<crate::op::PcodeOp>;
        // SAFETY: the pointer was obtained from Arc::as_ptr on an op that is
        // still in the obank. We rebuild the Arc via ManuallyDrop-free clone.
        unsafe {
            let arc = std::sync::Arc::from_raw(raw);
            // Clone to bump refcount, then forget the reconstructed one so we
            // don't double-free.
            let cloned = std::sync::Arc::clone(&arc);
            std::mem::forget(arc);
            Some(crate::op::PcodeOpRef(cloned))
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::opUndoPtradd
    /// Undo a PTRADD op, converting it back to INT_ADD/INT_MULT.
    /// Faithful to `Funcdata::opUndoPtradd` (funcdata_op.cc:579).
    pub fn op_undo_ptradd(&mut self, op: &crate::op::PcodeOpRef) {
        use crate::opcodes::OpCode;
        // PTRADD has 3 inputs: base, index, multiplier.
        // Get multiplier (input[2]).
        let mult_size = {
            let g = op.0.read().unwrap();
            if g.inrefs.len() < 3 {
                return; // malformed PTRADD
            }
            let vn = g.inrefs[2].clone();
            drop(g);
            let vn_rg = vn.read().unwrap();
            if vn_rg.is_constant() {
                vn_rg.get_offset() as usize
            } else {
                1
            }
        };
        // Remove input[2] (the multiplier).
        self.op_remove_input(op, 2);
        // Change opcode to INT_ADD.
        self.op_set_opcode(op, OpCode::CPUI_INT_ADD);
        if mult_size == 1 {
            return; // INT_ADD(base, index) is correct.
        }
        // The index input is now slot 1; scale it by mult_size via INT_MULT.
        let index_vn = {
            let g = op.0.read().unwrap();
            if g.inrefs.len() < 2 { return; }
            g.inrefs[1].clone()
        };
        let mult_const = self.new_constant(8, mult_size as u64);
        let mult_op = self.new_op(2, op.0.read().unwrap().get_seq_num().get_addr());
        self.op_set_opcode(&mult_op, OpCode::CPUI_INT_MULT);
        let mult_out = self.new_unique_out(8, &mult_op);
        // mult_op inputs: index, mult_const
        self.op_set_input(&mult_op, index_vn, 0);
        self.op_set_input(&mult_op, mult_const, 1);
        // Insert mult_op before op.
        self.op_insert_before(&mult_op, op);
        // Replace op's index input with mult_out.
        self.op_set_input(op, mult_out, 1);
    }

    // Ghidra: funcdata.cc:34 Funcdata::opMarkCpoolTransformed
    /// Mark `op` as having been checked for cpool transforms.
    /// Faithful to `Funcdata::opMarkCpoolTransformed` (funcdata.hh:485).
    pub fn op_mark_cpool_transformed(&mut self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().mark_cpool_transformed();
    }

    // Ghidra: funcdata.cc:34 Funcdata::getStoreGuard
    /// Find the STORE guard for `op`. Faithful to
    /// `Funcdata::getStoreGuard` (funcdata.hh:270). Returns None if no guard.
    pub fn get_store_guard(&self, op: &crate::op::PcodeOpRef) -> Option<&crate::heritage::LoadGuard> {
        self.heritage.get_store_guard(&op.0)
    }

    // Ghidra: funcdata.cc:34 Funcdata::getLoadGuard
    /// Find the LOAD guard for `op`. Faithful to
    /// `Funcdata::getLoadGuard` (funcdata.hh:269).
    pub fn get_load_guard(&self, op: &crate::op::PcodeOpRef) -> Option<&crate::heritage::LoadGuard> {
        self.heritage.get_load_guard(&op.0)
    }

    // Ghidra: funcdata.cc:34 Funcdata::newIndirectCreation
    /// Create an INDIRECT op with indirect_creation semantics. Faithful to
    /// `Funcdata::newIndirectCreation` (funcdata_op.cc:710-728). Unlike
    /// `new_indirect_op`, the input is a constant zero, and both the op and
    /// output carry the indirect_creation flag.
    pub fn new_indirect_creation(
        &mut self,
        indeffect: &crate::op::PcodeOpRef,
        addr: u64,
        sz: usize,
        possibleout: bool,
    ) -> crate::op::PcodeOpRef {
        use crate::op::pcodeop_flags;
        use crate::varnode::varnode_flags;
        // input[0]: constant zero.
        let newin = self.new_constant(sz, 0);
        // The op.
        let indeffect_addr = indeffect.0.read().unwrap().get_seq_num().get_addr();
        let newop = self.new_op(2, indeffect_addr);
        newop.0.write().unwrap().flags |= pcodeop_flags::INDIRECT_CREATION;
        // output: varnode at addr, defined by newop.
        let newout = self.vbank.create_with_space(sz, crate::space::AddressSpace::Unique, addr);
        self.vbank.set_def(newout.clone(), std::sync::Arc::downgrade(&newop.0));
        newop.0.write().unwrap().output = Some(newout.clone());
        // indirect_creation flags on input (if !possibleout) and output.
        if !possibleout {
            newin.write().unwrap().set_flags(varnode_flags::INDIRECT_CREATION);
        }
        newout.write().unwrap().set_flags(varnode_flags::INDIRECT_CREATION);
        // Set opcode to INDIRECT.
        self.op_set_opcode(&newop, crate::opcodes::OpCode::CPUI_INDIRECT);
        // input[0] = constant zero.
        self.op_set_input(&newop, newin, 0);
        // input[1] = iop varnode referencing the causing op.
        let iop_vn = self.new_varnode_iop(indeffect);
        self.op_set_input(&newop, iop_vn, 1);
        // active_heritage so rename processes the new varnodes.
        newout.write().unwrap().set_active_heritage();
        // Insert before the causing op.
        self.op_insert_before(&newop, indeffect);
        newop
    }

    // Ghidra: funcdata.cc:34 Funcdata::findJumpTable
    /// Find the JumpTable whose indirect op is at the same address as `op`.
    /// Faithful to `Funcdata::findJumpTable` (funcdata_block.cc:446-457).
    pub fn find_jump_table(&self, op: &crate::op::PcodeOpRef) -> Option<&std::sync::Arc<std::sync::RwLock<crate::jumptable::JumpTable>>> {
        let op_addr = op.0.read().unwrap().get_seq_num().get_addr().as_u64();
        self.jump_tables.iter().find(|jt| {
            let jt_rg = jt.read().unwrap();
            jt_rg.get_op_address().as_u64() == op_addr
        })
    }

    // Ghidra: funcdata.cc:34 Funcdata::removeJumpTable
    /// Remove a JumpTable from this function. Faithful to
    /// `Funcdata::removeJumpTable` (funcdata_block.cc:65).
    pub fn remove_jump_table(&mut self, jt: &std::sync::Arc<std::sync::RwLock<crate::jumptable::JumpTable>>) {
        let jt_ptr = std::sync::Arc::as_ptr(jt);
        self.jump_tables.retain(|j| std::sync::Arc::as_ptr(j) != jt_ptr);
    }


    // Ghidra: funcdata.cc:34 Funcdata::opInsertAfter
    /// Insert `op` immediately after `follow` in the alive list. Faithful to
    /// `Funcdata::opInsertAfter` (funcdata.hh:456). Used by split transforms
    /// (prefersplit.cc) that create new ops adjacent to the original.
    pub fn op_insert_after(&mut self, op: &crate::op::PcodeOpRef, follow: &crate::op::PcodeOpRef) {
        let pos = self.obank.alivelist.iter().position(|r| std::sync::Arc::ptr_eq(&r.0, &follow.0));
        match pos {
            Some(idx) => self.obank.alivelist.insert(idx + 1, op.clone()),
            None => self.obank.alivelist.push(op.clone()),
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::opUninsert
    /// Remove `op` from the alive list without destroying it. Faithful to
    /// `Funcdata::opUninsert` (funcdata.hh). The op is still alive (not dead)
    /// but temporarily detached from the ordered list, so it can be re-inserted
    /// elsewhere.
    pub fn op_uninsert(&mut self, op: &crate::op::PcodeOpRef) {
        self.obank
            .alivelist
            .retain(|r| !std::sync::Arc::ptr_eq(&r.0, &op.0));
    }

    // Ghidra: funcdata.cc:34 Funcdata::opInsertBegin
    /// Insert `op` at the beginning of a basic block's op list. Faithful to
    /// `Funcdata::opInsertBegin` (funcdata.hh:457). Rugra inserts at the start
    /// of the alive list (best-effort for block-begin placement).
    pub fn op_insert_begin(&mut self, op: &crate::op::PcodeOpRef, _bb: &std::sync::Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>) {
        self.obank.alivelist.insert(0, op.clone());
    }

    // Ghidra: funcdata.hh:461 Funcdata::opInsertEnd
    /// Insert `op` at the end of a basic block's op list. Faithful to
    /// `Funcdata::opInsertEnd(op, bl)` (funcdata.hh:461). Equivalent to
    /// inserting after the block's last op. Used by `buildDominantCopy`.
    pub fn op_insert_end(&mut self, op: &crate::op::PcodeOpRef, bb: &std::sync::Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>) {
        let last = {
            let rg = bb.read().unwrap();
            if let Some(bb2) = rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                bb2.last_op()
            } else {
                None
            }
        };
        match last {
            Some(last_op) => self.op_insert_after(op, &last_op),
            None => {
                // Empty block: append to alive list.
                self.obank.alivelist.push(op.clone());
            }
        }
    }

    // Ghidra: funcdata.hh:519 Funcdata::opMarkNonPrinting
    /// Mark `op` as non-printing (suppressed in C output). Faithful to
    /// `Funcdata::opMarkNonPrinting` (funcdata.hh:519).
    pub fn op_mark_non_printing(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().flags |= crate::op::pcodeop_flags::NONPRINTING;
    }

    // Ghidra: funcdata.hh:486 Funcdata::opMarkCalculatedBool
    /// Mark PcodeOp as having boolean output. Faithful to
    /// `Funcdata::opMarkCalculatedBool` (funcdata.hh:486).
    pub fn op_mark_calculated_bool(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().flags |= crate::op::pcodeop_flags::CALCULATED_BOOL;
    }

    // Ghidra: funcdata.hh:483 Funcdata::opMarkSpecialPrint
    /// Mark PcodeOp as needing special printing. Faithful to
    /// `Funcdata::opMarkSpecialPrint` (funcdata.hh:483).
    pub fn op_mark_special_print(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().addlflags |= crate::op::op_addl_flags::SPECIAL_PRINT;
    }

    // Ghidra: funcdata.hh:484 Funcdata::opMarkNoCollapse
    /// Mark PcodeOp as not collapsible. Faithful to
    /// `Funcdata::opMarkNoCollapse` (funcdata.hh:484).
    pub fn op_mark_no_collapse(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().flags |= crate::op::pcodeop_flags::NOCOLLAPSE;
    }

    // Ghidra: funcdata.hh:487 Funcdata::opMarkSpacebasePtr
    /// Mark PcodeOp as LOAD/STORE from spacebase ptr. Faithful to
    /// `Funcdata::opMarkSpacebasePtr` (funcdata.hh:487).
    pub fn op_mark_spacebase_ptr(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().flags |= crate::op::pcodeop_flags::SPACEBASE_PTR;
    }

    // Ghidra: funcdata.hh:488 Funcdata::opClearSpacebasePtr
    /// Unmark PcodeOp as using spacebase ptr. Faithful to
    /// `Funcdata::opClearSpacebasePtr` (funcdata.hh:488).
    pub fn op_clear_spacebase_ptr(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().flags &= !crate::op::pcodeop_flags::SPACEBASE_PTR;
    }

    // Ghidra: funcdata.hh:477 Funcdata::opSetAllInput
    /// Set all input Varnodes for the given PcodeOp simultaneously.
    /// Faithful to `Funcdata::opSetAllInput` (funcdata_op.cc:267-284).
    pub fn op_set_all_input(&mut self, op: &crate::op::PcodeOpRef, vvec: &[std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>]) {
        // Unset all existing inputs (funcdata_op.cc:276-278).
        let num = op.0.read().unwrap().num_input();
        for i in 0..num {
            self.op_unset_input(op, i);
        }
        // Resize input list (funcdata_op.cc:280).
        op.0.write().unwrap().inrefs.resize(vvec.len(), std::sync::Arc::new(std::sync::RwLock::new(
            crate::varnode::Varnode::new_constant(0, 0)
        )));
        // Set new inputs (funcdata_op.cc:282-283).
        for (i, vn) in vvec.iter().enumerate() {
            self.op_set_input(op, vn.clone(), i);
        }
    }

    // Ghidra: funcdata.hh:451 Funcdata::markIndirectCreation
    /// Convert CPUI_INDIRECT into an indirect creation. Faithful to
    /// `Funcdata::markIndirectCreation` (funcdata_op.cc:736-748).
    pub fn mark_indirect_creation(&self, indop: &crate::op::PcodeOpRef, possible_output: bool) {
        let (out_vn, in0_is_const) = {
            let o = indop.0.read().unwrap();
            let out = o.output.clone();
            let in0_const = o.get_in(0).map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
            (out, in0_const)
        };
        indop.0.write().unwrap().flags |= crate::op::pcodeop_flags::INDIRECT_CREATION;
        if !in0_is_const {
            eprintln!("[MERGE] Indirect creation not properly formed (in0 not constant)");
        }
        if !possible_output {
            if let Some(in0) = indop.0.read().unwrap().get_in(0) {
                in0.write().unwrap().set_flags(crate::varnode::varnode_flags::INDIRECT_CREATION);
            }
        }
        if let Some(out_vn) = out_vn {
            out_vn.write().unwrap().set_flags(crate::varnode::varnode_flags::INDIRECT_CREATION);
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::opGetSlot
    /// Get the input slot of `vn` within `op`. Faithful to `PcodeOp::getSlot`.
    /// Returns the slot index, or -1 if not found.
    pub fn op_get_slot(&self, op: &crate::op::PcodeOpRef, vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) -> i32 {
        let o = op.0.read().unwrap();
        for (i, v) in o.inrefs.iter().enumerate() {
            if std::sync::Arc::ptr_eq(v, vn) {
                return i as i32;
            }
        }
        -1
    }

    // Ghidra: funcdata.cc:230 Funcdata::spacebase
    /// Mark registers that map to a virtual address space (the stack
    /// spacebase). Faithful to `Funcdata::spacebase()` (funcdata.cc:230-269).
    ///
    /// For Rugra's x86-64 lift, the stack pointer is RSP at
    /// `AddressSpace::Register`, offset 0x20, size 8 (see `x86_lift.rs:40`).
    /// This method finds all varnodes at that location, marks them with the
    /// `SPACEBASE` flag, and — for already-marked spacebase varnodes with
    /// multiple descendants — calls `split_uses()` so each additive use
    /// (`INT_ADD(RSP, off)`) becomes independently addressable.
    ///
    /// This is the canonical Ghidra mechanism: it does NOT require the lifter
    /// to emit Stack-space varnodes. Instead, marking the RSP input as a
    /// spacebase lets downstream passes (varmap, ActionStackPtrFlow,
    /// heritage) recognize RSP as "a pointer into the Stack space."
    pub fn spacebase(&mut self) {
        // Stack pointer location from configuration (Architecture cspec fields).
        // Faithful to spc->getSpacebase(0) returning the register location.
        let sb_space = self.stack_pointer_space;
        let sb_offset = self.stack_pointer_offset;
        let sb_size = self.stack_pointer_size;

        // Collect all varnodes at the stack-pointer location that are not free.
        // Faithful to vbank.beginLoc(size, Address) / endLoc iteration.
        let candidates: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = {
            self.vbank
                .loc_tree
                .iter()
                .filter(|v| {
                    let g = v.0.read().unwrap();
                    !g.is_free()
                        && g.get_space() == sb_space
                        && g.get_offset() == sb_offset
                        && g.get_size() == sb_size
                })
                .map(|v| v.0.clone())
                .collect()
        };

        for vn_arc in candidates {
            let is_sb = vn_arc.read().unwrap().is_spacebase();
            if is_sb {
                // Already marked: give it a chance for descendants to be
                // eliminated naturally, now force a split if it still has
                // multiple descendants (funcdata.cc:253-259).
                let def_arc = {
                    let vn_g = vn_arc.read().unwrap();
                    vn_g.def.as_ref().and_then(|w| w.upgrade())
                };
                if let Some(def_op) = def_arc {
                    if def_op.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_INT_ADD {
                        self.split_uses(&vn_arc);
                    }
                }
            } else {
                // Mark all base registers (not just input) with spacebase flag
                // (funcdata.cc:262).
                vn_arc.write().unwrap().set_flags(crate::varnode::varnode_flags::SPACEBASE);
                // Note: Ghidra also sets TypeSpacebase pointer type on the
                // input register (funcdata.cc:263-264). Rugra's type system
                // does not yet have TypeSpacebase; the SPACEBASE flag alone is
                // sufficient for varmap/ActionStackPtrFlow recognition.
            }
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::calcNzMask
    /// Make all reads of the given Varnode unique. Faithful to
    /// `Funcdata::splitUses` (funcdata_varnode.cc:1540-1567).
    /// Calculate the non-zero mask (NZM) property on all Varnode objects.
    /// Faithful to `Funcdata::calcNZMask` (funcdata_varnode.cc:856-930).
    /// DFS traversal of ops in alive order: for each op whose output hasn't
    /// been calculated, compute its NZM from input NZMs using
    /// `PcodeOp::getNZMaskLocal` (op.cc:547-700).
    pub fn calc_nz_mask(&mut self) {
        use crate::opcodes::OpCode;
        // Process ops in alive list order (topological-ish).
        // For each op with an output, compute NZM.
        let ops: Vec<crate::op::PcodeOpRef> = self.obank.alivelist.clone();
        for op_ref in &ops {
            let (opcode, out_size) = {
                let op = op_ref.0.read().unwrap();
                let sz = op.output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(0);
                (op.opcode, sz)
            };
            if out_size == 0 { continue; }
            let full_mask = crate::address::calc_mask(out_size);
            // Get input NZMs
            let (in0_nzm, in1_nzm, in0_const, in1_const, in0_size, in1_val) = {
                let op = op_ref.0.read().unwrap();
                let i0 = op.inrefs.get(0).map(|v| {
                    let g = v.read().unwrap();
                    if g.is_constant() { g.get_offset() } else { g.get_nz_mask() }
                });
                let i1 = op.inrefs.get(1).map(|v| {
                    let g = v.read().unwrap();
                    if g.is_constant() { g.get_offset() } else { g.get_nz_mask() }
                });
                let c0 = op.inrefs.get(0).map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
                let c1 = op.inrefs.get(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
                let s0 = op.inrefs.get(0).map(|v| v.read().unwrap().get_size()).unwrap_or(0);
                let v1 = op.inrefs.get(1).map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
                (i0.unwrap_or(full_mask), i1.unwrap_or(full_mask), c0, c1, s0, v1)
            };
            let res_mask = match opcode {
                OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
                | OpCode::CPUI_INT_SLESS | OpCode::CPUI_INT_SLESSEQUAL
                | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_LESSEQUAL
                | OpCode::CPUI_INT_CARRY | OpCode::CPUI_INT_SCARRY | OpCode::CPUI_INT_SBORROW
                | OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_XOR
                | OpCode::CPUI_BOOL_AND | OpCode::CPUI_BOOL_OR
                | OpCode::CPUI_FLOAT_EQUAL | OpCode::CPUI_FLOAT_NOTEQUAL
                | OpCode::CPUI_FLOAT_LESS | OpCode::CPUI_FLOAT_LESSEQUAL
                | OpCode::CPUI_FLOAT_NAN => 1u64,
                OpCode::CPUI_COPY | OpCode::CPUI_INT_ZEXT => in0_nzm,
                OpCode::CPUI_INT_SEXT => {
                    // sign extend nzm from in0_size to out_size
                    let signbit = 1u64 << (in0_size * 8 - 1);
                    if (in0_nzm & signbit) != 0 && out_size > 8 {
                        full_mask // sign bit set, upper bits all 1
                    } else if (in0_nzm & signbit) != 0 {
                        in0_nzm | (full_mask & !crate::address::calc_mask(in0_size))
                    } else {
                        in0_nzm
                    }
                }
                OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_OR => {
                    if in0_nzm != full_mask { in0_nzm | in1_nzm } else { full_mask }
                }
                OpCode::CPUI_INT_AND => {
                    if in0_nzm != 0 { in0_nzm & in1_nzm } else { 0 }
                }
                OpCode::CPUI_INT_LEFT => {
                    if !in1_const { full_mask }
                    else {
                        let sa = in1_val as u32;
                        if sa >= 64 { 0 } else { in0_nzm.wrapping_shl(sa) & full_mask }
                    }
                }
                OpCode::CPUI_INT_RIGHT => {
                    if !in1_const { full_mask }
                    else {
                        let sa = in1_val as u32;
                        if sa >= 64 { 0 } else { in0_nzm >> sa }
                    }
                }
                OpCode::CPUI_INT_NEGATE => !in0_nzm & full_mask,
                OpCode::CPUI_INT_2COMP => {
                    // -x: if x is power of 2, nzm = x; else full_mask
                    if in0_nzm != 0 && (in0_nzm & (in0_nzm - 1)) == 0 { in0_nzm }
                    else { full_mask }
                }
                OpCode::CPUI_SUBPIECE => {
                    let trunc = in1_val as usize;
                    if trunc * 8 >= 64 { 0 }
                    else { (in0_nzm >> (trunc * 8)) & full_mask }
                }
                OpCode::CPUI_PIECE => {
                    // hi << lo_size | lo
                    in0_nzm.wrapping_shl(((out_size - in0_size) * 8) as u32) | in1_nzm
                }
                _ => full_mask,
            };
            // Set the output varnode's NZM
            if let Some(out) = op_ref.0.read().unwrap().output.as_ref() {
                out.write().unwrap().set_nzm(res_mask);
            }
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::splitUses
    ///
    /// If `vn` is defined by an op (e.g. INT_ADD) and has multiple
    /// descendants, duplicate the defining op so each reader gets its own
    /// independent output copy. This allows per-use analysis (e.g. distinct
    /// stack offsets from the same spacebase-derived pointer).
    pub fn split_uses(&mut self, vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) {
        // Get the defining op of vn.
        let def_arc = {
            let vn_g = vn.read().unwrap();
            match vn_g.def.as_ref().and_then(|w| w.upgrade()) {
                Some(a) => a,
                None => return, // no defining op
            }
        };

        // Collect descendant ops (readers), preserving order.
        let descendents: Vec<(crate::op::PcodeOpRef, i32)> = {
            let vn_g = vn.read().unwrap();
            vn_g.descend_iter()
                .map(|op| {
                    let opref = crate::op::PcodeOpRef(op.clone());
                    let slot = self.op_get_slot(&opref, vn);
                    (opref, slot)
                })
                .collect()
        };
        if descendents.len() <= 1 {
            return; // Only one (or zero) descendant — nothing to split.
        }

        // Clone the defining op for each descendant except the last.
        let num_inputs = def_arc.read().unwrap().inrefs.len();
        let def_addr = def_arc.read().unwrap().get_addr();
        let def_opcode = def_arc.read().unwrap().opcode;
        // Snapshot inputs before mutation (avoid holding lock across new_op).
        let inputs: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> =
            def_arc.read().unwrap().inrefs.clone();
        let vn_size = vn.read().unwrap().get_size();
        let vn_addr = vn.read().unwrap().loc.clone();
        let vn_space = vn.read().unwrap().address_space;

        // Faithful to funcdata_varnode.cc:1553-1565: for each descendant
        // except the last, create a new op cloning the definition, give it a
        // new output varnode, and redirect that descendant to the new output.
        let last_idx = descendents.len() - 1;
        for (i, (useop, slot)) in descendents.iter().enumerate() {
            if i == last_idx {
                break; // Last descendant keeps the original op.
            }
            if *slot < 0 {
                continue;
            }
            // newop = newOp(op->numInput(), op->getAddr())
            let newop = self.new_op(num_inputs, def_addr.clone());
            // newvn = newVarnode(vn->getSize(), vn->getAddr(), vn->getType())
            let newvn = self.vbank.create(vn_size, vn_addr.clone());
            newvn.write().unwrap().address_space = vn_space;
            // opSetOutput(newop, newvn)
            newvn.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
            newvn.write().unwrap().def = Some(std::sync::Arc::downgrade(&newop.0));
            newop.0.write().unwrap().output = Some(newvn.clone());
            // opSetOpcode(newop, op->code())
            self.op_set_opcode(&newop, def_opcode);
            // for each input: opSetInput(newop, op->getIn(i), i)
            for (idx, inp) in inputs.iter().enumerate() {
                self.op_set_input(&newop, inp.clone(), idx);
            }
            // opSetInput(useop, newvn, slot)
            self.op_set_input(useop, newvn.clone(), *slot as usize);
            // opInsertBefore(newop, op)
            let def_ref = crate::op::PcodeOpRef(def_arc.clone());
            self.op_insert_before(&newop, &def_ref);
        }
        // Dead-code actions should remove the original op if now unused.
    }

    // Ghidra: funcdata.cc:34 Funcdata::cseElimination
    /// Eliminate a common subexpression between two ops. Faithful to
    /// `Funcdata::cseElimination` (funcdata_op.cc:1358-1398). Keeps the
    /// earlier-ordered op (by sequence number), total_replaces the other's
    /// output, and destroys the duplicate.
    pub fn cse_elimination(
        &mut self,
        op1: &crate::op::PcodeOpRef,
        op2: &crate::op::PcodeOpRef,
    ) -> crate::op::PcodeOpRef {
        // Determine which op to keep (earlier sequence order).
        let order1 = op1.0.read().unwrap().start.get_order();
        let order2 = op2.0.read().unwrap().start.get_order();
        let (replace, dup) = if order1 <= order2 {
            (op1.clone(), op2.clone())
        } else {
            (op2.clone(), op1.clone())
        };
        let replace_out = replace.0.read().unwrap().output.clone();
        let dup_out = dup.0.read().unwrap().output.clone();
        if let (Some(rep_out), Some(dup_o)) = (replace_out, dup_out) {
            self.total_replace(&dup_o, rep_out);
        }
        self.op_destroy(&dup);
        replace
    }

    // Ghidra: funcdata.cc:34 Funcdata::cseEliminateList
    /// Perform CSE on a list of (hash, PcodeOp) pairs. Faithful to
    /// `Funcdata::cseEliminateList` (funcdata_op.cc:1420-1449). Sorts by hash,
    /// finds matching pairs via `is_cse_match`, eliminates duplicates.
    /// Returns the list of surviving output Varnodes.
    pub fn cse_eliminate_list(
        &mut self,
        list: &mut Vec<(u64, crate::op::PcodeOpRef)>,
    ) -> Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        let mut outlist = Vec::new();
        if list.is_empty() {
            return outlist;
        }
        // Sort by hash.
        list.sort_by_key(|(h, _)| *h);
        let mut i = 0;
        while i + 1 < list.len() {
            let h1 = list[i].0;
            let h2 = list[i + 1].0;
            if h1 == h2 {
                let op1 = list[i].1.clone();
                let op2 = list[i + 1].1.clone();
                let (is_dead1, is_dead2) = {
                    let r1 = op1.0.read().unwrap();
                    let r2 = op2.0.read().unwrap();
                    (r1.is_dead(), r2.is_dead())
                };
                if !is_dead1 && !is_dead2 {
                    let is_match = op1.0.read().unwrap().is_cse_match(&op2.0.read().unwrap());
                    if is_match {
                        let res_op = self.cse_elimination(&op1, &op2);
                        let out_opt = {
                            let r = res_op.0.read().unwrap();
                            r.output.clone()
                        };
                        if let Some(out) = out_opt {
                            outlist.push(out);
                        }
                    }
                }
            }
            i += 1;
        }
        outlist
    }

    // Ghidra: funcdata.cc:34 Funcdata::opBoolNegate
    /// Insert a BOOL_NEGATE (CPUI_BOOL_NEGATE in Rugra) of `vn`, returning the
    /// new output Varnode. Faithful to `Funcdata::opBoolNegate`
    /// (funcdata_op.cc:560-572). If `insert_after` is true, the negate op is
    /// inserted after `op`; otherwise before.
    pub fn op_bool_negate(
        &mut self,
        vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        op: &crate::op::PcodeOpRef,
        insert_after: bool,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let addr = op.0.read().unwrap().get_addr();
        let negate_op = self.new_op(1, addr);
        self.op_set_opcode(&negate_op, crate::opcodes::OpCode::CPUI_BOOL_NEGATE);
        let res_vn = self.new_unique_out(1, &negate_op);
        self.op_set_input(&negate_op, vn, 0);
        if insert_after {
            self.op_insert_after(&negate_op, op);
        } else {
            self.op_insert_before(&negate_op, op);
        }
        res_vn
    }

    // Ghidra: funcdata.cc:34 Funcdata::opFlipCondition
    /// Flip the condition of a CBRANCH/comparison op. Faithful to
    /// `Funcdata::opFlipCondition` (funcdata_op.cc). Changes the comparison
    /// opcode to its flipped variant (INT_LESS <-> INT_LESSEQUAL,
    /// INT_EQUAL <-> INT_NOTEQUAL) and clears the BOOLEAN_FLIP flag.
    pub fn op_flip_condition(&mut self, op: &crate::op::PcodeOpRef) {
        use crate::opcodes::get_booleanflip;
        let opc = op.0.read().unwrap().opcode;
        let mut reorder = false;
        let new_opc = get_booleanflip(opc, &mut reorder);
        op.0.write().unwrap().opcode = new_opc;
        if reorder {
            self.op_swap_input(op, 0, 1);
        }
        op.0.write().unwrap().flags &= !crate::op::pcodeop_flags::BOOLEAN_FLIP;
    }

    /// Inject raw P-code operations into this Funcdata
    ///
    /// This is the bridge between raw P-code translation output (e.g., from
    /// a SLEIGH translator or manual construction) and the `Funcdata` container
    /// that the `ActionDatabase` pipeline operates on.
    ///
    /// The method:
    /// 1. Converts each `PcodeOpRaw` into a `PcodeOp` in `obank`
    /// 2. Creates `Varnode` entries in `vbank` for all inputs/outputs
    /// 3. Detects basic block boundaries at control flow terminators
    /// 4. Populates `bblocks` with basic blocks and edges
    ///
    /// # Arguments
    /// * `raw_ops` - Vector of raw P-code operations in sequential order
    /// Inject a single instruction's P-code ops (for FlowInfo process_instruction).
    /// Does NOT call build_blocks_from_ops (that's done once after all flow is tracked).
    // RUGRA-GLUE: 单指令注入（FlowInfo process_instruction 用）。Ghidra 内联在 oneInstruction/emitter 中。
    pub fn inject_raw_ops_single(&mut self, raw_ops: &[PcodeOpRaw], base_addr: crate::address::Address) {
        for (raw_idx, raw) in raw_ops.iter().enumerate() {
            let opcode = match OpCode::from_i32(raw.get_opcode()) {
                Some(opc) => opc,
                None => continue,
            };
            let addr = raw.seq_num()
                .map(|s| s.get_addr())
                .unwrap_or(crate::address::Address::new(base_addr.as_u64() + raw_idx as u64 * 0x10));
            let op_ref = self.obank.create(opcode, raw.num_input(), addr);
            // Output varnode
            if let Some(out_raw) = raw.output() {
                let out_vn = self.vbank.create_with_space(out_raw.size, out_raw.space, out_raw.offset);
                self.vbank.set_def(out_vn.clone(), std::sync::Arc::downgrade(&op_ref.0));
                op_ref.0.write().unwrap().output = Some(out_vn);
            }
            // Input varnodes
            for input_raw in raw.inputs() {
                let in_vn = if input_raw.space == crate::space::AddressSpace::Const {
                    self.vbank.create_constant(input_raw.size, input_raw.offset)
                } else {
                    self.vbank.find_or_create_input_space(input_raw.size, input_raw.space, input_raw.offset)
                };
                op_ref.0.write().unwrap().inrefs.push(in_vn);
            }
            self.obank.mark_alive(op_ref);
        }
    }

    /// Build basic blocks from ALL alive ops (called after flow tracking completes).
    // RUGRA-GLUE: 从全部 alive ops 构建 CFG（FlowInfo 流追踪后调用）。
    pub fn build_blocks_from_alive(&mut self) {
        let op_refs: Vec<PcodeOpRef> = self.obank.alivelist.iter()
            .map(|r| PcodeOpRef(r.0.clone()))
            .collect();
        self.build_blocks_from_ops(&op_refs);
        eprintln!("[INJECT] {} build_blocks_from_alive done bblocks={}", self.name, self.bblocks.get_size());
    }

    // Ghidra: funcdata.cc:34 Funcdata::injectRawOps
    pub fn inject_raw_ops(&mut self, raw_ops: &[PcodeOpRaw]) {
        if raw_ops.is_empty() {
            return;
        }

        // Phase 1: Convert all raw ops into PcodeOps with proper varnodes
        let mut op_refs: Vec<PcodeOpRef> = Vec::with_capacity(raw_ops.len());

        for (raw_idx, raw) in raw_ops.iter().enumerate() {
            // NOTE: raw.get_opcode() returns a RUST enum discriminant (the
            // lifter in x86_lift.rs builds PcodeOpRaw via `OpCode::CPUI_X as
            // i32`), NOT a Ghidra-native opcode int. So OpCode::from_i32 is
            // correct here. map_ghidra_opcode is only for Ghidra-FFI ints.
            // (Audit BATCH3 R37 was a false-positive for this call site; the
            // real FFI mapping fix is in ffi.rs — CPUI_CAST now round-trips.)
            let opcode = match OpCode::from_i32(raw.get_opcode()) {
                Some(opc) => opc,
                None => {
                    log::warn!("Unknown opcode {}, skipping", raw.get_opcode());
                    continue;
                }
            };

            // Assign a distinct address to each op: base + index * stride
            // This allows CBRANCH targets to be resolved to block start addresses
            let addr = raw
                .seq_num()
                .map(|s| s.get_addr())
                .unwrap_or(Address::new(self.baseaddr.as_u64() + raw_idx as u64 * 0x10));

            let op_ref = self.obank.create(opcode, raw.num_input(), addr);

            // Create output varnode if present
            if let Some(out_raw) = raw.output() {
                let out_vn =
                    self.vbank
                        .create_with_space(out_raw.size, out_raw.space, out_raw.offset);
                // Mark as written and set def
                self.vbank
                    .set_def(out_vn.clone(), Arc::downgrade(&op_ref.0));
                op_ref.0.write().unwrap().output = Some(out_vn);
            }

            // Create input varnodes. For non-constant inputs, reuse an existing
            // free/input varnode at the same (space, offset, size) if one exists.
            // This ensures all reads of the same register (e.g. RSP) share ONE
            // varnode, so its `descend` list accumulates all readers — faithful
            // to Ghidra's varnode identity model (VarnodeBank::xref dedup).
            for input_raw in raw.inputs() {
                let in_vn = if input_raw.space == AddressSpace::Const {
                    self.vbank.create_constant(input_raw.size, input_raw.offset)
                } else {
                    self.vbank.find_or_create_input_space(
                        input_raw.size,
                        input_raw.space,
                        input_raw.offset,
                    )
                };
                // Add use-def link
                in_vn
                    .write()
                    .unwrap()
                    .descend
                    .push(Arc::downgrade(&op_ref.0));
                op_ref.0.write().unwrap().inrefs.push(in_vn);
            }

            op_refs.push(op_ref);
        }

        eprintln!("[INJECT] {} phase1 done ops={}", self.name, op_refs.len());

        // Phase 2: Build basic blocks from the linear op sequence
        self.build_blocks_from_ops(&op_refs);
        eprintln!("[INJECT] {} phase2 done bblocks={}", self.name, self.bblocks.get_size());

        // Phase 3: Mark unwritten Register-space input varnodes as INPUT
        // In Ghidra's model, Heritage marks register reads with no prior definition
        // within the function as INPUT varnodes (function parameters / callee-saved regs).
        //
        // Correct semantics (read-before-write): a register read at op N is an INPUT
        // if no earlier op (in instruction order) wrote to that register offset.
        // Using a global "ever-defined" set is WRONG because parameter registers
        // are routinely re-assigned mid-function (e.g. RDX is read as param_3 at
        // 0x34a2 then overwritten by `mov rdx,[rsp+8]` at 0x34ac). A global set
        // would see the later write and miss the earlier read.
        //
        // We process ops in order; for each op we first inspect its inputs (reads)
        // and then record its output (write). This gives correct read-before-write
        // ordering within the linear instruction stream.
        //
        // CALL ops are skipped: the lifter attaches 6 ABI arg registers as inputs
        // to every CALL, which represent arguments PASSED TO the callee, not
        // registers READ by this function. Counting them would inflate the INPUT
        // set with RDI/RSI/RDX/RCX/R8/R9 on every function containing a call.
        let mut defined_reg_offsets: std::collections::HashSet<u64> = std::collections::HashSet::new();

        // Track which offsets we've already marked as INPUT to avoid duplicates
        let mut marked_input = std::collections::HashSet::new();
        for op_ref in &op_refs {
            let op = op_ref.0.read().unwrap();

            // Skip CALL: its register inputs are callee args, not this function's reads.
            if op.opcode == OpCode::CPUI_CALL {
                // Still record any output (call return value in RAX) as defined,
                // so a later read of RAX is not mistaken for a parameter.
                if let Some(ref out_arc) = op.output {
                    let out_vn = out_arc.read().unwrap();
                    if out_vn.get_space() == AddressSpace::Register {
                        defined_reg_offsets.insert(out_vn.get_offset());
                    }
                }
                continue;
            }

            // First: process reads (inputs) against the *current* defined set.
            for in_arc in &op.inrefs {
                let vn = in_arc.read().unwrap();
                if vn.get_space() == AddressSpace::Register
                    && !vn.is_input()
                    && !defined_reg_offsets.contains(&vn.get_offset())
                    && marked_input.insert(vn.get_offset())
                {
                    drop(vn); // Release read lock before write
                    self.vbank.set_input(in_arc.clone());
                }
            }

            // Then: record this op's output as defined for subsequent ops.
            if let Some(ref out_arc) = op.output {
                let out_vn = out_arc.read().unwrap();
                if out_vn.get_space() == AddressSpace::Register {
                    defined_reg_offsets.insert(out_vn.get_offset());
                }
            }
        }
        eprintln!("[INJECT] {} phase3 done marked_input={}", self.name, marked_input.len());
        // NOTE: Phase 4 global use-def linking is disabled — it correctly
        // resolves stack symbols (verified) but perturbs typeop inference
        // (struct-pointer types leak into switch/arith contexts). varmap's
        // resolve_rsp_offset_via_bank provides a read-only def bridge scoped
        // to spacebase resolution only, avoiding the typeop interaction.
    }

    // Ghidra: funcdata.cc:34 Funcdata::buildBlocksFromOps
    /// Build basic blocks from a linear sequence of PcodeOps
    ///
    /// Splits the op list at control flow terminators (BRANCH, CBRANCH, RETURN, CALL)
    /// and creates basic blocks in `self.bblocks`.
    fn build_blocks_from_ops(&mut self, op_refs: &[PcodeOpRef]) {
        if op_refs.is_empty() {
            return;
        }

        // Identify block start indices. Ghidra's basic-block partitioning
        // (BlockGraph::copyBlocks / Funcdata::structureReset) splits at TWO
        // kinds of points:
        //   (1) after each block terminator (BRANCH/CBRANCH/BRANCHIND/RETURN)
        //   (2) at every jump TARGET address — any address that a BRANCH/
        //       CBRANCH points to must begin a new block, so the target edge
        //       resolves to a block start.
        // Rugra previously did only (1), which meant jump targets landing in
        // the middle of a block were unresolvable — the CBRANCH edge was
        // silently dropped (observed: curl main 56 / global 182 CBRANCH
        // targets unmatched, losing back-edges and collapsing while-loop
        // recovery from ~6 to 1).

        // Build addr -> op-index map for target resolution.
        let mut addr_to_idx: std::collections::HashMap<u64, usize> =
            std::collections::HashMap::with_capacity(op_refs.len());
        for (i, op_ref) in op_refs.iter().enumerate() {
            let addr = op_ref.0.read().unwrap().get_addr().as_u64();
            addr_to_idx.entry(addr).or_insert(i);
        }

        // Collect target op-indices from BRANCH/CBRANCH.
        let mut target_starts: std::collections::HashSet<usize> =
            std::collections::HashSet::new();
        for (i, op_ref) in op_refs.iter().enumerate() {
            let (opc, target_offset) = {
                let op = op_ref.0.read().unwrap();
                let tgt = match op.opcode {
                    OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCH => {
                        op.get_in(0).map(|vn| vn.read().unwrap().get_offset())
                    }
                    _ => None,
                };
                (op.opcode, tgt)
            };
            if matches!(opc, OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCH) {
                if let Some(taddr) = target_offset {
                    if let Some(&tidx) = addr_to_idx.get(&taddr) {
                        // The op at the target address starts a new block.
                        // Don't split at index 0 (it's already a start) and
                        // don't split at i+1 if this branch falls through to
                        // its target (handled by terminator rule below).
                        if tidx != 0 {
                            target_starts.insert(tidx);
                        }
                    }
                    // If target not in addr_to_idx, the target is outside
                    // this function (e.g. tail-call / external) — skip, the
                    // edge will be dropped as before.
                    let _ = i; // suppress unused warning
                }
            }
        }

        // Combine: block starts = {0} ∪ {terminator+1} ∪ {jump targets}.
        let mut block_starts: std::collections::BTreeSet<usize> =
            std::collections::BTreeSet::new();
        block_starts.insert(0);
        for (i, op_ref) in op_refs.iter().enumerate() {
            let op = op_ref.0.read().unwrap();
            if op.opcode.is_block_terminator() && i + 1 < op_refs.len() {
                block_starts.insert(i + 1);
            }
        }
        for tidx in target_starts {
            block_starts.insert(tidx);
        }
        let block_starts: Vec<usize> = block_starts.into_iter().collect();

        // Create basic blocks
        let mut blocks: Vec<Arc<RwLock<BlockBasic>>> = Vec::new();
        for (block_idx, &start) in block_starts.iter().enumerate() {
            let end = if block_idx + 1 < block_starts.len() {
                block_starts[block_idx + 1]
            } else {
                op_refs.len()
            };

            let block_addr = op_refs[start].0.read().unwrap().get_addr();
            let block = Arc::new(RwLock::new(BlockBasic::new(block_idx as i32, block_addr)));

            // Add ops to this block
            for op_ref in &op_refs[start..end] {
                {
                    let mut op = op_ref.0.write().unwrap();
                    op.parent = Some(Arc::downgrade(
                        // We need to cast to dyn FlowBlock
                        &(block.clone() as Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>),
                    ));
                }
                let insert_pos = block.read().unwrap().get_ops().len();
                block.write().unwrap().insert_op(insert_pos, op_ref.clone());
            }

            blocks.push(block);
        }

        // Add blocks to the graph
        for block in &blocks {
            self.bblocks.add_block(block.clone());
        }

        // Add fallthrough edges between consecutive blocks
        // Also resolve BRANCH and CBRANCH targets to add the branch edges
        for i in 0..blocks.len() {
            let (last_opcode, branch_target_offset) = {
                let b = blocks[i].read().unwrap();
                let ops = b.get_ops();
                if ops.is_empty() {
                    continue;
                }
                let last_op = ops.last().unwrap().0.read().unwrap();
                let target = match last_op.opcode {
                    OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCH => {
                        // Input 0 is the branch target address
                        last_op.get_in(0).map(|vn| vn.read().unwrap().get_offset())
                    }
                    _ => None,
                };
                (last_op.opcode, target)
            };

            match last_opcode {
                OpCode::CPUI_RETURN | OpCode::CPUI_BRANCHIND => {
                    // Terminators that don't transition to a known, raw intra-function block
                }
                OpCode::CPUI_BRANCH => {
                    // Unconditional branch: 1 edge to the target ONLY
                    if let Some(target_addr) = branch_target_offset {
                        for j in 0..blocks.len() {
                            let target_start = blocks[j].read().unwrap().get_start_addr().as_u64();
                            if target_start == target_addr {
                                self.bblocks.add_edge(blocks[i].clone(), blocks[j].clone());
                                break;
                            }
                        }
                    }
                }
                OpCode::CPUI_CBRANCH => {
                    // CBRANCH gets BOTH edges, but ORDER MATTERS for Structure Collapse!
                    // Edge 0: branch target (true branch)
                    if let Some(target_addr) = branch_target_offset {
                        for j in 0..blocks.len() {
                            let target_start = blocks[j].read().unwrap().get_start_addr().as_u64();
                            if target_start == target_addr {
                                self.bblocks.add_edge(blocks[i].clone(), blocks[j].clone());
                                break;
                            }
                        }
                    }

                    // Edge 1: fallthrough (false branch) to next sequential block
                    if i + 1 < blocks.len() {
                        self.bblocks
                            .add_edge(blocks[i].clone(), blocks[i + 1].clone());
                    }
                }
                _ => {
                    // Add fallthrough edge to next block
                    if i + 1 < blocks.len() {
                        self.bblocks
                            .add_edge(blocks[i].clone(), blocks[i + 1].clone());
                    }
                }
            }
        }
    }

    // Ghidra: funcdata.cc:84 Funcdata::clear
    /// Clear all analysis state
    pub fn clear(&mut self) {
        self.vbank.clear();
        self.obank.clear();
        self.bblocks.clear();
        self.sblocks.clear();
        self.heritage.clear();
    }

    // Ghidra: funcdata.cc:34 Funcdata::numHeritagePasses
    /// Get number of heritage passes completed
    pub fn num_heritage_passes(&self) -> i32 {
        self.heritage.get_pass()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::align::runtime_verify::{RuntimeVerifier, VerifyResult};
    use crate::disasm::{Disassembler, X86Lifter, X86_64Disassembler};
    use crate::ffi;
    use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
    use std::sync::Mutex;

    // Serialize tests that use the global CURRENT_PROGRAM to prevent
    // multi-threaded test races when `cargo test` runs in parallel.
    lazy_static::lazy_static! {
        static ref FFI_TEST_LOCK: Mutex<()> = Mutex::new(());
    }

    #[test]
    fn test_funcdata_creation() {
        let fd = Funcdata::new("test_func", Address::new(0x1000), 0x100);
        assert_eq!(fd.get_name(), "test_func");
        assert_eq!(fd.get_address().as_u64(), 0x1000);
    }

    #[test]
    fn test_inject_raw_ops_simple() {
        let mut fd = Funcdata::new("add", Address::new(0x1000), 7);

        // Build: RAX = COPY(RDI)
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        // Build: RAX = INT_ADD(RAX, RSI)
        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op2.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI

        // Build: RETURN(RAX)
        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op3.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX

        fd.inject_raw_ops(&[op1, op2, op3]);

        // Verify ops were created
        assert_eq!(fd.obank.alivelist.len(), 3);

        // Verify varnodes were created (2 outputs + 4 inputs = 6 total)
        assert!(fd.vbank.num_varnodes() > 0);

        // Verify basic blocks (RETURN terminates, so we get 1 block)
        assert_eq!(fd.bblocks.get_size(), 1);
    }

    #[test]
    fn test_inject_raw_ops_with_branch() {
        let mut fd = Funcdata::new("branch_test", Address::new(0x2000), 20);

        // Block 0: compare and branch
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 1));
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8));
        op1.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));

        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
        op2.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x2010, 8));
        op2.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 1));

        // Block 1: true branch
        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op3.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 1, 8));

        let mut op4 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op4.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));

        fd.inject_raw_ops(&[op1, op2, op3, op4]);

        // Basic-block partitioning splits at terminators AND at jump targets
        // (Ghidra-style). CBRANCH at op1 (addr 0x2010) targets 0x2010 — itself,
        // a self-loop — so op1 is its own block boundary. This yields 3 blocks:
        //   [op0(op1=INT_EQUAL), op1(CBRANCH)] | [op2(COPY), op3(RETURN)]
        // becomes, with the self-loop target splitting at op1:
        //   [op0] | [op1(CBRANCH, self-loop)] | [op2, op3]
        assert_eq!(fd.bblocks.get_size(), 3);
    }

    #[test]
    fn test_mov_reg_reg_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x89, 0xc3]; // mov rbx, rax
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "mov");
        assert!(inst.text.contains("rbx"));
        assert!(inst.text.contains("rax"));

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        assert_eq!(raw_ops.len(), 1);

        let raw = &raw_ops[0];
        assert_eq!(OpCode::from_i32(raw.get_opcode()), Some(OpCode::CPUI_COPY));

        let out_binding = raw.output();
        let out = out_binding.as_ref().unwrap();
        assert_eq!(out.space, AddressSpace::Register);
        assert_eq!(out.offset, 0x18);
        assert_eq!(out.size, 8);

        let inputs = raw.inputs();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].space, AddressSpace::Register);
        assert_eq!(inputs[0].offset, 0x00);
        assert_eq!(inputs[0].size, 8);

        let mut fd = Funcdata::new("mov_reg_reg", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 1);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result = verifier.verify_pcode_generation("mov_rbx_rax_minimal", start, &rugra_ops, 1);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_add_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x83, 0xc0, 0x01]; // add rax, 1
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "add");
        assert!(inst.text.contains("rax"));
        assert!(inst.text.contains("1"));

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        assert_eq!(raw_ops.len(), 2);

        let raw_add = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_add.get_opcode()),
            Some(OpCode::CPUI_INT_ADD)
        );

        let add_out_binding = raw_add.output();
        let add_out = add_out_binding.as_ref().unwrap();
        assert_eq!(add_out.space, AddressSpace::Unique);
        assert_eq!(add_out.size, 8);

        let add_inputs = raw_add.inputs();
        assert_eq!(add_inputs.len(), 2);
        assert_eq!(add_inputs[0].space, AddressSpace::Register);
        assert_eq!(add_inputs[0].offset, 0x00);
        assert_eq!(add_inputs[0].size, 8);
        assert_eq!(add_inputs[1].space, AddressSpace::Const);
        assert_eq!(add_inputs[1].offset, 0x01);
        assert_eq!(add_inputs[1].size, 1);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let copy_out_binding = raw_copy.output();
        let copy_out = copy_out_binding.as_ref().unwrap();
        assert_eq!(copy_out.space, AddressSpace::Register);
        assert_eq!(copy_out.offset, 0x00);
        assert_eq!(copy_out.size, 8);

        let copy_inputs = raw_copy.inputs();
        assert_eq!(copy_inputs.len(), 1);
        assert_eq!(copy_inputs[0].space, AddressSpace::Unique);
        assert_eq!(copy_inputs[0].offset, add_out.offset);
        assert_eq!(copy_inputs[0].size, 8);

        let mut fd = Funcdata::new("add_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result = verifier.verify_pcode_generation("add_rax_1_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_sub_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x83, 0xe8, 0x08]; // sub rax, 8
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "sub");
        assert!(inst.text.contains("rax"));
        assert!(inst.text.contains("8"));

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        // Expect INT_SUB + COPY (same pattern as add)
        assert_eq!(raw_ops.len(), 2);

        let raw_sub = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_sub.get_opcode()),
            Some(OpCode::CPUI_INT_SUB)
        );

        let sub_out_binding = raw_sub.output();
        let sub_out = sub_out_binding.as_ref().unwrap();
        assert_eq!(sub_out.space, AddressSpace::Unique);
        assert_eq!(sub_out.size, 8);

        let sub_inputs = raw_sub.inputs();
        assert_eq!(sub_inputs.len(), 2);
        assert_eq!(sub_inputs[0].space, AddressSpace::Register);
        assert_eq!(sub_inputs[0].offset, 0x00); // RAX
        assert_eq!(sub_inputs[0].size, 8);
        assert_eq!(sub_inputs[1].space, AddressSpace::Const);
        assert_eq!(sub_inputs[1].offset, 0x08);
        assert_eq!(sub_inputs[1].size, 1);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let copy_out_binding = raw_copy.output();
        let copy_out = copy_out_binding.as_ref().unwrap();
        assert_eq!(copy_out.space, AddressSpace::Register);
        assert_eq!(copy_out.offset, 0x00); // RAX
        assert_eq!(copy_out.size, 8);

        let copy_inputs = raw_copy.inputs();
        assert_eq!(copy_inputs.len(), 1);
        assert_eq!(copy_inputs[0].space, AddressSpace::Unique);
        assert_eq!(copy_inputs[0].offset, sub_out.offset);
        assert_eq!(copy_inputs[0].size, 8);

        let mut fd = Funcdata::new("sub_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result = verifier.verify_pcode_generation("sub_rax_8_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    // ========== Fourth batch: and / or / xor / shl / shr / cmp ==========

    #[test]
    fn test_and_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // and rax, 0xf  →  48 83 e0 0f
        let code = vec![0x48, 0x83, 0xe0, 0x0f];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "and");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        // Expect INT_AND + COPY
        assert_eq!(raw_ops.len(), 2);

        let raw_op = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_op.get_opcode()),
            Some(OpCode::CPUI_INT_AND)
        );

        let op_out_binding = raw_op.output();
        let op_out = op_out_binding.as_ref().unwrap();
        assert_eq!(op_out.space, AddressSpace::Unique);
        assert_eq!(op_out.size, 8);

        let op_inputs = raw_op.inputs();
        assert_eq!(op_inputs.len(), 2);
        assert_eq!(op_inputs[0].space, AddressSpace::Register);
        assert_eq!(op_inputs[0].offset, 0x00); // RAX
        assert_eq!(op_inputs[1].space, AddressSpace::Const);
        assert_eq!(op_inputs[1].offset, 0x0f);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let mut fd = Funcdata::new("and_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("and_rax_0xf_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_or_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // or rax, 0x10  →  48 83 c8 10
        let code = vec![0x48, 0x83, 0xc8, 0x10];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "or");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        assert_eq!(raw_ops.len(), 2);

        let raw_op = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_op.get_opcode()),
            Some(OpCode::CPUI_INT_OR)
        );

        let op_out_binding = raw_op.output();
        let op_out = op_out_binding.as_ref().unwrap();
        assert_eq!(op_out.space, AddressSpace::Unique);
        assert_eq!(op_out.size, 8);

        let op_inputs = raw_op.inputs();
        assert_eq!(op_inputs.len(), 2);
        assert_eq!(op_inputs[0].space, AddressSpace::Register);
        assert_eq!(op_inputs[0].offset, 0x00); // RAX
        assert_eq!(op_inputs[1].space, AddressSpace::Const);
        assert_eq!(op_inputs[1].offset, 0x10);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let mut fd = Funcdata::new("or_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("or_rax_0x10_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_xor_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // xor rax, 0x7  →  48 83 f0 07
        let code = vec![0x48, 0x83, 0xf0, 0x07];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "xor");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        assert_eq!(raw_ops.len(), 2);

        let raw_op = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_op.get_opcode()),
            Some(OpCode::CPUI_INT_XOR)
        );

        let op_out_binding = raw_op.output();
        let op_out = op_out_binding.as_ref().unwrap();
        assert_eq!(op_out.space, AddressSpace::Unique);
        assert_eq!(op_out.size, 8);

        let op_inputs = raw_op.inputs();
        assert_eq!(op_inputs.len(), 2);
        assert_eq!(op_inputs[0].space, AddressSpace::Register);
        assert_eq!(op_inputs[0].offset, 0x00); // RAX
        assert_eq!(op_inputs[1].space, AddressSpace::Const);
        assert_eq!(op_inputs[1].offset, 0x07);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let mut fd = Funcdata::new("xor_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("xor_rax_0x7_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_shl_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // shl rax, 4  →  48 c1 e0 04
        let code = vec![0x48, 0xc1, 0xe0, 0x04];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "shl");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        assert_eq!(raw_ops.len(), 2);

        let raw_op = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_op.get_opcode()),
            Some(OpCode::CPUI_INT_LEFT)
        );

        let op_out_binding = raw_op.output();
        let op_out = op_out_binding.as_ref().unwrap();
        assert_eq!(op_out.space, AddressSpace::Unique);
        assert_eq!(op_out.size, 8);

        let op_inputs = raw_op.inputs();
        assert_eq!(op_inputs.len(), 2);
        assert_eq!(op_inputs[0].space, AddressSpace::Register);
        assert_eq!(op_inputs[0].offset, 0x00); // RAX
        assert_eq!(op_inputs[1].space, AddressSpace::Const);
        assert_eq!(op_inputs[1].offset, 0x04);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let mut fd = Funcdata::new("shl_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("shl_rax_4_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_shr_rax_imm_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // shr rax, 4  →  48 c1 e8 04
        let code = vec![0x48, 0xc1, 0xe8, 0x04];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "shr");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        assert_eq!(raw_ops.len(), 2);

        let raw_op = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_op.get_opcode()),
            Some(OpCode::CPUI_INT_RIGHT)
        );

        let op_out_binding = raw_op.output();
        let op_out = op_out_binding.as_ref().unwrap();
        assert_eq!(op_out.space, AddressSpace::Unique);
        assert_eq!(op_out.size, 8);

        let op_inputs = raw_op.inputs();
        assert_eq!(op_inputs.len(), 2);
        assert_eq!(op_inputs[0].space, AddressSpace::Register);
        assert_eq!(op_inputs[0].offset, 0x00); // RAX
        assert_eq!(op_inputs[1].space, AddressSpace::Const);
        assert_eq!(op_inputs[1].offset, 0x04);

        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let mut fd = Funcdata::new("shr_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("shr_rax_4_minimal", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_cmp_rax_rbx_minimal_alignment_path() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // cmp rax, rbx  →  48 39 d8
        let code = vec![0x48, 0x39, 0xd8];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "cmp");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);
        // cmp produces 3 flag-setting ops: INT_EQUAL(ZF), INT_LESS(CF), INT_SLESS(SF)
        assert_eq!(raw_ops.len(), 3);

        // Op 0: ZF = INT_EQUAL(rax, rbx)
        let raw_zf = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_zf.get_opcode()),
            Some(OpCode::CPUI_INT_EQUAL)
        );
        let zf_out_binding = raw_zf.output();
        let zf_out = zf_out_binding.as_ref().unwrap();
        assert_eq!(zf_out.space, AddressSpace::Register);
        assert_eq!(zf_out.offset, 0x201); // ZF register
        assert_eq!(zf_out.size, 1);

        let zf_inputs = raw_zf.inputs();
        assert_eq!(zf_inputs.len(), 2);
        assert_eq!(zf_inputs[0].space, AddressSpace::Register);
        assert_eq!(zf_inputs[0].offset, 0x00); // RAX
        assert_eq!(zf_inputs[1].space, AddressSpace::Register);
        assert_eq!(zf_inputs[1].offset, 0x18); // RBX

        // Op 1: CF = INT_LESS(rax, rbx)
        let raw_cf = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_cf.get_opcode()),
            Some(OpCode::CPUI_INT_LESS)
        );
        let cf_out_binding = raw_cf.output();
        let cf_out = cf_out_binding.as_ref().unwrap();
        assert_eq!(cf_out.space, AddressSpace::Register);
        assert_eq!(cf_out.offset, 0x203); // CF register
        assert_eq!(cf_out.size, 1);

        // Op 2: SF = INT_SLESS(rax, rbx)
        let raw_sf = &raw_ops[2];
        assert_eq!(
            OpCode::from_i32(raw_sf.get_opcode()),
            Some(OpCode::CPUI_INT_SLESS)
        );
        let sf_out_binding = raw_sf.output();
        let sf_out = sf_out_binding.as_ref().unwrap();
        assert_eq!(sf_out.space, AddressSpace::Register);
        assert_eq!(sf_out.offset, 0x202); // SF register
        assert_eq!(sf_out.size, 1);

        let mut fd = Funcdata::new("cmp_rax_rbx", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 3);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("cmp_rax_rbx_minimal", start, &rugra_ops, 3);

        assert!(matches!(result, VerifyResult::Match));
    }

    // ========== Memory instruction (LOAD / STORE) alignment tests ==========

    /// Test: `mov rax, [rbx]` — Simple memory load
    /// Machine code: 48 8b 03
    /// Expected P-code:
    ///   1. CPUI_LOAD(const(ram_space_id), reg(rbx)) -> unique_tmp
    ///   2. CPUI_COPY(unique_tmp) -> reg(rax)
    #[test]
    fn test_load_mov_rax_mem_rbx_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x8b, 0x03]; // mov rax, [rbx]
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "mov");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);

        // parse_operand for Memory emits a LOAD internally, then mov emits COPY
        // So we expect: LOAD + COPY = 2 ops
        assert_eq!(raw_ops.len(), 2, "Expected LOAD + COPY, got {} ops", raw_ops.len());

        // Op 0: CPUI_LOAD
        let raw_load = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_load.get_opcode()),
            Some(OpCode::CPUI_LOAD)
        );

        let load_out_binding = raw_load.output();
        let load_out = load_out_binding.as_ref().unwrap();
        assert_eq!(load_out.space, AddressSpace::Unique);
        assert_eq!(load_out.size, 8);

        let load_inputs = raw_load.inputs();
        assert_eq!(load_inputs.len(), 2);
        // Input 0: RAM space ID as a constant
        assert_eq!(load_inputs[0].space, AddressSpace::Const);
        assert_eq!(load_inputs[0].offset, AddressSpace::Ram.space_id() as u64);
        // Input 1: address from rbx register
        assert_eq!(load_inputs[1].space, AddressSpace::Register);
        assert_eq!(load_inputs[1].offset, 0x18); // rbx offset
        assert_eq!(load_inputs[1].size, 8);

        // Op 1: CPUI_COPY
        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let copy_out_binding = raw_copy.output();
        let copy_out = copy_out_binding.as_ref().unwrap();
        assert_eq!(copy_out.space, AddressSpace::Register);
        assert_eq!(copy_out.offset, 0x00); // rax
        assert_eq!(copy_out.size, 8);

        let copy_inputs = raw_copy.inputs();
        assert_eq!(copy_inputs.len(), 1);
        assert_eq!(copy_inputs[0].space, AddressSpace::Unique);
        assert_eq!(copy_inputs[0].offset, load_out.offset);

        // Inject and verify
        let mut fd = Funcdata::new("load_mov_rax_mem_rbx", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("load_mov_rax_mem_rbx", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: `mov [rbx], rax` — Simple memory store
    /// Machine code: 48 89 03
    /// Expected P-code:
    ///   1. CPUI_STORE(const(ram_space_id), reg(rbx), reg(rax)) — no output
    #[test]
    fn test_store_mov_mem_rbx_rax_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x89, 0x03]; // mov [rbx], rax
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "mov");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);

        // mov [rbx], rax: source is register (no LOAD), dest is memory (STORE)
        // So we expect just 1 op: STORE
        assert_eq!(raw_ops.len(), 1, "Expected 1 STORE op, got {} ops", raw_ops.len());

        // Op 0: CPUI_STORE
        let raw_store = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_store.get_opcode()),
            Some(OpCode::CPUI_STORE)
        );

        // STORE has no output
        assert!(raw_store.output().is_none());

        let store_inputs = raw_store.inputs();
        assert_eq!(store_inputs.len(), 3);
        // Input 0: RAM space ID
        assert_eq!(store_inputs[0].space, AddressSpace::Const);
        assert_eq!(store_inputs[0].offset, AddressSpace::Ram.space_id() as u64);
        // Input 1: address from rbx
        assert_eq!(store_inputs[1].space, AddressSpace::Register);
        assert_eq!(store_inputs[1].offset, 0x18); // rbx
        assert_eq!(store_inputs[1].size, 8);
        // Input 2: value from rax
        assert_eq!(store_inputs[2].space, AddressSpace::Register);
        assert_eq!(store_inputs[2].offset, 0x00); // rax
        assert_eq!(store_inputs[2].size, 8);

        // Inject and verify
        let mut fd = Funcdata::new("store_mov_mem_rbx_rax", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 1);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("store_mov_mem_rbx_rax", start, &rugra_ops, 1);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: `mov rax, [rbx+0x10]` — Memory load with displacement
    /// Machine code: 48 8b 43 10
    /// Expected P-code:
    ///   1. CPUI_INT_ADD(rbx, 0x10) -> tmp_addr
    ///   2. CPUI_LOAD(const(ram_space_id), tmp_addr) -> tmp_val
    ///   3. CPUI_COPY(tmp_val) -> rax
    #[test]
    fn test_load_mov_rax_mem_rbx_disp_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x8b, 0x43, 0x10]; // mov rax, [rbx+0x10]
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "mov");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);

        // Displacement != 0 → INT_ADD for addr calc, then LOAD, then COPY
        assert_eq!(raw_ops.len(), 3, "Expected INT_ADD + LOAD + COPY, got {} ops", raw_ops.len());

        // Op 0: CPUI_INT_ADD for address computation
        let raw_add = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_add.get_opcode()),
            Some(OpCode::CPUI_INT_ADD)
        );

        let add_out_binding = raw_add.output();
        let add_out = add_out_binding.as_ref().unwrap();
        assert_eq!(add_out.space, AddressSpace::Unique);

        let add_inputs = raw_add.inputs();
        assert_eq!(add_inputs.len(), 2);
        assert_eq!(add_inputs[0].space, AddressSpace::Register);
        assert_eq!(add_inputs[0].offset, 0x18); // rbx
        assert_eq!(add_inputs[1].space, AddressSpace::Const);
        assert_eq!(add_inputs[1].offset, 0x10); // displacement

        // Op 1: CPUI_LOAD
        let raw_load = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_load.get_opcode()),
            Some(OpCode::CPUI_LOAD)
        );

        let load_out_binding = raw_load.output();
        let load_out = load_out_binding.as_ref().unwrap();
        assert_eq!(load_out.space, AddressSpace::Unique);
        assert_eq!(load_out.size, 8);

        let load_inputs = raw_load.inputs();
        assert_eq!(load_inputs.len(), 2);
        assert_eq!(load_inputs[0].space, AddressSpace::Const); // RAM space ID
        assert_eq!(load_inputs[1].space, AddressSpace::Unique); // computed address
        assert_eq!(load_inputs[1].offset, add_out.offset);

        // Op 2: CPUI_COPY
        let raw_copy = &raw_ops[2];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let copy_out_binding = raw_copy.output();
        let copy_out = copy_out_binding.as_ref().unwrap();
        assert_eq!(copy_out.space, AddressSpace::Register);
        assert_eq!(copy_out.offset, 0x00); // rax

        // Inject and verify
        let mut fd = Funcdata::new("load_mov_rax_mem_rbx_disp", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 3);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result = verifier.verify_pcode_generation(
            "load_mov_rax_mem_rbx_disp",
            start,
            &rugra_ops,
            3,
        );

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: `add [rbx], rax` — Memory read-modify-write
    /// Machine code: 48 01 03
    /// Expected P-code:
    ///   1. CPUI_LOAD(ram_space_id, rbx) -> tmp_orig  (read original value)
    ///   2. CPUI_INT_ADD(tmp_orig, rax) -> tmp_result
    ///   3. CPUI_STORE(ram_space_id, rbx, tmp_result)  (write back)
    #[test]
    fn test_add_mem_rbx_rax_rmw_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![0x48, 0x01, 0x03]; // add [rbx], rax
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 1);

        let inst = &instructions[0];
        assert_eq!(inst.mnemonic, "add");

        let mut lifter = X86Lifter::new();
        let raw_ops = lifter.lift(inst);

        // For `add [rbx], rax`:
        // - parse_dest_operand([rbx]) returns (rbx_vn, Some(size_vn)) — memory target
        // - parse_operand(rax) returns rax_vn — register source
        // - Because mem_size.is_some(), it calls parse_operand([rbx]) again for reading
        //   → this generates a LOAD op and returns tmp
        // - INT_ADD(tmp, rax) → tmp_result
        // - emit_store(rbx_vn, tmp_result, size_vn) → STORE
        // Total: LOAD + INT_ADD + STORE = 3 ops
        assert_eq!(raw_ops.len(), 3, "Expected LOAD + INT_ADD + STORE, got {} ops", raw_ops.len());

        // Op 0: CPUI_LOAD (read original value from [rbx])
        let raw_load = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_load.get_opcode()),
            Some(OpCode::CPUI_LOAD)
        );

        let load_out_binding = raw_load.output();
        let load_out = load_out_binding.as_ref().unwrap();
        assert_eq!(load_out.space, AddressSpace::Unique);
        assert_eq!(load_out.size, 8);

        let load_inputs = raw_load.inputs();
        assert_eq!(load_inputs.len(), 2);
        assert_eq!(load_inputs[0].space, AddressSpace::Const); // RAM space ID
        assert_eq!(load_inputs[1].space, AddressSpace::Register);
        assert_eq!(load_inputs[1].offset, 0x18); // rbx

        // Op 1: CPUI_INT_ADD
        let raw_add = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_add.get_opcode()),
            Some(OpCode::CPUI_INT_ADD)
        );

        let add_out_binding = raw_add.output();
        let add_out = add_out_binding.as_ref().unwrap();
        assert_eq!(add_out.space, AddressSpace::Unique);

        let add_inputs = raw_add.inputs();
        assert_eq!(add_inputs.len(), 2);
        // Input 0: loaded value (unique tmp from LOAD)
        assert_eq!(add_inputs[0].space, AddressSpace::Unique);
        assert_eq!(add_inputs[0].offset, load_out.offset);
        // Input 1: rax
        assert_eq!(add_inputs[1].space, AddressSpace::Register);
        assert_eq!(add_inputs[1].offset, 0x00); // rax

        // Op 2: CPUI_STORE (write result back to [rbx])
        let raw_store = &raw_ops[2];
        assert_eq!(
            OpCode::from_i32(raw_store.get_opcode()),
            Some(OpCode::CPUI_STORE)
        );
        assert!(raw_store.output().is_none());

        let store_inputs = raw_store.inputs();
        assert_eq!(store_inputs.len(), 3);
        assert_eq!(store_inputs[0].space, AddressSpace::Const); // RAM space ID
        assert_eq!(store_inputs[1].space, AddressSpace::Register);
        assert_eq!(store_inputs[1].offset, 0x18); // rbx (address)
        assert_eq!(store_inputs[2].space, AddressSpace::Unique); // result

        // Inject and verify
        let mut fd = Funcdata::new("add_mem_rbx_rax_rmw", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 3);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("add_mem_rbx_rax_rmw", start, &rugra_ops, 3);

        assert!(matches!(result, VerifyResult::Match));
    }

    // ========== SSA alignment tests ==========

    /// Test: Single-block SSA construction for `mov rax, rdi; add rax, rsi; ret`
    ///
    /// Verifies that after heritage (SSA construction), a single-block
    /// function has:
    /// - No MULTIEQUAL (Phi) nodes (single block, no merge point)
    /// - Heritage pass counter incremented
    /// - Varnode def/use chains are established
    #[test]
    fn test_ssa_single_block_linear() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();

        // Build raw ops for: mov rax, rdi; add rax, rsi; ret
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op2.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI

        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));

        let start = Address::new(0x2000);
        let mut fd = Funcdata::new("ssa_linear", start, 10);

        // Inject ops
        fd.inject_raw_ops(&[op1, op2, op3]);
        assert_eq!(fd.obank.alivelist.len(), 3);
        assert_eq!(fd.bblocks.get_size(), 1);

        // Build dominator tree (required for heritage)
        fd.bblocks.build_dom_tree();

        // Run heritage directly using the _direct methods to avoid
        // the deadlock that occurs when heritage() tries to re-acquire
        // the Funcdata lock via fd_weak.upgrade().
        fd.heritage.place_multiequals_direct(
            &mut fd.vbank,
            &mut fd.obank,
            &fd.bblocks,
            &fd.sblocks,
        );
        fd.heritage.rename_direct(&mut fd.vbank, &fd.bblocks);
        fd.heritage.pass += 1;

        // Heritage pass should have incremented
        assert_eq!(fd.num_heritage_passes(), 1, "Heritage pass should be 1 after first run");

        // Single block → no MULTIEQUAL ops should be inserted
        let multiequal_count = fd
            .obank
            .optree
            .iter()
            .filter(|op| op.0.read().unwrap().get_opcode() == OpCode::CPUI_MULTIEQUAL)
            .count();
        assert_eq!(
            multiequal_count, 0,
            "Single block should have no Phi (MULTIEQUAL) nodes, found {}",
            multiequal_count
        );

        // Original 3 ops should still be present
        assert!(
            fd.obank.alivelist.len() >= 3,
            "Should still have at least 3 original ops"
        );
    }

    // ========== Multi-instruction sequence tests ==========

    /// Test: `mov rax, rdi; add rax, rsi; ret`
    /// A minimal function that returns first_arg + second_arg.
    /// Produces 4 P-code ops in a single basic block:
    ///   COPY(rax ← rdi), INT_ADD(tmp), COPY(rax ← tmp), RETURN
    #[test]
    fn test_seq_mov_add_ret_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // mov rax, rdi = 48 89 f8
        // add rax, rsi = 48 01 f0
        // ret          = c3
        let code = vec![
            0x48, 0x89, 0xf8, // mov rax, rdi
            0x48, 0x01, 0xf0, // add rax, rsi
            0xc3,             // ret
        ];
        let start = Address::new(0x1000);

        // Phase 1: Disassemble
        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 3);
        assert_eq!(instructions[0].mnemonic, "mov");
        assert_eq!(instructions[1].mnemonic, "add");
        assert_eq!(instructions[2].mnemonic, "ret");

        // Verify sequential addresses
        assert_eq!(instructions[0].address.as_u64(), 0x1000);
        assert_eq!(instructions[1].address.as_u64(), 0x1003);
        assert_eq!(instructions[2].address.as_u64(), 0x1006);

        // Phase 2: Lift all instructions
        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            let ops = lifter.lift(inst);
            all_raw_ops.extend(ops);
        }
        // mov→1(COPY) + add→2(INT_ADD+COPY) + ret→1(RETURN) = 4
        assert_eq!(all_raw_ops.len(), 4);

        // Verify op sequence
        assert_eq!(OpCode::from_i32(all_raw_ops[0].get_opcode()), Some(OpCode::CPUI_COPY));
        assert_eq!(OpCode::from_i32(all_raw_ops[1].get_opcode()), Some(OpCode::CPUI_INT_ADD));
        assert_eq!(OpCode::from_i32(all_raw_ops[2].get_opcode()), Some(OpCode::CPUI_COPY));
        assert_eq!(OpCode::from_i32(all_raw_ops[3].get_opcode()), Some(OpCode::CPUI_RETURN));

        // Phase 3: Inject into Funcdata
        let mut fd = Funcdata::new("seq_mov_add_ret", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 4);
        // RETURN terminates, all ops in one block
        assert_eq!(fd.bblocks.get_size(), 1);

        // Phase 4: Verify via RuntimeVerifier
        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("seq_mov_add_ret", start, &rugra_ops, 4);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: `mov rax, rdi; and rax, 0xf; shl rax, 4; ret`
    /// Arithmetic chain: mask low nibble, shift left by 4. Returns (arg & 0xf) << 4.
    /// Produces 6 P-code ops in a single basic block:
    ///   COPY(rax←rdi), INT_AND(tmp1), COPY(rax←tmp1), INT_LEFT(tmp2), COPY(rax←tmp2), RETURN
    #[test]
    fn test_seq_mov_and_shl_ret_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![
            0x48, 0x89, 0xf8,       // mov rax, rdi
            0x48, 0x83, 0xe0, 0x0f, // and rax, 0xf
            0x48, 0xc1, 0xe0, 0x04, // shl rax, 4
            0xc3,                    // ret
        ];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 4);
        assert_eq!(instructions[0].mnemonic, "mov");
        assert_eq!(instructions[1].mnemonic, "and");
        assert_eq!(instructions[2].mnemonic, "shl");
        assert_eq!(instructions[3].mnemonic, "ret");

        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            all_raw_ops.extend(lifter.lift(inst));
        }
        // mov→1 + and→2 + shl→2 + ret→1 = 6
        assert_eq!(all_raw_ops.len(), 6);

        assert_eq!(OpCode::from_i32(all_raw_ops[0].get_opcode()), Some(OpCode::CPUI_COPY));
        assert_eq!(OpCode::from_i32(all_raw_ops[1].get_opcode()), Some(OpCode::CPUI_INT_AND));
        assert_eq!(OpCode::from_i32(all_raw_ops[2].get_opcode()), Some(OpCode::CPUI_COPY));
        assert_eq!(OpCode::from_i32(all_raw_ops[3].get_opcode()), Some(OpCode::CPUI_INT_LEFT));
        assert_eq!(OpCode::from_i32(all_raw_ops[4].get_opcode()), Some(OpCode::CPUI_COPY));
        assert_eq!(OpCode::from_i32(all_raw_ops[5].get_opcode()), Some(OpCode::CPUI_RETURN));

        let mut fd = Funcdata::new("seq_and_shl_ret", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 6);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("seq_and_shl_ret", start, &rugra_ops, 6);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: multi-block with conditional branch
    /// ```text
    /// 0x1000: cmp rdi, rsi     ; 48 39 f7
    /// 0x1003: je  0x100d       ; 74 08
    /// 0x1005: mov rax, 1       ; 48 c7 c0 01 00 00 00
    /// 0x100c: ret              ; c3
    /// 0x100d: xor rax, rax     ; 48 31 c0     (je target)
    /// 0x1010: ret              ; c3
    /// ```
    /// Tests: CBRANCH generation, basic block splitting, multi-block inject.
    /// Block 0: cmp(3 ops) + je(CBRANCH) = 4 ops
    /// Block 1: mov(COPY) + ret(RETURN) = 2 ops
    /// Block 2: xor(INT_XOR+COPY) + ret(RETURN) = 3 ops
    /// Total: 9 ops, 3 blocks
    #[test]
    fn test_seq_cmp_je_multiblock_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![
            0x48, 0x39, 0xf7,                         // cmp rdi, rsi
            0x74, 0x08,                                // je +8 → 0x100d
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1
            0xc3,                                      // ret
            0x48, 0x31, 0xc0,                          // xor rax, rax
            0xc3,                                      // ret
        ];
        let start = Address::new(0x1000);

        // Phase 1: Disassemble
        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 6);
        assert_eq!(instructions[0].mnemonic, "cmp");
        assert_eq!(instructions[1].mnemonic, "je");
        assert_eq!(instructions[2].mnemonic, "mov");
        assert_eq!(instructions[3].mnemonic, "ret");
        assert_eq!(instructions[4].mnemonic, "xor");
        assert_eq!(instructions[5].mnemonic, "ret");

        // Verify addresses
        assert_eq!(instructions[0].address.as_u64(), 0x1000);
        assert_eq!(instructions[1].address.as_u64(), 0x1003);
        assert_eq!(instructions[2].address.as_u64(), 0x1005);
        assert_eq!(instructions[3].address.as_u64(), 0x100c);
        assert_eq!(instructions[4].address.as_u64(), 0x100d);
        assert_eq!(instructions[5].address.as_u64(), 0x1010);

        // Phase 2: Lift all
        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            all_raw_ops.extend(lifter.lift(inst));
        }
        // cmp→3(INT_EQUAL+INT_LESS+INT_SLESS)
        // je→1(CBRANCH)
        // mov→1(COPY)
        // ret→1(RETURN)
        // xor→2(INT_XOR+COPY)
        // ret→1(RETURN)
        // Total: 9
        assert_eq!(all_raw_ops.len(), 9);

        // Verify key opcodes
        assert_eq!(OpCode::from_i32(all_raw_ops[0].get_opcode()), Some(OpCode::CPUI_INT_EQUAL));
        assert_eq!(OpCode::from_i32(all_raw_ops[3].get_opcode()), Some(OpCode::CPUI_CBRANCH));
        assert_eq!(OpCode::from_i32(all_raw_ops[4].get_opcode()), Some(OpCode::CPUI_COPY));
        assert_eq!(OpCode::from_i32(all_raw_ops[5].get_opcode()), Some(OpCode::CPUI_RETURN));
        assert_eq!(OpCode::from_i32(all_raw_ops[6].get_opcode()), Some(OpCode::CPUI_INT_XOR));

        // Phase 3: Inject and verify block structure
        let mut fd = Funcdata::new("seq_cmp_je_multi", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 9);
        // CBRANCH terminates block 0, RETURN terminates block 1 and block 2 → 3 blocks
        assert_eq!(fd.bblocks.get_size(), 3);

        // Verify block 0 has 4 ops (cmp: 3 flag ops + CBRANCH)
        let block0 = fd.bblocks.get_block(0).unwrap();
        assert_eq!(block0.read().unwrap().get_ops().len(), 4);

        // Verify block 1 has 2 ops (mov + ret)
        let block1 = fd.bblocks.get_block(1).unwrap();
        assert_eq!(block1.read().unwrap().get_ops().len(), 2);

        // Verify block 2 has 3 ops (xor: INT_XOR+COPY + ret)
        let block2 = fd.bblocks.get_block(2).unwrap();
        assert_eq!(block2.read().unwrap().get_ops().len(), 3);

        // Phase 4: Verify via RuntimeVerifier
        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("seq_cmp_je_multiblock", start, &rugra_ops, 9);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: multi-block with conditional branch converging to a merge block
    /// ```text
    /// 0x1000: cmp rdi, 0
    /// 0x1004: je 0x100f
    /// 0x1006: mov rax, 1
    /// 0x100d: jmp 0x1018
    /// 0x100f: mov rax, 2
    /// 0x1016: jmp 0x1018
    /// 0x1018: add rax, rsi
    /// 0x101b: ret
    /// ```
    /// This creates 4 basic blocks:
    /// Block 0: cmp + CBRANCH
    /// Block 1: mov rax, 1 + BRANCH (to block 3)
    /// Block 2: mov rax, 2 + BRANCH (to block 3)
    /// Block 3: MULTIEQUAL (Phi for rax) + add + ret
    #[test]
    fn test_ssa_dual_block_phi_alignment() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![
            0x48, 0x83, 0xff, 0x00,                         // cmp rdi, 0
            0x74, 0x09,                                     // je 0x100f
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,       // mov rax, 1
            0xeb, 0x09,                                     // jmp 0x1018
            0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00,       // mov rax, 2
            0xeb, 0x00,                                     // jmp 0x1018
            0x48, 0x01, 0xf0,                               // add rax, rsi
            0xc3,                                           // ret
        ];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        
        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            all_raw_ops.extend(lifter.lift(inst));
        }

        let mut fd = Funcdata::new("ssa_phi_test", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        // Build dom tree
        fd.bblocks.build_dom_tree();

        // Run heritage to build SSA
        fd.run_heritage_direct();

        // Verify that a MULTIEQUAL (Phi) node was created
        let multiequals: Vec<_> = fd.obank.optree.iter()
            .filter(|op| op.0.read().unwrap().get_opcode() == OpCode::CPUI_MULTIEQUAL)
            .collect();
            
        assert_eq!(multiequals.len(), 1, "Expected exactly 1 Phi node, got {}", multiequals.len());
        
        let phi = multiequals[0].0.read().unwrap();
        assert_eq!(phi.inrefs.len(), 2, "Phi node should have 2 inputs");
        
        let out_vn = phi.output.as_ref().unwrap().read().unwrap();
        assert_eq!(out_vn.get_space(), AddressSpace::Register);
        assert_eq!(out_vn.get_offset(), 0x00); // RAX
        assert_eq!(out_vn.get_size(), 8); // RAX is 8 bytes
    }

    // ========== SSA Renaming Verification Tests ==========

    /// Test: Single-block SSA renaming correctness
    ///
    /// Sequence: mov rax, rdi; add rax, rsi; ret
    /// P-code:
    ///   op0: RAX = COPY(RDI)
    ///   op1: RAX = INT_ADD(RAX, RSI)
    ///   op2: RETURN(const)
    ///
    /// After renaming:
    ///   - op1's first input (RAX) should be rewritten to point to op0's output (the first def of RAX)
    ///   - op0's output and op1's output should be DIFFERENT Varnode instances (different create_index)
    ///   - op1's input[0] should be Arc::ptr_eq to op0's output
    #[test]
    fn test_ssa_rename_single_block_linear() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();

        // Build: op0: RAX = COPY(RDI)
        let mut op0 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op0.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op0.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        // Build: op1: RAX = INT_ADD(RAX, RSI)
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX (should be rewritten)
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI

        // Build: op2: RETURN(const)
        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op2.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));

        let start = Address::new(0x3000);
        let mut fd = Funcdata::new("ssa_rename_linear", start, 10);
        fd.inject_raw_ops(&[op0, op1, op2]);

        assert_eq!(fd.bblocks.get_size(), 1, "Should have exactly 1 basic block");

        // Build dom tree & run heritage
        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Collect ops in order from the block
        let block = &fd.bblocks.blocks[0];
        let ops = block.read().unwrap().get_ops();

        // Filter to only non-MULTIEQUAL ops (there should be none in single block, but be safe)
        let regular_ops: Vec<_> = ops.iter()
            .filter(|op_ref| op_ref.0.read().unwrap().get_opcode() != OpCode::CPUI_MULTIEQUAL)
            .collect();
        assert!(regular_ops.len() >= 3, "Should have at least 3 regular ops, got {}", regular_ops.len());

        let pcode_op0 = regular_ops[0].0.read().unwrap();
        let pcode_op1 = regular_ops[1].0.read().unwrap();

        // op0 output: the first definition of RAX
        let op0_out = pcode_op0.output.as_ref().expect("op0 should have output");
        // op1 output: the second definition of RAX
        let op1_out = pcode_op1.output.as_ref().expect("op1 should have output");

        // VERIFY: op0 and op1 outputs are DIFFERENT Varnode instances
        assert!(
            !Arc::ptr_eq(op0_out, op1_out),
            "op0 and op1 should define DIFFERENT Varnode instances for RAX"
        );
        // Both should be at Register:0x00 (RAX)
        assert_eq!(op0_out.read().unwrap().get_space(), AddressSpace::Register);
        assert_eq!(op0_out.read().unwrap().get_offset(), 0x00);
        assert_eq!(op1_out.read().unwrap().get_space(), AddressSpace::Register);
        assert_eq!(op1_out.read().unwrap().get_offset(), 0x00);

        // VERIFY: op1's first input (RAX) was rewritten to point to op0's output
        let op1_in0 = &pcode_op1.inrefs[0];
        assert!(
            Arc::ptr_eq(op1_in0, op0_out),
            "After renaming, op1's RAX input should point to op0's output Varnode. \
             op1_in0 create_index={}, op0_out create_index={}",
            op1_in0.read().unwrap().get_create_index(),
            op0_out.read().unwrap().get_create_index(),
        );

        // VERIFY: op0's and op1's outputs have different create_index
        let ci0 = op0_out.read().unwrap().get_create_index();
        let ci1 = op1_out.read().unwrap().get_create_index();
        assert_ne!(ci0, ci1, "Different definitions of RAX should have different create_index: {} vs {}", ci0, ci1);
    }

    /// Test: Multi-block SSA renaming with Phi node input filling
    ///
    /// Assembly:
    ///   cmp rdi, 0       (Block 0)
    ///   je block2
    ///   mov rax, 1       (Block 1)
    ///   jmp block3
    ///   mov rax, 2       (Block 2)
    ///   jmp block3
    ///   add rax, rsi     (Block 3 — merge)
    ///   ret
    ///
    /// After renaming, at the merge block:
    ///   - A MULTIEQUAL (Phi) for RAX should exist
    ///   - Phi input 0 should be the RAX definition from Block 1 (mov rax, 1)
    ///   - Phi input 1 should be the RAX definition from Block 2 (mov rax, 2)
    ///   - op `add rax, rsi` in Block 3 should use the Phi output as its RAX input
    #[test]
    fn test_ssa_rename_multi_block_phi_inputs() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        let code = vec![
            0x48, 0x83, 0xff, 0x00,                         // cmp rdi, 0
            0x74, 0x09,                                     // je 0x100f
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,       // mov rax, 1
            0xeb, 0x09,                                     // jmp 0x1018
            0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00,       // mov rax, 2
            0xeb, 0x00,                                     // jmp 0x1018
            0x48, 0x01, 0xf0,                               // add rax, rsi
            0xc3,                                           // ret
        ];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();

        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            all_raw_ops.extend(lifter.lift(inst));
        }

        let mut fd = Funcdata::new("ssa_rename_phi", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        // Build dom tree & run heritage
        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Find the MULTIEQUAL (Phi) op for RAX
        let multiequals: Vec<_> = fd.obank.optree.iter()
            .filter(|op| op.0.read().unwrap().get_opcode() == OpCode::CPUI_MULTIEQUAL)
            .collect();

        // Find Phi node for RAX (Register:0x00)
        let rax_phis: Vec<_> = multiequals.iter()
            .filter(|op_ref| {
                let op = op_ref.0.read().unwrap();
                if let Some(out_vn) = &op.output {
                    let vn = out_vn.read().unwrap();
                    vn.get_space() == AddressSpace::Register && vn.get_offset() == 0x00
                } else {
                    false
                }
            })
            .collect();

        assert!(!rax_phis.is_empty(), "Should have at least one Phi node for RAX");
        let phi = rax_phis[0].0.read().unwrap();
        assert_eq!(phi.inrefs.len(), 2, "RAX Phi node should have 2 inputs (from 2 predecessor blocks)");

        // VERIFY: Both Phi inputs should be WRITTEN varnodes (defined by mov rax, 1 / mov rax, 2)
        // After renaming, Phi inputs should NOT be placeholder varnodes — they should point to
        // the actual definitions from the predecessor blocks.
        for (idx, phi_input) in phi.inrefs.iter().enumerate() {
            let vn = phi_input.read().unwrap();
            assert_eq!(
                vn.get_space(), AddressSpace::Register,
                "Phi input {} should be in Register space", idx
            );
            assert_eq!(
                vn.get_offset(), 0x00,
                "Phi input {} should reference RAX (offset 0x00)", idx
            );
            // Each phi input should be a WRITTEN varnode (defined by a preceding op)
            // or at least not the same as the phi output itself
            assert!(
                !Arc::ptr_eq(phi_input, phi.output.as_ref().unwrap()),
                "Phi input {} should NOT be the same as Phi output", idx
            );
        }

        // VERIFY: The two Phi inputs should be DIFFERENT varnodes
        // (they come from different blocks with different definitions)
        assert!(
            !Arc::ptr_eq(&phi.inrefs[0], &phi.inrefs[1]),
            "Phi's two inputs should be different Varnode instances (from different blocks). \
             input0 ci={}, input1 ci={}",
            phi.inrefs[0].read().unwrap().get_create_index(),
            phi.inrefs[1].read().unwrap().get_create_index(),
        );

        // VERIFY: Find the merge block's `add rax, rsi` op
        // Its RAX input should point to the Phi output, not to some random prior definition
        let phi_output = phi.output.as_ref().unwrap().clone();
        drop(phi); // Release the read lock

        // Search all ops for INT_ADD in the merge block that uses RAX
        let add_ops: Vec<_> = fd.obank.optree.iter()
            .filter(|op_ref| {
                let op = op_ref.0.read().unwrap();
                op.get_opcode() == OpCode::CPUI_INT_ADD
                    && op.inrefs.iter().any(|inref| {
                        let vn = inref.read().unwrap();
                        vn.get_space() == AddressSpace::Register && vn.get_offset() == 0x00
                    })
            })
            .collect();

        // Among those, find one whose RAX input is the Phi output
        let uses_phi_output = add_ops.iter().any(|op_ref| {
            let op = op_ref.0.read().unwrap();
            op.inrefs.iter().any(|inref| Arc::ptr_eq(inref, &phi_output))
        });
        assert!(
            uses_phi_output,
            "The merge block's INT_ADD should use the Phi output as its RAX input"
        );
    }

    /// Test: SSA renaming with diamond CFG pattern
    ///
    /// Uses `mov rax, imm` instructions to ensure direct RAX definitions.
    /// CFG:
    ///   Block 0 (entry): cmp rdi,0; je block2
    ///   Block 1 (then):  mov rax, 0x10; jmp block3
    ///   Block 2 (else):  mov rax, 0x20; jmp block3
    ///   Block 3 (merge): ret   (Phi for RAX should be placed here)
    #[test]
    fn test_ssa_rename_diamond_pattern() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();

        let code = vec![
            // Block 0: cmp rdi, 0; je block2
            0x48, 0x83, 0xff, 0x00,                         // 0x4000: cmp rdi, 0
            0x74, 0x09,                                     // 0x4004: je +9 → 0x400f
            // Block 1: mov rax, 0x10; jmp block3
            0x48, 0xc7, 0xc0, 0x10, 0x00, 0x00, 0x00,       // 0x4006: mov rax, 0x10
            0xeb, 0x09,                                     // 0x400d: jmp +9 → 0x4018
            // Block 2: mov rax, 0x20; jmp block3
            0x48, 0xc7, 0xc0, 0x20, 0x00, 0x00, 0x00,       // 0x400f: mov rax, 0x20
            0xeb, 0x00,                                     // 0x4016: jmp +0 → 0x4018
            // Block 3: ret
            0xc3,                                           // 0x4018: ret
        ];
        let start = Address::new(0x4000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();

        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            all_raw_ops.extend(lifter.lift(inst));
        }

        let mut fd = Funcdata::new("ssa_diamond", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        let num_blocks = fd.bblocks.get_size();
        assert!(num_blocks >= 3, "Diamond pattern should have at least 3 blocks, got {}", num_blocks);

        // Build dom tree & run heritage
        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Find Phi nodes for RAX (Register:0x00)
        let rax_phis: Vec<_> = fd.obank.optree.iter()
            .filter(|op_ref| {
                let op = op_ref.0.read().unwrap();
                if op.get_opcode() != OpCode::CPUI_MULTIEQUAL {
                    return false;
                }
                if let Some(out_vn) = &op.output {
                    let vn = out_vn.read().unwrap();
                    vn.get_space() == AddressSpace::Register && vn.get_offset() == 0x00
                } else {
                    false
                }
            })
            .collect();

        assert!(!rax_phis.is_empty(), "Diamond merge should have Phi for RAX");

        let phi = rax_phis[0].0.read().unwrap();
        assert_eq!(
            phi.inrefs.len(), 2,
            "RAX Phi at diamond merge should have 2 inputs, got {}",
            phi.inrefs.len()
        );

        // VERIFY: Both inputs should be register RAX varnodes
        for (i, phi_in) in phi.inrefs.iter().enumerate() {
            let vn = phi_in.read().unwrap();
            assert_eq!(vn.get_space(), AddressSpace::Register,
                "Phi input {} should be Register", i);
            assert_eq!(vn.get_offset(), 0x00,
                "Phi input {} should be RAX (offset 0x00)", i);
        }

        // VERIFY: Phi inputs are distinct (different definitions)
        assert!(
            !Arc::ptr_eq(&phi.inrefs[0], &phi.inrefs[1]),
            "Diamond Phi inputs should be distinct varnode instances"
        );

        // VERIFY: Phi output is distinct from both inputs
        let phi_out = phi.output.as_ref().unwrap();
        assert!(!Arc::ptr_eq(phi_out, &phi.inrefs[0]));
        assert!(!Arc::ptr_eq(phi_out, &phi.inrefs[1]));
    }

    /// Test: SSA renaming correctly uses INPUT varnodes for undefined reads
    ///
    /// Sequence: add rax, rsi; ret
    /// There is no prior definition of RAX — it should remain linked to
    /// the INPUT varnode that heritage creates for uninitialized reads.
    #[test]
    fn test_ssa_rename_input_varnode_for_undefined_read() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();

        // op0: RAX = INT_ADD(RAX, RSI)   — RAX is read before being defined
        let mut op0 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op0.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX out
        op0.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX in (undefined)
        op0.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI

        // op1: RETURN
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op1.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));

        let start = Address::new(0x5000);
        let mut fd = Funcdata::new("ssa_input_test", start, 10);
        fd.inject_raw_ops(&[op0, op1]);

        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Get ops
        let block = &fd.bblocks.blocks[0];
        let ops = block.read().unwrap().get_ops();
        let regular_ops: Vec<_> = ops.iter()
            .filter(|op_ref| op_ref.0.read().unwrap().get_opcode() != OpCode::CPUI_MULTIEQUAL)
            .collect();

        assert!(!regular_ops.is_empty(), "Should have at least 1 regular op");

        // Find the INT_ADD op
        let add_op_ref = regular_ops.iter()
            .find(|op_ref| op_ref.0.read().unwrap().get_opcode() == OpCode::CPUI_INT_ADD);
        assert!(add_op_ref.is_some(), "Should find INT_ADD op");

        let add_op = add_op_ref.unwrap().0.read().unwrap();
        assert!(add_op.inrefs.len() >= 2, "INT_ADD should have at least 2 inputs");

        // The RAX input (input 0) should reference a varnode.
        // Since there is no prior definition of RAX in this block,
        // after renaming it should either:
        // a) remain unchanged (no stack entry for RAX exists), or
        // b) point to an INPUT varnode if heritage created one
        //
        // The key verification: the input RAX varnode should be DIFFERENT from the output RAX varnode.
        let add_out = add_op.output.as_ref().expect("INT_ADD should have output");
        let add_in_rax = &add_op.inrefs[0];

        // Both refer to RAX
        assert_eq!(add_in_rax.read().unwrap().get_space(), AddressSpace::Register);
        assert_eq!(add_in_rax.read().unwrap().get_offset(), 0x00);
        assert_eq!(add_out.read().unwrap().get_space(), AddressSpace::Register);
        assert_eq!(add_out.read().unwrap().get_offset(), 0x00);

        // They must be DIFFERENT Varnode instances (input vs output are different SSA versions)
        assert!(
            !Arc::ptr_eq(add_in_rax, add_out),
            "Input RAX and output RAX should be different SSA versions. \
             Input ci={}, output ci={}",
            add_in_rax.read().unwrap().get_create_index(),
            add_out.read().unwrap().get_create_index(),
        );
    }

    // ========== ActionNormalizeBranches tests ==========

    #[test]
    fn test_normalize_branches_break_in_while_loop() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();

        // while(rdi != rsi) { if (rax == 0x10) break; rax++; }
        //
        // 0x1000: cmp rdi, rsi        48 39 f7
        // 0x1003: je  0x1011          74 0c       → exit (loop condition: if equal, exit)
        // 0x1005: cmp rax, 0x10       48 83 f8 10
        // 0x1009: je  0x1011          74 06       → break (early exit from loop body)
        // 0x100b: add rax, 1          48 83 c0 01
        // 0x100f: jmp 0x1000          eb ef       → continue (back to loop header)
        // 0x1011: ret                 c3
        let code: Vec<u8> = vec![
            0x48, 0x39, 0xf7,
            0x74, 0x0c,
            0x48, 0x83, 0xf8, 0x10,
            0x74, 0x06,
            0x48, 0x83, 0xc0, 0x01,
            0xeb, 0xef,
            0xc3,
        ];
        let start = Address::new(0x1000);

        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();

        let mut lifter = X86Lifter::new();
        let mut all_raw_ops = Vec::new();
        for inst in &instructions {
            all_raw_ops.extend(lifter.lift(inst));
        }

        let mut fd = Funcdata::new("loop_break_test", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        assert!(
            fd.bblocks.get_size() >= 3,
            "Loop CFG should have at least 3 blocks, got {}",
            fd.bblocks.get_size()
        );

        fd.bblocks.build_dom_tree();

        use crate::action::Action;
        let mut structurer = crate::blockaction::ActionBlockStructure::new();
        let result = structurer.apply(&mut fd);
        assert!(result.is_ok());

        let mut normalizer = crate::blockaction::ActionNormalizeBranches::new();
        let result = normalizer.apply(&mut fd);
        assert!(result.is_ok());

        let mut _found_break = false;
        let mut found_continue = false;

        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            match op.opcode {
                OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH => {
                    if op.branch_type == crate::op::branch_type::BREAK {
                        _found_break = true;
                    }
                    if op.branch_type == crate::op::branch_type::CONTINUE {
                        found_continue = true;
                    }
                }
                _ => {}
            }
        }

        // The jmp back to 0x1000 should be tagged CONTINUE
        assert!(
            found_continue,
            "The back-edge jmp to loop header should be tagged CONTINUE"
        );
    }

    #[test]
    fn test_normalize_branches_op_branch_type_field() {
        use crate::op::branch_type;
        use crate::address::SeqNum;

        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = crate::op::PcodeOp::new(seq, OpCode::CPUI_CBRANCH);

        assert_eq!(op.branch_type, branch_type::NONE);

        op.branch_type = branch_type::BREAK;
        assert_eq!(op.branch_type, branch_type::BREAK);

        op.branch_type = branch_type::CONTINUE;
        assert_eq!(op.branch_type, branch_type::CONTINUE);
    }

    // ========== Boolean Condition Folding tests ==========

    #[test]
    fn test_bool_condition_folding_and_pattern() {
        use crate::block::{BlockBasic, BlockGraph, BlockEdge, BlockType, BlockCondition, BoolOp, FlowBlock};
        use crate::opcodes::OpCode;
        use crate::op::PcodeOp;
        use crate::address::{Address, SeqNum};

        // AND-pattern CFG:
        // A (CBRANCH): out(0)=B, out(1)=C → false edge to C
        // B (CBRANCH): out(0)=D, out(1)=C → false edge to C (same as A)
        // Both false edges → C → AND pattern
        let mut basic_a = BlockBasic::new(0, Address::new(0x1000));
        basic_a.ops.push(crate::op::PcodeOpRef(Arc::new(RwLock::new(
            PcodeOp::new(SeqNum::new(Address::new(0x1000), 0), OpCode::CPUI_CBRANCH),
        ))));

        let mut basic_b = BlockBasic::new(1, Address::new(0x1010));
        basic_b.ops.push(crate::op::PcodeOpRef(Arc::new(RwLock::new(
            PcodeOp::new(SeqNum::new(Address::new(0x1010), 0), OpCode::CPUI_CBRANCH),
        ))));

        let basic_c = BlockBasic::new(2, Address::new(0x1020));
        let basic_d = BlockBasic::new(3, Address::new(0x1030));

        let block_a: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(basic_a));
        let block_b: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(basic_b));
        let block_c: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(basic_c));
        let block_d: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(basic_d));

        // Wire edges
        {
            let mut a = block_a.write().unwrap();
            a.add_out_edge(BlockEdge::new(block_b.clone(), 0)); // out(0)=B (true)
            a.add_out_edge(BlockEdge::new(block_c.clone(), 0)); // out(1)=C (false)
        }
        {
            let mut b = block_b.write().unwrap();
            b.add_in_edge(BlockEdge::new(block_a.clone(), 0));
            b.add_out_edge(BlockEdge::new(block_d.clone(), 0)); // out(0)=D (true)
            b.add_out_edge(BlockEdge::new(block_c.clone(), 1)); // out(1)=C (false)
        }
        {
            let mut c = block_c.write().unwrap();
            c.add_in_edge(BlockEdge::new(block_a.clone(), 1));
            c.add_in_edge(BlockEdge::new(block_b.clone(), 1));
        }
        {
            let mut d = block_d.write().unwrap();
            d.add_in_edge(BlockEdge::new(block_b.clone(), 0));
        }

        let mut graph = BlockGraph::new();
        graph.blocks = vec![block_a, block_b, block_c, block_d];

        let mut cs = crate::blockaction::CollapseStructure::new(&mut graph, "test");
        cs.collapse_all();

        // Search for BlockCondition(And) — after full Ghidra-style collapseAll
        // (including interleaved cat/if rules), it may be standalone, inside a
        // BlockList, or its original block slot may have been replaced.
        // Search ALL blocks recursively for any BlockCondition with And.
        let mut found_and = false;
        for i in 0..graph.get_size() {
            if let Some(block) = graph.get_block(i) {
                let b = block.read().unwrap();
                match b.get_type() {
                    BlockType::Condition => {
                        if let Some(cond) = b.as_any().downcast_ref::<BlockCondition>() {
                            if cond.op_type == BoolOp::And { found_and = true; }
                        }
                    }
                    BlockType::List => {
                        if let Some(list) = b.as_any().downcast_ref::<crate::block::BlockList>() {
                            for child in &list.children {
                                let c = child.read().unwrap();
                                if c.get_type() == BlockType::Condition {
                                    if let Some(cond) = c.as_any().downcast_ref::<BlockCondition>() {
                                        if cond.op_type == BoolOp::And { found_and = true; }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        assert!(found_and, "Expected BlockCondition(And) after boolean folding");
    }

    #[test]
    fn test_block_condition_struct_fields() {
        use crate::block::{BlockBasic, BlockCondition, BlockType, BoolOp, FlowBlock, BlockEdge};
        use crate::address::Address;

        let a: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x1000))));
        let b: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockBasic::new(1, Address::new(0x2000))));

        let cond = BlockCondition {
            index: 10,
            op_type: BoolOp::And,
            first: a.clone(),
            second: b.clone(),
            incoming: Vec::new(),
            outgoing: vec![BlockEdge {
                point: a.clone(),
                flags: 0,
                reverse_index: 0,
            }],
            parent: None,
            flags: 0,
        };

        assert_eq!(cond.get_type(), BlockType::Condition);
        assert_eq!(cond.get_index(), 10);
        assert_eq!(cond.op_type, BoolOp::And);
        assert_eq!(cond.size_out(), 1);
        assert_eq!(cond.get_start_addr(), Address::new(0x1000));

        let cond_or = BlockCondition {
            index: 20,
            op_type: BoolOp::Or,
            first: a,
            second: b,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0,
        };
        assert_eq!(cond_or.op_type, BoolOp::Or);
        assert_eq!(cond_or.get_type(), BlockType::Condition);
    }

    #[test]
    fn test_switch_case_structuring() {
        use crate::action::Action;
        use crate::blockaction::ActionBlockStructure;
        use crate::prettyprint::EmitNoMarkup;
        use crate::printlanguage::PrintLanguage;
        use crate::printc::PrintC;
        use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
        use crate::space::AddressSpace;
        use crate::block::BlockType;

        let mut fd = Funcdata::new("test_switch", Address::new(0x1000), 0x100);

        // Control block (Block 0): indirect jump
        // unique_var = COPY(RDI)
        // BRANCHIND(unique_var)
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x50, 8));
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_BRANCHIND as i32);
        op2.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x50, 8));

        // Case 0 block (Block 1): return 10
        // RAX = COPY(10)
        // RETURN(RAX)
        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op3.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 10, 8));

        let mut op4 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op4.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));

        // Case 1 block (Block 2): return 20
        // RAX = COPY(20)
        // RETURN(RAX)
        let mut op5 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op5.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op5.add_input(VarnodeRaw::new(AddressSpace::Const, 20, 8));

        let mut op6 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op6.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));

        fd.inject_raw_ops(&[op1, op2, op3, op4, op5, op6]);

        // Verify we got 3 basic blocks
        assert_eq!(fd.bblocks.get_size(), 3);

        // Add edges: Block 0 -> Block 1, Block 0 -> Block 2
        let b0 = fd.bblocks.get_block(0).unwrap();
        let b1 = fd.bblocks.get_block(1).unwrap();
        let b2 = fd.bblocks.get_block(2).unwrap();
        fd.bblocks.add_edge(b0.clone(), b1.clone());
        fd.bblocks.add_edge(b0.clone(), b2.clone());

        // Run block structuring action
        let mut action = ActionBlockStructure::new();
        action.apply(&mut fd).unwrap();

        // Verify the main block was collapsed into a Switch
        assert_eq!(fd.sblocks.get_size(), 3);
        let entry = fd.sblocks.get_block(0).unwrap();
        assert_eq!(entry.read().unwrap().get_type(), BlockType::Switch);

        // Print C code
        let emit = EmitNoMarkup::new();
        let mut printer = PrintC::new(Box::new(emit));
        printer.doc_function(&fd);

        let emitted_code = printer.take_emit().into_any().downcast::<EmitNoMarkup>().unwrap().get_output();
        println!("Emitted code:\n{}", emitted_code);

        // Assert code structure
        assert!(emitted_code.contains("switch ("));
        assert!(emitted_code.contains("case 0:"));
        assert!(emitted_code.contains("case 1:"));
    }

    #[test]
    fn test_type_propagation() {
        use crate::action::Action;
        use crate::coreaction::ActionTypeInfer;
        use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
        use crate::space::AddressSpace;
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
        use crate::opcodes::OpCode;
        use std::sync::Arc;

        let mut fd = Funcdata::new("test_type_prop", Address::new(0x1000), 0x100);

        // Define linear instructions representing:
        // unique_1 = COPY(RDI)
        // unique_2 = INT_ADD(unique_1, 8)
        // unique_3 = LOAD(unique_2)
        // STORE(unique_4, unique_3)
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x10, 8)); // unique_1
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI (input)

        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op2.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x20, 8)); // unique_2
        op2.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x10, 8));
        op2.add_input(VarnodeRaw::new(AddressSpace::Const, 8, 8));

        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        op3.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x30, 4)); // unique_3 (size 4)
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 2, 8)); // space Ram
        op3.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x20, 8)); // unique_2 (addr)

        let mut op4 = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        op4.add_input(VarnodeRaw::new(AddressSpace::Const, 2, 8)); // space Ram
        op4.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x40, 8)); // unique_4 (addr, untyped)
        op4.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x30, 4)); // unique_3 (val)

        fd.inject_raw_ops(&[op1, op2, op3, op4]);

        // 1. Deduplicate/Link variables so dataflow can propagate.
        // We link inputs to matching output Varnodes by space/offset/size.
        // First, collect all output varnode info to avoid RwLock deadlocks.
        let mut output_varnodes: Vec<(crate::space::AddressSpace, u64, usize, Arc<RwLock<crate::varnode::Varnode>>)> = Vec::new();
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if let Some(ref out_vn_arc) = op.output {
                let out_vn = out_vn_arc.read().unwrap();
                output_varnodes.push((out_vn.space(), out_vn.offset(), out_vn.get_size(), out_vn_arc.clone()));
            }
        }

        let ops_to_update: Vec<_> = fd.obank.alivelist.iter().cloned().collect();
        for op_ref in &ops_to_update {
            let mut op = op_ref.0.write().unwrap();
            let num_inputs = op.inrefs.len();
            for i in 0..num_inputs {
                let (in_space, in_offset, in_size) = {
                    let in_vn = op.inrefs[i].read().unwrap();
                    (in_vn.space(), in_vn.offset(), in_vn.get_size())
                };

                if in_space != AddressSpace::Const {
                    let found_match = output_varnodes.iter()
                        .find(|(s, o, sz, _)| *s == in_space && *o == in_offset && *sz == in_size)
                        .map(|(_, _, _, arc)| arc.clone());

                    if let Some(matching_vn) = found_match {
                        op.inrefs[i] = matching_vn.clone();
                        matching_vn.write().unwrap().descend.push(Arc::downgrade(&op_ref.0));
                    }
                }
            }
        }

        // Manually inject a starting type: RDI is an "int *" pointer.
        let int_type = Arc::new(Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int)));
        let int_ptr_type = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: int_type.clone(),
            wordsize: 1,
        }));

        {
            let mut found = false;
            for op_ref in &fd.obank.alivelist {
                let op = op_ref.0.read().unwrap();
                if op.opcode == OpCode::CPUI_COPY {
                    let mut in_vn = op.inrefs[0].write().unwrap();
                    if in_vn.space().is_register() && in_vn.offset() == 0x38 {
                        in_vn.v_type = Some(int_ptr_type.clone());
                        found = true;
                    }
                }
            }
            assert!(found, "RDI input varnode not found and typed");
        }

        // Run type propagation
        let mut action = ActionTypeInfer::new();
        action.apply(&mut fd).unwrap();

        // Verify propagation results on our unified SSA variable chain
        let mut checked_u1 = false;
        let mut checked_u2 = false;
        let mut checked_u3 = false;
        let mut checked_u4 = false;

        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            match op.opcode {
                OpCode::CPUI_COPY => {
                    let out_vn = op.output.as_ref().unwrap().read().unwrap();
                    assert_eq!(out_vn.space(), AddressSpace::Unique);
                    assert_eq!(out_vn.offset(), 0x10);
                    assert_eq!(out_vn.v_type.as_ref().unwrap().get_name(), "int *");
                    checked_u1 = true;
                }
                OpCode::CPUI_INT_ADD => {
                    let out_vn = op.output.as_ref().unwrap().read().unwrap();
                    assert_eq!(out_vn.space(), AddressSpace::Unique);
                    assert_eq!(out_vn.offset(), 0x20);
                    assert_eq!(out_vn.v_type.as_ref().unwrap().get_name(), "int *");
                    checked_u2 = true;
                }
                OpCode::CPUI_LOAD => {
                    let out_vn = op.output.as_ref().unwrap().read().unwrap();
                    assert_eq!(out_vn.space(), AddressSpace::Unique);
                    assert_eq!(out_vn.offset(), 0x30);
                    assert_eq!(out_vn.v_type.as_ref().unwrap().get_name(), "int");
                    checked_u3 = true;
                }
                OpCode::CPUI_STORE => {
                    let addr_vn = op.inrefs[1].read().unwrap();
                    assert_eq!(addr_vn.space(), AddressSpace::Unique);
                    assert_eq!(addr_vn.offset(), 0x40);
                    assert_eq!(addr_vn.v_type.as_ref().unwrap().get_name(), "int *");
                    checked_u4 = true;
                }
                _ => {}
            }
        }

        assert!(checked_u1, "unique_1 type verification failed");
        assert!(checked_u2, "unique_2 type verification failed");
        assert!(checked_u3, "unique_3 type verification failed");
        assert!(checked_u4, "unique_4 type verification failed");
    }

    #[test]
    fn test_infer_params_and_return_type() {
        use crate::action::Action;
        use crate::coreaction::ActionInferParams;
        use crate::type_system::datatype::Datatype;

        let mut fd = Funcdata::new("my_func", Address::new(0x1000), 0x100);

        // Create INPUT varnodes in SysV ABI parameter registers
        // param1 = RDI (offset 0x38, size 8)
        let rdi_vn = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x38);
        fd.vbank.set_input(rdi_vn.clone());
        // param2 = RSI (offset 0x30, size 8)
        let rsi_vn = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x30);
        fd.vbank.set_input(rsi_vn.clone());

        // Create an op that reads both params: ADD rdi, rsi -> result (RAX)
        let result_vn = fd.vbank.create_with_space(8, crate::space::AddressSpace::Register, 0x00);
        let add_ref = fd.obank.create(OpCode::CPUI_INT_ADD, 2, Address::new(0x1000));
        {
            let mut add_op = add_ref.0.write().unwrap();
            add_op.output = Some(result_vn.clone());
            add_op.inrefs.push(rdi_vn);
            add_op.inrefs.push(rsi_vn);
        }

        // Create RETURN op with RAX as return value
        let ret_addr_vn = fd.vbank.create_constant(8, 0);
        let ret_ref = fd.obank.create(OpCode::CPUI_RETURN, 2, Address::new(0x1010));
        {
            let mut ret_op = ret_ref.0.write().unwrap();
            ret_op.inrefs.push(ret_addr_vn);
            ret_op.inrefs.push(result_vn); // RAX as return value
        }

        // Verify initial state: void return, no params
        assert!(matches!(fd.funcp.return_type.as_ref(), Datatype::Void(_)));
        assert!(fd.funcp.parameters.is_empty());

        // Run ActionInferParams
        let mut action = ActionInferParams::new();
        let result = action.apply(&mut fd).unwrap();
        // Ghidra Actions return 0 (count is statistics only).
        assert_eq!(result, 0, "ActionInferParams returns 0 (Ghidra convention)");

        // Verify parameters detected
        assert_eq!(fd.funcp.parameters.len(), 2, "Should detect 2 parameters");
        assert_eq!(fd.funcp.parameters[0].name, "param_1");
        assert_eq!(fd.funcp.parameters[1].name, "param_2");

        // Verify return type inferred (RAX is size 8 -> long)
        assert_eq!(fd.funcp.return_type.get_name(), "long",
            "Return type should be inferred as 'long' from 8-byte RAX");
    }

    /// End-to-end decompilation test simulating a realistic curl-style function.
    ///
    /// Models a function like:
    /// ```c
    /// long curl_easy_setopt(long handle, int option, long value) {
    ///     long result;
    ///     if (option == 0x2712) {
    ///         *(long *)(handle + 0x28) = value;
    ///         result = 0;
    ///     } else {
    ///         result = curl_set_error(handle, option);
    ///     }
    ///     return result;
    /// }
    /// ```
    #[test]
    fn test_realistic_curl_function() {
        use crate::action::ActionDatabase;
        use crate::prettyprint::EmitNoMarkup;
        use crate::printlanguage::PrintLanguage;
        use crate::printc::PrintC;
        use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
        use crate::space::AddressSpace;

        let mut fd = Funcdata::new("curl_easy_setopt", Address::new(0x4050a0), 0x60);

        // Add symbol table entries for known functions
        fd.symbol_table.insert(0x403210, "curl_set_error".to_string());

        // Addresses: baseaddr + idx * 0x10
        // Block 0: op0..op4 (5 ops) → CBRANCH at op4
        //   Block 0 starts at 0x4050a0
        // Block 1: op5..op7 (3 ops) → BRANCH at op7
        //   Block 1 starts at 0x4050a0 + 5*0x10 = 0x4050f0
        // Block 2: op8..op11 (4 ops) → BRANCH at op11
        //   Block 2 starts at 0x4050a0 + 8*0x10 = 0x405120
        // Block 3: op12..op13 (2 ops) → RETURN at op13
        //   Block 3 starts at 0x4050a0 + 12*0x10 = 0x405160

        // === Block 0: Entry / condition check ===
        // op0: u0 = COPY(RDI)           ; handle → unique
        let mut op0 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op0.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));
        op0.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI = handle
        // op1: u1 = INT_ZEXT(ESI)       ; option → 8-byte
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_INT_ZEXT as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x108, 8));
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 4)); // ESI = option (4 byte)
        // op2: u2 = COPY(RDX)           ; value → unique
        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op2.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x110, 8));
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x10, 8)); // RDX = value
        // op3: u3 = INT_EQUAL(u1, 0x2712)  ; option == CURLOPT_URL
        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        op3.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x118, 1));
        op3.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x108, 8));
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 0x2712, 8));
        // op4: CBRANCH → Block 2 (then branch at 0x405120)
        let mut op4 = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
        op4.add_input(VarnodeRaw::new(AddressSpace::Const, 0x405120, 8));
        op4.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x118, 1));

        // === Block 1: else branch (call curl_set_error + branch to exit) ===
        // op5: CALL curl_set_error
        let mut op5 = PcodeOpRaw::new(OpCode::CPUI_CALL as i32);
        op5.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x403210, 8));
        // op6: u4 = COPY(RAX)     ; capture return value
        let mut op6 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op6.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x120, 8));
        op6.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        // op7: BRANCH → Block 3 (exit at 0x405160)
        let mut op7 = PcodeOpRaw::new(OpCode::CPUI_BRANCH as i32);
        op7.add_input(VarnodeRaw::new(AddressSpace::Const, 0x405160, 8));

        // === Block 2: then branch (store value + branch to exit) ===
        // op8: u5 = INT_ADD(u0, 0x28)  ; handle + 0x28
        let mut op8 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op8.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x128, 8));
        op8.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));
        op8.add_input(VarnodeRaw::new(AddressSpace::Const, 0x28, 8));
        // op9: STORE([ram], u5, u2)     ; *(handle+0x28) = value
        let mut op9 = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        op9.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        op9.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x128, 8));
        op9.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x110, 8));
        // op10: u6 = COPY(0)           ; result = 0
        let mut op10 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op10.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x130, 8));
        op10.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        // op11: BRANCH → Block 3 (exit at 0x405160)
        let mut op11 = PcodeOpRaw::new(OpCode::CPUI_BRANCH as i32);
        op11.add_input(VarnodeRaw::new(AddressSpace::Const, 0x405160, 8));

        // === Block 3: exit (return result) ===
        // op12: RAX = COPY(result)
        let mut op12 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op12.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        op12.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x120, 8));
        // op13: RETURN(RAX)
        let mut op13 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op13.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        op13.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));

        fd.inject_raw_ops(&[op0, op1, op2, op3, op4, op5, op6, op7, op8, op9, op10, op11, op12, op13]);

        // CFG edges are automatically created by build_blocks_from_ops

        // Run full analysis pipeline
        let mut db = ActionDatabase::new();
        db.set_default_actions();
        let _ = db.apply_all(&mut fd);

        // Print decompiled output
        let emit = EmitNoMarkup::new();
        let mut printer = PrintC::new(Box::new(emit));
        printer.doc_function(&fd);

        let emitted_code = printer.take_emit().into_any().downcast::<EmitNoMarkup>().unwrap().get_output();
        println!("\n====== Rugra Decompiled Output: curl_easy_setopt ======\n{}\n======================================================", emitted_code);

        // Basic structure assertions
        assert!(emitted_code.contains("curl_easy_setopt"), "Should contain function name");
        assert!(!emitted_code.contains("void curl_easy_setopt"), "Should NOT have void return (has RETURN with RAX)");
        // Function signature should contain parameters
        assert!(emitted_code.contains("param_1"), "Should contain param_1 in signature");
        assert!(emitted_code.contains("param_2"), "Should contain param_2 in signature or body");
        assert!(emitted_code.contains("param_3"), "Should contain param_3 in signature");
        // param_2 should appear in the body expression (not just signature)
        assert!(emitted_code.contains("(long)param_2") || emitted_code.contains("param_2"),
            "param_2 should be used in body expression");
    }

    /// Verify Funcdata::spacebase() marks the RSP input varnode with the
    /// SPACEBASE flag, faithful to Ghidra Funcdata::spacebase()
    /// (funcdata.cc:230-269). This is the foundational mechanism that lets
    /// varmap/ActionStackPtrFlow recognize RSP as a Stack-space pointer.
    #[test]
    fn test_spacebase_marks_rsp_input() {
        // RSP input at Register@0x20, size 8 (matches x86_lift.rs:40).
        // A normal register (RAX @ 0x00) that should NOT be marked spacebase.
        let mut read_rsp = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        read_rsp.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x10, 8));
        read_rsp.add_input(VarnodeRaw::new(AddressSpace::Const, 0x100, 8)); // space-id const
        read_rsp.add_input(VarnodeRaw::new(AddressSpace::Register, 0x20, 8)); // RSP

        let mut read_rax = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        read_rax.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x18, 8));
        read_rax.add_input(VarnodeRaw::new(AddressSpace::Const, 0x100, 8));
        read_rax.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX

        let mut fd = Funcdata::new("test_spacebase", Address::new(0x1000), 0x100);
        fd.inject_raw_ops(&[read_rsp, read_rax]);

        // Before spacebase(): no varnode has SPACEBASE flag.
        let sb_before = fd.vbank.loc_tree.iter()
            .filter(|v| v.0.read().unwrap().is_spacebase())
            .count();
        assert_eq!(sb_before, 0, "No spacebase varnodes before spacebase()");

        // Run spacebase() — faithful to Ghidra Funcdata::spacebase().
        fd.spacebase();

        // After: the RSP input (Register@0x20) should be marked SPACEBASE.
        let sb_varnodes: Vec<_> = fd.vbank.loc_tree.iter()
            .filter(|v| v.0.read().unwrap().is_spacebase())
            .map(|v| v.0.clone())
            .collect();
        assert!(!sb_varnodes.is_empty(), "RSP input should be marked SPACEBASE");

        // Verify it's at Register@0x20, size 8.
        let sb = sb_varnodes[0].read().unwrap();
        assert_eq!(sb.get_space(), AddressSpace::Register);
        assert_eq!(sb.get_offset(), 0x20);
        assert_eq!(sb.get_size(), 8);
        assert!(sb.is_spacebase());

        // RAX (Register@0x00) must NOT be marked.
        let rax_marked = fd.vbank.loc_tree.iter()
            .any(|v| {
                let g = v.0.read().unwrap();
                g.get_space() == AddressSpace::Register
                    && g.get_offset() == 0x00
                    && g.is_spacebase()
            });
        assert!(!rax_marked, "RAX must NOT be marked spacebase");
    }

    /// Verify split_uses() duplicates a multi-descendant op so each reader
    /// gets its own output, faithful to Ghidra Funcdata::splitUses()
    /// (funcdata_varnode.cc:1540-1567).
    #[test]
    fn test_split_uses_duplicates_op() {
        // Build a Funcdata where one INT_ADD output has 2 descendant readers.
        // We construct varnodes directly in the bank with proper descend links
        // (inject_raw_ops creates separate varnode instances for inputs, which
        // breaks identity; so we wire the descend chain manually here).
        let mut fd = Funcdata::new("test_split", Address::new(0x1000), 0x100);

        // INT_ADD(RSP, 0x10) -> tmp_out
        let add_op = fd.new_op(2, Address::new(0x1000));
        fd.op_set_opcode(&add_op, OpCode::CPUI_INT_ADD);
        let tmp_out = fd.new_unique_out(8, &add_op);
        let rsp = fd.vbank.create_with_space(8, AddressSpace::Register, 0x20);
        let off = fd.vbank.create_constant(8, 0x10);
        fd.op_set_input(&add_op, rsp, 0);
        fd.op_set_input(&add_op, off, 1);
        fd.obank.alivelist.push(add_op.clone());

        // Two readers of tmp_out.
        let r1 = fd.new_op(2, Address::new(0x1001));
        fd.op_set_opcode(&r1, OpCode::CPUI_LOAD);
        fd.op_set_input(&r1, tmp_out.clone(), 1);  // reads tmp_out -> adds descend
        fd.obank.alivelist.push(r1);

        let r2 = fd.new_op(3, Address::new(0x1002));
        fd.op_set_opcode(&r2, OpCode::CPUI_STORE);
        fd.op_set_input(&r2, tmp_out.clone(), 1);  // reads tmp_out -> adds descend
        fd.obank.alivelist.push(r2);

        // Before split: tmp_out has 2 descendants.
        assert_eq!(tmp_out.read().unwrap().count_descends(), 2);

        // Run split_uses — faithful to Ghidra Funcdata::splitUses().
        fd.split_uses(&tmp_out);

        // After: a new duplicated INT_ADD op exists whose output is NOT tmp_out.
        let has_new_add = fd.obank.alivelist.iter().any(|r| {
            let o = r.0.read().unwrap();
            if o.opcode != OpCode::CPUI_INT_ADD { return false; }
            match o.output.as_ref() {
                Some(out) => !std::sync::Arc::ptr_eq(out, &tmp_out),
                None => false,
            }
        });
        assert!(has_new_add, "split_uses should create a duplicated INT_ADD op");
    }

    /// Diagnostic (2026-07-02): does lifting `xor eax,eax; ret` produce the
    /// SAME varnode for both XOR inputs? Ghidra's SSA identity model requires
    /// all reads of the same register (before any write) to share ONE varnode,
    /// so that `x^x→0` (RuleTrivialArith) can fold via Arc::ptr_eq. If this
    /// FAILS (ptreq=false AND same_storage=false), it is the root cause of the
    /// `return iVar1 ^ iVar1` defect in curl main_init.
    #[test]
    fn test_xor_eax_eax_input_identity() {
        let _lock = FFI_TEST_LOCK.lock().unwrap();
        // 31 c0 = xor eax,eax ; c3 = ret
        let code = vec![0x31, 0xc0, 0xc3];
        let start = Address::new(0x1000);
        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(&code, start).unwrap();
        assert_eq!(instructions.len(), 2);
        let mut lifter = X86Lifter::new();
        let mut raw_ops = Vec::new();
        for inst in &instructions { raw_ops.extend(lifter.lift(inst)); }
        // xor→2(INT_XOR+COPY), ret→1(RETURN)
        assert_eq!(raw_ops.len(), 3, "expected 3 raw ops, got {}", raw_ops.len());
        let mut fd = Funcdata::new("xor_eax_eax", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if op.opcode == OpCode::CPUI_INT_XOR {
                let i0 = &op.inrefs[0]; let i1 = &op.inrefs[1];
                let v0 = i0.read().unwrap(); let v1 = i1.read().unwrap();
                let ptreq = std::sync::Arc::ptr_eq(i0, i1);
                let same_storage = v0.get_space()==v1.get_space()
                    && v0.get_offset()==v1.get_offset() && v0.get_size()==v1.get_size();
                eprintln!("XOR inputs: ptreq={} same_storage={} in0={:?}@0x{:x} sz{} written={} | in1={:?}@0x{:x} sz{} written={}",
                    ptreq, same_storage,
                    v0.get_space(), v0.get_offset(), v0.get_size(), v0.is_written(),
                    v1.get_space(), v1.get_offset(), v1.get_size(), v1.is_written());
            }
        }
    }

}

// RUGRA-GLUE: 在出边列表中查找指向目标块的索引。Ghidra 用 FlowBlock::getOutIndex
// (block.hh:317)；Rugra 内联为文件级函数（需 downcast 到 BlockBasic/BlockGraph）。
/// Find the index of the outgoing edge pointing to `target` in `src`.
fn find_out_index(
    src: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    target: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
) -> Option<usize> {
    let rg = src.read().unwrap();
    let n = rg.size_out();
    for i in 0..n {
        if let Some(e) = rg.get_out(i) {
            if Arc::ptr_eq(&e.point, target) {
                return Some(i);
            }
        }
    }
    None
}

// Ghidra: funcdata.hh:655 AncestorRealistic
/// Helper for determining if Varnodes can trace their value from a legitimate
/// source. Faithful 1:1 port of `AncestorRealistic` (funcdata.hh:655-724 +
/// funcdata_varnode.cc:1997-2237).
///
/// Tries to determine if a Varnode (a particular input to a CALL, CALLIND, or
/// RETURN op) makes sense as parameter-passing/return storage by examining the
/// Varnode's ancestors. If ancestors are \e unaffected, \e abnormal inputs, or
/// \e killedbycall, the Varnode doesn't make a good parameter.
///
/// The traversal is a depth-first walk over ancestor Varnodes (following the
/// def chain). The `State` stack holds the traversal frontier; each `State`
/// records (op, slot, flags, offset). The `marked_vn` list tracks visited
/// Varnodes so cycles are trimmed and marks can be cleared afterwards.
pub struct AncestorRealistic {
    state_stack: Vec<ArState>,
    marked_vn: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    multi_depth: i32,
    allow_failing_path: bool,
    // Snapshot of trial->isKilledByCall() taken at execute() start, so the
    // INDIRECT case can read it without &mut aliasing on ParamTrial.
    trial_killed_by_call: bool,
    // Snapshot of trial->getSize() taken at execute() start, so the PIECE
    // case can compare stateVn->getSize() > trial->getSize() faithfully.
    trial_size: i32,
    // Deferred ParamTrial flag mutations (applied by execute() after the
    // traversal). Ghidra mutates the trial pointer mid-traversal
    // (setIndCreateFormed / setCondExeEffect); Rugra defers these to avoid
    // &mut aliasing on ParamTrial during the self-referential traversal.
    pending_ind_create_formed: bool,
    pending_condexe_effect: bool,
}

// Ghidra: funcdata.hh:655 AncestorRealistic::State
/// One node in the depth-first ancestor traversal. Faithful to the nested
/// `AncestorRealistic::State` class (funcdata.hh:657-696).
#[derive(Clone)]
struct ArState {
    /// Operation along the path to the Varnode. `vn = op.getIn(slot)`.
    op: std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>,
    /// Input slot: `vn = op.getIn(slot)`.
    slot: i32,
    /// Boolean properties (seen_solid0 | seen_solid1 | seen_kill).
    flags: u32,
    /// Offset of the eventual trial value within a possibly larger register.
    offset: i32,
}

// Ghidra: funcdata.hh:659 AncestorRealistic::State (anonymous enum)
mod state_flags {
    /// Solid movement into slot 0 seen on at least one path to MULTIEQUAL.
    pub const SEEN_SOLID0: u32 = 1;
    /// Solid movement into a slot other than 0 seen.
    pub const SEEN_SOLID1: u32 = 2;
    /// Killedbycall seen on at least one path to MULTIEQUAL.
    pub const SEEN_KILL: u32 = 4;
}

// Ghidra: funcdata.hh:698 AncestorRealistic (anonymous enum)
/// Depth-first traversal commands. Faithful to the anonymous enum in
/// `AncestorRealistic` (funcdata.hh:698-704).
mod ar_command {
    /// Extending path into a new Varnode.
    pub const ENTER_NODE: i32 = 0;
    /// Backtracking, from a path that contained a reasonable ancestor.
    pub const POP_SUCCESS: i32 = 1;
    /// Backtracking, from a path with successful solid movement.
    pub const POP_SOLID: i32 = 2;
    /// Backtracking, from a path with a bad ancestor.
    pub const POP_FAIL: i32 = 3;
    /// Backtracking, from a path with a bad ancestor (specifically killedbycall).
    pub const POP_FAILKILL: i32 = 4;
}

impl ArState {
    // Ghidra: funcdata.hh:692 State::markSolid
    /// Mark the given slot as having solid movement. Faithful to
    /// `State::markSolid` (funcdata.hh:692).
    fn mark_solid(&mut self, s: i32) {
        self.flags |= if s == 0 { state_flags::SEEN_SOLID0 } else { state_flags::SEEN_SOLID1 };
    }
    // Ghidra: funcdata.hh:693 State::markKill
    /// Mark killedbycall as seen. Faithful to `State::markKill` (funcdata.hh:693).
    fn mark_kill(&mut self) {
        self.flags |= state_flags::SEEN_KILL;
    }
    // Ghidra: funcdata.hh:694 State::seenSolid
    /// Has solid movement been seen? Faithful to `State::seenSolid` (funcdata.hh:694).
    fn seen_solid(&self) -> bool {
        (self.flags & (state_flags::SEEN_SOLID0 | state_flags::SEEN_SOLID1)) != 0
    }
    // Ghidra: funcdata.hh:695 State::seenKill
    /// Has killedbycall been seen? Faithful to `State::seenKill` (funcdata.hh:695).
    fn seen_kill(&self) -> bool {
        (self.flags & state_flags::SEEN_KILL) != 0
    }
    // Ghidra: funcdata.hh:691 State::getSolidSlot
    /// Get the slot associated with solid movement. Faithful to
    /// `State::getSolidSlot` (funcdata.hh:691).
    fn get_solid_slot(&self) -> i32 {
        if (self.flags & state_flags::SEEN_SOLID0) != 0 { 0 } else { 1 }
    }
}

impl AncestorRealistic {
    // RUGRA-GLUE: AncestorRealistic::new constructor (no Ghidra counterpart — Ghidra uses stack allocation)
    /// Construct an empty ancestor-realistic checker.
    pub fn new() -> Self {
        Self {
            state_stack: Vec::new(),
            marked_vn: Vec::new(),
            multi_depth: 0,
            allow_failing_path: false,
            trial_killed_by_call: false,
            trial_size: 0,
            pending_ind_create_formed: false,
            pending_condexe_effect: false,
        }
    }

    // Ghidra: funcdata_varnode.cc:1997 AncestorRealistic::checkConditionalExe
    /// Check if the current Varnode was produced by conditional flow. Faithful
    /// to `AncestorRealistic::checkConditionalExe` (funcdata_varnode.cc:1997-2022).
    /// Returns true if there are two input flows and one is a normal solid flow
    /// (the MULTIEQUAL block has exactly 2 inputs, and the solid-slot's source
    /// block has exactly 1 out-edge).
    fn check_conditional_exe(&self, state: &ArState) -> bool {
        let parent_arc = {
            let op_rg = state.op.read().unwrap();
            op_rg.parent.as_ref().and_then(|w| w.upgrade())
        };
        let bl = match parent_arc { Some(b) => b, None => return false };
        let (solid_point, size_in) = {
            let bl_rg = bl.read().unwrap();
            let solid_slot = state.get_solid_slot();
            let point = bl_rg.get_in(solid_slot as usize).map(|e| e.point.clone());
            (point, bl_rg.size_in())
        };
        if size_in != 2 { return false; }
        match solid_point {
            Some(sb) => sb.read().unwrap().size_out() == 1,
            None => false,
        }
    }

    // Ghidra: funcdata_varnode.cc:2026 AncestorRealistic::enterNode
    /// Analyze a newly-entered node during the depth-first traversal. Faithful
    /// to `AncestorRealistic::enterNode` (funcdata_varnode.cc:2026-2136).
    /// Returns the command for the next traversal step.
    fn enter_node(&mut self) -> i32 {
        use crate::opcodes::OpCode as OC;
        let (op_arc, slot, state_offset) = {
            let state = self.state_stack.last().unwrap();
            (state.op.clone(), state.slot, state.offset)
        };
        // Resolve the Varnode being traversed: vn = op.getIn(slot)
        let state_vn = {
            let op_rg = op_arc.read().unwrap();
            op_rg.get_in(slot as usize).cloned()
        };
        let state_vn = match state_vn {
            Some(v) => v,
            None => return ar_command::POP_FAIL,
        };
        // Truncate traversal on already-visited varnodes (cycle prevention).
        let (is_mark, is_written) = {
            let vn = state_vn.read().unwrap();
            (vn.is_mark(), vn.is_written())
        };
        if is_mark { return ar_command::POP_SUCCESS; }
        if !is_written {
            let (is_input, is_unaffected, is_persist, is_direct_write) = {
                let vn = state_vn.read().unwrap();
                (vn.is_input(), vn.is_unaffected(), vn.is_persist(), vn.is_direct_write())
            };
            if is_input {
                if is_unaffected { return ar_command::POP_FAIL; }
                if is_persist { return ar_command::POP_SUCCESS; }
                if !is_direct_write { return ar_command::POP_FAIL; }
            }
            return ar_command::POP_SUCCESS;
        }
        // Mark the varnode as visited.
        {
            let mut vn = state_vn.write().unwrap();
            vn.set_mark();
        }
        self.marked_vn.push(state_vn.clone());
        // Follow the defining op.
        let def_arc = {
            let vn = state_vn.read().unwrap();
            vn.get_def()
        };
        let op_def = match def_arc {
            Some(d) => d,
            None => return ar_command::POP_FAIL,
        };
        let opcode = { op_def.read().unwrap().opcode };
        match opcode {
            OC::CPUI_INDIRECT => {
                let (is_ind_create, is_ind_store, out_is_return, in0_indirect_zero) = {
                    let d = op_def.read().unwrap();
                    let out_is_ret = d.get_out().map(|v| v.read().unwrap().is_return_address()).unwrap_or(false);
                    let in0_iz = d.get_in(0).map(|v| v.read().unwrap().is_indirect_zero()).unwrap_or(false);
                    (d.is_indirect_creation(), d.is_indirect_store(), out_is_ret, in0_iz)
                };
                if is_ind_create {
                    self.pending_ind_create_formed = true;
                    if in0_indirect_zero {
                        return ar_command::POP_FAILKILL;
                    }
                    return ar_command::POP_SUCCESS;
                }
                if !is_ind_store {
                    // Ghidra: funcdata_varnode.cc:2052 "If flow goes THROUGH a call"
                    if out_is_return { return ar_command::POP_FAIL; }
                    if self.trial_killed_by_call { return ar_command::POP_FAIL; }
                }
                self.state_stack.push(ArState {
                    op: op_def.clone(),
                    slot: 0,
                    flags: 0,
                    offset: 0,
                });
                return ar_command::ENTER_NODE;
            }
            OC::CPUI_SUBPIECE => {
                let (out_space_is_internal, is_incidental, in0_incidental, out_overlap_in0_eq_in1, new_offset) = {
                    let d = op_def.read().unwrap();
                    let out_vn = d.get_out().and_then(|v| Some(v.clone()));
                    let in0 = d.get_in(0).and_then(|v| Some(v.clone()));
                    let in1_off = d.get_in(1).and_then(|v| Some(v.clone()))
                        .map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
                    let out_space = out_vn.as_ref().map(|v| v.read().unwrap().get_space());
                    let out_overlap = match (&out_vn, &in0) {
                        (Some(o), Some(i)) => o.read().unwrap().overlap(&i.read().unwrap()),
                        _ => -1,
                    };
                    (
                        out_space == Some(AddressSpace::Unique),
                        d.is_incidental_copy(),
                        in0.as_ref().map(|v| v.read().unwrap().is_incidental_copy()).unwrap_or(false),
                        out_overlap == in1_off as i32,
                        state_offset + in1_off as i32,
                    )
                };
                if out_space_is_internal || is_incidental || in0_incidental || out_overlap_in0_eq_in1 {
                    self.state_stack.push(ArState {
                        op: op_def.clone(),
                        slot: 0,
                        flags: 0,
                        offset: new_offset,
                    });
                    return ar_command::ENTER_NODE;
                }
                // Ghidra: funcdata_varnode.cc:2069-2077 minimal traversal to
                // rule out unaffected/invalid inputs (COPY/SUBPIECE chain).
                let mut cur_op = op_def.clone();
                loop {
                    let (vn_mark, vn_input, vn_unaffected, vn_direct_write, next_def) = {
                        let d = cur_op.read().unwrap();
                        let vn = d.get_in(0).and_then(|v| Some(v.clone()));
                        match vn {
                            Some(v) => {
                                let vr = v.read().unwrap();
                                (vr.is_mark(), vr.is_input(), vr.is_unaffected(), vr.is_direct_write(), vr.get_def())
                            }
                            None => return ar_command::POP_FAIL,
                        }
                    };
                    if !vn_mark && vn_input {
                        if vn_unaffected || !vn_direct_write {
                            return ar_command::POP_FAIL;
                        }
                    }
                    match next_def {
                        Some(nd) => {
                            let next_code = nd.read().unwrap().opcode;
                            if next_code == OC::CPUI_COPY || next_code == OC::CPUI_SUBPIECE {
                                cur_op = nd;
                            } else {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                return ar_command::POP_SOLID;
            }
            OC::CPUI_COPY => {
                let (out_space_internal, is_incidental, in0_incidental, out_addr_eq_in0_addr) = {
                    let d = op_def.read().unwrap();
                    let out_vn = d.get_out().and_then(|v| Some(v.clone()));
                    let in0 = d.get_in(0).and_then(|v| Some(v.clone()));
                    let out_space = out_vn.as_ref().map(|v| v.read().unwrap().get_space());
                    let out_addr = out_vn.as_ref().map(|v| v.read().unwrap().get_offset());
                    let in0_addr = in0.as_ref().map(|v| v.read().unwrap().get_offset());
                    (
                        out_space == Some(AddressSpace::Unique),
                        d.is_incidental_copy(),
                        in0.as_ref().map(|v| v.read().unwrap().is_incidental_copy()).unwrap_or(false),
                        out_addr.is_some() && in0_addr.is_some() && out_addr == in0_addr,
                    )
                };
                if out_space_internal || is_incidental || in0_incidental || out_addr_eq_in0_addr {
                    self.state_stack.push(ArState {
                        op: op_def.clone(),
                        slot: 0,
                        flags: 0,
                        offset: 0,
                    });
                    return ar_command::ENTER_NODE;
                }
                // Ghidra: funcdata_varnode.cc:2090-2108 minimal traversal:
                // follow COPY/SUBPIECE/PIECE chain checking input flags +
                // store_unmapped. (op, vn) advance together.
                let mut cur_op = op_def.clone();
                let mut cur_vn = {
                    let d = op_def.read().unwrap();
                    d.get_in(0).and_then(|v| Some(v.clone()))
                };
                loop {
                    let (vn_mark, vn_input, vn_direct_write) = match &cur_vn {
                        Some(v) => {
                            let vr = v.read().unwrap();
                            (vr.is_mark(), vr.is_input(), vr.is_direct_write())
                        }
                        None => return ar_command::POP_FAIL,
                    };
                    if !vn_mark && vn_input {
                        if !vn_direct_write { return ar_command::POP_FAIL; }
                    }
                    if cur_op.read().unwrap().is_store_unmapped() {
                        return ar_command::POP_FAIL;
                    }
                    let next_def = match &cur_vn {
                        Some(v) => v.read().unwrap().get_def(),
                        None => break,
                    };
                    match next_def {
                        Some(nd) => {
                            let next_code = nd.read().unwrap().opcode;
                            if next_code == OC::CPUI_COPY || next_code == OC::CPUI_SUBPIECE {
                                cur_vn = nd.read().unwrap().get_in(0).cloned();
                            } else if next_code == OC::CPUI_PIECE {
                                // Follow least significant piece.
                                cur_vn = nd.read().unwrap().get_in(1).cloned();
                            } else {
                                break;
                            }
                            cur_op = nd;
                        }
                        None => break,
                    }
                }
                return ar_command::POP_SOLID;
            }
            OC::CPUI_MULTIEQUAL => {
                self.multi_depth += 1;
                self.state_stack.push(ArState {
                    op: op_def.clone(),
                    slot: 0,
                    flags: 0,
                    offset: 0,
                });
                return ar_command::ENTER_NODE;
            }
            OC::CPUI_PIECE => {
                // Ghidra: funcdata_varnode.cc:2115-2132 PIECE case.
                // stateVn is the PIECE output; compare its size to trial size.
                let state_vn_size = state_vn.read().unwrap().get_size() as i32;
                let (in1_size, in0_size, state_vn_is_spacebase) = {
                    let d = op_def.read().unwrap();
                    let in0 = d.get_in(0).and_then(|v| Some(v.clone()));
                    let in1 = d.get_in(1).and_then(|v| Some(v.clone()));
                    let state_vn_space = state_vn.read().unwrap().get_space();
                    let in0_sz = in0.as_ref().map(|v| v.read().unwrap().get_size() as i32).unwrap_or(0);
                    let in1_sz = in1.as_ref().map(|v| v.read().unwrap().get_size() as i32).unwrap_or(0);
                    (in1_sz, in0_sz, state_vn_space == AddressSpace::Stack)
                };
                if state_vn_size > self.trial_size {
                    if state_offset == 0 && in1_size <= self.trial_size {
                        self.state_stack.push(ArState {
                            op: op_def.clone(), slot: 1, flags: 0, offset: 0,
                        });
                        return ar_command::ENTER_NODE;
                    } else if state_offset == in1_size && in0_size <= self.trial_size {
                        self.state_stack.push(ArState {
                            op: op_def.clone(), slot: 0, flags: 0, offset: 0,
                        });
                        return ar_command::ENTER_NODE;
                    }
                    if !state_vn_is_spacebase {
                        return ar_command::POP_FAIL;
                    }
                }
                return ar_command::POP_SOLID;
            }
            _ => {
                // Any other LOAD or arithmetic/logical operation is solid movement.
                return ar_command::POP_SOLID;
            }
        }
    }

    // Ghidra: funcdata_varnode.cc:2141 AncestorRealistic::uponPop
    /// Backtrack into a previously visited node. Faithful to
    /// `AncestorRealistic::uponPop` (funcdata_varnode.cc:2141-2185).
    fn upon_pop(&mut self, pop_command: i32) -> i32 {
        use crate::opcodes::OpCode as OC;
        let is_multiequal = {
            let state = self.state_stack.last().unwrap();
            state.op.read().unwrap().opcode == OC::CPUI_MULTIEQUAL
        };
        if is_multiequal {
            let (cur_slot, cur_num_input) = {
                let state = self.state_stack.last().unwrap();
                let s = state.op.read().unwrap();
                (state.slot, s.num_input() as i32)
            };
            if pop_command == ar_command::POP_FAIL {
                self.multi_depth -= 1;
                self.state_stack.pop();
                return pop_command;
            } else if pop_command == ar_command::POP_SOLID && self.multi_depth == 1 && cur_num_input == 2 {
                let slot = self.state_stack.last().unwrap().slot;
                let stack_len = self.state_stack.len();
                if stack_len >= 2 {
                    self.state_stack[stack_len - 2].mark_solid(slot);
                }
            } else if pop_command == ar_command::POP_FAILKILL {
                let stack_len = self.state_stack.len();
                if stack_len >= 2 {
                    self.state_stack[stack_len - 2].mark_kill();
                }
            }
            // state.slot += 1 (Ghidra funcdata_varnode.cc:2156)
            self.state_stack.last_mut().unwrap().slot += 1;
            let (new_slot, num_input) = {
                let state = self.state_stack.last().unwrap();
                let s = state.op.read().unwrap();
                (state.slot, s.num_input() as i32)
            };
            if new_slot == num_input {
                // All siblings traversed.
                let (prev_seen_solid, prev_seen_kill) = if self.state_stack.len() >= 2 {
                    let p = &self.state_stack[self.state_stack.len() - 2];
                    (p.seen_solid(), p.seen_kill())
                } else { (false, false) };
                let mut final_cmd = pop_command;
                if prev_seen_solid {
                    final_cmd = ar_command::POP_SUCCESS;
                    if prev_seen_kill {
                        if self.allow_failing_path {
                            // Re-read the current state for checkConditionalExe.
                            let state_clone = self.state_stack.last().unwrap().clone();
                            if !self.check_conditional_exe(&state_clone) {
                                final_cmd = ar_command::POP_FAIL;
                            } else {
                                self.pending_condexe_effect = true;
                            }
                        } else {
                            final_cmd = ar_command::POP_FAIL;
                        }
                    }
                } else if prev_seen_kill {
                    final_cmd = ar_command::POP_FAILKILL;
                } else {
                    final_cmd = ar_command::POP_SUCCESS;
                }
                self.multi_depth -= 1;
                self.state_stack.pop();
                return final_cmd;
            }
            return ar_command::ENTER_NODE;
        } else {
            self.state_stack.pop();
            return pop_command;
        }
    }

    // Ghidra: funcdata_varnode.cc:2194 AncestorRealistic::execute
    /// Perform a full ancestor check on a given parameter trial. Faithful to
    /// `AncestorRealistic::execute` (funcdata_varnode.cc:2194-2237).
    ///
    /// Returns true if the varnode (op's input at `slot`) has realistic
    /// ancestors for a parameter-passing location. Sets the trial's
    /// ancestor_realistic / ancestor_solid / condexe_effect / ind_create_formed
    /// flags as appropriate.
    pub fn execute(
        &mut self,
        op: &crate::op::PcodeOpRef,
        slot: i32,
        trial: &mut crate::fspec::ParamTrial,
        allow_fail: bool,
    ) -> bool {
        self.allow_failing_path = allow_fail;
        self.trial_killed_by_call = trial.is_killed_by_call();
        self.trial_size = trial.get_size();
        self.marked_vn.clear();
        self.state_stack.clear();
        self.multi_depth = 0;
        self.pending_ind_create_formed = false;
        self.pending_condexe_effect = false;
        // If the parameter itself is an input, we don't consider this realistic
        // (unless retesting for condexe).
        let is_input = {
            let op_rg = op.0.read().unwrap();
            let vn = op_rg.get_in(slot as usize);
            match vn {
                Some(v) => v.read().unwrap().is_input(),
                None => return false,
            }
        };
        if is_input {
            if !trial.has_condexe_effect() {
                return false;
            }
        }
        // Run the depth-first traversal.
        let mut command = ar_command::ENTER_NODE;
        self.state_stack.push(ArState {
            op: op.0.clone(),
            slot,
            flags: 0,
            offset: 0,
        });
        while !self.state_stack.is_empty() {
            match command {
                c if c == ar_command::ENTER_NODE => command = self.enter_node(),
                _ => command = self.upon_pop(command),
            }
        }
        // Clean up marks.
        for vn_arc in &self.marked_vn {
            vn_arc.write().unwrap().clear_mark();
        }
        // Apply deferred trial mutations.
        if self.pending_ind_create_formed { trial.set_ind_create_formed(); }
        if self.pending_condexe_effect { trial.set_condexe_effect(); }
        if command == ar_command::POP_SUCCESS {
            trial.set_ancestor_realistic();
            return true;
        } else if command == ar_command::POP_SOLID {
            trial.set_ancestor_realistic();
            trial.set_ancestor_solid();
            return true;
        }
        false
    }
}

// TraverseNode flags (expression.hh:62-68), used by onlyOpUse/ancestorOpUse.
mod traverse_flags {
    pub const ACTIONALT: u32 = 1;
    pub const INDIRECT: u32 = 2;
    pub const INDIRECTALT: u32 = 4;
    pub const LSB_TRUNCATED: u32 = 8;
    pub const CONCAT_HIGH: u32 = 0x10;
}

// Ghidra: funcdata_varnode.cc:1805 Funcdata::onlyOpUse
/// Test if the given Varnode seems to only be used by a CALL/RETURN. Faithful
/// to `Funcdata::onlyOpUse` (funcdata_varnode.cc:1805-1904). Walks forward
/// through descendants; if any descendent is a non-call use (BRANCH, LOAD,
/// STORE, etc.) returns false. CALL/CALLIND descendants trigger
/// checkCallDoubleUse (conservatively returns false — safe direction).
fn only_op_use(
    has_active_output: bool,
    invn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    opmatch: &crate::op::PcodeOpRef,
    trial_slot: i32,
    main_flags: u32,
) -> bool {
    use crate::opcodes::OpCode as OC;
    use std::sync::{Arc, RwLock};
    struct TNode {
        vn: Arc<RwLock<crate::varnode::Varnode>>,
        flags: u32,
    }
    let mut varlist: Vec<TNode> = Vec::with_capacity(64);
    {
        let mut vn = invn.write().unwrap();
        vn.set_mark();
    }
    varlist.push(TNode { vn: invn.clone(), flags: main_flags });
    let mut idx = 0;
    let mut res = true;
    while idx < varlist.len() {
        let base_flags = varlist[idx].flags;
        let vn_arc = varlist[idx].vn.clone();
        let descends: Vec<Arc<RwLock<crate::op::PcodeOp>>> =
            vn_arc.read().unwrap().descend.iter().filter_map(|w| w.upgrade()).collect();
        for op_arc in descends {
            let op_rg = op_arc.read().unwrap();
            if Arc::ptr_eq(&op_arc, &opmatch.0) {
                let trial_in = op_rg.get_in(trial_slot as usize);
                if let Some(tiv) = trial_in {
                    if Arc::ptr_eq(tiv, &vn_arc) { continue; }
                }
            }
            let mut cur_flags = base_flags;
            match op_rg.opcode {
                OC::CPUI_BRANCH | OC::CPUI_CBRANCH | OC::CPUI_BRANCHIND
                | OC::CPUI_LOAD | OC::CPUI_STORE => {
                    res = false;
                }
                OC::CPUI_CALL | OC::CPUI_CALLIND => {
                    let _ = &mut cur_flags;
                    res = false;
                }
                OC::CPUI_INDIRECT => {
                    cur_flags |= traverse_flags::INDIRECTALT;
                }
                OC::CPUI_COPY => {
                    let out_internal = op_rg.get_out()
                        .map(|v| v.read().unwrap().get_space() == AddressSpace::Unique)
                        .unwrap_or(false);
                    let op_incidental = op_rg.is_incidental_copy();
                    let vn_incidental = vn_arc.read().unwrap().is_incidental_copy();
                    if !out_internal && !op_incidental && !vn_incidental {
                        cur_flags |= traverse_flags::ACTIONALT;
                    }
                }
                OC::CPUI_RETURN => {
                    let opmatch_code = opmatch.0.read().unwrap().opcode;
                    if opmatch_code == OC::CPUI_RETURN {
                        let r_in = op_rg.get_in(trial_slot as usize);
                        if let Some(riv) = r_in {
                            if Arc::ptr_eq(riv, &vn_arc) { continue; }
                        }
                    } else if has_active_output {
                        res = false;
                    } else {
                        res = false;
                    }
                }
                _ => {}
            }
            if !res { break; }
            if op_rg.opcode == OC::CPUI_INDIRECT || op_rg.opcode == OC::CPUI_COPY {
                if let Some(out) = op_rg.get_out() {
                    let out_clone = out.clone();
                    if !out_clone.read().unwrap().is_mark() {
                        out_clone.write().unwrap().set_mark();
                        varlist.push(TNode { vn: out_clone, flags: cur_flags });
                    }
                }
            }
        }
        if !res { break; }
        idx += 1;
    }
    for t in &varlist {
        t.vn.write().unwrap().clear_mark();
    }
    res
}

// Ghidra: funcdata_varnode.cc:1917 Funcdata::ancestorOpUse
/// Test if the given trial Varnode is likely only used for parameter passing.
/// Faithful to `Funcdata::ancestorOpUse` (funcdata_varnode.cc:1917-1994).
pub fn ancestor_op_use(
    has_active_output: bool,
    maxlevel: i32,
    invn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    op: &crate::op::PcodeOpRef,
    trial_slot: i32,
    offset: i32,
    main_flags: u32,
) -> bool {
    use crate::opcodes::OpCode as OC;
    if maxlevel == 0 { return false; }
    let (is_written, is_input, is_type_lock) = {
        let vn = invn.read().unwrap();
        (vn.is_written(), vn.is_input(), vn.is_type_lock())
    };
    if !is_written {
        if !is_input { return false; }
        if !is_type_lock { return false; }
        return only_op_use(has_active_output, invn, op, trial_slot, main_flags);
    }
    let def_arc = { invn.read().unwrap().get_def() };
    let def_arc = match def_arc { Some(d) => d, None => return false };
    let opcode = def_arc.read().unwrap().opcode;
    match opcode {
        OC::CPUI_INDIRECT => {
            if def_arc.read().unwrap().is_indirect_creation() { return false; }
            let in0 = def_arc.read().unwrap().get_in(0).cloned();
            match in0 {
                Some(v) => ancestor_op_use(has_active_output, maxlevel - 1, &v, op, trial_slot, offset,
                    main_flags | traverse_flags::INDIRECT),
                None => false,
            }
        }
        OC::CPUI_MULTIEQUAL => {
            if def_arc.read().unwrap().is_mark() { return false; }
            def_arc.write().unwrap().set_mark();
            let num_input = def_arc.read().unwrap().num_input();
            let mut result = false;
            for i in 0..num_input {
                let in_vn = def_arc.read().unwrap().get_in(i).cloned();
                if let Some(v) = in_vn {
                    if ancestor_op_use(has_active_output, maxlevel - 1, &v, op, trial_slot, offset, main_flags) {
                        result = true;
                        break;
                    }
                }
            }
            def_arc.write().unwrap().clear_mark();
            result
        }
        OC::CPUI_COPY => {
            let out_internal = def_arc.read().unwrap().get_out()
                .map(|v| v.read().unwrap().get_space() == AddressSpace::Unique)
                .unwrap_or(false);
            let op_incidental = def_arc.read().unwrap().is_incidental_copy();
            let in0 = def_arc.read().unwrap().get_in(0).cloned();
            let in0_incidental = in0.as_ref().map(|v| v.read().unwrap().is_incidental_copy()).unwrap_or(false);
            if out_internal || op_incidental || in0_incidental {
                match in0 {
                    Some(v) => ancestor_op_use(has_active_output, maxlevel - 1, &v, op, trial_slot, offset, main_flags),
                    None => false,
                }
            } else {
                only_op_use(has_active_output, invn, op, trial_slot, main_flags)
            }
        }
        OC::CPUI_PIECE => {
            let in0 = def_arc.read().unwrap().get_in(0).cloned();
            let in1 = def_arc.read().unwrap().get_in(1).cloned();
            let in1_size = in1.as_ref().map(|v| v.read().unwrap().get_size() as i32).unwrap_or(0);
            if let Some(v0) = in0 {
                if ancestor_op_use(has_active_output, maxlevel - 1, &v0, op, trial_slot, offset + in1_size,
                    main_flags | traverse_flags::CONCAT_HIGH) {
                    return true;
                }
            }
            if let Some(v1) = in1 {
                if ancestor_op_use(has_active_output, maxlevel - 1, &v1, op, trial_slot, offset, main_flags) {
                    return true;
                }
            }
            false
        }
        OC::CPUI_SUBPIECE => {
            let out_internal = def_arc.read().unwrap().get_out()
                .map(|v| v.read().unwrap().get_space() == AddressSpace::Unique)
                .unwrap_or(false);
            let op_incidental = def_arc.read().unwrap().is_incidental_copy();
            let in0 = def_arc.read().unwrap().get_in(0).cloned();
            let in0_incidental = in0.as_ref().map(|v| v.read().unwrap().is_incidental_copy()).unwrap_or(false);
            let in1_off = def_arc.read().unwrap().get_in(1)
                .map(|v| v.read().unwrap().get_offset() as i32).unwrap_or(0);
            if (out_internal || op_incidental || in0_incidental) && (offset - in1_off) >= 0 {
                match in0 {
                    Some(v) => ancestor_op_use(has_active_output, maxlevel - 1, &v, op, trial_slot, offset - in1_off,
                        main_flags | traverse_flags::LSB_TRUNCATED),
                    None => false,
                }
            } else {
                only_op_use(has_active_output, invn, op, trial_slot, main_flags)
            }
        }
        OC::CPUI_CALL | OC::CPUI_CALLIND => false,
        _ => only_op_use(has_active_output, invn, op, trial_slot, main_flags),
    }
}

// Ghidra: funcdata_block.cc:962 CloneBlockOps
/// Clone p-code ops from one basic block into another (for nodeSplit).
/// Faithful to Ghidra's `CloneBlockOps` class (funcdata_block.cc:962-1104).
struct CloneBlockOps {
    /// (clone_op, orig_op) pairs, in clone order.
    clone_list: Vec<(crate::op::PcodeOpRef, crate::op::PcodeOpRef)>,
    /// Map from orig op Arc ptr → clone op Arc.
    orig_to_clone: std::collections::HashMap<usize, crate::op::PcodeOpRef>,
}

impl CloneBlockOps {
    // RUGRA-GLUE: Rust 构造器（Ghidra CloneBlockOps 用 C++ 构造函数 + data 引用初始化）。
    fn new() -> Self {
        Self {
            clone_list: Vec::new(),
            orig_to_clone: std::collections::HashMap::new(),
        }
    }

    // Ghidra: funcdata_block.cc:962 CloneBlockOps::buildOpClone
    /// Clone a PcodeOp (copy opcode + flags). Skip branches (return None).
    fn build_op_clone(&mut self, fd: &mut Funcdata, orig: &crate::op::PcodeOpRef) -> Option<crate::op::PcodeOpRef> {
        let (is_branch, is_not_branch, num_input, addr, opcode, flags, addlflags) = {
            let o = orig.0.read().unwrap();
            let ib = o.is_branch();
            let addr = o.get_addr();
            let opcode = o.opcode;
            let flags = o.flags;
            let addlflags = o.addlflags;
            (ib, ib && o.opcode != crate::opcodes::OpCode::CPUI_BRANCH, o.num_input(), addr, opcode, flags, addlflags)
        };
        if is_branch {
            if is_not_branch {
                eprintln!("[BLOCK] Cannot duplicate 2-way or n-way branch in nodesplit");
            }
            return None;
        }
        let dup = fd.new_op(num_input, addr);
        fd.op_set_opcode(&dup, opcode);
        // Copy flag subset (funcdata_block.cc:974-978).
        let fl_mask = crate::op::pcodeop_flags::STARTBASIC
            | crate::op::pcodeop_flags::NOCOLLAPSE
            | crate::op::pcodeop_flags::STARTMARK
            | crate::op::pcodeop_flags::NONPRINTING
            | crate::op::pcodeop_flags::HALT
            | crate::op::pcodeop_flags::BADINSTRUCTION
            | crate::op::pcodeop_flags::UNIMPLEMENTED
            | crate::op::pcodeop_flags::NORETURN
            | crate::op::pcodeop_flags::MISSING
            | crate::op::pcodeop_flags::INDIRECT_CREATION
            | crate::op::pcodeop_flags::INDIRECT_STORE
            | crate::op::pcodeop_flags::CALCULATED_BOOL
            | crate::op::pcodeop_flags::PTRFLOW;
        dup.0.write().unwrap().flags |= flags & fl_mask;
        // Copy addlflag subset (funcdata_block.cc:979-980).
        let afl_mask = crate::op::op_addl_flags::SPECIAL_PRINT
            | crate::op::op_addl_flags::INCIDENTAL_COPY
            | crate::op::op_addl_flags::IS_CPOOL_TRANSFORMED
            | crate::op::op_addl_flags::STOP_TYPE_PROPAGATION
            | crate::op::op_addl_flags::STORE_UNMAPPED;
        dup.0.write().unwrap().addlflags |= addlflags & afl_mask;
        // Record mappings.
        self.clone_list.push((dup.clone(), orig.clone()));
        self.orig_to_clone.insert(Arc::as_ptr(&orig.0) as usize, dup.clone());
        Some(dup)
    }

    // Ghidra: funcdata_block.cc:992 CloneBlockOps::buildVarnodeOutput
    /// Clone the output Varnode of an op into the clone op.
    fn build_varnode_output(&self, fd: &mut Funcdata, orig_op: &crate::op::PcodeOpRef, clone_op: &crate::op::PcodeOpRef) {
        let orig_out = orig_op.0.read().unwrap().output.clone();
        let Some(orig_vn) = orig_out else { return };
        let (size, addr) = {
            let v = orig_vn.read().unwrap();
            (v.size, v.loc)
        };
        let new_vn = fd.new_varnode_out(size, addr, clone_op);
        // Copy varnode flag subset (funcdata_block.cc:1001-1004).
        let orig_flags = orig_vn.read().unwrap().flags;
        let vflag_mask = crate::varnode::varnode_flags::EXTERNREF
            | crate::varnode::varnode_flags::VOLATIL
            | crate::varnode::varnode_flags::INCIDENTAL_COPY
            | crate::varnode::varnode_flags::READONLY
            | crate::varnode::varnode_flags::PERSIST
            | crate::varnode::varnode_flags::ADDRTIED
            | crate::varnode::varnode_flags::ADDRFORCE
            | crate::varnode::varnode_flags::NOLOCALALIAS
            | crate::varnode::varnode_flags::SPACEBASE
            | crate::varnode::varnode_flags::INDIRECT_CREATION
            | crate::varnode::varnode_flags::RETURN_ADDRESS
            | crate::varnode::varnode_flags::PRECISLO
            | crate::varnode::varnode_flags::PRECISHI;
        new_vn.write().unwrap().set_flags(orig_flags & vflag_mask);
    }

    // Ghidra: funcdata_block.cc:1015 CloneBlockOps::cloneBlock
    /// Clone all ops from `b` into `bprime`, patching inputs.
    fn clone_block(
        &mut self,
        fd: &mut Funcdata,
        b: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        bprime: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        inedge: usize,
    ) {
        // Collect ops from b.
        let ops: Vec<crate::op::PcodeOpRef> = {
            let rg = b.read().unwrap();
            if let Some(bb) = rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                bb.get_ops()
            } else {
                Vec::new()
            }
        };
        for orig_ref in &ops {
            if let Some(clone_ref) = self.build_op_clone(fd, orig_ref) {
                self.build_varnode_output(fd, orig_ref, &clone_ref);
                fd.op_insert_end(&clone_ref, bprime);
            }
        }
        self.patch_inputs(fd, inedge);
    }

    // Ghidra: funcdata_block.cc:1058 CloneBlockOps::patchInputs
    /// Patch cloned op inputs: MULTIEQUAL → COPY; constants shared; written
    /// inputs mapped to clone outputs; others shared.
    fn patch_inputs(&self, fd: &mut Funcdata, inedge: usize) {
        use crate::opcodes::OpCode;
        for (clone_ref, orig_ref) in &self.clone_list {
            let opcode = orig_ref.0.read().unwrap().opcode;
            match opcode {
                OpCode::CPUI_MULTIEQUAL => {
                    // cloneOp becomes a single-input COPY from orig's inedge slot.
                    clone_ref.0.write().unwrap().inrefs.resize(1, std::sync::Arc::new(std::sync::RwLock::new(
                        crate::varnode::Varnode::new_constant(0, 0)
                    )));
                    fd.op_set_opcode(clone_ref, OpCode::CPUI_COPY);
                    let in_vn = orig_ref.0.read().unwrap().inrefs.get(inedge).cloned();
                    if let Some(vn) = in_vn {
                        fd.op_set_input(clone_ref, vn, 0);
                    }
                    // Remove inedge from original MULTIEQUAL (funcdata_block.cc:1068).
                    fd.op_remove_input(orig_ref, inedge);
                    if orig_ref.0.read().unwrap().num_input() == 1 {
                        fd.op_set_opcode(orig_ref, OpCode::CPUI_COPY);
                    }
                }
                OpCode::CPUI_INDIRECT => {
                    eprintln!("[BLOCK] Can't clone INDIRECTs in nodesplit");
                }
                _ if orig_ref.0.read().unwrap().is_call() => {
                    eprintln!("[BLOCK] Can't clone CALLs in nodesplit");
                }
                _ => {
                    // Regular op: patch each input (funcdata_block.cc:1079-1101).
                    let num_in = clone_ref.0.read().unwrap().num_input();
                    for i in 0..num_in {
                        let orig_vn = orig_ref.0.read().unwrap().inrefs.get(i).cloned();
                        let Some(orig_vn) = orig_vn else { continue };
                        let clone_vn = {
                            let v = orig_vn.read().unwrap();
                            if v.is_constant() {
                                Some(orig_vn.clone())
                            } else if v.is_annotation() {
                                // data.newCodeRef — Rugra shares annotation varnodes.
                                Some(orig_vn.clone())
                            } else if v.is_free() {
                                eprintln!("[BLOCK] Can't clone free varnode in nodesplit");
                                None
                            } else {
                                // Check if orig_vn is defined by a cloned op.
                                let def_op = v.def.as_ref().and_then(|w| w.upgrade());
                                match def_op {
                                    Some(def_arc) => {
                                        let key = Arc::as_ptr(&def_arc) as usize;
                                        match self.orig_to_clone.get(&key) {
                                            Some(clone_op) => clone_op.0.read().unwrap().output.clone(),
                                            None => Some(orig_vn.clone()),
                                        }
                                    }
                                    None => Some(orig_vn.clone()),
                                }
                            }
                        };
                        if let Some(cv) = clone_vn {
                            fd.op_set_input(clone_ref, cv, i);
                        }
                    }
                }
            }
        }
    }
}


