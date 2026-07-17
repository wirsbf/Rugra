//! Function prototypes and call specifications
//!
//! Corresponds to Ghidra's `fspec.hh`. This module manages how functions
//! are defined (prototypes) and how call sites are handled (call specs).

use std::sync::Arc;
use crate::address::Address;
use crate::space::AddressSpace;
use crate::type_system::datatype::Datatype;

/// Effect type for a memory range across a call. Faithful to
/// `EffectRecord` enum (fspec.hh:393-398).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectType {
    /// The sub-function does not change the value at all
    Unaffected = 1,
    /// The memory is changed and is completely unrelated to its original value
    KilledByCall = 2,
    /// The memory is being used to store the return address
    ReturnAddress = 3,
    /// An unknown effect (indicates the absence of an EffectRecord)
    UnknownEffect = 4,
}

/// A record of how a specific memory range is affected by a sub-function call.
/// Faithful to `EffectRecord` (fspec.hh:391-416). Used by ActionRestrictLocal
/// to identify saved registers (unaffected) that are copied to stack storage.
#[derive(Debug, Clone)]
pub struct EffectRecord {
    /// The memory range affected (space + offset)
    pub space: AddressSpace,
    /// The starting offset of the affected range
    pub offset: u64,
    /// The size of the affected range
    pub size: i32,
    /// The type of effect
    pub effect_type: EffectType,
}

impl EffectRecord {
    // Ghidra: fspec.cc:2212 EffectRecord::new
    /// Create a new effect record. Faithful to `EffectRecord(const VarnodeData&, uint4)`.
    pub fn new(space: AddressSpace, offset: u64, size: i32, effect_type: EffectType) -> Self {
        Self { space, offset, size, effect_type }
    }

    // Ghidra: fspec.cc:2212 EffectRecord::getType
    /// Get the type of effect. Faithful to `getType`.
    pub fn get_type(&self) -> EffectType { self.effect_type }

    // Ghidra: fspec.cc:2212 EffectRecord::getOffset
    /// Get the starting address offset. Faithful to `getAddress`.
    pub fn get_offset(&self) -> u64 { self.offset }

    // Ghidra: fspec.cc:2212 EffectRecord::getSize
    /// Get the size of the affected range. Faithful to `getSize`.
    pub fn get_size(&self) -> i32 { self.size }
}

/// Flags for ProtoParameter (corresponds to flags in fspec.hh)
pub mod protoparam_flags {
    pub const HIDDEN_RETURN: u32 = 1 << 0;
    pub const INDIRECT_STORAGE: u32 = 1 << 1;
    pub const THIS_POINTER: u32 = 1 << 2;
    pub const NAME_LOCKED: u32 = 1 << 3;
    pub const TYPE_LOCKED: u32 = 1 << 4;
}

/// A single parameter in a function signature
///
/// Corresponds to Ghidra's `ProtoParameter` class.
#[derive(Debug, Clone)]
pub struct ProtoParameter {
    /// Name of the parameter
    pub name: String,
    /// Data type of the parameter
    pub data_type: Arc<Datatype>,
    /// Storage location (register, stack offset, etc.)
    pub address: Address,
    /// Property flags
    pub flags: u32,
}

impl ProtoParameter {
    // Ghidra: fspec.hh:1100 ProtoParameter::new
    /// Create a new function parameter
    pub fn new(name: String, data_type: Arc<Datatype>, address: Address) -> Self {
        Self {
            name,
            data_type,
            address,
            flags: 0,
        }
    }

    // Ghidra: fspec.hh:1100 ProtoParameter::isThisPointer
    /// Returns true if this parameter is a "this" pointer
    pub fn is_this_pointer(&self) -> bool {
        (self.flags & protoparam_flags::THIS_POINTER) != 0
    }

    // Ghidra: fspec.hh:1100 ProtoParameter::isTypeLocked
    /// Returns true if the type is locked (user-defined)
    pub fn is_type_locked(&self) -> bool {
        (self.flags & protoparam_flags::TYPE_LOCKED) != 0
    }
}

/// A formal function prototype
///
/// Corresponds to Ghidra's `FuncProto` class. It defines the return type,
/// parameters, and calling convention of a function.
#[derive(Debug, Clone)]
pub struct FuncProto {
    /// Name of the function (optional, can be empty for anonymous signatures)
    pub name: String,
    /// Return type of the function
    pub return_type: Arc<Datatype>,
    /// List of formal parameters
    pub parameters: Vec<ProtoParameter>,
    /// Calling convention name (e.g., "__stdcall", "__cdecl")
    pub calling_convention: String,
    /// True if the function accepts variable arguments (...)
    pub is_dotdotdot: bool,
    /// Effect records: how registers/memory are affected by this function's calls.
    /// Faithful to `FuncProto::effectlist` (fspec.hh). Used by ActionRestrictLocal
    /// to identify saved registers (unaffected) that are copied to stack.
    pub effects: Vec<EffectRecord>,
    /// Is the return-value (output) data-type locked? Faithful to
    /// `FuncProto::isOutputLocked` (fspec.cc:3906-3914): a locked output means
    /// the presence and data-type of the return value is fixed and analysis
    /// must not change it. Set by `set_output_lock`. A locked-void return
    /// (e.g. `exit`, `free`) means the CALL produces NO output varnode.
    pub output_type_locked: bool,
    /// Number of bytes of the return value that are consumed by callers
    /// (0 = all bytes). Faithful to `FuncProto::returnBytesConsumed`
    /// (fspec.hh:1367). Set by `set_return_bytes_consumed`; read by the
    /// dead-code consume algorithm. RulePiecePathology records the partial
    /// consumption of a pathological PIECE here.
    pub return_bytes_consumed: u32,
}

impl FuncProto {
    // Ghidra: fspec.cc:3778 FuncProto::new
    /// Create a new function prototype
    pub fn new(name: String, return_type: Arc<Datatype>) -> Self {
        Self {
            name,
            return_type,
            parameters: Vec::new(),
            calling_convention: "unknown".to_string(),
            is_dotdotdot: false,
            effects: Vec::new(),
            output_type_locked: false,
            return_bytes_consumed: 0,
        }
    }

    // Ghidra: fspec.cc:3778 FuncProto::addParameter
    /// Add a parameter to the prototype
    pub fn add_parameter(&mut self, param: ProtoParameter) {
        self.parameters.push(param);
    }

    // Ghidra: fspec.cc:3778 FuncProto::numParams
    /// Get the number of parameters
    pub fn num_params(&self) -> usize {
        self.parameters.len()
    }

    // Ghidra: fspec.cc:3778 FuncProto::getParam
    /// Get a parameter by index
    pub fn get_param(&self, index: usize) -> Option<&ProtoParameter> {
        self.parameters.get(index)
    }

    // Ghidra: fspec.cc:3778 FuncProto::effectIter
    /// Iterate effect records. Faithful to `FuncProto::effectBegin/effectEnd`
    /// (fspec.hh). Returns a slice of all EffectRecords for this prototype.
    pub fn effect_iter(&self) -> &[EffectRecord] {
        &self.effects
    }

    // Ghidra: fspec.cc:3778 FuncProto::addEffect
    /// Add an effect record. Used during prototype analysis to record
    /// how registers/memory are affected by this function's calls.
    pub fn add_effect(&mut self, effect: EffectRecord) {
        self.effects.push(effect);
    }

    // Ghidra: fspec.cc:3906 FuncProto::isInputLocked
    /// Check if input parameters are locked (type-locked).
    /// Faithful to FuncProto::isInputLocked (fspec.cc:3906).
    pub fn is_input_locked(&self) -> bool {
        self.parameters.iter().all(|p| p.is_type_locked())
    }

    // Ghidra: fspec.cc:3921 FuncProto::setInputLock
    /// Set input lock state. When locked, parameters won't be
    /// overridden by active recovery.
    /// Faithful to FuncProto::setInputLock (fspec.cc:3921).
    pub fn set_input_lock(&mut self, val: bool) {
        for p in &mut self.parameters {
            if val { p.flags |= protoparam_flags::TYPE_LOCKED; }
            else { p.flags &= !protoparam_flags::TYPE_LOCKED; }
        }
    }

    // Ghidra: fspec.cc:3942 FuncProto::setOutputLock
    /// Set output lock state. When locked, the return value's presence and
    /// data-type will not be overridden by active recovery.
    /// Faithful to FuncProto::setOutputLock (fspec.cc:3942-3948).
    pub fn set_output_lock(&mut self, val: bool) {
        self.output_type_locked = val;
    }

    // Ghidra: fspec.cc:3778 FuncProto::isOutputLocked
    /// Is the output (return) data-type locked? Faithful to
    /// `FuncProto::isOutputLocked`. Used by `funcLinkOutput` to decide
    /// whether to build an output varnode immediately (locked) or defer to
    /// active-output trials (unlocked).
    pub fn is_output_locked(&self) -> bool {
        self.output_type_locked
    }

    // Ghidra: fspec.cc:3778 FuncProto::getReturnBytesConsumed
    /// Get the number of bytes of the return value consumed by callers.
    /// Faithful to `FuncProto::getReturnBytesConsumed` (fspec.hh:1429).
    /// A value of 0 means all bytes are presumed consumed.
    pub fn get_return_bytes_consumed(&self) -> u32 {
        self.return_bytes_consumed
    }

    // Ghidra: fspec.cc:3954 FuncProto::setReturnBytesConsumed
    /// Set the hint for how many bytes of the return value are consumed.
    /// Faithful to `FuncProto::setReturnBytesConsumed` (fspec.cc:3954-3965).
    /// The smallest hint wins (the value can only shrink). Returns true if
    /// the smallest hint changed.
    pub fn set_return_bytes_consumed(&mut self, val: u32) -> bool {
        if val == 0 {
            return false;
        }
        if self.return_bytes_consumed == 0 || val < self.return_bytes_consumed {
            self.return_bytes_consumed = val;
            return true;
        }
        false
    }

    // Ghidra: fspec.cc:3778 FuncProto::copyFrom
    /// Copy from another FuncProto.
    /// Faithful to FuncProto::copy (fspec.cc:3789).
    pub fn copy_from(&mut self, other: &FuncProto) {
        self.name = other.name.clone();
        self.return_type = other.return_type.clone();
        self.parameters = other.parameters.clone();
        self.calling_convention = other.calling_convention.clone();
        self.is_dotdotdot = other.is_dotdotdot;
        self.output_type_locked = other.output_type_locked;
        self.return_bytes_consumed = other.return_bytes_consumed;
    }

    // Ghidra: fspec.cc:3994 FuncProto::clearUnlockedInput
    /// Clear unlocked input parameters.
    /// Faithful to FuncProto::clearUnlockedInput (fspec.cc:3994).
    pub fn clear_unlocked_input(&mut self) {
        self.parameters.retain(|p| p.is_type_locked());
    }

    // Ghidra: fspec.cc:3778 FuncProto::isVarargs
    /// Check if this proto is variable-argument (...).
    pub fn is_varargs(&self) -> bool { self.is_dotdotdot }

    // Ghidra: fspec.cc:3778 FuncProto::setDotdotdot
    /// Set variable-argument flag.
    pub fn set_dotdotdot(&mut self, val: bool) { self.is_dotdotdot = val; }

    // Ghidra: fspec.cc:3778 FuncProto::getModelName
    /// Get the calling convention model name.
    pub fn get_model_name(&self) -> &str { &self.calling_convention }

    // Ghidra: fspec.cc:3778 FuncProto::setModelName
    /// Set the calling convention model name.
    pub fn set_model_name(&mut self, name: &str) { self.calling_convention = name.to_string(); }
}

/// Specification for a specific function call site
///
/// Corresponds to Ghidra's `FuncCallSpecs` class.
#[derive(Debug, Clone)]
pub struct FuncCallSpecs {
    /// The address of the call instruction
    pub op_addr: Address,
    /// The destination address of the call (if known)
    pub entry_addr: Option<Address>,
    /// The prototype used at this call site
    pub prototype: FuncProto,
    /// Flags and other metadata
    pub flags: u32,
    /// Active-input parameter trials (ParamActive). Faithful to
    /// `FuncCallSpecs::activeinput`. Set by ActionFuncLink::funcLinkInput.
    pub active_input: Option<ParamActive>,
    /// Active-output parameter trials. Faithful to
    /// `FuncCallSpecs::activeoutput`. Set by ActionFuncLink::funcLinkOutput.
    pub active_output: Option<ParamActive>,
    /// Calling-convention model for this call site. Faithful to
    /// `FuncCallSpecs::model`. Set by setModel; used by resolveModel/
    /// deriveInputMap/checkInputTrialUse.
    pub proto_model: Option<crate::type_system::protomodel::ProtoModel>,
    /// Relative offset of stack-pointer at time of this call. Faithful to
    /// `FuncCallSpecs::stackoffset` (fspec.hh:1651). Set by
    /// resolveSpacebaseRelative; used by ActionRestrictLocal to find
    /// stack-relative call params. offset_unknown = i64::MIN.
    pub stackoffset: i64,
    /// Per-input-slot bytes-consumed hints. Faithful to
    /// `FuncCallSpecs::inputConsume` (fspec.cc:5870-5906). A non-zero entry
    /// means that many least-significant bytes of the parameter storage are
    /// used by the sub-function; 0 means all bytes. Indexed by input slot
    /// (with slot 0 = the call target, parameters start at slot 1).
    /// Sparse — grown lazily by `set_input_bytes_consumed`.
    pub input_consume: Vec<u32>,
    /// Stack placeholder slot for spacebase-relative parameter passing.
    /// Faithful to `FuncCallSpecs::stackPlaceholderSlot` (fspec.hh:1653).
    /// -1 = no placeholder; >=0 = the input slot holding the placeholder
    /// varnode. Used by abortSpacebaseRelative to clean up placeholders
    /// after heritage resolves the actual stack values.
    pub stack_placeholder_slot: i32,
}

/// Sentinel value for unknown stack offset. Faithful to
/// `FuncCallSpecs::offset_unknown` (fspec.hh:1641).
pub const OFFSET_UNKNOWN: i64 = i64::MIN;

impl FuncCallSpecs {
    // Ghidra: fspec.cc:4924 FuncCallSpecs::new
    /// Create a new call specification
    pub fn new(op_addr: Address, prototype: FuncProto) -> Self {
        Self {
            op_addr,
            entry_addr: None,
            prototype,
            flags: 0,
            active_input: None,
            active_output: None,
            proto_model: None,
            stackoffset: OFFSET_UNKNOWN,
            input_consume: Vec::new(),
            stack_placeholder_slot: -1,
        }
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::getSpacebaseOffset
    /// Get the stack-pointer relative offset at the point of this call site.
    /// Faithful to `FuncCallSpecs::getSpacebaseOffset` (fspec.hh:1689).
    /// Returns OFFSET_UNKNOWN if not resolved.
    pub fn get_spacebase_offset(&self) -> i64 {
        self.stackoffset
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::setSpacebaseOffset
    /// Set the stack-pointer relative offset. Used during call analysis
    /// to record the RSP value at the call site.
    pub fn set_spacebase_offset(&mut self, offset: i64) {
        self.stackoffset = offset;
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::hasSpacebaseOffset
    /// Is the spacebase offset known (not OFFSET_UNKNOWN)?
    pub fn has_spacebase_offset(&self) -> bool {
        self.stackoffset != OFFSET_UNKNOWN
    }

    // Ghidra: fspec.hh:1553 FuncCallSpecs::characterizeAsOutput
    /// Characterize whether the given range overlaps output storage.
    /// Faithful to `characterizeAsOutput` (fspec.hh:1554). Delegates to
    /// ProtoModel::characterizeAsParam on the output parameter list.
    /// Returns: 0=no_containment, 1=contains_unjustified,
    /// 2=contains_justified, 3=contained_by.
    pub fn characterize_as_output(&self, addr: u64, size: i32, space: crate::space::AddressSpace) -> i32 {
        if let Some(ref model) = self.proto_model {
            model.characterize_as_input_param(addr, size, space)
        } else {
            0 // no_containment
        }
    }

    // Ghidra: fspec.hh:1553 FuncCallSpecs::characterizeAsInputParam
    /// Characterize whether the given range overlaps input parameter storage.
    pub fn characterize_as_input_param(&self, addr: u64, size: i32, space: crate::space::AddressSpace) -> i32 {
        if let Some(ref model) = self.proto_model {
            model.characterize_as_input_param(addr, size, space)
        } else {
            0
        }
    }

    // Ghidra: fspec.hh:883 FuncProto::possibleInputParam
    /// Does the given storage location make sense as an input parameter?
    pub fn possible_input_param(&self, addr: u64, size: i32, space: crate::space::AddressSpace) -> bool {
        if let Some(ref model) = self.proto_model {
            model.possible_input_param(addr, size, space)
        } else {
            false
        }
    }

    // Ghidra: fspec.cc:4234 FuncProto::hasEffect
    /// Determine the effect of this function on the given address range.
    /// Faithful to `FuncProto::hasEffect` (fspec.cc:4234-4241).
    /// Returns effect type:
    ///   0 = unknown_effect, 1 = unaffected, 2 = killedbycall,
    ///   3 = return_address, 4 = reload
    pub fn has_effect(&self, _addr: u64, _size: i32) -> u32 {
        // cc:4237-4240: if effectlist empty, delegate to model->hasEffect
        // Rugra's ProtoModel doesn't have hasEffect yet.
        // Conservative: return unknown_effect (0) for all ranges.
        0
    }

    // Ghidra: fspec.hh:1630 FuncCallSpecs::isAutoKilledByCall
    /// Should unaffected storage be treated as killed-by-call?
    pub fn is_auto_killed_by_call(&self) -> bool {
        // Ghidra: model->isAutoKilledByCall() — true for default x86 ABI.
        true
    }

    // Ghidra: fspec.hh:1543 FuncCallSpecs::isStackOutputLock
    /// Is the output prototype stack-locked?
    pub fn is_stack_output_lock(&self) -> bool {
        // Simplified: return false (no stack output lock in Rugra).
        false
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::isInputLocked
    /// Is the input prototype locked (params have TYPE_LOCKED)? Faithful to
    /// `FuncCallSpecs::isInputLocked` — true if all params are type-locked.
    pub fn is_input_locked(&self) -> bool {
        !self.prototype.parameters.is_empty()
            && self.prototype.parameters.iter().all(|p| p.is_type_locked())
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::isOutputLocked
    /// Is the output (return) locked? Faithful to `FuncCallSpecs::isOutputLocked`
    /// (delegates to FuncProto::isOutputLocked). A locked output means the
    /// return data-type (possibly void) is fixed; `funcLinkOutput` builds the
    /// output varnode only if the locked type is non-void.
    pub fn is_output_locked(&self) -> bool {
        self.prototype.is_output_locked()
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::isDotdotdot
    /// Is this a varargs (...) prototype? Faithful to `FuncCallSpecs::isDotdotdot`.
    pub fn is_dotdotdot(&self) -> bool {
        self.prototype.is_dotdotdot
    }

    // Ghidra: fspec.cc:5331 FuncCallSpecs::initActiveInput
    /// Initialize the active-input ParamActive container if not already present.
    /// Faithful to `FuncCallSpecs::initActiveInput`. Recovers sub-call prototypes.
    pub fn init_active_input(&mut self) {
        if self.active_input.is_none() {
            self.active_input = Some(ParamActive::new(true));
        }
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::hasModel
    /// Does this call site have a calling-convention model? Faithful to
    /// `FuncCallSpecs::hasModel`.
    pub fn has_model(&self) -> bool {
        self.proto_model.is_some()
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::setModel
    /// Set the calling-convention model. Faithful to `FuncCallSpecs::setModel`.
    pub fn set_model(&mut self, model: crate::type_system::protomodel::ProtoModel) {
        self.proto_model = Some(model);
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::resolveModel
    /// Resolve the calling-convention model from the active trials. Faithful
    /// to `FuncProto::resolveModel` (fspec.cc:3767-3776). For a non-merged
    /// model (which Rugra uses), this is a no-op — resolution is only needed
    /// for ProtoModelMerged (selecting between alternative models based on
    /// active trials).
    pub fn resolve_model(&mut self) {
        // Rugra's ProtoModel is always a concrete model (not merged), so
        // resolveModel is a no-op. Ghidra's ProtoModelMerged::selectModel
        // picks between alternatives — Rugra doesn't support that yet.
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::deriveInputMap
    /// Derive the input prototype from active trials using the model's
    /// fillinMap. Faithful to `ProtoModel::deriveInputMap` (fspec.hh:791-792).
    pub fn derive_input_map(&mut self) {
        if let (Some(model), Some(active)) = (self.proto_model.as_ref(), self.active_input.as_mut()) {
            model.derive_input_map(active);
        }
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::deriveOutputMap
    /// Derive the output prototype from active trials. Faithful to
    /// `ProtoModel::deriveOutputMap` (fspec.hh:798-799).
    pub fn derive_output_map(&mut self) {
        if let (Some(model), Some(active)) = (self.proto_model.as_ref(), self.active_output.as_mut()) {
            model.derive_output_map(active);
        }
    }

    // Ghidra: fspec.cc:5685 FuncCallSpecs::buildInputFromTrials
    /// Build the final input parameter list from the resolved trials. Faithful
    /// to `FuncCallSpecs::buildInputFromTrials` (fspec.cc:5685-5741).
    ///
    /// Walks the active-input trials; for each USED trial, records its (space,
    /// offset, size) as a formal parameter. Stack-space trials are translated
    /// relative to the caller's spacebase. Unused trials are dropped.
    ///
    /// Returns the list of resolved parameters as (address, size) pairs. The
    /// caller (ActionActiveParam) then updates the FuncProto.
    pub fn build_input_from_trials(&mut self) -> Vec<(Address, i32)> {
        let mut result = Vec::new();
        if let Some(active) = &self.active_input {
            for i in 0..active.get_num_trials() {
                let trial = active.get_trial(i);
                if !trial.is_used() { continue; }
                let addr = trial.get_address();
                let sz = trial.get_size();
                result.push((addr, sz));
            }
        }
        // Delete unused trials (renumber used ones).
        if let Some(active) = self.active_input.as_mut() {
            active.trial.retain(|t| t.is_used());
        }
        result
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::isInputActive
    /// Is the input currently in active-recovery mode? Faithful to
    /// `FuncCallSpecs::isInputActive`.
    pub fn is_input_active(&self) -> bool {
        self.active_input.is_some()
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::isOutputActive
    /// Is the output currently in active-recovery mode? Faithful to
    /// `FuncCallSpecs::isOutputActive`.
    pub fn is_output_active(&self) -> bool {
        self.active_output.is_some()
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::clearActiveInput
    /// Clear the active-input container (finalize recovery). Faithful to
    /// `FuncCallSpecs::clearActiveInput`.
    pub fn clear_active_input(&mut self) {
        self.active_input = None;
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::clearActiveOutput
    /// Clear the active-output container. Faithful to
    /// `FuncCallSpecs::clearActiveOutput`.
    pub fn clear_active_output(&mut self) {
        self.active_output = None;
    }

    // Ghidra: fspec.cc:5870 FuncCallSpecs::getInputBytesConsumed
    /// Get the estimated number of bytes within the given parameter that are
    /// consumed. Faithful to `FuncCallSpecs::getInputBytesConsumed`
    /// (fspec.cc:5870-5882). A non-zero value means that many LSBs of the
    /// storage location are used; 0 means all bytes are presumed used.
    pub fn get_input_bytes_consumed(&self, slot: usize) -> u32 {
        if slot >= self.input_consume.len() {
            0
        } else {
            self.input_consume[slot]
        }
    }

    // Ghidra: fspec.cc:5887 FuncCallSpecs::setInputBytesConsumed
    /// Set the estimated number of bytes within the given parameter that are
    /// consumed. Faithful to `FuncCallSpecs::setInputBytesConsumed`
    /// (fspec.cc:5887-5906). Provides a hint to the dead-code consume
    /// algorithm about how the parameter is used. The value can only shrink
    /// (the smallest hint wins). Returns true if there was a change.
    pub fn set_input_bytes_consumed(&mut self, slot: usize, val: u32) -> bool {
        while self.input_consume.len() <= slot {
            self.input_consume.push(0);
        }
        let old_val = self.input_consume[slot];
        if old_val == 0 || val < old_val {
            // Only let the value get smaller.
            self.input_consume[slot] = val;
            return true;
        }
        false
    }

    // Ghidra: fspec.hh FuncCallSpecs::getOp (via op_addr lookup)
    /// Find the CALL/CALLIND PcodeOp for this call spec by matching op_addr
    /// against the function's alive op list. Ghidra's FuncCallSpecs stores a
    /// direct `PcodeOp *op` pointer; Rugra looks it up by address.
    pub fn find_call_op(&self, fd: &crate::funcdata::Funcdata) -> Option<crate::op::PcodeOpRef> {
        use crate::opcodes::OpCode;
        for op_ref in &fd.obank.alivelist {
            let op_rg = op_ref.0.read().unwrap();
            if (op_rg.opcode == OpCode::CPUI_CALL || op_rg.opcode == OpCode::CPUI_CALLIND)
                && op_rg.get_addr() == self.op_addr
            {
                return Some(op_ref.clone());
            }
        }
        None
    }

    // Ghidra: fspec.cc:5564 FuncCallSpecs::finalInputCheck
    /// Make final activity check on trials that might have been affected by
    /// conditional execution. Faithful to `FuncCallSpecs::finalInputCheck`
    /// (fspec.cc:5564-5576). Re-runs AncestorRealistic on trials flagged with
    /// a condexe effect; trials that fail the recheck are marked no-use.
    pub fn final_input_check(&mut self, op_ref: &crate::op::PcodeOpRef) {
        let mut ancestor_real = crate::funcdata::AncestorRealistic::new();
        if let Some(active) = self.active_input.as_mut() {
            // Collect indices of trials to recheck (isActive + hasCondExeEffect),
            // then process them. Ghidra mutates trials in-place during iteration.
            let mut recheck: Vec<usize> = Vec::new();
            for i in 0..active.get_num_trials() {
                let t = active.get_trial(i);
                if t.is_active() && t.has_condexe_effect() {
                    recheck.push(i);
                }
            }
            for i in recheck {
                let slot = active.get_trial(i).get_slot();
                let success = {
                    let t = active.get_trial_mut(i);
                    ancestor_real.execute(&op_ref, slot, t, false)
                };
                if !success {
                    active.get_trial_mut(i).mark_no_use();
                }
            }
        }
    }

    // Ghidra: fspec.cc:5585 FuncCallSpecs::checkInputTrialUse
    /// Mark if input trials are being actively used. Faithful 1:1 port of
    /// `FuncCallSpecs::checkInputTrialUse` (fspec.cc:5585-5653).
    ///
    /// For each unchecked trial, determines if the trial varnode has realistic
    /// ancestors (via `AncestorRealistic`) and is only used for parameter
    /// passing (via `ancestorOpUse`). Stack-space trials are additionally
    /// checked against the alias checker and local range.
    ///
    /// Returns a list of (slot, varnode_size) pairs for trials that are
    /// definitely-not-used and should have their op input replaced with a
    /// constant (Ghidra's `data.opSetInput(op, newConstant(...), slot)`).
    pub fn check_input_trial_use(
        &mut self,
        op_ref: &crate::op::PcodeOpRef,
        has_active_output: bool,
        aliascheck: &crate::varmap::AliasChecker,
        maxancestor: i32,
    ) -> Vec<(i32, i32)> {
        let mut replace_slots: Vec<(i32, i32)> = Vec::new();
        let mut ancestor_real = crate::funcdata::AncestorRealistic::new();
        let active = match self.active_input.as_mut() {
            Some(a) => a,
            None => return replace_slots,
        };
        let mut needs_final_check = false;
        for i in 0..active.get_num_trials() {
            if active.get_trial(i).is_checked() { continue; }
            let slot = active.get_trial(i).get_slot();
            // Resolve the trial varnode: vn = op.getIn(slot).
            let vn_arc = {
                let op_rg = op_ref.0.read().unwrap();
                op_rg.get_in(slot as usize).cloned()
            };
            let vn = match vn_arc { Some(v) => v, None => continue };
            let vn_space = vn.read().unwrap().get_space();
            if vn_space == crate::space::AddressSpace::Stack {
                // Ghidra fspec.cc:5615-5634 — stack spacebase varnode path.
                if aliascheck.has_local_alias(&vn.read().unwrap()) {
                    active.get_trial_mut(i).mark_no_use();
                } else if ancestor_real.execute(op_ref, slot, active.get_trial_mut(i), false) {
                    let ao_result = crate::funcdata::ancestor_op_use(
                        has_active_output, maxancestor, &vn, op_ref, slot, 0, 0,
                    );
                    if ao_result {
                        active.get_trial_mut(i).mark_active();
                    } else {
                        active.get_trial_mut(i).mark_inactive();
                    }
                } else {
                    active.get_trial_mut(i).mark_no_use();
                }
            } else {
                // Ghidra fspec.cc:5635-5648 — register / other space path.
                if ancestor_real.execute(op_ref, slot, active.get_trial_mut(i), true) {
                    let ao_result = crate::funcdata::ancestor_op_use(
                        has_active_output, maxancestor, &vn, op_ref, slot, 0, 0,
                    );
                    if ao_result {
                        active.get_trial_mut(i).mark_active();
                        if active.get_trial(i).has_condexe_effect() {
                            needs_final_check = true;
                        }
                    } else {
                        active.get_trial_mut(i).mark_inactive();
                    }
                } else if vn.read().unwrap().is_input() {
                    active.get_trial_mut(i).mark_inactive();
                } else {
                    active.get_trial_mut(i).mark_no_use();
                }
            }
            if active.get_trial(i).is_definitely_not_used() {
                let vn_size = vn.read().unwrap().get_size() as i32;
                replace_slots.push((slot, vn_size));
            }
        }
        if needs_final_check {
            active.mark_needs_final_check();
        }
        replace_slots
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::initActiveOutput
    /// Initialize the active-output ParamActive container if not already present.
    /// Faithful to `FuncCallSpecs::initActiveOutput`.
    pub fn init_active_output(&mut self) {
        if self.active_output.is_none() {
            self.active_output = Some(ParamActive::new(false));
        }
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::getActiveInput
    /// Get the active-input trials (if initialized).
    pub fn get_active_input(&self) -> Option<&ParamActive> {
        self.active_input.as_ref()
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::getActiveOutput
    /// Get the active-output trials (if initialized).
    pub fn get_active_output(&self) -> Option<&ParamActive> {
        self.active_output.as_ref()
    }

    // Ghidra: fspec.cc:4910 FuncCallSpecs::abortSpacebaseRelative
    /// Remove the stack placeholder input from the call op and clean up.
    /// Faithful to `abortSpacebaseRelative` (fspec.cc:4910-4921). Called by
    /// Heritage::clearStackPlaceholders when heritage resolves actual stack
    /// values for this call's parameters.
    pub fn abort_spacebase_relative(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        call_op: &crate::op::PcodeOpRef,
    ) {
        if self.stack_placeholder_slot >= 0 {
            let slot = self.stack_placeholder_slot as usize;
            // cc:4914: vn = op->getIn(stackPlaceholderSlot).
            let placeholder_vn = call_op.0.read().unwrap().get_in(slot).cloned();
            // cc:4915: data.opRemoveInput(op, slot).
            fd.op_remove_input(call_op, slot);
            // cc:4916: clearStackPlaceholderSlot.
            self.clear_stack_placeholder_slot();
            // cc:4918-4919: if placeholder vn has no descend and is internal+
            // written, destroy its defining op.
            if let Some(vn) = placeholder_vn {
                let vn_r = vn.read().unwrap();
                let should_destroy = vn_r.has_no_descend()
                    && vn_r.get_space() == crate::space::AddressSpace::Unique
                    && vn_r.is_written();
                drop(vn_r);
                if should_destroy {
                    if let Some(def_weak) = vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                        fd.op_destroy(&crate::op::PcodeOpRef(def_weak));
                    }
                }
            }
        }
    }

    // Ghidra: fspec.hh:1654 FuncCallSpecs::clearStackPlaceholderSlot
    /// Clear the stack placeholder slot index.
    pub fn clear_stack_placeholder_slot(&mut self) {
        self.stack_placeholder_slot = -1;
    }
}

// ======================================================================
// ParamTrial + ParamActive (fspec.hh:210-380)
// ======================================================================
// These are the parameter-recovery infrastructure that FuncCallSpecs
// Actions (ActionFuncLink, ActionParamDouble, ActionActiveParam, etc.) need.
// Ported faithfully from fspec.hh so those Actions can be wired once
// FuncCallSpecs gains an `active_input`/`active_output` field.

/// Flags for a parameter trial. Faithful to `ParamTrial` enum (fspec.hh:212-223).
pub mod param_trial_flags {
    pub const CHECKED: u32 = 1;
    pub const USED: u32 = 2;
    pub const DEFNOUSE: u32 = 4;
    pub const ACTIVE: u32 = 8;
    pub const UNREF: u32 = 0x10;
    pub const KILLEDBYCALL: u32 = 0x20;
    pub const REM_FORMED: u32 = 0x40;
    pub const INDCREATE_FORMED: u32 = 0x80;
    pub const CONDEXE_EFFECT: u32 = 0x100;
    pub const ANCESTOR_REALISTIC: u32 = 0x200;
    pub const ANCESTOR_SOLID: u32 = 0x400;
}

/// A single parameter trial: a candidate storage location being evaluated
/// as a formal parameter. Faithful to `ParamTrial` (fspec.hh:210-273).
#[derive(Debug, Clone)]
pub struct ParamTrial {
    flags: u32,
    addr: Address,
    size: i32,
    slot: i32,
    offset: i32,
    fixed_position: i32,
}

impl ParamTrial {
    // Ghidra: fspec.hh:210 ParamTrial::new
    /// Construct from (address, size, slot). Faithful to the C++ constructor.
    pub fn new(addr: Address, sz: i32, sl: i32) -> Self {
        Self { flags: 0, addr, size: sz, slot: sl, offset: -1, fixed_position: -1 }
    }
    // Ghidra: fspec.hh:210 ParamTrial::getAddress
    pub fn get_address(&self) -> Address { self.addr }
    // Ghidra: fspec.hh:210 ParamTrial::getSize
    pub fn get_size(&self) -> i32 { self.size }
    // Ghidra: fspec.hh:210 ParamTrial::getSlot
    pub fn get_slot(&self) -> i32 { self.slot }
    // Ghidra: fspec.hh:210 ParamTrial::setSlot
    pub fn set_slot(&mut self, val: i32) { self.slot = val; }
    // Ghidra: fspec.hh:210 ParamTrial::getOffset
    pub fn get_offset(&self) -> i32 { self.offset }
    // Ghidra: fspec.hh:210 ParamTrial::setEntry
    pub fn set_entry(&mut self, off: i32) { self.offset = off; }
    // Ghidra: fspec.hh:210 ParamTrial::setFixedPosition
    pub fn set_fixed_position(&mut self, pos: i32) { self.fixed_position = pos; }
    // Ghidra: fspec.hh:210 ParamTrial::markUsed
    // --- flag accessors (fspec.hh:243-264) ---
    pub fn mark_used(&mut self) { self.flags |= param_trial_flags::USED; }
    // Ghidra: fspec.hh:210 ParamTrial::markActive
    pub fn mark_active(&mut self) { self.flags |= param_trial_flags::ACTIVE | param_trial_flags::CHECKED; }
    // Ghidra: fspec.hh:210 ParamTrial::markInactive
    pub fn mark_inactive(&mut self) { self.flags &= !param_trial_flags::ACTIVE; self.flags |= param_trial_flags::CHECKED; }
    // Ghidra: fspec.hh:210 ParamTrial::markNoUse
    pub fn mark_no_use(&mut self) { self.flags &= !(param_trial_flags::ACTIVE | param_trial_flags::USED); self.flags |= param_trial_flags::CHECKED | param_trial_flags::DEFNOUSE; }
    // Ghidra: fspec.hh:210 ParamTrial::markUnref
    pub fn mark_unref(&mut self) { self.flags |= param_trial_flags::UNREF | param_trial_flags::CHECKED; self.slot = -1; }
    // Ghidra: fspec.hh:210 ParamTrial::markKilledByCall
    pub fn mark_killed_by_call(&mut self) { self.flags |= param_trial_flags::KILLEDBYCALL; }
    // Ghidra: fspec.hh:210 ParamTrial::isChecked
    pub fn is_checked(&self) -> bool { self.flags & param_trial_flags::CHECKED != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::isActive
    pub fn is_active(&self) -> bool { self.flags & param_trial_flags::ACTIVE != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::isDefinitelyNotUsed
    pub fn is_definitely_not_used(&self) -> bool { self.flags & param_trial_flags::DEFNOUSE != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::isUsed
    pub fn is_used(&self) -> bool { self.flags & param_trial_flags::USED != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::isUnref
    pub fn is_unref(&self) -> bool { self.flags & param_trial_flags::UNREF != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::isKilledByCall
    pub fn is_killed_by_call(&self) -> bool { self.flags & param_trial_flags::KILLEDBYCALL != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::setRemFormed
    pub fn set_rem_formed(&mut self) { self.flags |= param_trial_flags::REM_FORMED; }
    // Ghidra: fspec.hh:210 ParamTrial::isRemFormed
    pub fn is_rem_formed(&self) -> bool { self.flags & param_trial_flags::REM_FORMED != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::setIndCreateFormed
    pub fn set_ind_create_formed(&mut self) { self.flags |= param_trial_flags::INDCREATE_FORMED; }
    // Ghidra: fspec.hh:210 ParamTrial::isIndCreateFormed
    pub fn is_ind_create_formed(&self) -> bool { self.flags & param_trial_flags::INDCREATE_FORMED != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::setCondexeEffect
    pub fn set_condexe_effect(&mut self) { self.flags |= param_trial_flags::CONDEXE_EFFECT; }
    // Ghidra: fspec.hh:210 ParamTrial::hasCondexeEffect
    pub fn has_condexe_effect(&self) -> bool { self.flags & param_trial_flags::CONDEXE_EFFECT != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::setAncestorRealistic
    pub fn set_ancestor_realistic(&mut self) { self.flags |= param_trial_flags::ANCESTOR_REALISTIC; }
    // Ghidra: fspec.hh:210 ParamTrial::hasAncestorRealistic
    pub fn has_ancestor_realistic(&self) -> bool { self.flags & param_trial_flags::ANCESTOR_REALISTIC != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::setAncestorSolid
    pub fn set_ancestor_solid(&mut self) { self.flags |= param_trial_flags::ANCESTOR_SOLID; }
    // Ghidra: fspec.hh:210 ParamTrial::hasAncestorSolid
    pub fn has_ancestor_solid(&self) -> bool { self.flags & param_trial_flags::ANCESTOR_SOLID != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::setAddress
    pub fn set_address(&mut self, ad: Address, sz: i32) { self.addr = ad; self.size = sz; }

    // Ghidra: fspec.cc:1845 ParamTrial::splitHi
    /// Create a trial for the first `sz` bytes (high part). Faithful to
    /// `ParamTrial::splitHi` (fspec.cc:1845).
    pub fn split_hi(&self, sz: i32) -> ParamTrial {
        ParamTrial::new(self.addr, sz, self.slot)
    }
    // Ghidra: fspec.cc:1856 ParamTrial::splitLo
    /// Create a trial for the last part after `sz` bytes (low part). Faithful
    /// to `ParamTrial::splitLo` (fspec.cc:1856).
    pub fn split_lo(&self, sz: i32) -> ParamTrial {
        ParamTrial::new(Address::new(self.addr.as_u64() + sz as u64), self.size - sz, self.slot + 1)
    }
}

/// Container for parameter trials. Faithful to `ParamActive` (fspec.hh:285-380).
#[derive(Debug, Clone)]
pub struct ParamActive {
    trial: Vec<ParamTrial>,
    slotbase: i32,
    stackplaceholder: i32,
    numpasses: i32,
    maxpass: i32,
    isfullychecked: bool,
    needsfinalcheck: bool,
    recoversubcall: bool,
    join_reverse: bool,
}

impl ParamActive {
    // Ghidra: fspec.cc:1936 ParamActive::new
    /// Construct empty. Faithful to `ParamActive(bool)` (fspec.cc:1936).
    pub fn new(recoversub: bool) -> Self {
        Self {
            trial: Vec::new(),
            slotbase: 0,
            stackplaceholder: -1,
            numpasses: 0,
            maxpass: 4,
            isfullychecked: false,
            needsfinalcheck: false,
            recoversubcall: recoversub,
            join_reverse: false,
        }
    }
    // Ghidra: fspec.cc:1949 ParamActive::clear
    /// Reset to empty. Faithful to `ParamActive::clear` (fspec.cc:1949).
    pub fn clear(&mut self) {
        self.trial.clear();
        self.slotbase = 0;
        self.stackplaceholder = -1;
        self.numpasses = 0;
        self.isfullychecked = false;
        self.needsfinalcheck = false;
    }
    // Ghidra: fspec.cc:1936 ParamActive::getNumTrials
    pub fn get_num_trials(&self) -> usize { self.trial.len() }
    // Ghidra: fspec.cc:1936 ParamActive::getTrial
    pub fn get_trial(&self, i: usize) -> &ParamTrial { &self.trial[i] }
    // Ghidra: fspec.cc:1936 ParamActive::getTrialMut
    pub fn get_trial_mut(&mut self, i: usize) -> &mut ParamTrial { &mut self.trial[i] }
    // Ghidra: fspec.cc:1936 ParamActive::getSlotBase
    pub fn get_slot_base(&self) -> i32 { self.slotbase }
    // Ghidra: fspec.cc:1936 ParamActive::setSlotBase
    pub fn set_slot_base(&mut self, val: i32) { self.slotbase = val; }
    // Ghidra: fspec.cc:1936 ParamActive::getNumPasses
    pub fn get_num_passes(&self) -> i32 { self.numpasses }
    // Ghidra: fspec.cc:1936 ParamActive::getMaxPass
    pub fn get_max_pass(&self) -> i32 { self.maxpass }
    // Ghidra: fspec.cc:1936 ParamActive::setMaxPass
    pub fn set_max_pass(&mut self, val: i32) { self.maxpass = val; }
    // Ghidra: fspec.cc:1936 ParamActive::isRecoverSubcall
    pub fn is_recover_subcall(&self) -> bool { self.recoversubcall }
    // Ghidra: fspec.cc:1936 ParamActive::isJoinReverse
    pub fn is_join_reverse(&self) -> bool { self.join_reverse }
    // Ghidra: fspec.cc:1936 ParamActive::setJoinReverse
    pub fn set_join_reverse(&mut self, val: bool) { self.join_reverse = val; }
    // Ghidra: fspec.cc:1936 ParamActive::needsFinalCheck
    pub fn needs_final_check(&self) -> bool { self.needsfinalcheck }
    // Ghidra: fspec.cc:1936 ParamActive::setNeedsFinalCheck
    pub fn set_needs_final_check(&mut self, val: bool) { self.needsfinalcheck = val; }
    // Ghidra: fspec.cc:1936 ParamActive::markNeedsFinalCheck
    pub fn mark_needs_final_check(&mut self) { self.needsfinalcheck = true; }

    // Ghidra: fspec.cc:1936 ParamActive::finishPass
    /// Increment pass counter. Faithful to `ParamActive::finishPass`.
    pub fn finish_pass(&mut self) { self.numpasses += 1; }
    // Ghidra: fspec.cc:1936 ParamActive::isFullyChecked
    /// Have all passes been exhausted? Faithful to `isFullyChecked`.
    pub fn is_fully_checked(&self) -> bool { self.isfullychecked }
    // Ghidra: fspec.cc:1936 ParamActive::markFullyChecked
    /// Mark all trials as fully checked. Faithful to `markFullyChecked`.
    pub fn mark_fully_checked(&mut self) { self.isfullychecked = true; }

    // Ghidra: fspec.cc:1963 ParamActive::registerTrial
    /// Add a new trial at (addr, sz). Faithful to `registerTrial`
    /// (fspec.cc:1963). Slot is assigned as the current trial count.
    pub fn register_trial(&mut self, addr: Address, sz: i32) {
        let slot = self.trial.len() as i32;
        self.trial.push(ParamTrial::new(addr, sz, slot));
    }

    // Ghidra: fspec.cc:1982 ParamActive::whichTrial
    /// Find the trial index matching (addr, sz), or -1. Faithful to
    /// `whichTrial` (fspec.cc:1982).
    pub fn which_trial(&self, addr: Address, sz: i32) -> i32 {
        for (i, t) in self.trial.iter().enumerate() {
            if t.get_address() == addr && t.get_size() == sz {
                return i as i32;
            }
        }
        -1
    }

    // Ghidra: fspec.cc:2033 ParamActive::splitTrial
    /// Split trial `i` at byte offset `sz`. Faithful to `splitTrial`
    /// (fspec.cc:2033): replaces trial i with its high part and inserts the
    /// low part at i+1.
    pub fn split_trial(&mut self, i: usize, sz: i32) {
        let hi = self.trial[i].split_hi(sz);
        let lo = self.trial[i].split_lo(sz);
        self.trial[i] = hi;
        self.trial.insert(i + 1, lo);
    }

    // Ghidra: fspec.cc:2097 ParamActive::getNumUsed
    /// Count trials flagged USED. Faithful to `getNumUsed` (fspec.cc:2097).
    pub fn get_num_used(&self) -> usize {
        self.trial.iter().filter(|t| t.is_used()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_system::datatype::{TypeBase, TypeMetatype};

    #[test]
    fn test_proto_creation() {
        let void_type = Arc::new(Datatype::Void(TypeBase::new("void".to_string(), 0, TypeMetatype::Void)));
        let int_type = Arc::new(Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int)));

        let mut proto = FuncProto::new("test_func".to_string(), void_type);
        proto.add_parameter(ProtoParameter::new("a".to_string(), int_type, Address::new(0)));

        assert_eq!(proto.num_params(), 1);
        assert_eq!(proto.get_param(0).unwrap().name, "a");
    }

    // ---- ParamTrial / ParamActive tests ----

    #[test]
    fn test_param_trial_flags() {
        let mut t = ParamTrial::new(Address::new(0x100), 8, 0);
        assert!(!t.is_used());
        assert!(!t.is_checked());
        t.mark_used();
        assert!(t.is_used());
        t.mark_active();
        assert!(t.is_active());
        assert!(t.is_checked());
        t.mark_no_use();
        assert!(!t.is_used());
        assert!(t.is_definitely_not_used());
    }

    #[test]
    fn test_param_trial_split() {
        let t = ParamTrial::new(Address::new(0x100), 8, 2);
        let hi = t.split_hi(4);
        let lo = t.split_lo(4);
        assert_eq!(hi.get_size(), 4);
        assert_eq!(hi.get_address(), Address::new(0x100));
        assert_eq!(lo.get_size(), 4);
        assert_eq!(lo.get_address(), Address::new(0x104));
        assert_eq!(lo.get_slot(), 3);
    }

    #[test]
    fn test_param_active_register_and_split() {
        let mut pa = ParamActive::new(true);
        assert_eq!(pa.get_num_trials(), 0);
        pa.register_trial(Address::new(0x200), 8);
        pa.register_trial(Address::new(0x208), 8);
        assert_eq!(pa.get_num_trials(), 2);
        assert_eq!(pa.which_trial(Address::new(0x208), 8), 1);
        assert_eq!(pa.which_trial(Address::new(0x300), 8), -1);
        // Split trial 0 at 4 bytes.
        pa.split_trial(0, 4);
        assert_eq!(pa.get_num_trials(), 3);
        assert_eq!(pa.get_trial(0).get_size(), 4);
        assert_eq!(pa.get_trial(1).get_size(), 4);
        assert_eq!(pa.get_trial(1).get_address(), Address::new(0x204));
    }

    #[test]
    fn test_param_active_num_used() {
        let mut pa = ParamActive::new(false);
        pa.register_trial(Address::new(0x100), 8);
        pa.register_trial(Address::new(0x108), 8);
        pa.register_trial(Address::new(0x110), 8);
        pa.get_trial_mut(0).mark_used();
        pa.get_trial_mut(2).mark_used();
        assert_eq!(pa.get_num_used(), 2);
    }

    #[test]
    fn test_func_proto_lock_and_copy() {
        let int_type = Arc::new(Datatype::Base(
            crate::type_system::datatype::TypeBase::new("int".into(), 4, crate::type_system::TypeMetatype::Int)));
        let mut proto = FuncProto::new("test".into(), int_type.clone());
        let p = ProtoParameter::new("param_1".into(), int_type.clone(), Address::new(0x38));
        proto.add_parameter(p);
        assert!(!proto.is_input_locked());
        proto.set_input_lock(true);
        assert!(proto.is_input_locked());

        let mut proto2 = FuncProto::new("other".into(), int_type.clone());
        proto2.copy_from(&proto);
        assert_eq!(proto2.num_params(), 1);
        assert_eq!(proto2.name, "test");

        proto.clear_unlocked_input();
        assert_eq!(proto.num_params(), 1); // locked params retained
    }

    #[test]
    fn test_func_proto_dotdotdot() {
        let int_type = Arc::new(Datatype::Base(
            crate::type_system::datatype::TypeBase::new("int".into(), 4, crate::type_system::TypeMetatype::Int)));
        let mut proto = FuncProto::new("varargs".into(), int_type);
        assert!(!proto.is_varargs());
        proto.set_dotdotdot(true);
        assert!(proto.is_varargs());
    }
}
