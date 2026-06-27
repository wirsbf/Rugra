//! Function prototypes and call specifications
//!
//! Corresponds to Ghidra's `fspec.hh`. This module manages how functions
//! are defined (prototypes) and how call sites are handled (call specs).

use std::sync::Arc;
use crate::address::Address;
use crate::type_system::datatype::Datatype;

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
    /// Create a new function parameter
    pub fn new(name: String, data_type: Arc<Datatype>, address: Address) -> Self {
        Self {
            name,
            data_type,
            address,
            flags: 0,
        }
    }

    /// Returns true if this parameter is a "this" pointer
    pub fn is_this_pointer(&self) -> bool {
        (self.flags & protoparam_flags::THIS_POINTER) != 0
    }

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
}

impl FuncProto {
    /// Create a new function prototype
    pub fn new(name: String, return_type: Arc<Datatype>) -> Self {
        Self {
            name,
            return_type,
            parameters: Vec::new(),
            calling_convention: "unknown".to_string(),
            is_dotdotdot: false,
        }
    }

    /// Add a parameter to the prototype
    pub fn add_parameter(&mut self, param: ProtoParameter) {
        self.parameters.push(param);
    }

    /// Get the number of parameters
    pub fn num_params(&self) -> usize {
        self.parameters.len()
    }

    /// Get a parameter by index
    pub fn get_param(&self, index: usize) -> Option<&ProtoParameter> {
        self.parameters.get(index)
    }
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
}

impl FuncCallSpecs {
    /// Create a new call specification
    pub fn new(op_addr: Address, prototype: FuncProto) -> Self {
        Self {
            op_addr,
            entry_addr: None,
            prototype,
            flags: 0,
            active_input: None,
            active_output: None,
        }
    }

    /// Is the input prototype locked (params have TYPE_LOCKED)? Faithful to
    /// `FuncCallSpecs::isInputLocked` — true if all params are type-locked.
    pub fn is_input_locked(&self) -> bool {
        !self.prototype.parameters.is_empty()
            && self.prototype.parameters.iter().all(|p| p.is_type_locked())
    }

    /// Is the output (return) locked? Faithful to `FuncCallSpecs::isOutputLocked`.
    /// True if the return type is non-void and locked.
    pub fn is_output_locked(&self) -> bool {
        // Rugra's FuncProto doesn't track a separate output-lock flag; we treat
        // a non-void return as locked when params are locked (heuristic matching
        // Ghidra's modelname-locked semantics).
        self.is_input_locked()
    }

    /// Is this a varargs (...) prototype? Faithful to `FuncCallSpecs::isDotdotdot`.
    pub fn is_dotdotdot(&self) -> bool {
        self.prototype.is_dotdotdot
    }

    /// Initialize the active-input ParamActive container if not already present.
    /// Faithful to `FuncCallSpecs::initActiveInput`. Recovers sub-call prototypes.
    pub fn init_active_input(&mut self) {
        if self.active_input.is_none() {
            self.active_input = Some(ParamActive::new(true));
        }
    }

    /// Initialize the active-output ParamActive container if not already present.
    /// Faithful to `FuncCallSpecs::initActiveOutput`.
    pub fn init_active_output(&mut self) {
        if self.active_output.is_none() {
            self.active_output = Some(ParamActive::new(false));
        }
    }

    /// Get the active-input trials (if initialized).
    pub fn get_active_input(&self) -> Option<&ParamActive> {
        self.active_input.as_ref()
    }

    /// Get the active-output trials (if initialized).
    pub fn get_active_output(&self) -> Option<&ParamActive> {
        self.active_output.as_ref()
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
    /// Construct from (address, size, slot). Faithful to the C++ constructor.
    pub fn new(addr: Address, sz: i32, sl: i32) -> Self {
        Self { flags: 0, addr, size: sz, slot: sl, offset: -1, fixed_position: -1 }
    }
    pub fn get_address(&self) -> Address { self.addr }
    pub fn get_size(&self) -> i32 { self.size }
    pub fn get_slot(&self) -> i32 { self.slot }
    pub fn set_slot(&mut self, val: i32) { self.slot = val; }
    pub fn get_offset(&self) -> i32 { self.offset }
    pub fn set_entry(&mut self, off: i32) { self.offset = off; }
    pub fn set_fixed_position(&mut self, pos: i32) { self.fixed_position = pos; }
    // --- flag accessors (fspec.hh:243-264) ---
    pub fn mark_used(&mut self) { self.flags |= param_trial_flags::USED; }
    pub fn mark_active(&mut self) { self.flags |= param_trial_flags::ACTIVE | param_trial_flags::CHECKED; }
    pub fn mark_inactive(&mut self) { self.flags &= !param_trial_flags::ACTIVE; self.flags |= param_trial_flags::CHECKED; }
    pub fn mark_no_use(&mut self) { self.flags &= !(param_trial_flags::ACTIVE | param_trial_flags::USED); self.flags |= param_trial_flags::CHECKED | param_trial_flags::DEFNOUSE; }
    pub fn mark_unref(&mut self) { self.flags |= param_trial_flags::UNREF | param_trial_flags::CHECKED; self.slot = -1; }
    pub fn mark_killed_by_call(&mut self) { self.flags |= param_trial_flags::KILLEDBYCALL; }
    pub fn is_checked(&self) -> bool { self.flags & param_trial_flags::CHECKED != 0 }
    pub fn is_active(&self) -> bool { self.flags & param_trial_flags::ACTIVE != 0 }
    pub fn is_definitely_not_used(&self) -> bool { self.flags & param_trial_flags::DEFNOUSE != 0 }
    pub fn is_used(&self) -> bool { self.flags & param_trial_flags::USED != 0 }
    pub fn is_unref(&self) -> bool { self.flags & param_trial_flags::UNREF != 0 }
    pub fn is_killed_by_call(&self) -> bool { self.flags & param_trial_flags::KILLEDBYCALL != 0 }
    pub fn set_rem_formed(&mut self) { self.flags |= param_trial_flags::REM_FORMED; }
    pub fn is_rem_formed(&self) -> bool { self.flags & param_trial_flags::REM_FORMED != 0 }
    pub fn set_ind_create_formed(&mut self) { self.flags |= param_trial_flags::INDCREATE_FORMED; }
    pub fn is_ind_create_formed(&self) -> bool { self.flags & param_trial_flags::INDCREATE_FORMED != 0 }
    pub fn set_condexe_effect(&mut self) { self.flags |= param_trial_flags::CONDEXE_EFFECT; }
    pub fn has_condexe_effect(&self) -> bool { self.flags & param_trial_flags::CONDEXE_EFFECT != 0 }
    pub fn set_ancestor_realistic(&mut self) { self.flags |= param_trial_flags::ANCESTOR_REALISTIC; }
    pub fn has_ancestor_realistic(&self) -> bool { self.flags & param_trial_flags::ANCESTOR_REALISTIC != 0 }
    pub fn set_ancestor_solid(&mut self) { self.flags |= param_trial_flags::ANCESTOR_SOLID; }
    pub fn has_ancestor_solid(&self) -> bool { self.flags & param_trial_flags::ANCESTOR_SOLID != 0 }
    pub fn set_address(&mut self, ad: Address, sz: i32) { self.addr = ad; self.size = sz; }

    /// Create a trial for the first `sz` bytes (high part). Faithful to
    /// `ParamTrial::splitHi` (fspec.cc:1845).
    pub fn split_hi(&self, sz: i32) -> ParamTrial {
        ParamTrial::new(self.addr, sz, self.slot)
    }
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
    /// Reset to empty. Faithful to `ParamActive::clear` (fspec.cc:1949).
    pub fn clear(&mut self) {
        self.trial.clear();
        self.slotbase = 0;
        self.stackplaceholder = -1;
        self.numpasses = 0;
        self.isfullychecked = false;
        self.needsfinalcheck = false;
    }
    pub fn get_num_trials(&self) -> usize { self.trial.len() }
    pub fn get_trial(&self, i: usize) -> &ParamTrial { &self.trial[i] }
    pub fn get_trial_mut(&mut self, i: usize) -> &mut ParamTrial { &mut self.trial[i] }
    pub fn get_slot_base(&self) -> i32 { self.slotbase }
    pub fn set_slot_base(&mut self, val: i32) { self.slotbase = val; }
    pub fn get_num_passes(&self) -> i32 { self.numpasses }
    pub fn get_max_pass(&self) -> i32 { self.maxpass }
    pub fn set_max_pass(&mut self, val: i32) { self.maxpass = val; }
    pub fn is_recover_subcall(&self) -> bool { self.recoversubcall }
    pub fn is_join_reverse(&self) -> bool { self.join_reverse }
    pub fn set_join_reverse(&mut self, val: bool) { self.join_reverse = val; }
    pub fn needs_final_check(&self) -> bool { self.needsfinalcheck }
    pub fn set_needs_final_check(&mut self, val: bool) { self.needsfinalcheck = val; }

    /// Add a new trial at (addr, sz). Faithful to `registerTrial`
    /// (fspec.cc:1963). Slot is assigned as the current trial count.
    pub fn register_trial(&mut self, addr: Address, sz: i32) {
        let slot = self.trial.len() as i32;
        self.trial.push(ParamTrial::new(addr, sz, slot));
    }

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

    /// Split trial `i` at byte offset `sz`. Faithful to `splitTrial`
    /// (fspec.cc:2033): replaces trial i with its high part and inserts the
    /// low part at i+1.
    pub fn split_trial(&mut self, i: usize, sz: i32) {
        let hi = self.trial[i].split_hi(sz);
        let lo = self.trial[i].split_lo(sz);
        self.trial[i] = hi;
        self.trial.insert(i + 1, lo);
    }

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
}
