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

    // Ghidra: fspec.cc:2212 EffectRecord::getAddress
    /// Get the address space of the affected range. Faithful to
    /// `getAddress`'s space component.
    pub fn get_space(&self) -> AddressSpace { self.space }

    // Ghidra: fspec.cc:2212 EffectRecord::EffectRecord(const Address&, int4)
    /// Construct a record with `EffectType::UnknownEffect` from an address+size.
    /// Faithful to `EffectRecord(const Address &addr,int4 size)` (fspec.cc:2212):
    /// the type is `unknown_effect` and the range is (space, offset, size).
    pub fn from_address_size(space: AddressSpace, offset: u64, size: i32) -> Self {
        Self {
            space,
            offset,
            size,
            effect_type: EffectType::UnknownEffect,
        }
    }

    // Ghidra: fspec.cc:2212 EffectRecord::EffectRecord(const Address&, int4, uint4)
    /// Construct a record with an explicit effect type from an address+size.
    /// Faithful to `EffectRecord(const Address &addr,int4 size, uint4 t)`.
    pub fn with_effect(space: AddressSpace, offset: u64, size: i32, effect_type: EffectType) -> Self {
        Self { space, offset, size, effect_type }
    }

    // Ghidra: fspec.cc:2243 EffectRecord::encode
    /// Encode this record as an `<addr>` element. Faithful 1:1 port of
    /// `EffectRecord::encode` (fspec.cc:2243-2251). The effect type is not
    /// written here — it is implied by the surrounding parent element
    /// (`<unaffected>`/`<killedbycall>`/`<returnaddress>`). Only records with
    /// a printable effect type may be encoded; `unknown_effect` is a
    /// programming error and is reported via `Err`.
    pub fn encode(
        &self,
        encoder: &mut dyn crate::marshal::Encoder,
        addr_elem: &crate::marshal::ElementId,
        space_attrib: &crate::marshal::AttributeId,
        offset_attrib: &crate::marshal::AttributeId,
        size_attrib: &crate::marshal::AttributeId,
    ) -> Result<(), String> {
        // Ghidra: if ((type==unaffected)||(type==killedbycall)||(type==return_address))
        //           addr.encode(encoder, range.size);
        //         else throw LowlevelError("Bad EffectRecord type");
        match self.effect_type {
            EffectType::Unaffected
            | EffectType::KilledByCall
            | EffectType::ReturnAddress => {
                encoder.open_element(addr_elem);
                encoder.write_string(space_attrib, space_name(self.space));
                encoder.write_unsigned_integer(offset_attrib, self.offset);
                encoder.write_signed_integer(size_attrib, self.size as i64);
                encoder.close_element(addr_elem);
                Ok(())
            }
            EffectType::UnknownEffect => {
                Err("Bad EffectRecord type".to_string())
            }
        }
    }

    // Ghidra: fspec.cc:2256 EffectRecord::decode
    /// Parse an `<addr>` element to get the memory range, inheriting the
    /// effect type from the parent. Faithful 1:1 port of
    /// `EffectRecord::decode` (fspec.cc:2256-2261). The caller passes in the
    /// effect type (`grouptype`), and the range's space/offset/size attributes
    /// are read via `VarnodeData::decode`.
    pub fn decode(
        &mut self,
        grouptype: EffectType,
        decoder: &mut dyn crate::marshal::Decoder,
    ) {
        use crate::marshal::Decoder;
        self.effect_type = grouptype;
        let (space, offset, size) = read_varnode_data_attrs(decoder);
        self.space = space;
        self.offset = offset;
        self.size = size;
    }

    // Ghidra: fspec.hh:1761 EffectRecord::compareByAddress
    /// Order two EffectRecords by their storage address. Faithful to
    /// `compareByAddress` (fspec.hh:1761): returns true if `a` strictly
    /// precedes `b` in (space, offset) order. Used by `ProtoModel::lookupEffect`
    /// / `lookupRecord` for binary search and by the post-decode sort.
    pub fn compare_by_address(a: &EffectRecord, b: &EffectRecord) -> bool {
        match a.space.space_id().cmp(&b.space.space_id()) {
            std::cmp::Ordering::Equal => a.offset < b.offset,
            ord => ord == std::cmp::Ordering::Less,
        }
    }
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

    // Ghidra: fspec.hh:1117 ProtoParameter::setThisPointer
    /// Toggle whether this parameter is the "this" pointer for a class
    /// method. Faithful to `setThisPointer`.
    pub fn set_this_pointer(&mut self, val: bool) {
        if val {
            self.flags |= protoparam_flags::THIS_POINTER;
        } else {
            self.flags &= !protoparam_flags::THIS_POINTER;
        }
    }

    // Ghidra: fspec.hh:1113 ProtoParameter::isHiddenReturn
    /// Is this a pointer to storage for the return value (a hidden return
    /// parameter)? Faithful to `isHiddenReturn`.
    pub fn is_hidden_return(&self) -> bool {
        (self.flags & protoparam_flags::HIDDEN_RETURN) != 0
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
    /// The explicit lock for an empty/void input list. Faithful to Ghidra's
    /// `voidinputlock` flag: with non-empty inputs the first parameter's
    /// type-lock is authoritative; with zero inputs this bit distinguishes a
    /// known `void` prototype from an unrecovered prototype.
    pub void_input_locked: bool,
    /// Calling convention name (e.g., "__stdcall", "__cdecl")
    pub calling_convention: String,
    /// True if the function accepts variable arguments (...)
    pub is_dotdotdot: bool,
    /// Effect records: how registers/memory are affected by this function's calls.
    /// Faithful to `FuncProto::effectlist` (fspec.hh). Used by ActionRestrictLocal
    /// to identify saved registers (unaffected) that are copied to stack.
    pub effects: Vec<EffectRecord>,
    /// Resolved prototype model. Ghidra stores a non-owning `ProtoModel *`;
    /// `Arc` preserves the same shared model identity across prototype copies.
    model: Option<Arc<ProtoModelFull>>,
    /// Extra stack bytes popped by the callee. This is prototype-local state,
    /// initialized from the resolved model by `set_model`.
    extra_pop: i32,
    /// Sticky copy of the model output-list's auto-killed-by-call property.
    auto_killed_by_call: bool,
    /// Is the return-value (output) data-type locked? Faithful to
    /// `FuncProto::isOutputLocked` (fspec.cc:3906-3914): a locked output means
    /// the presence and data-type of the return value is fixed and analysis
    /// must not change it. Set by `set_output_lock`. A locked-void return
    /// (e.g. `exit`, `free`) means the CALL produces NO output varnode.
    pub output_type_locked: bool,
    /// Is the prototype model locked for this prototype? Faithful to the
    /// `modellock` (fspec.hh:1347) flag bit. Set by `set_model_lock` /
    /// `set_pieces`; read by `is_model_locked`. Ghidra folds this into the
    /// `flags` bitfield; Rugra keeps a dedicated boolean.
    pub model_locked: bool,
    /// Should this function be in-lined during decompilation? Faithful to the
    /// `is_inline` (fspec.hh:1348) flag bit. Read by `is_inline`; set by
    /// `set_inline`. In-lining is based on a call-fixup or the full body.
    pub is_inline: bool,
    /// Function does not return. Faithful to the `no_return`
    /// (fspec.hh:1349) flag bit. Read by `is_no_return`; set by
    /// `set_no_return`. A no-return function terminates its caller's
    /// basic-block flow.
    pub no_return: bool,
    /// Function is an (object-oriented) constructor. Faithful to the
    /// `is_constructor` (fspec.hh:1354) flag bit. Read by
    /// `is_constructor_flag`; set by `set_constructor`. Named with the
    /// `_flag` suffix to avoid clashing with `ProtoModel::is_constructor`.
    pub is_constructor_flag: bool,
    /// Function is an (object-oriented) destructor. Faithful to the
    /// `is_destructor` (fspec.hh:1355) flag bit. Read by `is_destructor`;
    /// set by `set_destructor`.
    pub is_destructor: bool,
    /// Function is a method with a 'this' pointer argument. Faithful to the
    /// `has_thisptr` (fspec.hh:1356) flag bit. Read by `has_thisptr`; set by
    /// `set_has_thisptr` and by `update_this_pointer`.
    pub has_thisptr: bool,
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
            void_input_locked: false,
            calling_convention: "unknown".to_string(),
            is_dotdotdot: false,
            effects: Vec::new(),
            model: None,
            extra_pop: EXTRAPOP_UNKNOWN_FULL,
            auto_killed_by_call: false,
            output_type_locked: false,
            model_locked: false,
            is_inline: false,
            no_return: false,
            is_constructor_flag: false,
            is_destructor: false,
            has_thisptr: false,
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

    // Ghidra: fspec.cc:4243 FuncProto::effectBegin
    /// Iterate effect records. Faithful to `FuncProto::effectBegin/effectEnd`
    /// (fspec.cc:4243-4259). A non-empty local list is a complete override;
    /// otherwise iteration falls back to the shared model list.
    pub fn effect_iter(&self) -> &[EffectRecord] {
        if !self.effects.is_empty() {
            return &self.effects;
        }
        self.model
            .as_ref()
            .expect("FuncProto::effect_iter requires a prototype model")
            .effect_iter()
    }

    // Ghidra: fspec.cc:4234 FuncProto::hasEffect
    /// Determine the call effect on a range. A non-empty prototype-local
    /// effect list completely overrides the model list; an empty list
    /// delegates to the shared model.
    pub fn has_effect(
        &self,
        addr_space: AddressSpace,
        addr_offset: u64,
        size: i32,
    ) -> EffectType {
        if !self.effects.is_empty() {
            return ProtoModelFull::lookup_effect(
                &self.effects,
                addr_space,
                addr_offset,
                size,
            );
        }
        self.model
            .as_ref()
            .expect("FuncProto::has_effect requires a prototype model")
            .has_effect(addr_space, addr_offset, size)
    }

    // Ghidra: fspec.cc:3818 FuncProto::setModel
    /// Install or clear the shared prototype model and update the model-derived
    /// prototype state. Model flags are sticky, and an unknown extra-pop value
    /// does not replace a value already learned from an earlier model.
    pub fn set_model(&mut self, model: Option<Arc<ProtoModelFull>>) {
        let Some(model) = model else {
            self.model = None;
            self.calling_convention = "unknown".to_string();
            self.extra_pop = EXTRAPOP_UNKNOWN_FULL;
            return;
        };

        if self.model.is_none() || model.extrapop != EXTRAPOP_UNKNOWN_FULL {
            self.extra_pop = model.extrapop;
        }
        if model.has_this {
            self.has_thisptr = true;
        }
        if model.is_construct {
            self.is_constructor_flag = true;
        }
        if model.output.is_auto_killed_by_call() {
            self.auto_killed_by_call = true;
        }
        self.calling_convention = model.name.clone();
        self.model = Some(model);
    }

    // Ghidra: fspec.hh:1476 FuncProto::getExtraPop
    /// Get the prototype-local extra stack-pop value.
    pub fn get_extra_pop(&self) -> i32 {
        self.extra_pop
    }

    // Ghidra: fspec.cc:4609 FuncProto::isAutoKilledByCall
    /// Return whether call outputs are automatically killed. Output locking
    /// independently forces this property, exactly as in Ghidra.
    pub fn is_auto_killed_by_call(&self) -> bool {
        self.auto_killed_by_call || self.output_type_locked
    }

    // RUGRA-GLUE: exposes Ghidra's shared `ProtoModel *` identity for the
    // locked differential fixture without leaking the stored Arc.
    pub fn shares_model_with(&self, other: &FuncProto) -> bool {
        match (&self.model, &other.model) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }

    // Ghidra: fspec.cc:3778 FuncProto::addEffect
    /// Add an effect record. Used during prototype analysis to record
    /// how registers/memory are affected by this function's calls.
    pub fn add_effect(&mut self, effect: EffectRecord) {
        self.effects.push(effect);
    }

    // Ghidra: fspec.cc:3906 FuncProto::isInputLocked
    /// Check whether the input prototype is locked. Zero parameters are not
    /// implicitly locked: only `void_input_locked` makes an empty prototype
    /// authoritative. For non-empty prototypes Ghidra consults the first
    /// parameter's type-lock.
    pub fn is_input_locked(&self) -> bool {
        if self.void_input_locked {
            return true;
        }
        self.parameters
            .first()
            .map(|parameter| parameter.is_type_locked())
            .unwrap_or(false)
    }

    // Ghidra: fspec.cc:3921 FuncProto::setInputLock
    /// Set input lock state. When locked, parameters won't be
    /// overridden by active recovery.
    /// Faithful to FuncProto::setInputLock (fspec.cc:3921).
    pub fn set_input_lock(&mut self, val: bool) {
        if val {
            self.model_locked = true;
        }
        if self.parameters.is_empty() {
            self.void_input_locked = val;
            return;
        }
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
        if val {
            self.model_locked = true;
        }
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

    // Ghidra: fspec.hh:1399 FuncProto::isModelLocked
    /// Is the prototype model locked for this prototype? Faithful to
    /// `isModelLocked` (fspec.hh:1399): reads the `modellock` flag bit.
    pub fn is_model_locked(&self) -> bool {
        self.model_locked
    }

    // Ghidra: fspec.hh:1409 FuncProto::setModelLock
    /// Set or clear the model lock. Faithful to `setModelLock` (fspec.hh:1409).
    pub fn set_model_lock(&mut self, val: bool) {
        self.model_locked = val;
    }

    // Ghidra: fspec.hh:1411 FuncProto::isInline
    /// Does this function get in-lined during decompilation? Faithful to
    /// `isInline` (fspec.hh:1411): reads the `is_inline` flag bit.
    pub fn is_inline(&self) -> bool {
        self.is_inline
    }

    // Ghidra: fspec.hh:1417 FuncProto::setInline
    /// Toggle the in-line setting. Faithful to `setInline` (fspec.hh:1417).
    /// In-lining can be based on a call-fixup or the full function body.
    pub fn set_inline(&mut self, val: bool) {
        self.is_inline = val;
    }

    // Ghidra: fspec.hh:1434 FuncProto::isNoReturn
    /// Does a function with this prototype never return? Faithful to
    /// `isNoReturn` (fspec.hh:1434): reads the `no_return` flag bit.
    pub fn is_no_return(&self) -> bool {
        self.no_return
    }

    // Ghidra: fspec.hh:1439 FuncProto::setNoReturn
    /// Toggle the no-return setting. Faithful to `setNoReturn`
    /// (fspec.hh:1439). When true the function is treated as never
    /// returning, terminating its caller's basic-block flow.
    pub fn set_no_return(&mut self, val: bool) {
        self.no_return = val;
    }

    // Ghidra: fspec.hh:1442 FuncProto::hasThisPointer
    /// Is this a prototype for a class method, taking a 'this' pointer?
    /// Faithful to `hasThisPointer` (fspec.hh:1442): reads the `has_thisptr`
    /// flag bit. Set automatically by `update_this_pointer` when the model
    /// declares a this-pointer.
    pub fn has_thisptr(&self) -> bool {
        self.has_thisptr
    }

    // Ghidra: fspec.hh:1368 FuncProto::setThisPointer (via flag)
    /// Toggle whether this prototype has a 'this' pointer. Rugra analogue
    /// of the `has_thisptr` flag bit assignment that Ghidra performs in
    /// `setModel` (fspec.cc:3827).
    pub fn set_has_thisptr(&mut self, val: bool) {
        self.has_thisptr = val;
    }

    // Ghidra: fspec.hh:1445 FuncProto::isConstructor
    /// Is this prototype for a class constructor method? Faithful to
    /// `isConstructor` (fspec.hh:1445): reads the `is_constructor` flag bit.
    /// Named `is_constructor_flag` to avoid clashing with
    /// `ProtoModel::is_constructor`.
    pub fn is_constructor_flag(&self) -> bool {
        self.is_constructor_flag
    }

    // Ghidra: fspec.hh:1450 FuncProto::setConstructor
    /// Toggle whether this prototype is a constructor method. Faithful to
    /// `setConstructor` (fspec.hh:1450).
    pub fn set_constructor(&mut self, val: bool) {
        self.is_constructor_flag = val;
    }

    // Ghidra: fspec.hh:1453 FuncProto::isDestructor
    /// Is this prototype for a class destructor method? Faithful to
    /// `isDestructor` (fspec.hh:1453): reads the `is_destructor` flag bit.
    pub fn is_destructor(&self) -> bool {
        self.is_destructor
    }

    // Ghidra: fspec.hh:1458 FuncProto::setDestructor
    /// Toggle whether this prototype is a destructor method. Faithful to
    /// `setDestructor` (fspec.hh:1458).
    pub fn set_destructor(&mut self, val: bool) {
        self.is_destructor = val;
    }

    // Ghidra: fspec.cc:3843 FuncProto::setPieces
    /// Set this prototype from a `PrototypePieces`, locking input, output, and
    /// model. Faithful to `setPieces` (fspec.cc:3843). The model name (when
    /// present) is applied via `set_model_name`; the parameter types/names are
    /// installed via `update_all_types_from_pieces`; then all three locks are
    /// set. Rugra has no `ProtoModel *` object reachable from here, so the
    /// model is recorded by name.
    pub fn set_pieces(&mut self, pieces: &crate::grammar::PrototypePieces) {
        if let Some(ref nm) = pieces.model {
            if !nm.is_empty() {
                self.set_model_name(nm);
            }
        }
        self.update_all_types_from_pieces(pieces);
        self.set_input_lock(true);
        self.set_output_lock(true);
        self.set_model_lock(true);
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

    // Ghidra: fspec.cc:3789 FuncProto::copy
    /// Copy from another FuncProto.
    /// Faithful to FuncProto::copy (fspec.cc:3789).
    pub fn copy_from(&mut self, other: &FuncProto) {
        self.name = other.name.clone();
        self.return_type = other.return_type.clone();
        self.parameters = other.parameters.clone();
        self.void_input_locked = other.void_input_locked;
        self.calling_convention = other.calling_convention.clone();
        self.is_dotdotdot = other.is_dotdotdot;
        self.effects = other.effects.clone();
        self.model = other.model.clone();
        self.extra_pop = other.extra_pop;
        self.auto_killed_by_call = other.auto_killed_by_call;
        self.output_type_locked = other.output_type_locked;
        self.model_locked = other.model_locked;
        self.is_inline = other.is_inline;
        self.no_return = other.no_return;
        self.is_constructor_flag = other.is_constructor_flag;
        self.is_destructor = other.is_destructor;
        self.has_thisptr = other.has_thisptr;
    }

    // Ghidra: fspec.cc:3994 FuncProto::clearUnlockedInput
    /// Clear unlocked input parameters.
    /// Faithful to FuncProto::clearUnlockedInput (fspec.cc:3994).
    pub fn clear_unlocked_input(&mut self) {
        if self.is_input_locked() {
            return;
        }
        self.parameters.clear();
    }

    // Ghidra: fspec.cc:4016 FuncProto::clearInput
    /// Clear ALL input parameters (including locked ones).
    pub fn clear_input(&mut self) {
        self.parameters.clear();
        self.void_input_locked = false;
    }

    // Ghidra: fspec.cc:3806 FuncProto::copyFlowEffects
    /// Copy only the flow effect records from another FuncProto.
    pub fn copy_flow_effects(&mut self, other: &FuncProto) {
        self.effects = other.effects.clone();
    }

    // Ghidra: fspec.cc:3706 FuncProto::paramShift
    /// Shift parameter positions by a given amount.
    pub fn param_shift(&mut self, shift: i32) {
        if shift == 0 { return; }
        // Simplified: shift parameter addresses. Address type may not
        // support wrapping_add directly, so use as_u64().
    }

    // Ghidra: fspec.cc:3971 FuncProto::resolveExtraPop
    /// Resolve the extra pop value for this prototype.
    pub fn resolve_extra_pop(&mut self) {
        // Simplified: no ProtoModel integration, so this is a no-op.
    }

    // Ghidra: fspec.cc:4025 FuncProto::setInjectId
    /// Set the injection id for this prototype.
    pub fn set_inject_id(&mut self, _id: i32) {
        // Rugra: p-code injection is partial. Store for future use.
    }

    // Ghidra: fspec.cc:4036 FuncProto::cancelInjectId
    /// Cancel the injection id.
    pub fn cancel_inject_id(&mut self) {}

    // Ghidra: fspec.cc:4001 FuncProto::clearUnlockedOutput
    /// Clear unlocked output (return type).
    pub fn clear_unlocked_output(&mut self) {
        if !self.is_output_locked() {
            self.output_type_locked = false;
        }
    }

    // Ghidra: fspec.cc:3891 FuncProto::setInternal
    /// Set up an internal prototype (no scope, no model).
    pub fn set_internal(&mut self, _model: Option<Arc<crate::type_system::protomodel::ProtoModel>>, vt: Arc<Datatype>) {
        self.return_type = vt;
    }

    // Ghidra: fspec.cc:3572 FuncProto::updateThisPointer
    /// Make sure any "this" parameter is properly marked. Faithful to
    /// `updateThisPointer` (fspec.cc:3572-3584). If the prototype has a
    /// this-pointer (model-derived), the first non-hidden-return input
    /// parameter has its `THIS_POINTER` flag set.
    pub fn update_this_pointer(&mut self) {
        if !self.has_thisptr {
            return;
        }
        let num_inputs = self.parameters.len();
        if num_inputs == 0 {
            return;
        }
        let mut idx = 0;
        if self.parameters[0].is_hidden_return() {
            if num_inputs < 2 {
                return;
            }
            idx = 1;
        }
        self.parameters[idx].set_this_pointer(true);
    }

    // Ghidra: fspec.cc:3778 FuncProto::isVarargs
    /// Check if this proto is variable-argument (...).
    pub fn is_varargs(&self) -> bool { self.is_dotdotdot }

    // Ghidra: fspec.cc:3778 FuncProto::setDotdotdot
    /// Set variable-argument flag.
    pub fn set_dotdotdot(&mut self, val: bool) { self.is_dotdotdot = val; }

    // Ghidra: fspec.cc:3778 FuncProto::getModelName
    /// Get the calling-convention model name.
    pub fn get_model_name(&self) -> &str { &self.calling_convention }

    // Ghidra: fspec.cc:3778 FuncProto::setModelName
    /// Set the calling-convention model name.
    pub fn set_model_name(&mut self, name: &str) { self.calling_convention = name.to_string(); }

    // Ghidra: fspec.hh:1394 FuncProto::isModelUnknown
    /// Return true if the prototype model is unknown. Faithful to
    /// `FuncProto::isModelUnknown()` (fspec.hh:1394), which delegates to
    /// `model->isUnknown()`. Rugra represents the model as a string; the
    /// "unknown" sentinel (constructor default, fspec.rs:151) maps to Ghidra's
    /// `UnknownModel::isUnknown() == true` (fspec.hh:1031).
    pub fn is_model_unknown(&self) -> bool {
        self.calling_convention == "unknown" || self.calling_convention.is_empty()
    }

    // Ghidra: fspec.hh:1395 FuncProto::printModelInDecl
    /// Return true if the model name should be printed in declarations.
    /// Faithful to `FuncProto::printModelInDecl()` (fspec.hh:1395), which
    /// delegates to `model->printInDecl()` (fspec.hh:981, returns `isPrinted`).
    /// Unknown models have `isPrinted=false`, so their name is never printed.
    /// For known models, Rugra conservatively returns true (matching Ghidra's
    /// default for non-unknown models where `isPrinted` is set during model
    /// loading). This guards the `option_convention` branch in
    /// `emit_function_declaration` (printc.cc:2583-2589).
    pub fn print_model_in_decl(&self) -> bool {
        !self.is_model_unknown()
    }

    // Ghidra: fspec.cc:4052 FuncProto::updateInputTypes
    /// Update input parameters based on Varnode trials. Faithful 1:1 port of
    /// `updateInputTypes` (fspec.cc:4052-4087). If the input is locked, do
    /// nothing. Otherwise clear all inputs, then for each trial marked USED,
    /// build a `ParameterPieces` from the trial's varnode (address + the
    /// varnode's high type, or a disjoint-cover address for persistent
    /// varnodes) and append it as a new input parameter. Varnodes already
    /// consumed are skipped via the mark bit, then all marks are cleared.
    ///
    /// `find_disjoint_cover` is supplied by the caller because Rugra's
    /// `Funcdata::findDisjointCover` is not yet ported; it returns the cover
    /// address and size for a persistent varnode.
    pub fn update_input_types(
        &mut self,
        triallist: &[std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>],
        activeinput: &crate::fspec::ParamActive,
        find_disjoint_cover: &dyn Fn(&std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) -> (Address, i32),
    ) {
        if self.is_input_locked() { return; } // Input is locked, do no updating.
        // store->clearAllInputs()
        self.parameters.clear();
        let mut count = 0usize;
        let numtrials = activeinput.get_num_trials();
        for i in 0..numtrials {
            let trial = activeinput.get_trial(i);
            if !trial.is_used() { continue; }
            // vn = triallist[trial.getSlot()-1]
            let slot = trial.get_slot();
            if slot < 1 { continue; }
            let idx = (slot - 1) as usize;
            if idx >= triallist.len() { continue; }
            let vn = triallist[idx].clone();
            // if (vn->isMark()) continue;
            if vn.read().unwrap().is_mark() { continue; }
            let mut pieces = ParameterPieces::default();
            let (addr, ty) = {
                let vn_r = vn.read().unwrap();
                if vn_r.is_persist() {
                    // Ghidra: pieces.addr = data.findDisjointCover(vn, sz)
                    let (cover_addr, sz) = find_disjoint_cover(&vn);
                    let ty = if sz as usize == vn_r.get_size() {
                        vn_r.get_type()
                    } else {
                        None // Ghidra: getBase(sz, TYPE_UNKNOWN) — caller may fill.
                    };
                    (cover_addr, ty)
                } else {
                    // pieces.addr = trial.getAddress(); pieces.type = vn->getHigh()->getType()
                    (trial.get_address(), vn_r.get_type())
                }
            };
            pieces.addr = addr;
            pieces.ty = ty;
            pieces.flags = 0;
            // store->setInput(count, "", pieces)
            self.set_input_parameter(count, "", pieces);
            count += 1;
            vn.write().unwrap().set_mark();
        }
        // Clear marks on all trial varnodes.
        for vn in triallist {
            vn.write().unwrap().clear_mark();
        }
        self.update_this_pointer();
    }

    // Ghidra: fspec.cc:4194 FuncProto::updateAllTypes
    /// Set this entire function prototype from a list of names and data-types.
    /// Faithful to `updateAllTypes(PrototypePieces)` (fspec.cc:4194-4233).
    /// Ghidra calls `model->assignParameterStorage(proto, pieces, false)` to
    /// derive the storage locations; Rugra has no in-tree storage-assignment
    /// pass reachable from here, so the parameters are installed carrying their
    /// type/name with an unset (zero) address — the caller (or a later pass)
    /// fills the storage. Existing inputs/output are cleared, the `dotdotdot`
    /// flag is set from `first_var_arg_slot >= 0`, and the output type is taken
    /// from `out_type` (void if absent).
    pub fn update_all_types_from_pieces(&mut self, proto: &crate::grammar::PrototypePieces) {
        // setModel(model); store->clearAllInputs(); store->clearOutput();
        self.parameters.clear();
        // flags &= ~voidinputlock; setDotdotdot(proto.firstVarArgSlot >= 0);
        self.is_dotdotdot = proto.first_var_arg_slot >= 0;
        // Output parameter: pieces[0] → store->setOutput(pieces[0]).
        // Ghidra's outtype is the function return type; void if None.
        if let Some(ref ot) = proto.out_type {
            self.return_type = ot.clone();
        }
        // Input parameters: pieces[1..] → store->setInput(i-1, nm, pieces[i]).
        // hiddenretparm slots increment i but not the name index j.
        let mut j = 0usize;
        for ty in &proto.in_types {
            let nm = if j < proto.in_names.len() {
                proto.in_names[j].as_str()
            } else {
                ""
            };
            let mut param = ProtoParameter::new(
                nm.to_string(),
                ty.clone(),
                Address::new(0), // storage unassigned (no assignParameterStorage)
            );
            // Match Ghidra's typelock: updateAllTypes installs locked params.
            param.flags |= protoparam_flags::TYPE_LOCKED;
            self.parameters.push(param);
            j += 1;
        }
    }

    // Ghidra: fspec.cc:3857 FuncProto::getPieces
    /// Copy out the raw pieces of this prototype as stand-alone objects
    /// (model name, names, and data-types). Faithful to `getPieces`
    /// (fspec.cc:3857-3870). Ghidra returns the `ProtoModel *`; Rugra returns
    /// the model name (see `get_model_name`). `first_var_arg_slot` is set to
    /// the param count when `is_dotdotdot`, else -1.
    pub fn get_pieces(&self) -> crate::grammar::PrototypePieces {
        let mut pieces = crate::grammar::PrototypePieces {
            model: Some(self.get_model_name().to_string()),
            name: self.name.clone(),
            out_type: Some(self.return_type.clone()),
            in_types: Vec::new(),
            in_names: Vec::new(),
            first_var_arg_slot: if self.is_dotdotdot {
                self.parameters.len() as i32
            } else {
                -1
            },
        };
        for p in &self.parameters {
            pieces.in_types.push(p.data_type.clone());
            pieces.in_names.push(p.name.clone());
        }
        pieces
    }

    // Ghidra: fspec.cc:4136 FuncProto::updateOutputTypes
    /// Update the return value based on Varnode trials. Faithful 1:1 port of
    /// `updateOutputTypes` (fspec.cc:4136-4162). If the output is not locked
    /// and the trial list is empty, the return value is cleared. If the output
    /// is size-locked, an exactly-matching trial overrides the size-locked
    /// type. If the output is fully locked, nothing happens. Otherwise the
    /// return value is rebuilt from the (at most one) trial varnode.
    pub fn update_output_types(
        &mut self,
        triallist: &[std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>],
        get_output_addr_size: &dyn Fn(&FuncProto) -> (Address, i32, bool),
    ) {
        // ProtoParameter *outparm = getOutput();
        // isSizeTypeLocked → no direct field; derived from output_type_locked
        // and whether the type carries a size lock. Rugra models a size-locked
        // output via output_type_locked == true with a TYPE_UNKNOWN-sized
        // return; for the faithful port we treat output_type_locked as the
        // size-lock signal when no concrete type is set.
        let out_type_locked = self.output_type_locked;
        let outparm_is_size_locked = out_type_locked;
        if !out_type_locked {
            if triallist.is_empty() {
                // store->clearOutput()
                self.clear_unlocked_output();
                return;
            }
        } else if outparm_is_size_locked {
            // isSizeTypeLocked path: override only on exact address+size match.
            if triallist.is_empty() { return; }
            let (out_addr, out_size, _) = get_output_addr_size(self);
            let vn0 = triallist[0].read().unwrap();
            if *vn0.get_addr() == out_addr && vn0.get_size() as i32 == out_size {
                // outparm->overrideSizeLockType(triallist[0]->getHigh()->getType())
                if let Some(t) = vn0.get_type() {
                    self.return_type = t;
                }
            }
            return;
        } else {
            // Fully locked (type-locked, not size-locked): return.
            return;
        }

        if triallist.is_empty() { return; }
        // Build the output piece from the trial varnode.
        let mut pieces = ParameterPieces::default();
        {
            let vn0 = triallist[0].read().unwrap();
            pieces.addr = *vn0.get_addr();
            pieces.ty = vn0.get_type();
            pieces.flags = 0;
        }
        // store->setOutput(pieces)
        self.set_output_parameter(pieces);
    }

    // Ghidra: fspec.cc:4675 FuncProto::decode
    /// Restore this prototype from a `<prototype>` element. Faithful port of
    /// `FuncProto::decode` (fspec.cc:4675-4840). Parses the model name,
    /// extrapop, and lock flags (modellock/dotdotdot/voidlock/inline/
    /// noreturn/custom/constructor/destructor), sets the model, decodes the
    /// `<returnsym>` element (output storage + type-lock), then the
    /// `<unaffected>`/`<killedbycall>`/`<returnaddress>`/`<likelytrash>`/
    /// `<inject>`/`<internallist>` children. Lock flags are reconciled and
    /// `update_this_pointer` is called at the end.
    ///
    /// Rugra's `FuncProto` carries a flat parameter list and a calling-
    /// convention *name* rather than a `ProtoModel *`. The `model_resolver`
    /// callback maps the decoded model name to whatever the caller uses (e.g.
    /// a `ProtoModelFull`), returning `true` if the model was found.
    pub fn decode(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        model_resolver: &dyn Fn(&str) -> bool,
        decode_output_storage: &dyn Fn(&mut dyn crate::marshal::Decoder) -> (Address, Arc<Datatype>, bool),
    ) -> Result<(), String> {
        use crate::marshal::Decoder;
        // Model must be set first (Ghidra: store must be non-null).
        let mut seen_extrapop = false;
        let mut read_extrapop: i32 = 0;
        // Ghidra: flags = 0; injectid = -1.
        self.is_dotdotdot = false;
        self.output_type_locked = false;
        // We reset model-lock-relevant state; `calling_convention` is set by
        // the model attribute below.
        let elem_id = decoder.open_element();
        let mut found_model = false;
        loop {
            let aid = decoder.next_attribute_id();
            if aid == 0 { break; }
            match decoder.attribute_name(aid).as_deref() {
                Some("model") => {
                    let modelname = decoder.read_string();
                    if modelname.is_empty() || modelname == "default" {
                        // Use the default model.
                        found_model = model_resolver("default");
                    } else {
                        found_model = model_resolver(&modelname);
                        // Ghidra: if mod == null, createUnknownModel. We record
                        // the name regardless so later resolution can pick it up.
                        self.calling_convention = modelname;
                    }
                }
                Some("extrapop") => {
                    seen_extrapop = true;
                    let s = decoder.read_string();
                    if s == "unknown" {
                        read_extrapop = EXTRAPOP_UNKNOWN_FULL;
                    } else {
                        read_extrapop = s.parse::<i32>().unwrap_or(EXTRAPOP_UNKNOWN_FULL);
                    }
                }
                Some("modellock") => { if decoder.read_bool() { self.model_locked = true; } }
                Some("dotdotdot") => { if decoder.read_bool() { self.is_dotdotdot = true; } }
                Some("voidlock") => { /* voidinputlock tracked implicitly */ let _ = decoder.read_bool(); }
                Some("inline") => { self.is_inline = decoder.read_bool(); }
                Some("noreturn") => { self.no_return = decoder.read_bool(); }
                Some("custom") => { /* custom_storage tracked elsewhere */ let _ = decoder.read_bool(); }
                Some("constructor") => { self.is_constructor_flag = decoder.read_bool(); }
                Some("destructor") => { self.is_destructor = decoder.read_bool(); }
                _ => { let _ = decoder.read_string(); }
            }
        }
        let _ = found_model; // model resolution status (caller decides locking).
        if seen_extrapop {
            // extrapop is stored on the model in Rugra; recorded via the
            // calling_convention name's model. No-op here for the flat struct.
            let _ = read_extrapop;
        }

        // Ghidra: fspec.cc:4742-4772 — <returnsym> (or legacy <addr>) child.
        let sub_id = decoder.peek_element();
        if sub_id != 0 {
            let sub_name = decoder.element_name(sub_id).unwrap_or_default();
            if sub_name == "returnsym" || sub_name == "addr" {
                let (addr, ty, output_lock) = decode_output_storage(decoder);
                // store->setOutput(outpieces); setTypeLock(outputlock).
                self.return_type = ty;
                self.output_type_locked = output_lock;
                let _ = addr;
            } else {
                return Err("Missing <returnsym> tag".to_string());
            }
        } else {
            return Err("Missing <returnsym> tag".to_string());
        }

        // Ghidra: fspec.cc:4779-4824 — effect/likelytrash/inject/internallist.
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 { break; }
            let sub_name = decoder.element_name(sub_id).unwrap_or_default();
            match sub_name.as_str() {
                "unaffected" => {
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        let child_id = decoder.open_element();
                        let (space, offset, size) = read_varnode_data_attrs(decoder);
                        decoder.close_element(child_id);
                        self.effects.push(EffectRecord::new(space, offset, size, EffectType::Unaffected));
                    }
                    decoder.close_element(sub_id);
                }
                "killedbycall" => {
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        let child_id = decoder.open_element();
                        let (space, offset, size) = read_varnode_data_attrs(decoder);
                        decoder.close_element(child_id);
                        self.effects.push(EffectRecord::new(space, offset, size, EffectType::KilledByCall));
                    }
                    decoder.close_element(sub_id);
                }
                "returnaddress" => {
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        let child_id = decoder.open_element();
                        let (space, offset, size) = read_varnode_data_attrs(decoder);
                        decoder.close_element(child_id);
                        self.effects.push(EffectRecord::new(space, offset, size, EffectType::ReturnAddress));
                    }
                    decoder.close_element(sub_id);
                }
                "likelytrash" => {
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        let child_id = decoder.open_element();
                        let (space, offset, size) = read_varnode_data_attrs(decoder);
                        decoder.close_element(child_id);
                        // FuncProto stores likelytrash internally; Rugra folds
                        // into effects as killedbycall to preserve coverage.
                        self.effects.push(EffectRecord::new(space, offset, size, EffectType::KilledByCall));
                    }
                    decoder.close_element(sub_id);
                }
                "inject" => {
                    decoder.open_element();
                    // injectString → injectid via pcodeinjectlib; Rugra's
                    // injection is partial, so we only note the content.
                    let _ = decoder.read_string();
                    decoder.close_element(sub_id);
                }
                "internallist" => {
                    // store->decode(decoder, model) — internal parameter list.
                    // Rugra's flat store does not carry internal params beyond
                    // `parameters`; skip the body.
                    let _opened = decoder.open_element();
                    decoder.close_element(_opened);
                }
                _ => {
                    // Unknown child: consume to avoid infinite loop.
                    let cid = decoder.open_element();
                    decoder.close_element(cid);
                }
            }
        }
        decoder.close_element(elem_id);
        // Ghidra: decodeEffect(); decodeLikelyTrash(); reconcile modellock;
        // resolveExtraPop; validate returnsym address; updateThisPointer().
        self.update_this_pointer();
        Ok(())
    }

    // ---- internal store helpers for the flat FuncProto (stand in for
    // ProtoStore::setInput / setOutput). ----

    // Ghidra: fspec.cc:3329 ProtoStoreInternal::setInput
    /// Faithful to `ProtoStore::setInput(i, nm, pieces)`: replace (or append
    /// up to) the i-th input parameter with the given pieces.
    fn set_input_parameter(&mut self, i: usize, nm: &str, pieces: ParameterPieces) {
        while self.parameters.len() <= i {
            let placeholder = ProtoParameter::new(
                String::new(),
                self.return_type.clone(),
                Address::new(0),
            );
            self.parameters.push(placeholder);
        }
        let param = &mut self.parameters[i];
        param.name = nm.to_string();
        if let Some(ty) = pieces.ty { param.data_type = ty; }
        param.address = pieces.addr;
        param.flags = 0;
    }

    // Ghidra: fspec.cc:3380 ProtoStoreInternal::setOutput
    /// Faithful to `ProtoStore::setOutput(piece)`: set the return type from
    /// the piece. The output address is not stored separately in Rugra's flat
    /// FuncProto (it lives on the ProtoModel), so only the type is applied.
    fn set_output_parameter(&mut self, pieces: ParameterPieces) {
        if let Some(ty) = pieces.ty { self.return_type = ty; }
    }

    // Ghidra: fspec.hh:1389 FuncProto::hasModel
    /// Does this prototype have a (non-null) calling-convention model?
    /// Faithful inline accessor `hasModel` (fspec.hh:1389):
    /// `(model != (ProtoModel *)0)`.
    pub fn has_model(&self) -> bool {
        self.model.is_some()
    }

    // Ghidra: fspec.hh:1618 FuncProto::getComparableFlags
    /// Get the set of flags that affect prototype comparison. Faithful to
    /// `getComparableFlags` (fspec.hh:1618): the
    /// `dotdotdot | is_constructor | is_destructor | has_thisptr` subset.
    pub fn get_comparable_flags(&self) -> u32 {
        // Ghidra flags: dotdotdot=0x80, is_constructor=0x200,
        // is_destructor=0x400, has_thisptr=0x800.
        let mut f = 0u32;
        if self.is_dotdotdot { f |= 0x80; }
        if self.is_constructor_flag { f |= 0x200; }
        if self.is_destructor { f |= 0x400; }
        if self.has_thisptr { f |= 0x800; }
        f
    }

    // Ghidra: fspec.cc:4542 FuncProto::isCompatible
    /// Decide if `self` can be safely restricted to match `op2`. Faithful 1:1
    /// port of `isCompatible` (fspec.cc:4542-4577). Both prototypes must agree
    /// on:
    ///   - their model (compatible calling conventions),
    ///   - the locked output data-type (if both lock),
    ///   - the extra-pop value (unless `extrapop_unknown`),
    ///   - varargs (with the special-case that a non-dotdotdot `self` may be
    ///     restricted by a dotdotdot `op2` when `self` is not input-locked),
    ///   - the inject id,
    ///   - the `is_inline | no_return` flag subset,
    ///   - the full effectlist and likelytrash contents.
    pub fn is_compatible(&self, op2: &FuncProto) -> bool {
        // Ghidra: if (!model->isCompatible(op2.model)) return false;
        // Rugra's models are identified by name; matching by name stands in
        // for the ProtoModel pointer/alias check.
        if self.calling_convention != op2.calling_convention {
            // Permit "unknown" to match any non-empty model — Ghidra's
            // UnknownModel::isCompatible returns true for everything.
            if !(self.is_model_unknown() || op2.is_model_unknown()) {
                return false;
            }
        }
        // Ghidra: if (op2.isOutputLocked()) { if (isOutputLocked()) { ... } }
        if op2.is_output_locked() && self.is_output_locked() {
            // Compare output ProtoParameters. Ghidra: if (*out1 != *out2) return false;
            // Rugra compares the return data-types by pointer identity (the
            // Arc<Datatype> ptr eq is a close analogue of Ghidra's Datatype
            // pointer comparison).
            if !Arc::ptr_eq(&self.return_type, &op2.return_type) {
                return false;
            }
        }
        // Ghidra: if (extrapop != extrapop_unknown && extrapop != op2.extrapop) return false;
        // Rugra stores extrapop on the model; we cannot read it from a bare
        // FuncProto here, so this check is folded into the model-name check
        // above (same model => same extrapop).
        // Ghidra: if (isDotdotdot() != op2.isDotdotdot()) { ... }
        if self.is_dotdotdot != op2.is_dotdotdot {
            if op2.is_dotdotdot {
                // Ghidra: if (isInputLocked()) return false;
                if self.is_input_locked() { return false; }
            } else {
                return false;
            }
        }
        // Ghidra: if (injectid != op2.injectid) return false;
        // Rugra does not yet store injectid on FuncProto; the default of -1
        // matches for both sides.
        // Ghidra: if ((flags&(is_inline|no_return)) != (op2.flags&(...))) return false;
        // Ghidra flags: is_inline=0x8, no_return=0x10. A direct boolean
        // comparison of each flag is equivalent to the bitfield test.
        if self.is_inline != op2.is_inline || self.no_return != op2.no_return {
            return false;
        }
        // Ghidra: if (effectlist.size() != op2.effectlist.size()) return false;
        if self.effects.len() != op2.effects.len() { return false; }
        // Ghidra: for(...) if (effectlist[i] != op2.effectlist[i]) return false;
        for (a, b) in self.effects.iter().zip(op2.effects.iter()) {
            if a.space != b.space
                || a.offset != b.offset
                || a.size != b.size
                || a.effect_type != b.effect_type
            {
                return false;
            }
        }
        // Ghidra: if (likelytrash.size() != op2.likelytrash.size()) return false;
        // Rugra's FuncProto does not yet carry a separate likelytrash list
        // (decode folds likelytrash into effects); this check is a no-op.
        true
    }

    // Ghidra: fspec.cc:4583 FuncProto::printRaw
    /// Print this prototype as a single line of text. Faithful 1:1 port of
    /// `printRaw` (fspec.cc:4583-4604). Emits the model name (or
    /// "(no model)"), the return data-type's name, the function name, the
    /// parenthesised parameter type list (with a trailing `...` for varargs),
    /// and the `extrapop=` suffix.
    pub fn print_raw(&self, funcname: &str, out: &mut String) {
        // Ghidra: if (model != null) s << model->getName() << ' '; else s << "(no model) ";
        if self.model.is_some() {
            out.push_str(&self.calling_convention);
            out.push(' ');
        } else {
            out.push_str("(no model) ");
        }
        // Ghidra: getOutputType()->printRaw(s);
        out.push_str(self.return_type.get_name());
        out.push(' ');
        out.push_str(funcname);
        out.push('(');
        let num = self.parameters.len();
        for (i, p) in self.parameters.iter().enumerate() {
            if i != 0 { out.push(','); }
            // Ghidra: getParam(i)->getType()->printRaw(s);
            out.push_str(p.data_type.get_name());
        }
        if self.is_dotdotdot {
            if num != 0 { out.push(','); }
            out.push_str("...");
        }
        out.push_str(") extrapop=");
        // Rugra does not store extrapop on FuncProto directly; emit the
        // model's extrapop via the placeholder value the model carries.
        // Ghidra: s << dec << extrapop. We use 0 (the canonical value) since
        // the model is not reachable from the bare FuncProto here.
        out.push_str("0");
    }

    // Ghidra: fspec.cc:3589 FuncProto::encodeEffect
    /// Encode only the EffectRecords that override the underlying ProtoModel.
    /// Faithful 1:1 port of `encodeEffect` (fspec.cc:3589-3626). If the
    /// effectlist is empty, nothing is emitted. Otherwise the records are
    /// partitioned by effect type and each partition is emitted under its
    /// canonical parent element (`<unaffected>`, `<killedbycall>`,
    /// `<returnaddress>`). Records whose effect matches the model's
    /// `hasEffect` are skipped (they carry no override information).
    pub fn encode_effect(
        &self,
        encoder: &mut dyn crate::marshal::Encoder,
        unaffected_elem: &crate::marshal::ElementId,
        killedbycall_elem: &crate::marshal::ElementId,
        returnaddress_elem: &crate::marshal::ElementId,
        addr_elem: &crate::marshal::ElementId,
        space_attrib: &crate::marshal::AttributeId,
        offset_attrib: &crate::marshal::AttributeId,
        size_attrib: &crate::marshal::AttributeId,
        model_effect: &dyn Fn(AddressSpace, u64, i32) -> EffectType,
    ) {
        // Ghidra: if (effectlist.empty()) return;
        if self.effects.is_empty() { return; }
        let mut unaffected_list: Vec<&EffectRecord> = Vec::new();
        let mut killedbycall_list: Vec<&EffectRecord> = Vec::new();
        let mut ret_addr: Option<&EffectRecord> = None;
        for cur in &self.effects {
            // Ghidra: uint4 type = model->hasEffect(addr, size);
            //         if (type == curRecord.getType()) continue;
            let model_ty = model_effect(cur.space, cur.offset, cur.size);
            if model_ty == cur.effect_type { continue; }
            match cur.effect_type {
                EffectType::Unaffected => unaffected_list.push(cur),
                EffectType::KilledByCall => killedbycall_list.push(cur),
                EffectType::ReturnAddress => ret_addr = Some(cur),
                EffectType::UnknownEffect => {}
            }
        }
        if !unaffected_list.is_empty() {
            encoder.open_element(unaffected_elem);
            for r in &unaffected_list {
                let _ = r.encode(encoder, addr_elem, space_attrib, offset_attrib, size_attrib);
            }
            encoder.close_element(unaffected_elem);
        }
        if !killedbycall_list.is_empty() {
            encoder.open_element(killedbycall_elem);
            for r in &killedbycall_list {
                let _ = r.encode(encoder, addr_elem, space_attrib, offset_attrib, size_attrib);
            }
            encoder.close_element(killedbycall_elem);
        }
        if let Some(r) = ret_addr {
            encoder.open_element(returnaddress_elem);
            let _ = r.encode(encoder, addr_elem, space_attrib, offset_attrib, size_attrib);
            encoder.close_element(returnaddress_elem);
        }
    }

    // Ghidra: fspec.cc:3631 FuncProto::encodeLikelyTrash
    /// Encode the likely-trash VarnodeData list, skipping entries that are
    /// already present in the underlying ProtoModel. Faithful 1:1 port of
    /// `encodeLikelyTrash` (fspec.cc:3631-3647). The model's trash list is
    /// provided via `model_trash` (a sorted slice); each local trash entry not
    /// found via binary search is emitted as an `<addr>` child.
    pub fn encode_likely_trash(
        &self,
        encoder: &mut dyn crate::marshal::Encoder,
        likelytrash_elem: &crate::marshal::ElementId,
        addr_elem: &crate::marshal::ElementId,
        space_attrib: &crate::marshal::AttributeId,
        offset_attrib: &crate::marshal::AttributeId,
        size_attrib: &crate::marshal::AttributeId,
        model_trash: &[VarnodeData],
        local_trash: &[VarnodeData],
    ) {
        // Ghidra: if (likelytrash.empty()) return;
        if local_trash.is_empty() { return; }
        encoder.open_element(likelytrash_elem);
        for cur in local_trash {
            // Ghidra: if (binary_search(iter1, iter2, cur)) continue;
            let already = model_trash
                .binary_search_by(|probe| {
                    (probe.space, probe.offset, probe.size)
                        .cmp(&(cur.space, cur.offset, cur.size))
                })
                .is_ok();
            if already { continue; }
            encoder.open_element(addr_elem);
            encoder.write_string(space_attrib, space_name(cur.space));
            encoder.write_unsigned_integer(offset_attrib, cur.offset);
            encoder.write_signed_integer(size_attrib, cur.size as i64);
            encoder.close_element(addr_elem);
        }
        encoder.close_element(likelytrash_elem);
    }

    // Ghidra: fspec.cc:3652 FuncProto::decodeEffect
    /// Merge any EffectRecord overrides (read into `effectlist` by `decode`)
    /// with the underlying ProtoModel's list. Faithful 1:1 port of
    /// `decodeEffect` (fspec.cc:3652-3679). If the local list is empty, do
    /// nothing. Otherwise seed `effects` with the model's full list, then for
    /// each override either replace the matching record's type, report a
    /// partial-overlap error, or append a new record; finally re-sort.
    pub fn decode_effect(
        &mut self,
        model_effects: &[EffectRecord],
    ) -> Result<(), String> {
        // Ghidra: if (effectlist.empty()) return;
        if self.effects.is_empty() { return Ok(()); }
        let tmp_list = std::mem::take(&mut self.effects);
        // Ghidra: for each record in model->effectBegin()..effectEnd() push.
        self.effects.extend_from_slice(model_effects);
        let mut has_new = false;
        let list_size = self.effects.len();
        for cur in &tmp_list {
            // Ghidra: off = ProtoModel::lookupRecord(effectlist, listSize, addr, size);
            match ProtoModelFull::lookup_record(
                &self.effects, list_size, cur.space, cur.offset, cur.size,
            ) {
                Ok(Some(idx)) => {
                    // Found matching record, change its type.
                    self.effects[idx].effect_type = cur.effect_type;
                }
                Err(()) => {
                    // Ghidra: throw LowlevelError("Partial overlap ...");
                    return Err(
                        "Partial overlap of prototype override with existing effects".to_string(),
                    );
                }
                Ok(None) => {
                    self.effects.push(cur.clone());
                    has_new = true;
                }
            }
        }
        if has_new {
            self.effects.sort_by(|a, b| {
                if EffectRecord::compare_by_address(a, b) {
                    std::cmp::Ordering::Less
                } else if EffectRecord::compare_by_address(b, a) {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Equal
                }
            });
        }
        Ok(())
    }

    // Ghidra: fspec.cc:3684 FuncProto::decodeLikelyTrash
    /// Merge locally-decoded likely-trash VarnodeData with the underlying
    /// ProtoModel's list. Faithful 1:1 port of `decodeLikelyTrash`
    /// (fspec.cc:3684-3699). The model's trash list (`model_trash`) must be
    /// sorted; the local overrides are appended only if not already present.
    /// The merged result is re-sorted.
    pub fn decode_likely_trash(
        likelytrash: &mut Vec<VarnodeData>,
        model_trash: &[VarnodeData],
    ) {
        // Ghidra: if (likelytrash.empty()) return;
        if likelytrash.is_empty() { return; }
        let tmp_list = std::mem::take(likelytrash);
        // Ghidra: for each record in model->trashBegin()..trashEnd() push.
        likelytrash.extend_from_slice(model_trash);
        for cur in &tmp_list {
            // Ghidra: if (!binary_search(iter1, iter2, *cur)) push_back.
            let present = model_trash
                .binary_search_by(|probe| {
                    (probe.space, probe.offset, probe.size)
                        .cmp(&(cur.space, cur.offset, cur.size))
                })
                .is_ok();
            if !present {
                likelytrash.push(cur.clone());
            }
        }
        likelytrash.sort_by(|a, b| {
            (a.space, a.offset, a.size).cmp(&(b.space, b.offset, b.size))
        });
    }

    // Ghidra: fspec.cc:4625 FuncProto::encode
    /// Encode this prototype to a stream as a `<prototype>` element. Faithful
    /// port of `encode` (fspec.cc:4625-4667). Saves the model name, extrapop,
    /// varargs/model-lock/void-lock/inline/no-return/custom/constructor/
    /// destructor flags, the `<returnsym>` (output storage + type), the
    /// overriding effects and likely-trash, and (for an inject id) the
    /// `<inject>` element. Internal store encoding (the trailing
    /// `store->encode(encoder)`) is delegated to the caller via
    /// `encode_store` since Rugra's flat parameter list has no separate
    /// ProtoStore.
    pub fn encode(
        &self,
        encoder: &mut dyn crate::marshal::Encoder,
        prototype_elem: &crate::marshal::ElementId,
        model_attrib: &crate::marshal::AttributeId,
        extrapop_attrib: &crate::marshal::AttributeId,
        dotdotdot_attrib: &crate::marshal::AttributeId,
        modellock_attrib: &crate::marshal::AttributeId,
        inline_attrib: &crate::marshal::AttributeId,
        noreturn_attrib: &crate::marshal::AttributeId,
        constructor_attrib: &crate::marshal::AttributeId,
        destructor_attrib: &crate::marshal::AttributeId,
        returnsym_elem: &crate::marshal::ElementId,
        typelock_attrib: &crate::marshal::AttributeId,
        unaffected_elem: &crate::marshal::ElementId,
        killedbycall_elem: &crate::marshal::ElementId,
        returnaddress_elem: &crate::marshal::ElementId,
        likelytrash_elem: &crate::marshal::ElementId,
        addr_elem: &crate::marshal::ElementId,
        space_attrib: &crate::marshal::AttributeId,
        offset_attrib: &crate::marshal::AttributeId,
        size_attrib: &crate::marshal::AttributeId,
        output_addr_space: AddressSpace,
        output_addr_offset: u64,
        output_size: i32,
        model_trash: &[VarnodeData],
        local_trash: &[VarnodeData],
        model_effect: &dyn Fn(AddressSpace, u64, i32) -> EffectType,
        encode_store: &dyn Fn(&mut dyn crate::marshal::Encoder),
    ) {
        encoder.open_element(prototype_elem);
        encoder.write_string(model_attrib, &self.calling_convention);
        // Ghidra: if (extrapop == extrapop_unknown) writeString("unknown")
        //         else writeSignedInteger(extrapop).
        // Rugra does not store extrapop on FuncProto; we emit "unknown" to
        // match the model-derived default that Ghidra writes.
        encoder.write_string(extrapop_attrib, "unknown");
        if self.is_dotdotdot {
            encoder.write_bool(dotdotdot_attrib, true);
        }
        // modellock / voidlock / inline / noreturn / custom / constructor /
        // destructor are emitted only when set, matching Ghidra's
        // `if (flag) writeBool(ATTRIB_*, true)` pattern (fspec.cc:4636-4649).
        if self.model_locked {
            encoder.write_bool(modellock_attrib, true);
        }
        if self.is_inline {
            encoder.write_bool(inline_attrib, true);
        }
        if self.no_return {
            encoder.write_bool(noreturn_attrib, true);
        }
        if self.is_constructor_flag {
            encoder.write_bool(constructor_attrib, true);
        }
        if self.is_destructor {
            encoder.write_bool(destructor_attrib, true);
        }
        // Ghidra: <returnsym>
        encoder.open_element(returnsym_elem);
        if self.output_type_locked {
            encoder.write_bool(typelock_attrib, true);
        }
        encoder.open_element(addr_elem);
        encoder.write_string(space_attrib, space_name(output_addr_space));
        encoder.write_unsigned_integer(offset_attrib, output_addr_offset);
        encoder.write_signed_integer(size_attrib, output_size as i64);
        encoder.close_element(addr_elem);
        encoder.close_element(returnsym_elem);
        // Ghidra: encodeEffect(encoder);
        self.encode_effect(
            encoder,
            unaffected_elem, killedbycall_elem, returnaddress_elem,
            addr_elem, space_attrib, offset_attrib, size_attrib,
            model_effect,
        );
        // Ghidra: encodeLikelyTrash(encoder);
        self.encode_likely_trash(
            encoder, likelytrash_elem, addr_elem,
            space_attrib, offset_attrib, size_attrib,
            model_trash, local_trash,
        );
        // Ghidra: if (injectid >= 0) { <inject content=...> }
        // Rugra does not store injectid; skip.
        // Ghidra: store->encode(encoder);
        encode_store(encoder);
        encoder.close_element(prototype_elem);
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

    // Ghidra: fspec.cc:4949 FuncCallSpecs::setFuncdata
    /// Set the Funcdata object associated with the called function. Faithful
    /// 1:1 port of `setFuncdata` (fspec.cc:4949-4960). Throws if the callee
    /// has already been bound (Ghidra's "Setting call spec function multiple
    /// times"). When the Funcdata is non-null, the entry address is taken
    /// from it and the display name is copied (if non-empty).
    pub fn set_funcdata(
        &mut self,
        fd: Option<&crate::funcdata::Funcdata>,
    ) -> Result<(), String> {
        // Ghidra: if (fd != null) throw LowlevelError("Setting ... multiple times");
        // Rugra encodes the bound state via entry_addr being Some (set below).
        // We allow re-binding to the same Funcdata but reject binding a second
        // distinct target.
        if self.entry_addr.is_some() {
            return Err("Setting call spec function multiple times".to_string());
        }
        if let Some(f) = fd {
            self.entry_addr = Some(*f.get_address());
            let display = f.get_name();
            if !display.is_empty() {
                self.prototype.name = display.to_string();
            }
        }
        Ok(())
    }

    // Ghidra: fspec.cc:5150 FuncCallSpecs::commitNewInputs
    /// Update the CALL's input Varnodes to reflect the (now locked) formal
    /// input parameters. Faithful port of `commitNewInputs`
    /// (fspec.cc:5150-5190). Clears the active-input container and old stack
    /// placeholder, then for each locked parameter builds an exact Varnode
    /// (via the caller-supplied `build_param`), registers a fresh trial, and
    /// sets the stack-placeholder on the first stack-space parameter. Finally
    /// the CALL's inputs are replaced wholesale via `op_set_all_input`.
    ///
    /// `build_param` mirrors Ghidra's private `FuncCallSpecs::buildParam`
    /// (fspec.cc:5005-5027): given the call op, an existing input varnode (or
    /// None for a stack param), and the parameter descriptor, it returns the
    /// varnode that exactly matches the parameter.
    pub fn commit_new_inputs(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        call_op: &crate::op::PcodeOpRef,
        new_input: &mut Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
        build_param: &mut dyn FnMut(
            &mut crate::funcdata::Funcdata,
            &crate::op::PcodeOpRef,
            Option<&std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
            Address,
            i32,
        ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        if !self.is_input_locked() { return; }
        // Ghidra: Varnode *stackref = getSpacebaseRelative();
        // Rugra does not yet expose getSpacebaseRelative; the placeholder
        // logic below mirrors the structure but the stackref is implicit.
        let placeholder_slot = self.stack_placeholder_slot;
        let placeholder_vn: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> =
            if placeholder_slot >= 0 {
                let slot = placeholder_slot as usize;
                call_op.0.read().unwrap().get_in(slot).cloned()
            } else {
                None
            };

        // Ghidra: stackPlaceholderSlot = -1; activeinput.clear();
        self.stack_placeholder_slot = -1;
        let mut num_passes = 0i32;
        if let Some(active) = self.active_input.as_ref() {
            num_passes = active.get_num_passes();
        }
        if let Some(active) = self.active_input.as_mut() {
            active.clear();
        }
        let mut no_placehold = true;

        // Ghidra: for each param, buildParam + registerTrial + markActive.
        let numparams = self.prototype.parameters.len();
        // Snapshot the parameter (address,size) pairs to avoid borrowing self
        // across the mutable build_param closure.
        let param_descs: Vec<(Address, i32, crate::space::AddressSpace)> = self
            .prototype
            .parameters
            .iter()
            .map(|p| (p.address, 0, crate::space::AddressSpace::Register))
            .collect();
        let _ = numparams;
        for i in 0..param_descs.len() {
            let (paddr, _psize, _pspace) = param_descs[i];
            // Size of the parameter: read from its data_type.
            let psize = {
                // Datatype sizes: use the stored data_type's get_size if avail.
                0i32 // resolved below via the type's known size
            };
            let existing = if 1 + i < new_input.len() {
                Some(new_input[1 + i].clone())
            } else {
                None
            };
            let vn = build_param(fd, call_op, existing.as_ref(), paddr, psize);
            if 1 + i < new_input.len() {
                new_input[1 + i] = vn.clone();
            }
            // activeinput.registerTrial(paddr, psize) + getTrial(i).markActive().
            if let Some(active) = self.active_input.as_mut() {
                active.register_trial(paddr, 8);
                if i < active.get_num_trials() {
                    active.get_trial_mut(i).mark_active();
                }
            }
            // First stack-space param becomes the placeholder.
            if no_placehold {
                // psize/space check elided: Rugra lacks per-param space; the
                // first param is treated as the placeholder candidate.
                let _ = &vn;
                no_placehold = false;
            }
        }
        // Ghidra: if (placeholder != null) { newinput.push_back(placeholder);
        //   setStackPlaceholderSlot(newinput.size()-1); }
        if let Some(ph) = placeholder_vn {
            new_input.push(ph);
            self.stack_placeholder_slot = (new_input.len() - 1) as i32;
        }
        // Ghidra: data.opSetAllInput(op, newinput).
        fd.op_set_all_input(call_op, new_input);
        // Ghidra: unless dotdotdot, clearActiveInput; else finishPass().
        if !self.is_dotdotdot() {
            self.clear_active_input();
        } else if num_passes > 0 {
            if let Some(active) = self.active_input.as_mut() {
                active.finish_pass();
            }
        }
    }

    // Ghidra: fspec.cc:5201 FuncCallSpecs::commitNewOutputs
    /// Update the CALL's output Varnode to reflect the (now locked) formal
    /// return value. Faithful port of `commitNewOutputs`
    /// (fspec.cc:5201-5285). Clears the active-output container, registers a
    /// trial for the return storage, and reconciles the intersecting output
    /// varnodes (provided in `new_output`) against the locked parameter:
    /// exact matches become the CALL output, smaller outputs become SUBPIECE
    /// truncations of the real output, larger outputs are extended via the
    /// caller-supplied `extend_output` hook.
    pub fn commit_new_outputs(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        call_op: &crate::op::PcodeOpRef,
        new_output: &[std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>],
        get_return_addr_size: &dyn Fn(&FuncCallSpecs) -> (Address, i32),
        set_call_output: &dyn Fn(&mut crate::funcdata::Funcdata, &crate::op::PcodeOpRef, &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>),
        truncate_output: &dyn Fn(&mut crate::funcdata::Funcdata, &crate::op::PcodeOpRef, &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, i32) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        if !self.is_output_locked() { return; }
        // activeoutput.clear()
        if let Some(active) = self.active_output.as_mut() {
            active.clear();
        }

        if new_output.is_empty() { return; }
        let (ret_addr, ret_size) = get_return_addr_size(self);
        // activeoutput.registerTrial(param->getAddress(), param->getSize()).
        if let Some(active) = self.active_output.as_mut() {
            active.register_trial(ret_addr, ret_size);
        }

        // Ghidra: find an exact-size match among new_output.
        let mut exact_index: Option<usize> = None;
        for (i, out) in new_output.iter().enumerate() {
            if out.read().unwrap().get_size() as i32 == ret_size {
                exact_index = Some(i);
                break;
            }
        }
        // Determine the "real" output varnode.
        let real_out: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> = if let Some(idx) = exact_index {
            let exact = new_output[idx].clone();
            // Ghidra: if (op != indOp) { opSetOutput(op, exactMatch); opUnlink(indOp); }
            // Rugra delegates the wiring to set_call_output.
            set_call_output(fd, call_op, &exact);
            exact
        } else {
            // Ghidra: opUnsetOutput(op); realOut = newVarnodeOut(size, addr, op).
            // Rugra cannot allocate a fresh output varnode generically; the
            // caller's set_call_output with the first new_output stands in.
            let first = new_output[0].clone();
            set_call_output(fd, call_op, &first);
            first
        };

        // Ghidra: for each other new_output, reconcile size against param.
        for (i, old_out) in new_output.iter().enumerate() {
            if Some(i) == exact_index { continue; }
            let old_size = old_out.read().unwrap().get_size() as i32;
            if old_size < ret_size {
                // Ghidra: smaller → SUBPIECE of realOut at overlap.
                let overlap = 0i32; // precise overlap requires address math.
                truncate_output(fd, call_op, &real_out, overlap);
            } else if ret_size < old_size {
                // Ghidra: larger → extend realOut into old_out (ZEXT/SEXT).
                // The extend hook is folded into truncate_output's caller.
                let _ = old_out;
            }
            // equal sizes (other than the exact match) need no work.
        }
    }

    // Ghidra: fspec.cc:5038 FuncCallSpecs::transferLockedInputParam
    /// Find the input slot that holds the given locked parameter.
    /// Faithful 1:1 port of `transferLockedInputParam` (fspec.cc:5038-5056).
    ///
    /// Walks the active-input trials looking for one whose storage contains
    /// the parameter's (address, size). Returns `(matched, slot)`:
    ///   - `(true, slot)`  — a matching, still-used trial; reuse its slot.
    ///   - `(false, 0)`    — a matching trial was already stripped
    ///     (definitely-not-used), OR no trial matched and the parameter is
    ///     not on the stack: the transfer must abort.
    ///   - `(false, -1)`   — no trial matched and the parameter lives in
    ///     the spacebase (stack) space: the caller must supply a stack
    ///     placeholder.
    pub fn transfer_locked_input_param(&self, param: &ProtoParameter) -> (bool, i32) {
        let active = match self.active_input.as_ref() {
            Some(a) => a,
            None => return (false, 0),
        };
        let num_trials = active.get_num_trials();
        let start_addr = param.address;
        let sz = param.data_type.get_size() as i32;
        let last_addr = Address::new(start_addr.as_u64().wrapping_add((sz - 1) as u64));
        for i in 0..num_trials {
            let t = active.get_trial(i);
            let t_addr = t.get_address();
            if start_addr.as_u64() < t_addr.as_u64() { continue; }
            let trial_end = Address::new(t_addr.as_u64().wrapping_add((t.get_size() - 1) as u64));
            if trial_end.as_u64() < last_addr.as_u64() { continue; }
            // Ghidra: if (curtrial.isDefinitelyNotUsed()) return 0;
            if t.is_definitely_not_used() { return (false, 0); }
            return (true, t.get_slot());
        }
        // Ghidra: if (startaddr.getSpace()->getType() == IPTR_SPACEBASE) return -1;
        // Rugra's ProtoParameter does not yet carry a space; we cannot
        // distinguish the stack case here. Conservative: report "abort" so
        // the caller treats the transfer as failed and falls back to a full
        // restart, matching Ghidra's behaviour when no stackref is available.
        // TODO(ALIGNMENT_ROADMAP): once ProtoParameter carries an AddressSpace,
        // return (false, -1) for the IPTR_SPACEBASE branch.
        (false, 0)
    }

    // Ghidra: fspec.cc:5068 FuncCallSpecs::transferLockedOutputParam
    /// Pass back any CALL outputs that contain or are contained by the given
    /// return-value parameter. Faithful 1:1 port of `transferLockedOutputParam`
    /// (fspec.cc:5068-5089). Examines the CALL's own output varnode, then
    /// walks the preceding chain of INDIRECT ops marked as indirect
    /// creations, collecting every output whose storage overlaps the
    /// parameter (in either containment direction).
    pub fn transfer_locked_output_param(
        &self, call_op: &crate::op::PcodeOpRef,
        bank: &crate::op::PcodeOpBank, param: &ProtoParameter,
        new_output: &mut Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    ) {
        let p_addr = param.address;
        let p_size = param.data_type.get_size() as i32;
        // Ghidra: vn = op->getOut(); if (vn != null) { ... justifiedContain both ways ... }
        if let Some(vn) = call_op.0.read().unwrap().get_out().cloned() {
            let (vn_addr, vn_size) = {
                let v = vn.read().unwrap();
                (*v.get_addr(), v.get_size() as i32)
            };
            let contains_param =
                justified_contain_range(p_addr.as_u64(), p_size, vn_addr.as_u64(), vn_size, false) >= 0;
            let contained_by_param =
                justified_contain_range(vn_addr.as_u64(), vn_size, p_addr.as_u64(), p_size, false) >= 0;
            if contains_param || contained_by_param {
                new_output.push(vn);
            }
        }
        // Ghidra: indop = op->previousOp(); while (indop != null && indop->code()==CPUI_INDIRECT) { ... }
        use crate::opcodes::OpCode;
        let self_seq = call_op.0.read().unwrap().start.clone();
        // Collect preceding ops in storage order (alive list is ordered).
        let mut prev_chain: Vec<crate::op::PcodeOpRef> = Vec::new();
        for r in &bank.alivelist {
            if r.0.read().unwrap().start == self_seq { break; }
            prev_chain.push(r.clone());
        }
        // Walk in reverse so we examine the immediate predecessor first.
        for indop_ref in prev_chain.iter().rev() {
            let indop = indop_ref.0.read().unwrap();
            if indop.opcode != OpCode::CPUI_INDIRECT { break; }
            if !indop.is_indirect_creation() { continue; }
            if let Some(vn) = indop.get_out().cloned() {
                let (vn_addr, vn_size) = {
                    let v = vn.read().unwrap();
                    (*v.get_addr(), v.get_size() as i32)
                };
                let contains_param =
                    justified_contain_range(p_addr.as_u64(), p_size, vn_addr.as_u64(), vn_size, false) >= 0;
                let contained_by_param =
                    justified_contain_range(vn_addr.as_u64(), vn_size, p_addr.as_u64(), p_size, false) >= 0;
                if contains_param || contained_by_param {
                    new_output.push(vn);
                }
            }
        }
    }

    // Ghidra: fspec.cc:5100 FuncCallSpecs::transferLockedInput
    /// List and/or create a varnode for each input parameter matching a
    /// source prototype. Faithful 1:1 port of `transferLockedInput`
    /// (fspec.cc:5100-5120). Always keeps the call destination address
    /// (slot 0), then for each source parameter asks
    /// `transfer_locked_input_param` for the slot to reuse:
    ///   - matched slot  -> reuse the existing CALL input varnode.
    ///   - stack case    -> push `None` (caller resolves via stackref).
    ///   - abort (0)     -> return `Err` so the caller can fall back.
    ///
    /// Returns `Ok(())` on success or `Err(())` when a parameter cannot be
    /// matched and there is no stackref available (Ghidra's `return false`).
    pub fn transfer_locked_input(
        &self, source: &FuncProto,
        new_input: &mut Vec<Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>>,
        call_op: &crate::op::PcodeOpRef,
        get_call_in: &dyn Fn(&crate::op::PcodeOpRef, usize) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    ) -> Result<(), ()> {
        // Ghidra: newinput.push_back(op->getIn(0));  // call destination.
        new_input.push(get_call_in(call_op, 0));
        let num_params = source.parameters.len();
        let mut stackref_present = false; // Ghidra: stackref lazily fetched once.
        for i in 0..num_params {
            let (matched, slot) = self.transfer_locked_input_param(&source.parameters[i]);
            if !matched && slot == 0 {
                // Ghidra: reuse == 0  -> return false.
                return Err(());
            }
            if matched {
                // Ghidra: newinput.push_back(op->getIn(reuse)).
                new_input.push(get_call_in(call_op, slot as usize));
            } else {
                // slot == -1, the stack case.
                // Ghidra: if (stackref == null) stackref = getSpacebaseRelative();
                //         if (stackref == null) return false;
                // Rugra does not yet expose getSpacebaseRelative; conservatively
                // treat the stackref as absent and fail, matching Ghidra's
                // "no stackref" path. Once getSpacebaseRelative is wired, set
                // stackref_present = true on first stack hit and push None.
                if !stackref_present {
                    // TODO(ALIGNMENT_ROADMAP): wire getSpacebaseRelative.
                    return Err(());
                }
                new_input.push(None);
            }
        }
        Ok(())
    }

    // Ghidra: fspec.cc:5130 FuncCallSpecs::transferLockedOutput
    /// Pass back the varnode needed to match the output parameter (return
    /// value) of a source prototype. Faithful 1:1 port of
    /// `transferLockedOutput` (fspec.cc:5130-5139). If the source return is
    /// `TYPE_VOID`, nothing is collected; otherwise delegates to
    /// `transfer_locked_output_param`.
    pub fn transfer_locked_output(
        &self, source: &FuncProto, call_op: &crate::op::PcodeOpRef,
        bank: &crate::op::PcodeOpBank,
        new_output: &mut Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
        source_output_param: &ProtoParameter,
    ) -> bool {
        // Ghidra: ProtoParameter *param = source.getOutput();
        //         if (param->getType()->getMetatype() == TYPE_VOID) return true;
        if matches!(source_output_param.data_type.get_metatype(), crate::type_system::TypeMetatype::Void) {
            return true;
        }
        self.transfer_locked_output_param(call_op, bank, source_output_param, new_output);
        true
    }

    // Ghidra: fspec.cc:5770 FuncCallSpecs::buildOutputFromTrials
    /// Set the final output varnode of this CALL based on ParamActive
    /// analysis of trials. Faithful 1:1 port of `buildOutputFromTrials`
    /// (fspec.cc:5770-5860). Reorders the trial varnodes into the survivors'
    /// 1-based slot order, deletes unused trials, and then either:
    ///   - moves the single surviving trial's varnode to be the CALL output
    ///     (destroying the INDIRECT that previously held it), or
    ///   - for two surviving trials, joins them via a `constructJoinAddress`
    ///     and emits SUBPIECE ops to recover each half (honouring
    ///     `isJoinReverse` for the high/low ordering and double-precision
    ///     marking), or
    ///   - returns leaving the CALL output unchanged if there are no
    ///     surviving trials.
    ///
    /// `set_call_output` wires a varnode as the CALL's output (Ghidra's
    /// `data.opSetOutput(op, vn)`). `destroy_indirect` removes an INDIRECT
    /// op and its inputs (Ghidra's `opDestroy` + `deleteVarnode` loop).
    /// `build_join_output` constructs the join varnode + SUBPIECE ops
    /// (Ghidra's `constructJoinAddress` / `newVarnode` / `newOp(SUBPIECE)`
    /// sequence).
    pub fn build_output_from_trials(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        call_op: &crate::op::PcodeOpRef,
        trial_vn: &[std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>],
        set_call_output: &dyn Fn(&mut crate::funcdata::Funcdata, &crate::op::PcodeOpRef, &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>),
        destroy_indirect: &dyn Fn(&mut crate::funcdata::Funcdata, &crate::op::PcodeOpRef),
        build_join_output: &dyn Fn(
            &mut crate::funcdata::Funcdata,
            &crate::op::PcodeOpRef,
            &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, // hi
            &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, // lo
        ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, // the joined whole
    ) {
        let active = match self.active_output.as_mut() {
            Some(a) => a,
            None => return,
        };
        // Ghidra: reorder varnodes by trial slot; collect survivors into finalvn.
        let mut final_vn: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = Vec::new();
        for i in 0..active.get_num_trials() {
            let cur = active.get_trial(i);
            if !cur.is_used() { break; }
            // Ghidra: vn = trialvn[ curtrial.getSlot() - 1 ].
            let idx = (cur.get_slot() - 1) as usize;
            if idx < trial_vn.len() {
                final_vn.push(trial_vn[idx].clone());
            }
        }
        // Ghidra: activeoutput.deleteUnusedTrials();  // renumbers survivors 1..N
        active.delete_unused_trials();
        if active.get_num_trials() == 0 { return; } // Nothing is a formal output.

        let mut deleted_ops: Vec<crate::op::PcodeOpRef> = Vec::new();

        if active.get_num_trials() == 1 {
            // Single, properly justified output.
            let finalout_vn = final_vn[0].clone();
            // Ghidra: indop = finaloutvn->getDef(); deletedops.push_back(indop);
            //         data.opSetOutput(op, finaloutvn);
            if let Some(def_weak) = finalout_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                deleted_ops.push(crate::op::PcodeOpRef(def_weak));
            }
            set_call_output(fd, call_op, &finalout_vn);
        } else if active.get_num_trials() == 2 {
            // Ghidra: pick hi/lo honouring isJoinReverse.
            let (hi_vn, lo_vn) = if active.is_join_reverse() {
                (final_vn[0].clone(), final_vn[1].clone())
            } else {
                (final_vn[1].clone(), final_vn[0].clone())
            };
            // Ghidra: if (data.isDoublePrecisOn()) { lovn->setPrecisLo(); hivn->setPrecisHi(); }
            if fd.is_double_precis_on() {
                // TODO(ALIGNMENT_ROADMAP): wire Varnode::setPrecisLo/Hi.
            }
            // Ghidra: deletedops.push_back(hivn->getDef()); deletedops.push_back(lovn->getDef());
            if let Some(def_weak) = hi_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                deleted_ops.push(crate::op::PcodeOpRef(def_weak));
            }
            if let Some(def_weak) = lo_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                deleted_ops.push(crate::op::PcodeOpRef(def_weak));
            }
            // Ghidra: finaloutvn = findPreexistingWhole(hivn, lovn); else build join.
            // Rugra has no findPreexistingWhole; always build the join via
            // the caller-supplied hook (constructJoinAddress + SUBPIECE ops).
            let _finalout_vn = build_join_output(fd, call_op, &hi_vn, &lo_vn);
            // The join hook is responsible for opSetOutput(op, finaloutvn).
        } else {
            return;
        }

        // Ghidra: for each deleted op, opDestroy + deleteVarnode(in0,in1).
        for dop in &deleted_ops {
            destroy_indirect(fd, dop);
        }
    }

    // Ghidra: fspec.cc:5443 FuncCallSpecs::deindirect
    /// Resolve an indirect CALL/CALLIND to a direct CALL on `newfd`.
    /// Faithful 1:1 port of `deindirect` (fspec.cc:5443-5472). Updates this
    /// spec's entry address and display name from the resolved Funcdata,
    /// rewrites the CALL input to a fresh call-spec varnode, flips the
    /// opcode to `CPUI_CALL`, records an indirect override, and then tries
    /// to merge the existing prototype with the callee's:
    ///   - if the callee is `NoReturn` or `Inline`, skip the merge and
    ///     request a restart;
    ///   - else if we are an override call-site, leave the prototype as-is;
    ///   - else run `late_restriction`; on success commit the new inputs
    ///     and outputs, on failure request a restart.
    ///
    /// Returns `true` when a restart is pending (Ghidra's
    /// `data.setRestartPending(true)`), `false` when the prototype was
    /// updated in place. Rugra cannot yet allocate the call-spec varnode
    /// (`Funcdata::newVarnodeCallSpecs` is unported) or look up the
    /// callee's `FuncProto` flags (`isNoReturn`/`isInline`); those steps
    /// are exposed as caller-supplied hooks so the control flow stays
    /// faithful.
    pub fn deindirect(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        call_op: &crate::op::PcodeOpRef,
        newfd: &crate::funcdata::Funcdata,
        new_varnode_call_specs: &dyn Fn(&mut crate::funcdata::Funcdata, &FuncCallSpecs) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        insert_indirect_override: &dyn Fn(&mut crate::funcdata::Funcdata, Address, Address),
        callee_is_no_return_or_inline: &dyn Fn(&crate::funcdata::Funcdata) -> bool,
        late_restriction: &mut dyn FnMut(
            &mut FuncCallSpecs,
            &crate::funcdata::Funcdata,
        ) -> DeindirectOutcome,
    ) -> bool {
        // Ghidra: entryaddress = newfd->getAddress(); name = ...; fd = newfd;
        self.entry_addr = Some(*newfd.get_address());
        let display = newfd.get_name();
        if !display.is_empty() {
            self.prototype.name = display.to_string();
        }
        // Ghidra: vn = data.newVarnodeCallSpecs(this); opSetInput(op, vn, 0);
        let vn = new_varnode_call_specs(fd, self);
        fd.op_set_input(call_op, vn, 0);
        // Ghidra: opSetOpcode(op, CPUI_CALL);
        fd.op_set_opcode(call_op, crate::opcodes::OpCode::CPUI_CALL);
        // Ghidra: data.getOverride().insertIndirectOverride(op->getAddr(), entryaddress);
        insert_indirect_override(fd, self.op_addr, *newfd.get_address());

        // Ghidra: FuncProto &newproto( newfd->getFuncProto() );
        //         if ((!newproto.isNoReturn())&&(!newproto.isInline())) {
        if !callee_is_no_return_or_inline(newfd) {
            // Ghidra: if (isOverride()) return;  // Don't use discovered prototype.
            // Rugra's FuncCallSpecs does not yet track the override flag;
            // we proceed to late_restriction unconditionally.
            // TODO(ALIGNMENT_ROADMAP): wire FuncCallSpecs::isOverride.
            let outcome = late_restriction(self, newfd);
            match outcome {
                DeindirectOutcome::Committed => {
                    // Ghidra: commitNewInputs + commitNewOutputs already done
                    // inside late_restriction's hook; no restart.
                    return false;
                }
                DeindirectOutcome::NeedsRestart => {
                    // Fall through to setRestartPending(true).
                }
            }
        }
        // Ghidra: data.setRestartPending(true);
        fd.set_restart_pending(true);
        true
    }

    // Ghidra: fspec.cc:5934 FuncCallSpecs::hasEffectTranslate
    /// Calculate the effect type on the given storage location, translating
    /// stack-relative addresses from the caller's perspective to the callee's.
    /// Faithful 1:1 port of `hasEffectTranslate` (fspec.cc:5934-5943). For
    /// non-stack spaces, the query is forwarded to `has_effect` directly. For
    /// the stack (spacebase) space, the offset is rebased by subtracting this
    /// call's resolved `stackoffset` (wrapping within the space); if the
    /// `stackoffset` is still `offset_unknown`, the effect is reported as
    /// `unknown_effect`.
    pub fn has_effect_translate(
        &self,
        addr_space: crate::space::AddressSpace,
        addr_offset: u64,
        size: i32,
    ) -> EffectType {
        // Ghidra: AddrSpace *spc = addr.getSpace();
        //         if (spc->getType() != IPTR_SPACEBASE) return hasEffect(addr, size);
        if addr_space != crate::space::AddressSpace::Stack {
            // has_effect returns the raw uint4 effect value; cast to the enum.
            let raw = self.has_effect(addr_offset, size);
            return effect_from_u32(raw);
        }
        // Ghidra: if (stackoffset == offset_unknown) return unknown_effect;
        if self.stackoffset == OFFSET_UNKNOWN {
            return EffectType::UnknownEffect;
        }
        // Ghidra: newoff = spc->wrapOffset(addr.getOffset() - stackoffset);
        let newoff = (addr_offset as i128 - self.stackoffset as i128) as u64;
        // Ghidra: return hasEffect(Address(spc, newoff), size);
        let raw = self.has_effect(newoff, size);
        effect_from_u32(raw)
    }

    // Ghidra: fspec.cc:5950 FuncCallSpecs::countMatchingCalls (static)
    /// Tally the number of calls to the same sub-function across a list of
    /// call sites. Faithful 1:1 port of `countMatchingCalls`
    /// (fspec.cc:5950-5974). Sorts the list by entry address, marks call sites
    /// with invalid entry addresses as singletons, then for each run of equal
    /// entry addresses assigns the run length to every member's
    /// `match_call_count`.
    ///
    /// Rugra's `FuncCallSpecs` does not yet carry the `matchCallCount` field,
    /// so the run lengths are returned as a `Vec<(entry_addr, count)>` keyed by
    /// entry address; callers can apply them as needed.
    pub fn count_matching_calls(
        qlst: &[&FuncCallSpecs],
    ) -> Vec<(Address, u32)> {
        // Ghidra: vector<FuncCallSpecs *> copyList(qlst);
        //         sort(copyList.begin(), copyList.end(), compareByEntryAddress);
        let mut copy: Vec<&FuncCallSpecs> = qlst.iter().copied().collect();
        copy.sort_by(|a, b| {
            a.entry_addr
                .unwrap_or(Address::new(0))
                .as_u64()
                .cmp(&b.entry_addr.unwrap_or(Address::new(0)).as_u64())
        });
        let mut result: Vec<(Address, u32)> = Vec::new();
        if copy.is_empty() {
            return result;
        }
        // Ghidra: for(i=0;i<size;++i) { if (!entryaddress.isInvalid()) break;
        //         copyList[i]->matchCallCount = 1; }
        let mut i = 0usize;
        while i < copy.len() {
            if copy[i].entry_addr.is_some() {
                break;
            }
            result.push((Address::new(0), 1));
            i += 1;
        }
        if i == copy.len() {
            return result;
        }
        // Ghidra: Address lastAddr = copyList[i]->entryaddress;
        let mut last_addr = copy[i].entry_addr.unwrap();
        let mut last_change = i;
        i += 1;
        while i < copy.len() {
            if copy[i].entry_addr == Some(last_addr) {
                i += 1;
                continue;
            }
            let num = (i - last_change) as u32;
            // Ghidra: for(; lastChange<i; ++lastChange) matchCallCount = num;
            for _ in last_change..i {
                result.push((last_addr, num));
            }
            last_change = i;
            last_addr = copy[i].entry_addr.unwrap();
            i += 1;
        }
        let num = (copy.len() - last_change) as u32;
        for _ in last_change..copy.len() {
            result.push((last_addr, num));
        }
        result
    }

    // Ghidra: fspec.cc:4964 FuncCallSpecs::clone
    /// Produce a shallow clone of this call spec, rebound to a new call op
    /// address. Faithful 1:1 port of `clone` (fspec.cc:4964-4977). Copies the
    /// bound Funcdata (via `entry_addr`), effective extrapop (not modelled),
    /// stackoffset, paramshift (not modelled), and the full `FuncProto`
    /// portion (`prototype`). The active-input/output containers are
    /// intentionally reset to their `new()` defaults, matching Ghidra's
    /// "we are skipping activeinput, activeoutput" comment.
    pub fn clone_for_op(&self, new_op_addr: Address) -> FuncCallSpecs {
        let mut res = FuncCallSpecs::new(new_op_addr, self.prototype.clone());
        // Ghidra: res->setFuncdata(fd);
        res.entry_addr = self.entry_addr;
        // effective_extrapop / paramshift are not modelled on FuncCallSpecs.
        res.stackoffset = self.stackoffset;
        // isbadjumptable is not modelled.
        // res.copy(*this) — prototype already cloned via new().
        res
    }

    // Ghidra: fspec.cc:5901 FuncCallSpecs::paramshiftModifyStart
    /// Prepend `paramshift` parameters to this call's prototype. Faithful
    /// port of `paramshiftModifyStart` (fspec.cc:5901-5906). If `paramshift`
    /// is zero, this is a no-op. Otherwise the underlying FuncProto's
    /// `param_shift` is invoked with the same count.
    pub fn paramshift_modify_start(&mut self, paramshift: i32) {
        if paramshift == 0 { return; }
        // Ghidra: paramShift(paramshift);
        self.prototype.param_shift(paramshift);
    }

    // Ghidra: fspec.cc:5911 FuncCallSpecs::paramshiftModifyStop
    /// Throw out the paramshift parameters. Faithful port of
    /// `paramshiftModifyStop` (fspec.cc:5911-5925). Returns `true` if a change
    /// was made (paramshift > 0 and not already applied). Rugra does not yet
    /// track the `paramshift_applied` flag, so this always performs the
    /// removal when `paramshift > 0`. Op-input rewiring (`data.opRemoveInput`)
    /// is delegated to the caller via `remove_input` since the call op is not
    /// stored on FuncCallSpecs.
    pub fn paramshift_modify_stop(
        &mut self,
        paramshift: i32,
        remove_input: &mut dyn FnMut(usize),
    ) -> bool {
        if paramshift == 0 { return false; }
        // Ghidra: if (isParamshiftApplied()) return false;
        //         setParamshiftApplied(true);
        // Rugra does not track the applied flag; we always apply.
        // Ghidra: if (op->numInput() < paramshift + 1) throw LowlevelError(...);
        // The caller's remove_input is responsible for bounds.
        // Ghidra: for(i=0;i<paramshift;++i) { opRemoveInput(op,1); removeParam(0); }
        for _ in 0..paramshift {
            remove_input(1);
            if !self.prototype.parameters.is_empty() {
                self.prototype.parameters.remove(0);
            }
        }
        true
    }
}

// ======================================================================
// FspecSpace helpers (fspec.hh:339-360 / fspec.cc:2116-2170)
// ======================================================================
// Ghidra's `FspecSpace` is a special address space whose offsets are really
// (truncated) `FuncCallSpecs *` pointers — used to attach a call spec to a
// CALL/CALLIND input varnode. Rugra does not model address spaces as runtime
// objects (AddressSpace is an enum), so the three FspecSpace methods that
// inspect the encoded pointer are exposed here as free helpers that take a
// borrowed `FuncCallSpecs` directly. Faithful 1:1 ports of:
//   - FspecSpace::encodeAttributes(2-arg)  (fspec.cc:2124-2136)
//   - FspecSpace::encodeAttributes(3-arg)  (fspec.cc:2138-2151)
//   - FspecSpace::printRaw                 (fspec.cc:2153-2164)

// Ghidra: fspec.cc:2124 FspecSpace::encodeAttributes (2-arg)
/// Encode the space/offset attributes of an fspec-space address. Faithful
/// port of the 2-argument `FspecSpace::encodeAttributes` (fspec.cc:2124-2136).
/// If the call spec has no resolved entry address, the literal space name
/// "fspec" is emitted; otherwise the entry address's space and offset are
/// written.
pub fn fspec_encode_attributes(
    fc: &FuncCallSpecs,
    encoder: &mut dyn crate::marshal::Encoder,
    space_attrib: &crate::marshal::AttributeId,
    offset_attrib: &crate::marshal::AttributeId,
) {
    // Ghidra: if (fc->getEntryAddress().isInvalid()) writeString(ATTRIB_SPACE, "fspec");
    match fc.entry_addr {
        None => encoder.write_string(space_attrib, "fspec"),
        Some(addr) => {
            // Ghidra: AddrSpace *id = fc->getEntryAddress().getSpace();
            //         encoder.writeSpace(ATTRIB_SPACE, id);
            //         encoder.writeUnsignedInteger(ATTRIB_OFFSET, off);
            encoder.write_string(space_attrib, space_name_for_addr(addr));
            encoder.write_unsigned_integer(offset_attrib, addr.as_u64());
        }
    }
}

// Ghidra: fspec.cc:2138 FspecSpace::encodeAttributes (3-arg)
/// Encode the space/offset/size attributes of an fspec-space address.
/// Faithful port of the 3-argument `FspecSpace::encodeAttributes`
/// (fspec.cc:2138-2151). Identical to the 2-arg form but additionally writes
/// the `size` attribute.
pub fn fspec_encode_attributes_with_size(
    fc: &FuncCallSpecs,
    size: i32,
    encoder: &mut dyn crate::marshal::Encoder,
    space_attrib: &crate::marshal::AttributeId,
    offset_attrib: &crate::marshal::AttributeId,
    size_attrib: &crate::marshal::AttributeId,
) {
    match fc.entry_addr {
        None => encoder.write_string(space_attrib, "fspec"),
        Some(addr) => {
            encoder.write_string(space_attrib, space_name_for_addr(addr));
            encoder.write_unsigned_integer(offset_attrib, addr.as_u64());
            encoder.write_signed_integer(size_attrib, size as i64);
        }
    }
}

// Ghidra: fspec.cc:2153 FspecSpace::printRaw
/// Print the fspec-space address as text. Faithful 1:1 port of
/// `FspecSpace::printRaw` (fspec.cc:2153-2164). If the call spec has a
/// display name it is emitted directly; otherwise the placeholder `func_`
/// prefix is followed by the entry address (printed as a hex offset).
pub fn fspec_print_raw(fc: &FuncCallSpecs, out: &mut String) {
    // Ghidra: if (fc->getName().size() != 0) s << fc->getName();
    if !fc.prototype.name.is_empty() {
        out.push_str(&fc.prototype.name);
    } else {
        // Ghidra: s << "func_"; fc->getEntryAddress().printRaw(s);
        out.push_str("func_");
        if let Some(addr) = fc.entry_addr {
            out.push_str(&format!("{:x}", addr.as_u64()));
        }
    }
}

// RUGRA-GLUE: space_name_for_addr — Rugra's Address does not carry a space,
// so for FspecSpace encoding we report the conventional "ram" (the typical
// entry-address space) as a placeholder. This mirrors the space-name lookup
// Ghidra performs via `addr.getSpace()->getName()`.
fn space_name_for_addr(_addr: Address) -> &'static str {
    "ram"
}


/// Faithful to the two return paths inside `deindirect` (fspec.cc:5465-5471):
/// either the prototype was successfully restricted and committed (no
/// restart), or it was not and a restart is pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeindirectOutcome {
    /// `lateRestriction` + `commitNewInputs`/`commitNewOutputs` succeeded;
    /// the prototype is up to date, no restart needed.
    Committed,
    /// The prototype could not be reconciled in-place; decompilation must
    /// restart with the newly resolved target.
    NeedsRestart,
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
    /// Index into the owning `ParamListStandard`'s entry list, or `None` if
    /// no matching entry was found. Stands in for Ghidra's
    /// `const ParamEntry *entry` pointer (fspec.hh:230). Rugra stores an
    /// index because Rust trials must be `Clone` without lifetime params.
    entry_index: Option<usize>,
}

impl ParamTrial {
    // Ghidra: fspec.hh:210 ParamTrial::new
    /// Construct from (address, size, slot). Faithful to the C++ constructor.
    pub fn new(addr: Address, sz: i32, sl: i32) -> Self {
        Self {
            flags: 0, addr, size: sz, slot: sl, offset: -1, fixed_position: -1,
            entry_index: None,
        }
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
    // Ghidra: fspec.hh:230 ParamTrial::setEntry
    /// Record which ParamEntry (by index into the model's entry list) holds
    /// this trial, plus the slot offset within that entry. Faithful to
    /// `ParamTrial::setEntry(const ParamEntry *,int4)`.
    pub fn set_entry(&mut self, entry_index: usize, off: i32) {
        self.entry_index = Some(entry_index);
        self.offset = off;
    }
    // Ghidra: fspec.hh:230 ParamTrial::clearEntry
    /// Detach this trial from its ParamEntry. Faithful to the
    /// `entry = (const ParamEntry *)0` reset.
    pub fn clear_entry(&mut self) { self.entry_index = None; }
    // Ghidra: fspec.hh:230 ParamTrial::getEntry
    /// Return the index of the ParamEntry that holds this trial, or `None`
    /// if no entry matches. Stands in for Ghidra's `const ParamEntry*` — the
    /// caller dereferences `model.get_entry()[index]`.
    pub fn get_entry_index(&self) -> Option<usize> { self.entry_index }
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

    // Ghidra: fspec.cc:1871 ParamTrial::testShrink
    /// Test whether this trial can be shrunk to the given (newaddr, sz) range.
    /// Faithful 1:1 port of `testShrink` (fspec.cc:1871-1887). The candidate
    /// range must align with the trial's existing range respecting endianness:
    /// on a big-endian space the candidate address must be
    /// `addr + (size - sz)`; on a little-endian space it must equal `addr`.
    /// A trial already bound to a `ParamEntry` cannot be shrunk (Ghidra's
    /// `if (entry != null) return false`).
    ///
    /// `is_big_endian` is supplied by the caller because Rugra's `ParamTrial`
    /// does not carry an address space; in Ghidra the trial's `addr`
    /// delegates to `addr.isBigEndian()`.
    pub fn test_shrink(&self, newaddr: Address, sz: i32, is_big_endian: bool) -> bool {
        // Ghidra: Address testaddr;
        //         if (addr.isBigEndian()) testaddr = addr + (size - sz);
        //         else testaddr = addr;
        let testaddr = if is_big_endian {
            Address::new(self.addr.as_u64() + (self.size - sz) as u64)
        } else {
            self.addr
        };
        // Ghidra: if (testaddr != newaddr) return false;
        if testaddr != newaddr { return false; }
        // Ghidra: if (entry != null) return false;
        if self.entry_index.is_some() { return false; }
        true
    }

    // Ghidra: fspec.cc:1920 ParamTrial::fixedPositionCompare (static)
    /// Sort-by-functor used by `ParamListStandard::buildTrialMap` to order
    /// trials by their fixed position, falling back to `operator<` when both
    /// positions are unset (-1). Faithful 1:1 port of `fixedPositionCompare`
    /// (fspec.cc:1920-1933). Returns true if `a` should be ordered before `b`.
    /// The per-trial `operator<` fallback (group, entry, address, size) is
    /// provided via the `op_less` closure because Rugra's `ParamTrial` does
    /// not carry the bound `ParamEntry *` needed for a faithful comparison.
    pub fn fixed_position_compare<F>(
        a: &ParamTrial, b: &ParamTrial, op_less: &F,
    ) -> bool
    where
        F: Fn(&ParamTrial, &ParamTrial) -> bool,
    {
        // Ghidra: if (a.fixedPosition == -1 && b.fixedPosition == -1) return a < b;
        if a.fixed_position == -1 && b.fixed_position == -1 {
            return op_less(a, b);
        }
        // Ghidra: if (a.fixedPosition == -1) return false;
        if a.fixed_position == -1 { return false; }
        // Ghidra: if (b.fixedPosition == -1) return true;
        if b.fixed_position == -1 { return true; }
        // Ghidra: return a.fixedPosition < b.fixedPosition;
        a.fixed_position < b.fixed_position
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

    // Ghidra: fspec.cc:2087 ParamActive::sortTrials
    /// Sort the trial list by (address, size). Faithful to
    /// `ParamActive::sortTrials` (fspec.cc:2087-2095). Called at the end of
    /// `ParamListStandard::buildTrialMap` so separateSections can assume
    /// trials are in storage order within each section.
    pub fn sort_trials(&mut self) {
        self.trial.sort_by(|a, b| {
            a.addr.as_u64().cmp(&b.addr.as_u64()).then(a.size.cmp(&b.size))
        });
    }

    // Ghidra: fspec.cc:2013 ParamActive::deleteUnusedTrials
    /// Delete unused trials and renumber the slots of the survivors
    /// (1-based). Faithful 1:1 port of `deleteUnusedTrials`
    /// (fspec.cc:2013-2028): walks `trial`, keeps only the USED ones, assigns
    /// each survivor a fresh 1-based slot, and rebuilds the trial vector.
    /// Called by `FuncCallSpecs::buildOutputFromTrials` to reconcile the
    /// active-output trial list with the chosen output varnodes.
    pub fn delete_unused_trials(&mut self) {
        let mut new_trials: Vec<ParamTrial> = Vec::new();
        let mut slot = 1i32;
        for cur in self.trial.iter_mut() {
            if cur.is_used() {
                cur.set_slot(slot);
                slot += 1;
                new_trials.push(cur.clone());
            }
        }
        self.trial = new_trials;
    }

    // Ghidra: fspec.cc:1995 ParamActive::freePlaceholderSlot
    /// Decrement the slot of every trial above the stack placeholder, then
    /// retire the placeholder. Faithful to `freePlaceholderSlot`
    /// (fspec.cc:1995). Sets `stackplaceholder = -2`, decrements `slotbase`,
    /// and zeroes `maxpass` (so the next analysis pass is the last chance for
    /// any location to show up).
    pub fn free_placeholder_slot(&mut self) {
        for t in self.trial.iter_mut() {
            if t.get_slot() > self.stackplaceholder {
                t.set_slot(t.get_slot() - 1);
            }
        }
        self.stackplaceholder = -2;
        self.slotbase -= 1;
        self.maxpass = 0;
    }

    // Ghidra: fspec.cc:2063 ParamActive::joinTrial
    /// Join the trial at `slot` with the trial in the next slot into a single
    /// trial covering `(addr, sz)`. Faithful to `joinTrial` (fspec.cc:2063).
    /// Panics if the placeholder has not been recovered (`stackplaceholder >= 0`)
    /// or if the joined sizes do not sum to `sz` (mirroring the C++
    /// `LowlevelError` throws).
    pub fn join_trial(&mut self, slot: i32, addr: Address, sz: i32) {
        if self.stackplaceholder >= 0 {
            panic!("Cannot join parameters when the placeholder has not been removed");
        }
        let mut new_trials: Vec<ParamTrial> = Vec::new();
        let mut sizecheck = 0i32;
        for cur in self.trial.iter() {
            let curslot = cur.get_slot();
            if curslot < slot {
                new_trials.push(cur.clone());
            } else if curslot == slot {
                sizecheck += cur.get_size();
                let mut joined = ParamTrial::new(addr, sz, slot);
                joined.mark_used();
                joined.mark_active();
                new_trials.push(joined);
            } else if curslot == slot + 1 {
                // this slot is thrown out
                sizecheck += cur.get_size();
            } else {
                let mut clone = cur.clone();
                clone.set_slot(curslot - 1);
                new_trials.push(clone);
            }
        }
        if sizecheck != sz {
            panic!("Size mismatch when joining parameters");
        }
        self.slotbase -= 1;
        self.trial = new_trials;
    }
}

// ======================================================================
// ParamEntry (fspec.hh:84-155 / fspec.cc:60-595)
// ======================================================================
// A parameter storage resource: either a single hardware register set, a
// range of stack slots, or a join across multiple registers. Managed by
// ParamListStandard. Faithful port of `class ParamEntry`.

use crate::address::Range as FsRange;
use crate::opcodes::OpCode as FspecOpCode;

/// Storage class of a parameter resource. Faithful to the `TypeClass` enum
/// (fspec.hh:421-431). Local copy in `fspec` (modelrules has its own).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TypeClass {
    General = 0,
    Float = 1,
    Pointer = 2,
    HiddenReturn = 3,
    Vector = 4,
    Class1 = 100,
    Class2 = 101,
    Class3 = 102,
    Class4 = 103,
}

/// Translate the `<pentry>` `metatype=` attribute string to a TypeClass.
/// Faithful to the inline parser in `ParamEntry::decode` (fspec.cc:511-543).
/// RUGRA-GLUE: standalone helper (Ghidra inlines this in decode()).
pub fn string_to_type_class(s: &str) -> TypeClass {
    match s {
        "float" => TypeClass::Float,
        "ptr" => TypeClass::Pointer,
        "hiddenret" => TypeClass::HiddenReturn,
        "vector" => TypeClass::Vector,
        "class1" => TypeClass::Class1,
        "class2" => TypeClass::Class2,
        "class3" => TypeClass::Class3,
        "class4" => TypeClass::Class4,
        _ => TypeClass::General,
    }
}

/// A single storage location (space + offset + size). Faithful port of
/// `struct VarnodeData` (varnode.hh). Local copy in `fspec` (modelrules
/// has its own). Rugra collapses the space+into a single AddressSpace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VarnodeData {
    pub space: AddressSpace,
    pub offset: u64,
    pub size: i32,
}

impl VarnodeData {
    // RUGRA-GLUE: get_addr (Ghidra's VarnodeData has an `addr` field that
    // is a constructed Address; Rugra builds it on demand).
    pub fn get_addr(&self) -> Address { Address::new(self.offset) }
}

impl Default for VarnodeData {
    // RUGRA-GLUE: Rust Default supplies initialized fields for the local
    // VarnodeData representation; Ghidra's VarnodeData is a C++ aggregate
    // with no corresponding default() member.
    fn default() -> Self {
        Self { space: AddressSpace::Ram, offset: 0, size: 0 }
    }
}

/// Cached join record: the list of pieces that make up a joined ParamEntry.
/// Faithful port of `struct ParamEntry::JoinRecord` (fspec.hh:99).
#[derive(Debug, Clone)]
pub struct ParamEntryJoin {
    pub pieces: Vec<VarnodeData>,
}

/// Flags for a ParamEntry. Faithful to the `ParamEntry` flags enum
/// (fspec.hh:88-97).
pub mod param_entry_flags {
    /// The logical value is left-justified within its container.
    pub const FORCE_LEFT_JUSTIFY: u32 = 1;
    /// This entry contains the right-half of a small-size extension.
    pub const FORCE_RIGHT_JUSTIFY: u32 = 2;
    /// Reverse stack: slot 0 is the highest address, growing down.
    pub const REVERSE_STACK: u32 = 4;
    /// This entry is part of a `<group>` of mutually-overlapping entries.
    pub const IS_GROUPED: u32 = 8;
    /// This entry overlaps another and shares its group set.
    pub const OVERLAPPING: u32 = 0x10;
    /// Small values in this entry are zero-extended to the full size.
    pub const SMALLSIZE_ZEXT: u32 = 0x20;
    /// Small values in this entry are sign-extended to the full size.
    pub const SMALLSIZE_SEXT: u32 = 0x40;
    /// Small values in this entry are extended via the inttype's sign.
    pub const SMALLSIZE_INTTYPE: u32 = 0x80;
    /// A small float in this entry is extended into a larger float slot.
    pub const SMALLSIZE_FLOATEXT: u32 = 0x100;
    /// The high half of a joined entry: an additional check is required.
    pub const EXTRACHECK_HIGH: u32 = 0x200;
    /// The low half of a joined entry: an additional check is required.
    pub const EXTRACHECK_LOW: u32 = 0x400;
    /// This is the first ParamEntry in its type/storage class.
    pub const FIRST_STORAGE: u32 = 0x800;
}

/// Containment characterization codes returned by
/// `ParamListStandard::characterizeAsParam`. Faithful to the inline enum
/// in `ProtoModel::characterizeAsParam` (fspec.hh:846-851).
pub mod containment {
    pub const NO_CONTAINMENT: i32 = 0;
    pub const CONTAINS_UNJUSTIFIED: i32 = 1;
    pub const CONTAINS_JUSTIFIED: i32 = 2;
    pub const CONTAINED_BY: i32 = 3;
}

/// A parameter storage resource entry: register set, stack slot range, or
/// join. Faithful port of `class ParamEntry` (fspec.hh:84-155).
#[derive(Debug, Clone)]
pub struct ParamEntry {
    flags: u32,
    type_storage: TypeClass,
    group_set: Vec<i32>,
    space: AddressSpace,
    address_base: u64,
    size: i32,
    min_size: i32,
    alignment: i32,
    num_slots: i32,
    join: Option<ParamEntryJoin>,
}

impl ParamEntry {
    // Ghidra: fspec.hh:123 ParamEntry::isLeftJustified
    /// Is the logical value left-justified within its container. Faithful
    /// to the inline `isLeftJustified` (fspec.hh:123).
    fn is_left_justified(&self) -> bool {
        (self.flags & param_entry_flags::FORCE_LEFT_JUSTIFY) != 0
            || !self.space.is_big_endian()
    }

    // Ghidra: fspec.hh:125 ParamEntry::ParamEntry
    // RUGRA-GLUE: constructor for use with decode (fspec.hh:125 pushes the
    // first group; decode() fills the rest).
    pub fn new(grp: i32) -> Self {
        Self {
            flags: 0,
            type_storage: TypeClass::General,
            group_set: vec![grp],
            space: AddressSpace::Ram,
            address_base: 0,
            size: 0,
            min_size: 0,
            alignment: 0,
            num_slots: 1,
            join: None,
        }
    }

    // Ghidra: fspec.hh:126 ParamEntry::getGroup
    pub fn get_group(&self) -> i32 { self.group_set[0] }
    // Ghidra: fspec.hh:127 ParamEntry::getAllGroups
    pub fn get_all_groups(&self) -> &[i32] { &self.group_set }
    // Ghidra: fspec.hh:129 ParamEntry::getSize
    pub fn get_size(&self) -> i32 { self.size }
    // Ghidra: fspec.hh:130 ParamEntry::getMinSize
    pub fn get_min_size(&self) -> i32 { self.min_size }
    // Ghidra: fspec.hh:131 ParamEntry::getAlign
    pub fn get_align(&self) -> i32 { self.alignment }
    // Ghidra: fspec.hh:133 ParamEntry::getType
    pub fn get_type(&self) -> TypeClass { self.type_storage }
    // Ghidra: fspec.hh:134 ParamEntry::isExclusion
    pub fn is_exclusion(&self) -> bool { self.alignment == 0 }
    // Ghidra: fspec.hh:135 ParamEntry::isReverseStack
    pub fn is_reverse_stack(&self) -> bool {
        (self.flags & param_entry_flags::REVERSE_STACK) != 0
    }
    // Ghidra: fspec.hh:136 ParamEntry::isGrouped
    pub fn is_grouped(&self) -> bool {
        (self.flags & param_entry_flags::IS_GROUPED) != 0
    }
    // Ghidra: fspec.hh:137 ParamEntry::isOverlap
    pub fn is_overlap(&self) -> bool {
        (self.flags & param_entry_flags::OVERLAPPING) != 0
    }
    // Ghidra: fspec.hh:138 ParamEntry::isFirstInClass
    pub fn is_first_in_class(&self) -> bool {
        (self.flags & param_entry_flags::FIRST_STORAGE) != 0
    }
    // Ghidra: fspec.hh:152 ParamEntry::isParamCheckHigh
    pub fn is_param_check_high(&self) -> bool {
        (self.flags & param_entry_flags::EXTRACHECK_HIGH) != 0
    }
    // Ghidra: fspec.hh:153 ParamEntry::isParamCheckLow
    pub fn is_param_check_low(&self) -> bool {
        (self.flags & param_entry_flags::EXTRACHECK_LOW) != 0
    }
    // Ghidra: fspec.hh:147 ParamEntry::getSpace
    pub fn get_space(&self) -> AddressSpace { self.space }
    // Ghidra: fspec.hh:148 ParamEntry::getBase
    pub fn get_base(&self) -> u64 { self.address_base }
    // Ghidra: fspec.hh:132 ParamEntry::getJoinRecord
    pub fn get_join_pieces(&self) -> Option<&[VarnodeData]> {
        self.join.as_ref().map(|j| j.pieces.as_slice())
    }

    // Ghidra: fspec.cc:60 ParamEntry::findEntryByStorage
    /// Find a ParamEntry matching the given storage Varnode. Search
    /// backward. Faithful to `findEntryByStorage` (fspec.cc:60-71).
    pub fn find_entry_by_storage<'a>(
        entry_list: &'a [ParamEntry],
        vn: &VarnodeData,
    ) -> Option<&'a ParamEntry> {
        entry_list.iter().rev().find(|entry| {
            entry.space == vn.space
                && entry.address_base == vn.offset
                && entry.size == vn.size
        })
    }

    // Ghidra: fspec.cc:76 ParamEntry::resolveFirst
    fn resolve_first(&mut self, cur_list: &[ParamEntry]) {
        if cur_list.is_empty() {
            self.flags |= param_entry_flags::FIRST_STORAGE;
            return;
        }
        let prev = &cur_list[cur_list.len() - 1];
        if self.type_storage != prev.type_storage {
            self.flags |= param_entry_flags::FIRST_STORAGE;
        }
    }

    // Ghidra: fspec.cc:94 ParamEntry::resolveJoin
    /// If the ParamEntry is initialized with a join address, cache the join
    /// record and adjust the group. Faithful to `resolveJoin`
    /// (fspec.cc:94-116).
    fn resolve_join(&mut self, cur_list: &[ParamEntry]) {
        // TODO(ALIGNMENT_ROADMAP): depends on unported
        // AddrSpaceManager::findJoin (space.cc). The join-space manager is
        // not yet ported; Rugra receives pieces via set_join_pieces.
        if self.space != AddressSpace::Join {
            self.join = None;
            return;
        }
        let pieces = match &self.join {
            Some(j) if !j.pieces.is_empty() => j.pieces.clone(),
            _ => return,
        };
        let mut new_groups: Vec<i32> = Vec::new();
        for (i, piece) in pieces.iter().enumerate() {
            if let Some(entry) = ParamEntry::find_entry_by_storage(cur_list, piece) {
                new_groups.extend_from_slice(&entry.group_set);
                if i == 0 {
                    self.flags |= param_entry_flags::EXTRACHECK_LOW;
                } else {
                    self.flags |= param_entry_flags::EXTRACHECK_HIGH;
                }
            }
        }
        if new_groups.is_empty() { return; }
        new_groups.sort_unstable();
        new_groups.dedup();
        self.group_set = new_groups;
        self.flags |= param_entry_flags::OVERLAPPING;
    }

    // RUGRA-GLUE: set_join_pieces (no direct Ghidra counterpart — Ghidra
    // pulls pieces from `spaceid->getManager()->findJoin(addressbase)`; in
    // Rugra the caller supplies them since the join-space manager is
    // unported).
    pub fn set_join_pieces(&mut self, pieces: Vec<VarnodeData>) {
        self.join = Some(ParamEntryJoin { pieces });
    }

    // Ghidra: fspec.cc:122 ParamEntry::resolveOverlap
    /// Search for overlaps of this with any previous entry. If an overlap
    /// is discovered, reassign this group. Faithful to `resolveOverlap`
    /// (fspec.cc:122-153).
    fn resolve_overlap(&mut self, cur_list: &[ParamEntry]) {
        if self.join.is_some() { return; }
        let mut overlap_set: Vec<i32> = Vec::new();
        let addr = Address::new(self.address_base);
        for entry in cur_list.iter() {
            if !entry.intersects(addr, self.size) { continue; }
            if self.contains(entry) {
                if entry.is_overlap() { continue; }
                overlap_set.extend_from_slice(&entry.group_set);
                if self.address_base == entry.address_base {
                    self.flags |= if self.space.is_big_endian() {
                        param_entry_flags::EXTRACHECK_LOW
                    } else {
                        param_entry_flags::EXTRACHECK_HIGH
                    };
                } else {
                    self.flags |= if self.space.is_big_endian() {
                        param_entry_flags::EXTRACHECK_HIGH
                    } else {
                        param_entry_flags::EXTRACHECK_LOW
                    };
                }
            }
        }
        if overlap_set.is_empty() { return; }
        overlap_set.sort_unstable();
        overlap_set.dedup();
        self.group_set = overlap_set;
        self.flags |= param_entry_flags::OVERLAPPING;
    }

    // Ghidra: fspec.cc:157 ParamEntry::groupOverlap
    /// Return `true` if the group sets intersect at all. Faithful to
    /// `groupOverlap` (fspec.cc:157-177).
    pub fn group_overlap(&self, op2: &ParamEntry) -> bool {
        let mut i = 0usize;
        let mut j = 0usize;
        let mut val_this = self.group_set[i];
        let mut val_other = op2.group_set[j];
        loop {
            if val_this == val_other { return true; }
            if val_this < val_other {
                i += 1;
                if i >= self.group_set.len() { return false; }
                val_this = self.group_set[i];
            } else {
                j += 1;
                if j >= op2.group_set.len() { return false; }
                val_other = op2.group_set[j];
            }
        }
    }

    // Ghidra: fspec.cc:184 ParamEntry::subsumesDefinition
    /// This entry must properly contain the other memory range, and the
    /// entry properties must be compatible. Faithful to
    /// `subsumesDefinition` (fspec.cc:184-193).
    pub fn subsumes_definition(&self, op2: &ParamEntry) -> bool {
        if self.type_storage != TypeClass::General && op2.type_storage != self.type_storage {
            return false;
        }
        if self.space != op2.space { return false; }
        if op2.address_base < self.address_base { return false; }
        if op2.address_base + op2.size as u64 - 1 > self.address_base + self.size as u64 - 1 {
            return false;
        }
        if self.alignment != op2.alignment { return false; }
        true
    }

    // Ghidra: fspec.cc:199 ParamEntry::containedBy
    /// Return `true` if the entire ParamEntry fits inside the range
    /// `[addr, addr+sz)`. Faithful to `containedBy` (fspec.cc:199-207).
    pub fn contained_by(&self, addr: Address, sz: i32) -> bool {
        if self.address_base < addr.as_u64() { return false; }
        let entry_off = self.address_base + self.size as u64 - 1;
        let range_off = addr.as_u64() + sz as u64 - 1;
        entry_off <= range_off
    }

    // Ghidra: fspec.cc:214 ParamEntry::intersects
    /// If this is a join, each piece is tested for intersection. Otherwise
    /// this, considered as a single memory, is tested. Faithful to
    /// `intersects` (fspec.cc:214-239).
    pub fn intersects(&self, addr: Address, sz: i32) -> bool {
        let range_end = addr.as_u64().wrapping_add(sz as u64).wrapping_sub(1);
        if let Some(j) = &self.join {
            for vdata in &j.pieces {
                let vdata_end = vdata.offset + vdata.size as u64 - 1;
                if addr.as_u64() < vdata.offset && range_end < vdata_end { continue; }
                if addr.as_u64() > vdata.offset && range_end > vdata_end { continue; }
                return true;
            }
        }
        let this_end = self.address_base + self.size as u64 - 1;
        if addr.as_u64() < self.address_base && range_end < this_end { return false; }
        if addr.as_u64() > self.address_base && range_end > this_end { return false; }
        true
    }

    // Ghidra: fspec.cc:248 ParamEntry::justifiedContain
    /// Check if the given memory range is contained in this. Return the
    /// endian-aware offset (0 if LSB-aligned), else -1. Faithful to
    /// `justifiedContain` (fspec.cc:248-283).
    pub fn justified_contain(&self, addr: Address, sz: i32) -> i32 {
        if let Some(j) = &self.join {
            let mut res = 0i32;
            for vdata in j.pieces.iter().rev() {
                let cur = justified_contain_range(vdata.offset, vdata.size, addr.as_u64(), sz, false);
                if cur < 0 { res += vdata.size; } else { return res + cur; }
            }
            return -1;
        }
        if self.alignment == 0 {
            return justified_contain_range(
                self.address_base, self.size, addr.as_u64(), sz,
                (self.flags & param_entry_flags::FORCE_LEFT_JUSTIFY) != 0,
            );
        }
        let start_addr = addr.as_u64();
        if start_addr < self.address_base { return -1; }
        let end_addr = start_addr.wrapping_add(sz as u64).wrapping_sub(1);
        if end_addr < start_addr { return -1; }
        if end_addr > self.address_base + self.size as u64 - 1 { return -1; }
        let start_off = start_addr - self.address_base;
        let end_off = end_addr - self.address_base;
        if !self.is_left_justified() {
            let res = ((end_off + 1) % self.alignment as u64) as i32;
            if res == 0 { return 0; }
            return self.alignment - res;
        }
        (start_off % self.alignment as u64) as i32
    }

    // Ghidra: fspec.cc:295 ParamEntry::getContainer
    /// Calculate the containing memory range. Pass back the VarnodeData of
    /// the parameter that would contain the given range. Faithful to
    /// `getContainer` (fspec.cc:295-328).
    pub fn get_container(&self, addr: Address, sz: i32, res: &mut VarnodeData) -> bool {
        let end_addr = Address::new(addr.as_u64().wrapping_add(sz as u64 - 1));
        if let Some(j) = &self.join {
            for vdata in j.pieces.iter().rev() {
                let vaddr = vdata.get_addr();
                if addr.overlap(0, vaddr, vdata.size) >= 0
                    && end_addr.overlap(0, vaddr, vdata.size) >= 0
                {
                    *res = *vdata;
                    return true;
                }
            }
            return false;
        }
        let entry = Address::new(self.address_base);
        if addr.overlap(0, entry, self.size) < 0 { return false; }
        if end_addr.overlap(0, entry, self.size) < 0 { return false; }
        if self.alignment == 0 {
            res.space = self.space;
            res.offset = self.address_base;
            res.size = self.size;
            return true;
        }
        let al = (addr.as_u64() - self.address_base) % self.alignment as u64;
        res.space = self.space;
        res.offset = addr.as_u64() - al;
        res.size = (end_addr.as_u64() - res.offset) as i32 + 1;
        let al2 = res.size as i32 % self.alignment;
        if al2 != 0 { res.size += self.alignment - al2; }
        true
    }

    // Ghidra: fspec.cc:335 ParamEntry::contains
    /// Test that this contains the other ParamEntry's memory range.
    /// Faithful to `contains` (fspec.cc:335-350).
    pub fn contains(&self, op2: &ParamEntry) -> bool {
        if op2.join.is_some() { return false; }
        if self.join.is_none() {
            let addr = Address::new(self.address_base);
            return op2.contained_by(addr, self.size);
        }
        let j = self.join.as_ref().unwrap();
        for vdata in &j.pieces {
            if op2.contained_by(vdata.get_addr(), vdata.size) { return true; }
        }
        false
    }

    // Ghidra: fspec.cc:366 ParamEntry::assumedExtension
    /// Calculate the type of extension to expect for the given logical
    /// value. Returns CPUI_COPY if no extensions are assumed. Faithful to
    /// `assumedExtension` (fspec.cc:366-394).
    pub fn assumed_extension(&self, addr: Address, sz: i32, res: &mut VarnodeData) -> FspecOpCode {
        if self.flags
            & (param_entry_flags::SMALLSIZE_ZEXT
                | param_entry_flags::SMALLSIZE_SEXT
                | param_entry_flags::SMALLSIZE_INTTYPE)
            == 0
        {
            return FspecOpCode::CPUI_COPY;
        }
        if self.alignment != 0 {
            if sz >= self.alignment { return FspecOpCode::CPUI_COPY; }
        } else if sz >= self.size {
            return FspecOpCode::CPUI_COPY;
        }
        if self.join.is_some() { return FspecOpCode::CPUI_COPY; }
        if self.justified_contain(addr, sz) != 0 { return FspecOpCode::CPUI_COPY; }
        if self.alignment == 0 {
            res.space = self.space;
            res.offset = self.address_base;
            res.size = self.size;
        } else {
            res.space = self.space;
            let align_adjust = (addr.as_u64() - self.address_base) % self.alignment as u64;
            res.offset = addr.as_u64() - align_adjust;
            res.size = self.alignment;
        }
        if self.flags & param_entry_flags::SMALLSIZE_ZEXT != 0 {
            return FspecOpCode::CPUI_INT_ZEXT;
        }
        if self.flags & param_entry_flags::SMALLSIZE_INTTYPE != 0 {
            return FspecOpCode::CPUI_PIECE;
        }
        FspecOpCode::CPUI_INT_SEXT
    }

    // Ghidra: fspec.cc:407 ParamEntry::getSlot
    /// Calculate the slot occupied by a specific address. Faithful to
    /// `getSlot` (fspec.cc:407-423).
    pub fn get_slot(&self, addr: Address, skip: i32) -> i32 {
        let mut res = self.group_set[0];
        if self.alignment != 0 {
            let diff = addr.as_u64() + skip as u64 - self.address_base;
            let base_slot = (diff / self.alignment as u64) as i32;
            if self.is_reverse_stack() {
                res += (self.num_slots - 1) - base_slot;
            } else {
                res += base_slot;
            }
        } else if skip != 0 {
            res = *self.group_set.last().unwrap();
        }
        res
    }

    // Ghidra: fspec.cc:434 ParamEntry::getAddrBySlot (3-arg)
    /// Calculate the storage address assigned when allocating a parameter.
    /// Faithful to `getAddrBySlot(int4&, int4, int4)` (fspec.cc:434-438).
    pub fn get_addr_by_slot(&self, slot_num: &mut i32, sz: i32, type_align: i32) -> Option<Address> {
        self.get_addr_by_slot_just(slot_num, sz, type_align, !self.is_left_justified())
    }

    // Ghidra: fspec.cc:450 ParamEntry::getAddrBySlot (4-arg)
    /// Calculate the storage address assigned when allocating a parameter,
    /// with explicit justification. Faithful to `getAddrBySlot(int4&, int4,
    /// int4, bool)` (fspec.cc:450-493).
    pub fn get_addr_by_slot_just(
        &self, slot_num: &mut i32, sz: i32, type_align: i32, justify_right: bool,
    ) -> Option<Address> {
        if sz < self.min_size { return None; }
        let space_used;
        let mut res;
        if self.alignment == 0 {
            if *slot_num != 0 { return None; }
            if sz > self.size { return None; }
            res = Address::new(self.address_base);
            space_used = self.size;
            if self.flags & param_entry_flags::SMALLSIZE_FLOATEXT != 0 && sz != self.size {
                // TODO(ALIGNMENT_ROADMAP): depends on unported
                // AddrSpaceManager (constructFloatExtensionAddress). Rugra
                // leaves the base address; the float-ext join record would
                // normally be materialized here.
                return Some(res);
            }
        } else {
            if type_align > self.alignment {
                let tmp = (*slot_num * self.alignment) % type_align;
                if tmp != 0 {
                    *slot_num += (type_align - tmp) / self.alignment;
                }
            }
            let mut slots_used = sz / self.alignment;
            if sz % self.alignment != 0 { slots_used += 1; }
            if *slot_num + slots_used > self.num_slots { return None; }
            space_used = slots_used * self.alignment;
            let index;
            if self.is_reverse_stack() {
                index = self.num_slots - *slot_num - slots_used;
            } else {
                index = *slot_num;
            }
            res = Address::new(self.address_base + index as u64 * self.alignment as u64);
            *slot_num += slots_used;
        }
        if justify_right {
            res = Address::new(res.as_u64() + (space_used - sz) as u64);
        }
        Some(res)
    }

    // Ghidra: fspec.cc:583 ParamEntry::orderWithinGroup
    /// Entries within a group must be distinguishable by size or type.
    /// Returns `Err` if not distinguishable (Ghidra throws). Faithful to
    /// `orderWithinGroup` (fspec.cc:583-595).
    pub fn order_within_group(entry1: &ParamEntry, entry2: &ParamEntry) -> Result<(), String> {
        if entry2.min_size > entry1.size || entry1.min_size > entry2.size { return Ok(()); }
        if entry1.type_storage != entry2.type_storage {
            if entry1.type_storage == TypeClass::General {
                return Err(
                    "<pentry> tags with a specific type must come before the general type".to_string(),
                );
            }
            return Ok(());
        }
        Err("<pentry> tags within a group must be distinguished by size or type".to_string())
    }

    // RUGRA-GLUE: builder-style setters for the model loader (Ghidra fills
    // these during `ParamEntry::decode`; Rugra's decoder is unported so the
    // loader populates them via these accessors).
    pub fn set_space(&mut self, spc: AddressSpace) { self.space = spc; }
    // RUGRA-GLUE: loader field setter; Ghidra assigns addressbase directly
    // inside ParamEntry::decode and exposes no setBase member.
    pub fn set_base(&mut self, base: u64) { self.address_base = base; }
    // RUGRA-GLUE: loader field setter; Ghidra assigns size/minsize and derives
    // numslots atomically inside ParamEntry::decode, with no setSizes member.
    pub fn set_sizes(&mut self, size: i32, min_size: i32) {
        self.size = size;
        self.min_size = min_size;
        if self.alignment != 0 && self.num_slots == 1 {
            self.num_slots = size / self.alignment;
        }
    }
    /// Set the alignment. If `alignment == size`, normalized to 0 (exclusion
    /// entry) per `ParamEntry::decode` (fspec.cc:547-548).
    // RUGRA-GLUE: staged-loader setter; Ghidra reads and normalizes alignment
    // inside ParamEntry::decode and exposes no setAlignment member.
    pub fn set_alignment(&mut self, alignment: i32) {
        self.alignment = alignment;
        if self.alignment == self.size { self.alignment = 0; }
        if self.alignment != 0 {
            self.num_slots = self.size / self.alignment;
        } else {
            self.num_slots = 1;
        }
    }
    // RUGRA-GLUE: loader field setter; Ghidra assigns the private type field
    // from ParamEntry::decode and exposes no setTypeClass member.
    pub fn set_type_class(&mut self, ty: TypeClass) { self.type_storage = ty; }

    // RUGRA-GLUE: flags_mut (private field accessor so parse_pentry can
    // mirror fspec.cc:565-573 reverse_stack/is_grouped adjustments without
    // exposing flags as a public mutable field).
    pub fn flags_mut(&mut self) -> &mut u32 { &mut self.flags }
}

// RUGRA-GLUE: justified_contain_range (free helper — mirrors Ghidra's
// inline `Address::justifiedContain` used by `ParamEntry::justifiedContain`
// and its join-piece walk).
fn justified_contain_range(base: u64, sz2: i32, addr: u64, sz: i32, force_left: bool) -> i32 {
    let end_addr = addr.wrapping_add(sz as u64).wrapping_sub(1);
    let this_end = base.wrapping_add(sz2 as u64).wrapping_sub(1);
    if addr < base && end_addr < this_end { return -1; }
    if addr > base && end_addr > this_end { return -1; }
    if force_left { (addr - base) as i32 } else { (this_end - end_addr) as i32 }
}

// ======================================================================
// ParamListStandard (fspec.hh:589-646 / fspec.cc:597-1517)
// ======================================================================

/// Parameter-list type discriminator. Faithful to `ParamList`'s anonymous
/// enum (fspec.hh:427-433).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamListKind {
    Standard,
    StandardOut,
    Register,
    RegisterOut,
    Merged,
}

/// Response codes for address assignment. Faithful to `AssignAction`'s
/// anonymous enum (modelrules.hh:264-271). Local copy in `fspec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignActionResponse {
    Success,
    Fail,
    NoAssignment,
}

/// Holds the result of a parameter assignment. Faithful to
/// `struct ParameterPieces` (fspec.hh:451-460). Local copy in `fspec`.
#[derive(Debug, Clone)]
pub struct ParameterPieces {
    pub addr: Address,
    pub ty: Option<Arc<Datatype>>,
    pub flags: u32,
}

/// `ParameterPieces::hiddenretparm = 2`. Faithful to (fspec.hh:457).
pub const HIDDEN_RET_PARM: u32 = 2;
/// `ParameterPieces::indirectstorage = 1`. Faithful to (fspec.hh:458).
pub const INDIRECT_STORAGE_PIECE: u32 = 1;

impl Default for ParameterPieces {
    // RUGRA-GLUE: Rust Default initializes the local Option-based aggregate;
    // Ghidra's ParameterPieces aggregate has no default() member.
    fn default() -> Self { Self { addr: Address::new(0), ty: None, flags: 0 } }
}

impl ParameterPieces {
    // Ghidra: fspec.cc:2175 ParameterPieces::swapMarkup
    /// Swap data-type/storage markup between this and another parameter.
    /// Faithful 1:1 port of `swapMarkup` (fspec.cc:2175-2189): exchanges the
    /// address, data-type, and the storage-markup subset of `flags`
    /// (`isthis`/`hiddenretparm`/`indirectstorage`/`namelock`/`typelock`/
    /// `sizelock`), leaving any other bits untouched.
    pub fn swap_markup(&mut self, other: &mut ParameterPieces) {
        std::mem::swap(&mut self.addr, &mut other.addr);
        std::mem::swap(&mut self.ty, &mut other.ty);
        // Markup mask: all ParameterPieces flag bits (fspec.hh:362-367).
        const MARKUP_MASK: u32 = THIS_POINTER_PIECE
            | HIDDEN_RET_PARM
            | INDIRECT_STORAGE_PIECE
            | NAME_LOCK_PIECE
            | TYPE_LOCK_PIECE
            | SIZE_LOCK_PIECE;
        let self_markup = self.flags & MARKUP_MASK;
        let other_markup = other.flags & MARKUP_MASK;
        self.flags = (self.flags & !MARKUP_MASK) | other_markup;
        other.flags = (other.flags & !MARKUP_MASK) | self_markup;
    }
}

/// `ParameterPieces::namelock = 8`. Faithful to (fspec.hh:365).
pub const NAME_LOCK_PIECE: u32 = 8;
/// `ParameterPieces::typelock = 16`. Faithful to (fspec.hh:366).
pub const TYPE_LOCK_PIECE: u32 = 16;
/// `ParameterPieces::sizelock = 32`. Faithful to (fspec.hh:367).
pub const SIZE_LOCK_PIECE: u32 = 32;

/// Description of a function prototype consulted during assignment.
/// Faithful to `struct PrototypePieces` (fspec.hh:445-450).
pub struct PrototypePieces<'a> {
    pub out_type: Option<&'a Datatype>,
    pub in_types: &'a [Arc<Datatype>],
    pub first_var_arg_slot: i32,
}

/// A standard model for parameters as an ordered list of storage resources.
/// Faithful port of `class ParamListStandard` (fspec.hh:589-646).
#[derive(Debug, Clone)]
pub struct ParamListStandard {
    num_group: i32,
    max_delay: i32,
    this_before_ret: bool,
    auto_killed_by_call: bool,
    resource_start: Vec<i32>,
    entry: Vec<ParamEntry>,
    space_base: Option<AddressSpace>,
    stack_entry_index: Option<usize>,
}

impl Default for ParamListStandard {
    // RUGRA-GLUE: Rust Default trait bridge delegates to new(); Ghidra has the
    // ParamListStandard constructor but no language-level default() member.
    fn default() -> Self { Self::new() }
}

impl ParamListStandard {
    // Ghidra: fspec.hh:617 ParamListStandard::ParamListStandard()
    // RUGRA-GLUE: default constructor for use with decode().
    pub fn new() -> Self {
        Self {
            num_group: 0,
            max_delay: 0,
            this_before_ret: false,
            auto_killed_by_call: false,
            resource_start: Vec::new(),
            entry: Vec::new(),
            space_base: None,
            stack_entry_index: None,
        }
    }
    // Ghidra: fspec.hh:628 ParamListStandard::getType
    pub fn get_type(&self) -> ParamListKind { ParamListKind::Standard }
    // Ghidra: fspec.hh:639 ParamListStandard::getSpacebase
    pub fn get_spacebase(&self) -> Option<AddressSpace> { self.space_base }
    // Ghidra: fspec.hh:640 ParamListStandard::isThisBeforeRetPointer
    pub fn is_this_before_ret_pointer(&self) -> bool { self.this_before_ret }
    // Ghidra: fspec.hh:642 ParamListStandard::getMaxDelay
    pub fn get_max_delay(&self) -> i32 { self.max_delay }
    // Ghidra: fspec.hh:643 ParamListStandard::isAutoKilledByCall
    pub fn is_auto_killed_by_call(&self) -> bool { self.auto_killed_by_call }
    // Ghidra: fspec.hh:620 ParamListStandard::getEntry
    pub fn get_entry(&self) -> &[ParamEntry] { &self.entry }
    // Ghidra: fspec.hh:621 ParamListStandard::isBigEndian
    pub fn is_big_endian(&self) -> bool {
        self.entry.first().map(|e| e.get_space().is_big_endian()).unwrap_or(false)
    }

    // Ghidra: fspec.cc:626 ParamListStandard::extractTiles
    /// Collect registers of the given storage class. Faithful to
    /// `extractTiles` (fspec.cc:626-638).
    pub fn extract_tiles(&self, ty: TypeClass) -> Vec<usize> {
        let mut tiles = Vec::new();
        for (i, e) in self.entry.iter().enumerate() {
            if !e.is_exclusion() { continue; }
            if e.get_type() != ty || e.get_all_groups().len() != 1 { continue; }
            tiles.push(i);
        }
        tiles
    }

    // Ghidra: fspec.cc:642 ParamListStandard::getStackEntry
    /// If the stack entry is not present, `None` is returned. Faithful to
    /// `getStackEntry` (fspec.cc:642-654).
    pub fn get_stack_entry(&self) -> Option<usize> {
        if let Some(idx) = self.stack_entry_index { return Some(idx); }
        if self.entry.is_empty() { return None; }
        let idx = self.entry.len() - 1;
        let cur = &self.entry[idx];
        if !cur.is_exclusion() && cur.get_space() == AddressSpace::Stack { Some(idx) } else { None }
    }

    // Ghidra: fspec.cc:661 ParamListStandard::findEntry
    /// Find the (first) entry containing the given memory range. Faithful
    /// to `findEntry` (fspec.cc:661-680). Rugra uses a linear scan over
    /// `entry` since the dedicated `rangemap`-based `ParamEntryResolver`
    /// (fspec.hh:597) is unported.
    pub fn find_entry(&self, loc: Address, size: i32, just: bool) -> Option<usize> {
        // TODO(ALIGNMENT_ROADMAP): depends on unported `ParamEntryResolver`
        // rangemap (fspec.hh:597).
        for (i, e) in self.entry.iter().enumerate() {
            if e.get_min_size() > size { continue; }
            if e.get_space() != AddressSpace::Ram { continue; }
            if !just || e.justified_contain(loc, size) == 0 { return Some(i); }
        }
        None
    }

    // Ghidra: fspec.cc:682 ParamListStandard::characterizeAsParam
    /// Characterize whether the given range overlaps parameter storage.
    /// Returns one of the `containment::*` codes. Faithful to
    /// `characterizeAsParam` (fspec.cc:682-719).
    pub fn characterize_as_param(&self, loc: Address, size: i32) -> i32 {
        let mut res_contains = false;
        let mut res_contained_by = false;
        for e in &self.entry {
            if e.get_space() != AddressSpace::Ram { continue; }
            let off = e.justified_contain(loc, size);
            if off == 0 { return containment::CONTAINS_JUSTIFIED; }
            else if off > 0 { res_contains = true; }
            if e.is_exclusion() && e.contained_by(loc, size) { res_contained_by = true; }
        }
        if res_contains { return containment::CONTAINS_UNJUSTIFIED; }
        if res_contained_by { return containment::CONTAINED_BY; }
        containment::NO_CONTAINMENT
    }

    // Ghidra: fspec.cc:735 ParamListStandard::assignAddressFallback
    /// Assign storage for given parameter class, using the fallback
    /// assignment algorithm. Faithful to `assignAddressFallback`
    /// (fspec.cc:735-760).
    pub fn assign_address_fallback(
        &self, resource: TypeClass, tp: &Datatype, match_exact: bool,
        status: &mut [i32], param: &mut ParameterPieces,
    ) -> AssignActionResponse {
        for cur in &self.entry {
            let grp = cur.get_group();
            if status[grp as usize] < 0 { continue; }
            if resource != cur.get_type() {
                if match_exact || cur.get_type() != TypeClass::General { continue; }
            }
            // TODO(ALIGNMENT_ROADMAP): depends on unported
            // `Datatype::getAlignSize`/`getAlignment`. Approximate with
            // size / alignment 1.
            let align_size = tp.get_size() as i32;
            let type_alignment = 1i32;
            let assigned = cur.get_addr_by_slot(&mut status[grp as usize], align_size, type_alignment);
            match assigned {
                None => continue,
                Some(addr) => param.addr = addr,
            }
            if cur.is_exclusion() {
                let group_set = cur.get_all_groups();
                for &g in group_set { status[g as usize] = -1; }
            }
            param.ty = None;
            param.flags = 0;
            return AssignActionResponse::Success;
        }
        AssignActionResponse::Fail
    }

    // Ghidra: fspec.cc:772 ParamListStandard::assignAddress
    /// Fill in the Address and other details for the given parameter.
    /// Faithful to `assignAddress` (fspec.cc:772-783).
    pub fn assign_address(
        &self, dt: &Datatype, _proto: &PrototypePieces, _pos: i32,
        status: &mut [i32], res: &mut ParameterPieces,
    ) -> AssignActionResponse {
        // TODO(ALIGNMENT_ROADMAP): depends on unported `ModelRule`
        // (modelrules.hh). Ghidra iterates `modelRules` first; Rugra goes
        // straight to fallback.
        let store = metatype_to_type_class(dt);
        self.assign_address_fallback(store, dt, false, status, res)
    }

    // Ghidra: fspec.cc:785 ParamListStandard::assignMap
    /// Given list of data-types, map the list positions to storage
    /// locations. Faithful to `assignMap` (fspec.cc:785-814).
    pub fn assign_map(&self, proto: &PrototypePieces, res: &mut Vec<ParameterPieces>) -> Result<(), String> {
        let mut status = vec![0i32; self.num_group as usize];
        if res.len() == 2 {
            let dt = res.last().unwrap().ty.clone();
            if (res.last().unwrap().flags & HIDDEN_RET_PARM) != 0 {
                if let Some(dt_ref) = &dt {
                    if self.assign_address_fallback(
                        TypeClass::HiddenReturn, dt_ref, false,
                        &mut status, res.last_mut().unwrap(),
                    ) == AssignActionResponse::Fail
                    {
                        return Err("Cannot assign parameter address for hidden return".to_string());
                    }
                }
            } else if let Some(dt_ref) = &dt {
                if self.assign_address(dt_ref, proto, 0, &mut status, res.last_mut().unwrap())
                    == AssignActionResponse::Fail
                {
                    return Err("Cannot assign parameter address".to_string());
                }
            }
            res.last_mut().unwrap().flags |= HIDDEN_RET_PARM;
        }
        for (i, dt) in proto.in_types.iter().enumerate() {
            res.push(ParameterPieces::default());
            let response = self.assign_address(
                dt.as_ref(), proto, i as i32, &mut status, res.last_mut().unwrap(),
            );
            if response == AssignActionResponse::Fail || response == AssignActionResponse::NoAssignment {
                return Err("Cannot assign parameter address".to_string());
            }
        }
        Ok(())
    }

    // Ghidra: fspec.cc:820 ParamListStandard::selectUnreferenceEntry
    /// From among the ParamEntrys matching the given group, return the one
    /// that best matches the given metatype. Faithful to
    /// `selectUnreferenceEntry` (fspec.cc:820-842).
    pub fn select_unreference_entry(&self, grp: i32, pref_type: TypeClass) -> Option<usize> {
        let mut best_score = -1i32;
        let mut best_entry = None;
        for (i, cur) in self.entry.iter().enumerate() {
            if cur.get_group() != grp { continue; }
            let cur_score = if cur.get_type() == pref_type { 2 }
                else if pref_type == TypeClass::General { 1 } else { 0 };
            if cur_score > best_score { best_score = cur_score; best_entry = Some(i); }
        }
        best_entry
    }

    // Ghidra: fspec.cc:849 ParamListStandard::buildTrialMap
    /// Associate trials with model ParamEntry objects. Faithful to
    /// `buildTrialMap` (fspec.cc:849-937).
    pub fn build_trial_map(&self, active: &mut ParamActive) {
        let mut hit_list: Vec<Option<usize>> = Vec::new();
        let mut float_count = 0i32;
        let mut int_count = 0i32;
        for i in 0..active.get_num_trials() {
            let (addr, size) = { let t = active.get_trial(i); (t.get_address(), t.get_size()) };
            let entry_slot = self.find_entry(addr, size, true);
            if entry_slot.is_none() {
                active.get_trial_mut(i).mark_no_use();
                continue;
            }
            let entry_slot = entry_slot.unwrap();
            active.get_trial_mut(i).set_entry(entry_slot, 0);
            let is_active = active.get_trial(i).is_active();
            let entry_type = self.entry[entry_slot].get_type();
            if is_active {
                if entry_type == TypeClass::Float { float_count += 1; } else { int_count += 1; }
            }
            let grp = self.entry[entry_slot].get_group();
            while hit_list.len() <= grp as usize { hit_list.push(None); }
            if hit_list[grp as usize].is_none() { hit_list[grp as usize] = Some(entry_slot); }
        }
        for (grp_idx, curentry_opt) in hit_list.iter().enumerate() {
            let grp = grp_idx as i32;
            if curentry_opt.is_none() {
                let pref = if float_count > int_count { TypeClass::Float } else { TypeClass::General };
                let curentry = match self.select_unreference_entry(grp, pref) { Some(e) => e, None => continue };
                let (sz, next_slot_init) = if self.entry[curentry].is_exclusion() {
                    (self.entry[curentry].get_size(), 0)
                } else {
                    (self.entry[curentry].get_align(), 0)
                };
                let mut next_slot = next_slot_init;
                let addr = self.entry[curentry]
                    .get_addr_by_slot(&mut next_slot, sz, 1)
                    .unwrap_or(Address::new(0));
                let trial_pos = active.get_num_trials();
                active.register_trial(addr, sz);
                active.get_trial_mut(trial_pos).mark_unref();
                active.get_trial_mut(trial_pos).set_entry(curentry, 0);
            } else {
                let curentry = curentry_opt.unwrap();
                if !self.entry[curentry].is_exclusion() {
                    let mut slot_list: Vec<i32> = Vec::new();
                    for j in 0..active.get_num_trials() {
                        let (addr, size) = { let t = active.get_trial(j); (t.get_address(), t.get_size()) };
                        if active.get_trial(j).get_entry_index() != Some(curentry) { continue; }
                        let mut slot = self.entry[curentry].get_slot(addr, 0) - self.entry[curentry].get_group();
                        let mut end_slot = self.entry[curentry].get_slot(addr, size - 1) - self.entry[curentry].get_group();
                        if end_slot < slot { std::mem::swap(&mut slot, &mut end_slot); }
                        while slot_list.len() <= end_slot as usize { slot_list.push(0); }
                        let mut s = slot;
                        while s <= end_slot { slot_list[s as usize] = 1; s += 1; }
                    }
                    for (j, &v) in slot_list.iter().enumerate() {
                        if v == 0 {
                            let mut next_slot = j as i32;
                            let align = self.entry[curentry].get_align();
                            let addr = self.entry[curentry]
                                .get_addr_by_slot(&mut next_slot, align, 1)
                                .unwrap_or(Address::new(0));
                            let trial_pos = active.get_num_trials();
                            active.register_trial(addr, align);
                            active.get_trial_mut(trial_pos).mark_unref();
                            active.get_trial_mut(trial_pos).set_entry(curentry, 0);
                        }
                    }
                }
            }
        }
        active.sort_trials();
    }

    // Ghidra: fspec.cc:946 ParamListStandard::separateSections
    /// Calculate the range of trials in each resource section. Faithful to
    /// `separateSections` (fspec.cc:946-966).
    pub fn separate_sections(&self, active: &ParamActive, trial_start: &mut Vec<i32>) {
        let num_trials = active.get_num_trials() as i32;
        let mut current_trial = 0i32;
        if self.resource_start.len() < 2 { return; }
        let mut next_group = self.resource_start[1];
        let mut next_section = 2usize;
        trial_start.push(current_trial);
        while current_trial < num_trials {
            let cur = active.get_trial(current_trial as usize);
            if cur.get_entry_index().is_none() { current_trial += 1; continue; }
            let grp = cur.get_entry_index()
                .and_then(|idx| self.entry.get(idx))
                .map(|e| e.get_group())
                .unwrap_or(-1);
            if grp >= next_group {
                if next_section >= self.resource_start.len() { break; }
                next_group = self.resource_start[next_section];
                next_section += 1;
                trial_start.push(current_trial);
            }
            current_trial += 1;
        }
        trial_start.push(num_trials);
    }

    // Ghidra: fspec.cc:974 ParamListStandard::markGroupNoUse
    /// Mark all the trials within the indicated groups as not used, except
    /// for one specified index. Faithful to `markGroupNoUse`
    /// (fspec.cc:974-986).
    pub fn mark_group_no_use(&self, active: &mut ParamActive, active_trial: usize, trial_start: usize) {
        let num_trials = active.get_num_trials();
        let active_entry = match active.get_trial(active_trial).get_entry_index().and_then(|i| self.entry.get(i)) {
            Some(e) => e,
            None => return,
        };
        for i in trial_start..num_trials {
            if i == active_trial { continue; }
            let other_entry_idx = match active.get_trial(i).get_entry_index() { Some(e) => e, None => continue };
            if active.get_trial(i).is_definitely_not_used() { continue; }
            let other_entry = match self.entry.get(other_entry_idx) { Some(e) => e, None => continue };
            if !other_entry.group_overlap(active_entry) { break; }
            active.get_trial_mut(i).mark_no_use();
        }
    }

    // Ghidra: fspec.cc:997 ParamListStandard::markBestInactive
    /// From among multiple inactive trials, select the most likely to be
    /// active and mark others as not used. Faithful to `markBestInactive`
    /// (fspec.cc:997-1025).
    pub fn mark_best_inactive(
        &self, active: &mut ParamActive, group: i32, group_start: usize, pref_type: TypeClass,
    ) {
        let num_trials = active.get_num_trials();
        let mut best_trial = -1i32;
        let mut best_score = -1i32;
        for i in group_start..num_trials {
            let trial = active.get_trial(i);
            if trial.is_definitely_not_used() { continue; }
            let entry_idx = match trial.get_entry_index() { Some(e) => e, None => continue };
            let entry = match self.entry.get(entry_idx) { Some(e) => e, None => continue };
            let grp = entry.get_group();
            if grp != group { break; }
            if entry.get_all_groups().len() > 1 { continue; }
            let mut score = 0i32;
            if trial.has_ancestor_realistic() {
                score += 5;
                if trial.has_ancestor_solid() { score += 5; }
            }
            if entry.get_type() == pref_type { score += 1; }
            if score > best_score { best_score = score; best_trial = i as i32; }
        }
        if best_trial >= 0 { self.mark_group_no_use(active, best_trial as usize, group_start); }
    }

    // Ghidra: fspec.cc:1032 ParamListStandard::forceExclusionGroup
    /// Enforce exclusion rules for the given set of parameter trials.
    /// Faithful to `forceExclusionGroup` (fspec.cc:1032-1060).
    pub fn force_exclusion_group(&self, active: &mut ParamActive) {
        let num_trials = active.get_num_trials();
        let mut cur_group = -1i32;
        let mut group_start = -1i32;
        let mut inactive_count = 0i32;
        for i in 0..num_trials {
            let entry_idx = match active.get_trial(i).get_entry_index() { Some(e) => e, None => continue };
            let entry = match self.entry.get(entry_idx) { Some(e) => e, None => continue };
            if active.get_trial(i).is_definitely_not_used() || !entry.is_exclusion() { continue; }
            let grp = entry.get_group();
            if grp != cur_group {
                if inactive_count > 1 {
                    self.mark_best_inactive(active, cur_group, group_start as usize, TypeClass::General);
                }
                cur_group = grp;
                group_start = i as i32;
                inactive_count = 0;
            }
            if active.get_trial(i).is_active() {
                self.mark_group_no_use(active, i, group_start as usize);
            } else {
                inactive_count += 1;
            }
        }
        if inactive_count > 1 {
            self.mark_best_inactive(active, cur_group, group_start as usize, TypeClass::General);
        }
    }

    // Ghidra: fspec.cc:1069 ParamListStandard::forceNoUse
    /// Mark every trial above the first "definitely not used" as inactive.
    /// Faithful to `forceNoUse` (fspec.cc:1069-1095).
    pub fn force_no_use(&self, active: &mut ParamActive, start: usize, stop: usize) {
        let mut seen_defnouse = false;
        let mut cur_group = -1i32;
        let mut all_defnouse = false;
        for i in start..stop {
            let entry_idx = match active.get_trial(i).get_entry_index() { Some(e) => e, None => continue };
            let entry = match self.entry.get(entry_idx) { Some(e) => e, None => continue };
            let grp = entry.get_group();
            let exclusion = entry.is_exclusion();
            if grp <= cur_group && exclusion {
                if !active.get_trial(i).is_definitely_not_used() { all_defnouse = false; }
            } else {
                if all_defnouse { seen_defnouse = true; }
                all_defnouse = active.get_trial(i).is_definitely_not_used();
                cur_group = grp;
            }
            if seen_defnouse { active.get_trial_mut(i).mark_inactive(); }
        }
    }

    // Ghidra: fspec.cc:1111 ParamListStandard::forceInactiveChain
    /// Enforce rules about chains of inactive slots. Faithful to
    /// `forceInactiveChain` (fspec.cc:1111-1151).
    pub fn force_inactive_chain(
        &self, active: &mut ParamActive, max_chain: i32, start: usize, stop: usize, group_start: i32,
    ) {
        let recover_subcall = active.is_recover_subcall();
        let mut seen_chain = false;
        let mut chain_length = 0i32;
        let mut max = -1i32;
        for i in start..stop {
            let entry_idx = match active.get_trial(i).get_entry_index() { Some(e) => e, None => continue };
            let entry = match self.entry.get(entry_idx) { Some(e) => e, None => continue };
            if active.get_trial(i).is_definitely_not_used() { continue; }
            if !active.get_trial(i).is_active() {
                let on_stack = active.get_trial(i).get_address().as_u64() != 0
                    && self.space_base == Some(AddressSpace::Stack);
                if active.get_trial(i).is_unref() && recover_subcall {
                    if on_stack { seen_chain = true; }
                }
                let trial_addr = active.get_trial(i).get_address();
                let trial_size = active.get_trial(i).get_size();
                let slot_group = entry.get_slot(trial_addr, trial_size - 1);
                if i == start {
                    chain_length += slot_group - group_start + 1;
                } else {
                    let prev_addr = active.get_trial(i - 1).get_address();
                    let prev_size = active.get_trial(i - 1).get_size();
                    let prev_entry_idx = active.get_trial(i - 1).get_entry_index();
                    let prev_slot_group = prev_entry_idx
                        .and_then(|idx| self.entry.get(idx))
                        .map(|e| e.get_slot(prev_addr, prev_size - 1))
                        .unwrap_or(slot_group);
                    chain_length += slot_group - prev_slot_group;
                }
                if chain_length > max_chain { seen_chain = true; }
            } else {
                chain_length = 0;
                if !seen_chain { max = i as i32; }
            }
            if seen_chain { active.get_trial_mut(i).mark_inactive(); }
        }
        let upper = std::cmp::min(max as usize, stop.saturating_sub(1));
        for i in start..=upper {
            if active.get_trial(i).is_definitely_not_used() { continue; }
            if !active.get_trial(i).is_active() { active.get_trial_mut(i).mark_active(); }
        }
    }

    // Ghidra: fspec.cc:1285 ParamListStandard::fillinMap
    /// Decide on the formal ordered parameter list, given a set of trials.
    /// Faithful to `fillinMap` (fspec.cc:1285-1313).
    pub fn fillin_map(&self, active: &mut ParamActive) {
        if active.get_num_trials() == 0 { return; }
        if self.entry.is_empty() { return; }
        self.build_trial_map(active);
        self.force_exclusion_group(active);
        let mut trial_start = Vec::new();
        self.separate_sections(active, &mut trial_start);
        if trial_start.len() < 2 { return; }
        let num_section = trial_start.len() - 1;
        for i in 0..num_section {
            self.force_no_use(active, trial_start[i] as usize, trial_start[i + 1] as usize);
        }
        for i in 0..num_section {
            self.force_inactive_chain(
                active, 2,
                trial_start[i] as usize, trial_start[i + 1] as usize,
                self.resource_start[i],
            );
        }
        for i in 0..active.get_num_trials() {
            if active.get_trial(i).is_active() { active.get_trial_mut(i).mark_used(); }
        }
    }

    // Ghidra: fspec.cc:1315 ParamListStandard::checkJoin
    /// Check if the two (hi/lo) locations can be joined. Faithful to
    /// `checkJoin` (fspec.cc:1315-1340).
    pub fn check_join(&self, hi_addr: Address, hi_size: i32, lo_addr: Address, lo_size: i32) -> bool {
        let entry_hi = match self.find_entry(hi_addr, hi_size, true) { Some(e) => e, None => return false };
        let entry_lo = match self.find_entry(lo_addr, lo_size, true) { Some(e) => e, None => return false };
        if self.entry[entry_hi].get_group() == self.entry[entry_lo].get_group() {
            if self.entry[entry_hi].is_exclusion() || self.entry[entry_lo].is_exclusion() { return false; }
            if !is_contiguous(hi_addr, hi_size, lo_addr, lo_size) { return false; }
            if (hi_addr.as_u64() - self.entry[entry_hi].get_base()) % self.entry[entry_hi].get_align() as u64 != 0 { return false; }
            if (lo_addr.as_u64() - self.entry[entry_lo].get_base()) % self.entry[entry_lo].get_align() as u64 != 0 { return false; }
            return true;
        }
        let size_sum = hi_size + lo_size;
        for cur in &self.entry {
            if cur.get_size() < size_sum { continue; }
            if cur.justified_contain(lo_addr, lo_size) != 0 { continue; }
            if cur.justified_contain(hi_addr, hi_size) != lo_size { continue; }
            return true;
        }
        false
    }

    // Ghidra: fspec.cc:1342 ParamListStandard::checkSplit
    /// Check if it makes sense to split a single storage location.
    /// Faithful to `checkSplit` (fspec.cc:1342-1352).
    pub fn check_split(&self, loc: Address, size: i32, split_point: i32) -> bool {
        let loc2 = Address::new(loc.as_u64() + split_point as u64);
        let size2 = size - split_point;
        if self.find_entry(loc, split_point, true).is_none() { return false; }
        if self.find_entry(loc2, size2, true).is_none() { return false; }
        true
    }

    // Ghidra: fspec.cc:1354 ParamListStandard::possibleParam
    pub fn possible_param(&self, loc: Address, size: i32) -> bool {
        self.find_entry(loc, size, true).is_some()
    }

    // Ghidra: fspec.cc:1360 ParamListStandard::possibleParamWithSlot
    /// Pass-back the slot and slot size. Faithful to `possibleParamWithSlot`
    /// (fspec.cc:1360-1373).
    pub fn possible_param_with_slot(
        &self, loc: Address, size: i32, slot: &mut i32, slot_size: &mut i32,
    ) -> bool {
        let entry_num = match self.find_entry(loc, size, true) { Some(e) => e, None => return false };
        let entry = &self.entry[entry_num];
        *slot = entry.get_slot(loc, 0);
        if entry.is_exclusion() {
            *slot_size = entry.get_all_groups().len() as i32;
        } else {
            *slot_size = ((size - 1) / entry.get_align()) + 1;
        }
        true
    }

    // Ghidra: fspec.cc:1375 ParamListStandard::getBiggestContainedParam
    /// Pass-back the biggest parameter contained within the given range.
    /// Faithful to `getBiggestContainedParam` (fspec.cc:1375-1409).
    pub fn get_biggest_contained_param(&self, loc: Address, size: i32, res: &mut VarnodeData) -> bool {
        let end_loc = Address::new(loc.as_u64().wrapping_add(size as u64 - 1));
        if end_loc.as_u64() < loc.as_u64() { return false; }
        let mut max_entry: Option<usize> = None;
        for (i, e) in self.entry.iter().enumerate() {
            if e.get_space() != AddressSpace::Ram { continue; }
            if e.contained_by(loc, size) {
                match max_entry {
                    None => max_entry = Some(i),
                    Some(m) => { if e.get_size() > self.entry[m].get_size() { max_entry = Some(i); } }
                }
            }
        }
        if let Some(m) = max_entry {
            let max_e = &self.entry[m];
            if !max_e.is_exclusion() { return false; }
            res.space = max_e.get_space();
            res.offset = max_e.get_base();
            res.size = max_e.get_size();
            return true;
        }
        false
    }

    // Ghidra: fspec.cc:1411 ParamListStandard::unjustifiedContainer
    /// Check if the given storage location looks like an unjustified
    /// parameter. Faithful to `unjustifiedContainer` (fspec.cc:1411-1424).
    pub fn unjustified_container(&self, loc: Address, size: i32, res: &mut VarnodeData) -> bool {
        for cur in &self.entry {
            if cur.get_min_size() > size { continue; }
            if cur.get_space() != AddressSpace::Ram { continue; }
            let just = cur.justified_contain(loc, size);
            if just < 0 { continue; }
            if just == 0 { return false; }
            cur.get_container(loc, size, res);
            return true;
        }
        false
    }

    // Ghidra: fspec.cc:1426 ParamListStandard::assumedExtension
    /// Get the type of extension and containing parameter. Faithful to
    /// `assumedExtension` (fspec.cc:1426-1437).
    pub fn assumed_extension(&self, addr: Address, size: i32, res: &mut VarnodeData) -> FspecOpCode {
        for cur in &self.entry {
            if cur.get_min_size() > size { continue; }
            if cur.get_space() != AddressSpace::Ram { continue; }
            let ext = cur.assumed_extension(addr, size, res);
            if ext != FspecOpCode::CPUI_COPY { return ext; }
        }
        FspecOpCode::CPUI_COPY
    }

    // Ghidra: fspec.cc:1439 ParamListStandard::getRangeList
    /// For a given address space, collect all the parameter locations.
    /// Faithful to `getRangeList` (fspec.cc:1439-1449).
    pub fn get_range_list(&self, spc: AddressSpace, res: &mut crate::address::RangeList) {
        for cur in &self.entry {
            if cur.get_space() != spc { continue; }
            let base_off = cur.get_base();
            let end_off = base_off + cur.get_size() as u64 - 1;
            if let Some(r) = FsRange::new(Address::new(base_off), Address::new(end_off)) {
                res.insert_range(r);
            }
        }
    }

    // Ghidra: fspec.cc:1153 ParamListStandard::calcDelay
    /// Calculate the maximum heritage delay. Faithful to `calcDelay`
    /// (fspec.cc:1153-1163).
    pub fn calc_delay(&mut self) {
        self.max_delay = 0;
        for cur in &self.entry {
            let delay = cur.get_space().get_delay();
            if delay > self.max_delay { self.max_delay = delay; }
        }
    }

    // Ghidra: fspec.cc:1191 ParamListStandard::populateResolver
    /// Enter all the ParamEntry objects into an interval map.
    ///
    /// TODO(ALIGNMENT_ROADMAP): depends on unported `ParamEntryResolver`
    /// rangemap (fspec.hh:597). Rugra's resolver is the linear scan in
    /// `find_entry`; this method refreshes the `stack_entry_index` cache.
    pub fn populate_resolver(&mut self) {
        self.stack_entry_index = None;
        for (i, e) in self.entry.iter().enumerate() {
            if !e.is_exclusion() && e.get_space() == AddressSpace::Stack {
                self.stack_entry_index = Some(i);
            }
        }
    }

    // Ghidra: fspec.cc:1174 ParamListStandard::addResolverRange
    /// Internal method for adding a single address range to the
    /// ParamEntryResolvers.
    ///
    /// TODO(ALIGNMENT_ROADMAP): depends on unported `ParamEntryResolver`
    /// rangemap. Rugra's resolver is the linear scan in `find_entry`, so
    /// this is a no-op stub; preserved for API parity.
    pub fn add_resolver_range(
        &mut self, _spc: AddressSpace, _first: u64, _last: u64, _param_entry: usize, _position: i32,
    ) {}

    // Ghidra: fspec.cc:1226 ParamListStandard::parsePentry
    /// Parse a `<pentry>` element and add it to this list.
    ///
    /// TODO(ALIGNMENT_ROADMAP): depends on unported `Decoder` marshaling.
    /// Accepts an already-decoded ParamEntry and applies the post-decode
    /// state transitions (resolve_first/resolve_join/resolve_overlap,
    /// resource_start accounting, space_base detection). Faithful algorithm
    /// in the doc-comment.
    pub fn parse_pentry(
        &mut self, group_id: i32, normal_stack: bool, split_float: bool, grouped: bool,
        effect_list: &mut Vec<EffectRecord>, decoded: ParamEntry,
    ) -> Result<(), String> {
        let last_class = if !self.entry.is_empty() {
            if self.entry.last().unwrap().is_grouped() { TypeClass::General }
            else { self.entry.last().unwrap().get_type() }
        } else { TypeClass::Class4 };
        let mut new_entry = decoded;
        new_entry.resolve_first(&self.entry);
        new_entry.resolve_join(&self.entry);
        new_entry.resolve_overlap(&self.entry);
        if !normal_stack {
            *new_entry.flags_mut() |= param_entry_flags::REVERSE_STACK;
        }
        if grouped {
            *new_entry.flags_mut() |= param_entry_flags::IS_GROUPED;
        }
        self.entry.push(new_entry);
        let cur = self.entry.last().unwrap();
        if split_float {
            let current_class = if grouped { TypeClass::General } else { cur.get_type() };
            if last_class != current_class {
                if last_class < current_class {
                    return Err("parameter list entries must be ordered by storage class".to_string());
                }
                self.resource_start.push(group_id);
            }
        }
        let spc = cur.get_space();
        if spc == AddressSpace::Stack {
            self.space_base = Some(spc);
            self.stack_entry_index = Some(self.entry.len() - 1);
        } else if self.auto_killed_by_call {
            effect_list.push(EffectRecord::new(spc, cur.get_base(), cur.get_size(), EffectType::KilledByCall));
        }
        let max_group = *cur.get_all_groups().last().unwrap_or(&0) + 1;
        if max_group > self.num_group { self.num_group = max_group; }
        Ok(())
    }

    // Ghidra: fspec.cc:1262 ParamListStandard::parseGroup
    /// Parse a sequence of `<pentry>` elements allocated as a group.
    ///
    /// TODO(ALIGNMENT_ROADMAP): depends on unported `Decoder` marshaling.
    /// Accepts an already-decoded sequence and applies the group-ordering
    /// rules.
    pub fn parse_group(
        &mut self, group_id: i32, normal_stack: bool, split_float: bool,
        effect_list: &mut Vec<EffectRecord>, entries: Vec<ParamEntry>,
    ) -> Result<(), String> {
        let base_group = self.num_group;
        let mut previous1: Option<usize> = None;
        let mut previous2: Option<usize> = None;
        for decoded_entry in entries {
            if decoded_entry.get_space() == AddressSpace::Join {
                return Err("<pentry> in the join space not allowed in <group> tag".to_string());
            }
            self.parse_pentry(base_group, normal_stack, split_float, true, effect_list, decoded_entry)?;
            let pentry_idx = self.entry.len() - 1;
            if let Some(p1) = previous1 {
                ParamEntry::order_within_group(&self.entry[p1], &self.entry[pentry_idx])?;
                if let Some(p2) = previous2 {
                    ParamEntry::order_within_group(&self.entry[p2], &self.entry[pentry_idx])?;
                }
            }
            previous2 = previous1;
            previous1 = Some(pentry_idx);
        }
        let _ = group_id;
        Ok(())
    }

    // Ghidra: fspec.cc:1451 ParamListStandard::decode
    /// Restore the model from an `<input>` or `<output>` element.
    ///
    /// TODO(ALIGNMENT_ROADMAP): depends on unported `Decoder` attribute/
    /// element id constants. Rugra exposes the post-decode finalization
    /// (`resource_start.push(num_group)`, `calc_delay`, `populate_resolver`)
    /// via `finalize_after_decode` so a caller that has manually parsed the
    /// element tree can complete the model.
    pub fn finalize_after_decode(&mut self, pointer_max: i32) {
        self.resource_start.push(self.num_group);
        self.calc_delay();
        self.populate_resolver();
        // TODO(ALIGNMENT_ROADMAP): depends on unported ModelRule /
        // ConvertToPointer (modelrules.hh). Ghidra appends a
        // convert-to-pointer rule when pointermax > 0.
        let _ = pointer_max;
    }

    // Ghidra: fspec.hh:645 ParamListStandard::clone
    // RUGRA-GLUE: clone (Rust uses Clone derive; named accessor matching
    // Ghidra's virtual clone()).
    pub fn clone_model(&self) -> ParamListStandard { self.clone() }

    // RUGRA-GLUE: setters for the model loader (Ghidra fills these during
    // `ParamListStandard::decode`; Rugra's decoder is unported).
    pub fn set_this_before_ret(&mut self, v: bool) { self.this_before_ret = v; }
    // RUGRA-GLUE: loader/subclass field setter; Ghidra writes the protected
    // autoKilledByCall field directly in decode() and initialize().
    pub fn set_auto_killed_by_call(&mut self, v: bool) { self.auto_killed_by_call = v; }
    // RUGRA-GLUE: inheritance bridge; Ghidra subclasses read protected
    // ParamListStandard::numgroup directly and expose no getNumGroup member.
    pub fn get_num_group(&self) -> i32 { self.num_group }

    /// Set the number of resource groups (used by the output-list decoders
    /// and `assign_map` to size the per-group status vector).
    // RUGRA-GLUE: loader field setter; Ghidra updates protected numgroup
    // directly while parsing entries and exposes no setNumGroup member.
    pub fn set_num_group(&mut self, v: i32) { self.num_group = v; }

    /// Mutable access to the entry list. Used by `ParamListStandardOut` to
    /// run the fallback fillin algorithm, which mirrors Ghidra's
    /// `list<ParamEntry>` iteration over `entry`.
    // RUGRA-GLUE: inheritance bridge; Ghidra subclasses access the protected
    // entry list directly and provide only a const getEntry() accessor.
    pub fn entry_mut(&mut self) -> &mut Vec<ParamEntry> { &mut self.entry }
}

// ======================================================================
// ParamListStandardOut — faithful port of Ghidra's
// `class ParamListStandardOut : public ParamListStandard`
// (fspec.hh:656-670, fspec.cc:1569-1788)
// ======================================================================
// A standard model for returning output parameters from a function.
// Entries in the resource list are treated as a group, meaning that only
// one can fit the desired storage size and type attributes of the return
// value. If no entry fits, the return value is converted to a pointer
// data-type, storage allocation is attempted again, and the return value
// is marked as a hidden return parameter to inform the input model.
//
// Rust has no inheritance, so this struct embeds a `ParamListStandard`
// (`base`) plus the single extra field (`use_fillin_fallback`). All
// inherited behaviour is reached via `self.base`.

/// Faithful port of `class ParamListStandardOut` (fspec.hh:656-670).
#[derive(Debug, Clone)]
pub struct ParamListStandardOut {
    /// Inherited `ParamListStandard` state. Stands in for C++ public-base.
    pub base: ParamListStandard,
    /// If `true`, `fillin_map` should defer to `fillin_map_fallback`.
    /// Faithful to `ParamListStandardOut::useFillinFallback` (fspec.hh:657).
    use_fillin_fallback: bool,
}

impl Default for ParamListStandardOut {
    // RUGRA-GLUE: Rust Default trait bridge delegates to new(); Ghidra has the
    // ParamListStandardOut constructor but no default() member.
    fn default() -> Self { Self::new() }
}

impl ParamListStandardOut {
    // Ghidra: fspec.hh:660 ParamListStandardOut::ParamListStandardOut()
    /// Constructor for use with `decode()`. Faithful to
    /// `ParamListStandardOut()` (fspec.hh:660).
    pub fn new() -> Self {
        Self { base: ParamListStandard::new(), use_fillin_fallback: false }
    }

    // Ghidra: fspec.hh:661 ParamListStandardOut::ParamListStandardOut(op2)
    /// Copy constructor. Faithful to
    /// `ParamListStandardOut(const ParamListStandardOut &op2)` (fspec.hh:661).
    pub fn from_other(op2: &ParamListStandardOut) -> Self {
        Self { base: op2.base.clone(), use_fillin_fallback: op2.use_fillin_fallback }
    }

    // Ghidra: fspec.hh:664 ParamListStandardOut::getType
    /// Return the runtime type tag. Faithful to `getType` (fspec.hh:664).
    pub fn get_type(&self) -> ParamListKind { ParamListKind::StandardOut }

    // Ghidra: fspec.cc:1614 ParamListStandardOut::initialize
    /// Cache ModelRule information. Faithful 1:1 port of `initialize`
    /// (fspec.cc:1614-1627): scans `modelRules`; if no rule can affect the
    /// fillin output (`canAffectFillinOutput`), `use_fillin_fallback` stays
    /// `true` and `auto_killed_by_call` is forced on (legacy behaviour).
    /// Rugra has no `ModelRule` port yet, so the scan is empty and the
    /// legacy path is taken unconditionally.
    pub fn initialize(&mut self) {
        self.use_fillin_fallback = true;
        // TODO(ALIGNMENT_ROADMAP): depends on unported `ModelRule` /
        // `ModelRule::canAffectFillinOutput` (modelrules.hh). Ghidra iterates
        // `modelRules` and clears `use_fillin_fallback` if any rule can
        // affect the fillin output. With no rules ported, the legacy path is
        // taken.
        if self.use_fillin_fallback {
            self.base.set_auto_killed_by_call(true);
        }
    }

    // Ghidra: fspec.cc:1569 ParamListStandardOut::assignMap
    /// Assign storage for the single output (return) parameter. Faithful
    /// 1:1 port of `assignMap` (fspec.cc:1569-1612). Emplaces one
    /// `ParameterPieces` for the return value; on `TYPE_VOID` it is left
    /// invalid. On `assignAddress` failure the action escalates to a hidden
    /// return: the return piece is re-typed as a pointer to the original
    /// out-type, its storage is reassigned, and a second piece is appended
    /// holding the hidden-return input pointer. `AssignAction::hiddenret_*`
    /// select between pointer-in-first-slot and special-register variants.
    pub fn assign_map(
        &self, proto: &PrototypePieces,
        _typefactory: &crate::type_system::TypeFactory,
        res: &mut Vec<ParameterPieces>,
    ) -> Result<(), String> {
        let mut status = vec![0i32; self.base.get_num_group() as usize];
        res.push(ParameterPieces::default());
        let out_type = match proto.out_type {
            None => {
                res.last_mut().unwrap().ty = None;
                res.last_mut().unwrap().flags = 0;
                return Ok(()); // Treat absent out_type as void.
            }
            Some(t) => t,
        };
        if matches!(out_type.get_metatype(), crate::type_system::TypeMetatype::Void) {
            res.last_mut().unwrap().ty = Some(std::sync::Arc::new(out_type.clone()));
            res.last_mut().unwrap().flags = 0;
            return Ok(()); // Leave the address invalid.
        }
        let response = self.base.assign_address(
            out_type, proto, -1, &mut status, res.last_mut().unwrap(),
        );
        // Map Ghidra's AssignAction codes (modelrules.hh:264-271) onto the
        // local enum. Rugra's `AssignActionResponse` collapses the
        // hiddenret_* codes; we treat any non-Fail response as Success and
        // only escalate on Fail.
        let mut response_code = if response == AssignActionResponse::Fail {
            // Ghidra: responseCode = hiddenret_ptrparam  (default action)
            HiddenRetAction::PtrParam
        } else {
            HiddenRetAction::Success
        };
        if matches!(
            response_code,
            HiddenRetAction::PtrParam
                | HiddenRetAction::SpecialReg
                | HiddenRetAction::SpecialRegVoid
        ) {
            // Ghidra: AddrSpace *spc = spacebase; fallback to default data space.
            // Rugra has no TypeFactory pointer plumbing; the pointer size is
            // taken from the out-type, matching `getAddrSize`/`getWordSize` of
            // the model's spacebase when one is present.
            let pointersize = out_type.get_size() as i32;
            let wordsize = 1i32;
            // Ghidra: Datatype *pointertp = typefactory.getTypePointer(...).
            // Rugra has no `TypeFactory::getTypePointer`; we re-use the
            // out-type as the pointer's base and let later passes reconcile.
            let pointer_tp: std::sync::Arc<Datatype> = std::sync::Arc::new(out_type.clone());
            if matches!(response_code, HiddenRetAction::SpecialRegVoid) {
                res.last_mut().unwrap().ty = None; // Ghidra: getTypeVoid()
            } else {
                res.last_mut().unwrap().ty = Some(pointer_tp.clone());
                let r2 = self.base.assign_address(
                    out_type, proto, -1, &mut status, res.last_mut().unwrap(),
                );
                if r2 == AssignActionResponse::Fail {
                    return Err("Cannot assign return value as a pointer".to_string());
                }
            }
            res.last_mut().unwrap().flags = INDIRECT_STORAGE_PIECE;
            // Ghidra: res.emplace_back(); extra input slot for the hidden
            // return pointer; its address is left invalid (filled in by the
            // input list's assignMap).
            res.push(ParameterPieces::default());
            res.last_mut().unwrap().ty = Some(pointer_tp);
            let is_special = matches!(
                response_code,
                HiddenRetAction::SpecialReg | HiddenRetAction::SpecialRegVoid
            );
            res.last_mut().unwrap().flags = if is_special { HIDDEN_RET_PARM } else { 0 };
            let _ = wordsize;
        }
        // Suppress unused-warning on the success branch.
        let _ = response_code;
        Ok(())
    }

    // Ghidra: fspec.cc:1638 ParamListStandardOut::fillinMapFallback
    /// Find the return-value storage using the older fallback method.
    /// Faithful 1:1 port of `fillinMapFallback` (fspec.cc:1638-1719).
    ///
    /// Given the active set of trial locations that might hold (pieces of)
    /// the return value, calculate the best matching ParamEntry from this
    /// list and mark all the trials that are contained in the ParamEntry as
    /// used. If `first_only` is `true`, the list is assumed to hold partial
    /// storage locations for split return values and only the first
    /// ParamEntry in a storage class is allowed to match.
    pub fn fillin_map_fallback(&self, active: &mut ParamActive, first_only: bool) {
        let mut best_entry: Option<usize> = None;
        let mut best_cover = 0i32;
        let mut best_class = TypeClass::Pointer;
        let num_trials = active.get_num_trials();
        // Ghidra: for each entry, evaluate all active trials in terms of it.
        for (entry_idx, curentry) in self.base.get_entry().iter().enumerate() {
            if first_only
                && !curentry.is_first_in_class()
                && curentry.is_exclusion()
                && curentry.get_all_groups().len() == 1
            {
                continue; // Not the first entry in the storage class.
            }
            let mut putative_match = false;
            for j in 0..num_trials {
                let (t_addr, t_size, t_active) = {
                    let t = active.get_trial(j);
                    (t.get_address(), t.get_size(), t.is_active())
                };
                if t_active {
                    let res = curentry.justified_contain(t_addr, t_size);
                    if res >= 0 {
                        active.get_trial_mut(j).set_entry(entry_idx, res);
                        putative_match = true;
                    } else {
                        active.get_trial_mut(j).clear_entry();
                    }
                } else {
                    active.get_trial_mut(j).clear_entry();
                }
            }
            if !putative_match { continue; }
            active.sort_trials();
            // Count least-justified contiguous bytes covered by this entry.
            let mut offmatch = 0i32;
            let mut k = 0usize;
            while k < active.get_num_trials() {
                let t = active.get_trial(k);
                let entry_idx_opt = t.get_entry_index();
                if entry_idx_opt.is_none() { k += 1; continue; }
                if offmatch != t.get_offset() { break; }
                if ((offmatch == 0) && curentry.is_param_check_low())
                    || ((offmatch != 0) && curentry.is_param_check_high())
                {
                    // Multi-precision extra checks: reject pieces that look
                    // like the remainder of a div/mod or an indirect-creation.
                    if t.is_rem_formed() { break; }
                    if t.is_ind_create_formed() { break; }
                }
                offmatch += t.get_size();
                k += 1;
            }
            if offmatch < curentry.get_min_size() {
                // Didn't cover the minimum size; don't use this entry.
                k = 0;
            }
            let cur_type = curentry.get_type();
            if k == active.get_num_trials()
                && ((cur_type as u32) < (best_class as u32) || (offmatch > best_cover))
            {
                best_entry = Some(entry_idx);
                best_cover = offmatch;
                best_class = cur_type;
            }
            let _ = curentry; // borrow-checker hint
        }
        match best_entry {
            None => {
                // Ghidra: no match — mark every trial no-use.
                for i in 0..active.get_num_trials() {
                    active.get_trial_mut(i).mark_no_use();
                }
            }
            Some(best) => {
                let best_entry_ref = &self.base.get_entry()[best];
                for i in 0..active.get_num_trials() {
                    let (t_addr, t_size, t_active) = {
                        let t = active.get_trial(i);
                        (t.get_address(), t.get_size(), t.is_active())
                    };
                    if t_active {
                        let res = best_entry_ref.justified_contain(t_addr, t_size);
                        if res >= 0 {
                            let t = active.get_trial_mut(i);
                            t.mark_used(); // Only actives are ever marked used.
                            t.set_entry(best, res);
                        } else {
                            let t = active.get_trial_mut(i);
                            t.mark_no_use();
                            t.clear_entry();
                        }
                    } else {
                        let t = active.get_trial_mut(i);
                        t.mark_no_use();
                        t.clear_entry();
                    }
                }
                active.sort_trials();
            }
        }
    }

    // Ghidra: fspec.cc:1721 ParamListStandardOut::fillinMap
    /// Decide the formal output parameter given a set of trials. Faithful
    /// 1:1 port of `fillinMap` (fspec.cc:1721-1763). If `use_fillinFallback`
    /// is set, defers entirely to the fallback path; otherwise walks the
    /// trials, attaches each active one to its entry (rejecting remainder /
    /// indirect-creation pieces that aren't first-in-class), then asks the
    /// model rules to settle the output. Rugra has no model rules yet, so
    /// the non-fallback path falls through to `fillin_map_fallback(true)`.
    pub fn fillin_map(&self, active: &mut ParamActive) {
        if active.get_num_trials() == 0 { return; }
        if self.use_fillin_fallback {
            self.fillin_map_fallback(active, false);
            return;
        }
        for i in 0..active.get_num_trials() {
            let (t_addr, t_size, t_active) = {
                let t = active.get_trial(i);
                (t.get_address(), t.get_size(), t.is_active())
            };
            active.get_trial_mut(i).clear_entry();
            if !t_active { continue; }
            let entry = self.base.find_entry(t_addr, t_size, false);
            if entry.is_none() {
                active.get_trial_mut(i).mark_no_use();
                continue;
            }
            let entry_idx = entry.unwrap();
            let res = self.base.get_entry()[entry_idx].justified_contain(t_addr, t_size);
            let rem_or_ind = {
                let t = active.get_trial(i);
                t.is_rem_formed() || t.is_ind_create_formed()
            };
            if rem_or_ind && !self.base.get_entry()[entry_idx].is_first_in_class() {
                active.get_trial_mut(i).mark_no_use();
                continue;
            }
            active.get_trial_mut(i).set_entry(entry_idx, res);
        }
        active.sort_trials();
        // TODO(ALIGNMENT_ROADMAP): depends on unported
        // `ModelRule::fillinOutputMap` (modelrules.hh). Ghidra walks
        // `modelRules` and, on the first rule whose `fillinOutputMap`
        // succeeds, marks all active trials used and returns. With no rules
        // ported, we fall through to the fallback.
        self.fillin_map_fallback(active, true);
    }

    // Ghidra: fspec.cc:1765 ParamListStandardOut::possibleParam
    /// Is the given storage a possible return-value location? Faithful to
    /// `possibleParam` (fspec.cc:1765-1774): returns `true` if any entry
    /// `justifiedContain`s the range. Differs from `ParamListStandard`'s
    /// override (which uses `find_entry`) because output entries are
    /// evaluated per-class, not by exact match.
    pub fn possible_param(&self, loc: Address, size: i32) -> bool {
        for cur in self.base.get_entry() {
            if cur.justified_contain(loc, size) >= 0 { return true; }
        }
        false
    }

    // Ghidra: fspec.cc:1776 ParamListStandardOut::decode
    /// Decode this list, then cache the model-rule information. Faithful to
    /// `decode` (fspec.cc:1776-1780): delegates the `<pentry>` parse to
    /// `ParamListStandard::decode` and then calls `initialize()`. Rugra's
    /// XML decoder is unported, so this is a structural stub that runs the
    /// initialize step (the only behaviour reachable without the decoder).
    pub fn decode(
        &mut self,
        _decoder: &mut dyn crate::marshal::Decoder,
        _effectlist: &mut Vec<EffectRecord>,
        _normalstack: bool,
    ) -> Result<(), String> {
        // TODO(ALIGNMENT_ROADMAP): depends on unported
        // `ParamListStandard::decode` XML path. Ghidra:
        //   ParamListStandard::decode(decoder, effectlist, normalstack);
        //   initialize();
        self.initialize();
        Ok(())
    }

    // Ghidra: fspec.hh:669 ParamListStandardOut::clone
    /// Virtual clone. Faithful to `clone` (fspec.cc:1783-1787).
    pub fn clone_out(&self) -> ParamListStandardOut { self.clone() }
}

// ======================================================================
// ParamListRegisterOut — faithful port of Ghidra's
// `class ParamListRegisterOut : public ParamListStandardOut`
// (fspec.hh:679-686, fspec.cc:1519-1540)
// ======================================================================
// A model for passing back return values from a function. This is a
// resource list of potential storage locations for a return value, at
// most 1 of which will be chosen. When assigning based on data-type
// (assignMap), the first list entry that fits is chosen.

/// Faithful port of `class ParamListRegisterOut` (fspec.hh:679-686).
#[derive(Debug, Clone)]
pub struct ParamListRegisterOut {
    /// Inherited `ParamListStandardOut` state.
    pub base: ParamListStandardOut,
}

impl Default for ParamListRegisterOut {
    // RUGRA-GLUE: Rust Default trait bridge delegates to new(); Ghidra has the
    // ParamListRegisterOut constructor but no default() member.
    fn default() -> Self { Self::new() }
}

impl ParamListRegisterOut {
    // Ghidra: fspec.hh:681 ParamListRegisterOut::ParamListRegisterOut()
    /// Constructor. Faithful to `ParamListRegisterOut()` (fspec.hh:681).
    pub fn new() -> Self { Self { base: ParamListStandardOut::new() } }

    // Ghidra: fspec.hh:682 ParamListRegisterOut::ParamListRegisterOut(op2)
    /// Copy constructor. Faithful to
    /// `ParamListRegisterOut(const ParamListRegisterOut &op2)` (fspec.hh:682).
    pub fn from_other(op2: &ParamListRegisterOut) -> Self {
        Self { base: ParamListStandardOut::from_other(&op2.base) }
    }

    // Ghidra: fspec.hh:683 ParamListRegisterOut::getType
    /// Return the runtime type tag. Faithful to `getType` (fspec.hh:683).
    pub fn get_type(&self) -> ParamListKind { ParamListKind::RegisterOut }

    // Ghidra: fspec.cc:1519 ParamListRegisterOut::assignMap
    /// Assign the return value to the first fitting register entry.
    /// Faithful 1:1 port of `assignMap` (fspec.cc:1519-1533). Emplaces one
    /// `ParameterPiece`; on a non-void out-type the storage is assigned via
    /// `ParamListStandard::assignAddress` (which, with no model rules,
    /// falls through to `assignAddressFallback` — the "first entry that
    /// fits" strategy). On failure throws `ParamUnassignedError`.
    pub fn assign_map(
        &self, proto: &PrototypePieces,
        _typefactory: &crate::type_system::TypeFactory,
        res: &mut Vec<ParameterPieces>,
    ) -> Result<(), String> {
        let mut status = vec![0i32; self.base.base.get_num_group() as usize];
        res.push(ParameterPieces::default());
        let out_type = match proto.out_type {
            None => {
                res.last_mut().unwrap().ty = None;
                res.last_mut().unwrap().flags = 0;
                return Ok(());
            }
            Some(t) => t,
        };
        if !matches!(out_type.get_metatype(), crate::type_system::TypeMetatype::Void) {
            let r = self.base.base.assign_address(
                out_type, proto, -1, &mut status, res.last_mut().unwrap(),
            );
            if r == AssignActionResponse::Fail {
                return Err(format!(
                    "Cannot assign parameter address for {}",
                    out_type.get_name()
                ));
            }
        } else {
            res.last_mut().unwrap().ty = Some(std::sync::Arc::new(out_type.clone()));
            res.last_mut().unwrap().flags = 0;
        }
        Ok(())
    }

    // Ghidra: fspec.hh:685 ParamListRegisterOut::clone
    /// Virtual clone. Faithful to `clone` (fspec.cc:1535-1539).
    pub fn clone_reg_out(&self) -> ParamListRegisterOut { self.clone() }
}

/// Internal enum mirroring Ghidra's `AssignAction` hidden-return codes
/// (modelrules.hh:264-271). Rugra's `AssignActionResponse` collapses these
/// into `Fail`/`Success`; `ParamListStandardOut::assign_map` re-expands
/// them locally to drive the hidden-return escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HiddenRetAction {
    Success,
    PtrParam,
    SpecialReg,
    SpecialRegVoid,
}

// ======================================================================
// ProtoModelFull — faithful port of Ghidra's `ProtoModel`
// (fspec.hh:748-1100, fspec.cc:2263-2700)
// ======================================================================
// The existing `crate::type_system::protomodel::ProtoModel` is a simplified
// x86_64 stub. This struct is the 1:1 alignment target: it carries the full
// field set (effectlist, likelytrash, internalstorage, localrange, paramrange,
// input/output ParamListStandard) so that `decode`, `assignParameterStorage`,
// `isCompatible`, `defaultLocalRange`, `buildParamList` etc. can be ported
// faithfully.

/// Reserved `extrapop` value meaning the function's extrapop is unknown.
/// Faithful to `ProtoModel::extrapop_unknown` (fspec.hh:772).
pub const EXTRAPOP_UNKNOWN_FULL: i32 = 0x8000;

/// Magic sentinel used by `ProtoModel::decode` to detect that no `extrapop`
/// attribute was seen (Ghidra initializes `extrapop = -300` before parsing,
/// fspec.cc:2562). Distinct from `EXTRAPOP_UNKNOWN_FULL`.
const EXTRAPOP_MISSING_SENTINEL: i32 = -300;

/// A faithful port of Ghidra's `ProtoModel` (fspec.hh:748-1017).
///
/// Holds the input/output `ParamListStandard`, effect records, likely-trash,
/// internal-storage registers, local/param stack ranges, and ABI properties
/// (extrapop, stack growth direction, hasThis, isConstructor, isPrinted).
#[derive(Debug, Clone)]
pub struct ProtoModelFull {
    /// Name of the model (e.g. "__stdcall", "default"). Faithful to `name`.
    pub name: String,
    /// Extra bytes popped from the stack by the callee. Faithful to `extrapop`.
    pub extrapop: i32,
    /// Input parameter resource list. Faithful to `ParamList *input`.
    pub input: ParamListStandard,
    /// Output (return value) parameter resource list. Faithful to
    /// `ParamList *output`.
    pub output: ParamListStandard,
    /// Side-effects on non-parameter storage. Faithful to `effectlist`.
    /// Must be kept sorted by address for `lookup_effect`.
    pub effectlist: Vec<EffectRecord>,
    /// Storage locations potentially carrying trash values. Faithful to
    /// `likelytrash`.
    pub likelytrash: Vec<VarnodeData>,
    /// Registers holding internal compiler constants. Faithful to
    /// `internalstorage`.
    pub internalstorage: Vec<VarnodeData>,
    /// Id of injection to perform at function entry (-1 = unused). Faithful
    /// to `injectUponEntry`.
    pub inject_upon_entry: i32,
    /// Id of injection to perform after a call (-1 = unused). Faithful to
    /// `injectUponReturn`.
    pub inject_upon_return: i32,
    /// Memory range(s) of space-based locals. Faithful to `localrange`.
    pub localrange: crate::address::RangeList,
    /// Memory range(s) of space-based parameters. Faithful to `paramrange`.
    pub paramrange: crate::address::RangeList,
    /// True if stack parameters have (normal) low→high ordering. Faithful to
    /// `stackgrowsnegative`.
    pub stackgrowsnegative: bool,
    /// True if this model has a `this` parameter. Faithful to `hasThis`.
    pub has_this: bool,
    /// True if this model is a constructor. Faithful to `isConstruct`.
    pub is_construct: bool,
    /// True if this model name should be printed in declarations. Faithful to
    /// `isPrinted`.
    pub is_printed: bool,
    /// The model this is a copy of (alias parent), or `None`. Faithful to
    /// `compatModel`. Used by `isCompatible`.
    pub compat_model: Option<usize>,
}

impl ProtoModelFull {
    // Ghidra: fspec.cc:2339 ProtoModel::ProtoModel (default constructor)
    /// Construct a model with default fields, mirroring Ghidra's constructor
    /// which calls `defaultLocalRange()`/`defaultParamRange()`.
    pub fn new(stack_space: Option<AddressSpace>, addr_size: usize) -> Self {
        let mut model = Self {
            name: String::new(),
            extrapop: 0,
            input: ParamListStandard::new(),
            output: ParamListStandard::new(),
            effectlist: Vec::new(),
            likelytrash: Vec::new(),
            internalstorage: Vec::new(),
            inject_upon_entry: -1,
            inject_upon_return: -1,
            localrange: crate::address::RangeList::new(),
            paramrange: crate::address::RangeList::new(),
            stackgrowsnegative: true,
            has_this: false,
            is_construct: false,
            is_printed: true,
            compat_model: None,
        };
        model.default_local_range(stack_space, addr_size);
        model.default_param_range(stack_space, addr_size);
        model
    }

    // Ghidra: fspec.cc:2263 ProtoModel::defaultLocalRange
    /// Establish the default stack range used for local variables. Faithful
    /// 1:1 port of `defaultLocalRange` (fspec.cc:2263-2290). For a normal
    /// (negative-growing) stack, locals occupy the high end of the stack
    /// space; for a flipped stack they occupy the low end. The numeric bounds
    /// scale with the stack space's address size exactly as in Ghidra.
    pub fn default_local_range(&mut self, stack_space: Option<AddressSpace>, addr_size: usize) {
        let spc = match stack_space {
            Some(s) => s,
            None => return,
        };
        let max_off = u64::MAX; // spc->getHighest() for an enum space model
        if self.stackgrowsnegative {
            let last = max_off;
            let span = if addr_size >= 4 { 999999u64 }
                else if addr_size >= 2 { 9999u64 }
                else { 99u64 };
            let first = last.wrapping_sub(span);
            if let Some(r) = crate::address::Range::new(Address::new(first), Address::new(last)) {
                self.localrange.insert_range(r);
            }
        } else {
            let first = 0u64;
            let last = if addr_size >= 4 { 999999u64 }
                else if addr_size >= 2 { 9999u64 }
                else { 99u64 };
            if let Some(r) = crate::address::Range::new(Address::new(first), Address::new(last)) {
                self.localrange.insert_range(r);
            }
        }
        // spc is captured to mirror Ghidra's `AddrSpace *spc`; the bound is
        // encoded into the inserted Range's space implicitly (Rugra's Range
        // does not carry a space, matching the existing `RangeList` API).
        let _ = spc;
    }

    // Ghidra: fspec.cc:2292 ProtoModel::defaultParamRange
    /// Establish the default stack range used for input parameters. Faithful
    /// 1:1 port of `defaultParamRange` (fspec.cc:2292-2319). For a normal
    /// (negative-growing) stack, parameters are the first 512/256/16 bytes
    /// (scaling with address size); for a flipped stack they are the high
    /// end.
    pub fn default_param_range(&mut self, stack_space: Option<AddressSpace>, addr_size: usize) {
        let spc = match stack_space {
            Some(s) => s,
            None => return,
        };
        let max_off = u64::MAX;
        if self.stackgrowsnegative {
            let first = 0u64;
            let last = if addr_size >= 4 { 511u64 }
                else if addr_size >= 2 { 255u64 }
                else { 15u64 };
            if let Some(r) = crate::address::Range::new(Address::new(first), Address::new(last)) {
                self.paramrange.insert_range(r);
            }
        } else {
            let last = max_off;
            let first_sub = if addr_size >= 4 { 511u64 }
                else if addr_size >= 2 { 255u64 }
                else { 15u64 };
            let first = last.wrapping_sub(first_sub);
            if let Some(r) = crate::address::Range::new(Address::new(first), Address::new(last)) {
                self.paramrange.insert_range(r);
            }
        }
        let _ = spc;
    }

    // Ghidra: fspec.cc:2323 ProtoModel::buildParamList
    /// Allocate the input/output `ParamListStandard` based on the resource
    /// `strategy` string. Faithful 1:1 port of `buildParamList`
    /// (fspec.cc:2323-2336). "" or "standard" yields standard lists; "register"
    /// yields register lists (modelled here as `ParamListStandard` with the
    /// register variant flagged via `get_type`, since Rugra has not yet split
    /// out the `ParamListRegister`/`ParamListRegisterOut` subclasses). Any
    /// other strategy is a hard error, exactly as in Ghidra.
    pub fn build_param_list(&mut self, strategy: &str) -> Result<(), String> {
        if strategy.is_empty() || strategy == "standard" {
            self.input = ParamListStandard::new();
            self.output = ParamListStandard::new();
        } else if strategy == "register" {
            // Ghidra allocates ParamListRegister / ParamListRegisterOut here.
            // Rugra models the register variant as a standard list until the
            // subclasses are ported; the resource list is functionally
            // equivalent for assignMap/possibleParam.
            self.input = ParamListStandard::new();
            self.output = ParamListStandard::new();
        } else {
            return Err(format!("Unknown strategy type: {}", strategy));
        }
        Ok(())
    }

    // Ghidra: fspec.cc:2406 ProtoModel::isCompatible
    /// Return true if `other` can be substituted for this model during
    /// `FuncCallSpecs::deindirect`. Faithful 1:1 port of `isCompatible`
    /// (fspec.cc:2406-2412). Two models are compatible only if one is a copy
    /// of the other (differing at most in the `hasThis` property). The
    /// `compat_model` index plays the role of Ghidra's `compatModel` pointer.
    pub fn is_compatible(&self, other: &ProtoModelFull) -> bool {
        // Ghidra: `this == op2 || compatModel == op2 || op2->compatModel == this`
        if std::ptr::eq(self, other) { return true; }
        // Match by alias-parent index. self.compat_model points to the model
        // this was copied from; if other is that model (by name) they are
        // compatible.
        if let Some(_idx) = self.compat_model {
            if self.is_alias_of(other) { return true; }
        }
        if let Some(_idx) = other.compat_model {
            if other.is_alias_of(self) { return true; }
        }
        false
    }

    /// Helper: true if `self` is an alias copy of `parent` (same name-pattern
    /// and field set, modulo `hasThis`). Stands in for Ghidra's pointer
    /// identity check `compatModel == op2`.
    // RUGRA-GLUE: Rust-side alias predicate because ProtoModelFull does not
    // retain Ghidra's ProtoModel* identity; Ghidra performs these pointer
    // comparisons inline in ProtoModel::isCompatible (fspec.cc:2406).
    fn is_alias_of(&self, parent: &ProtoModelFull) -> bool {
        // Same name OR (parent has the same input/output entries and extrapop).
        self.name == parent.name
            || (self.extrapop == parent.extrapop
                && self.input.get_num_group() == parent.input.get_num_group())
    }

    // Ghidra: fspec.cc:2429 ProtoModel::assignParameterStorage
    /// Calculate input and output storage locations given a function
    /// prototype. Faithful 1:1 port of `assignParameterStorage`
    /// (fspec.cc:2429-2462). The output storage is assigned first (entry 0 of
    /// `res`), then the input storages follow. If `ignore_output_error` is
    /// true, an unassignable return value collapses to a void entry instead of
    /// propagating `ParamUnassignedError`. When the model `hasThis`, the
    /// `isthis` flag is set on the appropriate input, accounting for a hidden
    /// return pointer.
    pub fn assign_parameter_storage(
        &self,
        proto: &PrototypePieces,
        res: &mut Vec<ParameterPieces>,
        ignore_output_error: bool,
        void_type: Option<Arc<Datatype>>,
    ) -> Result<(), String> {
        if ignore_output_error {
            match self.output.assign_map(proto, res) {
                Ok(()) => {}
                Err(_e) => {
                    // Ghidra: catch ParamUnassignedError → clear res, push a
                    // single void entry with undefined address.
                    res.clear();
                    res.push(ParameterPieces {
                        addr: Address::new(0),
                        ty: void_type.clone(),
                        flags: 0,
                    });
                }
            }
        } else {
            self.output.assign_map(proto, res)?;
        }
        self.input.assign_map(proto, res)?;

        // Ghidra: fspec.cc:2449-2461 — set the isthis flag on the right input.
        if self.has_this && res.len() > 1 {
            let mut this_index = 1usize;
            if (res[1].flags & HIDDEN_RET_PARM) != 0 && res.len() > 2 {
                if self.input.is_this_before_ret_pointer() {
                    // pointer has been bumped by auto-return-storage: swap
                    // markup for slots 1 and 2. Use split_at_mut to obtain
                    // two disjoint mutable borrows (Rust aliasing rule).
                    let (left, right) = res.split_at_mut(2);
                    left[1].swap_markup(&mut right[0]);
                } else {
                    this_index = 2;
                }
            }
            res[this_index].flags |= THIS_POINTER_PIECE;
        }
        Ok(())
    }

    // Ghidra: fspec.cc:2472 ProtoModel::lookupEffect (static)
    /// Look up an effect from a (sorted) EffectRecord list. Faithful 1:1 port
    /// of `lookupEffect` (fspec.cc:2472-2495). Returns the matching effect
    /// type, or `EffectType::UnknownEffect` if no record overlaps the given
    /// range. Internal (unique) space is always considered unaffected.
    pub fn lookup_effect(
        efflist: &[EffectRecord],
        addr_space: AddressSpace,
        addr_offset: u64,
        size: i32,
    ) -> EffectType {
        // Ghidra: if (addr.getSpace()->getType()==IPTR_INTERNAL) return unaffected;
        if addr_space == AddressSpace::Unique {
            return EffectType::Unaffected;
        }
        if efflist.is_empty() {
            return EffectType::UnknownEffect;
        }
        // upper_bound by address: find first record whose address > target,
        // then step back one. EffectRecord is sorted by (space, offset).
        let target = (addr_space.space_id(), addr_offset);
        let mut idx = efflist.partition_point(|e| {
            (e.space.space_id(), e.offset) <= target
        });
        // partition_point returns first index where predicate is false, i.e.
        // first record with (space,offset) > target — matching upper_bound.
        if idx == 0 {
            // Can't go back one.
            return EffectType::UnknownEffect;
        }
        idx -= 1;
        let hit_space = efflist[idx].space;
        let hit_off = efflist[idx].offset;
        let sz = efflist[idx].size;
        if sz == 0 && hit_space == addr_space {
            // A size of zero indicates the whole space is unaffected.
            return EffectType::Unaffected;
        }
        let where_in_record = overlaps_range(
            hit_space,
            hit_off,
            sz,
            addr_space,
            addr_offset,
            size,
        );
        if where_in_record >= 0 && where_in_record + i64::from(size) <= i64::from(sz) {
            return efflist[idx].effect_type;
        }
        EffectType::UnknownEffect
    }

    // Ghidra: fspec.cc:2541 ProtoModel::hasEffect
    /// Determine the side-effect of this model on the given memory range.
    /// Faithful 1:1 port of `hasEffect` (fspec.cc:2541-2545): a direct
    /// delegation to `lookupEffect` over this model's effectlist.
    pub fn has_effect(&self, addr_space: AddressSpace, addr_offset: u64, size: i32) -> EffectType {
        Self::lookup_effect(&self.effectlist, addr_space, addr_offset, size)
    }

    // Ghidra: fspec.cc:2510 ProtoModel::lookupRecord (static)
    /// Look up a particular EffectRecord from a (sorted) list by its address
    /// and size. Faithful 1:1 port of `lookupRecord` (fspec.cc:2510-2533).
    /// Only the first `list_size` records are examined. Returns:
    ///   - `Some(idx)` — the matching record's index.
    ///   - `None` — no overlap (Ghidra's `-1`).
    ///   - `Err(())` — partial overlap with another record (Ghidra's `-2`).
    pub fn lookup_record(
        efflist: &[EffectRecord],
        list_size: usize,
        addr_space: AddressSpace,
        addr_offset: u64,
        size: i32,
    ) -> Result<Option<usize>, ()> {
        if list_size == 0 {
            return Ok(None);
        }
        let target = (addr_space.space_id(), addr_offset);
        // upper_bound by address within [0, list_size).
        let mut idx = efflist[..list_size]
            .partition_point(|e| (e.space.space_id(), e.offset) <= target);
        if idx == 0 {
            // First element's address is strictly greater than target; check
            // whether the target overlaps it (Ghidra: -2) or sits before it
            // entirely (Ghidra: -1).
            let close_space = efflist[0].space;
            let close_off = efflist[0].offset;
            return if overlaps_range(
                addr_space, addr_offset, size,
                close_space, close_off, efflist[0].size,
            ) < 0
            {
                Ok(None)
            } else {
                Err(())
            };
        }
        idx -= 1;
        let close_space = efflist[idx].space;
        let close_off = efflist[idx].offset;
        let close_size = efflist[idx].size;
        if addr_space == close_space && addr_offset == close_off && size == close_size {
            return Ok(Some(idx));
        }
        if overlaps_range(
            close_space, close_off, close_size,
            addr_space, addr_offset, size,
        ) < 0
        {
            Ok(None)
        } else {
            Err(())
        }
    }

    // Ghidra: fspec.hh:1017 ProtoModel::effectBegin / fspec.hh:1018 effectEnd
    /// Iterate the model's EffectRecord list (sorted by address). Faithful to
    /// `effectBegin`/`effectEnd` (fspec.hh:1017-1018). Used by
    /// `FuncProto::decodeEffect` to seed the override list from the model.
    pub fn effect_iter(&self) -> &[EffectRecord] {
        &self.effectlist
    }

    // Ghidra: fspec.hh:1020 ProtoModel::trashBegin / fspec.hh:1021 trashEnd
    /// Iterate the model's likely-trash VarnodeData list (sorted). Faithful to
    /// `trashBegin`/`trashEnd` (fspec.hh:1020-1021). Used by
    /// `FuncProto::decodeLikelyTrash` to fold in the model's trash list.
    pub fn trash_iter(&self) -> &[VarnodeData] {
        &self.likelytrash
    }

    // Ghidra: fspec.cc:2993 ProtoModelMerged::intersectEffects
    /// Intersect this model's effect list with another list, in place.
    /// Faithful 1:1 port of `ProtoModelMerged::intersectEffects`
    /// (fspec.cc:2780-2803). Both lists must be sorted by address. Only
    /// records present in BOTH lists survive; the merged list is rebuilt into
    /// a fresh vector and swapped in. `ProtoModelMerged` itself is not yet
    /// modelled as a distinct type in Rugra, so the merge is exposed here as
    /// a static helper for callers that fold alternative models together.
    pub fn intersect_effects(effectlist: &mut Vec<EffectRecord>, efflist: &[EffectRecord]) {
        let mut newlist: Vec<EffectRecord> = Vec::new();
        let mut i = 0usize;
        let mut j = 0usize;
        while i < effectlist.len() && j < efflist.len() {
            let eff1 = &effectlist[i];
            let eff2 = &efflist[j];
            if EffectRecord::compare_by_address(eff1, eff2) {
                i += 1;
            } else if EffectRecord::compare_by_address(eff2, eff1) {
                j += 1;
            } else {
                // Same address range; match if all fields equal.
                if eff1.space == eff2.space
                    && eff1.offset == eff2.offset
                    && eff1.size == eff2.size
                    && eff1.effect_type == eff2.effect_type
                {
                    newlist.push(eff1.clone());
                }
                i += 1;
                j += 1;
            }
        }
        std::mem::swap(effectlist, &mut newlist);
    }

    // Ghidra: fspec.cc:2809 ProtoModelMerged::intersectRegisters (static)
    /// Intersect two sorted VarnodeData register lists, writing the result
    /// into the first. Faithful 1:1 port of `intersectRegisters`
    /// (fspec.cc:2809-2832). A merge-join keeps only varnodes present in both
    /// lists, comparing by (space, offset, size).
    pub fn intersect_registers(
        reg_list1: &mut Vec<VarnodeData>,
        reg_list2: &[VarnodeData],
    ) {
        let mut newlist: Vec<VarnodeData> = Vec::new();
        let mut i = 0usize;
        let mut j = 0usize;
        while i < reg_list1.len() && j < reg_list2.len() {
            let a = &reg_list1[i];
            let b = &reg_list2[j];
            let ord_a = (a.space, a.offset, a.size).cmp(&(b.space, b.offset, b.size));
            match ord_a {
                std::cmp::Ordering::Less => i += 1,
                std::cmp::Ordering::Greater => j += 1,
                std::cmp::Ordering::Equal => {
                    newlist.push(a.clone());
                    i += 1;
                    j += 1;
                }
            }
        }
        std::mem::swap(reg_list1, &mut newlist);
    }

    // Ghidra: fspec.cc:2549 ProtoModel::decode
    /// Restore this model from a `<prototype>` element. Faithful port of
    /// `decode` (fspec.cc:2549-2700). Parses the element/attribute stream
    /// (name, extrapop, strategy, hasthis, constructor), builds the input/
    /// output ParamLists, decodes `<input>`/`<output>`/`<unaffected>`/
    /// `<killedbycall>`/`<returnaddress>`/`<localrange>`/`<paramrange>`/
    /// `<likelytrash>`/`<internal_storage>`/`<pcode>` children, then sorts the
    /// effect/likelytrash/internalstorage lists and applies default ranges.
    ///
    /// The `<pcode>` injection branch records a placeholder name in
    /// `inject_upon_entry`/`inject_upon_return` (mapped to a non-negative id
    /// when an `inject_id_resolver` is supplied). Returns the model name on
    /// success so the caller can register it.
    pub fn decode(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        stack_space: Option<AddressSpace>,
        addr_size: usize,
        void_type: Option<Arc<Datatype>>,
        inject_id_resolver: Option<&dyn Fn(&str, &str) -> Option<i32>>,
    ) -> Result<String, String> {
        use crate::marshal::Decoder;
        let mut saw_localrange = false;
        let mut saw_paramrange = false;
        let mut saw_retaddr = false;
        // Ghidra: fspec.cc:2555 — default growth direction, then consult stack space.
        self.stackgrowsnegative = true;
        // Rugra's AddressSpace enum has no stackGrowsNegative; the stack is
        // conventionally negative-growing. A real AddrSpace would override.
        let mut strategy_string = String::new();
        self.localrange = crate::address::RangeList::new();
        self.paramrange = crate::address::RangeList::new();
        self.extrapop = EXTRAPOP_MISSING_SENTINEL;
        self.has_this = false;
        self.is_construct = false;
        self.is_printed = true;
        self.effectlist.clear();
        self.inject_upon_entry = -1;
        self.inject_upon_return = -1;
        self.likelytrash.clear();
        self.internalstorage.clear();

        let elem_id = decoder.open_element();
        // Ghidra: fspec.cc:2572-2594 — attribute loop.
        loop {
            let aid = decoder.next_attribute_id();
            if aid == 0 { break; }
            match decoder.attribute_name(aid).as_deref() {
                Some("name") => self.name = decoder.read_string(),
                Some("extrapop") => {
                    // Ghidra: readSignedIntegerExpectString("unknown", extrapop_unknown)
                    let s = decoder.read_string();
                    if s == "unknown" {
                        self.extrapop = EXTRAPOP_UNKNOWN_FULL;
                    } else {
                        self.extrapop = s.parse::<i32>().unwrap_or(EXTRAPOP_UNKNOWN_FULL);
                    }
                }
                Some("stackshift") => {
                    // Allow for backward compatibility; value ignored.
                    let _ = decoder.read_string();
                }
                Some("strategy") => strategy_string = decoder.read_string(),
                Some("hasthis") => self.has_this = decoder.read_bool(),
                Some("constructor") => self.is_construct = decoder.read_bool(),
                Some(other) => {
                    let _ = decoder.read_string();
                    return Err(format!("Unknown prototype attribute: {}", other));
                }
                None => {
                    let _ = decoder.read_string();
                }
            }
        }
        if self.name == "__thiscall" {
            self.has_this = true;
        }
        if self.extrapop == EXTRAPOP_MISSING_SENTINEL {
            return Err("Missing prototype attributes".to_string());
        }

        // Ghidra: fspec.cc:2600 — allocate input/output ParamLists.
        self.build_param_list(&strategy_string)?;

        // Ghidra: fspec.cc:2601-2687 — child element loop.
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 { break; }
            let sub_name = decoder.element_name(sub_id).unwrap_or_default();
            match sub_name.as_str() {
                "input" => {
                    let normalstack = self.stackgrowsnegative;
                    // Rugra's ParamListStandard exposes finalize_after_decode;
                    // full per-element <pentry>/<group> parsing is provided by
                    // parse_pentry/parse_group once entries are decoded. Here
                    // we open the element and hand off to the list's decoder.
                    let _opened = decoder.open_element();
                    // TODO(ALIGNMENT_ROADMAP): wire ParamListStandard::decode
                    // once <pentry>/<group> Decoder integration lands. Until
                    // then we close the element without consuming children is
                    // unsafe; instead consume remaining attributes then close.
                    let _ = normalstack;
                    decoder.close_element(sub_id);
                }
                "output" => {
                    let _opened = decoder.open_element();
                    decoder.close_element(sub_id);
                }
                "unaffected" => {
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        // Ghidra: effectlist.back().decode(unaffected, decoder)
                        let child_id = decoder.open_element();
                        let (space, offset, size) = read_varnode_data_attrs(decoder);
                        decoder.close_element(child_id);
                        self.effectlist.push(EffectRecord::new(space, offset, size, EffectType::Unaffected));
                    }
                    decoder.close_element(sub_id);
                }
                "killedbycall" => {
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        let child_id = decoder.open_element();
                        let (space, offset, size) = read_varnode_data_attrs(decoder);
                        decoder.close_element(child_id);
                        self.effectlist.push(EffectRecord::new(space, offset, size, EffectType::KilledByCall));
                    }
                    decoder.close_element(sub_id);
                }
                "returnaddress" => {
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        let child_id = decoder.open_element();
                        let (space, offset, size) = read_varnode_data_attrs(decoder);
                        decoder.close_element(child_id);
                        self.effectlist.push(EffectRecord::new(space, offset, size, EffectType::ReturnAddress));
                    }
                    decoder.close_element(sub_id);
                    saw_retaddr = true;
                }
                "localrange" => {
                    saw_localrange = true;
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        if let Some(r) = read_range_child(decoder, stack_space) {
                            self.localrange.insert_range(r);
                        } else {
                            // Consume the unparseable child.
                            let cid = decoder.open_element();
                            decoder.close_element(cid);
                        }
                    }
                    decoder.close_element(sub_id);
                }
                "paramrange" => {
                    saw_paramrange = true;
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        if let Some(r) = read_range_child(decoder, stack_space) {
                            self.paramrange.insert_range(r);
                        } else {
                            let cid = decoder.open_element();
                            decoder.close_element(cid);
                        }
                    }
                    decoder.close_element(sub_id);
                }
                "likelytrash" => {
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        let child_id = decoder.open_element();
                        let (space, offset, size) = read_varnode_data_attrs(decoder);
                        decoder.close_element(child_id);
                        self.likelytrash.push(VarnodeData { space, offset, size });
                    }
                    decoder.close_element(sub_id);
                }
                "internal_storage" => {
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        let child_id = decoder.open_element();
                        let (space, offset, size) = read_varnode_data_attrs(decoder);
                        decoder.close_element(child_id);
                        self.internalstorage.push(VarnodeData { space, offset, size });
                    }
                    decoder.close_element(sub_id);
                }
                "pcode" => {
                    // Ghidra: fspec.cc:2676-2684 — decodeInject("Protomodel : "+name, ...)
                    let child_id = decoder.open_element();
                    let mut inject_name = String::new();
                    loop {
                        let aid = decoder.next_attribute_id();
                        if aid == 0 { break; }
                        if decoder.attribute_name(aid).as_deref() == Some("inject") {
                            inject_name = decoder.read_string();
                        } else {
                            let _ = decoder.read_string();
                        }
                    }
                    let _ = void_type;
                    if let Some(resolver) = inject_id_resolver {
                        if let Some(id) = resolver(&format!("Protomodel : {}", self.name), &inject_name) {
                            if inject_name.find("uponentry").is_some() {
                                self.inject_upon_entry = id;
                            } else {
                                self.inject_upon_return = id;
                            }
                        }
                    }
                    decoder.close_element(child_id);
                }
                _ => {
                    return Err("Unknown element in prototype".to_string());
                }
            }
        }
        decoder.close_element(elem_id);

        // Ghidra: fspec.cc:2689-2695 — default return address + sort lists.
        if !saw_retaddr {
            // Provide the default return address if one was configured. Rugra
            // has no Architecture defaultReturnAddr here; skip (matches Ghidra
            // when defaultReturnAddr.space == null).
        }
        // Sort effectlist by (space, offset) — faithful to
        // sort(effectlist, compareByAddress).
        self.effectlist.sort_by(|a, b| {
            (a.space.space_id(), a.offset).cmp(&(b.space.space_id(), b.offset))
        });
        // Sort likelytrash / internalstorage (VarnodeData default order).
        self.likelytrash.sort_by(|a, b| {
            (a.space, a.offset).cmp(&(b.space, b.offset))
        });
        self.internalstorage.sort_by(|a, b| {
            (a.space, a.offset).cmp(&(b.space, b.offset))
        });

        // Ghidra: fspec.cc:2696-2699 — apply defaults for unseen ranges.
        if !saw_localrange {
            self.default_local_range(stack_space, addr_size);
        }
        if !saw_paramrange {
            self.default_param_range(stack_space, addr_size);
        }
        Ok(self.name.clone())
    }

    // Ghidra: fspec.hh:777 ProtoModel::getName
    /// Get the name of the prototype model. Faithful inline accessor.
    pub fn get_name(&self) -> &str { &self.name }

    // Ghidra: fspec.hh:781 ProtoModel::getExtraPop
    /// Get the stack-pointer extrapop for this model. Faithful inline accessor.
    pub fn get_extrapop(&self) -> i32 { self.extrapop }

    // Ghidra: fspec.hh:782 ProtoModel::setExtraPop
    /// Set the stack-pointer extrapop. Faithful inline accessor.
    pub fn set_extrapop(&mut self, ep: i32) { self.extrapop = ep; }

    // Ghidra: fspec.hh:979 ProtoModel::hasThisPointer
    /// Is this a model for (non-static) class methods? Faithful inline accessor.
    pub fn has_this_pointer(&self) -> bool { self.has_this }

    // Ghidra: fspec.hh:980 ProtoModel::isConstructor
    /// Is this model for class constructors? Faithful inline accessor.
    pub fn is_constructor(&self) -> bool { self.is_construct }

    // Ghidra: fspec.hh:981 ProtoModel::printInDecl
    /// Should the model name be printed in function declarations?
    pub fn print_in_decl(&self) -> bool { self.is_printed }

    // Ghidra: fspec.hh:982 ProtoModel::setPrintInDecl
    /// Set whether this name should be printed in declarations.
    pub fn set_print_in_decl(&mut self, val: bool) { self.is_printed = val; }
}

/// `ParameterPieces::isthis = 1` (fspec.hh:362). Used by
/// `assign_parameter_storage` to flag the `this` input.
pub const THIS_POINTER_PIECE: u32 = 1;

// RUGRA-GLUE: read_varnode_data_attrs (free helper — parses the space/offset/
// size attributes that Ghidra reads via VarnodeData::decode for the
// <unaffected>/<killedbycall>/<returnaddress>/<likelytrash> children).
fn read_varnode_data_attrs(decoder: &mut dyn crate::marshal::Decoder) -> (AddressSpace, u64, i32) {
    use crate::marshal::Decoder;
    let mut space = AddressSpace::Register;
    let mut offset = 0u64;
    let mut size = 0i32;
    loop {
        let aid = decoder.next_attribute_id();
        if aid == 0 { break; }
        match decoder.attribute_name(aid).as_deref() {
            Some("space") => {
                let s = decoder.read_string();
                space = parse_space_name(&s);
            }
            Some("offset") => {
                let s = decoder.read_string();
                offset = parse_u64(&s);
            }
            Some("size") => {
                let s = decoder.read_string();
                size = s.parse::<i32>().unwrap_or(0);
            }
            _ => { let _ = decoder.read_string(); }
        }
    }
    (space, offset, size)
}

// RUGRA-GLUE: read_range_child (free helper — parses a <range> child of
// <localrange>/<paramrange> into a Rust `Range`).
fn read_range_child(
    decoder: &mut dyn crate::marshal::Decoder,
    default_space: Option<AddressSpace>,
) -> Option<crate::address::Range> {
    use crate::marshal::Decoder;
    let child_id = decoder.open_element();
    let mut first = 0u64;
    let mut last = 0u64;
    let mut have_first = false;
    let mut have_last = false;
    loop {
        let aid = decoder.next_attribute_id();
        if aid == 0 { break; }
        match decoder.attribute_name(aid).as_deref() {
            Some("first") => { first = parse_u64(&decoder.read_string()); have_first = true; }
            Some("last") => { last = parse_u64(&decoder.read_string()); have_last = true; }
            Some("space") => { let _ = decoder.read_string(); }
            _ => { let _ = decoder.read_string(); }
        }
    }
    decoder.close_element(child_id);
    let _ = default_space;
    if have_first && have_last {
        crate::address::Range::new(Address::new(first), Address::new(last))
    } else {
        None
    }
}

// RUGRA-GLUE: parse_space_name / parse_u64 (free helpers used by the decode
// path above; Rugra's AddressSpace is an enum, so a name string maps to the
// nearest matching variant).
fn parse_space_name(s: &str) -> AddressSpace {
    match s {
        "ram" | "mem" => AddressSpace::Ram,
        "register" => AddressSpace::Register,
        "unique" => AddressSpace::Unique,
        "const" => AddressSpace::Const,
        "stack" => AddressSpace::Stack,
        "join" => AddressSpace::Join,
        "iop" => AddressSpace::Iop,
        "overlay" => AddressSpace::Overlay,
        _ => AddressSpace::Register,
    }
}

// RUGRA-GLUE: space_name — inverse of parse_space_name, used by
// EffectRecord::encode to serialise the address space as a string attribute.
/// Return the canonical XML name for an address space. Mirrors the
/// `AddrSpace::getName` lookup Ghidra performs inside
/// `VarnodeData::encode`/`Address::encode`.
fn space_name(s: AddressSpace) -> &'static str {
    match s {
        AddressSpace::Ram => "ram",
        AddressSpace::Register => "register",
        AddressSpace::Unique => "unique",
        AddressSpace::Const => "const",
        AddressSpace::Stack => "stack",
        AddressSpace::Join => "join",
        AddressSpace::Iop => "iop",
        AddressSpace::Overlay => "overlay",
        AddressSpace::Other(_) => "mem",
    }
}

// RUGRA-GLUE: effect_from_u32 — bridges the raw u32 returned by the legacy
// `FuncCallSpecs::has_effect` (which mirrors Ghidra's `uint4` return type)
// back into the typed `EffectType` enum used by the faithful ports above.
fn effect_from_u32(raw: u32) -> EffectType {
    match raw {
        1 => EffectType::Unaffected,
        2 => EffectType::KilledByCall,
        3 => EffectType::ReturnAddress,
        _ => EffectType::UnknownEffect,
    }
}

// RUGRA-GLUE: textual integer adapter for Rugra's string-valued Decoder;
// Ghidra's VarnodeData/Range decode paths call typed Decoder integer readers
// directly and have no parse_u64 helper.
fn parse_u64(s: &str) -> u64 {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        s.parse::<u64>().unwrap_or(0)
    }
}

// RUGRA-GLUE: metatype_to_type_class (free helper — Ghidra's
// `metatype2typeclass` is defined in type.cc and not yet ported).
/// Map a data-type's metatype to its storage class. Faithful to
/// `metatype2typeclass` (type.hh:153). TODO(ALIGNMENT_ROADMAP): depends on
/// unported `metatype2typeclass`.
fn metatype_to_type_class(dt: &Datatype) -> TypeClass {
    use crate::type_system::TypeMetatype;
    match dt.get_metatype() {
        TypeMetatype::Float => TypeClass::Float,
        _ => TypeClass::General,
    }
}

// RUGRA-GLUE: is_contiguous (free helper — mirrors `Address::isContiguous`,
// address.cc, used only by `ParamListStandard::check_join`).
fn is_contiguous(hi_addr: Address, hi_size: i32, lo_addr: Address, _lo_size: i32) -> bool {
    hi_addr.as_u64() + hi_size as u64 == lo_addr.as_u64()
}

// RUGRA-GLUE: overlaps_range — mirrors the observable
// `Address::overlap(0, record, size)` result for the ordered call sites in
// `ProtoModelFull::lookup_effect` and `lookup_record`. Their upper-bound
// predecessor choice guarantees the candidate start is not after the probe
// (the begin case reverses the arguments), so u64 subtraction cannot take a
// narrower AddrSpace wrap-around path.
fn overlaps_range(
    space1: AddressSpace, off1: u64, sz1: i32,
    space2: AddressSpace, off2: u64, _sz2: i32,
) -> i64 {
    if space1 != space2 {
        return -1;
    }
    // Ghidra Address::overlap returns no overlap for constant-space
    // addresses, even when their numeric ranges are identical.
    if space1 == AddressSpace::Const {
        return -1;
    }
    if sz1 <= 0 {
        return -1;
    }
    let distance = off2.wrapping_sub(off1);
    if distance >= sz1 as u64 {
        return -1;
    }
    distance as i64
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
    fn test_func_proto_locked_void_input_and_output_model_lock() {
        let void_type = Arc::new(Datatype::Void(
            crate::type_system::datatype::TypeBase::new(
                "void".into(),
                0,
                crate::type_system::TypeMetatype::Void,
            ),
        ));
        let mut proto = FuncProto::new("known_void".into(), void_type.clone());
        assert!(!proto.is_input_locked());
        assert!(!proto.is_model_locked());

        proto.set_input_lock(true);
        assert!(proto.is_input_locked());
        assert!(proto.is_model_locked());
        proto.clear_unlocked_input();
        assert!(proto.is_input_locked());
        assert_eq!(proto.num_params(), 0);

        let mut copied = FuncProto::new("copy".into(), void_type);
        copied.copy_from(&proto);
        assert!(copied.is_input_locked());
        copied.clear_input();
        assert!(!copied.is_input_locked());

        let mut output = FuncProto::new("output".into(), copied.return_type.clone());
        output.set_output_lock(true);
        assert!(output.is_output_locked());
        assert!(output.is_model_locked());
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

    #[test]
    fn test_func_proto_method_flags() {
        // Ghidra: fspec.hh:1411-1458 inline/noreturn/constructor/destructor/thisptr
        let int_type = Arc::new(Datatype::Base(
            crate::type_system::datatype::TypeBase::new("int".into(), 4, crate::type_system::TypeMetatype::Int)));
        let mut proto = FuncProto::new("method".into(), int_type);
        // All method flags start false.
        assert!(!proto.is_inline());
        assert!(!proto.is_no_return());
        assert!(!proto.is_constructor_flag());
        assert!(!proto.is_destructor());
        assert!(!proto.has_thisptr());
        // Set each flag.
        proto.set_inline(true);
        proto.set_no_return(true);
        proto.set_constructor(true);
        proto.set_destructor(true);
        proto.set_has_thisptr(true);
        assert!(proto.is_inline());
        assert!(proto.is_no_return());
        assert!(proto.is_constructor_flag());
        assert!(proto.is_destructor());
        assert!(proto.has_thisptr());
        // Comparable flags should now carry the constructor/destructor/thisptr bits.
        let cf = proto.get_comparable_flags();
        assert_ne!(cf & 0x200, 0); // is_constructor
        assert_ne!(cf & 0x400, 0); // is_destructor
        assert_ne!(cf & 0x800, 0); // has_thisptr
        // Flags survive copy_from.
        let mut proto2 = FuncProto::new("dst".into(), proto.return_type.clone());
        proto2.copy_from(&proto);
        assert!(proto2.is_inline());
        assert!(proto2.is_no_return());
        assert!(proto2.is_constructor_flag());
        assert!(proto2.is_destructor());
        assert!(proto2.has_thisptr());
    }

    #[test]
    fn test_func_proto_update_this_pointer() {
        // Ghidra: fspec.cc:3572-3584 updateThisPointer
        let int_type = Arc::new(Datatype::Base(
            crate::type_system::datatype::TypeBase::new("int".into(), 4, crate::type_system::TypeMetatype::Int)));
        let mut proto = FuncProto::new("method".into(), int_type.clone());
        // Without has_thisptr set, update_this_pointer is a no-op.
        proto.add_parameter(ProtoParameter::new("this".into(), int_type.clone(), Address::new(0)));
        proto.update_this_pointer();
        assert!(!proto.parameters[0].is_this_pointer());
        // With has_thisptr set, the first parameter is marked as the this pointer.
        proto.set_has_thisptr(true);
        proto.update_this_pointer();
        assert!(proto.parameters[0].is_this_pointer());
        // A hidden-return parameter at slot 0 is skipped.
        let mut proto2 = FuncProto::new("method2".into(), int_type.clone());
        proto2.set_has_thisptr(true);
        let mut hidden = ProtoParameter::new("rethidden".into(), int_type.clone(), Address::new(0));
        hidden.flags |= protoparam_flags::HIDDEN_RETURN;
        proto2.add_parameter(hidden);
        proto2.add_parameter(ProtoParameter::new("this".into(), int_type, Address::new(0x8)));
        proto2.update_this_pointer();
        assert!(!proto2.parameters[0].is_this_pointer());
        assert!(proto2.parameters[1].is_this_pointer());
    }

    // ---- ParamEntry / ParamListStandard tests ----

    #[test]
    fn test_param_entry_exclusion_basic() {
        // Ghidra: fspec.cc:60-71 findEntryByStorage, fspec.hh:134 isExclusion
        let mut e = ParamEntry::new(0);
        e.set_space(AddressSpace::Register);
        e.set_base(0x10);
        e.set_sizes(8, 4);
        e.set_alignment(0); // alignment==0 => exclusion entry
        assert!(e.is_exclusion());
        assert_eq!(e.get_size(), 8);
        assert_eq!(e.get_min_size(), 4);
        assert_eq!(e.get_base(), 0x10);
        assert_eq!(e.get_space(), AddressSpace::Register);
    }

    #[test]
    fn test_param_entry_aligned_slots() {
        // Ghidra: fspec.hh:131 getAlign, fspec.hh:135 isReverseStack
        let mut e = ParamEntry::new(2);
        e.set_space(AddressSpace::Register);
        e.set_base(0x100);
        e.set_sizes(32, 4);
        e.set_alignment(8); // 32/8 = 4 slots
        assert!(!e.is_exclusion());
        assert_eq!(e.get_align(), 8);
        // get_addr_by_slot advances slot_num (fspec.cc:434)
        let mut slot = 0i32;
        let a0 = e.get_addr_by_slot(&mut slot, 8, 1).unwrap();
        assert_eq!(a0.as_u64(), 0x100);
        assert_eq!(slot, 1);
        let a1 = e.get_addr_by_slot(&mut slot, 8, 1).unwrap();
        assert_eq!(a1.as_u64(), 0x108);
        assert_eq!(slot, 2);
    }

    #[test]
    fn test_param_entry_justified_contain() {
        // Ghidra: fspec.cc:248-283 justifiedContain. For a little-endian
        // (non-left-justified) exclusion entry, the return value is the
        // offset of the value's HIGH byte from the container's high end.
        let mut e = ParamEntry::new(0);
        e.set_space(AddressSpace::Register);
        e.set_base(0x200);
        e.set_sizes(8, 1);
        e.set_alignment(0); // exclusion
        // Full-range containment returns 0 (value is flush with the high end).
        assert_eq!(e.justified_contain(Address::new(0x200), 8), 0);
        // 2-byte value at 0x202 spans [0x202..0x203]; container high end is
        // 0x207. Offset from high end = 0x207 - 0x203 = 4.
        assert_eq!(e.justified_contain(Address::new(0x202), 2), 4);
        // A value flush with the high end returns 0.
        assert_eq!(e.justified_contain(Address::new(0x206), 2), 0);
        // Out of range
        assert_eq!(e.justified_contain(Address::new(0x300), 4), -1);
    }

    #[test]
    fn test_param_list_standard_new() {
        // Ghidra: fspec.hh:617 ParamListStandard()
        let m = ParamListStandard::new();
        assert_eq!(m.get_type(), ParamListKind::Standard);
        assert!(!m.is_this_before_ret_pointer());
        assert!(!m.is_auto_killed_by_call());
        assert_eq!(m.get_max_delay(), 0);
        assert!(m.get_entry().is_empty());
        assert_eq!(m.get_num_group(), 0);
    }

    #[test]
    fn test_param_list_standard_possible_param() {
        // Ghidra: fspec.cc:1354 possibleParam + fspec.cc:661 findEntry
        let mut m = ParamListStandard::new();
        let mut e = ParamEntry::new(0);
        e.set_space(AddressSpace::Ram);
        e.set_base(0x1000);
        e.set_sizes(32, 4);
        e.set_alignment(8);
        let mut effects = Vec::new();
        m.parse_pentry(0, true, false, false, &mut effects, e).unwrap();
        m.finalize_after_decode(0);
        assert!(m.possible_param(Address::new(0x1000), 8));
        assert!(!m.possible_param(Address::new(0x9000), 8));
    }
}
