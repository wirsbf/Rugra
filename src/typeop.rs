//! Type operations for P-code
//!
//! Corresponds to Ghidra's `typeop.hh`

use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::printlanguage::PrintLanguage;
use crate::type_system::{Datatype, TypeMetatype};
// use crate::varnode::Varnode;
// use std::sync::{Arc, RwLock};
use std::sync::Arc;

// Forward declarations/Stubs for related modules
pub mod stubs {
    #[derive(Debug)]
    pub struct OpBehavior;
    #[derive(Debug)]
    pub struct Encoder;
}

// use stubs::*;

/// Flags for TypeOp properties (from Ghidra's TypeOp class)
pub mod typeop_flags {
    pub const INHERITS_SIGN: u32 = 1 << 0;
    pub const INHERITS_SIGN_ZERO: u32 = 1 << 1;
    pub const SHIFT_OP: u32 = 1 << 2;
    pub const ARITHMETIC_OP: u32 = 1 << 3;
    pub const LOGICAL_OP: u32 = 1 << 4;
    pub const FLOATINGPOINT_OP: u32 = 1 << 5;
}

/// Core trait representing a P-code operation type
///
/// Corresponds to Ghidra's `TypeOp` class
pub trait TypeOp {
    /// Get the opcode for this operation
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode;

    /// Get the name of the operation
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str;

    /// Get properties/flags for this operation
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32;

    /// Print the operation in a raw textual format
    // Ghidra: typeop.hh:176 TypeOp::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String;

    /// Push the operation to a print language emitter
    // Ghidra: typeop.hh:170 TypeOp::push
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        // Default implementation for basic ops
        match self.get_opcode() {
            OpCode::CPUI_COPY => lng.op_copy(op),
            OpCode::CPUI_LOAD => lng.op_load(op),
            OpCode::CPUI_STORE => lng.op_store(op),
            OpCode::CPUI_MULTIEQUAL => lng.op_multiequal(op),
            OpCode::CPUI_INDIRECT => lng.op_indirect(op),
            OpCode::CPUI_CALL => lng.op_call(op),
            OpCode::CPUI_RETURN => lng.op_return(op),
            _ => {
                if (self.get_flags()
                    & (typeop_flags::ARITHMETIC_OP
                        | typeop_flags::LOGICAL_OP
                        | typeop_flags::SHIFT_OP))
                    != 0
                {
                    lng.op_binary(op);
                }
            }
        }
    }

    // Metadata methods
    /// Get the minimal (or suggested) data-type of an output to this op-code
    // Ghidra: typeop.hh:149 TypeOp::getOutputLocal
    fn get_output_local(&self, _op: &PcodeOp) -> Option<Arc<Datatype>> {
        None
    }

    /// Get the minimal (or suggested) data-type of an input to this op-code
    // Ghidra: typeop.hh:152 TypeOp::getInputLocal
    fn get_input_local(&self, _op: &PcodeOp, _slot: usize) -> Option<Arc<Datatype>> {
        None
    }

    /// Find the data-type of the output that would be assigned by a compiler.
    ///
    /// Corresponds to Ghidra's `TypeOp::getOutputToken(op, castStrategy)`.
    /// The default returns `None`, meaning the output uses its local type
    /// (`outputTypeLocal`) with no token-level override.
    // Ghidra: typeop.hh:155 TypeOp::getOutputToken
    fn get_output_token(&self, _op: &PcodeOp) -> Option<Arc<Datatype>> {
        None
    }

    /// Find the data-type of the input to a specific PcodeOp (for casting).
    ///
    /// Corresponds to Ghidra's `TypeOp::getInputCast(op, slot, castStrategy)`.
    /// A `None` result indicates the input does not need a cast (the default).
    // Ghidra: typeop.hh:158 TypeOp::getInputCast
    fn get_input_cast(&self, _op: &PcodeOp, _slot: usize) -> Option<Arc<Datatype>> {
        None
    }

    /// Propagate an incoming data-type across a specific PcodeOp.
    ///
    /// Corresponds to Ghidra's `TypeOp::propagateType(alttype, op, invn, outvn,
    /// inslot, outslot)`. `alt_type` is the incoming type; `inslot`/`outslot`
    /// are -1 for the output varnode and >=0 for an input slot. Returns the
    /// outgoing data-type or `None` to indicate no propagation (the default).
    // Ghidra: typeop.hh:161 TypeOp::propagateType
    fn propagate_type(
        &self,
        _alt_type: &Arc<Datatype>,
        _op: &PcodeOp,
        _inslot: i32,
        _outslot: i32,
    ) -> Option<Arc<Datatype>> {
        None
    }

    /// Helper: the metatype assigned to an op's output for printing/token
    /// purposes. Mirrors Ghidra's per-opcode `metaout` metatype. Default
    /// `None` lets the caller fall back to the output varnode's own type.
    // RUGRA-GLUE: Rust trait accessor for the per-subclass `metaout` field
    //   cached by Ghidra's TypeOpBinary/TypeOpUnary/TypeOpFunc constructors
    //   (typeop.hh:205 / :222 / :239). Ghidra has no virtual getOutputMetatype
    //   method; the field is read directly by getOutputLocal (typeop.cc:326
    //   etc.), so Rugra exposes it via this helper.
    fn get_output_metatype(&self) -> Option<TypeMetatype> {
        None
    }
}

// --- Base implementations for Categories ---

/// Base behavior for binary operations
pub struct TypeOpBinary {
    pub opcode: OpCode,
    pub name: String,
    pub flags: u32,
}

impl TypeOp for TypeOpBinary {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode (inlined accessor; TypeOpBinary inherits)
    fn get_opcode(&self) -> OpCode {
        self.opcode
    }
    // Ghidra: typeop.hh:70 TypeOp::getName (inlined accessor; TypeOpBinary inherits)
    fn get_name(&self) -> &str {
        &self.name
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags (inlined accessor; TypeOpBinary inherits)
    fn get_flags(&self) -> u32 {
        self.flags
    }

    // Ghidra: typeop.cc:335 TypeOpBinary::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = {} {} {}", out, in0, self.get_name(), in1)
    }

    // RUGRA-GLUE: generic binary push dispatch; Ghidra's TypeOpBinary does not
    //   override push (pure virtual at typeop.hh:170), each concrete subclass
    //   provides its own `lng->opXxx(op)`.
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_binary(op);
    }
}

/// Base behavior for unary operations
pub struct TypeOpUnary {
    pub opcode: OpCode,
    pub name: String,
    pub flags: u32,
}

impl TypeOp for TypeOpUnary {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode (inlined accessor; TypeOpUnary inherits)
    fn get_opcode(&self) -> OpCode {
        self.opcode
    }
    // Ghidra: typeop.hh:70 TypeOp::getName (inlined accessor; TypeOpUnary inherits)
    fn get_name(&self) -> &str {
        &self.name
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags (inlined accessor; TypeOpUnary inherits)
    fn get_flags(&self) -> u32 {
        self.flags
    }

    // Ghidra: typeop.cc:357 TypeOpUnary::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = {} {}", out, self.get_name(), in0)
    }

    // RUGRA-GLUE: generic unary push dispatch; Ghidra's TypeOpUnary does not
    //   override push (pure virtual at typeop.hh:170), each concrete subclass
    //   provides its own `lng->opXxx(op)`.
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_unary(op);
    }
}

// --- Concrete Opcode Implementations ---

macro_rules! binary_op {
    ($struct_name:ident, $opcode:ident, $name:expr, $flags:expr, $symbol:expr) => {
        pub struct $struct_name;
        impl TypeOp for $struct_name {
            // Ghidra: typeop.hh:71 TypeOp::getOpcode
            fn get_opcode(&self) -> OpCode {
                OpCode::$opcode
            }
            // Ghidra: typeop.hh:70 TypeOp::getName
            fn get_name(&self) -> &str {
                $name
            }
            // Ghidra: typeop.hh:72 TypeOp::getFlags
            fn get_flags(&self) -> u32 {
                $flags
            }
            // Ghidra: typeop.cc:335 TypeOpBinary::printRaw
            fn print_raw(&self, op: &PcodeOp) -> String {
                let out = op
                    .get_out()
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                let in0 = op
                    .get_in(0)
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                let in1 = op
                    .get_in(1)
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                format!("{} = {} {} {}", out, in0, $symbol, in1)
            }
            // RUGRA-GLUE: macro-generated generic binary push; per-subclass push
            //   is inlined in typeop.hh (e.g. TypeOpIntSub::push at :451).
            fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
                lng.op_binary(op);
            }
            // Ghidra: typeop.cc:323 TypeOpBinary::getOutputLocal
            fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
                op.get_in(0).and_then(|v| v.read().unwrap().v_type.clone())
            }
            // Ghidra: typeop.cc:329 TypeOpBinary::getInputLocal
            fn get_input_local(&self, op: &PcodeOp, _slot: usize) -> Option<Arc<Datatype>> {
                op.get_out().and_then(|v| v.read().unwrap().v_type.clone())
            }
        }
    };
}

macro_rules! unary_op {
    ($struct_name:ident, $opcode:ident, $name:expr, $flags:expr, $symbol:expr) => {
        pub struct $struct_name;
        impl TypeOp for $struct_name {
            // Ghidra: typeop.hh:71 TypeOp::getOpcode
            fn get_opcode(&self) -> OpCode {
                OpCode::$opcode
            }
            // Ghidra: typeop.hh:70 TypeOp::getName
            fn get_name(&self) -> &str {
                $name
            }
            // Ghidra: typeop.hh:72 TypeOp::getFlags
            fn get_flags(&self) -> u32 {
                $flags
            }
            // Ghidra: typeop.cc:357 TypeOpUnary::printRaw
            fn print_raw(&self, op: &PcodeOp) -> String {
                let out = op
                    .get_out()
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                let in0 = op
                    .get_in(0)
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                format!("{} = {}{}", out, $symbol, in0)
            }
            // RUGRA-GLUE: macro-generated generic unary push; per-subclass push
            //   is inlined in typeop.hh (e.g. TypeOpIntNegate::push at :491).
            fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
                lng.op_unary(op);
            }
            // Ghidra: typeop.cc:345 TypeOpUnary::getOutputLocal
            fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
                op.get_in(0).and_then(|v| v.read().unwrap().v_type.clone())
            }
            // Ghidra: typeop.cc:351 TypeOpUnary::getInputLocal
            fn get_input_local(&self, op: &PcodeOp, _slot: usize) -> Option<Arc<Datatype>> {
                op.get_out().and_then(|v| v.read().unwrap().v_type.clone())
            }
        }
    };
}

macro_rules! functional_unary_op {
    ($struct_name:ident, $opcode:ident, $name:expr, $flags:expr, $func:expr) => {
        pub struct $struct_name;
        impl TypeOp for $struct_name {
            // Ghidra: typeop.hh:71 TypeOp::getOpcode
            fn get_opcode(&self) -> OpCode {
                OpCode::$opcode
            }
            // Ghidra: typeop.hh:70 TypeOp::getName
            fn get_name(&self) -> &str {
                $name
            }
            // Ghidra: typeop.hh:72 TypeOp::getFlags
            fn get_flags(&self) -> u32 {
                $flags
            }
            // Ghidra: typeop.cc:377 TypeOpFunc::printRaw
            fn print_raw(&self, op: &PcodeOp) -> String {
                let out = op
                    .get_out()
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                let in0 = op
                    .get_in(0)
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                format!("{} = {}({})", out, $func, in0)
            }
            // RUGRA-GLUE: macro-generated generic functional push; per-subclass
            //   push is inlined in typeop.hh (e.g. TypeOpIntCarry::push at :459).
            fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
                lng.op_unary(op);
            }
            // Ghidra: typeop.cc:365 TypeOpFunc::getOutputLocal
            fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
                op.get_in(0).and_then(|v| v.read().unwrap().v_type.clone())
            }
            // Ghidra: typeop.cc:371 TypeOpFunc::getInputLocal
            fn get_input_local(&self, op: &PcodeOp, _slot: usize) -> Option<Arc<Datatype>> {
                op.get_out().and_then(|v| v.read().unwrap().v_type.clone())
            }
        }
    };
}

macro_rules! functional_binary_op {
    ($struct_name:ident, $opcode:ident, $name:expr, $flags:expr, $func:expr) => {
        pub struct $struct_name;
        impl TypeOp for $struct_name {
            // Ghidra: typeop.hh:71 TypeOp::getOpcode
            fn get_opcode(&self) -> OpCode {
                OpCode::$opcode
            }
            // Ghidra: typeop.hh:70 TypeOp::getName
            fn get_name(&self) -> &str {
                $name
            }
            // Ghidra: typeop.hh:72 TypeOp::getFlags
            fn get_flags(&self) -> u32 {
                $flags
            }
            // Ghidra: typeop.cc:377 TypeOpFunc::printRaw
            fn print_raw(&self, op: &PcodeOp) -> String {
                let out = op
                    .get_out()
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                let in0 = op
                    .get_in(0)
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                let in1 = op
                    .get_in(1)
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                format!("{} = {}({}, {})", out, $func, in0, in1)
            }
            // RUGRA-GLUE: macro-generated generic functional push; per-subclass
            //   push is inlined in typeop.hh (e.g. TypeOpIntScarry::push at :467).
            fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
                lng.op_binary(op);
            }
            // Ghidra: typeop.cc:365 TypeOpFunc::getOutputLocal
            fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
                op.get_in(0).and_then(|v| v.read().unwrap().v_type.clone())
            }
            // Ghidra: typeop.cc:371 TypeOpFunc::getInputLocal
            fn get_input_local(&self, op: &PcodeOp, _slot: usize) -> Option<Arc<Datatype>> {
                op.get_out().and_then(|v| v.read().unwrap().v_type.clone())
            }
        }
    };
}

/// CPUI_COPY implementation
pub struct TypeOpCopy;
impl TypeOp for TypeOpCopy {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_COPY
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "COPY"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }

    // Ghidra: typeop.cc:425 TypeOpCopy::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = {}", out, in0)
    }

    // Ghidra: typeop.hh:261 TypeOpCopy::push
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_copy(op);
    }

    // Ghidra: typeop.hh:149 TypeOp::getOutputLocal (base; Copy does not override)
    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        op.get_in(0)
            .and_then(|vn| vn.read().unwrap().v_type.clone())
    }

    // Ghidra: typeop.hh:152 TypeOp::getInputLocal (base; Copy does not override)
    fn get_input_local(&self, op: &PcodeOp, _slot: usize) -> Option<Arc<Datatype>> {
        op.get_out()
            .and_then(|vn| vn.read().unwrap().v_type.clone())
    }

    /// The output token of a COPY is just the high type of its input.
    /// Faithful to `TypeOpCopy::getOutputToken` (typeop.cc:405-409).
    // Ghidra: typeop.cc:405 TypeOpCopy::getOutputToken
    fn get_output_token(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        op.get_in(0)
            .and_then(|vn| vn.read().unwrap().v_type.clone())
    }

    /// COPY is transparent: a type propagates across it in either direction
    /// (input<->output). One of the slots must be the output (-1). Spacebase
    /// inputs are rewrapped as a pointer to an unknown base type.
    /// Faithful to `TypeOpCopy::propagateType` (typeop.cc:411-423).
    // Ghidra: typeop.cc:411 TypeOpCopy::propagateType
    fn propagate_type(
        &self,
        alt_type: &Arc<Datatype>,
        op: &PcodeOp,
        inslot: i32,
        outslot: i32,
    ) -> Option<Arc<Datatype>> {
        if inslot != -1 && outslot != -1 {
            return None; // Must propagate input <-> output
        }
        // If the source varnode is a spacebase, rewrap as ptr-to-unknown.
        let src_slot = if inslot == -1 { outslot } else { inslot };
        if src_slot >= 0 {
            if let Some(vn) = op.get_in(src_slot as usize) {
                if vn.read().unwrap().is_spacebase() {
                    return Some(propagate_to_pointer(&Arc::new(Datatype::Base(
                        crate::type_system::TypeBase::new(
                            "unknown".to_string(),
                            1,
                            TypeMetatype::Unknown,
                        ),
                    ))));
                }
            }
        }
        Some(alt_type.clone())
    }
}

/// CPUI_LOAD implementation
pub struct TypeOpLoad;
impl TypeOp for TypeOpLoad {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_LOAD
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "LOAD"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }

    // Ghidra: typeop.cc:502 TypeOpLoad::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string()); // Space
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string()); // Pointer
        format!("{} = *({}){}", out, in0, in1)
    }

    // Ghidra: typeop.hh:274 TypeOpLoad::push
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_load(op);
    }

    // Ghidra: typeop.hh:149 TypeOp::getOutputLocal (base; Load does not override)
    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        // Output type should be the base type of the pointer input (inrefs[1])
        op.get_in(1).and_then(|vn| {
            let vn_read = vn.read().unwrap();
            if let Some(dt) = &vn_read.v_type {
                if let Datatype::Pointer(ptr) = dt.as_ref() {
                    return Some(ptr.ptr_to.clone());
                }
            }
            None
        })
    }

    /// The output token dereferences the pointer input: if in[1] is a pointer
    /// whose pointee matches the output size, the token is the pointee;
    /// otherwise fall back to the output varnode's high type.
    /// Faithful to `TypeOpLoad::getOutputToken` (typeop.cc:472-485).
    // Ghidra: typeop.cc:472 TypeOpLoad::getOutputToken
    fn get_output_token(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        let out_size = op.get_out().map(|v| v.read().unwrap().get_size());
        if let Some(vn) = op.get_in(1) {
            let vn_read = vn.read().unwrap();
            if let Some(Datatype::Pointer(ptr)) = vn_read.v_type.as_ref().map(|d| d.as_ref()) {
                if Some(ptr.ptr_to.get_size()) == out_size {
                    return Some(ptr.ptr_to.clone());
                }
            }
        }
        op.get_out()
            .and_then(|vn| vn.read().unwrap().v_type.clone())
    }

    /// For LOAD, a type propagates between the value (output/slot 2) and the
    /// pointer (input 1), never along the space constant (slot 0). Output-to-
    /// input rewraps the type as a pointer (propagateToPointer); input-to-
    /// output unwraps it (propagateFromPointer).
    /// Faithful to `TypeOpLoad::propagateType` (typeop.cc:487-500).
    // Ghidra: typeop.cc:487 TypeOpLoad::propagateType
    fn propagate_type(
        &self,
        alt_type: &Arc<Datatype>,
        op: &PcodeOp,
        inslot: i32,
        outslot: i32,
    ) -> Option<Arc<Datatype>> {
        if inslot == 0 || outslot == 0 {
            return None; // Don't propagate along the space-constant edge
        }
        // Spacebase pointers do not propagate.
        let src_slot = if inslot == -1 { outslot } else { inslot };
        if src_slot >= 0 {
            if let Some(vn) = op.get_in(src_slot as usize) {
                if vn.read().unwrap().is_spacebase() {
                    return None;
                }
            }
        }
        if inslot == -1 {
            // output -> input : wrap value type as a pointer (propagateToPointer)
            Some(propagate_to_pointer(alt_type))
        } else {
            // input -> output : unwrap pointer to its pointee (propagateFromPointer)
            propagate_from_pointer(alt_type)
        }
    }
}

/// CPUI_STORE implementation
pub struct TypeOpStore;
impl TypeOp for TypeOpStore {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_STORE
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "STORE"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }

    // Ghidra: typeop.cc:572 TypeOpStore::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string()); // Space
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string()); // Pointer
        let in2 = op
            .get_in(2)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string()); // Value
        format!("*({}){} = {}", in0, in1, in2)
    }

    // Ghidra: typeop.hh:286 TypeOpStore::push
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_store(op);
    }

    // Ghidra: typeop.hh:152 TypeOp::getInputLocal (base; Store does not override)
    fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
        if slot == 2 {
            // The value being stored should match the base type of the pointer (inrefs[1])
            return op.get_in(1).and_then(|vn| {
                let vn_read = vn.read().unwrap();
                if let Some(dt) = &vn_read.v_type {
                    if let Datatype::Pointer(ptr) = dt.as_ref() {
                        return Some(ptr.ptr_to.clone());
                    }
                }
                None
            });
        }
        None
    }

    /// For STORE, a type propagates between the value (slot 2) and the pointer
    /// (slot 1), never along the space constant (slot 0). Value-to-pointer
    /// rewraps (propagateToPointer); pointer-to-value unwraps
    /// (propagateFromPointer). Note STORE has no output varnode, so outslot is
    /// only ever an input slot.
    /// Faithful to `TypeOpStore::propagateType` (typeop.cc:557-570).
    // Ghidra: typeop.cc:557 TypeOpStore::propagateType
    fn propagate_type(
        &self,
        alt_type: &Arc<Datatype>,
        op: &PcodeOp,
        inslot: i32,
        outslot: i32,
    ) -> Option<Arc<Datatype>> {
        if inslot == 0 || outslot == 0 {
            return None; // Don't propagate along the space-constant edge
        }
        // Spacebase pointers do not propagate.
        let src_slot = if inslot == -1 { outslot } else { inslot };
        if src_slot >= 0 {
            if let Some(vn) = op.get_in(src_slot as usize) {
                if vn.read().unwrap().is_spacebase() {
                    return None;
                }
            }
        }
        if inslot == 2 {
            // value -> pointer : wrap value type as a pointer (propagateToPointer)
            Some(propagate_to_pointer(alt_type))
        } else {
            // pointer -> value : unwrap pointer to its pointee (propagateFromPointer)
            propagate_from_pointer(alt_type)
        }
    }
}

/// Wrap a value data-type as a pointer to it (used by LOAD/STORE output->input
/// propagation). Mirrors Ghidra's `TypeOp::propagateToPointer`
/// (typeop.cc:186-198): a pointer-to-pointer is collapsed to a pointer to an
/// unknown base of the right size to avoid creating ptr->ptr.
// Ghidra: typeop.cc:186 TypeOp::propagateToPointer
fn propagate_to_pointer(alt_type: &Arc<Datatype>) -> Arc<Datatype> {
    use crate::type_system::datatype::TypePointer;
    let sz = alt_type.get_size();
    let pointee = match alt_type.as_ref() {
        // If already a pointer, point at an unknown base of the pointee's size
        // so we never build ptr->ptr.
        Datatype::Pointer(_) => Arc::new(Datatype::Base(crate::type_system::TypeBase::new(
            "unknown".to_string(),
            alt_type.get_size(),
            TypeMetatype::Unknown,
        ))),
        _ => alt_type.clone(),
    };
    Arc::new(Datatype::Pointer(TypePointer {
        base: crate::type_system::TypeBase::new(
            format!("{} *", pointee.get_name()),
            sz,
            TypeMetatype::Pointer,
        ),
        ptr_to: pointee,
        wordsize: 1,
    }))
}

/// Unwrap a pointer data-type to its pointee (used by LOAD/STORE input->output
/// propagation). Mirrors Ghidra's `TypeOp::propagateFromPointer`
/// (typeop.cc:206-228): returns the pointee if `alt_type` is a pointer,
/// otherwise `None`.
// Ghidra: typeop.cc:206 TypeOp::propagateFromPointer
fn propagate_from_pointer(alt_type: &Arc<Datatype>) -> Option<Arc<Datatype>> {
    match alt_type.as_ref() {
        Datatype::Pointer(ptr) => Some(ptr.ptr_to.clone()),
        _ => None,
    }
}

// Arithmetic Operations
// NOTE: TypeOpIntAdd has a hand-written impl below (it needs a custom
// get_output_token and propagate_type).
binary_op!(
    TypeOpIntSub,
    CPUI_INT_SUB,
    "INT_SUB",
    typeop_flags::ARITHMETIC_OP,
    "-"
);
binary_op!(
    TypeOpIntMult,
    CPUI_INT_MULT,
    "INT_MULT",
    typeop_flags::ARITHMETIC_OP,
    "*"
);
binary_op!(
    TypeOpIntDiv,
    CPUI_INT_DIV,
    "INT_DIV",
    typeop_flags::ARITHMETIC_OP,
    "/"
);
binary_op!(
    TypeOpIntSdiv,
    CPUI_INT_SDIV,
    "INT_SDIV",
    typeop_flags::ARITHMETIC_OP,
    "s/"
);
binary_op!(
    TypeOpIntRem,
    CPUI_INT_REM,
    "INT_REM",
    typeop_flags::ARITHMETIC_OP,
    "%"
);
binary_op!(
    TypeOpIntSrem,
    CPUI_INT_SREM,
    "INT_SREM",
    typeop_flags::ARITHMETIC_OP,
    "s%"
);
unary_op!(
    TypeOpIntNeg,
    CPUI_INT_2COMP,
    "INT_2COMP",
    typeop_flags::ARITHMETIC_OP,
    "-"
);
functional_binary_op!(TypeOpIntCarry, CPUI_INT_CARRY, "INT_CARRY", 0, "carry");
functional_binary_op!(TypeOpIntScarry, CPUI_INT_SCARRY, "INT_SCARRY", 0, "scarry");
functional_binary_op!(
    TypeOpIntSborrow,
    CPUI_INT_SBORROW,
    "INT_SBORROW",
    0,
    "sborrow"
);

// Bitwise Operations
binary_op!(
    TypeOpIntAnd,
    CPUI_INT_AND,
    "INT_AND",
    typeop_flags::LOGICAL_OP,
    "&"
);
binary_op!(
    TypeOpIntOr,
    CPUI_INT_OR,
    "INT_OR",
    typeop_flags::LOGICAL_OP,
    "|"
);
binary_op!(
    TypeOpIntXor,
    CPUI_INT_XOR,
    "INT_XOR",
    typeop_flags::LOGICAL_OP,
    "^"
);
unary_op!(
    TypeOpIntNot,
    CPUI_INT_NEGATE,
    "INT_NEGATE",
    typeop_flags::LOGICAL_OP,
    "~"
);
binary_op!(
    TypeOpIntLeft,
    CPUI_INT_LEFT,
    "INT_LEFT",
    typeop_flags::SHIFT_OP,
    "<<"
);
binary_op!(
    TypeOpIntRight,
    CPUI_INT_RIGHT,
    "INT_RIGHT",
    typeop_flags::SHIFT_OP,
    ">>"
);
binary_op!(
    TypeOpIntSright,
    CPUI_INT_SRIGHT,
    "INT_SRIGHT",
    typeop_flags::SHIFT_OP,
    "s>>"
);

// Comparison Operations
// NOTE: The six comparison ops (Equal, NotEqual, Less, LessEqual, Sless,
// SlessEqual) have hand-written impls below: each has bool output metaout and
// a propagate_type that flows across the two input operands.

// Extension Operations
functional_unary_op!(
    TypeOpIntZext,
    CPUI_INT_ZEXT,
    "INT_ZEXT",
    typeop_flags::INHERITS_SIGN_ZERO,
    "zext"
);
functional_unary_op!(
    TypeOpIntSext,
    CPUI_INT_SEXT,
    "INT_SEXT",
    typeop_flags::INHERITS_SIGN,
    "sext"
);
functional_unary_op!(TypeOpTrunc, CPUI_SUBPIECE, "SUBPIECE", 0, "subpiece");

// Floating Point Operations
binary_op!(
    TypeOpFloatAdd,
    CPUI_FLOAT_ADD,
    "FLOAT_ADD",
    typeop_flags::FLOATINGPOINT_OP,
    "f+"
);
binary_op!(
    TypeOpFloatSub,
    CPUI_FLOAT_SUB,
    "FLOAT_SUB",
    typeop_flags::FLOATINGPOINT_OP,
    "f-"
);
binary_op!(
    TypeOpFloatMult,
    CPUI_FLOAT_MULT,
    "FLOAT_MULT",
    typeop_flags::FLOATINGPOINT_OP,
    "f*"
);
binary_op!(
    TypeOpFloatDiv,
    CPUI_FLOAT_DIV,
    "FLOAT_DIV",
    typeop_flags::FLOATINGPOINT_OP,
    "f/"
);
unary_op!(
    TypeOpFloatNeg,
    CPUI_FLOAT_NEG,
    "FLOAT_NEG",
    typeop_flags::FLOATINGPOINT_OP,
    "f-"
);
functional_unary_op!(
    TypeOpFloatAbs,
    CPUI_FLOAT_ABS,
    "FLOAT_ABS",
    typeop_flags::FLOATINGPOINT_OP,
    "fabs"
);
functional_unary_op!(
    TypeOpFloatSqrt,
    CPUI_FLOAT_SQRT,
    "FLOAT_SQRT",
    typeop_flags::FLOATINGPOINT_OP,
    "fsqrt"
);
binary_op!(
    TypeOpFloatEqual,
    CPUI_FLOAT_EQUAL,
    "FLOAT_EQUAL",
    typeop_flags::FLOATINGPOINT_OP,
    "f=="
);
binary_op!(
    TypeOpFloatNotEqual,
    CPUI_FLOAT_NOTEQUAL,
    "FLOAT_NOTEQUAL",
    typeop_flags::FLOATINGPOINT_OP,
    "f!="
);
binary_op!(
    TypeOpFloatLess,
    CPUI_FLOAT_LESS,
    "FLOAT_LESS",
    typeop_flags::FLOATINGPOINT_OP,
    "f<"
);
binary_op!(
    TypeOpFloatLessEqual,
    CPUI_FLOAT_LESSEQUAL,
    "FLOAT_LESSEQUAL",
    typeop_flags::FLOATINGPOINT_OP,
    "f<="
);
functional_unary_op!(
    TypeOpFloatNan,
    CPUI_FLOAT_NAN,
    "FLOAT_NAN",
    typeop_flags::FLOATINGPOINT_OP,
    "isnan"
);
functional_unary_op!(
    TypeOpFloatFloat2Float,
    CPUI_FLOAT_FLOAT2FLOAT,
    "FLOAT_FLOAT2FLOAT",
    typeop_flags::FLOATINGPOINT_OP,
    "f2f"
);
functional_unary_op!(
    TypeOpFloatInt2Float,
    CPUI_FLOAT_INT2FLOAT,
    "FLOAT_INT2FLOAT",
    typeop_flags::FLOATINGPOINT_OP,
    "i2f"
);
functional_unary_op!(
    TypeOpFloatTrunc,
    CPUI_FLOAT_TRUNC,
    "FLOAT_TRUNC",
    typeop_flags::FLOATINGPOINT_OP,
    "ftrunc"
);
functional_unary_op!(
    TypeOpFloatCeil,
    CPUI_FLOAT_CEIL,
    "FLOAT_CEIL",
    typeop_flags::FLOATINGPOINT_OP,
    "fceil"
);
functional_unary_op!(
    TypeOpFloatFloor,
    CPUI_FLOAT_FLOOR,
    "FLOAT_FLOOR",
    typeop_flags::FLOATINGPOINT_OP,
    "ffloor"
);
functional_unary_op!(
    TypeOpFloatRound,
    CPUI_FLOAT_ROUND,
    "FLOAT_ROUND",
    typeop_flags::FLOATINGPOINT_OP,
    "fround"
);

// Boolean Operations
binary_op!(TypeOpBoolAnd, CPUI_BOOL_AND, "BOOL_AND", 0, "&&");
binary_op!(TypeOpBoolOr, CPUI_BOOL_OR, "BOOL_OR", 0, "||");
binary_op!(TypeOpBoolXor, CPUI_BOOL_XOR, "BOOL_XOR", 0, "^^");
unary_op!(TypeOpBoolNot, CPUI_BOOL_NEGATE, "BOOL_NEGATE", 0, "!");

// Special Operations
functional_binary_op!(TypeOpPiece, CPUI_PIECE, "PIECE", 0, "concat");
functional_binary_op!(TypeOpSubpiece, CPUI_SUBPIECE, "SUBPIECE", 0, "subpiece");
functional_unary_op!(TypeOpPopcount, CPUI_POPCOUNT, "POPCOUNT", 0, "popcount");
functional_unary_op!(TypeOpLzcount, CPUI_LZCOUNT, "LZCOUNT", 0, "lzcount");

// Control Flow Operations
pub struct TypeOpBranch;
impl TypeOp for TypeOpBranch {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_BRANCH
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "BRANCH"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:590 TypeOpBranch::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("goto {}", in0)
    }
}

pub struct TypeOpCbranch;
impl TypeOp for TypeOpCbranch {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_CBRANCH
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "CBRANCH"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:621 TypeOpCbranch::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("if ({}) goto {}", in1, in0)
    }
}

pub struct TypeOpBranchind;
impl TypeOp for TypeOpBranchind {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_BRANCHIND
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "BRANCHIND"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:653 TypeOpBranchind::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("goto [{}]", in0)
    }
}

pub struct TypeOpCall;
impl TypeOp for TypeOpCall {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_CALL
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "CALL"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:667 TypeOpCall::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("call {}", in0)
    }

    // Ghidra: typeop.hh:319 TypeOpCall::push
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_call(op);
    }
}

pub struct TypeOpCallind;
impl TypeOp for TypeOpCallind {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_CALLIND
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "CALLIND"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:791 TypeOpCallind::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("call [{}]", in0)
    }
}

pub struct TypeOpReturn;
impl TypeOp for TypeOpReturn {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_RETURN
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "RETURN"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:882 TypeOpReturn::printRaw
    fn print_raw(&self, _op: &PcodeOp) -> String {
        "return".to_string()
    }

    // Ghidra: typeop.hh:350 TypeOpReturn::push
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_return(op);
    }
}

pub struct TypeOpPtradd;
impl TypeOp for TypeOpPtradd {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_PTRADD
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "PTRADD"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:2283 TypeOpPtradd::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in2 = op
            .get_in(2)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = ptradd({}, {}, {})", out, in0, in1, in2)
    }

    // Ghidra: typeop.cc:2238 TypeOpPtradd::getOutputLocal
    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        // Output should be a pointer, matching the base pointer input (inrefs[0])
        op.get_in(0)
            .and_then(|vn| vn.read().unwrap().v_type.clone())
    }

    // Ghidra: typeop.cc:2232 TypeOpPtradd::getInputLocal
    fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
        if slot == 0 {
            // Input 0 should match the output type
            return op
                .get_out()
                .and_then(|vn| vn.read().unwrap().v_type.clone());
        }
        None
    }
}

pub struct TypeOpPtrsub;
impl TypeOp for TypeOpPtrsub {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_PTRSUB
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "PTRSUB"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:2380 TypeOpPtrsub::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = {} + {}", out, in0, in1)
    }

    // Ghidra: typeop.cc:2308 TypeOpPtrsub::getOutputLocal
    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        // Ptrsub usually results in a pointer to a sub-field or element
        // For now, suggest the same type as input pointer if it's a pointer
        op.get_in(0).and_then(|vn| {
            let vn_read = vn.read().unwrap();
            if let Some(dt) = &vn_read.v_type {
                if let Datatype::Pointer(_) = dt.as_ref() {
                    return Some(dt.clone());
                }
            }
            None
        })
    }
}

pub struct TypeOpMulti;
impl TypeOp for TypeOpMulti {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_MULTIEQUAL
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "MULTIEQUAL"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:1967 TypeOpMulti::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let mut inputs = Vec::new();
        let mut i = 0;
        while let Some(v) = op.get_in(i) {
            inputs.push(format!("{}", v.read().unwrap()));
            i += 1;
        }
        format!("{} = phi({})", out, inputs.join(", "))
    }

    // Ghidra: typeop.hh:758 TypeOpMulti::push
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_multiequal(op);
    }

    // Ghidra: typeop.hh:149 TypeOp::getOutputLocal (base; Multi does not override)
    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        // Phi node output matches inputs. Pick first non-none.
        let mut i = 0;
        while let Some(v) = op.get_in(i) {
            if let Some(dt) = &v.read().unwrap().v_type {
                return Some(dt.clone());
            }
            i += 1;
        }
        None
    }

    // Ghidra: typeop.hh:152 TypeOp::getInputLocal (base; Multi does not override)
    fn get_input_local(&self, op: &PcodeOp, _slot: usize) -> Option<Arc<Datatype>> {
        // Inputs should match the output type
        op.get_out().and_then(|v| v.read().unwrap().v_type.clone())
    }

    /// MULTIEQUAL is a transparent phi node: a type propagates across it in
    /// either direction (input<->output). One slot must be the output (-1).
    /// Spacebase inputs are rewrapped as a pointer to an unknown base type.
    /// Faithful to `TypeOpMulti::propagateType` (typeop.cc:1951-1965).
    // Ghidra: typeop.cc:1951 TypeOpMulti::propagateType
    fn propagate_type(
        &self,
        alt_type: &Arc<Datatype>,
        op: &PcodeOp,
        inslot: i32,
        outslot: i32,
    ) -> Option<Arc<Datatype>> {
        if inslot != -1 && outslot != -1 {
            return None; // Must propagate input <-> output
        }
        let src_slot = if inslot == -1 { outslot } else { inslot };
        if src_slot >= 0 {
            if let Some(vn) = op.get_in(src_slot as usize) {
                if vn.read().unwrap().is_spacebase() {
                    return Some(propagate_to_pointer(&Arc::new(Datatype::Base(
                        crate::type_system::TypeBase::new(
                            "unknown".to_string(),
                            1,
                            TypeMetatype::Unknown,
                        ),
                    ))));
                }
            }
        }
        Some(alt_type.clone())
    }
}

pub struct TypeOpIndirect;
impl TypeOp for TypeOpIndirect {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_INDIRECT
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "INDIRECT"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:2022 TypeOpIndirect::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = {}({})", out, in0, in1)
    }

    // Ghidra: typeop.hh:769 TypeOpIndirect::push
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_indirect(op);
    }

    // Ghidra: typeop.hh:149 TypeOp::getOutputLocal (base; Indirect does not override)
    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        // Indirect usually inherits type from its first input
        op.get_in(0)
            .and_then(|vn| vn.read().unwrap().v_type.clone())
    }

    /// INDIRECT is transparent (like COPY/MULTIEQUAL) but never propagates
    /// along slot 1 (the code-pointer input) and does not propagate for an
    /// indirect creation. Otherwise a type flows input<->output, with a
    /// spacebase rewrapped as a pointer to an unknown base type.
    /// Faithful to `TypeOpIndirect::propagateType` (typeop.cc:2005-2020).
    // Ghidra: typeop.cc:2005 TypeOpIndirect::propagateType
    fn propagate_type(
        &self,
        alt_type: &Arc<Datatype>,
        op: &PcodeOp,
        inslot: i32,
        outslot: i32,
    ) -> Option<Arc<Datatype>> {
        if inslot == 1 || outslot == 1 {
            return None; // Never propagate along the code-pointer edge
        }
        if inslot != -1 && outslot != -1 {
            return None; // Must propagate input <-> output
        }
        let src_slot = if inslot == -1 { outslot } else { inslot };
        if src_slot >= 0 {
            if let Some(vn) = op.get_in(src_slot as usize) {
                if vn.read().unwrap().is_spacebase() {
                    return Some(propagate_to_pointer(&Arc::new(Datatype::Base(
                        crate::type_system::TypeBase::new(
                            "unknown".to_string(),
                            1,
                            TypeMetatype::Unknown,
                        ),
                    ))));
                }
            }
        }
        Some(alt_type.clone())
    }
}

pub struct TypeOpSegment;
impl TypeOp for TypeOpSegment {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_SEGMENTOP
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "SEGMENTOP"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:2397 TypeOpSegment::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let mut inputs = Vec::new();
        let mut i = 0;
        while let Some(v) = op.get_in(i) {
            inputs.push(format!("{}", v.read().unwrap()));
            i += 1;
        }
        format!("{} = segment({})", out, inputs.join(", "))
    }
}

pub struct TypeOpCpoolref;
impl TypeOp for TypeOpCpoolref {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_CPOOLREF
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "CPOOLREF"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:2471 TypeOpCpoolref::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let mut inputs = Vec::new();
        let mut i = 0;
        while let Some(v) = op.get_in(i) {
            inputs.push(format!("{}", v.read().unwrap()));
            i += 1;
        }
        format!("{} = cpool({})", out, inputs.join(", "))
    }
}

pub struct TypeOpNew;
impl TypeOp for TypeOpNew {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_NEW
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "NEW"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:2511 TypeOpNew::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let mut inputs = Vec::new();
        let mut i = 0;
        while let Some(v) = op.get_in(i) {
            inputs.push(format!("{}", v.read().unwrap()));
            i += 1;
        }
        format!("{} = new({})", out, inputs.join(", "))
    }
}

pub struct TypeOpCallother;
impl TypeOp for TypeOpCallother {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_CALLOTHER
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "CALLOTHER"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:818 TypeOpCallother::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let mut inputs = Vec::new();
        let mut i = 0;
        while let Some(v) = op.get_in(i) {
            inputs.push(format!("{}", v.read().unwrap()));
            i += 1;
        }
        format!("{} = callother({})", out, inputs.join(", "))
    }
}

functional_binary_op!(TypeOpInsert, CPUI_INSERT, "INSERT", 0, "insert");
functional_binary_op!(TypeOpExtract, CPUI_EXTRACT, "EXTRACT", 0, "extract");

// ---------------------------------------------------------------------------
// Hand-written impls for the comparison ops and INT_ADD.
//
// These were pulled out of the `binary_op!` macro because Ghidra's
// `TypeOpBinary` gives them a non-default metaout (TYPE_BOOL for comparisons,
// TYPE_INT for INT_ADD) and they override getInputCast/propagateType.
// ---------------------------------------------------------------------------

/// Shared body emitted by `compare_op_impl!` / `signed_compare_op_impl!`:
/// matches the fields the `binary_op!` macro sets (opcode/name/flags/print/push
/// + the transparent input<->output get_output_local/get_input_local).
macro_rules! compare_op_common {
    ($struct_name:ident, $opcode:ident, $name:expr, $flags:expr, $symbol:expr) => {
        // Ghidra: typeop.hh:71 TypeOp::getOpcode
        fn get_opcode(&self) -> OpCode {
            OpCode::$opcode
        }
        // Ghidra: typeop.hh:70 TypeOp::getName
        fn get_name(&self) -> &str {
            $name
        }
        // Ghidra: typeop.hh:72 TypeOp::getFlags
        fn get_flags(&self) -> u32 {
            $flags
        }
        // Ghidra: typeop.cc:335 TypeOpBinary::printRaw (comparison ops inherit)
        fn print_raw(&self, op: &PcodeOp) -> String {
            let out = op
                .get_out()
                .map(|v| format!("{}", v.read().unwrap()))
                .unwrap_or_else(|| "_".to_string());
            let in0 = op
                .get_in(0)
                .map(|v| format!("{}", v.read().unwrap()))
                .unwrap_or_else(|| "_".to_string());
            let in1 = op
                .get_in(1)
                .map(|v| format!("{}", v.read().unwrap()))
                .unwrap_or_else(|| "_".to_string());
            format!("{} = {} {} {}", out, in0, $symbol, in1)
        }
        // RUGRA-GLUE: macro-generated generic binary push for comparison ops.
        fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
            lng.op_binary(op);
        }
        // Ghidra: typeop.cc:323 TypeOpBinary::getOutputLocal (metaout=TYPE_BOOL)
        fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
            // Comparisons produce a bool of the output's size.
            Some(Arc::new(Datatype::Base(crate::type_system::TypeBase::new(
                "bool".to_string(),
                op.get_out().map(|v| v.read().unwrap().get_size()).unwrap_or(1),
                TypeMetatype::Bool,
            ))))
        }
        // Ghidra: typeop.cc:329 TypeOpBinary::getInputLocal
        fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
            op.get_in(slot)
                .and_then(|vn| vn.read().unwrap().v_type.clone())
        }
    };
}

/// Comparison ops whose output is a bool and whose propagateType flows the
/// incoming type across the two inputs (input<->input only), matching Ghidra's
/// `TypeOpEqual::propagateAcrossCompare` (typeop.cc:963-986). The result
/// metatype is Bool.
macro_rules! compare_op_impl {
    ($struct_name:ident, $opcode:ident, $name:expr, $flags:expr, $symbol:expr) => {
        pub struct $struct_name;
        impl TypeOp for $struct_name {
            compare_op_common!($struct_name, $opcode, $name, $flags, $symbol);

            /// A comparison's output is boolean.
            // RUGRA-GLUE: exposes the per-subclass `metaout` field
            //   (typeop.hh:205 TYPE_BOOL set by TypeOpBinary ctor).
            fn get_output_metatype(&self) -> Option<TypeMetatype> {
                Some(TypeMetatype::Bool)
            }

            /// The two comparison operands should share a type. We return the
            /// other operand's high type as the cast target for `slot` so the
            /// caller can reconcile them (or None if there is nothing to cast).
            /// Faithful in spirit to `TypeOpEqual::getInputCast`
            /// (typeop.cc:932-943), which picks the more general of the two
            /// input types.
            // Ghidra: typeop.cc:932 TypeOpEqual::getInputCast
            fn get_input_cast(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
                let other = if slot == 0 { 1 } else { 0 };
                op.get_in(other)
                    .and_then(|vn| vn.read().unwrap().v_type.clone())
            }

            /// Comparisons propagate a type across their two input operands
            /// (never to/from the output). Spacebase inputs are rewrapped as a
            /// pointer to an unknown base type.
            /// Faithful to `TypeOpEqual::propagateAcrossCompare`
            /// (typeop.cc:963-986).
            // Ghidra: typeop.cc:945 TypeOpEqual::propagateType
            fn propagate_type(
                &self,
                alt_type: &Arc<Datatype>,
                op: &PcodeOp,
                inslot: i32,
                outslot: i32,
            ) -> Option<Arc<Datatype>> {
                if inslot == -1 || outslot == -1 {
                    return None; // Must propagate input <-> input
                }
                let src_slot = inslot;
                if src_slot >= 0 {
                    if let Some(vn) = op.get_in(src_slot as usize) {
                        if vn.read().unwrap().is_spacebase() {
                            return Some(propagate_to_pointer(&Arc::new(Datatype::Base(
                                crate::type_system::TypeBase::new(
                                    "unknown".to_string(),
                                    1,
                                    TypeMetatype::Unknown,
                                ),
                            ))));
                        }
                    }
                }
                Some(alt_type.clone())
            }
        }
    };
}

/// Signed comparisons (INT_SLESS / INT_SLESSEQUAL) only propagate TYPE_INT
/// across their inputs, matching Ghidra's `TypeOpIntSless::propagateType`
/// (typeop.cc:1033-1039).
macro_rules! signed_compare_op_impl {
    ($struct_name:ident, $opcode:ident, $name:expr, $flags:expr, $symbol:expr) => {
        pub struct $struct_name;
        impl TypeOp for $struct_name {
            compare_op_common!($struct_name, $opcode, $name, $flags, $symbol);

            /// A signed comparison's output is boolean.
            // RUGRA-GLUE: exposes the per-subclass `metaout` field
            //   (typeop.hh:205 TYPE_BOOL set by TypeOpBinary ctor).
            fn get_output_metatype(&self) -> Option<TypeMetatype> {
                Some(TypeMetatype::Bool)
            }

            /// Signed comparisons only propagate signed (TYPE_INT) types
            /// across their inputs; nothing flows to/from the bool output.
            /// Faithful to `TypeOpIntSless::propagateType`
            /// (typeop.cc:1033-1039).
            // Ghidra: typeop.cc:1033 TypeOpIntSless::propagateType
            fn propagate_type(
                &self,
                alt_type: &Arc<Datatype>,
                _op: &PcodeOp,
                inslot: i32,
                outslot: i32,
            ) -> Option<Arc<Datatype>> {
                if inslot == -1 || outslot == -1 {
                    return None; // Must propagate input <-> input
                }
                if alt_type.get_metatype() != TypeMetatype::Int {
                    return None; // Only propagate signed things
                }
                Some(alt_type.clone())
            }
        }
    };
}

compare_op_impl!(TypeOpIntEqual, CPUI_INT_EQUAL, "INT_EQUAL", 0, "==");
compare_op_impl!(
    TypeOpIntNotEqual,
    CPUI_INT_NOTEQUAL,
    "INT_NOTEQUAL",
    0,
    "!="
);
compare_op_impl!(TypeOpIntLess, CPUI_INT_LESS, "INT_LESS", 0, "<");
compare_op_impl!(
    TypeOpIntLessEqual,
    CPUI_INT_LESSEQUAL,
    "INT_LESSEQUAL",
    0,
    "<="
);
signed_compare_op_impl!(
    TypeOpIntSless,
    CPUI_INT_SLESS,
    "INT_SLESS",
    typeop_flags::INHERITS_SIGN,
    "s<"
);
signed_compare_op_impl!(
    TypeOpIntSlessEqual,
    CPUI_INT_SLESSEQUAL,
    "INT_SLESSEQUAL",
    typeop_flags::INHERITS_SIGN,
    "s<="
);

/// CPUI_INT_ADD with custom get_output_token and propagate_type.
///
/// `get_output_token` uses the arithmetic typing rule (the output's own high
/// type). `propagate_type` lets a pointer flow input->output (and back) when
/// the other addend is a constant, and otherwise flows int/uint types when
/// adding a constant; it never flows pointer types output->input.
/// Faithful to `TypeOpIntAdd` (typeop.cc:1167-1201).
pub struct TypeOpIntAdd;
impl TypeOp for TypeOpIntAdd {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_INT_ADD
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "INT_ADD"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        typeop_flags::ARITHMETIC_OP
    }
    // Ghidra: typeop.cc:335 TypeOpBinary::printRaw (IntAdd inherits)
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = {} + {}", out, in0, in1)
    }
    // Ghidra: typeop.hh:439 TypeOpIntAdd::push
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_binary(op);
    }
    // Ghidra: typeop.cc:323 TypeOpBinary::getOutputLocal (inherited)
    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        op.get_in(0)
            .and_then(|v| v.read().unwrap().v_type.clone())
    }
    // Ghidra: typeop.cc:329 TypeOpBinary::getInputLocal (inherited)
    fn get_input_local(&self, op: &PcodeOp, _slot: usize) -> Option<Arc<Datatype>> {
        op.get_out()
            .and_then(|v| v.read().unwrap().v_type.clone())
    }

    /// The output token of an ADD follows the arithmetic typing rule, i.e. the
    /// output varnode's own resolved high type.
    /// Faithful to `TypeOpIntAdd::getOutputToken` (typeop.cc:1175-1179), which
    /// returns `castStrategy->arithmeticOutputStandard(op)`.
    // Ghidra: typeop.cc:1175 TypeOpIntAdd::getOutputToken
    fn get_output_token(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        op.get_out()
            .and_then(|vn| vn.read().unwrap().v_type.clone())
    }

    /// Pointer arithmetic rule. A pointer propagates input->output when the
    /// other input is a constant; ints/uints propagate when adding a constant
    /// to slot 1. Pointers never propagate output->input. Anything else is
    /// blocked.
    /// Faithful to `TypeOpIntAdd::propagateType` (typeop.cc:1181-1201).
    // Ghidra: typeop.cc:1181 TypeOpIntAdd::propagateType
    fn propagate_type(
        &self,
        alt_type: &Arc<Datatype>,
        op: &PcodeOp,
        inslot: i32,
        outslot: i32,
    ) -> Option<Arc<Datatype>> {
        let meta = alt_type.get_metatype();
        if meta != TypeMetatype::Pointer {
            // Only int/uint may flow, and only when adding a constant on slot 1.
            if meta != TypeMetatype::Int && meta != TypeMetatype::Uint {
                return None;
            }
            if outslot != 1 || op.get_in(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
                return None;
            }
        } else if inslot != -1 && outslot != -1 {
            return None; // Pointers only propagate input <-> output
        }
        // Don't propagate pointer types output -> input.
        if inslot == -1 && meta == TypeMetatype::Pointer {
            return None;
        }
        Some(alt_type.clone())
    }
}

/// Manager for TypeOps
///
/// This handles the mapping between OpCodes and their TypeOp implementations.
pub struct TypeOpManager {
    ops: Vec<Option<Box<dyn TypeOp>>>,
}

impl TypeOpManager {
    // RUGRA-GLUE: Rust manager ctor; mirrors Ghidra's
    //   `TypeOp::registerInstructions(inst, tlst, trans)` (typeop.cc:24),
    //   which allocates and registers one TypeOp subclass per op-code into the
    //   `inst` vector. Rugra stores them in `Self::ops` keyed by OpCode.
    pub fn new() -> Self {
        let mut ops: Vec<Option<Box<dyn TypeOp>>> = Vec::new();
        ops.resize_with(256, || None); // Large enough for all opcodes

        // Register initial ops
        ops[OpCode::CPUI_COPY as usize] = Some(Box::new(TypeOpCopy));
        ops[OpCode::CPUI_LOAD as usize] = Some(Box::new(TypeOpLoad));
        ops[OpCode::CPUI_STORE as usize] = Some(Box::new(TypeOpStore));

        // Arithmetic
        ops[OpCode::CPUI_INT_ADD as usize] = Some(Box::new(TypeOpIntAdd));
        ops[OpCode::CPUI_INT_SUB as usize] = Some(Box::new(TypeOpIntSub));
        ops[OpCode::CPUI_INT_MULT as usize] = Some(Box::new(TypeOpIntMult));
        ops[OpCode::CPUI_INT_DIV as usize] = Some(Box::new(TypeOpIntDiv));
        ops[OpCode::CPUI_INT_SDIV as usize] = Some(Box::new(TypeOpIntSdiv));
        ops[OpCode::CPUI_INT_REM as usize] = Some(Box::new(TypeOpIntRem));
        ops[OpCode::CPUI_INT_SREM as usize] = Some(Box::new(TypeOpIntSrem));
        ops[OpCode::CPUI_INT_2COMP as usize] = Some(Box::new(TypeOpIntNeg));
        ops[OpCode::CPUI_INT_CARRY as usize] = Some(Box::new(TypeOpIntCarry));
        ops[OpCode::CPUI_INT_SCARRY as usize] = Some(Box::new(TypeOpIntScarry));
        ops[OpCode::CPUI_INT_SBORROW as usize] = Some(Box::new(TypeOpIntSborrow));

        // Bitwise
        ops[OpCode::CPUI_INT_AND as usize] = Some(Box::new(TypeOpIntAnd));
        ops[OpCode::CPUI_INT_OR as usize] = Some(Box::new(TypeOpIntOr));
        ops[OpCode::CPUI_INT_XOR as usize] = Some(Box::new(TypeOpIntXor));
        ops[OpCode::CPUI_INT_NEGATE as usize] = Some(Box::new(TypeOpIntNot));
        ops[OpCode::CPUI_INT_LEFT as usize] = Some(Box::new(TypeOpIntLeft));
        ops[OpCode::CPUI_INT_RIGHT as usize] = Some(Box::new(TypeOpIntRight));
        ops[OpCode::CPUI_INT_SRIGHT as usize] = Some(Box::new(TypeOpIntSright));

        // Comparison
        ops[OpCode::CPUI_INT_EQUAL as usize] = Some(Box::new(TypeOpIntEqual));
        ops[OpCode::CPUI_INT_NOTEQUAL as usize] = Some(Box::new(TypeOpIntNotEqual));
        ops[OpCode::CPUI_INT_LESS as usize] = Some(Box::new(TypeOpIntLess));
        ops[OpCode::CPUI_INT_SLESS as usize] = Some(Box::new(TypeOpIntSless));
        ops[OpCode::CPUI_INT_LESSEQUAL as usize] = Some(Box::new(TypeOpIntLessEqual));
        ops[OpCode::CPUI_INT_SLESSEQUAL as usize] = Some(Box::new(TypeOpIntSlessEqual));

        // Extension
        ops[OpCode::CPUI_INT_ZEXT as usize] = Some(Box::new(TypeOpIntZext));
        ops[OpCode::CPUI_INT_SEXT as usize] = Some(Box::new(TypeOpIntSext));
        ops[OpCode::CPUI_SUBPIECE as usize] = Some(Box::new(TypeOpTrunc));

        // Floating Point
        ops[OpCode::CPUI_FLOAT_ADD as usize] = Some(Box::new(TypeOpFloatAdd));
        ops[OpCode::CPUI_FLOAT_SUB as usize] = Some(Box::new(TypeOpFloatSub));
        ops[OpCode::CPUI_FLOAT_MULT as usize] = Some(Box::new(TypeOpFloatMult));
        ops[OpCode::CPUI_FLOAT_DIV as usize] = Some(Box::new(TypeOpFloatDiv));
        ops[OpCode::CPUI_FLOAT_NEG as usize] = Some(Box::new(TypeOpFloatNeg));
        ops[OpCode::CPUI_FLOAT_ABS as usize] = Some(Box::new(TypeOpFloatAbs));
        ops[OpCode::CPUI_FLOAT_SQRT as usize] = Some(Box::new(TypeOpFloatSqrt));
        ops[OpCode::CPUI_FLOAT_EQUAL as usize] = Some(Box::new(TypeOpFloatEqual));
        ops[OpCode::CPUI_FLOAT_NOTEQUAL as usize] = Some(Box::new(TypeOpFloatNotEqual));
        ops[OpCode::CPUI_FLOAT_LESS as usize] = Some(Box::new(TypeOpFloatLess));
        ops[OpCode::CPUI_FLOAT_LESSEQUAL as usize] = Some(Box::new(TypeOpFloatLessEqual));
        ops[OpCode::CPUI_FLOAT_NAN as usize] = Some(Box::new(TypeOpFloatNan));
        ops[OpCode::CPUI_FLOAT_FLOAT2FLOAT as usize] = Some(Box::new(TypeOpFloatFloat2Float));
        ops[OpCode::CPUI_FLOAT_INT2FLOAT as usize] = Some(Box::new(TypeOpFloatInt2Float));
        ops[OpCode::CPUI_FLOAT_TRUNC as usize] = Some(Box::new(TypeOpFloatTrunc));
        ops[OpCode::CPUI_FLOAT_CEIL as usize] = Some(Box::new(TypeOpFloatCeil));
        ops[OpCode::CPUI_FLOAT_FLOOR as usize] = Some(Box::new(TypeOpFloatFloor));
        ops[OpCode::CPUI_FLOAT_ROUND as usize] = Some(Box::new(TypeOpFloatRound));

        // Boolean
        ops[OpCode::CPUI_BOOL_AND as usize] = Some(Box::new(TypeOpBoolAnd));
        ops[OpCode::CPUI_BOOL_OR as usize] = Some(Box::new(TypeOpBoolOr));
        ops[OpCode::CPUI_BOOL_XOR as usize] = Some(Box::new(TypeOpBoolXor));
        ops[OpCode::CPUI_BOOL_NEGATE as usize] = Some(Box::new(TypeOpBoolNot));

        // Special
        ops[OpCode::CPUI_PIECE as usize] = Some(Box::new(TypeOpPiece));
        ops[OpCode::CPUI_SUBPIECE as usize] = Some(Box::new(TypeOpSubpiece));
        ops[OpCode::CPUI_POPCOUNT as usize] = Some(Box::new(TypeOpPopcount));
        ops[OpCode::CPUI_LZCOUNT as usize] = Some(Box::new(TypeOpLzcount));

        // Control Flow
        ops[OpCode::CPUI_BRANCH as usize] = Some(Box::new(TypeOpBranch));
        ops[OpCode::CPUI_CBRANCH as usize] = Some(Box::new(TypeOpCbranch));
        ops[OpCode::CPUI_BRANCHIND as usize] = Some(Box::new(TypeOpBranchind));
        ops[OpCode::CPUI_CALL as usize] = Some(Box::new(TypeOpCall));
        ops[OpCode::CPUI_CALLIND as usize] = Some(Box::new(TypeOpCallind));
        ops[OpCode::CPUI_RETURN as usize] = Some(Box::new(TypeOpReturn));

        // Pointer/SSA/Other
        ops[OpCode::CPUI_PTRADD as usize] = Some(Box::new(TypeOpPtradd));
        ops[OpCode::CPUI_PTRSUB as usize] = Some(Box::new(TypeOpPtrsub));
        ops[OpCode::CPUI_MULTIEQUAL as usize] = Some(Box::new(TypeOpMulti));
        ops[OpCode::CPUI_INDIRECT as usize] = Some(Box::new(TypeOpIndirect));
        ops[OpCode::CPUI_SEGMENTOP as usize] = Some(Box::new(TypeOpSegment));
        ops[OpCode::CPUI_CPOOLREF as usize] = Some(Box::new(TypeOpCpoolref));
        ops[OpCode::CPUI_NEW as usize] = Some(Box::new(TypeOpNew));
        ops[OpCode::CPUI_CALLOTHER as usize] = Some(Box::new(TypeOpCallother));
        ops[OpCode::CPUI_INSERT as usize] = Some(Box::new(TypeOpInsert));
        ops[OpCode::CPUI_EXTRACT as usize] = Some(Box::new(TypeOpExtract));

        Self { ops }
    }

    // RUGRA-GLUE: Rust accessor for the opcode→TypeOp table; in Ghidra the
    //   table is `vector<TypeOp*> inst` indexed by OpCode and held by
    //   TypeFactory (typeop.hh:186 registerInstructions). Lookups go through
    //   PcodeOp::getOpcode (op.hh:232) → TypeOp*.
    pub fn get_op(&self, opcode: OpCode) -> Option<&dyn TypeOp> {
        self.ops[opcode as usize].as_ref().map(|o| o.as_ref())
    }
}

impl crate::op::PcodeOp {
    /// Push this operation to a language printer
    // RUGRA-GLUE: convenience wrapper that dispatches by opcode; in Ghidra the
    //   per-op push lives on the TypeOp subclass (typeop.hh:170 push), and
    //   PcodeOp has no push method of its own (it forwards via opcode->push).
    pub fn push(&self, lng: &mut dyn PrintLanguage) {
        match self.opcode {
            OpCode::CPUI_COPY => lng.op_copy(self),
            OpCode::CPUI_LOAD => lng.op_load(self),
            OpCode::CPUI_STORE => lng.op_store(self),
            OpCode::CPUI_MULTIEQUAL => lng.op_multiequal(self),
            OpCode::CPUI_INDIRECT => lng.op_indirect(self),
            OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => lng.op_call(self),
            OpCode::CPUI_RETURN => lng.op_return(self),
            OpCode::CPUI_CBRANCH => lng.op_cbranch(self),
            OpCode::CPUI_BRANCH | OpCode::CPUI_BRANCHIND => lng.op_branch(self),
            // Unary ops
            OpCode::CPUI_INT_2COMP
            | OpCode::CPUI_INT_NEGATE
            | OpCode::CPUI_BOOL_NEGATE
            | OpCode::CPUI_FLOAT_NEG
            | OpCode::CPUI_FLOAT_ABS
            | OpCode::CPUI_FLOAT_SQRT
            | OpCode::CPUI_INT_ZEXT
            | OpCode::CPUI_INT_SEXT => lng.op_unary(self),
            // Default to binary for all other ops
            _ => lng.op_binary(self),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, SeqNum};
    use crate::type_system::TypeBase;
    use crate::type_system::datatype::TypePointer;
    use crate::varnode::Varnode;
    use std::sync::{Arc, RwLock};

    /// Build a typed varnode with the given data-type.
    fn typed_vn(size: usize, offset: u64, dt: Option<Arc<Datatype>>) -> Arc<RwLock<Varnode>> {
        let mut vn = Varnode::new(size, Address::new(offset));
        vn.v_type = dt;
        Arc::new(RwLock::new(vn))
    }

    fn pcodeop(opcode: OpCode) -> PcodeOp {
        PcodeOp::new(SeqNum::new(Address::new(0), 0), opcode)
    }

    fn int_t() -> Arc<Datatype> {
        Arc::new(Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int)))
    }

    /// Compare two `Option<Arc<Datatype>>` by Arc identity (same allocation).
    fn same_arc(got: Option<Arc<Datatype>>, want: &Arc<Datatype>) -> bool {
        match got {
            Some(g) => Arc::ptr_eq(&g, want),
            None => false,
        }
    }

    #[test]
    fn copy_propagate_type_is_transparent() {
        // COPY propagates input<->output (one slot is -1).
        let op = pcodeop(OpCode::CPUI_COPY);
        let t = int_t();
        // input slot 0 -> output returns the same Arc.
        assert!(same_arc(TypeOpCopy.propagate_type(&t, &op, 0, -1), &t));
        // input<->input is blocked (both slots >= 0).
        assert!(TypeOpCopy.propagate_type(&t, &op, 0, 1).is_none());
    }

    #[test]
    fn copy_get_output_token_uses_input() {
        let mut op = pcodeop(OpCode::CPUI_COPY);
        let t = int_t();
        op.inrefs.push(typed_vn(4, 0x10, Some(t.clone())));
        // The token is the input varnode's high type (Arc identity).
        assert!(same_arc(TypeOpCopy.get_output_token(&op), &t));
    }

    #[test]
    fn compare_propagate_only_across_inputs() {
        // INT_EQUAL propagates a type across its two inputs, never to output.
        let op = pcodeop(OpCode::CPUI_INT_EQUAL);
        let t = int_t();
        assert!(same_arc(
            TypeOpIntEqual.propagate_type(&t, &op, 0, 1),
            &t
        ));
        // To/from the output is blocked.
        assert!(TypeOpIntEqual.propagate_type(&t, &op, -1, 0).is_none());
    }

    #[test]
    fn signed_compare_only_propagates_int() {
        let op = pcodeop(OpCode::CPUI_INT_SLESS);
        // uint does NOT propagate through a signed compare.
        let uint_t = Arc::new(Datatype::Base(TypeBase::new(
            "uint".into(),
            4,
            TypeMetatype::Uint,
        )));
        assert!(TypeOpIntSless.propagate_type(&uint_t, &op, 0, 1).is_none());
        // int does.
        let t = int_t();
        assert!(same_arc(
            TypeOpIntSless.propagate_type(&t, &op, 0, 1),
            &t
        ));
    }

    #[test]
    fn compare_output_metatype_is_bool_and_cast_uses_other_operand() {
        let mut op = pcodeop(OpCode::CPUI_INT_LESS);
        let t = int_t();
        op.inrefs.push(typed_vn(4, 0x10, Some(t.clone())));
        op.inrefs.push(typed_vn(4, 0x20, None));
        assert_eq!(TypeOpIntLess.get_output_metatype(), Some(TypeMetatype::Bool));
        // Casting slot 1 should target the other operand's type (in[0]).
        assert!(same_arc(TypeOpIntLess.get_input_cast(&op, 1), &t));
    }

    #[test]
    fn load_propagate_wraps_and_unwraps_pointer() {
        // LOAD: output(value) -> input(pointer) wraps the value as a pointer.
        let op = pcodeop(OpCode::CPUI_LOAD);
        let t = int_t();
        let wrapped = TypeOpLoad.propagate_type(&t, &op, -1, 1).expect("wraps");
        assert_eq!(wrapped.get_metatype(), TypeMetatype::Pointer);
        // input(pointer) -> output(value) unwraps to the pointee.
        let ptr_t = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".into(), 8, TypeMetatype::Pointer),
            ptr_to: t.clone(),
            wordsize: 1,
        }));
        assert!(same_arc(TypeOpLoad.propagate_type(&ptr_t, &op, 1, -1), &t));
        // The space-constant edge (slot 0) never propagates.
        assert!(TypeOpLoad.propagate_type(&t, &op, 0, -1).is_none());
    }

    #[test]
    fn int_add_propagates_pointer_with_constant() {
        // INT_ADD lets a pointer flow input->output; here in[1] is a constant.
        let mut op = pcodeop(OpCode::CPUI_INT_ADD);
        op.inrefs.push(typed_vn(8, 0x10, None));
        op.inrefs.push(Arc::new(RwLock::new(Varnode::new_constant(4, 8))));
        let ptr_t = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".into(), 8, TypeMetatype::Pointer),
            ptr_to: int_t(),
            wordsize: 1,
        }));
        // pointer input 0 -> output propagates.
        assert!(same_arc(
            TypeOpIntAdd.propagate_type(&ptr_t, &op, 0, -1),
            &ptr_t
        ));
        // pointer output -> input is blocked.
        assert!(TypeOpIntAdd.propagate_type(&ptr_t, &op, -1, 0).is_none());
    }

    #[test]
    fn default_trait_methods_are_none() {
        // Ops without overrides use the trait defaults.
        let op = pcodeop(OpCode::CPUI_BRANCH);
        assert!(TypeOpBranch.get_output_token(&op).is_none());
        assert!(TypeOpBranch.get_input_cast(&op, 0).is_none());
        assert!(TypeOpBranch.get_output_metatype().is_none());
        let t = int_t();
        assert!(TypeOpBranch.propagate_type(&t, &op, -1, 0).is_none());
    }
}
