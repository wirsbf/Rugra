//! Type operations for P-code
//!
//! Corresponds to Ghidra's `typeop.hh`

use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::printlanguage::PrintLanguage;
use crate::type_system::Datatype;
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
    fn get_opcode(&self) -> OpCode;

    /// Get the name of the operation
    fn get_name(&self) -> &str;

    /// Get properties/flags for this operation
    fn get_flags(&self) -> u32;

    /// Print the operation in a raw textual format
    fn print_raw(&self, op: &PcodeOp) -> String;

    /// Push the operation to a print language emitter
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
    fn get_output_local(&self, _op: &PcodeOp) -> Option<Arc<Datatype>> {
        None
    }

    /// Get the minimal (or suggested) data-type of an input to this op-code
    fn get_input_local(&self, _op: &PcodeOp, _slot: usize) -> Option<Arc<Datatype>> {
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
    fn get_opcode(&self) -> OpCode {
        self.opcode
    }
    fn get_name(&self) -> &str {
        &self.name
    }
    fn get_flags(&self) -> u32 {
        self.flags
    }

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
    fn get_opcode(&self) -> OpCode {
        self.opcode
    }
    fn get_name(&self) -> &str {
        &self.name
    }
    fn get_flags(&self) -> u32 {
        self.flags
    }

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

    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_unary(op);
    }
}

// --- Concrete Opcode Implementations ---

macro_rules! binary_op {
    ($struct_name:ident, $opcode:ident, $name:expr, $flags:expr, $symbol:expr) => {
        pub struct $struct_name;
        impl TypeOp for $struct_name {
            fn get_opcode(&self) -> OpCode {
                OpCode::$opcode
            }
            fn get_name(&self) -> &str {
                $name
            }
            fn get_flags(&self) -> u32 {
                $flags
            }
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
            fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
                lng.op_binary(op);
            }
            fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
                op.get_in(0).and_then(|v| v.read().unwrap().v_type.clone())
            }
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
            fn get_opcode(&self) -> OpCode {
                OpCode::$opcode
            }
            fn get_name(&self) -> &str {
                $name
            }
            fn get_flags(&self) -> u32 {
                $flags
            }
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
            fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
                lng.op_unary(op);
            }
            fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
                op.get_in(0).and_then(|v| v.read().unwrap().v_type.clone())
            }
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
            fn get_opcode(&self) -> OpCode {
                OpCode::$opcode
            }
            fn get_name(&self) -> &str {
                $name
            }
            fn get_flags(&self) -> u32 {
                $flags
            }
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
            fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
                lng.op_unary(op);
            }
            fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
                op.get_in(0).and_then(|v| v.read().unwrap().v_type.clone())
            }
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
            fn get_opcode(&self) -> OpCode {
                OpCode::$opcode
            }
            fn get_name(&self) -> &str {
                $name
            }
            fn get_flags(&self) -> u32 {
                $flags
            }
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
            fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
                lng.op_binary(op);
            }
            fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
                op.get_in(0).and_then(|v| v.read().unwrap().v_type.clone())
            }
            fn get_input_local(&self, op: &PcodeOp, _slot: usize) -> Option<Arc<Datatype>> {
                op.get_out().and_then(|v| v.read().unwrap().v_type.clone())
            }
        }
    };
}

/// CPUI_COPY implementation
pub struct TypeOpCopy;
impl TypeOp for TypeOpCopy {
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_COPY
    }
    fn get_name(&self) -> &str {
        "COPY"
    }
    fn get_flags(&self) -> u32 {
        0
    }

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

    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_copy(op);
    }

    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        op.get_in(0)
            .and_then(|vn| vn.read().unwrap().v_type.clone())
    }

    fn get_input_local(&self, op: &PcodeOp, _slot: usize) -> Option<Arc<Datatype>> {
        op.get_out()
            .and_then(|vn| vn.read().unwrap().v_type.clone())
    }
}

/// CPUI_LOAD implementation
pub struct TypeOpLoad;
impl TypeOp for TypeOpLoad {
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_LOAD
    }
    fn get_name(&self) -> &str {
        "LOAD"
    }
    fn get_flags(&self) -> u32 {
        0
    }

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

    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_load(op);
    }

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
}

/// CPUI_STORE implementation
pub struct TypeOpStore;
impl TypeOp for TypeOpStore {
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_STORE
    }
    fn get_name(&self) -> &str {
        "STORE"
    }
    fn get_flags(&self) -> u32 {
        0
    }

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

    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_store(op);
    }

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
}

// Arithmetic Operations
binary_op!(
    TypeOpIntAdd,
    CPUI_INT_ADD,
    "INT_ADD",
    typeop_flags::ARITHMETIC_OP,
    "+"
);
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
binary_op!(TypeOpIntEqual, CPUI_INT_EQUAL, "INT_EQUAL", 0, "==");
binary_op!(
    TypeOpIntNotEqual,
    CPUI_INT_NOTEQUAL,
    "INT_NOTEQUAL",
    0,
    "!="
);
binary_op!(TypeOpIntLess, CPUI_INT_LESS, "INT_LESS", 0, "<");
binary_op!(
    TypeOpIntSless,
    CPUI_INT_SLESS,
    "INT_SLESS",
    typeop_flags::INHERITS_SIGN,
    "s<"
);
binary_op!(
    TypeOpIntLessEqual,
    CPUI_INT_LESSEQUAL,
    "INT_LESSEQUAL",
    0,
    "<="
);
binary_op!(
    TypeOpIntSlessEqual,
    CPUI_INT_SLESSEQUAL,
    "INT_SLESSEQUAL",
    typeop_flags::INHERITS_SIGN,
    "s<="
);

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
functional_unary_op!(TypeOpTrunc, CPUI_TRUNC, "TRUNC", 0, "trunc");

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
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_BRANCH
    }
    fn get_name(&self) -> &str {
        "BRANCH"
    }
    fn get_flags(&self) -> u32 {
        0
    }
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
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_CBRANCH
    }
    fn get_name(&self) -> &str {
        "CBRANCH"
    }
    fn get_flags(&self) -> u32 {
        0
    }
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
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_BRANCHIND
    }
    fn get_name(&self) -> &str {
        "BRANCHIND"
    }
    fn get_flags(&self) -> u32 {
        0
    }
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
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_CALL
    }
    fn get_name(&self) -> &str {
        "CALL"
    }
    fn get_flags(&self) -> u32 {
        0
    }
    fn print_raw(&self, op: &PcodeOp) -> String {
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("call {}", in0)
    }

    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_call(op);
    }
}

pub struct TypeOpCallind;
impl TypeOp for TypeOpCallind {
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_CALLIND
    }
    fn get_name(&self) -> &str {
        "CALLIND"
    }
    fn get_flags(&self) -> u32 {
        0
    }
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
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_RETURN
    }
    fn get_name(&self) -> &str {
        "RETURN"
    }
    fn get_flags(&self) -> u32 {
        0
    }
    fn print_raw(&self, _op: &PcodeOp) -> String {
        "return".to_string()
    }

    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_return(op);
    }
}

pub struct TypeOpPtradd;
impl TypeOp for TypeOpPtradd {
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_PTRADD
    }
    fn get_name(&self) -> &str {
        "PTRADD"
    }
    fn get_flags(&self) -> u32 {
        0
    }
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

    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        // Output should be a pointer, matching the base pointer input (inrefs[0])
        op.get_in(0)
            .and_then(|vn| vn.read().unwrap().v_type.clone())
    }

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
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_PTRSUB
    }
    fn get_name(&self) -> &str {
        "PTRSUB"
    }
    fn get_flags(&self) -> u32 {
        0
    }
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
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_MULTIEQUAL
    }
    fn get_name(&self) -> &str {
        "MULTIEQUAL"
    }
    fn get_flags(&self) -> u32 {
        0
    }
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

    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_multiequal(op);
    }

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

    fn get_input_local(&self, op: &PcodeOp, _slot: usize) -> Option<Arc<Datatype>> {
        // Inputs should match the output type
        op.get_out().and_then(|v| v.read().unwrap().v_type.clone())
    }
}

pub struct TypeOpIndirect;
impl TypeOp for TypeOpIndirect {
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_INDIRECT
    }
    fn get_name(&self) -> &str {
        "INDIRECT"
    }
    fn get_flags(&self) -> u32 {
        0
    }
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

    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_indirect(op);
    }

    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        // Indirect usually inherits type from its first input
        op.get_in(0)
            .and_then(|vn| vn.read().unwrap().v_type.clone())
    }
}

pub struct TypeOpSegment;
impl TypeOp for TypeOpSegment {
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_SEGMENTOP
    }
    fn get_name(&self) -> &str {
        "SEGMENTOP"
    }
    fn get_flags(&self) -> u32 {
        0
    }
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
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_CPOOLREF
    }
    fn get_name(&self) -> &str {
        "CPOOLREF"
    }
    fn get_flags(&self) -> u32 {
        0
    }
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
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_NEW
    }
    fn get_name(&self) -> &str {
        "NEW"
    }
    fn get_flags(&self) -> u32 {
        0
    }
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
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_CALLOTHER
    }
    fn get_name(&self) -> &str {
        "CALLOTHER"
    }
    fn get_flags(&self) -> u32 {
        0
    }
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

/// Manager for TypeOps
///
/// This handles the mapping between OpCodes and their TypeOp implementations.
pub struct TypeOpManager {
    ops: Vec<Option<Box<dyn TypeOp>>>,
}

impl TypeOpManager {
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
        ops[OpCode::CPUI_TRUNC as usize] = Some(Box::new(TypeOpTrunc));

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

    pub fn get_op(&self, opcode: OpCode) -> Option<&dyn TypeOp> {
        self.ops[opcode as usize].as_ref().map(|o| o.as_ref())
    }
}

impl crate::op::PcodeOp {
    /// Push this operation to a language printer
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
