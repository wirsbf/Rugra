//! P-code operation codes
//!
//! Corresponds to Ghidra's `opcodes.hh`

use serde::{Deserialize, Serialize};
use std::fmt;

/// P-code operation type (OpCode in Ghidra)
///
/// This enum represents all possible P-code operations. Each operation
/// has specific semantics for how it operates on its input and output varnodes.
/// Prefixes match Ghidra's `CPUI_` naming convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum OpCode {
    // ===== Data Movement =====
    /// Copy value from input to output
    CPUI_COPY = 1,
    /// Load from memory
    CPUI_LOAD = 2,
    /// Store to memory
    CPUI_STORE = 3,

    // ===== Arithmetic Operations =====
    /// Integer addition
    CPUI_INT_ADD = 4,
    /// Integer subtraction
    CPUI_INT_SUB = 5,
    /// Integer multiplication
    CPUI_INT_MULT = 6,
    /// Unsigned integer division
    CPUI_INT_DIV = 7,
    /// Signed integer division
    CPUI_INT_SDIV = 8,
    /// Unsigned integer remainder/modulo
    CPUI_INT_REM = 9,
    /// Signed integer remainder/modulo
    CPUI_INT_SREM = 10,
    /// Integer negation
    CPUI_INT_NEG = 11,
    /// Unsigned integer carry
    CPUI_INT_CARRY = 12,
    /// Signed integer carry
    CPUI_INT_SCARRY = 13,
    /// Signed integer borrow
    CPUI_INT_SBORROW = 14,

    // ===== Bitwise Operations =====
    /// Bitwise AND
    CPUI_INT_AND = 15,
    /// Bitwise OR
    CPUI_INT_OR = 16,
    /// Bitwise XOR
    CPUI_INT_XOR = 17,
    /// Bitwise NOT
    CPUI_INT_NOT = 18,
    /// Left shift
    CPUI_INT_LEFT = 19,
    /// Logical right shift (zero-fill)
    CPUI_INT_RIGHT = 20,
    /// Arithmetic right shift (sign-extend)
    CPUI_INT_SRIGHT = 21,

    // ===== Comparison Operations =====
    /// Integer equality
    CPUI_INT_EQUAL = 22,
    /// Integer inequality
    CPUI_INT_NOTEQUAL = 23,
    /// Unsigned less than
    CPUI_INT_LESS = 24,
    /// Signed less than
    CPUI_INT_SLESS = 25,
    /// Unsigned less than or equal
    CPUI_INT_LESSEQUAL = 26,
    /// Signed less than or equal
    CPUI_INT_SLESSEQUAL = 27,

    // ===== Extension and Truncation =====
    /// Zero extension (unsigned)
    CPUI_INT_ZEXT = 28,
    /// Sign extension (signed)
    CPUI_INT_SEXT = 29,
    /// Truncation
    CPUI_TRUNC = 30,

    // ===== Floating Point Operations =====
    /// Floating point addition
    CPUI_FLOAT_ADD = 31,
    /// Floating point subtraction
    CPUI_FLOAT_SUB = 32,
    /// Floating point multiplication
    CPUI_FLOAT_MULT = 33,
    /// Floating point division
    CPUI_FLOAT_DIV = 34,
    /// Floating point negation
    CPUI_FLOAT_NEG = 35,
    /// Floating point absolute value
    CPUI_FLOAT_ABS = 36,
    /// Floating point square root
    CPUI_FLOAT_SQRT = 37,
    /// Floating point equality
    CPUI_FLOAT_EQUAL = 38,
    /// Floating point inequality
    CPUI_FLOAT_NOTEQUAL = 39,
    /// Floating point less than
    CPUI_FLOAT_LESS = 40,
    /// Floating point less than or equal
    CPUI_FLOAT_LESSEQUAL = 41,
    /// Floating point NaN check
    CPUI_FLOAT_NAN = 42,
    /// Float to float conversion
    CPUI_FLOAT_FLOAT2FLOAT = 43,
    /// Integer to float conversion
    CPUI_FLOAT_INT2FLOAT = 44,
    /// Float to integer conversion (truncate)
    CPUI_FLOAT_TRUNC = 45,
    /// Float ceiling
    CPUI_FLOAT_CEIL = 46,
    /// Float floor
    CPUI_FLOAT_FLOOR = 47,
    /// Float round
    CPUI_FLOAT_ROUND = 48,

    // ===== Control Flow =====
    /// Unconditional branch
    CPUI_BRANCH = 49,
    /// Conditional branch
    CPUI_CBRANCH = 50,
    /// Branch indirect (computed goto)
    CPUI_BRANCHIND = 51,
    /// Function call
    CPUI_CALL = 52,
    /// Indirect function call
    CPUI_CALLIND = 53,
    /// Return from function
    CPUI_RETURN = 54,

    // ===== Special Operations =====
    /// Piece/concatenate values
    CPUI_PIECE = 55,
    /// Extract sub-piece
    CPUI_SUBPIECE = 56,
    /// Boolean AND
    CPUI_BOOL_AND = 57,
    /// Boolean OR
    CPUI_BOOL_OR = 58,
    /// Boolean XOR
    CPUI_BOOL_XOR = 59,
    /// Boolean NOT
    CPUI_BOOL_NOT = 60,
    /// Population count (count set bits)
    CPUI_POPCOUNT = 61,
    /// Count leading zeros
    CPUI_LZCOUNT = 62,

    // ===== Additional Special Ops (from Ghidra) =====
    /// Function call with side-effects
    CPUI_CALLOTHER = 63,
    /// Phi-node for SSA
    CPUI_MULTIEQUAL = 64,
    /// Indirect reference/definition
    CPUI_INDIRECT = 65,
    /// Reference to constant pool
    CPUI_CPOOLREF = 66,
    /// Object creation
    CPUI_NEW = 67,
    /// Segmented address calculation
    CPUI_SEGMENTOP = 68,
    /// Pointer addition
    CPUI_PTRADD = 69,
    /// Pointer subtraction
    CPUI_PTRSUB = 70,
    /// Bit field extraction
    CPUI_EXTRACT = 71,
    /// Bit field insertion
    CPUI_INSERT = 72,

    /// Cast from one datatype to another (P-code annotation op).
    /// Mirrors Ghidra opcodes.hh:119 CPUI_CAST. The bit pattern is preserved;
    /// this op only annotates a metatype/size change. ActionSetCasts inserts
    /// it at the P-code layer, the print layer renders the cast syntax.
    CPUI_CAST = 73,

    /// No operation / placeholder
    CPUI_MAX = 74,
}

impl OpCode {
    pub fn name(&self) -> &'static str {
        match self {
            OpCode::CPUI_COPY => "COPY",
            OpCode::CPUI_LOAD => "LOAD",
            OpCode::CPUI_STORE => "STORE",
            OpCode::CPUI_INT_ADD => "INT_ADD",
            OpCode::CPUI_INT_SUB => "INT_SUB",
            OpCode::CPUI_INT_MULT => "INT_MULT",
            OpCode::CPUI_INT_DIV => "INT_DIV",
            OpCode::CPUI_INT_SDIV => "INT_SDIV",
            OpCode::CPUI_INT_REM => "INT_REM",
            OpCode::CPUI_INT_SREM => "INT_SREM",
            OpCode::CPUI_INT_NEG => "INT_NEG",
            OpCode::CPUI_INT_CARRY => "INT_CARRY",
            OpCode::CPUI_INT_SCARRY => "INT_SCARRY",
            OpCode::CPUI_INT_SBORROW => "INT_SBORROW",
            OpCode::CPUI_INT_AND => "INT_AND",
            OpCode::CPUI_INT_OR => "INT_OR",
            OpCode::CPUI_INT_XOR => "INT_XOR",
            OpCode::CPUI_INT_NOT => "INT_NOT",
            OpCode::CPUI_INT_LEFT => "INT_LEFT",
            OpCode::CPUI_INT_RIGHT => "INT_RIGHT",
            OpCode::CPUI_INT_SRIGHT => "INT_SRIGHT",
            OpCode::CPUI_INT_EQUAL => "INT_EQUAL",
            OpCode::CPUI_INT_NOTEQUAL => "INT_NOTEQUAL",
            OpCode::CPUI_INT_LESS => "INT_LESS",
            OpCode::CPUI_INT_SLESS => "INT_SLESS",
            OpCode::CPUI_INT_LESSEQUAL => "INT_LESSEQUAL",
            OpCode::CPUI_INT_SLESSEQUAL => "INT_SLESSEQUAL",
            OpCode::CPUI_INT_ZEXT => "INT_ZEXT",
            OpCode::CPUI_INT_SEXT => "INT_SEXT",
            OpCode::CPUI_TRUNC => "TRUNC",
            OpCode::CPUI_FLOAT_ADD => "FLOAT_ADD",
            OpCode::CPUI_FLOAT_SUB => "FLOAT_SUB",
            OpCode::CPUI_FLOAT_MULT => "FLOAT_MULT",
            OpCode::CPUI_FLOAT_DIV => "FLOAT_DIV",
            OpCode::CPUI_FLOAT_NEG => "FLOAT_NEG",
            OpCode::CPUI_FLOAT_ABS => "FLOAT_ABS",
            OpCode::CPUI_FLOAT_SQRT => "FLOAT_SQRT",
            OpCode::CPUI_FLOAT_EQUAL => "FLOAT_EQUAL",
            OpCode::CPUI_FLOAT_NOTEQUAL => "FLOAT_NOTEQUAL",
            OpCode::CPUI_FLOAT_LESS => "FLOAT_LESS",
            OpCode::CPUI_FLOAT_LESSEQUAL => "FLOAT_LESSEQUAL",
            OpCode::CPUI_FLOAT_NAN => "FLOAT_NAN",
            OpCode::CPUI_FLOAT_FLOAT2FLOAT => "FLOAT_FLOAT2FLOAT",
            OpCode::CPUI_FLOAT_INT2FLOAT => "FLOAT_INT2FLOAT",
            OpCode::CPUI_FLOAT_TRUNC => "FLOAT_TRUNC",
            OpCode::CPUI_FLOAT_CEIL => "FLOAT_CEIL",
            OpCode::CPUI_FLOAT_FLOOR => "FLOAT_FLOOR",
            OpCode::CPUI_FLOAT_ROUND => "FLOAT_ROUND",
            OpCode::CPUI_BRANCH => "BRANCH",
            OpCode::CPUI_CBRANCH => "CBRANCH",
            OpCode::CPUI_BRANCHIND => "BRANCHIND",
            OpCode::CPUI_CALL => "CALL",
            OpCode::CPUI_CALLIND => "CALLIND",
            OpCode::CPUI_RETURN => "RETURN",
            OpCode::CPUI_PIECE => "PIECE",
            OpCode::CPUI_SUBPIECE => "SUBPIECE",
            OpCode::CPUI_BOOL_AND => "BOOL_AND",
            OpCode::CPUI_BOOL_OR => "BOOL_OR",
            OpCode::CPUI_BOOL_XOR => "BOOL_XOR",
            OpCode::CPUI_BOOL_NOT => "BOOL_NOT",
            OpCode::CPUI_POPCOUNT => "POPCOUNT",
            OpCode::CPUI_LZCOUNT => "LZCOUNT",
            OpCode::CPUI_CALLOTHER => "CALLOTHER",
            OpCode::CPUI_MULTIEQUAL => "MULTIEQUAL",
            OpCode::CPUI_INDIRECT => "INDIRECT",
            OpCode::CPUI_CPOOLREF => "CPOOLREF",
            OpCode::CPUI_NEW => "NEW",
            OpCode::CPUI_SEGMENTOP => "SEGMENTOP",
            OpCode::CPUI_PTRADD => "PTRADD",
            OpCode::CPUI_PTRSUB => "PTRSUB",
            OpCode::CPUI_EXTRACT => "EXTRACT",
            OpCode::CPUI_INSERT => "INSERT",
            OpCode::CPUI_CAST => "CAST",
            OpCode::CPUI_MAX => "MAX",
        }
    }

    /// Convert from raw integer opcode to OpCode enum
    ///
    /// Used by the P-code injection bridge to convert `PcodeOpRaw.opcode`
    /// integer values into typed `OpCode` variants.
    pub fn from_i32(raw: i32) -> Option<OpCode> {
        match raw {
            1 => Some(OpCode::CPUI_COPY),
            2 => Some(OpCode::CPUI_LOAD),
            3 => Some(OpCode::CPUI_STORE),
            4 => Some(OpCode::CPUI_INT_ADD),
            5 => Some(OpCode::CPUI_INT_SUB),
            6 => Some(OpCode::CPUI_INT_MULT),
            7 => Some(OpCode::CPUI_INT_DIV),
            8 => Some(OpCode::CPUI_INT_SDIV),
            9 => Some(OpCode::CPUI_INT_REM),
            10 => Some(OpCode::CPUI_INT_SREM),
            11 => Some(OpCode::CPUI_INT_NEG),
            12 => Some(OpCode::CPUI_INT_CARRY),
            13 => Some(OpCode::CPUI_INT_SCARRY),
            14 => Some(OpCode::CPUI_INT_SBORROW),
            15 => Some(OpCode::CPUI_INT_AND),
            16 => Some(OpCode::CPUI_INT_OR),
            17 => Some(OpCode::CPUI_INT_XOR),
            18 => Some(OpCode::CPUI_INT_NOT),
            19 => Some(OpCode::CPUI_INT_LEFT),
            20 => Some(OpCode::CPUI_INT_RIGHT),
            21 => Some(OpCode::CPUI_INT_SRIGHT),
            22 => Some(OpCode::CPUI_INT_EQUAL),
            23 => Some(OpCode::CPUI_INT_NOTEQUAL),
            24 => Some(OpCode::CPUI_INT_LESS),
            25 => Some(OpCode::CPUI_INT_SLESS),
            26 => Some(OpCode::CPUI_INT_LESSEQUAL),
            27 => Some(OpCode::CPUI_INT_SLESSEQUAL),
            28 => Some(OpCode::CPUI_INT_ZEXT),
            29 => Some(OpCode::CPUI_INT_SEXT),
            30 => Some(OpCode::CPUI_TRUNC),
            31 => Some(OpCode::CPUI_FLOAT_ADD),
            32 => Some(OpCode::CPUI_FLOAT_SUB),
            33 => Some(OpCode::CPUI_FLOAT_MULT),
            34 => Some(OpCode::CPUI_FLOAT_DIV),
            35 => Some(OpCode::CPUI_FLOAT_NEG),
            36 => Some(OpCode::CPUI_FLOAT_ABS),
            37 => Some(OpCode::CPUI_FLOAT_SQRT),
            38 => Some(OpCode::CPUI_FLOAT_EQUAL),
            39 => Some(OpCode::CPUI_FLOAT_NOTEQUAL),
            40 => Some(OpCode::CPUI_FLOAT_LESS),
            41 => Some(OpCode::CPUI_FLOAT_LESSEQUAL),
            42 => Some(OpCode::CPUI_FLOAT_NAN),
            43 => Some(OpCode::CPUI_FLOAT_FLOAT2FLOAT),
            44 => Some(OpCode::CPUI_FLOAT_INT2FLOAT),
            45 => Some(OpCode::CPUI_FLOAT_TRUNC),
            46 => Some(OpCode::CPUI_FLOAT_CEIL),
            47 => Some(OpCode::CPUI_FLOAT_FLOOR),
            48 => Some(OpCode::CPUI_FLOAT_ROUND),
            49 => Some(OpCode::CPUI_BRANCH),
            50 => Some(OpCode::CPUI_CBRANCH),
            51 => Some(OpCode::CPUI_BRANCHIND),
            52 => Some(OpCode::CPUI_CALL),
            53 => Some(OpCode::CPUI_CALLIND),
            54 => Some(OpCode::CPUI_RETURN),
            55 => Some(OpCode::CPUI_PIECE),
            56 => Some(OpCode::CPUI_SUBPIECE),
            57 => Some(OpCode::CPUI_BOOL_AND),
            58 => Some(OpCode::CPUI_BOOL_OR),
            59 => Some(OpCode::CPUI_BOOL_XOR),
            60 => Some(OpCode::CPUI_BOOL_NOT),
            61 => Some(OpCode::CPUI_POPCOUNT),
            62 => Some(OpCode::CPUI_LZCOUNT),
            63 => Some(OpCode::CPUI_CALLOTHER),
            64 => Some(OpCode::CPUI_MULTIEQUAL),
            65 => Some(OpCode::CPUI_INDIRECT),
            66 => Some(OpCode::CPUI_CPOOLREF),
            67 => Some(OpCode::CPUI_NEW),
            68 => Some(OpCode::CPUI_SEGMENTOP),
            69 => Some(OpCode::CPUI_PTRADD),
            70 => Some(OpCode::CPUI_PTRSUB),
            71 => Some(OpCode::CPUI_EXTRACT),
            72 => Some(OpCode::CPUI_INSERT),
            73 => Some(OpCode::CPUI_CAST),
            74 => Some(OpCode::CPUI_MAX),
            _ => None,
        }
    }

    /// Check if this opcode is a control flow terminator (ends a basic block)
    pub fn is_block_terminator(&self) -> bool {
        matches!(
            self,
            OpCode::CPUI_BRANCH
                | OpCode::CPUI_CBRANCH
                | OpCode::CPUI_BRANCHIND
                | OpCode::CPUI_RETURN
        )
    }

    /// Check if this opcode is commutative (operand order doesn't matter)
    pub fn is_commutative(&self) -> bool {
        matches!(
            self,
            OpCode::CPUI_INT_ADD
                | OpCode::CPUI_INT_MULT
                | OpCode::CPUI_INT_AND
                | OpCode::CPUI_INT_OR
                | OpCode::CPUI_INT_XOR
                | OpCode::CPUI_INT_EQUAL
                | OpCode::CPUI_INT_NOTEQUAL
                | OpCode::CPUI_BOOL_AND
                | OpCode::CPUI_BOOL_OR
                | OpCode::CPUI_BOOL_XOR
                | OpCode::CPUI_FLOAT_ADD
                | OpCode::CPUI_FLOAT_MULT
                | OpCode::CPUI_FLOAT_EQUAL
                | OpCode::CPUI_FLOAT_NOTEQUAL
        )
    }

    /// Check if this opcode is a deterministic, side-effect-free operation
    /// suitable for CSE (Common Subexpression Elimination).
    ///
    /// Excludes LOAD/STORE (memory side-effects), branches, calls, and
    /// SSA-internal ops (MULTIEQUAL, INDIRECT).
    pub fn is_commutative_or_pure(&self) -> bool {
        matches!(
            self,
            // Arithmetic
            OpCode::CPUI_INT_ADD
                | OpCode::CPUI_INT_SUB
                | OpCode::CPUI_INT_MULT
                | OpCode::CPUI_INT_DIV
                | OpCode::CPUI_INT_SDIV
                | OpCode::CPUI_INT_REM
                | OpCode::CPUI_INT_SREM
                | OpCode::CPUI_INT_NEG
                | OpCode::CPUI_INT_CARRY
                | OpCode::CPUI_INT_SCARRY
                | OpCode::CPUI_INT_SBORROW
                // Bitwise
                | OpCode::CPUI_INT_AND
                | OpCode::CPUI_INT_OR
                | OpCode::CPUI_INT_XOR
                | OpCode::CPUI_INT_NOT
                | OpCode::CPUI_INT_LEFT
                | OpCode::CPUI_INT_RIGHT
                | OpCode::CPUI_INT_SRIGHT
                // Comparison
                | OpCode::CPUI_INT_EQUAL
                | OpCode::CPUI_INT_NOTEQUAL
                | OpCode::CPUI_INT_LESS
                | OpCode::CPUI_INT_SLESS
                | OpCode::CPUI_INT_LESSEQUAL
                | OpCode::CPUI_INT_SLESSEQUAL
                // Extension/Truncation
                | OpCode::CPUI_INT_ZEXT
                | OpCode::CPUI_INT_SEXT
                | OpCode::CPUI_TRUNC
                // Float arithmetic
                | OpCode::CPUI_FLOAT_ADD
                | OpCode::CPUI_FLOAT_SUB
                | OpCode::CPUI_FLOAT_MULT
                | OpCode::CPUI_FLOAT_DIV
                | OpCode::CPUI_FLOAT_NEG
                | OpCode::CPUI_FLOAT_ABS
                | OpCode::CPUI_FLOAT_SQRT
                | OpCode::CPUI_FLOAT_EQUAL
                | OpCode::CPUI_FLOAT_NOTEQUAL
                | OpCode::CPUI_FLOAT_LESS
                | OpCode::CPUI_FLOAT_LESSEQUAL
                | OpCode::CPUI_FLOAT_NAN
                // Boolean
                | OpCode::CPUI_BOOL_AND
                | OpCode::CPUI_BOOL_OR
                | OpCode::CPUI_BOOL_XOR
                | OpCode::CPUI_BOOL_NOT
                // Misc pure
                | OpCode::CPUI_POPCOUNT
                | OpCode::CPUI_LZCOUNT
                | OpCode::CPUI_PIECE
                | OpCode::CPUI_SUBPIECE
        )
    }
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Get the complementary OpCode for boolean-flip transformations.
/// Faithful to Ghidra's `get_booleanflip` (opcodes.cc:94-135). For a comparison
/// opcode, returns the negated opcode; `reorder` is set true when the operands
/// must be swapped to preserve semantics (e.g. `!(V < W) => W <= V`).
/// Returns `CPUI_MAX` if `opc` is not a flippable comparison.
///
/// Note: Rugra `CPUI_BOOL_NOT` == Ghidra `CPUI_BOOL_NEGATE`.
pub fn get_booleanflip(opc: OpCode, reorder: &mut bool) -> OpCode {
    match opc {
        OpCode::CPUI_INT_EQUAL => {
            *reorder = false;
            OpCode::CPUI_INT_NOTEQUAL
        }
        OpCode::CPUI_INT_NOTEQUAL => {
            *reorder = false;
            OpCode::CPUI_INT_EQUAL
        }
        OpCode::CPUI_INT_SLESS => {
            *reorder = true;
            OpCode::CPUI_INT_SLESSEQUAL
        }
        OpCode::CPUI_INT_SLESSEQUAL => {
            *reorder = true;
            OpCode::CPUI_INT_SLESS
        }
        OpCode::CPUI_INT_LESS => {
            *reorder = true;
            OpCode::CPUI_INT_LESSEQUAL
        }
        OpCode::CPUI_INT_LESSEQUAL => {
            *reorder = true;
            OpCode::CPUI_INT_LESS
        }
        // Ghidra BOOL_NEGATE == Rugra BOOL_NOT.
        OpCode::CPUI_BOOL_NOT => {
            *reorder = false;
            OpCode::CPUI_COPY
        }
        OpCode::CPUI_FLOAT_EQUAL => {
            *reorder = false;
            OpCode::CPUI_FLOAT_NOTEQUAL
        }
        OpCode::CPUI_FLOAT_NOTEQUAL => {
            *reorder = false;
            OpCode::CPUI_FLOAT_EQUAL
        }
        OpCode::CPUI_FLOAT_LESS => {
            *reorder = true;
            OpCode::CPUI_FLOAT_LESSEQUAL
        }
        OpCode::CPUI_FLOAT_LESSEQUAL => {
            *reorder = true;
            OpCode::CPUI_FLOAT_LESS
        }
        _ => OpCode::CPUI_MAX,
    }
}
