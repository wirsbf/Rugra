//! P-code operation behavior emulation.
//!
//! Corresponds to Ghidra's `opbehavior.hh` / `opbehavior.cc` (1364 lines).
//!
//! Each P-code opcode has an associated `OpBehavior` that describes how to
//! emulate the operation: `evaluateUnary`, `evaluateBinary`, `evaluateTernary`,
//! and reverse variants. This is used by constant folding (RuleCollapseConstants)
//! and by the jump-table analysis emulator.
//!
//! Key class: `OpBehavior` — base trait for all opcode behaviors.
//!
//! # Status
//! Core evaluate functions for the most common arithmetic/logic ops.
//! The full set of 60+ behaviors and registerInstructions are deferred.

use crate::opcodes::OpCode;

/// Mask of `bits` set bits.
fn mask(bits: usize) -> u64 {
    if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 }
}

/// Sign-extend a value from `in_size` bytes to full u64.
fn sign_extend(val: u64, in_size: usize) -> i64 {
    let bits = in_size * 8;
    if bits >= 64 { return val as i64; }
    let sign_bit = 1u64 << (bits - 1);
    if val & sign_bit != 0 {
        (val | (!mask(bits))) as i64
    } else {
        val as i64
    }
}

/// Evaluate a P-code operation on constant inputs.
/// Returns the result as a u64 masked to `size_out` bytes.
///
/// This implements the `evaluateUnary`/`evaluateBinary` methods of
/// Ghidra's OpBehavior subclasses.
pub fn evaluate_unary(opc: OpCode, size_out: usize, size_in: usize, in1: u64) -> Option<u64> {
    let out_mask = mask(size_out * 8);
    let in_mask = mask(size_in * 8);
    let result = match opc {
        OpCode::CPUI_COPY => in1 & out_mask,
        OpCode::CPUI_INT_ZEXT => in1 & out_mask,
        OpCode::CPUI_INT_SEXT => (sign_extend(in1 & in_mask, size_in) as u64) & out_mask,
        OpCode::CPUI_INT_NOT => (!in1) & out_mask,
        OpCode::CPUI_INT_NEG => {
            let m = in1 & in_mask;
            ((!m).wrapping_add(1)) & out_mask
        }
        OpCode::CPUI_BOOL_NOT => if in1 != 0 { 0 } else { 1 },
        OpCode::CPUI_INT_RIGHT => in1, // shift by 0 if no second input
        OpCode::CPUI_SUBPIECE => in1 & out_mask, // simplified
        _ => return None,
    };
    Some(result & out_mask)
}

/// Evaluate a binary P-code operation on constant inputs.
pub fn evaluate_binary(opc: OpCode, size_out: usize, size_in: usize, in1: u64, in2: u64) -> Option<u64> {
    let out_mask = mask(size_out * 8);
    let in_mask = mask(size_in * 8);
    let a = in1 & in_mask;
    let b = in2 & in_mask;
    let sa = sign_extend(a, size_in);
    let sb = sign_extend(b, size_in);
    let result = match opc {
        OpCode::CPUI_INT_ADD => a.wrapping_add(b) & out_mask,
        OpCode::CPUI_INT_SUB => a.wrapping_sub(b) & out_mask,
        OpCode::CPUI_INT_MULT => a.wrapping_mul(b) & out_mask,
        OpCode::CPUI_INT_DIV => {
            if b == 0 { return None; }
            (a / b) & out_mask
        }
        OpCode::CPUI_INT_SDIV => {
            if sb == 0 { return None; }
            (sa / sb) as u64 & out_mask
        }
        OpCode::CPUI_INT_REM => {
            if b == 0 { return None; }
            (a % b) & out_mask
        }
        OpCode::CPUI_INT_SREM => {
            if sb == 0 { return None; }
            (sa % sb) as u64 & out_mask
        }
        OpCode::CPUI_INT_AND => a & b,
        OpCode::CPUI_INT_OR => a | b,
        OpCode::CPUI_INT_XOR => a ^ b,
        OpCode::CPUI_INT_LEFT => (a << (b as u32 % (size_in * 8) as u32)) & out_mask,
        OpCode::CPUI_INT_RIGHT => (a >> (b as u32 % (size_in * 8) as u32)) & out_mask,
        OpCode::CPUI_INT_SRIGHT => ((sa >> (b as u32 % (size_in * 8) as u32)) as u64) & out_mask,
        OpCode::CPUI_INT_EQUAL => if a == b { 1 } else { 0 },
        OpCode::CPUI_INT_NOTEQUAL => if a != b { 1 } else { 0 },
        OpCode::CPUI_INT_LESS => if a < b { 1 } else { 0 },
        OpCode::CPUI_INT_SLESS => if sa < sb { 1 } else { 0 },
        OpCode::CPUI_INT_LESSEQUAL => if a <= b { 1 } else { 0 },
        OpCode::CPUI_INT_SLESSEQUAL => if sa <= sb { 1 } else { 0 },
        OpCode::CPUI_INT_CARRY => {
            let sum = a.wrapping_add(b);
            if sum < a { 1 } else { 0 }
        }
        OpCode::CPUI_INT_SCARRY => {
            let sum = (sa.wrapping_add(sb)) as u64;
            let carry = (a ^ sum) & (b ^ sum) & (1u64 << (size_in * 8 - 1));
            if carry != 0 { 1 } else { 0 }
        }
        OpCode::CPUI_INT_SBORROW => {
            let diff = a.wrapping_sub(b);
            let borrow = (a ^ b) & (a ^ diff) & (1u64 << (size_in * 8 - 1));
            if borrow != 0 { 1 } else { 0 }
        }
        OpCode::CPUI_BOOL_AND => if a != 0 && b != 0 { 1 } else { 0 },
        OpCode::CPUI_BOOL_OR => if a != 0 || b != 0 { 1 } else { 0 },
        OpCode::CPUI_BOOL_XOR => if (a != 0) != (b != 0) { 1 } else { 0 },
        _ => return None,
    };
    Some(result & out_mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_add() {
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_ADD, 4, 4, 3, 5), Some(8));
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_ADD, 4, 4, 0xffffffff, 1), Some(0));
    }

    #[test]
    fn test_evaluate_sub() {
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_SUB, 4, 4, 10, 3), Some(7));
    }

    #[test]
    fn test_evaluate_and_or_xor() {
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_AND, 4, 4, 0xff, 0x0f), Some(0x0f));
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_OR, 4, 4, 0xf0, 0x0f), Some(0xff));
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_XOR, 4, 4, 0xff, 0x0f), Some(0xf0));
    }

    #[test]
    fn test_evaluate_shifts() {
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_LEFT, 4, 4, 1, 4), Some(16));
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_RIGHT, 4, 4, 256, 4), Some(16));
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_SRIGHT, 4, 4, 0x80000000, 1), Some(0xc0000000));
    }

    #[test]
    fn test_evaluate_compare() {
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_EQUAL, 4, 4, 5, 5), Some(1));
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_NOTEQUAL, 4, 4, 5, 6), Some(1));
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_LESS, 4, 4, 3, 5), Some(1));
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_SLESS, 4, 4, 0xffffffff, 1), Some(1));
    }

    #[test]
    fn test_evaluate_unary() {
        assert_eq!(evaluate_unary(OpCode::CPUI_INT_NOT, 4, 4, 0), Some(0xffffffff));
        assert_eq!(evaluate_unary(OpCode::CPUI_INT_NEG, 4, 4, 5), Some(0xfffffffb));
        assert_eq!(evaluate_unary(OpCode::CPUI_INT_SEXT, 2, 1, 0xff), Some(0xffff));
    }
}
