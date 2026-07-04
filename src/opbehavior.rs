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

// RUGRA-GLUE: mask (no Ghidra counterpart found)
/// Mask of `bits` set bits.
fn mask(bits: usize) -> u64 {
    if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 }
}

// RUGRA-GLUE: sign_extend (no Ghidra counterpart found)
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

// RUGRA-GLUE: evaluate_unary (no Ghidra counterpart found)
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
        OpCode::CPUI_INT_NEGATE => (!in1) & out_mask,
        OpCode::CPUI_INT_2COMP => {
            let m = in1 & in_mask;
            ((!m).wrapping_add(1)) & out_mask
        }
        OpCode::CPUI_BOOL_NEGATE => if in1 != 0 { 0 } else { 1 },
        OpCode::CPUI_SUBPIECE => in1 & out_mask,
        OpCode::CPUI_POPCOUNT => (in1 & in_mask).count_ones() as u64 & out_mask,
        OpCode::CPUI_LZCOUNT => {
            let v = in1 & in_mask;
            let bits = size_in * 8;
            if v == 0 { bits as u64 } else { v.leading_zeros() as u64 - (64 - bits) as u64 }
        }
        _ => return None,
    };
    Some(result & out_mask)
}

// RUGRA-GLUE: evaluate_binary (no Ghidra counterpart found)
/// Evaluate a binary P-code operation on constant inputs.
pub fn evaluate_binary(opc: OpCode, size_out: usize, size_in: usize, in1: u64, in2: u64) -> Option<u64> {
    let out_mask = mask(size_out * 8);
    let in_mask = mask(size_in * 8);
    let a = in1 & in_mask;
    let b = in2 & in_mask;
    let sa = sign_extend(a, size_in);
    let sb = sign_extend(b, size_in);
    let shift_amt = (b % (size_in as u64 * 8)) as u32;
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
        OpCode::CPUI_INT_LEFT => (a << shift_amt) & out_mask,
        OpCode::CPUI_INT_RIGHT => (a >> shift_amt) & out_mask,
        OpCode::CPUI_INT_SRIGHT => ((sa >> shift_amt) as u64) & out_mask,
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
        OpCode::CPUI_PTRADD => a.wrapping_add(b.wrapping_mul(1)) & out_mask, // simplified: wordsize=1
        OpCode::CPUI_PTRSUB => a.wrapping_add(b) & out_mask,
        OpCode::CPUI_PIECE => {
            // PIECE(high, low): high is the more-significant piece
            (a << (size_in * 8)) | (b & in_mask)
        },
        OpCode::CPUI_SUBPIECE => {
            // SUBPIECE is unary but may appear here with 2 inputs in some contexts
            in1 & out_mask
        },
        _ => return None,
    };
    Some(result & out_mask)
}

// RUGRA-GLUE: evaluate_ternary (no Ghidra counterpart found)
/// Evaluate a ternary P-code operation on constant inputs.
/// Corresponds to `OpBehavior::evaluateTernary`.
pub fn evaluate_ternary(opc: OpCode, size_out: usize, size_in: usize, in1: u64, in2: u64, in3: u64) -> Option<u64> {
    let out_mask = mask(size_out * 8);
    let in_mask = mask(size_in * 8);
    let a = in1 & in_mask;
    let b = in2 & in_mask;
    let c = in3; // third input may have different size
    let result = match opc {
        OpCode::CPUI_PTRADD => {
            // PTRADD(base, index, sizeMult): base + index * sizeMult
            let mult = c;
            a.wrapping_add(b.wrapping_mul(mult)) & out_mask
        }
        _ => return None,
    };
    Some(result & out_mask)
}

// RUGRA-GLUE: recover_input_unary (no Ghidra counterpart found)
/// Recover input for a unary op (inverse of evaluate_unary).
/// Corresponds to `OpBehavior::recoverInputUnary`.
pub fn recover_input_unary(opc: OpCode, size_out: usize, out: u64, size_in: usize) -> Option<u64> {
    let in_mask = mask(size_in * 8);
    let result = match opc {
        OpCode::CPUI_COPY => out & in_mask,
        OpCode::CPUI_INT_ZEXT => out & in_mask,
        OpCode::CPUI_INT_SEXT => out & in_mask,
        OpCode::CPUI_INT_NEGATE => (!out) & in_mask,
        OpCode::CPUI_INT_2COMP => {
            ((!out).wrapping_add(1)) & in_mask
        }
        OpCode::CPUI_BOOL_NEGATE => if out != 0 { 0 } else { 1 },
        _ => return None,
    };
    Some(result)
}

// RUGRA-GLUE: recover_input_binary (no Ghidra counterpart found)
/// Recover input for a binary op (inverse of evaluate_binary).
/// Corresponds to `OpBehavior::recoverInputBinary`.
pub fn recover_input_binary(opc: OpCode, slot: usize, size_out: usize, out: u64, size_in: usize, other: u64) -> Option<u64> {
    let in_mask = mask(size_in * 8);
    let result = match opc {
        OpCode::CPUI_INT_ADD => (out.wrapping_sub(other)) & in_mask,
        OpCode::CPUI_INT_SUB => {
            if slot == 0 { out.wrapping_add(other) & in_mask }
            else { other.wrapping_sub(out) & in_mask }
        }
        OpCode::CPUI_INT_MULT => {
            if other == 0 { return None; }
            (out / other) & in_mask
        }
        OpCode::CPUI_INT_AND => {
            // out = in[slot] & other → in[slot] must have all bits of out set
            // and only bits in other can be set
            out & in_mask
        }
        OpCode::CPUI_INT_OR => {
            out & in_mask
        }
        OpCode::CPUI_INT_XOR => {
            (out ^ other) & in_mask
        }
        // Faithful to Ghidra OpBehaviorIntLeft::recoverInputBinary (cc:443):
        // slot==0 (the value being shifted): out >> shift_amount.
        // slot==1 (the shift amount): cannot recover (return None).
        OpCode::CPUI_INT_LEFT => {
            if slot != 0 || other as usize >= size_out * 8 {
                return None;
            }
            // Check no high bits were lost: (out << (bits-sa)) & mask must be 0.
            let sa = other as usize;
            let full_mask = mask(size_out * 8);
            if (out << (size_out * 8 - sa)) & full_mask != 0 {
                return None; // Output not in range of left shift
            }
            (out >> sa) & in_mask
        }
        _ => return None,
    };
    Some(result)
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
        assert_eq!(evaluate_unary(OpCode::CPUI_INT_NEGATE, 4, 4, 0), Some(0xffffffff));
        assert_eq!(evaluate_unary(OpCode::CPUI_INT_2COMP, 4, 4, 5), Some(0xfffffffb));
        assert_eq!(evaluate_unary(OpCode::CPUI_INT_SEXT, 2, 1, 0xff), Some(0xffff));
    }

    #[test]
    fn test_recover_input_left() {
        // INT_LEFT: 1 << 4 = 16. Recover slot 0: 16 >> 4 = 1.
        // Signature: (opc, slot, size_out, out, size_in, other)
        assert_eq!(recover_input_binary(OpCode::CPUI_INT_LEFT, 0, 4, 16, 4, 4), Some(1));
        // slot 1 (shift amount) cannot be recovered.
        assert_eq!(recover_input_binary(OpCode::CPUI_INT_LEFT, 1, 4, 16, 4, 1), None);
        // Shift >= size*8 is invalid.
        assert_eq!(recover_input_binary(OpCode::CPUI_INT_LEFT, 0, 4, 16, 4, 32), None);
    }

    #[test]
    fn test_recover_input_add_sub() {
        // INT_ADD: 3 + 4 = 7. Recover slot 0: 7 - 4 = 3.
        // Signature: (opc, slot, size_out, out, size_in, other)
        assert_eq!(recover_input_binary(OpCode::CPUI_INT_ADD, 0, 4, 7, 4, 4), Some(3));
        // INT_SUB slot 0: 7 - 4 = 3. Recover: 3 + 4 = 7.
        assert_eq!(recover_input_binary(OpCode::CPUI_INT_SUB, 0, 4, 3, 4, 4), Some(7));
        // INT_SUB slot 1: 7 - 4 = 3. Recover: 7 - 3 = 4.
        assert_eq!(recover_input_binary(OpCode::CPUI_INT_SUB, 1, 4, 3, 4, 7), Some(4));
    }
}
