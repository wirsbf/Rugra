//! PcodeOp and PcodeOperation alignment verification logic.
//!
//! This module ensures that Rugra's P-code operations match Ghidra's
//! internal PcodeOp representation as defined in `op.hh`.

use crate::pcode::{PcodeOp, PcodeOperation, Varnode};
use crate::ffi::VarnodeFFI;
use crate::align::address::verify_seqnum;
use crate::align::varnode::verify_varnode;

/// Map Ghidra OpCode integers to Rugra PcodeOp enum
///
/// This mapping is based on Ghidra's opcodes.hh
pub fn map_ghidra_opcode(opcode: i32) -> Option<PcodeOp> {
    match opcode {
        1 => Some(PcodeOp::Copy),
        2 => Some(PcodeOp::Load),
        3 => Some(PcodeOp::Store),
        4 => Some(PcodeOp::Branch),
        5 => Some(PcodeOp::CBranch),
        6 => Some(PcodeOp::BranchInd),
        7 => Some(PcodeOp::Call),
        8 => Some(PcodeOp::CallInd),
        10 => Some(PcodeOp::Return),

        // Integer operations
        11 => Some(PcodeOp::IntEqual),
        12 => Some(PcodeOp::IntNotEqual),
        13 => Some(PcodeOp::IntSLess),
        14 => Some(PcodeOp::IntSLessEqual),
        15 => Some(PcodeOp::IntLess),
        16 => Some(PcodeOp::IntLessEqual),
        17 => Some(PcodeOp::IntZext),
        18 => Some(PcodeOp::IntSext),
        19 => Some(PcodeOp::IntAdd),
        20 => Some(PcodeOp::IntSub),
        24 => Some(PcodeOp::IntNeg),
        25 => Some(PcodeOp::IntNot),
        26 => Some(PcodeOp::IntXor),
        27 => Some(PcodeOp::IntAnd),
        28 => Some(PcodeOp::IntOr),
        29 => Some(PcodeOp::IntLeft),
        30 => Some(PcodeOp::IntRight),
        31 => Some(PcodeOp::IntSRight),
        32 => Some(PcodeOp::IntMult),
        33 => Some(PcodeOp::IntDiv),
        34 => Some(PcodeOp::IntSDiv),
        35 => Some(PcodeOp::IntRem),
        36 => Some(PcodeOp::IntSRem),

        // Boolean operations
        37 => Some(PcodeOp::BoolNot),
        38 => Some(PcodeOp::BoolXor),
        39 => Some(PcodeOp::BoolAnd),
        40 => Some(PcodeOp::BoolOr),

        // Floating point operations
        41 => Some(PcodeOp::FloatEqual),
        42 => Some(PcodeOp::FloatNotEqual),
        43 => Some(PcodeOp::FloatLess),
        44 => Some(PcodeOp::FloatLessEqual),
        47 => Some(PcodeOp::FloatAdd),
        48 => Some(PcodeOp::FloatDiv),
        49 => Some(PcodeOp::FloatMult),
        50 => Some(PcodeOp::FloatSub),
        51 => Some(PcodeOp::FloatNeg),
        52 => Some(PcodeOp::FloatAbs),
        53 => Some(PcodeOp::FloatSqrt),

        // Piece/Subpiece
        62 => Some(PcodeOp::Piece),
        63 => Some(PcodeOp::SubPiece),

        // Extensions
        72 => Some(PcodeOp::PopCount),
        73 => Some(PcodeOp::Lzcount),

        _ => None,
    }
}

/// Verify that a Rugra PcodeOp matches a Ghidra opcode
pub fn verify_opcode(rugra_op: PcodeOp, ghidra_opcode: i32) -> bool {
    match map_ghidra_opcode(ghidra_opcode) {
        Some(mapped_op) => {
            let matches = rugra_op == mapped_op;
            if !matches {
                eprintln!(
                    "[ALIGN DIFF] Opcode mismatch: Rugra {:?} != Ghidra opcode {}",
                    rugra_op, ghidra_opcode
                );
            }
            matches
        }
        None => {
            eprintln!(
                "[ALIGN DIFF] Unknown Ghidra opcode: {}",
                ghidra_opcode
            );
            false
        }
    }
}

/// Verify that a complete PcodeOperation aligns with Ghidra's representation
///
/// This checks:
/// - Opcode match
/// - SeqNum match
/// - Input count and values
/// - Output presence and value
pub fn verify_operation(
    rugra_op: &PcodeOperation,
    ghidra_opcode: i32,
    ghidra_addr: u64,
    ghidra_seq: u32,
    ghidra_inputs: &[VarnodeFFI],
    ghidra_output: Option<&VarnodeFFI>,
) -> bool {
    // 1. Verify opcode
    let opcode_match = verify_opcode(rugra_op.opcode(), ghidra_opcode);

    // 2. Verify sequence number
    let seqnum_match = verify_seqnum(&rugra_op.seqnum(), ghidra_addr, ghidra_seq);

    // 3. Verify input count
    let input_count_match = rugra_op.inputs().len() == ghidra_inputs.len();
    if !input_count_match {
        eprintln!(
            "[ALIGN DIFF] Input count mismatch at {}: Rugra {} != Ghidra {}",
            rugra_op.seqnum(),
            rugra_op.inputs().len(),
            ghidra_inputs.len()
        );
    }

    // 4. Verify inputs
    let inputs_match = if input_count_match {
        rugra_op.inputs().iter()
            .zip(ghidra_inputs.iter())
            .all(|(r, g)| verify_varnode(r, g))
    } else {
        false
    };

    // 5. Verify output
    let output_match = match (rugra_op.output(), ghidra_output) {
        (Some(r_out), Some(g_out)) => verify_varnode(r_out, g_out),
        (None, None) => true,
        _ => {
            eprintln!(
                "[ALIGN DIFF] Output presence mismatch at {}",
                rugra_op.seqnum()
            );
            false
        }
    };

    opcode_match && seqnum_match && input_count_match && inputs_match && output_match
}

/// Verify input list alignment
pub fn verify_inputs(rugra_inputs: &[Varnode], ghidra_inputs: &[VarnodeFFI]) -> bool {
    if rugra_inputs.len() != ghidra_inputs.len() {
        eprintln!(
            "[ALIGN DIFF] Input count mismatch: Rugra {} != Ghidra {}",
            rugra_inputs.len(),
            ghidra_inputs.len()
        );
        return false;
    }

    rugra_inputs.iter()
        .zip(ghidra_inputs.iter())
        .all(|(r, g)| verify_varnode(r, g))
}

/// Verify output alignment
pub fn verify_output(rugra_output: Option<&Varnode>, ghidra_output: Option<&VarnodeFFI>) -> bool {
    match (rugra_output, ghidra_output) {
        (Some(r), Some(g)) => verify_varnode(r, g),
        (None, None) => true,
        (Some(_), None) => {
            eprintln!("[ALIGN DIFF] Rugra has output but Ghidra doesn't");
            false
        }
        (None, Some(_)) => {
            eprintln!("[ALIGN DIFF] Ghidra has output but Rugra doesn't");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Address;
    use crate::pcode::{PcodeId, SeqNum};

    #[test]
    fn test_opcode_mapping() {
        assert_eq!(map_ghidra_opcode(1), Some(PcodeOp::Copy));
        assert_eq!(map_ghidra_opcode(19), Some(PcodeOp::IntAdd));
        assert_eq!(map_ghidra_opcode(999), None);
    }

    #[test]
    fn test_verify_opcode() {
        assert!(verify_opcode(PcodeOp::Copy, 1));
        assert!(verify_opcode(PcodeOp::IntAdd, 19));
        assert!(!verify_opcode(PcodeOp::Copy, 19));
    }

    #[test]
    fn test_verify_inputs() {
        let rugra_inputs = vec![
            Varnode::new_register(0, 4),
            Varnode::new_constant(42, 4),
        ];

        let ghidra_inputs = vec![
            VarnodeFFI { space_id: 1, offset: 0, size: 4 },
            VarnodeFFI { space_id: 4, offset: 42, size: 4 },
        ];

        assert!(verify_inputs(&rugra_inputs, &ghidra_inputs));
    }

    #[test]
    fn test_verify_output() {
        let rugra_out = Varnode::new_register(0, 4);
        let ghidra_out = VarnodeFFI { space_id: 1, offset: 0, size: 4 };

        assert!(verify_output(Some(&rugra_out), Some(&ghidra_out)));
        assert!(verify_output(None, None));
        assert!(!verify_output(Some(&rugra_out), None));
    }

    #[test]
    fn test_verify_operation_complete() {
        let inputs = vec![Varnode::new_register(0, 4)];
        let output = Some(Varnode::new_register(1, 4));

        let op = PcodeOperation::new(
            PcodeId::new(1),
            SeqNum::new(Address::new(0x1000), 0),
            PcodeOp::Copy,
            output,
            inputs,
        );

        let ghidra_inputs = vec![VarnodeFFI { space_id: 1, offset: 0, size: 4 }];
        let ghidra_output = VarnodeFFI { space_id: 1, offset: 1, size: 4 };

        assert!(verify_operation(
            &op,
            1,  // COPY opcode
            0x1000,
            0,
            &ghidra_inputs,
            Some(&ghidra_output)
        ));
    }
}
