//! Call analysis and argument recovery
//!
//! This module implements heuristics to identify function arguments and return values
//! for Call operations, based on standard calling conventions (currently x86-64).

use crate::pcode::{Program, PcodeOp, Varnode};

/// Recover call arguments and return values based on calling convention
///
/// This pass injects register usage into CALL/CALLIND operations so that
/// subsequent analyses (Liveness, SSA) correctly track data flow across function calls.
///
/// Currently hardcoded for x86-64 System V ABI.
pub fn recover_call_semantics(program: &mut Program) {
    // x86-64 System V ABI argument registers
    // RDI, RSI, RDX, RCX, R8, R9
    // Offsets derived from X86_64RegisterMap
    let arg_regs = [
        (56, 8), // RDI
        (48, 8), // RSI
        (24, 8), // RDX
        (16, 8), // RCX
        (64, 8), // R8
        (72, 8), // R9
    ];

    // Return register: RAX (Offset 0, Size 8)
    let ret_reg = Varnode::new_register(0, 8);

    let op_count = program.operation_count();

    for i in 0..op_count {
        let op = &mut program.operations_mut()[i];

        if matches!(op.opcode(), PcodeOp::Call | PcodeOp::CallInd) {
            // 1. Add return value if missing
            // We assume functions return values in RAX.
            // If the function is void, this output will likely be dead code eliminated later
            // if it is not used.
            if op.output().is_none() {
                op.set_output(Some(ret_reg.clone()));
            }

            // 2. Add arguments
            // We assume standard calling convention registers are used.
            // We only add them if they are not already present to avoid duplicates.
            // Note: inputs[0] is the call target.

            // Create a local check to avoid borrow checker issues with op.inputs_mut() later
            let current_inputs = op.inputs().to_vec();

            for (offset, size) in &arg_regs {
                let reg = Varnode::new_register(*offset, *size);

                // Check if this register is already an input (ignoring target at index 0)
                let already_present = current_inputs.iter().skip(1).any(|inp| *inp == reg);

                if !already_present {
                    op.inputs_mut().push(reg);
                }
            }
        } else if matches!(op.opcode(), PcodeOp::Return) {
            // 3. Mark return register (RAX) as used by RETURN to prevent DCE
            // from removing calculations that contribute to the return value.
            if op.inputs().is_empty() {
                op.inputs_mut().push(ret_reg.clone());
            }
        }
    }
}
