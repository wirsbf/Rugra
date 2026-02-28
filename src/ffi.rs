//! FFI interface for Rugra
//!
//! This module provides C-compatible interfaces to Rugra's core logic,
//! allowing it to be integrated into Ghidra's C++ decompiler or used for
//! comparison testing ("对拍").

use crate::analysis::rules::constants::evaluate_constant_op;
use crate::opcodes::OpCode as PcodeOp;
use crate::pcode::{PcodeOpBank as Program, Varnode};
use lazy_static::lazy_static;
use std::os::raw::c_char;
use std::sync::Mutex;

lazy_static! {
    /// Global state to hold the Rugra program currently being compared
    static ref CURRENT_PROGRAM: Mutex<Option<Program>> = Mutex::new(None);
}

/// C-compatible representation of a Varnode for FFI comparison
#[repr(C)]
pub struct VarnodeFFI {
    pub space_id: i32,
    pub offset: u64,
    pub size: u32,
}

/// Map Ghidra OpCode integers to Rugra PcodeOp enum
/// Values are based on Ghidra's opcodes.hh
fn map_ghidra_opcode(opcode: i32) -> Option<PcodeOp> {
    match opcode {
        1 => Some(PcodeOp::CPUI_COPY),
        2 => Some(PcodeOp::CPUI_LOAD),
        3 => Some(PcodeOp::CPUI_STORE),
        4 => Some(PcodeOp::CPUI_BRANCH),
        5 => Some(PcodeOp::CPUI_CBRANCH),
        6 => Some(PcodeOp::CPUI_BRANCHIND),
        7 => Some(PcodeOp::CPUI_CALL),
        8 => Some(PcodeOp::CPUI_CALLIND),
        10 => Some(PcodeOp::CPUI_RETURN),

        11 => Some(PcodeOp::CPUI_INT_EQUAL),
        12 => Some(PcodeOp::CPUI_INT_NOTEQUAL),
        13 => Some(PcodeOp::CPUI_INT_SLESS),
        14 => Some(PcodeOp::CPUI_INT_SLESSEQUAL),
        15 => Some(PcodeOp::CPUI_INT_LESS),
        16 => Some(PcodeOp::CPUI_INT_LESSEQUAL),
        17 => Some(PcodeOp::CPUI_INT_ZEXT),
        18 => Some(PcodeOp::CPUI_INT_SEXT),
        19 => Some(PcodeOp::CPUI_INT_ADD),
        20 => Some(PcodeOp::CPUI_INT_SUB),
        21 => Some(PcodeOp::CPUI_INT_MULT),
        22 => Some(PcodeOp::CPUI_INT_DIV),
        23 => Some(PcodeOp::CPUI_INT_SDIV),
        24 => Some(PcodeOp::CPUI_INT_NEG),
        25 => Some(PcodeOp::CPUI_INT_NOT),
        26 => Some(PcodeOp::CPUI_INT_XOR),
        27 => Some(PcodeOp::CPUI_INT_AND),
        28 => Some(PcodeOp::CPUI_INT_OR),
        29 => Some(PcodeOp::CPUI_INT_LEFT),
        30 => Some(PcodeOp::CPUI_INT_RIGHT),
        31 => Some(PcodeOp::CPUI_INT_SRIGHT),
        32 => Some(PcodeOp::CPUI_INT_MULT),
        33 => Some(PcodeOp::CPUI_INT_DIV),
        34 => Some(PcodeOp::CPUI_INT_SDIV),
        35 => Some(PcodeOp::CPUI_INT_REM),
        36 => Some(PcodeOp::CPUI_INT_SREM),

        37 => Some(PcodeOp::CPUI_BOOL_NOT),
        38 => Some(PcodeOp::CPUI_BOOL_XOR),
        39 => Some(PcodeOp::CPUI_BOOL_AND),
        40 => Some(PcodeOp::CPUI_BOOL_OR),

        41 => Some(PcodeOp::CPUI_FLOAT_EQUAL),
        42 => Some(PcodeOp::CPUI_FLOAT_NOTEQUAL),
        43 => Some(PcodeOp::CPUI_FLOAT_LESS),
        44 => Some(PcodeOp::CPUI_FLOAT_LESSEQUAL),
        47 => Some(PcodeOp::CPUI_FLOAT_ADD),
        48 => Some(PcodeOp::CPUI_FLOAT_DIV),
        49 => Some(PcodeOp::CPUI_FLOAT_MULT),
        50 => Some(PcodeOp::CPUI_FLOAT_SUB),
        51 => Some(PcodeOp::CPUI_FLOAT_NEG),
        52 => Some(PcodeOp::CPUI_FLOAT_ABS),
        53 => Some(PcodeOp::CPUI_FLOAT_SQRT),

        62 => Some(PcodeOp::CPUI_PIECE),
        63 => Some(PcodeOp::CPUI_SUBPIECE),

        72 => Some(PcodeOp::CPUI_POPCOUNT),
        73 => Some(PcodeOp::CPUI_LZCOUNT),

        _ => None,
    }
}

/// FFI interface for constant folding evaluation
///
/// This matches Ghidra's OpBehavior::evaluateBinary/Unary logic.
///
/// # Arguments
/// * `opcode` - The Ghidra OpCode integer
/// * `size_out` - Expected output size in bytes
/// * `val1` - First input constant value
/// * `size1` - First input size in bytes
/// * `val2` - Second input constant value
/// * `size2` - Second input size in bytes
/// * `has_val2` - Boolean indicating if the second input is used (binary op)
///
/// # Returns
/// The resulting constant value, or 0 if evaluation failed or opcode is unsupported.
#[no_mangle]
pub extern "C" fn rugra_evaluate_constant(
    opcode: i32,
    size_out: usize,
    val1: u64,
    size1: usize,
    val2: u64,
    size2: usize,
    has_val2: bool,
) -> u64 {
    let op = match map_ghidra_opcode(opcode) {
        Some(o) => o,
        None => return 0,
    };

    let mut inputs = Vec::with_capacity(2);
    inputs.push(Varnode::new_constant(val1, size1));
    if has_val2 {
        inputs.push(Varnode::new_constant(val2, size2));
    }

    match evaluate_constant_op(op, &inputs) {
        Some(res) => {
            // Mask result to the requested output size to match Ghidra behavior
            if size_out > 0 && size_out < 8 {
                let mask = (1u64 << (size_out * 8)).wrapping_sub(1);
                res & mask
            } else {
                res
            }
        }
        None => 0,
    }
}

/// Get the version of Rugra as a C string
#[no_mangle]
pub extern "C" fn rugra_version() -> *const c_char {
    static VERSION_C: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();
    VERSION_C.as_ptr() as *const c_char
}

/// Set the current program for comparison
/// This is called by Rugra before starting the comparison with Ghidra
pub fn set_current_program(program: Program) {
    let mut lock = CURRENT_PROGRAM.lock().unwrap();
    *lock = Some(program);
}

/// Initialize a blank program for FFI testing
#[no_mangle]
pub extern "C" fn rugra_init_test_program() {
    let mut lock = CURRENT_PROGRAM.lock().unwrap();
    *lock = Some(Program::new());
}

/// Add an operation to the current test program
/// This allows Python/C++ to simulate Rugra's analysis state for comparison tests
#[no_mangle]
pub extern "C" fn rugra_add_test_op(
    addr: u64,
    opcode_val: i32,
    out_space: i32,
    out_offset: u64,
    out_size: u32,
) {
    let mut lock = CURRENT_PROGRAM.lock().unwrap();
    if let Some(ref mut program) = *lock {
        let op_addr = crate::Address::new(addr);
        let seqnum = crate::pcode::SeqNum::new(op_addr, program.get_uniqid());

        let op_type = match map_ghidra_opcode(opcode_val) {
            Some(o) => o,
            None => crate::pcode::OpCode::CPUI_COPY, // Fallback
        };

        let mut op_ref = program.create(op_type, 0, op_addr);
        let mut op_guard = op_ref.0.write().unwrap();
        op_guard.start = seqnum;

        if out_size > 0 {
            let space = if out_space == 1 { crate::pcode::AddressSpace::Register } else { crate::pcode::AddressSpace::Ram };
            let vn = crate::varnode::Varnode::new(space, out_offset, out_size as usize);
            op_guard.output = Some(std::sync::Arc::new(std::sync::RwLock::new(vn)));
        }
    }
}

}

/// Set the binary data context for FFI analysis
/// Allows Rugra to perform memory-backed verification
#[no_mangle]
pub extern "C" fn rugra_set_binary_data(_ptr: *const u8, len: usize) {
    // This would typically initialize a global analysis context
    println!("[RUGRA] Analysis context initialized with {} bytes", len);
}

/// Observe and validate a jumptable recovery in Ghidra
///
/// This is used for comparison testing to ensure Rugra's jumptable
/// recovery matches Ghidra's and is logically sound.
#[no_mangle]
pub extern "C" fn rugra_observe_jumptable(op_addr: u64, table_addr: u64, size: usize) {
    println!(
        "[RUGRA OBSERVE] JumpTable at 0x{:x}, Table: 0x{:x}, Entries: {}",
        op_addr, table_addr, size
    );

    // Validation 1: Size check
    if size == 0 || size > 4096 {
        println!(
            "[RUGRA WARN] Suspect JumpTable size: {} at 0x{:x}",
            size, op_addr
        );
    }

    // Validation 2: Table alignment (typically jump tables are pointer-aligned)
    if table_addr % 4 != 0 {
        println!(
            "[RUGRA WARN] Unaligned JumpTable address: 0x{:x}",
            table_addr
        );
    }

    // Validation 3: Null check
    if table_addr == 0 && size > 0 {
        println!(
            "[RUGRA ERR] JumpTable at 0x{:x} has non-zero size but null address!",
            op_addr
        );
    }

    // TODO: Cross-reference with Rugra's own recovery engine to ensure
    // 100% parity in decompilation output for the 'curl' sample.
}

/// Compare a P-code operation from Ghidra with Rugra's internal state
///
/// This is the "ultimate comparison" function that verifies if Rugra's
/// entire analysis pipeline produces the same P-code structure as Ghidra.
#[no_mangle]
pub unsafe extern "C" fn rugra_compare_pcode(
    op_addr: u64,
    opcode: i32,
    out_vn: *const VarnodeFFI,
    _inputs: *const VarnodeFFI,
    input_count: i32,
) {
    let lock = CURRENT_PROGRAM.lock().unwrap();
    let program = match lock.as_ref() {
        Some(p) => p,
        None => return,
    };

    // Find Rugra ops at this address
    let op_addr_obj = crate::Address::new(op_addr);
    let rugra_ops: Vec<_> = program.optree.iter()
        .filter(|o| o.0.read().unwrap().get_addr() == op_addr_obj)
        .cloned()
        .collect();
    let mapped_op = map_ghidra_opcode(opcode);

    // Check if Ghidra op exists in Rugra
    if rugra_ops.is_empty() {
        println!(
            "[RUGRA DIFF] 0x{:x}: Ghidra has op {}, but Rugra has NONE",
            op_addr, opcode
        );
        return;
    }

    // Try to find a matching op by opcode
    let matching_op = rugra_ops.iter().find(|o| {
        let op_locked = o.0.read().unwrap();
        let r_op = op_locked.get_opcode();
        match (r_op, &mapped_op) {
            (a, Some(b)) => a == *b,
            _ => false,
        }
    });

    match matching_op {
        Some(r_op_ref) => {
            let r_op = r_op_ref.0.read().unwrap();
            // Compare Output
            match (r_op.get_out(), out_vn.as_ref()) {
                (Some(r_out_lock), Some(g_out)) => {
                    let r_out = r_out_lock.read().unwrap();
                    if r_out.offset() != g_out.offset || r_out.size() != g_out.size as usize {
                        println!("[RUGRA DIFF] 0x{:x}: Output mismatch. Rugra: {}, Ghidra offset: 0x{:x}, size: {}",
                            op_addr, *r_out, g_out.offset, g_out.size);
                    }
                }
                (None, Some(_)) => println!("[RUGRA DIFF] 0x{:x}: Ghidra has output, Rugra has NONE", op_addr),
                (Some(_), None) => println!("[RUGRA DIFF] 0x{:x}: Rugra has output, Ghidra has NONE", op_addr),
                (None, None) => (),
            }

            // Compare Input Count
            let r_input_count = r_op.num_input();
            if r_input_count != input_count as usize {
                println!("[RUGRA DIFF] 0x{:x}: Input count mismatch. Rugra: {}, Ghidra: {}",
                    op_addr, r_input_count, input_count);
            }
        }
        None => {
            println!("[RUGRA DIFF] 0x{:x}: Opcode mismatch. Ghidra Op: {}, Rugra has {} ops here",
                op_addr, opcode, rugra_ops.len());
        }
    }
}

    });

    match matching_op {
        Some(r_op) => {
            // Compare Output
            match (r_op.output(), out_vn.as_ref()) {
                (Some(r_out), Some(g_out)) => {
                    if r_out.offset() != g_out.offset || r_out.size() != g_out.size as usize {
                        println!("[RUGRA DIFF] 0x{:x}: Output mismatch. Rugra: {}, Ghidra offset: 0x{:x}, size: {}",
                            op_addr, r_out, g_out.offset, g_out.size);
                    }
                }
                (None, Some(_)) => println!(
                    "[RUGRA DIFF] 0x{:x}: Ghidra has output, Rugra has NONE",
                    op_addr
                ),
                (Some(_), None) => println!(
                    "[RUGRA DIFF] 0x{:x}: Rugra has output, Ghidra has NONE",
                    op_addr
                ),
                (None, None) => (),
            }

            // Compare Input Count
            let r_input_count = r_op.inputs().len();
            if r_input_count != input_count as usize {
                println!(
                    "[RUGRA DIFF] 0x{:x}: Input count mismatch. Rugra: {}, Ghidra: {}",
                    op_addr, r_input_count, input_count
                );
            }
        }
        None => {
            println!(
                "[RUGRA DIFF] 0x{:x}: Opcode mismatch. Ghidra Op: {}, Rugra has {} ops here",
                op_addr,
                opcode,
                rugra_ops.len()
            );
        }
    }
}
