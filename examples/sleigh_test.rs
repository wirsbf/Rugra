//! Minimal smoke test for Rugra's direct Ghidra SLEIGH FFI.

use anyhow::{ensure, Context, Result};
use rugra::sleigh_ffi::SleighCtx;

fn main() -> Result<()> {
    let mut ctx = SleighCtx::new().context("failed to load sleigh_specs/x86-64.sla")?;
    ctx.load_pspec("sleigh_specs/x86-64.pspec");

    // MOV RAX,RDI; RET.  In x86-64 context the first instruction is three
    // bytes and produces a COPY.  Without pspec defaults it decodes as a
    // one-byte instruction, so this also checks context initialization.
    let code = [0x48, 0x89, 0xf8, 0xc3];
    ctx.set_image(&code, 0);
    let length = ctx
        .instruction_length(0)
        .context("SLEIGH rejected the first instruction")?;
    let ops = ctx.decode(0);

    ensure!(
        length == 3,
        "expected x86-64 instruction length 3, got {length}"
    );
    ensure!(!ops.is_empty(), "expected MOV RAX,RDI to emit p-code");

    println!("sleigh.context=x86:LE:64:default");
    println!("sleigh.spaces={}", ctx.num_spaces());
    println!("sleigh.registers={}", ctx.num_registers());
    println!("instruction.length={length}");
    for (index, op) in ops.iter().enumerate() {
        println!(
            "op[{index}].opcode={}:inputs={}:output={}",
            op.opcode, op.num_inputs, op.has_output
        );
    }
    Ok(())
}
