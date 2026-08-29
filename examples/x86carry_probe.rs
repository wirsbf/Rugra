//! GLOBWORD-C3-CARRY-INJECT-0001 probe: dump SLEIGH pcode for the curl
//! file2string.part.0 strlen tail (0x3b5a..0x3b65) and the register map
//! around register-space offset 0x200, to compare with the Ghidra oracle.

use rugra::sleigh_ffi::SleighCtx;

fn main() -> anyhow::Result<()> {
    let mut ctx = SleighCtx::new().ok_or_else(|| anyhow::anyhow!("sla load failed"))?;

    let pspec = std::path::Path::new("sleigh_specs/x86-64.pspec");
    if pspec.exists() {
        ctx.load_pspec(pspec.to_str().unwrap_or_default());
    }
    let image = std::fs::read("examples/curl")?;
    ctx.try_set_image(&image, 0)?;

    // Space inventory (to map ids).
    println!("== spaces ==");
    let nspaces = ctx.num_spaces();
    let mut register_space = -1;
    for i in 0..nspaces {
        if let Some((ty, name)) = ctx.space_info(i) {
            println!("space[{i}] type={ty} name={name}");
            if name == "register" {
                register_space = i as i32;
            }
        }
    }

    // Register map: GPRs and the flags/RIP region (register space), to audit
    // x86_lift.rs's register-offset table against the oracle sla layout.
    let n = ctx.num_registers();
    println!("== GPR + RIP + flags registers (register space) ==");
    for i in 0..n {
        if let Some((name, space, offset, size)) = ctx.register_info(i) {
            if space == register_space
                && ((offset < 0x100 && size >= 4) || (0x1c0..=0x240).contains(&offset))
            {
                println!("reg name={name} space={space} off=0x{offset:x} size={size}");
            }
        }
    }

    // Readable opcode names for dumps.
    let opcode_name = |raw: i32| -> String {
        rugra::opcodes::OpCode::from_i32(raw)
            .map(|o| o.name().to_string())
            .unwrap_or_else(|| format!("op{raw}"))
    };

    println!("== pcode for strlen tail ==");
    let mut addr: u64 = 0x3b5a;
    let end: u64 = 0x3b65;
    while addr < end {
        let decoded = ctx.one_instruction(addr)?;
        let ops = &decoded.ops;
        println!("-- @0x{addr:x} step={}", decoded.step);
        for (i, op) in ops.iter().enumerate() {
            let name = opcode_name(op.opcode);
            let out = if op.has_output != 0 {
                format!("{}:0x{:x}:{}", op.output.space, op.output.offset, op.output.size)
            } else {
                "-".to_string()
            };
            let inputs = op
                .inputs
                .iter()
                .map(|v| format!("{}:0x{:x}:{}", v.space, v.offset, v.size))
                .collect::<Vec<_>>()
                .join(", ");
            println!("   [{i}] {name} out={out} in=({inputs})");
        }
        addr += decoded.step as u64;
    }
    Ok(())
}
