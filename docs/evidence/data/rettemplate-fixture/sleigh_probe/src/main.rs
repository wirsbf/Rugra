// Probe (lane DU, RET-OP3-0001): dump the locked-oracle SLEIGH pcode for the
// RET family — `ret` (C3), `ret imm16` (C2 08 00), plus `call rel32` / `call
// rax` sanity anchors — to pin the exact op sequence the x86_lift.rs 'ret'
// arm must emit (same method as lane DL's CALL probe, HTTPD-CALL-PUSH-0001).
use anyhow::Result;
use rugra::opcodes::OpCode;
use rugra::sleigh_ffi::SleighCtx;

fn main() -> Result<()> {
    let mut ctx = SleighCtx::new().ok_or(anyhow::anyhow!("no ctx (run from repo root)"))?;
    for (name, value) in [
        ("addrsize", 2),
        ("opsize", 1),
        ("rexprefix", 0),
        ("longMode", 1),
    ] {
        ctx.try_set_context(name, value)?;
    }
    // space catalog
    let n = ctx.num_spaces();
    let mut names: Vec<String> = Vec::new();
    for i in 0..n {
        if let Some((_ty, name)) = ctx.space_info(i) {
            names.push(format!("{}={}", i, name));
        }
    }
    println!("spaces: {}", names.join(" "));

    let code = [
        0xc3,                          // @0 ret
        0xc2, 0x08, 0x00,              // @1 ret 0x8
        0xc2, 0x00, 0x80,              // @4 ret 0x8000
        0xe8, 0x40, 0x00, 0x00, 0x00,  // @7 call rel32 (+0x40)
        0xff, 0xd0,                    // @0xc call rax
    ];
    ctx.try_set_image(&code, 0)?;
    let mut off = 0u64;
    while (off as usize) < code.len() {
        let decoded = ctx.one_instruction(off)?;
        println!("@{:#x} step={}", off, decoded.step);
        for (i, op) in decoded.ops.iter().enumerate() {
            let opc = OpCode::from_i32(op.opcode)
                .map(|o| o.name().to_string())
                .unwrap_or_else(|| format!("?{}", op.opcode));
            let out = if op.has_output != 0 {
                format!("{}", vn(&op.output, &names))
            } else {
                "-".to_string()
            };
            let ins: Vec<String> = op.inputs.iter().map(|v| vn(v, &names)).collect();
            println!("  op[{i}] {opc} {out} <- {}", ins.join(", "));
        }
        off += decoded.step as u64;
    }
    Ok(())
}

fn vn(v: &rugra::sleigh_ffi::VarnodeC, names: &[String]) -> String {
    let sp = names
        .get(v.space as usize)
        .cloned()
        .unwrap_or_else(|| format!("sp{}", v.space));
    format!("{}:{:#x}({})", sp, v.offset, v.size)
}
// (appended helper — see probe body above)
