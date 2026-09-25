// Fixture (RET-OP3-0001, lane DU): lift `ret` (C3) and `ret imm16` (C2,
// 0x08 and 0x8000 forms) through the iced X86Lifter and print the raw ops
// in the same format as the locked-oracle .sla probe dump
// (/dev/shm/rugra-tests/sb-rettemplate/sleigh_probe) so the two can be
// diffed op-by-op: same inputs (same bytes, same context), same observable
// output (op sequence, opcode, output varnode, input varnodes).
use anyhow::Result;
use rugra::disasm::{Disassembler as _, X86Lifter, X86_64Disassembler};
use rugra::opcodes::OpCode;
use rugra::pcoderaw::PcodeOpRaw;

fn dump_ops(ops: &[PcodeOpRaw]) {
    for (i, op) in ops.iter().enumerate() {
        let opc = op.get_opcode();
        let name = OpCode::from_i32(opc)
            .map(|o| o.name().to_string())
            .unwrap_or_else(|| format!("?{}", opc));
        let out = op
            .output()
            .map(|v| format!("{}={}:0x{:x}({})", v.space.space_id() as u64, v.space, v.offset, v.size))
            .unwrap_or_else(|| "-".to_string());
        let ins: Vec<String> = op
            .inputs()
            .iter()
            .map(|v| format!("{}={}:0x{:x}({})", v.space.space_id() as u64, v.space, v.offset, v.size))
            .collect();
        println!("  op[{i}] {name} {out} <- {}", ins.join(", "));
    }
}

fn main() -> Result<()> {
    let cases: &[(&str, &[u8])] = &[
        ("ret", &[0xc3]),
        ("ret 0x8", &[0xc2, 0x08, 0x00]),
        ("ret 0x8000", &[0xc2, 0x00, 0x80]),
    ];
    for (label, code) in cases {
        let mut disasm = X86_64Disassembler::new();
        let instructions = disasm.disassemble(code, rugra::address::Address::new(0x1000))?;
        println!("== {label} ({})", instructions.len());
        let mut lifter = X86Lifter::new();
        for inst in &instructions {
            let ops = lifter.lift(inst);
            println!("  mnemonic={}", inst.mnemonic);
            dump_ops(&ops);
        }
    }
    Ok(())
}
