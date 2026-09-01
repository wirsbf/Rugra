//! X86LIFT-FLAG-PCODE-0001 gap probe (w-x86flags): disassemble a corpus
//! binary's executable sections with Rugra's own iced-based
//! X86_64Disassembler, lift every instruction through X86Lifter, and report
//! which mnemonics currently project ZERO pcode ops — the remaining iced-path
//! coverage gaps. Also prints per-mnemonic total counts for context.
//!
//! Usage: cargo run --release --example x86gap_probe -- examples/httpd

use rugra::disasm::{Disassembler, X86_64Disassembler, X86Lifter};
use std::collections::BTreeMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).unwrap_or_else(|| "examples/httpd".to_string());
    let buffer = std::fs::read(&path)?;
    let obj = goblin::Object::parse(&buffer)?;

    let mut total: BTreeMap<String, usize> = BTreeMap::new();
    let mut zero_op: BTreeMap<String, usize> = BTreeMap::new();
    let mut zero_op_samples: BTreeMap<String, String> = BTreeMap::new();
    let mut instr_count = 0usize;

    if let goblin::Object::Elf(elf) = &obj {
        for header in elf.section_headers.iter() {
            if header.sh_addr == 0 || (header.sh_flags & 0x4 /* SHF_EXECINSTR */) == 0 {
                continue;
            }
            let start = header.sh_offset as usize;
            let end = start + header.sh_size as usize;
            let code = &buffer[start..end];
            let mut disasm = X86_64Disassembler::new();
            let mut off = 0usize;
            while off < code.len() {
                let Ok((inst, used)) = disasm.disassemble_one(
                    &code[off..],
                    rugra::Address::new(header.sh_addr + off as u64),
                ) else {
                    off += 1;
                    continue;
                };
                if used == 0 {
                    off += 1;
                    continue;
                }
                off += used;
                instr_count += 1;
                *total.entry(inst.mnemonic.clone()).or_default() += 1;
                let mut lifter = X86Lifter::new();
                let ops = lifter.lift(&inst);
                if ops.is_empty() {
                    *zero_op.entry(inst.mnemonic.clone()).or_default() += 1;
                    zero_op_samples
                        .entry(inst.mnemonic.clone())
                        .or_insert_with(|| format!("{} @0x{:x}", inst.text, inst.address.as_u64()));
                }
            }
        }
    }

    println!("== {} : {} instructions disassembled ==", path, instr_count);
    println!("\n== zero-op projection mnemonics (iced-path gaps) ==");
    let mut rows: Vec<_> = zero_op.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1));
    for (m, c) in &rows {
        println!("{:>6}x {:<10} e.g. {}", c, m, zero_op_samples.get(m).map(|s| s.as_str()).unwrap_or(""));
    }
    println!("\n== all mnemonics (top 60) ==");
    let mut all: Vec<_> = total.into_iter().collect();
    all.sort_by(|a, b| b.1.cmp(&a.1));
    for (m, c) in all.iter().take(60) {
        println!("{:>6}x {}", c, m);
    }
    Ok(())
}
