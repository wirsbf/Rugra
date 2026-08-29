//! X86LIFT-FLAG-PCODE-0001 probe (w-iced): dump the locked-oracle x86-64.sla
//! flags register layout and the SLEIGH pcode (oracle semantics) for every
//! flag-producing opcode family present in the httpd corpus, side by side
//! with the current iced-path X86Lifter projection.
//!
//! Oracle chain: sleigh_specs/x86-64.sla was compiled from the locked Ghidra
//! 12.0.4 (e40ed130) x86-64 language; sleigh_shim decodes it directly, so the
//! pcode printed here IS the oracle lift for the same instruction bytes.

use rugra::disasm::Disassembler as _;
use rugra::sleigh_ffi::SleighCtx;

fn main() -> anyhow::Result<()> {
    let mut ctx = SleighCtx::new().ok_or_else(|| anyhow::anyhow!("sla load failed"))?;
    let pspec = std::path::Path::new("sleigh_specs/x86-64.pspec");
    if pspec.exists() {
        ctx.load_pspec(pspec.to_str().unwrap_or_default());
    }

    // Register space id, for filtering register_info.
    let nspaces = ctx.num_spaces();
    let mut register_space = -1;
    for i in 0..nspaces {
        if let Some((_, name)) = ctx.space_info(i) {
            if name == "register" {
                register_space = i as i32;
            }
        }
    }

    // Full flags-region layout: this is the authoritative register-offset map
    // the iced lifter must use when writing CF/OF/SF/ZF/... pcode outputs.
    println!("== flags region layout (register space 0x1f0..0x220) ==");
    for i in 0..ctx.num_registers() {
        if let Some((name, space, offset, size)) = ctx.register_info(i) {
            if space == register_space && (0x1f0..=0x220).contains(&offset) {
                println!("reg {name} off=0x{offset:x} size={size}");
            }
        }
    }

    // ---- httpd corpus scan (same selection as examples/httpd_decompile.rs) ----
    let buffer = std::fs::read("examples/httpd")?;
    let obj = goblin::Object::parse(&buffer)?;

    let mut functions: Vec<(u64, usize, u64, String)> = Vec::new();
    if let goblin::Object::Elf(elf) = &obj {
        // httpd is stripped: symbols come from dynsyms (same dual scan as
        // examples/httpd_decompile.rs).
        for (syms, strtab) in [(&elf.syms, &elf.strtab), (&elf.dynsyms, &elf.dynstrtab)] {
            for sym in syms.iter() {
                if sym.st_value != 0 && sym.is_function() {
                    if let Some(name) = strtab.get_at(sym.st_name) {
                        if name.is_empty() {
                            continue;
                        }
                        let mut file_off = 0u64;
                        for header in elf.section_headers.iter() {
                            if sym.st_value >= header.sh_addr
                                && sym.st_value < header.sh_addr + header.sh_size
                            {
                                file_off = header.sh_offset + (sym.st_value - header.sh_addr);
                                break;
                            }
                        }
                        if file_off > 0 && !functions.iter().any(|f| f.0 == sym.st_value) {
                            let size = if sym.st_size > 0 { sym.st_size as usize } else { 512 };
                            functions.push((sym.st_value, size, file_off, name.to_string()));
                        }
                    }
                }
            }
        }
    }
    functions.sort_by_key(|f| f.0);

    // iced-side census + sample addresses (first occurrence per mnemonic).
    let family_prefixes = [
        "add", "sub", "and", "or", "xor", "shl", "shr", "sal", "sar", "sbb", "adc", "cmp", "test",
        "cmov", "set", "neg", "not", "inc", "dec", "j", "pop", "push", "movzx", "movsx", "leave",
        "cdq", "cdqe", "cwde", "cbw", "cqo",
    ];
    let mut census: std::collections::BTreeMap<String, usize> = Default::default();
    let mut samples: Vec<(String, u64, u64, String)> = Vec::new(); // (mnemonic, vaddr, file_off, text)
    let mut seen: std::collections::HashSet<String> = Default::default();

    for &(vaddr, size, file_offset, ref name) in functions.iter() {
        if name == "_start"
            || name.starts_with("register_tm_clones")
            || name.starts_with("deregister_tm_clones")
            || name == "__libc_csu_init"
            || name == "__libc_csu_fini"
            || name == "frame_dummy"
        {
            continue;
        }
        if samples.len() >= 40 {
            // keep scanning a bounded number of functions for the census
        }
        let max_size = std::cmp::min(size, 8192);
        let end_off = std::cmp::min(file_offset as usize + max_size, buffer.len());
        if file_offset as usize >= buffer.len() {
            continue;
        }
        let code_bytes = &buffer[file_offset as usize..end_off];
        let mut disasm = rugra::disasm::X86_64Disassembler::new();
        let instructions = match disasm.disassemble(code_bytes, rugra::Address::new(vaddr)) {
            Ok(insts) => insts,
            Err(_) => continue,
        };
        for inst in &instructions {
            let m = inst.mnemonic.as_str();
            if family_prefixes.iter().any(|p| m.starts_with(p)) {
                *census.entry(m.to_string()).or_insert(0) += 1;
                if !seen.contains(m) && samples.len() < 48 {
                    seen.insert(m.to_string());
                    let fo = file_offset + (inst.address.as_u64() - vaddr);
                    samples.push((m.to_string(), inst.address.as_u64(), fo, inst.text.clone()));
                }
                // Memory-destination variants of the ALU families (oracle
                // op order around the LOAD/STORE differs from reg form).
                let alu_set = [
                    "add", "sub", "and", "or", "xor", "adc", "sbb", "neg", "not", "cmp", "test",
                ];
                if alu_set.contains(&m)
                    && matches!(
                        inst.operands.first(),
                        Some(rugra::disasm::Operand::Memory { .. })
                    )
                {
                    let key = format!("{m}-memdst");
                    if !seen.contains(&key) && samples.len() < 56 {
                        seen.insert(key.clone());
                        let fo = file_offset + (inst.address.as_u64() - vaddr);
                        samples.push((key, inst.address.as_u64(), fo, inst.text.clone()));
                    }
                }
                // Memory-SOURCE variants (op2 re-LOAD semantics).
                if alu_set.contains(&m)
                    && inst.operands.len() == 2
                    && matches!(
                        inst.operands.get(1),
                        Some(rugra::disasm::Operand::Memory { .. })
                    )
                    && !matches!(
                        inst.operands.first(),
                        Some(rugra::disasm::Operand::Memory { .. })
                    )
                {
                    let key = format!("{m}-memsrc");
                    if !seen.contains(&key) && samples.len() < 64 {
                        seen.insert(key.clone());
                        let fo = file_offset + (inst.address.as_u64() - vaddr);
                        samples.push((key, inst.address.as_u64(), fo, inst.text.clone()));
                    }
                }
            }
        }
    }

    println!("\n== httpd mnemonic census (families) ==");
    for (m, count) in &census {
        println!("{m} {count}");
    }

    // SLEIGH image at base 0 so decode addresses == file offsets.
    ctx.try_set_image(&buffer, 0)?;

    let opcode_name = |raw: i32| -> String {
        rugra::opcodes::OpCode::from_i32(raw)
            .map(|o| o.name().to_string())
            .unwrap_or_else(|| format!("op{raw}"))
    };

    println!("\n== SLEIGH oracle pcode per sampled mnemonic ==");
    for (m, vaddr, fo, text) in &samples {
        let decoded = ctx.one_instruction(*fo)?;
        println!("-- {m} @vaddr=0x{vaddr:x} bytes@0x{fo:x} : {text} (len={})", decoded.step);
        for (i, op) in decoded.ops.iter().enumerate() {
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
    }

    // Iced-path lift projection for the same sampled instructions: this is
    // the X86Lifter output that feeds the httpd pipeline, printed in the
    // same varnode notation for direct comparison with the SLEIGH dump.
    println!("\n== iced X86Lifter projection per sampled mnemonic ==");
    for (m, vaddr, fo, text) in &samples {
        let mut disasm = rugra::disasm::X86_64Disassembler::new();
        let Ok((inst, _)) = disasm.disassemble_one(&buffer[*fo as usize..], rugra::Address::new(*vaddr)) else {
            println!("-- {m} @0x{vaddr:x}: disasm failed");
            continue;
        };
        let mut lifter = rugra::disasm::X86Lifter::new();
        let lifted = lifter.lift(&inst);
        println!("-- {m} @vaddr=0x{vaddr:x} : {text}");
        for (i, op) in lifted.iter().enumerate() {
            let name = rugra::opcodes::OpCode::from_i32(op.get_opcode())
                .map(|o| o.name().to_string())
                .unwrap_or_else(|| format!("op{}", op.get_opcode()));
            let out = match op.output() {
                Some(v) => format!("{}:0x{:x}:{}", v.space, v.offset, v.size),
                None => "-".to_string(),
            };
            let inputs = op
                .inputs()
                .iter()
                .map(|v| format!("{}:0x{:x}:{}", v.space, v.offset, v.size))
                .collect::<Vec<_>>()
                .join(", ");
            println!("   [{i}] {name} out={out} in=({inputs})");
        }
    }
    Ok(())
}
