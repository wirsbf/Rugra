//! X86LIFT-PUSH88-0001 probe (w-push88): dump the locked-oracle x86-64.sla
//! pcode for every push instruction form (imm/reg/mem, rbp/rsp specials,
//! REX, 64/32/16-bit operand sizes), side by side with the httpd corpus push
//! census and the current iced-path X86Lifter projection.
//!
//! Oracle chain: sleigh_specs/x86-64.sla was compiled from the locked Ghidra
//! 12.0.4 (e40ed130) x86-64 language; sleigh_shim decodes it directly, so the
//! pcode printed here IS the oracle lift for the same instruction bytes.

use rugra::disasm::Disassembler as _;
use rugra::sleigh_ffi::SleighCtx;

struct Form {
    label: &'static str,
    bytes: &'static [u8],
}

/// Synthetic encodings covering the push constructor family.
fn synthetic_forms() -> Vec<Form> {
    vec![
        Form { label: "push imm8", bytes: &[0x6a, 0x5a] },
        Form { label: "push imm8 negative", bytes: &[0x6a, 0x9c] },
        Form { label: "push imm32", bytes: &[0x68, 0x78, 0x56, 0x34, 0x12] },
        Form { label: "push imm32 negative", bytes: &[0x68, 0xf0, 0xff, 0xff, 0xff] },
        Form { label: "push rbp (55)", bytes: &[0x55] },
        Form { label: "push rsp (54)", bytes: &[0x54] },
        Form { label: "push rax (50)", bytes: &[0x50] },
        Form { label: "push r8 (41 50)", bytes: &[0x41, 0x50] },
        Form { label: "push r15 (41 57)", bytes: &[0x41, 0x57] },
        Form { label: "push r12 (41 54)", bytes: &[0x41, 0x54] },
        Form { label: "push rbp via FF /6", bytes: &[0xff, 0xf5] },
        Form { label: "push rsp via FF /6", bytes: &[0xff, 0xf4] },
        Form { label: "push rax via FF /6", bytes: &[0xff, 0xf0] },
        Form { label: "push qword [rax]", bytes: &[0xff, 0x30] },
        Form { label: "push qword [rbp-8]", bytes: &[0xff, 0x75, 0xf8] },
        Form { label: "push qword [rsp+10h]", bytes: &[0xff, 0x74, 0x24, 0x10] },
        Form { label: "push qword [rip+1234h]", bytes: &[0xff, 0x35, 0x34, 0x12, 0x00, 0x00] },
        Form { label: "push qword [rax+rbx*4] (SIB no disp)", bytes: &[0xff, 0x34, 0x18] },
        Form { label: "push qword [rbx*8] (SIB no base)", bytes: &[0xff, 0x34, 0xe0] },
        Form { label: "push qword [12AABh] (abs disp32)", bytes: &[0xff, 0x34, 0x25, 0xab, 0xaa, 0x01, 0x00] },
        Form { label: "push qword [r13] (41 55)", bytes: &[0x41, 0x55] },
        Form { label: "push qword [r13+8] rm=101", bytes: &[0x41, 0xff, 0x75, 0x08] },
        Form { label: "push qword [rbp+0] disp8=0", bytes: &[0xff, 0x75, 0x00] },
        Form { label: "push qword [rsp] SIB d=0", bytes: &[0xff, 0x34, 0x24] },
        Form { label: "push qword [rbx*1+12345678h] (SIB nobase+d)", bytes: &[0xff, 0x34, 0x1d, 0x78, 0x56, 0x34, 0x12] },
        Form { label: "push qword [rbx*4+12345678h] (SIB nobase scale+d)", bytes: &[0xff, 0x34, 0x9d, 0x78, 0x56, 0x34, 0x12] },
        Form { label: "push imm32 66-prefixed? (68 id)", bytes: &[0x68, 0xcd, 0xab, 0x00, 0x00] },
        Form { label: "push qword [r8+rbx*4-0Ch] w/REX.XB", bytes: &[0x43, 0xff, 0x74, 0x98, 0xf4] },
        Form { label: "push imm16 (66 68 iw)", bytes: &[0x66, 0x68, 0x34, 0x12] },
        Form { label: "push ax (66 50)", bytes: &[0x66, 0x50] },
        Form { label: "push word [rax] (66 FF /6)", bytes: &[0x66, 0xff, 0x30] },
        Form { label: "push fs (0f a0)", bytes: &[0x0f, 0xa0] },
        Form { label: "push gs (0f a8)", bytes: &[0x0f, 0xa8] },
        Form { label: "push cs (0e)", bytes: &[0x0e] },
        Form { label: "push ss (16)", bytes: &[0x16] },
    ]
}

fn dump_ops(label: &str, bytes: &[u8], ops: &[rugra::sleigh_ffi::PcodeOpC]) {
    let opcode_name = |raw: i32| -> String {
        rugra::opcodes::OpCode::from_i32(raw)
            .map(|o| o.name().to_string())
            .unwrap_or_else(|| format!("op{raw}"))
    };
    println!("-- {label} bytes={bytes:02x?}");
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
}

fn main() -> anyhow::Result<()> {
    let mut ctx = SleighCtx::new().ok_or_else(|| anyhow::anyhow!("sla load failed"))?;
    let pspec = std::path::Path::new("sleigh_specs/x86-64.pspec");
    if pspec.exists() {
        ctx.load_pspec(pspec.to_str().unwrap_or_default());
    }

    // ---- 1) Synthetic form dump + op-for-op fixture gate: each encoding is
    // placed at a known image offset (base 0) so the sla oracle and the iced
    // X86Lifter decode the SAME bytes at the SAME address (rip-relative
    // resolution must agree). Unique-space offsets are normalized to their
    // order of first appearance (temporary ids are semantics-free — the sla
    // uses a per-instruction pool, alloc_tmp is sequential). Every other
    // field (opcode, op order, space, offset, size) must match exactly.
    println!("== SLEIGH oracle pcode: synthetic push forms ==");
    let mut image: Vec<u8> = Vec::new();
    let mut offs: Vec<(usize, &'static str, usize)> = Vec::new(); // (off, label, len)
    for f in synthetic_forms() {
        offs.push((image.len(), f.label, f.bytes.len()));
        image.extend_from_slice(f.bytes);
        image.push(0x90); // nop separator (not decoded, just padding)
    }
    ctx.try_set_image(&image, 0)?;

    // normalized (opcode, has_out, out_sig, in_sigs) with unique ids mapped
    // to first-appearance ordinals
    fn normalize_ops<'a, I: Iterator<Item = (i32, Option<(u8, u64, u64)>, Vec<(u8, u64, u64)>)>>(
        ops: I,
    ) -> Vec<(String, String, Vec<String>)> {
        let mut uniq: std::collections::HashMap<(u64, u64), String> = Default::default();
        let mut next = 0usize;
        let mut sig = |space: u8, offset: u64, size: u64| -> String {
            if space == 2 {
                // unique space: normalize offset
                let key = (offset, size);
                let name = uniq.entry(key).or_insert_with(|| {
                    let n = format!("u{next}");
                    next += 1;
                    n
                });
                format!("{}:{size}", name.clone())
            } else {
                format!("{space}:0x{offset:x}:{size}")
            }
        };
        ops.map(|(opcode, out, inputs)| {
            let name = rugra::opcodes::OpCode::from_i32(opcode)
                .map(|o| o.name().to_string())
                .unwrap_or_else(|| format!("op{opcode}"));
            let o = out
                .map(|(s, off, sz)| sig(s, off, sz))
                .unwrap_or_else(|| "-".into());
            let ins = inputs
                .into_iter()
                .map(|(s, off, sz)| sig(s, off, sz))
                .collect();
            (name, o, ins)
        })
        .collect()
    }

    let mut iced: rugra::disasm::X86Lifter = rugra::disasm::X86Lifter::new();
    let mut disasm = rugra::disasm::X86_64Disassembler::new();
    let mut pass = 0usize;
    let mut fail = 0usize;
    for (off, label, len) in &offs {
        let oracle = match ctx.one_instruction(*off as u64) {
            Ok(d) => {
                let exact = d.step == *len as i32;
                let tag = if exact { "" } else { "!!! LEN-MISMATCH " };
                println!("{tag}(step={} len={} addr=0x{off:x})", d.step, len);
                dump_ops(label, &image[*off..*off + *len], &d.ops);
                d
            }
            Err(e) => {
                println!("-- {label} DECODE-ERR {e:?}");
                continue;
            }
        };
        // iced projection at the SAME address
        let insts = disasm
            .disassemble(&image[*off..*off + *len], rugra::Address::new(*off as u64))
            .unwrap_or_default();
        let lifted: Vec<Vec<rugra::pcoderaw::PcodeOpRaw>> =
            insts.iter().map(|i| iced.lift(i)).collect();
        let oracle_sig = normalize_ops(
            oracle
                .ops
                .iter()
                .map(|op| {
                    (
                        op.opcode,
                        if op.has_output != 0 {
                            Some((op.output.space as u8, op.output.offset, op.output.size as u64))
                        } else {
                            None
                        },
                        op.inputs
                            .iter()
                            .map(|v| (v.space as u8, v.offset, v.size as u64))
                            .collect(),
                    )
                })
                .collect::<Vec<_>>()
                .into_iter(),
        );
        let iced_sig = normalize_ops(
            lifted
                .iter()
                .flatten()
                .map(|op| {
                    (
                        op.get_opcode(),
                        op.output()
                            .map(|v| (v.space.space_id(), v.offset, v.size as u64)),
                        op.inputs()
                            .iter()
                            .map(|v| (v.space.space_id(), v.offset, v.size as u64))
                            .collect(),
                    )
                })
                .collect::<Vec<_>>()
                .into_iter(),
        );
        if oracle_sig == iced_sig {
            println!("   [FIXTURE PASS] {label}");
            pass += 1;
        } else {
            fail += 1;
            println!("   [FIXTURE FAIL] {label}");
            println!("     oracle: {oracle_sig:?}");
            println!("     iced  : {iced_sig:?}");
        }
    }
    println!("\n== push fixture: {pass} PASS, {fail} FAIL ==");

    // ---- 2) httpd corpus push census + first sample of every form class.
    let buffer = std::fs::read("examples/httpd")?;
    let obj = goblin::Object::parse(&buffer)?;
    let mut functions: Vec<(u64, usize, u64, String)> = Vec::new();
    if let goblin::Object::Elf(elf) = &obj {
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

    let mut census: std::collections::BTreeMap<String, usize> = Default::default();
    let mut shape_count: std::collections::BTreeMap<String, usize> = Default::default();
    let mut samples: Vec<(String, u64, u64, String)> = Vec::new();
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
            if inst.mnemonic != "push" {
                continue;
            }
            let class = match inst.operands.first() {
                Some(rugra::disasm::Operand::Register { name, .. }) => {
                    if name == "rsp" { "push-rsp" } else { "push-reg" }.to_string()
                }
                Some(rugra::disasm::Operand::Immediate { .. }) => "push-imm".to_string(),
                Some(rugra::disasm::Operand::Memory { .. }) => "push-mem".to_string(),
                _ => "push-other".to_string(),
            };
            *census.entry(class.clone()).or_insert(0) += 1;
            // fine-grained shape key for the mem bucket: rip / abs / base /
            // base+idx+scale / base+disp / full
            let shape = match inst.operands.first() {
                Some(rugra::disasm::Operand::Memory { base, index, scale, displacement, .. }) => {
                    let b = base.clone().unwrap_or_else(|| "-".into());
                    let i = match index {
                        Some(ix) => format!("+{ix}*{scale}"),
                        None => String::new(),
                    };
                    let d = if *displacement != 0 { "+d" } else { "" };
                    format!("mem[{b}{i}{d}]")
                }
                Some(rugra::disasm::Operand::Register { name, size }) => format!("reg[{name}:{size}]"),
                Some(rugra::disasm::Operand::Immediate { value, size }) => format!("imm[{value}:{size}]"),
                _ => class.clone(),
            };
            *shape_count.entry(shape.clone()).or_insert(0) += 1;
            if !seen.contains(&shape) {
                seen.insert(shape.clone());
                let fo = file_offset + (inst.address.as_u64() - vaddr);
                samples.push((shape, inst.address.as_u64(), fo, inst.text.clone()));
            }
        }
    }
    println!("\n== httpd push census ==");
    for (c, count) in &census {
        println!("{c} {count}");
    }
    println!("\n== httpd push shape census ==");
    for (s, count) in &shape_count {
        println!("{s} {count}");
    }

    // (image replacement after decoding is refused by the shim → fresh ctx)
    println!("\n== SLEIGH oracle pcode: httpd corpus samples ==");
    let mut ctx = SleighCtx::new().ok_or_else(|| anyhow::anyhow!("sla load failed"))?;
    if pspec.exists() {
        ctx.load_pspec(pspec.to_str().unwrap_or_default());
    }
    ctx.try_set_image(&buffer, 0)?;
    for (class, vaddr, fo, text) in &samples {
        match ctx.one_instruction(*fo) {
            Ok(d) => {
                println!("-- {class} @vaddr=0x{vaddr:x} bytes@0x{fo:x} : {text}");
                dump_ops(class, &buffer[*fo as usize..*fo as usize + d.step as usize], &d.ops);
            }
            Err(e) => println!("-- {class} @0x{vaddr:x} DECODE-ERR {e:?}"),
        }
    }

    if fail > 0 {
        anyhow::bail!("push fixture: {fail} form(s) MISMATCH the sla oracle");
    }
    Ok(())
}
