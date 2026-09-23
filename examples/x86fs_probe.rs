//! LIFT-FS-CANARY-FORM-0001 probe (w-fscanary): dump the locked-oracle
//! x86-64.sla pcode for FS/GS segment-relative memory forms (stack-protector
//! canary load/store, segment+base/index combinations), side by side with the
//! current iced-path X86Lifter projection, plus the register-catalog rows for
//! the FS/GS base registers.
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

/// Synthetic encodings covering the FS/GS segment-relative memory family.
fn synthetic_forms() -> Vec<Form> {
    vec![
        Form { label: "mov rax, [fs:0x28] (canary load, SIB abs)", bytes: &[0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00] },
        Form { label: "mov eax, [fs:0x28] (32-bit canary-style)", bytes: &[0x64, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00] },
        Form { label: "mov rax, [0x28] (no segment, SIB abs)", bytes: &[0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00] },
        Form { label: "mov [fs:0x28], rax (canary store, SIB abs)", bytes: &[0x64, 0x48, 0x89, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00] },
        Form { label: "mov rax, [fs:rbx] (seg + base)", bytes: &[0x64, 0x48, 0x8b, 0x03] },
        Form { label: "mov rax, [fs:rbx+rcx*8+0x10] (seg + full EA)", bytes: &[0x64, 0x48, 0x8b, 0x44, 0x8c, 0x10] },
        Form { label: "mov rax, [gs:0x28] (gs variant)", bytes: &[0x65, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00] },
        Form { label: "cmp rax, [fs:0x28] (canary check)", bytes: &[0x64, 0x48, 0x3b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00] },
        Form { label: "push qword [fs:0x28]", bytes: &[0x64, 0xff, 0x34, 0x25, 0x28, 0x00, 0x00, 0x00] },
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

    // ---- 0) Register catalog rows for FS/GS base + selector registers.
    println!("== register catalog: FS/GS-related rows ==");
    for i in 0..ctx.num_registers() {
        if let Some((name, space, offset, size)) = ctx.register_info(i) {
            let lower = name.to_lowercase();
            if lower.contains("fs") || lower.contains("gs") || lower.contains("cs") {
                println!("   {name}: space={space} offset=0x{offset:x} size={size}");
            }
        }
    }

    // ---- 1) Oracle pcode dump for the FS/GS memory family.
    println!("== SLEIGH oracle pcode: FS/GS segment forms ==");
    let mut image: Vec<u8> = Vec::new();
    let mut offs: Vec<(usize, &'static str, usize)> = Vec::new();
    for f in synthetic_forms() {
        offs.push((image.len(), f.label, f.bytes.len()));
        image.extend_from_slice(f.bytes);
        image.push(0x90);
    }
    ctx.try_set_image(&image, 0)?;

    for (off, label, len) in &offs {
        match ctx.one_instruction(*off as u64) {
            Ok(d) => {
                let tag = if d.step == *len as i32 { "" } else { "!!! LEN-MISMATCH " };
                println!("{tag}(step={} len={} addr=0x{off:x})", d.step, len);
                dump_ops(label, &image[*off..*off + *len], &d.ops);
            }
            Err(e) => println!("-- {label} DECODE-ERR {e:?}"),
        }
    }

    // ---- 2) Current iced-path projection for the same bytes/addresses.
    println!("== iced X86Lifter projection (current) ==");
    let mut lifter = rugra::disasm::X86Lifter::new();
    let mut disasm = rugra::disasm::X86_64Disassembler::new();
    for (off, label, len) in &offs {
        let insts = disasm
            .disassemble(&image[*off..*off + *len], rugra::Address::new(*off as u64))
            .unwrap_or_default();
        let mut all: Vec<rugra::pcoderaw::PcodeOpRaw> = Vec::new();
        for i in &insts {
            all.extend(lifter.lift(i));
        }
        let mapped: Vec<rugra::sleigh_ffi::PcodeOpC> = all
            .iter()
            .map(|op| {
                let conv = |v: &rugra::pcoderaw::VarnodeRaw| rugra::sleigh_ffi::VarnodeC {
                    space: v.space.space_id() as i32,
                    offset: v.offset,
                    size: v.size as u32,
                    space_ref: -1,
                    identity: 0,
                };
                rugra::sleigh_ffi::PcodeOpC {
                    address_space: 0,
                    address_offset: 0,
                    opcode: op.get_opcode(),
                    num_inputs: op.inputs().len() as i32,
                    has_output: op.output().map(|_| 1).unwrap_or(0),
                    output: op.output().map(&conv).unwrap_or_default(),
                    inputs: op.inputs().iter().map(&conv).collect(),
                }
            })
            .collect();
        dump_ops(label, &image[*off..*off + *len], &mapped);
    }
    Ok(())
}
