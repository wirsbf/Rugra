//! X86LIFT-FLAG-PCODE-0001 extension probe (w-x86flags): dump the
//! locked-oracle x86-64.sla pcode (SLEIGH semantics) for the remaining
//! iced-path families — rol/ror rotate flags, imul (1/2/3-operand),
//! bt/bts/btr/btc, comiss/ucomisd compares, bswap, mul/div/idiv, plus
//! documentation dumps for rep-string and SSE forms — side by side with the
//! iced-path X86Lifter projection, with op-for-op normalized comparison.
//!
//! Oracle chain: sleigh_specs/x86-64.sla compiled from locked Ghidra 12.0.4
//! (e40ed130); sleigh_shim decodes it directly, so the pcode printed here IS
//! the oracle lift for the same instruction bytes.
//!
//! Modes (EXTPROBE_MODE env, default "sleigh"):
//!   sleigh  — dump oracle pcode per form (with iced decode cross-check)
//!   compare — dump both sides + op-for-op normalized diff (Unique offsets
//!             canonicalized to allocation ordinals per side)
//! Optional EXTPROBE_FAMILY filter (e.g. EXTPROBE_FAMILY=rol).

use rugra::disasm::Disassembler as _;
use rugra::sleigh_ffi::SleighCtx;

/// (family, label, encoding bytes)
fn form_matrix() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    let mut v: Vec<(&'static str, &'static str, Vec<u8>)> = Vec::new();
    let mut add =
        |family: &'static str, label: &'static str, bytes: &[u8]| v.push((family, label, bytes.to_vec()));

    // ---- rol/ror (rotate group-2, C0/C1 imm, D0/D1 by-one, D2/D3 cl) ----
    add("rol", "rol al,3", &[0xc0, 0xc0, 0x03]);
    add("rol", "rol ax,3", &[0x66, 0xc1, 0xc0, 0x03]);
    add("rol", "rol eax,3", &[0xc1, 0xc0, 0x03]);
    add("rol", "rol rax,3", &[0x48, 0xc1, 0xc0, 0x03]);
    add("rol", "rol al,1", &[0xd0, 0xc0]);
    add("rol", "rol eax,1", &[0xd1, 0xc0]);
    add("rol", "rol rax,1", &[0x48, 0xd1, 0xc0]);
    add("rol", "rol al,cl", &[0xd2, 0xc0]);
    add("rol", "rol eax,cl", &[0xd3, 0xc0]);
    add("rol", "rol rax,cl", &[0x48, 0xd3, 0xc0]);
    add("rol", "rol byte [rbx],3", &[0xc0, 0x03, 0x03]);
    add("rol", "rol dword [rbx],3", &[0xc1, 0x03, 0x03]);
    add("rol", "rol dword [rbx],cl", &[0xd3, 0x03]);
    add("rol", "rol eax,0", &[0xc1, 0xc0, 0x00]);
    add("rol", "rol ax,17", &[0x66, 0xc1, 0xc0, 0x11]);
    add("rol", "rol r9w,3", &[0x66, 0x41, 0xc1, 0xc0, 0x03]);
    add("rol", "rol ax,1", &[0x66, 0xd1, 0xc0]);
    add("rol", "rol ax,cl", &[0x66, 0xd3, 0xc0]);
    add("rol", "rol word [rbx],3", &[0x66, 0xc1, 0x03, 0x03]);
    add("rol", "rol qword [rbx],cl", &[0x48, 0xd3, 0x03]);
    add("rol", "rol byte [rbx],1", &[0xd0, 0x03]);
    add("rol", "rol dword [rbx],1", &[0xd1, 0x03]);
    add("ror", "ror al,3", &[0xc0, 0xc8, 0x03]);
    add("ror", "ror eax,3", &[0xc1, 0xc8, 0x03]);
    add("ror", "ror rax,3", &[0x48, 0xc1, 0xc8, 0x03]);
    add("ror", "ror al,1", &[0xd0, 0xc8]);
    add("ror", "ror eax,1", &[0xd1, 0xc8]);
    add("ror", "ror rax,1", &[0x48, 0xd1, 0xc8]);
    add("ror", "ror al,cl", &[0xd2, 0xc8]);
    add("ror", "ror eax,cl", &[0xd3, 0xc8]);
    add("ror", "ror rax,cl", &[0x48, 0xd3, 0xc8]);
    add("ror", "ror dword [rbx],3", &[0xc1, 0x0b, 0x03]);
    add("ror", "ror ax,3", &[0x66, 0xc1, 0xc8, 0x03]);
    add("ror", "ror ax,1", &[0x66, 0xd1, 0xc8]);
    add("ror", "ror ax,cl", &[0x66, 0xd3, 0xc8]);
    add("ror", "ror byte [rbx],1", &[0xd0, 0x0b]);
    add("ror", "ror qword [rbx],cl", &[0x48, 0xd3, 0x0b]);

    // ---- imul ----
    add("imul", "imul eax,ecx", &[0x0f, 0xaf, 0xc1]);
    add("imul", "imul rbx,rax", &[0x48, 0x0f, 0xaf, 0xd8]);
    add("imul", "imul rbx,[rax]", &[0x48, 0x0f, 0xaf, 0x18]);
    add("imul", "imul rbx,rbx,3E8h", &[0x48, 0x69, 0xdb, 0xe8, 0x03, 0x00, 0x00]);
    add("imul", "imul ebx,ebx,7Fh", &[0x6b, 0xdb, 0x7f]);
    add("imul", "imul rbx,[rax],10h", &[0x48, 0x69, 0x18, 0x10, 0x00, 0x00, 0x00]);
    add("imul", "imul rax", &[0x48, 0xf7, 0xe8]);
    add("imul", "imul eax", &[0xf7, 0xe8]);
    add("imul", "imul rcx", &[0x48, 0xf7, 0xe9]);
    add("imul", "imul word [rbx]", &[0x66, 0xf7, 0x2b]);
    add("imul", "imul ax,cx", &[0x66, 0x0f, 0xaf, 0xc1]);
    add("imul", "imul bx,si,7", &[0x66, 0x6b, 0xc6, 0x07]);
    add("imul", "imul qword [rbx]", &[0x48, 0xf7, 0x2b]);
    add("imul", "imul eax,[rbx],5", &[0x6b, 0x03, 0x05]);
    add("imul", "imul rcx,rdx,10h", &[0x48, 0x6b, 0xca, 0x10]);
    add("imul", "imul r8,rax", &[0x4c, 0x0f, 0xaf, 0xc0]);
    add("imul", "imul ebx,ebx,3E8h(69)", &[0x69, 0xdb, 0xe8, 0x03, 0x00, 0x00]);
    add("imul", "imul ax,ax,1234h(69)", &[0x66, 0x69, 0xc0, 0x34, 0x12]);
    add("imul", "imul al", &[0xf6, 0xe8]);
    add("imul", "imul byte [rbx]", &[0xf6, 0x2b]);

    // ---- bt/bts/btr/btc ----
    add("bt", "bt eax,ebx", &[0x0f, 0xa3, 0xd8]);
    add("bt", "bt rcx,rdx", &[0x48, 0x0f, 0xa3, 0xd1]);
    add("bt", "bt eax,5", &[0x0f, 0xba, 0xe0, 0x05]);
    add("bt", "bt [rax],edx", &[0x0f, 0xa3, 0x10]);
    add("bt", "bt rsi,3Fh", &[0x48, 0x0f, 0xba, 0xe6, 0x3f]);
    add("bts", "bts eax,ebx", &[0x0f, 0xab, 0xd8]);
    add("bts", "bts eax,5", &[0x0f, 0xba, 0xe8, 0x05]);
    add("btr", "btr eax,5", &[0x0f, 0xba, 0xf0, 0x05]);
    add("btc", "btc rsi,3Fh", &[0x48, 0x0f, 0xba, 0xe6, 0x3f]);
    add("btc", "btc eax,ebx", &[0x0f, 0xbb, 0xd8]);

    // ---- comiss/ucomiss/comisd/ucomisd ----
    add("comis", "comiss xmm0,xmm1", &[0x0f, 0x2f, 0xc1]);
    add("comis", "ucomiss xmm0,xmm1", &[0x0f, 0x2e, 0xc1]);
    add("comis", "comisd xmm0,xmm1", &[0x66, 0x0f, 0x2f, 0xc1]);
    add("comis", "ucomisd xmm0,xmm1", &[0x66, 0x0f, 0x2e, 0xc1]);
    add("comis", "comiss xmm0,[rbx]", &[0x0f, 0x2f, 0x03]);

    // ---- bswap ----
    add("bswap", "bswap eax", &[0x0f, 0xc8]);
    add("bswap", "bswap rax", &[0x48, 0x0f, 0xc8]);
    add("bswap", "bswap edx", &[0x0f, 0xca]);

    // ---- mul/div/idiv ----
    add("mul", "mul ecx", &[0xf7, 0xe1]);
    add("mul", "mul rcx", &[0x48, 0xf7, 0xe1]);
    add("mul", "mul eax", &[0xf7, 0xe0]);
    add("idiv", "idiv rcx", &[0x48, 0xf7, 0xf9]);
    add("idiv", "idiv ecx", &[0xf7, 0xf9]);
    add("div", "div rcx", &[0x48, 0xf7, 0xf1]);

    // ---- documentation-only families (not yet in lift scope) ----
    add("doc", "repe cmpsb", &[0xf3, 0xa6]);
    add("doc", "rep stosq", &[0xf3, 0x48, 0xab]);
    add("doc", "movss xmm0,[rbx]", &[0xf3, 0x0f, 0x10, 0x03]);
    add("doc", "pxor xmm0,xmm0", &[0x0f, 0xef, 0xc0]);
    add("doc", "cvtss2sd xmm0,xmm0", &[0xf3, 0x0f, 0x5a, 0xc0]);
    v
}

/// One pcode op in neutral form for comparison: opcode name + varnodes with
/// Unique offsets canonicalized to allocation ordinals per side.
#[derive(PartialEq, Clone)]
struct OpShape {
    opcode: String,
    output: Option<VnShape>,
    inputs: Vec<VnShape>,
}

#[derive(PartialEq, Clone)]
struct VnShape {
    space: String,
    offset: u64,
    size: usize,
    uniq_ordinal: Option<usize>,
}

struct UniqCanon {
    map: std::collections::HashMap<(u64, usize), usize>,
    next: usize,
}

impl UniqCanon {
    fn new() -> Self {
        Self { map: Default::default(), next: 0 }
    }
    fn canon(&mut self, space: u8, offset: u64, size: usize) -> VnShape {
        let space_name = match space {
            0 => "const",
            1 => "other",
            2 => "unique",
            3 => "ram",
            4 => "register",
            5 => "stack",
            6 => "join",
            7 => "iop",
            _ => "space?",
        }
        .to_string();
        if space == 2 {
            let key = (offset, size);
            let ord = *self.map.entry(key).or_insert_with(|| {
                let n = self.next;
                self.next += 1;
                n
            });
            VnShape { space: space_name, offset: 0, size, uniq_ordinal: Some(ord) }
        } else {
            VnShape { space: space_name, offset, size, uniq_ordinal: None }
        }
    }
}

fn vn_show(v: &VnShape) -> String {
    match v.uniq_ordinal {
        Some(o) => format!("{}#{}:{}", v.space, o, v.size),
        None => format!("{}:0x{:x}:{}", v.space, v.offset, v.size),
    }
}

fn op_show(o: &OpShape) -> String {
    let out = match &o.output {
        Some(v) => vn_show(v),
        None => "-".to_string(),
    };
    let ins = o.inputs.iter().map(vn_show).collect::<Vec<_>>().join(", ");
    format!("{} out={} in=({})", o.opcode, out, ins)
}

fn main() -> anyhow::Result<()> {
    let mode = std::env::var("EXTPROBE_MODE").unwrap_or_else(|_| "sleigh".to_string());
    let family_filter = std::env::var("EXTPROBE_FAMILY").ok();
    let forms: Vec<_> = form_matrix()
        .into_iter()
        .filter(|(f, _, _)| family_filter.as_deref().map(|ff| ff == *f).unwrap_or(true))
        .collect();

    // Concatenate encodings; decode offsets are positions in this buffer.
    let mut image: Vec<u8> = Vec::new();
    let mut entries: Vec<(&str, &str, u64, usize)> = Vec::new(); // (family, label, offset, len)
    for (family, label, bytes) in &forms {
        entries.push((family, label, image.len() as u64, bytes.len()));
        image.extend_from_slice(bytes);
    }

    let opcode_name = |raw: i32| -> String {
        rugra::opcodes::OpCode::from_i32(raw)
            .map(|o| o.name().to_string())
            .unwrap_or_else(|| format!("op{raw}"))
    };

    // SLEIGH side.
    let mut ctx = SleighCtx::new().ok_or_else(|| anyhow::anyhow!("sla load failed"))?;
    let pspec = std::path::Path::new("sleigh_specs/x86-64.pspec");
    if pspec.exists() {
        ctx.load_pspec(pspec.to_str().unwrap_or_default());
    }
    ctx.try_set_image(&image, 0)?;

    let mut sleigh_shapes: Vec<Vec<OpShape>> = Vec::new();
    println!("== SLEIGH oracle pcode per form (iced decode cross-checked) ==");
    for (family, label, off, len) in &entries {
        let decoded = ctx.one_instruction(*off)?;
        let mut canon = UniqCanon::new();
        let mut shapes = Vec::new();
        // iced cross-check: the encoding must decode to the labeled form
        let mut disasm = rugra::disasm::X86_64Disassembler::new();
        let iced_text = disasm
            .disassemble_one(&image[*off as usize..], rugra::Address::new(*off))
            .map(|(i, u)| format!("{} (used {})", i.text, u))
            .unwrap_or_else(|e| format!("DISASM ERR {e}"));
        println!("-- [{family}] {label} @0x{off:x} (len {len}, step {}) | iced: {iced_text}", decoded.step);
        for (i, op) in decoded.ops.iter().enumerate() {
            let output = if op.has_output != 0 {
                Some(canon.canon(op.output.space as u8, op.output.offset, op.output.size as usize))
            } else {
                None
            };
            let inputs = op
                .inputs
                .iter()
                .map(|v| canon.canon(v.space as u8, v.offset, v.size as usize))
                .collect();
            let shape = OpShape { opcode: opcode_name(op.opcode), output, inputs };
            println!("   [{i}] {}", op_show(&shape));
            shapes.push(shape);
        }
        sleigh_shapes.push(shapes);
    }

    if mode != "compare" {
        return Ok(());
    }

    // iced X86Lifter side + comparison.
    let mut pass = 0usize;
    let mut fail = 0usize;
    println!("\n== iced X86Lifter projection + op-for-op comparison ==");
    for ((family, label, off, _), oracle) in entries.iter().zip(&sleigh_shapes) {
        let mut disasm = rugra::disasm::X86_64Disassembler::new();
        let Ok((inst, _)) = disasm.disassemble_one(
            &image[*off as usize..],
            rugra::Address::new(*off),
        ) else {
            println!("-- [{family}] {label} @0x{off:x}: DISASM FAILED");
            fail += 1;
            continue;
        };
        let mut lifter = rugra::disasm::X86Lifter::new();
        let lifted = lifter.lift(&inst);
        let mut canon = UniqCanon::new();
        let mut mine = Vec::new();
        for op in lifted.iter() {
            let output = op
                .output()
                .map(|v| canon.canon(v.space.space_id(), v.offset, v.size));
            let inputs = op
                .inputs()
                .iter()
                .map(|v| canon.canon(v.space.space_id(), v.offset, v.size))
                .collect();
            mine.push(OpShape { opcode: opcode_name(op.get_opcode()), output, inputs });
        }
        if mine == *oracle {
            println!("-- [{family}] {label} @0x{off:x} : MATCH ({} ops)", mine.len());
            pass += 1;
        } else {
            println!(
                "-- [{family}] {label} @0x{off:x} : MISMATCH (mine {} ops vs oracle {} ops)",
                mine.len(),
                oracle.len()
            );
            let n = mine.len().max(oracle.len());
            for i in 0..n {
                let m = mine.get(i).map(op_show);
                let o = oracle.get(i).map(op_show);
                match (m, o) {
                    (Some(m), Some(o)) if m == o => println!("   [{i}] = {}", m),
                    (m, o) => {
                        println!("   [{i}] M mine: {}", m.unwrap_or_else(|| "<none>".into()));
                        println!("   [{i}] O orc : {}", o.unwrap_or_else(|| "<none>".into()));
                    }
                }
            }
            fail += 1;
        }
    }
    println!("\n== summary: {pass} MATCH / {fail} MISMATCH of {} ==", forms.len());
    Ok(())
}
