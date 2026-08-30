//! X86LIFT-SHIFTS-FLAGS-0001 probe (w-shifts): dump the locked-oracle
//! x86-64.sla pcode (SLEIGH semantics) for every shl/shr/sar form —
//! imm/1/cl count, 8/16/32/64-bit, reg/mem destination, REX.R/B — side by
//! side with the iced-path X86Lifter projection, with op-for-op normalized
//! comparison.
//!
//! Oracle chain: sleigh_specs/x86-64.sla compiled from locked Ghidra 12.0.4
//! (e40ed130); sleigh_shim decodes it directly, so the pcode printed here IS
//! the oracle lift for the same instruction bytes.
//!
//! Modes (SHIFTPROBE_MODE env, default "sleigh"):
//!   sleigh  — dump oracle pcode per form
//!   compare — dump both sides + op-for-op normalized diff (Unique offsets
//!             canonicalized to allocation ordinals per side)

use rugra::disasm::Disassembler as _;
use rugra::sleigh_ffi::SleighCtx;

/// (label, encoding bytes)
fn form_matrix() -> Vec<(&'static str, Vec<u8>)> {
    let mut v: Vec<(&'static str, Vec<u8>)> = Vec::new();
    let mut add = |label: &'static str, bytes: &[u8]| v.push((label, bytes.to_vec()));
    // ---- imm-count forms (C0 / C1) ----
    add("shl al,3", &[0xc0, 0xe0, 0x03]);
    add("shl cl,3", &[0xc0, 0xe1, 0x03]);
    add("shl ax,3", &[0x66, 0xc1, 0xe0, 0x03]);
    add("shl eax,3", &[0xc1, 0xe0, 0x03]);
    add("shl rax,3", &[0x48, 0xc1, 0xe0, 0x03]);
    add("shr al,3", &[0xc0, 0xe8, 0x03]);
    add("shr ax,3", &[0x66, 0xc1, 0xe8, 0x03]);
    add("shr eax,3", &[0xc1, 0xe8, 0x03]);
    add("shr rax,3", &[0x48, 0xc1, 0xe8, 0x03]);
    add("sar al,3", &[0xc0, 0xf8, 0x03]);
    add("sar ax,3", &[0x66, 0xc1, 0xf8, 0x03]);
    add("sar eax,3", &[0xc1, 0xf8, 0x03]);
    add("sar rax,3", &[0x48, 0xc1, 0xf8, 0x03]);
    add("shl byte [rbx],3", &[0xc0, 0x23, 0x03]);
    add("shl word [rbx],3", &[0x66, 0xc1, 0x23, 0x03]);
    add("shl dword [rbx],3", &[0xc1, 0x23, 0x03]);
    add("shl qword [rbx],3", &[0x48, 0xc1, 0x23, 0x03]);
    add("shr dword [rbx],3", &[0xc1, 0x2b, 0x03]);
    add("sar dword [rbx],3", &[0xc1, 0x3b, 0x03]);
    add("shl r8d,3", &[0x41, 0xc1, 0xe0, 0x03]);
    add("shl dil,3", &[0x40, 0xc0, 0xe7, 0x03]);
    add("shl dh,3", &[0xc0, 0xe6, 0x03]);
    // count edge forms
    add("shl eax,0", &[0xc1, 0xe0, 0x00]);
    add("shl eax,33", &[0xc1, 0xe0, 0x21]);
    add("shl eax,255", &[0xc1, 0xe0, 0xff]);
    // ---- shift-by-1 forms (D0 / D1) ----
    add("shl al,1", &[0xd0, 0xe0]);
    add("shl eax,1", &[0xd1, 0xe0]);
    add("shl rax,1", &[0x48, 0xd1, 0xe0]);
    add("shl ax,1", &[0x66, 0xd1, 0xe0]);
    add("shr ax,1", &[0x66, 0xd1, 0xe8]);
    add("shr al,1", &[0xd0, 0xe8]);
    add("shr eax,1", &[0xd1, 0xe8]);
    add("shr rax,1", &[0x48, 0xd1, 0xe8]);
    add("sar al,1", &[0xd0, 0xf8]);
    add("sar ax,1", &[0x66, 0xd1, 0xf8]);
    add("sar eax,1", &[0xd1, 0xf8]);
    add("sar rax,1", &[0x48, 0xd1, 0xf8]);
    add("shl dword [rbx],1", &[0xd1, 0x23]);
    add("shr dword [rbx],1", &[0xd1, 0x2b]);
    add("sar dword [rbx],1", &[0xd1, 0x3b]);
    add("shl byte [rbx],1", &[0xd0, 0x23]);
    add("shr byte [rbx],1", &[0xd0, 0x2b]);
    add("sar byte [rbx],1", &[0xd0, 0x3b]);
    add("shl qword [rbx],cl", &[0x48, 0xd3, 0x23]);
    // disp mem imm form (addr-ops vs count-op order)
    add("shl dword [rbx+8],3", &[0xc1, 0x63, 0x08, 0x03]);
    // ---- cl-count forms (D2 / D3) ----
    add("shl al,cl", &[0xd2, 0xe0]);
    add("shl ax,cl", &[0x66, 0xd3, 0xe0]);
    add("shl eax,cl", &[0xd3, 0xe0]);
    add("shl rax,cl", &[0x48, 0xd3, 0xe0]);
    add("shr eax,cl", &[0xd3, 0xe8]);
    add("shr rax,cl", &[0x48, 0xd3, 0xe8]);
    add("sar eax,cl", &[0xd3, 0xf8]);
    add("sar rax,cl", &[0x48, 0xd3, 0xf8]);
    add("shl byte [rbx],cl", &[0xd2, 0x23]);
    add("shl dword [rbx],cl", &[0xd3, 0x23]);
    add("shr dword [rbx],cl", &[0xd3, 0x2b]);
    add("sar dword [rbx],cl", &[0xd3, 0x3b]);
    // ---- mem with displacement+index (address-op interaction) ----
    add("shr dword [rbx+rcx*4+8],cl", &[0xd3, 0xa4, 0x8b, 0x08, 0x00, 0x00, 0x00]);
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
            // Unique raw offsets are allocation-scheme artifacts (proven
            // non-semantic temporaries); the ordinal carries identity, so
            // the offset itself must not participate in equality.
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
    let mode = std::env::var("SHIFTPROBE_MODE").unwrap_or_else(|_| "sleigh".to_string());
    let forms = form_matrix();

    // Concatenate encodings; decode offsets are positions in this buffer.
    let mut image: Vec<u8> = Vec::new();
    let mut entries: Vec<(&str, u64, usize)> = Vec::new(); // (label, offset, len)
    for (label, bytes) in &forms {
        entries.push((label, image.len() as u64, bytes.len()));
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
    println!("== SLEIGH oracle pcode per form ==");
    for (label, off, len) in &entries {
        let decoded = ctx.one_instruction(*off)?;
        let mut canon = UniqCanon::new();
        let mut shapes = Vec::new();
        println!("-- {label} @0x{off:x} (len {len}, step {})", decoded.step);
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
    for ((label, off, _), oracle) in entries.iter().zip(&sleigh_shapes) {
        let mut disasm = rugra::disasm::X86_64Disassembler::new();
        let Ok((inst, _)) = disasm.disassemble_one(
            &image[*off as usize..],
            rugra::Address::new(*off),
        ) else {
            println!("-- {label} @0x{off:x}: DISASM FAILED");
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
            println!("-- {label} @0x{off:x} : MATCH ({} ops)", mine.len());
            for (i, o) in mine.iter().enumerate() {
                println!("   [{i}] {}", op_show(o));
            }
            pass += 1;
        } else {
            println!(
                "-- {label} @0x{off:x} : MISMATCH (mine {} ops vs oracle {} ops)",
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
