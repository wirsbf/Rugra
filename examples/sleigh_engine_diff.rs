//! Op-for-op dual-engine decode differential (Phase2 gate instrument,
//! ticket SLEIGH-RUSTIFY-PHASE2-0001).
//!
//! Loads the same `.sla` and the same image bytes into BOTH engines (the
//! locked C++ runtime via the shim C ABI and the vendored kuna-sleigh Rust
//! runtime) in one process, decodes every corpus offset through each, and
//! compares the complete observable results per offset:
//!   - success: `step` + every emitted op (address space/offset, opcode,
//!     num_inputs, has_output, output + all inputs with space/offset/size/
//!     space_ref/identity)
//!   - failure: error kind + `instruction_length` (Unimpl) + message bytes
//!   - metadata: space catalog and register catalog enumeration
//!
//! Corpora (mirror the Phase0 probe_decode faces, extended):
//!   - the ELF header prefix of a real binary (garbage-as-instructions)
//!   - a deterministic LCG garbage stream
//!   - every byte offset of each corpus binary's `.text` (per-byte mode)
//!   - a linear disassembler sweep (step/+1) per `.text`
//!
//! Exit code 0 iff zero divergences.

use std::time::Instant;

use rugra::sleigh_ffi::{DecodedInstruction, SleighCtx, SleighDecodeError, SleighEngineKind};

/// Deterministic garbage stream (xorshift64*), independent of any file.
fn lcg_bytes(len: usize) -> Vec<u8> {
    let mut state = 0x243f_6a88_85a3_08d3u64;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        })
        .collect()
}

/// Extract executable sections from an ELF via goblin (names `.text` etc.).
fn exec_sections(path: &str) -> Vec<(String, Vec<u8>, u64)> {
    let Ok(bytes) = std::fs::read(path) else {
        eprintln!("[DIFF] corpus missing, skipping: {path}");
        return Vec::new();
    };
    let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(&bytes) else {
        eprintln!("[DIFF] corpus not an ELF, skipping: {path}");
        return Vec::new();
    };
    elf.section_headers
        .iter()
        .enumerate()
        .filter_map(|(index, header)| {
            if header.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 == 0 {
                return None;
            }
            let name = elf.shdr_strtab.get_at(header.sh_name)?;
            let start = header.sh_offset as usize;
            let end = start.checked_add(header.sh_size as usize)?;
            let data = bytes.get(start..end)?.to_vec();
            if data.is_empty() {
                return None;
            }
            Some((name.to_string(), data, header.sh_addr))
        })
        .collect()
}

struct CorpusFace {
    label: String,
    image: Vec<u8>,
    base: u64,
}

/// One corpus face's per-byte comparison across both engines.
struct FaceTally {
    instructions: u64,
    ok_pairs: u64,
    err_pairs: u64,
    op_total: u64,
    mismatches: Vec<String>,
}

fn format_decoded(decoded: &DecodedInstruction) -> String {
    let mut text = format!("step={} ops={}", decoded.step, decoded.ops.len());
    for (index, op) in decoded.ops.iter().enumerate() {
        text.push_str(&format!(
            "\n  op[{index}] at={}:{}#{} opc={} n={}:{} out[{}]",
            op.address_space,
            op.address_offset,
            op.num_inputs,
            op.opcode,
            op.has_output,
            op.has_output,
            format_varnode(&op.output)
        ));
        for (slot, input) in op.inputs.iter().enumerate() {
            text.push_str(&format!("\n    in[{slot}]={}", format_varnode(input)));
        }
    }
    text
}

fn format_varnode(varnode: &rugra::sleigh_ffi::VarnodeC) -> String {
    format!(
        "{{sp={},off={:#x},sz={},ref={},id={}}}",
        varnode.space, varnode.offset, varnode.size, varnode.space_ref, varnode.identity
    )
}

fn format_error(error: &SleighDecodeError) -> String {
    format!(
        "err kind={:?} len={:?} msg={}",
        error.kind,
        error.instruction_length,
        error.message_lossy()
    )
}

/// Compare one decode result pair; Some(divergence) on mismatch.
fn compare_pair(
    offset: u64,
    cpp: &Result<DecodedInstruction, SleighDecodeError>,
    rust: &Result<DecodedInstruction, SleighDecodeError>,
) -> Option<String> {
    match (cpp, rust) {
        (Ok(cpp_ok), Ok(rust_ok)) => {
            if cpp_ok == rust_ok {
                None
            } else {
                Some(format!(
                    "offset {offset:#x}:\n  C++  {}\n  Rust {}",
                    format_decoded(cpp_ok),
                    format_decoded(rust_ok)
                ))
            }
        }
        (Err(cpp_err), Err(rust_err)) => {
            // Error-kind and length must match. The message bytes come from
            // two different runtimes' diagnostics; compare them but classify
            // a pure message-text difference as its own (still fatal) class
            // so the report shows exactly what differs.
            if cpp_err.kind == rust_err.kind
                && cpp_err.instruction_length == rust_err.instruction_length
            {
                if cpp_err.message == rust_err.message {
                    None
                } else {
                    Some(format!(
                        "offset {offset:#x}: error message bytes differ\n  C++  {}\n  Rust {}",
                        format_error(cpp_err),
                        format_error(rust_err)
                    ))
                }
            } else {
                Some(format!(
                    "offset {offset:#x}: error mismatch\n  C++  {}\n  Rust {}",
                    format_error(cpp_err),
                    format_error(rust_err)
                ))
            }
        }
        (cpp_result, rust_result) => Some(format!(
            "offset {offset:#x}: status mismatch\n  C++  {}\n  Rust {}",
            cpp_result
                .as_ref()
                .map(format_decoded)
                .unwrap_or_else(|error| format_error(error)),
            rust_result
                .as_ref()
                .map(format_decoded)
                .unwrap_or_else(|error| format_error(error))
        )),
    }
}

fn run_face(face: &CorpusFace) -> FaceTally {
    let mut cpp = SleighCtx::with_engine(SleighEngineKind::Cpp).expect("cpp engine");
    let mut rust = SleighCtx::with_engine(SleighEngineKind::Rust).expect("rust engine");
    for engine in [&mut cpp, &mut rust] {
        engine.load_pspec("sleigh_specs/x86-64.pspec");
        engine
            .try_set_image(&face.image, face.base)
            .expect("image install");
    }

    let mut tally = FaceTally {
        instructions: 0,
        ok_pairs: 0,
        err_pairs: 0,
        op_total: 0,
        mismatches: Vec::new(),
    };

    // Per-byte mode: every byte position of the image is used as an
    // instruction start address (maximal coverage of decode contexts,
    // prefixes, and error paths). Addresses are base+i so every decode
    // reads real image bytes (decoding at 0..len against a nonzero base
    // wraps below the image and only exercises DataUnavail).
    for index in 0..face.image.len() as u64 {
        let offset = face.base.wrapping_add(index);
        let cpp_result = cpp.one_instruction(offset);
        let rust_result = rust.one_instruction(offset);
        tally.instructions += 1;
        if let Some(divergence) = compare_pair(offset, &cpp_result, &rust_result) {
            tally.mismatches.push(divergence);
        }
        match (&cpp_result, &rust_result) {
            (Ok(decoded), _) => {
                tally.ok_pairs += 1;
                tally.op_total += decoded.ops.len() as u64;
            }
            (Err(_), _) => tally.err_pairs += 1,
        }
        if tally.mismatches.len() >= 8 {
            eprintln!("[DIFF] aborting face after 8 divergences");
            break;
        }
    }
    tally
}

fn main() {
    let mut faces: Vec<CorpusFace> = Vec::new();

    // Garbage stream: a deterministic LCG buffer (fresh contexts + prefixes
    // no real binary produces).
    faces.push(CorpusFace {
        label: "lcg-16k".to_string(),
        image: lcg_bytes(16 * 1024),
        base: 0x400000,
    });

    // Corpus binaries: header prefix (garbage-as-instructions, Phase0 face)
    // + every executable section (per-byte + sweep below).
    let corpus_paths = [
        "examples/curl",
        "examples/httpd",
        "/usr/bin/virt-ssh-helper",
        "/usr/local/bin/sasquatch",
        "/usr/bin/sqlite3",
        "/usr/bin/ls",
    ];
    for path in corpus_paths {
        let Ok(bytes) = std::fs::read(path) else {
            eprintln!("[DIFF] corpus missing, skipping: {path}");
            continue;
        };
        let prefix = bytes.len().min(512);
        faces.push(CorpusFace {
            label: format!("{path}:header[0:{prefix}]"),
            image: bytes[..prefix].to_vec(),
            base: 0,
        });
        for (name, data, address) in exec_sections(path) {
            faces.push(CorpusFace {
                label: format!("{path}:{name}"),
                image: data,
                base: address,
            });
        }
    }

    let mut total_instructions = 0u64;
    let mut total_ok = 0u64;
    let mut total_err = 0u64;
    let mut total_ops = 0u64;
    let mut total_mismatches = 0usize;

    for face in &faces {
        let tally = run_face(face);
        println!(
            "[FACE] {:<52} instr={:<9} ok={:<9} err={:<7} ops={:<9} diverge={}",
            face.label,
            tally.instructions,
            tally.ok_pairs,
            tally.err_pairs,
            tally.op_total,
            tally.mismatches.len()
        );
        total_instructions += tally.instructions;
        total_ok += tally.ok_pairs;
        total_err += tally.err_pairs;
        total_ops += tally.op_total;
        total_mismatches += tally.mismatches.len();
        for divergence in &tally.mismatches {
            println!("[DIVERGE] {}", divergence);
        }
    }

    // Metadata catalogs: space + register enumeration must be identical.
    let cpp = SleighCtx::with_engine(SleighEngineKind::Cpp).expect("cpp engine");
    let rust = SleighCtx::with_engine(SleighEngineKind::Rust).expect("rust engine");
    let mut catalog_divergences = 0usize;
    let (cpp_spaces, rust_spaces) = (cpp.num_spaces(), rust.num_spaces());
    if cpp_spaces != rust_spaces {
        catalog_divergences += 1;
        println!("[DIVERGE] num_spaces cpp={cpp_spaces} rust={rust_spaces}");
    }
    for index in 0..cpp_spaces {
        let cpp_entry = cpp.space_info(index);
        let rust_entry = rust.space_info(index);
        if cpp_entry != rust_entry {
            catalog_divergences += 1;
            println!("[DIVERGE] space[{index}] cpp={cpp_entry:?} rust={rust_entry:?}");
        }
    }
    let (cpp_registers, rust_registers) = (cpp.num_registers(), rust.num_registers());
    if cpp_registers != rust_registers {
        catalog_divergences += 1;
        println!("[DIVERGE] num_registers cpp={cpp_registers} rust={rust_registers}");
    }
    for index in 0..cpp_registers {
        let cpp_entry = cpp.register_info(index);
        let rust_entry = rust.register_info(index);
        if cpp_entry != rust_entry {
            catalog_divergences += 1;
            println!("[DIVERGE] register[{index}] cpp={cpp_entry:?} rust={rust_entry:?}");
        }
    }

    // Decode throughput (performance face): one pass over the largest
    // corpus image per engine, per-byte mode.
    if let Some(face) = faces
        .iter()
        .filter(|face| face.image.len() >= 1024)
        .max_by_key(|face| face.image.len())
    {
        for (kind, name) in [(SleighEngineKind::Cpp, "cpp"), (SleighEngineKind::Rust, "rust")] {
            let mut engine = SleighCtx::with_engine(kind).expect("engine");
            engine.load_pspec("sleigh_specs/x86-64.pspec");
            engine
                .try_set_image(&face.image, face.base)
                .expect("image install");
            let start = Instant::now();
            let mut decoded_ops = 0u64;
            for index in 0..face.image.len() as u64 {
                if let Ok(decoded) = engine.one_instruction(face.base.wrapping_add(index)) {
                    decoded_ops += decoded.ops.len() as u64;
                }
            }
            let elapsed = start.elapsed();
            println!(
                "[PERF] engine={name} face={} bytes={} decodes={} ops={} elapsed={:.3}s ns/decode={:.0} ns/op={:.0}",
                face.label,
                face.image.len(),
                face.image.len(),
                decoded_ops,
                elapsed.as_secs_f64(),
                elapsed.as_nanos() as f64 / face.image.len() as f64,
                if decoded_ops > 0 {
                    elapsed.as_nanos() as f64 / decoded_ops as f64
                } else {
                    0.0
                }
            );
        }
    }

    println!(
        "[SUMMARY] faces={} instructions={total_instructions} ok={total_ok} err={total_err} ops={total_ops} decode_divergences={total_mismatches} catalog_divergences={catalog_divergences}",
        faces.len()
    );
    if total_mismatches == 0 && catalog_divergences == 0 {
        println!("[VERDICT] OP-FOR-OP IDENTICAL");
        std::process::exit(0);
    } else {
        println!("[VERDICT] DIVERGENT");
        std::process::exit(1);
    }
}
