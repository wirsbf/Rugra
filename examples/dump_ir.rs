//! Node-level IR dump tool: dump Rugra's per-function P-code IR in a
//! canonical, Ghidra-comparable form (basic blocks in address order, each
//! op with its inputs/output varnodes).
//!
//! Purpose: enable faithful node-by-node comparison of Rugra's IR against
//! Ghidra's IR for the same function. The output format mirrors Ghidra's
//! `print raw` / decompiler XML `<op>` elements so a side-by-side diff is
//! straightforward.
//!
//! Usage:
//!   cargo run --release --example dump_ir -- <binary> <name_or_addr> [--post]
//!
//!   --post : dump the IR AFTER the full pipeline (default: dump BEFORE,
//!            i.e. the raw lifted p-code, matching Ghidra's pre-analysis IR)
//!
//! To compare with Ghidra:
//!   1. Run Rugra:    cargo run --release --example dump_ir -- examples/curl main > rugra_ir.txt
//!   2. In Ghidra:    Decompile main → Window → "Decompiler" → right-click →
//!                    "Debug → Display Parse Tree" OR use the Headless analyzer
//!                    with -postScript to dump `<function><codegen>` XML.
//!                    Alternatively, in the Decompiler window set the
//!                    "Format: P-Code" option (Edit → Tool Options →
//!                    Decompiler → Display → check "Show P-Code").
//!   3. Diff:         python tools/diff_ir.py rugra_ir.txt ghidra_ir.xml
//!
//! Output format (one op per line):
//!   BB<start_addr>:
//!     [seq] OPCODE  out=<space@off#size>  in0=<space@off#size>  in1=...

use goblin::Object;
use std::fs;

use rugra::action::ActionDatabase;
use rugra::address::Address;
use rugra::disasm::{Disassembler, X86_64Disassembler};
use rugra::funcdata::Funcdata;
use rugra::block::FlowBlock;

fn format_vn(vn: &rugra::varnode::Varnode) -> String {
    let space = match vn.get_space() {
        rugra::space::AddressSpace::Ram => "ram",
        rugra::space::AddressSpace::Register => "reg",
        rugra::space::AddressSpace::Unique => "u",
        rugra::space::AddressSpace::Const => "const",
        rugra::space::AddressSpace::Stack => "stack",
        rugra::space::AddressSpace::Iop => "iop",
        rugra::space::AddressSpace::Join => "join",
        _ => "?",
    };
    let mut s = format!("{}@0x{:x}#{}", space, vn.get_offset(), vn.get_size());
    if vn.is_input() { s.push_str("[in]"); }
    if vn.is_constant() { s.push_str("[c]"); }
    if vn.is_written() { s.push_str("[w]"); }
    // Append type metatype (if any) so type-propagation gaps are visible.
    if let Some(ct) = vn.get_type_read_facing() {
        let mt = format!("{:?}", ct.get_metatype())
            .trim_start_matches("TypeMetatype::")
            .to_string();
        s.push_str(&format!(":{}", mt));
    }
    s
}

fn dump_funcdata_ir(fd: &Funcdata) {
    println!("==== IR dump: {} @ 0x{:x} ({} bytes) ====", fd.name, fd.baseaddr.as_u64(), fd.size);
    println!("==== {} bblocks, {} live ops ====", fd.bblocks.get_size(), fd.obank.alivelist.len());

    // Gather (block_start_addr, block_index) pairs and sort by address.
    let mut block_idx: Vec<(u64, usize)> = (0..fd.bblocks.get_size())
        .filter_map(|i| {
            fd.bblocks.get_block(i).map(|b| {
                let start = b.read().unwrap().get_start_addr().as_u64();
                (start, i)
            })
        })
        .collect();
    block_idx.sort_by_key(|&(addr, _)| addr);

    for (start, i) in block_idx {
        let block_arc = match fd.bblocks.get_block(i) { Some(b) => b, None => continue };
        let block = block_arc.read().unwrap();
        let mut ops: Vec<_> = block.get_ops();
        // Filter out dead ops so dump shows only alive IR.
        ops.retain(|o| !o.0.read().unwrap().is_dead());
        ops.sort_by_key(|o| o.0.read().unwrap().get_addr().as_u64());
        println!();
        println!("BB 0x{:x} ({} ops):", start, ops.len());
        for op_ref in &ops {
            let op = op_ref.0.read().unwrap();
            let addr = op.get_addr();
            let opc = format!("{:?}", op.opcode)
                .trim_start_matches("CPUI_")
                .to_string();
            let mut line = format!("  [0x{:x}] {:14}", addr.as_u64(), opc);
            if let Some(out) = op.get_out() {
                let out_vn = out.read().unwrap();
                line.push_str(&format!("  out={}", format_vn(&out_vn)));
            }
            for s in 0..op.num_input() {
                if let Some(in_vn) = op.get_in(s) {
                    let in_vn_read = in_vn.read().unwrap();
                    line.push_str(&format!("  in{}={}", s, format_vn(&in_vn_read)));
                }
            }
            let dead = (op.flags & rugra::op::pcodeop_flags::DEAD) != 0;
            if dead { line.push_str("  [DEAD]"); }
            println!("{}", line);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: dump_ir <binary> <name_or_addr> [--post]");
        eprintln!("  --post : dump IR after full pipeline (default: before)");
        std::process::exit(1);
    }
    let bin_path = &args[1];
    let target = &args[2];
    let post_pipeline = args.iter().any(|a| a == "--post");

    let buffer = match fs::read(bin_path) {
        Ok(b) => b,
        Err(e) => { eprintln!("Error reading {}: {}", bin_path, e); std::process::exit(1); }
    };
    let obj = match Object::parse(&buffer) {
        Ok(o) => o,
        Err(e) => { eprintln!("Error parsing: {}", e); std::process::exit(1); }
    };
    let elf = match obj {
        Object::Elf(e) => e,
        _ => { eprintln!("Not an ELF"); std::process::exit(1); }
    };

    // Resolve target (address or symbol name).
    let mut func_addr: Option<u64> = None;
    let mut func_size: u64 = 0x1000;
    let mut func_name = String::new();
    let as_addr = target.strip_prefix("0x").or_else(|| target.strip_prefix("0X")).unwrap_or(target);
    if let Ok(addr) = u64::from_str_radix(as_addr, 16) {
        func_addr = Some(addr);
        func_name = format!("sub_{:x}", addr);
    }
    if func_addr.is_none() {
        for sym in elf.syms.iter().chain(elf.dynsyms.iter()) {
            if let Some(name) = elf.strtab.get_at(sym.st_name).or_else(|| elf.dynstrtab.get_at(sym.st_name)) {
                if name == target {
                    func_addr = Some(sym.st_value);
                    func_size = sym.st_size;
                    func_name = name.to_string();
                    break;
                }
            }
        }
    }
    let func_addr = match func_addr {
        Some(a) => a,
        None => { eprintln!("Function '{}' not found", target); std::process::exit(1); }
    };

    // Find executable LOAD segment covering func_addr.
    let text_seg = elf.program_headers.iter()
        .find(|p| p.p_type == goblin::elf::program_header::PT_LOAD && p.p_flags & 1 != 0)
        .and_then(|p| if func_addr >= p.p_vaddr && func_addr < p.p_vaddr + p.p_memsz {
            Some((p.p_offset, p.p_vaddr))
        } else { None });
    let (text_off, text_vaddr) = match text_seg {
        Some(t) => t,
        None => { eprintln!("func_addr 0x{:x} not in any executable LOAD segment", func_addr); std::process::exit(1); }
    };
    let file_off = (text_off + (func_addr - text_vaddr)) as usize;
    let code_bytes = &buffer[file_off..file_off + func_size as usize];

    // Disassemble + lift to raw p-code via SLEIGH FFI (same as curl_decompile.rs,
    // which emits the push88 return-address STORE — the artifact we're diffing).
    let mut disasm = X86_64Disassembler::new();
    let instructions = match disasm.disassemble(code_bytes, Address::new(func_addr)) {
        Ok(v) => v,
        Err(e) => { eprintln!("Disassembly failed: {}", e); std::process::exit(1); }
    };
    let inst_offsets: Vec<(u64, usize)> = instructions.iter()
        .map(|i| (i.address.as_u64() - func_addr, i.length))
        .collect();
    let all_ops = rugra::disasm::sleigh_lift::SleighLifter::lift_function(
        code_bytes, func_addr, &inst_offsets,
    );
    let mut raw_ops = Vec::new();
    for (_addr, ops) in &all_ops {
        for op in ops {
            raw_ops.push(op.clone());
        }
    }

    let mut fd = Funcdata::new(&func_name, Address::new(func_addr), func_size as i32);
    fd.inject_raw_ops(&raw_ops);
    // inject_raw_ops internally builds bblocks and numbers input varnodes.

    if !post_pipeline {
        println!("# Rugra IR (PRE-pipeline, raw lifted p-code):");
        dump_funcdata_ir(&fd);
        return;
    }

    // Optionally seed DWARF struct-pointer types so the POST IR matches what
    // the real driver (curl_decompile.rs) produces. Without this, ActionInferTypes
    // has no Pointer(Struct) roots and RulePtrArith never fires.
    if args.iter().any(|a| a == "--seed") {
        seed_global_struct_ptrs(&mut fd);
    }

    // Run the full pipeline, then dump.
    let fd_arc = std::sync::Arc::new(std::sync::RwLock::new(fd));
    fd_arc.write().unwrap().set_self_ref(std::sync::Arc::downgrade(&fd_arc));
    let mut db = ActionDatabase::new();
    db.set_default_actions();
    if let Some(action) = db.get_action_mut("decompile") {
        let mut fd_write = fd_arc.write().unwrap();
        eprintln!("[PIPE] {} action apply START", fd_write.name);
        let _ = action.apply(&mut *fd_write);
        eprintln!("[PIPE] {} action apply DONE", fd_write.name);
    }
    let fd_read = fd_arc.read().unwrap();
    println!("# Rugra IR (POST-pipeline, after full decompile):");
    println!("# type_recovery_started={} global_struct_ptrs={}",
        fd_read.has_type_recovery_started(), fd_read.global_struct_ptrs.len());
    dump_funcdata_ir(&fd_read);
}

/// Seed the same DWARF struct-pointer map the real driver
/// (curl_decompile.rs::build_dwarf_struct_pointers) uses, so the POST IR
/// reflects Pointer(Struct) propagation and RulePtrArith can fire.
fn seed_global_struct_ptrs(fd: &mut Funcdata) {
    use rugra::type_system::typefactory::TypeFactory;
    use rugra::type_system::datatype::{Datatype, TypeField, TypeMetatype};
    let mut tf = TypeFactory::new(8);
    let long8 = tf.get_base(8, TypeMetatype::Int).expect("long base type");
    let field = |name: &str, off: usize| -> TypeField {
        TypeField { name: name.to_string(), offset: off, type_ptr: long8.clone() }
    };
    tf.create_struct("Configurable");
    tf.set_fields("Configurable", vec![
        field("useragent", 0), field("cookie", 8), field("use_resume", 16),
        field("resume_from", 20), field("postfields", 24), field("referer", 32),
        field("timeout", 40), field("outfile", 48), field("headerfile", 56),
        field("remotefile", 64), field("ftpport", 72), field("porttouse", 80),
        field("range", 88), field("low_speed_limit", 96), field("low_speed_time", 100),
        field("showerror", 104), field("infile", 112), field("userpwd", 120),
        field("proxyuserpwd", 128), field("proxy", 136), field("configread", 144),
        field("conf", 152), field("cert", 168), field("cert_passwd", 176),
        field("crlf", 184), field("cookiefile", 192), field("customrequest", 200),
        field("progressmode", 208), field("nobuffer", 209), field("writeout", 216),
        field("errors", 224), field("quote", 232), field("postquote", 240),
        field("ssl_version", 248), field("timecond", 256), field("condtime", 264),
        field("headers", 272), field("httppost", 280), field("last_post", 288),
        field("httpreq", 296),
    ]);
    tf.create_struct("URLGlob");
    tf.set_fields("URLGlob", vec![
        field("size", 0), field("urllen", 4), field("literal", 8),
        field("pattern", 16), field("beenhere", 24), field("glob_buffer", 32),
        field("trailer_296", 296),
    ]);
    tf.create_struct("ProgressData");
    tf.set_fields("ProgressData", vec![
        field("total", 0), field("prev", 8), field("point", 16), field("width", 24),
    ]);
    let configurable = tf.find_by_name("Configurable").expect("Configurable struct");
    let configurable_ptr = tf.get_ptr(configurable.clone());
    let urlglob = tf.find_by_name("URLGlob").expect("URLGlob struct");
    let urlglob_ptr = tf.get_ptr(urlglob.clone());
    // ::config @ 0x17520, glob_expand @ 0x17660
    fd.global_struct_ptrs.insert(0x17520, configurable_ptr);
    fd.global_struct_ptrs.insert(0x17660, urlglob_ptr);
}

