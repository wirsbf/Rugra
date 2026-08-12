//! End-to-end decompilation demo for the curl binary — ALL functions
//! Run with: cargo run --example curl_decompile

use goblin::Object;
use std::fs;
use std::collections::HashMap;
use std::sync::Arc;

use rugra::action::ActionDatabase;
use rugra::disasm::{Disassembler, X86_64Disassembler, X86Lifter};
use rugra::disasm::sleigh_lift::SleighLifter;
use rugra::funcdata::Funcdata;
use rugra::printc::PrintC;
use rugra::prettyprint::EmitNoMarkup;
use rugra::printlanguage::PrintLanguage;
use rugra::address::Address;
use rugra::debugproto::{DebugPrototypeDatabase, X86_64GccStorage};
use rugra::type_system::typefactory::TypeFactory;
use rugra::type_system::datatype::{Datatype, TypeField};

/// Build the DWARF-derived struct types for the curl binary and return a map
/// from global-variable address → struct-pointer Datatype. The driver seeds
/// each per-function Funcdata's `global_struct_ptrs` with this map so that
/// `type_infer::propagate_types` stamps the struct-pointer types onto the
/// constant varnodes that reference these globals.
///
/// The struct layouts are extracted from the curl ELF's DWARF debug_info via
/// `tools/extract_dwarf_structs.py`. This stands in for the Architecture/
/// TypeFactory layer that Ghidra populates from .cspec/.specfile; Rugra's
/// driver has no Architecture layer, so we register the types here.
fn build_dwarf_struct_pointers() -> HashMap<u64, Arc<Datatype>> {
    let mut tf = TypeFactory::new(8);

    // Helper field type: a pointer-sized long (the DWARF extraction reports
    // every member as `long`, which is the pointer-sized slot). Using `long`
    // for char*/long/int members keeps field offsets accurate for PTRSUB
    // generation without needing the full DWARF type tree.
    let long8 = tf.get_base(8, rugra::type_system::datatype::TypeMetatype::Int)
        .expect("long base type");
    let field = |name: &str, off: usize| -> TypeField {
        TypeField { name: name.to_string(), offset: off, type_ptr: long8.clone() }
    };

    // struct Configurable { ... 304 bytes ... }  (DWARF DW_AT_byte_size: 304)
    // Global `::config` lives at 0x17520.
    tf.create_struct("Configurable");
    tf.set_fields("Configurable", vec![
        field("useragent", 0),
        field("cookie", 8),
        field("use_resume", 16),
        field("resume_from", 20),
        field("postfields", 24),
        field("referer", 32),
        field("timeout", 40),
        field("outfile", 48),
        field("headerfile", 56),
        field("remotefile", 64),
        field("ftpport", 72),
        field("porttouse", 80),
        field("range", 88),
        field("low_speed_limit", 96),
        field("low_speed_time", 100),
        field("showerror", 104),
        field("infile", 112),
        field("userpwd", 120),
        field("proxyuserpwd", 128),
        field("proxy", 136),
        field("configread", 144),
        field("conf", 152),
        field("cert", 168),
        field("cert_passwd", 176),
        field("crlf", 184),
        field("cookiefile", 192),
        field("customrequest", 200),
        field("progressmode", 208),
        field("nobuffer", 209),
        field("writeout", 216),
        field("errors", 224),
        field("quote", 232),
        field("postquote", 240),
        field("ssl_version", 248),
        field("timecond", 256),
        field("condtime", 264),
        field("headers", 272),
        field("httppost", 280),
        field("last_post", 288),
        field("httpreq", 296),
    ]);

    // struct OutStruct { char *filename; FILE *stream; }  (16 bytes)
    // Used as a local `OutStruct outs;` on the stack — no single global, but
    // we register the type so propagated pointers can resolve to it.
    tf.create_struct("OutStruct");
    tf.set_fields("OutStruct", vec![
        field("filename", 0),
        field("stream", 8),
    ]);

    // struct ProgressData { long total; long prev; long point; long width; }
    tf.create_struct("ProgressData");
    tf.set_fields("ProgressData", vec![
        field("total", 0),
        field("prev", 8),
        field("point", 16),
        field("width", 24),
    ]);

    // struct HttpPost { ... } — chain node used by multipart post handling.
    tf.create_struct("HttpPost");
    tf.set_fields("HttpPost", vec![
        field("next", 0),
        field("name", 8),
        field("contents", 16),
        field("contenttype", 24),
        field("more", 32),
        field("flags", 40),
    ]);

    // Build the struct and pointer types and the address→type map.
    let configurable = tf.find_by_name("Configurable").expect("Configurable struct");
    let configurable_ptr = tf.get_ptr(configurable.clone());
    let _outstruct = tf.find_by_name("OutStruct").expect("OutStruct struct");
    let _progressdata = tf.find_by_name("ProgressData").expect("ProgressData struct");
    let _httppost = tf.find_by_name("HttpPost").expect("HttpPost struct");

    let mut map: HashMap<u64, Arc<Datatype>> = HashMap::new();
    // ::config @ 0x17520 (from DWARF DW_AT_location DW_OP_addr: 0x17520).
    // The global is accessed via RIP-relative lea which puts the ADDRESS
    // (a Configurable*) into a register. So stamp the POINTER type on the
    // address constant, not the struct itself. This lets ActionInferTypes
    // propagate Configurable* through COPY/INT_ADD chains to reach the
    // STORE address base varnode, triggering ->field rendering.
    map.insert(0x17520, configurable_ptr.clone());
    // Also expose the struct-pointer type for code that takes `&::config`
    // (the IR surfaces this via RIP-relative lea into a register). The
    // pointer type is registered in the TypeFactory under "Configurable *"
    // so propagation consumers can find it; we don't map an address to it.
    let _ = configurable_ptr;
    map
}


/// Information about one function in the ELF
struct FuncInfo {
    vaddr: u64,
    size: usize,
    file_offset: u64,
    name: String,
}

fn main() {
    // Run in a thread with a large stack to avoid stack overflow from
    // deeply nested ActionGroup.perform recursion in the repeatapply pipeline.
    let child = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024) // 256MB
        .spawn(|| {
            if let Err(e) = run_main() {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        })
        .expect("Failed to spawn stack thread");
    child.join().expect("Worker thread panicked");
}

fn run_main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Rugra End-to-End Decompilation: curl (all functions) ===\n");

    let buffer = match fs::read("examples/curl") {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: Could not read examples/curl: {}", e);
            return Ok(());
        }
    };

    let obj = Object::parse(&buffer)?;
    let elf = match &obj {
        Object::Elf(elf) => elf,
        _ => {
            eprintln!("Unsupported binary format. Expected ELF.");
            return Ok(());
        }
    };

    // Ghidra imports DWARF into its Program database before constructing
    // Funcdata. Build the same known-prototype database once, then apply each
    // matching prototype before any Rugra Action runs.
    let debug_prototypes = DebugPrototypeDatabase::parse_elf(&buffer)?;
    let register_context = rugra::sleigh_ffi::SleighCtx::new()
        .ok_or("unable to initialize SLEIGH register catalog")?;
    let prototype_storage = X86_64GccStorage::from_sleigh(&register_context)?;
    eprintln!(
        "[PREPASS] Imported {} DWARF function prototypes",
        debug_prototypes.len()
    );

    // Collect all functions and ELF metadata
    let mut functions: Vec<FuncInfo> = Vec::new();
    let mut symbol_table: HashMap<u64, String> = HashMap::new();
    let mut string_table: HashMap<u64, String> = HashMap::new();
    let mut plt_symbols: HashMap<u64, String> = HashMap::new();

    {
        // Collect all function symbols
        for sym in elf.syms.iter() {
            if sym.st_value != 0 {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        symbol_table.insert(sym.st_value, name.to_string());
                    }
                    if sym.is_function() && sym.st_size > 0 {
                        // Find file offset
                        let mut file_off = 0u64;
                        for header in elf.section_headers.iter() {
                            if sym.st_value >= header.sh_addr && sym.st_value < header.sh_addr + header.sh_size {
                                file_off = header.sh_offset + (sym.st_value - header.sh_addr);
                                break;
                            }
                        }
                        if file_off > 0 {
                            functions.push(FuncInfo {
                                vaddr: sym.st_value,
                                size: sym.st_size as usize,
                                file_offset: file_off,
                                name: name.to_string(),
                            });
                        }
                    }
                }
            }
        }

        // Dynamic symbols
        for sym in elf.dynsyms.iter() {
            if sym.st_value != 0 {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        symbol_table.insert(sym.st_value, name.to_string());
                    }
                }
            }
        }

        // PLT resolution
        {
            let mut plt_sec_base = 0u64;
            let mut plt_base = 0u64;
            for header in elf.section_headers.iter() {
                if let Some(name) = elf.shdr_strtab.get_at(header.sh_name) {
                    if name == ".plt" { plt_base = header.sh_addr; }
                    else if name == ".plt.sec" { plt_sec_base = header.sh_addr; }
                }
            }
            let (base, offset_start) = if plt_sec_base != 0 {
                (plt_sec_base, 0u64)
            } else if plt_base != 0 {
                (plt_base, 1u64)
            } else {
                (0, 0)
            };
            if base != 0 {
                for (i, reloc) in elf.pltrelocs.iter().enumerate() {
                    let plt_addr = base + 16 * (i as u64 + offset_start);
                    if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
                        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                            if !name.is_empty() {
                                plt_symbols.insert(plt_addr, name.to_string());
                                symbol_table.insert(plt_addr, name.to_string());
                            }
                        }
                    }
                }
            }
        }

        // String table from .rodata
        for header in elf.section_headers.iter() {
            if let Some(name) = elf.shdr_strtab.get_at(header.sh_name) {
                if name == ".rodata" {
                    let start = header.sh_offset as usize;
                    let end = std::cmp::min(start + header.sh_size as usize, buffer.len());
                    let rodata = &buffer[start..end];
                    let base_vaddr = header.sh_addr;
                    let mut i = 0;
                    while i < rodata.len() {
                        if rodata[i].is_ascii_graphic() || rodata[i] == b' '
                            || rodata[i] == b'\n' || rodata[i] == b'\t' || rodata[i] == b'\r' {
                            let str_start = i;
                            while i < rodata.len() && rodata[i] != 0 { i += 1; }
                            let str_len = i - str_start;
                            let va = base_vaddr + str_start as u64;
                            if str_len >= 1 {
                                let s = String::from_utf8_lossy(&rodata[str_start..str_start + str_len]);
                                if s.chars().all(|c| c.is_ascii() || c == '\u{FFFD}') {
                                    // Replace lossy replacement chars for clean display
                                    let clean: String = s.chars().filter(|c| c.is_ascii()).collect();
                                    if !clean.is_empty() {
                                        string_table.insert(va, clean);
                                    }
                                }
                            }
                        }
                        i += 1;
                    }
                    break;
                }
            }
        }

        // Synthetic BSS/data variable names for addresses without ELF symbols
        // Scan .data and .bss sections and create DAT_xxxxx entries for
        // addresses that don't already have a symbol.
        // We only create entries at 8-byte alignment to keep the table manageable.
        for header in elf.section_headers.iter() {
            if let Some(name) = elf.shdr_strtab.get_at(header.sh_name) {
                if name == ".data" || name == ".bss" {
                    let base = header.sh_addr;
                    let size = header.sh_size;
                    // Create synthetic names at every byte offset (sections are typically small)
                    if size <= 0x10000 { // Only for reasonably sized sections
                        for off in 0..size {
                            let addr = base + off;
                            if !symbol_table.contains_key(&addr) {
                                symbol_table.insert(addr, format!("DAT_{:05x}", addr));
                            }
                        }
                    }
                }
            }
        }
    }

    // Sort functions by address
    functions.sort_by_key(|f| f.vaddr);

    println!("Found {} functions, {} symbols, {} strings\n",
        functions.len(), symbol_table.len(), string_table.len());


    // Pre-pass: collect function prototypes for cross-function arg tracking.
    // Each function's detected param count is used by callers to trim CALL
    // args accurately. Mirrors Ghidra's ActionActiveParam multi-pass.
    let mut prototype_db: std::collections::HashMap<u64, usize> = debug_prototypes
        .iter()
        .map(|(&address, prototype)| (address, prototype.parameters.len()))
        .collect();
    for func in &functions {
        if func.size < 5 || func.name == "_start" { continue; }
        if prototype_db.contains_key(&func.vaddr) { continue; }
        let max_size = std::cmp::min(func.size, 4096);
        let end_offset = std::cmp::min(func.file_offset as usize + max_size, buffer.len());
        if func.file_offset as usize >= buffer.len() { continue; }
        let code_bytes = &buffer[func.file_offset as usize..end_offset];

        let mut disasm = X86_64Disassembler::new();
        let instructions = match disasm.disassemble(code_bytes, Address::new(func.vaddr)) {
            Ok(insts) => insts,
            Err(_) => continue,
        };

        let mut lifter = X86Lifter::new();
        let mut raw_ops = Vec::new();
        for inst in &instructions {
            let mut ops = lifter.lift(inst);
            for op in &mut ops {
                op.set_seq_num(rugra::address::SeqNum::new(inst.address, 0));
            }
            raw_ops.extend(ops);
        }

        let mut fd = Funcdata::new(&func.name, Address::new(func.vaddr), func.size as i32);
        fd.inject_raw_ops(&raw_ops);
        fd.run_heritage_direct();
        use rugra::action::Action;
        let mut infer = rugra::coreaction::ActionInferParams::new();
        let _ = infer.apply(&mut fd);
        prototype_db.insert(func.vaddr, fd.funcp.num_params());
    }
    eprintln!("[PREPASS] Collected {} function prototypes:", prototype_db.len());
    for (&addr, &count) in prototype_db.iter().take(30) {
        let name = symbol_table.get(&addr).cloned().unwrap_or_else(|| format!("FUN_{:08x}", addr));
        eprintln!("[PREPASS]   {} @ 0x{:x}: {} params", name, addr, count);
    }

    // Decompile each function
    let mut total_success = 0;
    let mut total_fail = 0;

    // Build the DWARF-derived struct-pointer map once; it is cloned into each
    // function's Funcdata below to seed type propagation.
    let global_struct_ptrs = build_dwarf_struct_pointers();


    for func in &functions {
        // Skip very tiny functions (< 5 bytes) and _start
        if func.size < 5 || func.name == "_start" {
            continue;
        }

        eprintln!("[SYMS] {} entries; targets 0x2000-0x5000:", symbol_table.len());
        for (&addr, name) in symbol_table.iter() {
            if addr >= 0x2000 && addr <= 0x5000 {
                eprintln!("[SYM] 0x{:x} = {}", addr, name);
            }
        }

        let Some(section) = elf.section_headers.iter().find(|section| {
            func.vaddr >= section.sh_addr
                && func.vaddr < section.sh_addr.saturating_add(section.sh_size)
        }) else {
            total_fail += 1;
            continue;
        };
        let section_start = section.sh_offset as usize;
        let section_end = section
            .sh_offset
            .saturating_add(section.sh_size)
            .min(buffer.len() as u64) as usize;
        let Some(section_image) = buffer.get(section_start..section_end) else {
            total_fail += 1;
            continue;
        };
        let mut sleigh = SleighLifter::new();
        if let Err(error) = sleigh.configure_x86_64(section_image, section.sh_addr) {
            eprintln!("[FLOW] {}: failed to configure SLEIGH: {}", func.name, error);
            total_fail += 1;
            continue;
        }

        // Run analysis + decompilation in a thread with timeout
        let sym_table = symbol_table.clone();
        let str_table = string_table.clone();
        let func_name = func.name.clone();
        let func_vaddr = func.vaddr;
        let func_size = func.size;
        let proto_db = prototype_db.clone();
        let gsp = global_struct_ptrs.clone();
        let debug_db = debug_prototypes.clone();
        let debug_storage = prototype_storage.clone();

        let handle = std::thread::spawn(move || -> Option<String> {
            let t0 = std::time::Instant::now();
            eprintln!("[STEP] {} START", func_name);

            let mut fd = Funcdata::new(&func_name, Address::new(func_vaddr), func_size as i32);
            match debug_db.apply(&mut fd, &debug_storage) {
                Ok(true) => eprintln!(
                    "[PREPASS] {} applied locked DWARF prototype: {} params{}",
                    func_name,
                    fd.funcp.num_params(),
                    if fd.funcp.is_varargs() { " + varargs" } else { "" }
                ),
                Ok(false) => {}
                Err(error) => eprintln!(
                    "[PREPASS] {} DWARF prototype rejected: {}",
                    func_name, error
                ),
            }
            fd.external_prototypes = proto_db;
            fd.global_struct_ptrs = gsp;
            for (&addr, name) in &sym_table {
                fd.add_symbol(addr, name.clone());
            }
            for (&addr, s) in &str_table {
                fd.add_string(addr, s.clone());
            }

            rugra::flow::follow_flow(
                &mut fd,
                &mut sleigh,
                Address::new(func_vaddr),
                u64::MAX,
            );
            eprintln!(
                "[STEP] {} flow done {:?} raw_ops={} bblocks={}",
                func_name,
                t0.elapsed(),
                fd.obank.optree.len(),
                fd.bblocks.get_size()
            );

            let fd_arc = std::sync::Arc::new(std::sync::RwLock::new(fd));
            fd_arc.write().unwrap().set_self_ref(std::sync::Arc::downgrade(&fd_arc));

            let mut db = ActionDatabase::new();
            db.set_default_actions();
            {
                let mut fd_write = fd_arc.write().unwrap();
                let _ = db.perform_action("decompile", &mut fd_write);
            }
            eprintln!("[STEP] {} action done {:?}", func_name, t0.elapsed());

            let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
            // EXPERIMENTAL: enable the RPN emit path (printc.rs build_rpn_token_table /
            // emit_block_basic_rpn / dispatch_op_rpn). NOTE: as of this experiment
            // `rpn_enabled` is only ever written, never read — doc_function does NOT
            // gate on it, so this call is expected to be a no-op. Kept here to verify
            // that hypothesis end-to-end.
            printer.set_rpn_enabled(true);
            let fd_read = fd_arc.read().unwrap();
            printer.doc_function(&fd_read);
            drop(fd_read);
            eprintln!("[STEP] {} print done {:?}", func_name, t0.elapsed());

            let output_buffer = printer.take_emit().into_any().downcast::<EmitNoMarkup>().unwrap();
            let c_code = output_buffer.get_output();

            if c_code.trim().is_empty() { None } else { Some(c_code) }
        });

        // Wait with 10-second timeout using channel
        let (tx, rx) = std::sync::mpsc::channel();
        let vaddr = func.vaddr;
        let name_copy = func.name.clone();
        let size = func.size;
        std::thread::spawn(move || {
            let result = handle.join();
            let _ = tx.send(result);
        });

        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(Ok(Some(c_code))) => {
                println!("/* ---- 0x{:x}: {} ({} bytes) ---- */", vaddr, name_copy, size);
                println!("{}", c_code);
                total_success += 1;
            }
            Ok(Ok(None)) => {
                total_fail += 1;
            }
            Ok(Err(e)) => {
                let msg = if let Some(s) = e.downcast_ref::<String>() {
                    s.clone()
                } else if let Some(s) = e.downcast_ref::<&str>() {
                    s.to_string()
                } else {
                    format!("{:?}", e)
                };
                println!("/* ---- 0x{:x}: {} PANICKED: {} ---- */", vaddr, name_copy, msg);
                total_fail += 1;
            }
            Err(_) => {
                println!("/* ---- 0x{:x}: {} TIMEOUT (>10s) ---- */", vaddr, name_copy);
                total_fail += 1;
            }
        }
    }

    println!("\n=== Summary: {} functions decompiled, {} skipped/failed ===",
        total_success, total_fail);

    Ok(())
}
