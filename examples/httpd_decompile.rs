//! End-to-end decompilation demo for the httpd binary
//! Run with: cargo run --release --example httpd_decompile

use goblin::Object;
use std::fs;
use std::collections::HashMap;
use std::alloc::{GlobalAlloc, System, Layout};

struct GuardAlloc;

const MAX_ALLOC: usize = 512 * 1024 * 1024; // 512MB threshold

unsafe impl GlobalAlloc for GuardAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() > MAX_ALLOC {
            let bt = std::backtrace::Backtrace::force_capture();
            eprintln!("FATAL: allocation of {} bytes blocked!\n{}", layout.size(), bt);
            std::process::abort();
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static ALLOC: GuardAlloc = GuardAlloc;

use rugra::action::{Action, ActionDatabase};
use rugra::disasm::{Disassembler, X86_64Disassembler, X86Lifter};
use rugra::funcdata::Funcdata;
use rugra::printc::PrintC;
use rugra::prettyprint::EmitNoMarkup;
use rugra::printlanguage::PrintLanguage;
use rugra::address::Address;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Rugra Decompilation: httpd ===\n");

    let buffer = match fs::read("examples/httpd") {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: Could not read examples/httpd: {}", e);
            return Ok(());
        }
    };

    let obj = Object::parse(&buffer)?;

    let mut functions: Vec<(u64, usize, u64, String)> = Vec::new();
    let mut symbol_table: HashMap<u64, String> = HashMap::new();
    let mut string_table: HashMap<u64, String> = HashMap::new();

    if let Object::Elf(elf) = &obj {
        for sym in elf.syms.iter() {
            if sym.st_value != 0 {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        symbol_table.insert(sym.st_value, name.to_string());
                    }
                    if sym.is_function() {
                        let mut file_off = 0u64;
                        for header in elf.section_headers.iter() {
                            if sym.st_value >= header.sh_addr && sym.st_value < header.sh_addr + header.sh_size {
                                file_off = header.sh_offset + (sym.st_value - header.sh_addr);
                                break;
                            }
                        }
                        if file_off > 0 {
                            let size = if sym.st_size > 0 { sym.st_size as usize } else { 512 };
                            functions.push((sym.st_value, size, file_off, name.to_string()));
                        }
                    }
                }
            }
        }

        for sym in elf.dynsyms.iter() {
            if sym.is_function() && sym.st_value != 0 {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    symbol_table.entry(sym.st_value).or_insert_with(|| name.to_string());
                    let mut file_off = 0u64;
                    for header in elf.section_headers.iter() {
                        if sym.st_value >= header.sh_addr && sym.st_value < header.sh_addr + header.sh_size {
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

        // Collect strings only from read-only allocated sections (.rodata).
        // Exclude .text (SHF_EXECINSTR), .data (SHF_WRITE), and non-allocated
        // sections like .comment (no SHF_ALLOC). This prevents GCC version
        // strings from .comment and assembly bytes from .text from polluting
        // the string table.
        for header in elf.section_headers.iter() {
            let is_rodata = header.sh_type == 1
                && header.sh_size > 0
                && (header.sh_flags & 0x2) != 0  // SHF_ALLOC
                && (header.sh_flags & 0x1) == 0  // not SHF_WRITE
                && (header.sh_flags & 0x4) == 0; // not SHF_EXECINSTR
            if !is_rodata { continue; }
            let start = header.sh_offset as usize;
            let end = std::cmp::min(start + header.sh_size as usize, buffer.len());
            if start >= end { continue; }
            let data = &buffer[start..end];
            let mut i = 0;
            while i < data.len() {
                let s_start = i;
                while i < data.len() && data[i] >= 0x20 && data[i] < 0x7f { i += 1; }
                let len = i - s_start;
                if len >= 4 {
                    let s = String::from_utf8_lossy(&data[s_start..i]).to_string();
                    string_table.insert(header.sh_addr + s_start as u64, s);
                }
                i += 1;
            }
        }
    }

    println!("Found {} functions, {} symbols, {} strings\n",
             functions.len(), symbol_table.len(), string_table.len());

    // Sort by address
    functions.sort_by_key(|f| f.0);

    let max_functions = std::env::var("MAX_FUNCS").ok().and_then(|s| s.parse::<usize>().ok()).unwrap_or(30);

    // Pre-pass: collect prototypes (limited to functions being decompiled)
    let mut prototype_db: HashMap<u64, usize> = HashMap::new();
    let mut call_targets: std::collections::HashSet<u64> = std::collections::HashSet::new();

    let addr_to_fileoff = |addr: u64| -> Option<(usize, usize)> {
        if let Object::Elf(ref elf) = obj {
            for header in elf.section_headers.iter() {
                if addr >= header.sh_addr && addr < header.sh_addr + header.sh_size {
                    let off = (header.sh_offset + (addr - header.sh_addr)) as usize;
                    let end = std::cmp::min(off + 512, buffer.len());
                    return Some((off, end));
                }
            }
        }
        None
    };

    for &(vaddr, size, file_offset, ref name) in functions.iter().take(max_functions + 50) {
        if size < 5 { continue; }
        let max_size = std::cmp::min(size, 4096);
        let end_off = std::cmp::min(file_offset as usize + max_size, buffer.len());
        if file_offset as usize >= buffer.len() { continue; }
        let code_bytes = &buffer[file_offset as usize..end_off];
        let mut disasm = X86_64Disassembler::new();
        let instructions = match disasm.disassemble(code_bytes, Address::new(vaddr)) {
            Ok(insts) => insts,
            Err(_) => continue,
        };
        for inst in &instructions {
            if inst.is_call() {
                if let Some(ref bt) = inst.metadata.branch_target {
                    call_targets.insert(bt.as_u64());
                }
            }
        }
        let mut lifter = X86Lifter::new();
        let mut raw_ops = Vec::new();
        for inst in &instructions {
            let mut ops = lifter.lift(inst);
            for op in &mut ops {
                op.set_seq_num(rugra::address::SeqNum::new(inst.address, 0));
            }
            raw_ops.extend(ops);
        }
        let mut fd = Funcdata::new(name, Address::new(vaddr), size as i32);
        fd.inject_raw_ops(&raw_ops);
        fd.run_heritage_direct();
        let infer = rugra::coreaction::ActionInferParams::new();
        let _ = infer.apply(&mut fd);
        prototype_db.insert(vaddr, fd.funcp.num_params());
    }

    for &target in &call_targets {
        if prototype_db.contains_key(&target) { continue; }
        let Some((foff, fend)) = addr_to_fileoff(target) else { continue; };
        if foff >= buffer.len() { continue; }
        let code_bytes = &buffer[foff..fend];
        let mut disasm = X86_64Disassembler::new();
        let instructions = match disasm.disassemble(code_bytes, Address::new(target)) {
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
        let name = symbol_table.get(&target).cloned().unwrap_or_else(|| format!("sub_{:x}", target));
        let mut fd = Funcdata::new(&name, Address::new(target), 512);
        fd.inject_raw_ops(&raw_ops);
        fd.run_heritage_direct();
        let infer = rugra::coreaction::ActionInferParams::new();
        let _ = infer.apply(&mut fd);
        prototype_db.insert(target, fd.funcp.num_params());
    }
    eprintln!("[PREPASS] Collected {} prototypes ({} from call targets)", prototype_db.len(), call_targets.len());

    let mut total_success = 0;
    let mut total_fail = 0;

    for (idx, &(vaddr, size, file_offset, ref name)) in functions.iter().enumerate() {
        if idx >= max_functions { break; }
        if size < 5 || name == "_start" || name.starts_with("register_tm_clones") || name.starts_with("deregister_tm_clones") || name == "__libc_csu_init" || name == "__libc_csu_fini" || name == "frame_dummy" {
            continue;
        }

        eprintln!("[DECOMP] {}/{} {}", idx+1, max_functions, name);

        let max_size = std::cmp::min(size, 8192);
        let end_off = std::cmp::min(file_offset as usize + max_size, buffer.len());
        if file_offset as usize >= buffer.len() { continue; }
        let code_bytes = &buffer[file_offset as usize..end_off];

        let mut disasm = X86_64Disassembler::new();
        let instructions = match disasm.disassemble(code_bytes, Address::new(vaddr)) {
            Ok(insts) => insts,
            Err(_) => { total_fail += 1; continue; }
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

        let sym_table = symbol_table.clone();
        let str_table = string_table.clone();
        let func_name = name.clone();
        let func_size = size;
        let proto_db = prototype_db.clone();

        let handle = std::thread::spawn(move || -> Option<String> {
            let mut fd = Funcdata::new(&func_name, Address::new(vaddr), func_size as i32);
            fd.external_prototypes = proto_db;
            for (&addr, n) in &sym_table { fd.add_symbol(addr, n.clone()); }
            for (&addr, s) in &str_table { fd.add_string(addr, s.clone()); }

            fd.inject_raw_ops(&raw_ops);
            eprintln!("[THREAD] {} inject done ops={} blocks={}", func_name, fd.obank.alivelist.len(), fd.bblocks.get_size());

            let fd_arc = std::sync::Arc::new(std::sync::RwLock::new(fd));
            fd_arc.write().unwrap().set_self_ref(std::sync::Arc::downgrade(&fd_arc));

            let mut db = ActionDatabase::new();
            db.set_default_actions();
            if let Some(action) = db.get_action("decompile") {
                let mut fd_write = fd_arc.write().unwrap();
                eprintln!("[THREAD] {} actions start", func_name);
                let result = action.apply(&mut *fd_write);
                eprintln!("[THREAD] {} actions done ({})", func_name, if result.is_ok() { "ok" } else { "err" });
            }

            let fd_read = fd_arc.read().unwrap();
            let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
            printer.doc_function(&fd_read);
            let output = printer.take_emit();
            let text = output.into_any().downcast::<EmitNoMarkup>().unwrap();
            Some(text.get_output())
        });

        match handle.join() {
            Ok(Some(output)) => {
                println!("/* ---- 0x{:x}: {} ({} bytes) ---- */", vaddr, name, size);
                println!("{}", output);
                println!();
                total_success += 1;
            }
            _ => {
                total_fail += 1;
            }
        }
    }

    println!("\n=== Summary: {} functions decompiled, {} skipped/failed ===",
             total_success, total_fail);

    Ok(())
}
