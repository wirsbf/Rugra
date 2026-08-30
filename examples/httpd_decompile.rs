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
        let mut infer = rugra::coreaction::ActionInferParams::new();
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
        let mut infer = rugra::coreaction::ActionInferParams::new();
        let _ = infer.apply(&mut fd);
        prototype_db.insert(target, fd.funcp.num_params());
    }
    eprintln!("[PREPASS] Collected {} prototypes ({} from call targets)", prototype_db.len(), call_targets.len());

    let mut total_success = 0;
    let mut total_fail = 0;

    // Known function entries for tail-call detection (TailCallAnalyzer
    // transport): ELF function symbols plus every address this corpus
    // calls (shared tail chunks Ghidra's analysis also turns into
    // functions, e.g. sub_2c960 = suck_in_APR+0x90).
    let func_entry_set: std::collections::HashSet<u64> = functions.iter().map(|f| f.0)
        .chain(call_targets.iter().copied())
        .collect();

    // PLT sections for tail-call detection: PLT stubs
    // (apr_pool_cleanup_kill@plt 0x2a970, ...) carry no .symtab entries
    // but are thunk functions on the Ghidra side; a stub START is
    // entry-aligned (sh_entsize), mid-stub addresses are not function
    // entries.
    let plt_entry_ranges: Vec<(u64, u64, u64)> = if let Object::Elf(elf) = &obj {
        elf.section_headers.iter()
            .filter(|h| {
                elf.shdr_strtab.get_at(h.sh_name).map(|n| n.starts_with(".plt")).unwrap_or(false)
            })
            .filter(|h| (h.sh_flags & 0x4) != 0) // SHF_EXECINSTR
            .map(|h| (h.sh_addr, h.sh_addr + h.sh_size, h.sh_entsize.max(1)))
            .collect()
    } else { Vec::new() };

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
        let entry_set = func_entry_set.clone();
        let plt_ranges = plt_entry_ranges.clone();

        let handle = std::thread::spawn(move || -> Option<String> {
            let mut fd = Funcdata::new(&func_name, Address::new(vaddr), func_size as i32);
            // HTTPD-STACKSLOT-FOLD-0001: Ghidra's Funcdata constructor always
            // binds its Architecture (`glb = scope->getArch()`, funcdata.cc:48)
            // — the headless oracle that produced
            // tests/golden/ghidra_httpd_1204.c decompiled every function with
            // its BfdArchitecture attached, and `RuleLoadVarnode::
            // correctSpacebase` / `RuleStoreVarnode` (ruleaction.cc:4173-4341)
            // dereference `data.getArch()->getSpaceBySpacebase(...)`
            // unconditionally. Rugra's arch-less Funcdata made those rules
            // take the miss branch for the input-RSP case, so spacebase-
            // relative STORE/LOAD (`push`/`sub rsp` prologues and `mov
            // [rsp+k], reg` spills) never reindexed into the stack space and
            // printed as raw `*(..)(in_RSP-8)` pointer expressions (148
            // in_RSP lines). Attach the canonical x86-64 Architecture —
            // exactly what curl's runner does with its worker arch at
            // curl_decompile.rs:2109/2471 — restoring the oracle invariant.
            // E2E: httpd skeleton 2546→2230, defects 5→5, numbering 0→0,
            // in_RSP lines 148→0 (2026-08-30).
            fd.set_arch(std::sync::Arc::new(rugra::arch::Architecture::new()));
            fd.external_prototypes = proto_db;
            for (&addr, n) in &sym_table { fd.add_symbol(addr, n.clone()); }
            for (&addr, s) in &str_table { fd.add_string(addr, s.clone()); }

            // Tail-call flow overrides — transport of Ghidra's Java-side
            // TailCallAnalyzer writing FlowOverride CALL_RETURN entries into
            // the program DB before decompilation: a direct `jmp` whose
            // target is a KNOWN function entry OUTSIDE this function's own
            // range is a tail call (PLT thunks, `jmp ap_getword` wrappers,
            // shared tail chunks like 0x2c960 that other functions call).
            // `inject_raw_ops` applies the override at the raw layer
            // (flow.cc:474-475 position) rewriting BRANCH→CALL and
            // appending the CALL_RETURN's RETURN. Without it the printer
            // emits the dangling `code_rXXXX: goto code_rXXXX;` self-loop
            // (GOTO-LABEL-UNPRINTED-0001 symptom family).
            for raw in &raw_ops {
                if rugra::opcodes::OpCode::from_i32(raw.get_opcode())
                    != Some(rugra::opcodes::OpCode::CPUI_BRANCH)
                {
                    continue;
                }
                let Some(tgt) = raw.inputs().first() else { continue };
                if tgt.space != rugra::space::AddressSpace::Ram { continue; }
                let known_entry = entry_set.contains(&tgt.offset)
                    || plt_ranges.iter().any(|&(s, e, es)| {
                        tgt.offset >= s && tgt.offset < e && (tgt.offset - s) % es == 0
                    });
                if !known_entry { continue; }
                if vaddr <= tgt.offset && tgt.offset < vaddr + func_size as u64 { continue; }
                if let Some(seq) = raw.seq_num() {
                    fd.localoverride.insert_flow_override(
                        seq.get_addr(),
                        rugra::override_rs::FlowOverride::CallReturn,
                    );
                }
            }

            fd.inject_raw_ops(&raw_ops);
            eprintln!("[THREAD] {} inject done ops={} blocks={}", func_name, fd.obank.alivelist.len(), fd.bblocks.get_size());

            let fd_arc = std::sync::Arc::new(std::sync::RwLock::new(fd));
            fd_arc.write().unwrap().set_self_ref(std::sync::Arc::downgrade(&fd_arc));

            let mut db = ActionDatabase::new();
            db.set_default_actions();
            {
                let mut fd_write = fd_arc.write().unwrap();
                eprintln!("[THREAD] {} actions start", func_name);
                let result = db.perform_action("decompile", &mut fd_write);
                eprintln!("[THREAD] {} actions done ({})", func_name, if result.is_ok() { "ok" } else { "err" });
            }

            let fd_read = fd_arc.read().unwrap();
            // BLOCKSTRUCT-COLLAPSE-RESIDUAL-0001 diagnostic: dump the final
            // structured tree (sblocks) for the RUGRA_DUMP_FUNC target.
            if let Ok(dump_fn) = std::env::var("RUGRA_DUMP_FUNC") {
                if dump_fn == func_name {
                    eprintln!("[DUMP] === structure tree for {} ===", func_name);
                    let mut tree_out = String::new();
                    for blk in &fd_read.sblocks.blocks {
                        rugra::block::print_tree_dbg(blk, 0, &mut tree_out);
                    }
                    eprintln!("{}", tree_out);
                }
            }
            let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
            printer.doc_function(&fd_read);
            let output = printer.take_emit();
            let text = output.into_any().downcast::<EmitNoMarkup>().unwrap();
            Some(text.get_output())
        });

        // Wait with timeout (like curl_decompile) to prevent single-function hangs
        let (tx, rx) = std::sync::mpsc::channel();
        let join_handle = handle;
        std::thread::spawn(move || {
            let result = join_handle.join();
            let _ = tx.send(result);
        });
        match rx.recv_timeout(std::time::Duration::from_secs(15)) {
            Ok(Ok(Some(output))) => {
                println!("/* ---- 0x{:x}: {} ({} bytes) ---- */", vaddr, name, size);
                println!("{}", output);
                println!();
                total_success += 1;
            }
            Ok(Ok(None)) | Ok(Err(_)) => {
                total_fail += 1;
            }
            Err(_) => {
                println!("/* ---- 0x{:x}: {} TIMEOUT (>15s) ---- */", vaddr, name);
                total_fail += 1;
            }
        }
    }

    println!("\n=== Summary: {} functions decompiled, {} skipped/failed ===",
             total_success, total_fail);

    Ok(())
}
