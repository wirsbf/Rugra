use goblin::Object;
use std::fs;
use std::collections::HashMap;
use std::path::Path;

use rugra::action::{Action, ActionDatabase};
use rugra::disasm::{Disassembler, X86_64Disassembler, X86Lifter};
use rugra::funcdata::Funcdata;
use rugra::printc::PrintC;
use rugra::prettyprint::EmitNoMarkup;
use rugra::printlanguage::PrintLanguage;
use rugra::address::Address;

// RUGRA-GLUE: main (no Ghidra counterpart found)
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: rugra <binary> [max_functions] [--symbols-only]");
        eprintln!("  binary          ELF/PE binary to decompile");
        eprintln!("  max_functions   Limit number of functions (default: all)");
        eprintln!("  --symbols-only  Only decompile functions with symbols (skip stripped)");
        return;
    }

    let binary_path = &args[1];
    let max_functions = args.get(2)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(usize::MAX);

    let buffer = match fs::read(binary_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: cannot read {}: {}", binary_path, e);
            std::process::exit(1);
        }
    };

    let obj = match Object::parse(&buffer) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Error: cannot parse binary: {}", e);
            std::process::exit(1);
        }
    };

    let elf = match &obj {
        Object::Elf(e) => e,
        _ => {
            eprintln!("Error: only ELF binaries are supported");
            std::process::exit(1);
        }
    };

    let mut functions: Vec<(u64, usize, u64, String)> = Vec::new();
    let mut symbol_table: HashMap<u64, String> = HashMap::new();
    let mut string_table: HashMap<u64, String> = HashMap::new();

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

    for header in elf.section_headers.iter() {
        let is_rodata = header.sh_type == 1
            && header.sh_size > 0
            && (header.sh_flags & 0x2) != 0
            && (header.sh_flags & 0x1) == 0
            && (header.sh_flags & 0x4) == 0;
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

    functions.sort_by_key(|f| f.0);

    eprintln!("[INFO] {} — {} functions, {} symbols, {} strings",
        Path::new(binary_path).file_name().unwrap_or_default().to_string_lossy(),
        functions.len(), symbol_table.len(), string_table.len());

    let take_count = max_functions.min(functions.len()) + 50;

    let mut prototype_db: HashMap<u64, usize> = HashMap::new();
    let mut call_targets: std::collections::HashSet<u64> = std::collections::HashSet::new();

    let addr_to_fileoff = |addr: u64| -> Option<(usize, usize)> {
        for header in elf.section_headers.iter() {
            if addr >= header.sh_addr && addr < header.sh_addr + header.sh_size {
                let off = (header.sh_offset + (addr - header.sh_addr)) as usize;
                let end = std::cmp::min(off + 512, buffer.len());
                return Some((off, end));
            }
        }
        None
    };

    // LoadImage wrapper for flow tracking (translates vaddr → file offset → bytes).
    struct BufferLoadImage<'b> {
        buffer: &'b [u8],
        sections: &'b [goblin::elf::SectionHeader],
    }
    // RUGRA-GLUE: BufferLoadImage 实现 LoadImage trait，将 ELF vaddr 翻译为
    // file offset 读取字节。Ghidra 用 LoadImage 抽象（loadimage.hh）。
    impl<'b> rugra::loadimage::LoadImage for BufferLoadImage<'b> {
        // RUGRA-GLUE: trait impl
        fn get_filename(&self) -> &str { "binary" }
        // RUGRA-GLUE: trait impl
        fn get_arch_type(&self) -> String { "x86_64".to_string() }
        // RUGRA-GLUE: trait impl
        fn adjust_vma(&mut self, _adjust: i64) {}
        // RUGRA-GLUE: trait impl
        fn load_fill(&self, size: usize, addr: rugra::address::Address) -> Result<Vec<u8>, rugra::loadimage::DataUnavailError> {
            let vaddr = addr.as_u64();
            for header in self.sections {
                if vaddr >= header.sh_addr && vaddr < header.sh_addr + header.sh_size {
                    let off = (header.sh_offset + (vaddr - header.sh_addr)) as usize;
                    let avail = self.buffer.len().saturating_sub(off);
                    let take = std::cmp::min(size, avail);
                    if take == 0 {
                        return Err(rugra::loadimage::DataUnavailError(format!("no bytes at {:#x}", vaddr)));
                    }
                    let mut result = self.buffer[off..off + take].to_vec();
                    result.resize(size, 0); // pad with zeros
                    return Ok(result);
                }
            }
            Err(rugra::loadimage::DataUnavailError(format!("addr {:#x} not in any section", vaddr)))
        }
    }
    let load_img = BufferLoadImage { buffer: &buffer, sections: &elf.section_headers };

    for &(vaddr, size, file_offset, ref name) in functions.iter().take(take_count) {
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

    let mut success = 0u32;
    let mut failed = 0u32;

    for (idx, &(vaddr, size, file_offset, ref name)) in functions.iter().enumerate() {
        if idx >= max_functions { break; }
        if size < 5 || name == "_start" || name == "register_tm_clones" || name == "deregister_tm_clones"
            || name == "frame_dummy" { continue; }

        let max_size = std::cmp::min(size, 8192);
        let eaddr = vaddr + max_size as u64;
        if file_offset as usize >= buffer.len() { continue; }

        // Use FlowInfo (reachability-based flow tracking) instead of linear scan.
        let mut disasm = X86_64Disassembler::new();
        let mut lifter = X86Lifter::new();
        let mut fd = Funcdata::new(name, Address::new(vaddr), size as i32);
        fd.external_prototypes = prototype_db.clone();
        for (&addr, n) in &symbol_table { fd.add_symbol(addr, n.clone()); }
        for (&addr, s) in &string_table { fd.add_string(addr, s.clone()); }
        rugra::flow::follow_flow(
            &mut fd,
            &load_img as &dyn rugra::loadimage::LoadImage,
            &mut disasm as &mut dyn rugra::disasm::Disassembler,
            &mut lifter,
            Address::new(vaddr),
            eaddr,
        );
        fd.run_heritage_direct();
        let mut infer = rugra::coreaction::ActionInferParams::new();
        let _ = infer.apply(&mut fd);

        let fd_arc = std::sync::Arc::new(std::sync::RwLock::new(fd));
        fd_arc.write().unwrap().set_self_ref(std::sync::Arc::downgrade(&fd_arc));

        let handle = std::thread::spawn(move || -> Option<String> {

            let mut db = ActionDatabase::new();
            db.set_default_actions();
            if let Some(action) = db.get_action_mut("decompile") {
                let mut fd_write = fd_arc.write().unwrap();
                let _ = action.apply(&mut *fd_write);
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
                success += 1;
            }
            _ => { failed += 1; }
        }
    }

    eprintln!("[INFO] {} functions decompiled, {} failed", success, failed);
}
