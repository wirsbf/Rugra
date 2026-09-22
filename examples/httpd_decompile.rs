//! End-to-end decompilation demo for the httpd binary
//! Run with: cargo run --release --example httpd_decompile

use goblin::Object;
use std::fs;
use std::collections::HashMap;
use std::alloc::{GlobalAlloc, System, Layout};
use std::io::Write;
use std::process::{Command, Stdio};

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

use rugra::action::{Action, ActionDatabase, ActionState, break_flags};
use rugra::disasm::{Disassembler, X86_64Disassembler, X86Lifter};
use rugra::funcdata::Funcdata;
use rugra::printc::PrintC;
use rugra::prettyprint::EmitNoMarkup;
use rugra::printlanguage::PrintLanguage;
use rugra::address::Address;

// RUGRA-GLUE (RUGRA-FLOW-MIRROR-0001, httpd lane BP / MIRROR-ENVS-CANONICAL
// -0001): the flow-mirror gate — the oracle single-function input contract.
// The locked oracle harness (tests/oracle/stage_projection_1204.cc run())
// loads httpd through BfdArchitecture (every PT_LOAD mapped, SLEIGH decode)
// and drives fd->followFlow(code:0, code:highest), so the driver's default
// linear disassemble+inject_raw_ops load is a DIFFERENT input contract
// (single_function_inject_linear) and the projection consumer correctly
// hard-blocks cross-side comparison on the load_mode identity key. Under
// the gate the driver reproduces the oracle contract instead: full-segment
// SLEIGH image + follow_flow_range(0, u64::MAX) + no analyzer transport
// (no tail-call CALL_RETURN overrides, no PLT thunk names, no inferred
// callee prototypes, dynsym-defined functions as the only symbol source —
// the registerDynamicFunctionSymbols mirror), and the projection flips its
// honest load_mode literal to single_function_bfd. On this driver the
// canonical bundle key RUGRA_MIRROR reduces to the flow component alone:
// httpd has no libc-signature ledger, no known-noreturn marking, and no
// DWARF prototype application to neutralize (the curl components with no
// counterpart here). Env unset = the exact historical inject path,
// byte-identical.
fn mirror_flow_enabled() -> bool {
    std::env::var("RUGRA_MIRROR").is_ok() || std::env::var("RUGRA_FLOW_MIRROR").is_ok()
}

// RUGRA-GLUE (RUGRA-FLOW-MIRROR-0001, httpd lane BP): the vaddr-keyed
// memory image the mirror path hands SLEIGH — the PT_LOAD segments laid
// out at their virtual addresses, NOBITS (.bss) zero-fill via the memsz
// top. httpd's four segments: 0x0 R (headers/.rela), 0x29000 RX (.plt/
// .plt.sec/.text), 0x7a000 R (.rodata), 0x999f0 RW (filesz 0x6df0 <
// memsz 0xa3d0, .bss tail), image top 0xa3cc0. Same construction the curl
// driver's worker loader uses (curl_decompile.rs worker_memory_image_bytes,
// B3-COREACTION-CONSTANTPTR-0001 b lineage).
fn worker_memory_image_bytes(elf: &goblin::elf::Elf, buffer: &[u8]) -> Vec<u8> {
    const PT_LOAD: u32 = 1;
    let mut top = 0usize;
    for ph in elf.program_headers.iter() {
        if ph.p_type == PT_LOAD {
            top = top
                .max((ph.p_vaddr as usize).saturating_add(ph.p_memsz as usize));
        }
    }
    let mut image = vec![0u8; top];
    for ph in elf.program_headers.iter() {
        if ph.p_type == PT_LOAD {
            let vaddr = ph.p_vaddr as usize;
            let file_size = ph.p_filesz as usize;
            let src = buffer
                .get(ph.p_offset as usize..(ph.p_offset as usize).saturating_add(file_size))
                .unwrap_or(&[]);
            let dst_end = vaddr.saturating_add(src.len()).min(top);
            if vaddr < dst_end {
                image[vaddr..dst_end].copy_from_slice(&src[..dst_end - vaddr]);
            }
        }
    }
    image
}

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

    // HTTPD-URAM-SYMBOLIZE-0001 (parse point): the PLT thunk import is
    // parsed once up front (it re-parses the image independently of the
    // goblin object below) so both the symbol_table seeding inside the ELF
    // block and the call-target default-name pass below share it.
    let plt_imports = rugra::debugproto::ElfPltImports::parse_elf(&buffer);

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

        // HTTPD-URAM-SYMBOLIZE-0001: PLT thunk names. httpd's imports
        // (apr_*/str*/mem*, dynamically linked against libapr/libc) are UND
        // (st_value==0) in .dynsym, so the symtab/dynsym loops above never
        // name them — the actual direct-call targets are .plt.sec thunks
        // (0x2a420..0x2b7f0). Ghidra's Java ELF/PLT analyzer creates a thunk
        // Function named after the resolved import for every one of those
        // slots, and the decompiler prints that name at each call site via
        // FlowInfo::queryCall (flow.cc:656-672) → FuncCallSpecs::setFuncdata
        // (fspec.cc:4949-4960) → PrintC::opCall's fc->getName()
        // (printc.cc:601-609). Without this seeding the target address has
        // no symbol anywhere, Funcdata::map_globals' no-symbol arm builds a
        // uRam<offset> data-global name for the callpoint varnode, and the
        // printer shows `uRam000000000002a6d0()` where the locked oracle
        // (tests/golden/ghidra_httpd_1204.c) prints `apr_app_initialize(...)`
        // (87 call sites: 82 thunk imports + 5 discovered functions).
        for (&thunk_addr, thunk_name) in plt_imports.iter() {
            symbol_table
                .entry(thunk_addr)
                .or_insert_with(|| thunk_name.clone());
        }
        eprintln!(
            "[PREPASS] ELF PLT thunk imports: {} entries",
            plt_imports.len()
        );

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

    // RUGRA-GLUE (stage emitters, httpd lane): env-gated single-function
    // projection/drill emitters with the same contract as the curl driver
    // (RUGRA_STAGE_PROJ / RUGRA_STAGE_DRILL + RUGRA_STAGE_FUNC selector +
    // RUGRA_STAGE_PROJ_OUT / RUGRA_STAGE_DRILL_OUT sinks; see
    // emit_stage_projection / emit_stage_drill at the bottom of this file).
    // Under the flow-mirror gate (RUGRA-FLOW-MIRROR-0001, lane BP) the
    // selected function loads through SLEIGH follow_flow_range instead of
    // inject_raw_ops.
    // Every env unset = the exact historical loop below, byte-identical.
    let stage_proj = std::env::var("RUGRA_STAGE_PROJ").is_ok();
    let stage_drill = std::env::var("RUGRA_STAGE_DRILL").is_ok();
    let stage_selector: Option<String> = if stage_proj || stage_drill {
        match std::env::var("RUGRA_STAGE_FUNC") {
            Ok(function) if !function.is_empty() => Some(function),
            _ => {
                eprintln!("RUGRA_STAGE_FUNC is required when RUGRA_STAGE_PROJ/RUGRA_STAGE_DRILL is set");
                std::process::exit(2);
            }
        }
    } else {
        None
    };
    // RUGRA-GLUE: RUGRA_STAGE_FUNC=<name|0xaddr> (curl driver contract);
    // the address arm only exists behind the stage envs so env-unset runs
    // keep name-only selection semantics untouched.
    let stage_target_selected = |vaddr: u64, name: &str| -> bool {
        let Some(selector) = stage_selector.as_ref() else { return false; };
        selector == name
            || selector.eq_ignore_ascii_case(&format!("0x{vaddr:x}"))
            || selector
                .strip_prefix("0x")
                .and_then(|value| u64::from_str_radix(value, 16).ok())
                .or_else(|| u64::from_str_radix(selector, 16).ok())
                == Some(vaddr)
    };
    let mut stage_seen = false;

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

    // HTTPD-URAM-SYMBOLIZE-0001: default names for analysis-discovered
    // functions. Ghidra's front-end creates a Function for every call target
    // its analysis follows that no ELF symbol covers (httpd's shared tail
    // chunks: 0x2c520/0x2c550/0x2c8e0/0x2c960/0x2ce20 — all present as
    // `FUN_0012cXXX` headers in the locked oracle), default-named
    // `FUN_` + 8-digit zero-padded hex of the analyzeHeadless image-base
    // address (the ET_DYN image loads at 0x100000, matching the curl
    // driver's ANALYZE_HEADLESS_IMAGE_BASE convention). The same
    // queryCall → setFuncdata → opCall chain as named thunks then prints
    // `FUN_0012c960(...)` at call sites. Thunk entries already carry their
    // import names, so they are excluded here.
    const ANALYZE_HEADLESS_IMAGE_BASE: u64 = 0x100000;
    for &target in &call_targets {
        if symbol_table.contains_key(&target) || plt_imports.contains(target) {
            continue;
        }
        symbol_table
            .entry(target)
            .or_insert_with(|| {
                rugra::debugproto::analyze_headless_function_symbol_name(
                    target,
                    ANALYZE_HEADLESS_IMAGE_BASE,
                )
            });
    }

    let mut total_success = 0;
    let mut total_fail = 0;

    // Known function entries for tail-call detection (TailCallAnalyzer
    // transport): ELF function symbols plus every address this corpus
    // calls (shared tail chunks Ghidra's analysis also turns into
    // functions, e.g. sub_2c960 = suck_in_APR+0x90).
    let func_entry_set: std::collections::HashSet<u64> = functions.iter().map(|f| f.0)
        .chain(call_targets.iter().copied())
        .collect();

    // RUGRA-FLOW-MIRROR-0001 (httpd lane BP M2): mirror-gate state, built
    // once — the full PT_LOAD SLEIGH image and the dynsym-defined function
    // symbol set (symtab ∪ dynsym-defined = `functions`; httpd is stripped,
    // so this is exactly the registerDynamicFunctionSymbols mirror of the
    // oracle harness). Both stay None/empty when the gate is unset; the
    // per-function clones below only exist behind the gate, same shape as
    // the stage_binary capture.
    let mirror = mirror_flow_enabled();
    let mirror_image: Option<Vec<u8>> = if mirror {
        match &obj {
            Object::Elf(elf) => Some(worker_memory_image_bytes(elf, &buffer)),
            _ => None,
        }
    } else {
        None
    };
    let mirror_fn_syms: Vec<(u64, String)> = if mirror {
        functions
            .iter()
            .map(|&(vaddr, _, _, ref name)| (vaddr, name.clone()))
            .collect()
    } else {
        Vec::new()
    };
    if mirror {
        eprintln!(
            "[PREPASS] flow mirror: image {} bytes, {} dynsym function symbols",
            mirror_image.as_ref().map(|image| image.len()).unwrap_or(0),
            mirror_fn_syms.len()
        );
    }

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
        if idx >= max_functions && stage_selector.is_none() { break; }
        if stage_selector.is_some() {
            if !stage_target_selected(vaddr, name) { continue; }
            stage_seen = true;
        } else if size < 5 || name == "_start" || name.starts_with("register_tm_clones") || name.starts_with("deregister_tm_clones") || name == "__libc_csu_init" || name == "__libc_csu_fini" || name == "frame_dummy" {
            continue;
        }

        eprintln!("[DECOMP] {}/{} {}", idx+1, max_functions, name);

        let max_size = std::cmp::min(size, 8192);
        let end_off = std::cmp::min(file_offset as usize + max_size, buffer.len());
        if file_offset as usize >= buffer.len() { continue; }
        let code_bytes = &buffer[file_offset as usize..end_off];

        // RUGRA-FLOW-MIRROR-0001: per-function mirror captures (only live
        // behind the gate). Under the gate the iced prelude is skipped —
        // SLEIGH + follow_flow_range inside the thread replace it.
        let mirror_fn = mirror;
        let mirror_img = mirror_image.clone();
        let mirror_syms = mirror_fn_syms.clone();

        let mut raw_ops = Vec::new();
        if !mirror_fn {
            let mut disasm = X86_64Disassembler::new();
            let instructions = match disasm.disassemble(code_bytes, Address::new(vaddr)) {
                Ok(insts) => insts,
                Err(_) => { total_fail += 1; continue; }
            };

            let mut lifter = X86Lifter::new();
            for inst in &instructions {
                let mut ops = lifter.lift(inst);
                for op in &mut ops {
                    op.set_seq_num(rugra::address::SeqNum::new(inst.address, 0));
                }
                raw_ops.extend(ops);
            }
        }

        let sym_table = symbol_table.clone();
        let str_table = string_table.clone();
        let func_name = name.clone();
        let func_size = size;
        let proto_db = prototype_db.clone();
        let entry_set = func_entry_set.clone();
        let plt_ranges = plt_entry_ranges.clone();
        // The stage emitters hash the full ELF image for the META
        // fingerprint (curl carries request.binary_image the same way); the
        // clone exists only behind the stage envs.
        let stage_binary = if stage_proj || stage_drill { Some(buffer.clone()) } else { None };
        let stage_proj_fn = stage_proj;
        let stage_drill_fn = stage_drill;

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
            // RUGRA-FLOW-MIRROR-0001: under the gate the Architecture also
            // carries the PT_LOAD loader (the oracle BfdArchitecture maps
            // every PT_LOAD — the loader is part of the input contract).
            // Jumptable recovery reads the table bytes through
            // fd.arch.loader (jumptable.rs sanity_check / find_normalized
            // readonly rescue / emulate get_load_image_value — the
            // MemoryImage channel of jumptable.cc:1225-1226/1588-1598); a
            // bare loader-less Architecture makes recovery DataUnavail and
            // main's relative-offset switch at 0x2ba94 (table @0x88530)
            // fail-thunks into CALLIND + artificial RETURN (the first
            // recorded httpd cross-side divergence, see
            // /dev/shm/rugra-tests/sb-httpdff/cross_side_report.txt).
            fd.set_arch({
                let mut arch = rugra::arch::Architecture::new();
                if mirror_fn {
                    let image = mirror_img
                        .as_deref()
                        .expect("mirror image captured behind the gate");
                    arch.loader = Some(std::sync::Arc::new(
                        rugra::loadimage::RawLoadImage::from_bytes("httpd", 0, image.to_vec()),
                    ));
                }
                std::sync::Arc::new(arch)
            });
            if !mirror_fn {
                fd.external_prototypes = proto_db;
            }
            // RUGRA-FLOW-MIRROR-0001: under the gate the symbol set is the
            // dynsym-defined functions only (registerDynamicFunctionSymbols
            // mirror — the oracle's bare BFD harness registers no PLT thunk
            // names and no analysis-discovered FUN_ defaults); the default
            // path keeps the full HTTPD-URAM-SYMBOLIZE-0001 table.
            if mirror_fn {
                for &(sym_addr, ref sym_name) in &mirror_syms {
                    fd.add_symbol(sym_addr, sym_name.clone());
                }
            } else {
                for (&addr, n) in &sym_table { fd.add_symbol(addr, n.clone()); }
            }
            for (&addr, s) in &str_table { fd.add_string(addr, s.clone()); }

            // RUGRA-FLOW-MIRROR-0001: the mirror load — the oracle contract
            // fd->followFlow(Address(code,0), Address(code,highest))
            // (funcdata_op.cc:756; stage_projection_1204.cc:419). SLEIGH
            // decodes through the full PT_LOAD image at base 0, so the
            // unbounded range can lift .plt/.plt.sec thunks below .text;
            // tail jumps into thunks truncate through the jumptable
            // fail-thunk path (jumptable.cc:2304-2320 -> flow.cc:727/735
            // CALLIND + artificial halt), the same contract the curl mirror
            // established. The analyzer transport is NOT applied here: no
            // tail-call CALL_RETURN overrides (below), no inferred callee
            // prototypes (external_prototypes stays empty — bare-BFD
            // parity, the RUGRA_BARE_LOAD principle), and an empty flow
            // callee table. .rodata strings stay seeded: the oracle
            // StringManager reads the same bytes through the loader.
            // Known recorded delta: the Funcdata size keeps the ELF
            // st_size (3062 for main) where the oracle harness's 2-arg
            // Scope::addFunction leaves it unset; size is outside the
            // projection grammar, and any behavioral effect surfaces as a
            // consumer-side divergence record.
            if mirror_fn {
                let image = match mirror_img.as_deref() {
                    Some(image) => image,
                    None => {
                        eprintln!("[THREAD] {} flow mirror failed: no PT_LOAD image", func_name);
                        return None;
                    }
                };
                let mut sleigh = rugra::disasm::sleigh_lift::SleighLifter::new();
                if let Err(error) = sleigh.configure_x86_64(image, 0) {
                    eprintln!("[THREAD] {} flow mirror SLEIGH setup failed: {:?}", func_name, error);
                    return None;
                }
                eprintln!("[THREAD] {} flow mirror: follow_flow_range(0, u64::MAX)", func_name);
                let callee_protos = std::collections::BTreeMap::new();
                if let Err(error) = rugra::flow::follow_flow_range(
                    &mut fd,
                    &mut sleigh,
                    0,
                    u64::MAX,
                    &callee_protos,
                ) {
                    eprintln!("[THREAD] {} flow mirror failed: {}", func_name, error);
                    return None;
                }
                eprintln!("[THREAD] {} flow mirror done ops={} blocks={}",
                    func_name, fd.obank.optree.len(), fd.bblocks.get_size());
            } else {

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
            }

            let fd_arc = std::sync::Arc::new(std::sync::RwLock::new(fd));
            fd_arc.write().unwrap().set_self_ref(std::sync::Arc::downgrade(&fd_arc));

            let mut db = ActionDatabase::new();
            db.set_default_actions();
            {
                let mut fd_write = fd_arc.write().unwrap();
                if stage_proj_fn || stage_drill_fn {
                    // Stage emitters fully replace the plain perform_action
                    // run for the selected function: the projection/drill
                    // stepping itself drives the same unmodified Action tree
                    // to completion (BREAK_START frontier pauses only), and
                    // the C body still prints afterwards, exactly like the
                    // curl driver's emitter path.
                    eprintln!(
                        "[THREAD] {} stage emitters start (proj={} drill={})",
                        func_name, stage_proj_fn, stage_drill_fn
                    );
                    let stage_image = stage_binary
                        .as_deref()
                        .expect("stage image captured behind stage envs");
                    if stage_proj_fn {
                        if let Err(err) = emit_stage_projection(
                            &mut fd_write,
                            &mut db,
                            stage_image,
                            &func_name,
                            vaddr,
                        ) {
                            eprintln!("[STAGE] projection failed: {}", err);
                            std::process::exit(1);
                        }
                    }
                    if stage_drill_fn {
                        if let Err(err) = emit_stage_drill(
                            &mut fd_write,
                            &mut db,
                            stage_image,
                            &func_name,
                            vaddr,
                        ) {
                            eprintln!("[STAGE] drill failed: {}", err);
                            std::process::exit(1);
                        }
                    }
                    eprintln!("[THREAD] {} stage emitters done", func_name);
                } else {
                    eprintln!("[THREAD] {} actions start", func_name);
                    let result = db.perform_action("decompile", &mut fd_write);
                    eprintln!("[THREAD] {} actions done ({})", func_name, if result.is_ok() { "ok" } else { "err" });
                }
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

        // Wait with timeout (like curl_decompile) to prevent single-function
        // hangs; stage-emitter runs wait indefinitely (frontier stepping is
        // many times slower than a plain perform).
        let (tx, rx) = std::sync::mpsc::channel();
        let join_handle = handle;
        std::thread::spawn(move || {
            let result = join_handle.join();
            let _ = tx.send(result);
        });
        let received: Result<Result<Option<String>, Box<dyn std::any::Any + Send>>, ()> =
            if stage_selector.is_some() {
                rx.recv().map_err(|_| ())
            } else {
                match rx.recv_timeout(std::time::Duration::from_secs(15)) {
                    Ok(inner) => Ok(inner),
                    Err(_) => Err(()),
                }
            };
        match received {
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

    if stage_selector.is_some() && !stage_seen {
        eprintln!(
            "RUGRA_STAGE_FUNC={:?} matched no function in the ELF symbol tables",
            stage_selector
        );
        std::process::exit(1);
    }

    println!("\n=== Summary: {} functions decompiled, {} skipped/failed ===",
             total_success, total_fail);

    Ok(())
}

// ===========================================================================
// RUGRA-GLUE (httpd stage emitters, Lane BF): env-gated single-function
// stage projection (spec v1.2.1 grammar, consumer tools/stage_bisect.py)
// and OPACTION_DEBUG-equivalent per-application drill (consumer
// tools/drill_diff.py). Ported from the curl driver's emitter block
// (wt/sb-rust curl_decompile.rs, commits 17f1c34..eea214a) with the
// httpd-specific META honesty changes:
//   - load_mode: env-dependent honest literal. Default
//     (single_function_inject_linear): this driver loads the target by
//     linear disassembly of the symbol's bytes through inject_raw_ops
//     (+ tail-call CALL_RETURN localoverrides), NOT followFlow — a
//     different input contract from the curl driver's bounded follow-flow
//     range (single_function_flow) and from the oracle/mirror contract,
//     and the consumer's load_mode identity key correctly hard-blocks
//     cross-side comparison for it while same-driver self-comparison
//     stays meaningful. Under the flow-mirror gate (RUGRA_MIRROR=1 /
//     RUGRA_FLOW_MIRROR=1, RUGRA-FLOW-MIRROR-0001 httpd lane BP) the
//     driver reproduces the oracle contract — full PT_LOAD SLEIGH image
//     + follow_flow_range(0, u64::MAX), no analyzer transport, dynsym
//     function symbols only (the registerDynamicFunctionSymbols mirror)
//     — and the literal flips to single_function_bfd, unblocking
//     cross-side comparison against the locked oracle projection.
//   - callspec_link producer annotation = inject-path: the httpd driver
//     has no RUGRA_DISABLE_CALLSPEC_LINK switch; its callspec state rides
//     external_prototypes + the inject-path qlst registration
//     (CALLSPEC-DRIVER-0002).
// Env-unset behavior of the driver above is byte-identical (verified by
// cmp against the pre-change build on the full default corpus).
// ===========================================================================
fn stage_sha256(bytes: &[u8]) -> Result<String, String> {
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("unable to start sha256sum: {error}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "sha256sum stdin was unavailable".to_string())?
        .write_all(bytes)
        .map_err(|error| format!("unable to hash binary image: {error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("unable to read binary hash: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "sha256sum failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| format!("sha256sum output was not UTF-8: {error}"))?
        .split_whitespace()
        .next()
        .map(str::to_string)
        .ok_or_else(|| "sha256sum returned no digest".to_string())
}

// RUGRA-GLUE: the producer identity records the source tree observed by the
// driver; the action pipeline never reads this value.
fn stage_producer() -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|commit| format!("rugra-tree-{}", commit.trim()))
        .unwrap_or_else(|| "rugra-tree-unknown".to_string())
}

// RUGRA-GLUE (stage projection v1.2, punch list P5): renders a spaceid
// constant slot as `s:<spacename>`. The oracle harness identifies these by
// exact-match against its registered AddrSpace object addresses
// (stage_projection_1204.cc:309-313 building g_spaceIdNames; the pointer
// encoding is `(uintb)(uintp)spc`, sleigh.cc:236/269). Rugra encodes the
// SpaceId enum value instead, and small integers are genuine constants on
// both sides (`c:0:8`/`c:1:8`/`c:8:8` occur as real constants in both
// projections), so the value alone cannot carry the discrimination: the
// structural mirror is the slot. Rugra's only spaceid-encoding slots are
// LOAD/STORE input 0 (funcdata.rs inject_raw_ops lift path,
// double_precis.rs make_space_varnode, funcdata.rs op_stack_store/load),
// which is exactly the set Varnode::getSpaceFromConst decodes
// (constseq.cc:911, coreaction.cc:976). size==sizeof(AddrSpace*)==8 mirrors
// the harness width gate; ids outside the registered-space set fall back
// to the plain `c:` rendering like the harness's table miss.
fn stage_spaceid_name(offset: u64) -> Option<&'static str> {
    if offset > rugra::space::SPACEID_IOP as u64 {
        return None;
    }
    match rugra::space::AddressSpace::from_id(offset as rugra::space::SpaceId) {
        // Registered-space mirror of the harness table: ids beyond the
        // architecture's space list never join g_spaceIdNames. from_id
        // cannot yield Other(id>SPACEID_IOP) under the bound above, but the
        // guard keeps the invariant explicit.
        rugra::space::AddressSpace::Other(id) if id != rugra::space::SPACEID_OTHER => None,
        space => Some(space.name()),
    }
}

// RUGRA-GLUE: one descriptor formatter is the sole owner of the v1.2
// varnode normalization contract (STAGE_BISECT_SPEC_1204.md §v1.2). Unique
// offsets intentionally remain raw. Pointer-valued varnodes render through
// stable identities, never raw pointers: spaceid constant slots as
// `s:<name>` (stage_spaceid_name), fspec annotations as `f:<host op
// SeqNum>` — the call-site identity, one host CALL-class op per
// FuncCallSpecs and SeqNums are globally unique — and iop annotations as
// `o:<referenced op SeqNum>` resolved against this @SNAP's live-op table;
// a reference whose target op left the tree renders `o:-` (both sides
// rebuild the table per snapshot, harness writeSnapshot L193-200).
fn stage_vn(
    vn: &std::sync::Arc<std::sync::RwLock<rugra::varnode::Varnode>>,
    host_addr: u64,
    host_time: u32,
    spaceid_slot: bool,
    live_ops: &std::collections::HashMap<usize, (u64, u32)>,
) -> String {
    let vn = vn.read().unwrap();
    let size = vn.get_size();
    let offset = vn.get_offset();
    if vn.is_constant() {
        if spaceid_slot && size == 8 {
            if let Some(name) = stage_spaceid_name(offset) {
                return format!("s:{name}");
            }
        }
        return format!("c:{offset:x}:{size}");
    }
    if vn.get_space() == rugra::space::AddressSpace::Unique {
        return format!("u:{offset:x}:{size}");
    }
    if vn.get_space() == rugra::space::AddressSpace::Iop {
        // Rugra shares the Iop enum space for both annotation kinds
        // (TYPEOP-FSPEC-SPACE-0001); Funcdata::get_op_from_const
        // discriminates fspec vs iop by the typed callspec binding, expired
        // or not (funcdata.rs "v.call_spec.is_some()"), and so does the
        // emitter. The fspec arm renders the host op's own SeqNum (the
        // harness writes slotOp's SeqNum); the iop arm decodes the offset
        // through the live-op table (new_varnode_iop encodes Arc::as_ptr,
        // the same key pass 1 builds).
        if vn.call_spec.is_some() {
            return format!("f:{host_addr:x}:{host_time:x}");
        }
        return match live_ops.get(&(offset as usize)) {
            Some((addr, time)) => format!("o:{addr:x}:{time:x}"),
            None => "o:-".to_string(),
        };
    }
    format!("n:{}:{offset:x}:{size}", vn.get_space().name())
}

// RUGRA-GLUE (stage projection v1.2.1, punch list P4): the op-line opcode
// domain is get_opname() verbatim — Ghidra's generated opcode_name[] table
// (opcodes.cc:29-48, 74 entries, upper-case, no CPUI_ prefix). The table is
// the emitted domain even where it drifted from the enum identifiers:
// slots 60/61/65/66 read BUILD/DELAY_SLOT/LABEL/CROSSBUILD for
// MULTIEQUAL/INDIRECT/PTRADD/PTRSUB (oracle-verbatim quirk; get_opname
// indexes this table directly, so it must NOT be "corrected" to the enum
// names). Transcription checked 74/74 against the consumer's
// V1_OPCODE_ENUM_NAMES (tools/stage_bisect.py, extracted from the locked
// oracle e40ed130 opcodes.cc by lane R3).
const STAGE_OPCODE_NAME: [&str; 74] = [
    "BLANK", "COPY", "LOAD", "STORE",
    "BRANCH", "CBRANCH", "BRANCHIND", "CALL",
    "CALLIND", "CALLOTHER", "RETURN", "INT_EQUAL",
    "INT_NOTEQUAL", "INT_SLESS", "INT_SLESSEQUAL", "INT_LESS",
    "INT_LESSEQUAL", "INT_ZEXT", "INT_SEXT", "INT_ADD",
    "INT_SUB", "INT_CARRY", "INT_SCARRY", "INT_SBORROW",
    "INT_2COMP", "INT_NEGATE", "INT_XOR", "INT_AND",
    "INT_OR", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT",
    "INT_MULT", "INT_DIV", "INT_SDIV", "INT_REM",
    "INT_SREM", "BOOL_NEGATE", "BOOL_XOR", "BOOL_AND",
    "BOOL_OR", "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS",
    "FLOAT_LESSEQUAL", "UNUSED1", "FLOAT_NAN", "FLOAT_ADD",
    "FLOAT_DIV", "FLOAT_MULT", "FLOAT_SUB", "FLOAT_NEG",
    "FLOAT_ABS", "FLOAT_SQRT", "INT2FLOAT", "FLOAT2FLOAT",
    "TRUNC", "CEIL", "FLOOR", "ROUND",
    "BUILD", "DELAY_SLOT", "PIECE", "SUBPIECE", "CAST",
    "LABEL", "CROSSBUILD", "SEGMENTOP", "CPOOLREF", "NEW",
    "INSERT", "EXTRACT", "POPCOUNT", "LZCOUNT",
];

// Rugra OpCode::name() spellings that deliberately differ from the locked
// table above — the exact set the full-table parity check pins:
// - 60/61/65/66: the generated-table quirk slots (MULTIEQUAL/INDIRECT/
//   PTRADD/PTRSUB render BUILD/DELAY_SLOT/LABEL/CROSSBUILD);
// - 54-59: Rugra's enum variants carry the FLOAT_ prefix that the table
//   entries INT2FLOAT/FLOAT2FLOAT/TRUNC/CEIL/FLOOR/ROUND omit.
const STAGE_OPCODE_TABLE_DIVERGENCE: [(&str, &str); 10] = [
    ("FLOAT_INT2FLOAT", "INT2FLOAT"),
    ("FLOAT_FLOAT2FLOAT", "FLOAT2FLOAT"),
    ("FLOAT_TRUNC", "TRUNC"),
    ("FLOAT_CEIL", "CEIL"),
    ("FLOAT_FLOOR", "FLOOR"),
    ("FLOAT_ROUND", "ROUND"),
    ("MULTIEQUAL", "BUILD"),
    ("INDIRECT", "DELAY_SLOT"),
    ("PTRADD", "LABEL"),
    ("PTRSUB", "CROSSBUILD"),
];

// RUGRA-GLUE: stage-projection op-name lookup — table spelling by numeric
// slot, mirroring get_opname(opcodes.cc:60-64). Real ops are always inside
// the table; an out-of-table value is an emitter bug worth a panic, not a
// silent wrong name.
fn stage_opname(code: rugra::opcodes::OpCode) -> &'static str {
    let index = code as i32 as usize;
    STAGE_OPCODE_NAME
        .get(index)
        .copied()
        .unwrap_or_else(|| panic!("opcode slot {index} outside the locked 74-name table"))
}

// v1.2.1 requires the parity check over the FULL 74-name table, not just
// the opcode subset seen in one corpus: every Rugra variant must match its
// locked-table slot, and every difference must be one of the pinned
// STAGE_OPCODE_TABLE_DIVERGENCE entries. Run once per projection.
fn stage_opcode_parity() -> Result<(), String> {
    use rugra::opcodes::OpCode;
    let mut divergences: Vec<(&str, &str)> = Vec::new();
    for index in 1..STAGE_OPCODE_NAME.len() {
        // Slot 0 (BLANK) has no Rust variant; CPUI_UNUSED1 (45) is
        // Ghidra-only — their table entries stay pinned by transcription.
        if let Some(code) = OpCode::from_i32(index as i32) {
            if code.name() != STAGE_OPCODE_NAME[index] {
                divergences.push((code.name(), STAGE_OPCODE_NAME[index]));
            }
        }
    }
    let mut expected = STAGE_OPCODE_TABLE_DIVERGENCE.to_vec();
    expected.sort_unstable();
    divergences.sort_unstable();
    if divergences != expected {
        return Err(format!(
            "opcode table parity break: found {divergences:?}, expected exactly {expected:?}"
        ));
    }
    Ok(())
}

// RUGRA-GLUE: emits the complete optree in PcodeOpBank::optree order, which
// is the v1.1 beginAll/optree order shared with the oracle fixture. Two
// passes per snapshot mirror the harness writeSnapshot
// (stage_projection_1204.cc:193-210): pass 1 builds the live-op identity
// table over every op still in the tree (dead-but-not-destroyed included,
// the beginOpAll set) keyed by the Arc::as_ptr encoding new_varnode_iop
// writes into iop varnodes; pass 2 emits the op lines.
fn stage_snapshot(
    output: &mut impl Write,
    fd: &Funcdata,
    seq: u64,
) -> Result<(), String> {
    let mut live_ops: HashMap<usize, (u64, u32)> =
        HashMap::with_capacity(fd.obank.optree.len());
    for op_ref in &fd.obank.optree {
        let op = op_ref.0.read().unwrap();
        live_ops.insert(
            std::sync::Arc::as_ptr(&op_ref.0) as usize,
            (op.get_addr().as_u64(), op.get_time()),
        );
    }
    writeln!(output, "@SNAP {seq} ops {}", fd.obank.optree.len())
        .map_err(|error| format!("unable to write stage snapshot header: {error}"))?;
    for op_ref in &fd.obank.optree {
        let op = op_ref.0.read().unwrap();
        let addr = op.get_addr().as_u64();
        let time = op.get_time();
        // d= follows op.cc:380-381 / harness writeOp: dead OR unattached
        // (no parent FlowBlock). The parent arm reads the Option without
        // upgrading the Weak (op.rs parent: Option<Weak<...>>).
        let dead = op.is_dead() || op.parent.is_none();
        // Only LOAD/STORE input 0 carries a spaceid constant on the Rugra
        // side (see stage_spaceid_name); every other slot stays value-only.
        let spaceid_slot = matches!(
            op.get_opcode(),
            rugra::opcodes::OpCode::CPUI_LOAD | rugra::opcodes::OpCode::CPUI_STORE
        );
        let out = op
            .get_out()
            .map(|vn| stage_vn(vn, addr, time, false, &live_ops))
            .unwrap_or_else(|| "-".to_string());
        let inputs = if op.inrefs.is_empty() {
            "-".to_string()
        } else {
            op.inrefs
                .iter()
                .enumerate()
                .map(|(slot, vn)| {
                    stage_vn(vn, addr, time, spaceid_slot && slot == 0, &live_ops)
                })
                .collect::<Vec<_>>()
                .join(",")
        };
        writeln!(
            output,
            "{addr:x}:{time:x} {} d={} out={} in={}",
            stage_opname(op.get_opcode()),
            u8::from(dead),
            out,
            inputs,
        )
        .map_err(|error| format!("unable to write stage snapshot op: {error}"))?;
    }
    Ok(())
}

// RUGRA-GLUE: static stage-tree description for the projection emitter. The
// tree is walked once from the live root; paths follow Ghidra's colon
// convention rooted at the registered root Action name (the derived
// "decompile" root keeps the cloned name "universal", matching the oracle's
// setBreakPoint addressing "universal:fullloop:mainloop").
struct StageNode {
    path: String,
    parent: Option<usize>,
    index_in_parent: usize,
    children: Vec<usize>,
}

// RUGRA-GLUE: one open v1.1 application frame; @BEGIN pushed it, and the
// matching @END/@SNAP pair must reuse its seq (consumer stacks frames LIFO).
struct StageFrame {
    node: usize,
    seq: u64,
    tests_before: u32,
    apply_before: u32,
}

// RUGRA-GLUE: pre-order walk of the Action tree; ActionPool leaves are event
// boundaries but their Rules are not (v1.1 has no rule-level events).
fn stage_walk(
    action: &dyn Action,
    parent: Option<usize>,
    index_in_parent: usize,
    path: &str,
    nodes: &mut Vec<StageNode>,
) -> usize {
    let index = nodes.len();
    nodes.push(StageNode {
        path: path.to_string(),
        parent,
        index_in_parent,
        children: Vec::new(),
    });
    if let Some(group) = action.as_action_group() {
        let actions = group.child_actions();
        for (child_index, child) in actions.iter().enumerate() {
            let child_path = format!("{path}:{}", child.get_name());
            let child_id = stage_walk(child.as_ref(), Some(index), child_index, &child_path, nodes);
            nodes[index].children.push(child_id);
        }
    }
    index
}

// RUGRA-GLUE: descends the live tree to a node's Action (read-only view).
fn stage_action_of<'a>(root: &'a dyn Action, nodes: &[StageNode], node: usize) -> &'a dyn Action {
    let mut chain = Vec::new();
    let mut current = node;
    while let Some(parent) = nodes[current].parent {
        chain.push(nodes[current].index_in_parent);
        current = parent;
    }
    chain.reverse();
    let mut action = root;
    for step in chain {
        action = action
            .as_action_group()
            .and_then(|group| group.child_actions().get(step))
            .map(|child| child.as_ref() as &dyn Action)
            .unwrap_or_else(|| panic!("stage tree walk diverged at {}", nodes[node].path));
    }
    action
}

// RUGRA-GLUE: read-only access to a node's externalized ActionState; never
// touches take_count_delta (v1.1 reads ActionState.count directly). A node's
// executor state lives in its parent's child_states slot; the root uses the
// externally held state.
fn stage_state_of<'a>(
    root: &'a dyn Action,
    root_state: &'a ActionState,
    nodes: &[StageNode],
    node: usize,
) -> &'a ActionState {
    match nodes[node].parent {
        None => root_state,
        Some(parent) => stage_action_of(root, nodes, parent)
            .as_action_group()
            .and_then(|group| group.child_state(nodes[node].index_in_parent))
            .unwrap_or_else(|| panic!("stage child state missing at {}", nodes[node].path)),
    }
}

// RUGRA-GLUE: sets BREAK_START on one node identified by tree index. This
// bypasses set_break_point's name resolution because the oracle tree has
// duplicate leaf names (e.g. two "unreachable" siblings inside mainloop,
// coreaction.cc:5490/5673) whose colon-path lookup is ambiguous; indexing the
// same child_states slot reaches the identical ActionState.breakpoint bit the
// name-based path would set, with no ambiguity.
fn stage_set_start_break(
    root: &mut dyn Action,
    root_state: &mut ActionState,
    nodes: &[StageNode],
    node: usize,
) {
    let Some(parent) = nodes[node].parent else {
        root_state.set_break(break_flags::BREAK_START);
        return;
    };
    let mut chain = Vec::new();
    let mut current = node;
    while let Some(ancestor) = nodes[current].parent {
        chain.push(nodes[current].index_in_parent);
        current = ancestor;
    }
    chain.reverse();
    let mut group = root
        .as_action_group_mut()
        .expect("stage root is a restart group");
    while chain.len() > 1 {
        let step = chain.remove(0);
        group = group.child_actions_mut()[step]
            .as_action_group_mut()
            .expect("intermediate stage node is a group");
    }
    let leaf = chain.remove(0);
    group
        .child_state_mut(leaf)
        .unwrap_or_else(|| panic!("stage child state missing at {}", nodes[node].path))
        .set_break(break_flags::BREAK_START);
}

// RUGRA-GLUE: first child of `group_node` at or after `from` whose status is
// not STATUS_END — v1.1 enumeration rule (ii): completed onceperfunc nodes
// are skipped without events or breakpoints.
fn stage_next_runnable(
    root: &dyn Action,
    nodes: &[StageNode],
    group_node: usize,
    from: usize,
) -> Option<usize> {
    let group = stage_action_of(root, nodes, group_node)
        .as_action_group()
        .expect("stage candidate parent is a group");
    for child in nodes[group_node].children.iter().skip(from) {
        let state = group
            .child_state(nodes[*child].index_in_parent)
            .expect("stage child state present");
        if state.status != rugra::action::status_flags::STATUS_END {
            return Some(*child);
        }
    }
    None
}

// RUGRA-GLUE: proper-ancestor test used to decide which open frames are still
// mid-apply at the next pause (v1.1 rule (iii): group @END is emitted only
// after the group resumes to completion, so a frame whose subtree contains
// the next paused node stays open).
fn stage_is_proper_ancestor(nodes: &[StageNode], ancestor: usize, node: usize) -> bool {
    let mut current = nodes[node].parent;
    while let Some(parent) = current {
        if parent == ancestor {
            return true;
        }
        current = nodes[parent].parent;
    }
    false
}

// RUGRA-GLUE: ordered candidate set for the next STATUS_START entry after the
// paused node applies — v1.1 enumeration rules (i)/(ii)/(iii). Exactly one
// node applies between two pauses; the first candidate whose start-break
// fires is the true next application. Candidates cover: the paused group's
// first runnable child, the next runnable sibling up the chain, repeatapply
// re-traversal firsts (whose count-based decision cannot be predicted before
// the current application returns), and the root restart re-entry.
fn stage_frontier(
    root: &dyn Action,
    root_state: &ActionState,
    nodes: &[StageNode],
    node: usize,
) -> Vec<usize> {
    let mut candidates: Vec<usize> = Vec::new();
    let mut push = |value: usize, list: &mut Vec<usize>| {
        if !list.contains(&value) {
            list.push(value);
        }
    };
    if nodes[node].parent.is_none()
        || stage_action_of(root, nodes, node).as_action_group().is_some()
    {
        if let Some(child) = stage_next_runnable(root, nodes, node, 0) {
            push(child, &mut candidates);
        }
    }
    let mut current = node;
    while let Some(parent) = nodes[current].parent {
        let index_in_parent = nodes[current].index_in_parent;
        if let Some(sibling) = stage_next_runnable(root, nodes, parent, index_in_parent + 1) {
            push(sibling, &mut candidates);
            break;
        }
        let parent_state = stage_state_of(root, root_state, nodes, parent);
        if parent_state.flags & rugra::action::action_flags::RULE_REPEATAPPLY != 0 {
            if let Some(child) = stage_next_runnable(root, nodes, parent, 0) {
                push(child, &mut candidates);
            }
        }
        if parent == 0 {
            // Root restart re-entry: ActionRestartGroup re-drives its children
            // from the top after curstart increments (Rugra: PIPE-RESTART-0001
            // keeps this unreachable today; the candidate is defensive).
            if let Some(child) = stage_next_runnable(root, nodes, parent, 0) {
                push(child, &mut candidates);
            }
        }
        current = parent;
    }
    candidates
}

// RUGRA-GLUE (v2 drill emitter plan, Lane AA): the OPACTION_DEBUG-equivalent
// per-application modified-op drill for stage-bisect v2, mirroring the
// locked-oracle harness tests/oracle/stage_drill_1204.cc (Lane Q; oracle
// baseline /dev/shm/rugra-tests/sb-drill/next_url.oracle.drill, 1293 blocks,
// 1019 records, sha b227ae94...). Design: DRILL_DESIGN.md §3/§4.
//
// Reused from the v1.1 emitter above (f07229c/05c8314):
//   - stage_walk/stage_action_of/stage_state_of/stage_set_start_break/
//     stage_frontier BREAK_START frontier stepping over the live Action tree
//     (one application between two pauses, index-addressed to dodge duplicate
//     leaf names);
//   - the RUGRA_STAGE_FUNC single-function selection plumbing.
//
// Added for v2 (all behind RUGRA_STAGE_DRILL=1; env-unset behavior stays
// byte-identical, verified in M3 against the pre-change build):
//   1. SeqNum raw formatter: "<pc-raw>:<uniq-hex>" matching Ghidra
//      address.cc SeqNum operator<< (pc printRaw leaves the stream in hex,
//      so uniq prints hex too; oracle lines like `0x00004ff4:2cd`).
//   2. Per-op mutation hooks (read-only observation, zero pipeline change
//      when the env is unset): first-touch before-caching with the
//      MODIFIED addl-flag for dedup, mirroring Funcdata::debugModCheck
//      (funcdata.cc:1010-1022) at the funcdata.rs mutation entries, plus a
//      per-rule activate/flush pair around ActionPool rule applications
//      mirroring action.cc:839-845.
//   3. Drill record format (identical grammar to the oracle drill):
//      `@BEGIN <boundary-seq> <full-path>` / native DEBUG text verbatim
//      (`DEBUG <n>: <leaf>`, before line, `   ` + after line; dead ops keep
//      `<seqnum>: **`) / `@END`. <n> counts only applications that modified
//      a traced op (opactdbg_count equivalent), boundary-seq is 1-based per
//      emitted block.
// Milestones: M0 plan (this comment) -> M1 hooks+emitter -> M2 next_url
// full output + diff-vs-oracle sampling (differences are signal, recorded
// per-item, never forced to match) -> M3 minimal src accessors + env-off
// byte-identity check.

// RUGRA-GLUE: wraps the existing Action::perform state machine with only
// BREAK_START bits and read-only optree observation; no Action/Rule
// implementation changes and no snapshot is fed back into the pipeline.
// Stepping protocol (v1.1): breakpoint before each node apply; resume past
// the pause; the node that applied between two pauses gets one
// @BEGIN/@END/@SNAP triple, seq is globally consecutive from 1, and open
// group frames close LIFO when the next pause falls outside their subtree.
fn emit_stage_projection(
    fd: &mut Funcdata,
    db: &mut ActionDatabase,
    binary_image: &[u8],
    func_name: &str,
    func_vaddr: u64,
) -> Result<(), String> {
    let output_path = std::env::var("RUGRA_STAGE_PROJ_OUT")
        .map_err(|_| "RUGRA_STAGE_PROJ_OUT is required when RUGRA_STAGE_PROJ is set")?;
    // v1.2.1 full-table opcode parity gate: refuse to emit a projection
    // whose enum/table correspondence has drifted from the locked 74 names.
    stage_opcode_parity()?;
    let binary_sha256 = stage_sha256(binary_image)?;
    let mut output = std::io::BufWriter::new(
        fs::File::create(&output_path)
            .map_err(|error| format!("unable to create stage projection {output_path}: {error}"))?,
    );
    // META identity keys (v1.2.x punch list P1-P3): arch/cspec/
    // analysis_options are pinned to the oracle harness's final configured
    // values (oracle projection META, STAGE_BISECT_SPEC_1204.md identity
    // keys). The callspec-link injection difference moves out of the
    // analysis_options identity key into the producer annotation (D3).
    // The httpd driver has no RUGRA_DISABLE_CALLSPEC_LINK switch (its
    // callspec state rides external_prototypes + the inject-path qlst
    // registration, CALLSPEC-DRIVER-0002); the producer annotation records
    // that carrier instead of the curl driver's on/off toggle.
    let callspec_link = true;
    writeln!(
        output,
        "META side=rugra oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b arch=x86:LE:64:default cspec=gcc"
    )
    .map_err(|error| format!("unable to write stage metadata: {error}"))?;
    writeln!(
        output,
        "META analysis_options=default build_flags=v1-no-OPACTION_DEBUG"
    )
    .map_err(|error| format!("unable to write stage metadata: {error}"))?;
    // load_mode (D10 honest literal): under the flow-mirror gate
    // (MIRROR-ENVS-CANONICAL-0001: RUGRA_MIRROR=1 or legacy
    // RUGRA_FLOW_MIRROR=1) the driver reproduces the oracle load contract
    // — the full-segment SLEIGH image + follow_flow_range(0, u64::MAX)
    // with no analyzer transport (RUGRA-FLOW-MIRROR-0001, httpd lane BP)
    // — so the honest literal is single_function_bfd, matching the locked
    // oracle projection META. The default path still loads the target by
    // LINEAR disassembly of the symbol's bytes through inject_raw_ops
    // (plus tail-call CALL_RETURN localoverrides), NOT by followFlow — a
    // different input contract from both the curl driver's bounded
    // follow-flow range (single_function_flow) and the oracle/mirror
    // contract — and the consumer's load_mode identity-key hard block is
    // the correct behavior for it.
    let load_mode = if mirror_flow_enabled() {
        "single_function_bfd"
    } else {
        "single_function_inject_linear"
    };
    writeln!(
        output,
        "META binary_sha256={} func_entry=0x{:x} func_name={} load_mode={}",
        binary_sha256, func_vaddr, func_name, load_mode
    )
    .map_err(|error| format!("unable to write stage metadata: {error}"))?;
    // unique_base = ANALYSIS_UNIQUE_START (src/varnode.rs:30, Ghidra
    // varnode.cc unique space allocation base), printed as hex. The
    // callspec_link annotation is producer-level (D3), never an identity
    // key: it documents which driver-side injection state produced this
    // file, while analysis_options stays the oracle-final literal.
    writeln!(
        output,
        "META producer={},callspec_link={} maxrestarts=1 unique_base=10000000",
        stage_producer(),
        if callspec_link { "inject-path" } else { "off" }
    )
    .map_err(|error| format!("unable to write stage metadata: {error}"))?;

    let root = db
        .get_action_mut("decompile")
        .ok_or_else(|| "decompile action was not registered".to_string())?;
    let mut nodes: Vec<StageNode> = Vec::new();
    let root_name = root.get_name().to_string();
    stage_walk(&*root, None, 0, &root_name, &mut nodes);
    if nodes.len() < 2 {
        return Err("decompile action has no stage children".to_string());
    }
    root.reset(fd);
    let mut root_state = ActionState::new(root.get_flags());
    root.clear_break_points(&mut root_state);

    let mut seq: u64 = 0;
    let mut open: Vec<StageFrame> = Vec::new();
    let mut curstart_seen = root.fixture_curstart();

    // Initial pause: break on the root's own STATUS_START entry.
    stage_set_start_break(root, &mut root_state, &nodes, 0);
    let ret = root
        .perform(fd, &mut root_state)
        .map_err(|error| format!("initial stage breakpoint failed: {error}"))?;
    if ret >= 0 {
        return Err("root completed before the first stage breakpoint".to_string());
    }
    seq = 1;
    writeln!(output, "@BEGIN {seq} {}", nodes[0].path)
        .map_err(|error| format!("unable to write stage begin: {error}"))?;
    open.push(StageFrame {
        node: 0,
        seq,
        tests_before: root_state.count_tests,
        apply_before: root_state.count_apply,
    });

    loop {
        let current = open
            .last()
            .map(|frame| frame.node)
            .ok_or_else(|| "stage frame stack emptied mid-run".to_string())?;
        let candidates = stage_frontier(&*root, &root_state, &nodes, current);

        root.clear_break_points(&mut root_state);
        for candidate in &candidates {
            stage_set_start_break(root, &mut root_state, &nodes, *candidate);
        }
        let ret = root
            .perform(fd, &mut root_state)
            .map_err(|error| format!("stage perform failed at {}: {error}", nodes[current].path))?;

        if ret >= 0 {
            // Whole tree converged: every open frame completes, LIFO.
            while let Some(frame) = open.pop() {
                let state = stage_state_of(&*root, &root_state, &nodes, frame.node);
                writeln!(
                    output,
                    "@END {} {} result={} count={} tests={} apply={}",
                    frame.seq,
                    nodes[frame.node].path,
                    state.count,
                    state.count,
                    state.count_tests.wrapping_sub(frame.tests_before),
                    state.count_apply.wrapping_sub(frame.apply_before),
                )
                .map_err(|error| format!("unable to write stage end: {error}"))?;
                stage_snapshot(&mut output, fd, frame.seq)?;
            }
            break;
        }

        // The pause fired at exactly one candidate's STATUS_START.
        let paused = candidates
            .iter()
            .copied()
            .find(|candidate| {
                stage_state_of(&*root, &root_state, &nodes, *candidate).status
                    == rugra::action::status_flags::STATUS_BREAKSTARTHIT
            })
            .ok_or_else(|| {
                format!(
                    "stage pause without a hit candidate after {} (candidates: {})",
                    nodes[current].path,
                    candidates
                        .iter()
                        .map(|candidate| nodes[*candidate].path.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;

        // Close every open frame that is not a proper ancestor of the paused
        // node — v1.1 rule (iii): group @END fires when the group has resumed
        // to completion, which is exactly when the next application leaves
        // its subtree.
        while let Some(frame) = open.last() {
            if stage_is_proper_ancestor(&nodes, frame.node, paused) {
                break;
            }
            let frame = open.pop().expect("frame presence checked by last()");
            let state = stage_state_of(&*root, &root_state, &nodes, frame.node);
            writeln!(
                output,
                "@END {} {} result={} count={} tests={} apply={}",
                frame.seq,
                nodes[frame.node].path,
                state.count,
                state.count,
                state.count_tests.wrapping_sub(frame.tests_before),
                state.count_apply.wrapping_sub(frame.apply_before),
            )
            .map_err(|error| format!("unable to write stage end: {error}"))?;
            stage_snapshot(&mut output, fd, frame.seq)?;
        }

        let curstart_now = root.fixture_curstart();
        if curstart_now != curstart_seen {
            curstart_seen = curstart_now;
            writeln!(output, "@RESTART {curstart_now}")
                .map_err(|error| format!("unable to write restart marker: {error}"))?;
        }

        seq += 1;
        writeln!(output, "@BEGIN {seq} {}", nodes[paused].path)
            .map_err(|error| format!("unable to write stage begin: {error}"))?;
        let paused_state = stage_state_of(&*root, &root_state, &nodes, paused);
        open.push(StageFrame {
            node: paused,
            seq,
            tests_before: paused_state.count_tests,
            apply_before: paused_state.count_apply,
        });
    }
    output
        .flush()
        .map_err(|error| format!("unable to flush stage projection: {error}"))?;
    Ok(())
}

// RUGRA-GLUE (v2 drill emitter, Lane AA): per-application modified-op drill
// using the same BREAK_START frontier stepping as the v1.1 projection
// above, but emitting the oracle-drill grammar of
// tests/oracle/stage_drill_1204.cc (Lane Q):
//   @BEGIN <boundary-seq> <full-path>
//   <native-form DEBUG block: "DEBUG <n>: <leaf>", before line,
//    "   " + after line; dead ops keep "<seqnum>: **">
//   @END <boundary-seq> <full-path>
// Records come from the drillobserve hooks (funcdata.rs mutation entries,
// action.rs perform/process_op boundaries); <n> is the recorder's native
// opactdbg_count equivalent (advances only when an application modified a
// traced op); boundary-seq is 1-based per emitted block, and applications
// that modified nothing still emit an `empty=1` block (v1.1 semantics).
fn emit_stage_drill(
    fd: &mut Funcdata,
    db: &mut ActionDatabase,
    binary_image: &[u8],
    func_name: &str,
    func_vaddr: u64,
) -> Result<(), String> {
    let output_path = std::env::var("RUGRA_STAGE_DRILL_OUT")
        .map_err(|_| "RUGRA_STAGE_DRILL_OUT is required when RUGRA_STAGE_DRILL is set")?;
    let binary_sha256 = stage_sha256(binary_image)?;
    let mut output = std::io::BufWriter::new(
        fs::File::create(&output_path)
            .map_err(|error| format!("unable to create stage drill {output_path}: {error}"))?,
    );
    writeln!(
        output,
        "META side=rugra oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b build_flags=env-RUGRA_STAGE_DRILL func={} entry=0x{:x} arch=x86:LE:64:default cspec=gcc format=raw-native-printdebug record_seq=native_opactdbg_count boundary_seq=1based_perform_bracket ladder=break_start_frontier binary_sha256={} producer={}",
        func_name,
        func_vaddr,
        binary_sha256,
        stage_producer()
    )
    .map_err(|error| format!("unable to write stage drill metadata: {error}"))?;

    let root = db
        .get_action_mut("decompile")
        .ok_or_else(|| "decompile action was not registered".to_string())?;
    let mut nodes: Vec<StageNode> = Vec::new();
    let root_name = root.get_name().to_string();
    stage_walk(&*root, None, 0, &root_name, &mut nodes);
    if nodes.len() < 2 {
        return Err("decompile action has no stage children".to_string());
    }
    root.reset(fd);
    let mut root_state = ActionState::new(root.get_flags());
    root.clear_break_points(&mut root_state);
    let fd_arch = fd
        .arch
        .clone()
        .ok_or_else(|| "drill requires a bound Architecture".to_string())?;
    rugra::drillobserve::start(fd_arch);

    let mut blocks: u64 = 0;
    let mut records: u64 = 0;
    let mut perform_calls: u64 = 0;
    // Emitted blocks for one application bracket: pools attribute each
    // flushed rule block to <pool-path>:<rule-leaf>; leaf actions repeat
    // their own path; groups must never produce records (kept visible via
    // a ?group-emitted marker if the invariant is ever violated).
    fn emit_blocks(
        root: &dyn Action,
        nodes: &[StageNode],
        output: &mut std::io::BufWriter<std::fs::File>,
        current: usize,
        drained: Vec<String>,
        blocks: &mut u64,
    ) -> Result<u64, String> {
        let action = stage_action_of(root, nodes, current);
        let is_group = action.as_action_group().is_some();
        let is_pool = !is_group && action.as_action_pool().is_some();
        let mut record_count: u64 = 0;
        fn leaf_name_of(path: &str) -> &str {
            path.rsplit(':').next().unwrap_or("")
        }
        for block in &drained {
            record_count += 1;
            *blocks += 1;
            let header_leaf = block
                .split_once("DEBUG ")
                .and_then(|(_, rest)| rest.split_once(':'))
                .map(|(_, rest)| {
                    rest.trim_start()
                        .split(['\n', ' '])
                        .next()
                        .unwrap_or("")
                        .to_string()
                })
                .unwrap_or_default();
            let path = if is_group {
                format!("{}?group-emitted", nodes[current].path)
            } else if is_pool {
                format!("{}:{header_leaf}", nodes[current].path)
            } else if header_leaf == leaf_name_of(&nodes[current].path) {
                nodes[current].path.clone()
            } else {
                format!("{}:{header_leaf}?foreign", nodes[current].path)
            };
            writeln!(output, "@BEGIN {} {path}\n{block}@END {} {path}", *blocks, *blocks)
                .map_err(|error| format!("unable to write drill block: {error}"))?;
        }
        if drained.is_empty() && !is_group {
            *blocks += 1;
            writeln!(
                output,
                "@BEGIN {} {} empty=1\n@END {} {}",
                *blocks,
                nodes[current].path,
                *blocks,
                nodes[current].path
            )
            .map_err(|error| format!("unable to write drill block: {error}"))?;
        }
        Ok(record_count)
    }

    // Initial pause at the root's STATUS_START, then step application by
    // application exactly like the v1.1 projection loop.
    stage_set_start_break(root, &mut root_state, &nodes, 0);
    let ret = root
        .perform(fd, &mut root_state)
        .map_err(|error| format!("initial drill breakpoint failed: {error}"))?;
    perform_calls += 1;
    if ret >= 0 {
        return Err("root completed before the first drill breakpoint".to_string());
    }
    let mut current = 0usize;
    loop {
        let candidates = stage_frontier(&*root, &root_state, &nodes, current);
        root.clear_break_points(&mut root_state);
        for candidate in &candidates {
            stage_set_start_break(root, &mut root_state, &nodes, *candidate);
        }
        let ret = root
            .perform(fd, &mut root_state)
            .map_err(|error| format!("drill perform failed at {}: {error}", nodes[current].path))?;
        perform_calls += 1;
        let drained = rugra::drillobserve::drain();
        let recs = emit_blocks(&*root, &nodes, &mut output, current, drained, &mut blocks)?;
        records += recs;
        if ret >= 0 {
            break;
        }
        let paused = candidates
            .iter()
            .copied()
            .find(|candidate| {
                stage_state_of(&*root, &root_state, &nodes, *candidate).status
                    == rugra::action::status_flags::STATUS_BREAKSTARTHIT
            })
            .ok_or_else(|| {
                format!(
                    "drill pause without a hit candidate after {} (candidates: {})",
                    nodes[current].path,
                    candidates
                        .iter()
                        .map(|candidate| nodes[*candidate].path.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
        current = paused;
    }
    writeln!(
        output,
        "@DONE applications={blocks} records={records} opactdbg_final={} perform_calls={perform_calls} nodes={}",
        rugra::drillobserve::count(),
        nodes.len()
    )
    .map_err(|error| format!("unable to write drill done line: {error}"))?;
    output
        .flush()
        .map_err(|error| format!("unable to flush stage drill: {error}"))?;
    Ok(())
}
