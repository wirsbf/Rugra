//! X86LIFT-FLAG-PCODE-0001 IR-survival probe (w-iced): run the FULL httpd
//! pipeline (iced lift → inject_raw_ops → ActionDatabase "decompile") on the
//! httpd functions that contain adc/sbb sites, then count ALIVE flag ops
//! (INT_CARRY / INT_SCARRY / INT_SBORROW / INT_LESS writing CF, flag reads)
//! in the final op bank. This is the acceptance evidence that the iced-path
//! CARRY chain survives analysis when the printc CARRY macro is not yet
//! integrated (rc3 pending).

use rugra::action::ActionDatabase;
use rugra::disasm::{Disassembler, X86_64Disassembler, X86Lifter};
use rugra::funcdata::Funcdata;

fn main() -> anyhow::Result<()> {
    let buffer = std::fs::read("examples/httpd")?;
    let obj = goblin::Object::parse(&buffer)?;

    let mut functions: Vec<(u64, usize, u64, String)> = Vec::new();
    if let goblin::Object::Elf(elf) = &obj {
        for (syms, strtab) in [(&elf.syms, &elf.strtab), (&elf.dynsyms, &elf.dynstrtab)] {
            for sym in syms.iter() {
                if sym.st_value != 0 && sym.is_function() {
                    if let Some(name) = strtab.get_at(sym.st_name) {
                        if name.is_empty() {
                            continue;
                        }
                        let mut file_off = 0u64;
                        for header in elf.section_headers.iter() {
                            if sym.st_value >= header.sh_addr
                                && sym.st_value < header.sh_addr + header.sh_size
                            {
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
        }
    }
    functions.sort_by_key(|f| f.0);

    // Targets of interest: functions containing the census adc/sbb sites.
    // golden CARRY8 (FUN_00157760) / CARRY1 (ap_http_header_filter) raw
    // addresses (golden image base 0x100000 above the ELF vaddrs).
    let sites = match std::env::var("PROBE_SITE") {
        Ok(v) => vec![u64::from_str_radix(v.trim_start_matches("0x"), 16).expect("hex u64")],
        Err(_) => vec![0x2f5c4u64, 0x2f0e6, 0x57760, 0x5cac0],
    };
    // E2E-set functions (first 30 after the httpd_decompile skip list) that
    // contain adc/sbb or an add immediately followed by sbb/cmovcc (the
    // CARRY-chain shape of the golden CARRY1/CARRY8 cases).
    let skip = |n: &str| {
        n == "_start"
            || n.starts_with("register_tm_clones")
            || n.starts_with("deregister_tm_clones")
            || n == "__libc_csu_init"
            || n == "__libc_csu_fini"
            || n == "frame_dummy"
    };
    let mut e2e_set: Vec<&(u64, usize, u64, String)> = Vec::new();
    for f in &functions {
        if skip(&f.3) || f.1 < 5 {
            continue;
        }
        e2e_set.push(f);
        if e2e_set.len() >= 30 {
            break;
        }
    }
    let mut targets: Vec<(u64, usize, u64, String)> = Vec::new();
    for (vaddr, size, file_offset, name) in &e2e_set {
        let end_off =
            std::cmp::min(file_offset + *size as u64, buffer.len() as u64) as usize;
        let code_bytes = &buffer[*file_offset as usize..end_off];
        let mut disasm = X86_64Disassembler::new();
        let Ok(instructions) = disasm.disassemble(code_bytes, rugra::Address::new(*vaddr)) else {
            continue;
        };
        let mn: Vec<&str> = instructions.iter().map(|i| i.mnemonic.as_str()).collect();
        let has_chain = mn.windows(2).any(|w| {
            (w[0] == "add" || w[0] == "adc") && (w[1] == "sbb" || w[1].starts_with("cmov"))
        }) || mn.iter().any(|m| *m == "sbb" || *m == "adc");
        if has_chain {
            println!("chain-candidate: 0x{vaddr:x} {name}");
            targets.push((*vaddr, *size, *file_offset, name.clone()));
        }
    }
    for &site in &sites {
        if let Some(f) = functions
            .iter()
            .find(|f| site >= f.0 && site < f.0 + f.1 as u64)
        {
            if !targets.iter().any(|t| t.0 == f.0) {
                targets.push(f.clone());
            }
        } else if let goblin::Object::Elf(elf) = &obj {
            // unnamed target (no symbol): synthesize an entry from the
            // executable section containing it (bounded to next symbol).
            for header in elf.section_headers.iter() {
                if (header.sh_flags & 0x4) != 0
                    && site >= header.sh_addr
                    && site < header.sh_addr + header.sh_size
                {
                    let file_off = header.sh_offset + (site - header.sh_addr);
                    let next = functions
                        .iter()
                        .map(|f| f.0)
                        .filter(|&a| a > site)
                        .min()
                        .unwrap_or(site + 512);
                    let size = (next - site).min(2048) as usize;
                    targets.push((site, size, file_off, format!("sub_{site:x}")));
                    break;
                }
            }
        }
    }
    println!("== target functions covering adc/sbb sites ==");
    for t in &targets {
        println!("0x{:x} {} ({} bytes)", t.0, t.3, t.1);
    }

    let mut total_carry = 0;
    let mut total_scarry = 0;
    let mut total_sborrow = 0;
    let mut total_cf_less = 0;
    for (vaddr, size, file_offset, name) in &targets {
        let end_off =
            std::cmp::min(file_offset + *size as u64, buffer.len() as u64) as usize;
        let code_bytes = &buffer[*file_offset as usize..end_off];
        let mut disasm = X86_64Disassembler::new();
        let Ok(instructions) = disasm.disassemble(code_bytes, rugra::Address::new(*vaddr)) else {
            continue;
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
        // raw-lift census
        let raw_carry = raw_ops
            .iter()
            .filter(|o| {
                rugra::opcodes::OpCode::from_i32(o.get_opcode())
                    == Some(rugra::opcodes::OpCode::CPUI_INT_CARRY)
            })
            .count();

        // full pipeline (same as httpd_decompile worker)
        let mut fd = Funcdata::new(name, rugra::Address::new(*vaddr), *size as i32);
        fd.inject_raw_ops(&raw_ops);
        let fd_arc = std::sync::Arc::new(std::sync::RwLock::new(fd));
        fd_arc.write().unwrap().set_self_ref(std::sync::Arc::downgrade(&fd_arc));
        let mut db = ActionDatabase::new();
        db.set_default_actions();
        // watchdog: sample IR size while the pipeline runs (oscillation hunter)
        let watchdog_fd = fd_arc.clone();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_w = stop.clone();
        let _wd = std::thread::spawn(move || {
            let mut i = 0;
            while !stop_w.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(2000));
                if stop_w.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                i += 1;
                if let Ok(fd) = watchdog_fd.try_read() {
                    let alive = fd.obank.alivelist.len();
                    let blocks = fd.bblocks.get_size();
                    let hpass = fd.num_heritage_passes();
                    eprintln!("[WD {i}] alive_ops={alive} blocks={blocks} heritage_passes={hpass}");
                }
            }
        });
        let result = if std::env::var("PROBE_STEPS").is_ok() {
            // per-group timing mode: run each DECOMPILE member with a clock
            use std::time::Instant;
            const GROUPS: &[&str] = &[
                "base", "protorecovery", "protorecovery_a", "deindirect", "localrecovery",
                "deadcode", "typerecovery", "stackptrflow",
                "blockrecovery", "stackvars", "deadcontrolflow", "switchnorm",
                "cleanup", "splitcopy", "splitpointer", "merge", "dynamic", "casts", "analysis",
                "fixateglobals", "fixateproto", "constsequence",
                "segment", "returnsplit", "nodejoin", "doubleload", "doubleprecis",
                "unreachable", "subvar", "floatprecision",
                "conditionalexe",
            ];
            for g in GROUPS {
                let t0 = Instant::now();
                let mut fd_write = fd_arc.write().unwrap();
                let r = db.perform_action(g, &mut fd_write);
                drop(fd_write);
                eprintln!("[STEP] {g} {:?} -> {:?}", t0.elapsed(), r.is_ok());
            }
            Ok(None)
        } else {
            let mut fd_write = fd_arc.write().unwrap();
            db.perform_action("decompile", &mut fd_write)
        };
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        // final IR census: count alive flag ops
        let fd_read = fd_arc.read().unwrap();
        let mut carry = 0;
        let mut scarry = 0;
        let mut sborrow = 0;
        let mut cf_less = 0;
        let mut flag_writes = 0;
        let mut flag_reads_alive = 0;
        for op_ref in &fd_read.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            use rugra::opcodes::OpCode;
            match op.get_opcode() {
                OpCode::CPUI_INT_CARRY => carry += 1,
                OpCode::CPUI_INT_SCARRY => scarry += 1,
                OpCode::CPUI_INT_SBORROW => sborrow += 1,
                _ => {
                    // INT_LESS writing CF (sub/cmp/sbb chains)
                    if op.get_opcode() == OpCode::CPUI_INT_LESS {
                        if let Some(out) = &op.output {
                            let o = out.read().unwrap();
                            if o.space().is_register() && o.offset() == 0x200 {
                                cf_less += 1;
                            }
                        }
                    }
                }
            }
            // any op touching the flag region 0x200..0x20c
            for i in 0..op.num_input() {
                if let Some(v) = op.get_in(i) {
                    let vn = v.read().unwrap();
                    if vn.space().is_register()
                        && (0x200..0x20c).contains(&vn.offset())
                    {
                        flag_reads_alive += 1;
                    }
                }
            }
            if let Some(out) = &op.output {
                let vn = out.read().unwrap();
                if vn.space().is_register() && (0x200..0x20c).contains(&vn.offset()) {
                    flag_writes += 1;
                }
            }
        }
        println!(
            "== {name} @0x{vaddr:x} decompile={:?} raw_carry={raw_carry} final: INT_CARRY={carry} INT_SCARRY={scarry} INT_SBORROW={sborrow} CF_INT_LESS={cf_less} flag_writes={flag_writes} flag_reads={flag_reads_alive}",
            result.is_ok()
        );
        total_carry += carry;
        total_scarry += scarry;
        total_sborrow += sborrow;
        total_cf_less += cf_less;
    }
    println!(
        "TOTAL: INT_CARRY={total_carry} INT_SCARRY={total_scarry} INT_SBORROW={total_sborrow} CF_INT_LESS={total_cf_less}"
    );
    Ok(())
}
