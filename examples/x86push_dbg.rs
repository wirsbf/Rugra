//! X86LIFT-PUSH88-0001 debug probe: run the exact httpd_decompile pipeline
//! (lift -> inject_raw_ops -> ActionDatabase "decompile") on one function and
//! dump the surviving ops, to trace what the push STORE/INT_SUB ops do to
//! CALL targets downstream.

use rugra::action::ActionDatabase;
use rugra::address::Address;
use rugra::disasm::{Disassembler as _, X86Lifter, X86_64Disassembler};
use rugra::printc::PrintC;
use rugra::prettyprint::EmitNoMarkup;
use rugra::printlanguage::PrintLanguage;
use rugra::funcdata::Funcdata;

fn main() -> anyhow::Result<()> {
    let buffer = std::fs::read("examples/httpd")?;
    let obj = goblin::Object::parse(&buffer)?;
    let elf = match &obj {
        goblin::Object::Elf(e) => e,
        _ => anyhow::bail!("not elf"),
    };

    // ap_pregfree @ 0x2e230 (50 bytes)
    let target: u64 = 0x2e230;
    let mut file_off = 0usize;
    for h in elf.section_headers.iter() {
        if target >= h.sh_addr && target < h.sh_addr + h.sh_size {
            file_off = (h.sh_offset + (target - h.sh_addr)) as usize;
            break;
        }
    }
    let code = &buffer[file_off..file_off + 50];

    let mut disasm = X86_64Disassembler::new();
    let instructions = disasm.disassemble(code, Address::new(target))?;
    let mut lifter = X86Lifter::new();
    let mut raw_ops = Vec::new();
    for inst in &instructions {
        let mut ops = lifter.lift(inst);
        for op in &mut ops {
            op.set_seq_num(rugra::address::SeqNum::new(inst.address, 0));
        }
        raw_ops.extend(ops);
    }

    println!("== raw lifted ops ({}):", raw_ops.len());
    for (i, op) in raw_ops.iter().enumerate() {
        let name = rugra::opcodes::OpCode::from_i32(op.get_opcode())
            .map(|o| o.name().to_string())
            .unwrap_or_default();
        let inputs = op
            .inputs()
            .iter()
            .map(|v| format!("{}:0x{:x}:{}", v.space, v.offset, v.size))
            .collect::<Vec<_>>()
            .join(",");
        println!("  [{i}] {name} in=({inputs})");
    }

    let mut fd = Funcdata::new("ap_pregfree", Address::new(target), 50);
    // symbol for the call target + PLT tail-call target (same as example)
    fd.add_symbol(0x31070, "ap_regfree".into());
    fd.add_symbol(0x2a970, "apr_pool_cleanup_kill".into());
    fd.inject_raw_ops(&raw_ops);

    let fd_arc = std::sync::Arc::new(std::sync::RwLock::new(fd));
    fd_arc.write().unwrap().set_self_ref(std::sync::Arc::downgrade(&fd_arc));
    {
        let mut db = ActionDatabase::new();
        db.set_default_actions();
        // Prefix bisect: derive a root for each prefix of the DECOMPILE group
        // list (set_group + set_current registers the derived root) and run
        // it on a FRESH Funcdata each time, dumping CALL in(0) after.
        let groups = rugra::action::default_groups::DECOMPILE;
        for prefix_len in 1..=groups.len() {
            let mut disasm2 = X86_64Disassembler::new();
            let instructions2 = disasm2
                .disassemble(code, Address::new(target))
                .unwrap_or_default();
            let mut lifter2 = X86Lifter::new();
            let mut raw_ops2 = Vec::new();
            for inst in &instructions2 {
                let mut ops = lifter2.lift(inst);
                for op in &mut ops {
                    op.set_seq_num(rugra::address::SeqNum::new(inst.address, 0));
                }
                raw_ops2.extend(ops);
            }
            let mut fd2 = Funcdata::new("ap_pregfree", Address::new(target), 50);
            fd2.add_symbol(0x31070, "ap_regfree".into());
            fd2.add_symbol(0x2a970, "apr_pool_cleanup_kill".into());
            fd2.inject_raw_ops(&raw_ops2);
            let fd2_arc = std::sync::Arc::new(std::sync::RwLock::new(fd2));
            fd2_arc.write().unwrap().set_self_ref(std::sync::Arc::downgrade(&fd2_arc));
            {
                let mut db2 = ActionDatabase::new();
                db2.set_default_actions();
                let prefix: Vec<&'static str> = groups[..prefix_len].to_vec();
                let root_name = format!("bis{prefix_len}");
                db2.set_group(&root_name, &prefix);
                db2.set_current(&root_name);
                let mut fd2_write = fd2_arc.write().unwrap();
                let result = db2.apply_all(&mut fd2_write);
                drop(fd2_write);
                let fd2_read = fd2_arc.read().unwrap();
                let mut call_desc = Vec::new();
                let mut store_count = 0usize;
                for op_ref in fd2_read.obank.alivelist.iter() {
                    let op = op_ref.0.read().unwrap();
                    match op.opcode {
                        rugra::opcodes::OpCode::CPUI_CALL => {
                            let d = op
                                .inrefs
                                .first()
                                .map(|v| {
                                    let g = v.read().unwrap();
                                    format!(
                                        "{}:0x{:x}:{}",
                                        g.get_space(),
                                        g.get_offset(),
                                        g.get_size()
                                    )
                                })
                                .unwrap_or_else(|| "none".into());
                            call_desc.push(format!("CALL in0=({d}) nin={}", op.inrefs.len()));
                        }
                        rugra::opcodes::OpCode::CPUI_STORE => store_count += 1,
                        _ => {}
                    }
                }
                let g_last = groups[prefix_len - 1];
                println!(
                    "== prefix ..{prefix_len} (+{g_last}) ({:?}): stores={store_count} {}",
                    result.map(|_| ()),
                    call_desc.join(" | ")
                );
            }
        }
    }

    let fd_read = fd_arc.read().unwrap();
    println!("\n== surviving ops:");
    for (i, op_ref) in fd_read.obank.alivelist.iter().enumerate() {
        let op = op_ref.0.read().unwrap();
        let name = rugra::opcodes::OpCode::from_i32(op.opcode as i32)
            .map(|o| o.name().to_string())
            .unwrap_or_default();
        let inputs = op
            .inrefs
            .iter()
            .map(|v| {
                let g = v.read().unwrap();
                format!("{}:0x{:x}:{}", g.get_space(), g.get_offset(), g.get_size())
            })
            .collect::<Vec<_>>()
            .join(",");
        let out = match &op.output {
            Some(o) => {
                let g = o.read().unwrap();
                format!("{}:0x{:x}:{}", g.get_space(), g.get_offset(), g.get_size())
            }
            None => "-".to_string(),
        };
        println!("  [{i}] {name} out={out} in=({inputs})");
    }

    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    printer.doc_function(&fd_read);
    let output = printer.take_emit();
    let text = output.into_any().downcast::<EmitNoMarkup>().unwrap();
    println!("\n== printed:\n{}", text.get_output());
    Ok(())
}
