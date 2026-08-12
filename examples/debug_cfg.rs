use goblin::Object;
use std::fs;

use rugra::action::ActionDatabase;
use rugra::disasm::{Disassembler, X86_64Disassembler, X86Lifter};
use rugra::funcdata::Funcdata;
use rugra::block::BlockGraph;

fn dump_blocks(prefix: &str, graph: &BlockGraph) {
    println!("{} Graph: {} blocks", prefix, graph.get_size());
    for i in 0..graph.get_size() {
        if let Some(block) = graph.get_block(i) {
            let b = block.read().unwrap();
            print!("  Block {}: Type={:?}, In={}", b.get_index(), b.get_type(), b.size_in());
            print!(", Out={} (", b.size_out());
            for j in 0..b.size_out() {
                if let Some(edge) = b.get_out(j) {
                    print!("{} ", edge.point.read().unwrap().get_index());
                }
            }
            println!(")");
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let buffer = fs::read("examples/curl")?;
    let obj = Object::parse(&buffer)?;
    let mut main_vaddr = 0;
    let mut main_size = 0;
    let mut main_offset = 0;

    if let Object::Elf(elf) = obj {
        for sym in elf.syms.iter() {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if name == "main" {
                    main_vaddr = sym.st_value;
                    main_size = sym.st_size as usize;
                    break;
                }
            }
        }
        for header in elf.section_headers.iter() {
            if main_vaddr >= header.sh_addr && main_vaddr < header.sh_addr + header.sh_size {
                main_offset = header.sh_offset + (main_vaddr - header.sh_addr);
                break;
            }
        }
    }

    let size = if main_size > 0 { std::cmp::min(main_size, 512) } else { 128 };
    let end_offset = std::cmp::min(main_offset as usize + size, buffer.len());
    let code_bytes = &buffer[main_offset as usize..end_offset];

    let mut disasm = X86_64Disassembler::new();
    let instructions = disasm.disassemble(code_bytes, rugra::address::Address::new(main_vaddr)).map_err(|e| e.to_string())?;

    println!("--- Disassembly ---");
    for inst in &instructions {
        println!("0x{:x}: [{}] {} (Operands: {:?})", inst.address, inst.mnemonic, inst.text, inst.operands);
    }
    println!("-------------------");

    let mut lifter = X86Lifter::new();
    let mut raw_ops = Vec::new();

    for inst in &instructions {
        let mut ops = lifter.lift(inst);
        for op in &mut ops {
            op.set_seq_num(rugra::address::SeqNum::new(inst.address, 0));
        }
        raw_ops.extend(ops);
    }

    let mut fd = Funcdata::new("main", rugra::address::Address::new(main_vaddr), main_size as i32);
    
    // Quick debug: how many branches?
    let mut num_branches = 0;
    for op in &raw_ops {
        if op.get_opcode() == rugra::opcodes::OpCode::CPUI_CBRANCH as i32 || op.get_opcode() == rugra::opcodes::OpCode::CPUI_BRANCH as i32 {
            num_branches += 1;
            println!("Found branch op at {:?}", op.seq_num().unwrap().get_addr());
        }
    }
    println!("Total branch ops: {}", num_branches);

    fd.inject_raw_ops(&raw_ops);
    
    let fd_arc = std::sync::Arc::new(std::sync::RwLock::new(fd));
    fd_arc.write().unwrap().set_self_ref(std::sync::Arc::downgrade(&fd_arc));

    let mut db = ActionDatabase::new();
    db.set_default_actions();
    
    {
        let mut fd_write = fd_arc.write().unwrap();
        
        println!("=== BEFORE ACTION DATABASE ===");
        dump_blocks("Basic", &fd_write.bblocks);
        
        let _ = db.perform_action("decompile", &mut fd_write);
        
        println!("=== AFTER ACTION DATABASE ===");
        dump_blocks("Basic", &fd_write.bblocks);
        dump_blocks("Struct", &fd_write.sblocks);
    }

    Ok(())
}
