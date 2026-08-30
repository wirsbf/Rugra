//! COREACTION-CALLIN0-CLOBBER-0001 trace probe: run prefix 18 vs prefix 19 of
//! the DECOMPILE groups on ap_pregfree and dump CALL in(0) + STORE count.
//! With RUGRA_CALLIN0_TRACE set, funcdata::op_set_input backtraces CALL slot-0
//! rewrites (temp diagnostic).

use rugra::action::ActionDatabase;
use rugra::address::Address;
use rugra::disasm::{Disassembler as _, X86Lifter, X86_64Disassembler};
use rugra::funcdata::Funcdata;

fn build_fd() -> anyhow::Result<(std::sync::Arc<std::sync::RwLock<Funcdata>>, Vec<u8>)> {
    let buffer = std::fs::read("examples/httpd")?;
    let obj = goblin::Object::parse(&buffer)?;
    let elf = match &obj {
        goblin::Object::Elf(e) => e,
        _ => anyhow::bail!("not elf"),
    };
    let target: u64 = 0x2e230;
    let mut file_off = 0usize;
    for h in elf.section_headers.iter() {
        if target >= h.sh_addr && target < h.sh_addr + h.sh_size {
            file_off = (h.sh_offset + (target - h.sh_addr)) as usize;
            break;
        }
    }
    let code = buffer[file_off..file_off + 50].to_vec();

    let mut disasm = X86_64Disassembler::new();
    let instructions = disasm.disassemble(&code, Address::new(target))?;
    let mut lifter = X86Lifter::new();
    let mut raw_ops = Vec::new();
    for inst in &instructions {
        let mut ops = lifter.lift(inst);
        for op in &mut ops {
            op.set_seq_num(rugra::address::SeqNum::new(inst.address, 0));
        }
        raw_ops.extend(ops);
    }

    let mut fd = Funcdata::new("ap_pregfree", Address::new(target), 50);
    fd.add_symbol(0x31070, "ap_regfree".into());
    fd.add_symbol(0x2a970, "apr_pool_cleanup_kill".into());
    fd.inject_raw_ops(&raw_ops);
    let fd_arc = std::sync::Arc::new(std::sync::RwLock::new(fd));
    fd_arc
        .write()
        .unwrap()
        .set_self_ref(std::sync::Arc::downgrade(&fd_arc));
    Ok((fd_arc, code))
}

fn main() -> anyhow::Result<()> {
    let prefixes: Vec<usize> = std::env::args()
        .skip(1)
        .map(|a| a.parse().expect("prefix len"))
        .collect();
    let prefixes = if prefixes.is_empty() { vec![19] } else { prefixes };
    let groups = rugra::action::default_groups::DECOMPILE;
    for prefix_len in prefixes {
        let (fd_arc, _code) = build_fd()?;
        let mut db = ActionDatabase::new();
        db.set_default_actions();
        let prefix: Vec<&'static str> = groups[..prefix_len].to_vec();
        let root_name = format!("bis{prefix_len}");
        db.set_group(&root_name, &prefix);
        db.set_current(&root_name);
        let mut fd_write = fd_arc.write().unwrap();
        let result = db.apply_all(&mut fd_write);
        drop(fd_write);
        let fd_read = fd_arc.read().unwrap();
        let mut call_desc = Vec::new();
        let mut store_count = 0usize;
        for op_ref in fd_read.obank.alivelist.iter() {
            let op = op_ref.0.read().unwrap();
            match op.opcode {
                rugra::opcodes::OpCode::CPUI_CALL => {
                    let d = op
                        .inrefs
                        .first()
                        .map(|v| {
                            let g = v.read().unwrap();
                            format!("{}:0x{:x}:{}", g.get_space(), g.get_offset(), g.get_size())
                        })
                        .unwrap_or_else(|| "none".into());
                    call_desc.push(format!("CALL in0=({d})"));
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
    Ok(())
}
