//! HTTPD-STACKSLOT-FOLD-0001 diagnostic: decompile ap_parse_vhost_addrs via
//! the standard pipeline, then dump every surviving LOAD/STORE with its
//! pointer def chain, checking the RuleLoadVarnode/RuleStoreVarnode
//! (ruleaction.cc:4165-4341) firing conditions.

use rugra::action::ActionDatabase;
use rugra::address::Address;
use rugra::funcdata::Funcdata;
use rugra::opcodes::OpCode;

fn vn_desc(vn: &std::sync::Arc<std::sync::RwLock<rugra::varnode::Varnode>>, depth: usize) -> String {
    let v = vn.read().unwrap();
    let mut s = format!(
        "[{}:0x{:x}:{} const={} input={} written={} spacebase={:?}]",
        v.get_space(),
        v.get_offset(),
        v.get_size(),
        v.is_constant(),
        v.is_input(),
        v.is_written(),
        v.is_spacebase()
    );
    if depth < 8 {
        if let Some(def_w) = v.def.as_ref().and_then(|w| w.upgrade()) {
            let d = def_w.read().unwrap();
            s.push_str(&format!(
                " = {:?}(",
                d.opcode
            ));
            let parts: Vec<String> = d
                .inrefs
                .iter()
                .map(|inv| vn_desc(inv, depth + 1))
                .collect();
            s.push_str(&parts.join(", "));
            s.push(')');
        }
    }
    s
}

/// Walk the def chain of vn looking for Register:offset. Depth-limited.
fn chain_has_reg(vn: &std::sync::Arc<std::sync::RwLock<rugra::varnode::Varnode>>, reg_off: u64, depth: usize) -> bool {
    if depth > 8 { return false; }
    let v = vn.read().unwrap();
    if v.get_space() == rugra::space::AddressSpace::Register && v.get_offset() == reg_off {
        return true;
    }
    if let Some(def_w) = v.def.as_ref().and_then(|w| w.upgrade()) {
        let d = def_w.read().unwrap();
        for inv in d.inrefs.iter() {
            if chain_has_reg(inv, reg_off, depth + 1) { return true; }
        }
    }
    false
}

fn main() -> anyhow::Result<()> {
    let buffer = std::fs::read("examples/httpd")?;
    let obj = goblin::Object::parse(&buffer)?;
    let elf = match &obj {
        goblin::Object::Elf(e) => e,
        _ => anyhow::bail!("not elf"),
    };

    let target: u64 = 0x2cf30;
    let size: usize = 203;
    let mut file_off = 0usize;
    for h in elf.section_headers.iter() {
        if target >= h.sh_addr && target < h.sh_addr + h.sh_size {
            file_off = (h.sh_offset + (target - h.sh_addr)) as usize;
            break;
        }
    }
    let code = &buffer[file_off..file_off + size];

    // SLEIGH-RUSTIFY-PHASE3-0001: canon-contract linear walk (the httpd
    // driver's lift_instruction_skip_nops padding filter) — the 203-byte
    // symbol window ends in a 7-byte `0f 1f 80` alignment NOP whose engine
    // operand pcode the canon path never injects.
    let raw_ops = rugra::disasm::sleigh_lift::sleigh_raw_ops_skip_nops(code, target);

    eprintln!("== raw lifted STORE/LOAD ops:");
    for op in raw_ops.iter() {
        let opc = OpCode::from_i32(op.get_opcode()).unwrap();
        if opc == OpCode::CPUI_STORE || opc == OpCode::CPUI_LOAD {
            let inputs = op
                .inputs()
                .iter()
                .map(|v| format!("{}:0x{:x}:{}", v.space, v.offset, v.size))
                .collect::<Vec<_>>()
                .join(",");
            eprintln!("  {:?} in=({inputs})", opc);
        }
    }

    let mut fd = Funcdata::new("ap_parse_vhost_addrs", Address::new(target), size as i32);
    // HTTPD-STACKSLOT-FOLD-0001 fixture runner: the shipped httpd runner
    // attaches the canonical Architecture (mirroring `glb =
    // scope->getArch()`, funcdata.cc:48) before the pipeline. STACKFOLD_ARCH=0
    // reproduces the pre-fix arch-less break for differential debugging.
    if std::env::var("STACKFOLD_ARCH").map(|v| v != "0").unwrap_or(true) {
        fd.set_arch(std::sync::Arc::new(rugra::arch::Architecture::new()));
    }
    fd.add_symbol(0x2ec00, "ap_getword_conf".into());
    fd.add_symbol(0x2c960, "FUN_0012c960".into());
    fd.inject_raw_ops(&raw_ops);

    {
        let mut db = ActionDatabase::new();
        db.set_default_actions();
        db.apply_all(&mut fd)?;
    }

    eprintln!("\n== surviving STORE/LOAD ops after full pipeline:");
    let fdg = &fd;
    let mut n = 0;
    for op_ref in &fdg.obank.alivelist {
        let op = op_ref.0.read().unwrap();
        if op.opcode == OpCode::CPUI_STORE || op.opcode == OpCode::CPUI_LOAD {
            n += 1;
            eprintln!("\n--- #{n} {:?} @ 0x{:x}", op.opcode, op.get_addr());
            if let Some(addr_vn) = op.inrefs.get(1) {
                eprintln!("  ptr chain: {}", vn_desc(addr_vn, 0));
            }
        }
    }
    eprintln!("\ntotal surviving LOAD/STORE: {n}");

    // HTTPD-STACKSLOT-FOLD-0001 regression assertion: with the canonical
    // Architecture attached, every spacebase-relative STORE/LOAD of
    // ap_parse_vhost_addrs folds into stack-space COPYs; the single
    // survivor must be the INT_ADD(param, 0x60) register-pointer chain
    // (in_RDX here), not an in_RSP chain. Pre-fix (arch-less) census was 7
    // with 7/7 in_RSP chains.
    if std::env::var("STACKFOLD_ARCH").map(|v| v != "0").unwrap_or(true) {
        let leak = fdg
            .obank
            .alivelist
            .iter()
            .filter_map(|op_ref| {
                let op = op_ref.0.read().unwrap();
                if op.opcode == OpCode::CPUI_STORE || op.opcode == OpCode::CPUI_LOAD {
                    op.inrefs.get(1).cloned()
                } else {
                    None
                }
            })
            .filter(|addr_vn| chain_has_reg(addr_vn, 0x20, 0))
            .count();
        if n != 1 || leak != 0 {
            eprintln!(
                "STACKFOLD FIXTURE FAIL: surviving={n} in_RSP-chained={leak} (expected 1/0)"
            );
            std::process::exit(1);
        }
        eprintln!("STACKFOLD FIXTURE PASS: surviving={n} in_RSP-chained={leak}");
    }

    // Does an input RSP exist and is it spacebase-marked?
    for entry in fdg.vbank.loc_tree.iter() {
        let v = entry.0.read().unwrap();
        if v.get_space() == rugra::space::AddressSpace::Register
            && v.get_offset() == 0x20
            && v.get_size() == 8
        {
            eprintln!(
                "RSP vn: input={} spacebase={:?} written={} ndesc={}",
                v.is_input(),
                v.is_spacebase(),
                v.is_written(),
                v.descend.len()
            );
        }
    }
    Ok(())
}
