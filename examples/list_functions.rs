use goblin::Object;
fn main() {
    let buffer = std::fs::read("examples/curl").unwrap();
    if let Object::Elf(elf) = Object::parse(&buffer).unwrap() {
        let mut funcs: Vec<(u64, u64, String)> = Vec::new();
        for sym in elf.syms.iter() {
            if sym.is_function() && sym.st_size > 0 {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    funcs.push((sym.st_value, sym.st_size, name.to_string()));
                }
            }
        }
        funcs.sort_by_key(|f| f.0);
        println!("Found {} functions:", funcs.len());
        for (addr, size, name) in &funcs {
            println!("  0x{:06x}  {:5} bytes  {}", addr, size, name);
        }
    }
}
