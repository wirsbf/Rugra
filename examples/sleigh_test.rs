//! Minimal SLEIGH integration test — verify jingle_sleigh can decode x86-64
//! instructions into P-code using the compiled x86-64.sla spec.

use jingle_sleigh::context::SleighContextBuilder;

fn main() {
    let specs_dir = std::path::Path::new("sleigh_specs");
    println!("Loading SLEIGH specs from {:?}...", specs_dir);

    let builder = SleighContextBuilder::load_folder(specs_dir)
        .expect("Failed to load SLEIGH specs");

    let lang_ids = builder.get_language_ids();
    println!("Available languages: {:?}", lang_ids);

    let ctx = builder.build("x86:LE:64:default")
        .expect("Failed to build SLEIGH context");

    println!("SLEIGH context created!");
    println!("Spaces: {}", ctx.spaces().len());

    // Print some known registers
    for name in &["RAX", "RSP", "RBP", "RDI", "RSI"] {
        if let Some(vn) = ctx.arch_info().register(name) {
            println!("  {} = offset=0x{:x} size={}", name, vn.offset(), vn.size());
        }
    }

    let code: &[u8] = &[
        0x55,                                           // PUSH RBP
        0x48, 0x89, 0xe5,                               // MOV RBP, RSP
        0x48, 0x89, 0xf8,                               // MOV RAX, RDI
        0xe8, 0x10, 0x00, 0x00, 0x00,                   // CALL rel32
    ];

    let loaded = ctx.initialize_with_image(code)
        .expect("Failed to initialize with image");

    let mut offset = 0u64;
    while offset < code.len() as u64 {
        match loaded.instruction_at(offset) {
            Some(inst) => {
                println!("=== 0x{:x} ({} bytes) ===", inst.address, inst.length);
                println!("  Disasm: {}", inst.disassembly);
                for (i, op) in inst.ops.iter().enumerate() {
                    println!("  [{}] {}", i, op);
                }
                offset = inst.next_addr();
            }
            None => { println!("Cannot decode at 0x{:x}", offset); break; }
        }
    }
}
