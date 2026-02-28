//! Example: Translate x86-64 instructions to P-code
//!
//! This example demonstrates the complete translation pipeline from
//! machine code → disassembly → P-code IR.
//!
//! Run with: cargo run --example translate_demo

use rugra::disasm::{Disassembler, X86_64Disassembler};
use rugra::translator::{Translator, X86_64Translator};
use rugra::Address;

fn main() -> anyhow::Result<()> {
    println!("🔬 Rugra Translation Demo\n");
    println!("{}", "=".repeat(70));

    // Example 1: Simple mov instruction
    println!("\n📝 Example 1: MOV Instruction");
    println!("{}", "-".repeat(70));
    
    let code = vec![0x48, 0x89, 0xd8]; // mov rax, rbx
    translate_and_display(&code, 0x1000, "mov rax, rbx")?;

    // Example 2: Arithmetic
    println!("\n📝 Example 2: ADD Instruction");
    println!("{}", "-".repeat(70));
    
    let code = vec![0x48, 0x01, 0xd8]; // add rax, rbx
    translate_and_display(&code, 0x2000, "add rax, rbx")?;

    // Example 3: Comparison and jump
    println!("\n📝 Example 3: CMP and Conditional Jump");
    println!("{}", "-".repeat(70));
    
    let code = vec![
        0x48, 0x39, 0xf8,  // cmp rax, rdi
        0x74, 0x05,        // je +5
    ];
    translate_and_display(&code, 0x3000, "cmp + je")?;

    // Example 4: Complete function
    println!("\n📝 Example 4: Complete Function");
    println!("{}", "-".repeat(70));
    
    let code = vec![
        0x48, 0x89, 0xf8,  // mov rax, rdi
        0x48, 0x01, 0xf0,  // add rax, rsi
        0xc3,              // ret
    ];
    translate_function(&code, 0x4000, "add_function")?;

    println!("\n{}", "=".repeat(70));
    println!("✅ Translation demo complete!\n");

    Ok(())
}

fn translate_and_display(code: &[u8], start_addr: u64, description: &str) -> anyhow::Result<()> {
    println!("Code: {}", description);
    println!("Address: 0x{:x}\n", start_addr);

    // Step 1: Disassemble
    let mut disasm = X86_64Disassembler::new();
    let instructions = disasm.disassemble(code, Address::new(start_addr))?;

    // Step 2: Translate
    let translator = X86_64Translator::new();

    for inst in &instructions {
        println!("  Assembly: {}", inst.text);
        println!("  Address:  {}\n", inst.address);

        match translator.translate(inst) {
            Ok(pcode_ops) => {
                println!("  P-code ({} operations):", pcode_ops.len());
                for (i, op) in pcode_ops.iter().enumerate() {
                    println!("    [{}] {}", i, op);
                }
            }
            Err(e) => {
                println!("  Translation error: {}", e);
            }
        }
        println!();
    }

    Ok(())
}

fn translate_function(code: &[u8], start_addr: u64, name: &str) -> anyhow::Result<()> {
    println!("Function: {}", name);
    println!("Address: 0x{:x}\n", start_addr);

    let mut disasm = X86_64Disassembler::new();
    let instructions = disasm.disassemble(code, Address::new(start_addr))?;

    let translator = X86_64Translator::new();

    let mut total_pcode_ops = 0;

    for inst in &instructions {
        println!("  0x{:08x}  {}", inst.address.as_u64(), inst.text);
        
        match translator.translate(inst) {
            Ok(pcode_ops) => {
                total_pcode_ops += pcode_ops.len();
                for op in pcode_ops {
                    println!("      {}", op);
                }
            }
            Err(e) => {
                println!("      Error: {}", e);
            }
        }
        println!();
    }

    println!("Summary:");
    println!("  Instructions:    {}", instructions.len());
    println!("  P-code ops:      {}", total_pcode_ops);
    println!("  Avg ops/inst:    {:.1}", total_pcode_ops as f64 / instructions.len() as f64);

    Ok(())
}
