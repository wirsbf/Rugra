//! Example: Disassemble x86-64 machine code
//!
//! This example demonstrates how to use Rugra's disassembler to convert
//! raw machine code bytes into human-readable assembly instructions.
//!
//! Run with: cargo run --example disassemble_demo

use rugra::disasm::{Disassembler, X86_64Disassembler};
use rugra::Address;

fn main() -> anyhow::Result<()> {
    println!("🔧 Rugra Disassembly Demo\n");
    println!("{}", "=".repeat(60));

    // Example 1: Simple arithmetic function
    println!("\n📝 Example 1: Simple Add Function");
    println!("{}", "-".repeat(60));

    // This is the machine code for:
    // add(int a, int b) {
    //   return a + b;
    // }
    // Compiled with: gcc -O2
    let add_function = vec![
        0x48, 0x89, 0xf8, // mov rax, rdi  ; move first arg to rax
        0x48, 0x01, 0xf0, // add rax, rsi  ; add second arg
        0xc3,             // ret
    ];

    disassemble_and_display(&add_function, 0x1000, "add_function")?;

    // Example 2: Conditional branch
    println!("\n📝 Example 2: Conditional Function");
    println!("{}", "-".repeat(60));

    let conditional = vec![
        0x48, 0x85, 0xff,       // test rdi, rdi
        0x74, 0x05,             // je +5
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0xc3,                   // ret
        0x31, 0xc0,             // xor eax, eax
        0xc3,                   // ret
    ];

    disassemble_and_display(&conditional, 0x2000, "is_nonzero")?;

    // Example 3: Loop example
    println!("\n📝 Example 3: Simple Loop");
    println!("{}", "-".repeat(60));

    let loop_code = vec![
        0x31, 0xc0,             // xor eax, eax      ; counter = 0
        0xeb, 0x03,             // jmp +3            ; jump to condition
        0xff, 0xc0,             // inc eax           ; counter++
        0x39, 0xf8,             // cmp eax, edi      ; compare counter with limit
        0x7c, 0xfa,             // jl -6             ; jump if less
        0xc3,                   // ret
    ];

    disassemble_and_display(&loop_code, 0x3000, "count_to_n")?;

    // Example 4: Analyze instruction properties
    println!("\n📊 Example 4: Instruction Analysis");
    println!("{}", "-".repeat(60));

    let mixed_code = vec![
        0xe8, 0x00, 0x00, 0x00, 0x00, // call rel32
        0xeb, 0x05,                   // jmp +5
        0x74, 0x03,                   // je +3
        0xc3,                         // ret
        0x90,                         // nop
    ];

    analyze_instructions(&mixed_code, 0x4000)?;

    println!("\n{}", "=".repeat(60));
    println!("✅ Disassembly demo complete!\n");

    Ok(())
}

fn disassemble_and_display(code: &[u8], start_addr: u64, name: &str) -> anyhow::Result<()> {
    let mut disasm = X86_64Disassembler::new();
    let instructions = disasm.disassemble(code, Address::new(start_addr))?;

    println!("Function: {}", name);
    println!("Address range: 0x{:x} - 0x{:x}", start_addr, start_addr + code.len() as u64);
    println!("Total instructions: {}\n", instructions.len());

    for inst in &instructions {
        // Print address
        print!("  {:08x}  ", inst.address.as_u64());

        // Print bytes (padded to 12 characters for alignment)
        let bytes_str: String = inst.bytes.iter()
            .take(inst.length)
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        print!("{:20}", bytes_str);

        // Print instruction
        print!("  {}", inst.text);

        // Add markers for control flow
        if inst.is_call() {
            print!("  ; CALL");
        } else if inst.is_return() {
            print!("  ; RETURN");
        } else if inst.is_branch() {
            if inst.metadata.is_conditional {
                print!("  ; CONDITIONAL BRANCH");
            } else {
                print!("  ; BRANCH");
            }
            if let Some(target) = inst.branch_target() {
                print!(" -> 0x{:x}", target.as_u64());
            }
        }

        println!();
    }

    Ok(())
}

fn analyze_instructions(code: &[u8], start_addr: u64) -> anyhow::Result<()> {
    let mut disasm = X86_64Disassembler::new();
    let instructions = disasm.disassemble(code, Address::new(start_addr))?;

    println!("Analyzing {} instructions...\n", instructions.len());

    let mut branch_count = 0;
    let mut call_count = 0;
    let mut return_count = 0;
    let mut memory_read_count = 0;
    let mut memory_write_count = 0;

    for inst in &instructions {
        println!("  0x{:08x}: {}", inst.address.as_u64(), inst.text);

        if inst.is_branch() {
            branch_count += 1;
            println!("    ├─ Type: Branch (conditional: {})", inst.metadata.is_conditional);
        } else if inst.is_call() {
            call_count += 1;
            println!("    ├─ Type: Call");
        } else if inst.is_return() {
            return_count += 1;
            println!("    ├─ Type: Return");
        }

        if inst.metadata.reads_memory {
            memory_read_count += 1;
            println!("    ├─ Memory: Read");
        }
        if inst.metadata.writes_memory {
            memory_write_count += 1;
            println!("    ├─ Memory: Write");
        }

        if !inst.metadata.reads_registers.is_empty() {
            println!("    ├─ Reads: {}", inst.metadata.reads_registers.join(", "));
        }
        if !inst.metadata.writes_registers.is_empty() {
            println!("    └─ Writes: {}", inst.metadata.writes_registers.join(", "));
        }

        println!();
    }

    println!("Statistics:");
    println!("  Branches:      {}", branch_count);
    println!("  Calls:         {}", call_count);
    println!("  Returns:       {}", return_count);
    println!("  Memory Reads:  {}", memory_read_count);
    println!("  Memory Writes: {}", memory_write_count);

    Ok(())
}
