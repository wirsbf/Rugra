//! End-to-end decompilation example
//!
//! This example demonstrates the complete decompilation pipeline:
//! 1. Machine code → Disassembly
//! 2. Disassembly → P-code IR
//! 3. P-code → Control Flow Graph
//! 4. Analysis
//! 5. C code generation

use rugra::{
    Address, Result,
    disasm::{Disassembler, X86_64Disassembler},
    translator::{Translator, X86_64Translator},
    pcode::Program,
    analysis::{analyze_function, cfg::ControlFlowGraph},
    codegen::generate_c_code,
};

fn main() -> Result<()> {
    println!("=== Rugra Decompilation Demo ===\n");

    // Example 1: Simple addition function
    println!("Example 1: Simple Addition Function");
    println!("-----------------------------------");
    decompile_addition_function()?;

    println!("\n");

    // Example 2: Conditional function
    println!("Example 2: Conditional Function");
    println!("--------------------------------");
    decompile_conditional_function()?;

    println!("\n");

    // Example 3: Loop function
    println!("Example 3: Loop Function");
    println!("------------------------");
    decompile_loop_function()?;

    Ok(())
}

/// Decompile a simple addition function
///
/// C equivalent:
/// ```c
/// int add(int a, int b) {
///     return a + b;
/// }
/// ```
fn decompile_addition_function() -> Result<()> {
    // x86-64 assembly:
    // mov rax, rdi     ; rax = first argument
    // add rax, rsi     ; rax += second argument
    // ret              ; return rax
    let machine_code: Vec<u8> = vec![
        0x48, 0x89, 0xf8,  // mov rax, rdi
        0x48, 0x01, 0xf0,  // add rax, rsi
        0xc3,              // ret
    ];

    println!("Machine code: {:02x?}", machine_code);
    println!();

    // Step 1: Disassemble
    let mut disasm = X86_64Disassembler::new();
    let instructions = disasm.disassemble(&machine_code, Address::new(0x1000))?;

    println!("Disassembly:");
    for instr in &instructions {
        println!("  {}", instr);
    }
    println!();

    // Step 2: Translate to P-code
    let translator = X86_64Translator::new();
    let mut program = Program::with_entry_point(Address::new(0x1000));

    for instr in &instructions {
        let pcode_ops = translator.translate(instr)?;
        for op in pcode_ops {
            program.add_operation(op);
        }
    }

    println!("P-code IR:");
    for op in program.operations() {
        println!("  {}", op);
    }
    println!();

    // Step 3: Build Control Flow Graph
    let cfg = ControlFlowGraph::from_program(&program)?;
    println!("Control Flow Graph:");
    println!("  Blocks: {}", cfg.block_count());
    println!("  Entry: {}", cfg.entry);
    println!("  Exits: {:?}", cfg.exits);
    println!();

    // Step 4: Analyze
    let analysis = analyze_function(&mut program, None)?;
    println!("Analysis complete");
    println!();

    // Step 5: Generate C code
    let c_code = generate_c_code(&analysis, &program, None)?;
    println!("Generated C code:");
    println!("{}", c_code);

    Ok(())
}

/// Decompile a conditional function
///
/// C equivalent:
/// ```c
/// int max(int a, int b) {
///     if (a > b) {
///         return a;
///     } else {
///         return b;
///     }
/// }
/// ```
fn decompile_conditional_function() -> Result<()> {
    // x86-64 assembly:
    // cmp rdi, rsi     ; compare a and b
    // jle .else        ; if a <= b, jump to else
    // mov rax, rdi     ; return a
    // ret
    // .else:
    // mov rax, rsi     ; return b
    // ret
    let machine_code: Vec<u8> = vec![
        0x48, 0x39, 0xf7,  // cmp rdi, rsi
        0x7e, 0x05,        // jle +5 (to 0x100a)
        0x48, 0x89, 0xf8,  // mov rax, rdi
        0xc3,              // ret
        // else branch (0x100a):
        0x48, 0x89, 0xf0,  // mov rax, rsi
        0xc3,              // ret
    ];

    println!("Machine code: {:02x?}", machine_code);
    println!();

    // Step 1: Disassemble
    let mut disasm = X86_64Disassembler::new();
    let instructions = disasm.disassemble(&machine_code, Address::new(0x1000))?;

    println!("Disassembly:");
    for instr in &instructions {
        println!("  {}", instr);
    }
    println!();

    // Step 2: Translate to P-code
    let translator = X86_64Translator::new();
    let mut program = Program::with_entry_point(Address::new(0x1000));

    for instr in &instructions {
        let pcode_ops = translator.translate(instr)?;
        for op in pcode_ops {
            program.add_operation(op);
        }
    }

    println!("P-code IR: {} operations", program.operation_count());
    println!();

    // Step 3: Build Control Flow Graph
    let cfg = ControlFlowGraph::from_program(&program)?;
    println!("Control Flow Graph:");
    println!("  Blocks: {}", cfg.block_count());
    println!("  Entry: {}", cfg.entry);
    println!("  Exits: {:?}", cfg.exits);

    for (i, block) in cfg.blocks.iter().enumerate() {
        println!("  Block {}: {} ops, successors: {:?}",
            i, block.operations.len(), block.successors);
    }
    println!();

    // Step 4: Analyze
    let analysis = analyze_function(&mut program, None)?;
    println!("Analysis complete");
    println!();

    // Step 5: Generate C code
    let c_code = generate_c_code(&analysis, &program, None)?;
    println!("Generated C code:");
    println!("{}", c_code);

    Ok(())
}

/// Decompile a loop function
///
/// C equivalent:
/// ```c
/// int sum_n(int n) {
///     int sum = 0;
///     for (int i = 0; i < n; i++) {
///         sum += i;
///     }
///     return sum;
/// }
/// ```
fn decompile_loop_function() -> Result<()> {
    // x86-64 assembly:
    // xor eax, eax     ; sum = 0
    // xor ecx, ecx     ; i = 0
    // .loop:
    // cmp ecx, edi     ; compare i and n
    // jge .end         ; if i >= n, exit loop
    // add eax, ecx     ; sum += i
    // inc ecx          ; i++
    // jmp .loop        ; repeat
    // .end:
    // ret
    let machine_code: Vec<u8> = vec![
        0x31, 0xc0,        // xor eax, eax
        0x31, 0xc9,        // xor ecx, ecx
        // loop (0x1004):
        0x39, 0xf9,        // cmp ecx, edi
        0x7d, 0x06,        // jge +6 (to 0x100e)
        0x01, 0xc8,        // add eax, ecx
        0xff, 0xc1,        // inc ecx
        0xeb, 0xf6,        // jmp -10 (to 0x1004)
        // end (0x100e):
        0xc3,              // ret
    ];

    println!("Machine code: {:02x?}", machine_code);
    println!();

    // Step 1: Disassemble
    let mut disasm = X86_64Disassembler::new();
    let instructions = disasm.disassemble(&machine_code, Address::new(0x1000))?;

    println!("Disassembly:");
    for instr in &instructions {
        println!("  {}", instr);
    }
    println!();

    // Step 2: Translate to P-code
    let translator = X86_64Translator::new();
    let mut program = Program::with_entry_point(Address::new(0x1000));

    for instr in &instructions {
        let pcode_ops = translator.translate(instr)?;
        for op in pcode_ops {
            program.add_operation(op);
        }
    }

    println!("P-code IR: {} operations", program.operation_count());
    println!();

    // Step 3: Build Control Flow Graph
    let cfg = ControlFlowGraph::from_program(&program)?;
    println!("Control Flow Graph:");
    println!("  Blocks: {}", cfg.block_count());
    println!("  Entry: {}", cfg.entry);
    println!("  Exits: {:?}", cfg.exits);

    for (i, block) in cfg.blocks.iter().enumerate() {
        println!("  Block {}: addr 0x{:x}, {} ops, successors: {:?}",
            i, block.start_addr.as_u64(), block.operations.len(), block.successors);
    }
    println!();

    // Step 4: Analyze
    let analysis = analyze_function(&mut program, None)?;
    println!("Analysis complete");
    println!();

    // Step 5: Generate C code
    let c_code = generate_c_code(&analysis, &program, None)?;
    println!("Generated C code:");
    println!("{}", c_code);

    Ok(())
}
