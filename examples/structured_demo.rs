//! Advanced Control Flow Structuring Example
//!
//! This example demonstrates Rugra's ability to recognize and reconstruct
//! structured control flow (loops, conditionals) from machine code.

use rugra::{
    Address, Result,
    disasm::{Disassembler, X86_64Disassembler},
    translator::{Translator, X86_64Translator},
    pcode::Program,
    analysis::{analyze_function, cfg::ControlFlowGraph},
    codegen::generate_c_code,
};

fn main() -> Result<()> {
    println!("=== Rugra Advanced Control Flow Structuring Demo ===\n");

    // Example 1: While loop
    println!("Example 1: While Loop");
    println!("=====================");
    demonstrate_while_loop()?;

    println!("\n");

    // Example 2: For loop with counter
    println!("Example 2: For Loop");
    println!("===================");
    demonstrate_for_loop()?;

    println!("\n");

    // Example 3: Nested conditionals
    println!("Example 3: Nested If/Else");
    println!("=========================");
    demonstrate_nested_conditionals()?;

    println!("\n");

    // Example 4: Loop with break
    println!("Example 4: Loop with Early Exit");
    println!("================================");
    demonstrate_loop_with_break()?;

    Ok(())
}

/// Demonstrate while loop detection
///
/// C equivalent:
/// ```c
/// int count_down(int n) {
///     while (n > 0) {
///         n--;
///     }
///     return n;
/// }
/// ```
fn demonstrate_while_loop() -> Result<()> {
    // x86-64 assembly:
    // .loop:
    //   test edi, edi      ; check if n > 0
    //   jle .end           ; if n <= 0, exit
    //   dec edi            ; n--
    //   jmp .loop          ; repeat
    // .end:
    //   mov eax, edi       ; return n
    //   ret
    let machine_code: Vec<u8> = vec![
        // loop (0x1000):
        0x85, 0xff,        // test edi, edi
        0x7e, 0x04,        // jle +4 (to 0x1008)
        0xff, 0xcf,        // dec edi
        0xeb, 0xf8,        // jmp -8 (to 0x1000)
        // end (0x1008):
        0x89, 0xf8,        // mov eax, edi
        0xc3,              // ret
    ];

    println!("Machine code: {:02x?}", machine_code);
    println!();

    // Disassemble
    let mut disasm = X86_64Disassembler::new();
    let instructions = disasm.disassemble(&machine_code, Address::new(0x1000))?;

    println!("Disassembly:");
    for instr in &instructions {
        println!("  {}", instr);
    }
    println!();

    // Translate to P-code
    let translator = X86_64Translator::new();
    let mut program = Program::with_entry_point(Address::new(0x1000));

    for instr in &instructions {
        let pcode_ops = translator.translate(instr)?;
        for op in pcode_ops {
            program.add_operation(op);
        }
    }

    println!("P-code: {} operations", program.operation_count());
    println!();

    // Build CFG and analyze
    let cfg = ControlFlowGraph::from_program(&program)?;
    println!("Control Flow Graph:");
    println!("  Blocks: {}", cfg.block_count());

    // Detect loops
    let loops = cfg.detect_loops();
    println!("  Loops detected: {}", loops.len());
    for (i, loop_info) in loops.iter().enumerate() {
        println!("    Loop {}: header={}, body={:?}, type={:?}",
            i, loop_info.header, loop_info.body, loop_info.loop_type);
    }
    println!();

    // Show dominator tree
    println!("{}", cfg.dominator_tree_string());

    // Generate structured C code
    let analysis = analyze_function(&mut program, None)?;

    println!("P-code after optimization:");
    for (i, op) in program.operations().iter().enumerate() {
        println!("  {}: {}", i, op);
    }
    println!();

    let c_code = generate_c_code(&analysis, &program, None)?;

    println!("Generated C code:");
    println!("{}", c_code);

    Ok(())
}

/// Demonstrate for loop detection
///
/// C equivalent:
/// ```c
/// int sum_range(int n) {
///     int sum = 0;
///     for (int i = 0; i < n; i++) {
///         sum += i;
///     }
///     return sum;
/// }
/// ```
fn demonstrate_for_loop() -> Result<()> {
    // x86-64 assembly:
    //   xor eax, eax       ; sum = 0
    //   xor ecx, ecx       ; i = 0
    // .loop:
    //   cmp ecx, edi       ; compare i and n
    //   jge .end           ; if i >= n, exit
    //   add eax, ecx       ; sum += i
    //   inc ecx            ; i++
    //   jmp .loop          ; repeat
    // .end:
    //   ret
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

    // Disassemble
    let mut disasm = X86_64Disassembler::new();
    let instructions = disasm.disassemble(&machine_code, Address::new(0x1000))?;

    println!("Disassembly:");
    for instr in &instructions {
        println!("  {}", instr);
    }
    println!();

    // Translate and analyze
    let translator = X86_64Translator::new();
    let mut program = Program::with_entry_point(Address::new(0x1000));

    for instr in &instructions {
        let pcode_ops = translator.translate(instr)?;
        for op in pcode_ops {
            program.add_operation(op);
        }
    }

    let cfg = ControlFlowGraph::from_program(&program)?;

    println!("Control Flow Analysis:");
    println!("  Total blocks: {}", cfg.block_count());

    let loops = cfg.detect_loops();
    println!("  Loops: {}", loops.len());
    for loop_info in &loops {
        println!("    Header: Block {}", loop_info.header);
        println!("    Body: {} blocks", loop_info.body.len());
        println!("    Back edge from: Block {}", loop_info.back_edge_source);
        println!("    Type: {:?}", loop_info.loop_type);
        if let Some(inc) = loop_info.increment {
            println!("    Increment block: {}", inc);
        }
    }
    println!();

    // Generate code
    let analysis = analyze_function(&mut program, None)?;

    println!("P-code after optimization:");
    for (i, op) in program.operations().iter().enumerate() {
        println!("  {}: {}", i, op);
    }
    println!();

    let c_code = generate_c_code(&analysis, &program, None)?;

    println!("Generated C code:");
    println!("{}", c_code);

    Ok(())
}

/// Demonstrate nested conditional detection
///
/// C equivalent:
/// ```c
/// int classify(int x, int y) {
///     if (x > 0) {
///         if (y > 0) {
///             return 1;  // both positive
///         } else {
///             return 2;  // x positive, y negative
///         }
///     } else {
///         return 3;  // x negative
///     }
/// }
/// ```
fn demonstrate_nested_conditionals() -> Result<()> {
    // x86-64 assembly:
    //   test edi, edi      ; check if x > 0
    //   jle .x_negative
    //   test esi, esi      ; check if y > 0
    //   jle .y_negative
    //   mov eax, 1         ; return 1
    //   ret
    // .y_negative:
    //   mov eax, 2         ; return 2
    //   ret
    // .x_negative:
    //   mov eax, 3         ; return 3
    //   ret
    let machine_code: Vec<u8> = vec![
        0x85, 0xff,        // test edi, edi
        0x7e, 0x0a,        // jle +10 (to 0x100e)
        0x85, 0xf6,        // test esi, esi
        0x7e, 0x05,        // jle +5 (to 0x100b)
        0xb8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
        0xc3,              // ret
        // y_negative (0x100b):
        0xb8, 0x02, 0x00, 0x00, 0x00,  // mov eax, 2
        0xc3,              // ret
        // x_negative (0x100e):
        0xb8, 0x03, 0x00, 0x00, 0x00,  // mov eax, 3
        0xc3,              // ret
    ];

    println!("Machine code: {:02x?}", machine_code);
    println!();

    // Process
    let mut disasm = X86_64Disassembler::new();
    let instructions = disasm.disassemble(&machine_code, Address::new(0x1000))?;

    println!("Disassembly:");
    for instr in &instructions {
        println!("  {}", instr);
    }
    println!();

    let translator = X86_64Translator::new();
    let mut program = Program::with_entry_point(Address::new(0x1000));

    for instr in &instructions {
        let pcode_ops = translator.translate(instr)?;
        for op in pcode_ops {
            program.add_operation(op);
        }
    }

    let cfg = ControlFlowGraph::from_program(&program)?;

    println!("Control Flow Analysis:");
    println!("  Total blocks: {}", cfg.block_count());

    let conditionals = cfg.identify_conditionals();
    println!("  Conditionals: {}", conditionals.len());
    for (i, cond) in conditionals.iter().enumerate() {
        println!("    Conditional {}:", i);
        println!("      Condition: Block {}", cond.condition_block);
        println!("      True branch: Block {}", cond.true_branch);
        println!("      False branch: Block {}", cond.false_branch);
        if let Some(merge) = cond.merge_point {
            println!("      Merge point: Block {}", merge);
        }
    }
    println!();

    let analysis = analyze_function(&mut program, None)?;
    let c_code = generate_c_code(&analysis, &program, None)?;

    println!("Generated C code:");
    println!("{}", c_code);

    Ok(())
}

/// Demonstrate loop with early exit (break)
///
/// C equivalent:
/// ```c
/// int find_zero(int arr[], int len) {
///     for (int i = 0; i < len; i++) {
///         if (arr[i] == 0) {
///             return i;  // found zero
///         }
///     }
///     return -1;  // not found
/// }
/// ```
fn demonstrate_loop_with_break() -> Result<()> {
    // x86-64 assembly (simplified):
    //   xor eax, eax       ; i = 0
    // .loop:
    //   cmp eax, esi       ; compare i and len
    //   jge .not_found     ; if i >= len, not found
    //   cmp DWORD PTR [rdi + rax*4], 0  ; check if arr[i] == 0
    //   je .found          ; if zero, found it
    //   inc eax            ; i++
    //   jmp .loop          ; continue
    // .found:
    //   ret                ; return i
    // .not_found:
    //   mov eax, -1        ; return -1
    //   ret
    let machine_code: Vec<u8> = vec![
        0x31, 0xc0,        // xor eax, eax
        // loop (0x1002):
        0x39, 0xf0,        // cmp eax, esi
        0x7d, 0x09,        // jge +9 (to 0x1010)
        0x83, 0x3c, 0x87, 0x00,  // cmp DWORD PTR [rdi+rax*4], 0
        0x74, 0x05,        // je +5 (to 0x100f)
        0xff, 0xc0,        // inc eax
        0xeb, 0xf3,        // jmp -13 (to 0x1002)
        // found (0x100f):
        0xc3,              // ret
        // not_found (0x1010):
        0xb8, 0xff, 0xff, 0xff, 0xff,  // mov eax, -1
        0xc3,              // ret
    ];

    println!("Machine code: {:02x?}", machine_code);
    println!();

    let mut disasm = X86_64Disassembler::new();
    let instructions = disasm.disassemble(&machine_code, Address::new(0x1000))?;

    println!("Disassembly:");
    for instr in &instructions {
        println!("  {}", instr);
    }
    println!();

    let translator = X86_64Translator::new();
    let mut program = Program::with_entry_point(Address::new(0x1000));

    for instr in &instructions {
        let pcode_ops = translator.translate(instr)?;
        for op in pcode_ops {
            program.add_operation(op);
        }
    }

    let cfg = ControlFlowGraph::from_program(&program)?;

    println!("Control Flow Analysis:");
    println!("  Total blocks: {}", cfg.block_count());

    let loops = cfg.detect_loops();
    let conditionals = cfg.identify_conditionals();

    println!("  Loops: {}", loops.len());
    println!("  Conditionals: {}", conditionals.len());
    println!();

    println!("Loop structure:");
    for loop_info in &loops {
        println!("  Loop with {} blocks, type={:?}", loop_info.body.len(), loop_info.loop_type);
        println!("  Contains conditional branches for loop exit and break");
    }
    println!();

    let analysis = analyze_function(&mut program, None)?;
    let c_code = generate_c_code(&analysis, &program, None)?;

    println!("Generated C code:");
    println!("{}", c_code);

    Ok(())
}
