//! Variable Recovery and Type Inference Demo
//!
//! This example demonstrates Rugra's ability to recover variables and infer types
//! from machine code, including:
//! - Stack variable detection
//! - Function parameter identification
//! - Register variable tracking
//! - Type inference from operations
//! - Pointer detection

use rugra::{
    Address, Result,
    disasm::{Disassembler, X86_64Disassembler},
    translator::{Translator, X86_64Translator},
    pcode::Program,
    analysis::analyze_function,
};

fn main() -> Result<()> {
    println!("=== Rugra Variable Recovery and Type Inference Demo ===\n");

    // Example 1: Simple function with parameters
    println!("Example 1: Function Parameters");
    println!("================================");
    demonstrate_parameters()?;

    println!("\n");

    // Example 2: Stack variables
    println!("Example 2: Stack Variables");
    println!("==========================");
    demonstrate_stack_variables()?;

    println!("\n");

    // Example 3: Pointer detection
    println!("Example 3: Pointer Detection");
    println!("============================");
    demonstrate_pointers()?;

    println!("\n");

    // Example 4: Type inference
    println!("Example 4: Type Inference");
    println!("=========================");
    demonstrate_type_inference()?;

    Ok(())
}

/// Demonstrate parameter detection
///
/// C equivalent:
/// ```c
/// int add(int a, int b) {
///     return a + b;
/// }
/// ```
fn demonstrate_parameters() -> Result<()> {
    // x86-64 assembly (System V ABI):
    //   mov eax, edi       ; a is in edi (first parameter)
    //   add eax, esi       ; b is in esi (second parameter)
    //   ret
    let machine_code: Vec<u8> = vec![
        0x89, 0xf8,        // mov eax, edi
        0x01, 0xf0,        // add eax, esi
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

    // Translate to P-code
    let translator = X86_64Translator::new();
    let mut program = Program::with_entry_point(Address::new(0x1000));

    for instr in &instructions {
        let pcode_ops = translator.translate(instr)?;
        for op in pcode_ops {
            program.add_operation(op);
        }
    }

    // Analyze
    let analysis = analyze_function(&mut program, None)?;

    // Show variable analysis
    if let Some(var_analysis) = &analysis.variables {
        println!("Variable Analysis:");
        println!("  Total variables: {}", var_analysis.variables.len());
        println!("  Parameters: {}", var_analysis.parameters.len());
        println!("  Locals: {}", var_analysis.locals.len());
        println!();

        println!("Parameters:");
        for &param_id in &var_analysis.parameters {
            if let Some(var) = var_analysis.get_variable(param_id) {
                println!("  {} ({}): {:?}, size={}",
                    var.name,
                    param_id,
                    var.storage,
                    var.size
                );
                if let Some(type_hint) = &var.type_hint {
                    println!("    Type hint: {}", type_hint);
                }
            }
        }
    }

    Ok(())
}

/// Demonstrate stack variable detection
///
/// C equivalent:
/// ```c
/// int sum_local(int n) {
///     int sum = 0;
///     int i = 0;
///     while (i < n) {
///         sum += i;
///         i++;
///     }
///     return sum;
/// }
/// ```
fn demonstrate_stack_variables() -> Result<()> {
    // x86-64 assembly with stack variables:
    //   push rbp
    //   mov rbp, rsp
    //   sub rsp, 16          ; allocate stack space
    //   mov DWORD PTR [rbp-4], 0    ; sum = 0
    //   mov DWORD PTR [rbp-8], 0    ; i = 0
    //   jmp .check
    // .loop:
    //   mov eax, [rbp-8]     ; load i
    //   add [rbp-4], eax     ; sum += i
    //   inc DWORD PTR [rbp-8]; i++
    // .check:
    //   mov eax, [rbp-8]
    //   cmp eax, edi         ; compare i and n
    //   jl .loop
    //   mov eax, [rbp-4]     ; return sum
    //   leave
    //   ret
    let machine_code: Vec<u8> = vec![
        0x55,                    // push rbp
        0x48, 0x89, 0xe5,        // mov rbp, rsp
        0x48, 0x83, 0xec, 0x10,  // sub rsp, 16
        0xc7, 0x45, 0xfc, 0x00, 0x00, 0x00, 0x00,  // mov DWORD PTR [rbp-4], 0
        0xc7, 0x45, 0xf8, 0x00, 0x00, 0x00, 0x00,  // mov DWORD PTR [rbp-8], 0
        0xeb, 0x0a,              // jmp +10
        // loop (0x101a):
        0x8b, 0x45, 0xf8,        // mov eax, [rbp-8]
        0x01, 0x45, 0xfc,        // add [rbp-4], eax
        0xff, 0x45, 0xf8,        // inc DWORD PTR [rbp-8]
        // check (0x1024):
        0x8b, 0x45, 0xf8,        // mov eax, [rbp-8]
        0x39, 0xf8,              // cmp eax, edi
        0x7c, 0xf1,              // jl -15 (to loop)
        0x8b, 0x45, 0xfc,        // mov eax, [rbp-4]
        0xc9,                    // leave
        0xc3,                    // ret
    ];

    println!("Machine code: {} bytes", machine_code.len());
    println!();

    // Process
    let mut disasm = X86_64Disassembler::new();
    let instructions = disasm.disassemble(&machine_code, Address::new(0x1000))?;

    println!("Disassembly ({} instructions):", instructions.len());
    for (i, instr) in instructions.iter().take(10).enumerate() {
        println!("  {:2}. {}", i, instr);
    }
    if instructions.len() > 10 {
        println!("  ... ({} more instructions)", instructions.len() - 10);
    }
    println!();

    // Translate
    let translator = X86_64Translator::new();
    let mut program = Program::with_entry_point(Address::new(0x1000));

    for instr in &instructions {
        let pcode_ops = translator.translate(instr)?;
        for op in pcode_ops {
            program.add_operation(op);
        }
    }

    // Analyze
    let analysis = analyze_function(&mut program, None)?;

    // Show variable analysis
    if let Some(var_analysis) = &analysis.variables {
        println!("Variable Analysis:");
        println!("  Total variables: {}", var_analysis.variables.len());
        println!("  Parameters: {}", var_analysis.parameters.len());
        println!("  Local variables: {}", var_analysis.locals.len());

        if let Some(frame_size) = var_analysis.stack_frame_size {
            println!("  Stack frame size: {} bytes", frame_size);
        }
        println!();

        println!("Local Variables:");
        for &local_id in &var_analysis.locals {
            if let Some(var) = var_analysis.get_variable(local_id) {
                println!("  {} ({:?}):", var.name, var.storage);
                println!("    Size: {} bytes", var.size);
                if let Some(type_hint) = &var.type_hint {
                    println!("    Type: {}", type_hint);
                }
                if let Some(first_use) = var.first_use {
                    println!("    First use: 0x{:x}", first_use.as_u64());
                }
                if let Some(last_use) = var.last_use {
                    println!("    Last use: 0x{:x}", last_use.as_u64());
                }
            }
        }
    }

    Ok(())
}

/// Demonstrate pointer detection
///
/// C equivalent:
/// ```c
/// void set_value(int *ptr, int value) {
///     *ptr = value;
/// }
/// ```
fn demonstrate_pointers() -> Result<()> {
    // x86-64 assembly:
    //   mov [rdi], esi     ; *ptr = value
    //   ret
    let machine_code: Vec<u8> = vec![
        0x89, 0x37,        // mov [rdi], esi
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

    // Translate
    let translator = X86_64Translator::new();
    let mut program = Program::with_entry_point(Address::new(0x1000));

    for instr in &instructions {
        let pcode_ops = translator.translate(instr)?;
        for op in pcode_ops {
            program.add_operation(op);
        }
    }

    println!("P-code: {} operations", program.operation_count());
    for op in program.operations() {
        println!("  {}", op);
    }
    println!();

    // Analyze
    let analysis = analyze_function(&mut program, None)?;

    // Show type inference
    if let Some(type_analysis) = &analysis.type_inference {
        println!("Type Inference:");
        println!("  Inferred types: {}", type_analysis.varnode_types.len());
        println!("  Detected pointers: {}", type_analysis.pointers.len());
        println!();

        if !type_analysis.pointers.is_empty() {
            println!("Pointers:");
            for ptr in &type_analysis.pointers {
                println!("  {}", ptr);
                if let Some(inferred_type) = type_analysis.get_type(ptr) {
                    println!("    Type: {:?}", inferred_type.kind);
                    println!("    Confidence: {}%", inferred_type.confidence);
                    println!("    Source: {:?}", inferred_type.source);
                }
            }
        }
    }

    Ok(())
}

/// Demonstrate type inference
///
/// C equivalent:
/// ```c
/// bool is_equal(int a, int b) {
///     return a == b;
/// }
/// ```
fn demonstrate_type_inference() -> Result<()> {
    // x86-64 assembly:
    //   cmp edi, esi
    //   sete al          ; set al to 1 if equal
    //   movzx eax, al    ; zero-extend to 32-bit
    //   ret
    let machine_code: Vec<u8> = vec![
        0x39, 0xf7,        // cmp edi, esi
        0x0f, 0x94, 0xc0,  // sete al
        0x0f, 0xb6, 0xc0,  // movzx eax, al
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

    // Translate
    let translator = X86_64Translator::new();
    let mut program = Program::with_entry_point(Address::new(0x1000));

    for instr in &instructions {
        let pcode_ops = translator.translate(instr)?;
        for op in pcode_ops {
            program.add_operation(op);
        }
    }

    // Analyze
    let analysis = analyze_function(&mut program, None)?;

    // Show all analysis results
    println!("Complete Analysis Results:");
    println!("==========================");
    println!();

    // Variables
    if let Some(var_analysis) = &analysis.variables {
        println!("Variables: {}", var_analysis.variables.len());
        for (i, var) in var_analysis.variables.iter().enumerate() {
            println!("  {}: {} ({:?}, {} bytes)", i, var.name, var.storage, var.size);
        }
        println!();
    }

    // Type inference
    if let Some(type_analysis) = &analysis.type_inference {
        println!("Type Inference:");
        println!("  Total inferred types: {}", type_analysis.varnode_types.len());
        println!();

        // Show some inferred types
        let mut count = 0;
        for (varnode_key, inferred_type) in &type_analysis.varnode_types {
            if count >= 5 {
                println!("  ... ({} more types)", type_analysis.varnode_types.len() - 5);
                break;
            }
            println!("  {}:", varnode_key);
            println!("    Type: {:?}", inferred_type.kind);
            println!("    Confidence: {}%", inferred_type.confidence);
            println!("    Source: {:?}", inferred_type.source);
            count += 1;
        }
    }

    // CFG
    if let Some(cfg) = &analysis.cfg {
        println!();
        println!("Control Flow:");
        println!("  Blocks: {}", cfg.block_count());
        println!("  Entry: {}", cfg.entry);
        println!("  Exits: {:?}", cfg.exits);
    }

    Ok(())
}
