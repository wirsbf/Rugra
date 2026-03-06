//! Example: Decompiling curl's main function with detailed debugging
//!
//! This example performs the decompilation pipeline step-by-step to
//! identify where the process might be failing for complex binaries.
//!
//! Run with: cargo run --example curl_decompile

use rugra::{
    Address, Architecture, Result,
    disasm::{Disassembler, X86_64Disassembler},
    translator::{Translator, X86_64Translator},
    pcode::{Program},
    analysis::{analyze_function},
    codegen::generate_c_code,
    binary::Binary,
};
use std::fs;

fn main() -> Result<()> {
    println!("=== Rugra Debug Decompiler: curl main() ===\n");

    let binary_path = "rugra/examples/curl";
    let main_addr = 0x25a0;

    // 1. Read binary
    println!("[1] Reading binary: {}...", binary_path);
    let data = match fs::read(binary_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: Could not read {}: {}", binary_path, e);
            return Ok(());
        }
    };
    println!("    Binary size: {} bytes", data.len());

    let binary = Binary::parse(&data)?;
    println!("    Parsed binary format: {:?}", binary.format());

    // 2. Disassemble
    println!("\n[2] Disassembling at 0x{:x}...", main_addr);
    let mut disasm = X86_64Disassembler::new();

    let offset = main_addr as usize;
    if offset >= data.len() {
        println!("    Error: Address 0x{:x} is outside binary bounds!", main_addr);
        return Ok(());
    }

    // Attempt to disassemble a reasonable chunk of the function
    let code_limit = std::cmp::min(offset + 4096, data.len());
    let code_slice = &data[offset..code_limit];

    let instructions = disasm.disassemble(code_slice, Address::new(main_addr))?;
    println!("    Disassembled {} instructions", instructions.len());

    if instructions.is_empty() {
        println!("    Warning: No instructions found. Checking first few bytes...");
        let preview_end = std::cmp::min(offset + 16, data.len());
        println!("    Bytes at 0x{:x}: {:02x?}", main_addr, &data[offset..preview_end]);
        return Ok(());
    }

    // Print first few instructions for verification
    println!("    First few instructions:");
    for (i, instr) in instructions.iter().take(10).enumerate() {
        println!("      {:2}: 0x{:04x} | {}", i, instr.address.as_u64(), instr.text);
    }

    // 3. Translate to P-code
    println!("\n[3] Translating to P-code...");
    let translator = X86_64Translator::new();
    let mut program = Program::with_entry_point(Address::new(main_addr));

    let mut translated_count = 0;
    for instr in &instructions {
        match translator.translate(instr) {
            Ok(ops) => {
                for op in ops {
                    program.add_operation(op);
                }
                translated_count += 1;
            }
            Err(e) => {
                println!("    Warning: Translation failed for '{}' at 0x{:x}: {}", instr.text, instr.address.as_u64(), e);
            }
        }
    }
    println!("    Translated {}/{} instructions to {} P-code operations",
        translated_count, instructions.len(), program.operation_count());

    if program.operation_count() == 0 {
        println!("    Error: No P-code operations generated.");
        return Ok(());
    }

    // 4. Analysis
    println!("\n[4] Performing Analysis (CFG, SSA, Type Inference, Optimization)...");
    match analyze_function(&mut program, Some(&binary)) {
        Ok(analysis) => {
            println!("    Analysis complete.");

            if let Some(cfg) = &analysis.cfg {
                println!("    CFG Blocks: {}", cfg.blocks.len());
                for (i, block) in cfg.blocks.iter().enumerate().take(5) {
                    println!("      Block {}: index {}, addr 0x{:x}, {} ops, successors: {:?}",
                        i, block.index, block.start_addr.as_u64(), block.operations.len(), block.successors);
                }
            }

            // 5. Code Generation
            println!("\n[5] Generating C code...");
            match generate_c_code(&analysis, &program, Some(&binary)) {
                Ok(c_code) => {
                    println!("Successfully generated C code:");
                    println!("--------------------------------------------------------------------------------");
                    if c_code.trim().is_empty() {
                        println!("    (Output is empty)");
                    } else {
                        println!("{}", c_code);
                    }
                    println!("--------------------------------------------------------------------------------");
                }
                Err(e) => println!("    Error during code generation: {}", e),
            }
        }
        Err(e) => {
            println!("    Error during analysis: {}", e);
            println!("    This might be due to an edge case in SSA or CFG construction for this specific function.");
        }
    }

    println!("\nDecompilation debug session complete.");
    Ok(())
}
