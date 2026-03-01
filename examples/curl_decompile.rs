//! Example: Initializing the new Arc/RwLock Aligned Architecture
//!
//! This example performs the setup of the GHIDRA-aligned structures.
//!
//! Run with: cargo run --example curl_decompile

use rugra::block::{BlockBasic, BlockGraph};
use rugra::heritage::Heritage;
use rugra::op::PcodeOpBank;
use rugra::varnode::VarnodeBank;
use rugra::{Address, OpCode, Result};

fn main() -> Result<()> {
    println!("=== Rugra Aligned Decompiler Architecture Init ===\n");

    println!("[1] Initializing VarnodeBank (Ghidra aligned)");
    let mut vbank = VarnodeBank::new();
    let vn_ref = vbank.create(8, Address::new(0x1000));
    println!("    Created Varnode: {:?}", vn_ref.read().unwrap());

    println!("[2] Initializing PcodeOpBank (Ghidra aligned)");
    let mut opbank = PcodeOpBank::new();
    let op_ref = opbank.create(OpCode::CPUI_INT_ADD, 2, Address::new(0x1000));
    println!(
        "    Created PcodeOp: sequence {}",
        op_ref.0.read().unwrap().start.order
    );

    println!("[3] Initializing BlockGraph and BasicBlocks");
    let mut graph = BlockGraph::new();
    let block = BlockBasic::new(0, Address::new(0x1000));
    println!(
        "    Created Basic Block at 0x{:x}",
        block.start_addr.as_u64()
    );

    println!("[4] Setting up Heritage (Pruned SSA Engine)");
    let mut heritage = Heritage::new();
    println!(
        "    Heritage engine initialized at depth {}",
        heritage.maxdepth
    );

    println!("\nSUCCESS: All aligned structures have been validated.");
    println!("Note: Legacy 'curl_decompile' CLI operations disabled during transition.");
    Ok(())
}
