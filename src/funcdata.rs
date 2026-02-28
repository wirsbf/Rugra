//! High-level function data container
//!
//! Corresponds to Ghidra's `funcdata.hh`

use crate::address::Address;
use crate::varnode::VarnodeBank;
use crate::op::PcodeOpBank;
use crate::block::BlockGraph;
use crate::heritage::Heritage;
use std::sync::{Arc, RwLock, Weak};

/// Main container for a function being decompiled
///
/// Corresponds to Ghidra's `Funcdata` class. This class ties together
/// the P-code operations, varnodes, control flow graph, and analysis state.
#[derive(Debug)]
pub struct Funcdata {
    /// Name of the function
    pub name: String,
    /// Base address of the function
    pub baseaddr: Address,
    /// Size of the function in bytes
    pub size: i32,

    /// Bank of all varnodes in this function
    pub vbank: VarnodeBank,
    /// Bank of all P-code operations in this function
    pub obank: PcodeOpBank,
    /// Control flow graph (basic blocks)
    pub bblocks: BlockGraph,
    /// Structure tree (composite blocks)
    pub sblocks: BlockGraph,
    /// SSA construction manager
    pub heritage: Heritage,

    /// Self-reference for use by child components
    pub self_ref: Option<Weak<RwLock<Funcdata>>>,
}

impl Funcdata {
    /// Create a new Funcdata instance
    pub fn new(name: &str, addr: Address, size: i32) -> Self {
        Self {
            name: name.to_string(),
            baseaddr: addr,
            size,
            vbank: VarnodeBank::new(),
            obank: PcodeOpBank::new(),
            bblocks: BlockGraph::new(),
            sblocks: BlockGraph::new(),
            heritage: Heritage::new(),
            self_ref: None,
        }
    }

    /// Set the self-reference after wrapping in Arc<RwLock>
    pub fn set_self_ref(&mut self, self_ref: Weak<RwLock<Funcdata>>) {
        self.self_ref = Some(self_ref.clone());
        self.heritage.fd = Some(self_ref);
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_address(&self) -> &Address {
        &self.baseaddr
    }

    pub fn get_size(&self) -> i32 {
        self.size
    }

    /// Clear all analysis state
    pub fn clear(&mut self) {
        self.vbank.clear();
        self.obank.clear();
        self.bblocks.clear();
        self.sblocks.clear();
        self.heritage.clear();
    }

    pub fn num_heritage_passes(&self) -> i32 {
        self.heritage.get_pass()
    }
}
