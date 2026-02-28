//! P-code Intermediate Representation
//!
//! This module implements Ghidra-inspired P-code, a register transfer language (RTL)
//! used as the intermediate representation for decompilation.
//!
//! P-code represents low-level operations in a generic, architecture-independent way,
//! making it easier to analyze and transform machine code from different architectures.
//!
//! # Architecture
//!
//! ```text
//! Machine Code → P-code Operations → SSA Form → High-level IR → C Code
//! ```
//!
//! # P-code Operations
//!
//! P-code consists of a small set of operations that can represent any machine instruction:
//!
//! - **Data Movement**: COPY, LOAD, STORE
//! - **Arithmetic**: INT_ADD, INT_SUB, INT_MULT, INT_DIV, etc.
//! - **Logical**: INT_AND, INT_OR, INT_XOR, INT_NOT
//! - **Comparison**: INT_EQUAL, INT_LESS, INT_SLESS, etc.
//! - **Control Flow**: BRANCH, CBRANCH, CALL, RETURN
//! - **Type Conversion**: INT_ZEXT, INT_SEXT, TRUNC, etc.
//!
//! # Example
//!
//! x86: `add eax, ebx` might translate to:
//! ```text
//! $U10:4 = INT_ADD eax:4, ebx:4
//! eax:4 = COPY $U10:4
//! ZF:1 = INT_EQUAL $U10:4, 0:4
//! SF:1 = INT_SLESS $U10:4, 0:4
//! ```

mod program;

// Varnode and Op are now top-level modules (corresponds to Ghidra's varnode.hh and op.hh)
pub use crate::varnode::*;
pub use crate::op::*;
pub use program::*;

use crate::address::Address;
// Re-export for backwards compatibility and convenience
pub use crate::address::SeqNum;
pub use crate::space::AddressSpace;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for a P-code operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PcodeId(u64);

impl PcodeId {
    /// Create a new P-code ID
    pub const fn new(id: u64) -> Self {
        PcodeId(id)
    }

    /// Get the raw ID value
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Get the next ID
    pub fn next(&self) -> Self {
        PcodeId(self.0 + 1)
    }
}

impl fmt::Display for PcodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

// AddressSpace is now defined in src/space.rs (corresponds to Ghidra's space.hh)
// Re-exported above

// SeqNum is now defined in src/address.rs (corresponds to Ghidra's address.hh)
// Re-exported above

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcode_id() {
        let id = PcodeId::new(42);
        assert_eq!(id.as_u64(), 42);
        assert_eq!(id.next().as_u64(), 43);
    }

    #[test]
    fn test_address_space() {
        assert!(AddressSpace::Register.is_register());
        assert!(AddressSpace::Unique.is_unique());
        assert!(AddressSpace::Const.is_const());
        assert!(AddressSpace::Ram.is_ram());
    }

    #[test]
    fn test_seqnum() {
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let next = seq.next();
        assert_eq!(next.addr, Address::new(0x1000));
        assert_eq!(next.order, 1);
    }

    #[test]
    fn test_address_space_display() {
        assert_eq!(AddressSpace::Ram.to_string(), "ram");
        assert_eq!(AddressSpace::Register.to_string(), "register");
        assert_eq!(AddressSpace::Unique.to_string(), "unique");
        assert_eq!(AddressSpace::Const.to_string(), "const");
    }
}
