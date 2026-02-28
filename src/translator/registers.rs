//! Register mapping for architecture-specific translators
//!
//! This module provides register mapping functionality to convert
//! architecture-specific register names to P-code varnodes.

use crate::pcode::Varnode;
use std::collections::HashMap;

/// Trait for register mapping
///
/// Implementers provide mappings from register names to P-code varnodes.
pub trait RegisterMap {
    /// Get a varnode for a register name
    ///
    /// # Arguments
    ///
    /// * `name` - Register name (e.g., "rax", "rbx")
    ///
    /// # Returns
    ///
    /// A varnode representing this register, or None if not found
    fn get_register(&self, name: &str) -> Option<Varnode>;

    /// Get the size of a register in bytes
    ///
    /// # Arguments
    ///
    /// * `name` - Register name
    ///
    /// # Returns
    ///
    /// Size in bytes, or None if not found
    fn get_register_size(&self, name: &str) -> Option<usize>;

    /// Check if a register name is valid
    fn has_register(&self, name: &str) -> bool {
        self.get_register(name).is_some()
    }
}

/// x86-64 register map
///
/// Maps x86-64 register names to P-code varnodes with proper offsets and sizes.
pub struct X86_64RegisterMap {
    /// Register name to (offset, size) mapping
    registers: HashMap<String, (u64, usize)>,
}

impl X86_64RegisterMap {
    /// Create a new x86-64 register map
    pub fn new() -> Self {
        let mut registers = HashMap::new();

        // 64-bit general purpose registers (8 bytes)
        registers.insert("rax".to_string(), (0, 8));
        registers.insert("rbx".to_string(), (8, 8));
        registers.insert("rcx".to_string(), (16, 8));
        registers.insert("rdx".to_string(), (24, 8));
        registers.insert("rsp".to_string(), (32, 8));
        registers.insert("rbp".to_string(), (40, 8));
        registers.insert("rsi".to_string(), (48, 8));
        registers.insert("rdi".to_string(), (56, 8));
        registers.insert("r8".to_string(), (64, 8));
        registers.insert("r9".to_string(), (72, 8));
        registers.insert("r10".to_string(), (80, 8));
        registers.insert("r11".to_string(), (88, 8));
        registers.insert("r12".to_string(), (96, 8));
        registers.insert("r13".to_string(), (104, 8));
        registers.insert("r14".to_string(), (112, 8));
        registers.insert("r15".to_string(), (120, 8));

        // 32-bit registers (4 bytes) - lower 32 bits of 64-bit registers
        registers.insert("eax".to_string(), (0, 4));
        registers.insert("ebx".to_string(), (8, 4));
        registers.insert("ecx".to_string(), (16, 4));
        registers.insert("edx".to_string(), (24, 4));
        registers.insert("esp".to_string(), (32, 4));
        registers.insert("ebp".to_string(), (40, 4));
        registers.insert("esi".to_string(), (48, 4));
        registers.insert("edi".to_string(), (56, 4));
        registers.insert("r8d".to_string(), (64, 4));
        registers.insert("r9d".to_string(), (72, 4));
        registers.insert("r10d".to_string(), (80, 4));
        registers.insert("r11d".to_string(), (88, 4));
        registers.insert("r12d".to_string(), (96, 4));
        registers.insert("r13d".to_string(), (104, 4));
        registers.insert("r14d".to_string(), (112, 4));
        registers.insert("r15d".to_string(), (120, 4));

        // 16-bit registers (2 bytes)
        registers.insert("ax".to_string(), (0, 2));
        registers.insert("bx".to_string(), (8, 2));
        registers.insert("cx".to_string(), (16, 2));
        registers.insert("dx".to_string(), (24, 2));
        registers.insert("sp".to_string(), (32, 2));
        registers.insert("bp".to_string(), (40, 2));
        registers.insert("si".to_string(), (48, 2));
        registers.insert("di".to_string(), (56, 2));

        // 8-bit registers (1 byte)
        registers.insert("al".to_string(), (0, 1));
        registers.insert("bl".to_string(), (8, 1));
        registers.insert("cl".to_string(), (16, 1));
        registers.insert("dl".to_string(), (24, 1));
        registers.insert("ah".to_string(), (1, 1)); // High byte offset
        registers.insert("bh".to_string(), (9, 1));
        registers.insert("ch".to_string(), (17, 1));
        registers.insert("dh".to_string(), (25, 1));

        // Special registers
        registers.insert("rip".to_string(), (128, 8)); // Instruction pointer
        registers.insert("eip".to_string(), (128, 4));

        // Flags (1 byte each, starting at offset 200)
        registers.insert("zf".to_string(), (200, 1));  // Zero flag
        registers.insert("sf".to_string(), (201, 1));  // Sign flag
        registers.insert("cf".to_string(), (202, 1));  // Carry flag
        registers.insert("of".to_string(), (203, 1));  // Overflow flag
        registers.insert("pf".to_string(), (204, 1));  // Parity flag
        registers.insert("af".to_string(), (205, 1));  // Auxiliary carry flag
        registers.insert("df".to_string(), (206, 1));  // Direction flag

        X86_64RegisterMap { registers }
    }

    /// Get varnode for a flag register
    pub fn get_flag(&self, flag_name: &str) -> Option<Varnode> {
        self.get_register(flag_name)
    }
}

impl Default for X86_64RegisterMap {
    fn default() -> Self {
        Self::new()
    }
}

impl RegisterMap for X86_64RegisterMap {
    fn get_register(&self, name: &str) -> Option<Varnode> {
        let name_lower = name.to_lowercase();
        self.registers
            .get(&name_lower)
            .map(|&(offset, size)| Varnode::new_register(offset, size))
    }

    fn get_register_size(&self, name: &str) -> Option<usize> {
        let name_lower = name.to_lowercase();
        self.registers.get(&name_lower).map(|&(_, size)| size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_64bit_registers() {
        let map = X86_64RegisterMap::new();

        let rax = map.get_register("rax").unwrap();
        assert_eq!(rax.offset(), 0);
        assert_eq!(rax.size(), 8);

        let rbx = map.get_register("rbx").unwrap();
        assert_eq!(rbx.offset(), 8);
        assert_eq!(rbx.size(), 8);
    }

    #[test]
    fn test_32bit_registers() {
        let map = X86_64RegisterMap::new();

        let eax = map.get_register("eax").unwrap();
        assert_eq!(eax.offset(), 0); // Same offset as rax
        assert_eq!(eax.size(), 4);   // But smaller size

        let ebx = map.get_register("ebx").unwrap();
        assert_eq!(ebx.offset(), 8);
        assert_eq!(ebx.size(), 4);
    }

    #[test]
    fn test_16bit_registers() {
        let map = X86_64RegisterMap::new();

        let ax = map.get_register("ax").unwrap();
        assert_eq!(ax.offset(), 0);
        assert_eq!(ax.size(), 2);
    }

    #[test]
    fn test_8bit_registers() {
        let map = X86_64RegisterMap::new();

        let al = map.get_register("al").unwrap();
        assert_eq!(al.offset(), 0);
        assert_eq!(al.size(), 1);

        let ah = map.get_register("ah").unwrap();
        assert_eq!(ah.offset(), 1); // High byte
        assert_eq!(ah.size(), 1);
    }

    #[test]
    fn test_flags() {
        let map = X86_64RegisterMap::new();

        let zf = map.get_flag("zf").unwrap();
        assert_eq!(zf.size(), 1);

        let sf = map.get_flag("sf").unwrap();
        assert_eq!(sf.size(), 1);

        let cf = map.get_flag("cf").unwrap();
        assert_eq!(cf.size(), 1);
    }

    #[test]
    fn test_case_insensitive() {
        let map = X86_64RegisterMap::new();

        let rax1 = map.get_register("rax").unwrap();
        let rax2 = map.get_register("RAX").unwrap();
        let rax3 = map.get_register("RaX").unwrap();

        assert_eq!(rax1, rax2);
        assert_eq!(rax2, rax3);
    }

    #[test]
    fn test_invalid_register() {
        let map = X86_64RegisterMap::new();

        assert!(map.get_register("invalid").is_none());
        assert!(!map.has_register("xyz"));
    }

    #[test]
    fn test_get_register_size() {
        let map = X86_64RegisterMap::new();

        assert_eq!(map.get_register_size("rax"), Some(8));
        assert_eq!(map.get_register_size("eax"), Some(4));
        assert_eq!(map.get_register_size("ax"), Some(2));
        assert_eq!(map.get_register_size("al"), Some(1));
        assert_eq!(map.get_register_size("invalid"), None);
    }

    #[test]
    fn test_register_overlap() {
        let map = X86_64RegisterMap::new();

        // rax, eax, ax, al should all share the same base offset
        let rax = map.get_register("rax").unwrap();
        let eax = map.get_register("eax").unwrap();
        let ax = map.get_register("ax").unwrap();
        let al = map.get_register("al").unwrap();

        assert_eq!(rax.offset(), eax.offset());
        assert_eq!(eax.offset(), ax.offset());
        assert_eq!(ax.offset(), al.offset());

        // But different sizes
        assert_eq!(rax.size(), 8);
        assert_eq!(eax.size(), 4);
        assert_eq!(ax.size(), 2);
        assert_eq!(al.size(), 1);
    }

    #[test]
    fn test_special_registers() {
        let map = X86_64RegisterMap::new();

        let rip = map.get_register("rip").unwrap();
        assert_eq!(rip.size(), 8);

        let rsp = map.get_register("rsp").unwrap();
        assert_eq!(rsp.size(), 8);

        let rbp = map.get_register("rbp").unwrap();
        assert_eq!(rbp.size(), 8);
    }
}
