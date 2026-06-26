//! Function signature matching for identifying known library functions.
//!
//! Corresponds to Ghidra's `signature.hh` / `signature.cc` (1505 lines).
//!
//! The signature system hashes data-flow features of a function and
//! compares them against a database of known function signatures to
//! identify standard library calls.
//!
//! Key classes:
//! - `Signature`: a single 32-bit feature hash
//! - `SignatureEntry`: a node for data-flow feature generation
//! - `SignatureDB`: collection of known signatures for matching
//!
//! # Status
//! Core data structures (Signature, SignatureEntry, SignatureDB skeleton).
//! The full feature generation algorithm (iterative hashing over data-flow
//! graph) is deferred.

use std::collections::HashMap;

/// A feature describing some aspect of a function.
/// Corresponds to Ghidra's `Signature` (signature.hh:50).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Signature {
    /// Underlying 32-bit hash
    pub hash: u32,
}

impl Signature {
    pub fn new(hash: u32) -> Self { Self { hash } }
    pub fn get_hash(&self) -> u32 { self.hash }
}

/// Varnode properties for feature generation.
/// Corresponds to Ghidra's `SignatureEntry::SignatureFlags`.
#[derive(Debug, Clone, Copy)]
pub struct SignatureFlags {
    pub terminal: bool,
    pub commutative: bool,
    pub not_emitted: bool,
    pub standalone: bool,
    pub visited: bool,
}

impl Default for SignatureFlags {
    fn default() -> Self {
        Self { terminal: false, commutative: false, not_emitted: false, standalone: false, visited: false }
    }
}

/// A node for data-flow feature generation.
/// Corresponds to Ghidra's `SignatureEntry` (signature.hh:78).
#[derive(Debug, Clone)]
pub struct SignatureEntry {
    /// Current and previous hash values
    pub hash: [u32; 2],
    /// Feature generation properties
    pub flags: SignatureFlags,
    /// Post-order index
    pub index: i32,
}

impl SignatureEntry {
    pub fn new() -> Self {
        Self { hash: [0, 0], flags: SignatureFlags::default(), index: -1 }
    }

    /// Check if this node has been visited.
    pub fn is_visited(&self) -> bool { self.flags.visited }

    /// Mark that this node has been visited.
    pub fn set_visited(&mut self) { self.flags.visited = true; }

    /// Set the current hash.
    pub fn set_hash(&mut self, h: u32) {
        self.hash[1] = self.hash[0];
        self.hash[0] = h;
    }

    /// Get the current hash.
    pub fn get_current_hash(&self) -> u32 { self.hash[0] }

    /// Get the previous hash.
    pub fn get_previous_hash(&self) -> u32 { self.hash[1] }

    /// Check if the hash changed in the last iteration.
    pub fn hash_changed(&self) -> bool { self.hash[0] != self.hash[1] }
}

/// Hash a single opcode for feature generation.
/// Corresponds to Ghidra's `SignatureEntry::getOpHash`.
pub fn hash_opcode(opc: crate::opcodes::OpCode, modifiers: u32) -> u32 {
    let base = opc as u32;
    base.wrapping_mul(0x01000193).wrapping_add(modifiers)
}

/// Combine two hashes using Ghidra's mixing function.
pub fn combine_hashes(a: u32, b: u32) -> u32 {
    a.rotate_left(5) ^ b.wrapping_mul(31)
}

/// Generate a feature signature from a simple opcode sequence.
/// This is a simplified version of Ghidra's iterative feature generation.
pub fn generate_features(opcodes: &[crate::opcodes::OpCode]) -> Vec<Signature> {
    if opcodes.is_empty() { return Vec::new(); }
    let mut result = Vec::new();
    let mut current_hash = 0u32;
    for &opc in opcodes {
        current_hash = combine_hashes(current_hash, hash_opcode(opc, 0));
        result.push(Signature::new(current_hash));
    }
    result
}

/// A database of known function signatures.
/// Corresponds to Ghidra's `SignatureDB`.
pub struct SignatureDB {
    /// Known signatures by function name
    pub signatures: HashMap<String, Vec<Signature>>,
    /// Map from hash to function name(s)
    pub hash_index: HashMap<u32, Vec<String>>,
}

impl SignatureDB {
    pub fn new() -> Self {
        Self { signatures: HashMap::new(), hash_index: HashMap::new() }
    }

    /// Register a set of signatures for a named function.
    pub fn register_function(&mut self, name: String, sigs: Vec<Signature>) {
        for sig in &sigs {
            self.hash_index.entry(sig.hash).or_default().push(name.clone());
        }
        self.signatures.insert(name, sigs);
    }

    /// Look up function name(s) by a single signature hash.
    pub fn lookup_hash(&self, hash: u32) -> &[String] {
        self.hash_index.get(&hash).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get the number of registered functions.
    pub fn num_functions(&self) -> usize { self.signatures.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_basic() {
        let s = Signature::new(0xdeadbeef);
        assert_eq!(s.get_hash(), 0xdeadbeef);
    }

    #[test]
    fn test_signature_entry() {
        let mut e = SignatureEntry::new();
        assert!(!e.is_visited());
        e.set_visited();
        assert!(e.is_visited());
    }

    #[test]
    fn test_signature_db() {
        let mut db = SignatureDB::new();
        db.register_function("memcpy".into(), vec![Signature::new(0x12345678)]);
        assert_eq!(db.num_functions(), 1);
        let names = db.lookup_hash(0x12345678);
        assert_eq!(names, &["memcpy".to_string()]);
    }

    #[test]
    fn test_hash_opcode() {
        let h1 = hash_opcode(crate::opcodes::OpCode::CPUI_INT_ADD, 0);
        let h2 = hash_opcode(crate::opcodes::OpCode::CPUI_INT_SUB, 0);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_combine_hashes() {
        let a = 0x12345u32;
        let b = 0x67890u32;
        let combined = combine_hashes(a, b);
        assert_ne!(combined, a);
        assert_ne!(combined, b);
    }

    #[test]
    fn test_generate_features() {
        use crate::opcodes::OpCode;
        let ops = vec![OpCode::CPUI_INT_ADD, OpCode::CPUI_INT_MULT, OpCode::CPUI_COPY];
        let sigs = generate_features(&ops);
        assert_eq!(sigs.len(), 3);
        // Each successive hash should be different.
        assert_ne!(sigs[0].get_hash(), sigs[1].get_hash());
        assert_ne!(sigs[1].get_hash(), sigs[2].get_hash());
    }

    #[test]
    fn test_signature_entry_hash() {
        let mut e = SignatureEntry::new();
        e.set_hash(42);
        assert_eq!(e.get_current_hash(), 42);
        assert!(e.hash_changed());
        e.set_hash(42); // Same hash again
        assert!(!e.hash_changed());
    }
}
