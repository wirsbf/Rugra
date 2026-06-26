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
}
