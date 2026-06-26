//! P-code injection engine.
//!
//! Corresponds to Ghidra's `pcodeinject.hh` / `pcodeinject.cc` (638 lines).
//!
//! P-code injection allows substituting user-defined p-code templates for
//! specific operations (CALL fixups, CALLOTHER fixups, call mechanism patches).
//!
//! Key classes:
//! - `InjectParameter`: an input/output parameter to an injection payload
//! - `InjectContext`: context for resolving placeholders during injection
//! - `InjectPayload`: a container for injectable p-code operations
//! - `PcodeInjectLibrary`: manager for all injection payloads
//!
//! # Status
//! Core data structures (InjectParameter, InjectContext, InjectPayload
//! types, PcodeInjectLibrary skeleton). The full inject() method requires
//! PcodeEmit integration.

use std::collections::HashMap;

/// An input or output parameter to a p-code injection payload.
/// Corresponds to Ghidra's `InjectParameter` (pcodeinject.hh:55).
#[derive(Debug, Clone)]
pub struct InjectParameter {
    /// Name of the parameter
    pub name: String,
    /// Unique index for cross-referencing
    pub index: i32,
    /// Size of the parameter Varnode in bytes
    pub size: u32,
}

impl InjectParameter {
    pub fn new(name: String, size: u32) -> Self {
        Self { name, index: 0, size }
    }
}

/// Injection payload types.
/// Corresponds to Ghidra's `InjectPayload` enum (pcodeinject.hh:103).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InjectPayloadType {
    /// Injection that replaces a CALL
    CallFixup = 1,
    /// Injection that replaces a user-defined p-code op (CALLOTHER)
    CallOtherFixup = 2,
    /// Injection to patch up data-flow around the caller/callee boundary
    CallMechanism = 3,
    /// Injection running as a stand-alone p-code script
    ExecutablePcode = 4,
}

/// A container for a set of p-code operations that can be injected.
/// Corresponds to Ghidra's `InjectPayload` (pcodeinject.hh:101).
#[derive(Debug, Clone)]
pub struct InjectPayload {
    /// Formal name of the payload
    pub name: String,
    /// Type of this payload
    pub payload_type: InjectPayloadType,
    /// True if the injection is generated dynamically
    pub dynamic: bool,
    /// True if injected COPYs are considered incidental
    pub incidental_copy: bool,
    /// Number of parameters shifted in the original call
    pub paramshift: i32,
    /// List of input parameters
    pub input_list: Vec<InjectParameter>,
    /// List of output parameters
    pub output: Vec<InjectParameter>,
}

impl InjectPayload {
    pub fn new(name: String, payload_type: InjectPayloadType) -> Self {
        Self {
            name,
            payload_type,
            dynamic: false,
            incidental_copy: false,
            paramshift: 0,
            input_list: Vec::new(),
            output: Vec::new(),
        }
    }

    pub fn get_paramshift(&self) -> i32 { self.paramshift }
    pub fn is_dynamic(&self) -> bool { self.dynamic }
    pub fn is_incidental_copy(&self) -> bool { self.incidental_copy }
    pub fn size_input(&self) -> usize { self.input_list.len() }
    pub fn size_output(&self) -> usize { self.output.len() }
}

/// Manager for all injection payloads.
/// Corresponds to Ghidra's `PcodeInjectLibrary` (pcodeinject.hh).
pub struct PcodeInjectLibrary {
    /// All registered payloads by name
    pub payloads: HashMap<String, InjectPayload>,
    /// Map from injection name to numeric id
    pub name_to_id: HashMap<String, i32>,
    /// Next available id
    next_id: i32,
}

impl PcodeInjectLibrary {
    pub fn new() -> Self {
        Self {
            payloads: HashMap::new(),
            name_to_id: HashMap::new(),
            next_id: 0,
        }
    }

    /// Register a payload, returning its numeric id.
    pub fn register_payload(&mut self, payload: InjectPayload) -> i32 {
        let id = self.next_id;
        self.next_id += 1;
        self.name_to_id.insert(payload.name.clone(), id);
        self.payloads.insert(payload.name.clone(), payload);
        id
    }

    /// Get a payload by name.
    pub fn get_payload(&self, name: &str) -> Option<&InjectPayload> {
        self.payloads.get(name)
    }

    /// Get a payload id by name.
    pub fn get_id(&self, name: &str) -> Option<i32> {
        self.name_to_id.get(name).copied()
    }

    /// Get the number of registered payloads.
    pub fn num_payloads(&self) -> usize { self.payloads.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inject_parameter() {
        let p = InjectParameter::new("input0".into(), 4);
        assert_eq!(p.name, "input0");
        assert_eq!(p.size, 4);
    }

    #[test]
    fn test_inject_payload() {
        let mut p = InjectPayload::new("my_fixup".into(), InjectPayloadType::CallFixup);
        p.input_list.push(InjectParameter::new("in".into(), 8));
        assert_eq!(p.size_input(), 1);
        assert_eq!(p.payload_type, InjectPayloadType::CallFixup);
    }

    #[test]
    fn test_pcode_inject_library() {
        let mut lib = PcodeInjectLibrary::new();
        let p = InjectPayload::new("test".into(), InjectPayloadType::CallOtherFixup);
        let id = lib.register_payload(p);
        assert_eq!(id, 0);
        assert!(lib.get_payload("test").is_some());
        assert_eq!(lib.get_id("test"), Some(0));
    }
}
