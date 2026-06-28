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

    /// Add an input parameter to this payload.
    pub fn add_input(&mut self, name: String, size: u32) {
        self.input_list.push(InjectParameter::new(name, size));
    }

    /// Add an output parameter to this payload.
    pub fn add_output(&mut self, name: String, size: u32) {
        self.output.push(InjectParameter::new(name, size));
    }

    /// Get an input parameter by index.
    pub fn get_input(&self, i: usize) -> Option<&InjectParameter> {
        self.input_list.get(i)
    }

    /// Get an output parameter by index.
    pub fn get_output(&self, i: usize) -> Option<&InjectParameter> {
        self.output.get(i)
    }
}

/// Context needed to emit a p-code injection.
/// Corresponds to Ghidra's `InjectContext` (pcodeinject.hh:79).
#[derive(Debug, Clone)]
pub struct InjectContext {
    /// Address of instruction causing inject
    pub base_addr: u64,
    /// Address of following instruction
    pub next_addr: u64,
    /// If the injection is for a call, this is the address being called
    pub call_addr: u64,
    /// Input parameters (varnode space + offset + size)
    pub input_list: Vec<(u32, u64, u32)>,
    /// Output parameters
    pub output: Vec<(u32, u64, u32)>,
}

impl InjectContext {
    pub fn new() -> Self {
        Self {
            base_addr: 0,
            next_addr: 0,
            call_addr: 0,
            input_list: Vec::new(),
            output: Vec::new(),
        }
    }

    pub fn clear(&mut self) {
        self.input_list.clear();
        self.output.clear();
    }
}

/// A trait for emitting injected p-code operations.
/// Corresponds to Ghidra's `PcodeEmit` callback.
pub trait PcodeEmit {
    /// Emit a single p-code operation.
    fn dump(&mut self, addr: u64, opc: crate::opcodes::OpCode, inputs: &[(u32, u64, u32)], output: Option<(u32, u64, u32)>);
}

/// A simple in-memory p-code emitter that collects emitted ops.
pub struct PcodeEmitArray {
    /// Collected operations: (addr, opcode, inputs, output)
    pub ops: Vec<(u64, crate::opcodes::OpCode, Vec<(u32, u64, u32)>, Option<(u32, u64, u32)>)>,
}

impl PcodeEmitArray {
    pub fn new() -> Self { Self { ops: Vec::new() } }
    pub fn len(&self) -> usize { self.ops.len() }
    pub fn is_empty(&self) -> bool { self.ops.is_empty() }
}

impl PcodeEmit for PcodeEmitArray {
    fn dump(&mut self, addr: u64, opc: crate::opcodes::OpCode, inputs: &[(u32, u64, u32)], output: Option<(u32, u64, u32)>) {
        self.ops.push((addr, opc, inputs.to_vec(), output));
    }
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
    /// Call fixup name → inject id (pcodeinject.cc:220)
    pub call_fixups: HashMap<String, i32>,
    /// CALLOTHER fixup name → inject id (pcodeinject.cc:236)
    pub call_other_fixups: HashMap<String, i32>,
    /// Call mechanism name → inject id (pcodeinject.cc:252)
    pub call_mechanisms: HashMap<String, i32>,
}

impl PcodeInjectLibrary {
    pub fn new() -> Self {
        Self {
            payloads: HashMap::new(),
            name_to_id: HashMap::new(),
            next_id: 0,
            call_fixups: HashMap::new(),
            call_other_fixups: HashMap::new(),
            call_mechanisms: HashMap::new(),
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

    /// Register a call fixup payload and return its inject id.
    /// Faithful to Ghidra PcodeInjectLibrary::registerCallFixup (pcodeinject.cc:220).
    pub fn register_call_fixup(&mut self, fixup_name: &str, payload: InjectPayload) -> i32 {
        let id = self.register_payload(payload);
        self.call_fixups.insert(fixup_name.to_string(), id);
        id
    }

    /// Register a CALLOTHER fixup payload and return its inject id.
    /// Faithful to Ghidra PcodeInjectLibrary::registerCallOtherFixup (pcodeinject.cc:236).
    pub fn register_call_other_fixup(&mut self, fixup_name: &str, payload: InjectPayload) -> i32 {
        let id = self.register_payload(payload);
        self.call_other_fixups.insert(fixup_name.to_string(), id);
        id
    }

    /// Register a call mechanism payload and return its inject id.
    /// Faithful to Ghidra PcodeInjectLibrary::registerCallMechanism (pcodeinject.cc:252).
    pub fn register_call_mechanism(&mut self, fixup_name: &str, payload: InjectPayload) -> i32 {
        let id = self.register_payload(payload);
        self.call_mechanisms.insert(fixup_name.to_string(), id);
        id
    }

    /// Get the payload id for a given type and name.
    /// Faithful to Ghidra PcodeInjectLibrary::getPayloadId (pcodeinject.cc:285).
    pub fn get_payload_id(&self, inject_type: InjectPayloadType, nm: &str) -> Option<i32> {
        match inject_type {
            InjectPayloadType::CallFixup => self.call_fixups.get(nm).copied(),
            InjectPayloadType::CallOtherFixup => self.call_other_fixups.get(nm).copied(),
            InjectPayloadType::CallMechanism => self.call_mechanisms.get(nm).copied(),
            _ => None,
        }
    }
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

    #[test]
    fn test_inject_context() {
        let mut ctx = InjectContext::new();
        ctx.base_addr = 0x1000;
        ctx.call_addr = 0x2000;
        ctx.input_list.push((1, 0x100, 4));
        assert_eq!(ctx.input_list.len(), 1);
        ctx.clear();
        assert!(ctx.input_list.is_empty());
    }

    #[test]
    fn test_pcode_emit_array() {
        let mut emit = PcodeEmitArray::new();
        use crate::opcodes::OpCode;
        emit.dump(0x1000, OpCode::CPUI_COPY, &[(1, 0x200, 4)], Some((1, 0x300, 4)));
        assert_eq!(emit.len(), 1);
        assert_eq!(emit.ops[0].1, OpCode::CPUI_COPY);
    }

    #[test]
    fn test_payload_add_params() {
        let mut p = InjectPayload::new("test".into(), InjectPayloadType::CallFixup);
        p.add_input("in0".into(), 8);
        p.add_output("out0".into(), 8);
        assert_eq!(p.size_input(), 1);
        assert_eq!(p.size_output(), 1);
        assert_eq!(p.get_input(0).unwrap().name, "in0");
    }

    #[test]
    fn test_register_call_fixup() {
        let mut lib = PcodeInjectLibrary::new();
        let p = InjectPayload::new("memcpy_fixup".into(), InjectPayloadType::CallFixup);
        let id = lib.register_call_fixup("memcpy", p);
        assert_eq!(lib.get_payload_id(InjectPayloadType::CallFixup, "memcpy"), Some(id));
    }

    #[test]
    fn test_register_call_other_fixup() {
        let mut lib = PcodeInjectLibrary::new();
        let p = InjectPayload::new("other_fixup".into(), InjectPayloadType::CallOtherFixup);
        let id = lib.register_call_other_fixup("myop", p);
        assert_eq!(lib.get_payload_id(InjectPayloadType::CallOtherFixup, "myop"), Some(id));
    }

    #[test]
    fn test_register_call_mechanism() {
        let mut lib = PcodeInjectLibrary::new();
        let p = InjectPayload::new("callmech".into(), InjectPayloadType::CallMechanism);
        let id = lib.register_call_mechanism("__thunk", p);
        assert_eq!(lib.get_payload_id(InjectPayloadType::CallMechanism, "__thunk"), Some(id));
    }
}
