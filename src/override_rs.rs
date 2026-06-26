//! Override commands — faithful port of `override.hh` / `override.cc` (435 lines).
//!
//! A container of commands that override the decompiler's default behavior for
//! a single function. Information about a particular function that can be
//! overridden includes:
//!   - sub-functions: how they are called and where they call to
//!   - jumptables:    mark indirect jumps that need multistage analysis
//!   - deadcode:      details about how dead code is eliminated
//!   - data-flow:     override the interpretation of specific branch instructions
//!
//! Commands exist independently of the main data-flow, control-flow, and symbol
//! structures and survive decompilation restart.
//!
//! Ghidra reference: ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/override.{hh,cc}.

use crate::address::Address;
use std::collections::BTreeMap;

/// Flow-override type enumeration. Faithful to `Override` enum
/// (override.hh:53).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowOverride {
    /// No override.
    None = 0,
    /// Replace primary CALL or RETURN with suitable BRANCH operation.
    Branch = 1,
    /// Replace primary BRANCH or RETURN with suitable CALL operation.
    Call = 2,
    /// Replace primary BRANCH or RETURN with suitable CALL/RETURN operation.
    CallReturn = 3,
    /// Replace primary BRANCH or CALL with a suitable RETURN operation.
    Return = 4,
}

impl FlowOverride {
    /// Convert a flow-override type to its string name. Faithful to
    /// `Override::typeToString` (override.cc:405).
    pub fn to_string(self) -> &'static str {
        match self {
            FlowOverride::Branch => "branch",
            FlowOverride::Call => "call",
            FlowOverride::CallReturn => "callreturn",
            FlowOverride::Return => "return",
            FlowOverride::None => "none",
        }
    }

    /// Convert a string name to a flow-override type. Faithful to
    /// `Override::stringToType` (override.cc:421).
    pub fn from_string(nm: &str) -> Self {
        match nm {
            "branch" => FlowOverride::Branch,
            "call" => FlowOverride::Call,
            "callreturn" => FlowOverride::CallReturn,
            "return" => FlowOverride::Return,
            _ => FlowOverride::None,
        }
    }
}

/// A container of commands that override the decompiler's default behavior
/// for a single function. Faithful to `Override` (override.hh:50).
///
/// The container is keyed by `Address` (which is `Ord`) so the maps preserve
/// Ghidra's `map<Address, ...>` ordering semantics.
#[derive(Debug, Default, Clone)]
pub struct Override {
    /// Force goto on jump at `targetpc` to `destpc`.
    forcegoto: BTreeMap<Address, Address>,
    /// Delay count indexed by address-space index. -1 = no override.
    deadcodedelay: Vec<i32>,
    /// Override indirect at `callpoint` into direct call to `directcall`.
    indirectover: BTreeMap<Address, Address>,
    /// Override prototype at `callpoint`. Stored as a marker (the FuncProto
    /// reference is held externally until fspec.rs lands).
    protoover: BTreeMap<Address, bool>,
    /// Addresses of indirect jumps that need multistage recovery.
    multistagejump: Vec<Address>,
    /// Override the CALL <-> BRANCH flow at the given address.
    flowoverride: BTreeMap<Address, FlowOverride>,
}

impl Override {
    /// Create an empty override set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear the entire set of overrides. Faithful to `clear()`
    /// (override.cc:29).
    pub fn clear(&mut self) {
        self.forcegoto.clear();
        self.deadcodedelay.clear();
        self.indirectover.clear();
        self.protoover.clear();
        self.multistagejump.clear();
        self.flowoverride.clear();
    }

    /// Force a specific branch instruction to be an unstructured goto.
    /// Faithful to `insertForceGoto` (override.cc:66).
    pub fn insert_force_goto(&mut self, targetpc: Address, destpc: Address) {
        self.forcegoto.insert(targetpc, destpc);
    }

    /// Override the number of passes before dead-code elimination starts for an
    /// address space. Faithful to `insertDeadcodeDelay` (override.cc:79).
    ///
    /// `space_index` is the index of the address space ( AddrSpace::getIndex() ).
    pub fn insert_deadcode_delay(&mut self, space_index: usize, delay: i32) {
        while self.deadcodedelay.len() <= space_index {
            self.deadcodedelay.push(-1);
        }
        self.deadcodedelay[space_index] = delay;
    }

    /// Check if a delay override is already installed for an address space.
    /// Faithful to `hasDeadcodeDelay` (override.cc:92).
    ///
    /// `current_delay` is the space's current `getDeadcodeDelay()` value.
    pub fn has_deadcode_delay(&self, space_index: usize, current_delay: i32) -> bool {
        if space_index >= self.deadcodedelay.len() {
            return false;
        }
        let val = self.deadcodedelay[space_index];
        if val == -1 {
            return false;
        }
        val != current_delay
    }

    /// Override an indirect call turning it into a direct call. Faithful to
    /// `insertIndirectOverride` (override.cc:109).
    pub fn insert_indirect_override(&mut self, callpoint: Address, directcall: Address) {
        self.indirectover.insert(callpoint, directcall);
    }

    /// Override the assumed function prototype at a specific call site.
    /// Faithful to `insertProtoOverride` (override.cc:121).
    ///
    /// NOTE: The FuncProto itself is owned externally until fspec integration;
    /// this records that an override exists at the callpoint.
    pub fn insert_proto_override(&mut self, callpoint: Address) {
        self.protoover.insert(callpoint, true);
    }

    /// Flag an indirect jump for multistage analysis. Faithful to
    /// `insertMultistageJump` (override.cc:137).
    pub fn insert_multistage_jump(&mut self, addr: Address) {
        self.multistagejump.push(addr);
    }

    /// Mark a branch instruction with a different flow type. Faithful to
    /// `insertFlowOverride` (override.cc:148).
    pub fn insert_flow_override(&mut self, addr: Address, flow_type: FlowOverride) {
        self.flowoverride.insert(addr, flow_type);
    }

    /// Look up the destination of a forced goto at the given branch address.
    /// Returns None if no force-goto override exists. (Derived from
    /// `applyForceGoto`, override.cc:204.)
    pub fn query_force_goto(&self, targetpc: Address) -> Option<Address> {
        self.forcegoto.get(&targetpc).copied()
    }

    /// Return an iterator over all force-goto overrides.
    pub fn force_gotos(&self) -> impl Iterator<Item = (&Address, &Address)> {
        self.forcegoto.iter()
    }

    /// Push all the force-goto overrides into the function. Faithful to
    /// `applyForceGoto` (override.cc:204). Calls `fd.force_goto` for each
    /// stored (targetpc, destpc) pair. Returns the number of overrides applied.
    pub fn apply_force_gotos(&self, fd: &mut crate::funcdata::Funcdata) -> usize {
        let mut count = 0;
        for (&targetpc, &destpc) in &self.forcegoto {
            if fd.force_goto(targetpc, destpc) {
                count += 1;
            }
        }
        count
    }

    /// Apply destination overrides of indirect calls. Returns the overriding
    /// direct-call address for the given callpoint, if any. Faithful to
    /// `applyIndirect` (override.cc:177).
    pub fn apply_indirect(&self, callpoint: Address) -> Option<Address> {
        self.indirectover.get(&callpoint).copied()
    }

    /// Check for a prototype override at the given callpoint. Faithful to
    /// `applyPrototype` (override.cc:160).
    pub fn apply_prototype(&self, callpoint: Address) -> bool {
        self.protoover.get(&callpoint).copied().unwrap_or(false)
    }

    /// Check for a multistage marker for a specific indirect jump. Faithful to
    /// `queryMultistageJumptable` (override.cc:191).
    pub fn query_multistage_jumptable(&self, addr: Address) -> bool {
        self.multistagejump.iter().any(|&a| a == addr)
    }

    /// Return the dead-code delay override for the given address-space index,
    /// or -1 if none. Faithful to `applyDeadCodeDelay` (override.cc:217).
    pub fn get_deadcode_delay(&self, space_index: usize) -> i32 {
        if space_index >= self.deadcodedelay.len() {
            return -1;
        }
        self.deadcodedelay[space_index]
    }

    /// Iterate over (space_index, delay) pairs for all dead-code delay
    /// overrides.
    pub fn deadcode_delays(&self) -> impl Iterator<Item = (usize, i32)> + '_ {
        self.deadcodedelay
            .iter()
            .copied()
            .enumerate()
            .filter(|&(_, d)| d >= 0)
    }

    /// Are there any flow overrides? Faithful to `hasFlowOverride`
    /// (override.hh:84).
    pub fn has_flow_override(&self) -> bool {
        !self.flowoverride.is_empty()
    }

    /// Return the particular flow override at a given address. Faithful to
    /// `getFlowOverride` (override.cc:233).
    pub fn get_flow_override(&self, addr: Address) -> FlowOverride {
        self.flowoverride
            .get(&addr)
            .copied()
            .unwrap_or(FlowOverride::None)
    }

    /// Iterate over all flow overrides.
    pub fn flow_overrides(&self) -> impl Iterator<Item = (&Address, &FlowOverride)> {
        self.flowoverride.iter()
    }

    /// Are there any overrides at all?
    pub fn is_empty(&self) -> bool {
        self.forcegoto.is_empty()
            && self.deadcodedelay.iter().all(|&d| d < 0)
            && self.indirectover.is_empty()
            && self.protoover.is_empty()
            && self.multistagejump.is_empty()
            && self.flowoverride.is_empty()
    }

    /// Generate a dead-code delay warning message. Faithful to
    /// `generateDeadcodeDelayMessage` (override.cc:51).
    pub fn generate_deadcode_delay_message(space_name: &str) -> String {
        format!("Restarted to delay deadcode elimination for space: {space_name}")
    }

    /// Generate warning messages describing current overrides. Faithful to
    /// `generateOverrideMessages` (override.cc:279).
    pub fn generate_override_messages(&self, space_names: &[String]) -> Vec<String> {
        let mut messages = Vec::new();
        for (i, delay) in self.deadcodedelay.iter().copied().enumerate() {
            if delay >= 0 {
                let name = space_names.get(i).map(|s| s.as_str()).unwrap_or("unknown");
                messages.push(Self::generate_deadcode_delay_message(name));
            }
        }
        messages
    }

    /// Dump a description of the overrides for debug. Faithful to `printRaw`
    /// (override.cc:248).
    pub fn print_raw(&self, space_names: &[String]) -> Vec<String> {
        let mut lines = Vec::new();
        for (target, dest) in &self.forcegoto {
            lines.push(format!("force goto at {target:#x} jumping to {dest:#x}"));
        }
        for (i, delay) in self.deadcodedelay.iter().copied().enumerate() {
            if delay < 0 {
                continue;
            }
            let name = space_names.get(i).map(|s| s.as_str()).unwrap_or("unknown");
            lines.push(format!("dead code delay on {name} set to {delay}"));
        }
        for (cp, dc) in &self.indirectover {
            lines.push(format!("override indirect at {cp:#x} to call directly to {dc:#x}"));
        }
        for cp in self.protoover.keys() {
            lines.push(format!("override prototype at {cp:#x}"));
        }
        for &a in &self.multistagejump {
            lines.push(format!("multistage jump at {a:#x}"));
        }
        for (addr, flow) in &self.flowoverride {
            lines.push(format!("flow override at {addr:#x} to {}", flow.to_string()));
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_override_roundtrip() {
        for flow in [
            FlowOverride::None,
            FlowOverride::Branch,
            FlowOverride::Call,
            FlowOverride::CallReturn,
            FlowOverride::Return,
        ] {
            assert_eq!(FlowOverride::from_string(flow.to_string()), flow);
        }
        assert_eq!(FlowOverride::from_string("garbage"), FlowOverride::None);
    }

    #[test]
    fn test_force_goto() {
        let mut o = Override::new();
        assert!(o.is_empty());
        o.insert_force_goto(Address::new(0x1000), Address::new(0x2000));
        assert!(!o.is_empty());
        assert_eq!(
            o.query_force_goto(Address::new(0x1000)),
            Some(Address::new(0x2000))
        );
        assert_eq!(o.query_force_goto(Address::new(0x9999)), None);
    }

    #[test]
    fn test_deadcode_delay() {
        let mut o = Override::new();
        assert!(!o.has_deadcode_delay(2, 0));
        o.insert_deadcode_delay(2, 5);
        assert!(o.has_deadcode_delay(2, 0));
        assert!(!o.has_deadcode_delay(2, 5)); // same as current → not an override
        assert_eq!(o.get_deadcode_delay(2), 5);
        assert_eq!(o.get_deadcode_delay(99), -1);
    }

    #[test]
    fn test_indirect_override() {
        let mut o = Override::new();
        o.insert_indirect_override(Address::new(0x401000), Address::new(0x402000));
        assert_eq!(
            o.apply_indirect(Address::new(0x401000)),
            Some(Address::new(0x402000))
        );
        assert_eq!(o.apply_indirect(Address::new(0x401111)), None);
    }

    #[test]
    fn test_multistage_jump() {
        let mut o = Override::new();
        o.insert_multistage_jump(Address::new(0x401000));
        assert!(o.query_multistage_jumptable(Address::new(0x401000)));
        assert!(!o.query_multistage_jumptable(Address::new(0x401001)));
    }

    #[test]
    fn test_flow_override_insert() {
        let mut o = Override::new();
        assert!(!o.has_flow_override());
        o.insert_flow_override(Address::new(0x100), FlowOverride::Call);
        assert!(o.has_flow_override());
        assert_eq!(
            o.get_flow_override(Address::new(0x100)),
            FlowOverride::Call
        );
        assert_eq!(
            o.get_flow_override(Address::new(0x200)),
            FlowOverride::None
        );
    }

    #[test]
    fn test_proto_override() {
        let mut o = Override::new();
        assert!(!o.apply_prototype(Address::new(0x1000)));
        o.insert_proto_override(Address::new(0x1000));
        assert!(o.apply_prototype(Address::new(0x1000)));
    }

    #[test]
    fn test_clear() {
        let mut o = Override::new();
        o.insert_force_goto(Address::new(0x10), Address::new(0x20));
        o.insert_flow_override(Address::new(0x30), FlowOverride::Return);
        o.insert_multistage_jump(Address::new(0x40));
        o.clear();
        assert!(o.is_empty());
    }

    #[test]
    fn test_print_raw() {
        let mut o = Override::new();
        o.insert_force_goto(Address::new(0x1000), Address::new(0x2000));
        o.insert_deadcode_delay(1, 3);
        let lines = o.print_raw(&["ram".to_string(), "register".to_string()]);
        assert!(lines.iter().any(|l| l.contains("force goto")));
        assert!(lines.iter().any(|l| l.contains("dead code delay on register")));
    }

    #[test]
    fn test_generate_messages() {
        let mut o = Override::new();
        o.insert_deadcode_delay(0, 2);
        let msgs = o.generate_override_messages(&["ram".to_string()]);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].contains("ram"));
    }

    #[test]
    fn test_deadcode_delays_iterator() {
        let mut o = Override::new();
        o.insert_deadcode_delay(0, 2);
        o.insert_deadcode_delay(2, 5);
        let pairs: Vec<_> = o.deadcode_delays().collect();
        assert_eq!(pairs, vec![(0, 2), (2, 5)]);
    }
}
