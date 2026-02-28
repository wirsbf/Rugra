//! P-code program representation
//!
//! This module defines the structure for P-code programs, which consist of
//! sequences of P-code operations that represent machine code functions.

use super::{PcodeId, PcodeOp, SeqNum, Varnode};
use crate::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// A P-code operation with inputs and output
///
/// This represents a single P-code instruction with:
/// - An opcode (the operation to perform)
/// - Zero or one output varnode
/// - Zero or more input varnodes
/// - Metadata (ID, sequence number)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeOperation {
    /// Unique identifier for this operation
    id: PcodeId,

    /// Sequence number (address + sequence within instruction)
    seqnum: SeqNum,

    /// The operation to perform
    opcode: PcodeOp,

    /// Output varnode (if any)
    output: Option<Varnode>,

    /// Input varnodes
    inputs: Vec<Varnode>,
}

impl PcodeOperation {
    /// Create a new P-code operation
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier
    /// * `seqnum` - Sequence number
    /// * `opcode` - Operation type
    /// * `output` - Output varnode (optional)
    /// * `inputs` - Input varnodes
    pub fn new(
        id: PcodeId,
        seqnum: SeqNum,
        opcode: PcodeOp,
        output: Option<Varnode>,
        inputs: Vec<Varnode>,
    ) -> Self {
        PcodeOperation {
            id,
            seqnum,
            opcode,
            output,
            inputs,
        }
    }

    /// Get the operation ID
    pub fn id(&self) -> PcodeId {
        self.id
    }

    /// Get the sequence number
    pub fn seqnum(&self) -> SeqNum {
        self.seqnum
    }

    /// Get the opcode
    pub fn opcode(&self) -> PcodeOp {
        self.opcode
    }

    /// Get the output varnode
    pub fn output(&self) -> Option<&Varnode> {
        self.output.as_ref()
    }

    /// Get the input varnodes
    pub fn inputs(&self) -> &[Varnode] {
        &self.inputs
    }

    /// Get a mutable reference to the output
    pub fn output_mut(&mut self) -> Option<&mut Varnode> {
        self.output.as_mut()
    }

    /// Set the output varnode
    pub fn set_output(&mut self, output: Option<Varnode>) {
        self.output = output;
    }

    /// Get a mutable reference to the inputs
    pub fn inputs_mut(&mut self) -> &mut Vec<Varnode> {
        &mut self.inputs
    }

    /// Check if this operation has side effects
    pub fn has_side_effects(&self) -> bool {
        matches!(
            self.opcode,
            PcodeOp::Store
                | PcodeOp::Branch
                | PcodeOp::CBranch
                | PcodeOp::BranchInd
                | PcodeOp::Call
                | PcodeOp::CallInd
                | PcodeOp::Return
                | PcodeOp::UserOp(_)
        )
    }

    /// Check if this operation is a terminator (ends a basic block)
    pub fn is_terminator(&self) -> bool {
        self.opcode.is_control_flow()
    }

    /// Get the number of inputs
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Get the address this operation came from
    pub fn address(&self) -> Address {
        self.seqnum.addr
    }
}

impl fmt::Display for PcodeOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ", self.seqnum)?;

        if let Some(output) = &self.output {
            write!(f, "{} = ", output)?;
        }

        write!(f, "{}", self.opcode)?;

        if !self.inputs.is_empty() {
            write!(f, " ")?;
            for (i, input) in self.inputs.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{}", input)?;
            }
        }

        Ok(())
    }
}

/// A P-code program representing a function
///
/// This contains all P-code operations for a function, along with metadata
/// about varnodes, basic blocks, and control flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Program {
    /// All P-code operations in the program
    operations: Vec<PcodeOperation>,

    /// Entry point address
    entry_point: Option<Address>,

    /// Next unique varnode ID
    next_unique_id: u64,

    /// Next operation ID
    next_op_id: u64,

    /// Metadata about the program
    metadata: ProgramMetadata,
}

impl Program {
    /// Create a new empty P-code program
    pub fn new() -> Self {
        Program {
            operations: Vec::new(),
            entry_point: None,
            next_unique_id: 0,
            next_op_id: 0,
            metadata: ProgramMetadata::default(),
        }
    }

    /// Create a program with a known entry point
    pub fn with_entry_point(entry: Address) -> Self {
        Program {
            operations: Vec::new(),
            entry_point: Some(entry),
            next_unique_id: 0,
            next_op_id: 0,
            metadata: ProgramMetadata::default(),
        }
    }

    /// Add a P-code operation to the program
    pub fn add_operation(&mut self, op: PcodeOperation) {
        self.operations.push(op);
    }

    /// Get all operations
    pub fn operations(&self) -> &[PcodeOperation] {
        &self.operations
    }

    /// Get mutable access to all operations
    pub fn operations_mut(&mut self) -> &mut Vec<PcodeOperation> {
        &mut self.operations
    }

    /// Get the entry point address
    pub fn entry_point(&self) -> Option<Address> {
        self.entry_point
    }

    /// Set the entry point address
    pub fn set_entry_point(&mut self, addr: Address) {
        self.entry_point = Some(addr);
    }

    /// Generate a new unique varnode
    pub fn new_unique_varnode(&mut self, size: usize) -> Varnode {
        let id = self.next_unique_id;
        self.next_unique_id += 1;
        Varnode::new_unique(id, size)
    }

    /// Generate a new operation ID
    pub fn new_operation_id(&mut self) -> PcodeId {
        let id = self.next_op_id;
        self.next_op_id += 1;
        PcodeId::new(id)
    }

    /// Get the number of operations
    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }

    /// Get metadata
    pub fn metadata(&self) -> &ProgramMetadata {
        &self.metadata
    }

    /// Get mutable metadata
    pub fn metadata_mut(&mut self) -> &mut ProgramMetadata {
        &mut self.metadata
    }

    /// Find all operations at a specific address
    pub fn operations_at_address(&self, addr: Address) -> Vec<&PcodeOperation> {
        self.operations
            .iter()
            .filter(|op| op.seqnum.addr == addr)
            .collect()
    }

    /// Find an operation by ID
    pub fn find_operation(&self, id: PcodeId) -> Option<&PcodeOperation> {
        self.operations.iter().find(|op| op.id == id)
    }

    /// Clear all operations
    pub fn clear(&mut self) {
        self.operations.clear();
        self.next_unique_id = 0;
        self.next_op_id = 0;
    }

    /// Check if the program is empty
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }
}

impl Default for Program {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "P-code Program:")?;
        if let Some(entry) = self.entry_point {
            writeln!(f, "Entry Point: {}", entry)?;
        }
        writeln!(f, "Operations: {}", self.operations.len())?;
        writeln!(f)?;

        for op in &self.operations {
            writeln!(f, "  {}", op)?;
        }

        Ok(())
    }
}

/// Metadata about a P-code program
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProgramMetadata {
    /// Function name (if known)
    pub name: Option<String>,

    /// Number of basic blocks
    pub basic_block_count: usize,

    /// Whether SSA form has been constructed
    pub is_ssa: bool,

    /// Whether type inference has been performed
    pub has_types: bool,

    /// Custom properties
    pub properties: HashMap<String, String>,
}

impl ProgramMetadata {
    /// Create new metadata
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the function name
    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    /// Set a property
    pub fn set_property(&mut self, key: String, value: String) {
        self.properties.insert(key, value);
    }

    /// Get a property
    pub fn get_property(&self, key: &str) -> Option<&String> {
        self.properties.get(key)
    }
}

/// Builder for creating P-code operations
pub struct PcodeBuilder {
    program: Program,
    current_addr: Address,
    current_seq: u32,
}

impl PcodeBuilder {
    /// Create a new builder for a program
    pub fn new(entry_point: Address) -> Self {
        PcodeBuilder {
            program: Program::with_entry_point(entry_point),
            current_addr: entry_point,
            current_seq: 0,
        }
    }

    /// Move to a new address
    pub fn at_address(&mut self, addr: Address) -> &mut Self {
        self.current_addr = addr;
        self.current_seq = 0;
        self
    }

    /// Add an operation
    pub fn add_op(
        &mut self,
        opcode: PcodeOp,
        output: Option<Varnode>,
        inputs: Vec<Varnode>,
    ) -> &mut Self {
        let id = self.program.new_operation_id();
        let seqnum = SeqNum::new(self.current_addr, self.current_seq);
        self.current_seq += 1;

        let op = PcodeOperation::new(id, seqnum, opcode, output, inputs);
        self.program.add_operation(op);
        self
    }

    /// Create a new unique varnode
    pub fn new_unique(&mut self, size: usize) -> Varnode {
        self.program.new_unique_varnode(size)
    }

    /// Build and return the program
    pub fn build(self) -> Program {
        self.program
    }

    /// Get a mutable reference to the program
    pub fn program_mut(&mut self) -> &mut Program {
        &mut self.program
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcode_operation_creation() {
        let output = Varnode::new_register(0, 4);
        let input1 = Varnode::new_register(1, 4);
        let input2 = Varnode::new_register(2, 4);

        let op = PcodeOperation::new(
            PcodeId::new(0),
            SeqNum::new(Address::new(0x1000), 0),
            PcodeOp::IntAdd,
            Some(output),
            vec![input1, input2],
        );

        assert_eq!(op.opcode(), PcodeOp::IntAdd);
        assert!(op.output().is_some());
        assert_eq!(op.input_count(), 2);
    }

    #[test]
    fn test_program_creation() {
        let mut program = Program::new();
        assert!(program.is_empty());
        assert_eq!(program.operation_count(), 0);

        let op = PcodeOperation::new(
            PcodeId::new(0),
            SeqNum::new(Address::new(0x1000), 0),
            PcodeOp::Copy,
            Some(Varnode::new_register(0, 4)),
            vec![Varnode::new_register(1, 4)],
        );

        program.add_operation(op);
        assert!(!program.is_empty());
        assert_eq!(program.operation_count(), 1);
    }

    #[test]
    fn test_unique_varnode_generation() {
        let mut program = Program::new();

        let vn1 = program.new_unique_varnode(4);
        let vn2 = program.new_unique_varnode(4);

        assert_ne!(vn1, vn2);
        assert_eq!(vn1.offset() + 1, vn2.offset());
    }

    #[test]
    fn test_program_builder() {
        let entry = Address::new(0x1000);
        let mut builder = PcodeBuilder::new(entry);

        let temp = builder.new_unique(4);
        builder.add_op(
            PcodeOp::IntAdd,
            Some(temp.clone()),
            vec![
                Varnode::new_register(0, 4),
                Varnode::new_register(1, 4),
            ],
        );

        builder.add_op(
            PcodeOp::Copy,
            Some(Varnode::new_register(2, 4)),
            vec![temp],
        );

        let program = builder.build();
        assert_eq!(program.operation_count(), 2);
        assert_eq!(program.entry_point(), Some(entry));
    }

    #[test]
    fn test_operation_display() {
        let op = PcodeOperation::new(
            PcodeId::new(0),
            SeqNum::new(Address::new(0x1000), 0),
            PcodeOp::IntAdd,
            Some(Varnode::new_register(0, 4)),
            vec![
                Varnode::new_register(1, 4),
                Varnode::new_register(2, 4),
            ],
        );

        let display = format!("{}", op);
        assert!(display.contains("INT_ADD"));
        assert!(display.contains("0x1000"));
    }

    #[test]
    fn test_operation_properties() {
        let store_op = PcodeOperation::new(
            PcodeId::new(0),
            SeqNum::new(Address::new(0x1000), 0),
            PcodeOp::Store,
            None,
            vec![
                Varnode::new_constant(0, 4),
                Varnode::new_constant(0x2000, 8),
                Varnode::new_register(0, 4),
            ],
        );

        assert!(store_op.has_side_effects());
        assert!(!store_op.is_terminator()); // STORE is not a control flow terminator

        let add_op = PcodeOperation::new(
            PcodeId::new(1),
            SeqNum::new(Address::new(0x1004), 0),
            PcodeOp::IntAdd,
            Some(Varnode::new_register(0, 4)),
            vec![
                Varnode::new_register(1, 4),
                Varnode::new_register(2, 4),
            ],
        );

        assert!(!add_op.has_side_effects());
        assert!(!add_op.is_terminator());
    }

    #[test]
    fn test_metadata() {
        let mut metadata = ProgramMetadata::new();
        metadata.set_property("author".to_string(), "test".to_string());

        assert_eq!(metadata.get_property("author"), Some(&"test".to_string()));
        assert_eq!(metadata.get_property("missing"), None);
    }

    #[test]
    fn test_find_operations() {
        let addr1 = Address::new(0x1000);
        let addr2 = Address::new(0x1004);

        let mut program = Program::new();

        program.add_operation(PcodeOperation::new(
            PcodeId::new(0),
            SeqNum::new(addr1, 0),
            PcodeOp::Copy,
            Some(Varnode::new_register(0, 4)),
            vec![Varnode::new_register(1, 4)],
        ));

        program.add_operation(PcodeOperation::new(
            PcodeId::new(1),
            SeqNum::new(addr1, 1),
            PcodeOp::IntAdd,
            Some(Varnode::new_register(0, 4)),
            vec![
                Varnode::new_register(0, 4),
                Varnode::new_constant(1, 4),
            ],
        ));

        program.add_operation(PcodeOperation::new(
            PcodeId::new(2),
            SeqNum::new(addr2, 0),
            PcodeOp::Return,
            None,
            vec![],
        ));

        let ops_at_addr1 = program.operations_at_address(addr1);
        assert_eq!(ops_at_addr1.len(), 2);

        let ops_at_addr2 = program.operations_at_address(addr2);
        assert_eq!(ops_at_addr2.len(), 1);
    }
}
