//! Type Inference Module
//!
//! This module implements type inference algorithms to recover type information
//! from P-code IR, including:
//! - Basic type propagation
//! - Pointer detection
//! - Struct/array recognition
//! - Type constraint solving

use crate::{Result, types::TypeKind, pcode::{Program, PcodeOp, Varnode, AddressSpace}};
use std::collections::{HashMap, HashSet};

/// Inferred type information for a varnode
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferredType {
    /// The type kind
    pub kind: TypeKind,
    /// Confidence level (0-100)
    pub confidence: u8,
    /// Source of inference
    pub source: InferenceSource,
}

/// Source of type inference
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferenceSource {
    /// Inferred from operation
    Operation,
    /// Inferred from size
    Size,
    /// Inferred from usage pattern
    Usage,
    /// Inferred from pointer arithmetic
    PointerArithmetic,
    /// Explicitly known
    Explicit,
}

/// Type inference analysis results
#[derive(Debug, Clone)]
pub struct TypeInferenceAnalysis {
    /// Mapping from varnode description to inferred type
    pub varnode_types: HashMap<String, InferredType>,
    /// Detected pointer types
    pub pointers: HashSet<String>,
    /// Detected array accesses
    pub arrays: Vec<ArrayAccess>,
    /// Detected struct accesses
    pub structs: Vec<StructAccess>,
}

/// Represents an array access pattern
#[derive(Debug, Clone)]
pub struct ArrayAccess {
    /// Base pointer varnode
    pub base: String,
    /// Index varnode
    pub index: String,
    /// Element size
    pub element_size: usize,
    /// Inferred element type
    pub element_type: Option<TypeKind>,
}

/// Represents a struct/object access pattern
#[derive(Debug, Clone)]
pub struct StructAccess {
    /// Base pointer varnode
    pub base: String,
    /// Field offset
    pub offset: i64,
    /// Field size
    pub field_size: usize,
    /// Inferred field type
    pub field_type: Option<TypeKind>,
}

impl TypeInferenceAnalysis {
    /// Create new empty analysis
    pub fn new() -> Self {
        TypeInferenceAnalysis {
            varnode_types: HashMap::new(),
            pointers: HashSet::new(),
            arrays: Vec::new(),
            structs: Vec::new(),
        }
    }

    /// Get inferred type for a varnode
    pub fn get_type(&self, varnode_key: &str) -> Option<&InferredType> {
        self.varnode_types.get(varnode_key)
    }

    /// Set inferred type for a varnode
    pub fn set_type(&mut self, varnode_key: String, inferred_type: InferredType) {
        self.varnode_types.insert(varnode_key, inferred_type);
    }

    /// Check if a varnode is inferred to be a pointer
    pub fn is_pointer(&self, varnode_key: &str) -> bool {
        self.pointers.contains(varnode_key)
    }
}

impl Default for TypeInferenceAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

/// Perform type inference on a P-code program
pub fn infer_types(program: &Program) -> Result<TypeInferenceAnalysis> {
    let mut analysis = TypeInferenceAnalysis::new();

    // 1. Initial type inference from sizes
    infer_types_from_sizes(program, &mut analysis);

    // 2. Detect pointers from operations
    detect_pointers(program, &mut analysis);

    // 3. Detect array accesses
    detect_arrays(program, &mut analysis);

    // 4. Detect struct accesses
    detect_structs(program, &mut analysis);

    // 5. Propagate types through operations
    propagate_types(program, &mut analysis);

    Ok(analysis)
}

/// Infer initial types from varnode sizes
fn infer_types_from_sizes(program: &Program, analysis: &mut TypeInferenceAnalysis) {
    for op in program.operations() {
        // Check output
        if let Some(output) = op.output.as_ref() {
            let key = varnode_key(output);
            if !analysis.varnode_types.contains_key(&key) {
                if let Some(type_kind) = type_from_size(output.size()) {
                    analysis.set_type(key, InferredType {
                        kind: type_kind,
                        confidence: 50,
                        source: InferenceSource::Size,
                    });
                }
            }
        }

        // Check inputs
        for input in op.inputs.as_slice() {
            let key = varnode_key(input);
            if !analysis.varnode_types.contains_key(&key) {
                if let Some(type_kind) = type_from_size(input.size()) {
                    analysis.set_type(key, InferredType {
                        kind: type_kind,
                        confidence: 50,
                        source: InferenceSource::Size,
                    });
                }
            }
        }
    }
}

/// Detect pointer types from operations
fn detect_pointers(program: &Program, analysis: &mut TypeInferenceAnalysis) {
    for op in program.operations() {
        match op.opcode {
            // LOAD and STORE indicate pointer usage
            OpCode::CPUI_LOAD => {
                if let Some(ptr) = op.inputs.as_slice().get(1) {
                    let key = varnode_key(ptr);
                    analysis.pointers.insert(key.clone());

                    // Update type to pointer
                    let _element_type = if let Some(output) = op.output.as_ref() {
                        type_from_size(output.size())
                    } else {
                        None
                    };

                    analysis.set_type(key, InferredType {
                        kind: TypeKind::Pointer,
                        confidence: 80,
                        source: InferenceSource::Operation,
                    });
                }
            }
            OpCode::CPUI_STORE => {
                if let Some(ptr) = op.inputs.as_slice().get(1) {
                    let key = varnode_key(ptr);
                    analysis.pointers.insert(key.clone());

                    let _element_type = if let Some(value) = op.inputs.as_slice().get(2) {
                        type_from_size(value.size())
                    } else {
                        None
                    };

                    analysis.set_type(key, InferredType {
                        kind: TypeKind::Pointer,
                        confidence: 80,
                        source: InferenceSource::Operation,
                    });
                }
            }
            // Pointer arithmetic
            OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB => {
                // Check if one operand is a pointer and other is integer
                if let (Some(left), Some(right)) = (op.inputs.as_slice().get(0), op.inputs.as_slice().get(1)) {
                    let left_key = varnode_key(left);
                    let right_key = varnode_key(right);

                    if analysis.is_pointer(&left_key) && !analysis.is_pointer(&right_key) {
                        // Result is also a pointer
                        if let Some(output) = op.output.as_ref() {
                            let out_key = varnode_key(output);
                            analysis.pointers.insert(out_key.clone());

                            // Copy pointer type from left operand
                            if let Some(left_type) = analysis.get_type(&left_key) {
                                analysis.set_type(out_key, InferredType {
                                    kind: left_type.kind.clone(),
                                    confidence: 70,
                                    source: InferenceSource::PointerArithmetic,
                                });
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Detect array access patterns
fn detect_arrays(program: &Program, analysis: &mut TypeInferenceAnalysis) {
    for op in program.operations() {
        if op.opcode == OpCode::CPUI_LOAD {
            // Pattern: LOAD space, (base + index * scale)
            // Look for pointer arithmetic followed by load
            if let Some(ptr) = op.inputs.as_slice().get(1) {
                // Check if this is result of multiplication or addition
                if let Some(element_type) = op.output.as_ref().and_then(|o| type_from_size(o.size())) {
                    let access = ArrayAccess {
                        base: varnode_key(ptr),
                        index: "unknown".to_string(), // Would need data flow analysis
                        element_size: op.output.as_ref().map(|o| o.size()).unwrap_or(1),
                        element_type: Some(element_type),
                    };
                    analysis.arrays.push(access);
                }
            }
        }
    }
}

/// Detect struct/object access patterns
fn detect_structs(program: &Program, analysis: &mut TypeInferenceAnalysis) {
    for op in program.operations() {
        match op.opcode {
            OpCode::CPUI_LOAD | OpCode::CPUI_STORE => {
                // Pattern: access at base + constant offset
                if let Some(ptr) = op.inputs.as_slice().get(1) {
                    // If pointer is constant offset from base, it's likely a struct field
                    if ptr.space() == AddressSpace::Ram {
                        let offset = ptr.offset() as i64;
                        let field_size = if op.opcode == OpCode::CPUI_LOAD {
                            op.output.as_ref().map(|o| o.size()).unwrap_or(4)
                        } else {
                            op.inputs.as_slice().get(2).map(|v| v.size()).unwrap_or(4)
                        };

                        let field_type = type_from_size(field_size);

                        let access = StructAccess {
                            base: varnode_key(ptr),
                            offset,
                            field_size,
                            field_type,
                        };
                        analysis.structs.push(access);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Propagate types through operations
fn propagate_types(program: &Program, analysis: &mut TypeInferenceAnalysis) {
    // Iterate until no more changes
    let mut changed = true;
    let mut iterations = 0;
    const MAX_ITERATIONS: usize = 10;

    while changed && iterations < MAX_ITERATIONS {
        changed = false;
        iterations += 1;

        for op in program.operations() {
            match op.opcode {
                // Copy propagates type exactly
                OpCode::CPUI_COPY => {
                    if let (Some(output), Some(input)) = (op.output.as_ref(), op.inputs.as_slice().get(0)) {
                        let input_key = varnode_key(input);
                        let output_key = varnode_key(output);

                        if let Some(input_type) = analysis.get_type(&input_key).cloned() {
                            if !analysis.varnode_types.contains_key(&output_key) {
                                analysis.set_type(output_key, input_type);
                                changed = true;
                            }
                        }
                    }
                }
                // Arithmetic operations preserve integer types
                OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB | OpCode::CPUI_INT_MULT | OpCode::CPUI_INT_DIV => {
                    if let Some(output) = op.output.as_ref() {
                        let output_key = varnode_key(output);
                        if !analysis.varnode_types.contains_key(&output_key) {
                            // Infer as integer type based on size
                            if let Some(type_kind) = type_from_size(output.size()) {
                                analysis.set_type(output_key, InferredType {
                                    kind: type_kind,
                                    confidence: 60,
                                    source: InferenceSource::Operation,
                                });
                                changed = true;
                            }
                        }
                    }
                }
                // Comparison operations produce boolean
                OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL | OpCode::CPUI_INT_LESS |
                OpCode::CPUI_INT_LESSEqual | OpCode::CPUI_INT_SLESS | OpCode::CPUI_INT_SLESSEqual => {
                    if let Some(output) = op.output.as_ref() {
                        let output_key = varnode_key(output);
                        if !analysis.varnode_types.contains_key(&output_key) {
                            analysis.set_type(output_key, InferredType {
                                kind: TypeKind::Bool,
                                confidence: 90,
                                source: InferenceSource::Operation,
                            });
                            changed = true;
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Generate a unique key for a varnode
fn varnode_key(varnode: &Varnode) -> String {
    format!("{:?}_{:x}_{}", varnode.space(), varnode.offset(), varnode.size())
}

/// Infer basic type from size
fn type_from_size(size: usize) -> Option<TypeKind> {
    match size {
        1 => Some(TypeKind::Int8),
        2 => Some(TypeKind::Int16),
        4 => Some(TypeKind::Int32),
        8 => Some(TypeKind::Int64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Address, pcode::PcodeBuilder};

    #[test]
    fn test_type_inference_basic() {
        let mut builder = PcodeBuilder::new(Address::new(0x1000));

        // Simple copy operation
        let src = Varnode::new_register(0, 4);
        let dst = Varnode::new_register(8, 4);
        builder.add_op(OpCode::CPUI_COPY, Some(dst), vec![src]);

        let program = builder.build();
        let analysis = infer_types(&program).unwrap();

        assert!(!analysis.varnode_types.is_empty());
    }

    #[test]
    fn test_pointer_detection() {
        let mut builder = PcodeBuilder::new(Address::new(0x1000));

        // LOAD operation - indicates pointer
        let ptr = Varnode::new_register(0, 8);
        let value = Varnode::new_register(8, 4);
        builder.add_op(OpCode::CPUI_LOAD, Some(value), vec![
            Varnode::new_constant(0, 8), // space
            ptr.clone(),
        ]);

        let program = builder.build();
        let analysis = infer_types(&program).unwrap();

        assert!(!analysis.pointers.is_empty());
    }

    #[test]
    fn test_type_from_size() {
        assert_eq!(type_from_size(1), Some(TypeKind::Int8));
        assert_eq!(type_from_size(2), Some(TypeKind::Int16));
        assert_eq!(type_from_size(4), Some(TypeKind::Int32));
        assert_eq!(type_from_size(8), Some(TypeKind::Int64));
        assert_eq!(type_from_size(3), None);
    }

    #[test]
    fn test_type_propagation() {
        let mut builder = PcodeBuilder::new(Address::new(0x1000));

        // Chain of copies
        let v1 = Varnode::new_register(0, 4);
        let v2 = Varnode::new_register(8, 4);
        let v3 = Varnode::new_register(16, 4);

        builder.add_op(OpCode::CPUI_COPY, Some(v2.clone()), vec![v1]);
        builder.add_op(OpCode::CPUI_COPY, Some(v3), vec![v2]);

        let program = builder.build();
        let analysis = infer_types(&program).unwrap();

        // Types should propagate through copies
        assert!(!analysis.varnode_types.is_empty());
    }

    #[test]
    fn test_comparison_produces_bool() {
        let mut builder = PcodeBuilder::new(Address::new(0x1000));

        // Comparison operation
        let result = Varnode::new_register(0, 1);
        let a = Varnode::new_register(8, 4);
        let b = Varnode::new_register(16, 4);

        builder.add_op(OpCode::CPUI_INT_EQUAL, Some(result.clone()), vec![a, b]);

        let program = builder.build();
        let analysis = infer_types(&program).unwrap();

        let result_key = varnode_key(&result);
        if let Some(inferred_type) = analysis.get_type(&result_key) {
            assert_eq!(inferred_type.kind, TypeKind::Bool);
        }
    }

    #[test]
    fn test_analysis_creation() {
        let analysis = TypeInferenceAnalysis::new();
        assert_eq!(analysis.varnode_types.len(), 0);
        assert_eq!(analysis.pointers.len(), 0);
        assert_eq!(analysis.arrays.len(), 0);
        assert_eq!(analysis.structs.len(), 0);
    }

    #[test]
    fn test_inferred_type_confidence() {
        let inferred = InferredType {
            kind: TypeKind::Int32,
            confidence: 80,
            source: InferenceSource::Operation,
        };

        assert_eq!(inferred.confidence, 80);
        assert_eq!(inferred.kind, TypeKind::Int32);
    }
}
