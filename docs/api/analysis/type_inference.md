# `analysis/type_inference.rs` API Reference

**源代码路径**: `src/analysis/type_inference.rs`

## 模块说明 (Module Doc)

Type Inference Module

This module implements type inference algorithms to recover type information
from P-code IR, including:
- Basic type propagation
- Pointer detection
- Struct/array recognition
- Type constraint solving

## 导出的公共 API (Public API)

### `pub struct InferredType`

Inferred type information for a varnode

### `pub enum InferenceSource`

Source of type inference

### `pub struct TypeInferenceAnalysis`

Type inference analysis results

### `pub struct ArrayAccess`

Represents an array access pattern

### `pub struct StructAccess`

Represents a struct/object access pattern

### `pub fn new() -> Self`

Create new empty analysis

### `pub fn get_type(&self, varnode_key: &str) -> Option<&InferredType>`

Get inferred type for a varnode

### `pub fn set_type(&mut self, varnode_key: String, inferred_type: InferredType)`

Set inferred type for a varnode

### `pub fn is_pointer(&self, varnode_key: &str) -> bool`

Check if a varnode is inferred to be a pointer

### `pub fn infer_types(program: &Program) -> Result<TypeInferenceAnalysis>`

Perform type inference on a P-code program

