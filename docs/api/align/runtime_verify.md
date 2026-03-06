# `align/runtime_verify.rs` API Reference

**源代码路径**: `src/align/runtime_verify.rs`

## 模块说明 (Module Doc)

Runtime verification framework for Rugra-Ghidra alignment

This module provides runtime comparison testing between Rugra and Ghidra's
actual outputs, going beyond static type checking to ensure behavioral equivalence.

# Architecture

```text
Binary Input
↓
┌─────────────┐         ┌─────────────┐
│   Rugra     │         │   Ghidra    │
│ Decompiler  │         │ (via FFI)   │
└─────────────┘         └─────────────┘
↓                       ↓
Rugra Output           Ghidra Output
↓                       ↓
└───────────┬───────────┘
↓
Runtime Comparator
↓
Difference Report
```

## 导出的公共 API (Public API)

### `pub enum VerifyResult`

Test result for a single verification

### `pub fn is_match(&self) -> bool`

*暂无代码注释*

### `pub struct VerifyStats`

Statistics for verification runs

### `pub fn record(&mut self, result: &VerifyResult)`

*暂无代码注释*

### `pub fn success_rate(&self) -> f64`

*暂无代码注释*

### `pub struct RuntimeVerifier`

Runtime verification context

### `pub struct MismatchRecord`

Record of a specific mismatch

### `pub fn new() -> Self`

*暂无代码注释*

### `pub fn verify_constant_eval(`

Verify constant folding/evaluation

Calls both Rugra's and Ghidra's constant evaluation and compares results

### `pub fn verify_pcode_generation(`

Verify P-code generation for a single instruction

This requires Ghidra to be loaded with the same binary

### `pub fn verify_ssa_versions(`

Verify SSA construction

This is critical - SSA version numbers must match exactly

### `pub fn verify_cfg_structure(`

Verify control flow graph structure

### `pub fn get_stats(&self) -> VerifyStats`

Get current statistics

### `pub fn get_mismatches(&self) -> Vec<MismatchRecord>`

Get all mismatch records

### `pub fn generate_report(&self) -> String`

Generate a detailed report

### `pub fn reset(&self)`

Reset all statistics and records

### `pub fn global_verifier() -> &'static RuntimeVerifier`

Get the global runtime verifier

