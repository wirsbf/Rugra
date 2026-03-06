# `analysis/rules/constants.rs` API Reference

**源代码路径**: `src/analysis/rules/constants.rs`

## 模块说明 (Module Doc)

Constant folding rules

Implements Ghidra's RuleConstant logic for folding operations with constant inputs.

## 导出的公共 API (Public API)

### `pub struct RuleConstantFolding`

Rule: Fold operations with constant inputs into a single constant copy

### `pub fn evaluate_constant_op(opcode: PcodeOp, inputs: &[Varnode]) -> Option<u64>`

Helper to evaluate constant operations

