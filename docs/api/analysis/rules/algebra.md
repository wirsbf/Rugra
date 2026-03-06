# `analysis/rules/algebra.rs` API Reference

**源代码路径**: `src/analysis/rules/algebra.rs`

## 模块说明 (Module Doc)

Algebraic simplification rules

Rules for simplifying algebraic expressions (identities, strength reduction, etc.)

## 导出的公共 API (Public API)

### `pub struct RuleAlgebraicSimplification`

Rule: Simplify algebraic expressions

Implements:
- Identity: x + 0 -> x, x * 1 -> x, ...
- Nullifying: x * 0 -> 0, x & 0 -> 0
- Idempotence: x | x -> x, x & x -> x
- Cancellation: x - x -> 0, x ^ x -> 0

