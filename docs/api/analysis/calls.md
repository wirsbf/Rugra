# `analysis/calls.rs` API Reference

**源代码路径**: `src/analysis/calls.rs`

## 模块说明 (Module Doc)

Call analysis and argument recovery

This module implements heuristics to identify function arguments and return values
for Call operations, based on standard calling conventions (currently x86-64).

## 导出的公共 API (Public API)

### `pub fn recover_call_semantics(program: &mut Program)`

Recover call arguments and return values based on calling convention

This pass injects register usage into CALL/CALLIND operations so that
subsequent analyses (Liveness, SSA) correctly track data flow across function calls.

Currently hardcoded for x86-64 System V ABI.

