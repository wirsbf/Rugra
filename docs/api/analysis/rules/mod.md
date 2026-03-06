# `analysis/rules/mod.rs` API Reference

**源代码路径**: `src/analysis/rules/mod.rs`

## 模块说明 (Module Doc)

Rule-based optimization system

This module implements a rule-based simplification engine inspired by Ghidra's
decompiler architecture. It allows defining small, focused optimization rules
that are applied iteratively until the P-code stabilizes.

## 导出的公共 API (Public API)

### `pub enum RuleResult`

Result of applying a rule

### `pub trait Rule`

A simplification rule that can be applied to a P-code operation

### `pub trait Action`

Represents a major optimization pass or action

### `pub struct RuleController`

Controller that manages and applies optimization rules

### `pub fn new() -> Self`

Create a new rule controller

### `pub fn add_rule<R: Rule + 'static>(&mut self, rule: R)`

Register a new rule

### `pub fn apply_rules(&self, program: &mut Program, cfg: &ControlFlowGraph, analysis: &FunctionAnalysis) -> bool`

Apply all rules iteratively until convergence

### `pub struct ActionSimplify`

Action that applies a set of rules repeatedly

### `pub fn new(controller: RuleController) -> Self`

*暂无代码注释*

### `pub fn with_defaults() -> Self`

Create a controller pre-populated with default optimization rules

