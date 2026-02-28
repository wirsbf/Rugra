//! C code generation module for Rugra Decompiler
//!
//! This module converts the analyzed P-code IR into structured C code.
//! It handles control flow recovery, expression folding, and type-aware formatting.

use crate::analysis::cfg::{Conditional, ControlFlowGraph, Loop, LoopType};
use crate::analysis::FunctionAnalysis;
use crate::pcode::{PcodeOp, Program, Varnode};
use std::collections::HashSet;

/// Generate C code for a function analyzed in the given FunctionAnalysis.
pub fn generate_c_code(
    analysis: &FunctionAnalysis,
    program: &Program,
    binary: Option<&crate::binary::Binary>,
) -> crate::Result<String> {
    let mut output = String::new();
    let mut used_names = HashSet::new();

    // 1. Generate Function Signature
    output.push_str(&generate_function_signature(analysis, program, binary, &mut used_names));
    output.push_str(" {\n");

    // 2. Generate Variable Declarations
    output.push_str(&generate_variable_declarations(analysis, &mut used_names));
    if !used_names.is_empty() {
        output.push('\n');
    }

    // 3. Generate Structured Body
    if let Some(cfg) = &analysis.cfg {
        let loops = cfg.detect_loops();
        let conditionals = cfg.identify_conditionals();
        let switches = cfg.identify_switches(program);
        let mut structured_blocks = HashSet::new();
        let formatter = formatter::CFormatter::new();

        output.push_str(&generate_structured_blocks(
            cfg,
            program,
            analysis,
            binary,
            cfg.entry,
            &loops,
            &conditionals,
            &switches,
            &mut structured_blocks,
            &formatter,
            1,
            &mut used_names,
        ));
    }

    output.push_str("}\n");
    Ok(output)
}

fn generate_function_signature(
    analysis: &FunctionAnalysis,
    program: &Program,
    binary: Option<&crate::binary::Binary>,
    _used_names: &mut HashSet<String>,
) -> String {
    let mut name = program.metadata().name.clone().unwrap_or_else(|| "func_unknown".to_string());

    // Fallback to binary symbols if name is generic
    if name == "func_unknown" || name.starts_with("func_") {
        if let Some(entry) = program.entry_point() {
            if let Some(bin) = binary {
                if let Some(sym_name) = bin.get_function_name(entry) {
                    name = sym_name.clone();
                }
            }
        }
    }

    let name = name.replace('.', "_");

    let mut has_return_value = false;
    for op in program.operations() {
        if op.opcode() == PcodeOp::Return && !op.inputs().is_empty() {
            has_return_value = true;
            break;
        }
    }

    let ret_type = if has_return_value { "long" } else { "void" };
    let mut params = Vec::new();
    if let Some(high_vars) = &analysis.high_variables {
        let mut param_list: Vec<_> = high_vars.variables.iter()
            .filter(|v| v.name.starts_with("param_"))
            .collect();
        param_list.sort_by_key(|v| v.name.clone());

        for p in param_list {
            let p_type = match p.size {
                1 => "char",
                2 => "short",
                4 => "int",
                8 => "long",
                _ => "long",
            };
            params.push(format!("{} {}", p_type, p.name));
        }
    }

    let params_str = if params.is_empty() {
        "void".to_string()
    } else {
        params.join(", ")
    };

    format!("{} {}({})", ret_type, name, params_str)
}

fn generate_variable_declarations(
    analysis: &FunctionAnalysis,
    _used_names: &mut HashSet<String>,
) -> String {
    let mut output = String::new();
    if let Some(high_vars) = &analysis.high_variables {
        for var in &high_vars.variables {
            if var.name.starts_with("param_") || !analysis.ssa.as_ref().map_or(true, |ssa| {
                var.instances.iter().any(|inst| ssa.uses.get(inst).map_or(false, |u| !u.is_empty()))
            }) {
                continue;
            }
            let type_name = match var.size {
                1 => "char",
                2 => "short",
                4 => "int",
                8 => "long",
                _ => "undefined",
            };
            output.push_str(&format!("    {} {};\n", type_name, var.name));
        }
    }
    output
}

fn generate_structured_blocks(
    cfg: &crate::analysis::cfg::ControlFlowGraph,
    program: &Program,
    analysis: &FunctionAnalysis,
    binary: Option<&crate::binary::Binary>,
    start_block: usize,
    loops: &[Loop],
    conditionals: &[Conditional],
    switches: &[crate::analysis::cfg::Switch],
    structured_blocks: &mut HashSet<usize>,
    formatter: &formatter::CFormatter,
    indent_level: usize,
    used_names: &mut HashSet<String>,
) -> String {
    let mut output = String::new();
    let indent = "    ".repeat(indent_level);

    if structured_blocks.contains(&start_block) || start_block >= cfg.blocks.len() {
        return output;
    }

    // A. Check for Loop Header
    if let Some(loop_info) = loops.iter().find(|l| l.header == start_block) {
        let block = &cfg.blocks[start_block];
        if loop_info.loop_type == LoopType::DoWhile {
            output.push_str(&format!("{}do {{\n", indent));
        } else {
            let cond_str = get_block_condition(cfg, program, analysis, binary, start_block, used_names);
            output.push_str(&format!("{}while ({}) {{\n", indent, cond_str));
        }

        structured_blocks.insert(start_block);
        output.push_str(&generate_block_content(cfg, program, analysis, binary, start_block, formatter, indent_level + 1, used_names));

        for &block_idx in &loop_info.body {
            if !structured_blocks.contains(&block_idx) {
                output.push_str(&generate_structured_blocks(cfg, program, analysis, binary, block_idx, loops, conditionals, switches, structured_blocks, formatter, indent_level + 1, used_names));
            }
        }
        output.push_str(&format!("{}}}\n", indent));

        // Follow-up with blocks outside loop
        for &succ in &block.successors {
            if !loop_info.body.contains(&succ) {
                output.push_str(&generate_structured_blocks(cfg, program, analysis, binary, succ, loops, conditionals, switches, structured_blocks, formatter, indent_level, used_names));
            }
        }
        return output;
    }

    // B. Check for Conditional Header
    if let Some(cond) = conditionals.iter().find(|c| c.condition_block == start_block) {
        output.push_str(&generate_block_content(cfg, program, analysis, binary, start_block, formatter, indent_level, used_names));
        structured_blocks.insert(start_block);

        let cond_str = get_block_condition(cfg, program, analysis, binary, start_block, used_names);
        output.push_str(&format!("{}if ({}) {{\n", indent, cond_str));

        output.push_str(&generate_structured_blocks(cfg, program, analysis, binary, cond.true_branch, loops, conditionals, switches, structured_blocks, formatter, indent_level + 1, used_names));

        output.push_str(&format!("{}}} else {{\n", indent));
        output.push_str(&generate_structured_blocks(cfg, program, analysis, binary, cond.false_branch, loops, conditionals, switches, structured_blocks, formatter, indent_level + 1, used_names));
        output.push_str(&format!("{}}}\n", indent));

        if let Some(merge) = cond.merge_point {
            output.push_str(&generate_structured_blocks(cfg, program, analysis, binary, merge, loops, conditionals, switches, structured_blocks, formatter, indent_level, used_names));
        }
        return output;
    }

    // C. Regular Block
    output.push_str(&generate_block_content(cfg, program, analysis, binary, start_block, formatter, indent_level, used_names));
    structured_blocks.insert(start_block);

    let block = &cfg.blocks[start_block];
    for &succ in &block.successors {
        output.push_str(&generate_structured_blocks(cfg, program, analysis, binary, succ, loops, conditionals, switches, structured_blocks, formatter, indent_level, used_names));
    }

    output
}

fn get_block_statements(
    cfg: &ControlFlowGraph,
    program: &Program,
    analysis: &FunctionAnalysis,
    binary: Option<&crate::binary::Binary>,
    block_idx: usize,
    used_names: &mut HashSet<String>,
) -> Vec<ast::Statement> {
    let mut stmts = Vec::new();
    let block = &cfg.blocks[block_idx];
    for &op_idx in &block.operations {
        if op_idx >= program.operation_count() { continue; }
        let op = &program.operations()[op_idx];
        if op.opcode() == PcodeOp::Nop || op.opcode() == PcodeOp::CBranch { continue; }
        if let Some(stmt) = pcode_to_statement(op, program, analysis, binary, used_names) {
            stmts.push(stmt);
        }
    }
    stmts
}

fn generate_block_content(
    cfg: &ControlFlowGraph,
    program: &Program,
    analysis: &FunctionAnalysis,
    binary: Option<&crate::binary::Binary>,
    block_idx: usize,
    formatter: &formatter::CFormatter,
    indent_level: usize,
    used_names: &mut HashSet<String>,
) -> String {
    let mut output = String::new();
    let stmts = get_block_statements(cfg, program, analysis, binary, block_idx, used_names);
    let mut block_formatter = formatter.clone();
    block_formatter.indent_level = indent_level;

    for stmt in stmts {
        output.push_str(&block_formatter.format_statement(&stmt));
    }
    output
}

fn get_block_condition(
    cfg: &ControlFlowGraph,
    program: &Program,
    analysis: &FunctionAnalysis,
    binary: Option<&crate::binary::Binary>,
    block_idx: usize,
    used_names: &mut HashSet<String>,
) -> String {
    let block = &cfg.blocks[block_idx];
    for &op_idx in block.operations.iter().rev() {
        if op_idx >= program.operation_count() { continue; }
        let op = &program.operations()[op_idx];
        if op.opcode() == PcodeOp::CBranch {
            if let Some(cond_vn) = op.inputs().get(1) {
                let expr = fold_expression(cond_vn, analysis, program, binary, used_names);
                let fmt = formatter::CFormatter::new();
                return fmt.format_expression(&expr);
            }
        }
    }
    "1".to_string()
}

fn pcode_to_statement(
    op: &crate::pcode::PcodeOperation,
    program: &Program,
    analysis: &FunctionAnalysis,
    binary: Option<&crate::binary::Binary>,
    used_names: &mut HashSet<String>,
) -> Option<ast::Statement> {
    use ast::*;

    match op.opcode() {
        PcodeOp::Copy => {
            if let Some(output) = op.output() {
                if let Some(input) = op.inputs().get(0) {
                    return Some(Statement::Assignment {
                        lhs: Box::new(varnode_to_expression(output, analysis, binary, used_names)),
                        rhs: Box::new(varnode_to_expression(input, analysis, binary, used_names)),
                    });
                }
            }
        }
        PcodeOp::Load => {
            if let Some(output) = op.output() {
                if let Some(ptr) = op.inputs().get(1) {
                    return Some(Statement::Assignment {
                        lhs: Box::new(varnode_to_expression(output, analysis, binary, used_names)),
                        rhs: Box::new(Expression::Unary {
                            op: UnaryOp::Dereference,
                            operand: Box::new(varnode_to_expression(ptr, analysis, binary, used_names)),
                        }),
                    });
                }
            }
        }
        PcodeOp::Store => {
            if let (Some(ptr), Some(value)) = (op.inputs().get(1), op.inputs().get(2)) {
                return Some(Statement::Assignment {
                    lhs: Box::new(Expression::Unary {
                        op: UnaryOp::Dereference,
                        operand: Box::new(varnode_to_expression(ptr, analysis, binary, used_names)),
                    }),
                    rhs: Box::new(varnode_to_expression(value, analysis, binary, used_names)),
                });
            }
        }
        PcodeOp::Call | PcodeOp::CallInd => {
            if let Some(target) = op.inputs().get(0) {
                let args = op.inputs().iter().skip(1)
                    .map(|vn| fold_expression(vn, analysis, program, binary, used_names))
                    .collect();

                let func_expr = if target.is_constant() {
                    let addr = target.offset();
                    let mut name = if let Some(bin) = binary {
                        bin.get_function_name(crate::Address::new(addr)).cloned()
                            .unwrap_or_else(|| format!("func_{:x}", addr))
                    } else {
                        format!("func_{:x}", addr)
                    };
                    Expression::Variable(name.replace('.', "_"))
                } else {
                    varnode_to_expression(target, analysis, binary, used_names)
                };

                let call_expr = Expression::Call { function: Box::new(func_expr), arguments: args };
                if let Some(output) = op.output() {
                    return Some(Statement::Assignment {
                        lhs: Box::new(varnode_to_expression(output, analysis, binary, used_names)),
                        rhs: Box::new(call_expr),
                    });
                } else {
                    return Some(Statement::Expression(call_expr));
                }
            }
        }
        PcodeOp::Return => {
            let ret_val = op.inputs().get(0).map(|v| Box::new(varnode_to_expression(v, analysis, binary, used_names)));
            return Some(Statement::Return { value: ret_val });
        }
        _ => {
            if let Some(output) = op.output() {
                if output.is_unique() {
                    if let Some(ssa) = &analysis.ssa {
                        let key = format!("{:?}_{:x}_{}_{}", output.space(), output.offset(), output.size(), output.version());
                        if let Some(uses) = ssa.uses.get(&key) {
                            if uses.len() <= 1 { return None; }
                        } else { return None; }
                    } else { return None; }
                }
                if op.inputs().len() >= 2 {
                    let bin_op = match op.opcode() {
                        PcodeOp::IntAdd => BinaryOp::Add,
                        PcodeOp::IntSub => BinaryOp::Sub,
                        PcodeOp::IntMult => BinaryOp::Mul,
                        PcodeOp::IntDiv => BinaryOp::Div,
                        PcodeOp::IntAnd => BinaryOp::And,
                        PcodeOp::IntOr => BinaryOp::Or,
                        PcodeOp::IntXor => BinaryOp::Xor,
                        PcodeOp::IntLeft => BinaryOp::Shl,
                        PcodeOp::IntRight => BinaryOp::Shr,
                        _ => return None,
                    };
                    return Some(Statement::Assignment {
                        lhs: Box::new(varnode_to_expression(output, analysis, binary, used_names)),
                        rhs: Box::new(Expression::Binary {
                            op: bin_op,
                            left: Box::new(varnode_to_expression(&op.inputs()[0], analysis, binary, used_names)),
                            right: Box::new(varnode_to_expression(&op.inputs()[1], analysis, binary, used_names)),
                        }),
                    });
                }
            }
        }
    }
    None
}

fn fold_expression(
    vn: &Varnode,
    analysis: &FunctionAnalysis,
    program: &Program,
    binary: Option<&crate::binary::Binary>,
    used_names: &mut HashSet<String>,
) -> ast::Expression {
    if vn.is_unique() {
        if let Some(def_op) = program.operations().iter().find(|op| op.output() == Some(vn)) {
            match def_op.opcode() {
                PcodeOp::IntAdd | PcodeOp::IntSub | PcodeOp::IntMult | PcodeOp::IntDiv |
                PcodeOp::IntAnd | PcodeOp::IntOr | PcodeOp::IntXor |
                PcodeOp::IntLeft | PcodeOp::IntRight => {
                    if def_op.inputs().len() >= 2 {
                         let bin_op = match def_op.opcode() {
                            PcodeOp::IntAdd => ast::BinaryOp::Add,
                            PcodeOp::IntSub => ast::BinaryOp::Sub,
                            PcodeOp::IntMult => ast::BinaryOp::Mul,
                            PcodeOp::IntDiv => ast::BinaryOp::Div,
                            PcodeOp::IntAnd => ast::BinaryOp::And,
                            PcodeOp::IntOr => ast::BinaryOp::Or,
                            PcodeOp::IntXor => ast::BinaryOp::Xor,
                            PcodeOp::IntLeft => ast::BinaryOp::Shl,
                            PcodeOp::IntRight => ast::BinaryOp::Shr,
                            _ => ast::BinaryOp::Add,
                        };
                        return ast::Expression::Binary {
                            op: bin_op,
                            left: Box::new(fold_expression(&def_op.inputs()[0], analysis, program, binary, used_names)),
                            right: Box::new(fold_expression(&def_op.inputs()[1], analysis, program, binary, used_names)),
                        };
                    }
                }
                PcodeOp::Copy => {
                    if let Some(inp) = def_op.inputs().get(0) {
                        return fold_expression(inp, analysis, program, binary, used_names);
                    }
                }
                _ => {}
            }
        }
    }
    varnode_to_expression(vn, analysis, binary, used_names)
}

fn varnode_to_expression(
    vn: &Varnode,
    analysis: &FunctionAnalysis,
    _binary: Option<&crate::binary::Binary>,
    _used_names: &mut HashSet<String>,
) -> ast::Expression {
    if let Some(high_vars) = &analysis.high_variables {
        let key = format!("{:?}_{:x}_{}_{}", vn.space(), vn.offset(), vn.size(), vn.version());
        if let Some(hv) = high_vars.get_high_variable(&key) {
            return ast::Expression::Variable(hv.name.clone());
        }
    }

    if vn.is_constant() {
        ast::Expression::IntLiteral(vn.offset() as i64)
    } else if vn.is_register() {
        let name = match vn.offset() {
            0 => "rax", 8 => "rcx", 16 => "rdx", 24 => "rbx", 32 => "rsp",
            40 => "rbp", 48 => "rsi", 56 => "rdi", _ => "reg_unknown",
        };
        ast::Expression::Variable(name.to_string())
    } else {
        ast::Expression::Variable(format!("var_{:?}_{}", vn.space(), vn.offset()))
    }
}

pub mod ast {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Statement {
        Assignment { lhs: Box<Expression>, rhs: Box<Expression> },
        If { condition: String, then_block: Vec<Statement>, else_block: Option<Vec<Statement>> },
        While { condition: String, body: Vec<Statement> },
        Return { value: Option<Box<Expression>> },
        Expression(Expression),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Expression {
        IntLiteral(i64),
        Variable(String),
        Binary { op: BinaryOp, left: Box<Expression>, right: Box<Expression> },
        Unary { op: UnaryOp, operand: Box<Expression> },
        Call { function: Box<Expression>, arguments: Vec<Expression> },
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BinaryOp { Add, Sub, Mul, Div, And, Or, Xor, Shl, Shr, Eq, Ne }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum UnaryOp { Dereference, Neg, Not }
}

pub mod formatter {
    use super::ast::*;

    #[derive(Clone)]
    pub struct CFormatter { pub indent_level: usize }

    impl CFormatter {
        pub fn new() -> Self { CFormatter { indent_level: 0 } }
        pub fn format_statement(&self, stmt: &Statement) -> String {
            let indent = "    ".repeat(self.indent_level);
            match stmt {
                Statement::Assignment { lhs, rhs } => format!("{}{} = {};\n", indent, self.format_expression(lhs), self.format_expression(rhs)),
                Statement::Return { value } => {
                    if let Some(v) = value { format!("{}return {};\n", indent, self.format_expression(v)) }
                    else { format!("{}return;\n", indent) }
                }
                Statement::Expression(expr) => format!("{}{};\n", indent, self.format_expression(expr)),
                Statement::If { condition, then_block, else_block } => {
                    let mut s = format!("{}if ({}) {{\n", indent, condition);
                    let mut inner = self.clone(); inner.indent_level += 1;
                    for st in then_block { s.push_str(&inner.format_statement(st)); }
                    if let Some(eb) = else_block {
                        s.push_str(&format!("{}}} else {{\n", indent));
                        for st in eb { s.push_str(&inner.format_statement(st)); }
                    }
                    s.push_str(&format!("{}}}\n", indent));
                    s
                }
                Statement::While { condition, body } => {
                    let mut s = format!("{}while ({}) {{\n", indent, condition);
                    let mut inner = self.clone(); inner.indent_level += 1;
                    for st in body { s.push_str(&inner.format_statement(st)); }
                    s.push_str(&format!("{}}}\n", indent));
                    s
                }
            }
        }

        pub fn format_expression(&self, expr: &Expression) -> String {
            match expr {
                Expression::IntLiteral(v) => if *v > 0xffff { format!("0x{:x}", v) } else { v.to_string() },
                Expression::Variable(v) => v.clone(),
                Expression::Binary { op, left, right } => {
                    let op_str = match op {
                        BinaryOp::Add => "+", BinaryOp::Sub => "-", BinaryOp::Mul => "*",
                        BinaryOp::Div => "/", BinaryOp::And => "&", BinaryOp::Or => "|",
                        BinaryOp::Xor => "^", BinaryOp::Shl => "<<", BinaryOp::Shr => ">>",
                        BinaryOp::Eq => "==", BinaryOp::Ne => "!=",
                    };
                    format!("({} {} {})", self.format_expression(left), op_str, self.format_expression(right))
                }
                Expression::Call { function, arguments } => {
                    let args: Vec<String> = arguments.iter().map(|a| self.format_expression(a)).collect();
                    format!("{}({})", self.format_expression(function), args.join(", "))
                }
                Expression::Unary { op, operand } => match op {
                    UnaryOp::Dereference => format!("*{}", self.format_expression(operand)),
                    UnaryOp::Neg => format!("-{}", self.format_expression(operand)),
                    UnaryOp::Not => format!("~{}", self.format_expression(operand)),
                }
            }
        }
    }
}
