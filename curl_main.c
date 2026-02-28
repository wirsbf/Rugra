warning: unused import: `PcodeId`
  --> src\pcode\varnode.rs:13:27
   |
13 | use super::{AddressSpace, PcodeId};
   |                           ^^^^^^^
   |
   = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: unused imports: `Address` and `Result`
  --> src\pcode\varnode.rs:14:13
   |
14 | use crate::{Address, Result};
   |             ^^^^^^^  ^^^^^^

warning: unused import: `AddressSpace`
 --> src\pcode\program.rs:6:13
  |
6 | use super::{AddressSpace, PcodeId, PcodeOp, SeqNum, Varnode};
  |             ^^^^^^^^^^^^

warning: unused import: `Result`
 --> src\pcode\program.rs:7:22
  |
7 | use crate::{Address, Result};
  |                      ^^^^^^

warning: unused import: `Result`
  --> src\pcode\mod.rs:44:22
   |
44 | use crate::{Address, Result};
   |                      ^^^^^^

warning: unused import: `PcodeOperation`
  --> src\analysis\variables.rs:10:61
   |
10 | use crate::{Address, Result, pcode::{Varnode, AddressSpace, PcodeOperation, Program}};
   |                                                             ^^^^^^^^^^^^^^

warning: unused imports: `Address` and `PcodeOp`
 --> src\analysis\ssa.rs:9:13
  |
9 | use crate::{Address, Result, pcode::{Program, PcodeOp, Varnode}};
  |             ^^^^^^^                           ^^^^^^^

warning: unused import: `AddressSpace`
   --> src\analysis\mod.rs:116:60
    |
116 |     use crate::{Address, Result, pcode::{Program, PcodeOp, AddressSpace}};
    |                                                            ^^^^^^^^^^^^

warning: unused import: `HashSet`
   --> src\analysis\mod.rs:528:37
    |
528 |     use std::collections::{HashMap, HashSet};
    |                                     ^^^^^^^

warning: unused import: `types::TypeKind`
  --> src\codegen\mod.rs:24:5
   |
24 |     types::TypeKind,
   |     ^^^^^^^^^^^^^^^

warning: unused import: `HashMap`
  --> src\codegen\mod.rs:26:33
   |
26 | use std::collections::{HashSet, HashMap};
   |                                 ^^^^^^^

warning: unused import: `crate::pcode::PcodeOp`
  --> src\codegen\mod.rs:53:9
   |
53 |     use crate::pcode::PcodeOp;
   |         ^^^^^^^^^^^^^^^^^^^^^

warning: unused import: `crate::Address`
   --> src\codegen\mod.rs:236:9
    |
236 |     use crate::Address;
    |         ^^^^^^^^^^^^^^

warning: unexpected `cfg` condition value: `capstone`
   --> src\error.rs:116:7
    |
116 | #[cfg(feature = "capstone")]
    |       ^^^^^^^^^^^^^^^^^^^^
    |
    = note: expected values for `feature` are: `cli` and `default`
    = help: consider adding `capstone` as a feature in `Cargo.toml`
    = note: see <https://doc.rust-lang.org/nightly/rustc/check-cfg/cargo-specifics.html> for more information about checking conditional configuration
    = note: `#[warn(unexpected_cfgs)]` on by default

warning: unexpected `cfg` condition value: `capstone`
  --> src\error.rs:87:11
   |
87 |     #[cfg(feature = "capstone")]
   |           ^^^^^^^^^^^^^^^^^^^^
   |
   = note: expected values for `feature` are: `cli` and `default`
   = help: consider adding `capstone` as a feature in `Cargo.toml`
   = note: see <https://doc.rust-lang.org/nightly/rustc/check-cfg/cargo-specifics.html> for more information about checking conditional configuration

warning: unused imports: `Address` and `Result`
 --> src\utils.rs:6:13
  |
6 | use crate::{Address, Result};
  |             ^^^^^^^  ^^^^^^

warning: unused imports: `HashMap` and `HashSet`
 --> src\utils.rs:7:24
  |
7 | use std::collections::{HashMap, HashSet};
  |                        ^^^^^^^  ^^^^^^^

warning: unused variable: `element_type`
   --> src\analysis\type_inference.rs:177:25
    |
177 |                     let element_type = if let Some(output) = op.output() {
    |                         ^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_element_type`
    |
    = note: `#[warn(unused_variables)]` (part of `#[warn(unused)]`) on by default

warning: unused variable: `element_type`
   --> src\analysis\type_inference.rs:195:25
    |
195 |                     let element_type = if let Some(value) = op.inputs().get(2) {
    |                         ^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_element_type`

warning: unused variable: `block`
   --> src\analysis\ssa.rs:236:17
    |
236 |         for (i, block) in cfg.blocks.iter().enumerate() {
    |                 ^^^^^ help: if this is intentional, prefix it with an underscore: `_block`

warning: unused variable: `ssa`
   --> src\analysis\ssa.rs:337:20
    |
337 | pub fn destroy_ssa(ssa: &SSAForm) -> Result<()> {
    |                    ^^^ help: if this is intentional, prefix it with an underscore: `_ssa`

warning: unused variable: `dominators`
   --> src\analysis\mod.rs:241:74
    |
241 |         fn find_loop_body(&self, header: usize, back_edge_source: usize, dominators: &HashMap<usize, usize>) -> Loop {
    |                                                                          ^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_dominators`

warning: unused variable: `dominators`
   --> src\analysis\mod.rs:272:17
    |
272 |             let dominators = self.compute_dominators();
    |                 ^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_dominators`

warning: unused variable: `type_analysis`
   --> src\codegen\mod.rs:128:5
    |
128 |     type_analysis: &Option<crate::analysis::type_inference::TypeInferenceAnalysis>,
    |     ^^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_type_analysis`

warning: unused variable: `formatter`
   --> src\codegen\mod.rs:159:5
    |
159 |     formatter: &formatter::CFormatter,
    |     ^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_formatter`

warning: unused variable: `blocks`
   --> src\codegen\mod.rs:629:35
    |
629 |     pub fn structure_control_flow(blocks: &[BasicBlockInfo]) -> Vec<Statement> {
    |                                   ^^^^^^ help: if this is intentional, prefix it with an underscore: `_blocks`

warning: unused variable: `ip`
  --> src\disasm\x86_64.rs:49:13
   |
49 |         let ip = iced_inst.ip();
   |             ^^ help: if this is intentional, prefix it with an underscore: `_ip`

warning: unused variable: `current_addr`
   --> src\disasm\x86_64.rs:201:57
    |
201 |     fn get_branch_target(&self, inst: &IcedInstruction, current_addr: Address) -> Option<Address> {
    |                                                         ^^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_current_addr`

warning: unused variable: `size`
  --> src\translator\x86_64.rs:96:39
   |
96 |             Operand::Register { name, size } => {
   |                                       ^^^^ help: try ignoring the field: `size: _`

warning: unused variable: `builder`
   --> src\translator\x86_64.rs:172:9
    |
172 |         builder: &mut PcodeBuilder,
    |         ^^^^^^^ help: if this is intentional, prefix it with an underscore: `_builder`

warning: unused variable: `seqnum`
   --> src\translator\x86_64.rs:173:9
    |
173 |         seqnum: SeqNum,
    |         ^^^^^^ help: if this is intentional, prefix it with an underscore: `_seqnum`

warning: unused variable: `src`
   --> src\translator\x86_64.rs:672:13
    |
672 |         let src = self.operand_to_varnode(&inst.operands[0])?;
    |             ^^^ help: if this is intentional, prefix it with an underscore: `_src`

warning: unused variable: `dest`
   --> src\translator\x86_64.rs:701:13
    |
701 |         let dest = self.operand_to_varnode(&inst.operands[0])?;
    |             ^^^^ help: if this is intentional, prefix it with an underscore: `_dest`

warning: variable does not need to be mutable
   --> src\utils.rs:228:17
    |
228 |             let mut candidates: Vec<_> = dominators
    |                 ----^^^^^^^^^^
    |                 |
    |                 help: remove this `mut`
    |
    = note: `#[warn(unused_mut)]` (part of `#[warn(unused)]`) on by default

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:243:13
    |
243 |             type_name: String,
    |             ^^^^^^^^^^^^^^^^^
    |
note: the lint level is defined here
   --> src\lib.rs:44:9
    |
 44 | #![warn(missing_docs)]
    |         ^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:244:13
    |
244 |             name: String,
    |             ^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:245:13
    |
245 |             initializer: Option<Box<Expression>>,
    |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:249:13
    |
249 |             lhs: Box<Expression>,
    |             ^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:250:13
    |
250 |             rhs: Box<Expression>,
    |             ^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:254:13
    |
254 |             condition: Box<Expression>,
    |             ^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:255:13
    |
255 |             then_block: Vec<Statement>,
    |             ^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:256:13
    |
256 |             else_block: Option<Vec<Statement>>,
    |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:260:13
    |
260 |             condition: Box<Expression>,
    |             ^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:261:13
    |
261 |             body: Vec<Statement>,
    |             ^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:265:13
    |
265 |             init: Option<Box<Statement>>,
    |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:266:13
    |
266 |             condition: Option<Box<Expression>>,
    |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:267:13
    |
267 |             increment: Option<Box<Expression>>,
    |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:268:13
    |
268 |             body: Vec<Statement>,
    |             ^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:272:13
    |
272 |             value: Option<Box<Expression>>,
    |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:284:13
    |
284 |             expr: Box<Expression>,
    |             ^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:285:13
    |
285 |             cases: Vec<(i64, Vec<Statement>)>,
    |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:286:13
    |
286 |             default: Option<Vec<Statement>>,
    |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:290:13
    |
290 |             label: String,
    |             ^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:294:13
    |
294 |             name: String,
    |             ^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:309:13
    |
309 |             op: BinaryOp,
    |             ^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:310:13
    |
310 |             left: Box<Expression>,
    |             ^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:311:13
    |
311 |             right: Box<Expression>,
    |             ^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:315:13
    |
315 |             op: UnaryOp,
    |             ^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:316:13
    |
316 |             operand: Box<Expression>,
    |             ^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:320:13
    |
320 |             function: Box<Expression>,
    |             ^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:321:13
    |
321 |             arguments: Vec<Expression>,
    |             ^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:325:13
    |
325 |             array: Box<Expression>,
    |             ^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:326:13
    |
326 |             index: Box<Expression>,
    |             ^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:330:13
    |
330 |             object: Box<Expression>,
    |             ^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:331:13
    |
331 |             member: String,
    |             ^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:335:13
    |
335 |             pointer: Box<Expression>,
    |             ^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:336:13
    |
336 |             member: String,
    |             ^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:340:13
    |
340 |             type_name: String,
    |             ^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:341:13
    |
341 |             expr: Box<Expression>,
    |             ^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:345:13
    |
345 |             condition: Box<Expression>,
    |             ^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:346:13
    |
346 |             true_expr: Box<Expression>,
    |             ^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\codegen\mod.rs:347:13
    |
347 |             false_expr: Box<Expression>,
    |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:354:9
    |
354 |         Add, Sub, Mul, Div, Mod,
    |         ^^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:354:14
    |
354 |         Add, Sub, Mul, Div, Mod,
    |              ^^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:354:19
    |
354 |         Add, Sub, Mul, Div, Mod,
    |                   ^^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:354:24
    |
354 |         Add, Sub, Mul, Div, Mod,
    |                        ^^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:354:29
    |
354 |         Add, Sub, Mul, Div, Mod,
    |                             ^^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:355:9
    |
355 |         And, Or, Xor,
    |         ^^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:355:14
    |
355 |         And, Or, Xor,
    |              ^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:355:18
    |
355 |         And, Or, Xor,
    |                  ^^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:356:9
    |
356 |         Shl, Shr,
    |         ^^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:356:14
    |
356 |         Shl, Shr,
    |              ^^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:357:9
    |
357 |         Eq, Ne, Lt, Le, Gt, Ge,
    |         ^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:357:13
    |
357 |         Eq, Ne, Lt, Le, Gt, Ge,
    |             ^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:357:17
    |
357 |         Eq, Ne, Lt, Le, Gt, Ge,
    |                 ^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:357:21
    |
357 |         Eq, Ne, Lt, Le, Gt, Ge,
    |                     ^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:357:25
    |
357 |         Eq, Ne, Lt, Le, Gt, Ge,
    |                         ^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:357:29
    |
357 |         Eq, Ne, Lt, Le, Gt, Ge,
    |                             ^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:358:9
    |
358 |         LogicalAnd, LogicalOr,
    |         ^^^^^^^^^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:358:21
    |
358 |         LogicalAnd, LogicalOr,
    |                     ^^^^^^^^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:364:9
    |
364 |         Neg, Not, LogicalNot,
    |         ^^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:364:14
    |
364 |         Neg, Not, LogicalNot,
    |              ^^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:364:19
    |
364 |         Neg, Not, LogicalNot,
    |                   ^^^^^^^^^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:365:9
    |
365 |         AddressOf, Dereference,
    |         ^^^^^^^^^

warning: missing documentation for a variant
   --> src\codegen\mod.rs:365:20
    |
365 |         AddressOf, Dereference,
    |                    ^^^^^^^^^^^

warning: missing documentation for a struct field
  --> src\disasm\mod.rs:99:9
   |
99 |         name: String,
   |         ^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\disasm\mod.rs:100:9
    |
100 |         size: usize,
    |         ^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\disasm\mod.rs:104:9
    |
104 |         value: i64,
    |         ^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\disasm\mod.rs:105:9
    |
105 |         size: usize,
    |         ^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\disasm\mod.rs:109:9
    |
109 |         base: Option<String>,
    |         ^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\disasm\mod.rs:110:9
    |
110 |         index: Option<String>,
    |         ^^^^^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\disasm\mod.rs:111:9
    |
111 |         scale: i32,
    |         ^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\disasm\mod.rs:112:9
    |
112 |         displacement: i64,
    |         ^^^^^^^^^^^^^^^^^

warning: missing documentation for a struct field
   --> src\disasm\mod.rs:113:9
    |
113 |         size: usize,
    |         ^^^^^^^^^^^

warning: `rugra` (lib) generated 104 warnings (run `cargo fix --lib -p rugra` to apply 32 suggestions)
   Compiling rugra v0.1.0 (D:\ghidra\rugra)
error: argument never used
   --> examples\curl_decompile.rs:102:92
    |
101 |                     println!("      Block {}: addr 0x{:x}, {} ops, successors: {:?}",
    |                              ------------------------------------------------------- formatting specifier missing
102 |                         i, block.index, block.start_addr.as_u64(), block.operations.len(), block.successors);
    |                                                                                            ^^^^^^^^^^^^^^^^ argument never used

warning: unused import: `Architecture`
 --> examples\curl_decompile.rs:9:14
  |
9 |     Address, Architecture, Result,
  |              ^^^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: `rugra` (example "curl_decompile") generated 1 warning
error: could not compile `rugra` (example "curl_decompile") due to 1 previous error; 1 warning emitted
