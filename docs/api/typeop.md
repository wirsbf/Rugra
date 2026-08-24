# `typeop.rs` API Reference

**状态**: 🔧 L2（仅逐函数核对，禁止据此宣称模块 L3）
**源代码路径**: `src/typeop.rs`

## 模块说明 (Module Doc)

Type operations for P-code

Corresponds to Ghidra's `typeop.hh`

## 2026-08-24：LOAD/STORE 解引用宽度门槛（TYPE-PTRWIDTH-PTRSUB-0001）

`TypeOpLoad::propagate_type` 与 `TypeOpStore::propagate_type` 的
pointer→value 方向现在把目标 Varnode 的真实字节宽度传给
`propagate_from_pointer`。对固定长度 pointee，只有 pointee size 与访问宽度完全相等
时才传播，并返回原 pointee `Arc`；因此 `ProgressData(32B)*` 不再把 16B/4B STORE
错误标成整个 `ProgressData`，32B exact STORE 仍保留类型身份。

双侧 fixture `tests/oracle/type_ptrwidth_1204.{cc,rs,metadata.json}` 直接执行锁定
Ghidra 12.0.4 `TypeOpLoad/Store::propagateType` 与 Rugra 同一组 LOAD/STORE
宽度、别名和身份观察，runner 为 `tools/run_type_ptrwidth_oracle.sh`。该 covered
projection 为 `MATCH`。

状态仍为 **PARTIAL_MATCH**：Ghidra 在 size mismatch 时还允许 plain enum 的
`TypePartialEnum` 与 `TypePointerRel` parent 上的 enum exact-piece。该路径必须由拥有
canonical registry 的 `TypeFactory::getExactPiece` 构造；当前 TypeOp trait 没有 factory
参数，所以 Rugra 暂时 fail-closed，记为 `TYPEFACTORY-EXACTPIECE-0001`，未用本地
`Arc::new` 伪造对象身份。

## 2026-08-11：`TypeOpFloatInt2Float::preferredZextSize`

`TypeOpFloatInt2Float::preferred_zext_size` 对应锁定 oracle
Ghidra 12.0.4 `typeop.cc:1891-1902`。它按严格边界选择无符号整数转浮点前的
`INT_ZEXT` 输出宽度：

| 输入字节数 | 1 | 2 | 3 | 4 | 7 | 8 | 16 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 输出字节数 | 4 | 4 | 4 | 8 | 8 | 9 | 17 |

状态：`MATCH`。证据不是手写期望值：
`tools/run_preferred_zext_oracle.sh` 会校验 Ghidra checkout 的 commit，直接编译
`typeop.cc`，再调用上游静态方法产生上述结果。Rust 单元测试覆盖同一边界集。

该函数已由以下 Ghidra 调用点共享使用，移除了各处不同的近似分支：

- `RuleUnsigned2Float::applyOp`（`ruleaction.cc:9822`）
- `RuleInt2FloatCollapse::applyOp`（`ruleaction.cc:9888`）
- `SubvariableFlow::tryInt2FloatPull`（`subflow.cc:351`）
- `SubvariableFlow::doReplacement`（`subflow.cc:1537`）

模块仍为 L2：`TypeOp::getFlags` 的 `opflags/addlflags` 组合、`OpBehavior` 桥接及
若干 opcode 专用虚函数尚未逐项完成 12.0.4 oracle 对拍，列入 `PCODE-0002`。

## 导出的公共 API (Public API)

### `pub struct OpBehavior`

*暂无代码注释*

### `pub struct Encoder`

*暂无代码注释*

### `pub const INHERITS_SIGN: u32 = 1 << 0`

*暂无代码注释*

### `pub const INHERITS_SIGN_ZERO: u32 = 1 << 1`

*暂无代码注释*

### `pub const SHIFT_OP: u32 = 1 << 2`

*暂无代码注释*

### `pub const ARITHMETIC_OP: u32 = 1 << 3`

*暂无代码注释*

### `pub const LOGICAL_OP: u32 = 1 << 4`

*暂无代码注释*

### `pub const FLOATINGPOINT_OP: u32 = 1 << 5`

*暂无代码注释*

### `pub trait TypeOp`

Core trait representing a P-code operation type

Corresponds to Ghidra's `TypeOp` class

### `pub struct TypeOpBinary`

Base behavior for binary operations

### `pub struct TypeOpUnary`

Base behavior for unary operations

### `pub struct $struct_name`

*暂无代码注释*

### `pub struct $struct_name`

*暂无代码注释*

### `pub struct $struct_name`

*暂无代码注释*

### `pub struct $struct_name`

*暂无代码注释*

### `pub struct TypeOpCopy`

CPUI_COPY implementation

### `pub struct TypeOpLoad`

CPUI_LOAD implementation

### `pub struct TypeOpStore`

CPUI_STORE implementation

### `pub struct TypeOpBranch`

*暂无代码注释*

### `pub struct TypeOpCbranch`

*暂无代码注释*

### `pub struct TypeOpBranchind`

*暂无代码注释*

### `pub struct TypeOpCall`

*暂无代码注释*

### `pub struct TypeOpCallind`

*暂无代码注释*

### `pub struct TypeOpReturn`

*暂无代码注释*

### `pub struct TypeOpPtradd`

*暂无代码注释*

### `pub struct TypeOpPtrsub`

*暂无代码注释*

### `pub struct TypeOpMulti`

*暂无代码注释*

### `pub struct TypeOpIndirect`

*暂无代码注释*

### `pub struct TypeOpSegment`

*暂无代码注释*

### `pub struct TypeOpCpoolref`

*暂无代码注释*

### `pub struct TypeOpNew`

*暂无代码注释*

### `pub struct TypeOpCallother`

*暂无代码注释*

### `pub struct TypeOpManager`

Manager for TypeOps

This handles the mapping between OpCodes and their TypeOp implementations.

### `pub fn new() -> Self`

*暂无代码注释*

### `pub fn get_op(&self, opcode: OpCode) -> Option<&dyn TypeOp>`

*暂无代码注释*

### `pub fn push(&self, lng: &mut dyn PrintLanguage)`

Push this operation to a language printer

### 2026-08-23：RULE-PORT-COLLAPSECONSTANTS-0001（TypeOp::evaluate 桥）

新增模块级 `pub fn evaluate_unary(opc, size_out, size_in, in1) -> Option<u64>` 与
`pub fn evaluate_binary(opc, size_out, size_in, in1, in2) -> Option<u64>`，
对应 Ghidra `TypeOp::evaluateUnary/evaluateBinary`（typeop.hh:81-92，内联委托
`behave->evaluate*`）。Rugra 无 per-op TypeOp 实例，桥承担该角色：

- 非 FLOAT opcode 委托 `opbehavior::{evaluate_unary, evaluate_binary}` 自由函数表
  （opbehavior.cc:171-792 的整数/布尔/PIECE/SUBPIECE 全表）；
- FLOAT_* 分支复刻 `OpBehaviorFloat*::evaluate*`（opbehavior.cc:569-750）：
  按 sizein（INT2FLOAT/FLOAT2FLOAT 按 sizeout）查 `opbehavior::float_format`
  （`Translate::getFloatFormat` 的静态替身，仅 4/8 字节 IEEE754）；缺格式 →
  `None`（C++ 基类 LowlevelError "…emulation unimplemented"，RuleCollapseConstants
  映射为 opMarkNoCollapse）；命中 → `FloatFormat::op_*` 求值；
- 结果统一 `& calc_mask(size_out)`（保持自由函数 sizing 契约；对 FLOAT_TRUNC
  同时落实 float.cc:638 的 `res &= calc_mask(sizeout)`）。

`PcodeOp::collapse`（op.rs）改为经本桥求值，对齐
`PcodeOp::collapse -> TypeOp::evaluate* -> OpBehavior::evaluate*` 分层。

 2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。

### 2026-07-01：getInputCast/getOutputToken/propagateType 补全
TypeOp trait +get_output_token/get_input_cast/propagate_type/get_output_metatype（默认 None）。
关键 op 实现：COPY（透明传播）、LOAD/STORE（指针↔值）、MULTIEQUAL/INDIRECT（透明）、INT_ADD（指针传播）、6 个比较 op（bool 输出+跨 input 传播）。+propagate_to_pointer/from_pointer 辅助。8 新测试。
<!-- annotation-pass: 2026-07-04 -->
<!-- opcode-correct: 1783180039.060287 -->
