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

prospective 双侧 fixture `tests/oracle/type_ptrwidth_1204.{cc,rs,metadata.json}` 计划直接调用
锁定 Ghidra 12.0.4 `TypeOpLoad/Store::propagateType` 与 Rugra 对应函数，比较同一组
LOAD/STORE 宽度、别名和身份观察。当前 prospective fixture 只把 Varnode 单向挂到 PcodeOp 槽位：
C++ PcodeOp 的 opcode 仍为 null，且未建立 output→def/input→descend；Rust PcodeOp
带 CPUI_LOAD/STORE opcode，但也没有走生产 builder。因此它不是同一份生产 IR/别名图。
runner 为
`tools/run_type_ptrwidth_oracle.sh`。修订后的 fixture 已通过锁定源码树的 C++
syntax-only 门禁，但 isolated whole-archive link 尚未绑定 BFD 依赖闭包，因此当前
covered projection 保守记为 `NO_ORACLE`，不得沿用旧 standalone fixture 的 MATCH。

状态仍为 **MISMATCH**：Ghidra 在 size mismatch 时还允许 plain enum 的
`TypePartialEnum` 与 `TypePointerRel` parent 上的 enum exact-piece。该路径必须由拥有
canonical registry 的 `TypeFactory::getExactPiece` 构造；当前 TypeOp trait 没有 factory
参数，所以 Rugra 暂时 fail-closed，记为 `TYPEFACTORY-EXACTPIECE-0001`，未用本地
`Arc::new` 伪造对象身份。

LOAD/STORE 的 spacebase 守卫按 oracle 的显式传播源 `invn` 判断；尤其 LOAD
value→pointer 方向检查 output，而不是把 `outslot` 当作 input 下标。Rust 回归测试已覆盖
这个槽位选择，两侧 prospective fixture 也已有 spacebase case；但双侧执行尚未完成，
metadata 因此记为 `NO_ORACLE`，不宣称 MATCH。

value→pointer 方向仍为 **MISMATCH**：oracle 使用目标 `outvn` 的 pointer storage width、
地址空间 wordsize 和 `TypeFactory` canonical identity；当前 Rust 使用 `alt_type` 宽度、
固定 wordsize 1，并新建 `Arc`。

runner 会重算输入 manifest，分别钉住两侧 stdout，并从锁定 commit 的源码 archive
重建 `libdecomp.a`，避免复用 Ghidra checkout 中未追踪的历史产物。但 isolated
whole-archive link 的 pinned BFD header/library/dependency closure 尚未闭合；Rust 侧
声明的 base commit/blob 也未被重建为快照，仍直接构建 live tree 到 shared target。
两项 harness 缺口都记为 `NO_ORACLE`，绑定 `ORACLE-RUNNER-HERMETIC-0001`。

生产 `ActionInferTypes` 仍在 `coreaction.rs:3994-4020` 自行分派 LOAD/STORE，绕过这里的
TypeOp 宽度门槛；该生产闭包保持 `MISMATCH`，本切片不会改变 progressbarinit 输出。

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
