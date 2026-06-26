# `ruleaction.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/ruleaction.rs`

## 模块说明 (Module Doc)

Rule-based transformations for P-code operations

Corresponds to Ghidra's `ruleaction.hh`. Rules are small, local
transformations that target specific opcodes to simplify the IR.

## 导出的公共 API (Public API)

### `pub struct RuleCollapseConstants`

Rule for collapsing constants in arithmetic operations

Corresponds to Ghidra's `RuleCollapseConstants`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct RuleTrivialBool`

Rule for simplifying trivial boolean identities (e.g., x && true -> x)

Corresponds to Ghidra's `RuleTrivialBool`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct RulePropagateCopy`

Rule for propagating copies

Corresponds to Ghidra's `RulePropagateCopy`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct RuleZextEliminate`

Rule for eliminating redundant zero-extensions

Corresponds to Ghidra's `RuleZextEliminate`

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct RuleSextEliminate`

Rule for eliminating redundant sign-extensions

Corresponds to Ghidra's `RuleSextEliminate`.
Collapses `INT_SEXT(x)` to `COPY(x)` when input and output sizes match.

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct RuleTrivialArith`

Rule for simplifying trivial arithmetic identities

Corresponds to Ghidra's `RuleTrivialArith`.
Simplifies: `x + 0 → x`, `x - 0 → x`, `x * 1 → x`,
`x ^ 0 → x`, `x | 0 → x`.

### `pub fn new() -> Self`

*暂无代码注释*

### `pub struct RuleShiftBitops`

Rule for simplifying shift-by-zero operations

Corresponds to Ghidra's shift simplification rules.
Collapses `x << 0 → x`, `x >> 0 → x`, `x >>> 0 → x`.

### `pub fn new() -> Self`

*暂无代码注释*

 
## 2026-06-26：新增 RuleNegateIdentity（ruleaction.cc:444-474）

### `pub struct RuleNegateIdentity`
应用 INT_NEGATE 恒等式：`V & ~V => #0`，`V | ~V => #-1`，`V ^ ~V => #-1`。
忠实移植 Ghidra `RuleNegateIdentity`。

- `apply_op`：当 `INT_NOT(V)` 的输出被一个 `INT_AND`/`INT_OR`/`INT_XOR` 读取，且该逻辑 op 的另一输入正是 V 时，将该逻辑 op 折叠为 `COPY(0)`（AND）或 `COPY(all-ones)`（OR/XOR）。
- `get_opcodes`：`[CPUI_INT_NOT]`（注意：Rugra `CPUI_INT_NOT` == Ghidra `INT_NEGATE`；Rugra `CPUI_INT_NEG` == Ghidra `INT_2COMP`）。

测试：ruleaction::tests 3 个新增（AND→0、OR→全1、无匹配→NO_CHANGE）。

### 2026-06-26（续）：Funcdata op-edit API + RuleNotDistribute

#### Funcdata op-edit API（解锁创建/改写 P-code 的 Rule）
见 docs/api/funcdata.md。

#### `pub struct RuleNotDistribute`（ruleaction.cc:1139-1183）
德摩根律：`!(V && W) => !V || !W`，`!(V || W) => !V && !W`。
- `apply_op`：BOOL_NOT(BOOL_AND/OR(V,W)) → 创建两个 BOOL_NOT(V)/BOOL_NOT(W)，
  原 op 改写为对偶逻辑 op（AND↔OR）。
- `get_opcodes`：`[CPUI_BOOL_NOT]`（Rugra CPUI_BOOL_NOT == Ghidra BOOL_NEGATE）。

测试：ruleaction::tests +2（AND→OR、非 bool 内层 NO_CHANGE）+ Funcdata API +3。

### 2026-06-26（续）：RuleConcatZero + RuleXorCollapse

#### `pub struct RuleConcatZero`（ruleaction.cc:4977）
`concat(V, 0) => zext(V) << c`。当 PIECE 的低位(in1)是全 0 常量时，
改写为 INT_LEFT(INT_ZEXT(V), 8*low_size)。用 Funcdata op-edit API 创建 ZEXT op。

#### `pub struct RuleXorCollapse`（ruleaction.cc:4058）
消除比较中的 XOR：
- `(V ^ c) == d => V == (c^d)`（常量项折叠）
- `(V ^ W) == 0 => V == W`（移项）
- 要求 xor 输出为 lone descend（loneDescend）。

测试：ruleaction::tests +4（ConcatZero 折叠/非零不变；XorCollapse 常量折叠/移项）。

### 2026-06-26（续）：RuleAddMultCollapse

#### `pub struct RuleAddMultCollapse`（ruleaction.cc:4099-4183）
折叠加法/乘法中的常量：
- `((V + c) + d)  =>  V + (c+d)`
- `((V * c) * d)  =>  V * (c*d)`
主形式：当 op(in0=sub, in1=const) 且 sub 由同 op-code 定义且其 in1 也是常量时，
折叠两常量。spacebase 子情形（4131-4169）待 isSpacebase/isInput 跟踪后补。

测试：ruleaction::tests +2（双加折叠、双乘折叠）。

### 2026-06-26（续）：RuleLess2Zero + RuleLessEqual2Zero

#### `pub struct RuleLess2Zero`（ruleaction.cc:5557-5603）
INT_LESS 与极值常量（0 或全1）的简化：
- `0 < V  => 0 != V`；`V < 0 => false`；`ffff < V => false`；`V < ffff => V != ffff`

#### `pub struct RuleLessEqual2Zero`（ruleaction.cc:5605-5651）
INT_LESSEQUAL 与极值常量的简化：
- `0 <= V => true`；`V <= 0 => V == 0`；`ffff <= V => ffff == V`；`V <= ffff => true`

辅助：`fn calc_mask(size)` 对应 Ghidra calc_mask。

测试：ruleaction::tests +4（Less2Zero 两态、LessEqual2Zero 两态）。

### 2026-06-26（续）：RuleBoolNegate + get_booleanflip + op_swap_input

#### `pub fn get_booleanflip(opc, &mut reorder) -> OpCode`（opcodes.cc:94-135）
比较 op 的互补翻转表。EQUAL↔NOTEQUAL（不换序）；LESS↔LESSEQUAL、SLESS↔SLESSEQUAL（换序）；BOOL_NOT→COPY；FLOAT_* 同理。非可翻 op 返回 CPUI_MAX。

#### `Funcdata::op_swap_input(op, slot1, slot2)`（funcdata.hh）
交换两输入操作数（用于 RuleBoolNegate 翻转比较时的换序）。

#### `pub struct RuleBoolNegate`（ruleaction.cc:5516-5555）
将 BOOL_NOT 推过比较 op：
- `!!V => V`（内层 BOOL_NOT → COPY，外层也 → COPY）
- `!(V == W) => V != W`；`!(V < W) => W <= V`（换序）；`!(V <= W) => W < V`；`!(V != W) => V == W`
要求比较输出仅被 BOOL_NOT 消费（ALL descendants must be negates）。

测试：ruleaction::tests +3（双否定塌缩、LESS→LESSEQUAL 换序、非 BOOL 后代 NO_CHANGE）。
