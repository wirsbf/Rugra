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

### 2026-06-26（续）：RuleOrMask + RuleAndOrLump

#### `pub struct RuleOrMask`（ruleaction.cc:276-300）
`V | 0xffff => COPY(0xffff)`。当 OR 的常量覆盖输出 size 的所有位时，
结果就是该常量 → COPY。size=0 或 >8 时跳过（uintb 精度）。

#### `pub struct RuleAndOrLump`（ruleaction.cc:403-442）
折叠逻辑表达式的常量：
- `(V & c) & d => V & (c & d)`
- `(V | c) | d => V | (c | d)`
- `(V ^ c) ^ d => V ^ (c ^ d)`
模式同 AddMultCollapse，但用于 AND/OR/XOR。

测试：ruleaction::tests +4（OrMask 全掩码/部分不变；AndOrLump 双 AND/双 OR）。

### 2026-06-26（续）：RulePiece2Zext + RulePiece2Sext + RuleBxor2NotEqual

#### `pub struct RulePiece2Zext`（ruleaction.cc:207-230）
`concat(0, V) => zext(V)`。PIECE 的高位(in0)为常量 0 时，塌缩为 INT_ZEXT。

#### `pub struct RulePiece2Sext`（ruleaction.cc:232-259）
`concat(V s>> (8*size-1), V) => sext(V)`。PIECE 高位是低位的符号位算术右移时，塌缩为 INT_SEXT。

#### `pub struct RuleBxor2NotEqual`（ruleaction.cc:261-274）
`V ^^ W => V != W`。布尔 XOR 等价于布尔不等。

测试：ruleaction::tests +3（Piece2Zext、Piece2Sext、Bxor2NotEqual）。

### 2026-06-26（续）：RuleTermOrder + RuleShift2Mult

#### `pub struct RuleTermOrder`（ruleaction.cc:645-674）
交换交换律 op 的输入，使常量在 slot 1（`INT_ADD(5,V) => INT_ADD(V,5)`），消除表达式组合爆炸。

#### `pub struct RuleShift2Mult`（ruleaction.cc:3720-3771）
将参与算术（INT_ADD/SUB/MULT）或其输入由算术定义的常量移位转为乘法：
`(V << c) => V * (1<<c)`，c<32。

测试：ruleaction::tests +4（TermOrder 交换/已序不变；Shift2Mult 喂入 ADD 转乘/非算术不变）。

### 2026-06-26（续）：RuleDoubleSub + RuleTrivialShift

#### `pub struct RuleDoubleSub`（ruleaction.cc:1796-1823）
`sub(sub(V,a),b) => sub(V, a+b)`。链式 SUBPIECE 折叠，跳过中间层。

#### `pub struct RuleTrivialShift`（ruleaction.cc:3515-3542）
平凡移位简化：
- `V << 0 => COPY(V)`
- `V << c (c >= 8*size, 逻辑移位) => COPY(0)`
- INT_SRIGHT 超 size 不变（无法预测符号位）

测试：ruleaction::tests +4（DoubleSub 折叠；TrivialShift 移0/超size归零/sright超size不变）。

### 2026-06-26（续）：bit helpers + get_nz_mask + RuleSlessToLess

#### Bit 助手（address.rs，对应 address.cc:641-745）
- `signbit_negative(val, size)` — address.cc:641，符号位是否为负
- `calc_mask(size)` — address.hh:577，全1掩码
- `leastsigbit_set(val)` — address.cc:714，最低有效位索引（-1 若 0）
- `mostsigbit_set(val)` — address.cc:735，最高有效位索引

#### `Varnode::get_nz_mask()`（varnode.hh:231）
非零掩码。Ghidra 由 Heritage/Cover 维护；Rugra 当前保守近似（常量=值，其他=calc_mask(size)）。

#### `pub struct RuleSlessToLess`（ruleaction.cc:2548-2573）
当两操作数的 NZMask 表明符号位为 0（均为已知非负）时，将 INT_SLESS→INT_LESS、INT_SLESSEQUAL→INT_LESSEQUAL。

测试：address.rs +4（signbit_negative/calc_mask/leastsigbit/mostsigbit）；ruleaction::tests +3（SlessToLess 正常/负不变/Slessequal）。

### 2026-06-26（续）：RuleOrCollapse + RuleConcatLeftShift

#### `pub struct RuleOrCollapse`（ruleaction.cc:373-401）
`V | c => c` 当 NZM(V)|c == c（V 能置位的位都已被 c 覆盖）→ COPY。用 get_nz_mask。

#### `pub struct RuleConcatLeftShift`（ruleaction.cc:5004-5042）
`concat(V, zext(W) << c) => concat(concat(V, W), 0)`。当 PIECE 低位是 zext(W) 的对齐左移（c 为 8 倍数且移到最高有效边界）时，重构为两级 PIECE。用 op-edit API 创建新 PIECE op。

测试：ruleaction::tests +3（OrCollapse 覆盖/部分不变；ConcatLeftShift 重构）。

### 2026-06-26（续）：RuleDoubleShift + lone_descend/has_no_descend

#### `Varnode::lone_descend()` / `has_no_descend()`（varnode.hh）
单后代 / 无后代查询，解锁 RuleDoubleShift/RuleSubZext 等需独占使用检查的 Rule。

#### `pub struct RuleDoubleShift`（ruleaction.cc:1825-1941）
链式移位简化：
- 同向：`(V<<c)<<d => V<<(c+d)`；`(V>>c)>>d => V>>(c+d)`
- 反向（等量）：`(V<<c)>>c => V & mask`；`(V>>c)<<c => V & mask`
- INT_MULT 乘 2 的幂视为左移（leastsigbit_set）
- 移位 ≥ size 时归零为 COPY(0)

测试：ruleaction::tests +2（同向合并 2+3=5；反向抵消 LEFT4/RIGHT4 → AND 0x0fffffff）。

### 2026-06-26（续）：RuleIdentityEl + RuleSignShift

#### `pub struct RuleIdentityEl`（ruleaction.cc:3696-3722）
移除单位元：
- `V + 0 / - 0 / & 0 / | 0 / ^ 0 => COPY(V)`
- `V * 1 => COPY(V)`；`V * 0 => COPY(0)`

#### `pub struct RuleSignShift`（ruleaction.cc:3544-3600）
符号位提取规范化：`V >> 0x1f => (V s>> 0x1f) * -1`。当逻辑右移符号位参与算术（INT_ADD/MULT）或常量比较时，转为算术右移乘全1。

测试：ruleaction::tests +5（IdentityEl 加0/乘1/乘0；SignShift 算术触发/COPY不变）。

### 2026-06-26（续）：RuleSubZext + op_set_output

#### `Funcdata::op_set_output(op, vn)`（funcdata.hh）
设置/替换 op 的输出 varnode（标记 WRITTEN、设 def 链）。

#### `pub struct RuleSubZext`（ruleaction.cc:5044-5089）
简化 ZEXT(SUBPIECE)：
- `zext(sub(V, 0)) => V & mask`（偏移0，绕过截断）
- `zext(sub(V, c)) => (V >> c*8) & mask`（中间偏移，需 sub 输出为 lone descend）

测试：ruleaction::tests +2（偏移0 绕过→AND；中间偏移→SUBPIECE 改 RIGHT(32)）。

### 2026-06-26（续）：RuleConcatShift

#### `pub struct RuleConcatShift`（ruleaction.cc:1969-2014）
移位连接的变换：当右/左移位把 PIECE 的最低有效片段整体移走时，
`(concat(main, least) >> sa) => zext(main) >> (sa - leastbits)`。
精确抵消时退化为 zext/sext(main)。

测试：ruleaction::tests +2（精确抵消→ZEXT；部分不移完→NO_CHANGE）。

### 2026-06-26（续）：RuleShiftCompare

#### `pub struct RuleShiftCompare`（ruleaction.cc:2064-2168）
移位比较变换：将比较一侧的常量移位移到另一侧。
- `V >> c == d => V == (d << c)`（右移需 loneDescend）
- `V << c == d => V == (d >> c)`
- INT_MULT/INT_DIV 乘除 2 的幂视为移位（leastsigbit_set）
当 NZM 表明移位丢信息时不转换（AND-mask 子形式暂缓）。

测试：ruleaction::tests +2（左移丢高位不变；右移寄存器丢低位不变——记录保守 NZM 行为，待 Heritage 提供 NZM 后可触发）。

### 2026-06-26（续）：RuleAndCompare

#### `pub struct RuleAndCompare`（ruleaction.cc:1729-1796）
AND-比较变换，把 AND 推到更大的定义域：
- `(sub(V,c) & mask) == 0 => (V & (mask << c*8)) == 0`
- `(zext(V) & mask) == 0 => (V & mask) == 0`
当 AND 常量 != calc_mask（非退化）且 basevn 非 free 时，创建新的 INT_AND(basevn, adjusted_mask) 并改写比较。

测试：ruleaction::tests +1（zext 推送：in1 归零到 base size）。

### 2026-06-26（续）：RuleTestSign

#### `pub struct RuleTestSign`（ruleaction.cc:3602-3677）
符号位测试转有符号比较：
- `(V s>> 0x1f) != 0 => V s< 0`
- `(V s>> 0x1f) == 0 => V s<= 0`
- `(V s>> 0x1f) == -1 => V s< 0`（互补域）
遍历 SRIGHT 输出的后代比较，改写为 INT_SLESS/INT_SLESSEQUAL vs 0。

测试：ruleaction::tests +2（NOTEQUAL→SLESS；EQUAL→SLESSEQUAL）。

### 2026-06-26（续）：RuleEquality + functional_equality

#### `fn functional_equality(vn1, vn2) -> bool`（expression.cc:520, level-0:404）
判断两 varnode 是否持有相同值（立即层）：同指针或同常量。深层 functionalEqualityLevel 待补。

#### `pub struct RuleEquality`（ruleaction.cc:619-643）
`f(V,W) == f(V,W) => true`，`f(V,W) != f(V,W) => false`。两输入功能相等时塌缩为 COPY(1/0)。

测试：ruleaction::tests +3（同 varnode→COPY(1)；同常量 NOTEQUAL→COPY(0)；异常量不变）。

### 2026-06-26（续）：RuleLessNotEqual

#### `pub struct RuleLessNotEqual`（ruleaction.cc:2310-2357）
`(s)lessequal AND notequal`（同操作数对）折叠为 `(s)less`：
`V <= W && V != W => V < W`。用 functional_equality 验操作数匹配。

测试：ruleaction::tests +1（LE+NE 同操作数→LESS）。

### 2026-06-26（续）：RuleLessEqual

#### `pub struct RuleLessEqual`（ruleaction.cc:2247-2308）
`(s)less OR equal`（同操作数对）折叠为 `(s)lessequal`：
- `V < W || V == W => V <= W`
- `V < W || V != W => COPY(NOTEQUAL 输出)`（NOTEQUAL 占优）

测试：ruleaction::tests +1（LESS+EQUAL 同操作数→LESSEQUAL）。

### 2026-06-26（续）：RuleRightShiftAnd + RuleHighOrderAnd

#### `pub struct RuleRightShiftAnd`（ruleaction.cc:575-600）
`(V & mask) >> sa` 当 mask==full>>sa 时绕过 AND：`(V & full) >> sa => V >> sa`。

#### `pub struct RuleHighOrderAnd`（ruleaction.cc:1185-1250）
对齐 INT_ADD 的 INT_AND 简化（mask 形如 11110000）：
`(V + c) & 0xfff0 => V + (c & 0xfff0)`，要求 addend 的 NZM 高位为零。移植了常量 addend 主分支。

测试：ruleaction::tests +2（RightShiftAnd 绕过；HighOrderAnd 寄存器 NZM=full→正确 NO_CHANGE）。

### 2026-06-26（续）：RuleAndZext

#### `pub struct RuleAndZext`（ruleaction.cc:1697-1732）
`sext(V) & mask => zext(V)` 与 `concat(a, V) & mask => zext(V)`，当 mask 恰为根值的 full mask 时。AND 冗余等价于零扩展。

测试：ruleaction::tests +1（sext 全掩码→zext）。
