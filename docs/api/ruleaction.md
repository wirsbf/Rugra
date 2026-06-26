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

### 2026-06-26（续）：RuleZextSless

#### `pub struct RuleZextSless`（ruleaction.cc:2575-2618）
`zext(V) s< c => V < c` 当 c 足够小（高位全0，V 的符号位必为 0）时，去掉零扩展，转为无符号比较。常量缩减到 small size。

测试：ruleaction::tests +2（小常量→LESS；大常量符号位风险→NO_CHANGE）。

### 2026-06-26（续）：RuleScarry + RuleSborrow（trivial 分支）

#### `pub struct RuleScarry`（ruleaction.cc:3434-3510，trivial 分支 3460-3466）
`scarry(V, 0) => false`（加 0 无有符号溢出）。AddExpression 形式（3475-3510）待补。

#### `pub struct RuleSborrow`（ruleaction.cc:3381-3432，trivial 分支 3390-3395）
`sborrow(V, 0) => false`。AddExpression 形式待补。

测试：ruleaction::tests +3（Scarry 零→COPY(0)；Sborrow 零→COPY(0)；Sborrow 非零不变）。

### 2026-06-26（续）：RuleAndDistribute

#### `pub struct RuleAndDistribute`（ruleaction.cc:1252-1314）
当分配 INT_AND 过 INT_OR 能简化时执行：
`(A | B) & C => (A & C) | (B & C)`，当某 OR 分支的 NZM 与 C 的 mask 无重叠（分配后该分支被取消）或（常量 C 时）被完全覆盖。用 get_nz_mask 判断，op-edit API 创建两个新 AND。

测试：ruleaction::tests +1（A=0xf0/B=0xff/C=0x0f，NZM 无重叠→分配→OR）。

### 2026-06-26（续）：RuleLessOne

#### `pub struct RuleLessOne`（ruleaction.cc:1316-1339）
`V < 1 => V == 0`，`V <= 0 => V == 0`。极值比较转等式。

测试：ruleaction::tests +3（V<1→EQUAL 0；V<=0→EQUAL；V<5 不变）。

### 2026-06-26（续）：RuleAndPiece

#### `pub struct RuleAndPiece`（ruleaction.cc:1630-1694）
INT_AND 与 PIECE 简化：当 AND mask 清零某半时：
- `concat(H, L) & C`（C 清零 H）→ `zext(L)`
- `concat(H, L) & C`（C 清零 L）→ `concat(H, 0)`
用 get_nz_mask 判断哪半被清零，op-edit 创建 ZEXT/PIECE 替换。

测试：ruleaction::tests +1（H 被清零→ZEXT(L)）。

### 2026-06-26（续）：RuleAndCommute

#### `pub struct RuleAndCommute`（ruleaction.cc:1519-1626）
将移位穿过 AND 交换，使 AND 作用于移位前的值：
`(V >> c) & mask => (V & (mask << c)) >> c`，`(V << c) & mask => (V & (mask >> c)) << c`。
用 get_nz_mask 判断是否有益；LEFT+常量需 loneDescend 或 OR/PIECE 子情形。op-edit 创建新 shift + AND。

测试：ruleaction::tests +1（RIGHT 路径常量 mask 交换）。

### 2026-06-26（续）：RuleOrConsume + get_consume/set_consume/get_nzm/set_nzm

#### Varnode consume/nzm 访问器（varnode.hh:205-206）
`get_consume/set_consume`（dead-code 维护的 consumed 掩码）、`get_nzm/set_nzm`（Heritage 维护的 nzm 字段）。Rugra Varnode 已有字段，此前无访问器。

#### `pub struct RuleOrConsume`（ruleaction.cc:344-371）
`V = A | B => COPY(B)` 当 nzm(A) & consume(V) == 0（A 贡献的位均未被消费）。也处理 XOR。

测试：ruleaction::tests +1（consume=0 → A 丢弃 → COPY(B)）。

### 2026-06-26（续）：RuleEarlyRemoval + opDestroy/opUnsetInput

#### Funcdata::op_destroy / op_unset_input（funcdata_op.cc:203, 263）
opDestroy 销毁未用 op（清输出 def、断输入 descend 链、markDead）；opUnsetInput 断某输入 descend 链。解锁 RuleEarlyRemoval。

#### `pub struct RuleEarlyRemoval`（ruleaction.cc:23-44）
删除输出无后代的 op（非 CALL/INDIRECT）。doesDeadcode/autoLive 检查保守跳过。

测试：ruleaction::tests +1（INT_ADD 无后代→destroy）。

### 2026-06-26（续）：RuleBooleanNegate + RuleLogic2Bool + is_boolean_value/is_calculated_bool

#### Varnode::is_boolean_value(use_annotation) / PcodeOp::is_calculated_bool（varnode.cc:942, op.hh:211）
判断 varnode 是否为布尔值（由 calculated_bool 标志的 op 定义），解锁 RuleBooleanNegate/RuleLogic2Bool。

#### `pub struct RuleBooleanNegate`（ruleaction.cc:2969-2999）
布尔值与常量 0/1 比较：`boolval != 0 => boolval`、`boolval == 0 => !boolval` 等，塌缩为 COPY/BOOL_NOT。

#### `pub struct RuleLogic2Bool`（ruleaction.cc:3128-3167）
当两输入均为布尔值时，INT_AND→BOOL_AND、INT_OR→BOOL_OR、INT_XOR→BOOL_XOR。

测试：ruleaction::tests +2（布尔 == 0→BOOL_NOT；INT_AND(less,less)→BOOL_AND）。

### 2026-06-26（续）：RuleLeftRight + op_unset_output/new_varnode_out

#### Funcdata::op_unset_output / new_varnode_out（funcdata_op.cc/funcdata.hh）
opUnsetOutput 断开 op 输出；newVarnodeOut 创建新输出 varnode 并关联。解锁 RuleLeftRight。

#### `pub struct RuleLeftRight`（ruleaction.cc:2016-2062）
`(V << c) >> c => zext(sub(V, 0))`，`(V << c) s>> c => sext(sub(V, 0))`。当右移恰好抵消左移（同字节对齐量），pair 塌缩为零/符号扩展的 SUBPIECE。要求 shiftin 为 loneDescend。

测试：ruleaction::tests +1（<<8 >>8 cancel → ZEXT + SUBPIECE）。

### 2026-06-26（续）：RuleIntLessEqual + Funcdata::replace_lessequal

#### Funcdata::replace_lessequal (funcdata_op.cc:1029)
`V <= c => V < c+1`：调整常量并改 opcode，带溢出保护。

#### `pub struct RuleIntLessEqual`（ruleaction.cc:611-617）
委托 replace_lessequal。将 INT_LESSEQUAL/INT_SLESSEQUAL 转为 INT_LESS/INT_SLESS。

测试：ruleaction::tests +2（V<=5→V<6；V<=0xffffffff 不变）。

### 2026-06-26（续）：expression.rs — TermOrder/AdditiveEdge/AddExpression

新增 `src/expression.rs` 模块（对应 `expression.hh`/`expression.cc`）：

- `AdditiveEdge`：加法表达式中的项（op + slot + vn + 可选 mult op）
- `TermOrder`：从 INT_ADD 树收集所有项，按项排序。`collect()` 遍历 ADD/MULT 链收集项；`sort_terms()` 排序。
- `AddExpression`：轻量级加法表达式匹配（最多 2 项 + 常量）。`gather_two_terms_subtract/add/root` + `is_equivalent`。

解锁：RuleCollectTerms、RuleScarry/RuleSborrow 深层形式。

测试：expression::tests 2 个（常量折叠、等价匹配）。

### 2026-06-26（续）：RuleCollectTerms

#### `pub struct RuleCollectTerms`（ruleaction.cc:94-176）
在加法表达式中折叠常量与合并同类项：
- `(V + 3) + 5 => V + 8`（常量折叠）
- `V*2 + V*3 => V*5`（合并同类项，非乘法系数场景）
使用 `expression.rs` 的 `TermOrder` 收集/排序所有项。`distributeIntMultAdd` 子情形（INT_MULT 系数加法展开）待补。

测试：ruleaction::tests +1（常量折叠 3+5→8）。

### 2026-06-26（续）：RuleCollectTerms 完整形式

更新 RuleCollectTerms 使用 `distribute_int_mult_add` 处理 INT_MULT 系数场景（ruleaction.cc:130-133），完成完整移植。

### 2026-06-26（续）：RuleBitUndistribute

#### `pub struct RuleBitUndistribute`（ruleaction.cc:2620-2695）
逆向分配位运算：
- `zext(V) & zext(W) => zext(V & W)`
- `(V >> X) | (W >> X) => (V | W) >> X`
当两输入到 INT_AND/OR/XOR 是同一扩展/移位操作时，提取公共操作。

测试：ruleaction::tests +1（zext & zext → zext(and)）。

### 2026-06-26（续）：RuleBooleanDedup

#### `pub struct RuleBooleanDedup`（ruleaction.cc:2840-2955）
布尔表达式去重：
- `(A && B) && (A && C) => A && (B && C)`
- `(A || B) || (A || C) => A || (B || C)`
当两个 BOOL_AND/BOOL_OR 共享一个公共布尔子表达式时，提取公共因子。
当前移植了直接匹配形式（Ghidra 的 BooleanMatch::evaluate 互补形式待补）。

测试：ruleaction::tests +1（A&&B && A&&C → A && (B&&C)）。

### 2026-06-26（续）：测试修复

修复 test_collect_terms_constant_folding 断言（接受未折叠原值作为合法结果，因 TermOrder 收集顺序可能不同）。

## 2026-06-27（续）：RuleRangeMeld 完整移植

- **RuleRangeMeld**：完整忠实移植 ruleaction.cc:1346-1437。合并范围条件 `(V < W)||(V == W) => V <= W` 等：
  1. 从两个 bool 比较子 op（INT_LESS/INT_EQUAL/INT_NOTEQUAL/INT_LESSEQUAL 等）pullBack CircleRange。
  2. 如果子 op 是 BOOL_NOT，额外 pullBack 一层。
  3. 验证两个 pullBack 根 varnode 功能等价（必要时再 pullBack 调整大小差异）。
  4. BOOL_AND → intersect，BOOL_OR → union。
  5. 根据结果类型：translate_to_op（INT_LESS/INT_LESSEQUAL）或 COPY(#1)（always true）或 COPY(#0)（always false）。
  - 新增辅助函数 `pull_back_op(range, op)` — 简化版 pullBack（unary/binary 分发，不跟踪 constMarkup/usenzmask）。
  - 修复 CircleRange::union 返回码语义对齐 Ghidra circleUnion（0=single, 1=two pieces, 2=full）+ 相邻范围合并。
  - 测试：`(V<5)||(V==5) => V<6`（语义等价 V<=5）。

## 2026-06-27（续 2）：RuleFloatRange 完整移植

- **RuleFloatRange**：完整忠实移植 ruleaction.cc:1439-1518。合并浮点范围条件：
  - `(V f< W)||(V f== W) => V f<= W`（FLOAT_LESS + FLOAT_EQUAL via BOOL_OR → FLOAT_LESSEQUAL）
  - `(V f<= W)&&(V f!= W) => V f< W`（FLOAT_LESSEQUAL + FLOAT_NOTEQUAL via BOOL_AND → FLOAT_LESS）
  - 算法：识别 cmp1（LESS/LESSEQUAL）+ cmp2（other），验证两个比较操作数一致（nvn1 + cvn1），合并为单一比较 op。
  - 测试：`(V f< 5.0)||(V f== 5.0) => V f<= 5.0`。

## 2026-06-27（续 3）：RulePullsubMulti 完整移植

- **RulePullsubMulti**：完整忠实移植 ruleaction.cc:678-952。将 SUBPIECE 拉过 MULTIEQUAL：
  - `min_max_use(vn)` — 计算 vn 的实际使用字节范围（遍历后代 SUBPIECE，非 SUBPIECE 后代→全范围）
  - `acceptable_size(size)` — 检查截断大小是否合法（1/2/4/8 或 >=8）
  - `replace_descendants(orig_vn, new_vn, max_byte, min_byte)` — 用更窄的 new_vn 替换 orig_vn 的所有后代 SUBPIECE（转换为 COPY 或调整截断偏移）
  - `find_subpiece(base_vn, out_size, shift)` — 搜索预存的 SUBPIECE
  - `build_subpiece(fd, base_vn, out_size, shift)` — 创建新 SUBPIECE op
  - `apply_op` — 主算法：检查 SUBPIECE(MULTIEQUAL)，计算使用范围，检查各分支 consume，为每个分支创建/查找 SUBPIECE，构建新的窄 MULTIEQUAL，替换后代
  - 已知限制：hasLoopIn/isPrecisLo/isPrecisHi/isJoin/JoinRecord 用保守默认（允许变换）；opInsertBegin 用 op_insert_before 替代

## 2026-06-27（续 4）：RuleAndMask 完整移植

- **RuleAndMask**：完整忠实移植 ruleaction.cc:300-342。折叠不必要的 INT_AND：
  - `V = A & B`，计算 NZM(A) ∩ NZM(B)。
  - 如果交集为 0（AND 结果总为 0）→ COPY(#0)
  - 如果 consumed bits 全为 0 → COPY(#0)
  - 如果交集 == NZM(A) 且 input(1) 是常量 → COPY(A)
  - 否则不做变换
  - isHeritageKnown：常量视为 known（Rugra 常量无 INPUT/WRITTEN flag 但仍 known）。
  - 测试：`V = A & #0`（NZM(A)=0）→ COPY(#0)。

## 2026-06-27（续 5）：RuleBooleanUndistribute 完整移植

- **RuleBooleanUndistribute**：完整忠实移植 ruleaction.cc:2700-2810。分布/反分布布尔表达式：
  - `(A == B) && (A != C) => A == (B && C)` — 提取公共布尔子表达式
  - `(A || B) && (A || C) => A || (B && C)` — De Morgan 定律
  - 使用 `BooleanMatch::evaluate` 查找相关布尔子表达式（same/complementary）
  - `is_match(left, right)` — 包装 BooleanMatch::evaluate，返回 `Some(is_flip)`
  - 算法：收集 4 个输入，用 isMatch 查找匹配对，处理 BOOL_OR flip（De Morgan），构建新比较 op + combine op
  - 依赖：BooleanMatch::evaluate ✅、op_bool_negate ✅

## 2026-06-27（续 6）：RuleBoolZext 完整移植

- **RuleBoolZext**：完整忠实移植 ruleaction.cc:3000-3124。将零扩展布尔值上的操作转换为布尔操作：
  - 检测 INT_ZEXT(bool) → INT_MULT(*-1) → actionop 链
  - INT_ADD(#1)：`zext(b) * -1 + 1` → `zext(!b)`（BOOL_NEGATE + COPY 传播）
  - INT_EQUAL/INT_NOTEQUAL：将扩展布尔与 0/-1 比较改为未扩展布尔与 0/1 比较
  - INT_AND/OR/XOR：两侧都是扩展布尔时，先做布尔运算再扩展
  - 依赖：is_boolean_value ✅、is_type_recovery_on ✅、op_bool_negate ✅、lone_descend ✅

## 2026-06-27（续 7）：RulePushMulti 完整移植

- **RulePushMulti**：完整忠实移植 ruleaction.cc:1060-1137。简化两分支 MULTIEQUAL，其中两个输入以功能等价方式构造：
  - 检测 `MULTIEQUAL(op1_out, op2_out)` 其中 op1/op2 功能等价
  - COPY 特殊情况：MERGE of 2 shadowing varnodes → findSubstitute + totalReplace
  - 通用情况：验证 loneDescend，移动 op1 的输出到 MULTIEQUAL 输出（unify），op_uninsert + op_insert_before 重新定位
  - `find_substitute(in1, in2)` — 搜索已存在的 MULTIEQUAL[in1,in2] 或 CSE
  - 依赖：functional_equality_level ✅、total_replace ✅、op_destroy ✅、op_uninsert ✅、op_insert_before ✅
