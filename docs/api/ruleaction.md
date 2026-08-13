# `ruleaction.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/ruleaction.rs`
**2026-07-02 修复（R9）**: `RuleTrivialArith` 重写为忠实移植 Ghidra ruleaction.cc:2370-2433——同输入坍缩（`x^x→0`/`x==x→1`/`x!=x→0`/`x^^x→0`/`x&&x→x` 等），输入须 Arc::ptr_eq 或 is_cse_match。原 Rugra 实现做了 `RuleIdentityEl` 的活（`x+0→x`），从不执行同输入坍缩 → `x^x` 残留。getOpList 改为 Ghidra 16 opcode。3 个旧测试（add_zero/mult_one/sub_zero）重定向到 `RuleIdentityEl`（其本应处理），3 个新测试覆盖 x^x→0/x==x→1/distinct-no-change。

Rule-based transformations for P-code operations

Corresponds to Ghidra's `ruleaction.hh`. Rules are small, local
transformations that target specific opcodes to simplify the IR.

## 2026-08-13：RuleCollectTerms 定宽系数与常量归并

`RuleCollectTerms::apply_op` 现在按锁定 Ghidra 12.0.4
`ruleaction.cc:107-176` 执行两种定宽加法：相同项系数使用 64 位无符号
`wrapping_add` 后再以项的 storage size mask 截断；常量项也先按 `uintb`
回绕、再按常量 Varnode 的 size 截断。因此 1-byte 的 `0xff + 2` 与 8-byte
的 `UINT64_MAX + 2` 都得到 `1`，不会在 Rust overflow-check 构建中 panic。

常量归并严格从排好序的尾部倒序扫描。`lastconst` 最终指向排序后第一个
非零常量边；该边接收总和，所有后续、未被外层乘法包裹的常量边按原顺序
替换为零。这修复了原正序扫描留下多个非零常量、且选择错误输入槽的问题。

锁定 oracle fixture `tests/oracle/rule_collect_terms_1204.{cc,rs}` 对七组同输入
IR 逐字节比较，包括非溢出、storage-mask 回绕、`uintb` 固定 64 位回绕和结果
为零的相同项系数，以及三组常量归并。目标相关的结构观察保留
block/alive/dead 顺序、parent/SeqNum order、每个输入槽与输出、所有 fixture
追踪和变换新建 Varnode 的 SSA 分类、def 和有序 descendants；仅规范化
allocation-only unique-space offset。这个窄 fixture 不声称观察 PcodeOp/Varnode
的所有非目标 flags、type/symbol/high 状态，也不能消除 `OPBANK-0001`
中 nullable input slot 被 Rugra 临时 sentinel Varnode 代替的 whole-bank 差异。root guard、
`distributeIntMultAdd` 两分支和无可归并项的 NO_CHANGE 路径仍单列为
`UNTESTED`。其他未覆盖路径还包括 helper 的三种系数回退、all-constant 根、
初始零和多于两个常量、multiplier constant-edge skip 与共享 ADD 边界；
多个 `termOrder == 0` 的等价项还需对拍 Ghidra `std::sort` 的 tie 重排顺序；
不能据此把整个 Rule 升为 L3。
因此 runner 的合格结论仅为七个目标结构投影 `PARTIAL_MATCH`，不是逐函数
B2 `MATCH`；整个 Funcdata/VarnodeBank 仍受 `OPBANK-0001` 阻断。
另外，完整架构服务图仍受 `ARCH-0001` 阻断，新建 Varnode 的 TypeFactory 类型身份
仍属 `TYPE-UNKNOWN-0001` 未验证依赖。

## 2026-08-11：FLOAT_INT2FLOAT 零扩展宽度

`RuleUnsigned2Float::apply_op` 和 `RuleInt2FloatCollapse::apply_op` 不再维护局部
宽度近似；两者现在与 Ghidra `ruleaction.cc:9822/9888` 一样调用
`TypeOpFloatInt2Float::preferred_zext_size`。这修正了 1 字节输入（旧值 2、正确值 4）
和 8 字节输入（旧值 8、正确值 9），并由直接编译 Ghidra 12.0.4
`typeop.cc` 的 oracle fixture 验证。此次只确认共享宽度语义；两个 Rule 的完整
CFG/IR 变换仍按各自既有状态管理，不能由本项单独升级为 L3。

## 2026-08-11：Ghidra 12.0.4 引用 bootstrap

`GATE-REF-RULEACTION` 使用锁定 oracle commit
`e40ed13014025f82488b1f8f7bca566894ac376b` 重新核对
`RuleTransformCpool::applyOp`，并将 `ruleaction.rs` 唯一越界的源码引用修正为
实际对应的 `RuleExpandLoad::applyOp` 定义起始行 `ruleaction.cc:10919`。本次只修复
12.0.4 源码引用元数据，不改变 Rust 行为，不产生函数 oracle `MATCH`，也不升级
模块状态。

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
使用 `expression.rs` 的 `TermOrder` 收集/排序所有项。

测试：ruleaction::tests +1（常量折叠 3+5→8）。

### 2026-06-26（续）：RuleCollectTerms 完整形式

更新 RuleCollectTerms 使用 `distribute_int_mult_add` 处理 INT_MULT 系数场景（ruleaction.cc:130-133）。
该路径尚未经锁定 oracle fixture 覆盖，不作完整对齐声明。

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

旧测试曾宽松接受未折叠值；2026-08-13 对齐工作已将此改为精确槽位和常量值断言。

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

## 2026-06-27（续 8）：RuleSelectCse 完整移植

- **RuleSelectCse**：完整忠实移植 ruleaction.cc:178-209。在 SUBPIECE/INT_SRIGHT 的 input(0) 后代中查找公共子表达式：
  - 收集与给定 op 相同 opcode 且 CSE hash 非零的后代 ops
  - 调用 `Funcdata::cse_eliminate_list` 进行排序+匹配+消除
  - 依赖：get_cse_hash ✅、is_cse_match ✅、cse_eliminate_list ✅、cse_elimination ✅

## 2026-06-27（续 9）：清理规则移植

- **RuleMultNegOne**：完整移植 ruleaction.cc:7171-7190。`V * -1 => -V`（INT_MULT + all-ones → INT_NEG）。
- **RuleSub2Add**：完整移植 ruleaction.cc:4030-4056。`V - W => V + (W * -1)`（INT_SUB → INT_ADD + INT_MULT(*-1)）。使加法项重排规则能匹配。
- **RuleSubExtComm**：完整移植 ruleaction.cc:4410-4461。SUBPIECE 穿过 INT_ZEXT/INT_SEXT：
  - SUBPIECE 不触及扩展位 → COPY/直接替换
  - 否则创建中间 SUBPIECE + 重写为 zext/sext

## 2026-06-27（续 10）：更多清理规则移植

- **Rule2Comp2Mult**：完整移植 ruleaction.cc:3980-3995。`-V => V * -1`（INT_NEG → INT_MULT + 插入 -1 输入）。
- **Rule2Comp2Sub**：完整移植 ruleaction.cc:7236-7256。`-V => 0 - V`（INT_NEG → INT_SUB + 插入 0 输入）。
- **RuleCarryElim**：完整移植 ruleaction.cc:3997-4030。`carry(V,c) => -c <= V`（INT_CARRY + 常量 → INT_LESSEQUAL）；`carry(V,0) => false`。

## 2026-06-27（续 11）：Zext 交换/简化规则

- **RuleConcatZext**：完整移植 ruleaction.cc:4806-4842。`concat(zext(V), W) => zext(concat(V, W))`（PIECE + ZEXT → 新 PIECE + ZEXT）。
- **RuleZextCommute**：完整移植 ruleaction.cc:4844-4875。`zext(V) >> W => zext(V >> W)`（INT_RIGHT + ZEXT → 新 INT_RIGHT + ZEXT）。
- **RuleZextShiftZext**：完整移植 ruleaction.cc:4877-4919。简化多重 ZEXT：
  - `zext(zext(V)) => zext(V)`（loneDescend 验证）
  - `zext(zext(V) << c) => zext(V) << c`（检查 shift 不丢失扩展位）

## 2026-06-27（续 12）：SUBPIECE/PIECE 简化规则

- **RuleShiftSub**：完整移植 ruleaction.cc:5201-5230。`sub(V << 8*k, c) => sub(V, c-k)`（SUBPIECE + INT_LEFT → 调整截断偏移）。
- **RuleHumptyDumpty**：完整移植 ruleaction.cc:5232-5281。合并拆分+重组：
  - `concat(sub(V,c), sub(V,0)) => V`（完整重组）
  - `concat(sub(V,c), sub(V,d)) => sub(V,d)`（部分重组）
- **RuleDumptyHump**：完整移植 ruleaction.cc:5283-5337。简化连接+拆分：
  - `sub(concat(V,W), 0) => W`（完整消除）
  - `sub(concat(V,W), c) => sub(W,c)` 或 `sub(V,c-k)`（部分消除）

## 2026-06-27（续 13）：SUBPIECE 消除 + OR 重组规则

- **RuleSubCancel**：完整移植 ruleaction.cc:5115-5199。SUBPIECE 应用于扩展运算的消除：
  - INT_AND + 掩码：`sub(V & mask, 0) => V`（当 mask == calc_mask(outsize)）
  - INT_ZEXT/INT_SEXT：`sub(zext(V), 0)` → COPY（完全消除）或 SUBPIECE（部分）
  - INT_ZEXT + 高偏移：`sub(zext(V), c)` 当 c >= insize → COPY(#0)
- **RuleHumptyOr**：完整移植 ruleaction.cc:5339-5420。简化掩码 OR 重组：
  - `(V & ff00) | (V & 00ff) => V`（所有位覆盖 → COPY）
  - `(V & W) | (V & X) => V & (W|X)`（部分覆盖 → AND）
  - 非常量掩码：创建 INT_OR(b,c) + INT_AND(a,result)，检查 NZMask 防止 RuleAndDistribute 反转

## 2026-06-27（续 14）：比较简化规则

- **RuleEqual2Zero**：完整移植 ruleaction.cc:5857-5924。简化与 0 的比较：
  - `0 == V + W * -1 => V == W`（乘以 -1 的形式）
  - `0 == V + c => V == -c`（常量偏移形式）
  - 验证 addvn 的所有后代都是布尔比较（isBoolOutput）

## 2026-06-27（续 15）：移位消除 + 条件翻转规则

- **RuleShiftAnd**：完整移植 ruleaction.cc:4921-4975。消除被移位丢弃的 INT_AND：
  - `(V & mask) >> sa => V >> sa`（当移位后的 mask 覆盖所有 NZM 位）
  - 支持 INT_RIGHT/INT_LEFT/INT_MULT（2 的幂）
- **RuleCondNegate**：完整移植 ruleaction.cc:5478-5510。翻转带 boolean_flip 标志的 CBRANCH：
  - 插入 BOOL_NOT 取反条件，调用 op_flip_condition 清除标志
  - 依赖：is_boolean_flip ✅、op_bool_negate ✅、op_flip_condition ✅（新增）

## 2026-06-27（续 16）：XOR/比较简化规则

- **RuleXorSwap**：完整移植 ruleaction.cc:10614-10650。`(V ^ W) ^ V => W`（XOR 链简化）。
- **RuleEqual2Constant**：完整移植 ruleaction.cc:5926-5990。简化算术表达式与常量的比较：
  - `(V + c) == d => V == (d - c)`（加法常量偏移）
  - `(V * -1) == d => V == -d`（乘 -1）
  - 验证 lhs 的所有后代都是比较
  - 跳过 INT_NEGATE 情况（Rugra 缺少此 opcode）
- **RuleOrCompare**：完整移植 ruleaction.cc:10808-10872。分配 INT_OR 到比较：
  - `(V | W) == 0 => V == 0 && W == 0`（INT_EQUAL → BOOL_AND）
  - `(V | W) != 0 => V != 0 || W != 0`（INT_NOTEQUAL → BOOL_OR）

## 2026-06-27（续 17）：ConcatCommute 规则

- **RuleConcatCommute**：完整移植 ruleaction.cc:4675-4748。逻辑运算与拼接的交换：
  - `concat(V, W) | c => concat(V | c_hi, W) | c_lo`（INT_OR/INT_XOR 交换进 PIECE）
  - `concat(V, W) & c => concat(V & c_hi, W & c_lo)`（INT_AND 交换进 PIECE）
  - 常量值根据高低位偏移调整

## 2026-06-27（续 18）：LZCOUNT 简化规则

- **RuleLzcountShiftBool**：完整移植 ruleaction.cc:10660-10712。简化使用 lzcount 的相等检查：
  - `lzcount(X) >> c => X == 0`（当 X 大小为 2^c 字节时，lzcount 的最高位指示是否为 0）
  - 仅对 2 的幂大小生效（popcount(max_return) == 1）
  - 将移位后代替换为 INT_EQUAL + COPY/ZEXT

## 2026-06-27（续 19）：ThreeWayCompare 规则

- **RuleThreeWayCompare**：完整移植 ruleaction.cc:9949-10263（~230 行）。简化三方比较表达式：
  - 三方比较 = `zext(V < W) + zext(V <= W) - 1`，结果为 -1/0/1
  - `detect_three_way(addop)` — 检测 INT_ADD(zext(cmp1), zext(cmp2)) 模式
  - `test_compare_equivalence(lessop, lessequalop)` — 验证两个比较操作等价
  - 对 24 种 form 组合（const 值 × 位置 × 比较类型）分别重写为直接比较
  - 包括：always true/false、a<b、a<=b、a>b、a>=b、a==b、a!=b

## 2026-06-27（续 20）：MultiCollapse 规则

- **RuleMultiCollapse**：完整移植 ruleaction.cc:3246-3363。折叠所有输入追溯到相同值的 MULTIEQUAL：
  - 使用 functional_equality_level 检查输入是否绝对等价或功能等价
  - 处理嵌套 MULTIEQUAL：将非匹配的 MULTIEQUAL 输入展开到匹配列表
  - 循环构造检测：is_mark 表示值在循环中递归（跳过处理）
  - 绝对等价：total_replace + op_destroy 所有 MULTIEQUAL
  - 功能等价：同样 total_replace（Rugra 缺 cseFindInBlock/earliestUse，用保守替换）
  - 已知限制：cseFindInBlock/earliestUse/opSetAllInput 用保守 total_replace 替代

## 2026-06-27（续 21）：除法优化规则

- **RuleSignDiv2**：完整移植 ruleaction.cc:8357-8408。`(V + -1*(V s>> 31)) s>> 1 => V s/ 2`（有符号除以 2 的编译器惯用法简化）。
- **RuleDivChain**：完整移植 ruleaction.cc:8410-8455。折叠连续除法：
  - `(x / c1) / c2 => x / (c1*c2)`（相同符号 INT_DIV/INT_SDIV）
  - `(x >> c1) / c2 => x / (2^c1 * c2)`（无符号 INT_RIGHT + INT_DIV）
  - 中间结果必须 loneDescend（仅在此处使用）

## 2026-06-27（续 22）：符号提取归一化规则

- **RuleSignForm**：完整移植 ruleaction.cc:8449-8492。`sub(sext(V), c) s>> n => V s>> (8*|V|-1)`（归一化符号位提取）。
- **RuleSignForm2**：完整移植 ruleaction.cc:8494-8570。`sub(sext(V) * small, c) s>> 31 => V s>> 31`（当 small 是小的正整数且不溢出到符号位时）。

## 2026-06-27（续 23）：除法/移位优化规则

- **RulePositiveDiv**：完整移植 ruleaction.cc:7803-7830。当两个输入保证非负时，将 INT_SDIV→INT_DIV / INT_SREM→INT_REM（检查 NZMask 符号位）。
- **RuleDoubleArithShift**：完整移植 ruleaction.cc:1930-1964。`(V s>> c) s>> d => V s>> (c+d)`（合并连续有符号右移，饱和到最大移位）。
- **RuleSignNearMult**：完整移植 ruleaction.cc:8543-8610。将近乘法形式转换为有符号除法：`(X + ((X s>> n-1) >> k)) * c => (X s/ 2^n) * 2^n`，其中 c = 2^n。

## 2026-06-27（续 24）：浮点转换简化

- **RuleFloatCast**：完整移植 ruleaction.cc:9545-9602。简化冗余浮点转换链：
  - `float2float(float2float(V)) => float2float(V)`（当外层冗余时）
  - `float2float(int2float(V)) => int2float(V)`（整数直接转最终浮点大小）
  - `trunc(float2float(V)) => trunc(V)`（浮点直接转最终整数大小）

## 2026-06-27（续 25）：SUBPIECE 归一化

- **RuleSubNormal**：完整移植 ruleaction.cc:7700-7803。归一化 SUBPIECE 应用于移位结果：
  - `sub(V >> n, c) => V >> n'`（合并移位+截断，字节对齐时消除多余移位）
  - 处理溢出情况：当截断超出输入大小时，创建额外扩展（ZEXT/SEXT）
  - 饱和移位：当剩余移位超过输出大小时，饱和到最大值

## 2026-06-27（续 26）：有符号模运算优化

- **RuleSignMod2nOpt**：完整移植 ruleaction.cc:8650-8769。将有符号模运算惯用法转换为 INT_SREM：
  - `(V + (sign >> (64-n)) & (2^n-1)) - (sign >> (64-n)) => V s% 2^n`
  - `sign = V s>> (size*8-1)`（符号提取）
  - 支持截断形式（INT_ZEXT 介入 INT_AND 后）
  - 辅助函数 `check_sign_extraction(out_vn)` — 验证 `V s>> (size*8-1)` 模式，返回 V
  - 遍历 correct_vn 的后代，检测完整的 mult(-1) → add → and(mask) → add(V, shift(sign)) 链

### 2026-06-27（会话2 续）：RuleDivOpt

- `RuleDivOpt` — `RuleDivOpt`（ruleaction.cc:8069-8355）：除法乘法编码还原。`sub(ext(V)*c, d) >> e` / `sub(ext(V)*c) >> e` / `(ext(V)*c) >> n` → `V / divisor`。
  - `find_form` — `findForm`（8069）：检测 shift→subpiece→mult→zext/sext 链，返回 (in_vn, n, y128, xsize, ext_opc)
  - `calc_divisor` — `calcDivisor`（8157）：从乘法编码 c 反推除数（u128 运算）
  - `check_form_overlap` — `checkFormOverlap`（8260）：检测 SUBPIECE 形式是否被上级 shift 形式包含
  - `apply_op` — `applyOp`（8295）：三种尺寸分支（需扩展/需截断/同尺寸）转换

**注**：此前误记"缺第二变体 ruleaction.cc:8010-8046"——核实后确认该段是**独立的 RuleDivTermAdd2**（另一个 Rule），非 RuleDivOpt 的一部分。RuleDivOpt 本身完整对应 8295-8355。
### 2026-06-27（续）：RuleEarlyRemoval 补齐 Ghidra 6 守卫
- RuleEarlyRemoval::apply_op 补 is_indirect_source/is_auto_live/空间门（ruleaction.cc:30-40）。因 descend 追踪有缺口（多处直接 push inrefs 绕过 op_set_input），空间门保守只允许 CONSTANT 输出删除。REGISTER/UNIQUE 待 descend 追踪完整后放开。
2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。

### 2026-06-29：RuleSubCommute（ruleaction.cc:4534-4673）

- `RuleSubCommute` — SUBPIECE 与二元算术的 commute：`SUBPIECE(INT_ADD(a,b), 0) → INT_ADD(SUBPIECE(a,0), SUBPIECE(b,0))`。把截断推进算术内部，使操作数能用更小宽度类型化。
- 触发于 CPUI_SUBPIECE；支持的 longform op：INT_ADD/INT_MULT/INT_NEGATE/INT_XOR/INT_AND/INT_OR（offset 任意）、INT_LEFT/INT_DIV/INT_REM（offset==0）、INT_SDIV/INT_SREM（需 sign_extend，deferred）。
- 守卫：base 必须 loneDescend == op（cc:4641）；INT_LEFT 的 in(0) 必须是 ZEXT/PIECE；INT_DIV/INT_REM 的输入必须是 ZEXT。
- 2 单元测试：test_rule_sub_commute_add（验证转换）+ test_rule_sub_commute_no_lone_descend（验证守卫）。注册进 oppool1（5577）。
- 实测 curl/httpd 未触发（curl 的 P-code 已被前置简化），但模式匹配时正确生效。

### 2026-06-29：RuleFloatSign（ruleaction.cc:10714 + typeop.cc:153）
- `RuleFloatSign` — 检测浮点符号位操作并转换为 FLOAT_ABS/FLOAT_NEG：`x & 0x7fffffff => FLOAT_ABS(x)`，`x ^ 0x80000000 => FLOAT_NEG(x)`。辅助函数 `float_sign_manipulation` 对应 Ghidra `TypeOp::floatSignManipulation`（typeop.cc:153-176）。
- 触发于所有 FLOAT_ opcodes（18 个）。注册进 oppool1（5619）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续）：RuleSLess2Zero（ruleaction.cc:5711 + getHiBit 5659）
- `RuleSLess2Zero` — 简化 INT_SLESS 与 0/-1 的比较。形式包括：`-1 s< SUB(V,hi) => -1 s< V`、`~V s< 0 => -1 s< V`、`-1 s< CONCAT(V,W) => -1 s< V` 等。辅助函数 `get_hi_bit` 对应 Ghidra `getHiBit`（ruleaction.cc:5659-5682）。
- 触发于 CPUI_INT_SLESS。注册进 oppool1（5558）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 2）：RulePopcountBoolXor（ruleaction.cc:10265 + getBooleanResult 10335）
- `RulePopcountBoolXor` — 简化通过 POPCOUNT 组合的布尔表达式：`popcount((b1 << 6) | (b2 << 2)) & 1 => b1 ^ b2`。辅助函数 `get_boolean_result` 对应 Ghidra `getBooleanResult`（ruleaction.cc:10335-10419），追踪 INT_AND/XOR/OR/ZEXT/SEXT/LEFT 链提取布尔源。
- 触发于 CPUI_POPCOUNT。注册进 oppool1（5616）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 3）：RuleModOpt（ruleaction.cc:8612）
- `RuleModOpt` — 简化 INT_DIV/INT_SDIV 的模运算表达式：`x/d * (-d) + x => x%d`。检测 div2 是 div 的二补数（常量或 INT_2COMP）。
- 指针守卫：若任一输入是指针类型则跳过（防止指针算术被误匹配）。
- 触发于 CPUI_INT_DIV/CPUI_INT_SDIV。注册进 oppool1（5602）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 4）：RuleDivTermAdd（ruleaction.cc:7832 + findSubshift 7928）
- `RuleDivTermAdd` — 简化优化的除法表达式：`sub(ext(V)*c,b)>>d + V => sub((ext(V)*(c+2^n))>>n, 0)`，其中 n=d+b*8。
- 使用 Rust 原生 `u128` 替代 Ghidra 的 128 位多精度算术（set_u128/leftshift128/add128）。`is_constant_extended` 已存在（varnode.rs），`new_extended_constant` 新增到 funcdata.rs（funcdata_varnode.cc:462 忠实移植）。
- 辅助函数 `find_subshift` 对应 Ghidra `findSubshift`（ruleaction.cc:7928-7953）。
- 触发于 CPUI_SUBPIECE/INT_RIGHT/INT_SRIGHT。注册进 oppool1（5594）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 5）：RuleDivTermAdd2（ruleaction.cc:7955）
- `RuleDivTermAdd2` — 简化优化的除法表达式变体：`W+((V-W)>>1) => sub((zext(V)*(c+2^n))>>(n+1), 0)`，其中 W=sub(zext(V)*c,d)，n=d*8。使用 Rust 原生 u128。
- 指针守卫：若输入是指针类型则跳过。
- 触发于 CPUI_INT_RIGHT（shift==1）。注册进 oppool1（5595）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 6）：RuleSignMod2nOpt2（ruleaction.cc:8867）
- `RuleSignMod2nOpt2` — 转换 INT_SREM 形式：`V - (Vadj & ~(2^n-1)) => V s% 2^n`。
- 实现了 `check_sign_ext_form` 路径（INT_ADD，CDQ 风格符号扩展，ruleaction.cc:8928-8952）。
- MULTIEQUAL 路径（`checkMultiequalForm`）需块结构访问（getParent/getIn/getTrueOut），deferred。
- 触发于 CPUI_INT_MULT。注册进 oppool1（5604）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 7）：RuleSignMod2nOpt 去重确认
- `RuleSignMod2nOpt`（ruleaction.cc:8673）此前已完整实现并注册（oppool1 5603）。本轮清理了意外添加的重复定义。现有实现含 `check_sign_extraction` 辅助函数 + 完整模式匹配（含 trunc_size/ZEXT/SUBPIECE 变体）。

### 2026-06-29（续 8）：RuleSignMod2Opt（ruleaction.cc:8794）
- `RuleSignMod2Opt` — 转换 INT_SREM 特殊形式：`(V-sign)&1+sign => V s% 2`（sign = V s>> 63）。是 RuleSignMod2nOpt 的 mod-2 特化。
- 复用 `check_sign_extraction` 辅助函数。支持 SUBPIECE 截断变体。
- 触发于 CPUI_INT_AND。注册进 oppool1（5605）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-06-29（续 9）：RuleShiftPiece（ruleaction.cc:3791）
- `RuleShiftPiece` — 检测 `(zext(V) << #sa) | zext(V)` 并转换为 PIECE。也处理 CDQ 特殊情况（INT_SRIGHT 形成高位 → INT_SEXT）。两条路径均为纯数据流，无需块结构。
- 触发于 CPUI_INT_OR/INT_XOR/INT_ADD。注册进 oppool1（5549）。
- 验证：780/780 测试，curl 24/24，httpd 29/29 gcc 审计通过。

### 2026-07-01：oppool1 + cleanup 池大批补缺 Rule（21 条 + DivOpt 修复）

**Bug 修复**：
- `RuleDivOpt`（ruleaction.cc:8295）：补上 signed-division 路径缺失的 `moveSignBitExtraction` 调用（Ghidra ruleaction.cc:8335）。忠实移植 `moveSignBitExtraction`(8210-8253) 为 `move_sign_bit_extraction` + 辅助 `resolve_shift_const`。

**cleanup 池新增（coreaction.cc:5696-5708）**：
- `RuleAddUnsigned`(7200) — INT_ADD，`V+0xff..⇒V-0x00..`（数值变换 1:1）
- `RuleSubRight`(7269) — INT_SUB，sub right 规范化（含 lone-shift lump）
- `RuleFloatSignCleanup`(10789) — floatSignManipulation 1:1
- `RuleExpandLoad`(10937) — helpers(checkAndComparison/modifyAndComparison) 1:1；applyOp 标 TODO（需 pointer datatype）
- `RulePtrsubCharConstant`(7372) — pushConstFurther helper 1:1；applyOp 标 TODO（需 TYPE_SPACEBASE/Scope/stringManager）
- `RuleExtensionPush`(7435) — descendant-count guard 1:1；duplicateNeed 标 TODO
- `RulePieceStructure`(7625) — helpers(determineDatatype/spanningRange/convertZextToPiece) 占位 1:1；applyOp 标 TODO（需 structured types）

**oppool1 独立族新增**：
- `RulePullsubIndirect`(962) — 可触发非 creation 分支（复用 RulePullsubMulti helpers）；indirect-creation/iop 分支标 TODO
- `RuleIndirectCollapse`(3177) — 标 TODO（需 iop-space coderef + characterizeOverlap）
- `RuleTransformCpool`(3915) — 标 TODO（Funcdata 无 get_arch/cpool accessor）
- `RuleSwitchSingle`(5430) — 标 TODO（需 findJumpTable/getStructure）
- `RuleNegateNegate`(9258) — **完全可触发**（`~~V⇒V`）
- `RuleConditionalMove`(9390) — checkBoolean helper 1:1；applyOp 标 TODO（需 block graph）
- `RuleFuncPtrEncoding`(9926) — 标 TODO（Funcdata 无 get_arch/funcptr_align）
- `RuleIgnoreNan`(9740) — 标 TODO（需 nan_ignore_all + block 查询）
- `RuleUnsigned2Float`(9795) — **可触发**（pattern+变换 1:1）
- `RuleInt2FloatCollapse`(9863) — 标 TODO（需 FlowBlock::findCondition）
- `RulePtraddUndo`(6927) — 标 TODO（需 hasTypeRecoveryStarted + opUndoPtradd）
- `RulePtrsubUndo`(7146) — **4 helper(getConstOffsetBack/getExtraOffset/removeLocalAddRecurse/removeLocalAdds) 1:1 完全移植**；applyOp 标 TODO（需 isPtrsubMatching）
- `RuleSegment`(9013) — 标 TODO（需 SegmentOp/userops）
- `RulePiecePathology`(10578) — INDIRECT case wired via `fd.get_op_from_const` + `is_call()` (对齐 ruleaction.cc:10453-10464). 标 TODO（bytes-consumed API for tracePathologyForward）

验证：832/832 测试（新增 13），curl 24/24 无回归。

**基础设施缺口（TODO 清单，均已在代码注释标注，未绕过）**：
1. Varnode 数据类型系统（get_type_read_facing/TYPE_UINT/TYPE_FLOAT/isCharPrint 等）
2. Funcdata 无 `get_arch()` 访问器（影响 TransformCpool/FuncPtrEncoding/IgnoreNan）
3. iop-space / coderef 解析缺失（影响 IndirectCollapse/PullsubIndirect）
4. block graph 访问（影响 ConditionalMove/Int2FloatCollapse/IgnoreNan 的 CBRANCH 路径）
5. Varnode flag/overlap API（isAddrForce/isTypeLock/isPrecisLo/Hi 等）
6. Funcdata 高级 op API（opUndoPtradd/newIndirectCreation/newVarnodeIop 等）

### 2026-07-01（续 2）：Layer-3 TODO 替换 — 接入基础设施让 Rule 生效
11 个 Rule 的 TODO 占位替换为真实基础设施调用：
- **RuleExtensionPush**(7435): is_addr_force/is_type_lock/is_name_lock + duplicate_need
- **RulePtraddUndo**(6927): has_type_recovery_started + op_undo_ptradd + type guard
- **RuleTransformCpool**(3915): get_arch().cpool + op_mark_cpool_transformed + CPoolRecord
- **RuleFuncPtrEncoding**(9926): get_arch().funcptr_align + mask compare
- **RuleIgnoreNan**(9740): get_arch().nan_ignore_all + find_condition
- **RuleInt2FloatCollapse**(9863): find_condition + cbranch flip
- **RuleIndirectCollapse**(3177): characterize_overlap/contains_storage + get_op_from_const + total_replace
- **RuleExpandLoad**(10937): space from_id + get_type/get_sub_type
- **RulePullsubIndirect**(962): is_addr_force/is_precis_lo/hi + new_varnode_iop/get_op_from_const
- **RulePtrsubUndo**(7146): is_ptrsub_matching + remove_local_adds(op->getOut())
- **RuleConditionalMove**(9390): get_true_out/get_false_out (bool-const-const path)

仍保留为 guard+no-op（需更深基础设施）：RulePtrsubCharConstant(需 stringManager)、RulePieceStructure(需 PieceNode/gatherPieces)、RuleIgnoreNan 深度路径、RuleConditionalMove 非 const 路径、RuleIndirectCollapse 创建/空间库分支。每处 TODO 精确标注缺失项。

### 2026-07-01（续 3）：Layer-5 TODO 替换 — update_type/new_indirect_creation/find_jump_table/get_store_guard
- RulePtrsubCharConstant: push_const_further 加 outtype 参数 + update_type（cc:7351）
- RuleExpandLoad: modify_and_comparison 加 dt 参数 + update_type ×2（cc:10915）
- RuleExpandLoad apply: new_out update_type（cc:10994）
- RuleAddUnsigned: copy_symbol（cc:7228）
- RulePullsubIndirect: indirect-creation 分支完整移植 new_indirect_creation（cc:998-1002）
- RuleIndirectCollapse: STORE guard 完整移植 get_store_guard + is_guarded（cc:3223-3236）
- RuleSwitchSingle: 完整 applyOp（find_jump_table + jt 判断 + BRANCH 改写 + remove_jump_table + structure clear，cc:5430-5477）

### 2026-07-01（续 4）：Layer-6 剩余 TODO 填补（12 处）
RuleAddUnsigned: get_type_read_facing + TYPE_UINT/!is_char_print 守卫。RuleSubRight: does_special_printing + is_piece_structured + is_addr_tied + get_base_type(Uint/Int)+update_type。RuleFloatSignCleanup: TYPE_FLOAT 判断。RuleExpandLoad: get_base_type(Uint) 重写。RuleIndirectCollapse: has_no_local_alias + no_indirect_collapse + INDIRECT_CREATION。RuleSwitchSingle: warning_header 替换 eprintln。RulePtrsubUndo: clear_stop_type_propagation + op_undo_ptradd 完整接入。RuleSegment: userops.get_segment_op 接入 + contiguous_test/findContiguousWhole 移植。RuleTransformCpool: tf.find_by_name(rec.type_name) + update_type_lock。剩余 10 处 TODO 每处精确标注缺失 API（SymbolEntry/resolveConstant/PieceNode/CloneBlockOps/functionalEquality/SegmentOp.execute）。

### 2026-07-01（续 5）：determine_datatype partial path + RulePtrsubCharConstant full transform
- determine_datatype（ruleaction.cc:7481-7510）：partial 路径用 get_structured_type + get_symbol_entry + SymbolEntry::get_addr/get_offset + get_sub_type walk 实现。不再对 partial 返回 None。
- RulePtrsubCharConstant（ruleaction.cc:7372-7421）：完整 transform。用 Funcdata::string_table 做 read-only+string 检查（symaddr=vn1 offset，spacebase base=0）。PTRSUB→COPY of constant pointer + update_type。删除 resolveConstant/isReadOnly TODO（退化 via string_table）。

### 2026-07-01（续 6）：oppool2 完整移植（5 条 Rule，0%→100%）
- RuleLoadVarnode（ruleaction.cc:4285）+ correct_spacebase/vn_spacebase/check_spacebase helper — LOAD→COPY 栈变量化。
- RuleStoreVarnode（4339）— STORE→COPY 栈变量化。
- RulePtrArith（6629）+ AddTreeState 状态机 + verify_preferred_pointer/evaluate_pointer_expression — INT_ADD/MULT→PTRADD/PTRSUB。
- RulePushPtr（6852）+ build_varnode_out/collect_duplicate_needs/duplicate_need — 指针 push 到使用点。
- RuleStructOffset0（6678）— struct offset 0 下钻 PTRSUB。
20 新测试。

### 2026-07-01（续 7）：3 条缺失 Rule 实现 + 注册
- RulePtrFlow（ruleaction.cc:9050-9251）：指针流传播+截断。trialSetPtrFlow/propagateFlowToDef/Reads/truncatePointer。注册 oppool1:5624。has_truncations 默认 false（Rugra 无 isTruncated 空间）。
- RuleDumptyHumpLate（subflow.cc:3006-3064）：SUBPIECE(PIECE) 回溯。注册 cleanup:5699。
- RuleOrPredicate（condexe.cc:509-635）：impl Rule trait（包装现有 apply_op）。注册 oppool1:5631。
13 新测试。

### 2026-07-01（续 8）：PieceStructure piece 重组引擎 + Segment 常量折叠
- PieceStructure：PieceNode struct + is_leaf_node + gather_pieces（op.cc:801-876）+ convert_zext_to_piece（cc:7543）+ find_replace_zext + separate_symbol + get_exact_piece + apply_op 真正变换（cc:7625-7718）。4 新测试。
- `RulePieceStructure::apply_op` 在替换非叶 Varnode 后显式传播 `VarnodeBank::destroy_varnode` 的失败；这对应 Ghidra `data.deleteVarnode(vn)` 对仍集成 Varnode 抛出的 `LowlevelError`，不会吞掉结构不变量错误。该错误路径未纳入本次 RuleCollectTerms fixture，状态仍为 `UNTESTED`，不属于下述七个目标结构投影的批准范围。
- Segment：SegmentOp::execute（userop.cc:218）+ supports_far_pointer/has_far_pointer_support。RuleSegment::apply_op 常量折叠分支（cc:9024）+ far-pointer 分支（cc:9034）+ contiguous_test/find_contiguous_whole helper。4 新测试。

### 2026-07-01（续 9）：PiecePathology + IgnoreNan 深度路径
- PiecePathology：isPathology（ruleaction.cc:10427-10505）递归 def 链遍历 + tracePathologyForward（10506-10559）前向 descend 追踪到 CALL/RETURN 记 bytes_consumed。apply_op 双路径（SUBPIECE + INDIRECT）。
- IgnoreNan 深度路径：checkBackForCompare（9622-9662）+ isAnotherNan（9664-9694）+ testForComparison（9696-9738）三种合并路径 + CBRANCH 保护。nan_ignore_all=false 时真正执行 NaN 数据流移除。
- fspec.rs：FuncProto +return_bytes_consumed + FuncCallSpecs +input_consume Vec + getter/setter。

### 2026-07-01（续 10）：4 条 stub/partial Rule 补全
- SubfloatConvert：常量折叠路径（subflow.cc:3394-3403）。非 const 保持 NO_CHANGE（完整 SubfloatFlow 精度追踪 TODO）。
- ConditionalMove 非 const 路径：gather_expression + construct_bool（ruleaction.cc:9305-9381）。值在分支前形成的非 const 情况能产生 BOOL_OR/AND。
- RuleEarlyRemoval：6 guard 全对齐（ruleaction.cc:25-44）。IOP 空间输出新增可删。
- AddTreeState distribute/collapse：while 循环补全（ruleaction.cc:6475-6491）+ collapse_int_mult_mult。

### 2026-07-01（续 11）：PtrsubUndo testForArraySlack + PtrsubCharConstant stringManager
PtrsubUndo：test_for_array_slack（type.cc:990-1005）+ nearest_arrayed_component_forward/backward + get_lower_bound_field。数组 slack 现在允许 PTRSUB。
PtrsubCharConstant：stringManager.is_string 精确守卫（ruleaction.cc:7393）。string_table + is_string 双重确认。6 新测试。

### 2026-07-01（续 12）：empty pairs guard
RulePushMulti find_substitute 对空 pairs 防越界。

### 2026-07-01（续 13）：RulePtrFlow has_truncations=false 是正确行为（非缺陷）
Ghidra 的 `hasTruncations` 检查 `glb->getDefaultDataSpace()->isTruncated()`。`isTruncated` 是地址空间属性（space.hh:94），仅在 16-bit x86 等有段截断的架构上为 true。x86-64 没有截断空间，所以 `has_truncations=false` 对 x86-64 是**正确**的——RulePtrFlow 应该在该架构上不触发。**非缺陷，无需修复**。

### 2026-07-03：命名对齐 Ghidra（camelCase→snake_case）
- 调用点 `v1.contains_storage(&v2)` → `v1.contains(&v2)`（配合 varnode.rs 的 `contains_storage`→`contains` 重命名，对齐 `Varnode::contains`）。
<!-- annotation-pass: 2026-07-04 -->
