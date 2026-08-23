# 批3 函数级对齐审计报告（2026-07-02）— IR/类型基础（抽查 L3 声明）

> 纯只读并发审计。9 个 Agent。判档：✅ALIGN / ⚠️DIFF / ❌MISSING / ➕EXTRA。
> **本批目标是验证"L3 基础已对齐"的声明。结论：声明在 8/9 文件中不实。**

## 批3 跨文件头号根因（按 ROI 排序，续编 R33+）

| # | 根因 | 文件:行 | 直接症状 | Ghidra 对照 |
|---|---|---|---|---|
| R33 | **varnode `eraseDescend`/`destroyDescend` 缺失** | varnode.rs（无） | op-edit 不能切断旧读链 → DCE 失效、僵尸节点（funcdata 审计的机制根源）| varnode.cc:316,344 |
| R34 | **`VarnodeBank::replace` 复制 size/loc 而非重写读者** | varnode.rs:1108 | 任何 substitution Action 语义全错 | varnode.cc:1332-1352 |
| R35 | **`op_set_opcode` 只派生 7 控制流 flag 非 14** | funcdata.rs:515 | getEvalType/isCommutative/isBoolOutput 对 op-edit 路径设的 op 返 0/false → CSE 静默失效 | op.cc:276-285 |
| R36 | **`is_indirect_creation` 在 ruleaction 读 Varnode 非 PcodeOp** | ruleaction.rs:11242 | 读错对象的 flag（两不同 flag 在两不同对象）| op.hh:179 |
| R37 | **opcodes.rs `OpCode::from_i32` 用于 Ghidra 原生整数 → 大多数 op 误分类** | funcdata.rs:2017 | 每个 raw 注入 p-code op（前 3 个外）误分类（如 Ghidra 4=BRANCH→INT_ADD）。代码库 pcodeop.rs:16 自己警告别用 from_i32 | ffi.rs map_ghidra_opcode |
| R38 | **opcodes.rs `64=>CPUI_CAST` 在 FFI map 被注释掉** | ffi.rs:129 | 从 Ghidra 来的 CAST 丢成 None，破往返 | ffi.rs |
| R39 | **opbehavior.rs SUBPIECE 两路径都错（忽略字节偏移）** | opbehavior.rs:53,129 | 常量折叠 SUBPIECE 产垃圾（最常见截断）| opbehavior.cc:788 |
| R40 | **双分歧求值器**（opbehavior.rs 38 op vs ffi.rs rugra_evaluate_constant 24 op 语义不同，Ghidra 对拍调错的那个）| ffi.rs:244 | 对拍验证无意义 | opbehavior.cc |
| R41 | **space.rs `is_big_endian()` 硬 false + `word_size()` 硬 1** | space.rs:131,137 | 大端目标全错；addressToByte/byteToAddress 不可能正确（jumptable/子流审计的根源）| space.hh:430,340 |
| R42 | **space.rs `overlap_join` 契约错**（范围vs范围返 bool，Ghidra 点在范围返 index）| space.rs:412,213 | 任何期望 Ghidra 契约的调用错 | space.cc:126 |
| R43 | **address.rs `Address` 是裸 u64（丢 space 指针）** | address.rs:23 | overlap/containedBy/isBigEndian/renormalize/encode-decode 全缺或桩；subflow 大端 gap 根源 | address.hh Address 类 |
| R44 | **address.rs `minimalmask` 错**（别名 coveringmask；Ghidra 向上取整）| address.rs:542 | minimalmask(0xF) 给 0xF vs Ghidra 0xff；coreaction/jumptable 依赖真语义 | address.hh:537 |
| R45 | **address.rs `pcode_left`/`pcode_right` 全树缺失** | （无） | RuleShiftBitops 不能用（AGENTS.md 列了但从未加）| address.hh:517,526 |
| R46 | **rangeutil.rs `intersect` 返回约定反转** | rangeutil.rs:112-138 | wrap 情形静默错 + 破 pullBackUnary::INT_ZEXT（jumptable 审计的 let _ = gr.intersect 根源）| rangeutil.cc:549-664 |
| R47 | **rangeutil.rs `pullBackUnary` INT_2COMP/NEGATE 运算符优先级 bug** | rangeutil.rs:346,351 | `~(left+...)` vs Ghidra `(~left)+...` | rangeutil.cc |
| R48 | **cover.rs 无 CFG 递归填充**（addRefRecurse 缺）| cover.rs/merge.rs:1289 | cover 是 Ghidra 严格子集 → 允许 Ghidra 禁止的合并（中间路径同时活跃的变量被合并）| cover.cc:477,524 |
| R49 | **cover.rs 0/1/2 边界三档塌成 bool** + 整 PcodeOpSet/HighIntersectTest 缺 | cover.rs | merge_test 浅（合并审计的根源）| cover.cc:269,342 |

---

## 报告 1: varnode.rs

**Summary**: ~95 Varnode impl + ~21 VarnodeBank | Ghidra ~138 Varnode + ~30 bank + 2 free | ✅~62 ⚠~23 ❌~76 ➕~22

**Headline**: **L3 声明不实**。好消息：**所有 32 主 flag 位 + 9/11 addl flag 位精确匹配**——varnode.rs 没有 block.rs 的 flag 乱位病。坏消息：**~76 方法缺**，其中多个正是 op-edit API 依赖的。关键：
- `eraseDescend` 和 `destroyDescend` **MISSING** —— 这是 funcdata 审计发现的 op-edit descend 损坏的根因
- `isAutoLive` **桩返回 false** —— Ghidra `flags & (addrforce|autolive_hold)`；任何 addr-force varnode 错误地被 DCE
- `getNZMask` 返回**重算近似而非 `nzm` 字段** —— 语义错配
- `operator==`/`operator<`/`Ord` 按 `create_index` 比，非 Ghidra 的 `flags + def SeqNum` —— 破 VarnodeBank 去重
- `VarnodeBank::replace` **复制 size+loc 而非重写读者** —— 完全错语义
- `destroyVarnode` **存在**（更正 funcdata 审计的"MISSING"——是弱移植非缺）

**Flag 位核查**: 32/32 主 flag + 9/11 addl flag 精确。2 addl flag 缺：`stop_uppropagation (0x800)`、`has_implied_field (0x1000)`。

**关键修复**（见 R33-R34 +）:
1. ❌ 加 `erase_descend(op)` + `destroy_descend()`（cc:316,344 含 setFlags(coverdirty)）—— op-edit API 根因修复
2. ⚠️ 修 `is_auto_live` → `flags & (ADDRFORCE|AUTOLIVE_HOLD)`；加 is_auto_live_hold/set/clear
3. ⚠️ 修 `get_nz_mask` 返 `self.nzm`
4. ⚠️ 修 `VarnodeBank::replace`（cc:1332-1352 descend 迭代+op setInput）
5. ⚠️ 修 Varnode 级 PartialEq/Ord 用 (loc,size,input|written,def-SeqNum)（VarnodeLocRef 已对，standalone Varnode 错）
6. 批加 ~45 个 one-liner flag 访问器 + 2 缺 addl flag 常量
7. 加 intersects(×2)/overlap(×3)/overlapJoin —— heritage/merge 重叠检测用
8. 加 get_cover/update_cover/calc_cover/clear_cover —— 接 Cover 字段（merge 依赖）

---

## 报告 2: op.rs

**Summary**: 42/43 flag 位 ✅ | ✅31 ⚠4 ❌~28+5 ➕6

**Headline**: **flag 位值位精确**（32 pcodeop_flags + 10 addlflags + branch_type 全匹配 op.hh）。~30 inline 访问器功能忠实。两系统性 gap 拉低"L3"：
1. **`op_set_opcode`（funcdata.rs:515）只重派生 7 控制流 flag**（branch|call|coderef|returns|marker|has_callspec|return_copy）给 ~9 opcode。**漏 eval-type flag**（unary|binary|special|ternary）、booloutput、commutative、nocollapse。Ghidra setOpcode（op.cc:276-285）清并重应用 **14 flag 位**从 TypeOp::getFlags()。Rugra 无 opcode→flags 映射表——故 getEvalType()/isCommutative()/isBoolOutput() 对经 op-edit 路径设 opcode 的 op 返 0/false。消费端用 OpCode::is_commutative() 直接查绕过——静默偏离 Ghidra 数据模型。
2. **SeqNum 把 getOrder()+getTime() 合成一个 `order:u32`**。Ghidra 分指令内 order 和全局 time。getCseHash/getNZMaskLocal 用 getTime；Rugra CSE hash 用 get_order，变 hash 值。

**另**: `is_indirect_creation` 在 Rugra 在 **Varnode** 但 Ghidra 在 **PcodeOp**（ruleaction 读错对象）。PcodeOp::isCollapsible/getNZMaskLocal/collapse/executeSimple/isMoveable/nextOp/previousOp/target/encode/getSlot/getRepeatSlot 及所有 mark/set flag-writer 缺。PcodeOpBank 缺 target/fallthru/insertAfterDead/moveSequenceDead/markIncidentalCopy + 4 opcode-特定 list（storelist/loadlist/returnlist/useroplist）。

**关键修复**（见 R35-R36 +）:
1. P0 **`op_set_opcode` flag 映射不全**——建完整 opcode→u32 flags 表（镜像 typeop.cc ~70 条）在 op_set_opcode + PcodeOpBank::change_opcode/create 都应用
2. P0 **`is_indirect_creation` 读错对象**——加 PcodeOp::is_indirect_creation() 并改 3 调用点
3. P1 SeqNum 拆 order+time 或文档化 + 加 get_time 别名
4. P1 缺 CSE/常量折叠算法方法（isCollapsible/collapse/executeSimple/collapseConstantSymbol/getNZMaskLocal）
5. P2 PcodeOpBank 缺 codelist + 关键导航 + O(n) find_op
6. P2 ~20 inline 访问器缺

---

## 报告 3: pcoderaw.rs

**Summary**: MATCH 6 · MATCH(+ext) 1 · SEMANTIC-DIVERGE 6 · MISSING 10 · RUST-ONLY 5 · NON-MATCHING(decode) 1

**Headline**: 结构干净但语义分歧。~16"核心"访问器名/arity 干净映射。**但 load/store emit 路径功能损坏**（两处），且 `behavior` 字段是**类型兼容谎言**（把 Ghidra OpBehavior 架构塌成 u32 flag）。净：不"正确喂 PcodeOp 构造"——只因 Funcdata::inject_raw_ops（funcdata.rs:2008）静默重派生 opcode + 忽略 behavior/seqnum.order 才工作。

**关键修复**:
1. CRITICAL STORE 输入契约错（x86_lift.rs:236-244）：传 Const-space vn 而非指针 vn；segment override 忽略
2. CRITICAL decode/encode space 表不全（5 hardcoded）——命名异种 space 静默 None 丢 op
3. HIGH `behavior:u32` 误表 OpBehavior——重命名 behavior_flags 或实现真 OpBehavior 句柄
4. MEDIUM seq_num Option 丢 order
5. LOW VarnodeRaw 重复 VarnodeData（合并）

---

## 报告 4: opcodes.rs

**Summary**: **名一致 73/73**（全 Ghidra CPUI_* 在，全名对，CPUI_CAST 在 rs:182，BOOL_NEGATE 修保持）。`get_booleanflip` 忠实。

**但枚举静默坏（3 复合）**:
1. 🔴 **判别式值重编号非 Ghidra 原生**（CPUI_INT_ADD Rust=4 Ghidra=19；CPUI_BRANCH Rust=49 Ghidra=4；CPUI_CAST Rust=73 Ghidra=64）。仅 COPY/LOAD/STORE(1-3)+MAX(74) 巧合合。靠 ffi.rs 手维护 map_ghidra_opcode/to_ghidra_opcode 桥掩盖。
2. 🔴 **funcdata.rs:2017 调 `OpCode::from_i32(raw.get_opcode())` 处理 Ghidra 原生整数**——raw 是 Ghidra 编号，from_i32 按 Rugra 重编号解释 → 每个注入 p-code op（前 3 外）误分类。**代码库自己 pcodeop.rs:16 警告"用 map_ghidra_opcode 非 from_i32"——但生产转换路径无视自己警告**。
3. 🟠 **CPUI_CAST 半接线**——枚举有，name()/from_i32/to_ghidra_opcode 有，但**map_ghidra_opcode 注释掉**（"暂无此变体"——现假）

**附**: 虚构 CPUI_TRUNC 变体（Ghidra 无，撞 INT_RIGHT slot 30）；6 float 转 name() 字串错（FLOAT_INT2FLOAT vs Ghidra INT2FLOAT 等）；无 get_opcode 逆。

**关键修复**（见 R37-R38 +）:
1. 🔴 funcdata.rs:2017 用 ffi::map_ghidra_opcode 非 from_i32
2. 🔴 ffi.rs:129 取消注释 `64 => Some(CPUI_CAST)`
3. 🟠 删虚构 CPUI_TRUNC + 其接线
4. 🟡 修 6 float name() 字串
5. 🟡 impl get_opcode(&str)→OpCode

---

## 报告 5: opbehavior.rs

**Summary**: AGENTS.md "完整"**错**。结构脚手架（evaluate_unary/binary/ternary + recover_input_unary/binary）在，~38 opcode，**但非 Ghidra OOP 类层次**（无子类无注册表，flat 自由函数 match 分派）且**静默与并行 ffi.rs::rugra_evaluate_constant 不一致**（后者只 24 op 语义不同）。

**架构错配**：Ghidra ~38 OpBehavior 子类 + registerInstructions() 填 66 项向量按 CPUI_* 索引。Rugra 无子类无表，5 自由函数 match OpCode。第二个分歧 Rugra 求值器 ffi.rs::rugra_evaluate_constant——第三份算术逻辑副本，24 op，不同 mask/sign。**Ghidra check_rugra_eval 调它——对拍 Ghidra 对照错的 Rust 代码**。

**关键修复**（见 R39-R40 +）:
1. 🔴 **SUBPIECE 两路径都错**（rs:53,129）——Ghidra 二元 `(in1>>(in2*8))&mask`（cc:788），第二输入是字节偏移。Rust unary 返 in1 不变，binary 忽略 in2。常量折叠 SUBPIECE 产垃圾。**最高影响正确性 bug**
2. 🔴 **双分歧求值器**——统一 rugra_evaluate_constant 委托 opbehavior::evaluate_unary/binary，否则对拍无意义
3. 🔴 INT_LEFT/RIGHT/SRIGHT 溢出语义分歧（Rust `%size*8` 绕；Ghidra `>=sizeout*8` 返 0）
4. 🟠 recover_input_binary 缺 INT_RIGHT/INT_SRIGHT（jumptable.rs:1483 消费 → 丢跳表 case）
5. 🟠 INT_NEGATE mask 输出 size 非 Ghidra 输入 size
6. 🟠 PIECE 用输入 size 移位非输出-输入
7. 🟡 17 FLOAT_* 全缺（需 FloatFormat）

---

## 报告 6: space.rs

**Summary**: **非 L3；枚举 tag 填充非端口**。~52 文档化 AddrSpace 函数 + 4 子类，Rust 只有少数，多数签名/语义错。**4 标记关键 bug 全确认真**。

**根因**: Rugra 用 AddressSpace enum（类型 tag 非可寻址空间）+ 分离 helper struct（只 id + join/overlay pieces）。enum 无 per-instance 状态（wordSize/addressSize/delay/deadcodedelay/flags/highest/pointerBounds/type/name）→ 每个 field-backed getter 塌成硬编码常量。这是 bug#1/#2/#4 根因。

**关键修复**（见 R41-R42 +）:
1. 🔴 `is_big_endian()` 硬 false（space.rs:131）——double_precis/prefersplit/ruleaction/transform/subflow 全错。加 big_endian 字段从 arch/spec 传
2. 🔴 `word_size()` 硬 1 + 无 addressToByte/byteToAddress——wordsize>1 架构潜 bug。加 word_size 字段 + 两静态 scale 方法
3. 🔴 `overlap_join` 是错的函数（范围vs范围返 bool）——Ghidra 点在范围返 index。重命名 + 提供 faithful overlap_join
4. 🟠 无 wrapOffset/getHighest/calcScaleMask
5. 🟠 getDeadcodeDelay/setDeadcodeDelay/getDelay 在 space 上缺（override 审计无法应用 delay）
6. 🟠 spacetype enum 错配 / 缺 IPTR_SPACEBASE/IPTR_FSPEC / 虚构 numeric ID
7. 🟠 栈方向符号约定脑裂（ScopeLocal -1=下 vs AliasChecker 1=下）
8. 🟡 ConstantSpace.id=3 vs Ghidra INDEX=0

**判定**: space.rs 是 enum 驱动类型 tag 填充，非 L3 AddrSpace 端口。4 标记关键 bug 全真。最深根因：无 per-space 实例状态（wordsize/addressSize/delay/deadcodedelay/flags/highest/bounds），迫使每个 field-backed getter 硬编码。

---

## 报告 7: address.rs

**Summary**: bit-helpers 忠实（calc_mask/leastsigbit/mostsigbit/signbit_negative/coveringmask ✅），但 Address 类半根本不同。

**Headline**: `Address` 是裸 `u64`（rs:23），Ghidra 是 `(AddrSpace*, uintb offset)` 对。每个依赖 space 指针的 Address 方法——overlap/overlapJoin/containedBy/justifiedContain/isContiguous/isBigEndian/isConstant/isJoin/isInvalid/getSpace/getAddrSize/renormalize + XML encode/decode——**缺或桩**。单一架构决策是 subflow isBigEndian gap + 先前审计畸形 XML encode/decode 的根因。

**关键正确性 bug**: Rust `minimalmask`（rs:542）别名 coveringmask，Ghidra minimalmask 是完全不同函数（向上取整到 {0xff,0xffff,0xffffffff,~0} 最小）。除 0 外输入全分歧。

**两声称移植的 helper 全缺**: `pcode_left`/`pcode_right` Rust 树无处（全树 grep 确认）。AGENTS.md memory line 180 只列 signbit_negative/calc_mask/leastsigbit/mostsigbit+functional_equality，从未列 pcode_left/right——但本审计被指示查它们，确认缺。

**关键修复**（见 R43-R45 +）:
1. 🔴 `minimalmask` 错（rs:542）——别别名 coveringmask。正确 body：val>0xffffffff→MAX，>0xffff→0xffffffff，>0xff→0xffff，else 0xff
2. 🔴 加 `pcode_left`/`pcode_right`（address.hh:517,526）——全树缺。trivial，关 RuleShiftBitops 问题
3. 🟠 协调 sign_extend/uintb_negate 位置（在 rangeutil.rs:742/ruleaction.rs:15340，应从 address 重导出）
4. 🟠 Address 类 space-aware 方法缺（overlap/containedBy/isBigEndian/renormalize）——根因 Address(u64) 丢 space 指针
5. 🟠 encode/decode 非 XML（确认 override 审计）——决定 serde-text 还是真 XML
6. 🟡 RangeList::in_range 丢 size 参数
7. 🟡 RangeList::longest_fit 返错类型
8. 🟡 SeqNum 丢 uniq

---

## 报告 8: rangeutil.rs

**Summary**: **`intersect` 返回约定反转**（相对 Ghidra）+ `pullBackUnary` 两运算符优先级 bug → 值域传播不可靠。

**Ghidra**（cc:549-664）: 返 0=成功（单 range 可能空 this 更新）；2=交集两片 **this 不改**（调用者回退另一 range）。**Rust**（rs:112-138）: 返 0 仅当结果空；1 每条非空路径**含 wrap/disjoint fallthrough 行 137 不改 self**。无 2 片信号。doc 注释（"0=空,1=非空,2=this 含 op2"）是**捏造约定匹配 Ghidra 无**。

**后果**: (1) wrap 情形静默错——jumptable.rs:1635 `let _ = gr.intersect(rng)` 等丢弃返回假设 self 更新。wrap 命中 fallthrough（Ghidra cc:653 retval=2）时 Rust 不改 range 调用者当作已 intersect → jumptable range 过宽。(2) **pullBackUnary::INT_ZEXT 主动坏**——rs:369 `if self.intersect(&zext) != 0 { return false }`。Rust 成功返 1 → 条件真 → INT_ZEXT 回拉几乎总假报失败。

**次级**: Ghidra range 代数精度核心——encodeRangeOverlaps + arrange[] 表 + newStride + newDomain——**全缺**。intersect/union/contains_range 全手摇启发，wrap/stride 时退化"保当前 range"。L3 声明对 wrap/stride range 不成立。

**关键修复**（见 R46-R47 +）:
1. ❌ 修 `intersect` 返回语义——采 Ghidra 契约（0=成功 self 更新可能空；2=两片失败 self 不改）。修 wrap fallthrough（:137）返 2 非静默返 1。删捏造 doc
2. ❌ 修 `pullBackUnary` INT_2COMP（:346）/INT_NEGATE（:351）运算符优先级——括号为 `(!self.left).wrapping_add(1).wrapping_add(self.step)` / `(!self.left).wrapping_add(self.step)`
3. ❌ 修 `translate_to_op` right==0 off-by-one（:618 发 `(left-1)&mask` 非 `left`）；加缺 INT_EQUAL/NOTEQUAL/SLESS 案
4. ❌ 决定 `invert` 契约——faithful 移植或重命名当前 piece-count 函数
5. ⚠️ 移植精度核心（encodeRangeOverlaps + arrange[] + newStride + newDomain）——否则 intersect/union/contains_range 对 wrap/stride 不能 faithful
6. ⚠️ 恢复 pull_back_through_op 的 SUBPIECE（jumptable.rs:774）+ 合并重复 pull_back_op（ruleaction.rs:9223）
7. ⚠️ 补全 pushForwardBinary（INT_MULT/LEFT/SUBPIECE/RIGHT/SRIGHT + 布尔结果组）；恢复 INT_ADD 溢出/step 逻辑
8. ⚠️ 替 INT_ZEXT/SEXT 桩（push/pull）用真逻辑（需 sign_extend 已在 sign_extend_size）
9. ⚠️ 加缺 pull-back opcode INT_SLESS/SLESSEQUAL/CARRY/SRIGHT
10. ⚠️ 移植 getSize 的 wrap/溢出"lie-by-one"逻辑

---

## 报告 9: cover.rs

**Summary**: **非 L3；L1-L2**。实现**激进简化** Cover 模型，三承重方式分歧：
1. **无 CFG 递归填充**（Ghidra Cover 核心）。Ghidra Cover::rebuild→addDefPoint/addRefPoint→addRefRecurse 从每用向 def 后走 CFG，标每中间块 setAll() 算部分 range——Cover 是真拓扑作用域（所有 def→use 路径上所有块）。Rugra compute_varnode_covers（merge.rs:1289）**只记 def 块和直接用块**无 CFG 遍历。过时 doc（merge.rs:1284-1288 "covers 经 CFG 前向传播"）直接矛盾实现注释（merge.rs:1346-1352"我们故意不传播"）。**净：Rugra cover 是 Ghidra cover 严格子集 → intersects 更频返 false → 允许 Ghidra 禁止的合并**（两变量在中间路径同时活跃被合并）。验证并锐化 merge 审计。
2. **无两片/wrap 区间支持**。Ghidra CoverBlock 用哨兵 PcodeOp*（0=块始 1=块尾）via getUIndex，yield ~0 表尾——允许 ustart>ustop 表 wrap 两段区间。Rugra CoverBlock{start:u32,end:u32} 单片，重用 start=u32::MAX 作空哨兵——撞合法 [MAX,…] order。
3. **边界/内部三档塌成 bool；marker-op 定位忽略**。Ghidra CoverBlock::intersect/Cover::intersect/intersectByBlock 返 0/1/2（无/边界/区间）+ boundary()+contain(op,max)+containVarnodeDef。MULTIEQUAL→块始 INDIRECT→其目标 order via getUIndex。Rugra intersects()->bool 丢全部，op.start.get_order()（merge.rs:1471）用字面 seqnum **无 MULTIEQUAL/INDIRECT 特案**。失精度恰在 PHI/INDIRECT 边界——合并决定点。

**关键修复**（见 R48-R49 +）:
1. 🔴 实现 CFG 递归 cover 填充——compute_varnode_covers 须在记 def/用块后，从每用块向 def 块后走，每严格中间块调 set_all() 等价。否则 cover 欠估 + merge_speculative/merge_by_cover/inflate_test 批准 Ghidra 拒绝的合并。**单最高影响 gap**。删/修过时 doc
2. 🔴 恢复 0/1/2 边界三档——加 classify_intersect()→{None,Boundary,Interval}。实现 contain(op,max)+containVarnodeDef。merge_test 浅恰因缺 containVarnodeDef
3. 🟠 实现 getUIndex/marker-op 定位（MULTIEQUAL→块始 INDIRECT→目标 order）
4. 🟠 加 PcodeOpSet(+HighIntersectTest 等价)+intersectList——merge 审计标的缺缓存
5. 🟡 修 addDefPoint/addRefPoint 契约或移除
6. 🟡 支持两片/wrap 区间或文档化不变量
7. 🟡 停用 u32::MAX 作空哨兵
8. 🟢 重命名 mutating Cover::intersect/CoverBlock::intersect（无 Ghidra 对应，遮蔽非 mutating intersects）

---

## 批3 总结

- 9/9 报告完成
- **"L3 IR/类型基础已对齐"声明在 8/9 文件中不实**（仅 varnode.rs 的 flag 位精确，但 76 方法缺）
- 头号根因 17 个（R33-R49）入修复清单
- **R33（eraseDescend 缺）+ R34（replace 错）是 funcdata op-edit 损坏 + merge 失败的底层根源**
- **R46（intersect 约定反转）是 jumptable range 失败的底层根源**
- **R48-R49（cover 无 CFG 填充 + 三档塌 bool）是 merge 过度合并/uVar 爆炸的底层根源**
- **R37（from_i32 用于 Ghidra 整数）是潜在的全树 p-code 误分类 bug**——代码库自己警告但生产路径无视

下一步: 批4-6 待发起（剩 ~40 文件）。
