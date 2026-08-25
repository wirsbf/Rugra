# R20 — 机制 C 独立复核报告：RETURNFOLD-GAPB-CONDCONST-0001

- 复核对象：worktree `/home/wirs/.cache/rugra-wt-gapb` 分支 `agent/returnfold-gapb`
  - `c2a4a652` align: port ActionConditionalConst propagateConstant CPUI_RETURN copyBeforeRet arm (GAP-B)
  - `9c4ecb1f` test: pin returnfold_gapb bilateral gate to GAP-B snapshot
- 复核方式：**独立打开 Ghidra 12.0.4 锁定 oracle 原文逐行比对**，不采信实现者 Evidence 块的任何声明。
  Oracle HEAD 实测 = `e40ed13014025f82488b1f8f7bca566894ac376b` = tag `Ghidra_12.0.4_build`，与锁定一致。
- 复核约束遵守：worktree/git 只读；未运行 cargo；唯一写本文件。
- 结论：**Cross-Review: APPROVE**（附 6 条非阻断建议，见 §7）。

---

## 1. Ghidra 原文核对（我亲自读的行）

| 引用 | 核对结果 |
|---|---|
| `coreaction.cc:4383-4467` propagateConstant 全函数 | 逐行读毕。RETURN 臂 cc:4439-4448 与 commit 摘录逐字一致：`newOp(1, op->getAddr())` → `opSetOpcode(CPUI_COPY)` → `opSetInput(copyBeforeRet,constVn,0)` → `newVarnodeOut(varVn->getSize(),varVn->getAddr(),copyBeforeRet)` → `opSetInput(op,copyBeforeRet->getOut(),1)` → `opInsertBefore(copyBeforeRet,op)`；else 臂 cc:4449-4452 `int4 slot = op->getSlot(varVn); opSetInput(op,constVn,slot)`；`count += 1` 在 cc:4453、if/else 之外、dominates 分支之内 |
| `coreaction.cc:4437-4438` | `constVn` 惰性创建**先于** RETURN/else 分叉；注意 `constVn` 是 `point.constVn` 的**局部指针拷贝**（cc:4390），创建后**不写回** point 字段——同点后代共享的是这个局部量 |
| `coreaction.cc:4545` | apply `return 0;` 无条件 ✓ |
| `action.cc:298-324` perform | `case status_start: count = 0;`（cc:306）✓ count 清零在 perform 不在 apply |
| `ruleaction.cc:3926-3957` RulePropagateCopy::applyOp | `if (op->isReturnCopy()) return 0;`（cc:3933）在输入扫描之前 ✓。任务书写的 "action.cc:3933" 系笔误，实为 ruleaction.cc:3933 |
| `typeop.cc:875-880` TypeOpReturn 构造 | `opflags = special|returns|nocollapse|return_copy` 在 **878 行**（commit 引 :879 差一行；metadata 的区间引用 875-879 覆盖）。全库 grep 证实 return_copy **只**经 TypeOpReturn 的 opflags 设置（op.cc:279-285 setOpcode 先清后置），即只有 RETURN op 携带该 flag，任何 COPY 都不带 |
| `funcdata_varnode.cc:104-122` newVarnodeOut | createDef(TYPE_UNKNOWN 基类型) → `op->setOutput(vn)`（op.hh:135 裸赋值）→ `assignHigh(vn)` → `if (s >= minLanedSize) checkForLanedRegister(s,m)` → `localmap->queryProperties(m,s,op->getAddr(),vflags)` + setSymbolProperties/setFlags 腿 |
| `funcdata_op.cc:104-125` opSetInput | cc:107 同值早退；cc:108-115 常量单后代去重（非 spacebase 时 newConstant 新对象 + copySymbol）；cc:120-121 opUnsetInput（eraseDescend 旧输入）；cc:123-124 addDescend + setInput |
| `varnode.cc:1411-1418` createDef / `:1291-1310` xref / `:34-53` VarnodeCompareLocDef / `:394-404` setDef | createDef = 新 Varnode(s,m,ct) + create_index + setDef（置 written|coverdirty）+ xref（loc/def 双树插入、置 insert）。**LocDef 比较键 = (addr,size,input/written 类别,written 时 def SeqNum,free 时 createIndex)**——COPY 输出落 X 的精确地址不会与 X（input 类）碰撞，同址多次写由 def SeqNum 区分 |
| `varnode.cc` / `varbank.hh`（查找过程） | varbank.cc 不存在，createDef/xref 实际在 varnode.cc —— 实现者引用无误 |

## 2. 四类决定性语义核对（独立清单 vs Rust）

Rugra 侧：`/home/wirs/.cache/rugra-wt-gapb/src/coreaction.rs` `propagate_constant`（fn 注释 `// Ghidra: coreaction.cc:4383`，实际行 8484/8502）。

### 2.1 引用/输出参数
- `const_vn`：`let mut const_vn = point.const_vn.clone()`（8514），惰性创建（8642-8646）位于 RETURN/else 分叉**之前**，且**不写回** point —— 与 Ghidra 局部指针语义（含不写回这点）**精确一致**。
- COPY 输出：`fd.vbank.create_def_with_space(var_size, var_space, var_off, &copy)`（8674-8679），(space,offset,size) 三元组取自 varVn 实测字段（8654-8657）。`create_def_with_space`（varnode.rs:3013-3027）= allocate（canonical TYPE_UNKNOWN + create_index）+ set def + WRITTEN|COVERDIRTY + xref —— 与 createDef 逐腿对齐；loc_tree 键含 input/written 类别与 def SeqNum（继承自既有 VarnodeLocRef 序），与 X 同址不碰撞（双侧 fixture `x_loc=register:0x0:4` 与 `copy_out=register:0x0:4` 并存即为实证）。
- **newVarnodeOut 全腿接线**（cc:104-122 五腿全在，顺序一致）：
  1. createDef ↔ create_def_with_space ✓
  2. `op->setOutput(vn)`（裸 setter，op.hh:135）↔ `copy_before_ret.0.write().unwrap().output = Some(...)` ✓（等价裸赋值，与 Rust 自家 new_varnode_out funcdata.rs:2057 同法）
  3. assignHigh ↔ `fd.assign_high(&out_vn)` ✓
  4. `s >= minLanedSize` 门 ↔ `var_size >= fd.min_laned_size as usize` + `check_for_laned_register(size, space, Address)`（funcdata.rs:8475-8494，显式 space 参数恢复 Ghidra Address 的 space 分量，对 funcdata_varnode.cc:298-309 忠实）✓
  5. queryProperties/setSymbolProperties/setFlags 腿 ↔ `fd.set_varnode_properties(&out_vn)` —— **预存基础设施替身**（Funcdata::setVarnodeProperties 的 symbol_table best-effort 版，非 newVarnodeOut 内联腿的 usepoint=op->getAddr() 语义；ScopeLocal::queryProperties 未移植，funcdata_audit 已记录）。该替身与 Rust 自家 new_varnode_out（funcdata.rs:2068）走的是同一函数，本片无新增偏差；fixture 无 local 符号，两腿均为 no-op。非阻断（§7-6）。
- `fd.op_set_input` 常量去重/erase_descend/add_descend（funcdata.rs:1649-1739）对 cc:107-124 逐腿对齐；第二 COPY 的 in0 因去重而是新常量对象 —— 双侧 `distinct_copy_in0=1` 同证。

### 2.2 循环边界/遍历顺序
- 外层 FIFO：`points.remove(0)` ↔ `points.pop_front()` ✓。
- 后代遍历：Ghidra 活链表 + 先推进迭代器（cc:4396-4397）；Rust 每 point 重建 `descend_refs` 快照（8519-8522）。本函数内对 varVn descend 链的仅有可能变更 = 当前处理的 op 自身（RETURN 臂/else 臂的 opSetInput 只切当前 op 的链，COPY 插入不动 varVn 的链，pushConstant 不改输入），故快照 ≡ 活链表；断链后的重访两侧都到不了（快照按 point 重建 / Ghidra 条目已删）。`block_is_dom && dominated` 单一插入门 ↔ cc:4435-4436 ✓（dominates 经 structure_reset 的 RPO index + immed_dom 链，fixture pre 记录钉死两侧同一 RPO 序）。
- `op_insert_before` 时序：Rust 8691（set slot1）→ 8693（insert）= cc:4446 → cc:4447 ✓；new_op/op_set_opcode/op_set_input(copy,in0) 先后 = cc:4442-4444 ✓。COPY 落 RETURN 所在块、紧邻 RETURN 之前（fixture `b2_ops=INT_ADD,COPY,RETURN` 双侧一致）。

### 2.3 计数器/累加器
- `self.count += 1`（8698）在 `if opc==RETURN / else` 之外、dominated 分支之内 = cc:4453 位置精确一致，两臂同权。fixture pass1 count=3（1 INT_ADD + 2 RETURN）双侧同值。
- phiNodeEdges 点级收集/清空 ↔ cc:4459-4464（8708-8717）✓，与本臂无交互。

### 2.4 排序/比较键
- RETURN 臂字面 `1`（8691 `fd.op_set_input(&op_ref, out_vn, 1)`）↔ cc:4446 字面 1，**未用 getSlot** ✓。
- else 臂 `slot_of_input(&var_vn)`（= getSlot，op.rs:360-362，首匹配/Option 形）↔ cc:4450 ✓。
- 守卫中的 `slot` 只用于 already_const 探测，不影响 RETURN 臂落点（臂内重算字面 1），与 Ghidra 语义无冲突。

**四类核对：[x]引用参数 [x]遍历顺序 [x]计数器 [x]排序键 — 无 MISMATCH。**

## 3. 「Rust-only 值级收敛守卫在 RETURN 臂空转」论证验证

守卫（8633-8641，**预存**——c2a4a652 diff 中为上下文行，仅追加注释与臂内分叉）：`slot_of_input` → `if let Some(slot)` → `already_const` 早退。

- **首次访问**：`slot_of_input` 命中的 slot 当前输入就是 varVn 本身；varVn 非常量有保证——findConstCompare cc:4500-4507 的交换逻辑使 varVn 必为非常量侧，implied-bool 点的 boolVn 为被写变量 → `already_const` 恒 false，守卫放行。唯一反例是退化形 INT_EQUAL(c,c)（双常量比较存活到 condconst 且该常量被 RETURN）——该情形下守卫会跳过而 Ghidra 会插 COPY，但这是**守卫的预存行为**（改前同样跳过），且实际管线中 RuleEqual2Constant/分支折叠早已消解该形。记入 §7-5。
- **重访**：插入后 RETURN slot 1 持 COPY 输出（非常量），且 `op_set_input` 对旧 slot-1 输入（varVn）执行 erase_descend，切断 varVn→RETURN 链；快照每个 point 每次应用重建 → RETURN 不会再被枚举。Ghidra 活链表同理（条目已删）。即使 RETURN 经由另一 slot 仍在 descend 表中被重访，slot 1 上的输入是 COPY 输出也非常量，`already_const` 仍不触发。**论证成立**。
- `slot_of_input → None`（快照过期）：Rust 不做事不计数；Ghidra 活链表根本不含该 op。等价。

结论：守卫在 RETURN 臂确实空转，实现者论证与代码事实相符；保留守卫不构成本片新增偏差。

## 4. 双侧 fixture 13 records 自洽性

- 记录数：schema, pre, pass1, ret×3, add, pass2, ruleprop, case×4 = **13** ✓（metadata observation_schema 同枚举）。
- **我对 C++ 侧（oracle 真值）静态推演**与 metadata/commit 声明一致：X descend 序 INT_EQUAL,INT_ADD,RETURN(b2),RETURN(b3),RETURN(b4)（构造序即 addDescend 序）；b1 支配 b2/b3、不支配 b0/b4 → INT_EQUAL 与 b4 RETURN 走 pushConstant、不落常量；count=3；x_desc_after=INT_EQUAL,RETURN；copy_pc==ret_pc（cc:4442 取 op->getAddr()）；copy_out=X 精确 (register,0x0:4)；两 COPY 的 in0 因 opSetInput 去重（const5 已有 INT_EQUAL 后代）为互异新常量；ret_retflag=1 / copy_retflag=0（return_copy 仅 TypeOpReturn 设置）；b2_ops=INT_ADD,COPY,RETURN；pass2 count=0 且 IR 不变；ruleprop hits=0（RETURN 被 cc:3933 跳过；其余输入或非常量-def 或 `!isWritten` 于 cc:3936 跳过）。
- Rust 侧 fixture（.rs）构造与投影逐项镜像（同一 5 块图、同 pc 序、同 descend 序、同 13 行格式）；`action.count = 0` 模拟 CountProbe::zeroCount。
- **锁定链我独立复核**（git rev-parse / sha256sum，非采信 metadata）：
  - oracle：HEAD=tag=e40ed130 ✓，cpp tree=`b02e230a…` ✓，Makefile blob=`ca0719fa…` ✓；
  - Rugra base：tree=`0a331f5f…` ✓，src tree=`3b8cfb86…` ✓，Cargo.toml/Cargo.lock/build.rs blob ✓；`git diff --stat c2a4a652 9c4ecb1f -- src/` 为空（fixture 提交未动源码）✓；
  - 文件 sha256：.cc=`f1cfc5cc…`、.rs=`d5ea2767…`、runner=`34b41a80…`、c2a4a652:src/coreaction.rs=`7e4d7195…` 全部与 metadata 一致 ✓。
- runner 静态审：oracle 侧用 `git archive e40ed130` 的 cpp 目录构建（非活树，更强）；Rust 侧用 `git archive c2a4a652` 部分快照构建；双侧各跑 2 次强制确定性；diff 字节级比对；所有期望值同时钉在 runner 变量与 metadata 并交叉校验；`--validate-only` 路径完整重验锁链。未运行（禁 cargo），但逻辑闭合。
- 非支配阴性对照（b4）、非 RETURN 阳性对照（INT_ADD 直接槽替换 cc:4449-4452）、同点多 RETURN 去重（MULTI-RET）三类关键形态都有专门投影。fixture 设计自洽。

## 5. 三个残差声明确为预存（对照 parent `b8047d7e`）

`git diff b8047d7e c2a4a652 -- src/coreaction.rs` 中 grep 不到任何对下列行的 +/- 修改，且 parent 同位置代码相同：

1. **CONDCONST-APPLY-RETURN-0001**：Ghidra apply 恒 return 0（cc:4545 已核）+ perform 才清 count（action.cc:306 已核）；Rust apply 开头 `self.count = 0`（8813）+ `count>0 → CHANGE`（8964-8968）——parent 8757/8908 同构。预存 ✓。
2. **CONDCONST-MULTIEQUAL-GUARD-0001**：`let use_multiequal = false;` 遮蔽（8837）parent 8781 同在。预存 ✓。fixture 两侧 heritage pass 0，Ghidra 侧亦为 false，投影不受影响。
3. **CONDCONST-IMPLIEDBOOL-0001**：implied-bool 点在首次 apply 中仍被构造并传播（8915-8944 活代码，仅受预存 `cond_const_done` 一次门约束）——parent 相同。预存 ✓。注意 metadata 中 "Rugra force-disables this arm too" 措辞**过强**（代码未禁用，是注释声明禁用而代码活跃），见 §7-3。

## 6. E2E 方向判断

- 打印链条核实：TypeOpReturn::push → `PrintLanguage::opReturn`（typeop.hh:350）；`return <const>;` 的成立依赖值 varnode 的 def 链经 implied COPY 折叠到常量——恰是 copyBeforeRet 形态，且 cc:3933 isReturnCopy 守卫阻止 RulePropagateCopy 破坏该形态直至 MarkImplied/打印。**「COPY 是打印折叠的 IR 前置形」判断在 Ghidra 架构上成立**。
- GAP-A（ActionPrototypeTypes output-locked 附着）与 GAP-D（COREACTION-BASEEXPLICIT-NUMINST-0001 / COREACTION-MARKIMPLIED-COUNT-0001）在 worktree 审计文档（REVIEW_R16）中确有登记为事实缺口。print_fold 记 UNTESTED 并声明依赖链，未越权宣称。方向判断合理。

## 7. 建议（非阻断）

1. **TODO 看板缺登记**：`docs/TODO_BOARD.md` 无 RETURNFOLD-GAPB-CONDCONST-0001 及三个残差 ID 的条目（目前仅见于 docs/api/coreaction.md、fixture metadata/case 行）。铁律 3 要求认领/残差在看板登记——根集成时须补。
2. **pass2 机制归因错误（仅散文，不影响观察值）**：fixture 头注与 metadata 称 "findConstCompare's loneDescend gate now rejects X"——pass1 后 X 仍有 2 个后代（INT_EQUAL + b4 RETURN），loneDescend 返回 NULL，门**不**拒绝；Ghidra 侧 count=0 来自无支配读，Rust 侧来自预存 `cond_const_done` 整体跳过（`reset()` 不清该标志，已核 ActionConditionalConst 无 reset 覆写）。双侧观察值相同、机制不同（预存差异），散文应修正。
3. **metadata "implied_bool_arm … force-disables this arm too" 措辞过强**：apply 8915-8944 实际构造并（首次）传播 implied-bool 点；代码注释（8907-8914）声称禁用而代码活跃。请在 CONDCONST-IMPLIEDBOOL-0001 下统一注释/文档与代码事实。
4. **行号小漂移**：commit message 引 "typeop.cc:879"，return_copy 的 opflags 赋值实在 **878**（metadata 的 875-879 区间引用无碍）。
5. **退化守卫反例备案**：varVn 本身为常量且等于 point.value（INT_EQUAL(c,c) 存活形）时守卫会跳过 Ghidra 会执行的 COPY 插入——预存、实际不可达，建议并入守卫族残差文档。
6. **set_varnode_properties 替身**：与 Ghidra newVarnodeOut 内联 queryProperties 腿的差异（无 ScopeLocal::queryProperties、无 usepoint=op->getAddr()）为全体 new_varnode_out 调用点共享的预存基础设施缺口；本片内联腿与之同轨、无新增偏差，未来 scope 移植时须回补 usepoint 语义。

## 8. 判定

四类决定性语义独立核对**零 MISMATCH**；守卫空转论证成立；fixture 双侧 13 records 自洽且锁定链经独立 git/sha256 复核全部吻合；三个残差确为预存且本片未动；E2E 方向判断与 Ghidra 打印架构一致。核心算法白名单模块的本次 commit 达到机制 C 合并标准。

**Cross-Review: APPROVE**
