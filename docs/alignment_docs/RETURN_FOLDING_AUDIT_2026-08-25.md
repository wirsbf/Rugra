# A61 — ACTIONRETURN-RECOVERY 域缺口审计（return 值折叠）

- 审计 Agent：a61（只读，未改仓库、未跑 cargo）
- 日期：2026-08-25
- Oracle：Ghidra 12.0.4 tag `Ghidra_12.0.4_build` commit `e40ed13014025f82488b1f8f7bca566894ac376b`，源码 `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/`
- 输入证据：`result/curl_cur.c`（= `/tmp/rugra-reports/e2e-post-a36.stdout`，2026-08-25 06:20，sha 同尺寸 37553B）vs 正典 golden `tests/golden/ghidra_curl_1204.c`
- A51 原始发现出处：`docs/api/printc.md:1347`（printc_switch_emit fixture 的 out_of_scope_gaps：doc_function 全管线 `uVar0 = 10; return uVar0;` 未折叠为 `return 10;`）

---

## 0. 一句话结论

**折叠机制本体（RulePropagateCopy 的 RETURN 守卫 + explicit/implied 层 + 打印内联）在 Rugra 已全部 1:1 存在；真正缺的是两个上游环节——`ActionPrototypeTypes` 的 output-locked 直挂分支（Ghidra cc:4637-4649，Rust 完全缺失）和 `ActionConditionalConst::propagateConstant` 的 CPUI_RETURN 特例（cc:4436-4451，Rust 把常量直接塞进 RETURN 输入槽）——加上 E2E 里 8/70 共享函数的 return 值根本没挂上（上游 IR 破损所致），A51 症状在最新输出中为 0 实例，被"值未挂接"这一更大缺口遮蔽。**

---

## 1. Ghidra return 值折叠机制全链（oracle 侧，逐环节行号）

Ghidra 的 `return 10;` **不是**靠把常量传播进 RETURN 得到的。恰恰相反：

| # | 环节 | Ghidra 位置 | 语义 |
|---|------|------------|------|
| 1 | `TypeOpReturn::TypeOpReturn` | typeop.cc:875-879 | 每个 CPUI_RETURN 恒带 `PcodeOp::return_copy` 标志（opflags = special\|returns\|nocollapse\|return_copy） |
| 2 | `RulePropagateCopy::applyOp` 守卫 | ruleaction.cc:3926-3957，守卫在 :3933 `if (op->isReturnCopy()) return 0;` | **永不**向 RETURN 传播 COPY 输入（也永不动 heritage guard COPY）。folded 形态 `RETURN const` 在 Ghidra 正常 IR 中不存在 |
| 3 | `Heritage::guardReturns` / `guardReturnsOverlapping` | heritage.cc:1652-1692 / 1609-1638 | trial 注册 + RETURN 插入 slot-1 值 varnode 的**唯一**位置（`opInsertInput(op,invn,op->numInput())` cc:1672）；persist 范围插 addr-force COPY 并 `markReturnCopy`（cc:1681-1690，funcdata.hh:452） |
| 4 | `ActionPrototypeTypes::apply` 输出双分支 | coreaction.cc:4637-4651 | **output-locked**：`newVarnode(size,addr)` 直挂每个 RETURN + `updateType`（cc:4638-4649）；**未锁**：`initActiveOutput()`（cc:4651；funcdata.hh:418） |
| 5 | `ActionReturnRecovery::apply` + `buildReturnOutput` | coreaction.cc:1908-1955 / 1836-1906 | trial 活性（`AncestorRealistic::execute` + `ancestorOpUse`，cc:1920-1932）→ `deriveOutputMap` → PIECE 拼接挂值；mainloop/protorecovery 组（cc:5500） |
| 6 | 折叠判定：`ActionMarkExplicit::baseExplicit` | coreaction.cc:3007-3082 | high>1 实例（:3020-3021）或 addr-tied/mapped/protoPartial（:3022-3063）→ explicit（打印 `uVar0 = 10; return uVar0;`）；单实例 COPY 输出 → implied 候选 |
| 7 | `ActionMarkImplied::apply` + `checkImpliedCover` | coreaction.cc:3416-3455 / 3376-3414 | 候选 varnode 标 `Merge::markImplied`（cover 无 LOAD/STORE/CALL 交叉、`inflateTest` 无交叠时） |
| 8 | 打印内联 | printlanguage.cc:526-534（`recurse`：`vn->isImplied()` → `defOp->getOpcode()->push` 内联定义表达式）；printc.cc:754-766（`opReturn` → `pushVn(op->getIn(1))`） | 常量 COPY 表达式内联进 return 语句 |
| 9 | 语句省略 | printc.cc:2703-2705（`emitBlockBasic`：`vn->isImplied()` → `continue`） | implied 输出的 COPY **永不**作为独立语句打印（`uVar0 = 10;` 行消失） |
| 10 | 晚期条件常量 | `ActionConditionalConst::propagateConstant` coreaction.cc:4436-4451 | `if (opc == CPUI_RETURN)` 特例：插 `copyBeforeRet` COPY（"CPUI_RETURN ops can't directly take constants as inputs"），**再由 6-9 折叠** |
| 11 | 死代码视角 | `ActionDeadCode::gatherConsumedReturn` coreaction.cc:3871-3901 | locked/activeOutput 存在 → consume=~0；否则 `minimalmask(vn->getNZMask())`，`returnBytesConsumed` 截断 |
| 12 | 双精度返回形 | double.cc:1406/1426/3160（`returnForm`/`markReturnCopy`） | float 双寄存器返回特例 |

**净效果**：`mov eax,0xa; ret` 的最终 IR 是 `t = COPY 0xa; RETURN t`（t 为 RAX 寄存器 SSA varnode），t 被标 implied → 打印 `return 10;`。oracle golden 中 33 处 `return iVar;` 是 high 多实例/cover 交叉的**合法显式形**，8 处 `return <const>;` 是折叠形——两者都是设计内输出。

---

## 2. Rugra 现状对照

### 2.1 已 1:1 存在（核验过实现体）

| 环节 | Rugra 位置 | 核验结论 |
|------|-----------|---------|
| RulePropagateCopy（含 return_copy 守卫） | src/ruleaction.rs:199-322 | 守卫在 :233（RETURN_COPY 经 op.rs:122 `CPUI_RETURN => …\|return_copy` 正确设置）；槽序/单替换/marker 子守卫齐 |
| guard_returns / guard_returns_overlapping | src/heritage.rs:1678-1790 / 1577-1659 | 全量 port（含 persist COPY 标 RETURN_COPY :1770，halt 语义正确）；在 guard 流程被调（heritage.rs:2116） |
| ActionReturnRecovery + build_return_output | src/coreaction.rs:9162-9438 | 忠实（join 地址用 min-off 代替 constructJoinAddress，:9207-9212，化妆品级偏差） |
| init_active_output | src/funcdata.rs:8688（调用于 coreaction.rs:5953） | 未锁分支存在 |
| ActionMarkExplicit / ActionMarkImplied | src/coreaction.rs:2854-2965 / 2974-3200；Merge::mark_implied merge.rs:866 | 存在（但见 2.3 已登记缺陷） |
| 打印内联 + 语句省略 | src/printc.rs:961-1030（rpn_recurse implied 分派）、:2584/:2795/:2905（implied 输出跳过） | 存在 |
| gather_consumed_return | src/coreaction.rs:389-410 | 与 cc:3871-3901 一致（含 locked/activeOutput → u64::MAX） |
| 管线顺序 | src/action.rs:2085-2140 vs coreaction.cc:5480-5508 | 1:1（Heritage→DirectWrite×2→ActiveParam→ReturnRecovery→…→ConditionalConst） |

### 2.2 缺失清单（本轮新发现，双侧行号）

**GAP-A（P0）`ActionPrototypeTypes` output-locked 直挂分支整体缺失**
- Ghidra：coreaction.cc:4637-4649 —— `isOutputLocked()` 且输出非 VOID 时，对每个活 RETURN `newVarnode(outparam->getSize(), outparam->getAddress())` + `opInsertInput` + `vn->updateType(outparam->getType(),true,true)`。
- Rugra：src/coreaction.rs:5952-5954 只有 `if !output_type_locked { init_active_output() }`——locked 路径**什么都不做**：不挂 varnode、不建 activeOutput → locked-output 函数打印裸 `return;`。
- 关联降级：fspec.rs:405-425 `characterize_as_output` 的 locked 分支退化为 model 分支（已登记 ADDRESS-0001）；`get_output()`/`ProtoParameter.address` 的 space 身份缺失是本 GAP 的地基依赖。

**GAP-B（P0）`ActionConditionalConst::propagateConstant` CPUI_RETURN 特例缺失**
- Ghidra：coreaction.cc:4436-4451 —— `if (opc == CPUI_RETURN)` 插 `copyBeforeRet` COPY（newOp + COPY + newVarnodeOut(varVn 尺寸/地址) + `opSetInput(op, out, 1)` + opInsertBefore）；else 才直接 `opSetInput(op,constVn,slot)`。
- Rugra：src/coreaction.rs:8520-8549 —— 无 RETURN case，`fd.op_set_input(op, cvn, slot)` 对 RETURN 一视同仁 → **产出 Ghidra 永不存在的 `RETURN const` IR 形**，下游（类型/原型/命名）全部偏离 oracle 观察面。
- 附带偏差（同函数）：:8521-8539 "SAFETY GUARD (convergence)" 值级去重守卫是 Rugra-only 添加（行内已注明 12/24 curl 超时动机）——修复 GAP-B 时应顺带核对 Ghidra 靠什么收敛（cc:4437 的 deadcode/condexe 折叠）并决定守卫去留。

**GAP-C（P1）`ActionReturnRecovery` 内嵌试验 seeding + RETURN 输入合成（Ghidra 无此双入口）**
- Rugra：src/coreaction.rs:9296-9303 `seed_output_trials`（按 `ProtoModel::default_x86_64().output_entries` 盲注 trial，RUGRA-GLUE ANN-F，登记 HERITAGE-0001/FSPEC-0002）+ :9358-9374 在 Action 内合成 RETURN 输入 varnode。
- Ghidra：trial 注册与 RETURN 输入插入**只**发生在 heritage 的 guardReturns（数据流真实触碰该范围时）。heritage.rs:1678 已是全量 port 后，此 seeding 是历史补偿层：trial 集合时序与 Ghidra 不同（无数据流也注册）、RETURN 输入插入点不同（Guard 期 vs Recovery 期）。
- 附带：coreaction.rs:9154-9161 doc 注释仍称 "guardReturns is still a stub"——已过时，需清理。
- 附带：coreaction.rs:9280-9284 的 `output_type_locked` 早退是 Ghidra 没有的守卫（在 Ghidra 中因 locked 时 activeOutput 必为 NULL 而冗余等价——但 GAP-A 修复后此守卫变成必要的唯一防线，需保留并注明）。

**GAP-D（已登记，复核确认与本域直接相关）**
- `COREACTION-BASEEXPLICIT-NUMINST-0001`（TODO_BOARD:27，QUEUED）：src/coreaction.rs:2866 `base_explicit` 缺 cc:3020-3021 的 `high->numInstances()>1 → explicit` 规则——正是 §1 环节 6 的折叠判定开关，缺它则折叠/显式选择系统性偏离 oracle。
- `COREACTION-MARKIMPLIED-COUNT-0001`（TODO_BOARD:26，QUEUED）：count 语义（cc:3426/3454）影响 mainloop 收敛与重跑次数。

### 2.3 无 `RuleReturnRecovery`

ruleaction.hh 全 133 个 Rule 中无 return 专项 Rule；return 域全部在 Action 层 + 打印层（§1 表）。Rust 侧同构，无缺失。

---

## 3. 影响面量化（fresh 输出，函数面）

对比基准：`result/curl_cur.c`（Rugra，71 函数）vs `tests/golden/ghidra_curl_1204.c`（oracle，79 函数），共享 70 函数。

| 指标 | oracle | Rugra |
|------|--------|-------|
| `return <常量>;`（折叠形） | **8**（golden 行 1117/1187/1538/1642/2160/2238/2458/2461：`-1/0/2/0/0/1/0/3`） | **0** |
| 带值 return 总数 | 52 | 1（`match_url: return pcVar4;`） |
| `X = <expr>; return X;` 未折叠模式（A51 症状） | —（33 处 var-return 均为 oracle 合法显式形） | 1（`pcVar4 = strdup(0x17680); return pcVar4;`） |
| `X = <const>; return X;`（A51 精确症状） | 0 | **0** —— 被"值未挂接"上游缺口遮蔽 |

**逐函数 return 形态差（9/70 共享函数）**：
- **8 个 return 值整体缺失**（Rugra 裸 `return;`/无 return，oracle 有值）：`SetHTTPrequest`（oracle `return iVar1;`+`return 0;` 混合形）、`_init`、`glob_url`（`return 0;`+`return 3;`）、`main_init`（`return CURLE_OK;`）、`my_fwrite`（`return -1;`+`return (int)sVar1;`）、`my_get_token`（4×`return (char *)0x0;`）、`myprogress`、`next_url`
- 1 个命名漂移：`match_url`（`return pcVar4;` vs oracle `return pcVar8;`，均为显式形，属 varmap 域）

**根因分层**（读 Rugra 函数体证据）：`myprogress`/`next_url`/`getparameter` 等的函数体存在深层 IR 破损（SUB84 部分算子未折叠、未写占位读 `*uVar0 = '#'`、`in_register_00000110`、空 if 体、`->literal` 链）——return 通路在这些函数中先死于 heritage/类型/结构化上游，轮不到 return 域；`my_fwrite`/`SetHTTPrequest.part.0` 这类小函数则与 GAP-A/GAP-C 的挂接链直接相关。

---

## 4. 修复切片建议（优先级序）

**切片 1（P0，GAP-B）：补 `ActionConditionalConst` RETURN 特例**
- write-set：`src/coreaction.rs`（propagate_constant，~8520-8556）+ `docs/api/coreaction.md`
- 串行关系：**`src/coreaction.rs` 当前被 a21（INFERTYPES-CALLINPUT-D2-0001，IN_PROGRESS）持有**，且队列中还有 MARKIMPLIED-COUNT/BASEEXPLICIT-NUMINST/REGNAMES-FS/MERGE-ADDRTIED-CALLER-CLOSURE——本切片排队于 D2 释放后，与 QUEUED 两项同批协调（同文件一次 writer）。
- 独立性好：改动局部（一个 else 分支），无跨文件依赖，可先行做双侧 fixture（fixture 文件与 runner 不占 src 租约）。

**切片 2（P0，GAP-A）：补 `ActionPrototypeTypes` output-locked 直挂分支**
- write-set：`src/coreaction.rs`（prototypetypes apply）+ `src/fspec.rs`（`ProtoParameter` 输出地址 space 身份——ADDRESS-0001 地基，若未解锁则本切片降级为登记）+ 两份 docs/api
- 串行关系：coreaction.rs 同上；fspec.rs 的 FSPEC-PARAMLIST 系列已 INTEGRATED_PENDING_REGISTRY，无活跃 writer，可直接排队。
- 依赖：需要 FuncProto 能给出 locked 输出的 (space,offset,size,type)；先核 fspec.rs 现状再定是否拆两段。

**切片 3（P1，GAP-D 两项已登记 TODO）：BASEEXPLICIT-NUMINST + MARKIMPLIED-COUNT**
- write-set：`src/coreaction.rs:2866` 一带 + heritage 属性尾——**这是让折叠判定与 oracle 同判的最小切片**，修完后 A51 症状类（显式/折叠选择）才有对拍意义。
- 串行关系：已在 TODO 队列（a36 发现），按队列顺序执行即可。

**切片 4（P2，GAP-C 清理）：移除/降级 seed_output_trials 与 stale 注释**
- 前置：切片 2/3 落地 + guard_returns 路径有真实 oracle fixture 覆盖后，删 coreaction.rs:9296-9303/:9358-9374 的替代层，改注释 :9154-9161。
- 铁律 1.5：需先证明移除后 E2E return 挂接不回退（跑 curl 差分门禁）。

**不做**：`RulePropagateCopy` 向 RETURN 传播——oracle 明确禁止（cc:3933），Rugra 现状正确，任何"让传播进 RETURN 来折叠"的方案都是反 oracle 的。

---

## 5. 双侧 fixture 设计（观察面）

**fixture-1 `condconst_return_copy`（切片 1 验收）**
- 构造：`if (c == 5) { x = 7; } … return x;`——ConditionalConst 把 7 传播进 RETURN 的路径。
- 观察面：oracle 侧 IR 序列必含 `COPY 7 → t; RETURN t`（copyBeforeRet），绝无 `RETURN 7`；Rugra 侧同输入产出同形 IR + 打印 `return 7;`。C++ 侧手搭 Funcdata（照 printc_switch_emit 模式）驱动真 `ActionConditionalConst`；Rust 侧同形驱动。断言：op 序列（opcode/slot/addr）、RETURN 输入是否 constant（必须否）、打印文本。
- 负控制：`opc != CPUI_RETURN` 槽直接替换路径不受影响。

**fixture-2 `prototypetypes_locked_output`（切片 2 验收）**
- 构造：output-locked（非 VOID）FuncProto + 2 个 RETURN（1 普通返回 + 1 halt 返回）。
- 观察面：oracle 每个**非 halt** RETURN 恰好多 1 个输入（newVarnode at locked addr，type 更新）；halt RETURN 不挂；未锁函数走 initActiveOutput 对照组。双侧对拍 op 输入计数、varnode 地址/尺寸、类型元数据。

**fixture-3 `return_fold_vs_explicit`（切片 3 验收，复用 my_fwrite 蓝本）**
- 观察面三平面：
  1. **COPY 消融**：`mov eax,-1; ret` 形 → 折叠 `return -1;`（COPY 输出 implied，打印无独立赋值行）；
  2. **常量直返 vs 调用值显式**：同函数 `return -1;`（implied 折叠）+ `return (int)sVar1;`（CALL 输出多实例 → explicit）并存——oracle golden `my_fwrite`（golden:1107-1121 附近）就是现成正典答案；
  3. **多 return 路径**：`SetHTTPrequest`/`glob_url`（oracle `return 0;`+`return 3;` 混合形，golden:2458/2461）。
- 双侧：Rust 侧手搭 SSA（COPY-from-const 单实例 → 期望 implied；CALL 输出双读 → 期望 explicit），C++ 侧同输入走真 ActionMarkExplicit/ActionMarkImplied；断言 flags（explicit/implied）逐 varnode + 最终打印文本。

**fixture-4（E2E 门禁增量）**：以 `--func my_fwrite`/`--func glob_url` 做 curl 差分函数级对拍，作为切片 2/3 的端到端验收（tools/compare_ghidra.py）。

---

## 6. 元数据

- 本审计未修改仓库任何文件；报告仅写入 /tmp/rugra-reports/。
- 所有 Ghidra 行号属锁定 oracle（e40ed130）；Rust 行号属当前工作树（HEAD 于审计时点）。
- 差分数字基于 stdout 提取（已避开 stderr 的 [SYM]/[STEP] 噪音）；函数级结论以函数体提取对比为准（AGENTS.md 机制 B 注意事项）。
