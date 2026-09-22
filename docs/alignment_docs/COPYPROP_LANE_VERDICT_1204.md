# COPYPROP Lane Verdict — ActionCopyPropagation 在锁定 oracle 12.0.4 中不存在

> Lane BY (wt/sb-copyprop,自 master 77e97b4)。本文是 M1 判决 + 真实机制图谱 + main 实证噪声解剖。
> oracle:Ghidra 12.0.4,commit `e40ed13014025f82488b1f8f7bca566894ac376b`(worktree ghidra symlink HEAD 已核对相等)。
> 所有行号均指向该 commit。日期:2026-09-22。

## 1. 前提纠错(决定性)

**`ActionCopyPropagation` 在锁定 oracle 中零匹配**:

- `grep -rn "CopyPropagation" ghidra/.../decompile/cpp/` → 0 hits(.cc/.hh 全部)。
- `git log --all --oneline -S "ActionCopyPropagation"` / `-S "RuleCopyPropagate"` → 0 hits
  (仓库史起于 2019-02-28 开源首提交 64ad1bc9,16030 commits 全量 pickaxe)。
- 首提交即无此类(开源前已被移除)。12.0.4 中 coreaction.cc:5509-5511 实际内容:

```cpp
actstackstall = new ActionGroup(Action::rule_repeatapply,"stackstall");
{
  actprop = new ActionPool(Action::rule_repeatapply,"oppool1");
  actprop->addRule( new RuleEarlyRemoval("deadcode"));
```

即 oppool1 规则池块,**不是任何 COPY 传播 Action 的注册位**。

结论:
1. TODO_BOARD:491 `CALLSPEC-DRIVER-0002` 解除门条件 写的"(b)补 ActionCopyPropagation(coreaction.cc:5510-5511,Rugra universal 树缺失)"是事实错误——universal 树没有该槽位,oracle 也没有该 Action。实现它=自创 Action(违反 AGENTS.md 铁律 1.1/1.4,ROADMAP 头部已把 `copypropagate` 列为 6 个 Ghidra 不存在的自造 Action 技术债之一)。
2. Rugra `src/coreaction.rs:1798-1911` 存在一个**未注册的死代码** `ActionCopyPropagate`(全仓零引用),注释谎称 "Corresponds to Ghidra's `RuleCopyPropagate`"(12.0.4 无此 Rule),且实现是无守卫的 blanket 传播(重定向全部 users 后杀 COPY,无 Cover/liveness 检查)——Ghidra 从不做这种传播;Ghidra 的 COPY 治理是 merge 相位的 HighVariable 分组+打印抑制。本 lane 已删除该死代码(行为零变化,E2E byte-identical 验证)。

## 2. oracle 12.0.4 真实的 COPY 噪声治理机制(四个 Action)

全部注册在 universal 根 merge 组(coreaction.cc:5712-5731 尾段),顺序:

| 槽位 | Action | apply 委托 | Ghidra 实现 | Rugra 状态 |
|---|---|---|---|---|
| cc:5722 | `ActionMergeCopy` | `data.getMerge().mergeOpcode(CPUI_COPY)` | merge.cc:326-348 | ✅ 已实现已挂(action.rs // :5722) |
| cc:5723 | `ActionDominantCopy` | `data.getMerge().processCopyTrims()` | merge.cc:1415-1437 | ✅ 已实现已挂(// :5723) |
| cc:5728 | `ActionHideShadow` | 自有 apply cc:4831→`hideShadows(high)` | merge.cc:1070-1108 | ✅ 已实现已挂(// :5728) |
| cc:5729 | `ActionCopyMarker` | `data.getMerge().markInternalCopies()` | merge.cc:1444-1541 | ✅ 已实现已挂(// :5729) |

"merge" 组在 decompile 默认 grouplist 内(action.rs default_groups::DECOMPILE,与 oracle 一致),四个 Action 在主管线真实运行。

### 2.1 四类决定性语义核对表(逐函数,读全函数体后摘录)

#### A. `Merge::mergeOpcode(OpCode opc)` — merge.cc:326-348(签名逐字:`void Merge::mergeOpcode(OpCode opc)`)

1. **引用/输出参数**: `data`(成员,经 `getBasicBlocks()` 只读遍历);`merge(vn1->getHigh(), vn2->getHigh(), false)` 以 HighVariable 指针并入,第二 High 实例被搬空删除,返回 bool 仅作 intersection 信号(false→跳过,cc:345-347 无 snip)。
2. **循环边界/遍历顺序**: 外层 `for(int4 i=0;i<bblocks.getSize();++i)` 线性块下标序;内层 `iter=bl->beginOp();iter!=bl->endOp()` 块内 op 插入序;再内层 `for(int4 j=0;j<op->numInput();++j)` 槽位序。
3. **计数器/累加器**: 无。
4. **排序/比较键**: 无排序;守卫=`mergeTestBasic(vn)`(per-varnode 标志)与 `mergeTestRequired(high_out,high_in)`(merge.cc:102,高层标志:addrTied/persistent/error 类),合并成败由 Cover 相交测试决定。

Rugra 对应 `Merge::merge_opcode`(merge.rs:2307):块序/槽位序/守卫/非 snip 语义均按上表;分歧点=Cover 模型本身(见 §3 R1)。

#### B. `Merge::processCopyTrims(void)` — merge.cc:1415-1437(签名逐字:`void Merge::processCopyTrims(void)`)

1. **引用/输出参数**: 成员 `copyTrims`(PcodeOp* 列表)读后 `clear()`;`processHighDominantCopy(high)` 会改 IR。
2. **循环边界/遍历顺序**: 两个串行循环均按 copyTrims 插入序;`multiCopy` 按**首见序** push。
3. **计数器/累加器**: per-HighVariable 的 `copy_in1/copy_in2` 标志充当"≥2"计数器;循环尾 `clearCopyIns()` 清零。
4. **排序/比较键**: HighVariable 指针等值(first-seen 去重);≥2 才进 `processHighDominantCopy`。

Rugra `Merge::process_copy_trims`(merge.rs:3552):first_seen Vec+counts HashMap,迭代序由 Vec 承载(HashMap 仅查询)——与上表四项一致。

#### C. `ActionHideShadow::apply(Funcdata &data)` — coreaction.cc:4831-4849 + `Merge::hideShadows(HighVariable *high)` — merge.cc:1070-1108(签名逐字:`int4 ActionHideShadow::apply(Funcdata &data)` / `bool Merge::hideShadows(HighVariable *high)`)

1. **引用/输出参数**: `data` 引用;`hideShadows` 返回 bool(数据流是否改变),经 `data.opSetInput(vn1->getDef(),vn2,0)` 突变 COPY 输入;apply 的 `count` 是 Action 基类计数。
2. **循环边界/遍历顺序**: apply 外层 `iter=data.beginDef();iter!=enditer(endDef(Varnode::written))` = **VarnodeDefSet 定义序**(input 先,written 按 SeqNum);`isMark/setMark` 两遍式去重+清标。hideShadows 内部:`findSingleCopy` 收集后双重 `i<j` 实例配对。
3. **计数器/累加器**: `count += 1` 仅在 hideShadows 返回 true 时;mark 标志作用域=本次 apply。
4. **排序/比较键**: `vn1->copyShadow(vn2)`(共同祖先 shadow 测试)+ `getCover()->containVarnodeDef(...)==1`(cover 包含判定,值必须恰为 1)。

Rugra `ActionHideShadow::apply`(coreaction.rs:3564)+`Merge::hide_shadows_of`(merge.rs:4036):**类别 2 分歧**——遍历用 `fd.vbank.loc_tree`(地址序)而非 VarnodeDefSet(定义序)。hideShadows 的结果按 high 处理顺序可能级联(改一个 COPY 输入影响后续 high 的 findSingleCopy/copyShadow),此分歧登记为 R3。

#### D. `Merge::markInternalCopies(void)` — merge.cc:1444-1541(签名逐字:`void Merge::markInternalCopies(void)`)

1. **引用/输出参数**: `data.beginOpAlive()..endOpAlive()` 活 op 遍历;`data.opMarkNonPrinting(op)` 置 op 标志;`multiCopy` 收集 HighVariable*。
2. **循环边界/遍历顺序**: 单遍活 op(Switch: COPY/PIECE/SUBPIECE);第二循环按 multiCopy **首见序**;COPY 分支内 `hasCopyIn1` 首见 push、再见 `setCopyIn2`。
3. **计数器/累加器**: per-high copy_in1/copy_in2(≥2 信号);`processHighRedundantCopy` 后 `clearCopyIns()`。**守卫语义:只有 `hasCopyIn2()`(≥2)才进 processHighRedundantCopy(cc:1535-1536)**。
4. **排序/比较键**: `h1 == op->getIn(0)->getHigh()` 指针等值(internal COPY);`shadowedVarnode(v1)`(同 High 内 cover 全交==2);`findAllIntoCopies` 按**输入 Varnode 等值**分组;`checkCopyPair` 用 dominates + Cover range 的中间写判定。

Rugra `Merge::mark_internal_copies`(merge.rs:4349):COPY 分支忠实;**分歧 R4a**:PIECE/SUBPIECE 两臂整体省略(VariablePiece 基建缺失,登记缺口);**分歧 R4b**:≥2 门被"对 multiCopy 全体调用,靠 find_all_into_copies 内部 <2 早退"替代——side-effect 等价性成立(早退无突变)但与 cc:1535 的门形式不同,复核时按行为论。

## 3. main 实证噪声解剖(本 worktree,master 77e97b4,fast-release)

基线门禁:curl 全量 skeleton diff **3752**,defects **0**,numbering **0**;自赋值语句(文本层 `x = x;`)Rugra **326** vs golden **0**(main 214 / helpf 102 / 其余 10)。

探针(RUGRA_DBG_COPYPROBE,已在提交前移除,E2E byte-identical 复核)测得:

| 观测点 | 数值 |
|---|---|
| ActionCopyMarker 时 main 活 COPY 总数 | **9051** |
| 其中 out.high==in.high(被标 nonprinting) | 8059 |
| 其中 **out.high≠in.high(幸存)** | **992** |
| 无 high | 0 |
| 打印出的 COPY 语句(不同 op) | **608**(每 op 恰好发射 2 次=discovery NullEmit+正式遍) |
| 打印 COPY 的 out 空间分布(按发射 1216) | Unique 884 / Stack 296 / Register 26 / Ram 10 |
| RHS 供给集中度 | top-1 in-High 供 264 次发射,top-3 ≈ 628 |
| 语句漏斗处双侧显示名相等的 COPY 发射 | **2/1216**(`argc = argc` 类参数临时拷贝) |

形态学:垃圾语句族=**调用点周围的 spill/restore 乒乓**(`uVar16 = uStack_240;` … `uStack_240 = uVar16;`、`uVar20 = uVar20;`、`uVar19 = uVar19;`),IR 侧病灶=unique 临时↔stack 槽↔callee-saved 寄存器的 COPY 流量**未被合并进同一 HighVariable**。

文本层 `uVar16 = uVar16` 的两侧名字**不是**同一次命名解析的产物(漏斗处同名发射仅 2 条):LHS 走 High 符号名,RHS 经另一条解析链(候选:copy_map 追逐 printc.rs:6817-6822/8722+、或 RPN atom 的 fallback ladder)落到同一文本。即:**IR 病征(未合并 COPY)先在,同名文本是次生碰撞**。

## 4. 修域裁决(本 lane 不做的,按依赖登记)

- **R1(主杠杆,merge.rs Cover 模型)**:`Merge::compute_varnode_covers`(merge.rs:4437)自述"successor [0,MAX] 填充是保守近似——可能阻止合法合并"。992 个 diff-high COPY 的直接嫌疑=required/speculative merge 被 over-approximated Cover 的假相交挡掉。oracle 的 Cover 逐 def/use 点精确重建(cover.cc)。修域=`src/merge.rs`(核心算法白名单,机制 C 强制独立复核),须另开 lane。
- **R2(BANK-COPY-159 终快照 COPY 171vs12)**:9051(mergetime)→终快照 171 的漏斗与本 lane 数据吻合——大头在上游 COPY 生产/消解(heritage/SSA/deadcode/merge 覆盖),不是 print 层。
- **R3(ActionHideShadow 遍历序)**:loc_tree vs VarnodeDefSet(§2.1C 类别 2)。
- **R4(markInternalCopies PIECE/SUBPIECE 臂缺失)**:依赖 VariablePiece 基建(既有登记缺口)。
- **R5(次生,printc RHS 命名追逐)**:文本同名碰撞的精确机制(copy_map chase vs ladder)未钉死,归 printc lane;IR 修复后此症状预计随之消失大半。

## 5. 本 lane 交付物

1. 本判决文档(前提纠错+机制图谱+四类语义表+实证解剖)。
2. 删除死代码 `ActionCopyPropagate`(coreaction.rs,零引用,行为零变化,E2E byte-identical)。
3. TODO_BOARD 三处更新(CALLSPEC-DRIVER-0002 门条件纠错、PRINTC-CONDBLOCK-JUNKOPS-0001 数据补注、新登记 MERGE-COPYNOISE-DIFFHIGH-0001)。
4. ROADMAP 头部自造 Action 清单勾销 copypropagate 项。
