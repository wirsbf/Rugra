# Lane BJ — goto_prints_walk_level 建模完整性审查(只读)

- Date: 2026-09-22
- Repo: /home/ls/Rugra @ master a75d743(未修改任何 repo 文件)
- Oracle: ghidra/ @ e40ed13014025f82488b1f8f7bca566894ac376b(Ghidra_12.0.4_build)
- Scope: `goto_prints_walk_level`(block.rs:418)对 `getParent()->nextFlowAfter(this)` 虚派发的建模完整性;
  对照 Lane BB 的 `next_flow_after_successors`(coreaction.rs:14367,已随 wt/sb-returnsplit 并入 master)。
- 产物路径: /dev/shm/rugra-tests/sb-returnsplit/GOTO_PRINTS_AUDIT.md

---

## 1. Oracle 事实(全部函数体已读)

### 1.1 gotoPrints 语义

`BlockGoto::gotoPrints`(block.cc:2881-2890):

```cpp
if (getParent() != (FlowBlock *)0) {
  FlowBlock *nextbl = getParent()->nextFlowAfter(this);
  FlowBlock *gotobl = getGotoTarget()->getFrontLeaf();
  return (gotobl != nextbl);          // 指针同一性;null==null 为 false
}
return false;
```

doxygen: "Under rare circumstances, the emitter can place the target block of the goto
immediately after this goto block … there should not be a formal goto statement emitted."
(声明 block.hh:554;任务书引用的 block.hh:155-156 实为 setFlag/clearFlag 行,正确锚点是 554。)

### 1.2 nextFlowAfter override 完整集(每个函数体逐行读毕)

| 类 | 行号 | 语义 |
|---|---|---|
| FlowBlock(基类, inline) | block.hh:884-887 | `return 0` |
| BlockGraph(含 root/List) | block.cc:1335-1353 | 在 list 中找 bl;非末位 → 下一兄弟的 front leaf;末位 → `getParent()->nextFlowAfter(this)`,root 处 null |
| BlockList | (block.hh:600, 无 override) | 继承 BlockGraph 兄弟规则 |
| BlockGoto | block.cc:2899-2903 | `return getGotoTarget()->getFrontLeaf()`(任何 bl) |
| BlockMultiGoto | block.cc:2931-2934 | `return 0`(任何 bl;gotoedges 不是组件,newBlockMultiGoto nodes=[bl] 单元素) |
| BlockCondition | block.cc:3053-3056 | `return 0`(任何 bl) |
| BlockIf | block.cc:3127-3134 | `getBlock(0)==bl → 0`;否则 `getParent()->nextFlowAfter(this)`(**不做兄弟扫描** — if/else 的两个 body 的后继都是整个 if 的后继,不是对方!) |
| BlockWhileDo | block.cc:3341-3351 | `getBlock(0)==bl → 0`;否则 `front_leaf(getBlock(0))` = **循环头**(body 的后继是条件,不是循环后) |
| BlockDoWhile | block.cc:3448-3451 | `return 0`(任何 bl — 可能在迭代) |
| BlockInfLoop | block.cc:3476-3483 | `front_leaf(getBlock(0))` = **循环头**(任何 bl) |
| BlockSwitch | block.cc:3639-3661 | ① `getBlock(0)==bl`(=cs[0] 调度根)→ 0;② `bl->getType()!=t_goto → 0`("Otherwise there is a break statement in the flow");③ 在 **caseblocks**(不是组件 list!)中找 bl,找不到 → 0;④ 非末位 → `caseblocks[i+1].block->getFrontLeaf()`(**fallthru/打印序**,grabCaseBasic block.cc:3591 stable_sort by label,同 label 比 depth);⑤ 末位 case → `getParent()->nextFlowAfter(this)` |

Switch 组件 vs caseblocks 关键事实(newBlockSwitch block.cc:1904-1919 + grabCaseBasic block.cc:3524-3592):
- 组件 list = `cs` = [调度根(常为 BlockMultiGoto), case1, case2, ...];`getBlock(0)` = **调度根**,不是第一个 case。
- `caseblocks` = cs[1..] + multigoto 的 gotoedge 目标(标 f_goto_goto,cc:3548-3553),再按 label/depth stable_sort。
- t_goto 的 case 才有非 null 后继 — fallthru 链(grabCaseBasic cc:3536-3546)里所有 fallthru 块都是 plain goto。

### 1.3 gotoPrints 的全部 oracle 消费点

1. `BlockGoto::markUnstructured`(block.cc:2857-2864): `gototype==f_goto_goto && gotoPrints()` →
   `markCopyBlock(gototarget, f_unstructured_targ)` — **决定目标块是否获得 code_r0x 标签**
   (emitAnyLabelStatement/printc.cc:3198 只给带 f_unstructured_targ 的块发标签)。
2. `PrintC::emitBlockGoto`(printc.cc:2766-2779): `if (bl->gotoPrints())` 才 `emitGotoStatement`
   — **goto 语句是否打印**(goto/continue/break 关键字,cc:2775)。
3. `ActionReturnSplit::gatherReturnGotos`(blockaction.cc:2215-2217): t_goto 资格判定(Lane BB 已移植)。

注意:switch 的 goto-case 发射(printc.cc:3334-3337)与 ifgoto 发射(printc.cc:2914-2916)**不经过**
gotoPrints 门控(无条件 emitGotoStatement);它们只受消费点 1 的**标签标记**间接影响
(goto 语句引用的 label 是否被 emitAnyLabelStatement 定义)。

求值时机:oracle 是**惰性**虚派发 — markUnstructured 时(ActionFinalStructure,
blockaction.cc:2193-2194: scopeBreak → markUnstructured)、emit 时、以及 ReturnSplit 时(中途树态,
树形可能不同于 final)各查一次,结果**不缓存**。

---

## 2. Rust 现状

### 2.1 既有实现(本次审查对象)

- `goto_prints_walk_level`(block.rs:418-434)+ `goto_prints_visit`(block.rs:443-464)+
  `BlockGraph::compute_goto_prints`(block.rs:3857-3860)。
- 语义:**纯兄弟规则** — 每个组件 succ = 下一兄弟 front leaf;末位组件 succ = 外层传入的 tail
  (根处 None)。**对任意复合类型一视同仁,无 per-type 分派。**
- 消费链(单一事实源 = `BlockGoto::prints_precomputed`,block.rs:5270):
  - `ActionFinalStructure`(blockaction.rs:8010-8031): scopeBreak → **compute_goto_prints()** →
    mark_unstructured(→ `mark_unstructured_target` block.rs:5431 读 prints_precomputed →
    决定 UNSTRUCTURED_TARG 标签标记)。
  - `printc emit_block_goto`(printc.rs:12762-12764): `get_parent(g)` 从未接线(结构器不 wire
    BlockGoto::parent)→ 走 `goto_prints()` = prints_precomputed → 决定 goto 语句是否发射。
  - switch goto-case 发射(printc.rs:5071-5089)与 oracle 一致,不做 prints 门控(只受标签标记影响)。
- 旁注:block.rs 内存在一套**逐类型 typed `next_flow_after` 方法**(BlockGraph:3746 / Goto→index:5532 /
  If→next_flow_after_parent:6040 / WhileDo:6326 / DoWhile:6496 / InfLoop:6665 / Condition:7157 /
  Switch:7473),**全部为死代码**(grep 无调用点),且自身各有简化(WhileDo 不 front-leaf 条件、
  If/Switch 末位不递归 parent、Switch 缺 t_goto 门控与 front-leaf)。goto_prints 链不经过它们。

### 2.2 BB 的新分表(已并入 master)

`next_flow_after_successors`(coreaction.rs:14349-14447):按父类型分派 —
If: 槽0=null 其余=父succ;WhileDo: 槽0=null 其余=front_leaf(槽0);DoWhile/Condition: 全 null;
InfLoop: 全=front_leaf(槽0);Goto: 全=target front leaf;Switch: 槽0=null、t_goto case→下一 case
front leaf(末位→父succ)、非 t_goto case→null;默认(List/root): 纯兄弟规则。
消费方:**仅** ActionReturnSplit 的 gather 访问器(coreaction.rs:14287),不喂 prints_precomputed。

---

## 3. 逐父类型差异清单(核心产物)

记 W = 既有 walk(纯兄弟规则),O = oracle,B = BB 分表。组件序:block.rs:3766-3774 注释
(If [cond]/[cond,tc]/[cond,tc,fc];WhileDo [cond,body];DoWhile [condcl 单组件];InfLoop [body];
Condition [b1,b2];Switch Rust=**cases+default 末尾追加,不含调度根**;Goto [wrapped])。

| # | 父类型 | O 的组件 succ | W 的组件 succ | W 缺口 | B |
|---|---|---|---|---|---|
| 1 | root/BlockList | 兄弟规则 | 兄弟规则 | 无 | ✓ |
| 2 | BlockIf — 槽0(cond/ifgoto 的 goto) | null(cc:3130-3131) | 下一兄弟 front leaf | **缺** | ✓ |
| 3 | BlockIf — 非槽0(tc/fc,含中间位) | 父succ(cc:3134,**无兄弟扫描**) | 下一兄弟 front leaf(tc 得到 fc 头!) | **缺**(if/else 三组件形态) | ✓ |
| 4 | BlockWhileDo — 槽0(cond) | null(cc:3344-3345) | body front leaf | **缺** | ✓ |
| 5 | BlockWhileDo — body(末位) | **front_leaf(cond)=循环头**(cc:3347-3350) | 循环后 succ | **缺**(方向性错误) | ✓ |
| 6 | BlockDoWhile — 唯一组件(融合体) | null(cc:3451) | 循环后 succ | **缺** | ✓ |
| 7 | BlockCondition — b1/b2 | null(cc:3056) | 对方 front leaf | **缺**(理论;gotos 不是其组件,低危) | ✓ |
| 8 | BlockInfLoop — body | **front_leaf(body)=循环头**(cc:3479-3482) | 循环后(常 None) | **缺**(方向性错误) | ✓ |
| 9 | BlockGoto — wrapped | **target front leaf**(cc:2902) | 外层 goto 的 succ | **缺**(goto 套 goto 时) | ✓ |
| 10 | BlockSwitch — 调度根槽 | null(cc:3642-3643) | (Rust 组件表无调度根 — 见下) | 结构差异 | **半缺**(B 把槽0当调度根,但 Rust 组件[0]实为第一个 case) |
| 11 | BlockSwitch — 非 t_goto case | null(cc:3646-3647) | 下一 case front leaf | **缺** | ✓ |
| 12 | BlockSwitch — t_goto case(非末) | 下一 **caseblocks(fallthru/label 排序)** front leaf(cc:3655-3657) | 下一组件(cases 构造序 + default 追尾)front leaf | **缺 + 排序基准不同**(Rust cases=out-edge 扫描序 cc:6148-6160,oracle=stable_sort(label,depth) cc:3591;oracle 检索的是 caseblocks 不是组件表) | 半✓(规则同,序不同) |
| 13 | BlockSwitch — 末位 case | 父succ(cc:3659-3660) | 兄弟规则同 | 形似 ✓,但"末位"落点不同(oracle=排序后末 caseblock;Rust=default 若存在) | 半✓ |
| 14 | BlockMultiGoto — wrapped | null(cc:2933) | W 不下钻(component_list_dyn 对 MultiGoto 返回空) | 形似 null(不访问) — 偶然而非建模 | 默认臂 sibling(组件空,事实无害) |

### 3.1 各缺口的可观测后果(输出形态)

prints_precomputed 同时驱动 **(a) goto 语句发射**(printc emit_block_goto)与
**(b) 目标块的 code_r0x 标签标记**(mark_unstructured_target)。两类输出都会偏。

- **#5 WhileDo body 末位 goto 指向循环头**(显式回边,scopeBreak 不转 break/continue):
  O: gotobl==循环头 → prints=false → 无 goto 语句、目标无标签(自然回边)。
  W: gotobl(头) vs 循环后 → prints=true → **多打一条 `goto <头标签>;` + 多一个标签**;
  且 markUnstructured 会把循环头标记成 unstructured_targ → **循环头也挂上 code_r0x 标签**。
- **#5/#6/#8 反向**:body 末位 f_goto_goto 的目标 front leaf == 循环后块(W 的 succ):
  W: prints=false → **goto 被吞**。scopeBreak 已把"target==本层 loop exit"转成 break
  (cc:2872-2873),所以直接形态多被兜住;但 target 为**外层**结构、front leaf 恰与本层循环后
  同 leaf 时(嵌套 loop 共享出口块),W 吞 goto → 发出的 C 变成回边循环 → **语义级错误
  (死循环),非仅文本差**。
- **#8 InfLoop body 末位 goto 指向循环头**:O: prints=false(自然回边)。W: (Some,None) →
  prints=true → **多打 goto + 标签**(infloop 无出口,外层 succ 常为 None,此形态必现差异)。
- **#3 If 三组件(if/else)tc 末位 goto 指向 join**:O: nextbl=父succ=join → prints=false →
  不打 goto(tc 之后的打印流是 fc,oracle 认定 fall-thru 目标是 join — 依赖结构器保证该形态
  不产生语义问题);W: nextbl=fc 头 → prints=true → **多打 goto + 标签**。
- **#2 If 槽0(ifgoto 单组件 [goto])**:O: null → prints **恒 true**(ifgoto 的 goto 永远保留,
  但其发射路径 printc.cc:2914-2916 本就不经 prints 门控;影响面在 markUnstructured 标签:
  oracle 由 BlockIf::markUnstructured 无条件标,不走 BlockGoto 的 prints 门)。若 Rust 把
  ifgoto 建成 BlockIf(goto_target)而非 BlockGoto 组件,W 的 #2 不触发表面行为;
  若建成 BlockGoto 直接挂 If 下且目标==if 后继 → W prints=false → 吞 goto 语句(ifgoto
  发射路径不过 prints 门控,则主要吞的是**目标标签**)→ `goto` 引用了未定义标签的风险。
- **#11/#12 Switch**:goto-case 自身的 goto 语句发射不经 prints 门控(两侧一致),受影响的是
  (i) **case 体内末位 goto**(其父=case 体 list,末位 → Switch 臂):O 对非 t_goto case 给 null
  → prints 恒 true(永不被吞);W 给下一 case 头 → 若 goto 目标==下一 case 头(显式 fallthru
  意图)→ W 吞 goto → 恰好退化为 C 的自然 fall-through,**文本与 oracle 不同**(oracle 会打
  goto+标签)但语义同;若目标≠下一 case 头则无差异。(ii) **goto-case 的标签标记**:目标
  fallthru 到下一 case 时 O prints=false → 目标无 unstructured 标签;W(若序对齐)同;排序
  基准不同(#12)时两端"下一 case"取错人 → prints 翻转 → **多/吞标签**。
- **#9 Goto 套 Goto**(wrapped 为复合体且其末位组件是 goto):O: succ=target front leaf;
  W: 外层 succ → prints 可能翻转 → 多/吞 goto 语句(printc.rs:12719-12743 注释表明
  Goto 确实会包复合体 — main 的 else-if 臂观察过 Goto(208) 包 If(150))。

---

## 4. 语料可触发性 + 修复与登记建议

### 4.1 实测(只读,fast-release 构建产物在 target/,repo 未动)

方法:`cargo build --profile fast-release --example blockstruct_tree_dump`(1m17s,0 改动)
→ 对 result/curl_cur.c 中含 `goto ` 的函数逐个 dump 最终树(main/glob_url/GetStr/myprogress/
glob_word 成功;parseconfig_constprop_0 与 getparameter_constprop_0 为 constprop 名,ELF 符号表
不可解析,未dump;httpd 本次无 result 产物)→ 自写解析器
(/dev/shm/rugra-tests/sb-returnsplit/analyze_goto_prints.py)按缩进重建父子链,对每个 Goto 节点
模拟 W(纯兄弟)与 O(分臂)两套 succ(叶子以 front-leaf 地址近似指针同一性),分类:

- main:170 节点,最终树仅 **3 个 BlockGoto**(另 3 个 IFGOTO);glob_url/GetStr/myprogress/
  glob_word 最终树 **0 个 BlockGoto**(C 输出中的 goto 来自 IFGOTO 形态与 flat 发射通道 —
  Rugra 26 goto vs golden 61、11 break vs golden 58 的既有差距是多因的发射通道问题,不在本审计范围)。
- main 的 3 个 Goto:2 个祖先链全为 List/If(末位/非槽0)臂,W==O;1 个为 **Goto 套 If 内的
  goto(L814,父链边界 = 外层 Goto 臂)**:W 给 `0x26dc`(兄弟),O 给 `0x3180`(外层 goto 的
  target front leaf)— **臂已分歧**,但该例 gotobl(0x2688)与两者都不等 → prints 两边均 true,
  **今天语料零 prints 翻转、零输出差异**。
- **最终树中不存在** WhileDo/DoWhile/InfLoop/Switch 直接挂 BlockGoto 的形态(main 仅有的
  WhileDo body 尾部是 Copy/IFGOTO,glob_word 的 InfLoop 内无 Goto)→ 缺口 #4/#5/#6/#8/#11-#13
  当前全部 **LATENT(潜伏)**。

结论:当前 curl 语料不触发;但 Rugra 结构器随对齐推进必然产出更多真实 BlockGoto 摆位
(oracle 侧这些是常态形态),潜伏臂届时显形。

### 4.2 最危险的具体形态(修复优先级依据)

**f_break_goto 位于 while body 列表末位**:scopeBreak 把 goto-to-loop-exit 转成 f_break_goto
(block.cc:2872-2873),该块恰在 body List 尾 →
- O:succ = WhileDo 臂 = front_leaf(cond)(循环头)≠ gotobl(循环后)→ prints=true → `break;` 发射。
- W:succ = 线程传递的 WhileDo 自身 succ(循环后)== gotobl → prints=**false** →
  printc.rs:12771 的门控吞掉 `break;` → **发出的 C 无限循环(语义级错误,非文本差)**。
同构风险:DoWhile 尾 goto(O 恒 true vs W 可 false)、InfLoop 显式回边 goto(反向:多打 goto+标签)。
这是"纯兄弟规则"唯一的**吞语句**通道,其余形态多为多打 goto/标签(文本差)。

### 4.3 修复建议

**复用 BB 的分表,不要独立实现**:
1. 将 `next_flow_after_successors`(coreaction.rs:14367)从 ActionReturnSplit 私有提升为
   `block.rs` 的 pub(crate)(或移入 block.rs),`goto_prints_visit`(block.rs:460-463)的递归
   改用该表计算每组件 succ(替换 goto_prints_walk_level 的纯兄弟循环)。ReturnSplit 侧同步
   引用同一实现,单一事实源。
2. 顺带修 BB 表自身的两处 Switch 建模偏差(见附录 A):槽0 特判与 Rust 组件表不符
   (Rust components[0] 是第一个 case,不是调度根);"下一 case" 的序基准需与发射序一致。
3. 死代码清理(可并入或另开):block.rs 7 个 typed `next_flow_after*`(5532/6040/6326/6496/
   6665/7157/7473)无调用点且各有简化 — 接入统一分表后删除或改为薄委托,避免双源漂移。
4. 注意时序语义差:oracle 是**惰性**求值(ReturnSplit 用中途树态、markUnstructured/emit 用
   final 树态,同一谓词两态各查);Rugra 的 prints_precomputed 在 ActionFinalStructure 一次
   算清,ReturnSplit 用 BB 表现算 — 两消费者两态,与 oracle 分态语义一致 ✓(保持现状即可,
   勿让 ReturnSplit 读 prints_precomputed)。

验证门禁(修复时):blockaction.rs/coreaction.rs/printc 输出受影响 → 机制 B 差分门禁
(compare_ghidra.py vs ghidra_curl_1204.c,逐 --func 核 main);机制 B2 需 oracle 双侧 fixture
(建议 fixture 形态:while-body-尾 break-goto、infloop 回边 goto、switch fallthru goto-case、
goto 套 goto);blockaction 属核心算法白名单 → 机制 C 独立复核 + `## Cross-Review: APPROVE`。

### 4.4 登记建议

**新开 TODO ID**(不并入 BB 的 returnsplit 条目 — 那条 write-set 已合并闭环,本项 write-set
在 block.rs/blockaction.rs/printc 侧):

- ID:`GOTO-PRINTS-NEXTFLOWAFTER-ARMS-0001`
- 内容:goto_prints_walk_level 换用 per-type nextFlowAfter 分表;修 BB 表 Switch 两偏差;
  清理死代码 typed 方法。
- 状态:登记时 LATENT(当前语料零翻转),风险定级 P1(结构器演进后必显形,含吞 break 语义错)。
- owner/write-set/验收命令按铁律 3 五要素填。

---

## 附录 A — BB 分表(next_flow_after_successors)自身与 oracle 的残余偏差(审查新发现)

1. **Switch 槽0 特判错位**(coreaction.rs:14426-14428 `if i==0 → None` 注释 "case 0 null"):
   oracle 的 `getBlock(0)==bl → null` 指的是**调度根 cs[0]**(block.cc:3642,newBlockSwitch 的
   组件表含它);Rust `component_list_dyn(Switch)` = cases(+default),**不含调度根**
   (blockaction.rs:6143-6147、block.rs:3824-3832)。BB 表把第一个 **case** 当成了调度根:
   若第一个 case 是 t_goto(oracle 应得下一 caseblock front leaf),BB 给 null。对 ReturnSplit
   现网是否可观测未验证(goto-case 目标是 RETURN 的场景),但建模上错位。
2. **Switch "下一 case" 的序基准**:oracle 检索 `caseblocks` — grabCaseBasic(block.cc:3524-
   3592)= cs[1..] + multigoto gotoedge 目标,再 `stable_sort(label, depth)`(block.hh:903-907);
   "next" = **fallthru/打印序**。BB 表用组件表顺序(= Rust cases 的 out-edge 构造序,default
   追加尾,blockaction.rs:6148-6160)。两者排序基准不同,且 oracle 的末位置("flow is to exit
   of switch")落在排序后的末 caseblock,Rust 落在 default(若存在)。goto-case 与相邻 case 的
   prints 判定在序错位时会翻。
3. **WhileDo 臂 BB 表已 front-leaf 条件** ✓,If/DoWhile/Condition/InfLoop/Goto/List/root 各臂
   与 oracle 逐行核对一致 ✓;MultiGoto 落默认臂但组件表为空,事实无害。

## 附录 B — 复现命令

```bash
cargo build --profile fast-release --example blockstruct_tree_dump
./target/fast-release/examples/blockstruct_tree_dump examples/curl main \
  2>&1 | tee /dev/shm/rugra-tests/sb-returnsplit/tree_main.log
python3 /dev/shm/rugra-tests/sb-returnsplit/analyze_goto_prints.py   # 本审计分析器
```

## 结论一句话

`goto_prints_walk_level` 只实现了 oracle `nextFlowAfter` 12 个 override 中的 1 个
(BlockGraph 兄弟臂),If/WhileDo/DoWhile/InfLoop/Goto/Switch 六类父类型的分臂全部缺失
(BB 的 coreaction 侧分表已有其中大部分),当前 curl 语料零翻转(纯潜伏),但
while-body-尾 break-goto 一旦出现会被吞语句成死循环;建议新开
`GOTO-PRINTS-NEXTFLOWAFTER-ARMS-0001` 复用 BB 分表并修其 Switch 两处偏差。
