# Ghidra 12.0.4 反编译管线阶段清单(权威参考)

> Oracle: Ghidra `Ghidra_12.0.4_build` commit `e40ed13014025f82488b1f8f7bca566894ac376b`。
> 本文逐行摘自 `coreaction.cc:5462-5739`(universalAction)、`action.cc`(perform/apply/restart)、
> `funcdata.cc:150-182`(startProcessing/stopProcessing)、`ghidra_process.cc:310`(驱动入口)。
> 用途:PIPE 系列任务(`PIPE-DERIVED-TREE-0001`、`PIPE-STACKSTALL-COUNT-0001`、
> `PIPE-HEAD-FLAT-ACTIONS-0001`)与逐阶段差分/快照基础设施的唯一阶段参考。
> Rugra 侧对应文档:`docs/api/action.md`、`docs/api/coreaction.md`。

## 1. 生命周期三层

入口一行驱动整棵树(`ghidra_process.cc:310`):

```cpp
ghidra->allacts.getCurrent()->perform( *fd );
```

1. **Architecture 初始化**(每会话一次):spec 解析、`resetDefaults()`(`action.cc:986`)重建默认 action database。
2. **每函数 Action 管线**:`universal` 树的一次 `perform`。
3. **输出打印**(命令驱动):perform 完成后按请求用 `PrintC` emit C 文本。结构化在管线内
   `ActionBlockStructure` 完成,打印阶段不做 IR 变换。

## 2. `universal` 原子清单

树根:`ActionRestartGroup(rule_onceperfunc, "universal", maxrestarts=1)`(`coreaction.cc:5474`)。

```
universal (ActionRestartGroup, onceperfunc, max=1)          ← pending restart 时整树重跑至多 1 次
├─ 【头部 8 个顺序 Action】(仅一次)
│   1 ActionStart("base")         coreaction.cc:5477 → startProcessing (funcdata.cc:150):
│   │                               followFlow(baddr,eaddr) + structureReset + sortCallSpecs
│   │                               + heritage.buildInfoList + localoverride.applyDeadCodeDelay
│   2 ActionConstbase("base")                    :5478
│   3 ActionNormalizeSetup("normalanalysis")     :5479
│   4 ActionDefaultParams("base")                :5480
│   5 ActionExtraPopSetup("base", stackspace)    :5482
│   6 ActionPrototypeTypes("protorecovery")      :5483
│   7 ActionFuncLink("protorecovery")            :5484
│   8 ActionFuncLinkOutOnly("noproto")           :5485
├─ fullloop (ActionGroup, rule_repeatapply)      :5488
│   ├─ mainloop (ActionGroup, rule_repeatapply)  :5490
│   │   ├─ 18 个顺序 Action                       :5491-5511
│   │   │    Unreachable → VarnodeProps → Heritage(SSA) → ParamDouble →
│   │   │    Segmentize → InternalStorage → ForceGoto → DirectWrite("protorecovery_a") →
│   │   │    DirectWrite("protorecovery_b") → ActiveParam → ReturnRecovery →
│   │   │    RestrictLocal → DeadCode → DynamicMapping → RestructureVarnode →
│   │   │    Spacebase → NonzeroMask → InferTypes
│   │   ├─ stackstall (ActionGroup, rule_repeatapply)   :5512
│   │   │    ├─ oppool1 (ActionPool, rule_repeatapply, ~140 Rule + arch extra_pool_rules)
│   │   │    │    注册序:EarlyRemoval…PiecePathology + DoubleLoad/DoubleStore/DoubleIn/DoubleOut
│   │   │    │    (Rule 即原子单元:per-op getOpList/applyOp;池本身 repeatapply 至不动点)
│   │   │    ├─ ActionLaneDivide("base")
│   │   │    ├─ ActionMultiCse("analysis")
│   │   │    ├─ ActionShadowVar("analysis")
│   │   │    ├─ ActionDeindirect("deindirect")
│   │   │    └─ ActionStackPtrFlow("stackptrflow")
│   │   ├─ ActionRedundBranch("deadcontrolflow")  :5652
│   │   ├─ ActionBlockStructure("blockrecovery")  :5653  ← 控制流结构化
│   │   ├─ ActionConstantPtr("typerecovery")      :5654
│   │   ├─ oppool2 (ActionPool, rule_repeatapply, 5 Rule):
│   │   │    PushPtr / StructOffset0 / PtrArith / LoadVarnode / StoreVarnode
│   │   ├─ ActionDeterminedBranch("unreachable")
│   │   ├─ ActionUnreachable("unreachable")
│   │   ├─ ActionNodeJoin("nodejoin")
│   │   ├─ ActionConditionalExe("conditionalexe")
│   │   └─ ActionConditionalConst("analysis")
│   └─ fullloop 尾部 10 个顺序 Action(mainloop 之后,仍受 fullloop 不动点控制):
│        LikelyTrash → DirectWrite×2 → DeadCode → DoNothing → SwitchNorm →
│        ReturnSplit → UnjustifiedParams → StartTypes → ActiveReturn
├─ ActionMappedLocalSync("localrecovery")
├─ ActionStartCleanUp("cleanup")
├─ cleanup 池 (ActionPool, rule_repeatapply, 15 Rule):
│     MultNegOne / AddUnsigned / 2Comp2Sub / DumptyHumpLate / SubRight /
│     FloatSignCleanup / ExpandLoad / PtrsubCharConstant / ExtensionPush /
│     PieceStructure / SplitCopy / SplitLoad / SplitStore / StringCopy / StringStore
└─ 【尾部 28 个顺序 Action】(仅一次)
    PreferComplement → StructureTransform → NormalizeBranches →
    merge 链 13 个:AssignHigh → MergeRequired → MarkExplicit → MarkImplied →
      MergeMultiEntry → MergeCopy → DominantCopy → DynamicSymbols →
      MarkIndirectOnly → MergeAdjacent → MergeType → HideShadow → CopyMarker
    → OutputPrototype → InputPrototype → MapGlobals → DynamicSymbols(第 2 次) →
      NameVars → SetCasts → FinalStructure → PrototypeWarnings →
      ActionStop("base") → stopProcessing (funcdata.cc:172):
        flags |= processing_complete + obank.destroyDead + issueDatatypeWarnings
```

计数:顶层顺序 Action ≈ 46;Rule 池 3 个(oppool1 ~140 / oppool2 5 / cleanup 15);
不动点循环层 4 层(universal 重启 → fullloop → mainloop → stackstall;池自身也 repeatapply)。

## 3. 循环与观测机制(action.cc)

- **`ActionGroup::apply`**(:506):顺序遍历子节点 `perform`;子返回 `>0` 记 change count,
  `<0`(部分完成)则组也中断返回 -1;每次变更后 `checkActionBreak()` 可在任意 Action 上停住。
- **`rule_repeatapply`**:整组反复遍历直到一整轮 count==0(不动点)。
- **`ActionRestartGroup::apply`**(:553):`hasRestartPending` 时 reset 全部子节点(除自身)、
  `status = status_start`、整树重跑;`curstart > maxrestarts` 时 warning 并终止。
  jumptable recovery 期间不重启。**"第 0 轮 / 第 1 轮(restart)"是阶段属性,必须记录。**
- **断点**:`setBreakPoint(Action::break_action | break_start, name)`(ifacedecomp.cc:1196/1222)
  是 Ghidra 原生的"中途停下观察"机制;console 另有 dataflow/controlflow/dom 图 dump
  (ifacedecomp.cc:2526/2552/2578,仅导出观察用)。
- **Funcdata 无 saveXml/restoreXml**:锁定 oracle 不存在整函数 IR 的序列化/恢复。
  任何"每阶段缓存/断点续跑"设施在 Rugra 侧均无 oracle 对应物,属 RUGRA-GLUE 工具层,
  禁止进入对齐语义路径(见 §5)。

## 4. 稳定切点 vs 不稳定切点(差分/fixture 边界规则)

| 切点 | 稳定性 | 规则 |
|---|---|---|
| 顶层顺序 Action 之间(头部/尾部/merge 链内) | ✅ 稳定 | 每个 Action 完成即是边界 |
| repeatapply 组不动点收敛后(mainloop / stackstall / fullloop / cleanup 各自收敛) | ✅ 稳定 | 以"该轮 count 全 0"为完成判据 |
| 不动点循环内部某一趟之后 | ❌ 不稳定 | 组内成员相互反馈(oppool1 ↔ StackPtrFlow 等),中间态依赖遍历顺序 |
| Rule 池内按 Rule 切 | ❌ 不稳定 | Rule 按 op 遍历交错触发;Rule 级只能做单 op 触发观察,池级以收敛为界 |

任何阶段 fixture / 差分记录必须同时登记:阶段路径(树路径)、restart 轮次(curstart)、
各 repeatapply 组的 count 状态。

## 5. 每阶段快照/缓存的设计约束(RUGRA-GLUE,无 oracle 对应物)

1. **定位**:缓存是纯加速/调试设施,不得改变任何可观测行为;必须实现在驱动层
   (perform 树外层包装),禁止在 Action/Rule 内部感知缓存。
2. **快照手段二选一**:
   - A. 进程内 checkpoint:`Funcdata` 为纯数据结构(无 Rc/RefCell;仅 `self_ref: Weak`
     需克隆时置 None/重绑),手动 `Clone` 深 IR 可行;恢复 = 替换 fd 后继续 perform 余下子树。
   - B. 磁盘序列化:可跨 session 复用,但需要完整 Funcdata 编解码器;漏字段会造成
     "续跑结果 ≠ 全量结果"的静默正确性风险,必须配等价门禁(见 4)。
3. **缓存键(内容寻址)**:oracle/Rugra 源码版本(含 dirty 标记)+ 函数输入指纹
   (地址/字节/架构 spec/analysis options)+ 阶段路径 + restart 轮次 + 各组 count。
4. **失效规则**:保守 = 任一管线相关 `src/*.rs` 变更即整体失效;精确 = 仅使阶段路径的
   前缀算法失效。
5. **等价门禁**:对每个快照点,随机抽样"全量跑" vs "缓存续跑",最终输出(含 stderr
   warning 与最终 IR)必须字节一致;接入 `check_determinism.py` 式双跑框架。
