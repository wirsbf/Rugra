# L4 — 持久化 IR 与廉价分叉（Persistent IR + Fork）

> 依赖: L2(确定性)、L1(事件流)。状态: 设计。**AI-native 的分水岭。**

## 动机（wave 实证）

wave 最贵的动作循环: 假设修复 → release 构建(4-5min) → 全量 E2E(1-2min) → 双语料
差分 → 对比。**每个假设的全量重跑成本 ~7min,而真正的信息量只有 diff 那几行**。

- 现在 Funcdata 是单一可变状态(Arc/RwLock 共享),无快照;restart = clear + 从头重做
  全部 stage。
- agent 无法"从 stage N 分叉试 3 个修复择优"——只能串行全量跑 3 次。

## 设计

**IR 用结构共享的持久结构(Arc 语义,类 git):**

```rust
let snap = run.snapshot();                    // O(1): 不可变根 Arc
let fork = run.fork_at(Stage::Heritage);      // 从任意 stage 分叉,共享底层节点
// 对 fork 应用修复 A/B/C —— 各自 O(diff) 写放大,共享未变部分
let div = diff_runs(&original, &fork_b)?;     // 结构 diff,非文本 diff
let best = evaluate([fork_a, fork_b, fork_c])?;
run = best;                                   // 择优落定
```

- Varnode/PcodeOp/BlockGraph 已部分 Arc 化;补全"突变即新建+指针替换"路径
  (write-path 改造是主要工程量,与正典突变语义的 parity 用 L1 事件流验证:
  持久化路径的事件流必须与现状逐事件一致)。
- fork 天然携带分叉点事件流前缀 → diff_runs = 事件流对齐比较(L1 的 native 化)。
- 内存盘语义: 大规模分叉的快照落 /dev/shm(回收纪律同 AGENTS worktree 规则)。

## 收益量化(wave 数据)

- 假设验证成本: 7min(全量) → O(diff)(秒级),试错预算放大 ~100 倍。
- 归因试探(如"这个 op 不死会怎样"): 现在不可能 → fork + 屏蔽单条 Rule 一跑即得。
