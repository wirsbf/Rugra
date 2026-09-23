# L1 — 事件溯源（Event Sourcing）

> 依赖: 无(第一个落地项)。状态: 设计。

## 动机（wave 实证）

Ghidra 的 Action/Rule 只做 in-place 突变,执行过程是黑盒。wave 为观测它付出的成本:

- stage 投影规范从 v1.0 演进到 v1.2.2（Gate 1 两次 REJECT + 两次勘误),10+ 个车道
  交付 harness/runner/消费端三方才凑齐观测能力。
- 归因一个首分歧需要:bisect 定位 ordinal → drill 窗口分解 → 分类学归因 → 人工读
  Ghidra 源码对照——每环都是独立车道的天级工作。
- "这个 op 谁杀的"这种问题,今天要跑一次全量镜像投影才能回答。

## 设计

**每条 Rule 每次 apply 发结构化 mutation 事件,持久化为 append-only log:**

```rust
struct RuleEvent {
    stage_seq: u64,            // 全局单调应用序号(即 v1.2.2 的 @BEGIN seq)
    tree_path: Path,           // "universal:fullloop:mainloop:stackstall:oppool1"
    rule: RuleId,              // 规则稳定 ID
    op: SeqNum,                // 目标 op (addr:time)
    before: OpSnapshot,        // 变更前(操作码/输入/输出/flags)
    after: OpSnapshot,         // 变更后
    created: Vec<OpRef>,       // 本次新建的 op(如 CAST/COPY 注入)
    destroyed: Vec<OpRef>,
    round: u32,                // restart 轮次(curstart)
}
```

- sink 经 trait 注入,IO 与逻辑分离(生产可关)。
- **格式语义基准 = docs/alignment_docs/STAGE_BISECT_SPEC_1204.md v1.2.2**——该格式
  已被 14 次机制 C 复核钉死,直接复用其字段语义,不发明新格式。

## 解锁的查询（原来天级 → 毫秒级）

- `explain(run, op) -> Vec<RuleEvent>`: op 的完整变更史(谁改的/何时/为什么)。
- `first_divergence(runA, runB)`: 事件流对齐比较——native stage_bisect。
- `killed_by(op) -> RuleId`: 定责直达。
- agent 归因循环从"跑投影+读源码"变为"查事件"。

## 实现锚点

`src/drillobserve.rs` 的 mod_check/flush(action.cc:316-322/:839-845 镜像)已是
per-op 突变钩子的原型;funcdata.rs 的 10 个变更入口(insert/remove/destroy 等)已挂
探针——L1 = 把探针语义正规化为核心事件流,退役外挂 harness。

## 门禁

- 事件流关闭时(默认)行为与现状逐字节一致。
- 开启时事件 log 本身过双侧一致性校验(同输入同事件流)。
- stage_bisect.py 消费端保留为交叉验证(核心事件流 vs 独立解析器,双通道互证)。
