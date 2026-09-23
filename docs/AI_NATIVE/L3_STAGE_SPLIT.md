# L3 — 显式阶段拆分（Explicit Stage Pipeline）

> 依赖: L1(事件流为拆分提供观测验证)。状态: 设计。

## 动机（wave 实证）

- 78 节点 Action 树(4 层嵌套 repeatapply)的依赖是**隐式的**: blockstructure 消费
  heritage 结果、print 消费 markLabelBumpUp——结构上看不出来,只有读源码/踩坑才知道。
- wave 踩过的坑: orderBlocks 未接线导致 BlockBasic 多范围 cover 缺失,下游 label 全
  偏移(ord 50 根因);markLabelBumpUp 死代码被发现前文档曾虚报"五连调用完成"。
- 阶段边界是隐式的 → per-stage 缓存/并行/断点都无从谈起。

## 设计

**逻辑投影先行,物理拆分后置:**

1. **逻辑投影**(纯观测层,零执行变化): 每个 tree 节点归属一个 typed Stage
   (Lift/Ssa/Structure/Type/Print),阶段间数据流声明为
   `StageIO { reads: Vec<Effect>, writes: Vec<Effect> }`——从 L1 事件流自动推导
   依赖图并校验人工声明(声明≠事实时报告)。
2. **API 断点正规化**: 现在 breakpoint hack(setBreakPoint/perform -1 续跑)转为
   `run.stop_at(Stage::Heritage)` 一等公民。
3. **per-stage 缓存**: 改打印规则不重跑 lift;stage 输入哈希相同则复用输出——
   agent 试错的构建成本从"整库 release 4-5min"降到"单 stage 增量"。
4. **跨函数 stage 并行**: 函数间本就独立;stage 边界显式后可安全交错调度 112 核。
5. **物理拆分**(执行重排)只在 parity 证明后、且只对声明无依赖的 stage 开启。

## 铁律

- **顺序即语义**: 拆分是逻辑投影,不得隐式重排执行序——Ghidra 的 perform/apply
  次序是行为的一部分,wave 的双 MATCH 依赖逐序对齐。
- 每步拆分过门禁: 逐函数 stage 投影 MATCH + 双语料 E2E defects=numbering=0。

## 与现有资产

- `docs/alignment_docs/PIPELINE_STAGES_1204.md`(78 节点权威清单)即逻辑投影的
  事实起点;stage_bisect 的 tree-path 寻址空间直接沿用。
