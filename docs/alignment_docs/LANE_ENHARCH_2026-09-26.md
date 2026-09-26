# LANE ENHARCH — 增强轨总体架构设计（docs-only 设计票）

> 日期 2026-09-26 | 车道 ENHARCH（worktree /dev/shm/rugra-worktrees/enharch，分支 wt/enharch）
> 交付：docs/alignment_docs/ENHANCED_TRACK_ARCH_2026-09-26.md（架构图纸，9 节）+ docs/TODO_BOARD.md 增强轨票池（10 票）。
> commit：**e376c26c**（单原子 commit，2 文件 +372/−1；三门禁+gate health 全绿；机制 A 红词未触发）。
> 零 src 零 tools；MB18 并 master 期间基线=中间态，docs-only 零冲突。worktree+分支留 root 合并（MB19）。

## 交付物结构

**图纸 ENHANCED_TRACK_ARCH_2026-09-26.md**（§〇执行摘要/§一第一性原理与双脸纪律/§二统一输入契约/§三分层组件图/§四 PRINTIR 渲染器/§五 Pcode2C sidecar/§六排程里程碑/§七风险与诚实边界/§八零矛盾自检/§九票池指针）。

**票池（TODO_BOARD 尾部新节，全部 ENHANCEMENT 域声明）**：
IRFIX-CONTRACT-0001（P1）/ SAILR-PHASE2-SEAM-0001（P1，SAILR-PORT 在飞线）/ IRCONV-PASSMENU-0001（P2）/ GEP-RECON-0001（P2）/ PRINTIR-RENDERER-0001（P1）/ BEHAVIOR-SIDECAR-0001（P1）/ SEL-TRIPLEGATE-0001（P1）/ STRIDE-SIDECAR-0001（P2）/ TRex-TYPE-SOCKET-0001（P2，深挖前置）/ ERASE-DEINLINE-0001（P3）。
任务书点名的四 ID（PRINTIR-RENDERER-0001/IRFIX-CONTRACT-0001/GEP-RECON-0001/BEHAVIOR-SIDECAR-0001）全部在池（机器自检 doc↔board 双向 10/10 一致）。

## 核心架构裁决（一段话版）

反编译质量=重建表示向语义 IR 的收敛度；Rugra 双脸双 oracle——默认脸收敛于锁定 oracle（canon/fixture 门禁冻结），增强脸收敛于源码语义（DecBench 三指标+行为门禁，Ghidra 自身 Union 32.26/type_match 7.56 只是起点不是天花板）。增强组件全部走可配置路径：env 门控默认关（MIRROR 存在性开关先例）+ 纯增量写域 + 恢复层 100% 复用（printc 前 IR 即增强脸输入面，双先例背书：Ghidrall/Patchestry 独立同选此切点）+ 末端逐函数择优（默认候选恒在场=oracle 字节恒等回退）+ 记分双列。十组件分四层：L1 基座（默认脸主管线+raw pcode 旁路）→ L2 接口（IRFIX 契约=stage 投影 v1.2.2 增强面+Patchestry 五缺口补齐、MULTIEQUAL 原样保留 SSA=比三先行工作都强；PRINTIR .ll 渲染器=SSA 直发+mem 兜底档，三用途排序：IR 级差分仪器>机器消费面>DecBench 侧车）→ L3 变换（SAILR 在飞/GEP 单 struct 帧/pass 菜单/TRex 插座/ERASE，全部契约→契约纯函数）→ L4 决策（三重门禁选择器：汇编 diff+arity+SMT 调用序列，行为 sidecar=Pcode2C 逐字 C 从 raw pcode 直达，Decompile-Diverge 教训=可编译性非语义门禁）。

## 排程建议（MB19 后）

关键路径 = **C1 契约 → C2 SAILR Phase 2 缝 → C9 选择器**；增强脸首跑最低组件集={C1 减配版（块出边+DECLARE 先行）+ C2 缝 + env 门控双脸发射}。里程碑：M1 契约 v1（1-2 车道周）∥ M2 Stage 0（DECBENCH 车道独立线）→ M3 增强脸首跑（SAILR 全链 10-20 车道日）→ M4 PRINTIR v1 → M5 三重门禁闭环 → M6 类型层（STRIDE→TRex）→ M7 Stage 4 冲榜（Union>41.06+type_match>7.56）。C6 sidecar 无前置可随时并行开工。Union>41.06 组合路径：≈Ghidra（32% 档）+SAILR（kuna 同族 28.45→39.05 空间）+类型洼地（kuna 6.91）+byte_match 选择器闭环（kuna roadmap 16.4 空窗，D-LiFT 窗口期真实动作要快）；反面锚=codex byte 15.08 但 Union 26.49——单指标突进换不来 Union。

## 主要风险（图纸 §七全表）

每组件两栏（先例背书 vs 设计判断）：最大未知数=①SAILR 的 angr 图模型适配（Phase 2 缝核心）②PRINTIR SSA 直发无先例（三先行工作全发内存形态，留 mem 档对冲）③TRex artifact 内部形态未深挖（123/125 为论文自报）④ERASE 的 GED 收益是机理推论非实测⑤C9 三 gate 的错杀率与 SMT 求解器依赖引入方式（需 root 裁决）。GEP 层特注：我们 varmap 已恢复相对索引，收益可能显著小于 Ghidrall 文献值（86.08%），触发即测不预支。

## 收尾

/dev/shm/rugra-tests/enharch 不存在（本车道未产生测试代码，无物可清）。worktree+分支留 root（MB19 合并；图纸+票池与 master 上任何在飞 docs 变更的冲突面=TODO_BOARD 尾部 append，union 即净）。
