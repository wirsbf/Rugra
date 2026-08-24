# W-2026-08-24-TRIFUNC-GAP 状态快照 v2（2026-08-25 03:05，接续 MID 版）

> 任务唯一事实源仍是 docs/TODO_BOARD.md。本快照记录 MID 之后的增量。

## 1. E2E 基线演进链（关键决策记录）

| 时点 | sha | skeleton/defects/numbering | 事件 |
|---|---|---|---|
| f7b3c31（wave 起点） | `fc9a33ba…` | 2409/2/1 | 交接基线 |
| A9 flow 后 | `68d4041a…` | **2377**/2/1 | 尾调用 PIC 修复：5→0 误报、glob_word 176→144（wave 首次全局改善） |
| A20 driver 后 | （折入下行） | — | UTF-8 门+DAT 层：5 行已归因（1 计数+4 预存命名） |
| A14 varmap 后 | `b9f34811…` | 2405/2/1 | **Differential 已裁决**：+28 为窗口×未修症状2 交互（my_get_line 151→160），oracle 级修复方向已证（R8 APPROVE），保留集成，A25+A28 合流后复测回收；match_url/_start 改善 |

## 2. MID 后新增集成（全部有复核或差分门禁）

exact-piece callers（f87e4d8，R4 复现级 APPROVE）→ downchain virtual（3fa2802，R6 APPROVE）→
typeop localbase defaults（0f0a060，M1 证据锁定）→ flow overtrace（bdc7f34）→
stringmanage Java 契约（11371d5，18/18；43min 死锁根因=RwLock 重入已修）→
noreturn 段a（7b1da21，6/6；copy_flow_effects 自创语义纠正）→
driver a0（e20ca72+debc817，checker 放宽经 root 亲自复核）→
varmap 窗口（c042d9a+4fcfc1b，R8 REJECT→返修→APPROVE 闭环）→
varmap fixture 重钉（5fde682）。

## 3. 复核流水记录

R4（exact-piece APPROVE）R6（downchain APPROVE）R8（varmap REJECT→返修→APPROVE，抓出 Range::operator< 排序键前提错误）
R9（heritage 附条件 APPROVE，F1/F2 整改中）R7（breakpool rebase 8 语义点裁决，uVar 标签阻断→R10 post-varmap 重裁）
R10/R8 快速复审在途。**机制 C 的两次 REJECT 都抓到了 fixture 抓不住的真问题**（排序键前提、跨趟持久性缝隙）。

## 4. 审计驱动的连锁发现（新增登记）

FSPEC-JUSTIFIED-CONTAIN-0001（极性 bug，guardReturnsOverlapping 不可达，A26 修中）、
VARMAP-CROSSPASS-PERSISTENCE-0001（跨趟 ScopeLocal 持久性）、
VARMAP-GATHEROPEN-GUARD-0001（S3 解锁）、FUNCDATA-NEWVARNODE-FLAGS-TAIL-0001（R9-F2）、
HERITAGE-GUARD-FLSYMBOL-TIEBREAK-0001（R9-F4）、FLOW-NORETURN-DATA-0001（A28 修中）。

## 5. 在途（12）：A10 blockstruct / A16 heritage 整改 / A21 D2（首个预期移动 E2E 的 type 波）/
A22 jtpipeline 段1 / A23 ConstantPtr a1 / A24 printc / A25 noreturn 段b / A26 justified-contain /
A28 noreturn 数据源 / A29 W2 前滚 / R10 breakpool 裁决。（A27 重钉已完成）

## 6. 纪律沉淀

同文件单 writer（A4/ACTIONPOOL 事故→板头铁律）、构建 timeout 600（死锁事故）、
集成前租约查重、W 系列四件套全提（W1 漏三件教训）、E2E 基线随集成演进重钉。
