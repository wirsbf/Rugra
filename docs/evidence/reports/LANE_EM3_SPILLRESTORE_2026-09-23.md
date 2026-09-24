# Lane EM3 终报 — MERGE-COPYNOISE-SPILLRESTORE-0001（EM/EM2 两次配额中断后接手,第三代）

- worktree: /dev/shm/rugra-worktrees/highint（branch wt/highint,基线=亲父 5cd326c0）
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b（worktree HEAD 已核验）
- 交付 commit: **5174d05f**（src/merge.rs + docs/api/merge.md + docs/TODO_BOARD.md 行;tree clean）
- 写域遵守: merge.rs + merge.md + TODO 行;varnode.rs/variable.rs/coreaction 零改动（探针已全部回退,`git show 5174d05f --stat` 佐证）

## 交付内容

1. **EM2 hang 真因钉死并修复**:EM2 记录的 "post-restart mergerequired 圈零进展锁等待" 不是 CFG 遍历里的阻塞读取,而是
   `high.write().cover_dirty()` 在外层写锁内调用 → `mark_extend_cover_dirty` 自腿（variable.cc:136 写回 own high）
   = **同线程同锁写重入死锁**。gdb 表象"thread running"与此吻合（写锁自等待在 Linux 上非可中断睡眠呈现）。
   逐步探针链:markexplicit 返回 → markimplied apply 内 `Unique+0x23600` → mark_implied 传播腿 →
   `high.write().cover_dirty()` 内部卡死。修复=merge.rs 新增 `mark_high_cover_dirty`（标志写与 piece walk 分窗,
   可观测状态与 variable.hh:275-281 逐位同）;EM2 因误判根因移除的成员重建链随之恢复。
2. **新鲜度协议完成**（oracle 强制语义,全在 merge.rs 域内）:
   update_high 成员 COVERDIRTY 扫描+无条件 purge（variable.cc:1153-1154;EM2 的 cover-identity purge 门移除——
   实例级 copy-shadow 判定下 cover 恒等不是可靠失效谓词）、update_high_cover 成员重建链恢复（variable.cc:331）、
   gather/test_block_intersection 惰性 getCover 读（variable.cc:951/975）、mark_implied 补全
   merge.cc:1594-1605（def 输入 COVERDIRTY+high 传播）、compute_varnode_covers sweep 传播。
3. **根因收窄（关键负结果）**:全新鲜 cover 下 main 对判定仍 intersect=true。census 触发对=
   Register+0xb0（R14 phi@0x2780 MULTIEQUAL）× Stack-0x240 MULTIEQUAL @blk29,双侧 span 均起于
   MULTIEQUAL marker-0（getUIndex 折叠）⇒ 端点语义精确的任意实现都会判区间相交。oracle 合并成功 ⇒
   其两侧 high 在 mergecopy 时点不含这对实例共存 ⇒ **R1（testCache 时序）/R2（high.cover 新鲜度）/
   R3（参数序）全部证伪为该症状成因**;真分歧在测试上游（high 实例组成/merge 候选生成）。
   EM2 中间态的"修复"=陈旧空 high cover 意外放行合并,非 oracle 行为,已随其噪声（uStack_248 27→11、
   mirror 模式 in_RDI +16）一并消除。

## 门禁（基线=亲父 5cd326c0 本 lane 亲测,plain-run,merge.rs 单文件换回法;非沿用旧数）

| 门禁 | 亲父 | EM3 | 备注 |
|---|---|---|---|
| curl 全语料 skeleton | 2593 | **2450** | getparameter 751→623/glob_word 27→23/glob_set 100→96/glob_range 85→84/file2string 120→119;main 588→591（纯编号位移）;defects/numbering 双侧 0/0 |
| httpd skeleton | 2335 | 2336 | +1=httpd main 域 int8 临时物化（合并判定新鲜度同族形态）;0 defects |
| gcc 审计 | 82 OK/25 FAIL | 82 OK/25 FAIL | 逐字相同 |
| lib 单测失败集 | 18（flaky 族） | 18（同名集合） | diff 为空 |
| 三投影 next_url/match_url/parseconfig | — | **v1.2 stage+snapshot identical MATCH ×3** | RUGRA_MIRROR=1 全家 env |
| --func main spill/restore 对 | 1（存在） | **1（仍存在）** | 目标 1→0 未达成,残差绑定本 ID |

注意:EM2 遗留工件 `em2/curl.parent2.c` 是 **RUGRA_MIRROR=1 镜像跑**（skeleton 4091）,与 plain 门禁不可比——
后继者勿再误用。

## 机制 C 复核请求（必须,merge.rs 属核心算法白名单）

commit 5174d05f 的改动面:update_high / update_high_cover / gather_block_varnodes /
test_block_intersection / block_intersection / mark_implied / mark_high_cover_dirty（新增）/
compute_varnode_covers 传播腿。复核者请自读:variable.cc:1148（updateHigh）、variable.cc:324-347
（updateInternalCover/updateCover）、variable.hh:275-300（coverDirty/isCoverDirty/getCover 内联）、
merge.cc:1594-1605（markImplied）、varnode.cc:352-374（setFlags 传播）、merge.cc:1616-1646（inflateTest
既有 EM2 段）。重点核查:①无条件 purge 与成员扫描的可观测等价性声明;②mark_high_cover_dirty 两窗顺序
（标志先、piece walk 后）与 oracle 内联的等价性;③mark_implied 输入收集槽序与 hasCover 门。

## 下一步建议（绑定 MERGE-COPYNOISE-SPILLRESTORE-0001,登记于 TODO 行）

mergecopy 时点双侧 high 实例组成差分:在 mergecopy 候选评估处 census (slot-high, __stream-high) 双侧实例清单
（地址+def op）,对照 oracle drill（/dev/shm/rugra-tests/sb-drill/curl.main.oracle.drill,@0x2780 phi 族
18ca/18cc/18cd…）找出 oracle 侧缺少/多出的实例及其产生 pass(mergerequired/mergeentry/dominantcopy 的
实例搬运差)。census 探针原始输出留档 /dev/shm/rugra-tests/sb-highint/em3/main.census.stderr.log
（[EM3-BI] 行,98 条,R14-phi 触发对在列）。

## 资源与回收

- /dev/shm/rugra-tests/sb-highint/em3/:保留 census/commitmsg/门禁小结等小件;21MB 三投影与 E2E .c 产物已清理。
- /dev/shm/rugra-targets/sb-highint:待 root 集成后回收（本 lane 不动）。
- 前代工件（main.baseline.c/probe*/em2/*）保留未动,属 EM1/EM2 会话证据。
