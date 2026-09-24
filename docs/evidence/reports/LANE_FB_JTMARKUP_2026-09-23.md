# LANE REPORT — FB jtmarkup（JUMPTABLE-MARKUP-CONSUMER-0001）

- Branch: wt/jtmarkup @ **a62435d4**（基=master 1b0acf11；master 后移 dc62a4bf 为注释级，
  门禁数字同基线；oracle=Ghidra 12.0.4 e40ed130 逐行亲读）
- CARGO_TARGET_DIR=/dev/shm/rugra-targets/sb-jtmarkup（+sb-jtmarkup-base 亲父 A/B、
  sb-jtmarkup-jtg-* fixture 探针；均已回收）
- 写域: src/jumptable.rs + docs/api/{jumptable,rangeutil,lib}.md + docs/TODO_BOARD.md 本行；
  rangeutil.rs 零改动（正典 pull_back EZ 已落，CR14 已核）

## 1. markup 消费链断点（一句话）

**车道前提对 12.0.4 oracle 证伪**：jumptable.cc:1103（analyzeGuards）与 cc:1362
（checkUnrolledGuard）两处均 `Varnode *markup; // Throw away markup information`——
声明传入 `rng.pullBack(readOp,&markup,usenzmask)`（cc:1106/cc:1366）后**从不读取**；
jumptable.cc 全文无 copySymbolIfValid/copySymbol 调用。12.0.4 中 pullBack markup 的
唯一消费者是 **RuleRangeMeld**（ruleaction.cc:1416，EZ 0d4e1602 已接，CR14 APPROVE）。
"jumptable 恢复路径消费 markup（EquateSymbol 标注）"对本 oracle 不成立——不存在可接
的消费链。真正的预存缺口是**调用形态**：jumptable.rs 保留本地自由包装
`pull_back_through_op`（与 EZ 在 ruleaction 删除的 pull_back_op 简化版同型），且带一处
Ghidra-unreachable 行为微差（missing out 回退 `unwrap_or(in_size)` 续算，正典按
"Ghidra 无条件解引用 getOut()" 语义返 None）。

## 2. 前后形态

| 项 | 前（1b0acf11） | 后（a62435d4） |
|---|---|---|
| analyze_guards（cc:1106 镜像） | `pull_back_through_op(&mut rng, &read_op, usenzmask)` 本地包装 | `rng.pull_back(&read_op, usenzmask, &mut None)` 正典 + discard 槽 |
| check_unrolled_guard（cc:1366 镜像） | 同上 | 同上 |
| 本地包装 pull_back_through_op（~102 行） | 存在，重复实现 | 删除 |
| cc 行号注释（两调用点周围） | 漂移 +1（8 处） | 修正（CR14 annotation-drift 尾巴） |

`usenzmask` 语义不变：analyze_guards `= !parent.partial_table`（cc:1052）、
checkUnrolledGuard 参数透传（cc:1337）。

## 3. 三门禁 + 投影（基线=亲父 1b0acf11 pristine worktree 亲测）

| 门禁 | child | parent | 判定 |
|---|---|---|---|
| curl E2E vs ghidra_curl_1204 | **2511/0/0** | 2511/0/0 | ==基线==任务书（master dc62a4bf ≈2511/0/0） |
| httpd 门禁面 vs ghidra_httpd_1204 | **2282/0/0** | 2282/0/0 | ==基线==任务书 |
| httpd full 840 | panic=0 TIMEOUT=0 not-settling=1 | — | not-settling==预存（pcre_exec） |
| 三投影 next_url/match_url/parseconfig | **MATCH×3**（RUGRA_MIRROR=1，stage_bisect v1.2 stage+snapshot identical） | — | ==
| jumptable 族（getparameter/glob_word/file2string + next_url 投影 + curl E2E 全文） | **A/B 亲父六输出字节恒等** | — | 潜伏类实证 |
| 族 oracle 分歧 provenance | V1_RESULT_COUNT / V1_OP_LINE×2 | 同 kind 同位 | 预存已登记残差（GETPARAM-OPPOOL/SWITCHNORM 族），非本 lane 引入 |
| --func getparameter/glob_word/file2string | defects=0 numbering=0 ×3 | — | skeleton 残差=既有变换级 |
| jumptable 单测 / rangeutil 单测 | **36/36** / **54/54** | — | |
| check_ghidra_annotations / check_ghidra_refs（97 files） | 通过 | — | commit hook 亲跑 |

jt_guards_1204 fixture：对 master API 已陈旧（JumpBasic::new/analyze_guards 的
JumpParentFacts 签名漂移，2026-09-22 返修引入），双侧同败——root 重钉时顺带更新。

## 4. 改动清单

- src/jumptable.rs：+2 调用点切正典（discard 槽）+ 8 处注释行号修正 −包装删除，净 −116/+41
- docs/api/jumptable.md：新 2026-09-23 小节（oracle 事实核对+改动）+ 两处历史条目补撤注
- docs/api/rangeutil.md / lib.md：包装删除撤注
- docs/TODO_BOARD.md：JUMPTABLE-MARKUP-CONSUMER-0001 DONE 行（含证伪结论+验收证据）

## 5. 机制 C 声明

jumptable.rs 是机制 C 显式白名单模块：a62435d4 携 ## Alignment Evidence（四类语义
4/4，analyzeGuards/checkUnrolledGuard 双函数签名行）+ ## Differential + 
**Cross-Review: PENDING**。**请求 root 集成时派独立复核**，重点：
1. 两镜像 discard 槽语义（oracle throw-away 局部的逐字镜像，markup 永不读取）；
2. usenzmask 派生（!parent.partial_table / 参数透传）未动；
3. 删除的包装与正典 pull_back 的等价性（唯一行为差=missing-out 回退，Ghidra-unreachable）；
4. FUNCTION_LEDGER.json 仍含 pull_back_through_op 条目（生成物，账本重建时回收，
   非本 write-set）。

## 6. 工件与回收

- 证据包: /dev/shm/rugra-reports/sb-jtmarkup/evidence/（ab_identity、双侧 gate、
  6×mbisect、单测输出、commit_msg、curl_cur.c 快照、run_verify.sh/run_parent_ab.sh）
- /dev/shm/rugra-tests/sb-jtmarkup 原始大件已自清；targets sb-jtmarkup(+base+jtg×2)
  已回收；jtmarkup-base 亲父 worktree 已移除。lane worktree
  /dev/shm/rugra-worktrees/jtmarkup 保留待 root 集成。
