# W1 独立复核报告 — REGISTRY-CONTINUITY-W1-0001 (commit 52e4421)

- 复核 Agent: W1 独立复核（机制 C 精神；只读 worktree + git 历史，未改任何仓库文件，未跑 cargo）
- 复核对象: worktree `/home/wirs/.cache/rugra-wt-registry-w1`，分支 `agent/registry-continuity-w1`，提交 `52e4421`（"registry: roll continuity checkpoint 9640->9726, regenerate central ledgers"），base `92fd927`
- 方法: git show/diff/rev-parse + 只读加载 `tools/generate_function_ledger.py`（52e4421 版）内部解析器（`_scan_rekey_blob` / `_scan_rust_revision` / `rust_identity_projection_sha256`）+ 在 worktree 上运行只读 `--check` 门禁（`write_or_check(check=True)` 仅 read+compare，已核实无写路径）
- 日期: 2026-08-24

## 总判定: APPROVE

7/7 复核项全部 PASS。另做了 3 组超出清单的独立闭环验证（净账目、fail-closed 逻辑、DAG 对 B8 独立预测的吻合），亦全部通过。无阻断问题；4 条非阻断建议见文末。

---

## 1. append-only 不变量 — PASS

对比 `92fd927..52e4421` 的 `docs/alignment_audit/FUNCTION_ID_CONTINUITY.json`（+2075 行）：

| 部分 | 结果 |
|---|---|
| `baseline` 块（9 字段含 ledger_blob/sha、migration_blob_at_checkpoint/sha、src_tree、9639 records） | JSON 序列化完全相等，逐字节未改 |
| `id_scheme` / `oracle_commit` / `schema` / `semantics` | 完全相等 |
| 旧 2 条 lineages（`RG-F-7622630f…`/`RG-F-c76e93f7…`，36633d9 half_delete 对） | 对象保留且**原始文本块逐字节相同**（grep -A24 提取对比 0 diff）；位置从 [0],[1] 移至 [12],[20]，列表按 `base_id` 字典序确定性重排（`sorted(bases)==bases` 实测成立），非内容篡改 |
| 旧 1 条 introduced_live（`RG-F-2646dcd0…`） | 对象保留，文本块逐字节相同 |
| `docs/alignment_audit/FUNCTION_ID_MIGRATION.json` | **blob id 完全相同**（`8ecab1e6160b…` 两 rev-parse 一致）= 历史迁移表逐字节不可变 |
| `checkpoint`/`history`/`stats` | 仅前滚字段变化：36633d9→92fd927、src_tree ae8f4a75→af8f7a93、9640→9726、projection 3484939c→d68a155b、commit_count 31→85（first-parent span 实测 85 ✓） |

stats 新值（lineages=31, introduced_live=91, reviewed_transitions=28, tombstones=4, current=9726）与 commit message 及实体列表长度一致。

## 2. reviewed transitions 抽查 — PASS（10/10，覆盖全部 9 个 commit）

用生成器自身扫描器（`_scan_rekey_blob`，ID = `stable_id("RG-F",(module,owner,signature))`）对每条 transition 的 parent/child blob 独立解析。抽查 10 条 REVIEWED（判据：child/parent blob pin、from_id 在 parent 唯一、to_id 在 child 唯一、from_id 在 child 消失、同 path/owner/name 下 1:1、签名逐字匹配）：

| # | base_id | commit | path | fn | 演化 |
|---|---|---|---|---|---|
| 1 | RG-F-09d0ffc3… | 33793c13 | src/flow.rs | fallthru (impl:FlowInfo<'a>) | `-> ()` → `-> Result<()>` |
| 2 | RG-F-29f1bd83… | 33793c13 | src/flow.rs | finish_process_instruction | Result 错误通道 |
| 3 | RG-F-2c988c04… | 3be7b24c | src/flow.rs | build_callother_op (free) | `PcodeOp` → `PcodeOpRef` |
| 4 | RG-F-56aa5a2c… | cad41c27 | src/fspec.rs | find_call_op (impl:FuncCallSpecs) | `fd` → `_fd` |
| 5 | RG-F-72110be6… | 0d2252dd | src/flow.rs | set_block_range | bounds u64→Address |
| 6 | RG-F-9f45a266… | 87f9309b | src/fspec.rs | decode (impl:ParamListStandardOut) | `_decoder`→`decoder` |
| 7 | RG-F-cb145336… | 805cf887 | src/fspec.rs | register_trial (impl:ParamActive) | `-> ()` → `-> bool` |
| 8 | RG-F-d21d7ad7… | 577e54bb | src/typeop.rs | propagate_from_pointer (free) | +dereference_size 参数 |
| 9 | RG-F-f828f9d8… | e9a0b7a8 | src/merge.rs | merge_test_must (impl:Merge) | `bool` → `Result<()>` |
| 10 | RG-F-7d56bab7… | 33793c13 | src/funcdata.rs | override_flow (impl:Funcdata) | Result 通道 |

10/10 全 PASS。覆盖 commit：33793c13(×3)、3be7b24c、cad41c27、0d2252dd、87f9309b、805cf887、577e54bb、e9a0b7a8（全部 9 个）。抽样包含 name 重载场景（fspec.rs 中多个 `decode`）——owner+name 维度 1:1 成立。附带复验 36633d9 的 2 条 AUTO（half_delete_in/out_edge `slot`→`mut slot`）：blob pin 正确，纯 mut-binding 差异。

注：初版抽查脚本用"from_signature 子串不在 child"与"按 name 计数"两个粗判据误报 3 条 FAIL，换用生成器解析器后全部通过——初版误报是复核方法缺陷，非数据缺陷。

## 3. 4 tombstone + 1 ephemeral — PASS

**Tombstones（4/4 PASS，判据：parent/child blob pin、base_id 在 parent 唯一解析、child 中消失、child 中无同 owner+name 后继=纯删除）**：

| base_id | commit | path | fn |
|---|---|---|---|
| RG-F-002a9ec1… | 874e81f | src/type_system/typefactory.rs | array_element_matches (impl:TypeFactory) |
| RG-F-5ec71c48… | 92daed3 | src/coreaction.rs | ptr_to (free) |
| RG-F-bd9141cd… | cad41c2 | src/funcdata.rs | block_index_for_op_addr (impl:Funcdata) |
| RG-F-e43c2d78… | cad41c2 | src/ruleaction.rs | find_call_spec_by_addr (impl:RulePiecePathology) |

**Ephemeral（PASS）**：`RG-F-763fefee…` = `test_series_b_named_scope_preserves_non_b_pointer_projection`（typefactory test，is_test=True，line 5129）。实测：874e81f 引入端（parent 无 / child 有，blob pin 一致）；23ef9c9 删除端（`23ef9c9^` == 874e81f 相邻 commit，parent_blob f2e73aa6 / child_blob 78d21a33 pin 正确，parent 有 / child 无）；该 ID 在 baseline ledger(8d12962)、92fd927 ledger、52e4421 ledger、MIGRATION.json 新旧两版中**全部零出现**——"从未出现在任何 pinned ledger" 成立，schema 1 无法编码 introduced-then-deleted origin 的 retiring 理由成立。

## 4. 幂等复现 — PASS

在 worktree HEAD=52e4421（工作区 clean）实测：

```
$ python3 tools/generate_function_ledger.py --check
generate_function_ledger: verified definitions=9494 raw=15811 rust=9726     # rc0
$ python3 tools/generate_function_ledger.py --reconcile-continuity --check
generate_function_ledger: reconciled continuity baseline=9639 current=9726
  lineages=31 introduced=91 tombstones=4                                   # rc0
$ python3 tools/oracle_registry.py migration-status --strict               # rc1
registry statuses: MATCH=53, MISMATCH=21, PARTIAL_MATCH=32, UNTESTED=12
plan: auto_replacements=9, rekey_gap_family_size=3, unmappable=21
$ python3 tools/oracle_registry.py doctor --json                           # rc1, 188 issues
```

- 双 `--check` 全绿（rc0），生成物与 continuity 重放均幂等。
- `migration-status --strict` = **rc1（EXIT_FINDINGS）而非 rc2（EXIT_HARNESS）**：oracle_registry.py:96-98 定义 EXIT_FINDINGS=1/EXIT_HARNESS=2；B8 审计实测的 92fd927 状态 rc2（"continuity HEAD src tree differs from checkpoint"）已消除，loader 完整跑完。
- doctor 188 issues / migration-status 490 blockers 均为 fixture registry 层存量 corpus findings（本 commit 未触碰 tests/oracle/ 任何文件，`git show --stat` 六文件可证）；STALE_FUNCTION_ID=9 与 B8 预测的 9 条存量 stale_migratable 一致，UNMAPPABLE=21 与 tools/README.md 记录的 21 处 GH placeholder 一致——**非本 commit 引入的回归**，属 commit message 所述 "documented for the fixture registry landing batch" 的后续批次范围。

## 5. PROTOCOL_TABLE.json 同批提交正当性 — PASS

生成器主流程（无参模式）将 4 个生成物放进同一 `outputs` dict 循环 `write_or_check`（generate_function_ledger.py:4644-4651）：FUNCTION_LEDGER.json、FUNCTION_MAP.generated.md、**PROTOCOL_TABLE.json**、DEPENDENCY_DAG.json。`--check` 任一文件 stale 即 raise（`write_or_check`: "generated file is stale"）。src 前滚导致 PROTO 行号平移与 id 变化（diff 全为 `id`/`line` 行替换）——不提交它则 `--check` 必失败。同批提交是幂等的必要条件。

## 6. 3 条 rekey_gap_family 零引用 — PASS

三个旧 ID 仅存在于 `FUNCTION_ID_MIGRATION.json` 的 `old_id`（reason=rust_identity_rekey）：

- `RG-F-7e4bf41954d3fba2ded4` → `RG-F-5ec71c480ba4438dca3a`（= tombstone ptr_to base_id）
- `RG-F-9af4ae6c76903376917b` → `RG-F-e43c2d78ba8a0472a781`（= tombstone find_call_spec_by_addr base_id）
- `RG-F-c64137180dbec03023af` → `RG-F-bd9141cd6ae9f5a4ddad`（= tombstone block_index_for_op_addr base_id）

`git grep` 三个旧 ID 于 `92fd927 -- tests/`（含 fixture_registry.json + 133 个 metadata.json）与 `52e4421 -- tests/`：**全部零命中**（rc1 = no match）。迁移目标恰为三个 tombstone base_id（目标已死 → gap family），与 migration-status `rekey_gap_family_size=3` 一致。零引用声明成立。

## 7. 新 checkpoint pin 一致性 — PASS

- `92fd927:src` == `af8f7a9318d6f9b6429c840a0eeac611c508f539` ✓
- `52e4421:src` == `92fd927:src`（本 commit 只动 tools/ 与 docs/，故 loader 在 HEAD 通过）✓
- `92fd927^{tree}` == `d447eb3c2ebb…` ✓；`92fd927^` == `482f955`（checkpoint.parent）✓
- **fresh 扫描复现**：用生成器 `_scan_rust_revision(root,'92fd927')` 实测 **9726 条记录、projection sha256 = `d68a155b27d1d6003…` 与 checkpoint pin 完全一致** ✓
- `git rev-list --first-parent 8d12962..92fd927` = 85 == history.commit_count ✓；history.first_commit == span 末位 ✓
- 91/91 introduced_live 的 base_id 全部在 92fd927 fresh scan 中解析 ✓；全部在新 ledger 中存活 ✓；31 个 lineage new_id 全部在新 ledger、31 个 base_id 全部不在 ✓；4 tombstone 全部不在 ✓

---

## 附加独立验证（超出清单）

### A. 净账目精确闭环（无静默 ID 漂移）

对比已提交 ledger 的 rust_functions ID 集（旧 9639 → 新 9726，**+122 / −35**）：

- removed 35 = 4 tombstones + 31 lineage base_ids + **0 未解释**
- added 122 = 91 introduced_live + 31 lineage new_ids + **0 未解释**

每一个 ID 消失/出现都被 continuity 记录精确解释，不存在未登记的 rekey。checkpoint 口径账目 9640 + 90 新 introduced − 4 tombstone = 9726 亦自洽（2646dcd0 已在旧 checkpoint pin 内、属旧 introduced_live）。

### B. 生成器 fail-closed 强化

`function_id_continuity_document`（generate_function_ledger.py:3203-3219）对 transitions/introduced_live/tombstones 三组 **exact-set 匹配**：重放结果与 `CONTINUITY_EXPECTED_*` 常量集合任一元素漂移即 `MigrationHarnessError`。相比 base 版"拒绝任何 tombstone"，新改为"pin 精确期望集合"，收敛且不可绕过。reviewed 规则常量计数：TRANSITIONS=28、TOMBSTONES=4、EPHEMERAL=1，与 stats 一致。

### C. 其余生成物一致性

- FUNCTION_LEDGER.json summary：rust=9726 / production=8024 / test=1702，与 FUNCTION_MAP.generated.md 声称的 8024+1702 一致 ✓
- DEPENDENCY_DAG.json：todo_nodes 429（+29，0 删除） / todo_dependency_edges 160——**边数与 B8 审计对定稿板的独立模拟预测（160）完全吻合**；`ACTIONPOOL-CLONE-FILTER-0001 → PIPE-DERIVED-TREE-0001` 边已恢复（B8 判定该边"其实是板面正确边"）✓；新增 29 节点 = TRIFUNC-GAP wave 租约（TYPEFACTORY-*/SPLITDATATYPE-*/TYPEFIELD-*/TYPEOP-FSPEC-SPACE 等，92fd927 注册）+ B8 第 1 步回填账 ✓
- 生成器自检（self-test）通过由 commit message 声称；本次复核以 `--check`/`--reconcile-continuity --check` 双绿等效覆盖。

---

## 建议（非阻断）

1. **commit message 的 "31 lineages" 表述**：其中 2 条（36633d9 half_delete 对）是旧 checkpoint 已有 lineage 的重放保留，非本次新认定；本次新增为 29（26 reviewed + 3 auto？实测新增 reviewed=28 条规则中含 36633d9 之外的 28 条，AUTO 新增 1 条 find_add）。stats 字段语义准确，仅叙述可更精确。
2. **两个计数口径并存**：checkpoint pin 口径 9640（=9639 baseline + 2646dcd0，36633d9 时刻）与 92fd927 已提交 ledger 的 9639。两者均自洽，但未来读者 diff ledger 会看到 +122/−35 而非 +86；建议 fixture registry 落地批次的文档里点明这两个口径，避免误解。
3. **doctor 188 / migration-status 490 findings** 是 fixture registry 落地批次的既有欠账（本批无法也不应消化）；落地时按 B8 §3 第 4 步验收口径核对（预期 9 条存量 stale_migratable、rekey_gap_family 3 条随 tombstone 语义处置）。
4. **continuity 文件 diff 噪音**：lineages/introduced_live 按 base_id 全局重排导致旧条目位置移动；排序键确定性已证，重放幂等已证，仅提示未来对该文件做 diff 审阅时按对象而非行位置比对。

## 复核环境声明

- worktree HEAD 验证为 `52e4421`，工作区 clean（复核全程未产生任何工作区改动）
- 唯一写入：本报告文件 `/tmp/rugra-reports/W1-REVIEW.md` 及 `/tmp/mig_status_w1.out`、`/tmp/doctor_w1.out`（临时输出）
- 未运行 cargo；未触碰主仓未提交文件
