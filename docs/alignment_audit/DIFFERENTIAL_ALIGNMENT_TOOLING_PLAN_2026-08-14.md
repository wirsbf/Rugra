# Rugra 差分对齐工具链实施计划（2026-08-14）

> 本计划只定义诊断、证据和自动化基础设施，不提升任何模块的 L1/L2/L3 状态。
> 唯一源码 oracle 仍为 Ghidra 12.0.4 `Ghidra_12.0.4_build`，commit
> `e40ed13014025f82488b1f8f7bca566894ac376b`。所有正式行为证据仍须满足
> `AGENTS.md` 的同输入、完整观察、B2 四态和独立复核要求。

## 1. 目标

把当前分散的 runner、缓存、阶段快照、函数账本和 reducer 连成一个可重复闭环：

```text
锁定同输入与 provenance
  → 阶段/Action/Rule 事件快照
  → 修改后 IR 不变量检查
  → 第一条不同 mutation
  → 保持同一失败签名的合法语义缩减
  → 最小 fixture 与语料归档
  → registry / FUNCTION_EVIDENCE / CI
```

核心指标不是 runner 数、LOC 或 Rust 单测数，而是：

1. 从失败到“首个不同函数/事件/字段”的自动定位时间；
2. 能进入正式 gate 的已登记 oracle 覆盖率；
3. 最小复现能否稳定保持同一个 failure signature；
4. 受影响函数能否只选择必要 fixture，同时对未覆盖函数 fail-closed；
5. 任何缓存命中、重复运行和诊断产物是否具备完整 provenance。

## 2. 当前基线与已确认缺口

2026-08-14 的只读审计基线：

- 工作树可见 32 个 C++ oracle、29 个 Rust comparand、32 个 metadata 和 32 个 runner；
  Git 已跟踪的 runner/metadata 中只有 12 项进入正式 `fixture_registry.json`。
- 已登记 12 项的 evidence 状态为 3 `MATCH`、4 `PARTIAL_MATCH`、5 `MISMATCH`；
  `PARTIAL_MATCH` 不是 B2 顶层合法状态，必须逐 fixture 重判：已有观察差异为 `MISMATCH`，
  双侧观察相同但覆盖不全为 `UNTESTED`，缺有效双侧 oracle 为 `NO_ORACLE`；已覆盖部分另记
  observation 级 `MATCH`，不得一律改成某一个状态。
- 12 个 registry 项只有 3 项声明了稳定 `rust_function_ids`；路径命中目前可能把整文件
  误当作已有行为覆盖。
- `FUNCTION_LEDGER.json` 当前生成 9494 个 Ghidra behavior definitions 和 7164 个 Rust
  production functions，但账本没有消费 fixture evidence，不能据此声明完成度。
- `stage_diff.py` 能定位首个不同阶段，但通用路径只报告 hash/order/state；GetStr 的 JSON
  path diff 是 runner 内的专用实现。
- `reduce_fixture.py` 已具备 deterministic ddmin、重试、memo 和 1-minimal 骨架，但只会删除
  JSON list/hex 单元；它不维护 CFG/def-use/PHI/IOP 前置条件，也没有锁定失败签名。
- `FunctionSemanticSnapshot` 只覆盖粗粒度 P-code/CFG/SSA 和 Varnode storage，尚未完整观察
  flags、type、symbol、bank lifecycle、slot occurrence、alias graph 和 mutation 顺序。
- 现有 runner 大量重复 shell/内嵌 Python；gate 通常只能取得 exit code、stdout/stderr hash
  和 tail，cache hit 也不会恢复 runner 生成的完整诊断 artifact。
- GetStr runner 当前会在执行前 fail-closed：metadata 的 Rust comparand pin 是 `bfcadc80…`，
  当前文件实际为 `8e74e438…`。这证明历史证据验证与当前源码诊断必须拆开，不能把该命令描述为
  最新可运行结果。

这些缺口已经造成实际诊断成本：

| 已遇问题 | 错误产生点 | 迟到的可见症状 | 目标工具 |
|---|---|---|---|
| stale opcode dispatch | Rule 改 opcode 后仍沿旧规则表执行 | `RuleSubvarSubpiece` 下标 panic | Action/Rule trace |
| VarnodeBank key drift | 静态与定向诊断指向 `split_uses` 原地改 space/def/flags；仍待 journal 在同一 fixture 锁定首次 mutation | 后续 SetCasts/makeFree 断言 | IR invariant + mutation journal |
| DeadCode/Cover 自锁 | 持同一 Varnode 锁后递归重取写/读锁 | 函数超时 | hang triage + lock event |
| datatype merge O(N²) | 同类型 High 反复聚合 Cover | `my_get_line` 10 秒超时 | Action metrics + scale probe |
| fixture 未登记 | runner 已存在但 registry 不可见 | wave/nightly 静默漏跑 | registry doctor |

## 3. 统一状态和证据协议

### 3.1 Fixture 顶层状态

顶层只能使用 B2 四态：

```text
MATCH | MISMATCH | NO_ORACLE | UNTESTED
```

局部覆盖不再使用顶层 `PARTIAL_MATCH`。迁移时必须按证据选择整体状态。例如已有 raw 差异时：

```json
{
  "status": "MISMATCH",
  "observations": [
    {"id": "covered_projection", "status": "MATCH"},
    {"id": "nullable_slots", "status": "MISMATCH", "todo_id": "OPBANK-0001"},
    {"id": "error_path", "status": "UNTESTED", "todo_id": "..."}
  ]
}
```

如果已观察部分零差异但仍有未覆盖分支，顶层应为 `UNTESTED`；如果只有 Ghidra 单侧输出或
同输入条件不成立，顶层应为 `NO_ORACLE`。不得为统一 schema 而把这两类强制写成 `MISMATCH`。

已知 residual 只能附 `TODO ID` 并继续出现在结果中；不得从 equality 中过滤或规范化掉。

### 3.2 `fixture-v1`

`fixture-v1` 至少包含：

- fixture ID、schema version、锁定 oracle commit/tag；
- architecture、compiler spec、analysis options、输入指纹；
- Ghidra/Rust 稳定函数 ID；
- 选择路径与真正被证明的函数分别记录；
- case/observation 的四态、完整观察域和 residual TODO；
- 两侧必须实际导出的 effective configuration 观察域，而不是只信 metadata 声明；
- runner、comparand、工具链、环境和 artifact 声明；
- timeout、重复次数和确定性要求。

路径只能决定“改动后运行哪些 fixture”，不得证明函数覆盖。

### 3.3 `oracle-result-v1`

统一 runner 输出：

```json
{
  "schema": "oracle-result-v1",
  "fixture_id": "...",
  "execution_status": "OK",
  "comparison_status": "MISMATCH",
  "expected_comparison_status": "MISMATCH",
  "status_drift": false,
  "effective_configuration": {"status": "MATCH", "artifact": "..."},
  "cases": [],
  "first_difference": {
    "stage": "03_action_ir",
    "event": 137,
    "path": "/ops/31/inputs/0/space",
    "kind": "value_mismatch",
    "left": 5,
    "right": 7
  },
  "site_signature": "...",
  "predicate_signature": "...",
  "observation_signature": "...",
  "observation_hashes": {},
  "residual_todo_ids": [],
  "artifacts": {}
}
```

三级签名各司其职：

- `site_signature` 是版本化的粗聚类键，包含 profile/schema version、稳定目标函数 ID、stage、
  Action/Rule/操作类别、字段 schema 和 outcome class；
- `predicate_signature` 是 reducer 的 `SAME_FAILURE` 合同，在 site 键上再加入稳定的语义
  object/operand/edge/PHI role、差异方向/左右语义类别、invariant ID 和稳定栈。hang 还包含
  hang class 与最后稳定 progress/action signature；
- `observation_signature` 对完整观察结果取 hash，用于检测重复运行是否确定。

原始事件序号、具体 RFC 6901 JSON Pointer、内存地址、allocation ID 等易变诊断位置不进入
前两种签名；但 slot/edge/alias 等语义角色不得删除。合法缩减可移动事件/数组位置，却必须保持
`predicate_signature`；不同 slot、opcode、alias role 或左右方向必须产生不同 predicate。

`execution_status`、B2 `comparison_status` 与可选的 `expected_comparison_status` 是不同维度：
runner/harness 的 `ERROR/TIMEOUT` 不能冒充
`MISMATCH`，两侧恰好产生相同错误也不能判 `MATCH`。正式比较前，两侧须输出并比较实际生效的
地址空间/endian/wordsize、SLA/pspec/cspec、默认 prototype、Action tree/Rule 集、analysis/flow
options 及所需 symbol/prototype/callspec 摘要；不相等时顶层为 `NO_ORACLE`，停止解释下游 IR 差异。
gate 模式下 execution=`OK` 且 observed comparison 等于 expected 时返回 0（即使 expected 是
`MISMATCH`）；execution 正常但状态漂移返回 1；provenance/schema/harness/timeout 失败返回 2。
`--diagnose-current` 可省略 expected，此时 `status_drift=null`，只要 execution=`OK` 即返回 0。

### 3.4 `action-trace-v1`

诊断事件采用 JSONL，至少记录：

- Action tree path、Action/Rule 名和稳定函数 ID；
- attempt/apply/change 计数和 reset 边界；
- PcodeOp SeqNum、Varnode/Block 稳定身份及 alias class；
- before/after 完整局部状态 hash；
- 创建、删除、重排、slot/edge/flags/type/symbol mutation；
- 返回值、异常、断点/恢复状态和时间/CPU/progress hash。

Ghidra debug trace 只作为定位工具；除非同一正式 fixture 的完整观察结果通过 B2 门禁，否则
不能把 trace 相似冒充函数 `MATCH`。

## 4. 依赖 DAG 与实施 wave

```text
LEDGER-0001（DONE）→ FUNCTION-ID-0001 → ORACLE-REGISTRY-0001
ORACLE-REGISTRY-0001 → ORACLE-METADATA-MIGRATE-0001
ORACLE-METADATA-MIGRATE-0001 → ORACLE-REGISTRY-ENFORCE-0001
ORACLE-REGISTRY-ENFORCE-0001 → FUNCTION-EVIDENCE-0001
ORACLE-REGISTRY-0001 → ORACLE-RESULT-0001

ORACLE-CACHE-HARDEN-0002 ──→ ORACLE-RESULT-0001
DIFF-REDUCE-HARDEN-0002 ───→ PCODE-CFG-REDUCE-0001

ORACLE-RESULT-0001 + ORACLE-REGISTRY-ENFORCE-0001
  → ORACLE-RUNNER-MIGRATE-0001

ORACLE-RESULT-0001
  └─→ IR-INVARIANT-0001 ──→ ACTION-TRACE-0001 ──→ HANG-TRIAGE-0001

PIPE-TREE-0001（DONE）───────────────────────→ ACTION-TRACE-0001
RUNTIME-TIMEOUT-0001（DONE）────────────────→ HANG-TRIAGE-0001

FUNCTION-EVIDENCE-0001 + ORACLE-RESULT-0001
  → PCODE-CASE-DSL-0001
      → PCODE-CFG-FUZZ-0001（另依赖 IR-INVARIANT-0001）
          → PCODE-CFG-REDUCE-0001
              → ORACLE-CORPUS-PROMOTE-0001

ORACLE-0002（12.0.4 全程序 golden）与上述地基并行推进，
但不得用 11.3.2 diagnostic golden 填补其证据。
```

### Wave T0：事实源收口

#### `ORACLE-CACHE-HARDEN-0002`

先修复既有 cache 的执行闭包：provenance 中记录的显式环境必须也是子进程唯一可见环境；
路径型环境变量同时指纹内容；命令结束后重新读取全部输入，运行期间漂移时拒绝存储。扩展 artifact
bundle，使 cache hit 能原子恢复 stage manifest、comparison 和最小输入，而不只是 stdout/stderr。

验收核心：未声明环境对子进程不可见；已声明值或路径内容变化必换 key；运行期间改动输入必拒绝
store；miss 后删除结果目录再 hit，全部诊断 artifact 逐字恢复。

#### `DIFF-REDUCE-HARDEN-0002`

修复通用 reducer 的证据合同：

- seed 先运行原始 bytes，再检查渲染后的规范化输入，分类漂移时报 `NORMALIZATION_DRIFT`；
- 最终验证绕过 memo，按 retries fresh 启动 predicate；
- predicate 支持带稳定 `predicate_signature` 的 `INTERESTING`、`BORING`、`INVALID` 和
  `HARNESS_ERROR`；
- invalid candidate 只跳过，predicate signature 从 A 漂到 B 必须拒绝；
- trace 可增量保存并支持中断后 resume。

验收核心：最终 process count 确实增加 retries；最后 trace 为 fresh verification；原始/渲染输入
hash 和分类都被记录；注入 bug A、bug B、invalid case 后只允许保留 A。

#### `FUNCTION-ID-0001`

在 registry 迁移前先稳定两侧函数身份：

- Ghidra ID 基于 locked path、完整 qualified signature 与定义/声明类别，不依赖行号；
- Rust ID 基于 module path、owner kind、完整 normalized signature 与稳定 AST identity：inherent impl
  使用 `Type`，trait impl 必须使用 `Type as Trait`，free function 使用 module owner；宏展开或匿名
  冲突才允许使用记录在迁移表中的显式 stable disambiguator，禁止用出现 ordinal；
- 生成旧 ID → 新 ID 迁移表，歧义必须人工消解，禁止静默多配一；
- 新增同名函数、移动无关函数或插入测试函数不得改变既有生产函数 ID。

验收核心：对包含多个 `apply_op`/`new` 的真实文件做插入、删除、移动和 dirty-worktree 矩阵，
并加入同一 `Type` 对多个 trait 实现同名同签名方法的碰撞 case；未改函数 ID 全部稳定且
`Type as TraitA`/`Type as TraitB` 不碰撞。旧 registry ID 可无歧义迁移，无法迁移的项 fail-closed。

#### `ORACLE-REGISTRY-0001`

建立 `fixture-v1` schema、registry doctor 和反向索引工具：

- 自动发现所有已跟踪 metadata/runner/comparand；
- orphan、重复 ID、metadata/registry 状态冲突、陈旧函数 ID、缺 provenance 全部 fail-closed；
- 为迁移工具输出逐 fixture 的建议 B2 状态、缺失字段和精确文件清单，但本任务不批量改写
  所有 metadata，也不提前打开 strict CI。

验收核心：工具 self-test 覆盖 orphan、重复 ID、非法状态、单侧假 MATCH、状态漂移和 stale ID；
对当前仓库输出确定的 migration plan，同一输入两次报告 hash 相同。

#### `ORACLE-METADATA-MIGRATE-0001`

这是协调父任务，不直接把 `tests/oracle/*.metadata.json` 通配符交给一个 writer。root 根据
registry doctor 的冻结报告，为每个无重叠 fixture 或小批次建立子 TODO，逐项写出明确文件名、
原始状态、目标 B2 状态和观察 residual。迁移时：

- 有真实双侧差异的 fixture → `MISMATCH`；
- 双侧覆盖部分零差异但分支未覆盖 → `UNTESTED`；
- 单侧或同输入条件不成立 → `NO_ORACLE`；
- 只有完整观察域零差异才可 `MATCH`。

每个子批次必须保留迁移前后 raw comparand hash，禁止借 schema 迁移改变观察结果或缩窄 residual。

#### `ORACLE-REGISTRY-ENFORCE-0001`

所有 metadata 子批次迁移完成后，再将 strict lint 接入 `check_gate_health.py`、commit gate 和 CI。
此时验收才要求所有已跟踪 fixture 均登记，`orphan_metadata=0`、`orphan_runner=0`、
`schema_errors=0`、`status_conflicts=0`、`stale_function_ids=0`，并拒绝任何 `PENDING_*` pin。

#### `FUNCTION-EVIDENCE-0001`

将 ledger、registry 和 metadata 机械合并成 `FUNCTION_EVIDENCE.json`：

- `select_on_paths` 与 `proves_*_functions` 分离；
- 未绑定函数的路径 fixture 只能触发运行，不能消除 coverage gap；
- evidence query 能展示 callers、fixtures、observations、residuals 和最后验证 commit；
- 只消费 `FUNCTION-ID-0001` 生成的稳定 ID，发现 legacy ordinal ID 立即 fail-closed；
- staged/base 模式必须扫描对应 Git blob，而非当前工作树；删除 hunk 使用 pre-image，新增 hunk使用
  post-image；dirty worktree 不得污染选择结果；
- ledger 输入或生成文件陈旧时 fail-closed；同名/同短名 selector 有多个结果时必须报歧义；
- 重新核对 `~2055`、旧 `~5200+` 和当前 9494 denominator，冲突关闭前全局完成度仍未证明。

验收核心：`src/action.rs`/`src/merge.rs` 等路径级 fixture 不再吞掉未映射函数，任何未覆盖
生产函数在 strict selector 中返回 coverage gap。

### Wave T1：结构化结果和首差异

#### `ORACLE-RESULT-0001`

建立通用 harness、结构化 diff 和 artifact cache：

- runner 输出 `oracle-result-v1`；
- execution 与 comparison 状态分离；相同 `ERROR` artifact 仍是 harness failure，不是行为相等；
- 增加 `00_effective_configuration` preflight，机器证明两侧真实输入环境相同；
- JSON diff 输出 RFC 6901 Pointer、左右值、邻域和全部差异分类；
- 数组顺序、alias、CFG、slot occurrence 保持语义，不作为噪音排序；
- Ghidra snapshot、当前 Rust snapshot 和 comparison 分层缓存；
- cache key 与实际受控执行环境完全相同，未声明环境对子进程不可见；
- cache hit 原子恢复完整 artifact bundle；失败发布不得污染上一份成功证据；
- 历史证据重放与当前源码诊断分开，修复一个差异后仍能显示下一处差异。
- `--verify-recorded`、`--diagnose-current` 与人工审核后的 `--accept` 三种模式边界分明；
- stage artifact 记录 `run_id/parent_stage/construction_recipe`，优先使用同一对象的连续状态演化；
  必须 fork/rebuild 时不得伪装成同一条状态链。

验收核心：通用工具可直接报告 GetStr 的首层、首个 JSON Pointer 和后续分类差异；preflight
故意改一项时稳定返回 `NO_ORACLE`；六层全等、单层先等、尾部增删及 error artifact 均不崩溃、
不产生假 `MATCH`。

#### `ORACLE-RUNNER-MIGRATE-0001`

在协议和参考 runner 冻结后逐批迁移全部已登记 runner。迁移只替换重复的 provenance、build、
compare 和结果发布外壳，不改变 fixture 的生产 API 输入、观察域或历史 evidence。每批迁移都要
独立回放迁移前后的原始 comparand 输出，发现观察域缩窄或状态漂移立即停止。

本项同样是协调父任务：激活前由 root 按 runner 列表建立显式子 TODO，每个子项只租一组明确
的 `run_<fixture>_oracle.sh`、对应 metadata/comparand 和 registry 记录；父任务不把通配路径作为
可并行 write-set。

父任务除依赖 `ORACLE-RESULT-0001` 外，还必须等待 `ORACLE-REGISTRY-ENFORCE-0001` 完成，确保
全部 tracked runner 已登记且旧非法状态已完成 B2 四态迁移；不能只迁当前 registry 可见的 12 项。

验收核心：registry 中每个 runner 都产生 schema-valid `oracle-result-v1`，gate 报告可恢复其全部
artifact；迁移前后 Ghidra/Rust 原始输出 hash 和整体 B2 状态保持一致。

#### `IR-INVARIANT-0001`

在诊断模式下建立完整 IR 一致性检查和 mutation journal：

- `op.input[slot] ↔ varnode.descend` 双向、按 occurrence 精确一致；
- `op.output ↔ varnode.def` 双向一致；
- Loc/Def bank key 指纹与插入时 key 一致，禁止树内原地修改 key 字段；
- alive/dead/opcode list、parent、block op 顺序和 bank membership 一致；
- CFG in/out edge、reverse slot、MULTIEQUAL input 与 predecessor 顺序互反；
- Cover dirty/对象身份、High/Varnode 回指和必要锁边界可验证；
- 支持 `mutation`、`rule`、`action` 三个开销等级，release 默认关闭。

诊断 checker 不改变生产算法结果；任何为通过 checker 而绕过 Ghidra 行为的修复均不允许。

### Wave T2：细粒度 trace 与超时分类

#### `ACTION-TRACE-0001`

利用 locked Ghidra 的 `Action::perform`、`ActionPool::processOp` 和
`Funcdata::debugModCheck/debugModPrint` 观察点，建立双方最长共同事件前缀比较。首个报告必须落到
Action/Rule、SeqNum、对象和字段，而不是只报 `03_action_ir` hash 不同。

先以 opcode redispatch、DeadCode self-loop 和 merge-order fixture 做验收；Rust instrumentation
触及主管线时必须独立 cross-review，且不得改变无 trace 模式的行为/输出 hash。

#### `HANG-TRIAGE-0001`

在 `ACTION-TRACE-0001` 已提供稳定 progress event 后，于隔离 worker 超时终止前保存：

- 全线程稳定栈、`/proc/<pid>/task/*/{wchan,stat,stack}` 和进程树；
- 最后 Action/Rule/event/progress hash；
- CPU 时间与 IR cardinality 增量；
- 进程组终止和残留验证。

分类至少包括 `PANIC`、`SELF_LOCK`、`NO_PROGRESS_LOOP`、`CPU_SCALE`、`IO_WAIT`、
`PROTOCOL_FAILURE`。分类是诊断，不得以 wall-clock cap 替代 Ghidra 算法。

### Wave T3：约束感知 fuzz、缩减与语料提升

#### `PCODE-CASE-DSL-0001`

先定义严格的 `pcode_cfg_case_v1` 行协议。C++ 与 Rust 必须从同一 case 调用各自生产 API，
不得直接写内部字段。初始 profile 为 `opbank_mutation_v1`，维护：

- ID/引用存在性和 alias；
- def-use/output 双向关系；
- parent/block op 顺序和 CFG reverse slot；
- PHI incoming edge 顺序；
- INDIRECT Iop、LOAD/STORE space 输入及目标函数前置条件。

#### `PCODE-CFG-FUZZ-0001`

按确定 seed 生成合法操作序列，双方逐步输出完整对象图并通过 `oracle-result-v1` 比较。推进顺序：

```text
opbank_mutation_v1 → rule_local_v1 → small_ssa_cfg_v1 → action_tree_v1
```

在上游已知 residual 仍多时不直接 fuzz 完整二进制，否则只会形成低质量噪音桶。

#### `PCODE-CFG-REDUCE-0001`

使用六态 predicate：

```text
SAME_FAILURE | MATCH | DIFFERENT_FAILURE | INVALID_CASE |
HARNESS_ERROR | NONDETERMINISTIC
```

缩减必须维护引用闭包并依次尝试删除操作片段、无关 block/edge/op/Varnode、修复 PHI/def-use、
缩减槽位/重复 use、缩小 size/address/offset/flags。事件序号和具体 JSON Pointer 允许随合法缩减
变化，但稳定语义 `predicate_signature` 不得变化。最终 fresh rerun 三次保持同一
`predicate_signature`，并验证所有 transform 均不能再缩，才可称 1-minimal。

#### `ORACLE-CORPUS-PROMOTE-0001`

按 `(site_signature,predicate_signature)` 去重，每一对只保留复杂度元组
`(steps, blocks, edges, ops, varnodes, bytes)` 最小者，避免粗 site 桶吞掉不同 slot/alias/hang bug。
正式 promotion 必须补齐 oracle commit、
arch、cspec、options、输入 hash、稳定函数 ID、TODO ID、两侧 observation hash、reducer trace 和
registry entry；任何字段缺失均拒绝进入正式 corpus。

## 5. 原子 write-set 原则

每个 TODO 的精确 write-set 以 `docs/TODO_BOARD.md` 为准。实施时另遵循：

1. schema/registry/evidence writer 与 fixture 业务 writer 串行修改 `fixture_registry.json`；
2. IR checker 对 `src/varnode.rs`、`src/op.rs`、`src/funcdata.rs`、`src/block.rs` 的插桩必须按
   当前文件租约拆分提交，不允许一个基础设施 commit 越过活跃算法 writer；
3. Action trace 触及 `src/action.rs` 或主管线时必须重新读取 locked `.cc/.hh` 全函数并独立复核；
4. fuzz/reducer 只通过生产 API 构造状态，不增加 production test hook 绕过前置条件；
5. 每个阶段立即原子 commit，显式 `git add <owned files>`，不得 `git add -A`、restore、checkout、
   stash 或全 crate `cargo fmt`。
6. 所有任务都需要更新的 `docs/TODO_BOARD.md`、本计划、验证指南和 `tools/README.md` 由 root
   串行维护；实现 agent 只租其专属工具/源码/fixture 文件，不能把这些共享文档视为并行 write-set。

## 6. 分阶段验收命令

计划中的目标命令如下；工具实现前这些命令是验收合同，不是现有通过证据：

```bash
# T0：以下 self-test/check 均要求 rc=0
python3 tools/oracle_cache.py --self-test
python3 tools/reduce_fixture.py --self-test
python3 tools/generate_function_ledger.py --self-test
python3 tools/generate_function_ledger.py --check
python3 tools/oracle_registry.py self-test
python3 tools/oracle_registry.py plan --check-determinism --output target/oracle-tooling-accept/migration-plan.json
python3 tools/oracle_registry.py migration-status --strict
python3 tools/oracle_registry.py lint --strict
python3 tools/select_fixtures.py --self-test --matrix staged,base,delete,dirty,stale,ambiguous
python3 tools/evidence_query.py check --strict
python3 tools/evidence_query.py fixture action_opcode_redispatch_1204 --functions --callers --residuals
# 真实路径矩阵的预期 rc=2，且 JSON report 的 coverage_gap 必须非空
python3 tools/select_fixtures.py --path src/action.rs --strict --pretty --report target/oracle-tooling-accept/action-selection.json

# T1：self-test/cargo/runner 均要求 rc=0
python3 tools/oracle_harness.py self-test
python3 tools/oracle_harness.py run getstr_pipeline_1204 --diagnose-current --report target/oracle-tooling-accept/getstr-current.json
python3 tools/oracle_harness.py verify-report target/oracle-tooling-accept/getstr-current.json --execution OK --comparison NO_ORACLE --status-drift null
python3 tools/observation_diff.py --self-test
python3 tools/oracle_registry.py runner-status --schema oracle-result-v1 --strict
cargo test --lib align::ir_invariant::tests::
tools/run_ir_mutation_journal_oracle.sh

# T2：均要求 rc=0；fixture 的已知 MISMATCH 是 comparison 状态，不是进程失败
python3 tools/run_action_trace_oracle.py --fixture action_opcode_redispatch_1204 --expect-comparison MISMATCH --report target/oracle-tooling-accept/action-trace.json
python3 tools/trace_diff.py --self-test
python3 tools/hang_triage.py --self-test

# T3：均要求 rc=0
python3 tools/pcode_cfg_case.py --self-test
python3 tools/fuzz_pcode_cfg.py --profile opbank_mutation_v1 --seed 1 --cases 100 --check-determinism
python3 tools/reduce_pcode_cfg.py --self-test
python3 tools/triage_oracle_failures.py --check
python3 tools/promote_oracle_case.py --self-test
tools/run_pcode_cfg_corpus_oracle.sh
```

最终集成门禁：

```bash
python3 tools/check_gate_health.py
python3 tools/rugra_gate.py commit --staged
python3 tools/rugra_gate.py wave --report target/oracle-tooling-accept/wave.json
```

## 7. 完成判定

本计划完成只表示“差分诊断闭环可用”，不表示 Rugra 已与 Ghidra 完成对齐。全部满足以下条件
才可关闭工具链计划：

1. 所有已跟踪 fixture 均受 schema/registry/gate 管理，无 orphan 或状态冲突；
2. 每个证明行为的 fixture 均绑定稳定 Ghidra/Rust 函数 ID 和 observation；
3. 每个正式比较先证明 effective configuration 同输入，execution failure 不会变成假 `MATCH`；
4. 任一 stage mismatch 能自动展开到首个 JSON Pointer；Action/Rule 问题能定位首个不同事件；
5. IR checker 能在首次非法 mutation 后立即报错，并证明关闭诊断时生产输出不变；
6. grammar-aware reducer 不漂移 failure signature，能 fresh rerun 证明 1-minimal；
7. corpus promotion 自动补齐 provenance、TODO、evidence 和 registry；
8. 同 seed、同输入、同选项的重复运行 artifact hash 稳定；
9. `ORACLE-0002` 完成前，11.3.2 curl golden 始终只标 diagnostic，绝不升为 12.0.4 证据；
10. 函数 denominator 冲突关闭前，全局完成度仍明确为未证明。
