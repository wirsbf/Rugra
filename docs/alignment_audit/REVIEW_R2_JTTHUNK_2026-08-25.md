# R2 独立复核报告 — JUMPTABLE-THUNK-CLASSIFY-0001 返修（机制 C）

- 复核对象: worktree `/tmp/rugra-wt-jt-thunk-classify`，分支 `agent/jt-thunk-classify`，HEAD `cb9e0542a543590c96b772e49ea432d02a2d31b1`（base `58aa109` 之后 6 提交）
- 复核 Agent: R2（独立只读；不采信实现者声明，逐条自证）
- 复核时间: 2026-08-25 00:05–00:40 (本地)
- 结论: **APPROVE**（附 3 项非阻断建议，其中 S1 建议在集成同 commit 或紧随的 docs-only 提交中修复）

---

## 0. 复核方法与信任边界

本人未采信任何实现者/前任复核的文字结论。全部结论来自本轮亲自执行：
`git log/diff/rev-parse`、runner 2076 行全文通读、metadata 全字段解析、证据 bundle 逐文件重哈希、
input_manifest 指纹重算、六 blob OID 与 worktree HEAD 外部锚定、C++/Rust fixture 源码检查、
以及在锁定的同一 HEAD 上**完整重跑 runner 一次**（见 §6）。

信任边界声明：git 对象库与 worktree 由本机提供；runner 对 root-owned 工具链的哈希校验只能证明
"哈希时点内容"，无法抵抗同 UID 恶意进程的 inode 级替换——runner 自身（`candidate_evidence.capture_policy`
相关段落）已如实声明该边界，本人认可该声明与实际机制一致。

## 1. 提交范围审计（清单 1）

`git log --oneline 58aa109..HEAD` = 6 提交（b8b41af → 9ad9479 → aa87931 → 84d1242 → 8fff4b2 → cb9e054）。
累计 diff --stat（58aa109..HEAD）：

```
 docs/api/jumptable.md                             |  128 +-
 tests/oracle/jt_thunk_classify_1204.metadata.json |  773 +++++++-
 tests/oracle/jt_thunk_classify_1204.rs            |   16 +-
 tools/run_jt_thunk_classify_oracle.sh             | 2191 ++++++++++++++++++++-
 4 files changed, 2716 insertions(+), 392 deletions(-)
```

- `src/**` 零改动 ✓（返修轮全部是 runner/metadata/文档/fixture 输入补齐，与"双侧零差异故 src 零改动"的声明一致）
- 注意：改动不止清单预期的 2 个文件——`docs/api/jumptable.md`（诚实性重写：登记 EMULFN、撤回历史
  L3 误判、排序残留改述）与 `tests/oracle/jt_thunk_classify_1204.rs`（+13 行：production XML decoder
  建立 `<prototype name="fixture" extrapop="0">`、`max_basetype_size=16`、stack pointer register:0/8
  钉到 C++ synthetic Architecture 同值）也在 b8b41af 中修改。本人核验这两处改动均为**同输入补齐**，
  不触碰生产代码，属于正当改动（铁律 2.1 "同输入包括 Architecture 状态"的补齐方向）。
- worktree 干净（`git status --porcelain` 空），HEAD/分支与任务描述一致 ✓
- 6 提交全部只动 owned write-set（与主仓 TODO_BOARD:17 声明的 write-set 一致），无 `git add -A` 越界痕迹

## 2. Runner 通读（清单 2）— 前任 5 条 REJECT 逐条核验

### R1-#1 完整 runner 从未执行 → **闭合**
- 旧 `find -path` selector 已删除。现 selector（runner:1710-1748）：只在 `$cargo_target/debug/build`
  **深度 2** 枚举 `root-output`，按直接父目录 basename `rugra-*` 过滤，要求**恰好 1 个**；rlib
  （runner:1760-1783）限定 `debug/deps` 下唯一 `librugra-<hash>.rlib`，并用 `readlink -f` 验证
  全部落在 run-local target 内。dependency 的 root-output（父目录是 `libz-sys-<hash>` 等）不匹配
  `rugra-*`，不可能再误选。
- 证据 bundle 实际存在且完整（§4），本人在同一 HEAD 重跑一次 exit 0（§6）——24-case 确已执行。

### R1-#2 metadata 误标 MATCH → **闭合**（状态字段层面）
- `coverage` 13 组：10 组 `MATCH`/`BILATERAL_24_CASE_BYTE_IDENTICAL`，3 组
  `MISMATCH`（`production_typed_stage_consumption`→`JUMPTABLE-PIPELINE-0001`、
  `sort_toolchain_portability`→`JUMPTABLE-SORT-TOOLCHAIN-0001`、
  `emulate_function_lowlevel_channel`→`JUMPTABLE-EMULFN-0001`），residual_todo_ids 绑定逐一核对无误。
- `overall_status=MISMATCH` ✓，`known_diffs=[]` ✓，`projection_status=MATCH`（附 "pending independent
  review" 措辞，run-record.txt 同样写明）。
- runner:1180-1514 的 metadata 自校验 Python 将上述全部结构（含 provenance 双态：pre-execution 只允许
  UNTESTED / post-execution 必须指定本 runner sha256 + exit 0）钉死，metadata 无法在与 runner 不一致的
  状态下通过门禁。
- 残留问题：SORT residual detail 有一句执行前残文（见 S2），不影响状态字段。

### R1-#3 live metadata/overlay TOCTOU → **闭合**
- 一次捕获 `HEAD` commit/tree（runner:386-396）；六个 owned path 要求 `status --porcelain` clean、
  tree OID == stage-0 index OID、mode 一致、live bytes 经 `O_NOFOLLOW` FD 读出 == captured blob sha256
  （runner:398-443）。
- **编译/执行阶段不再读 live 文件**：metadata、双侧 fixture、jumptable overlay、API 文档、runner
  全部从 captured `commit:path` blob 物化进私有 snapshot（runner:1115-1129），物化后逐文件 sha256 复核；
  runner 自身先经 FD 重执行（runner:14-30 打开 `/proc/$$/fd/3`，外层与物化副本 `cmp` 后才
  setsid+handshake 进入 captured stage，runner:512-590）。
- 运行后全量回读（runner:1903-2065）：snapshot 逐文件 sha256/文件 mode/目录 mode 三重 cmp
  before/after；oracle 源逐文件；toolchain_state（50+ 可执行/库/头 sha256 + root-owned 检查 + 55 库
  ldd 闭包 + 6 棵语义树全量 rgbl 哈希）整函数重跑 cmp；base/oracle archive 重哈希；cargo artifacts、
  direct-rustc 两个输入树（deps + native out 全树 mode+bytes）三态 cmp；双侧 fixture 可执行文件
  sha256；runner FD vs 物化副本；git HEAD/tree/oracle identity/两 repo replace-refs 重验；六 blob
  readback vs live 状态终验。Ghidra 冷构建输出被限制为白名单（79 个 `com_opt/*.o` + 2 depend +
  libdecomp.a + 两个 0700 目录），多一个少一个都失败（runner:1941-1997）。
- umask pin：`git -c tar.umask=0022 archive`（runner:932、1080）保证 archive member mode == Git tree
  mode，注释明确说明动机；解包后 `verify_git_materialization` 仍逐 blob 对 git tree 回验（runner:823-881）。
- CACHEDIR pin：Cargo 1.97 无条件写 `registry/CACHEDIR.TAG`，runner:1656-1687 只放行该唯一 marker
  （sha256 pin `6d9d1d21…`），其余任何 registry/git/config/credential 状态 = 失败。Cargo 全程
  `--offline --locked` + run-local `CARGO_HOME` + 空配置 + vendor 目录源（Cargo.lock checksum 逐包
  认证，O_NOFOLLOW 单次读取，安全解包拒绝 traversal/link/device 成员）。

### R1-#4 Ghidra archive/toolchain/libstdc++ 未冻结 → **闭合**
- oracle: commit/tag/cpp-tree/Makefile-blob 四重身份 + worktree clean 校验（runner:883-901）；
  cpp archive sha256 `503b60e0…` pin + 解包逐 blob 回验 + 冷构建检查（无 .o/.a/.so 残留）+
  非 regular 节点拒绝。
- toolchain：g++/gcc/ar/make/flock/setsid/env/git/python3.14/cargo/rustc/cc1/cc1plus/collect2/ld/as/
  ranlib/librustc_driver/libLLVM/ldd/ld.so.cache/libstdc++.so.6.0.36/libz/CRT/libc/libm/4 个 STL
  header 全部 sha256 + root-owned + 非 group/world-writable + 版本串 + `-dumpspecs` 哈希 +
  `-print-file-name` 解析绑定；55 个动态库闭包 manifest；`rustlib target-libdir`/`gcc 16 root`/
  `/usr/include/c++/16`/`/usr/include`/`/usr/local/include`/`/usr/lib/python3.14` 六棵语义树
  （33k+ 文件、~780MB）全量确定性树哈希。
- libdecomp.a：锁定 Makefile 独立展开 `LIBDECOMP_OPT_OBJS`（79 项，无重复，`com_opt/*.o` 形态），
  `ar t` member 顺序必须逐项等于展开序，且每个 member 字节 == 对应 object（构建后与双侧执行后各验一次）。
- 双侧 fixture 执行时 `LD_PRELOAD=$libstdcpp_path:$zlib_path` 钉运行时库。

### R1-#5 EmulateFunction LowlevelError 通道缺失未登记 → **闭合**
- `JUMPTABLE-EMULFN-0001` 已登记（metadata residuals[2]，MISMATCH，4 个 branch：
  `load_callback_data_unavailable` / `multiequal_lastop_selection` / `control_flow_lowlevel_errors` /
  `emulation_failure_silently_zeroed`），detail 逐条对应 locked `EmulateFunction::executeLoad`
  （成功解析 LOAD 地址后、payload 读取前 append record）、`executeCurrentOp` DataUnavailError→
  带当前 op 地址的 LowlevelError、ordinary MULTIEQUAL 的 lastOp 前驱选择、start-MULTIEQUAL/
  non-MULTIEQUAL-not-in-PathMeld/BRANCH/BRANCHIND 各自精确文本，及"最终 result varnode 读取位于
  catch 之外"的时序。
- `docs/api/jumptable.md` 同步登记（含 2026-06-27 历史段落撤回"达到 L3"结论、`execute_op` 的 LOAD
  record 分支不可达分析）。runner:1500-1501 强制 `evidence_kind=LOCKED_SOURCE_AUDIT_OUTSIDE_24_CASE_FIXTURE`。

## 3. Metadata 诚实性（清单 4）

- `MATCH` 仅属于 10 个双侧执行组（`evidence_kind=BILATERAL_24_CASE_BYTE_IDENTICAL`，`residual_todo_ids=[]`）✓
- 3 个源审计/可移植性组保持 `MISMATCH` 并绑定正确 TODO ID ✓
- `overall_status=MISMATCH` ✓；`residuals` 3 项全 MISMATCH ✓
- `expected_results`：双侧 stdout sha256 相同（`c4cc2b35…`），双侧 stderr 均空文件 sha256，raw.diff
  空文件 sha256，双侧 exit 0，diff exit 0 ✓
- `input_manifest.sha256` 本人用 runner 同构算法重算：`7f485e6a…` **一致** ✓（fingerprinted 子集 =
  architecture + compiler_spec + analysis_options + oracle_toolchain + cargo_dependency_vendor + cases）
- `comparand.runner_sha256` == `latest_validation.attempted_runner_sha256` == worktree runner 实测
  sha256 = `78292b2b5bdac710418753fa555e17b32ce36751dc4e7a89a629d32aad1dcac0` ✓
- `representation_residual` 明示不宣称 whole-compiler-spec 同输入（FSPEC-PARAMLIST-OUTPUT-DISPATCH-0001，
  24-case 不消费该 dispatch）——正确的保守声明 ✓
- `std_sort_contract` 明示仅复现 pinned libstdc++ 行为、跨 STL 无契约 ✓

## 4. 证据 bundle 核验（清单 3）

`/home/wirs/.cache/a3-jtthunk-tmp/jt-thunk-classify-evidence-cb9e0542a543590c96b772e49ea432d02a2d31b1/`

本人重算：
- `ghidra.stdout` sha256 = `c4cc2b35…d9e0`，`rugra.stdout` sha256 = `c4cc2b35…d9e0`（相等，== metadata）✓
- `ghidra.stderr`/`rugra.stderr`/`raw.diff` 均 0 字节（sha256 = 空文件 `e3b0c442…`）✓
- stdout 恰好 24 行 `case|id=…|path=…|kind=…`；kind 计数 **success=11 / thunk=10 / lowlevel=3** ✓
  （含 `0xffff`→success、`0x10000`→thunk、multi→success、partial=1 组、`recover>build>sanity>collapse`
  事件序、`16@0x00100000:WARNING: Sanity check requires truncation` 表长 warning、16/17 项同址
  size4/8 交替排列、tiny(8) 空间 wrap、space index 3/8 排序等全部可观察字段）
- `run-record.txt`：candidate_commit=cb9e0542…、tree=`090413ee…`、六 blob OID+sha256 与 worktree HEAD
  `git rev-parse HEAD:<path>` **逐一相等**（外部锚定成立）✓，metadata live sha256 `a904a0c0…` 与
  run-record 记录一致 ✓
- `focused-results.txt`：`31 passed; 0 failed` + doc_sync filtered `0 passed; 0 failed; 1 filtered out`，
  与 runner:1700-1707 的强制格式一致 ✓
- bundle 文件 mode 600、目录 700 ✓；staging root 早期还保留了 3 份失败运行日志
  （23:14/23:29/23:32，对应 status_note 所述"三次环境修复"历史）与 jtrun2-6.log 外层日志，
  `jtrun6.log` 显示完整成功序列（cargo-vendor 164 → libdecomp-manifest 79 → 31 tests → run-record →
  `EXIT=0`）✓

## 5. jumptable.rs 本体零改动的正当性（清单 6）

- 编译绑定链：snapshot src 树 = pinned base `8d3a556` 的 `git archive`（sha256 `8751c496…`）+
  **candidate HEAD 的 `src/jumptable.rs` blob 覆盖**（runner:1115-1129，`jumptable_overlay_sha256=4fe0f3c7…`
  == HEAD blob 内容哈希）→ `cargo test --lib` 构建 run-local `librugra-*.rlib` →
  `rustc --extern rugra=<该 rlib> -l static=rugra_sleigh` 链接 fixture（runner:1821-1831）。
- **本人验证** `git diff --stat 8d3a556..HEAD -- src/`：src 下**只有** `src/jumptable.rs` 一个文件变化
  （560+/86-）。因此 snapshot src（base + overlay）与 HEAD:src **完全等价**——fixture 对拍的确实是
  生产 `src/jumptable.rs`（含 typed `JumpTableRecoveryError`/`recovery_mode()` 实现），不是测试副本。
- base..HEAD 的非 src 改动只有本任务 5 个自有文件；Cargo.toml/Cargo.lock/build.rs 未变，编译框架与
  HEAD 无漂移，`OBSERVED_CURRENT_CANDIDATE_24_CASE_OUTPUT` 声明在 src 维度成立。
- C++ 侧：fixture include 锁定 `jumptable.hh` 等真实头（先 `<bits/stdc++.h>` 再 `#define private
  public`，注明 test-only 访问 hack 不影响 libstdc++），链接锁定 Makefile 构建的 79-member
  `libdecomp.a`——对拍的是 locked `ghidra::JumpTable::sanityCheck`/`recoverAddresses` 真实行为。
- Rust fixture 驱动（fixture.rs:486-506）真实调用 `recover_addresses_classified`/`sanity_check`，
  观察 typed 分类/RecoveryMode/精确 message/loadcounts 生命周期/commentdb warning，与 C++ 侧同构。

## 6. 可复现性重跑（清单 5）

本人在同一 worktree、同一 HEAD（cb9e054）、worktree 干净状态下重跑 runner 一次（先备份原 bundle 至
`/home/wirs/.cache/r2-jtreview-tmp/bundle-backup/`；期间从未触碰主仓未提交文件）：

- 重跑 **exit code = 0**；run-local staging 目录由 runner cleanup 自行删除；重跑后 worktree 仍干净、
  HEAD 仍为 cb9e054。
- 重跑 stdout 与 jtrun6.log 序列一致：cargo-vendor 164 / libdecomp-manifest 79 / `31 passed; 0 failed`
  / doc_sync filtered / run-record / `EXIT=0`。
- 成功后 evidence bundle 同名重写，与备份逐文件对比结果：
  - **观察输出完全复现**：`ghidra.stdout` 与 `rugra.stdout` 均为 `c4cc2b35…d9e0`（两次运行、双侧
    四份全等），`raw.diff` 仍 0 字节，`focused-results.txt` 一致，六 comparand blob sha256 完全不变，
    `libdecomp.a`（`3c225572…`）与 C++ fixture 可执行（`93f5b90a…`）两次构建**字节相同**。
  - 仅有的差异：(a) 各 hash 清单文件的**路径字段**含随机 run 目录后缀（`288tlk` → `ClQbLW`）；
    (b) Rust debug 构建产物字节哈希不同（rlib `0003b9f7…`→`c67ca60d…`、native `258282c7…`→
    `5ef87de9…`、rust 可执行 `d91dc301…`→`7089936…`），原因明确：debug rlib/静态库/可执行内嵌
    run-local 绝对路径（build.rs OUT_DIR、调试信息），run 目录名随机。注意 rlib 的 **crate disambiguator
    hash `951ff0296a4578f1` 两次相同**（元数据一致，仅字节级路径差异）。
- 判定：门禁 pin 的是**观察输出**（stdout/stderr/diff/exit/blob 锚），不 pin Rust 构建产物字节——
  该设计与 Cargo debug 构建的路径非确定性一致，本人认可。24-case 双侧 MATCH 在当前机器当前 HEAD 上
  **确定性可复现**。

## 7. 发现的问题

### 阻断级（MISMATCH）
无。5 条前任 REJECT 理由全部实质闭合；fixture 证据真实、可复现、外部锚定成立；metadata 状态字段诚实。

### 建议级（非阻断，S=建议）

**S1（建议集成前顺手修复，docs-only）`docs/api/jumptable.md` 三处执行前残留与 metadata 状态矛盾**
- `docs/api/jumptable.md:9`：头部摘要写 "扩展 24-case 的 current-Rust coverage 为 `UNTESTED`"
- `docs/api/jumptable.md:47`：正文写 "尚无一次运行把当前 Rust candidate 链入扩展后的 24-case
  fixture……因此上述所有 24-case behavior coverage 当前均为 `UNTESTED`，不得写作 `MATCH`"
- `docs/api/jumptable.md:56`：写 "current-Rust 尚未执行共同阻止 fixture 投影升级为 `MATCH`"
- 同一提交 cb9e054 的 metadata 已是执行后状态（10 组 MATCH + projection MATCH + current_runner_executed
  =true），且 docs 文件后半段（runner 物化/外部 anchor 段）描述的正是执行后机制——文件前后自相矛盾。
  矛盾方向保守（低估），不构成虚假 MATCH，但会误导后续 agent 得出"从未执行"的结论（恰好重现 R1 时代的
  错误印象）。修正方向：把 :9/:47/:56 改为"已于 cb9e054 执行、双侧字节一致、projection=MATCH pending
  independent review"，保留 R1 失败史作为历史叙述。

**S2（建议同批修复，docs-only）metadata SORT residual detail 执行前残句**
- `tests/oracle/jt_thunk_classify_1204.metadata.json:789`（`residuals[1].detail`）写 "the current
  Rust 24-case projection and heap fallback remain untested"，与本文件 `status_note` 的 "The 24-case
  projection is therefore MATCH as observed" 及 coverage 组 `equal_address_pinned_toolchain_order`
  的 BILATERAL_24_CASE_BYTE_IDENTICAL 矛盾。其中 "heap fallback untested" 仍真实（16/17 项不触发
  heap 分支），过时的只是 "24-case projection untested" 半句。修正方向：删去该半句，保留 heap
  fallback 与跨 toolchain 两点。注意修改 metadata 会改变其 blob sha256 → 需按 pin 重钉三件套流程
  重跑 runner（runner 校验 `comparand.runner_sha256` 等，metadata 的 manifest 指纹不受 residual 文本
  影响，但 run-record 的 metadata blob OID 会变）。

**S3（建议登记）`JUMPTABLE-SORT-TOOLCHAIN-0001` 在主仓 TODO_BOARD 无独立条目**
- metadata/coverage 均绑定该 TODO ID，docs 亦有专段；PIPELINE/EMULFN 在 TODO_BOARD 都有独立条目，
  SORT-TOOLCHAIN 只在 `JUMPTABLE-THUNK-CLASSIFY-0001` 行内被提及。按铁律 3"每项 TODO 必须包含稳定
  ID/状态/owner/write-set/验收"，建议 root 补一行独立条目（P1，owner=root 或 jt_thunk_writer，
  验收=固定 oracle toolchain 或定义并双侧验证实现无关契约）。

### 不构成问题的核验说明
- worktree 内 `docs/TODO_BOARD.md` 仍是 58aa109 旧基线（THUNK-CLASSIFY=IN_PROGRESS/evidence=pending）：
  主仓 TODO_BOARD:17 已由 root 更新为 `REVIEW（候选 cb9e054）`且内容与事实相符（TODO_BOARD 是主 Agent
  维护的活动队列，worktree 不拥有该文件 write-set，非实现者违规）。
- `#define private public` hack（cpp fixture:14-16）：标准头先于宏 include，注释明示 test-only，
  双侧同构；可接受。
- Rust fixture `.rs` 的 XML decoder 建立 prototype 与 C++ synthetic Architecture 钉值：这是**补齐**
  同输入（此前双侧 Architecture 状态有差异），metadata `representation_residual` 仍诚实声明
  ParamListStandardOut 债务，无过度声明。

## 8. 逐项对照表（5 条 REJECT × 复核结论）

| # | 前任 REJECT 理由 | 复核结论 | 关键证据 |
|---|---|---|---|
| 1 | runner 从未完整执行 24-case | **闭合** | bundle 存在 + 本轮重跑 exit 0 + 双侧 stdout 字节一致 + selector 已限 depth2/rugra-*/唯一 |
| 2 | metadata 子项误标 MATCH | **闭合**（S2 残句除外） | 10 MATCH 全部双侧执行、3 组 MISMATCH 保持、overall=MISMATCH、runner 结构强制 |
| 3 | live metadata/overlay TOCTOU | **闭合** | captured blob 物化 + O_NOFOLLOW FD + 前后全量回读 cmp + FD 重执行 |
| 4 | archive/toolchain/libstdc++ 未冻结 | **闭合** | oracle 四重身份 + archive sha + 逐 blob 回验 + 50+ 工具哈希 + 6 语义树 + 55 库闭包 + libdecomp 79 member 逐字节 |
| 5 | EmulateFunction LowlevelError 通道未登记 | **闭合** | JUMPTABLE-EMULFN-0001 四分支登记 + docs 同步 + runner evidence_kind 强制 |

## 9. 最终判定

**APPROVE** — `cb9e054` 可作为 JUMPTABLE-THUNK-CLASSIFY-0001 的证据候选集成（合并时按主仓 TODO_BOARD:17
的要求由 root 执行集成 commit 与门禁）。fixture 的 24-case 双侧 MATCH 声明经本人独立验证为真；模块与
overall 状态保持 MISMATCH/L2，无越级声明。S1/S2 为文档一致性修复（建议集成同批或紧随 docs-only 提交），
S3 为登记完整性建议，均不阻断。
