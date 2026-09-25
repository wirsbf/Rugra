# FUNCTION_MAP 分母对账报告（2026-09-26，车道 FMAPRECON）

> **任务**: 关闭 AGENTS.md「~2055 与旧报告 ~5200+ 分母冲突 → 全局完成度未证明」的唯一阻塞项。
> 本报告独立复现权威分母、逐项对账现行账本、裁决历史口径冲突，并给出账本生成器重建规格。
> Oracle: `Ghidra_12.0.4_build` / `e40ed13014025f82488b1f8f7bca566894ac376b`（114 个 `.cc` + 114 个 `.hh`）。
> 复现脚本: `/dev/shm/rugra-reports/fmaprecon/{enumerate_authoritative,reconcile_four_category,delta_characterize,adjudicate_historical}.py`。

## TL;DR（结论）

1. **权威分母 = 9494 条行为定义**（`.cc` 5691 + `.hh` inline 3803），与 `FUNCTION_MAP.md`/生成器口径逐数复现。
   本机 Universal Ctags 6.2.0 与账本记录的 6.2.1 计数**完全一致**（版本字符串差异不影响分母）。
2. **逐项对账闭环**: 现行机器账本 `FUNCTION_LEDGER.json` 的 **15811/15811** 条记录与全新枚举在
   `(path, line, qualified_name, kind)` 粒度 **1:1 全等**（缺失 0 / 多余 0）。定义按映射状态拆分:
   **已映射 4279 / 未映射 5215**（缺 0 / 多余 0）。
3. **冲突裁决**: `~2055`、`~5200+`、`9494`、`5549` 是**四个不同口径的数字，两两不矛盾**:
   - `~2055` = 9 份手写 `FUNC_*.md` 的计划估算总和（精确算术 85+135+185+120+170+190+465+620+85=2055），
     仅覆盖 26/114 个 `.cc`、不含 `.hh`，是**工作计划子集**，从来不是全量分母。
   - `~5200+` = 2026-07-02 手工审计（`docs/archive/function_audit/`）在其提及的 72 个源文件
     （53 `.cc` + 19 `.hh`）内的 `.cc`+`.hh` 定义计数——实测该集合权威定义数 **5280**，与 `~5200+` 吻合
     （偏差 <1.5%）。是**63% 文件子集的真实计数**。
   - `9494` = 全量 228 文件、锁定 oracle、ctags 机器口径——**唯一合法完成度分母**。
   - `5549` = REFSDEF 解析器（`tools/check_ghidra_refs.py`）对 114 个 `.cc` 的**唯一限定名**计数
     （同名重载/多定义点合并），非定义点数；与 ctags 的 `.cc` 唯一名 5530 仅差 122/103 个键
     （分类见 §3.4）。**口径单位不同**（唯一名 vs 定义点），非冲突。
4. **账本不陈旧于 Ghidra 侧，但整体 `--check` 失败（rc=1）**: 原因是 (a) 账本内嵌 ctags 版本串
   6.2.1 vs 本机 6.2.0；(b) Rust 侧记录锚定 continuity checkpoint `ac7a3526`（10581 条），
   而本 worktree 基线为 `d0e27c14`。分母断言（5691/101/3803/6216）依旧通过。
   → **P2 重建票**（root 串行）: 推进 continuity 到当前 master 锚点并在当前 ctags 下重生成四件套。

---

## §1 权威分母（双方法独立复现）

### 1.1 方法 A — Universal Ctags（主口径，与生成器逐字同参数）

命令（在 repo 根执行；与 `tools/generate_function_ledger.py::ctags_entries` 完全一致）:

```bash
cd <repo-root>
ctags --output-format=json --fields=+neKStz --extras=+F --kinds-C++=+p -o - \
  ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/*.cc \
  ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/*.hh \
  | python3 -c '<按 _type==tag 且 kind∈{function,prototype} 分桶计数>'
```

| 类别 | 数量 | 说明 |
|---|---:|---|
| `.cc` definitions | **5691** | 行为分母主体 |
| `.hh` inline definitions | **3803** | 行为分母主体 |
| **行为定义合计** | **9494** | **唯一函数级完成分母** |
| `.cc` prototypes | 101 | 声明参考 |
| `.hh` prototypes | 6216 | 声明参考 |
| raw 记录合计 | 15811 | definitions + declarations |

**环境指纹**（可复现性）:
- oracle commit: `e40ed13014025f82488b1f8f7bca566894ac376b`（worktree `ghidra/` symlink → 主仓，HEAD 校验通过）
- ctags: `Universal Ctags 6.2.0(d8622b793)`（账本生成时为 6.2.1(v6.2.1)——**两版本计数恒等**，仅版本串不同）
- `.cc` 树 sha256 指纹: 见 `/dev/shm/rugra-reports/fmaprecon/authoritative_enumeration.json`
  （`oracle.cc_tree_sha256` / `oracle.hh_tree_sha256`，按文件名+单文件 sha256 链式累加）

### 1.2 定义形态分类（ctags 9494 条行为的结构拆分）

| 形态 | 数量 |
|---|---:|
| 带作用域（method/类成员）定义 | 9453 |
| 自由函数（无作用域）定义 | 41 |
| 其中: 构造函数 | 1134 |
| 其中: 析构函数 | 205 |
| 其中: `operator` 重载 | 95 |
| 其中: 普通方法/成员 | 8060 |

定义点最多的 12 个文件: `ruleaction.cc` 340, `ruleaction.hh` 272, `fspec.hh` 271, `fspec.cc` 243,
`type.cc` 235, `typeop.cc` 210, `block.cc` 204, `slghsymbol.hh` 173, `block.hh` 171,
`slghsymbol.cc` 171, `database.cc` 170, `unify.hh` 163。携带定义的文件共 216/228。

### 1.3 方法 B — REFSDEF 行形解析器（旁证口径，只读复用）

`tools/check_ghidra_refs.py::parse_cc_definitions`（未改动一行）跑 114 个 `.cc` + 114 个 `.hh`:

| 度量 | `.cc` | `.hh` |
|---|---:|---:|
| 解析器: 定义点总数 | 5723 | 5169 |
| 解析器: 唯一限定名 | **5549** | 4066 |
| ctags: 唯一名（剥 `ghidra::` 前缀后） | 5530 | 3642 |
| ctags: 定义点 | 5691 | 3803 |

`.cc` 侧两法在唯一名粒度吻合良好（差 122/103 键，见 §3.4）；`.hh` 侧解析器**系统性高估**
（`;\t///< doxygen 尾注` 使 `endswith(";")` 守卫失效 ≈1943 例，另有类体内联方法的自由键 vs
ctags 作用域键错位），故 `.hh` 权威只能取 ctags。这与 `check_ghidra_refs.py` 自身的 scope 规则
（def-start 校验仅覆盖 `.cc`）一致——**该解析器设计用途是 .cc 引用门禁，不是分母枚举器**。

---

## §2 逐项对账（四分类闭环）

### 2.1 机器账本（现行 `FUNCTION_LEDGER.json`，commit 时锚 `ac7a3526`）

权威集 = 全新 ctags 运行；账本集 = 签入的 `ghidra_functions` 记录。键 = `(path, line, qualified_name, kind)`:

| 分类 | 定义 | 数量 |
|---|---|---:|
| **已映射** | 账本定义记录携带 ≥1 条 Rust 映射边 | **4279** |
| **未映射** | 账本定义记录无任何 Rust 映射边 | **5215** |
| **账本缺失** | 权威集有、账本无 | **0** |
| **账本多余** | 账本有、权威集无（陈旧条目） | **0** |

- 已映射 4279 + 未映射 5215 = 9494（定义全量闭环）；缺失/多余在**全部 15811 条**（含声明）上均为 0。
- 映射边形态: `exact_definition_start` 5129 条 + `inside_function_body` 649 条（一条定义可挂多边；
  账本 summary 的 3992/353 为"任一边为 exact/body 的记录数"，与边数口径不同，无矛盾）。
- 已映射率 4279/9494 = **45.1%**（仅证明来源注释指向，行为状态全部默认 `UNTESTED`，见 §4.3）。

抽样（未映射定义最多的域）: `context.hh` 57、`fspec.hh` 未映射 271 中的多数、`codedata.cc` 41、
`slghsymbol.*`/`unify.*`（SLEIGH 编译器域，Rugra 由 iced-x86/SLEIGH shim 替代层承载）——
与"不移植/替代实现"类目的预期分布一致。

### 2.2 历史手写账本（`FUNC_*.md`，即 "~2055"）

| 组 | 手写估算 | 该组文件权威 `.cc` 定义数 |
|---|---:|---:|
| FUNC_address_space (~85) | 85 | 76 |
| FUNC_varnode_op (~135) | 135 | 137 |
| FUNC_funcdata (~185) | 185 | 186 |
| FUNC_heritage_merge_varmap (~170) | 170 | 172 |
| FUNC_blockaction_jumptable_condexe (~190) | 190 | 446（含 block.cc 204） |
| FUNC_actions_rules (~465) | 465 | 541 |
| FUNC_type_print (~620) | 620 | 683 |
| FUNC_cover_rangeutil (~85) | 85 | 86 |

26 个 `.cc` 文件合计权威 `.cc` 定义 2327（手写表格因 block.cc 双计得 2055）。表格实际行数 671
（大量行段合并列举）。**裁决: 手写账本是估算工作清单，非可审计分母**——现行 `FUNCTION_MAP.md`
将其降级为历史笔记的决定正确。

---

## §3 冲突裁决（四口径来源假说逐项验证）

### 3.1 `~2055`（来源: 旧版手写 FUNCTION_MAP.md 索引表）

**假说: 子集计划估算总和** → **证实**。9 行估算精确相加 = 2055（85+135+185+120+170+190+465+620+85，
其中 block.cc 的 ~120 与 blockaction 组重复计入）。覆盖 26/114 `.cc`（22.8%），零 `.hh`。
同文件集合权威计数 2327（估算偏低 11.7%，主要低估 blockaction/jumptable/condexe 组与 actions_rules 组）。

### 3.2 `~5200+`（来源: `docs/archive/function_audit/SUMMARY_all_67_files.md`, 2026-07-02）

**假说: .cc+.hh 混合计数 / 部分文件集** → **证实**。审计文档提及 72 个不同源文件（53 `.cc` + 19 `.hh`；
标题"67 个"为审计批次记账数）。该提及集合内权威定义 = 53 `.cc` 的 3837 + 19 `.hh` 的 1443 = **5280**
≈ `~5200+`（偏差 1.5%）。若按"53 `.cc`+其配对 `.hh`全集"算是 6505，若纯 `.cc` 是 3837——
**只有"提及文件集内 .cc+.hh 定义"口径命中 ~5200+**，假说成立。占全量分母 55.6%（63% 文件集）。

### 3.3 `9494` vs `~5200+`（差 ≈4200）

差量来源两块: (a) 审计未提及的 61 个 `.cc`（5691−3837=1854 条定义，SLEIGH 域 `slgh*.cc`、
`pcodeparse.cc`、`unify.cc`、`grammar.cc` 等大文件占多数）; (b) 未提及的 95 个 `.hh` inline
（3803−1443=2360 条）。两者合计 4214 ≈ 差值。

### 3.4 `5549` vs `5691`（REFSDEF 解析器 vs ctags，.cc）

同树两种聚合: 唯一限定名 5549 vs 定义点 5691（重载/多定义点 142 处之差），**非冲突**。
名粒度残差（剥 `ghidra::` 后）: 解析器独有 122 / ctags 独有 103:
- ctags 独有 103: `operator` 拼写差（`operator <<` vs `operator<<`, 24）、嵌套类构造
  `Outer::Inner::Inner`（裸 ctor 正则只认单层）、flex 生成物前向声明误判 1 例等;
- 解析器独有 122: 类体内联方法被记为自由键（`getNumVariables` vs `StackSolver::getNumVariables`）、
  `const X &name(expr); // 注释` 局部变量初始化误判、operator 拼写反向差。
结论: **ctags 为定义点权威，解析器为 .cc 旁证**；两者一致到 ~2% 名粒度，互为交叉校验。

---

## §4 账本生成器重建规格（增量维护协议）

生成器 `tools/generate_function_ledger.py`（9365 行）已具备以下能力，本节将其固化为
**唯一重建规程**（P2 票 `FMAPRECON-REGEN-0001` 落实 root 侧执行部分）。

### 4.1 数据源

| 源 | 用途 | 工具 |
|---|---|---|
| 锁定 oracle 228 文件 | 权威分母与签名 | Universal Ctags（主）+ `check_ghidra_refs.py` 解析器（.cc 旁证，CI 交叉断言） |
| `src/**/*.rs` | Rust 侧记录与映射 | `tools/rust_fn_scanner.py` |
| `// Ghidra:` / `// RUGRA-GLUE:` 注释 | 来源映射边 | 生成器内置 marker 扫描 |
| 首父历史（pinned） | ID 连续性/谱系 | `--reconcile-continuity`（checkpoint 链） |

### 4.2 记录字段（Ghidra 侧，schema 2）

`id`（`GH12-F-<sha256[:20]>`，= hash(锁定路径, entry_kind, 完整限定签名[, 预处理守卫消歧])，
**不含行号/序号，位置无关**）、`id_disambiguator`、`path/file/source_kind/entry_kind`、
`line/end_line`、`name/scope/qualified_name/arguments/return_type/signature`、`file_scope`、
`rust_mappings[]`（`{kind: exact_definition_start|inside_function_body, rust_id}`）、
`behavior_status`（定义默认 `UNTESTED`；仅锁定 oracle fixture 完整同输入/同输出可升 `MATCH`）。
Rust 侧 `RG-F-*` 同理由 (module, owner_context, 规范化签名) 哈希。

### 4.3 状态语义（与 AGENTS.md 对齐约定一致）

- 注释映射（exact/body）只证明**来源指向**，不证明行为;
- 全部 9494 定义默认 `UNTESTED`；`MATCH` 仅当机制 B2 fixture（oracle commit+架构+compiler spec+
  analysis options+输入指纹齐全）完整观察零差异;
- 分母断言 `EXPECTED_COUNTS = {cc_definition:5691, cc_prototype:101, hh_definition:3803,
  hh_prototype:6216}` 硬编码于生成器，任何漂移立即 `RuntimeError`——**分母变更必须人工裁决**。

### 4.4 增量维护协议

1. **日常**: `src/*.rs` 改动不触发账本重生成; 生成器 `--check` 模式是 CI 门（当前在非锚点
   worktree/不同 ctags 下 rc=1 属预期，root 集成点统一重生成）。
2. **root 集成点（每 wave 收尾）**: ①`--reconcile-continuity` 推进 checkpoint 至新锚 commit
   （保 ID 谱系/tombstone/别名链，禁止直接改历史段）; ②重生成四件套
   （`FUNCTION_LEDGER.json`、`FUNCTION_MAP.generated.md`、`PROTOCOL_TABLE.json`、
   `DEPENDENCY_DAG.json`）; ③`--check` 字节级复核; ④同 commit 提交 + `docs/TODO_BOARD.md` 记录锚点。
3. **ctags 版本变化**: 分母断言保证计数恒等即可重生成; 新版本串写入 `oracle.ctags` 字段并同 commit
   记录（本报告已证 6.2.0/6.2.1 计数恒等）。
4. **oracle 变更（不应发生，oracle 锁死）**: 全量 `--migrate` 级处理，需 root 明确批准。
5. **新增交叉断言（本 lane 建议，随 P2 票交付）**: CI 中加入解析器旁证计数
   （唯一名 5549±容差或重算名粒度 diff），防 ctags 行为漂移单点失效。

### 4.5 与旧规格的差异说明

本 lane 任务书原设"数据源=解析器输出"; 实际裁决: 解析器行形启发式在 `.hh` 系统性高估
（doxygen 尾注 defeating `;` 守卫）且设计用途是 `.cc` 引用门禁，**不担当分母枚举器**;
生成器 ctags 口径已被本报告双方法独立验证，保留为主数据源，解析器降为 CI 交叉断言（§4.4.5）。

---

## §5 残余风险与后续动作

| # | 事项 | 等级 | 归属 |
|---|---|---|---|
| 1 | 账本四件套需在当前 master 锚点 + 本机 ctags 下重生成（`--check` rc=1 根因=锚点漂移+版本串，非分母漂移） | P2 | `FMAPRECON-REGEN-0001`（root 串行） |
| 2 | AGENTS.md「对齐 Oracle」节仍称冲突未决——本报告裁决后需 root 措辞更新（将"冲突待裁决"改为"已裁决，9494 为准，重建票在案"） | P2 | root（随 #1 同 commit） |
| 3 | 已映射 4279 仅是来源注释映射; 行为 `MATCH` 证据索引仍由 `FUNCTION-EVIDENCE-0001` 承载（BLOCKED，独立推进） | P0 | 既有票 |
| 4 | 未映射 5215 中的 SLEIGH 域（slgh*/pcodeparse/unify/grammar）需按"替代实现"路径逐项裁决而非按缺失记 | P3 | 后续审计车道 |

## 附录: 复现命令

```bash
# 权威分母（本报告 §1.1 全表 + §1.2 形态分类 + 指纹）
python3 /dev/shm/rugra-reports/fmaprecon/enumerate_authoritative.py
# 四分类对账（§2.1）
python3 /dev/shm/rugra-reports/fmaprecon/reconcile_four_category.py
# 解析器 vs ctags 差量刻画（§1.3/§3.4）
python3 /dev/shm/rugra-reports/fmaprecon/delta_characterize.py
# 历史口径裁决（§3.1/§3.2）
python3 /dev/shm/rugra-reports/fmaprecon/adjudicate_historical.py
# 生成器自检（§4.4; 非锚点环境 rc=1 属预期）
python3 tools/generate_function_ledger.py --check
```

产物 JSON（均含 oracle 指纹）: `/dev/shm/rugra-reports/fmaprecon/{authoritative_enumeration,
reconcile_four_category,delta_characterization,historical_adjudication}.json`。
