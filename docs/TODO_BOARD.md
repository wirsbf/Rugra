# Todo Board (任务看板)

本文档的顶部“活跃 wave”是当前任务唯一事实源；后文保留历史阶段记录，不能作为当前优先级。

## 活跃 wave：`W-2026-08-11-A` — oracle 与高扇出地基

**锁定 oracle**：Ghidra 12.0.4 / `Ghidra_12.0.4_build` /
`e40ed13014025f82488b1f8f7bca566894ac376b`。

**状态机**：`BACKLOG → READY → IN_PROGRESS → REVIEW → DONE`。`BLOCKED` 必须指向一个更底层 TODO ID；
`DONE` 必须同时有 commit、四类语义、验收命令和 oracle 状态。

| ID | P | 状态 | owner | Ghidra ↔ Rugra | write-set | 依赖 / 验收 | 更新 |
|---|---:|---|---|---|---|---|---|
| `ORACLE-0001` | P0 | DONE | root | 本地参考树 | 忽略的 `ghidra/` | HEAD=`e40ed13`, 114 `.cc` | 2026-08-11 |
| `ORACLE-0002` | P0 | BLOCKED | unassigned | 12.0.4 curl/httpd golden | `tests/golden/*`, oracle metadata | 依赖 `SLEIGH-0001` + 可运行 12.0.4 headless distribution + 锁定 analysis options；重生后 compare 零未解释差异 | 2026-08-11 |
| `LEDGER-0001` | P0 | DONE | root | 114 `.cc/.hh` 全函数 ↔ `src/**/*.rs` + 协议表/依赖 DAG | `tools/generate_function_ledger.py`, `docs/alignment_audit/{FUNCTION_LEDGER.json,FUNCTION_MAP.md,FUNCTION_MAP.generated.md,PROTOCOL_TABLE.json,DEPENDENCY_DAG.json}`, `docs/TODO_BOARD.md` | evidence=`this commit`；locked HEAD/clean tree + Universal Ctags 6.2.0；9494 behavior definitions（5691 `.cc` + 3803 `.hh`）/6317 declarations/15811 raw records，Rugra=8407；3026 exact definition markers、380 body refs，其余不伪报；1660 protocol observations/73 cross-language candidates；474 Rust + 396 include + 68 TODO edges；self-test、py_compile、`--check` 零漂移 | 2026-08-12 |
| `PERF-BUILD-0001` | P0 | DONE | root | Rust/C++ 可复现快速构建 | `.gitignore`, `Cargo.toml`, `Cargo.lock`, `build.rs`, `tools/rugra_build.py`, `tools/README.md`, `docs/TODO_BOARD.md` | evidence=`this commit`；versioned lockfile + `cc/parallel`；受控 offline/locked 环境、430-file input digest、工具链/dirty-state/report；自动探测 cache（本机无 sccache/ccache，正确回退 none）；fast-release all-targets cold=43.17s、warm=0.162s，release lib=35.79s；self-test/py_compile/tree/profile checks 全绿，canonical release 配置未改 | 2026-08-12 |
| `PERF-GATE-0001` | P0 | DONE | root | edit/commit/wave/nightly 四级门禁 | `tools/rugra_gate.py`, `tests/oracle/fixture_registry.json`, `tools/README.md`, `docs/VERIFICATION_GUIDE.md`, `docs/TODO_BOARD.md` | evidence=`this commit`；每级命令、超时、输入/输出 hash、exit 状态与工作树指纹结构化记录；commit 级使用稳定函数账本选择 changed fixture，未覆盖源码改动 fail-closed；wave/nightly 保留全 fixture、端到端与冷 release 门禁；self-test、dry-run、真实 edit tier 全绿（health=0.04s，fast lib check=17.99s） | 2026-08-12 |
| `IMPACT-0001` | P0 | DONE | root | changed Rust function/path → oracle fixture/门禁 | `tools/select_fixtures.py`, `tests/oracle/fixture_registry.json`, `tools/README.md`, `docs/VERIFICATION_GUIDE.md`, `docs/TODO_BOARD.md` | evidence=`this commit`；依赖 `LEDGER-0001`（已满足）；5 个真实 runner 注册；git hunk→当前 Rust span→稳定 ID，支持 staged/base/显式 path/function/tier；新增/删除/rename-as-D+A/顶层/未登记函数 fail-closed 选择全量，`--strict` rc=2；registry stale-ID/runner/commit/timeout 自检；目标选择约 0.4s | 2026-08-12 |
| `ORACLE-CACHE-0001` | P0 | DONE | root | 内容寻址 oracle 产物与阶段快照 | `.gitignore`, `tools/oracle_cache.py`, `tools/{rugra_gate,select_fixtures}.py`, `tests/oracle/{fixture_registry.json,preferred_zext_1204.metadata.json}`, `tools/README.md`, `docs/VERIFICATION_GUIDE.md`, `docs/TODO_BOARD.md` | evidence=`this commit`；5 个 registry fixture 默认走 cache capture；key 覆盖锁定 commit、arch/cspec/options、metadata、input/tool/comparand、command/executable/env hash；成功可重放，失败/超时不缓存，`--refresh-fixtures` 检测同 key 非确定输出；原子并发 store、逐 artifact/结果交叉校验、防 symlink/path traversal、只读 restore、超时清理进程组；命中重新计算 provenance；self-test + real miss/store/hit/verify/restore 全绿，preferred fixture 4.34s→0.128s | 2026-08-12 |
| `DIFF-BISECT-0001` | P1 | DONE | root | pipeline stage hash/首差异定位 | `tools/stage_diff.py`, `tools/README.md`, `docs/VERIFICATION_GUIDE.md`, `docs/TODO_BOARD.md` | evidence=`this commit`；依赖 `ORACLE-CACHE-0001`（已满足）；snapshot 固定 oracle/arch/cspec/options/metadata/context 与有序原始 artifact；compare 报首个 provenance/stage ID/order/schema/state/hash/size/缺失差异，rc=0/1/2；不规范化顺序/别名/CFG；self-test 覆盖零差异/内容/重排/缺失/schema | 2026-08-12 |
| `PIPE-SNAPSHOT-0001` | P0 | DONE | root | locked 12.0.4 `GetStr` ↔ Rugra 六层 pipeline snapshot | `examples/getstr_stage_snapshot.rs`, `tests/oracle/getstr_pipeline_1204.{cc,metadata.json}`, `tools/run_getstr_pipeline_oracle.sh`, `tests/oracle/fixture_registry.json`, `docs/{TODO_BOARD,VERIFICATION_GUIDE}.md` | evidence=`this commit`；同一 curl SHA/entry/x86-64 gcc/BFD-symbol-only 输入保存 P-code、CFG、Heritage/SSA、Action IR、结构树、C；真实 locked runner exit0 并产 stage manifests/comparison；首差异 raw op 103↔105、index77 为 Ghidra 可达 `0x3708` ↔ Rugra 不可达 NOP `0x3702`；两次 Rugra 00-02逐字相同但03起非确定，完整保留不规范化；Heritage 边界仍 `NO_ORACLE`，overall=`MISMATCH`、模块不升级 | 2026-08-13 |
| `REDUCE-0001` | P1 | DONE | root | oracle mismatch 输入 delta reduction | `tools/reduce_fixture.py`, `tools/README.md`, `docs/VERIFICATION_GUIDE.md`, `docs/TODO_BOARD.md` | evidence=`this commit`；JSON list/JSON Pointer object-field/byte-hex deterministic ddmin；predicate argv 无 shell、interesting/boring/harness exit 严格分型、进程组 timeout、重复判定、candidate mutation guard、内容 hash memoization；输出原始/最小指纹与完整 evaluation trace，最终重跑并证明 1-minimal；self-test + 三格式 CLI fixture 全绿 | 2026-08-12 |
| `PERF-VALIDATE-0001` | P1 | DONE | root | verification acceleration wave 冷闭包验收 | `docs/TODO_BOARD.md` | evidence=`753cfd3`；全部新增 Python 工具 py_compile/self-test、ledger `--check`、gate health/doc/annotations/strict refs/Evidence 全绿；`cargo test --offline --locked --all-targets` exit 0（既有 warnings）；fresh-target canonical `release --all-targets` exit 0，430 inputs / 112 jobs / cache=none / 174.31s，临时 target 自动清理；nightly dry-run 13 checks | 2026-08-12 |
| `GATE-0001` | P0 | DONE | root | `pre-commit` / `commit-msg` / ZCode events / CI | `.githooks/{pre-commit,commit-msg}`, `.zcode/config.json`, `tools/check_alignment_evidence.py`, `.github/workflows/alignment-gates.yml`, `docs/alignment_docs/HOOK_GUIDE.md` | `da4d93a`；hooksPath=`.githooks`，两 hook index mode=100755；health/doc/annotations/strict refs/Evidence 全绿；ZCode `startup|resume`；独立终审 APPROVE | 2026-08-12 |
| `GATE-SCANNER-0001` | P0 | DONE | annotation_checker_review | Rust fn item scanner + commit/PreToolUse 共用 scope | `tools/rust_fn_scanner.py`, `tools/check_ghidra_annotations.py`, `.zcode/align_gate.py` | `ce1d32c`；共享 scanner 覆盖 const/extern/restricted visibility/单行 impl、item macro、精确 cfg(test) scope、trait `;` 终点、多编辑重叠与逐次读取 freshness；94 文件零违规；独立终审 APPROVE | 2026-08-12 |
| `SLEIGH-0001` | P0 | DONE | root | Linux SLEIGH source build + FFI link | `build.rs`, `sleigh_shim/`, `examples/sleigh_test.rs`, build/verification docs | `fcc5142`；22 TU + CLI/example 链接，SLEIGH smoke 3-byte/COPY，`cargo test --offline --all-targets` 1297/0/3，独立复核 APPROVE | 2026-08-11 |
| `SLEIGH-0002` | P0 | IN_PROGRESS | root | raw SLEIGH 资产/ABI/context/lifecycle 闭包 | 由 `SLEIGH-0002A`…`D`、`SLEIGH-0002B-COVERAGE` 与 `SLEIGH-0003` 精确租约组成 | 依赖链 `2A → 2B → {2B-COVERAGE,2C,0003}`，`2C → 2D → SLEIGH-FLOW-0001`；禁止以单次 `load_pspec` 冒充修复；完整 raw fixture 前保持 MISMATCH/NO_ORACLE | 2026-08-12 |
| `SLEIGH-0002A` | P0 | DONE | root | 锁定 x86-64 spec 资产与可重现生成 | `.gitattributes`, `tools/build_locked_x86_64_sla.sh`, `sleigh_specs/{x86-64.sla,x86-64-gcc.cspec,x86-64.spec-metadata.json}`, `docs/TODO_BOARD.md` | evidence commit=`87aaef2`；从 `e40ed130` Git 对象临时提取 cpp+language tree；双编译 SHA `d5adc314…`/487659；pspec/cspec/ldefs hash 固定；example 3-byte/COPY；Cross-Review APPROVE；仅资产 provenance，仍 NO_ORACLE | 2026-08-12 |
| `SLEIGH-0002B` | P0 | DONE | root + sleigh_abi_fixture | 动态无截断 C ABI + owned image + typed result/error | `sleigh_shim/rugra_sleigh.cpp`, `src/sleigh_ffi.rs`, `docs/api/sleigh_ffi.md`, `examples/sleigh_test.rs`, `tests/oracle/sleigh_decode_1204.{cc,rs,metadata.json}`, `tools/run_sleigh_decode_oracle.sh`, `docs/TODO_BOARD.md` | evidence=`this commit`；锁定 12.0.4 同 schema stdout direct diff：12 个已覆盖 case `MATCH`（CPUID 78 ops/134 inputs），fixture overall=`PARTIAL_MATCH`，`Unimpl`=`UNTESTED`；四类语义 4/4：owned result/输出与 pointer alias、issued/input 顺序、per-instruction identity 计数、pointer/space whitelist 比较键；runner + `cargo test --offline --all-targets` + example 全绿；独立 fixture/provenance 与 C++ semantic review APPROVE；余项绑定 `SLEIGH-0002B-COVERAGE`/`SLEIGH-0002C`/`SLEIGH-0002D`/`SLEIGH-0003`，模块保持 L2 | 2026-08-12 |
| `SLEIGH-0002B-COVERAGE` | P1 | READY | unassigned | `Sleigh::oneInstruction` 动态 ABI 未覆盖分支闭包 | `tests/oracle/assets/sleigh_decode_coverage_1204/`, `tests/oracle/sleigh_decode_coverage_1204.{cc,rs,metadata.json}`, `tools/run_sleigh_decode_coverage_oracle.sh`, `docs/TODO_BOARD.md` | 依赖 `SLEIGH-0002B`（已满足）；用锁定官方语言资产触发 `Unimpl`，并覆盖单 op >16 inputs、delay-slot step、STORE space-id、OOM/std/unknown 与析构 fault injection；完整 result/state direct diff；lifecycle/InvalidState 归 `SLEIGH-0002D` | 2026-08-12 |
| `SLEIGH-0002C` | P0 | READY | unassigned | `ContextInternal::decodeFromSpec` 完整 pspec context/tracked ranges | `sleigh_shim/rugra_sleigh.cpp`, `src/sleigh_ffi.rs`, `docs/api/sleigh_ffi.md`, `tests/oracle/sleigh_context_1204.{cc,rs,metadata.json}`, `tools/run_sleigh_context_oracle.sh`, `tests/oracle/sleigh_decode_1204.metadata.json`, `docs/TODO_BOARD.md` | 依赖 `SLEIGH-0002B`（已满足）；`.sla initialize` 后走真实 XmlDecode，逐项对拍 range/mask/order/tracked DF/异常与全部 state mutation，删除字符串扫 `<set>`；与 `SLEIGH-0003` write-set 互斥 | 2026-08-12 |
| `SLEIGH-0002D` | P0 | BLOCKED | unassigned | 长生命周期 `SleighLifter` / parser cache | `src/disasm/sleigh_lift.rs`, `src/sleigh_ffi.rs`, paired API/oracle | 依赖 `SLEIGH-0002C`；同一 translator/context 跨解码复用，禁止每指令 new；prefix 不泄漏、cache/image 规则与 branch constant-space 保真 | 2026-08-12 |
| `SLEIGH-0003` | P1 | READY | unassigned | `Sleigh::initialize` + space/register catalog ↔ lossless construction/metadata ABI | `sleigh_shim/rugra_sleigh.cpp`, `src/sleigh_ffi.rs`, `docs/api/sleigh_ffi.md`, `examples/sleigh_test.rs`, `tests/oracle/sleigh_decode_1204.{rs,metadata.json}`, `tests/oracle/sleigh_create_metadata_1204.{cc,rs,metadata.json}`, `tools/run_sleigh_create_metadata_oracle.sh`, `docs/TODO_BOARD.md` | 依赖 `SLEIGH-0002B`（已满足）；用 typed owned result 替代 `new()->Option`/固定 64-byte name 缓冲的证据入口；同输入对拍创建异常与完整 space/register 字段；与 `SLEIGH-0002C` 串行 | 2026-08-12 |
| `SLEIGH-FLOW-0001` | P0 | BLOCKED | unassigned | Flow 使用 SLEIGH step/error/xref | `src/flow.rs`, `src/bin/rugra.rs`, paired API/examples/oracle/differential | 依赖 `SLEIGH-0002D` + `ARCH-0001`/storage 地基；iced 仅诊断；按 FlowInfo::processInstruction 分支处理 typed error、visited、halt/warning/xref | 2026-08-12 |
| `ANN-0001` | P0 | DONE | root | 旧 scanner 基线 247 项 + expanded scanner 新发现 85 项 | `ANN-A`…`ANN-P` 的互斥 annotation 租约 | `d78f3d0`…`8a3e13d` + `ce1d32c`；全部先读锁定 `.cc/.hh` 后分类；`annotations --all` 94 文件零违规，strict refs/doc-sync 全绿；纯 provenance 不升级模块状态 | 2026-08-12 |
| `ANN-A` | P0 | DONE | ann_options | `options.rs` 44 个（37×`name` + parse/collection/default helpers） | `src/options.rs`, `docs/api/options.md` | `d78f3d0`；锁定 oracle 全文重读；纯 provenance、四类行为语义未变、B2 仍 NO_ORACLE；scoped annotation+refs+doc-sync+check 通过 | 2026-08-11 |
| `ANN-B` | P0 | DONE | pipeline_reachability | `flow.rs` 18 个 + `callgraph.rs` 2 个 accessor/helper | `src/{flow,callgraph}.rs`, `docs/api/{flow,callgraph}.md` | `d2526ee`；锁定 oracle 全文重读；纯 provenance、四类行为语义未变、B2 不升级；scoped annotation+refs+doc-sync+check 通过 | 2026-08-11 |
| `ANN-C` | P0 | DONE | database_symbol_1204 | `fspec.rs` 18 个 parameter/default/helper 函数 | `src/fspec.rs`, `docs/api/fspec.md` | `0857dec`；锁定 oracle 函数体重读；纯 provenance、四类行为语义未变、B2 不升级；scoped annotation+refs+doc-sync+check 通过 | 2026-08-11 |
| `ANN-D` | P0 | DONE | small_foundation_1204 | `signature.rs` 12 个 + `memstate.rs` 14 个 container/accessor 函数 | `src/{signature,memstate}.rs`, `docs/api/{signature,memstate}.md` | `609e89a`；锁定 oracle 两模块全文重读；纯 provenance、四类行为语义未变、B2 不升级；scoped annotation+refs+doc-sync+check 通过 | 2026-08-11 |
| `ANN-E` | P0 | DONE | cover_merge_foundation_1204 | `cover.rs` 12 个 + `funcdata.rs` 7 个 CFG/helper 函数 | `src/{cover,funcdata}.rs`, `docs/api/{cover,funcdata}.md` | `0cfe1a4`；锁定 oracle 函数体重读；纯 provenance、四类行为语义未变、已知 CFG/identity 差异保留；scoped gates 通过 | 2026-08-11 |
| `ANN-F` | P0 | DONE | heritage_ssa_1204 | `coreaction.rs::{newparam_push_unique,seed_output_trials,derive_func_output_map}` + `heritage.rs::guard_calls_range_with_space` | `src/{coreaction,heritage}.rs`, `docs/api/{coreaction,heritage}.md` | `0864a47`；锁定 oracle 函数体重读；纯 provenance、四类行为语义未变，缺口绑定 OPBANK/FSPEC/HERITAGE/ADDRESS；scoped gates 通过 | 2026-08-11 |
| `ANN-G` | P0 | DONE | parser_ruleparse_1204 | `pcodeparse.rs` 22 个 lexer/decoder helper + `grammar.rs::new_impl` | `src/{pcodeparse,grammar}.rs`, `docs/api/{pcodeparse,grammar}.md` | `64eda57`；锁定 oracle parser/decoder 函数体重读；纯 provenance、四类行为语义未变，wire/parser gaps 保留；scoped gates 通过 | 2026-08-12 |
| `ANN-H` | P0 | DONE | print_pipeline_1204 | `printc.rs` 6 个 + `opbehavior.rs` 36 个 output/behavior helper | `src/{printc,opbehavior}.rs`, `docs/api/{printc,opbehavior}.md` | `d7e7a37`；锁定 oracle 相关文件/函数体重读；纯 provenance、四类行为语义未变，output/behavior gaps 保留；scoped annotation/doc/check 通过 | 2026-08-12 |
| `ANN-I` | P0 | DONE | transform_subflow_1204 | `variable.rs` 14 个 + `dynamic.rs::default` + `unionresolve.rs` 6 个 helper | `src/{variable,dynamic,unionresolve}.rs`, `docs/api/{variable,dynamic,unionresolve}.md` | `10a1929`；锁定 oracle 三模块全文重读；纯 provenance、四类行为语义未变，legacy/ownership gaps 保留；scoped gates 通过 | 2026-08-12 |
| `ANN-J` | P0 | DONE | space_address_1204 | `translate.rs` 6 + `constseq.rs` 5 + `typefactory.rs::insert` + `datatype.rs` 18 个 helper | `src/{translate,constseq}.rs`, `src/type_system/{typefactory,datatype}.rs`, paired `docs/api/*` | `40fa6f9`；锁定 oracle 函数体重读；纯 provenance、四类行为语义未变，TypeFactory/space/wire gaps 明确保留；scoped gates 通过 | 2026-08-12 |
| `ANN-K` | P0 | DONE | print_pipeline_1204 | expanded scanner: `opbehavior.rs` 42 个 const constructors | `src/opbehavior.rs`, `docs/api/opbehavior.md` | `6540688` + `3122d5f`；40 个锁定 inline constructor + 2 个 macro GLUE；Translate 缺口不伪装成 GLUE；scoped gates 通过 | 2026-08-12 |
| `ANN-L` | P0 | DONE | isolated_candidate_b | expanded scanner: `ffi.rs` 10 个 extern ABI 函数 | `src/ffi.rs`, `docs/api/ffi.md` | `3deef90`；10 个 C/Python comparison ABI 均为具体 GLUE；纯 provenance；expanded scanner/refs/doc/check 通过 | 2026-08-12 |
| `ANN-M` | P0 | DONE | cover_merge_foundation_1204 | expanded scanner: `blockaction.rs` 2 个 const helpers | `src/blockaction.rs`, `docs/api/blockaction.md` | `7dd5246`；锁定 12.0.4 constructors/functions 重读；纯 provenance，既有 collapse 差异保留；scoped gates/check 通过 | 2026-08-12 |
| `ANN-N` | P0 | DONE | small_foundation_1204 | expanded scanner: address 2 + marshal 1 + signature 2 + types 13 | `src/{address,marshal,signature,types}.rs`, paired `docs/api/{address,marshal,signature,types}.md` | `7029011`；1 个 locked inline 映射 + 17 个 scalar/const-holder compatibility GLUE；纯 provenance；scoped gates/check 通过 | 2026-08-12 |
| `ANN-O` | P0 | DONE | parser_ruleparse_1204 | expanded scanner: `pcodeparse.rs` 3 个 const token helpers | `src/pcodeparse.rs`, `docs/api/pcodeparse.md` | `1ab0429`；锁定 parser declarations/consumers 重读；3 个具体 typed-token/Pratt GLUE，纯 provenance；scoped gates/check 通过 | 2026-08-12 |
| `ANN-P` | P0 | DONE | transform_subflow_1204 | expanded scanner: `unify.rs` 10 个单行 impl functions | `src/unify.rs`, `docs/api/unify.md` | `8a3e13d`；9 个锁定 constructor + 1 个 Default GLUE；uniqid/maxnum 差异不伪装成 GLUE；scoped gates/tests 通过 | 2026-08-12 |
| `GATE-REF-PRINTC` | P0 | DONE | printc_wire_impl | `printc.rs` 9 个越界 refs（含 integer format wire 值） | `src/printc.rs`, `docs/api/printc.md` | `d9bb491`；9 refs strict 全绿；display wire 窄域 oracle MATCH；完整 push_integer 保持 MISMATCH/L2；Cross-Review APPROVE | 2026-08-12 |
| `GATE-REF-OPBEHAVIOR` | P0 | DONE | print_pipeline_1204 | `opbehavior.rs` 9 个 PTRADD/PTRSUB/POPCOUNT/LZCOUNT refs | `src/opbehavior.rs`, `docs/api/opbehavior.md` | `46752a8`；locked 12.0.4 定义起始行已核；另修 PIECE/SUBPIECE strict false-negative；零行为改动；scoped refs/annotations/doc/check 通过 | 2026-08-12 |
| `GATE-REF-RULEACTION` | P0 | DONE | isolated_candidate_b | `ruleaction.rs` 1 个 `RuleExpandLoad::applyOp` ref | `src/ruleaction.rs`, `docs/api/ruleaction.md` | `a64752b`；锁定 12.0.4 两个完整函数体重读；零行为改动；strict refs 绿，11.3.2 回归 defects/numbering=0 | 2026-08-12 |
| `PCODE-0001` | P0 | DONE | root | `TypeOpFloatInt2Float::preferredZextSize` | `src/typeop.rs`, `src/ruleaction.rs`, `src/subflow.rs`, 对应 API 文档 | `3762e22`；oracle MATCH；1294/0/3；Cross-Review APPROVE | 2026-08-11 |
| `PCODE-0002` | P0 | READY | unassigned | `TypeOp` flags + `OpBehavior` + PcodeOpBank opcode mutation | `src/typeop.rs`, `src/opbehavior.rs`, `src/op.rs`, `src/funcdata.rs`, API/路线图 | 72 descriptors + 72x72 mutation + code-list oracle；当前 clear mask `0x2008084e` vs `0x200fc8de`，仅 1/72 COPY-origin 结果正确 | 2026-08-11 |
| `FFI-0001` | P0 | READY | unassigned | constant evaluator/test IR/comparator ABI 真实 oracle 化 | `src/ffi.rs`, `tools/pcode_compare_test.py`, `docs/api/ffi.md`, locked oracle fixture | 依赖 `PCODE-0002`；修正 5/6 参数 ABI 漂移，区分合法 0/unsupported/div0/error，禁止 RuntimeVerifier 自比较；binary buffer 必须有真实所有权/LoadImage 语义；完整同输入 stdout/state diff | 2026-08-12 |
| `OPCODE-0001` | P0 | READY | unassigned | OpCode 文本/wire 表 + reverse + reserved raw values | `src/opcodes.rs`, `src/marshal.rs`, `src/ffi.rs`, `src/unify.rs`, API/路线图 | 10 个协议名不符；缺 reverse；packed 0/45 raw round-trip；72 正式 discriminants 保持不变 | 2026-08-11 |
| `OPTIONS-0001` | P0 | READY | unassigned | `ArchOption` validation/registry/wire IDs/state mutation | `src/options.rs`, `docs/api/options.md`, 路线图, oracle fixture | 依赖 `MARSHAL-ID-0001` + `ARCH-0001`；精确 name/ID/注册顺序、异常与 numeric 边界、alias/split/nan 参数、所有 state mutation；当前 L2/NO_ORACLE | 2026-08-11 |
| `PARSER-0001` | P0 | READY | root | `PcodeSnippet` 必选标点与失败状态 | `src/pcodeparse.rs`, tests, API/审计文档 | 当前 27 个 `expect_punct` 结果被丢弃且 3 个 local 分支静默漏 `;`；标点删除矩阵 + 失败时无 result + Ghidra parser oracle | 2026-08-11 |
| `PARSER-0002` | P0 | DONE | root | `UserOpSymbol::getIndex` → `CPUI_CALLOTHER` input 0 | `src/pcodeparse.rs`, API/路线图, oracle fixture | `c1e799a`；锁定 runtime oracle MATCH；statement/expression+两参数顺序；1295/0/3；Cross-Review APPROVE | 2026-08-11 |
| `MULTI-0001` | P0 | READY | unassigned | `multiprecision.cc` 16 functions / 7 public operations → RuleDiv* | 新 `src/multiprecision.rs`, `src/ruleaction.rs`, API/路线图 | 完整 334 LoC limb engine；先修 extended PIECE 布局再替换 native `u128`；cross-review+differential | 2026-08-11 |
| `COMP-0001` | P1 | IN_PROGRESS | root | `Decompress` 五函数闭包 | `src/compression.rs`, error/API/oracle fixture | system z_stream + 同 libz/stdout 直接差分；normal/replace/mutate/same-address alias/data-error MATCH；尚缺 init/NEED_DICT/MEM/STREAM/Drop fault injection，整个 compression 保持 L2 | 2026-08-11 |
| `RANGE-0001` | P0 | READY | unassigned | `CircleRange::{intersect,circleUnion,translate2Op}` + `RuleRangeMeld` | `src/rangeutil.rs`, `src/ruleaction.rs`, API/路线图 | `PCODE-0001` 已完成并释放租约；8-bit exhaustive + cross-review + differential | 2026-08-11 |
| `PIPE-0000` | P0 | READY | unassigned | `Action::{reset,perform}` + group/CLI execution | `src/action.rs`, `src/bin/rugra.rs`, API/路线图 | 子 Action 一律走 perform；root 统一 reset→perform；status/count/repeat oracle + cross-review+differential | 2026-08-11 |
| `PIPE-0001` | P0 | IN_PROGRESS | root | `ActionDatabase::universalAction` + six default groups | `src/action.rs`, `src/coreaction.rs`, `docs/api/{action,coreaction}.md`, ordered-tree oracle/路线图 | evidence=`this commit`；按 `coreaction.cc:5421-5441,5479` 从 default decompile 排除 group=`normalanalysis` 的 `ActionNormalizeSetup`，保住外部 FuncProto locks；locked-void Rust regression PASS，curl 24/24 完成且签名已消费锁定原型。仍依赖 `PIPE-0000`，oracle universal=76 leaves/default decompile=71 与当前剩余平铺/重复项须有序树 fixture + 独立 cross-review+differential 后闭环；本次因用户要求串行而未取得独立 APPROVE，不得升 L3 | 2026-08-12 |
| `CALLSPEC-0001` | P0 | READY | unassigned | stable Fspec/callspec identity → normal CALL/CALLIND flow | `src/space.rs`, `src/fspec.rs`, `src/funcdata.rs`, `src/flow.rs`, x86 lift, API/路线图 | 禁止按机器地址去重；direct/indirect/inject/inline/truncate 全路径 oracle；再统一入口和消费者 | 2026-08-11 |
| `PRINTC-0001` | P1 | DONE | printc_wire_impl | integer display wire values | `src/printc.rs`, `docs/api/printc.md`, `tests/oracle/printc_display_1204.*`, runner | `d9bb491`；0..5 wire + valid codec 1..5 + resolved scalar matrix direct diff MATCH；完整 object/alias/tag/suffix/主管线仍 MISMATCH/UNTESTED | 2026-08-12 |
| `DISPLAYFMT-0002` | P0 | READY | unassigned | Symbol/Datatype display-format state + typedef marshal 错误闭包 | `src/database.rs`, `src/type_system/{datatype,typefactory}.rs`, paired API/oracle | 依赖 `MARSHAL-ID-0001`；set 应 OR 完整值、invalid name/value 抛同类错误、重复属性/round-trip、typedef 持久化 format；当前 masks/静默清零/丢弃 typedef format | 2026-08-12 |
| `SSA-0001` | P0 | BLOCKED | unassigned | `ValueSetSolver` constraints → Heritage guards | `src/rangeutil.rs`, `src/heritage.rs`, API/路线图 | 依赖 `RANGE-0001`；先底层 constraints 再 guard integration | 2026-08-11 |
| `MARSHAL-ID-0001` | P0 | READY | unassigned | 12.0.4 AttributeId/ElementId 全表 + reverse | `src/marshal.rs`, `src/translate.rs`, API/oracle | 固定进程级 ID；0=end sentinel；UNKNOWN=159/289；Translate 复用 SPACE=20/SIZE=19 | 2026-08-11 |
| `MARSHAL-PACKED-0001` | P0 | BLOCKED | unassigned | Decoder error channel + four-position packed state machine | `src/marshal.rs`, all codec callers, API/oracle | 依赖 `MARSHAL-ID-0001` + `SPACE-0001`；strict close/skip/type/EOF/raw bytes/space/opcode，禁止 self-roundtrip 冒充 wire parity | 2026-08-11 |
| `SPACE-0001` | P0 | READY | unassigned | architecture-owned AddrSpace registry/handle | `src/space.rs`, arch/translate API/oracle | 稳定 index/type/name/addrsize/wordsize/endian/flags/invalid；是 Address 等所有 storage 键前置 | 2026-08-11 |
| `ADDRESS-0001` | P0 | BLOCKED | unassigned | `Address=(SpaceId, byte offset)` | `src/address.rs`, 全部直接消费者/API/oracle | 依赖 `SPACE-0001`；跨 space equality/order、wrap、word conversion、invalid | 2026-08-11 |
| `SEQNUM-0001` | P0 | BLOCKED | unassigned | immutable uniq/time identity + mutable order | `src/address.rs`, `src/op.rs`, bank/CFG API/oracle | 依赖 `ADDRESS-0001`；setOrder 不得改 Eq/Ord/BTree 键 | 2026-08-11 |
| `RANGEADDR-0001` | P0 | BLOCKED | unassigned | space-aware Range/RangeList | `src/address.rs`, API/oracle | 依赖 `ADDRESS-0001`；相邻不合并、跨 space 分离、完整区间 inRange | 2026-08-11 |
| `BLOCK-0001` | P0 | BLOCKED | unassigned | FlowBlock core + atomic bidirectional edges | `src/block.rs`, `src/funcdata.rs`, API/oracle | 依赖 `ADDRESS-0001` + `SEQNUM-0001`；exact flags/parent/reverse-index/false-first/RPO/loop/dom/marshal | 2026-08-11 |
| `VARNODE-0001` | P0 | BLOCKED | unassigned | VarnodeBank keys/canonicalization/query | `src/varnode.rs`, API/oracle | 依赖 `ADDRESS-0001` + `SEQNUM-0001`；unique base、constructor、loc/def comparator、xref/makeFree/destroy | 2026-08-11 |
| `OPBANK-0001` | P0 | BLOCKED | unassigned | nullable slots/occurrence reads/op lifecycle/IOP | `src/op.rs`, `src/funcdata.rs`, `src/varnode.rs`, API/oracle | 依赖 `VARNODE-0001`；transactional set/unset/output/destroy + deadandgone，移除 Arc::from_raw UAF | 2026-08-11 |
| `CONSTSEQ-0001` | P1 | BLOCKED | unassigned | `Array/String/HeapSequence` storage/order/transform closure | `src/constseq.rs`, Rule/action consumers, API/路线图/oracle | 依赖 `SPACE-0001` + `OPBANK-0001` + `USEROP-0001`；wordsize 转换、encoded space identity、previousOp 顺序、dead outputs 与 CALLOTHER transform 同输入对拍 | 2026-08-12 |
| `MEMSTATE-0001` | P0 | BLOCKED | unassigned | `MemoryBank/MemoryState` exact space/Translate/error state | `src/memstate.rs`, emulate/loadimage consumers, API/路线图/oracle | 依赖 `SPACE-0001` + `ADDRESS-0001` + `ARCH-0001`；命名寄存器必须经 Translate 而非 hash，动态 space/wordsize/endian/异常/overlay mutation 同输入对拍 | 2026-08-11 |
| `VARIABLE-0001` | P0 | BLOCKED | unassigned | HighVariable attach/detach/ownership/order | `src/variable.rs`, `src/varnode.rs`, API/oracle | 依赖 `OPBANK-0001`；Weak ownership、annotation/later VN、sorted instances、dirty propagation | 2026-08-11 |
| `COVER-0001` | P0 | BLOCKED | unassigned | endpoint identity + CFG cover rebuild | `src/cover.rs`, `src/varnode.rs`, `src/merge.rs`, API/oracle | 依赖 `BLOCK-0001` + `VARIABLE-0001`；wrapping cover、predecessor recursion、PcodeOpSet/HighIntersect | 2026-08-11 |
| `DBSYM-FLAGS` | P0 | READY | unassigned | Symbol/Varnode canonical flag namespace | `src/database.rs`, `src/varnode.rs`, API/oracle | NAMELOCK|READONLY 必须是 0x2200，当前 0x6 被解释为 CONSTANT|ANNOTATION | 2026-08-11 |
| `DATABASE-0001` | P0 | BLOCKED | unassigned | SymbolKind identity + addMap/rangemap/query + pipeline | `src/database.rs`, `src/rangemap.rs`, `src/funcdata.rs`, actions/API/oracle | 依赖 `DBSYM-FLAGS` + `ADDRESS-0001` + `TYPE-0001`；最后接 ScopeLocal/newVarnode/Dynamic Actions | 2026-08-11 |
| `FSPEC-0001` | P0 | IN_PROGRESS | root | FuncProto lock/void/model state | `src/fspec.rs`, `docs/api/fspec.md`, locked oracle fixture, `docs/TODO_BOARD.md` | evidence=`this commit`；`tools/run_funcproto_lock_oracle.sh` 对锁定 12.0.4 同输入 stdout direct diff=`MATCH`，覆盖 fresh/zero-input lock/clearUnlocked/copy/clearInput/output lock-unlock 及 model lock；全库 1303 tests PASS。`compat_model` identity 等其余 FuncProto 状态仍留后续闭环，模块保持 L2 | 2026-08-12 |
| `FSPEC-0002` | P0 | BLOCKED | unassigned | ParamActive/Trial ordering and assignment | `src/fspec.rs`, `src/type_system/protomodel.rs`, API/oracle | 依赖 `FSPEC-0001` + `ADDRESS-0001`；slotbase=1、overlap trial、used prefix、ParamEntry alignment/groups；piece flags 必须 isthis=1/hiddenret=2/indirect=4，当前 indirect 与 this 碰撞 | 2026-08-11 |
| `PARAM-RECOVERY-0001` | P0 | BLOCKED | unassigned | `ActionInputPrototype` / `ActionUnjustifiedParams` / own-function `FuncProto` recovery | `src/{coreaction,action,fspec,funcdata}.rs`, `src/type_system/protomodel.rs`, paired API, locked oracle fixture, curl differential | 依赖 `SPACE-0001` + `ADDRESS-0001` + `ARCH-0001` + `FSPEC-0001/0002`；本轮已让兼容 `ActionInferParams` 尊重 imported locks，DWARF 已知原型不再膨胀；但 stripped/unlocked 路径仍以 live-in heuristic 代替 Ghidra 的 `possibleInputParam→ParamActive→resolve/derive→updateInputTypes`，必须对拍完整 prototype/IR mutation并删除硬编码 count/type/ABI 表；诊断见 `FUNCTION_SIGNATURE_PARAMETERS_2026-08-12.md`，B2=`NO_ORACLE` | 2026-08-12 |
| `DWARF-PROTO-0001` | P0 | IN_PROGRESS | root | ELF DWARF subprogram/formal-parameter/varargs → locked `FuncProto` | `Cargo.{toml,lock}`, `src/debugproto.rs`, `src/lib.rs`, `docs/api/{debugproto,lib}.md`, `examples/curl_decompile.rs`, importer regression, `docs/TODO_BOARD.md` | evidence=`this commit`；实现 Ghidra 的“Program DB 已知原型”前端边界：解析 definition/abstract-origin/specification、name/type/order/varargs，以锁定 x86-64 gcc cspec 的资源顺序赋寄存器 storage，再在 Action 前锁定 `FuncProto`。curl input SHA256=`4ee4002b...c6b5d1a`；Rust regression 覆盖 `GetStr=2`、`myprogress=5`、`helpf=1+...`、`getparameter=4`、`hugehelp=0 locked`；由于尚无真实 Java DWARF analyzer 同输入 fixture，importer B2=`NO_ORACLE`。跨 CU/location-list/stack/aggregate/split-DWARF/non-x86 与 stripped recovery 分别留本项 residual/`PARAM-RECOVERY-0001`，不得升 L3 | 2026-08-12 |
| `PRINT-SIGNATURE-0001` | P0 | IN_PROGRESS | root | `PrintC::docFunction` → canonical `emitFunctionDeclaration` | `src/printc.rs`, `docs/api/printc.md`, locked prototype/text fixture, curl differential, `docs/TODO_BOARD.md` | evidence=`this commit`；删除 production `main` 特判、任意 RAX-write return heuristic 和 empty-proto 六寄存器 fallback，直接消费 finalized `FuncProto`。最新 `result/curl_cur.c` SHA256=`01b5eabe...d7aa68`，24/24 反编译、11.3.2 诊断 golden `defects=0,numbering=0,skeleton=2735`；但 12.0.4 prototype/text fixture 尚缺，B2=`NO_ORACLE`。gcc audit 仅 5/23 syntax OK，剩余正文/类型声明问题与 `match_url` aggregate-stack 参数分别绑定既有 Print/Type/Address/FSPEC 缺口，模块保持 L2 | 2026-08-12 |
| `TYPE-0001` | P0 | BLOCKED | unassigned | exact Datatype model + stable TypeFactory identity | `src/type_system/datatype.rs`, `typefactory.rs`, consumers/API/oracle | 依赖 `SPACE-0001`；submeta/virtual compare、arena、dual indices、findAdd、recursive completion、exact-piece、codec | 2026-08-11 |
| `HERITAGE-0001` | P0 | BLOCKED | unassigned | canonical single-pass SSA driver + ActionStart/ActionHeritage | `src/heritage.rs`, `src/coreaction.rs`, `src/funcdata.rs`, API/oracle/differential | 依赖 `ADDRESS/BLOCK/VARNODE/OPBANK/COVER`；先消除 canonical 锁重入，再补 collect/refinement/guards/ADT，最后删除 direct 双 pass | 2026-08-11 |
| `CONDEXE-0001` | P0 | BLOCKED | unassigned | ConditionalExecution/RuleOrPredicate exact CFG rewrite | `src/condexe.rs`, `src/expression.rs`, Funcdata/Block API/oracle/differential | 依赖 `OPBANK-0001` + `BLOCK-0001` + `HERITAGE-0001`；true/false slots、异常、storage/order、Action stage/count | 2026-08-11 |
| `PATHMELD-0001` | P0 | BLOCKED | unassigned | parent/SeqNum ordered path meld + cutoff/truncate | `src/jumptable.rs`, op/block API/oracle | 依赖 `BLOCK-0001` + `OPBANK-0001`；MARK 必须进 PcodeOp flags，删除自创 LOAD 例外 | 2026-08-11 |
| `JUMPTABLE-0001` | P0 | BLOCKED | unassigned | Override/Basic/Basic2/Assisted model recovery closure | `src/jumptable.rs`, flow/action/emulate/userop API/oracle/differential | 依赖 `RANGE-0001` + `PATHMELD-0001` + `ADDRESS/BLOCK/OPBANK` + `INJECT-0001`；先 trialNorm/findStartOp，再 model selection/guards/normalization | 2026-08-11 |
| `PRINT-RPN-0001` | P0 | IN_PROGRESS | root | invisible groups + complete OpToken/RPN/CFG emission | 由 `PRINT-RPN-0001A` 起按表达式分组 → terminal mask → CFG 单次发射拆分原子闭环 | exact group IDs；全部算术/CALL/subscript/STORE走 RPN；terminal mask 生效；删除 fresh-loop 重发；主管线 cross-review | 2026-08-12 |
| `PRINT-RPN-0001A` | P0 | DONE | root | `PrintLanguage::pushOp/pushAtom` invisible group 文本语义 | `src/prettyprint.rs`, `src/printlanguage.rs`, `docs/api/{prettyprint,printlanguage}.md`, `tests/oracle/printlanguage_group_1204.{cc,rs,metadata.json}`, `tools/run_printlanguage_group_oracle.sh`, `tests/oracle/fixture_registry.json`, `docs/TODO_BOARD.md` | evidence=`this commit`；锁定 12.0.4 `pushOp/pushAtom` 同输入 stdout direct diff：root unary/binary、无括号嵌套、必须括号嵌套 visible text 全部 `MATCH`；fixture overall=`UNTESTED`（exact TokenSplit group ID/queue）；curl 24 函数回归输出无变化，证明剩余 116 个 `(bVar);` 来自 terminal-branch 重发而非 invisible group | 2026-08-12 |
| `PRINT-RPN-0001B` | P0 | DONE | root | `PrintC::emitBlockBasic` terminal/no-branch 选择语义 | `src/printc.rs`, `docs/api/printc.md`, `tests/oracle/printc_terminal_1204.{cc,rs,metadata.json}`, `tools/run_printc_terminal_oracle.sh`, `tests/oracle/fixture_registry.json`, `docs/TODO_BOARD.md` | evidence=`this commit`；锁定 12.0.4 actual `PrintC::emitBlockBasic` 六场景 statement-selection/order direct diff=`MATCH`，raw text=`MISMATCH`（`(true)` vs `(vn_1)`），overall=`MISMATCH`；curl 24 函数中孤立 `(bVar);` 116→27，11.3.2 诊断 skeleton 2874→2747、defects/numbering 均0；三次新输出均27条但 SHA 不同且 gcc=8/10/10，非确定性另立 `PRINT-DETERMINISM-0001`；完整表达式/markup/CFG 单次发射仍归父项，模块保持 L2 | 2026-08-12 |
| `PRINT-RPN-0001C` | P0 | DONE | root | `PrintC::docFunction` → `PrintC::emitBlockGraph` 单次顶层遍历 | `src/printc.rs`, `docs/api/printc.md`, `tests/oracle/printc_blockgraph_1204.{cc,rs,metadata.json}`, `tests/oracle/printc_terminal_1204.metadata.json`, `tools/run_printc_blockgraph_oracle.sh`, `tests/oracle/fixture_registry.json`, `docs/TODO_BOARD.md` | evidence=`this commit`；锁定 12.0.4 actual `docFunction` 仅调用一次 `emitBlockGraph`，后者按 `getList()` 顺序逐项一次 virtual emit；fixture list-order/single-dispatch=`MATCH`、overall=`MISMATCH`（完整 docFunction 对象图未闭合）；curl 顶层 `do {` 16→8，`__libc_csu_init` 的 return 后重复 loop 消失，孤立 `(bVarN);` 27→26，11.3.2 诊断 skeleton 2747→2729–2730、defects/numbering=0；三次 SHA 仍不同且 GCC=10/9/10，继续绑定 `PRINT-DETERMINISM-0001`，模块保持 L2 | 2026-08-12 |
| `PRINT-DETERMINISM-0001` | P0 | READY | unassigned | PrintC 跨进程名称/调用目标输出非确定性 | `src/printc.rs`, `src/printlanguage.rs`, symbols/variable naming dependencies, paired API, locked oracle fixture, curl determinism runner, `docs/TODO_BOARD.md` | 由 `PRINT-RPN-0001B` 回归发现：同一 release binary、输入和选项连续三次 SHA 为 `9a1b43cf…/be4d5889…/7fb9b064…`，`hugehelp` 在 `FUN_35/puts` 与错误 `puts/local_35` 分配间漂移，gcc 8/10/10；先锁定 Ghidra `assignDefaultNames`/symbol traversal 的容器顺序与单一计数器，再对拍完整名称、调用目标、声明顺序和重复运行哈希；不得用 HashMap seed 或文本后处理稳定化 | 2026-08-12 |
| `PRETTY-0001` | P1 | BLOCKED | unassigned | TokenSplit/Oppen queue + semantic markup payload | `src/prettyprint.rs`, `src/printlanguage.rs`, API/oracle/differential | 依赖 `PRINT-RPN-0001`；保留 op/vn/type/field/case identity、spaces+bump、line-width break/indent | 2026-08-11 |
| `ARCH-0001` | P0 | BLOCKED | unassigned | production Architecture ownership/init/decode | `src/arch.rs`, Funcdata/Flow/CLI/examples/API/oracle | 依赖 `SPACE-0001` + `SLEIGH-0001` + `TYPE-0001`；必须安装 loader/types/userops/cpool/pcodeinjectlib，禁止裸 None 容器冒充接线 | 2026-08-11 |
| `USEROP-0001` | P0 | BLOCKED | unassigned | exact derived userop registry + Segment/JumpAssist consumers | `src/userop.rs`, `src/coreaction.rs`, API/oracle/differential | 依赖 `ARCH-0001`；全局 selector/name冲突、builtin flags、架构特定 segment execute、真实 ActionSegmentize | 2026-08-11 |
| `INJECT-0001` | P0 | BLOCKED | unassigned | payload decode/registry/temp allocation + Flow injection | `src/pcodeinject.rs`, `src/flow.rs`, `src/arch.rs`, API/oracle | 依赖 `ARCH-0001` + `USEROP-0001` + `OPBANK-0001`；CALL/CALLOTHER/entry/return 全路径有序注入，禁止 HashMap 首项 | 2026-08-11 |

### 已完成发现审计（本 wave）

- `cargo test --lib`：1292 passed / 0 failed / 3 ignored；`cargo check --lib` 通过。该证据只证明 Rugra 回归基线，不是 oracle parity。
- 注释门禁已收口：旧 scanner 初检 22 文件/249 项，fcc5142 后基线为 21 文件/247 项；
  修复 scanner 后又发现 85 项 const/extern/restricted/单行函数。当前 94 文件零违规。
- 门禁健康已修复：`core.hooksPath=.githooks`，两 hook 为 100755，ZCode 使用项目相对
  `python3` + `startup|resume`，Evidence 严格要求 4/4，CI 复跑锁定 oracle 全套门禁。
- 路线图至少 9 个模块存在“代码自承 stub/简化，但文档标 L3”的反证；未复核前不得沿用这些 L3 声明。
- `PcodeSnippet` 实测会接受缺失 `]`/`;` 的非法语句并返回成功；反例和完整修复边界见
  `docs/alignment_audit/PCODEPARSE_SYNTAX_2026-08-11.md`。
- Action executor/tree、callspec、Pcode flags/opcode protocol、SLEIGH、compression、multiprecision、ledger 与 gate 的
  确定性反例见 `docs/alignment_audit/FOUNDATION_PIPELINE_2026-08-11.md`；未带 runtime fixture 的项目保持
  `MISMATCH / NO_ORACLE`，不冒充 MATCH。
- Space/Address/SeqNum、Block、Varnode/PcodeOp、Cover、Database/Fspec、Marshal 与 TypeFactory 的底向上依赖图见
  `docs/alignment_audit/CORE_FOUNDATIONS_2026-08-11.md`；这些模块的历史 L3 已撤回。
- Heritage/CondExe/PathMeld/JumpTable、Print RPN/PrettyPrint、Architecture/UserOp/PcodeInject 的生产可达性与输出链审计见
  `docs/alignment_audit/CONTROL_OUTPUT_PIPELINES_2026-08-11.md`；无锁定同输入 fixture 的结论统一保持 `NO_ORACLE`。
- PackedDecode 的四位置状态机、嵌套 close/skip、typed error/EOF 与 raw string 反例见
  `docs/alignment_audit/MARSHAL_PACKED_2026-08-11.md`；现有 happy-path self-roundtrip 测试不构成 wire 证据。

---

## 当前阶段目标

### Phase A：文档可信化与索引修复

- [x] 重写根目录与 `rugra/` 子项目之间的文档边界说明，避免把工作区描述成不存在的主工程。
- [x] 为 `docs/` 建立清晰的文档索引，说明每个目录/文件的作用、适用范围、维护责任和更新触发条件。
- [x] 清理 README、状态报告、路线图、对齐报告中的夸大结论、未验证能力和过期叙述。
- [x] 统一“已实现 / 部分实现 / 计划中 / 未验证”的措辞标准，禁止混用。
- [x] 修复 API 文档总索引
中的失真描述，移除“与源码 1:1 完全同步”之类无法保证的表述。

### Phase B：事实核验与结论分级

- [x] 对照 `src/` 实际模块，逐项核对 README、`docs/PROJECT_STRUCTURE.md`、`docs/api/README.md` 中的模块清单。
- [x] 对照 `src/bin/rugra.rs` 真实状态，修正所有关于 CLI 已完整可用的描述。
- [x] 对照 `src/lib.rs` 当前公开接口，修正库入口、示例代码、API 文档中的过期接口说明。
- [x] 对照 `src/align/runtime_verify.rs` 当前实现情况，修正“已完成验证能力”与“仅有框架/占位实现”的界限。
- [x] 对照现有测试与示例，重写“生产可用”“完全一致”“端到端已解决”等高风险结论。

### Phase C：维护流程固化

- [x] 建立"修改代码时必须同步检查哪些文档"的最小清单。
  - [x] 已新增 `docs/workflow/CODE_CHANGE_CHECKLIST.md`（2026-04-24）
- [x] 为新增/删除/重命名模块制定文档更新流程。
  - [x] 已纳入 `CODE_CHANGE_CHECKLIST.md` 的"必查项"表格
- [x] 为状态类文档增加"证据来源"要求：每个关键结论必须能回溯到代码、测试、示例或验证记录。
  - [x] 已在 `CODE_CHANGE_CHECKLIST.md` 建立证据来源规则和格式模板
  - [~] 为 `CURRENT_STATUS.md` 增加"证据来源 / Evidence Sources"段落或统一模板
  - [~] 为 `ALIGNMENT_PROGRESS.md` 增加"证据来源 / Evidence Sources"段落或统一模板
  - [~] 为 `docs/VERIFICATION_GUIDE.md` 增加"证据来源 / Evidence Sources"段落或统一模板
  - [x] 统一高风险结论的引用格式（代码 / 测试 / 示例 /日志 / 实验记录）
- [x] 为后续会话建立统一的文档审计模板，避免再次出现系统性失真。
  - [x] 已纳入 `CODE_CHANGE_CHECKLIST.md` 的"会话结束检查清单"
- [~] 为恢复 Ghidra 对齐工作建立“最小 P-code 对拍重入计划”，优先从单条指令 / 小型指令序列开始，而不是直接回到端到端大样本。
  - [x] 已确认最小闭环入口：`x86_lift.rs -> pcoderaw.rs -> funcdata.rs -> runtime_verify.rs -> ffi.rs`
  - [x] 已确定第一批最小指令样本优先级：
    - [x] `mov`
    - [x] `add`
    - [x] `sub`
    - [x] `and/or/xor`
    - [x] 简单 `cmp/jcc`
    - [x] 简单位移
  - [~] 为第一批样本建立可复现的输入/输出记录模板
    - [x] 定义统一字段：指令/序列、原始字节、Rugra 入口、Rugra 结果、参考结果、差异分类、当前层级、下一步修复点
    - [x] 已为 3 条首批样本建立模板化记录草案：`mov rbx, rax`、`add rax, 1`、`sub rax, 8`
    - [x] 已把 `mov rbx, rax` 推进成第一条最小可执行对拍记录说明
    - [x] 为 `mov rbx, rax` 补首条真实运行记录填写清单
    - [x] 继续把 `mov rbx, rax` 补成第一条真实运行记录
      - [x] 已新增最小测试：`funcdata::tests::test_mov_reg_reg_minimal_alignment_path`
      - [x] 已确认样本输入：机器码 `48 89 c3`，起始地址 `0x1000`
      - [x] 已确认 Rugra 路径：`disasm -> x86_lift -> inject_raw_ops -> verify_pcode_generation`
      - [x] 已确认当前结果：测试执行通过，`CPUI_COPY`、`rbx <- rax`、单 op、单 block
      - [x] 已确认当前限制：`verify_pcode_generation(...)` 仍使用框架级占位比较，执行时出现 `[RUGRA DIFF] 0x1000: Opcode mismatch. Ghidra Op: 0, Rugra has 1 ops here`
      - [x] 已把当前 Rugra op 的真实 opcode / 输出 varnode / 输入 varnode 列表传入比较入口，不再使用 `null inputs + 仅 input_count` 的占位调用
      - [x] 已让 `verify_pcode_generation(...)` 基于结构化局部比较结果返回 `Match` / `Mismatch(...)`，不再无条件返回 `VerifyResult::Match`
      - [x] 已让 FFI 比较入口返回结构化状态码，至少区分：`match`、`opcode mismatch`、`output mismatch`、`input count mismatch`、`input mismatch`、`missing Rugra op`
      - [x] 已让 `verify_pcode_generation(...)` 消费 FFI 结构化状态，不再只依赖 stdout 日志副作用
      - [x] 已开始第二条最小样本：`add rax, 1`
      - [x] 已新增最小测试：`funcdata::tests::test_add_rax_imm_minimal_alignment_path`
      - [x] 已确认样本输入：机器码 `48 83 c0 01`，起始地址 `0x1000`
      - [x] 已确认当前 Rugra lifting 结果：`INT_ADD` + `COPY`，共 `2` 条 op
      - [x] 已确认当前失败现象：最小测试执行失败，日志出现 `Opcode mismatch. Ghidra Op: 4` 与 unique 输入比较失败
      - [x] 已让 raw P-code 在 lifting 后补齐 `SeqNum(order)`，为同地址多 op 比较建立顺序基础
      - [x] 已把 FFI 比较入口从“仅按地址匹配”推进到“按地址 + `SeqNum.order` 匹配”
      - [x] 已开始函数级批量语义对齐骨架：新增 `src/align/function_snapshot.rs`
      - [x] 已为函数级语义快照建立核心结构：
        - [x] `FunctionSemanticSnapshot`
        - [x] `PcodeSnapshot`
        - [x] `CfgSnapshot`
        - [x] `SsaSnapshot`
        - [x] `BatchSemanticCompareReport`
      - [x] 已支持从 `Funcdata` 导出 Rugra 侧函数语义快照
      - [x] 已将 `function_snapshot` 接入 `align` 模块
      - [x] 已确认函数级快照基础测试通过：
        - [x] `align::function_snapshot::tests::test_snapshot_from_funcdata_basic`
        - [x] `align::function_snapshot::tests::test_batch_report_counts`
      - [~] 下一步：
        - [x] 已修正 `add rax, 1` 参考 opcode 来源错误（新增 `ffi::to_ghidra_opcode()`，修复 `verify_opcode()` 使用 `map_ghidra_opcode`）
        - [x] 已修正 unique 临时值输入的比较策略（`align/varnode.rs`、`ffi.rs`、`runtime_verify.rs` 均跳过 unique offset 精确比较）
        - [x] 已修正 space_id FFI 映射不一致（新增 `ffi::space_to_ffi_id()`）
        - [x] `add rax, 1` 测试已通过
        - [x] 已新增第三条最小样本 `sub rax, 8` 并验证通过
        - [x] 全部 138 测试通过，0 失败（2026-04-24）
        - [x] 在函数级快照骨架上补批量 runner 与导出流程
          - [x] 已补单函数快照 compare 入口
          - [x] 已补按函数入口地址配对的批量 compare runner
          - [x] 已补缺失 Rugra / 参考函数快照的批量差异记录
          - [x] 已细化各语义层差异明细：新增 `diff_pcode_ops()` / `diff_cfg_blocks()` / `diff_ssa_varnodes()`（2026-04-25）
        - [~] 真实 Ghidra 参考侧接入
          - [x] 已设计 Ghidra 侧 JSON 快照导出格式规范：`docs/method/ghidra_snapshot_format.md`
          - [x] 已创建手工示例 JSON：`docs/method/impl/ghidra_export_example.json`
          - [ ] 需要真实 Ghidra 环境验证导出脚本
        - [~] 内存指令（LOAD/STORE）对拍
          - [x] `mov rax, [rbx]` — LOAD + COPY（2026-04-25）
          - [x] `mov [rbx], rax` — STORE（2026-04-25）
          - [x] `mov rax, [rbx+0x10]` — INT_ADD + LOAD + COPY（2026-04-25）
          - [x] `add [rbx], rax` — LOAD + INT_ADD + STORE（2026-04-25）
        - [~] SSA 对拍
          - [x] SSA 单块线性测试 — 无 Phi 节点验证（2026-04-25）
          - [x] 修复 `Heritage` 的 `place_multiequals` 在处理不同 AddressSpace 但 offset 相同的 Varnode 时错误合并的问题（使用 `(AddressSpace, Address)` 复合键）
          - [x] 发现 heritage() deadlock，并已新增 `Funcdata::run_heritage_direct()` API 从架构层规避
          - [x] SSA 双块 Phi 测试（dominator tree 已就绪，已验证 `MULTIEQUAL` 节点按预期生成并落入 `Register` 空间）
          - [x] 修复 `rename_direct` 的 AddressSpace 碰撞 bug：将 stack key 从 `Address` 改为 `(AddressSpace, Address)` 复合键，与 `place_multiequals_direct` 保持一致（2026-05-09）
          - [x] SSA renaming 验证测试完成（2026-05-09）：
            - [x] 单块线性 renaming：验证 op 输入被正确重写为前序定义的 Varnode（`test_ssa_rename_single_block_linear`）
            - [x] 多块 Phi 输入填充：验证 MULTIEQUAL 输入从前驱块定义正确填充（`test_ssa_rename_multi_block_phi_inputs`）
            - [x] 菱形 CFG（if-then-else 合并）：验证 Phi 输入引用正确分支定义（`test_ssa_rename_diamond_pattern`）
            - [x] INPUT varnode 回退：未定义寄存器读取使用 INPUT varnode（`test_ssa_rename_input_varnode_for_undefined_read`）
          - [~] 下一步：SSA renaming 跨图验证（Ghidra 侧参考数据接入后）
          - [x] ActionNormalizeBranches 实现（2026-05-09）：
            - [x] 新增 `edge_flags` 模块（block.rs）：F_BREAK_EDGE / F_CONTINUE_EDGE / F_GOTO_EDGE
            - [x] 新增 `branch_type` 模块（op.rs）：PcodeOp.branch_type 字段，支持 NONE/BREAK/CONTINUE
            - [x] 增强 `collapse_loops`（blockaction.rs）：新增自然循环检测，支持多块循环体
            - [x] 实现 ActionNormalizeBranches（blockaction.rs）：标记 BRANCH/CBRANCH 为 break/continue
            - [x] 更新 PrintC（printc.rs）：根据 branch_type 输出 break/continue 而非 goto
            - [x] 新增 2 项测试，全部 159 测试通过（原 157 + 新增 2），0 回归
          - [x] Boolean Condition Folding 实现（2026-05-09）：
            - [x] 新增 `BlockCondition` 结构体（block.rs）：BoolOp::And / BoolOp::Or，first/second 子块
            - [x] 新增 `collapse_bool_conditions` pass（blockaction.rs）：Ghidra ruleBlockOr 等价实现
            - [x] 集成到 CollapseStructure.collapse_all（Pass 3），介于 collapse_conditions 和 collapse_sequences 之间
            - [x] PrintC 支持 BlockCondition 输出（printc.rs）：emit_block_condition 递归发射 (a) && (b) / (a) || (b)
            - [x] 新增 2 项测试，全部 161 测试通过（原 159 + 新增 2），0 回归
          - [x] HighVariable 寄存器命名初步实现（2026-05-09）：
            - [x] merge.rs 新增 `register_name()` 函数：根据 Varnode 的 offset 和 size 返回 x86-64 寄存器名（RAX, RDI, RSI 等）
            - [x] merge.rs `assign_names()` 使用 register_name 为 Register 空间的 HighVariable 生成人类可读名称
            - [x] curl 反编译输出从 uVarN 改为 RAX、RDI、RSI 等真实寄存器名
          - [x] CBRANCH-latch 循环检测初步实现（2026-05-09）：
            - [x] blockaction.rs `detect_cbranch_loops()` 新增：检测以 CBRANCH 结尾的 latch 块回边模式
            - [x] 真实 curl 二进制中成功检测出 do-while 循环
          - [x] ActionFinalStructure 初步实现（2026-05-09）：
            - [x] op.rs 新增 GOTO 常量（PcodeOp 操作码）
            - [x] blockaction.rs 新增 `tag_gotos()` 和 `remove_dead_code()`
            - [x] tag_gotos：将无法结构化的 BRANCH/CBRANCH 标记为 GOTO
            - [x] remove_dead_code：清除 BRANCH 后的不可达代码
            - [x] 全部 161 测试通过，0 回归
          - [x] Expression inlining for Unique-space temps（2026-05-09）：
            - [x] printc.rs: 新增 `inline_candidates` map，在 `doc_function` 中通过 use-count 分析构建
            - [x] printc.rs: 新增 `emit_inline_expr` 方法，递归发射 RHS 表达式
            - [x] printc.rs: `push_varnode` 检查 `inline_candidates`，命中则内联表达式而非输出 `uVar_xxx`
            - [x] printc.rs: `get_varnode_display_name` 对 inline candidates 返回空（不生成声明）
            - [x] 结果：curl 输出中 0 个 Unique-space `uVar_xxx` 残留（全部内联为表达式）
            - [x] 161 测试通过，0 回归
          - [x] Pointer type inference improvements（2026-05-09）：
            - [x] coreaction.rs: ActionTypeInfer LOAD/STORE 地址输入现在覆写非指针类型
            - [x] printc.rs: 声明类型解析优先选择指针类型而非 int
            - [x] 结果：curl 输出声明中可见 `void *` 和 `int *` 类型
          - [x] While-do loop detection verified（2026-05-09）：
            - [x] 基础设施已存在（3-phase collapse_loops）
            - [x] curl main loop 过于复杂，当前模式无法匹配（需要 interval analysis — 后续工作）
- [x] 为 `docs/api/` 建立统一文档状态标签规则。
- [x] 为历史会话日志建立复核提示策略与使用口径。
- [~] 将复核提示策略逐步回填到历史日志文件。
  - [x] 已为首批高风险历史日志补充或统一复核提示：
    - [x] `docs/AgentLog/engineering_progress_2026-03-07_api_docs_completion.md`
    - [x] `docs/AgentLog/engineering_progress_2026-03-08_zero_codegen_pipeline_resolved.md`
    - [x] `docs/AgentLog/engineering_progress_2026-03-08_output_refinement_and_quality.md`
  - [ ] 继续覆盖剩余高风险历史日志

---

## P0：最高优先级任务

- [x] **修复 `README.md` 的现状描述**
  - [x] 删除与当前代码不符的完整产品化叙述
  - [x] 明确区分“项目目标”和“当前仓库状态”
  - [x] 标注 CLI 当前受限/临时禁用事实
  - [x] 重新整理“已实现能力”与“开发中能力”

- [x] **修复 `docs/PROJECT_STRUCTURE.md`**
  - [x] 基于当前真实目录树重写模块说明
  - [x] 去除不存在或过时的 `analysis/`、`codegen/`、`pcode/`、`translator/` 主体叙述（若当前源码目录并不直接对应）
  - [x] 补齐 `align/`、`disasm/`、`type_system/`、`bin/` 等现存目录的职责说明
  - [x] 增加文档索引入口，说明 `docs/` 下各目录用途

- [x] **修复 `CURRENT_STATUS.md`**
  - [x] 去除未经证实的完成度与可靠性数字
  - [x] 去除与日期、版本、阶段不匹配的乐观结论
  - [x] 重新定义“已验证”“仅静态对齐”“仅框架存在”“待实测”四级状态
  - [x] 将“当前能做什么、不能保证什么”写清楚

- [x] **修复 `ALIGNMENT_PROGRESS.md`**
  - [x] 清理自相矛盾内容，例如一边写“运行时验证 0%”，一边又写“已保障一致性”
  - [x] 将静态结构对齐、运行时验证框架、真实 FFI 集成、端到端语义比对分层记录
  - [x] 所有勾选项必须以代码或测试证据为基础

- [x] **修复 `docs/api/README.md`**
  - [x] 改为“API 文档目标与当前维护状态说明”
  - [x] 不再宣称自动完整同步
  - [x] 明确哪些目录/文档可能已经过期，哪些应优先校正
  - [x] 增补统一状态标签规则

- [x] **建立 `docs/README.md` 总索引**
  - [x] 为 `docs/` 提供统一入口
  - [x] 说明阅读顺序与使用场景
  - [x] 区分总控文档、API 文档、对齐文档、实验文档、工程日志

---

## P1：高优先级任务

- [ ] **全面审计 `docs/api/`**
  - [ ] 核对每个 API 文档是否仍对应真实源文件
  - [x] 将高风险旧目录页统一降级为“历史遗留 / 待复核”口径
  - [x] 修复 `lib.md` 中对 `Decompiler` 等已注释/已停用接口的描述
  - [x] 为 `docs/api/README.md` 补充统一状态标签规则：
    - `已核对（当前有效）`
    - `部分有效（需对照源码）`
    - `历史遗留（仅供参考）`
    - `明显过期（待重写）`
  - [~] 按新标签体系逐页补齐状态标记
    - [x] 当前主线高风险 API 页面已基本补齐显式状态标签
    - [ ] 继续检查并补齐剩余低风险或边缘页面
  - [ ] 清点并标记仍未处理的遗留目录与子页
  - [~] 建立主线文档清单与历史文档清单两份索引视图
    - [x] 已完成双索引结构设计与清单范围梳理
    - [x] 已将双索引正式写入 `docs/api/README.md`
  - [~] 设计最小 P-code 对拍重入路径
    - [x] 已明确 `x86_lift.rs -> pcoderaw.rs -> funcdata.rs -> runtime_verify.rs -> ffi.rs` 的最小闭环
    - [x] 已固定第一批“单条指令 / 小型指令序列”样本方向，不直接扩大到端到端样本
    - [~] 为第一批对拍结果约定记录格式：输入、Rugra 结果、参考结果、差异分类
      - [ ] 将记录格式补成统一模板
      - [~] 先落首批 3 条样本的模板化记录
        - [x] `mov rbx, rax` 已从草案推进为首条真实运行记录，并补到结构化局部比较返回与 FFI 状态消费
        - [~] `add rax, 1`
          - [x] 已新增最小测试与失败记录
          - [x] 已确认当前 Rugra 侧为 `INT_ADD` + `COPY`
          - [x] 已确认当前仍未通过最小局部验证
          - [x] 已补 `SeqNum(order)` 并切换到按地址 + order 的比较路径
          - [x] 当前问题已修复（2026-04-24）：
            - [x] 参考 opcode 来源错误 → 新增 `ffi::to_ghidra_opcode()`
            - [x] unique 输入比较策略不合理 → 三处跳过 unique offset
            - [x] space_id FFI 映射不一致 → 新增 `ffi::space_to_ffi_id()`
        - [x] `sub rax, 8` — 测试已通过（2026-04-24）
      - [~] 建立函数级批量语义对齐骨架
        - [x] 已新增函数级语义快照模块：`src/align/function_snapshot.rs`
        - [x] 已定义函数级批量对齐所需的核心快照/报告结构
        - [x] 已支持从 `Funcdata` 导出 Rugra 侧函数语义快照
        - [x] 已补基础测试并确认通过
        - [x] 下一步补批量 runner
        - [x] 已设计 Ghidra 侧数据导出约定（2026-04-25）：`docs/method/ghidra_snapshot_format.md`

- [x] **修复 `docs/VERIFICATION_GUIDE.md`**
  - [x] 区分“可以直接运行的验证”“需要环境准备但尚未打通的验证”“仅为计划/示例的验证”
  - [x] 删除将伪代码/示意脚本写成现成流程的表述
  - [x] 明确当前验证链路的真实阻塞点

- [x] **补作文档索引页**
  - [x] 在 `docs/` 下新增总索引文件
  - [x] 汇总：
    - [x] 核心状态文档
    - [x] API 文档
    - [x] 对齐文档
    - [x] 实验与方法文档
    - [x] 工程日志
  - [x] 说明阅读顺序与使用场景

- [ ] **统一术语**
  - [ ] 统一使用：
    - [ ] 静态对齐
    - [ ] 运行时验证框架
    - [ ] FFI 集成
    - [ ] 端到端示例
    - [ ] 生产可用性
    - [ ] 历史遗留
    - [ ] 待复核
    - [ ] 已核对（当前有效）
  - [ ] 避免“打通”“完成”“可用”在不同文档中表达不同含义

---

## P2：中优先级任务

- [x] 审核 `docs/data_contract.md`，补充最基础的数据契约说明，至少覆盖：
  - [x] `Address`
  - [x] `Varnode`
  - [x] `PcodeOp`
  - [x] `Funcdata`
  - [x] `PrintC` 输出阶段的输入约束

- [~] 审核 `docs/AgentLog/` 历史日志，给明显失真的日志增加“按当时记录，尚待复核”提示。
  - [x] 已完成首批高风险日志复核提示落地
  - [ ] 继续扩展到剩余历史日志
- [ ] 为 `docs/branches/` 建立最小状态记录规范，避免该目录空转。
- [ ] 为 `docs/method/`、`docs/experiments/` 补充“引用真实实验或代码依据”的要求。
- [ ] 清理仓库中明显属于调试残留但被文档错误当作正式产物引用的文件说明。
- [ ] 把历史日志复核策略沉淀到单独规范文档或模板补充说明中。
- [ ] 为状态类文档建立统一的“证据来源 / Evidence Sources”写作规则，并沉淀到规范文档中。

---

## 文档修复判定标准

以下条件全部满足，才能认为“文档失真修复”阶段基本完成：

- [x] 根目录文档与 `rugra/` 实际工程定位一致
- [x] README 不再把目标态写成现状
- [x] 项目结构文档与真实目录结构一致
- [x] 状态/进度文档不再自相矛盾
- [x] API 文档索引不再声称绝对同步
- [x] 验证文档明确区分“已实现”“可运行”“待集成”“计划中”
- [x] 至少建立一份清晰可用的 `docs/` 总索引
- [~] 所有高风险结论都能指出代码或测试依据
  - [ ] `CURRENT_STATUS.md` 已建立证据来源回链
  - [ ] `ALIGNMENT_PROGRESS.md` 已建立证据来源回链
  - [ ] `docs/VERIFICATION_GUIDE.md` 已建立证据来源回链
- [~] API 文档状态标签已覆盖主要高风险页面
- [ ] 旧架构文档已系统性标注为历史说明或完成重写
- [~] 历史日志已具备统一复核提示机制

---

## 暂缓事项

以下事项不是当前阶段的第一优先级，应在文档可信化完成后再系统推进：

- [ ] 新功能扩展（除非为修正文档失真必须先核实代码）
- [ ] 新架构支持
- [ ] 大规模重构
- [ ] 对外宣传材料撰写
- [ ] 新一轮“与 Ghidra 完全一致”的结果宣称

---

## 历史日志复核提示策略

为避免旧日志继续被误当成当前事实，后续审阅 `docs/AgentLog/` 时应遵守以下口径：

### 适用条件
如果历史日志中出现以下情况之一，应补“复核提示”：

- 把阶段性结果写成最终完成
- 把局部样例成功写成整体能力成熟
- 把静态结构对齐写成运行时一致
- 把旧架构写成当前主线
- 把 CLI/验证/输出质量写得明显超出当前可证实范围

### 推荐提示语
建议使用类似表述：

- “按当时记录，尚待按当前代码状态复核”
- “该结论反映当时阶段性判断，不应直接视为当前事实”
- “该条目涉及旧架构口径，需结合当前总控文档重新理解”

### 使用原则
- 不删除历史日志原文
- 不事后篡改历史过程结论
- 通过补充说明降低误导风险
- 以当前总控文档和源码状态为准重新解释历史记录

---

## 最近完成

- [x] 变量声明重构与反编译质量质量提升（2026-05-23）：(1) **变量声明重构** — 废弃原本基于 AST op-scanning 的局部变量声明机制，改为在 Discovery Pass（Pass 1）中使用 `used_varnode_types` 映射收集所有实际被打印的变量名、空间、偏移及类型，并在函数开头进行声明；(2) **未声明 Register/Unique 变量修复** — 允许声明变量化了的寄存器变量（如 `lVar_a8`），支持声明由于 DCE 消除定义后悬空使用的 Unique 临时变量（如 `uVar_a0`）；(3) **非标识符声明过滤** — 过滤包含 `->`、`.` 等非合法 C 标识符字符的名字（如 `struct2->field_8`），确保仅声明基址；(4) **Puts 字符串解析** — 改用 lossy UTF-8 扫描跳过对齐 NULL padding 恢复 3 处 hugehelp 字符串；(5) **puts()) 多余括号修复** — 增加 pass 15 消除多余右括号。所有 168 个测试通过，未声明变量全部消除，C 语法正确性获得飞跃。

- [x] 反编译出力品質改善 v36→v39（2026-05-22 夜）：(1) **位运算常量修复** — push_varnode 在 XOR/AND/OR/SHIFT 上下文中跳过字符串解析，`*DAT ^ "huge_string"` → `*DAT ^ 0x400000`；(2) **未使用变量清除** — prettyprint.rs 第十一趟 pass 扫描声明行变量名是否在函数体引用，uVar 声明 75→30（-60%）；(3) **空 else 空行清除** — 第十二趟 pass 删除 `} else {` 后空行，17→0；(4) **return void() 拆分** — 第十三趟 pass 将 `return free()` 拆为 `free(); return;`，2→0；(5) **连续 goto 死代码** — 第十四趟 pass 删除 goto 后的 goto，1→0；(6) **fwrite 签名修正** — 3→4 参数，显示 `*stderr` 第四参数；(7) **字符串扫描改进** — .rodata 扫描接受 \n\t\r 开头字符串，部分 hugehelp puts 恢复；(8) **字符字面量格式** — ASCII 字母/常用标点显示为 `'/'`、`'='`，数字/符号保持 hex；(9) **长字符串截断** — 超过 80 字符的字符串截断为 60+`(continues)`。总行数 926→865（-7%），声明 75→30。168 测试通过。
- [x] 反编译输出三大结构性问题修复 v32→v35（2026-05-22）：(1) **if-no-body 修复** — `BlockType::Condition` 顶层处理器从错误的 `if(compound_cond)` 无 body 输出改为递归展开子块，0/4 处消除；(2) **函数参数缺失修复** — 恢复 CBRANCH 作为后向搜索停止条件（避免跨分支路径错误拾取寄存器写入），新增首调用入口回退搜索（函数入口参数传递），扩展签名数据库（fputc/curl_slist_free_all/_init 等），无参调用 15→9；(3) **getparameter 死代码消除** — prettyprint.rs 新增第十趟 pass，检测 `return;`/`break;`/`continue;` 后相同缩进级别的不可达代码（排除标签/case），死代码 11→0、getparameter 行数 295→251、return 数 41→33。无回归（fclose 等不出现错误参数），168/168 测试通过，24/24 函数反编译成功。
- [x] 反编译输出质量综合改进 v24→v28（2026-05-22）：(1) 返回类型推断——扫描 RAX 写入推断 int/long，23→7 void（-70%）；(2) 字符串常量解析——.rodata 子串查找，`0x62f8`→`"--"`；(3) switch 条件变量——CBRANCH cascade 比较操作数提取，5→1 空 switch（-80%）；(4) case 字符格式——`case 45:`→`case '-':`；(5) 变量内联扩展——Register 空间单次使用 varnode 内联，uVar 引用 582→502（-14%）；(6) goto 消除——"exit label"检测+替换为 break/return，goto 135→66（-51%）。所有 168 测试通过，24/24 函数反编译成功。
- [x] ActionCallParams 函数签名数据库 + 常量显示改进 + 作弊代码清除：(1) `known_param_count()` 标准 libc 类型库映射约 80 个常见 C/libc 函数的已知参数数量，未知函数默认 6（SysV AMD64 全部参数寄存器）；(2) CALL ops 按签名裁剪参数——0 参数函数无参数、1 参数函数精确 1 个参数；(3) 间隙处理从遇首个间隙停止改为收集到最后找到的参数并插入占位 Register varnode；(4) 常量 >= 256 显示 `0x2726 /* 10022 */` 格式；(5) 高位置位常量显示有符号值（`-1`）；(6) 删除 `curlopt_name()`、`known_global_name()`、`curl_setopt_arg_index` 等二进制特定硬编码。全部 168 测试通过。（2026-05-21 深夜）
- [x] 反编译质量批量修复 (10 项中 7 项完全解决, 2 项改善, 1 项未动)：(1) 空 if/else 死代码块消除 — `is_block_body_empty()` + `seen_return` 守卫 + 空 true 分支条件取反；(2) continue 外循环抑制 — `loop_depth` 跟踪；(3) 函数签名回退检测 — 扫描 SysV ABI 寄存器读取；(4) 大函数栈帧检测 — INT_ADD 二进制补码 + alivelist 回退；(5) RSP STORE → `local_XX`；(6) 全局符号解析 → `*config`；(7) 参数命名 → `param_N`；(8) SSA def chain 回退到 `try_fold_bool_comparison`；(9) getparameter 声明 100→41。效果：998→920 行, 0 空块, 0 非法 continue, 18/18 函数有签名。168 测试通过。（2026-05-21）
- [x] SSA def-use chain 完整集成 + 结构体字段聚合：(1) `get_defining_op` 使用 `Varnode.def` 追踪 SSA 定义链，作为 `emit_condition` 的首选策略（Strategy 0）；(2) 修复 legacy if/else 代码路径，改用 `emit_block_condition` 确保与 BlockIf 一致的条件解析；(3) BOOL_OR/BOOL_AND 的操作数改为递归 `emit_condition`，配合 `try_fold_bool_comparison` 恢复 `argc <= 1`；(4) 新增 `StackStruct` 模型，从 `INT_ADD(RSP, const)` → COPY → Register 模式检测函数参数中的栈结构体基址；(5) `get_stack_variable_name` 优先匹配检测到的结构体范围，发射 `config.field_XX`。效果：`if(uVar99)` → `if(uVar194 == 0)`，`if(uVar156)` → `if(uVar194 != 0)`，`&local_1f0` → `&config`。全部 168 测试通过。（2026-05-21）
- [x] 栈帧分析模型 + 栈变量命名 + 帧基址解析 + SSA-aware 条件解析：(1) `stack_frame_size` 从 `INT_SUB(RSP, const)` 检测栈帧大小；(2) `get_stack_variable_name` 将 `RSP + offset` 转换为 `&local_XX`（Ghidra 风格命名）；(3) `stack_frame_base_key` 追踪帧基址 varnode，将 `uVar107 + 0x218` 解析为 `local_10`；(4) `comparison_def_map` 仅存储比较/布尔 ops，不被后续非比较 ops 覆盖；(5) do-while 条件从 `push_varnode` 改为 `emit_condition`；(6) `def_map` 扩展到 block-level ops。效果：`RSP + 0x38` → `&local_1f0`，`uVar107 = RSP - 0x228` 消除，`while(uVar99)` → `while(uVar194 == 0)`，变量 8 → 7 个。全部 168 测试通过。（2026-05-21）
- [x] 布尔表达式简化 + 跨块 DCE + 寄存器名消除 + CALL 参数深度解析：(1) `try_fold_bool_comparison` 将 `BOOL_OR(INT_EQUAL(A,B), INT_LESS(A,B))` 折叠为 `A <= B`，用 pointer-based def_map 精确匹配；(2) 全局 `global_used_outputs` 跨所有基本块检测死输出；(3) RIP-relative INT_ADD 在 emit_block_ops 级别跳过；(4) `is_raw_register_name` 检测 HighVariable 中的 x86-64 寄存器名，转换为 `lVar_b0`/`iVar_0` 风格的局部变量名（RSP/RBP 保留）；(5) op_call 的 COPY 源增加 RIP-relative 深度解析。效果：`uVar99 || uVar100` → `argc <= 1`，`R14` → `lVar_b0`，`EAX` → `iVar_0`，声明 17 → 8 个。全部 168 测试通过。（2026-05-21）
- [x] 常量折叠 + Def Chain Resolution + 扩展 DCE + argc/argv 映射：(1) 跳过 Const 空间 HighVariable 命名，常量直接显示数值；(2) Priority 1.5 通过 value_def_map 追踪 Register/Unique uVar 的定义链，解析 COPY(Const)、COPY(Unique → RIP-relative)、直接 RIP INT_ADD；(3) is_lhs guard 防止输出端折叠；(4) main() 自动映射 argc/argv；(5) 扩展 DCE 到所有纯计算 opcode；(6) uVar 声明裁剪只从输入端触发。效果：变量声明 75 → 17 个，代码行数 ~93 → ~62 行，`EDI == 1` → `argc == 1`。全部 168 测试通过。（2026-05-21）
- [x] CALL 参数解析 (P2)：在 op_call 中添加 Register 参数的 def chain 追踪，通过 value_def_map 找到 COPY 源并 inline。将 Register-space COPY 纳入 value_def_map。`curl_version(RDI)` → `curl_version(uVar193)` 现在展示实际计算值而非寄存器名。全部 168 测试通过。（2026-05-21）
- [x] 变量声明精简 (P1)：排除所有 Register 空间和 Ram/Const 空间（全局符号）的 varnode 从变量声明。75 → 35 个变量声明。全部 168 测试通过。（2026-05-21）
- [x] RIP-relative 地址折叠 (P0)：新增 `get_rip_relative_operand` 辅助方法检测 `INT_ADD(RIP, x)` 模式，在 `op_binary`、`emit_inline_expr`、`op_store` 三处添加 RIP 折叠。全部 168 测试通过。（2026-05-21）
- [x] If-else 结构化 + 反编译质量优化：(1) 参数名优先级提升（param_names > HighVariable），(2) CALL 从 block terminator 移除，(3) skip_terminal 无条件跳过 branch ops，(4) BlockIf body 使用 skip_terminal=true，(5) E2E 测试重构为 14-op 4-block diamond CFG。输出从 `goto LAB_xxx` 提升到完整 `if/else` 结构。全部 168 测试通过。（2026-05-21）
- [x] INPUT varnode 标记修复 + Pipeline 重排序：`inject_raw_ops` 新增 Phase 3 自动标记未定义的寄存器读取为 INPUT；将 `ActionInferParams` 移到 `ActionHeritage` 后、`ActionCopyPropagate` 前，避免 COPY 传播消除参数寄存器。curl_easy_setopt 现在输出 `long curl_easy_setopt(long param_1, int param_2, long param_3)`。全部 168 测试通过。（2026-05-21）
- [x] 参数名称传播：在 PrintC 中实现了寄存器偏移→参数名称映射（`param_names`），表达式中使用 `param_1` 而非 `RDI`，变量声明中跳过已在签名中声明的参数。全部 167 测试通过。（2026-05-21）
- [x] 函数签名恢复（ActionInferParams）：实现了从 INPUT varnodes 和 RETURN ops 中自动检测函数参数和返回类型。将 FuncProto 集成到 Funcdata，升级 PrintC 的函数头部发射从硬编码改为原型驱动。全部 166 测试通过。（2026-05-21）
- [x] PrintC 类型转换集成：将 `CastStrategyC` 集成到 `PrintC`，实现 LOAD/STORE 类型感知解引用（`*(type *)addr`）、ZEXT/SEXT 类型感知 cast（使用推断出的实际类型名替代硬编码 `(uint)`/`(int)`）。修复了 `test_type_propagation` 的 RwLock 死锁。更新了 `coreaction.md` API 文档。全部 163 测试通过。（2026-05-21）
- [x] 迭代类型恢复引擎与测试对齐验证：重构了 `ActionTypeInfer` 为基于收敛性数据流的双向类型传播引擎，引入基础 Opcode、COPY 传播、ADD/SUB 偏移、LOAD/STORE 解引用以及 Phi 节点等规则，配合 post-pass size 兜底，完美通过了 `test_type_propagation` 单元测试及全局 163 个单元测试。（2026-05-21）
- [x] switch-case 检测与生成初步实现：在 `block.rs` 实现了 `BlockSwitch`，在 `blockaction.rs` 引入了 `collapse_switches` 折叠 Pass，在 `printc.rs` 实现了 `BlockType::Switch` 的 C 语言打印支持，并在 `funcdata.rs` 补齐了闭环单元测试。（2026-05-21）
- [x] HighVariable 寄存器命名初步实现：merge.rs 新增 `register_name()` + `assign_names()` 使用寄存器名，curl 输出从 uVarN 改为 RAX/RDI/RSI 等（2026-05-09）
- [x] CBRANCH-latch 循环检测初步实现：blockaction.rs 新增 `detect_cbranch_loops()`，真实 curl 二进制检测出 do-while 循环（2026-05-09）
- [x] ActionFinalStructure 初步实现：op.rs 新增 GOTO 常量，blockaction.rs 新增 `tag_gotos()` + `remove_dead_code()`，清除 BRANCH 后不可达代码（2026-05-09）
- [x] 修复 `heritage.rs` 中 `rename_direct` 的 AddressSpace 碰撞 bug，stack key 从 `Address` 改为 `(AddressSpace, Address)`（2026-05-09）
- [x] 完成 SSA renaming 验证：4 项测试覆盖单块 renaming、多块 Phi 输入填充、菱形 CFG Phi 验证、INPUT varnode 回退（2026-05-09）
- [x] 更正根目录 `AGENTS.md`，将错误的 RustVSR 项目描述改为与 `rugra/` 实际工程一致的说明。
- [x] 明确后续文档维护默认以 `rugra/` 子项目为核心，避免继续围绕不存在的顶层主工程写作。
- [x] 为 `mov rbx, rax` 补出第一条最小真实运行记录：已新增 `funcdata::tests::test_mov_reg_reg_minimal_alignment_path`，确认 `48 89 c3 -> mov rbx, rax -> CPUI_COPY -> inject_raw_ops(...)` 的最小链路可执行。
- [x] 已把该样本从“框架级占位比较”推进到“Rugra 侧结构化局部比较”：`verify_pcode_generation(...)` 现会传入真实 opcode、输出 varnode、输入 varnode 列表，并按结构化比较结果返回 `VerifyResult::Match` / `VerifyResult::Mismatch(...)`。
- [x] 已让 `rugra_compare_pcode(...)` 从 stdout-only 入口升级为“stdout + 结构化状态码返回”，并把该状态回传给 `verify_pcode_generation(...)` 参与最终判定。
- [~] `mov rbx, rax` 仍未达到“完整 Ghidra 局部对拍通过”：当前结构化比较和 FFI 状态仍主要围绕 Rugra 侧本地构造数据，尚未接入真实 Ghidra 参考 opcode / 输出 / 输入明细。
- [~] `add rax, 1` 已进入最小样本验证，但当前属于“失败样本记录”而非“局部对拍通过”：测试已新增，当前日志显示 opcode 与输入比对仍存在错位；在补齐 `SeqNum(order)` 和按地址 + order 比较后，问题已进一步收敛到“参考 opcode 来源错误”和“unique 输入比较策略”两个点。
- [x] 已开始函数级批量语义对齐骨架建设：新增 `src/align/function_snapshot.rs`，并已支持从 `Funcdata` 导出函数级 `P-code / CFG / SSA` 语义快照。
- [x] 已确认函数级快照骨架基础测试通过，说明 Rugra 侧函数语义摘要结构已经具备最小可用性。
- [x] 将文档修复目标重新聚焦到“事实校验、索引建设、去失真”，而不是继续堆叠未经验证的完成度表述。
- [x] 重写 `rugra/README.md`，纠正项目定位、CLI 状态和当前能力边界。
- [x] 重写 `rugra/docs/PROJECT_STRUCTURE.md`，建立与真实目录结构一致的结构索引。
- [x] 重写 `rugra/CURRENT_STATUS.md`，按可信边界重述当前状态。
- [x] 重写 `rugra/ALIGNMENT_PROGRESS.md`，明确区分静态对齐、运行时验证和端到端验证。
- [x] 重写 `rugra/docs/VERIFICATION_GUIDE.md`，修复把验证框架写成已完成闭环的问题。
- [x] 重写 `rugra/docs/data_contract.md`，从占位
文档补成主链路数据契约文档。
- [x] 重写 `rugra/docs/api/README.md`，改为基于当前源码状态的 API 索引，并加入统一状态标签规则。
- [x] 新增 `rugra/docs/README.md`，作为 `docs/` 统一入口。
- [x] 修复并重写一批当前主线高风险 API 文档入口，包括：
  - [x] `docs/api/lib.md`
  - [x] `docs/api/funcdata.md`
  - [x] `docs/api/op.md`
  - [x] `docs/api/varnode.md`
  - [x] `docs/api/printc.md`
  - [x] `docs/api/block.md`
  - [x] `docs/api/heritage.md`
  - [x] `docs/api/action.md`
  - [x] `docs/api/pcoderaw.md`
  - [x] `docs/api/binary/mod.md`
  - [x] `docs/api/disasm/mod.md`
  - [x] `docs/api/align/runtime_verify.md`
  - [x] `docs/api/bin/rugra.md`
- [x] 将旧架构目录索引统一降级为历史说明，包括：
  - [x] `docs/api/analysis/mod.md`
  - [x] `docs/api/pcode/mod.md`
  - [x] `docs/api/codegen/mod.md`
  - [x] `docs/api/translator/mod.md`
- [x] 将旧架构高风险子页继续降级为“历史遗留 / 待复核”说明，包括：
  - [x] `docs/api/analysis/calls.md`
  - [x] `docs/api/analysis/dataflow.md`
  - [x] `docs/api/analysis/high_variable.md`
  - [x] `docs/api/analysis/liveness.md`
  - [x] `docs/api/analysis/optimization.md`
  - [x] `docs/api/analysis/ssa.md`
  - [x] `docs/api/analysis/type_inference.md`
  - [x] `docs/api/analysis/type_propagation.md`
  - [x] `docs/api/analysis/variables.md`
  - [x] `docs/api/analysis/api/mod.md`
  - [x] `docs/api/analysis/rules/mod.md`
  - [x] `docs/api/analysis/rules/algebra.md`
  - [x] `docs/api/analysis/rules/constants.md`
  - [x] `docs/api/analysis/rules/dataflow.md`
  - [x] `docs/api/pcode/program.md`
  - [x] `docs/api/translator/x86_64.md`
  - [x] `docs/api/translator/registers.md`
- [x] 开始将历史日志复核提示策略回填到高风险 `AgentLog`，包括：
  - [x] `docs/AgentLog/engineering_progress_2026-03-07_api_docs_completion.md`
  - [x] `docs/AgentLog/engineering_progress_2026-03-08_zero_codegen_pipeline_resolved.md`
  - [x] `docs/AgentLog/engineering_progress_2026-03-08_output_refinement_and_quality.md`
- [x] 继续为当前主线 API 文档补齐显式状态标签，已覆盖的高风险页面包括：
  - [x] `docs/api/coreaction.md`
  - [x] `docs/api/ruleaction.md`
  - [x] `docs/api/blockaction.md`
  - [x] `docs/api/fspec.md`
  - [x] `docs/api/typeop.md`
  - [x] `docs/api/merge.md`
  - [x] `docs/api/cover.md`
  - [x] `docs/api/space.md`
  - [x] `docs/api/address.md`
  - [x] `docs/api/opcodes.md`
  - [x] `docs/api/error.md`
  - [x] `docs/api/ffi.md`
  - [x] `docs/api/disasm/x86_64.md`
  - [x] `docs/api/disasm/x86_lift.md`
  - [x] `docs/api/align/mod.md`
  - [x] `docs/api/align/action.md`
  - [x] `docs/api/align/address.md`
  - [x] `docs/api/align/block.md`
  - [x] `docs/api/align/datatype.md`
  - [x] `docs/api/align/heritage.md`
  - [x] `docs/api/align/pcodeop.md`
  - [x] `docs/api/align/range.md`
  - [x] `docs/api/align/varnode.md`
- [x] 已在 `docs/api/README.md` 建立“当前主线文档清单 / 历史文档清单”双索引视图。
- [x] 已完成最小 P-code 对拍闭环首批样本规划，当前优先级明确为：
  - [x] `mov`
  - [x] `add`
  - [x] `sub`
  - [x] `and/or/xor`
  - [x] 简单 `cmp/jcc`
  - [x] 简单位移
- [~] 已开始为首批最小 P-code 对拍样本设计统一记录模板
  - [x] 已把统一字段固化到实验记录模板中
  - [x] 已先落 3 条样本的模板化记录草案
  - [x] 已把 `mov rbx, rax` 推进成第一条最小可执行对拍记录说明
  - [x] 已把 `add rax, 1` 推进为第二条最小样本失败记录
  - [x] 已修正 `add rax, 1` 的局部比较错位，测试通过（2026-04-24）
  - [x] 已新增 `sub rax, 8` 第三条最小样本并通过（2026-04-24）
  - [x] 已新增第四批 6 条样本并全部通过（2026-04-24）：
    - [x] `and rax, 0xf` — INT_AND + COPY ✅
    - [x] `or rax, 0x10` — INT_OR + COPY ✅
    - [x] `xor rax, 0x7` — INT_XOR + COPY ✅
    - [x] `shl rax, 4` — INT_LEFT + COPY ✅
    - [x] `shr rax, 4` — INT_RIGHT + COPY ✅
    - [x] `cmp rax, rbx` — INT_EQUAL + INT_LESS + INT_SLESS (3 ops) ✅
  - [x] 修复多线程测试竞争：新增 FFI_TEST_LOCK 序列化锁
  - [x] 全部 144 测试通过，0 失败（2026-04-24）

---


## 下一会话建议切入点

1. 推进多指令序列对拍（2-5 条指令组成的小基本块）
2. 在函数级快照骨架基础上补批量 runner 与导出流程
3. 完成 Phase C 维护流程固化（证据来源规则、审计模板）
4. 检查剩余 API 文档页面并补齐状态标签
5. 设计 Ghidra 侧快照导出约定
6. ~~Unique 空间临时变量命名改进（当前仍为 uVarNN）~~ → 已通过 Cover-based merge 大幅缓解（uVar 引用 129→72，2026-06-21）
7. 结合类型恢复引擎开始在高层 C 代码发射（PrintC）中处理必要的类型转换（Type Casts）打印逻辑。
8. 探索结构体（Struct）成员和偏移量的类型传播恢复方案。
9. [x] 迭代类型恢复引擎与测试对齐验证：设计并实现基于固定点迭代的多趟数据流类型传播分析（ActionTypeInfer），支持 COPY、ADD/SUB 偏移、LOAD/STORE 解引用及 Phi 等双向传播规则，测试 `test_type_propagation` 完美验证闭环。（2026-05-21）
10. [x] switch-case 检测（BlockSwitch + jump table） （2026-05-21）
11. [x] **Cover-based HighVariable merging**（2026-06-21）：实现 `Merge::merge_by_cover` + `Cover::intersects_except_at`，对齐 Ghidra `Merge::mergeByCopy`。curl `uVar` 引用 -44%。修正 `ActionMergeType` 在 `ActionCopyPropagate` 之前的流水线顺序。173 测试通过。详见 `docs/AgentLog/engineering_progress_2026-06-21_cover_based_merge.md`。
12. [ ] 区域化控制流结构化（基于 Ghidra `blockaction.cc`）— 当前 5 个 goto、5 个 switch 仍可改进
13. [ ] for 循环恢复（当前 `for_count=0`，所有循环都是 `while`）
14. [ ] Cover 跨块传递性扩展（当前 Cover 仅覆盖 def/use 块，未做 CFG 传播，导致部分安全合并被错过）
15. [ ] 填补 `merge_adjacent` / `merge_multi_entry` / `merge_marker` / `merge_by_datatype` 桩函数

---
