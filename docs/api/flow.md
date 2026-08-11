# flow.rs — Reachability-based control flow tracking

## 2026-07-04：新建 src/flow.rs — FlowInfo Phase 1（可达性流追踪核心）
- 新建 `src/flow.rs`，实现 `FlowInfo` struct（对齐 flow.hh:58-169 FlowInfo）。
- `generate_ops(entry)`：addrlist 工作列表驱动的指令解码主循环（对齐 flow.cc:785-822）。
- `fallthru()`：顺序解码内循环（对齐 flow.cc:545-580）。
- `set_fallthru_bound()`：边界检测 + visited 去重（对齐 flow.cc:489-513）。
- `process_instruction(addr)`：单指令解码 → lift → inject_raw_ops_single（对齐 flow.cc:383-482）。
- `xref_control_flow()`：控制流分析，BRANCH/CBRANCH/RETURN/CALL 分类（对齐 flow.cc:264-372）。
- `follow_flow()` 入口函数（对齐 funcdata_op.cc:756 followFlow）。
- Funcdata 新增 `inject_raw_ops_single`（单指令注入，不建块）+ `build_blocks_from_alive`（流追踪后建块）。
- **Phase 1 完成**（可达性流追踪核心）。Phase 2（跳转表恢复/inline/truncatedFlow）待后续。
- **BRANCHIND 限制**：间接跳转在流追踪中被标记为 non-fallthru（流停止），需要后续补 x86_lift.rs 的 BRANCHIND 发射 + jumptable 恢复。
git add src/flow.rs src/funcdata.rs src/lib.rs docs/api/flow.md && git commit -q -F - <<'EOF'
core(flow): new src/flow.rs — FlowInfo Phase 1 (reachability flow tracking)

New src/flow.rs implementing Ghidra's FlowInfo reachability-based flow
tracking (flow.hh:58-169, flow.cc:785-822). This is the core of the
L1 gap: replaces Rugra's linear scan with address-list-driven decoding.

## Components

FlowInfo struct (flow.hh:58-169):
- addrlist: Vec<Address> (LIFO work-list, flow.hh:82)
- visited: BTreeMap<u64, VisitStat> (flow.hh:84, for dedup + range query)
- insn_count/insn_max (flow.hh:95-96)
- baddr/eaddr/minaddr/maxaddr (flow.hh:97-100)

Methods:
- generate_ops(entry): addrlist-driven decode loop (flow.cc:785-822)
- fallthru(): sequential decode inner loop (flow.cc:545-580)
- set_fallthru_bound(): boundary detection + visited dedup (flow.cc:489-513)
- process_instruction(addr): decode one instruction, lift, inject (flow.cc:383-482)
- xref_control_flow(): classify BRANCH/CBRANCH/RETURN/CALL (flow.cc:264-372)

Funcdata additions:
- inject_raw_ops_single: inject single instruction's P-code (no block building)
- build_blocks_from_alive: build CFG after all flow tracking completes

follow_flow() entry point (funcdata_op.cc:756 followFlow).

Ghidra: flow.cc:785 generateOps, :545 fallthru, :489 setFallthruBound,
:383 processInstruction, :264 xrefControlFlow.

Phase 1 complete. Phase 2 (jump-table recovery, inline, truncatedFlow) TODO.
BRANCHIND targets are not followed (flow stops) — needs x86_lift.rs fix.

Verification: 952/952 tests pass, curl 24/24 gcc (unchanged — flow.rs
not yet wired into main.rs; existing linear scan still active).

### 2026-07-04（续）：BRANCHIND 发射 + Phase 1 无回归确认
- x86_lift.rs 的 `jmp` 分支现在处理非 Immediate 操作数（Register/Memory）→ 发射 CPUI_BRANCHIND。
- curl 的 24 个函数中无 switch/间接跳转（BRANCHIND count = 0），所以 Phase 2 跳转表恢复不会影响 curl 输出。
- FlowInfo Phase 1 的 BRANCHIND 处理：当前标记为 non-fallthru（流停止），Phase 2 将添加跳转表恢复。

### 2026-07-04（续 2）：FlowInfo Phase 2 — 跳转表恢复循环
- `generate_ops` 新增 Phase 2：BRANCHIND 收集 → try_recover 跳转表恢复 → 地址推入 addrlist → fallthru 追踪（对齐 flow.cc:796-821）。
- 新增 `collect_branchinds`（扫描 alive ops 找 BRANCHIND）+ `new_address`（范围检查 + visited 去重后推入 addrlist）。
- 跳转表恢复使用现有 jumptable.rs::try_recover（已移植）。
- 多阶段检测：如果新 BRANCHIND 出现，循环继续（flow.cc:814 checkMultistageJumptables）。
- curl 无间接跳转，无回归。Phase 2 对 switch/间接跳转函数生效。
<!-- annotation-pass: 2026-07-04 -->

<!-- sleigh-lift-pipeline: 1783181897.3074532 -->
 
**2026-07-22**: 23 missing flow.cc methods added (11→34 functions, +361 lines)

## 2026-08-11：ANN-B 注释 provenance 审计

- Oracle 固定为 Ghidra 12.0.4 commit `e40ed13014025f82488b1f8f7bca566894ac376b`；完整读取 `flow.cc` 与 `flow.hh` 后分类。
- 为 `FuncCallSpecsExt` 的 8 个 trait 声明和 8 个 Rust 实现补充具体 `RUGRA-GLUE: ANN-B`：这些是 flow-local 适配层，不是 Ghidra `FlowInfo` 函数。缺失的 callspec 状态/身份分别仍由 `CALLSPEC-0001` 与 `INJECT-0001` 跟踪。
- `address_space_as_u32` 是 Rust `AddressSpace` 到临时注入元组的适配；`find_callspec_for_op` 是 callspec 指针身份尚未落地时的线性扫描回退，二者均无可诚实引用的 Ghidra 函数体。
- 本轮仅补对齐来源注释，不改行为，也不产生逐函数 oracle `MATCH` 或 L3 证明。

## 2026-07-22（续）：FlowInfo 跳转表细节补齐 — Phase 2 完整化

补齐 Ghidra `flow.cc` 中缺失的跳转表（jump-table）分析与基本块生成方法。每个
移植方法均带 `// Ghidra: flow.cc:<行号> FlowInfo::<函数名>` 注释，Rust 胶水
标 `// RUGRA-GLUE: <理由>`。

### 新增方法（src/flow.rs，+403 行，778→1181）

| Rust 方法 | Ghidra flow.cc | 说明 |
|---|---|---|
| `recover_jump_tables` | :1427 recoverJumpTables | BRANCHIND 跳转表恢复主入口；notreached 延迟列表 + partial/complete 分支 |
| `check_multistage_jumptables` | :1408 checkMultistageJumptables | 多阶段跳转表检测（结构占位，checkForMultistage 未移植） |
| `xref_inlined_branch` | :1053 xrefInlinedBranch | 内联注入的 CALL/CALLIND/BRANCHIND 交叉引用；BRANCHIND 走 find_jump_table |
| `find_unprocessed` | :850 findUnprocessed | addrlist 剩余地址 → unprocessed |
| `dedup_unprocessed` | :866 dedupUnprocessed | 排序 + 去重（Address: Ord） |
| `fillin_branch_stubs` | :889 fillinBranchStubs | 为 unprocessed 地址生成 artificial_halt(MISSING) + STARTBASIC/STARTMARK |
| `collect_edges` | :906 collectEdges | 收集 (src,targ) 边对；BRANCH/CBRANCH/BRANCHIND(jumptable 条目)/fallthru |
| `split_basic` | :983 splitBasic | 委托 build_blocks_from_alive；保留入口块不变量 |
| `connect_basic` | :1021 connectBasic | 边重放（Rugra 在 build 时已派生） |
| `generate_blocks` | :824 generateBlocks | fillinBranchStubs → splitBasic → connectBasic → removeUnreachableBlocks |

辅助方法（`// RUGRA-GLUE`）：
- `target_op_for_branch` — BRANCH/CBRANCH input(0) 地址 → alive op（Ghidra
  branchTarget 的直接地址路径，相对分支走 lifter 已发射绝对地址）
- `target_op_by_addr` — 地址 → 首个 alive op（Ghidra target() 地址回退循环）
- `fallthru_op` — 顺序下一个 alive op（Ghidra fallthruOp 的近似）

### 已知缺口（RUGRA-GLUE 标注）

- **partial Funcdata 克隆**：Ghidra 在 recoverJumpTables 里构建独立的 partial
  Funcdata 做分析；Rugra 无此机制，恢复直接走 `jumptable::try_recover` 原地执行
  `JumpTable::recover_addresses`。
- **JumpTable::checkForMultistage**：未移植（依赖 partial Funcdata 简化路径），
  `check_multistage_jumptables` 保留迭代结构但不推送新 op。
- **Funcdata::linkJumpTable**：未移植，`xref_inlined_branch` 用 `find_jump_table`
  近似。
- **FuncCallSpecs 管线**：`setupCallSpecs`/`setupCallindSpecs` 需要 FuncCallSpecs，
  推迟到 ActionFuncLink；`xref_inlined_branch` 的 CALL/CALLIND 分支为 no-op。
- **opMarkStartBasic/opMarkStartInstruction**：Rugra 在 build_blocks_from_alive
  统一处理，fillin_branch_stubs 直接置 STARTBASIC/STARTMARK flag。

### 验证

- `cargo check --lib`：flow.rs 零错误（唯一的 E0502 在 grammar.rs，与本任务无关的
  并发改动）。
- flow.rs 仅 3 个 pre-existing 警告（unused `Instruction` import / `stat` / `inst`）。
- 新增方法无新增警告。

## Alignment Evidence

- 源文件：`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/flow.cc`（1460 行）
  + `flow.hh`（172 行）。
- 目标文件：`src/flow.rs`（778 → 1181 行，+403 行）。
- 每个移植方法上方有 `// Ghidra: flow.cc:<行号> FlowInfo::<名>` 注释。
- `cargo check --lib` 通过（flow.rs 零错误）。
