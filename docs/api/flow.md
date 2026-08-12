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
| `connect_basic` | :1021 connectBasic | 按 collectEdges 的原始顺序清空并重放边，保留正反向 slot |
| `generate_blocks` | :824 generateBlocks | fillinBranchStubs → collectEdges → splitBasic → connectBasic → removeUnreachableBlocks |

辅助方法（`// RUGRA-GLUE`）：
- `target_op_for_branch` — `collect_edges` 的内部适配名，委托完整
  `branch_target`/`target`，包括目标指令无 P-code 时沿 visited 前进的路径
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
- **opMarkStartInstruction**：`fillin_branch_stubs` 直接设置 STARTMARK；正常指令由
  `process_instruction` 设置。`opMarkStartBasic` 不再推迟给 block builder：work-list
  目标边界必须在 `new_address`、`set_fallthru_bound`、`fallthru` 和
  `find_unprocessed` 的 Ghidra 对应位置即时设置 STARTBASIC。

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

## 2026-08-13：`PIPE-REACH-0001` 可达指令闭环

锁定 oracle 为 Ghidra 12.0.4 commit
`e40ed13014025f82488b1f8f7bca566894ac376b`。本轮重新完整读取
`FlowInfo::processInstruction`、`xrefControlFlow`、`setFallthruBound`、`fallthru`、
`generateOps` 和 `Funcdata::followFlow` 后，将 canonical CLI/curl 路径改为：

1. 为所属 ELF section 创建一个 owned `SleighLifter`；
2. 从函数入口用 LIFO 地址工作表追踪；
3. 每条指令一次性取得 `Sleigh::oneInstruction` 的 step 与全部 P-code；
4. 根据 BRANCH/CBRANCH/RETURN 推进可达地址，再从 alive ops 构造 CFG；
5. CALL/CALLIND 在 flow 阶段创建 `FuncCallSpecs`，直接 CALL 的 input(0) 改成
   synthetic call-spec annotation。

真实 `GetStr` 六层 fixture 的直接结果：旧 Rugra 在 RETURN 后仍线性提升的
`0x3702` 对齐 NOP 已消失；两侧 raw P-code 均为 103 ops / 272 Varnodes、CFG 均为
6 blocks，并且全部 103 条 op 的 `(address, opcode, input_count, has_output)` 顺序一致。
两次 Rugra release 运行的六层 JSON 逐字节相同。

这只是 `PIPE-REACH-0001` 的窄闭环，`flow.rs` 仍是 **L2 / MISMATCH**：

- raw Varnode 的初始 unknown type、COVERDIRTY/其他状态尚未与 Ghidra 一致；
- CALL annotation 的动态 Fspec space 被固定枚举中的 Iop space 代替；
- `xrefControlFlow` 的 relative internal branch、`maxtime`、删除尾部 ops、CALLOTHER
  injection、override、noreturn 与完整 jump-table 流程未闭合；
- `generateBlocks` 仍委托 `build_blocks_from_alive` 做块划分；入口身份、边重放及
  回边入口的 synthetic front 已对齐，剩余块 range cover 和特殊边属性另行跟踪；
- DataUnavail、BadData、Unimpl 和 instruction-limit 的异常/状态路径尚未逐分支 MATCH。

这些残差继续由 `SLEIGH-FLOW-0001`、`CALLSPEC-0001`、`ADDR-0001`、
`SLEIGH-0002C`/`D` 跟踪，不能沿用本文件早期“Phase 完成”文字推断 L3。

## 2026-08-13：`BLOCK-ENTRY-0001` 入口块与边顺序

锁定 oracle：Ghidra 12.0.4 commit
`e40ed13014025f82488b1f8f7bca566894ac376b`。生产 `follow_flow` 现在调用完整的
`FlowInfo::generate_blocks`，不再直接绕到 `build_blocks_from_alive`。该阶段按
Ghidra `flow.cc:824-845`、`:906-1037` 与 `block.cc:1627-1645` 执行：

1. 在拆块前保存 `collectEdges` 的 `(source op,target op)` 插入顺序；
2. `split_basic` 将首块登记为唯一 `ENTRY_POINT (0x200)`；
3. 清除 builder 的临时边，按保存顺序重放边及 reverse slot；
4. 若首块存在入边，创建空前置块、追加 `newfront -> old entry`，再把前置块移到
   `list[0]` 并转移 `ENTRY_POINT`；
5. 分支目标指令本身无 P-code（例如 ENDBR64）时，通过 visited 顺序推进到该指令
   的首个实际 P-code，与 Ghidra `target()` 一致。

真实行为门禁 `tools/run_block_entry_oracle.sh` 用同一个无 PIE x86-64 fixture 分别
运行锁定的 Ghidra 与 Rugra，完整对比普通 RETURN 与入口自环两条路径的块顺序、
入口对象身份/数量/flags、op 数、归一化地址范围、正反向边及 reverse slot。当前
结果为 `MATCH`。这证明上述窄行为，不代表整个 FlowInfo 或 CFG 模块 L3；
multiple roots、unreachable pruning、BRANCHIND 和 Action 后 index 仍未覆盖。

## 2026-08-13：`FLOW-TARGET-BOUND-0001` 已访问目标边界

独立复核发现，清除 provisional builder 边后，`GetStr` 中 CALL@`0x36e4` 到已访问
汇合点 `0x36e9` 的 fallthrough 丢失。根因不在 `connect_basic`：Ghidra 的
`collectEdges` 本来就只依赖拆块前的 STARTBASIC；差异来自更早的地址工作表。

当前实现按 locked `flow.cc:219-235`、`:489-513`、`:545-580` 恢复以下时序：

1. `new_address` 遇到已访问目标，立即通过 `target(addr)` 找到首个实际 P-code 并
   设置 STARTBASIC；否则保持 LIFO push。
2. `set_fallthru_bound` 用 `visited.upper_bound(addr)` 的语义找 predecessor。若
   predecessor 与待处理地址相等，先设置 STARTBASIC，再丢弃重复 work item。
3. `fallthru` 在整段顺序解码期间保留同一个 `bound`，不随 work-list 栈顶变化而
   重算；精确命中已访问 bound 时，只有持久的 `startbasic` 为真才设置标志。
4. `find_unprocessed` 对仍留在工作表且已经访问的目标执行相同标记。

真实门禁 `tools/run_flow_target_boundary_oracle.sh` 同时逐字节差分：

- 最小 `CBRANCH → CALL → visited join` 三块函数；
- Git commit `86ffa7bcaba0100cdd32b55a619bb07e31af84ad` 中
  `examples/curl` blob 物化的 ELF 里，`GetStr` 的六块完整 CFG，
  包括唯一 CALL fallthrough `1→2`；
- 每块 flags、op 数、地址范围，以及所有有序 in/out peer ordinal 和 reverse slot。

结果为 `MATCH`。原 `tools/run_block_entry_oracle.sh` 的 RETURN 与 synthetic-front
self-loop 也继续 `MATCH`。此闭环不扩展到 off-cut/reinterpreted 错误模式、
out-of-bounds stub、BRANCHIND 或 intra-instruction relative branch 残差。
