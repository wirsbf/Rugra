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

## 2026-08-13：`SLEIGH-FLOW-REL-0001` 只读设计与 locked fixture

本节是源码租约释放前的设计草案，当前状态仍为 **UNTESTED**。锁定 oracle：Ghidra
12.0.4 commit `e40ed13014025f82488b1f8f7bca566894ac376b`。本轮完整重读
`FlowInfo::{findRelTarget,xrefControlFlow,processInstruction}`、`PcodeEmitFd::dump` 和
SLEIGH relative label resolution 全链。

必须落地的边界如下：

- `findRelTarget` 以 source op 的 immutable `SeqNum::time` 加 Const offset，先精确找
  同 address/time 的 op；缺失时只检查 `time - 1` 的 next-instruction boundary，并通过
  out address 返回 machine fallthrough。不得用 Varnode offset 做 machine-address lookup。
- `xrefControlFlow` 对 Const BRANCH/CBRANCH 只标记 internal target 为 basic start 并更新
  `maxtime`；不得把它加入 machine-address work list。非 Const target 才调用
  `newAddress`。
- 无条件 BRANCH 仅在其 time 不小于当前最深 forward relative target 时删除同一条
  instruction 的剩余 ops；CBRANCH 同时保留 internal branch edge 与 p-code fallthrough。
- `processInstruction` 在 xref 前记录 instruction size 和首 op 的 immutable SeqNum，
  并且 machine fallthrough 只入队一次。
- 初始 basic-block 插入必须保留两个 SeqNum 维度：immutable time 用于 relative lookup；
  mutable order 按 locked `BlockBasic::insert` 的执行顺序赋值。Rust 当前单字段模型由
  flow-local post-emission snapshot 保存 time，不把 SLEIGH ABI identity 当作对象 identity。

对应 oracle 使用真实 `0f a2 c3`（CPUID; RET），完整观察 81 ops、186 Varnodes、
33 relative resolutions、49 raw/final edges、34 blocks 和 visited
`ram:0 size=2 first_time=0`、`ram:2 size=1 first_time=78`。计划中的
`FlowInfoSnapshot` 只克隆 post-emission op/edge 引用与值状态，供独立 Rust fixture
序列化；它不缓存 callback `VarnodeData*`，也不改变生产 CFG。runner 已按 immutable
fd、锁定 git archive、isolated Cargo.lock vendor 和 byte diff 起草，但 metadata 的
`PENDING_*` 会 fail closed，直到三份共享源码完成并重算闭包。

## 2026-08-15：`SLEIGH-FLOW-REL-0001` 落地 — relative 分支 → FlowInfo 内部 p-code 边

锁定 oracle：Ghidra 12.0.4 commit `e40ed13014025f82488b1f8f7bca566894ac376b`。本轮
完整重读 `flow.cc:88-107/115-138/149-179/187-199/204-212/219-248/264-372/383-482/
545-580/785-845/906-1037`、`op.cc:355-372/941-1150`、`block.cc:2258-2289/2625-2631`
与 `flow.hh:58-169` 后，完成如下对齐（替换此前 `UNTESTED` 设计稿）：

- **`VisitStat` 恢复 SeqNum 模型**：`{ first_seq: Option<SeqNum>, size }` 等价
  Ghidra `{ SeqNum seqnum; int4 size; }`（flow.hh:77-80）。`processInstruction`
  在发射后记录首 op 的完整 SeqNum（地址+immutable time，flow.cc:472），
  `target()` 经 `PcodeOpBank::findOp(SeqNum)` 精确解析并按 no-op 指令回退，
  `updateTarget` 用 time-only 等价（address.hh:148 operator==）比较。
- **`findRelTarget` 忠实移植**（flow.cc:149-179）：目标时间 = 源 op 的
  immutable `SeqNum::time` + Const 偏移（uintm wrapping）；先精确查找同地址同
  time 的 op；缺失时只查 `time-1`（branch-to-next-instruction），经
  `visited` 上界回退得到机器 fallthrough 地址并检查 `op_addr < res`；否则报
  "Bad relative branch"。不再用 Varnode offset 做机器地址查找。
- **`xrefControlFlow` 忠实移植**（flow.cc:264-372）：per-instruction `maxtime`
  追踪最深 forward relative 目标；Const 空间 BRANCH/CBRANCH 只把内部目标
  `opMarkStartBasic` 并更新 `maxtime`（不进机器 worklist），relative-to-end 置
  `isfallthru`；非 Const 目标才 `newAddress`。BRANCH/BRANCHIND/RETURN 在
  `getTime() >= maxtime` 时 `deleteRemainingOps`（`opDestroyRaw` 语义，连同
  Varnode 一并销毁）。每个分支后 `startbasic = true`。CALL/CALLIND 的
  noreturn halt 插入后按 Ghidra 的 `--oiter` 重新 xref（插入位置即下一迭代
  索引）。`isfallthru` 终判按最后一个 op 的 opcode。
- **`processInstruction` 忠实移植**（flow.cc:383-482）：发射（`inject_raw_ops_
  single` = `PcodeEmitFd::dump`）→ 记录 VisitStat/首 op SeqNum/STARTMARK →
  xref（可能删尾）→ 仅当 fallthru 时把机器后继入队一次。
- **`fallthruOp` 忠实移植**（flow.cc:88-107）：同指令下一 op（无 STARTMARK）
  优先，否则定位所属指令并 `target(下一条指令)`。
- **`splitBasic` 忠实移植**（flow.cc:983-1017）：按 STARTBASIC 切块、首块注册
  官方入口；每个 op 按 `BlockBasic::insert`（block.cc:2258-2289）的 midpoint
  公式赋 mutable `SeqNum::order`（首 op `2 → 2+0x1000000` 中点 `0x800002`，
  之后每步 +0x800000）；块地址范围按 `setBasicBlockRange`（funcdata.hh:556 →
  block.cc:2625 `setInitialRange`）语义记录。此处现保留完整 `Address`
  空间身份，`stop` 按 `Address::operator<` 扫描块内所有非起始 op 取最大值，
  不再降为 `u64` 或使用最后 op 近似。
- **`collectEdges` 修正**：CBRANCH 先 fallthru 后 branch 边（flow.cc:961-966）；
  BRANCHIND 的 setMark 去重后按 flow.cc:947-956 只清除本次设置的 mark。
- **`generateOps`** 头部补 `clearProperties()`（flow.cc:790）。
- **新增 `FlowInfoSnapshot`**（`snapshot()`）：为 oracle fixture 克隆 post-
  emission 的 op/time、VisitStat 值、relative 解析与 raw edge Arc；不缓存
  SLEIGH callback `VarnodeData*` 身份，不改变生产 CFG。

真实 `0f a2 c3`（CPUID; RET）门禁结果：`tools/run_sleigh_flow_relative_oracle.sh`
差分 Rust 与锁定 Ghidra capture（sha256 `7490edf5…`）**逐字节一致**（81 ops /
186 Varnodes / 33 relative 全 internal / 34 blocks / 49 边 / visited 2）。
该门禁只证明本 fixture 的观察闭包；错误路径（BadData/Unimpl/越界/指令上限）、
跳转表恢复、inline/injection 与 SeqNum 残差仍属 `SLEIGH-FLOW-0001`/`INJECT-0001`
等 TODO，flow.rs 整体保持 L2/MISMATCH。

## 2026-08-23：`FLOW-CONTAINEDCALL-0001` checkContainedCall 移植

锁定 oracle 为 Ghidra 12.0.4 commit
`e40ed13014025f82488b1f8f7bca566894ac376b`。完整读取 `FlowInfo::checkContainedCall`
（flow.cc:1357-1405）、其唯一调用点 `generateOps`（flow.cc:813，do-while 循环体内、
jumptable 内循环之后）、`setPossibleUnreachable` 的设置点 `inlineSubFunction`
（flow.cc:1274）与消费点 `generateBlocks`（flow.cc:843-844）后移植：

- **`check_contained_call`**（flow.cc:1361-1405）：逐 spec 扫描 `fd.callspecs`
  （= Ghidra Funcdata 持有、FlowInfo 以引用持有的 `qlst`）：
  - callee 已解析为 Funcdata → 跳过（flow.cc:1367-1368；Rugra `has_funcdata`
    适配器因 `query_call` 尚未接线恒为 false，CALLSPEC-0001）；
  - 非 `CPUI_CALL`（按 op 当前 opcode）→ 跳过（flow.cc:1369-1370）；
  - visited 覆盖判定用 `BTreeMap::range(..=addr).next_back()` 精确复刻
    `upper_bound` + 前移一步：无 ≤addr 的表项（flow.cc:1375）或
    `start+size <= addr`（flow.cc:1377-1378）→ 跳过；
  - 恰为 visited 指令起点（flow.cc:1379）：`Possible PIC construction` header
    warning → `op_set_opcode(BRANCH)` → `target(addr)` 与 call 后继 op 打
    STARTBASIC（`opMarkStartBasic` = funcdata.hh:480 置位 startbasic）→
    `new_code_ref` 恢复 input(0) → 从 callspecs 删除该 spec；
  - 落在已访问指令中间（flow.cc:1400-1402）：仅
    `Call to offcut address within same function` warning。
- **erase-后继跳过 quirk**：Ghidra 的 `iter = qlst.erase(iter); if (iter ==
  qlst.end()) break;` 加 for 头部 `++iter` 意味着紧随被转换 spec 之后的
  spec 在本轮**不被检查**。Rugra 以相同索引步进复刻（fixture `multi` case
  锁定该行为）。
- **`generate_ops` 接线**（flow.cc:796-821）：重构为 do-while 形状——jumptable
  内循环（`!branchinds.is_empty()`）之后无条件执行 `check_contained_call()`，
  即使首轮无 BRANCHIND 也运行一次，对齐 Ghidra 至少执行一次的 do-while 语义；
  退出条件保持既有 multistage 近似（`checkMultistageJumptables` 仍未移植）。
- **possible_unreachable 消费端**（跨域）：`setPossibleUnreachable` 由
  `inlineSubFunction`（flow.cc:1274）设置、`generateBlocks`（flow.cc:843-844）
  消费 `data.removeUnreachableBlocks(false,true)`。Rugra 的
  `generate_blocks` 已有 `has_possible_unreachable → remove_unreachable_blocks`
  接线；`remove_unreachable_blocks` 本体在 funcdata.rs 的对齐深度属 flow 审计
  另一项（见报告登记的 TODO 建议），本租约未触碰。

验证：`cargo test --lib flow` 57/57 全绿；全量 --lib 除两个预存在失败
（`test_infer_params_and_return_type`/`test_type_propagation`，基线 e959d08
同样失败，类型推断子系统，与本改动无关）。逐函数 oracle 差分见
`tools/run_flow_containedcall_oracle.sh`。

### 2026-08-23（续）：erase-后继跳过的单一自增修正

修正 `check_contained_call` 首版的一个移植缺陷：erase 后多写了一个
`iter += 1`，使每次转换前进两步、索引越过表尾（fixture `multi` case 直接
panic）。Ghidra 每个循环体执行**恰好一次**自增（for 头部 `++iter`，
flow.cc:1365），该唯一自增本身就是"跳过被删元素后继"的实现。修正后
`tools/run_flow_containedcall_oracle.sh` 11/11 MATCH（`multi` 双侧第二个
call 均保留为 CPUI_CALL + callspec）。

## 2026-08-23：`FLOW-INJECT-WIRING-0001` P-code 注入接线

锁定 oracle Ghidra 12.0.4 commit `e40ed130…`。完整读取 `FlowInfo::doInjection`
（flow.cc:1177-1208）、`injectUserOp`（1212-1236）、`injectSubFunction`
（1284-1303）、`injectPcode`（1327-1355）、`generateOps` 两处 `hasInject()`
门（794-795/819-820）、`xrefControlFlow` 的 CALLOTHER 臂（344-348）、
`checkForFlowModification`（639-640）以及 emit 桥 `PcodeEmitFd::dump`
（funcdata.cc:878-908）后接线：

- **`xref_control_flow` CALLOTHER 臂**（flow.cc:344-348）：
  `arch.userops.get_op(in(0) 常量).is_injected()` → `injectlist.push`。
  Ghidra 裸解引用 getOp；Rugra 对 Option 缺失按"非注入"守卫。
  `xref_control_flow_at` 扩展为返回（最后处理 op, isfallthru）并透传
  `inject_fc`（Ghidra fc 参数，供 setupCallSpecs/setupCallindSpecs 的注入
  循环检查，flow.cc:337/341）。
- **`generate_ops` 两处接线**（flow.cc:794-795/819-820）：phase-1 fallthru
  扫尾后与 do-while 体内（checkMultistageJumptables/tablelist 回填之后、
  循环条件之前）各 `if hasInject() inject_pcode()`。
- **`do_injection` 真实 emit 桥**（flow.cc:1177-1208）：签名改为
  `(payload, icontext, op, inject_fc)`；`payload->inject(icontext, emitter)`
  → `InjectPayload::inject`（pcodeinject.rs）+ `inject_raw_ops_single`
  （= `PcodeEmitFd::dump`，每个注入 op 带 baseaddr，对齐
  `cacher.emit(con.baseaddr,…)`）。xref 复用完整 `xref_control_flow_at`；
  startbasic 后继标记改用 dead-list 直接后继（`++getInsertIter()`，
  非 fallthruOp）；`markIncidentalCopy`/`moveSequenceDead` 由 payload 的
  incidentalCopy 属性守卫并改走流期容器（`move_sequence_flow`/
  `mark_incidental_copy_flow`——op.rs 版本作用于 action 期 deadlist，
  流期为空表，见 PcodeOpBank::create 注）；最后 updateTarget+opDestroyRaw。
- **`inject_user_op`**（flow.cc:1212-1236）：userop 索引（in(0) 常量）→
  `UserOpManage` Injected 描述 → inject_id → `PcodeInjectLibrary` payload；
  icontext 按 op 地址与 in[1..]/output 填充后 doInjection(fc=null)。
- **`inject_sub_function`**（flow.cc:1284-1303）：icontext 带
  calladdr=entry；doInjection(fc)；paramshift≠0 → `qlst.back()`（= callspecs
  末位）set_paramshift。
- **`inject_pcode`**（flow.cc:1327-1355）：自足签名 `(&mut self)`；逐槽
  nullify；CALLOTHER→injectUserOp；CALL/CALLIND→callspec（按 op 地址匹配，
  `getFspecFromConst` 残差）→ isInline → injectId≥0：injectSubFunction+
  `Function: <name> replaced with injection: <fixup>` warningHeader+
  deleteCallSpec（Rugra callspec 无名，warning 以 entry 地址拼写，残差）；
  否则 inlineSubFunction+`Inlined function`+deleteCallSpec；收尾
  injectlist.clear()。
- **`fixture_queue_inject`**（RUGRA-GLUE，snapshot() 同类 fixture 观察 API）：
  锁定的 x86-64 SLEIGH 声明无 userop，双侧都无法用真实指令发射 CALLOTHER；
  C++ fixture 直写私有 injectlist，Rust fixture 经此钩子镜像。

残差：`query_call` 仍为 no-op（CALLSPEC-0001：copyFlowEffects/set_funcdata
缺位，CALLFIXUP 经真实 flow 触发不可达，只能 CALLOTHER 路径）；
`inline_sub_function` 实克隆仍 TODO（inlineFlow）；wrapOffset/JCurSpaceSize
见 pcodeinject.md。测试：`cargo test --lib flow pcodeinject` 28 绿
（subflow 既有崩溃与 base 6ee34dc 相同，非本租约）。

### 2026-08-23（续）：`flow_inject_1204` oracle 门禁 MATCH

`tools/run_flow_inject_oracle.sh`（pin-base schema 2，oracle 锁定 commit
`e40ed130…`，Rugra 源 pin `835456b` + flow.rs/pcodeinject.rs 双 overlay）
三 case 双侧 stdout 逐字节一致（sha256 `6effd232…`，stderr 空，diff 空）：

- `inject_cpuid`：真实生产路径——x86-64 SLEIGH 对 `cpuid` 指令发射
  CALLOTHER(44)，经公开 `UserOpManage::manualCallOtherFixup` 注册 fixup 后
  `followFlow` 即可让 **xrefControlFlow CALLOTHER 臂（flow.cc:344-348）在双侧
  自行排队并展开**（无需 fixture 种子）；81 op 流中 CALLOTHER(44) 被销毁、
  注入 COPY 就位、其余 CALLOTHER(45+) 保留；
- `inject_add`：种子路径（合成索引 2001，越过引擎 1756 项 userop 表），
  INT_ADD 替换（const 掩码 + 操作数替换 + moveSequenceDead 落位）；
- `inject_label`：带内部条件分支的 payload（label 相对解析
  `labels[id]-calling_index`、注入后 xref 的 block 拆分、多 op move）。

LOAD/STORE 空间引用常量按 containedcall fixture 同规则投影为 `spc:<name>`。
覆盖率 6/9 MATCH；残差 `CALLSPEC-0001`（queryCall→copyFlowEffects 缺位，
CALLFIXUP 触发不可达）与 `INJECT-0001`（inlineFlow 克隆）登记于
`flow_inject_1204.metadata.json`。发现并登记：containedcall runner 的
spec pin `34a3febf…` 在本仓库不可解析（本 fixture 改 pin 已核实的
identical-asset commit `87aaef2`）。
## 2026-08-23：`FLOW-TRUNCATED-0001` FlowInfo 克隆与 raw-op 生命周期

新增 `TruncatedFlowState`，作为 Rust 借用边界上的值快照；它保存锁定
`FlowInfo` clone constructor（`flow.cc:52-76`）实际读取的
`unprocessed`、`addrlist`、`visited`、instruction 计数/上限、range、flags、
inline head/base。`FlowInfo::from_truncated_state` 保持这些容器原顺序，按目标
Funcdata base 重置 min/max，重新查询目标 override 的 flow-override 状态；存在
inline head 时，recursion 集合指向克隆后的 inline-base 内容。lifter 改为可选，
因为 partial clone 只消费既有 raw p-code，不解码新机器指令。

raw flow 现在在 block 生成前统一停留于 `PcodeOpBank::deadlist`。控制流交叉引用、
edge 收集、injection 序列移动和 branchind 收集都读取该容器；
`split_basic` 按 dead-list 顺序逐 op 调用 `mark_alive`，紧接着插入当前
`BlockBasic` 并赋 block order。这一点对应 `flow.cc:983-1017` 中每次循环的
`data.opInsert`，没有在 `generate_blocks` 入口批量激活的额外阶段。

`split_basic` 与 `generate_blocks` 返回 `crate::error::Result<()>`。后者在
`fillin_branch_stubs`、`collect_edges`、block 创建和 dead→alive 转换之前，以只读
方式验证 `fillinBranchStubs` 结束时首 op 是否会带 `STARTBASIC`；不满足时传播精确
`Lowlevel("First op not marked as entry point")`。直接调用 `split_basic` 也保留同一
守卫。因此错误路径不会产生 block、parent/order、alive-list 或 edge 突变；公开
`follow_flow` 同步返回并传播该 `Result`。

`truncated_flow_1204` 已证明 clone 后 op/tree/list/block 的投影及首 op 缺少
`STARTBASIC` 的异常文本/错误后生命周期状态与锁定 oracle 逐字节相同。异常仍保留
Oracle 在进入 `generateBlocks` 前已经完成的 raw clone，但不会开始 block 生命周期，
且目标不会误置 `BLOCKS_GENERATED`。clone constructor 的全部地址状态、inline
recursion 与 injection 分支尚未逐分支驱动，仍标 `UNTESTED`；FlowInfo 模块保持
L2，不沿用本文早期“Phase 完成”文字推断全模块对齐。

2026-08-24 的切片 B 另增单块地址序列 `[0,64,32]`：Ghidra 与
Rugra 都保留默认 code space 身份，范围为闭区间 `[0,64]`，
从而同时锁定完整 `Address` 传递、遍历边界与“块内最大值而非最后
op”。`BlockBasic` 多范围 copy/merge/marshal 仍归 `BLOCKBASIC-COVER-0001`，
本 fixture 对该部分保持 `UNTESTED`。
