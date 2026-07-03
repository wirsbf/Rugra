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
