# FLOW-MIRROR-0001 — 驱动层流跟随镜像设计(M1,RUGRA_FLOW_MIRROR=1)

> Lane AQ / wt/sb-rust,基线 6ad21c4。oracle = Ghidra 12.0.4 `e40ed130`
> (AGENTS.md 锁定)。依据:D10(STAGE_BISECT_SPEC_1204.md 增补 v1.2.2)、
> Lane AL ATTRIBUTION_V2.md §1(R1/R1a 实证)。

## 1. 根因(两个驱动层分歧,均在 oracle raw-native 单函数 BFD harness 中不存在)

### D-range — 流范围 marshaling 差

- oracle 正典(regen_ghidra_golden.py:388 ≡ oracle harness:315):
  `fd->followFlow(Address(codeSpace, 0), Address(codeSpace, getHighest()))`
  — funcdata_op.cc:756-783,FlowInfo ctor 默认 `baddr=(space,0)`、
  `eaddr=(space,~0)`(flow.cc:28-29),followFlow 形参收窄。
- Rugra 现状:examples/curl_decompile.rs:3582 传
  `follow_flow_with_callee_protos(fd, lifter, Address::new(entry), u64::MAX, …)`,
  src/flow.rs:3331 硬编码 `baddr = entry.as_u64()`。
- 后果:curl 二进制 `.plt@0x2xxx < .text@0x4f90`,一切 `.text` 函数的尾跳
  `jmp strdup@plt`(如 next_url 0x50fa → 0x2530)目标 < entry → 出界 →
  `new_address` OOB → unprocessed → `fillin_branch_stubs` 补 missing halt
  (flow.cc:889-901;Rugra flow.rs:957-972 忠实移植),PLT 体不入函数。

### D-shared-return — Java Shared Return Calls analyzer 仿真

- examples/curl_decompile.rs:215 `collect_known_entry_shared_return_overrides`
  仿真 Java `SharedReturnAnalysisCmd`(直接 jmp → 已知函数入口 ⇒ CALL_RETURN
  override),经 worker :3392-3415 注入 `fd.localoverride`,flow 期
  flow.rs:3065 `override_flow`(funcdata_op.cc:969-1021 忠实移植)把
  BRANCH@0x50fa 改写 CALL@0x50fa:53 + RETURN@:54(drill 签名:uniq 连续)。
- oracle harness 是裸 BFD 加载,无任何 Java analyzer ⇒ 无 override。
  已有 A/B 门 `RUGRA_DISABLE_SHARED_RETURN`(controller :4849)。

## 2. 镜像语义(RUGRA_FLOW_MIRROR=1,默认 off,默认 E2E 逐字节不变)

1. **controller**(:4849 区域):mirror 时 `flow_override_entries = []`
   (与 RUGRA_DISABLE_SHARED_RETURN 同效,日志区分)。
2. **worker**(:3582 区域):mirror 时改调
   `rugra::flow::follow_flow_range(fd, lifter, /*baddr*/ 0, /*eaddr*/ u64::MAX, &callee_protos)`
   — 新 src 入口,镜像 followFlow 完整 (baddr,eaddr) 形参语义
   (funcdata_op.cc:756);entry 取 `fd.get_address()`(flow.cc:791
   `addrlist.push_back(data.getAddress())`)。
   x86-64 ram space `getHighest()` = 2^64-1 = u64::MAX。
   `follow_flow_with_callee_protos` 保留原签名并委托(baddr=entry),
   getstr_stage_snapshot 等既有调用点零改动。
3. **PLT 内联后的 op 生成**(全部为已移植机制的首次驱动层启用,
   无新 src 语义):BRANCH@0x50fa 目标 0x2530 界内 → SLEIGH(real .sla,
   sleigh_lift.rs)翻译 `endbr64`(零 op)+ `bnd jmp *[rip+X]`@0x2534 →
   BRANCHIND → tablelist → `recover_jump_tables`(flow.cc:1427)→
   partial-clone `stage_jump_table` → `recover_addresses` →
   `sanity_check`(jumptable.cc:2304-2320;Rugra jumptable.rs:4597-4605,
   1 表项且 |target−site|>0xffff 或 target==0 → Thunk)→
   FailThunk(funcdata_block.cc:539-541 catch 的移植)→
   `truncate_indirect_jump`(flow.cc:727-769;Rugra flow.rs:720-778)
   → **CALLIND@0x2534 + artificial RETURN@+1** — 与 oracle drill L94 一致。
4. **META load_mode**(emit_stage_projection :2702):mirror 时发
   `single_function_bfd`(D10 镜像落地条件满足),否则 `single_function_flow`。

## 3. M3 — RUGRA_BARE_LOAD=1(裸 BFD 等价,默认 off)

ACTIVEPARAM-COUNT-9V2-0001 RCA-1 药方:worker :3435
`libc_signatures = LibcSignatureTable::empty()`(新增 glue 空表构造)⇒
(a) PLT-import 签名覆盖(:3475)与 (b) link_call_specs 的 libc 台账
解析(:881)自然变 no-op — 裸 BFD 无 generic_clib 签名数据。
`libc_import_signature`(:657,外部 stub 渲染)不动:不属单函数加载路径。

## 4. 改动清单(行号对照)

| 文件 | 函数 | 动作 | Ghidra 对照 |
|---|---|---|---|
| src/flow.rs | 新 `follow_flow_range` | 新增(完整 baddr/eaddr 形参入口) | funcdata_op.cc:756 followFlow |
| src/flow.rs | `follow_flow_with_callee_protos` | 委托 follow_flow_range(baddr=entry) | 同上(收窄调用形态) |
| src/debugproto.rs | 新 `LibcSignatureTable::empty` | 新增空表 ctor | RUGRA-GLUE(平台侧数据源) |
| examples/curl_decompile.rs | controller :4849 | mirror ⇒ 跳过 shared-return 收集 | — |
| examples/curl_decompile.rs | worker :3435/:3582 | bare-load 空表 / mirror 走 follow_flow_range | — |
| examples/curl_decompile.rs | emit_stage_projection :2702 | load_mode 双态 | STAGE_BISECT_SPEC D10 |
| docs/api/flow.md, docs/api/debugproto.md | — | 同步 | — |

## 5. 验证链(M2/M4)

- `cargo check --lib` → `cargo build --profile fast-release`(example)。
- env 全 off:改前/改后 curl E2E 输出字节一致(防回归门)。
- M4:`RUGRA_STAGE_PROJ=1 RUGRA_STAGE_FUNC=next_url RUGRA_FLOW_MIRROR=1
  RUGRA_BARE_LOAD=1` 重产投影,load_mode=single_function_bfd;
  master 消费端记录新首分歧层(预期 0x2534 CALLIND/RETURN 对消失,
  D9 事件数 335vs479 与 op 集 96457vs129745 显著收窄,如实报告)。
- mirror E2E 全量(curl/httpd)信息性跑,如实记录 skeleton 变化(非门禁)。
