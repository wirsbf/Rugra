# sleigh_lift.rs — SLEIGH P-code bridge

`src/disasm/sleigh_lift.rs` converts the owned, dynamic result from
`SleighCtx::one_instruction` into Rugra `PcodeOpRaw` values. The locked source oracle is
Ghidra 12.0.4 commit `e40ed13014025f82488b1f8f7bca566894ac376b`, principally
`Sleigh::oneInstruction` (`sleigh.cc:741`) and the `Translate::oneInstruction`
contract (`translate.hh:419`).

## Status

This module is **L2 / MISMATCH**. It is now used by the production CLI and canonical curl
example, but neither the SLEIGH context path nor the surrounding Flow pipeline is fully
equivalent to Ghidra.

- `SleighLifter::configure_x86_64` owns one translator and one copied ELF-section image for
  a function-flow run. It loads the repository x86-64 pspec compatibility path before the
  first decode. Full `ContextInternal::decodeFromSpec` behavior remains
  `SLEIGH-0002C`.
- `SleighLifter::lift_instruction` makes exactly one strict `one_instruction` call and
  returns its step together with every emitted op. A legal zero-op instruction remains a
  successful decode. Typed errors are preserved for `FlowInfo`.
- `convert` no longer applies the legacy 16-input cap. It preserves callback op/input
  order, while the Address/AddrSpace model and branch/call constant-space conversion still
  depend on `ADDR-0001` and `SLEIGH-FLOW-0001`.
- `lift_function` and `lift_from_func` remain compatibility helpers. They fold strict errors
  into omitted/empty output and therefore are not behavior-oracle entry points.

## 2026-08-13 reachable-flow integration

`PIPE-REACH-0001` replaced the canonical linear iced-x86 address sweep with a single
configured `SleighLifter` consumed by `FlowInfo`. On locked `examples/curl` / `GetStr`, the
reachable raw sequence is now 103 ops on both sides; the numeric tuple
`(address, opcode, input_count, has_output)` agrees for every op. Full raw state remains
`MISMATCH`: emitted Varnode type/cover flags differ, and direct CALL annotations use
Rugra's synthetic Iop space because it has no dynamic Fspec address space.

Behavior evidence is produced by:

```bash
tools/run_getstr_pipeline_oracle.sh
```

The fixture uses the release profile because two independently reviewed core-algorithm
repairs are still pending (`VARMAP-GATHEROFFSET-0001` and
`RULE-COLLECTTERMS-0001`). This evidence does not promote the module to L3.

## 2026-08-13：`SLEIGH-FLOW-REL-0001` relative operand 设计草案

本节目前是租约释放前的设计与真实 oracle 记录，不表示 Rust 改动已经落地。锁定
Ghidra 12.0.4 commit 为
`e40ed13014025f82488b1f8f7bca566894ac376b`；已完整重读
`SleighBuilder::dump`、`PcodeCacher::{addLabelRef,addLabel,resolveRelatives}`、
`PcodeBuilder::build` 和 `Sleigh::oneInstruction`。

relative input(0) 的决定性时序是：

1. `SleighBuilder::dump` 看到 relative `ConstTpl` 时，以当前 label base 计算 label id；
2. 在分配该分支的 `PcodeData` 前，以 `issued.size()` 记录 calling index；
3. `LABELBUILD` 把 label id 映射到当时的 `issued.size()`；
4. `resolveRelatives` 写回
   `(labels[id] - calling_index) & calc_mask(varnode_size)`；
5. `oneInstruction` 严格执行 build → resolve → emit。

因此 `convert` 必须原样保留 callback input(0) 的 Const space 和已经 mask 的 offset。
它不是 machine RAM address；将 `space == 0` 的 BRANCH/CBRANCH 改成 RAM 会同时破坏
`PcodeEmitFd::dump` 与 `FlowInfo::findRelTarget`。LOAD/STORE input(0) 的 AddrSpace 指针
仍只按 `VarnodeC::space_ref` 规范化为目标 space id；该规则不能扩展到 relative branch。

真实 fixture `tests/oracle/sleigh_flow_relative_1204.cc` 使用 `0f a2 c3`
（CPUID; RET）。锁定 capture 为 81 ops、186 post-emission Varnodes、33 个 Const-space
relative internal branches、34 blocks、49 edges、2 个 visited instructions。Rust fixture
明确忽略 callback `VarnodeData*` identity：PcodeEmitFd 后每个新 Varnode 由 Rust bank
独立创建，只有真实 post-emission `Arc` 重复引用才共享 fixture id。metadata 仍为
`UNTESTED/PENDING`，直至共享 `funcdata.rs` 租约释放、Rust comparand 编译并与 oracle
NDJSON 逐字节相同。

## 2026-08-15：`SLEIGH-FLOW-REL-0001` 落地 — Const 空间相对分支原样保留

锁定 oracle：Ghidra 12.0.4 commit `e40ed13014025f82488b1f8f7bca566894ac376b`。
本轮实现（不再是设计草案）：

- `SleighLifter::convert` 移除了旧的 "input(0) Const→Ram 重映射"。该重映射把
  SLEIGH 内部 label 分支（`PcodeCacher::resolveRelatives`，sleigh.cc:120-134，
  写回 `(labels[id] - calling_index) & calc_mask(size)`）误标成机器地址，破坏了
  `FlowInfo::branchTarget`（flow.cc:190 `addr.isConstant()`）的分派前提。现在
  每个输入的 `(space, offset, size)` 原样通过，对齐 `PcodeEmitFd::dump`
  （funcdata.cc:878-908）的 `Address(vars[0].space, vars[0].offset)` 语义。
- 决定性依据：`slghparse.y` jumpdest 规则把 `goto <label>` 编译为
  `VarnodeTpl(ConstTpl(const_space), ConstTpl(j_relative, id), ConstTpl(real,
  sizeof(uintm)))`；x86 机器 `jmp/call rel` 的 `rel8/16/32` 子构造器导出
  `*[ram]:$(SIZE) reloc`（ia.sinc:1149-1151）。x86 下机器分支本来就在 Ram
  空间，重映射只影响 CPUID 决策树这类 label 分支，因此 curl/httpd 路径不受
  影响（GetStr 无 intra-instruction label 分支）。
- `lift_instruction` 语义不变：一次严格 `oneInstruction`，step 与全部 ops 原子
  返回；shim（sleigh_shim/rugra_sleigh.cpp `RugraPcodeEmit`）只规范化
  LOAD/STORE 的 space-id 常量偏移，不改分支空间。

真实 `0f a2 c3` 门禁（`tools/run_sleigh_flow_relative_oracle.sh`）：Rust 侧
81 ops / 33 Const branches / 34 blocks / 49 双向边，与锁定 Ghidra capture
（sha256 `7490edf5…`）逐字节一致。模块整体仍为 L2/MISMATCH（ContextInternal
pspec 全量、Fspec 动态空间等见 `SLEIGH-0002C/D`、`ADDR-0001`）。
