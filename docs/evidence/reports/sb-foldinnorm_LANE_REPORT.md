# SB-FOLDINNORM lane report (JUMPTABLE-HYGIENE-0001 族, CR-CH 条件③)

日期: 2026-09-22 | worktree: /home/ls/Rugra-wt-sb-foldinnorm (wt/sb-foldinnorm, master a58091e5)
oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b

## 1. 静态核对(已完成)

### minimalmask 误植(实锤,已修)
- Ghidra `minimalmask`(address.hh:525-534,inline)= 整字节掩码阶梯选择器:
  val>0xffffffff→~0; val>0xffff→0xffffffff; val>0xff→0xffff; else 0xff。
- Rust address.rs:1985 原实现 = `coveringmask` 别名(address.cc:800 语义,最小 2^n-1≥val),
  系统性低估 consumed 位(minimalmask ≥ coveringmask 恒成立;
  minimalmask(0)=0xff vs coveringmask(0)=0; minimalmask(0x7ff)=0xffff vs 0x7ff)。
- 三个消费方(调用点本已正确,仅函数体错):
  - ActionDeadCode::markConsumedParameters (coreaction.cc:3856 / coreaction.rs:447)
  - ActionDeadCode::gatherConsumedReturn (coreaction.cc:3884 / coreaction.rs:470)
  - JumpTable::foldInNormalization switchVarConsume (jumptable.cc:2581 / jumptable.rs:5014)
    → ActionDeadCode BRANCHIND 臂 (coreaction.cc:3984-3992 / coreaction.rs:628-635)
- 修复: address.rs minimalmask 改 1:1 阶梯;test_minimalmask 重钉边界;
  docs/api/address.md 修正 2026-06-27 误植记录 + docs/api/jumptable.md 加注。

### foldInNormalization 家族其余核对(全部一致,无需改动)
- JumpTable::foldInNormalization (cc:2574-2591 / jumptable.rs:4998-5043): 结构逐行一致
  (含 INT_SEXT 回退臂 + calc_mask(in0.size));唯一差异源=minimalmask(已修)。
- JumpBasic::foldInNormalization (cc:1546-1553 / jumptable.rs:3111-3126): op_set_input 一致。
- JumpModelTrivial (hh:361 / rs:1813): None 一致。
- JumpBasicOverride (hh:485 继承 / rs:3967 委托 base) 一致。
- JumpAssisted (cc:2193-2206 / rs:4181-4204): descendants 快照+op_destroy 一致。
- coveringmask (address.cc:800 / address.rs:1970): 本就正确。
- switchVarConsume 初值 ~0 (cc:2387/2408/2755 / rs:4353/4653): 一致。

## 2. E2E 实证

### httpd (29 fns)
- master a58091e5: skeleton 2392, defects=0, numbering=0
- +minimalmask 修复: skeleton 2392, defects=0, numbering=0
  **输出与 master 字节恒等(diff=0)→ +2 与 minimalmask 无关(CR-CH 条件③假设的
  minimalmask 臂在 httpd 语料上不改变任何输出;INT_SEXT 臂同构建零变化)。**

### curl (124 fns)
- +minimalmask 修复: skeleton 2977, defects=0, numbering=0(=任务预期 2977±)
- master 侧 curl A/B: (待 target-master 构建完成)

## 3. +2 真凶排查(进行中)

master httpd 两个 switch 形态:
- main(:67): `switch((int *)*(( *)iRam...b3fba + (int *)uVar1*4) + iRam...b3fba) {}` 空 switch,
  头=BRANCHIND 活输入=表读表达式 ⇒ main 的表未走 foldInNormalization 重接
  (golden main 头= `*(undefined1 *)((long)plVar12 + 0x33)`,Ghidra 已归一化+死码消除)。
- ap_vhost_iterate_given_conn(:632): `switch(param_1) {}` 空 switch;
  golden=UNRECOVERED_JUMPTABLE(Ghidra recoverModel 无模型→"Too many branches"→
  flow.cc:1443-1445 truncateIndirectJump 当调用)。Rugra 恢复成功→结构化 switch。

CH 提交 db0eddeb: printc 头改读活 BRANCHIND in(0)+default 按序;
+2 假设候选 = 某函数头形态/空 switch 出现。待 pre-CH(df9febd9)构建 diff 定位。
