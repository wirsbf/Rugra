# A11 — `getparameter.constprop.0` 48-case switch 未恢复 · 只读诊断报告

- 任务 ID: `FLOW-JUMPTABLE-GETPARAM-0001`(P0,诊断阶段)
- Agent: 只读诊断 Agent(未修改任何仓库文件、未运行 cargo/build)
- 日期: 2026-08-24
- oracle: Ghidra 12.0.4 tag `Ghidra_12.0.4_build`,commit `e40ed13014025f82488b1f8f7bca566894ac376b`
- fresh 基线: `/home/wirs/.cache/rugra-threefunc-main-f7b3c31-XJYadF/artifacts/`(commit `f7b3c31` release 单次运行,
  stdout SHA-256 `fc9a33ba…91d60e7`,stderr `curl.stderr.log`)
- golden: `tests/golden/ghidra_curl_1204.c`(0x103f00 = Ghidra 镜像基址下的同一函数;Rugra 地址 = golden 地址 − 0x100000)

## 0. 根因一句话

Rugra 在 flow 阶段(`generate_ops`)把 BRANCHIND 直接交给 `jumptable::try_recover` 在**未做
partial 克隆、未跑 "jumptable" 策略简化、无 SSA def 链、无基本块**的原始 Funcdata 上恢复;
`JumpBasic::recover_model` 第一步 `find_determining_varnodes` 就在 BRANCHIND 的 def-less 寄存器读
varnode 上剪枝、`analyze_guards` 因 `op.parent == None` 被整体跳过,range 尺寸远超
maxtablesize(1024) → 恢复失败返回 `None`;而 `generate_ops` 的调用点**没有失败分支**(既不
`truncate_indirect_jump` 也不记日志),间接跳转被静默丢弃 → 88 个 case 体地址从未入队 →
`bblocks=36`(日志行 5550),switch 体整体不可达,后续结构化/死代码阶段将其丢弃。

**这不是 flow 没把间接跳转交给 jumptable(交接发生了),而是 jumptable 恢复被放在了一个
Ghidra 从不存在的运行环境里(raw pcode),恢复必然失败且失败被静默吞掉。**

## 1. 症状与证据

### 1.1 fresh 基线日志(/home/wirs/.cache/rugra-threefunc-main-f7b3c31-XJYadF/artifacts/curl.stderr.log)

- 行 5550: `[STEP] getparameter.constprop.0 flow done 124.343961ms raw_ops=677 bblocks=36`
  — 2609 字节函数线性 lift 出 677 ops,但只有 36 个基本块;48-case switch 至少需要 50+ 块。
- 全文件 jumptable 相关 TAG(`[JT]`/jumptable/tablelist/recover)计数 = **0**;
  `[FLOW]` TAG 全文件仅 1 条(行 4325,frame_dummy 越界,与本函数无关)。
  → 恢复失败路径没有任何日志(见 §4 第 6 步:generate_ops 无失败分支)。
- 阶段顺序佐证:flow done(行 5550)→ `[HERITAGE]` WARN(行 5553+,**heritage/SSA 在 flow 之后才跑**)
  → `[BLOCKSTRUCT] … sblocks=36`(结构化只能看到 36 块)→ `[COLLAPSE] … goto cascade`
  → 输出塌缩为 67 行(diff 504,详见 B6 报告 §1.1)。
- 排除"恢复成功但表错":若 `try_recover` 返回含越界地址(如全 0)的表,`new_address`
  (flow.rs:2736-2742)会逐地址打 `[FLOW] … out of bounds` 日志 — 日志里没有,证明恢复在更早处
  返回了 `None`。

### 1.2 间接跳转的机器码模式(examples/curl,objdump)

```asm
3fc0: 8d 46 dd          lea    -0x23(%rsi),%eax     ; eax = (u8)flag - 0x23
3fc3: 3c 57             cmp    $0x57,%al            ; 守卫: al <= 0x57(88 槽)
3fc5: 0f 87 d5 01 …     ja     41a0                 ; default 臂
3fcb: 0f b6 c0          movzbl %al,%eax             ; ZEXT(1 字节)
3fce: 49 63 04 86       movslq (%r14,%rax,4),%rax   ; LOAD 4 字节有符号相对偏移 + SEXT
3fd2: 4c 01 f0          add    %r14,%rax            ; + 表基址(r14,LEA 常量)
3fd5: 3e ff e0          notrack jmp *%rax           ; BRANCHIND @ 0x3fd5
```

gcc -fPIE 相对偏移表:恢复需要 ①守卫范围截取(`ja` CBRANCH → [0,0x57]) ②LOAD 求值(从
rodata 表读 88 个 4 字节偏移) — golden `switch((int)pCVar10 - 0x23U & 0xff)`(golden 行 1765)
+ 48 个非重复 case 正是 88 槽去重 default 目标后的结果。

### 1.3 输出对照

- golden: `tests/golden/ghidra_curl_1204.c` 行 1649-2130(475 行),switch 体 ~350 行。
- Rugra: `artifacts/curl.stdout.c` 行 986-1053(67 行),**无 switch**,仅 default 臂可达后经
  fall-through 线性区漏出的碎片(`helpf(0x6255 …)` 等)+ 大量下游症状(条件语句化 ×6、
  寄存器泄漏 `uVar_8f00`/`in_register_00000110`、伪造死循环)。

## 2. Ghidra 决策链(oracle 行号,全部已逐行读过)

```
FlowInfo::generateOps                     flow.cc:785-822
  └ Phase1 fallthru 消耗 addrlist;BRANCHIND 在 xrefControlFlow 里被登记
    flow.cc:321-322 `case CPUI_BRANCHIND: tablelist.push_back(op);`
  └ do { while(!tablelist.empty()) {
      FlowInfo::recoverJumpTables          flow.cc:1427-1458
        对 tablelist 每个 op:
        jt = data.recoverJumpTable(partial,op,this,mode)   flow.cc:1442
        jt==NULL → truncateIndirectJump(op,mode)           flow.cc:1443-1445
        jt->isPartial() 且还有更多流 → notreached.push     flow.cc:1447-1452
      成功表:newAddress(indirectOp, 每个 addresstable[i]) + fallthru
                                            flow.cc:805-809
    } checkContainedCall(); checkMultistageJumptables(); … } while(!tablelist.empty())

Funcdata::recoverJumpTable                funcdata_block.cc:639-673
  linkJumpTable 已有完整表 → 直接返回      funcdata_block.cc:645-656
  earlyJumpTableFail 回溯找 CALLOTHER      funcdata_block.cc:554-627, 调用点 660
  stageJumpTable(partial,&trialjt,op,flow) funcdata_block.cc:664
  成功 → new JumpTable(&trialjt) 入 jumpvec + setIndirectOp   cc:669-671

Funcdata::stageJumpTable                  funcdata_block.cc:491-547   ★ Rugra 整段缺失
  (仅一次)partial.truncatedFlow(this,flow)  cc:494-497
      Funcdata::truncatedFlow             funcdata_op.cc:792-840
        克隆 raw ops + callspecs + jumptables → partial
        partialflow.generateBlocks()       funcdata_op.cc:839   ★ partial 有 CFG,parent 存在
  glb->allacts.setCurrent("jumptable"); getCurrent()->perform(partial)
                                           funcdata_block.cc:501-508   ★ "jumptable" 策略简化
        (含 heritage/SSA、常量传播等 — 策略组 XML 在完整 Ghidra 树
         data/pcodeactions/,本稀疏 oracle checkout 不含,移植时需补取)
  partop = partial.findOp(seqnum)          cc:520-523
  partop dead → success(空表)             cc:524-525
  testForReturnAddress → fail_return       cc:528-529
  jt->setLoadCollect / setIndirectOp(partop)
  jt->recoverAddresses(&partial)           cc:531-537
  JumptableThunkError → fail_thunk; LowlevelError → fail_normal   cc:539-545

JumpTable::recoverAddresses               jumptable.cc:2623-2649
  → JumpTable::recoverModel               jumptable.cc:2254-2285
      模型顺序: override → JumpAssisted(CALLOTHER def) → JumpBasic → JumpBasic2   cc:2274-2282
  → jmodel->buildAddresses(EmulateFunction 逐值 emulatePath)     cc:2639-2646
  → JumpTable::sanityCheck                jumptable.cc:2295-2329
      isReachable 检查、单入口 thunk 判定(JumptableThunkError)、
      jmodel->sanityCheck 失败 → LowlevelError、截断 warning

JumpBasic::recoverModel                   jumptable.cc:1418-1432
  jrange = new JumpValuesRange()
  findDeterminingVarnodes(indop,0)        (在 SSA 化的 partial 上,def 链完整)
  findNormalized(fd,indop->getParent(),-1,matchsize,maxtablesize)  cc:1427
      = analyzeGuards(rootbl,pathout)     jumptable.cc:1046-1112  ← 需要 CFG 块
      + findSmallestNormal(matchsize)     jumptable.cc:1165-1193
            calcRange: 守卫 range 交集   jumptable.cc:1120-1156(cc:1139-1145)
      + readonly 单入口救援              cc:1212-1231(MemoryImage 读 loader)
  jrange->getSize() > maxtablesize → false
  markFoldableGuards()

JumpBasic::buildAddresses                 jumptable.cc:1434-1460
  EmulateFunction emul(fd); emulatePath(val,pathMeld,…)
  EmulateFunction::getVarnodeValue        jumptable.cc:179-192
      const → 值;varnodeMap → 缓存;否则 getLoadImageValue(space,offset,size)
      ← LOAD/表基址常量经 loader 读出,rodata 表可求值
```

## 3. Rugra 现状链(src 行号,全部已逐行读过)

```
FlowInfo::generate_ops                    src/flow.rs:2504-2613
  Phase1 fallthru                         rs:2512-2514
  Phase2 loop:                            rs:2530
    collect_branchinds() 扫 deadlist       rs:2532 → rs:2718-2726   [交接发生了]
    for 每个 branchind:
      已有表 → 复用地址                    rs:2539-2558
      try_recover(&bi_ref.0, self.fd)     rs:2561
        Some → new_address(每个表项)+fallthru   rs:2562-2585
        None → 【无 else 分支,静默跳过】   ★ rs:2561-2570
    check_contained_call                  rs:2591
    check_multistage_jumptables(空壳)     rs:2592-2594 → rs:850-863

(忠实移植 FlowInfo::recover_jump_tables 含 truncate 分支的版本在 rs:766-834,
 含 rs:789-794 truncate_indirect_jump —— 但 generate_ops 不调用它 = 死代码)

jumptable::try_recover                    src/jumptable.rs:4339-4358
  jt.recover_addresses(fd) 【对 raw fd 原地跑】 rs:4350-4351;panic→None rs:4353-4356
JumpTable::recover_addresses              rs:4047-4100
  recover_model(fd, MAX_JUMPTABLE_SIZE=1024)   rs:4048
JumpTable::recover_model                  rs:3994-4038
  模型顺序: JumpBasic → JumpModelTrivial(非 Ghidra 的 override→Assisted→Basic→Basic2) rs:4026-4035
JumpBasic::recover_model                  rs:2463-2494
  find_determining_varnodes               rs:2472 → rs:2041-2119
  analyze_guards 仅当 op.parent 存在       rs:2475-2481  ★ flow 阶段 parent 恒为 None
    (parent 只在 generate_blocks 阶段赋值:flow.rs:2369 block_insert_at_end / funcdata.rs:3113)
  find_smallest_normal(matchsize)         rs:2482 → rs:2195-2234
  size_ok = jrange.size <= maxtablesize   rs:2484-2487   ★ 无守卫时 range 巨大 → false
JumpModelTrivial::recover_model           rs:1456-1481
  读 parent 块出边数;parent None → n_out=0 → false   rs:1465-1480
→ jmodel=None → recover_addresses false → try_recover None

关键前置事实(为什么 find_determining_varnodes 必然立刻剪枝):
  flow 阶段 pcode 注入路径 inject_raw_ops_single   src/funcdata.rs:5444-5513
  每个输入引用都新建 FRESH varnode(rs:5497-5511 注释:"no location dedup"),
  跨指令寄存器读无 def(与 Ghidra raw pcode 相同)→ BRANCHIND 的 rax 读
  is_written()==false → is_prune=true(jumptable.rs:1625-1626)
  → path_meld = 单点(裸寄存器读),numCommonVarnode==1
  is_point=true(rs:1644-1655,寄存器读非 const/annotation/readonly)
  calc_range(裸寄存器读):unwritten → getMaxValue=0 → 全幅 range,
  >0x10000 走 positive 截断(rs:2131-2188,忠实移植 cc:1120-1156,但
  selectguards 为空 → 无交集,rs:2162-2177 空转)
```

次级缺口(即使补上 CFG+SSA,恢复仍会错;均已在板,见 §7):

- `EmulateFunction` 无 fd/loader 桥:`EmulateFunction::new()` 无参(rs:4130-4135);
  `get_varnode_value` fallback 恒 0(rs:4155-4156,Ghidra 是 `getLoadImageValue`);
  `execute_op` 把 LOAD 当 `evaluate_binary` 纯算子求值(rs:4199-4214)— rodata 表根本读不出来。
- `build_addresses` 模拟失败推 `Address::new(0)` 入表继续跑(rs:2557-2569 `None => 0`),
  Ghidra 抛 LowlevelError 终止全表。
- 表级 `JumpTable::sanityCheck`(cc:2295-2329,含 JumptableThunkError/截断)MISSING;
  模型级 `sanity_check` 返回值被丢弃(rs:4078-4084、4094 `let _ =`)。
- `JumpTable::recover_model` 选择顺序错误 + 无 JumpAssisted/JumpBasic2 尝试
  (rs:4024-4035 vs cc:2274-2282;= TODO JUMPTABLE-SELECTION-0001)。
- `JumpBasic::recover_model` 绕过 `find_normalized`(rs:2473-2482 直调两步),
  readonly 救援空壳(rs:2255-2265)。
- `check_multistage_jumptables` 空壳(flow.rs:850-863,checkForMultistage 未移植)。

## 4. 失败链推演(getparameter @ 0x3f00,BRANCHIND @ 0x3fd5)

| 步 | 事件 | Rugra 行号 | Ghidra 对应 |
|---|---|---|---|
| 1 | flow Phase1 线性追踪,BRANCHIND 入收集 | flow.rs:2532/2718 | flow.cc:321-322 |
| 2 | try_recover 在 raw fd 上原地恢复 | jumptable.rs:4339-4351 | stageJumpTable 先建 partial+CFG+简化(funcdata_block.cc:491-547, funcdata_op.cc:792-839)★缺 |
| 3 | find_determining_varnodes:BRANCHIND 输入(0x3fd5 读 rax)无 def → is_prune → 单点 path_meld | jumptable.rs:2056-2073 + 1625;funcdata.rs:5497-5511 fresh input | partial 已 SSA,def 链完整走 到 LOAD/守卫 |
| 4 | analyze_guards 跳过(parent=None)→ selectguards 空 | jumptable.rs:2475-2481;parent 赋值在 flow.rs:2369(generate_blocks 阶段) | partialflow.generateBlocks() 后 analyzeGuards(cc:1046)产出 `ja 0x57` 守卫 range [0,0x57] |
| 5 | find_smallest_normal:裸 8 字节读 range 巨大 → size_ok=false → JumpBasic 失败;Trivial 也失败(parent None) | jumptable.rs:2484-2487, 4031-4035, 1465-1480 | findSmallestNormal 经守卫交集得 88 项 ≤1024 通过(cc:1165-1193, 1418-1432) |
| 6 | try_recover=None;generate_ops **无失败分支**,不 truncate 不记日志 | flow.rs:2561-2570(对比死代码 rs:766-834 有 truncate) | jt==NULL → truncateIndirectJump(op,mode)(flow.cc:1443-1445) |
| 7 | BRANCHIND 永不展开,88 个 case 地址不入队 | — | flow.cc:805-809 newAddress+fallthru |
| 8 | bblocks=36(日志 5550);后续 HERITAGE/BLOCKSTRUCT/COLLAPSE 只见 36 块,switch 体不存在,输出塌缩 67 行 | 日志 5550-5600 | golden 475 行含 switch(行 1765 起) |

即使第 3-5 步被修复(有 def 链+CFG),第 2 步环境缺口仍使 `build_addresses` 的 LOAD 求值
返回 0/垃圾(rs:4155, 4199-4214),表内容错误 — 所以修复必须按 §5 顺序做全。

## 5. 修复方案(租约感知,串行顺序)

> write-set 与在板 TODO 对齐;不新开重复 TODO,建议把本 TODO(`FLOW-JUMPTABLE-GETPARAM-0001`)
> 的修复阶段并入 `JUMPTABLE-PIPELINE-0001` 主管线项,本报告作为其 getparameter 端到端证据。

串行顺序(依赖驱动):

1. **jumptable.rs 租约(在占,等释放)**
   a. `JUMPTABLE-EMULFN-0001`(P0,已在板):EmulateFunction 带 `fd`/loader 桥 —
      `get_varnode_value` fallback → loadimage(Ghidra cc:179-192)、LOAD 经 loader 求值、
      失败语义 = 终止全表(删 rs:2557-2569 的 `None => 0` 入表);补表级
      `JumpTable::sanityCheck`(cc:2295-2329)并让 rs:4078/4094 尊重其返回值。
   b. `JUMPTABLE-SELECTION-0001`(P0,已在板):recover_model 恢复 Ghidra 顺序
      override→Assisted→Basic→Basic2(cc:2274-2282),去掉 Trivial 回退;maxtablesize 接 arch。
   c. `JumpBasic::recover_model` 改回调 `find_normalized`(rs:2240 已存在,接到 rs:2482)。
2. **funcdata.rs/fspec.rs/coreaction.rs(阶段克隆地基,= JUMPTABLE-PIPELINE-0001)**
   `Funcdata::truncated_flow`(funcdata_op.cc:792-840)+ `stage_jump_table`
   (funcdata_block.cc:491-547)+ "jumptable" Action 策略组注册并 perform 于 partial。
   ⚠ 策略组 XML 在完整 Ghidra 12.0.4 树 `data/pcodeactions/`,本 oracle checkout 不含 —
   实现前须补取并指纹登记(否则 NO_ORACLE)。
3. **flow.rs 租约(当前在占,排在 1/2 之后串行)**
   `generate_ops` Phase2 改为调用 `self.recover_jump_tables(&mut new_tables, &mut notreached)`
   (rs:766-834 忠实版,现为死代码):失败 → `truncate_indirect_jump(op, mode)`(flow.cc:1443-1445),
   成功 → 逐表项 `new_address` + `fallthru`(flow.cc:805-809);接线 `RecoveryMode` 枚举
   (含 earlyJumpTableFail 的 fail_callother 判定,funcdata_block.cc:554-627)。
   接线 `check_multistage_jumptables`(checkForMultistage, jumptable.cc:2847+)。
4. **收尾门禁**:机制 B 差分(`compare_ghidra.py --summary-only` + `--func getparameter.constprop.0 -v`),
   skeleton 504 显著下降、输出出现 switch;`docs/api/{jumptable,flow,funcdata}.md` 同 commit。

租约注意:jumptable.rs 与 flow.rs 均不可并行持有;1a/1b/1c 在 jumptable.rs 内部也需串行
(同文件单 writer);2 与 3 有调用依赖(3 的接线依赖 2 的 stage 存在),必须 2→3。

## 6. 双侧 fixture 设计(观察面)

**观察面 A — 恢复决策**:对 BRANCHIND@0x3fd5(Rugra)/0x103fd5(oracle):
`recoverJumpTable` 返回的 mode、JumpTable 数、模型类型(Basic)、`numEntries()`
(oracle 应为 88)、`addresstable`(88 项,= r14 基址 + sext(4 字节偏移);镜像基址归一化
0x100000 后逐项相等)、selectguards(应含 `ja 0x41a0` 守卫,range [0,0x58))。

**观察面 B — 可达块集合**:flow/generateOps 后 `bblocks.getSize()`(oracle ≥ 88;Rugra 当前 36)
+ case 体首地址集合(从 addresstable 推出的目标块存在且 STARTBASIC)。

**观察面 C — 端到端文本**:golden 的 `switch((int)pCVar10 - 0x23U & 0xff)` + 48 case
(golden 行 1765-2130)在 Rugra 输出出现;`--func getparameter.constprop.0` skeleton 504 显著降。

fixture 形态:沿用 `tests/oracle/jt_*` runner 模式(锁定 oracle 跑 C++ harness 拿
addressthrough/label/blocks dump,Rust fixture 同观察面);oracle 侧可经
`Funcdata::jtcallback`/OPACTION_DEBUG 或小 harness 在 stageJumpTable 前后各 dump 一次。
元数据按 B2 记录 oracle commit/架构/compiler spec/选项/输入指纹。

## 7. 与在板 TODO 的映射(不新开重复项)

| 本报告发现 | 在板 TODO | 状态 |
|---|---|---|
| partial 克隆 + "jumptable" 策略缺失(根因主件) | `JUMPTABLE-PIPELINE-0001`(P0) | 排队(依赖 Layer1-3) |
| EmulateFunction 无 loader / 失败语义 | `JUMPTABLE-EMULFN-0001`(P0) | 排队 |
| 模型选择顺序 Basic→Trivial ≠ oracle | `JUMPTABLE-SELECTION-0001`(P0) | 排队 |
| generate_ops 静默吞失败(无 truncate) | 本 TODO flow 侧接线点(§5.3) | 新证据,建议并入 PIPELINE-0001 |
| 表级 sanityCheck MISSING | `JUMPTABLE-TABLEAPI-0001`(P0) | 排队 |
| checkForMultistage 空壳 | JUMPTABLE-MULTISTAGE gap(flow_audit) | 在板 |

## 8. 四类决定性语义核对表(Ghidra 签名逐字摘录)

### 8.1 `JumpTable::RecoveryMode Funcdata::stageJumpTable(Funcdata &partial,JumpTable *jt,PcodeOp *op,FlowInfo *flow)` — funcdata_block.cc:491

- **引用/输出参数**:`partial` 按引用跨 BRANCHIND 复用(`isJumptableRecoveryOn` 一次性建);
  `mode` 为 out 参数;`jt` 原地填充后由调用方 `new JumpTable(&trialjt)` 永久化(cc:669)。
- **循环边界/遍历顺序**:无循环;一次性 guard `if (!partial.isJumptableRecoveryOn())`(cc:494)。
- **计数器/累加器**:无。
- **排序/比较键**:无;`partop` 按 SeqNum 精确匹配(`partial.findOp(op->getSeqNum())`,cc:520)。
- Rugra 对应物:**不存在**(try_recover 内联,rs:4339)—— 引用语义(partial 复用/SeqNum 匹配)
  无对应,为根因主件。

### 8.2 `bool JumpBasic::recoverModel(Funcdata *fd,PcodeOp *indop,uint4 matchsize,uint4 maxtablesize)` — jumptable.cc:1418

- **引用/输出参数**:`fd` 只读(但其 partial 的 SSA/CFG 是先决条件);成员 jrange/pathMeld/selectguards 突变。
- **循环边界/遍历顺序**:无自循环;委托 findNormalized(rootbl=indop->getParent(), pathout=-1)。
- **计数器/累加器**:`jrange->getSize() > maxtablesize` 判假阈值;maxtablesize=glb->max_jumptable_size(1024)。
- **排序/比较键**:无。
- Rugra rs:2463-2494:size 判定同;但无 parent → analyzeGuards 缺、matchsize 传参一致;
  **委托链被改写**(rs:2473-2482 直调两步,绕过 find_normalized 的 readonly 救援)。

### 8.3 `void JumpBasic::findNormalized(Funcdata *fd,BlockBasic *rootbl,int4 pathout,uint4 matchsize,uint4 maxtablesize)` — jumptable.cc:1204

- **引用/输出参数**:jrange/setStartVn/setStartOp 突变;readonly 救援经 `MemoryImage(vn->getSpace(),4,16,glb->loader)` 读值。
- **循环边界/遍历顺序**:findSmallestNormal 遍历 `i=1..numCommonVarnode`,`maxsize==matchsize` 即 return(cc:1177-1179);守卫交集遍历 selectguards(cc:1139-1145)。
- **计数器/累加器**:`varnodeIndex` 记录胜出 varnode;`maxsize` 单调收紧(仅 `sz < maxsize` 更新)。
- **排序/比较键**:range 尺寸最小者胜;1 字节 256 特例 `sz != 256 || size != 1` 放行(cc:1184,无 isLoadInPath — Rust rs:2221-2223 多加了 load 判断 = INVENTED,审计已记)。
- Rugra rs:2240-2267 结构在;readonly 救援空壳;调用点未接(§5.1c)。

### 8.4 `void FlowInfo::recoverJumpTables(vector<JumpTable *> &newTables,vector<PcodeOp *> &notreached)` — flow.cc:1427

- **引用/输出参数**:newTables/notreached 为 out 向量;`mode` 逐 op out;`partial` 每次 new 一个标签名 `name@@jump@addr`。
- **循环边界/遍历顺序**:`for(i=0;i<tablelist.size();++i)`,tablelist 顺序 = xrefControlFlow 发现顺序(dead-list 发射序)。
- **计数器/累加器**:无;notreached 去重靠 isInArray 线性扫(cc:1448)。
- **排序/比较键**:无。
- Rugra rs:766-834 忠实(含 truncate/notreached),但 generate_ops 不调用它 = 死代码;
  实际路径 rs:2561 无失败分支 — 遍历顺序等价、失败侧语义缺失。

### 8.5 `uintb EmulateFunction::getVarnodeValue(Varnode *vn) const` — jumptable.cc:179

- **引用/输出参数**:`varnodeMap` 跨 emulatePath 调用共享(同 varnode 恒同值);const 方法。
- **循环边界/遍历顺序**:const 判定 → map 查找 → loader fallback 三级。
- **计数器/累加器**:无。
- **排序/比较键**:map 键 = Varnode* 身份。
- Rugra rs:4146-4157:前两级等价(Arc 指针为键);**fallback 恒 0 ≠ getLoadImageValue** —
  决定 LOAD/rodata 表可读性的语义缺口(JUMPTABLE-EMULFN-0001)。

## 9. 附:证据文件路径

- fresh stderr: `/home/wirs/.cache/rugra-threefunc-main-f7b3c31-XJYadF/artifacts/curl.stderr.log`(行 5550 起)
- fresh stdout: 同目录 `curl.stdout.c`(行 986-1053)
- golden: `/home/wirs/DEV/Rugra/tests/golden/ghidra_curl_1204.c`(行 1649-2130,switch 行 1765)
- 二进制: `/home/wirs/DEV/Rugra/examples/curl`(objdump 0x3fc0-0x3fd5)
- Ghidra oracle: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/{flow.cc, funcdata_block.cc, funcdata_op.cc, jumptable.cc}`
- Rugra: `src/{flow.rs, jumptable.rs, funcdata.rs, coreaction.rs}`
- 审计交叉: `docs/alignment_audit/JUMPTABLE_GAPS_2026-08-22.md`(行号有漂移,本文行号以当前 HEAD 读数为准)
