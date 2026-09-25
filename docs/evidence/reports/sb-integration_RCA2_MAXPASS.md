# RCA-2 探针 — fspec 有效 maxpass/maxdelay 双侧实值测量(Lane AM,只读调查)

> 2026-09-22。工作目录 /home/ls/Rugra(master);oracle 侧 /home/ls/Rugra-wt-sb-oracle。
> 产物仅写 /dev/shm,不改 repo。背景:D14_ACTIVEPARAM.md §RCA-2——activeparam 9v2 之外,
> 相位差 oracle=[9,9,0](build@pass2) vs rugra=[2,2,2,0](build@pass3)。
> 本节起为静态链复核,每节独立写盘(防崩溃)。

## §1 Ghidra 静态链(完整枚举,oracle=e40ed130 已核验)

### maxpass 写点(全 corpus grep `setMaxPass|maxpass =`,仅 3 处)

| # | 位置 | 代码 | 语义 |
|---|---|---|---|
| W1 | fspec.cc:1942 `ParamActive::ParamActive` | `maxpass = 0` | 构造默认 0 |
| W2 | fspec.cc:2007 `ParamActive::freePlaceholderSlot` | `maxpass = 0` | "next 遍后停止分析";**12.0.4 全 corpus 无调用者=死代码**(仅 splitTrial/joinTrial 有 `stackplaceholder>=0` 卫哨) |
| W3 | fspec.cc:5335-5338 `FuncCallSpecs::initActiveInput` | `maxdelay=getMaxInputDelay(); if(maxdelay>0) maxdelay=3; setMaxPass(maxdelay)` | **取值域只能是 {0, 3, 负}** |

### maxdelay 取值链

fspec.hh:990 `getMaxInputDelay()` → `input->getMaxDelay()` (ParamList, fspec.hh:642)
→ fspec.cc:1153-1163(遍历 pentry group 取各空间 delay 最大值;赋值点 :1156/:1160-1161)。
delay 源 = ProtoModel 的 ParamList 实例(x86-64 SysV default 模型,register 空间 delay)。

### numpasses 写点(全 corpus grep `finishPass`,仅 2 处)

| # | 位置 | 语义 |
|---|---|---|
| P1 | coreaction.cc:1744 `ActionActiveParam::apply` | 每次 apply +1(主计数器) |
| P2 | fspec.cc:5186-5188 `commitNewInputs` | 仅 varargs 且 numPasses>0 时重置为 1("Don't totally reset the pass counter") |

### fullychecked 写点

- coreaction.cc:1745-1746(numpasses>maxpass,ActiveParam 主路径)
- coreaction.cc:1938-1939(**ActionReturnRecovery,output 侧,与 input 无关**)
- checkInputTrialUse(fspec.cc:5585+)**不写** fullychecked/maxpass/numpasses(已逐行核实)

### clearActiveInput 路径(直接 CALL 解锁原型的唯一收尾)

- coreaction.cc:1755(ActiveParam build:trimmable && fullychecked → resolveModel/deriveInputMap/buildInputFromTrials/clearActiveInput)
- fspec.cc:5185(commitNewInputs,仅被 deindirect:5466 / forceSet:5497 调用)

### 静态矛盾(本探针立项依据)

ActionActiveParam::apply(coreaction.cc:1725-1771)逐行相位推演:
- maxpass=0 → [N,0](1 个非零窗口)
- maxpass=3 → [N,N,N,N,0](4 个非零窗口)
- **实测 oracle [9,9,0] 需有效 maxpass=1;rugra [2,2,2,0] 需有效 maxpass=2——{0,3} 都推不出来。**
⇒ 必有一个环节假设错误(候选:getMaxInputDelay 实值/调用时机、initActiveInput 重入、
numpasses 在别处被改、或 D14 相位解读有误)。转实测裁决。

## §1.5 【更正】freePlaceholderSlot 不是死代码——占位符生命周期链(静态链真正闭环)

§1 W2 最初判"死代码"是 **grep 笔误**(`grep -v "^fspec.hh"` 把整个 fspec.hh 排除了)。
真实链路(fsSpec.hh inline):

```
createPlaceholder (fspec.cc:4843-4852, CALL 加 LOAD-from-spacebase 占位输入)
  → setStackPlaceholderSlot(slot)  [fspec.hh:1672]
      → if (isinputactive) activeinput.setPlaceholderSlot()   [占 trial slot]
解除路径 A:RuleLoadVarnode::applyOp (ruleaction.cc:4283-4305)
  → LOAD 解析成 stack COPY 时 → fc->resolveSpacebaseRelative(data,refvn) [fspec.cc:4870]
  → 若 phvn 即占位输入 → abortSpacebaseRelative (fspec.cc:4910-4920)
  → clearStackPlaceholderSlot() [fspec.hh:1673-1675]
      → if (isinputactive) activeinput.freePlaceholderSlot() → ★ maxpass = 0 ★
解除路径 B:heritage.cc:2052(stack heritage 后兜底 abort 未解析占位符)
  → abortSpacebaseRelative → 同上 → ★ maxpass = 0 ★
```

⇒ **有效 maxpass 动态模型:initActiveInput 设 3(maxdelay>0 时)→ 占位符被解析/中止
的那个 pass 结束后 maxpass=0 → 下一次 ActiveParam::apply 即 markFullyChecked+build**。
- oracle build@apply2 ⟺ 占位符在 apply1 与 apply2 之间被解除
- rugra build@apply3 ⟺ 占位符在 apply2 与 apply3 之间被解除(或晚一拍)
⇒ RCA-2 相位差的本质候选:**stack 占位符解除时机(= stack heritage + RuleLoadVarnode
节奏)相对 ActiveParam 的相位**,而非 initActiveInput 常量。

## §2 Rust 侧静态链对照(src/,master)

| 环节 | Ghidra | Rugra | 状态 |
|---|---|---|---|
| init_active_input cap | fspec.cc:5331-5339 | fspec.rs:2382-2392 | 逐字同构({0,3}) |
| ParamActive::maxpass 字段 | fspec.hh:290/313-314 | fspec.rs:4091/4151-4153 | ✓ |
| free_placeholder_slot→maxpass=0 | fspec.cc:1995-2008 | fspec.rs:4374-4389 | ✓ |
| clear_stack_placeholder_slot→free | fspec.hh:1673-1675 | fspec.rs:2803-2816 | ✓(条件同为 input_recovery_active) |
| create_placeholder(+set slot) | fspec.cc:4843-4852 | fspec.rs:2840(coreaction.rs:9787 调用) | ✓ |
| abort_spacebase_relative | fspec.cc:4910-4920 | fspec.rs:2767 | ✓ |
| resolve_spacebase_relative | fspec.cc:4870-4903 | fspec.rs:2880(RuleLoadVarnode:ruleaction.rs:17053 调用) | ✓ |
| Heritage::clearStackPlaceholders | heritage.cc:2046-2053 | heritage.rs:3826-3851 | ✓ |
| heritage 驱动门控 | heritage.cc:2684-2689 | heritage.rs:4800-4826 | ✓(含 `pass < delay` continue) |
| HeritageInfo hasCallPlaceholders | heritage.cc:198/204-205 | heritage.rs:435(reset)/406-427 | ✓ |
| ActionActiveParam::apply 计数点 | coreaction.cc:1739-1757 | coreaction.rs:8958-9030 | 逐行同构(D14 已核) |
| 现有 env 钩子 | — | RUGRA_DEBUG_ACTIVEPARAM(coreaction.rs:8959,仅打 n_calls,**无逐 call maxpass/numpasses**);RUGRA_HERITAGE_TRACE(heritage.rs:1794) | 钩子不足,需探针 |

**静态结论**:双侧占位符生命周期链完整同构 ⇒ 相位差不可能来自"缺移植",只能来自
**运行时值/时机**。两个决定性未测值:
1. **initActiveInput 时 getMaxInputDelay() 实值**(决定初始 maxpass=0 还是 3);
2. **stack 空间(=spacebase 空间)的 delay 实值**——`if (pass < info->delay) continue`
   门控该空间第一次 heritage 的 pass 号,而 clearStackPlaceholders 恰在其首次 heritage
   前触发(heritage.cc:2688-2689),把 maxpass 砸到 0 ⇒ **stack delay=1 → build@apply2
   (oracle 相位);delay=2 → build@apply3(rugra 相位)**。备选机制:RuleLoadVarnode 提前
   解析占位符(越早 → 越早 build)。二者均需实测区分。

## §3 oracle 实测结果(rca2_oracle.stderr,274 行 RCA2 记录)

### 初值(D14 未测的关键值)

**9/9 call 全部 `maxdelay_in=1 → maxpass_set=3`**(cap `>0→3` 生效),全部 inputlocked=0
(RCA-1 佐证:BFD 无签名)。space 表:`stack(type=IPTR_SPACEBASE,idx=8,delay=1,ph=1)`、
`ram(delay=1)`、`register(delay=0)`、`unique(delay=0)`。

### 相位时间线(投影可见段,root->reset 之后)

| 时点 | 事件 | 证据 |
|---|---|---|
| mainloop pass1 heritage(hit 时 hpass=0) | stack delay=1 未到期,ph=1 保留 | `heritage-run unique/register hpass=0`(无 stack) |
| pass1 activeparam apply | 9 call 全部 `numpasses=1 maxpass=3 phslot=1`;2534(CALLIND) trimmable=0;全部 1≤3 → still-work +1 → **count=9** | `activeparam-apply site=… numpasses=1 maxpass=3` ×9 |
| **pass1 后段规则池** | **RuleLoadVarnode 逐个解析 9 个占位 LOAD** → resolveSpacebaseRelative → abortSpacebaseRelative → freePlaceholderSlot → **maxpass 3→0(phslot→-1)**;首个 abort(2534)紧随 apply1 块后 | `ruleload-resolve ram:2534/505d/…/513a` + `abortSpacebaseRelative … maxpass_before=3` + `freePlaceholderSlot maxpass_was=3` ×9 |
| pass2 heritage(hpass=1) | stack 首次 heritage,clearStackPlaceholders 触发但**无事可做**(占位已全部由规则解析;loop 0 abort) | `clearStackPlaceholders space=stack hpass=1 ncalls=9`(其后无 abort 行) |
| pass2 activeparam dump+apply | dump:9 call `numpasses=1 maxpass=0 fully=0 phslot=-1` → apply:finishPass→2 > 0 → markFullyChecked + build + clearActiveInput → **count=9** | dump 行 + `numpasses=2 maxpass=0 trimmable=1` ×9 |
| pass3 activeparam | inputactive=0(已清) → **count=0** | dump `inputactive=0 numpasses=2 fully=1` |

⇒ **oracle 有效 maxpass 动态模型:初值 3 → pass1 规则段被 freePlaceholderSlot 砸到 0 →
pass2 build**。投影 [9,9,0] 每一项均被逐行解释。观测到的"有效 maxpass=1"是
"3 起步 + pass1 内解除占位"的合成相位,不是常量赋值。

### 附带观察

- followFlow 阶段已有 5 轮 heritage()(pass 0..4)+一次 clear(ncalls=8,占位未建,无操作),
  `root->reset()` 将 Heritage 重置(pass→0,ph→1),投影不可见;pre-perform 时 9 个
  callspec 已存在(followFlow 创建)但全部 inputactive=0(initActiveInput 在 perform 内
  的 funclink 才调用)。
- 2534(CALLIND)pass1 trimmable=0、pass2 numpasses=2>0 → trimmable=1,与
  coreaction.cc:1741 逐字一致。

## §4 rugra 实测(17f1c34 副本 + 独立 /dev/shm target;打印级 patch,零语义改动)

探针打印点:`init_active_input`(maxdelay_in/maxpass_set)、`activeparam-apply`
(逐 call numpasses/maxpass/trimmable/exceeded)、`placeholder-guard`(abort/resolve 的
占位卫兵命中)、`free_placeholder_slot`(maxpass_was)、`clear_stack_placeholders`。
运行:examples/curl_decompile 全语料(与 sb-rust 投影同 tree 17f1c34)。

### 4.1 默认态(有锁定台账,= 投影环境同族)

next_url 段(仅 2 个 unlocked call:505d/50ae,与 D14 §3 一致):

```
init_active_input site=0x505d maxdelay_in=2 maxpass_set=3   ← maxdelay_in=2!
init_active_input site=0x50ae maxdelay_in=2 maxpass_set=3
activeparam-apply 0x505d numpasses=1 maxpass=3  (apply1, 1≤3 → still-work)
activeparam-apply 0x50ae numpasses=1 maxpass=3
activeparam-apply 0x505d numpasses=2 maxpass=3  (apply2, 2≤3 → still-work)
activeparam-apply 0x50ae numpasses=2 maxpass=3
placeholder-guard 0x505d maxpass_before=3 → free_placeholder_slot(maxpass 3→0)
placeholder-guard 0x50ae maxpass_before=3 → free_placeholder_slot(maxpass 3→0)
```

- **flip(maxpass 3→0)发生在 apply2 之后** → 下一次 apply numpasses=3 > 0 → build@pass3
  ⇒ 投影 [2,2,2,0] 的第三窗口 = build 遍,与 oracle 的 build@pass2 相位差 +1 遍。
- 其余 7 个 call 的 placeholder-guard 打出 maxpass_before=0(input 不活跃,
  ParamActive ctor 值 0)——锁定 call 的 resolve 走 locked-param 路径,与 Ghidra 同构。

### 4.2 无签名对照(RUGRA_DISABLE_CALLSPEC_LINK=1,任务 #4)

- **9/9 call 全部 init_active_input**(50ce/50d6/505d/5065/5128/513a/50ae/50b8/50fa)
  → 复现 oracle 的 9-call 计数域 ⇒ **RCA-1(计数 9v2)确证为环境差**(台账锁原型),
  探针级证据首次直接观测到 9/9 解锁。
- **相位不变**:apply1(np=1,mp=3)→ apply2(np=2,mp=3)→ flip → build@pass3。
  ⇒ **RCA-2 相位差与锁/签名环境无关,是 rugra 内在分歧**。

### 4.3 stack delay 嫌疑与决定性实验

双侧对齐缺口:
- oracle 实测 `HeritageInfo[stack].delay = 1`(fixture dump `[stack:idx=8,type=2,delay=1,ph=1]`)
- rugra `src/space.rs get_delay(): AddressSpace::Stack => 2`

Ghidra 真源核验(本 session 逐行读):
- architecture.cc:1011 `VarnodeData point = translate->getRegister(registerName)` ——RSP 在
  **register 空间(delay=0)**
- architecture.cc:565 `SpacebaseSpace(..., ptrdata.space->getDelay()+1, ...)` ——是
  **ptrdata.space(register,0)+1 = 1**,不是 basespace(ram,1)+1
- translate.cc:57-59 `AddrSpace(..., ind, 0, dl, dl)` ——dl 即 heritage delay
- **rugra space.rs:133-150 的注释把 ptrdata.space 误读成 basespace,得出 ram+1=2**
  (MAINDIFF-UNIQLEAK-0001 当时的"oracle first stack pass at pass 2"观察按
  mainloop-round 计数恰好对应 delay=1,当时被误译成 delay=2)。

**实验**(副本内单行改 `Stack => 2` → `1`,重建重跑全语料):

| 量 | oracle | rugra 默认 | rugra delay=1 实验 |
|---|---|---|---|
| init maxdelay_in | 1 | 2 | **1(=oracle)** |
| init maxpass | 3 | 3 | 3 |
| flip(maxpass→0)时点 | apply1 后(pass1 规则段) | apply2 后 | **apply1 后(=oracle)** |

⇒ **单行 delay 修正即把两个可观测量(maxdelay_in、flip 相位)都拉回 oracle 值:
充分性证明。** maxdelay_in 链 = ParamList::calcDelay(fspec.rs:6376-6382)取各 pentry
空间 delay 最大值,SysV 模型 stack pentry 的 delay 即 stack 空间 delay(oracle=1/rugra=2)。

实验附带观察(如实记录,需正式修复时重验):delay=1 后 next_url 的 mainloop 轮形态
改变(apply 只见 np=1 一组、flip 后无 np=2/np=3 打印,最终 C 仍产出已解析
strstr/strrchr 原型),提示 stack delay 还耦合 rugra 其他 heritage/收敛逻辑
(MAINDIFF-UNIQLEAK-0001 同域);正式修复必须走全量门禁,不可盲翻常量。

## §5 裁决

### 双侧终值表

| 量 | Ghidra oracle(e40ed130 实测) | Rugra(17f1c34 实测) | 定性 |
|---|---|---|---|
| initActiveInput maxdelay_in | **1**(9/9 call) | **2**(unlocked call) | 真差(stack delay) |
| initActiveInput maxpass_set | 3(cap 生效) | 3(cap 生效) | 一致 |
| maxpass 翻转机制 | pass1 规则段 RuleLoadVarnode→resolve→abort→freePlaceholderSlot | pass2 规则段同链路 | 机制同构,时机差 1 遍 |
| build 遍(有效 maxpass 相位) | pass2(投影 [9,9,0]) | pass3(投影 [2,2,2,0]) | 真差(相位 +1) |
| stack 空间 heritage delay | **1**(HeritageInfo 实测) | **2**(space.rs 写死) | **根因** |

### 一句话定因

**RCA-2 是真语义差,根因 = rugra `src/space.rs::get_delay()` 将 Stack 空间 delay
写死为 2,而 Ghidra 12.0.4 的 stack 空间 delay = 指针寄存器空间(register,delay 0)
+ 1 = 1(architecture.cc:565 `ptrdata.space->getDelay()+1`,rugra 注释误读为
basespace+1);该 delay 既经 ParamList::calcDelay 抬高 getMaxInputDelay(1 vs 2,
initActiveInput 双侧 cap 到 3 后无直接差),又经 `Heritage::heritage` 的
`pass < info->delay` 门把 stack 首次 heritage 及占位符解析窗口推迟 1 遍,
令 freePlaceholderSlot(maxpass→0)与 ActionActiveParam 的 build 各晚 1 遍——
即"有效 maxpass 1 vs 2"的相位差全由这一个常量造成。**

与 RCA-1 正交:nosig 对照显示锁/签名环境只改计数域(9v2),不改相位。

### 修复建议(给 AJ 后续 lane)

1. `src/space.rs get_delay(): AddressSpace::Stack => 2` 改为 1,并更正
   133-150 注释(ptrdata.space 而非 basespace);同步更新 docs/api/space.md。
2. 必须同 commit 重跑:MAINDIFF-UNIQLEAK-0001 的 fixture(其结论建立在该 delay 上)、
   curl/httpd E2E 差分门禁、sb-rust 投影重产(预期 activeparam 相位 [.., .., 0] 对齐
   oracle build@pass2)。实验已示 pipeline 轮形态会动,需全量门禁验证,不是无害翻转。
3. 登记建议:`ACTIVEPARAM-COUNT-9V2-0001` 的 RCA-2 子项**关闭为已定因**
   (真差,root=space.rs stack delay),修复动作并入或交叉引用
   `FSPEC-0002`/`MAINDIFF-UNIQLEAK-0001`(同 delay 域);RCA-1 侧补一条
   nosig 双态开关证据(本探针 RUGRA_DISABLE_CALLSPEC_LINK=1 → 9/9 解锁,
   投影产线可比性开关已有现成 env,无需新代码)。

### 产物清单

- oracle:`probe/rca2_oracle.bin`(instrumented)、`rca2_oracle.stderr`(274 行 RCA2)、
  `rca2_oracle.projection`;构建脚本 `probe/build_oracle_probe.sh`、fixture
  `probe/stage_projection_rca2.cc`(archive+patch 全在 /tmp,repo 零改动)。
- rugra:`/dev/shm/rugra-rca2-rugra`(17f1c34 archive+打印 patch,delay 实验态=1)、
  target `/dev/shm/rugra-rca2-target`;日志 `probe/rca2_rugra_{default,nosig,delay1}.stderr`。
- 报告:本文件 `/dev/shm/rugra-tests/sb-integration/RCA2_MAXPASS.md`。


- 复刻 d9_calib.sh 流程:git-archive oracle cpp 到 /tmp 临时目录 → 打印级 patch
  (仅 stderr 打印,不改语义:heritage.cc clearStackPlaceholders、fspec.cc
  abortSpacebaseRelative/initActiveInput、ruleaction.cc resolveSpacebaseRelative 调用点)
  → fixture 副本(/dev/shm/.../probe/stage_projection_rca2.cc)在 break 命中
  activeparam/heritage 时 dump 全部 FuncCallSpecs 的
  isInputActive/numpasses/maxpass/fullychecked/stackPlaceholderSlot,并 dump
  HeritageInfo 表(space 名/delay/hasCallPlaceholders)与 stack 空间 delay。
- 运行:examples/curl,entry=4ff0(next_url),对照 D14 投影。

(§3 实测结果、§4 rugra 实测、§5 裁决,追加于下)
