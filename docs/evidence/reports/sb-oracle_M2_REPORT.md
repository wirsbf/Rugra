# Lane A M2 报告 — next_url oracle 侧全量 stage 投影(v1.2.2 现行版)

日期: 2026-09-22(初版)/ 2026-09-22 v1.2.1 更新 / 2026-09-22 v1.2.2 D9 更新 | worktree: wt/sb-oracle | 产物: next_url.oracle.projection

> **规范增补已批准落地**:v1.2 指针 vn 描述符增补 = master `a31a3cb`;v1.2.1 opcode 域勘误
> (枚举域 `get_opname`) = master `85d78a7`;v1.2.2 D9 事件枚举粒度(perform 级)+ D10
> 加载契约 = master `6553193`。本文与产物均已按 v1.2.2 同步。

## 产物统计(v1.2.2 D9 现行)

| 指标 | 值 |
|---|---|
| 文件 | /dev/shm/rugra-tests/sb-oracle/next_url.oracle.projection |
| 大小 | 6,081,486 bytes(D9 后;v1.2.1 changed-apply 粒度前值 6,410,681) |
| sha256 | 8144a7bf482c8cd53171efae88c6607cb9ad95c9c2ffdfbec46aee0d23b14ab7 |
| @BEGIN/@END/@SNAP | 335 / 335 / 335(一一配对,seq 1..335 连续,LIFO 嵌套零违例;v1.2.1 前值 355) |
| @RESTART | 0(next_url 单轮完成,curstart 0→-1,首轮本就不发) |
| @SNAP 总 ops | 96,457(max snap 1836,min 219;前值 101,892) |
| opcode 域 | CPUI 枚举域(v1.2.1),全部 `^[A-Z][A-Z0-9_]*$` |
| 确定性 | 同机三跑字节级一致(ASLR 开启);三跑 cmp 零差异且等于 metadata pin |

## v1.2.2 D9 增补:事件枚举粒度 = perform 级

**裁决**(master `6553193`,STAGE_BISECT_SPEC_1204.md v1.2.2 节):一个事件对(@BEGIN/@END/@SNAP)
= 该树节点的**一次 perform() 调用**;repeatapply 叶的整个收敛过程(rule_repeatapply 的
action.cc do-while 在**单次** perform 内跑完)是**单事件**,@END count=收敛后累计值、
apply=内部多趟自增;BREAK_ACTION 不用于 v1 枚举。

**落地**(commit `7827856`,fixture 生产端):
- 删除 repeatapply 叶的 break_action 设置与 status_actionbreak 的 close-and-reopen 分支
  (~15 行);break_start-only 协议;同名双 unreachable 叶的指针级断点寻址按 v1.2.2 保留。
- closeInactive 无需改:pool 的 perform 完结后 status 回到 status_start(action.cc
  perform 尾部,无 onceperfunc 标志),自然落入下一 stop 的关闭条件;@SNAP 在下一 stop
  拍摄 = pool 完成后,边界正确。

**事件计数新旧对照**(逐路径 diff,全部差异已归因):

| 路径 | v1.2.1(changed-apply 粒度) | v1.2.2(perform 级) | 差异归因 |
|---|---|---|---|
| universal:fullloop:mainloop:stackstall:oppool1 | 28 | 12 | 旧 28 = 12 个 break_start stop + 16 个 actionbreak stop 逐事件;新 12 = 12 次 perform()(=stackstall pass 数,与旧 run 的 break_start stop 数一致,底层计算不变) |
| universal:fullloop:mainloop:oppool2 | 10 | 8 | 同上:旧含 2 个 actionbreak 拆分 |
| universal:cleanup | 2 | 1 | 同上:旧含 1 个 actionbreak 拆分 |
| universal:fullloop:donothing | 4 | 3 | **旧选择器按 rule_repeatapply 标志过匹配**:ActionDoNothing 本身带 rule_repeatapply(coreaction.hh:504),旧代码误给它上了 break_action,把其单次 perform 拆成 2 事件;新协议下 donothing 每次 perform 恰 1 事件(如 seq154 result=1 apply=1) |
| 其余全部路径 | 不变 | 不变 | — |
| **总 @BEGIN** | **355** | **335** | −20 = (16+2+1+1) |

pool 事件的 @END 现携带收敛后累计值:oppool1 pass 1 = `result=863 count=863 apply=7`
(旧协议拆成 7 个事件 430/697/785/843/856/862/863)。tests=0 是 break_start 协议的一致
副产物(每次 perform 先停在 break,resume 走 case status_breakstarthit,跳过
count_tests+=1),双侧同口径即可比(D9)。

**对拍提示**:Rugra 侧 perform 级 oppool1 事件若为 18(此前 Lane 估计),则与 oracle 12
是**真实行为分歧**(stackstall/mainloop pass 次数不同),正是消费端首个分歧点要暴露的
对象,不属本生产端问题。

## META 头部字段(现行全指纹)

```
META side=oracle oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b arch=x86:LE:64:default cspec=gcc
META analysis_options=default build_flags=v1-no-OPACTION_DEBUG
META binary_sha256=8af50bca2f812580933fbbf125b66ce8ba4acfe88ef4435c89ac72356f122d41 func_entry=0x4ff0 func_name=next_url load_mode=single_function_bfd
META producer=f5d54a0a861359f512fa15ed8a3a816cf3789a37 maxrestarts=1 unique_base=0x364200
```

producer = `git hash-object tests/oracle/stage_projection_1204.cc`(fixture git blob sha;v1.2.2 D9 版)。

### 身份键三键终值与来源(D1-D3 裁决落地,conf 派生非硬编码)

| 键 | 终值 | 来源(装载链实证,fixture 运行时自 conf 对象派生并打印 provenance 行) |
|---|---|---|
| arch | `x86:LE:64:default` | x86.ldefs `<language id="x86:LE:64:default">`;sleigh_arch.cc:336-338 按 baseid(前 4 段)匹配 |
| cspec | `gcc` | bfd_arch.cc:97 elf64 分支置 `archid="x86:LE:64:default:gcc"` → sleigh_arch.cc:359 取末段 → `LanguageDescription::getCompiler("gcc")` 精确命中 ldefs `<compiler id="gcc" spec="x86-64-gcc.cspec">`;**`x86-64-gcc` 是 spec 文件名不是 id** |
| analysis_options | `default` | 如实:fixture 除断点观测外**不注入任何非默认分析选项**(无 options->set 调用);runner 传字面 `default` |

fixture stderr provenance 行:`[stage_projection] archid=x86:LE:64:default:gcc arch=x86:LE:64:default cspec=gcc`。

## v1.2 增补(已批准):指针值 vn 描述符 — master `a31a3cb`

**发现**:SLEIGH/Ghidra 在三处把**堆对象指针**直接编码进 varnode 值,ASLR 下逐进程变化,
oracle 自身两跑都不同(已实证 diff,共 3 类值):

| 类别 | Ghidra 编码源 | 出现次数(next_url) |
|---|---|---|
| load/store spaceid 常量 | sleigh.cc:236/269 `(uintb)(uintp)spc` | 12,492 |
| CALL input0(fspec 空间) | Funcdata::newVarnodeCallSpecs(指针) | 2,840 |
| INDIRECT 引用(iop 空间) | Funcdata::newVarnodeIop(指针) | 12,944 |

Ghidra 下游用 `getSpaceFromConst()`/指针 cast 解码回对象(constseq.cc:911、coreaction.cc:976),
指针值本身无跨进程语义。不做规范化则双侧投影永远"不同",且噪声淹没真分歧。

**已实现并被 v1.2 增补(master `a31a3cb`)批准的规范化(双射,不损失可分辨性)**:

- `s:<spacename>` — spaceid 常量:精确匹配本进程全部注册 AddrSpace 对象地址表→稳定空间名。
- `f:<addr>:<time>` — fspec 空间:渲染**宿主 CALL op 自己的 SeqNum**(一个 call site 恰好一个
  FuncCallSpecs,不同 call site 保持不同身份;不同轮次同 site 重 apply 也不碰撞,seq 全局唯一)。
- `o:<addr>:<time>` / `o:-` — iop 空间:渲染**被引用 PcodeOp 的 SeqNum**(每个 @SNAP 建一次
  live-op 指针表反查;查不到兜底 `o:-`,next_url 全程零 `o:-`)。

其余类别不动:unique 原始 offset 直出不规范化(规范 BLOCKER-1)、命名空间精确 offset、
常量 `c:`、空槽 `-`。**Lane C(Rust emitter)与 Lane R(消费端 parser)须按同一规则跟进**
(消费端 V1_OPCODE_RE 放宽/V1_VN_RE 扩前缀属 Lane R 域,见 PRE_RECON D13)。

## v1.2.1 勘误(已批准):opcode 域 = CPUI 枚举域 — master `85d78a7`

- writeOp 发射改为 `get_opname(op->code())`(opcodes.hh:133,opcode_name 正典 74 名全大写表,
  逐名同序核对);弃用 `getOpName()`(typeop.cc name 域)——name 域**有损**:
  `goto`=BRANCH+CBRANCH、`+`=INT_ADD/FLOAT_ADD/PTRADD、`SUB`=SUBPIECE 非 INT_SUB、
  `INT_LESS`/`INT_SLESS` 同渲 `<`,且符号拼写破坏消费端 tokenizer。
- `code()` 与 `getOpName()` 解引用同一 TypeOp 指针,空指针安全性不变。
- runner 校验器:`OPCODE_DOMAIN = "cpui"` 数据驱动名表常量(74 名,表序对齐 opcodes.cc;
  保留 typeop 34 名历史域与 any 兜底,一行切换),token 形状 `^[A-Z][A-Z0-9_]*$`;
  vn 文法含 `s:/f:/o:`(f:/o: addr:time 双段 hex,o:- 兜底)。
- META 仅 producer 行变化(a3aca4b5…→8776a327…);arch/cspec/analysis_options 字面与 v1.0
  版相同(现自 conf 派生,见上节)。

## op-line 发射集中性

全部 op-line 仍由单一函数 writeOp 发射;描述符文法唯一出口 writeVarnodeDescriptor
(s:/f:/o:/c:/u:/n:/- 集中定义,含全部依据行号注释);opcode 域唯一出口 get_opname。

## 验证命令(可复跑,对 commit 后的 repo 原生 runner)

```bash
cd /home/ls/Rugra-wt-sb-oracle
bash tools/run_stage_projection_oracle.sh   # 端到端:锁定校验→插桩构建→步进→v1.2.1/v1.2.2 全流校验→安装
sha256sum /dev/shm/rugra-tests/sb-oracle/next_url.oracle.projection
# 期望 8144a7bf482c8cd53171efae88c6607cb9ad95c9c2ffdfbec46aee0d23b14ab7(字节级,与 metadata pin 同源)
python3 /home/ls/Rugra/tools/stage_bisect.py --v1 \
  /dev/shm/rugra-tests/sb-oracle/next_url.oracle.projection \
  /dev/shm/rugra-tests/sb-oracle/next_url.oracle.projection   # 自比:kind: MATCH, exit 0(已验证)
```

结构校验(runner 内嵌全流校验):META 13 键逐键对 pin、seq 连续/配对/LIFO/@SNAP 计数/
opcode 名表+形状/vn 描述符合法性,全部通过,零错误。三跑字节一致见上表(D9 后
2026-09-22 复跑,commit `7827856`)。
