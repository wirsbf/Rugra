# REMAINING_DELTA — v1.2.1 消费端下的双侧投影剩余差集核对(Lane AG,只读)

> 2026-09-22。消费端 = master `e561762`(tools/stage_bisect.py v1.2.1:枚举域 OPCODE_RE +
> 74 名表 advisory + s/f/o vn 描述符)。oracle 侧 = `wt/sb-oracle@614b646` 系列重产投影
> `/dev/shm/rugra-tests/sb-oracle/next_url.oracle.projection`(355 stages / 101,892 ops,
> 6.41MB)。rugra 侧 = 旧投影 `/dev/shm/rugra-tests/sb-rust/next_url.rugra.projection`
> (479 stages / 129,745 ops,8.05MB,producer=`rugra-tree-17f1c34`,emitter 定稿 `05c8314`)。
> 本报告不改 repo/worktree;副本/脚本/日志均在 sb-integration/(`layered_probe.py`、
> `L*_*.projection`、`run_L*.log`)。D9/D10 在途裁决,本文不预设结论。

## 0. oracle 新投影 META 头确认(producer=614b646 系列)

```
META side=oracle oracle_commit=e40ed130…376b arch=x86:LE:64:default cspec=gcc
META analysis_options=default build_flags=v1-no-OPACTION_DEBUG
META binary_sha256=8af50bca…41d func_entry=0x4ff0 func_name=next_url load_mode=single_function_bfd
META producer=8776a327f8d88f9757fa4150580ee7fea6548caa maxrestarts=1 unique_base=0x364200
```

- 13 键齐全,身份键 9 项全部规范化(arch/cspec/analysis_options 已与规范钦定字面一致)。
- producer=8776a327(harness blob sha);harness 源 = `wt/sb-oracle tests/oracle/
  stage_projection_1204.cc@614b646`,op-line 已切 `get_opname(op->code())` 枚举域(§3)。

## 1. 分层实跑结果(master 消费端,逐层解锁;副本构造法同 PRE_RECON §4.2)

| 层 | 解锁动作(副本侧) | 消费端裁决 | 卡点定位 | 性质 |
|---|---|---|---|---|
| L1 | 原文件直跑 | `V1_META_MISMATCH` exit 1 | 3 身份键:`analysis_options`(default vs default_actions,callspec_link=true)、`arch`(x86:LE:64:default vs x86_64)、`cspec`(gcc vs x86-64-gcc) | **emitter 可修**(P1-P3);两侧文件均无 FormatError,v1.2.1 文法全通过 |
| L2 | rugra META 三键改 oracle 字面 | `V1_OP_LINE_DIVERGENCE` | stage 2 `universal:start` op 0:oracle 多 2 行 `2534:54 CALLIND` + `2534:2cc RETURN`(PLT 占位) | **D10 加载/流契约**(裁决在途);PLT op 全文件 2,993 行已从 L3 副本剔除验证 |
| L3 | oracle 副本删 `2534:*` 行(@SNAP 计数同步 −2993) | `V1_OP_LINE_DIVERGENCE` | 同 stage op 4:`in=s:ram,…` vs `in=c:3:8,…`(STORE 首槽) | **emitter 可修**(P5,D5) |
| L4 | L2 + rugra quirk 名按表映射(MULTIEQUAL→BUILD 等 4 项) | 不变(仍 op 4 s:ram) | quirk 拼写在本语料序中不是**首个**卡点(MULTIEQUAL 首现于 file line 5933 之后的 SSA 快照),但属硬不兼容域:31,558 行 off-table advisory | **emitter 可修**(P4) |
| L5 | oracle 副本 `s:ram`→`c:3:8`(D5 反向归一) | `V1_OP_LINE_DIVERGENCE` | 同 stage op 60:**同内容不同 SeqNum time**:`5040:119` vs `5040:ea`(Δ=0x2f=47)。全快照漂移直方图 {0:146, +47:63} 双峰 | **非 emitter 层**:初始 IR 编号契约,与 D10 同源(见 §1.1) |
| L6 | L5 + oracle 副本 `f:/o:`→`n:iop:0:8`(D6 反向归一) | 不变(仍 op 60) | f:/o: 归零不是本序首个卡点,但 oracle 侧 12,492(s:)+12,944(o:)+~2,840(f:) 槽位与 rugra `n:iop:0:8` 归零互不可比 | **emitter 可修**(P6/P7,D6) |
| L7 | 离线 time 掩码(`addr:time`→`addr`)逐 stage 扫描 | (offline) | 下一层链:①op 209 起地址序分歧(0x50b8 RETURN vs 0x50c0)→②@END 属性差:seq 18 `activeparam` result/count **9 vs 2**→③stage-key 差:index 24/seq 29 `oppool1` vs `lanedivide`(D9);共享 stage 对齐行差分类:addr 14,903 / content 4,665 / d= 15 | ①D10 尾部控制流 op 集(4 op:0x50b8 RETURN、0x50fa CALL/BRANCH/RETURN 多寡)②**新发现 D14**(action 计数语义,管线层)③D9(裁决在途) |

### 1.1 SeqNum time 漂移实证(新证据,D10 影响面扩大)

`universal:start` 初始快照 715(oracle 去 PLT 后) vs 717(rugra) 行,**内容多重集差仅 4 行**
(oracle-only:`50fa BRANCH in=n:ram:2530:1`;rugra-only:`50b8 RETURN`、`50fa CALL`、
`50fa RETURN`)——其余 713 行 time 掩码后逐字相等,但 oracle 的 time 从 0x5040 起恒 +47,
且 0x50b8/0x50c0 段地址-time 关联错位(同 time 值绑到不同地址的 op)。结论:**即使 D10 裁决为
oracle 限流删行,SeqNum 分配序仍暴露流深度差**(占位/injection op 创建消耗了 time 计数);
反之若裁决为 rugra 补流,rugra 需同时复现创建序。D10 修复验收必须含 time 对齐,不能只对行集。

## 2. C 侧对齐 punch list 终版(供 C-alignment lane 直接执行)

改动主战场 = `wt/sb-rust examples/curl_decompile.rs`(`stage_vn` L2179 / `stage_snapshot`
L2197 / `emit_stage_projection` META 段 L2497-2521)。src/ 仅只读访问器或既有 API
(`op.rs:300 parent`、`constseq.rs:502 get_space_from_const`、`funcdata.rs:4244
get_op_from_const`+`call_spec` 判别、`space.rs:329 name()`)。

| # | 项 | 现值(rugra 投影) | 目标值(oracle 新投影逐键抄录) | 改动位置(预估) | 验证方法 |
|---|---|---|---|---|---|
| P1 | META `arch` | `x86_64` | **`x86:LE:64:default`** | `emit_stage_projection` 首行字面(curl_decompile.rs:2499) | 重产投影后 `head -1`;消费端 L1 裁决该键从 meta_diff 消失 |
| P2 | META `cspec` | `x86-64-gcc` | **`gcc`** | 同上同行(curl_decompile.rs:2499) | 同 P1 |
| P3 | META `analysis_options` | `default_actions,callspec_link=<bool>` | **`default`** | curl_decompile.rs:2502-2507(callspec 注入差异按 D3 移记 producer 附注,不占身份键) | 同 P1;`RUGRA_DISABLE_CALLSPEC_LINK` 两态下投影字节一致 |
| P4 | opcode quirk 四槽表拼写 | `MULTIEQUAL`/`INDIRECT`/`PTRADD`/`PTRSUB`(枚举名,31,558 行 off-table advisory) | **`BUILD`/`DELAY_SLOT`/`LABEL`/`CROSSBUILD`**(opcodes.cc opcode_name[] 表 60/61/65/66 槽**按表直发**,勿"纠正"成枚举名) | `stage_snapshot` op 名臂(curl_decompile.rs:2217)emitter 局部 4 臂映射;**勿改** `src/opcodes.rs name()`(全域副作用) | 重产后 `grep -c "MULTIEQUAL\|INDIRECT\|PTRADD\|PTRSUB"` = 0;`BUILD`=17,660、`DELAY_SLOT`=13,008、`LABEL`=628 对齐 oracle 计数;消费端 advisory 警告归零 |
| P5 | spaceid 常量槽(D5) | `c:3:8`(STORE 首槽等,12,492 处) | **`s:ram`**(harness 语义:IPTR_CONSTANT 且 size==sizeof(AddrSpace*) 且命中活表→`s:<name>`,未命中回退 `c:`) | `stage_vn` is_constant 臂(curl_decompile.rs:2183-2185):size==8 时 `AddressSpace::from_id(offset)` 有效→`s:{name()}`;Rugra 枚举值稳定(ram=3),映射零歧义 | 重产后 `grep -c "s:ram"` = 12,492;`c:3:8` 仅残留非 spaceid 语义槽 |
| P6 | fspec 槽 f:(D6 前半) | CALL 输入槽 `n:iop:0:8` | **`f:<call op 自身 addr:time>`**(oracle 样例 `505d:131 CALL d=0 out=- in=f:505d:131`;harness:slotOp 自身 SeqNum 即稳定伪身份) | `stage_vn` 增 slotOp 参数;Iop 分支中 `vn.call_spec.is_some()` 判别(funcdata.rs:4249 同款)→`f:{slotOp.addr:x}:{slotOp.time:x}` | 重产后 CALL 行 `in=f:<本行行首 seq>` 自指;与 oracle CALL 样例逐行拼写一致(time 对齐前先验格式) |
| P7 | iop 槽 o:(D6 后半) | INDIRECT 等输入槽 `n:iop:0:8` | **`o:<目标 op addr:time>`**(活 op 表反查;查不到→`o:-`,本语料 0 处但须实现) | `stage_snapshot` 改两遍扫描:pass1 建 `Arc::as_ptr()→(addr,time)` 活表(镜像 harness writeSnapshot L193-200),pass2 发射;o: 臂经活表(参考 `fd.get_op_from_const` funcdata.rs:4244 的指针语义) | 重产后 DELAY_SLOT 行 `o:` 槽拼写与 oracle 一致;`o:-` 路径用单测 |
| P8 | d= 语义(D7) | 仅 `is_dead()`(全文件 d=1 计 88) | **`is_dead() || parent.is_none()`**(oracle op.cc:380-381 双条件,harness L169/L178 明示;目标计数 462) | `stage_snapshot` dead 臂(curl_decompile.rs:2218):`op.is_dead() \|\| op.parent.is_none()`(op.rs:300 `parent: Option<Weak<…>>`,判 None 免 upgrade) | 重产后 `awk '$3=="d=1"' | wc -l` = 462(在 D10 序号对齐后逐步逼近,先验显著上升且方向正确) |

**Punch list 之外(不属 emitter,防越界)**:
- D10 初始 IR 契约(2534 PLT 行 + §1.1 time 漂移 + 0x50b8/0x50fa 尾部 4 op)→ 待 root+oracle 裁决;
- D9 oppool1 枚举粒度(seq 29 分歧)→ 待裁决;
- **D14(新发现)**:`@END seq 18 universal:fullloop:mainloop:activeparam result/count oracle=9 vs rugra=2` — action 行为计数真差,管线语义层,建议登记 TODO 交 coreaction 对齐 lane;
- D8 dead op 空槽保留(`in=-` vs `in=-,-`)维持记录级(IR 生命周期,非 emitter);
- D11/D12(producer 格式、unique_base 语义)维持 warning 级,无需动作。

## 3. 词表覆盖复核(oracle 新投影 vs 74 名表)

- oracle distinct opcode = **38**(全文件计数见 run_L1_raw.log 旁账):全部 ∈ 消费端
  `V1_OPCODE_ENUM_NAMES` 74 名闭集,**覆盖缺口 0**。R2 报过的 38 复核一致。
- quirk 槽在语料中出现 3 个:`BUILD`×17,660、`DELAY_SLOT`×13,008、`LABEL`×628;
  `CROSSBUILD`×0(= oracle 语料无 PTRSUB 类 op;rugra 有 PTRSUB 7,345 行——修复 P4 后该差
  显性化为 op 集差,归 D10/后续管线差,非拼写问题)。
- rugra distinct = 38,其中 **4 个 off-table**(MULTIEQUAL/INDIRECT/PTRADD/PTRSUB,advisory
  31,558 行)+ oracle-only `CALLIND`×355(全部来自 2534:54 单 op 逐快照复现,归 D10)。
- 其余 33 个拼写两侧逐字一致(v1.2.1 枚举域切换后 name 域 34 拼写类问题全部消失)。

## 4. 验证命令(C-alignment lane 交付时)

```bash
# 重产(wt/sb-rust):
RUGRA_STAGE_PROJ=1 RUGRA_STAGE_FUNC=0x4ff0 RUGRA_STAGE_PROJ_OUT=/dev/shm/rugra-tests/sb-rust/next_url.rugra.projection \
  cargo run --release --example curl_decompile -- examples/curl
# 消费端(master,期望 L1 卡点消失、卡点推进到 §1 L2 层):
python3 tools/stage_bisect.py --v1 \
  /dev/shm/rugra-tests/sb-oracle/next_url.oracle.projection \
  /dev/shm/rugra-tests/sb-rust/next_url.rugra.projection
# 逐项计数(目标值见 P4/P5/P8):
grep -c "s:ram" <proj>; awk '!/^[@#]/&&!/^META/&&NF==5&&$3=="d=1"' <proj> | wc -l
```

## 5. 产物清单(sb-integration/)

- `layered_probe.py`(L1-L6 驱动,可复跑)、`run_L1_raw.log`、`run_L2..L6.log`
- `L2_rugra_meta.projection` / `L3_oracle_noplt.projection` / `L4_rugra_quirk.projection` /
  `L5_oracle_sconst.projection` / `L6_oracle_zeroptr.projection`(探测副本,非对齐证据)
- PRE_RECON 期产物(`adj_*.projection`、四个分析脚本)保留未动
