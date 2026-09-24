# MERGE-COPYNOISE-CANDGEN-0001 调查报告(+33 候选生成/顺序域)

日期:2026-09-22。Rust 探针基线:wt_rust 快照(repo rsync,master 谱系 a58091e5+;终态
census 与 df9febd9 基线逐数复现:R 318/91/187/38/2/3,O 234/47/154/23/10,见 §3)。
oracle:Ghidra 12.0.4 **e40ed130**(repo ghidra HEAD 核对相等;oracle_cpp = sb-okokprobe
runner 树 rsync + 本 lane merge.cc 插桩)。只读调查,**repo 零改动**;全部探针在
/dev/shm/rugra-tests/sb-candgen/,env 门控(RUGRA_CANDGEN / CANDGEN)。

## 0. 一句话结论

**候选生成链双侧 1:1 对齐,+33 域内 0 对是"本可合并却因遍历/顺序/漏看而未尝试"。
187/154 对在双侧全部被 mergeTestBasic 的 structural 门(const nocover / implied)当场
拒绝——这是设计行为,不是缺陷。** +33 完全分解为上游 op 数量差:
**+42(输出 implied 的 COPY,Rugra 独有存活群体,半数来自单一创建波 uniq 30d6)+
6(输入 implied,多为双侧同 op,Rugra 多 6)− 12(const 装载族 oracle 反而更多)−
3(oracle merge 时 req-fail、终态 req=1 的 flag 漂移)= +33。**
归因域 = implied 群体/MarkImplied 上游 + junk-COPY/const 记账(与 +44 same-high 同源),
**不是 merge 域;无顺序涟漪;无 adjacent 域缺口。**

## 1. 候选生成链结构对照(读双侧源码,先于探针)

### 1.1 oracle mergeOpcode(merge.cc:326-350)

- 遍历: `bblocks`(BlockGraph 线性 index)→ 每 block `beginOp()..endOp()`(list 插入序)
  → `op->code()==CPUI_COPY`;候选对 = (vn1=out, vn2=in[j]) 逐 j。
- 顺序键: **block index 线性序 + block 内 op 插入序**,无排序无哈希;Rust
  merge.rs:2404-2414 同构(bblocks get_size/get_block → get_ops)。
- 门链: ①mergeTestBasic(vn1) ②mergeTestBasic(vn2) ③mergeTestRequired → merge(,false)。
- **mergeTestBasic(merge.cc:255-264)拒绝 5 类**: null / `!hasCover()`(⇒**常量输入
  永远非候选**)/ `isImplied()` / `isProtoPartial()` / `isSpacebase()`。
  Rust merge.rs:1350-1363 逐条对齐(is_implied 在 :1354)。
- **implied 冻结点**:ActionMarkImplied(coreaction.cc:3416)在 ActionMergeCopy
  (coreaction.cc:5722)**之前**(:5720)跑一次;implied 的全部 setter 都在 merge 前
  (coreaction.cc:2597/2637/2705 = MarkExplicit 家族,funcdata_op.cc:603 = op 插入期,
  merge.cc:1598 = markImplied 本体)⇒ merge 时刻的 implied 集 ≈ 终态 implied 集
  (探针实证:47 个 basicout-fail:implied 在 merge 时与终态 oimpl=1 完全一致)。
- 可并对其余吸收源(coreaction.cc:5717-5729)在 Rust 全部存在
  (MergeRequired/MarkExplicit/MarkImplied/MultiEntry/MergeCopy/DominantCopy/
  MarkIndirectOnly/MergeAdjacent/MergeType/HideShadow/CopyMarker;
  merge.rs:1899/2166/2328/3328/3628/3963/4166/4371,coreaction.rs:1620-1770)⇒
  **缺 Action 不是候选解释**。

### 1.2 双侧 [CANDAT] 插桩(本 lane,格式逐字段一致)

`[CANDAT] pass=copy|adj op=<ptr> seq=<uniq>/<time>/<order> out=sp:off:sz [in=…] gate=
basicout-fail:{nocover|implied|protopartial|spacebase|other} | basicin-fail:<同> |
same-high | req-fail | merged | isect-block`
- Rust: wt_rust/src/merge.rs merge_opcode/merge_adjacent(env RUGRA_CANDGEN;前次中断
  遗留的编译错 cg_id move + ispace 未定义已修,.as_ref() 补丁 7 处);
- oracle: oracle_cpp/merge.cc mergeOpcode/mergeAdjacent(env CANDGEN;getenv/fprintf,
  getName().c_str());终态 census 复用 OKOK 探针([OKOKFINAL],同 run 内 op ptr 稳定,
  ptr join 合法)。

## 2. 运行记录(可复现)

- Rust:`RUGRA_CANDGEN=1 RUGRA_OKOKPROBE=1 RUGRA_OKOKFUNC=main ./target/fast-release/
  examples/curl_decompile --rugra-selected-function main` → `rugra_candgen.stderr.log`
  (CANDSNAP 326,CANDAT pass=copy 326 ops×1 次 + pass=adj 101,CANDGEN-BEGIN alive_copy=326)。
- oracle:`CANDGEN=1 ./oracle_candgen /home/ls/Rugra/sleigh_specs /home/ls/Rugra/examples/curl
  main` → `oracle_candgen.stderr.log`(pass=copy 235 ops×1 次 + pass=adj 66,census 234)。
- **两侧 mergeOpcode 均恰好跑 1 次**(无 restart 重跑;此前 awk 统计"每 op 2 行"为假象,
  Python 直方图 {1:326} 证实;uniq 基址 2750:40 / 3366:40 / 30d6:23 是**创建波**不是遍历波)。
- oracle 构建:make 重编 merge.o → `ar r libdecomp.a com_opt/merge.o` → g++ -std=c++11
  链 oracle_candgen.cc(=sb-okokprobe/oracle_okokprobe.cc 原样)+ sleigh_arch.cc +
  bfd_arch.cc + loadimage_bfd.cc + com_opt/{libdecomp,inject_sleigh,interface}.o +
  libdecomp.a + bfd_root=/tmp/rugra-ghidra-bfd-2.38(重启即丢,重建见 AGENTS)。

## 3. 终态 census 与 +33 域逐对 join(核心证据)

### 3.1 census 复现(与 df9febd9 基线一致)

| | Rugra | oracle | Δ |
|---|---|---|---|
| 终态存活 COPY(对) | 318 | 234 | +84 |
| same-high | 91 | 47 | +44(已知 junk 域) |
| diff-high v=0 req=1(**+33 域**) | **187** | **154** | **+33** |
| diff-high v=1(cover 阻断) | 38 | 33 | +5(过严方向,非本域) |
| diff-high v=0 req=0 | 2 | 0 | +2 |

### 3.2 merge 时刻逐对 fate(ptr join,双侧 100% 命中,**never-seen = 0/0**)

| gate(merge 时刻) | Rugra | oracle | Δ | 构成(R | O) |
|---|---|---|---|---|
| copy:basicout-fail:**implied** | 47 | 5 | **+42** | unique→unique(1,1) 19|0;unique→const(1,0) 18|1;register→const(1,0) 7|2;register→reg/stack、unique→ram 3|2 |
| copy:basicin-fail:**implied** | 13 | 7 | **+6** | unique→register(0,1) 9|3;unique→unique(0,1) 4|4 |
| copy:basicin-fail:**nocover**(const 输入) | 127 | 139 | **−12** | stack→const 103|108;register→const 20|25;ram→const 2|4;unique→const 2|2 |
| copy:req-fail(merge 时) | 0 | 3 | **−3** | O:stack/register/unique→unique(0,1) 各 1 |
| never-in-mergepass-logs | **0** | **0** | 0 | — |
| 合计 | 187 | 154 | +33 | |

四类决定性语义核对(机制 A 口径,读行确认):引用/输出参数(mergeOpcode 无,纯遍历);
循环边界(bblocks.getSize() `<`,Rust `0..n_blocks` 同);计数器(无);排序键(无排序,
插入序,Rust Vec get_ops 同)。双侧 gate 语义逐条读行比对,无差异。

### 3.3 +42 out-implied 的指纹(上游入口)

- Rust 47 个中 **20 个来自同一创建波 seq-uniq 基址 `30d6`**(含 size 24×8、8×20+、4×若干
  ——struct 分片 COPY 家族,unique:268439xxx 连续);其余散点。
- oracle 5 个全散点,**与 Rust 无 uniq 基址重叠**(⇒ Rugra 独有 op 群体,非同 op 不同判)。
- in-implied 13/7:uniq 基址 2845/28c8/2e8e/30cd/25ed/29dd 双侧**同 op 对齐**,Rugra 净多 6。
- 同源旁证(OKOK 报告 §3.3 细切):implied 牵连 Rust 60 vs oracle 15(+45)——与本文
  +48 implied 净差同族,两口径互恰。
- −12 nocover:oracle 反而**多** 12 个未并 const 装载(stack→const +5、register→const +5、
  ram→const +2),与 +44 same-high junk 域同一记账面(const 装载在 Rugra 侧被 junk 家族
  不同的创建/折叠路径吸收),方向相消。
- −3 req-fail:oracle 3 对 merge 时 req 失败、终态 req=1 ——input/persist/extraout flag
  在 merge 后被 ActionOutputPrototype/InputPrototype(coreaction.cc:5730/5731)改写的
  边缘效应;Rust 0 例(该 3 对在 Rust 侧不存在同 op)。P3 观察项,不承重。

## 4. 裁决(33 对定因分类 + 可修计数)

| 类 | 对数(净) | 定因 | 裁决 | 可修点 |
|---|---|---|---|---|
| out-implied 未并 | **+42** | Rugra 独有存活 implied COPY 群体(20/47 单波 30d6,struct 分片族),merge 前已 implied ⇒ mergeTestBasic 结构性排除,**双侧行为均正确** | **adjacent 域 = 上游 MarkImplied/op 创建波问题,等上游** | 0(merge 域无可修) |
| in-implied 未并 | **+6** | 同上,双侧同 op 对齐,Rugra 多 6 个 | 同上 | 0 |
| nocover(const)未并 | **−12** | const 输入永远非候选(双侧同);数量差 = const 装载/创建路径差 | 归 PRINTC-CONDBLOCK-JUNKOPS-0001/+44 same-high 记账面 | 0 |
| req flag 漂移 | **−3** | oracle merge 时 req-fail→终态 req=1(Output/InputPrototype 后置改 flag) | P3 观察项 | 0(行为正确) |

- **可修计数(merge 候选生成/顺序域内):0/33。** 无一对因遍历容器、顺序键、early-skip、
  漏创建 op 而错过合并;双侧 never-seen=0 证明终态全部 COPY 在 merge 时刻都被看过且
  被同一门语义拒绝。
- **顺序涟漪:未发现**(两侧均单次执行、同遍历序、同单态门结果;adj/DominantCopy/
  MergeType 动作齐全,本域内未产生差异对)。
- 域内 187/154 对"终态可并(req=1、isect=0)"只是终态投影:它们不是候选,因为
  mergeTestBasic 的 const/implied 门在 **merge 时刻**成立且此后不可逆(implied 冻结、
  const 恒无 cover)。"可并未尝试"的准确表述 = **"structurally never a candidate,
  by design, on both sides"**。

## 5. 登记建议

1. **MERGE-COPYNOISE-CANDGEN-0001:关闭,判定 = 候选生成无缺陷**(双侧 [CANDAT]
   join 100% 命中、never-seen 0/0、gate 分布差异全部上游化)。不新开 merge 修复 lane。
2. **+42/+6 implied 群体 → 路由到 MarkImplied/implied 打印域既有 lane**(OKOK 报告
   §3.3 已登记的 +45 细切):修复任务书要点 =
   a) 以 seq-uniq 创建波为指纹:Rugra `30d6` 波(~20 个 size 8/24/4 implied COPY,
      unique:268439xxx 连续段)定位创建者(疑 struct 分片/CONCAT-SUBPIECE 家族,
      ActionDistributeBases/RulePiece 前置域),对照 oracle 同位函数该波为 0;
   b) 双侧比对 ActionMarkImplied 输入集(哪些 varnode 被 checkImpliedCover 判 implied),
      Rust 侧多标的是"创建多了"还是"标错了"——用 in-implied 6 个净多同 op 对做锚点;
   c) 验收 = 终态 implied-out COPY 对 R≤O+ε 且 30d6 波指纹消失。
3. **−12 nocover 记账面 → 并入 PRINTC-CONDBLOCK-JUNKOPS-0001(+44 same-high)**:
   同一 junk/const 创建路径差的两面;修复任务书把"stack/register→const 未并数
   (R103/108、20/25)"列为回归指标即可,不单独立项。
4. **可选 P3 观察项**:oracle 3 对 merge 时 req-fail→终态 req=1 的后置 flag 漂移
   (Output/InputPrototype 晚于 merge 改 input/persist);仅在将来做 req 域逐函数
   fixture 时顺带覆盖,不承重。
5. **工具沉淀**:双侧 [CANDAT] gate 级插桩 + ptr join 的方法可直接复用于任何
   "为什么这对没并"类问题;探针代码在 /dev/shm(重启即丢),若上游 lane 需要,
   从本报告 §1.2/§2 的格式与补丁说明重建(<30 行/侧)。

## 6. 可复现清单(本目录)

- `wt_rust/`:Rust 探针副本(merge.rs CANDAT 插桩 + cg_id/ispace 修复;curl_decompile
  OKOK hook)。
- `oracle_cpp/`:oracle 副本(merge.cc mergeOpcode/mergeAdjacent 插桩,其余 = okok 树
  rsync 含 variable.cc/merge.hh/cover.hh OKOK 插桩)。
- `oracle_candgen.cc` / `oracle_candgen`:oracle 探针源与二进制(= okok 探针 main 原样)。
- `rugra_candgen.stderr.log`(25919 行)/ `oracle_candgen.stderr.log`(980 行):双侧
  CANDAT+census 日志。
- `cand33_orders.json`:187/154 域逐对分类(gate/out/in/oimpl/iimpl/seq/op ptr)。
- `rugra_main_new.c` / `oracle_main_new.c`:本次双侧 C 输出(与 okok 基线一致)。
