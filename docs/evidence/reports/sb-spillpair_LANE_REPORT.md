# Lane FI 终报 — MERGE-COPYNOISE-SPILLRESTORE 终局:实例组合差分判决(第 4 代)

- worktree: /dev/shm/rugra-worktrees/spillpair(wt/spillpair,基线=亲父 d7478187)
- oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b(worktree ghidra HEAD 已核验;
  本 lane 新增 oracle 侧证据由 sb-drill 既有锁定构建产出,见 §3)
- src 改动: **零**(merge.rs 探针已回退,`git status` clean;main 输出 byte-identical 复验)
- 结论: **MERGE-COPYNOISE-SPILLRESTORE-0001 关闭为 NOT-A-DEFECT(非缺陷)**——spill/restore 对
  在锁定 oracle 的 C++ 反编译器管线产物中**同样存在**,1→1 就是正确状态。

## 1. 实例组合差分判决(任务①②核心问题)

方法:merge.rs 临时 env 探针(RUGRA_FIPROBE,已回退)在 merge_addr_tied/merge_marker/
merge_opcode 的 entry/exit census(stack:fdc0 / register:b0(R14) / ram:174f0(stdin) 邻域
+ high 成员清单 + per-block cover spans + IMPL/EXPL flags);oracle 侧新造 stage_drill_fi
runner(sb-drill 锁定 libdecomp.a 复用,仅 runner 级追加 dump,oracle 库零改动,ASLR-off
setarch -R env -i 同 canonical recipe)输出终态 flags/high 符号/cover + 真打印。

**双侧逐点对照(mergecopy 时点)**:

| 观察项 | Rugra(d7478187) | oracle(C++ 管线) | 判定 |
|---|---|---|---|
| mergerequired 前态 R14phi@0x2780 输入 | sfdc0#45532 ×2 + ram:174f0(input) | sfdc0(0x3180:38d5) ×2 + r0x174f0(i) | 同 |
| mergeAddrTied 产物 | 入口 COPY u:10000f59=r0x174f0@0x25a4 + spill 输入重接 + phi slot2 重接 | u0x10000a41=r0x174f0@0x25a4 + 同 | 同 |
| mergeOp(R14phi) trims | u:10001061/u:10001069 = sfdc0@0x3188/0x3198 | u0x10000b49/u0x10000b51 = sfdc0@0x3188/0x3198 | 同 |
| R14 族 high(mergecopy 时) | 7 成员(a41+b49+b51+R14 phi 链+RAX 例外件) | 16 成员(同核+phi 链展开更多) | 同核 |
| spill 写 cover | b11[de1e1db6..ffffffff], b12[0..0] | b11[0xde1e1db6..0xffffffff], b12[0..0] | **逐字节同** |
| sfdc0-phi@0x2780 cover | b29[0..call@0x278d] | b29[0..call@0x278d] | 同(终点=0x278d call 的 order,数值域不同) |
| mergecopy 判定 | (R14phi #18121 [0..full]) × (sfdc0phi #45539 [0..call]) blk29 相交,copyShadow=false → merge 跳过 | 同一对、同相交(数学同构) | 同 |
| 终态 flags | spill 写/出 EXPL,not-printed=0 | spill 写/出 EXPL,notprinted=0(dump 实测) | 同 |

**EM3 收窄结论的证伪**:EM3 推断"oracle 能合并 ⇒ mergecopy 时点两侧 high 不含这对实例共存
⇒ 实例组成上游有分歧"。实测双侧实例组成、cover、trims 全部一致;oracle 的 mergecopy 对该对
**同样拒绝合并**(b29 双 MULTIEQUAL marker-0 相交不可逃逸,copyShadow 对 MULTIEQUAL×MULTIEQUAL
不成立——varnode.cc:977-995 链源即自身)。分歧不存在。

## 2. 真根因:对照基线选错(headless golden ≠ C++ 管线 oracle)

三代 lane 一直把 `--func main` 的 spill 对与 **headless 正典 golden**(tests/golden/
ghidra_curl_1204.c)对照——那里 main 确实没有 spill 对。但:

1. **直接 runner golden**(tests/golden/ghidra_curl_1204.direct-runner.c,同一锁定 oracle、
   同一 C++ 库、无 Java 分析器)的 main **有同对**:
   - L530 `iStack_240 = iVar10;`(spill)
   - L573 `iVar10 = iStack_240;`(restore)
   httpd direct-runner golden 同族(L4132/4134 `iStack_5a = iVar2; iVar2 = iStack_5a;`)。
2. **本 lane 实测**:stage_drill_fi(锁定 oracle 库+canonical recipe)终态打印 main,输出
   含 `iStack_240 = iVar10;` / `iVar10 = iStack_240;`(与 direct-runner golden 除 callee
   符号解析外逐语句同;模 callee 名归一后仅符号差异)。终态 IR dump:spill COPY out
   EXPL/notprinted=0/sfdc0high sym=iStack_240——按 printc.cc:2694-2705 门它**必须打印**。
3. headless golden 的 main 变量名全 DWARF 化(__stream/outs/progressbar),provenance 记载
   direct-runner 与 headless 的等价性缺口(72 函数 changed_text,"differences expected from
   analyzer-provided signatures/references")。headless 侧该对的消失是 **Java 分析器栈
   (DWARF 局部符号/类型/引用分析)改变了 merge/type-lock 输入**的结果,不是 C++ 反编译库行为。

Rugra 对齐目标是 C++ 反编译库(e40ed130 的 decompile/cpp)。因此 Rugra main 的
`pFStack_240 = __stream;` + `__stream = pFStack_240;` 与 oracle C++ 管线的
`iStack_240 = iVar10;` + `iVar10 = iStack_240;` **结构等价,1→1 为正确终态**。
三代未消除的"残差"实为把 headless-only 的输出口径当成了 C++ 管线预期。

## 3. 证据工件(本目录)

- `main.baseline.c` / `main.reverted.c`:d7478187 基线 main 与回退后 main(byte-identical)。
- `main.probe.stderr.log`:FI-BI/FI-CV census(merge_addr_tied/merge_marker/merge_opcode 全段)。
- `stage_drill_fi.cc` / `stage_drill_fi`:oracle runner(锁定库 + dump/打印插桩,库零改动)。
- `main.oracle.fi.drill`:oracle 终态 IR dump(FINEIGH 段:flags/high/cover)。
- `main.oracle.fi.c`:oracle 真打印的 main(spill 对在列)。
- `main.directrunner.golden.c` / `main.headless.golden.c`:两种 golden 的 main 提取(对照 §2)。
- `*.rugra.projection`:next_url / match_url / parseconfig.constprop.0 投影。

## 4. 门禁(基线=亲父 d7478187 本 lane 亲测,src 零改动)

| 门禁 | 结果 |
|---|---|
| curl 全语料 defects/numbering | **0/0**(compare_ghidra.py --summary-only;skeleton 原始 diff 2203 行) |
| httpd 全语料 defects/numbering | **0/0**(skeleton 2239 行) |
| gcc 审计 | **82 OK / 25 FAIL == 亲父** |
| --func main | byte-identical 亲父(spill 对 1,== direct-runner oracle 的 1) |
| 三投影 next_url / match_url / parseconfig.constprop.0 | **v1.2 stage+snapshot identical MATCH ×3**(stage_bisect.py --v1) |

注:skeleton 计数与 EM3 报告(2450/2336)不同源于亲父 d7478187 已含 FC lane(AndCommute
benefit gate,faf0d593)的输出收敛,非本 lane 改动。

## 5. 机制 C 声明

本 lane **零 src/merge.rs 改动**(探针创建→回退,git 干净),不触发机制 B/C 白名单;
merge.rs 相关既有改动(EM3/d7478187)的复核请求仍随其 commit 悬置,不受本 lane 影响。
oracle 侧仅新增 runner 级插桩(不改 oracle 库、不改正典 golden/direct-runner golden)。

## 6. 回收

- 本目录保留 LANE_REPORT/探针日志/oracle runner 工件(小件);curl_all.c/httpd_all.c/
  *.projection 大件确认 MATCH 后可清(root 集成时处置)。
- /dev/shm/rugra-targets/sb-spillpair:worktree 即将交付,按回收纪律待 root 集成后回收。
