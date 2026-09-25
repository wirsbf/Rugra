# GEN5 第五语料记分板 — libsqlite3.so.0 镜像首期成绩单（2026-09-26）

> 车道：wt/gen5 @ master efc28f4a（基）｜owner: gen5(subagent)｜oracle = Ghidra 12.0.4
> e40ed130（锁定）｜golden commit `ff06b3c7`。本档为第五语料泛化棘轮的**首期记分板**：
> 差异按族归因登记 TODO，未修任何 src。

## 1. 靶选型（第一记分维度：与既有四语料的互补性）

机器清单调查（2026-09-26 亲测）：
- /usr/bin、/usr/sbin 全部系统工具均为 **stripped 可执行文件**，dynsym 导出 FUNC
  ≈0-12 个（`gzip`/`xz`/`jq`/`grep`=0、`tar`=12、`make` 有 211 个 .dynsym 导出但无
  .symtab）——GEN4 已证明 stripped 可执行是 wget 型**退化语料**（BFD 契约下 PLT 桩+
  零真身）。
- /usr/local/bin 非 stripped 候选：ctags（10MB debug_info）、readtags、docker-compose
  （Go 静态 63MB，过大）。
- **共享库方向**：stripped 库的 dynsym 导出即真身代码面。锁定 oracle runner `list`
  探针亲测三候选：

| 候选 | 单元 | 导出 FUNC 真身 | PLT 桩 |
|---|---|---|---|
| **libsqlite3.so.0**（1.36MB） | **1385** | **1339** | 46 |
| libxml2.so.2（1.97MB） | 1797 | 1694 | 103 |
| libgmp.so.10（0.53MB） | 620 | 589 | 31 |

**正靶 libsqlite3.so.0**（sha256 `f5a7fc236f80f3185608d14e9f4dea3e3fd647582e123e8a00f253629fe16830`，
Ubuntu libsqlite3-0 3.37.2-2ubuntu0.8）选型理由：
1. **首个 stripped 共享库 profile**：无 .symtab、无 DWARF、纯 dynsym 契约；库脸
   （无 main/_start，API 导出为入口，导出函数间互调的跨函数调用图）——既有四语料
   中 curl/httpd/sasquatch 是带 .symtab 可执行、vsh 是 stripped 可执行，sqlite 是
   唯一 library-face。
2. **源系零重叠**：SQLite amalgamation（tokenizer/parser/VDBE/btree/pager）vs
   libcurl/Apache/libvirt/squashfs+LZMA。
3. **巨型 switch 脸**：sqlite3VdbeExec 30609B/3877 行（五语料最大单函数）；全语料
   61 switch/1486 case/4869 goto/7688 code_r 标签。
4. **oracle 自身压力面**（golden 亲测计数）：327×"Could not recover jumptable
   (Too many branches)"（VDBE switch 超 oracle 跳转表分支上限）+327×"Treating
   indirect jump as call"+1760×"Removing unreachable block"（dynsym st_size 异常
   大函数含邻接函数代码，如 sqlite3ExprCodeLoadIndexColumn 标 644156B）+12×"Type
   propagation algorithm not settling"（oracle 自带非收敛脸）——oracle 侧这些行为
   本身就是要对齐的目标。

## 2. Oracle 真值（第二记分维度：溯源完整性）

- 复用 `tools/regen_ghidra_golden.py` 库：preflight 锁 oracle commit `e40ed130` +
  cpp tree `b02e230a` + x86 language tree `84265e1e` 全过；BFD 2.38
  （/tmp/rugra-ghidra-bfd-2.38 存活亲验：bfd.h + libbfd-2.38-system.so）。
- **1385/1385 OK，30.3s**（hermetic one-mode ×12 workers，600s/函数）；
  **determinism 12/12 字节恒等**（分层抽样重跑）。
- 产物：`tests/golden/ghidra_sqlite_1204.direct-runner.c`
  （sha256 `90950e1fa11d03eb77bf73abb24664e7fad3b9abc05ee11cf302f399a2636244`，
  143012 行，commit ff06b3c7）
  + `ghidra_sqlite_1204.provenance.json`（oracle commit/tag/arch=
  x86:LE:64:default/cspec=gcc/分析选项/输入 sha/逐函数 ledger/runner 构建指纹/
  determinism 全记录——**NO_ORACLE 缺项为零**；canon headless 档 NO_ORACLE 已记
  tier 字段，重建入口 tools/build_ghidra_1204_headless.sh）。
- **同输入前提**：Rugra gen 驱动发现 1385/1385 与 oracle 逐名逐址一致。

## 3. Rugra 镜像首期成绩单（mirror 臂，RUGRA_GEN_MIRROR=1 同契约）

运行形态说明：gen_decompile all-mode 为串行逐函数，sqlite 全量串行不可行（单函数
病态慢可达 600s 墙）；本车道用**并行分片驱动**（mirror_shard_sqlite.py：16 分片 ×
顺序 `--one i` 子进程 = 与 all-mode 完全相同的 hermetic 逐函数语义的并行化包装，
失败重试 3 轮）。795s 完成（含重试）。

| 指标 | 值 |
|---|---|
| ok / 总单元 | **1355/1385**（27 PANICKED + 3 TIMEOUT；0 误退出） |
| Matched | 1355（=ok 数；30 非 ok 单元不计入骨架口径） |
| **skeleton**（匹配函数归一化骨架差） | **17652** |
| **defects** | **0** |
| **numbering** | **0**（sq 打破过镜面 numbering=0 不变量=7；sqlite 复零） |
| 骨架恒等函数 | 874/1355（64.4%） |

面级对照（Rugra/golden，全语料计数）：

| 面 | Rugra | golden | 备注 |
|---|---|---|---|
| WARNING 总数 | 2393 | 2579 | 大面近 parity |
| unreachable-block 警 | 1613 | 1760 | oracle 压力面被复现 |
| jumptable Too-many-branches 警 | 319 | 327 | 同上 |
| indirect-jump-as-call 警 | 319 | 327 | 与 jumptable 警成对 |
| PIC construction 警 | 126 | 144 | — |
| typeprop 不收敛警 | 10 | 12 | oracle 自带非收敛脸近 parity |
| `_` Globals-overlap 假警 | **0** | 0 | sq 爆 188 的 GLOBALOVERLAP 族在 sqlite 不点火 |
| goto / case / switch | 3671/1002/48 | 4869/1486/61 | 差额 **1233/484/13 全部由 30 个非 ok 函数的 golden 体解释**（≥gap 1198/484/13），匹配函数近 parity |
| unaff_ / extraout_ | 5237/1136 | 6203/1845 | 差额主体同上（非 ok 函数） |
| ram0x 兜底 token | 129 | 0 | GEN4-SQ-RAMNAME 族（sq 553→sqlite 129） |
| Ram 符号名 `<t>Ram<hex16>` | 814 | 899 | 与 ram0x 129 合看=覆盖缺口 |
| ZEXT/SEXT 泄漏 | 98/166 | 15/3 | GEN4-SQ-ZEXT-OPNAME+SEXT(F-TYPE 派生)族 |
| FUN_ 回退 | 0 | 0 | — |

## 4. 残差族分拣（hunk 级分类器，17652 行全分类）

| 族 | 行数 | 函数数 | 票务 |
|---|---|---|---|
| OTHER（主成分=cast token 3594+栈/Ram 变量 churn 2527，见下拆解） | 5317 | 398 | 拆解归并入下两族 |
| CAST-SHAPE（cast 放置/形态） | 3908 | 224 | 归并 **GEN4-SQ-CASTFUSE-DEPTH-0001** |
| SWITCH-GOTO（switch/case/goto 形态） | 3779 | 85 | 归并 **MSTRUCT-SWITCHGOTO-SELECTGOTO-0001** |
| UNAFF-EXTRAOUT（放置/拼写） | 2235 | 81 | 归并 **GENSMOKE-S4/S2**（sq 同判） |
| OPNAME-LEAK（ZEXT98+SEXT166 泄漏入 C 文本） | 1263 | 88 | 归并 **GEN4-SQ-ZEXT-OPNAME-0001**（SEXT 半=VARMPOISON/F-TYPE 中毒派生，sq 同判） |
| LOOPSHAPE（for↔while 等） | 810 | 12 | 归并 **MSTRUCT-FORSPLIT-DECOMP-0001** |
| CAST-TEMP-HOIST（cast 临时语句 vs 内联融合） | 146 | 12 | 归并 **GEN4-SQ-CASTFUSE-DEPTH-0001** |
| CMP-ORIENT（`V < LIT` vs `LIT < V`） | 91 | 8 | 归并 **GEN4-SQ-CMP-ORIENT-0001** |
| WARNING-FACE（jumptable/indirect 警告行数差 319vs327 等） | 58 | 9 | 归并既有警告族杂项 |
| TYPE-SPELL | 37 | 14 | 归并 **F-TYPE/S2-TYPEINFER**（VARMPOISON 域） |
| BRANCH-INVERT | 8 | 1 | 归并 **GEN4-SQ-BRANCH-INVERT-0001** |

OTHER 桶主成分亲分（逐行 token 普查）：`has-cast-token` 3594（归 CASTFUSE）+
`stack/ram-var` 2527（归 **GEN4-SQ-STACKSLOT-MATERIALIZE-0001**，中链值栈槽物化/
放置 churn，sq 同形）+ 链表遍历循环形态 + 杂项赋值形（`V = LIT;` 376、`V = V;` 218
等=同两族的行级表现）。

**sqlite 特异新脸（证据归并，不另开票）**：链表遍历 for 形
`for(V=V[i]; V!=0; V=*(int8 *)(V+f))`——golden **31 处 vs Rugra 0 处**（Rugra 恒
while 形）；位点是 sqlite3BackupRestart/sqlite3BtreeEnter(Cursor) 等 Btree/pager
链表遍历（sqlite3ExprCodeTarget 257 LOOPSHAPE、sqlite3VdbeExplain/VdbeChangeP4
各 ~153 领跑）。根因域=for-split 重建（指针追逐 loop-carried 更新不触发 for 形），
归并 MSTRUCT-FORSPLIT；sqlite3Select（2313 行=单函数最大，UNAFF 710+CAST 686+
SWITCH 580）与 sq 的 CodeSpec 同为多族复合体。

## 5. Worker 失败分拣（30 个，重试 3/3 轮复现=确定性）

- **3× TIMEOUT = GEN5 新票 GEN5-SQLITE-PATHOSLOW-BITVEC-0001（P1）**：
  `sqlite3BitvecSet`（idx 114，golden 114 行）/`sqlite3BitvecClear`（idx 57，77 行）/
  `sqlite3BitvecTestNotNull`（idx 55，39 行）——oracle 三函数毫秒级轻松（全量
  1385 函数共 30.3s），Rugra 单函数 CPU 燃烧 >95s 起、至 600s 墙杀（idx 55 两轮
  亲测 4:16+CPU 仍 100%）。**性能级分歧**（活跃性/复杂度爆炸族），Bitvec 三兄弟
  全灭=同根（位图散列子表递归结构）。repro：
  `RUGRA_GEN_MIRROR=1 /dev/shm/rugra-targets/gen5/fast-release/examples/gen_decompile /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 --one 55|57|114`。
- **27× PANICKED = 全部既有族 MIRROR3-PRETTYFLUSH-FAILCLOSED-0001**
  （prettyprint.rs:3946 indentstack 空 unwrap；每索引 3/3 轮复现）。sq 2 站点→
  sqlite **27 站点**（族半径 ×13.5，含 sqlite3VdbeExec/sqlite3RunParser/
  sqlite3_mprintf 等顶梁函数）：sqlite3AlterFinishAddColumn/AlterBeginAddColumn/
  BtreeInsert/StartTable/AffinityType/AddDefaultValue/AddPrimaryKey/sqlite3_complete/
  FindFunction/ExprAffinity/FkCheck/FkActions/Fts3EvalPhraseStats/PhrasePoslist/
  GenerateConstraintChecks/sqlite3_exec/PagerSetPagesize/str_vappendf/vmprintf/
  mprintf/Pragma/ResolveSelectNames/db_status/RunParser/BeginTrigger/VdbeExec/
  WalFrames。

## 6. 与既有语料的纵向对比（棘轮扩大效应）

| | curl | httpd | vsh | sq（GEN4） | **sqlite（GEN5）** |
|---|---|---|---|---|---|
| profile | C 可执行 | C 可执行 | stripped C 可执行 | C++ 可执行 | **stripped 共享库（dynsym-only）** |
| 单元/真身 | 74/— | 790/— | 71/12 | 810/776 | **1385/1339** |
| ok | — | — | 71/71 | 804→805/810 | **1355/1385** |
| skeleton | 132 | 265 | 41→15 | 15889 | **17652** |
| defects/numbering | 0/0 | 0/0 | 0/0 | 0/**7** | **0/0** |
| panic 族 | — | — | — | 2（DBLHI 修复前 6） | **1（PRETTYFLUSH 预存，半径 ×13.5）+PATHOSLOW 新族** |

泛化结论：
1. **拼写族零回归**：GLOBALOVERLAP 假警族（sq 188 行）在 sqlite **不点火**（0/0）；
   RAMNAME 收缩（553→129）；numbering 复零——sq 暴露的三张 P2 拼写票未在 sqlite
   恶化。
2. **结构族同根扩容**：CASTFUSE/SWITCH-GOTO/UNAFF/STACKSLOT 四族仍是骨架主战场
   （合计 ~1.2 万行级），sqlite 的链表遍历 for 形缺席（31:0）给 MSTRUCT-FORSPLIT
   一个此前不可见的**绝对缺席**证据面。
3. **新捕获 1 个 P1 族**：PATHOSLOW-BITVEC（首个性能级分歧族——oracle 轻松、
   Rugra 600s 不收敛）；PRETTYFLUSH 既有族半径 ×13.5（2→27 站点）成 sqlite 面的
   panic 主导族——棘轮扩大继续有效。
4. oracle 自带压力面（jumptable 超限/不可达块/非收敛警告）Rugra 全部以近 parity
   复现（319/327 等）——这些是此前四语料从未出现过的 oracle 行为面。

## 7. 复现配方

```bash
# oracle 真值（已入库，重生成用）
python3 /dev/shm/rugra-reports/gen5-evidence/capture_oracle_gen5.py   # 需 worktree 路径内的 tools/regen_ghidra_golden.py
# Rugra 镜像（并行分片=hermetic --one 语义并行化，重试 3 轮）
python3 /dev/shm/rugra-reports/gen5-evidence/mirror_shard_sqlite.py 1385
# 对拍
python3 tools/compare_ghidra.py /dev/shm/rugra-tests/gen5/sqlite_mirror.c \
  tests/golden/ghidra_sqlite_1204.direct-runner.c --base 0 --summary-only
```
