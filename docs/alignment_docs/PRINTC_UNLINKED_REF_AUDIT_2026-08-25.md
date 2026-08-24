# A35 — PRINTC-UNLINKED-REF label 交换族审计（7 函数，R10 §3.2 残差）

- 日期: 2026-08-25（只读审计 agent A35；零仓库改动、零 cargo）
- 任务源: R10-BREAKPOOL-ADJUDICATION §3.2 —— 忠实 Action 执行器集成后，标签漂移迁移到 10 函数 211 行；
  本审计只做其中 **7 个纯等距 label 交换函数**（5 处孤儿声明已登记 `VARMAP-ORPHAN-DECL-0001`，不重复）
- 锁定 oracle: Ghidra 12.0.4 `e40ed13014025f82488b1f8f7bca566894ac376b`（本 session 亲核 `ghidra/` HEAD）

## 0. 输入指纹（全部逐字节锚定）

| 文件 | 角色 | sha256（本 session 亲算） |
|---|---|---|
| `/tmp/r10-curl-merged.c` | merged 侧（忠实执行器 E2E 输出，R10 留档） | `165f3e72d6c713c3fa527d9793f23b3dffefde29bc6c8f7b69041a6a52e16858`（= R10 §2 记录） |
| `result/curl_cur.c` | master 侧（post-varmap 基线） | `b9f34811cbce602ba10387650fcb7b0311d123adabd98a800434c365dbfb9b2e`（= R10 头记录） |
| `tests/golden/ghidra_curl_1204.c` | golden 真值 | `aca3798881fddc2ce541c3e731b88f9fcf4736451db98fdd9247366f78b6097f` |
| repo HEAD | `deb72c3`（docs: breakpool integrated…，即执行器已入 main） | — |

注意：任务书引的 `printc.cc:4220/5164/8152` 实为 **Rust `src/printc.rs` 行号**（oracle 的 printc.cc 全文仅 3401 行，
无 4220 行）。本报告已把两侧行号全部实读校正。

`uVar_` 兜底总量：merged 36 个不同名 / 262 次出现；master 29 / 220；**golden 0**（`uniq<hex>` 形也 0）。
所有被交换标签 offset 均落在 `0x10000000` 基之上（unique 空间，`ANALYSIS_UNIQUE_START=0x1000_0000`，
varnode.rs:30）；`uVar_23e00/uVar_c900/uVar_8f00` 等稳定标签是 **ram 空间**全局引用（curl .data 地址段），
不属于本交换族（它们双侧逐字节相同）。

## 1. 证据：7 函数逐标签差异（merged ↔ master，golden 真名）

提取方法：三份文件按函数体切出（merged/master/golden），unified diff n=0，再按正则盘点全部 `Var_<hex>` 兜底名。
**每个函数除交换标签外，其余兜底名（含 unique 与 ram 两类）双侧逐字节相同** —— 差异面 100% 集中在下表。

| # | 函数 | 交换标签 merged → master（出现次数） | 双侧稳定的共享兜底 | golden 真值（同名位置） |
|---|---|---|---|---|
| 1 | myprogress | `uVar_10000044`→`uVar_100000a1`（decl 1 + use 1，`while (uVar_10 + (0-(X+1)) != 0)`） | `uVar_1000067e`,`uVar_10000686`(unique) + `uVar_23e00`,`uVar_c900`(ram) | 计数名 `uVar2/uVar4/uVar6/uVar7/uVar8` + `lVar1/pbVar3/iVar5/fVar9/fVar10`（golden:1130-1141） |
| 2 | helpf | `uVar_100000fc`→`uVar_10000090`（decl 1 + use 1，`if (uVar_18==0 \|\| (…plVar_18 + X + 1 & 2)…)`） | `uVar_100001c1`(unique，**晚于交换标签出生但 offset 相同**) + `uVar_22200`,`uVar_23e00`,`uVar_c900` | 干净 canary 体 `__stack_chk_fail()`；`lVar1` + varargs 寄存器输入 + `local_b8`（golden:628 区域） |
| 3 | file2string_part_0 | `uVar_100000bc`→`uVar_10000060`（decl 1 + use 1，同 helpf 的 `& 2` 判式） | `uVar_10000181`,`uVar_22200`,`uVar_23d00`,`uVar_23e00`,`uVar_c900` | 同 helpf（无 `uVar_` 形） |
| 4 | match_url | `uVar_10000175`→`uVar_10000181`（4 次：decl + `while (X != '#')` + 2×`* = uVara0 = X`） | `uVar_23b00`,`uVar_8f00`,`uVar_9500`,`uVar_9e00`（全 ram） | `while (cVar4 == '#')`（计数/类型名，无 `uVar_` 形） |
| 5 | my_get_line | `uVar_100001e4`→`uVar_100000d8`、`uVar_100002d3`→`uVar_100002eb`（各 decl 1 + use 1） | `uVar_22200`,`uVar_23d00`,`uVar_23e00`,`uVar_c900` | 类型名 `lVar1/pbVar2/pcVar3/__dest…` |
| 6 | next_url | `uVar_1000003c`→`uVar_100000d3`、`uVar_100000dc`→`uVar_100000ff`（5 次）、`uVar_100001df`→`uVar_100000f7` | `uVar_9500`,`uVar_d400` | 类型名 `cVar1/sVar2/UVar3…` |
| 7 | glob_word | `uVar_10000461`→`_45d`、`uVar_1000048a`→`_4be`、`uVar_1000049f`→`_4ba`、`uVar_1000050f`→`_52b`（各 decl+use）+ 内联单现 `_10000d51→_10000d75`、`_10000d7d→_10000da1`、`_10000ce5→_10000d09` | `uVar_23b00`(12 次),`uVar_8f00`(23 次),`uVar_9100`,`uVar_a100`,`uVar_a400`,`uVar_9500`,`uVar_23d00`(计数不同：m=2/M=5，非本族) | 7 个干净类型名 `bVar1/pUVar2/cVar3/iVar4/pcVar5/pcVar6/pcVar7`（golden decl 全文） |

交换标签共 **16 个 unique 空间 varnode**（1+1+1+1+2+3+7）。glob_word 的 4 个有 decl 的交换不是保序映射
（merged 有序 461<48a<49f<50f ↔ master 45d<4be<4ba<52b，第三/四名次互换）——不是整体平移，是**不同中间
varnode 存活**（见 §3c）。

glob_word 附带（归 (a) 证据，不属交换）：master 侧另有 3 处**无下划线** `uVarffffffffffffff70/-98/-c0`
（result/curl_cur.c:1233/1323/1396，raw 负 offset 走 Register 阶梯 `uVar{:x}`，printc.rs:1262/4243）；
merged 侧对应位置是孤儿 Stack 声明（`uStack_90` 等，归 VARMAP-ORPHAN-DECL-0001）。同一源槽位两侧走了
完全不同的命名分支——fallback 阶梯对空间判定敏感的直接证据。

## 2. Ghidra 命名决策链（锁定 oracle 亲读）

### 2.1 命名保证（为什么 golden 里没有 `uVar_` / `uniq<hex>`）

1. `coreaction.cc:2978-3002 ActionNameVars::apply`：
   - `linkSymbols`（:2930-2976）对每个 high 的 name representative 走 `hasName` 门（variable.cc:718-747）
     → `data.linkSymbol(vn)` 建 Symbol → 名字未定且 `getSymbolOffset()<0` 者入 `namerec`（:2964-2966）。
   - :2988-2997：`int4 base=1` 计数环——namerec 每个 symbol 经 `buildDefaultName` 命名。
   - **:2998 `data.getScopeLocal()->assignDefaultNames(base)`** —— 兜底总闸：把 ScopeLocal 里一切仍为
     `$$undef` 的 symbol 全部命名（`database.cc:2854-2869`，沿 SymbolNameTree 顺序，共用同一 `base`）。
2. `database.cc:1756-1785 Scope::buildDefaultName` → `varmap.cc:548-581 ScopeLocal::buildVariableName`：
   addrtied 且在 local range → `<typebase>Stack[X|Y]_<hex>`（auStack_238/iStack_40 形）；否则落到
   `database.cc:2434-2521 ScopeInternal::buildVariableName` 的 flag 阶梯
   （unaff_ / persist 寄存器名 / `in_` 非法输入 / `param_N` / addrtied `<tb><Space><paddedhex>` / extraout_ /
   **else 计数名 `<typebase>Var<index++>`**（:2501-2517，含 10 次 bump 重试 + makeNameUnique）——golden 的
   `uVar2/iVar5/fVar9` 即此分支）。
3. 结论：**Ghidra 打印期每个显式变量都有 symbol**；golden 零兜底不是巧合，是 `assignDefaultNames` 的全称命题。

### 2.2 打印兜底（symbol 仍为 null 时才发生）

`printlanguage.cc:238-257 PrintLanguage::pushSymbolDetail`：

```cpp
Symbol *sym = high->getSymbol();
if (sym == (Symbol *)0) {
  pushUnnamedLocation(high->getNameRepresentative()->getAddr(),vn,op);   // :244-246
}
```

`printc.cc:1938-1945 PrintC::pushUnnamedLocation`：`s << addr.getSpace()->getName(); addr.printRaw(s);`
→ 形如 `uniq10000044` / `ram0000c900`（**空間名 + printRaw 十六进制**），且打印的是
**name representative 的地址**，不是当前实例的 offset。E2E golden 中该分支 0 次触发。

### 2.3 uniqid 生命周期（offset=出生证明）

- `varnode.cc:1265-1271 VarnodeBank::createUnique`：`Address addr(uniq_space,uniqid); uniqid += s;`
  ——**按尺寸步进的单调计数器**。
- `varnode.cc:1240-1243 VarnodeBank::clear`：`uniqid = uniqbase`（**清零重置**）；由 `funcdata.cc:84-108
  Funcdata::clear` → `:102 obank.clear()` 按函数调用 → offset 是**函数内、上次 reset 之后**的分配史。
  （`action.cc:553-582 ActionRestartGroup::apply` 的 restart 走 `clearAnalysis`，不重置 obank。）
- 因此 helpf 的稳定标签 `uVar_100001c1`（双侧同 offset）与交换标签 `0xfc/0x90`（不同）可以共存：
  两执行器的差异不在"总分配数"（到 0x1c1 时已一致），而在**打印位置 P 上存活的那个 varnode 出生槽不同**
  （master 存活了出生于 0x90 的实例、merged 存活了 0xfc 的实例；glob_word 的非保序映射是同一现象的直接证据）。

### 2.4 Rust 对应物（本 session 实读）

| Ghidra | Rugra | 判定 |
|---|---|---|
| coreaction.cc:2978-3002 ActionNameVars::apply（含 :2998 assignDefaultNames） | `src/coreaction.rs:4736-4910`（namerec 环 :4877-4899 + `assign_default_names` :4900-4904） | 已移植 |
| database.cc:2854-2869 assignDefaultNames | `src/database.rs:2668` | 已移植 |
| varmap.cc:548-581 / database.cc:2434-2521 buildVariableName | `src/varmap.rs:3000-3043` / `build_variable_name_internal:3052+` | 已移植（VARMAP-NAMING-REPIN-0001 fixture MATCH） |
| printlanguage.cc:244-246 + printc.cc:1938-1945 pushUnnamedLocation | `src/printc.rs` **三条互相不一致的阶梯**：`get_varnode_display_name_inner` 尾部 `:4237-4261`（Register→`uVar{:x}`:4243 / Stack→`local_`/`param_stack_` / **Unique→`uVar_{:x}`:4258**）；RPN 原子路径 `:1255-1270`（Register→`uVar{:x}`:1262 / Stack→`local_`/`param_stack_` / else→`vn_`）；`push_varnode` `:8174-8208`（**Unique→`uVar_{:x}`:8199**、Ram→`DAT_`:8204）；`emit_inline_expr` `_`臂 `:5202` | **形式偏离（a）**：`uVar_<hex>` vs `uniq<printRaw>`；且用 `vn.get_offset()`（当前实例）而非 name representative 地址 |
| varnode.cc:1265-1271 / :1240-1243 | `src/varnode.rs:2496-2500` `create_unique`、`:2541-2549` `create_def_unique`、`:2731-2736` `clear`（`ANALYSIS_UNIQUE_START=0x1000_0000`，:30） | 忠实 |

2026-08-17 的全语料 census（TODO_BOARD :1191 行）已证：`nameable∧无符号 high 计数 = 0`——
`hasName` 门本身忠实（Ghidra 同判拒绝 implied/unaffected/spacebase）；uVar_ 兜底触发的原因是
**这些 varnode 以"显式变量"形态活到了打印期**（Ghidra 的 IR 在上游就把它们消除/内联），加上
Rugra printc 内联缺口（`inline_candidates` 未覆盖 → 不内联 → 兜底命名）。

## 3. 根因分类（任务定义的 a/b/c）

**分类对象 = 每处交换（16 标签 / 7 函数）。交换的"delta"与"存在"是两个不同问题，分开判：**

| 类 | 定义 | 计数 | 判定依据 |
|---|---|---|---|
| (c) 唯一 offset 分配序差异 | merged↔master 的**标签数值差异**本身 | **16/16 交换标签（7/7 函数）** | 全部交换是同分支 `uVar_{offset}`→`uVar_{offset}`（无 uVar_↔iStack_/uStack_ 分支翻转）；offset 是 uniqid 出生槽（varnode.cc:1265/:1240；varnode.rs:2496/:2731）；非保序映射（glob_word）+ 稳定标签共存（helpf 0x1c1）证明是"不同中间 varnode 存活"而非计数器整体平移。**语义上 Ghidra 也由创建序决定**（§2.3），修复不属于 printc/varmap 域——任何上游 Action/Rule 执行序变化都会重排它；双侧 fixture 必须钉创建序（§5 观察面 3） |
| (b) varmap 命名到达率不足 | 标签**存在**（golden 该位置是计数名/类型名，双侧都不是） | **7/7 函数的全部 36+29 个兜底名**（含未交换的稳定兜底） | golden 0 个 `uVar_`：`assignDefaultNames` 全称命题（coreaction.cc:2998）保证每个显式变量有 symbol；Rugra 侧同一 varnode 打印期 symbol==null（printc.rs:4215-4218 `high` 缺失或名为空 → 落空间阶梯）。**与孤儿声明（VARMAP-ORPHAN-DECL-0001）不同根但同域**：孤儿=符号化了但零存活使用（极性相反）；两者都收敛到"打印期变量集 ≠ Ghidra symbol⇔活跃范围耦合"。细分门（has high? / has_name? / link_symbol? / write-back 桥?）需 §5 观察面 2 的 runtime 证据 |
| (a) printc 兜底名选取分支与 Ghidra 不同 | 兜底**形式**与**地址来源**偏离 | **0/16 交换 delta**（交换本身无 (a) 分量）；**3 处潜在形式偏离全局成立** | ① 形式：`uVar_<hex>`（printc.rs:4258/8199/5202）vs Ghidra `uniq<printRaw>`（printc.cc:1938-1945）；② 地址来源：`vn.get_offset()`（当前实例）vs `high->getNameRepresentative()->getAddr()`（printlanguage.cc:245）——**同一 high 的多实例会被碎片化成 N 个不同标签**（my_get_line 2 个、next_url 3 个、glob_word 7 个交换标签很可能就是碎片化的放大面）；③ 空间阶梯分裂：三条阶梯不一致（4237-4261 / 1255-1270 / 8174-8208），master 的 `uVarffffffffffffff70`×3 证明 Register 阶梯可吞 raw 负 offset。golden 从不触发该分支 → 对 golden 不可见（latent），但按铁律 2.1 属可 fixture 观测的映射函数偏离 |

**结论一句话：交换 delta 全部是 (c)（执行序域、非 printc/varmap 缺陷）；交换的可见性（标签存在）全部是 (b)
（符号化到达）；(a) 是兜底一旦触发时的形式/地址偏离（latent，但三条阶梯不一致 + 碎片化是真实代码缺陷）。**

关键洞察（修复排序依据）：Ghidra 的计数名（`uVar2`）**不编码 uniqid**——符号化到达后，标签自然与
创建序解耦，上游执行序变化不再引起标签漂移。**治本 = (b)，不是追 (c) 的 offset 数值。**

## 4. 修复切片建议（write-set + 串行关系 + 优先级）

租约现状：**a30 持有 printc.rs**（PRINTC-PTRCONST-DAT-SYMBOL-0001 M4 修中）；`VARMAP-ORPHAN-DECL-0001`
QUEUED 待 a30（write-set `src/{printc,varmap}.rs`）；a31 = `src/fspec.rs`（无重叠）；a34 = heritage/varnode
fixture 重钉（已完成，无 src 冲突）。

| 切片 | 内容 | write-set | 串行关系 | 优先级 |
|---|---|---|---|---|
| **C（fixture 先行）** | 双侧 fixture（§5）：先拿 runtime 证据把 16 标签逐个钉到 (b) 的具体失败门，并建立 uniqid 序投影基线 | `tests/oracle/printc_unnamed_1204.{cc,rs,metadata.json}` + `tools/run_printc_unnamed_oracle.sh`（新文件，从 varmap_unlinked_locals runner 派生）+ TODO 行 | **无冲突可立即发射**（不动 src/；a34 的 heritage runner 模式可直接复用） | **P0（证据驱动其余切片）** |
| **B1（碎片化止血）** | 兜底地址来源统一：`uVar_`/`uVar` 阶梯全部改用 high 的 name representative（对齐 printlanguage.cc:245；Rust 侧 `get_name_representative` 已存在，coreaction.rs:4665 在用）——同 high 多实例塌缩成单标签 | `src/printc.rs`（get_varnode_display_name_inner / push_varnode / 1255-1270 三点）+ `docs/api/printc.md` | **串行在 a30 M4 之后**（同文件）；与 VARMAP-ORPHAN-DECL-0001（prettyprint 声明过滤 + varmap 窗口生命周期）**函数级不重叠但文件重叠 → 同文件单 writer 排队** | **P1**（预测：next_url 3→1、glob_word 7→N≈high 数、交换面缩小、E2E uVar_ 不同名数 36→显著下降） |
| **B2（到达率治本）** | 按 C 的证据修最大失败门：候选门序 = ① printc 内联缺口（implied high 应内联而非命名——2026-08-17 census 的 glob_url 结论推广到 7 函数）② ActionNameVars write-back 桥（coreaction.rs:4918-4940 按 `fd.high_symbols`+loc_tree 回写 display name，可能漏后加入的实例）③ 上游 IR 形态（copy-prop/DeadCode/MarkExplicit 差异使 varnode 显式存活——Ghidra 侧早消） | 视证据落在 `src/{printc,coreaction,varmap}.rs`；若为 ③ 则登记到 Action/Rule 对应域 TODO，不在本族强行修 | 依赖 C 的观察面 2 输出；B1 之后同文件串行；**与 a30/a31 无关，与孤儿声明 agent 协调 varmap.rs** | **P1（治本）** |
| **A（形式对齐）** | ① 兜底形式改 `pushUnnamedLocation`（空間名+printRaw，printc.cc:1938-1945；实现前须读 address.cc printRaw 的确切格式）；② 三条阶梯合并为单一 `push_unnamed_location` helper（消灭 `uVar{:x}` Register 阶梯吞负 offset 的 `uVarffffffffffffff70` 类产物） | `src/printc.rs` + docs/api/printc.md | a30 之后；**放在 B1/B2 后做**——B2 消灭大部分触发点后，A 的输出搅动面（262→残余数）最小 | **P2**（latent，golden 不可见；对齐后 E2E 会把残余 uVar_ 变成 uniq<hex> 形——需 Differential 块说明） |
| （不修）(c) offset 数值 | 追两侧 uniqid 数值一致无意义：Ghidra 语义也由创建序决定（§2.3），且 golden 0 兜底 → 无真值可追 | — | — | 不立项；(c) 的可控面 = B2 让标签不再编码 offset |

**验收门（B1/B2/A 任一落地）**：`compare_ghidra.py` defects/numbering 不劣化 + `## Differential` 块逐函数
解释 uVar_ 计数变化（预期方向：不同名数 36→更低、7 函数交换面收敛）；B2 若触 varmap/coreaction 白名单 →
机制 C Cross-Review。

## 5. 双侧 fixture 设计（观察面）

派生自 `tests/oracle/varmap_unlinked_locals_1204.*`（现有 6 case 只观察 hasName/linked；本设计补三个轴）。
Ghidra 侧 `.cc` 直接以 locked oracle 编译，Rust 侧同 case 逐条对拍：

**观察面 1 — 命名分支命中**（(a)/(b) 判据）
每 case 打印 `buildVariableName` 结果 + 命中分支标签：`{stack-form, counter(<tb>Var<n>), persist-reg,
in_, param_N, extraout_, addrtied-<Space><hex>, unnamed(<space><printRaw>)}`。
cases：i) addrtied stack 正/负 offset（Stack_/StackX_）；ii) 零 flag 高（→计数名 uVarN）；iii) persist 寄存器；
iv) 非法输入；v) symbol-less 显式 unique varnode 直喂 print（→Ghidra `uniq<printRaw>` vs Rugra 现状 `uVar_<hex>`
——钉出 (a)①② 的双侧真值）。

**观察面 2 — 符号化到达**（(b) 的门序证据）
对每个 unique 空间存活 varnode 打印五元组：`{has_high, has_name 门结果, link_symbol 返回, symbol 终名,
print 期名}`。直接覆盖 7 函数的 16 个交换标签的可构造最小重现（如 helpf 的 `& 2` 判式形、match_url 的
`while (X != '#')` 形）；出口即 §4-B2 的门序表。

**观察面 3 — uniqid 序投影**（(c) 的钉序基线）
在固定 Action 边界（如 oppool2 前/NameVars 前）遍历 obank unique 空间 varnode，按 offset 序打印
`(offset, size, def-op SeqNum, opcode)`。双侧逐字节 MATCH = 创建序钉死；此后任何执行器改动的标签漂移都能
在该投影上二分定位（比 C 文本 diff 早一个阶段）。

**pin 三件套**（照 HANDOVER 套路）：runner shell 变量（commit/tree/git blob id）+ metadata comparand
（文件 sha256）+ overlays 表；oracle 侧锁 `e40ed130…`。

## 6. 风险与边界

- B1 有 E2E 搅动：同 high 多实例塌缩会改变既有 262 处 uVar_ 中的多标签函数文本（my_get_line/glob_word 重组
  decl 块）——必须 Differential 块逐函数归因；这正是消除"漂移放大面"的目的。
- A 落地后 E2E 残余兜底变为 `uniq<hex>` 形——对 golden 仍是差异（golden 0），只是从"自创形式"变"oracle
  兜底形式"；真值闭合仍取决于 B2。
- (c) 的 fixture（观察面 3）在执行器 swap（如未来 restart/breakpoint 行为改动）后会 MISMATCH——这是设计
  行为：该投影就是用来报警执行序漂移的，MISMATCH 时归 ACTION 域而非 printc 域。
- 本审计为只读：未改任何 repo 文件、未跑 cargo；所有结论基于上述指纹文件 + 锁定 oracle 源码实读。

## 7. 浓缩结论

- **根因分布**：(c)=16/16 交换 delta（7/7 函数，执行序域，不立项修）；(b)=7/7 函数的存在面（符号化到达，
  治本）；(a)=0/16 交换 delta，但 3 处全局形式偏离（uVar_ 形 vs uniq<printRaw>、实例 offset vs name
  representative、三条阶梯分裂）。
- **最优先切片**：C（双侧 fixture，零 src 冲突立即发射）→ B1（name-representative 统一，a30 后）→
  B2（到达率，证据驱动）→ A（形式对齐，最后）。(c) offset 数值不追。
- 报告路径：`/tmp/rugra-reports/A35-PRINTC-UNLINKED-REF.md`
