# R8 — 独立复核报告：VARMAP-LOCALWINDOW-0001（机制 C）

- **对象**: worktree `/home/wirs/.cache/rugra-wt-varmap-localwindow`，分支 `agent/varmap-localwindow`，HEAD `e7ae84f`（"align: port ScopeLocal::resetLocalWindow local-window wiring"）
- **复核者**: 独立复核 Agent（自读 Ghidra 原文，未采信实现者 Evidence 声明）
- **Oracle**: Ghidra 12.0.4，commit `e40ed13014025f82488b1f8f7bca566894ac376b`（worktree 内 `ghidra/` symlink 指向主仓，runner 三重 pin：commit/tag/tree+Makefile blob，见 §5）
- **日期**: 2026-08-24
- **结论**: **REJECT**（一处真实 MISMATCH + 等价论证漏洞 + 铁律 3 流程缺口；核心移植在被覆盖域内忠实、证据链自洽，修复量小——见 §7 修正方向，修复后可快速复审 APPROVE）

---

## 1. 复核方法与范围

逐行自读以下 Ghidra 原文（全文，非签名行）后与 Rust 对照：

| Ghidra 原文 | 内容 |
|---|---|
| varmap.cc:341-351 | ScopeLocal 构造（min/max 初值、rangeLocked=false） |
| varmap.cc:432-460 | **resetLocalWindow** 全文 |
| varmap.cc:494-546 | isUnmappedUnaliased / markNotMapped（removeRange→symboltab:545） |
| varmap.cc:548-581 | **buildVariableName**（:555 门读原型 localRange） |
| varmap.cc:587-612 | adjustFit（:593 getRangeTree().longestFit） |
| varmap.cc:632-655 | AliasChecker::deriveBoundaries（localBoundary 从原型 paramrange 推导） |
| varmap.cc:660-730 | AliasChecker::gatherInternal / gather / hasLocalAlias |
| varmap.cc:864-919 | **MapState 构造**（:864-875 rn 拷贝减 pm）+ **addRange**（:896-908） |
| varmap.cc:960-996 | **reconcileDatatypes** 全文 |
| varmap.cc:1063-1082 | **initialize** 全文（:1067 lastrange 先于 :1069 empty） |
| varmap.cc:1256-1325 | restructureVarnode（:1260-1261 MapState 组装）+ restructure |
| varmap.cc:1332-1390 | markUnaliased（对照消费面，本 commit 未触碰） |
| varmap.hh:174-259 | MapState/ScopeLocal 声明与 doxygen |
| address.hh:197-210 | **Range::operator<（决定性：只按 (spaceIndex, first) 比较，不含 last）** |
| address.cc:468-487 / 512-537 / 562-584 | RangeList::inRange / longestFit / **getLastSignedRange** |
| space.hh:383-393 | AddrSpace::wrapOffset（off ≤ highest 恒等；否则取模） |
| fspec.cc:2263-2319 | defaultLocalRange / defaultParamRange |
| fspec.cc:2339-2354 | ProtoModel 默认构造（stackgrowsnegative=true, :2349） |
| fspec.cc:3879-3885 | FuncProto::setScope（model==0 → defaultfp） |
| fspec.cc:5585-5653 | checkInputTrialUse（:5616 hasLocalAlias 唯一调用点） |
| fspec.hh:838/978/1539/1541 | getLocalRange / isStackGrowsNegative 内联 |
| funcdata.cc:55-96, 820-836 | resetLocalWindow 三个调用点（构造/clear/decode） |
| coreaction.cc:2274-2290 | ActionRestructureVarnode::apply（numpass、aliasyes） |
| action.cc:539-570 | ActionRestartGroup（重启**不**调 Funcdata::clear） |

Rust 侧通读：`src/varmap.rs`（diff 全部 hunk + 周边消费面 mark_not_mapped/adjust_fit/longest_fit/build_variable_name/mark_unaliased/restructure）、`src/coreaction.rs:775-902`（ActionRestructureVarnode）、`src/action.rs:1160-1210`（管线组装，mainloop=RULE_REPEATAPPLY）、`src/fspec.rs`（localrange 解析/ProtoModelFull/aliascheck 调用点）、fixture 三件套 + runner。

---

## 2. 四类决定性语义核对表

### 2.1 引用/输出参数 — ✅ PASS（一处注明）

| 项 | Ghidra | Rust | 判定 |
|---|---|---|---|
| resetLocalWindow 读 fd | `fd->getFuncProto()`（只读引用） | `&Funcdata` 只读，`func_proto_*` 三桥经 `get_model_name()`→注册表→defaultfp→默认构造，镜像 setScope 回退序（fspec.cc:3879-3885） | ✅ |
| 并集树安装 | `glb->symboltab->setRange(this,newrange)` 覆盖整个范围树 | `self.local_range = collect(...)` 整体覆盖赋值（varmap.rs:2582-2586） | ✅ |
| MapState 减除 | `: range(rn)` 值拷贝，`removeRange` 不回写 scope 树 | `build_map_state` 重建临时 RangeList 减 paramrange，不回写（varmap.rs:2612-2628） | ✅ |
| reconcile 类型写回 | `newList[startPos]->type = startDatatype` 指针写回组内全部成员 | `new_list[start_pos].dtype = start_datatype.clone()`（varmap.rs:1686-1690, 1703-1706） | ✅ |
| buildVariableName 门 | **:555 读 `fd->getFuncProto().getLocalRange()`（原型自身窗，非并集树）** | `local_range_in_range` → `proto_local_range`（varmap.rs:3308-3312） | ✅ 双窗分立正确 |
| rangeLocked 早退（:439） | `<localdb lock>` decode 可置位 | 无 Rugra 路径（decode 未移植），注释说明、唯一可达行为为无条件安装 | ✅ 降级有据 |

### 2.2 循环边界/遍历顺序 — ❌ 一处 MISMATCH（midway 谓词）

| 项 | Ghidra | Rust | 判定 |
|---|---|---|---|
| 并集构造序 | 先 localRange 全部 range，后 paramrange（:447-458） | 同序（varmap.rs:2575-2580） | ✅ |
| MapState 减除序 | pm 升序逐条 | paramrange.ranges() 顺序（varmap.rs:2621-2623） | ✅ |
| initialize 顺序 | lastrange 判空（:1067-68）**先于** maplist.empty（:1069） | 同序（varmap.rs:1619-1624） | ✅（两侧均无副作用，顺序本不可观察，仍忠实） |
| 排序稳定性 | `stable_sort`（:1078） | `sort_by`（Rust 稳定排序） | ✅ |
| **getLastSignedRange 探测边界** | `upper_bound(Range(spaceid,midway,midway))`，**Range::operator< 只按 (spaceIndex, first) 比较（address.hh:202-205，不含 last）**→ upper_bound = 第一条 first>midway 的 range，`--iter` 到**最后一条 first≤midway 的 range（含 first==midway 的任意 last）** | `partition_point(|&(first,last)| first < midway \|\| (first == midway && last <= midway))`（varmap.rs:1032-1035）→ **排除 first==midway && last>midway 的 range** | ❌ **MISMATCH** |

**MISMATCH 细节（REJECT 主因）**：当窗口存在 `first == midway (0x7fffffffffffffff) && last > midway` 的 range 时：
- Ghidra 第一探测返回**该 range**（operator< 下它与键 (midway,midway) 等价，upper_bound 越过它，--iter 落在它上面）；
- Rust 谓词将其排除在"正半区"前缀外，返回**前一条正 range**（若无则落入 `ranges.last()` 负半区末位）。
- 后果：`initialize` 端点 `wrapOffset(lastrange->getLast()+1)` 放错位置 → open hint 的数组上界/类型错误。

例：窗口 `{[0x100,0x200], [0x7fffffffffffffff, 0x8000000000000100], [0xfffffffffff0bdc0, 0xffffffffffffffff]}`（Rugra fspec.rs:6735 **确实解析** cspec 自定义 `<localrange>`，此形态可表示）：
Ghidra lastrange=[midway,0x8000...0100] → 端点 0x8000000000000101；Rust 返回 [0x100,0x200] → 端点 0x201。

**加重情节（机制 D 红旗）**：varmap.rs:1021-1023 注释断言 "`(set<Range> orders by (first,last))`" —— **与 address.hh:202-205 事实相反**（只比较 spaceIndex+first）。这是"引用了行号但没引用那一行的决定性语义细节"的典型模式：谓词正是从这个错误前提推导出来的。

**可达性评估**：默认模型不可达（defaultLocalRange first=max-999999、defaultParamRange first=0，均不触及 midway；fspec.cc:2263-2319）；curl/httpd 语料与 fixture 均为默认窗，故 5/5 MATCH 不受影响、fixture sha 不变。但 Rugra 已具备解析自定义 `<localrange>` 的能力，该角点是**可表示输入域内的真实语义偏差**，不是死代码。

### 2.3 计数器/累加器 — ✅ 单趟忠实；❌ 等价论证有洞（跨趟）

| 项 | Ghidra | Rust | 判定 |
|---|---|---|---|
| min/maxParamOffset 复位 | resetLocalWindow :436-437 每次调用复位 | reset_local_window varmap.rs:2568-2569 复位 | ✅ 语句级 |
| markNotMapped 累积 | :520-524 只缩 min/扩 max；窄化 removeRange :545 **持续存在于 scope 树** | mark_not_mapped varmap.rs:2145-2178 同构 | ✅ 语句级 |
| reconcile startPos | 单游标，组切换回填 startPos..end，尾部收尾 | varmap.rs:1664/1683-1690/1703-1706 同构 | ✅ |
| iter 复位 | `iter = maplist.begin()`（:1080） | `iter_pos = 0` | ✅ |
| **复位时机等价论证** | resetLocalWindow 仅在构造（funcdata.cc:70）/`Funcdata::clear`（:96，仅 Architecture::clearAnalysis/ifacedecomp 显式再反编译）/decode（:836）调用；**mainloop 是 RULE_REPEATAPPLY + ActionRestartGroup 重启均不调 clear（action.cc:539-570）**→ 第 2+ 趟 restructureVarnode 使用**已窄化窗口 + 跨趟累积的 min/max** | coreaction.rs:791 每次 apply `ScopeLocal::new()`（丢弃上一趟符号与窄化），varmap.rs:2721 每趟 reset_local_window 重装全窗 + 复位 min/max；mainloop（action.rs:1194）含 restructure，多趟必然发生 | ❌ **"每轮 fresh scope ≡ fd 生命周期"仅在第 1 趟成立**。Ghidra 第 2+ 趟：markNotMapped 窄化（如超出 [0,511] 的出参槽、restrict 标记的临时区）持续生效、min/max 累积（Y 命名门 :571-574 消费）；Rugra 每趟全量重置，且 ActionRestrictLocal（action.rs:1193，:5502 位）在上一趟 scope 上的窄化在下一趟 restructure 前即被丢弃 |

**定性**：fresh-scope-per-pass 是**预先存在的架构缝隙**（本 commit 未引入；旧正窗代码同样每趟重装），且本 commit 使单趟窗口首次与 Ghidra 第 1 趟精确一致（严格更近）。但 Evidence 块断言"installing here is the same lifecycle point"而未限定单趟，属**等价论证过度声明**，须限定 + 登记 TODO（跨趟 scope 持久性 / markNotMapped 窄化丢失）。暴露面：出参栈槽 >511 字节、restrict 标记临时区，在第 2+ 趟被 Rugra 重新映射为符号而 Ghidra 保持 unmapped。

### 2.4 排序/比较键 — ✅ PASS

| 项 | Ghidra | Rust | 判定 |
|---|---|---|---|
| inRange 无符号 extent 回绕 | `(*iter).last >= offset+size-1`（uintb 回绕，address.cc:484） | `last >= offset.wrapping_add(size).wrapping_sub(1)`（varmap.rs:1014） | ✅ 位级等同 |
| inRange 定位 | upper_bound + --iter = 最后一条 first≤offset（first-only 排序） | `partition_point(first <= offset)`（varmap.rs:1009-1013）——此处谓词用对了（≤），与 operator< 同构 | ✅ |
| 边界数学（fixture 实证） | `bdbf`（窗首-1）：upper_bound→--iter→begin→false；`bdc0`（窗首）：等价键→返回该 range→last≥bdc0 ✓ | 同结果；双侧 fixture 字节一致 | ✅ oracle 实证 |
| 空间测试 | `(*iter).spc != addr.getSpace()` → false | Vec 无 space（全栈 range，测试被涵盖）；前提：窗口只能含栈 range——当前成立（见 §6-S3 风险注记） | ✅（有条件） |
| sstart 符号扩展 | byteToAddress+sign_extend(addrSize*8-1)+addressToByte（:904-906） | `start as i64`——wordSize==1 且 8 字节栈上位级等同 | ✅（限 8 字节 wordsize-1 栈） |
| RangeHint::compareRanges | sstart 有符号 → size 小先 → rangeType → flags → highind（:321-335） | RangeHint::compare 同键（分组键 start/size/flags、去重 compare==0、择优 typeOrder<0 均逐行核对 reconcileDatatypes :960-996） | ✅ |
| 端点 | `wrapOffset(lastrange->getLast()+1)`：8 字节栈 off≤highest 恒等 → wrapping_add(1)；默认负窗 max+1 回绕=0 | `last.wrapping_add(1)`（varmap.rs:1631） | ✅（限 8 字节栈；<8 字节需 wrapOffset 取模，见 §6-S4） |
| 端点 hint 字段 | `(high,1,sst,defaultType,0,endpoint,-2)`（:1075） | 同（varmap.rs:1637-1641） | ✅ |
| 命名 X/Y 分支 | start≤0→X 取负；min<max 且 (负增长 ? off<min : off>max)→Y（:566-576） | 逐分支同（varmap.rs:3011-3024） | ✅ |

---

## 3. MapState 单窗→多窗结构改造 — ✅

- `range: Vec<(first,last)>`（varmap.rs:1241-1247）取代 `local_start/local_end`，对应 varmap.hh:176 `RangeList range` 成员模型。
- 构造减 paramrange 移到调用方 `build_map_state`（注释声明"window can double as the scope's range tree before subtraction"），与 Ghidra "ctor 减除" 的净效果等同：MapState 收到的窗口 = 并集树 − paramrange，值语义、不回写。✅
- `add_range` 门：`window_in_range(&self.range, start, size)`，完整 extent 落单一 range，含 None 回退 default_type（:899-900 对应）。✅
- 空窗行为：`window_in_range` 空表 false；`initialize` 经 `get_last_signed_range` None → false（:1067-68 对应）；`build_map_state` 空并集 → 空 analysis → add_range 全拒 → initialize false → restructure 返回（restructure_varnode 提前退出，对应 Ghidra "No references to stack at all"）。✅
- 观察口 `analysis_range()/hints()` 为 RUGRA-GLUE 只读（Ghidra fixture 经 `#define private public` 直读，对称合理）。

## 4. ScopeLocal 双窗分立 — ✅（本 commit 的关键正确性判断）

- **Ghidra 事实**：buildVariableName :555 读 `fd->getFuncProto().getLocalRange()`（原型自身窗）；adjustFit :593 读 `getRangeTree()`（symboltab 树）；markNotMapped :545 removeRange 作用于 symboltab 树。两窗**确实分立**。
- **Rugra**：`local_range`（并集树，longest_fit/mark_not_mapped/in_scope 消费）vs `proto_local_range`（buildVariableName 门）。正偏移栈参数（在并集、不在原型窗）正确 fall through 到 `build_variable_name_internal` 的 16 位十六进制 addrtied 形态——fixture naming 案例双侧字节一致（`iStack0000000000000010` 等）实证。✅
- proto_local_range 仅在 reset_local_window 填充；fd.scope 恒由 ActionRestructureVarnode 安装（先 reset 后用），printc 仅 Clone 消费。无未初始化消费路径（printc.rs:11757 裸 scope 为 decl 发射测试，不走命名门）。✅

## 5. 双侧 fixture 证据 — ✅（独立重验）

- **pins**：metadata `oracle.commit=e40ed130…` ✓；`comparand.rugra_base_commit=dfd27ad`（=HEAD~1）✓；varmap.rs/fixture.cc/fixture.rs/runner/docs 的 sha256 与 HEAD 工作树逐一重算吻合（f5098caa/c94f5153/35b53254/e505e372/4c4e2e65）；build.rs 当前 sha 与 pin 一致（runner.log 首跑曾有瞬时 mismatch，runner2/3 通过，现态自洽）。
- **独立重算**：`/tmp/rugra-localwindow-build/{ghidra,rugra}.stdout` 两侧 sha256 均 = `83c3d7423e23b6c4de3ec792b9f5bf9955f9be57bc043c720a3fe75e04977853`，`diff` 逐字节一致；与 metadata `expected_stdout_sha256`、commit message、runner 日志三方吻合。
- **关键观察值逐项手工验证**：
  - `local=fffffffffff0bdc0-ffffffffffffffff` = max−999999（999999=0xF423F，fspec.cc:2271-2278）✓；`param=0-1ff`（:2298-2307）✓；`union=0-1ff;fffffffffff0bdc0-ffffffffffffffff`（:441-459）✓。
  - 门案例：`bdbf`/`0`/`0x1ff` 无符号（出窗/被减除），`bdc0:1:char`/`8000:4:int`/`fffffff8:8:long` 入符号（含跨到窗末字节的 8 字节 extent）✓。
  - `ffffffffffffeff0:4104:int[1026]`：open 于 sp−0x1010 延伸至 sp−8 的 fixed long，0x1010=4104=4×1026 ✓；`fffffffffffffff0:16:int[4]`：无后续 fixed hint，被 initialize 端点（wrapOffset(max+1)=0）封顶 ✓——端点数学经真实 oracle 双侧执行验证。
  - 命名：`iStack_f0`（−0xf0）/`iStack_f4240`（−999999）入窗，参数区/出窗 fall through ✓。
- **诚实披露**：`overall=PARTIAL_MATCH`，LoadGuard addGuard + gatherSymbols re-feed 列 UNTESTED 并绑 `VARMAP-GATHEROPEN-GUARD-0001`——符合机制 B2（UNTESTED 禁 L3；模块维持 L2）。
- **fixture 质量**：C++ 侧为真实生产路径（真 Funcdata/ScopeLocal/FuncProto XML decode/无 localrange 覆盖的默认模型 → restructureVarnode → buildVariableName），非手写 expected。

## 6. 衍生影响核实

1. **varmap_naming_1204 失效原因**：✅ 证实。`tests/oracle/varmap_naming_1204.rs:26` `scope.local_range = local_ranges.to_vec()` 设置旧字段，命名门现读 proto_local_range → Rust 侧门不再打开、与锁定 oracle 输出必然分歧。确为"一行 proto_local_range 缺失"。
2. **varmap_unlinked_locals_1204 失效原因**：✅ 证实。`…_1204.rs:68` 同型直赋旧字段；且 metadata pin `varmap_rs=e9642192…` ≠ 现 `f5098caa…` → runner pin 门拒绝（不可变 fd runner 设计行为）。确为"comparand 过期"。**但两 fixture 的修复/重钉均未在本 commit 完成，也未登记 TODO（铁律 3 缺口，REJECT 次因之一）。**
3. **AliasChecker localBoundary "死区=行为等价"**：❌ **论证不成立（降级为"语料未观察"）**。Ghidra deriveBoundaries（varmap.cc:632-655）在有模型时把 localBoundary 从原型 paramrange 推导（默认=511）；Rugra 管线从不调用 `derive_boundaries`（varmap.rs:2731-2732 直接 `AliasChecker::new`），保持 0x1000000。死区差异 [511, 0x1000000)：该区间内的正偏移加法基在 Ghidra 会收缩 aliasBoundary，Rugra 跳过；消费面唯一（hasLocalAlias → fspec.cc:5616 ↔ fspec.rs:2136 markNoUse vs ancestor 路径），存在可构造的分歧输入（正偏移 alias + 负偏移栈 trial 组合），非行为等价。**预先存在**（本 commit 未触碰 AliasChecker），非本 commit 责任，但实现者的"仅死区有别"声明不实，须更正并登记。附带发现（预先存在，fspec 租约）：Rugra check_input_trial_use 缺 Ghidra `!getLocalRange().inRange → markNoUse`（fspec.cc:5618）与 callee_pop 分支——新增的 `func_proto_local_range` 桥恰可供给前者。

## 7. REJECT 判定与修正方向

### R1（主因）get_last_signed_range 谓词 MISMATCH + 错误排序键断言
- **Rugra**: `src/varmap.rs:1032-1035`（谓词）、`src/varmap.rs:1021-1023`（错误注释 "(set<Range> orders by (first,last))"）
- **Ghidra**: `address.hh:202-205`（operator< 只比 spaceIndex+first）、`address.cc:565-573`（upper_bound+--iter 语义）
- **修正方向**: 谓词改为 `partition_point(|&(first, _)| first <= midway)`（即 window_in_range:1009 同型），删除 `first == midway && last <= midway` 子句；注释改为引用 address.hh:202-205 的 first-only 排序键。**默认窗行为零变化**（[0,511]: 0≤midway 真；[max−999999,max]: first>midway 假 → 落 ranges.last()，与现状同）——修复后重跑 pinned fixture，stdout sha 必须仍为 `83c3d742…`（不变式验证）。
- **回归防护**: 建议补一条单测：`get_last_signed_range(&[(0x100,0x200),(midway,0x8000000000000100),(max-999999,max)]) == Some((midway,0x8000000000000100))`。

### R2（次因）跨趟等价论证过度声明
- **Rugra**: `src/varmap.rs:2717-2721` 注释与 Evidence 块"same lifecycle point"、`docs/api/varmap.md:114` 同文
- **Ghidra**: `funcdata.cc:70/96/836`（resetLocalWindow 仅三处）+ `action.cc:539-570`（restart 不 clear）+ `coreaction.cc:2280`（repeatapply 多趟）+ `varmap.cc:545/520-524`（窄化/min-max 跨趟持续）
- **修正方向**: 措辞限定为"第 1 趟/经 clear 的边界等价"；登记 TODO（跨趟 ScopeLocal 持久性：符号累积、markNotMapped 窄化、min/max 跨趟保持），在 TODO 中写明暴露面（出参槽 >511B、restrict 临时区第 2+ 趟重映射）。

### R3（流程，铁律 3）
- `docs/TODO_BOARD.md` 无 `VARMAP-LOCALWINDOW-0001`、`VARMAP-GATHEROPEN-GUARD-0001` 行（仅存在于先行 commit 的 `docs/alignment_docs/MYGETLINE_VARMAP_MERGE_AUDIT_2026-08-24.md`）；两个失效 fixture 无重钉 TODO；本 commit 未更新看板。**修正方向**: 补三行 TODO（本任务送审状态、GATHEROPEN-GUARD、旧 fixture 重钉）。

## 8. 非阻断「建议」

- **S1** `window_in_range`/`get_last_signed_range` 的无 space 模型：现前提"窗口只含栈 range"成立（默认模型），但 fspec.rs:6735 已解析 `<localrange>`，若未来 cspec 声明非栈空间 range，需在 Vec 模型加 space 或在桥处过滤——建议注释标注该前提的失效条件。
- **S2** wrapOffset/sst 的 8 字节 wordsize-1 限定：32 位目标（addrSize<8 的栈，wrapOffset 取模语义）与 wordsize≠1 栈不在当前模型能力内——在函数注释标注，防未来误用。
- **S3** reconcile_datatypes 的 None-arm（varmap.rs:1664 附近）：Ghidra 对 null type 是解引用崩溃，Rugra 保守保 None——仅 test-only 路径可达，注释已说明，维持即可。
- **S4** aliasyes 未穿透（coreaction.rs:877-880 TODO）与 protectSwitchPaths no-op：预先存在、已注释，建议并入 R2 的跨趟 TODO 一并登记依赖。
- **S5** curl 差分门禁（机制 B）尚未在本分支运行（commit 已披露 pending）——merge 前必须跑 `compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl_1204.c` 并按门禁出 `## Differential` 块。

## 9. 复核者签字声明

本人已独立打开并逐行阅读 §1 所列全部 Ghidra 函数原文（锁定 oracle e40ed130 工作树），独立推导四类语义清单后与 Rugra 对照；未采信实现者 Alignment Evidence 块的任何断言（其中 2 处被证伪：§2.2 排序键前提、§6.3 死区等价）。fixture 证据经本地独立重算（sha/diff/边界数学手推）验证。判定：**REJECT**——R1 修复为单行谓词+注释更正（默认域零行为变化，pinned sha 不变式可即刻复验），R2/R3 为措辞限定与登记；完成后复审可快速 APPROVE。
