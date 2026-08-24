# C1 — my_get_line varmap/merge 域过度扩张：逐行修复方案（只读审计）

- 产出：只读审计 Agent（B6 分流 Top5 #5 板载建议并入 `MERGE-DATATYPE-SCALE-0001`）。
- 未修改仓库任何文件、未运行 cargo/build。
- oracle：Ghidra 12.0.4 `e40ed13014025f82488b1f8f7bca566894ac376b`。
- fresh 基线：`/home/wirs/.cache/rugra-threefunc-main-f7b3c31-XJYadF/artifacts/curl.stdout.c`
  （SHA-256 `fc9a33ba…91d60e7`，commit `f7b3c31`）；golden：`tests/golden/ghidra_curl_1204.c`。
- 函数级对照：fresh `curl.stdout.c:619-747`（119 行 body）vs golden `ghidra_curl_1204.c:1277-1346`
  （69 行 body，diff=151）。

## 0. 浓缩结论（三症状根因各一句 + 最早分叉行号）

| # | 症状 | 根因一句话 | 最早分叉（Ghidra vs Rugra） |
|---|---|---|---|
| 1 | 4096B 局部数组未恢复为 `bool buf[4096]` | varmap 的 local 分析窗口被硬编码为正向 `[0,0x100000)`，而 heritage/栈引用产生的偏移全是 Ghidra 式**符号扩展负偏移**（0xFFFFFFFFFFFxxxxx），`MapState::addRange` 把每一条 local/open hint 都当越界丢弃，open hint 从未进入 restructure，数组无从延伸。 | Ghidra `fspec.cc:2263 defaultLocalRange`（负向栈窗口 = `[getHighest()-999999, getHighest()]`）+ `varmap.cc:902 addRange` 的 inRange 门 vs **Rugra `src/varmap.rs:2407-2412`（`local_start=0; local_end=0x100000` 硬编码，方向相反）→ `varmap.rs:1184` add_range 丢 hint**。忠实的 `default_local_range` 已在 `src/fspec.rs:6244-6272` 存在但未被 varmap 消费。 |
| 2 | extraout varnode 未合并/吸收（`extraout_var`×5、`in_register_0000124x`×8 声明 + `__stack_chk_fail(0,…,14 实参)`） | `FuncCallSpecs::is_no_return()` 是硬编码 `false` 的 stub（CALLSPEC-0001），`__stack_chk_fail` 的 noreturn halt 从不插入，call 的投机寄存器实参与 INDIRECT 副作用输出全部存活到 ActionNameVars，被 `linkSymbol` 建成 ScopeLocal 符号并按 `extraout_`/`in_register_` 分支命名后从符号表整表打出。 | Ghidra `flow.cc:636-651 checkForFlowModification`（`fspecs.isNoReturn()` → `artificialHalt(noreturn)` + warning）vs **Rugra `src/flow.rs:120-123`（`is_no_return(){false}` stub）**；`flow.rs:1245-1254` 本体忠实但被上游 stub 废掉。merge 侧无缺陷（见 §3）。 |
| 3 | 负偏移名符号回绕（`in_stack_ffffffffffffedb8/edbc`、`uVar_100002eb` 族） | 与症状 1 同一根因的另一面：负偏移栈 varnode 不在 local 窗口内 → `ScopeLocal::buildVariableName` 的 localRange 分支永不命中，落到 `ScopeInternal::buildVariableName` 的 irregular-input 分支打出 `in_stack_<未符号化十六进制>`；符号未覆盖的 varnode 再落到 print 层自创兜底名（`uVar_{offset:x}`/`local_{:x}`）。 | Ghidra `varmap.cc:553-578 buildVariableName`（`getLocalRange().inRange(addr,1)` 命中 → `StackX_<正数>` 形式）vs Rugra `varmap.rs:2687 local_range_in_range(负偏移)=false` → `varmap.rs:2763-2770`（`in_stack_`）/ `printc.rs:4205-4220、8152`（`uVar{:x}`/`uVar_{:x}`/`local_{:x}` 自创名）。 |

三症状中 **varmap.rs 的窗口硬编码是症状 1+3 的单点根因**；症状 2 的根因在 flow/fspec（noreturn stub），
varmap/merge 只是泄漏面。`src/merge.rs` 经逐段核对（`merge_test_required` extraout 禁合、`merge_addr_tied_inner`、
`is_extra_out`）均忠实，**merge.rs 不需要为本症状改动**；板上 `MERGE-DATATYPE-SCALE-0001`（mergeByDatatype 域）
与本三症状不同层，建议本报告条目并入该 TODO 时注明分层。

## 1. 双侧输出对照要点

golden（`ghidra_curl_1204.c:1279-1346`）：
- 声明集 11 项：9 个普通局部 + `long in_FS_OFFSET;` + `bool buf [4096];`（fgets 4096 字节缓冲被恢复为 1 字节
  元素数组，元素 `bool` 来自 `TypeFactory::concretize(TYPE_UNKNOWN,1)`）。
- `__stack_chk_fail()` **零实参**，头带 `/* WARNING: Subroutine does not return */`。
- 无 extraout/in_register/in_stack 名（`in_stack_` 全文件仅 28 处且全部在参数侧异常位置，如
  `in_stack_fffffffffffffc78`，形式本身合法）。

fresh（`curl.stdout.c:621-714`）：
- 声明 50+：`extraout_var…extraout_var_03`×5（**无类型**声明）、`in_register_00001240…13c0`×8（步长 0x40）、
  `in_register_00000110`、`in_stack_ffffffffffffedb8/edbc`、`in_ram_00017500`，再加 ~30 个
  `uVar_XXX`/`uVar{:x}`（Unique/Register 兜底名）。
- `__stack_chk_fail(0,0,0,0,0,0,(undefined8)(uVar1200>>0x40),…)` **14 实参**（6 个清零寄存器参 + 8 个
  16 字节寄存器对的高半字），无 noreturn warning。
- 两个空 do-while（strlen 惯用法体丢失）与 `*uVar_c900 == *uVar_c900` 恒真自比较（canary 检查塌缩，
  golden 为 `lVar1 != *(long *)(in_FS_OFFSET + 0x28)`；FS 段寄存器未入 `register_names` 表，
  见 §6 关联观察）。

fresh 名字解码（供后续 grep 验收）：
- `in_stack_ffffffffffffedb8` = stack 空间符号扩展负偏移 −0x1248 的 input varnode 符号（varmap.rs:2767）。
- `uVar1200/1240/…13c0`（无下划线）= **Register** 空间 offset 0x1200+ 的未命名 varnode（printc.rs:4205）。
- `uVar_100002eb/uVar_23d00/uVar_c900/uVar_18`（有下划线）= **Unique** 空间未命名 temp（printc.rs:4220/8152）。
- `local_{:x}`/`param_stack_{:x}`（printc.rs:4209-4212，my_get_line 外其它函数出现）= Stack 空间无名兜底。

## 2. 症状 1：4096B 数组未恢复 — 完整证据链

### 2.1 Ghidra 恢复路径（数组从哪来）

1. `ProtoModel::defaultLocalRange`（fspec.cc:2263-2290）：负向栈时
   `localrange = [spc->getHighest()-999999, spc->getHighest()]`（8 字节地址空间即
   `[0xFFFFFFFFFFF0BDC0, 0xFFFFFFFFFFFFFFFF]`）；`defaultParamRange`（fspec.cc:2292-2307）= `[0,511]`。
   x86-64 cspec 显式给出范围时同理：**locals 在符号扩展负偏移侧，params 在 [0,511] 侧**。
2. `ScopeLocal::resetLocalWindow`（varmap.cc:432-460）把 localRange+paramRange 装进 symboltab 的 scope 窗口。
3. `MapState` 构造（varmap.cc:864-879）以该窗口为分析范围并**减去 paramrange**（:870-875）。
4. `MapState::addRange`（varmap.cc:896-919）`if (!range.inRange(Address(spaceid,st),sz)) return;`（:902）
   ——负偏移 hint 正常保留；`sst` 经 `byteToAddress`+`sign_extend(addrSize*8-1)`（:904-906）成有符号。
5. `MapState::gatherOpen`（varmap.cc:1211-1249）：`checker.gather(&fd,spaceid,false)` 后，对每个 addBase 根
   （如作为 CALL 实参的 buf 指针 `PTRSUB/INT_SUB(SP,#-0x1010)`，nonadduse=true 才入 addbase），
   `offset = alias[i]`（= `AliasChecker::gatherOffset` 常量和，varmap.cc:817-858），指针 pointee 类型下钻数组层
   （:1224-1227），`addRange(offset,ct,0,RangeHint::open,minItems)`（:1238）；LOAD/STORE LoadGuard 经
   `addGuard`（varmap.cc:1003-1039）也产 open hint。
6. `ScopeLocal::restructure`（varmap.cc:1294-1325）：open hint 与下一定点 hint（canary/下一个 local）不相交时
   `cur.size = next->sstart - cur.sstart`（:1314-1315）——**open 区间延伸 4096 字节**；
   `adjustFit`（:587-612）按窗口 `longestFit` 与既有符号收缩；`createEntry`（:617-628）
   `concretize(a.type)` 后 `num = a.size/ct->getAlignSize(); if (num>1) ct = getTypeArray(num,ct)`。
   `concretize` 把 1 字节 TYPE_UNKNOWN 变 **bool** → `bool buf[4096]`。与 golden 完全吻合。

### 2.2 Rugra 断链（逐行）

- `src/varmap.rs:2404-2412`：`restructure_varnode` 内
  `let local_start = 0u64; let local_end = 0x100000u64;`，注释自认 "Rugra uses the full stack extent"，
  并 `self.local_range = vec![(local_start, local_end - 1)]`。**方向与 Ghidra 相反**（盖住的是参数侧）。
- `src/varmap.rs:1184`：`if start < self.local_start || start >= self.local_end { return; }` ——
  heritage 产生的栈偏移（`src/heritage.rs:1026` BFS 从 RSP=0 起步累积 **i64** 常量和，
  `:1110 stack_off as u64` 存入 Stack 空间，如 −4136 → `0xffffffffffffefd8`）全部 ≥ 0x100000 → **每条 local
  hint 被丢**。`gather_spacebase`（varmap.rs:1393-1431，RUGRA 自创的 LOAD/STORE→fixed hint 合成器）与
  `gather_open`（:1438-1472）产出的 hint 同样被丢。
- `src/varmap.rs:1480-1483`：`initialize` 的 endpoint 也硬编码 `self.local_end`（Ghidra 为
  `wrapOffset(lastrange->getLast()+1)`，varmap.cc:1070-1075，即窗口**顶端** 0 —— 恰是负偏移世界的
  "最深 locals 上方"）。
- 忠实件已存在却未消费：`src/fspec.rs:6244-6272 default_local_range`（`[u64::MAX-999999, u64::MAX]`，
  逐字对齐 fspec.cc:2270-2278）；paramrange 的读取桥 `varmap.rs:935-948 func_proto_param_range` 也已有
  （fake_input_symbols 在用）——**local 侧缺同一个桥**。
- 次级缺口（窗口修好后才可见）：`gather_open` 未实现 `addGuard`（varmap.rs:1469-1471 注释自认；
  Ghidra varmap.cc:1241-1248/1003-1039，strlen 惯用法循环的 LOAD 需要它产 minItems=3 的 open hint）；
  `restructure_varnode` 缺 `gatherSymbols`（Ghidra varmap.cc:1269，typelocked 符号回灌为 hint）、
  `annotateRawStackPtr`（:1284-1285）与 `checkUnaliasedReturn`（:1282）；`MapState` 构造未减 paramrange
  （varmap.cc:870-875）。

### 2.3 四类决定性语义核对表（症状 1）

Ghidra 签名逐字摘录：

```cpp
// fspec.cc:2263
void ProtoModel::defaultLocalRange(void)
{ AddrSpace *spc = glb->getStackSpace(); uintb first,last;
  if (stackgrowsnegative) { last = spc->getHighest();
    if (spc->getAddrSize()>=4) first = last - 999999; ... localrange.insertRange(spc,first,last); } }

// varmap.cc:896
void MapState::addRange(uintb st,Datatype *ct,uint4 fl,RangeHint::RangeType rt,int4 hi)
{ ... if (!range.inRange(Address(spaceid,st),sz)) return;
  intb sst = (intb)AddrSpace::byteToAddress(st,spaceid->getWordSize());
  sst = sign_extend(sst,spaceid->getAddrSize()*8-1); ... }

// varmap.cc:1211
void MapState::gatherOpen(const Funcdata &fd)
{ checker.gather(&fd,spaceid,false); ...
  for(int4 i=0;i<addbase.size();++i) { offset = alias[i];
    ct = addbase[i].base->getType();
    if (ct->getMetatype() == TYPE_PTR) { ct = ((TypePointer*)ct)->getPtrTo();
      while(ct->getMetatype() == TYPE_ARRAY) ct = ((TypeArray*)ct)->getBase(); }
    else ct = (Datatype *)0;
    int4 minItems; if (addbase[i].index != (Varnode *)0) minItems = 3; else minItems = -1;
    addRange(offset,ct,0,RangeHint::open,minItems); } ... }

// varmap.cc:1294
bool ScopeLocal::restructure(MapState &state)
{ ... if (next->sstart < cur.sstart+cur.size) { if (cur.merge(next,space,glb->types)) overlapProblems = true; }
  else { if (!cur.attemptJoin(next)) {
      if (cur.rangeType == RangeHint::open) cur.size = next->sstart-cur.sstart;
      if (adjustFit(cur)) createEntry(cur); cur = *next; } } ... }
```

| 语义类 | Ghidra | Rugra 现状 | 判定 |
|---|---|---|---|
| 引用/输出参数 | `addRange` 按值入 `maplist`（堆 RangeHint*），`restructure` 内 `cur = *next` 值拷贝 | `RangeHint` Clone 入 Vec，`current = next.clone()` | 一致 |
| 循环边界/遍历顺序 | `stable_sort(compareRanges)`（sstart 有符号→size 小者先→rangeType→flags→highind），`gatherOpen` 按 `addbase.size()` 与 `alias[i]` **同长对位** | `sort_by(RangeHint::compare)` 键一致（varmap.rs:404-426 忠实）；gather_open `aliases.get(i).unwrap_or(0)`（varmap.rs:1446）——addbase/alias 同 push 序，对位一致 | 一致 |
| 计数器/累加器 | open 延伸 `cur.size = next->sstart-cur.sstart` 每区间一次性；`highind` 仅 absorb/attemptJoin 内更新 | varmap.rs:2493-2495 同式（`next.start.wrapping_sub(current.start)`，位级等价 sstart） | 一致（但窗口使 open hint 根本不存在） |
| 排序/比较键 | inRange 门用的是**无符号 offset 对 RangeList**（address.cc:468-487，窗口是符号扩展负偏移区间） | `start < local_start || start >= local_end`（varmap.rs:1184）形式一致，**但窗口数值在错误半区** | **MISMATCH（根因）** |

## 3. 症状 2：extraout/in_register 声明爆炸 — 完整证据链

### 3.1 Ghidra 消除路径（为什么 golden 一个都没有）

1. `__stack_chk_fail` 是 noreturn：`FlowInfo::checkForFlowModification`（flow.cc:636-651）在 call 后插入
   `artificialHalt(PcodeOp::noreturn)` 并 `data.warning("Subroutine does not return")`（golden 头部的
   WARNING 即此）。
2. halt 之后一切不可达 → call 的投机寄存器实参无读者、INDIRECT 副作用输出（`Funcdata::newIndirect`
   funcdata_op.cc:718-747 置 `Varnode::indirect_creation`）被死码/不可达阶段删除 → 到
   `ActionNameVars::linkSymbols`（coreaction.cc:2930-2976）时这些 high 根本不存在。
3. 即便个别 extraout 存活：`HighVariable::hasName`（variable.cc:718-747）过滤 → `Funcdata::linkSymbol`
   （funcdata_varnode.cc:1156-1184）`addSymbol("",high->getType(),addr,usepoint)` 建符号 →
   命名循环（coreaction.cc:2988-2997）`buildDefaultName(sym,base,vn)` → `ScopeInternal::buildVariableName`
   的 `extraout_` 分支（database.cc:2492-2500）。**该名在 Ghidra 是合法可达输出**，golden 无它只因步骤 1-2
   已把来源消灭。`Merge::mergeTestRequired`（merge.cc:127-128/133-134）对 `isExtraOut` 高**禁止合并**
   （variable.hh:205 `isExtraOut = indirect_creation && !addrtied`）——extraout 设计上就是孤立高，
   merge 域从不吸收它。
4. 声明发射来自符号表：`PrintC::emitLocalVarDecls`（printc.cc:2260-2279）→
   `emitScopeVarDecls(scopeLocal, no_category)`——**打的是 Scope 符号，不是 High 列表**。

### 3.2 Rugra 泄漏链（逐行）

- `src/flow.rs:120-123`：`fn is_no_return(&self) -> bool { /* TODO(CALLSPEC-0001) */ false }` ——
  noreturn 链路整体失效；`check_for_flow_modification`（flow.rs:1229-1257）逐行忠实（含 halt 插入与
  warning），但永远走不到 `is_no_return` 分支。
- 投机实参存活：fresh 的 14 实参调用、`(undefined8)(uVar1200 >> 0x40)`（Register 0x1200+ 的 16 字节
  varnode 高半字读取）即 call-spec 投机输入域（fspec CALLSPEC-0001 家族）残留。
- 符号化：`src/coreaction.rs:4869-4902`（coreaction.cc:2988-2998 的命名循环移植）调
  `scope.build_default_name(idx,&mut base,Some(&vn),fd)`（varmap.rs:3459-3529，database.cc:1756-1786 移植，
  **忠实**）→ `build_variable_name_internal` 的 extraout 分支（varmap.rs:2780-2787）与 irregular-input 分支
  （:2763-2770，`in_register_`/`in_stack_` 名）→ 符号进入 Scope。
- 声明发射：`src/printc.rs:9648-9731 emit_scope_var_decls`（printc.cc:2523-2572 移植，**忠实**）整表打出
  ——`extraout_var;` 无类型是因为该符号 dtype 解析为空（上游 high 类型未定）。
- merge 侧核对（无缺陷）：`src/merge.rs:1387-1445 merge_test_required` 的 extraout 禁合、
  `merge.rs:933-974 merge_addr_tied_inner`（overlapLoc 簇 + unify_address + merge_range_must + groupWith，
  对应 merge.cc:609-648）、`variable.rs:1309-1312 is_extra_out` 均与 oracle 一致。
  **症状 2 不需要动 merge.rs。**

### 3.3 四类决定性语义核对表（症状 2）

Ghidra 签名逐字摘录：

```cpp
// flow.cc:636
bool FlowInfo::checkForFlowModification(FuncCallSpecs &fspecs)
{ if (fspecs.isInline()) injectlist.push_back(fspecs.getOp());
  if (fspecs.isNoReturn()) {
    PcodeOp *op = fspecs.getOp();
    PcodeOp *haltop = artificialHalt(op->getAddr(),PcodeOp::noreturn);
    data.opDeadInsertAfter(haltop,op);
    if (!fspecs.isInline()) data.warning("Subroutine does not return",op->getAddr());
    return true; }
  return false; }

// coreaction.cc:2930
void ActionNameVars::linkSymbols(Funcdata &data,vector<Varnode *> &namerec)
{ ... Varnode *vn = curvn->getHigh()->getNameRepresentative();
  if (vn != curvn) continue;
  HighVariable *high = vn->getHigh();
  if (!high->hasName()) continue;
  Symbol *sym = data.linkSymbol(vn);
  if (sym != (Symbol *)0) {
    if (sym->isNameUndefined() && high->getSymbolOffset() < 0) namerec.push_back(vn); ... } }

// merge.cc:102
bool Merge::mergeTestRequired(HighVariable *high_out,HighVariable *high_in)
{ ... else if (high_in->isExtraOut()) return false;
  if (high_out->isInput()) { ... } else if (high_out->isExtraOut()) return false; ... }
```

| 语义类 | Ghidra | Rugra 现状 | 判定 |
|---|---|---|---|
| 引用/输出参数 | `checkForFlowModification` 经 `FuncCallSpecs&` 改 call-site 状态并**插入 halt op**（mutating） | flow.rs:1229 有插入逻辑，但 `is_no_return` 恒 false → 分支死 | **MISMATCH（stub 根因）** |
| 循环边界/遍历顺序 | `linkSymbols` 按空间序遍历 loc-tree，`getNameRepresentative` 每 high 一次 | coreaction 命名循环按 namerec 顺序（对齐 cc:2989 的 for i<size） | 一致 |
| 计数器/累加器 | `int4 base = 1` 单计数器贯穿 namerec 循环 + `assignDefaultNames(base)`（coreaction.cc:2988/2998） | coreaction.rs:4873-4898 同一 `base` 贯穿 + `assign_default_names(&mut base)` | 一致 |
| 排序/比较键 | `hasName()`/`isExtraOut()`（flag 位组合 `indirect_creation && !addrtied`） | variable.rs:1309-1312 位组合一致 | 一致（泄漏源头不在键上） |

## 4. 症状 3：负偏移名符号回绕 — 完整证据链

### 4.1 机制

- heritage 写 stack 空间 varnode 用**符号扩展负偏移**（heritage.rs:1026 BFS offset 从 0 起步累积 i64 和，
  :1110 `stack_off as u64`）——与 Ghidra 栈空间编码一致（golden 的 `in_stack_fffffffffffffc78` 证明
  Ghidra 同为符号扩展）。
- 但 varmap 的 local 窗口/命名门全部错半区：
  - `varmap.rs:2687`：`self.local_range_in_range(offset)` 对负偏移 false → `build_variable_name`
    （:2674-2718，varmap.cc:548-581 移植本体忠实）的 `<base>Stack[X|Y]_<hex>` 分支永不命中；
  - 落入 `build_variable_name_internal`：input 高 → `in_stack_ffffffffffffedb8`（:2763-2770，
    database.cc:2470-2478 的 `in_<space>_<8hex>`，**形式在 Ghidra 合法但只该给参数侧异常 input**）；
  - 无符号覆盖的 varnode 由打印层兜底：Register→`uVar{:x}`（printc.rs:4205）、Unique→`uVar_{:x}`
    （:4220/8152）、Stack→`local_{:x}`/`param_stack_{:x}`（:4209-4212）——后两者为 **Rugra 自创名**，
    Ghidra 打印层不存在（Ghidra 经 `pushUnnamedLocation`/符号名解析）。
- Ghidra 对照：`ScopeLocal::buildVariableName`（varmap.cc:553-578）`getLocalRange().inRange(addr,1)` 命中后
  `start = sign_extend(byteToAddress(offset,…), addrSize*8-1)`，`stackGrowsNegative` 取负，`start<=0` 打
  `X` 再取反（caller 分配侧）、param 侧超界打 `Y`，最终 `StackX_1248` 形式。
- `fake_input_symbols`（varmap.rs:3649-3738）本身有 paramrange 门（:3685 `param_range_in_range`），
  `in_stack_…edb8` 不是它产的（−0x1248 不在 [0,511]），而是 ActionNameVars/linkSymbol 域为 read-before-write
  的栈 input 建符号后命名产生——窗口修复后这些位置会被 `buf`/locals 符号吸收，名字消失。

### 4.2 四类决定性语义核对表（症状 3）

Ghidra 签名逐字摘录：

```cpp
// varmap.cc:548
string ScopeLocal::buildVariableName(const Address &addr, const Address &pc,
                                     Datatype *ct, int4 &index,uint4 flags) const
{ if (((flags & (Varnode::addrtied|Varnode::persist))==Varnode::addrtied) &&
      addr.getSpace() == space) {
    if (fd->getFuncProto().getLocalRange().inRange(addr,1)) {
      intb start = (intb) AddrSpace::byteToAddress(addr.getOffset(),space->getWordSize());
      start = sign_extend(start,addr.getAddrSize()*8-1);
      if (stackGrowsNegative) start = -start;
      ...
      if (start <= 0) { s << 'X'; start = -start; }
      else { if ((minParamOffset < maxParamOffset) && (...)) s << 'Y'; }
      s << '_' << hex << start; return makeNameUnique(s.str()); } }
  return ScopeInternal::buildVariableName(addr,pc,ct,index,flags); }
```

| 语义类 | Ghidra | Rugra 现状 | 判定 |
|---|---|---|---|
| 引用/输出参数 | `int4 &index` 引用计数器跨层共享（input 分支不增，local 分支 `index++`） | `index: &mut i32` 同语义（varmap.rs:2680/2794-2795） | 一致 |
| 循环边界/遍历顺序 | 无循环；`makeNameUnique` 查 nametree 下界 | 同（varmap.rs:2827-2888） | 一致 |
| 计数器/累加器 | `minParamOffset/maxParamOffset` 由 `markNotMapped(parameter=true)` 单调扩张（varmap.cc:520-524） | varmap.rs mark_not_mapped 同式（:1908） | 一致 |
| 排序/比较键 | inRange 判定地址空间内 **无符号 offset ∈ localRange**（窗口=负偏移半区）；X/Y 以 sign_extend+取负后的 `start` 符号定 | inRange 形式一致但窗口错半区 → 分支永不命中；X/Y 逻辑（:2701-2712）本体一致 | **MISMATCH（根因，同症状 1 窗口）** |

## 5. 修复方案：切片划分（预计 write-set 与依赖）

> varmap.rs 属机制 B/C 白名单（varmap 核心算法层）：集成前需独立 Cross-Review + curl 差分门禁。
> varmap.rs 与 merge.rs 当前空闲（B6 §3 占用列表不含）；fspec.rs 空闲；flow.rs 有 FLOW-* 候选 TODO 需串行。

### S1（P0）`VARMAP-LOCALWINDOW-0001` — local 窗口接线（症状 1+3 单点根因）

- 文件：`src/varmap.rs` + `docs/api/varmap.md`（+ TODO_BOARD 行）。
- 内容：
  1. 新增 `func_proto_local_range(fd)`（镜像 varmap.rs:935-948 `func_proto_param_range`：arch.proto_models
     → defaultfp → `ProtoModelFull::new(Some(Stack),8).localrange` 兜底）。
  2. `restructure_varnode`（varmap.rs:2404-2412）用其结果替换硬编码 `(0, 0x100000)`；窗口写入
     `self.local_range`（供 `build_variable_name`/`local_range_in_range`/`longest_fit` 消费——
     `longest_fit` 的链式区间算术 :2571-2606 对负偏移大区间位级兼容，无需改）。
  3. `MapState` 构造减除 paramrange（varmap.cc:870-875）；`initialize`（:1480-1483）endpoint 改为
     `wrap(last+1)` 语义（负向栈 = 窗口顶端 0 的符号扩展）。
  4. 注意 `add_range` 的 `sst`（varmap.rs:1185 `start as i64`）在符号扩展偏移下天然正确
     （0xffffffffffffedb8 as i64 = -0x1248），排序键 `RangeHint::compare` 用 sstart 有符号——已兼容。
- 预期：负偏移 hint 全部进 MapState → `gather_spacebase` 的 per-access fixed hint、`gather_open` 的
  open hint 汇入 restructure → buf 的 open 区间延伸到下一定点 → `bool buf[4096]` 恢复；命名走
  `StackX_<n>` 形式；`in_stack_ffffffffffff…` 声明消失。
- 风险：全函数栈布局重排（所有函数的声明集变化）——必须全量差分；`gather_spacebase` 逐访问 fixed hint
  在窗口打开后数量激增，`reconcileDatatypes`（Ghidra varmap.cc:960-996；Rugra 缺失？核对项）与
  `merge/preferred` 的 tie-break 压力增大。若 hint 洪水导致行为异常，优先核对 `MapState::initialize`
  的 `stable_sort` + `reconcileDatatypes` 是否已移植（Rugra `initialize` :1477-1488 目前**没有**
  reconcileDatatypes 步骤——列为 S1 随附核对项，Ghidra varmap.cc:1079）。

### S2（P0）`CALLSPEC-NORETURN-WIRE-0001` — noreturn 接线（症状 2 根因）

- 文件：`src/fspec.rs`（FuncCallSpecs/FuncProto 增 noreturn 位 + 从符号/函数解析填充）+ `src/flow.rs`
  （删除 :120-123 stub，改读真值）+ paired docs。
- 依赖：fspec.rs 空闲；flow.rs 与 FLOW-TAILCALL/FLOW-JUMPTABLE 候选 TODO 串行排期。
- 预期：`__stack_chk_fail` 后插 halt + "Subroutine does not return" warning（golden 有）；call 投机
  实参 14→0；extraout/INDIRECT 副作用高死码消除 → `extraout_var*`/`in_register_*` 声明与
  `uVar1200>>0x40` 高半字读取消失。
- 说明：这不是 varmap/merge 改动，但它是 `MERGE-DATATYPE-SCALE-0001` 里 my_get_line 域"extraout 未吸收"
  的真正上游；merge.rs 本体经核对无需改动（§3.2）。

### S3（P1）`VARMAP-GATHEROPEN-GUARD-0001` — gatherOpen 补全（症状 1 的次级缺口）

- 文件：`src/varmap.rs`。依赖 S1 落地（窗口修好前 open hint 进不来）。
- 内容：`addGuard`（varmap.cc:1003-1039，LoadGuard/StoreGuard → open hint，minItems 来自
  `isRangeLocked() ? (max-min+1)/step-1 : 3`）；`gatherSymbols`（varmap.cc:1269/1044-1059，
  typelocked 符号回灌）；`restructure_varnode` 补 `annotateRawStackPtr`（:1284-1285，alias[0]==0 时）
  与 `checkUnaliasedReturn`（:1282）；`fake_input_symbols` 前 `clearUnlockedCategory(function_parameter)`
  + `clearCategory(fake_input)`（varmap.cc:1275-1276；现 survivor 逻辑只覆盖 clearUnlockedCategory(-1)）。
- 关联：strlen 惯用法两个空 do-while 的恢复依赖本切片 + 类型传播。

### S4（P1，print 域，独立租约）`PRINTC-UNNAMED-FALLBACK-0001`

- 文件：`src/printc.rs`。S1/S2 落地后评估残余：`uVar_{:x}`（:4220/8152）、`uVar{:x}`（:4205）、
  `local_{:x}`/`param_stack_{:x}`（:4209-4212）自创名 → 对齐 Ghidra 符号名解析/`pushUnnamedLocation`
  语义；属 PRINTC-SYMBOL-DECL-0001 / PRINTC-UNLINKED-REF-0001 族（coreaction.rs:4904-4935 的
  symbol→high 名字回写桥的退役条件）。

### 顺序与门禁

S1 → (S3)；S2 独立并行（fspec/flow 租约）；S4 最后。每片：`cargo check --lib` → `cargo test --lib` →
`cargo run --release --example curl_decompile` → `python tools/compare_ghidra.py result/curl_cur.c
tests/golden/ghidra_curl_1204.c --func my_get_line -v` + 全量 `--summary-only`（机制 B）；S1/S3 触发
机制 C（独立 Cross-Review，复核者须自读 varmap.cc 对应行）。

## 6. 双侧 fixture 设计（观察面）

F1 **RangeHint 序列**（S1/S3 验收核心）：
- Rugra：`restructure_varnode` 内 dump `MapState.maplist`（每行 `hex(start) size range_type flags highind
  typename`）与 restructure 后 `symbols`（`start size dtype name category`）。
- Ghidra oracle：OPACTION_DEBUG 已有 "Add Range:" 打点（varmap.cc:909-918）+ `ActionRestructureVarnode`
  的 `printEntries`（coreaction.cc:2288-2293）；在锁定 oracle 以相同 my_get_line 输入开启 debug 构建。
- 判据：buf 起点（≈sp−0x1010，即 hint start `ffffffffffffeff0` 邻域）出现 `open/1B` hint，
  endpoint 截断后 size=4096，entry `bool[4096]` 双侧一致；负偏移 hint 不被窗口丢弃（计数 >0）。

F2 **合并决策/extraout 观察面**（S2 验收）：
- 双侧在 mergerequired/mergetype 阶段 dump `isExtraOut()` 高清单（addr/size/def-op/opcode）+
  `mergeTestRequired` 拒绝样本；Ghidra 侧断言 noreturn halt 后该清单为空；Rugra 修复后同空。
- 附带断言：`__stack_chk_fail` 调用实参数 14→0、函数头出现 "Subroutine does not return"。

F3 **符号 entry/声明集观察面**（S1+S2 端到端）：
- ActionNameVars 后 dump ScopeLocal 符号表（name,start,size,category,flags）与
  `emitLocalVarDecls` 的声明文本行集，双侧函数级 diff；预期 fresh 的 50+ 声明收敛到 golden 的 11 项
  （含 `bool buf [4096]`、`in_FS_OFFSET`）。

F4 **差分门禁**：
```
python3 tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl_1204.c --func my_get_line -v
python3 tools/compare_ghidra.py result/curl_cur.c tests/golden/ghidra_curl_1204.c --summary-only
grep -c "extraout_var" result/curl_cur.c          # 5 → 0
grep -c "in_register_" result/curl_stdout.c        # 全文件 28 → ≤ golden(0)
grep -c "Subroutine does not return"               # my_get_line 0 → 1
```
（注意 stderr 的 `[SYM]`/`[STEP]` 噪音勿混入 stdout；`result/` 回流约定照旧。）

## 7. 关联观察（不在本三症状内，同函数）

- canary 恒真自比较 `*uVar_c900 == *uVar_c900`：FS 段寄存器未入 `register_names` 表
  （coreaction.rs:858-875 仅 GPR+RIP），golden 的 `in_FS_OFFSET+0x28` canary 模式无法成型；与 S1/S2
  正交，建议登记独立小 TODO（`VARMAP-REGNAMES-FS-0001`，表补 FS_OFFSET 即可，但需先读 Ghidra
  x86-64 .sla/编译器 spec 确认 register space offset）。
- fresh `uVar_100002eb/100000d8`（Unique 大偏移）与 S4 相关：Unique 未命名 temp 的打印兜底名，
  Ghidra 侧这类 temp 多为 implied（不打印）或经 high/symbol 命名。
- 板上 `MERGE-DATATYPE-SCALE-0001` 记录的 "varmap.rs:1675 溢出"（3.95s 后暴露）与 TODO_BOARD 475 行
  现状吻合本报告 S1 域，建议该 TODO 的 my_get_line 部分引用本报告并按 S1/S2 拆分认领。

## 8. 报告元数据

- oracle：Ghidra 12.0.4 `e40ed13014025f82488b1f8f7bca566894ac376b`（varmap.cc 1620 行 / varmap.hh 269 行 /
  merge.cc 1695 行 / database.cc / fspec.cc / coreaction.cc / flow.cc / variable.cc / printc.cc /
  funcdata_varnode.cc 全文或对应域逐行读取）。
- fresh 指纹：`fc9a33baaab1310929b78b508b27f6810fd5e2eca7da80bf17d2a584e91d60e7`（commit `f7b3c31`）。
- 关键 Rust 文件行号基于当前工作区 HEAD（只读核对：varmap.rs 4860 行 / merge.rs 4759 行 /
  flow.rs / heritage.rs / fspec.rs / coreaction.rs / printc.rs / variable.rs）。
- 工具：grep/sed 逐行对照，无 compare 运行（fresh 对照直接读 artifacts 文件）。
