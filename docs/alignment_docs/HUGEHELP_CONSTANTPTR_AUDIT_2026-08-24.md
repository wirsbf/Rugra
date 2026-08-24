# B3 审计报告：hugehelp 六别名常量 × ActionConstantPtr 未建 PTRSUB/符号引用

- 审计类型：只读（未改仓库文件、未跑 cargo）
- 仓库：`/home/wirs/DEV/Rugra` @ 主线 `1cda523d7aba2aa7bd393e2e1492bcad85b86eed`（交接文档口径）
- oracle：Ghidra 12.0.4 `e40ed13014025f82488b1f8f7bca566894ac376b`（`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/`）
- 输入：`examples/curl`（.text@0x25a0/.rodata@0x6000/…；Rugra 以 base-0 地址工作，Ghidra golden 以 0x100000 镜像基）
- 对应交接文档：`docs/alignment_docs/THREE_FUNCTION_HANDOVER_2026-08-24.md` §3.1 第 3 步、§5.6 串行约束

## 0. 结论（TL;DR）

Rugra 的 `ActionConstantPtr`（`src/coreaction.rs:615-666`）是**臆造实现**：它扫描存活 LOAD/STORE、给常量地址输入打 `READONLY` flag，恒返回 `NO_CHANGE`——与 Ghidra 的算法（常量空间迭代 → `selectInferSpace` → `isPointer` → `queryContainer` → `spacebaseConstant` 改写为 PTRSUB）**零对应**，属铁律 1.4 违反。Ghidra 侧忠实移植的 `Funcdata::spacebaseConstant`（`src/funcdata.rs:4828`）是**死代码**（全仓零调用）且 `sz`/`extra` 两处语义错。缺口分三层：① Action 逻辑完全缺失；② Program DB 条目缺失（`.rodata` 无 DAT 条目，driver 只给 `.data/.bss` 合成）；③ query 通道未接线（`database.rs` 的 `Scope::query_container` 存在但 Funcdata 用 `symbol_table: HashMap<u64,String>` 名称代理）。下游 `RulePtrsubCharConstant`/PrintC 也有已登记的后续缺口（`PRINTC-PTRCHAR-CONSTANT-0001`、`PRINTC-PTRCONST-DAT-SYMBOL-0001`）。另发现 `ALIGNMENT_ROADMAP.md` 把 `ActionConstantPtr` 记为「✅ L3 已实现」，**账本失实**。

## 1. Ghidra 侧：0x7180 从「CALL input 常量」到「PTRSUB &DAT/字符串」的完整判定链

### 1.1 判定链（双侧行号均为锁定 oracle）

```
ActionConstantPtr::apply                     coreaction.cc:1167-1217   （typerecovery 组，:5660 注册）
 ├─ guard: hasTypeRecoveryStarted；localcount>=4 早退（每函数最多 4 遍）    :1170-1174
 ├─ 迭代常量空间 varnode: data.beginLoc(cspc)..endLoc，vn=*begiter++       :1182-1187
 │   ├─ 跳过: offset==0 / isPtrCheck / hasNoDescend / isSpacebase         :1188-1191
 │   └─ op = vn->loneDescend()；非唯一消费者跳过                           :1194-1195
 ├─ rspc = selectInferSpace(vn,op,glb->inferPtrSpaces)                    :1196 / :1005-1032
 │   ├─ TYPE_PTR 显式空间属性直取；否则遍历 inferPtrSpaces（cacheAddrSpaceProperties
 │   │   已把 default data space 换到首位，architecture.cc:665-701）
 │   └─ 尺寸门: minSize==0 → vn.size==spc.addrSize；否则 vn.size>=minSize  :1016-1022
 │       多候选时 searchForSpaceAttribute 沿 INT_ADD/COPY/INDIRECT/MULTIEQUAL :957-995
 ├─ slot 门: INT_ADD 另一侧已是 spacebase 跳过；PTRSUB/PTRADD 跳过         :1200-1204
 ├─ entry = isPointer(rspc,vn,op,slot,rampoint,fullEncoding,data)          :1207 / :1070-1165
 │   ├─ 显式 TYPE_PTR → resolveConstant + needexacthit=false               :1077-1080
 │   ├─ 否则 op 门: CALL/CALLIND(slot!=0, 看 callspec 锁定参数类型是否 PTR/
 │   │   UNKNOWN，否则需 infer_pointers)；COPY(checkCopy)；PIECE/INT_EQUAL/
 │   │   INT_NOTEQUAL/INT_LESS/INT_LESSEQUAL(infer_pointers)；INT_ADD(输出
 │   │   PTR→needexacthit=false，另一输入已 PTR→拒绝)；STORE(slot==2)      :1086-1136
 │   ├─ 范围门: pointerLowerBound<=off<=pointerUpperBound（x86-64 ram:
 │   │   0x1000 .. highest-0x1000，space.cc:34-44 calcScaleMask）           :1138-1141
 │   ├─ 位形门: bit_transitions(off,size)>=3（address.cc:818）              :1143-1144
 │   └─ rampoint = glb->resolveConstant(spc,off,size,opaddr,fullEncoding)
 │       （translate.cc:628-641：无 resolver 时 addressToByte+wrapOffset）
 │       → queryContainer(rampoint,1,Address()) 于 local scope 的 parent    :1145,1151
 │       → entry 为 TYPE_ARRAY 且 base isCharPrint → needexacthit=false
 │         （字符串中部允许）；needexacthit 且 entry 起点≠rampoint → 拒绝    :1152-1163
 ├─ vn->setPtrCheck()（搜索完再置位）                                       :1208
 └─ 命中: data.spacebaseConstant(op,slot,entry,rampoint,fullEncoding,size) :1210
           INT_ADD slot==1 时 opSwapInput(op,0,1)；count+=1                :1211-1213
```

`Funcdata::spacebaseConstant`（funcdata.cc:360-462）把常量改写为
`PTRSUB(spacebase_vn=const(sz,0)+SPACEBASE flag, newconst=origval-extra)`，`extra = rampoint - entry 起点地址`（byteToAddress 归一）；按 COPY/尺寸关系最多再插 `INT_ADD`（extra≠0）/`INT_ZEXT`（sz<origsize）/`SUBPIECE`（origsize<sz）；输出置 `getTypePointerStripArray(entrytype)` 并按 symbol typelock。

符号名挂接（打印 `&DAT_...` 的来源）：
`ActionNameVars::linkSymbols`（coreaction.cc:2930）→ 常量空间里 `isSpacebase()` 的 varnode → `linkSpacebaseSymbol`（:2907-2920）→ `Funcdata::linkSymbolReference(offVn)`（funcdata_varnode.cc:1193，`queryContainer(addr,1,Address())`）→ `HighVariable::setSymbol`。打印时 `PrintC::opPtrsub` 的 `TYPE_SPACEBASE` 分支（printc.cc:1057-1097）：symbol 命中且 `symbolOffset==0` → `pushSymbol`（`&name`，:1071-1072/:1084-1086）；无 symbol → `pushUnnamedLocation`（:1078-1082）。

字符串折叠（决定「字符串字面量 vs `&DAT_`」）：
`RulePtrsubCharConstant::applyOp`（ruleaction.cc:7354-7403）对 `PTRSUB(spacebase,const)` 要求输出为 char* 指针（:7366-7369），`TypeSpacebase::getAddress` 解析地址（type.cc:3070 → `resolveConstant`），`scope->isReadOnly(symaddr,1,opaddr)`（:7372）后问 `stringManager->isString`（:7375）。`StringManagerUnicode::getStringData`（stringmanage.cc:427-475）逐 32B `loadFill` 找 NUL 终止 + `checkCharacters`（:324-339，UTF-8 逐 codepoint 校验，:347-410）；非法 UTF-8 → 空缓冲 → `isString`（:166-172）false。命中则按 `pushConstFurther`（:7323-7340，PTRADD 常量折叠）传播，全部成功才 `opDestroy`，否则 PTRSUB→COPY(typed const)（:7379-7401）。最终 `PrintC::pushConstant` → `pushPtrCharConstant`（printc.cc:1698-1719，再次 `resolveConstant`+`isReadOnly`+`printCharacterConstant`）输出带引号字符串。

### 1.2 对 curl 六个别名地址的预期行为（已用二进制实测验证）

`.rodata` 实测（`examples/curl`，base-0 偏移）：

| 常量 | 到 NUL 长度 | UTF-8 有效 | golden 输出 | 机制 |
|---|---:|---|---|---|
| 0x7180 | 10272 | **否**（rel 1452 处 0xad） | `puts(&DAT_00107180);` | isString=false → PTRSUB 保留 → linkSymbolReference 挂 DAT 符号 |
| 0x99a8 | 10284 | **否**（rel 388 处 0xad） | `puts(&DAT_001099a8);` | 同上 |
| 0xc1d8 | 10340 | **否**（rel 397 处 0xad） | `puts(&DAT_0010c1d8);` | 同上 |
| 0xea40 | 10284 | 是（`\n   or specify them…`） | `puts("…");` | isString=true → Rule 折叠 → 字符串字面量 |
| 0x11270 | 10329 | 是（`\n        curl --dump-header…`） | `puts("…");` | 同上 |
| 0x13ad0 | 3354 | 是（` check the other way…`） | `puts("…");` | 同上 |

六者在 `isPointer` 处的走查：CALL input slot=1；`puts` 的 callspec 参数类型 `char*`（TYPE_PTR）→ 不被 :1094-1099 拒绝；`0x7180 >= 0x1000` 下界且远小于上界；`bit_transitions(0x7180)`：bits={7,8,12,13,14}，序列 0…0 1 1 0 0 0 1 1 1 1 → 3 次翻转，`<3` 为假 → 通过；`resolveConstant(ram,0x7180)` → Address(ram,0x7180)；`queryContainer` 需要**起点恰为 0x7180 的 SymbolEntry**（needexacthit=true，除非 entry 是 char 数组——oracle 侧这三个是未定义数据 DAT，不是 string data，故必须精确命中）。

`DAT_` 符号来源：Ghidra 平台侧（database_ghidra.cc 是 glue；名字由 Ghidra 分析器在引用数据上建 default DAT 标签），经 `<symboltable>` 装入 decompiler 的 global scope。**decompiler 自身在无符号时不会造 DAT**（`stackContainer` 的 `inScope` 分支只返回 scope、entry 仍为 NULL，database.cc:957-958）。

## 2. Rugra 与 Ghidra 逐点差异

### 2.1 Action 逻辑层（最核心缺口 — 完全臆造）

| # | Ghidra | Rugra | 差异定性 |
|---|---|---|---|
| A1 | `apply` 迭代常量空间 locset（coreaction.cc:1182-1187），`vn=*begiter++` 防迭代器失效 | `src/coreaction.rs:635` 迭代 `fd.obank.alivelist` 找 LOAD/STORE | **遍历对象完全不同**：Ghidra 看「常量 varnode 的消费者」，Rugra 看「LOAD/STORE 的地址输入」 |
| A2 | `localcount`（coreaction.hh:189）成员，`>=4` 早退（:1172-1174） | `coreaction.rs:618` unit struct，无状态 | 缺 per-function 4 遍上限 |
| A3 | `selectInferSpace`/`searchForSpaceAttribute`（:957-1032）多空间消歧 + `inferPtrSpaces` 顺序 | 无对应函数（全仓 grep 无 `select_infer_space`） | 缺失 |
| A4 | `checkCopy`（:1041-1054）RETURN/输出锁定的 COPY 特例 | 无 | 缺失 |
| A5 | `isPointer`（:1070-1165）CALL/COPY/PIECE/比较/INT_ADD/STORE 门 + pointer bounds + `bit_transitions>=3` + `resolveConstant` + `queryContainer` | 无 | 缺失。注意 `bit_transitions` 已有忠实移植 `src/rangeutil.rs:1234`，pointer bounds 已在 `src/space.rs:1634-1647`（calc_scale_mask，0x1000/high-0x1000 正确）——地基在，无消费者 |
| A6 | 命中后 `spacebaseConstant`（funcdata.cc:360）改写为 PTRSUB(spacebase,newconst)，`INT_ADD slot==1` 时 `opSwapInput`（coreaction.cc:1210-1212） | `coreaction.rs:643-647` 只对 LOAD/STORE 常量输入 `set_flags(READONLY)`；从不建 PTRSUB | **行为注入而非缺失**：Ghidra 的 readonly flag 来自 loader/`queryProperties`（database.cc:1263-1281），没有任何 Action 扫 LOAD/STORE 打 flag——这是自创语义 |
| A7 | `count += 1` 且 ActionGroup 以 count 判变化（:1213） | `coreaction.rs:655-659`：`changed>0` 时仍返回 `NO_CHANGE`（两分支都 `NO_CHANGE`） | 恒报无变化：即使做对了也无法触发 restart 语义 |
| A8 | `setPtrCheck` 搜索后置位防重查（:1208；flag 定义 varnode.hh） | `PTR_CHECK` 常量存在（`src/varnode.rs:108`）但无 `set/is_ptr_check` 方法，apply 无置位 | 缺失（spacebase_constant 内有直接 `addlflags |=` 用法） |

### 2.2 Program DB 条目层

| # | Ghidra（oracle） | Rugra | 差异定性 |
|---|---|---|---|
| B1 | global scope 有 `DAT_00107180` 等 SymbolEntry（平台分析器建，含 addr/size/type/flags） | `examples/curl_decompile.rs:2576-2597` 只对 `.data`/`.bss` 每字节合成 `DAT_{:05x}`；**`.rodata` 零 DAT 条目** | 六个别名地址全部无条目：即使 Action 逻辑正确，`queryContainer` 也必 miss |
| B2 | 符号名 `DAT_` + 8 位十六进制全地址（golden：`DAT_00107180`，镜像基 0x100000） | `format!("DAT_{:05x}", addr)`，base-0 地址（`DAT_07180` 形态） | 命名宽度/基址口径与 golden 不一致，字节对齐需统一（加载基或格式化任选其一，需与 fixture 指纹绑定） |
| B3 | `.rodata` readonly 性经 loader→`symboltab` property ranges（`queryProperties` 消费，database.cc:1276/1279） | `Database::set_property_range`（`src/database.rs:3758`）存在但无人注册 `.rodata` 范围；Rule 侧用 `string_table` 代理（见 C 层） | readonly 通道空转 |
| B4 | `StringManagerUnicode` 逐 32B loadImage 读 + UTF-8 校验（stringmanage.cc:427-475） | driver `curl_decompile.rs:2533-2574` 从 `.rodata` 预扫：**首字节可打印**即收，`from_utf8_lossy` 后过滤非 ASCII 字符入库 | **语义反转风险**：0x7180（首字节空格、内含 0xad）会被收进 `string_table`；若以 string_table 当 isString 代理，0x7180/0x99a8/0xc1d8 会被错误折叠成字符串，与 golden 的 `&DAT_*` 相反。缺「非法 UTF-8 → 拒绝」语义 |

### 2.3 query 通道层

| # | Ghidra | Rugra | 差异定性 |
|---|---|---|---|
| C1 | `Scope::queryContainer`（database.cc:1246-1253）= `mapScope` + `stackContainer`（:943-962，沿 parent 上溯、findContainer 最小包含、inScope 只返回 scope） | `Scope::query_container`（`src/database.rs:1997-2010`）+ `stack_container` + `map_scope`（:3780）均已忠实移植，**但没有任何 production 调用方接到 Funcdata**（仅 :2731/:2816 两处 scope 内部用法与测试） | 通道存在、未接线：Funcdata 无 `getScopeLocal()->getParent()` 等价物 |
| C2 | `Funcdata::linkSymbolReference`（funcdata_varnode.cc:1193）走 `queryContainer`，把 SymbolEntry 挂上 HighVariable | `src/funcdata.rs:1221-1264` 用 `fd.symbol_table: HashMap<u64,String>`（`src/funcdata.rs:459`）按偏移取名字，无 entry 起点尺寸、无 type、无 flags；stack 符号另走 `fd.scope.symbols` 线性扫描（:1253-1262） | 名称代理替代容器查询：`needexacthit` 的「entry 起点==rampoint」、char-array 中部例外（coreaction.cc:1154-1159）都无法表达 |
| C3 | `queryProperties`/`queryByName`（database.cc:1263/1198） | `src/database.rs:2022`/`:1929` 已移植，未接生产 | 同 C1 |
| C4 | `resolveConstant`（translate.cc:628-641） | `src/translate.rs:1679-1701` 已移植（wordsize/wrap 语义一致），无 Action 调用方 | 地基在、无消费者 |
| C5 | `inferPtrSpaces` 由 `<global>` 收集（architecture.cc:826-844 push :832）+ `cacheAddrSpaceProperties` 终整理（:665-701：按 index 排序去重、滤 delay==0/SPACEBASE/other/overlay、default data space 换首位） | `src/arch.rs:501` 字段 + `:1017` push（`add_to_global_scope`）；**`cache_addr_space_properties` 无移植**（grep 无果），首位换序/过滤缺失 | selectInferSpace 的遍历顺序前提不成立 |

### 2.4 下游（打印/折叠）——已有租约，此处只列与本链相关项

| # | Ghidra | Rugra | 差异定性 |
|---|---|---|---|
| D1 | `ActionNameVars::linkSpacebaseSymbol`（coreaction.cc:2907-2920）→ linkSymbolReference 挂符号 | `src/coreaction.rs:4561-4601` 已移植并调用 `fd.link_symbol_reference`（:4591），但拿到名字后 `namerec` 分支为显式 no-op（:4593-4599），名字未落到 HighVariable/print 通道 | 半接线 |
| D2 | `RulePtrsubCharConstant`（ruleaction.cc:7354-7403）：isReadOnly 经 scope，`pushConstFurther` 全成功才 `opDestroy` | `src/ruleaction.rs:11262-11325`：`isReadOnly` 用 `string_table.contains_key` 代理（:11299，见 B4 反转风险）；`push_const_further`（:11228）是死代码，`removeCopy/opDestroy` 分支整段缺失，恒走 PTRSUB→COPY | 保守改写 + 代理判定 |
| D3 | `PrintC::opPtrsub` TYPE_SPACEBASE 分支（printc.cc:1057-1097）打印 `&name`/`pushUnnamedLocation` | `src/printc.rs:1870-1872` 自述缺该分支，落入通用 `in0->field_0x…` 渲染 | 缺失 |
| D4 | `PrintC::pushPtrCharConstant`（printc.cc:1698-1719） | `src/printc.rs:9090-9093` 打印字面 `"<str>"` 桩；且注释引用 `printc.cc:900`，实际函数在 :1698 —— **cited-line-drift 红旗（机制 D）** | 桩 + 引用行漂移 |

### 2.5 死代码与账本失实

- `Funcdata::spacebase_constant`（`src/funcdata.rs:4828-4955`）：全仓无调用。另有两处语义错：① `sz` 用 `rampoint.as_u64().leading_zeros()` 推导（:4838-4842，恒得 8 再 `origsize.max(sz).min(8)`）——Ghidra 是 `sz = rampoint.getAddrSize()`（**空间的地址大小**，funcdata.cc:363）；② `extra` 硬编码 0（:4843-4847）——Ghidra 是 `rampoint - entry->getAddr()`，且签名缺 `SymbolEntry *entry` 参数，typelock/`getTypePointerStripArray` 全缺（自述 caveat）。
- `ALIGNMENT_ROADMAP.md`（coreaction 段）将 `ActionConstantPtr` 列入「已实现（✅ L3）」——与 2.1 的臆造实现矛盾，**账本失实，须更正为 L1 并登记**。

## 3. 四类决定性语义核对表（Ghidra 签名逐字摘录）

### 3.1 `ActionConstantPtr::apply`

```
Ghidra: coreaction.cc:1167  int4 ActionConstantPtr::apply(Funcdata &data)
```
- 引用/输出参数：`Funcdata &data` 被突变（`spacebaseConstant` 改写 op/插 op/换输入）；返回 `int4` 恒 0（变化经基类 `count` 上报）。
- 循环边界/遍历顺序：`data.beginLoc(cspc)`→`endLoc(cspc)` 常量空间 VarnodeLocSet 有序迭代；`vn = *begiter++` 先解引用后自增（容忍迭代中新插入 varnode）；`!vn->isConstant()` 即 break。
- 计数器/累加器：`localcount` 是 **Action 实例成员**（跨 apply 调用累计、per-函数），`>=4` 早退后 `+=1`；`count`（基类）每命中 `+=1`；跳过条件（offset==0/已 PtrCheck/无后代/是 spacebase）不计数。
- 排序/比较键：locset 按 (space,offset,…) 全序；`selectInferSpace` 遍历 `inferPtrSpaces`（`cacheAddrSpaceProperties` 保证 default data space 在首位），尺寸匹配取第一个，多命中才用 `searchForSpaceAttribute` 消歧后 break。

### 3.2 `ActionConstantPtr::isPointer`

```
Ghidra: coreaction.cc:1070-1071  SymbolEntry *ActionConstantPtr::isPointer(AddrSpace *spc,Varnode *vn,PcodeOp *op,int4 slot,
						  Address &rampoint,uintb &fullEncoding,Funcdata &data)
```
- 引用/输出参数：`rampoint`（Address&）与 `fullEncoding`（uintb&）为 out 参数；返回查询所得 `SymbolEntry*`（scope 拥有，不转移）；`data` 只读。
- 循环边界/遍历顺序：无循环；`op->code()` switch；查询用**空 usepoint** `Address()`（coreaction.cc:1151，地址绑定假设）。
- 计数器/累加器：`needexacthit` 局部 bool——初值 true；显式 TYPE_PTR 时 false（:1079）；INT_ADD 输出为 PTR 时 false（:1125）；entry 类型是 char 数组时 false（:1154-1159）。
- 排序/比较键：`queryContainer` 取**最小包含** Symbol；精确命中判据 `entry->getAddr() != rampoint`（字节地址相等）；范围门 `getPointerLowerBound() > off` 拒 / `getPointerUpperBound() < off` 拒；位形门 `bit_transitions(off,size) < 3` 拒。

### 3.3 `Scope::queryContainer`

```
Ghidra: database.cc:1246-1247  SymbolEntry *Scope::queryContainer(const Address &addr,int4 size,
					   const Address &usepoint) const
```
- 引用/输出参数：const 成员；返回 `SymbolEntry*`（可空）。
- 循环边界/遍历顺序：`mapScope(this,addr,usepoint)` 定位 base scope → `stackContainer(basescope, NULL, addr, size, usepoint, &res)` 沿 parent 链上溯；每层先 `findContainer` 后 `inScope`；首个命中即 return（子 scope 优先于父）。
- 计数器/累加器：无。
- 排序/比较键：`findContainer` 于 ScopeInternal rangemap 取包含 `[addr,addr+size)` 的**最小** entry；`usepoint` 参与 MapClass 排序键（有效 usepoint 优先）；`inScope` 命中只返回 scope 本身、entry 保持 NULL（新变量发现，不算符号命中）。

### 3.4 `Funcdata::spacebaseConstant`

```
Ghidra: funcdata.cc:360  void Funcdata::spacebaseConstant(PcodeOp *op,int4 slot,SymbolEntry *entry,const Address &rampoint,uintb origval,int4 origsize)
```
- 引用/输出参数：`op`（及其输入）被改写；`entry` 只读（取 `getAddr()`/`getSymbol()->getType()`/typelock）；`sz = rampoint.getAddrSize()`＝空间地址大小（x86-64=8），**不是**常量大小。
- 循环边界/遍历顺序：无循环；新 op 均 `opInsertBefore(op)` 保持顺序；COPY 复用自身为末级 op（`insertInput(1)` 补第二输入）。
- 计数器/累加器：`extra = rampoint.getOffset() - entry->getAddr().getOffset()` 再 `byteToAddress`（wordsize 归一）；`newconstoff = origval - extra`（全在地址单位）。
- 排序/比较键：无排序；分支键为 `op->code()==COPY` ×（`sz<origsize` / `origsize<sz` / `extra!=0`）四象限选 ZEXT/SUBPIECE/INT_ADD/PTRSUB 复用；`spaceid->isTruncated()` 时 `addOp->setPtrFlow()`。

## 4. 最小修复租约建议（B3-COREACTION-CONSTANTPTR-0001 建议）

依赖顺序（遵循交接文档 §5.6）：**必须在 D2（CALL-input local dispatch，占 `coreaction.rs`）完成释放后串行启动**；与 exact-piece callers WIP（也占 `coreaction.rs` 极窄调用点）互斥。字符串/打印下游不并入本租约（已有 `PRINTC-PTRCHAR-CONSTANT-0001`/`PRINTC-PTRCONST-DAT-SYMBOL-0001`）。

Write-set（原子片建议拆 3 个串行 commit）：

1. **通道+条目（先行，不占 coreaction.rs）**：
   - `src/funcdata.rs` + `src/database.rs`：Funcdata 挂 global scope 查询通道（`getScopeLocal()->getParent()` 等价：注入 scope 栈或 Database 句柄）；`link_symbol_reference` 改走 `Scope::query_container`（保留旧表作过渡断言）。
   - `examples/curl_decompile.rs`（或独立 loader 模块）：`.rodata` 引用数据建 DAT SymbolEntry（含 addr/size），命名宽度与 golden 对齐（`DAT_{:08x}`，镜像基口径写入 fixture 指纹）；注册 `.rodata` readonly property range（`Database::set_property_range`）。
2. **Action 主体（占 coreaction.rs，D2 后串行）**：
   - `src/coreaction.rs`：`ActionConstantPtr` 重写——struct 加 `localcount`；`apply`/`select_infer_space`/`search_for_space_attribute`/`check_copy`/`is_pointer` 按 §1.1 逐行移植；命中调 `spacebase_constant`；`count` 语义恢复。
   - `src/funcdata.rs`：修 `spacebase_constant` 的 `sz`（取 rampoint 空间 addrsize）与 `extra`（按 entry 起点计算，需扩签名或传 entry 摘要），激活为被调用代码。
   - `src/arch.rs`：补 `cache_addr_space_properties`（排序去重过滤 + default data space 首位换序）。
   - 同 commit 更新 `docs/api/coreaction.md`/`funcdata.md`/`arch.md` 与 `ALIGNMENT_ROADMAP.md`（**更正 ActionConstantPtr 的失实 L3 记载**）。
3. **验收**：六常量函数 fixture（oracle 12.0.4）：0x7180/0x99a8/0xc1d8 产出 `PTRSUB(ram spacebase, const)` + `&DAT_*`；0xea40/0x11270/0x13ad0 在 Rule 阶段折叠为 typed constant；`hugehelp` 六行字节对齐 golden；差分门禁 `## Differential` 块按缺口逐条登记。

风险预警：修复 2 之前**必须先修 B4 的字符串判定语义**（或确保 Rule 层走真实 StringManagerUnicode 的 UTF-8 拒绝），否则 `string_table` 代理会把 0x7180 类地址误折叠成字符串，比现状多一层 MISMATCH；coreaction.rs 属机制 B 白名单（Actions 影响输出），commit 需 `## Alignment Evidence` + `## Differential`；本模块非机制 C 白名单，但建议对 `isPointer` 的 CALL 门与 `spacebaseConstant` 的四象限分支做独立复核。

## 5. 关键文件/行号索引

Ghidra：`coreaction.cc:957/1005/1041/1070/1167/2907/2930/5660`、`coreaction.hh:188-196`、`database.cc:909/943/1198/1246/1263`、`funcdata.cc:360-462`、`funcdata_varnode.cc:1193`、`translate.cc:628`、`architecture.cc:665/826`、`space.cc:34`、`address.cc:818`、`ruleaction.cc:7323/7354`、`printc.cc:1057/1698`、`stringmanage.cc:166/324/427`。

Rugra：`src/coreaction.rs:615-666`（臆造 apply）、`src/coreaction.rs:4561-4601`、`src/funcdata.rs:459/1221-1264/4799/4828-4955`、`src/database.rs:1929/1997/2022/3758/3780`、`src/translate.rs:1679`、`src/arch.rs:501/1017`、`src/space.rs:1634`、`src/rangeutil.rs:1234`、`src/ruleaction.rs:11202-11331`、`src/printc.rs:9090-9093/1797-1893`、`src/action.rs:1213`、`examples/curl_decompile.rs:2533-2574/2576-2597`、`ALIGNMENT_ROADMAP.md`（coreaction L3 失实段）。
