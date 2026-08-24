# R6 独立复核报告 — TYPEFACTORY-DOWNCHAIN-VIRTUAL-0001

- 复核对象：master 集成 `3fa2802`（实现）+ `18192f9`（双侧 fixture gate）；候选分支原始提交 `f9307c7`（实现）+ `60c39f4`（fixture）
- 复核 Agent：R6（机制 C：独立打开 Ghidra 原文逐行核对，不采信实现者声明）
- 复核日期：2026-08-25
- 方式：只读主仓与 git；oracle 原文 = `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/`，HEAD 已核实 = `e40ed13014025f82488b1f8f7bca566894ac376b`（锁定 oracle）
- 结论：**APPROVE**（建议项见 §6，均非阻断）

---

## 0. Oracle 原文摘录（本人独立读取）

### type.cc:1084-1121 TypePointer::downChain（plain 版）

```cpp
1084  TypePointer *TypePointer::downChain(int8 &off,TypePointer *&par,int8 &parOff,bool allowArrayWrap,TypeFactory &typegrp)
1087    int4 ptrtoSize = ptrto->getAlignSize();
1088    if (off < 0 || off >= ptrtoSize) {
1089      if (ptrtoSize != 0 && !ptrto->isVariableLength()) {
1090        if (!allowArrayWrap)
1091          return (TypePointer *)0;
1092        intb signOff = sign_extend(off,size*8-1);
1093        signOff = signOff % ptrtoSize;
1094        if (signOff < 0)
1095          signOff = signOff + ptrtoSize;
1096        off = signOff;
1097        if (off == 0)
1098          return this;
1102    if (ptrto->isEnumType()) { ... typegrp.getBase(1, TYPE_UINT); off = 0;
1106      return typegrp.getTypePointer(size,tmp,wordsize); }
1108    type_metatype meta = ptrto->getMetatype();
1109    bool isArray = (meta == TYPE_ARRAY);
1110    if (isArray || meta == TYPE_STRUCT) {
1111      par = this;
1112      parOff = off;
1115    Datatype *pt = ptrto->getSubType(off,&off);
1116    if (pt == (Datatype *)0) return (TypePointer *)0;
1118    if (!isArray) return typegrp.getTypePointerStripArray(size, pt, wordsize);
1120    return typegrp.getTypePointer(size,pt,wordsize);
```

### type.cc:2656-2671 TypePointerRel::downChain（rel 版）

```cpp
2656  TypePointer *TypePointerRel::downChain(int8 &off,TypePointer *&par,int8 &parOff,bool allowArrayWrap, TypeFactory &typegrp)
2659    type_metatype ptrtoMeta = ptrto->getMetatype();
2660    if (off >= 0 && off < ptrto->getSize() && (ptrtoMeta == TYPE_STRUCT || ptrtoMeta == TYPE_ARRAY)) {
2661      return TypePointer::downChain(off,par,parOff,allowArrayWrap,typegrp);   // 静态限定调用（非虚）
2663    int8 relOff = (off + offset) & calc_mask(size);
2664    if (relOff < 0 || relOff >= parent->getSize())
2665      return (TypePointer *)0;
2667    TypePointer *origPointer = typegrp.getTypePointer(size, parent, wordsize);
2668    off = relOff;
2669    if (relOff == 0 && offset != 0)
2670      return origPointer;                       // 不写 par/parOff
2671    return origPointer->downChain(off,par,parOff,allowArrayWrap,typegrp);  // 虚调用，结果直传可为 NULL
```

### 虚调用点

- type.hh:429 `virtual TypePointer *downChain(...)`（TypePointer 基类声明）；type.hh:681 同签名 override（TypePointerRel）。
- 实际派发点（供后续 B1 接线参考，本 slice 未接线）：typeop.cc:1228（`TypeOpIntAdd::propagateAddIn2Out` do-while 循环体内）、typeop.cc:2357（`TypeOpPtrsub::getOutputToken` 单次调用）。
- typeop.cc:1225-1230 调用方循环：`do { pointer = pointer->downChain(typeOffset,parent,parentOff,allowWrap,*typegrp); if (pointer==0) break; } while(typeOffset != 0);` —— do-while 至少一次、NULL 即断、off 归零终止；`parent`/`parentOff` 是跨迭代共享覆写的累积槽。

### 关联函数（plain 版尾部分派的工厂方法）

type.cc:3849-3860 `getTypePointerStripArray`：`if (pt->hasStripped()) pt = pt->getStripped(); if (pt->getMetatype()==TYPE_ARRAY) pt = ((TypeArray*)pt)->getBase();`——**只剥一层 array**（注释原文 "Strip the first ARRAY type"），随后 findAdd intern + `res->calcTruncate(*this)`。type.cc:3867+ `getTypePointer`：同样 hasStripped 前置 + findAdd + calcTruncate。

---

## 1. 四类决定性语义核对表

### 1.1 plain 版：`down_chain_pointer`（typefactory.rs:1996-2063 ↔ type.cc:1084-1121）

| # | Ghidra 行 | 语义 | Rugra 行 | 判定 |
|---|---|---|---|---|
| 1 | 1087 | `ptrtoSize = ptrto->getAlignSize()` | :2009 `ptrto.get_align_size()`（与 get_size 区分的实现，datatype.rs:817） | MATCH |
| 2 | 1088-1089 | wrap 守卫 `off<0 \|\| off>=ptrtoSize`；wrappable `ptrtoSize!=0 && !isVariableLength()` | :2011-2012 同序同条件 | MATCH |
| 3 | 1090-1091 | `!allowArrayWrap → NULL`（在 off 改写之前返回） | :2013-2015 | MATCH |
| 4 | 1092 | `sign_extend(off, size*8-1)`，size=指针自身 size | :2017-2018 `sign_extend(*off, ptr.base.size*8 - 1)`（bits>=63 时 no-op=Ghidra 移 0 位等价） | MATCH |
| 5 | 1093-1095 | `signOff % ptrtoSize`；负则 +ptrtoSize（C++ 截断取余） | :2019-2022（Rust `%` 同为截断取余，符号语义一致） | MATCH |
| 6 | 1096-1098 | `off=signOff; if(off==0) return this` | :2023-2028 `*off=sign_off; if *off==0 { return Some(orig.clone()) }` —— **返回被下降指针本身的 Arc，不 re-intern**。本 slice 修正点，与 `return this` 精确对应；`par` 未触碰（Ghidra 同） | MATCH |
| 7 | 1102-1107 | enum 分支：getBase(1,TYPE_UINT) 先、`off=0`、getTypePointer(size,tmp,wordsize) | :2031-2039 同序（get_base_result → *off=0 → get_type_pointer） | MATCH |
| 8 | 1108-1113 | `par = this; parOff = off`（仅 isArray\|\|STRUCT） | :2040-2046 `*par = Some(orig.clone()); *par_off = *off` —— **par=this 保留 this 身份**。延迟路径（rel 版 2661 经 rel 对象调 plain 版）下 par 即 rel 指针，与 C++ 静态限定调用中 this=TypePointerRel* 一致 | MATCH |
| 9 | 1115-1117 | `getSubType(off,&off)` 就地重规范化；NULL→NULL | :2048-2053 `get_sub_type` 失败即 `return None` 不写 `*off`（Ghidra 失败路径写回原值/不写，观察值等价） | MATCH |
| 10 | 1118-1119 | `!isArray → getTypePointerStripArray`（hasStripped 前置 + **剥一层** array） | :2054-2059 `strip_array`（单层，:4302-4307）+ `get_type_pointer`；hasStripped 前置在 get_type_pointer_result:1828 以 `get_stripped_arc` 实现，strip_array 内不做——见 §6 建议 1 的域界说明（fixture 域内无 stripped 类型，residual 已登记 TYPE-0001/TYPEFACTORY-ARC-IDENTITY-0001） | MATCH（域内） |
| 11 | 1120 | `isArray → getTypePointer`（preserve 数组层） | :2060-2062 | MATCH |

- 引用/输出参数：`off` in/out 就地改写（wrap 改写 + getSubType 重规范化）；`par`/`par_off` caller 共享累积槽，仅 struct/array 分支写入。✓
- 循环边界/遍历顺序：守卫顺序 wrap→enum→struct/array→getSubType→strip/preserve，逐条同序。✓
- 计数器/累加器：无计数器；par/par_off 只写不清。✓
- 排序/比较键：无排序；边界键 = getAlignSize（wrap）vs getSize（rel 延迟），区分正确。✓

### 1.2 rel 版：`down_chain`（typefactory.rs:1938-1982 ↔ type.cc:2656-2671）

| # | Ghidra 行 | 语义 | Rugra 行 | 判定 |
|---|---|---|---|---|
| 1 | 2659-2662 | 延迟守卫 `off>=0 && off<ptrto->getSize()`（**getSize 非 alignSize**）且 STRUCT/ARRAY → `TypePointer::downChain(...)` **静态限定调用**（this=rel 对象） | :1952-1960 `ptr.ptr_to.get_size()`（正确用 get_size）→ `down_chain_pointer(orig, ...)` 传 rel 指针 Arc 本身 → `par=this` 观察到 rel 身份 | MATCH |
| 2 | 2663 | `relOff = (off + offset) & calc_mask(size)`，size=指针大小 | :1962-1963 `calc_mask(ptr.base.size) as i64` 后 i64 AND（calc_mask: address.rs:1924，size>=8→u64::MAX，与 Ghidra address.hh 一致；C++ intb&uintb 提升再截断 ↔ Rust i64 AND，位模式恒等） | MATCH |
| 3 | 2664-2665 | `relOff<0 \|\| relOff>=parent->getSize() → NULL` | :1964-1966 | MATCH |
| 4 | 2667 | `origPointer = getTypePointer(size, parent, wordsize)`（size/wordsize 取 this） | :1969 `get_type_pointer(ptr.base.size, parent, ptr.wordsize)` | MATCH |
| 5 | 2668 | `off = relOff`（在 getTypePointer 之后） | :1970 同序 | MATCH |
| 6 | 2669-2670 | `relOff==0 && offset!=0 → return origPointer`，**无 par/parOff 写入** | :1975-1977 —— 本 slice 删除了旧 `*par=Some(orig_pointer); *par_off=rel_off` 写入，修正正确，父容器恢复分支现在零多余副作用 | MATCH |
| 7 | 2671 | `return origPointer->downChain(...)` 虚调用结果直传，**可为 NULL 无 fallback** | :1981 直传 `down_chain_pointer(&orig_pointer, ...)` 结果 —— origPointer 出自 getTypePointer（Ghidra 构造 plain TypePointer，虚派发必达 plain 版，静态调用等价）；本 slice 删除旧 `.or(Some(orig_pointer))` fallback，None 穿透语义正确 | MATCH |

- 引用/输出参数：off 被 relOff 改写后交递归进一步重规范化；par/par_off 只由延迟/递归 plain 版写入（recover-parent 路径零写入）。✓
- 循环边界/遍历顺序：守卫顺序 延迟→mask→parent 越界→recover-parent→递归，同序。✓
- 计数器/累加器：同 plain（caller 共享槽）。✓
- 排序/比较键：延迟键 getSize+metatype；越界键 parent->getSize()。✓

### 1.3 调用方多层下降循环（do-while vs while、offset 累加器跨迭代携带）

- Ghidra 真调用方 typeop.cc:1225-1230 为 **do-while**（首轮必执行）+ `pointer==NULL break` + `while(typeOffset != 0)` 续航；`parent`/`parentOff` 跨迭代共享、深层覆写浅层。
- 本 slice 明确不接线 production caller（commit message、metadata `production_caller_state` 一致声明 coreaction.rs/typeop.rs 无 downChain 调用——本人 grep 全仓证实：`down_chain` 生产调用面仅 typefactory.rs 内部，typeop.rs:2474 仅为注释占位）。
- fixture 以 `chain_step1`（fresh 累积器）+ `chain_step2`（显式携带 step1 的 off/par/parOff）两步复现 do-while 前两迭代的携带与覆写语义（step2 中 par 由 array 层的 `arr_pointer` 被覆写为 struct 层的 `ptr->inner`）。循环本体（while 条件、NULL break）留给 B1 接线租约双侧闭环——已如实登记，非本 slice 缺陷。

### 1.4 wrap-to-zero 身份与 re-intern 偏差（本 slice 修正点）

- type.cc:1098 `return this` ↔ Rust `Some(orig.clone())`（:2027）：返回**被下降指针本身的 Arc**，不再 `get_type_pointer` 重 intern。身份位由 fixture `pd_off_size_wrap`/`uint4_off_size_wrap` 的 `result_same_input=1` 双侧钉死。
- type.cc:1111 `par = this` ↔ Rust `*par = Some(orig.clone())`（:2044）：同上不 re-intern；延迟路径下保留 rel 身份，由 `rel_defer_field` 的 `par_same_input=1`（par shape = ptrrel）双侧钉死。
- 两处修正消除了旧实现"重 intern 丢失对象身份"的偏差，方向正确。

## 2. 路由正确性：`down_chain_virtual`（typefactory.rs:1888-1916）

C++ 派发语义（type.hh:429/681）：按对象动态类型——TypePointerRel → rel override；TypePointer → plain；非指针类型在 C++ 中虚调用不可达（ill-typed）。

Rugra 路由（三段）：
1. `pointer.base.pointer_rel` 存在（ephemeral 正规表示，`get_type_pointer_rel_ephemeral` ↔ type.cc:4016 安装，PointerRelState{parent,offset,stripped} ↔ TypePointerRel 字段，datatype.rs:335）→ rel 版：从 state 提取 parent/offset 传入，ptrto/size/wordsize 仍取自指针本体（= C++ this 的字段）。✓
2. `IS_PTRREL` flag 且 `rel_pointers` 侧表命中（legacy 命名表示，`get_type_pointer_rel`，RUGRA-GLUE 三参数形式）→ rel 版：parent/offset 取自侧表（Ghidra 中它们在对象内；纯表示差异，flag 与侧表在 `get_type_pointer_rel:1789-1790` 同步建立）。✓
3. 其余指针 → plain 版；非指针 → None（C++ ill-typed 的保守对应，注释已声明）。✓

Ghidra 单一 TypePointerRel 类 ↔ Rust 两种表示均路由 override，与两个虚声明点的派发语义一致。侧表 miss（不变量破坏态，Ghidra 不存在）fall-through plain 为防御分支，有 RUGRA-GLUE 注释，非对齐缺陷。

## 3. 双侧 fixture 证据自洽性（3fa2802 + 18192f9 + 60c39f4）

### 3.1 Git 对象级验证（本人独立执行）

| Pin | 声明值 | 复核值 | 判定 |
|---|---|---|---|
| ghidra HEAD | e40ed130… | `git -C ghidra rev-parse HEAD` = e40ed130… | ✓ |
| oracle cpp tree | b02e230a… | `rev-parse e40ed130:...cpp` = b02e230a… | ✓ |
| oracle Makefile blob | ca0719fa… | `rev-parse e40ed130:...Makefile` = ca0719fa… | ✓ |
| candidate commit | f9307c77… | 存在（commit），tree=50ac5a9d… | ✓ |
| 3fa2802:typefactory.rs blob | fc60ceb1… | `rev-parse 3fa2802:src/type_system/typefactory.rs` = fc60ceb1… | ✓ |
| 3fa2802:datatype.rs / Cargo.toml / Cargo.lock / build.rs blobs | 3c84bad…/f15ed7d…/9736a3c…/a0c81c8… | 全部一致 | ✓ |
| f9307c7 的同名 5 blobs | 同上 | **f9307c7 与 3fa2802 逐字节相同**（fc60ceb/3c84bad）——被 fixture 验证的源码 = 集成进 master 的源码 | ✓ |
| 8 个文件 sha256（comparand：cpp/rust fixture、runner、datatype.rs、typefactory.rs、Cargo.toml/lock、build.rs） | metadata 值 | 当前 HEAD `sha256sum` 全部一致（生产源码自 fixture 冻结后未漂移） | ✓ |
| input_manifest canonical sha256 | 1fd170d0… | 本人以 `json.dumps(sort_keys, separators, ensure_ascii=False)` 重算 = 1fd170d0…；25 个唯一 case id | ✓ |

### 3.2 stdout/diff sha 声明自洽

- `expected_ghidra_stdout_sha256` = `expected_rugra_stdout_sha256` = 4ec3a9cb…（双侧同 pin）；`observed_output_diff_sha256` = e3b0c442…（**空文件的 sha256 恒等式**，即零差异的数学化陈述）。
- Runner（tools/run_typefactory_downchain_virtual_oracle.sh，本人通读）在 normal mode 强制：所有 PENDING_* 必须已升级为真实 pin；oracle 侧 `git archive e40ed130` 提取 cpp 子树并**逐文件重建 blob sha1 与 ls-tree 全量比对**（归档=commit 树的强证明）后构建运行；candidate 侧 `git archive f9307c7` 同样全树 blob 校验 + 5 文件 sha256 校验 + 禁 cargo config + `--offline --locked`；双侧 stdout 逐行 schema 校验（25 行、kind、case 顺序、字段名/序）后**逐字段精确比对**，差异集合与 allowed 集合做精确等式（MATCH 要求空集）；最后三重 sha drift 检查（ghidra stdout/rugra stdout/output.diff 对 pin），任何 drift 即非零退出。**在双侧 stdout sha 与 diff sha 双 pin 下，"25 records 零差异"的声明无法在输出漂移时通过 runner**——声明与机制自洽。
- 注意（限制，非缺陷）：本人未重跑双侧（任务禁 cargo；oracle 重建依赖 binutils-dev 环境）。上述为 pin 链 + 机制自洽性的静态验证。

### 3.3 case 覆盖与声明的对应性（逐 case 推演 vs Ghidra 行为）

25 case 清单（.cc 与 .rs 逐条同名同参同序，输出 schema 逐字段一致；身份投影 C++ 指针相等 ↔ Rust `Arc::ptr_eq`）：

| 声明覆盖域 | case | 本人推演与 Ghidra 对照 |
|---|---|---|
| off==0 边界 | pd_off0 / route_rel_first | plain 首字段命中 off_out=0；rel offset==0 不触发 recover-parent（2669 需 offset!=0）落入递归 → 首字段。✓ |
| off==size 边界 | pd_off_size_nowrap / pd_off_size_wrap / uint4_off_size_wrap | nowrap：1088 命中、1090 返回 NULL（off/par 零突变）；wrap：24%24=0 → return this（result_same_input=1）；uint4 标量同构。✓ |
| 负编码 wrap | pd_negative_nowrap / pd_negative_wrap | -4 nowrap→NULL；wrap：sign_extend→-4%24=-4→+24=20（parOff=20 预重规范化值，par=this）→getSubType(20)→total 字段→off_out=4。与 metadata note 逐字一致。✓ |
| 多层 array 链 | array_elem / array_strip_contrast / array_preserve_nested / chain_step1 / chain_step2 | elem preserve（1119/1120 两分支的对照：strip_contrast 走 !isArray 剥一层、preserve_nested 走 isArray 保层数组）；chain 两步验证累积器携带与 par 覆写（do-while 语义的成分覆盖）。✓ |
| rel 再传播（递归 plain） | rel_total_field / rel_tail_null / rel_defer_boundary | rel_total_field：relOff=16→origPointer(ptr->progress)→递归 plain 命中 total；rel_tail_null：relOff=6 落 parent hole→递归 plain NULL **直穿**（2671 无 fallback，off_out=6、par 已被递归写入）；rel_defer_boundary：off==ptrto->getSize() 恰好脱离 2660 守卫（**用 getSize 的边界区分**）走 parent-relative。✓ |
| plain-rel 路由 | uint4_plain_null vs route_rel_first | 同形标量 ptrto：plain 基类 getSubType NULL→None；rel 经 parent-relative 到达首字段。派发差异被钉死。✓ |
| rel 延迟 + par 身份 | rel_defer_field | off=4∈[0,inner.size) 且 STRUCT→2661 静态调 plain 于 rel 对象：par=this=rel（par_same_input=1、par shape=ptrrel）。✓ |
| recover-parent 零副作用 | rel_recover_parent | relOff=(−16+16)=0 且 offset=16≠0→2670 返回 origPointer，par=null/par_off=−999 未触碰（parOff 初值 −999 为未触碰观察哨）。✓ |
| enum 分支 | enum_into_uint1 | 1102-1107：uint1 pointee、off=0。✓ |
| parent 越界 | rel_out_of_parent | relOff=24==parent->getSize()→2665 NULL（边界 `<` 不含端点）。✓ |

覆盖声明（commit message 的六个决定性观察）与 fixture 源码真实对应，无虚报。

## 4. 残差/边界声明核对

metadata 如实登记且与代码事实一致：
- hasStripped pre-strip / calcTruncate（TYPE-0001、TYPEFACTORY-ARC-IDENTITY-0001）：fixture 域内无 stripped 类型、无 alternate pointer size，不可观察——属实（fixture 头注释 §20-24 双侧同文声明）。
- TypeField ident（TYPEFIELD-IDENT-REPRESENTATION-0001）：downChain 闭包不读 ident——属实（type.cc:1084-1121/2656-2671 无 ident 访问）。
- wordsize != 1 / spacebase / 变长数组 / int8 外偏移：UNTESTED——如实（未列入 MATCH）。
- 零 production caller（B1 coreaction/typeop 接线为后续租约）——与全仓 grep 结果一致。
- 诚实性：claim_boundary 明示不主张 propagateAddIn2Out 消费者、主管线修复或模块 L3。✓

## 5. 预存测试失败抽查（实现者声明："3 个预存失败在父 commit 同样失败"）

任务指定的抽查（comment::test_comment_sorter… 域）以**因果链闭合**方式完成（禁 cargo，无法本地复跑名单）：
1. `git diff --stat 2972224 3fa2802` = 仅 `src/type_system/typefactory.rs` + `docs/api/type_system/typefactory.md` 两个文件——write-set 干净，不触碰 comment.rs 或任何其他模块。
2. `down_chain*` 生产调用面全仓 grep：仅 typefactory.rs 内部（typeop.rs:2474 为注释）→ 本 slice 的签名变更（首参 &TypePointer→&Arc<Datatype>）无外部破坏面；`cargo check --lib` 通过（commit 声明）与调用面独立证据互洽。
3. comment.rs 最后一次源码变更 `c5e685c` 是父 commit 2972224 的祖先（`git merge-base --is-ancestor` 证实）→ comment 域测试的代码与被测对象在父/子 commit 完全同源。
4. 结论：write-set 之外的任何测试失败（含 comment::test_comment_sorter* 若失败）不可能由本切片引入；"父 commit 同样失败"在因果上必然成立。typefactory 自身 57/57 通过（commit 声明）与 write-set 内聚一致。
- 限制记录：精确的失败数量"3"未做本地复现（禁 cargo）；历史 TODO 记录的预存失败域（comment/dynamic/funcdata/ruleaction 家族）与本切片 write-set 无交集，与声明相容。

## 6. 建议（非阻断）

1. **fixture 对 getSize vs getAlignSize 无区分力**：域内全部类型 size==alignSize（inner 8/8、progress 24/24、holed 12/12、inners3 24/24、uint4 4/4、enum8 8/8），故 rel 延迟守卫 2660 的 `getSize()` 与 plain wrap 1087 的 `getAlignSize()` 之差（off 落在 [size, alignSize) 时 rel 不延迟而 plain 进 wrap）未被任何 case 区分。源码层 Rust 已用正确 getter（rel: get_size :1953；plain: get_align_size :2009），非缺陷；建议后续 re-pin 批补一个 alignSize>size 的 case（如 size=12/alignment=8→alignSize=16 的 struct，off=12/14 两路对照），并在 metadata `api_domain` 的 UNTESTED 清单补录该维度。
2. **do-while 调用方闭环**：typeop.cc:1225-1230 的循环本体（NULL break、`while(typeOffset!=0)`、parent/parentOff 深层覆写浅层后的 getTypePointerRel(parent,pt,parentOff) 收尾）在 B1 coreaction/typeop 接线租约交付时需双侧 fixture 闭环；本 gate 只覆盖了两步显式链的成分语义。
3. **legacy 侧表 miss fall-through**：IS_PTRREL 置位但侧表无条目时静默走 plain（typefactory.rs:1905-1914）。该状态在 Ghidra 不存在（flag 与 parent/offset 同对象），建议加 debug_assert 在调试构建暴露不变量破坏（生产路径可保留现状）。
4. **metadata 字段口径**：`critical_git_blobs` 为 git blob id、`comparand.*` 为文件 sha256，两种形态并存（符合 AGENTS.md 双形态惯例），但建议在 metadata 头部加一行口径注释，降低后续 re-pin 混用风险。
5. 18192f9 的 Alignment Evidence 引用 "typefactory.rs:1888/:1938/:1996" 为候选 f9307c7 树行号，与 master 3fa2802 行号一致（同 blob），无漂移。

## 7. 最终判定

**APPROVE**

- 四类决定性语义：plain 版（wrap 链/return this 身份/enum/par=this/strip-vs-preserve）与 rel 版（getSize 延迟键/mask 位模式/parent 越界/recover-parent 零写入/尾式 None 直穿）逐行与锁定 oracle e40ed130 等价；本 slice 的三处修正（rel recover-parent 副作用删除、rel 尾式 fallback 删除、plain 身份去 re-intern）方向均正确。
- 虚分派路由：与 type.hh:429/681 的动态类型派发语义一致，两种 Rust 表示（pointer_rel 状态/legacy 侧表）均达 rel override。
- 双侧证据：oracle/candidate/集成三方 blob 逐字节闭合，8 文件 sha256 无漂移，manifest sha 可重算复现，stdout/diff 双 pin 下 runner 的 drift 检查使零差异声明自洽；25 case 覆盖声明与 fixture 源码逐条对应。
- 残差与边界如实登记，无 L3 越权主张；预存失败抽查因果闭合。
