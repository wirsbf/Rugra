# `varmap.rs` API Reference

**状态**: 骨架已实现（L2），集成待完成
**源代码路径**: `src/varmap.rs`

**2026-08-24 修复（VARMAP-LOCALWINDOW-0001）**: local 分析窗口接线——`restructure_varnode` 内硬编码的正向 `[0, 0x100000)` 窗口（参数侧半区）替换为忠实的 `reset_local_window`（varmap.cc:432-460）：并集树 = 原型 localRange ∪ paramRange（默认负增长 8 字节栈 = `[u64::MAX-999999, u64::MAX] ∪ [0,511]`），MapState 构造逐条减 paramrange（varmap.cc:870-875），initialize 端点 = `wrapOffset(getLastSignedRange+1)`（= 0，varmap.cc:1070），并补齐 `reconcile_datatypes`（varmap.cc:960）。此前每条符号扩展负偏移 local/open hint 在 `add_range` 门被丢弃（varmap.cc:902），4096B 数组无从恢复、负偏移名回绕（`in_stack_ffffffffffff…`）。原型 localRange 与并集树分立缓存（`proto_local_range` vs `local_range`——buildVariableName 读前者，varmap.cc:555，正偏移参数命名不回归）。锁定 oracle 双侧 fixture：`tools/run_varmap_localwindow_oracle.sh`（VARMAP-LOCALWINDOW-0001，四 case：默认窗、进窗/出窗门、open 数组延伸+端点截断、命名分支）。

**2026-08-23 修复（GETSTR-ZERODIFF-C）**: `restructure_varnode` 开头的符号全清改为 `clearUnlockedCategory(-1)` 忠实移植（Ghidra varmap.cc:1273 调用 ScopeInternal::clearUnlockedCategory，database.cc:2086-2096：`if (sym->getCategory() >= 0) continue;` —— 参数/equate 类符号无条件存活；category<0 且 typelock 的存活（未锁名重置为 $$undef 占位，cc:2091-2094）；其余 removeSymbol）。旧实现 `self.symbols.clear()` 抹掉平台播种的 function_parameter 符号，导致 input-locked DWARF 参数每次重结构化退化为 in_RXX 不规则输入名。幸存者的 nametree/category/mapentry 以旧索引→新索引重链。

## 模块说明

Ghidra `varmap.cc` (1620行) 的 Rust 移植。负责局部变量的栈帧重构和映射。

## 导出的公共 API

### `pub struct RangeHint`
栈地址空间上的类型化范围提示。对应 Ghidra RangeHint。
- `start: u64` — 起始偏移
- `size: i32` — 字节大小
- `sstart: i64` — 有符号起始偏移（用于比较）
- `dtype: Option<Arc<Datatype>>` — 数据类型
- `flags: u32` — 标志（TYPE_LOCK, COPY_CONSTANT, UNALIASED, MAPPED）
- `range_type: RangeType` — Fixed/Open/Endpoint

#### RangeHint 方法（2026-06-26 完整对齐 Ghidra varmap.cc）
以下方法现已 **1:1 对齐 Ghidra**（此前为简化版，已替换）：

- `is_const_absorbable(&self, b)` — `RangeHint::isConstAbsorbable` (varmap.cc:30)
- `reconcile(&self, b)` — `RangeHint::reconcile` (varmap.cc:62)，含 `get_sub_type` 对齐遍历
- `contain(&self, b)` — `RangeHint::contain` (varmap.cc:109)
- `preferred(&self, b, reconcile)` — `RangeHint::preferred` (varmap.cc:126)
- `absorb(&mut self, b)` — `RangeHint::absorb` (varmap.cc:217)
- `merge_with(&mut self, b, types)` — `RangeHint::merge` (varmap.cc:259)，三态 resType（0/1/2）；`types` 对应 Ghidra 签名的 `TypeFactory *typeFactory` 参数（varmap.hh:124），resType==2 时经 `getBase(size,TYPE_UNKNOWN)` 取未知类型（varmap.cc:309）（2026-08-16，`TYPE-WIRING-0001`）
- `compare(a, b)` — `RangeHint::compare` (varmap.cc:321)，排序：offset→size小优先→rangeType→flags→highind
- `attempt_join(&mut self, b)` — `RangeHint::attemptJoin` (varmap.cc:170)，数组元素吸收

### `pub struct AliasChecker`
栈指针别名分析器。对应 Ghidra AliasChecker。
**2026-06-26 完整对齐**（此前为简化版，仅扫描 STORE）。
**2026-07-05 方向约定修正**：`direction` 字段遵循 Ghidra 约定
（`varmap.cc:700` `direction = stackGrowsNegative() ? 1 : -1`），
即 `1` = 负向增长（x86）、`-1` = 正向增长。此前 `ScopeLocal::new`
误初始化为 `-1`，导致 `has_local_alias` 在 x86 上恒返回 false，静默
关闭了别名分析（P0-1，详见 `docs/alignment_audit/INDEX.md`）。
- `pub aliases: Vec<u64>` — 别名偏移（gather 后按 gather 序；`sort_aliases` 后升序，varmap.cc:726）
- `pub add_base: Vec<AddBase>` — 加法基根（base + index）
- `direction: i32` — 方向：`1`=负向增长(x86)，`-1`=正向增长（与 Ghidra `AliasChecker::direction` 同号）
- `gather(&mut self, fd, stack_grows_negative, defer)` — `AliasChecker::gather` (varmap.cc:692-704)：复位状态、`direction = stackGrowsNegative() ? 1 : -1`（Rugra 无 per-space 增长位，传 scope 的原型派生旗标——与 Ghidra 栈空间的位同源配置）、`derive_boundaries(fd 原型)`、非 defer 立即 `gather_internal`。**2026-08-25 VARMAP-GATHEROPEN-GUARD-0001**：deriveBoundaries 从此经该入口接入 varmap 域（此前管线从不调用，边界恒 0x1000000）
- `gather_internal(&mut self, fd)` — `AliasChecker::gatherInternal` (varmap.cc:660)；`alias_boundary` 初值 = `local_extreme`（非硬编码 ~0——正向增长时为 localBoundary），列表清理由 `gather` 承担（varmap.cc:698-699），此处不再排序（sortAlias 独立，varmap.cc:1279）
- `gather_additive_base(&mut self, startvn)` — `AliasChecker::gatherAdditiveBase` (varmap.cc:741)，递归 BFS 追踪 INT_ADD/INT_SUB/PTRADD/PTRSUB/SEGMENTOP/COPY 后继
- `sort_aliases(&mut self)` — `AliasChecker::sortAlias` (varmap.cc:726)，restructureVarnode varmap.cc:1279 调用（checkUnaliasedReturn 的 lower_bound 依赖有序）
- `has_local_alias(&self, vn)` — `AliasChecker::hasLocalAlias` (varmap.cc:711)；`direction==-1`（正向增长）时返回 false；`!calculated` 时保守 true（Ghidra 此处现场 gatherInternal——Rust 取 &self，管线两条路径均预计算，未计算分支不可达）
- `derive_boundaries(&mut self, localrange, paramrange, has_model)` — `AliasChecker::deriveBoundaries` (varmap.cc:633-655)：默认 `localExtreme=~0 / localBoundary=0x1000000`（正向增长时 `localExtreme=localBoundary`）；**有模型时** `localBoundary = paramrange 末 range 的 last`（默认负增长模型 = **511**，fspec.cc:2298-2307——此前死区 [511,0x1000000) 内的正偏移加法基不收缩 aliasBoundary，R8 §6.3 证伪"行为等价"后的修复），正向增长改 `paramrange 首 range 的 first` 且 `localExtreme = localBoundary`
- `boundaries()` — RUGRA-GLUE 观察口：`(localBoundary, localExtreme, aliasBoundary)`（C++ fixture 经 `#define private public` 直读成员）

辅助函数：
- `pub fn gather_offset(vn)` — `AliasChecker::gatherOffset` (varmap.cc:817)，递归求和常量偏移（COPY/ADD/SUB/PTRADD/SEGMENTOP），末尾按字节大小掩码；`VARMAP-GATHEROFFSET-0001` 已按 `address.hh:499` 的 `size >= 8` 钳位语义修复 8-byte 边界，并由锁定 12.0.4 的 7/8-byte 直接状态 fixture 验证。该窄分支的 `MATCH` 不提升整个 `AliasChecker` 模块状态。
- `fn find_spacebase_input(fd)` — `Funcdata::findSpacebaseInput`，Rugra 中 RSP = Register@0x20 size8 无 def 的输入 varnode

### `pub struct MapState`
范围提示收集器和重构器。对应 Ghidra MapState。
**2026-06-26 完整对齐**（此前为简化版）；**2026-08-24 VARMAP-LOCALWINDOW-0001**：分析窗口
由硬编码半开 `[0,0x100000)` 换为 Ghidra 的 `range` 成员模型（varmap.hh:176）——
`MapState(spc,rn,pm,dt) : range(rn)` 后逐条减 paramrange（varmap.cc:864-875），以排序
闭区间 `Vec<(first,last)>` 承载，add_range 的门与 initialize 的端点都从该真值窗口推导：
- `new(range)` / `new_with_default(range, default_type)` — 构造器（varmap.cc:864-867）：`range` 为
  分析窗口（scope 并集树减 paramrange，由 `ScopeLocal::build_map_state` 按 varmap.cc:1260 组装）
- `analysis_range()` / `hints()` — RUGRA-GLUE 只读观察口（锁定 fixture 的观察面；C++ 侧经
  `#define private public` 直读 `range`/`maplist`）
- `add_range(start, dtype, flags, rt, high_ind)` — `MapState::addRange` (varmap.cc:896)：size<=0 或
  完整 extent `[st, st+size-1]`（uintb 回绕）不在分析窗口单一 range 内则丢弃（`range.inRange(addr,sz)`，
  varmap.cc:902 / address.cc:468-487，`window_in_range`）；无类型回退默认类型；`sst` 为
  byteToAddress+sign_extend+addressToByte（varmap.cc:904-906，1-word-size 8 字节栈上即
  `start as i64`——负偏移保持负值供 `RangeHint::compare` 有符号排序）
- `add_fixed_type(start, dtype, flags)` — `MapState::addFixedType` (varmap.cc:926)
- `gather_varnodes(fd)` — `MapState::gatherVarnodes` (varmap.cc:1124)，逐 op-code 分支（INDIRECT/MULTIEQUAL/PIECE/SUBPIECE/COPY/默认），含 same-storage 去重与 `is_read_active`。PIECE 视为两个 COPY（little-endian slot=1，addr+=inFirst.size）；SUBPIECE 用 little-endian `trunc = in1.offset`，`addr = in0.off + trunc` 后与 vn 地址比较
- `gather_open(fd, types)` — `MapState::gatherOpen` (varmap.cc:1211-1249)：先跑内嵌 checker 的 `gather(fd, grows, false)`（varmap.cc:1214，含 deriveBoundaries），对每个 AddBase 根：指针→pointee，**数组层全下钻**（varmap.cc:1226-1227 `while`——此前单层是缺陷），index 在则 minItems=3；非指针传 `None`（Ghidra 传 NULL，"Do unknown array"，varmap.cc:1230），由 `add_range` 回退默认类型（varmap.cc:896）；随后遍历 `fd.heritage.load_guard`/`store_guard` 走 `add_guard`（varmap.cc:1241-1248）。**checker 现为 MapState 成员**（varmap.hh MapState `AliasChecker checker`），`sort_alias`/`get_alias` 是 restructureVarnode 的消费口（varmap.cc:1279-1284）
- `set_stack_grows_negative(grows)` — RUGRA-GLUE：Ghidra 由 space 成员的增长位（varmap.cc:700）供 checker.gather 取向；Rugra AddressSpace 无该位，装 scope 的原型派生值
- `add_guard(guard, opc, types)` — **2026-08-25 VARMAP-GATHEROPEN-GUARD-0001** `MapState::addGuard` (varmap.cc:1003-1039)：`isValid`（op 活且 opcode 匹配，heritage.hh:169）→ step==0 拒 → 地址输入类型指针下钻数组层 → outSize 匹配/整除 step（整除时假装 outSize 数组）→ 对齐不匹配且 step<=8 时工厂 `getBase(step,TYPE_UNKNOWN)` 重型 → range-locked（`analysis_state==2`）`minItems=(max-min+1)/step-1` 否则 3 → open hint
- `gather_symbols(scope)` — **2026-08-25** `MapState::gatherSymbols` (varmap.cc:1044-1059)：按 space 的 maptable 列表序回灌每个映射符号（entry 起始偏移、符号类型、typelock→hint 旗标）为 fixed hint——restructureVarnode varmap.cc:1269 的 typelocked 符号回灌
- `sort_alias()` / `get_alias()` — varmap.cc:1279/1281-1284 的 `state.sortAlias()`/`state.getAlias()`
- `is_read_active(vn)` — `MapState::isReadActive` (varmap.cc:1088)，过滤纯 same-storage INDIRECT/MULTIEQUAL
- `initialize()` — `MapState::initialize` (varmap.cc:1063-1082)：先取分析窗口的
  ** getLastSignedRange**（`get_last_signed_range`，address.cc:562-583——正半区
  `first <= midway` 末位，否则负半区末位），端点在 `wrapOffset(last+1)`
  （varmap.cc:1070，8 字节负增长默认窗 → 偏移 0，即"窗口顶端"），size=1/endpoint/-2；
  之后 stable_sort + `reconcile_datatypes`（varmap.cc:1078-1079）
- `reconcile_datatypes()` — `MapState::reconcileDatatypes` (varmap.cc:960-996)：同
  start/size/flags 组内取 `typeOrder < 0` 最具体类型统一到全组，`compare == 0` 的重复
  hint 消除（2026-08-24 随 VARMAP-LOCALWINDOW-0001 补齐——窗口打开后 hint 量激增，
  initialize 的该步骤成为必需）
- `gather_spacebase(fd, types)` — **Rugra 专有**：Rugra 的 x86 lift 不产 Stack varnode，故扫描 LOAD/STORE 的地址，若为 RSP 派生（含 frame_base 链 `INT_ADD(INT_SUB(RSP,fs),off)`），则在对应栈偏移合成 fixed RangeHint（类型取 `make_int_type(types,size)` 即工厂 `getBase(size,TYPE_UNKNOWN)`）。对应 Ghidra 的 Stack-spacebase 解析（`ActionSpacebase`）。
  - **2026-06-29 续**：Stack INDIRECT varnode 现在产生了（heritage discover+guard），但 gather_varnodes 对 same-addr INDIRECT 跳过（对齐 varmap.cc:1145-1151），不产生 RangeHint。Stack symbol 仍由 gather_spacebase 提供。这是正确的——Ghidra 的 Stack symbol 也来自 gatherOpen + rename 后的 def-use 链，而非 gather_varnodes 直接。

### `pub struct LocalSymbol`
重构后的局部变量符号（Ghidra Symbol database.hh:168 + 首个整映射 SymbolEntry）。
- `name: String` — 变量名（Symbol::name）
- `start: u64` — 栈偏移
- `size: i32` — 大小
- `dtype: Option<Arc<Datatype>>` — 类型
- `unaliased: bool` — 是否无别名（可安全合并）
- `is_param: bool` — 是否为函数参数
- `display_name: String` — Symbol::displayName（database.hh:179），输出用名
- `name_dedup: u32` — Symbol::nameDedup（database.hh:181），nametree 同名去重 id
- `category: i32` — Symbol::category（-1/0/1/2/3 = 无/参数/equate/union_facet/fake_input，见 `symbol_category`）
- `cat_index: u32` — Symbol::catindex，category 内位置
- `typelock`/`namelock: bool` — Symbol::flags 的 typelock/namelock 位
- `addrtied: bool` — database.cc:1149-1150（任一空 uselimit 静态映射置位）
- `persist: bool` — database.cc:1131-1132/1138-1139（全局 scope 或全局发现域
  命中，装图时折入符号）
- `property_flags: u32` — database.cc:1153 的 addMap 属性折入位（flagbase 的
  readonly/volatile 折到符号 flags，一次性、装图时）
- `usepoint: Option<u64>` — 首个 SymbolEntry 的 first use address（None = invalid Address；`buildDefaultName` 据此决定 addrtied flag，database.cc:1776）
- `is_name_undefined()` — `Symbol::isNameUndefined`（database.cc:246）：15 字符 `$$undef` 前缀

### `pub struct ScopeLocal`
局部变量作用域。对应 Ghidra ScopeLocal。`#[derive(Debug, Clone)]`（2026-06-26：
Clone 用于 printc 从 `fd.scope` 复用）。
**2026-06-26 完整对齐**（类型面 2026-08-16 `TYPE-WIRING-0001` 统一到 TypeFactory 单轨：`restructure_varnode` 解析工厂句柄——`fd.arch.types` 优先，无 Architecture 生产路径回退 `TypeFactory::shared_default()`（DataOrg flavor，模拟 headless 单 Architecture 进程）——并贯穿 `gather_spacebase`/`restructure`/`merge_with`/`create_entry`/`fake_input_symbols`；Ghidra 对应 `glb->types` 于 varmap.cc:1261/1309、`fd.getArch()->types` 于 varmap.cc:1129/1438）：
- `restructure_varnode(fd)` — 主入口（**fd 取 `&mut`**：annotateRawStackPtr 插 PTRSUB op，varmap.cc:405-406）：`ScopeLocal::restructureVarnode` (varmap.cc:1256-1286) 完整编排：clearUnlockedCategory(-1) 存活逻辑→reset_local_window→build_map_state→gather_varnodes→gather_spacebase→gather_open（内嵌 checker.gather + addGuard）→**gather_symbols 回灌（:1269）**→restructure→**clear_unlocked_category(function_parameter) + clear_category(fake_input)（:1275-1276）**→fake_input_symbols→**sort_alias（:1279）→mark_unaliased→check_unaliased_return（:1280-1282）→alias[0]==0 时 annotate_raw_stack_ptr（:1284-1285）**；默认类型 = 工厂 `getBase(1,TYPE_UNKNOWN)`（varmap.cc:1261）。fakeInputSymbols 先于 markUnaliased（Ghidra varmap.cc:1272-1277 的注释："define fake symbols so that mark_unaliased will work"——此前 Rugra 顺序颠倒）；aliasyes 门未穿透（coreaction.rs:877-880 TODO，Rugra 恒 true）
- `clear_unlocked_category(cat)` — `ScopeInternal::clearUnlockedCategory` (database.cc:2071-2090) 的 cat>=0 分支（varmap.cc:1275 对 function_parameter 调用）：typelock 存活（未 namelock 的已定义名重置 $$undef，database.cc:2080-2082）；`resetSizeLockType`（:2085-2086）无 Rugra 路径（LocalSymbol 无 sizelock 概念，不可达）；其余 removeSymbol
- `clear_category(cat)` — `ScopeInternal::clearCategory` (database.cc:2022-2029) 的 cat>=0 分支（varmap.cc:1276 对 fake_input 调用）
- `check_unaliased_return(fd, alias)` — **2026-08-25** `ScopeLocal::checkUnaliasedReturn` (varmap.cc:414-428)：首个 RETURN 的值输入在栈空间且无别名（有序表的 lower_bound）触达 `[off, off+size-1]` 时 `mark_not_mapped(off, size, false)`（删重叠符号 + 并集树去范围）
- `annotate_raw_stack_ptr(fd)` — **2026-08-25** `ScopeLocal::annotateRawStackPtr` (varmap.cc:386-408)：type recovery 已开始时，栈指针的非加法读者（跳过 eval-special 非调用与 INT_ADD/PTRSUB/PTRADD）改为消费占位 `PTRSUB(sp,#0)`（newOpBefore + opSetInput 到 getSlot 槽位）
- `reset_local_window(fd)` — `ScopeLocal::resetLocalWindow` (varmap.cc:432-460)：`stackGrowsNegative` 取自原型（:435），`min/maxParamOffset` 复位（:436-437；**等价性仅限第 1 趟/经 clear 的边界**——Ghidra 只在构造/`Funcdata::clear`/decode 调 resetLocalWindow（funcdata.cc:70/96/836），RULE_REPEATAPPLY 重启不 clear（action.cc:539-570），第 2+ 趟保持 markNotMapped 窄化窗口与跨趟累积 min/max；Rugra 每趟 fresh scope 全量重装——登记 `VARMAP-CROSSPASS-PERSISTENCE-0001`），并集树 = 原型 localRange ∪ paramRange（:441-458）装入 `local_range`；原型自身 localRange 另存 `proto_local_range`（buildVariableName 的门读原型而非并集，varmap.cc:555）。`rangeLocked`（:439）无 Rugra 路径（`<localdb lock>` decode 未移植）。**2026-08-24 VARMAP-LOCALWINDOW-0001**：替换原先硬编码的正向 `[0,0x100000)` 窗口——那是参数侧半区，把每条符号扩展负偏移 local/open hint 在 add_range 门丢弃（4096B 数组不恢复、负偏移名回绕的单点根因）
- `build_map_state(fd, types)` — varmap.cc:1260-1261 的 MapState 组装：分析窗口 = 并集树逐条减 paramrange（varmap.cc:870-875 "Clear possible input symbols"）+ `getBase(1,TYPE_UNKNOWN)` 默认类型
- `restructure(state, types)` — `ScopeLocal::restructure` (varmap.cc:1294)，相交→merge_with(工厂句柄)，不相交→attempt_join/adjust_fit/create_entry
- `adjust_fit(a)` — `ScopeLocal::adjustFit` (varmap.cc:587)，typelock/size0 拒绝 + 符号重叠收缩
- `create_entry(hint, types)` — `ScopeLocal::createEntry` (varmap.cc:617)：空名 addSymbol（$$undef 占位）+ `concretize`（工厂，varmap.cc:622）+ 数组类型包装（varmap.cc:625——Rust 无 `TypeFactory::getTypeArray`，数组壳仍本地构造，元素类型为工厂对象；登记 TYPE-WIRING-0001 残差）；命名推迟到 assign_default_names
- `fake_input_symbols(fd, types)` — **完整 1:1** `ScopeLocal::fakeInputSymbols` (varmap.cc:1392-1448)：按 `fd->beginDef(Varnode::input)`（VarnodeCompareDefLoc：space/offset/size）遍历 input Varnode；仅以**首地址 1 字节**做 `getParamRange().inRange(addr,1)` 过滤（varmap.cc:1407，负增长 flipped 局部被滤除）；内层按重叠（`off2 <= endpoint`，**相邻不合并**，varmap.cc:1412）吸收同 space 组员；组员 typelock 则整组跳过（varmap.cc:1416-1420）；`lockedinputs != 0` 时以**内层最后检视的（breaker）Varnode** 做 `queryProperties` 探测，命中 `function_parameter` 符号则 continue（varmap.cc:1428-1435）；endpoint/size 为 uintb 模 2^64 回绕（varmap.cc:1408/1413/1437）；`addSymbol("",getBase(size,TYPE_UNKNOWN),addr,invalid)` + `setCategory(fake_input,-1)`，LowlevelError（无类型 / 映射越过地址空间末端，database.cc:1822-1823/1855-1861）被捕获并路由 `fd->warningHeader` 后继续扫描（varmap.cc:1439-1445）。fixture：`tools/run_scope_fake_input_symbols_oracle.sh`（VARMAP-FAKEINPUT-0001，八 case 全观察点 MATCH）
- `get_category_size(cat)` — `ScopeInternal::getCategorySize` (database.cc:2806)：负数/未分配类别返回 0；fake_input_symbols 的 `lockedinputs` 探测源
- `find_container_invalid_usepoint(space, addr, size)` — `ScopeInternal::findContainer`（invalid usepoint 形态，database.cc:2250-2282）+ `SymbolEntry::inUse`（database.cc:114-120，仅 addrtied 项匹配 invalid usepoint）：降序 (first,last) 遍历、严格更小替换、精确尺寸短路，平局取升序末位；dynamic 项不参与；父作用域链（Scope::queryProperties 的 stackContainer 上溯）在 varmap ScopeLocal 无父链——database-scope 统一前为登记残差
- `add_fake_input_symbol(types, addr, size)` — `Scope::addSymbol` 的 LowlevelError 面（database.cc:1810 addSymbolInternal 的 no-type 检查 + database.cc:1843 addMapInternal 的地址空间末端回绕检查），错误文本携带 `buildUndefinedName` 占位名
- `func_proto_param_range(fd)`（自由函数）— `FuncProto::getParamRange` (fspec.hh:1540)：Rugra FuncProto 不持有模型 Arc，按 `FuncProto::setScope` 的回退序（fspec.cc:3879-3885）经 Architecture 注册表解析——约定名 → defaultfp → 无 Architecture 时以 `ProtoModelFull::new`（= `defaultParamRange`，fspec.cc:2292，8 字节负增长栈 [0,511]）作 FUNCPROTO-MODEL-BIND-0001 期占位
- `func_proto_local_range(fd)`（自由函数）— `FuncProto::getLocalRange` (fspec.hh:1539)：与 param 版同一回退序的 local 窗口桥（2026-08-24 VARMAP-LOCALWINDOW-0001）；无 Architecture 回退 `ProtoModelFull::new` 的 `default_local_range`（fspec.cc:2263-2290，负增长 8 字节栈 = `[u64::MAX-999999, u64::MAX]`——heritage 符号扩展负偏移所在半区）
- `func_proto_stack_grows_negative(fd)`（自由函数）— `FuncProto::isStackGrowsNegative` (fspec.hh:1541)：同回退序读模型 `stackgrowsnegative`（resetLocalWindow :435 消费）；无模型回退 `true`（ProtoModel 默认构造，fspec.cc:2349）
- `func_proto_has_model(fd)`（自由函数）— `FuncProto::hasModel` (fspec.hh:1389)：同回退序探测模型是否绑定；derive_boundaries 的 `if (proto.hasModel())` 门（varmap.cc:641）——无 Architecture 时 false，边界保持 0x1000000 默认（与 Ghidra 无模型原型一致；Ghidra 侧经 Funcdata 构造的 setScope（funcdata.cc:68）模型恒绑定，该 false 分支在 oracle fixture 域不可构造，仅 Rust 单测覆盖）
- `window_in_range(ranges, offset, size)`（自由函数）— `RangeList::inRange(addr,size)` (address.cc:468-487) 的 Vec 窗口形态：完整 extent（uintb 回绕）须落在单一 range 内
- `get_last_signed_range(ranges)`（自由函数）— `RangeList::getLastSignedRange` (address.cc:562-583)：正半区（`first <= midway`）末位，无则负半区末位；initialize 的端点推导源
- `param_range_in_range(paramrange, offset)`（自由函数）— `RangeList::inRange(addr,1)` (address.cc:468-487)：空表 false，否则最后一个 `first <= offset` 的 range 须 `last >= offset`（Rugra fspec RangeList 无 space 字段——参数 range 全为 stack 且调用方已过滤 scope space，Ghidra 的 space 测试被覆盖）
- `make_int_type(types, size)` — 辅助：工厂 `getBase(size,TYPE_UNKNOWN)`（varmap.cc:942/1031 同型调用），供 gather_spacebase 与 fallback
- `build_variable_name(space, offset, usepoint, ct, index, flags)` — **权威命名覆盖** `ScopeLocal::buildVariableName` (varmap.cc:548)：addrtied 且在 local_range 内走 `<printNameBase>Stack[X|Y]_hex`，否则落到 `build_variable_name_internal`
- `build_variable_name_internal(...)` — `ScopeInternal::buildVariableName` (database.cc:2434)：unaffected/persist/irregular input/param_N/addrtied/extraout/default local 七分支 + 10 次碰撞 bump + makeNameUnique
- `make_name_unique(nm)` — `ScopeInternal::makeNameUnique` (database.cc:2553)：`_NN`(2位)/`_xNNNNN`(5位) 后缀递增
- `find_first_by_name(nm)` / `insert_name_tree(idx)` — `findFirstByName`/`insertNameTree` (database.cc:2733/2712)：SymbolNameTree (name, nameDedup) BTreeMap 模拟
- `rename_symbol(idx, newname)` — `ScopeInternal::renameSymbol` (database.cc:2152)：erase→改名+display→reinsert
- `build_undefined_name()` — `ScopeInternal::buildUndefinedName` (database.cc:2520)：`$$undefXXXXXXXX` 递增序列
- `add_symbol(nm, ct, start, usepoint)` — `Scope::addSymbol`+`addSymbolInternal`+`addMapPoint` (database.cc:1530/1810/1548)
- `build_default_name(idx, base, vn, fd)` — `Scope::buildDefaultName` (database.cc:1756)：entry 路径由 usepoint 推导 flags、function_parameter 用 catindex+1；vn 分支保留（待 ActionNameVars 接入）
- `assign_default_names(base)` — **`ScopeInternal::assignDefaultNames`** (database.cc:2850)：nametree 顺序、共享 `int4 base` 计数器、二次运行幂等
- `set_category(idx, cat, ind)` / `get_category_symbol(cat, ind)` / `get_category_size(cat)` — `ScopeInternal::setCategory`/`getCategorySymbol`/`getCategorySize` (database.cc:2824/2814/2806)
- `symbols_in_nametree_order()` — RUGRA-GLUE：锁定 fixture 的 nametree 顺序只读观察口
- `mark_unaliased(aliases)` — `ScopeLocal::markUnaliased` (varmap.cc:1332)，含 0xffff 距离启发式（alias_block_level 待接入）
- `find_symbol(offset)` — 按偏移查找重构后的符号

**命名状态字段**（database.hh:809/805, varmap.cc:345-348）：`nametree: BTreeMap<(String,u32),usize>`、
`category_lists`、`local_range: Vec<(first,last)>`（symboltab 并集范围树——resetLocalWindow
装入的 localRange ∪ paramRange，`longest_fit`/`local_range_remove_range`/`in_scope` 消费）、
`proto_local_range: Vec<(first,last)>`（**原型自身 localRange** 缓存——buildVariableName 的门，
varmap.cc:555；正偏移参数在并集内但不在本窗口，命名落入 ScopeInternal 分支）、`min_param_offset`/
`max_param_offset`（markNotMapped parameter=true 更新，varmap.cc:519-524）、`stack_grows_negative`、
`register_names`（Translate::getRegisterName 表，translate.hh:380 的调用方装填桥）。

## 当前限制

varmap 算法层（RangeHint/AliasChecker/MapState/ScopeLocal）已 1:1 对齐 Ghidra。
尚未完成：
- ~~**集成到 printc.rs**：变量命名仍用启发式 get_stack_variable_name，未走 ScopeLocal 符号查找~~ → 2026-08-15 已完成：printc 消费 `assign_default_names` 建立的权威名（见 printc.md），命名源切换
- alias_block_level 配置（影响 markUnaliased 的 struct/array 阻断）
- ~~LoadGuard/StoreGuard 在 gatherOpen 中的 addGuard 路径~~ → 2026-08-25 VARMAP-GATHEROPEN-GUARD-0001 已移植（MapState::addGuard + gather_open 消费 `fd.heritage.load_guard/store_guard`），锁定 oracle 双侧 fixture 验证
- coreaction.rs ActionActiveParam 的 `AliasChecker::new(1)+gather_internal` 改走 `gather`（coreaction.cc:1731 `aliascheck.gather(&data,stack,true)` 的 defer 语义 + deriveBoundaries）——fspec/coreaction 租约外，登记 VARMAP-ACTIVEPARAM-GATHER-0001
- fspec.rs `check_input_trial_use` 缺 fspec.cc:5618 `!getLocalRange().inRange → markNoUse` 与 callee_pop 分支（fspec.cc:5619-5625）——func_proto_local_range 桥已可供，fspec.rs 租约外，登记 FSPEC-TRIALUSE-LOCALRANGE-0001
- derive_boundaries 的 direction==-1（正向增长栈）分支无 fixture 驱动（fixture 栈为负增长；可构造分歧输入需正向增长 SpacebaseSpace）
- TYPE_PARTIALSTRUCT/PARTIALUNION 在 addFixedType 的处理（Rugra 无此元类型）
- buildDefaultName 的代表 Varnode 分支（database.cc:1759-1771）已移植但无 fixture 驱动（需活 Funcdata/HighVariable；绑定 ActionNameVars caller 闭包）
- 真实 Translate 寄存器表接入 ScopeLocal::register_names（生产管线 Architecture 桥接待做）
- Symbol::symbolId 分配（database.cc:1813-1816）与 multiEntrySet 维护：Rugra LocalSymbol 单整映射模型暂无对应物

测试：varmap::tests 26 个（compare/contain/reconcile/preferred/merge/absorb/const_absorbable/
build_variable_name×2/assign_default_names 共享计数器/make_name_unique 后缀/param category/
typelock 存留/name_dedup/$$undef 序列/mark_unaliased/restructure/spacebase）。
锁定 oracle：`tools/run_varmap_naming_oracle.sh`（VARMAP-NAMING-0001，六 case 投影 MATCH）、
`tools/run_scope_fake_input_symbols_oracle.sh`（VARMAP-FAKEINPUT-0001，八 case 全观察点 MATCH：
paramrange 首字节过滤/重叠吸收+standalone 对照/相邻不合并/跨 space 断裂/typelock 整组跳过/
lockedinputs breaker 与 leader-only 双向/翻转栈 max 边界回绕异常经 warningHeader 继续）。

### 2026-06-27（会话3 续）：MapState::hint_count（诊断）

- `MapState::hint_count() -> usize` — 诊断辅助：返回已收集的 RangeHint 数量。用于核实 gather_spacebase 的实际产出（发现多数函数返回 0，定位 G3 阻塞根因）。

### 2026-06-27（会话3 G3 深水区诊断）：uVar 碎片根因实证定位

通过 `examples/diag_stack.rs` 实证诊断 curl 函数的 P-code，确认 uVar 碎片的**两个根因**：

**根因 A：def 链断链（主要）**
`inject_raw_ops` 为每个 op 的 input 创建**全新的** varnode（`create_with_space`），而非复用产出该地址的 op 的 output varnode。例如 myprogress 的 `STORE@0x34f0` 地址是 `INT_ADD(COPY(INT_SUB(RSP,0x258)), 0x248)`，但 STORE 的 input varnode 是新对象（`Unique:0x1018`），其 def=None——与产出它的 INT_ADD 的 output 是不同 Arc。

`resolve_rsp_offset` 已正确处理 COPY/INT_ADD/INT_SUB 递归，但因 def 链断裂，递归到 def=None 就终止。

**根因 B：参数指针基址（次要）**
my_fwrite 的 `LOAD@0x3475` 是 `INT_ADD(param_4=Register:0x8, 8)`——参数指针解引用，正确地**不应**被当作栈访问。这类"碎片"其实是参数访问。

**为何不能简单复用 varnode**：尝试在 inject 里 `find_by_loc` 复用同 (size,offset) 的 varnode，导致 7 个 SSA 测试失败——Rugra 的 SSA 基于 Arc identity 区分定义点，合并对象破坏了 SSA 语义。正确方案需重新设计 def 链建立（heritage 后统一），非 inject 时合并。

**剩余工作**：重新设计 inject/heritage 的 def 链建立，使 LOAD/STORE 的地址 varnode 能追溯到产出它的 op（保留 SSA 独立性的同时建立 use-def）。这是 G3 的核心阻塞。

诊断工具 `examples/diag_stack.rs` 保留，可打印任意函数的 LOAD/STORE def 链 + scope symbol 数。

### 2026-06-27（会话3 G3 续2）：resolve_rsp_offset_via_bank 重新启用 — spacebase 解析恢复

- `resolve_rsp_offset_via_bank(addr, fd)` — 只读空间回查：当 addr varnode 的 def 链断裂（inject 创建独立 def-less 输入 varnode），在 vbank 中查找同 (space, offset) 且有 def 的 varnode，通过它解析到 RSP 派生偏移。**不修改任何 varnode**（保持 SSA identity），作用域仅限 varmap 的 gather_spacebase。

**关键决策**：此前全局 def-linking（inject Phase 4）虽正确解析栈符号（helpf 10 个），但扰动 typeop 推断（struct 指针类型泄漏到 switch/算术上下文）。via_bank 只读法**不扰动 typeop/copyprop**，避免回归。

**验证效果**：helpf 的栈符号解析 StackX 使用 5→9（scope 10 符号中 9 个被引用）。配合 printc scope 声明增强（声明所有 scope 符号），输出 24/24 + 29/29 全绿。

**uVar 碎片**：spacebase 修复的是*栈变量*恢复，而 uVar_N 是 SSA 中间临时碎片（main 69 个），属 printc 表达式内联问题（独立子系统）。

### 2026-06-29：ScopeLocal::mark_not_mapped + has_overlap
- `mark_not_mapped(offset, size, parameter)` — 忠实移植 Ghidra `ScopeLocal::markNotMapped`（varmap.cc:510-546）。从符号列表移除与范围重叠的符号。用于 ActionRestrictLocal 防止特定栈位置（保存的寄存器、调用参数）被当作局部变量。
- `has_overlap(offset, size)` — 检查范围是否与任何符号重叠。

### 2026-07-01：query_by_addr
- `ScopeLocal::query_by_addr(offset, size) -> Option<(&LocalSymbol, i32)>` — 查栈范围匹配符号，返回符号+偏移（partial read）。
<!-- annotation-pass: 2026-07-04 -->
 

### 2026-08-16：`Funcdata::linkSymbol` 忠实化（`FUNCDATA-LINKSYMBOL-TYPED-0001`）

`LocalSymbol` 增补 `space`/`is_dynamic`/`hash` 字段：linkSymbol 建立的
register/unique/ram 空间符号与 restructureVarnode 的栈符号共用
`ScopeLocal::symbols`，`find_symbol` 及 funcdata.rs 各扫描改为按空间过滤。
`ScopeLocal::add_symbol` 携带空间参数（Ghidra addSymbol 的 Address 语义）；
新增 `add_dynamic_symbol`（database.cc:1690-1701）与 `query_properties`
（database.cc:1263-1281：最小包含 + use-limit 判定，动态项不可按址查询）。
`buildDefaultName` 无 vn 路径改用符号自身空间；vn 路径的
`HighVariable::isInput` 读取前先 `update_flags()`（variable.hh:200 的惰性
updateFlags 语义）。

## ScopeInternal 查询层 r2（SCOPELOCAL-QUERY-0001，2026-08-23）

r1 复核 REJECT 的逐项关闭：查询层从「符号级 Vec+min_by_key」重构为
**条目级 rangemap 委托**（复用 RANGEMAP-COMMON-REFINEMENT-0001 已对拍的
`src/rangemap.rs`），遍历序/subsort tie-break/等价键插入序由该组件的 43/43
oracle 证据承担：

- `EntrySubsort`（database.hh:107-134）——`(useindex, useoffset)` 全序，
  `minimum()/maximum()` 对应 `EntrySubsort(false)/(true)`；`ghidra_space_index`
  按锁定 x86-64 oracle 实测（const=0、unique=2、ram=3、stack=8，
  fixture setup 记录双端核对）。
- `LocalMapEntry`（database.hh:75 SymbolEntry）——一条静态映射
  `{sym, space, start, size, offset, extraflags, uselimit, subsort}`；
  `uselimit` 为 `(space index, first, last)` 区间表（空=全程有效=符号
  addrtied，database.cc:1149-1150 的符号级标志由任一空 uselimit 条目置位）；
  `offset>0` 表达 partial piece（join 拆片，database.cc:1156-1177）。
  `ScopeLocal::mapentry_log` 为插入序条目日志（maptable 数据源），
  `materialize_maptable` 每查询按序重放成 `RangeMap`（`ScopeLocal: Clone`
  无法持有非 Clone 的 RangeMap；等价键插入序与 erase 后幸存者相对序由
  重放保真，fixture 的 removal 案例覆盖）。
- `add_map_entry`（database.cc:1843 addMapInternal）——条目安装（无属性折入
  的生产形态，`property` 恒 0——Database 未接线，DB-LOCALSCOPE-MAP-0001）：
  委托 `add_map_entry_with_property`。
- `add_map_entry_with_property`（database.cc:1843 + addMap 折入
  database.cc:1149-1153）——空 uselimit 置符号 addrtied **并**把
  `property(space, start)`（`glb->symboltab->getProperty(entry.addr)` 的
  flagbase 查询）OR 进 `LocalSymbol::property_flags`（符号级，一次性，
  装图时折入；后装属性区间不污染已装符号——victim 构造序）；uselimit 按
  `(index,first)` 排序并合并相邻（address.cc RangeList 语义）、subsort 在
  插入时冻结（rangemap.hh:238，属性位不入 getSubsort，database.cc:98-106）。
- `install_symbol`——fixture/测试构造路径（addSymbol+addMapPoint 单条目镜像；
  动态符号不装静态条目；零属性闭包）。`add_symbol` 生产路径现在同步建条目。
- `install_symbol_with_property` / `install_symbol_addmap`（database.cc:1530 +
  1126-1155）——完整 addMap 规则集：全局 scope 置 `LocalSymbol::persist`
  （database.cc:1131-1132）；`addmap` 形态另带全局发现域闭包
  （`glbScope->inScope`，database.cc:1138）——命中置 persist **并清 uselimit**
  （database.cc:1140），清空后的 uselimit 进入 addrtied+折入分支
  （db_localscope_map_1204 的 fold_discovery 决定性案例）；空 uselimit 折入
  property_flags。`entry_all_flags` 把 persist/property_flags 投影进
  getAllFlags（database.hh:271）。
- `find_overlap`/`find_overlap_entry`（database.cc:2392）——直接委托
  `RangeMap::find_overlap`：`(last,subsort)` 最左相交分区单元的 owner。
  oracle 实测怪癖：等值等 subsort 的二次插入会以 hinted+tail 双 part
  「包夹」首条（rangemap.hh:223-277 的 break-不更新-f 路径），双向遍历都
  答**后插入者**——Rust rangemap 同构复现，fixture equal_subsort 双案覆盖。
- `find_addr`/`find_addr_entry`（database.cc:2224）——
  `find_with_subsort(point, min, EntrySubsort(usepoint))` 窗口的 `.rev()`
  反向走：精确起点 + `entry_in_use`（database.cc:114：addrtied 全程有效，
  否则 uselimit 区间**包含**判定 + 空间维——跨空间 uselimit 区间不匹配
  代码空间 usepoint）。
- `find_container_entry`（database.cc:2250）——反向走 + 严格更小者替换 +
  精确尺寸短路（oldsize 只在 inUse 通过后更新）。
- `query_properties_ex`（database.cc:1263 + 943 stackContainer + 3185
  mapScope）——完整三分支 flags：`getAllFlags`（extraflags|符号
  addrtied/typelock/namelock/global-persist，database.hh:271）、scope-only
  `mapped|addrtied(|persist)|property(addr)`、property-only；parent 以
  `Option<&ScopeLocal>`（`is_global_scope=true`）建模全局 scope 链；
  常量空间短路（database.cc:950）。`query_properties` 旧签名保持
  （linkSymbol 投影，parent=None/property=0 的生产残差）。
- `has_overlap_in(space, offset, size)`——queryProperties 无效 usepoint 探针
  的空间维形式；`has_overlap(offset,size)` 保持无空间签名（funcdata.rs
  mapGlobals 冻结调用面的兼容 shim，遍历日志中出现过的空间）。
- `remove_symbol` 改 pub（database.hh:601 公共入口）并维护条目日志
  （retain+重键）。`in_scope`（database.hh:597 rangetree.inRange 全包含）。

验证：varmap:: 43/43 单测绿；`tests/oracle/scopelocal_query_1204` 27 记录
（equal-subsort 双向、wide/narrow 双序、多 uselimit 二区间/间隙、跨空间
存储、多映射+删除重查、findContainer 最小/等值 tie、partial offset 拆片、
queryProperties 三分支+parent+常量、markNotMapped 窗口分裂）双侧逐字节
MATCH。残差：multiEntrySet/wholeCount 迭代无查询可观察（未建模）、
addMap 属性折入符号 flags（database.cc:1153）与 Database flagbase 归
DB-LOCALSCOPE-MAP-0001、生产 mapGlobals/linkSymbol 消费者不线程 parent/空间
归 funcdata 轮（r1 REJECT 第 4 项）。


## 动态符号化投影锁定（VARMAP-DYNAMICSYM-0001，2026-08-23）

`PRINTC-UNLINKED-REF-0001` 的 varmap 域残差（explicit 未符号化 high 走
buildDynamicSymbol）以 `tests/oracle/varmap_dynamicsym_1204` 三件套 +
`tools/run_varmap_dynamicsym_oracle.sh` 锁定（pin-base schema2，base
e9baabd，无源码 overlay——基线链路已忠实，fixture 是 B2 证据而非修复）：

- **explicit 冲突 → 动态符号**（`explicit_conflict_dynamic`）：同存储、同
  指令地址定义的两个 explicit high——第二个 `linkSymbol` 的
  `queryProperties` 命中首符号的单点 uselimit，`handleSymbolConflict`
  在 loc-set 走查中发现异 high，`buildDynamicSymbol`（funcdata_varnode.cc:
  1283-1306）经 `DynamicHash::uniqueHash` 建动态 Symbol（database.cc:1690
  `addDynamicSymbol`：$$undef 名 + 哈希映射 + 单地址 uselimit），namerec →
  `buildDefaultName` vn 路径 → `ScopeInternal::buildVariableName` 局部分支
  共享计数器命名（iVar3/uVar4）→ `renameSymbol`。12/12 记录双侧逐字节
  MATCH。
- **uselimit 门**（`separate_usepoints_two_statics`）：同存储不同 usepoint
  → 两个静态符号，动态路径不触发。
- **implied 拒绝**（`implied_conflict_rejected`）：implied 成员在
  `hasName`（variable.cc:729-733）处被拒，linkSymbol 不运行——implied
  语义零改动（与 varmap_unlinked_locals 基线一致）。
- **input/addrtied 附着**（`illegal_input_attach`/`addrtied_attach_conflict`）：
  handleSymbolConflict 的 isInput/isAddrTied 腿（cc:1000-1003）附着既有
  条目，不建动态符号；栈分支经 cspec localrange 窗口命名 iStack_c0。
- **spacebase 拒绝**（`spacebase_input_rejected`）：unaffected+spacebase
  输入在 cc:737-745 被拒。

**E2E 残差归因（fixture 排除 varmap 域缺口）**：curl 6 函数的
`uVar_<unique偏移>` GLUE 兜底名（printc 注入组）不是 varmap 缺路径——
explicit 代表所在 high 混入 implied 实例（如 my_get_token unique+0x23b00：
15 实例含 3 implied），`hasName` 在 linkSymbol 之前拒绝。oracle 序
markimplied(:5720) < mergetype(:5727) 在 Rugra 注册正确，但
`ActionMergeRequired`/mergeOp 把同槽实例强并入一个 high 后，Rugra 的
`check_implied_cover` 近似（静态聚合 cover）标出 mixed 而 Ghidra 的
inflateTest cover 模型对已合并 high 整体判 explicit（Ghidra 中 mixed 态
不可达——hasName 会 throw "Implied varnode has been merged"）。修复归
merge/cover 域（`MERGE-MIXEDHIGH-0001`：merge.rs `inflate_test` /
coreaction.rs `check_implied_cover`）。另有 `DYNAMICSYM-PROD-0001`
（ActionDynamicSymbols stub：attemptDynamicMappingLate 未接）、
`DYNAMICSYM-EQUATE-0001`（常量 equate 腿经 ActionNameVars 投影不可达）、
`VNCREATE-PROPS-0001`（newVarnode 的 setVarnodeProperties scope-ownership
查询：Rugra set_varnode_properties 查 flat symbol_table 而非
ScopeLocal::queryProperties，创建期 mapped 位与 oracle 不同）。

## 引用行号勘误（2026-08-24，root，getstr 复核必改项）

survivor-clear 注释引用 varmap.cc:1273 修正为 1259（`clearUnlockedCategory(-1)` 实际位置；1275 是 function_parameter 的另一调用）。
