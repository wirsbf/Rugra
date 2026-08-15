# `varmap.rs` API Reference

**状态**: 骨架已实现（L2），集成待完成
**源代码路径**: `src/varmap.rs`

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
- `merge_with(&mut self, b)` — `RangeHint::merge` (varmap.cc:259)，三态 resType（0/1/2）
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
- `pub aliases: Vec<u64>` — 排序的别名偏移（varmap.cc `alias`）
- `pub add_base: Vec<AddBase>` — 加法基根（base + index）
- `direction: i32` — 方向：`1`=负向增长(x86)，`-1`=正向增长（与 Ghidra `AliasChecker::direction` 同号）
- `gather_internal(&mut self, fd)` — `AliasChecker::gatherInternal` (varmap.cc:660)
- `gather_additive_base(&mut self, startvn)` — `AliasChecker::gatherAdditiveBase` (varmap.cc:741)，递归 BFS 追踪 INT_ADD/INT_SUB/PTRADD/PTRSUB/SEGMENTOP/COPY 后继
- `has_local_alias(&self, vn)` — `AliasChecker::hasLocalAlias` (varmap.cc:711)；`direction==-1`（正向增长）时返回 false
- `derive_boundaries(&mut self, local_boundary)` — `AliasChecker::deriveBoundaries`

辅助函数：
- `pub fn gather_offset(vn)` — `AliasChecker::gatherOffset` (varmap.cc:817)，递归求和常量偏移（COPY/ADD/SUB/PTRADD/SEGMENTOP），末尾按字节大小掩码；`VARMAP-GATHEROFFSET-0001` 已按 `address.hh:499` 的 `size >= 8` 钳位语义修复 8-byte 边界，并由锁定 12.0.4 的 7/8-byte 直接状态 fixture 验证。该窄分支的 `MATCH` 不提升整个 `AliasChecker` 模块状态。
- `fn find_spacebase_input(fd)` — `Funcdata::findSpacebaseInput`，Rugra 中 RSP = Register@0x20 size8 无 def 的输入 varnode

### `pub struct MapState`
范围提示收集器和重构器。对应 Ghidra MapState。
**2026-06-26 完整对齐**（此前为简化版）：
- `new_with_default(local_start, local_end, default_type)` — 带 getBase(1,TYPE_UNKNOWN) 默认类型
- `add_range(start, dtype, flags, rt, high_ind)` — `MapState::addRange` (varmap.cc:896)，size<=0/越界时丢弃，无类型时回退默认
- `add_fixed_type(start, dtype, flags)` — `MapState::addFixedType` (varmap.cc:926)
- `gather_varnodes(fd)` — `MapState::gatherVarnodes` (varmap.cc:1124)，逐 op-code 分支（INDIRECT/MULTIEQUAL/PIECE/SUBPIECE/COPY/默认），含 same-storage 去重与 `is_read_active`。PIECE 视为两个 COPY（little-endian slot=1，addr+=inFirst.size）；SUBPIECE 用 little-endian `trunc = in1.offset`，`addr = in0.off + trunc` 后与 vn 地址比较
- `gather_open(fd, checker)` — `MapState::gatherOpen` (varmap.cc:1211)，对每个 AddBase 根：指针→pointee，数组→base，index 在则 minItems=3
- `is_read_active(vn)` — `MapState::isReadActive` (varmap.cc:1088)，过滤纯 same-storage INDIRECT/MULTIEQUAL
- `initialize()` — `MapState::initialize` (varmap.cc:1063)，加端点 + 排序
- `gather_spacebase(fd)` — **Rugra 专有**：Rugra 的 x86 lift 不产 Stack varnode，故扫描 LOAD/STORE 的地址，若为 RSP 派生（含 frame_base 链 `INT_ADD(INT_SUB(RSP,fs),off)`），则在对应栈偏移合成 fixed RangeHint。对应 Ghidra 的 Stack-spacebase 解析（`ActionSpacebase`）。
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
- `usepoint: Option<u64>` — 首个 SymbolEntry 的 first use address（None = invalid Address；`buildDefaultName` 据此决定 addrtied flag，database.cc:1776）
- `is_name_undefined()` — `Symbol::isNameUndefined`（database.cc:246）：15 字符 `$$undef` 前缀

### `pub struct ScopeLocal`
局部变量作用域。对应 Ghidra ScopeLocal。`#[derive(Debug, Clone)]`（2026-06-26：
Clone 用于 printc 从 `fd.scope` 复用）。
**2026-06-26 完整对齐**：
- `restructure_varnode(fd)` — 主入口：`ScopeLocal::restructureVarnode` (varmap.cc:1256)，编排 gather_varnodes→gather_internal→gather_open→restructure→mark_unaliased→fake_input_symbols
- `restructure(state)` — `ScopeLocal::restructure` (varmap.cc:1294)，相交→merge_with，不相交→attempt_join/adjust_fit/create_entry
- `adjust_fit(a)` — `ScopeLocal::adjustFit` (varmap.cc:587)，typelock/size0 拒绝 + 符号重叠收缩
- `create_entry(hint)` — `ScopeLocal::createEntry` (varmap.cc:617)：空名 addSymbol（$$undef 占位）+ 数组类型包装；命名推迟到 assign_default_names
- `build_variable_name(space, offset, usepoint, ct, index, flags)` — **权威命名覆盖** `ScopeLocal::buildVariableName` (varmap.cc:548)：addrtied 且在 local_range 内走 `<printNameBase>Stack[X|Y]_hex`，否则落到 `build_variable_name_internal`
- `build_variable_name_internal(...)` — `ScopeInternal::buildVariableName` (database.cc:2434)：unaffected/persist/irregular input/param_N/addrtied/extraout/default local 七分支 + 10 次碰撞 bump + makeNameUnique
- `make_name_unique(nm)` — `ScopeInternal::makeNameUnique` (database.cc:2553)：`_NN`(2位)/`_xNNNNN`(5位) 后缀递增
- `find_first_by_name(nm)` / `insert_name_tree(idx)` — `findFirstByName`/`insertNameTree` (database.cc:2733/2712)：SymbolNameTree (name, nameDedup) BTreeMap 模拟
- `rename_symbol(idx, newname)` — `ScopeInternal::renameSymbol` (database.cc:2152)：erase→改名+display→reinsert
- `build_undefined_name()` — `ScopeInternal::buildUndefinedName` (database.cc:2520)：`$$undefXXXXXXXX` 递增序列
- `add_symbol(nm, ct, start, usepoint)` — `Scope::addSymbol`+`addSymbolInternal`+`addMapPoint` (database.cc:1530/1810/1548)
- `build_default_name(idx, base, vn, fd)` — `Scope::buildDefaultName` (database.cc:1756)：entry 路径由 usepoint 推导 flags、function_parameter 用 catindex+1；vn 分支保留（待 ActionNameVars 接入）
- `assign_default_names(base)` — **`ScopeInternal::assignDefaultNames`** (database.cc:2850)：nametree 顺序、共享 `int4 base` 计数器、二次运行幂等
- `set_category(idx, cat, ind)` / `get_category_symbol(cat, ind)` — `ScopeInternal::setCategory`/`getCategorySymbol` (database.cc:2824/2814)
- `symbols_in_nametree_order()` — RUGRA-GLUE：锁定 fixture 的 nametree 顺序只读观察口
- `mark_unaliased(aliases)` — `ScopeLocal::markUnaliased` (varmap.cc:1332)，含 0xffff 距离启发式（alias_block_level 待接入）
- `fake_input_symbols(fd)` — `ScopeLocal::fakeInputSymbols` (varmap.cc:1392)：addSymbol 空名 + setCategory(fake_input, -1)（varmap.cc:1440-1441）
- `find_symbol(offset)` — 按偏移查找重构后的符号

**命名状态字段**（database.hh:809/805, varmap.cc:345-348）：`nametree: BTreeMap<(String,u32),usize>`、
`category_lists`、`local_range: Vec<(first,last)>`（FuncProto localRange 缓存）、`min_param_offset`/
`max_param_offset`（markNotMapped parameter=true 更新，varmap.cc:519-524）、`stack_grows_negative`、
`register_names`（Translate::getRegisterName 表，translate.hh:380 的调用方装填桥）。

## 当前限制

varmap 算法层（RangeHint/AliasChecker/MapState/ScopeLocal）已 1:1 对齐 Ghidra。
尚未完成：
- ~~**集成到 printc.rs**：变量命名仍用启发式 get_stack_variable_name，未走 ScopeLocal 符号查找~~ → 2026-08-15 已完成：printc 消费 `assign_default_names` 建立的权威名（见 printc.md），命名源切换
- alias_block_level 配置（影响 markUnaliased 的 struct/array 阻断）
- LoadGuard/StoreGuard 在 gatherOpen 中的 addGuard 路径（待 LoadGuard 接入 Funcdata 栈空间）
- TYPE_PARTIALSTRUCT/PARTIALUNION 在 addFixedType 的处理（Rugra 无此元类型）
- buildDefaultName 的代表 Varnode 分支（database.cc:1759-1771）已移植但无 fixture 驱动（需活 Funcdata/HighVariable；绑定 ActionNameVars caller 闭包）
- 真实 Translate 寄存器表接入 ScopeLocal::register_names（生产管线 Architecture 桥接待做）
- Symbol::symbolId 分配（database.cc:1813-1816）与 multiEntrySet 维护：Rugra LocalSymbol 单整映射模型暂无对应物

测试：varmap::tests 26 个（compare/contain/reconcile/preferred/merge/absorb/const_absorbable/
build_variable_name×2/assign_default_names 共享计数器/make_name_unique 后缀/param category/
typelock 存留/name_dedup/$$undef 序列/mark_unaliased/restructure/spacebase）。
锁定 oracle：`tools/run_varmap_naming_oracle.sh`（VARMAP-NAMING-0001，六 case 投影 MATCH）。

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
 
