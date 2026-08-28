# `type_system/datatype.rs` API Reference

**2026-08-23 新增**: `Datatype::type_equal`——Ghidra interned TypeFactory 指针比较（如 castOutput 的 `tokenct == outHighType` coreaction.cc:2544）的 Rust 等价：Base 型按 (name,size,metatype) 结构比较，其余形状退回 Arc 同一性。


**源代码路径**: `src/type_system/datatype.rs`
**Ghidra 对应**: `type.hh` / `type.cc` (`Datatype` 类层次)
**状态**: 🔧 **L2 / overall MISMATCH（2026-08-23 residual 矩阵补齐）**——datatype 层的 submeta、公开虚派发 compare/compareDependency、Pointer state/space、PointerRel、TypeCode varargs/model/param/return/dependency、Array/Union/三个 Partial 全矩阵、Struct offset/dependency、Spacebase identity、1-byte Unicode 和全部 24 个 submetatype 值均有 12.0.4 行为证据。历史 TypeFactory 的 6 个差异中，5 个 pointer-factory 字节已由 series B/C 改写但尚无新 oracle；1-byte Unicode 仍为 MISMATCH。当前 pointer space 仍有对象身份表示差异，Pointer XML decode 还会丢弃 `<space>`，TypeCode null-output 边界与 struct 递归环/incomplete 转移仍未测，绑定 `TYPEFACTORY-POINTER-CANONICAL-0001` / `TYPEFACTORY-SUBMETA-RECLASS-0001` / `DATATYPE-TYPEORDER-RESIDUAL-0001`，不能升 L3。

## 模块说明

Rugra 的数据类型系统，对应 Ghidra 的 `Datatype` 类层次
（`TypeBase`/`TypePointer`/`TypeArray`/`TypeStruct`/`TypeUnion`/`TypeEnum`/`TypeCode`/`TypeSpacebase`）。
采用 `enum Datatype` + 携带各自 `TypeBase` 的变体表示。

## 2026-08-11 ANN-J annotation bootstrap

This pass classified eighteen previously unanchored helpers without changing
behavior:

- The `elem::{element,attribute,type_,typeref,field,void_,val,def,off,
  prototype}` helpers and `TypeXmlIdMap::{new,id_for_element,
  id_for_attribute}` are `RUGRA-GLUE`. Ghidra declares fixed global
  `AttributeId`/`ElementId` objects and registers them during static
  initialization; it has no per-thread sequential allocator. Numeric ids are
  observable in the packed protocol, so the glue is not codec `MATCH`.
- `address_to_byte_int` and `byte_to_address_int` are anchored to
  `space.hh:532/541`; they are source mappings only and still depend on
  Rugra's incomplete address-space metadata.
- `covering_mask` is anchored to `address.cc:800 coveringmask`; a locked
  runtime boundary fixture, including the high-bit case, is still absent.
- `cmp_u64` is Rust glue extracted from repeated inline id comparisons in the
  concrete Ghidra `compare` methods; there is no standalone C++ function.
- `TypeSpacebase::is_invalid` is Rust glue extracted from direct
  `localframe.isInvalid()` calls. R2 now delegates to `Address::is_invalid`,
  so a spaceless nonzero address is invalid and a space-tagged zero address is valid.

At the time of that annotation-only pass, these markers provided provenance
without raising the module above L2, and the formal status remained
`NO_ORACLE`. The 2026-08-21 R3 fixture now supersedes that historical status
for its covered projection; the module remains L2 with overall `MISMATCH` and
explicit `UNTESTED` residuals as stated above.

## 2026-08-15 TYPEFACTORY-UNDEFNAME-0001（命名下游影响）

`Datatype::print_name_base`（`type.hh:273` 基类 `printNameBase`、`:424`
TypePointer、`:457` TypeArray 的枚举派发移植）本身与具体类型名无关——它取
名字首字符，因此**无行为改动**。本 TODO 改的是其输入：TypeFactory 核心未知
类型由 `xunknown1/2/4/8` 更名为数据组织命名 `undefined1/2/4/8`
（ghidra_arch.cc:349-352），于是 `print_name_base` 对未知类型输出 `'u'`，
`Scope::build_variable_name`（database.cc:2434）产出的本地变量前缀家族从
`xVar`/`axVar`/`pxVar` 变为 golden 的 `uVar`/`auVar`/`puVar`。Ghidra 侧同理：
standalone SLEIGH 架构（sleigh_arch.cc:229 的 `xunknown*`）产出 `xVar` 家族，
headless/数据组织路径产出 `uVar` 家族；Rugra 选择对齐后者（E2E 差分门禁目标）。
见 `typefactory.md` 2026-08-15 节。

## 2026-06-26 新增原语（解锁 varmap.cc 移植）

以下方法对应 Ghidra `type.cc` 中的算法，是 `varmap.cc` 的
`RangeHint::reconcile` / `attemptJoin` / `preferred` 所必需的：
此前缺失，导致 varmap 骨架被迫简化。

### `pub fn get_alignment(&self) -> usize`
对应 `Datatype::getAlignment` (type.hh:241)。`TypeBase` 独立保存
`alignment`；factory 插入、decode 以及 struct/union 定义路径均写入该字段。
仅旧的、未经过 factory 的直接构造器使用默认 alignment map 兼容回退：
`{0:1, 1:1, 2:2, 3:2, 4:4, 5:4, 6:4, 7:4, 8+:8}`。
这里 alignment map 的 size-3 槽虽然是 2，完整 fallback 会先把宽度填充到
4，再查询 aligned-size 4 的 alignment，因此最终是
`alignment=4, alignSize=4`；不能把原始 size 槽的值误当作最终 alignment。

### `pub fn get_align_size(&self) -> usize`
对应 `Datatype::getAlignSize` (type.hh:240)。`TypeBase` 独立保存
`alignSize`；primitive `findAdd` 按 `getPrimitiveAlignSize(size)` 写入，
struct/union 定义按 `calcAlignSize(size, alignment)` 写入，array decode
保留总宽度。旧的直接构造器仍以 `calc_align_size(size, alignment)` 回退。

### 2026-08-24：TypeBase layout / display-name 生命周期（series A）

`TypeBase` 新增独立的 `display_name`、`alignment` 与 `align_size`，对应
Ghidra `Datatype` 基类字段。`decodeBasic` 读取 `label`/`alignment`，缺省
display name 回退到 lookup name；struct/union encoder 输出真实 alignment。
`TypeCode::new` 对应 `Datatype(1,1,TYPE_CODE)`：构造和无 alignment 属性的
decode 均保留 `alignment=1`、`alignSize=1`，并从 incomplete 状态开始。
当前 scoped 状态保持 **L2 / MISMATCH**：factory 内部 replacement 会让旧的
`Arc<Datatype>` 句柄与依赖它的 array/pointer/partial/typedef/incomplete/cache
继续看到旧对象，绑定 `TYPEFACTORY-ARC-IDENTITY-0001`。最终 series D 的
锁定 12.0.4 bilateral fixture 才会给这组字段可观察状态；在此之前为
`UNTESTED`，不能升 L3。

### 2026-08-24：array/partial stripped 状态（series B）

`Datatype::get_stripped_arc` 是 Rust 所有权胶水，保留 concrete virtual
`getStripped` 返回对象的 `Arc` 身份。普通 typedef 只有 `typedefImm`，不会因此
获得 stripped 形态；从 PartialStruct/PartialEnum/PartialUnion 克隆出的 typedef
保留 concrete subclass 的 `HAS_STRIPPED` 与 stripped 指针。PointerRel 分支暴露
相同状态；series C 的 TypeFactory ephemeral overload 现在写入 canonical stripped
pointer、parent/offset 与 `SUB_PTRREL_UNK`，其 bilateral 行为证据仍留到 series D。

`TypePartialEnum::new` 现在复现 `TypeEnum(sz, TYPE_PARTIALENUM)` 的两层状态：
stored metatype 是 `TYPE_UINT`，submeta 是 `SUB_UINT_PARTIALENUM`，并保留
`ENUMTYPE|HAS_STRIPPED`。本片 Rust tests 固定这些字段；锁定 oracle 的完整
同输入观察仍在最终 series D fixture 前保持 `NO_ORACLE`。模块整体因已登记
残差保持 **L2 / MISMATCH**，不能把本片的 Rust 回归测试解释为行为对齐证据。

### `pub fn get_sub_type(&self, off: i64) -> (Option<&Datatype>, i64)`
对应 `Datatype::getSubType` (type.hh:247, type.cc:174)。
返回包含 `off` 的一级组件类型及组件内偏移。
- Struct: `TypeStruct::getSubType` (type.cc:1640) 经 `getFieldIter` 的原始
  binary-search midpoint 顺序；重叠/同 offset 字段不会退化为线性“最后命中”。
  `getFieldIter` 的参数是 `int4`，所以 `getSubType(int8)` / `findTruncation(int8)`
  会先按 locked GCC 规则窄化搜索 offset，再用原 int8 offset 计算 `newoff`
- Struct 的 `getHoleSize` 独立调用 `getLowerBoundField`（type.cc:1604/1652），
  用 upper-midpoint 选择 offset 不大于请求值的最后字段；它不复用
  `getFieldIter` 的“字段必须包含 offset”判定，同 offset 重叠字段因而选择最后一项
- Union: locked `TypeUnion` 没有 override（type.hh:554 注释掉声明），所以
  走基类并返回 `(None, 原 off)`；`getExactPiece` 在下钻前单独处理 union
- Array: `TypeArray::getSubType` (type.cc:1234)，直接读取元素对象存储的
  `alignSize`，`newoff = off % elem.alignSize`；不会调用 legacy constructor
  的 layout fallback
- PartialStruct: 保持 `do/while` 覆盖语义；较深一层失败会把先前成功结果覆盖为 null
- 其他: 返回 `(None, off)`。Pointer truncate、带 factory 的 TypeCode，以及
  Spacebase 的 unknown1 回退仍是已登记 residual。

`Datatype::get_sub_type_arc` 是 Rust 所有权胶水：它在 Struct、Array 与
PartialStruct 的 covered projection 中保留 canonical `Arc`，供
`TypeFactory::get_exact_piece` 使用。Spacebase 的 borrowed API 无法借出 scope-owned
symbol type，而 Arc helper 会走 Rugra 当前的 symbol lookup，因此两路并非完整同输出。
Pointer truncate、TypeCode factory attachment，以及 Spacebase 的 byte/address-unit
换算、`resolveConstant`、scope query 与 miss→unknown1 均未完整表示，整体继续绑定
`TYPE-0001`、`DATATYPE-SPACEBASE-SPACEID-0001`、`ARCH-0001`、`ADDRESS-0001`、
`DATABASE-0001`，状态为 MISMATCH/UNTESTED。

### `pub fn get_hole_size(&self, off: i64) -> i64`
对应 `Datatype::getHoleSize`（type.hh:256 基类返回 **0**——标量/未覆写类型无 hole）。
- Struct: 距下一字段或结构末尾的距离 (type.cc:1652-1663)；委托进标量字段 → 基类 0。
- Array: 委托元素 `off % elemAlignSize`（type.cc:1243-1247）。
- PartialStruct: 容器委托 + 剩余尺寸 clamp（type.cc:2379-2385）。
- **2026-08-25（R15 M-1 修正）**：基类 fallback 由 `size-off` 改为 0——旧值把
  TypeStruct 尾部规则（type.cc:1663）错误下放到所有非组合类型，被
  `SplitDatatype::get_component` 消费后在 both-composite 标量降取/标量字段内部
  偏移路径 false-accept（oracle NO_CHANGE → Rust 拆分）。datatype.rs 内
  overlap 测试断言已按 oracle 重钉（委托进 int4 字段 → 0）。

### `pub fn type_order(&self, other: &Datatype) -> i32`
对应 `Datatype::typeOrder` (type.hh:283) = `compare(other, 10)`。
先比独立的 submeta（不是 Rust `TypeMetatype` discriminant），再比 size（大者优先，返回
`op.size - size`），随后按具体派生类的虚函数规则递归；递归层级耗尽才比较 id。
varmap `RangeHint::preferred` 用其选择更具体的类型。

### `pub fn type_order_bool(&self, other: &Datatype) -> i32`
对应 `Datatype::typeOrderBool` (type.hh:916)：bool 永不被优先。

## 2026-08-20：DATATYPE-TYPEORDER-0001

旧实现直接比较 Rugra 私有 enum 序（`Unknown=0`），把 UNKNOWN 错排在
PTR/INT/UINT 前；同时浅 compare 错把名字当 tie-break、同 metatype 尺寸方向也反了。
本轮按锁定 `type.cc/.hh` 恢复：

- `SubMetatype` 以 `#[repr(i32)]` 完整镜像 Ghidra `sub_metatype` 的 0..23
  数值与特异性顺序；`get_submeta()` 返回该类型，避免再把 Rugra 私有
  `TypeMetatype` discriminant 当传播次序。
- `get_submeta()` 映射 `Datatype::base2sub`，并覆盖 INT/UINT 的 enum、char、unicode
  特化以及 `TypePointer::calcSubmeta` 的 incomplete/multi-field struct、union 和
  relative-pointer 分支。
- `type_order()` 保留同对象 identity 快路，然后以 level=10 进入派生 compare；Pointer、
  Array、Struct、Union、Enum、Code、Spacebase 和三个 Partial 变体均走现有 API 的虚派发
  闭包。
- R2 修正公开 API：`Datatype::compare()` 与 `compare_dependency()` 本身执行 enum 虚派发；
  `compare_at_level()` 只承载显式递归深度，旧 `compare_deep()` 降为兼容别名。fixture
  通过 `Datatype&` / `&Datatype` 基类入口钉住 Pointer 派生判别。
- base compare 只看 submeta 与反向 size 差，绝不比较名称；Struct/Union 的第一层字段
  metatype tie-break 使用 Ghidra `type_metatype` 数值，不使用 Rust discriminant。
- 深递归在 `level-1 < 0` 时按 id 决胜；dependency compare 对组件采用 `Arc` 对象身份，
  fixture 只观察相等/非零和反对称性，不跨进程比较原始地址。
- `TypePointer::{new,new_with_space,new_relative,mark_ephemeral,calc_submeta}` 写入
  pointer-to-array、needs-resolution、core inheritance、space、parent/offset/stripped 和
  SUB_PTRREL_UNK 状态；PointerRel 普通 compare 比 stripped，dependency compare 比
  ptrto/offset/parent/wordsize/size。
  `PointerRelState` 逻辑上对应 Ghidra 派生类字段；为兼容仓库既有 `TypePointer` struct
  literal，Rust 将该可选状态随 `TypeBase` 克隆保存，而不是继续依赖 TypeFactory 的名称侧表。
- `TypeCode::compare_basic` 直接调用 `FuncProto::{has_model,get_comparable_flags}`；真实
  decoded `hasthis` ProtoModel 与 constructor/destructor 三类 flag 均已双侧覆盖；has-this
  判别两侧使用同名 `fixture_same` model，并显式输出 model-name 相等，确保此前所有键相同
  后才落到 comparable flags。
- Spacebase 改用 space identity 和 `Address::is_invalid()`；`TypeBase::new_unicode` 用
  submeta override 保证 1-byte Unicode 仍为 `SUB_INT_UNICODE`，不会退化为 char。

真 oracle 证据为 `tests/oracle/datatype_type_order_1204.{cc,rs,metadata.json}` 与
`tools/run_datatype_type_order_oracle.sh`：182 条固定记录中 datatype 投影 174 MATCH、
8 MISMATCH（6 个 TypeFactory 接线 + 2 个 same-kind space 表示差异）；oracle/Rugra stdout
SHA-256 分别为
`4bc6b452023ac5c7a6b3e9ff3038c5c848ef222f1f5ffa856aedb545659ad1e5` /
`85775338934840a3e7f6265a10e6fd1d34af0fd49d0a267b0363ad262d9c3cdd`。fixture 使用
x86:LE:64:default/gcc、固定 curl/spec Git 输入和隔离 Rugra 基线 overlay。

2026-08-23 residual 矩阵补齐（零未解释差异，`datatype.rs` 本轮无需改动）：

- **TypeCode**：varargs（dotdotdot comparable flag）、0/1 参数计数、参数类型递归、
  返回类型递归、不同 model 名、level-0 id 决胜、以及 dependency 的参数/输出指针身份
  （深度相等但对象不同时 deep=0、dependency 非零且反对称）全部 MATCH。参数经由真实
  `FuncProto::updateAllTypes`（fspec.cc:3735）+ `assignParameterStorage` 写入。
- **Array/Union/Partial**：元素/字段/容器/父类型递归、offset 决胜、level-0 id cutoff、
  dependency 的元素身份与 size tiebreak 全部 MATCH。
- **Struct**：等 size 下 field offset 决胜、指针字段穿过第一层 metatype tie 的深递归、
  dependency field-offset 与不同 field-type 对象身份全部 MATCH。
- **same-kind AddrSpace**：Ghidra 用裸 `AddrSpace*` 指针身份，Rust 用 `AddressSpace`
  enum。两个 IPTR_PROCESSOR 空间不同 index 时双侧非零且反对称（MATCH）；但 Ghidra 中
  共享 index 的两个**不同对象**（fixture 裸构造，真实 AddrSpaceManager 不会产生该状态）
  仍非零，Rust enum 折叠为相等；`TypePointer::compare` 对同 index 空间恒返回 1 的
  Ghidra quirk（type.cc:944，索引相等时三元表达式取 `1` 分支）在 Rust 落入 pointee
  递归——两条登记为 MISMATCH，绑定 `DATATYPE-TYPEORDER-RESIDUAL-0001`。
- **24 个 submetatype**：全部 24 个 `sub_metatype` 值双侧构造并打印、23 个相邻对
  order 全部 `+1`、全部 276 对 total-order violation 计数为 0（MATCH）。无公开构造器
  的 `SUB_UINT_CHAR` 由 `ProbeChar` 复刻 `TypeChar::decode`（type.cc:818）的 submeta
  写入；`SUB_PTRREL_UNK` 由 `ProbeRel` 暴露 protected `markEphemeral` 构造。

旧 `datatype_type_order_1204` 证据中的 5 个 pointer-factory 差异（普通 pointer
误置 `IS_PTRREL`、ephemeral state、`SUB_PTRREL_UNK`、pointer-to-array、coretype
继承）已由 series B/C 的 constructor + canonical factory 闭包改写；因此旧 fixture
只能保留为历史证据，不能证明当前 pointer 字节 MATCH。factory 1-byte Unicode
仍退化成 SUB_INT_PLAIN(17)，绑定 `TYPEFACTORY-SUBMETA-RECLASS-0001`；pointer
新投影在 series D bilateral fixture 前保持 `NO_ORACLE`。模块整体仍为 MISMATCH/L2。
metadata 为 schema 2，逐项 coverage 使用结构化 `status/covers/residual_todo_ids`；TypeCode
null-output 边界（`ProtoStoreInternal` 总是初始化输出槽，公开构造不可达，fspec.cc:3306）
与 struct 递归环/incomplete 转移保持 `UNTESTED`，绑定 `DATATYPE-TYPEORDER-RESIDUAL-0001`。

### `pub fn calc_align_size(sz, align) -> usize`
对应 `Datatype::calcAlignSize` (type.cc:536)。

### `pub fn primitive_alignment(size) -> usize`
对应 `TypeFactory::setDefaultAlignmentMap` (type.cc:4649)。

## 测试

`type_system::datatype::tests` 当前 60 个测试覆盖上述原语；series D 新增
struct overlap 的 midpoint/lower-bound 分流、int8→int4 搜索窄化、raw array
stored-alignSize、Union base dispatch 与 PartialStruct 深层成功/失败边界。

### 2026-07-01：is_char_print / is_piece_structured（解锁 RulePtrsubCharConstant/RulePieceStructure/Rule2Comp2Sub）
- `is_char_print()`（type.hh:218）— 检查 CHARTYPE|UTF16|UTF32|OPAQUE_STRUCT flag。
- `is_piece_structured()`（type.hh:929-935）— Struct|Union|Array 语义判断（Ghidra 用 metatype<=TYPE_ARRAY，Rugra 枚举值不同故用 matches!）。

### 2026-08-18：TYPEUNION-CACHE-READSIDE-0001——find_truncation (op,slot) 参数化 + Union 臂解析缓存读侧接线
- `find_truncation(off, sz, op, slot, resolutions) -> Option<(TypeField, newoff)>`（type.cc:160 base / :1624 TypeStruct / :2185 TypeUnion / :2440 TypePartialUnion）——签名扩展为 Ghidra 虚函数的参数形态（`op`/`slot` + 缓存通道）：
  - **Struct 臂**不变（Ghidra override 忽略 op/slot）。
  - **Union 臂**（type.cc:2185-2199）落地真正的读侧："No new scoring is done"——只读查询 (parent=this, op, slot) 的 ResolvedUnion 缓存（`fd->getUnionField`，funcdata.cc:917），miss 或 `field_num < 0` → None（**不写缓存**，区别于 resolveTruncation 的打分+写入）；命中时 `newoff = off - field.offset`，跨字段（`newoff + sz > field.type_ptr.get_size()`，严格 `>`）→ None。通道为 `Option<&UnionResolveMap>`（新公开类型别名 = `BTreeMap<ResolveEdge, ResolvedUnion>`，即 `Funcdata::union_map` 的快照视图）；`op=None` 或 `resolutions=None` 等价缓存 miss（无 op 语境兼容）。
  - **PartialUnion 臂**（type.cc:2440-2444）委托 `container.find_truncation(off + offset, sz, op, slot, resolutions)`——同一 (op,slot) 透传，**容器成为缓存键的 parent**（与 Ghidra 委托语义一致；Ghidra ResolveEdge 构造器的 TYPE_PARTIALUNION 臂 unionresolve.cc:74-75 同样按容器 id 键控）。
- 真 oracle 证据：fixture `printc_subpiece_fieldextract_1204` 新增 5 条 union 记录（armB.unionhit=U.b / armA.unionhit=V.b / armA.unionmiss=W / armA.unionspan=X / armA.unionsynth=Z._0_2_），经真 `Funcdata::setUnionField`（funcdata.cc:937）写侧注入、12.0.4 oracle 逐字节 MATCH（31 records）。
- 新增单元测试 `test_find_truncation_union_cache`（miss/负 fieldNum/命中/跨 slot/跨字段/PartialUnion 委托含非零偏移）。

### 2026-08-17：PRINTC-SUBPIECE-FIELDEXTRACT-0001 缺口 b/c——is_piece_structured 宽度 + find_truncation/array_get_sub_entry
- `is_piece_structured()` 匹配集扩为 **{Struct, Union, Array, PartialStruct, PartialUnion}**（Ghidra `metatype <= TYPE_ARRAY` 按**存储** metatype 的实际可达集合）。两个被真 oracle 纠正的细节：Ghidra `TypeEnum` 构造器（type.hh:489-494）把存储 metatype 归一为 TYPE_INT/TYPE_UINT，且 `TypePartialEnum`（type.cc:2255-2262）经同一构造器落到 TYPE_UINT——故 enum/partialenum **不是** piece-structured（fixture `piece.enum=0`/`piece.partialenum=0` 由 12.0.4 oracle 实测确认）。
- `find_truncation(off, sz) -> Option<(TypeField, newoff)>`（type.cc:160 base / :1624 TypeStruct / :2185 TypeUnion / :2440 TypePartialUnion）——SUBPIECE 字段抽取的判定原语：Struct 臂经 `struct_get_field_iter`（字段严格包含 off）+ 跨字段拒绝（`noff+sz > size`，type.cc:1634）；Union 臂无 (op,slot) 解析缓存时返回 None（Ghidra TypeUnion::findTruncation 无缓存 ResolvedUnion 同样返回 null）；PartialUnion 臂委托 `container.find_truncation(off + offset, sz)`。
- `array_get_sub_entry(off, sz) -> Option<(Arc<Datatype>, newoff, el)>`（type.cc:1257 TypeArray::getSubEntry）——元素步长为 **getAlignSize()**（对齐尺寸），跨元素（`noff+sz > align`）返回 None。
- 新增 3 个单元测试（宽度 sweep / struct findTruncation 边界 / array getSubEntry 对齐步长与跨元素）。

### 2026-07-01（续）：needs_resolution/find_resolve/is_enum_type/get_stripped/equate + type_flags 对齐
- needs_resolution()（type.hh:231）、find_resolve()（type.cc:586）、is_enum_type()（type.hh:219）、has_stripped()（type.hh:229）。
- mark_equate/mark_un_equate/is_equated（Rugra 私有 EQUATED 位，Ghidra 对应 EquateSymbol）。
- type_flags 补齐 CHARTYPE/ENUMTYPE/UTF16/UTF32/HAS_STRIPPED/IS_PTRREL/TYPE_INCOMPLETE/NEEDS_RESOLUTION。

## 2026-07-22 新增 P0：TypePartialStruct / TypePartialEnum / TypePartialUnion + TypeSpacebase 结构补齐（非完整对齐）

部分填补 `docs/alignment_audit/type_audit.md` 指出的 P0 缺口：三个 partial 子类此前完全缺失
（被 `varmap.cc`/`printc.cc`/`ruleaction.cc` 大量使用），且 `TypeSpacebase::getMap/getSubType/getAddress`
（栈帧/全局变量类型传播）未实现。本次按 `type.cc` 行号逐一忠实移植。

### 新增 TypeMetatype 变体
- `PartialStruct = 13`、`PartialEnum = 14`、`PartialUnion = 15`
（对应 Ghidra `TYPE_PARTIALSTRUCT/TYPE_PARTIALENUM/TYPE_PARTIALUNION`，type.hh:79-98）。

### `struct TypePartialStruct`（type.hh:571-585, type.cc:2330-2420）
表示从一个 struct/array 容器中按字节区间 `[offset, offset+size)` 切出的部分。
- `new(container, offset, size, stripped)`（type.cc:2330）— 断言容器为 Struct|Array，置 `HAS_STRIPPED`。
- `get_component_for_ptr(off, sz)`（type.cc:2382）— 在容器内查找容纳 `[off, off+sz)` 的字段。
- `compare` / `compare_dependency`（type.cc:2405/2415）— 先比 container 指针、再比 offset、再比 size。
- 通过 `partial_struct_get_sub_type` / `partial_struct_get_hole_size`（free 函数）接入
  `Datatype::get_sub_type` / `get_hole_size` 的 match 分派。

### `struct TypePartialEnum`（type.hh:569-587, type.cc:2247-2330）
表示枚举值的高/低字节切片：解析前将值左移 `8*offset` 位再委托给父枚举。
- `new(container, offset, size, stripped)`（type.cc:2255）— stored metatype
  归一为 Uint、submeta 保持 UintPartialEnum，并置 `ENUMTYPE|HAS_STRIPPED`。
- `resolve_in_flow(val)`（type.cc:2280）— `val << (8*offset)` 后构造 `EnumRepresentation`。
- `find_resolve(val)` / `find_compatible_resolve(val)`（type.cc:2300/2315）。
- `resolve_truncation(val, skip)`（type.cc:2322）— 截断到 `size` 字节后解析。
- `has_named_value` / `get_matches` 经 `enum_has_named_value`（type.cc:1354）、
  `enum_get_matches`（type.cc:1365）实现，后者为 Ghidra 的命名恢复算法：
  贪心匹配最大命名值，并以 `val` 的按位补码作第二轮回退（`covering_mask`）。

### `struct TypePartialUnion`（type.hh:597-617, type.cc:2425-2546）
union 切片，解析延迟到流分析阶段（`needs_resolution` 恒真）。
- `new(container, offset, size, stripped)`（type.cc:2433）。
- `resolve_in_flow(val)`（type.cc:2478）— 遍历容器 union 的同偏移字段，返回首个匹配 size 的字段类型。
- `find_resolve(val)` / `find_compatible_resolve(val)`（type.cc:2500/2515）。
- `find_truncation(val, shortsize)`（type.cc:2525）— 在 union 字段中找截断匹配。
- `num_depend` / `get_depend` 经 `union_num_depend` / `union_get_depend`（type.cc:2540）
  返回容器 union 的字段列表。

### `TypeSpacebase` 完整方法（type.hh:721-746, type.cc:2935-3098）
将一个 `AddrSpace` 视作按指针偏移索引的"结构体"，用于栈帧/全局变量类型传播。
- 结构体新增字段 `spaceid: Option<AddressSpace>`、`localframe: Address`、`scope: Option<Arc<Scope>>`。
- `get_map(off)`（type.cc:2996）— 委托 `Scope::map_addr(localframe, off, ...)`；
  无 scope 时返回空（对应 Ghidra "no map ⇒ TYPE_UNKNOWN" 回退）。
- `get_sub_type(off)`（type.cc:3040）— 经 `get_map` 取组件。
- `get_address(off, sz)`（type.cc:3060）— 构造目标 `Address`。
- `compare` / `compare_dependency`（type.cc:3085/3092）— 比 spaceid/localframe。
- `new_global(address)` 便捷构造全局 spacebase；`is_invalid()` 判定 localframe 是否 INVALID。

### 依赖范围与工厂（见 `typefactory.md` / `typefactory.rs`）
- `TypeFactory::depends_of` 已覆盖三 partial 变体：PartialStruct 返回 container；
  PartialEnum 返回 parent；PartialUnion 返回 union 字段。
- `TypeFactory::typedef` 已覆盖三 partial 变体的克隆（带新 base）。
- 新增工厂 getter：`get_type_partial_struct` / `get_type_partial_enum` /
  `get_type_partial_union`（type.cc:3929/3980/3955）；series B 已删除合成名，
  改以 parent/container `Arc` 身份、offset、descending size、id=0 的 ordered-tree
  键进行匿名 canonicalization。
- `get_type_spacebase`（type.cc:3992）。

### 测试
新增 10 个单元测试覆盖：partial struct 的 offset 切片与 compare、partial enum 的位移解析与
`get_matches`、partial union 的 `resolve_in_flow`、spacebase 的 `get_map`/`is_invalid` 行为。
<!-- partial-port: 2026-07-22 -->
<!-- annotation-pass: 2026-07-04 -->
<!-- printnamebase-port: 1783140112.9236958 -->

### 2026-08-16：`get_inheritable` 修正为锁定 oracle 语义（TYPE-WIRING 收尾）

复核 varnode_init fixture 揭出：Rust 旧实现返回
`flags & (chartype|utf16|utf32|opaque_string|enumtype)`（引 type.hh:208 的
过时行号），而锁定 12.0.4 `type.hh:233` 是 `flags & coretype`——只有
core-type 位向指针传播。已改为 `flags & CORETYPE`；工厂核心类型
（undefinedN/xunknownN）现正确传播 1。

## 2026-08-23 TYPEFACTORY-CODEFLAGS-DECODE-0001

- **`Datatype::decode_basic`** now returns `Result`: a missing/negative
  `size` raises `"Bad size for type {name}"` (type.cc:671-672) instead of
  coercing the size to 0. The name is whatever the attribute enumeration
  actually read — empty when the attributes were already exhausted by a
  previous enumeration on the same element, which is exactly the re-read
  `TypeFactory::decodeTypeWithCodeFlags` triggers through
  `TypeCode::decodeStub`.
- **`TypeCode::decode_code_stub`** (type.cc:2903-2911): the peek's
  `variable_length` bit and the `TypeCode` ctor's `type_incomplete` bit
  (type.cc:2757-2763) are OR-composed onto the decoded attribute flags —
  Ghidra's `decodeBasic` never resets `flags`, so pre-states set before it
  survive.
- **`TypeCode::decode_prototype`** (type.cc:2918-2931): full signature with
  `is_constructor`/`isDestructor` and the factory void type; builds the
  `FuncProto`, applies `setConstructor`/`setDestructor`, assigns the
  prototype, and runs `markComplete` unconditionally (also with no
  `<prototype>` child). Rugra residual: `FuncProto::decode`
  (fspec.cc:4675-4839, fspec.rs lease) is not ported, so a present
  `<prototype>` child errors after being consumed — cursor partial state
  preserved (TYPEFACTORY-CODEFLAGS-DECODE-0001).

### 2026-08-26：TypeSpacebase::getMap 的 findContainer 适配
- `type.cc:2962-2963` 的 `queryContainer(addr, 1, nullPoint)`：随
  `Scope::find_container` 签名变化传入空 usepoint（Rugra 的 null
  usepoint = `Address::new(0)`），语义不变（addrtied 符号空 uselimit
  恒 in-use）。

## 2026-08-28：TypeCode prototype 返回类型 Arc 传递

`TypeCode::set_prototype_pieces` 现在从借用的 `PrototypePieces::out_type`
克隆 `Arc`，保留原返回 Datatype 身份，不再构造深拷贝对象。这是调用约定模型
carrier 的身份修正；完整 TypeCode prototype、null output 和 dependency 行为
没有新增双侧门禁，整体仍为 L2/MISMATCH。
