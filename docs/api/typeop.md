# `typeop.rs` API Reference

**状态**: 🔧 L2（仅逐函数核对，禁止据此宣称模块 L3）
**源代码路径**: `src/typeop.rs`

## 2026-08-28：比较输入的 read-facing cast

`INT_EQUAL`/`INT_NOTEQUAL` 的 cast 选择现在读取两个精确 reader slot 的 High 类型，
按 `typeOrder` 选 requirement，并调用 C comparison-promotion 与 `castStandard`。
GetStr 的 `char/char` 比较因此不产生 cast。当前策略 int-size 仍固定为该 x86 fixture 的
4 字节，完整跨架构 TypeOpEqual 和 MULTIEQUAL 传播不得宣称 MATCH。

## 2026-08-27：PTRSUB output-token 阶段纠偏（TYPEOP-PTRSUB-FIELDCAST-0001）

锁定 oracle `TypeOpPtrsub::getOutputLocal`（typeop.cc:2308-2312）请求
Architecture-owned TypeFactory 的 `getBase(output-size, TYPE_INT)`；本 fixture 的
8 字节输出得到 canonical int8。`size > max_basetype_size` 时 Ghidra 会转成
unknown1 数组，Rust 的完整 large-base caller 闭包仍绑定
`TYPEFACTORY-LOCALTYPE-CACHE-0001`。字段敏感类型只由
`getOutputToken`（typeop.cc:2349-2364）产生，并且只在
`ActionSetCasts::castOutput`（coreaction.cc:2541）消费，不能进入
`Varnode::getLocalType` 或 `ActionInferTypes::buildLocaltypes`。

`get_output_token` 当前窄实现遵守以下顺序：从 input-0 的 High read-facing
类型取 pointer；以 unsigned raw offset 调 `AddrSpace::address_to_byte`，按
`uintb` 模 2^64 缩放后转为 `i64`；只调用一次
`down_chain_virtual(..., allow_array_wrap=false)`；检查该调用原地改写后的
residual offset。仅当 residual 为 0 且返回类型非空时返回 descended token，
否则构造 `size=op output storage size`、`wordsize=input-0 pointer address-unit
wordsize` 的 canonical `unknown1 *`。fixture 已覆盖 output storage=8、pointer
storage=8、address-unit wordsize=1/2；未覆盖 output storage≠8 或 pointer
storage≠8，不能把 storage size 与 address-unit wordsize 混为同一宽度。非 pointer 输入
委托 `TypeOp::getOutputToken`（typeop.cc:282-286），后者再返回
`getOutputLocal`。此前循环调用 downChain、按原始 offset 判定以及让 local
派发表消费 token 的实现方向均已撤销。

双侧 fixture `tests/oracle/ptrsub_output_token_1204.*` 固定 24 条记录：1 条
schema、5 条 unsigned scale、14 条 direct token/local、1 条 action_pre 与 1 条
action_post，以及 infer_pre/infer_post 各 1 条。matched direct-token 子投影中，
exact0/exact8/exact24、单次
下降后的 nested/non-field fallback、边界/负编码、wordsize=2 wrap、scalar0 与
nonpointer 的 token shape、token/pointee/repeat identity，以及所有 direct case
经 PcodeOp/local 派发取得的 canonical int8 identity/core 均为 MATCH；fixture 还
强制直接 TypeOp local 与派发结果保持同一 identity。ordinary PTRSUB castOutput 的
所列 def-use/type graph 字段也为 MATCH；infer canary 的 base/out int8 shape、STOP
和定义边字段同样匹配；双侧 raw apply 都是 `result=0,count=1`，infer output 也都
保持 Architecture TypeFactory canonical int8 identity=1。fixture 整体仍为
MISMATCH，因为 Rust `take_count_delta` 是无 Ghidra 对应方法的 `NO_ORACLE` adapter，
而完整 ActionSetCasts/ActionInferTypes/type closure 仍有 MISMATCH/UNTESTED 分支。

该证据不覆盖 High/local read-facing 分歧、PointerRel、array/enum/
PartialStruct/Spacebase、alternate-pointer truncate、冷 TypeFactory 插入副作用、
needs-resolution 或错误路径；oversized local/base fallback 已知受
`TYPEFACTORY-LOCALTYPE-CACHE-0001` 影响而 MISMATCH，其余列举分支仍 UNTESTED，
所以完整 `getOutputToken` 与 typeop 模块保持 MISMATCH/L2。原 R2 的
`getInputCast` typedef 解包历史不属于本 24-record fixture。

production curl release A/B 另行保持 MISMATCH：2026-08-28 formal stdout 两次
byte-identical（只证明 stdout），
sha=`f04dee502dc0131b27b41acb5ec412c0e413515aecf3f29e0e2532b304912a73`，
canonical skeleton 2822→2820、defects/numbering 0/0；raw `diff -U3` 为 12
grouped hunks，`diff -U0` 为 33 atomic hunks、42-/42+，覆盖 7 个
函数而非单行。除 progressbarinit 的 4-byte 字段 cast 与 main literal 精确化外，
六个 concrete-pointer local 发射成无类型声明，glob_set switch cast 方向也未证明；
分别绑定 `PTRSUB-TYPED-DECL-RESIDUAL-0001` 与
`PTRSUB-SWITCH-CAST-RESIDUAL-0001`；main `"--"` 仍不同于 golden
`&DAT_001062f8`，该差异继续由本节 `TYPEOP-PTRSUB-FIELDCAST-0001` 承担。
上游完整类型/符号闭包仍由 `TYPE-UNKNOWN-0001`、`PRINTC-SYMBOL-DECL-0001` 与
`ACTION-INFERTYPES-DISPATCH-0001` 跟踪。它们不是 direct TypeOp 子投影的 MATCH
证据，也不能据 skeleton 净减 2
外推 production 闭包对齐。

## 2026-08-26：`TypeOpStore::get_input_local` 自创 override 移除（TRI2-STORESPLIT-WHOLESTRUCT-0001）

锁定 oracle 的 `typeop.hh:279` 中 `TypeOpStore::getInputLocal` 声明是注释行
（`TypeOpStore` 只覆写 `getInputCast`/`getOutputToken`/`propagateType`），
slot 2 值输入的局部类型因此是基默认
`TypeOp::getInputLocal` = `tlst->getBase(in.size, TYPE_UNKNOWN)`
（typeop.cc:266-276）。旧的表内 override 发明了 Ghidra 从不执行的
slot-2「指针 pointee 回查」，已删除；trait 默认经
`local_type_factory()` 解析（表注册 unit type 不携带工厂时返回 None），
`ActionInferTypes` 的 coreaction 读者派发臂直接播种基类型，观察行为与
oracle 一致。

## 2026-08-25：`TypeOpIntAdd::propagate_add_in2out` 全量移植（typeop.cc:1215-1253）

生产 caller 为 `ActionInferTypes` dispatch 的 PTRSUB/PTRADD/INT_ADD 指针臂
（coreaction.rs，typeop.cc:2375/:2279/:1200）。四类决定性语义：

- **引用/输出参数**：`typegrp: &Arc<RwLock<TypeFactory>>` 显式穿透（C++ 经
  TypeOp 的 `tlst` 成员）；factory 真实改写（downChain/getBase/
  getTypePointer/getTypePointerRel 全部 intern）。`parent/parent_off` 是跨
  整个 do-while 循环共享的累积槽——循环前清一次，downChain 只在当前
  pointee 为 struct/array 时写入、从不重置；`getTypePointerRel` 用**循环
  结束时**的快照。
- **循环边界/遍历顺序**：`do { downChain } while`——至少一次；downChain
  返回 None 即 break；重规范化 offset 归零才停；无显式深度上限。
  `allow_wrap = op != PTRSUB`（PTRSUB 永不回绕）。`command == Passthrough`
  完全跳过循环、pointer 保持 alttype。
- **计数器/累加器**：无计数器；`parent_off` per-call 累积（最后一次
  struct/array 容器写入生效）。
- **排序/比较键**：重载选择——`get_type_pointer_rel_ephemeral`
  （type.cc:4016 无名 ephemeral 版，非 :4029 具名版）；downChain 全灭但
  parent 存在 → `pt = getBase(1, Unknown)`；pointer==NULL 且 command==AddZero
  退回 alttype；spacebase 输入且 ptrto 为 TYPE_SPACEBASE → 以**结果**
  pointer 的 size/wordsize 改写为 unknown 基类型指针。

双侧 fixture：`tests/oracle/stop_ptrsub_wire_1204.*`（MATCH）。

## 模块说明 (Module Doc)

Type operations for P-code

Corresponds to Ghidra's `typeop.hh`

## 2026-08-24：宏族 metatype local 默认（PRINTC-CAST-OPNAME-0001 M1）

宏族（`binary_op!`/`unary_op!`/`functional_unary_op!`/`functional_binary_op!`/
`compare_op_common!`）的 `get_output_local`/`get_input_local` 不再回读对侧
varnode 的 `v_type`（语义颠倒：旧实现 output 读 in(0)、input 读 out），改为
Ghidra `TypeOpBinary/TypeOpUnary/TypeOpFunc::get*Local` 的
`tlst->getBase(size, meta)`（typeop.cc:323/:329/:345/:351/:365/:371），meta 取
各 TypeOp 子类构造器注册的 `(metaout, metain)`（构造签名
`TypeOpXxx(t,opc,name,mout,min)`，typeop.hh:211/:227/:244）：

- **每个宏调用点带构造行注释与 metatype 对**，全部取自锁定 oracle 构造器
  逐行核对：ZEXT=UINT/UINT（typeop.cc:1115）、SEXT=INT/INT（:1141）、
  SUBPIECE=UNKNOWN/UNKNOWN（:2116）、INT_ADD=INT/INT（:1167）、比较族
  BOOL/INT（Equal/NotEqual/Sless/SlessEqual，:924/:988/:1015/:1041）或
  BOOL/UINT（Less/LessEqual，:1067/:1091）、INT_CARRY=BOOL/UINT（:1332）、
  SCARRY/SBORROW=BOOL/INT（:1348/:1364）、NEGATE=UINT/UINT（:1394）、
  2COMP=INT/INT（:1380）、AND/OR/XOR=UINT/UINT、DIV/REM=UINT/UINT、
  ADD/SUB/MULT/SDIV/SREM/LEFT/SRIGHT=INT/INT、RIGHT=UINT/UINT、
  BOOL_XOR/AND/OR/NEGATE=BOOL/BOOL、FLOAT_*=FLOAT/FLOAT（比较族
  BOOL/FLOAT）、NAN=BOOL/FLOAT（:1775）、TRUNC=INT/FLOAT（:1912）、
  INT2FLOAT=FLOAT/INT（:1839）、PIECE=UNKNOWN/UNKNOWN（:2037）、
  POPCOUNT/LZCOUNT=INT/UNKNOWN（:2558/:2565）。
- **宏生成的 struct 现持有构造注入的 `Arc<RwLock<TypeFactory>>`**（`new()`
  构造器，对齐 Ghidra 每个子类构造器接收 `TypeFactory *t` 存入基类 `tlst`
  字段，typeop.cc:233-242），覆写 `local_type_factory()`。
- **共享 `base_local_type(factory, size, meta)` 增加 meta 参数**；trait 默认与
  `TypeOpCall` fallback 显式传 `TypeMetatype::Unknown`，canonical fallback
  语义不变（typeop.cc:261-275）。
- **三个 shift op 转手写 impl**：Ghidra `TypeOpIntLeft/IntRight/IntSright`
  覆写 `getInputLocal`（typeop.cc:1509/:1536/:1600）——slot 1（移位数）返回
  `getBaseNoChar(size, TYPE_INT)`（size-1 INT 得 nochar 基类型，type.cc
  `getBaseNoChar`；Rust 对应 `TypeFactory::get_base_no_char`），其余槽位走
  TypeOpBinary 默认。宏无法表达该覆写，保留宏形式即简化实现。
- **`TypeOpInsert`/`TypeOpExtract` 转工厂 + 覆写移植**：INSERT ctor 为
  UNKNOWN/INT（typeop.cc:2528，旧注释误记 INT/INT 已纠正），EXTRACT 为
  INT/INT（:2543）；二者 `getInputLocal` 覆写（:2535/:2550）：slot 0 保持
  `getBase(size, TYPE_UNKNOWN)`。
- **`TypeOpIntAdd` 手写 impl 的 local 默认改 getBase(size, INT)**（继承
  TypeOpBinary，typeop.cc:1167 构造对），不再回读对侧 v_type。
- **`TypeOpCopy` 删除回读式覆写**：Ghidra TypeOpCopy 无 `get*Local` 覆写
  （typeop.hh:253-263），改持有工厂、走 trait 基类默认。
- `TypeOpManager::new` 对上述全部 opcode 注入工厂（与 CALL/BRANCH 等现有
  注入同一分配）。
- **未触碰**（Ghidra 有各自语义、非宏族，另行任务）：TypeOpLoad（指针解引用
  语义）、TypeOpPtradd（getBase(size,TYPE_INT)，typeop.cc:2233-2240——属
  TYPE-PTRWIDTH-PTRSUB-0001 簇）、TypeOpPtrsub、TypeOpStore、CBRANCH/
  CALLIND/RETURN/CPOOLREF/NEW/CALLOTHER 的 get*Local 覆写。shift 三品的
  `push` 仍走 `op_binary`（Ghidra 是 `opIntLeft/opIntRight/opIntSright`，
  print 侧 emitter 缺口已注释登记，print-language 移植另行任务）。

双侧 fixture `tests/oracle/typeop_localbase_defaults_1204` 的 ZEXT/SEXT 16 行
差异（oracle `getBase(size,metain/metaout)` 得 uint1/uint4/char/int4 vs 旧宏
回读 xunknown4/xunknown1、size 互换）为本切片双侧 oracle 证据；修复后重钉
comparand 至本 commit，bilateral 翻 MATCH。打印侧三发射臂（printc.rs
opIntZext/opIntSext/opSubpiece）与 cast.rs 三谓词不在本切片 write-set，行为
不变——泄漏的打印侧根因（M2 varnode get_local_type 空壳、M3 coreaction
build_localtypes v_type 播种）另行切片。
## 2026-08-24：TypeOpCallind::getInputLocal + Funcdata 上下文入口（TYPEOP-LOCALTYPE-DISPATCH-0001 D2）

- **`TypeOpCallind::get_input_local` 完整移植 `TypeOpCallind::getInputLocal`
  （`typeop.cc:745-774`）**，与 CALL 有意保留三处不对称（fixture 必测判别面）：
  - `slot==0` 返回 code pointer：`tlst->getTypeCode()` + `tlst->getTypePointer(
    in0.size, td, op.addr.space.wordsize)`（typeop.cc:752-756； getTypeCode/
    getTypePointer 需工厂写锁）。Rugra 无 `op->getParent()->getFuncdata()` 链，
    空间经 `op.get_addr().get_space()` 读取，spaceless 旧式 Address 回退
    wordsize 1（锁定 oracle 的 code space wordsize 均为 1）。
  - callspec 来源不同：走 `getCallSpecs(op)`（typeop.cc:757）而非 CALL 的
    fspec 常量解码——Rugra 由 `fd.get_call_specs_of_op(op_ref)` 承载（op
    identity 扫描，非地址扫描）。
  - 锁定参数检查**只有 VOID 拒绝，没有 `size <= in(slot).size` 检查**
    （typeop.cc:764 vs CALL 的 :707）；this-pointer 分支同 CALL（:767-771）。
- **新增 trait 方法 `get_input_local_in_fd(op: &PcodeOpRef, slot, fd)`**（默认
  转发 fd-less `get_input_local`）：Ghidra 的虚调用点
  `PcodeOp::inputTypeLocal`（op.hh:252）天然可达宿主 Funcdata，Rust `PcodeOp`
  无父链，故 Funcdata 经此入口穿参。目前仅 TypeOpCallind 消费（getCallSpecs）。
  `TypeOpCallind::get_input_local`（fd-less）实现 slot0 + fc==0 缺省路径；
  slot≥1 的完整 callspec 解析走 `get_input_local_in_fd`。
- `TypeOpCallind` 改为持有构造注入的 `Arc<RwLock<TypeFactory>>`（对齐
  `TypeOpCallind(TypeFactory *t)`，typeop.cc:738），覆写 `local_type_factory`；
  `get_flags` 补 `typeop.cc:741` 的 `special|call|has_callspec|nocollapse`；
  `TypeOpManager` 注册处传入工厂。
- 双侧 fixture `tests/oracle/infertypes_callinput_local_1204`（CALLIND 的
  C5/C5S0 case：8B 锁定参数播到 4B 实参、slot0 code pointer、CALLIND
  callspec 查询路径），双侧字节一致（见 coreaction.md D2 条目）。

## 2026-08-24：TypeOp 基类 local 默认与 TypeOpCall opflags（TYPEOP-LOCALBASE-DEFAULTS-0001）

修复 R3 复核发现的两个预存缺口（R3-D1-REVIEW §7 建议②③）：

- **trait 默认 `get_output_local`/`get_input_local` 不再返回 `None`**，而是对齐
  Ghidra 基类 `TypeOp::getOutputLocal/getInputLocal`（`typeop.cc:261-275`）：
  `tlst->getBase(op->getOut()/getIn(slot)->getSize(), TYPE_UNKNOWN)`。共享
  helper `base_local_type(factory, size)` 承载该 base 查找（typeop.cc:264/:274），
  工厂经新 trait 钩子 `local_type_factory()`（RUGRA-GLUE：Ghidra 基类 `tlst` 字段
  的 provider；宏生成的无状态 unit struct 返回 `None`，与"尚未接入 Architecture
  工厂"的实现状态一致）。
- `TypeOpCall::get_flags` 由 `0` 改为 `typeop.cc:663` 构造函数的
  `opflags = special|call|has_callspec|coderef|nocollapse`（0x20020814），逐位使用
  `op::pcodeop_flags` 常量，与 `op::opcode_flags(CPUI_CALL)` 同值。
- `TypeOpCall::get_input_local` 的 fallback 闭包改用共享 `base_local_type`（行为
  不变，同一工厂同一 `get_base(size, Unknown)`）。
- `TypeOpBranch`/`TypeOpBranchind`/`TypeOpSegment`/`TypeOpCast`（Ghidra 侧无
  `get*Local` 覆写的四个 opcode，typeop.hh:253-263/:849-860/:804-811）改为持有
  构造注入的 `Arc<RwLock<TypeFactory>>`（对齐 Ghidra 构造签名
  `TypeOpXxx(TypeFactory *t)`，typeop.cc:583/:646/:2209/:2390），覆写
  `local_type_factory`，使基类默认在分派表中可用。Ghidra 侧有覆写而 Rust 尚未
  移植的 opcode（CBRANCH/CALLIND/RETURN/CPOOLREF/NEW/CALLOTHER）保持无工厂，
  其 local 默认仍为 `None`（不伪对齐）。
- 已有覆写（TypeOpCall::get_input_local 等）行为不变；宏族
  `v_type` 读取在 PRINTC-CAST-OPNAME-0001 M1（见上节）已改为
  `getBase(size, metain/metaout)`（ZEXT=UINT/SEXT=INT，typeop.cc:1115/:1141）。

双侧 fixture `tests/oracle/typeop_localbase_defaults_1204.{cc,rs,metadata.json}` +
`tools/run_typeop_localbase_defaults_oracle.sh`：C++ 经真实
`PcodeOp::input/outputTypeLocal` 虚分派，Rust 经生产 `TypeOpManager` 分派表；
覆盖 BRANCH/BRANCHIND/SEGMENTOP/CAST 基类默认（含 3 字节非标准 size 边界）、
ZEXT/UINT 与 SEXT/INT 判别（oracle 侧记录 TypeOpFunc metain/metaout 推导；Rust
宏覆写残差如实呈现为差异行）、CALL 无 fspec 时经基类默认的 input/output、CALL
锁定参数（D1 不回归）、`flags.call` 逐位。

## 2026-08-24：TypeOpCall::getInputLocal D1（TYPEOP-LOCALTYPE-DISPATCH-0001）

`TypeOpCall::get_input_local` 现在完整移植锁定 oracle 的
`TypeOpCall::getInputLocal`（`typeop.cc:687-718`）：

- `slot==0` 或 input0 不是 callspec 注解时，返回基类行为
  `tlst->getBase(op->getIn(slot)->getSize(), TYPE_UNKNOWN)`（`typeop.cc:271-275`）。
  由于 Rugra 的 `TypeOp` trait object 不持有 `tlst`，`TypeOpCall` 构造时接收
  `Arc<RwLock<TypeFactory>>`（与 Architecture/VarnodeBank 同一分配），fallback
  由该工厂的 canonical `get_base` 提供。
- IPTR_FSPEC 判定采用 D0 表示：Iop 空间 + `ANNOTATION` flag + typed callspec
  Weak（`Funcdata::new_varnode_call_specs`，TYPEOP-FSPEC-SPACE-0001）。Weak
  失效（callspec 已删除）等价 Ghidra 的悬垂 FSPEC 不可用，落到 fallback。
- `prototype.get_param(slot - 1)` 后：type-lock 分支要求
  `metatype != TYPE_VOID && param.size <= input.size`；`else if` this-pointer
  分支只接受 PTR→STRUCT（无 size 检查）；两分支都未命中时返回同一工厂的
  canonical UNKNOWN。禁止地址扫描、字符串硬编码、prototype snapshot 旁路。

`TypeOpManager::new` 因此需要传入该工厂并把它装进 `CPUI_CALL` 槽位。

双侧 fixture `tests/oracle/typeop_local_type_1204.{cc,rs}` 通过
`tools/run_typeop_local_type_oracle.sh` 运行：C++ 侧经真实
`PcodeOp::inputTypeLocal` 虚分派，Rust 侧直接驱动生产
`TypeOpCall::get_input_local`；167 条记录中 165 条字节一致，仅
`representation.fspec_name`（fspec vs iop）与
`representation.fspec_type`（4 vs 5）两条表示行差异，即已登记的
CALLSPEC-0001/TYPEOP-FSPEC-SPACE-0001 残留。covered projection 行为
MATCH、整体因表示残留记 MISMATCH，不宣称 L3。生产
`ActionInferTypes` 尚未把 CALL inputs 接到该分派（D2，另行 fixture）。

## 2026-08-24：LOAD/STORE 解引用宽度门槛（TYPE-PTRWIDTH-PTRSUB-0001）

`TypeOpLoad::propagate_type` 与 `TypeOpStore::propagate_type` 的
pointer→value 方向现在把目标 Varnode 的真实字节宽度传给
`propagate_from_pointer`。对固定长度 pointee，只有 pointee size 与访问宽度完全相等
时才传播，并返回原 pointee `Arc`；因此 `ProgressData(32B)*` 不再把 16B/4B STORE
错误标成整个 `ProgressData`，32B exact STORE 仍保留类型身份。

prospective 双侧 fixture `tests/oracle/type_ptrwidth_1204.{cc,rs,metadata.json}` 计划直接调用
锁定 Ghidra 12.0.4 `TypeOpLoad/Store::propagateType` 与 Rugra 对应函数，比较同一组
LOAD/STORE 宽度、别名和身份观察。当前 prospective fixture 只把 Varnode 单向挂到 PcodeOp 槽位：
C++ PcodeOp 的 opcode 仍为 null，且未建立 output→def/input→descend；Rust PcodeOp
带 CPUI_LOAD/STORE opcode，但也没有走生产 builder。因此它不是同一份生产 IR/别名图。
runner 为
`tools/run_type_ptrwidth_oracle.sh`。修订后的 fixture 已通过锁定源码树的 C++
syntax-only 门禁，但 isolated whole-archive link 尚未绑定 BFD 依赖闭包，因此当前
covered projection 保守记为 `NO_ORACLE`，不得沿用旧 standalone fixture 的 MATCH。

状态仍为 **MISMATCH**：Ghidra 在 size mismatch 时还允许 plain enum 的
`TypePartialEnum` 与 `TypePointerRel` parent 上的 enum exact-piece。该路径必须由拥有
canonical registry 的 `TypeFactory::getExactPiece` 构造；当前 TypeOp trait 没有 factory
参数，所以 Rugra 暂时 fail-closed，记为 `TYPEFACTORY-EXACTPIECE-0001`，未用本地
`Arc::new` 伪造对象身份。

LOAD/STORE 的 spacebase 守卫按 oracle 的显式传播源 `invn` 判断；尤其 LOAD
value→pointer 方向检查 output，而不是把 `outslot` 当作 input 下标。Rust 回归测试已覆盖
这个槽位选择，两侧 prospective fixture 也已有 spacebase case；但双侧执行尚未完成，
metadata 因此记为 `NO_ORACLE`，不宣称 MATCH。

value→pointer 方向仍为 **MISMATCH**：oracle 使用目标 `outvn` 的 pointer storage width、
地址空间 wordsize 和 `TypeFactory` canonical identity；当前 Rust 使用 `alt_type` 宽度、
固定 wordsize 1，并新建 `Arc`。

runner 会重算输入 manifest，分别钉住两侧 stdout，并从锁定 commit 的源码 archive
重建 `libdecomp.a`，避免复用 Ghidra checkout 中未追踪的历史产物。但 isolated
whole-archive link 的 pinned BFD header/library/dependency closure 尚未闭合；Rust 侧
声明的 base commit/blob 也未被重建为快照，仍直接构建 live tree 到 shared target。
两项 harness 缺口都记为 `NO_ORACLE`，绑定 `ORACLE-RUNNER-HERMETIC-0001`。

生产 `ActionInferTypes` 仍在 `coreaction.rs:3994-4020` 自行分派 LOAD/STORE，绕过这里的
TypeOp 宽度门槛；该生产闭包保持 `MISMATCH`，本切片不会改变 progressbarinit 输出。

## 2026-08-11：`TypeOpFloatInt2Float::preferredZextSize`

`TypeOpFloatInt2Float::preferred_zext_size` 对应锁定 oracle
Ghidra 12.0.4 `typeop.cc:1891-1902`。它按严格边界选择无符号整数转浮点前的
`INT_ZEXT` 输出宽度：

| 输入字节数 | 1 | 2 | 3 | 4 | 7 | 8 | 16 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 输出字节数 | 4 | 4 | 4 | 8 | 8 | 9 | 17 |

状态：`MATCH`。证据不是手写期望值：
`tools/run_preferred_zext_oracle.sh` 会校验 Ghidra checkout 的 commit，直接编译
`typeop.cc`，再调用上游静态方法产生上述结果。Rust 单元测试覆盖同一边界集。

该函数已由以下 Ghidra 调用点共享使用，移除了各处不同的近似分支：

- `RuleUnsigned2Float::applyOp`（`ruleaction.cc:9822`）
- `RuleInt2FloatCollapse::applyOp`（`ruleaction.cc:9888`）
- `SubvariableFlow::tryInt2FloatPull`（`subflow.cc:351`）
- `SubvariableFlow::doReplacement`（`subflow.cc:1537`）

模块仍为 L2：`TypeOp::getFlags` 的 `opflags/addlflags` 组合、`OpBehavior` 桥接及
若干 opcode 专用虚函数尚未逐项完成 12.0.4 oracle 对拍，列入 `PCODE-0002`。

## 导出的公共 API (Public API)

### `pub struct OpBehavior`

*暂无代码注释*

### `pub struct Encoder`

*暂无代码注释*

### `pub const INHERITS_SIGN: u32 = 1 << 0`

*暂无代码注释*

### `pub const INHERITS_SIGN_ZERO: u32 = 1 << 1`

*暂无代码注释*

### `pub const SHIFT_OP: u32 = 1 << 2`

*暂无代码注释*

### `pub const ARITHMETIC_OP: u32 = 1 << 3`

*暂无代码注释*

### `pub const LOGICAL_OP: u32 = 1 << 4`

*暂无代码注释*

### `pub const FLOATINGPOINT_OP: u32 = 1 << 5`

*暂无代码注释*

### `pub trait TypeOp`

Core trait representing a P-code operation type

Corresponds to Ghidra's `TypeOp` class

钩子 `local_type_factory()`（RUGRA-GLUE）：Ghidra 基类 `tlst` 字段
（typeop.cc:233-242）的 provider，默认 `None`；持有构造注入工厂的 impl
（TypeOpCall/TypeOpBranch/TypeOpBranchind/TypeOpSegment/TypeOpCast 及 M1 后的
全部宏族/比较族/shift/INSERT/EXTRACT/INT_ADD/COPY struct）覆写它。
默认 `get_output_local`/`get_input_local` 经共享 `base_local_type` 返回
`getBase(size, TYPE_UNKNOWN)`（typeop.cc:261-275），无工厂时 `None`。宏族覆写
按构造器注册的 `(metaout, metain)` 走 `getBase(size, meta)`
（typeop.cc:323/:329/:345/:351/:365/:371，PRINTC-CAST-OPNAME-0001 M1）。

### `pub struct TypeOpBinary`

Base behavior for binary operations

### `pub struct TypeOpUnary`

Base behavior for unary operations

### `pub struct $struct_name`

宏族（binary/unary/functional_unary/functional_binary/compare_*）生成的
struct：持有构造注入的 `Arc<RwLock<TypeFactory>>`（`new()`），`get*Local` 按
构造器注册 metatype 的 `getBase(size, meta)`（注册点逐 opcode 附
`// Ghidra: typeop.cc:<ctor行>` 注释）。

### `pub struct TypeOpCopy`

CPUI_COPY implementation. 无 `get*Local` 覆写（typeop.hh:253-263），持工厂走
trait 基类默认（PRINTC-CAST-OPNAME-0001 M1 起不再回读对侧 v_type）。

### `pub struct TypeOpLoad`

CPUI_LOAD implementation

### `pub struct TypeOpStore`

CPUI_STORE implementation

### `pub struct TypeOpBranch`

Ghidra `TypeOpBranch(TypeFactory *t)`（typeop.cc:583）；无 `get*Local` 覆写，
基类默认经 `local_type_factory` 提供的工厂解析。

### `pub struct TypeOpCbranch`

*暂无代码注释*

### `pub struct TypeOpBranchind`

Ghidra `TypeOpBranchind(TypeFactory *t)`（typeop.cc:646）；无 `get*Local` 覆写，
基类默认经 `local_type_factory` 提供的工厂解析。

### `pub struct TypeOpCall`

CPUI_CALL implementation. Holds the Architecture-owned `TypeFactory`
handle used by `get_input_local`（`typeop.cc:687-718`）的 fallback 与
canonical UNKNOWN；`get_flags` 返回 `typeop.cc:663` 的
`special|call|has_callspec|coderef|nocollapse`（0x20020814）。

### `pub struct TypeOpCallind`

CPUI_CALLIND implementation. Holds the Architecture-owned `TypeFactory`
handle（对齐 `TypeOpCallind(TypeFactory *t)`，typeop.cc:738）。`get_input_local`
（fd-less）实现 slot0 code pointer 与 fc==0 缺省；`get_input_local_in_fd` 为
`TypeOpCallind::getInputLocal`（typeop.cc:745-774）的完整移植——callspec 经
`fd.get_call_specs_of_op`（= `getCallSpecs(op)`，typeop.cc:757）、锁定参数仅
VOID 拒绝（无 CALL 的 size 检查，:764 vs :707）、this-pointer 同 CALL
（:767-771）。`get_flags` 返回 `typeop.cc:741` 的
`special|call|has_callspec|nocollapse`。

### `pub struct TypeOpReturn`

*暂无代码注释*

### `pub struct TypeOpPtradd`

*暂无代码注释*

### `pub struct TypeOpPtrsub`

*暂无代码注释*

### `pub struct TypeOpMulti`

*暂无代码注释*

### `pub struct TypeOpIndirect`

*暂无代码注释*

### `pub struct TypeOpSegment`

Ghidra `TypeOpSegment(TypeFactory *t)`（typeop.cc:2390）；`get*Local` 覆写在
Ghidra 已注释掉（typeop.hh:852-853），基类默认经 `local_type_factory` 提供的
工厂解析。

### `pub struct TypeOpCpoolref`

*暂无代码注释*

### `pub struct TypeOpNew`

*暂无代码注释*

### `pub struct TypeOpCallother`

*暂无代码注释*

### `pub struct TypeOpManager`

Manager for TypeOps

This handles the mapping between OpCodes and their TypeOp implementations.

### `pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self`

Build the per-opcode table; the factory is injected into every factory-backed
slot — `CPUI_CALL`, `CPUI_BRANCH`, `CPUI_BRANCHIND`, `CPUI_SEGMENTOP`,
`CPUI_CAST`, and (PRINTC-CAST-OPNAME-0001 M1) the full macro/compare family,
the three shift ops, `CPUI_INSERT`, `CPUI_EXTRACT`, `CPUI_INT_ADD`, and
`CPUI_COPY` — so the base-default and metatype
`get_output_local`/`get_input_local` paths share the Architecture's canonical
TypeFactory.
Build the per-opcode table; the factory is installed into the `CPUI_CALL`,
`CPUI_CALLIND`, `CPUI_BRANCH`, `CPUI_BRANCHIND`, `CPUI_SEGMENTOP`, and
`CPUI_CAST` slots so the base-default `get_output_local`/`get_input_local`
and the `TypeOpCall`/`TypeOpCallind` `get_input_local` fallbacks share the
Architecture's canonical TypeFactory.

### `pub fn get_op(&self, opcode: OpCode) -> Option<&dyn TypeOp>`

*暂无代码注释*

### `pub fn push(&self, lng: &mut dyn PrintLanguage)`

Push this operation to a language printer

### 2026-08-23：RULE-PORT-COLLAPSECONSTANTS-0001（TypeOp::evaluate 桥）

新增模块级 `pub fn evaluate_unary(opc, size_out, size_in, in1) -> Option<u64>` 与
`pub fn evaluate_binary(opc, size_out, size_in, in1, in2) -> Option<u64>`，
对应 Ghidra `TypeOp::evaluateUnary/evaluateBinary`（typeop.hh:81-92，内联委托
`behave->evaluate*`）。Rugra 无 per-op TypeOp 实例，桥承担该角色：

- 非 FLOAT opcode 委托 `opbehavior::{evaluate_unary, evaluate_binary}` 自由函数表
  （opbehavior.cc:171-792 的整数/布尔/PIECE/SUBPIECE 全表）；
- FLOAT_* 分支复刻 `OpBehaviorFloat*::evaluate*`（opbehavior.cc:569-750）：
  按 sizein（INT2FLOAT/FLOAT2FLOAT 按 sizeout）查 `opbehavior::float_format`
  （`Translate::getFloatFormat` 的静态替身，仅 4/8 字节 IEEE754）；缺格式 →
  `None`（C++ 基类 LowlevelError "…emulation unimplemented"，RuleCollapseConstants
  映射为 opMarkNoCollapse）；命中 → `FloatFormat::op_*` 求值；
- 结果统一 `& calc_mask(size_out)`（保持自由函数 sizing 契约；对 FLOAT_TRUNC
  同时落实 float.cc:638 的 `res &= calc_mask(sizeout)`）。

`PcodeOp::collapse`（op.rs）改为经本桥求值，对齐
`PcodeOp::collapse -> TypeOp::evaluate* -> OpBehavior::evaluate*` 分层。

 2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。

### 2026-07-01：getInputCast/getOutputToken/propagateType 补全
TypeOp trait +get_output_token/get_input_cast/propagate_type/get_output_metatype（默认 None）。
关键 op 实现：COPY（透明传播）、LOAD/STORE（指针↔值）、MULTIEQUAL/INDIRECT（透明）、INT_ADD（指针传播）、6 个比较 op（bool 输出+跨 input 传播）。+propagate_to_pointer/from_pointer 辅助。8 新测试。
<!-- annotation-pass: 2026-07-04 -->
<!-- opcode-correct: 1783180039.060287 -->

### 2026-08-25 测试修复

- `default_trait_methods_are_none` 测试改用 `TypeOpBranch::new(TypeFactory::raw())` 构造实例（TYPEOP-LOCALBASE-DEFAULTS-0001 的 TypeOpBranch 带工厂字段后，原 unit-struct 用法触发 E0423，阻塞全仓 cargo test --lib）。行为语义不变（token/cast/metatype/propagate 默认值均不触工厂）。


### D2 集成补丁

-  的 fallback 调用点适配 A38 的 3 参
  `base_local_type`（meta=`TypeMetatype::Unknown`，D2 语义不变：
  typeop.cc:271-275 基类缺省）。


## propagate_to_pointer 提为 pub（MYFWRITE-TEMPVAR-0001，2026-08-26）

`propagate_to_pointer`（typeop.cc:186-198）可见性改 pub：coreaction.rs 的
LOAD/STORE 专用 cast 臂需要构造 pointer 包装类型（`tlst->getTypePointer` 等
价路径），与 Ghidra 中 TypeOpLoad/TypeOpStore 同文件共享 propagateToPointer
的布局一致。

## 2026-08-29：propagate_to_pointer 产物改匿名指针（PTRSUB-TYPED-DECL-RESIDUAL-0001）

Ghidra 的 `TypeOp::propagateToPointer` 终归 3-arg
`t->getTypePointer(sz,dt,wordsz)`（typeop.cc:197 / type.cc:3867-3875），指针名
为空。Rugra 此前给产物附带组合名（`"char *"`），使下游声明/转型把该指针当
命名单层指针渲染（`char * pcVar5`，oracle named_ptr_contrast 形），偏离
golden 的匿名钻取形 `char *pcVar5`。现在用 `TypePointer::new`（空名 +
calc_submeta）构造。coreaction.rs 的 `make_pointer_type`/`make_ptr`/
COPY-spacebase 指针臂（typeop.cc:418 同源）同批修正，见
docs/api/coreaction.md。

