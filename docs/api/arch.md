# arch.rs — Architecture manager API

Architecture manager corresponding to Ghidra's `architecture.hh` /
`architecture.cc`.

**Status:** L2 (locked 12.0.4 audit, 2026-08-14; production text-ingest slice
landed 2026-08-16, oracle fixture MATCH on the covered projection). The
structured-DOM prototype/default-model slice and the production
`parse_compiler_config` text-ingest slice have locked oracle fixtures, but
`data_organization`/`enum` (CSPEC-TYPEORG-STATE-0001), `resolveprototype`
(CSPEC-PARAMMODEL-0001), `spacebase`/`deadcodedelay`/`inferptrbounds` (space
manager wiring), `readonly` (Database property ranges) and the factory/init
chain remain incomplete, so the module stays L2/MISMATCH, not L3.

This is the Ghidra `Architecture` class — distinct from `types::Architecture`
(which is the target CPU enum). It holds all configuration parameters and owns
the sub-component references.

Ghidra reference:
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/architecture.{hh,cc}`.

## Constants

| Name | Value | Description |
|---|---|---|
| `MAJOR_VERSION` | 6 | Decompiler major version. |
| `MINOR_VERSION` | 1 | Decompiler minor version. |
| `FLOWOPT_ERROR_TOOMANY` | 1 | FlowInfo error-on-too-many bit. |

## Module `split_datatype`
- `OPTION_STRUCT = 1`, `OPTION_ARRAY = 2`, `OPTION_POINTER = 4`.

## Traits

### `ArchitectureCapability`
Abstract extension point for building Architecture objects. Faithful to
`ArchitectureCapability` (architecture.hh:117).
- `name() -> &str`
- `build_architecture(filename, target) -> Result<Box<dyn ArchitectureBuilder>, String>`
- `is_file_match(filename) -> bool`
- `is_xml_match(doc) -> bool`

### `ArchitectureBuilder`
Provides the virtual factory hooks for sub-components. Faithful to the
protected virtual methods of `Architecture` (architecture.hh:264-348).
- `build_database()`, `build_translator()`, `build_loader()`,
  `build_pcode_inject_library()`, `build_typegrp()`, `build_core_types()`,
  `build_comment_db()`, `build_string_manager()`,
  `build_constant_pool()`, `build_context()`, `build_symbols()`,
  `build_spec_file()`, `modify_spaces()`, `resolve_architecture()`.

### `SpecQuery`
Language/space queries consumed by the compiler-spec decode chain, standing
in for the Architecture's `AddrSpaceManager` + `Translate` during
`parseCompilerConfig` (Rugra's `Architecture` does not own a space manager
yet). Mirrors `SleighBase::getRegister` (sleighbase.cc:133),
`AddrSpaceManager::getSpaceByName` (translate.cc:590),
`AddrSpace::getHighest`, the overlay enumeration of
`addToGlobalScope`/`addOtherSpace`, `SleighBase::findSymbol` and
`Translate::getUniqueStart(Translate::INJECT)`.
- `get_register(name) -> Option<VarnodeData>`
- `space_by_name(name) -> Option<AddressSpace>`
- `space_highest(spc) -> u64`
- `num_spaces()`, `space_at(i)`, `is_overlay(spc)`, `is_overlay_base(spc)`,
  `contain_space(spc)` (default: no overlay enumeration)
- `sleigh_symbol(name) -> Option<SleighSymbol>`
- `unique_inject_base() -> u64` (default `0x200`)

### `CompilerConfigReport`
Residual report returned by `parse_compiler_config`: `skipped_children`
(child tag + owning TODO for children whose full decode belongs to another
domain), `ignored_children` (tags the Ghidra oracle's own dispatch ignores —
architecture.cc:1249-1305 has no else branch) and `post_step_residuals`
(initializeSegments / PreferSplitManager / setupSizes infrastructure gaps).
Nothing is silently skipped.

## Structs

### `CapabilityRegistry`
Registry of `ArchitectureCapability` extensions. Faithful to the static
`thelist` and static methods (architecture.hh:120-156).
- `new()`, `register(cap)`, `find_capability_for_file(filename)`,
  `find_capability_for_xml(doc)`, `get_capability(name)`,
  `sort_capabilities()`, `major_version()`, `minor_version()`.

### `ProtoModelMap`

`BTreeMap<String, Arc<ProtoModelFull>>`. Each map value is a stable shared
model object. The selected `defaultfp` is the same `Arc` as its map entry,
mirroring Ghidra's pointer identity rather than copying a lightweight name
record.

### `Architecture`
Manager for all the major decompiler subsystems. Faithful to `Architecture`
(architecture.hh:165).

| Field | Type | Description |
|---|---|---|
| `archid` | `String` | Unique architecture id. |
| `trim_recurse_max` | `i32` | Parameter trim recursion limit. |
| `max_implied_ref` | `i32` | Max implied-var references. |
| `max_term_duplication` | `i32` | Max duplicated terms. |
| `max_basetype_size` | `i32` | Max integer size before array. |
| `min_funcsymbol_size` | `i32` | Min function symbol size. |
| `max_jumptable_size` | `u32` | Max jumptable entries. |
| `aggressive_ext_trim` | `bool` | Aggressive sign-ext trim. |
| `readonlypropagate` | `bool` | Treat readonly as constants. |
| `infer_pointers` | `bool` | Infer pointers from constants. |
| `analyze_for_loops` | `bool` | Convert while-do to for loops. |
| `nan_ignore_all` / `nan_ignore_compare` | `bool` | NaN handling. |
| `funcptr_align` | `i32` | Function ptr alignment bits. |
| `flowoptions` | `u32` | Flow engine options. |
| `max_instructions` | `u32` | Max instructions per function. |
| `alias_block_level` | `i32` | Alias blocking (0-3). |
| `split_datatype_config` | `u32` | Datatype split config bits. |
| `proto_models` | `ProtoModelMap` | Prototype models. |
| `defaultfp_name` | `Option<String>` | Default model name. |
| `defaultfp` | `Option<Arc<ProtoModelFull>>` | Shared default model, pointer-identical to its map entry. |
| `default_return_addr` | `Option<VarnodeData>` | `defaultReturnAddr` (architecture.hh:194); `None` mirrors the ctor's null-space sentinel (architecture.cc:159). |
| `evalfp_current_name` / `evalfp_called_name` | `Option<String>` | Eval model names. |
| `evalfp_current` / `evalfp_called` | `Option<Arc<ProtoModelFull>>` | `evalfp_current`/`evalfp_called` (architecture.hh:195-196). |
| `infer_ptr_spaces` | `Vec<AddressSpace>` | `inferPtrSpaces` (architecture.hh:182), appended by `add_to_global_scope`. |
| `global_scope_ranges` | `Vec<(AddressSpace, u64, u64)>` | Applied `<global>` + OTHER-space triples in application order (Database-side application is a registered residual). |
| `pcodeinjectlib` | `Option<Arc<RwLock<PcodeInjectLibrary>>>` | `pcodeinjectlib` (architecture.hh:200). |
| `nohighptr` | `RangeList` | No-high-pointer ranges. |
| `overrides` | `Override` | Override commands. |
| `loadersymbols_parsed` | `bool` | Loader symbols read. |
| `stack_reverse_justify` | `bool` | `<stackpointer reversejustify>` (`setReverseJustified`, architecture.cc:566). |

**Methods:** `new()`, `reset_defaults_internal()` (architecture.cc:1416),
`reset_defaults()` (architecture.cc:1438), `get_model(name)`, `has_model(name)`,
`set_default_model(name)` (architecture.cc:323), `get_default_model()`,
`decode_proto(decoder, addr_size, register_resolver)` (architecture.cc:741),
`decode_proto_spec(...)` (parseCompilerConfig path injecting
`default_return_addr`, fspec.cc:2689),
`decode_default_proto(...)`/`decode_default_proto_spec(...)`
(architecture.cc:795), `decode_global(decoder, range_props)`
(architecture.cc:812), `add_to_global_scope(props, host)`
(architecture.cc:826), `add_other_space(host)` (architecture.cc:847),
`decode_return_address(decoder, host)` (architecture.cc:898),
`decode_stack_pointer(decoder, host)` (architecture.cc:979),
`decode_proto_eval(decoder)` (architecture.cc:769),
`decode_no_high_ptr(decoder, host)` (architecture.cc:1086),
`decode_prefer_split(decoder, host)` (architecture.cc:1101),
`decode_aggressive_trim(decoder)` (architecture.cc:1121),
`decode_funcptr_align(decoder)` (architecture.cc:1049),
`create_model_alias_exact(alias, parent)` (architecture.cc:1138 with
Ghidra's exact error strings),
`parse_compiler_config(store, host, addr_size) -> Result<CompilerConfigReport, String>`
(architecture.cc:1239, including the specextensions pass, the deferred
`<global>` application loop, `addOtherSpace`, the default-model fallback,
the `__thiscall` alias clone and the post-loop residual disclosure),
`high_ptr_possible(addr, size)` (architecture.hh:408),
`add_no_high_ptr(range)` (architecture.cc:576), `globalify()`
(architecture.cc:437), `create_model_alias(alias, parent)`,
`decode_flow_override()`, `get_description()`, `print_message(msg)`.

## L3 gaps
- Virtual factory hooks (`buildTranslator`, `buildLoader`, `buildTypegrp`, …)
  require Translate/LoadImage/TypeFactory integration.
- Production XML text ingestion and full processor/compiler-spec dispatch
  (`parseProcessorConfig`, `parseCompilerConfig`, …). The current decode
  methods intentionally begin at an existing structured `TreeDecoder`.
- `AddrSpaceManager` integration (`getSpaceBySpacebase`, `getSegmentOp`).
- `DocumentStorage` for `init`/`restoreXml`.

## 2026-06-27 历史实现记录（“达到 L3”结论已于 2026-08-11 撤回）

- **Architecture 新增子组件字段**：symboltab (Database)、loader (LoadImage)、commentdb、string_manager、cpool、context_db、options_db、split_records、lane_records。
- **虚拟工厂钩子等价物**：`set_symboltab`/`set_loader`/`set_commentdb`/`set_string_manager`/`set_cpool`/`set_context_db`/`set_options_db`/`set_split_records`/`set_lane_records` — 替代 Ghidra 的 buildXxx 虚函数。
- **init()**：验证架构 ID 已设置，编排初始化流程。
- **clear_analysis()**、**read_loader_symbols()**、**encode()**。

## 2026-06-29：Stack 空间 / spacebase 配置字段（cspec `<stackpointer>` 对齐）

- Architecture 新增字段（对齐 Ghidra cspec `<stackpointer register="RSP" space="ram"/>` + `SpacebaseSpace::getSpacebase(0)`）：`stack_space: AddressSpace`（= Stack，IPTR_SPACEBASE）、`stack_pointer_space: AddressSpace`（= Register）、`stack_pointer_offset: u64`（= 0x20 = RSP）、`stack_pointer_size: usize`（= 8）、`stack_grows_negative: bool`（= true，x86 约定）。
- 默认值匹配 x86-64-gcc.cspec。Funcdata 也有对应字段（不持有 Architecture 引用，用默认值初始化），`Funcdata::spacebase()` 从这些字段读 stack pointer 位置。
- 这是层次 1 Stack 空间架构对齐的阶段 2：建立 spacebase 配置容器（暂不解析 .cspec 文件，用硬编码配置）。
- arch.rs 所有 L3 缺口已关闭。

### 2026-07-01：Architecture 手动 Debug impl
- 为 Architecture 添加 `impl Debug`（打印 archid）。因 loader 字段是 `Arc<dyn LoadImage>`（无 Debug bound），不能 derive。这使得 Funcdata（derive Debug）能持有 `Option<Arc<Architecture>>` 字段。

### 2026-07-01（续 2）：types + userops 字段 + get_base_type + construct_join_address
- `types: Option<Arc<RwLock<TypeFactory>>>` + `userops: Option<Arc<RwLock<UserOpManage>>>` 字段 + set_types/set_userops。
- `get_base_type(size, metatype)` — 委托 TypeFactory::get_base。
- `construct_join_address(hi,sz,lo,sz)`（translate.cc:817）— 桩：contiguous 早返回，否则 0。
- **2026-08-16（`TYPE-WIRING-0001`）**：新增 `ensure_types()` — 无工厂时安装并返回
  process-canonical 工厂（`TypeFactory::shared_default()`，DataOrg flavor）。Ghidra 的
  Architecture 恒持有唯一 `TypeFactory`（type.cc:3106）；Rugra 的 `types` 在
  CSPEC-TEXT-INGEST-0001 落地前可选。生产接线建议（root，funcdata.rs 租约外）：
  `fd.set_arch(arch)` 后调 `arch.ensure_types()` 并
  `fd.vbank.set_type_factory(handle)`，使 Varnode/varmap/打印消费同一工厂。
<!-- annotation-pass: 2026-07-04 -->
 
# 2026-08-14：Architecture 消息保持 oracle 原文

`Architecture::print_message` 现在按锁定 Ghidra
`SleighArchitecture::printMessage`（`sleigh_arch.hh:138`）把消息原文加换行写到
stderr，不再添加 Rust 自创的 `[ARCH] ` 前缀。这使 Action/Rule 的错误与警告
消息可逐字对拍；调用方负责提供完整的 `ERROR:` / `WARNING:` 文本。

# 2026-08-14：共享 ProtoModel map 与 default Arc

`Architecture::proto_models` 现在保存 `Arc<ProtoModelFull>`；
`set_default_model` 恢复旧默认模型的 print flag、清除其 default 指针，再把新
模型的 print flag 设为 false，并将同一个 `Arc` 同时保存在 map 与
`defaultfp`。print flag 在共享模型对象上原位更新，不使用 `Arc::make_mut`，
因此已交给 `FuncProto` 或 `decode_proto` 调用方的外部 handle 保持同一身份，
并能观察默认模型切换。`decode_proto` 和 `decode_default_proto` 从既有 `TreeDecoder`
注册/选择真实模型，duplicate/default-wrapper 错误在替换共享状态前返回。

锁定 fixture `tools/run_cspec_param_model_oracle.sh` 对完整
`x86-64-gcc.cspec` 中默认 `__stdcall` 的名称、extrapop、参数范围、map/default
身份和 print flag 做 Ghidra 12.0.4 对拍。已声明观测相同，但生产文本 ingestion、
`resolveprototype` 和 `<modelrule>` 仍未完成，所以整体诚实保持 `MISMATCH`，
不得据此声称 compiler-spec 或主管线已完全接通。

本切片不把 `create_model_alias` / `is_compatible` 计为匹配：Rust 的既有 bool
adapter 尚不能表达 Ghidra 对 merged parent、alias-of-alias、duplicate 和缺失
parent 的异常域，alias-parent 身份也未对拍。`set_default_model(&str)` 对未知名称
静默返回，而 Ghidra 的 pointer API 不存在相同错误输入；这个 name-adapter 错误域
同样保持 `MISMATCH`。

# 2026-08-16：CSPEC 文本 ingestion 四切片（GLOBAL-APPLY / DEFAULT-RETURN /
# PCODEINJECT-CALLFIXUP / UNIVERSAL-CHILD）

`Architecture::parse_compiler_config`（architecture.cc:1239-1351 全链）落地：
真实 production `x86-64-gcc.cspec` 字节经 marshal `DocumentStorage::parse_document`
文本 ingest 后逐 child decode。新增（对应 oracle 行号见各函数注释）：
`SpecQuery` 语言查询 trait、`decode_global`+`add_to_global_scope`+`add_other_space`
（`<global>` 收集为 RangeProperties、主循环与 specextensions 后按源序延迟应用、
overlay 复制循环、OTHER space 全域）、`decode_return_address`（多重标签错误
`Multiple <returnaddress> tags in .cspec`）+ `default_return_addr` 字段、
`decode_stack_pointer`、`decode_proto_eval`、`decode_no_high_ptr`、
`decode_prefer_split`、`decode_aggressive_trim`、`decode_funcptr_align`、
`create_model_alias_exact`（Ghidra 逐字异常消息）、主循环 dispatch（含
`callfixup`→`PcodeInjectLibrary::decode_inject`、`callotherfixup`/`segmentop`→
UserOpManage decode 链、`modelalias`、specextensions 二遍）、default-model 回退
（map 首项）与 `__thiscall` 别名克隆。`decode_proto_spec` 把
`default_return_addr` 注入无自带 `<returnaddress>` 的模型（fspec.cc:2689，
`ProtoModelFull::decode_with_defaults` 新入口，旧 `decode_with_register_resolver`
委托 None 保持兼容）。

配套（同 write-set 模块）：`pcodeinject.rs` 重构为 Ghidra 结构
（id 索引 `injection` 向量 + name→id map + id→name 向量 + SLEIGH
tempbase/sleigh 成员；`decode_inject`=allocate→decode→register/compile 全链，
`parse_inject` 走 `PcodeSnippet` 编译，错误逐字）；`pcodeparse.rs`
`PcodeSnippet::lex` 补 sleigh symbol fallback（pcodeparse.cc:3223-3224）、
`STRING ':' INTEGER '='`/`STRING '='` 声明语句（pcodeparse.y:108/110）、
`ConstTpl::handle` 携带 v_field selector（semantics.cc:425-432）、
ConstructTpl delayslot 默认 0（semantics.hh:174）；`userop.rs` 补
`decode_call_other_fixup`/`decode_segment_op`/`decode_jump_assist`/
`decode_volatile`/`register_user_op`（userop.cc:490/533/551/589/606 +
InjectedUserOp/SegmentOp/JumpAssistOp decode）。

**对拍证据**：`tools/run_cspec_text_ingest_oracle.sh`（locked 12.0.4 oracle
BfdArchitecture 真链 init vs Rugra 文本 ingest，同一 cspec/sla/curl 字节），
67 行投影逐字节一致（含 16 个 `<callfixup>` 的编译模板 XML：LOAD/INT_ADD/
RETURN、COPY@unique 0x364420/0x364430 递进、13×CALLIND），合成探针覆盖
callotherfixup 编译失败残留（count 16→17、residue id）、未知名错误、
"segment" 定制成功（type 2/index 0）、volatile 注册+重复注册错误。

**残差（如实登记，非静默跳过）**：`data_organization`/`enum` →
CSPEC-TYPEORG-STATE-0001；`spacebase`/`deadcodedelay`/`inferptrbounds` →
空间管理器接线；`readonly` → Database property ranges；`context_data` →
context spec decode；`resolveprototype` → CSPEC-PARAMMODEL-0001；
`inferPtrSpaces` 的 post-init 过滤（cacheAddrSpaceProperties 域）不可观察；
`<body>` 内容经配对 DOM handle 提供（`XmlDecode::readString(ATTRIB_CONTENT)`
的 TreeDecoder 缺口，归 MARSHAL 域）；segmentop/jumpassist decode 已移植但
无 oracle 观察（UNTESTED）。模块保持 L2。

## 2026-08-17：UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ① — commentdb 工作侧分配

Ghidra 的 `Architecture::init`（architecture.cc:1391-1414）在 :1400 调
`buildCommentDB`，`SleighArchitecture::buildCommentDB`（sleigh_arch.cc:241-245）
分配内存态 `CommentDatabaseInternal`；构造器本身保持
`commentdb = (CommentDatabase *)0`（architecture.cc:166，Rugra
`Architecture::new` 的 `commentdb: None` 已对齐）。

Rugra 的分配点在 worker 的 init 等价物
`examples/curl_decompile.rs::worker_architecture`：`Architecture::new()` 之后、
cspec 解析（restoreFromSpec 等价步骤）之前，调用既有
`set_commentdb(Arc<RwLock<CommentDatabaseInternal::new>>)`,
与 init 序中 buildCommentDB 先于 restoreFromSpec(:1405) 的位置一致。此后
`Funcdata::warning_header`/`warning`（funcdata.cc:135/119）全部入库——包括
`ActionPrototypeWarnings` 的 unknown-calling-convention 警告
（coreaction.cc:4908）——E2E stderr 从 48 条（eprintln 回退 × 双注册）降为 0，
警告以 `Comment::warningheader` 类型按函数地址入库，等待 printc 侧
`emitCommentFuncHeader`（printc.cc:3272）接线后进入 C 输出。
