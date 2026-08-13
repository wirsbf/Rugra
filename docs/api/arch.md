# arch.rs — Architecture manager API

Architecture manager corresponding to Ghidra's `architecture.hh` /
`architecture.cc`.

**Status:** L2 (locked 12.0.4 audit, 2026-08-14). The structured-DOM
prototype/default-model slice has a locked oracle fixture, but production
compiler-spec text ingestion, `resolveprototype`, model rules, factory/init,
and consumer wiring remain incomplete. The fixture's declared observations
match; the module-level status remains `MISMATCH` / `UNTESTED`, not L3.

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
| `evalfp_current_name` / `evalfp_called_name` | `Option<String>` | Eval models. |
| `nohighptr` | `RangeList` | No-high-pointer ranges. |
| `overrides` | `Override` | Override commands. |
| `loadersymbols_parsed` | `bool` | Loader symbols read. |

**Methods:** `new()`, `reset_defaults_internal()` (architecture.cc:1416),
`reset_defaults()` (architecture.cc:1438), `get_model(name)`, `has_model(name)`,
`set_default_model(name)` (architecture.cc:323), `get_default_model()`,
`decode_proto(decoder, addr_size, register_resolver)` (architecture.cc:741),
`decode_default_proto(decoder, addr_size, register_resolver)`
(architecture.cc:795), `high_ptr_possible(addr, size)` (architecture.hh:408),
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
