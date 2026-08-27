# `debugproto.rs` API Reference

`src/debugproto.rs` implements Rugra's native equivalent of Ghidra's
pre-decompiler debug-import boundary. Ghidra's DWARF analyzer writes declared
function prototypes into the Program database; the C++ decompiler subsequently
receives a locked `FuncProto`. Rugra now parses concrete ELF DWARF subprograms,
follows `DW_AT_abstract_origin` / `DW_AT_specification`, preserves formal
parameter order, names, resolved scalar/pointer types and varargs, assigns
register storage from the locked `x86-64-gcc.cspec` default prototype, and
locks input/output/model state before Actions run.

It also imports DWARF global variables (`DWARF-TYPE-IMPORT-0001`):
`DebugGlobalDatabase::parse_elf` walks `DW_TAG_variable` DIEs whose
`DW_AT_location` is exactly `DW_OP_addr <addr>` and records each global's
storage address, name, and resolved data type. `address_pointer_map` projects
those globals into the `Funcdata::global_struct_ptrs` seeding form: the type
of an address constant that references the global, i.e. a pointer to the
declared variable type with C array decay (0x17660 `glob_expand` →
`URLGlob **`, 0x17520 `config` → `Configurable *`, 0x17680 `glob_buffer`
→ `char *`).

## Locked libc ABI signatures (`CALLSPEC-DRIVER-0001`)

`LibcSignatureTable` is Rugra's native front-end adapter for the platform-side
signature data Ghidra ships as generic_clib: the decompile/cpp code never
parses these declarations — the Program database holds the locked `FuncProto`
for each EXTERNAL symbol, `FlowInfo::queryCall` (flow.cc:656-672) associates
the call site with it, and `ActionDefaultParams` (coreaction.cc:2322-2330)
copies the prototype onto the call site. The table encodes the same 24 public
glibc ABI declarations verbatim (glibc reserved `__`-prefixed parameter names
included) that back the external-stub rendering
(`EXTERNAL-STUB-SUPPORT-0001`).

- `LibcSignatureTable::lookup(name)` — the signature record for an imported
  symbol, `None` for anything else (unknown imports stay unlocked).
- `LibcSignatureTable::locked_proto(name, storage)` — materializes the locked
  call-site `FuncProto`: parameter storage assigned through
  `X86_64GccStorage::assign` (the locked `x86-64-gcc.cspec` resource order),
  input and output locked (`FuncProto::setPieces`, fspec.cc:3830), model left
  unlocked so `ActionDefaultParams` attaches the default model — the golden's
  "Unknown calling convention -- yet parameter storage is locked" warning is
  exactly this combination. Returns `Ok(None)` for unknown imports and `Err`
  when a listed signature cannot be represented (stack/aggregate spill).
  Every materialized parameter additionally carries
  `protoparam_flags::NAME_LOCKED` (2026-08-25,
  COREACTION-FUNCPARAMNAMES-RECOMMEND-0001): the platform-side signature
  decode reads ATTRIB_NAMELOCK into `ParameterPieces::namelock`
  (fspec.cc:3503-3506) and `FuncProto::decode` propagates it via
  `curparam->setNameLock(...)` (fspec.cc:3564) — the bit
  `ActionNameVars::lookForFuncParamNames` gates recommendations on
  (coreaction.cc:2818 `param->isNameLocked()`), which names call-site
  variables after locked callee parameter names (`strtol` → `__nptr`).

Supporting parsers: `split_parameter_list` / `split_declaration` split the
comma-separated `TYPE NAME` declarations (the trailing identifier run is the
name, pointer stars belong to the type: `void *__ptr`), and `parse_c_type`
maps the C spellings (`void`, `char`, `int`, `long`, `size_t`, `time_t`,
`ushort`, opaque base names, pointer layers) onto `Datatype` metatype/size
pairs. Unit tests cover the 24-entry table, SYSV storage assignment
(`free`→RDI void*, `strtol`→RDI/RSI/RDX, `__ctype_b_loc`→locked void input,
`ushort **` return), and the unknown-import unlock path.

## Type resolution

`resolve_type` materializes the DWARF type graph into `Datatype` objects:

- base types map `DW_AT_encoding` onto the Rugra metatype (float/unsigned/
  boolean/int);
- pointers/references build `Datatype::Pointer` with the pointee's spelling
  (`URLGlob *`, and `URLGlob **` for pointer-to-pointer);
- `DW_TAG_structure_type`/`DW_TAG_union_type` build fielded
  `Datatype::Struct`/`Datatype::Union` from `DW_TAG_member` children (name,
  `DW_AT_data_member_location` constant or `DW_OP_plus_uconst`, resolved
  member type) — named by `DW_AT_name` without a `struct `/`union ` prefix,
  which is the spelling Ghidra's type manager prints (`Configurable *`,
  matching the 12.0.4 golden);
- `DW_TAG_enumeration_type` builds `TypeEnum` with its `DW_TAG_enumerator`
  value table;
- `DW_TAG_array_type` builds `Datatype::Array` from the first subrange's
  `DW_AT_count`/`DW_AT_upper_bound`+1 (`char *[10]`, `URLPattern[9]`);
- typedefs over composites/enums are materialized as the renamed underlying
  type (Rugra has no `TypeTypedef` variant yet — fields and enumerator names
  are carried on the renamed type);
- recursive type graphs (`FILE` → `struct _IO_FILE` → `_chain FILE *`) break
  at the back edge with a shallow named projection (name/size/metatype, no
  fields), mirroring how Ghidra's two-phase type manager exposes an
  already-created type before its members are filled.

This is the first `DWARF-PROTO-0001` closure, not a claim of complete DWARF or
prototype recovery. Cross-compilation-unit references, location-list state,
aggregate rules, stack parameters, split DWARF and non-x86 compiler specs remain
explicitly unsupported. Such a prototype is rejected instead of being assigned
approximate storage. Stripped-binary inference remains
`PARAM-RECOVERY-0001`. The module and signature pipeline therefore remain L2.

The current curl regression input has SHA-256
`4ee4002baf3525d9fef062f9fcb9b7a9a890509b8bc5211740d0155d7c6b5d1a`.
Rust-side import tests cover `GetStr` (2 fixed parameters), `myprogress` (5),
`helpf` (1 plus varargs), the optimized `getparameter` definition (4 via
`DW_AT_abstract_origin`), locked zero-input `hugehelp`, and the five DWARF
globals of the curl fixture (`config`, `save`, `beenhere`, `glob_buffer`,
`glob_expand`) including the `URLGlob` 304-byte layout (literal char*[10] @0,
pattern URLPattern[9] @80, size int @296) and the `&global` pointer map.
This is useful regression evidence, but it is not a Ghidra DWARF-analyzer
oracle fixture; the importer remains `NO_ORACLE` under mechanism B2.

#### 会话状态（2026-08-16）
本 session 在此文件对应的 `src/debugproto.rs` 上落地了
`CALLSPEC-DRIVER-0001`（`LibcSignatureTable` 24 条 glibc ABI 签名 + 按入口地址
解析调用目标）与 DWARF 全局变量类型图（`address_pointer_map` 投影，见上文
`DWARF-TYPE-IMPORT-0001` 段落）。两者均为 front-end 适配层：Ghidra 对应行为
发生在 Program 数据库与 analyzer 侧，decompile/cpp 内无逐行对应物，因此标注为
`RUGRA-GLUE` 类桥接，不参与机制 C 核心白名单。端到端效果由
`result/curl_cur.c` 对 `tests/golden/ghidra_curl_1204.c` 的差分门禁回归
（`FUN_0` → `free`/`strdup` 调用解析与全局类型指针化在本 session 达到
byte-stable）。

## 2026-08-17：UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ⑤ — void 签名 DWARF 覆盖钉住 unknown 模型

### `DebugPrototypeDatabase::apply` 的模型状态（fspec.cc:4690-4698/4776）

锁定的 Program-database 签名经 `FuncProto::decode` 进入反编译器：ATTRIB_MODEL
携带平台侧调用约定名，无法识别的名字走 `createUnknownModel`
（fspec.cc:4697 → architecture.cc:1159-1166），得到克隆 defaultfp 行为、
`isUnknown()=true`、且名字 "unknown" 不打印进声明的 `UnknownProtoModel`；
空参列表的 voidlock 置位 modellock（fspec.cc:4776）。

Rugra 的 `apply` 现按同一边界可观察行为钉模型状态：

- **空参签名**（`parameters.is_empty()`）：`set_model_name("unknown")` —
  克隆的模型 Arc 保留为 UnknownProtoModel 的 placeholder（行为/效果/extrapop
  仍随 default 模型），`is_model_unknown()` 为 true，`ActionPrototypeWarnings`
  （coreaction.cc:4901-4909）发射 "Unknown calling convention" 警告。锁定
  golden 中恰好只有三个空参 DWARF 函数告警：main_init(0x4960)/
  main_free(0x4970)/hugehelp(0x4a00)。
- **带参签名**：保持既有解析模型绑定（golden 中 18 个带参 DWARF 函数全部
  无警告——它们的模型保持 resolved，ActionPrototypeTypes 不会被锁死的
  unknown 名覆盖）。

### 残差（main_init 后缀）

golden 的 main_init 为裸 "Unknown calling convention"（存储未锁：
isInputLocked/isOutputLocked 均假），main_free/hugehelp 带
"-- yet parameter storage is locked"。Rugra 当前对三个函数统一
`set_input_lock(true)+set_output_lock(true)`，main_init 会多出后缀（27 字符
文本差）。DWARF 可见判别（main_init 的 abstract DIE 带 DW_AT_type，其余两个
void 返回无）不足以从 decompiler 侧语义推导平台侧锁属性差异；待 printc 侧
②③ 接线落地、差分可见时按 golden 逐位置复核（登记在
UNKNOWN-PROTOMODEL-WARN-EMIT-0001）。

### 新增测试

- `void_signature_dwarf_prototype_pins_unknown_model`：三函数 unknown 钉住 +
  modellock + void_input_locked。
- `parameterized_dwarf_prototype_keeps_resolved_model`：带参签名保持
  resolved 名。
- `unknown_model_warning_stores_in_commentdb`：①+⑤ 端到端——
  Architecture 分配 CommentDatabaseInternal（sleigh_arch.cc:244）后，
  ActionPrototypeWarnings 把 "WARNING: Unknown calling convention -- yet
  parameter storage is locked" 以 WARNINGHEADER 类型存入 0x4970 函数地址下
  （printc emitCommentFuncHeader 的打印侧接线另行登记）。

## 2026-08-25：COREACTION-FUNCPARAMNAMES-RECOMMEND-0001 — 锁定签名的参数名锁位

### `NAME_LOCKED` 在两个 front-end 适配层的落位（fspec.cc:3564）

Ghidra 的锁定签名经 `FuncProto::decode` 进入反编译器时，每个 `<param>` 的
ATTRIB_NAMELOCK 置 `ParameterPieces::namelock`（fspec.cc:3503-3506），
`curparam->setNameLock((pieces[i].flags & namelock)!=0)`（fspec.cc:3564）把它
落到 `ProtoParameter` 上。`ActionNameVars::lookForFuncParamNames`
（coreaction.cc:2858-2897）推荐命名的第一道门禁就是
`param->isNameLocked()`（coreaction.cc:2818，经 `makeRec`）——没有该位，
strtol 的 `__nptr`/strstr 的 `__haystack` 永远不会推荐到调用点变量。

Rugra 此前 `ProtoParameter::new` 恒 `flags: 0`，两个适配层都只靠
`set_input_lock(true)` 置 TYPE_LOCKED，NAME_LOCKED 全程缺失，推荐链断在
数据侧（coreaction.rs 的 lookForFuncParamNames 内联实现本身已齐全）。修复：

- **`LibcSignatureTable::locked_proto`**：每个物化参数置 NAME_LOCKED
  （generic_clib 签名数据全部带真名，`split_declaration` 拒绝无名声明）。
- **`DebugPrototypeDatabase::apply`**：仅 DWARF 真实 `DW_AT_name` 参数置
  NAME_LOCK；无名 DIE 的 `param_N` 合成名不锁（Ghidra 侧无名 DIE 保持未命名、
  由 buildDefaultName 接管；lookForFuncParamNames 另有 `param_` 前缀过滤，
  coreaction.cc:2831）。

### 端到端效果（curl 12.0.4 golden 差分）

- `progressbarinit` 的 strtol 调用点变量 `extraout_RAX` → `__nptr`
  （golden 同名，函数级 defects=0/numbering=0）。
- 全量 124 函数：13 个函数获得推荐命名（`__s`/`__dest`/`__ptr`/`__n`/
  `__nptr`/`__stream`/`__haystack`/`__filename`，即 golden 中 fwrite/fgets/
  strcat/strcpy/free/realloc/fopen/strstr/strtol 的锁定参数名），
  skeleton 差异 2863 → 2849（-14），defects=0、numbering=0 保持。
  其余 skeleton 差异均为独立既有缺口（curl_getenv 赋值语句缺失、"COLUMNS"
  字符串引用、char* cast 传播等）。

## 2026-08-25：CALLSPEC-ENV-SCOPE-0001 — DWARF 签名链接到调用点（queryCall→copy 边界）

### 缺口

`DebugPrototypeDatabase::apply` 只把 DWARF 签名锁到**被反编译函数自身**的
`fd.funcp`；调用点的 105 个 callspec 里只有 24 个 generic_clib 导入拿到锁定
原型（`LibcSignatureTable`），其余 81 个（curl 内部函数：glob_url/
getparameter/parseconfig/match_url 等）在 flow 期保持 `fd.funcp.clone()`
（flow.rs:1390，Ghidra 的 `FuncCallSpecs` ctor 克隆 default 而非调用者）。
headless golden 的环境里这些 callee 的 DWARF 签名被 analyzer 锁进 Program
数据库，`FlowInfo::queryCall`（flow.cc:656-672）解析 callee `Funcdata`，
`ActionDefaultParams`（coreaction.cc:2322-2330）`fc->copy(otherfunc->
getFuncProto())` 把整份 callee 原型（model + 全部锁位 + 参数 store 的 clone，
`FuncProto::copy` fspec.cc:3789-3804）复制到调用点——这是 golden main
`glob_url(&urls,pcVar12,&urlnum)`（3 参）与 `curl_version()`（0 参）的来源。

### 落地

- `DebugPrototypeDatabase::locked_callsite_proto(entry, model_carrier,
  storage)`：同一 Program-数据库边界的调用点半边。`model_carrier` 提供模型
  ——与 callee 自身 `Funcdata` 绑定的 Architecture defaultfp 相同（driver 传
  `fd.funcp`，FUNCPROTO-MODEL-BIND-0001 的 set_arch 绑定后）。锁配方与
  `apply` 完全一致（共享 `locked_proto` 构建器，fspec.cc:3843-3852 setPieces
  语义）：SYSV 存储、DW_AT_name 才 NAME_LOCKED、input/output/model 三锁、
  空参签名钉 unknown 模型哨兵。`Ok(None)` = 该地址无 DWARF 定义（thunk/
  导入：generic_clib 表或 active recovery 负责）。
- driver `link_call_specs`：libc 表未命中（thunk 地址无 DWARF 定义、DWARF
  函数名不在 24 条导入表内——两源按构造不相交）后查 DWARF，命中即整体替换
  callspec `prototype`。`[PREPASS]` 日志新增 locked DWARF signatures 计数。

### 可观察效果与边界（诚实账）

- main：`extraout_var` 声明位次变化（14 个 DWARF 锁定 callee 的 output_type
  _locked 改变了 funcLinkOutput 的锁定路径与 active-output trial 集合）。
  **调用实参个数不变**：`curl_version(lVar50,in_RDX,argv,argc,in_R8,in_R9)`
  仍 6 个试验参数——实参个数由 CALL op 的 input varnodes 决定
  （printc opCall 按 `op->numInput()-1` 渲染，printc.cc:610-624），而 Rugra
  缺少 Ghidra 的收敛消费者：`build_input_from_trials` 未做
  `data.opSetAllInput`（fspec.cc:5739 尾）、`commit_new_inputs`（fspec.cc:5150
  port）零调用方、`ActionLockInputs`/`ActionParamList` 未移植、
  `ActionFuncLink::func_link_input` 读硬编码 ABI 表而非锁定原型参数。这些
  全部在 coreaction/fspec 租约域（`MAINDIFF-CALLPROTO-0001`），本改动是它们
  需要的环境数据面。
- `match_url` 的 `URLGlob **glob` 聚合参数走 fail-visible 拒绝路径
  （`compiler-spec aggregate/stack assignment is not yet representable`），
  保持未锁——与 `apply` 对聚合参数的既有拒绝语义一致。

## parse_type_names：DWARF 命名类型索引（2026-08-26）

`parse_type_names`（RUGRA-GLUE，Program-import 边界）：遍历 DWARF 单元的
structure/union/enumeration/typedef/base_type DIE 建立名字→类型索引，供
`LibcSignatureTable::locked_proto` 解析签名基础拼写（如 `FILE`）。Ghidra 侧
由 DWARF analyzer 填充 program type manager；重复名首见优先（锁定 curl
语料无冲突）。

## parse_c_type/split_pointer_depth：嵌套指针归一（2026-08-27）

`split_pointer_depth` 逐星剥离（星 + 前导空格循环），任意间距形式
（`char **`/`char**`/`char * *`）归一到 base+depth；旧
`trim_end_matches(" *")` 剥不掉第二颗星，双指针落入 unknown-name 基臂产出
`Base("char **", TYPE_UNKNOWN)` 而非结构化 Pointer-to-Pointer。
`parse_c_type` 嵌套层显示名在前层以 `*` 结尾时粘着（`char *` → `char **`），
匹配类型打印机右到左 C 声明形。
